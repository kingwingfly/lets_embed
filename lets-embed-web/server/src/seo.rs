//! Public SEO endpoints: `/robots.txt`, `/sitemap.xml`, and chunked `/sitemap/{page}.xml`.
//!
//! - In Managed Mode, canonical origin is ALWAYS the pinned `PUBLIC_URL` (never `Host`/`X-Forwarded-Host`).
//! - Sitemaps ALWAYS run under the anonymous safe view (`sitemap_post_count_with_policy` /
//!   `sitemap_post_entries_with_policy`), honoring `policy.legal.noindex_restricted`.

use std::sync::Arc;

use app::{
    state::{AppState, RequestSafetyContext},
    util::resolve_origin_for_request,
};
use axum::{
    Extension,
    extract::{Path, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};

/// Maximum post URLs per sitemap XML page (well below the 50,000 protocol limit).
pub const SITEMAP_PAGE_SIZE: i64 = 5_000;

fn resolve_origin(state: &AppState, headers: &HeaderMap) -> Option<String> {
    resolve_origin_for_request(state, headers)
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(ch),
        }
    }
    out
}

fn parse_sitemap_page(raw: &str) -> Option<u32> {
    let num = raw.strip_suffix(".xml")?;
    if num.is_empty() || !num.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let page: u32 = num.parse().ok()?;
    (page >= 1).then_some(page)
}

fn render_urlset(
    origin: &str,
    include_home: bool,
    entries: &[search_engine::SitemapPostEntry],
) -> String {
    let base = xml_escape(origin);
    let mut xml = String::with_capacity(256 + entries.len() * 96);
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n");
    if include_home {
        xml.push_str("  <url>\n");
        xml.push_str(&format!("    <loc>{base}/</loc>\n"));
        xml.push_str("    <changefreq>daily</changefreq>\n");
        xml.push_str("    <priority>1.0</priority>\n");
        xml.push_str("  </url>\n");
    }
    for entry in entries {
        xml.push_str("  <url>\n");
        xml.push_str(&format!(
            "    <loc>{base}/details/{}</loc>\n",
            entry.cover_image_id
        ));
        if let Some(lastmod) = entry.lastmod.as_deref()
            && !lastmod.is_empty()
        {
            xml.push_str(&format!("    <lastmod>{}</lastmod>\n", xml_escape(lastmod)));
        }
        xml.push_str("  </url>\n");
    }
    xml.push_str("</urlset>\n");
    xml
}

fn render_sitemap_index(origin: &str, total_pages: u32) -> String {
    let base = xml_escape(origin);
    let mut xml = String::with_capacity(256 + (total_pages as usize) * 80);
    xml.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    xml.push_str("<sitemapindex xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">\n");
    for page in 1..=total_pages {
        xml.push_str("  <sitemap>\n");
        xml.push_str(&format!("    <loc>{base}/sitemap/{page}.xml</loc>\n"));
        xml.push_str("  </sitemap>\n");
    }
    xml.push_str("</sitemapindex>\n");
    xml
}

/// `GET /robots.txt`
pub async fn robots_txt(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let mut body = String::from(
        "User-agent: *\n\
         Allow: /\n\
         Disallow: /user/\n\
         Disallow: /admin/\n\
         Disallow: /api/\n\
         Disallow: /media/\n",
    );
    if let Some(origin) = resolve_origin(&state, &headers) {
        body.push_str(&format!("\nSitemap: {origin}/sitemap.xml\n"));
    }
    (
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        body,
    )
        .into_response()
}

/// `GET /sitemap.xml` — serves a single `<urlset>` when the catalog fits in one
/// chunk, or a `<sitemapindex>` referencing `/sitemap/1.xml` .. `/sitemap/{n}.xml`.
pub async fn sitemap_root(
    State(state): State<AppState>,
    ctx_ext: Option<Extension<RequestSafetyContext>>,
    headers: HeaderMap,
) -> Response {
    let policy = match ctx_ext {
        Some(Extension(c)) => c.policy,
        None if state.mode.is_managed() => {
            return (
                StatusCode::FORBIDDEN,
                [(header::CACHE_CONTROL, "private, no-store")],
                "Forbidden",
            )
                .into_response();
        }
        None => state.policy_store.current_standalone(),
    };
    let Some(origin) = resolve_origin(&state, &headers) else {
        return (StatusCode::BAD_REQUEST, "Unable to determine site origin").into_response();
    };
    let engine: Arc<search_engine::Engine> = state.engine.clone();
    let total = match engine.sitemap_post_count_with_policy(&policy).await {
        Ok(n) => n.max(0),
        Err(e) => {
            tracing::error!("sitemap_post_count failed: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Sitemap unavailable").into_response();
        }
    };

    let xml = if total <= SITEMAP_PAGE_SIZE {
        let entries = match engine
            .sitemap_post_entries_with_policy(&policy, SITEMAP_PAGE_SIZE, 0)
            .await
        {
            Ok(list) => list,
            Err(e) => {
                tracing::error!("sitemap_post_entries failed: {e}");
                return (StatusCode::INTERNAL_SERVER_ERROR, "Sitemap unavailable").into_response();
            }
        };
        render_urlset(&origin, true, &entries)
    } else {
        let pages =
            ((total + SITEMAP_PAGE_SIZE - 1) / SITEMAP_PAGE_SIZE).min(i64::from(u32::MAX)) as u32;
        render_sitemap_index(&origin, pages)
    };

    (
        [
            (header::CONTENT_TYPE, "application/xml; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        xml,
    )
        .into_response()
}

/// `GET /sitemap/{page}` (e.g. `/sitemap/1.xml`)
pub async fn sitemap_page(
    State(state): State<AppState>,
    ctx_ext: Option<Extension<RequestSafetyContext>>,
    Path(raw_page): Path<String>,
    headers: HeaderMap,
) -> Response {
    let policy = match ctx_ext {
        Some(Extension(c)) => c.policy,
        None if state.mode.is_managed() => {
            return (
                StatusCode::FORBIDDEN,
                [(header::CACHE_CONTROL, "private, no-store")],
                "Forbidden",
            )
                .into_response();
        }
        None => state.policy_store.current_standalone(),
    };
    let Some(page) = parse_sitemap_page(&raw_page) else {
        return (StatusCode::NOT_FOUND, "Not Found").into_response();
    };
    let Some(origin) = resolve_origin(&state, &headers) else {
        return (StatusCode::BAD_REQUEST, "Unable to determine site origin").into_response();
    };
    let engine: Arc<search_engine::Engine> = state.engine.clone();
    let total = match engine.sitemap_post_count_with_policy(&policy).await {
        Ok(n) => n.max(0),
        Err(e) => {
            tracing::error!("sitemap_post_count failed: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Sitemap unavailable").into_response();
        }
    };
    let total_pages = ((total + SITEMAP_PAGE_SIZE - 1) / SITEMAP_PAGE_SIZE).max(1);
    if i64::from(page) > total_pages {
        return (StatusCode::NOT_FOUND, "Not Found").into_response();
    }

    let offset = (i64::from(page) - 1).saturating_mul(SITEMAP_PAGE_SIZE);
    let entries = match engine
        .sitemap_post_entries_with_policy(&policy, SITEMAP_PAGE_SIZE, offset)
        .await
    {
        Ok(list) => list,
        Err(e) => {
            tracing::error!("sitemap_post_entries failed: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Sitemap unavailable").into_response();
        }
    };
    let xml = render_urlset(&origin, page == 1, &entries);
    (
        [
            (header::CONTENT_TYPE, "application/xml; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        xml,
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::{parse_sitemap_page, render_sitemap_index, render_urlset};
    use search_engine::SitemapPostEntry;

    #[test]
    fn parses_valid_sitemap_page_filenames_only() {
        assert_eq!(parse_sitemap_page("1.xml"), Some(1));
        assert_eq!(parse_sitemap_page("42.xml"), Some(42));
        assert_eq!(parse_sitemap_page("0.xml"), None);
        assert_eq!(parse_sitemap_page("-1.xml"), None);
        assert_eq!(parse_sitemap_page("1.txt"), None);
        assert_eq!(parse_sitemap_page("abc.xml"), None);
    }

    #[test]
    fn renders_valid_urlset_and_index_xml() {
        let entries = vec![SitemapPostEntry {
            cover_image_id: 42,
            lastmod: Some("2026-11-22".into()),
        }];
        let xml = render_urlset("https://lets-embed.louisfly.icu", true, &entries);
        assert!(xml.contains("<loc>https://lets-embed.louisfly.icu/</loc>"));
        assert!(xml.contains("<loc>https://lets-embed.louisfly.icu/details/42</loc>"));
        assert!(xml.contains("<lastmod>2026-11-22</lastmod>"));

        let index = render_sitemap_index("https://lets-embed.louisfly.icu", 2);
        assert!(index.contains("<loc>https://lets-embed.louisfly.icu/sitemap/1.xml</loc>"));
        assert!(index.contains("<loc>https://lets-embed.louisfly.icu/sitemap/2.xml</loc>"));
    }
}
