//! Sanitized Legal Markdown routes: `/terms`, `/privacy`, `/dmca`, `/content-policy`.
//!
//! Renders Markdown from the active pinned `CompiledPolicy` through `pulldown-cmark`
//! and strict `ammonia` HTML allowlist sanitization (`app::legal::render_sanitized_markdown`),
//! emitting a strict Content-Security-Policy header disallowing all script execution.

use app::{
    legal::{LEGAL_PAGE_CSP, render_sanitized_markdown},
    state::{AppState, RequestSafetyContext},
    util::resolve_origin_for_request,
};
use axum::{
    Extension,
    extract::State,
    http::{HeaderMap, HeaderName, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
};

fn html_escape_attr(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

fn render_legal_document(
    state: &AppState,
    ctx_ext: Option<Extension<RequestSafetyContext>>,
    headers: &HeaderMap,
    slug: &'static str,
    title: &'static str,
    extract_md: impl FnOnce(&site_access::LegalDocConfig) -> &str,
) -> Response {
    let ctx = match ctx_ext {
        Some(Extension(c)) => c,
        None if state.mode.is_managed() => {
            return (
                StatusCode::FORBIDDEN,
                [(header::CACHE_CONTROL, "private, no-store")],
                "Forbidden",
            )
                .into_response();
        }
        None => RequestSafetyContext::standalone(
            state.policy_store.current_standalone(),
            state.trust_proxy,
        ),
    };

    let legal = &ctx.policy.policy.legal;
    let raw_md = extract_md(legal);
    let body_html = if raw_md.trim().is_empty() {
        format!(
            "<h1>{}</h1><p>This policy document has not been published yet.</p>",
            html_escape_attr(title)
        )
    } else {
        render_sanitized_markdown(raw_md)
    };

    let canonical_tag = resolve_origin_for_request(state, headers)
        .map(|origin| {
            let href = html_escape_attr(&format!("{origin}/{slug}"));
            format!(r#"<link rel="canonical" href="{href}">"#)
        })
        .unwrap_or_default();

    let rta_tags = if legal.rta_meta_enabled {
        r#"<meta name="rating" content="RTA-5042-1996-1400-1577-RTA"><meta name="rating" content="adult">"#
    } else {
        ""
    };

    let escaped_title = html_escape_attr(title);
    let html = format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{escaped_title} · Let's Embed</title>
{canonical_tag}
{rta_tags}
<style>
  :root {{ color-scheme: light; }}
  body {{ margin: 0; font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: linear-gradient(180deg, #f0f9ff 0%, #ffffff 45%, #e0f2fe 100%); color: #334155; min-height: 100vh; display: flex; flex-direction: column; }}
  header {{ padding: 14px 20px; border-bottom: 1px solid #bae6fd; background: rgba(255,255,255,0.88); backdrop-filter: blur(8px); }}
  .nav-inner {{ max-width: 820px; margin: 0 auto; display: flex; flex-wrap: wrap; align-items: center; justify-content: space-between; gap: 12px; }}
  .brand {{ font-weight: 700; font-size: 1.05rem; color: #0284c7; text-decoration: none; }}
  nav {{ display: flex; flex-wrap: wrap; gap: 14px; font-size: 0.85rem; }}
  nav a {{ color: #475569; text-decoration: none; }}
  nav a:hover {{ color: #0284c7; text-decoration: underline; }}
  main {{ flex: 1; width: 100%; max-width: 820px; margin: 28px auto; padding: 0 18px; box-sizing: border-box; }}
  article {{ background: rgba(255,255,255,0.92); border: 1px solid #bae6fd; border-radius: 20px; padding: 28px 32px; box-shadow: 0 8px 30px rgba(14, 165, 233, 0.08); line-height: 1.65; }}
  article h1, article h2, article h3 {{ color: #0f172a; line-height: 1.3; }}
  article a {{ color: #0284c7; }}
  article pre {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 10px; padding: 12px; overflow-x: auto; }}
  article code {{ font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.9em; }}
  article table {{ width: 100%; border-collapse: collapse; margin: 16px 0; }}
  article th, article td {{ border: 1px solid #cbd5e1; padding: 8px 10px; text-align: left; }}
</style>
</head>
<body>
<header>
  <div class="nav-inner">
    <a class="brand" href="/">Let&#39;s Embed</a>
    <nav aria-label="Legal navigation">
      <a href="/terms">Terms</a>
      <a href="/privacy">Privacy</a>
      <a href="/dmca">DMCA</a>
      <a href="/content-policy">Content Policy</a>
    </nav>
  </div>
</header>
<main>
  <article>{body_html}</article>
</main>
</body>
</html>"#
    );

    let mut resp = (StatusCode::OK, html).into_response();
    let h = resp.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    h.insert(
        HeaderName::from_static("content-security-policy"),
        HeaderValue::from_static(LEGAL_PAGE_CSP),
    );
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    if state.mode.is_managed() {
        h.insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static("private, no-store"),
        );
    }
    resp
}

pub async fn terms(
    State(state): State<AppState>,
    ctx: Option<Extension<RequestSafetyContext>>,
    headers: HeaderMap,
) -> Response {
    render_legal_document(&state, ctx, &headers, "terms", "Terms of Service", |l| {
        &l.terms_md
    })
}

pub async fn privacy(
    State(state): State<AppState>,
    ctx: Option<Extension<RequestSafetyContext>>,
    headers: HeaderMap,
) -> Response {
    render_legal_document(&state, ctx, &headers, "privacy", "Privacy Policy", |l| {
        &l.privacy_md
    })
}

pub async fn dmca(
    State(state): State<AppState>,
    ctx: Option<Extension<RequestSafetyContext>>,
    headers: HeaderMap,
) -> Response {
    render_legal_document(
        &state,
        ctx,
        &headers,
        "dmca",
        "DMCA & Copyright Policy",
        |l| &l.dmca_md,
    )
}

pub async fn content_policy(
    State(state): State<AppState>,
    ctx: Option<Extension<RequestSafetyContext>>,
    headers: HeaderMap,
) -> Response {
    render_legal_document(
        &state,
        ctx,
        &headers,
        "content-policy",
        "Content Policy",
        |l| &l.content_policy_md,
    )
}
