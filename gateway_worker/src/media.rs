//! Capability-based `/media/{image,video,preview}/{id}?cap=...` route parsing,
//! Policy v3 `facts_rev` lookup helpers, canonical upstream URL construction,
//! and locked server-side Cloudflare Images blur verification.

use axum::http::{HeaderMap, StatusCode};
use serde::{Deserialize, Serialize};
use site_access::{MediaCapKind, PublicSitePolicy};

use crate::http_util::{
    Upstreams, is_canonical_path, is_rfc3986_unreserved, parse_upstream_origin, percent_decode,
};

/// Hardcoded, non-overridable Cloudflare Worker `cf.image` parameters used for
/// server-side blurred previews when `policy.fixed_blur_enabled` is true.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PreviewBlurConfig {
    pub(crate) blur: u8,
    pub(crate) width: u32,
    pub(crate) quality: u8,
    pub(crate) format: &'static str,
}

pub(crate) const LOCKED_PREVIEW_BLUR: PreviewBlurConfig = PreviewBlurConfig {
    blur: 80,
    width: 360,
    quality: 30,
    format: "webp",
};

/// Request payload sent to `USER_ACCOUNT` DO (`POST /preview-budget`).
///
/// Strictly separated from clear-view `charge`/`can-charge`/`guest` endpoints so
/// reading a blurred preview can never deduct points or mark a clear view paid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PreviewBudgetReq {
    pub(crate) key: String,
    pub(crate) head: bool,
    pub(crate) guest: bool,
}

/// Response payload from `GET {APP_ORIGIN}/internal/facts-rev/{kind}/{id}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct FactsRevResponse {
    pub(crate) facts_rev: u64,
}

/// Maps a [`MediaCapKind`] to the authoritative origin `/internal/facts-rev/{kind}/{id}`
/// resource kind (`"image"` | `"video"`). Blurred previews target image assets.
pub(crate) const fn facts_rev_resource_kind(kind: MediaCapKind) -> &'static str {
    match kind {
        MediaCapKind::Image | MediaCapKind::Preview => "image",
        MediaCapKind::Video => "video",
    }
}

/// Builds and strictly validates `{API_UPSTREAM}/internal/facts-rev/{kind}/{id}`.
pub(crate) fn build_facts_rev_target(
    kind: MediaCapKind,
    asset_id: i64,
    upstreams: &Upstreams,
) -> std::result::Result<worker::Url, ()> {
    if asset_id <= 0 {
        return Err(());
    }
    let upstream = parse_upstream_origin(upstreams.api.as_str()).map_err(|_| ())?;
    let expected_path = format!("/internal/facts-rev/{}/{asset_id}", facts_rev_resource_kind(kind));
    if !is_canonical_path(&expected_path) {
        return Err(());
    }
    let target = format!("{upstream}{expected_path}");
    let base_url = worker::Url::parse(&upstream).map_err(|_| ())?;
    let target_url = worker::Url::parse(&target).map_err(|_| ())?;
    if target_url.scheme() != base_url.scheme()
        || target_url.host_str() != base_url.host_str()
        || target_url.port_or_known_default() != base_url.port_or_known_default()
        || !target_url.username().is_empty()
        || target_url.password().is_some()
        || target_url.path() != expected_path
        || target_url.query().is_some()
        || target_url.fragment().is_some()
    {
        return Err(());
    }
    Ok(target_url)
}

/// Strictly parses `{ "facts_rev": u64 }` from origin, rejecting malformed JSON or `0`.
pub(crate) fn parse_facts_rev_response(raw: &str) -> std::result::Result<u64, &'static str> {
    let parsed: FactsRevResponse =
        serde_json::from_str(raw).map_err(|_| "malformed facts-rev JSON")?;
    if parsed.facts_rev == 0 {
        return Err("facts_rev must be >= 1");
    }
    Ok(parsed.facts_rev)
}

/// Parses `/media/{image|video|preview}/{id}` where `{id}` is a canonical
/// positive base-10 integer (no leading zeros, signs, or extra path segments).
pub(crate) fn parse_media_route(path: &str) -> Option<(MediaCapKind, i64)> {
    let rest = path.strip_prefix("/media/")?;
    let (kind_str, id_str) = rest.split_once('/')?;
    if id_str.is_empty()
        || id_str.contains('/')
        || id_str.starts_with('0')
        || !id_str.bytes().all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let kind = MediaCapKind::parse(kind_str)?;
    let id: i64 = id_str.parse().ok()?;
    (id > 0).then_some((kind, id))
}

/// Extracts the single non-empty `cap` query parameter from a URI query string.
///
/// Rejects missing, empty, malformed percent-encoding, or duplicate `cap`
/// parameters (HTTP parameter pollution defense).
pub(crate) fn extract_media_cap_query(query: Option<&str>) -> Option<String> {
    let q = query?;
    let mut found: Option<String> = None;
    for pair in q.split('&') {
        if pair.is_empty() {
            continue;
        }
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        let decoded_k = percent_decode(k)?;
        if decoded_k == "cap" {
            if found.is_some() {
                return None;
            }
            let decoded_v = percent_decode(v)?;
            if decoded_v.is_empty() {
                return None;
            }
            found = Some(decoded_v);
        }
    }
    found
}

/// Validates and canonicalizes a relative `cap.immutable_locator` into a
/// leading-slash RFC 3986 path safe to join onto `IMAGE_UPSTREAM` or `VIDEO_UPSTREAM`.
///
/// Aligned with `site_access::is_safe_media_path`: rejects leading/trailing `/`,
/// empty segments, `.` / `..`, `'%'`, `':'`, `'\\'`, `'?'`, `'#'`, and control chars,
/// then percent-encodes raw non-unreserved bytes (spaces, parens, UTF-8) once.
pub(crate) fn encode_canonical_cap_path(cap_path: &str) -> Option<String> {
    if cap_path.is_empty()
        || cap_path.starts_with('/')
        || cap_path.ends_with('/')
        || cap_path.contains("//")
        || cap_path
            .chars()
            .any(|c| c.is_control() || matches!(c, '%' | ':' | '\\' | '?' | '#'))
    {
        return None;
    }

    let mut out = String::with_capacity(cap_path.len() + 1);
    for seg in cap_path.split('/') {
        if seg.is_empty() || seg == "." || seg == ".." {
            return None;
        }
        out.push('/');
        for b in seg.bytes() {
            if is_rfc3986_unreserved(b) {
                out.push(b as char);
            } else {
                use std::fmt::Write as _;
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    Some(out)
}

/// Builds and strictly validates the upstream media URL for a verified capability:
/// - `Image` and `Preview` -> `IMAGE_UPSTREAM`
/// - `Video` -> `VIDEO_UPSTREAM`
///
/// Re-checks canonical path, exact upstream origin match, no userinfo, no query,
/// and no fragment.
pub(crate) fn build_media_upstream_target(
    kind: MediaCapKind,
    immutable_locator: &str,
    upstreams: &Upstreams,
) -> std::result::Result<worker::Url, ()> {
    let encoded_path = encode_canonical_cap_path(immutable_locator).ok_or(())?;
    if !is_canonical_path(&encoded_path) {
        return Err(());
    }
    let raw_upstream = match kind {
        MediaCapKind::Image | MediaCapKind::Preview => upstreams.image.as_str(),
        MediaCapKind::Video => upstreams.video.as_str(),
    };
    let upstream = parse_upstream_origin(raw_upstream).map_err(|_| ())?;
    let target = format!("{upstream}{encoded_path}");

    let base_url = worker::Url::parse(&upstream).map_err(|_| ())?;
    let target_url = worker::Url::parse(&target).map_err(|_| ())?;
    if target_url.scheme() != base_url.scheme()
        || target_url.host_str() != base_url.host_str()
        || target_url.port_or_known_default() != base_url.port_or_known_default()
        || !target_url.username().is_empty()
        || target_url.password().is_some()
        || target_url.path() != encoded_path
        || target_url.query().is_some()
        || target_url.fragment().is_some()
    {
        return Err(());
    }
    Ok(target_url)
}

/// Returns `true` for the strict allowlist of read-only client headers forwarded
/// to private media origins (`IMAGE_UPSTREAM` / `VIDEO_UPSTREAM`).
///
/// For `MediaCapKind::Preview`, `Range`, `If-Range`, and conditional validator
/// headers (`If-None-Match`, `If-Modified-Since`, `If-Match`, `If-Unmodified-Since`)
/// are stripped so previews never request raw byte ranges or receive `304`/`412`
/// responses (previews always return `Cache-Control: private, no-store`).
pub(crate) fn is_allowed_media_request_header(kind: MediaCapKind, name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    if kind == MediaCapKind::Preview {
        return matches!(lower.as_str(), "accept" | "accept-encoding" | "user-agent");
    }
    matches!(
        lower.as_str(),
        "range"
            | "if-none-match"
            | "if-modified-since"
            | "if-range"
            | "accept"
            | "accept-encoding"
            | "user-agent"
    )
}

/// Returns the non-overridable preview blur config when `kind == Preview` and
/// `policy.fixed_blur_enabled` is true.
pub(crate) const fn resolve_preview_blur(
    kind: MediaCapKind,
    policy: &PublicSitePolicy,
) -> Option<PreviewBlurConfig> {
    if matches!(kind, MediaCapKind::Preview) && policy.fixed_blur_enabled {
        Some(LOCKED_PREVIEW_BLUR)
    } else {
        None
    }
}

/// Fail-closed verification that an upstream response for `MediaCapKind::Preview`
/// was actually transformed by Cloudflare Images (`cf.image`).
///
/// Rejects:
/// - Any non-`200 OK` status (3xx redirects, 4xx/5xx errors, 206 partial content)
/// - Any `cf-not-resized` header
/// - Missing `cf-resized` header (indicates Image Resizing unavailable / raw clear pass-through)
/// - Any `cf-resized` header containing `err=` or `internal=err` or lacking `internal=ok`
pub(crate) fn is_verified_preview_transform_response(
    status: StatusCode,
    headers: &HeaderMap,
) -> bool {
    if status != StatusCode::OK {
        return false;
    }
    if headers.contains_key("cf-not-resized") {
        return false;
    }
    let Some(raw) = headers.get("cf-resized").and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let lower = raw.trim().to_ascii_lowercase();
    if lower.is_empty() || lower.contains("err=") || lower.contains("internal=err") {
        return false;
    }
    lower.contains("internal=ok")
}
