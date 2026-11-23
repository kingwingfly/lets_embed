//! Capability-based `/media/{image,video,preview}/{id}?cap=...` route parsing,
//! authorization, canonical upstream URL construction, and locked server-side
//! Cloudflare Images blur configuration.

use serde::{Deserialize, Serialize};
use site_access::{MEDIA_CAP_ANON_SUB, MediaCapKind, MediaCapability, PublicSitePolicy};

use crate::auth::{ADMIN_VIEW_SUB, LiveSession, admin_eligible_switchers};
use crate::http_util::{
    Upstreams, is_canonical_path, is_rfc3986_unreserved, parse_upstream_origin, percent_decode,
};

/// Hardcoded, non-overridable Cloudflare Worker `cf.image` parameters used for
/// server-side blurred previews when `policy.cloudflare_images_blur` is enabled.
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

/// Authorizes a cryptographically verified [`MediaCapability`] against the
/// caller's live session context and current policy BEFORE any billing or
/// budget check occurs.
pub(crate) fn authorize_media_capability(
    cap: &MediaCapability,
    auth: Option<&LiveSession>,
    is_admin_view: bool,
    policy: &PublicSitePolicy,
) -> bool {
    if !cap.requires_live_session_check() {
        // Anonymous safe capability (`sub == "anon"` and `req_switchers.is_empty()`).
        // `verify_media_capability` has already verified `cap.rev >= policy.min_enforce_rev`.
        return true;
    }

    if cap.sub == ADMIN_VIEW_SUB {
        if !is_admin_view || cap.sid.is_some() {
            return false;
        }
        if let Some(live) = auth
            && live.ctx.safe_mode
        {
            return false;
        }
        let allowed = admin_eligible_switchers(policy);
        return cap
            .req_switchers
            .iter()
            .all(|req_sw| allowed.iter().any(|sw| sw == req_sw));
    }

    let Some(live) = auth else {
        return false;
    };
    if !live.ctx.is_authenticated() || live.ctx.safe_mode {
        return false;
    }
    if cap.sub != live.session.user_id() {
        return false;
    }
    if cap.sid.as_deref() != live.session.sid() {
        return false;
    }
    cap.req_switchers
        .iter()
        .all(|req_sw| live.eligible_switchers.iter().any(|sw| sw == req_sw))
}

/// Validates and canonicalizes a relative `cap.path` into a leading-slash
/// RFC 3986 path safe to join onto `IMAGE_UPSTREAM` or `VIDEO_UPSTREAM`.
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
    cap_path: &str,
    upstreams: &Upstreams,
) -> std::result::Result<worker::Url, ()> {
    let encoded_path = encode_canonical_cap_path(cap_path).ok_or(())?;
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
pub(crate) fn is_allowed_media_request_header(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "range"
            | "if-none-match"
            | "if-modified-since"
            | "if-range"
            | "if-match"
            | "if-unmodified-since"
            | "accept"
            | "accept-encoding"
            | "user-agent"
    )
}

/// Returns the non-overridable preview blur config when `kind == Preview` and
/// `policy.cloudflare_images_blur` is enabled.
pub(crate) const fn resolve_preview_blur(
    kind: MediaCapKind,
    policy: &PublicSitePolicy,
) -> Option<PreviewBlurConfig> {
    if matches!(kind, MediaCapKind::Preview) && policy.cloudflare_images_blur {
        Some(LOCKED_PREVIEW_BLUR)
    } else {
        None
    }
}

/// Explicit sanity check that `MEDIA_CAP_ANON_SUB` never collides with `ADMIN_VIEW_SUB`.
const _: () = assert!(
    MEDIA_CAP_ANON_SUB.len() != ADMIN_VIEW_SUB.len()
        || MEDIA_CAP_ANON_SUB.as_bytes()[0] != ADMIN_VIEW_SUB.as_bytes()[0]
);
