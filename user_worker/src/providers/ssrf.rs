//! Strict SSRF defense for OIDC Discovery, JWKS, Token, and UserInfo URLs
//! (fixes H11).
//!
//! Rules enforced on EVERY admin-configured issuer and every discovered endpoint:
//! - `https://` scheme ONLY (rejects `http://`, `file://`, `data://`, etc.)
//! - Zero userinfo (`user:pass@`), zero fragment, default HTTPS port (443) only
//! - Rejects ALL IPv4 and IPv6 literals, including decimal/octal/hex obfuscations
//! - Rejects `localhost`, `*.localhost`, `*.local`, `*.internal`, `*.arpa`,
//!   `*.home.arpa`, single-label hosts, trailing-dot variants
//! - Exact issuer equality (`discovery.issuer == configured_issuer`)
//! - Approved endpoint origin pinning against `configured_issuer`
//! - Outbound fetches use `redirect: Manual` and reject any 3xx response!

use std::fmt;

use serde::Deserialize;
use url::{Host, Url};
use worker::{Fetch, Method, Request, RequestInit, RequestRedirect, Response};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SsrfError {
    InvalidUrl(&'static str),
    NonHttpsScheme,
    UserinfoForbidden,
    FragmentForbidden,
    NonDefaultPort,
    IpLiteralForbidden,
    PrivateOrLocalHost,
    IssuerMismatch,
    EndpointOriginNotPinned,
    RedirectBlocked(u16),
    HttpError(u16),
    FetchFailed(String),
}

impl fmt::Display for SsrfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidUrl(m) => write!(f, "invalid URL: {m}"),
            Self::NonHttpsScheme => write!(f, "only https:// URLs are permitted"),
            Self::UserinfoForbidden => write!(f, "URL userinfo is forbidden"),
            Self::FragmentForbidden => write!(f, "URL fragment is forbidden"),
            Self::NonDefaultPort => write!(f, "only default HTTPS port 443 is permitted"),
            Self::IpLiteralForbidden => write!(f, "IP literal hosts are forbidden"),
            Self::PrivateOrLocalHost => write!(f, "loopback, private, or local hosts are forbidden"),
            Self::IssuerMismatch => write!(f, "discovery issuer does not match configured issuer"),
            Self::EndpointOriginNotPinned => {
                write!(f, "discovered OIDC endpoint origin is not pinned to configured issuer")
            }
            Self::RedirectBlocked(code) => write!(f, "outbound redirect ({code}) rejected"),
            Self::HttpError(code) => write!(f, "upstream HTTP error {code}"),
            Self::FetchFailed(msg) => write!(f, "upstream fetch failed: {msg}"),
        }
    }
}

impl std::error::Error for SsrfError {}

const FORBIDDEN_HOST_SUFFIXES: &[&str] = &[
    ".localhost",
    ".local",
    ".internal",
    ".localdomain",
    ".arpa",
    ".home.arpa",
    ".lan",
    ".corp",
    ".intranet",
];

/// Multi-tenant or two-label public suffixes that MUST NOT be treated as a
/// shared organization parent domain when pinning discovery endpoints.
const NON_SHARED_PARENT_SUFFIXES: &[&str] = &[
    "co.uk",
    "org.uk",
    "gov.uk",
    "ac.uk",
    "com.au",
    "net.au",
    "org.au",
    "co.jp",
    "ne.jp",
    "or.jp",
    "com.cn",
    "com.br",
    "co.nz",
    "workers.dev",
    "pages.dev",
    "amazonaws.com",
    "cloudfront.net",
    "appspot.com",
    "azurewebsites.net",
    "herokuapp.com",
    "googleapis.com",
    "github.io",
    "netlify.app",
    "vercel.app",
];

/// Validate a URL for OIDC Discovery / JWKS / Token / UserInfo / Authorization.
pub fn validate_oidc_url(raw: &str) -> Result<Url, SsrfError> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.len() > 2048
        || trimmed.contains('\\')
        || trimmed.chars().any(char::is_control)
    {
        return Err(SsrfError::InvalidUrl("empty, oversized, backslash, or control chars"));
    }
    if !trimmed
        .get(..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"))
    {
        return Err(SsrfError::NonHttpsScheme);
    }
    // Reject dot-segment traversal before `Url::parse` normalizes/collapses `..` (case-insensitive scheme!).
    let after_scheme = &trimmed[8..];
    if let Some(slash_idx) = after_scheme.find('/') {
        let raw_path = after_scheme[slash_idx..]
            .split(['?', '#'])
            .next()
            .unwrap_or("");
        let lower_path = raw_path.to_ascii_lowercase();
        if lower_path.contains("%2e")
            || lower_path.contains("%2f")
            || lower_path.contains("%5c")
            || raw_path.split('/').any(|seg| seg == "." || seg == "..")
        {
            return Err(SsrfError::InvalidUrl("dot-segment path traversal forbidden"));
        }
    }
    let parsed = Url::parse(trimmed).map_err(|_| SsrfError::InvalidUrl("malformed URL"))?;

    if parsed.scheme() != "https" {
        return Err(SsrfError::NonHttpsScheme);
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(SsrfError::UserinfoForbidden);
    }
    if parsed.fragment().is_some() {
        return Err(SsrfError::FragmentForbidden);
    }
    if parsed.port().is_some_and(|p| p != 443) {
        return Err(SsrfError::NonDefaultPort);
    }

    let domain = match parsed.host() {
        Some(Host::Domain(d)) => d,
        Some(Host::Ipv4(_) | Host::Ipv6(_)) => return Err(SsrfError::IpLiteralForbidden),
        None => return Err(SsrfError::InvalidUrl("missing host")),
    };

    let lower = domain.to_ascii_lowercase();
    if lower.is_empty() || lower.ends_with('.') || lower.starts_with('.') || lower.contains("..") {
        return Err(SsrfError::PrivateOrLocalHost);
    }
    // Single-label hosts (including `localhost`, `metadata`, `db`, integer IPs like `2130706433`)
    if !lower.contains('.') {
        return Err(SsrfError::PrivateOrLocalHost);
    }
    if lower == "localhost"
        || FORBIDDEN_HOST_SUFFIXES
            .iter()
            .any(|sfx| lower.ends_with(sfx))
    {
        return Err(SsrfError::PrivateOrLocalHost);
    }

    // Reject obfuscated IPv4 dotted forms (decimal/hex/octal like `0x7f.0.0.1` or `0177.0.0.1`)
    let labels: Vec<&str> = lower.split('.').collect();
    if labels.iter().all(|lbl| is_numeric_ip_label(lbl)) {
        return Err(SsrfError::IpLiteralForbidden);
    }
    for lbl in &labels {
        if lbl.is_empty()
            || lbl.len() > 63
            || lbl.starts_with('-')
            || lbl.ends_with('-')
            || !lbl.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return Err(SsrfError::InvalidUrl("invalid DNS label"));
        }
    }
    // TLD cannot be purely numeric (RFC 3696 / ICANN)
    if labels
        .last()
        .is_some_and(|tld| tld.bytes().all(|b| b.is_ascii_digit()))
    {
        return Err(SsrfError::IpLiteralForbidden);
    }

    Ok(parsed)
}

fn is_numeric_ip_label(lbl: &str) -> bool {
    if lbl.is_empty() {
        return false;
    }
    if let Some(hex) = lbl.strip_prefix("0x") {
        !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit())
    } else {
        lbl.bytes().all(|b| b.is_ascii_digit())
    }
}

/// Checks whether `endpoint_url` has an approved origin pinned to `issuer_url`.
/// Allows exact host match, subdomains of `issuer_host`, or sibling subdomains
/// under the same non-public-suffix parent domain (e.g. `id.vendor.com` + `api.vendor.com`).
/// For Google's built-in OIDC issuer (`accounts.google.com`), explicitly pins only
/// Google's official OIDC hosts (`oauth2.googleapis.com`, `www.googleapis.com`,
/// `openidconnect.googleapis.com`).
pub fn is_endpoint_origin_pinned(issuer_url: &Url, endpoint_url: &Url) -> bool {
    if issuer_url.scheme() != "https" || endpoint_url.scheme() != "https" {
        return false;
    }
    let (Some(Host::Domain(iss_h)), Some(Host::Domain(ep_h))) =
        (issuer_url.host(), endpoint_url.host())
    else {
        return false;
    };
    let iss = iss_h.to_ascii_lowercase();
    let ep = ep_h.to_ascii_lowercase();
    if iss == ep {
        return true;
    }
    // Google's real OIDC discovery (`https://accounts.google.com`) publishes endpoints
    // on these exact `googleapis.com` hosts. Pin them explicitly ONLY for Google while
    // keeping `googleapis.com` in `NON_SHARED_PARENT_SUFFIXES` for all other issuers.
    if iss == "accounts.google.com"
        && matches!(
            ep.as_str(),
            "oauth2.googleapis.com" | "www.googleapis.com" | "openidconnect.googleapis.com"
        )
    {
        return true;
    }
    // Endpoint is a subdomain of issuer (e.g. issuer = yoti.com, ep = api.yoti.com)
    if ep.ends_with(&format!(".{iss}")) {
        return true;
    }
    // Sibling subdomains sharing the same registrable 2-label parent domain,
    // excluding public/multi-tenant suffixes.
    let iss_parts: Vec<&str> = iss.split('.').collect();
    let ep_parts: Vec<&str> = ep.split('.').collect();
    if iss_parts.len() >= 2 && ep_parts.len() >= 2 {
        let iss_parent = format!(
            "{}.{}",
            iss_parts[iss_parts.len() - 2],
            iss_parts[iss_parts.len() - 1]
        );
        let ep_parent = format!(
            "{}.{}",
            ep_parts[ep_parts.len() - 2],
            ep_parts[ep_parts.len() - 1]
        );
        if iss_parent == ep_parent && !NON_SHARED_PARENT_SUFFIXES.contains(&iss_parent.as_str()) {
            return true;
        }
    }
    false
}

/// Build the OIDC discovery metadata URL for a validated issuer.
pub fn discovery_url_for_issuer(configured_issuer: &str) -> Result<Url, SsrfError> {
    let base = validate_oidc_url(configured_issuer)?;
    let trimmed = base.as_str().trim_end_matches('/');
    validate_oidc_url(&format!("{trimmed}/.well-known/openid-configuration"))
}

#[derive(Debug, Clone, Deserialize)]
pub struct OidcDiscoveryDoc {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    #[serde(default)]
    pub userinfo_endpoint: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ValidatedOidcEndpoints {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub userinfo_endpoint: Option<String>,
}

/// Validate a fetched OIDC discovery document against `configured_issuer`:
/// enforces exact `discovery.issuer == configured_issuer`, strict HTTPS/SSRF
/// checks on every endpoint, and approved origin pinning!
pub fn validate_discovery_document(
    configured_issuer: &str,
    doc: &OidcDiscoveryDoc,
) -> Result<ValidatedOidcEndpoints, SsrfError> {
    let issuer_url = validate_oidc_url(configured_issuer)?;
    if doc.issuer.trim() != configured_issuer.trim() {
        return Err(SsrfError::IssuerMismatch);
    }

    let auth_url = validate_oidc_url(&doc.authorization_endpoint)?;
    let token_url = validate_oidc_url(&doc.token_endpoint)?;
    let jwks_url = validate_oidc_url(&doc.jwks_uri)?;
    if !is_endpoint_origin_pinned(&issuer_url, &auth_url)
        || !is_endpoint_origin_pinned(&issuer_url, &token_url)
        || !is_endpoint_origin_pinned(&issuer_url, &jwks_url)
    {
        return Err(SsrfError::EndpointOriginNotPinned);
    }

    let userinfo_endpoint = match doc.userinfo_endpoint.as_deref() {
        Some(raw) if !raw.trim().is_empty() => {
            let ui_url = validate_oidc_url(raw)?;
            if !is_endpoint_origin_pinned(&issuer_url, &ui_url) {
                return Err(SsrfError::EndpointOriginNotPinned);
            }
            Some(ui_url.to_string())
        }
        _ => None,
    };

    Ok(ValidatedOidcEndpoints {
        issuer: doc.issuer.trim().to_string(),
        authorization_endpoint: auth_url.to_string(),
        token_endpoint: token_url.to_string(),
        jwks_uri: jwks_url.to_string(),
        userinfo_endpoint,
    })
}

/// Execute an SSRF-hardened outbound HTTP fetch:
/// - Validates URL via [`validate_oidc_url`]
/// - Forces `redirect: RequestRedirect::Manual`
/// - Explicitly rejects ANY `3xx` redirect status so upstream redirects can NEVER
///   escape the allowlist into internal/private networks!
pub async fn fetch_https_no_redirect(
    url: &str,
    method: Method,
    headers: &[(&str, &str)],
    body: Option<String>,
) -> Result<Response, SsrfError> {
    let validated = validate_oidc_url(url)?;
    let mut init = RequestInit::new();
    init.with_method(method);
    init.with_redirect(RequestRedirect::Manual);
    for &(k, v) in headers {
        init.headers
            .set(k, v)
            .map_err(|e| SsrfError::FetchFailed(e.to_string()))?;
    }
    if let Some(b) = body {
        init.with_body(Some(b.into()));
    }
    let req = Request::new_with_init(validated.as_str(), &init)
        .map_err(|e| SsrfError::FetchFailed(e.to_string()))?;
    let resp = Fetch::Request(req)
        .send()
        .await
        .map_err(|e| SsrfError::FetchFailed(e.to_string()))?;
    let code = resp.status_code();
    if (300..400).contains(&code) {
        return Err(SsrfError::RedirectBlocked(code));
    }
    if !(200..300).contains(&code) {
        return Err(SsrfError::HttpError(code));
    }
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssrf_validator_accepts_valid_https_oidc_urls() {
        assert!(validate_oidc_url("https://id.yoti.com").is_ok());
        assert!(validate_oidc_url("https://auth.example.org/realms/main").is_ok());
        assert!(validate_oidc_url("https://auth.example.org:443/.well-known/jwks.json").is_ok());
    }

    #[test]
    fn ssrf_validator_rejects_http_userinfo_ips_private_hosts_and_ports() {
        let bad = [
            "http://auth.example.org",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "https://user:pass@auth.example.org",
            "https://user@auth.example.org",
            "https://auth.example.org:8443/jwks",
            "https://auth.example.org/#frag",
            "https://127.0.0.1/jwks",
            "https://169.254.169.254/latest/meta-data/",
            "https://10.0.0.1/internal",
            "https://172.16.0.5/internal",
            "https://192.168.1.1/admin",
            "https://0.0.0.0/",
            "https://[::1]/jwks",
            "https://[fe80::1]/jwks",
            "https://[fc00::1]/jwks",
            "https://2130706433/",
            "https://0x7f000001/",
            "https://0x7f.0.0.1/",
            "https://localhost/jwks",
            "https://sub.localhost/jwks",
            "https://localhost./jwks",
            "https://metadata.google.internal/computeMetadata/v1/",
            "https://printer.local/jwks",
            "https://service.home.arpa/jwks",
            "https://intranet/",
            "Https://auth.example.org/a/../secret",
            "HTTPS://auth.example.org/a/%2e%2e/secret",
            "https://auth.example.org/a\\b",
        ];
        for url in bad {
            assert!(
                validate_oidc_url(url).is_err(),
                "SSRF URL MUST be rejected: {url}"
            );
        }
    }

    #[test]
    fn discovery_validation_enforces_exact_issuer_and_origin_pinning() {
        let configured = "https://id.vendor.example";
        let good = OidcDiscoveryDoc {
            issuer: configured.into(),
            authorization_endpoint: "https://id.vendor.example/oauth/authorize".into(),
            token_endpoint: "https://api.vendor.example/oauth/token".into(),
            jwks_uri: "https://keys.vendor.example/.well-known/jwks.json".into(),
            userinfo_endpoint: Some("https://api.vendor.example/userinfo".into()),
        };
        assert!(validate_discovery_document(configured, &good).is_ok());

        // Issuer mismatch rejected
        let wrong_iss = OidcDiscoveryDoc {
            issuer: "https://other.vendor.example".into(),
            ..good.clone()
        };
        assert_eq!(
            validate_discovery_document(configured, &wrong_iss).unwrap_err(),
            SsrfError::IssuerMismatch
        );

        // Off-origin jwks_uri rejected
        let evil_jwks = OidcDiscoveryDoc {
            jwks_uri: "https://attacker.evil.org/jwks.json".into(),
            ..good.clone()
        };
        assert_eq!(
            validate_discovery_document(configured, &evil_jwks).unwrap_err(),
            SsrfError::EndpointOriginNotPinned
        );

        // Multi-tenant suffix (workers.dev) MUST NOT allow sibling tenants!
        let mt_issuer = "https://good-idp.workers.dev";
        let mt_doc = OidcDiscoveryDoc {
            issuer: mt_issuer.into(),
            authorization_endpoint: "https://good-idp.workers.dev/authorize".into(),
            token_endpoint: "https://evil-idp.workers.dev/token".into(),
            jwks_uri: "https://good-idp.workers.dev/jwks.json".into(),
            userinfo_endpoint: None,
        };
        assert_eq!(
            validate_discovery_document(mt_issuer, &mt_doc).unwrap_err(),
            SsrfError::EndpointOriginNotPinned
        );

        // Google's real discovery document shape (accounts.google.com -> pinned googleapis.com hosts)
        let google_issuer = "https://accounts.google.com";
        let google_doc = OidcDiscoveryDoc {
            issuer: google_issuer.into(),
            authorization_endpoint: "https://accounts.google.com/o/oauth2/v2/auth".into(),
            token_endpoint: "https://oauth2.googleapis.com/token".into(),
            jwks_uri: "https://www.googleapis.com/oauth2/v3/certs".into(),
            userinfo_endpoint: Some("https://openidconnect.googleapis.com/v1/userinfo".into()),
        };
        assert!(validate_discovery_document(google_issuer, &google_doc).is_ok());

        // Non-pinned googleapis host or third-party host on Google MUST still be rejected
        let google_bad = OidcDiscoveryDoc {
            jwks_uri: "https://storage.googleapis.com/attacker/jwks.json".into(),
            ..google_doc
        };
        assert_eq!(
            validate_discovery_document(google_issuer, &google_bad).unwrap_err(),
            SsrfError::EndpointOriginNotPinned
        );
    }
}
