//! Server-side Markdown -> strict allowlist sanitized HTML renderer for legal
//! documents (`/terms`, `/privacy`, `/dmca`, `/content-policy`) and notice banners.

use std::collections::{HashMap, HashSet};

use ammonia::{Builder, UrlRelative};
use pulldown_cmark::{Options, Parser, html};

/// Strict Content-Security-Policy header applied to rendered legal document routes
/// (disallows all script execution, objects, framing, and form submissions).
pub const LEGAL_PAGE_CSP: &str = "default-src 'none'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";

/// Render Markdown into HTML and sanitize through a strict `ammonia` HTML allowlist.
///
/// Strips all `<script>`, `<iframe>`, `<svg>`, `<style>`, `<form>`, event-handler
/// attributes (`on*`), and non-allowlisted URI schemes (`javascript:`, `data:`, etc.).
pub fn render_sanitized_markdown(markdown: &str) -> String {
    let mut opts = Options::empty();
    opts.insert(Options::ENABLE_TABLES);
    opts.insert(Options::ENABLE_STRIKETHROUGH);
    opts.insert(Options::ENABLE_TASKLISTS);

    let parser = Parser::new_ext(markdown, opts);
    let mut raw_html = String::with_capacity(markdown.len().saturating_mul(2));
    html::push_html(&mut raw_html, parser);

    sanitize_html_strict(&raw_html)
}

/// Sanitize raw HTML through a strict allowlist (used by both legal documents
/// and the dismissible site notice banner).
pub fn sanitize_html_strict(raw_html: &str) -> String {
    let allowed_tags: HashSet<&str> = [
        "a",
        "b",
        "blockquote",
        "br",
        "code",
        "del",
        "div",
        "em",
        "h1",
        "h2",
        "h3",
        "h4",
        "h5",
        "h6",
        "hr",
        "i",
        "li",
        "ol",
        "p",
        "pre",
        "s",
        "span",
        "strong",
        "table",
        "tbody",
        "td",
        "th",
        "thead",
        "tr",
        "ul",
    ]
    .into_iter()
    .collect();

    let mut tag_attributes: HashMap<&str, HashSet<&str>> = HashMap::new();
    tag_attributes.insert("a", ["href", "title"].into_iter().collect());
    tag_attributes.insert("th", ["align"].into_iter().collect());
    tag_attributes.insert("td", ["align"].into_iter().collect());

    let url_schemes: HashSet<&str> = ["http", "https", "mailto"].into_iter().collect();
    let clean_content_tags: HashSet<&str> = [
        "script", "style", "iframe", "svg", "math", "noscript", "template",
    ]
    .into_iter()
    .collect();

    Builder::empty()
        .tags(allowed_tags)
        .clean_content_tags(clean_content_tags)
        .generic_attributes(HashSet::new())
        .tag_attributes(tag_attributes)
        .url_schemes(url_schemes)
        .url_relative(UrlRelative::PassThrough)
        .link_rel(Some("noopener noreferrer nofollow"))
        .clean(raw_html)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn renders_safe_markdown_and_preserves_internal_links() {
        let md = "# Terms of Service\n\nRead our [DMCA Policy](/dmca) and [site](https://example.com).\n\n- **Rule 1**\n- *Rule 2*";
        let out = render_sanitized_markdown(md);
        assert!(out.contains("<h1>Terms of Service</h1>"));
        assert!(out.contains(r#"href="/dmca""#));
        assert!(out.contains(r#"href="https://example.com""#));
        assert!(out.contains("noopener noreferrer nofollow"));
        assert!(out.contains("<strong>Rule 1</strong>"));
    }

    #[test]
    fn strips_xss_scripts_handlers_and_javascript_urls() {
        let malicious = r#"
# Legal

<script>alert('xss')</script>

<img src="x" onerror="alert(1)">

<svg onload="alert(2)"><script>alert(3)</script></svg>

<iframe src="https://evil.example"></iframe>

<a href="javascript:alert(4)" onclick="alert(5)">Click me</a>

[bad link](javascript:alert(6))

[data link](data:text/html,evil)

<style>body { display: none; }</style>

<form action="https://evil.example"><input name="x"></form>
"#;
        let out = render_sanitized_markdown(malicious);
        let lower = out.to_ascii_lowercase();
        assert!(!lower.contains("<script"), "output was: {out}");
        assert!(!lower.contains("alert("), "output was: {out}");
        assert!(!lower.contains("onerror"), "output was: {out}");
        assert!(!lower.contains("onload"), "output was: {out}");
        assert!(!lower.contains("onclick"), "output was: {out}");
        assert!(!lower.contains("javascript:"), "output was: {out}");
        assert!(!lower.contains("data:text/html"), "output was: {out}");
        assert!(!lower.contains("<iframe"), "output was: {out}");
        assert!(!lower.contains("<svg"), "output was: {out}");
        assert!(!lower.contains("<style"), "output was: {out}");
        assert!(!lower.contains("<form"), "output was: {out}");
        assert!(!lower.contains("<input"), "output was: {out}");
        assert!(out.contains("<h1>Legal</h1>"));
        assert!(out.contains("Click me"));
        assert!(out.contains("bad link"));
        assert!(out.contains("data link"));
    }
}
