//! Legal & policy document configuration and built-in default Markdown templates.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const DEFAULT_TERMS_MD: &str = r#"# Terms of Service

Welcome to this gallery service ("the Service"). By accessing or using the Service, you agree to be bound by these Terms of Service.

## 1. Eligibility & Age Requirements
- You must comply with all applicable local, national, and international laws when accessing the Service.
- Where age-restricted content categories or age-verification policies are enabled by the site administrator, you must be at least 18 years old (or the age of majority in your jurisdiction, whichever is higher) and satisfy the active age-assurance policy before viewing restricted material.

## 2. Accounts, Authentication & Payments
- You are responsible for maintaining the security of your linked authentication providers, sessions, and payment wallets.
- Balances, points, and subscription quotas are non-transferable unless explicitly provided by the operator.
- We reserve the right to suspend or revoke sessions or accounts that violate these Terms, attempt to bypass content safety or metering controls, or engage in abusive automation.

## 3. Acceptable Use & Prohibited Conduct
You agree not to:
- Circumvent, disable, or interfere with content filtering, age gates, capability tokens, rate limits, or geographic restrictions.
- Scrape, mirror, or redistribute media in violation of applicable law or third-party rights.
- Submit abusive, fraudulent, or malicious reports or payloads.

## 4. Intellectual Property & Takedowns
All hosted media remains the property of its respective rights holders. Copyright owners may submit takedown notices as described in our [DMCA & Copyright Policy](/dmca).

## 5. Disclaimers & Changes
The Service is provided "as is" without warranties of any kind. When these Terms are materially updated, the Terms version increases and you may be asked to review and accept the updated Terms before continuing to access restricted features.
"#;

pub const DEFAULT_PRIVACY_MD: &str = r#"# Privacy Policy

This Privacy Policy explains what information the Service processes and how it is handled.

## 1. Information We Collect
- **Account & Identity Records**: When you sign in, we store your internal account identifier, linked authentication provider identifiers (subject/issuer), optional display name or contact email, and any recorded age-assurance level or Terms acceptance timestamp.
- **Session & Security State**: Active session identifiers, safety switcher preferences, safe-mode status, and anti-abuse rate-limiting counters are stored to enforce revocable sessions and service integrity.
- **Billing & Payment Records**: If crypto top-ups or plans are enabled, we record wallet addresses, transaction hashes, token amounts, and credited balances.
- **Content Reports**: Reports submitted by visitors record the target item, reason category, optional note, and a salted reporter key for deduplication and spam prevention.

## 2. Cookies & Local State
- Strictly necessary `HttpOnly`, `Secure` cookies are used for session authentication and short-lived login transactions.
- Optional UI preferences (such as layout density or Safe Mode broadcast synchronization across browser tabs) may be stored in browser storage.

## 3. Data Sharing & Retention
- We do not sell personal data. Third-party identity or age-assurance providers process authentication requests under their respective privacy policies.
- Session records expire automatically or upon sign-out. Payment ledger entries and moderation audit logs may be retained as required for accounting, security, and legal compliance.

## 4. Your Choices
- You may sign out at any time to immediately revoke your active session, manage linked identities on your account page, or contact the site operator to request account deletion.
"#;

pub const DEFAULT_DMCA_MD: &str = r#"# DMCA & Copyright Policy

We respect the intellectual property rights of creators and respond promptly to valid copyright takedown notices.

## 1. Submitting a Takedown Notice
If you believe that material accessible through the Service infringes your copyright, please submit a written notice containing:
1. Identification of the copyrighted work claimed to have been infringed.
2. Identification of the specific material claimed to be infringing, including the exact URL(s) or item ID(s) on the Service.
3. Your contact information (full name, mailing address, telephone number, and email address).
4. A statement that you have a good-faith belief that use of the material in the manner complained of is not authorized by the copyright owner, its agent, or the law.
5. A statement, made under penalty of perjury, that the information in your notice is accurate and that you are the copyright owner or authorized to act on the owner's behalf.
6. Your physical or electronic signature.

## 2. Counter-Notification
If material was removed in error, the affected party may submit a written counter-notification identifying the removed item, stating under penalty of perjury that the removal was a mistake or misidentification, and providing contact and jurisdictional consent information.

## 3. Repeat Infringers
In appropriate circumstances, we disable or terminate access for accounts associated with repeat infringement.
"#;

pub const DEFAULT_CONTENT_POLICY_MD: &str = r#"# Content Policy

This Content Policy describes how media is categorized, gated, and moderated on the Service.

## 1. Automated Classification & Safety Rules
- Media items are evaluated server-side against configured metadata and tag rules before pages or media URLs are delivered.
- Items matching active **Switcher** rules remain locked until an eligible visitor explicitly unlocks the relevant category.
- Items matching **Spoiler Blur** rules are masked by default and may require explicit reveal.
- Unclassified media fails closed (locked) whenever restrictive Switcher rules are active, unless explicitly overridden by site policy.

## 2. Strictly Prohibited Content
The following content is strictly prohibited and will be removed upon discovery or report:
- Non-consensual intimate imagery, exploitation, or any illegal material under applicable law.
- Content facilitating real-world violence, self-harm, or illegal acts.

## 3. Reporting Content
Visitors can flag any post, image, or video using the in-app **Report** dialog. Reports are deduplicated and reviewed by site administrators.
"#;

/// Computes the canonical lowercase hex SHA-256 digest of a Markdown Terms document.
pub fn compute_terms_digest(terms_md: &str) -> String {
    let digest = Sha256::digest(terms_md.as_bytes());
    hex_lower(&digest)
}

pub(crate) fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct LegalDocConfig {
    pub terms_version: u32,
    pub terms_digest: String,
    pub terms_md: String,
    pub privacy_md: String,
    pub dmca_md: String,
    pub content_policy_md: String,
    pub notice_banner_md: String,
    pub notice_banner_enabled: bool,
    pub rta_meta_enabled: bool,
    pub noindex_restricted: bool,
}

impl Default for LegalDocConfig {
    fn default() -> Self {
        Self {
            terms_version: 1,
            terms_digest: compute_terms_digest(DEFAULT_TERMS_MD),
            terms_md: DEFAULT_TERMS_MD.to_string(),
            privacy_md: DEFAULT_PRIVACY_MD.to_string(),
            dmca_md: DEFAULT_DMCA_MD.to_string(),
            content_policy_md: DEFAULT_CONTENT_POLICY_MD.to_string(),
            notice_banner_md: String::new(),
            notice_banner_enabled: false,
            rta_meta_enabled: false,
            noindex_restricted: false,
        }
    }
}

impl LegalDocConfig {
    /// Recomputes `terms_digest` from `terms_md`.
    pub fn refresh_terms_digest(&mut self) {
        self.terms_digest = compute_terms_digest(&self.terms_md);
    }
}
