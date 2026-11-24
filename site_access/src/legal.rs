//! Legal & policy document configuration and built-in default Markdown templates.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const DEFAULT_TERMS_MD: &str = r#"# Terms of Service

By accessing or using this gallery service ("the Service"), you agree to these Terms of Service as well as our [Privacy Policy](/privacy) and [Content Policy](/content-policy). If you do not agree, do not use the Service.

## 1. Eligibility, Age Requirements & Regional Compliance
- You must comply with all applicable local, national, and international laws when accessing the Service.
- Where age-restricted categories or age-verification policies are enabled by the site operator, you confirm that you are at least 18 years old (or the age of majority in your jurisdiction, whichever is higher), are legally permitted to view adult material where you reside, and will satisfy the active age-assurance policy before unlocking restricted content.
- Access to the Service or specific restricted categories may be blocked in jurisdictions where such material is prohibited by law. You agree not to circumvent geographic blocks or age gates.

## 2. Accounts, Sessions & Preferences
- You are responsible for safeguarding your linked sign-in providers, active sessions, and linked payment wallets.
- You may manage linked sign-in methods, content safety visibility preferences, and active sessions in [Account Settings](/user/account).
- We may suspend or revoke sessions or accounts that violate these Terms, attempt to bypass content safety, metering, or access controls, or engage in abusive automation.

## 3. Credits, Subscriptions & Payments (Where Enabled)
- Points, daily free allowances, and subscription quotas apply solely within the Service and are non-transferable unless explicitly stated by the operator.
- Where cryptocurrency or point top-ups are enabled, confirmed on-chain transactions are final and non-refundable except as required by applicable law. You are responsible for verifying deposit addresses, networks, and transaction fees before sending funds.

## 4. Acceptable Use & Prohibited Conduct
You agree not to:
- Circumvent, disable, or interfere with content filtering, blurred previews, age gates, short-lived media capability tokens, rate limits, or geographic restrictions.
- Scrape, mirror, hotlink, or redistribute hosted media in violation of applicable law or third-party rights.
- Submit abusive, fraudulent, or malicious reports or payloads.

## 5. Intellectual Property & Takedowns
All hosted media remains the property of its respective rights holders. Copyright owners or their authorized agents may submit takedown requests as described in our [DMCA & Copyright Policy](/dmca).

## 6. Disclaimers, Limitation of Liability & Updates
- The Service is provided "as is" and "as available" without warranties of any kind. Automated content tagging and safety classification are best-effort; if you encounter misclassified or prohibited material, please flag it using the in-app **Report** dialog.
- To the maximum extent permitted by law, the Service operator is not liable for indirect, incidental, or consequential damages arising from your use of or inability to use the Service.
- When these Terms are materially updated, the Terms version increases and you may be asked to review and accept the updated Terms before continuing to access restricted features.
"#;

pub const DEFAULT_PRIVACY_MD: &str = r#"# Privacy Policy

This Privacy Policy explains what information this gallery service ("the Service") processes, how it is used, and the choices available to you.

## 1. Information We Process
- **Account & Identity Records**: When you sign in, we store your internal account identifier, linked sign-in provider identifiers (such as OIDC/OAuth subject and issuer, verified email address, Telegram ID, or wallet address), optional display name, recorded age-assurance level, and Terms acceptance version and timestamp.
- **Preferences, Favorites & Sessions**: We store your saved favorites, content safety opt-in preferences, active revocable session records, and anti-abuse rate-limiting counters to operate your account and protect service integrity.
- **Billing & Payment Records (Where Enabled)**: If top-ups or subscription plans are enabled, we record linked payment wallet addresses, transaction hashes, token amounts, and credited balances.
- **Content Reports**: Reports submitted through the in-app **Report** dialog record the target item ID, reason category, optional note, and a keyed cryptographic hash of the reporter identifier for deduplication and abuse prevention. Raw visitor IP addresses are not stored in report records.
- **Edge Security & Geographic Enforcement**: Request country codes provided by the edge network are evaluated transiently per request to enforce configured geographic restrictions and per-rule regional exclusions.

## 2. Cookies & Browser Storage
- We use strictly necessary `HttpOnly` cookies (marked `Secure` over HTTPS) for authenticated sessions, short-lived sign-in challenges, and short-lived anonymous reveal sessions required to issue time-limited click-to-reveal media capabilities.
- Browser `localStorage` is used only for non-tracking UI preferences such as gallery layout density and site notice banner dismissal.
- We do not sell personal data or place third-party advertising trackers.

## 3. Third-Party Services & Retention
- Third-party identity or age-assurance providers you choose to sign in with process authentication requests under their respective privacy policies.
- Sessions expire automatically or immediately upon sign-out. Payment ledger entries and moderation audit logs may be retained as required for accounting, security, and legal compliance.

## 4. Your Choices
- You can manage linked sign-in methods, update content safety preferences, or sign out (immediately revoking your current session) at any time in [Account Settings](/user/account).
- To request account deletion or data inquiries, please contact the site operator.
"#;

pub const DEFAULT_NOTICE_BANNER_MD: &str = "This gallery hosts community-tagged artwork. Review our [Content Policy](/content-policy) or adjust your content preferences in [Account Settings](/user/account).";

pub const DEFAULT_DMCA_MD: &str = r#"# DMCA & Copyright Policy

We respect the intellectual property rights of creators and respond promptly to valid copyright takedown requests.

## 1. Submitting a Takedown Notice
Copyright owners or their authorized agents can report allegedly infringing material directly on any post, image, or video using the in-app **Report** button (select **Copyright / DMCA** and include your contact email and claim details), or submit a written notice through the site operator's designated copyright contact channel containing:
1. Identification of the copyrighted work claimed to have been infringed.
2. Identification of the specific material claimed to be infringing, including the exact URL(s) or item ID(s) on the Service.
3. Your contact information (full name, mailing address, telephone number, and email address).
4. A statement that you have a good-faith belief that use of the material in the manner complained of is not authorized by the copyright owner, its agent, or the law.
5. A statement, made under penalty of perjury, that the information in your notice is accurate and that you are the copyright owner or authorized to act on the owner's behalf.
6. Your physical or electronic signature.

## 2. Counter-Notification
If material was removed or disabled in error, the affected party may submit a written counter-notification identifying the removed item, stating under penalty of perjury that the removal was the result of mistake or misidentification, and providing contact information and consent to jurisdiction as required by applicable law.

## 3. Repeat Infringers
In appropriate circumstances, we may disable or terminate access for accounts associated with repeat infringement.
"#;

pub const DEFAULT_CONTENT_POLICY_MD: &str = r#"# Content Policy

This Content Policy explains how media is categorized, filtered, and moderated on this gallery service ("the Service").

## 1. Automated Classification & Content Safety Rules
- Media items are evaluated server-side against automated tag scores, post tags, and author metadata before gallery pages or media URLs are delivered.
- **Blocked Categories**: Items matching an active **Block** rule are replaced with a locked placeholder card; no clear image or video URLs are exposed unless an eligible visitor explicitly enables that category in [Account Settings](/user/account).
- **Blurred Categories**: Items matching an active **Blur** rule are hidden behind a blurred preview by default. Eligible visitors may click to reveal an individual item or enable automatic reveal in [Account Settings](/user/account).
- **Unclassified Media**: While Content Safety is enabled, newly ingested or unindexed items fail closed behind a locked placeholder until classification completes, unless configured otherwise by the site operator.

## 2. Age-Restricted & Regional Controls
- Where enabled by the site operator, unlocking mature or R-18 categories requires signing in, confirming 18+ eligibility under the active age-verification policy, and accepting the current [Terms of Service](/terms).
- Access to the Service or specific restricted categories may be restricted in jurisdictions where such material is prohibited by law.

## 3. Strictly Prohibited Content
The following material is strictly prohibited and will be removed upon discovery or report:
- Any depiction of minors in sexual or exploitative contexts (CSAM / CSEM).
- Non-consensual intimate imagery, private imagery shared without consent, or exploitative deepfakes.
- Content facilitating real-world violence, terrorism, self-harm, or illegal acts.
- Any material unlawful under applicable law.

## 4. Reporting Content
Visitors can flag any post, image, or video using the in-app **Report** dialog for prohibited content, suspected underage material, non-consensual imagery, extreme violence or gore, copyright/DMCA claims, or misclassified safety tags. Reports are deduplicated and reviewed by site administrators. Copyright owners may also consult our [DMCA & Copyright Policy](/dmca).
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

    /// Returns the effective notice banner Markdown when enabled, falling back
    /// to [`DEFAULT_NOTICE_BANNER_MD`] if `notice_banner_md` is blank.
    pub fn effective_notice_banner_md(&self) -> Option<&str> {
        if !self.notice_banner_enabled {
            return None;
        }
        let trimmed = self.notice_banner_md.trim();
        if trimmed.is_empty() {
            Some(DEFAULT_NOTICE_BANNER_MD)
        } else {
            Some(trimmed)
        }
    }
}
