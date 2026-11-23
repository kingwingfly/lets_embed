//! Public policy, content safety, auth provider capability, and session context models.
//!
//! `PublicSitePolicy` is a strict allowlist struct with ZERO secret fields so it
//! can be published safely to `SitePolicyDO`, `gateway_worker`, `lets-embed-web`,
//! and public clients.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::legal::{LegalDocConfig, hex_lower};

pub const DEFAULT_PANIC_SHORTCUT: &str = "Shift+S";

/// Canonical WD-Tagger vocabulary tags used by built-in safety presets and
/// category-9 rating persistence.
pub const BUILTIN_SAFETY_VOCABULARY_TAGS: &[&str] = &[
    // Category 9 ratings
    "general",
    "sensitive",
    "questionable",
    "explicit",
    // R-18 / Explicit preset
    "nude",
    "nipples",
    "pussy",
    "penis",
    "sex",
    "uncensored",
    "censored",
    "topless",
    "bottomless",
    // Suggestive / Ecchi preset
    "lingerie",
    "bikini",
    "underwear",
    "panties",
    "cleavage",
    "bdsm",
    // Blood / Violence preset
    "blood",
];

// ---------------------------------------------------------------------------
// Policy Enums
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgeVerificationPolicy {
    #[default]
    Off,
    SelfAttestation,
    StrictProviderVerified18,
}

impl AgeVerificationPolicy {
    /// Monotonic strictness rank (`0 = Off`, `1 = SelfAttestation`, `2 = StrictProviderVerified18`).
    pub const fn strictness_rank(self) -> u8 {
        match self {
            Self::Off => 0,
            Self::SelfAttestation => 1,
            Self::StrictProviderVerified18 => 2,
        }
    }

    pub const fn is_strict(self) -> bool {
        matches!(self, Self::StrictProviderVerified18)
    }

    pub const fn requires_adult_assurance(self) -> bool {
        !matches!(self, Self::Off)
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgeGateTrigger {
    #[default]
    Off,
    JustInTime,
    SiteWideSplash,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleMode {
    #[default]
    Switcher,
    SpoilerBlur,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaceholderPreset {
    R18,
    Blood,
    Sensitive,
    #[default]
    Custom,
}

impl PlaceholderPreset {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::R18 => "r18",
            Self::Blood => "blood",
            Self::Sensitive => "sensitive",
            Self::Custom => "custom",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnclassifiedMode {
    #[default]
    LockFailClosed,
    Allow,
}

// ---------------------------------------------------------------------------
// Safety Rule, Similarity & Geo Models
// ---------------------------------------------------------------------------

const fn default_rule_min_score() -> f32 {
    0.5
}

const fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SafetyRuleConfig {
    pub id: String,
    pub name: String,
    pub mode: RuleMode,
    pub query: String,
    #[serde(default = "default_rule_min_score")]
    pub default_min_score: f32,
    #[serde(default)]
    pub preset: PlaceholderPreset,
    #[serde(default)]
    pub requires_login: bool,
    #[serde(default)]
    pub requires_age_18: bool,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SimilarityDefaults {
    pub dinov3_min: f32,
    pub siglip2_min: f32,
}

impl SimilarityDefaults {
    pub fn is_valid(&self) -> bool {
        self.dinov3_min.is_finite()
            && (0.0..=1.0).contains(&self.dinov3_min)
            && self.siglip2_min.is_finite()
            && (0.0..=1.0).contains(&self.siglip2_min)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct GeoPolicy {
    pub blocked_countries: Vec<String>,
    pub block_unknown: bool,
    pub block_tor: bool,
}

impl GeoPolicy {
    /// Evaluates whether a Cloudflare `request.cf().country()` value is blocked.
    ///
    /// - `None`, `""`, or `"XX"` (unknown country) -> `self.block_unknown`
    /// - `"T1"` (Tor exit node) -> `self.block_tor`
    /// - Any ISO-3166 alpha-2 code in `blocked_countries` (case-insensitive) -> `true`
    pub fn is_blocked(&self, country: Option<&str>) -> bool {
        let Some(raw) = country.map(str::trim).filter(|c| !c.is_empty()) else {
            return self.block_unknown;
        };
        if raw.eq_ignore_ascii_case("XX") {
            return self.block_unknown;
        }
        if raw.eq_ignore_ascii_case("T1") {
            return self.block_tor;
        }
        self.blocked_countries
            .iter()
            .any(|blocked| blocked.trim().eq_ignore_ascii_case(raw))
    }
}

// ---------------------------------------------------------------------------
// Auth Providers (Strictly Non-Secret Public Configuration)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthProviderId {
    OidcAgeAssurance,
    Google,
    #[serde(rename = "github")]
    GitHub,
    X,
    Discord,
    EmailOtp,
    Telegram,
    Siwe,
    Siws,
}

impl AuthProviderId {
    pub const ALL: [Self; 9] = [
        Self::OidcAgeAssurance,
        Self::Google,
        Self::GitHub,
        Self::X,
        Self::Discord,
        Self::EmailOtp,
        Self::Telegram,
        Self::Siwe,
        Self::Siws,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OidcAgeAssurance => "oidc_age_assurance",
            Self::Google => "google",
            Self::GitHub => "github",
            Self::X => "x",
            Self::Discord => "discord",
            Self::EmailOtp => "email_otp",
            Self::Telegram => "telegram",
            Self::Siwe => "siwe",
            Self::Siws => "siws",
        }
    }

    pub const fn display_name(self) -> &'static str {
        match self {
            Self::OidcAgeAssurance => "Age-Assurance OIDC",
            Self::Google => "Google",
            Self::GitHub => "GitHub",
            Self::X => "X (Twitter)",
            Self::Discord => "Discord",
            Self::EmailOtp => "Email Magic Link / OTP",
            Self::Telegram => "Telegram",
            Self::Siwe => "Ethereum (SIWE)",
            Self::Siws => "Solana (SIWS)",
        }
    }

    /// Returns `true` ONLY for providers eligible to satisfy
    /// [`AgeVerificationPolicy::StrictProviderVerified18`].
    ///
    /// Standard OAuth providers (including Google, whose profile birthday is
    /// user-editable), social logins, email OTP, and crypto wallets MUST return `false`.
    pub const fn supports_strict_age_verification(&self) -> bool {
        matches!(self, Self::OidcAgeAssurance)
    }

    /// Returns `true` if this provider is permitted for login / 18+ unlock under
    /// the given [`AgeVerificationPolicy`].
    pub const fn is_allowed_under(&self, policy: AgeVerificationPolicy) -> bool {
        match policy {
            AgeVerificationPolicy::Off | AgeVerificationPolicy::SelfAttestation => true,
            AgeVerificationPolicy::StrictProviderVerified18 => {
                self.supports_strict_age_verification()
            }
        }
    }

    /// Returns `true` if this provider can be linked as a `purpose = 'payment'` wallet.
    pub const fn is_payment_wallet(&self) -> bool {
        matches!(self, Self::Siwe | Self::Siws)
    }
}

/// Strictly non-secret public configuration for an authentication provider.
///
/// Secret credentials (`client_secret`, `bot_token`, mail API keys, etc.) live
/// exclusively in the encrypted `provider_secrets` D1 table and MUST NEVER be
/// added to this struct.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthProviderPublicConfig {
    pub id: AuthProviderId,
    pub enabled: bool,
    #[serde(default)]
    pub display_name: Option<String>,
    /// Public OIDC issuer URL (non-secret).
    #[serde(default)]
    pub issuer: Option<String>,
    /// Public OAuth client ID or Telegram bot username (never a secret).
    #[serde(default)]
    pub public_client_id: Option<String>,
    /// Optional soft convenience birthday check (Google + Self-Attestation only).
    #[serde(default)]
    pub soft_birthday_check: bool,
}

// ---------------------------------------------------------------------------
// Public Site Policy & Deterministic Digest
// ---------------------------------------------------------------------------

fn default_panic_shortcut() -> String {
    DEFAULT_PANIC_SHORTCUT.to_string()
}

/// Strict allowlist public site policy distributed to `SitePolicyDO`,
/// `gateway_worker`, `lets-embed-web`, and browser clients.
///
/// Fresh deployments default to all content filters, age gates, and notice
/// banners disabled.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct PublicSitePolicy {
    pub revision: u32,
    pub min_enforce_rev: u32,
    pub safety_enabled: bool,
    pub rules: Vec<SafetyRuleConfig>,
    pub unclassified_mode: UnclassifiedMode,
    pub cloudflare_images_blur: bool,
    pub age_policy: AgeVerificationPolicy,
    pub age_gate_trigger: AgeGateTrigger,
    pub similarity: SimilarityDefaults,
    pub legal: LegalDocConfig,
    pub geo: GeoPolicy,
    pub enabled_providers: Vec<AuthProviderPublicConfig>,
    #[serde(default = "default_panic_shortcut")]
    pub panic_shortcut: String,
}

impl Default for PublicSitePolicy {
    fn default() -> Self {
        Self {
            revision: 0,
            min_enforce_rev: 0,
            safety_enabled: false,
            rules: Vec::new(),
            unclassified_mode: UnclassifiedMode::LockFailClosed,
            cloudflare_images_blur: false,
            age_policy: AgeVerificationPolicy::Off,
            age_gate_trigger: AgeGateTrigger::Off,
            similarity: SimilarityDefaults::default(),
            legal: LegalDocConfig::default(),
            geo: GeoPolicy::default(),
            enabled_providers: Vec::new(),
            panic_shortcut: default_panic_shortcut(),
        }
    }
}

impl PublicSitePolicy {
    /// Returns `true` if any enabled `Switcher` rule exists while safety is enabled.
    pub fn has_active_switcher_rules(&self) -> bool {
        self.safety_enabled
            && self
                .rules
                .iter()
                .any(|r| r.enabled && r.mode == RuleMode::Switcher)
    }

    /// Returns enabled providers filtered by the active [`AgeVerificationPolicy`].
    pub fn effective_login_providers(&self) -> Vec<&AuthProviderPublicConfig> {
        self.enabled_providers
            .iter()
            .filter(|p| p.enabled && p.id.is_allowed_under(self.age_policy))
            .collect()
    }
}

/// Built-in WD-Tagger preset rule templates verified against `assets/translations.json`.
pub fn builtin_safety_presets() -> Vec<SafetyRuleConfig> {
    vec![
        SafetyRuleConfig {
            id: "r18".to_string(),
            name: "NSFW".to_string(),
            mode: RuleMode::Switcher,
            query: "tag:explicit OR tag:nude OR tag:nipples OR tag:pussy OR tag:penis OR tag:sex OR tag:uncensored OR tag:censored OR tag:topless OR tag:bottomless".to_string(),
            default_min_score: 0.5,
            preset: PlaceholderPreset::R18,
            requires_login: true,
            requires_age_18: true,
            enabled: true,
        },
        SafetyRuleConfig {
            id: "sensitive".to_string(),
            name: "Suggestive / Ecchi".to_string(),
            mode: RuleMode::SpoilerBlur,
            query: "tag:questionable OR tag:sensitive OR tag:lingerie OR tag:bikini OR tag:underwear OR tag:panties OR tag:cleavage OR tag:bdsm".to_string(),
            default_min_score: 0.5,
            preset: PlaceholderPreset::Sensitive,
            requires_login: false,
            requires_age_18: false,
            enabled: true,
        },
        SafetyRuleConfig {
            id: "blood".to_string(),
            name: "Blood / Gore".to_string(),
            mode: RuleMode::Switcher,
            query: "tag:blood".to_string(),
            default_min_score: 0.5,
            preset: PlaceholderPreset::Blood,
            requires_login: false,
            requires_age_18: false,
            enabled: true,
        },
        SafetyRuleConfig {
            id: "custom".to_string(),
            name: "Custom".to_string(),
            mode: RuleMode::Switcher,
            query: String::new(),
            default_min_score: 0.5,
            preset: PlaceholderPreset::Custom,
            requires_login: false,
            requires_age_18: false,
            enabled: false,
        },
    ]
}

fn write_canonical_json(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => {
            if let Some(f) = n.as_f64()
                && f == 0.0
                && f.is_sign_negative()
            {
                out.push_str("0.0");
            } else {
                out.push_str(&n.to_string());
            }
        }
        Value::String(s) => {
            out.push_str(&serde_json::to_string(s).expect("string JSON serialization"));
        }
        Value::Array(items) => {
            out.push('[');
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_canonical_json(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|(a, _), (b, _)| a.as_bytes().cmp(b.as_bytes()));
            out.push('{');
            for (idx, (k, v)) in entries.into_iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                out.push_str(&serde_json::to_string(k).expect("key JSON serialization"));
                out.push(':');
                write_canonical_json(v, out);
            }
            out.push('}');
        }
    }
}

/// Serializes `PublicSitePolicy` into deterministic canonical JSON (lexicographically
/// sorted object keys, no insignificant whitespace).
///
/// `SitePolicyDO` should serve these exact bytes so both raw-body SHA-256 and
/// parsed `compute_policy_digest(&policy)` produce the identical digest.
pub fn canonical_policy_json(policy: &PublicSitePolicy) -> String {
    let value = serde_json::to_value(policy).expect("PublicSitePolicy serializes to JSON");
    let mut out = String::new();
    write_canonical_json(&value, &mut out);
    out
}

/// Computes the deterministic lowercase hex SHA-256 digest of a [`PublicSitePolicy`].
pub fn compute_policy_digest(policy: &PublicSitePolicy) -> String {
    let canonical = canonical_policy_json(policy);
    let digest = Sha256::digest(canonical.as_bytes());
    hex_lower(&digest)
}

// ---------------------------------------------------------------------------
// UserAccount DO Session Context DTO
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AssuranceLevel {
    #[default]
    None,
    SelfAttestation,
    ProviderSelfReportedDob,
    Verified18,
}

/// Live session context returned by `UserAccount` DO (`session-context`) to
/// `gateway_worker` on every protected request.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionContext {
    pub active: bool,
    pub banned: bool,
    pub sid_valid: bool,
    pub assurance_level: AssuranceLevel,
    pub strict_age_ok: bool,
    pub terms_version_accepted: Option<u32>,
    pub terms_digest_accepted: Option<String>,
    pub enabled_switchers: Vec<String>,
    pub safe_mode: bool,
}

impl SessionContext {
    pub fn is_authenticated(&self) -> bool {
        self.active && !self.banned && self.sid_valid
    }

    pub fn satisfies_age_policy(&self, policy: AgeVerificationPolicy) -> bool {
        match policy {
            AgeVerificationPolicy::Off => true,
            AgeVerificationPolicy::SelfAttestation => matches!(
                self.assurance_level,
                AssuranceLevel::SelfAttestation
                    | AssuranceLevel::ProviderSelfReportedDob
                    | AssuranceLevel::Verified18
            ),
            AgeVerificationPolicy::StrictProviderVerified18 => {
                self.strict_age_ok && self.assurance_level == AssuranceLevel::Verified18
            }
        }
    }

    pub fn satisfies_terms(&self, legal: &LegalDocConfig) -> bool {
        self.terms_version_accepted == Some(legal.terms_version)
            && self.terms_digest_accepted.as_deref() == Some(legal.terms_digest.as_str())
    }

    /// Computes the set of Switcher rule IDs this session is currently allowed
    /// to unlock under `policy` (deduplicated in policy order).
    ///
    /// Rules enforced:
    /// - If `!policy.safety_enabled`, `!self.is_authenticated()`, or `self.safe_mode`,
    ///   returns `[]`.
    /// - Only enabled `RuleMode::Switcher` rules requested in `self.enabled_switchers`
    ///   are considered.
    /// - When `policy.legal.terms_version > 0` and `(rule.requires_login ||
    ///   rule.requires_age_18 || policy.age_gate_trigger != AgeGateTrigger::Off)`,
    ///   both `terms_version_accepted` and `terms_digest_accepted` must match
    ///   `policy.legal`.
    /// - When `rule.requires_age_18`, `self.satisfies_age_policy(policy.age_policy)`
    ///   must hold (`AgeVerificationPolicy::Off` imposes no age check).
    pub fn effective_switchers(&self, policy: &PublicSitePolicy) -> Vec<String> {
        if !policy.safety_enabled || !self.is_authenticated() || self.safe_mode {
            return Vec::new();
        }
        let terms_ok = policy.legal.terms_version == 0 || self.satisfies_terms(&policy.legal);
        let age_ok = self.satisfies_age_policy(policy.age_policy);
        let global_terms_gate = policy.age_gate_trigger != AgeGateTrigger::Off;

        let mut out = Vec::new();
        for rule in &policy.rules {
            if !rule.enabled || rule.mode != RuleMode::Switcher {
                continue;
            }
            if !self.enabled_switchers.iter().any(|s| s == &rule.id) {
                continue;
            }
            let requires_terms = policy.legal.terms_version > 0
                && (rule.requires_login || rule.requires_age_18 || global_terms_gate);
            if requires_terms && !terms_ok {
                continue;
            }
            if rule.requires_age_18 && !age_ok {
                continue;
            }
            if !out.iter().any(|existing| existing == &rule.id) {
                out.push(rule.id.clone());
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_rule(
        id: &str,
        mode: RuleMode,
        requires_login: bool,
        requires_age_18: bool,
        enabled: bool,
    ) -> SafetyRuleConfig {
        SafetyRuleConfig {
            id: id.to_string(),
            name: id.to_string(),
            mode,
            query: format!("tag:{id}"),
            default_min_score: 0.5,
            preset: PlaceholderPreset::Custom,
            requires_login,
            requires_age_18,
            enabled,
        }
    }

    fn base_policy() -> PublicSitePolicy {
        let mut p = PublicSitePolicy {
            safety_enabled: true,
            age_policy: AgeVerificationPolicy::Off,
            age_gate_trigger: AgeGateTrigger::Off,
            rules: vec![
                test_rule("login_only", RuleMode::Switcher, true, false, true),
                test_rule("open_sw", RuleMode::Switcher, false, false, true),
                test_rule("adult", RuleMode::Switcher, true, true, true),
                test_rule("blur_only", RuleMode::SpoilerBlur, false, false, true),
                test_rule("disabled_sw", RuleMode::Switcher, false, false, false),
            ],
            ..PublicSitePolicy::default()
        };
        p.legal.terms_version = 1;
        p
    }

    fn authed_ctx(switchers: &[&str]) -> SessionContext {
        SessionContext {
            active: true,
            banned: false,
            sid_valid: true,
            assurance_level: AssuranceLevel::None,
            strict_age_ok: false,
            terms_version_accepted: None,
            terms_digest_accepted: None,
            enabled_switchers: switchers.iter().map(|s| (*s).to_string()).collect(),
            safe_mode: false,
        }
    }

    #[test]
    fn effective_switchers_enforces_terms_for_requires_login_without_age_18() {
        let mut policy = base_policy();
        let mut ctx = authed_ctx(&["login_only", "open_sw", "adult", "blur_only", "disabled_sw"]);

        // With terms_version > 0 and age_gate_trigger == Off, login_only (requires_login=true,
        // requires_age_18=false) and adult (requires_age_18=true) both require Terms acceptance,
        // while open_sw (requires_login=false, requires_age_18=false) does not.
        assert_eq!(ctx.effective_switchers(&policy), vec!["open_sw"]);

        // Stale version or mismatched digest stays fail-closed.
        ctx.terms_version_accepted = Some(1);
        ctx.terms_digest_accepted = Some("0".repeat(64));
        assert_eq!(ctx.effective_switchers(&policy), vec!["open_sw"]);

        ctx.terms_version_accepted = Some(2);
        ctx.terms_digest_accepted = Some(policy.legal.terms_digest.clone());
        assert_eq!(ctx.effective_switchers(&policy), vec!["open_sw"]);

        // Matching version + digest unlocks login_only and (under age_policy=Off) adult.
        ctx.terms_version_accepted = Some(1);
        ctx.terms_digest_accepted = Some(policy.legal.terms_digest.clone());
        assert_eq!(
            ctx.effective_switchers(&policy),
            vec!["login_only", "open_sw", "adult"]
        );

        // When terms_version == 0, Terms gate is inactive.
        policy.legal.terms_version = 0;
        ctx.terms_version_accepted = None;
        ctx.terms_digest_accepted = None;
        assert_eq!(
            ctx.effective_switchers(&policy),
            vec!["login_only", "open_sw", "adult"]
        );
    }

    #[test]
    fn effective_switchers_enforces_terms_when_age_gate_trigger_is_active() {
        for trigger in [AgeGateTrigger::JustInTime, AgeGateTrigger::SiteWideSplash] {
            let mut policy = base_policy();
            policy.age_gate_trigger = trigger;
            let mut ctx = authed_ctx(&["open_sw", "login_only"]);

            // Global terms gate blocks even open_sw (requires_login=false, requires_age_18=false)
            // until current Terms are accepted.
            assert!(
                ctx.effective_switchers(&policy).is_empty(),
                "trigger {trigger:?} must require Terms"
            );

            ctx.terms_version_accepted = Some(policy.legal.terms_version);
            ctx.terms_digest_accepted = Some(policy.legal.terms_digest.clone());
            assert_eq!(
                ctx.effective_switchers(&policy),
                vec!["login_only", "open_sw"]
            );
        }
    }

    #[test]
    fn effective_switchers_enforces_age_policy_safe_mode_and_deduplication() {
        let mut policy = base_policy();
        policy.age_policy = AgeVerificationPolicy::StrictProviderVerified18;
        // Duplicate rule IDs in policy/session must deduplicate cleanly.
        policy
            .rules
            .push(test_rule("open_sw", RuleMode::Switcher, false, false, true));

        let mut ctx = authed_ctx(&["adult", "open_sw", "open_sw"]);
        ctx.terms_version_accepted = Some(policy.legal.terms_version);
        ctx.terms_digest_accepted = Some(policy.legal.terms_digest.clone());
        ctx.assurance_level = AssuranceLevel::SelfAttestation;
        assert_eq!(ctx.effective_switchers(&policy), vec!["open_sw"]);

        ctx.assurance_level = AssuranceLevel::Verified18;
        ctx.strict_age_ok = true;
        assert_eq!(ctx.effective_switchers(&policy), vec!["open_sw", "adult"]);

        ctx.safe_mode = true;
        assert!(ctx.effective_switchers(&policy).is_empty());
    }
}
