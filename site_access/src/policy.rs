//! Policy v3 public site policy, strict validation, conservative versioning,
//! auth provider capability, and bypass evaluation (`compute_policy_access`).
//!
//! `PublicSitePolicy` is a strict allowlist struct with ZERO secret fields so it
//! can be published safely to `SitePolicyDO`, `gateway_worker`, `lets-embed-web`,
//! and public clients.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fmt,
};

use search_types::{
    BUILTIN_SAFETY_PRESET_TAGS, WD_VOCAB_DIGEST,
    query::{validate_threshold_hundredths_f32, validate_threshold_range},
    safety::{
        MAX_POLICIES_PER_SET, MAX_TERMS_PER_POLICY, MAX_TOTAL_TERMS_PER_SET,
        parse_safety_rule, parse_safety_rule_legacy_precision, validate_wd_tags_in_expr,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::{
    legal::{LegalDocConfig, hex_lower},
    tokens::is_valid_sha256_hex,
};

pub use search_types::PlaceholderPreset;

/// Active Policy v3 schema version. Readers strictly reject any other version.
pub const SITE_POLICY_SCHEMA_VERSION: u32 = 3;

/// Default minimum WD-Tagger confidence score for Policy v3 policies.
pub const DEFAULT_POLICY_TAG_MIN: f32 = 0.45;

/// Canonical WD-Tagger vocabulary tags used by built-in safety presets and
/// category-9 rating persistence.
pub const BUILTIN_SAFETY_VOCABULARY_TAGS: &[&str] = BUILTIN_SAFETY_PRESET_TAGS;

// ---------------------------------------------------------------------------
// Policy Validation Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyValidationError {
    UnsupportedSchemaVersion(Option<u32>),
    LegacyFieldPresent(&'static str),
    DigestMismatch,
    VocabDigestMismatch,
    InvalidField(String),
    RuleError(String),
}

impl fmt::Display for PolicyValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSchemaVersion(Some(v)) => {
                write!(
                    f,
                    "unsupported policy schema_version {v} (expected {SITE_POLICY_SCHEMA_VERSION})"
                )
            }
            Self::UnsupportedSchemaVersion(None) => {
                write!(
                    f,
                    "missing required policy schema_version (expected {SITE_POLICY_SCHEMA_VERSION})"
                )
            }
            Self::LegacyFieldPresent(field) => {
                write!(f, "legacy policy field '{field}' is not allowed in schema v3")
            }
            Self::DigestMismatch => write!(f, "policy_digest does not match canonical policy"),
            Self::VocabDigestMismatch => {
                write!(f, "vocab_digest does not match bundled WD-Tagger v3 vocabulary")
            }
            Self::InvalidField(msg) | Self::RuleError(msg) => f.write_str(msg),
        }
    }
}

impl std::error::Error for PolicyValidationError {}

// ---------------------------------------------------------------------------
// PolicyRef & Core Policy v3 Enums
// ---------------------------------------------------------------------------

/// Validates a Policy v3 immutable slug ID (`1..=32` lowercase ASCII `[a-z0-9_-]`).
pub fn is_valid_policy_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 32
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// Validates an uppercase ISO-3166 alpha-2 country code (`[A-Z]{2}`).
pub fn is_valid_iso_country_code(code: &str) -> bool {
    code.len() == 2 && code.bytes().all(|b| b.is_ascii_uppercase())
}

/// Versioned reference to a specific policy and its opt-in generation.
///
/// Compact wire/storage form: `"{id}@{grant_generation}"`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PolicyRef {
    pub id: String,
    pub grant_generation: u64,
}

impl PolicyRef {
    pub fn new(id: impl Into<String>, grant_generation: u64) -> Self {
        Self {
            id: id.into(),
            grant_generation,
        }
    }

    pub fn validate(&self) -> Result<(), PolicyValidationError> {
        if !is_valid_policy_id(&self.id) {
            return Err(PolicyValidationError::InvalidField(format!(
                "invalid policy id '{}' (expected 1..=32 lowercase [a-z0-9_-])",
                self.id
            )));
        }
        if self.grant_generation == 0 {
            return Err(PolicyValidationError::InvalidField(format!(
                "policy '{}' grant_generation must be >= 1",
                self.id
            )));
        }
        Ok(())
    }

    /// Formats as canonical compact key `"{id}@{grant_generation}"`.
    pub fn to_key(&self) -> String {
        format!("{}@{}", self.id, self.grant_generation)
    }

    /// Parses canonical compact key `"{id}@{grant_generation}"` strictly.
    pub fn from_key(raw: &str) -> Result<Self, PolicyValidationError> {
        let Some((id, gen_str)) = raw.split_once('@') else {
            return Err(PolicyValidationError::InvalidField(format!(
                "invalid PolicyRef key '{raw}' (expected '<id>@<gen>')"
            )));
        };
        if gen_str.is_empty()
            || gen_str.contains('@')
            || !gen_str.bytes().all(|b| b.is_ascii_digit())
            || gen_str.starts_with('0')
        {
            return Err(PolicyValidationError::InvalidField(format!(
                "invalid grant_generation in PolicyRef key '{raw}'"
            )));
        }
        let grant_generation = gen_str.parse::<u64>().map_err(|_| {
            PolicyValidationError::InvalidField(format!(
                "invalid grant_generation in PolicyRef key '{raw}'"
            ))
        })?;
        let pref = Self {
            id: id.to_string(),
            grant_generation,
        };
        pref.validate()?;
        Ok(pref)
    }
}

impl fmt::Display for PolicyRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.id, self.grant_generation)
    }
}

/// Policy v3 enforcement action (strictly `Block` or `Blur`; NO top-level `Allow`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PolicyAction {
    #[default]
    Block,
    Blur,
}

/// How unclassified media (`images.status != 'completed'`) is handled globally.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnclassifiedMode {
    #[default]
    Placeholder,
    Continue,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgeVerificationPolicy {
    #[default]
    Off,
    SelfAttestation,
    StrictProviderVerified18,
}

/// Alias matching Policy v3 specification terminology.
pub type AgeVerificationMode = AgeVerificationPolicy;

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

// ---------------------------------------------------------------------------
// PolicyBypass & ContentPolicy
// ---------------------------------------------------------------------------

/// Policy v3 bypass predicate:
/// `any(enabled Include matches) AND all(checked Require pass) AND none(checked Exclude match)`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PolicyBypass {
    // INCLUDE (OR — caller must match >= 1 enabled branch; empty Include => ALWAYS FALSE)
    pub include_switcher: bool,
    /// ONLY permitted on `PolicyAction::Blur`; rejected at validation on `PolicyAction::Block`.
    pub include_click: bool,
    /// Explicit opt-in, default `false`; requires live staff CF Access identity (NEVER browse cookie).
    pub include_live_admin: bool,

    // REQUIRE (AND — caller MUST satisfy EVERY checked requirement)
    pub require_gallery_login: bool,
    /// Requires `age_policy != Off` + valid identity-bound 18+ evidence.
    pub require_age_18: bool,
    /// Requires exact active `terms_version` AND `terms_digest` match.
    pub require_current_terms: bool,

    // EXCLUDE (NOR — matching ANY exclude branch ALWAYS denies bypass)
    pub exclude_anonymous: bool,
    /// ISO-3166 alpha-2 country codes; when non-empty, missing / `"XX"` / `"T1"` is DENIED.
    pub exclude_countries: Vec<String>,
}

impl PolicyBypass {
    /// Returns `true` if at least one `Include` branch is enabled.
    pub const fn has_any_include(&self) -> bool {
        self.include_switcher || self.include_click || self.include_live_admin
    }

    /// Evaluates whether a runtime `cf.country` is excluded by `exclude_countries`.
    ///
    /// When `exclude_countries` is empty, returns `false`.
    /// When non-empty, missing (`None`), blank, `"XX"` (unknown), `"T1"` (Tor),
    /// or any listed country (case-insensitive) returns `true` (DENIED).
    pub fn is_country_excluded(&self, country: Option<&str>) -> bool {
        if self.exclude_countries.is_empty() {
            return false;
        }
        let Some(raw) = country.map(str::trim).filter(|c| !c.is_empty()) else {
            return true;
        };
        if raw.eq_ignore_ascii_case("XX") || raw.eq_ignore_ascii_case("T1") {
            return true;
        }
        self.exclude_countries
            .iter()
            .any(|code| code.trim().eq_ignore_ascii_case(raw))
    }
}

const fn default_grant_generation() -> u64 {
    1
}

const fn default_true() -> bool {
    true
}

const fn default_policy_tag_min() -> f32 {
    DEFAULT_POLICY_TAG_MIN
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContentPolicy {
    pub id: String,
    #[serde(default = "default_grant_generation")]
    pub grant_generation: u64,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub priority: u16,
    pub name: String,
    #[serde(default)]
    pub preset: PlaceholderPreset,
    pub match_expr: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub except_expr: Option<String>,
    #[serde(default = "default_policy_tag_min")]
    pub default_tag_min: f32,
    #[serde(default)]
    pub action: PolicyAction,
    #[serde(default)]
    pub bypass: PolicyBypass,
}

impl ContentPolicy {
    pub fn policy_ref(&self) -> PolicyRef {
        PolicyRef {
            id: self.id.clone(),
            grant_generation: self.grant_generation,
        }
    }
}

// ---------------------------------------------------------------------------
// Similarity & Geo Models
// ---------------------------------------------------------------------------

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

/// Curated ISO-3166 alpha-2 preset of countries with nationwide legal
/// prohibitions or blocks on online adult / R-18 content.
///
/// Operators should review and customize this list with legal counsel for their
/// specific jurisdiction and content profile. Always sorted & deduplicated.
pub const R18_PROHIBITED_COUNTRIES: &[&str] = &[
    "AE", "AF", "BD", "BH", "BN", "BT", "BY", "CN", "CU", "DZ", "EG", "ER", "ET", "ID", "IN",
    "IQ", "IR", "JO", "KH", "KP", "KR", "KW", "LA", "LK", "LY", "MA", "MM", "MV", "MY", "NP",
    "OM", "PK", "PS", "QA", "SA", "SD", "SG", "SO", "SY", "TH", "TM", "TN", "TR", "TZ", "UA",
    "UG", "UZ", "VN", "YE",
];

/// Merges existing ISO-3166 alpha-2 codes with additional preset codes into a
/// sorted, uppercase, deduplicated list (ignoring blank entries).
pub fn merge_country_codes(existing: &[String], additions: &[&str]) -> Vec<String> {
    let mut set = BTreeSet::new();
    for raw in existing {
        let code = raw.trim().to_ascii_uppercase();
        if !code.is_empty() {
            set.insert(code);
        }
    }
    for raw in additions {
        let code = raw.trim().to_ascii_uppercase();
        if !code.is_empty() {
            set.insert(code);
        }
    }
    set.into_iter().collect()
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

    /// Returns the sorted, deduplicated Cloudflare `ip.src.country` code list
    /// represented by this [`GeoPolicy`], including `"T1"` when `block_tor` is
    /// enabled and `"XX"` when `block_unknown` is enabled.
    ///
    /// Invalid or malformed country entries are omitted so generated WAF
    /// expressions remain syntactically valid while editing a draft.
    pub fn cloudflare_waf_codes(&self) -> Vec<String> {
        let mut codes = BTreeSet::new();
        for raw in &self.blocked_countries {
            let code = raw.trim().to_ascii_uppercase();
            if is_valid_iso_country_code(&code) {
                codes.insert(code);
            }
        }
        if self.block_tor {
            codes.insert("T1".to_string());
        }
        if self.block_unknown {
            codes.insert("XX".to_string());
        }
        codes.into_iter().collect()
    }

    /// Formats the equivalent Cloudflare WAF Custom Rule expression matching
    /// `gateway_worker`'s Step 0 geo enforcement (blocking the configured
    /// countries, optional Tor `T1`, and optional unknown `XX`, while keeping
    /// `/admin` and `/admin/*` exempt).
    ///
    /// Returns `None` when no countries, unknown (`XX`), or Tor (`T1`) are
    /// blocked.
    pub fn to_cloudflare_waf_expression(&self) -> Option<String> {
        let codes = self.cloudflare_waf_codes();
        if codes.is_empty() {
            return None;
        }
        let country_clause = if codes.len() == 1 {
            format!(r#"ip.src.country eq "{}""#, codes[0])
        } else {
            let quoted: Vec<String> = codes.iter().map(|c| format!(r#""{c}""#)).collect();
            format!("ip.src.country in {{{}}}", quoted.join(" "))
        };
        Some(format!(
            r#"({country_clause}) and not (http.request.uri.path eq "/admin" or starts_with(http.request.uri.path, "/admin/"))"#
        ))
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthProviderPublicConfig {
    pub id: AuthProviderId,
    pub enabled: bool,
    #[serde(default)]
    pub display_name: Option<String>,
    #[serde(default)]
    pub issuer: Option<String>,
    #[serde(default)]
    pub public_client_id: Option<String>,
    #[serde(default)]
    pub soft_birthday_check: bool,
}

// ---------------------------------------------------------------------------
// PublicSitePolicy (Schema v3) & Deterministic Digest
// ---------------------------------------------------------------------------

fn default_vocab_digest() -> String {
    WD_VOCAB_DIGEST.to_string()
}

/// Policy v3 public site policy distributed to `SitePolicyDO`, `gateway_worker`,
/// `lets-embed-web`, and public clients.
///
/// NOTE: `schema_version` intentionally has NO `serde(default)` so pre-v3
/// documents without `schema_version: 3` fail closed instead of silently
/// decoding with empty `policies`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicSitePolicy {
    pub schema_version: u32,
    #[serde(default)]
    pub revision: u64,
    #[serde(default)]
    pub min_enforce_rev: u64,
    #[serde(default)]
    pub policy_digest: String,
    #[serde(default = "default_vocab_digest")]
    pub vocab_digest: String,
    #[serde(default)]
    pub safety_enabled: bool,
    #[serde(default)]
    pub unclassified_mode: UnclassifiedMode,
    #[serde(default)]
    pub fixed_blur_enabled: bool,
    #[serde(default)]
    pub policies: Vec<ContentPolicy>,
    #[serde(default)]
    pub age_policy: AgeVerificationPolicy,
    #[serde(default)]
    pub age_gate_trigger: AgeGateTrigger,
    #[serde(default)]
    pub similarity: SimilarityDefaults,
    #[serde(default)]
    pub legal: LegalDocConfig,
    #[serde(default)]
    pub geo: GeoPolicy,
    #[serde(default)]
    pub enabled_providers: Vec<AuthProviderPublicConfig>,
}

impl Default for PublicSitePolicy {
    fn default() -> Self {
        Self::fresh_bootstrap()
    }
}

impl PublicSitePolicy {
    /// Fresh-installation disabled v3 bootstrap policy (`revision == 0`).
    pub fn fresh_bootstrap() -> Self {
        let mut policy = Self {
            schema_version: SITE_POLICY_SCHEMA_VERSION,
            revision: 0,
            min_enforce_rev: 0,
            policy_digest: String::new(),
            vocab_digest: default_vocab_digest(),
            safety_enabled: false,
            unclassified_mode: UnclassifiedMode::Placeholder,
            fixed_blur_enabled: false,
            policies: Vec::new(),
            age_policy: AgeVerificationPolicy::Off,
            age_gate_trigger: AgeGateTrigger::Off,
            similarity: SimilarityDefaults::default(),
            legal: LegalDocConfig::default(),
            geo: GeoPolicy::default(),
            enabled_providers: Vec::new(),
        };
        policy.refresh_policy_digest();
        policy
    }

    /// Recomputes and stores `self.policy_digest` from the canonical policy payload.
    pub fn refresh_policy_digest(&mut self) {
        self.policy_digest = compute_policy_digest(self);
    }

    /// Verifies that `self.policy_digest` is a valid 64-char hex SHA-256 matching
    /// [`compute_policy_digest`].
    pub fn verify_policy_digest(&self) -> bool {
        is_valid_sha256_hex(&self.policy_digest) && self.policy_digest == compute_policy_digest(self)
    }

    /// Strict schema v3 JSON decoder for active readers.
    ///
    /// Rejects missing or non-3 `schema_version`, legacy v2 `"rules"` fields,
    /// malformed JSON, digest mismatches (for active `revision > 0` policies),
    /// and invalid Policy v3 invariants.
    pub fn decode_strict_v3(raw_json: &str) -> Result<Self, PolicyValidationError> {
        decode_active_policy_v3(raw_json)
    }

    /// Returns `true` if safety is enabled and at least one policy is enabled.
    pub fn has_active_policies(&self) -> bool {
        self.safety_enabled && self.policies.iter().any(|p| p.enabled)
    }

    /// Returns `true` if safety is enabled and any enabled policy supports switcher opt-in.
    pub fn has_active_switcher_policies(&self) -> bool {
        self.safety_enabled
            && self
                .policies
                .iter()
                .any(|p| p.enabled && p.bypass.include_switcher)
    }

    /// Returns enabled providers filtered by the active [`AgeVerificationPolicy`].
    ///
    /// Mirrors `user_worker::identity::is_provider_enabled_in_policy`: on a fresh
    /// zero-config deployment (`enabled_providers` empty and `age_policy != StrictProviderVerified18`),
    /// defaults to Ethereum (SIWE) and Solana (SIWS) so `/user/login` stays usable
    /// under both `Off` and `SelfAttestation`.
    pub fn effective_login_providers(&self) -> Vec<AuthProviderPublicConfig> {
        if self.enabled_providers.is_empty()
            && self.age_policy != AgeVerificationPolicy::StrictProviderVerified18
        {
            return vec![
                AuthProviderPublicConfig {
                    id: AuthProviderId::Siwe,
                    enabled: true,
                    display_name: None,
                    issuer: None,
                    public_client_id: None,
                    soft_birthday_check: false,
                },
                AuthProviderPublicConfig {
                    id: AuthProviderId::Siws,
                    enabled: true,
                    display_name: None,
                    issuer: None,
                    public_client_id: None,
                    soft_birthday_check: false,
                },
            ];
        }
        self.enabled_providers
            .iter()
            .filter(|p| p.enabled && p.id.is_allowed_under(self.age_policy))
            .cloned()
            .collect()
    }
}

/// Strictly decodes an active Policy v3 JSON document, failing closed on any
/// non-3 `schema_version`, legacy `"rules"` key, digest mismatch, or invalid policy.
pub fn decode_active_policy_v3(raw_json: &str) -> Result<PublicSitePolicy, PolicyValidationError> {
    let val: Value = serde_json::from_str(raw_json)
        .map_err(|e| PolicyValidationError::InvalidField(format!("malformed policy JSON: {e}")))?;
    let obj = val.as_object().ok_or_else(|| {
        PolicyValidationError::InvalidField("policy document must be a JSON object".into())
    })?;

    match obj.get("schema_version").and_then(Value::as_u64) {
        Some(v) if v == u64::from(SITE_POLICY_SCHEMA_VERSION) => {}
        Some(other) => {
            return Err(PolicyValidationError::UnsupportedSchemaVersion(Some(
                u32::try_from(other).unwrap_or(u32::MAX),
            )));
        }
        None => return Err(PolicyValidationError::UnsupportedSchemaVersion(None)),
    }

    if obj.contains_key("rules") {
        return Err(PolicyValidationError::LegacyFieldPresent("rules"));
    }

    let policy: PublicSitePolicy = serde_json::from_value(val)
        .map_err(|e| PolicyValidationError::InvalidField(format!("invalid v3 policy: {e}")))?;

    if (policy.revision > 0 || policy.safety_enabled || !policy.policy_digest.is_empty())
        && !policy.verify_policy_digest()
    {
        return Err(PolicyValidationError::DigestMismatch);
    }

    validate_policy_set_with_mode(&policy, false)?;
    Ok(policy)
}

/// Built-in Policy v3 preset templates verified against the bundled 10,861-name
/// WD-Tagger v3 vocabulary.
pub fn builtin_safety_presets() -> Vec<ContentPolicy> {
    vec![
        ContentPolicy {
            id: "r18".to_string(),
            grant_generation: 1,
            enabled: true,
            priority: 10,
            name: "NSFW / Explicit".to_string(),
            preset: PlaceholderPreset::R18,
            match_expr: "tag:explicit OR tag:nude OR tag:nipples OR tag:pussy OR tag:penis OR tag:sex OR tag:uncensored OR tag:censored OR tag:topless OR tag:bottomless".to_string(),
            except_expr: None,
            default_tag_min: DEFAULT_POLICY_TAG_MIN,
            action: PolicyAction::Block,
            bypass: PolicyBypass {
                include_switcher: true,
                include_click: false,
                include_live_admin: false,
                require_gallery_login: true,
                require_age_18: false,
                require_current_terms: true,
                exclude_anonymous: true,
                exclude_countries: Vec::new(),
            },
        },
        ContentPolicy {
            id: "sensitive".to_string(),
            grant_generation: 1,
            enabled: true,
            priority: 20,
            name: "Suggestive / Ecchi".to_string(),
            preset: PlaceholderPreset::Sensitive,
            match_expr: "tag:questionable OR tag:sensitive OR tag:lingerie OR tag:bikini OR tag:underwear OR tag:panties OR tag:cleavage OR tag:bdsm".to_string(),
            except_expr: None,
            default_tag_min: DEFAULT_POLICY_TAG_MIN,
            action: PolicyAction::Blur,
            bypass: PolicyBypass {
                include_switcher: true,
                include_click: true,
                include_live_admin: false,
                require_gallery_login: false,
                require_age_18: false,
                require_current_terms: false,
                exclude_anonymous: false,
                exclude_countries: Vec::new(),
            },
        },
        ContentPolicy {
            id: "blood".to_string(),
            grant_generation: 1,
            enabled: true,
            priority: 30,
            name: "Blood / Gore".to_string(),
            preset: PlaceholderPreset::Blood,
            match_expr: "tag:blood".to_string(),
            except_expr: None,
            default_tag_min: DEFAULT_POLICY_TAG_MIN,
            action: PolicyAction::Block,
            bypass: PolicyBypass {
                include_switcher: true,
                include_click: false,
                include_live_admin: false,
                require_gallery_login: false,
                require_age_18: false,
                require_current_terms: false,
                exclude_anonymous: false,
                exclude_countries: Vec::new(),
            },
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

/// Serializes `PublicSitePolicy` into deterministic canonical JSON
/// (lexicographically sorted object keys, no insignificant whitespace).
pub fn canonical_policy_json(policy: &PublicSitePolicy) -> String {
    let value = serde_json::to_value(policy).expect("PublicSitePolicy serializes to JSON");
    let mut out = String::new();
    write_canonical_json(&value, &mut out);
    out
}

/// Computes the deterministic lowercase hex SHA-256 digest of a [`PublicSitePolicy`].
///
/// The top-level `policy_digest` field itself is excluded from the hashed object
/// so storing the computed digest inside `policy.policy_digest` is idempotent.
pub fn compute_policy_digest(policy: &PublicSitePolicy) -> String {
    let mut value = serde_json::to_value(policy).expect("PublicSitePolicy serializes to JSON");
    if let Some(obj) = value.as_object_mut() {
        obj.remove("policy_digest");
    }
    let mut canonical = String::new();
    write_canonical_json(&value, &mut canonical);
    let digest = Sha256::digest(canonical.as_bytes());
    hex_lower(&digest)
}

// ---------------------------------------------------------------------------
// Policy Set Validation (Publish & Active Checks)
// ---------------------------------------------------------------------------

/// Summary of validated expressions & catalog references extracted by [`validate_policy_set`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ValidatedPolicySetInfo {
    pub total_terms: usize,
    pub referenced_wd_tags: Vec<String>,
    pub referenced_post_tags: Vec<String>,
    pub referenced_authors: Vec<String>,
}

/// Strictly validates a [`PublicSitePolicy`] prior to publication, enforcing:
/// - `schema_version == 3`, `min_enforce_rev <= revision`, `vocab_digest == WD_VOCAB_DIGEST`
/// - Limits: `<= 16` policies, `<= 32` terms per policy (`match_expr + except_expr`),
///   AST depth `<= 6`, `<= 128` total terms
/// - Strict hundredths `default_tag_min` and tag score thresholds (`0.01..=1.00`)
/// - Canonical WD-Tagger v3 vocabulary validation for EVERY `tag:<name>` (even in `NOT`/`except_expr`)
/// - Rejects `action == Block && bypass.include_click == true`
/// - Rejects `bypass.require_age_18 == true && age_policy == AgeVerificationPolicy::Off`
/// - Uppercase ISO-3166 alpha-2 `exclude_countries` and `geo.blocked_countries`, valid slugs, `grant_generation >= 1`
pub fn validate_policy_set(
    policy: &PublicSitePolicy,
) -> Result<ValidatedPolicySetInfo, PolicyValidationError> {
    validate_policy_set_with_mode(policy, true)
}

/// Validates a [`PublicSitePolicy`] with configurable threshold precision mode
/// (`strict_hundredths = true` for new publishes, `false` for reading legacy precision).
pub fn validate_policy_set_with_mode(
    policy: &PublicSitePolicy,
    strict_hundredths: bool,
) -> Result<ValidatedPolicySetInfo, PolicyValidationError> {
    if policy.schema_version != SITE_POLICY_SCHEMA_VERSION {
        return Err(PolicyValidationError::UnsupportedSchemaVersion(Some(
            policy.schema_version,
        )));
    }
    if policy.min_enforce_rev > policy.revision {
        return Err(PolicyValidationError::InvalidField(
            "min_enforce_rev cannot exceed revision".into(),
        ));
    }
    if policy.vocab_digest != WD_VOCAB_DIGEST {
        return Err(PolicyValidationError::VocabDigestMismatch);
    }
    if !policy.similarity.is_valid() {
        return Err(PolicyValidationError::InvalidField(
            "similarity thresholds must be finite and within 0.0..=1.0".into(),
        ));
    }
    validate_country_list(&policy.geo.blocked_countries, "geo.blocked_countries")?;

    if policy.policies.len() > MAX_POLICIES_PER_SET {
        return Err(PolicyValidationError::InvalidField(format!(
            "PolicySet exceeds maximum of {MAX_POLICIES_PER_SET} policies"
        )));
    }

    let mut seen_ids = HashSet::new();
    let mut total_terms = 0usize;
    let mut wd_tags = BTreeSet::new();
    let mut post_tags = BTreeSet::new();
    let mut authors = BTreeSet::new();

    for (idx, item) in policy.policies.iter().enumerate() {
        if !is_valid_policy_id(&item.id) {
            return Err(PolicyValidationError::InvalidField(format!(
                "Policy #{} id '{}' must be 1..=32 lowercase ASCII [a-z0-9_-]",
                idx + 1,
                item.id
            )));
        }
        if !seen_ids.insert(item.id.as_str()) {
            return Err(PolicyValidationError::InvalidField(format!(
                "Duplicate policy id '{}'",
                item.id
            )));
        }
        if item.grant_generation == 0 {
            return Err(PolicyValidationError::InvalidField(format!(
                "Policy '{}' grant_generation must be >= 1",
                item.id
            )));
        }
        let name = item.name.trim();
        if name.is_empty() || name.len() > 120 || name.chars().any(char::is_control) {
            return Err(PolicyValidationError::InvalidField(format!(
                "Policy '{}' name must be 1..=120 non-control characters",
                item.id
            )));
        }

        if strict_hundredths {
            validate_threshold_hundredths_f32(item.default_tag_min).map_err(|e| {
                PolicyValidationError::InvalidField(format!(
                    "Policy '{}' default_tag_min: {e}",
                    item.id
                ))
            })?;
        } else {
            validate_threshold_range(item.default_tag_min).map_err(|e| {
                PolicyValidationError::InvalidField(format!(
                    "Policy '{}' default_tag_min: {e}",
                    item.id
                ))
            })?;
        }

        if item.action == PolicyAction::Block && item.bypass.include_click {
            return Err(PolicyValidationError::InvalidField(format!(
                "Policy '{}' cannot enable click-to-reveal (include_click) with action=block",
                item.id
            )));
        }
        if item.bypass.require_age_18 && policy.age_policy == AgeVerificationPolicy::Off {
            return Err(PolicyValidationError::InvalidField(format!(
                "Policy '{}' cannot enable require_age_18 while age verification mode is off",
                item.id
            )));
        }
        validate_country_list(
            &item.bypass.exclude_countries,
            &format!("policy '{}'.bypass.exclude_countries", item.id),
        )?;

        let match_raw = item.match_expr.trim();
        let except_raw = item
            .except_expr
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());

        if item.enabled && match_raw.is_empty() {
            return Err(PolicyValidationError::RuleError(format!(
                "Enabled policy '{}' cannot have an empty match_expr",
                item.id
            )));
        }

        let mut policy_terms = 0usize;
        if !match_raw.is_empty() {
            let expr = if strict_hundredths {
                parse_safety_rule(match_raw)
            } else {
                parse_safety_rule_legacy_precision(match_raw)
            }
            .map_err(|e| {
                PolicyValidationError::RuleError(format!("Policy '{}' match_expr: {e}", item.id))
            })?;
            validate_wd_tags_in_expr(&expr).map_err(|e| {
                PolicyValidationError::RuleError(format!("Policy '{}' match_expr: {e}", item.id))
            })?;
            policy_terms += expr.term_count();
            wd_tags.extend(expr.referenced_wd_tags());
            post_tags.extend(expr.referenced_post_tags());
            authors.extend(expr.referenced_authors());
        }

        if let Some(ex_raw) = except_raw {
            let expr = if strict_hundredths {
                parse_safety_rule(ex_raw)
            } else {
                parse_safety_rule_legacy_precision(ex_raw)
            }
            .map_err(|e| {
                PolicyValidationError::RuleError(format!("Policy '{}' except_expr: {e}", item.id))
            })?;
            validate_wd_tags_in_expr(&expr).map_err(|e| {
                PolicyValidationError::RuleError(format!("Policy '{}' except_expr: {e}", item.id))
            })?;
            policy_terms += expr.term_count();
            wd_tags.extend(expr.referenced_wd_tags());
            post_tags.extend(expr.referenced_post_tags());
            authors.extend(expr.referenced_authors());
        }

        if policy_terms > MAX_TERMS_PER_POLICY {
            return Err(PolicyValidationError::RuleError(format!(
                "Policy '{}' has {policy_terms} combined terms (match_expr + except_expr), exceeding maximum of {MAX_TERMS_PER_POLICY}",
                item.id
            )));
        }

        total_terms += policy_terms;
        if total_terms > MAX_TOTAL_TERMS_PER_SET {
            return Err(PolicyValidationError::RuleError(format!(
                "PolicySet exceeds maximum of {MAX_TOTAL_TERMS_PER_SET} total terms"
            )));
        }
    }

    Ok(ValidatedPolicySetInfo {
        total_terms,
        referenced_wd_tags: wd_tags.into_iter().collect(),
        referenced_post_tags: post_tags.into_iter().collect(),
        referenced_authors: authors.into_iter().collect(),
    })
}

fn validate_country_list(codes: &[String], label: &str) -> Result<(), PolicyValidationError> {
    let mut seen = HashSet::new();
    for code in codes {
        if !is_valid_iso_country_code(code) {
            return Err(PolicyValidationError::InvalidField(format!(
                "{label}: invalid ISO-3166 alpha-2 country code '{code}' (expected 2 uppercase ASCII letters)"
            )));
        }
        if !seen.insert(code.as_str()) {
            return Err(PolicyValidationError::InvalidField(format!(
                "{label}: duplicate country code '{code}'"
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Conservative Version Bump & Grant Generation Helpers
// ---------------------------------------------------------------------------

fn normalized_opt_expr(raw: Option<&str>) -> Option<&str> {
    raw.map(str::trim).filter(|s| !s.is_empty())
}

fn normalized_countries(codes: &[String]) -> BTreeSet<String> {
    codes.iter().map(|c| c.trim().to_ascii_uppercase()).collect()
}

fn policy_enforcement_changed(old: &ContentPolicy, new: &ContentPolicy) -> bool {
    old.id != new.id
        || old.grant_generation != new.grant_generation
        || old.enabled != new.enabled
        || old.priority != new.priority
        || old.match_expr.trim() != new.match_expr.trim()
        || normalized_opt_expr(old.except_expr.as_deref())
            != normalized_opt_expr(new.except_expr.as_deref())
        || old.default_tag_min.to_bits() != new.default_tag_min.to_bits()
        || old.action != new.action
        || old.bypass.include_switcher != new.bypass.include_switcher
        || old.bypass.include_click != new.bypass.include_click
        || old.bypass.include_live_admin != new.bypass.include_live_admin
        || old.bypass.require_gallery_login != new.bypass.require_gallery_login
        || old.bypass.require_age_18 != new.bypass.require_age_18
        || old.bypass.require_current_terms != new.bypass.require_current_terms
        || old.bypass.exclude_anonymous != new.bypass.exclude_anonymous
        || normalized_countries(&old.bypass.exclude_countries)
            != normalized_countries(&new.bypass.exclude_countries)
}

/// Conservatively determines whether transitioning from `old` to `new` requires
/// raising `min_enforce_rev` to `new.revision`.
///
/// Returns `true` on ANY edit affecting selectors, exceptions, thresholds (in
/// EITHER direction!), action, bypass, country exclusions/geo, age policy/gate,
/// Terms version/digest, classification (`unclassified_mode`, `vocab_digest`),
/// preview mode (`fixed_blur_enabled`), safety master switch, or policy ordering/priority.
///
/// Purely cosmetic edits (display name, preset icon, privacy/DMCA/notice text,
/// search similarity defaults) return `false`.
pub fn should_bump_min_enforce_rev(old: &PublicSitePolicy, new: &PublicSitePolicy) -> bool {
    if old.safety_enabled != new.safety_enabled
        || old.unclassified_mode != new.unclassified_mode
        || old.fixed_blur_enabled != new.fixed_blur_enabled
        || old.vocab_digest != new.vocab_digest
        || old.age_policy != new.age_policy
        || old.age_gate_trigger != new.age_gate_trigger
        || old.legal.terms_version != new.legal.terms_version
        || old.legal.terms_digest != new.legal.terms_digest
        || old.geo.block_unknown != new.geo.block_unknown
        || old.geo.block_tor != new.geo.block_tor
        || normalized_countries(&old.geo.blocked_countries)
            != normalized_countries(&new.geo.blocked_countries)
    {
        return true;
    }

    if old.policies.len() != new.policies.len() {
        return true;
    }

    old.policies
        .iter()
        .zip(new.policies.iter())
        .any(|(o, n)| policy_enforcement_changed(o, n))
}

/// Computes the next monotonic `min_enforce_rev` using [`should_bump_min_enforce_rev`].
pub fn compute_next_min_enforce_rev(
    old: &PublicSitePolicy,
    new: &PublicSitePolicy,
    new_revision: u64,
) -> (u64, bool) {
    let bumped = should_bump_min_enforce_rev(old, new);
    if bumped {
        (old.min_enforce_rev.max(new_revision), true)
    } else {
        (old.min_enforce_rev, false)
    }
}

/// Updates `grant_generation` on every policy in `new.policies` relative to `old.policies`.
///
/// Advances `grant_generation` (`old.grant_generation.max(1) + 1`) whenever a
/// policy changes what a saved opt-in (`include_switcher`) authorizes:
/// selector (`match_expr`), exception (`except_expr`), threshold (`default_tag_min`),
/// action (`Block <-> Blur`), re-enabling the policy or its switcher branch, or
/// modifying any `require_*` / `exclude_*` bypass condition.
///
/// Never allows `grant_generation` to decrease below the previous generation.
pub fn compute_next_grant_generations(old: &PublicSitePolicy, new: &mut PublicSitePolicy) {
    let prev_by_id: HashMap<&str, &ContentPolicy> = old
        .policies
        .iter()
        .map(|p| (p.id.as_str(), p))
        .collect();

    for next_p in &mut new.policies {
        let Some(&prev_p) = prev_by_id.get(next_p.id.as_str()) else {
            // Monotonic floor using `new.revision`: if an admin deletes a policy slug
            // and later recreates the same slug, its `grant_generation` jumps above any
            // previously issued generation so stale user DO opt-ins never reactivate.
            let fresh_floor = new.revision.max(1);
            next_p.grant_generation = next_p.grant_generation.max(fresh_floor);
            continue;
        };

        let base = prev_p.grant_generation.max(1);
        let opt_in_scope_changed = prev_p.match_expr.trim() != next_p.match_expr.trim()
            || normalized_opt_expr(prev_p.except_expr.as_deref())
                != normalized_opt_expr(next_p.except_expr.as_deref())
            || prev_p.default_tag_min.to_bits() != next_p.default_tag_min.to_bits()
            || prev_p.action != next_p.action
            || (!prev_p.enabled && next_p.enabled)
            || (!prev_p.bypass.include_switcher && next_p.bypass.include_switcher)
            || prev_p.bypass.require_gallery_login != next_p.bypass.require_gallery_login
            || prev_p.bypass.require_age_18 != next_p.bypass.require_age_18
            || prev_p.bypass.require_current_terms != next_p.bypass.require_current_terms
            || prev_p.bypass.exclude_anonymous != next_p.bypass.exclude_anonymous
            || normalized_countries(&prev_p.bypass.exclude_countries)
                != normalized_countries(&next_p.bypass.exclude_countries);

        if opt_in_scope_changed {
            next_p.grant_generation = base.saturating_add(1).max(next_p.grant_generation);
        } else {
            next_p.grant_generation = base.max(next_p.grant_generation);
        }
    }
}

// ---------------------------------------------------------------------------
// SessionContext, PolicyCallerContext & compute_policy_access
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
/// `gateway_worker` on every protected request (Safe Mode removed in Policy v3).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionContext {
    pub active: bool,
    pub banned: bool,
    pub suspended: bool,
    pub sid_valid: bool,
    pub assurance_level: AssuranceLevel,
    pub strict_age_ok: bool,
    pub terms_version_accepted: Option<u32>,
    pub terms_digest_accepted: Option<String>,
    pub enabled_switchers: Vec<PolicyRef>,
    pub pref_version: u64,
}

impl SessionContext {
    pub fn is_authenticated(&self) -> bool {
        self.active && !self.banned && !self.suspended && self.sid_valid
    }

    /// Evaluates whether this authenticated session satisfies a policy's
    /// `require_age_18` gate under the site's [`AgeVerificationPolicy`].
    ///
    /// CRITICAL Policy v3 invariant: returns `false` when `policy == Off`!
    pub fn satisfies_age_18(&self, policy: AgeVerificationPolicy) -> bool {
        match policy {
            AgeVerificationPolicy::Off => false,
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
}

/// Live request context fed into [`compute_policy_access`].
///
/// NOTE: `ADMIN_VIEW_COOKIE` (browse-pass) MUST NEVER populate `live_admin_email`
/// or `session`; browse-pass is strictly limited to billing and guest login wall waiver.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PolicyCallerContext {
    /// Live gallery session context if a gallery session cookie was presented.
    pub session: Option<SessionContext>,
    /// True if a session cookie was presented but was revoked, expired, or invalid.
    /// Forces ZERO bypass grants (fail closed).
    pub session_revoked_or_invalid: bool,
    /// Live verified staff CF Access email on THIS request (after optional allowlist check).
    /// NEVER populated from `ADMIN_VIEW_COOKIE`.
    pub live_admin_email: Option<String>,
    /// Runtime Cloudflare `request.cf().country()` (e.g. `Some("US")`, `Some("XX")`, `Some("T1")`).
    pub country: Option<String>,
}

/// Computed Policy v3 bypass entitlements for a live request.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyAccessResult {
    /// Policies bypassed directly via matched Switcher opt-in or LiveAdmin bypass.
    pub direct_grants: Vec<PolicyRef>,
    /// `Blur` policies eligible for object-bound `POST /api/safety/reveal`.
    pub click_eligible: Vec<PolicyRef>,
}

/// Computes `direct_grants` and `click_eligible` under Policy v3 rules:
///
/// - Formula: `any(enabled Include matches) AND all(checked Require pass) AND none(checked Exclude match)`
/// - Empty `Include` => ALWAYS FALSE.
/// - Banned, suspended, or presented revoked session => ZERO grants (`direct_grants = []`, `click_eligible = []`).
/// - `require_age_18` => ALWAYS FALSE when `policy.age_policy == AgeVerificationPolicy::Off`.
/// - `require_current_terms` => exact `terms_version` AND `terms_digest` match.
/// - `include_live_admin` => requires live verified `live_admin_email.is_some()` AND all `Require`/`Exclude` still apply.
/// - `include_click` => ONLY valid on `PolicyAction::Blur` (defense-in-depth ignored on `Block`).
/// - `exclude_countries` non-empty => missing, `""`, `"XX"`, or `"T1"` is DENIED.
pub fn compute_policy_access(
    policy: &PublicSitePolicy,
    caller: &PolicyCallerContext,
) -> PolicyAccessResult {
    if !policy.safety_enabled || policy.schema_version != SITE_POLICY_SCHEMA_VERSION {
        return PolicyAccessResult::default();
    }

    // Presented revoked/invalid/banned/suspended session => ZERO bypass.
    if caller.session_revoked_or_invalid {
        return PolicyAccessResult::default();
    }
    if let Some(sess) = &caller.session
        && (sess.banned || sess.suspended || !sess.active || !sess.sid_valid)
    {
        return PolicyAccessResult::default();
    }

    let authed_session = caller.session.as_ref().filter(|s| s.is_authenticated());
    let has_gallery_login = authed_session.is_some();
    let has_live_admin = caller
        .live_admin_email
        .as_deref()
        .map(str::trim)
        .is_some_and(|e| !e.is_empty());
    let is_anonymous = !has_gallery_login && !has_live_admin;
    let age_18_ok = authed_session.is_some_and(|s| s.satisfies_age_18(policy.age_policy));
    let current_terms_ok = authed_session.is_some_and(|s| s.satisfies_terms(&policy.legal));

    let mut direct_grants = Vec::new();
    let mut click_eligible = Vec::new();

    for rule in &policy.policies {
        if !rule.enabled || !rule.bypass.has_any_include() {
            continue;
        }

        // REQUIRE (AND)
        if rule.bypass.require_gallery_login && !has_gallery_login {
            continue;
        }
        if rule.bypass.require_age_18
            && (!policy.age_policy.requires_adult_assurance() || !age_18_ok)
        {
            continue;
        }
        if rule.bypass.require_current_terms && !current_terms_ok {
            continue;
        }

        // EXCLUDE (NOR)
        if rule.bypass.exclude_anonymous && is_anonymous {
            continue;
        }
        if rule.bypass.is_country_excluded(caller.country.as_deref()) {
            continue;
        }

        // INCLUDE (OR)
        let pref = rule.policy_ref();
        let switcher_matched = rule.bypass.include_switcher
            && authed_session.is_some_and(|s| s.enabled_switchers.contains(&pref));
        let live_admin_matched = rule.bypass.include_live_admin && has_live_admin;
        let click_matched = rule.action == PolicyAction::Blur && rule.bypass.include_click;

        if (switcher_matched || live_admin_matched) && !direct_grants.contains(&pref) {
            direct_grants.push(pref.clone());
        }
        if click_matched && !click_eligible.contains(&pref) {
            click_eligible.push(pref);
        }
    }

    PolicyAccessResult {
        direct_grants,
        click_eligible,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_policy(id: &str, action: PolicyAction, bypass: PolicyBypass) -> ContentPolicy {
        ContentPolicy {
            id: id.to_string(),
            grant_generation: 1,
            enabled: true,
            priority: 10,
            name: id.to_string(),
            preset: PlaceholderPreset::Custom,
            match_expr: "tag:blood".to_string(),
            except_expr: None,
            default_tag_min: 0.45,
            action,
            bypass,
        }
    }

    fn authed_session(
        policy: &PublicSitePolicy,
        switchers: Vec<PolicyRef>,
    ) -> SessionContext {
        SessionContext {
            active: true,
            banned: false,
            suspended: false,
            sid_valid: true,
            assurance_level: AssuranceLevel::SelfAttestation,
            strict_age_ok: false,
            terms_version_accepted: Some(policy.legal.terms_version),
            terms_digest_accepted: Some(policy.legal.terms_digest.clone()),
            enabled_switchers: switchers,
            pref_version: 1,
        }
    }

    #[test]
    fn policy_ref_key_roundtrip_and_strict_rejection() {
        let pref = PolicyRef::new("r18_strict-1", 42);
        assert_eq!(pref.to_key(), "r18_strict-1@42");
        assert_eq!(PolicyRef::from_key("r18_strict-1@42").unwrap(), pref);

        for bad in [
            "",
            "r18",
            "r18@",
            "@1",
            "r18@0",
            "r18@01",
            "r18@-1",
            "r18@1@2",
            "R18@1",
            "r18 @1",
            "r18@1 ",
        ] {
            assert!(
                PolicyRef::from_key(bad).is_err(),
                "must reject invalid PolicyRef key {bad:?}"
            );
        }
    }

    #[test]
    fn validate_policy_set_enforces_codex_invariants() {
        let mut p = PublicSitePolicy {
            revision: 1,
            min_enforce_rev: 1,
            safety_enabled: true,
            policies: builtin_safety_presets(),
            ..PublicSitePolicy::default()
        };
        p.refresh_policy_digest();
        let info = validate_policy_set(&p).expect("builtin presets valid");
        assert_eq!(info.total_terms, 19);

        // 1. Block + include_click MUST be rejected
        let mut bad_click = p.clone();
        bad_click.policies[0].action = PolicyAction::Block;
        bad_click.policies[0].bypass.include_click = true;
        assert!(validate_policy_set(&bad_click).is_err());

        // 2. require_age_18 while age_policy == Off MUST be rejected
        let mut bad_age = p.clone();
        bad_age.age_policy = AgeVerificationPolicy::Off;
        bad_age.policies[0].bypass.require_age_18 = true;
        assert!(validate_policy_set(&bad_age).is_err());
        bad_age.age_policy = AgeVerificationPolicy::SelfAttestation;
        assert!(validate_policy_set(&bad_age).is_ok());

        // 3. Unknown WD tag (in match_expr, NOT, or except_expr) MUST be rejected
        let mut bad_tag = p.clone();
        bad_tag.policies[2].match_expr = "tag:blood AND NOT tag:not_a_real_wd_tag".into();
        assert!(validate_policy_set(&bad_tag).is_err());

        let mut bad_except = p.clone();
        bad_except.policies[2].except_expr = Some("tag:typoo_tag".into());
        assert!(validate_policy_set(&bad_except).is_err());

        // 4. Lowercase or non-alpha2 exclude_countries MUST be rejected
        let mut bad_country = p.clone();
        bad_country.policies[0].bypass.exclude_countries = vec!["us".into()];
        assert!(validate_policy_set(&bad_country).is_err());
        bad_country.policies[0].bypass.exclude_countries = vec!["USA".into()];
        assert!(validate_policy_set(&bad_country).is_err());
        bad_country.policies[0].bypass.exclude_countries = vec!["T1".into()];
        assert!(validate_policy_set(&bad_country).is_err());
        bad_country.policies[0].bypass.exclude_countries = vec!["US".into(), "GB".into()];
        assert!(validate_policy_set(&bad_country).is_ok());

        // 5. > 2 decimal places default_tag_min rejected on publish
        let mut bad_min = p.clone();
        bad_min.policies[0].default_tag_min = 0.456;
        assert!(validate_policy_set(&bad_min).is_err());
        bad_min.policies[0].default_tag_min = 0.0;
        assert!(validate_policy_set(&bad_min).is_err());

        // 6. Strict schema decoding rejects missing/non-3 schema_version and legacy `rules`
        assert!(decode_active_policy_v3(r#"{"revision":1,"safety_enabled":true,"rules":[]}"#).is_err());
        assert!(decode_active_policy_v3(r#"{"schema_version":2,"revision":1,"safety_enabled":true}"#).is_err());
        let good_json = canonical_policy_json(&p);
        assert_eq!(decode_active_policy_v3(&good_json).unwrap(), p);

        // Digest mismatch on active policy fails closed
        let tampered_json = good_json.replace(&p.policy_digest, &"0".repeat(64));
        assert_eq!(
            decode_active_policy_v3(&tampered_json),
            Err(PolicyValidationError::DigestMismatch)
        );
    }

    #[test]
    fn compute_policy_access_enforces_empty_include_age_off_countries_bans_and_live_admin() {
        let mut policy = PublicSitePolicy {
            revision: 3,
            min_enforce_rev: 1,
            safety_enabled: true,
            age_policy: AgeVerificationPolicy::Off,
            policies: vec![
                // Empty Include => ALWAYS FALSE
                sample_policy("empty_inc", PolicyAction::Blur, PolicyBypass::default()),
                // Age18 gate (must be FALSE when age_policy == Off!)
                sample_policy(
                    "age_gated",
                    PolicyAction::Block,
                    PolicyBypass {
                        include_switcher: true,
                        require_age_18: true,
                        ..PolicyBypass::default()
                    },
                ),
                // Country-excluded blur with click + live admin
                sample_policy(
                    "geo_blur",
                    PolicyAction::Blur,
                    PolicyBypass {
                        include_click: true,
                        include_live_admin: true,
                        exclude_countries: vec!["GB".into()],
                        ..PolicyBypass::default()
                    },
                ),
                // LiveAdmin + require_gallery_login + require_current_terms
                sample_policy(
                    "admin_strict",
                    PolicyAction::Block,
                    PolicyBypass {
                        include_live_admin: true,
                        require_gallery_login: true,
                        require_current_terms: true,
                        ..PolicyBypass::default()
                    },
                ),
                // Switcher with generation 2
                ContentPolicy {
                    grant_generation: 2,
                    ..sample_policy(
                        "gen2_sw",
                        PolicyAction::Block,
                        PolicyBypass {
                            include_switcher: true,
                            ..PolicyBypass::default()
                        },
                    )
                },
            ],
            ..PublicSitePolicy::default()
        };
        policy.refresh_policy_digest();

        // 1. Empty Include is ALWAYS false; Age18 with Off is ALWAYS false; stale gen1 != gen2!
        let sess = authed_session(
            &policy,
            vec![
                PolicyRef::new("empty_inc", 1),
                PolicyRef::new("age_gated", 1),
                PolicyRef::new("gen2_sw", 1), // stale generation!
            ],
        );
        let res = compute_policy_access(
            &policy,
            &PolicyCallerContext {
                session: Some(sess.clone()),
                session_revoked_or_invalid: false,
                live_admin_email: None,
                country: Some("US".into()),
            },
        );
        assert!(res.direct_grants.is_empty());
        assert_eq!(res.click_eligible, vec![PolicyRef::new("geo_blur", 1)]);

        // 2. Country missing, "", "XX", "T1", or "GB" MUST deny geo_blur!
        for denied_country in [None, Some(""), Some("XX"), Some("T1"), Some("GB"), Some("gb")] {
            let res_geo = compute_policy_access(
                &policy,
                &PolicyCallerContext {
                    session: None,
                    session_revoked_or_invalid: false,
                    live_admin_email: Some("admin@example.com".into()),
                    country: denied_country.map(str::to_string),
                },
            );
            assert!(
                !res_geo.click_eligible.contains(&PolicyRef::new("geo_blur", 1))
                    && !res_geo.direct_grants.contains(&PolicyRef::new("geo_blur", 1)),
                "country {denied_country:?} must be denied for geo_blur"
            );
        }

        // 3. LiveAdmin still enforces require_gallery_login + require_current_terms!
        let admin_no_login = compute_policy_access(
            &policy,
            &PolicyCallerContext {
                session: None,
                session_revoked_or_invalid: false,
                live_admin_email: Some("staff@example.com".into()),
                country: Some("US".into()),
            },
        );
        assert_eq!(admin_no_login.direct_grants, vec![PolicyRef::new("geo_blur", 1)]);
        assert!(!admin_no_login.direct_grants.contains(&PolicyRef::new("admin_strict", 1)));

        let admin_with_login = compute_policy_access(
            &policy,
            &PolicyCallerContext {
                session: Some(sess.clone()),
                session_revoked_or_invalid: false,
                live_admin_email: Some("staff@example.com".into()),
                country: Some("US".into()),
            },
        );
        assert!(admin_with_login.direct_grants.contains(&PolicyRef::new("admin_strict", 1)));

        // 4. Banned / suspended / revoked session receives ZERO grants (even if click or live_admin!)
        let mut banned_sess = sess.clone();
        banned_sess.banned = true;
        let banned_res = compute_policy_access(
            &policy,
            &PolicyCallerContext {
                session: Some(banned_sess),
                session_revoked_or_invalid: false,
                live_admin_email: Some("staff@example.com".into()),
                country: Some("US".into()),
            },
        );
        assert!(banned_res.direct_grants.is_empty());
        assert!(banned_res.click_eligible.is_empty());

        let mut suspended_sess = sess.clone();
        suspended_sess.suspended = true;
        let susp_res = compute_policy_access(
            &policy,
            &PolicyCallerContext {
                session: Some(suspended_sess),
                session_revoked_or_invalid: false,
                live_admin_email: None,
                country: Some("US".into()),
            },
        );
        assert!(susp_res.direct_grants.is_empty());
        assert!(susp_res.click_eligible.is_empty());

        let revoked_res = compute_policy_access(
            &policy,
            &PolicyCallerContext {
                session: None,
                session_revoked_or_invalid: true,
                live_admin_email: Some("staff@example.com".into()),
                country: Some("US".into()),
            },
        );
        assert!(revoked_res.direct_grants.is_empty());
        assert!(revoked_res.click_eligible.is_empty());

        // 5. Exact gen2 match + age_policy enabled unlocks age_gated & gen2_sw
        policy.age_policy = AgeVerificationPolicy::SelfAttestation;
        let sess_gen2 = authed_session(
            &policy,
            vec![PolicyRef::new("age_gated", 1), PolicyRef::new("gen2_sw", 2)],
        );
        let ok_res = compute_policy_access(
            &policy,
            &PolicyCallerContext {
                session: Some(sess_gen2),
                session_revoked_or_invalid: false,
                live_admin_email: None,
                country: Some("US".into()),
            },
        );
        assert_eq!(
            ok_res.direct_grants,
            vec![PolicyRef::new("age_gated", 1), PolicyRef::new("gen2_sw", 2)]
        );
    }

    #[test]
    fn conservative_min_enforce_rev_and_grant_generation_bumps() {
        let base = PublicSitePolicy {
            revision: 5,
            min_enforce_rev: 2,
            safety_enabled: true,
            fixed_blur_enabled: true,
            policies: builtin_safety_presets(),
            ..PublicSitePolicy::default()
        };

        // Purely cosmetic changes do NOT bump min_enforce_rev or grant_generation
        let mut cosmetic = base.clone();
        cosmetic.policies[0].name = "Renamed NSFW".into();
        cosmetic.policies[0].preset = PlaceholderPreset::Custom;
        cosmetic.legal.privacy_md = "Updated privacy text".into();
        assert!(!should_bump_min_enforce_rev(&base, &cosmetic));
        compute_next_grant_generations(&base, &mut cosmetic);
        assert_eq!(cosmetic.policies[0].grant_generation, 1);

        // Raising default_tag_min (even upward!) MUST bump BOTH min_enforce_rev AND grant_generation!
        let mut raised_min = base.clone();
        raised_min.policies[0].default_tag_min = 0.65;
        assert!(should_bump_min_enforce_rev(&base, &raised_min));
        compute_next_grant_generations(&base, &mut raised_min);
        assert_eq!(raised_min.policies[0].grant_generation, 2);
        assert_eq!(raised_min.policies[1].grant_generation, 1);

        // Adding except_expr bumps BOTH min_enforce_rev AND grant_generation
        let mut with_except = base.clone();
        with_except.policies[1].except_expr = Some("tag:general".into());
        assert!(should_bump_min_enforce_rev(&base, &with_except));
        compute_next_grant_generations(&base, &mut with_except);
        assert_eq!(with_except.policies[1].grant_generation, 2);

        // Toggling fixed_blur_enabled bumps min_enforce_rev
        let mut blur_off = base.clone();
        blur_off.fixed_blur_enabled = false;
        assert!(should_bump_min_enforce_rev(&base, &blur_off));

        // Reordering priority bumps min_enforce_rev (without invalidating saved opt-in gen)
        let mut reordered = base.clone();
        reordered.policies[0].priority = 99;
        assert!(should_bump_min_enforce_rev(&base, &reordered));
        compute_next_grant_generations(&base, &mut reordered);
        assert_eq!(reordered.policies[0].grant_generation, 1);
    }

    #[test]
    fn validate_policy_set_supports_in_not_in_rules_and_extracts_all_refs() {
        let mut p = PublicSitePolicy {
            revision: 1,
            min_enforce_rev: 1,
            safety_enabled: true,
            policies: vec![ContentPolicy {
                id: "r18".into(),
                grant_generation: 1,
                enabled: true,
                priority: 10,
                name: "R-18".into(),
                preset: PlaceholderPreset::R18,
                match_expr: "tag IN (explicit, nude, nipples) >= 0.45".into(),
                except_expr: Some(
                    r#"post_tag IN (medical, educational) OR author NOT IN ("alice", bob)"#.into(),
                ),
                default_tag_min: 0.45,
                action: PolicyAction::Block,
                bypass: PolicyBypass::default(),
            }],
            ..PublicSitePolicy::default()
        };
        p.refresh_policy_digest();

        let info = validate_policy_set(&p).expect("IN/NOT IN policy set valid");
        assert_eq!(info.total_terms, 7);
        assert_eq!(
            info.referenced_wd_tags,
            vec!["explicit", "nipples", "nude"]
        );
        assert_eq!(info.referenced_post_tags, vec!["educational", "medical"]);
        assert_eq!(info.referenced_authors, vec!["alice", "bob"]);

        // Typo inside `tag NOT IN (...)` rejected by validate_policy_set
        let mut bad = p.clone();
        bad.policies[0].match_expr = "tag NOT IN (general, bad_wd_typo) >= 0.45".into();
        assert!(validate_policy_set(&bad).is_err());
    }

    #[test]
    fn r18_prohibited_countries_preset_is_valid_sorted_and_generates_waf_rule() {
        assert!(!R18_PROHIBITED_COUNTRIES.is_empty());
        for w in R18_PROHIBITED_COUNTRIES.windows(2) {
            assert!(
                w[0] < w[1],
                "R18_PROHIBITED_COUNTRIES must be strictly sorted & deduplicated: {} vs {}",
                w[0],
                w[1]
            );
        }
        for &code in R18_PROHIBITED_COUNTRIES {
            assert!(
                is_valid_iso_country_code(code),
                "preset country code '{code}' must be valid ISO-3166 alpha-2 (excluding XX/T1)"
            );
        }

        // Empty GeoPolicy produces None
        assert_eq!(GeoPolicy::default().to_cloudflare_waf_expression(), None);

        // Single country uses `eq` + `/admin` exemption
        let single = GeoPolicy {
            blocked_countries: vec![" kp ".into()],
            block_unknown: false,
            block_tor: false,
        };
        assert_eq!(
            single.to_cloudflare_waf_expression().as_deref(),
            Some(
                r#"(ip.src.country eq "KP") and not (http.request.uri.path eq "/admin" or starts_with(http.request.uri.path, "/admin/"))"#
            )
        );

        // Multiple countries + Tor + Unknown deduplicates, ignores invalid tokens, and includes T1/XX
        let mixed = GeoPolicy {
            blocked_countries: vec!["cn".into(), "AE".into(), "INVALID".into(), "XX".into()],
            block_unknown: true,
            block_tor: true,
        };
        assert_eq!(
            mixed.to_cloudflare_waf_expression().as_deref(),
            Some(
                r#"(ip.src.country in {"AE" "CN" "T1" "XX"}) and not (http.request.uri.path eq "/admin" or starts_with(http.request.uri.path, "/admin/"))"#
            )
        );

        // Merging preset preserves custom additions and validates inside PublicSitePolicy
        let merged = merge_country_codes(&["us".into(), "CN".into()], R18_PROHIBITED_COUNTRIES);
        assert_eq!(merged.len(), R18_PROHIBITED_COUNTRIES.len() + 1);
        assert!(merged.iter().any(|c| c == "US"));

        let mut pol = PublicSitePolicy {
            revision: 1,
            min_enforce_rev: 1,
            geo: GeoPolicy {
                blocked_countries: merged,
                block_unknown: false,
                block_tor: true,
            },
            ..PublicSitePolicy::default()
        };
        pol.refresh_policy_digest();
        validate_policy_set(&pol).expect("R-18 geo preset must pass validate_policy_set");
        let waf = pol
            .geo
            .to_cloudflare_waf_expression()
            .expect("non-empty WAF rule");
        assert!(waf.starts_with(r#"(ip.src.country in {"AE" "AF" "#));
        assert!(waf.contains(r#""T1""#));
        assert!(waf.contains(r#"starts_with(http.request.uri.path, "/admin/")"#));
    }

    #[test]
    fn zero_config_effective_providers_and_monotonic_recreated_grant_generation() {
        // Fresh zero-config policy (empty providers, Age Off) exposes SIWE + SIWS
        let fresh = PublicSitePolicy::default();
        let ids: Vec<AuthProviderId> = fresh
            .effective_login_providers()
            .into_iter()
            .map(|p| p.id)
            .collect();
        assert_eq!(ids, vec![AuthProviderId::Siwe, AuthProviderId::Siws]);

        // Under SelfAttestation, zero-config preserves SIWE + SIWS defaults
        let self_attested = PublicSitePolicy {
            age_policy: AgeVerificationPolicy::SelfAttestation,
            ..PublicSitePolicy::default()
        };
        let self_ids: Vec<AuthProviderId> = self_attested
            .effective_login_providers()
            .into_iter()
            .map(|p| p.id)
            .collect();
        assert_eq!(self_ids, vec![AuthProviderId::Siwe, AuthProviderId::Siws]);

        // Under StrictProviderVerified18, zero-config does NOT expose SIWE/SIWS
        let strict = PublicSitePolicy {
            age_policy: AgeVerificationPolicy::StrictProviderVerified18,
            ..PublicSitePolicy::default()
        };
        assert!(strict.effective_login_providers().is_empty());

        // Deleting a policy at rev 5 and recreating the same slug at rev 6 assigns grant_generation >= 6
        let after_delete = PublicSitePolicy {
            revision: 5,
            min_enforce_rev: 5,
            policies: Vec::new(),
            ..PublicSitePolicy::default()
        };
        let mut recreated = PublicSitePolicy {
            revision: 6,
            min_enforce_rev: 5,
            policies: vec![ContentPolicy {
                id: "r18".into(),
                grant_generation: 1,
                enabled: true,
                priority: 10,
                name: "Recreated R-18".into(),
                preset: PlaceholderPreset::R18,
                match_expr: "tag:explicit >= 0.45".into(),
                except_expr: None,
                default_tag_min: 0.45,
                action: PolicyAction::Block,
                bypass: PolicyBypass::default(),
            }],
            ..PublicSitePolicy::default()
        };
        compute_next_grant_generations(&after_delete, &mut recreated);
        assert_eq!(recreated.policies[0].grant_generation, 6);
    }
}
