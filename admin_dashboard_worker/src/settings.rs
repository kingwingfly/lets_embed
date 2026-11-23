//! Immutable revisioned site settings (`site_settings` D1 table), access/pricing
//! validation, safety/age/legal/geo/provider validation, monotonic `min_enforce_rev`
//! tightening detection, and atomic `SitePolicyDO` publication.
//!
//! `site_settings.document` stores the flattened union of [`AccessPolicy`] and
//! [`PublicSitePolicy`] (whose field names are 100% disjoint, with ZERO secret fields),
//! keeping backwards-compatibility with `user_worker` billing/deposit lookups and
//! `SitePolicyDO` cold-start bootstrapping.

use std::collections::HashSet;

use search_types::{
    safety::{MAX_RULES_PER_POLICY, validate_policy_rules},
    validate_min_similarity,
};
use serde::{Deserialize, Serialize};
use site_access::{
    AgeGateTrigger, AgeVerificationPolicy, AuthProviderId, AuthProviderPublicConfig, ChargeKind,
    PublicSitePolicy, RuleMode, SafetyRuleConfig, UnclassifiedMode, compute_policy_digest,
    compute_terms_digest, is_eth_address, is_sol_principal,
};
use worker::{Env, Result};

use crate::{
    D1_BINDING,
    api::{ProviderUpdateItem, SaveSafetyReq},
    do_client,
    security::{validate_and_normalize_geo, validate_oidc_url},
};

pub const MAX_VALUE: i64 = 1_000_000_000;
pub const MAX_LEGAL_DOC_BYTES: usize = 100_000;
pub const MAX_NOTICE_BANNER_BYTES: usize = 8_000;

pub const LEGACY_UNCLASSIFIED_NOTE: &str = "Legacy-ingested or pending images (`images.status != 'completed'`) fail closed to Locked whenever any Switcher rule is enabled (unless Unclassified Mode is set to Allow). Run `embed --retag-safety` against Postgres to backfill WD-Tagger category-9 rating and safety-vocabulary tags on existing media.";

// Default pricing / plan constants matching `user_worker/src/config.rs`.
pub const DEFAULT_POINTS_PER_USD: i64 = 10_000;
pub const DEFAULT_COST_IMAGE_VIEW: i64 = 1;
pub const DEFAULT_COST_VIDEO_VIEW: i64 = 5;
pub const DEFAULT_COST_SEARCH: i64 = 100;
pub const DEFAULT_COST_EMBED_SEARCH: i64 = 10;
pub const DEFAULT_FREE_GRANT_POINTS: i64 = 3_000;
pub const DEFAULT_MIN_TOPUP_POINTS: i64 = 1_000;

pub const PLAN_IDS: [&str; 2] = ["basic", "pro"];

/// Known ERC-20 contracts and Chainlink price feeds that must never be configured
/// as an Ethereum deposit treasury address.
const DISALLOWED_ETH_RECIPIENTS: &[&str] = &[
    "0xdac17f958d2ee523a2206206994597c13d831ec7", // USDT
    "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48", // USDC
    "0x5f4ec3df9cbd43714fe2740f5e3616155c5b8419", // Chainlink ETH/USD
    "0x4ffc43a60e009b551865a93d232e33fce9f01507", // Chainlink SOL/USD
];

/// Known Solana programs and SPL mints that must never be configured as a Solana treasury.
const DISALLOWED_SOLANA_RECIPIENTS: &[&str] = &[
    "11111111111111111111111111111111",             // System Program
    "So11111111111111111111111111111111111111112",  // Wrapped SOL native mint
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",  // SPL Token Program
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",  // SPL Token-2022 Program
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL", // SPL Associated Token Account Program
    "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",  // SPL Memo v2 Program
    "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo",  // SPL Memo v1 Program
    "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB", // SPL USDT
    "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", // SPL USDC
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChainKind {
    Ethereum,
    Solana,
}

/// Validates an Ethereum or Solana deposit treasury address (rejects zero address,
/// token contracts, Chainlink feeds, Solana programs/mints, and off-curve PDAs).
pub fn valid_deposit_address(chain: ChainKind, address: &str) -> bool {
    match chain {
        ChainKind::Ethereum => {
            is_eth_address(address)
                && address[2..].bytes().any(|b| b != b'0')
                && !DISALLOWED_ETH_RECIPIENTS
                    .iter()
                    .any(|c| c.eq_ignore_ascii_case(address))
        }
        ChainKind::Solana => {
            if !is_sol_principal(address) || DISALLOWED_SOLANA_RECIPIENTS.contains(&address) {
                return false;
            }
            let mut raw = [0u8; 32];
            matches!(bs58::decode(address).onto(&mut raw), Ok(32))
                && ed25519_dalek::VerifyingKey::from_bytes(&raw).is_ok_and(|vk| !vk.is_weak())
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemPricing {
    pub price: i64,
    pub daily_free: i64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanTerms {
    pub price: i64,
    pub views: Option<i64>,
    pub searches: i64,
}

/// Access, metering, subscription, and treasury settings stored in `site_settings.document`
/// alongside `PublicSitePolicy`. Field names match `user_worker/src/settings.rs::Policy`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AccessPolicy {
    pub login_required: bool,
    pub free_media_folders: Vec<String>,
    pub items: [ItemPricing; 5],
    pub plans: [PlanTerms; 2],
    pub signup_points: i64,
    pub points_per_usd: i64,
    pub minimum_topup: i64,
    pub eth_deposit: String,
    pub sol_deposit: String,
}

impl Default for AccessPolicy {
    fn default() -> Self {
        let costs = [
            DEFAULT_COST_IMAGE_VIEW,
            DEFAULT_COST_VIDEO_VIEW,
            DEFAULT_COST_SEARCH,
            DEFAULT_COST_EMBED_SEARCH,
            DEFAULT_COST_SEARCH,
        ];
        Self {
            login_required: true,
            free_media_folders: Vec::new(),
            items: costs.map(|price| ItemPricing {
                price,
                daily_free: 0,
            }),
            plans: [
                PlanTerms {
                    price: 20_000,
                    views: Some(2_000),
                    searches: 10,
                },
                PlanTerms {
                    price: 50_000,
                    views: None,
                    searches: 50,
                },
            ],
            signup_points: DEFAULT_FREE_GRANT_POINTS,
            points_per_usd: DEFAULT_POINTS_PER_USD,
            minimum_topup: DEFAULT_MIN_TOPUP_POINTS,
            eth_deposit: String::new(),
            sol_deposit: String::new(),
        }
    }
}

impl AccessPolicy {
    /// Validates and canonically normalizes an [`AccessPolicy`] submitted via `/admin/api/settings/access`.
    pub fn validate_and_normalize(&self) -> std::result::Result<Self, String> {
        let check_range = |name: &str, v: i64, min: i64| -> std::result::Result<i64, String> {
            if (min..=MAX_VALUE).contains(&v) {
                Ok(v)
            } else {
                Err(format!("{name} must be between {min} and {MAX_VALUE}"))
            }
        };

        let points_per_usd = check_range("points_per_usd", self.points_per_usd, 1)?;
        let minimum_topup = check_range("minimum_topup", self.minimum_topup, 1)?;
        let signup_points = check_range("signup_points", self.signup_points, 0)?;

        let eth_deposit = self.eth_deposit.trim().to_ascii_lowercase();
        let sol_deposit = self.sol_deposit.trim().to_string();
        if !eth_deposit.is_empty() && !valid_deposit_address(ChainKind::Ethereum, &eth_deposit) {
            return Err("Invalid Ethereum deposit address".into());
        }
        if !sol_deposit.is_empty() && !valid_deposit_address(ChainKind::Solana, &sol_deposit) {
            return Err("Invalid Solana deposit address".into());
        }

        let mut folders = Vec::new();
        for raw in &self.free_media_folders {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            let folder = trimmed.trim_end_matches('/');
            let root = folder.split('/').nth(1);
            if !folder.starts_with('/')
                || !matches!(root, Some("images" | "videos"))
                || folder.contains("//")
                || folder.contains('\\')
                || folder.chars().any(char::is_control)
                || folder.split('/').any(|part| matches!(part, "." | ".."))
                || folder.len() > 1024
            {
                return Err(
                    "Each free media folder must be a clean gallery path under /images or /videos"
                        .into(),
                );
            }
            if !folders.iter().any(|existing: &String| existing == folder) {
                folders.push(folder.to_owned());
            }
        }
        if folders.len() > 64 {
            return Err("Choose up to 64 free media folders".into());
        }

        let mut items = self.items;
        for kind in ChargeKind::ALL {
            let idx = kind as usize;
            let name = kind.name();
            items[idx].price = check_range(&format!("{name}_price"), items[idx].price, 0)?;
            items[idx].daily_free =
                check_range(&format!("{name}_daily_free"), items[idx].daily_free, -1)?;
        }

        let mut plans = self.plans;
        for (idx, plan_id) in PLAN_IDS.iter().enumerate() {
            plans[idx].price = check_range(&format!("{plan_id}_price"), plans[idx].price, 0)?;
            if let Some(v) = plans[idx].views {
                plans[idx].views = Some(check_range(&format!("{plan_id}_views"), v, 0)?);
            }
            plans[idx].searches =
                check_range(&format!("{plan_id}_searches"), plans[idx].searches, 0)?;
        }

        Ok(Self {
            login_required: self.login_required,
            free_media_folders: folders,
            items,
            plans,
            signup_points,
            points_per_usd,
            minimum_topup,
            eth_deposit,
            sol_deposit,
        })
    }
}

/// Complete revisioned settings document stored in D1 `site_settings.document`.
///
/// Flattens [`AccessPolicy`] and [`PublicSitePolicy`] (disjoint fields, zero secrets).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SiteSettingsDocument {
    #[serde(flatten)]
    pub access: AccessPolicy,
    #[serde(flatten)]
    pub public: PublicSitePolicy,
}

// ---------------------------------------------------------------------------
// Secret Field Mapping for Auth Providers
// ---------------------------------------------------------------------------

/// Canonical `provider_secrets.field_name` for each provider that holds a server-side secret.
/// Wallet providers (`siwe`, `siws`) use public-key cryptography and store no secret.
pub const fn secret_field_for_provider(id: AuthProviderId) -> Option<&'static str> {
    match id {
        AuthProviderId::OidcAgeAssurance
        | AuthProviderId::Google
        | AuthProviderId::GitHub
        | AuthProviderId::X
        | AuthProviderId::Discord => Some("client_secret"),
        AuthProviderId::EmailOtp => Some("api_key"),
        AuthProviderId::Telegram => Some("bot_token"),
        AuthProviderId::Siwe | AuthProviderId::Siws => None,
    }
}

// ---------------------------------------------------------------------------
// Tightening Detection (Fixes H3)
// ---------------------------------------------------------------------------

const fn trigger_rank(trigger: AgeGateTrigger) -> u8 {
    match trigger {
        AgeGateTrigger::Off => 0,
        AgeGateTrigger::JustInTime => 1,
        AgeGateTrigger::SiteWideSplash => 2,
    }
}

/// Determines whether transitioning from `prev` to `next` tightens safety, age,
/// Terms, or geographic enforcement — requiring `min_enforce_rev = new_revision`
/// to immediately invalidate stale edge caches and anonymous media capability tokens.
pub fn did_policy_tighten(prev: &PublicSitePolicy, next: &PublicSitePolicy) -> bool {
    // 1. Safety master switch turned on
    if !prev.safety_enabled && next.safety_enabled {
        return true;
    }

    // 2. Safety enforcement parameters tightened while safety is enabled
    if next.safety_enabled {
        if prev.unclassified_mode == UnclassifiedMode::Allow
            && next.unclassified_mode == UnclassifiedMode::LockFailClosed
        {
            return true;
        }
        if !prev.cloudflare_images_blur && next.cloudflare_images_blur {
            return true;
        }
        if did_rules_tighten(&prev.rules, &next.rules) {
            return true;
        }
    }

    // 3. Age verification policy or gate trigger tightened
    if next.age_policy.strictness_rank() > prev.age_policy.strictness_rank() {
        return true;
    }
    if trigger_rank(next.age_gate_trigger) > trigger_rank(prev.age_gate_trigger) {
        return true;
    }

    // 4. Terms of Service version bumped or digest changed
    if next.legal.terms_version > prev.legal.terms_version
        || next.legal.terms_digest != prev.legal.terms_digest
    {
        return true;
    }

    // 5. Geo-blocklist expanded or unknown/Tor blocking turned on
    if (!prev.geo.block_unknown && next.geo.block_unknown)
        || (!prev.geo.block_tor && next.geo.block_tor)
    {
        return true;
    }
    for country in &next.geo.blocked_countries {
        if !prev
            .geo
            .blocked_countries
            .iter()
            .any(|old| old.eq_ignore_ascii_case(country))
        {
            return true;
        }
    }

    false
}

fn did_rules_tighten(prev_rules: &[SafetyRuleConfig], next_rules: &[SafetyRuleConfig]) -> bool {
    for next in next_rules.iter().filter(|r| r.enabled) {
        let Some(prev) = prev_rules.iter().find(|r| r.id == next.id && r.enabled) else {
            // Newly added or newly enabled rule.
            return true;
        };
        if prev.query.trim() != next.query.trim() {
            return true;
        }
        // Lowering default_min_score causes MORE media to match the rule -> stricter.
        if next.default_min_score + f32::EPSILON < prev.default_min_score {
            return true;
        }
        // Promoting SpoilerBlur -> Switcher hard-locks media -> stricter.
        if prev.mode == RuleMode::SpoilerBlur && next.mode == RuleMode::Switcher {
            return true;
        }
        if (!prev.requires_login && next.requires_login)
            || (!prev.requires_age_18 && next.requires_age_18)
        {
            return true;
        }
    }
    false
}

/// Computes the next monotonic `min_enforce_rev`.
pub fn compute_next_min_enforce_rev(
    prev: &PublicSitePolicy,
    next: &PublicSitePolicy,
    new_revision: u32,
) -> (u32, bool) {
    let tightened = did_policy_tighten(prev, next);
    let floor = prev.min_enforce_rev;
    if tightened {
        (floor.max(new_revision), true)
    } else {
        (floor, false)
    }
}

// ---------------------------------------------------------------------------
// Pure Policy Mutation Builders (Host-Testable)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ValidatedSafetyUpdate {
    pub next_policy: PublicSitePolicy,
    pub digest: String,
    pub tightened: bool,
    pub terms_bumped: bool,
    pub auto_disabled_providers: Vec<AuthProviderId>,
}

fn is_valid_rule_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_')
}

/// Validates and applies a `/admin/api/safety` update against `prev`, computing
/// `terms_digest`, bumping `terms_version` when `terms_md` changed, enforcing
/// Strict 18+ provider auto-disablement, and computing monotonic `min_enforce_rev`.
pub fn prepare_safety_update(
    prev: &PublicSitePolicy,
    req: &SaveSafetyReq,
    new_revision: u32,
) -> std::result::Result<ValidatedSafetyUpdate, String> {
    if req.rules.len() > MAX_RULES_PER_POLICY {
        return Err(format!(
            "Policy exceeds maximum of {MAX_RULES_PER_POLICY} safety rules"
        ));
    }

    let mut seen_ids = HashSet::new();
    let mut normalized_rules = Vec::with_capacity(req.rules.len());
    let mut queries_to_validate: Vec<String> = Vec::new();

    for (idx, rule) in req.rules.iter().enumerate() {
        let id = rule.id.trim().to_ascii_lowercase();
        if !is_valid_rule_id(&id) {
            return Err(format!(
                "Rule #{} id '{}' must be 1..=64 lowercase ASCII [a-z0-9_-]",
                idx + 1,
                rule.id
            ));
        }
        if !seen_ids.insert(id.clone()) {
            return Err(format!("Duplicate safety rule id '{id}'"));
        }
        let name = rule.name.trim().to_string();
        if name.is_empty() || name.len() > 120 || name.chars().any(char::is_control) {
            return Err(format!(
                "Rule '{id}' name must be 1..=120 non-control characters"
            ));
        }
        if !rule.default_min_score.is_finite()
            || rule.default_min_score <= 0.0
            || rule.default_min_score > 1.0
        {
            return Err(format!(
                "Rule '{id}' default_min_score must be finite and in (0.0, 1.0]"
            ));
        }

        let query = rule.query.trim().to_string();
        if rule.enabled && query.is_empty() {
            return Err(format!("Enabled rule '{id}' cannot have an empty query"));
        }
        if !query.is_empty() {
            queries_to_validate.push(query.clone());
        }

        normalized_rules.push(SafetyRuleConfig {
            id,
            name,
            mode: rule.mode,
            query,
            default_min_score: rule.default_min_score,
            preset: rule.preset,
            requires_login: rule.requires_login,
            requires_age_18: rule.requires_age_18,
            enabled: rule.enabled,
        });
    }

    // Validate all non-empty rule queries via shared metadata-only safety grammar.
    validate_policy_rules(queries_to_validate.iter().map(String::as_str))
        .map_err(|e| format!("Invalid safety rule: {e}"))?;

    // Validate similarity thresholds via search_types helper.
    validate_min_similarity(Some(req.similarity.dinov3_min))
        .map_err(|e| format!("DINOv3 {e}"))?;
    validate_min_similarity(Some(req.similarity.siglip2_min))
        .map_err(|e| format!("SigLIP2 {e}"))?;

    // Validate and normalize ISO-3166 geo blocklist.
    let geo = validate_and_normalize_geo(&req.geo)?;

    // Validate panic shortcut.
    let panic_shortcut = req.panic_shortcut.trim().to_string();
    if panic_shortcut.is_empty()
        || panic_shortcut.len() > 32
        || panic_shortcut.chars().any(char::is_control)
    {
        return Err("Panic shortcut must be 1..=32 non-control characters".into());
    }

    // Validate legal document lengths and compute canonical terms digest + monotonic version.
    let mut legal = req.legal.clone();
    for (label, doc, limit) in [
        ("Terms of Service", &legal.terms_md, MAX_LEGAL_DOC_BYTES),
        ("Privacy Policy", &legal.privacy_md, MAX_LEGAL_DOC_BYTES),
        ("DMCA Policy", &legal.dmca_md, MAX_LEGAL_DOC_BYTES),
        ("Content Policy", &legal.content_policy_md, MAX_LEGAL_DOC_BYTES),
        (
            "Notice Banner",
            &legal.notice_banner_md,
            MAX_NOTICE_BANNER_BYTES,
        ),
    ] {
        if doc.len() > limit {
            return Err(format!("{label} exceeds maximum length of {limit} bytes"));
        }
    }
    let new_terms_digest = compute_terms_digest(&legal.terms_md);
    let prev_terms_digest = compute_terms_digest(&prev.legal.terms_md);
    let terms_bumped = new_terms_digest != prev_terms_digest || new_terms_digest != prev.legal.terms_digest;
    legal.terms_digest = new_terms_digest;
    legal.terms_version = if terms_bumped {
        prev.legal.terms_version.max(1).saturating_add(1)
    } else {
        prev.legal.terms_version.max(1)
    };

    // Enforce Strict 18+ invariant on already-configured providers: automatically
    // disable any non-age-capable provider when switching into StrictProviderVerified18.
    let mut enabled_providers = prev.enabled_providers.clone();
    let mut auto_disabled_providers = Vec::new();
    for prov in &mut enabled_providers {
        if prov.enabled && !prov.id.is_allowed_under(req.age_policy) {
            prov.enabled = false;
            auto_disabled_providers.push(prov.id);
        }
        if req.age_policy != AgeVerificationPolicy::SelfAttestation {
            prov.soft_birthday_check = false;
        }
    }

    let mut next_policy = PublicSitePolicy {
        revision: new_revision,
        min_enforce_rev: prev.min_enforce_rev,
        safety_enabled: req.safety_enabled,
        rules: normalized_rules,
        unclassified_mode: req.unclassified_mode,
        cloudflare_images_blur: req.cloudflare_images_blur,
        age_policy: req.age_policy,
        age_gate_trigger: req.age_gate_trigger,
        similarity: req.similarity,
        legal,
        geo,
        enabled_providers,
        panic_shortcut,
    };

    let (min_enforce_rev, tightened) = compute_next_min_enforce_rev(prev, &next_policy, new_revision);
    next_policy.min_enforce_rev = min_enforce_rev;
    let digest = compute_policy_digest(&next_policy);

    Ok(ValidatedSafetyUpdate {
        next_policy,
        digest,
        tightened,
        terms_bumped,
        auto_disabled_providers,
    })
}

/// Validates provider updates against active [`AgeVerificationPolicy`] (Strict 18+ H7)
/// and OIDC SSRF URL defense (H11), returning strictly non-secret [`AuthProviderPublicConfig`]
/// rows ready for `site_settings` + `SitePolicyDO`.
pub fn validate_provider_updates(
    age_policy: AgeVerificationPolicy,
    items: &[ProviderUpdateItem],
) -> std::result::Result<Vec<AuthProviderPublicConfig>, String> {
    let mut seen = HashSet::new();
    let mut configs = Vec::with_capacity(items.len());

    for item in items {
        if !seen.insert(item.id) {
            return Err(format!("Duplicate provider entry '{}'", item.id.as_str()));
        }

        // Strict Provider-Verified 18+ enforcement (H7): reject enabling non-age-capable providers.
        if item.enabled && !item.id.is_allowed_under(age_policy) {
            return Err(format!(
                "Provider '{}' cannot be enabled under Strict Provider-Verified 18+ age policy; only Age-Assurance OIDC is allowed",
                item.id.display_name()
            ));
        }

        // Soft birthday convenience check is strictly Google + SelfAttestation only.
        if item.soft_birthday_check {
            if item.id != AuthProviderId::Google {
                return Err("soft_birthday_check is only supported on the Google provider".into());
            }
            if age_policy != AgeVerificationPolicy::SelfAttestation {
                return Err(
                    "Google soft_birthday_check can only be enabled under Self-Attestation age policy"
                        .into(),
                );
            }
        }

        // Normalize & validate display_name and public_client_id.
        let display_name = item
            .display_name
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| {
                if s.len() > 80 || s.chars().any(char::is_control) {
                    Err(format!(
                        "Provider '{}' display_name is invalid",
                        item.id.as_str()
                    ))
                } else {
                    Ok(s.to_string())
                }
            })
            .transpose()?;

        let public_client_id = item
            .public_client_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(|s| {
                if s.len() > 256 || s.chars().any(char::is_control) {
                    Err(format!(
                        "Provider '{}' public_client_id is invalid",
                        item.id.as_str()
                    ))
                } else {
                    Ok(s.to_string())
                }
            })
            .transpose()?;

        // Validate OIDC / provider HTTPS URLs against SSRF (H11).
        let issuer = match item
            .issuer
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            Some(raw_url) => Some(validate_oidc_url(raw_url).map_err(|e| {
                format!("Provider '{}' issuer URL rejected: {e}", item.id.as_str())
            })?),
            None => {
                if item.enabled && item.id == AuthProviderId::OidcAgeAssurance {
                    return Err(
                        "Age-Assurance OIDC requires a valid https:// issuer URL when enabled"
                            .into(),
                    );
                }
                None
            }
        };

        // Check write-only secret sanity (never log secret contents!).
        if let Some(secret) = item.secret_value.as_deref() {
            if !secret.is_empty() && secret_field_for_provider(item.id).is_none() {
                return Err(format!(
                    "Provider '{}' does not use a server-side secret",
                    item.id.as_str()
                ));
            }
            if secret.len() > 4096 || secret.chars().any(char::is_control) {
                return Err(format!(
                    "Provider '{}' secret is invalid or exceeds maximum length",
                    item.id.as_str()
                ));
            }
        }

        configs.push(AuthProviderPublicConfig {
            id: item.id,
            enabled: item.enabled,
            display_name,
            issuer,
            public_client_id,
            soft_birthday_check: item.soft_birthday_check,
        });
    }

    // Deterministic ordering matching AuthProviderId::ALL.
    configs.sort_by_key(|c| c.id);
    Ok(configs)
}

// ---------------------------------------------------------------------------
// D1 Persistence + SitePolicyDO Sync
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct LoadedSettings {
    pub revision: u32,
    pub doc: SiteSettingsDocument,
}

impl LoadedSettings {
    pub async fn load(env: &Env) -> Result<Self> {
        #[derive(Deserialize)]
        struct Row {
            revision: u32,
            document: String,
        }
        let db = env.d1(D1_BINDING)?;
        let row: Row = db
            .prepare("SELECT revision, document FROM site_settings ORDER BY revision DESC LIMIT 1")
            .first(None)
            .await?
            .ok_or_else(|| worker::Error::RustError("Missing site_settings migration".into()))?;

        let mut doc = if row.revision == 0 && row.document.trim() == "{}" {
            initial_document(env)
        } else {
            serde_json::from_str::<SiteSettingsDocument>(&row.document)
                .map_err(|e| worker::Error::RustError(format!("corrupt site_settings JSON: {e}")))?
        };
        doc.public.revision = row.revision;
        doc.public.legal.refresh_terms_digest();
        Ok(Self {
            revision: row.revision,
            doc,
        })
    }

    /// Atomically publishes `doc` at `expected_revision + 1` via D1 CAS
    /// (`WHERE revision=? AND revision=(SELECT MAX(revision) FROM site_settings)`)
    /// and immediately pushes `{ policy, digest }` to `SITE_POLICY` DO `POST /publish`.
    ///
    /// Returns `Ok(Some((new_rev, digest)))` on success, `Ok(None)` on revision conflict (409).
    pub async fn save_and_publish(
        env: &Env,
        expected_revision: u32,
        doc: &SiteSettingsDocument,
        editor: &str,
    ) -> Result<Option<(u32, String)>> {
        let new_revision = expected_revision.saturating_add(1);
        let mut to_store = doc.clone();
        to_store.public.revision = new_revision;
        let digest = compute_policy_digest(&to_store.public);

        let db = env.d1(D1_BINDING)?;
        let mut writes = Vec::new();
        if expected_revision == 0 {
            writes.push(
                db.prepare("UPDATE site_settings SET document=? WHERE revision=0 AND document='{}'")
                    .bind(&[serde_json::to_string(&initial_document(env))?.into()])?,
            );
        }
        writes.push(
            db.prepare(
                "INSERT INTO site_settings (revision, document, updated_at, updated_by) \
                 SELECT revision+1, ?, unixepoch(), ? FROM site_settings \
                 WHERE revision=? AND revision=(SELECT MAX(revision) FROM site_settings)",
            )
            .bind(&[
                serde_json::to_string(&to_store)?.into(),
                editor.into(),
                f64::from(expected_revision).into(),
            ])?,
        );
        let results = db.batch(writes).await?;
        let inserted = results
            .last()
            .expect("at least one write")
            .meta()?
            .and_then(|m| m.changes)
            == Some(1);

        if !inserted {
            return Ok(None);
        }

        // Immediately notify SitePolicyDO so gateway_worker observes tightened revisions
        // without waiting for edge caches.
        do_client::publish_site_policy(env, &to_store.public, &digest).await?;
        Ok(Some((new_revision, digest)))
    }
}

fn initial_document(env: &Env) -> SiteSettingsDocument {
    let eth_deposit = env
        .var("DEPOSIT_ADDRESS")
        .ok()
        .map(|v| v.to_string().trim().to_ascii_lowercase())
        .filter(|a| valid_deposit_address(ChainKind::Ethereum, a))
        .unwrap_or_default();
    let sol_deposit = env
        .var("SOL_DEPOSIT_ADDRESS")
        .ok()
        .map(|v| v.to_string().trim().to_owned())
        .filter(|a| valid_deposit_address(ChainKind::Solana, a))
        .unwrap_or_default();
    SiteSettingsDocument {
        access: AccessPolicy {
            eth_deposit,
            sol_deposit,
            ..AccessPolicy::default()
        },
        public: PublicSitePolicy::default(),
    }
}
