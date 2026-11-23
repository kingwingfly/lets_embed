//! Immutable revisioned site settings (`site_settings` D1 table), Policy v3
//! validation, conservative `min_enforce_rev` & `grant_generation` computation,
//! catalog reference collection, and two-phase `SitePolicyDO` activation.
//!
//! `site_settings.document` stores the flattened union of [`AccessPolicy`] and
//! [`PublicSitePolicy`] (whose field names are 100% disjoint, with ZERO secret fields),
//! keeping compatibility with `user_worker` billing/deposit lookups and
//! `SitePolicyDO` cold-start bootstrapping.

use std::collections::{BTreeSet, HashSet};

use search_types::{
    WD_VOCAB_DIGEST,
    safety::{collect_catalog_refs, parse_safety_rule},
    validate_min_similarity,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use site_access::{
    AgeGateTrigger, AgeVerificationPolicy, AuthProviderId, AuthProviderPublicConfig, ChargeKind,
    ContentPolicy, GeoPolicy, LegalDocConfig, PublicSitePolicy, SITE_POLICY_SCHEMA_VERSION,
    SimilarityDefaults, compute_next_grant_generations,
    compute_next_min_enforce_rev, compute_policy_digest, compute_terms_digest, is_eth_address,
    is_sol_principal, validate_policy_set_with_mode,
};
use worker::{Env, Result};

use crate::{
    D1_BINDING,
    api::{ActivationStatus, FieldValidationError, ProviderUpdateItem, SaveSafetyReq},
    do_client::{self, DoActivationAck},
    security::{
        validate_and_normalize_country_list, validate_and_normalize_geo, validate_oidc_url,
    },
};

pub const MAX_VALUE: i64 = 1_000_000_000;
pub const MAX_LEGAL_DOC_BYTES: usize = 100_000;
pub const MAX_NOTICE_BANNER_BYTES: usize = 8_000;

pub const LEGACY_UNCLASSIFIED_NOTE: &str = "Pending or legacy-ingested images (`images.status != 'completed'` or missing `wd_min_persisted_score` coverage) fail closed to a Placeholder whenever Policy v3 restrictions evaluate to Unknown. Run `embed --retag-safety` against Postgres to backfill full WD-Tagger v3 coverage on existing media.";

pub const LEGACY_UPGRADE_REQUIRED_MSG: &str = "Legacy pre-v3 policy detected; review and publish Content Safety Policy v3 first before updating other settings.";

/// Fail-closed migration guard for all non-safety settings mutations (`access`,
/// `providers`, `retry-activation`). Rejects writes whenever D1 holds a legacy
/// pre-v3 `site_settings` row so non-safety saves can NEVER stamp `schema_version = 3`
/// with empty `policies: []` and silently clear legacy safety enforcement.
pub fn ensure_v3_ready_for_non_safety_mutation(
    legacy_upgrade_notice: Option<&str>,
) -> std::result::Result<(), &'static str> {
    if legacy_upgrade_notice.is_some() {
        return Err(LEGACY_UPGRADE_REQUIRED_MSG);
    }
    Ok(())
}

/// Fail-closed migration guard for `POST /admin/api/safety`.
///
/// When D1 holds a legacy pre-v3 row, ONLY an explicit Policy v3 publish from the
/// Content Safety tab (`confirm_policy_v3_migration == true`) is permitted to perform
/// the upgrade; partial saves from other tabs (`Similarity & Geo`, `Age & Legal`) or
/// older clients (`confirm_policy_v3_migration == false`) are rejected with `409 Conflict`.
pub fn ensure_v3_ready_for_safety_mutation(
    legacy_upgrade_notice: Option<&str>,
    confirm_policy_v3_migration: bool,
) -> std::result::Result<(), &'static str> {
    if legacy_upgrade_notice.is_some() && !confirm_policy_v3_migration {
        return Err(LEGACY_UPGRADE_REQUIRED_MSG);
    }
    Ok(())
}

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
// Policy v3 Catalog Reference Tracking & Validation Builders (Host-Testable)
// ---------------------------------------------------------------------------

/// Per-policy, per-field (`match_expr` / `except_expr`) catalog references extracted via
/// [`search_types::safety::collect_catalog_refs`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyFieldCatalogRefs {
    pub policy_id: String,
    pub field: &'static str,
    pub post_tags: Vec<String>,
    pub authors: Vec<String>,
}

/// Complete validated Policy v3 update ready for catalog validation and two-phase activation.
#[derive(Debug, Clone)]
pub struct ValidatedSafetyUpdate {
    pub next_policy: PublicSitePolicy,
    pub policy_digest: String,
    pub tightened: bool,
    pub terms_bumped: bool,
    pub auto_disabled_providers: Vec<AuthProviderId>,
    pub all_post_tags: Vec<String>,
    pub all_authors: Vec<String>,
    pub field_refs: Vec<PolicyFieldCatalogRefs>,
}

/// Converts unknown `post_tag` and `author` names returned by
/// `POST {APP_ORIGIN}/internal/validate-safety-catalog` into crisp per-field
/// validation errors pinpointing every affected `(policy_id, match_expr|except_expr)`.
pub fn build_catalog_field_errors(
    field_refs: &[PolicyFieldCatalogRefs],
    unknown_post_tags: &[String],
    unknown_authors: &[String],
) -> Vec<FieldValidationError> {
    let unknown_tags_set: HashSet<&str> = unknown_post_tags.iter().map(String::as_str).collect();
    let unknown_authors_set: HashSet<&str> = unknown_authors.iter().map(String::as_str).collect();
    let mut errors = Vec::new();

    for entry in field_refs {
        let bad_tags: Vec<&str> = entry
            .post_tags
            .iter()
            .map(String::as_str)
            .filter(|t| unknown_tags_set.contains(*t))
            .collect();
        if !bad_tags.is_empty() {
            errors.push(FieldValidationError {
                policy_id: Some(entry.policy_id.clone()),
                field: entry.field.to_string(),
                message: format!(
                    "Policy '{}' {} references unknown post_tag(s): {}",
                    entry.policy_id,
                    entry.field,
                    bad_tags.join(", ")
                ),
            });
        }

        let bad_authors: Vec<&str> = entry
            .authors
            .iter()
            .map(String::as_str)
            .filter(|a| unknown_authors_set.contains(*a))
            .collect();
        if !bad_authors.is_empty() {
            errors.push(FieldValidationError {
                policy_id: Some(entry.policy_id.clone()),
                field: entry.field.to_string(),
                message: format!(
                    "Policy '{}' {} references unknown author(s): {}",
                    entry.policy_id,
                    entry.field,
                    bad_authors.join(", ")
                ),
            });
        }
    }

    // Fallback if origin returned an unknown item not mapped to a specific field entry.
    if errors.is_empty() && (!unknown_post_tags.is_empty() || !unknown_authors.is_empty()) {
        if !unknown_post_tags.is_empty() {
            errors.push(FieldValidationError {
                policy_id: None,
                field: "policies".to_string(),
                message: format!(
                    "Unknown post_tag(s) in safety policy: {}",
                    unknown_post_tags.join(", ")
                ),
            });
        }
        if !unknown_authors.is_empty() {
            errors.push(FieldValidationError {
                policy_id: None,
                field: "policies".to_string(),
                message: format!(
                    "Unknown author(s) in safety policy: {}",
                    unknown_authors.join(", ")
                ),
            });
        }
    }

    errors
}

/// Validates and applies a Policy v3 `/admin/api/safety` update against `prev`:
/// - Normalizes policy slugs, expressions, and ISO-3166 country exclusions
/// - Enforces all Policy v3 invariants via [`site_access::validate_policy_set_with_mode`]
///   (`Block`/`Blur` only, rejects `Block + include_click`, rejects `require_age_18` while
///   `age_policy == Off`, validates every `tag:<name>` against the 10,861-tag WD-Tagger v3
///   vocabulary even inside `NOT` and `except_expr`, enforces hundredths `0.01..=1.00`,
///   16 policies / 32 terms per policy / depth 6 / 128 total terms)
/// - Computes conservative `grant_generation` (`compute_next_grant_generations`) and
///   conservative `min_enforce_rev` (`compute_next_min_enforce_rev`)
/// - Stamps `schema_version = 3`, `vocab_digest = WD_VOCAB_DIGEST`, and canonical `policy_digest`
/// - Collects all `post_tag:` and `author:` refs via [`search_types::safety::collect_catalog_refs`]
pub fn prepare_safety_update(
    prev: &PublicSitePolicy,
    req: &SaveSafetyReq,
    new_revision: u64,
) -> std::result::Result<ValidatedSafetyUpdate, String> {
    // 1. Validate similarity thresholds via search_types helper.
    validate_min_similarity(Some(req.similarity.dinov3_min))
        .map_err(|e| format!("DINOv3 {e}"))?;
    validate_min_similarity(Some(req.similarity.siglip2_min))
        .map_err(|e| format!("SigLIP2 {e}"))?;

    // 2. Validate and normalize site-wide ISO-3166 geo blocklist.
    let geo = validate_and_normalize_geo(&req.geo)?;

    // 3. Validate legal document lengths and compute canonical terms digest + monotonic version.
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
    let terms_bumped =
        new_terms_digest != prev_terms_digest || new_terms_digest != prev.legal.terms_digest;
    legal.terms_digest = new_terms_digest;
    legal.terms_version = if terms_bumped {
        prev.legal.terms_version.max(1).saturating_add(1)
    } else {
        prev.legal.terms_version.max(1)
    };

    // 4. Normalize policies (slug trim/lowercase, expr trim, country normalization).
    let mut normalized_policies = Vec::with_capacity(req.policies.len());
    for pol in &req.policies {
        let id = pol.id.trim().to_ascii_lowercase();
        let name = pol.name.trim().to_string();
        let match_expr = pol.match_expr.trim().to_string();
        let except_expr = pol
            .except_expr
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::to_string);

        let exclude_countries = validate_and_normalize_country_list(
            &pol.bypass.exclude_countries,
            "Policy exclude_countries must not list XX (unknown/missing countries are automatically denied whenever exclude_countries is non-empty)",
            "Policy exclude_countries must not list T1 (Tor exit nodes are automatically denied whenever exclude_countries is non-empty)",
        )
        .map_err(|e| format!("Policy '{id}': {e}"))?;

        let mut bypass = pol.bypass.clone();
        bypass.exclude_countries = exclude_countries;

        normalized_policies.push(ContentPolicy {
            id,
            grant_generation: pol.grant_generation.max(1),
            enabled: pol.enabled,
            priority: pol.priority,
            name,
            preset: pol.preset,
            match_expr,
            except_expr,
            default_tag_min: pol.default_tag_min,
            action: pol.action,
            bypass,
        });
    }

    // 5. Enforce Strict 18+ invariant on already-configured providers.
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

    // 6. Build candidate Policy v3 document.
    let mut next_policy = PublicSitePolicy {
        schema_version: SITE_POLICY_SCHEMA_VERSION,
        revision: new_revision,
        min_enforce_rev: prev.min_enforce_rev,
        policy_digest: String::new(),
        vocab_digest: WD_VOCAB_DIGEST.to_string(),
        safety_enabled: req.safety_enabled,
        unclassified_mode: req.unclassified_mode,
        fixed_blur_enabled: req.fixed_blur_enabled,
        policies: normalized_policies,
        age_policy: req.age_policy,
        age_gate_trigger: req.age_gate_trigger,
        similarity: req.similarity,
        legal,
        geo,
        enabled_providers,
    };

    // 7. Compute conservative `grant_generation` and `min_enforce_rev`, then stamp digest.
    compute_next_grant_generations(prev, &mut next_policy);
    let (min_enforce_rev, tightened) = compute_next_min_enforce_rev(prev, &next_policy, new_revision);
    next_policy.min_enforce_rev = min_enforce_rev;
    next_policy.refresh_policy_digest();

    // 8. Enforce EVERY Policy v3 invariant with strict hundredths precision.
    validate_policy_set_with_mode(&next_policy, true).map_err(|e| e.to_string())?;

    // 9. Collect per-field `post_tag:` and `author:` refs via `search_types::safety::collect_catalog_refs`.
    let mut all_post_tags = BTreeSet::new();
    let mut all_authors = BTreeSet::new();
    let mut field_refs = Vec::new();

    for pol in &next_policy.policies {
        if !pol.match_expr.is_empty() {
            let expr = parse_safety_rule(&pol.match_expr)
                .map_err(|e| format!("Policy '{}' match_expr: {e}", pol.id))?;
            let (ptags, auths) = collect_catalog_refs(&expr);
            if !ptags.is_empty() || !auths.is_empty() {
                all_post_tags.extend(ptags.iter().cloned());
                all_authors.extend(auths.iter().cloned());
                field_refs.push(PolicyFieldCatalogRefs {
                    policy_id: pol.id.clone(),
                    field: "match_expr",
                    post_tags: ptags,
                    authors: auths,
                });
            }
        }
        if let Some(ex_raw) = pol.except_expr.as_deref()
            && !ex_raw.is_empty()
        {
            let expr = parse_safety_rule(ex_raw)
                .map_err(|e| format!("Policy '{}' except_expr: {e}", pol.id))?;
            let (ptags, auths) = collect_catalog_refs(&expr);
            if !ptags.is_empty() || !auths.is_empty() {
                all_post_tags.extend(ptags.iter().cloned());
                all_authors.extend(auths.iter().cloned());
                field_refs.push(PolicyFieldCatalogRefs {
                    policy_id: pol.id.clone(),
                    field: "except_expr",
                    post_tags: ptags,
                    authors: auths,
                });
            }
        }
    }

    let policy_digest = next_policy.policy_digest.clone();
    Ok(ValidatedSafetyUpdate {
        next_policy,
        policy_digest,
        tightened,
        terms_bumped,
        auto_disabled_providers,
        all_post_tags: all_post_tags.into_iter().collect(),
        all_authors: all_authors.into_iter().collect(),
        field_refs,
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

        if item.enabled && !item.id.is_allowed_under(age_policy) {
            return Err(format!(
                "Provider '{}' cannot be enabled under Strict Provider-Verified 18+ age policy; only Age-Assurance OIDC is allowed",
                item.id.display_name()
            ));
        }

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

    configs.sort_by_key(|c| c.id);
    Ok(configs)
}

// ---------------------------------------------------------------------------
// D1 Persistence + Two-Phase SitePolicyDO Activation
// ---------------------------------------------------------------------------

/// Result of Phase-2 `SitePolicyDO` activation after D1 persistence.
#[derive(Debug, Clone)]
pub enum ActivationOutcome {
    Active {
        ack: DoActivationAck,
        min_enforce_rev: u64,
    },
    PendingDoAck {
        revision: u64,
        min_enforce_rev: u64,
        policy_digest: String,
        error: String,
    },
}

#[derive(Debug, Clone)]
pub struct LoadedSettings {
    pub revision: u64,
    pub activation_status: ActivationStatus,
    pub doc: SiteSettingsDocument,
    pub legacy_upgrade_notice: Option<String>,
}

/// Decodes a persisted `site_settings.document` JSON string into a Policy v3
/// [`SiteSettingsDocument`], allowing clean admin-side migration if an existing
/// deployment holds a pre-v3 row while strictly decoding schema v3 rows.
pub fn decode_site_settings_document(
    revision: u64,
    raw_json: &str,
    default_doc: SiteSettingsDocument,
) -> std::result::Result<(SiteSettingsDocument, Option<String>), String> {
    if revision == 0 && raw_json.trim() == "{}" {
        return Ok((default_doc, None));
    }

    let val: Value = serde_json::from_str(raw_json)
        .map_err(|e| format!("corrupt site_settings JSON: {e}"))?;
    let Some(obj) = val.as_object() else {
        return Err("site_settings document must be a JSON object".into());
    };

    if obj.get("schema_version").and_then(Value::as_u64) == Some(u64::from(SITE_POLICY_SCHEMA_VERSION))
    {
        let mut doc: SiteSettingsDocument = serde_json::from_value(val)
            .map_err(|e| format!("corrupt Policy v3 site_settings document: {e}"))?;
        doc.public.revision = revision;
        doc.public.schema_version = SITE_POLICY_SCHEMA_VERSION;
        if doc.public.vocab_digest.trim().is_empty() {
            doc.public.vocab_digest = WD_VOCAB_DIGEST.to_string();
        }
        doc.public.legal.refresh_terms_digest();
        if doc.public.policy_digest.trim().is_empty() {
            doc.public.refresh_policy_digest();
        }
        return Ok((doc, None));
    }

    // Legacy pre-v3 row (missing `schema_version: 3`): preserve access, age, similarity,
    // legal, geo, and providers so the admin can configure & publish Policy v3 cleanly.
    let access: AccessPolicy = serde_json::from_value(val.clone()).unwrap_or(default_doc.access);
    let mut public = PublicSitePolicy::fresh_bootstrap();
    public.revision = revision;
    if let Some(min_rev) = obj.get("min_enforce_rev").and_then(Value::as_u64) {
        public.min_enforce_rev = min_rev.min(revision);
    }
    if let Some(enabled) = obj.get("safety_enabled").and_then(Value::as_bool) {
        public.safety_enabled = enabled;
    }
    if let Some(blur) = obj.get("cloudflare_images_blur").and_then(Value::as_bool) {
        public.fixed_blur_enabled = blur;
    }
    if let Some(ap) = obj.get("age_policy")
        && let Ok(parsed) = serde_json::from_value::<AgeVerificationPolicy>(ap.clone())
    {
        public.age_policy = parsed;
    }
    if let Some(trig) = obj.get("age_gate_trigger")
        && let Ok(parsed) = serde_json::from_value::<AgeGateTrigger>(trig.clone())
    {
        public.age_gate_trigger = parsed;
    }
    if let Some(sim) = obj.get("similarity")
        && let Ok(parsed) = serde_json::from_value::<SimilarityDefaults>(sim.clone())
        && parsed.is_valid()
    {
        public.similarity = parsed;
    }
    if let Some(leg) = obj.get("legal")
        && let Ok(mut parsed) = serde_json::from_value::<LegalDocConfig>(leg.clone())
    {
        parsed.refresh_terms_digest();
        public.legal = parsed;
    }
    if let Some(geo) = obj.get("geo")
        && let Ok(parsed) = serde_json::from_value::<GeoPolicy>(geo.clone())
    {
        public.geo = parsed;
    }
    if let Some(provs) = obj.get("enabled_providers")
        && let Ok(parsed) = serde_json::from_value::<Vec<AuthProviderPublicConfig>>(provs.clone())
    {
        public.enabled_providers = parsed;
    }
    public.refresh_policy_digest();

    let notice = format!(
        "Stored revision #{revision} uses legacy pre-v3 schema. Review your Content Safety policies and publish to activate Policy v3."
    );
    Ok((SiteSettingsDocument { access, public }, Some(notice)))
}

impl LoadedSettings {
    pub async fn load(env: &Env) -> Result<Self> {
        #[derive(Deserialize)]
        struct Row {
            revision: u64,
            document: String,
            #[serde(default)]
            activation_status: Option<String>,
        }
        let db = env.d1(D1_BINDING)?;
        let row: Row = db
            .prepare(
                "SELECT revision, document, activation_status \
                 FROM site_settings ORDER BY revision DESC LIMIT 1",
            )
            .first(None)
            .await?
            .ok_or_else(|| worker::Error::RustError("Missing site_settings migration".into()))?;

        let (doc, legacy_upgrade_notice) =
            decode_site_settings_document(row.revision, &row.document, initial_document(env))
                .map_err(worker::Error::RustError)?;
        let activation_status = row
            .activation_status
            .as_deref()
            .map(ActivationStatus::parse)
            .unwrap_or(ActivationStatus::Active);

        Ok(Self {
            revision: row.revision,
            activation_status,
            doc,
            legacy_upgrade_notice,
        })
    }

    /// Phase 1 of Two-Phase Activation:
    /// Atomically commits `doc` at `expected_revision + 1` in D1 via CAS with
    /// `activation_status = 'pending_do_ack'` BEFORE notifying `SitePolicyDO`.
    ///
    /// Returns `Ok(Some((new_rev, stored_public_policy, digest)))` on success,
    /// or `Ok(None)` on revision conflict (409).
    pub async fn save_d1_cas_pending(
        env: &Env,
        expected_revision: u64,
        doc: &SiteSettingsDocument,
        editor: &str,
    ) -> Result<Option<(u64, PublicSitePolicy, String)>> {
        let new_revision = expected_revision.saturating_add(1);
        let mut to_store = doc.clone();
        to_store.public.schema_version = SITE_POLICY_SCHEMA_VERSION;
        to_store.public.revision = new_revision;
        to_store.public.vocab_digest = WD_VOCAB_DIGEST.to_string();
        to_store.public.legal.refresh_terms_digest();
        to_store.public.refresh_policy_digest();
        let digest = to_store.public.policy_digest.clone();

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
                "INSERT INTO site_settings (revision, document, updated_at, updated_by, activation_status) \
                 SELECT revision+1, ?, unixepoch(), ?, 'pending_do_ack' FROM site_settings \
                 WHERE revision=? AND revision=(SELECT MAX(revision) FROM site_settings)",
            )
            .bind(&[
                serde_json::to_string(&to_store)?.into(),
                editor.into(),
                (expected_revision as f64).into(),
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

        Ok(Some((new_revision, to_store.public, digest)))
    }

    /// Marks a D1 `site_settings` revision as `'active'` ONLY after exact
    /// `(revision, policy_digest)` acknowledgement from `SitePolicyDO`.
    pub async fn mark_revision_active(env: &Env, revision: u64) -> Result<()> {
        let db = env.d1(D1_BINDING)?;
        db.prepare(
            "UPDATE site_settings \
             SET activation_status = 'active' \
             WHERE revision = ?",
        )
        .bind(&[(revision as f64).into()])?
        .run()
        .await?;
        Ok(())
    }

    /// Phase 2 of Two-Phase Activation:
    /// Calls `SitePolicyDO`, verifies exact `(revision, policy_digest)` ACK, and marks
    /// `activation_status = 'active'` ONLY on exact acknowledgement.
    ///
    /// On DO error or ACK mismatch, leaves D1 `activation_status = 'pending_do_ack'`
    /// and returns `ActivationOutcome::PendingDoAck`.
    pub async fn activate_saved_revision(
        env: &Env,
        public: &PublicSitePolicy,
        digest: &str,
    ) -> Result<ActivationOutcome> {
        match do_client::activate_site_policy(env, public, digest).await {
            Ok(ack) => {
                if let Err(e) = Self::mark_revision_active(env, ack.revision).await {
                    worker::console_error!(
                        "Failed to mark site_settings rev={} active after DO ACK: {e:?}",
                        ack.revision
                    );
                    return Ok(ActivationOutcome::PendingDoAck {
                        revision: public.revision,
                        min_enforce_rev: public.min_enforce_rev,
                        policy_digest: digest.to_string(),
                        error: format!(
                            "SitePolicyDO acknowledged rev #{}, but D1 activation_status update failed: {e}",
                            ack.revision
                        ),
                    });
                }
                Ok(ActivationOutcome::Active {
                    ack,
                    min_enforce_rev: public.min_enforce_rev,
                })
            }
            Err(e) => {
                worker::console_error!(
                    "SitePolicyDO activation failed for rev={} digest={digest}: {e:?}",
                    public.revision
                );
                Ok(ActivationOutcome::PendingDoAck {
                    revision: public.revision,
                    min_enforce_rev: public.min_enforce_rev,
                    policy_digest: digest.to_string(),
                    error: e.to_string(),
                })
            }
        }
    }

    /// Two-Phase Activation helper:
    /// 1. Saves D1 CAS revision with `activation_status = 'pending_do_ack'`
    /// 2. Activates on `SitePolicyDO` and transitions to `'active'` ONLY on exact `(rev, digest)` ACK.
    pub async fn save_and_activate(
        env: &Env,
        expected_revision: u64,
        doc: &SiteSettingsDocument,
        editor: &str,
    ) -> Result<Option<ActivationOutcome>> {
        let Some((_new_revision, public, digest)) =
            Self::save_d1_cas_pending(env, expected_revision, doc, editor).await?
        else {
            return Ok(None);
        };
        let outcome = Self::activate_saved_revision(env, &public, &digest).await?;
        Ok(Some(outcome))
    }

    /// Idempotent retry for an already-loaded Policy v3 revision (`POST /admin/api/policy/retry-activation`).
    pub async fn retry_loaded_activation(
        env: &Env,
        mut loaded: Self,
    ) -> Result<ActivationOutcome> {
        ensure_v3_ready_for_non_safety_mutation(loaded.legacy_upgrade_notice.as_deref())
            .map_err(|msg| worker::Error::RustError(msg.to_string()))?;
        loaded.doc.public.schema_version = SITE_POLICY_SCHEMA_VERSION;
        loaded.doc.public.revision = loaded.revision;
        loaded.doc.public.vocab_digest = WD_VOCAB_DIGEST.to_string();
        loaded.doc.public.legal.refresh_terms_digest();
        let digest = compute_policy_digest(&loaded.doc.public);
        loaded.doc.public.policy_digest = digest.clone();

        Self::activate_saved_revision(env, &loaded.doc.public, &digest).await
    }

    /// Idempotent retry for the latest saved revision (`POST /admin/api/policy/retry-activation`).
    pub async fn retry_latest_activation(env: &Env) -> Result<ActivationOutcome> {
        let loaded = Self::load(env).await?;
        Self::retry_loaded_activation(env, loaded).await
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
        public: PublicSitePolicy::fresh_bootstrap(),
    }
}
