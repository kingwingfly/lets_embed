//! JSON wire DTOs for `/admin/api/*` (Policy v3 + Two-Phase Activation + Catalog Validation).
//!
//! Secret values are write-only on `ProviderUpdateItem` (never included in any
//! `GET` response struct or redacted `Debug` output).

use std::fmt;

use serde::{Deserialize, Serialize};
use site_access::{
    AgeGateTrigger, AgeVerificationPolicy, AuthProviderId, AuthProviderPublicConfig, ContentPolicy,
    GeoPolicy, LegalDocConfig, SimilarityDefaults, UnclassifiedMode,
};

use crate::settings::AccessPolicy;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldValidationError {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_id: Option<String>,
    pub field: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub field_errors: Vec<FieldValidationError>,
}

/// D1 `site_settings.activation_status` two-phase publication state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationStatus {
    #[default]
    Active,
    PendingDoAck,
    Failed,
}

impl ActivationStatus {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::PendingDoAck => "pending_do_ack",
            Self::Failed => "failed",
        }
    }

    pub fn parse(raw: &str) -> Self {
        match raw.trim() {
            "pending_do_ack" => Self::PendingDoAck,
            "failed" => Self::Failed,
            _ => Self::Active,
        }
    }

    pub const fn is_pending(self) -> bool {
        !matches!(self, Self::Active)
    }
}

/// Returned when D1 saved the revision as `pending_do_ack` but `SitePolicyDO`
/// failed to acknowledge exact `(revision, policy_digest)`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingActivationResp {
    pub ok: bool,
    pub pending_activation: bool,
    pub activation_status: String,
    pub revision: u64,
    pub min_enforce_rev: u64,
    pub policy_digest: String,
    pub error: String,
}

/// Returned by idempotent `POST /admin/api/policy/retry-activation` on ACK success.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryActivationResp {
    pub ok: bool,
    pub pending_activation: bool,
    pub activation_status: String,
    pub revision: u64,
    pub min_enforce_rev: u64,
    pub policy_digest: String,
}

// ---------------------------------------------------------------------------
// Overview & Access Settings
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccountsSummary {
    pub total: i64,
    pub active: i64,
    pub banned: i64,
    pub basic: i64,
    pub pro: i64,
    pub eth: i64,
    pub sol: i64,
    pub multi_auth: i64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PaymentsSummary {
    pub total_count: i64,
    pub credited_count: i64,
    pub total_points: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyOverview {
    pub safety_enabled: bool,
    pub policy_count: usize,
    pub active_switcher_count: usize,
    pub active_blur_count: usize,
    pub age_policy: AgeVerificationPolicy,
    pub age_gate_trigger: AgeGateTrigger,
    pub blocked_country_count: usize,
    pub fixed_blur_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OverviewResp {
    pub admin_email: String,
    pub schema_version: u32,
    pub revision: u64,
    pub min_enforce_rev: u64,
    pub policy_digest: String,
    pub vocab_digest: String,
    pub activation_status: String,
    pub access: AccessPolicy,
    pub safety: SafetyOverview,
    pub accounts_summary: AccountsSummary,
    pub payments_summary: PaymentsSummary,
    pub open_report_count: i64,
    pub legacy_unclassified_note: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_upgrade_notice: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveAccessReq {
    pub revision: u64,
    pub access: AccessPolicy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveAccessResp {
    pub ok: bool,
    #[serde(default)]
    pub unchanged: bool,
    pub pending_activation: bool,
    pub activation_status: String,
    pub revision: u64,
    pub min_enforce_rev: u64,
    pub policy_digest: String,
    pub digest: String,
    pub access: AccessPolicy,
}

// ---------------------------------------------------------------------------
// Accounts & Payments
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DoStatusResp {
    pub address: String,
    pub balance: i64,
    pub plan: Option<String>,
    pub period_end: u64,
    pub views_remaining: Option<i64>,
    pub searches_remaining: Option<i64>,
    pub window_reset: u64,
    pub banned: bool,
    pub total_views: i64,
    #[serde(default)]
    pub allow_paid_media: bool,
    #[serde(default)]
    pub self_attested_18: bool,
    #[serde(default)]
    pub suspended: bool,
    #[serde(default)]
    pub merged_into: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdentitySummary {
    pub provider_id: String,
    pub issuer: String,
    pub subject: String,
    pub purpose: String,
    pub label: Option<String>,
    pub verified_email: Option<String>,
    pub assurance_level: String,
    pub assurance_method: Option<String>,
    pub assurance_verified_at: Option<i64>,
    pub assurance_expires_at: Option<i64>,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountEntryResp {
    pub id: String,
    pub account_do_key: String,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub created_at: i64,
    pub last_login: i64,
    pub plan: Option<String>,
    pub banned: bool,
    pub terms_version_accepted: Option<i64>,
    pub terms_accepted_at: Option<i64>,
    pub topup_count: i64,
    pub topup_points: String,
    pub like_count: i64,
    pub identities: Vec<IdentitySummary>,
    pub live_status: Option<DoStatusResp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountsListResp {
    pub summary: AccountsSummary,
    pub total: usize,
    pub page: usize,
    pub page_size: usize,
    #[serde(default)]
    pub live_sort_capped: bool,
    #[serde(default)]
    pub live_sort_scan_limit: usize,
    pub accounts: Vec<AccountEntryResp>,
    pub selected: Option<AccountEntryResp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminPlanMutationReq {
    pub user_id: String,
    pub plan: String,
    #[serde(default)]
    pub days: Option<u32>,
    #[serde(default)]
    pub token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminPlanMutationResp {
    pub user_id: String,
    pub plan: Option<String>,
    pub period_end: u64,
    pub status: DoStatusResp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminCreditMutationReq {
    pub user_id: String,
    pub points: i64,
    #[serde(default)]
    pub reason: String,
    #[serde(default)]
    pub token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminCreditMutationResp {
    pub user_id: String,
    pub balance: i64,
    pub applied: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminBanMutationReq {
    pub user_id: String,
    pub banned: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdminBanMutationResp {
    pub user_id: String,
    pub banned: bool,
    pub sessions_revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentRecordResp {
    pub tx_hash: String,
    pub address: String,
    pub chain: String,
    pub token: String,
    pub amount: String,
    pub points: String,
    pub status: String,
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PaymentsListResp {
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
    pub payments: Vec<PaymentRecordResp>,
}

// ---------------------------------------------------------------------------
// Content Safety (Policy v3), Similarity, Geo, Age & Legal
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SafetyConfigResp {
    pub schema_version: u32,
    pub revision: u64,
    pub min_enforce_rev: u64,
    pub policy_digest: String,
    pub vocab_digest: String,
    pub activation_status: String,
    pub safety_enabled: bool,
    pub policies: Vec<ContentPolicy>,
    pub presets: Vec<ContentPolicy>,
    pub unclassified_mode: UnclassifiedMode,
    pub fixed_blur_enabled: bool,
    pub age_policy: AgeVerificationPolicy,
    pub age_gate_trigger: AgeGateTrigger,
    pub similarity: SimilarityDefaults,
    pub geo: GeoPolicy,
    pub legal: LegalDocConfig,
    pub legacy_unclassified_note: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub legacy_upgrade_notice: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveSafetyReq {
    pub revision: u64,
    pub safety_enabled: bool,
    pub policies: Vec<ContentPolicy>,
    pub unclassified_mode: UnclassifiedMode,
    pub fixed_blur_enabled: bool,
    pub age_policy: AgeVerificationPolicy,
    pub age_gate_trigger: AgeGateTrigger,
    pub similarity: SimilarityDefaults,
    pub geo: GeoPolicy,
    pub legal: LegalDocConfig,
    /// Must be `true` ONLY when publishing explicitly from the Content Safety Policy v3
    /// builder; defaults to `false` so non-safety tabs (`Similarity & Geo`, `Age & Legal`)
    /// or older clients fail closed (`409 Conflict`) when D1 holds a legacy pre-v3 row.
    #[serde(default)]
    pub confirm_policy_v3_migration: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveSafetyResp {
    pub ok: bool,
    #[serde(default)]
    pub unchanged: bool,
    pub pending_activation: bool,
    pub activation_status: String,
    pub revision: u64,
    pub min_enforce_rev: u64,
    pub tightened: bool,
    pub terms_bumped: bool,
    pub auto_disabled_providers: Vec<AuthProviderId>,
    pub policy_digest: String,
    pub vocab_digest: String,
    pub policies: Vec<ContentPolicy>,
    pub legal: LegalDocConfig,
}

// ---------------------------------------------------------------------------
// Auth Providers & Masked Secrets
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderView {
    pub config: AuthProviderPublicConfig,
    pub supports_strict_age_verification: bool,
    pub allowed_under_age_policy: bool,
    pub secret_field_name: Option<String>,
    pub has_client_secret: bool,
    pub kid: Option<String>,
    pub updated_at: Option<i64>,
    pub updated_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvidersResp {
    pub ok: bool,
    #[serde(default)]
    pub unchanged: bool,
    pub pending_activation: bool,
    pub activation_status: String,
    pub revision: u64,
    pub min_enforce_rev: u64,
    pub policy_digest: String,
    pub digest: String,
    pub age_policy: AgeVerificationPolicy,
    pub current_kid: String,
    pub has_prev_key: bool,
    #[serde(default)]
    pub public_origin: String,
    pub providers: Vec<ProviderView>,
}

/// Response returned by `POST /admin/api/providers` (identical shape to [`ProvidersResp`]).
pub type SaveProvidersResp = ProvidersResp;

/// Write-only provider update item. Custom `Debug` redacts `secret_value`.
#[derive(Clone, Serialize, Deserialize)]
pub struct ProviderUpdateItem {
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
    /// Write-only secret material (stored encrypted in `provider_secrets`, NEVER in `site_settings`).
    #[serde(default)]
    pub secret_value: Option<String>,
    /// Explicitly deletes the stored encrypted secret for this provider.
    #[serde(default)]
    pub clear_secret: bool,
}

impl fmt::Debug for ProviderUpdateItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProviderUpdateItem")
            .field("id", &self.id)
            .field("enabled", &self.enabled)
            .field("display_name", &self.display_name)
            .field("issuer", &self.issuer)
            .field("public_client_id", &self.public_client_id)
            .field("soft_birthday_check", &self.soft_birthday_check)
            .field(
                "secret_value",
                &self.secret_value.as_ref().map(|_| "[REDACTED]"),
            )
            .field("clear_secret", &self.clear_secret)
            .finish()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SaveProvidersReq {
    pub revision: u64,
    pub providers: Vec<ProviderUpdateItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RotateSecretsResp {
    pub current_kid: String,
    pub total_rows: usize,
    pub rotated: usize,
    pub skipped_current: usize,
    pub failed: usize,
}

// ---------------------------------------------------------------------------
// Content Reports Moderation Queue
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ReportCounts {
    pub open: i64,
    pub reviewing: i64,
    pub resolved: i64,
    pub dismissed: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentReportItem {
    pub id: String,
    pub reporter_key: String,
    pub reporter_user_id: Option<String>,
    pub target_kind: String,
    pub target_id: i64,
    pub reason: String,
    pub note: Option<String>,
    pub status: String,
    pub created_at: i64,
    pub resolved_at: Option<i64>,
    pub resolved_by: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportsListResp {
    pub status: String,
    pub counts: ReportCounts,
    pub reports: Vec<ContentReportItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveReportReq {
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResolveReportResp {
    pub id: String,
    pub status: String,
    pub resolved_at: Option<i64>,
    pub resolved_by: Option<String>,
}
