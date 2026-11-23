//! Shared security contracts, Policy v3 models, HKDF-SHA256 key derivation,
//! versioned token codecs (`GatewayAssertion v3`, `MediaCapability v3`,
//! `AdminAssertionClaims v2`, `GuestSessionToken`), and public policy validators
//! used across `gateway_worker`, `user_worker`, `admin_dashboard_worker`,
//! `search_engine`, and `lets-embed-web`.

pub mod kdf;
pub mod legal;
pub mod policy;
pub mod tokens;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit as _, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

pub use kdf::{
    HKDF_SALT, KeyDomain, MIN_MASTER_SECRET_BYTES, derive_domain_key_bytes, derive_domain_secret,
    hkdf_expand, hkdf_extract, resolve_domain_secret, resolve_provider_aes_key,
    validate_master_secret,
};
pub use legal::{
    DEFAULT_CONTENT_POLICY_MD, DEFAULT_DMCA_MD, DEFAULT_NOTICE_BANNER_MD, DEFAULT_PRIVACY_MD,
    DEFAULT_TERMS_MD, LegalDocConfig, compute_terms_digest,
};
pub use policy::{
    AgeGateTrigger, AgeVerificationMode, AgeVerificationPolicy, AssuranceLevel, AuthProviderId,
    AuthProviderPublicConfig, BUILTIN_SAFETY_VOCABULARY_TAGS, ContentPolicy,
    DEFAULT_POLICY_TAG_MIN, GeoPolicy, PlaceholderPreset, PolicyAccessResult, PolicyAction,
    PolicyBypass, PolicyCallerContext, PolicyRef, PolicyValidationError, PublicSitePolicy,
    SITE_POLICY_SCHEMA_VERSION, SessionContext, SimilarityDefaults, UnclassifiedMode,
    ValidatedPolicySetInfo, builtin_safety_presets, canonical_policy_json,
    compute_next_grant_generations, compute_next_min_enforce_rev, compute_policy_access,
    compute_policy_digest, decode_active_policy_v3, is_valid_iso_country_code, is_valid_policy_id,
    should_bump_min_enforce_rev, validate_policy_set, validate_policy_set_with_mode,
};
pub use tokens::{
    ADMIN_ASSERTION_AUDIENCE, ADMIN_ASSERTION_HEADER, ADMIN_ASSERTION_TTL,
    ADMIN_ASSERTION_VERSION, ADMIN_CSRF_HEADER, AUTH_TX_COOKIE, ActorBinding, AdminAssertion,
    AdminAssertionClaims, BillableMediaKind, GALLERY_SWITCHERS_HEADER, GATEWAY_ASSERTION_AUDIENCE,
    GATEWAY_ASSERTION_DEFAULT_MAX_SKEW, GATEWAY_ASSERTION_HEADER, GATEWAY_ASSERTION_TTL,
    GATEWAY_ASSERTION_VERSION, GUEST_SESSION_COOKIE, GUEST_SESSION_VERSION, GatewayAssertion,
    GuestSessionToken, LEGACY_APP_COOKIE, LEGACY_TOKEN_COOKIE, LegacySessionClaims,
    MEDIA_CAP_AUDIENCE, MEDIA_CAP_VERSION, MediaBillingKey, MediaCapKind, MediaCapability,
    POLICY_MIN_REVISION_HEADER, POLICY_REVISION_HEADER, PRIVILEGED_REQUEST_HEADER_PREFIXES,
    PRIVILEGED_REQUEST_HEADERS, SESSION_COOKIE, SESSION_V2_PREFIX, SESSION_V2_VERSION,
    STRIPPED_ORIGIN_COOKIES, SessionV2Claims, TokenError, USER_CSRF_HEADER, VerifiedSession,
    authorize_media_capability_v3, is_eth_address, is_privileged_request_header, is_sol_principal,
    is_valid_do_key, is_valid_legacy_principal, sha256_hex, sign_admin_assertion,
    sign_gateway_assertion, sign_guest_session, sign_legacy_session, sign_media_capability,
    sign_session_v2, verify_admin_assertion, verify_admin_assertion_with_body_hash,
    verify_gateway_assertion, verify_guest_session, verify_legacy_session, verify_media_capability,
    verify_session_any, verify_session_v2,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
// Discriminants are the published settings array indices. Append new kinds at the end.
#[repr(u8)]
pub enum ChargeKind {
    Image = 0,
    Video = 1,
    Search = 2,
    EmbedSearch = 3,
    Description = 4,
}
impl ChargeKind {
    pub const ALL: [Self; 5] = [
        Self::Image,
        Self::Video,
        Self::EmbedSearch,
        Self::Search,
        Self::Description,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Self::Image => "image",
            Self::Video => "video",
            Self::EmbedSearch => "similar",
            Self::Search => "upload",
            Self::Description => "description",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Image => "Image views",
            Self::Video => "Video views",
            Self::EmbedSearch => "Similar-image searches",
            Self::Search => "Uploaded-image searches",
            Self::Description => "Description searches",
        }
    }
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ChargeReq {
    pub path: String,
    pub kind: ChargeKind,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct GuestReq {
    pub item: Option<ChargeReq>,
    pub head: bool,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct HoldReq {
    pub hold_id: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct HoldResp {
    pub hold_id: Option<String>,
}

pub const ADMIN_HEADER: &str = "x-gallery-admin-email";
pub const UPGRADE_PATH: &str = "/user/upgrade";
pub const ADMIN_VIEW_COOKIE: &str = "__Host-ue_admin_view";
pub const VIEW_TTL: u64 = 15 * 60;

fn mac(secret: &[u8], purpose: &[u8], value: &[u8]) -> Hmac<Sha256> {
    let mut mac = Hmac::new_from_slice(secret).expect("HMAC accepts variable length keys");
    mac.update(purpose);
    mac.update(value);
    mac
}
/// A short-lived browsing pass, issued only after verifying the admin application
/// assertion. Strictly limited to billing and guest login wall waiver — NEVER
/// grants `LiveAdmin` content bypass or Switcher unlocks.
pub fn admin_view_pass(secret: &[u8], expiry: u64) -> String {
    let signature = mac(secret, b"admin-view/v1\0", &expiry.to_be_bytes())
        .finalize()
        .into_bytes();
    format!("{expiry}.{}", URL_SAFE_NO_PAD.encode(signature))
}
pub fn valid_admin_view(secret: &[u8], value: &str, now: u64) -> bool {
    if secret.is_empty() {
        return false;
    }
    let Some((exp, signature)) = value.split_once('.') else {
        return false;
    };
    let Ok(exp) = exp.parse::<u64>() else {
        return false;
    };
    if exp <= now || exp > now.saturating_add(VIEW_TTL) {
        return false;
    }
    let Ok(sig) = URL_SAFE_NO_PAD.decode(signature) else {
        return false;
    };
    mac(secret, b"admin-view/v1\0", &exp.to_be_bytes())
        .verify_slice(&sig)
        .is_ok()
}
pub fn guest_account(secret: &[u8], ip: std::net::IpAddr) -> String {
    let digest = mac(
        secret,
        b"guest/v1\0",
        ip.to_canonical().to_string().as_bytes(),
    )
    .finalize()
    .into_bytes();
    format!("guest:{}", URL_SAFE_NO_PAD.encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ETH_ADDR: &str = "0xd8da6bf26964af9d7eed9e03e53415d37aa96045";
    const SOL_ADDR: &str = "7Np41oeYqPefeNQEHSv1UDhYrehxin3NStELsSKCT4K2";
    const SAMPLE_DIGEST: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    #[test]
    fn wd_vocab_digest_matches_sha2_crate() {
        let computed = sha256_hex(search_types::canonical_wd_vocab_bytes());
        assert_eq!(computed, search_types::WD_VOCAB_DIGEST);
        assert_eq!(search_types::wd_vocab_count(), 10_861);
    }

    #[test]
    fn browsing_pass_is_scoped_and_expires_and_never_grants_live_admin() {
        let pass = admin_view_pass(b"local", 600);
        assert!(valid_admin_view(b"local", &pass, 500));
        assert!(!valid_admin_view(b"other", &pass, 500));
        assert!(!valid_admin_view(b"local", &pass, 600));
        assert!(!valid_admin_view(
            b"local",
            &pass.replace("600.", "601."),
            500
        ));
        assert!(!valid_admin_view(
            b"local",
            &admin_view_pass(b"local", 1800),
            1
        ));
        assert!(!valid_admin_view(b"", &admin_view_pass(b"", 600), 500));

        // Even with a valid browse pass cookie, PolicyCallerContext has no live_admin_email
        // so LiveAdmin bypass is NEVER granted!
        let mut policy = PublicSitePolicy {
            revision: 1,
            min_enforce_rev: 1,
            safety_enabled: true,
            policies: vec![ContentPolicy {
                id: "staff_only".into(),
                grant_generation: 1,
                enabled: true,
                priority: 1,
                name: "Staff".into(),
                preset: PlaceholderPreset::R18,
                match_expr: "tag:explicit".into(),
                except_expr: None,
                default_tag_min: 0.45,
                action: PolicyAction::Block,
                bypass: PolicyBypass {
                    include_live_admin: true,
                    ..PolicyBypass::default()
                },
            }],
            ..PublicSitePolicy::default()
        };
        policy.refresh_policy_digest();

        let browse_pass_only = PolicyCallerContext {
            session: None,
            session_revoked_or_invalid: false,
            live_admin_email: None,
            country: Some("US".into()),
        };
        assert!(
            compute_policy_access(&policy, &browse_pass_only)
                .direct_grants
                .is_empty()
        );
    }

    #[test]
    fn session_v2_and_guest_session_sign_verify_and_domain_separate() {
        let secret = b"same-raw-secret-for-domain-separation-test";
        let v2_claims = SessionV2Claims {
            v: SESSION_V2_VERSION,
            sub: "usr-uuid-12345678".to_string(),
            do_key: "usr:550e8400-e29b-41d4-a716-446655440000".to_string(),
            sid: "sid_abc123".to_string(),
            iat: 1000,
            exp: 2000,
        };
        let v2_tok = sign_session_v2(&v2_claims, secret).expect("sign v2");
        assert!(v2_tok.starts_with("v2."));
        assert_eq!(verify_session_v2(&v2_tok, secret, 1500).unwrap(), v2_claims);
        assert_eq!(
            verify_session_v2(&v2_tok, secret, 2001),
            Err(TokenError::Expired)
        );
        assert_eq!(
            verify_session_v2(&v2_tok, b"wrong-secret", 1500),
            Err(TokenError::InvalidSignature)
        );

        // Guest session cookie codec (`le_guest_sid`)
        let guest = GuestSessionToken {
            v: GUEST_SESSION_VERSION,
            gid: "guest_rnd_0123456789".to_string(),
            iat: 1000,
            exp: 2000,
        };
        let gtok = sign_guest_session(&guest, secret).expect("sign guest");
        assert!(gtok.starts_with("gs1."));
        assert_eq!(verify_guest_session(&gtok, secret, 1500).unwrap(), guest);
        assert_eq!(
            verify_guest_session(&gtok, secret, 2001),
            Err(TokenError::Expired)
        );
        assert!(verify_session_v2(&gtok, secret, 1500).is_err());
        assert!(verify_guest_session(&v2_tok, secret, 1500).is_err());
        assert!(STRIPPED_ORIGIN_COOKIES.contains(&GUEST_SESSION_COOKIE));

        // Legacy wallet cutover still domain-separated
        let legacy_claims = LegacySessionClaims {
            sub: ETH_ADDR.to_string(),
            iat: 1000,
            exp: 2000,
        };
        let legacy_tok = sign_legacy_session(&legacy_claims, secret).expect("sign legacy");
        assert!(verify_session_v2(&legacy_tok, secret, 1500).is_err());
        let any_legacy = verify_session_any(&legacy_tok, b"v2-key", Some(secret), 1500).unwrap();
        assert_eq!(any_legacy.do_key(), ETH_ADDR);

        let migrated_sol = SessionV2Claims {
            v: SESSION_V2_VERSION,
            sub: SOL_ADDR.to_string(),
            do_key: SOL_ADDR.to_string(),
            sid: "sid_sol".to_string(),
            iat: 100,
            exp: 500,
        };
        let sol_tok = sign_session_v2(&migrated_sol, secret).unwrap();
        assert_eq!(
            verify_session_v2(&sol_tok, secret, 200).unwrap(),
            migrated_sol
        );
    }

    #[test]
    fn gateway_assertion_v3_rejects_v1_anon_direct_grants_skew_and_tamper() {
        let secret = b"gw-assertion-v3-secret";
        let assertion = GatewayAssertion {
            v: GATEWAY_ASSERTION_VERSION,
            aud: GATEWAY_ASSERTION_AUDIENCE.to_string(),
            actor: ActorBinding::User {
                sub: "user-1".into(),
                sid: "sid-1".into(),
            },
            rev: 7,
            min_enforce_rev: 5,
            digest: SAMPLE_DIGEST.to_string(),
            direct_grants: vec![PolicyRef::new("r18", 2)],
            click_eligible: vec![PolicyRef::new("sensitive", 1)],
            is_billing_waived: false,
            caller_age_verified: true,
            caller_terms_accepted: true,
            exp: 1030,
        };

        let header = sign_gateway_assertion(&assertion, secret).expect("sign ga3");
        assert!(header.starts_with("ga3."));
        assert_eq!(
            verify_gateway_assertion(&header, secret, GATEWAY_ASSERTION_AUDIENCE, 1020, 5).unwrap(),
            assertion
        );
        assert_eq!(
            verify_gateway_assertion(&header, secret, GATEWAY_ASSERTION_AUDIENCE, 1036, 5),
            Err(TokenError::Expired)
        );
        assert_eq!(
            verify_gateway_assertion(&header, secret, "other-aud", 1020, 5),
            Err(TokenError::AudienceMismatch)
        );

        // Anon actor with direct_grants MUST fail validation
        let bad_anon = GatewayAssertion {
            actor: ActorBinding::Anon,
            ..assertion.clone()
        };
        assert!(sign_gateway_assertion(&bad_anon, secret).is_err());

        // Anon actor with click_eligible only is valid
        let ok_anon = GatewayAssertion {
            actor: ActorBinding::Anon,
            direct_grants: Vec::new(),
            ..assertion.clone()
        };
        assert!(sign_gateway_assertion(&ok_anon, secret).is_ok());

        // Legacy v3 payload omitting caller_age_verified / caller_terms_accepted defaults both to false
        let legacy_ga3_json = serde_json::json!({
            "v": GATEWAY_ASSERTION_VERSION,
            "aud": GATEWAY_ASSERTION_AUDIENCE,
            "actor": { "kind": "user", "sub": "user-legacy", "sid": "sid-legacy" },
            "rev": 7,
            "min_enforce_rev": 5,
            "digest": SAMPLE_DIGEST,
            "direct_grants": [],
            "click_eligible": [],
            "is_billing_waived": false,
            "exp": 1030
        });
        let legacy_payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&legacy_ga3_json).unwrap());
        let mut mac_v3 = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac_v3.update(b"gateway-assertion/v3\0");
        mac_v3.update(b"ga3.");
        mac_v3.update(legacy_payload.as_bytes());
        let legacy_ga3_hdr = format!(
            "ga3.{legacy_payload}.{}",
            URL_SAFE_NO_PAD.encode(mac_v3.finalize().into_bytes())
        );
        let decoded_legacy = verify_gateway_assertion(
            &legacy_ga3_hdr,
            secret,
            GATEWAY_ASSERTION_AUDIENCE,
            1020,
            5,
        )
        .expect("v3 assertion without caller flags must decode with defaults");
        assert!(!decoded_legacy.caller_age_verified);
        assert!(!decoded_legacy.caller_terms_accepted);

        // Reject legacy v1 (`ga1.`) assertion!
        let fake_v1_payload = URL_SAFE_NO_PAD.encode(b"{}");
        let mut mac_v1 = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        mac_v1.update(b"gateway-assertion/v1\0");
        mac_v1.update(b"ga1.");
        mac_v1.update(fake_v1_payload.as_bytes());
        let fake_v1 = format!(
            "ga1.{fake_v1_payload}.{}",
            URL_SAFE_NO_PAD.encode(mac_v1.finalize().into_bytes())
        );
        assert!(
            verify_gateway_assertion(&fake_v1, secret, GATEWAY_ASSERTION_AUDIENCE, 1020, 5)
                .is_err()
        );
    }

    #[test]
    fn media_capability_v3_rejects_v1_v2_facts_mismatch_and_revoked_click_reveal() {
        let secret = b"media-cap-v3-secret";
        let mut policy = PublicSitePolicy {
            revision: 10,
            min_enforce_rev: 5,
            safety_enabled: true,
            fixed_blur_enabled: true,
            policies: builtin_safety_presets(),
            ..PublicSitePolicy::default()
        };
        policy.refresh_policy_digest();

        let guest_actor = ActorBinding::GuestSession {
            gid: "guest_session_999999".into(),
        };
        let blur_ref = PolicyRef::new("sensitive", 1);
        let block_ref = PolicyRef::new("r18", 1);

        // 1. Click-revealed clear capability for blurred asset
        let cap = MediaCapability {
            v: MEDIA_CAP_VERSION,
            aud: MEDIA_CAP_AUDIENCE.into(),
            kind: MediaCapKind::Image,
            asset_id: 42,
            immutable_locator: "2026/01/photo_42.webp".into(),
            facts_rev: 7,
            policy_rev: 10,
            actor_binding: guest_actor.clone(),
            matched_blocks: vec![],
            matched_blurs: vec![blur_ref.clone()],
            revealed_refs: vec![blur_ref.clone()],
            exp: 5000,
        };
        let tok = sign_media_capability(&cap, secret).expect("sign mc3");
        assert!(tok.starts_with("mc3."));

        let verified = verify_media_capability(
            &tok,
            secret,
            MEDIA_CAP_AUDIENCE,
            MediaCapKind::Image,
            42,
            4500,
            policy.min_enforce_rev,
            policy.revision,
        )
        .expect("verify mc3");
        assert_eq!(verified, cap);

        // Reject legacy v1/v2 empty-switcher capabilities!
        let v1_payload = URL_SAFE_NO_PAD.encode(
            r#"{"v":1,"kind":"image","id":42,"path":"2026/01/photo_42.webp","rev":10,"sub":"anon","req_switchers":[],"exp":5000}"#,
        );
        let mut m1 = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        m1.update(b"media-cap/v1\0");
        m1.update(v1_payload.as_bytes());
        let legacy_v1 = format!(
            "{v1_payload}.{}",
            URL_SAFE_NO_PAD.encode(m1.finalize().into_bytes())
        );
        assert!(
            verify_media_capability(
                &legacy_v1,
                secret,
                MEDIA_CAP_AUDIENCE,
                MediaCapKind::Image,
                42,
                4500,
                5,
                10
            )
            .is_err()
        );

        // Reject policy_rev ahead of active_rev or behind min_enforce_rev
        assert_eq!(
            verify_media_capability(
                &tok,
                secret,
                MEDIA_CAP_AUDIENCE,
                MediaCapKind::Image,
                42,
                4500,
                11,
                12
            ),
            Err(TokenError::PolicyRevisionStale {
                token_rev: 10,
                min_enforce_rev: 11,
            })
        );
        assert_eq!(
            verify_media_capability(
                &tok,
                secret,
                MEDIA_CAP_AUDIENCE,
                MediaCapKind::Image,
                42,
                4500,
                5,
                9
            ),
            Err(TokenError::PolicyRevisionAhead {
                token_rev: 10,
                active_rev: 9,
            })
        );

        // Authorize succeeds when facts_rev matches, actor matches, and blur_ref is click_eligible
        let live_click_ok = PolicyAccessResult {
            direct_grants: vec![],
            click_eligible: vec![blur_ref.clone()],
        };
        assert!(authorize_media_capability_v3(
            &cap,
            &guest_actor,
            &live_click_ok,
            &policy,
            Some(7)
        ));

        // facts_rev mismatch or None fails closed!
        assert!(!authorize_media_capability_v3(
            &cap,
            &guest_actor,
            &live_click_ok,
            &policy,
            Some(8)
        ));
        assert!(!authorize_media_capability_v3(
            &cap,
            &guest_actor,
            &live_click_ok,
            &policy,
            None
        ));

        // Actor mismatch (different guest or Anon) fails closed!
        assert!(!authorize_media_capability_v3(
            &cap,
            &ActorBinding::GuestSession {
                gid: "different_guest_sid".into()
            },
            &live_click_ok,
            &policy,
            Some(7)
        ));
        assert!(!authorize_media_capability_v3(
            &cap,
            &ActorBinding::Anon,
            &live_click_ok,
            &policy,
            Some(7)
        ));

        // Revocation via revealed_refs ∩ live_click_eligible:
        // If admin turns off include_click or country changes so click_eligible no longer
        // contains blur_ref, previously minted revealed capability is IMMEDIATELY DENIED!
        let live_click_revoked = PolicyAccessResult {
            direct_grants: vec![],
            click_eligible: vec![],
        };
        assert!(!authorize_media_capability_v3(
            &cap,
            &guest_actor,
            &live_click_revoked,
            &policy,
            Some(7)
        ));

        // Preview cap succeeds when fixed_blur_enabled == true and matched_blocks satisfied,
        // and FAILS immediately when fixed_blur_enabled == false!
        let preview_cap = MediaCapability {
            kind: MediaCapKind::Preview,
            matched_blocks: vec![block_ref.clone()],
            matched_blurs: vec![blur_ref.clone()],
            revealed_refs: vec![],
            ..cap.clone()
        };
        let with_block_grant = PolicyAccessResult {
            direct_grants: vec![block_ref.clone()],
            click_eligible: vec![],
        };
        assert!(authorize_media_capability_v3(
            &preview_cap,
            &guest_actor,
            &with_block_grant,
            &policy,
            Some(7)
        ));
        policy.fixed_blur_enabled = false;
        assert!(!authorize_media_capability_v3(
            &preview_cap,
            &guest_actor,
            &with_block_grant,
            &policy,
            Some(7)
        ));
        policy.fixed_blur_enabled = true;

        // Public Anon cap STILL requires facts_rev match when safety_enabled == true!
        let anon_cap = MediaCapability {
            actor_binding: ActorBinding::Anon,
            matched_blocks: vec![],
            matched_blurs: vec![],
            revealed_refs: vec![],
            ..cap.clone()
        };
        assert!(authorize_media_capability_v3(
            &anon_cap,
            &ActorBinding::Anon,
            &PolicyAccessResult::default(),
            &policy,
            Some(7)
        ));
        assert!(!authorize_media_capability_v3(
            &anon_cap,
            &ActorBinding::Anon,
            &PolicyAccessResult::default(),
            &policy,
            Some(8)
        ));

        // Video capability with unsatisfied Blur MUST be denied; revealed Video Blur succeeds!
        let video_blur_cap = MediaCapability {
            kind: MediaCapKind::Video,
            immutable_locator: "2026/01/clip_42.mp4".into(),
            matched_blocks: vec![],
            matched_blurs: vec![blur_ref.clone()],
            revealed_refs: vec![],
            ..cap.clone()
        };
        assert!(!authorize_media_capability_v3(
            &video_blur_cap,
            &guest_actor,
            &live_click_ok,
            &policy,
            Some(7)
        ));
        let video_blur_revealed = MediaCapability {
            revealed_refs: vec![blur_ref.clone()],
            ..video_blur_cap
        };
        assert!(authorize_media_capability_v3(
            &video_blur_revealed,
            &guest_actor,
            &live_click_ok,
            &policy,
            Some(7)
        ));
        assert!(!authorize_media_capability_v3(
            &video_blur_revealed,
            &guest_actor,
            &live_click_revoked,
            &policy,
            Some(7)
        ));

        // Anon cap with any matched restriction MUST be rejected at sign AND authorize!
        let bad_anon_cap = MediaCapability {
            actor_binding: ActorBinding::Anon,
            matched_blurs: vec![blur_ref],
            revealed_refs: vec![],
            ..cap
        };
        assert!(sign_media_capability(&bad_anon_cap, secret).is_err());
        assert!(!authorize_media_capability_v3(
            &bad_anon_cap,
            &ActorBinding::Anon,
            &live_click_ok,
            &policy,
            Some(7)
        ));
    }

    #[test]
    fn admin_assertion_v2_enforces_method_target_body_hash_and_rejects_v1() {
        let secret = b"admin-assertion-v2-secret";
        let body = br#"{"safety_enabled":true}"#;
        let claims = AdminAssertionClaims {
            v: ADMIN_ASSERTION_VERSION,
            aud: ADMIN_ASSERTION_AUDIENCE.into(),
            email: "admin@example.com".into(),
            m: "POST".into(),
            p: "/admin/api/safety?rev=3".into(),
            bh: sha256_hex(body),
            jti: "nonce_0123456789abcdef".into(),
            exp: 2030,
        };
        let hdr = sign_admin_assertion(&claims, secret).expect("sign aa2");
        assert!(hdr.starts_with("aa2."));

        // Exact match succeeds
        assert_eq!(
            verify_admin_assertion(
                &hdr,
                secret,
                ADMIN_ASSERTION_AUDIENCE,
                "POST",
                "/admin/api/safety?rev=3",
                body,
                2010,
                5
            )
            .unwrap(),
            claims
        );

        // Wrong method rejected
        assert_eq!(
            verify_admin_assertion(
                &hdr,
                secret,
                ADMIN_ASSERTION_AUDIENCE,
                "DELETE",
                "/admin/api/safety?rev=3",
                body,
                2010,
                5
            ),
            Err(TokenError::RequestBindingMismatch("HTTP method mismatch"))
        );

        // Wrong canonical path/query rejected
        assert_eq!(
            verify_admin_assertion(
                &hdr,
                secret,
                ADMIN_ASSERTION_AUDIENCE,
                "POST",
                "/admin/api/safety?rev=4",
                body,
                2010,
                5
            ),
            Err(TokenError::RequestBindingMismatch(
                "canonical request target mismatch"
            ))
        );

        // Tampered body hash rejected
        assert_eq!(
            verify_admin_assertion(
                &hdr,
                secret,
                ADMIN_ASSERTION_AUDIENCE,
                "POST",
                "/admin/api/safety?rev=3",
                br#"{"safety_enabled":false}"#,
                2010,
                5
            ),
            Err(TokenError::RequestBindingMismatch("body digest mismatch"))
        );

        // Expired rejected
        assert_eq!(
            verify_admin_assertion(
                &hdr,
                secret,
                ADMIN_ASSERTION_AUDIENCE,
                "POST",
                "/admin/api/safety?rev=3",
                body,
                2036,
                5
            ),
            Err(TokenError::Expired)
        );

        // Legacy aa1. assertion rejected
        let fake_v1 = format!("aa1.{}.sig", URL_SAFE_NO_PAD.encode(b"{}"));
        assert!(
            verify_admin_assertion(
                &fake_v1,
                secret,
                ADMIN_ASSERTION_AUDIENCE,
                "POST",
                "/admin/api/safety?rev=3",
                body,
                2010,
                5
            )
            .is_err()
        );
    }

    #[test]
    fn strict_age_verification_allows_only_oidc_age_assurance() {
        for provider in AuthProviderId::ALL {
            if provider == AuthProviderId::OidcAgeAssurance {
                assert!(provider.supports_strict_age_verification());
                assert!(provider.is_allowed_under(AgeVerificationPolicy::StrictProviderVerified18));
            } else {
                assert!(!provider.supports_strict_age_verification());
                assert!(
                    !provider.is_allowed_under(AgeVerificationPolicy::StrictProviderVerified18)
                );
            }
        }
    }

    #[test]
    fn policy_digest_is_deterministic_idempotent_and_secret_free() {
        let mut p1 = PublicSitePolicy {
            revision: 3,
            min_enforce_rev: 2,
            safety_enabled: true,
            policies: builtin_safety_presets(),
            age_policy: AgeVerificationPolicy::SelfAttestation,
            age_gate_trigger: AgeGateTrigger::JustInTime,
            geo: GeoPolicy {
                blocked_countries: vec!["KP".to_string()],
                block_unknown: false,
                block_tor: true,
            },
            ..PublicSitePolicy::default()
        };
        let d1 = compute_policy_digest(&p1);
        assert_eq!(d1.len(), 64);

        // Storing policy_digest inside p1 keeps compute_policy_digest identical!
        p1.refresh_policy_digest();
        assert_eq!(p1.policy_digest, d1);
        assert!(p1.verify_policy_digest());
        assert_eq!(compute_policy_digest(&p1), d1);

        // JSON roundtrip preserves exact digest
        let json = canonical_policy_json(&p1);
        let p2 = decode_active_policy_v3(&json).unwrap();
        assert_eq!(p2, p1);
        assert_eq!(compute_policy_digest(&p2), d1);

        // Changing any enforcement field invalidates digest
        p1.min_enforce_rev = 3;
        assert!(!p1.verify_policy_digest());
        assert_ne!(compute_policy_digest(&p1), d1);

        // AuthProviderPublicConfig rejects unknown secret fields
        let with_secret = r#"{"id":"google","enabled":true,"client_secret":"leaked"}"#;
        assert!(serde_json::from_str::<AuthProviderPublicConfig>(with_secret).is_err());

        // Geo policy evaluation
        assert!(p1.geo.is_blocked(Some("kp")));
        assert!(p1.geo.is_blocked(Some("T1")));
        assert!(!p1.geo.is_blocked(Some("XX")));
        assert!(!p1.geo.is_blocked(None));
        assert!(!p1.geo.is_blocked(Some("US")));
    }

    #[test]
    fn default_policy_starts_disabled_with_v3_defaults() {
        let p = PublicSitePolicy::default();
        assert_eq!(p.schema_version, SITE_POLICY_SCHEMA_VERSION);
        assert_eq!(p.revision, 0);
        assert!(!p.safety_enabled);
        assert!(p.policies.is_empty());
        assert_eq!(p.unclassified_mode, UnclassifiedMode::Placeholder);
        assert!(!p.fixed_blur_enabled);
        assert_eq!(p.vocab_digest, search_types::WD_VOCAB_DIGEST);
        assert!(p.verify_policy_digest());
        assert_eq!(p.age_policy, AgeVerificationPolicy::Off);
        assert_eq!(p.age_gate_trigger, AgeGateTrigger::Off);
        assert_eq!(p.legal.terms_digest.len(), 64);
    }

    #[test]
    fn media_capability_rejects_path_traversal_and_percent_encoding_traps() {
        let secret = b"media-cap-secret";
        let base = MediaCapability {
            v: MEDIA_CAP_VERSION,
            aud: MEDIA_CAP_AUDIENCE.into(),
            kind: MediaCapKind::Image,
            asset_id: 42,
            immutable_locator: "2026/01/ok.webp".into(),
            facts_rev: 1,
            policy_rev: 1,
            actor_binding: ActorBinding::User {
                sub: "user-1".into(),
                sid: "sid-1".into(),
            },
            matched_blocks: vec![PolicyRef::new("r18", 1)],
            matched_blurs: vec![],
            revealed_refs: vec![],
            exp: 5000,
        };

        let oversized_path = format!("{}.webp", "a".repeat(1025));
        for bad in [
            "../secret.webp",
            "%2e%2e/secret.webp",
            "%2E%2E/secret.webp",
            ".%2e/secret.webp",
            "..%2fsecret.webp",
            "a%5c..%5cb",
            "img%00.webp",
            "img%3fx=1",
            "img%23frag",
            "http:evil.com/x.webp",
            "https://evil.com/x.webp",
            " 2026/ok.webp",
            "2026/ok.webp ",
            "2026//ok.webp",
            "2026/ok\x00.webp",
            oversized_path.as_str(),
        ] {
            let cap = MediaCapability {
                immutable_locator: bad.to_string(),
                ..base.clone()
            };
            assert!(
                sign_media_capability(&cap, secret).is_err(),
                "must reject unsafe locator: {bad:?}"
            );
        }

        // Canonical billing keys separate clear views from previews
        let img_key = base.billing_key().expect("image is billable");
        assert_eq!(img_key.canonical_key(), "media:image:42");
        assert_eq!(img_key.charge_kind(), ChargeKind::Image);
        assert_eq!(MediaBillingKey::video(42).canonical_key(), "media:video:42");
        assert_eq!(MediaBillingKey::from_cap_kind(MediaCapKind::Preview, 42), None);
        assert_ne!(
            MediaBillingKey::preview_budget_key(42),
            img_key.canonical_key()
        );
    }

    #[test]
    fn legal_defaults_export_notice_banner_and_omit_safe_mode_copy() {
        assert_eq!(
            DEFAULT_NOTICE_BANNER_MD,
            "This gallery hosts community-tagged artwork. Review our [Content Policy](/content-policy) or adjust your content preferences in [Account Settings](/user/account)."
        );

        let privacy_lower = DEFAULT_PRIVACY_MD.to_ascii_lowercase();
        assert!(!privacy_lower.contains("safe mode"));
        assert!(!privacy_lower.contains("safe-mode"));

        let mut legal = LegalDocConfig::default();
        assert!(legal.notice_banner_md.is_empty());
        assert!(!legal.notice_banner_enabled);
        assert_eq!(legal.effective_notice_banner_md(), None);

        legal.notice_banner_enabled = true;
        assert_eq!(
            legal.effective_notice_banner_md(),
            Some(DEFAULT_NOTICE_BANNER_MD)
        );

        legal.notice_banner_md = "   ".to_string();
        assert_eq!(
            legal.effective_notice_banner_md(),
            Some(DEFAULT_NOTICE_BANNER_MD)
        );

        legal.notice_banner_md = "  Custom notice  ".to_string();
        assert_eq!(legal.effective_notice_banner_md(), Some("Custom notice"));

        legal.notice_banner_enabled = false;
        assert_eq!(legal.effective_notice_banner_md(), None);
    }
}
