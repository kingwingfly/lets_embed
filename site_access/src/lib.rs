//! Shared security contracts, wire types, token codecs, and public policy models
//! used across `gateway_worker`, `user_worker`, `admin_dashboard_worker`, and `lets-embed-web`.

pub mod legal;
pub mod policy;
pub mod tokens;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit as _, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

pub use legal::{
    DEFAULT_CONTENT_POLICY_MD, DEFAULT_DMCA_MD, DEFAULT_PRIVACY_MD, DEFAULT_TERMS_MD,
    LegalDocConfig, compute_terms_digest,
};
pub use policy::{
    AgeGateTrigger, AgeVerificationPolicy, AssuranceLevel, AuthProviderId,
    AuthProviderPublicConfig, BUILTIN_SAFETY_VOCABULARY_TAGS, DEFAULT_PANIC_SHORTCUT, GeoPolicy,
    PlaceholderPreset, PublicSitePolicy, RuleMode, SafetyRuleConfig, SessionContext,
    SimilarityDefaults, UnclassifiedMode, builtin_safety_presets, canonical_policy_json,
    compute_policy_digest,
};
pub use tokens::{
    ADMIN_ASSERTION_AUDIENCE, ADMIN_ASSERTION_HEADER, ADMIN_ASSERTION_TTL,
    ADMIN_ASSERTION_VERSION, ADMIN_CSRF_HEADER, AUTH_TX_COOKIE, AdminAssertion, BillableMediaKind,
    GALLERY_SWITCHERS_HEADER, GATEWAY_ASSERTION_AUDIENCE, GATEWAY_ASSERTION_DEFAULT_MAX_SKEW,
    GATEWAY_ASSERTION_HEADER, GATEWAY_ASSERTION_TTL, GATEWAY_ASSERTION_VERSION, GatewayAssertion,
    LEGACY_APP_COOKIE, LEGACY_TOKEN_COOKIE, LegacySessionClaims, MEDIA_CAP_ANON_SUB,
    MEDIA_CAP_VERSION, MediaBillingKey, MediaCapKind, MediaCapability, POLICY_MIN_REVISION_HEADER,
    POLICY_REVISION_HEADER, PRIVILEGED_REQUEST_HEADER_PREFIXES, PRIVILEGED_REQUEST_HEADERS,
    SESSION_COOKIE, SESSION_V2_PREFIX, SESSION_V2_VERSION, STRIPPED_ORIGIN_COOKIES,
    SessionV2Claims, TokenError, USER_CSRF_HEADER, VerifiedSession, is_eth_address,
    is_privileged_request_header, is_sol_principal, is_valid_do_key, is_valid_legacy_principal,
    sign_admin_assertion, sign_gateway_assertion, sign_legacy_session, sign_media_capability,
    sign_session_v2, verify_admin_assertion, verify_gateway_assertion, verify_legacy_session,
    verify_media_capability, verify_session_any, verify_session_v2,
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
/// assertion. Admin mutations always require a fresh Access-authenticated request.
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
    fn browsing_pass_is_scoped_and_expires() {
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
    }

    #[test]
    fn session_v2_sign_verify_tamper_expiry_and_domain_separation() {
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

        // Valid verification
        assert_eq!(verify_session_v2(&v2_tok, secret, 1500).unwrap(), v2_claims);
        assert_eq!(verify_session_v2(&v2_tok, secret, 2000).unwrap(), v2_claims);

        // Expiry
        assert_eq!(
            verify_session_v2(&v2_tok, secret, 2001),
            Err(TokenError::Expired)
        );

        // Wrong secret
        assert_eq!(
            verify_session_v2(&v2_tok, b"wrong-secret", 1500),
            Err(TokenError::InvalidSignature)
        );

        // Tampered payload
        let mut tampered = v2_tok.clone();
        let last = tampered.pop().unwrap();
        tampered.push(if last == 'A' { 'B' } else { 'A' });
        assert_eq!(
            verify_session_v2(&tampered, secret, 1500),
            Err(TokenError::InvalidSignature)
        );

        // Domain separation: v2 token MUST NOT verify as legacy, even with identical secret
        assert!(verify_legacy_session(&v2_tok, secret, 1500).is_err());
        // Stripping "v2." prefix MUST also fail legacy verification (different HMAC domain + payload)
        let stripped = v2_tok.strip_prefix("v2.").unwrap();
        assert!(verify_legacy_session(stripped, secret, 1500).is_err());

        // Legacy wallet token signs & verifies via cutover helper, NEVER as v2
        let legacy_claims = LegacySessionClaims {
            sub: ETH_ADDR.to_string(),
            iat: 1000,
            exp: 2000,
        };
        let legacy_tok = sign_legacy_session(&legacy_claims, secret).expect("sign legacy");
        assert!(!legacy_tok.starts_with("v2."));
        assert!(verify_session_v2(&legacy_tok, secret, 1500).is_err());
        assert!(verify_session_v2(&format!("v2.{legacy_tok}"), secret, 1500).is_err());

        let any_v2 = verify_session_any(&v2_tok, secret, Some(secret), 1500).unwrap();
        assert!(any_v2.is_v2());
        assert_eq!(any_v2.sid(), Some("sid_abc123"));

        let any_legacy = verify_session_any(&legacy_tok, b"v2-key", Some(secret), 1500).unwrap();
        assert!(!any_legacy.is_v2());
        assert_eq!(any_legacy.user_id(), ETH_ADDR);
        assert_eq!(any_legacy.do_key(), ETH_ADDR);
        assert_eq!(any_legacy.sid(), None);

        // Legacy gw_token (UUID sub signed with same raw secret) MUST be rejected by both!
        let fake_gw_payload =
            URL_SAFE_NO_PAD.encode(r#"{"sub":"2f4d0c9e-9f5a-4a2c-8f2e-2d3b4c5d6e7f","iat":1000,"exp":2000}"#);
        let mut raw_mac = Hmac::<Sha256>::new_from_slice(secret).unwrap();
        raw_mac.update(fake_gw_payload.as_bytes());
        let gw_tok = format!(
            "{fake_gw_payload}.{}",
            URL_SAFE_NO_PAD.encode(raw_mac.finalize().into_bytes())
        );
        assert!(verify_legacy_session(&gw_tok, secret, 1500).is_err());
        assert!(verify_session_v2(&gw_tok, secret, 1500).is_err());
        assert!(verify_session_any(&gw_tok, secret, Some(secret), 1500).is_err());

        // Legacy migrated wallet principals remain valid do_key in v2 sessions
        let migrated_sol = SessionV2Claims {
            v: SESSION_V2_VERSION,
            sub: SOL_ADDR.to_string(),
            do_key: SOL_ADDR.to_string(),
            sid: "sid_sol".to_string(),
            iat: 100,
            exp: 500,
        };
        let sol_tok = sign_session_v2(&migrated_sol, secret).unwrap();
        assert_eq!(verify_session_v2(&sol_tok, secret, 200).unwrap(), migrated_sol);
    }

    #[test]
    fn gateway_assertion_verifies_audience_skew_expiry_and_tamper() {
        let secret = b"gw-assertion-secret";
        let assertion = GatewayAssertion {
            v: GATEWAY_ASSERTION_VERSION,
            aud: GATEWAY_ASSERTION_AUDIENCE.to_string(),
            rev: 7,
            min_enforce_rev: 5,
            policy_digest: SAMPLE_DIGEST.to_string(),
            sub: Some("user-1".to_string()),
            sid: Some("sid-1".to_string()),
            switchers: vec!["r18".to_string()],
            safe_mode: false,
            is_admin_view: false,
            exp: 1030,
        };

        let header = sign_gateway_assertion(&assertion, secret).expect("sign assertion");

        // Exact audience & within expiry
        assert_eq!(
            verify_gateway_assertion(&header, secret, GATEWAY_ASSERTION_AUDIENCE, 1020, 5)
                .unwrap(),
            assertion
        );
        // Within clock skew (1035 <= 1030 + 5)
        assert!(
            verify_gateway_assertion(&header, secret, GATEWAY_ASSERTION_AUDIENCE, 1035, 5).is_ok()
        );
        // Past clock skew
        assert_eq!(
            verify_gateway_assertion(&header, secret, GATEWAY_ASSERTION_AUDIENCE, 1036, 5),
            Err(TokenError::Expired)
        );
        // Audience mismatch
        assert_eq!(
            verify_gateway_assertion(&header, secret, "other-service", 1020, 5),
            Err(TokenError::AudienceMismatch)
        );
        // Tamper rejection
        let tampered = header.replacen('a', "b", 1);
        assert!(verify_gateway_assertion(&tampered, secret, GATEWAY_ASSERTION_AUDIENCE, 1020, 5).is_err());

        // Cross-protocol rejection: gateway assertion cannot verify as v2 session or media cap
        assert!(verify_session_v2(&header, secret, 1020).is_err());
        assert!(verify_media_capability(&header, secret, MediaCapKind::Image, 1, 1020, 0).is_err());

        // Privileged header stripping helper
        assert!(is_privileged_request_header("X-Gateway-Assertion"));
        assert!(is_privileged_request_header("x-policy-min-revision"));
        assert!(is_privileged_request_header("CF-Access-Jwt-Assertion"));
        assert!(is_privileged_request_header("X-Gallery-Admin-Email"));
        assert!(!is_privileged_request_header("Accept"));
        assert!(!is_privileged_request_header("Cookie"));
    }

    #[test]
    fn media_capability_checks_target_expiry_min_enforce_rev_and_billing_key() {
        let secret = b"media-cap-secret";
        let cap = MediaCapability {
            v: MEDIA_CAP_VERSION,
            kind: MediaCapKind::Image,
            id: 42,
            path: "2026/01/photo_42.webp".to_string(),
            rev: 10,
            sub: "user-42".to_string(),
            sid: Some("sid-42".to_string()),
            req_switchers: vec!["r18".to_string()],
            exp: 5000,
        };
        let tok = sign_media_capability(&cap, secret).expect("sign cap");

        assert_eq!(
            verify_media_capability(&tok, secret, MediaCapKind::Image, 42, 4999, 10).unwrap(),
            cap
        );
        assert_eq!(
            verify_media_capability(&tok, secret, MediaCapKind::Image, 42, 5000, 10).unwrap(),
            cap
        );
        // Expired
        assert_eq!(
            verify_media_capability(&tok, secret, MediaCapKind::Image, 42, 5001, 10),
            Err(TokenError::Expired)
        );
        // Wrong id or kind
        assert_eq!(
            verify_media_capability(&tok, secret, MediaCapKind::Image, 43, 4500, 10),
            Err(TokenError::TargetMismatch)
        );
        assert_eq!(
            verify_media_capability(&tok, secret, MediaCapKind::Preview, 42, 4500, 10),
            Err(TokenError::TargetMismatch)
        );
        // min_enforce_rev tightening invalidates older caps immediately
        assert_eq!(
            verify_media_capability(&tok, secret, MediaCapKind::Image, 42, 4500, 11),
            Err(TokenError::PolicyRevisionStale {
                token_rev: 10,
                min_enforce_rev: 11,
            })
        );

        // Path traversal rejected
        let bad_path = MediaCapability {
            path: "../secret.webp".to_string(),
            ..cap.clone()
        };
        assert!(sign_media_capability(&bad_path, secret).is_err());

        // Anon capability cannot carry required switchers
        let bad_anon = MediaCapability {
            sub: MEDIA_CAP_ANON_SUB.to_string(),
            sid: None,
            req_switchers: vec!["r18".to_string()],
            ..cap.clone()
        };
        assert!(sign_media_capability(&bad_anon, secret).is_err());

        // Canonical billing keys separate clear views from previews
        let img_key = cap.billing_key().expect("image is billable");
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
    fn strict_age_verification_allows_only_oidc_age_assurance() {
        for provider in AuthProviderId::ALL {
            if provider == AuthProviderId::OidcAgeAssurance {
                assert!(provider.supports_strict_age_verification());
                assert!(provider.is_allowed_under(AgeVerificationPolicy::StrictProviderVerified18));
            } else {
                assert!(
                    !provider.supports_strict_age_verification(),
                    "{provider:?} must NOT satisfy strict 18+ verification"
                );
                assert!(
                    !provider.is_allowed_under(AgeVerificationPolicy::StrictProviderVerified18)
                );
            }
        }
        assert!(!AuthProviderId::Google.supports_strict_age_verification());
    }

    #[test]
    fn policy_digest_is_deterministic_and_secret_free() {
        let mut p1 = PublicSitePolicy {
            revision: 3,
            min_enforce_rev: 2,
            safety_enabled: true,
            rules: builtin_safety_presets(),
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

        // Roundtrip via JSON must yield identical digest
        let json = serde_json::to_string(&p1).unwrap();
        let p2: PublicSitePolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(compute_policy_digest(&p2), d1);

        // Digest of canonical_policy_json raw bytes must match compute_policy_digest
        let canonical = canonical_policy_json(&p1);
        let raw_digest = legal::hex_lower(&<Sha256 as sha2::Digest>::digest(canonical.as_bytes()));
        assert_eq!(raw_digest, d1);

        // Changing any policy field changes the digest
        p1.min_enforce_rev = 3;
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
    fn default_policy_starts_disabled_and_legal_templates_are_populated() {
        let p = PublicSitePolicy::default();
        assert!(!p.safety_enabled);
        assert!(p.rules.is_empty());
        assert_eq!(p.unclassified_mode, UnclassifiedMode::LockFailClosed);
        assert_eq!(p.age_policy, AgeVerificationPolicy::Off);
        assert_eq!(p.age_gate_trigger, AgeGateTrigger::Off);
        assert_eq!(p.panic_shortcut, "Shift+S");
        assert!(p.legal.terms_md.contains("Terms of Service"));
        assert!(p.legal.privacy_md.contains("Privacy Policy"));
        assert!(p.legal.dmca_md.contains("DMCA"));
        assert!(p.legal.content_policy_md.contains("Content Policy"));
        assert_eq!(p.legal.terms_digest.len(), 64);
    }

    #[test]
    fn media_capability_rejects_percent_encoding_scheme_colon_and_whitespace_traps() {
        let secret = b"media-cap-secret";
        let base = MediaCapability {
            v: MEDIA_CAP_VERSION,
            kind: MediaCapKind::Image,
            id: 42,
            path: "2026/01/ok.webp".to_string(),
            rev: 1,
            sub: "user-1".to_string(),
            sid: Some("sid-1".to_string()),
            req_switchers: vec!["r18".to_string()],
            exp: 5000,
        };

        let oversized_path = format!("{}.webp", "a".repeat(1025));
        let bad_paths = [
            "%2e%2e/secret.webp",
            "%2E%2E/secret.webp",
            ".%2e/secret.webp",
            "..%2fsecret.webp",
            "a%5c..%5cb",
            "img%00.webp",
            "img%3fx=1",
            "img%23frag",
            "%252e%252e/x",
            "bad%2",
            "http:evil.com/x.webp",
            "https://evil.com/x.webp",
            " 2026/ok.webp",
            "2026/ok.webp ",
            "2026//ok.webp",
            "2026/ok\x00.webp",
            oversized_path.as_str(),
        ];

        for bad in bad_paths {
            let cap = MediaCapability {
                path: bad.to_string(),
                ..base.clone()
            };
            assert!(
                sign_media_capability(&cap, secret).is_err(),
                "sign must reject unsafe path: {bad:?}"
            );

            // Also verify that even a manually HMAC-signed payload with an unsafe path is rejected on verify!
            let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&cap).unwrap());
            let mut m = Hmac::<Sha256>::new_from_slice(secret).unwrap();
            m.update(b"media-cap/v1\0");
            m.update(payload.as_bytes());
            let forged = format!(
                "{payload}.{}",
                URL_SAFE_NO_PAD.encode(m.finalize().into_bytes())
            );
            assert!(
                verify_media_capability(&forged, secret, MediaCapKind::Image, 42, 4000, 1)
                    .is_err(),
                "verify must reject unsafe path: {bad:?}"
            );
        }

        // Padded " anon " must NOT bypass anon switcher check
        let padded_anon = MediaCapability {
            sub: " anon ".to_string(),
            sid: None,
            req_switchers: vec!["r18".to_string()],
            ..base.clone()
        };
        assert!(sign_media_capability(&padded_anon, secret).is_err());

        // Empty / padded / control-char switchers rejected
        for bad_sw in ["", " ", " r18", "r18 ", "r18\n"] {
            let cap = MediaCapability {
                req_switchers: vec![bad_sw.to_string()],
                ..base.clone()
            };
            assert!(sign_media_capability(&cap, secret).is_err());
        }
    }

    #[test]
    fn rejects_empty_secrets_far_future_assertions_safe_mode_switchers_and_dirty_claims() {
        let secret = b"real-secret";
        let valid_v2 = SessionV2Claims {
            v: SESSION_V2_VERSION,
            sub: "usr-123".to_string(),
            do_key: "usr:550e8400-e29b-41d4-a716-446655440000".to_string(),
            sid: "sid-123".to_string(),
            iat: 1000,
            exp: 2000,
        };
        assert!(sign_session_v2(&valid_v2, b"").is_err());
        let tok_v2 = sign_session_v2(&valid_v2, secret).unwrap();
        assert!(verify_session_v2(&tok_v2, b"", 1500).is_err());

        // Leading/trailing whitespace & control chars in SessionV2Claims rejected
        assert!(
            sign_session_v2(
                &SessionV2Claims {
                    sub: " usr-123 ".to_string(),
                    ..valid_v2.clone()
                },
                secret
            )
            .is_err()
        );
        assert!(
            sign_session_v2(
                &SessionV2Claims {
                    sid: "sid\x001".to_string(),
                    ..valid_v2.clone()
                },
                secret
            )
            .is_err()
        );

        // Legacy session empty secret rejected
        let valid_legacy = LegacySessionClaims {
            sub: ETH_ADDR.to_string(),
            iat: 1000,
            exp: 2000,
        };
        assert!(sign_legacy_session(&valid_legacy, b"").is_err());
        let tok_legacy = sign_legacy_session(&valid_legacy, secret).unwrap();
        assert!(verify_legacy_session(&tok_legacy, b"", 1500).is_err());

        // valid_admin_view rejects empty secret
        let pass = admin_view_pass(b"", 600);
        assert!(!valid_admin_view(b"", &pass, 500));

        // GatewayAssertion: empty secret, safe_mode + non-empty switchers, far-future exp
        let base_assertion = GatewayAssertion {
            v: GATEWAY_ASSERTION_VERSION,
            aud: GATEWAY_ASSERTION_AUDIENCE.to_string(),
            rev: 1,
            min_enforce_rev: 1,
            policy_digest: SAMPLE_DIGEST.to_string(),
            sub: Some("user-1".to_string()),
            sid: Some("sid-1".to_string()),
            switchers: vec!["r18".to_string()],
            safe_mode: false,
            is_admin_view: false,
            exp: 1030,
        };
        assert!(sign_gateway_assertion(&base_assertion, b"").is_err());

        let bad_safe_mode = GatewayAssertion {
            safe_mode: true,
            ..base_assertion.clone()
        };
        assert!(sign_gateway_assertion(&bad_safe_mode, secret).is_err());

        let dirty_sw = GatewayAssertion {
            switchers: vec![" r18 ".to_string()],
            ..base_assertion.clone()
        };
        assert!(sign_gateway_assertion(&dirty_sw, secret).is_err());

        // Far-future exp exceeds now + GATEWAY_ASSERTION_TTL + max_skew
        let far_future = GatewayAssertion {
            exp: 1000 + GATEWAY_ASSERTION_TTL + 5 + 1,
            ..base_assertion.clone()
        };
        let far_hdr = sign_gateway_assertion(&far_future, secret).unwrap();
        assert!(
            verify_gateway_assertion(&far_hdr, secret, GATEWAY_ASSERTION_AUDIENCE, 1000, 5)
                .is_err()
        );
        // At exact boundary (now + TTL + max_skew) succeeds
        let boundary = GatewayAssertion {
            exp: 1000 + GATEWAY_ASSERTION_TTL + 5,
            ..base_assertion
        };
        let boundary_hdr = sign_gateway_assertion(&boundary, secret).unwrap();
        assert!(
            verify_gateway_assertion(&boundary_hdr, secret, GATEWAY_ASSERTION_AUDIENCE, 1000, 5)
                .is_ok()
        );
    }
}
