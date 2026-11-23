//! Host unit tests covering every security invariant of `admin_dashboard_worker`:
//! - AES-256-GCM encryption/decryption, fresh nonces, AAD tampering rejection, key rotation, redacted Debug
//! - Strict Provider-Verified 18+ rejecting Google/GitHub/X/Discord/Email/Telegram/SIWE/SIWS
//! - OIDC SSRF URL validation (HTTPS-only, no IP literals, no localhost/private domains, no userinfo/non-443)
//! - Monotonic `min_enforce_rev` tightening detection (safety/age/terms/geo vs relaxing edits)
//! - Zero-bypass admin-binding guard, CSRF verification (`Origin`, `Sec-Fetch-Site`, `X-Admin-CSRF: 1`), security headers
//! - Safety rule validation rejecting vector operators (`clip:`, `dino:`, `upload:`), regexes, bare text, and out-of-range scores
//! - Access policy deposit address & free media folder validation, ISO-3166 geo normalization

use axum::http::{HeaderMap, HeaderValue, header};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use site_access::{
    ADMIN_CSRF_HEADER, ADMIN_HEADER, AgeGateTrigger, AgeVerificationPolicy, AuthProviderId,
    AuthProviderPublicConfig, GeoPolicy, LegalDocConfig, PlaceholderPreset, PublicSitePolicy,
    RuleMode, SafetyRuleConfig, SimilarityDefaults, UnclassifiedMode, builtin_safety_presets,
};

use crate::{
    api::{ProviderUpdateItem, SaveSafetyReq},
    crypto::{CryptoError, KeyRing, SecretKey},
    security::{
        ADMIN_CACHE_CONTROL, ADMIN_CSP, ADMIN_ROBOTS_TAG, apply_security_headers,
        map_admin_asset_path, require_admin_identity, validate_and_normalize_geo,
        validate_oidc_url, verify_admin_mutation,
    },
    settings::{
        AccessPolicy, ChainKind, SiteSettingsDocument, compute_next_min_enforce_rev,
        did_policy_tighten, prepare_safety_update, valid_deposit_address,
        validate_provider_updates,
    },
};

fn sample_key_hex(byte: u8) -> String {
    hex::encode([byte; 32])
}

fn sample_key_b64(byte: u8) -> String {
    STANDARD.encode([byte; 32])
}

// ---------------------------------------------------------------------------
// 1. AES-256-GCM Encryption, AAD Binding & Key Rotation (M3)
// ---------------------------------------------------------------------------

#[test]
fn aes_gcm_encrypt_decrypt_roundtrip_and_unique_nonces() {
    let ring = KeyRing::from_env_strings(&sample_key_b64(0x11), None).expect("parse base64 key");
    let plaintext = b"super-secret-oauth-client-secret";

    let e1 = ring
        .encrypt("prod-1", "google", "client_secret", plaintext)
        .expect("encrypt 1");
    let e2 = ring
        .encrypt("prod-1", "google", "client_secret", plaintext)
        .expect("encrypt 2");

    // Fresh CSPRNG 96-bit nonce on every write
    assert_eq!(e1.nonce.len(), 12);
    assert_ne!(e1.nonce, e2.nonce);
    assert_ne!(e1.ciphertext, e2.ciphertext);
    assert_eq!(e1.kid, ring.current.kid());
    assert!(e1.kid.starts_with("k1:"));

    // Decrypt succeeds with matching AAD
    let pt1 = ring
        .decrypt(
            "prod-1",
            "google",
            "client_secret",
            &e1.kid,
            &e1.nonce,
            &e1.ciphertext,
        )
        .expect("decrypt 1");
    assert_eq!(pt1, plaintext);

    // Debug output NEVER leaks key bytes or secret values
    let key_dbg = format!("{:?}", ring.current);
    assert!(key_dbg.contains("[REDACTED]"));
    assert!(!key_dbg.contains("11111111"));
}

#[test]
fn aes_gcm_rejects_aad_tamper_ciphertext_tamper_and_wrong_key() {
    let ring = KeyRing::from_env_strings(&sample_key_hex(0x22), None).expect("parse hex key");
    let enc = ring
        .encrypt("prod-1", "oidc_age_assurance", "client_secret", b"top-secret")
        .expect("encrypt");

    // Wrong deployment_id -> AAD mismatch
    assert_eq!(
        ring.decrypt(
            "staging-1",
            "oidc_age_assurance",
            "client_secret",
            &enc.kid,
            &enc.nonce,
            &enc.ciphertext
        ),
        Err(CryptoError::DecryptionFailed)
    );
    // Wrong provider_id -> AAD mismatch (prevents cross-provider ciphertext transplant)
    assert_eq!(
        ring.decrypt(
            "prod-1",
            "google",
            "client_secret",
            &enc.kid,
            &enc.nonce,
            &enc.ciphertext
        ),
        Err(CryptoError::DecryptionFailed)
    );
    // Wrong field_name -> AAD mismatch
    assert_eq!(
        ring.decrypt(
            "prod-1",
            "oidc_age_assurance",
            "bot_token",
            &enc.kid,
            &enc.nonce,
            &enc.ciphertext
        ),
        Err(CryptoError::DecryptionFailed)
    );

    // Tampered ciphertext byte fails GCM tag check
    let mut bad_ct = enc.ciphertext.clone();
    bad_ct[0] ^= 0xff;
    assert_eq!(
        ring.decrypt(
            "prod-1",
            "oidc_age_assurance",
            "client_secret",
            &enc.kid,
            &enc.nonce,
            &bad_ct
        ),
        Err(CryptoError::DecryptionFailed)
    );

    // Tampered nonce fails GCM tag check
    let mut bad_nonce = enc.nonce;
    bad_nonce[0] ^= 0x01;
    assert_eq!(
        ring.decrypt(
            "prod-1",
            "oidc_age_assurance",
            "client_secret",
            &enc.kid,
            &bad_nonce,
            &enc.ciphertext
        ),
        Err(CryptoError::DecryptionFailed)
    );

    // Unrelated key fails closed
    let other_ring = KeyRing::from_env_strings(&sample_key_hex(0x99), None).unwrap();
    assert_eq!(
        other_ring.decrypt(
            "prod-1",
            "oidc_age_assurance",
            "client_secret",
            &enc.kid,
            &enc.nonce,
            &enc.ciphertext
        ),
        Err(CryptoError::DecryptionFailed)
    );

    // Rejects AAD delimiter injection and malformed keys
    assert!(ring.encrypt("prod|evil", "google", "client_secret", b"x").is_err());
    assert!(SecretKey::parse("too-short").is_err());
    assert!(SecretKey::parse("").is_err());
}

#[test]
fn aes_gcm_zero_downtime_key_rotation_from_prev_to_current() {
    let old_ring = KeyRing::from_env_strings(&sample_key_hex(0x33), None).unwrap();
    let enc_old = old_ring
        .encrypt("prod-1", "telegram", "bot_token", b"123456:ABCDEF")
        .expect("encrypt with old key");

    // Deploy new key as current + old key as SETTINGS_ENCRYPTION_KEY_PREV
    let rot_ring =
        KeyRing::from_env_strings(&sample_key_b64(0x44), Some(&sample_key_hex(0x33))).unwrap();
    assert!(rot_ring.has_previous());
    assert_ne!(rot_ring.current.kid(), enc_old.kid);

    // Existing ciphertext decrypts seamlessly via previous key
    let pt = rot_ring
        .decrypt(
            "prod-1",
            "telegram",
            "bot_token",
            &enc_old.kid,
            &enc_old.nonce,
            &enc_old.ciphertext,
        )
        .expect("decrypt via prev key");
    assert_eq!(pt, b"123456:ABCDEF");

    // Rotate row to current key with fresh nonce
    let enc_new = rot_ring
        .reencrypt(
            "prod-1",
            "telegram",
            "bot_token",
            &enc_old.kid,
            &enc_old.nonce,
            &enc_old.ciphertext,
        )
        .expect("reencrypt to new key");
    assert_eq!(enc_new.kid, rot_ring.current.kid());
    assert_ne!(enc_new.nonce, enc_old.nonce);

    // After removing SETTINGS_ENCRYPTION_KEY_PREV, rotated row still decrypts cleanly!
    let final_ring = KeyRing::from_env_strings(&sample_key_b64(0x44), None).unwrap();
    let pt_after = final_ring
        .decrypt(
            "prod-1",
            "telegram",
            "bot_token",
            &enc_new.kid,
            &enc_new.nonce,
            &enc_new.ciphertext,
        )
        .expect("decrypt after retiring prev key");
    assert_eq!(pt_after, b"123456:ABCDEF");
}

// ---------------------------------------------------------------------------
// 2. Strict Provider-Verified 18+ Enforcement (H7)
// ---------------------------------------------------------------------------

#[test]
fn strict_18_rejects_enabling_google_github_x_discord_email_telegram_siwe_siws() {
    for provider in AuthProviderId::ALL {
        let item = ProviderUpdateItem {
            id: provider,
            enabled: true,
            display_name: None,
            issuer: if provider == AuthProviderId::OidcAgeAssurance {
                Some("https://age-id.example.com".to_string())
            } else {
                None
            },
            public_client_id: Some("client-123".to_string()),
            soft_birthday_check: false,
            secret_value: None,
            clear_secret: false,
        };
        let res = validate_provider_updates(
            AgeVerificationPolicy::StrictProviderVerified18,
            &[item],
        );
        if provider == AuthProviderId::OidcAgeAssurance {
            assert!(res.is_ok(), "OidcAgeAssurance must be allowed in Strict 18+");
        } else {
            assert!(
                res.is_err(),
                "{provider:?} MUST be rejected when enabled in StrictProviderVerified18 mode"
            );
        }
    }

    // Soft birthday check is disallowed in Strict mode and on non-Google providers
    let google_soft_in_strict = ProviderUpdateItem {
        id: AuthProviderId::Google,
        enabled: false,
        display_name: None,
        issuer: None,
        public_client_id: None,
        soft_birthday_check: true,
        secret_value: None,
        clear_secret: false,
    };
    assert!(
        validate_provider_updates(
            AgeVerificationPolicy::StrictProviderVerified18,
            std::slice::from_ref(&google_soft_in_strict)
        )
        .is_err()
    );
    assert!(
        validate_provider_updates(
            AgeVerificationPolicy::SelfAttestation,
            &[google_soft_in_strict]
        )
        .is_ok()
    );
}

#[test]
fn switching_to_strict_18_auto_disables_non_age_capable_providers() {
    let prev = PublicSitePolicy {
        age_policy: AgeVerificationPolicy::SelfAttestation,
        enabled_providers: vec![
            AuthProviderPublicConfig {
                id: AuthProviderId::OidcAgeAssurance,
                enabled: true,
                display_name: None,
                issuer: Some("https://idv.example.com".into()),
                public_client_id: Some("idv-client".into()),
                soft_birthday_check: false,
            },
            AuthProviderPublicConfig {
                id: AuthProviderId::Google,
                enabled: true,
                display_name: None,
                issuer: None,
                public_client_id: Some("g-client".into()),
                soft_birthday_check: true,
            },
            AuthProviderPublicConfig {
                id: AuthProviderId::GitHub,
                enabled: true,
                display_name: None,
                issuer: None,
                public_client_id: Some("gh-client".into()),
                soft_birthday_check: false,
            },
        ],
        ..PublicSitePolicy::default()
    };

    let req = SaveSafetyReq {
        revision: 1,
        safety_enabled: true,
        rules: vec![],
        unclassified_mode: UnclassifiedMode::LockFailClosed,
        cloudflare_images_blur: false,
        age_policy: AgeVerificationPolicy::StrictProviderVerified18,
        age_gate_trigger: AgeGateTrigger::JustInTime,
        similarity: SimilarityDefaults::default(),
        geo: GeoPolicy::default(),
        legal: prev.legal.clone(),
        panic_shortcut: prev.panic_shortcut.clone(),
    };

    let updated = prepare_safety_update(&prev, &req, 2).expect("valid strict upgrade");
    assert!(updated.tightened);
    assert_eq!(updated.next_policy.min_enforce_rev, 2);
    assert_eq!(
        updated.auto_disabled_providers,
        vec![AuthProviderId::Google, AuthProviderId::GitHub]
    );
    let google = updated
        .next_policy
        .enabled_providers
        .iter()
        .find(|p| p.id == AuthProviderId::Google)
        .unwrap();
    assert!(!google.enabled);
    assert!(!google.soft_birthday_check);
    let oidc = updated
        .next_policy
        .enabled_providers
        .iter()
        .find(|p| p.id == AuthProviderId::OidcAgeAssurance)
        .unwrap();
    assert!(oidc.enabled);
}

// ---------------------------------------------------------------------------
// 3. OIDC SSRF URL Validation (H11)
// ---------------------------------------------------------------------------

#[test]
fn oidc_url_validator_blocks_ssrf_and_accepts_public_https() {
    assert_eq!(
        validate_oidc_url("https://idp.example.com/realms/age/").unwrap(),
        "https://idp.example.com/realms/age"
    );
    assert_eq!(
        validate_oidc_url("https://auth.yoti.com:443").unwrap(),
        "https://auth.yoti.com"
    );

    let rejected = [
        "",
        "http://idp.example.com",
        "javascript:alert(1)",
        "file:///etc/passwd",
        "https://127.0.0.1",
        "https://127.0.0.1/oidc",
        "https://[::1]/oidc",
        "https://169.254.169.254/latest/meta-data",
        "https://10.0.0.1/oidc",
        "https://192.168.1.1/oidc",
        "https://2130706433/oidc",       // decimal IPv4 -> 127.0.0.1
        "https://0x7f000001/oidc",       // hex IPv4 -> 127.0.0.1
        "https://localhost/oidc",
        "https://sub.localhost/oidc",
        "https://metadata.google.internal/computeMetadata",
        "https://auth.internal/oidc",
        "https://service.local/oidc",
        "https://intranet/oidc",         // single-label hostname
        "https://user:pass@idp.example.com",
        "https://idp.example.com:8443/oidc",
        "https://idp.example.com/oidc?foo=bar",
        "https://idp.example.com/oidc#frag",
        "https://idp.example.com/a/../secret",
    ];
    for bad in rejected {
        assert!(
            validate_oidc_url(bad).is_err(),
            "expected SSRF OIDC URL to be rejected: {bad}"
        );
    }
}

// ---------------------------------------------------------------------------
// 4. Tightening Detection & Monotonic min_enforce_rev (H3)
// ---------------------------------------------------------------------------

#[test]
fn min_enforce_rev_bumps_on_tightening_and_stays_monotonic_on_relaxation() {
    let base = PublicSitePolicy {
        revision: 4,
        min_enforce_rev: 2,
        safety_enabled: true,
        rules: vec![SafetyRuleConfig {
            id: "r18".into(),
            name: "NSFW".into(),
            mode: RuleMode::SpoilerBlur,
            query: "tag:explicit".into(),
            default_min_score: 0.5,
            preset: PlaceholderPreset::R18,
            requires_login: false,
            requires_age_18: false,
            enabled: true,
        }],
        unclassified_mode: UnclassifiedMode::Allow,
        cloudflare_images_blur: false,
        age_policy: AgeVerificationPolicy::Off,
        age_gate_trigger: AgeGateTrigger::Off,
        geo: GeoPolicy {
            blocked_countries: vec!["KP".into()],
            block_unknown: false,
            block_tor: false,
        },
        ..PublicSitePolicy::default()
    };

    // Unrelated/relaxing change (renaming rule, raising threshold) does NOT tighten
    let mut relaxed = base.clone();
    relaxed.rules[0].name = "Adult".into();
    relaxed.rules[0].default_min_score = 0.7;
    relaxed.panic_shortcut = "Shift+X".into();
    assert!(!did_policy_tighten(&base, &relaxed));
    assert_eq!(compute_next_min_enforce_rev(&base, &relaxed, 5), (2, false));

    // Tightening 1: SpoilerBlur -> Switcher
    let mut promote = base.clone();
    promote.rules[0].mode = RuleMode::Switcher;
    assert_eq!(compute_next_min_enforce_rev(&base, &promote, 5), (5, true));

    // Tightening 2: lowering default_min_score (matches more items)
    let mut lower_score = base.clone();
    lower_score.rules[0].default_min_score = 0.35;
    assert_eq!(compute_next_min_enforce_rev(&base, &lower_score, 5), (5, true));

    // Tightening 3: Unclassified Allow -> LockFailClosed
    let mut fail_closed = base.clone();
    fail_closed.unclassified_mode = UnclassifiedMode::LockFailClosed;
    assert_eq!(compute_next_min_enforce_rev(&base, &fail_closed, 5), (5, true));

    // Tightening 4: Age policy Off -> SelfAttestation
    let mut age_up = base.clone();
    age_up.age_policy = AgeVerificationPolicy::SelfAttestation;
    assert_eq!(compute_next_min_enforce_rev(&base, &age_up, 5), (5, true));

    // Tightening 5: Adding a country or blocking Tor
    let mut geo_up = base.clone();
    geo_up.geo.blocked_countries.push("IR".into());
    assert_eq!(compute_next_min_enforce_rev(&base, &geo_up, 5), (5, true));

    let mut tor_up = base.clone();
    tor_up.geo.block_tor = true;
    assert_eq!(compute_next_min_enforce_rev(&base, &tor_up, 5), (5, true));

    // Tightening 6: Terms Markdown updated -> auto-bumps terms_version & min_enforce_rev
    let mut new_legal = base.legal.clone();
    new_legal.terms_md.push_str("\n## 6. Updated Clause\n");
    let req = SaveSafetyReq {
        revision: 4,
        safety_enabled: base.safety_enabled,
        rules: base.rules.clone(),
        unclassified_mode: base.unclassified_mode,
        cloudflare_images_blur: base.cloudflare_images_blur,
        age_policy: base.age_policy,
        age_gate_trigger: base.age_gate_trigger,
        similarity: base.similarity,
        geo: base.geo.clone(),
        legal: new_legal,
        panic_shortcut: base.panic_shortcut.clone(),
    };
    let prepared = prepare_safety_update(&base, &req, 5).expect("terms update");
    assert!(prepared.terms_bumped);
    assert!(prepared.tightened);
    assert_eq!(prepared.next_policy.legal.terms_version, 2);
    assert_eq!(prepared.next_policy.min_enforce_rev, 5);
}

// ---------------------------------------------------------------------------
// 5. Rule Validation Rejecting Vector Operators & Bad Thresholds (H4, M2)
// ---------------------------------------------------------------------------

#[test]
fn safety_update_rejects_vector_operators_regex_and_invalid_similarity() {
    let base = PublicSitePolicy::default();
    let mk_req = |query: &str, dinov3_min: f32| SaveSafetyReq {
        revision: 0,
        safety_enabled: true,
        rules: vec![SafetyRuleConfig {
            id: "custom-1".into(),
            name: "Test".into(),
            mode: RuleMode::Switcher,
            query: query.into(),
            default_min_score: 0.5,
            preset: PlaceholderPreset::Custom,
            requires_login: true,
            requires_age_18: false,
            enabled: true,
        }],
        unclassified_mode: UnclassifiedMode::LockFailClosed,
        cloudflare_images_blur: false,
        age_policy: AgeVerificationPolicy::Off,
        age_gate_trigger: AgeGateTrigger::Off,
        similarity: SimilarityDefaults {
            dinov3_min,
            siglip2_min: 0.0,
        },
        geo: GeoPolicy::default(),
        legal: LegalDocConfig::default(),
        panic_shortcut: "Shift+S".into(),
    };

    // Valid metadata rule succeeds
    assert!(prepare_safety_update(&base, &mk_req("tag:explicit>=0.6 OR post_tag:nsfw", 0.4), 1).is_ok());
    // Built-in presets succeed
    let preset_req = SaveSafetyReq {
        rules: builtin_safety_presets(),
        ..mk_req("tag:blood", 0.0)
    };
    assert!(prepare_safety_update(&base, &preset_req, 1).is_ok());

    // Disallowed vector operators, regexes, and bare text rejected
    for bad_query in [
        r#"clip:"explicit""#,
        "dino:12345",
        "upload:0",
        "tag:blood OR clip:gore",
        "tag:/blood.*/",
        "blood",
        "tag:explicit>=1.5",
        "",
    ] {
        assert!(
            prepare_safety_update(&base, &mk_req(bad_query, 0.0), 1).is_err(),
            "expected bad safety query to be rejected: {bad_query}"
        );
    }

    // Invalid similarity thresholds rejected
    assert!(prepare_safety_update(&base, &mk_req("tag:blood", -0.1), 1).is_err());
    assert!(prepare_safety_update(&base, &mk_req("tag:blood", 1.2), 1).is_err());
    assert!(prepare_safety_update(&base, &mk_req("tag:blood", f32::NAN), 1).is_err());
}

// ---------------------------------------------------------------------------
// 6. Zero-Bypass Admin Guard, CSRF, Security Headers & Asset Path Safety (H13)
// ---------------------------------------------------------------------------

#[test]
fn admin_guard_and_csrf_enforce_binding_header_origin_sec_fetch_and_custom_header() {
    let mut headers = HeaderMap::new();
    headers.insert(ADMIN_HEADER, HeaderValue::from_static("admin@example.com"));
    headers.insert(
        header::ORIGIN,
        HeaderValue::from_static("https://gallery.example.com"),
    );
    headers.insert("sec-fetch-site", HeaderValue::from_static("same-origin"));
    headers.insert(ADMIN_CSRF_HEADER, HeaderValue::from_static("1"));

    // Valid binding + headers pass
    assert_eq!(require_admin_identity(true, &headers), Some("admin@example.com"));
    assert_eq!(
        verify_admin_mutation(
            true,
            &headers,
            Some("https://gallery.example.com"),
            "gallery.example.com"
        ),
        Ok("admin@example.com")
    );

    // Missing gallery_admin binding prop ALWAYS fails even with valid ADMIN_HEADER
    assert_eq!(require_admin_identity(false, &headers), None);
    assert!(
        verify_admin_mutation(
            false,
            &headers,
            Some("https://gallery.example.com"),
            "gallery.example.com"
        )
        .is_err()
    );

    // Missing or wrong X-Admin-CSRF fails
    let mut no_csrf = headers.clone();
    no_csrf.remove(ADMIN_CSRF_HEADER);
    assert!(
        verify_admin_mutation(
            true,
            &no_csrf,
            Some("https://gallery.example.com"),
            "gallery.example.com"
        )
        .is_err()
    );

    // Cross-origin Origin fails
    let mut evil_origin = headers.clone();
    evil_origin.insert(header::ORIGIN, HeaderValue::from_static("https://evil.example.com"));
    assert!(
        verify_admin_mutation(
            true,
            &evil_origin,
            Some("https://gallery.example.com"),
            "gallery.example.com"
        )
        .is_err()
    );

    // Null Origin fails
    let mut null_origin = headers.clone();
    null_origin.insert(header::ORIGIN, HeaderValue::from_static("null"));
    assert!(
        verify_admin_mutation(
            true,
            &null_origin,
            Some("https://gallery.example.com"),
            "gallery.example.com"
        )
        .is_err()
    );

    // Cross-site Sec-Fetch-Site fails
    let mut cross_site = headers.clone();
    cross_site.insert("sec-fetch-site", HeaderValue::from_static("cross-site"));
    assert!(
        verify_admin_mutation(
            true,
            &cross_site,
            Some("https://gallery.example.com"),
            "gallery.example.com"
        )
        .is_err()
    );

    // Duplicate security headers rejected (prevents header smuggling)
    let mut dup_origin = headers.clone();
    dup_origin.append(header::ORIGIN, HeaderValue::from_static("https://evil.example.com"));
    assert!(
        verify_admin_mutation(
            true,
            &dup_origin,
            Some("https://gallery.example.com"),
            "gallery.example.com"
        )
        .is_err()
    );
    let mut dup_admin = headers.clone();
    dup_admin.append(ADMIN_HEADER, HeaderValue::from_static("spoof@example.com"));
    assert_eq!(require_admin_identity(true, &dup_admin), None);

    // Local dev http://127.0.0.1:8787 allowed ONLY when configured for localhost/127.0.0.1
    let mut local_headers = headers.clone();
    local_headers.insert(
        header::ORIGIN,
        HeaderValue::from_static("http://127.0.0.1:8787"),
    );
    assert!(
        verify_admin_mutation(
            true,
            &local_headers,
            Some("http://127.0.0.1:8787"),
            "127.0.0.1:8787"
        )
        .is_ok()
    );
    assert!(
        verify_admin_mutation(
            true,
            &local_headers,
            Some("https://gallery.example.com"),
            "gallery.example.com"
        )
        .is_err()
    );

    // Security headers check
    let mut resp_headers = HeaderMap::new();
    apply_security_headers(&mut resp_headers);
    assert_eq!(
        resp_headers.get(header::CACHE_CONTROL).unwrap(),
        ADMIN_CACHE_CONTROL
    );
    assert_eq!(resp_headers.get("x-robots-tag").unwrap(), ADMIN_ROBOTS_TAG);
    assert_eq!(
        resp_headers.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
        "nosniff"
    );
    assert_eq!(resp_headers.get(header::X_FRAME_OPTIONS).unwrap(), "DENY");
    assert_eq!(
        resp_headers.get(header::CONTENT_SECURITY_POLICY).unwrap(),
        ADMIN_CSP
    );

    // Static asset path mapping blocks traversal & percent encoding
    assert_eq!(map_admin_asset_path("/admin"), Some("/index.html".into()));
    assert_eq!(map_admin_asset_path("/admin/"), Some("/index.html".into()));
    assert_eq!(
        map_admin_asset_path("/admin/pkg/admin_web.js"),
        Some("/pkg/admin_web.js".into())
    );
    assert_eq!(map_admin_asset_path("/admin/../secret"), None);
    assert_eq!(map_admin_asset_path("/admin/%2e%2e/secret"), None);
}

// ---------------------------------------------------------------------------
// 7. Flattened site_settings Document Compatibility, Geo & Access Validation
// ---------------------------------------------------------------------------

#[test]
fn flattened_site_settings_document_roundtrips_cleanly_with_zero_secrets() {
    let mut doc = SiteSettingsDocument::default();
    doc.access.login_required = false;
    doc.access.free_media_folders = vec!["/images/sample".into()];
    doc.public.safety_enabled = true;
    doc.public.revision = 3;
    doc.public.min_enforce_rev = 2;

    let json = serde_json::to_string(&doc).expect("serialize flattened doc");
    // Must deserialize cleanly as AccessPolicy, PublicSitePolicy, AND SiteSettingsDocument
    let access_only: AccessPolicy = serde_json::from_str(&json).expect("access parse");
    let public_only: PublicSitePolicy = serde_json::from_str(&json).expect("public parse");
    let full: SiteSettingsDocument = serde_json::from_str(&json).expect("full parse");

    assert_eq!(access_only, doc.access);
    assert_eq!(public_only, doc.public);
    assert_eq!(full, doc);

    // Legacy `{}` row parses with safe defaults
    let legacy: SiteSettingsDocument = serde_json::from_str("{}").expect("legacy empty");
    assert!(legacy.access.login_required);
    assert!(!legacy.public.safety_enabled);
}

#[test]
fn geo_and_deposit_validation_enforce_strict_rules() {
    let geo = validate_and_normalize_geo(&GeoPolicy {
        blocked_countries: vec![" jp ".into(), "US".into(), "jp".into()],
        block_unknown: true,
        block_tor: true,
    })
    .expect("valid geo");
    assert_eq!(geo.blocked_countries, vec!["JP", "US"]);

    assert!(
        validate_and_normalize_geo(&GeoPolicy {
            blocked_countries: vec!["XX".into()],
            ..Default::default()
        })
        .is_err()
    );
    assert!(
        validate_and_normalize_geo(&GeoPolicy {
            blocked_countries: vec!["T1".into()],
            ..Default::default()
        })
        .is_err()
    );
    assert!(
        validate_and_normalize_geo(&GeoPolicy {
            blocked_countries: vec!["USA".into()],
            ..Default::default()
        })
        .is_err()
    );

    assert!(valid_deposit_address(
        ChainKind::Ethereum,
        "0x2222222222222222222222222222222222222222"
    ));
    assert!(!valid_deposit_address(
        ChainKind::Ethereum,
        "0x0000000000000000000000000000000000000000"
    ));
    assert!(!valid_deposit_address(
        ChainKind::Ethereum,
        "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
    ));
    assert!(valid_deposit_address(
        ChainKind::Solana,
        "5tE57EgXH3HTpbtiEQxVzdJeg2NZgGaH2KSSwc7e63DR"
    ));
    assert!(!valid_deposit_address(
        ChainKind::Solana,
        "11111111111111111111111111111111"
    ));
}
