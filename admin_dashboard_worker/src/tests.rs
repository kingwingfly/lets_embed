//! Host unit tests covering every security & Policy v3 invariant of `admin_dashboard_worker`:
//! - HKDF `SITE_SECRET` key derivation & explicit override precedence (`AdminAssertion`, `InternalApi`, `ProviderSecrets`)
//! - `AdminAssertion` v2 (`aa2.`) verification: valid, expired, wrong audience, mismatched email, wrong method,
//!   wrong path+query, wrong body hash, legacy `aa1.`, missing/duplicate headers
//! - Policy v3 validation: `Block + include_click` rejected, `require_age_18 + AgeVerificationPolicy::Off` rejected,
//!   unknown WD-Tagger tag rejected even inside `NOT` and `except_expr`, hundredths precision, limits
//! - Conservative `min_enforce_rev` & `grant_generation` bumps on scope edits vs cosmetic edits
//! - Catalog reference collection (`post_tag:` / `author:`) & per-field validation errors
//! - Two-phase `SitePolicyDO` exact `(revision, policy_digest)` ACK verification
//! - AES-256-GCM encryption/decryption, fresh nonces, AAD tampering rejection, key rotation, redacted Debug
//! - Strict Provider-Verified 18+, OIDC SSRF URL defense, CSRF verification, security headers, geo/access validation

use axum::http::{HeaderMap, HeaderValue, Uri, header};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use search_types::WD_VOCAB_DIGEST;
use site_access::{
    ADMIN_ASSERTION_AUDIENCE, ADMIN_ASSERTION_HEADER, ADMIN_ASSERTION_VERSION, ADMIN_CSRF_HEADER,
    ADMIN_HEADER, AdminAssertionClaims, AgeGateTrigger, AgeVerificationPolicy, AuthProviderId,
    AuthProviderPublicConfig, ContentPolicy, GeoPolicy, KeyDomain, LegalDocConfig,
    PlaceholderPreset, PolicyAction, PolicyBypass, PublicSitePolicy, SITE_POLICY_SCHEMA_VERSION,
    SimilarityDefaults, UnclassifiedMode, builtin_safety_presets, compute_next_min_enforce_rev,
    derive_domain_key_bytes, derive_domain_secret, sha256_hex, sign_admin_assertion,
};

use crate::{
    api::{ProviderUpdateItem, SaveSafetyReq},
    crypto::{CryptoError, KeyRing, SecretKey},
    do_client::verify_do_activation_ack,
    security::{
        ADMIN_CACHE_CONTROL, ADMIN_CSP, ADMIN_ROBOTS_TAG, AdminIdentity, apply_security_headers,
        canonical_request_target, map_admin_asset_path, require_admin_identity,
        resolve_admin_assertion_secret, resolve_internal_api_secret, validate_and_normalize_geo,
        validate_oidc_url, verify_admin_mutation, verify_admin_request,
    },
    settings::{
        AccessPolicy, ChainKind, LEGACY_UPGRADE_REQUIRED_MSG, SiteSettingsDocument,
        build_catalog_field_errors, decode_site_settings_document,
        ensure_v3_ready_for_non_safety_mutation, ensure_v3_ready_for_safety_mutation,
        prepare_safety_update, valid_deposit_address, validate_provider_updates,
    },
};

fn sample_key_hex(byte: u8) -> String {
    hex::encode([byte; 32])
}

fn sample_key_b64(byte: u8) -> String {
    STANDARD.encode([byte; 32])
}

fn sample_policy(id: &str, action: PolicyAction, match_expr: &str, bypass: PolicyBypass) -> ContentPolicy {
    ContentPolicy {
        id: id.to_string(),
        grant_generation: 1,
        enabled: true,
        priority: 10,
        name: format!("Policy {id}"),
        preset: PlaceholderPreset::Custom,
        match_expr: match_expr.to_string(),
        except_expr: None,
        default_tag_min: 0.45,
        action,
        bypass,
    }
}

fn sample_safety_req(policies: Vec<ContentPolicy>) -> SaveSafetyReq {
    SaveSafetyReq {
        revision: 0,
        safety_enabled: true,
        policies,
        unclassified_mode: UnclassifiedMode::Placeholder,
        fixed_blur_enabled: false,
        age_policy: AgeVerificationPolicy::Off,
        age_gate_trigger: AgeGateTrigger::Off,
        similarity: SimilarityDefaults {
            dinov3_min: 0.0,
            siglip2_min: 0.0,
        },
        geo: GeoPolicy::default(),
        legal: LegalDocConfig::default(),
        confirm_policy_v3_migration: true,
    }
}

// ---------------------------------------------------------------------------
// 1. HKDF Master Secret (`SITE_SECRET`) Resolution & Explicit Overrides
// ---------------------------------------------------------------------------

#[test]
fn site_secret_hkdf_resolves_admin_internal_and_provider_keys_with_override_precedence() {
    let master = "super-high-entropy-site-secret-at-least-32-bytes-long!!";

    // AdminAssertion & InternalApi derive distinct 64-hex secrets from SITE_SECRET
    let admin_derived = resolve_admin_assertion_secret(None, Some(master)).expect("derive admin");
    let internal_derived = resolve_internal_api_secret(None, Some(master)).expect("derive internal");
    assert_eq!(
        admin_derived,
        derive_domain_secret(master, KeyDomain::AdminAssertion).into_bytes()
    );
    assert_eq!(
        internal_derived,
        derive_domain_secret(master, KeyDomain::InternalApi)
    );
    assert_ne!(admin_derived, internal_derived.as_bytes());

    // Explicit overrides take precedence over SITE_SECRET
    assert_eq!(
        resolve_admin_assertion_secret(Some(" explicit-admin-key "), Some(master)).unwrap(),
        b"explicit-admin-key"
    );
    assert_eq!(
        resolve_internal_api_secret(Some(" explicit-internal-key "), Some(master)).unwrap(),
        "explicit-internal-key"
    );

    // Missing both fails closed
    assert!(resolve_admin_assertion_secret(None, None).is_err());
    assert!(resolve_admin_assertion_secret(Some("  "), Some("")).is_err());
    assert!(resolve_internal_api_secret(None, None).is_err());

    // ProviderSecrets AES-256-GCM keyring derives from SITE_SECRET and honors overrides
    let ring_hkdf =
        KeyRing::from_resolved_env(None, None, Some(master), None, None, None).expect("hkdf ring");
    let expected_aes = derive_domain_key_bytes(master.as_bytes(), KeyDomain::ProviderSecrets);
    let direct_key = SecretKey::from_bytes(expected_aes);
    assert_eq!(ring_hkdf.current.kid(), direct_key.kid());
    assert!(!ring_hkdf.has_previous());

    // Explicit PROVIDER_SECRETS_KEY beats legacy SETTINGS_ENCRYPTION_KEY and SITE_SECRET
    let explicit_hex = sample_key_hex(0x66);
    let legacy_hex = sample_key_hex(0x55);
    let ring_override = KeyRing::from_resolved_env(
        Some(&format!("prov-v2:{explicit_hex}")),
        Some(&format!("legacy-v1:{legacy_hex}")),
        Some(master),
        None,
        Some(&format!("legacy-v1:{legacy_hex}")),
        None,
    )
    .expect("override ring");
    assert_eq!(ring_override.current.kid(), "prov-v2");
    assert_eq!(ring_override.previous.as_ref().unwrap().kid(), "legacy-v1");

    // Legacy SETTINGS_ENCRYPTION_KEY beats SITE_SECRET when PROVIDER_SECRETS_KEY is absent
    let ring_legacy = KeyRing::from_resolved_env(
        None,
        Some(&format!("legacy-v1:{legacy_hex}")),
        Some(master),
        None,
        None,
        Some(master),
    )
    .expect("legacy override ring");
    assert_eq!(ring_legacy.current.kid(), "legacy-v1");
    assert!(ring_legacy.has_previous());
    assert_eq!(ring_legacy.previous.as_ref().unwrap().kid(), direct_key.kid());

    // Missing all fails closed
    assert!(KeyRing::from_resolved_env(None, None, None, None, None, None).is_err());
}

// ---------------------------------------------------------------------------
// 2. AdminAssertion v2 (`aa2.`) Verification (All Rejection Vectors)
// ---------------------------------------------------------------------------

#[test]
fn admin_assertion_v2_verifies_valid_and_rejects_all_tampered_or_malformed_cases() {
    let secret = resolve_admin_assertion_secret(
        None,
        Some("test-master-site-secret-32-bytes-minimum!!"),
    )
    .unwrap();
    let now = 1_700_000_000u64;
    let body = br#"{"revision":3,"safety_enabled":true}"#;
    let method = "POST";
    let target = "/admin/api/safety?dry_run=0";

    let claims = AdminAssertionClaims {
        v: ADMIN_ASSERTION_VERSION,
        aud: ADMIN_ASSERTION_AUDIENCE.to_string(),
        email: "staff@example.com".to_string(),
        m: method.to_string(),
        p: target.to_string(),
        bh: sha256_hex(body),
        jti: "nonce_abcdef0123456789".to_string(),
        exp: now + 25,
    };
    let signed = sign_admin_assertion(&claims, &secret).expect("sign aa2");
    assert!(signed.starts_with("aa2."));

    let make_headers = |email: &str, tok: &str| {
        let mut h = HeaderMap::new();
        h.insert(ADMIN_HEADER, HeaderValue::from_str(email).unwrap());
        h.insert(ADMIN_ASSERTION_HEADER, HeaderValue::from_str(tok).unwrap());
        h
    };

    // 1. Valid request succeeds even when ctx.props binding is false (Cloudflare [assets] hop)
    let ok = verify_admin_request(
        false,
        Some(&secret),
        &make_headers("staff@example.com", &signed),
        method,
        target,
        body,
        now,
    )
    .expect("valid aa2 assertion");
    assert_eq!(
        ok.identity,
        AdminIdentity {
            email: "staff@example.com".to_string()
        }
    );
    assert_eq!(ok.jti.as_deref(), Some("nonce_abcdef0123456789"));
    assert_eq!(ok.exp, Some(now + 25));

    // 2. Expired token rejected (beyond clock skew)
    assert!(
        verify_admin_request(
            true,
            Some(&secret),
            &make_headers("staff@example.com", &signed),
            method,
            target,
            body,
            now + 60,
        )
        .is_none()
    );

    // 3. Wrong audience rejected
    let wrong_aud_claims = AdminAssertionClaims {
        aud: "wrong-audience".to_string(),
        ..claims.clone()
    };
    let wrong_aud_tok = sign_admin_assertion(&wrong_aud_claims, &secret).unwrap();
    assert!(
        verify_admin_request(
            true,
            Some(&secret),
            &make_headers("staff@example.com", &wrong_aud_tok),
            method,
            target,
            body,
            now,
        )
        .is_none()
    );

    // 4. Mismatched email header vs signed claims rejected
    assert!(
        verify_admin_request(
            true,
            Some(&secret),
            &make_headers("other@example.com", &signed),
            method,
            target,
            body,
            now,
        )
        .is_none()
    );

    // 5. Wrong HTTP method rejected
    assert!(
        verify_admin_request(
            true,
            Some(&secret),
            &make_headers("staff@example.com", &signed),
            "PUT",
            target,
            body,
            now,
        )
        .is_none()
    );

    // 6. Wrong canonical path or query rejected
    assert!(
        verify_admin_request(
            true,
            Some(&secret),
            &make_headers("staff@example.com", &signed),
            method,
            "/admin/api/safety?dry_run=1",
            body,
            now,
        )
        .is_none()
    );
    assert!(
        verify_admin_request(
            true,
            Some(&secret),
            &make_headers("staff@example.com", &signed),
            method,
            "/admin/api/providers",
            body,
            now,
        )
        .is_none()
    );

    // 7. Tampered body hash rejected
    assert!(
        verify_admin_request(
            true,
            Some(&secret),
            &make_headers("staff@example.com", &signed),
            method,
            target,
            br#"{"revision":3,"safety_enabled":false}"#,
            now,
        )
        .is_none()
    );

    // 8. Missing assertion header rejected
    let mut missing_tok = HeaderMap::new();
    missing_tok.insert(ADMIN_HEADER, HeaderValue::from_static("staff@example.com"));
    assert!(
        verify_admin_request(true, Some(&secret), &missing_tok, method, target, body, now)
            .is_none()
    );

    // 9. Duplicate assertion header or duplicate admin email header rejected
    let mut dup_tok = make_headers("staff@example.com", &signed);
    dup_tok.append(ADMIN_ASSERTION_HEADER, HeaderValue::from_str(&signed).unwrap());
    assert!(
        verify_admin_request(true, Some(&secret), &dup_tok, method, target, body, now).is_none()
    );

    let mut dup_email = make_headers("staff@example.com", &signed);
    dup_email.append(ADMIN_HEADER, HeaderValue::from_static("evil@example.com"));
    assert!(
        verify_admin_request(true, Some(&secret), &dup_email, method, target, body, now).is_none()
    );

    // 10. Legacy `aa1.` assertion rejected
    assert!(
        verify_admin_request(
            true,
            Some(&secret),
            &make_headers("staff@example.com", "aa1.e30.sig"),
            method,
            target,
            body,
            now,
        )
        .is_none()
    );

    // Canonical request target helper preserves exact path+query
    let uri: Uri = "/admin/api/accounts?page=2&plan=pro".parse().unwrap();
    assert_eq!(canonical_request_target(&uri), "/admin/api/accounts?page=2&plan=pro");
}

// ---------------------------------------------------------------------------
// 3. Policy v3 Validation, Conservative min_enforce_rev & grant_generation
// ---------------------------------------------------------------------------

#[test]
fn policy_v3_validation_enforces_codex_invariants_and_wd_vocab() {
    let base = PublicSitePolicy::fresh_bootstrap();

    // Built-in presets validate cleanly & stamp schema_version = 3 + WD_VOCAB_DIGEST
    let preset_req = sample_safety_req(builtin_safety_presets());
    let ok = prepare_safety_update(&base, &preset_req, 1).expect("builtin presets valid");
    assert_eq!(ok.next_policy.schema_version, SITE_POLICY_SCHEMA_VERSION);
    assert_eq!(ok.next_policy.vocab_digest, WD_VOCAB_DIGEST);
    assert!(ok.next_policy.verify_policy_digest());

    // 1. Block + include_click MUST be rejected
    let bad_click = sample_safety_req(vec![sample_policy(
        "r18",
        PolicyAction::Block,
        "tag:explicit",
        PolicyBypass {
            include_click: true,
            ..PolicyBypass::default()
        },
    )]);
    assert!(
        prepare_safety_update(&base, &bad_click, 1).is_err(),
        "Block + include_click must be rejected"
    );

    // Blur + include_click succeeds
    let ok_blur_click = sample_safety_req(vec![sample_policy(
        "blur_ok",
        PolicyAction::Blur,
        "tag:sensitive >= 0.50",
        PolicyBypass {
            include_click: true,
            ..PolicyBypass::default()
        },
    )]);
    assert!(prepare_safety_update(&base, &ok_blur_click, 1).is_ok());

    // 2. require_age_18 while age_policy == Off MUST be rejected
    let mut bad_age = sample_safety_req(vec![sample_policy(
        "age_rule",
        PolicyAction::Block,
        "tag:explicit",
        PolicyBypass {
            include_switcher: true,
            require_age_18: true,
            ..PolicyBypass::default()
        },
    )]);
    bad_age.age_policy = AgeVerificationPolicy::Off;
    assert!(
        prepare_safety_update(&base, &bad_age, 1).is_err(),
        "require_age_18 with AgeVerificationPolicy::Off must be rejected"
    );
    bad_age.age_policy = AgeVerificationPolicy::SelfAttestation;
    assert!(prepare_safety_update(&base, &bad_age, 1).is_ok());

    // 3. Unknown WD-Tagger tag typo rejected in match_expr, under NOT, and in except_expr!
    for (expr, except) in [
        ("tag:not_a_real_wd_tag", None),
        ("tag:blood AND NOT tag:typo_under_not_tag", None),
        ("tag:blood", Some("tag:typo_in_except_expr")),
        ("tag:blood", Some("NOT tag:another_fake_wd_tag")),
    ] {
        let mut pol = sample_policy("typo_test", PolicyAction::Block, expr, PolicyBypass::default());
        pol.except_expr = except.map(str::to_string);
        assert!(
            prepare_safety_update(&base, &sample_safety_req(vec![pol]), 1).is_err(),
            "unknown WD tag must be rejected for match={expr:?}, except={except:?}"
        );
    }

    // 4. Vector operators, regexes, bare text, and non-hundredths thresholds rejected
    for bad_query in [
        r#"clip:"explicit""#,
        "dino:12345",
        "upload:0",
        "tag:blood OR clip:gore",
        "tag:/blood.*/",
        "blood",
        "tag:explicit>=1.5",
        "tag:explicit>=0.456",
        "",
    ] {
        let pol = sample_policy("bad_q", PolicyAction::Block, bad_query, PolicyBypass::default());
        assert!(
            prepare_safety_update(&base, &sample_safety_req(vec![pol]), 1).is_err(),
            "bad query must be rejected: {bad_query}"
        );
    }

    // 5. Invalid similarity thresholds rejected
    let mut bad_sim = sample_safety_req(vec![]);
    bad_sim.similarity.dinov3_min = -0.1;
    assert!(prepare_safety_update(&base, &bad_sim, 1).is_err());
    bad_sim.similarity.dinov3_min = 1.2;
    assert!(prepare_safety_update(&base, &bad_sim, 1).is_err());
    bad_sim.similarity.dinov3_min = f32::NAN;
    assert!(prepare_safety_update(&base, &bad_sim, 1).is_err());

    // 6. Catalog refs extracted across BOTH match_expr and except_expr with per-field errors
    let mut cat_pol = sample_policy(
        "custom_cat",
        PolicyAction::Block,
        "tag:blood OR post_tag:nsfw_custom",
        PolicyBypass::default(),
    );
    cat_pol.except_expr = Some("author:trusted_artist AND post_tag:safe_override".into());
    let prepared_cat = prepare_safety_update(&base, &sample_safety_req(vec![cat_pol]), 1)
        .expect("valid syntax with post_tag & author");
    assert_eq!(
        prepared_cat.all_post_tags,
        vec!["nsfw_custom".to_string(), "safe_override".to_string()]
    );
    assert_eq!(prepared_cat.all_authors, vec!["trusted_artist".to_string()]);

    let field_errs = build_catalog_field_errors(
        &prepared_cat.field_refs,
        &["nsfw_custom".to_string()],
        &["trusted_artist".to_string()],
    );
    assert_eq!(field_errs.len(), 2);
    assert_eq!(field_errs[0].policy_id.as_deref(), Some("custom_cat"));
    assert_eq!(field_errs[0].field, "match_expr");
    assert!(field_errs[0].message.contains("nsfw_custom"));
    assert_eq!(field_errs[1].policy_id.as_deref(), Some("custom_cat"));
    assert_eq!(field_errs[1].field, "except_expr");
    assert!(field_errs[1].message.contains("trusted_artist"));
}

#[test]
fn conservative_min_enforce_rev_and_grant_generation_bumps() {
    let mut base = PublicSitePolicy {
        schema_version: SITE_POLICY_SCHEMA_VERSION,
        revision: 4,
        min_enforce_rev: 2,
        safety_enabled: true,
        unclassified_mode: UnclassifiedMode::Continue,
        fixed_blur_enabled: false,
        policies: vec![ContentPolicy {
            id: "r18".into(),
            grant_generation: 1,
            enabled: true,
            priority: 10,
            name: "NSFW".into(),
            preset: PlaceholderPreset::R18,
            match_expr: "tag:explicit".into(),
            except_expr: None,
            default_tag_min: 0.45,
            action: PolicyAction::Blur,
            bypass: PolicyBypass {
                include_switcher: true,
                include_click: true,
                include_live_admin: false,
                require_gallery_login: false,
                require_age_18: false,
                require_current_terms: false,
                exclude_anonymous: false,
                exclude_countries: vec![],
            },
        }],
        age_policy: AgeVerificationPolicy::Off,
        age_gate_trigger: AgeGateTrigger::Off,
        geo: GeoPolicy {
            blocked_countries: vec!["KP".into()],
            block_unknown: false,
            block_tor: false,
        },
        ..PublicSitePolicy::fresh_bootstrap()
    };
    base.refresh_policy_digest();

    // Purely cosmetic edit (display name, preset icon, similarity defaults) keeps min_enforce_rev & grant_generation
    let mut cosmetic_req = SaveSafetyReq {
        revision: 4,
        safety_enabled: base.safety_enabled,
        policies: base.policies.clone(),
        unclassified_mode: base.unclassified_mode,
        fixed_blur_enabled: base.fixed_blur_enabled,
        age_policy: base.age_policy,
        age_gate_trigger: base.age_gate_trigger,
        similarity: SimilarityDefaults {
            dinov3_min: 0.35,
            siglip2_min: 0.25,
        },
        geo: base.geo.clone(),
        legal: base.legal.clone(),
        confirm_policy_v3_migration: true,
    };
    cosmetic_req.policies[0].name = "Adult Content".into();
    cosmetic_req.policies[0].preset = PlaceholderPreset::Custom;
    let cosmetic = prepare_safety_update(&base, &cosmetic_req, 5).expect("cosmetic update");
    assert!(!cosmetic.tightened);
    assert_eq!(cosmetic.next_policy.min_enforce_rev, 2);
    assert_eq!(cosmetic.next_policy.policies[0].grant_generation, 1);

    // Conservative Policy v3: RAISING default_tag_min ALSO bumps min_enforce_rev AND grant_generation
    // (because raising a threshold can widen `NOT tag:...` blocks!)
    let mut raise_min_req = cosmetic_req.clone();
    raise_min_req.policies[0].default_tag_min = 0.70;
    let raised = prepare_safety_update(&base, &raise_min_req, 5).expect("raise threshold");
    assert!(raised.tightened);
    assert_eq!(raised.next_policy.min_enforce_rev, 5);
    assert_eq!(raised.next_policy.policies[0].grant_generation, 2);

    // Adding except_expr bumps BOTH min_enforce_rev and grant_generation
    let mut except_req = cosmetic_req.clone();
    except_req.policies[0].except_expr = Some("tag:general".into());
    let with_except = prepare_safety_update(&base, &except_req, 5).expect("add except");
    assert!(with_except.tightened);
    assert_eq!(with_except.next_policy.min_enforce_rev, 5);
    assert_eq!(with_except.next_policy.policies[0].grant_generation, 2);

    // Promoting Blur -> Block bumps BOTH min_enforce_rev and grant_generation
    let mut block_req = cosmetic_req.clone();
    block_req.policies[0].action = PolicyAction::Block;
    block_req.policies[0].bypass.include_click = false;
    let promoted = prepare_safety_update(&base, &block_req, 5).expect("promote to block");
    assert!(promoted.tightened);
    assert_eq!(promoted.next_policy.min_enforce_rev, 5);
    assert_eq!(promoted.next_policy.policies[0].grant_generation, 2);

    // Updating Terms Markdown auto-bumps terms_version & min_enforce_rev
    let mut terms_req = cosmetic_req.clone();
    terms_req.legal.terms_md.push_str("\n## 6. Updated Clause\n");
    let terms_upd = prepare_safety_update(&base, &terms_req, 5).expect("terms update");
    assert!(terms_upd.terms_bumped);
    assert!(terms_upd.tightened);
    assert_eq!(terms_upd.next_policy.legal.terms_version, 2);
    assert_eq!(terms_upd.next_policy.min_enforce_rev, 5);

    // Direct site_access compute_next_min_enforce_rev sanity check
    let mut toggled_blur = base.clone();
    toggled_blur.fixed_blur_enabled = true;
    assert_eq!(compute_next_min_enforce_rev(&base, &toggled_blur, 5), (5, true));
}

// ---------------------------------------------------------------------------
// 4. Two-Phase SitePolicyDO ACK Verification
// ---------------------------------------------------------------------------

#[test]
fn do_activation_ack_requires_exact_revision_and_policy_digest() {
    let digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    // Compact v3 ACK shape succeeds
    let compact = format!(r#"{{"ok":true,"revision":7,"policy_digest":"{digest}"}}"#);
    let ack1 = verify_do_activation_ack(&compact, 7, digest).expect("compact ack");
    assert_eq!(ack1.revision, 7);
    assert_eq!(ack1.policy_digest, digest);

    // Envelope ACK shape succeeds
    let envelope = format!(
        r#"{{"policy":{{"revision":7,"policy_digest":"{digest}"}},"digest":"{digest}"}}"#
    );
    let ack2 = verify_do_activation_ack(&envelope, 7, digest).expect("envelope ack");
    assert_eq!(ack2.revision, 7);

    // Rejects ok=false, wrong revision, wrong digest, missing fields, malformed JSON
    assert!(verify_do_activation_ack(
        &format!(r#"{{"ok":false,"revision":7,"policy_digest":"{digest}"}}"#),
        7,
        digest
    )
    .is_err());
    assert!(verify_do_activation_ack(
        &format!(r#"{{"ok":true,"revision":6,"policy_digest":"{digest}"}}"#),
        7,
        digest
    )
    .is_err());
    assert!(verify_do_activation_ack(
        &format!(r#"{{"ok":true,"revision":7,"policy_digest":"{}"}}"#, "f".repeat(64)),
        7,
        digest
    )
    .is_err());
    assert!(verify_do_activation_ack(r#"{"ok":true}"#, 7, digest).is_err());
    assert!(verify_do_activation_ack("not-json", 7, digest).is_err());
}

// ---------------------------------------------------------------------------
// 5. AES-256-GCM Encryption, AAD Binding & Key Rotation (M3)
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

    assert_eq!(e1.nonce.len(), 12);
    assert_ne!(e1.nonce, e2.nonce);
    assert_ne!(e1.ciphertext, e2.ciphertext);
    assert_eq!(e1.kid, ring.current.kid());
    assert!(e1.kid.starts_with("k1:"));

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

    let rot_ring =
        KeyRing::from_env_strings(&sample_key_b64(0x44), Some(&sample_key_hex(0x33))).unwrap();
    assert!(rot_ring.has_previous());
    assert_ne!(rot_ring.current.kid(), enc_old.kid);

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
// 6. Strict Provider-Verified 18+ Enforcement & OIDC SSRF Validation
// ---------------------------------------------------------------------------

#[test]
fn strict_18_rejects_non_age_capable_providers_and_auto_disables_on_upgrade() {
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
            assert!(res.is_ok());
        } else {
            assert!(res.is_err());
        }
    }

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
        ..PublicSitePolicy::fresh_bootstrap()
    };

    let mut req = sample_safety_req(vec![]);
    req.revision = 1;
    req.age_policy = AgeVerificationPolicy::StrictProviderVerified18;
    req.age_gate_trigger = AgeGateTrigger::JustInTime;
    req.legal = prev.legal.clone();

    let updated = prepare_safety_update(&prev, &req, 2).expect("valid strict upgrade");
    assert!(updated.tightened);
    assert_eq!(updated.next_policy.min_enforce_rev, 2);
    assert_eq!(
        updated.auto_disabled_providers,
        vec![AuthProviderId::Google, AuthProviderId::GitHub]
    );
}

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

    for bad in [
        "",
        "http://idp.example.com",
        "javascript:alert(1)",
        "file:///etc/passwd",
        "https://127.0.0.1",
        "https://[::1]/oidc",
        "https://169.254.169.254/latest/meta-data",
        "https://localhost/oidc",
        "https://metadata.google.internal/computeMetadata",
        "https://auth.internal/oidc",
        "https://intranet/oidc",
        "https://user:pass@idp.example.com",
        "https://idp.example.com:8443/oidc",
        "https://idp.example.com/oidc?foo=bar",
        "https://idp.example.com/a/../secret",
        "https://idp.example.com/%2e%2e/secret",
    ] {
        assert!(
            validate_oidc_url(bad).is_err(),
            "expected SSRF OIDC URL to be rejected: {bad}"
        );
    }
}

// ---------------------------------------------------------------------------
// 7. CSRF, Security Headers, Asset Paths, Geo, Access & Legacy Decode
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

    assert_eq!(require_admin_identity(true, &headers), Some("admin@example.com"));
    assert_eq!(
        verify_admin_mutation(
            true,
            &headers,
            None,
            Some("https://gallery.example.com"),
            "gallery.example.com"
        ),
        Ok("admin@example.com")
    );

    // Split-host ADMIN_DOMAIN rejects gallery origin
    assert!(
        verify_admin_mutation(
            true,
            &headers,
            Some("admin.example.com"),
            Some("https://gallery.example.com"),
            "gallery.example.com"
        )
        .is_err()
    );

    // Missing CSRF or cross-origin fails
    let mut no_csrf = headers.clone();
    no_csrf.remove(ADMIN_CSRF_HEADER);
    assert!(
        verify_admin_mutation(
            true,
            &no_csrf,
            None,
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
    assert_eq!(
        map_admin_asset_path("/admin/pkg/admin_web.js"),
        Some("/pkg/admin_web.js".into())
    );
    assert_eq!(map_admin_asset_path("/admin/../secret"), None);
    assert_eq!(map_admin_asset_path("/admin/%2e%2e/secret"), None);
}

#[test]
fn flattened_site_settings_v3_roundtrips_and_validates_geo_and_access() {
    let mut doc = SiteSettingsDocument::default();
    doc.access.login_required = false;
    doc.access.free_media_folders = vec!["/images/sample".into()];
    doc.public.safety_enabled = true;
    doc.public.revision = 3;
    doc.public.min_enforce_rev = 2;
    doc.public.policies = builtin_safety_presets();
    doc.public.refresh_policy_digest();

    let json = serde_json::to_string(&doc).expect("serialize flattened doc");
    let (decoded, notice) =
        decode_site_settings_document(3, &json, SiteSettingsDocument::default()).expect("decode v3");
    assert!(notice.is_none());
    assert_eq!(decoded.public.schema_version, SITE_POLICY_SCHEMA_VERSION);
    assert_eq!(decoded.public.policies.len(), 3);
    assert!(!decoded.access.login_required);

    // Legacy pre-v3 row decodes cleanly with upgrade notice
    let legacy_json = r#"{"login_required":false,"safety_enabled":true,"rules":[]}"#;
    let (legacy_doc, legacy_notice) =
        decode_site_settings_document(2, legacy_json, SiteSettingsDocument::default())
            .expect("decode legacy");
    assert!(legacy_notice.is_some());
    assert_eq!(legacy_doc.public.schema_version, SITE_POLICY_SCHEMA_VERSION);
    assert!(!legacy_doc.access.login_required);

    // Geo normalization
    let geo = validate_and_normalize_geo(&GeoPolicy {
        blocked_countries: vec![" jp ".into(), "US".into(), "jp".into()],
        block_unknown: true,
        block_tor: false,
    })
    .expect("valid geo");
    assert_eq!(geo.blocked_countries, vec!["JP", "US"]);
    assert!(validate_and_normalize_geo(&GeoPolicy {
        blocked_countries: vec!["XX".into()],
        ..GeoPolicy::default()
    })
    .is_err());

    // Access policy validation
    let valid_access = AccessPolicy {
        free_media_folders: vec!["/images/free/".into(), "/videos/demo".into()],
        ..AccessPolicy::default()
    }
    .validate_and_normalize()
    .expect("valid access");
    assert_eq!(
        valid_access.free_media_folders,
        vec!["/images/free", "/videos/demo"]
    );
    assert!(!valid_deposit_address(
        ChainKind::Ethereum,
        "0x0000000000000000000000000000000000000000"
    ));
}

#[test]
fn legacy_pre_v3_row_rejects_non_safety_mutations_and_unconfirmed_safety_saves() {
    // Legacy pre-v3 row (no schema_version: 3, safety_enabled: true with legacy rules)
    let legacy_json = r#"{"login_required":false,"safety_enabled":true,"rules":[{"id":"r18","expr":"tag:explicit"}]}"#;
    let (_legacy_doc, legacy_notice) =
        decode_site_settings_document(5, legacy_json, SiteSettingsDocument::default())
            .expect("decode legacy pre-v3 row");
    assert!(legacy_notice.is_some());

    // 1. All non-safety settings mutations (`save_access_settings`, `save_providers`,
    //    `retry_policy_activation`) MUST fail closed until Content Safety publishes Policy v3.
    assert_eq!(
        ensure_v3_ready_for_non_safety_mutation(legacy_notice.as_deref()),
        Err(LEGACY_UPGRADE_REQUIRED_MSG)
    );

    // 2. Non-safety tabs hitting `/admin/api/safety` (`Similarity & Geo`, `Age & Legal`)
    //    or older clients omitting `confirm_policy_v3_migration` MUST fail closed too.
    let mut partial_req = serde_json::to_value(sample_safety_req(vec![])).unwrap();
    partial_req
        .as_object_mut()
        .unwrap()
        .remove("confirm_policy_v3_migration");
    let decoded_default: SaveSafetyReq =
        serde_json::from_value(partial_req).expect("deserialize SaveSafetyReq without flag");
    assert!(
        !decoded_default.confirm_policy_v3_migration,
        "omitted confirm_policy_v3_migration must default to false (fail-closed)"
    );
    assert_eq!(
        ensure_v3_ready_for_safety_mutation(
            legacy_notice.as_deref(),
            decoded_default.confirm_policy_v3_migration
        ),
        Err(LEGACY_UPGRADE_REQUIRED_MSG)
    );

    // 3. ONLY explicit Content Safety Policy v3 publication (`confirm_policy_v3_migration == true`)
    //    is allowed to perform the legacy -> v3 upgrade.
    assert_eq!(
        ensure_v3_ready_for_safety_mutation(legacy_notice.as_deref(), true),
        Ok(())
    );

    // 4. Fresh installation (`revision = 0, "{}"`) has no legacy notice and permits all saves.
    let (_fresh_doc, fresh_notice) =
        decode_site_settings_document(0, "{}", SiteSettingsDocument::default())
            .expect("decode fresh install");
    assert!(fresh_notice.is_none());
    assert_eq!(
        ensure_v3_ready_for_non_safety_mutation(fresh_notice.as_deref()),
        Ok(())
    );
    assert_eq!(
        ensure_v3_ready_for_safety_mutation(fresh_notice.as_deref(), false),
        Ok(())
    );

    // 5. After Policy v3 is published (`schema_version = 3`), all non-safety tabs work normally.
    let mut v3_doc = SiteSettingsDocument::default();
    v3_doc.public.revision = 6;
    v3_doc.public.safety_enabled = true;
    v3_doc.public.policies = builtin_safety_presets();
    v3_doc.public.refresh_policy_digest();
    let v3_json = serde_json::to_string(&v3_doc).unwrap();
    let (_decoded_v3, v3_notice) =
        decode_site_settings_document(6, &v3_json, SiteSettingsDocument::default())
            .expect("decode v3 row");
    assert!(v3_notice.is_none());
    assert_eq!(
        ensure_v3_ready_for_non_safety_mutation(v3_notice.as_deref()),
        Ok(())
    );
    assert_eq!(
        ensure_v3_ready_for_safety_mutation(v3_notice.as_deref(), false),
        Ok(())
    );
}
