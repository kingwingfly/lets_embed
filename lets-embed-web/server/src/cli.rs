use std::path::PathBuf;

use anyhow::{Context as _, bail};
use app::{
    policy_sync::{DEFAULT_MAX_POLICY_STALENESS, PolicySyncConfig},
    state::DeploymentMode,
    util::normalize_public_origin,
};
use clap::Parser;
use site_access::{KeyDomain, resolve_domain_secret, validate_master_secret};
use url::{Host, Url};

#[derive(Parser, Debug, Clone, Default)]
#[command(name = "lets-embed-web", version, about = "Let's Embed web server")]
pub struct Cli {
    #[arg(long, default_value = "0.0.0.0")]
    pub host: String,

    #[arg(long, default_value_t = 3000)]
    pub port: u16,

    /// Explicit deployment mode: `standalone` (default) or `managed`.
    /// Also configurable via `DEPLOYMENT_MODE`.
    #[arg(long)]
    pub mode: Option<String>,

    /// Optional static safety policy JSON file for Standalone Mode (`PublicSitePolicy`).
    #[arg(long)]
    pub policy_file: Option<PathBuf>,

    /// In Standalone Mode only, trust `X-Forwarded-Host` / `X-Forwarded-Proto` when
    /// `PUBLIC_URL` is unset. Ignored in Managed Mode (which pins `PUBLIC_URL`).
    #[arg(long, default_value_t = false)]
    pub trust_proxy: bool,

    /// Managed Mode policy endpoint (`POLICY_URL`). Must be `https://` unless
    /// `--allow-insecure-local-policy` is explicitly passed for localhost testing.
    #[arg(long)]
    pub policy_url: Option<String>,

    /// Test-only opt-in allowing `http://127.0.0.1` or `http://localhost` for `POLICY_URL`
    /// in Managed Mode.
    #[arg(long, default_value_t = false)]
    pub allow_insecure_local_policy: bool,

    /// Master site secret (`SITE_SECRET`, >= 32 bytes) used to derive domain-isolated
    /// `GatewayAssertion`, `MediaCap`, and `InternalApi` secrets via HKDF-SHA256.
    /// Individual secret flags/env vars override the derived value for independent rotation.
    #[arg(long)]
    pub site_secret: Option<String>,

    /// Optional override for verifying `X-Gateway-Assertion` (`GATEWAY_ASSERTION_SECRET`).
    #[arg(long)]
    pub gateway_assertion_secret: Option<String>,

    /// Optional override for minting `/media/*` capabilities (`MEDIA_CAP_SECRET`).
    #[arg(long)]
    pub media_cap_secret: Option<String>,

    /// Optional override for authenticating `/internal/*` endpoints (`INTERNAL_API_SECRET`).
    #[arg(long)]
    pub internal_api_secret: Option<String>,

    /// Optional Cloudflare Access service token client ID for `POLICY_URL` (`CF_ACCESS_CLIENT_ID`).
    #[arg(long)]
    pub cf_access_client_id: Option<String>,

    /// Optional Cloudflare Access service token client secret for `POLICY_URL` (`CF_ACCESS_CLIENT_SECRET`).
    #[arg(long)]
    pub cf_access_client_secret: Option<String>,

    #[arg(
        long,
        default_value = "models/siglip2-so400m-patch14-384/onnx/text_model.onnx"
    )]
    pub clip_text_model: Option<PathBuf>,

    #[arg(
        long,
        default_value = "models/siglip2-so400m-patch14-384/tokenizer.json"
    )]
    pub tokenizer: Option<PathBuf>,

    #[arg(
        long,
        default_value = "models/dinov3-vitb16-pretrain-lvd1689m/onnx/model.onnx"
    )]
    pub dinov3_model: Option<PathBuf>,

    #[arg(alias = "it", long)]
    pub idle_timeout: Option<u64>,

    /// Canonical public origin (e.g. `https://lets-embed.louisfly.icu`) for
    /// robots.txt, sitemap.xml, and canonical/OpenGraph tags. Required in Managed Mode.
    #[arg(long)]
    pub public_url: Option<String>,

    /// Local media root directory for `/images` & `/videos` in Standalone Mode.
    /// Explicitly refused/ignored in Managed Mode.
    pub prefix: Option<PathBuf>,
}

/// Validated runtime configuration produced at startup before binding any sockets.
#[derive(Debug, Clone)]
pub struct RuntimeConfig {
    pub mode: DeploymentMode,
    pub public_url: Option<String>,
    pub trust_proxy: bool,
    /// Only populated in Standalone Mode when `--prefix` is supplied; always `None` in Managed Mode.
    pub serve_media_prefix: Option<PathBuf>,
    /// Optional static policy file path for Standalone Mode.
    pub standalone_policy_file: Option<PathBuf>,
    /// Managed Mode policy sync configuration (always `Some` in Managed Mode, `None` in Standalone).
    pub managed_policy_sync: Option<PolicySyncConfig>,
    /// Managed Mode HMAC secret for verifying `X-Gateway-Assertion`.
    pub gateway_assertion_secret: Option<Vec<u8>>,
    /// Managed Mode HMAC secret for minting `/media/*` capabilities.
    pub media_cap_secret: Option<Vec<u8>>,
    /// Managed Mode secret for authenticating `/internal/*` requests (`INTERNAL_API_SECRET`
    /// or HKDF-derived from `SITE_SECRET`).
    pub internal_api_secret: Option<Vec<u8>>,
}

fn non_empty(v: Option<String>) -> Option<String> {
    v.map(|s| s.trim().to_string()).filter(|s| !s.is_empty())
}

fn cli_or_env(
    cli_val: &Option<String>,
    env_name: &str,
    env_get: &impl Fn(&str) -> Option<String>,
) -> Option<String> {
    non_empty(cli_val.clone()).or_else(|| non_empty(env_get(env_name)))
}

pub fn parse_deployment_mode(raw: Option<&str>) -> anyhow::Result<DeploymentMode> {
    match raw.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
        None | Some("") | Some("standalone") => Ok(DeploymentMode::Standalone),
        Some("managed") => Ok(DeploymentMode::Managed),
        Some(other) => bail!(
            "invalid deployment mode `{other}`: expected `standalone` or `managed`"
        ),
    }
}

pub fn validate_policy_url(raw: &str, allow_insecure_local: bool) -> anyhow::Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("POLICY_URL must not be empty in managed mode");
    }
    let parsed = Url::parse(trimmed).context("invalid POLICY_URL")?;
    if !parsed.username().is_empty() || parsed.password().is_some() {
        bail!("POLICY_URL must not contain embedded userinfo credentials");
    }
    let Some(host) = parsed.host() else {
        bail!("POLICY_URL must include a valid host");
    };
    match parsed.scheme() {
        "https" => Ok(parsed.to_string()),
        "http" => {
            let is_local = match host {
                Host::Domain(d) => d.eq_ignore_ascii_case("localhost"),
                Host::Ipv4(ip) => ip.is_loopback(),
                Host::Ipv6(ip) => ip.is_loopback(),
            };
            if allow_insecure_local && is_local {
                Ok(parsed.to_string())
            } else if !allow_insecure_local {
                bail!(
                    "POLICY_URL must use https:// in managed mode (pass --allow-insecure-local-policy for local http://127.0.0.1 or http://localhost tests)"
                );
            } else {
                bail!(
                    "--allow-insecure-local-policy only permits http://127.0.0.1 or http://localhost, not `{}`",
                    parsed.host_str().unwrap_or_default()
                );
            }
        }
        other => bail!("POLICY_URL has unsupported scheme `{other}` (expected https://)"),
    }
}

/// Resolve and strictly validate deployment mode, secrets, canonical origin, and media mounts.
///
/// - **Standalone Mode**: succeeds with zero Cloudflare env vars or secrets.
/// - **Managed Mode**: fails fast if `POLICY_URL`, `GATEWAY_ASSERTION_SECRET`,
///   `MEDIA_CAP_SECRET`, or `PUBLIC_URL` is missing/invalid, and refuses raw `/images` / `/videos` mounts.
pub fn resolve_runtime_config(
    cli: &Cli,
    env_get: impl Fn(&str) -> Option<String>,
) -> anyhow::Result<RuntimeConfig> {
    let mode_raw = cli_or_env(&cli.mode, "DEPLOYMENT_MODE", &env_get);
    let mode = parse_deployment_mode(mode_raw.as_deref())?;

    let raw_public_url = cli_or_env(&cli.public_url, "PUBLIC_URL", &env_get);
    let public_url = match raw_public_url {
        Some(raw) => {
            let normalized = normalize_public_origin(&raw)
                .ok_or_else(|| anyhow::anyhow!("invalid PUBLIC_URL `{raw}` (expected http(s)://host[:port])"))?;
            Some(normalized)
        }
        None => None,
    };

    match mode {
        DeploymentMode::Standalone => Ok(RuntimeConfig {
            mode,
            public_url,
            trust_proxy: cli.trust_proxy,
            serve_media_prefix: cli.prefix.clone(),
            standalone_policy_file: cli.policy_file.clone(),
            managed_policy_sync: None,
            gateway_assertion_secret: None,
            media_cap_secret: None,
            internal_api_secret: None,
        }),
        DeploymentMode::Managed => {
            let Some(pinned_public_url) = public_url else {
                bail!("PUBLIC_URL (--public-url or PUBLIC_URL env) is required in managed mode");
            };
            let raw_policy_url = cli_or_env(&cli.policy_url, "POLICY_URL", &env_get)
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "POLICY_URL (--policy-url or POLICY_URL env) is required in managed mode"
                    )
                })?;
            let policy_url = validate_policy_url(&raw_policy_url, cli.allow_insecure_local_policy)?;

            let site_secret = cli_or_env(&cli.site_secret, "SITE_SECRET", &env_get);
            if let Some(ref master) = site_secret {
                validate_master_secret(master)
                    .map_err(|msg| anyhow::anyhow!("invalid SITE_SECRET: {msg}"))?;
            }

            let explicit_assertion = cli_or_env(
                &cli.gateway_assertion_secret,
                "GATEWAY_ASSERTION_SECRET",
                &env_get,
            );
            let explicit_media_cap =
                cli_or_env(&cli.media_cap_secret, "MEDIA_CAP_SECRET", &env_get);
            let explicit_internal =
                cli_or_env(&cli.internal_api_secret, "INTERNAL_API_SECRET", &env_get);

            let assertion_secret = resolve_domain_secret(
                explicit_assertion.as_deref(),
                site_secret.as_deref(),
                KeyDomain::GatewayAssertion,
            )
            .map_err(|_| {
                anyhow::anyhow!(
                    "GATEWAY_ASSERTION_SECRET or SITE_SECRET is required in managed mode"
                )
            })?;
            let media_cap_secret = resolve_domain_secret(
                explicit_media_cap.as_deref(),
                site_secret.as_deref(),
                KeyDomain::MediaCap,
            )
            .map_err(|_| {
                anyhow::anyhow!("MEDIA_CAP_SECRET or SITE_SECRET is required in managed mode")
            })?;
            let internal_api_secret = resolve_domain_secret(
                explicit_internal.as_deref(),
                site_secret.as_deref(),
                KeyDomain::InternalApi,
            )
            .ok()
            .map(String::into_bytes);

            let cf_access_client_id =
                cli_or_env(&cli.cf_access_client_id, "CF_ACCESS_CLIENT_ID", &env_get);
            let cf_access_client_secret = cli_or_env(
                &cli.cf_access_client_secret,
                "CF_ACCESS_CLIENT_SECRET",
                &env_get,
            );

            Ok(RuntimeConfig {
                mode,
                public_url: Some(pinned_public_url),
                // Managed Mode NEVER trusts X-Forwarded-Host; canonical origin is pinned to PUBLIC_URL.
                trust_proxy: false,
                // Managed Mode REFUSES raw ServeDir mounts on /images and /videos even if --prefix is passed.
                serve_media_prefix: None,
                standalone_policy_file: None,
                managed_policy_sync: Some(PolicySyncConfig {
                    policy_url,
                    cf_access_client_id,
                    cf_access_client_secret,
                    max_staleness: DEFAULT_MAX_POLICY_STALENESS,
                }),
                gateway_assertion_secret: Some(assertion_secret.into_bytes()),
                media_cap_secret: Some(media_cap_secret.into_bytes()),
                internal_api_secret,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn env_map(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |k: &str| map.get(k).cloned()
    }

    #[test]
    fn standalone_starts_with_zero_cloudflare_env_and_mounts_prefix() {
        let cli = Cli {
            prefix: Some(PathBuf::from("/data/media")),
            ..Cli::default()
        };
        let cfg = resolve_runtime_config(&cli, env_map(&[])).expect("standalone config");
        assert_eq!(cfg.mode, DeploymentMode::Standalone);
        assert_eq!(cfg.serve_media_prefix, Some(PathBuf::from("/data/media")));
        assert!(!cfg.trust_proxy);
        assert!(cfg.managed_policy_sync.is_none());
        assert!(cfg.gateway_assertion_secret.is_none());
        assert!(cfg.media_cap_secret.is_none());
    }

    #[test]
    fn managed_mode_fails_fast_when_any_required_config_is_missing() {
        let managed_cli = Cli {
            mode: Some("managed".into()),
            prefix: Some(PathBuf::from("/data/media")),
            ..Cli::default()
        };

        // Missing all required vars
        assert!(resolve_runtime_config(&managed_cli, env_map(&[])).is_err());

        // Missing POLICY_URL
        assert!(
            resolve_runtime_config(
                &managed_cli,
                env_map(&[
                    ("PUBLIC_URL", "https://gallery.example.com"),
                    ("GATEWAY_ASSERTION_SECRET", "sec1"),
                    ("MEDIA_CAP_SECRET", "sec2"),
                ])
            )
            .is_err()
        );

        // Missing GATEWAY_ASSERTION_SECRET
        assert!(
            resolve_runtime_config(
                &managed_cli,
                env_map(&[
                    ("PUBLIC_URL", "https://gallery.example.com"),
                    ("POLICY_URL", "https://policy.example.com/api/policy"),
                    ("MEDIA_CAP_SECRET", "sec2"),
                ])
            )
            .is_err()
        );

        // Missing MEDIA_CAP_SECRET
        assert!(
            resolve_runtime_config(
                &managed_cli,
                env_map(&[
                    ("PUBLIC_URL", "https://gallery.example.com"),
                    ("POLICY_URL", "https://policy.example.com/api/policy"),
                    ("GATEWAY_ASSERTION_SECRET", "sec1"),
                ])
            )
            .is_err()
        );

        // Missing PUBLIC_URL
        assert!(
            resolve_runtime_config(
                &managed_cli,
                env_map(&[
                    ("POLICY_URL", "https://policy.example.com/api/policy"),
                    ("GATEWAY_ASSERTION_SECRET", "sec1"),
                    ("MEDIA_CAP_SECRET", "sec2"),
                ])
            )
            .is_err()
        );
    }

    #[test]
    fn managed_mode_enforces_https_policy_url_and_refuses_prefix_mount() {
        let base_env = [
            ("DEPLOYMENT_MODE", "managed"),
            ("PUBLIC_URL", "https://gallery.example.com/"),
            ("GATEWAY_ASSERTION_SECRET", "assert-secret"),
            ("MEDIA_CAP_SECRET", "media-secret"),
        ];

        // Plain http:// rejected without --allow-insecure-local-policy
        let mut env_http = base_env.to_vec();
        env_http.push(("POLICY_URL", "http://127.0.0.1:8787/policy"));
        let cli_no_flag = Cli {
            prefix: Some(PathBuf::from("/data/media")),
            ..Cli::default()
        };
        assert!(resolve_runtime_config(&cli_no_flag, env_map(&env_http)).is_err());

        // Plain http:// to remote host STILL rejected even WITH --allow-insecure-local-policy
        let mut env_remote_http = base_env.to_vec();
        env_remote_http.push(("POLICY_URL", "http://evil.example.com/policy"));
        let cli_with_flag = Cli {
            allow_insecure_local_policy: true,
            prefix: Some(PathBuf::from("/data/media")),
            ..Cli::default()
        };
        assert!(resolve_runtime_config(&cli_with_flag, env_map(&env_remote_http)).is_err());

        // Plain http://127.0.0.1 accepted WITH --allow-insecure-local-policy
        let local_cfg = resolve_runtime_config(&cli_with_flag, env_map(&env_http))
            .expect("localhost policy allowed with explicit test flag");
        assert_eq!(local_cfg.mode, DeploymentMode::Managed);
        // Raw ServeDir prefix MUST be suppressed in Managed Mode even when --prefix is passed!
        assert!(local_cfg.serve_media_prefix.is_none());
        assert!(!local_cfg.trust_proxy);
        assert_eq!(
            local_cfg.public_url.as_deref(),
            Some("https://gallery.example.com")
        );

        // https:// succeeds without test flag
        let mut env_https = base_env.to_vec();
        env_https.push(("POLICY_URL", "https://policy.example.com/policy"));
        let prod_cfg = resolve_runtime_config(&cli_no_flag, env_map(&env_https))
            .expect("https managed config");
        assert!(prod_cfg.serve_media_prefix.is_none());
        assert_eq!(
            prod_cfg.managed_policy_sync.as_ref().unwrap().policy_url,
            "https://policy.example.com/policy"
        );
    }

    #[test]
    fn managed_mode_derives_domain_secrets_from_site_secret_with_override_precedence() {
        let master = "0123456789abcdef0123456789abcdef0123456789abcdef";
        let cli = Cli {
            mode: Some("managed".into()),
            ..Cli::default()
        };

        // Short SITE_SECRET rejected fast.
        assert!(
            resolve_runtime_config(
                &cli,
                env_map(&[
                    ("PUBLIC_URL", "https://gallery.example.com"),
                    ("POLICY_URL", "https://policy.example.com/policy"),
                    ("SITE_SECRET", "too-short"),
                ])
            )
            .is_err()
        );

        // Single SITE_SECRET derives distinct GatewayAssertion, MediaCap, and InternalApi secrets.
        let derived = resolve_runtime_config(
            &cli,
            env_map(&[
                ("PUBLIC_URL", "https://gallery.example.com"),
                ("POLICY_URL", "https://policy.example.com/policy"),
                ("SITE_SECRET", master),
            ]),
        )
        .expect("managed config from SITE_SECRET");

        let ga = derived.gateway_assertion_secret.as_ref().unwrap();
        let mc = derived.media_cap_secret.as_ref().unwrap();
        let ia = derived.internal_api_secret.as_ref().unwrap();
        assert_eq!(
            ga.as_slice(),
            site_access::derive_domain_secret(master, KeyDomain::GatewayAssertion).as_bytes()
        );
        assert_eq!(
            mc.as_slice(),
            site_access::derive_domain_secret(master, KeyDomain::MediaCap).as_bytes()
        );
        assert_eq!(
            ia.as_slice(),
            site_access::derive_domain_secret(master, KeyDomain::InternalApi).as_bytes()
        );
        assert_ne!(ga, mc);
        assert_ne!(ga, ia);
        assert_ne!(mc, ia);

        // Explicit overrides take precedence over SITE_SECRET while other domains still derive.
        let overridden = resolve_runtime_config(
            &cli,
            env_map(&[
                ("PUBLIC_URL", "https://gallery.example.com"),
                ("POLICY_URL", "https://policy.example.com/policy"),
                ("SITE_SECRET", master),
                ("MEDIA_CAP_SECRET", "explicit-media-override"),
                ("INTERNAL_API_SECRET", "explicit-internal-override"),
            ]),
        )
        .expect("managed config with overrides");
        assert_eq!(
            overridden.gateway_assertion_secret.as_deref(),
            Some(
                site_access::derive_domain_secret(master, KeyDomain::GatewayAssertion).as_bytes()
            )
        );
        assert_eq!(
            overridden.media_cap_secret.as_deref(),
            Some(b"explicit-media-override".as_slice())
        );
        assert_eq!(
            overridden.internal_api_secret.as_deref(),
            Some(b"explicit-internal-override".as_slice())
        );
    }
}
