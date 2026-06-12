use std::{
    collections::{HashMap, HashSet},
    env,
    sync::{Arc, LazyLock},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::bail;
use arc_swap::ArcSwap;
use aws_lc_rs::signature::{ParsedPublicKey, RSA_PKCS1_2048_8192_SHA256, RsaPublicKeyComponents};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Keys {
    keys: Vec<Key>,
}

#[derive(Debug, Deserialize)]
struct Key {
    kid: String,
    n: String,
    e: String,
}

type KeyMap = HashMap<String, ParsedPublicKey>;

#[tracing::instrument(skip_all, ret)]
fn init_keys(url: impl AsRef<str>) -> Option<KeyMap> {
    match reqwest::blocking::get(url.as_ref())
        .and_then(|resp| resp.error_for_status())
        .and_then(|resp| resp.json::<Keys>())
    {
        Ok(keys) => keys
            .keys
            .into_iter()
            .map(|key| {
                Some((
                    key.kid,
                    URL_SAFE_NO_PAD
                        .decode(key.n)
                        .and_then(|n| Ok((n, URL_SAFE_NO_PAD.decode(key.e)?)))
                        .inspect_err(|e| tracing::error!(e=%e, "Invalid key from cloudflare"))
                        .ok()
                        .and_then(|(n, e)| {
                            RsaPublicKeyComponents { n, e }
                                .to_parsed_public_key(&RSA_PKCS1_2048_8192_SHA256)
                                .inspect_err(
                                    |e| tracing::error!(e=%e, "Invalid key format from cloudflare"),
                                )
                                .ok()
                        })?,
                ))
            })
            .try_collect::<KeyMap>(),
        Err(e) => {
            tracing::error!(e=%e, "Failed to fetch keys");
            None
        }
    }
}

fn team() -> Option<&'static str> {
    static TEAM: LazyLock<Option<String>> = LazyLock::new(|| {
        env::var("TEAM_NAME")
            .inspect_err(|_| tracing::error!(env_var = "TEAM_NAME", "Not presented"))
            .ok()
    });
    TEAM.as_ref().map(|team| team.as_str())
}

pub fn keys() -> Option<Arc<KeyMap>> {
    static KEYS: LazyLock<Option<Arc<ArcSwap<KeyMap>>>> = LazyLock::new(|| {
        let team = team()?;

        let url = format!("https://{}.cloudflareaccess.com/cdn-cgi/access/certs", team);

        tracing::info!(url, "Fetching certs");

        let keys = init_keys(&url)?;
        let keys = Arc::new(ArcSwap::from_pointee(keys));

        thread::spawn({
            let keys = keys.clone();
            move || {
                loop {
                    thread::sleep(Duration::from_days(1));
                    if let Some(new_keys) = init_keys(&url) {
                        keys.store(Arc::new(new_keys));
                    }
                }
            }
        });

        Some(keys)
    });
    KEYS.as_ref().map(|k| k.load_full())
}

#[derive(Debug, Deserialize)]
struct JwtKeyInfo {
    alg: String,
    kid: String,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Audience {
    Single(String),
    Multiple(HashSet<String>),
}

impl Audience {
    pub fn contains(&self, expected: &str) -> bool {
        match self {
            Audience::Single(s) => s == expected,
            Audience::Multiple(v) => v.contains(expected),
        }
    }
}

#[derive(Debug, Deserialize)]
struct JwtClaim {
    aud: Audience,
    exp: u64,
    iss: String,
}

#[tracing::instrument(skip_all, ret)]
pub fn verify(jwt: impl AsRef<[u8]>, expected_aud: impl AsRef<str>) -> anyhow::Result<()> {
    let Some(team) = team() else { bail!("no team") };
    let Some(keys) = keys() else { bail!("no keys") };

    let jwt = String::from_utf8_lossy(jwt.as_ref());
    let parts = jwt.split('.').collect::<Vec<_>>();
    if parts.len() != 3 {
        bail!("invalid jwt format");
    }
    let [header_b64, claim_b64, sig_b64] = parts.try_into().unwrap();

    let JwtKeyInfo { alg, kid } = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(header_b64)?)?;
    if alg != "RS256" {
        bail!("unsupport sign algorithm");
    }
    let Some(pub_key) = keys.get(&kid) else {
        bail!("key id not found");
    };

    let signing_input = format!("{header_b64}.{claim_b64}");
    let sig = URL_SAFE_NO_PAD.decode(sig_b64)?;
    pub_key.verify_sig(signing_input.as_bytes(), &sig)?;

    let claim = URL_SAFE_NO_PAD.decode(claim_b64)?;
    let JwtClaim { aud, exp, iss, .. } = serde_json::from_slice(&claim)?;

    if !aud.contains(expected_aud.as_ref()) {
        bail!("aud mismatch");
    }

    if iss != format!("https://{team}.cloudflareaccess.com") {
        bail!("iss mismatch");
    }

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    if exp < now {
        bail!("expired");
    }

    Ok(())
}
