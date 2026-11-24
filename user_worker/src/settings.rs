//! Site settings are immutable published revisions in D1. A dashboard tab can save
//! only the revision it displayed, so two editors cannot silently overwrite one another.
use crate::{config, session};
use serde::{Deserialize, Serialize};
use site_access::ChargeKind;
use std::collections::HashMap;
use worker::{Env, Result};

pub const MAX_VALUE: i64 = 1_000_000_000;

/// Well-known Solana programs and native mints that can never act as a treasury
/// wallet authority.
const DISALLOWED_SOLANA_RECIPIENTS: &[&str] = &[
    "11111111111111111111111111111111",             // System Program
    "So11111111111111111111111111111111111111112",  // Wrapped SOL native mint
    "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",  // SPL Token Program
    "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb",  // SPL Token-2022 Program
    "ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL", // SPL Associated Token Account Program
    "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr",  // SPL Memo v2 Program
    "Memo1UhkJRfHyvLMcVucJwxXeuD728EqVDDwQDxFMNo",  // SPL Memo v1 Program
];

pub(crate) fn valid_deposit_address(chain: config::Chain, address: &str) -> bool {
    match chain {
        config::Chain::Ethereum => {
            session::is_eth_address(address)
                && address[2..].bytes().any(|b| b != b'0')
                && !config::TOKENS.iter().any(|t| {
                    t.contract.is_some_and(|c| c.eq_ignore_ascii_case(address))
                        || t.feed.is_some_and(|f| f.eq_ignore_ascii_case(address))
                })
        }
        config::Chain::Solana => {
            if !session::is_sol_principal(address)
                || DISALLOWED_SOLANA_RECIPIENTS.contains(&address)
                || config::TOKENS
                    .iter()
                    .any(|t| t.chain == config::Chain::Solana && t.contract == Some(address))
            {
                return false;
            }
            // Treasury must be an on-curve, non-weak Ed25519 wallet pubkey so it can
            // own ATAs and sign outgoing transfers (rejects off-curve PDAs).
            let mut raw = [0u8; 32];
            matches!(bs58::decode(address).onto(&mut raw), Ok(32))
                && ed25519_dalek::VerifyingKey::from_bytes(&raw).is_ok_and(|vk| !vk.is_weak())
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Item {
    pub price: i64,
    pub daily_free: i64,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PlanTerms {
    pub price: i64,
    pub views: Option<i64>,
    pub searches: i64,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Policy {
    pub login_required: bool,
    pub free_media_folders: Vec<String>,
    pub items: [Item; 5],
    pub plans: [PlanTerms; 2],
    pub signup_points: i64,
    pub points_per_usd: i64,
    pub minimum_topup: i64,
    pub eth_deposit: String,
    pub sol_deposit: String,
}
impl Default for Policy {
    fn default() -> Self {
        let costs = [
            config::COST_IMAGE_VIEW,
            config::COST_VIDEO_VIEW,
            config::COST_SEARCH,
            config::COST_EMBED_SEARCH,
            config::COST_SEARCH,
        ];
        Self {
            login_required: true,
            free_media_folders: Vec::new(),
            items: costs.map(|price| Item {
                price,
                daily_free: 0,
            }),
            plans: std::array::from_fn(|i| {
                let p = &config::PLANS[i];
                PlanTerms {
                    price: p.price_points,
                    views: p.views_per_window,
                    searches: p.searches_per_window,
                }
            }),
            signup_points: config::FREE_GRANT_POINTS,
            points_per_usd: config::POINTS_PER_USD,
            minimum_topup: config::MIN_TOPUP_POINTS,
            eth_deposit: String::new(),
            sol_deposit: String::new(),
        }
    }
}
impl Policy {
    /// Folder rules use decoded, segment-delimited gallery paths (`/{images,videos}/...`)
    /// carried on `request.media_path` for Policy v3 `/media/*` requests. Searches have separate quotas.
    pub fn free_media_in_scope(&self, request: &site_access::ChargeReq) -> bool {
        if self.free_media_folders.is_empty()
            || !matches!(request.kind, ChargeKind::Image | ChargeKind::Video)
        {
            return true;
        }
        let Some(raw_path) = request.media_path.as_deref() else {
            return false;
        };
        let Ok(path) = percent_encoding::percent_decode_str(raw_path).decode_utf8() else {
            return false;
        };
        if path.contains('\\') || path.split('/').any(|part| matches!(part, "." | "..")) {
            return false;
        }
        self.free_media_folders.iter().any(|folder| {
            path.strip_prefix(folder)
                .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with('/'))
        })
    }

    pub fn item(&self, kind: ChargeKind) -> Item {
        self.items[kind as usize]
    }
    pub fn plan(&self, id: &str) -> Option<config::Plan> {
        let ix = config::PLANS.iter().position(|plan| plan.id == id)?;
        let p = self.plans[ix];
        Some(config::Plan {
            id: config::PLANS[ix].id,
            period_secs: config::PLANS[ix].period_secs,
            price_points: p.price,
            views_per_window: p.views,
            searches_per_window: p.searches,
        })
    }
    pub fn from_form(f: &HashMap<String, String>) -> std::result::Result<(u32, Self), String> {
        let field = |k: &str| {
            f.get(k)
                .map(|s| s.trim())
                .ok_or_else(|| format!("Missing field {k}"))
        };
        let number = |k: &str, min: i64| -> std::result::Result<i64, String> {
            field(k)?
                .parse::<i64>()
                .ok()
                .filter(|v| (min..=MAX_VALUE).contains(v))
                .ok_or_else(|| format!("{k} must be a whole number between {min} and {MAX_VALUE}"))
        };
        let revision = field("revision")?
            .parse()
            .map_err(|_| "Invalid settings revision")?;
        let mut p = Self {
            login_required: match field("login_required")? {
                "yes" => true,
                "no" => false,
                _ => return Err("Select a browsing mode".into()),
            },
            points_per_usd: number("points_per_usd", 1)?,
            minimum_topup: number("minimum_topup", 1)?,
            signup_points: number("signup_points", 0)?,
            eth_deposit: field("eth_deposit")?.to_ascii_lowercase(),
            sol_deposit: field("sol_deposit")?.to_owned(),
            ..Default::default()
        };
        for line in f
            .get("free_media_folders")
            .ok_or("Missing free media folders")?
            .lines()
            .filter(|line| !line.trim().is_empty())
        {
            let folder = line.trim_end_matches('/');
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
                    "Each free media folder must be a gallery path under /images or /videos".into(),
                );
            }
            if !p.free_media_folders.iter().any(|f| f == folder) {
                p.free_media_folders.push(folder.to_owned());
            }
        }
        if p.free_media_folders.len() > 64 {
            return Err("Choose up to 64 free media folders".into());
        }
        if !p.eth_deposit.is_empty()
            && !valid_deposit_address(config::Chain::Ethereum, &p.eth_deposit)
        {
            return Err("Invalid Ethereum deposit address".into());
        }
        if !p.sol_deposit.is_empty()
            && !valid_deposit_address(config::Chain::Solana, &p.sol_deposit)
        {
            return Err("Invalid Solana deposit address".into());
        }
        for k in ChargeKind::ALL {
            let name = k.name();
            p.items[k as usize] = Item {
                price: number(&format!("{name}_price"), 0)?,
                daily_free: number(&format!("{name}_free"), -1)?,
            };
        }
        for (i, plan) in config::PLANS.iter().enumerate() {
            let id = plan.id;
            let views = number(&format!("{id}_views"), -1)?;
            p.plans[i] = PlanTerms {
                price: number(&format!("{id}_price"), 0)?,
                views: (views >= 0).then_some(views),
                searches: number(&format!("{id}_searches"), 0)?,
            };
        }
        Ok((revision, p))
    }
}

pub struct Published {
    pub revision: u32,
    pub policy: Policy,
}
impl Published {
    pub async fn load(env: &Env) -> Result<Self> {
        let query = env.d1(crate::D1_BINDING)?.prepare(
            "SELECT revision, document FROM site_settings \
             WHERE activation_status = 'active' \
             ORDER BY revision DESC LIMIT 1",
        );
        Self::read(env, query).await
    }

    pub async fn at_block(env: &Env, timestamp: u64) -> Result<Policy> {
        let query = env
            .d1(crate::D1_BINDING)?
            .prepare(
                "SELECT revision, document FROM site_settings \
                 WHERE activation_status = 'active' AND updated_at <= ? \
                 ORDER BY revision DESC LIMIT 1",
            )
            .bind(&[(timestamp as f64).into()])?;
        Ok(Self::read(env, query).await?.policy)
    }

    /// Return the policy effective at `timestamp`, followed by nearby revisions
    /// that can legitimately apply when:
    /// - Chain `blockTime` / `block.timestamp` lags D1 `unixepoch()` right after
    ///   opening or rotating a deposit address (+120s forward clock-skew grace), or
    /// - An admin rotated or closed a deposit address while a prepared checkout
    ///   was already in flight (-900s backward rotation grace).
    pub async fn at_block_candidates(env: &Env, timestamp: u64) -> Result<Vec<Policy>> {
        #[derive(Deserialize)]
        struct Row {
            revision: u32,
            document: String,
            updated_at: i64,
        }
        let decode = |row: &Row| -> Result<Policy> {
            if row.revision == 0 && row.document == "{}" {
                Ok(Self::initial_policy(env))
            } else {
                Ok(serde_json::from_str(&row.document)?)
            }
        };

        let db = env.d1(crate::D1_BINDING)?;
        let active: Row = db
            .prepare(
                "SELECT revision, document, updated_at FROM site_settings \
                 WHERE activation_status = 'active' AND updated_at <= ? \
                 ORDER BY revision DESC LIMIT 1",
            )
            .bind(&[(timestamp as f64).into()])?
            .first(None)
            .await?
            .ok_or_else(|| worker::Error::RustError("Missing site settings migration".into()))?;

        let mut out = vec![decode(&active)?];
        let mut seen = vec![active.revision];

        // Forward clock-skew grace: revisions published up to 2 minutes after block timestamp.
        let skew_ceiling = timestamp.saturating_add(120);
        let forward: Vec<Row> = db
            .prepare(
                "SELECT revision, document, updated_at FROM site_settings \
                 WHERE activation_status = 'active' AND updated_at > ? AND updated_at <= ? \
                 ORDER BY revision ASC LIMIT 5",
            )
            .bind(&[(timestamp as f64).into(), (skew_ceiling as f64).into()])?
            .all()
            .await?
            .results()?;
        for row in forward {
            if !seen.contains(&row.revision) {
                seen.push(row.revision);
                out.push(decode(&row)?);
            }
        }

        // Backward rotation grace: if `active` was published within 15 minutes
        // before `timestamp`, include revisions that were active during that window
        // (plus the immediately preceding revision).
        let grace_floor = timestamp.saturating_sub(900);
        if (active.updated_at.max(0) as u64) >= grace_floor && active.revision > 0 {
            let backward: Vec<Row> = db
                .prepare(
                    "SELECT revision, document, updated_at FROM site_settings \
                     WHERE activation_status = 'active' AND revision < ? AND (updated_at >= ? OR revision = (\
                         SELECT MAX(revision) FROM site_settings WHERE activation_status = 'active' AND updated_at < ?\
                     )) ORDER BY revision DESC LIMIT 5",
                )
                .bind(&[
                    f64::from(active.revision).into(),
                    (grace_floor as f64).into(),
                    (grace_floor as f64).into(),
                ])?
                .all()
                .await?
                .results()?;
            for row in backward {
                if !seen.contains(&row.revision) {
                    seen.push(row.revision);
                    out.push(decode(&row)?);
                }
            }
        }

        Ok(out)
    }

    async fn read(env: &Env, query: worker::D1PreparedStatement) -> Result<Self> {
        #[derive(Deserialize)]
        struct Row {
            revision: u32,
            document: String,
        }
        let row: Row = query
            .first(None)
            .await?
            .ok_or_else(|| worker::Error::RustError("Missing site settings migration".into()))?;
        let policy = if row.revision == 0 && row.document == "{}" {
            Self::initial_policy(env)
        } else {
            serde_json::from_str(&row.document)?
        };
        Ok(Self {
            revision: row.revision,
            policy,
        })
    }

    fn initial_policy(env: &Env) -> Policy {
        let eth_deposit = env
            .var("DEPOSIT_ADDRESS")
            .ok()
            .map(|v| v.to_string().trim().to_ascii_lowercase())
            .filter(|a| valid_deposit_address(config::Chain::Ethereum, a))
            .unwrap_or_default();
        let sol_deposit = env
            .var("SOL_DEPOSIT_ADDRESS")
            .ok()
            .map(|v| v.to_string().trim().to_owned())
            .filter(|a| valid_deposit_address(config::Chain::Solana, a))
            .unwrap_or_default();
        Policy {
            eth_deposit,
            sol_deposit,
            ..Policy::default()
        }
    }

    pub async fn save(env: &Env, revision: u32, policy: &Policy, editor: &str) -> Result<bool> {
        let db = env.d1(crate::D1_BINDING)?;
        let mut writes = Vec::new();
        if revision == 0 {
            // Preserve the environment's original recipients inside the first publish transaction.
            writes.push(
                db.prepare(
                    "UPDATE site_settings SET document=? WHERE revision=0 AND document='{}'",
                )
                .bind(&[serde_json::to_string(&Self::initial_policy(env))?.into()])?,
            );
        }
        writes.push(db.prepare(
            "INSERT INTO site_settings (revision,document,updated_at,updated_by) SELECT revision+1, ?, unixepoch(), ? FROM site_settings WHERE revision=? AND revision=(SELECT MAX(revision) FROM site_settings)"
        ).bind(&[serde_json::to_string(policy)?.into(), editor.into(), f64::from(revision).into()])?);
        let results = db.batch(writes).await?;
        Ok(results
            .last()
            .expect("at least one write")
            .meta()?
            .and_then(|m| m.changes)
            == Some(1))
    }
}

pub async fn load(env: &Env) -> Result<Policy> {
    Ok(Published::load(env).await?.policy)
}

#[cfg(test)]
mod tests {
    use super::*;
    use site_access::ChargeReq;

    #[test]
    fn legacy_settings_and_decoded_folder_names() {
        let mut policy: Policy = serde_json::from_str("{}").unwrap();
        assert!(policy.login_required);
        assert_eq!(
            policy.item(ChargeKind::Description).price,
            config::COST_SEARCH
        );
        let item = |media_path: Option<&str>| ChargeReq {
            path: "media:image:42".into(),
            kind: ChargeKind::Image,
            media_path: media_path.map(str::to_string),
        };
        assert!(policy.free_media_in_scope(&item(Some("/images/example"))));
        assert!(policy.free_media_in_scope(&item(None)));
        policy.free_media_folders.push("/images/图库+a b".into());
        assert!(policy.free_media_in_scope(&item(Some(
            "/images/%E5%9B%BE%E5%BA%93+a%20b/a.webp"
        ))));
        assert!(!policy.free_media_in_scope(&item(Some("/images/图库+a%20bc/a.webp"))));
        assert!(!policy.free_media_in_scope(&item(Some("/videos/a.mp4"))));
        // Missing `media_path` MUST fail closed when `free_media_folders` is non-empty (Cycle 2 D-1)
        assert!(!policy.free_media_in_scope(&item(None)));
    }

    #[test]
    fn deposit_address_rejects_unspendable_contracts_mints_and_pdas() {
        assert!(valid_deposit_address(
            config::Chain::Ethereum,
            "0x2222222222222222222222222222222222222222"
        ));
        assert!(!valid_deposit_address(
            config::Chain::Ethereum,
            "0x0000000000000000000000000000000000000000"
        ));
        // ERC-20 contracts and Chainlink feeds cannot be deposit wallets.
        assert!(!valid_deposit_address(
            config::Chain::Ethereum,
            "0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48"
        ));
        assert!(!valid_deposit_address(
            config::Chain::Ethereum,
            config::FEED_ETH_USD
        ));

        // Real Ed25519 pubkey accepted.
        assert!(valid_deposit_address(
            config::Chain::Solana,
            "5tE57EgXH3HTpbtiEQxVzdJeg2NZgGaH2KSSwc7e63DR"
        ));
        // System program, wrapped SOL mint, token programs and SPL mints rejected.
        for bad in [
            "11111111111111111111111111111111",
            "So11111111111111111111111111111111111111112",
            "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
            "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v",
            "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB",
        ] {
            assert!(
                !valid_deposit_address(config::Chain::Solana, bad),
                "{bad} should be rejected"
            );
        }
        // An ATA (off-curve PDA) is not an on-curve Ed25519 wallet key.
        let owner = "5tE57EgXH3HTpbtiEQxVzdJeg2NZgGaH2KSSwc7e63DR"
            .parse()
            .unwrap();
        let mint = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v"
            .parse()
            .unwrap();
        let ata = spl_associated_token_account_interface::address::get_associated_token_address(
            &owner, &mint,
        );
        assert!(!valid_deposit_address(
            config::Chain::Solana,
            &ata.to_string()
        ));
    }
}
