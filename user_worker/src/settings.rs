//! Site settings are immutable published revisions in D1. A dashboard tab can save
//! only the revision it displayed, so two editors cannot silently overwrite one another.
use crate::{config, session};
use serde::{Deserialize, Serialize};
use site_access::ChargeKind;
use std::collections::HashMap;
use worker::{Env, Result};

pub const MAX_VALUE: i64 = 1_000_000_000;
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
    /// Folder rules use decoded, segment-delimited gallery paths. Searches have separate quotas.
    pub fn free_media_in_scope(&self, request: &site_access::ChargeReq) -> bool {
        if self.free_media_folders.is_empty()
            || !matches!(request.kind, ChargeKind::Image | ChargeKind::Video)
        {
            return true;
        }
        let Ok(path) = percent_encoding::percent_decode_str(&request.path).decode_utf8() else {
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
            && (!session::is_eth_address(&p.eth_deposit)
                || p.eth_deposit[2..].bytes().all(|c| c == b'0'))
        {
            return Err("Invalid Ethereum deposit address".into());
        }
        if !p.sol_deposit.is_empty()
            && (!session::is_sol_principal(&p.sol_deposit)
                || p.sol_deposit == "11111111111111111111111111111111")
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
        let query = env
            .d1(crate::D1_BINDING)?
            .prepare("SELECT revision, document FROM site_settings ORDER BY revision DESC LIMIT 1");
        Self::read(env, query).await
    }

    pub async fn at_block(env: &Env, timestamp: u64) -> Result<Policy> {
        let query = env.d1(crate::D1_BINDING)?.prepare(
            "SELECT revision, document FROM site_settings WHERE updated_at <= ? ORDER BY revision DESC LIMIT 1"
        ).bind(&[(timestamp as f64).into()])?;
        Ok(Self::read(env, query).await?.policy)
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
        Policy {
            eth_deposit: env
                .var("DEPOSIT_ADDRESS")
                .ok()
                .map(|v| v.to_string().to_ascii_lowercase())
                .unwrap_or_default(),
            sol_deposit: env
                .var("SOL_DEPOSIT_ADDRESS")
                .ok()
                .map(|v| v.to_string())
                .unwrap_or_default(),
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
        let item = |path: &str| ChargeReq {
            path: path.into(),
            kind: ChargeKind::Image,
        };
        assert!(policy.free_media_in_scope(&item("/images/example")));
        policy.free_media_folders.push("/images/图库+a b".into());
        assert!(policy.free_media_in_scope(&item("/images/%E5%9B%BE%E5%BA%93+a%20b/a.webp")));
        assert!(!policy.free_media_in_scope(&item("/images/图库+a%20bc/a.webp")));
        assert!(!policy.free_media_in_scope(&item("/videos/a.mp4")));
    }
}
