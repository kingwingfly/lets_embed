//! UNIT 5: Like/Favorite API over D1 (`likes` table).
//!
//! - POST   /user/api/like          Json(LikeReq)          -> LikedResp{liked:true} (INSERT OR IGNORE)
//! - DELETE /user/api/like          Json(LikeReq)          -> LikedResp{liked:false}
//! - GET    /user/api/like          Query(LikeQuery)       -> LikedResp
//! - GET    /user/api/likes         Query(LikesQuery)      -> LikesResp, keyset on created_at DESC
//! - GET    /user/api/likes/status  Query(LikesStatusQuery)-> {"liked": ["post:1", "image:2"]}
//!
//! All require a session (401 otherwise); bad `kind` is a 400.

use std::collections::{BTreeMap, HashSet};

use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use tower_cookies::Cookies;
use wasm_bindgen::JsValue;

use crate::{
    AppState, do_client, session,
    types::{ApiError, LikeReq, LikeRow, LikedResp, LikesResp, valid_like_kind},
};

const MAX_STATUS_ITEMS: usize = 100;
const MAX_RAW_STATUS_SEGMENTS: usize = 200;

#[derive(Debug, Deserialize)]
pub struct LikesStatusQuery {
    /// Comma-separated `kind:target_id` pairs (capped at 100 unique valid pairs).
    #[serde(default)]
    pub items: String,
}

#[derive(Debug, Serialize)]
struct LikesStatusResp {
    liked: Vec<String>,
}

/// Parse up to `MAX_STATUS_ITEMS` unique valid `(kind, target_id)` pairs grouped by kind.
/// Returns `Err` if the caller exceeds the raw segment cap or unique item cap.
fn parse_status_items(raw: &str) -> Result<BTreeMap<&'static str, Vec<i64>>, &'static str> {
    let mut seen: HashSet<(&'static str, i64)> = HashSet::new();
    let mut grouped: BTreeMap<&'static str, Vec<i64>> = BTreeMap::new();
    let mut segments = 0usize;
    for pair in raw.split(',') {
        segments += 1;
        if segments > MAX_RAW_STATUS_SEGMENTS {
            return Err("too many items (max 100)");
        }
        let Some((kind_raw, id_raw)) = pair.split_once(':') else {
            continue;
        };
        let kind = match kind_raw.trim() {
            "post" => "post",
            "image" => "image",
            "video" => "video",
            _ => continue,
        };
        let Ok(id) = id_raw.trim().parse::<i64>() else {
            continue;
        };
        if seen.insert((kind, id)) {
            if seen.len() > MAX_STATUS_ITEMS {
                return Err("too many items (max 100)");
            }
            grouped.entry(kind).or_default().push(id);
        }
    }
    Ok(grouped)
}

#[derive(Debug, Deserialize)]
pub struct LikeQuery {
    pub kind: String,
    pub target_id: i64,
}

#[derive(Debug, Deserialize)]
pub struct LikesQuery {
    #[serde(default, deserialize_with = "empty_as_none")]
    pub kind: Option<String>,
    #[serde(default, deserialize_with = "empty_as_none")]
    pub limit: Option<u32>,
    /// created_at keyset cursor from the previous page's next_cursor.
    #[serde(default, deserialize_with = "empty_as_none")]
    pub cursor: Option<i64>,
}

/// Treat present-but-empty query params (`?cursor=&limit=`) as absent.
fn empty_as_none<'de, D, T>(de: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: std::str::FromStr,
    T::Err: std::fmt::Display,
{
    match Option::<String>::deserialize(de)?.as_deref() {
        None | Some("") => Ok(None),
        Some(s) => s.parse().map(Some).map_err(serde::de::Error::custom),
    }
}

fn err(status: StatusCode, msg: &str) -> Response {
    (status, Json(ApiError { error: msg.into() })).into_response()
}

fn db_err(e: worker::Error) -> Response {
    worker::console_error!("likes: db error: {e:?}");
    err(StatusCode::INTERNAL_SERVER_ERROR, "database error")
}

/// Verified, non-suspended session address, or a ready 401/403/502 response.
async fn auth_active(st: &AppState, cookies: &Cookies) -> Result<String, Response> {
    let address = session::session_address(cookies, &st.jwt_secret)
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "not signed in"))?;
    let resp = do_client::call_do::<()>(
        &st.env,
        &address,
        worker::Method::Post,
        "/check-active",
        None,
    )
    .await
    .map_err(|e| {
        worker::console_error!("likes: active check failed: {e:?}");
        err(StatusCode::BAD_GATEWAY, "account service unavailable")
    })?;
    match resp.status_code() {
        200 => Ok(address),
        403 => Err(err(StatusCode::FORBIDDEN, "account suspended")),
        code => {
            worker::console_error!("likes: unexpected active check status {code}");
            Err(err(StatusCode::BAD_GATEWAY, "account service unavailable"))
        }
    }
}

fn check_kind(kind: &str) -> Result<(), Response> {
    valid_like_kind(kind)
        .then_some(())
        .ok_or_else(|| err(StatusCode::BAD_REQUEST, "invalid kind"))
}

/// Keyset cursor: last row's created_at, only when the page came back full.
fn page_cursor(items: &[LikeRow], limit: usize) -> Option<i64> {
    match items.last() {
        Some(last) if items.len() == limit => Some(last.created_at),
        _ => None,
    }
}

#[worker::send]
pub async fn like(
    State(st): State<AppState>,
    cookies: Cookies,
    Json(req): Json<LikeReq>,
) -> Response {
    let address = match auth_active(&st, &cookies).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    if let Err(r) = check_kind(&req.kind) {
        return r;
    }
    let res = async {
        st.env
            .d1(crate::D1_BINDING)?
            .prepare(
                "INSERT OR IGNORE INTO likes (address, kind, target_id, created_at) \
                 VALUES (?, ?, CAST(? AS INTEGER), ?)",
            )
            .bind(&[
                address.into(),
                req.kind.into(),
                req.target_id.to_string().into(),
                (session::now_secs() as f64).into(),
            ])?
            .run()
            .await
    }
    .await;
    match res {
        Ok(_) => Json(LikedResp { liked: true }).into_response(),
        Err(e) => db_err(e),
    }
}

#[worker::send]
pub async fn unlike(
    State(st): State<AppState>,
    cookies: Cookies,
    Json(req): Json<LikeReq>,
) -> Response {
    let address = match auth_active(&st, &cookies).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    if let Err(r) = check_kind(&req.kind) {
        return r;
    }
    let res = async {
        st.env
            .d1(crate::D1_BINDING)?
            .prepare(
                "DELETE FROM likes WHERE address = ? AND kind = ? AND target_id = CAST(? AS INTEGER)",
            )
            .bind(&[
                address.into(),
                req.kind.into(),
                req.target_id.to_string().into(),
            ])?
            .run()
            .await
    }
    .await;
    match res {
        Ok(_) => Json(LikedResp { liked: false }).into_response(),
        Err(e) => db_err(e),
    }
}

#[worker::send]
pub async fn liked(
    State(st): State<AppState>,
    cookies: Cookies,
    Query(q): Query<LikeQuery>,
) -> Response {
    let address = match auth_active(&st, &cookies).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    if let Err(r) = check_kind(&q.kind) {
        return r;
    }

    let res = async {
        st.env
            .d1(crate::D1_BINDING)?
            .prepare(
                "SELECT 1 AS x FROM likes WHERE address = ? AND kind = ? AND target_id = CAST(? AS INTEGER)",
            )
            .bind(&[address.into(), q.kind.into(), q.target_id.to_string().into()])?
            .first::<i64>(Some("x"))
            .await
    }
    .await;
    match res {
        Ok(row) => Json(LikedResp {
            liked: row.is_some(),
        })
        .into_response(),
        Err(e) => db_err(e),
    }
}

#[worker::send]
pub async fn list(
    State(st): State<AppState>,
    cookies: Cookies,
    Query(q): Query<LikesQuery>,
) -> Response {
    let address = match auth_active(&st, &cookies).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    if let Some(kind) = &q.kind
        && let Err(r) = check_kind(kind)
    {
        return r;
    }
    let limit = q.limit.unwrap_or(50).clamp(1, 100);

    #[derive(Deserialize)]
    struct ListRow {
        kind: String,
        target_id: String,
        created_at: i64,
    }

    let mut sql = String::from(
        "SELECT kind, CAST(target_id AS TEXT) AS target_id, created_at FROM likes WHERE address = ?",
    );
    let mut binds: Vec<JsValue> = vec![address.into()];
    if let Some(kind) = q.kind {
        sql.push_str(" AND kind = ?");
        binds.push(kind.into());
    }
    if let Some(cursor) = q.cursor {
        sql.push_str(" AND created_at < ?");
        binds.push((cursor as f64).into());
    }
    sql.push_str(" ORDER BY created_at DESC LIMIT ?");
    binds.push((limit as f64).into());

    let res = async {
        let rows = st
            .env
            .d1(crate::D1_BINDING)?
            .prepare(sql)
            .bind(&binds)?
            .all()
            .await?
            .results::<ListRow>()?;
        let mut items = Vec::with_capacity(rows.len());
        for r in rows {
            let target_id = r
                .target_id
                .parse::<i64>()
                .map_err(|e| worker::Error::RustError(format!("invalid target_id: {e}")))?;
            items.push(LikeRow {
                kind: r.kind,
                target_id,
                created_at: r.created_at,
            });
        }
        Ok::<Vec<LikeRow>, worker::Error>(items)
    }
    .await;
    match res {
        Ok(items) => {
            let next_cursor = page_cursor(&items, limit as usize);
            Json(LikesResp { items, next_cursor }).into_response()
        }
        Err(e) => db_err(e),
    }
}

#[worker::send]
pub async fn status_batch(
    State(st): State<AppState>,
    cookies: Cookies,
    Query(q): Query<LikesStatusQuery>,
) -> Response {
    let address = match auth_active(&st, &cookies).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    let grouped = match parse_status_items(&q.items) {
        Ok(g) => g,
        Err(msg) => return err(StatusCode::BAD_REQUEST, msg),
    };
    if grouped.is_empty() {
        return Json(LikesStatusResp { liked: Vec::new() }).into_response();
    }

    #[derive(Deserialize)]
    struct Row {
        kind: String,
        target_id: String,
    }

    // Stay well below Cloudflare D1's 100-bound-parameter-per-statement limit
    // by chunking each kind to <= 45 ids and executing all chunks in one batch.
    // Bind and select target_id as decimal strings so full 64-bit ids never lose
    // precision through JS f64 conversion.
    let res = async {
        let db = st.env.d1(crate::D1_BINDING)?;
        let mut stmts = Vec::new();
        for (kind, ids) in grouped {
            for chunk in ids.chunks(45) {
                let placeholders = vec!["CAST(? AS INTEGER)"; chunk.len()].join(",");
                let sql = format!(
                    "SELECT kind, CAST(target_id AS TEXT) AS target_id FROM likes \
                     WHERE address = ? AND kind = ? AND target_id IN ({placeholders})"
                );
                let mut binds: Vec<JsValue> = Vec::with_capacity(2 + chunk.len());
                binds.push(address.as_str().into());
                binds.push(kind.into());
                for &id in chunk {
                    binds.push(id.to_string().into());
                }
                stmts.push(db.prepare(sql).bind(&binds)?);
            }
        }
        let mut liked = Vec::new();
        for result in db.batch(stmts).await? {
            for row in result.results::<Row>()? {
                liked.push(format!("{}:{}", row.kind, row.target_id));
            }
        }
        Ok::<Vec<String>, worker::Error>(liked)
    }
    .await;

    match res {
        Ok(liked) => Json(LikesStatusResp { liked }).into_response(),
        Err(e) => db_err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(created_at: i64) -> LikeRow {
        LikeRow {
            kind: "image".into(),
            target_id: 1,
            created_at,
        }
    }

    #[test]
    fn empty_query_params_are_none() {
        // query-string values arrive as strings; empty means absent
        let q: LikesQuery = serde_json::from_str(r#"{"kind":"","limit":"","cursor":""}"#).unwrap();
        assert!(q.kind.is_none() && q.limit.is_none() && q.cursor.is_none());
        let q: LikesQuery =
            serde_json::from_str(r#"{"kind":"image","limit":"10","cursor":"99"}"#).unwrap();
        assert_eq!(q.kind.as_deref(), Some("image"));
        assert_eq!((q.limit, q.cursor), (Some(10), Some(99)));
    }

    #[test]
    fn cursor_only_on_full_page() {
        // partial page -> no cursor
        assert_eq!(page_cursor(&[row(30), row(20)], 3), None);
        // full page -> last (oldest) created_at
        assert_eq!(page_cursor(&[row(30), row(20), row(10)], 3), Some(10));
        // empty
        assert_eq!(page_cursor(&[], 3), None);
    }

    #[test]
    fn parse_status_items_dedupes_filters_and_rejects_oversize() {
        let grouped =
            parse_status_items("post:12, image:34, post:12, bad:1, image:nan, video:9").unwrap();
        assert_eq!(grouped.get("post").map(Vec::as_slice), Some(&[12][..]));
        assert_eq!(grouped.get("image").map(Vec::as_slice), Some(&[34][..]));
        assert_eq!(grouped.get("video").map(Vec::as_slice), Some(&[9][..]));
        let exact_cap: String = (0..100)
            .map(|i| format!("image:{i}"))
            .collect::<Vec<_>>()
            .join(",");
        assert_eq!(
            parse_status_items(&exact_cap)
                .unwrap()
                .get("image")
                .map(Vec::len),
            Some(100)
        );
        let over_cap: String = (0..101)
            .map(|i| format!("image:{i}"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(parse_status_items(&over_cap).is_err());
        let garbage = vec!["bad"; 205].join(",");
        assert!(parse_status_items(&garbage).is_err());
    }
}
