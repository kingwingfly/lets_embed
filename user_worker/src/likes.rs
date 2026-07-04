//! UNIT 5: Like/Favorite API over D1 (`likes` table).
//!
//! - POST   /user/api/like   Json(LikeReq)     -> LikedResp{liked:true} (INSERT OR IGNORE)
//! - DELETE /user/api/like   Json(LikeReq)     -> LikedResp{liked:false}
//! - GET    /user/api/like   Query(LikeQuery)  -> LikedResp
//! - GET    /user/api/likes  Query(LikesQuery) -> LikesResp, keyset on created_at DESC
//!
//! All require a session (401 otherwise); bad `kind` is a 400.

use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use tower_cookies::Cookies;
use wasm_bindgen::JsValue;

use crate::{
    AppState, session,
    types::{ApiError, LikeReq, LikeRow, LikedResp, LikesResp, valid_like_kind},
};

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

/// Verified session address, or a ready 401 response.
fn auth(st: &AppState, cookies: &Cookies) -> Result<String, Response> {
    session::session_address(cookies, &st.jwt_secret)
        .ok_or_else(|| err(StatusCode::UNAUTHORIZED, "not signed in"))
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
    let address = match auth(&st, &cookies) {
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
                 VALUES (?, ?, ?, ?)",
            )
            .bind(&[
                address.into(),
                req.kind.into(),
                (req.target_id as f64).into(),
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
    let address = match auth(&st, &cookies) {
        Ok(a) => a,
        Err(r) => return r,
    };
    if let Err(r) = check_kind(&req.kind) {
        return r;
    }
    let res = async {
        st.env
            .d1(crate::D1_BINDING)?
            .prepare("DELETE FROM likes WHERE address = ? AND kind = ? AND target_id = ?")
            .bind(&[
                address.into(),
                req.kind.into(),
                (req.target_id as f64).into(),
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
    let address = match auth(&st, &cookies) {
        Ok(a) => a,
        Err(r) => return r,
    };
    if let Err(r) = check_kind(&q.kind) {
        return r;
    }

    let res = async {
        st.env
            .d1(crate::D1_BINDING)?
            .prepare("SELECT 1 AS x FROM likes WHERE address = ? AND kind = ? AND target_id = ?")
            .bind(&[
                address.into(),
                q.kind.into(),
                (q.target_id as f64).into(),
            ])?
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
    let address = match auth(&st, &cookies) {
        Ok(a) => a,
        Err(r) => return r,
    };
    if let Some(kind) = &q.kind
        && let Err(r) = check_kind(kind)
    {
        return r;
    }
    let limit = q.limit.unwrap_or(50).clamp(1, 100);

    let mut sql = String::from("SELECT kind, target_id, created_at FROM likes WHERE address = ?");
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
        st.env
            .d1(crate::D1_BINDING)?
            .prepare(sql)
            .bind(&binds)?
            .all()
            .await?
            .results::<LikeRow>()
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
        let q: LikesQuery =
            serde_json::from_str(r#"{"kind":"","limit":"","cursor":""}"#).unwrap();
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
}
