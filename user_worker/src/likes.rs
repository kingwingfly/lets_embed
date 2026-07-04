//! UNIT 5: Like/Favorite API over D1.
//!
//! STUB: implement like / unlike / liked / list. Contracts:
//! - POST   /user/api/like  Json(LikeReq) -> 200 Json(LikedResp{liked:true})
//!   (INSERT OR IGNORE) | 400 bad kind | 401.
//! - DELETE /user/api/like  Json(LikeReq) -> 200 Json(LikedResp{liked:false}).
//! - GET    /user/api/like?kind=image&target_id=42 -> 200 Json(LikedResp).
//! - GET    /user/api/likes?kind=&limit=&cursor= -> 200 Json(LikesResp),
//!   keyset pagination on created_at DESC (cursor = last created_at).
//! All require a session (`session::session_address`), else 401 Json(ApiError).

use axum::{
    Json,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use tower_cookies::Cookies;

use crate::AppState;
use crate::types::LikeReq;

#[derive(Debug, Deserialize)]
pub struct LikeQuery {
    pub kind: String,
    pub target_id: i64,
}

#[derive(Debug, Deserialize)]
pub struct LikesQuery {
    pub kind: Option<String>,
    pub limit: Option<u32>,
    /// created_at keyset cursor from the previous page's next_cursor.
    pub cursor: Option<i64>,
}

#[worker::send]
pub async fn like(
    State(_st): State<AppState>,
    _cookies: Cookies,
    Json(_req): Json<LikeReq>,
) -> Response {
    (StatusCode::NOT_IMPLEMENTED, "not implemented").into_response()
}

#[worker::send]
pub async fn unlike(
    State(_st): State<AppState>,
    _cookies: Cookies,
    Json(_req): Json<LikeReq>,
) -> Response {
    (StatusCode::NOT_IMPLEMENTED, "not implemented").into_response()
}

#[worker::send]
pub async fn liked(
    State(_st): State<AppState>,
    _cookies: Cookies,
    Query(_q): Query<LikeQuery>,
) -> Response {
    (StatusCode::NOT_IMPLEMENTED, "not implemented").into_response()
}

#[worker::send]
pub async fn list(
    State(_st): State<AppState>,
    _cookies: Cookies,
    Query(_q): Query<LikesQuery>,
) -> Response {
    (StatusCode::NOT_IMPLEMENTED, "not implemented").into_response()
}
