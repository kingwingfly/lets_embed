//! UNIT 2: SIWE auth handlers.
//!
//! - GET  /user/api/nonce  -> 200 Json(NonceResp); nonce stored in KV
//!   (`NONCE_BINDING`) under "nonce:{nonce}" with `NONCE_TTL_SECS`.
//! - POST /user/api/verify Json(VerifyReq) -> 200 Json(VerifyResp) + session
//!   cookie | 400/401 Json(ApiError) | 403 banned.
//! - POST /user/api/logout -> clears the cookie.
//! - GET  /user/api/me     -> 200 Json(StatusResp) | 401.

use axum::{
    Json,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Deserialize;
use tower_cookies::Cookies;

use crate::types::{ApiError, NonceResp, VerifyReq, VerifyResp};
use crate::{AppState, config, do_client, session, siwe};

fn api_error(status: StatusCode, msg: impl Into<String>) -> Response {
    (status, Json(ApiError { error: msg.into() })).into_response()
}

fn internal_error() -> Response {
    api_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
}

#[worker::send]
pub async fn nonce(State(st): State<AppState>) -> Response {
    let nonce = uuid::Uuid::new_v4().simple().to_string();

    let kv = match st.env.kv(crate::NONCE_BINDING) {
        Ok(kv) => kv,
        Err(e) => {
            worker::console_error!("kv binding failed: {e:?}");
            return internal_error();
        }
    };
    let put = match kv.put(&format!("nonce:{nonce}"), "1") {
        Ok(p) => p,
        Err(e) => {
            worker::console_error!("nonce put failed: {e:?}");
            return internal_error();
        }
    };
    if let Err(e) = put.expiration_ttl(config::NONCE_TTL_SECS).execute().await {
        worker::console_error!("nonce store failed: {e:?}");
        return internal_error();
    }

    Json(NonceResp { nonce }).into_response()
}

#[worker::send]
pub async fn verify(
    State(st): State<AppState>,
    cookies: Cookies,
    Json(req): Json<VerifyReq>,
) -> Response {
    // 1) Parse the EIP-4361 message.
    let msg = match siwe::parse_siwe(&req.message) {
        Ok(m) => m,
        Err(e) => return api_error(StatusCode::BAD_REQUEST, e.to_string()),
    };

    // 2) Domain / version / chain binding.
    if msg.domain != *st.siwe_domain {
        return api_error(StatusCode::UNAUTHORIZED, "domain mismatch");
    }
    if msg.version != "1" {
        return api_error(StatusCode::UNAUTHORIZED, "unsupported version");
    }
    if msg.chain_id != st.chain_id {
        return api_error(StatusCode::UNAUTHORIZED, "chain id mismatch");
    }

    // 3) Timestamps: issued-at freshness + optional expiration.
    let now = session::now_secs();
    let Some(iat) = siwe::parse_rfc3339_epoch(&msg.issued_at) else {
        return api_error(StatusCode::UNAUTHORIZED, "invalid issued-at timestamp");
    };
    if now.abs_diff(iat) > config::SIWE_MAX_AGE_SECS {
        return api_error(StatusCode::UNAUTHORIZED, "message issued-at out of range");
    }
    if let Some(exp_str) = &msg.expiration_time {
        let Some(exp) = siwe::parse_rfc3339_epoch(exp_str) else {
            return api_error(StatusCode::UNAUTHORIZED, "invalid expiration timestamp");
        };
        if exp <= now {
            return api_error(StatusCode::UNAUTHORIZED, "message expired");
        }
    }

    // 4) Single-use nonce: must exist in KV, then delete it.
    let kv = match st.env.kv(crate::NONCE_BINDING) {
        Ok(kv) => kv,
        Err(e) => {
            worker::console_error!("kv binding failed: {e:?}");
            return internal_error();
        }
    };
    let nonce_key = format!("nonce:{}", msg.nonce);
    match kv.get(&nonce_key).text().await {
        Ok(Some(_)) => {}
        Ok(None) => return api_error(StatusCode::UNAUTHORIZED, "unknown or expired nonce"),
        Err(e) => {
            worker::console_error!("nonce get failed: {e:?}");
            return internal_error();
        }
    }
    if let Err(e) = kv.delete(&nonce_key).await {
        worker::console_error!("nonce delete failed: {e:?}");
        return internal_error();
    }

    // 5) Recover the signer and compare against the claimed address.
    let addr = match siwe::recover_address(&req.message, &req.signature) {
        Ok(a) => a,
        Err(e) => return api_error(StatusCode::UNAUTHORIZED, e.to_string()),
    };
    if addr != msg.address.to_lowercase() {
        return api_error(
            StatusCode::UNAUTHORIZED,
            "signature does not match address",
        );
    }

    // 6) D1: upsert the user row, then check the ban flag.
    let db = match st.env.d1(crate::D1_BINDING) {
        Ok(db) => db,
        Err(e) => {
            worker::console_error!("d1 binding failed: {e:?}");
            return internal_error();
        }
    };
    let upsert = db
        .prepare(
            "INSERT INTO users (address, created_at, last_login) VALUES (?, ?, ?) \
             ON CONFLICT(address) DO UPDATE SET last_login = excluded.last_login",
        )
        .bind(&[
            addr.as_str().into(),
            (now as f64).into(),
            (now as f64).into(),
        ]);
    match upsert {
        Ok(stmt) => {
            if let Err(e) = stmt.run().await {
                worker::console_error!("user upsert failed: {e:?}");
                return internal_error();
            }
        }
        Err(e) => {
            worker::console_error!("user upsert bind failed: {e:?}");
            return internal_error();
        }
    }

    #[derive(Deserialize)]
    struct BanRow {
        banned: i64,
    }
    let banned = match db
        .prepare("SELECT banned FROM users WHERE address = ?")
        .bind(&[addr.as_str().into()])
    {
        Ok(stmt) => match stmt.first::<BanRow>(None).await {
            Ok(row) => row.is_some_and(|r| r.banned != 0),
            Err(e) => {
                worker::console_error!("ban check failed: {e:?}");
                return internal_error();
            }
        },
        Err(e) => {
            worker::console_error!("ban check bind failed: {e:?}");
            return internal_error();
        }
    };
    if banned {
        return api_error(StatusCode::FORBIDDEN, "account banned");
    }

    // 7) Ensure the Durable Object account exists (free grant on first touch).
    if let Err(e) = do_client::do_init(&st.env, &addr).await {
        worker::console_error!("do init failed: {e:?}");
        return internal_error();
    }

    // 8) Issue the session cookie.
    let claims = session::SessionClaims {
        sub: addr.clone(),
        iat: now,
        exp: now + config::SESSION_TTL_SECS,
    };
    let token = session::jwt_sign(&claims, &st.jwt_secret);
    cookies.add(session::make_session_cookie(
        token,
        config::SESSION_TTL_SECS as i64,
    ));

    Json(VerifyResp {
        address: siwe::to_checksum(&addr),
    })
    .into_response()
}

#[worker::send]
pub async fn logout(cookies: Cookies) -> Response {
    cookies.add(session::clear_session_cookie());
    StatusCode::OK.into_response()
}

#[worker::send]
pub async fn me(State(st): State<AppState>, cookies: Cookies) -> Response {
    let Some(addr) = session::session_address(&cookies, &st.jwt_secret) else {
        return api_error(StatusCode::UNAUTHORIZED, "not signed in");
    };
    match do_client::do_status(&st.env, &addr).await {
        Ok(status) => Json(status).into_response(),
        Err(e) => {
            worker::console_error!("do status failed: {e:?}");
            internal_error()
        }
    }
}
