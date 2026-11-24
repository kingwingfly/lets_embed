//! Thin `wasm-bindgen` bindings over `window.__leWallet` (`assets/wallet-bridge.js`).

use js_sys::{Function, Promise, Reflect};
use serde::Deserialize;
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;

#[derive(Clone, Debug, Deserialize)]
pub struct SiweSignature {
    pub message: String,
    pub signature: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SolSignature {
    pub address: String,
    pub signature: String,
    #[serde(default)]
    pub signed_message: Option<String>,
}

fn bridge() -> Result<JsValue, String> {
    let win = web_sys::window().ok_or_else(|| "Browser window unavailable.".to_string())?;
    let val = Reflect::get(&win, &JsValue::from_str("__leWallet"))
        .map_err(|_| "Wallet bridge failed to load.".to_string())?;
    if val.is_undefined() || val.is_null() {
        return Err("Wallet bridge script is not loaded yet. Reload and retry.".to_string());
    }
    Ok(val)
}

fn js_err_msg(err: JsValue) -> String {
    if let Some(s) = err.as_string() {
        return s;
    }
    if let Ok(msg) = Reflect::get(&err, &JsValue::from_str("message"))
        && let Some(s) = msg.as_string()
    {
        return s;
    }
    "Wallet request was cancelled or failed.".to_string()
}

async fn call_async_string(method: &str, args: &[JsValue]) -> Result<String, String> {
    let b = bridge()?;
    let func = Reflect::get(&b, &JsValue::from_str(method))
        .map_err(js_err_msg)?
        .dyn_into::<Function>()
        .map_err(|_| format!("Missing wallet bridge method {method}"))?;
    let arr = js_sys::Array::new();
    for a in args {
        arr.push(a);
    }
    let promise: Promise = func
        .apply(&b, &arr)
        .map_err(js_err_msg)?
        .dyn_into()
        .map_err(|_| format!("{method} did not return a Promise"))?;
    let val = JsFuture::from(promise).await.map_err(js_err_msg)?;
    val.as_string()
        .ok_or_else(|| format!("Unexpected async return from {method}"))
}

pub async fn connect_and_sign_siwe(
    provider_id: &str,
    domain: &str,
    chain_id: u64,
    nonce: &str,
    statement: &str,
    uri_override: Option<&str>,
) -> Result<SiweSignature, String> {
    let json = call_async_string(
        "connectAndSignSiwe",
        &[
            JsValue::from_str(provider_id),
            JsValue::from_str(domain),
            JsValue::from_f64(chain_id as f64),
            JsValue::from_str(nonce),
            JsValue::from_str(statement),
            JsValue::from_str(uri_override.unwrap_or("")),
        ],
    )
    .await?;
    serde_json::from_str(&json).map_err(|e| format!("Invalid wallet response: {e}"))
}

pub async fn connect_and_sign_sol_message(
    provider_id: &str,
    message: &str,
) -> Result<SolSignature, String> {
    let json = call_async_string(
        "connectAndSignSolMessage",
        &[JsValue::from_str(provider_id), JsValue::from_str(message)],
    )
    .await?;
    serde_json::from_str(&json).map_err(|e| format!("Invalid Solana wallet response: {e}"))
}

pub async fn send_eth_tx(provider_id: &str, tx_json: &str) -> Result<String, String> {
    call_async_string(
        "sendEthTx",
        &[JsValue::from_str(provider_id), JsValue::from_str(tx_json)],
    )
    .await
}

pub async fn send_sol_tx(provider_id: &str, base64_wire_tx: &str) -> Result<String, String> {
    call_async_string(
        "sendSolTx",
        &[
            JsValue::from_str(provider_id),
            JsValue::from_str(base64_wire_tx),
        ],
    )
    .await
}

/// Mount the official Telegram Login Widget inside `container_id` using the
/// CSP-safe redirect callback `auth_url` (`/user/auth/telegram/callback?next=...`).
pub fn mount_telegram_widget(container_id: &str, bot_username: &str, auth_url: &str) {
    let Ok(b) = bridge() else {
        return;
    };
    let Ok(func) = Reflect::get(&b, &JsValue::from_str("mountTelegramWidget"))
        .and_then(|v| v.dyn_into::<Function>())
    else {
        return;
    };
    let _ = func.call3(
        &b,
        &JsValue::from_str(container_id),
        &JsValue::from_str(bot_username),
        &JsValue::from_str(auth_url),
    );
}
