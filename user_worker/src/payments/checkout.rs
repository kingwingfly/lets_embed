//! Prepare an unsigned wallet transfer using the current deposit terms.

use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::Response,
};
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_json::{Value, json};
use solana_transaction::{Address, Instruction, Message, Transaction};
use spl_associated_token_account_interface::{
    address::get_associated_token_address, instruction::create_associated_token_account_idempotent,
};
use tower_cookies::Cookies;

use super::{
    api_err, eth_sender, payment_db_error, resolve_price, rpc, rpc_unavailable, solana_sender,
    verify_ethereum_network, verify_solana_network,
};
use crate::{
    AppState, auth,
    config::{self, Chain, TokenSpec},
    do_client, identity, rates, settings,
};

/// SPL Memo v2 program id used to attach a unique checkout reference to each
/// prepared Solana transaction so two identical-amount payments cannot collide
/// on the same recent blockhash.
const MEMO_PROGRAM_ID: &str = "MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr";

#[derive(Deserialize)]
pub struct PrepareReq {
    account: String,
    chain: String,
    token: String,
    /// Human-readable token units, supplied as text to preserve every digit.
    amount: String,
}

fn format_points(n: i64) -> String {
    if n == 1 {
        "1 point".to_string()
    } else {
        format!("{n} points")
    }
}

/// Pad the fractional part to the asset's precision and parse once as an integer.
fn base_units(amount: &str, decimals: u32) -> Option<u128> {
    let amount = amount.trim();
    let (whole, fraction) = amount.split_once('.').unwrap_or((amount, ""));
    if amount.len() > 80
        || fraction.len() > decimals as usize
        || !whole
            .bytes()
            .chain(fraction.bytes())
            .all(|b| b.is_ascii_digit())
    {
        return None;
    }
    let digits = format!("{whole}{fraction:0<width$}", width = decimals as usize);
    digits.parse().ok().filter(|&raw| raw > 0)
}

fn eth_transfer(
    sender: &str,
    recipient: &str,
    spec: &TokenSpec,
    amount: u128,
    network: &str,
) -> Value {
    match spec.contract {
        Some(contract) => {
            let to_hex = recipient.strip_prefix("0x").unwrap_or(recipient);
            json!({
                "from": sender, "to": contract, "chainId": network, "value": "0x0",
                // ERC-20 transfer(address,uint256), both arguments ABI-encoded to 32 bytes.
                "data": format!("0xa9059cbb{:0>64}{amount:064x}", to_hex),
            })
        }
        None => {
            json!({"from": sender, "to": recipient, "chainId": network, "value": format!("0x{amount:x}")})
        }
    }
}

fn sol_transfer(
    sender: &str,
    recipient: &str,
    spec: &TokenSpec,
    amount: u64,
    blockhash: &str,
    memo: &str,
) -> Result<Transaction, &'static str> {
    let payer: Address = sender.parse().map_err(|_| "invalid Solana sender")?;
    let recipient = recipient.parse().map_err(|_| "invalid Solana recipient")?;
    let blockhash = blockhash.parse().map_err(|_| "invalid recent blockhash")?;
    let memo_program: Address = MEMO_PROGRAM_ID
        .parse()
        .map_err(|_| "invalid memo program")?;
    let mut instructions = match spec.contract {
        None => vec![solana_system_interface::instruction::transfer(
            &payer, &recipient, amount,
        )],
        Some(mint) => {
            let mint = mint.parse().map_err(|_| "invalid token mint")?;
            let program = spl_token_interface::id();
            vec![
                create_associated_token_account_idempotent(&payer, &recipient, &mint, &program),
                spl_token_interface::instruction::transfer_checked(
                    &program,
                    &get_associated_token_address(&payer, &mint),
                    &mint,
                    &get_associated_token_address(&recipient, &mint),
                    &payer,
                    &[],
                    amount,
                    spec.decimals as u8,
                )
                .map_err(|_| "invalid token transfer")?,
            ]
        }
    };
    instructions.push(Instruction {
        program_id: memo_program,
        accounts: vec![],
        data: memo.as_bytes().to_vec(),
    });
    let message = Message::new_with_blockhash(&instructions, Some(&payer), &blockhash);
    Ok(Transaction::new_unsigned(message))
}

async fn solana_transaction_wire(
    st: &AppState,
    sender: &str,
    recipient: &str,
    spec: &TokenSpec,
    amount: u128,
) -> Result<(Value, Option<u64>), Response> {
    let amount = u64::try_from(amount).map_err(|_| {
        api_err(
            StatusCode::BAD_REQUEST,
            "Amount exceeds the Solana transfer limit.",
        )
    })?;
    let latest = rpc(
        &st.sol_rpc_url,
        "getLatestBlockhash",
        json!([{"commitment": "confirmed"}]),
    )
    .await
    .map_err(|e| rpc_unavailable("getLatestBlockhash", e))?;
    let memo = format!("lets-embed:{}", uuid::Uuid::new_v4().simple());
    let tx = sol_transfer(
        sender,
        recipient,
        spec,
        amount,
        latest["value"]["blockhash"].as_str().unwrap_or(""),
        &memo,
    )
    .map_err(|msg| api_err(StatusCode::BAD_GATEWAY, msg))?;
    let wire = bincode::serialize(&tx).map_err(|_| {
        api_err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Could not encode the transfer.",
        )
    })?;
    let last_valid_block_height = latest["value"]["lastValidBlockHeight"].as_u64();
    Ok((json!(STANDARD.encode(wire)), last_valid_block_height))
}

#[worker::send]
pub async fn prepare(
    State(st): State<AppState>,
    headers: HeaderMap,
    cookies: Cookies,
    Json(req): Json<PrepareReq>,
) -> Result<Json<Value>, Response> {
    auth::require_same_origin(&st, &headers)?;
    let active = identity::require_active_session(&st, &cookies).await?;
    if req.account != active.user_id && req.account != active.do_key {
        return Err(api_err(
            StatusCode::CONFLICT,
            "Your gallery account changed. Reload before paying.",
        ));
    }
    let Some(chain) = Chain::parse(req.chain.trim()) else {
        return Err(api_err(StatusCode::BAD_REQUEST, "Unsupported chain."));
    };
    let symbol = req.token.trim().to_ascii_lowercase();
    let spec = config::token(chain, &symbol)
        .ok_or_else(|| api_err(StatusCode::BAD_REQUEST, "Unsupported asset."))?;
    let amount = base_units(&req.amount, spec.decimals).ok_or_else(|| {
        api_err(
            StatusCode::BAD_REQUEST,
            &format!(
                "Enter a positive amount with up to {} decimal places.",
                spec.decimals
            ),
        )
    })?;
    match do_client::do_status(&st.env, &active.do_key).await {
        Ok(status) if status.banned => {
            return Err(api_err(
                StatusCode::FORBIDDEN,
                "This account is suspended. New payments are disabled.",
            ));
        }
        Ok(_) => {}
        Err(e) => {
            worker::console_error!("do status failed during prepare: {e:?}");
            return Err(api_err(
                StatusCode::SERVICE_UNAVAILABLE,
                "Account status unavailable, retry later.",
            ));
        }
    }
    let policy = settings::load(&st.env).await.map_err(payment_db_error)?;
    let (sender, recipient) = match chain {
        Chain::Ethereum => (eth_sender(&st, &active.user_id).await?, policy.eth_deposit),
        Chain::Solana => (solana_sender(&st, &active.user_id).await?, policy.sol_deposit),
    };
    if !settings::valid_deposit_address(chain, &recipient) {
        return Err(api_err(
            StatusCode::CONFLICT,
            "New deposits on this chain are closed.",
        ));
    }
    if sender == recipient {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            "The deposit wallet cannot pay itself.",
        ));
    }
    // Validate the payment RPC network (and Ethereum mainnet for Chainlink feeds)
    // before resolving prices so misconfigured RPCs report 503 rather than 502.
    let network = match chain {
        Chain::Ethereum => verify_ethereum_network(&st).await?,
        Chain::Solana => {
            let sol_net = verify_solana_network(&st).await?;
            if spec.feed.is_some() {
                verify_ethereum_network(&st).await?;
            }
            sol_net.to_string()
        }
    };
    let price = resolve_price(&st, spec).await?;
    let estimate = rates::points_at_rate(amount, spec.decimals, price, policy.points_per_usd);
    if estimate < policy.minimum_topup {
        return Err(api_err(
            StatusCode::BAD_REQUEST,
            &format!(
                "This amount is worth about {}. The minimum top-up is {}.",
                format_points(estimate),
                format_points(policy.minimum_topup)
            ),
        ));
    }
    let (transaction, last_valid_block_height) = match chain {
        Chain::Ethereum => (
            eth_transfer(&sender, &recipient, spec, amount, &network),
            None,
        ),
        Chain::Solana => solana_transaction_wire(&st, &sender, &recipient, spec, amount).await?,
    };
    let mut resp = json!({
        "sender": sender,
        "recipient": recipient,
        "network": network,
        "transaction": transaction,
        "estimated_points": estimate,
    });
    if let Some(height) = last_valid_block_height {
        resp["last_valid_block_height"] = json!(height);
    }
    Ok(Json(resp))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decimal_amounts_are_exact_and_never_rounded_into_a_transfer() {
        assert_eq!(base_units(" .25 ", 6), Some(250_000));
        assert_eq!(
            base_units("1.000000000000000001", 18),
            Some(10u128.pow(18) + 1)
        );
        assert_eq!(
            base_units("9007199254.740993", 6),
            Some(9_007_199_254_740_993)
        );
        for invalid in ["", ".", "0.00", "-1", "+1", "1e3", "1.2.3", "0.0000001"] {
            assert_eq!(base_units(invalid, 6), None, "{invalid}");
        }
        assert_eq!(base_units(&u128::MAX.to_string(), 18), None);
    }

    #[test]
    fn ethereum_requests_use_the_registry_and_exact_base_units() {
        let sender = "0x1111111111111111111111111111111111111111";
        let recipient = "0x2222222222222222222222222222222222222222";
        for spec in config::TOKENS.iter().filter(|s| s.chain == Chain::Ethereum) {
            let tx = eth_transfer(sender, recipient, spec, 1_000_001, "0x1");
            assert_eq!(tx["from"], sender);
            assert_eq!(tx["chainId"], "0x1");
            if let Some(contract) = spec.contract {
                assert_eq!(tx["to"], contract);
                assert_eq!(tx["value"], "0x0");
                assert_eq!(
                    tx["data"],
                    concat!(
                        "0xa9059cbb0000000000000000000000002222222222222222222222222222222222222222",
                        "00000000000000000000000000000000000000000000000000000000000f4241"
                    )
                );
            } else {
                assert_eq!(tx["to"], recipient);
                assert_eq!(tx["value"], "0xf4241");
                assert!(tx.get("data").is_none());
            }
        }
    }

    #[test]
    fn solana_wallet_signs_as_payer_for_native_and_checked_token_transfers() {
        let payer = Address::new_from_array([1; 32]);
        let recipient = Address::new_from_array([2; 32]);
        let blockhash = bs58::encode([3; 32]).into_string();
        let memo_program: Address = MEMO_PROGRAM_ID.parse().unwrap();
        for spec in config::TOKENS.iter().filter(|s| s.chain == Chain::Solana) {
            let tx = sol_transfer(
                &payer.to_string(),
                &recipient.to_string(),
                spec,
                1_000_001,
                &blockhash,
                "lets-embed:checkout-a",
            )
            .unwrap();
            let tx_b = sol_transfer(
                &payer.to_string(),
                &recipient.to_string(),
                spec,
                1_000_001,
                &blockhash,
                "lets-embed:checkout-b",
            )
            .unwrap();
            let wire = bincode::serialize(&tx).unwrap();
            let wire_b = bincode::serialize(&tx_b).unwrap();
            // Distinct checkout references produce distinct wire bytes even on the same blockhash.
            assert_ne!(wire, wire_b);
            // Legacy transaction prefix declares one signature, left for the wallet.
            assert_eq!(wire[0], 1);
            assert_eq!(&wire[1..65], &[0; 64]);
            let message = tx.message;
            assert_eq!(message.recent_blockhash.to_string(), blockhash);
            let keys = &message.account_keys;
            assert_eq!(keys[0], payer);
            assert_eq!(message.header.num_required_signatures, 1);
            let memo = message.instructions.last().unwrap();
            assert_eq!(keys[usize::from(memo.program_id_index)], memo_program);
            assert_eq!(memo.data, b"lets-embed:checkout-a");
            let transfer = &message.instructions[message.instructions.len() - 2];
            let accounts: Vec<_> = transfer
                .accounts
                .iter()
                .map(|i| keys[*i as usize])
                .collect();
            if let Some(mint) = spec.contract {
                let mint = mint.parse().unwrap();
                let destination = get_associated_token_address(&recipient, &mint);
                let create = &message.instructions[0];
                assert_eq!(message.instructions.len(), 3);
                assert_eq!(
                    keys[usize::from(create.program_id_index)],
                    spl_associated_token_account_interface::program::id()
                );
                assert_eq!(create.data, [1]); // CreateIdempotent
                assert_eq!(keys[usize::from(create.accounts[1])], destination);
                assert_eq!(keys[usize::from(create.accounts[2])], recipient);
                assert_eq!(
                    keys[usize::from(transfer.program_id_index)],
                    spl_token_interface::id()
                );
                assert_eq!(
                    accounts,
                    [
                        get_associated_token_address(&payer, &mint),
                        mint,
                        destination,
                        payer
                    ]
                );
                assert_eq!(transfer.data, [12, 65, 66, 15, 0, 0, 0, 0, 0, 6]); // TransferChecked, u64, decimals
            } else {
                assert_eq!(message.instructions.len(), 2);
                assert_eq!(
                    keys[usize::from(transfer.program_id_index)],
                    Address::default()
                );
                assert_eq!(accounts, [payer, recipient]);
                assert_eq!(transfer.data, [2, 0, 0, 0, 65, 66, 15, 0, 0, 0, 0, 0]); // System transfer
            }
        }
    }
}
