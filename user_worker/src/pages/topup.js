"use strict";

const topup = document.getElementById("topup");
const account = topup.dataset.account;
const ethAccount = account.startsWith("0x");
const chainSel = document.getElementById("topup-chain");
const tokenSel = document.getElementById("topup-token");
const solWalletWrap = document.getElementById("sol-wallet-wrap");
const solWalletSel = document.getElementById("sol-wallet");
const amountInput = document.getElementById("topup-amount");
const hashInput = document.getElementById("tx-hash");
const payBtn = document.getElementById("topup-btn");
const linkBtn = document.getElementById("sol-link-btn");
const claimMsg = document.getElementById("claim-msg");
const solSend = "solana:signAndSendTransaction";
const STALE_RECEIPT_MS = 24 * 60 * 60 * 1000;
let linkedSol = null;
let linkVersion = 0;
let paying = false;
let linking = false;
let userPickedSolWallet = false;

function bytesToBase64(bytes) {
  if (!bytes || typeof bytes.length !== "number") return null;
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin);
}

function solanaWallets(feature) {
  return solWallets.filter(w => w?.features?.[feature] && w.features["standard:connect"]);
}

function syncSolanaWalletSelect() {
  if (!solWalletWrap || !solWalletSel) return;
  const chain = chainSel.value;
  const feature = chain === "solana" ? solSend : "solana:signMessage";
  const wallets = solanaWallets(feature);
  const previous = solWalletSel.value;
  solWalletSel.textContent = "";
  wallets.forEach((w, index) => {
    const option = document.createElement("option");
    option.value = String(index);
    option.textContent = w.name || ("Solana wallet " + (index + 1));
    solWalletSel.appendChild(option);
  });
  const matchingIndex = linkedSol
    ? wallets.findIndex(w => w.accounts?.some(a => a.address === linkedSol))
    : -1;
  if (userPickedSolWallet && previous !== "" && Number(previous) < wallets.length) {
    solWalletSel.value = previous;
  } else if (matchingIndex >= 0) {
    solWalletSel.value = String(matchingIndex);
  } else if (wallets.length > 0) {
    solWalletSel.value = "0";
  }
  solWalletWrap.hidden = chain !== "solana" || wallets.length <= 1;
}

function updatePaymentControls() {
  const chain = chainSel.value;
  const eth = chain === "ethereum";
  const sender = eth ? account : linkedSol;
  const recipient = topup.dataset[chain];
  const banned = !!(typeof currentMe !== "undefined" && currentMe && currentMe.banned);
  syncSolanaWalletSelect();
  let help = "";
  if (banned) help = "This account is suspended. New payments are disabled.";
  else if (!recipient) help = "New deposits on this chain are closed. You can still recover an earlier transfer below.";
  else if (!sender) help = "Link your Solana wallet to pay from it.";
  else if (eth ? !window.ethereum?.request : !pickSolanaWallet(solSend, sender)) {
    help = "Open this page in a compatible wallet, or use the manual payment option below.";
  }
  setText("topup-help", help);
  document.getElementById("topup-help").hidden = !help;
  payBtn.disabled = paying || linking || !!help;
  chainSel.disabled = tokenSel.disabled = amountInput.disabled = paying;
  if (solWalletSel) solWalletSel.disabled = paying || linking;
  linkBtn.disabled = paying || linking;
  setText("amount-label", "Amount in " + tokenSel.value.toUpperCase());
  document.getElementById("sol-token-rent").hidden = eth || tokenSel.value === "sol";
  setText("manual-sender", recipient && sender
    ? "Send " + tokenSel.value.toUpperCase() + " directly from " + sender +
      " (as the transaction fee payer) on " + chainSel.selectedOptions[0].textContent +
      ", then check the transfer here."
    : "Choose the chain and asset used for your transfer above.");
}

function applyChain() {
  const chain = chainSel.value;
  const eth = chain === "ethereum";
  for (const option of tokenSel.options) {
    option.disabled = option.hidden = option.dataset.chain !== chain;
  }
  tokenSel.selectedIndex = Array.from(tokenSel.options).findIndex(option => !option.disabled);
  document.getElementById("sol-link").hidden = eth || !ethAccount;
  setText("deposit-address", topup.dataset[chain] || "Deposits closed");
  setText("tx-label", eth ? "Transaction hash" : "Transaction signature");
  hashInput.placeholder = eth ? "0x…" : "Base58 signature";
  hashInput.value = amountInput.value = "";
  document.getElementById("topup-msg").hidden = true;
  if (claimMsg) claimMsg.hidden = true;
  updatePaymentControls();
}

// Minimal base58 (Bitcoin alphabet) encoder for the wallet's signature bytes.
// Canonical base-x algorithm: each leading zero byte becomes one "1", and the
// leading-zeros loop stops one short of the end so an all-zero input still emits
// its final digit (matches the bs58 crate the server verifies with).
function bs58encode(bytes) {
  var ALPH = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  if (bytes.length === 0) return "";
  var digits = [0];
  for (var i = 0; i < bytes.length; i++) {
    var carry = bytes[i];
    for (var j = 0; j < digits.length; j++) {
      carry += digits[j] << 8;
      digits[j] = carry % 58;
      carry = (carry / 58) | 0;
    }
    while (carry > 0) { digits.push(carry % 58); carry = (carry / 58) | 0; }
  }
  var str = "";
  for (var k = 0; k < bytes.length - 1 && bytes[k] === 0; k++) str += "1";
  for (var q = digits.length - 1; q >= 0; q--) str += ALPH[digits[q]];
  return str;
}

function setLinked(addr) {
  linkedSol = ethAccount ? (addr || null) : account;
  document.getElementById("sol-linked-state").textContent =
    linkedSol ? ("Payment wallet · " + linkedSol) : "No Solana wallet linked yet.";
  document.getElementById("sol-link-btn").textContent =
    linkedSol ? "Change linked wallet" : "Link Solana wallet";
  updatePaymentControls();
}

async function loadLink() {
  if (!ethAccount) return;
  const version = linkVersion;
  try {
    var r = await fetch("/user/api/link_solana");
    if (!r.ok || version !== linkVersion) return;
    var d = await r.json();
    if (version !== linkVersion) return;
    setLinked(d.solana_address);
  } catch (_) {}
}

// ---- Solana wallet discovery (Wallet Standard) ---------------------------
// Modern Solana-capable wallets — including MetaMask (multichain accounts),
// Phantom, Solflare and Backpack — announce themselves via the Wallet Standard
// rather than a single injected `window.solana`. We run the standard app<->wallet
// handshake so any of them is discoverable, then fall back to a legacy injected
// provider (older Phantom) if no standard wallet registers.
var solWallets = [];
(function () {
  function register() {
    for (var i = 0; i < arguments.length; i++) {
      var wallet = arguments[i];
      if (wallet && solWallets.indexOf(wallet) === -1) {
        solWallets.push(wallet);
        try {
          wallet.features?.["standard:events"]?.on?.("change", updatePaymentControls);
        } catch (_) {}
      }
    }
    updatePaymentControls();
    return function () {};
  }
  var api = { register: register, get: function () { return solWallets.slice(); }, on: function () { return function () {}; } };
  try {
    window.addEventListener("wallet-standard:register-wallet", function (ev) { ev.detail(api); });
  } catch (e) {}
  try {
    window.dispatchEvent(new CustomEvent("wallet-standard:app-ready", { detail: api }));
  } catch (e) {}
})();

function pickSolanaWallet(feature = "solana:signMessage", address) {
  const wallets = solanaWallets(feature);
  if (!wallets.length) return undefined;
  if (userPickedSolWallet && solWalletSel && solWalletSel.value !== "") {
    const selected = wallets[Number(solWalletSel.value)];
    if (selected) return selected;
  }
  return wallets.find(w => address && w.accounts?.some(a => a.address === address)) || wallets[0];
}

// Prefer an account that advertises a Solana chain; else the first account.
function pickSolanaAccount(accounts) {
  for (var i = 0; i < accounts.length; i++) {
    var chains = accounts[i].chains || [];
    for (var j = 0; j < chains.length; j++) {
      if (chains[j].indexOf("solana:") === 0) return accounts[i];
    }
  }
  return accounts.length ? accounts[0] : null;
}

// Resolve a { address, sign(msgBytes) -> { signature, signedMessage } } signer,
// or null if no Solana-capable wallet is available. Connecting may prompt the wallet.
async function getSolanaSigner() {
  var w = pickSolanaWallet("solana:signMessage", linkedSol);
  if (w) {
    var res = await w.features["standard:connect"].connect();
    var accounts = (res && res.accounts && res.accounts.length ? res.accounts : w.accounts) || [];
    var solAcct = pickSolanaAccount(accounts);
    if (!solAcct) throw new Error("No Solana account in this wallet — enable one (e.g. in MetaMask) and try again.");
    return {
      address: solAcct.address,
      sign: async function (msgBytes) {
        var out = await w.features["solana:signMessage"].signMessage({ account: solAcct, message: msgBytes });
        return { signature: out[0].signature, signedMessage: out[0].signedMessage };
      },
    };
  }
  var provider = window.solana || (window.phantom && window.phantom.solana);
  if (provider && provider.connect) {
    var conn = await provider.connect();
    var pk = provider.publicKey || (conn && conn.publicKey);
    if (!pk) throw new Error("wallet did not return a public key");
    return {
      address: pk.toString(),
      sign: async function (msgBytes) {
        var signed = await provider.signMessage(msgBytes, "utf8");
        return { signature: signed && signed.signature ? signed.signature : signed, signedMessage: null };
      },
    };
  }
  return null;
}

linkBtn.addEventListener("click", async function () {
  if (!ethAccount) return;
  linking = true;
  updatePaymentControls();
  try {
    var signer = await getSolanaSigner();
    if (!signer) {
      setMsg("sol-link-msg", "No Solana-capable wallet found. Enable Solana in MetaMask (or install Phantom / another Solana wallet), then reload this page.", "err");
      return;
    }
    var solAddr = signer.address;
    var nr = await fetch("/user/api/nonce");
    if (!nr.ok) throw new Error("failed to fetch nonce (" + nr.status + ")");
    var nonce = (await nr.json()).nonce;
    // MUST match solana_link::challenge_message byte for byte.
    var message = "Link Solana wallet to " + account + "\nNonce: " + nonce;
    var signed = await signer.sign(new TextEncoder().encode(message));
    var sigBytes = signed.signature;
    var sigB58 = typeof sigBytes === "string" ? sigBytes : bs58encode(sigBytes);
    var payload = { solana_address: solAddr, signature: sigB58, nonce: nonce };
    var signedMsgB64 = bytesToBase64(signed.signedMessage);
    if (signedMsgB64) payload.signed_message = signedMsgB64;
    var r = await fetch("/user/api/link_solana", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (r.ok) {
      var lr = await r.json();
      linkVersion++;
      setLinked(lr.solana_address);
      setMsg("sol-link-msg", "Wallet linked. You can now top up with SOL/USDT/USDC.", "ok");
    } else {
      var err;
      try { err = (await r.json()).error; } catch (_) {}
      setMsg("sol-link-msg", err || "link failed (" + r.status + ")", "err");
    }
  } catch (e) {
    setMsg("sol-link-msg", e && e.message ? e.message : String(e), "err");
  } finally {
    linking = false;
    updatePaymentControls();
  }
});

function postTopup(path, body) {
  return fetch("/user/api/topup" + path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ ...body, account }),
  });
}

function isUserCanceled(error) {
  return error?.code === 4001
    || error?.code === "ACTION_REJECTED"
    || /user rejected|user denied|user cancel|rejected the request/i.test(error?.message || "");
}

// Some providers disconnect after broadcasting. A missing receipt requires
// checking wallet activity before the customer decides to send again.
async function broadcast(send) {
  try {
    return await send();
  } catch (error) {
    if (isUserCanceled(error)) throw error;
    throw new Error((error?.message || "The wallet did not return a receipt.") +
      " Check your wallet activity before paying again. You can recover a completed transfer below.");
  }
}

async function ethereumPayment(prepared) {
  const provider = window.ethereum;
  if (!provider?.request) {
    throw new Error("Open this page in a compatible Ethereum wallet, or use the manual payment option below.");
  }
  const network = prepared.network;
  if (BigInt(await provider.request({ method: "eth_chainId" })) !== BigInt(network)) {
    await provider.request({ method: "wallet_switchEthereumChain", params: [{ chainId: network }] });
  }
  const accounts = await provider.request({ method: "eth_requestAccounts" });
  const hasSender = Array.isArray(accounts) && accounts.some(a => a?.toLowerCase() === prepared.sender);
  if (!hasSender || BigInt(await provider.request({ method: "eth_chainId" })) !== BigInt(network)) {
    throw new Error("Select the signed-in Ethereum address and the payment network in your wallet.");
  }
  return broadcast(() => provider.request({ method: "eth_sendTransaction", params: [prepared.transaction] }));
}

async function connectSolanaPayment() {
  const wallets = solanaWallets(solSend);
  const wallet = pickSolanaWallet(solSend, linkedSol);
  if (!wallet) throw new Error("Open a Solana wallet that supports payments, or pay manually below.");
  const connected = await wallet.features["standard:connect"].connect();
  const accounts = (connected?.accounts?.length ? connected.accounts : wallet.accounts) || [];
  const payer = accounts.find(a => a.address === linkedSol);
  if (!payer) {
    const extra = wallets.length > 1 ? ", or choose another Solana wallet above." : ".";
    throw new Error("Select " + linkedSol + " in your Solana wallet" + extra);
  }
  return async function (prepared) {
    const feature = wallet.features?.[solSend];
    const versions = feature?.supportedTransactionVersions;
    const legacyOk = !versions || Array.from(versions).includes("legacy");
    const chainOk = !payer.chains?.length || payer.chains.includes(prepared.network);
    const featureOk = !payer.features?.length || payer.features.includes(solSend);
    if (payer.address !== prepared.sender || !chainOk || !featureOk || !legacyOk) {
      throw new Error("This Solana account cannot send this transfer on the payment network. Use the manual payment option below.");
    }
    const wire = Uint8Array.from(atob(prepared.transaction), byte => byte.charCodeAt(0));
    const sent = await broadcast(() => feature.signAndSendTransaction({
      account: payer, chain: prepared.network, transaction: wire, options: { preflightCommitment: "confirmed" },
    }));
    const signature = sent?.[0]?.signature;
    return signature?.length === 64 ? bs58encode(signature) : null;
  };
}

function validReceipt(chain, hash) {
  return typeof hash === "string" && (chain === "ethereum"
    ? /^0x[0-9a-f]{64}$/i.test(hash)
    : /^[1-9A-HJ-NP-Za-km-z]{64,88}$/.test(hash));
}

document.getElementById("topup-form").addEventListener("submit", async function (event) {
  event.preventDefault();
  if (payBtn.disabled) return;
  paying = true;
  updatePaymentControls();
  const chain = chainSel.value;
  const token = tokenSel.value;
  const amount = amountInput.value.trim();
  try {
    setMsg("topup-msg", "Preparing your payment…");
    const send = chain === "ethereum" ? ethereumPayment : await connectSolanaPayment();
    const response = await postTopup("/prepare", { chain, token, amount });
    let prepared = {};
    try { prepared = (await response.json()) || {}; } catch (_) {}
    if (!response.ok) throw new Error(prepared.error || "Could not prepare the payment.");
    if (prepared.recipient !== topup.dataset[chain] || prepared.sender !== (chain === "ethereum" ? account : linkedSol)) {
      throw new Error("The payment address changed. Reload to review the current details.");
    }
    setMsg("topup-msg", "Review " + amount + " " + token.toUpperCase() + " in your wallet for approximately " +
      prepared.estimated_points.toLocaleString() + " points.");
    const hash = await send(prepared);
    if (!validReceipt(chain, hash)) throw new Error("Your wallet returned an unreadable receipt. Check your wallet activity and recover the transfer below.");
    amountInput.value = "";
    document.getElementById("topup-msg").hidden = true;
    trackPayment(chain, token, hash, { lastValidBlockHeight: prepared.last_valid_block_height });
  } catch (error) {
    setMsg("topup-msg", isUserCanceled(error) ? "Canceled in your wallet." : (error?.message || String(error)), "err");
  } finally {
    paying = false;
    updatePaymentControls();
  }
});

// A separate key for each receipt lets multiple tabs submit independent payments.
// Resuming a receipt only calls the verifier. A wallet send requires form submission.
const pendingPrefix = "lets-embed:topup:" + account + ":";
const activeReceipts = new Map();

function parseSavedReceipt(raw) {
  if (!raw || raw === "pending") return { ts: Date.now(), lastValidBlockHeight: null };
  try {
    const parsed = JSON.parse(raw);
    return {
      ts: Number.isFinite(parsed?.ts) ? parsed.ts : Date.now(),
      lastValidBlockHeight: Number.isFinite(parsed?.lastValidBlockHeight) ? parsed.lastValidBlockHeight : null,
    };
  } catch (_) {
    return { ts: Date.now(), lastValidBlockHeight: null };
  }
}

function trackPayment(chain, token, hash, opts = {}) {
  const tx_hash = chain === "ethereum" ? hash.toLowerCase() : hash;
  const key = pendingPrefix + [chain, token, tx_hash].join("/");
  const existing = activeReceipts.get(key);
  if (existing) {
    existing.check();
    return;
  }
  const ts = Number.isFinite(opts.ts) ? opts.ts : Date.now();
  const lastValidBlockHeight = Number.isFinite(opts.lastValidBlockHeight) ? opts.lastValidBlockHeight : null;
  let saved = true;
  try {
    localStorage.setItem(key, JSON.stringify({ ts, lastValidBlockHeight }));
  } catch (_) { saved = false; }

  const row = document.createElement("div");
  row.className = "msg";
  const status = document.createElement("span");
  const reference = document.createElement("div");
  reference.className = "meta";
  reference.textContent = tx_hash;
  const actions = document.createElement("div");
  actions.className = "receipt-actions";
  const retry = document.createElement("button");
  retry.type = "button";
  retry.className = "btn small secondary";
  retry.textContent = "Check again";
  retry.hidden = true;
  const dismiss = document.createElement("button");
  dismiss.type = "button";
  dismiss.className = "btn small ghost";
  dismiss.textContent = "Dismiss";
  dismiss.hidden = true;
  actions.append(retry, dismiss);
  row.append(status, reference, actions);
  document.getElementById("topup-receipts").prepend(row);

  let inFlight = false;
  let dismissed = false;

  function removeReceipt() {
    dismissed = true;
    activeReceipts.delete(key);
    try { localStorage.removeItem(key); } catch (_) {}
    row.remove();
  }

  function finish(message, credited) {
    status.textContent = message;
    row.className = credited ? "msg ok" : "msg err";
    retry.hidden = true;
    dismiss.hidden = credited;
    activeReceipts.delete(key);
    try { localStorage.removeItem(key); } catch (_) {}
    loadPayments();
    if (credited) loadMe();
  }

  async function check() {
    if (inFlight || dismissed) return;
    inFlight = true;
    retry.hidden = true;
    retry.disabled = true;
    dismiss.hidden = true;
    row.className = "msg";
    try {
      for (let attempt = 0; attempt < 10; attempt++) {
        if (dismissed) return;
        let code = 0;
        let result = {};
        try {
          const response = await postTopup("", { chain, token, tx_hash });
          code = response.status;
          result = (await response.json()) || {};
        } catch (_) {}
        if (dismissed) return;
        if (code === 200 && Number.isFinite(result.credited_points)) {
          finish(result.credited_points.toLocaleString() + " points credited.", true);
          return;
        }
        if (code === 409 && result.status === "credited") {
          finish("This transfer has already been credited to your balance.", true);
          return;
        }
        if (code === 401) {
          const login = document.createElement("a");
          login.href = "/user/login?next=/user/account%23topup";
          login.textContent = "Sign back in";
          status.replaceChildren(login, " to the same gallery account to finish checking this transfer.");
          break;
        }
        if (code === 403) {
          // Retain the receipt in storage: re-linking the original Solana wallet
          // or signing in with the sending account can still resolve it.
          row.className = "msg err";
          status.textContent = (result.error || "Transfer sender does not match this account.") +
            " Restore the sending wallet and check again, or dismiss this receipt.";
          break;
        }
        if (code >= 400 && code < 500 && code !== 425 && code !== 429 && code !== 408) {
          finish(result.error || "The transfer could not be credited.", false);
          return;
        }
        const waiting = code === 425 ? "Waiting for network confirmation." : "Verification is temporarily unavailable.";
        if (attempt === 9) {
          status.textContent = waiting + " Check this receipt again later, or dismiss it if the transfer was replaced or canceled.";
          break;
        }
        status.textContent = waiting + " Checking automatically." +
          (saved ? "" : " Keep this receipt if you leave the page.");
        await new Promise(resolve => setTimeout(resolve, Math.min(60000, 5000 * 2 ** attempt)));
      }
      if (!dismissed) {
        retry.hidden = false;
        dismiss.hidden = false;
      }
    } finally {
      inFlight = false;
      retry.disabled = false;
    }
  }

  activeReceipts.set(key, { check, row });
  retry.addEventListener("click", check);
  dismiss.addEventListener("click", removeReceipt);
  if (opts.paused) {
    status.textContent = "Unconfirmed " + token.toUpperCase() +
      " transfer from earlier. Check again or dismiss if it was replaced or canceled.";
    retry.hidden = false;
    dismiss.hidden = false;
  } else {
    status.textContent = "Checking your " + token.toUpperCase() + " transfer…";
    check();
  }
}

document.getElementById("claim-form").addEventListener("submit", function (event) {
  event.preventDefault();
  const hash = hashInput.value.trim();
  if (!validReceipt(chainSel.value, hash)) {
    const target = claimMsg ? "claim-msg" : "topup-msg";
    setMsg(target, "Enter a valid " + (chainSel.value === "ethereum" ? "Ethereum transaction hash." : "Solana transaction signature."), "err");
    return;
  }
  document.getElementById("topup-msg").hidden = true;
  if (claimMsg) claimMsg.hidden = true;
  trackPayment(chainSel.value, tokenSel.value, hash);
  hashInput.value = "";
});

if (!ethAccount || (!topup.dataset.ethereum && topup.dataset.solana)) chainSel.value = "solana";
chainSel.options[0].disabled = !ethAccount;
chainSel.addEventListener("change", applyChain);
tokenSel.addEventListener("change", () => {
  amountInput.value = "";
  updatePaymentControls();
});
if (solWalletSel) {
  solWalletSel.addEventListener("change", () => {
    userPickedSolWallet = true;
    updatePaymentControls();
  });
}
window.addEventListener("ethereum#initialized", updatePaymentControls);
try {
  window.ethereum?.on?.("accountsChanged", updatePaymentControls);
  window.ethereum?.on?.("chainChanged", updatePaymentControls);
} catch (_) {}
applyChain();
setLinked(null);
loadLink();
try {
  for (const key of Object.keys(localStorage)) {
    if (!key.startsWith(pendingPrefix)) continue;
    const [chain, token, hash] = key.slice(pendingPrefix.length).split("/");
    if (validReceipt(chain, hash) && Array.from(tokenSel.options).some(o => o.dataset.chain === chain && o.value === token)) {
      const savedMeta = parseSavedReceipt(localStorage.getItem(key));
      const paused = Date.now() - savedMeta.ts > STALE_RECEIPT_MS;
      trackPayment(chain, token, hash, { ...savedMeta, paused });
    }
  }
} catch (_) {}
