// Minimal browser-wallet & Telegram widget bridge for the Leptos CSR SPA.
// All UI rendering and application state live in Rust (`user_worker/web`).
(function () {
  "use strict";

  const ethProviders = new Map();
  const solProviders = new Map();

  // EIP-6963 discovery
  window.addEventListener("eip6963:announceProvider", function (ev) {
    const detail = ev && ev.detail;
    if (!detail || !detail.info || !detail.provider) return;
    const id = detail.info.uuid || detail.info.rdns || detail.info.name;
    if (!id) return;
    ethProviders.set(id, {
      id,
      name: detail.info.name || "Ethereum Wallet",
      provider: detail.provider,
    });
  });
  try {
    window.dispatchEvent(new Event("eip6963:requestProvider"));
  } catch (_) {}

  // Solana Wallet Standard discovery (strictly filter out non-Solana extensions!)
  function registerSolWallet(wallet) {
    if (!wallet || !wallet.name) return;
    const features = wallet.features || {};
    if (!features["standard:connect"] || !features["solana:signMessage"]) return;
    if (Array.isArray(wallet.chains) && wallet.chains.length > 0) {
      const hasSolanaChain = wallet.chains.some(
        (c) => typeof c === "string" && c.startsWith("solana:")
      );
      if (!hasSolanaChain) return;
    }
    const id = "ws:" + wallet.name;
    solProviders.set(id, { id, name: wallet.name, wallet, isStandard: true });
  }
  try {
    window.addEventListener("wallet-standard:register-wallet", function (ev) {
      if (ev && typeof ev.detail === "function") {
        ev.detail({ register: registerSolWallet });
      }
    });
    window.dispatchEvent(
      new CustomEvent("wallet-standard:app-ready", {
        detail: { register: registerSolWallet },
      })
    );
  } catch (_) {}

  function discoverEthProviders() {
    try {
      window.dispatchEvent(new Event("eip6963:requestProvider"));
    } catch (_) {}
    const out = [];
    for (const entry of ethProviders.values()) {
      out.push({ id: entry.id, name: entry.name });
    }
    if (out.length === 0 && window.ethereum) {
      out.push({ id: "window.ethereum", name: "Browser Ethereum Wallet" });
    }
    return JSON.stringify(out);
  }

  function getEthProvider(providerId) {
    if (providerId && ethProviders.has(providerId)) {
      return ethProviders.get(providerId).provider;
    }
    for (const entry of ethProviders.values()) {
      return entry.provider;
    }
    if (window.ethereum) return window.ethereum;
    throw new Error("No Ethereum wallet detected. Install MetaMask, Rabby, or Coinbase Wallet.");
  }

  function discoverSolProviders() {
    const out = [];
    for (const entry of solProviders.values()) {
      out.push({ id: entry.id, name: entry.name });
    }
    const fallbacks = [
      ["phantom", "Phantom", window.phantom && window.phantom.solana],
      ["solflare", "Solflare", window.solflare],
      ["backpack", "Backpack", window.backpack],
      ["solana", "Browser Solana Wallet", window.solana],
    ];
    for (const [id, name, prov] of fallbacks) {
      if (prov && !out.some((x) => x.name.toLowerCase() === name.toLowerCase())) {
        out.push({ id: "legacy:" + id, name });
      }
    }
    return JSON.stringify(out);
  }

  function getSolEntry(providerId) {
    if (providerId && solProviders.has(providerId)) {
      return solProviders.get(providerId);
    }
    if (providerId && providerId.startsWith("legacy:")) {
      const key = providerId.slice("legacy:".length);
      const map = {
        phantom: window.phantom && window.phantom.solana,
        solflare: window.solflare,
        backpack: window.backpack,
        solana: window.solana,
      };
      if (map[key]) return { isStandard: false, provider: map[key] };
    }
    for (const entry of solProviders.values()) {
      return entry;
    }
    const legacy =
      (window.phantom && window.phantom.solana) ||
      window.solflare ||
      window.backpack ||
      window.solana;
    if (legacy) return { isStandard: false, provider: legacy };
    throw new Error("No Solana wallet detected. Install Phantom, Solflare, or Backpack.");
  }

  const B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
  function base58Encode(bytes) {
    const digits = [0];
    for (let i = 0; i < bytes.length; i++) {
      let carry = bytes[i];
      for (let j = 0; j < digits.length; j++) {
        carry += digits[j] << 8;
        digits[j] = carry % 58;
        carry = (carry / 58) | 0;
      }
      while (carry > 0) {
        digits.push(carry % 58);
        carry = (carry / 58) | 0;
      }
    }
    let out = "";
    for (let k = 0; k < bytes.length && bytes[k] === 0; k++) out += "1";
    for (let q = digits.length - 1; q >= 0; q--) out += B58_ALPHABET[digits[q]];
    return out;
  }

  function bytesToBase64(bytes) {
    let bin = "";
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  function base64ToBytes(b64) {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  async function connectAndSignSiwe(providerId, domain, chainId, nonce, statement, uriOverride) {
    const provider = getEthProvider(providerId);
    const accounts = await provider.request({ method: "eth_requestAccounts" });
    if (!accounts || !accounts.length) {
      throw new Error("No Ethereum account returned by wallet.");
    }
    const address = accounts[0];
    const issuedAt = new Date().toISOString();
    const uri = uriOverride && uriOverride.length ? uriOverride : window.location.origin;
    const message = [
      `${domain} wants you to sign in with your Ethereum account:`,
      address,
      "",
      statement || "Sign in to gallery account.",
      "",
      `URI: ${uri}`,
      "Version: 1",
      `Chain ID: ${chainId}`,
      `Nonce: ${nonce}`,
      `Issued At: ${issuedAt}`,
    ].join("\n");
    const signature = await provider.request({
      method: "personal_sign",
      params: [message, address],
    });
    return JSON.stringify({ address, message, signature });
  }

  async function connectAndSignSolMessage(providerId, message) {
    const entry = getSolEntry(providerId);
    const msgBytes = new TextEncoder().encode(message);

    if (entry.isStandard) {
      const w = entry.wallet;
      const connectFeat = w.features["standard:connect"];
      const connected = await connectFeat.connect();
      const account = (connected && connected.accounts && connected.accounts[0]) || (w.accounts && w.accounts[0]);
      if (!account) throw new Error("No Solana account selected.");
      const signFeat = w.features["solana:signMessage"];
      if (!signFeat) throw new Error("Selected Solana wallet does not support message signing.");
      const res = await signFeat.signMessage({ account, message: msgBytes });
      const first = Array.isArray(res) ? res[0] : res;
      const sigBytes = first.signature instanceof Uint8Array ? first.signature : new Uint8Array(first.signature);
      const signedBytes = first.signedMessage
        ? first.signedMessage instanceof Uint8Array
          ? first.signedMessage
          : new Uint8Array(first.signedMessage)
        : null;
      return JSON.stringify({
        address: account.address,
        signature: base58Encode(sigBytes),
        signed_message: signedBytes ? bytesToBase64(signedBytes) : null,
      });
    }

    const p = entry.provider;
    const conn = await p.connect();
    const pubkey = (conn && conn.publicKey) || p.publicKey;
    if (!pubkey) throw new Error("No Solana account connected.");
    const address = typeof pubkey.toBase58 === "function" ? pubkey.toBase58() : String(pubkey);
    const signed = await p.signMessage(msgBytes, "utf8");
    const sigRaw = signed && signed.signature ? signed.signature : signed;
    const sigBytes = sigRaw instanceof Uint8Array ? sigRaw : new Uint8Array(sigRaw);
    return JSON.stringify({
      address,
      signature: base58Encode(sigBytes),
      signed_message: null,
    });
  }

  async function sendEthTx(providerId, txJson) {
    const provider = getEthProvider(providerId);
    const tx = JSON.parse(txJson);
    await provider.request({ method: "eth_requestAccounts" });
    if (tx.chainId) {
      const expectedChain = parseInt(String(tx.chainId), 16);
      try {
        await provider.request({
          method: "wallet_switchEthereumChain",
          params: [{ chainId: tx.chainId }],
        });
      } catch (err) {
        const detail = err && err.message ? err.message : String(err);
        throw new Error(
          `Wallet refused to switch to required Ethereum network (${tx.chainId}): ${detail}`
        );
      }
      const activeChainHex = await provider.request({ method: "eth_chainId" });
      const activeChain = parseInt(String(activeChainHex), 16);
      if (!Number.isFinite(activeChain) || activeChain !== expectedChain) {
        throw new Error(
          `Wallet is on chain ${activeChainHex}, but this payment requires ${tx.chainId}. Switch networks in your wallet and retry.`
        );
      }
    }
    const params = { from: tx.from, to: tx.to, value: tx.value || "0x0" };
    if (tx.chainId) params.chainId = tx.chainId;
    if (tx.data) params.data = tx.data;
    const hash = await provider.request({
      method: "eth_sendTransaction",
      params: [params],
    });
    return String(hash);
  }

  async function sendSolTx(providerId, base64WireTx) {
    const entry = getSolEntry(providerId);
    const txBytes = base64ToBytes(base64WireTx);

    if (entry.isStandard) {
      const w = entry.wallet;
      const connected = await w.features["standard:connect"].connect();
      const account = (connected && connected.accounts && connected.accounts[0]) || (w.accounts && w.accounts[0]);
      if (!account) throw new Error("No Solana account selected.");
      const sendFeat = w.features["solana:signAndSendTransaction"];
      if (!sendFeat) {
        throw new Error("Selected Solana wallet does not support signAndSendTransaction.");
      }
      const res = await sendFeat.signAndSendTransaction({
        account,
        transaction: txBytes,
        chain: "solana:mainnet",
      });
      const first = Array.isArray(res) ? res[0] : res;
      const sigBytes = first.signature instanceof Uint8Array ? first.signature : new Uint8Array(first.signature);
      return base58Encode(sigBytes);
    }

    throw new Error(
      "Your Solana wallet must support Wallet Standard signAndSendTransaction for one-click checkout. You can also send manually and paste the transaction signature below."
    );
  }

  function mountTelegramWidget(containerId, botUsername, authUrl) {
    const el = document.getElementById(containerId);
    const cleanBot = typeof botUsername === "string" ? botUsername.trim().replace(/^@+/, "") : "";
    if (!el || !cleanBot || !authUrl) return;
    el.innerHTML = "";
    const script = document.createElement("script");
    script.async = true;
    script.src = "https://telegram.org/js/telegram-widget.js?22";
    script.setAttribute("data-telegram-login", cleanBot);
    script.setAttribute("data-size", "large");
    script.setAttribute("data-radius", "10");
    // Use redirect callback (`data-auth-url`) instead of `data-onauth` so strict CSP
    // without 'unsafe-eval' never blocks Telegram login.
    script.setAttribute("data-auth-url", authUrl);
    el.appendChild(script);
  }

  async function copyText(text) {
    if (navigator.clipboard && navigator.clipboard.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand("copy");
    document.body.removeChild(ta);
    return ok;
  }

  window.__leWallet = {
    discoverEthProviders,
    discoverSolProviders,
    connectAndSignSiwe,
    connectAndSignSolMessage,
    sendEthTx,
    sendSolTx,
    mountTelegramWidget,
    copyText,
  };
})();
