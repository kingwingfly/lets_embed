//! UNIT 6: HTML pages (inline HTML + JS, gateway_worker aesthetic).
//!
//! Three server-rendered shells with inline vanilla JS that talks to the
//! `/user/api/*` endpoints:
//! - GET /user/login: SIWE wallet sign-in (EIP-4361 message, strict shape).
//! - GET /user/account: balance / plan / top-up / payments / logout.
//! - GET /user/favorites: paged list of likes (text links only, no media).
//!
//! Everything dynamic coming from Rust is passed through [`html_escape`];
//! JSON fetched client-side is rendered with `textContent` (never innerHTML).

use axum::{
    extract::State,
    http::{StatusCode, header},
    response::{Html, IntoResponse, Response},
};
use tower_cookies::Cookies;

use crate::{AppState, config, session::session_address};

// ---------------------------------------------------------------------------
// shared shell
// ---------------------------------------------------------------------------

const STYLE: &str = r##"<style>
:root{--bg:#f5f6f8;--card:#fff;--fg:#1f2329;--muted:#6b7280;--border:#e5e7eb;
--accent:#4f46e5;--accent-h:#4338ca;--danger:#dc2626;--ok:#059669;--warn:#d97706;
--radius:14px;--shadow:0 10px 30px rgba(0,0,0,.08)}
@media(prefers-color-scheme:dark){:root{--bg:#0e1116;--card:#171b22;--fg:#e6e8eb;
--muted:#9aa4b2;--border:#262c36;--shadow:0 10px 30px rgba(0,0,0,.45)}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;justify-content:center;align-items:flex-start;
background:radial-gradient(1200px 600px at 50% -10%,rgba(79,70,229,.14),transparent),var(--bg);
color:var(--fg);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;
line-height:1.55;padding:8vh 16px 6vh}
.wrap{width:100%;max-width:640px}
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--radius);
box-shadow:var(--shadow);padding:30px;margin:0 0 16px}
h1{font-size:22px;margin:0 0 4px;letter-spacing:-.01em}
h2{font-size:16px;margin:0 0 10px;letter-spacing:-.01em}
.sub{color:var(--muted);font-size:14px;margin:0 0 22px}
label{display:block;font-size:13px;font-weight:600;color:var(--muted);margin-bottom:8px}
input[type=text],select{width:100%;padding:10px 12px;border:1px solid var(--border);border-radius:10px;
background:transparent;color:var(--fg);font:inherit;transition:border-color .15s,box-shadow .15s}
input[type=text]:focus,select:focus{outline:none;border-color:var(--accent);box-shadow:0 0 0 3px rgba(79,70,229,.2)}
select{background:var(--card);margin-bottom:14px}
.btn{display:inline-flex;align-items:center;gap:6px;border:0;border-radius:10px;padding:10px 18px;font:inherit;
font-weight:600;cursor:pointer;color:#fff;background:var(--accent);transition:background .15s,transform .05s}
.btn:hover{background:var(--accent-h)}.btn:active{transform:translateY(1px)}
.btn:disabled{opacity:.55;cursor:default}
.btn.ghost{background:transparent;color:var(--danger);border:1px solid var(--border)}
.btn.ghost:hover{background:rgba(220,38,38,.08);border-color:var(--danger)}
.btn.small{padding:6px 12px;font-size:13px}
.full{width:100%;justify-content:center;margin-top:20px}
.badge{display:inline-flex;align-items:center;gap:6px;font-size:12px;font-weight:600;padding:4px 11px;border-radius:999px}
.badge.ok{color:var(--ok);background:rgba(5,150,105,.13)}
.badge.warn{color:var(--warn);background:rgba(217,119,6,.13)}
.badge.err{color:var(--danger);background:rgba(220,38,38,.13)}
a{color:var(--accent);text-decoration:none;font-weight:600}a:hover{text-decoration:underline}
.center{text-align:center}.icon{font-size:46px;line-height:1;margin-bottom:12px}
.meta{color:var(--muted);font-size:12px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}
.msg{white-space:pre-wrap;margin:12px 0 0;padding:12px 14px;background:rgba(127,127,127,.07);
border:1px solid var(--border);border-radius:10px;font-size:14px}
.msg.err{color:var(--danger);border-color:var(--danger)}
.msg.ok{color:var(--ok);border-color:var(--ok)}
.actions{display:flex;flex-wrap:wrap;gap:10px;align-items:center}
.empty{text-align:center;color:var(--muted);padding:32px 0;font-size:15px}
.headrow{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:8px}
.tablewrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:8px 10px;text-align:left;border-bottom:1px solid var(--border);white-space:nowrap}
th{color:var(--muted);font-weight:600}
dl.stats{display:grid;grid-template-columns:max-content 1fr;gap:6px 18px;margin:0;font-size:14px}
dl.stats dt{color:var(--muted);font-weight:600}dl.stats dd{margin:0}
ul.likes{list-style:none;margin:0;padding:0}
ul.likes li{display:flex;align-items:center;gap:10px;padding:10px 0;border-bottom:1px solid var(--border)}
ul.likes li .date{margin-left:auto;color:var(--muted);font-size:12px;white-space:nowrap}
.links{margin-top:18px;display:flex;gap:16px;flex-wrap:wrap}
</style>"##;

fn page(title: &str, body: &str) -> String {
    format!(
        r##"<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>{title}</title>{STYLE}
</head><body><div class="wrap">{body}</div></body></html>"##
    )
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// 302 to the login page with a `next` back-reference.
fn redirect_to_login(next: &str) -> Response {
    (
        StatusCode::FOUND,
        [(header::LOCATION, format!("/user/login?next={next}"))],
    )
        .into_response()
}

// ---------------------------------------------------------------------------
// GET /user/login
// ---------------------------------------------------------------------------

/// `__CHAIN_ID__` is substituted server-side (numeric, from `AppState`).
const LOGIN_BODY: &str = r##"<div class="card center">
<div class="icon">&#128274;</div>
<h1>Sign in with Ethereum</h1>
<p class="sub">Authenticate with your wallet to access your account.</p>
<button class="btn full" id="siwe-btn" type="button">Sign in with Ethereum</button>
<div class="msg" id="login-msg" hidden></div>
<div class="links" style="justify-content:center"><a href="/">&larr; Back to site</a></div>
</div>
<script>
"use strict";
var CHAIN_ID = __CHAIN_ID__;
var btn = document.getElementById("siwe-btn");
var msgEl = document.getElementById("login-msg");

function showMsg(text, cls) {
  msgEl.hidden = false;
  msgEl.className = "msg" + (cls ? " " + cls : "");
  msgEl.textContent = text;
}

function nextUrl() {
  var next = new URLSearchParams(location.search).get("next") || "/";
  // Browsers treat "\" as "/" when resolving URLs, so also reject backslashes
  // to keep "/\evil.com" from becoming a protocol-relative redirect.
  if (!next.startsWith("/") || next.startsWith("//") || next.includes("\\")) next = "/";
  return next;
}

if (!window.ethereum) {
  btn.disabled = true;
  showMsg("No Ethereum wallet detected. Please install a wallet extension (e.g. MetaMask) and reload this page.");
} else {
  btn.addEventListener("click", async function () {
    btn.disabled = true;
    try {
      var accounts = await window.ethereum.request({ method: "eth_requestAccounts" });
      var addr = accounts[0];
      if (!addr) throw new Error("no account returned by the wallet");
      var nr = await fetch("/user/api/nonce");
      if (!nr.ok) throw new Error("failed to fetch nonce (" + nr.status + ")");
      var nonce = (await nr.json()).nonce;
      var message = `${location.host} wants you to sign in with your Ethereum account:
${addr}

Sign in to lets_embed

URI: ${location.origin}/user/login
Version: 1
Chain ID: ${CHAIN_ID}
Nonce: ${nonce}
Issued At: ${new Date().toISOString()}`;
      var signature = await window.ethereum.request({
        method: "personal_sign",
        params: [message, addr],
      });
      var vr = await fetch("/user/api/verify", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ message: message, signature: signature }),
      });
      if (vr.ok) {
        showMsg("Signed in. Redirecting…", "ok");
        location = nextUrl();
        return;
      }
      var err;
      try { err = (await vr.json()).error; } catch (_) {}
      showMsg(err || "sign-in failed (" + vr.status + ")", "err");
    } catch (e) {
      showMsg(e && e.message ? e.message : String(e), "err");
    } finally {
      btn.disabled = false;
    }
  });
}
</script>"##;

#[worker::send]
pub async fn login_page(State(st): State<AppState>) -> Response {
    let body = LOGIN_BODY.replace("__CHAIN_ID__", &st.chain_id.to_string());
    Html(page("Sign in — lets_embed", &body)).into_response()
}

// ---------------------------------------------------------------------------
// GET /user/account
// ---------------------------------------------------------------------------

/// Server-rendered subscription plans table (from the frozen `config::PLANS`).
fn plans_table() -> String {
    let mut rows = String::new();
    for p in config::PLANS {
        let id = html_escape(p.id);
        let views = p
            .views_per_window
            .map_or_else(|| "unlimited".to_string(), |v| v.to_string());
        rows.push_str(&format!(
            r##"<tr><td>{id}</td><td>{price}</td><td>{views}</td><td>{searches}</td><td>{days}</td>
<td><button class="btn small subscribe-btn" type="button" data-plan="{id}">Subscribe</button></td></tr>"##,
            price = p.price_points,
            searches = p.searches_per_window,
            days = p.period_secs / 86_400,
        ));
    }
    format!(
        r##"<div class="tablewrap"><table>
<thead><tr><th>Plan</th><th>Price (points)</th><th>Views / 5h</th><th>Searches / 5h</th><th>Period (days)</th><th></th></tr></thead>
<tbody>{rows}</tbody></table></div>"##
    )
}

/// `__DEPOSIT_ADDRESS__` (HTML-escaped) and `__PLANS_TABLE__` are substituted
/// server-side.
const ACCOUNT_BODY: &str = r##"<div class="card">
<div class="headrow"><h1>Your account</h1><span class="badge err" id="banned-badge" hidden>Banned</span></div>
<p class="sub meta" id="acct-address">loading&hellip;</p>
<dl class="stats">
<dt>Balance</dt><dd id="acct-balance">&mdash;</dd>
<dt>Plan</dt><dd id="acct-plan">&mdash;</dd>
<dt>Quota remaining</dt><dd id="acct-quota">&mdash;</dd>
<dt>Period ends</dt><dd id="acct-period-end">&mdash;</dd>
<dt>Total views</dt><dd id="acct-views">&mdash;</dd>
</dl>
<div class="links"><a href="/user/favorites">My favorites</a><a href="/">&larr; Back to site</a></div>
</div>

<div class="card">
<h2>Top up</h2>
<p class="sub">Send ETH to the deposit address below, then paste the transaction hash to credit your balance.</p>
<label>Deposit address</label>
<p class="meta">__DEPOSIT_ADDRESS__</p>
<form id="topup-form">
<label for="tx-hash">Transaction hash</label>
<input type="text" id="tx-hash" placeholder="0x&hellip;" autocomplete="off" required>
<button class="btn full" type="submit" id="topup-btn">Credit top-up</button>
</form>
<div class="msg" id="topup-msg" hidden></div>
</div>

<div class="card">
<h2>Subscription</h2>
<p class="sub">Plans are paid from your point balance and renew automatically each period.</p>
__PLANS_TABLE__
<div class="actions" style="margin-top:14px">
<button class="btn ghost small" type="button" id="unsub-btn">Unsubscribe</button>
</div>
<div class="msg" id="sub-msg" hidden></div>
</div>

<div class="card">
<h2>Payment history</h2>
<div class="tablewrap"><table>
<thead><tr><th>Tx</th><th>Amount (wei)</th><th>Token</th><th>Points</th><th>Status</th><th>Date</th></tr></thead>
<tbody id="payments-body"></tbody>
</table></div>
<div class="empty" id="payments-empty" hidden>No payments yet.</div>
</div>

<div class="card">
<div class="actions">
<button class="btn ghost" type="button" id="logout-btn">Log out</button>
</div>
</div>

<script>
"use strict";
function fmtDate(epochSecs) {
  return new Date(epochSecs * 1000).toLocaleString();
}
function setMsg(id, text, cls) {
  var el = document.getElementById(id);
  el.hidden = false;
  el.className = "msg" + (cls ? " " + cls : "");
  el.textContent = text;
}
function setText(id, text) {
  document.getElementById(id).textContent = text;
}

async function loadMe() {
  var r = await fetch("/user/api/me");
  if (r.status === 401) {
    location = "/user/login?next=/user/account";
    return;
  }
  if (!r.ok) {
    setText("acct-address", "failed to load account (" + r.status + ")");
    return;
  }
  var me = await r.json();
  setText("acct-address", me.address);
  setText("acct-balance", String(me.balance) + " points");
  setText("acct-plan", me.plan ? me.plan : "none");
  setText("acct-quota", String(me.quota_remaining) + " points");
  setText("acct-period-end", me.period_end ? fmtDate(me.period_end) : "—");
  setText("acct-views", String(me.total_views));
  document.getElementById("banned-badge").hidden = !me.banned;
}

async function loadPayments() {
  var body = document.getElementById("payments-body");
  var empty = document.getElementById("payments-empty");
  var r = await fetch("/user/api/payments");
  if (!r.ok) return;
  var rows = await r.json();
  body.textContent = "";
  empty.hidden = rows.length !== 0;
  for (var i = 0; i < rows.length; i++) {
    var p = rows[i];
    var tr = document.createElement("tr");
    var cells = [p.tx_hash, p.amount_wei, p.token, String(p.points), p.status, fmtDate(p.created_at)];
    for (var j = 0; j < cells.length; j++) {
      var td = document.createElement("td");
      if (j === 0) td.className = "meta";
      td.textContent = cells[j];
      tr.appendChild(td);
    }
    body.appendChild(tr);
  }
}

document.getElementById("topup-form").addEventListener("submit", async function (ev) {
  ev.preventDefault();
  var btn = document.getElementById("topup-btn");
  btn.disabled = true;
  try {
    var txHash = document.getElementById("tx-hash").value.trim();
    var r = await fetch("/user/api/topup", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ tx_hash: txHash }),
    });
    if (r.ok) {
      var res = await r.json();
      setMsg("topup-msg", "Credited " + res.credited_points + " points. New balance: " + res.balance + ".", "ok");
      loadMe();
      loadPayments();
    } else if (r.status === 425) {
      setMsg("topup-msg", "Not enough confirmations yet — retry in a few minutes.", "err");
    } else {
      var err;
      try { err = (await r.json()).error; } catch (_) {}
      setMsg("topup-msg", err || "top-up failed (" + r.status + ")", "err");
    }
  } catch (e) {
    setMsg("topup-msg", e && e.message ? e.message : String(e), "err");
  } finally {
    btn.disabled = false;
  }
});

var subBtns = document.querySelectorAll(".subscribe-btn");
for (var i = 0; i < subBtns.length; i++) {
  subBtns[i].addEventListener("click", async function (ev) {
    var plan = ev.currentTarget.getAttribute("data-plan");
    try {
      var r = await fetch("/user/api/subscribe", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ plan: plan }),
      });
      if (r.ok) {
        setMsg("sub-msg", "Subscribed to " + plan + ".", "ok");
        loadMe();
      } else {
        var err;
        try { err = (await r.json()).error; } catch (_) {}
        setMsg("sub-msg", err || "subscribe failed (" + r.status + ")", "err");
      }
    } catch (e) {
      setMsg("sub-msg", e && e.message ? e.message : String(e), "err");
    }
  });
}

document.getElementById("unsub-btn").addEventListener("click", async function () {
  try {
    var r = await fetch("/user/api/unsubscribe", { method: "POST" });
    if (r.ok) {
      setMsg("sub-msg", "Unsubscribed.", "ok");
      loadMe();
    } else {
      var err;
      try { err = (await r.json()).error; } catch (_) {}
      setMsg("sub-msg", err || "unsubscribe failed (" + r.status + ")", "err");
    }
  } catch (e) {
    setMsg("sub-msg", e && e.message ? e.message : String(e), "err");
  }
});

document.getElementById("logout-btn").addEventListener("click", async function () {
  try { await fetch("/user/api/logout", { method: "POST" }); } catch (_) {}
  location = "/user/login";
});

loadMe();
loadPayments();
</script>"##;

#[worker::send]
pub async fn account_page(State(st): State<AppState>, cookies: Cookies) -> Response {
    if session_address(&cookies, &st.jwt_secret).is_none() {
        return redirect_to_login("/user/account");
    }
    let body = ACCOUNT_BODY
        .replace("__DEPOSIT_ADDRESS__", &html_escape(&st.deposit_address))
        .replace("__PLANS_TABLE__", &plans_table());
    Html(page("Account — lets_embed", &body)).into_response()
}

// ---------------------------------------------------------------------------
// GET /user/favorites
// ---------------------------------------------------------------------------

// No thumbnails on purpose: media requests consume points.
const FAVORITES_BODY: &str = r##"<div class="card">
<div class="headrow"><h1>Favorites</h1></div>
<p class="sub">Your liked posts, images and videos. Text links only &mdash; media loads cost points.</p>
<ul class="likes" id="likes-list"></ul>
<div class="empty" id="likes-empty" hidden>No favorites yet.</div>
<div class="msg err" id="likes-msg" hidden></div>
<div class="actions" style="margin-top:14px">
<button class="btn small" type="button" id="more-btn" hidden>Load more</button>
</div>
<div class="links"><a href="/user/account">&larr; Account</a><a href="/">Back to site</a></div>
</div>

<script>
"use strict";
var cursor = null;
var loadedAny = false;
var list = document.getElementById("likes-list");
var moreBtn = document.getElementById("more-btn");

function badgeFor(kind) {
  var span = document.createElement("span");
  span.className = "badge " + (kind === "video" ? "warn" : "ok");
  span.textContent = kind;
  return span;
}

function renderItem(it) {
  var li = document.createElement("li");
  li.appendChild(badgeFor(it.kind));
  if (it.kind === "post" || it.kind === "image") {
    var a = document.createElement("a");
    a.href = "/details/" + encodeURIComponent(it.target_id);
    a.textContent = (it.kind === "post" ? "post #" : "image #") + it.target_id;
    li.appendChild(a);
  } else {
    var span = document.createElement("span");
    span.textContent = "video #" + it.target_id;
    li.appendChild(span);
  }
  var date = document.createElement("span");
  date.className = "date";
  date.textContent = new Date(it.created_at * 1000).toLocaleString();
  li.appendChild(date);
  list.appendChild(li);
}

async function loadPage() {
  moreBtn.disabled = true;
  try {
    var url = "/user/api/likes?limit=50";
    if (cursor !== null) url += "&cursor=" + encodeURIComponent(cursor);
    var r = await fetch(url);
    if (r.status === 401) {
      location = "/user/login?next=/user/favorites";
      return;
    }
    if (!r.ok) {
      var err;
      try { err = (await r.json()).error; } catch (_) {}
      var msgEl = document.getElementById("likes-msg");
      msgEl.hidden = false;
      msgEl.textContent = err || "failed to load favorites (" + r.status + ")";
      return;
    }
    var data = await r.json();
    for (var i = 0; i < data.items.length; i++) renderItem(data.items[i]);
    loadedAny = loadedAny || data.items.length > 0;
    document.getElementById("likes-empty").hidden = loadedAny;
    cursor = data.next_cursor;
    moreBtn.hidden = cursor === null || cursor === undefined;
  } catch (e) {
    var m = document.getElementById("likes-msg");
    m.hidden = false;
    m.textContent = e && e.message ? e.message : String(e);
  } finally {
    moreBtn.disabled = false;
  }
}

moreBtn.addEventListener("click", loadPage);
loadPage();
</script>"##;

#[worker::send]
pub async fn favorites_page(State(st): State<AppState>, cookies: Cookies) -> Response {
    if session_address(&cookies, &st.jwt_secret).is_none() {
        return redirect_to_login("/user/favorites");
    }
    Html(page("Favorites — lets_embed", FAVORITES_BODY)).into_response()
}
