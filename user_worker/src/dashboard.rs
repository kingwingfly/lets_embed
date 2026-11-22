use crate::{
    admin::html_escape,
    config,
    settings::{MAX_VALUE, Published},
};
use site_access::ChargeKind;
use std::fmt::Write;

fn number(name: &str, label: &str, value: i64, min: i64) -> String {
    format!(
        r#"<input aria-label="{label}" type="number" step="1" min="{min}" max="{MAX_VALUE}" name="{name}" value="{value}" required>"#
    )
}

fn tab_cls(active_tab: &str, tab: &str) -> &'static str {
    if active_tab == tab {
        "panel tab-panel is-active"
    } else {
        "panel tab-panel"
    }
}

pub fn settings_form(published: &Published, saved: bool, active_tab: &str) -> String {
    let p = &published.policy;
    let (wallet, public, mode) = if p.login_required {
        ("checked", "", "Wallet required")
    } else {
        ("", "checked", "Public browsing")
    };
    let save_message = if saved {
        "Settings saved"
    } else if published.revision == 0 {
        "Using deployment defaults"
    } else {
        "All changes saved"
    };
    let saved_banner = if saved {
        r#"<div class="admin-banner ok" role="status"><span>✓ Site settings saved and published immediately.</span><button type="button" class="banner-close" aria-label="Dismiss">&times;</button></div>"#
    } else {
        ""
    };
    let save_bar_cls = if active_tab == "accounts" {
        "save-bar is-hidden"
    } else {
        "save-bar"
    };
    let form_tab = if matches!(active_tab, "access" | "pricing" | "plans" | "payments") {
        active_tab
    } else {
        "access"
    };

    let mut out = format!(
        r##"<form id="settings" method="post" action="/user/admin/settings"><input type="hidden" name="revision" value="{rev}"><input type="hidden" name="active_tab" id="settings-active-tab" value="{form_tab}">{saved_banner}
<section class="{access_cls}" id="access" data-tab="access" role="tabpanel" aria-labelledby="tab-access"><div class="section-head"><div><h2>Browsing access</h2><p class="section-sub">Control whether visitors need a wallet and which folders are included in daily free allowances.</p></div><span class="pill">{mode}</span></div>
<fieldset class="modes"><legend class="sr">Visitor access</legend>
<label class="mode"><input type="radio" name="login_required" value="yes" {wallet}><span><strong>Require a wallet</strong><small>Visitors sign in before opening the gallery.</small></span></label>
<label class="mode"><input type="radio" name="login_required" value="no" {public}><span><strong>Public browsing</strong><small>Visitors can browse and use the daily allowances below.</small></span></label></fieldset>
<label class="folder-label" for="free-folders">Free media folders</label>
<textarea id="free-folders" name="free_media_folders" rows="3" aria-describedby="folder-help" placeholder="/images/Sample album">{folders}</textarea>
<p id="folder-help" class="hint">Leave empty to include all media folders, or enter one gallery path per line under /images or /videos. Daily allowances apply within those folders. Search results can list the full catalog.</p>
</section>
<section class="{pricing_cls}" id="pricing" data-tab="pricing" role="tabpanel" aria-labelledby="tab-pricing"><div class="section-head"><div><h2>Prices &amp; free access</h2><p class="section-sub">Configure per-item point pricing and daily UTC free quotas for guests and wallets.</p></div></div>
<p class="hint">An allowance of 0 closes the item to guests. Use −1 for unlimited free access. Guests share an allowance per IP address, and signed-in users receive one per wallet.</p>
<div class="tablewrap"><table class="rates"><thead><tr><th>Item</th><th>Points per item</th><th>Free per day</th></tr></thead><tbody>"##,
        rev = published.revision,
        access_cls = tab_cls(active_tab, "access"),
        pricing_cls = tab_cls(active_tab, "pricing"),
        folders = html_escape(&p.free_media_folders.join("\n"))
    );
    for kind in ChargeKind::ALL {
        let rule = p.item(kind);
        let id = kind.name();
        let label = kind.label();
        let price = number(
            &format!("{id}_price"),
            &format!("{label}, points per item"),
            rule.price,
            0,
        );
        let free = number(
            &format!("{id}_free"),
            &format!("{label}, free per day"),
            rule.daily_free,
            -1,
        );
        write!(
            out,
            "<tr><th>{label}</th><td>{price}</td><td>{free}</td></tr>"
        )
        .unwrap();
    }
    write!(
        out,
        r#"</tbody></table></div><p class="hint">A price of 0 makes an item free for wallet holders. Guests can access items with a daily allowance.</p></section>
<section class="{plans_cls}" id="plans" data-tab="plans" role="tabpanel" aria-labelledby="tab-plans"><div class="section-head"><div><h2>Subscription plans</h2><p class="section-sub">30-day recurring allowance tiers. Views and searches replenish every five hours.</p></div></div>
<p class="hint">Prices apply at purchase or renewal. Use −1 for unlimited view units.</p>
<div class="tablewrap"><table class="rates"><thead><tr><th>30-day plan</th><th>Price in points</th><th>View units</th><th>Searches</th></tr></thead><tbody>"#,
        plans_cls = tab_cls(active_tab, "plans"),
    )
    .unwrap();
    for plan in config::PLANS.iter().filter_map(|p1| p.plan(p1.id)) {
        let id = plan.id;
        write!(
            out,
            "<tr><th class=\"plan-name\">{id}</th><td>{}</td><td>{}</td><td>{}</td></tr>",
            number(
                &format!("{id}_price"),
                &format!("{id} price"),
                plan.price_points,
                0
            ),
            number(
                &format!("{id}_views"),
                &format!("{id} view units"),
                plan.views_per_window.unwrap_or(-1),
                -1
            ),
            number(
                &format!("{id}_searches"),
                &format!("{id} searches"),
                plan.searches_per_window,
                0
            )
        )
        .unwrap();
    }
    write!(
        out,
        r#"</tbody></table></div></section>
<section class="{payments_cls}" id="payments" data-tab="payments" role="tabpanel" aria-labelledby="tab-payments"><div class="section-head"><div><h2>Payments &amp; credits</h2><p class="section-sub">Exchange rate, minimum top-up, signup grant, and on-chain treasury addresses.</p></div></div>
<div class="fields three"><label>Points per USD{}</label><label>Minimum top-up, points{}</label><label>New wallet grant, points{}</label></div>
<div class="fields"><label>Ethereum deposit address<input type="text" name="eth_deposit" value="{}" maxlength="42" spellcheck="false" autocomplete="off" placeholder="0x…"></label>
<label>Solana deposit address<input type="text" name="sol_deposit" value="{}" maxlength="44" spellcheck="false" autocomplete="off" placeholder="Base58 public key"></label></div>
<p class="hint">An empty address closes the chain to new deposits. Transfers use the receiving address, minimum and points per USD in effect at their block time.</p></section>
<div class="{save_bar_cls}" id="settings-save-bar"><div class="save-status"><span class="save-dot" aria-hidden="true"></span><span id="save-state" role="status" aria-live="polite">{save_message}</span></div><button class="btn" type="submit">Save site settings</button></div></form>"#,
        number("points_per_usd", "Points per USD", p.points_per_usd, 1),
        number("minimum_topup", "Minimum top-up", p.minimum_topup, 1),
        number("signup_points", "New wallet grant", p.signup_points, 0),
        html_escape(&p.eth_deposit),
        html_escape(&p.sol_deposit),
        payments_cls = tab_cls(active_tab, "payments"),
    )
    .unwrap();
    out
}
