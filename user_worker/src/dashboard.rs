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

pub fn settings_form(published: &Published, saved: bool) -> String {
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
    let mut out = format!(
        r##"<header class="page-head"><div><h1>Gallery controls</h1></div>
<a class="gallery-link" href="/">View gallery <span aria-hidden="true">↗</span></a></header>
<form id="settings" method="post" action="/user/admin/settings"><input type="hidden" name="revision" value="{rev}">
<section class="panel" id="access"><div class="section-head"><h2>Browsing access</h2><span class="pill">{mode}</span></div>
<fieldset class="modes"><legend class="sr">Visitor access</legend>
<label class="mode"><input type="radio" name="login_required" value="yes" {wallet}><span><strong>Require a wallet</strong><small>Visitors sign in before opening the gallery.</small></span></label>
<label class="mode"><input type="radio" name="login_required" value="no" {public}><span><strong>Public browsing</strong><small>Visitors can browse and use the daily allowances below.</small></span></label></fieldset>
<label class="folder-label" for="free-folders">Free media folders</label>
<textarea id="free-folders" name="free_media_folders" rows="2" aria-describedby="folder-help" placeholder="/images/Sample album">{folders}</textarea>
<p id="folder-help" class="hint">Leave empty to include all media folders, or enter one gallery path per line under /images or /videos. Daily allowances apply within those folders. Search results can list the full catalog.</p>
</section>
<section class="panel" id="pricing"><div class="section-head"><h2>Prices &amp; free access</h2></div>
<p class="hint">Set the points per item and the number of distinct items included each UTC day. An allowance of 0 closes the item to guests. Use −1 for unlimited free access. Guests share an allowance per IP address, and signed-in users receive one per wallet.</p>
<div class="tablewrap"><table class="rates"><thead><tr><th>Item</th><th>Points per item</th><th>Free per day</th></tr></thead><tbody>"##,
        rev = published.revision,
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
    out.push_str(r#"</tbody></table></div><p class="hint">A price of 0 makes an item free for wallet holders. Guests can access items with a daily allowance.</p></section>
<section class="panel" id="plans"><h2>Subscription plans</h2><p class="hint">Prices apply at purchase or renewal. Views and searches replenish every five hours. Use −1 for unlimited view units.</p>
<div class="tablewrap"><table class="rates"><thead><tr><th>30-day plan</th><th>Price in points</th><th>View units</th><th>Searches</th></tr></thead><tbody>"#);
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
    write!(out,r#"</tbody></table></div></section><section class="panel" id="payments"><h2>Payments &amp; credits</h2>
<div class="fields three"><label>Points per USD{}</label><label>Minimum top-up, points{}</label><label>New wallet grant, points{}</label></div>
<div class="fields"><label>Ethereum deposit address<input type="text" name="eth_deposit" value="{}" maxlength="42" spellcheck="false" autocomplete="off"></label>
<label>Solana deposit address<input type="text" name="sol_deposit" value="{}" maxlength="44" spellcheck="false" autocomplete="off"></label></div>
<p class="hint">An empty address closes the chain to new deposits. Transfers use the receiving address, minimum and points per USD in effect at their block time.</p></section>
<div class="save-bar"><span id="save-state" role="status" aria-live="polite">{save_message}</span><button class="btn" type="submit">Save site settings</button></div></form>"#,
    number("points_per_usd","Points per USD",p.points_per_usd,1),number("minimum_topup","Minimum top-up",p.minimum_topup,1),
    number("signup_points","New wallet grant",p.signup_points,0),html_escape(&p.eth_deposit),html_escape(&p.sol_deposit)).unwrap();
    out
}
