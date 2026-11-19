//! Wire types used by the gateway and the account Durable Object.
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, KeyInit as _, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
// Discriminants are the published settings array indices. Append new kinds at the end.
#[repr(u8)]
pub enum ChargeKind {
    Image = 0,
    Video = 1,
    Search = 2,
    EmbedSearch = 3,
    Description = 4,
}
impl ChargeKind {
    pub const ALL: [Self; 5] = [
        Self::Image,
        Self::Video,
        Self::EmbedSearch,
        Self::Search,
        Self::Description,
    ];
    pub fn name(self) -> &'static str {
        match self {
            Self::Image => "image",
            Self::Video => "video",
            Self::EmbedSearch => "similar",
            Self::Search => "upload",
            Self::Description => "description",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Image => "Image views",
            Self::Video => "Video views",
            Self::EmbedSearch => "Similar-image searches",
            Self::Search => "Uploaded-image searches",
            Self::Description => "Description searches",
        }
    }
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ChargeReq {
    pub path: String,
    pub kind: ChargeKind,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct GuestReq {
    pub item: Option<ChargeReq>,
    pub head: bool,
}

pub const ADMIN_HEADER: &str = "x-gallery-admin-email";
pub const ADMIN_VIEW_COOKIE: &str = "__Host-ue_admin_view";
pub const VIEW_TTL: u64 = 15 * 60;

fn mac(secret: &[u8], purpose: &[u8], value: &[u8]) -> Hmac<Sha256> {
    let mut mac = Hmac::new_from_slice(secret).expect("HMAC accepts variable length keys");
    mac.update(purpose);
    mac.update(value);
    mac
}
/// A short-lived browsing pass, issued only after verifying the admin application
/// assertion. Admin mutations always require a fresh Access-authenticated request.
pub fn admin_view_pass(secret: &[u8], expiry: u64) -> String {
    let signature = mac(secret, b"admin-view/v1\0", &expiry.to_be_bytes())
        .finalize()
        .into_bytes();
    format!("{expiry}.{}", URL_SAFE_NO_PAD.encode(signature))
}
pub fn valid_admin_view(secret: &[u8], value: &str, now: u64) -> bool {
    let Some((exp, signature)) = value.split_once('.') else {
        return false;
    };
    let Ok(exp) = exp.parse::<u64>() else {
        return false;
    };
    if exp <= now || exp > now.saturating_add(VIEW_TTL) {
        return false;
    }
    let Ok(sig) = URL_SAFE_NO_PAD.decode(signature) else {
        return false;
    };
    mac(secret, b"admin-view/v1\0", &exp.to_be_bytes())
        .verify_slice(&sig)
        .is_ok()
}
pub fn guest_account(secret: &[u8], ip: std::net::IpAddr) -> String {
    let digest = mac(
        secret,
        b"guest/v1\0",
        ip.to_canonical().to_string().as_bytes(),
    )
    .finalize()
    .into_bytes();
    format!("guest:{}", URL_SAFE_NO_PAD.encode(digest))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn browsing_pass_is_scoped_and_expires() {
        let pass = admin_view_pass(b"local", 600);
        assert!(valid_admin_view(b"local", &pass, 500));
        assert!(!valid_admin_view(b"other", &pass, 500));
        assert!(!valid_admin_view(b"local", &pass, 600));
        assert!(!valid_admin_view(
            b"local",
            &pass.replace("600.", "601."),
            500
        ));
        assert!(!valid_admin_view(
            b"local",
            &admin_view_pass(b"local", 1800),
            1
        ));
    }
}
