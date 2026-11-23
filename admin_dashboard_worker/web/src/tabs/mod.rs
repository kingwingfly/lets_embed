pub mod access;
pub mod accounts;
pub mod age_legal;
pub mod geo;
pub mod providers;
pub mod reports;
pub mod safety;
pub mod similarity;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminTab {
    Access,
    Accounts,
    Safety,
    Geo,
    AgeLegal,
    Similarity,
    Providers,
    Reports,
}

impl AdminTab {
    pub const ALL: [Self; 8] = [
        Self::Access,
        Self::Accounts,
        Self::Safety,
        Self::Geo,
        Self::AgeLegal,
        Self::Similarity,
        Self::Providers,
        Self::Reports,
    ];

    pub const fn slug(self) -> &'static str {
        match self {
            Self::Access => "access",
            Self::Accounts => "accounts",
            Self::Safety => "safety",
            Self::Geo => "geo",
            Self::AgeLegal => "age-legal",
            Self::Similarity => "similarity",
            Self::Providers => "providers",
            Self::Reports => "reports",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Access => "Access & Pricing",
            Self::Accounts => "Accounts & Payments",
            Self::Safety => "Content Safety",
            Self::Geo => "Geo-Blocking",
            Self::AgeLegal => "Age & Legal",
            Self::Similarity => "Similarity",
            Self::Providers => "Auth Providers",
            Self::Reports => "Reports",
        }
    }

    pub fn from_hash(raw: &str) -> Self {
        match raw.trim().trim_start_matches('#') {
            "accounts" => Self::Accounts,
            "safety" => Self::Safety,
            "geo" | "geo-blocking" | "similarity-geo" => Self::Geo,
            "age-legal" | "legal" => Self::AgeLegal,
            "similarity" | "search-similarity" => Self::Similarity,
            "providers" => Self::Providers,
            "reports" => Self::Reports,
            _ => Self::Access,
        }
    }
}
