pub mod access;
pub mod accounts;
pub mod age_legal;
pub mod providers;
pub mod reports;
pub mod safety;
pub mod similarity_geo;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminTab {
    Access,
    Accounts,
    Safety,
    SimilarityGeo,
    AgeLegal,
    Providers,
    Reports,
}

impl AdminTab {
    pub const ALL: [Self; 7] = [
        Self::Access,
        Self::Accounts,
        Self::Safety,
        Self::SimilarityGeo,
        Self::AgeLegal,
        Self::Providers,
        Self::Reports,
    ];

    pub const fn slug(self) -> &'static str {
        match self {
            Self::Access => "access",
            Self::Accounts => "accounts",
            Self::Safety => "safety",
            Self::SimilarityGeo => "similarity-geo",
            Self::AgeLegal => "age-legal",
            Self::Providers => "providers",
            Self::Reports => "reports",
        }
    }

    pub const fn label(self) -> &'static str {
        match self {
            Self::Access => "Access & Pricing",
            Self::Accounts => "Accounts & Payments",
            Self::Safety => "Content Safety",
            Self::SimilarityGeo => "Similarity & Geo",
            Self::AgeLegal => "Age & Legal",
            Self::Providers => "Auth Providers",
            Self::Reports => "Reports Queue",
        }
    }

    pub fn from_hash(raw: &str) -> Self {
        match raw.trim().trim_start_matches('#') {
            "accounts" => Self::Accounts,
            "safety" => Self::Safety,
            "similarity-geo" | "geo" => Self::SimilarityGeo,
            "age-legal" | "legal" => Self::AgeLegal,
            "providers" => Self::Providers,
            "reports" => Self::Reports,
            _ => Self::Access,
        }
    }
}
