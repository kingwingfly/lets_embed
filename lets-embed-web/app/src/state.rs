use axum::extract::FromRef;
use leptos::config::LeptosOptions;
use leptos::prelude::{ServerFnError, use_context};
use std::{path::PathBuf, sync::Arc};

pub use search_engine::{
    CallerContext, CompiledPolicy, Engine, MediaSigner, SafetyFilter, SeedLockedError,
};

use crate::policy_sync::PolicyStore;

/// Explicit deployment mode for `lets-embed-web` (never inferred implicitly).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum DeploymentMode {
    #[default]
    Standalone,
    Managed,
}

impl DeploymentMode {
    pub const fn is_managed(self) -> bool {
        matches!(self, Self::Managed)
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Standalone => "standalone",
            Self::Managed => "managed",
        }
    }
}

/// Immutable per-request safety & caller context pinned once by Axum middleware.
#[derive(Debug, Clone)]
pub struct RequestSafetyContext {
    pub mode: DeploymentMode,
    pub policy: Arc<CompiledPolicy>,
    pub caller: CallerContext,
    pub signer: MediaSigner,
    pub trust_proxy: bool,
}

impl RequestSafetyContext {
    pub fn standalone(policy: Arc<CompiledPolicy>, trust_proxy: bool) -> Self {
        Self {
            mode: DeploymentMode::Standalone,
            policy,
            caller: CallerContext::anonymous(),
            signer: MediaSigner::Standalone,
            trust_proxy,
        }
    }

    pub fn standalone_disabled() -> Self {
        Self::standalone(Arc::new(CompiledPolicy::disabled()), false)
    }

    pub fn safety_filter(&self) -> SafetyFilter<'_> {
        SafetyFilter::new(&self.policy, &self.caller)
    }

    pub fn effective_dinov3_min(&self, user_override: Option<f32>) -> Option<f32> {
        match user_override {
            Some(v) => Some(v),
            None => {
                let d = self.policy.policy.similarity.dinov3_min;
                (d.is_finite() && d > 0.0).then_some(d)
            }
        }
    }

    pub fn effective_siglip2_min(&self, user_override: Option<f32>) -> Option<f32> {
        match user_override {
            Some(v) => Some(v),
            None => {
                let d = self.policy.policy.similarity.siglip2_min;
                (d.is_finite() && d > 0.0).then_some(d)
            }
        }
    }

    /// Resolve the per-request pinned context from Leptos/Axum request extensions.
    ///
    /// In Managed Mode, missing request context ALWAYS fails closed — never falls
    /// back to `CompiledPolicy::disabled()`.
    pub fn from_leptos_context(state: &AppState) -> Result<Self, ServerFnError> {
        if let Some(ctx) = use_context::<axum::http::request::Parts>()
            .and_then(|parts| parts.extensions.get::<Self>().cloned())
        {
            return Ok(ctx);
        }
        if state.mode.is_managed() {
            return Err(ServerFnError::Response(
                "request missing verified managed safety context".to_string(),
            ));
        }
        Ok(Self::standalone(
            state.policy_store.current_standalone(),
            state.trust_proxy,
        ))
    }
}

#[derive(Debug, Clone, FromRef)]
pub struct AppState {
    pub leptos_options: LeptosOptions,
    pub engine: Arc<Engine>,
    pub prefix: Arc<Option<PathBuf>>,
    pub public_url: Arc<Option<String>>,
    pub mode: DeploymentMode,
    pub trust_proxy: bool,
    pub policy_store: Arc<PolicyStore>,
    #[from_ref(skip)]
    pub gateway_assertion_secret: Option<Arc<Vec<u8>>>,
    #[from_ref(skip)]
    pub media_cap_secret: Option<Arc<Vec<u8>>>,
}
