//! Policy v3 content safety compiler, 3-valued logic (`TriBool`) evaluator,
//! multi-parent shared-image & video Block+Blur inheritance, bound exact-name
//! SQL filtering, single-snapshot `facts_rev` loading, and media projection /
//! `MediaCapability v3` signing.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fmt,
    sync::Arc,
};

use anyhow::{anyhow, bail};
use search_types::{
    Image, MaskMetadata, MediaKind, PlaceholderPreset, ProjectedImage, ProjectedVideo, Video,
    safety::{SafetyExpr, SafetyPredicate, TriBool, parse_safety_rule_legacy_precision},
};
use site_access::{
    ActorBinding, AgeVerificationPolicy, GatewayAssertion, MEDIA_CAP_AUDIENCE, MEDIA_CAP_VERSION,
    MediaCapKind, MediaCapability, PolicyAction, PolicyBypass, PolicyRef, PublicSitePolicy,
    UnclassifiedMode, compute_policy_digest, sign_media_capability, validate_policy_set_with_mode,
};
use sqlx::{Executor as _, PgPool, Postgres, QueryBuilder, Row as _};

/// Computes an order-independent, non-zero 53-bit `u64` fingerprint of an image's
/// own `facts_rev` and EVERY attached parent post's `(post_id, post_facts_rev)`.
///
/// Unlike `MAX(...)`, bumping ANY lower-revision parent or attaching/detaching a parent
/// ALWAYS changes the resulting `facts_rev`, immediately invalidating stale capabilities.
pub fn compute_image_facts_rev(image_own_rev: u64, parent_post_revs: &[(i64, u64)]) -> u64 {
    let mut pairs: Vec<(i64, u64)> = parent_post_revs
        .iter()
        .map(|&(pid, rev)| (pid, rev.max(1)))
        .collect();
    pairs.sort_unstable();
    pairs.dedup();
    let mut buf = Vec::with_capacity(24 + pairs.len() * 16);
    buf.extend_from_slice(b"img-facts-rev/v1\0");
    buf.extend_from_slice(&image_own_rev.max(1).to_be_bytes());
    for (pid, rev) in pairs {
        buf.extend_from_slice(&pid.to_be_bytes());
        buf.extend_from_slice(&rev.to_be_bytes());
    }
    digest_to_safe_u64(&buf)
}

/// Computes an order-independent, non-zero 53-bit `u64` fingerprint of a video's
/// own `facts_rev`, every parent post's `(post_id, post_facts_rev)`, and every
/// sibling image's `(post_id, image_id, image_own_facts_rev)`.
pub fn compute_video_facts_rev(
    video_own_rev: u64,
    parent_post_revs: &[(i64, u64)],
    sibling_image_revs: &[(i64, i64, u64)],
) -> u64 {
    let mut posts: Vec<(i64, u64)> = parent_post_revs
        .iter()
        .map(|&(pid, rev)| (pid, rev.max(1)))
        .collect();
    posts.sort_unstable();
    posts.dedup();
    let mut siblings: Vec<(i64, i64, u64)> = sibling_image_revs
        .iter()
        .map(|&(pid, iid, rev)| (pid, iid, rev.max(1)))
        .collect();
    siblings.sort_unstable();
    siblings.dedup();
    let mut buf = Vec::with_capacity(32 + posts.len() * 16 + siblings.len() * 24);
    buf.extend_from_slice(b"vid-facts-rev/v1\0");
    buf.extend_from_slice(&video_own_rev.max(1).to_be_bytes());
    buf.extend_from_slice(&(posts.len() as u64).to_be_bytes());
    for (pid, rev) in posts {
        buf.extend_from_slice(&pid.to_be_bytes());
        buf.extend_from_slice(&rev.to_be_bytes());
    }
    buf.extend_from_slice(&(siblings.len() as u64).to_be_bytes());
    for (pid, iid, rev) in siblings {
        buf.extend_from_slice(&pid.to_be_bytes());
        buf.extend_from_slice(&iid.to_be_bytes());
        buf.extend_from_slice(&rev.to_be_bytes());
    }
    digest_to_safe_u64(&buf)
}

fn digest_to_safe_u64(data: &[u8]) -> u64 {
    let hex = site_access::sha256_hex(data);
    let raw = u64::from_str_radix(&hex[..16], 16).unwrap_or(1);
    (raw & 0x001f_ffff_ffff_ffff).max(1)
}

/// Public/anonymous capability TTL (1 hour — bounded 1..6h for SEO/crawlers,
/// immediately invalidated by `min_enforce_rev` or `facts_rev` changes).
pub const PUBLIC_MEDIA_CAP_TTL_SECS: u64 = 3600;

/// Restricted clear-media capability TTL (5 minutes — bound to caller actor
/// and matched policy refs).
pub const RESTRICTED_MEDIA_CAP_TTL_SECS: u64 = 300;

/// Short-lived click-to-reveal clear capability TTL (15 minutes — minted ONLY
/// by same-origin CSRF-protected `POST /api/safety/reveal`).
pub const CLICK_REVEAL_MEDIA_CAP_TTL_SECS: u64 = 900;

/// Reserved marker appended to [`MaskMetadata::matched_policy_ids`] when a
/// placeholder restriction has no user self-service unlock path (e.g. neither
/// `include_switcher` nor `include_click` is enabled, `require_age_18` is
/// configured while `age_policy == Off`, or the asset is pending classification).
pub use search_types::MASK_NO_UNLOCK_MARKER;

/// Explicit error returned when a similarity search seed (`search_similar` or
/// `dino:<id>` / `-dino:<id>`) is not Clear for the caller or lacks trusted facts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedLockedError {
    pub image_id: i64,
    pub policy_id: String,
    pub label: String,
}

impl fmt::Display for SeedLockedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Seed image #{} is restricted by safety policy ({})",
            self.image_id, self.label
        )
    }
}

impl std::error::Error for SeedLockedError {}

/// Verified caller identity & Policy v3 grants pinned for a single request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerContext {
    pub actor: ActorBinding,
    pub direct_grants: HashSet<PolicyRef>,
    pub click_eligible: HashSet<PolicyRef>,
    pub is_billing_waived: bool,
    pub age_verified: bool,
    pub terms_accepted: bool,
}

impl Default for CallerContext {
    fn default() -> Self {
        Self {
            actor: ActorBinding::Anon,
            direct_grants: HashSet::new(),
            click_eligible: HashSet::new(),
            is_billing_waived: false,
            age_verified: false,
            terms_accepted: false,
        }
    }
}

impl CallerContext {
    pub fn anonymous() -> Self {
        Self::default()
    }

    pub fn from_assertion(assertion: &GatewayAssertion) -> Self {
        Self {
            actor: assertion.actor.clone(),
            direct_grants: assertion.direct_grants.iter().cloned().collect(),
            click_eligible: assertion.click_eligible.iter().cloned().collect(),
            is_billing_waived: assertion.is_billing_waived,
            age_verified: assertion.caller_age_verified,
            terms_accepted: assertion.caller_terms_accepted,
        }
    }

    pub fn is_authenticated(&self) -> bool {
        matches!(self.actor, ActorBinding::User { .. })
    }

    pub fn has_direct_grant(&self, policy_ref: &PolicyRef) -> bool {
        self.direct_grants.contains(policy_ref)
    }

    pub fn is_click_eligible(&self, policy_ref: &PolicyRef) -> bool {
        self.click_eligible.contains(policy_ref)
    }
}

/// Strategy used when turning evaluated media into `ProjectedImage` / `ProjectedVideo`.
#[derive(Debug, Clone)]
pub enum MediaSigner {
    /// Standalone mode: emits direct `/images/{encoded_name}.webp` and `/videos/{encoded_name}`
    /// for Clear assets; NEVER leaks clear URLs on Blurred or Placeholder assets.
    Standalone,
    /// Managed mode: emits HMAC-SHA256 signed `/media/{image|video|preview}/{id}?cap=mc3...`.
    Managed {
        secret: Arc<Vec<u8>>,
        now_secs: u64,
    },
}

/// Compiled leaf predicate bound directly to exact canonical names (ZERO DB ID lookup).
#[derive(Debug, Clone, PartialEq)]
pub enum CompiledPredicate {
    WdTag { name: String, min_score: f32 },
    PostTag(String),
    Author(String),
    Unclassified,
}

#[derive(Debug, Clone, PartialEq)]
pub enum CompiledExpr {
    Predicate(CompiledPredicate),
    Not(Box<CompiledExpr>),
    And(Vec<CompiledExpr>),
    Or(Vec<CompiledExpr>),
}

impl CompiledExpr {
    /// Evaluates this expression in 3-valued Kleene logic (`TriBool`) against
    /// a single `(image, parent_post_context)` pair.
    pub fn eval_tribool(
        &self,
        is_completed: bool,
        wd_vocab_matches: bool,
        wd_min_persisted_score: Option<f32>,
        wd_tag_scores: &HashMap<String, f32>,
        post_tags: &HashSet<String>,
        authors: &HashSet<String>,
    ) -> TriBool {
        match self {
            Self::Predicate(pred) => match pred {
                CompiledPredicate::WdTag { name, min_score } => {
                    if !is_completed {
                        return TriBool::Unknown;
                    }
                    if let Some(&score) = wd_tag_scores.get(name) {
                        TriBool::from_bool(score >= *min_score)
                    } else if wd_vocab_matches
                        && wd_min_persisted_score.is_some_and(|floor| floor <= *min_score)
                    {
                        TriBool::False
                    } else {
                        TriBool::Unknown
                    }
                }
                CompiledPredicate::PostTag(name) => TriBool::from_bool(post_tags.contains(name)),
                CompiledPredicate::Author(name) => TriBool::from_bool(authors.contains(name)),
                CompiledPredicate::Unclassified => TriBool::from_bool(!is_completed),
            },
            Self::Not(inner) => inner
                .eval_tribool(
                    is_completed,
                    wd_vocab_matches,
                    wd_min_persisted_score,
                    wd_tag_scores,
                    post_tags,
                    authors,
                )
                .not(),
            Self::And(items) => items.iter().fold(TriBool::True, |acc, item| {
                acc.and(item.eval_tribool(
                    is_completed,
                    wd_vocab_matches,
                    wd_min_persisted_score,
                    wd_tag_scores,
                    post_tags,
                    authors,
                ))
            }),
            Self::Or(items) => items.iter().fold(TriBool::False, |acc, item| {
                acc.or(item.eval_tribool(
                    is_completed,
                    wd_vocab_matches,
                    wd_min_persisted_score,
                    wd_tag_scores,
                    post_tags,
                    authors,
                ))
            }),
        }
    }

    pub fn uses_post_context(&self) -> bool {
        match self {
            Self::Predicate(CompiledPredicate::PostTag(_) | CompiledPredicate::Author(_)) => true,
            Self::Predicate(_) => false,
            Self::Not(inner) => inner.uses_post_context(),
            Self::And(items) | Self::Or(items) => items.iter().any(Self::uses_post_context),
        }
    }

    pub fn references_wd_tags(&self) -> bool {
        match self {
            Self::Predicate(CompiledPredicate::WdTag { .. }) => true,
            Self::Predicate(_) => false,
            Self::Not(inner) => inner.references_wd_tags(),
            Self::And(items) | Self::Or(items) => items.iter().any(Self::references_wd_tags),
        }
    }

    /// Push a parameterized Postgres 3-valued (`TRUE` / `FALSE` / `NULL` = `Unknown`)
    /// SQL expression referencing `images` alias `img_alias` and optional parent-post
    /// column expression `post_id_expr` (e.g. `Some("pi.post_id")` or `None` for orphan).
    ///
    /// Uses bound exact-name joins (`wt.name = $k`, `t.name = $k`, `a.name = $k`) so missing
    /// tags in Postgres NEVER cause 503 errors and new tags take effect immediately.
    pub fn push_tribool_sql(
        &self,
        qb: &mut QueryBuilder<Postgres>,
        img_alias: &'static str,
        post_id_expr: Option<&'static str>,
        expected_vocab_digest: &str,
    ) {
        match self {
            Self::Predicate(pred) => match pred {
                CompiledPredicate::WdTag { name, min_score } => {
                    qb.push("(CASE WHEN ");
                    qb.push(img_alias);
                    qb.push(".status <> 'completed'::process_status THEN NULL ");
                    qb.push("WHEN EXISTS (SELECT 1 FROM wd_tag_images wti JOIN wd_tags wt ON wt.id = wti.wd_tag_id WHERE wti.image_id = ");
                    qb.push(img_alias);
                    qb.push(".id AND wt.name = ");
                    qb.push_bind(name.clone());
                    qb.push(" AND wti.score >= ");
                    qb.push_bind(*min_score);
                    qb.push(") THEN TRUE ");
                    qb.push("WHEN EXISTS (SELECT 1 FROM wd_tag_images wti JOIN wd_tags wt ON wt.id = wti.wd_tag_id WHERE wti.image_id = ");
                    qb.push(img_alias);
                    qb.push(".id AND wt.name = ");
                    qb.push_bind(name.clone());
                    qb.push(") OR (");
                    qb.push(img_alias);
                    qb.push(".wd_vocab_digest = ");
                    qb.push_bind(expected_vocab_digest.to_string());
                    qb.push(" AND ");
                    qb.push(img_alias);
                    qb.push(".wd_min_persisted_score IS NOT NULL AND ");
                    qb.push(img_alias);
                    qb.push(".wd_min_persisted_score <= ");
                    qb.push_bind(*min_score);
                    qb.push(") THEN FALSE ELSE NULL END)");
                }
                CompiledPredicate::PostTag(name) => {
                    if let Some(pid) = post_id_expr {
                        qb.push("EXISTS (SELECT 1 FROM tag_posts tp JOIN tags t ON t.id = tp.tag_id WHERE tp.post_id = ");
                        qb.push(pid);
                        qb.push(" AND t.name = ");
                        qb.push_bind(name.clone());
                        qb.push(")");
                    } else {
                        qb.push("FALSE");
                    }
                }
                CompiledPredicate::Author(name) => {
                    if let Some(pid) = post_id_expr {
                        qb.push("EXISTS (SELECT 1 FROM author_posts ap JOIN authors a ON a.id = ap.author_id WHERE ap.post_id = ");
                        qb.push(pid);
                        qb.push(" AND a.name = ");
                        qb.push_bind(name.clone());
                        qb.push(")");
                    } else {
                        qb.push("FALSE");
                    }
                }
                CompiledPredicate::Unclassified => {
                    qb.push("(");
                    qb.push(img_alias);
                    qb.push(".status <> 'completed'::process_status)");
                }
            },
            Self::Not(inner) => {
                qb.push("(NOT ");
                inner.push_tribool_sql(qb, img_alias, post_id_expr, expected_vocab_digest);
                qb.push(")");
            }
            Self::And(items) => {
                qb.push("(");
                for (idx, item) in items.iter().enumerate() {
                    if idx > 0 {
                        qb.push(" AND ");
                    }
                    item.push_tribool_sql(qb, img_alias, post_id_expr, expected_vocab_digest);
                }
                qb.push(")");
            }
            Self::Or(items) => {
                qb.push("(");
                for (idx, item) in items.iter().enumerate() {
                    if idx > 0 {
                        qb.push(" OR ");
                    }
                    item.push_tribool_sql(qb, img_alias, post_id_expr, expected_vocab_digest);
                }
                qb.push(")");
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompiledPolicyItem {
    pub id: String,
    pub grant_generation: u64,
    pub policy_ref: PolicyRef,
    pub priority: u16,
    pub order_index: usize,
    pub name: String,
    pub preset: PlaceholderPreset,
    pub action: PolicyAction,
    pub bypass: PolicyBypass,
    pub default_tag_min: f32,
    pub match_expr: CompiledExpr,
    pub except_expr: Option<CompiledExpr>,
    pub uses_post_context: bool,
    pub references_wd_tags: bool,
}

impl CompiledPolicyItem {
    pub fn eval_context(
        &self,
        is_completed: bool,
        wd_vocab_matches: bool,
        wd_min_persisted_score: Option<f32>,
        wd_tag_scores: &HashMap<String, f32>,
        post_tags: &HashSet<String>,
        authors: &HashSet<String>,
    ) -> TriBool {
        let matched = self.match_expr.eval_tribool(
            is_completed,
            wd_vocab_matches,
            wd_min_persisted_score,
            wd_tag_scores,
            post_tags,
            authors,
        );
        match &self.except_expr {
            None => matched,
            Some(ex) => matched.and(
                ex.eval_tribool(
                    is_completed,
                    wd_vocab_matches,
                    wd_min_persisted_score,
                    wd_tag_scores,
                    post_tags,
                    authors,
                )
                .not(),
            ),
        }
    }

    /// Push the single-context 3-valued SQL expression for `(match_expr AND NOT except_expr)`.
    fn push_policy_match_sql(
        &self,
        qb: &mut QueryBuilder<Postgres>,
        img_alias: &'static str,
        post_id_expr: Option<&'static str>,
        expected_vocab_digest: &str,
    ) {
        match &self.except_expr {
            None => self.match_expr.push_tribool_sql(
                qb,
                img_alias,
                post_id_expr,
                expected_vocab_digest,
            ),
            Some(ex) => {
                qb.push("(");
                self.match_expr.push_tribool_sql(
                    qb,
                    img_alias,
                    post_id_expr,
                    expected_vocab_digest,
                );
                qb.push(" AND NOT ");
                ex.push_tribool_sql(qb, img_alias, post_id_expr, expected_vocab_digest);
                qb.push(")");
            }
        }
    }
}

/// Immutable compiled Policy v3 snapshot pinned per request.
///
/// Compiled purely from [`PublicSitePolicy`] with zero DB tag-ID cache so
/// missing Postgres tag rows NEVER cause 503 errors.
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    pub policy: PublicSitePolicy,
    pub digest: String,
    /// Enabled policies sorted deterministically by `(priority ASC, order_index ASC)`.
    pub policies: Vec<CompiledPolicyItem>,
    pub referenced_wd_tags: Vec<String>,
    pub referenced_post_tags: Vec<String>,
    pub referenced_authors: Vec<String>,
}

impl CompiledPolicy {
    /// Disabled default policy (Standalone default, zero SQL overhead).
    pub fn disabled() -> Self {
        let policy = PublicSitePolicy::default();
        let digest = compute_policy_digest(&policy);
        Self {
            policy,
            digest,
            policies: Vec::new(),
            referenced_wd_tags: Vec::new(),
            referenced_post_tags: Vec::new(),
            referenced_authors: Vec::new(),
        }
    }

    /// True when safety enforcement is active — either because at least one rule
    /// is enabled OR because global `unclassified_mode == UnclassifiedMode::Placeholder`
    /// restricts unclassified media while the master safety switch is on.
    pub fn is_enabled(&self) -> bool {
        self.policy.safety_enabled
            && (!self.policies.is_empty()
                || self.policy.unclassified_mode == UnclassifiedMode::Placeholder)
    }

    /// Pure deterministic Policy v3 compiler (zero DB queries, zero tag-ID cache).
    pub fn compile(policy: PublicSitePolicy) -> anyhow::Result<Self> {
        let digest = compute_policy_digest(&policy);
        validate_policy_set_with_mode(&policy, false)
            .map_err(|e| anyhow!("invalid Policy v3 set: {e}"))?;

        if !policy.safety_enabled {
            return Ok(Self {
                policy,
                digest,
                policies: Vec::new(),
                referenced_wd_tags: Vec::new(),
                referenced_post_tags: Vec::new(),
                referenced_authors: Vec::new(),
            });
        }

        let mut compiled_items = Vec::new();
        let mut all_wd = BTreeSet::new();
        let mut all_post = BTreeSet::new();
        let mut all_authors = BTreeSet::new();

        for (order_index, item) in policy.policies.iter().enumerate() {
            if !item.enabled {
                continue;
            }
            let match_ast = parse_safety_rule_legacy_precision(&item.match_expr)
                .map_err(|e| anyhow!("invalid match_expr for policy '{}': {e}", item.id))?;
            let match_expr = compile_expr(
                &match_ast,
                item.default_tag_min,
                &mut all_wd,
                &mut all_post,
                &mut all_authors,
            )?;

            let except_expr = match item
                .except_expr
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                Some(raw_ex) => {
                    let ex_ast = parse_safety_rule_legacy_precision(raw_ex).map_err(|e| {
                        anyhow!("invalid except_expr for policy '{}': {e}", item.id)
                    })?;
                    Some(compile_expr(
                        &ex_ast,
                        item.default_tag_min,
                        &mut all_wd,
                        &mut all_post,
                        &mut all_authors,
                    )?)
                }
                None => None,
            };

            let uses_post_context = match_expr.uses_post_context()
                || except_expr
                    .as_ref()
                    .is_some_and(CompiledExpr::uses_post_context);
            let references_wd_tags = match_expr.references_wd_tags()
                || except_expr
                    .as_ref()
                    .is_some_and(CompiledExpr::references_wd_tags);

            compiled_items.push(CompiledPolicyItem {
                id: item.id.clone(),
                grant_generation: item.grant_generation,
                policy_ref: item.policy_ref(),
                priority: item.priority,
                order_index,
                name: item.name.clone(),
                preset: item.preset,
                action: item.action,
                bypass: item.bypass.clone(),
                default_tag_min: item.default_tag_min,
                match_expr,
                except_expr,
                uses_post_context,
                references_wd_tags,
            });
        }

        compiled_items.sort_by_key(|p| (p.priority, p.order_index));

        Ok(Self {
            policy,
            digest,
            policies: compiled_items,
            referenced_wd_tags: all_wd.into_iter().collect(),
            referenced_post_tags: all_post.into_iter().collect(),
            referenced_authors: all_authors.into_iter().collect(),
        })
    }

    /// Evaluate ALL enabled Policy v3 restrictions for a single image across EVERY
    /// parent post context independently and return the strictest [`MediaOutcome`].
    pub fn evaluate_image(&self, facts: &ImageFacts, caller: &CallerContext) -> MediaOutcome {
        let parent_pairs: Vec<(i64, u64)> = facts
            .parent_posts
            .iter()
            .map(|p| (p.post_id, p.facts_rev))
            .collect();
        let facts_rev = if facts.exists {
            compute_image_facts_rev(facts.image_own_facts_rev, &parent_pairs)
        } else {
            facts.facts_rev.max(1)
        };
        let canonical_name = facts.canonical_name.clone();
        if !self.is_enabled() {
            return MediaOutcome::Clear {
                matched_blocks: Vec::new(),
                matched_blurs: Vec::new(),
                facts_rev,
                canonical_name,
            };
        }

        if !facts.exists {
            return MediaOutcome::Placeholder {
                mask: unclassified_mask(),
                facts_rev,
            };
        }

        let empty_set = HashSet::new();
        let mut agg = EvalAccumulator::default();
        if !facts.is_completed && self.policy.unclassified_mode == UnclassifiedMode::Placeholder {
            agg.general_unclassified = true;
        }

        let wd_vocab_matches = facts.wd_vocab_digest.as_deref() == Some(self.policy.vocab_digest.as_str());
        if facts.parent_posts.is_empty() {
            self.eval_single_context(
                facts.is_completed,
                wd_vocab_matches,
                facts.wd_min_persisted_score,
                &facts.wd_tag_scores,
                &empty_set,
                &empty_set,
                &mut agg,
            );
        } else {
            for parent in &facts.parent_posts {
                self.eval_single_context(
                    facts.is_completed,
                    wd_vocab_matches,
                    facts.wd_min_persisted_score,
                    &facts.wd_tag_scores,
                    &parent.post_tags,
                    &parent.authors,
                    &mut agg,
                );
            }
        }

        self.finalize_outcome(agg, facts_rev, canonical_name, caller)
    }

    /// Evaluate a video across EVERY parent post and EVERY sibling image independently,
    /// aggregating BOTH `Block` and `Blur` restrictions (NEVER discarding `Blur`!).
    pub fn evaluate_video_posts(
        &self,
        posts: &[ParentPostFacts],
        video_facts_rev: u64,
        caller: &CallerContext,
    ) -> MediaOutcome {
        self.evaluate_video_posts_with_name(posts, video_facts_rev, None, caller)
    }

    pub fn evaluate_video_posts_with_name(
        &self,
        posts: &[ParentPostFacts],
        video_facts_rev: u64,
        canonical_name: Option<String>,
        caller: &CallerContext,
    ) -> MediaOutcome {
        // Match `lookup_facts_rev(MediaKind::Video)` exactly via deterministic fingerprint
        // of video own rev, all parent post revs, and all sibling image own revs!
        let parent_revs: Vec<(i64, u64)> = posts
            .iter()
            .map(|p| (p.post_id, p.post_facts_rev))
            .collect();
        let mut sibling_revs: Vec<(i64, i64, u64)> = Vec::new();
        for post in posts {
            for img in &post.images {
                sibling_revs.push((post.post_id, img.image_id, img.image_own_facts_rev));
            }
        }
        let authoritative_rev =
            compute_video_facts_rev(video_facts_rev, &parent_revs, &sibling_revs);

        if !self.is_enabled() {
            return MediaOutcome::Clear {
                matched_blocks: Vec::new(),
                matched_blurs: Vec::new(),
                facts_rev: authoritative_rev,
                canonical_name,
            };
        }

        let empty_scores = HashMap::new();
        let empty_set = HashSet::new();
        let mut agg = EvalAccumulator::default();

        if posts.is_empty() {
            // Video attached to zero parent posts has no classified sibling images.
            if self.policy.unclassified_mode == UnclassifiedMode::Placeholder {
                agg.general_unclassified = true;
            }
            self.eval_single_context(
                false,
                false,
                None,
                &empty_scores,
                &empty_set,
                &empty_set,
                &mut agg,
            );
        } else {
            for post in posts {
                if post.images.is_empty() {
                    // Video-only parent post: treat image side as unclassified while
                    // still evaluating post_tag / author / unclassified policies!
                    if self.policy.unclassified_mode == UnclassifiedMode::Placeholder {
                        agg.general_unclassified = true;
                    }
                    self.eval_single_context(
                        false,
                        false,
                        None,
                        &empty_scores,
                        &post.post_tags,
                        &post.authors,
                        &mut agg,
                    );
                } else {
                    for img in &post.images {
                        if (!img.exists || !img.is_completed)
                            && self.policy.unclassified_mode == UnclassifiedMode::Placeholder
                        {
                            agg.general_unclassified = true;
                        }
                        let wd_vocab_matches =
                            img.wd_vocab_digest.as_deref() == Some(self.policy.vocab_digest.as_str());
                        self.eval_single_context(
                            img.exists && img.is_completed,
                            wd_vocab_matches,
                            img.wd_min_persisted_score,
                            &img.wd_tag_scores,
                            &post.post_tags,
                            &post.authors,
                            &mut agg,
                        );
                    }
                }
            }
        }

        self.finalize_outcome(agg, authoritative_rev, canonical_name, caller)
    }

    #[allow(clippy::too_many_arguments)]
    fn eval_single_context<'a>(
        &'a self,
        is_completed: bool,
        wd_vocab_matches: bool,
        wd_min_persisted_score: Option<f32>,
        wd_tag_scores: &HashMap<String, f32>,
        post_tags: &HashSet<String>,
        authors: &HashSet<String>,
        agg: &mut EvalAccumulator<'a>,
    ) {
        for item in &self.policies {
            match item.eval_context(
                is_completed,
                wd_vocab_matches,
                wd_min_persisted_score,
                wd_tag_scores,
                post_tags,
                authors,
            ) {
                TriBool::True => match item.action {
                    PolicyAction::Block => agg.add_block(item),
                    PolicyAction::Blur => agg.add_blur(item),
                },
                TriBool::Unknown => agg.add_unknown(item),
                TriBool::False => {}
            }
        }
    }

    fn finalize_outcome(
        &self,
        agg: EvalAccumulator<'_>,
        facts_rev: u64,
        canonical_name: Option<String>,
        caller: &CallerContext,
    ) -> MediaOutcome {
        let mut matched_blocks: Vec<&CompiledPolicyItem> = agg.blocks.into_values().collect();
        matched_blocks.sort_by_key(|p| (p.priority, p.order_index));
        let mut matched_blurs: Vec<&CompiledPolicyItem> = agg.blurs.into_values().collect();
        matched_blurs.sort_by_key(|p| (p.priority, p.order_index));
        let mut unknown_policies: Vec<&CompiledPolicyItem> = agg.unknowns.into_values().collect();
        unknown_policies.sort_by_key(|p| (p.priority, p.order_index));

        let unsatisfied_blocks: Vec<&CompiledPolicyItem> = matched_blocks
            .iter()
            .copied()
            .filter(|p| !caller.has_direct_grant(&p.policy_ref))
            .collect();

        // 1. Any unsatisfied Block ALWAYS yields Placeholder.
        if !unsatisfied_blocks.is_empty() {
            return MediaOutcome::Placeholder {
                mask: aggregate_placeholder_mask(&unsatisfied_blocks, &self.policy, caller),
                facts_rev,
            };
        }

        // 2. Any indeterminate Unknown restriction yields Placeholder (fail closed).
        if !unknown_policies.is_empty() {
            return MediaOutcome::Placeholder {
                mask: aggregate_unknown_mask(&unknown_policies, &self.policy),
                facts_rev,
            };
        }

        // 3. General unclassified placeholder (waived ONLY by UnclassifiedMode::Continue).
        if agg.general_unclassified {
            return MediaOutcome::Placeholder {
                mask: unclassified_mask(),
                facts_rev,
            };
        }

        let mut matched_block_refs: Vec<PolicyRef> =
            matched_blocks.iter().map(|p| p.policy_ref.clone()).collect();
        matched_block_refs.sort();
        matched_block_refs.dedup();

        let mut matched_blur_refs: Vec<PolicyRef> =
            matched_blurs.iter().map(|p| p.policy_ref.clone()).collect();
        matched_blur_refs.sort();
        matched_blur_refs.dedup();

        let unsatisfied_blurs: Vec<&CompiledPolicyItem> = matched_blurs
            .iter()
            .copied()
            .filter(|p| !caller.has_direct_grant(&p.policy_ref))
            .collect();

        // 4. Any unsatisfied Blur -> Blurred ONLY if fixed_blur_enabled == true,
        //    otherwise degrade to Placeholder so zero clear pixels ever leak!
        if !unsatisfied_blurs.is_empty() {
            if !self.policy.fixed_blur_enabled {
                return MediaOutcome::Placeholder {
                    mask: aggregate_placeholder_mask(&unsatisfied_blurs, &self.policy, caller),
                    facts_rev,
                };
            }
            let primary = unsatisfied_blurs[0];
            let can_click_reveal = unsatisfied_blurs
                .iter()
                .all(|b| caller.is_click_eligible(&b.policy_ref));
            let mut matched_policy_ids: Vec<String> =
                unsatisfied_blurs.iter().map(|p| p.id.clone()).collect();
            if !unsatisfied_blurs
                .iter()
                .all(|p| policy_has_user_unlock_path(p, &self.policy))
            {
                matched_policy_ids.push(MASK_NO_UNLOCK_MARKER.to_string());
            }
            return MediaOutcome::Blurred {
                policy_id: primary.id.clone(),
                matched_policy_ids,
                label: primary.name.clone(),
                preset: primary.preset,
                can_click_reveal,
                matched_blocks: matched_block_refs,
                matched_blurs: matched_blur_refs,
                facts_rev,
                canonical_name,
            };
        }

        // 5. Clear ONLY when EVERY matched Block AND EVERY matched Blur is directly granted!
        MediaOutcome::Clear {
            matched_blocks: matched_block_refs,
            matched_blurs: matched_blur_refs,
            facts_rev,
            canonical_name,
        }
    }

    /// Project an `Image` + its evaluated [`MediaOutcome`] into a Policy v3 [`ProjectedImage`].
    ///
    /// - `Placeholder`: ZERO media locator, filename, preview URL, or clear URL.
    /// - `Blurred`: NEVER emits a pre-minted clear `reveal_url`. Emits `preview_url` ONLY
    ///   when `policy.fixed_blur_enabled == true` (in Managed mode, signed `MediaCapKind::Preview`
    ///   when actor is non-Anon; in Standalone mode `preview_url: None` so clear bytes never leak).
    /// - `Clear`: emits direct path in Standalone mode or signed `MediaCapKind::Image` v3 in Managed mode.
    pub fn project_image(
        &self,
        image: &Image,
        outcome: MediaOutcome,
        caller: &CallerContext,
        signer: &MediaSigner,
    ) -> ProjectedImage {
        let policy_rev = self.policy.revision;
        match outcome {
            MediaOutcome::Placeholder { mask, .. } => ProjectedImage::Placeholder {
                id: image.id,
                policy_rev,
                width: image.width,
                height: image.height,
                mask,
            },
            MediaOutcome::Clear {
                matched_blocks,
                matched_blurs,
                facts_rev,
                canonical_name,
            } => {
                let effective_name = canonical_name.as_deref().unwrap_or(&image.name);
                match signer {
                    MediaSigner::Standalone => ProjectedImage::Clear {
                        id: image.id,
                        url: format!("/images/{}.webp", encode_url_path(effective_name)),
                        name: Some(effective_name.to_string()),
                        width: image.width,
                        height: image.height,
                    },
                    MediaSigner::Managed { secret, now_secs } => {
                        let locator = format!("{}.webp", effective_name.trim_start_matches('/'));
                        match mint_cap_url_v3(
                            secret,
                            *now_secs,
                            policy_rev,
                            facts_rev,
                            MediaCapKind::Image,
                            image.id,
                            locator,
                            &matched_blocks,
                            &matched_blurs,
                            &[],
                            caller,
                            None,
                        ) {
                            Ok((url, _exp)) => ProjectedImage::Clear {
                                id: image.id,
                                url,
                                name: None,
                                width: image.width,
                                height: image.height,
                            },
                            Err(mask) => ProjectedImage::Placeholder {
                                id: image.id,
                                policy_rev,
                                width: image.width,
                                height: image.height,
                                mask,
                            },
                        }
                    }
                }
            }
            MediaOutcome::Blurred {
                policy_id,
                matched_policy_ids,
                label,
                preset,
                can_click_reveal,
                matched_blocks,
                matched_blurs,
                facts_rev,
                canonical_name,
            } => {
                if !self.policy.fixed_blur_enabled {
                    return ProjectedImage::Placeholder {
                        id: image.id,
                        policy_rev,
                        width: image.width,
                        height: image.height,
                        mask: MaskMetadata {
                            policy_id,
                            matched_policy_ids,
                            label,
                            preset,
                            requires_login: false,
                            requires_age: false,
                            requires_terms: false,
                        },
                    };
                }
                let effective_name = canonical_name.as_deref().unwrap_or(&image.name);
                let preview_url = match signer {
                    // Never emit clear `/images/...` bytes as preview_url!
                    MediaSigner::Standalone => None,
                    MediaSigner::Managed { secret, now_secs } => {
                        if caller.actor.is_anon() {
                            // `MediaCapability v3` forbids Anon actor when matched_blocks/blurs are non-empty.
                            // Card still renders frosted blur overlay + Click-to-Reveal (which upgrades to GuestSession).
                            None
                        } else {
                            let locator = format!("{}.webp", effective_name.trim_start_matches('/'));
                            match mint_cap_url_v3(
                                secret,
                                *now_secs,
                                policy_rev,
                                facts_rev,
                                MediaCapKind::Preview,
                                image.id,
                                locator,
                                &matched_blocks,
                                &matched_blurs,
                                &[],
                                caller,
                                None,
                            ) {
                                Ok((url, _exp)) => Some(url),
                                Err(_) => None,
                            }
                        }
                    }
                };
                ProjectedImage::Blurred {
                    id: image.id,
                    preview_url,
                    can_click_reveal,
                    policy_rev,
                    matched_policy_ids,
                    label,
                    preset,
                    width: image.width,
                    height: image.height,
                }
            }
        }
    }

    /// Project a `Video` + its evaluated [`MediaOutcome`] into a Policy v3 [`ProjectedVideo`].
    ///
    /// Videos honor BOTH `Block` (`Placeholder`) AND `Blur` (`Blurred` when `fixed_blur_enabled`
    /// else `Placeholder`) — NEVER silently turning a blurred video into `Clear`!
    pub fn project_video(
        &self,
        video: &Video,
        outcome: MediaOutcome,
        caller: &CallerContext,
        signer: &MediaSigner,
    ) -> ProjectedVideo {
        let policy_rev = self.policy.revision;
        match outcome {
            MediaOutcome::Placeholder { mask, .. } => ProjectedVideo::Placeholder {
                id: video.id,
                policy_rev,
                width: video.width,
                height: video.height,
                duration: video.duration,
                mask,
            },
            MediaOutcome::Blurred {
                policy_id,
                matched_policy_ids,
                label,
                preset,
                can_click_reveal,
                ..
            } => {
                if !self.policy.fixed_blur_enabled {
                    return ProjectedVideo::Placeholder {
                        id: video.id,
                        policy_rev,
                        width: video.width,
                        height: video.height,
                        duration: video.duration,
                        mask: MaskMetadata {
                            policy_id,
                            matched_policy_ids,
                            label,
                            preset,
                            requires_login: false,
                            requires_age: false,
                            requires_terms: false,
                        },
                    };
                }
                ProjectedVideo::Blurred {
                    id: video.id,
                    preview_url: None,
                    can_click_reveal,
                    policy_rev,
                    matched_policy_ids,
                    label,
                    preset,
                    width: video.width,
                    height: video.height,
                    duration: video.duration,
                }
            }
            MediaOutcome::Clear {
                matched_blocks,
                matched_blurs,
                facts_rev,
                canonical_name,
            } => {
                let effective_name = canonical_name.as_deref().unwrap_or(&video.name);
                match signer {
                    MediaSigner::Standalone => ProjectedVideo::Clear {
                        id: video.id,
                        url: format!("/videos/{}", encode_url_path(effective_name)),
                        name: Some(effective_name.to_string()),
                        width: video.width,
                        height: video.height,
                        duration: video.duration,
                    },
                    MediaSigner::Managed { secret, now_secs } => {
                        let locator = effective_name.trim_start_matches('/').to_string();
                        match mint_cap_url_v3(
                            secret,
                            *now_secs,
                            policy_rev,
                            facts_rev,
                            MediaCapKind::Video,
                            video.id,
                            locator,
                            &matched_blocks,
                            &matched_blurs,
                            &[],
                            caller,
                            None,
                        ) {
                            Ok((url, _exp)) => ProjectedVideo::Clear {
                                id: video.id,
                                url,
                                name: None,
                                width: video.width,
                                height: video.height,
                                duration: video.duration,
                            },
                            Err(mask) => ProjectedVideo::Placeholder {
                                id: video.id,
                                policy_rev,
                                width: video.width,
                                height: video.height,
                                duration: video.duration,
                                mask,
                            },
                        }
                    }
                }
            }
        }
    }

    /// Push SQL Clear-authorization clauses onto `qb` (inside a `WHERE` clause, starting
    /// with `AND ...`) so ONLY images that are strictly `Clear` for `caller` (BOTH `Block`
    /// AND `Blur` satisfied, ZERO `Unknown` restrictions) match search candidates, ranking,
    /// counts, autocomplete suggestions, or anonymous sitemaps.
    ///
    /// Returns `true` if any filter predicate was emitted.
    pub fn push_caller_allowed_image_sql(
        &self,
        qb: &mut QueryBuilder<Postgres>,
        caller: &CallerContext,
        img_alias: &'static str,
    ) -> bool {
        if !self.is_enabled() {
            return false;
        }
        let mut emitted = false;
        if self.policy.unclassified_mode == UnclassifiedMode::Placeholder {
            qb.push(" AND ");
            qb.push(img_alias);
            qb.push(".status = 'completed'::process_status");
            emitted = true;
        }

        let expected_vocab = self.policy.vocab_digest.as_str();
        for item in &self.policies {
            let has_grant = caller.has_direct_grant(&item.policy_ref);
            if has_grant && !item.references_wd_tags {
                // Directly granted policy with purely 2-valued predicates can never be Unknown.
                continue;
            }
            if has_grant {
                // Directly granted policy referencing WD tags must still not evaluate to Unknown (NULL).
                qb.push(" AND ");
                push_policy_not_unknown_sql(qb, item, img_alias, expected_vocab);
            } else {
                // Unsatisfied Block OR Blur policy MUST evaluate strictly to FALSE across all contexts.
                qb.push(" AND ");
                push_policy_strictly_false_sql(qb, item, img_alias, expected_vocab);
            }
            emitted = true;
        }

        emitted
    }

    /// Push SQL indexability clauses onto `qb` (inside a `WHERE` clause, starting
    /// with `AND ...`) for anonymous XML sitemaps when `noindex_restricted == false`:
    /// - Excludes unclassified images when `unclassified_mode == Placeholder`
    /// - Excludes any image matching (or `Unknown` against) a **non-bypassable** policy
    ///   (zero user self-service unlock path, e.g. `Extreme / Gore & Illegal` or staff-only rules)
    /// - Keeps classified images matching only **bypassable** policies (e.g. `NSFW` / `Sensitive`)
    ///   so their titles and detail pages stay indexable while media bytes remain protected.
    ///
    /// Returns `true` if any filter predicate was emitted.
    pub fn push_indexable_image_sql(
        &self,
        qb: &mut QueryBuilder<Postgres>,
        img_alias: &'static str,
    ) -> bool {
        if !self.is_enabled() {
            return false;
        }
        let mut emitted = false;
        if self.policy.unclassified_mode == UnclassifiedMode::Placeholder {
            qb.push(" AND ");
            qb.push(img_alias);
            qb.push(".status = 'completed'::process_status");
            emitted = true;
        }

        let expected_vocab = self.policy.vocab_digest.as_str();
        for item in &self.policies {
            let bypassable = policy_has_user_unlock_path(item, &self.policy);
            if !bypassable {
                // Non-bypassable policy (zero user unlock path) MUST evaluate strictly to FALSE.
                qb.push(" AND ");
                push_policy_strictly_false_sql(qb, item, img_alias, expected_vocab);
                emitted = true;
            } else if item.references_wd_tags {
                // Bypassable WD-tag policy may match (TRUE) or not match (FALSE),
                // but indeterminate coverage (NULL / Unknown) still fails closed.
                qb.push(" AND ");
                push_policy_not_unknown_sql(qb, item, img_alias, expected_vocab);
                emitted = true;
            }
        }

        emitted
    }
}

fn push_policy_strictly_false_sql(
    qb: &mut QueryBuilder<Postgres>,
    item: &CompiledPolicyItem,
    img_alias: &'static str,
    expected_vocab_digest: &str,
) {
    if !item.uses_post_context {
        qb.push("((");
        item.push_policy_match_sql(qb, img_alias, None, expected_vocab_digest);
        qb.push(") IS FALSE)");
    } else {
        // Multi-parent invariant: EVERY parent post must evaluate strictly to FALSE,
        // AND if the image has zero parent posts, the orphan context must evaluate to FALSE.
        qb.push("(NOT EXISTS (SELECT 1 FROM post_images pi WHERE pi.image_id = ");
        qb.push(img_alias);
        qb.push(".id AND ((");
        item.push_policy_match_sql(qb, img_alias, Some("pi.post_id"), expected_vocab_digest);
        qb.push(") IS NOT FALSE)) AND (EXISTS (SELECT 1 FROM post_images pi WHERE pi.image_id = ");
        qb.push(img_alias);
        qb.push(".id) OR ((");
        item.push_policy_match_sql(qb, img_alias, None, expected_vocab_digest);
        qb.push(") IS FALSE)))");
    }
}

fn push_policy_not_unknown_sql(
    qb: &mut QueryBuilder<Postgres>,
    item: &CompiledPolicyItem,
    img_alias: &'static str,
    expected_vocab_digest: &str,
) {
    if !item.uses_post_context {
        qb.push("((");
        item.push_policy_match_sql(qb, img_alias, None, expected_vocab_digest);
        qb.push(") IS NOT NULL)");
    } else {
        qb.push("(NOT EXISTS (SELECT 1 FROM post_images pi WHERE pi.image_id = ");
        qb.push(img_alias);
        qb.push(".id AND ((");
        item.push_policy_match_sql(qb, img_alias, Some("pi.post_id"), expected_vocab_digest);
        qb.push(") IS NULL)) AND (EXISTS (SELECT 1 FROM post_images pi WHERE pi.image_id = ");
        qb.push(img_alias);
        qb.push(".id) OR ((");
        item.push_policy_match_sql(qb, img_alias, None, expected_vocab_digest);
        qb.push(") IS NOT NULL)))");
    }
}

/// Pair of pinned Policy v3 snapshot + verified caller passed to `Engine` search/filter methods.
#[derive(Debug, Clone)]
pub struct SafetyFilter<'a> {
    pub policy: &'a CompiledPolicy,
    pub caller: &'a CallerContext,
}

impl<'a> SafetyFilter<'a> {
    pub fn new(policy: &'a CompiledPolicy, caller: &'a CallerContext) -> Self {
        Self { policy, caller }
    }

    pub fn is_filtering_active(&self) -> bool {
        self.policy.is_enabled()
    }

    pub fn push_allowed_image_sql(
        &self,
        qb: &mut QueryBuilder<Postgres>,
        img_alias: &'static str,
    ) -> bool {
        self.policy
            .push_caller_allowed_image_sql(qb, self.caller, img_alias)
    }
}

/// Per-parent-post context attached to an image for multi-parent independent evaluation.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ImageParentPostFacts {
    pub post_id: i64,
    pub post_tags: HashSet<String>,
    pub authors: HashSet<String>,
    pub facts_rev: u64,
}

/// Exact DB metadata facts for evaluating Policy v3 on an image in a single snapshot.
#[derive(Debug, Clone)]
pub struct ImageFacts {
    pub image_id: i64,
    pub exists: bool,
    pub is_completed: bool,
    /// Canonical `images.name` captured in the same `REPEATABLE READ` snapshot as `facts_rev`.
    pub canonical_name: Option<String>,
    pub wd_min_persisted_score: Option<f32>,
    /// Canonical WD-Tagger v3 vocabulary digest stamped on `images.wd_vocab_digest`.
    /// Must equal `policy.vocab_digest` for absent WD tags to evaluate `False` instead of `Unknown`.
    pub wd_vocab_digest: Option<String>,
    /// Image row's own `images.facts_rev` (used by `compute_image_facts_rev` and `compute_video_facts_rev`).
    pub image_own_facts_rev: u64,
    /// Authoritative image `facts_rev` fingerprint covering `image_own_facts_rev` and all parent posts.
    pub facts_rev: u64,
    /// Canonical `wd_tags.name -> score` pairs present on this image.
    pub wd_tag_scores: HashMap<String, f32>,
    /// Every parent post attached to this image, evaluated independently.
    pub parent_posts: Vec<ImageParentPostFacts>,
}

impl Default for ImageFacts {
    fn default() -> Self {
        Self {
            image_id: 0,
            exists: false,
            is_completed: false,
            canonical_name: None,
            wd_min_persisted_score: None,
            wd_vocab_digest: None,
            image_own_facts_rev: 1,
            facts_rev: 1,
            wd_tag_scores: HashMap::new(),
            parent_posts: Vec::new(),
        }
    }
}

impl ImageFacts {
    /// Convenience constructor for single-parent / unit-test evaluation.
    pub fn completed_with_floor(
        min_persisted_score: Option<f32>,
        wd_tag_scores: HashMap<String, f32>,
    ) -> Self {
        Self {
            image_id: 0,
            exists: true,
            is_completed: true,
            canonical_name: None,
            wd_min_persisted_score: min_persisted_score,
            wd_vocab_digest: Some(search_types::wd_vocab::WD_VOCAB_DIGEST.to_string()),
            image_own_facts_rev: 1,
            facts_rev: compute_image_facts_rev(1, &[]),
            wd_tag_scores,
            parent_posts: Vec::new(),
        }
    }
}

/// Parent post metadata facts used to evaluate a video's inherited Policy v3 outcome
/// independently per parent post.
#[derive(Debug, Clone, Default)]
pub struct ParentPostFacts {
    pub post_id: i64,
    pub post_facts_rev: u64,
    pub images: Vec<ImageFacts>,
    pub post_tags: HashSet<String>,
    pub authors: HashSet<String>,
}

/// Outcome of evaluating a [`CompiledPolicy`] on an image or video for a caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaOutcome {
    Clear {
        matched_blocks: Vec<PolicyRef>,
        matched_blurs: Vec<PolicyRef>,
        facts_rev: u64,
        canonical_name: Option<String>,
    },
    Blurred {
        policy_id: String,
        matched_policy_ids: Vec<String>,
        label: String,
        preset: PlaceholderPreset,
        can_click_reveal: bool,
        matched_blocks: Vec<PolicyRef>,
        matched_blurs: Vec<PolicyRef>,
        facts_rev: u64,
        canonical_name: Option<String>,
    },
    Placeholder {
        mask: MaskMetadata,
        facts_rev: u64,
    },
}

impl MediaOutcome {
    pub fn is_clear(&self) -> bool {
        matches!(self, Self::Clear { .. })
    }

    pub fn is_blurred(&self) -> bool {
        matches!(self, Self::Blurred { .. })
    }

    pub fn is_placeholder(&self) -> bool {
        matches!(self, Self::Placeholder { .. })
    }

    pub fn facts_rev(&self) -> u64 {
        match self {
            Self::Clear { facts_rev, .. }
            | Self::Blurred { facts_rev, .. }
            | Self::Placeholder { facts_rev, .. } => *facts_rev,
        }
    }

    pub fn is_public_safe_clear(&self) -> bool {
        matches!(
            self,
            Self::Clear {
                matched_blocks,
                matched_blurs,
                ..
            } if matched_blocks.is_empty() && matched_blurs.is_empty()
        )
    }

    /// Returns `true` when the media is either `Clear` for the caller or restricted ONLY
    /// by user-bypassable policies (has a self-service Switcher / Click-to-Reveal unlock path).
    ///
    /// Returns `false` for non-bypassable hard blocks (e.g. `Extreme / Gore & Illegal`,
    /// live-admin-only rules, impossible age gates) and unclassified / `Unknown` items.
    pub fn is_user_bypassable_or_clear(&self) -> bool {
        match self {
            Self::Clear { .. } => true,
            Self::Blurred {
                matched_policy_ids, ..
            } => !matched_policy_ids.iter().any(|id| id == MASK_NO_UNLOCK_MARKER),
            Self::Placeholder { mask, .. } => !mask.has_no_unlock_path(),
        }
    }
}

/// Result of single-snapshot Policy v3 reveal evaluation for `POST /api/safety/reveal`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevealCheckResult {
    NotFound,
    Denied,
    Allowed {
        immutable_locator: String,
        facts_rev: u64,
        matched_blocks: Vec<PolicyRef>,
        matched_blurs: Vec<PolicyRef>,
        revealed_refs: Vec<PolicyRef>,
    },
}

/// Result of `POST /internal/validate-safety-catalog`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CatalogValidationResult {
    pub unknown_post_tags: Vec<String>,
    pub unknown_authors: Vec<String>,
}

#[derive(Default)]
struct EvalAccumulator<'a> {
    blocks: HashMap<&'a str, &'a CompiledPolicyItem>,
    blurs: HashMap<&'a str, &'a CompiledPolicyItem>,
    unknowns: HashMap<&'a str, &'a CompiledPolicyItem>,
    general_unclassified: bool,
}

impl<'a> EvalAccumulator<'a> {
    fn add_block(&mut self, item: &'a CompiledPolicyItem) {
        self.blocks.entry(item.id.as_str()).or_insert(item);
    }
    fn add_blur(&mut self, item: &'a CompiledPolicyItem) {
        self.blurs.entry(item.id.as_str()).or_insert(item);
    }
    fn add_unknown(&mut self, item: &'a CompiledPolicyItem) {
        self.unknowns.entry(item.id.as_str()).or_insert(item);
    }
}

fn unclassified_mask() -> MaskMetadata {
    MaskMetadata {
        policy_id: "unclassified".to_string(),
        matched_policy_ids: vec![
            "unclassified".to_string(),
            MASK_NO_UNLOCK_MARKER.to_string(),
        ],
        label: "Pending classification".to_string(),
        preset: PlaceholderPreset::Custom,
        requires_login: false,
        requires_age: false,
        requires_terms: false,
    }
}

fn policy_has_user_unlock_path(item: &CompiledPolicyItem, site_policy: &PublicSitePolicy) -> bool {
    let has_branch = match item.action {
        PolicyAction::Block => item.bypass.include_switcher || item.bypass.include_click,
        PolicyAction::Blur => {
            item.bypass.include_switcher
                || (site_policy.fixed_blur_enabled && item.bypass.include_click)
        }
    };
    let age_impossible =
        item.bypass.require_age_18 && site_policy.age_policy == AgeVerificationPolicy::Off;
    has_branch && !age_impossible
}

fn aggregate_placeholder_mask(
    unsatisfied: &[&CompiledPolicyItem],
    policy: &PublicSitePolicy,
    caller: &CallerContext,
) -> MaskMetadata {
    let primary = unsatisfied[0];
    let mut matched_policy_ids: Vec<String> = unsatisfied.iter().map(|p| p.id.clone()).collect();
    let has_user_unlock = unsatisfied
        .iter()
        .all(|p| policy_has_user_unlock_path(p, policy));

    if !has_user_unlock {
        matched_policy_ids.push(MASK_NO_UNLOCK_MARKER.to_string());
        return MaskMetadata {
            policy_id: primary.id.clone(),
            matched_policy_ids,
            label: primary.name.clone(),
            preset: primary.preset,
            requires_login: false,
            requires_age: false,
            requires_terms: false,
        };
    }

    let caller_is_authenticated = caller.is_authenticated();
    let requires_login = unsatisfied
        .iter()
        .any(|p| p.bypass.require_gallery_login || p.bypass.exclude_anonymous)
        && !caller_is_authenticated;
    let requires_age = unsatisfied.iter().any(|p| p.bypass.require_age_18)
        && policy.age_policy != AgeVerificationPolicy::Off
        && !caller.age_verified;
    let requires_terms = unsatisfied
        .iter()
        .any(|p| p.bypass.require_current_terms)
        && !caller.terms_accepted;
    MaskMetadata {
        policy_id: primary.id.clone(),
        matched_policy_ids,
        label: primary.name.clone(),
        preset: primary.preset,
        requires_login,
        requires_age,
        requires_terms,
    }
}

fn aggregate_unknown_mask(
    unknowns: &[&CompiledPolicyItem],
    _policy: &PublicSitePolicy,
) -> MaskMetadata {
    let primary = unknowns[0];
    let mut matched_policy_ids: Vec<String> = unknowns.iter().map(|p| p.id.clone()).collect();
    matched_policy_ids.push(MASK_NO_UNLOCK_MARKER.to_string());
    MaskMetadata {
        policy_id: primary.id.clone(),
        matched_policy_ids,
        label: format!("Pending classification ({})", primary.name),
        preset: primary.preset,
        requires_login: false,
        requires_age: false,
        requires_terms: false,
    }
}

fn compile_expr(
    ast: &SafetyExpr,
    default_tag_min: f32,
    all_wd: &mut BTreeSet<String>,
    all_post: &mut BTreeSet<String>,
    all_authors: &mut BTreeSet<String>,
) -> anyhow::Result<CompiledExpr> {
    match ast {
        SafetyExpr::Predicate(pred) => match pred {
            SafetyPredicate::WdTag { name, min_score } => {
                let score = min_score.unwrap_or(default_tag_min);
                if !score.is_finite() || score <= 0.0 || score > 1.0 {
                    bail!("invalid score threshold {score} for tag '{name}'");
                }
                all_wd.insert(name.clone());
                Ok(CompiledExpr::Predicate(CompiledPredicate::WdTag {
                    name: name.clone(),
                    min_score: score,
                }))
            }
            SafetyPredicate::PostTag(name) => {
                all_post.insert(name.clone());
                Ok(CompiledExpr::Predicate(CompiledPredicate::PostTag(
                    name.clone(),
                )))
            }
            SafetyPredicate::Author(name) => {
                all_authors.insert(name.clone());
                Ok(CompiledExpr::Predicate(CompiledPredicate::Author(
                    name.clone(),
                )))
            }
            SafetyPredicate::Unclassified => {
                Ok(CompiledExpr::Predicate(CompiledPredicate::Unclassified))
            }
        },
        SafetyExpr::Not(inner) => Ok(CompiledExpr::Not(Box::new(compile_expr(
            inner,
            default_tag_min,
            all_wd,
            all_post,
            all_authors,
        )?))),
        SafetyExpr::And(items) => {
            let mut compiled = Vec::with_capacity(items.len());
            for item in items {
                compiled.push(compile_expr(
                    item,
                    default_tag_min,
                    all_wd,
                    all_post,
                    all_authors,
                )?);
            }
            Ok(CompiledExpr::And(compiled))
        }
        SafetyExpr::Or(items) => {
            let mut compiled = Vec::with_capacity(items.len());
            for item in items {
                compiled.push(compile_expr(
                    item,
                    default_tag_min,
                    all_wd,
                    all_post,
                    all_authors,
                )?);
            }
            Ok(CompiledExpr::Or(compiled))
        }
    }
}

/// Mint a signed Policy v3 `MediaCapability` URL (`/media/{kind}/{id}?cap=mc3...`).
#[allow(clippy::too_many_arguments)]
pub fn mint_cap_url_v3(
    secret: &[u8],
    now_secs: u64,
    policy_rev: u64,
    facts_rev: u64,
    kind: MediaCapKind,
    asset_id: i64,
    immutable_locator: String,
    matched_blocks: &[PolicyRef],
    matched_blurs: &[PolicyRef],
    revealed_refs: &[PolicyRef],
    caller: &CallerContext,
    ttl_override_secs: Option<u64>,
) -> Result<(String, u64), MaskMetadata> {
    if secret.is_empty() {
        return Err(unclassified_mask());
    }
    if immutable_locator.is_empty()
        || immutable_locator.contains('%')
        || immutable_locator.contains(':')
        || immutable_locator.contains('\\')
        || immutable_locator.starts_with('/')
        || immutable_locator.len() > 1024
    {
        return Err(unclassified_mask());
    }

    let is_unrestricted =
        matched_blocks.is_empty() && matched_blurs.is_empty() && revealed_refs.is_empty();

    let (actor_binding, default_ttl) = if is_unrestricted {
        (caller.actor.clone(), PUBLIC_MEDIA_CAP_TTL_SECS)
    } else {
        if caller.actor.is_anon() {
            let policy_id = matched_blocks
                .first()
                .or_else(|| matched_blurs.first())
                .map(|r| r.id.clone())
                .unwrap_or_else(|| "restricted".to_string());
            return Err(MaskMetadata {
                policy_id: policy_id.clone(),
                matched_policy_ids: vec![policy_id],
                label: "Restricted content".to_string(),
                preset: PlaceholderPreset::Custom,
                requires_login: true,
                requires_age: false,
                requires_terms: false,
            });
        }
        (caller.actor.clone(), RESTRICTED_MEDIA_CAP_TTL_SECS)
    };

    let ttl = ttl_override_secs.unwrap_or(default_ttl);
    let exp = now_secs.saturating_add(ttl);
    let cap = MediaCapability {
        v: MEDIA_CAP_VERSION,
        aud: MEDIA_CAP_AUDIENCE.to_string(),
        kind,
        asset_id,
        immutable_locator,
        facts_rev: facts_rev.max(1),
        policy_rev,
        actor_binding,
        matched_blocks: matched_blocks.to_vec(),
        matched_blurs: matched_blurs.to_vec(),
        revealed_refs: revealed_refs.to_vec(),
        exp,
    };

    let tok = sign_media_capability(&cap, secret).map_err(|_| unclassified_mask())?;
    Ok((format!("/media/{}/{}?cap={tok}", kind.as_str(), asset_id), exp))
}

/// Mint a 15-minute click-to-reveal clear capability URL (used by `POST /api/safety/reveal`).
#[allow(clippy::too_many_arguments)]
pub fn mint_reveal_cap_url_v3(
    secret: &[u8],
    now_secs: u64,
    policy_rev: u64,
    facts_rev: u64,
    kind: MediaKind,
    asset_id: i64,
    immutable_locator: String,
    matched_blocks: &[PolicyRef],
    matched_blurs: &[PolicyRef],
    revealed_refs: &[PolicyRef],
    caller: &CallerContext,
) -> anyhow::Result<(String, u64)> {
    let cap_kind = match kind {
        MediaKind::Image => MediaCapKind::Image,
        MediaKind::Video => MediaCapKind::Video,
    };
    mint_cap_url_v3(
        secret,
        now_secs,
        policy_rev,
        facts_rev,
        cap_kind,
        asset_id,
        immutable_locator,
        matched_blocks,
        matched_blurs,
        revealed_refs,
        caller,
        Some(CLICK_REVEAL_MEDIA_CAP_TTL_SECS),
    )
    .map_err(|mask| anyhow!("unable to mint reveal capability ({})", mask.label))
}

pub fn encode_url_path(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for (idx, seg) in path.split('/').enumerate() {
        if idx > 0 {
            out.push('/');
        }
        for b in seg.as_bytes() {
            if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
                out.push(*b as char);
            } else {
                use std::fmt::Write as _;
                let _ = write!(out, "%{b:02X}");
            }
        }
    }
    out
}

/// Begin a single-snapshot read-only `REPEATABLE READ` transaction so all facts,
/// embeddings, and authoritative `facts_rev` values are read consistently together.
pub(crate) async fn begin_repeatable_read_tx(
    pool: &PgPool,
) -> anyhow::Result<sqlx::Transaction<'_, Postgres>> {
    let mut tx = pool.begin().await?;
    tx.execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
        .await?;
    Ok(tx)
}

/// Fetch exact [`ImageFacts`] and authoritative `facts_rev` for a batch of image IDs
/// inside a single `REPEATABLE READ READ ONLY` transaction snapshot.
pub async fn load_image_facts(
    pool: &PgPool,
    image_ids: &[i64],
    policy: &CompiledPolicy,
) -> anyhow::Result<HashMap<i64, ImageFacts>> {
    if image_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let mut tx = begin_repeatable_read_tx(pool).await?;
    let map = load_image_facts_in_tx(&mut tx, image_ids, policy).await?;
    tx.commit().await?;
    Ok(map)
}

/// Internal helper that loads [`ImageFacts`] inside an existing `REPEATABLE READ` transaction.
pub(crate) async fn load_image_facts_in_tx(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    image_ids: &[i64],
    policy: &CompiledPolicy,
) -> anyhow::Result<HashMap<i64, ImageFacts>> {
    if image_ids.is_empty() {
        return Ok(HashMap::new());
    }

    let img_rows = sqlx::query(
        r#"
        SELECT id,
               name::TEXT AS canonical_name,
               (status = 'completed'::process_status) AS is_completed,
               wd_min_persisted_score,
               wd_vocab_digest,
               facts_rev
        FROM images
        WHERE id = ANY($1::BIGINT[])
        "#,
    )
    .bind(image_ids)
    .fetch_all(&mut **tx)
    .await?;

    let mut map: HashMap<i64, ImageFacts> = HashMap::with_capacity(img_rows.len());
    for row in img_rows {
        let id: i64 = row.try_get("id")?;
        let canonical_name: String = row.try_get("canonical_name")?;
        let is_completed: bool = row.try_get("is_completed")?;
        let wd_min_persisted_score: Option<f32> = row.try_get("wd_min_persisted_score")?;
        let wd_vocab_digest: Option<String> = row.try_get("wd_vocab_digest")?;
        let facts_rev: i64 = row.try_get("facts_rev")?;
        let own_rev = facts_rev.max(1) as u64;
        map.insert(
            id,
            ImageFacts {
                image_id: id,
                exists: true,
                is_completed,
                canonical_name: Some(canonical_name),
                wd_min_persisted_score,
                wd_vocab_digest,
                image_own_facts_rev: own_rev,
                facts_rev: compute_image_facts_rev(own_rev, &[]),
                wd_tag_scores: HashMap::new(),
                parent_posts: Vec::new(),
            },
        );
    }

    if map.is_empty() {
        return Ok(map);
    }

    // Load parent posts (always needed for authoritative dependency-fingerprint `facts_rev`).
    let parent_rows = sqlx::query(
        r#"
        SELECT pi.image_id, p.id AS post_id, p.facts_rev
        FROM post_images pi
        JOIN posts p ON p.id = pi.post_id
        WHERE pi.image_id = ANY($1::BIGINT[])
        "#,
    )
    .bind(image_ids)
    .fetch_all(&mut **tx)
    .await?;

    let mut image_post_pairs: HashMap<i64, Vec<(i64, u64)>> = HashMap::new();
    let mut all_post_ids: BTreeSet<i64> = BTreeSet::new();
    for row in parent_rows {
        let image_id: i64 = row.try_get("image_id")?;
        let post_id: i64 = row.try_get("post_id")?;
        let post_rev: i64 = row.try_get("facts_rev")?;
        let rev_u64 = post_rev.max(1) as u64;
        image_post_pairs
            .entry(image_id)
            .or_default()
            .push((post_id, rev_u64));
        all_post_ids.insert(post_id);
    }

    for (&image_id, entry) in &mut map {
        let pairs = image_post_pairs
            .get(&image_id)
            .map(Vec::as_slice)
            .unwrap_or(&[]);
        entry.facts_rev = compute_image_facts_rev(entry.image_own_facts_rev, pairs);
    }

    let mut post_tags_map: HashMap<i64, HashSet<String>> = HashMap::new();
    let mut post_authors_map: HashMap<i64, HashSet<String>> = HashMap::new();

    if policy.is_enabled() {
        if !policy.referenced_wd_tags.is_empty() {
            let wd_rows = sqlx::query(
                r#"
                SELECT wti.image_id, wt.name::TEXT AS name, wti.score
                FROM wd_tag_images wti
                JOIN wd_tags wt ON wt.id = wti.wd_tag_id
                WHERE wti.image_id = ANY($1::BIGINT[])
                  AND wt.name = ANY($2::TEXT[])
                "#,
            )
            .bind(image_ids)
            .bind(&policy.referenced_wd_tags)
            .fetch_all(&mut **tx)
            .await?;

            for row in wd_rows {
                let image_id: i64 = row.try_get("image_id")?;
                let name: String = row.try_get("name")?;
                let score: f32 = row.try_get("score")?;
                if let Some(entry) = map.get_mut(&image_id) {
                    entry.wd_tag_scores.insert(name, score);
                }
            }
        }

        let post_ids_vec: Vec<i64> = all_post_ids.into_iter().collect();

        if !post_ids_vec.is_empty() && !policy.referenced_post_tags.is_empty() {
            let pt_rows = sqlx::query(
                r#"
                SELECT tp.post_id, t.name::TEXT AS name
                FROM tag_posts tp
                JOIN tags t ON t.id = tp.tag_id
                WHERE tp.post_id = ANY($1::BIGINT[])
                  AND t.name = ANY($2::TEXT[])
                "#,
            )
            .bind(&post_ids_vec)
            .bind(&policy.referenced_post_tags)
            .fetch_all(&mut **tx)
            .await?;
            for row in pt_rows {
                let post_id: i64 = row.try_get("post_id")?;
                let name: String = row.try_get("name")?;
                post_tags_map.entry(post_id).or_default().insert(name);
            }
        }

        if !post_ids_vec.is_empty() && !policy.referenced_authors.is_empty() {
            let au_rows = sqlx::query(
                r#"
                SELECT ap.post_id, a.name::TEXT AS name
                FROM author_posts ap
                JOIN authors a ON a.id = ap.author_id
                WHERE ap.post_id = ANY($1::BIGINT[])
                  AND a.name = ANY($2::TEXT[])
                "#,
            )
            .bind(&post_ids_vec)
            .bind(&policy.referenced_authors)
            .fetch_all(&mut **tx)
            .await?;
            for row in au_rows {
                let post_id: i64 = row.try_get("post_id")?;
                let name: String = row.try_get("name")?;
                post_authors_map.entry(post_id).or_default().insert(name);
            }
        }
    }

    // Always attach parent post IDs + revs so `evaluate_image` reproduces the exact same
    // `compute_image_facts_rev` fingerprint as `lookup_facts_rev` even when safety is off.
    for (image_id, pairs) in image_post_pairs {
        if let Some(entry) = map.get_mut(&image_id) {
            for (post_id, post_rev) in pairs {
                entry.parent_posts.push(ImageParentPostFacts {
                    post_id,
                    post_tags: post_tags_map.get(&post_id).cloned().unwrap_or_default(),
                    authors: post_authors_map.get(&post_id).cloned().unwrap_or_default(),
                    facts_rev: post_rev,
                });
            }
        }
    }

    Ok(map)
}

/// Evaluate video outcomes and authoritative `facts_rev` for a batch of videos
/// inside ONE `REPEATABLE READ READ ONLY` DB transaction snapshot.
pub async fn evaluate_videos_batch(
    pool: &PgPool,
    video_ids: &[i64],
    policy: &CompiledPolicy,
    caller: &CallerContext,
) -> anyhow::Result<HashMap<i64, MediaOutcome>> {
    if video_ids.is_empty() {
        return Ok(HashMap::new());
    }
    let mut tx = begin_repeatable_read_tx(pool).await?;
    let out = evaluate_videos_in_tx(&mut tx, video_ids, policy, caller).await?;
    tx.commit().await?;
    Ok(out)
}

pub(crate) async fn evaluate_videos_in_tx(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    video_ids: &[i64],
    policy: &CompiledPolicy,
    caller: &CallerContext,
) -> anyhow::Result<HashMap<i64, MediaOutcome>> {
    let mut out = HashMap::with_capacity(video_ids.len());
    if video_ids.is_empty() {
        return Ok(out);
    }

    let vid_rows = sqlx::query(
        r#"
        SELECT id, name::TEXT AS canonical_name, facts_rev
        FROM videos
        WHERE id = ANY($1::BIGINT[])
        "#,
    )
    .bind(video_ids)
    .fetch_all(&mut **tx)
    .await?;

    let mut video_meta: HashMap<i64, (u64, String)> = HashMap::with_capacity(vid_rows.len());
    for row in vid_rows {
        let id: i64 = row.try_get("id")?;
        let canonical_name: String = row.try_get("canonical_name")?;
        let rev: i64 = row.try_get("facts_rev")?;
        video_meta.insert(id, (rev.max(1) as u64, canonical_name));
    }

    let pv_rows = sqlx::query(
        r#"
        SELECT pv.video_id, p.id AS post_id, p.facts_rev
        FROM post_videos pv
        JOIN posts p ON p.id = pv.post_id
        WHERE pv.video_id = ANY($1::BIGINT[])
        "#,
    )
    .bind(video_ids)
    .fetch_all(&mut **tx)
    .await?;

    let mut video_posts: HashMap<i64, Vec<(i64, u64)>> = HashMap::new();
    let mut all_post_ids: BTreeSet<i64> = BTreeSet::new();
    for row in pv_rows {
        let video_id: i64 = row.try_get("video_id")?;
        let post_id: i64 = row.try_get("post_id")?;
        let post_rev: i64 = row.try_get("facts_rev")?;
        video_posts
            .entry(video_id)
            .or_default()
            .push((post_id, post_rev.max(1) as u64));
        all_post_ids.insert(post_id);
    }

    let post_ids_vec: Vec<i64> = all_post_ids.into_iter().collect();
    let mut post_image_ids: HashMap<i64, Vec<i64>> = HashMap::new();
    let mut all_image_ids: BTreeSet<i64> = BTreeSet::new();
    let mut post_tags: HashMap<i64, HashSet<String>> = HashMap::new();
    let mut post_authors: HashMap<i64, HashSet<String>> = HashMap::new();

    if !post_ids_vec.is_empty() {
        let pi_rows = sqlx::query(
            r#"
            SELECT post_id, image_id
            FROM post_images
            WHERE post_id = ANY($1::BIGINT[])
            "#,
        )
        .bind(&post_ids_vec)
        .fetch_all(&mut **tx)
        .await?;
        for row in pi_rows {
            let post_id: i64 = row.try_get("post_id")?;
            let image_id: i64 = row.try_get("image_id")?;
            post_image_ids.entry(post_id).or_default().push(image_id);
            all_image_ids.insert(image_id);
        }

        if policy.is_enabled() && !policy.referenced_post_tags.is_empty() {
            let pt_rows = sqlx::query(
                r#"
                SELECT tp.post_id, t.name::TEXT AS name
                FROM tag_posts tp
                JOIN tags t ON t.id = tp.tag_id
                WHERE tp.post_id = ANY($1::BIGINT[])
                  AND t.name = ANY($2::TEXT[])
                "#,
            )
            .bind(&post_ids_vec)
            .bind(&policy.referenced_post_tags)
            .fetch_all(&mut **tx)
            .await?;
            for row in pt_rows {
                let post_id: i64 = row.try_get("post_id")?;
                let name: String = row.try_get("name")?;
                post_tags.entry(post_id).or_default().insert(name);
            }
        }

        if policy.is_enabled() && !policy.referenced_authors.is_empty() {
            let au_rows = sqlx::query(
                r#"
                SELECT ap.post_id, a.name::TEXT AS name
                FROM author_posts ap
                JOIN authors a ON a.id = ap.author_id
                WHERE ap.post_id = ANY($1::BIGINT[])
                  AND a.name = ANY($2::TEXT[])
                "#,
            )
            .bind(&post_ids_vec)
            .bind(&policy.referenced_authors)
            .fetch_all(&mut **tx)
            .await?;
            for row in au_rows {
                let post_id: i64 = row.try_get("post_id")?;
                let name: String = row.try_get("name")?;
                post_authors.entry(post_id).or_default().insert(name);
            }
        }
    }

    let img_ids_vec: Vec<i64> = all_image_ids.into_iter().collect();
    let img_facts_map = if img_ids_vec.is_empty() {
        HashMap::new()
    } else {
        load_image_facts_in_tx(tx, &img_ids_vec, policy).await?
    };

    for &vid in video_ids {
        let (base_rev, canonical_name) = match video_meta.get(&vid) {
            Some((r, name)) => (*r, Some(name.clone())),
            None => {
                if policy.is_enabled() {
                    out.insert(
                        vid,
                        MediaOutcome::Placeholder {
                            mask: unclassified_mask(),
                            facts_rev: 1,
                        },
                    );
                } else {
                    out.insert(
                        vid,
                        MediaOutcome::Clear {
                            matched_blocks: Vec::new(),
                            matched_blurs: Vec::new(),
                            facts_rev: 1,
                            canonical_name: None,
                        },
                    );
                }
                continue;
            }
        };

        let mut parent_posts = Vec::new();
        if let Some(pids) = video_posts.get(&vid) {
            for &(pid, post_rev) in pids {
                let mut images = Vec::new();
                if let Some(iids) = post_image_ids.get(&pid) {
                    for iid in iids {
                        if let Some(f) = img_facts_map.get(iid) {
                            images.push(f.clone());
                        }
                    }
                }
                parent_posts.push(ParentPostFacts {
                    post_id: pid,
                    post_facts_rev: post_rev,
                    images,
                    post_tags: post_tags.get(&pid).cloned().unwrap_or_default(),
                    authors: post_authors.get(&pid).cloned().unwrap_or_default(),
                });
            }
        }

        let outcome =
            policy.evaluate_video_posts_with_name(&parent_posts, base_rev, canonical_name, caller);
        out.insert(vid, outcome);
    }

    Ok(out)
}

/// Authoritative single-snapshot `facts_rev` lookup backing `GET /internal/facts-rev/{kind}/{id}`.
///
/// Uses [`compute_image_facts_rev`] / [`compute_video_facts_rev`] over ALL dependency
/// `(id, rev)` pairs inside a single `REPEATABLE READ` snapshot so mutating ANY parent
/// post or sibling image (even one with a lower revision than another parent) ALWAYS
/// changes the fingerprint.
pub async fn lookup_facts_rev(
    pool: &PgPool,
    kind: MediaKind,
    asset_id: i64,
) -> anyhow::Result<Option<u64>> {
    if asset_id <= 0 {
        return Ok(None);
    }
    let mut tx = begin_repeatable_read_tx(pool).await?;
    let rev = match kind {
        MediaKind::Image => {
            let own_row = sqlx::query("SELECT facts_rev FROM images WHERE id = $1")
                .bind(asset_id)
                .fetch_optional(&mut *tx)
                .await?;
            let Some(own_row) = own_row else {
                tx.commit().await?;
                return Ok(None);
            };
            let own_rev = own_row.try_get::<i64, _>("facts_rev")?.max(1) as u64;
            let parent_rows = sqlx::query(
                r#"
                SELECT p.id AS post_id, p.facts_rev
                FROM post_images pi
                JOIN posts p ON p.id = pi.post_id
                WHERE pi.image_id = $1
                "#,
            )
            .bind(asset_id)
            .fetch_all(&mut *tx)
            .await?;
            let mut parents = Vec::with_capacity(parent_rows.len());
            for r in parent_rows {
                let pid: i64 = r.try_get("post_id")?;
                let prev: i64 = r.try_get("facts_rev")?;
                parents.push((pid, prev.max(1) as u64));
            }
            compute_image_facts_rev(own_rev, &parents)
        }
        MediaKind::Video => {
            let own_row = sqlx::query("SELECT facts_rev FROM videos WHERE id = $1")
                .bind(asset_id)
                .fetch_optional(&mut *tx)
                .await?;
            let Some(own_row) = own_row else {
                tx.commit().await?;
                return Ok(None);
            };
            let own_rev = own_row.try_get::<i64, _>("facts_rev")?.max(1) as u64;
            let parent_rows = sqlx::query(
                r#"
                SELECT p.id AS post_id, p.facts_rev
                FROM post_videos pv
                JOIN posts p ON p.id = pv.post_id
                WHERE pv.video_id = $1
                "#,
            )
            .bind(asset_id)
            .fetch_all(&mut *tx)
            .await?;
            let mut parents = Vec::with_capacity(parent_rows.len());
            let mut post_ids = Vec::with_capacity(parent_rows.len());
            for r in parent_rows {
                let pid: i64 = r.try_get("post_id")?;
                let prev: i64 = r.try_get("facts_rev")?;
                parents.push((pid, prev.max(1) as u64));
                post_ids.push(pid);
            }
            let mut siblings = Vec::new();
            if !post_ids.is_empty() {
                let sib_rows = sqlx::query(
                    r#"
                    SELECT pi.post_id, si.id AS image_id, si.facts_rev
                    FROM post_images pi
                    JOIN images si ON si.id = pi.image_id
                    WHERE pi.post_id = ANY($1::BIGINT[])
                    "#,
                )
                .bind(&post_ids)
                .fetch_all(&mut *tx)
                .await?;
                for r in sib_rows {
                    let pid: i64 = r.try_get("post_id")?;
                    let iid: i64 = r.try_get("image_id")?;
                    let srev: i64 = r.try_get("facts_rev")?;
                    siblings.push((pid, iid, srev.max(1) as u64));
                }
            }
            compute_video_facts_rev(own_rev, &parents, &siblings)
        }
    };
    tx.commit().await?;
    Ok(Some(rev))
}

/// Exact catalog validation backing `POST /internal/validate-safety-catalog`.
pub async fn validate_safety_catalog(
    pool: &PgPool,
    post_tags: &[String],
    authors: &[String],
) -> anyhow::Result<CatalogValidationResult> {
    let req_post_tags: BTreeSet<String> = post_tags
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    let req_authors: BTreeSet<String> = authors
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if req_post_tags.is_empty() && req_authors.is_empty() {
        return Ok(CatalogValidationResult::default());
    }

    let mut tx = begin_repeatable_read_tx(pool).await?;

    let mut found_post_tags: HashSet<String> = HashSet::new();
    if !req_post_tags.is_empty() {
        let vec_tags: Vec<String> = req_post_tags.iter().cloned().collect();
        let rows = sqlx::query("SELECT name::TEXT AS name FROM tags WHERE name = ANY($1::TEXT[])")
            .bind(&vec_tags)
            .fetch_all(&mut *tx)
            .await?;
        for r in rows {
            found_post_tags.insert(r.try_get("name")?);
        }
    }

    let mut found_authors: HashSet<String> = HashSet::new();
    if !req_authors.is_empty() {
        let vec_authors: Vec<String> = req_authors.iter().cloned().collect();
        let rows =
            sqlx::query("SELECT name::TEXT AS name FROM authors WHERE name = ANY($1::TEXT[])")
                .bind(&vec_authors)
                .fetch_all(&mut *tx)
                .await?;
        for r in rows {
            found_authors.insert(r.try_get("name")?);
        }
    }

    tx.commit().await?;

    let unknown_post_tags = req_post_tags
        .into_iter()
        .filter(|t| !found_post_tags.contains(t))
        .collect();
    let unknown_authors = req_authors
        .into_iter()
        .filter(|a| !found_authors.contains(a))
        .collect();

    Ok(CatalogValidationResult {
        unknown_post_tags,
        unknown_authors,
    })
}

/// Evaluate a single asset inside ONE `REPEATABLE READ READ ONLY` transaction snapshot
/// for `POST /api/safety/reveal`, returning its authoritative `facts_rev`, locator,
/// and exact `revealed_refs = matched_blurs \ direct_grants`.
pub async fn evaluate_single_asset_for_reveal(
    pool: &PgPool,
    kind: MediaKind,
    asset_id: i64,
    policy: &CompiledPolicy,
    caller: &CallerContext,
) -> anyhow::Result<RevealCheckResult> {
    if asset_id <= 0 {
        return Ok(RevealCheckResult::NotFound);
    }

    let mut tx = begin_repeatable_read_tx(pool).await?;
    let (immutable_locator, outcome) = match kind {
        MediaKind::Image => {
            let row = sqlx::query("SELECT name::TEXT AS name FROM images WHERE id = $1 LIMIT 1")
                .bind(asset_id)
                .fetch_optional(&mut *tx)
                .await?;
            let Some(row) = row else {
                tx.commit().await?;
                return Ok(RevealCheckResult::NotFound);
            };
            let name: String = row.try_get("name")?;
            let locator = format!("{}.webp", name.trim_start_matches('/'));
            let facts_map = load_image_facts_in_tx(&mut tx, &[asset_id], policy).await?;
            let facts = facts_map.get(&asset_id).cloned().unwrap_or_default();
            let outcome = policy.evaluate_image(&facts, caller);
            (locator, outcome)
        }
        MediaKind::Video => {
            let row = sqlx::query("SELECT name::TEXT AS name FROM videos WHERE id = $1 LIMIT 1")
                .bind(asset_id)
                .fetch_optional(&mut *tx)
                .await?;
            let Some(row) = row else {
                tx.commit().await?;
                return Ok(RevealCheckResult::NotFound);
            };
            let name: String = row.try_get("name")?;
            let locator = name.trim_start_matches('/').to_string();
            let outcomes = evaluate_videos_in_tx(&mut tx, &[asset_id], policy, caller).await?;
            let outcome = outcomes.get(&asset_id).cloned().unwrap_or(
                MediaOutcome::Placeholder {
                    mask: unclassified_mask(),
                    facts_rev: 1,
                },
            );
            (locator, outcome)
        }
    };
    tx.commit().await?;

    match outcome {
        MediaOutcome::Clear {
            matched_blocks,
            matched_blurs,
            facts_rev,
            ..
        } => Ok(RevealCheckResult::Allowed {
            immutable_locator,
            facts_rev,
            matched_blocks,
            matched_blurs,
            revealed_refs: Vec::new(),
        }),
        MediaOutcome::Blurred {
            can_click_reveal: true,
            matched_blocks,
            matched_blurs,
            facts_rev,
            ..
        } => {
            let revealed_refs: Vec<PolicyRef> = matched_blurs
                .iter()
                .filter(|r| !caller.has_direct_grant(r))
                .cloned()
                .collect();
            // Double-check every required reveal ref is click-eligible.
            if !revealed_refs.iter().all(|r| caller.is_click_eligible(r)) {
                return Ok(RevealCheckResult::Denied);
            }
            Ok(RevealCheckResult::Allowed {
                immutable_locator,
                facts_rev,
                matched_blocks,
                matched_blurs,
                revealed_refs,
            })
        }
        MediaOutcome::Blurred {
            can_click_reveal: false,
            ..
        }
        | MediaOutcome::Placeholder { .. } => Ok(RevealCheckResult::Denied),
    }
}

/// Evaluate a single image or video by its canonical DB `name` inside ONE
/// `REPEATABLE READ READ ONLY` transaction snapshot (used by Standalone Media Guard).
pub async fn evaluate_asset_by_name(
    pool: &PgPool,
    kind: MediaKind,
    canonical_name: &str,
    policy: &CompiledPolicy,
    caller: &CallerContext,
) -> anyhow::Result<Option<(i64, MediaOutcome)>> {
    let mut tx = begin_repeatable_read_tx(pool).await?;
    let res = match kind {
        MediaKind::Image => {
            let row = sqlx::query("SELECT id FROM images WHERE name = $1 LIMIT 1")
                .bind(canonical_name)
                .fetch_optional(&mut *tx)
                .await?;
            let Some(row) = row else {
                tx.commit().await?;
                return Ok(None);
            };
            let id: i64 = row.try_get("id")?;
            let facts_map = load_image_facts_in_tx(&mut tx, &[id], policy).await?;
            let facts = facts_map.get(&id).cloned().unwrap_or_default();
            let outcome = policy.evaluate_image(&facts, caller);
            Some((id, outcome))
        }
        MediaKind::Video => {
            let row = sqlx::query("SELECT id FROM videos WHERE name = $1 LIMIT 1")
                .bind(canonical_name)
                .fetch_optional(&mut *tx)
                .await?;
            let Some(row) = row else {
                tx.commit().await?;
                return Ok(None);
            };
            let id: i64 = row.try_get("id")?;
            let outcomes = evaluate_videos_in_tx(&mut tx, &[id], policy, caller).await?;
            let outcome = outcomes.get(&id).cloned().unwrap_or(
                MediaOutcome::Placeholder {
                    mask: unclassified_mask(),
                    facts_rev: 1,
                },
            );
            Some((id, outcome))
        }
    };
    tx.commit().await?;
    Ok(res)
}

#[cfg(test)]
mod tests {
    use super::*;
    use site_access::{ContentPolicy, verify_media_capability};
    use sqlx::Execute as _;

    fn sample_policy_v3() -> PublicSitePolicy {
        let mut p = PublicSitePolicy {
            revision: 7,
            min_enforce_rev: 5,
            safety_enabled: true,
            unclassified_mode: UnclassifiedMode::Placeholder,
            fixed_blur_enabled: true,
            age_policy: AgeVerificationPolicy::SelfAttestation,
            policies: vec![
                ContentPolicy {
                    id: "r18".into(),
                    grant_generation: 2,
                    enabled: true,
                    priority: 10,
                    name: "NSFW".into(),
                    preset: PlaceholderPreset::R18,
                    match_expr: "tag:explicit>=0.60 OR tag:nude".into(),
                    except_expr: Some("post_tag:exempt_r18".into()),
                    default_tag_min: 0.45,
                    action: PolicyAction::Block,
                    bypass: PolicyBypass {
                        include_switcher: true,
                        require_gallery_login: true,
                        require_age_18: true,
                        require_current_terms: true,
                        exclude_anonymous: true,
                        ..PolicyBypass::default()
                    },
                },
                ContentPolicy {
                    id: "blood".into(),
                    grant_generation: 1,
                    enabled: true,
                    priority: 20,
                    name: "Blood / Gore".into(),
                    preset: PlaceholderPreset::Blood,
                    match_expr: "tag:blood".into(),
                    except_expr: None,
                    default_tag_min: 0.45,
                    action: PolicyAction::Block,
                    bypass: PolicyBypass {
                        include_switcher: true,
                        ..PolicyBypass::default()
                    },
                },
                ContentPolicy {
                    id: "sensitive".into(),
                    grant_generation: 3,
                    enabled: true,
                    priority: 30,
                    name: "Suggestive".into(),
                    preset: PlaceholderPreset::Sensitive,
                    match_expr: "tag:lingerie".into(),
                    except_expr: None,
                    default_tag_min: 0.45,
                    action: PolicyAction::Blur,
                    bypass: PolicyBypass {
                        include_switcher: true,
                        include_click: true,
                        ..PolicyBypass::default()
                    },
                },
            ],
            ..PublicSitePolicy::default()
        };
        p.refresh_policy_digest();
        p
    }

    #[test]
    fn pure_compiler_succeeds_without_db_tag_cache_and_rejects_unknown_wd_tag() {
        let compiled = CompiledPolicy::compile(sample_policy_v3()).expect("compile v3");
        assert!(compiled.is_enabled());
        assert_eq!(compiled.policies.len(), 3);
        assert!(compiled.referenced_wd_tags.iter().any(|i| i == "explicit"));
        assert!(compiled.referenced_post_tags.iter().any(|i| i == "exempt_r18"));

        // Unknown WD tag rejected at compile time (validated against canonical 10,861-tag vocab)
        let mut bad = sample_policy_v3();
        bad.policies[0].match_expr = "tag:totally_bogus_nonexistent_tag".into();
        assert!(CompiledPolicy::compile(bad).is_err());
    }

    #[test]
    fn tribool_coverage_floor_and_unclassified_continue_mode() {
        let compiled = CompiledPolicy::compile(sample_policy_v3()).unwrap();
        let anon = CallerContext::anonymous();

        // 1. Legacy image with wd_min_persisted_score == None and missing `explicit` row -> Unknown -> Placeholder!
        let legacy_uncovered = ImageFacts {
            image_id: 1,
            exists: true,
            is_completed: true,
            canonical_name: None,
            wd_min_persisted_score: None,
            wd_vocab_digest: Some(search_types::wd_vocab::WD_VOCAB_DIGEST.to_string()),
            image_own_facts_rev: 3,
            facts_rev: compute_image_facts_rev(3, &[]),
            wd_tag_scores: HashMap::new(),
            parent_posts: Vec::new(),
        };
        assert!(compiled.evaluate_image(&legacy_uncovered, &anon).is_placeholder());

        // 1b. Image with wd_min_persisted_score <= threshold BUT mismatched/NULL wd_vocab_digest -> Unknown -> Placeholder (fail-closed H1)!
        let stale_vocab_img = ImageFacts {
            image_id: 2,
            exists: true,
            is_completed: true,
            canonical_name: None,
            wd_min_persisted_score: Some(0.05),
            wd_vocab_digest: Some("0000000000000000000000000000000000000000000000000000000000000000".into()),
            image_own_facts_rev: 3,
            facts_rev: compute_image_facts_rev(3, &[]),
            wd_tag_scores: HashMap::new(),
            parent_posts: Vec::new(),
        };
        assert!(compiled.evaluate_image(&stale_vocab_img, &anon).is_placeholder());
        let null_vocab_img = ImageFacts {
            wd_vocab_digest: None,
            ..stale_vocab_img
        };
        assert!(compiled.evaluate_image(&null_vocab_img, &anon).is_placeholder());

        // 2. Covered image with wd_min_persisted_score = 0.05 (<= 0.45) and no matching rows -> False -> Clear!
        let covered_clean = ImageFacts::completed_with_floor(Some(0.05), HashMap::new());
        assert!(compiled.evaluate_image(&covered_clean, &anon).is_public_safe_clear());

        // 3. Covered image whose floor (0.50) > policy threshold (0.45) -> missing row is STILL Unknown -> Placeholder!
        let loose_floor = ImageFacts::completed_with_floor(Some(0.50), HashMap::new());
        assert!(compiled.evaluate_image(&loose_floor, &anon).is_placeholder());

        // 4. Explicit row below threshold (0.55 < 0.60) + covered floor for other tags -> False -> Clear!
        let below_thresh = ImageFacts::completed_with_floor(
            Some(0.05),
            HashMap::from([("explicit".into(), 0.55)]),
        );
        assert!(compiled.evaluate_image(&below_thresh, &anon).is_public_safe_clear());

        // 5. UnclassifiedMode::Continue waives ONLY general unclassified placeholder;
        //    author/post_tag restrictions STILL run AND any Unknown tag restriction STILL yields Placeholder!
        let mut cont_pol = PublicSitePolicy {
            revision: 2,
            min_enforce_rev: 1,
            safety_enabled: true,
            unclassified_mode: UnclassifiedMode::Continue,
            policies: vec![ContentPolicy {
                id: "author_block".into(),
                grant_generation: 1,
                enabled: true,
                priority: 1,
                name: "Blocked Author".into(),
                preset: PlaceholderPreset::Custom,
                match_expr: "author:bad_artist".into(),
                except_expr: None,
                default_tag_min: 0.45,
                action: PolicyAction::Block,
                bypass: PolicyBypass::default(),
            }],
            ..PublicSitePolicy::default()
        };
        cont_pol.refresh_policy_digest();
        let cont_compiled = CompiledPolicy::compile(cont_pol).unwrap();

        let pending_safe_author = ImageFacts {
            image_id: 3,
            exists: true,
            is_completed: false,
            canonical_name: None,
            wd_min_persisted_score: None,
            wd_vocab_digest: None,
            image_own_facts_rev: 2,
            facts_rev: compute_image_facts_rev(2, &[(1, 2)]),
            wd_tag_scores: HashMap::new(),
            parent_posts: vec![ImageParentPostFacts {
                post_id: 1,
                post_tags: HashSet::new(),
                authors: HashSet::from(["good_artist".into()]),
                facts_rev: 2,
            }],
        };
        assert!(cont_compiled.evaluate_image(&pending_safe_author, &anon).is_clear());

        let pending_bad_author = ImageFacts {
            parent_posts: vec![ImageParentPostFacts {
                post_id: 2,
                post_tags: HashSet::new(),
                authors: HashSet::from(["bad_artist".into()]),
                facts_rev: 2,
            }],
            ..pending_safe_author
        };
        assert!(cont_compiled.evaluate_image(&pending_bad_author, &anon).is_placeholder());
    }

    #[test]
    fn shared_image_multi_parent_never_clears_via_exempt_parent() {
        let compiled = CompiledPolicy::compile(sample_policy_v3()).unwrap();
        let anon = CallerContext::anonymous();

        // Image attached ONLY to exempt parent -> Clear (except_expr = post_tag:exempt_r18 clears r18)
        let exempt_only = ImageFacts {
            image_id: 10,
            exists: true,
            is_completed: true,
            canonical_name: None,
            wd_min_persisted_score: Some(0.05),
            wd_vocab_digest: Some(search_types::wd_vocab::WD_VOCAB_DIGEST.to_string()),
            image_own_facts_rev: 9,
            facts_rev: compute_image_facts_rev(9, &[(100, 9)]),
            wd_tag_scores: HashMap::from([("nude".into(), 0.90)]),
            parent_posts: vec![ImageParentPostFacts {
                post_id: 100,
                post_tags: HashSet::from(["exempt_r18".into()]),
                authors: HashSet::new(),
                facts_rev: 9,
            }],
        };
        assert!(compiled.evaluate_image(&exempt_only, &anon).is_clear());

        // Same image ALSO attached to a non-exempt parent -> Placeholder (strictest across all parents!)
        let mut shared = exempt_only;
        shared.parent_posts.push(ImageParentPostFacts {
            post_id: 200,
            post_tags: HashSet::new(),
            authors: HashSet::new(),
            facts_rev: 12,
        });
        let outcome = compiled.evaluate_image(&shared, &anon);
        assert!(
            matches!(outcome, MediaOutcome::Placeholder { ref mask, .. } if mask.policy_id == "r18")
        );
    }

    #[test]
    fn video_aggregates_both_block_and_blur_and_never_discards_blur() {
        let compiled = CompiledPolicy::compile(sample_policy_v3()).unwrap();
        let guest_click = CallerContext {
            actor: ActorBinding::GuestSession {
                gid: "guest_123456".into(),
            },
            direct_grants: HashSet::new(),
            click_eligible: HashSet::from([PolicyRef::new("sensitive", 3)]),
            is_billing_waived: false,
            age_verified: false,
            terms_accepted: false,
        };

        // Sibling image has own facts_rev = 15, while another unrelated post bumped its effective facts_rev to 99.
        // Video MUST aggregate `image_own_facts_rev = 15` (matching `lookup_facts_rev(Video)`), NOT 99!
        let blur_img = ImageFacts {
            image_id: 42,
            exists: true,
            is_completed: true,
            canonical_name: None,
            wd_min_persisted_score: Some(0.05),
            wd_vocab_digest: Some(search_types::wd_vocab::WD_VOCAB_DIGEST.to_string()),
            image_own_facts_rev: 15,
            facts_rev: 99,
            wd_tag_scores: HashMap::from([("lingerie".into(), 0.85)]),
            parent_posts: Vec::new(),
        };
        let post = ParentPostFacts {
            post_id: 10,
            post_facts_rev: 11,
            images: vec![blur_img],
            post_tags: HashSet::new(),
            authors: HashSet::new(),
        };

        let expected_rev = compute_video_facts_rev(4, &[(10, 11)], &[(10, 42, 15)]);
        // Video MUST become Blurred (NEVER Clear!), inheriting authoritative fingerprint `facts_rev`!
        let outcome = compiled.evaluate_video_posts(&[post], 4, &guest_click);
        assert_eq!(
            outcome,
            MediaOutcome::Blurred {
                policy_id: "sensitive".into(),
                matched_policy_ids: vec!["sensitive".into()],
                label: "Suggestive".into(),
                preset: PlaceholderPreset::Sensitive,
                can_click_reveal: true,
                matched_blocks: vec![],
                matched_blurs: vec![PolicyRef::new("sensitive", 3)],
                facts_rev: expected_rev,
                canonical_name: None,
            }
        );

        // Projected video MUST be Blurred with NO url / NO preview_url / NO reveal_url!
        let vid = Video {
            id: 55,
            name: "clip.mp4".into(),
            width: 1920,
            height: 1080,
            duration: 30,
        };
        let signer = MediaSigner::Managed {
            secret: Arc::new(b"test-secret-32-bytes-0123456789ab".to_vec()),
            now_secs: 1000,
        };
        let projected = compiled.project_video(&vid, outcome, &guest_click, &signer);
        assert!(matches!(
            projected,
            ProjectedVideo::Blurred {
                id: 55,
                preview_url: None,
                can_click_reveal: true,
                policy_rev: 7,
                ..
            }
        ));
    }

    #[test]
    fn blurred_degrades_to_placeholder_when_fixed_blur_disabled_and_never_mints_reveal_url() {
        let mut pol = sample_policy_v3();
        pol.fixed_blur_enabled = false;
        pol.refresh_policy_digest();
        let compiled = CompiledPolicy::compile(pol).unwrap();

        let user = CallerContext {
            actor: ActorBinding::User {
                sub: "usr-1".into(),
                sid: "sid-1".into(),
            },
            direct_grants: HashSet::new(),
            click_eligible: HashSet::from([PolicyRef::new("sensitive", 3)]),
            is_billing_waived: false,
            age_verified: false,
            terms_accepted: false,
        };
        let blur_img = ImageFacts::completed_with_floor(
            Some(0.05),
            HashMap::from([("lingerie".into(), 0.85)]),
        );
        let outcome = compiled.evaluate_image(&blur_img, &user);
        assert!(outcome.is_placeholder(), "fixed_blur_enabled=false must degrade Blur to Placeholder");

        // With fixed_blur_enabled = true, Managed projection emits preview_url ONLY (no reveal_url)
        let compiled_blur = CompiledPolicy::compile(sample_policy_v3()).unwrap();
        let outcome_blur = compiled_blur.evaluate_image(&blur_img, &user);
        assert!(outcome_blur.is_blurred());
        let img = Image {
            id: 42,
            name: "2026/01/test".into(),
            width: 800,
            height: 600,
        };
        let secret = Arc::new(b"media-secret-v3-0123456789abcdef".to_vec());
        let signer = MediaSigner::Managed {
            secret: secret.clone(),
            now_secs: 2000,
        };
        let proj = compiled_blur.project_image(&img, outcome_blur, &user, &signer);
        match proj {
            ProjectedImage::Blurred {
                preview_url: Some(ref p),
                can_click_reveal: true,
                policy_rev: 7,
                ..
            } => {
                assert!(p.starts_with("/media/preview/42?cap=mc3."));
                let tok = p.split("cap=").nth(1).unwrap();
                let verified = verify_media_capability(
                    tok,
                    &secret,
                    MEDIA_CAP_AUDIENCE,
                    MediaCapKind::Preview,
                    42,
                    2050,
                    5,
                    7,
                )
                .expect("preview cap v3 verifies");
                assert_eq!(verified.facts_rev, compute_image_facts_rev(1, &[]));
                assert!(verified.revealed_refs.is_empty());
                assert_eq!(verified.matched_blurs, vec![PolicyRef::new("sensitive", 3)]);
            }
            other => panic!("expected Blurred with preview_url, got {other:?}"),
        }
    }

    #[test]
    fn f1_facts_rev_fingerprint_changes_when_lower_rev_parent_or_sibling_mutates() {
        let rev_before = compute_image_facts_rev(10, &[(1, 100), (2, 5)]);
        let rev_after_parent2 = compute_image_facts_rev(10, &[(1, 100), (2, 6)]);
        assert_ne!(
            rev_before, rev_after_parent2,
            "mutating a lower-rev parent MUST change image facts_rev even when another parent is at rev 100"
        );
        // Order-independent across parent pairs
        assert_eq!(rev_before, compute_image_facts_rev(10, &[(2, 5), (1, 100)]));

        let vid_before = compute_video_facts_rev(4, &[(1, 100), (2, 5)], &[(1, 50, 90), (2, 51, 3)]);
        let vid_after_sibling =
            compute_video_facts_rev(4, &[(1, 100), (2, 5)], &[(1, 50, 90), (2, 51, 4)]);
        assert_ne!(
            vid_before, vid_after_sibling,
            "mutating a lower-rev sibling image MUST change video facts_rev"
        );
    }

    #[test]
    fn f4_empty_rules_still_enforces_global_unclassified_placeholder() {
        let mut pol = PublicSitePolicy {
            revision: 4,
            min_enforce_rev: 1,
            safety_enabled: true,
            unclassified_mode: UnclassifiedMode::Placeholder,
            policies: vec![],
            ..PublicSitePolicy::default()
        };
        pol.refresh_policy_digest();
        let compiled = CompiledPolicy::compile(pol).unwrap();
        assert!(
            compiled.is_enabled(),
            "safety_enabled + UnclassifiedMode::Placeholder must stay enabled even with 0 rules"
        );

        let anon = CallerContext::anonymous();
        let pending = ImageFacts {
            image_id: 9,
            exists: true,
            is_completed: false,
            canonical_name: None,
            wd_min_persisted_score: None,
            wd_vocab_digest: None,
            image_own_facts_rev: 1,
            facts_rev: compute_image_facts_rev(1, &[]),
            wd_tag_scores: HashMap::new(),
            parent_posts: Vec::new(),
        };
        assert!(compiled.evaluate_image(&pending, &anon).is_placeholder());

        let completed = ImageFacts::completed_with_floor(Some(0.05), HashMap::new());
        assert!(compiled.evaluate_image(&completed, &anon).is_clear());

        let mut qb = QueryBuilder::<Postgres>::new("SELECT i.id FROM images i WHERE TRUE");
        assert!(compiled.push_caller_allowed_image_sql(&mut qb, &anon, "i"));
        let built = qb.build();
        assert!(built.sql().as_str().contains("status = 'completed'"));
    }

    fn decode_b64url_test(input: &str) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf: u32 = 0;
        let mut bits: u8 = 0;
        for b in input.bytes() {
            let val = match b {
                b'A'..=b'Z' => b - b'A',
                b'a'..=b'z' => b - b'a' + 26,
                b'0'..=b'9' => b - b'0' + 52,
                b'-' => 62,
                b'_' => 63,
                _ => continue,
            };
            buf = (buf << 6) | u32::from(val);
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push((buf >> bits) as u8);
            }
        }
        out
    }

    #[test]
    fn f19_and_f20_snapshot_canonical_name_overrides_stale_image_name_and_preview_hides_filename() {
        let compiled = CompiledPolicy::compile(sample_policy_v3()).unwrap();
        let user = CallerContext {
            actor: ActorBinding::User {
                sub: "usr-9".into(),
                sid: "sid-9".into(),
            },
            direct_grants: HashSet::new(),
            click_eligible: HashSet::from([PolicyRef::new("sensitive", 3)]),
            is_billing_waived: false,
            age_verified: false,
            terms_accepted: false,
        };
        let secret = Arc::new(b"media-secret-v3-0123456789abcdef".to_vec());
        let signer = MediaSigner::Managed {
            secret: secret.clone(),
            now_secs: 3000,
        };
        let stale_img = Image {
            id: 77,
            name: "2026/01/old_stale_name".into(),
            width: 800,
            height: 600,
        };

        // Clear image uses canonical_name from REPEATABLE READ snapshot rather than stale Image.name.
        let mut facts = ImageFacts::completed_with_floor(Some(0.05), HashMap::new());
        facts.canonical_name = Some("2026/01/renamed_canonical".into());
        let clear_outcome = compiled.evaluate_image(&facts, &user);
        let clear_proj = compiled.project_image(&stale_img, clear_outcome, &user, &signer);
        match clear_proj {
            ProjectedImage::Clear { ref url, .. } => {
                let tok = url.split("cap=").nth(1).unwrap();
                let verified = verify_media_capability(
                    tok,
                    &secret,
                    MEDIA_CAP_AUDIENCE,
                    MediaCapKind::Image,
                    77,
                    3010,
                    5,
                    7,
                )
                .unwrap();
                assert_eq!(verified.immutable_locator, "2026/01/renamed_canonical.webp");
            }
            other => panic!("expected Clear, got {other:?}"),
        }

        // Blurred preview capability uses canonical_name AND seals it in the wire token (F20).
        let mut blur_facts = ImageFacts::completed_with_floor(
            Some(0.05),
            HashMap::from([("lingerie".into(), 0.90)]),
        );
        blur_facts.canonical_name = Some("2026/01/secret_blurred_title".into());
        let blur_outcome = compiled.evaluate_image(&blur_facts, &user);
        let blur_proj = compiled.project_image(&stale_img, blur_outcome, &user, &signer);
        match blur_proj {
            ProjectedImage::Blurred {
                preview_url: Some(ref p),
                ..
            } => {
                let tok = p.split("cap=").nth(1).unwrap();
                let payload_b64 = tok.strip_prefix("mc3.").unwrap().split_once('.').unwrap().0;
                let decoded = String::from_utf8(decode_b64url_test(payload_b64)).unwrap();
                assert!(!decoded.contains("secret_blurred_title"));
                let verified = verify_media_capability(
                    tok,
                    &secret,
                    MEDIA_CAP_AUDIENCE,
                    MediaCapKind::Preview,
                    77,
                    3010,
                    5,
                    7,
                )
                .unwrap();
                assert_eq!(verified.immutable_locator, "2026/01/secret_blurred_title.webp");
            }
            other => panic!("expected Blurred with preview_url, got {other:?}"),
        }
    }

    #[test]
    fn clear_search_sql_filters_both_block_and_blur_with_bound_exact_name_tribool_sql() {
        let compiled = CompiledPolicy::compile(sample_policy_v3()).unwrap();
        let anon = CallerContext::anonymous();
        let mut qb = QueryBuilder::<Postgres>::new("SELECT i.id FROM images i WHERE TRUE");
        assert!(compiled.push_caller_allowed_image_sql(&mut qb, &anon, "i"));
        let built = qb.build();
        let sql_str = built.sql();
        let sql = sql_str.as_str();
        assert!(sql.contains("JOIN wd_tags wt ON wt.id = wti.wd_tag_id"));
        assert!(sql.contains("i.wd_min_persisted_score IS NOT NULL"));
        assert!(sql.contains("IS FALSE"));
        // Post context policy (`r18` has `except_expr = post_tag:exempt_r18`) uses multi-parent check
        assert!(sql.contains("NOT EXISTS (SELECT 1 FROM post_images pi WHERE pi.image_id = i.id"));
        // Blur policy (`sensitive`) is ALSO filtered in Clear-only SQL (used by sitemaps & tag autocomplete).
        assert!(sql.matches("JOIN wd_tags wt ON wt.id = wti.wd_tag_id").count() >= 6);
    }

    #[test]
    fn placeholder_mask_reflects_caller_auth_age_terms_and_no_unlock_path() {
        let compiled = CompiledPolicy::compile(sample_policy_v3()).unwrap();
        let explicit_img = ImageFacts::completed_with_floor(
            Some(0.05),
            HashMap::from([("explicit".into(), 0.90)]),
        );

        // 1. Guest (Anon) sees requires_login=true, requires_age=true, requires_terms=true.
        let anon = CallerContext::anonymous();
        match compiled.evaluate_image(&explicit_img, &anon) {
            MediaOutcome::Placeholder { mask, .. } => {
                assert_eq!(mask.policy_id, "r18");
                assert!(mask.requires_login);
                assert!(mask.requires_age);
                assert!(mask.requires_terms);
                assert!(!mask.matched_policy_ids.iter().any(|s| s == MASK_NO_UNLOCK_MARKER));
            }
            other => panic!("expected Placeholder for anon, got {other:?}"),
        }

        // 2. Signed-in user who has NOT verified 18+ or accepted Terms:
        //    requires_login MUST be false (never bounce signed-in users back to /user/login!).
        let signed_in_unverified = CallerContext {
            actor: ActorBinding::User {
                sub: "usr-1".into(),
                sid: "sid-1".into(),
            },
            age_verified: false,
            terms_accepted: false,
            ..CallerContext::default()
        };
        match compiled.evaluate_image(&explicit_img, &signed_in_unverified) {
            MediaOutcome::Placeholder { mask, .. } => {
                assert!(!mask.requires_login, "signed-in user must not be asked to sign in");
                assert!(mask.requires_age);
                assert!(mask.requires_terms);
                assert!(!mask.matched_policy_ids.iter().any(|s| s == MASK_NO_UNLOCK_MARKER));
            }
            other => panic!("expected Placeholder for unverified user, got {other:?}"),
        }

        // 3. Signed-in user who verified 18+ but has NOT accepted Terms:
        let age_only_user = CallerContext {
            age_verified: true,
            terms_accepted: false,
            ..signed_in_unverified.clone()
        };
        match compiled.evaluate_image(&explicit_img, &age_only_user) {
            MediaOutcome::Placeholder { mask, .. } => {
                assert!(!mask.requires_login);
                assert!(!mask.requires_age);
                assert!(mask.requires_terms);
            }
            other => panic!("expected Placeholder for age-verified user, got {other:?}"),
        }

        // 4. Signed-in user who satisfied BOTH 18+ and Terms (just hasn't enabled switcher yet):
        let ready_user = CallerContext {
            age_verified: true,
            terms_accepted: true,
            ..signed_in_unverified
        };
        match compiled.evaluate_image(&explicit_img, &ready_user) {
            MediaOutcome::Placeholder { mask, .. } => {
                assert!(!mask.requires_login);
                assert!(!mask.requires_age);
                assert!(!mask.requires_terms);
                assert!(!mask.matched_policy_ids.iter().any(|s| s == MASK_NO_UNLOCK_MARKER));
            }
            other => panic!("expected Placeholder for switcher-off user, got {other:?}"),
        }

        // 5. CallerContext::from_assertion preserves caller_age_verified & caller_terms_accepted.
        let assertion = GatewayAssertion {
            v: site_access::GATEWAY_ASSERTION_VERSION,
            aud: site_access::GATEWAY_ASSERTION_AUDIENCE.to_string(),
            actor: ActorBinding::User {
                sub: "usr-2".into(),
                sid: "sid-2".into(),
            },
            rev: 7,
            min_enforce_rev: 5,
            digest: "0".repeat(64),
            direct_grants: vec![],
            click_eligible: vec![],
            is_billing_waived: false,
            caller_age_verified: true,
            caller_terms_accepted: true,
            exp: 2_000_000_000,
        };
        let from_ga = CallerContext::from_assertion(&assertion);
        assert!(from_ga.is_authenticated());
        assert!(from_ga.age_verified);
        assert!(from_ga.terms_accepted);

        // 6. Hard block with NO user unlock path (`!include_switcher && !include_click`)
        //    marks `MASK_NO_UNLOCK_MARKER` so UI hides any misleading unlock CTA!
        let mut locked_pol = PublicSitePolicy {
            revision: 3,
            min_enforce_rev: 1,
            safety_enabled: true,
            policies: vec![ContentPolicy {
                id: "staff_only".into(),
                grant_generation: 1,
                enabled: true,
                priority: 1,
                name: "Staff Restricted".into(),
                preset: PlaceholderPreset::Custom,
                match_expr: "tag:explicit".into(),
                except_expr: None,
                default_tag_min: 0.45,
                action: PolicyAction::Block,
                bypass: PolicyBypass {
                    include_live_admin: true,
                    require_gallery_login: true,
                    ..PolicyBypass::default()
                },
            }],
            ..PublicSitePolicy::default()
        };
        locked_pol.refresh_policy_digest();
        let locked_compiled = CompiledPolicy::compile(locked_pol).unwrap();
        match locked_compiled.evaluate_image(&explicit_img, &anon) {
            MediaOutcome::Placeholder { mask, .. } => {
                assert_eq!(mask.policy_id, "staff_only");
                assert!(!mask.requires_login);
                assert!(!mask.requires_age);
                assert!(!mask.requires_terms);
                assert!(mask.matched_policy_ids.iter().any(|s| s == MASK_NO_UNLOCK_MARKER));
            }
            other => panic!("expected no-unlock Placeholder, got {other:?}"),
        }
    }

    #[test]
    fn indexable_metadata_and_sitemap_sql_allow_bypassable_and_block_hard_blocks() {
        let mut pol = PublicSitePolicy {
            revision: 1,
            min_enforce_rev: 1,
            safety_enabled: true,
            fixed_blur_enabled: false,
            age_policy: AgeVerificationPolicy::SelfAttestation,
            policies: site_access::builtin_safety_presets(),
            ..PublicSitePolicy::default()
        };
        pol.refresh_policy_digest();
        let compiled = CompiledPolicy::compile(pol.clone()).expect("builtin presets compile");
        let anon = CallerContext::anonymous();

        // 1. SFW Clear image -> indexable & public-safe clear
        let sfw = ImageFacts::completed_with_floor(Some(0.30), HashMap::from([("1girl".into(), 0.9)]));
        let sfw_out = compiled.evaluate_image(&sfw, &anon);
        assert!(sfw_out.is_public_safe_clear());
        assert!(sfw_out.is_user_bypassable_or_clear());

        // 2. Bypassable NSFW (`r18`) -> Placeholder, NOT public-safe clear, IS user-bypassable (title indexable!)
        let nsfw =
            ImageFacts::completed_with_floor(Some(0.30), HashMap::from([("explicit".into(), 0.9)]));
        let nsfw_out = compiled.evaluate_image(&nsfw, &anon);
        assert!(nsfw_out.is_placeholder());
        assert!(!nsfw_out.is_public_safe_clear());
        assert!(nsfw_out.is_user_bypassable_or_clear());

        // 3. Bypassable Sensitive (`sensitive`) -> Placeholder when fixed_blur_enabled=false, IS user-bypassable
        let niche =
            ImageFacts::completed_with_floor(Some(0.30), HashMap::from([("bdsm".into(), 0.9)]));
        let niche_out = compiled.evaluate_image(&niche, &anon);
        assert!(niche_out.is_placeholder());
        assert!(niche_out.is_user_bypassable_or_clear());

        // 4. Hard-blocked Extreme / Gore (`blood`) -> NOT user-bypassable (NEVER indexable!)
        let gore =
            ImageFacts::completed_with_floor(Some(0.30), HashMap::from([("blood".into(), 0.9)]));
        let gore_out = compiled.evaluate_image(&gore, &anon);
        assert!(gore_out.is_placeholder());
        assert!(!gore_out.is_user_bypassable_or_clear());

        // 5. Combined NSFW + Extreme (`explicit` + `blood`) -> NOT user-bypassable!
        let nsfw_gore = ImageFacts::completed_with_floor(
            Some(0.30),
            HashMap::from([("explicit".into(), 0.9), ("guro".into(), 0.9)]),
        );
        assert!(!compiled.evaluate_image(&nsfw_gore, &anon).is_user_bypassable_or_clear());

        // 6. Unclassified / pending image -> NOT user-bypassable!
        let pending = ImageFacts::default();
        assert!(!compiled.evaluate_image(&pending, &anon).is_user_bypassable_or_clear());

        // 7. Sitemap indexable SQL: strictly FALSE ONLY for non-bypassable (`blood`, 1 rule),
        //    IS NOT NULL for bypassable WD-tag rules (`r18` & `sensitive`, 2 rules).
        let mut qb = QueryBuilder::<Postgres>::new("SELECT i.id FROM images i WHERE TRUE");
        assert!(compiled.push_indexable_image_sql(&mut qb, "i"));
        let built = qb.build();
        let sql_str = built.sql();
        let sql = sql_str.as_str();
        assert!(sql.contains("i.status = 'completed'::process_status"));
        assert_eq!(
            sql.matches(") IS FALSE)").count(),
            1,
            "only the 1 non-bypassable policy (blood) must require IS FALSE in indexable sitemap SQL"
        );
        assert_eq!(
            sql.matches(") IS NOT NULL)").count(),
            2,
            "the 2 bypassable WD-tag policies (r18, sensitive) must allow TRUE/FALSE and reject only Unknown/NULL"
        );

        // 8. Non-bypassable Blur rule with fixed_blur_enabled=true marks MASK_NO_UNLOCK_MARKER
        let mut hard_blur_pol = PublicSitePolicy {
            revision: 2,
            min_enforce_rev: 1,
            safety_enabled: true,
            fixed_blur_enabled: true,
            policies: vec![ContentPolicy {
                id: "hard_blur".into(),
                grant_generation: 1,
                enabled: true,
                priority: 1,
                name: "Hard Blur".into(),
                preset: PlaceholderPreset::Blood,
                match_expr: "tag:blood >= 0.45".into(),
                except_expr: None,
                default_tag_min: 0.45,
                action: PolicyAction::Blur,
                bypass: PolicyBypass::default(),
            }],
            ..PublicSitePolicy::default()
        };
        hard_blur_pol.refresh_policy_digest();
        let hard_blur_compiled = CompiledPolicy::compile(hard_blur_pol).unwrap();
        let hb_out = hard_blur_compiled.evaluate_image(&gore, &anon);
        assert!(hb_out.is_blurred());
        assert!(!hb_out.is_user_bypassable_or_clear());
    }
}
