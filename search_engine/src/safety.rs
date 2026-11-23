//! Server-side content safety rule compiler, evaluator, video inheritance,
//! anti-oracle SQL filtering, and unified media projection / capability signing.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    fmt,
    sync::Arc,
};

use anyhow::{Context as _, anyhow, bail};
use search_types::{
    BlurDeliveryMode, Image, MaskMetadata, ProjectedImage, ProjectedVideo, Video,
    safety::{SafetyExpr, SafetyPredicate, parse_safety_rule, validate_policy_rules},
};
use site_access::{
    AgeVerificationPolicy, GatewayAssertion, MEDIA_CAP_ANON_SUB, MEDIA_CAP_VERSION, MediaCapKind,
    MediaCapability, PlaceholderPreset, PublicSitePolicy, RuleMode, UnclassifiedMode,
    compute_policy_digest, sign_media_capability,
};
use sqlx::{PgPool, Postgres, QueryBuilder, Row as _};

/// Public/anonymous capability TTL (1 hour — bounded 1..6h for SEO/crawlers,
/// immediately invalidated by `min_enforce_rev` tightening).
pub const PUBLIC_MEDIA_CAP_TTL_SECS: u64 = 3600;

/// Restricted clear-media capability TTL (5 minutes — short 5..10m TTL bound
/// to caller `sub`, `sid`, and required switchers).
pub const RESTRICTED_MEDIA_CAP_TTL_SECS: u64 = 300;

/// Explicit error returned when a similarity search seed (`search_similar` or
/// `dino:<id>` / `-dino:<id>`) is locked for the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedLockedError {
    pub image_id: i64,
    pub rule_id: String,
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

/// Verified caller identity & safety preferences pinned for a single request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CallerContext {
    /// Authenticated subject (`None` for anonymous, `Some("admin")` for admin view,
    /// or `Some(user_id)`).
    pub sub: Option<String>,
    /// Revocable v2 session identifier (`sid`).
    pub sid: Option<String>,
    /// Verified active Switcher rule IDs allowed for this caller.
    /// Always ignored (treated as empty) when `safe_mode == true`.
    pub switchers: HashSet<String>,
    /// Panic / Safe Mode flag (forces empty effective switchers).
    pub safe_mode: bool,
    /// Admin browse view marker.
    pub is_admin_view: bool,
}

impl CallerContext {
    pub fn anonymous() -> Self {
        Self::default()
    }

    pub fn from_assertion(assertion: &GatewayAssertion) -> Self {
        let switchers = if assertion.safe_mode {
            HashSet::new()
        } else {
            assertion.switchers.iter().cloned().collect()
        };
        let sub = match (&assertion.sub, assertion.is_admin_view) {
            (Some(s), _) => Some(s.clone()),
            (None, true) => Some("admin".to_string()),
            (None, false) => None,
        };
        Self {
            sub,
            sid: assertion.sid.clone(),
            switchers,
            safe_mode: assertion.safe_mode,
            is_admin_view: assertion.is_admin_view,
        }
    }

    pub fn has_switcher(&self, rule_id: &str) -> bool {
        !self.safe_mode && self.switchers.contains(rule_id)
    }
}

/// Strategy used when turning evaluated media into `ProjectedImage` / `ProjectedVideo`.
#[derive(Debug, Clone)]
pub enum MediaSigner {
    /// Standalone mode: emits direct `/images/{encoded_name}.webp` and `/videos/{encoded_name}`.
    Standalone,
    /// Managed mode: emits HMAC-SHA256 signed `/media/{image|video|preview}/{id}?cap=...`.
    Managed {
        secret: Arc<Vec<u8>>,
        now_secs: u64,
    },
}

/// Compiled leaf predicate bound to exact canonical Postgres row IDs.
#[derive(Debug, Clone, PartialEq)]
pub enum CompiledPredicate {
    WdTag { tag_id: i64, min_score: f32 },
    PostTag(i64),
    Author(i64),
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
    pub fn eval(&self, facts: &ImageFacts) -> bool {
        match self {
            Self::Predicate(pred) => match pred {
                CompiledPredicate::WdTag { tag_id, min_score } => facts
                    .wd_tag_scores
                    .get(tag_id)
                    .is_some_and(|&score| score >= *min_score),
                CompiledPredicate::PostTag(tag_id) => facts.post_tag_ids.contains(tag_id),
                CompiledPredicate::Author(author_id) => facts.author_ids.contains(author_id),
                CompiledPredicate::Unclassified => !facts.is_completed,
            },
            Self::Not(inner) => !inner.eval(facts),
            Self::And(items) => items.iter().all(|e| e.eval(facts)),
            Self::Or(items) => items.iter().any(|e| e.eval(facts)),
        }
    }

    /// Push a parameterized SQL boolean expression referencing `images` alias `img_alias`.
    pub fn push_sql(&self, qb: &mut QueryBuilder<Postgres>, img_alias: &'static str) {
        match self {
            Self::Predicate(pred) => match pred {
                CompiledPredicate::WdTag { tag_id, min_score } => {
                    qb.push("EXISTS (SELECT 1 FROM wd_tag_images wti WHERE wti.image_id = ");
                    qb.push(img_alias);
                    qb.push(".id AND wti.wd_tag_id = ");
                    qb.push_bind(*tag_id);
                    qb.push(" AND wti.score >= ");
                    qb.push_bind(*min_score);
                    qb.push(")");
                }
                CompiledPredicate::PostTag(tag_id) => {
                    qb.push(
                        "EXISTS (SELECT 1 FROM post_images pi JOIN tag_posts tp ON tp.post_id = pi.post_id WHERE pi.image_id = ",
                    );
                    qb.push(img_alias);
                    qb.push(".id AND tp.tag_id = ");
                    qb.push_bind(*tag_id);
                    qb.push(")");
                }
                CompiledPredicate::Author(author_id) => {
                    qb.push(
                        "EXISTS (SELECT 1 FROM post_images pi JOIN author_posts ap ON ap.post_id = pi.post_id WHERE pi.image_id = ",
                    );
                    qb.push(img_alias);
                    qb.push(".id AND ap.author_id = ");
                    qb.push_bind(*author_id);
                    qb.push(")");
                }
                CompiledPredicate::Unclassified => {
                    qb.push("(");
                    qb.push(img_alias);
                    qb.push(".status <> 'completed'::process_status)");
                }
            },
            Self::Not(inner) => {
                qb.push("(NOT ");
                inner.push_sql(qb, img_alias);
                qb.push(")");
            }
            Self::And(items) => {
                qb.push("(");
                for (idx, item) in items.iter().enumerate() {
                    if idx > 0 {
                        qb.push(" AND ");
                    }
                    item.push_sql(qb, img_alias);
                }
                qb.push(")");
            }
            Self::Or(items) => {
                qb.push("(");
                for (idx, item) in items.iter().enumerate() {
                    if idx > 0 {
                        qb.push(" OR ");
                    }
                    item.push_sql(qb, img_alias);
                }
                qb.push(")");
            }
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CompiledRule {
    pub id: String,
    pub name: String,
    pub mode: RuleMode,
    pub preset: PlaceholderPreset,
    pub requires_login: bool,
    pub requires_age_18: bool,
    pub expr: CompiledExpr,
    pub referenced_wd_tag_ids: HashSet<i64>,
}

/// Immutable compiled policy snapshot pinned per request.
#[derive(Debug, Clone)]
pub struct CompiledPolicy {
    pub policy: PublicSitePolicy,
    pub digest: String,
    pub rules: Vec<CompiledRule>,
    pub referenced_wd_tag_ids: Vec<i64>,
    pub referenced_post_tag_ids: Vec<i64>,
    pub referenced_author_ids: Vec<i64>,
    pub restricted_wd_tag_ids: HashSet<i64>,
}

impl CompiledPolicy {
    /// Disabled default policy (Standalone default, zero SQL overhead).
    pub fn disabled() -> Self {
        let policy = PublicSitePolicy::default();
        let digest = compute_policy_digest(&policy);
        Self {
            policy,
            digest,
            rules: Vec::new(),
            referenced_wd_tag_ids: Vec::new(),
            referenced_post_tag_ids: Vec::new(),
            referenced_author_ids: Vec::new(),
            restricted_wd_tag_ids: HashSet::new(),
        }
    }

    pub fn is_enabled(&self) -> bool {
        self.policy.safety_enabled && !self.rules.is_empty()
    }

    pub fn has_active_switcher_rules(&self) -> bool {
        self.policy.safety_enabled && self.rules.iter().any(|r| r.mode == RuleMode::Switcher)
    }

    /// Compile a [`PublicSitePolicy`] against exact Postgres canonical IDs (`wd_tags.name`,
    /// `tags.name`, `authors.name`). Never uses fuzzy `ILIKE` or translation alias matching.
    pub async fn compile(policy: PublicSitePolicy, pool: &PgPool) -> anyhow::Result<Self> {
        let digest = compute_policy_digest(&policy);
        if !policy.safety_enabled {
            return Ok(Self {
                policy,
                digest,
                rules: Vec::new(),
                referenced_wd_tag_ids: Vec::new(),
                referenced_post_tag_ids: Vec::new(),
                referenced_author_ids: Vec::new(),
                restricted_wd_tag_ids: HashSet::new(),
            });
        }

        let enabled: Vec<_> = policy.rules.iter().filter(|r| r.enabled).collect();
        if enabled.is_empty() {
            return Ok(Self {
                policy,
                digest,
                rules: Vec::new(),
                referenced_wd_tag_ids: Vec::new(),
                referenced_post_tag_ids: Vec::new(),
                referenced_author_ids: Vec::new(),
                restricted_wd_tag_ids: HashSet::new(),
            });
        }

        validate_policy_rules(enabled.iter().map(|r| r.query.as_str()))
            .map_err(|e| anyhow!("invalid safety policy rules: {e}"))?;

        let mut parsed_exprs = Vec::with_capacity(enabled.len());
        let mut wd_names = BTreeSet::new();
        let mut post_tag_names = BTreeSet::new();
        let mut author_names = BTreeSet::new();

        for rule in &enabled {
            let expr = parse_safety_rule(&rule.query)
                .map_err(|e| anyhow!("invalid safety rule '{}': {e}", rule.id))?;
            for n in expr.referenced_wd_tags() {
                wd_names.insert(n);
            }
            for n in expr.referenced_post_tags() {
                post_tag_names.insert(n);
            }
            for n in expr.referenced_authors() {
                author_names.insert(n);
            }
            parsed_exprs.push(expr);
        }

        let wd_map = resolve_exact_names(pool, "wd_tags", &wd_names)
            .await
            .context("failed resolving wd_tags for safety policy")?;
        let post_tag_map = resolve_exact_names(pool, "tags", &post_tag_names)
            .await
            .context("failed resolving tags for safety policy")?;
        let author_map = resolve_exact_names(pool, "authors", &author_names)
            .await
            .context("failed resolving authors for safety policy")?;

        Self::compile_with_resolver(policy, &wd_map, &post_tag_map, &author_map)
    }

    /// Pure deterministic compiler using pre-resolved exact name -> ID maps.
    /// Fails closed if any referenced canonical name is missing or invalid.
    pub fn compile_with_resolver(
        policy: PublicSitePolicy,
        wd_tags: &HashMap<String, i64>,
        post_tags: &HashMap<String, i64>,
        authors: &HashMap<String, i64>,
    ) -> anyhow::Result<Self> {
        let digest = compute_policy_digest(&policy);
        if !policy.safety_enabled {
            return Ok(Self {
                policy,
                digest,
                rules: Vec::new(),
                referenced_wd_tag_ids: Vec::new(),
                referenced_post_tag_ids: Vec::new(),
                referenced_author_ids: Vec::new(),
                restricted_wd_tag_ids: HashSet::new(),
            });
        }

        let enabled: Vec<_> = policy.rules.iter().filter(|r| r.enabled).collect();
        if enabled.is_empty() {
            return Ok(Self {
                policy,
                digest,
                rules: Vec::new(),
                referenced_wd_tag_ids: Vec::new(),
                referenced_post_tag_ids: Vec::new(),
                referenced_author_ids: Vec::new(),
                restricted_wd_tag_ids: HashSet::new(),
            });
        }

        validate_policy_rules(enabled.iter().map(|r| r.query.as_str()))
            .map_err(|e| anyhow!("invalid safety policy rules: {e}"))?;

        let mut seen_rule_ids = HashSet::new();
        let mut compiled_rules = Vec::with_capacity(enabled.len());
        let mut all_wd = BTreeSet::new();
        let mut all_post = BTreeSet::new();
        let mut all_authors = BTreeSet::new();
        let mut restricted_wd = HashSet::new();

        for rule in enabled {
            let trimmed_id = rule.id.trim();
            if trimmed_id.is_empty() || trimmed_id != rule.id {
                bail!("safety rule id '{}' must be non-empty without padding", rule.id);
            }
            if !seen_rule_ids.insert(rule.id.clone()) {
                bail!("duplicate enabled safety rule id '{}'", rule.id);
            }
            if !rule.default_min_score.is_finite()
                || rule.default_min_score <= 0.0
                || rule.default_min_score > 1.0
            {
                bail!(
                    "safety rule '{}' default_min_score {} must be in (0.0, 1.0]",
                    rule.id,
                    rule.default_min_score
                );
            }

            let ast = parse_safety_rule(&rule.query)
                .map_err(|e| anyhow!("invalid safety rule '{}': {e}", rule.id))?;
            let mut rule_wd = HashSet::new();
            let expr = compile_expr(
                &ast,
                rule.default_min_score,
                wd_tags,
                post_tags,
                authors,
                &mut rule_wd,
                &mut all_post,
                &mut all_authors,
            )?;
            for &id in &rule_wd {
                all_wd.insert(id);
                if rule.mode == RuleMode::Switcher {
                    restricted_wd.insert(id);
                }
            }
            compiled_rules.push(CompiledRule {
                id: rule.id.clone(),
                name: rule.name.clone(),
                mode: rule.mode,
                preset: rule.preset,
                requires_login: rule.requires_login,
                requires_age_18: rule.requires_age_18,
                expr,
                referenced_wd_tag_ids: rule_wd,
            });
        }

        Ok(Self {
            policy,
            digest,
            rules: compiled_rules,
            referenced_wd_tag_ids: all_wd.into_iter().collect(),
            referenced_post_tag_ids: all_post.into_iter().collect(),
            referenced_author_ids: all_authors.into_iter().collect(),
            restricted_wd_tag_ids: restricted_wd,
        })
    }

    /// Evaluate safety rules for a single image given its exact DB facts and caller context.
    pub fn evaluate_image(&self, facts: &ImageFacts, caller: &CallerContext) -> MediaOutcome {
        if !self.is_enabled() {
            return MediaOutcome::Clear {
                req_switchers: Vec::new(),
            };
        }

        // Fail-closed Unclassified lock when any Switcher rule is enabled.
        if !facts.is_completed
            && self.policy.unclassified_mode == UnclassifiedMode::LockFailClosed
            && self.has_active_switcher_rules()
        {
            return MediaOutcome::Locked {
                mask: unclassified_mask(),
            };
        }

        let mut matched_switchers: Vec<&CompiledRule> = Vec::new();
        let mut unsatisfied_switchers: Vec<&CompiledRule> = Vec::new();
        let mut first_spoiler: Option<&CompiledRule> = None;

        for rule in &self.rules {
            if !rule.expr.eval(facts) {
                continue;
            }
            match rule.mode {
                RuleMode::Switcher => {
                    matched_switchers.push(rule);
                    if !caller.has_switcher(&rule.id) {
                        unsatisfied_switchers.push(rule);
                    }
                }
                RuleMode::SpoilerBlur => {
                    if first_spoiler.is_none() {
                        first_spoiler = Some(rule);
                    }
                }
            }
        }

        // Multi-rule precedence: ANY unsatisfied Switcher lock ALWAYS overrides SpoilerBlur.
        if !unsatisfied_switchers.is_empty() {
            return MediaOutcome::Locked {
                mask: aggregate_lock_mask(&unsatisfied_switchers, &self.policy),
            };
        }

        let mut req_switchers: Vec<String> =
            matched_switchers.into_iter().map(|r| r.id.clone()).collect();
        req_switchers.sort();
        req_switchers.dedup();

        if let Some(spoiler) = first_spoiler {
            return MediaOutcome::Spoiler {
                rule_id: spoiler.id.clone(),
                label: spoiler.name.clone(),
                preset: spoiler.preset,
                req_switchers,
            };
        }

        MediaOutcome::Clear { req_switchers }
    }

    /// Evaluate a video by inheriting the strictest rule outcome across its parent post(s)'
    /// images, post tags, and authors. Video-only posts (or posts with zero `completed`
    /// images) evaluate as `Unclassified` -> `Locked` whenever any Switcher rule is enabled
    /// (unless `UnclassifiedMode::Allow`).
    pub fn evaluate_video(
        &self,
        parent_images: &[ImageFacts],
        post_tag_ids: &HashSet<i64>,
        author_ids: &HashSet<i64>,
        caller: &CallerContext,
    ) -> MediaOutcome {
        if !self.is_enabled() {
            return MediaOutcome::Clear {
                req_switchers: Vec::new(),
            };
        }

        let has_any_completed = parent_images.iter().any(|img| img.is_completed);
        let has_unclassified = parent_images.is_empty()
            || !has_any_completed
            || parent_images.iter().any(|img| !img.is_completed);

        if has_unclassified
            && self.policy.unclassified_mode == UnclassifiedMode::LockFailClosed
            && self.has_active_switcher_rules()
        {
            return MediaOutcome::Locked {
                mask: unclassified_mask(),
            };
        }

        let mut all_req_switchers: BTreeSet<String> = BTreeSet::new();
        let mut locked_masks: Vec<MaskMetadata> = Vec::new();

        // Always evaluate post-level tags and authors — both for video-only posts
        // (under UnclassifiedMode::Allow) AND merged onto every parent image so rules
        // referencing `post_tag:` or `author:` (alone or combined with `tag:`) always apply.
        if parent_images.is_empty() {
            let synthetic = ImageFacts {
                is_completed: false,
                wd_tag_scores: HashMap::new(),
                post_tag_ids: post_tag_ids.clone(),
                author_ids: author_ids.clone(),
            };
            match self.evaluate_image(&synthetic, caller) {
                MediaOutcome::Locked { mask } => locked_masks.push(mask),
                MediaOutcome::Clear { req_switchers }
                | MediaOutcome::Spoiler { req_switchers, .. } => {
                    for sw in req_switchers {
                        all_req_switchers.insert(sw);
                    }
                }
            }
        } else {
            for img in parent_images {
                let mut merged = img.clone();
                merged.post_tag_ids.extend(post_tag_ids.iter().copied());
                merged.author_ids.extend(author_ids.iter().copied());
                match self.evaluate_image(&merged, caller) {
                    MediaOutcome::Locked { mask } => locked_masks.push(mask),
                    MediaOutcome::Clear { req_switchers }
                    | MediaOutcome::Spoiler { req_switchers, .. } => {
                        for sw in req_switchers {
                            all_req_switchers.insert(sw);
                        }
                    }
                }
            }
        }

        if let Some(merged) = merge_masks(&locked_masks) {
            return MediaOutcome::Locked { mask: merged };
        }

        MediaOutcome::Clear {
            req_switchers: all_req_switchers.into_iter().collect(),
        }
    }

    /// Evaluate a video that may belong to zero, one, or multiple parent posts by
    /// evaluating EVERY parent post independently and taking the strictest outcome
    /// across all parent posts.
    ///
    /// A video belonging to a safe-image post AND a video-only (or restricted post-tag /
    /// restricted author) post fails closed (`Locked`) whenever any parent post locks.
    pub fn evaluate_video_posts(
        &self,
        posts: &[ParentPostFacts],
        caller: &CallerContext,
    ) -> MediaOutcome {
        if !self.is_enabled() {
            return MediaOutcome::Clear {
                req_switchers: Vec::new(),
            };
        }

        if posts.is_empty() {
            if self.policy.unclassified_mode == UnclassifiedMode::LockFailClosed
                && self.has_active_switcher_rules()
            {
                return MediaOutcome::Locked {
                    mask: unclassified_mask(),
                };
            }
            return MediaOutcome::Clear {
                req_switchers: Vec::new(),
            };
        }

        let mut all_req_switchers: BTreeSet<String> = BTreeSet::new();
        let mut locked_masks: Vec<MaskMetadata> = Vec::new();

        for post in posts {
            match self.evaluate_video(&post.images, &post.post_tag_ids, &post.author_ids, caller) {
                MediaOutcome::Locked { mask } => locked_masks.push(mask),
                MediaOutcome::Clear { req_switchers }
                | MediaOutcome::Spoiler { req_switchers, .. } => {
                    for sw in req_switchers {
                        all_req_switchers.insert(sw);
                    }
                }
            }
        }

        if let Some(merged) = merge_masks(&locked_masks) {
            return MediaOutcome::Locked { mask: merged };
        }

        MediaOutcome::Clear {
            req_switchers: all_req_switchers.into_iter().collect(),
        }
    }

    /// Project an `Image` + its evaluated [`MediaOutcome`] into a typed [`ProjectedImage`].
    pub fn project_image(
        &self,
        image: &Image,
        outcome: MediaOutcome,
        caller: &CallerContext,
        signer: &MediaSigner,
    ) -> ProjectedImage {
        match outcome {
            MediaOutcome::Locked { mask } => ProjectedImage::Locked {
                id: image.id,
                width: image.width,
                height: image.height,
                mask,
            },
            MediaOutcome::Clear { req_switchers } => match signer {
                MediaSigner::Standalone => ProjectedImage::Clear {
                    id: image.id,
                    url: format!("/images/{}.webp", encode_url_path(&image.name)),
                    name: Some(image.name.clone()),
                    width: image.width,
                    height: image.height,
                },
                MediaSigner::Managed { secret, now_secs } => {
                    let path = format!("{}.webp", image.name.trim_start_matches('/'));
                    match mint_cap_url(
                        secret,
                        *now_secs,
                        self.policy.revision,
                        MediaCapKind::Image,
                        image.id,
                        path,
                        &req_switchers,
                        caller,
                    ) {
                        Ok(url) => ProjectedImage::Clear {
                            id: image.id,
                            url,
                            name: None,
                            width: image.width,
                            height: image.height,
                        },
                        Err(mask) => ProjectedImage::Locked {
                            id: image.id,
                            width: image.width,
                            height: image.height,
                            mask,
                        },
                    }
                }
            },
            MediaOutcome::Spoiler {
                rule_id,
                label,
                preset,
                req_switchers,
            } => {
                let preset_str = preset.as_str().to_string();
                match signer {
                    MediaSigner::Standalone => {
                        let url = format!("/images/{}.webp", encode_url_path(&image.name));
                        ProjectedImage::Spoiler {
                            id: image.id,
                            preview_url: url.clone(),
                            reveal_url: url,
                            width: image.width,
                            height: image.height,
                            rule_id,
                            label,
                            preset: preset_str,
                            blur_mode: BlurDeliveryMode::CssCourtesy,
                        }
                    }
                    MediaSigner::Managed { secret, now_secs } => {
                        let path = format!("{}.webp", image.name.trim_start_matches('/'));
                        let reveal_res = mint_cap_url(
                            secret,
                            *now_secs,
                            self.policy.revision,
                            MediaCapKind::Image,
                            image.id,
                            path.clone(),
                            &req_switchers,
                            caller,
                        );
                        let reveal_url = match reveal_res {
                            Ok(u) => u,
                            Err(mask) => {
                                return ProjectedImage::Locked {
                                    id: image.id,
                                    width: image.width,
                                    height: image.height,
                                    mask,
                                };
                            }
                        };
                        if self.policy.cloudflare_images_blur {
                            let preview_res = mint_cap_url(
                                secret,
                                *now_secs,
                                self.policy.revision,
                                MediaCapKind::Preview,
                                image.id,
                                path,
                                &req_switchers,
                                caller,
                            );
                            match preview_res {
                                Ok(preview_url) => ProjectedImage::Spoiler {
                                    id: image.id,
                                    preview_url,
                                    reveal_url,
                                    width: image.width,
                                    height: image.height,
                                    rule_id,
                                    label,
                                    preset: preset_str,
                                    blur_mode: BlurDeliveryMode::ServerTransform,
                                },
                                Err(mask) => ProjectedImage::Locked {
                                    id: image.id,
                                    width: image.width,
                                    height: image.height,
                                    mask,
                                },
                            }
                        } else {
                            ProjectedImage::Spoiler {
                                id: image.id,
                                preview_url: reveal_url.clone(),
                                reveal_url,
                                width: image.width,
                                height: image.height,
                                rule_id,
                                label,
                                preset: preset_str,
                                blur_mode: BlurDeliveryMode::CssCourtesy,
                            }
                        }
                    }
                }
            }
        }
    }

    /// Project a `Video` + its evaluated [`MediaOutcome`] into a typed [`ProjectedVideo`].
    pub fn project_video(
        &self,
        video: &Video,
        outcome: MediaOutcome,
        caller: &CallerContext,
        signer: &MediaSigner,
    ) -> ProjectedVideo {
        match outcome {
            MediaOutcome::Locked { mask } => ProjectedVideo::Locked {
                id: video.id,
                width: video.width,
                height: video.height,
                duration: video.duration,
                mask,
            },
            MediaOutcome::Clear { req_switchers }
            | MediaOutcome::Spoiler { req_switchers, .. } => match signer {
                MediaSigner::Standalone => ProjectedVideo::Clear {
                    id: video.id,
                    url: format!("/videos/{}", encode_url_path(&video.name)),
                    name: Some(video.name.clone()),
                    width: video.width,
                    height: video.height,
                    duration: video.duration,
                },
                MediaSigner::Managed { secret, now_secs } => {
                    let path = video.name.trim_start_matches('/').to_string();
                    match mint_cap_url(
                        secret,
                        *now_secs,
                        self.policy.revision,
                        MediaCapKind::Video,
                        video.id,
                        path,
                        &req_switchers,
                        caller,
                    ) {
                        Ok(url) => ProjectedVideo::Clear {
                            id: video.id,
                            url,
                            name: None,
                            width: video.width,
                            height: video.height,
                            duration: video.duration,
                        },
                        Err(mask) => ProjectedVideo::Locked {
                            id: video.id,
                            width: video.width,
                            height: video.height,
                            duration: video.duration,
                            mask,
                        },
                    }
                }
            },
        }
    }

    /// Push SQL exclusion clauses onto `qb` (inside a `WHERE` clause, starting with `AND ...`)
    /// so images locked for `caller` never match search, vector ranking, autocomplete, or sitemaps.
    ///
    /// Returns `true` if any filter predicate was emitted.
    pub fn push_caller_allowed_image_sql(
        &self,
        qb: &mut QueryBuilder<Postgres>,
        caller: &CallerContext,
        img_alias: &'static str,
    ) -> bool {
        if !self.has_active_switcher_rules() {
            return false;
        }
        let mut emitted = false;
        if self.policy.unclassified_mode == UnclassifiedMode::LockFailClosed {
            qb.push(" AND ");
            qb.push(img_alias);
            qb.push(".status = 'completed'::process_status");
            emitted = true;
        }
        for rule in &self.rules {
            if rule.mode == RuleMode::Switcher && !caller.has_switcher(&rule.id) {
                qb.push(" AND NOT ");
                rule.expr.push_sql(qb, img_alias);
                emitted = true;
            }
        }
        emitted
    }
}

/// Pair of pinned policy + verified caller passed to `Engine` search/filter methods.
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
        self.policy.has_active_switcher_rules()
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

/// Exact DB metadata facts for evaluating safety rules on an image.
#[derive(Debug, Clone, Default)]
pub struct ImageFacts {
    pub is_completed: bool,
    pub wd_tag_scores: HashMap<i64, f32>,
    pub post_tag_ids: HashSet<i64>,
    pub author_ids: HashSet<i64>,
}

/// Parent post metadata facts used to evaluate a video's inherited safety outcome
/// independently per parent post.
#[derive(Debug, Clone, Default)]
pub struct ParentPostFacts {
    pub images: Vec<ImageFacts>,
    pub post_tag_ids: HashSet<i64>,
    pub author_ids: HashSet<i64>,
}

/// Outcome of evaluating a [`CompiledPolicy`] on an image or video for a caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MediaOutcome {
    Clear {
        /// Switcher rule IDs that matched and were satisfied by the caller.
        /// Empty means truly public safe media.
        req_switchers: Vec<String>,
    },
    Spoiler {
        rule_id: String,
        label: String,
        preset: PlaceholderPreset,
        /// Any matched Switcher rules that were satisfied by the caller.
        req_switchers: Vec<String>,
    },
    Locked {
        mask: MaskMetadata,
    },
}

impl MediaOutcome {
    pub fn is_locked(&self) -> bool {
        matches!(self, Self::Locked { .. })
    }

    pub fn is_public_safe_clear(&self) -> bool {
        matches!(self, Self::Clear { req_switchers } if req_switchers.is_empty())
    }
}

fn unclassified_mask() -> MaskMetadata {
    MaskMetadata {
        rule_id: "unclassified".to_string(),
        label: "Pending classification".to_string(),
        preset: PlaceholderPreset::Custom.as_str().to_string(),
        requires_login: false,
        requires_age: false,
        requires_terms: false,
    }
}

fn aggregate_lock_mask(unsatisfied: &[&CompiledRule], policy: &PublicSitePolicy) -> MaskMetadata {
    let primary = unsatisfied[0];
    let requires_age = unsatisfied.iter().any(|r| r.requires_age_18)
        && policy.age_policy != AgeVerificationPolicy::Off;
    let requires_login = unsatisfied.iter().any(|r| r.requires_login) || requires_age;
    let requires_terms = requires_age && policy.age_policy.requires_adult_assurance();
    MaskMetadata {
        rule_id: primary.id.clone(),
        label: primary.name.clone(),
        preset: primary.preset.as_str().to_string(),
        requires_login,
        requires_age,
        requires_terms,
    }
}

fn merge_masks(masks: &[MaskMetadata]) -> Option<MaskMetadata> {
    let first = masks.first()?.clone();
    if masks.len() == 1 {
        return Some(first);
    }
    let mut merged = first;
    for m in &masks[1..] {
        merged.requires_login |= m.requires_login;
        merged.requires_age |= m.requires_age;
        merged.requires_terms |= m.requires_terms;
    }
    Some(merged)
}

#[allow(clippy::too_many_arguments)]
fn compile_expr(
    ast: &SafetyExpr,
    default_min_score: f32,
    wd_tags: &HashMap<String, i64>,
    post_tags: &HashMap<String, i64>,
    authors: &HashMap<String, i64>,
    rule_wd: &mut HashSet<i64>,
    all_post: &mut BTreeSet<i64>,
    all_authors: &mut BTreeSet<i64>,
) -> anyhow::Result<CompiledExpr> {
    match ast {
        SafetyExpr::Predicate(pred) => match pred {
            SafetyPredicate::WdTag { name, min_score } => {
                let Some(&tag_id) = wd_tags.get(name) else {
                    bail!("unresolved canonical wd_tag '{name}' in safety rule");
                };
                let score = min_score.unwrap_or(default_min_score);
                if !score.is_finite() || score <= 0.0 || score > 1.0 {
                    bail!("invalid score threshold {score} for tag '{name}'");
                }
                rule_wd.insert(tag_id);
                Ok(CompiledExpr::Predicate(CompiledPredicate::WdTag {
                    tag_id,
                    min_score: score,
                }))
            }
            SafetyPredicate::PostTag(name) => {
                let Some(&tag_id) = post_tags.get(name) else {
                    bail!("unresolved canonical post_tag '{name}' in safety rule");
                };
                all_post.insert(tag_id);
                Ok(CompiledExpr::Predicate(CompiledPredicate::PostTag(tag_id)))
            }
            SafetyPredicate::Author(name) => {
                let Some(&author_id) = authors.get(name) else {
                    bail!("unresolved canonical author '{name}' in safety rule");
                };
                all_authors.insert(author_id);
                Ok(CompiledExpr::Predicate(CompiledPredicate::Author(author_id)))
            }
            SafetyPredicate::Unclassified => {
                Ok(CompiledExpr::Predicate(CompiledPredicate::Unclassified))
            }
        },
        SafetyExpr::Not(inner) => Ok(CompiledExpr::Not(Box::new(compile_expr(
            inner,
            default_min_score,
            wd_tags,
            post_tags,
            authors,
            rule_wd,
            all_post,
            all_authors,
        )?))),
        SafetyExpr::And(items) => {
            let mut compiled = Vec::with_capacity(items.len());
            for item in items {
                compiled.push(compile_expr(
                    item,
                    default_min_score,
                    wd_tags,
                    post_tags,
                    authors,
                    rule_wd,
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
                    default_min_score,
                    wd_tags,
                    post_tags,
                    authors,
                    rule_wd,
                    all_post,
                    all_authors,
                )?);
            }
            Ok(CompiledExpr::Or(compiled))
        }
    }
}

async fn resolve_exact_names(
    pool: &PgPool,
    table: &'static str,
    names: &BTreeSet<String>,
) -> anyhow::Result<HashMap<String, i64>> {
    if names.is_empty() {
        return Ok(HashMap::new());
    }
    let query = match table {
        "wd_tags" => "SELECT id, name::TEXT AS name FROM wd_tags WHERE name = ANY($1::TEXT[])",
        "tags" => "SELECT id, name::TEXT AS name FROM tags WHERE name = ANY($1::TEXT[])",
        "authors" => "SELECT id, name::TEXT AS name FROM authors WHERE name = ANY($1::TEXT[])",
        _ => bail!("unsupported table '{table}'"),
    };
    let name_vec: Vec<String> = names.iter().cloned().collect();
    let rows = sqlx::query(query).bind(&name_vec).fetch_all(pool).await?;
    let mut map = HashMap::with_capacity(rows.len());
    for row in rows {
        let id: i64 = row.try_get("id")?;
        let name: String = row.try_get("name")?;
        map.insert(name, id);
    }
    Ok(map)
}

#[allow(clippy::too_many_arguments)]
fn mint_cap_url(
    secret: &[u8],
    now_secs: u64,
    policy_rev: u32,
    kind: MediaCapKind,
    id: i64,
    path: String,
    req_switchers: &[String],
    caller: &CallerContext,
) -> Result<String, MaskMetadata> {
    if secret.is_empty() {
        return Err(unclassified_mask());
    }
    // Fail-closed path validation echoing verifier #63 defense-in-depth.
    if path.contains('%') || path.contains(':') || path.len() > 1024 {
        return Err(unclassified_mask());
    }
    let (sub, sid, exp, switchers) = if req_switchers.is_empty() {
        (
            MEDIA_CAP_ANON_SUB.to_string(),
            None,
            now_secs.saturating_add(PUBLIC_MEDIA_CAP_TTL_SECS),
            Vec::new(),
        )
    } else {
        // Restricted media MUST be bound to an authenticated subject (never anon).
        let Some(sub) = caller.sub.as_ref().filter(|s| !s.trim().is_empty() && *s != MEDIA_CAP_ANON_SUB) else {
            return Err(MaskMetadata {
                rule_id: req_switchers[0].clone(),
                label: "Restricted content".to_string(),
                preset: PlaceholderPreset::Custom.as_str().to_string(),
                requires_login: true,
                requires_age: false,
                requires_terms: false,
            });
        };
        (
            sub.clone(),
            caller.sid.clone(),
            now_secs.saturating_add(RESTRICTED_MEDIA_CAP_TTL_SECS),
            req_switchers.to_vec(),
        )
    };

    let cap = MediaCapability {
        v: MEDIA_CAP_VERSION,
        kind,
        id,
        path,
        rev: policy_rev,
        sub,
        sid,
        req_switchers: switchers,
        exp,
    };
    let tok = sign_media_capability(&cap, secret).map_err(|_| unclassified_mask())?;
    Ok(format!("/media/{}/{}?cap={tok}", kind.as_str(), id))
}

fn encode_url_path(path: &str) -> String {
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

/// Fetch exact [`ImageFacts`] for a batch of image IDs in bounded set-based queries.
pub async fn load_image_facts(
    pool: &PgPool,
    image_ids: &[i64],
    policy: &CompiledPolicy,
) -> anyhow::Result<HashMap<i64, ImageFacts>> {
    if image_ids.is_empty() || !policy.is_enabled() {
        return Ok(HashMap::new());
    }

    let status_rows = sqlx::query(
        r#"
        SELECT id, (status = 'completed'::process_status) AS is_completed
        FROM images
        WHERE id = ANY($1::BIGINT[])
        "#,
    )
    .bind(image_ids)
    .fetch_all(pool)
    .await?;

    let mut map: HashMap<i64, ImageFacts> = HashMap::with_capacity(status_rows.len());
    for row in status_rows {
        let id: i64 = row.try_get("id")?;
        let is_completed: bool = row.try_get("is_completed")?;
        map.insert(
            id,
            ImageFacts {
                is_completed,
                ..ImageFacts::default()
            },
        );
    }

    if !policy.referenced_wd_tag_ids.is_empty() {
        let wd_rows = sqlx::query(
            r#"
            SELECT image_id, wd_tag_id, score
            FROM wd_tag_images
            WHERE image_id = ANY($1::BIGINT[])
              AND wd_tag_id = ANY($2::BIGINT[])
            "#,
        )
        .bind(image_ids)
        .bind(&policy.referenced_wd_tag_ids)
        .fetch_all(pool)
        .await?;
        for row in wd_rows {
            let image_id: i64 = row.try_get("image_id")?;
            let wd_tag_id: i64 = row.try_get("wd_tag_id")?;
            let score: f32 = row.try_get("score")?;
            if let Some(entry) = map.get_mut(&image_id) {
                entry.wd_tag_scores.insert(wd_tag_id, score);
            }
        }
    }

    if !policy.referenced_post_tag_ids.is_empty() {
        let pt_rows = sqlx::query(
            r#"
            SELECT pi.image_id, tp.tag_id
            FROM post_images pi
            JOIN tag_posts tp ON tp.post_id = pi.post_id
            WHERE pi.image_id = ANY($1::BIGINT[])
              AND tp.tag_id = ANY($2::BIGINT[])
            "#,
        )
        .bind(image_ids)
        .bind(&policy.referenced_post_tag_ids)
        .fetch_all(pool)
        .await?;
        for row in pt_rows {
            let image_id: i64 = row.try_get("image_id")?;
            let tag_id: i64 = row.try_get("tag_id")?;
            if let Some(entry) = map.get_mut(&image_id) {
                entry.post_tag_ids.insert(tag_id);
            }
        }
    }

    if !policy.referenced_author_ids.is_empty() {
        let au_rows = sqlx::query(
            r#"
            SELECT pi.image_id, ap.author_id
            FROM post_images pi
            JOIN author_posts ap ON ap.post_id = pi.post_id
            WHERE pi.image_id = ANY($1::BIGINT[])
              AND ap.author_id = ANY($2::BIGINT[])
            "#,
        )
        .bind(image_ids)
        .bind(&policy.referenced_author_ids)
        .fetch_all(pool)
        .await?;
        for row in au_rows {
            let image_id: i64 = row.try_get("image_id")?;
            let author_id: i64 = row.try_get("author_id")?;
            if let Some(entry) = map.get_mut(&image_id) {
                entry.author_ids.insert(author_id);
            }
        }
    }

    Ok(map)
}

/// Evaluate video outcomes for a batch of videos by loading their parent post(s)'
/// images, post tags, and authors.
pub async fn evaluate_videos_batch(
    pool: &PgPool,
    video_ids: &[i64],
    policy: &CompiledPolicy,
    caller: &CallerContext,
) -> anyhow::Result<HashMap<i64, MediaOutcome>> {
    let mut out = HashMap::with_capacity(video_ids.len());
    if video_ids.is_empty() {
        return Ok(out);
    }
    if !policy.is_enabled() {
        for &vid in video_ids {
            out.insert(
                vid,
                MediaOutcome::Clear {
                    req_switchers: Vec::new(),
                },
            );
        }
        return Ok(out);
    }

    let pv_rows = sqlx::query(
        r#"
        SELECT video_id, post_id
        FROM post_videos
        WHERE video_id = ANY($1::BIGINT[])
        "#,
    )
    .bind(video_ids)
    .fetch_all(pool)
    .await?;

    let mut video_posts: HashMap<i64, Vec<i64>> = HashMap::new();
    let mut all_post_ids: BTreeSet<i64> = BTreeSet::new();
    for row in pv_rows {
        let video_id: i64 = row.try_get("video_id")?;
        let post_id: i64 = row.try_get("post_id")?;
        video_posts.entry(video_id).or_default().push(post_id);
        all_post_ids.insert(post_id);
    }

    let post_ids_vec: Vec<i64> = all_post_ids.iter().copied().collect();
    let mut post_image_ids: HashMap<i64, Vec<i64>> = HashMap::new();
    let mut all_image_ids: BTreeSet<i64> = BTreeSet::new();
    let mut post_tags: HashMap<i64, HashSet<i64>> = HashMap::new();
    let mut post_authors: HashMap<i64, HashSet<i64>> = HashMap::new();

    if !post_ids_vec.is_empty() {
        let pi_rows = sqlx::query(
            r#"
            SELECT post_id, image_id
            FROM post_images
            WHERE post_id = ANY($1::BIGINT[])
            "#,
        )
        .bind(&post_ids_vec)
        .fetch_all(pool)
        .await?;
        for row in pi_rows {
            let post_id: i64 = row.try_get("post_id")?;
            let image_id: i64 = row.try_get("image_id")?;
            post_image_ids.entry(post_id).or_default().push(image_id);
            all_image_ids.insert(image_id);
        }

        if !policy.referenced_post_tag_ids.is_empty() {
            let pt_rows = sqlx::query(
                r#"
                SELECT post_id, tag_id
                FROM tag_posts
                WHERE post_id = ANY($1::BIGINT[])
                  AND tag_id = ANY($2::BIGINT[])
                "#,
            )
            .bind(&post_ids_vec)
            .bind(&policy.referenced_post_tag_ids)
            .fetch_all(pool)
            .await?;
            for row in pt_rows {
                let post_id: i64 = row.try_get("post_id")?;
                let tag_id: i64 = row.try_get("tag_id")?;
                post_tags.entry(post_id).or_default().insert(tag_id);
            }
        }

        if !policy.referenced_author_ids.is_empty() {
            let au_rows = sqlx::query(
                r#"
                SELECT post_id, author_id
                FROM author_posts
                WHERE post_id = ANY($1::BIGINT[])
                  AND author_id = ANY($2::BIGINT[])
                "#,
            )
            .bind(&post_ids_vec)
            .bind(&policy.referenced_author_ids)
            .fetch_all(pool)
            .await?;
            for row in au_rows {
                let post_id: i64 = row.try_get("post_id")?;
                let author_id: i64 = row.try_get("author_id")?;
                post_authors.entry(post_id).or_default().insert(author_id);
            }
        }
    }

    let img_ids_vec: Vec<i64> = all_image_ids.into_iter().collect();
    let img_facts_map = load_image_facts(pool, &img_ids_vec, policy).await?;

    for &vid in video_ids {
        let mut parent_posts = Vec::new();
        if let Some(pids) = video_posts.get(&vid) {
            for pid in pids {
                let mut images = Vec::new();
                if let Some(iids) = post_image_ids.get(pid) {
                    for iid in iids {
                        if let Some(f) = img_facts_map.get(iid) {
                            images.push(f.clone());
                        }
                    }
                }
                parent_posts.push(ParentPostFacts {
                    images,
                    post_tag_ids: post_tags.get(pid).cloned().unwrap_or_default(),
                    author_ids: post_authors.get(pid).cloned().unwrap_or_default(),
                });
            }
        }
        let outcome = policy.evaluate_video_posts(&parent_posts, caller);
        out.insert(vid, outcome);
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use site_access::{SafetyRuleConfig, verify_media_capability};
    use sqlx::Execute as _;

    fn sample_policy() -> PublicSitePolicy {
        PublicSitePolicy {
            revision: 5,
            min_enforce_rev: 4,
            safety_enabled: true,
            unclassified_mode: UnclassifiedMode::LockFailClosed,
            cloudflare_images_blur: true,
            age_policy: AgeVerificationPolicy::SelfAttestation,
            rules: vec![
                SafetyRuleConfig {
                    id: "r18".into(),
                    name: "NSFW".into(),
                    mode: RuleMode::Switcher,
                    query: "tag:explicit>=0.6 OR tag:nude".into(),
                    default_min_score: 0.5,
                    preset: PlaceholderPreset::R18,
                    requires_login: true,
                    requires_age_18: true,
                    enabled: true,
                },
                SafetyRuleConfig {
                    id: "blood".into(),
                    name: "Blood / Gore".into(),
                    mode: RuleMode::Switcher,
                    query: "tag:blood".into(),
                    default_min_score: 0.5,
                    preset: PlaceholderPreset::Blood,
                    requires_login: false,
                    requires_age_18: false,
                    enabled: true,
                },
                SafetyRuleConfig {
                    id: "sensitive".into(),
                    name: "Suggestive".into(),
                    mode: RuleMode::SpoilerBlur,
                    query: "tag:lingerie".into(),
                    default_min_score: 0.5,
                    preset: PlaceholderPreset::Sensitive,
                    requires_login: false,
                    requires_age_18: false,
                    enabled: true,
                },
            ],
            ..PublicSitePolicy::default()
        }
    }

    fn compile_sample() -> CompiledPolicy {
        let wd = HashMap::from([
            ("explicit".into(), 1),
            ("nude".into(), 2),
            ("blood".into(), 3),
            ("lingerie".into(), 4),
        ]);
        CompiledPolicy::compile_with_resolver(
            sample_policy(),
            &wd,
            &HashMap::new(),
            &HashMap::new(),
        )
        .expect("compile sample policy")
    }

    #[test]
    fn compiler_fails_closed_on_unresolved_canonical_tag() {
        let wd = HashMap::from([("explicit".into(), 1)]);
        let err = CompiledPolicy::compile_with_resolver(
            sample_policy(),
            &wd,
            &HashMap::new(),
            &HashMap::new(),
        )
        .unwrap_err();
        assert!(err.to_string().contains("unresolved canonical wd_tag"));
    }

    #[test]
    fn evaluates_per_row_score_precedence_safe_mode_and_unclassified() {
        let compiled = compile_sample();
        let anon = CallerContext::anonymous();

        // Unclassified fails closed to Locked.
        let pending = ImageFacts {
            is_completed: false,
            ..Default::default()
        };
        let out_pending = compiled.evaluate_image(&pending, &anon);
        assert!(matches!(out_pending, MediaOutcome::Locked { ref mask } if mask.rule_id == "unclassified"));

        // Score below per-term threshold (0.55 < 0.6) does NOT trigger explicit rule.
        let low_score = ImageFacts {
            is_completed: true,
            wd_tag_scores: HashMap::from([(1, 0.55)]),
            ..Default::default()
        };
        assert_eq!(
            compiled.evaluate_image(&low_score, &anon),
            MediaOutcome::Clear {
                req_switchers: vec![]
            }
        );

        // Multi-rule precedence: matches BOTH r18 + blood + sensitive.
        let multi = ImageFacts {
            is_completed: true,
            wd_tag_scores: HashMap::from([(1, 0.9), (3, 0.8), (4, 0.9)]),
            ..Default::default()
        };

        // Only r18 unlocked -> STILL Locked by blood (overrides SpoilerBlur!).
        let only_r18 = CallerContext {
            sub: Some("usr-1".into()),
            sid: Some("sid-1".into()),
            switchers: HashSet::from(["r18".into()]),
            safe_mode: false,
            is_admin_view: false,
        };
        let out_partial = compiled.evaluate_image(&multi, &only_r18);
        assert!(matches!(out_partial, MediaOutcome::Locked { ref mask } if mask.rule_id == "blood"));

        // Both r18 & blood unlocked -> SpoilerBlur wins with req_switchers = ["blood", "r18"].
        let both = CallerContext {
            sub: Some("usr-1".into()),
            sid: Some("sid-1".into()),
            switchers: HashSet::from(["r18".into(), "blood".into()]),
            safe_mode: false,
            is_admin_view: false,
        };
        let out_both = compiled.evaluate_image(&multi, &both);
        assert_eq!(
            out_both,
            MediaOutcome::Spoiler {
                rule_id: "sensitive".into(),
                label: "Suggestive".into(),
                preset: PlaceholderPreset::Sensitive,
                req_switchers: vec!["blood".into(), "r18".into()],
            }
        );

        // Safe Mode overrides unlocked switchers -> Locked!
        let panic_caller = CallerContext {
            safe_mode: true,
            ..both
        };
        assert!(compiled.evaluate_image(&multi, &panic_caller).is_locked());
    }

    #[test]
    fn video_inherits_strictest_parent_outcome_and_locks_video_only_posts() {
        let compiled = compile_sample();
        let anon = CallerContext::anonymous();

        // Video-only post (0 images) -> Unclassified -> Locked.
        let v_only = compiled.evaluate_video(&[], &HashSet::new(), &HashSet::new(), &anon);
        assert!(matches!(v_only, MediaOutcome::Locked { ref mask } if mask.rule_id == "unclassified"));

        // Mixed album: 1 safe image + 1 R-18 image -> video inherits R-18 lock!
        let safe_img = ImageFacts {
            is_completed: true,
            ..Default::default()
        };
        let r18_img = ImageFacts {
            is_completed: true,
            wd_tag_scores: HashMap::from([(2, 0.85)]),
            ..Default::default()
        };
        let mixed = compiled.evaluate_video(
            &[safe_img.clone(), r18_img.clone()],
            &HashSet::new(),
            &HashSet::new(),
            &anon,
        );
        assert!(matches!(mixed, MediaOutcome::Locked { ref mask } if mask.rule_id == "r18"));

        // Caller with r18 unlocked -> video becomes Clear carrying req_switchers = ["r18"].
        let unlocked = CallerContext {
            sub: Some("usr-1".into()),
            sid: Some("sid-1".into()),
            switchers: HashSet::from(["r18".into()]),
            safe_mode: false,
            is_admin_view: false,
        };
        let mixed_ok = compiled.evaluate_video(
            &[safe_img, r18_img],
            &HashSet::new(),
            &HashSet::new(),
            &unlocked,
        );
        assert_eq!(
            mixed_ok,
            MediaOutcome::Clear {
                req_switchers: vec!["r18".into()]
            }
        );
    }

    #[test]
    fn managed_projection_mints_verified_capabilities_and_zero_url_for_locked() {
        let compiled = compile_sample();
        let secret = Arc::new(b"test-media-cap-secret-32-bytes!!".to_vec());
        let signer = MediaSigner::Managed {
            secret: secret.clone(),
            now_secs: 1_700_000_000,
        };
        let img = Image {
            id: 42,
            name: "folder/pic_42".into(),
            width: 800,
            height: 1200,
        };

        // 1. Public safe -> anon capability with 1h TTL, zero raw filename in `name`.
        let pub_proj = compiled.project_image(
            &img,
            MediaOutcome::Clear {
                req_switchers: vec![],
            },
            &CallerContext::anonymous(),
            &signer,
        );
        let ProjectedImage::Clear { url, name, .. } = pub_proj else {
            panic!("expected clear");
        };
        assert_eq!(name, None);
        let cap_tok = url
            .strip_prefix("/media/image/42?cap=")
            .expect("signed image cap URL");
        let cap = verify_media_capability(
            cap_tok,
            &secret,
            MediaCapKind::Image,
            42,
            1_700_000_010,
            4,
        )
        .expect("verify public cap");
        assert_eq!(cap.sub, "anon");
        assert!(cap.req_switchers.is_empty());
        assert_eq!(cap.path, "folder/pic_42.webp");
        assert_eq!(cap.exp, 1_700_000_000 + PUBLIC_MEDIA_CAP_TTL_SECS);

        // 2. Restricted clear -> bound to sub, sid, req_switchers, short 5m TTL.
        let caller = CallerContext {
            sub: Some("usr-99".into()),
            sid: Some("sid-99".into()),
            switchers: HashSet::from(["r18".into()]),
            safe_mode: false,
            is_admin_view: false,
        };
        let restr_proj = compiled.project_image(
            &img,
            MediaOutcome::Clear {
                req_switchers: vec!["r18".into()],
            },
            &caller,
            &signer,
        );
        let ProjectedImage::Clear { url, name, .. } = restr_proj else {
            panic!("expected restricted clear");
        };
        assert_eq!(name, None);
        let cap_tok = url.strip_prefix("/media/image/42?cap=").unwrap();
        let cap = verify_media_capability(
            cap_tok,
            &secret,
            MediaCapKind::Image,
            42,
            1_700_000_010,
            4,
        )
        .expect("verify restricted cap");
        assert_eq!(cap.sub, "usr-99");
        assert_eq!(cap.sid.as_deref(), Some("sid-99"));
        assert_eq!(cap.req_switchers, vec!["r18"]);
        assert_eq!(cap.exp, 1_700_000_000 + RESTRICTED_MEDIA_CAP_TTL_SECS);

        // 3. Spoiler with cloudflare_images_blur = true -> Preview cap + Clear reveal cap.
        let spoiler_proj = compiled.project_image(
            &img,
            MediaOutcome::Spoiler {
                rule_id: "sensitive".into(),
                label: "Suggestive".into(),
                preset: PlaceholderPreset::Sensitive,
                req_switchers: vec![],
            },
            &CallerContext::anonymous(),
            &signer,
        );
        let ProjectedImage::Spoiler {
            preview_url,
            reveal_url,
            blur_mode,
            ..
        } = spoiler_proj
        else {
            panic!("expected spoiler");
        };
        assert_eq!(blur_mode, BlurDeliveryMode::ServerTransform);
        let ptok = preview_url.strip_prefix("/media/preview/42?cap=").unwrap();
        verify_media_capability(ptok, &secret, MediaCapKind::Preview, 42, 1_700_000_010, 4)
            .expect("verify preview cap");
        let rtok = reveal_url.strip_prefix("/media/image/42?cap=").unwrap();
        verify_media_capability(rtok, &secret, MediaCapKind::Image, 42, 1_700_000_010, 4)
            .expect("verify reveal cap");

        // 4. Locked -> JSON contains zero name, zero url, zero cap.
        let locked_proj = compiled.project_image(
            &img,
            MediaOutcome::Locked {
                mask: unclassified_mask(),
            },
            &CallerContext::anonymous(),
            &signer,
        );
        assert!(locked_proj.is_locked());
        #[cfg(feature = "serde")]
        {
            let json = serde_json::to_string(&locked_proj).unwrap();
            assert!(!json.contains("folder/pic_42"));
            assert!(!json.contains("/media/"));
            assert!(!json.contains("cap="));
        }
    }

    #[test]
    fn anti_oracle_sql_excludes_unclassified_and_unsatisfied_switchers() {
        let compiled = compile_sample();
        let anon = CallerContext::anonymous();
        let mut qb = QueryBuilder::<Postgres>::new("SELECT i.id FROM images i WHERE TRUE");
        assert!(compiled.push_caller_allowed_image_sql(&mut qb, &anon, "i"));
        let built = qb.build();
        let sql_str = built.sql();
        let sql = sql_str.as_str();
        assert!(sql.contains("i.status = 'completed'::process_status"));
        assert!(sql.contains("AND NOT (EXISTS (SELECT 1 FROM wd_tag_images wti WHERE wti.image_id = i.id AND wti.wd_tag_id = $1 AND wti.score >= $2)"));
        // Spoiler rule (`lingerie`, id=4) is NOT excluded from search; only Switcher rules (1, 2, 3) are.
        assert_eq!(sql.matches("wti.wd_tag_id =").count(), 3);
    }

    #[test]
    fn video_multi_post_inheritance_evaluates_each_post_and_post_tags_independently() {
        let policy = PublicSitePolicy {
            revision: 9,
            min_enforce_rev: 9,
            safety_enabled: true,
            unclassified_mode: UnclassifiedMode::LockFailClosed,
            rules: vec![
                SafetyRuleConfig {
                    id: "post_nsfw".into(),
                    name: "Post Tag NSFW".into(),
                    mode: RuleMode::Switcher,
                    query: "post_tag:nsfw_post".into(),
                    default_min_score: 0.5,
                    preset: PlaceholderPreset::R18,
                    requires_login: true,
                    requires_age_18: true,
                    enabled: true,
                },
                SafetyRuleConfig {
                    id: "restricted_author".into(),
                    name: "Restricted Author".into(),
                    mode: RuleMode::Switcher,
                    query: "author:secret_artist".into(),
                    default_min_score: 0.5,
                    preset: PlaceholderPreset::Custom,
                    requires_login: true,
                    requires_age_18: false,
                    enabled: true,
                },
            ],
            ..PublicSitePolicy::default()
        };

        let mut pt_map = HashMap::new();
        pt_map.insert("nsfw_post".to_string(), 101);
        let mut au_map = HashMap::new();
        au_map.insert("secret_artist".to_string(), 202);
        let compiled = CompiledPolicy::compile_with_resolver(
            policy,
            &HashMap::new(),
            &pt_map,
            &au_map,
        )
        .expect("compile post_tag & author rules");

        let anon = CallerContext::anonymous();
        let safe_img = ImageFacts {
            is_completed: true,
            ..Default::default()
        };

        // 1. Single post with safe image + restricted post_tag -> Locked (post_tag NOT ignored!).
        let tagged_post = ParentPostFacts {
            images: vec![safe_img.clone()],
            post_tag_ids: HashSet::from([101]),
            author_ids: HashSet::new(),
        };
        assert!(matches!(
            compiled.evaluate_video_posts(std::slice::from_ref(&tagged_post), &anon),
            MediaOutcome::Locked { ref mask } if mask.rule_id == "post_nsfw"
        ));

        // 2. Single post with safe image + restricted author -> Locked (author NOT ignored!).
        let author_post = ParentPostFacts {
            images: vec![safe_img.clone()],
            post_tag_ids: HashSet::new(),
            author_ids: HashSet::from([202]),
        };
        assert!(matches!(
            compiled.evaluate_video_posts(std::slice::from_ref(&author_post), &anon),
            MediaOutcome::Locked { ref mask } if mask.rule_id == "restricted_author"
        ));

        // 3. Multi-post video: Post A (safe completed image) + Post B (video-only with 0 images) -> Locked!
        let safe_post = ParentPostFacts {
            images: vec![safe_img.clone()],
            post_tag_ids: HashSet::new(),
            author_ids: HashSet::new(),
        };
        let video_only_post = ParentPostFacts {
            images: vec![],
            post_tag_ids: HashSet::new(),
            author_ids: HashSet::new(),
        };
        assert!(matches!(
            compiled.evaluate_video_posts(&[safe_post.clone(), video_only_post], &anon),
            MediaOutcome::Locked { ref mask } if mask.rule_id == "unclassified"
        ));

        // 4. Multi-post video: Post A (safe) + Post B (safe image + restricted post_tag) -> Locked for anon,
        //    Clear with req_switchers = ["post_nsfw"] for authorized caller.
        assert!(matches!(
            compiled.evaluate_video_posts(&[safe_post.clone(), tagged_post.clone()], &anon),
            MediaOutcome::Locked { ref mask } if mask.rule_id == "post_nsfw"
        ));
        let unlocked_caller = CallerContext {
            sub: Some("u1".into()),
            sid: Some("s1".into()),
            switchers: HashSet::from(["post_nsfw".to_string()]),
            safe_mode: false,
            is_admin_view: false,
        };
        assert_eq!(
            compiled.evaluate_video_posts(&[safe_post, tagged_post], &unlocked_caller),
            MediaOutcome::Clear {
                req_switchers: vec!["post_nsfw".to_string()],
            }
        );
    }
}
