//! Policy v3 Web-of-Science-style advanced query execution with independent
//! per-condition thresholds, zero cross-model weighted summation, zero centroid
//! averaging, single-snapshot seed authorization, and hard bounded SQL `LIMIT`.

use std::{
    collections::{HashMap, HashSet},
    hash::{DefaultHasher, Hash, Hasher},
    io::Cursor,
    sync::{Arc, LazyLock},
};

use anyhow::{anyhow, bail};
use moka::future::Cache;
use pgvector::HalfVector;
use search_types::{
    Image, Post,
    query::{
        AdvancedSort, QueryExpr, QueryPlan, ResultKind, SearchField, VectorTarget,
        parse_and_compile,
    },
    validate_min_similarity,
};
use sqlx::{Executor as _, Postgres, QueryBuilder, Row as _};

use crate::{
    Engine, VECTOR_STATEMENT_TIMEOUT_SQL, escape_like,
    safety::{MediaOutcome, SafetyFilter, SeedLockedError, begin_repeatable_read_tx, load_image_facts_in_tx},
};

/// Hard upper bound on candidate rows scanned per request (replaces unbounded `WITH TIES`).
const VECTOR_CANDIDATE_LIMIT: i64 = 2000;

/// Fallback similarity cutoff for negated vector leaves (`NOT clip:`, `NOT dino:`,
/// `NOT upload:`) when neither an explicit `>=` threshold nor a positive site default
/// is configured, ensuring negated leaves actively exclude matching items.
const DEFAULT_NEGATED_VECTOR_SIMILARITY: f32 = 0.25;

#[derive(Debug, Clone)]
pub struct AdvancedSearchRequest {
    pub query: String,
    pub uploads: Vec<Vec<u8>>,
    pub sort: AdvancedSort,
    /// Optional default minimum SigLIP2 cosine similarity cutoff in `[0.0, 1.0]`
    /// used when a `clip:` leaf omits an explicit `>=` threshold.
    pub clip_min_similarity: Option<f32>,
    /// Optional default minimum DINOv3 cosine similarity cutoff in `[0.0, 1.0]`
    /// used when a `dino:` or `upload:` leaf omits an explicit `>=` threshold.
    pub dino_min_similarity: Option<f32>,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Debug, Clone)]
pub enum AdvancedSearchResult {
    Posts(Vec<Post>),
    Images(Vec<Image>),
}

/// Independent resolved vector leaf clause evaluated against its OWN embedding
/// and its OWN per-condition threshold (zero weighting or centroid averaging).
#[derive(Debug, Clone)]
pub(crate) struct ResolvedVectorClause {
    pub positive: bool,
    pub col: &'static str,
    pub vec: HalfVector,
    pub threshold: Option<f32>,
}

/// L2-normalize a single embedding vector and convert to `HalfVector`.
pub(crate) fn unit_halfvec(raw: &[f32], dim: usize) -> anyhow::Result<HalfVector> {
    if raw.len() != dim {
        bail!("unexpected embedding dimension {}, expected {dim}", raw.len());
    }
    if raw.iter().any(|x| !x.is_finite()) {
        bail!("embedding vector contains non-finite values");
    }
    let norm = raw.iter().map(|x| x * x).sum::<f32>().sqrt();
    if !norm.is_finite() || norm < 1e-6 {
        bail!("embedding vector collapsed to zero");
    }
    let inv = 1.0 / norm;
    let normalized: Vec<f32> = raw.iter().map(|x| x * inv).collect();
    Ok(HalfVector::from_f32_slice(&normalized))
}

fn collect_all_tag_values(expr: &QueryExpr, out: &mut Vec<String>) {
    match expr {
        QueryExpr::Term {
            field: SearchField::Tag,
            value,
            ..
        } => {
            if !out.iter().any(|v| v == value) {
                out.push(value.clone());
            }
        }
        QueryExpr::Not(inner) => collect_all_tag_values(inner, out),
        QueryExpr::And(items) | QueryExpr::Or(items) => {
            for item in items {
                collect_all_tag_values(item, out);
            }
        }
        _ => {}
    }
}

/// Convert a pgvector `HalfVector` (`f16` elements) into `Vec<f32>`.
fn halfvec_to_f32(hv: &HalfVector) -> Vec<f32> {
    hv.as_slice().iter().map(|h| h.to_f32()).collect()
}

pub(crate) fn push_post_predicate(qb: &mut QueryBuilder<Postgres>, expr: &QueryExpr) {
    match expr {
        QueryExpr::Term { field, value, .. } => {
            let pat = format!("%{}%", escape_like(value.trim()));
            match field {
                SearchField::Title => {
                    qb.push("(p.title ILIKE ");
                    qb.push_bind(pat);
                    qb.push(r" ESCAPE '\')");
                }
                SearchField::Author => {
                    qb.push(
                        "EXISTS (SELECT 1 FROM author_posts ap JOIN authors a ON a.id = ap.author_id WHERE ap.post_id = p.id AND a.name ILIKE ",
                    );
                    qb.push_bind(pat);
                    qb.push(r" ESCAPE '\')");
                }
                SearchField::All => {
                    qb.push("(p.title ILIKE ");
                    qb.push_bind(pat.clone());
                    qb.push(
                        r" ESCAPE '\' OR EXISTS (SELECT 1 FROM author_posts ap JOIN authors a ON a.id = ap.author_id WHERE ap.post_id = p.id AND a.name ILIKE ",
                    );
                    qb.push_bind(pat);
                    qb.push(r" ESCAPE '\'))");
                }
                _ => {
                    qb.push("FALSE");
                }
            }
        }
        QueryExpr::Not(inner) => {
            qb.push("(NOT ");
            push_post_predicate(qb, inner);
            qb.push(")");
        }
        QueryExpr::And(items) => {
            qb.push("(");
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    qb.push(" AND ");
                }
                push_post_predicate(qb, item);
            }
            qb.push(")");
        }
        QueryExpr::Or(items) => {
            qb.push("(");
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    qb.push(" OR ");
                }
                push_post_predicate(qb, item);
            }
            qb.push(")");
        }
    }
}

fn is_post_only_expr(expr: &QueryExpr) -> bool {
    match expr {
        QueryExpr::Term { field, .. } => {
            matches!(
                field,
                SearchField::All | SearchField::Title | SearchField::Author
            )
        }
        QueryExpr::Not(inner) => is_post_only_expr(inner),
        QueryExpr::And(items) | QueryExpr::Or(items) => {
            !items.is_empty() && items.iter().all(is_post_only_expr)
        }
    }
}

fn has_positive_post_term(expr: &QueryExpr) -> bool {
    match expr {
        QueryExpr::Term { field, .. } => {
            matches!(
                field,
                SearchField::All | SearchField::Title | SearchField::Author
            )
        }
        QueryExpr::Not(_) => false,
        QueryExpr::And(items) | QueryExpr::Or(items) => items.iter().any(has_positive_post_term),
    }
}

fn flatten_and<'a>(items: &'a [QueryExpr], out: &mut Vec<&'a QueryExpr>) {
    for item in items {
        if let QueryExpr::And(sub) = item {
            flatten_and(sub, out);
        } else {
            out.push(item);
        }
    }
}

fn push_correlated_post_exists(qb: &mut QueryBuilder<Postgres>, post_exprs: &[&QueryExpr]) {
    qb.push(
        "EXISTS (SELECT 1 FROM post_images pi JOIN posts p ON p.id = pi.post_id WHERE pi.image_id = i.id AND ",
    );
    if post_exprs.len() == 1 {
        push_post_predicate(qb, post_exprs[0]);
    } else {
        qb.push("(");
        for (idx, expr) in post_exprs.iter().enumerate() {
            if idx > 0 {
                qb.push(" AND ");
            }
            push_post_predicate(qb, expr);
        }
        qb.push(")");
    }
    qb.push(")");
}

pub(crate) fn push_image_predicate(
    qb: &mut QueryBuilder<Postgres>,
    expr: &QueryExpr,
    tag_map: &HashMap<String, Vec<i64>>,
) {
    match expr {
        QueryExpr::Term {
            field,
            value,
            threshold,
        } => match field {
            SearchField::Tag => {
                let ids = tag_map.get(value).map(Vec::as_slice).unwrap_or(&[]);
                if ids.is_empty() {
                    qb.push("FALSE");
                } else {
                    qb.push(
                        "EXISTS (SELECT 1 FROM wd_tag_images wti WHERE wti.image_id = i.id AND wti.wd_tag_id = ANY(",
                    );
                    qb.push_bind(ids.to_vec());
                    qb.push("::BIGINT[])");
                    if let Some(min_score) = threshold.filter(|v| v.is_finite() && *v > 0.0) {
                        qb.push(" AND wti.score >= ");
                        qb.push_bind(min_score);
                    }
                    qb.push(")");
                }
            }
            SearchField::Title | SearchField::Author | SearchField::All => {
                push_correlated_post_exists(qb, &[expr]);
            }
            _ => {
                qb.push("TRUE");
            }
        },
        QueryExpr::Not(inner) => {
            if is_post_only_expr(inner) {
                qb.push("(NOT ");
                push_correlated_post_exists(qb, &[inner.as_ref()]);
                qb.push(")");
            } else {
                qb.push("(NOT ");
                push_image_predicate(qb, inner, tag_map);
                qb.push(")");
            }
        }
        QueryExpr::And(items) => {
            let mut flat = Vec::with_capacity(items.len());
            flatten_and(items, &mut flat);
            let mut post_conjuncts: Vec<&QueryExpr> = Vec::new();
            let mut other_items: Vec<&QueryExpr> = Vec::new();
            for item in &flat {
                if is_post_only_expr(item) {
                    post_conjuncts.push(item);
                } else {
                    other_items.push(item);
                }
            }
            if post_conjuncts.iter().any(|e| has_positive_post_term(e)) {
                if other_items.is_empty() {
                    push_correlated_post_exists(qb, &post_conjuncts);
                } else {
                    qb.push("(");
                    push_correlated_post_exists(qb, &post_conjuncts);
                    for item in other_items {
                        qb.push(" AND ");
                        push_image_predicate(qb, item, tag_map);
                    }
                    qb.push(")");
                }
            } else {
                qb.push("(");
                for (idx, item) in flat.iter().enumerate() {
                    if idx > 0 {
                        qb.push(" AND ");
                    }
                    push_image_predicate(qb, item, tag_map);
                }
                qb.push(")");
            }
        }
        QueryExpr::Or(items) => {
            qb.push("(");
            for (idx, item) in items.iter().enumerate() {
                if idx > 0 {
                    qb.push(" OR ");
                }
                push_image_predicate(qb, item, tag_map);
            }
            qb.push(")");
        }
    }
}

pub(crate) fn map_post_rows(rows: Vec<sqlx::postgres::PgRow>) -> anyhow::Result<Vec<Post>> {
    rows.into_iter()
        .map(|r| -> sqlx::Result<Post> {
            Ok(Post {
                id: r.try_get("id")?,
                title: r.try_get("title")?,
            })
        })
        .try_collect()
        .map_err(Into::into)
}

pub(crate) fn map_image_rows(rows: Vec<sqlx::postgres::PgRow>) -> anyhow::Result<Vec<Image>> {
    rows.into_iter()
        .map(|r| -> sqlx::Result<Image> {
            Ok(Image {
                id: r.try_get("id")?,
                name: r.try_get("name")?,
                width: r.try_get("width")?,
                height: r.try_get("height")?,
            })
        })
        .try_collect()
        .map_err(Into::into)
}

fn collect_positive_tag_clauses(
    positive_tags: &[String],
    tag_map: &HashMap<String, Vec<i64>>,
) -> Vec<Vec<i64>> {
    let mut clauses = Vec::new();
    let mut seen: HashSet<Vec<i64>> = HashSet::new();
    for tag in positive_tags {
        if let Some(ids) = tag_map.get(tag)
            && !ids.is_empty()
        {
            let mut sorted = ids.clone();
            sorted.sort_unstable();
            sorted.dedup();
            if seen.insert(sorted.clone()) {
                clauses.push(sorted);
            }
        }
    }
    clauses
}

fn push_tag_clause_score(qb: &mut QueryBuilder<Postgres>, ids: &[i64]) {
    qb.push(
        "COALESCE((SELECT MAX(wti.score) FROM wd_tag_images wti WHERE wti.image_id = m.id AND wti.wd_tag_id = ANY(",
    );
    qb.push_bind(ids.to_vec());
    qb.push("::BIGINT[])), 0.0)");
}

pub(crate) fn build_metadata_images_query(
    meta: &QueryExpr,
    tag_map: &HashMap<String, Vec<i64>>,
    positive_tags: &[String],
    sort: AdvancedSort,
    safety: Option<&SafetyFilter<'_>>,
    limit: i64,
    offset: i64,
) -> QueryBuilder<Postgres> {
    let pos_tag_clauses = collect_positive_tag_clauses(positive_tags, tag_map);

    if sort == AdvancedSort::Relevance && !pos_tag_clauses.is_empty() {
        let mut qb = QueryBuilder::<Postgres>::new(
            "WITH matched AS (SELECT i.id, i.name::TEXT AS name, i.width, i.height FROM images i WHERE ",
        );
        push_image_predicate(&mut qb, meta, tag_map);
        if let Some(sf) = safety {
            sf.push_allowed_image_sql(&mut qb, "i");
        }
        qb.push(") SELECT m.id, m.name, m.width, m.height FROM matched m ORDER BY ");
        if pos_tag_clauses.len() == 1 {
            push_tag_clause_score(&mut qb, &pos_tag_clauses[0]);
        } else {
            qb.push("((");
            for (idx, ids) in pos_tag_clauses.iter().enumerate() {
                if idx > 0 {
                    qb.push(" + ");
                }
                push_tag_clause_score(&mut qb, ids);
            }
            qb.push(") / ");
            qb.push(pos_tag_clauses.len());
            qb.push(".0)");
        }
        qb.push(" DESC, m.id DESC LIMIT ");
        qb.push_bind(limit);
        qb.push(" OFFSET ");
        qb.push_bind(offset);
        return qb;
    }

    let mut qb = QueryBuilder::<Postgres>::new(
        "SELECT i.id, i.name::TEXT AS name, i.width, i.height FROM images i WHERE ",
    );
    push_image_predicate(&mut qb, meta, tag_map);
    if let Some(sf) = safety {
        sf.push_allowed_image_sql(&mut qb, "i");
    }
    qb.push(" ORDER BY i.id DESC LIMIT ");
    qb.push_bind(limit);
    qb.push(" OFFSET ");
    qb.push_bind(offset);
    qb
}

/// Build a bounded single-request SQL query evaluating EVERY resolved vector leaf
/// independently against its OWN embedding and per-condition threshold (including
/// negated leaves `NOT clip:`, `NOT dino:`, `NOT upload:`), with a hard `LIMIT`
/// (zero `WITH TIES`), ranked by the first declared positive vector (`primary_positive_vector`)
/// and stable asset ID `DESC`.
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_vector_clauses_query(
    clauses: &[ResolvedVectorClause],
    meta_filter: Option<&QueryExpr>,
    tag_map: &HashMap<String, Vec<i64>>,
    safety: Option<&SafetyFilter<'_>>,
    limit: i64,
    offset: i64,
) -> QueryBuilder<Postgres> {
    let primary_idx = clauses.iter().position(|c| c.positive);

    if let Some(p_idx) = primary_idx {
        let primary = &clauses[p_idx];
        let needs_clip_non_null = clauses
            .iter()
            .any(|c| c.positive && c.col == "clip_embedding");
        let needs_dino_non_null = clauses
            .iter()
            .any(|c| c.positive && c.col == "dinov3_embedding");

        let mut qb = QueryBuilder::<Postgres>::new(
            "WITH cands AS (SELECT i.id, i.name::TEXT AS name, i.width, i.height, (i.",
        );
        qb.push(primary.col);
        qb.push(" <=> ");
        qb.push_bind(primary.vec.clone());
        qb.push("::halfvec) AS primary_dist FROM images i WHERE TRUE");
        if needs_clip_non_null {
            qb.push(" AND i.clip_embedding IS NOT NULL");
        }
        if needs_dino_non_null {
            qb.push(" AND i.dinov3_embedding IS NOT NULL");
        }
        if let Some(meta) = meta_filter {
            qb.push(" AND ");
            push_image_predicate(&mut qb, meta, tag_map);
        }
        if let Some(sf) = safety {
            sf.push_allowed_image_sql(&mut qb, "i");
        }
        qb.push(" ORDER BY i.");
        qb.push(primary.col);
        qb.push(" <=> ");
        qb.push_bind(primary.vec.clone());
        qb.push("::halfvec LIMIT ");
        qb.push(VECTOR_CANDIDATE_LIMIT);
        qb.push(") SELECT c.id, c.name, c.width, c.height FROM cands c");

        let has_secondary = clauses.len() > 1;
        if has_secondary {
            qb.push(" JOIN images i ON i.id = c.id");
        }
        qb.push(" WHERE TRUE");

        if let Some(min_sim) = primary.threshold.filter(|&v| v > 0.0) {
            qb.push(" AND (1.0 - c.primary_dist) >= ");
            qb.push_bind(f64::from(min_sim));
        }

        for (idx, clause) in clauses.iter().enumerate() {
            if idx == p_idx {
                continue;
            }
            if clause.positive {
                if let Some(min_sim) = clause.threshold.filter(|&v| v > 0.0) {
                    qb.push(" AND (1.0 - (i.");
                    qb.push(clause.col);
                    qb.push(" <=> ");
                    qb.push_bind(clause.vec.clone());
                    qb.push("::halfvec)) >= ");
                    qb.push_bind(f64::from(min_sim));
                }
            } else {
                let cutoff = clause
                    .threshold
                    .filter(|&v| v > 0.0)
                    .unwrap_or(DEFAULT_NEGATED_VECTOR_SIMILARITY);
                qb.push(" AND (i.");
                qb.push(clause.col);
                qb.push(" IS NULL OR (1.0 - (i.");
                qb.push(clause.col);
                qb.push(" <=> ");
                qb.push_bind(clause.vec.clone());
                qb.push("::halfvec)) < ");
                qb.push_bind(f64::from(cutoff));
                qb.push(")");
            }
        }

        qb.push(" ORDER BY c.primary_dist ASC, c.id DESC LIMIT ");
        qb.push_bind(limit);
        qb.push(" OFFSET ");
        qb.push_bind(offset);
        return qb;
    }

    // Negated-only vector query (e.g. `tag:maid AND NOT clip:"dark"`):
    // take bounded candidate pool by stable asset ID, then exclude every negated leaf independently.
    let mut qb = QueryBuilder::<Postgres>::new(
        "WITH cands AS (SELECT i.id, i.name::TEXT AS name, i.width, i.height FROM images i WHERE TRUE",
    );
    if let Some(meta) = meta_filter {
        qb.push(" AND ");
        push_image_predicate(&mut qb, meta, tag_map);
    }
    if let Some(sf) = safety {
        sf.push_allowed_image_sql(&mut qb, "i");
    }
    qb.push(" ORDER BY i.id DESC LIMIT ");
    qb.push(VECTOR_CANDIDATE_LIMIT);
    qb.push(") SELECT c.id, c.name, c.width, c.height FROM cands c JOIN images i ON i.id = c.id WHERE TRUE");

    for clause in clauses {
        let cutoff = clause
            .threshold
            .filter(|&v| v > 0.0)
            .unwrap_or(DEFAULT_NEGATED_VECTOR_SIMILARITY);
        qb.push(" AND (i.");
        qb.push(clause.col);
        qb.push(" IS NULL OR (1.0 - (i.");
        qb.push(clause.col);
        qb.push(" <=> ");
        qb.push_bind(clause.vec.clone());
        qb.push("::halfvec)) < ");
        qb.push_bind(f64::from(cutoff));
        qb.push(")");
    }

    qb.push(" ORDER BY c.id DESC LIMIT ");
    qb.push_bind(limit);
    qb.push(" OFFSET ");
    qb.push_bind(offset);
    qb
}

pub(crate) fn build_similar_images_query(
    seed_vec: HalfVector,
    seed_id: i64,
    exclude_post_id: Option<i64>,
    min_similarity: Option<f32>,
    safety: Option<&SafetyFilter<'_>>,
    limit: i64,
    offset: i64,
) -> QueryBuilder<Postgres> {
    let mut qb = QueryBuilder::<Postgres>::new(
        "WITH cands AS (SELECT i.id, i.name::TEXT AS name, i.width, i.height, (i.dinov3_embedding <=> ",
    );
    qb.push_bind(seed_vec.clone());
    qb.push("::halfvec) AS dist FROM images i WHERE i.dinov3_embedding IS NOT NULL AND i.id <> ");
    qb.push_bind(seed_id);
    if let Some(post_id) = exclude_post_id {
        qb.push(
            " AND NOT EXISTS (SELECT 1 FROM post_images pi WHERE pi.image_id = i.id AND pi.post_id = ",
        );
        qb.push_bind(post_id);
        qb.push(")");
    }
    if let Some(sf) = safety {
        sf.push_allowed_image_sql(&mut qb, "i");
    }
    qb.push(" ORDER BY i.dinov3_embedding <=> ");
    qb.push_bind(seed_vec);
    qb.push("::halfvec LIMIT ");
    qb.push(VECTOR_CANDIDATE_LIMIT);
    qb.push(") SELECT id, name, width, height FROM cands");
    if let Some(min_sim) = min_similarity.filter(|&v| v > 0.0) {
        qb.push(" WHERE (1.0 - dist) >= ");
        qb.push_bind(f64::from(min_sim));
    }
    qb.push(" ORDER BY dist ASC, id DESC LIMIT ");
    qb.push_bind(limit);
    qb.push(" OFFSET ");
    qb.push_bind(offset);
    qb
}

impl Engine {
    /// Default post search matching either post title OR author name (deduplicated per post).
    pub async fn search_posts_by_title_or_author(
        &self,
        query: impl AsRef<str>,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<Post>> {
        if limit < 0 || offset < 0 {
            bail!("both limit and offset should >= 0")
        }
        let raw = query.as_ref().trim();
        if raw.is_empty() {
            bail!("query should not be empty")
        }
        let pat = format!("%{}%", escape_like(raw));
        let rows = sqlx::query(
            r#"
            SELECT p.id, p.title::TEXT AS title
            FROM posts p
            WHERE p.title ILIKE $1 ESCAPE '\'
               OR EXISTS (
                   SELECT 1
                   FROM author_posts ap
                   JOIN authors a ON a.id = ap.author_id
                   WHERE ap.post_id = p.id
                     AND a.name ILIKE $1 ESCAPE '\'
               )
            ORDER BY p.id DESC
            LIMIT $2 OFFSET $3
            "#,
        )
        .bind(&pat)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await?;

        map_post_rows(rows)
    }

    async fn resolve_tag_ids(&self, raw: &str) -> anyhow::Result<Vec<i64>> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Ok(vec![]);
        }
        let underscored = trimmed.replace(' ', "_");
        let pat_raw = format!("%{}%", escape_like(trimmed));
        let pat_under = format!("%{}%", escape_like(&underscored));

        let rows = sqlx::query(
            r#"
            SELECT wt.id AS tag_id
            FROM wd_tags wt
            WHERE wt.name ILIKE $1 ESCAPE '\'
               OR ($2 <> $1 AND wt.name ILIKE $2 ESCAPE '\')
            UNION
            SELECT tt.tag_id
            FROM wd_tag_translations tt
            WHERE tt.translation ILIKE $1 ESCAPE '\'
            "#,
        )
        .bind(pat_raw)
        .bind(pat_under)
        .fetch_all(&self.pool)
        .await?;

        rows.into_iter()
            .map(|r| r.try_get::<i64, _>("tag_id"))
            .try_collect()
            .map_err(Into::into)
    }

    pub(crate) async fn clip_text_vec_cached(&self, text: &str) -> anyhow::Result<Arc<Vec<f32>>> {
        static CACHE: LazyLock<Cache<String, Arc<Vec<f32>>>> =
            LazyLock::new(|| Cache::new(2 << 13));
        let key = text.to_owned();
        let text_owned = key.clone();
        CACHE
            .try_get_with(key, async move {
                let hv = self.clip_embedding([text_owned]).await?;
                anyhow::Ok(Arc::new(halfvec_to_f32(&hv)))
            })
            .await
            .map_err(|e| anyhow!("{e}"))
    }

    pub(crate) async fn dinov3_upload_vec_cached(
        &self,
        bytes: Vec<u8>,
    ) -> anyhow::Result<Arc<Vec<f32>>> {
        static CACHE: LazyLock<Cache<u64, Arc<Vec<f32>>>> = LazyLock::new(|| Cache::new(2 << 12));
        let mut hasher = DefaultHasher::default();
        bytes.hash(&mut hasher);
        let key = hasher.finish();
        CACHE
            .try_get_with(key, async move {
                let hv = self.dinov3_embedding([Cursor::new(bytes)]).await?;
                anyhow::Ok(Arc::new(halfvec_to_f32(&hv)))
            })
            .await
            .map_err(|e| anyhow!("{e}"))
    }

    /// Authorize EVERY positive AND negative stored `dino:<id>` seed (Clear only!)
    /// and fetch its `dinov3_embedding` inside ONE `REPEATABLE READ READ ONLY`
    /// transaction snapshot. Fails closed with [`SeedLockedError`] if ANY seed
    /// is not Clear or missing trusted facts.
    pub(crate) async fn authorize_and_fetch_dino_seeds_in_tx(
        tx: &mut sqlx::Transaction<'_, Postgres>,
        ids: &[i64],
        safety: Option<&SafetyFilter<'_>>,
    ) -> anyhow::Result<HashMap<i64, Vec<f32>>> {
        if ids.is_empty() {
            return Ok(HashMap::new());
        }

        if let Some(sf) = safety
            && sf.is_filtering_active()
        {
            let facts_map = load_image_facts_in_tx(tx, ids, sf.policy).await?;
            for &id in ids {
                let Some(facts) = facts_map.get(&id) else {
                    return Err(anyhow::Error::new(SeedLockedError {
                        image_id: id,
                        policy_id: "unclassified".to_string(),
                        label: "Pending classification".to_string(),
                    }));
                };
                match sf.policy.evaluate_image(facts, sf.caller) {
                    MediaOutcome::Clear { .. } => {}
                    MediaOutcome::Blurred {
                        policy_id, label, ..
                    } => {
                        return Err(anyhow::Error::new(SeedLockedError {
                            image_id: id,
                            policy_id,
                            label,
                        }));
                    }
                    MediaOutcome::Placeholder { mask, .. } => {
                        return Err(anyhow::Error::new(SeedLockedError {
                            image_id: id,
                            policy_id: mask.policy_id,
                            label: mask.label,
                        }));
                    }
                }
            }
        }

        let rows = sqlx::query(
            r#"
            SELECT id, dinov3_embedding
            FROM images
            WHERE id = ANY($1::BIGINT[])
              AND dinov3_embedding IS NOT NULL
            "#,
        )
        .bind(ids)
        .fetch_all(&mut **tx)
        .await?;

        let mut map = HashMap::with_capacity(rows.len());
        for row in rows {
            let id: i64 = row.try_get("id")?;
            let emb: HalfVector = row.try_get("dinov3_embedding")?;
            map.insert(id, halfvec_to_f32(&emb));
        }

        for &id in ids {
            if !map.contains_key(&id) {
                bail!("Image #{id} not found or has no visual embedding");
            }
        }
        Ok(map)
    }

    pub async fn advanced_search(
        &self,
        req: AdvancedSearchRequest,
    ) -> anyhow::Result<AdvancedSearchResult> {
        self.advanced_search_with_safety(req, None).await
    }

    pub async fn advanced_search_with_safety(
        &self,
        req: AdvancedSearchRequest,
        safety: Option<&SafetyFilter<'_>>,
    ) -> anyhow::Result<AdvancedSearchResult> {
        if req.limit < 0 || req.offset < 0 {
            bail!("both limit and offset should >= 0");
        }
        let (_expr, plan) = parse_and_compile(&req.query).map_err(|e| anyhow!("{e}"))?;
        self.execute_advanced_plan_with_safety(&plan, &req, safety)
            .await
    }

    pub async fn execute_advanced_plan(
        &self,
        plan: &QueryPlan,
        req: &AdvancedSearchRequest,
    ) -> anyhow::Result<AdvancedSearchResult> {
        self.execute_advanced_plan_with_safety(plan, req, None)
            .await
    }

    pub async fn execute_advanced_plan_with_safety(
        &self,
        plan: &QueryPlan,
        req: &AdvancedSearchRequest,
        safety: Option<&SafetyFilter<'_>>,
    ) -> anyhow::Result<AdvancedSearchResult> {
        if req.limit < 0 || req.offset < 0 {
            bail!("both limit and offset should >= 0");
        }
        let clip_default_min =
            validate_min_similarity(req.clip_min_similarity).map_err(|e| anyhow!("{e}"))?;
        let dino_default_min =
            validate_min_similarity(req.dino_min_similarity).map_err(|e| anyhow!("{e}"))?;

        if plan.result_kind == ResultKind::Posts {
            let Some(meta) = &plan.meta_filter else {
                return Ok(AdvancedSearchResult::Posts(vec![]));
            };
            let mut qb = QueryBuilder::<Postgres>::new(
                "SELECT p.id, p.title::TEXT AS title FROM posts p WHERE ",
            );
            push_post_predicate(&mut qb, meta);
            qb.push(" ORDER BY p.id DESC LIMIT ");
            qb.push_bind(req.limit);
            qb.push(" OFFSET ");
            qb.push_bind(req.offset);

            let rows = qb.build().fetch_all(&self.pool).await?;
            return Ok(AdvancedSearchResult::Posts(map_post_rows(rows)?));
        }

        // Pre-resolve every distinct Tag string referenced in the metadata AST.
        let mut tag_map: HashMap<String, Vec<i64>> = HashMap::new();
        if let Some(meta) = &plan.meta_filter {
            let mut distinct_tags = Vec::new();
            collect_all_tag_values(meta, &mut distinct_tags);
            for t in distinct_tags {
                let ids = self.resolve_tag_ids(&t).await?;
                tag_map.insert(t, ids);
            }
        }

        if !plan.has_vectors() {
            let images = self
                .query_images_metadata_only(
                    plan,
                    &tag_map,
                    req.sort,
                    safety,
                    req.limit,
                    req.offset,
                )
                .await?;
            return Ok(AdvancedSearchResult::Images(images));
        }

        // Collect all unique stored `dino:<id>` seeds (both positive AND negated!).
        let mut all_dino_ids: Vec<i64> = plan
            .dino_pos
            .iter()
            .chain(plan.dino_neg.iter())
            .map(|c| c.image_id)
            .collect();
        all_dino_ids.sort_unstable();
        all_dino_ids.dedup();

        // Single-snapshot authorization + embedding read for ALL stored `dino:<id>` seeds
        // BEFORE running any inference or search so locked seeds fail fast with zero oracle leakage!
        let id_vecs = if !all_dino_ids.is_empty() {
            let mut tx = begin_repeatable_read_tx(&self.pool).await?;
            let vecs =
                Self::authorize_and_fetch_dino_seeds_in_tx(&mut tx, &all_dino_ids, safety).await?;
            tx.commit().await?;
            vecs
        } else {
            HashMap::new()
        };

        // Resolve every distinct CLIP text embedding independently (zero averaging).
        let mut clip_vecs: HashMap<String, HalfVector> = HashMap::new();
        for clause in plan.clip_pos.iter().chain(plan.clip_neg.iter()) {
            if !clip_vecs.contains_key(&clause.text) {
                let raw = self.clip_text_vec_cached(&clause.text).await?;
                let hv = unit_halfvec(&raw, siglip2::EMBED_DIM)?;
                clip_vecs.insert(clause.text.clone(), hv);
            }
        }

        // Resolve every distinct uploaded image embedding independently (zero averaging).
        let mut upload_vecs: HashMap<usize, HalfVector> = HashMap::new();
        for clause in plan.upload_pos.iter().chain(plan.upload_neg.iter()) {
            if upload_vecs.contains_key(&clause.slot) {
                continue;
            }
            let Some(bytes) = req.uploads.get(clause.slot) else {
                bail!(
                    "Uploaded image #{} is missing — re-upload the image and try again",
                    clause.slot
                );
            };
            if bytes.is_empty() {
                bail!("Uploaded image #{} is empty", clause.slot);
            }
            let raw = self.dinov3_upload_vec_cached(bytes.clone()).await?;
            let hv = unit_halfvec(&raw, dinov3::EMBED_DIM)?;
            upload_vecs.insert(clause.slot, hv);
        }

        // Build per-clause resolved vector list in exact declared AST order
        // (preserving `plan.primary_positive_vector()` as the first positive clause).
        let mut resolved_clauses = Vec::with_capacity(plan.vector_clauses.len());
        for vc in &plan.vector_clauses {
            let (col, vec, default_min) = match &vc.target {
                VectorTarget::Clip(text) => (
                    "clip_embedding",
                    clip_vecs[text].clone(),
                    clip_default_min,
                ),
                VectorTarget::Dino(id) => (
                    "dinov3_embedding",
                    unit_halfvec(&id_vecs[id], dinov3::EMBED_DIM)?,
                    dino_default_min,
                ),
                VectorTarget::Upload(slot) => (
                    "dinov3_embedding",
                    upload_vecs[slot].clone(),
                    dino_default_min,
                ),
            };
            resolved_clauses.push(ResolvedVectorClause {
                positive: vc.positive,
                col,
                vec,
                threshold: vc.threshold.or(default_min),
            });
        }

        let images = self
            .query_images_vector_clauses(
                &resolved_clauses,
                plan.meta_filter.as_ref(),
                &tag_map,
                safety,
                req.limit,
                req.offset,
            )
            .await?;

        Ok(AdvancedSearchResult::Images(images))
    }

    async fn query_images_metadata_only(
        &self,
        plan: &QueryPlan,
        tag_map: &HashMap<String, Vec<i64>>,
        sort: AdvancedSort,
        safety: Option<&SafetyFilter<'_>>,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<Image>> {
        let Some(meta) = &plan.meta_filter else {
            return Ok(vec![]);
        };

        // Fast path for a single positive Tag term with Relevance sort: uses the
        // `wd_tag_images(wd_tag_id, image_id)` PK index directly.
        if sort == AdvancedSort::Relevance
            && let QueryExpr::Term {
                field: SearchField::Tag,
                value,
                threshold,
            } = meta
        {
            let ids = tag_map.get(value).map(Vec::as_slice).unwrap_or(&[]);
            if ids.is_empty() {
                return Ok(vec![]);
            }
            let mut qb = QueryBuilder::<Postgres>::new(
                "WITH img_match AS (SELECT wti.image_id, MAX(wti.score) AS max_score FROM wd_tag_images wti WHERE wti.wd_tag_id = ANY(",
            );
            qb.push_bind(ids.to_vec());
            qb.push("::BIGINT[])");
            if let Some(min_score) = threshold.filter(|v| v.is_finite() && *v > 0.0) {
                qb.push(" AND wti.score >= ");
                qb.push_bind(min_score);
            }
            qb.push(
                " GROUP BY wti.image_id) SELECT i.id, i.name::TEXT AS name, i.width, i.height FROM img_match im JOIN images i ON i.id = im.image_id WHERE TRUE",
            );
            if let Some(sf) = safety {
                sf.push_allowed_image_sql(&mut qb, "i");
            }
            qb.push(" ORDER BY im.max_score DESC, im.image_id DESC LIMIT ");
            qb.push_bind(limit);
            qb.push(" OFFSET ");
            qb.push_bind(offset);
            let rows = qb.build().fetch_all(&self.pool).await?;
            return map_image_rows(rows);
        }

        let mut qb = build_metadata_images_query(
            meta,
            tag_map,
            &plan.positive_tags,
            sort,
            safety,
            limit,
            offset,
        );
        let rows = qb.build().fetch_all(&self.pool).await?;
        map_image_rows(rows)
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn query_images_single_vector(
        &self,
        col: &'static str,
        vec: HalfVector,
        meta_filter: Option<&QueryExpr>,
        tag_map: &HashMap<String, Vec<i64>>,
        min_similarity: Option<f32>,
        safety: Option<&SafetyFilter<'_>>,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<Image>> {
        let clauses = [ResolvedVectorClause {
            positive: true,
            col,
            vec,
            threshold: min_similarity,
        }];
        self.query_images_vector_clauses(&clauses, meta_filter, tag_map, safety, limit, offset)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn query_images_vector_clauses(
        &self,
        clauses: &[ResolvedVectorClause],
        meta_filter: Option<&QueryExpr>,
        tag_map: &HashMap<String, Vec<i64>>,
        safety: Option<&SafetyFilter<'_>>,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<Image>> {
        let safety_active = safety.is_some_and(SafetyFilter::is_filtering_active);
        let mut qb =
            build_vector_clauses_query(clauses, meta_filter, tag_map, safety, limit, offset);

        let mut tx = begin_repeatable_read_tx(&self.pool).await?;
        tx.execute(VECTOR_STATEMENT_TIMEOUT_SQL).await?;
        if meta_filter.is_some() || safety_active || clauses.len() > 1 {
            tx.execute("SET LOCAL hnsw.max_scan_tuples = 20000").await?;
        }
        let rows = qb.build().fetch_all(&mut *tx).await?;
        tx.commit().await?;
        map_image_rows(rows)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use search_types::query::{parse_and_compile, parse_query};
    use sqlx::Execute as _;

    #[test]
    fn unit_halfvec_normalizes_single_vector_and_rejects_bad_inputs() {
        let hv = unit_halfvec(&[3.0, 4.0, 0.0, 0.0], 4).unwrap();
        let v = halfvec_to_f32(&hv);
        assert!((v[0] - 0.6).abs() < 1e-2);
        assert!((v[1] - 0.8).abs() < 1e-2);

        assert!(unit_halfvec(&[1.0, 2.0], 4).is_err());
        assert!(unit_halfvec(&[0.0, 0.0, 0.0, 0.0], 4).is_err());
        assert!(unit_halfvec(&[f32::NAN, 1.0, 0.0, 0.0], 4).is_err());
        assert!(unit_halfvec(&[f32::INFINITY, 1.0, 0.0, 0.0], 4).is_err());
    }

    #[test]
    fn builds_parameterized_post_and_image_predicates_with_per_leaf_tag_threshold() {
        let expr = parse_query(r#"(title:"咖啡" OR author:渡久山) NOT title:预告"#).unwrap();
        let mut qb = QueryBuilder::<Postgres>::new("SELECT p.id FROM posts p WHERE ");
        push_post_predicate(&mut qb, &expr);
        let built = qb.build();
        let sql_str = built.sql();
        let sql = sql_str.as_str();
        assert!(sql.contains("p.title ILIKE $1"));
        assert!(sql.contains("a.name ILIKE $2"));
        assert!(sql.contains("NOT (p.title ILIKE $3"));
        assert!(!sql.contains("渡久山"));

        let img_expr = parse_query(r#"(tag:maid>=0.45 OR tag:missing) AND author:渡久山"#).unwrap();
        let mut tag_map = HashMap::new();
        tag_map.insert("maid".to_string(), vec![10, 20]);
        tag_map.insert("missing".to_string(), vec![]);
        let mut qb2 = QueryBuilder::<Postgres>::new("SELECT i.id FROM images i WHERE ");
        push_image_predicate(&mut qb2, &img_expr, &tag_map);
        let built2 = qb2.build();
        let sql_str2 = built2.sql();
        let sql2 = sql_str2.as_str();
        assert!(sql2.contains("a.name ILIKE $1"));
        assert!(sql2.contains("wti.wd_tag_id = ANY($2::BIGINT[]) AND wti.score >= $3"));
        assert!(sql2.contains("OR FALSE"));
    }

    #[test]
    fn correlates_conjunctive_post_predicates_against_same_post() {
        let mut tag_map = HashMap::new();
        tag_map.insert("cat".to_string(), vec![10, 11]);

        let expr1 = parse_query("title:Foo AND author:Bar AND tag:cat").unwrap();
        let mut qb1 = QueryBuilder::<Postgres>::new("SELECT i.id FROM images i WHERE ");
        push_image_predicate(&mut qb1, &expr1, &tag_map);
        let built1 = qb1.build();
        let sql_str1 = built1.sql();
        let sql1 = sql_str1.as_str();
        assert_eq!(
            sql1.matches("FROM post_images pi JOIN posts p ON p.id = pi.post_id")
                .count(),
            1
        );

        let expr2 = parse_query("title:Foo AND NOT author:Bar AND tag:cat").unwrap();
        let mut qb2 = QueryBuilder::<Postgres>::new("SELECT i.id FROM images i WHERE ");
        push_image_predicate(&mut qb2, &expr2, &tag_map);
        let built2 = qb2.build();
        let sql_str2 = built2.sql();
        let sql2 = sql_str2.as_str();
        assert_eq!(
            sql2.matches("FROM post_images pi JOIN posts p ON p.id = pi.post_id")
                .count(),
            1
        );
    }

    #[test]
    fn independent_multi_clause_vectors_use_hard_limit_per_clause_thresholds_and_primary_ranking() {
        let v1 = HalfVector::from_f32_slice(&[1.0, 0.0, 0.0, 0.0]);
        let v2 = HalfVector::from_f32_slice(&[0.0, 1.0, 0.0, 0.0]);
        let v3 = HalfVector::from_f32_slice(&[0.0, 0.0, 1.0, 0.0]);

        let clauses = vec![
            ResolvedVectorClause {
                positive: true,
                col: "clip_embedding",
                vec: v1.clone(),
                threshold: Some(0.30),
            },
            ResolvedVectorClause {
                positive: true,
                col: "dinov3_embedding",
                vec: v2.clone(),
                threshold: Some(0.65),
            },
            ResolvedVectorClause {
                positive: false,
                col: "clip_embedding",
                vec: v3,
                threshold: Some(0.40),
            },
        ];

        let mut qb = build_vector_clauses_query(&clauses, None, &HashMap::new(), None, 50, 0);
        let built = qb.build();
        let sql_str = built.sql();
        let sql = sql_str.as_str();

        // Hard LIMIT (ZERO FETCH FIRST ... WITH TIES!)
        assert!(!sql.contains("WITH TIES"), "must not use WITH TIES: {sql}");
        assert!(sql.contains("LIMIT 2000"));
        // Primary positive vector drives HNSW scan & final ORDER BY (zero weighted blend!)
        assert!(sql.contains("ORDER BY i.clip_embedding <=>") && sql.contains("ORDER BY c.primary_dist ASC, c.id DESC"));
        // Independent positive threshold on CLIP, independent positive threshold on DINO,
        // and independent negated threshold on NOT CLIP!
        assert!(sql.contains("(1.0 - c.primary_dist) >="));
        assert!(sql.contains("(1.0 - (i.dinov3_embedding <=>") && sql.contains(")) >="));
        assert!(sql.contains("(i.clip_embedding IS NULL OR (1.0 - (i.clip_embedding <=>") && sql.contains(")) < "));

        // Negated-only vector query works cleanly with hard LIMIT and stable ID order
        let neg_only = vec![ResolvedVectorClause {
            positive: false,
            col: "clip_embedding",
            vec: v1.clone(),
            threshold: None,
        }];
        let mut qb_neg =
            build_vector_clauses_query(&neg_only, None, &HashMap::new(), None, 25, 0);
        let built_neg = qb_neg.build();
        let sql_str_neg = built_neg.sql();
        let sql_neg = sql_str_neg.as_str();
        assert!(!sql_neg.contains("WITH TIES"));
        assert!(sql_neg.contains("ORDER BY i.id DESC LIMIT 2000"));
        assert!(sql_neg.contains(")) < "));
        assert!(sql_neg.contains("ORDER BY c.id DESC LIMIT"));

        // Similar images query ALSO uses hard LIMIT (zero WITH TIES)
        let mut qb_sim = build_similar_images_query(v1, 42, Some(7), Some(0.6), None, 50, 0);
        let built_sim = qb_sim.build();
        let sql_str_sim = built_sim.sql();
        let sql_sim = sql_str_sim.as_str();
        assert!(!sql_sim.contains("WITH TIES"));
        assert!(sql_sim.contains("LIMIT 2000"));
        assert!(sql_sim.contains("i.id <> $2"));
        assert!(sql_sim.contains("ORDER BY dist ASC, id DESC LIMIT"));
    }

    #[test]
    fn scores_each_distinct_positive_tag_clause_with_max() {
        let mut tag_map = HashMap::new();
        tag_map.insert("cat".to_string(), vec![10, 11]);
        tag_map.insert("maid".to_string(), vec![30, 31]);

        let (_, plan_two) = parse_and_compile("tag:cat>=0.45 AND tag:maid").unwrap();
        let mut qb_two = build_metadata_images_query(
            plan_two.meta_filter.as_ref().unwrap(),
            &tag_map,
            &plan_two.positive_tags,
            AdvancedSort::Relevance,
            None,
            50,
            0,
        );
        let built_two = qb_two.build();
        let sql_str_two = built_two.sql();
        let sql_two = sql_str_two.as_str();
        assert_eq!(
            sql_two
                .matches("COALESCE((SELECT MAX(wti.score) FROM wd_tag_images wti")
                .count(),
            2
        );
        assert!(sql_two.contains("wti.score >= $2"));
        assert!(sql_two.contains("/ 2.0) DESC"));
    }
}
