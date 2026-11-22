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
    query::{AdvancedSort, QueryExpr, QueryPlan, ResultKind, SearchField, parse_and_compile},
};
use sqlx::{Executor as _, Postgres, QueryBuilder, Row as _};

use crate::{Engine, escape_like};

/// Relative weight subtracted for negative semantic prompts (`NOT clip:...` / `NOT dino:...`).
const NEGATIVE_VECTOR_WEIGHT: f32 = 0.6;
/// Fixed per-index HNSW candidate pool for vector queries so `halfvec` distance ties
/// paginate deterministically with `ORDER BY dist ASC, id DESC` and zero cross-page duplicates.
const VECTOR_CANDIDATE_LIMIT: i64 = 2000;
/// Fixed per-index HNSW candidate pool when blending CLIP + DINOv3 so pagination is stable.
const DUAL_VECTOR_CANDIDATE_LIMIT: i64 = 1000;

#[derive(Debug, Clone)]
pub struct AdvancedSearchRequest {
    pub query: String,
    pub uploads: Vec<Vec<u8>>,
    pub sort: AdvancedSort,
    /// Weight for CLIP in `[0.05, 0.95]` when both CLIP and DINOv3 are active (default `0.5`).
    pub clip_weight: f32,
    pub limit: i64,
    pub offset: i64,
}

#[derive(Debug, Clone)]
pub enum AdvancedSearchResult {
    Posts(Vec<Post>),
    Images(Vec<Image>),
}

/// L2-normalize `vec` in place; returns `Err` on zero-length or non-finite values.
fn normalize_unit_vec(vec: &mut [f32]) -> anyhow::Result<()> {
    if vec.iter().any(|x| !x.is_finite()) {
        bail!("embedding vector contains non-finite values");
    }
    let norm = vec.iter().map(|x| x * x).sum::<f32>().sqrt();
    if !norm.is_finite() || norm < 1e-6 {
        bail!("embedding vector collapsed to zero");
    }
    let inv = 1.0 / norm;
    for x in vec {
        *x *= inv;
    }
    Ok(())
}

/// Combine L2-normalized positive and negative embedding vectors into a single
/// L2-normalized query vector compatible with pgvector `<=>` cosine distance.
pub(crate) fn combine_unit_vectors(
    pos: &[Vec<f32>],
    neg: &[Vec<f32>],
    dim: usize,
) -> anyhow::Result<HalfVector> {
    if pos.is_empty() && neg.is_empty() {
        bail!("cannot combine empty vector sets");
    }
    for v in pos.iter().chain(neg.iter()) {
        if v.len() != dim {
            bail!("unexpected embedding dimension {}, expected {dim}", v.len());
        }
        if v.iter().any(|x| !x.is_finite()) {
            bail!("embedding vector contains non-finite values");
        }
    }

    let mut pos_unit = vec![0.0f32; dim];
    if !pos.is_empty() {
        let inv = 1.0 / pos.len() as f32;
        for v in pos {
            for (acc, &x) in pos_unit.iter_mut().zip(v.iter()) {
                *acc += x * inv;
            }
        }
        normalize_unit_vec(&mut pos_unit)?;
    }

    let mut neg_unit = vec![0.0f32; dim];
    let mut has_neg = false;
    if !neg.is_empty() {
        let inv = 1.0 / neg.len() as f32;
        for v in neg {
            for (acc, &x) in neg_unit.iter_mut().zip(v.iter()) {
                *acc += x * inv;
            }
        }
        if normalize_unit_vec(&mut neg_unit).is_ok() {
            has_neg = true;
        } else if pos.is_empty() {
            bail!("negative semantic query vectors collapsed to zero");
        }
    }

    let mut combined = vec![0.0f32; dim];
    match (!pos.is_empty(), has_neg) {
        (true, false) => combined.copy_from_slice(&pos_unit),
        (false, true) => {
            for (out, &n) in combined.iter_mut().zip(neg_unit.iter()) {
                *out = -n;
            }
        }
        (true, true) => {
            for ((out, &p), &n) in combined
                .iter_mut()
                .zip(pos_unit.iter())
                .zip(neg_unit.iter())
            {
                *out = p - NEGATIVE_VECTOR_WEIGHT * n;
            }
        }
        (false, false) => unreachable!(),
    }

    if normalize_unit_vec(&mut combined).is_err() {
        // Fallback to unit positive centroid if positive & negative nearly cancel out.
        if !pos.is_empty() {
            return Ok(HalfVector::from_f32_slice(&pos_unit));
        }
        bail!("combined semantic query vector collapsed to zero");
    }
    Ok(HalfVector::from_f32_slice(&combined))
}

fn collect_all_tag_values(expr: &QueryExpr, out: &mut Vec<String>) {
    match expr {
        QueryExpr::Term {
            field: SearchField::Tag,
            value,
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
        QueryExpr::Term { field, value } => {
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
        QueryExpr::Term { field, value } => match field {
            SearchField::Tag => {
                let ids = tag_map.get(value).map(Vec::as_slice).unwrap_or(&[]);
                if ids.is_empty() {
                    qb.push("FALSE");
                } else {
                    qb.push(
                        "EXISTS (SELECT 1 FROM wd_tag_images wti WHERE wti.image_id = i.id AND wti.wd_tag_id = ANY(",
                    );
                    qb.push_bind(ids.to_vec());
                    qb.push("::BIGINT[]))");
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
    limit: i64,
    offset: i64,
) -> QueryBuilder<Postgres> {
    let pos_tag_clauses = collect_positive_tag_clauses(positive_tags, tag_map);

    if sort == AdvancedSort::Relevance && !pos_tag_clauses.is_empty() {
        let mut qb = QueryBuilder::<Postgres>::new(
            "WITH matched AS (SELECT i.id, i.name::TEXT AS name, i.width, i.height FROM images i WHERE ",
        );
        push_image_predicate(&mut qb, meta, tag_map);
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
    qb.push(" ORDER BY i.id DESC LIMIT ");
    qb.push_bind(limit);
    qb.push(" OFFSET ");
    qb.push_bind(offset);
    qb
}

pub(crate) fn build_single_vector_query(
    col: &'static str,
    vec: HalfVector,
    meta_filter: Option<&QueryExpr>,
    tag_map: &HashMap<String, Vec<i64>>,
    limit: i64,
    offset: i64,
) -> QueryBuilder<Postgres> {
    // Fetch a fixed-size HNSW candidate pool WITH TIES first, then apply a deterministic
    // `(dist ASC, id DESC)` tie-breaker so `halfvec` ties never duplicate or skip items
    // across OFFSET pages.
    let mut qb = QueryBuilder::<Postgres>::new(
        "WITH cands AS (SELECT i.id, i.name::TEXT AS name, i.width, i.height, (i.",
    );
    qb.push(col);
    qb.push(" <=> ");
    qb.push_bind(vec.clone());
    qb.push("::halfvec) AS dist FROM images i WHERE i.");
    qb.push(col);
    qb.push(" IS NOT NULL");
    if let Some(meta) = meta_filter {
        qb.push(" AND ");
        push_image_predicate(&mut qb, meta, tag_map);
    }
    qb.push(" ORDER BY i.");
    qb.push(col);
    qb.push(" <=> ");
    qb.push_bind(vec);
    qb.push("::halfvec FETCH FIRST ");
    qb.push(VECTOR_CANDIDATE_LIMIT);
    qb.push(" ROWS WITH TIES) SELECT id, name, width, height FROM cands ORDER BY dist ASC, id DESC LIMIT ");
    qb.push_bind(limit);
    qb.push(" OFFSET ");
    qb.push_bind(offset);
    qb
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_dual_vector_query(
    clip_vec: HalfVector,
    dino_vec: HalfVector,
    clip_weight: f32,
    meta_filter: Option<&QueryExpr>,
    tag_map: &HashMap<String, Vec<i64>>,
    limit: i64,
    offset: i64,
) -> QueryBuilder<Postgres> {
    let dino_weight = 1.0 - clip_weight;
    let mut qb = QueryBuilder::<Postgres>::new(
        "WITH clip_cands AS (SELECT i.id FROM images i WHERE i.clip_embedding IS NOT NULL AND i.dinov3_embedding IS NOT NULL",
    );
    if let Some(meta) = meta_filter {
        qb.push(" AND ");
        push_image_predicate(&mut qb, meta, tag_map);
    }
    qb.push(" ORDER BY i.clip_embedding <=> ");
    qb.push_bind(clip_vec.clone());
    qb.push("::halfvec FETCH FIRST ");
    qb.push(DUAL_VECTOR_CANDIDATE_LIMIT);
    qb.push(
        " ROWS WITH TIES), dino_cands AS (SELECT i.id FROM images i WHERE i.clip_embedding IS NOT NULL AND i.dinov3_embedding IS NOT NULL",
    );
    if let Some(meta) = meta_filter {
        qb.push(" AND ");
        push_image_predicate(&mut qb, meta, tag_map);
    }
    qb.push(" ORDER BY i.dinov3_embedding <=> ");
    qb.push_bind(dino_vec.clone());
    qb.push("::halfvec FETCH FIRST ");
    qb.push(DUAL_VECTOR_CANDIDATE_LIMIT);
    qb.push(
        " ROWS WITH TIES), candidates AS (SELECT id FROM clip_cands UNION SELECT id FROM dino_cands) SELECT i.id, i.name::TEXT AS name, i.width, i.height FROM candidates c JOIN images i ON i.id = c.id ORDER BY (",
    );
    qb.push_bind(f64::from(clip_weight));
    qb.push(" * (i.clip_embedding <=> ");
    qb.push_bind(clip_vec);
    qb.push("::halfvec) + ");
    qb.push_bind(f64::from(dino_weight));
    qb.push(" * (i.dinov3_embedding <=> ");
    qb.push_bind(dino_vec);
    qb.push("::halfvec)) ASC, i.id DESC LIMIT ");
    qb.push_bind(limit);
    qb.push(" OFFSET ");
    qb.push_bind(offset);
    qb
}

pub(crate) fn build_similar_images_query(
    seed_vec: HalfVector,
    seed_id: i64,
    exclude_post_id: Option<i64>,
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
    qb.push(" ORDER BY i.dinov3_embedding <=> ");
    qb.push_bind(seed_vec);
    qb.push("::halfvec FETCH FIRST ");
    qb.push(VECTOR_CANDIDATE_LIMIT);
    qb.push(" ROWS WITH TIES) SELECT id, name, width, height FROM cands ORDER BY dist ASC, id DESC LIMIT ");
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

    pub(crate) async fn fetch_dino_id_vectors(
        &self,
        ids: &[i64],
    ) -> anyhow::Result<HashMap<i64, Vec<f32>>> {
        if ids.is_empty() {
            return Ok(HashMap::new());
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
        .fetch_all(&self.pool)
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

    /// Execute a parsed Web-of-Science-style advanced query.
    ///
    /// - Post-only queries (`All` / `Title` / `Author`) paginate `posts` directly in SQL.
    /// - Queries with any `Tag` / `CLIP` / `DINO` / `Upload` paginate `images` directly in SQL.
    pub async fn advanced_search(
        &self,
        req: AdvancedSearchRequest,
    ) -> anyhow::Result<AdvancedSearchResult> {
        if req.limit < 0 || req.offset < 0 {
            bail!("both limit and offset should >= 0");
        }
        let (_expr, plan) = parse_and_compile(&req.query).map_err(|e| anyhow!("{e}"))?;
        self.execute_advanced_plan(&plan, &req).await
    }

    pub async fn execute_advanced_plan(
        &self,
        plan: &QueryPlan,
        req: &AdvancedSearchRequest,
    ) -> anyhow::Result<AdvancedSearchResult> {
        if req.limit < 0 || req.offset < 0 {
            bail!("both limit and offset should >= 0");
        }
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
            let posts = rows
                .into_iter()
                .map(|r| -> sqlx::Result<Post> {
                    Ok(Post {
                        id: r.try_get("id")?,
                        title: r.try_get("title")?,
                    })
                })
                .try_collect()?;
            return Ok(AdvancedSearchResult::Posts(posts));
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

        // Compute CLIP query vector (if any CLIP clauses exist).
        let clip_vec = if plan.has_clip() {
            let mut pos = Vec::with_capacity(plan.clip_pos.len());
            for text in &plan.clip_pos {
                pos.push((*self.clip_text_vec_cached(text).await?).clone());
            }
            let mut neg = Vec::with_capacity(plan.clip_neg.len());
            for text in &plan.clip_neg {
                neg.push((*self.clip_text_vec_cached(text).await?).clone());
            }
            Some(combine_unit_vectors(&pos, &neg, siglip2::EMBED_DIM)?)
        } else {
            None
        };

        // Compute DINOv3 query vector (combining stored image IDs and uploaded images).
        let dino_vec = if plan.has_dino() {
            let mut all_ids: Vec<i64> = plan
                .dino_pos
                .iter()
                .chain(plan.dino_neg.iter())
                .copied()
                .collect();
            all_ids.sort_unstable();
            all_ids.dedup();
            let id_vecs = self.fetch_dino_id_vectors(&all_ids).await?;

            // Validate every referenced upload index exists in `req.uploads`.
            let mut upload_vecs: HashMap<usize, Vec<f32>> = HashMap::new();
            for &idx in plan.upload_pos.iter().chain(plan.upload_neg.iter()) {
                if upload_vecs.contains_key(&idx) {
                    continue;
                }
                let Some(bytes) = req.uploads.get(idx) else {
                    bail!("Uploaded image #{idx} is missing — re-upload the image and try again");
                };
                if bytes.is_empty() {
                    bail!("Uploaded image #{idx} is empty");
                }
                let vec = (*self.dinov3_upload_vec_cached(bytes.clone()).await?).clone();
                upload_vecs.insert(idx, vec);
            }

            let mut pos = Vec::with_capacity(plan.dino_pos.len() + plan.upload_pos.len());
            for id in &plan.dino_pos {
                pos.push(id_vecs[id].clone());
            }
            for idx in &plan.upload_pos {
                pos.push(upload_vecs[idx].clone());
            }
            let mut neg = Vec::with_capacity(plan.dino_neg.len() + plan.upload_neg.len());
            for id in &plan.dino_neg {
                neg.push(id_vecs[id].clone());
            }
            for idx in &plan.upload_neg {
                neg.push(upload_vecs[idx].clone());
            }
            Some(combine_unit_vectors(&pos, &neg, dinov3::EMBED_DIM)?)
        } else {
            None
        };

        // Dispatch by vector combination: None, Single (CLIP or DINO), or Dual (CLIP + DINO).
        let images = match (clip_vec, dino_vec) {
            (None, None) => {
                self.query_images_metadata_only(plan, &tag_map, req.sort, req.limit, req.offset)
                    .await?
            }
            (Some(c), None) => {
                self.query_images_single_vector(
                    "clip_embedding",
                    c,
                    plan.meta_filter.as_ref(),
                    &tag_map,
                    req.limit,
                    req.offset,
                )
                .await?
            }
            (None, Some(d)) => {
                self.query_images_single_vector(
                    "dinov3_embedding",
                    d,
                    plan.meta_filter.as_ref(),
                    &tag_map,
                    req.limit,
                    req.offset,
                )
                .await?
            }
            (Some(c), Some(d)) => {
                let clip_weight = if req.clip_weight.is_finite() {
                    req.clip_weight.clamp(0.05, 0.95)
                } else {
                    0.5
                };
                self.query_images_dual_vector(
                    c,
                    d,
                    clip_weight,
                    plan.meta_filter.as_ref(),
                    &tag_map,
                    req.limit,
                    req.offset,
                )
                .await?
            }
        };

        Ok(AdvancedSearchResult::Images(images))
    }

    async fn query_images_metadata_only(
        &self,
        plan: &QueryPlan,
        tag_map: &HashMap<String, Vec<i64>>,
        sort: AdvancedSort,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<Image>> {
        let Some(meta) = &plan.meta_filter else {
            return Ok(vec![]);
        };

        // Fast path for a single positive Tag term with Relevance sort: uses the
        // `wd_tag_images(wd_tag_id, image_id)` PK index directly, matching `search_images_by_tag`.
        if sort == AdvancedSort::Relevance
            && let QueryExpr::Term {
                field: SearchField::Tag,
                value,
            } = meta
        {
            let ids = tag_map.get(value).map(Vec::as_slice).unwrap_or(&[]);
            if ids.is_empty() {
                return Ok(vec![]);
            }
            let rows = sqlx::query(
                r#"
                WITH img_match AS (
                    SELECT wti.image_id, MAX(wti.score) AS max_score
                    FROM wd_tag_images wti
                    WHERE wti.wd_tag_id = ANY($1::BIGINT[])
                    GROUP BY wti.image_id
                )
                SELECT i.id, i.name::TEXT AS name, i.width, i.height
                FROM img_match im
                JOIN images i ON i.id = im.image_id
                ORDER BY im.max_score DESC, im.image_id DESC
                LIMIT $2 OFFSET $3
                "#,
            )
            .bind(ids)
            .bind(limit)
            .bind(offset)
            .fetch_all(&self.pool)
            .await?;
            return map_image_rows(rows);
        }

        let mut qb =
            build_metadata_images_query(meta, tag_map, &plan.positive_tags, sort, limit, offset);
        let rows = qb.build().fetch_all(&self.pool).await?;
        map_image_rows(rows)
    }

    pub(crate) async fn query_images_single_vector(
        &self,
        col: &'static str,
        vec: HalfVector,
        meta_filter: Option<&QueryExpr>,
        tag_map: &HashMap<String, Vec<i64>>,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<Image>> {
        let mut qb = build_single_vector_query(col, vec, meta_filter, tag_map, limit, offset);

        if meta_filter.is_some() {
            let mut tx = self.pool.begin().await?;
            tx.execute("SET TRANSACTION READ ONLY").await?;
            tx.execute("SET LOCAL hnsw.max_scan_tuples = 20000").await?;
            let rows = qb.build().fetch_all(&mut *tx).await?;
            tx.commit().await?;
            map_image_rows(rows)
        } else {
            let rows = qb.build().fetch_all(&self.pool).await?;
            map_image_rows(rows)
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn query_images_dual_vector(
        &self,
        clip_vec: HalfVector,
        dino_vec: HalfVector,
        clip_weight: f32,
        meta_filter: Option<&QueryExpr>,
        tag_map: &HashMap<String, Vec<i64>>,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<Vec<Image>> {
        let mut qb = build_dual_vector_query(
            clip_vec,
            dino_vec,
            clip_weight,
            meta_filter,
            tag_map,
            limit,
            offset,
        );

        if meta_filter.is_some() {
            let mut tx = self.pool.begin().await?;
            tx.execute("SET TRANSACTION READ ONLY").await?;
            tx.execute("SET LOCAL hnsw.max_scan_tuples = 20000").await?;
            let rows = qb.build().fetch_all(&mut *tx).await?;
            tx.commit().await?;
            map_image_rows(rows)
        } else {
            let rows = qb.build().fetch_all(&self.pool).await?;
            map_image_rows(rows)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use search_types::query::{parse_and_compile, parse_query};
    use sqlx::Execute as _;

    #[test]
    fn combine_unit_vectors_handles_positive_negative_and_cancel() {
        let pos = vec![vec![1.0, 0.0, 0.0, 0.0]];
        let neg = vec![vec![0.0, 1.0, 0.0, 0.0]];
        let combined = halfvec_to_f32(&combine_unit_vectors(&pos, &neg, 4).unwrap());
        let norm: f32 = combined.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-2);
        assert!(combined[0] > 0.8);
        assert!(combined[1] < -0.4);

        let neg_only = halfvec_to_f32(&combine_unit_vectors(&[], &neg, 4).unwrap());
        assert!((neg_only[1] + 1.0).abs() < 1e-2);

        // Positive and negative along identical direction stays non-zero & normalized.
        let same = halfvec_to_f32(&combine_unit_vectors(&pos, &pos, 4).unwrap());
        assert!((same[0] - 1.0).abs() < 1e-2);

        // Opposing negative vectors canceling to zero fall back to `pos_unit` when `!pos.is_empty()`.
        let cancel_neg = vec![vec![0.0, 1.0, 0.0, 0.0], vec![0.0, -1.0, 0.0, 0.0]];
        let fallback = halfvec_to_f32(&combine_unit_vectors(&pos, &cancel_neg, 4).unwrap());
        assert!((fallback[0] - 1.0).abs() < 1e-2);
        assert!(fallback[1].abs() < 1e-2);
        // Without positive vectors, canceling negative vectors still fail.
        assert!(combine_unit_vectors(&[], &cancel_neg, 4).is_err());

        // Diverse positive vectors are L2-normalized before subtracting negative prompt.
        let diverse_pos = vec![
            vec![0.5, 0.866_025_4, 0.0, 0.0],
            vec![0.5, -0.866_025_4, 0.0, 0.0],
        ];
        let diverse_out = halfvec_to_f32(&combine_unit_vectors(&diverse_pos, &neg, 4).unwrap());
        assert!(diverse_out[0] > 0.8);

        // Non-finite inputs are rejected.
        assert!(combine_unit_vectors(&[vec![f32::NAN, 0.0, 0.0, 0.0]], &[], 4).is_err());
        assert!(combine_unit_vectors(&[vec![f32::INFINITY, 0.0, 0.0, 0.0]], &[], 4).is_err());
    }

    #[test]
    fn builds_parameterized_post_and_image_predicates() {
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

        let img_expr = parse_query(r#"(tag:maid OR tag:missing) AND author:渡久山"#).unwrap();
        let mut tag_map = HashMap::new();
        tag_map.insert("maid".to_string(), vec![10, 20]);
        tag_map.insert("missing".to_string(), vec![]);
        let mut qb2 = QueryBuilder::<Postgres>::new("SELECT i.id FROM images i WHERE ");
        push_image_predicate(&mut qb2, &img_expr, &tag_map);
        let built2 = qb2.build();
        let sql_str2 = built2.sql();
        let sql2 = sql_str2.as_str();
        assert!(sql2.contains("a.name ILIKE $1"));
        assert!(sql2.contains("wti.wd_tag_id = ANY($2::BIGINT[])"));
        assert!(sql2.contains("OR FALSE"));
    }

    #[test]
    fn correlates_conjunctive_post_predicates_against_same_post() {
        let mut tag_map = HashMap::new();
        tag_map.insert("cat".to_string(), vec![10, 11]);

        // 1. Positive post conjuncts correlate in ONE post_images EXISTS.
        let expr1 = parse_query("title:Foo AND author:Bar AND tag:cat").unwrap();
        let mut qb1 = QueryBuilder::<Postgres>::new("SELECT i.id FROM images i WHERE ");
        push_image_predicate(&mut qb1, &expr1, &tag_map);
        let built1 = qb1.build();
        let sql_str1 = built1.sql();
        let sql1 = sql_str1.as_str();
        assert_eq!(
            sql1.matches("FROM post_images pi JOIN posts p ON p.id = pi.post_id")
                .count(),
            1,
            "expected single correlated post EXISTS: {sql1}"
        );
        assert!(sql1.contains("p.title ILIKE $1"));
        assert!(sql1.contains("a.name ILIKE $2"));
        assert!(sql1.contains("wti.wd_tag_id = ANY($3::BIGINT[])"));

        // 2. Positive + negated post conjunct correlate against the SAME post.
        let expr2 = parse_query("title:Foo AND NOT author:Bar AND tag:cat").unwrap();
        let mut qb2 = QueryBuilder::<Postgres>::new("SELECT i.id FROM images i WHERE ");
        push_image_predicate(&mut qb2, &expr2, &tag_map);
        let built2 = qb2.build();
        let sql_str2 = built2.sql();
        let sql2 = sql_str2.as_str();
        assert_eq!(
            sql2.matches("FROM post_images pi JOIN posts p ON p.id = pi.post_id")
                .count(),
            1,
            "expected single correlated post EXISTS for title AND NOT author: {sql2}"
        );
        assert!(sql2.contains("(p.title ILIKE $1 ESCAPE '\\') AND (NOT EXISTS"));
        assert!(sql2.contains("wti.wd_tag_id = ANY($3::BIGINT[])"));

        // 3. Only negated post term excludes images belonging to ANY matching post.
        let expr3 = parse_query("NOT author:Bar AND tag:cat").unwrap();
        let mut qb3 = QueryBuilder::<Postgres>::new("SELECT i.id FROM images i WHERE ");
        push_image_predicate(&mut qb3, &expr3, &tag_map);
        let built3 = qb3.build();
        let sql_str3 = built3.sql();
        let sql3 = sql_str3.as_str();
        assert!(
            sql3.contains("(NOT EXISTS (SELECT 1 FROM post_images pi JOIN posts p ON p.id = pi.post_id WHERE pi.image_id = i.id AND EXISTS"),
            "expected NOT EXISTS post_images for negated-only post term: {sql3}"
        );
        assert!(sql3.contains("wti.wd_tag_id = ANY($2::BIGINT[])"));
    }

    #[test]
    fn scores_each_distinct_positive_tag_clause_with_max_not_flat_avg() {
        let mut tag_map = HashMap::new();
        tag_map.insert("cat".to_string(), vec![10, 11]);
        tag_map.insert("dog".to_string(), vec![20]);
        tag_map.insert("maid".to_string(), vec![30, 31]);

        // Repeating the same tag uses a single MAX(wti.score) clause (never AVG over union).
        let (_, plan_dup) = parse_and_compile("tag:cat AND tag:cat").unwrap();
        let mut qb_dup = build_metadata_images_query(
            plan_dup.meta_filter.as_ref().unwrap(),
            &tag_map,
            &plan_dup.positive_tags,
            AdvancedSort::Relevance,
            50,
            0,
        );
        let built_dup = qb_dup.build();
        let sql_str_dup = built_dup.sql();
        let sql_dup = sql_str_dup.as_str();
        assert!(!sql_dup.contains("AVG("), "should not use AVG: {sql_dup}");
        assert_eq!(
            sql_dup
                .matches("COALESCE((SELECT MAX(wti.score) FROM wd_tag_images wti")
                .count(),
            1,
            "expected 1 MAX clause for repeated tag: {sql_dup}"
        );

        // Single positive tag + negated tag also uses 1 MAX(wti.score) clause.
        let (_, plan_neg) = parse_and_compile("tag:cat AND NOT tag:dog").unwrap();
        let mut qb_neg = build_metadata_images_query(
            plan_neg.meta_filter.as_ref().unwrap(),
            &tag_map,
            &plan_neg.positive_tags,
            AdvancedSort::Relevance,
            50,
            0,
        );
        let built_neg = qb_neg.build();
        let sql_str_neg = built_neg.sql();
        let sql_neg = sql_str_neg.as_str();
        assert_eq!(
            sql_neg
                .matches("COALESCE((SELECT MAX(wti.score) FROM wd_tag_images wti")
                .count(),
            1,
            "expected 1 MAX clause for tag AND NOT tag: {sql_neg}"
        );

        // Two distinct positive tag clauses average their per-clause MAX scores.
        let (_, plan_two) = parse_and_compile("tag:cat AND tag:maid").unwrap();
        let mut qb_two = build_metadata_images_query(
            plan_two.meta_filter.as_ref().unwrap(),
            &tag_map,
            &plan_two.positive_tags,
            AdvancedSort::Relevance,
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
            2,
            "expected 2 MAX clauses for two distinct tags: {sql_two}"
        );
        assert!(
            sql_two.contains("/ 2.0) DESC"),
            "expected average by 2.0: {sql_two}"
        );
    }

    #[test]
    fn vector_queries_use_fetch_first_with_ties_and_similar_excludes_seed_and_post() {
        let hv = HalfVector::from_f32_slice(&[1.0, 0.0, 0.0, 0.0]);
        let mut qb_single =
            build_single_vector_query("clip_embedding", hv.clone(), None, &HashMap::new(), 50, 0);
        let built_single = qb_single.build();
        let sql_str_single = built_single.sql();
        let sql_single = sql_str_single.as_str();
        assert!(sql_single.contains("FETCH FIRST 2000 ROWS WITH TIES"));
        assert!(sql_single.contains("ORDER BY dist ASC, id DESC LIMIT"));

        let mut qb_dual =
            build_dual_vector_query(hv.clone(), hv.clone(), 0.5, None, &HashMap::new(), 50, 0);
        let built_dual = qb_dual.build();
        let sql_str_dual = built_dual.sql();
        let sql_dual = sql_str_dual.as_str();
        assert_eq!(
            sql_dual.matches("FETCH FIRST 1000 ROWS WITH TIES").count(),
            2
        );

        let mut qb_sim = build_similar_images_query(hv, 42, Some(7), 50, 0);
        let built_sim = qb_sim.build();
        let sql_str_sim = built_sim.sql();
        let sql_sim = sql_str_sim.as_str();
        assert!(sql_sim.contains("i.id <> $2"));
        assert!(sql_sim.contains(
            "NOT EXISTS (SELECT 1 FROM post_images pi WHERE pi.image_id = i.id AND pi.post_id = $3)"
        ));
        assert!(sql_sim.contains("FETCH FIRST 2000 ROWS WITH TIES"));
        assert!(sql_sim.contains("ORDER BY dist ASC, id DESC LIMIT"));
    }
}
