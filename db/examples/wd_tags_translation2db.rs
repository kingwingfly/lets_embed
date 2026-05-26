use std::{collections::HashMap, env};

use serde::Deserialize;
use sqlx::PgPool;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut file = std::fs::File::open("models/wd-eva02-large-tagger-v3/zh_CN.yaml")?;

    let classes: Vec<Class> = yaml_serde::from_reader(&mut file)?;

    let (ens, chs) = classes
        .into_iter()
        .flat_map(|c| c.groups.into_iter().flat_map(|g| g.tags.into_iter()))
        .unzip::<_, _, Vec<_>, Vec<_>>();

    let pool = PgPool::connect_lazy(
        env::var("DATABASE_URL")
            .unwrap_or("postgres://postgres:postgres@postgres:5432/postgres".to_string())
            .as_str(),
    )?;

    sqlx::query!(
        r#"
        UPDATE wd_tags AS t
        SET translations = COALESCE(
            (
                SELECT array_agg(DISTINCT x)
                FROM unnest(COALESCE(t.translations, ARRAY[]::varchar[]) || ARRAY[v.new_ch]::varchar[]) AS _(x)
                WHERE btrim(x) != ''
            ),
            t.translations
        )
        FROM UNNEST($1::varchar[], $2::varchar[]) AS v(name, new_ch)
        WHERE t.name = v.name
            AND btrim(v.new_ch) != ''
            AND (t.translations IS NULL OR NOT (v.new_ch = ANY(t.translations)))
        "#,
        &ens,
        &chs
    ).execute(&pool).await?;

    Ok(())
}

#[derive(Debug, Deserialize)]
struct Class {
    _name: Option<String>,
    #[serde(default)]
    groups: Vec<Group>,
}

#[derive(Debug, Deserialize)]
struct Group {
    _name: Option<String>,
    _type: Option<String>,
    #[serde(default)]
    tags: HashMap<String, String>,
}
