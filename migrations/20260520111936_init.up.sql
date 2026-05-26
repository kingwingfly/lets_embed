CREATE EXTENSION IF NOT EXISTS vector;

CREATE TYPE process_status AS ENUM ('pending', 'processing', 'completed');

CREATE TYPE image AS (
    name TEXT,
    width INT,
    height INT
);

CREATE TYPE meta AS (
    title TEXT,
    authors TEXT[],
    tags TEXT[],
    images image[]
);

CREATE TYPE translation AS (
    name TEXT,
    translations TEXT[]
);

-- posts
CREATE TABLE IF NOT EXISTS posts (
    id BIGSERIAL PRIMARY KEY,
    title VARCHAR(255) UNIQUE NOT NULL CHECK (btrim(title) != ''),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_posts_title ON posts(title);

-- images
CREATE TABLE IF NOT EXISTS images (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL CHECK (btrim(name) != ''),
    width INT NOT NULL CHECK (width > 0),
    height INT NOT NULL CHECK (height > 0),
    status process_status NOT NULL DEFAULT 'pending'::process_status,
    attempt INT NOT NULL DEFAULT 0,
    dinov3_embedding halfvec(768),
    clip_embedding halfvec(1152),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS post_images (
    post_id BIGINT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    image_id BIGINT NOT NULL REFERENCES images(id) ON DELETE CASCADE,
    PRIMARY KEY (post_id, image_id)
);

CREATE INDEX IF NOT EXISTS idx_images_name ON images(name);
CREATE INDEX IF NOT EXISTS idx_images_status ON images (status) WHERE status = 'pending'::process_status;
CREATE INDEX IF NOT EXISTS idx_images_dinov3 ON images USING hnsw (dinov3_embedding halfvec_cosine_ops);
CREATE INDEX IF NOT EXISTS idx_images_clip ON images USING hnsw (clip_embedding halfvec_cosine_ops);
CREATE INDEX IF NOT EXISTS idx_post_images_image_id ON post_images(image_id);

-- authors
CREATE TABLE IF NOT EXISTS authors (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL CHECK (btrim(name) != ''),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS author_posts (
    author_id BIGINT NOT NULL REFERENCES authors(id) ON DELETE CASCADE,
    post_id BIGINT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    PRIMARY KEY (author_id, post_id)
);

CREATE INDEX IF NOT EXISTS idx_authors_name ON authors(name);
CREATE INDEX IF NOT EXISTS idx_author_posts_post_id ON author_posts(post_id);

-- tags
CREATE TABLE IF NOT EXISTS tags (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL CHECK (btrim(name) != ''),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tag_posts (
    tag_id BIGINT NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    post_id BIGINT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    PRIMARY KEY (tag_id, post_id)
);

CREATE INDEX IF NOT EXISTS idx_tags_name ON tags(name);
CREATE INDEX IF NOT EXISTS idx_tag_posts_post_id ON tag_posts(post_id);

-- wd_tags
CREATE TABLE IF NOT EXISTS wd_tags (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL CHECK (btrim(name) != ''),
    translations VARCHAR(100)[] CHECK (
            translations IS NULL
            OR (
                array_position(translations, NULL) IS NULL
                AND array_position(translations, '') IS NULL
            )
        ),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS wd_tag_images (
    wd_tag_id BIGINT NOT NULL REFERENCES wd_tags(id) ON DELETE CASCADE,
    image_id BIGINT NOT NULL REFERENCES images(id) ON DELETE CASCADE,

    score REAL NOT NULL,

    PRIMARY KEY (wd_tag_id, image_id)
);

CREATE INDEX IF NOT EXISTS idx_wd_tags_name ON wd_tags(name);
CREATE INDEX IF NOT EXISTS idx_wd_tags_translations ON wd_tags USING gin (translations);
CREATE INDEX IF NOT EXISTS idx_image_wd_tags_image_id ON wd_tag_images(image_id);
CREATE INDEX IF NOT EXISTS idx_wd_tag_images_score ON wd_tag_images(score);
