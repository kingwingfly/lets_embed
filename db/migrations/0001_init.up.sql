CREATE EXTENSION IF NOT EXISTS vector;

CREATE TYPE process_status AS ENUM ('Pending', 'Processing', 'Complete');

CREATE TYPE meta AS (
    title TEXT,
    authors TEXT[],
    tags TEXT[],
    images TEXT[]
);

-- titles
CREATE TABLE IF NOT EXISTS titles (
    id BIGSERIAL PRIMARY KEY,
    title VARCHAR(255) UNIQUE NOT NULL CHECK (trim(title) != ''),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- images
CREATE TABLE IF NOT EXISTS images (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL CHECK (trim(name) != ''),
    status process_status NOT NULL DEFAULT 'Pending'::process_status,
    dinov3_embedding vector(384),
    clip_embedding vector(512),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_images_dinov3 ON images USING hnsw (dinov3_embedding vector_cosine_ops);
CREATE INDEX IF NOT EXISTS idx_images_clip ON images USING hnsw (clip_embedding vector_cosine_ops);

CREATE TABLE IF NOT EXISTS title_images (
    title_id BIGINT NOT NULL REFERENCES titles(id) ON DELETE CASCADE,
    image_id BIGINT NOT NULL REFERENCES images(id) ON DELETE CASCADE,
    PRIMARY KEY (title_id, image_id)
);

CREATE INDEX IF NOT EXISTS idx_title_images_image_id ON title_images(image_id);

-- authors
CREATE TABLE IF NOT EXISTS authors (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL CHECK (trim(name) != ''),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS author_titles (
    author_id BIGINT NOT NULL REFERENCES authors(id) ON DELETE CASCADE,
    title_id BIGINT NOT NULL REFERENCES titles(id) ON DELETE CASCADE,
    PRIMARY KEY (author_id, title_id)
);

CREATE INDEX IF NOT EXISTS idx_author_titles_title_id ON author_titles(title_id);

-- tags
CREATE TABLE IF NOT EXISTS tags (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL CHECK (trim(name) != ''),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS tag_titles (
    tag_id BIGINT NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
    title_id BIGINT NOT NULL REFERENCES titles(id) ON DELETE CASCADE,
    PRIMARY KEY (tag_id, title_id)
);

CREATE INDEX IF NOT EXISTS idx_tag_titles_title_id ON tag_titles(title_id);

-- wd_tags
CREATE TABLE IF NOT EXISTS wd_tags (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(100) UNIQUE NOT NULL CHECK (trim(name) != ''),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS wd_tag_images (
    wd_tag_id BIGINT NOT NULL REFERENCES wd_tags(id) ON DELETE CASCADE,
    image_id BIGINT NOT NULL REFERENCES images(id) ON DELETE CASCADE,

    score REAL NOT NULL,

    PRIMARY KEY (wd_tag_id, image_id)
);

CREATE INDEX IF NOT EXISTS idx_image_wd_tags_image_id ON wd_tag_images(image_id);
CREATE INDEX IF NOT EXISTS idx_wd_tag_images_score ON wd_tag_images(score);
