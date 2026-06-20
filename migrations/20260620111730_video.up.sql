CREATE TABLE IF NOT EXISTS videos (
    id BIGSERIAL PRIMARY KEY,
    name VARCHAR(255) UNIQUE NOT NULL CHECK (btrim(name) != ''),
    width INT NOT NULL CHECK (width > 0),
    height INT NOT NULL CHECK (height > 0),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS post_videos (
    post_id BIGINT NOT NULL REFERENCES posts(id) ON DELETE CASCADE,
    video_id BIGINT NOT NULL REFERENCES videos(id) ON DELETE CASCADE,
    PRIMARY KEY (post_id, video_id)
);

CREATE INDEX IF NOT EXISTS idx_videos_name_trgm ON videos USING GIN (name gin_trgm_ops);
CREATE INDEX IF NOT EXISTS idx_post_videos_video_id ON post_videos(video_id);
