-- Policy v3: Transactional `facts_rev` tracking across posts, images, and videos,
-- plus WD-Tagger v3 coverage tracking (`wd_min_persisted_score`, `wd_vocab_digest`).

ALTER TABLE posts
    ADD COLUMN IF NOT EXISTS facts_rev BIGINT NOT NULL DEFAULT 1;

ALTER TABLE images
    ADD COLUMN IF NOT EXISTS facts_rev BIGINT NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS wd_min_persisted_score REAL,
    ADD COLUMN IF NOT EXISTS wd_vocab_digest TEXT;

ALTER TABLE images
    DROP CONSTRAINT IF EXISTS chk_images_wd_min_persisted_score;
ALTER TABLE images
    ADD CONSTRAINT chk_images_wd_min_persisted_score
    CHECK (
        wd_min_persisted_score IS NULL
        OR (wd_min_persisted_score >= 0.0 AND wd_min_persisted_score <= 1.0)
    );

ALTER TABLE videos
    ADD COLUMN IF NOT EXISTS facts_rev BIGINT NOT NULL DEFAULT 1;

-- ---------------------------------------------------------------------------
-- Helper Functions (update ONLY `facts_rev`, never re-triggering content hooks)
-- ---------------------------------------------------------------------------

CREATE OR REPLACE FUNCTION policy_v3_bump_posts_and_media(p_post_ids BIGINT[])
RETURNS VOID
LANGUAGE plpgsql
AS $$
BEGIN
    IF p_post_ids IS NULL OR cardinality(p_post_ids) = 0 THEN
        RETURN;
    END IF;

    UPDATE posts
       SET facts_rev = facts_rev + 1
     WHERE id = ANY(p_post_ids);

    UPDATE images
       SET facts_rev = facts_rev + 1
     WHERE id IN (
         SELECT DISTINCT pi.image_id
           FROM post_images pi
          WHERE pi.post_id = ANY(p_post_ids)
     );

    UPDATE videos
       SET facts_rev = facts_rev + 1
     WHERE id IN (
         SELECT DISTINCT pv.video_id
           FROM post_videos pv
          WHERE pv.post_id = ANY(p_post_ids)
     );
END;
$$;

CREATE OR REPLACE FUNCTION policy_v3_bump_images_and_siblings(
    p_image_ids BIGINT[],
    p_bump_images BOOLEAN
)
RETURNS VOID
LANGUAGE plpgsql
AS $$
DECLARE
    v_post_ids BIGINT[];
BEGIN
    IF p_image_ids IS NULL OR cardinality(p_image_ids) = 0 THEN
        RETURN;
    END IF;

    IF p_bump_images THEN
        UPDATE images
           SET facts_rev = facts_rev + 1
         WHERE id = ANY(p_image_ids);
    END IF;

    SELECT ARRAY(
        SELECT DISTINCT pi.post_id
          FROM post_images pi
         WHERE pi.image_id = ANY(p_image_ids)
    ) INTO v_post_ids;

    IF v_post_ids IS NOT NULL AND cardinality(v_post_ids) > 0 THEN
        UPDATE posts
           SET facts_rev = facts_rev + 1
         WHERE id = ANY(v_post_ids);

        UPDATE videos
           SET facts_rev = facts_rev + 1
         WHERE id IN (
             SELECT DISTINCT pv.video_id
               FROM post_videos pv
              WHERE pv.post_id = ANY(v_post_ids)
         );
    END IF;
END;
$$;

-- ---------------------------------------------------------------------------
-- Trigger Functions
-- ---------------------------------------------------------------------------

-- 1. Self-mutations on `images` (name/locator, status, wd_min_persisted_score, wd_vocab_digest)
CREATE OR REPLACE FUNCTION policy_v3_trg_images_before_upd()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.facts_rev := OLD.facts_rev + 1;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION policy_v3_trg_images_after_upd()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM policy_v3_bump_images_and_siblings(ARRAY[NEW.id], FALSE);
    RETURN NULL;
END;
$$;

-- 2. Self-mutations on `videos` (name/locator)
CREATE OR REPLACE FUNCTION policy_v3_trg_videos_before_upd()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.facts_rev := OLD.facts_rev + 1;
    RETURN NEW;
END;
$$;

CREATE OR REPLACE FUNCTION policy_v3_trg_videos_after_upd()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    UPDATE posts
       SET facts_rev = facts_rev + 1
     WHERE id IN (
         SELECT DISTINCT pv.post_id
           FROM post_videos pv
          WHERE pv.video_id = NEW.id
     );
    RETURN NULL;
END;
$$;

-- 3. Self-mutations on `posts` (title)
CREATE OR REPLACE FUNCTION policy_v3_trg_posts_before_upd()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.facts_rev := OLD.facts_rev + 1;
    RETURN NEW;
END;
$$;

-- 4. Mutations on `wd_tag_images` (score, tag, or image association)
CREATE OR REPLACE FUNCTION policy_v3_trg_wd_tag_images()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_image_ids BIGINT[];
BEGIN
    IF TG_OP = 'UPDATE'
       AND OLD.image_id = NEW.image_id
       AND OLD.wd_tag_id = NEW.wd_tag_id
       AND OLD.score IS NOT DISTINCT FROM NEW.score THEN
        RETURN NULL;
    END IF;

    IF TG_OP = 'INSERT' THEN
        v_image_ids := ARRAY[NEW.image_id];
    ELSIF TG_OP = 'DELETE' THEN
        v_image_ids := ARRAY[OLD.image_id];
    ELSIF OLD.image_id = NEW.image_id THEN
        v_image_ids := ARRAY[NEW.image_id];
    ELSE
        v_image_ids := ARRAY[OLD.image_id, NEW.image_id];
    END IF;

    PERFORM policy_v3_bump_images_and_siblings(v_image_ids, TRUE);
    RETURN NULL;
END;
$$;

-- 5. Renaming a canonical row in `wd_tags`
CREATE OR REPLACE FUNCTION policy_v3_trg_wd_tags_name_upd()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_image_ids BIGINT[];
BEGIN
    SELECT ARRAY(
        SELECT DISTINCT wti.image_id
          FROM wd_tag_images wti
         WHERE wti.wd_tag_id = NEW.id
    ) INTO v_image_ids;

    PERFORM policy_v3_bump_images_and_siblings(v_image_ids, TRUE);
    RETURN NULL;
END;
$$;

-- 6. Attaching/detaching/moving images across posts (`post_images`)
CREATE OR REPLACE FUNCTION policy_v3_trg_post_images()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_image_ids BIGINT[];
    v_post_ids  BIGINT[];
BEGIN
    IF TG_OP = 'UPDATE'
       AND OLD.post_id = NEW.post_id
       AND OLD.image_id = NEW.image_id THEN
        RETURN NULL;
    END IF;

    IF TG_OP = 'INSERT' THEN
        v_image_ids := ARRAY[NEW.image_id];
        v_post_ids  := ARRAY[NEW.post_id];
    ELSIF TG_OP = 'DELETE' THEN
        v_image_ids := ARRAY[OLD.image_id];
        v_post_ids  := ARRAY[OLD.post_id];
    ELSE
        v_image_ids := CASE
            WHEN OLD.image_id = NEW.image_id THEN ARRAY[NEW.image_id]
            ELSE ARRAY[OLD.image_id, NEW.image_id]
        END;
        v_post_ids := CASE
            WHEN OLD.post_id = NEW.post_id THEN ARRAY[NEW.post_id]
            ELSE ARRAY[OLD.post_id, NEW.post_id]
        END;
    END IF;

    UPDATE images
       SET facts_rev = facts_rev + 1
     WHERE id = ANY(v_image_ids);

    UPDATE posts
       SET facts_rev = facts_rev + 1
     WHERE id = ANY(v_post_ids);

    UPDATE videos
       SET facts_rev = facts_rev + 1
     WHERE id IN (
         SELECT DISTINCT pv.video_id
           FROM post_videos pv
          WHERE pv.post_id = ANY(v_post_ids)
     );

    RETURN NULL;
END;
$$;

-- 7. Attaching/detaching/moving videos across posts (`post_videos`)
CREATE OR REPLACE FUNCTION policy_v3_trg_post_videos()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_video_ids BIGINT[];
    v_post_ids  BIGINT[];
BEGIN
    IF TG_OP = 'UPDATE'
       AND OLD.post_id = NEW.post_id
       AND OLD.video_id = NEW.video_id THEN
        RETURN NULL;
    END IF;

    IF TG_OP = 'INSERT' THEN
        v_video_ids := ARRAY[NEW.video_id];
        v_post_ids  := ARRAY[NEW.post_id];
    ELSIF TG_OP = 'DELETE' THEN
        v_video_ids := ARRAY[OLD.video_id];
        v_post_ids  := ARRAY[OLD.post_id];
    ELSE
        v_video_ids := CASE
            WHEN OLD.video_id = NEW.video_id THEN ARRAY[NEW.video_id]
            ELSE ARRAY[OLD.video_id, NEW.video_id]
        END;
        v_post_ids := CASE
            WHEN OLD.post_id = NEW.post_id THEN ARRAY[NEW.post_id]
            ELSE ARRAY[OLD.post_id, NEW.post_id]
        END;
    END IF;

    UPDATE videos
       SET facts_rev = facts_rev + 1
     WHERE id = ANY(v_video_ids);

    UPDATE posts
       SET facts_rev = facts_rev + 1
     WHERE id = ANY(v_post_ids);

    RETURN NULL;
END;
$$;

-- 8. Post tags (`tag_posts` & `tags.name`)
CREATE OR REPLACE FUNCTION policy_v3_trg_tag_posts()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_post_ids BIGINT[];
BEGIN
    IF TG_OP = 'UPDATE'
       AND OLD.post_id = NEW.post_id
       AND OLD.tag_id = NEW.tag_id THEN
        RETURN NULL;
    END IF;

    IF TG_OP = 'INSERT' THEN
        v_post_ids := ARRAY[NEW.post_id];
    ELSIF TG_OP = 'DELETE' THEN
        v_post_ids := ARRAY[OLD.post_id];
    ELSIF OLD.post_id = NEW.post_id THEN
        v_post_ids := ARRAY[NEW.post_id];
    ELSE
        v_post_ids := ARRAY[OLD.post_id, NEW.post_id];
    END IF;

    PERFORM policy_v3_bump_posts_and_media(v_post_ids);
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION policy_v3_trg_tags_name_upd()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_post_ids BIGINT[];
BEGIN
    SELECT ARRAY(
        SELECT DISTINCT tp.post_id
          FROM tag_posts tp
         WHERE tp.tag_id = NEW.id
    ) INTO v_post_ids;

    PERFORM policy_v3_bump_posts_and_media(v_post_ids);
    RETURN NULL;
END;
$$;

-- 9. Post authors (`author_posts` & `authors.name`)
CREATE OR REPLACE FUNCTION policy_v3_trg_author_posts()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_post_ids BIGINT[];
BEGIN
    IF TG_OP = 'UPDATE'
       AND OLD.post_id = NEW.post_id
       AND OLD.author_id = NEW.author_id THEN
        RETURN NULL;
    END IF;

    IF TG_OP = 'INSERT' THEN
        v_post_ids := ARRAY[NEW.post_id];
    ELSIF TG_OP = 'DELETE' THEN
        v_post_ids := ARRAY[OLD.post_id];
    ELSIF OLD.post_id = NEW.post_id THEN
        v_post_ids := ARRAY[NEW.post_id];
    ELSE
        v_post_ids := ARRAY[OLD.post_id, NEW.post_id];
    END IF;

    PERFORM policy_v3_bump_posts_and_media(v_post_ids);
    RETURN NULL;
END;
$$;

CREATE OR REPLACE FUNCTION policy_v3_trg_authors_name_upd()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    v_post_ids BIGINT[];
BEGIN
    SELECT ARRAY(
        SELECT DISTINCT ap.post_id
          FROM author_posts ap
         WHERE ap.author_id = NEW.id
    ) INTO v_post_ids;

    PERFORM policy_v3_bump_posts_and_media(v_post_ids);
    RETURN NULL;
END;
$$;

-- ---------------------------------------------------------------------------
-- Attach Triggers
-- ---------------------------------------------------------------------------

DROP TRIGGER IF EXISTS trg_images_facts_rev_before_upd ON images;
CREATE TRIGGER trg_images_facts_rev_before_upd
    BEFORE UPDATE ON images
    FOR EACH ROW
    WHEN (
        OLD.name IS DISTINCT FROM NEW.name
        OR OLD.status IS DISTINCT FROM NEW.status
        OR OLD.wd_min_persisted_score IS DISTINCT FROM NEW.wd_min_persisted_score
        OR OLD.wd_vocab_digest IS DISTINCT FROM NEW.wd_vocab_digest
    )
    EXECUTE FUNCTION policy_v3_trg_images_before_upd();

DROP TRIGGER IF EXISTS trg_images_facts_rev_after_upd ON images;
CREATE TRIGGER trg_images_facts_rev_after_upd
    AFTER UPDATE ON images
    FOR EACH ROW
    WHEN (
        OLD.name IS DISTINCT FROM NEW.name
        OR OLD.status IS DISTINCT FROM NEW.status
        OR OLD.wd_min_persisted_score IS DISTINCT FROM NEW.wd_min_persisted_score
        OR OLD.wd_vocab_digest IS DISTINCT FROM NEW.wd_vocab_digest
    )
    EXECUTE FUNCTION policy_v3_trg_images_after_upd();

DROP TRIGGER IF EXISTS trg_videos_facts_rev_before_upd ON videos;
CREATE TRIGGER trg_videos_facts_rev_before_upd
    BEFORE UPDATE ON videos
    FOR EACH ROW
    WHEN (OLD.name IS DISTINCT FROM NEW.name)
    EXECUTE FUNCTION policy_v3_trg_videos_before_upd();

DROP TRIGGER IF EXISTS trg_videos_facts_rev_after_upd ON videos;
CREATE TRIGGER trg_videos_facts_rev_after_upd
    AFTER UPDATE ON videos
    FOR EACH ROW
    WHEN (OLD.name IS DISTINCT FROM NEW.name)
    EXECUTE FUNCTION policy_v3_trg_videos_after_upd();

DROP TRIGGER IF EXISTS trg_posts_facts_rev_before_upd ON posts;
CREATE TRIGGER trg_posts_facts_rev_before_upd
    BEFORE UPDATE ON posts
    FOR EACH ROW
    WHEN (OLD.title IS DISTINCT FROM NEW.title)
    EXECUTE FUNCTION policy_v3_trg_posts_before_upd();

DROP TRIGGER IF EXISTS trg_wd_tag_images_facts_rev ON wd_tag_images;
CREATE TRIGGER trg_wd_tag_images_facts_rev
    AFTER INSERT OR UPDATE OR DELETE ON wd_tag_images
    FOR EACH ROW
    EXECUTE FUNCTION policy_v3_trg_wd_tag_images();

DROP TRIGGER IF EXISTS trg_wd_tags_name_facts_rev ON wd_tags;
CREATE TRIGGER trg_wd_tags_name_facts_rev
    AFTER UPDATE OF name ON wd_tags
    FOR EACH ROW
    WHEN (OLD.name IS DISTINCT FROM NEW.name)
    EXECUTE FUNCTION policy_v3_trg_wd_tags_name_upd();

DROP TRIGGER IF EXISTS trg_post_images_facts_rev ON post_images;
CREATE TRIGGER trg_post_images_facts_rev
    AFTER INSERT OR UPDATE OR DELETE ON post_images
    FOR EACH ROW
    EXECUTE FUNCTION policy_v3_trg_post_images();

DROP TRIGGER IF EXISTS trg_post_videos_facts_rev ON post_videos;
CREATE TRIGGER trg_post_videos_facts_rev
    AFTER INSERT OR UPDATE OR DELETE ON post_videos
    FOR EACH ROW
    EXECUTE FUNCTION policy_v3_trg_post_videos();

DROP TRIGGER IF EXISTS trg_tag_posts_facts_rev ON tag_posts;
CREATE TRIGGER trg_tag_posts_facts_rev
    AFTER INSERT OR UPDATE OR DELETE ON tag_posts
    FOR EACH ROW
    EXECUTE FUNCTION policy_v3_trg_tag_posts();

DROP TRIGGER IF EXISTS trg_tags_name_facts_rev ON tags;
CREATE TRIGGER trg_tags_name_facts_rev
    AFTER UPDATE OF name ON tags
    FOR EACH ROW
    WHEN (OLD.name IS DISTINCT FROM NEW.name)
    EXECUTE FUNCTION policy_v3_trg_tags_name_upd();

DROP TRIGGER IF EXISTS trg_author_posts_facts_rev ON author_posts;
CREATE TRIGGER trg_author_posts_facts_rev
    AFTER INSERT OR UPDATE OR DELETE ON author_posts
    FOR EACH ROW
    EXECUTE FUNCTION policy_v3_trg_author_posts();

DROP TRIGGER IF EXISTS trg_authors_name_facts_rev ON authors;
CREATE TRIGGER trg_authors_name_facts_rev
    AFTER UPDATE OF name ON authors
    FOR EACH ROW
    WHEN (OLD.name IS DISTINCT FROM NEW.name)
    EXECUTE FUNCTION policy_v3_trg_authors_name_upd();
