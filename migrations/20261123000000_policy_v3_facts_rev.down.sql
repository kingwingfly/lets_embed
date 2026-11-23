-- Rollback Policy v3 `facts_rev` triggers and coverage columns.

DROP TRIGGER IF EXISTS trg_authors_name_facts_rev ON authors;
DROP TRIGGER IF EXISTS trg_author_posts_facts_rev ON author_posts;
DROP TRIGGER IF EXISTS trg_tags_name_facts_rev ON tags;
DROP TRIGGER IF EXISTS trg_tag_posts_facts_rev ON tag_posts;
DROP TRIGGER IF EXISTS trg_post_videos_facts_rev ON post_videos;
DROP TRIGGER IF EXISTS trg_post_images_facts_rev ON post_images;
DROP TRIGGER IF EXISTS trg_wd_tags_name_facts_rev ON wd_tags;
DROP TRIGGER IF EXISTS trg_wd_tag_images_facts_rev ON wd_tag_images;
DROP TRIGGER IF EXISTS trg_posts_facts_rev_before_upd ON posts;
DROP TRIGGER IF EXISTS trg_videos_facts_rev_after_upd ON videos;
DROP TRIGGER IF EXISTS trg_videos_facts_rev_before_upd ON videos;
DROP TRIGGER IF EXISTS trg_images_facts_rev_after_upd ON images;
DROP TRIGGER IF EXISTS trg_images_facts_rev_before_upd ON images;

DROP FUNCTION IF EXISTS policy_v3_trg_authors_name_upd();
DROP FUNCTION IF EXISTS policy_v3_trg_author_posts();
DROP FUNCTION IF EXISTS policy_v3_trg_tags_name_upd();
DROP FUNCTION IF EXISTS policy_v3_trg_tag_posts();
DROP FUNCTION IF EXISTS policy_v3_trg_post_videos();
DROP FUNCTION IF EXISTS policy_v3_trg_post_images();
DROP FUNCTION IF EXISTS policy_v3_trg_wd_tags_name_upd();
DROP FUNCTION IF EXISTS policy_v3_trg_wd_tag_images();
DROP FUNCTION IF EXISTS policy_v3_trg_posts_before_upd();
DROP FUNCTION IF EXISTS policy_v3_trg_videos_after_upd();
DROP FUNCTION IF EXISTS policy_v3_trg_videos_before_upd();
DROP FUNCTION IF EXISTS policy_v3_trg_images_after_upd();
DROP FUNCTION IF EXISTS policy_v3_trg_images_before_upd();
DROP FUNCTION IF EXISTS policy_v3_bump_images_and_siblings(BIGINT[], BOOLEAN);
DROP FUNCTION IF EXISTS policy_v3_bump_posts_and_media(BIGINT[]);

ALTER TABLE videos
    DROP COLUMN IF EXISTS facts_rev;

ALTER TABLE images
    DROP CONSTRAINT IF EXISTS chk_images_wd_min_persisted_score,
    DROP COLUMN IF EXISTS wd_vocab_digest,
    DROP COLUMN IF EXISTS wd_min_persisted_score,
    DROP COLUMN IF EXISTS facts_rev;

ALTER TABLE posts
    DROP COLUMN IF EXISTS facts_rev;
