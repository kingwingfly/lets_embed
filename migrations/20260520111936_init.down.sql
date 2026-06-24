-- wd_tag translations
DROP INDEX IF EXISTS idx_wd_tag_translations_translation_trgm;
DROP TABLE IF EXISTS wd_tag_translations;

-- wd_tags
DROP INDEX IF EXISTS idx_wd_tag_images_score;
DROP INDEX IF EXISTS idx_image_wd_tags_image_id;
DROP INDEX IF EXISTS idx_wd_tags_name_trgm;
DROP TABLE IF EXISTS wd_tag_images;
DROP TABLE IF EXISTS wd_tags;

-- tags
DROP INDEX IF EXISTS idx_tag_posts_post_id;
DROP INDEX IF EXISTS idx_tags_name_trgm;
DROP TABLE IF EXISTS tag_posts;
DROP TABLE IF EXISTS tags;

-- authors
DROP INDEX IF EXISTS idx_author_posts_post_id;
DROP INDEX IF EXISTS idx_authors_name_trgm;
DROP TABLE IF EXISTS author_posts;
DROP TABLE IF EXISTS authors;

-- images
DROP INDEX IF EXISTS idx_post_images_image_id;
DROP INDEX IF EXISTS idx_images_clip;
DROP INDEX IF EXISTS idx_images_dinov3;
DROP INDEX IF EXISTS idx_images_status;
DROP INDEX IF EXISTS idx_images_name_trgm;
DROP TABLE IF EXISTS post_images;
DROP TABLE IF EXISTS images;

-- posts
DROP INDEX IF EXISTS idx_posts_title_trgm;
DROP TABLE IF EXISTS posts;

DROP TYPE IF EXISTS translation;
DROP TYPE IF EXISTS meta;
DROP TYPE IF EXISTS image;
DROP TYPE IF EXISTS process_status;

DROP EXTENSION IF EXISTS pg_trgm;
DROP EXTENSION IF EXISTS vector;
