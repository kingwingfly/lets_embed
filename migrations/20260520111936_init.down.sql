-- wd_tags
DROP INDEX idx_wd_tag_images_score;
DROP INDEX idx_image_wd_tags_image_id;
DROP INDEX idx_wd_tags_name;
DROP TABLE wd_tag_images;
DROP TABLE wd_tags;

-- tags
DROP INDEX idx_tag_posts_post_id;
DROP INDEX idx_tags_name;
DROP TABLE tag_posts;
DROP TABLE tags;

-- authors
DROP INDEX idx_author_posts_post_id;
DROP INDEX idx_authors_name;
DROP TABLE author_posts;
DROP TABLE authors;

-- images
DROP INDEX idx_post_images_image_id;
DROP INDEX idx_images_clip;
DROP INDEX idx_images_dinov3;
DROP INDEX idx_images_status;
DROP INDEX idx_images_name;
DROP TABLE post_images;
DROP TABLE images;

-- posts
DROP INDEX idx_posts_title;
DROP TABLE posts;
DROP INDEX idx_posts_title;

DROP TYPE meta;
DROP TYPE process_status;

DROP EXTENSION vector;
