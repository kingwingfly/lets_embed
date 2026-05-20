-- wd_tags
DROP INDEX idx_wd_tag_images_score;
DROP INDEX idx_image_wd_tags_image_id;
DROP TABLE wd_tag_images;
DROP TABLE wd_tags;

-- tags
DROP INDEX idx_tag_posts_post_id;
DROP TABLE tag_posts;
DROP TABLE tags;

-- authors
DROP INDEX idx_author_posts_post_id;
DROP TABLE author_posts;
DROP TABLE authors;

-- images
DROP INDEX idx_post_images_image_id;
DROP TABLE post_images;
DROP INDEX idx_images_clip;
DROP INDEX idx_images_dinov3;
DROP INDEX idx_images_status;
DROP TABLE images;

-- posts
DROP TABLE posts;
DROP INDEX idx_posts_title;

DROP TYPE meta;
DROP TYPE process_status;

DROP EXTENSION vector;
