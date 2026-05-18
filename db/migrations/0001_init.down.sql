-- wd_tags
DROP INDEX idx_wd_tag_images_score;
DROP INDEX idx_image_wd_tags_image_id;
DROP TABLE wd_tag_images;
DROP TABLE wd_tags;

-- tags
DROP INDEX idx_tag_titles_title_id;
DROP TABLE tag_titles;
DROP TABLE tags;

-- authors
DROP INDEX idx_author_titles_title_id;
DROP TABLE author_titles;
DROP TABLE authors;

-- titles
DROP INDEX idx_title_images_image_id;
DROP TABLE title_images;
DROP INDEX idx_images_clip;
DROP INDEX idx_images_dinov3;
DROP TABLE images;

-- images
DROP TABLE titles;

DROP TYPE meta;
DROP TYPE process_status;

DROP EXTENSION vector;
