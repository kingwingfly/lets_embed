-- Narrow `images` facts_rev triggers so non-completed status transitions
-- (`pending <-> processing` worker claims and failure resets) do not lock
-- parent `posts` / sibling `videos` or spuriously bump `facts_rev` (Cycle 4 I5).

DROP TRIGGER IF EXISTS trg_images_facts_rev_before_upd ON images;
CREATE TRIGGER trg_images_facts_rev_before_upd
    BEFORE UPDATE ON images
    FOR EACH ROW
    WHEN (
        OLD.name IS DISTINCT FROM NEW.name
        OR (OLD.status = 'completed'::process_status) IS DISTINCT FROM (NEW.status = 'completed'::process_status)
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
        OR (OLD.status = 'completed'::process_status) IS DISTINCT FROM (NEW.status = 'completed'::process_status)
        OR OLD.wd_min_persisted_score IS DISTINCT FROM NEW.wd_min_persisted_score
        OR OLD.wd_vocab_digest IS DISTINCT FROM NEW.wd_vocab_digest
    )
    EXECUTE FUNCTION policy_v3_trg_images_after_upd();
