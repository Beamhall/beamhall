-- Audit retention with integrity. The audit chain is append-only, so old events
-- can't simply be deleted without breaking Verify (the first survivor's
-- prev_hash would point at a removed row). A prune therefore records a
-- checkpoint: the seq it pruned through and the chain hash at that point
-- (anchor_hash). Verify resumes from the latest checkpoint instead of genesis,
-- so the surviving chain stays tamper-evident AND any deletion NOT recorded by a
-- checkpoint still trips Verify's seq-gap / prev_hash checks. The checkpoint row
-- also makes each prune itself auditable (when, who, how many).
CREATE TABLE audit_checkpoints (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    through_seq  INTEGER NOT NULL, -- every audit_events row with seq <= this was pruned
    anchor_hash  TEXT NOT NULL,    -- hash of the event formerly at through_seq (chain value at the cut)
    pruned_count INTEGER NOT NULL,
    at           INTEGER NOT NULL,
    pruned_by    TEXT NOT NULL
);
CREATE INDEX audit_checkpoints_through ON audit_checkpoints (through_seq);
