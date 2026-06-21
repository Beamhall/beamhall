-- 0003_release_workload.sql — persist the runtime workload handle on releases.
--
-- A deployed Release owns at most one workload (container/pod/vm); the
-- orchestrator needs the driver handle back after a restart to pause, stop,
-- or destroy it. Superseded releases keep their last handle as history; it is
-- stale once that workload is destroyed.

ALTER TABLE releases ADD COLUMN handle_driver TEXT NOT NULL DEFAULT '';
ALTER TABLE releases ADD COLUMN handle_ref    TEXT NOT NULL DEFAULT '';
