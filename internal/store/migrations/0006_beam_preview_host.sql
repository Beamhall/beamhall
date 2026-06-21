-- A preview beam keeps a STABLE hostname across redeploys (good DX while a
-- developer iterates), and only rotates it on pause -> resume (the security
-- property: a leaked/idle preview URL stops working). Empty until the first
-- preview deploy assigns it.
ALTER TABLE beams ADD COLUMN preview_host TEXT NOT NULL DEFAULT '';
