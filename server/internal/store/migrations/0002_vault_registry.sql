-- M10 S1: the vault becomes a server-side fact an operator sets up, rather
-- than a namespace a client invents silently.
--
-- Every vault that has ever been committed already has a row here (commits
-- upsert it), so adopting existing vaults is a column change, not a backfill:
-- they appear in the registry nameless and unarchived, and the console lets
-- the operator name them.
--
-- Rule 1 of the initial schema still holds — nothing here needs a key to
-- read. `name` is operator-typed metadata ("Photos", "Work"), never derived
-- from user data, and the archived flag is bookkeeping.

ALTER TABLE vault ADD COLUMN name TEXT NOT NULL DEFAULT '';
ALTER TABLE vault ADD COLUMN archived_at INTEGER;
