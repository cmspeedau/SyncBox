-- M11 S1: a space gets a mode. A `sync` space is stored in the clear
-- server-side, so the server can index, browse and share it; a `vault` is
-- encrypted on the client, so the server holds only an opaque blob and never a
-- key. It is one column, not a second product: the commit protocol, the chunk
-- store and the registry read the same whichever a space is.
--
-- Existing rows become `vault`. Every space that exists today was encrypted —
-- that was the only kind there was — so the column default, and the backfill
-- that does not rely on it, both say `vault`. New *registrations* default to
-- `sync` (decided in CreateVault, not in the schema); a space born of a commit
-- nothing registered also stays `vault`, so the server keeps claiming it cannot
-- read data it was never handed in the clear.
--
-- Rule 1 of the initial schema now holds per mode rather than for the whole
-- store: a vault's columns are ciphertext the server only compares for
-- equality; a sync space's columns are cleartext paths and bytes the server may
-- read, index and serve.
ALTER TABLE vault ADD COLUMN mode TEXT NOT NULL DEFAULT 'vault';

-- Explicit backfill: an ALTER ... DEFAULT already stamps existing rows, but
-- saying it makes the intent legible and survives a future default change.
UPDATE vault SET mode = 'vault';
