-- M10 S3c: where a vault's files land becomes the server's fact, not a
-- question every client asks its human.
--
-- The location is a path *relative to each client's home directory*
-- ("Syncbox/Family Photos"), so one vault works on a laptop, a desktop and a
-- NAS with different home dirs; a `~`-prefixed or absolute value is used as
-- typed, for single-machine setups. It is set once when the vault is created
-- (defaulting to the vault's own name) and editable on the vault's card. The
-- server refuses a location another live vault already claims, because two
-- vaults writing the same folder would shred each other's index.
--
-- Rule 1 of the initial schema still holds: a location is operator-typed
-- metadata ("Photos", "Work"), never derived from anything a key is needed
-- to read.
ALTER TABLE vault ADD COLUMN location TEXT NOT NULL DEFAULT '';

-- Adopt the vault's name as the default location for existing vaults whose
-- name is unique. A name two vaults share is left without a location rather
-- than pointing both at one folder; the operator picks distinct ones in the
-- console.
UPDATE vault
SET location = name
WHERE name <> ''
  AND (SELECT COUNT(*) FROM vault AS other WHERE other.name = vault.name) = 1;
