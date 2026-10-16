# Server-side backups

The server holds the only copy of everyone's data, so taking snapshots of it is not an
optional feature. This document describes what `server/internal/backup` does; the code
and this file are written together.

## What a snapshot is

A snapshot is **self-contained**: a consistent copy of the bookkeeping plus every
chunk the server held at that moment. Restoring one needs nothing else. It stays
ciphertext the whole way — the backup path never touches a key, so a stolen backup is
no more readable than a stolen server.

Layout inside the target:

```text
snapshots/
  2026-10-16T030000Z-a1b2c3d4/
    metadata.json      # chunks, vaults, revisions — never chunk bodies
    chunks/
      ABCDEFGHIJKLMNOP # every chunk, copied at snapshot time
    manifest.json      # written LAST, and it seals the directory
```

The manifest is what makes a snapshot a snapshot:

```json
{
  "version": 1,
  "id": "2026-10-16T030000Z-a1b2c3d4",
  "created_at": "2026-10-16T03:00:00Z",
  "server_version": "0.1.0",
  "metadata_bytes": 4128,
  "metadata_sha256": "…",
  "chunk_bytes": 10485760,
  "chunks": [ { "id": "ABCDEFGHIJKLMNOP", "size": 65536, "sha256": "…" } ],
  "policy": { "hourly": 24, "daily": 7, "weekly": 8, "monthly": 12 }
}
```

Three properties follow from that layout, and they are the reason it is arranged this
way:

- **A directory without a manifest is not a snapshot.** A crash mid-write leaves a
  half-written bundle that `List` skips rather than offering for restore.
- **Everything is checksummed as it is written**, so `verify` can prove a snapshot was
  not quietly damaged afterwards, rather than discovering it during the restore you
  needed.
- **The snapshot directory is sealed** when the manifest lands.

## Immutability, honestly

`target.ReadOnly` is the hook that makes a backup survive the server being compromised:
after sealing, the server process cannot rewrite or delete the bundle.

On the local filesystem that means mode `0550`/`0440`, owned by the backup identity.
That stops the server process and stops accidents. **It does not stop root.** Object
storage with object lock — a later milestone — is what makes the guarantee real,
because there the lock is honoured by the service rather than by a permission bit.

This is stated rather than glossed so nobody deploys a local target believing they have
WORM storage.

## Taking one

```sh
# on a schedule, automatically
SYNCBOX_BACKUP_TARGET=/mnt/nas/snapshots
SYNCBOX_BACKUP_SCHEDULE=1h

# or on demand, against a running server
syncboxd backup -url http://127.0.0.1:8080 -token "$SYNCBOX_TOKEN"

# or through the API
curl -X POST -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8080/admin/backups

# or from any machine holding the client
syncbox backup now --server https://sync.example
```

`syncboxd backup` is a client of the running server rather than a direct call, because
the store being snapshotted is the one the server holds. That is also what lets cron
trigger a backup through a localhost socket without the CLI opening the data files.

On a schedule the server also prunes, so retention is not a second job someone has to
remember.

## Retention

A grandfather/father/son ladder, configured as counts:

| Tier | Kept |
| --- | --- |
| `hourly` | the newest N snapshots, overall |
| `daily` | the newest snapshot in each of the N most recent days |
| `weekly` | the newest snapshot in each of the N most recent ISO weeks |
| `monthly` | the newest snapshot in each of the N most recent months |

A snapshot survives if any tier claims it. The newest snapshot of a day is also the
newest snapshot overall, and both tiers want exactly that one, so claiming it for one
reason does not stop the other. A zero turns a tier off.

Default: `24 / 7 / 8 / 12` — about a day of hourly detail, a week of daily, two months
of weekly, and a year of monthly.

`Prune` is a pure function over the snapshot list, so a schedule can be reasoned about
and tested without touching a filesystem.

## Verifying a snapshot

An unverified backup is a hope, not a backup. Verification re-reads every object on
the target and re-hashes it against the checksums the manifest recorded when it was
written, so a silently damaged chunk is found now rather than during the restore that
needed it.

```sh
syncbox backup list   --server https://sync.example
syncbox backup verify 2026-10-16T030000Z-a1b2c3d4 --server https://sync.example
```

It is an admin API call (`POST /admin/backups/{id}/verify`), so it runs wherever the
server runs and the target is opened by the server, not by a laptop holding the
target's credentials. The answer is either the numbers it just re-checked — chunks,
bytes, the metadata hash — or a refusal: `corrupt_snapshot` says something on the
target changed after the seal, `incomplete_snapshot` says the bundle was never
finished. Snapshots taken on the schedule are never re-read by anything, so
verification is deliberately a thing an operator (or a cron job) does.

## Restoring

Offline, whole server:

```sh
systemctl stop syncboxd            # or: docker compose stop
syncboxd restore -snapshot 2026-10-16T030000Z-a1b2c3d4 \
                 -target /mnt/nas/snapshots \
                 -to /srv/syncbox/data
systemctl start syncboxd
```

`restore` verifies every checksum in the manifest before writing a single byte, and it
refuses a destination that already contains a `metadata.json`. Silently replacing live
data is the one thing a restore must not do.

What it writes — `metadata.json` plus `chunks/` — is exactly the server's own data
directory layout. Point `SYNCBOX_DATA_DIR` at the restored directory and the server
adopts it on start: a fresh database beside a `metadata.json` is imported into SQLite
and the file renamed aside. So an offline restore is directly runnable — there is no
separate "load" step to write.

The same operation exists over the admin API, for when the server is reachable but a
shell on the machine holding the target is not:

```sh
syncbox backup restore 2026-10-16T030000Z-a1b2c3d4 \
                       --server https://sync.example \
                       --dest /srv/syncbox/restored
```

The server verifies before it copies, writes a directly-runnable data directory into
`--dest`, and refuses a `--dest` that already holds a restore (`restore_target_occupied`).
The drill then completes where only a drill can: start a second server pointed at the
restored directory (`SYNCBOX_DATA_DIR=/srv/syncbox/restored`), let a client sync
against it, and open a few files — proving the backup can serve, not just that bytes
hash right.

Restoring *into a running server as a separate vault* — so a user can pull yesterday's
version down without anyone going offline — is still deferred. That needs an online
import into a live store, which is a different operation from the offline whole-server
restore above.

## Retiring a snapshot

Retention calls `target.RemoveAll`, which clears the seal before deleting. That path is
the maintenance path: the running server never deletes a snapshot to make room, which
is what a ransomware encryptor would want it to do.

## Limits of the current implementation

- **Snapshots are full, not incremental — on purpose.** A snapshot has to be
  self-contained and independent of the live store, because the guarantee that matters
  is that it survives the server that made it being deleted, corrupted, or compromised.
  Hard links would share an inode with the running server's chunks, so the server could
  still rewrite "its own" backup through that inode, and retention's `RemoveAll` does a
  chmod walk that would quietly un-seal any *other* snapshot sharing the same chunk. The
  layout keeps `chunks/` separate so a size-vs-safety tradeoff (copy-on-write on a
  WORM target, or a separate incremental pass) can be added with the space hardening in
  M7 — but it is a tradeoff, not a free win, and it is not the default here.
- **A backup on the same host as the server** survives deleted files and a broken
  install. It does not survive a dead disk. The target is meant to be a NAS or a second
  disk.
