# The Syncbox sync protocol

Version 1, over HTTPS. This is the contract between `client/crates/transport` and
`server/internal/api`; both sides are written from this file.

Status: implemented on the server against the durable SQLite + filesystem store, and
on the Rust client (`client/crates/transport` over an `Http` seam, driven by
`client/crates/sync`). The two have been run against each other end to end: a folder
is pushed from one client and pulled, byte for byte, by a second, including edits,
deletions, and nested directories.

## What the server is

A store of chunks and a ledger of revisions. It never holds a key and never
decrypts anything, so the useful mental model is "a content-addressed blob store with
a per-file version log bolted on".

Since M11 a space has a **mode**, and it decides what a chunk and a `dir_id` /
`cipher_name` actually are:

| Mode | Stored as | The server |
| --- | --- | --- |
| `vault` | ciphertext — names and bytes encrypted on the client | stores and serves it opaquely; never reads a name or a byte |
| `sync` | cleartext — names, paths and bytes as the client sees them | may index, browse, serve and share it; TLS protects it in flight and the operator's disk protects it at rest |

That is the whole of the encryption promise, stated once: **only a vault is
encrypted.** A sync space is trusted to the server on purpose, which is what lets it
do the things the vault-era sections below say it cannot. Those sections describe the
`vault` case; the table there is true of a vault and deliberately not of a sync
space:

| The server can see | The server cannot see |
| --- | --- |
| Chunk ids and sizes | Keys, and therefore any plaintext |
| Revision numbers and parentage | Real filenames or the folder tree |
| Plaintext file size and mtime | What a manifest says |
| When a vault was written to | Which vault belongs to whom |

Two honest consequences of sync mode, recorded rather than discovered: the **backup
target becomes a sensitive location** (a sync space's snapshot is readable to whoever
holds it), and the server **sees names, sizes and mtimes** — the metadata a vault
deliberately withholds, and exactly what makes indexing, browsing and search possible
(S3). Fine on your own box; not private metadata.

## Authentication

Single-user for v1. One password buys a bearer token.

```
POST /api/v1/auth/token
     { "password": "..." }
 →   { "token": "<opaque>", "expires_unix": 1760000000 }
```

Send it back as `Authorization: Bearer <token>`. The token is a base64url claim set
with an HMAC-SHA256 over it, signed with `SYNCBOX_TOKEN_SECRET`; there is no session
table, so a restarted server keeps accepting tokens as long as that secret is stable.

`/healthz` is the only route that needs no token.

## Errors

Every non-2xx response has the same body:

```json
{ "code": "conflict", "reason": "vault x is at revision 4, client committed against 3" }
```

| Status | `code` | Client should |
| --- | --- | --- |
| 400 | `bad_request`, `bad_chunk_id`, `invalid_request`, `unreadable_manifest` | Bug or bad input; do not retry |
| 401 | `unauthorized` | Re-authenticate, then retry once. A refused share link says this too, and re-authenticating does not help |
| 403 | `unknown_vault`, `not_browsable`, `not_shareable`, `not_recyclable` | Off-limits on purpose. A space registered as a `vault` has no browsable files, nothing to share and no recycle bin; do not retry |
| 404 | `not_found`, `incomplete_snapshot` | Chunk collected, vault unknown, or a half-written snapshot |
| 409 | `conflict`, `restore_target_occupied` | Someone else committed. Re-fetch, keep both copies |
| 413 | `too_large` | Chunk exceeds the server's limit |
| 429 | `rate_limited` | Wait `Retry-After` seconds. Chunk transfers retry this themselves |
| 501 | `not_configured` | Feature off on this server (backups with no target) |
| 500 | `internal`, `corrupt_snapshot` | Back off and report |

Codes are the interface. Statuses are for humans reading a log.

## Chunks

Chunks are addressed by id, scoped to a vault. `PUT` is idempotent: the id is a
content address, so storing the same id twice is a no-op that reports zero new bytes.

```
POST /api/v1/vaults/{vaultID}/chunks/exists
     { "ids": ["ABCDEFGHIJKLMNOP", ...] }
 →   { "missing": ["ABCDEFGHIJKLMNOP", ...] }

HEAD /api/v1/vaults/{vaultID}/chunks/{chunkID}     → 200 + Content-Length, or 404
PUT  /api/v1/vaults/{vaultID}/chunks/{chunkID}     body: raw bytes → 201 { "stored": N }
GET  /api/v1/vaults/{vaultID}/chunks/{chunkID}     → raw bytes
```

Chunk ids are validated server-side as alphanumeric strings of 8–128 characters. The
server cannot check an id against a chunk's content — it has no key — but refusing
anything not shaped like a content address keeps path traversal and odd filenames out
of the blob store.

## Revisions

A revision is one committed state of one file. The client owns the plaintext path; the
server only ever sees `dir_id` and `cipher_name`, and only compares them for equality.
In a vault those two are ciphertext; in a sync space they are the cleartext path, and
while this route still only compares them, the browse and share surfaces (S3) read
them as paths — which is the point of the mode.

The same split runs through the rest of a revision. A vault's `manifest` is an
authenticated, encrypted chunk list and its chunk bodies are sealed, so the server can
size them but not read them; a sync space's `manifest` is the same chunk list in a
small cleartext record (`SBXSYNC1 || size || count || (stored_len, id)*`, spelled out in
[Browsing, sharing and the recycle bin](#browsing-sharing-and-the-recycle-bin)) and its
chunk bodies are the file's own bytes. The server stores both forms verbatim, and reads a
sync one only when it is handing a shared file back in order to find its chunks. It
never parses a vault's, and could not.

```
POST /api/v1/vaults/{vaultID}/revisions
     {
       "parent": 3,
       "revision": {
         "revision": 0,
         "parent": 3,
         "dir_id": "ABCDEFGHIJ",
         "cipher_name": "KLMNOPQRST",
         "manifest": "<base64 of the encrypted chunk list>",
         "size": 1048576,
         "modified_unix": 1760000000,
         "deleted": false
       }
     }
 →   201 { "revision": 4 }

GET  /api/v1/vaults/{vaultID}/revisions?since=4&limit=500
 →   { "revisions": [ ... ], "upto": 4 }
```

`revision.vault_id` is ignored: the URL path decides the vault, so a request cannot
write into someone else's history by naming it in the body. `revision.revision` is
assigned by the server and ignored on the way in.

`size` is plaintext on purpose. A client cannot allocate or show progress without it,
and this is one of the two leaks the design accepts — the other is `modified_unix`.

### Conflict rule

A commit names the revision it was derived from. If that is not the vault's current
head, the server answers `409 conflict` and changes nothing.

The client's response to a 409 is the important part: it re-fetches the head, keeps
the server's version, and writes its own next to it as

```
notes.txt  →  notes (conflicted copy 2026-10-16).txt
```

Both edits survive. There is no merge that is safe to perform silently on arbitrary
bytes, so Syncbox does not pretend otherwise.

### Tombstones

A deletion is not the absence of a revision; it is a revision with `"deleted": true`
committed against the current head. Because the log is ordered, the highest-numbered
revision for a `(dir_id, cipher_name)` is that file's current state, whether it is
content or a tombstone. A client applying the log therefore either writes the file
(content) or removes it (tombstone), and a file it has never seen can be skipped
rather than resurrected.

A tombstone carries no manifest. The client sends `""`, the Go server stores a nil
`[]byte`, and `encoding/json` writes a nil byte slice as `null` — so a tombstone comes
back over the wire as `"manifest": null`. Both sides treat `null`, `""`, and an absent
field as the same empty manifest; the Rust client pins this with a test so a future
Go or Rust change that makes them differ is caught.

## A full upload, in order

1. Read the vault's revision log and apply anything newer than the index reflects.
2. For each changed local file, split its content into chunks with FastCDC and seal
   each chunk under a content-derived key.
3. Ask `chunks/exists` for those ids, and `PUT` only the missing ones.
4. `POST` the revision with `parent` set to the vault's **current head** — the highest
   revision in the log, not the file's previous revision. The head advances on every
   commit by anyone, so a commit is always against the head the client last read.
5. On 409, the head moved under the client: keep its bytes as a conflicted copy and
   reconcile the canonical file on the next pass.

Steps 3 and 4 are why an edit to a large file costs the edit rather than the file:
content-defined chunking leaves every chunk after an insertion unchanged in both
content and id, so `chunks/exists` reports them present and only the touched bytes are
uploaded.

## A full download, in order

1. `GET .../revisions?since=0` and take the newest revision for each file key.
2. For a content revision newer than the local index, decrypt its manifest, `GET` its
   chunks, and reassemble — the same chunks the uploader sent, because keys are derived
   from content, not from which file referenced them. With a local store the client
   fetches *through* it: a chunk already stored is never re-downloaded, every chunk
   downloaded is staged the moment it arrives, and the manifest is cached only after
   the last chunk — so an interrupted file resumes where the drop happened instead
   of starting over.
3. For a tombstone, remove the file.

The client reads the log from `0` and reconciles it against a per-file revision number
it keeps in its own index, so it needs no sync cursor of its own and a crash mid-pass
costs a re-read, not a lost revision.

## Change notification

```
GET /api/v1/vaults/{vaultID}/events?since=4&wait=30s
 → 200 { "revisions": [ ... ], "upto": 7 }
```

A long poll, chosen over a WebSocket so the server needs no dependency and the
proxy story stays simple. The client passes the highest revision it already has as
`since`; the server holds the connection open until a commit advances the vault past
that point (returning the new revisions and the new head as `upto`), until `wait`
elapses (returning an empty `revisions` with the current `upto`), or until the client
disconnects. `wait` defaults to 30s and is clamped to 60s.

Crucially, the response is **the same revision page** `GET .../revisions` returns, so
the notification is a hint to read, not the change itself. A client that was offline
while commits landed loses nothing: it reconnects with its last-seen `since` and the
endpoint hands back the whole backlog. Catch-up and notification are the same path,
so a dropped or late signal can only cost one `wait` interval — never a missed
revision. `wait=0` turns the endpoint into a single-shot catch-up read that never
blocks.

## Vault registry

```
GET /vaults → 200 { "vaults": [ { "id", "name", "location", "mode", "archived" } ] }
```

Every vault the server knows, in the small shape a sync client needs: to
resolve a `--vault-name` against the operator's label, or to take the sole
vault by itself when a home server holds exactly one and `--vault-id` was
omitted. Archived vaults are listed so a client can say "retired" instead of
"no such vault" — and name-based selection refuses them either way. An
explicit `--vault-id` needs no lookup at all, which is also why a client
keeps working against a server too old to answer this route.

`mode` is `sync` or `vault` (M11 S1): a `vault` client encrypts names and bytes
before it sends them, a `sync` client sends them in the clear so the server can
index and serve them. It is set when the space is registered and never changes;
a server too old to send it means the old, vault-only world.

`location` is where the vault's files land on each client, relative to that
client's home directory (`Syncbox/Photos`); a `~`-prefixed or absolute value
is used as typed, for a single-machine setup. It defaults to the vault's name
and is empty when the operator left the choice to each client. Older servers
predate the field and send nothing, which a client reads as empty.

The operator's console reads and writes a richer view under `/admin/vaults`
(create with `{name, location, mode}`, rename and locate with
`{name?, location?}`, archive, bookkeeping); clients never need it. `mode` is
accepted on create only — empty means the new-registration default, `sync`, and
anything else is `400 invalid_mode`; there is no route that changes a space's
mode afterwards, because a space whose earlier revisions are ciphertext and
later ones cleartext would be neither of the two things a mode promises. The
server refuses a `location` another live vault already claims
(`409 location_taken`), because two vaults writing one folder would shred each
other's index. Both views share the one bearer token — until per-vault
credentials exist there is no separate admin role to divide them by. A commit
into an unregistered vault still registers it nameless — and as a `vault`, so
the server keeps claiming it cannot read what nothing handed it in the clear —
rather than failing; set `SYNCBOX_REQUIRE_REGISTERED_VAULTS` to turn that into
a refusal — `403 unknown_vault` — which is the right move once every client has
been pointed at a registered vault, and safe to leave off until then.

## Browsing, sharing and the recycle bin

Three surfaces exist because a sync space is readable: someone wants to see a folder's
files without a client, hand one file to someone, and take back a deletion. They are the
reason the mode table is at the top of this file rather than in a footnote — on a vault
there is nothing to serve, so a vault refuses all three, by code:

```
GET  /api/v1/vaults/{vaultID}/files    → 200 { "vault_id", "files": [ { file } ] }
GET  /api/v1/vaults/{vaultID}/recycle  → 200 { "vault_id", "deleted": [ { entry } ], "retention_days" }
POST /api/v1/vaults/{vaultID}/recycle/restore
     { "dir_id", "cipher_name" }       → 201 { file }
POST /api/v1/vaults/{vaultID}/shares
     { "dir_id", "cipher_name", "expires_in_seconds"? }  → 201 { share }
GET  /api/v1/shares/{token}            → the file's bytes, with no credential
```

A space registered as `vault` answers `403` with `not_browsable`, `not_recyclable` or
`not_shareable` — one code per surface, because a client that asked to browse wants a
different message from one that asked to share. A space nothing ever registered answers
`404`, which is a different fact: there is no space here to refuse.

### What a listing says about a file

Browse reads the log rather than keeping a second index: the newest revision per
`(dir_id, cipher_name)`, tombstones skipped. It therefore cannot disagree with what a
client would pull, and there is nothing to invalidate. Each entry carries the key it is
stored under — that is what a commit or a share names — next to a decoded `path`:

```json
{ "dir_id": "01J6YRVK5WS30CHP", "cipher_name": "plan.md", "path": "docs/2026/plan.md",
  "size": 6, "modified_unix": 1760000100, "revision": 2 }
```

`path` is the server's own decoding of those two fields, which makes a sync space's
naming part of the protocol. That coupling is accepted on purpose, so it is written down
rather than discovered later:

- `dir_id` is `BASE32(0x00 || relative_path)` in Crockford's alphabet
  (`0123456789ABCDEFGHJKMNPQRSTVWXYZ`), unpadded, with the leftover bits shifted left
  into a final symbol. The leading `0x00` marks the record as a path rather than a key
  digest, so the root folder is `00`. Decoding tolerates lowercase and the `I`/`L`→`1`
  and `U`→`V` spellings the client tolerates, and refuses anything the client could not
  have written: another first byte, `..`, an empty or `.` segment, a backslash. A
  directory whose id decodes to nothing browses under its raw id rather than a guess.
- A sync manifest is `SBXSYNC1 || size:u64 || count:u32 || (stored_len:u32 || id_len:u16
  || chunk_id)*`, little-endian. `stored_len` is the bytes the chunk holds — the
  plaintext's own length — so a download can state a `Content-Length` its body meets
  rather than trusting the size a revision happened to report. A manifest that lies about
  its own length, or names more chunks than its bytes hold, is refused rather than
  allocated: the count is never trusted before the record vouches for it.

### A share link

Minting is an authenticated call; opening one is not. The link *is* the credential: a
base64url claim set naming one space, one key and an expiry, signed with the same secret
as a bearer token but over a message prefixed `syncbox-share-v1\n`. The prefix is the
whole of the domain separation, and it earns its keep in both directions — a share link
presented as a bearer token and a bearer token presented at `/api/v1/shares/{token}` are
both signature failures, checked before anything is read.

Nothing is stored, so a link has no state to revoke. Two things take its place: the
lifetime is short by default (`SYNCBOX_SHARE_TTL`, a week), and the route re-reads the
*file* rather than a copy of its bytes, so a link stops answering the moment the file is
deleted. `expires_in_seconds` may shorten a link; it cannot lengthen one past the
server's ceiling. An expired, edited or foreign-signed link is a `401`, a link to a file
the space no longer holds is a `404`, and a file whose stored record is not a sync
manifest — a revision some other client wrote — is refused at the mint with `400
unreadable_manifest`, because a link that fails on the first try is worse than no link.

Every download says `Content-Disposition: attachment` and `X-Content-Type-Options:
nosniff`. The reason is the console: a shared `.html` arrives from the same origin the
console's session lives on, so it must reach the browser as a file it saves, never as a
page that runs there.

### The recycle bin, and what expiring means

The bin is the same log read the other way: each key whose newest revision is a tombstone
reports the size its file last had. `retention_days` is the configured window
(`SYNCBOX_RECYCLE_DAYS`, default 30); `0` switches the sweep off, and a deletion then
stays restorable until the operator says otherwise.

A restore is the one commit the server itself writes: it appends a copy of the last live
revision *at the space's head* — not at the revision that file was last seen at, which a
peer may have passed by — and then wakes any long-poll, so clients pull the file back. A
restore of a live or unknown key is a `404`, not a silent no-op.

Once a deletion is past the window an hourly pass drops the dead revisions behind it —
the chunks they named stay, since the server has no blob collector yet, so expiring a
deletion bounds how far back a file can be undone rather than reclaiming its bytes. It
keeps the tombstone itself, and that asymmetry is the point: the tombstone is what tells a
client that was away through the sweep that the file is gone, so dropping it would let a
settled client write the purged bytes straight back. A vault's history is never swept —
its revisions are the only copy there is, and the server does not know what any of them
are.

## Backups

```
GET  /admin/backups     → [ { "ID": "...", "Manifest": { ... } } ]
POST /admin/backups     → 201 { "ID": "...", "Manifest": { ... } }

POST /admin/backups/{id}/verify  → 200 { "id", "chunks", "chunk_bytes", "metadata_sha256" }
POST /admin/backups/{id}/restore → { "dest_dir" }
                               → 200 { "id", "dest_dir", "chunks", "chunk_bytes" }
```

All four answer `501 not_configured` when no `SYNCBOX_BACKUP_TARGET` is set. The
target may be a directory or an `s3://bucket[/prefix]` URL — what sealing and retiring
mean on each is in [docs/backup.md](backup.md).
`verify` re-hashes every chunk and the metadata file against the manifest the snapshot
was sealed with, and answers `404 not_found` for a snapshot that never landed,
`404 incomplete_snapshot` for a half-written bundle, or `500 corrupt_snapshot` when a
stored object no longer matches its recorded hash. `restore` verifies before it copies
and refuses a destination that already holds a `metadata.json` with
`409 restore_target_occupied` — replacing live data is the one thing restore must not
do silently.

The operator's console carries a Snapshots panel over these same four routes:
list, take, verify, and a restore that asks for the destination directory and
then for the snapshot id typed back, because a wrong destination is a real
overwrite and the console has no other hand on the wheel.

Refusals carry a stable `code` in the error body, and that code — not the HTTP status —
is what a client should branch on: `500 corrupt_snapshot` and a generic `500 internal`
are different problems an operator acts on differently. See
[backup.md](backup.md) for what a snapshot contains and how it is restored.

## Rate limits

By default the server answers every caller as fast as it can. A server on a home
connection — or any server that would rather stay responsive than maximally busy —
can opt into a per-address token bucket:

| Variable | Meaning |
| --- | --- |
| `SYNCBOX_RATE_LIMIT` | sustained requests per second per caller IP; unset means unlimited |
| `SYNCBOX_RATE_BURST` | how many requests a caller may spend at once before the sustained rate bites (default 100) |

A refusal is a `429` carrying the stable `rate_limited` code and a `Retry-After`
header in whole seconds. It guards every route, login included, and it refuses
*before* the request buys any auth or storage work — the point is to protect the
machine, not to meter honest use, which a full sync's burst will almost never
notice.

Chunk transfers retry a `rate_limited` themselves: the client waits a doubling
backoff (up to four retries), which converges on the granularity the server
advertised. Commit — the one call that is not idempotent — replays on a stricter
proof: only a `429` carrying this protocol's own `rate_limited` body, which only
the server's limiter writes and which it writes *before any handler runs*, so the
refused commit demonstrably never happened. A bare `429` from a proxy or any other
intermediary, which cannot say what happened downstream, surfaces unretried.

## Versioning the protocol

Every path carries `/api/v1`. A change that breaks an existing client is a new prefix,
not a modified v1, because clients in the wild are older than any server the user
upgrades.
