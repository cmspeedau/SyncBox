# syncboxd — the Syncbox server

One static binary: it serves the sync API, stores what clients have
uploaded, and seals snapshots of its own state. Every space it holds is one
of two kinds (M11): a **vault**, where it holds opaque, content-addressed
chunks and metadata it can never read (no keys, no filenames, no plaintext),
or a **sync** space, kept in the clear so the server can index and serve it.
Only the vault half is the zero-knowledge promise — a sync space is trusted
to the server on purpose. This is the operator's manual; the wire format
lives in [docs/protocol.md](../docs/protocol.md), the vault format in
[docs/format.md](../docs/format.md), and the snapshot engine in
[docs/backup.md](../docs/backup.md).

## Running it

### With Docker Compose (the shape we expect most people to run)

```sh
cp deploy/.env.example .env      # fill in the secrets it asks for
docker compose -f deploy/docker-compose.yml up --build
```

That publishes the API on `127.0.0.1:8080` only, on purpose: the vault's
"in transit as well as at rest" claim is completed by TLS, and the compose
file ships a Caddy profile that provides it —

```sh
SYNCBOX_DOMAIN=vault.example.com docker compose -f deploy/docker-compose.yml --profile tls up --build
```

— which asks Let's Encrypt for a certificate and proxies port 443 to the
server. Without the profile, put your own reverse proxy in front before
anything leaves the machine.

### With plain Docker

```sh
docker build -f deploy/Dockerfile -t syncbox/server .
docker run -d --name syncboxd \
  -p 127.0.0.1:8080:8080 \
  -e SYNCBOX_PASSWORD="$(openssl rand -hex 32)" \
  -e SYNCBOX_TOKEN_SECRET="$(openssl rand -hex 32)" \
  -v syncbox-data:/data -v syncbox-backups:/backups \
  syncbox/server
```

The image is `scratch` plus the binary, running unprivileged; everything
it writes goes into the two mounts.

### From source

```sh
cd server
go build ./cmd/syncboxd
SYNCBOX_PASSWORD=… ./syncboxd serve
```

It binds `127.0.0.1:8080` by default — exposing it takes a deliberate
`SYNCBOX_LISTEN_ADDR`. Pass `-addr` on the command line to override the
environment for one run. On `SIGINT`/`SIGTERM` it stops accepting, drains
in-flight requests, and closes the store.

## Configuration

Everything comes from the environment (`SYNCBOX_*` on purpose: one shared
host can run two servers). `syncboxd serve -h` lists the flags.

| Variable | Default | Meaning |
| --- | --- | --- |
| `SYNCBOX_LISTEN_ADDR` | `127.0.0.1:8080` | host:port to bind; `0.0.0.0` earns a startup warning and needs TLS in front |
| `SYNCBOX_PASSWORD` | unset | the one account credential; clients buy tokens with it. Set, it always wins and is compared as typed. Unset, the server falls back to a password an earlier first run sealed into the data dir, or — with neither — starts *uninitialised* and awaits first-run setup in the console (`POST /api/v1/auth/setup`); it no longer generates and logs one. Set it before exposing the server on a network |
| `SYNCBOX_TOKEN_SECRET` | per-boot | signs bearer tokens; unset, every restart invalidates outstanding tokens |
| `SYNCBOX_TOKEN_TTL` | `24h` | how long an issued token stays valid (any Go duration) |
| `SYNCBOX_DATA_DIR` | `./data` | SQLite metadata plus the `chunks/` store; the container sets `/data` |
| `SYNCBOX_BACKUP_TARGET` | none | directory or `s3://bucket[/prefix]` for snapshots; empty disables the `/admin/*` endpoints |
| `SYNCBOX_BACKUP_SCHEDULE` | off | how often to snapshot itself (`1h`); refused below `1m` |
| `SYNCBOX_BACKUP_LOCK_DAYS` | `400` | COMPLIANCE object-lock retention per sealed version on an `s3://` target — past the yearly rung of the GFS ladder |
| `SYNCBOX_BACKUP_POST` | none | shell command run after every sealed snapshot (restic/rsync/borg carry it further); see docs/backup.md |
| `SYNCBOX_S3_ENDPOINT` | AWS | point at MinIO/R2/Wasabi instead; requests go path-style |
| `SYNCBOX_S3_REGION` | `us-east-1` | request signing region (`AWS_REGION` honored) |
| `SYNCBOX_S3_ACCESS_KEY` / `SYNCBOX_S3_SECRET_KEY` | — | backup signing credentials; `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` are the fallback, and an `s3://` target without either fails at boot |
| `SYNCBOX_RATE_LIMIT` | off | sustained requests per second per caller IP |
| `SYNCBOX_RATE_BURST` | `100` | how many requests an IP may spend at once before the sustained rate takes over |
| `SYNCBOX_REQUIRE_REGISTERED_VAULTS` | off | refuse commits to a vault the registry does not know (`403 unknown_vault`); turn on once every client targets a console-created vault |
| `SYNCBOX_SHARE_TTL` | `168h` | how long a share link of a sync-space file stays open (any Go duration). It is also the ceiling: a mint may ask for a shorter link, never a longer one |
| `SYNCBOX_RECYCLE_DAYS` | `30` | days a deleted sync-space file stays restorable. An hourly pass then drops the dead history behind the tombstone and keeps the tombstone; `0` switches the pass off |

One number is fixed rather than configured: a chunk may be at most 8 MiB,
which is what bounds a single upload.

## Commands

```
syncboxd serve     [-addr host:port]
syncboxd backup    [-url URL] [-token TOKEN]
syncboxd restore   -snapshot ID -target DIR|s3://BUCKET[/PREFIX] -to DIR
syncboxd version
```

`backup` asks a *running* server to take a snapshot now — a client rather
than a direct call because the store being snapshotted is the one the
server holds (`-token` is a bearer token, or `SYNCBOX_TOKEN`; cron talks
over a localhost socket). `restore` is deliberately offline: it writes a
snapshot out into a directory without a running server, which is the point
of a backup.

## Talking to the API

The desktop client and CLI use this API; curl is for poking and for
integrations. Everything under `/api/v1` and `/admin` is bearer-token
only, with the exceptions that a server cannot yet be behind: the signed
share link `/api/v1/shares/{token}` (whose credential *is* the link), and
the first-run pair `/api/v1/auth/status` + `/api/v1/auth/setup`, which a
server with no password yet answers before any credential exists.
`/healthz` is open.

The embedded console at `/` drives all of it: sign in with the same
password — or, on a server that has none yet, meet the **first run** screen
that lets you set one — and each **sync space** offers *Browse files* — read
its tree, hand out a share link to one file (with a copyable URL and its
expiry), and pull a deletion back from the recycle bin. A **vault's** card
says plainly that none of that is possible, because the server holds only
ciphertext — and would answer `403` if you asked it to try.

```sh
# buy a token with the password
TOKEN=$(curl -s localhost:8080/api/v1/auth/token \
  -d '{"password":"…"}' | jq -r .token)

# health: status, uptime-independent timestamp, storage stats
curl -s localhost:8080/healthz | jq

# revisions in a vault (what a sync pass starts with)
curl -s -H "Authorization: Bearer $TOKEN" \
  localhost:8080/api/v1/vaults/VAULT_ID/revisions | jq
```

The surface, all under a bearer header:

| Endpoint | Purpose |
| --- | --- |
| `POST /api/v1/auth/token` | exchange the password for a token (`{token, expires_unix}`). While the server is uninitialised it answers `401 uninitialized` |
| `GET /api/v1/auth/status` | `{"initialized": bool}` — whether anything can sign in yet; the console's login screen reads it to choose sign-in vs first run (open, no credential) |
| `POST /api/v1/auth/setup` | give a fresh server its first password, once. Argon2id-sealed into the data dir; a later call is `409 already_initialized`, a password under 8 chars is `400 weak_password` (open only until it succeeds) |
| `GET/POST /api/v1/vaults/{id}/revisions` | list revisions; commit a new one (manifest + chunk references) |
| `GET /api/v1/vaults/{id}/events` | long-poll-style wakeups when a vault changes |
| `POST /api/v1/vaults/{id}/chunks/exists` | "which of these chunk IDs do you already have" — dedup before upload |
| `HEAD/GET/PUT /api/v1/vaults/{id}/chunks/{id}` | presence check, download, upload |
| `GET /vaults` | the vault registry in client shape (id, name, location, mode, archived) |
| `GET /api/v1/vaults/{id}/files` | browse a **sync space** — the newest revision per file, with its cleartext path decoded. A vault answers `403 not_browsable` |
| `GET /api/v1/vaults/{id}/recycle` · `POST …/recycle/restore` | a sync space's deletions inside the retention window, and a restore, which is a commit at the head. A vault answers `403 not_recyclable` |
| `POST /api/v1/vaults/{id}/shares` | mint a link to one sync-space file, optionally shorter than the TTL. A vault answers `403 not_shareable` |
| `GET /api/v1/shares/{token}` | that one file's bytes with no credential at all, always as an attachment with `nosniff` |
| `GET/POST /admin/vaults` · `PATCH /admin/vaults/{id}` · `POST …/archive` | the console's vault registry: list, create (name, location, mode), rename/locate, retire |
| `GET/POST /admin/backups` | list snapshots (the console's Snapshots panel); take one now |
| `POST /admin/backups/{id}/verify` · `/restore` | verify a sealed snapshot's pins; restore it into a running store |

Every non-2xx reply is `{"code": …, "reason": …}`. PUTs are
content-addressed: the ID *is* the content's identity, so a re-upload of
known bytes is a no-op — that is what makes interrupted transfers
resumable for free. On an `s3://` target, reads the server makes pin the
exact version each chunk was sealed at, so a tampered "current" version of
an object is never read (docs/backup.md).

## Operational notes

- **Tokens are per-boot unless you set `SYNCBOX_TOKEN_SECRET`.** Set it in
  `.env` and restarts stop logging everyone out.
- **Finish first run before you expose the server.** A password-less server is
  reachable-by-anyone-once by design: whoever calls `POST /api/v1/auth/setup`
  first gives it its password. That is the point on loopback or tailscale,
  where first run is the operator's own, but a deployment heading for a network
  should set `SYNCBOX_PASSWORD` — or complete the console's first-run screen —
  *before* it is reachable. Once any password exists, env or sealed, setup is
  refused forever (`409`). A sealed password lands in the data dir as an
  Argon2id hash at mode `0600`, never as the password itself.
- **The data dir is everything.** SQLite file plus `chunks/`; snapshots
  under `SYNCBOX_BACKUP_TARGET` are the copies. A restore is `syncboxd
  restore` (offline) or `POST /admin/backups/{id}/restore` (live store),
  and both verify the sealed manifest's version pins before trusting
  bytes — an `s3://` restore reads pinned versions, so even a bucket
  admin who overwrote current objects cannot poison it.
- **Rate limiting is opt-in.** Off is right on LAN; set
  `SYNCBOX_RATE_LIMIT` if the server faces the internet, and still put
  TLS in front of it.
- **Vault enforcement is opt-in too.** By default a commit may name a vault
  the registry has never heard of, and the server adopts it nameless — as a
  vault, so it keeps claiming it cannot read what nothing registered. That is
  what keeps a pre-registry client working against a fresh console. Once
  every client points at a vault created in the console, set
  `SYNCBOX_REQUIRE_REGISTERED_VAULTS`: commits to anything else are then
  refused `403 unknown_vault` instead of quietly minting a namespace.
- **A share link is a credential with no revocation.** Nothing is stored behind
  it, so the only levers are its lifetime (`SYNCBOX_SHARE_TTL`, a week by
  default) and the file itself — delete it and every link to it stops answering
  at once. Anyone who has the URL has the file, so mint one over TLS.
- **The recycle sweep drops history, not tombstones.** Once an hour it removes
  the dead revisions behind a deletion older than `SYNCBOX_RECYCLE_DAYS`, which
  is what bounds how far back a deletion can be undone — the chunk blobs outlive
  it, since the server has no blob garbage collection yet. It keeps each
  tombstone, so a client that was away through the sweep still learns the file is
  gone instead of writing it back. A vault's revisions are never touched: they
  are the only copy there is, and the server does not know what any of them are.
- **Backups off means no `/admin` routes.** That is the safe default:
  the endpoint that says "copy everything off this box" should require a
  stated destination.
