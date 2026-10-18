# Syncbox web settings — design reference

Version 2. The sidebar-footer **Settings** row opens **one clean page** —
no settings rail, no panels. The interactive mockup is
[`reference-web-settings.html`](reference-web-settings.html): *Take a
snapshot*, the schedule *Apply*, per-snapshot *Verify* and *Sign out* all
work. Supersedes the v1 rail + panels design (commit `7ae1b59`).

Status: design reference for the web frontend. Two server pieces already exist
and the embedded console drives them: the snapshot **schedule**
(`GET/PUT /admin/backups/config`, Snapshots panel) and the read-only **About
server** facts (`GET /admin/about` — version, storage backend, data dir, backup
target, share TTL, recycle retention, session-token lifetime, rate limit, and the
unknown-vault commit gate — shown under the Server stats). The web
page itself, the vault-key change, and Set-up-S3 are not built.

## Shape

Shared shell, one scrollable column (660 px centred):

- **Sidebar** (the Files-UI gradient): an **All Vaults** pill on top with a
  back chevron inside it — back to the vault list, which is the app root
  (search lives inside a vault, not in the shell); then the footer
  *quota read-out · **Settings** (active pill while on this page) ·
  Sign out*. No *All files* or *Deleted files* pills, no app top bar.
- **Page**: the three blocks below, in order, each an ordinary section
  heading + card.

## Page blocks

| Block | Content |
|---|---|
| About server | server name as the card title; version; **storage — live** stat block: four counters (chunks, chunk bytes, revisions, largest chunk) re-read from `/healthz` every 5 s under a green *live* dot — a poll, not a page-load snapshot; storage backend + data dir; agent installer links (macOS / Windows / Linux). **No `check for updates`** — there is no endpoint and no release feed behind it; it must not ship dead, and re-adding it is the PR that designs the feed. The read facts (version, backend, data dir, backup target, share TTL, recycle retention) are already served by `GET /admin/about` and shown under the embedded console's Server stats; the installer links still need release assets |
| Change password | the vault password; changing it re-wraps the vault key on the server — zero-knowledge, so no one can reset it for you |
| Snapshots | **Take a snapshot** button; schedule select + inline *Apply* (every 15 min … once a day, plus *Off*); sealed-snapshot list (stamp, short hash, size, age) with per-row **Verify** |

That is the whole settings page. Deliberately **not** web UI:

- profile fields, notification settings, 2FA / recovery kit / web sessions,
  device pairing lists, user admin, backup target / retention / post-hook;
- **sharing settings** — share options live on the share itself;
- **everything device-side** — sync folder, selective sync, Run at login,
  pause, vault auto-lock — lives in the agent Settings window
  ([`reference-agent-settings.md`](reference-agent-settings.md)).

Server and admin tasks stay CLI (`syncbox users …`,
`syncbox backup restore`) and env config; the web page only exposes the
three blocks above.

## Snapshots & the S3 connection

Mirrors `server/internal/backup` and [`backup.md`](backup.md); sizes are
ciphertext as stored.

- Actions map to real endpoints: **Take a snapshot** →
  `POST /admin/backups`, **Verify** → `POST /admin/backups/{id}/verify`,
  list → `GET /admin/backups`.
- **Shipped (server + console):** `GET/PUT /admin/backups/config` reads or changes
  the schedule, or switches it off, on the running server, no restart;
  `SYNCBOX_BACKUP_*` env stays the fallback for headless setup. The embedded
  console's Snapshots panel drives it today; its `GET` also carries
  `next_due_unix` and the boot cadence with a `drifted` flag, so the panel shows
  how soon the next one lands and warns when a live change will revert on a
  restart. The *test-then-save a connection* half (the Set-up-S3
  card below) is still to come.
- **Not configured:** the snapshot list is replaced by a **Set up S3
  connection** card — bucket (`s3://bucket[/prefix]`), optional custom
  endpoint (MinIO-style), region, access/secret key, compliance-lock days
  (default 400) — with **Test connection** (checks the three things the
  sealer refuses without: bucket responds, versioning on, object lock
  enabled) and **Save & enable**.
- **Restore stays CLI.** The API can stage a runnable data directory, but
  the cutover is a deliberate offline act — the web UI never offers to
  replace live data.

## Tokens & implementation

Design tokens are unchanged from the Files UI
([`reference-web-ui.md`](reference-web-ui.md)): `#0082C9` / `#006AA3`,
22 px pills, sidebar gradient, 12–13 px type — the settings page must read
as the same app. Implementation: same web frontend, route `/settings`;
the blocks map to server API calls (about, password rewrap, backups).

Pass 2: the About-server stats block inherits today's console strip —
`/healthz` polled every 5 s, kept live (the rewrite must not downgrade it
to a page-load snapshot). The theme override lives in the shared shell's
sidebar footer ([`reference-web-ui.md`](reference-web-ui.md)), not on this
page — including the **drafted dark palette** recorded there.

The two references share one sidebar shell; the Files UI side is documented
in [`reference-web-ui.md`](reference-web-ui.md).

## Design sources

The ownCloud 11 / Nextcloud baselines informed the earlier, broader
v1 design; version 2 intentionally narrows the surface to what a
self-hosted operator actually needs in a browser.
