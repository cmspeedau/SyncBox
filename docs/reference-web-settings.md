# Syncbox web settings — design reference

Version 1. What the sidebar-footer **Settings** row of the Files UI opens:
a settings menu rail (Personal / Administration) plus one panel per entry.
The interactive mockup is [`reference-web-settings.html`](reference-web-settings.html)
— the rail switches panels, toggles flip, the S3 setup form opens, and the
backup schedule select works.

Status: design reference only. Nothing in the web frontend implements it yet.

## Shape

Full-page settings view replacing the Files UI; `← All files` in the rail
returns. No application top bar — same rule as the Files UI. The rail is
210 px, same gradient family as the sidebar, with two groups and a
bottom-anchored **Sign out** + version. Administration rows render only for
admin accounts.

## Rail

| Section | Who | Content |
|---|---|---|
| Account | everyone | profile (picture, full name, email), language & timezone |
| Security | everyone | password (change = vault-key rewrap, server can never decrypt), two-factor (TOTP; agents keep device tokens), recovery kit (download / regenerate — there is no server-side reset), web sessions with per-session revoke |
| Notifications | everyone | email toggles (share, comment, quota, new device) + digest cadence |
| Storage | everyone | quota use, ciphertext breakdown (files / old versions / deleted); quota itself is set under Users |
| Devices | everyone | paired agents with status chips + Unpair, installer download — pairing only |
| Users | admin | list, roles, per-user quota, disable, invite |
| Backups | admin | see below |
| Server info | admin | version, storage backend, encryption note, agent installers |

Deliberately absent:

- **Sharing settings.** Share options live on the share itself in All
  files, not in a settings page.
- **Everything device-side** — sync folder, selective folder tree, Run at
  login, pause durations, vault auto-lock — lives in the agent Settings
  window ([`reference-agent-settings.md`](reference-agent-settings.md)).

## Backups panel

Mirrors `server/internal/backup` and [`backup.md`](backup.md); sizes are
ciphertext as stored.

- **Not configured:** a red card with **Set up S3 connection** → form:
  bucket (`s3://bucket[/prefix]`), optional custom endpoint (MinIO-style),
  region, access/secret key, compliance-lock days (default 400).
  **Test connection** checks the three things the sealer refuses without —
  bucket responds, versioning on, object lock enabled at creation.
  **Save & enable** starts the schedule immediately.
- **Configured:** Status card — target, seal, retention ladder, post-backup
  hook read-only; **the schedule is editable** (every 15 min … once a day,
  plus *Off* to stop the schedule without unpairing the bucket), applied
  inline.
- Actions map to real endpoints: **Run backup now** → `POST /admin/backups`,
  per-snapshot **Verify** → `POST /admin/backups/{id}/verify`, list →
  `GET /admin/backups`. The form + schedule need **one new endpoint**,
  `PUT /admin/backups/config` (test-then-save the connection, change or
  switch off the schedule; applied to the running server, no restart).
  `SYNCBOX_BACKUP_*` env remains the fallback for headless setup.
- **Restore stays CLI.** The API can stage a runnable data directory, but
  the cutover is a deliberate offline act — the web UI never offers to
  replace live data.

## Tokens & implementation

Design tokens are unchanged from the Files UI
([`reference-web-ui.md`](reference-web-ui.md)): `#0082C9` / `#006AA3`,
22 px pills, sidebar gradient, 12–13 px type — the settings page must read
as the same app. Implementation: same web frontend, routes
`/settings/<section>`; each card maps to a server API call (profile,
password rewrap, sessions, quota, devices, users, backups).

## Design sources

- **ownCloud Server 11 (classic UI) personal settings** — left section
  menu + right panel cards, and the connected-browsers/sessions list.
  [doc.owncloud.com](https://doc.owncloud.com/server/11.0/classic_ui/personal_settings/general.html)
- **Nextcloud** — Personal / Administration grouping of one settings menu.
