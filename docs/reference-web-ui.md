# Syncbox web/desktop UI — design reference

Version 2. This is the visual reference the Files UI is built toward: layout
anatomy, design tokens, and interaction rules extracted from the mockups. The
interactive mockup is [`reference-web-ui.html`](reference-web-ui.html) — open
it in a browser; the grid/list toggle, search, and selection all work, and a
"Show design specs" panel below the mock mirrors the tokens in this document.
Version 2 makes the **main page the vault list** (the file view lives *inside*
a vault) and replaces the sidebar with the shared shell also used by the
settings page ([`reference-web-settings.md`](reference-web-settings.md)).

Pass 2 (M11 mock review) folds the operator decisions into v2: the card meta
gains **last write**, every card shows its server-derived **folder line**
(read-only), the `⋯` menu is **Archive/Restore only** — *Set folder* and
*Copy pairing command* are retired by decision — archived spaces stay
**visible** dimmed with a chip, the create dialog is **name only**, the
sidebar footer gains a **theme** control, and a **drafted dark palette** is
recorded in the tokens.

Status: design reference only. Nothing in `client/` implements it yet; when it
does (Tauri desktop client), deviations from this document should be called
out in the PR that introduces them.

## Anatomy

```text
┌──────────────────────────────────────────────────────────┐
│ sidebar       │ toolbar: [ + New vault ]  All Vaults     │
│ ┌───────────┐ ├──────────────────────────────────────────┤
│ │search     │ │                                          │
│ ├───────────┤ │  vault grid (main page) — click a card   │
│ │All Vaults │ │  opens the file view inside that vault,  │
│ │           │ │  toolbar becomes [ + New ] Name ⌄  ⋯     │
│ │           │ ├──────────────────────────────────────────┤
│ │───────────│ │ footer: counts                 total size│
│ │1.8 MB     │ └──────────────────────────────────────────┘
│ │Settings   │
│ │Sign out   │
└──────────────────────────────────────────────────────────┘
```

There is **no application top bar** — the sidebar and content fill the whole
window. (Earlier mockups had a blue Nextcloud-style top bar with global
actions; it was deliberately dropped.)

### Sidebar (200 px) — the shared shell

Top to bottom, and nothing else:

| Group | Items |
|---|---|
| Search | rounded field, at the very top; placeholder is `Search vaults …` on the main page, `Search in vault …` inside a vault; filters whatever is showing (search lives in the shell, results depend on level) |
| Vault label | `All Vaults` — white pill under the search, vault icon, brand-dark text; **static label, not a button** (no chevron, no click). On the settings page the same slot carries the back chevron and *is* clickable — the chevron appears only where the pill navigates |
| Footer (bottom-anchored, divider above) | `1.8 MB used` (quota readout) · **theme chip** `Theme: system` (cycles system → light → dark, persists in `localStorage`, repaints the `light-dark()` tokens) · `Settings` · `Sign out` (red) |

`Settings` opens the one-page settings view — see
[`reference-web-settings.md`](reference-web-settings.md), whose sidebar
section documents this same shell (there, `Settings` carries the active
pill).

Deliberately absent from earlier drafts: the `All files` nav pill (this page
*is* all files of the current vault), the `Deleted files` sidebar entry
(how deleted files are reached is an open decision — most likely a filter in
the file area, not a sidebar destination), Personal files, Recent, Favorites,
Shares, Tags, Folder tree, and the "Files settings" label (now just
**Settings**). Re-adding any of these should be a decision, not a drift.

### Toolbar (contextual)

- **Main page**: `+ New vault` pill CTA; breadcrumb reads `All Vaults` (no
  chevron); filter and grid/list toggles are hidden — vaults are always a
  card grid.
- **Inside a vault**: `+ New` pill CTA (same style); breadcrumb is the vault
  name with a chevron — clicking it returns to the vault list (a fuller build
  may hang a vault-switch menu off the chevron); right side has the filter
  button, then grid ⇄ list view toggle (active state = filled circle
  background).
- Pill CTA is brand-dark fill, white text, leading plus icon, 22 px radius.
- When selection is non-empty a `N selected · Clear selection` strip appears
  after the breadcrumb (inside a vault only).

### Main page — vault list

- Grid: auto-fill columns `minmax(180px, 1fr)`, gap 20 × 14.
- Card: 1 px `#E6EEF4` border, radius 12 px, hover border `#0082C9` + tint
  `#F3F9FD`. Contents: 88 px vault icon (stacked-disc glyph), name 13 px
  semibold, meta line `CODE · N items · SIZE · last write` (code is the short
  vault id; *last write* — `2 h ago`, `yesterday` — is the "is anyone
  actually syncing this?" signal, shown in `#3C8A5A` semibold), folder line
  (see *Automatic folder*), status chip (`synced` brand pill, `paused` grey
  pill, `archived` grey pill).
- Footer strip: vault count left, total bytes right (`3 vaults · 1.5 GB total`).
- **Rename**: pencil button at the card's top-right corner (26 px circle,
  muted icon, hover tint). Clicking it swaps the name for an inline text
  field — Enter or blur commits, Esc cancels; the card never opens the vault
  while renaming. (Rename is a server op on the vault record; the mock edits
  its local data only.)
- **Card menu (`⋯`)**: the `⋯` button joins the pencil in the top-right
  corner. Its menu holds **Archive** (red, active space) or **Restore**
  (archived space) — nothing else. **Retired by decision, recorded so they
  are not resurrected by drift**: no *Set folder* (the location is automatic,
  below) and no *Copy pairing command* (the console dispenses no pairing
  block — the card's short code is display only, and terminal pairing stays
  at the terminal). Both buttons exist in today's shipped console and retire
  with this design.
- **Archived spaces stay in the grid**: dimmed (0.55), `archived` grey chip,
  click inert until restored. An archived space never hides without saying
  so.
- **Automatic folder**: a space's location is its **name**, relative to each
  client's home (`~/Syncbox/<name>` as the client resolves it), derived by
  the server at registration. The card shows it as a read-only line —
  `⌂ ~/Syncbox/<name>` plus an `auto` micro-pill. Nothing in this design has
  a field or button that edits a location; renaming a space does not move
  it. `PATCH /admin/vaults/{id}` remains for terminal admins.
- **Create dialog**: the `+ New vault` pill opens a dialog with **one input
  — the name**. Folder is not asked; it derives from the name. (Today's
  console form has a folder field; it retires with this design.)

### File area (inside a vault)

- **Grid**: auto-fill columns `minmax(148px, 1fr)`, gap 20 × 14. Tile = 96 px
  thumbnail (radius 8; folder tiles render the folder icon only, no backdrop),
  name row (ellipsis, trailing share icons), meta row (`modified` + `⋯`).
- **List**: 48 px rows with columns
  `checkbox 24 / icon 30 / name 1fr / shared 130 / size 92 / modified 90 / ⋯ 28`,
  plus a 34 px header row (`Name ▲`, Size, Modified).
- **Shared indicator**: in grid, people/link glyphs after the name; in list, a
  `Shared` chip (#0082C9) plus the glyphs. People = user share, chain = link
  share, both may appear.
- Footer strip: item counts left, bytes used right.

## Design tokens

| Token | Value | Used for |
|---|---|---|
| `--brand` | `#0082C9` | links, checkbox fill, shared chip, focus ring |
| `--brand-dark` | `#006AA3` | `+ New`, active pill, All Vaults text |
| `--sidebar` | linear-gradient 160° `#F1F8FD → #DCEBFA` | sidebar background |
| `--text` | `#272833` | primary text |
| `--muted` | `#7A8694` | meta rows, footer, column headers |
| `--row-hover` | `#F3F9FD` | hover on tiles/rows/nav |
| `--row-selected` | `#E8F3FB` | selected list row |
| `--danger` (file-type) | `#E05252` | PDF tile/tint |

Geometry: radius 22 px pills (nav rows, CTA), 8 px tiles/rows, 5 px / 20 px
checkbox (border `#9FB4C4` 2 px, selected = brand fill + white tick),
icon hit-areas 36 px circles.

Type: 13 px base system sans; names 12.5 px (single-line ellipsis); meta
11.5–12 px muted; breadcrumb 15 px/600.

### Dark palette (drafted)

The shipped console already has a full `light-dark()` palette and a
system/light/dark override; the references must keep up, not the other way
round. These dark values are **drafted** — no build ships dark pixels from
this table until a console or agent build renders it and the values are
confirmed in review.

| Token | Light | Dark (drafted) |
|---|---|---|
| window background | `#FFFFFF` | `#0B1016` |
| row / card surface | `#FFFFFF` | `#101820` |
| input / tinted fill | `#F3F9FD` | `#131C24` |
| border | `#E6EEF4` | `#1E2831` |
| text | `#272833` | `#E6EDF3` |
| muted | `#7A8694` | `#8B98A6` |
| brand / brand-dark | `#0082C9` / `#006AA3` | `#0B8BD2` (both) |
| sidebar / bar gradient | `#F1F8FD → #DCEBFA` | `#16222E → #111E29` |
| synced chip | `#E8F3FB` on `#006AA3` | `#123A54` on `#7CC0EA` |
| locked / paused / archived chip | `#EEF1F4` on `#66727E` | `#222B34` on `#9AA7B3` |

## Interaction rules

1. Clicking a vault card opens that vault (file view). The **breadcrumb**
   (vault name) clicks back to the main page; the sidebar `All Vaults` pill
   is a static label, never a button. Entering or leaving a vault clears the
   search and the selection, and the search placeholder follows the level.
2. Search filters the visible set immediately (case-insensitive name
   substring — vaults on the main page, files inside a vault); empty result
   shows a centered "No … match" state, and the footer counts reflect the
   filtered set.
3. Click anywhere on a tile/row toggles its checkbox; the selection strip
   tracks the count. No ctrl/shift ranges in the mock — decide those when
   implementing.
4. Grid ⇄ list keeps selection and search state.
5. Sidebar is fixed at 200 px on desktop; below 640 px it collapses away
   (margin-left −200 px) and list view drops the shared/modified columns.
6. The theme chip in the sidebar footer cycles system → light → dark,
   persists in `localStorage`, and repaints through the `light-dark()`
   tokens — never by forking a second stylesheet.

## Implementation notes

- The mock is static HTML/ES5 with all data in one `FILES` array plus a
  `VAULTS` array — keep the token values here and in the HTML in lockstep if
  either changes.
- Thumbnails are inline SVG placeholders (sunset, mountain, PDF tile, text
  sheet, folder glyphs); real clients swap them for generated previews.
- Sync status (spinner rows, error badges, pause state) is not represented in
  this version of the reference; it will most likely land in the list-view
  meta column and as a tile overlay — design it against this layout rather
  than alongside it.
