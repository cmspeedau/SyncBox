# Syncbox web/desktop UI — design reference

Version 2. This is the visual reference the Files UI is built toward: layout
anatomy, design tokens, and interaction rules extracted from the mockups. The
interactive mockup is [`reference-web-ui.html`](reference-web-ui.html) — open
it in a browser; the grid/list toggle, search, and selection all work, and a
"Show design specs" panel below the mock mirrors the tokens in this document.
Version 2 makes the **main page the vault list** (the file view lives *inside*
a vault) and replaces the sidebar with the shared shell also used by the
settings page ([`reference-web-settings.md`](reference-web-settings.md)).

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
| Footer (bottom-anchored, divider above) | `1.8 MB used` (quota readout) · `Settings` · `Sign out` (red) |

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
  semibold, meta line `CODE · N items · SIZE` (code is the short vault id),
  status chip (`synced` brand pill, `paused` grey pill).
- Footer strip: vault count left, total bytes right (`3 vaults · 1.5 GB total`).
- **Rename**: pencil button at the card's top-right corner (26 px circle,
  muted icon, hover tint). Clicking it swaps the name for an inline text
  field — Enter or blur commits, Esc cancels; the card never opens the vault
  while renaming. (Rename is a server op on the vault record; the mock edits
  its local data only.)

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
