# Syncbox web/desktop UI — design reference

Version 1. This is the visual reference the Files UI is built toward: layout
anatomy, design tokens, and interaction rules extracted from the mockups. The
interactive mockup is [`reference-web-ui.html`](reference-web-ui.html) — open
it in a browser; the grid/list toggle, search, and selection all work, and a
"Show design specs" panel below the mock mirrors the tokens in this document.

Status: design reference only. Nothing in `client/` implements it yet; when it
does (Tauri desktop client), deviations from this document should be called
out in the PR that introduces them.

## Anatomy

```text
┌──────────────────────────────────────────────────────────┐
│ sidebar      │ toolbar: [ + New ]  All files ⌄   ⋯ toggles│
│ ┌──────────┐ ├──────────────────────────────────────────┤
│ │search    │ │                                           │
│ ├──────────┤ │  file area (grid tiles or list rows)      │
│ │All files │ │                                           │
│ │          │ │                                           │
│ │──────────│ │                                           │
│ │Deleted   │ ├──────────────────────────────────────────┤
│ │1.8 MB    │ │ footer: "4 files · 2 folders"    "1.8 MB" │
│ │Settings  │ └──────────────────────────────────────────┘
└──────────────────────────────────────────────────────────┘
```

There is **no application top bar** — the sidebar and content fill the whole
window. (Earlier mockups had a blue Nextcloud-style top bar with global
actions; it was deliberately dropped.)

### Sidebar (200 px)

Top to bottom, and nothing else:

| Group | Items |
|---|---|
| Search | rounded field, "Search here …", filters the file area live |
| Primary nav | `All files` (the only nav entry) |
| Footer (bottom-anchored, divider above) | `Deleted files` · `1.8 MB used` (quota readout) · `Settings` |

`Settings` opens the settings page — see
[`reference-web-settings.md`](reference-web-settings.md).

Deliberately absent from earlier drafts: Personal files, Recent, Favorites,
Shares, Tags, Folder tree, and the "Files settings" label (now just
**Settings**). Re-adding any of these should be a decision, not a drift.

### Toolbar

- `+ New` — pill CTA, brand-dark fill, white text, leading plus icon.
- Breadcrumb `All files ⌄` — 15 px semibold; chevron opens the location menu.
- Right side: filter button, then grid ⇄ list view toggle (active state =
  filled circle background).
- When selection is non-empty a `N selected · Clear selection` strip appears
  after the breadcrumb.

### File area

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
| `--brand-dark` | `#006AA3` | `+ New`, selected nav pill |
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

1. Search filters the visible set immediately (case-insensitive name
   substring); empty result shows a centered "No files match" state, and the
   footer counts reflect the filtered set.
2. Click anywhere on a tile/row toggles its checkbox; the selection strip
   tracks the count. No ctrl/shift ranges in the mock — decide those when
   implementing.
3. Grid ⇄ list keeps selection and search state.
4. Sidebar is fixed at 200 px on desktop; below 640 px it collapses away
   (margin-left −200 px) and list view drops the shared/modified columns.

## Implementation notes

- The mock is static HTML/ES5 with all file data in one `FILES` array — keep
  the token values here and in the HTML in lockstep if either changes.
- Thumbnails are inline SVG placeholders (sunset, mountain, PDF tile, text
  sheet, folder glyphs); real clients swap them for generated previews.
- Sync status (spinner rows, error badges, pause state) is not represented in
  this version of the reference; it will most likely land in the list-view
  meta column and as a tile overlay — design it against this layout rather
  than alongside it.
