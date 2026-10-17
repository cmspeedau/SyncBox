# Syncbox web login — design reference

Companion to [`reference-web-ui.md`](reference-web-ui.md) (the app behind this
screen) and [`reference-web-settings.md`](reference-web-settings.md).
Interactive mockup: [`reference-web-login.html`](reference-web-login.html).

## Anatomy

One blue screen, one centered column, nothing else. Two states on the same
screen: **Sign in** (password + Sign in) and **First run** (password set,
shown when the server has no password yet).

```text
┌───────────────────────────┐      ┌───────────────────────────┐
│     (brand-blue tint)     │      │     (brand-blue tint)     │
│        ⊙ vault glyph      │      │        ⊙ vault glyph      │
│         Syncbox           │      │         Syncbox           │
│     ┌──────────────┐      │      │ First run — set the       │
│     │  Password    │ pill │      │ server password (caption) │
│     └──────────────┘      │      │     ┌──────────────┐      │
│     ┌──────────────┐      │      │     │  Password    │ pill │
│     │   Sign in    │ pill │      │     └──────────────┘      │
│     └──────────────┘      │      │     ┌──────────────┐      │
│      (error line)         │      │     │Confirm passw.│ pill │
│         homebox           │      │     └──────────────┘      │
└───────────────────────────┘      │     ┌──────────────┐      │
                                   │     │   Confirm    │ pill │
     sign-in (normal)              │     └──────────────┘      │
                                   │      (error line)         │
                                   │         homebox           │
                                   └───────────────────────────┘

     first run (server has no password yet)
```

- **Background**: brand-blue vertical gradient `#0A86CC → #05649C`, full
  viewport. The blue *is* the page — no card, no header bar, no sidebar yet
  (the shared shell starts after sign-in).
- **Syncbox wordmark**: white vault glyph (44 px, same icon as the sidebar
  pill) above the name (26 px / 600, letter-spacing .5px).
- **Password field**: 300 px white pill (radius 22 px — the Files UI pill
  geometry), placeholder `Password`, `autocomplete="current-password"`.
- **Sign in**: same-width white pill, brand-dark text `#006AA3`, semibold.
- **First run** (server has no password yet): a caption `First run — set the
  server password` (12 px, white 85%) replaces nothing — the wordmark stays —
  then two pill fields `Password` + `Confirm password` (12 px gap) and a
  white `Confirm` pill.
- **Error line**: reserved slot under the button (no layout shift), 12 px
  `#FFD9D5` on blue; the field border goes `#FFB3AB` in the error state.
- **Server name**: bottom-center, 11 px white at 70% (mock shows `homebox`).

Deliberately absent: username field (v1 has one server password, not users),
"forgot password" link, captcha, language picker, footer links.

## Interaction rules

1. Enter in the field or clicking **Sign in** submits.
2. Empty password → error state ("Password required"), any keystroke clears
   it.
3. Wrong password (server 401) → same error slot: "Wrong password." Submit
   while in-flight disables the button (label "Signing in …").
4. Success stores the token and lands on the vault list
   (`reference-web-ui.md` main page).
5. First run validates client-side before confirming: empty →
   "Password required"; under 8 characters → "Use at least 8 characters";
   mismatch → "Passwords don't match" with the error border on the second
   field. A successful Confirm stores the password and the page becomes the
   normal sign-in.

## Implementation notes

- Maps to the real endpoint: `POST /api/v1/auth/token` with
  `{"password": …}` → `{"token", "expires_unix"}`; the token is then sent as
  `Authorization: Bearer` (`server/internal/api/router.go`).
- v1 auth is a single server password ("owner"); the single field mirrors
  that. Multi-user would add the username field as a decision, not drift.
- The route is IP rate-limited server-side (`limit` guard covers login), so
  the client needs no extra throttle beyond disabling the button in flight.
- Token expiry: on a 401 from any API call, the app returns here.
- First run is a **server change, not just a screen**: today the password
  comes from server config and `POST /api/v1/auth/token` is the only auth
  endpoint — nothing reports "no password yet". Needs (a) an uninitialised
  signal the page can read (`GET /healthz` returning `initialized: false`, or
  a small `GET /api/v1/auth/status`) and (b) `POST /api/v1/auth/setup`
  `{"password": …}` that stores the first password and refuses all later
  calls. Until then the first-run screen is design-only.

Status: design reference only.
