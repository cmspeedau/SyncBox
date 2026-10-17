# Syncbox web login — design reference

Companion to [`reference-web-ui.md`](reference-web-ui.md) (the app behind this
screen) and [`reference-web-settings.md`](reference-web-settings.md).
Interactive mockup: [`reference-web-login.html`](reference-web-login.html).

## Anatomy

One blue screen, one centered column, nothing else:

```text
┌─────────────────────────────────────┐
│         (brand-blue gradient)       │
│                                     │
│              ⊙ vault glyph          │
│             Syncbox                 │
│        ┌──────────────────┐         │
│        │ Password         │  pill   │
│        └──────────────────┘         │
│        ┌──────────────────┐         │
│        │     Sign in      │  pill   │
│        └──────────────────┘         │
│         (error line, reserved)      │
│                                     │
│              homebox                │
└─────────────────────────────────────┘
```

- **Background**: brand-blue vertical gradient `#0A86CC → #05649C`, full
  viewport. The blue *is* the page — no card, no header bar, no sidebar yet
  (the shared shell starts after sign-in).
- **Syncbox wordmark**: white vault glyph (44 px, same icon as the sidebar
  pill) above the name (26 px / 600, letter-spacing .5px).
- **Password field**: 300 px white pill (radius 22 px — the Files UI pill
  geometry), placeholder `Password`, `autocomplete="current-password"`.
- **Sign in**: same-width white pill, brand-dark text `#006AA3`, semibold.
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

## Implementation notes

- Maps to the real endpoint: `POST /api/v1/auth/token` with
  `{"password": …}` → `{"token", "expires_unix"}`; the token is then sent as
  `Authorization: Bearer` (`server/internal/api/router.go`).
- v1 auth is a single server password ("owner"); the single field mirrors
  that. Multi-user would add the username field as a decision, not drift.
- The route is IP rate-limited server-side (`limit` guard covers login), so
  the client needs no extra throttle beyond disabling the button in flight.
- Token expiry: on a 401 from any API call, the app returns here.

Status: design reference only.
