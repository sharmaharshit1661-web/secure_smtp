# Secure SMTP interface review

Reference: supplied Figma file `9kZW7TDE1jsD6IIKJLf8VA`, Home frame `2:2`.

This is a source and logic review, with the reference theme implemented. It is **not a completed browser acceptance review**. The browser tool rejected localhost access because a saved permission or managed policy blocks the origin, including after the user authorized verification. No alternative browser access was attempted.

## Changes by area

| Area | Implemented improvements |
| --- | --- |
| Landing | Condensed Figma-inspired landing page: hero, three brief capabilities, workspace preview, collapsible standards, and one closing action. Original radar assets retained. |
| Shared UI | Consistent paper/forest palette, quieter card states, readable form controls, focus indicators, reduced motion, repaired missing spacing utilities. |
| Navigation | Mobile backdrop, Escape dismissal, focus containment, background inertness, keyboard sidebar resizing, skip links. Removed the redundant sidebar clock and promotional block. |
| Fleet | Circular risk chart restored as the default, with tier-filtering legend controls; ranked bars and table remain available. Unknown data is preserved. |
| Sessions | Stale responses discarded, exact live-session links, unknown risk/handshake/certificate states, chart values table, generated content reset on context changes. |
| Capture | File type/size/empty validation, analysis completion polling, retryable pending jobs, abort on navigation, report links enabled only for completed jobs, actual listener status. |
| Dispatcher | Keyboard scenario controls, non-overlapping requests, persistent loop progression, backend failures surfaced, bounded transcript, corrected navigation. |
| Compliance | Available reference rules retained during API failure, retry feedback, copy action labeled accurately, active filter states and reset. |
| AI workspace | Invented fallback metrics removed, responsive grid repaired, request race protection, copy failures visible, context controls protected while chat is pending. |
| Authentication | Local demo behavior disclosed, misleading provider controls removed from demo mode, password toggle reachable by keyboard, requested dashboard route preserved after local sign-in. |
| Dialogs | Native modal focus containment, Escape/backdrop dismissal, focus restoration and scroll locking. |

## Verified

- `npm run build --prefix frontend`
- `npm run lint --prefix frontend`
- `npm test --prefix frontend`: 14 passing logic tests covering missing telemetry, observed transport, filtering, file validation, completion/failure/poll limits, and cancellation.
- `git diff --check`

The tests exercise data and asynchronous state helpers. They do not verify rendered controls or live backend integrations.

## Design-hook decisions

- Fixed thick side accents, gradient text, decorative card glows, excessive hover movement, and the inherited spring easing.
- Kept Inter and Space Grotesk because the supplied Figma uses them. Persisted narrow value exceptions.
- Kept the radar measurement grid because it is part of the supplied reference. Persisted an exception limited to the landing stylesheet.
- No whole-file or whole-rule suppressions were added.

## Browser checks still required

At desktop, tablet, and phone widths: inspect every route, overflow and text wrapping, modal focus, menu behavior, filters, chart tooltips, capture selection/upload/completion/failure, real report downloads, dispatcher loop start/stop, clipboard failure, AI request failure/retry, and local/Clerk sign-in. Test keyboard-only navigation and reduced-motion preference. Capture the final desktop/mobile layouts for visual comparison and an independent finish review before recording a completed design system.

## User-requested simplification

- Fleet defaults to the circular host-risk chart. Its legend and the inventory filters share one selection. Ranked and table views remain available.
- Capture centers on upload, reports, and live sessions. Listener setup and history management are expandable.
- AI shows one task at a time: Ask AI, Configuration, or Briefing. Configuration generation now requires an explicit action. Fleet insights remain expandable.
- Compliance shows compact standard scores and expandable rule rows with all conditions and recommendations retained.
- Sessions default to findings, with a compact risk / TLS / anomaly summary. Detailed evidence remains in the existing tabs.
- Dispatcher places scenario selection beside the message form. Transcript detail is expandable; transmission failures remain visible outside it.
- Landing copy, repeated claims, resource-cover sections, and the repeated process explanation were removed. Existing routes and core actions remain reachable.

Validation after simplification: production build, lint, 14 logic tests, and whitespace checks pass. Browser permission remains unchanged; rendered layouts and interactive acceptance still require browser verification.

## Site-wide dark mode

- Added a keyboard-accessible sun/moon toggle to the landing navigation, dashboard header, and both local/Clerk authentication pages. The pressed state indicates dark mode.
- Uses the device preference until a choice is saved. Explicit choices persist across reloads and synchronize across tabs. Blocked browser storage does not prevent switching during the current visit.
- Applies the initial theme before React loads, including native controls and browser theme color, to avoid a light flash.
- Mapped surfaces, text, borders, focus states, buttons, notices, dialogs, tables, transcripts, chart series and tooltips to shared semantic colors. The circular risk graph remains intact.
- Clerk receives a reactive light/dark appearance, including account popovers. Fixed forest radar artwork and its lime icon keep their intentional colors in both themes.
- Slightly darkened muted light-theme text after a contrast check found 4.44:1 against the elevated surface.

Validation: production build and lint pass; all 19 tests pass, including preference precedence, persistence, unavailable storage, pre-paint/runtime consistency, and palette contrast in both themes. These are source and logic checks; browser interaction and rendered desktop/mobile verification remain blocked by the saved browser permission policy. No new design-hook suppressions were added.
