# The Security Bench

Two browser-based teaching tools for cyber security (AAQ IT Unit 2 / BTEC L3).
No accounts, installs or build step — just static HTML.

## Files
- `index.html` — **the software bench**: build an antivirus detector and configure a
  firewall from zero, then evaluate (AO3). ~90 minutes.
- `measures.html` — **measures & threats**: physical, hardware and software controls
  matched to real threats, a layered-defence build, a budgeted recommendation for one
  of three organisations, and a cost-vs-effectiveness evaluation. ~90 minutes.

The two cross-link to each other (on the cover and at the end), so students can move
between them.

## Hosting (GitHub Pages)
Commit both files to the repo root and enable Pages. `index.html` is served at the
root; `measures.html` sits beside it, reachable at `/measures.html`.

To make the measures lesson the landing page instead, rename the files
(`index.html` → `software.html`, `measures.html` → `index.html`) and swap the two
cross-link hrefs inside each file.

## Notes
- Fonts load from Google Fonts; everything else is self-contained.
- The "Download .txt" buttons work when hosted (and when opened locally); the Copy
  button is the universal fallback.
