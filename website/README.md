# Beamhall website

The marketing site for [Beamhall](https://github.com/Beamhall/beamhall) — a
single-page, **terminal-TUI styled** landing built with [Astro](https://astro.build)
and deployed as static assets to **Cloudflare Pages**.

The page is a left sidebar (logo + a vertical "screens" menu) beside a terminal
window whose content switches like a TUI. No docs framework — deep dives link to
the Markdown docs under `../docs/` on GitHub.

## Develop

Requires Node 20+ (developed on Node 26).

```sh
npm install
npm run dev        # local dev server at http://localhost:4321
npm run build      # static build → ./dist
npm run preview    # serve the built ./dist locally
```

## Structure

| Path | What |
|---|---|
| `src/pages/index.astro` | The whole page: sidebar + terminal + all six screens. |
| `src/components/*.astro` | Themed inline-SVG diagrams (flow + trust boundary) — build-time, no client JS. |
| `src/styles/terminal.css` | The terminal/TUI theme (palette anchored to the logo navy). |
| `public/fonts/` | Self-hosted JetBrains Mono (full font, so box-drawing renders from it). |
| `public/nav.js` | Screen switching (click, `1`–`6`, `↑`/`↓`); served from origin so the CSP stays `script-src 'self'`. |
| `src/assets/beamhall-logo.png` | The sidebar logo (optimized to webp at build). |
| `public/_headers` | Cloudflare security headers (HSTS, strict CSP, `frame-ancestors 'none'`). |
| `public/favicon.ico` + `favicon-*.png` / `apple-touch-icon.png` / `icon-*.png` | Favicons + touch/PWA icons, generated from `src/assets/beamhall-icon.png` (the simple UFO mark). |
| `public/site.webmanifest` | PWA manifest (name, icons, theme color). |

The six screens (`overview`, `architecture`, `features`, `security`, `roadmap`,
`get-started`) are plain HTML in `index.astro`. To add or rename one, edit the
`nav` array at the top of `index.astro` and add a matching
`<section class="screen" id="screen-<id>">`. Each is deep-linkable via
`#<id>` (e.g. `/#security`).

The `security` screen (which absorbed the former standalone threat-model screen)
is the buyer-facing security story; keep it in sync with the full
`../docs/threat-model.md`.

## Social share card (Open Graph)

`public/og.png` (1200×630) is the link-preview image used by WhatsApp, Slack,
iMessage, Twitter/X, etc. (wired via `og:image` / `twitter:image` in
`index.astro`). It's rendered from the `/og` route. To regenerate after a brand or
copy change:

```sh
npm run preview &      # serve the built site
"/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" \
  --headless=new --hide-scrollbars --force-device-scale-factor=1 \
  --window-size=1200,630 --screenshot=public/og.png http://localhost:4321/og
```

Keep it under ~300 KB so WhatsApp shows the large preview.

## Deploy to Cloudflare (Workers Static Assets)

The site is a static Astro build — no Worker script, just assets served from
`./dist`. `wrangler.jsonc` declares the `assets` block; `wrangler deploy` uploads
the directory.

**Connect the Git repo (recommended).** In Workers & Pages → your project →
Settings → Build, set:

- **Root directory:** `website`
- **Build command:** `npm run build`  ← required, this is what produces `./dist`
- **Deploy command:** `npx wrangler deploy`

The most common failure is leaving the **build command empty**: `wrangler deploy`
then runs with no `./dist` and fails with *"Missing entry-point … or assets
directory."*

**Direct upload from a laptop.**

```sh
npm run build
npx wrangler deploy            # uses wrangler.jsonc (assets.directory = ./dist)
```

Set the production URL in `astro.config.mjs` (`site:`) and attach the `beamhall.com`
domain to the project in the dashboard.

> Prefer classic **Cloudflare Pages** instead? Create a Pages project (not
> Workers) with root `website`, build `npm run build`, output `dist` — and the
> `assets` block in `wrangler.jsonc` is ignored by that flow.
