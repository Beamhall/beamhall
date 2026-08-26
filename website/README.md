# Beamhall website

The marketing site for [Beamhall](https://github.com/Beamhall/beamhall) — a
**terminal-TUI styled** landing built with [Astro](https://astro.build)
and deployed to Cloudflare as a **Worker with Static Assets**.

The landing page is a left sidebar (logo + a vertical "screens" menu) beside a
terminal window whose content switches like a TUI. A few long-form pages
(`/alternatives/...`) live outside that single page but reuse the same shell. No
docs framework — deep dives link to the Markdown docs under `../docs/` on GitHub.

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
| `src/pages/index.astro` | The landing page: sidebar + terminal + all seven screens. |
| `src/nav.ts` | The shared menu model: `nav` (in-page screens) + `pages` (real routes). |
| `src/components/Sidebar.astro` | The shared sidebar (`mode="screens"` on the landing page, `mode="links"` on standalone routes). |
| `src/pages/alternatives/*.astro` | Long-form comparison articles (their own routes, same shell). |
| `src/styles/article.css` | Long-form typography: prose, pull quotes, flow chains, the comparison table. |
| `src/components/*.astro` | Themed inline-SVG diagrams (flow + trust boundary) — build-time, no client JS. |
| `src/styles/terminal.css` | The terminal/TUI theme (palette anchored to the logo navy). |
| `public/fonts/` | Self-hosted JetBrains Mono (full font, so box-drawing renders from it). |
| `public/nav.js` | Screen switching (click, `1`–`6`, `↑`/`↓`); served from origin so the CSP stays `script-src 'self'`. |
| `src/assets/beamhall-logo.png` | The sidebar logo (optimized to webp at build). |
| `public/_headers` | Cloudflare security headers (HSTS, strict CSP, `frame-ancestors 'none'`). |
| `public/favicon.ico` + `favicon-*.png` / `apple-touch-icon.png` / `icon-*.png` | Favicons + touch/PWA icons, generated from `src/assets/beamhall-icon.png` (the simple UFO mark). |
| `public/site.webmanifest` | PWA manifest (name, icons, theme color). |
| `public/robots.txt` | Crawl policy. Everything allowed except `/og`; AI/LLM crawlers are named explicitly (we *want* to be ingested). Points at the sitemap. |
| `src/content/*.md` | The plain-markdown text source for the machine-readable twins (`/llms-full.txt`, `/*.md`). |
| `src/pages/llms.txt.ts` | `/llms.txt` — the curated LLM index (llmstxt.org convention). |
| `src/pages/llms-full.txt.ts` | `/llms-full.txt` — every `src/content/*.md` concatenated. |
| `src/pages/alternatives/*.md.ts` | The plain-markdown twin of each article, e.g. `/alternatives/beamhall-vs-dokploy-vs-coolify.md`. |

The six screens (`overview`, `architecture`, `features`, `security`, `roadmap`,
`get-started`) are plain HTML in `index.astro`. To add or rename one, edit the
`nav` array in `src/nav.ts` and add a matching
`<section class="screen" id="screen-<id>">` in `index.astro`. Each is
deep-linkable via `#<id>` (e.g. `/#security`).

## Long-form pages (the "alternatives" section)

Standalone routes are plain Astro pages that import `Sidebar` with
`mode="links"` and both stylesheets, and put the content inside
`.term-body > .screen.active > article.article`. They carry their own
`<title>` / description / keywords / canonical / OG tags and reuse `/og.png`.

Add one to the menu by appending to `pages` in `src/nav.ts` — it renders after
the screens and keeps the `1`–`N` keyboard numbering (`public/nav.js` follows the
link for those numbers). Today:

| Route | What |
|---|---|
| `/alternatives/beamhall-vs-dokploy-vs-coolify/` | Beamhall vs Dokploy vs Coolify comparison. `/alternatives` redirects here (`redirects` in `astro.config.mjs`). |

House rules for the prose: `##` headings render with a cyan `##` marker, ASCII
flow diagrams are rebuilt as `.flow` node chains (responsive, no client JS), and
the comparison table restacks into one card per row below 760px — keep the
`data-label` on every `<td>` so that stacked view keeps its column names.

The `security` screen (which absorbed the former standalone threat-model screen)
is the buyer-facing security story; keep it in sync with the full
`../docs/threat-model.md`.

## SEO and LLM/AI-crawler surface

Both pages carry a canonical URL, full `og:*` / `twitter:*` tags (`og:type`
`website` on the landing, `article` on the comparison), `lang`/`dir`, and
JSON-LD. `@astrojs/sitemap` emits `/sitemap-index.xml` at build; its `filter` in
`astro.config.mjs` keeps `/og`, the `/alternatives` redirect stub and the
machine-readable twins out of it. `site:` in `astro.config.mjs` is what makes all
of that absolute — do not remove it.

Structured data (`<script type="application/ld+json">`) is a **data** block, not
an executable script, so it does not need a CSP exception; verified against the
real `_headers` CSP with a headless load. Never add an executable inline script.

| Page | JSON-LD |
|---|---|
| `/` | `Organization` + `WebSite` + `SoftwareApplication` (keep `softwareVersion` in step with the current release). |
| `/alternatives/...` | `TechArticle` + `BreadcrumbList` + `FAQPage` (built from the `faq` array, which mirrors the article's question H2s — keep the two in sync). |

The TUI expresses page and section titles as a prompt line, so the real `<h1>`
(one per page) and the per-screen `<h2>`s are `.sr-only` in `index.astro`. The
inline SVG diagrams carry `<title>`/`<desc>` (referenced by
`aria-labelledby`/`aria-describedby`) and the `.flow` chains in articles carry an
`.sr-only` sentence, so a text extractor gets the argument rather than a pile of
arrows. Tables need a `<caption class="sr-only">`, `<th scope="col">` on the
header row and `<th scope="row">` on the first column.

### Machine-readable twins

| Route | What |
|---|---|
| `/llms.txt` | Curated markdown index of the site for LLMs/agents ([llmstxt.org](https://llmstxt.org)). |
| `/llms-full.txt` | Every `src/content/*.md` concatenated — one fetch for retrieval pipelines. |
| `/alternatives/beamhall-vs-dokploy-vs-coolify.md` | Plain-markdown twin of the article, linked from its byline and `<link rel="alternate">`. |

The `.md` twins and `/llms-full.txt` are generated from `src/content/*.md`, so
there is one text source per document — but the `.astro` page is a *separate*
presentation copy. **When you edit an article's prose, edit its
`src/content/*.md` too**, or the version LLMs quote will drift from the one
humans read. `public/_headers` gives the `.md` twin a `Link: rel="canonical"`
header back to the HTML page so it never competes with it in search.

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

## Deploy to Cloudflare (Worker, Static Assets)

The project in the dashboard is a **Worker** named `beamhall` (`.../workers/
services/view/beamhall`) serving the static Astro build from `./dist`. The
`assets` block in `wrangler.jsonc` declares it; `wrangler deploy` uploads it.

**Connect the Git repo.** In Workers & Pages → `beamhall` → Settings → Build:

- **Root directory:** `website`
- **Build command:** `npm run build`  ← produces `./dist`
- **Deploy command:** `npx wrangler deploy`  ← the **Workers** command

Because it's a Worker (not a Pages project), use `wrangler deploy` — **not**
`wrangler pages deploy` (that looks for a Pages project named `beamhall` and fails
with *"Project not found"*). `name` in `wrangler.jsonc` must equal the Worker's
name so the deploy targets it.

**Direct upload from a laptop.**

```sh
npm run build
npx wrangler deploy              # uses wrangler.jsonc (name + assets.directory)
```

Set the production URL in `astro.config.mjs` (`site:`) and attach the `beamhall.com`
domain to the Worker in the dashboard.
