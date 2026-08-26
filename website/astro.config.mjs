// @ts-check
import { defineConfig } from "astro/config";
import sitemap from "@astrojs/sitemap";

// Beamhall marketing site — a terminal-styled landing plus a few long-form
// routes. Static output (no adapter) → deploys to Cloudflare as plain assets.
export default defineConfig({
  site: "https://beamhall.com",
  srcDir: "./src",
  // The "alternatives" section has one comparison today; keep the section root
  // pointing at it (static build → a meta-refresh page, no inline script).
  redirects: {
    "/alternatives": "/alternatives/beamhall-vs-dokploy-vs-coolify/",
  },
  integrations: [
    sitemap({
      // /og is the share-card render target (noindex); the /alternatives
      // redirect stub and the machine-readable twins are not indexable pages.
      filter: (page) =>
        !page.includes("/og") &&
        !page.endsWith("/alternatives/") &&
        !page.endsWith(".md") &&
        !page.endsWith(".txt"),
    }),
  ],
});
