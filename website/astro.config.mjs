// @ts-check
import { defineConfig } from "astro/config";

// Beamhall marketing site — a single custom terminal-styled page.
// Static output (no adapter) → deploys to Cloudflare Pages as plain assets.
export default defineConfig({
  site: "https://beamhall.com",
  srcDir: "./src",
});
