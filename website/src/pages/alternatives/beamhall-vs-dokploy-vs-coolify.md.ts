// Plain-markdown twin of the comparison article, served at
// /alternatives/beamhall-vs-dokploy-vs-coolify.md — a canonical
// machine-readable version for LLM crawlers and "view as markdown" flows.
//
// KEEP IN SYNC with the .astro page: the Astro file is the presentation source,
// `src/content/beamhall-vs-dokploy-vs-coolify.md` is the text source. Edit both.
import article from "../../content/beamhall-vs-dokploy-vs-coolify.md?raw";

export const GET = () =>
  new Response(article, {
    headers: { "Content-Type": "text/markdown; charset=utf-8" },
  });
