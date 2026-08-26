// /llms-full.txt — the whole substantive site as one markdown document, for
// LLM crawlers and retrieval pipelines that prefer a single fetch. Generated
// from the same markdown sources as the /*.md twins, so there is one text
// source per document rather than a third hand-maintained copy.
import overview from "../content/beamhall-overview.md?raw";
import comparison from "../content/beamhall-vs-dokploy-vs-coolify.md?raw";

const header = `<!--
Beamhall — full text (https://beamhall.com/llms-full.txt)
Everything substantive on beamhall.com, concatenated as markdown.
Free to quote with attribution to Beamhall (https://beamhall.com).
-->

`;

const body = header + [overview, comparison].join("\n\n---\n\n");

export const GET = () =>
  new Response(body, {
    headers: { "Content-Type": "text/plain; charset=utf-8" },
  });
