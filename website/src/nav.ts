// Shared sidebar navigation model.
//
// `screens` are the TUI screens of the landing page (`/#<id>`), switched
// client-side by `public/nav.js`. `pages` are real routes that live outside the
// single-page terminal; they render in the same menu, after the screens, and
// keep the same 1..N keyboard numbering.

export const repo = "https://github.com/Beamhall/beamhall";

export type NavScreen = { id: string; n: string; label: string; cmd: string };
export type NavPage = { id: string; n: string; label: string; href: string; cmd: string };

export const nav: NavScreen[] = [
  { id: "overview", n: "01", label: "overview", cmd: "beamhall --about" },
  { id: "walkthrough", n: "02", label: "walkthrough", cmd: "beamhall demo --replay" },
  { id: "architecture", n: "03", label: "architecture", cmd: "beamhall architecture" },
  { id: "features", n: "04", label: "features", cmd: "beamhall features --all" },
  { id: "security", n: "05", label: "security", cmd: "beamhall security" },
  { id: "roadmap", n: "06", label: "roadmap", cmd: "beamhall roadmap" },
  { id: "install", n: "07", label: "get-started", cmd: "beamhall install" },
];

export const pages: NavPage[] = [
  {
    id: "alternatives",
    n: "08",
    label: "alternatives",
    href: "/alternatives/beamhall-vs-dokploy-vs-coolify/",
    cmd: "beamhall compare --vs dokploy,coolify",
  },
];

export const byId = Object.fromEntries(nav.map((x) => [x.id, x]));
