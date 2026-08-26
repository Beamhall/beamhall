// Site-wide SEO/social defaults.
//
// The share card is the ONE image every shared link falls back to — Slack,
// X/Twitter, LinkedIn, Discord, iMessage, WhatsApp, Facebook and Google's
// social preview all read `og:image` / `twitter:image`. Any new page should
// spread `ogImageTags()` into its <head> rather than hardcoding a path, so a
// future card swap is a one-file change.
//
// The served card lives at public/og.png (1200x630, the aspect every platform
// crops to). The full-resolution master is src/assets/social-share-image.png —
// re-derive the served card from it with:
//
//   node -e "require('sharp')('src/assets/social-share-image.png') \
//     .resize(1200,630,{fit:'cover'}).png({palette:true,effort:10}) \
//     .toFile('public/og.png')"
//
// Keep it under ~300 KB: several platforms silently skip larger cards.

/** Canonical origin. Mirrors `site` in astro.config.mjs. */
export const SITE = "https://beamhall.com";

/** The default share card for every page that does not override it. */
export const ogImage = {
  path: "/og.png",
  width: 1200,
  height: 630,
  type: "image/png",
  alt: "Beamhall — agent-built apps. Self-hosted infrastructure secured.",
} as const;

/** Absolute URL of the share card (crawlers reject relative ones). */
export const ogImageUrl = `${SITE}${ogImage.path}`;
