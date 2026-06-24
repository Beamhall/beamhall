# Beamhall release workflow

CI tests `main`; it does **not** release it. A GitHub Release is published only
when a `vX.Y.Z` tag is pushed (`.github/workflows/release.yml` → GoReleaser). That
gate is deliberate, but it has a failure mode: completed, verified features pile up
on `main` and nobody pauses to ship them.

**The release process is owned by the `release-guardian` agent**
(`.claude/agents/release-guardian.md`) — the executable procedure, the full
release-notes format rules, and the cut steps live there, so they don't weigh down
the main working context. To cut a release or check whether one is due, invoke that
agent. This file is the human-readable summary.

## Policy in brief

- **When to cut:** there's a user/operator-facing change since the last tag, CI is
  green on the tip, the change is complete and (if it touches the appliance)
  lab-verified, and docs + `CHANGELOG.md` `[Unreleased]` + any website `(coming)`
  flag are current. Event-driven, not calendrical.
- **Versioning (pre-1.0):** patch `0.1.Z` is the default — feature batches, fixes,
  additive seam methods. Minor `0.Y.0` is reserved for a milestone pillar or a
  **breaking** seam change (called out with `BREAKING:` + migration note). `1.0.0`
  = seams frozen / GA. Pre-releases use `-rc.N`.
- **Release notes:** `CHANGELOG.md` ([Keep a Changelog](https://keepachangelog.com/en/1.1.0/))
  is the single source of truth — the release workflow uses the tag's section as the
  GitHub Release body. Add entries under `[Unreleased]` **as work lands**, grouped
  Added / Changed (BREAKING first) / Deprecated / Removed / Fixed / Security,
  written for the operator.
- **Website sync** is the `website-steward` agent's half of a release (flip shipped
  `(coming)` flags, bump install/version references, keep the security screen in
  sync with `docs/threat-model.md`).
- **The tag is the only outward-facing step** — it publishes public binaries. An
  agent must get explicit operator confirmation before `git push origin vX.Y.Z`;
  every other step is an ordinary repo change.

## Standing guardian duty

A `CHANGELOG.md` `[Unreleased]` entry is part of "done" for any user-facing change.
After a feature fast-forwards into `main`, check whether a release is due
(`git log $(git describe --tags --abbrev=0)..HEAD --oneline`) and surface it — don't
let shipped work sit unreleased by default.
