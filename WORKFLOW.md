# Beamhall release workflow — the release guardian

CI tests `main`; it does **not** release it. A GitHub Release is published only
when a `vX.Y.Z` tag is pushed (`.github/workflows/release.yml` → GoReleaser).
That gate is deliberate — not every commit to `main` should mint a public
release — but it has a failure mode: features pile up on `main`, tested and even
lab-verified, and nobody pauses to ship them. **This file is the antidote.**

Every agent and contributor acts as a **release guardian**: keep the changelog
current as you work, and at natural stopping points ask out loud *"is it time to
cut a release?"* — see [Guardian duties](#guardian-duties). CLAUDE.md points
here and makes this a standing requirement.

---

## When to cut a release

Cut when **all** of these hold:

1. **There is user- or operator-facing change since the last tag** — a new or
   changed MCP tool, a new capability, a packaging/install change, or a bug a
   user could hit. (Pure internal refactors, tests, and docs can wait; they ride
   the next feature release.)
2. **CI is green on the `main` tip** — `gh run list --branch main -L 1`.
3. **The change is complete and verified.** A feature that touches the appliance
   is lab-verified (see `docs/lab-phase0-validation.md`); a half-finished feature
   stays on `main` **untagged** until it's done — never tag a partial feature.
4. **Docs and changelog are current** — `docs/STATUS.md`, `docs/PLAN.md`, the lab
   doc, the `[Unreleased]` block in `CHANGELOG.md`, and any website `(coming)`
   flag for a feature that just shipped (see [Website sync](#website-sync)).

Cadence is event-driven, not calendrical: ship a coherent feature/fix once it's
done and verified. Don't let a completed, verified feature sit untagged across
more than a couple of follow-up commits.

## Versioning (pre-1.0)

Beamhall is `0.x`. The stable seams (the `RuntimeDriver` interface, the MCP tool
contract, `identityadmin.Provider`) may still evolve before `1.0`.

- **Patch — `0.1.Z`** (the default cadence): a feature batch, new tools, bug
  fixes, packaging changes, **additive** seam methods that don't change existing
  behavior. Most releases are this. Examples: `0.1.9` (the admin-over-MCP
  surface), `0.1.12` (provisioned auth).
- **Minor — `0.Y.0`**: a new **product pillar** that changes the story (a new
  "what a beam inherits" capability at a milestone level), **or** any change that
  **breaks an existing seam contract**. Pre-1.0, breaking changes are allowed but
  must be loud: list them first under **Changed** with a `BREAKING:` prefix and a
  migration note.
- **`1.0.0`**: the seams are frozen and the appliance is GA. Not yet.
- **Pre-release**: `-rc.N` suffix (e.g. `v0.2.0-rc.1`); GoReleaser marks these as
  prerelease automatically (`prerelease: auto`).

When in doubt between patch and minor, prefer **patch** and say why in the cut
proposal — reserve a minor bump for genuine milestones.

## Release-notes format

`CHANGELOG.md` is the **single source of truth** for release notes, in
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) style. The GitHub
Release body is generated from the matching version section (the release workflow
extracts it and passes it to GoReleaser as `--release-notes`).

- Accumulate entries under `## [Unreleased]` **as the work lands** — adding the
  changelog line is part of "done", not a release-day scramble.
- Group under these headings, in this order, omitting empty ones:
  **Added** (new capabilities/tools), **Changed** (behavior changes; lead with
  `BREAKING:` items), **Deprecated**, **Removed**, **Fixed** (bug fixes),
  **Security** (hardening, isolation proofs, CVE fixes).
- Write for the **operator/builder**, not the committer: describe the capability
  and its guarantee, not the patch. One bullet per change; reference `PLAN §x`
  where useful. No AI-attribution lines (see CLAUDE.md).

## Cutting a release — step by step

```sh
# 0. Preconditions
gh run list --branch main -L 1          # CI green on the tip
git checkout main && git pull --ff-only

# 1. Decide the version per the policy above → vX.Y.Z

# 2. Roll the changelog: rename [Unreleased] → [vX.Y.Z] - <today>, add a fresh
#    empty [Unreleased], and update the compare links at the bottom of the file.

# 3. Website sync: flip any shipped `(coming)` feature flag and bump version /
#    install references (see Website sync).

# 4. Sanity: docs/STATUS.md, docs/PLAN.md, docs/lab-phase0-validation.md current.

# 5. Commit on a branch, fast-forward into main, push (repo convention: no PRs).
git checkout -b release-vX.Y.Z
git add CHANGELOG.md website/ docs/
git -c user.email=marcosmachado@gmail.com commit -m "release: vX.Y.Z"
git checkout main && git merge --ff-only release-vX.Y.Z && git push origin main
git branch -d release-vX.Y.Z

# 6. Tag and push the tag — THIS publishes the release (outward-facing).
git tag -a vX.Y.Z -m "vX.Y.Z — <one-line summary>"
git push origin vX.Y.Z

# 7. Watch + verify
gh run watch                            # the Release workflow
gh release view vX.Y.Z                  # body = the CHANGELOG section
#    binaries (linux amd64/arm64) + checksums.txt + the bootstrap scripts attached
```

Pushing the tag is the only **outward-facing, hard-to-undo** step (it publishes
public binaries). An agent must get explicit operator confirmation before
`git push origin vX.Y.Z`; steps 1–5 are ordinary repo changes.

If a release is wrong: `gh release delete vX.Y.Z` and `git push --delete origin
vX.Y.Z`, fix, re-tag. Assets may already have been fetched, so prefer a fast
follow-up patch over deletion once a release has been public for any time.

## Website sync

The marketing/docs site is `website/` (Astro → Cloudflare Pages). On every
release, check and update:

- **`website/src/pages/index.astro`** — flip any feature marked `(coming)` to
  shipped once it lands (e.g. provisioned auth flips the **Identity** item), and
  keep the "what a beam inherits" list and the install snippet current.
- Any **version or install reference** (binary version, `install.sh` URL) so the
  site matches the just-published release.

The bootstrap scripts (`install.sh`, the Keycloak setup) are attached to every
release as version-independent assets at
`https://github.com/Beamhall/beamhall/releases/latest/download/<name>`, so docs
that use that stable URL need no per-version edit.

## Guardian duties

At the end of a unit of work — especially after fast-forwarding a feature into
`main`, and whenever the operator asks "anything else?" — evaluate:

```sh
git describe --tags          # e.g. v0.1.11-10-g… → 10 commits past the last tag
git log $(git describe --tags --abbrev=0)..HEAD --oneline
```

If those commits contain a completed, verified, user-facing change, **proactively
tell the operator it's time to cut a release**: name the unreleased highlights,
the recommended version (with the patch-vs-minor reasoning), and what the website
needs. Then wait for the go-ahead before pushing the tag. Don't let shipped work
sit unreleased by default — surface it.
