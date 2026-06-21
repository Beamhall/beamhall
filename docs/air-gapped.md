# Running Beamhall air-gapped

Beamhall runs in environments with **no internet egress**. Once installed, the
appliance's own operation is offline — the control store is local SQLite, the
runtime daemon pulls only pinned digests from the **internal registry**, secrets
are sealed locally, and an **internal IdP** (the bundled Keycloak, or your
on-prem corporate IdP) means JWKS is reachable without the internet.

The one thing that reaches out by default is the **build pipeline**: Cloud Native
Buildpacks pull the builder + run images from Docker Hub on every build. This
guide makes that offline.

## What needs to come in over offline media

| Dependency | Why | How |
|---|---|---|
| **CNB builder + run images** | `pack build` uses them every build | `airgap-bundle.sh` → `airgap-load.sh` + `BEAMHALL_PACK_PULL_POLICY=if-not-present` |
| Bundled Keycloak / Postgres / registry images | first-run install | same bundle (loaded into the runtime daemon) |
| beamhalld binary, gVisor, pack, Caddy | install-time baseline | release archive + `lab-bootstrap.sh` artifacts (carry the binaries in) |
| **Beam package deps** (npm, pip, …) | a beam's own `npm install`/`pip install` | point the beam's build at your **internal package mirror** (Artifactory/Nexus/Verdaccio); not Beamhall-managed |
| CVE databases | only when image scanning ships (fast-follow) | not applicable yet — documented for completeness |

## Procedure

**1. On a connected machine** — build the bundle:

```sh
bash scripts/airgap-bundle.sh beamhall-airgap-bundle.tar.gz
# override the image set with IMAGES="img-a img-b ..."
```

This pulls and `docker save`s the CNB builder + run image, the bundled Keycloak,
Postgres, and the registry image, and writes a `.images.txt` manifest.

**2. Carry both files** to the air-gapped host (the bundle is the only thing that
crosses the gap).

**3. On the air-gapped host** — load them:

```sh
sudo bash scripts/airgap-load.sh beamhall-airgap-bundle.tar.gz
```

It loads the CNB images into the **build daemon** (where `pack` runs) and the
IdP/support images into the runtime daemon, and verifies the builder is present.

**4. Point Beamhall at the local images** in `/etc/beamhall/beamhall.env`:

```sh
BEAMHALL_PACK_PULL_POLICY=if-not-present   # use the loaded builder/run images, don't pull
# only if you retagged the images into the internal registry:
#BEAMHALL_CNB_BUILDER=127.0.0.1:5000/paketo/builder-jammy-base:<tag>
#BEAMHALL_CNB_RUN_IMAGE=127.0.0.1:5000/paketo/run-jammy-base:<tag>
```

Restart beamhalld and run a test deploy. With `if-not-present`, `pack` uses the
pre-loaded builder and never reaches the internet; the runtime daemon pulls only
the pinned digest from the internal registry. *(Lab-verified: a deploy builds and
serves with the builder image staying local — no re-pull.)*

## Updating

Re-run `airgap-bundle.sh` on the connected machine when a new builder/IdP image
ships, carry the new bundle in, and `airgap-load.sh` it. `if-not-present` keeps
using whatever is loaded until you replace it.

## Identity (JWKS) in an air-gap

No internet is needed for token validation as long as the **IdP is internal**:
- the **bundled Keycloak** (`packaging/keycloak/`) runs on the appliance itself; or
- your **on-prem corporate IdP** — Beamhall resolves its JWKS via OIDC discovery
  over the internal network (`docs/idp-setup.md`).
