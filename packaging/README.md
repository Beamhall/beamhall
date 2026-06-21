# Packaging Beamhall

Three layers, from a binary to a turnkey image.

## 1. Binaries (GoReleaser)

Reproducible, static (CGO-free), cross-compiled `beamhalld` + `bh-devidp` with
checksums and the systemd packaging bundled.

```sh
goreleaser build   --snapshot --clean   # binaries only, ./dist
goreleaser release --snapshot --clean   # archives + checksums, ./dist (no publish)
git tag v0.1.0 && goreleaser release --clean   # tagged draft release
```

Without GoReleaser, a plain static build works too:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath \
  -ldflags "-s -w -X main.version=$(git describe --tags --always)" \
  -o beamhalld ./cmd/beamhalld
```

## 2. Install onto a provisioned host (systemd)

The host first needs the runtime baseline — `scripts/lab-bootstrap.sh`
(Docker + userns-remap, the non-remapped build daemon, the internal registry,
Postgres, Caddy, gVisor). Then:

```sh
sudo bash packaging/install.sh ./beamhalld
# edit /etc/beamhall/beamhall.env   (BASE_DOMAIN, the IdP, the admin client)
# install the age root key at /etc/beamhall/secret.key (0400 root:root)
sudo systemctl enable --now beamhalld
journalctl -u beamhalld -f
```

The unit (`beamhalld.service`) runs as a dedicated `beamhall` user in the
`docker` group, applies the systemd sandbox where it does not fight Docker
access, and delivers the secret root key via `LoadCredential` — beamhalld loads
it read-only and refuses to start if it is missing
(`BEAMHALL_SECRET_KEY_FILE=%d/secret.key`).

## 3. Bake a VM image (Packer)

`packer/beamhall.pkr.hcl` produces a configured-but-stopped appliance image:
baseline + binary + service, ready for the operator to drop in config and
enable. A NoCloud seed (`packer/seed/`) lets Packer SSH into the Ubuntu cloud
image; the final provisioner locks the build credential and resets cloud-init so
the exported image carries no build secrets. Build the static binary first,
then:

```sh
GOOS=linux GOARCH=amd64 go build -o packaging/packer/beamhalld ./cmd/beamhalld
packer init     packaging/packer
packer validate packaging/packer
packer build    packaging/packer        # qemu builder needs /dev/kvm
# small host? size the build VM down: -var memory=2048 -var cpus=2
```

The qemu builder writes a multi-GB disk image — **run it from a real disk, not a
tmpfs**: if `/tmp` is tmpfs, set `PACKER_CACHE_DIR` and run from a path on
persistent storage or the build fails with "No space left on device".

Swap the `qemu` source block for `amazon-ebs` / `googlecompute` / `azure-arm`
to bake a cloud image (no local KVM needed) — the provisioners are identical.
Lab-verified: a full bake on the dev VM produced a 20 GiB qcow2 with `beamhalld`
+ the (disabled) unit + the gVisor/Docker baseline, build credential locked.

## The crown jewel

The age root key (`/etc/beamhall/secret.key`) seals every stored secret.
**Losing it loses every secret.** It is delivered out-of-band (never in the
image, never in the env file, never in the data dir), and it travels inside
appliance backups (`beamhalld backup`), which are therefore as sensitive as the
appliance itself. Back it up to your KMS/vault separately.
