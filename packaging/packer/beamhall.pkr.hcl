# Packer template — bake a Beamhall appliance image: an Ubuntu base + the full
# runtime baseline (Docker/userns-remap, the build daemon, registry, Postgres,
# Caddy, gVisor — scripts/lab-bootstrap.sh) + the beamhalld binary and systemd
# service (packaging/install.sh). The result boots into a configured-but-stopped
# appliance; the operator drops in /etc/beamhall/beamhall.env + secret.key and
# enables the service.
#
#   # build the static binary first (any arch the image targets):
#   GOOS=linux GOARCH=amd64 go build -o packaging/packer/beamhalld ./cmd/beamhalld
#   packer init   packaging/packer
#   packer validate packaging/packer
#   packer build  packaging/packer        # needs KVM for the qemu builder
#
# Swap the `qemu` source for amazon-ebs / googlecompute / azure-arm to bake a
# cloud image — only the source block changes; the provisioners are identical.

packer {
  required_plugins {
    qemu = {
      source  = "github.com/hashicorp/qemu"
      version = "~> 1"
    }
  }
}

variable "iso_url" {
  type        = string
  description = "Ubuntu 24.04 cloud/live image URL or local path"
  default     = "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-amd64.img"
}

variable "iso_checksum" {
  type    = string
  default = "none" # set to "sha256:..." for a release build
}

variable "ssh_username" {
  type    = string
  default = "ubuntu"
}

variable "ssh_password" {
  type        = string
  default     = "packer"
  description = "Build-time password for the cloud image's default user (NoCloud seed). Ephemeral: the build VM is discarded and the bake locks this account before export."
}

variable "memory" {
  type        = number
  default     = 8192
  description = "Build VM RAM (MB). Lower on small hosts, e.g. -var memory=2048."
}

variable "cpus" {
  type    = number
  default = 4
}

source "qemu" "beamhall" {
  iso_url          = var.iso_url
  iso_checksum     = var.iso_checksum
  disk_image       = true
  disk_size        = "20G"
  format           = "qcow2"
  accelerator      = "kvm"
  cpus             = var.cpus
  memory           = var.memory
  headless         = true

  # Ubuntu cloud images ship no console login; cloud-init (NoCloud) seeds the
  # default user's password from a CD labelled "cidata" so Packer can SSH in.
  cd_label = "cidata"
  cd_files = ["${path.root}/seed/user-data", "${path.root}/seed/meta-data"]

  ssh_username     = var.ssh_username
  ssh_password     = var.ssh_password
  ssh_timeout      = "30m"
  shutdown_command = "echo '${var.ssh_password}' | sudo -S shutdown -P now"
  output_directory = "build/beamhall-image"
  vm_name          = "beamhall.qcow2"
}

build {
  name    = "beamhall-appliance"
  sources = ["source.qemu.beamhall"]

  # Upload the runtime-baseline scripts, the binary, and the systemd packaging.
  provisioner "file" {
    source      = "${path.root}/../../scripts"
    destination = "/tmp/beamhall-scripts"
  }
  provisioner "file" {
    source      = "${path.root}/../../packaging"
    destination = "/tmp/beamhall-packaging"
  }
  provisioner "file" {
    source      = "${path.root}/beamhalld" # pre-built static binary (see header)
    destination = "/tmp/beamhalld"
  }

  # Provision the runtime baseline, then install the service (stopped).
  provisioner "shell" {
    inline = [
      "set -e",
      "sudo bash /tmp/beamhall-scripts/lab-bootstrap.sh",
      "sudo bash /tmp/beamhall-packaging/install.sh /tmp/beamhalld",
      "sudo rm -rf /tmp/beamhall-scripts /tmp/beamhall-packaging /tmp/beamhalld",
      "echo 'beamhall appliance baked — configure /etc/beamhall and enable beamhalld on first boot'",
    ]
  }

  # Hygiene: strip the ephemeral build credential and reset cloud-init so the
  # exported image carries no build-time secrets and re-seeds on first real boot.
  provisioner "shell" {
    inline = [
      "echo '${var.ssh_password}' | sudo -S passwd -l ${var.ssh_username} || true",
      "sudo cloud-init clean --logs || true",
      "sudo rm -f /home/${var.ssh_username}/.ssh/authorized_keys || true",
    ]
  }
}
