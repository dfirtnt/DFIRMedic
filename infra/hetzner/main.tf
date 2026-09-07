resource "random_password" "admin" {
  count   = var.velociraptor_admin_password == "" ? 1 : 0
  length  = 24
  special = true
  # setup.sh.tftpl embeds this value inside a double-quoted shell string
  # (`user add --role=administrator admin "${velociraptor_admin_password}"`).
  # Bash still expands $, `, and \ inside double quotes, so the default
  # special-character set is excluded here in favor of one that can't be
  # misread as shell syntax during the VM's own bootstrap.
  override_special = "!#%^&*()-_=+[]{}<>:?"
}

locals {
  admin_password = var.velociraptor_admin_password != "" ? var.velociraptor_admin_password : random_password.admin[0].result
}

resource "hcloud_ssh_key" "responder" {
  name       = "${var.server_name}-key"
  public_key = file(pathexpand(var.ssh_public_key_path))
}

# Mirrors the host-level ufw policy in responder-setup.md §1: only 443 is
# public. SSH/GUI reach the box over the tailnet, which needs no inbound
# rule here (Tailscale NAT-traverses or falls back to DERP).
resource "hcloud_firewall" "responder" {
  name = "${var.server_name}-fw"

  rule {
    direction  = "in"
    protocol   = "tcp"
    port       = "443"
    source_ips = ["0.0.0.0/0", "::/0"]
  }
}

resource "hcloud_server" "responder" {
  name        = var.server_name
  server_type = var.server_type
  image       = var.image
  location    = var.location
  ssh_keys    = [hcloud_ssh_key.responder.id]
  firewall_ids = [hcloud_firewall.responder.id]

  user_data = templatefile("${path.module}/setup.sh.tftpl", {
    velociraptor_version            = var.velociraptor_version
    tailscale_authkey               = var.tailscale_authkey
    velociraptor_admin_password     = local.admin_password
    kape_triage_artifact_b64        = base64encode(file("${path.module}/../../server/artifacts/Custom.Windows.KapeTriage.yaml"))
    baseline_triage_artifact_b64    = base64encode(file("${path.module}/../../server/artifacts/Custom.DFIRMedic.BaselineTriage.yaml"))
  })

  labels = {
    project = "dfirmedic"
  }
}
