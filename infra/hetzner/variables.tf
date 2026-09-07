variable "hcloud_token" {
  description = "Hetzner Cloud API token (Read & Write), from Project > Security > API Tokens."
  type        = string
  sensitive   = true
}

variable "ssh_public_key_path" {
  description = "Path to the SSH public key to install on the server."
  type        = string
  default     = "~/.ssh/id_ed25519.pub"
}

variable "server_name" {
  description = "Hetzner server name."
  type        = string
  default     = "dfirmedic-responder"
}

variable "server_type" {
  description = "Hetzner server type. cx22 = 2 vCPU / 4GB RAM / 40GB NVMe."
  type        = string
  default     = "cx22"
}

variable "location" {
  description = "Hetzner datacenter location. ash = Ashburn, VA; hil = Hillsboro, OR."
  type        = string
  default     = "ash"
}

variable "image" {
  description = "Base OS image. responder-setup.md's firewall step uses ufw, so keep this Debian/Ubuntu."
  type        = string
  default     = "debian-12"
}

variable "velociraptor_version" {
  description = "Must match payload/velociraptor.exe's version so kits and server agree."
  type        = string
  default     = "0.77.2"
}

variable "tailscale_authkey" {
  description = "Non-interactive tailnet join key for the VPS (Tailscale admin console > Settings > Keys). Use a reusable, tagged key so it survives a rebuild."
  type        = string
  sensitive   = true
}

variable "velociraptor_admin_password" {
  description = "Password for the Velociraptor GUI 'admin' user. Leave blank to have Terraform generate a strong random one (see output)."
  type        = string
  sensitive   = true
  default     = ""
}
