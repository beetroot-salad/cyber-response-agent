variable "server_name" {
  description = "Name for the playground VPS (shows in Hetzner Console + DNS labels)."
  type        = string
  default     = "soc-playground"
}

variable "server_type" {
  description = "Hetzner server type. CCX33 = 8 dedicated vCPU / 32 GB / 240 GB."
  type        = string
  default     = "ccx33"
}

variable "location" {
  description = "Hetzner datacenter location. fsn1 / nbg1 / hel1 in EU."
  type        = string
  default     = "fsn1"
}

variable "image" {
  description = "Base OS image."
  type        = string
  default     = "ubuntu-24.04"
}

variable "ssh_public_key" {
  description = "SSH public key text (e.g., contents of ~/.ssh/id_ed25519.pub). The matching private key stays on your machine; Terraform never sees it."
  type        = string
}

variable "devcontainer_ssh_public_key_path" {
  description = "Path to the devcontainer's SSH public key. Generated once via ssh-keygen into /workspace/.ssh/; persists across rebuilds via the workspace mount."
  type        = string
  default     = "/workspace/.ssh/devcontainer_ed25519.pub"
}

variable "ssh_source_cidrs" {
  description = "List of CIDRs allowed to reach SSH (port 22). Keep narrow. Example: [\"203.0.113.7/32\"]."
  type        = list(string)
}

variable "labels" {
  description = "Labels applied to all Hetzner resources for filtering in the Console and hcloud CLI."
  type        = map(string)
  default = {
    project = "soc-playground"
    managed = "terraform"
  }
}
