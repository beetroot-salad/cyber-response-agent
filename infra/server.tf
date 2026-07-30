# The devcontainer's working key. Created out-of-band (not Terraform-owned), so it is
# read as a data source rather than declared — Terraform must attach it but must never
# destroy it. Without this the restored server gets only the admin + devcontainer keys,
# whose private halves are not on this machine, and `ssh_keys` is create-time-only, so an
# unreachable server could only be fixed by recreating it.
data "hcloud_ssh_key" "claude" {
  name = "claude-soc-playground-1"
}

resource "hcloud_server" "main" {
  name        = var.server_name
  server_type = var.server_type
  image       = var.image
  location    = var.location
  labels      = var.labels

  ssh_keys = [
    hcloud_ssh_key.main.id,
    hcloud_ssh_key.devcontainer.id,
    data.hcloud_ssh_key.claude.id,
  ]
  firewall_ids = [hcloud_firewall.main.id]

  public_net {
    ipv4_enabled = true
    ipv6_enabled = true
  }

  user_data = file("${path.module}/cloud-init/bootstrap.yaml")
}
