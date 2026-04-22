resource "hcloud_server" "main" {
  name        = var.server_name
  server_type = var.server_type
  image       = var.image
  location    = var.location
  labels      = var.labels

  ssh_keys     = [hcloud_ssh_key.main.id, hcloud_ssh_key.devcontainer.id]
  firewall_ids = [hcloud_firewall.main.id]

  public_net {
    ipv4_enabled = true
    ipv6_enabled = true
  }

  user_data = file("${path.module}/cloud-init/bootstrap.yaml")
}
