resource "hcloud_ssh_key" "main" {
  name       = "${var.server_name}-admin"
  public_key = var.ssh_public_key
  labels     = var.labels
}

resource "hcloud_ssh_key" "devcontainer" {
  name       = "${var.server_name}-devcontainer"
  public_key = file(var.devcontainer_ssh_public_key_path)
  labels     = var.labels
}
