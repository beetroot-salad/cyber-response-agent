resource "hcloud_firewall" "main" {
  name   = "${var.server_name}-edge"
  labels = var.labels

  rule {
    direction   = "in"
    protocol    = "tcp"
    port        = "22"
    source_ips  = var.ssh_source_cidrs
    description = "SSH from admin CIDRs"
  }

  rule {
    direction   = "in"
    protocol    = "icmp"
    source_ips  = ["0.0.0.0/0", "::/0"]
    description = "ICMP (ping) — useful for connectivity checks"
  }

  # Outbound: no rules => all egress allowed.
  # Inbound 80/443, Kibana, MinIO etc. will be added in later batches as services come up.
}
