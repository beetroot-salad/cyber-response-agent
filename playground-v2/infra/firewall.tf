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

  # The lab's edge (#1391 r6 L1): the ports the credential proxy reaches, from the same narrow
  # sources as SSH. The edge publishes them on the server's public address; nothing else there
  # listens. Keep in step with lab-surface.json (scripts/tests/test_1391_lab_surface.py checks).
  rule {
    direction   = "in"
    protocol    = "tcp"
    port        = "8001-8005"
    source_ips  = var.ssh_source_cidrs
    description = "Lab edge: stubs (credential proxy)"
  }

  rule {
    direction   = "in"
    protocol    = "tcp"
    port        = "8007"
    source_ips  = var.ssh_source_cidrs
    description = "Lab edge: endpoint-query (credential proxy)"
  }

  rule {
    direction   = "in"
    protocol    = "tcp"
    port        = "9200"
    source_ips  = var.ssh_source_cidrs
    description = "Lab edge: Elasticsearch passthrough (credential proxy)"
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
