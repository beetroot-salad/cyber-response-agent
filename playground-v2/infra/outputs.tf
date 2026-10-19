output "server_name" {
  value = hcloud_server.main.name
}

output "ipv4" {
  value = hcloud_server.main.ipv4_address
}

output "ipv6" {
  value = hcloud_server.main.ipv6_address
}

output "ssh_command" {
  description = "Ready-to-run SSH command (assumes you have the matching private key)."
  value       = "ssh root@${hcloud_server.main.ipv4_address}"
}
