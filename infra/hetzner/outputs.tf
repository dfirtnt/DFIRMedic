output "public_ipv4" {
  description = "Static public IPv4 — this is what --server-url and payload/velociraptor.client.yaml must point at."
  value       = hcloud_server.responder.ipv4_address
}

output "server_id" {
  value = hcloud_server.responder.id
}

output "velociraptor_admin_password" {
  description = "GUI 'admin' password. Retrieve with: terraform output -raw velociraptor_admin_password"
  value       = local.admin_password
  sensitive   = true
}
