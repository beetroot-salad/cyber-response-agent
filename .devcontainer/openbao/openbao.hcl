# The dev issuer (#1108 P4, U1/U4): OpenBao signs the short-lived identity tokens Forgejo's
# Authorized Integrations accept. A real server, not `bao server -dev`: file storage and a static
# seal keep it initialised and unsealed across restarts with no human (O12). Its state, seal key
# and TLS material live on disk under <repo>/playground-issuer/ (gitignored), prepared by
# .devcontainer/provision-dev-issuer.sh. Dev posture only: the seal key sits beside the storage.

ui = false
api_addr = "https://openbao:8200"

storage "file" {
  path = "/openbao/file"
}

# Forgejo accepts only an HTTPS issuer; the certificate is signed by the dev CA.
listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_cert_file = "/openbao/tls/server.pem"
  tls_key_file  = "/openbao/tls/server.key"
}

seal "static" {
  current_key_id = "dev-1"
  current_key    = "file:///openbao/seal/unseal"
}
