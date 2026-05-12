# infra/ — playground IaC

Terraform configuration for the Hetzner Cloud VPS hosting the v2 playground. Design rationale: `/workspace/docs/playground-environment-v2.md`. This dir is dev-only infrastructure — not shipped with the soc-agent plugin.

## Tech stack

| Concern | Tool | Version / pin |
|---|---|---|
| IaC | Terraform | `>= 1.10` (installed via HashiCorp apt repo in Dockerfile.dev) |
| Provider | `hetznercloud/hcloud` | `~> 1.50` (resolved 1.60.x) |
| CLI | `hcloud` (Hetzner Cloud CLI) | v1.62.2, pinned in Dockerfile.dev |
| Cloud | Hetzner Cloud project `soc-playground` | — |
| VPS image | Ubuntu 24.04 LTS | default; overridden by `image.auto.tfvars` after lever-up |
| VPS type | CCX33 (8 dedicated vCPU / 32 GB / 240 GB) | ~€74/mo gross (~€62 net) |
| Location | `nbg1` (Nuremberg, DE) | fsn1 was out of stock at provisioning; pricing identical across EU DCs |
| Bootstrap | cloud-init (`cloud-init/bootstrap.yaml`) | Installs Docker + Compose + unattended-upgrades |
| Auth | `HCLOUD_TOKEN` env var | sourced from `/workspace/.env` (chmod 600, gitignored) |
| State | Local `terraform.tfstate` (gitignored) | single-dev; revisit for multi-dev |

## File layout

```
infra/
├── main.tf                      # Terraform + provider pin
├── variables.tf                 # Input variables
├── ssh_key.tf                   # Admin key (Windows) + devcontainer key
├── firewall.tf                  # Hetzner Cloud edge firewall
├── server.tf                    # CCX33 + cloud-init bootstrap
├── outputs.tf                   # ipv4 / ipv6 / ssh_command
├── cloud-init/
│   └── bootstrap.yaml           # First-boot config (Docker, unattended-upgrades)
├── bin/
│   ├── down.sh                  # Lever down: snapshot + destroy server
│   ├── up.sh                    # Lever up: restore from latest snapshot
│   ├── update-ssh-config.sh     # Sync /workspace/.ssh/config with current server IP
│   └── es.sh                    # curl helper for the playground Elasticsearch (`es.sh --help`)
├── terraform.tfvars             # Local overrides (gitignored; see .example)
├── terraform.tfvars.example     # Template
├── image.auto.tfvars            # Written by up.sh to pin snapshot (gitignored)
├── .terraform.lock.hcl          # Provider version lockfile (committed)
└── .gitignore
```

## Workflows

### Initial provision (one-time)

```bash
cd /workspace/infra
cp terraform.tfvars.example terraform.tfvars   # paste SSH pubkey + set CIDRs
terraform init                                 # first time only
terraform apply
bin/update-ssh-config.sh                       # sync SSH alias
ssh soc-playground
```

### Lever down (long idle — save money)

```bash
bin/down.sh
```
- Creates a Hetzner snapshot labeled `project=soc-playground,role=lever-down`
- Runs `terraform destroy -target=hcloud_server.main` (keeps firewall + SSH keys — both free)
- Billing stops immediately; snapshot storage ~€0.01/GB/mo

### Lever up

```bash
bin/up.sh
```
- Finds the latest lever-down snapshot
- Writes `image.auto.tfvars` pinning that snapshot ID
- Runs `terraform apply` → new server from snapshot
- Calls `update-ssh-config.sh` to sync SSH alias with new IP

### Back to a fresh install

```bash
rm -f image.auto.tfvars
terraform apply          # uses default Ubuntu image
bin/update-ssh-config.sh
```

### Fully tear down

```bash
terraform destroy        # removes server + firewall + SSH keys
# Snapshots are NOT auto-deleted — inspect with: hcloud image list -l project=soc-playground
```

## Gotchas

- **Hetzner bills for existence, not uptime.** Powered-off server still bills at full hourly rate — `hcloud server poweroff` saves zero euros. Only `bin/down.sh` (destroy + snapshot) actually stops the bill.
- **No budget hard-cap.** Hetzner has per-resource monthly price caps (CCX33 ≤ €74/mo) but no AWS-Budgets-style auto-destroy. For a hard ceiling, prepay credit via Console → Billing.
- **Changing `ssh_keys` or `user_data` forces server recreation** — these are create-time-only attributes on `hcloud_server`. Server state is lost; snapshot first if it matters.
- **IP may change across destroy/recreate.** Run `bin/update-ssh-config.sh` after apply. Floating IP (€4/mo) would stabilize addressing; not worth it at playground scale.
- **cloud-init re-runs on lever-up.** Hetzner assigns a new instance-id to the restored server, so cloud-init treats per-instance modules (`runcmd`) as unseen and re-runs them. Harmless because our bootstrap is idempotent (apt install no-ops, ack file rewrites), but adds ~30s to lever-up. To suppress, remove `user_data` from `server.tf` after the first apply — tradeoff: any future reprovision needs to restore it.
- **`/etc/hosts` regeneration on lever-up.** Cloud-init's `manage_etc_hosts` module rewrites `/etc/hosts` from a template on every boot. Any entries we append manually get clobbered on the next lever-up. Fix in `cloud-init/bootstrap.yaml`: `manage_etc_hosts: false` + idempotent `runcmd` append of our Docker-service-name entries (`elasticsearch`, `fleet-server` → `127.0.0.1`).
- **Firewall source IP.** `ssh_source_cidrs` in `terraform.tfvars` is a `/32` by default. If your public IP changes, update tfvars and `terraform apply` — the API accepts your token from anywhere, so you're never actually locked out.
- **Snapshots accumulate.** `bin/down.sh` always creates a fresh snapshot and never deletes old ones. Periodically clean with `hcloud image delete <id>`.

## Auth quick-reference

```bash
# Verify env is loaded (from /workspace/.env)
echo "${HCLOUD_TOKEN:0:8}..."

# Direct API smoke test
hcloud server list
```

API token is project-scoped (scope: Read & Write). Rotation is manual via Hetzner Console → Security → API Tokens. If the token leaks, revoke in Console; Terraform state has no auth material.
