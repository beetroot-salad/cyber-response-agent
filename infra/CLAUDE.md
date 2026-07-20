# infra/ — playground IaC

Terraform config for the Hetzner Cloud VPS (`soc-playground`) that hosts the v2 playground (`hetznercloud/hcloud` provider, CCX33 in `nbg1`, ~€74/mo gross). Cloud-init bootstrap installs Docker + Compose. Dev-only — not shipped with the soc-agent plugin. Design rationale: `/workspace/docs/playground-environment-v2.md`.

Auth: `HCLOUD_TOKEN` from `/workspace/.env` (project-scoped; rotate via Hetzner Console). State is local `terraform.tfstate` (gitignored, single-dev). Local overrides in `terraform.tfvars` (gitignored; see `.example` — SSH pubkey + `ssh_source_cidrs`).

## The levers (`bin/`)

| Script | Does |
|---|---|
| `bin/down.sh` | **Lever down** (long idle): snapshot the server, destroy it (keeps firewall + SSH keys — free), clear the SSH alias. Billing stops; snapshot ~€0.01/GB/mo. |
| `bin/up.sh` | **Lever up**: restore from the latest lever-down snapshot (pins it via `image.auto.tfvars`), apply, re-sync the SSH alias. |
| `bin/update-ssh-config.sh` | Sync `/workspace/.ssh/config` with the current server IP (`--clear` parks the alias on an unresolvable name). Run after any apply. |
| `bin/es.sh` | curl helper for the playground Elasticsearch (`es.sh --help`). |

Fresh install instead of snapshot: `rm -f image.auto.tfvars && terraform apply`. Full teardown: `terraform destroy && bin/update-ssh-config.sh --clear` (snapshots are NOT auto-deleted — `hcloud image list -l project=soc-playground`).

## Gotchas

- **Hetzner bills for existence, not uptime** — `poweroff` saves nothing; only `bin/down.sh` stops the bill. No budget hard-cap exists; prepay credit for a ceiling.
- **A released IP belongs to someone else within days** — and the SSH alias would silently connect to whoever holds it next. Any teardown (including manual, which `down.sh` can't see with local state) must run `bin/update-ssh-config.sh --clear` so the alias fails closed.
- **Changing `ssh_keys` or `user_data` forces server recreation** (create-time-only attributes). Snapshot first if state matters.
- **cloud-init re-runs on lever-up** (new instance-id). Bootstrap is idempotent, so harmless; `manage_etc_hosts: false` + a grep-gated runcmd keep our `/etc/hosts` service-name entries from being clobbered.
- **Snapshots accumulate** — `down.sh` never deletes old ones; clean periodically with `hcloud image delete <id>`.
- **Firewall SSH source is a `/32`** — if your public IP changes, update `terraform.tfvars` and apply (the API token works from anywhere, so you're never locked out).
