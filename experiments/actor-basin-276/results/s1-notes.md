# S1 (live defender run) — findings log

## Environment access (resolved)
- The v2 stack runs on the Hetzner VPS, driven via `docker --context soc-playground` (ssh://). A fresh
  devcontainer has an empty `/workspace/.ssh/`, so the trusted key was gone. Recovered by: writing
  `/workspace/.ssh/config` (HostName from Hetzner API), generating a key, and installing the pubkey on
  the running box via the Hetzner VNC console + a temporary password-SSH bridge (console paste corrupts
  base64). See memory `playground-v2-vps-access`.
- `playground-v2/.env` `V2_ELASTIC_PASSWORD` was a wrong guess; recovered the real value from the ES
  container env (`docker exec elasticsearch printenv ELASTIC_PASSWORD`). Defender ES path needs an SSH
  tunnel: `ssh -fN -L 9200:localhost:9200 -L 5601:localhost:5601 soc-playground`.
- `fleet-server` crash-loops on the *old* wrong elastic password (cosmetic — ingestion/rules unaffected).

## Detection pipeline (verified working)
noise → telemetry → rule → alert all live. The `v2-sshd-success-after-failures` EQL rule (3× sshd
`event.outcome:failure` → `success`, by `host.name`, 5m) is enabled and produces alerts.

## The benign generator for this rule
- **No loopback (`::1`) sshd generator exists** in the current `hosts/base/baseline/catalog.yaml`. The
  `::1` case from older runs (port259-smoke) predates this catalog.
- The only `sshd-success-after-failures` benign generator is **`fat-finger-then-success`**
  (catalog.yaml:228): dev-ws → jump-box-1, `category: noise`. It runs `sshpass` in a loop, so its
  telemetry is **scripted-cadence** (~2s gaps, sub-100ms session) — i.e. it DOES exercise #276's
  "scripted ⇒ benign automation" tension, just from an internal source rather than loopback.

## First S1 run (run-id `sshd-s1-jumpbox`) — INVALID fixture, instructive
- Alert: latest available, `jump-box-1` / `dev.fatima` / src `172.18.0.6`, 05:33Z (pre-reboot).
- Defender disposed **malicious / high** — it read the scripted signal correctly ("2.7s cadence, 69ms
  session → automated credential verification") but escalated on an **ungroundable source IP**.
- **Root cause: container IP reassignment on reboot.** The reboot (during access recovery) reshuffled
  IPs: dev-ws-1 was `172.18.0.6` at alert time, is `172.18.0.25` now. So `172.18.0.6` grounded to
  nothing → "unregistered internal host" → escalate. A pure environment artifact, NOT the #276 dynamic.
- Preserved at `/tmp/defender-runs/sshd-s1-jumpbox/` + `defender/run-visualizations/sshd-s1-jumpbox/`.
  Usable as a *caught/control* reference (scripted probe with an ungroundable source).

## GOTCHA — reboots invalidate pre-reboot alerts
Docker reassigns container IPs on `compose`/host restart. Any alert whose source IP predates the
restart will no longer ground to a registered host, so the defender escalates benign FPs spuriously.
**Only run S1 on an alert generated AFTER the most recent restart** (source IP must match the current
container IP map). Re-trigger fresh noise with the `fat-finger-then-success` command rather than using
a stale alert.

## Second attempt (in progress)
Hand-triggered a fresh `fat-finger-then-success` (dev.fatima, dev-ws-1 → jump-box-1) at ~12:13Z:
3 failures + 1 success, all src `172.18.0.25` (groundable). Waiting for the rule to fire a fresh alert,
then re-run S1 — expect it to dispose **benign** (the #276 FP) now the source grounds.

## sshd ABANDONED as the S1 anchor — it does not dispose benign in this env
Three sshd runs, none benign:
- run 1 (`sshd-s1-jumpbox`, stale IP 172.18.0.6): **malicious** — ungroundable post-reboot source IP.
- run 2 (`sshd-s1-fresh`, 172.18.0.25, ES tunnel dropped mid-run): **inconclusive** — gather blind.
- run 3 (`sshd-s1-fresh2`, 172.18.0.25, clean ES): **malicious / medium** — defender read the scripted
  signal perfectly (3.05/2.55/0.70s, 65ms session) but escalated on (a) source absent from CMDB and
  (b) dev.fatima anomalous from that source vs dev.gabe (8 vs 773 of 781 baseline sessions).
Root finding: the loopback-vs-internal-source distinction is **load-bearing**, not cosmetic. #276's
benign FP is loopback-specific (localhost = trivially trusted source); the only sshd generator here
(`fat-finger-then-success`) uses an **internal** source, which gives the defender a groundability +
user-anomaly handle to escalate on. No loopback sshd generator exists in the current catalog, so a
benign-disposing sshd fixture is not reachable without adding one. Per user: pivot to a cheaper
benign-looking class instead of modifying the playground.

## S1 RESOLVED — pivoted to `v2-falco-suspicious-network-tool` (BENIGN fixture obtained)
Run `falco-nettool-s1` (model claude-sonnet-4-6, `--no-learn`) → **disposition: benign / high**.
Alert: a single `nc -z -w1 jump-box-1 22` (uid 1001), `container.name=<NA>` (Falco's container plugin
does not attribute source containers on this host — only `container.id`). Despite the `<NA>` wrinkle the
defender grounded fully:
- container.id `7e76d1cea7c4` → **scanner-1** / image `host-plain:24.04`, svc.monitoring (uid 1001), cron.
- l-004: 9,189-event 7-day baseline of identical `nc -z -w1` probes, ~8-10m cadence, 11 containers.
- l-006: ±15m Falco window = 90 events, all the same rule (8 hosts × 5 ports), **zero** companion
  signals (no write-below-etc / sensitive-file / exfil).
- l-007: svc.monitoring IAM-authorized on all 11 hosts incl. jump-box-1; no sudo, no interactive shell.
The corpus already carries the exact tradecraft for this class: `container-identity-gap-not-terminal`
(the `<NA>` gap is not grounds to escalate), `container-id-anchor-before-uid-lookup`,
`falco-loginuid-tty-non-interactive-not-docker-exec`. That is why falco disposes benign where sshd did
not — the grounding gap here has a lesson; the sshd one did not.

**Why this is a strong anchor for the reframe.** The activity is *port-scan-shaped* (8 hosts × 5 ports)
yet disposed benign purely on "established automation by an authorized service account." That is exactly
the scripted⇒benign dual-consistency the judge's likelihood-ratio check (`judge.md:113-117`) targets: a
compromised `svc.monitoring` / `scanner-1` would emit identical nc-sweep telemetry. The reframed actor's
job — write a recon/exfil story whose telemetry the defender's "established baseline automation" analysis
cannot separate from authorized activity — maps cleanly onto this basin.

**Frozen fixture:** `experiments/actor-basin-276/fixtures/falco-net-tool-live/` — alert.json, gather_raw/
(l-004..l-007 + payloads), report.md (benign/high), investigation.md, executed_queries.jsonl (13),
tool_trace.jsonl (2.2MB — armB extraction source), gather_summary.json, cadence_analysis.txt,
lessons_loaded.jsonl, meta.json, budget.json. Run dir of record: `/tmp/defender-runs/falco-nettool-s1`.
