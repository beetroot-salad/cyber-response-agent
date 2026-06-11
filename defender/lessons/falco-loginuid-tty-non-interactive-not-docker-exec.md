---
name: falco-loginuid-tty-non-interactive-not-docker-exec
description: loginuid=-1 + tty=0 means non-interactive automated context only; both container init and docker exec match, so exec origin requires ancestry evidence Falco cannot provide.
telemetry_source: [falco]
attack_phase: [execution]
source_signature: [v2-falco-suspicious-network-tool]
source_finding_ids:
  - lotl-oracle-test-1/benign/1
created_at: 2026-06-07T00:00:00Z
---

`loginuid=-1` combined with `proc.tty=0` means the process ran in a non-interactive, non-login session. That is the correct and complete inference from those two fields. It does not identify docker exec as the origin.

Container entrypoint scripts, init helpers (`wait-for-it`, tini, s6-overlay), cron-triggered jobs, and any automated non-login process all produce the same `loginuid=-1` / `tty=0` profile. A service entrypoint also runs without login credentials and without a terminal — it does not carry a positive loginuid.

Treating these values as "the signature of a docker exec-spawned process" manufactures a false refutation of the routine story. If the container's normal startup flow was the actual origin, reasoning from `loginuid=-1` to "inconsistent with a service entrypoint" would wrongly eliminate it.

To distinguish docker exec from container-native automation, check process ancestry above the executing shell: a docker exec handler inserts dockerd or a container runtime exec shim (e.g. `containerd-shim`) between the container's PID 1 and the spawned process. Falco's `execve` surface exposes only `proc.pname` — one level up — which is insufficient for that ancestry check.

If the ancestry is not available, characterize the context as "non-interactive automated process" and flag the docker exec claim as unverifiable. Do not weight it as a refutation; treat it as a ceiling gap.
