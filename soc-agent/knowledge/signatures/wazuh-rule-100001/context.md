---
signature_id: wazuh-rule-100001
name: Terminal shell in container
severity: medium
data_sources:
  - process-events
created_at: 2026-04-08
updated_at: 2026-04-08
mitre:
  tactics: Execution
  techniques: T1059
references:
  - https://github.com/falcosecurity/rules/blob/main/rules/falco_rules.yaml
related_signatures:
  - wazuh-rule-100002
  - wazuh-rule-100007
base_rate:
  benign_pct: null
  sample_size: null
---

# Wazuh Rule 100001: Terminal shell in container

## Signature Logic

Wazuh rule 100001 is a wrapper around Falco's default rule
**"Terminal shell in container"**. The condition Falco evaluates (paraphrased
from the upstream rule):

> `spawned_process` event where `proc.name` is one of the known shell
> binaries (`bash`, `sh`, `ash`, `csh`, `ksh`, `zsh`, ...), the process has
> a controlling terminal (`proc.tty != 0`), and the process is running
> inside a container (`container.id != "host"`), excluding processes whose
> ancestor matches the `user_known_shell_in_container_activities` macro.

So the fundamental detected activity is: **a shell binary started, with a
TTY attached, inside a container's pid namespace.** This is a syscall-level
event captured by Falco's eBPF probe — `execve` of a shell binary with a
TTY fd open and a non-host `container.id`.

The Wazuh side is a JSON localfile ingestion of `/var/log/falco/events.json`
plus a rule chain: rule 100000 catches any Falco event, rule 100001 narrows
to events whose `data.rule` matches this name. The Wazuh chain is in
`playground/config/wazuh_cluster/rules/falco_rules.xml`. The upstream Falco
rule definition (and any version drift) is in the falcosecurity/rules repo
linked above.

## Related Rules

| Rule ID | Description | Relationship |
|---------|-------------|--------------|
| 100000 | Base Falco event | Parent rule (always fires first via `if_sid`) |
| 100002 | Redirect STDOUT/STDIN to network connection | Stronger reverse-shell signal — verified firing in playground |
| 100007 | Drop and execute new binary in container | Often correlated with post-exploitation — verified firing in playground |
| 100020 | Falco high priority unclassified | Catch-all fallback (level 4 — specific rules win) |

## Threat & Motivation

**What the activity is.** A shell binary executing with a TTY inside a
container's pid namespace. At the OS level this is one syscall: `execve`
of `/bin/bash` (or similar) by some parent process, with stdin/stdout
attached to a pty.

**Why an attacker would want this.** Containers are typically immutable
execution units shipped with a fixed application surface. An interactive
shell gives an attacker arbitrary command execution inside that surface,
which is what they need for: enumeration of the container's filesystem and
mounted secrets, lateral movement to other containers/services reachable
from this one, persistence via dropped binaries or modified entrypoint
scripts, and (if container privileges allow) escape to the host.

**Concrete attacker scenarios:**
- Web app RCE → shell in the app container → read mounted Kubernetes
  service-account token → API server access
- Compromised CI pipeline → shell in a build container → exfiltrate
  source / signing keys
- Container with the Docker socket mounted → shell → `docker run` a
  privileged container → host root

**Legitimate reasons this fires.** All of these are real and common:
- Operator debugging via `docker exec` / `kubectl exec` / `oc exec`
- CI/CD pipelines exec'ing into containers to run scripted commands
- Healthcheck and readiness probes that invoke `sh -c "..."`
- Container entrypoints or init scripts that themselves call a shell
- Application code that calls `os.system()` / `subprocess.run(shell=True)`
  or otherwise shells out as part of normal operation

**Blast radius if real.** Equal to the container's effective privileges:
unprivileged sidecar < typical app container < container with mounted
Docker socket / privileged flag / host-network / host-pid. Always check
container privileges before assigning severity.

## Risk Indicators

The risk on this signature comes from **two orthogonal axes**:

### Axis 1 — Privilege of the target

How much harm could the attacker do if this *were* an attacker?

- Container is privileged, has the Docker socket mounted, runs with host
  network or host PID
- Container hosts a critical workload (production database, payment
  service, identity provider)
- Container has secrets mounted or holds tokens with broad scope

### Axis 2 — Abnormality vs baseline

Does this look like *novel* activity or an *expected* pattern?

- This image/container has fired this rule before, in a recurring pattern
  (lower risk — likely a healthcheck, init script, or CI flow)
- This image/container has *never* fired this rule before (higher risk)
- The shell ancestry doesn't match any pattern we've seen for this image
- Co-firing of related Falco rules (100002 network redirect, 100006
  sensitive file read, 100007 drop-and-exec) in the same `container.id`
  in a tight window

A high-privilege target + novel/abnormal pattern is the high-risk
quadrant. A low-privilege target + recurring expected pattern is the
low-risk quadrant.

> **Note on "app spawned a shell":** parent being an application binary
> (web server, database, language runtime) is a *suspicion multiplier*,
> not a hard indicator. Many real applications shell out as part of normal
> work — `subprocess.run(..., shell=True)` from Python, `system()` calls
> from C, build/deploy/log-rotation hooks, ImageMagick and ffmpeg
> wrappers, anything that calls a binary via a shell. Treat
> `pname=<app binary>` as input to the abnormality axis (never seen this
> app spawn a shell before? higher risk; routinely spawns shells? lower
> risk), not as a standalone red flag.

## Detection Gaps

- Falco only sees containers it is configured to watch — host shells and
  shells in containers outside Falco's scope are invisible.
- A non-shell process executing arbitrary commands (e.g., `python -c`,
  `perl -e`) does not match this rule.
- Shells started via syscalls Falco doesn't instrument can be missed.
- Falco's `user_known_shell_in_container_activities` macro suppresses
  matches — anything that exception list covers is invisible to this
  rule even if the activity is interesting.
