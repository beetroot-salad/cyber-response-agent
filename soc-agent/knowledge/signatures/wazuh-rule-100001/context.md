---
signature_id: wazuh-rule-100001
name: Terminal shell in container
severity: medium
data_sources:
  - falco
  - /var/log/falco/events.json
created_at: 2026-04-08
updated_at: 2026-04-08
mitre:
  tactics: Execution
  techniques: T1059
references:
  - https://falco.org/docs/rules/default-rules/
related_signatures:
  - wazuh-rule-100002
  - wazuh-rule-100007
base_rate:
  benign_pct: null
  sample_size: null
---

# Wazuh Rule 100001: Terminal shell in container

## Signature Logic

Wazuh rule 100001 maps Falco's default rule **"Terminal shell in container"**
to Wazuh level 10. Falco fires when an interactive shell (`bash`, `sh`, `ash`,
`zsh`, `csh`, `ksh`, etc.) is spawned inside a container with a TTY attached
or under a parent that indicates interactive use.

The Falco event is ingested via `/var/log/falco/events.json` (JSON localfile
in the manager). Wazuh rule 100000 catches the base Falco event; 100001
matches the specific rule name. See
`playground/config/wazuh_cluster/rules/falco_rules.xml`.

## Alert Fields

Falco event fields come through under `data.*` in the Wazuh alert. Exact
paths depend on the Falco output format, but commonly include:

| Field | JSON Path | Description | Example |
|-------|-----------|-------------|---------|
| Falco rule | `data.rule` | Falco rule name | `Terminal shell in container` |
| Priority | `data.priority` | Falco priority | `Notice` |
| Output | `data.output` | Falco-formatted message | `A shell was spawned in a container...` |
| Process name | `data.output_fields."proc.name"` | The shell binary | `bash` |
| Parent process | `data.output_fields."proc.pname"` | Parent of the shell | `runc` |
| Command line | `data.output_fields."proc.cmdline"` | Full shell command | `bash -i` |
| User | `data.output_fields."user.name"` | User inside the container | `root` |
| Container ID | `data.output_fields."container.id"` | Short container ID | `a1b2c3d4e5f6` |
| Container name | `data.output_fields."container.name"` | Container name | `target-endpoint` |
| Container image | `data.output_fields."container.image.repository"` | Image name | `ubuntu` |
| Agent | `agent.name` | Host running Falco | `falco` |

> **Note:** Field names under `output_fields` follow Falco's dotted convention.
> Inspect a real event to confirm the exact JSON path before relying on a
> field — the structure depends on the Falco output format and version.

## Related Rules

| Rule ID | Description | Relationship |
|---------|-------------|--------------|
| 100000 | Base Falco event | Parent rule (always fires first) |
| 100002 | Redirect STDOUT/STDIN to network connection | Stronger reverse-shell signal |
| 100007 | Drop and execute new binary in container | Often correlated with post-exploitation |
| 100020 | Falco high priority unclassified | Catch-all fallback |

## Threat & Motivation

Containers are typically immutable execution units. An interactive shell
inside a running container is unusual outside of:

- Operator debugging via `docker exec` / `kubectl exec`
- CI/CD pipelines that exec into a build container
- Containers whose entrypoint or healthcheck themselves invoke a shell
- Post-exploitation activity by an attacker who reached RCE inside a container

**Blast radius if real:** The blast radius is the container's privileges plus
any escape primitives available (mounted Docker socket, privileged flag,
host path mounts, capabilities). A shell in a privileged or
host-network container is significantly higher impact than a shell in an
unprivileged sidecar.

## Known False Positives

Not yet characterized for this environment — populate from real tickets as
they accumulate. Generic categories that *typically* drive benign 100001
alerts include `kubectl exec` debugging, CI/CD pipelines, and images whose
entrypoints invoke `/bin/sh`, but the specific patterns dominant in this
environment are unknown.

## Risk Indicators

### Lower Risk
1. Parent process is a container runtime exec primitive (`runc`, `containerd-shim`,
   `docker-exec`) reachable from an operator-initiated exec
2. Container image is a known interactive/debug image
3. Shell command line is a recognizable operator pattern (e.g., `bash`, no args)
4. Originates during a known maintenance window

### Higher Risk
1. Parent process is an application binary (web server, database, etc.) — the
   app spawned a shell, which it should not do
2. Shell is `bash -i`, `sh -i`, or pipes stdout/stdin to a network socket
3. Container is privileged, has the Docker socket mounted, or runs with host
   network/PID
4. Correlated with rule 100002 (STDOUT/STDIN to network), 100006 (sensitive
   file read), or 100007 (drop-and-exec) within the same container
5. Shell appears in a long-running production container that has never had a
   shell event before

## Field Notes

- Falco's exact output field layout depends on the configured `json_output`
  format and the Falco version. Confirm field paths against a real event
  before writing rigid query templates.
- The healthcheck operations of monitoring containers can themselves trigger
  Falco events — be ready to identify and exclude known benign sources.
- Wazuh rule 100001 fires once per Falco event; Falco itself rate-limits
  duplicate events.

## Impact

A shell inside a production container is a strong post-exploitation signal
when it cannot be tied back to an operator action or automation pipeline.
Treat unattributed shells in production workloads as potentially critical
until ruled out.

## Operational Notes

To be populated from real investigations.

## Tuning Guidance

Falco's default "Terminal shell in container" rule can be tuned via macros
(`user_known_shell_in_container_activities`). Wazuh-side tuning is generally
limited to suppressing specific image/container combinations after they have
been characterized as benign.

## Detection Gaps

- Falco only sees containers it is configured to watch — host shells and
  shells in containers outside Falco's scope are invisible to this rule.
- A non-shell process executing arbitrary commands (e.g., a Python interpreter
  invoked with `-c`) does not match this rule.
- Shells started via syscalls Falco does not instrument may be missed.
