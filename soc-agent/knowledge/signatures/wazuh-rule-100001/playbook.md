---
signature_id: wazuh-rule-100001
last_updated: 2026-04-09
total_investigations: 0
resolution_rate: null
---

# Investigation Playbook: Terminal shell in container (100001)

This playbook is **steering, not procedure**. The investigation
methodology — hypothesis discipline, lead severity, verification and
scoping, escalation defaults, stop conditions — lives in the
`investigate` skill. This file provides only what is signature-specific:

- Field shortcuts so the agent doesn't query for what the alert already
  carries
- Named archetypes the agent should try to recognize, each defined in
  `archetypes/`
- A recommended starter lead order
- Composition rules when multiple archetypes match
- Quirks of this signature that aren't general investigation lessons

## Field shortcuts

| Field | JSON path |
|---|---|
| Parent process | `data.output_fields.proc.pname` |
| Process ancestry | `data.output_fields.proc.aname[2..n]` |
| Container image | `data.output_fields.container.image.repository` |

`pname` is easy to misread as "process name" — it's the parent. `aname`
is the ancestry walk for cases where `pname` itself is a shell or
interpreter and you need to walk further up. Container image carries
the registry prefix that the `container-baseline` lead keys on.

`proc.tty != 0` is **always true** on every 100001 alert by
construction of the upstream Falco rule. Do not treat it as a
discriminating signal.

## Hypothesis seeds

The alert confirms a child shell `process` vertex with a `spawned`
edge from its parent. The discriminating question is the parent's
process-topology mechanism — three mutually-exclusive options, read
directly from `pname` / `aname` in the alert:

- **`?image-entrypoint`** — parent is the image's entrypoint / init
  wrapper (`tini`, `dumb-init`, `s6`, supervisord, custom launcher).
- **`?runtime-process`** — parent ancestry walks back to the
  container's PID 1 entirely inside the pid namespace (long-running
  app or its descendants).
- **`?underlying-host`** — parent ancestry crosses the namespace
  boundary at a runtime exec primitive (`runc`, `containerd-shim`,
  `docker-exec`, `crictl`, `crio`, `oc exec`, kubelet exec path).

Legitimacy (approved operator vs. RCE attacker spawning a shell from
the same process) is a trust-anchor attribute on the confirmed
parent, not a separate hypothesis. The `correlated-endpoint-events`
lead runs regardless as evidence, captured in the composition rule
below.

## Archetypes

The archetypes below are a pattern-recognition *cache* — they carry
trust-anchor definitions and precedent snapshots for the dispositions
that commonly follow each mechanism. They are not a parallel seed
list; each archetype lives under exactly one of the three mechanism
seeds above.

| Archetype | Parent mechanism | One-line description | Directory |
|---|---|---|---|
| `container-init-script` | `?image-entrypoint` | The image's own entrypoint or init script invokes a shell at container start | `archetypes/container-init-script/` |
| `app-spawned-shell` | `?runtime-process` | A long-running application binary shells out as part of its normal work, matching this image's established baseline | `archetypes/app-spawned-shell/` |
| `post-exploit-interactive` | `?runtime-process` | Application-spawned shell with no benign baseline — escalation outcome | `archetypes/post-exploit-interactive/` |
| `operator-runtime-debug` | `?underlying-host` | Authorized operator opened a shell via `docker exec` / `kubectl exec` for ad-hoc debugging | `archetypes/operator-runtime-debug/` |
| `ci-pipeline-exec` | `?underlying-host` | CI/CD job exec'd into the container to run a scripted, non-interactive command | `archetypes/ci-pipeline-exec/` |
| `k8s-exec-probe` | `?underlying-host` | Kubernetes liveness/readiness/exec probe runs `sh -c "..."` on a strict cadence | `archetypes/k8s-exec-probe/` |

## Contextualize leads

These run in parallel at CONTEXTUALIZE time, before SCREEN/PREDICT —
mechanically enriching the prologue vertices with classification +
authoritative-record context that every downstream phase reads.

- `endpoint-context`
- `identity-context`

`endpoint-context` runs once per endpoint vertex (the container/host the
shell spawned in), deriving the classification label from the IP-ranges
context file and attaching the CMDB record. `identity-context` runs once
per identity vertex (the in-container user, e.g. `root`); on this rule
the IdP record is typically empty since the user is a container runtime
identity, not a directory-managed account, and `loginuid=-1` means no
upstream login session is present. Classification still resolves (the
identity-pattern file recognizes `root` as `container-runtime-uid0` or
similar), which lets PREDICT discriminate authorized-runtime-exec
from a privilege-escalation chain without dispatching a separate lead.

## Starter lead order

Most investigations resolve after the first two leads. The third only
runs when the composition rules below need checking, or when the
picture is still ambiguous after lead 2.

1. **`shell-context`** — read parent process, cmdline, container image,
   and user from the alert directly (no query needed). This alone is
   enough to recognize most archetypes; the rest of the leads only
   refine.
2. **`container-baseline`** — query other 100001 events from the same
   `container.image` over the last 7-30 days. Surfaces whether this
   image has a history of shells from this parent (the benign-baseline
   vs no-baseline discriminator) and whether the cadence matches a
   recurring scheduled-probe shape.
3. **`correlated-endpoint-events`** — query Falco rules 100000-100099 from
   the same `container.id` in a ±15 minute window, especially 100002,
   100006, 100007, and 100008. Required by the composition rules below.

**Composite dispatch:** leads 2 and 3 share the same `container.id`
and overlap in window. If lead 1 alone does not uniquely characterize
the parent mechanism, dispatch leads 2 and 3 as a composite — one
subagent, one expanded base query.

## Composition rules

When evidence matches multiple disposition shapes, the composition is
the finding — escalate citing each matching shape, do not pick one.

The composition that matters for this signature:

**Any benign-shaped match + co-firing of related Falco rules in the
same `container.id` window is severe regardless of the
otherwise-benign shape.** If the `correlated-endpoint-events` lead
returns any of the following from the same container within ±15
minutes, escalate immediately and cite both the matched benign shape
and the co-firing rule(s):

- 100002 — Redirect STDOUT/STDIN to network connection
- 100006 — Sensitive file read
- 100007 — Drop and execute new binary
- 100008 — Log clearing

This applies even when an anchor confirms the benign match. A
confirmed authorized-runtime-exec accompanied by 100007 in the same
window is the strongest possible evidence that the authorized
credentials were compromised — the anchor confirmation does not
override the co-firing.

## Benign action classes

Commands whose body, executed in isolation, cannot damage or exfiltrate
data. CONCLUDE consults this list at trust-root: when the alert's
command body is on the list, every adversarial-archetype hypothesis is
below `++`, and the investigation has reached `termination_category:
trust-root` (no further upstream authority is reachable), disposition
routes `inconclusive` rather than escalating to `true_positive` by
exhaustion alone.

The body is the argument to `bash -c`, `sh -c`, or the direct argv
when no shell is invoked — strip the shell wrapper before comparing.

- `whoami`
- `id`
- `hostname`
- `uname` (any flags)
- `pwd`
- `ls` (any flags, any path)
- `ps` (any flags)
- `cat /etc/os-release`
- `cat /proc/version`
- `cat /etc/hostname`
- `cat /etc/resolv.conf`
- `df` (any flags)
- `free` (any flags)
- `uptime`
- `date`
- `env` (no arguments — listing env vars only, not setting them)

Exhaustion-by-trust-root with a benign command body is a real failure
mode: the agent runs out of upstream authority to consult and routes
`true_positive` because no anchor closed the authorization contract.
For a non-damaging command, that exhaustion is not evidence of
compromise — it is the limit of available telemetry. Cite the
short-circuit explicitly in the report rationale when it fires.

## Signature quirks

- **Falco only sees containers it watches.** Containers outside Falco's
  configured scope are invisible to this rule. Absence of prior events
  for an image *might* mean "first time" or *might* mean "Falco isn't
  watching it." The `container-baseline` lead must distinguish via
  Falco's coverage data, not by inferring from silence alone.
- **The `user_known_shell_in_container_activities` macro suppresses
  matches.** Anything on Falco's exception list never fires this rule,
  so absence of an alert is not evidence the activity didn't happen.
- **Container privileges are scoping evidence, not a discriminator.**
  Privileged containers, Docker-socket mounts, host network, host PID
  raise severity if the matched shape escalates, but they do not
  change which shape matches. Capture them when escalating for
  accurate blast-radius reporting.
- **Apps shelling out is normal.** `pname=<application binary>` is not
  a standalone red flag — `subprocess.run`, build hooks, image
  processing wrappers, log rotation, and many other legitimate things
  all produce shells whose parent is the application binary. The
  discriminating signal is whether this image has done it *before*
  (the baseline anchor on the runtime-process mechanism).

## Scope

Standard for this signature: the alerting Falco event, other Falco
events from the same `container.id` in ±15 minutes, and other alerts
from the same agent in the last 24 hours (the latter is provided by
ticket-context at CONTEXTUALIZE — don't re-query). Anything beyond
this requires escalation per the skill's stay-in-scope rule.
