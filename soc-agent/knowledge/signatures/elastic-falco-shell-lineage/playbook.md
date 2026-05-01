---
signature_id: elastic-falco-shell-lineage
last_updated: 2026-04-30
total_investigations: 0
resolution_rate: null
---

# Investigation Playbook: Falco Attack-Lineage Rule (elastic-falco-shell-lineage)

This playbook is **steering, not procedure**. The investigation methodology
— hypothesis discipline, lead severity, verification and scoping, escalation
defaults, stop conditions — lives in the `investigate` skill. This file
provides only what is signature-specific:

- Field shortcuts so the agent doesn't query for what the alert already carries
- Named archetypes the agent should try to recognize
- A recommended starter lead order
- Composition rules when multiple co-firing rules appear
- Quirks of this signature that aren't general investigation lessons

## Field shortcuts

| Field | JSON path |
|---|---|
| Falco rule name | `falco.rule` |
| Acting process | `falco.output_fields.proc.name` |
| Parent process | `falco.output_fields.proc.pname` |
| Process ancestry | `falco.output_fields.proc.aname[2..n]` |
| Full cmdline | `falco.output_fields.proc.cmdline` |
| Touched file | `falco.output_fields.fd.name` |
| Container ID | `falco.output_fields.container.id` |
| Container image | `falco.output_fields.container.image.repository` |
| MITRE tags | `falco.tags` |
| VPS host | `host.name` |

`host.name` is the VPS running Falco, NOT the attacked container's assigned
host. Use `container.id` / `container.image.repository` for per-workload
scoping. `pname` is the *parent*; `proc.name` is the acting binary — mixing
them inverts the story. See `field-quirks.md` for the full field gotchas.

## Hypothesis seeds

The alert confirms a process event inside a container that Falco's rule
engine classified as attack-lineage. The discriminating question is the
**parent process mechanism** — three mutually-exclusive options, read from
`pname` / `aname` in the alert fields:

- **`?image-entrypoint`** — parent is the image's entrypoint / init wrapper
  (`tini`, `dumb-init`, `s6`, `supervisord`, custom launcher). Shell spawning
  during container start — typically benign but requires confirmation against
  the image's established startup sequence.
- **`?in-namespace-app`** — parent ancestry walks back to the container's
  PID 1 entirely inside the pid namespace (long-running app or its
  descendants). Could be the app shelling out legitimately or an attacker
  controlling that process via RCE.
- **`?underlying-host`** — parent ancestry crosses the namespace boundary
  at a runtime exec primitive (`runc`, `containerd-shim`, `docker exec`,
  `crictl exec`, `crio`, `oc exec`, kubelet exec path). Operator or
  CI/CD-driven exec — legitimacy is the anchor question, not mechanism.

Legitimacy (authorized operator vs. attacker controlling the same process
level) is a trust-anchor attribute on the confirmed parent, not a separate
hypothesis. The `correlated-endpoint-events` lead runs regardless as
evidence, captured in the composition rule below.

## Archetypes

Archetypes are a pattern-recognition *cache* — they carry trust-anchor
definitions and precedent snapshots for the dispositions that commonly follow
each mechanism. Each archetype lives under exactly one of the three mechanism
seeds above.

**Note: archetype directories for this signature are TODO — they require at
least one completed investigation run per archetype before the `required_anchors`
are testable and `{TICKET-ID}.json` snapshots can be captured. The catalog
below mirrors `wazuh-rule-100001` (the Wazuh analog) and will be populated
in a follow-up pass once Phase 3 investigation runs complete.**

| Archetype | Parent mechanism | One-line description | Directory |
|---|---|---|---|
| `container-init-script` | `?image-entrypoint` | The image's own entrypoint or init script invokes a shell at container start | `archetypes/container-init-script/` (TODO) |
| `app-spawned-shell` | `?in-namespace-app` | A long-running application binary shells out (or fetches/decodes a payload) as part of its normal work, matching this image's established baseline | `archetypes/app-spawned-shell/` (TODO) |
| `post-exploit-interactive` | `?in-namespace-app` | Application-spawned attack-lineage event (interactive shell, ingress copy, payload decode) with no benign baseline — escalation outcome | `archetypes/post-exploit-interactive/` (TODO) |
| `operator-runtime-debug` | `?underlying-host` | Authorized operator opened a shell via `docker exec` / `kubectl exec` for ad-hoc debugging | `archetypes/operator-runtime-debug/` (TODO) |
| `ci-pipeline-exec` | `?underlying-host` | CI/CD job exec'd into the container to run a scripted, non-interactive command | `archetypes/ci-pipeline-exec/` (TODO) |

## Contextualize leads

Run in parallel at CONTEXTUALIZE time before SCREEN/PREDICT — mechanically
enriching the prologue vertices with classification context every downstream
phase reads.

- `endpoint-context` — runs once per container vertex, deriving the
  classification label from IP-ranges context and attaching any CMDB record.
- `identity-context` — runs once per user vertex (typically `root` or a
  container-runtime UID). IdP record is usually empty for container-runtime
  identities; classification still resolves (e.g., `container-runtime-uid0`),
  which lets PREDICT discriminate authorized-runtime-exec from privilege-
  escalation without dispatching a separate lead.

## Starter lead order

1. **`shell-context`** — read `falco.rule`, `pname`, `cmdline`,
   `container.image.repository`, and `container.id` from the alert directly
   (no query needed). The Falco rule name alone narrows the mechanism family;
   `pname` and `aname` pick the parent-mechanism seed. Most archetypes are
   recognizable from these fields alone; subsequent leads only refine.

2. **`container-baseline`** — query `logs-falco.alerts-default` for events
   matching the same `container.image.repository` over the last 7–30 days.
   Surfaces whether this image has a history of this rule firing from this
   parent (benign baseline vs. novel). Filter:
   ```
   event.dataset: "falco.alerts"
   AND falco.output_fields.container.image.repository: "<image>"
   AND falco.rule: "<rule>"
   ```
   Use the Elastic CLI:
   ```bash
   python3 scripts/tools/elastic_cli.py query \
     'event.dataset: "falco.alerts" AND falco.output_fields.container.image.repository: "<image>" AND falco.rule: "<rule>"' \
     --start <7d-ago> --limit 100 --run-dir <run-dir>
   ```

3. **`correlated-endpoint-events`** — query `logs-falco.alerts-default` for
   all Falco rules from the same `container.id` in a ±15 minute window around
   the alert timestamp. Required by the composition rules below.
   ```bash
   python3 scripts/tools/elastic_cli.py query \
     'event.dataset: "falco.alerts" AND falco.output_fields.container.id: "<id>"' \
     --start <alert_time-15m> --end <alert_time+15m> --limit 200 --run-dir <run-dir>
   ```

**Composite dispatch:** leads 2 and 3 share the same `container.id` and
overlap in window. If lead 1 alone does not uniquely characterize the parent
mechanism, dispatch leads 2 and 3 as a composite — one subagent, one expanded
base query.

## Composition rules

When evidence matches multiple disposition shapes, the composition is the
finding — escalate citing each matching shape, do not pick one.

**Any benign-shaped match + co-firing of attack-lineage rules in the same
`container.id` window is severe regardless of the otherwise-benign shape.**
If `correlated-endpoint-events` returns any of the following from the same
container within ±15 minutes, escalate immediately and cite both the matched
benign shape and the co-firing rule(s):

- `Launch Ingress Remote File Copy Tools in Container` — payload fetch via
  curl/wget/scp
- `Decoding Payload in Container` — base64 decode of fetched content
- `Drop and execute new binary in container` — new executable staged in /tmp
- `Adding ssh keys to authorized_keys` — persistence installation
- `Write below root` — writes to system directories
- `Modify Shell Configuration File` — shell init file modification

This applies even when an anchor confirms the benign match. A confirmed
`operator-runtime-debug` accompanied by `Decoding Payload in Container` in
the same window is strong evidence that the authorized credentials were
compromised — the anchor confirmation does not override the co-firing.

The composition that carries the batch-10 attack shapes specifically:
- **living-off-the-land** fires `Launch Ingress Remote File Copy Tools in
  Container` + `Decoding Payload in Container` in sequence on the same
  `container.id`. Either rule alone would require baseline comparison; both
  in sequence always escalates.
- **persistence-authorized-keys** fires `Adding ssh keys to authorized_keys`
  as a standalone event. No baseline comparison required — this rule class
  has no benign exemption in any known archetype.

## Benign action classes

Commands whose body, executed in isolation, cannot damage or exfiltrate data.
When the alert's cmdline body is on this list, every adversarial-archetype
hypothesis is below `++`, and exhaustion at `termination_category: trust-root`
routes `disposition: inconclusive` rather than escalating by exhaustion alone.

Strip the shell wrapper (`bash -c`, `sh -c`) before comparing:

- `whoami`, `id`, `hostname`, `uname` (any flags)
- `pwd`, `ls` (any flags, any path)
- `ps` (any flags)
- `cat /etc/os-release`, `cat /proc/version`, `cat /etc/hostname`, `cat /etc/resolv.conf`
- `df` (any flags), `free` (any flags), `uptime`, `date`
- `env` (no arguments — list only)

Cite the short-circuit explicitly in the report rationale when it fires.

## Signature quirks

- **Falco only sees containers it watches.** Absence of prior Falco events
  for an image might mean "first time" or "Falco isn't watching it." The
  `container-baseline` lead must distinguish via Falco's coverage data, not
  by inferring from silence alone.
- **`container.name` may be `<NA>`** for containers running before Falco's
  container plugin attached (v0.6.4 limitation). Use `container.id` + an
  out-of-band lookup for per-host attribution; never key a disposition on
  `container.name`.
- **`host.name` is the VPS, not the attacked workload.** Every Falco event
  carries the VPS's hostname regardless of which container triggered it. Use
  `falco.output_fields.container.*` for per-workload scoping.
- **`falco.output_fields` is nested.** The integration's `decode_json_fields`
  processor converts Falco's dotted top-level keys into a nested object. Query
  `falco.output_fields.container.id`, not the dotted string form.
- **Multiple rules can fire on the same syscall.** A single `curl` invocation
  can trigger both `Launch Ingress Remote File Copy Tools in Container` and
  `Unexpected Outbound Connection` (or similar). Deduplicate by syscall
  timestamp + cmdline before counting distinct "attack steps."
- **`Adding ssh keys to authorized_keys` has no benign exemption in this
  environment.** The playground bakes SSH keys into images at build time, not
  at runtime. A runtime write to `authorized_keys` is adversarial-by-shape
  unless an authorized operator can produce a timestamped ticket.

## Scope

Standard for this signature: the alerting Falco event, other Falco events
from the same `container.id` in ±15 minutes, and other alerts from the same
agent in the last 24 hours (the latter is provided by ticket-context at
CONTEXTUALIZE — don't re-query). Anything beyond this requires escalation
per the skill's stay-in-scope rule.
