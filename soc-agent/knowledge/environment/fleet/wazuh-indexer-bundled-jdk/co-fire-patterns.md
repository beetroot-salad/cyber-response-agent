---
name: wazuh-indexer-bundled-jdk co-fire patterns
description: Known-baseline correlated-event patterns for any host running the wazuh-indexer bundled JDK sshd. Use this to discriminate benign infrastructure noise from true post-exploit signals.
---

# wazuh-indexer-bundled-jdk — correlated-event baselines

Hosts running the wazuh-indexer image execute a Java-based SSH daemon bundled from the indexer's JDK installation. This shared-layer artifact produces a set of correlated Falco events that appear adversarial-looking at first glance but are routine infrastructure signatures. Use the patterns below to contextualize co-fires on any container or VM running this image before grading refutations.

## Bundled JDK sshd

- `proc.name = sshd`
- `proc.pname = bash` (sshd spawned by the container's bash entrypoint, NOT by init/systemd)
- `proc.exepath = /usr/share/wazuh-indexer/jdk/bin/java` (the Java runtime bundled with wazuh-indexer, used by the SSH server implementation)
- `proc.cmdline = sshd` (bare, no daemon flags)
- Ancestor chain: `bash → containerd-shim → initd`

Every inbound SSH connection from the fleet (typically from `172.22.0.10` = monitoring-host) produces a cluster of `rule.id:100002` dup2 events as sshd redirects stdin/stdout to the accepted socket. This is the **normal I/O setup for a TCP SSH session**, not reverse-shell behavior.

## How to tell inbound sshd session I/O from reverse shell

Inbound sshd accept (benign, routine on this container):

- `fd.lport = 22` — local process bound to port 22 (server side)
- `fd.rport = <ephemeral>` — remote peer's source port
- `fd.sip = 172.22.0.13` — the container's own IP (wazuh-indexer-baseline-view)
- connection tuple `<remote>:<ephemeral> → 172.22.0.13:22`

Reverse shell (would be genuinely concerning):

- `fd.lport = <ephemeral>` — process dialed out from ephemeral port
- `fd.rport = <attacker listening port>`
- `fd.sip = <external / unregistered>` — destination is NOT the container's own IP
- connection tuple `172.22.0.13:<ephemeral> → <attacker>:<port>`

When grading a refutation that hinges on "reverse shell present / absent", check geometry before concluding.

## rule:100002 baseline rates for target-endpoint

Running at steady state, the container produces ~80-90 rule:100002 events per hour, all matching the inbound-sshd pattern above. A ±15min window commonly contains 20-30 such events regardless of other activity. Presence of 26 rule:100002 events in a ±15min window is **not evidence of novelty** for this container — compare against 7-day same-container baseline before grading refutations that depend on "escalation-trigger events fired."

## Co-fire patterns for rule:100001 on this container

When rule:100001 (Terminal shell in container) fires on target-endpoint, the most common co-fire is the independent rule:100002 sshd dup2 cluster (same container.id, but a distinct process lineage). The rule:100001 chain is typically `runc → bash` (host-side docker-exec); the rule:100002 chain is `bash → sshd` (unrelated in-container service). These two lineages are concurrent but structurally unrelated — do not treat rule:100002 presence as refutation of benign docker-exec unless the rule:100002 events show reverse-shell geometry (see above).

## When this pattern does NOT apply

- If `proc.exepath` on rule:100002 events is NOT `/usr/share/wazuh-indexer/jdk/bin/java` — that's a different sshd and this file's assumptions don't hold; treat as unknown.
- If rule:100002 shows `fd.lport` ephemeral and `fd.sip` pointing outside this environment's subnet — that's outbound, not inbound; this file doesn't vouch for that.
- If the ancestor chain shows `bash` without the `containerd-shim → initd` upstream path — the process is running outside the documented container infra; re-evaluate from first principles.

## Atoms

```yaml
- id: wazuh-indexer-jdk-sshd-baseline
  body: |
    Hosts running the wazuh-indexer image run a bundled-JDK sshd:
    proc.name=sshd, proc.pname=bash, proc.exepath=/usr/share/wazuh-indexer/jdk/bin/java,
    proc.cmdline=sshd, ancestor chain bash → containerd-shim → initd. This is the
    container's own SSH server, NOT a planted reverse shell. proc.exepath
    pointing elsewhere → different sshd, this baseline does not apply.
  anchors:
    mechanic: [process-exec]
    vertex_classification: [host-with-wazuh-indexer-jdk]
  valid: {from: 2026-04-25, to: 2027-04-25}
  status: live

- id: wazuh-indexer-rule-100002-dup2-baseline
  body: |
    Steady-state rule:100002 (dup2) rate on hosts running the wazuh-indexer
    image: ~80-90 events/hour, all from the bundled-JDK sshd setting up
    stdin/stdout for inbound TCP connections. A ±15min window commonly
    contains 20-30 such events independent of other activity. Counts in this
    range are NOT evidence of novelty — compare against 7-day same-host
    baseline before grading refutations that depend on "escalation-trigger
    events fired."
  anchors:
    mechanic: [process-exec]
    vertex_classification: [host-with-wazuh-indexer-jdk]
    signature_id: ["100002"]
  valid: {from: 2026-04-25, to: 2027-04-25}
  status: live

- id: wazuh-indexer-rule-100001-cofire-100002
  body: |
    When rule:100001 (Terminal shell in container) fires on a host running
    the wazuh-indexer image, the most common co-fire is the independent
    rule:100002 sshd dup2 cluster — same container.id, distinct process
    lineage. rule:100001 chain is typically `runc → bash` (host-side
    docker-exec); rule:100002 chain is `bash → sshd` (in-container service).
    Concurrent but structurally unrelated. Do NOT treat rule:100002 presence
    as refutation of benign docker-exec unless the rule:100002 events also
    show reverse-shell network geometry.
  anchors:
    mechanic: [interactive-session, process-exec]
    vertex_classification: [host-with-wazuh-indexer-jdk]
    signature_id: ["100001", "100002"]
  valid: {from: 2026-04-25, to: 2027-04-25}
  status: live

- id: wazuh-indexer-reverse-shell-geometry-discriminator
  body: |
    To distinguish inbound sshd I/O from a reverse shell on a wazuh-indexer
    host, check the connection tuple:
      - inbound sshd accept (benign): fd.lport=22, fd.rport=ephemeral,
        fd.sip=<container's own IP>; tuple <remote>:<eph> → <self>:22
      - reverse shell (concerning): fd.lport=ephemeral, fd.rport=<attacker>,
        fd.sip=<external/unregistered>; tuple <self>:<eph> → <attacker>:<port>
    Always check geometry before grading refutations that hinge on
    "reverse shell present / absent."
  anchors:
    mechanic: [network-connect]
    vertex_classification: [host-with-wazuh-indexer-jdk]
  valid: {from: 2026-04-25, to: 2027-04-25}
  status: live
```
