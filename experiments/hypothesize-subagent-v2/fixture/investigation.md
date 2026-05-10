# Investigation: wazuh-rule-5710 / alert-fixture-v2-01

## CONTEXTUALIZE

**Alert summary.** Single SSH invalid-user attempt on `app-web-07` (10.30.12.88) from internal source `10.30.18.42`, attempted username `root`. Rule 5710, level 5, at 2026-04-18T14:22:17Z.

**Prologue vertices/edges (canonical):**

- `v-src-ip-10.30.18.42` — type: ip
- `v-dst-host-app-web-07` — type: host
- `v-attempted-user-root` — type: username (as-string)
- `e-attempted-auth-01` — type: `attempted_auth`; source: `v-src-ip-10.30.18.42`; target: `v-dst-host-app-web-07`; identity: `v-attempted-user-root`; timestamp: 2026-04-18T14:22:17Z; outcome: failed (non-existent user)

**Environment readiness.** Wazuh indexer: reachable. Auth log pipeline: reachable. All leads' data sources available.

**Ticket-context correlation (4h window on `10.30.18.42` and `app-web-07`).** No prior tickets on either entity in the last 4 hours. No sibling 5710 events from the same srcip in the 4h window. No 5501 / 5715 success events on `app-web-07` in the last 4 hours.

**Archetype scan (ranked against the alert's shape):**

```yaml
archetype_scan:
  - archetype: credential-stuffing
    required_anchors: []
    disqualifiers:
      - "source IP is a known internal range with no external egress"
      - "attempted username is a documented sentinel (probe, healthcheck) rather than a real-looking human username"
    story_match: "weak — attempted username 'root' is a generic privileged account commonly used in breach-dump lists, but the source IP 10.30.18.42 is internal, which cuts against the external-breach story"
    boundary_note: "source is internal, which the story explicitly excludes"

  - archetype: external-bruteforce
    required_anchors: []
    disqualifiers:
      - "source IP is internal"
      - "only a single attempt observed in the alert window"
    story_match: "weak — 'root' matches the wordlist shape, but volume is 1 and source is internal"
    boundary_note: "volume and source both fail the story"

  - archetype: monitoring-probe
    required_anchors: [approved-monitoring-sources]
    disqualifiers:
      - "attempted username is not in the sentinel list (nagios, zabbix, prometheus, healthcheck, monitorprobe, sensu, testuser, probe)"
      - "source IP is not in the approved-monitoring-sources registry"
    story_match: "weak — source is internal but the attempted username 'root' is not a sentinel; the single-shot cadence fits the story but the identity does not"
    boundary_note: "attempted username is explicitly out-of-story"

  - archetype: service-account-rotation
    required_anchors: [scheduled-jobs]
    disqualifiers:
      - "attempted username is not a service-account-pattern name"
      - "no corresponding scheduled-job entry for the (source, username, target) triple"
    story_match: "weak — 'root' is not a service-account-pattern name; no automation shape evident"
    boundary_note: "identity shape fails the story"

adversarial_archetype:
  archetype: credential-stuffing
  required_anchors: []
  story_match: "weak — the single-attempt shape is atypical for stuffing, but 'root' being attempted from an internal IP could also be a post-compromise lateral probe, which is the most severe framing available in this signature's catalog"
  reason: "for 5710, the worst outcome is an authenticated adversary already inside the network using a foothold to probe for privileged accounts on adjacent hosts; lateral credential-guessing from an internal source fits credential-stuffing's 'worst-case' semantics better than external-bruteforce when the source is already internal"
```

**ASSESS decision.** The hypothesis space forks:
- No archetype matches strongly — all four score weak.
- The source is internal (10.30.18.42), which rules out the two external archetypes as-literally-defined but opens a lateral-movement reading.
- The attempted username `root` is generic, not a sentinel, not a service-account pattern — which rules out the two benign archetypes as-literally-defined.
- Competing one-hop classifications of the upstream process initiating `e-attempted-auth-01` are plausible and predict different observables.

Proceed to HYPOTHESIZE.
