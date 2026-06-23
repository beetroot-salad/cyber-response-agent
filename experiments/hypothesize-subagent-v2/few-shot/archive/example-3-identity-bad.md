# Example 3 — identity, loop 1 (negative)

Signature: `wazuh-rule-5710`. Loop 1 HYPOTHESIZE. Shows the narrative-
umbrella failure mode and premature HYPOTHESIZE entry.

## Alert

```
rule.id:       5710
data.srcip:    172.16.8.42          # internal RFC1918
data.srcuser:  admin
agent.name:    app-db-01
timestamp:     2026-04-18T14:22:17Z
```

## State at entry

Prologue confirms `v-src-ip-172.16.8.42`, `v-dst-host-app-db-01`,
`v-attempted-user-admin`, and the failed `attempted_auth` edge.
ticket-context: no prior 5710 on this srcip in 4h; no 5501/5715 on
target in 4h. Archetype scan: all four rule-5710 archetypes score
**weak**. No lead has run. Starter leads queued: `source-classification`,
`username-classification`, `authentication-history`.

## Bad HYPOTHESIZE output

```yaml
hypothesize:
  hypotheses:
    - id: h-001
      name: "?credential-guessing"
      attached_to_vertex: e-attempted-auth-01
      proposed_edge:
        relation: initiated_by
        parent_vertex:
          type: process
          classification: adversarial-credential-attack
      predictions:
        - id: p1
          claim: "172.16.8.42 is not in approved-monitoring-sources"
        - id: p2
          claim: "admin classifies as wordlist-common"
        - id: p3
          claim: "additional failed attempts from this srcip in the
            5-min window"
        - id: p4
          claim: "no successful login from this srcip in the forward
            60-sec window"
      weight: null
    - id: h-002
      name: "?authentication-mistake"
      # ... 3 predictions: isolated volume + forward success within
      #     60s with a different username + admin is close to a real
      #     account
    - id: h-003
      name: "?compromise-followup"
      # ... parallel adversarial hypothesis attached to a future
      #     5501/5715 edge
```

## Why this fails (five labeled defects)

**1. Narrative umbrellas.** `?credential-guessing` packs source-trust
attribute + username shape + edge-cluster shape + forward-window
attribute into one label with an intent suffix. Four separate attributes
on three different vertices, all under one name. `?authentication-
mistake` has the same defect.

**2. Violates ≤2 predictions.** h-001 has 4 predictions, h-002 has 3.
Per §HYPOTHESIZE Leanness: a third prediction signals an unlean
hypothesis — split or defer.

**3. Conflates mechanism with legitimacy.** The `?credential-guessing`
vs. `?authentication-mistake` framing mixes mechanism-topology (what
upstream process initiated the attempt) with legitimacy-attribute (is
that process sanctioned). Per the rule-5710 playbook rewrite
(2026-04-18), these are orthogonal — mechanism is topology; legitimacy
is anchor-resolved at disposition time.

**4. Parallel adversarial hypothesis.** `?compromise-followup` doubles
the frontier without adding a topology distinction. Forward-window
success is a mandatory attribute check inside `authentication-history`,
not a hypothesis slot. (See `docs/decisions/adversarial-as-attribute-not-
hypothesis.md` for the SKILL.md-level reframe this depends on.)

**5. Premature HYPOTHESIZE entry.** Before `source-classification` has
run, no mechanism fork is observable. Per §ASSESS reclassification cue:
name ≥2 competing one-hop classifications whose predictions diverge, or
stay in the mechanical / interpretive lane. The good output omits
`## HYPOTHESIZE` entirely at loop 1 and uses lead-level predictions:

```yaml
gather:
  - id: l-001
    loop: 1
    name: source-classification
    target: v-src-ip-172.16.8.42
    predictions:
      - id: lp1
        if: "classifies as internal-monitoring-host"
        read_as: sanctioned-automation-source
        advance_to: username-classification
      - id: lp2
        if: "classifies as internal-other with no registry match"
        read_as: unsanctioned-or-unregistered-source
        advance_to: authentication-history
      - id: lp3
        if: "classifies as external"
        read_as: external-origin
        advance_to: authentication-history
```

HYPOTHESIZE only enters later if enrichment leaves disposition
ambiguous (e.g., internal-other source + generic-privileged username
like `admin`/`root`/`ubuntu`); the fork that opens is legitimacy-
attribute-shaped (`?sanctioned-but-unregistered` vs. `?unsanctioned-
origin`), not narrative-umbrella-shaped.
