<!-- HYPOTHESIZE skipped: no lead has run. Alert fields (srcip, srcuser, target, outcome) name the confirmed vertices but do not discriminate between competing upstream classifications — source-classification, authentication-history, and username-classification are the discriminating leads, not already-observable attributes. Entry discipline requires ≥2 competing classifications with predictions that diverge on already-observable fields; that condition is not met here. Emitting GATHER with lead-level predictions instead. -->

```yaml
gather:
  - id: l-001
    loop: 1
    name: source-classification
    target: v-src-ip-10.30.18.42
    predictions:
      - id: lp1
        if: "classifies as approved-monitoring-source (registry match for 10.30.18.42)"
        read_as: "sanctioned-automation-source — expected probe shape, identity mismatch still requires username-classification"
        advance_to: username-classification
      - id: lp2
        if: "classifies as internal-infrastructure (known internal asset, no monitoring-source registry entry)"
        read_as: "unsanctioned-or-unregistered-internal-origin — opens lateral-movement framing"
        advance_to: authentication-history
      - id: lp3
        if: "classifies as unknown-or-unregistered (no asset record for 10.30.18.42)"
        read_as: "shadow asset or recently provisioned host — ambiguous, escalate to authentication-history for volume"
        advance_to: authentication-history
```

Selected lead: `source-classification` — resolves the upstream vertex classification fork (sanctioned-automation vs. unsanctioned-internal) that all subsequent hypothesis formation depends on. Single dispatch.

Pitfalls:
- A monitoring host that recently changed IP may appear unregistered while still being sanctioned; a registry miss alone is not sufficient to classify as adversarial — cross-check asset DB before advancing to authentication-history framing.
- An internal host that has been compromised retains its legitimate asset record; a registry hit does not clear the lateral-movement framing — username-classification and authentication-history must still run even on lp1 outcome.
