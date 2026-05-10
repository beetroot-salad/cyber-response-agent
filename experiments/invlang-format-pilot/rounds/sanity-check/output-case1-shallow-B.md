```yaml
gather:
  - id: l-001
    loop: 1
    name: source-classification
    target: v-src-ip-172.22.0.10
    predictions:
      - {id: lp1, if: "classifies as internal-monitoring-host", read_as: "sanctioned-automation-source-candidate", advance_to: authentication-history}
      - {id: lp2, if: "classifies as internal-other with no monitoring-host match", read_as: "unsanctioned-internal-source", advance_to: authentication-history}
      - {id: lp3, if: "classifies as external", read_as: "external-origin", advance_to: authentication-history}
```

Selected lead: `source-classification` — map `data.srcip` (172.22.0.10) against `environment/context/ip-ranges.md`. The source classification partitions the archetype space (monitoring-probe / service-account-rotation vs. credential-stuffing / external-bruteforce) before any mechanism fork is articulable; the CONTEXTUALIZE archetype-scan's "internal monitoring host" assertion needs grounding against the ip-ranges reference before it carries weight.

Pitfalls:
- l-001: `ip-ranges.md` classification is necessary but not sufficient for sanctioning — an internal-monitoring-host classification says "this subnet hosts monitoring infrastructure", not "this (srcip, srcuser, target) triple is authorized". Do not conflate a passing source classification with a passing `approved-monitoring-sources` anchor; the anchor lookup is a separate later step bound to the `attempted_auth` edge's `legitimacy_contract`.
- l-001: an adversary with a foothold inside the monitoring subnet would inherit the `internal-monitoring-host` classification trivially; source classification alone never resolves benign — it only narrows which half of the archetype catalog applies, with cadence shape and forward-success still required to discriminate `monitoring-probe` from an adversarial reuse of a sanctioned source.
