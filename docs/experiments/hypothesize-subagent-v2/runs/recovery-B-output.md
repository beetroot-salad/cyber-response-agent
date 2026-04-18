---
run: recovery-B
task: loop-2 recovery after partial-coverage lead failure (DNS high-entropy subdomain)
signature: wazuh-rule-100110
loop: 2
---

# Recovery-B output

## Chosen block

```yaml
gather:
  - id: l-002
    loop: 2
    name: query-history-for-parent
    target: v-queried-domain
    predictions:
      - {id: lp1, if: "≤2 distinct subdomains under svc-edge.net from any host in last 30 days", read_as: "sparse-footprint", advance_to: subdomain-shape}
      - {id: lp2, if: "≥3 distinct subdomains under svc-edge.net from multiple hosts, varied but low-volume and spread over days", read_as: "distributed-low-volume", advance_to: subdomain-shape}
      - {id: lp3, if: "sustained high-volume or bursty cluster of distinct subdomains under svc-edge.net from web-app-11 alone in a short window (minutes to hours)", read_as: "concentrated-high-rate", advance_to: HYPOTHESIZE}
```

Selected lead: `query-history-for-parent`

Pitfalls:
- Established multi-host footprint (known from loop-1 environment context) biases toward lp2, but multi-host spread is also consistent with a widely deployed C2 beacon — do not read lp2 as benign; it advances to subdomain-shape for further discrimination.
- lp3 advance_to HYPOTHESIZE is warranted because a concentrated high-rate cluster from one host would open the ?dns-channel / ?candidate-probing fork on observable fields; do not collapse it to subdomain-shape, which is insufficient to discriminate at volume.

---

## Recovery rationale

**Why GATHER on `query-history-for-parent`, not the other options:**

**Retry `parent-domain-classification`** is a non-starter. The failure was an external allowlist service timeout, not a transient SIEM connectivity issue. Retrying the same lead against the same unavailable service produces the same partial-coverage result. There is no new information to gain.

**`data-source-debug`** is the wrong tool. That lead is designed to diagnose SIEM query failures — wrong field names, index unavailability, event-absent data sources. The partial coverage here came from a reputation API timeout outside the SIEM. The SIEM itself returned data; only the enrichment layer timed out. Running data-source-debug would investigate the wrong failure mode.

**HYPOTHESIZE** is blocked by discipline. The rule is: no HYPOTHESIZE without a fork whose predictions diverge on **already-observable** fields. After loop-1, what is observable?

- `svc-edge.net` is not in known-malicious lists (partial result confirmed this).
- `svc-edge.net` has established multi-host footprint (environment context, available now).
- The allowlist classification (CDN / cloud / analytics / other) is **unknown** — that is the exact fact the failed lead was meant to resolve.

The lp1-vs-lp3 distinction (known-allowlisted vs. known-but-not-allowlisted) is still unresolvable. The three mechanism seeds (`?one-shot-resolution`, `?candidate-probing`, `?dns-channel`) cannot be forked on these attributes alone — they split on query-volume, subdomain-count, NXDOMAIN rate, and cadence, none of which has been measured yet. No observable fork exists; HYPOTHESIZE would be speculative.

**`query-history-for-parent` directly** is the right move. The loop-1 lp2 and lp3 branches both had `advance_to: query-history-for-parent`. The loop-1 failure did not invalidate those routing instructions — it merely prevented us from knowing *which* of lp2/lp3 fired. But lp1 (known-allowlisted) is the only branch that would have bypassed this lead, and lp1 is the one that is unresolvable (not confirmable without the allowlist service). The partial result rules out the "known-malicious" reading; lp1-vs-lp3 ambiguity is real but both advance to the same next lead anyway. Dispatching `query-history-for-parent` now is consistent with every non-lp1-confirmed path.

**The partial evidence shapes the new predictions.** Because multi-host footprint is already known from environment context, lp1 (sparse footprint — only 1–2 distinct subdomains ever) is still structurally live but less likely. The three predictions above are ordered by footprint density and advance to subdomain-shape for the low-to-moderate cases (which need label-shape analysis to discriminate mechanism) and directly to HYPOTHESIZE for the concentrated-high-rate case (which is itself discriminating — it opens the ?dns-channel / ?candidate-probing fork on observable volume fields).
