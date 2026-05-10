## CONTEXTUALIZE

**Alert:** 1777226650.70 — Zeek: sustained outbound TLS volume from internal host
**Key observables:**
- src: ci-runner-04 / 10.0.18.41 (internal CI runner)
- dst: 185.220.101.7:443 (TLS, ssl.server_name=cdn.staticfiles.example.org)
- conn duration: 4187s (~70 min)
- orig_bytes: 27.4 GB outbound, resp_bytes: 41 MB inbound (asymmetric, classic exfil shape)
- 5-min window egress: 6.2 GB
- timestamp: 2026-04-25T22:04:10.700Z
**Playbook hypotheses:** ?package-cache-warm, ?ci-artifact-upload, ?credentialed-exfil, ?cdn-mirror-pull
**Available leads:** host-egress-baseline, dst-reputation, ci-job-correlation, ssl-jarm-fingerprint, internal-process-attribution
**Archetype matches:**
- ci-artifact-upload — candidate — CI runners legitimately push large artifacts; asymmetric byte ratio is normal for upload jobs.
- credentialed-exfil — candidate — large outbound from a CI runner with persistent credentials is a textbook supply-chain exfil shape.
- cdn-mirror-pull — ruled-out — pull would be inbound-asymmetric, not outbound.
**Adversarial archetype:** credentialed-exfil — worst-case is an attacker on the runner is staging artifacts to a controlled CDN-shaped destination.
**Data environment:** reachable: zeek, host_query, ci_orchestrator_api, threat_intel, playground_ticket; degraded: none

```yaml
prologue:
  vertices:
  - id: v-001
    type: endpoint
    classification: internal-ci-runner
    identifier: 10.0.18.41
    attributes:
      hostname: ci-runner-04
  - id: v-002
    type: external_endpoint
    classification: external-ip
    identifier: 185.220.101.7
    attributes:
      port: 443
      ssl_server_name: cdn.staticfiles.example.org
  edges:
  - id: e-001
    relation: opened_tls_connection
    source_vertex: v-001
    target_vertex: v-002
    when:
      timestamp: '2026-04-25T22:04:10.700Z'
    attributes:
      duration_s: 4187
      orig_bytes: 27411889204
      resp_bytes: 41204117
      service: ssl
    authority:
      kind: siem-event
      source: Zeek conn.log

hypothesize:
  hypotheses: []
```

## PREDICT (loop 1)

Shape: E. Loop 1 enrichment: `host-egress-baseline` to characterize ci-runner-04's recurring egress geometry — daily byte volume, top destinations, typical asymmetric ratios for CI artifact uploads.

```yaml
hypothesize:
  hypotheses: []
```

## GATHER (loop 1) — host-egress-baseline

Returned: ci-runner-04 has a recurring 24h egress pattern. Median daily outbound: 4.2 GB across 12-18 distinct destinations. Top destinations historically: github.com (artifact pulls), pkg.example.io (corp package mirror), jfrog.example.io (artifact uploads). The ssl.server_name `cdn.staticfiles.example.org` and the dst IP `185.220.101.7` do **not** appear in the past 30-day destination set for this host. Today's 5-min egress window of 6.2 GB exceeds the host's recurring 99th-percentile 5-min volume of ~480 MB by ~13x. No recent CI job orchestrator events are co-correlated.

## ANALYZE (loop 1)

Loop 1 established baseline + flagged: destination is novel for this host AND volume materially exceeds the recurring 99th-percentile 5-min distribution. No CI orchestrator job correlated. Loop 2 PREDICT must fork on whether this is a rare-but-legitimate ad-hoc CI run or credentialed-exfil with a destination outside the host's recurring set.
