# Arm A curated addendum library

## Curator

- cost: $0.1045
- tokens: in=2 out=1752

```
# Addendum library

1. **Credentialed-action class, service principal**: Before evaluating traffic anomalies, verify the executing workload's orchestration lineage (ownership records, deployment history, admission controls). An out-of-band workload holding valid credentials makes access appear authorized by design — compute provenance is the primary finding; traffic shape is secondary.

2. **Human principal + infrastructure action + correlated-channel silence**: Absent activity across expected network-access and communication channels during the action window strongly favors stolen or stale credentials over insider action. Run credential-chain forensics in parallel with containment, not after.

3. **Logging verbosity at or below fleet baseline coincident with suspicious workload**: Treat as intentional anti-forensics, not misconfiguration. Capture forensic state before containment destroys it.

4. **Egress to a recently registered destination with zero prior fleet presence, explicitly excluded by the relevant feature spec**: Classify as exfiltration infrastructure. Domain age + fleet novelty + spec exclusion is sufficient — no external reputation signal required.

5. **Artifact creation timestamp and first anomalous event timestamp**: Record these as a load-bearing pair in the disposition chain. A tight gap establishes actor intent; it is not supporting color.
```


## Raw inputs

[from defender on training fixture] DIRECTIVE-TO-CRITIC and final commit:
**Turn 4 — No VPN, no Slack. Committing.**

The absent VPN and Slack records for abansal are themselves significant: a legitimate platform-team member deploying a pod on a Tuesday business day would have VPN sessions and routine Slack activity. Total silence across both suggests either a dormant/former employee account with live kubeconfig, or credentials extracted and used from outside corporate infrastructure entirely.

This doesn't change the disposition — the pod is malicious regardless — but it means the kubeconfig-compromise track must run in parallel with the containment action.

---

STATE: committing

**Disposition: MALICIOUS** — adversary-controlled pod exfiltrating PII via hijacked service account and suppressed logging.

**Load-bearing reasoning:**

- **Freestanding pod created outside CI/CD by a human principal** — `billing-api-7c9f8b-x2q4n` has no ownerRef and no corresponding helm release; `abansal@corp.com` created it via kubectl at 2026-05-03T11:24Z, 10 minutes before external egress began. Legitimate billing-api pods are deployment-managed.

- **External egress to a freshly registered domain** — 1.4 MB HTTPS out to 203.0.113.99 (registered 2026-04-08, unknown reputation, zero prior fleet presence, PTR null). PR #6612 explicitly does not require external egress. This is exfiltration infrastructure.

- **Query logging deliberately suppressed** — `BILLING_DB_QUERY_LOG_LEVEL=ERROR` deviates from fleet norm of `INFO`; combined with the warehouse_audit gap, this is consistent with intentional anti-forensics, not misconfiguration.

- **No VPN and no Slack for abansal during this period** — a platform-team member doing hands-on cluster work with no corresponding corporate activity strongly suggests a stolen or stale kubeconfig, not an insider making authorized changes.

**Load-bearing assumption:** that 198.51.100.42 is not a legitimate corporate egress IP for abansal. If VPN records are simply absent due to a logging gap and that IP resolves to known corporate infrastructure, the actor framing shifts to insider — but the pod remains malicious and containment is unchanged.

**Recommended immediate actions:**
1. Kill pod `billing-api-7c9f8b-x2q4n` and block egress to 203.0.113.99.
2. Revoke `abansal@corp.com` kubeconfig + suspend account pending investigation.
3. Audit all k8s resources created by abansal credentials since 2026-04-08 (domain registration date).
4. Assess scope of data exfiltrated: 1.4 MB at mean 1.4 rows/query × ~100 bytes/row implies O(10,000) customer records — legal/privacy notification may be required.

---

[from critic on training fixture] DIRECTIVE-TO-DEFENDER block:
### VERDICT

**CONCEDE**

No sharp critique with observable consequence exists. The defender's evidence chain is multi-layered and convergent: the freestanding pod (no ownerRef, no helm release), external egress to a 27-day-old domain explicitly excluded by the feature spec, suppressed query logging deviating from fleet norm, and a human-created artifact with a precise 10-minute gap to first egress. Removing any single leg leaves the others. The acknowledged load-bearing assumption (198.51.100.42 not being a corporate egress IP) correctly identifies the insider-vs-stolen-credential fork but does not threaten the MALICIOUS verdict — containment is warranted either way. The warehouse_audit no_results is a loose end, but querying without a principal filter was not done; that would confirm or deny attribution without changing the artifact-level finding. No unrun tool produces a result that plausibly reverses MALICIOUS.

---

### DIRECTIVE-TO-DEFENDER

For data-access alerts where a legitimately-provisioned service account is the named principal, establish compute provenance before evaluating traffic shape. The principal identity in the alert is only as trustworthy as the workload that holds its credentials — a hijacked SA attached to an out-of-band compute artifact makes the access look authorized by design. On structurally similar alerts (credentialed-action class with a well-understood baseline service), your first tool call should verify that the executing artifact is CI/CD-managed; if ownerRef, deployment history, and admission controller records don't converge on a known release, treat the compute layer as the primary finding and the traffic anomaly as a secondary indicator, not the other way around.