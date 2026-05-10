# Arm A training transcript — fixture 11-billing-svc-account-mimicry

## Defender loop

- turns: 4, committed: True
- total cost: $0.4177
- tokens: in=8 out=4992 cache_read=47584 cache_create=83979
- wall: 119.4s

### TURN 1

```
**Turn 1 — Hypothesis formation + initial evidence gathering**

The alert is statistically mild (within 2σ, shape unchanged), and the context provides a plausible legitimate explanation (PR #6612 + new export endpoint). But "deliberately staying under threshold" is a classic exfiltration pattern, so I won't close this fast.

**Hypotheses:**

1. `?legitimate-new-feature-usage` — `/v2/exports/customer-pii` introduced 7d ago is driving modest volume increase; everything matches (shape, rows/query, image SHA).
2. `?adversary-controlled-pod` — Pod compromised post-deploy; attacker exfiltrating PII via legitimate SA, tuning volume to stay under 2σ.
3. `?bulk-export-misuse` — Authenticated internal or external caller is hammering the new export endpoint, not adversarial but unauthorized bulk access.
4. `?n-plus-one-regression` — New export feature has an inefficient query pattern inflating count without increasing rows/query much.

**Discriminating moves:**
- `warehouse_audit` — do the queries look like per-customer invoice lookups or cross-customer sweeps?
- `network_egress` — is data leaving the pod to unexpected destinations?
- `pod_get` — verify env vars for anything injected post-deploy

```
<tool_call>{"tool": "warehouse_audit", "args": {"principal": "serviceaccount:billing/api-billing-prod", "time_range": "2026-05-05T13:00Z/2026-05-05T17:00Z"}}</tool_call>
```

```
<tool_call>{"tool": "network_egress", "args": {"host": "billing-api-7c9f8b-x2q4n", "time_range": "2026-05-05T13:00Z/2026-05-05T17:00Z"}}</tool_call>
```

```
<tool_call>{"tool": "pod_get", "args": {"pod": "billing-api-7c9f8b-x2q4n"}}</tool_call>
```

STATE: investigating — waiting on warehouse query patterns (per-customer vs. sweep), egress destinations, and pod env vars. If warehouse shows single-customer-id queries and egress is clean internal routing, `?legitimate-new-feature-usage` wins. Any cross-customer sweeps or unexpected egress flips to `?adversary-controlled-pod`.
```

#### tool results

```
<tool_result tool="warehouse_audit" args="principal=serviceaccount:billing/api-billing-prod|time_range=2026-05-05T13:00Z/2026-05-05T17:00Z">
{
  "status": "no_results",
  "note": "no events matched warehouse_audit with {'principal': 'serviceaccount:billing/api-billing-prod', 'time_range': '2026-05-05T13:00Z/2026-05-05T17:00Z'}"
}
</tool_result>

<tool_result tool="network_egress" args="host=billing-api-7c9f8b-x2q4n|time_range=2026-05-05T13:00Z/2026-05-05T17:00Z">
{
  "external_connections": [
    {
      "dst": "203.0.113.99:443",
      "proto": "https",
      "bytes_out": 1432819,
      "first_seen_org": "2026-05-03T11:34Z"
    }
  ],
  "dst_metadata": {
    "203.0.113.99": {
      "ptr": null,
      "registered": "2026-04-08",
      "reputation": "unknown",
      "fleet_seen_count_90d": 1
    }
  },
  "fleet_comparison": "no other billing-api-* pod has connections to 203.0.113.99",
  "feature_spec_check_pr_6612": "does not require external HTTPS egress"
}
</tool_result>

<tool_result tool="pod_get" args="pod=billing-api-7c9f8b-x2q4n">
{
  "name": "billing-api-7c9f8b-x2q4n",
  "namespace": "billing",
  "spec": {
    "containers": [
      {
        "name": "billing-api",
        "image": "registry.corp/billing-api@sha256:abc...123",
        "image_matches_helm_2.18.0_manifest": true,
        "env": [
          {
            "name": "BILLING_DB_QUERY_LOG_LEVEL",
            "value": "ERROR",
            "fleet_norm": "INFO"
          },
          {
            "name": "DB_HOST",
            "value": "warehouse.prod.internal"
          }
        ]
      }
    ]
  },
  "labels": {
    "app": "billing-api"
  },
  "owner_references": [],
  "fleet_comparison_note": "no replicaset/deployment ownerRef \u2014 pod is freestanding, not deployment-managed"
}
</tool_result>
```

### TURN 2

```
**Turn 2 — Three simultaneous red flags; pivoting hard toward `?adversary-controlled-pod`**

Results are alarming in combination:

1. **Freestanding pod (no ownerRef)** — legitimate billing-api pods are deployment-managed (Deployment → ReplicaSet → Pod). This pod has no owner references, meaning someone created it manually. That is not normal for production.

2. **External egress to 203.0.113.99:443** — 1.4 MB out, domain registered 27 days ago, no PTR, unknown reputation, never seen by any other billing-api pod, and PR #6612 explicitly does not require external egress. This is data leaving to an unexpected destination.

3. **Query logging suppressed** — `BILLING_DB_QUERY_LOG_LEVEL=ERROR` (fleet norm: `INFO`). Silences application-level query logs. Combined with `warehouse_audit` returning no_results despite the alert claiming 4720 queries, this is consistent with deliberate log suppression.

The warehouse_audit tool description says it "CANNOT be silenced by app config" — yet returned no results. This may mean the DB sees a different principal identity, or the queries are being routed differently. Worth ruling out a principal mismatch, but the pod anomalies already warrant escalation.

**Critical unknown: who created this freestanding pod?** That's the most direct discriminator.

```
<tool_call>{"tool": "k8s_audit", "args": {"resource": "pods/billing-api-7c9f8b-x2q4n", "verb": "create"}}</tool_call>
```

```
<tool_call>{"tool": "helm_history", "args": {"release": "billing-api", "time_range": "2026-04-28Z/2026-05-05T17:00Z"}}</tool_call>
```

```
<tool_call>{"tool": "iam_audit", "args": {"principal": "serviceaccount:billing/api-billing-prod", "time_range": "2026-05-03T00:00Z/2026-05-05T17:00Z"}}</tool_call>
```

STATE: investigating — the no-ownerRef finding alone would trigger escalation in most environments. I want to confirm who created this pod and whether the helm release manages a different pod set. If k8s_audit shows the pod was created by a human or CI principal outside the normal deployment pipeline, this commits as malicious.
```

#### tool results

```
<tool_result tool="k8s_audit" args="resource=pods/billing-api-7c9f8b-x2q4n|verb=create">
{
  "events": [
    {
      "ts": "2026-05-03T11:24:08Z",
      "verb": "create",
      "resource": "pods/billing-api-7c9f8b-x2q4n",
      "namespace": "billing",
      "user": "dev:abansal@corp.com",
      "user_groups": [
        "platform-team",
        "kubeconfig-issued"
      ],
      "source_ip": "198.51.100.42",
      "user_agent": "kubectl/v1.29.3 (linux/amd64)"
    }
  ],
  "context_note": "creator is a kubeconfig user, NOT system:serviceaccount:kube-system:deployment-controller"
}
</tool_result>

<tool_result tool="helm_history" args="release=billing-api|time_range=2026-04-28Z/2026-05-05T17:00Z">
{
  "releases": [
    {
      "version": "billing-api-2.18.0",
      "ts": "2026-04-28T15:11:02Z",
      "deployed_by": "ci-bot@corp",
      "status": "deployed"
    }
  ],
  "note": "no helm rollouts after 2026-04-28; the suspect pod's 2026-05-03 creation has no corresponding helm release"
}
</tool_result>

<tool_result tool="iam_audit" args="principal=serviceaccount:billing/api-billing-prod|time_range=2026-05-03T00:00Z/2026-05-05T17:00Z">
{
  "status": "no_results",
  "note": "no events matched iam_audit with {'principal': 'serviceaccount:billing/api-billing-prod', 'time_range': '2026-05-03T00:00Z/2026-05-05T17:00Z'}"
}
</tool_result>
```

### TURN 3

```
**Turn 3 — Evidence is conclusive; one targeted pivot on the actor**

The k8s_audit and helm_history results close the loop:

- **abansal@corp.com manually `kubectl create`d this pod at 2026-05-03T11:24:08Z** from 198.51.100.42 — 9 minutes before the first external egress hit 203.0.113.99 (T11:34Z). The timing is precise, not coincidental.
- **No helm release covers this pod.** The deployment pipeline last touched billing-api on 2026-04-28. This pod exists entirely outside the CI/CD chain.
- The pod carries the production SA (`api-billing-prod`), suppressed query logging, and exfiltrates to a domain registered 27 days ago.

The only remaining question that affects response actions: **is abansal an insider actor, or was their kubeconfig stolen?** That changes whether we also need to escalate a credential-compromise incident alongside the pod containment. One VPN + Slack check will tell me.

```
<tool_call>{"tool": "vpn_log", "args": {"user": "abansal@corp.com", "time_range": "2026-05-01T00:00Z/2026-05-05T17:00Z"}}</tool_call>
```

```
<tool_call>{"tool": "slack_history", "args": {"user": "abansal@corp.com"}}</tool_call>
```

STATE: investigating — I expect to commit next turn regardless of result. If VPN shows 198.51.100.42 as a known corporate/VPN exit IP with abansal's normal geo, this skews insider. If that IP is foreign or never seen for this user, it's compromised credentials + adversary-controlled pod. Either way the pod is malicious and must be contained now.
```

#### tool results

```
<tool_result tool="vpn_log" args="time_range=2026-05-01T00:00Z/2026-05-05T17:00Z|user=abansal@corp.com">
{
  "status": "no_results",
  "note": "no events matched vpn_log with {'user': 'abansal@corp.com', 'time_range': '2026-05-01T00:00Z/2026-05-05T17:00Z'}"
}
</tool_result>

<tool_result tool="slack_history" args="user=abansal@corp.com">
{
  "status": "no_results",
  "note": "no events matched slack_history with {'user': 'abansal@corp.com'}"
}
</tool_result>
```

### TURN 4

```
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
```


## Critic (REPORT-time)

- cost: $0.1716
- tokens: in=2 out=5186

```
### VERDICT

**CONCEDE**

No sharp critique with observable consequence exists. The defender's evidence chain is multi-layered and convergent: the freestanding pod (no ownerRef, no helm release), external egress to a 27-day-old domain explicitly excluded by the feature spec, suppressed query logging deviating from fleet norm, and a human-created artifact with a precise 10-minute gap to first egress. Removing any single leg leaves the others. The acknowledged load-bearing assumption (198.51.100.42 not being a corporate egress IP) correctly identifies the insider-vs-stolen-credential fork but does not threaten the MALICIOUS verdict — containment is warranted either way. The warehouse_audit no_results is a loose end, but querying without a principal filter was not done; that would confirm or deny attribution without changing the artifact-level finding. No unrun tool produces a result that plausibly reverses MALICIOUS.

---

### DIRECTIVE-TO-DEFENDER

For data-access alerts where a legitimately-provisioned service account is the named principal, establish compute provenance before evaluating traffic shape. The principal identity in the alert is only as trustworthy as the workload that holds its credentials — a hijacked SA attached to an out-of-band compute artifact makes the access look authorized by design. On structurally similar alerts (credentialed-action class with a well-understood baseline service), your first tool call should verify that the executing artifact is CI/CD-managed; if ownerRef, deployment history, and admission controller records don't converge on a known release, treat the compute layer as the primary finding and the traffic anomaly as a secondary indicator, not the other way around.
```
