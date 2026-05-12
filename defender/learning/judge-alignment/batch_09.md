# Batch 09 — judge-alignment samples

Three samples: one **incoherent** (actor story posits a `LIMIT 0` SQL
injection that contradicts the alert's row-count payload), one **caught**
via Snowflake query-history + masking-policy + warehouse-billing join, one
**survived** on a Slack-token misuse alert against an OAuth-app
provenance gap.

---

## Sample 25 — incoherent (story posits failed SQLi; alert payload shows ~70k-row exfil success)

**Expected outcome:** `incoherent`

**Rationale:** The alerting WAF event carries the actual response body
size (4.7 MB) and the database tier's slow-query log shows the offending
statement returned 71,402 rows. The actor's story posits an injection
attempt that failed because the application's parameter binding rejected
the payload, so no data left the system. Both load-bearing claims of the
story ("failed binding" and "no rows returned") are directly contradicted
by the alert and investigation surface. Lead-set quality is irrelevant —
the story is incompatible with the alert payload itself.

**Expected actor observation (gist):** Story posited a parameter-bound SQLi failure while the alert's `response.status: 200` with a 4.77 MB body and the RDS slow-query log's 71,402 rows demonstrate a successful UNION-SELECT exfil — both load-bearing fields the actor's framing ignored.

### alert.json (trimmed)

```json
{
  "source": "cloudflare.waf",
  "rule": {"id": "cf.sqli_union_match", "severity": "high"},
  "request": {
    "host": "api.shop.example.com",
    "path": "/v2/orders",
    "method": "GET",
    "query": "id=42%20UNION%20SELECT%20customer_id,email,card_last4,card_exp%20FROM%20customers--",
    "client_ip": "194.50.18.214"
  },
  "response": {
    "status": 200,
    "bytes": 4768221,
    "duration_ms": 11418
  }
}
```

### investigation.md (excerpt)

```
## PHASE: GATHER

Lead 0: cloudflare.access_logs (api.shop.example.com, ±10min)
  → 4 requests from 194.50.18.214: 3 probing payloads (boolean and
    error-based) each returning 400 with the WAF-block body (~2 KB);
    1 successful UNION SELECT returning 200 with 4.77 MB response.
    The 200 response is the alert.
Lead 1: rds.postgres.slow_query_log (shop-orders-prod, same window)
  → 1 matching statement at the alert timestamp:
    `SELECT id,total,status,customer_id,email,card_last4,card_exp
     FROM orders WHERE id = 42 UNION SELECT customer_id,email,
     card_last4,card_exp,'','' FROM customers --`
    Rows returned: 71,402. Duration: 11.4s. Same as response duration
    in the WAF log.
Lead 2: shop-app.access_log (orders service, same window)
  → 1 request matching the WAF event. Application returned a 200 with
    a JSON body length matching 4.77 MB. Stack-trace logs at the same
    timestamp show the SQL was constructed via string concatenation
    in `OrdersController#show` — a known-vuln endpoint flagged in the
    pen-test backlog 6 weeks ago, not yet remediated.
Lead 3: rds.audit_log (cardholder-data tables, 7d)
  → `customers.card_last4` and `customers.card_exp` were read by the
    `shop_app` role from the application IP 412 times in 7 days,
    distribution: 411 single-row lookups, 1 read of 71,402 rows (the
    alert).

## PHASE: ANALYZE
?failed-injection-attempt -- (RDS slow-query log shows the statement
  executed and returned ~71k rows; WAF returned 200 with a 4.77 MB
  body; the application's stack-trace shows string-concatenated SQL
  with no parameter binding on this endpoint)
?successful-sqli-data-exfiltration ++ (canonical UNION-SELECT against
  a vulnerable endpoint; row count matches customers table size;
  response bytes match expected projection volume)
```

### actor_story.md

```
## Attack story
A penetration tester probed the orders endpoint with several SQLi
payloads. The application uses parameter binding everywhere, so the
UNION-SELECT was treated as a literal string and the query failed to
parse. No data left the database. The WAF event is one of several
benign rejected attempts.

## Goal
Frame the WAF alert as a defended SQLi probe with no impact.

## Bypass
Defenders see "SQLi rule fired" and may not check whether the request
actually succeeded. A response status code is easy to miss in the
alert's metadata.
```

### projected_telemetry.yaml

```yaml
- lead_position: 0
  events:
    - {requests: "several 400/403 WAF blocks, no 200 with large body"}
- lead_position: 1
  events: []   # story posits parser rejection — no slow-query entry
- lead_position: 2
  events:
    - {app_response: "4xx/5xx parse error"}
- lead_position: 3
  events:
    - {cardholder_reads: "baseline only"}
```

**Expected findings:** `defender_findings: []` (per judge.md, incoherent
→ empty list). Surface the alert/story contradiction in
`actor_observations`:

- **`misprediction`** on response-status reading. The alert's
  `response.status: 200` and `response.bytes: 4,768,221` are
  load-bearing fields the actor either did not read or did not
  reconcile with the "failed-binding" framing. WAF alerts carry the
  upstream response code; a successful 200 with a multi-MB body is
  incompatible with parser rejection. Story should have been framed
  as a partial-success or as a successful exfil with a *different*
  cover (e.g., authorised data-export by an internal report tool).

---

## Sample 26 — caught (Snowflake query history + masking policy + warehouse billing refute service-monitoring framing)

**Expected outcome:** `caught`

**Rationale:** Actor frames a large query against the customer-PII table
as a routine analytics job by the data-science team's warehouse user.
Three joined leads refute: the Snowflake query-history lead shows the
query was issued by a *role* not in the analytics team's bound roles,
the masking-policy lead shows the role was elevated 11 minutes earlier
via a privilege grant that the column-level masking-policy audit logs
as bypassing the standard `analytics_pii_masked` policy, and the
warehouse-billing lead shows the warehouse cost for the query window is
5× the analytics team's documented per-job ceiling. Cover dies on the
join.

**Expected actor observation (gist):** Actor's analytics-team framing fell to the query running under `DATA_SCIENTIST_ROLE` (privacy-team-owned, granted to svc-analytics 11 minutes earlier by `SECURITYADMIN`) with masking-policy bypassed and the sign-in from a Frankfurt DigitalOcean droplet.

### alert.json (trimmed)

```json
{
  "source": "snowflake.access_history",
  "warehouse": "ANALYTICS_WH",
  "role": "DATA_SCIENTIST_ROLE",
  "user": "svc-analytics",
  "query_id": "01b8d2…",
  "query_text_excerpt": "SELECT customer_id, full_name, email, ssn, dob, phone FROM corp.customers WHERE last_purchase >= …",
  "rows_returned": 4218409,
  "bytes_scanned": 12849023012,
  "rule": {"id": "snowflake.pii_table_high_volume_read", "severity": "high"}
}
```

### investigation.md (excerpt)

```
## PHASE: GATHER

Lead 0: snowflake.query_history (svc-analytics, ±2h)
  → 17 queries. 16 against `analytics_db.derived_*` views (no PII).
    The 17th is the alert: 4.2M-row read of `corp.customers` raw
    table including `ssn`, `dob`, `phone`. Role for that query:
    `DATA_SCIENTIST_ROLE`. For the other 16: `ANALYTICS_VIEWER`.
Lead 1: snowflake.grants_to_user (svc-analytics, 7d)
  → `DATA_SCIENTIST_ROLE` granted to svc-analytics at T-11min by
    `SECURITYADMIN`. svc-analytics's documented role set is
    `ANALYTICS_VIEWER` + `ANALYTICS_WRITER`; `DATA_SCIENTIST_ROLE`
    is not part of the team's published role catalog.
Lead 2: snowflake.masking_policy_audit (`corp.customers.ssn`, ±2h)
  → 4.2M rows read with masking policy *not applied* — the
    `customer_pii_mask_for_analytics` policy excludes
    `DATA_SCIENTIST_ROLE` from masking by design (the role is meant
    for the privacy team's authorised audits). Audit log records
    the bypass tag.
Lead 3: snowflake.warehouse_billing (`ANALYTICS_WH`, query window)
  → 5,400 credits consumed in the 14-minute query window. Daily
    average for `ANALYTICS_WH` over 30d: 1,100 credits/day. The
    single query exceeded daily average by 5×.
Lead 4: snowflake.login_history (`svc-analytics`, ±2h)
  → 1 sign-in at T-15min from 134.209.211.74 (DigitalOcean droplet
    in Frankfurt). svc-analytics's prior sign-ins all originated
    from the org's AWS NAT in us-east-1.
Lead 5: cmdb.role_catalog (analytics-team)
  → published team-role bindings list `ANALYTICS_VIEWER` and
    `ANALYTICS_WRITER` only. `DATA_SCIENTIST_ROLE` is owned by the
    privacy team; svc-analytics has no documented privacy-team
    affiliation.

## PHASE: ANALYZE
?routine-analytics-job -- (the role used (DATA_SCIENTIST_ROLE) is
  not in the analytics team's bound role catalog; the masking
  policy was bypassed because of that role; warehouse billing is
  5× the documented baseline; sign-in was from a non-corporate IP)
?compromised-service-account-with-role-elevation ++ (canonical:
  attacker landed svc-analytics's keys, elevated to a privacy-team
  role through `SECURITYADMIN`, ran a single high-volume PII read
  with masking bypassed, paid for it on the analytics team's
  warehouse to obscure the cost trail)
```

### actor_story.md

```
## Attack story
The data-science team kicked off an ad-hoc deep analysis of customer
churn that required raw PII fields. The team's service account
(`svc-analytics`) is rated for analytics workloads and has access to
the production customer table through the analytics team's documented roles
(`ANALYTICS_VIEWER` / `ANALYTICS_WRITER`), with standard analytics masking
policies applied. The job ran from the team's usual AWS NAT and should fit
the analytics warehouse's normal cost envelope.

## Goal
Frame the high-volume PII read as a one-off analytics deep-dive.

## Bypass
Snowflake's query history will show the query ran successfully
through the analytics warehouse with the team's service account and
documented analytics roles. Defenders who stop at "analytics team's account
did an analytics query" will not refute.
```

### projected_telemetry.yaml

```yaml
- lead_position: 0
  events:
    - {role: ANALYTICS_VIEWER or ANALYTICS_WRITER, query: "PII read with masking applied"}
- lead_position: 1
  events:
    - {grants: "stable; no recent role additions"}
- lead_position: 2
  events:
    - {masking: "applied per analytics policy"}
- lead_position: 3
  events:
    - {billing: "within team's documented ceiling"}
- lead_position: 4
  events:
    - {sign_in: "from org's AWS NAT"}
- lead_position: 5
  events:
    - {role_catalog: "matches roles actually used"}
```

**Expected findings:**

- **`detection-confirmed`** on lead 0 + lead 1 + lead 5 joined (role
  used vs role-catalog vs grants timeline). The load-bearing
  refutation is the *role mismatch*: the query ran under
  `DATA_SCIENTIST_ROLE`, which is owned by the privacy team and
  was granted to svc-analytics 11 minutes before the query by
  `SECURITYADMIN`. The actor's story projects an analytics-team
  role; the role on the actual query is a different team's. Surface
  that role-vs-team-catalog is the durable signal under most
  cover variants.
- **`detection-confirmed`** on lead 2 (masking-policy audit). The
  masking-policy audit log explicitly records the bypass tag for
  this query. Affirmative-bypass surfaces are high-leverage and
  often forgotten; preserve as a discipline note (always check
  masking-bypass audits on PII reads).
- **`detection-confirmed`** on lead 3 (warehouse billing) + lead 4
  (sign-in origin). Cost anomaly (5× daily baseline in a single
  14-min query) + non-corporate sign-in IP each independently
  corroborate. The billing axis is unusual but durable — exfil
  workloads have a cost shape that is hard to forge without
  blowing the cover.

---

## Sample 27 — survived (Slack token misuse via app installed in another workspace; OAuth-app provenance gap)

**Expected outcome:** `survived`

**Rationale:** Defender exhausts the available Slack-side surface.
The token belongs to a Slack app legitimately installed in the
workspace; the app's scopes are within its declared manifest; the
audit log shows the API calls happened through normal Slack channels.
The story — an attacker compromised a separate org's
shared Slack app and reused its tokens — is consistent with
everything the defender can observe in their own workspace. The
discriminating evidence (whether the app's tokens were issued from a
maintainer-controlled deploy or from an attacker who breached the
publisher's CI) sits in the app publisher's own deployment-pipeline
audit, which the defender's tools do not chain to.

**Expected actor observation (gist):** Story's load-bearing claim required Pulse Software Inc.'s deployment-pipeline audit or signed attestation distinguishing legitimate token issuance from compromise reuse, which the victim's Slack-side surface cannot access.

### alert.json (trimmed)

```json
{
  "source": "slack.audit_logs",
  "action": "files.list",
  "actor": {"type": "app", "name": "Pulse Analytics", "app_id": "A091Z…"},
  "context": {"workspace": "corp", "ip_address": "23.94.55.18"},
  "anomaly": "files.list scoped to all private channels in 5min",
  "rule": {"id": "slack.app_broad_files_enumeration", "severity": "high"}
}
```

### investigation.md (excerpt)

```
## PHASE: GATHER

Lead 0: slack.audit_logs (app_id=A091Z, 24h)
  → 1,142 events. files.list across 311 private channels (the
    alerting burst), conversations.history reads on 84 channels,
    47 files.info calls. Activity over a 12-minute window. App's
    declared scopes include `channels:history,groups:history,
    files:read,users:read` — every call is within scope.
Lead 1: slack.app_management (Pulse Analytics)
  → installed in the workspace 9 months ago by `ahodge`
    (engineering manager). Re-authorised 4 months ago. App's
    listing page on the Slack App Directory shows publisher
    "Pulse Software Inc." with verified-publisher badge.
Lead 2: enrich.publisher_metadata (Pulse Software Inc.)
  → website pulsesoftware.io, 200 employees per LinkedIn,
    customers include three Fortune-500s. Security page advertises
    SOC 2 + ISO 27001. No public incident disclosures.
Lead 3: slack.api_call_source (the burst's tokens)
  → all calls originated from 23.94.55.18 (Linode VPS in Texas),
    which matches the publisher's documented backend IP range
    (per their public docs).
Lead 4: slack.audit_logs (cross-tenant correlation, available
    via Slack Enterprise Grid?)
  → not available — workspace is on Slack Business+, no cross-
    tenant API-call telemetry is exposed by this tier.

## PHASE: ANALYZE
?legitimate-app-broad-scan ++ (token, scopes, source IP, publisher
  reputation all consistent with the app doing what its scopes
  permit)
?compromised-publisher-token-reused-on-victim ++ (cannot rule out
  — every Slack-side artefact would be identical if the
  publisher's CI / token-vault were breached and the attacker
  reused the long-lived workspace token to enumerate)
Picture: insufficient. Discriminating evidence (whether Pulse's
deployment pipeline issued the token-bearing calls vs an
unauthorised reuse) sits in the publisher's own audit, which the
defender's surface does not access. Disposition: inconclusive,
escalate for vendor-side incident-response contact.
```

### actor_story.md

```
## Attack story
An attacker breached Pulse Software Inc.'s CI/CD pipeline and
extracted the long-lived workspace tokens the company holds on
behalf of customers. They used the corp workspace's token to mass-
enumerate files and channel histories for later exfil.

## Goal
Reach corp's Slack content through a trusted-vendor token reuse
that the victim's own surface cannot distinguish from legitimate
publisher activity.

## Bypass
Every Slack-side leaf is identical between "Pulse running its own
analytics" and "attacker reusing Pulse's tokens". The victim's
audit log shows the app, the scopes, the source IP range. None of
that chains back to the publisher's CI/CD to attest who actually
issued the calls.
```

### projected_telemetry.yaml

```yaml
- lead_position: 0
  events:
    - {api_calls: "scopes consistent, possibly higher volume than baseline"}
- lead_position: 1
  events:
    - {app: installed, publisher: verified}
- lead_position: 2
  events:
    - {publisher: "established, no public incidents"}
- lead_position: 3
  events:
    - {source: "publisher's documented IP range"}
- lead_position: 4
  events: []   # cross-tenant correlation not available on this tier
```

**Expected findings:**

- **`lead-set`** gap: no lead obtains publisher-side provenance for
  the token-bearing API calls, such as deployment-pipeline audit,
  token-vault access history, or a signed attestation that the calls
  were issued by Pulse's authorised workload. The Slack workspace can
  prove app, scopes, volume, and source IP; it cannot prove who drove
  the publisher's token.
- **`observability`** gap: victim-side Slack audit and app-directory
  metadata do not distinguish legitimate verified-publisher activity
  from unauthorised token reuse after publisher compromise. The root
  system class is third-party SaaS supply-chain provenance bound to
  API calls; without that vendor-side proof, the correct outcome is
  `survived`.
