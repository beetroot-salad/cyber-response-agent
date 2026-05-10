## CONTEXTUALIZE

**Alert:** 1777250334.33 — BigQuery: large export from PII dataset
**Key observables:**
- principal: analyst-svc@analytics-prod.iam.gserviceaccount.com (service account)
- caller_user_agent: google-cloud-sdk gcloud/472.0.0
- service: bigquery.googleapis.com
- method: JobService.InsertJob (SELECT → GCS export)
- dataset: customer_pii (project: analytics-prod)
- referenced tables: customer_pii.users, customer_pii.payment_methods
- bytes processed: ~412 GB
- rows returned: 18,472,911
- destination: gs://analytics-export-prod/exports/2026-04-26-customer-extract.csv.gz
- timestamp: 2026-04-26T11:18:54.331Z
**Playbook hypotheses:** ?scheduled-etl-export, ?credentialed-exfil, ?ad-hoc-analyst-query, ?compromised-service-account
**Available leads:** service-account-job-history, scheduler-job-correlation, gcs-bucket-acl-history, recent-iam-changes, downstream-bucket-readers
**Archetype matches:**
- scheduled-etl — candidate — analyst-svc + analytics-export-prod + daily-named CSV match the standard daily-extract pattern; the SA is the right shape for batch ETL.
- credentialed-exfil — candidate — large PII pull to a GCS bucket could equally be a stolen-key exfil if the bucket's readers include external principals.
- ad-hoc-analyst — candidate — humans sometimes run analyst-svc-keyed queries during incidents/audits; rate-limit policies allow it.
**Adversarial archetype:** credentialed-exfil — worst-case is an attacker holds the analyst-svc key and is staging customer PII for download.
**Data environment:** reachable: gcp_audit, gcp_iam, gcs, scheduler_api, playground_ticket; degraded: none

```yaml
prologue:
  vertices:
  - id: v-001
    type: identity
    classification: gcp-service-account
    identifier: analyst-svc@analytics-prod.iam.gserviceaccount.com
    attributes:
      project: analytics-prod
  - id: v-002
    type: dataset
    classification: pii-dataset
    identifier: analytics-prod:customer_pii
  - id: v-003
    type: gcs_object
    classification: export-destination
    identifier: gs://analytics-export-prod/exports/2026-04-26-customer-extract.csv.gz
  edges:
  - id: e-001
    relation: read_from
    source_vertex: v-001
    target_vertex: v-002
    when:
      timestamp: '2026-04-26T11:18:54.331Z'
    attributes:
      bytes_processed: 412803881420
      rows_returned: 18472911
      tables: ['customer_pii.users', 'customer_pii.payment_methods']
    authority:
      kind: siem-event
      source: GCP Audit / BigQuery JobService
  - id: e-002
    relation: wrote_to
    source_vertex: v-001
    target_vertex: v-003
    when:
      timestamp: '2026-04-26T11:18:54.331Z'
    authority:
      kind: siem-event
      source: GCP Audit / BigQuery JobService
```
