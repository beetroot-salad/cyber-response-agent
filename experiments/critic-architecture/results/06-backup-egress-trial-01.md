# Trial 06-01 — backup-large-egress

Fixture: `06-backup-large-egress` (label: true-benign, expected: CONCEDE)

## Defender
Claim: scheduled restic backup within historical norms, benign.
Load-bearing assumption: CMDB mapping of `corp-backups-prod-eu` as canonical destination is current and authoritative — bucket not re-pointed/re-owned/IAM-mutated since last reconcile.

## Critic
Verdict: **CRITIQUE**.
Mechanism: bucket policy/replication mutated; exfil rides legitimate write path.
Lead: CloudTrail `PutBucketPolicy` / `PutBucketReplication` / `PutBucketAcl` / `PutBucketOwnershipControls` since last CMDB reconcile; live `GetBucketPolicy` + `GetBucketReplication` + owner-id vs CMDB snapshot.
Prediction: zero matching events + hashes match → CONCEDE; mismatch → unauthorized.

## Baseline (single-agent)
Hypotheses: `?scheduled-fleet-backup`, `?adversary-controlled-restic-binary` (FIM hash + package provenance), `?adversary-controlled-timer-unit` (config-mgmt drift), `?exfil-piggyback-on-backup` (off-tree egress destinations + cgroup process tree), `?credential-misuse-on-canonical-bucket` (PutBucketPolicy + PutObjectAcl in window).

## Comparison
**Critic novelty: none.** Baseline's `?credential-misuse-on-canonical-bucket` lead explicitly cites `PutBucketPolicy` and ACL events. Critic adds `PutBucketReplication` and `PutBucketOwnershipControls` (incremental). Baseline broader (FIM, timer drift, off-tree destinations). Verdict mismatch but produced lead is fully covered.
