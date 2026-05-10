## Meta

### Files actually read

- `/workspace/docs/experiments/hypothesize-subagent-pilot/fixtures/case-egress-spike/truncated-investigation.md`
- `/workspace/soc-agent/skills/investigate/SKILL.md` (§ASSESS, §HYPOTHESIZE, §GATHER)
- `/workspace/docs/investigation-language.md` (§Hypothesis, §Lead, §Philosophy)
- `/workspace/soc-agent/knowledge/common-investigation/leads/process-lineage/definition.md`
- `/workspace/soc-agent/knowledge/common-investigation/leads/network-analysis/definition.md`
- `/workspace/soc-agent/knowledge/common-investigation/leads/ad-hoc/definition.md`

### ASSESS verdict

**Branching: yes.** The choice of first lead depends on the active prior: a benign story sends us to `backup-system-audit` first (cheap, authoritative for schedule intent); an adversarial story sends us to `process-flow-attribution` first (reveals whether a novel process exists alongside the expected backup binary). These are different data sources targeting different system layers, so the fork is real at step 1.

**Interpretation-vulnerable: yes.** If `process-flow-attribution` returns "python3 / gunicorn-worker" as the attributing process, a reviewer could reasonably disagree on whether that process should be initiating a 2.9 GB S3 transfer. Pre-registered predictions lock the interpretation before the lead runs.

Combined verdict: **branching + interpretation-vulnerable → HYPOTHESIZE with per-hypothesis prediction blocks.**

### Dispatch choice

**Single lead — `process-flow-attribution`.**

Rationale: This lead queries a single entity (the host's conntrack + process-socket snapshots) and answers the highest-priority discrimination question: does the process initiating the S3 transfer match the expected backup binary? A composite dispatch is not warranted here because the investigative question is not a profiling question spanning multiple entities — it is a single attribution query on prod-api-01. `backup-system-audit` is the natural *second* lead (it provides the authoritative schedule-intent check), but its result meaningfully depends on what `process-flow-attribution` first reveals (e.g., if a novel process is identified, backup-system-audit is still useful but the adversarial branch is already open). Single dispatch on `process-flow-attribution` is the highest-discriminating-first choice.

---

## HYPOTHESIZE (loop 1)

**Active hypotheses:**

- `?scheduled-backup-overrun` — attaches upstream of `v-001` (prod-api-01) via `initiated_transfer`; proposed parent: `{type: process, classification: authorized-backup-agent}`. The org's scheduled backup job ran on prod-api-01 during the 02:00–04:00 UTC window and transferred an unusually large volume — likely due to a larger-than-normal dataset (new data, retention extension, or full-rescan trigger). Predicts: (1) the process responsible for the S3 transfer bytes is the expected backup binary (binary path matches the org's registered backup agent, e.g., `awsbackup-agent`, `aws-backup`, `s3-sync`, `backup-runner`, or a known Python wrapper); (2) the backup-system audit log records a scheduled or manually triggered job for prod-api-01 in the window. Refutation shape: process responsible is a novel binary not matching the expected backup agent path, OR no backup job is recorded in the backup-system audit for the window.

- `?misconfigured-backup-runaway` — attaches upstream of `v-001` via `initiated_transfer`; proposed parent: `{type: process, classification: misconfigured-backup-agent}`. The authorized backup agent is the responsible process, but it is running a misconfigured job (wrong retention window, deduplication cache miss, accidental full-resync flag) causing legitimate software to transfer far more data than expected. Predicts: (1) the process responsible is the expected backup binary (same binary path as for `?scheduled-backup-overrun`); (2) the backup-system audit shows a job that ran, but with anomalous parameters or an unusual job size relative to historical runs for this host (volume >2σ above trailing-28-day mean for prod-api-01 backup jobs). Refutation shape: backup job volume is within historical norms (indicating the run itself was the expected size), OR no backup job is recorded.

- `?adversarial-exfil-via-s3` — attaches upstream of `v-001` via `initiated_transfer`; proposed parent: `{type: process, classification: adversary-controlled-process}`. An adversary with foothold on prod-api-01 is exfiltrating data to `s3-prod-backups` (a bucket already on the egress allow-list, providing cover). The transfer is disguised or co-occurring with normal operations during the off-hours window when monitoring attention is lowest. Predicts: (1) the process responsible is NOT the expected backup binary — it is a novel binary path, an unexpected interpreter (e.g., a Python script not in the backup agent's known path), or the backup binary wrapped by an unexpected parent process chain. Refutation shape: the process attributing all 2.9 GB to `s3-prod-backups` is exclusively the expected backup binary with a well-known parent chain (e.g., `systemd → backup-agent`), AND the backup-system audit confirms the job in the window.

**Selected lead:** `process-flow-attribution` — queries the host's conntrack + process-socket snapshots during the 02:00–04:00 UTC window, joins by 4-tuple to netflow flows toward `s3-prod-backups`, and identifies which process(es) generated the 2.9 GB egress. The outcome discriminates all three hypotheses: an expected backup binary confirms `?scheduled-backup-overrun` or `?misconfigured-backup-runaway` (the two are not yet distinguishable without backup-system audit); a novel or unexpected binary directly opens the adversarial branch.

**Pitfalls:**

- `?scheduled-backup-overrun` / `?misconfigured-backup-runaway`: The expected backup binary may be a Python interpreter (`python3`) or shell wrapper (`bash`). A result showing `python3` as the initiating process is NOT self-interpreting — an adversary could equally use `python3`. The discriminating fact is the *script path* and *parent process chain*, not the interpreter name. Pre-register that "python3 with script path outside known backup agent installation directory" is NOT confirmation of a benign backup process.
- `?adversarial-exfil-via-s3`: The destination `s3-prod-backups` is a known, previously-connected endpoint. The adversary may have hijacked the backup mechanism (e.g., modified the backup script in-place) rather than introducing a novel binary — in which case `process-flow-attribution` may show the expected binary path while the behavior is still adversarial. This is a residual after process attribution and must be caught by the backup-system audit's job-parameter comparison.
- Both: Process-socket snapshots are at 5-minute granularity. A short-lived exfil process that completed within a snapshot window may be missed. If `process-flow-attribution` returns "no process attribution for some flows," that is not confirmation of benign activity — it is a data gap and an escalation signal.

---

```yaml
hypothesize:
  hypotheses:
    - id: h-001
      name: "?scheduled-backup-overrun"
      attached_to_vertex: v-001
      proposed_edge:
        relation: initiated_transfer
        parent_vertex:
          type: process
          classification: authorized-backup-agent
      predictions:
        - id: p1
          claim: "The process responsible for the S3 egress bytes has a binary path matching the org's registered backup agent (e.g., awsbackup-agent, s3-sync, or known Python backup wrapper installed under the backup agent's directory)."
        - id: p2
          claim: "The backup-system audit log records a scheduled or manually triggered job for prod-api-01 within the 02:00–04:00 UTC window."
      refutation_shape:
        - id: r1
          claim: "The attributing process has a binary or script path outside the backup agent installation directory, or no backup-system job is recorded for the window."
      weight: null

    - id: h-002
      name: "?misconfigured-backup-runaway"
      attached_to_vertex: v-001
      proposed_edge:
        relation: initiated_transfer
        parent_vertex:
          type: process
          classification: misconfigured-backup-agent
      predictions:
        - id: p1
          claim: "The process responsible is the expected backup binary (same path as authorized-backup-agent), but the job volume transferred is >2σ above the trailing-28-day mean for prod-api-01 backup jobs recorded in the backup-system audit."
      refutation_shape:
        - id: r1
          claim: "The job volume is within historical norms for this host, OR the attributing process is not the expected backup binary."
      weight: null

    - id: h-003
      name: "?adversarial-exfil-via-s3"
      attached_to_vertex: v-001
      proposed_edge:
        relation: initiated_transfer
        parent_vertex:
          type: process
          classification: adversary-controlled-process
      predictions:
        - id: p1
          claim: "The process responsible for the S3 egress bytes has a binary or script path that does not match the org's registered backup agent installation directory, or shares the backup binary name but has an unexpected parent process chain (not the expected systemd/cron ancestry)."
      refutation_shape:
        - id: r1
          claim: "All 2.9 GB of S3 egress is exclusively attributable to the expected backup binary with an unbroken, expected parent chain (e.g., systemd or crond as root ancestor), AND the backup-system audit confirms a job in the window."
      concerns:
        - "Adversary may have modified the backup script in-place (same binary path, different behavior) — process-flow-attribution alone cannot rule this out; backup-system job parameters must be cross-checked."
      weight: null
```

---

### Lead pre-registered predictions (for GATHER)

The outcome of `process-flow-attribution` is interpretation-vulnerable on the process-path field. Pre-register before running:

```yaml
predictions:
  - id: lp1
    if: "All flows to s3-prod-backups are attributed to a single process whose binary/script path is within the registered backup agent installation directory, with parent chain consistent with scheduled execution (systemd, crond, or equivalent)."
    read_as: "Process attribution is consistent with h-001 or h-002; adversarial branch not yet open. Advance to backup-system-audit to distinguish scheduled vs. misconfigured."
    advance_to: "backup-system-audit"

  - id: lp2
    if: "Flows to s3-prod-backups are attributed to a process whose binary/script path is outside the backup agent installation directory, or whose parent chain includes an unexpected ancestor (shell, gunicorn worker, web framework process)."
    read_as: "Attribution does not match the expected backup agent — adversarial branch opens. h-003 receives + evidence."
    advance_to: "HYPOTHESIZE"

  - id: lp3
    if: "Process attribution is incomplete — some flows have no matching socket snapshot entry (snapshot granularity gap, short-lived process, or attribution failure)."
    read_as: "Data gap: cannot rule out adversarial process. This is an escalation signal if the unattributed volume is substantial (>0.5 GB of the 2.9 GB)."
    advance_to: "HYPOTHESIZE"

  - id: lp4
    if: "Flows to s3-prod-backups are attributed to multiple distinct processes — one matching the backup agent and one or more novel processes."
    read_as: "Mixed attribution: legitimate backup process ran concurrently with an unknown process. Adversarial branch is open regardless of backup agent presence."
    advance_to: "HYPOTHESIZE"
```
