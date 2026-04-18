## Meta

### Files actually read

- `/workspace/docs/experiments/hypothesize-subagent-pilot/fixtures/case-db-outbound-lowrep/truncated-investigation.md`
- `/workspace/soc-agent/skills/investigate/SKILL.md` — §ASSESS (line 138), §HYPOTHESIZE (line 319)
- `/workspace/docs/investigation-language.md` — §Hypothesis (lines 225–265), §Philosophy (lines 38–130)
- `/workspace/soc-agent/knowledge/common-investigation/leads/process-lineage/definition.md`
- `/workspace/soc-agent/knowledge/common-investigation/leads/network-analysis/definition.md`
- `/workspace/soc-agent/knowledge/common-investigation/leads/source-reputation/definition.md`

### ASSESS verdict

**Branching: YES.**

The confirmed graph anchor is the `connect()` syscall edge from the `postgres`-uid process on `prod-db-03` to `45.77.192.41:443`. The competing explanations diverge on _who initiated the syscall_: the canonical postgres server process, a postgres-spawned extension/UDF, or an attacker-injected subprocess (shell, interpreter, network tool). Falco records `proc.pname` and `proc.aname[...]` ancestry but the alert payload only surfaced `proc.name = postgres` — the full ancestry chain is a follow-up query away.

The very next lead is `process-lineage`: it returns the ancestry chain and directly partitions the hypothesis set. A clean canonical chain (postgres → postmaster → systemd) keeps benign hypotheses alive and refutes the attacker-subprocess form of the adversarial hypothesis. An anomalous chain (postgres → sh, postgres → python, postgres → curl) is `--` for all benign hypotheses and strongly implicates the adversarial branch. The lead selection is therefore hypothesis-conditional — it can't be collapsed to a mechanical query that means the same thing under all explanations.

**Interpretation-vulnerability: YES** (moderate — on the "is this ancestry canonical?" judgment field).

The ancestry chain itself is largely a mechanical read (either a shell is present or it isn't), but the step "is this a canonical process chain for postgres on this host?" carries a reviewer-disagreeable judgment: postgres can legitimately have varied ancestry depending on whether it was started via systemd unit, a wrapper script, a container entrypoint, or supervisord. Pre-registering the key readings prevents post-hoc drift on mixed-signal chains.

**ASSESS cell: yes / yes → HYPOTHESIZE with full per-hypothesis predictions.**

### Dispatch choice

**Single lead — `process-lineage`.**

Rationale: The ancestry chain is the highest-discrimination first query. It directly partitions the adversarial hypothesis from the benign cluster with a single syscall-level read that Falco provides at native authority. Composite dispatch is not warranted yet: the time window, entity scope, and query refinements for secondary leads (network-analysis, extension-inventory) all depend on whether the ancestry is anomalous — running them in parallel before the branch result is available wastes budget on leads that may be irrelevant. Network-analysis and extension-inventory are the correct loop-2 leads contingent on loop-1 outcome.

---

## HYPOTHESIZE (loop 1)

**Active hypotheses:**

- `?canonical-telemetry` — attaches upstream of `v-connect-edge` (the `connect()` syscall edge from `proc postgres` to `45.77.192.41:443`) via `initiated_by`; proposed parent: `{type: process, classification: canonical-postgres-server-process}`. Predicts: (1) ancestry chain is postgres → postmaster → init/systemd with no shell, interpreter, or network-tool in the chain; (2) passive-DNS name `api.postgresql-telemetry-eu.example` is listed in the vendor's published telemetry endpoint registry OR an org-approved extension/feature registry. Refutation shape: any shell, interpreter (python, perl, ruby), or standalone network tool (curl, wget, nc) appearing in the ancestor chain; OR the destination domain is absent from both vendor and org registries.

- `?extension-initiated` — attaches upstream of same `v-connect-edge` via `initiated_by`; proposed parent: `{type: process, classification: postgres-extension-or-udf}`. Predicts: (1) ancestry is canonical postgres chain (no shell) but a loaded extension (e.g., `pg_net`, `http`, `plpython3u`, custom `.so`) is consistent with outbound 443 capability; (2) no equivalent prior outbound connection from `prod-db-03` to any external host in the 90-day netflow window (first-ever pattern consistent with a recently activated extension). Refutation shape: ancestry chain contains a non-postgres binary; OR extension inventory shows no extension with outbound-HTTP capability installed/active.

- `?compromised-postgres` — attaches upstream of same `v-connect-edge` via `initiated_by`; proposed parent: `{type: process, classification: adversary-injected-subprocess}` (spawned via SQL injection, `COPY TO PROGRAM`, untrusted UDF, or RCE in a loaded library). Predicts: (1) ancestry chain contains at least one anomalous process — a shell (`sh`, `bash`, `dash`), interpreter (`python`, `perl`), or standalone network tool (`curl`, `wget`, `nc`) — between `postgres` and the process that called `connect()`; OR `proc.name` ≠ `postgres` (i.e., the connecting process is a child binary). Refutation shape: ancestry is exclusively canonical postgres server processes with no injected subprocess present.

- `?misconfigured-feature` — attaches upstream of same `v-connect-edge` via `initiated_by`; proposed parent: `{type: process, classification: postgres-server-process-with-misconfigured-feature}` (logical replication slot, foreign data wrapper, pg_cron job, `archive_command`). Predicts: (1) ancestry is canonical postgres chain; (2) a recently modified postgres config parameter or a newly created replication slot / FDW / scheduled job has an external-endpoint target matching the `45.77.77.*` range. Refutation shape: ancestry contains an anomalous subprocess; OR no recent config change, replication slot, FDW, or pg_cron job with external target exists.

**Selected lead:** `process-lineage` — queries the Falco event record for the full `proc.pname` and `proc.aname[...]` ancestry chain of the process that executed the alerting `connect()` syscall on `prod-db-03` at `2026-04-18T14:22:17.311Z`. Discriminates all four hypotheses: an anomalous subprocess anywhere in the chain is `--` for `?canonical-telemetry`, `?extension-initiated`, and `?misconfigured-feature`, and `++` predictor confirmation for `?compromised-postgres`. A clean canonical chain eliminates `?compromised-postgres` (subprocess form) and routes to loop-2 leads targeting the extension inventory and network history.

**Pre-registered readings for `process-lineage` outcome:**

- `if: ancestry is exclusively postgres → postmaster → init or systemd (no non-postgres binary in any aname slot)` → `read_as: canonical chain confirmed; ?compromised-postgres (subprocess form) weakly refuted; advance_to GATHER loop 2 targeting extension-inventory and network-analysis`
- `if: any aname slot contains sh / bash / dash / python / perl / ruby / curl / wget / nc / or a binary outside /usr/lib/postgresql/ and /usr/bin/` → `read_as: anomalous subprocess detected; ?compromised-postgres strongly supported; ?canonical-telemetry and ?extension-initiated and ?misconfigured-feature refuted; advance_to HYPOTHESIZE loop 2 (adversarial branch)`
- `if: ancestry is canonical postgres chain but proc.name at the connect() event is not 'postgres' (e.g., a .so-spawned process or a worker with unexpected binary name)` → `read_as: ambiguous — possible extension or injected library; neither clean canonical nor overt subprocess; advance_to HYPOTHESIZE loop 2 for extension-inventory + lineage disambiguation`
- `if: Falco ancestry record is unavailable or proc.aname fields are null/truncated (telemetry gap)` → `read_as: inconclusive; data gap; advance_to HYPOTHESIZE loop 2 but flag escalation risk — adversarial hypothesis cannot be refuted without ancestry`

**Pitfalls:**

- `?canonical-telemetry` trap: the passive-DNS record `api.postgresql-telemetry-eu.example` is attacker-controllable (any actor can register a plausible-looking hostname and point it at their infrastructure). Do not treat the domain name as authoritative — only an entry in the vendor's published registry or the org's approved-endpoint list carries weight. Absence of prior connections in 90 days is also consistent with a recently deployed C2 rather than a newly enabled telemetry feature.
- `?compromised-postgres` trap: postgres in some deployments legitimately spawns shell workers for `archive_command` or `restore_command` (point-in-time recovery). A bare `sh -c` in the ancestry does not automatically confirm compromise — the specific command arguments and the target binary matter. Pre-check whether `archive_command` is configured before grading a shell spawn as `++`.
- `?extension-initiated` trap: an extension with outbound capability (e.g., `pg_net`) can be legitimate or attacker-planted. Presence of the extension in the inventory is necessary but not sufficient for the benign reading — the _when it was installed_ and _what query triggered the call_ must also be checked to close the adversarial sub-case.

---

```yaml
hypothesize:
  hypotheses:
    - id: h-001
      name: "?canonical-telemetry"
      attached_to_vertex: v-003        # the connect() syscall edge's source process vertex
      proposed_edge:
        relation: initiated_by
        parent_vertex:
          type: process
          classification: canonical-postgres-server-process
      predictions:
        - id: p1
          claim: "Ancestry chain is postgres → postmaster → init/systemd with no shell, interpreter, or standalone network tool at any aname slot"
        - id: p2
          claim: "Destination domain api.postgresql-telemetry-eu.example is listed in the vendor's published telemetry endpoint registry or the org's approved-external-endpoint list"
      refutation_shape:
        - id: r1
          claim: "Any shell (sh/bash/dash), interpreter (python/perl/ruby), or standalone network tool (curl/wget/nc) present in proc.aname ancestry chain"
        - id: r2
          claim: "Destination domain absent from both vendor and org endpoint registries"
      weight: null
      status: active

    - id: h-002
      name: "?extension-initiated"
      attached_to_vertex: v-003
      proposed_edge:
        relation: initiated_by
        parent_vertex:
          type: process
          classification: postgres-extension-or-udf
      predictions:
        - id: p1
          claim: "Ancestry chain is canonical postgres (no shell/interpreter), but a loaded extension with outbound-HTTP capability (pg_net, http, plpython3u, or custom .so) is active on prod-db-03"
        - id: p2
          claim: "No prior outbound connection from prod-db-03 to any external host in 90-day netflow window (first-ever pattern consistent with recently activated extension)"
      refutation_shape:
        - id: r1
          claim: "Ancestry chain contains a non-postgres binary, indicating subprocess injection rather than extension"
        - id: r2
          claim: "Extension inventory shows no extension with outbound-HTTP or outbound-TCP capability installed or active"
      weight: null
      status: active

    - id: h-003
      name: "?compromised-postgres"
      attached_to_vertex: v-003
      proposed_edge:
        relation: initiated_by
        parent_vertex:
          type: process
          classification: adversary-injected-subprocess
          attributes:
            spawn_vector: "SQL injection / COPY TO PROGRAM / untrusted UDF / RCE in loaded library"
      predictions:
        - id: p1
          claim: "Ancestry chain contains at least one anomalous binary — shell (sh/bash/dash), interpreter (python/perl), or standalone network tool (curl/wget/nc) — between postgres and the connect() syscall, OR proc.name at connect() event is not 'postgres'"
      refutation_shape:
        - id: r1
          claim: "Ancestry is exclusively canonical postgres server processes (postmaster, postgres workers) with no injected subprocess present at any aname slot"
      weight: null
      status: active

    - id: h-004
      name: "?misconfigured-feature"
      attached_to_vertex: v-003
      proposed_edge:
        relation: initiated_by
        parent_vertex:
          type: process
          classification: postgres-server-process-with-misconfigured-feature
          attributes:
            feature_candidates: "logical replication slot, foreign data wrapper, pg_cron job, archive_command"
      predictions:
        - id: p1
          claim: "Ancestry chain is canonical postgres (no shell/interpreter); a recently modified config parameter, replication slot, FDW definition, or pg_cron job references an external endpoint in the 45.77.0.0/16 range"
      refutation_shape:
        - id: r1
          claim: "Ancestry contains an anomalous subprocess; or no recent config change, replication slot, FDW, or scheduled job with external target exists in the postgres config audit log"
      weight: null
      status: active
```
