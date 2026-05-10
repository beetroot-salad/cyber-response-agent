## Meta

### Files read

- `/workspace/docs/experiments/hypothesize-subagent-pilot/fixtures/case-cron-modification/truncated-investigation.md`
- `/workspace/soc-agent/skills/investigate/SKILL.md` (lines 1–350, §ASSESS + §HYPOTHESIZE)
- `/workspace/docs/investigation-language.md` (lines 1–350, §Hypothesis + §Lead schema)
- `/workspace/soc-agent/knowledge/common-investigation/leads/process-lineage/definition.md`
- `/workspace/soc-agent/knowledge/common-investigation/leads/ad-hoc/definition.md`
- `/workspace/soc-agent/knowledge/environment/context/ip-ranges.md`
- `/workspace/soc-agent/knowledge/environment/operations/deploy-runs.md`
- `/workspace/soc-agent/knowledge/environment/operations/scheduled-jobs.md`
- `/workspace/soc-agent/knowledge/environment/operations/approved-monitoring-sources.md`
- `/workspace/soc-agent/knowledge/environment/operations/change-windows.md`

### ASSESS verdict

**Branching: yes.** The very next lead depends on which explanation is true. `auditd-syscall-audit` is available and would mechanically recover the modifying process's pid/ppid/sid and full command-line. However, that query returns the same process-ancestry data regardless of hypothesis — it would not branch on hypothesis identity. But the *selection* of the first lead does branch: if the modification came from the CM control plane (Ansible), the discriminating first query is `cm-deploy-audit` (structured job history, binary yes/no); if it came from an interactive session, the discriminating first query is `session-audit` (SSH/su logins in the T−30 window). Both are plausible given the observables. Running `auditd-syscall-audit` first is tempting, but it only refines a vertex already partially known (uid=0 process, openat syscall) rather than choosing between competing upstream actors. The fork is open: which actor class wrote this file?

**Interpretation-vulnerable: yes.** The leading candidates (CM-authorized deploy vs. interactive admin vs. adversary) all overlap on surface-observable shape — root uid, off-hours timing, `curl`-invoked script. An `auditd-syscall-audit` outcome showing `ansible-playbook` as the immediate parent is mechanically unambiguous. But a `cm-deploy-audit` null result (no job found) is interpretation-vulnerable: absence of a recorded job could mean the activity was unauthorized, or it could mean the CM adapter is stale / the deploy ran out-of-band. Pre-registering branch plans on outcome fields is warranted.

Combined cell: **yes / yes** → HYPOTHESIZE with per-hypothesis predictions, pre-register lead-level predictions on the interpretation-vulnerable outcome fields.

### Dispatch choice

**Single lead: `cm-deploy-audit`** (Ansible Tower query targeting `prod-api-02`, window T−15min to T+5min).

Rationale: `cm-deploy-audit` is the highest-severity discriminating lead given the observables. A positive match with job type consistent with cron-entry creation would strongly support `?cm-authorized-deploy` and simultaneously refute `?unauthorized-modification` and `?adversary-persistence` without requiring further process-ancestry work. A null result is a meaningful partial refutation of the CM-authorized story, opening the adversarial branch without ambiguity. `auditd-syscall-audit` would be valuable but is a second-order step: it enriches the confirmed graph (parent pid/ppid/command-line) without collapsing the hypothesis fork on its own — the process name recovered from auditd would still require CM validation to distinguish a CM-agent process from an impostored one. Running CM first collapses the fork more cleanly.

---

## HYPOTHESIZE (loop 1)

### Hypothesis formation

Three plausible one-hop upstream vertices attach to the confirmed `file-modification` edge on `prod-api-02:/etc/cron.d/backup-tasks`. Enumeration follows the novel-alert protocol: anchor → enumerate one-hop parents → constrain with observables.

**Anchor vertex:** `v-002` — the production API host `prod-api-02` (10.0.3.27). The confirmed edge is `e-001`: a `file-modification` event on `/etc/cron.d/backup-tasks` at 2026-04-18T03:47:22Z by uid=0.

**Observables that constrain the hypothesis set:**

- uid=0 (root) — narrows actor to: CM agent running as root, interactive admin (sudo/su), or adversary with root. Rules out unprivileged process.
- `openat` with `O_WRONLY|O_TRUNC` — deliberate truncate-and-write, not append; consistent with config-management idempotent writes.
- Off-hours (03:47 UTC) — not a typical operator window, consistent with CM cron runs or adversary operating outside business hours.
- No package-management events in 24h — rules out package-postinstall as the proximate cause; narrows to direct file write.
- Script content (`curl` to `metrics-ingest.hosted-vendor.example`) — ambiguous: could be a legitimate new metrics integration deployed via CM, or an adversary dropping a callback script styled to look like monitoring.
- No prior tickets for this script or domain — raises novelty signal; no precedent for legitimate baseline.

**Hypotheses:**

1. `?cm-authorized-deploy` — the modifying process is the Ansible agent (`ansible-playbook` or `ansible-runner`) running a sanctioned deploy job targeting `prod-api-02`. One-hop upstream: `process:cm-agent` connected to `v-002` via `initiated-file-modification`. Prediction: a CM deploy run exists in Ansible Tower for `prod-api-02` with window containing T.

2. `?unauthorized-interactive-modification` — an authenticated operator (or attacker with a valid session) modified the file interactively during a shell session. One-hop upstream: `session:interactive-shell` connected to `v-002` via `initiated-file-modification`. Prediction: an SSH or console session exists on `prod-api-02` from T−30min to T, from an internal operator IP, using a named human identity.

3. `?adversary-persistence` — an adversary with an existing root foothold on `prod-api-02` added a cron entry to maintain persistence and establish a callback channel. One-hop upstream: `process:adversary-controlled` connected to `v-002` via `initiated-file-modification`. Prediction: no CM deploy run covers this modification AND no authorized session on record — the modifying process is either anomalous or originates from a non-operator identity.

Note: `?adversary-persistence` is the mandatory adversarial hypothesis. It remains active until explicitly refuted with `--` weight evidence.

---

```yaml
hypothesize:
  hypotheses:
    - id: h-001
      name: "?cm-authorized-deploy"
      attached_to_vertex: v-002
      proposed_edge:
        relation: initiated-file-modification
        parent_vertex:
          type: process
          classification: cm-agent
          attributes:
            binary: ansible-playbook
            identity: service-account (CM runner)
      predictions:
        - id: p1
          claim: >
            Ansible Tower shows a deploy job whose target includes prod-api-02
            with a window containing 2026-04-18T03:47:22Z; job type is
            consistent with cron-entry creation or metrics-integration
            deployment.
      refutation_shape:
        - id: r1
          claim: >
            No CM deploy run recorded for prod-api-02 in the T−15min to T+5min
            window, OR the run exists but its job type is inconsistent with
            cron-entry modification.
      weight: null
      status: active

    - id: h-002
      name: "?unauthorized-interactive-modification"
      attached_to_vertex: v-002
      proposed_edge:
        relation: initiated-file-modification
        parent_vertex:
          type: session
          classification: interactive-shell
          attributes:
            source: internal-operator-ip
            identity: named-human-account
      predictions:
        - id: p1
          claim: >
            Session-audit shows an authenticated SSH or console login to
            prod-api-02 from a known operator identity in the T−30min to
            T window, with no corresponding CM deploy job.
      refutation_shape:
        - id: r1
          claim: >
            No interactive session on prod-api-02 in the T−30min to T window
            from any operator identity, or the session identity matches a
            CM service account rather than a human operator.
      weight: null
      status: active

    - id: h-003
      name: "?adversary-persistence"
      attached_to_vertex: v-002
      proposed_edge:
        relation: initiated-file-modification
        parent_vertex:
          type: process
          classification: adversary-controlled
          attributes:
            foothold: existing-root-access
            intent: persistence-and-callback
      predictions:
        - id: p1
          claim: >
            No CM deploy run covers this modification AND no authorized
            operator session is present at T; the modifying process ancestry
            (from auditd) traces to an anomalous or non-standard parent
            (e.g., web server, unexpected interpreter, or dropped binary).
        - id: p2
          claim: >
            `metrics-ingest.hosted-vendor.example` has no prior outbound
            connections from prod-api-02 in the 30-day window, and the domain
            is not registered under the org's known vendor list.
      refutation_shape:
        - id: r1
          claim: >
            A confirmed CM deploy job OR an authorized operator session accounts
            for the modification with no unexplained residuals.
      weight: null
      status: active
```

---

### Next lead — GATHER

**Lead:** `cm-deploy-audit`

Query the Ansible Tower API for any deploy run whose target includes `prod-api-02` with a window of T−15min to T+5min (2026-04-18T03:32Z – 2026-04-18T03:52Z).

**Tests:** h-001, h-002, h-003

**Lead-level predictions (interpretation-vulnerable outcome fields):**

- `lp1`: if a run is returned with target `prod-api-02` AND job type consistent with cron-entry or metrics-integration deployment AND window contains T → read_as `cm-authorized-deploy confirmed` → advance_to ANALYZE (h-001 ++; requires corroboration from auditd-syscall-audit process name before CONCLUDE)
- `lp2`: if a run is returned with target `prod-api-02` BUT job type is a different activity class (e.g., security patch, package upgrade) → read_as `suspicious timing — CM job existed but wrong type` → advance_to HYPOTHESIZE (refine h-001; h-003 gains weight)
- `lp3`: if no run returned for `prod-api-02` in window → read_as `CM-authorized-deploy refuted` → advance_to GATHER (next: `session-audit` to test h-002 vs h-003)
- `lp4`: if anchor unavailable (Ansible Tower unreachable or API error) → read_as `authorization anchor degraded` → advance_to CONCLUDE with status=escalate, context: "CM deploy-audit unavailable, cannot rule out unauthorized modification on production API host"
