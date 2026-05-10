## Meta

### Files read
- `/workspace/docs/experiments/hypothesize-subagent-pilot/fixtures/case-cron-modification/truncated-investigation.md`
- `/workspace/soc-agent/skills/investigate/SKILL.md` (full file — §ASSESS ~line 138, §HYPOTHESIZE)
- `/workspace/docs/investigation-language.md` (§Hypothesis, §Lead schema, §Philosophy — lines 1–320)
- `/workspace/soc-agent/knowledge/common-investigation/leads/process-lineage/definition.md`
- `/workspace/soc-agent/knowledge/common-investigation/leads/authentication-history/definition.md`
- `/workspace/soc-agent/knowledge/environment/operations/scheduled-jobs.md`
- `/workspace/soc-agent/knowledge/environment/operations/deploy-runs.md`

### ASSESS verdict

**Fork: yes.** The anchor (`prod-api-02` file-modification event, uid=0) admits three competing one-hop parent classifications whose predictions diverge observationally: a CM-deploy process chain, an interactive-admin shell session, and an anomalous/adversary-controlled process. These cannot be collapsed — each predicts a different parent-process identity, a different session type, and a different authorization trail.

**Interpretation-vulnerable: yes.** The `auditd-syscall-audit` lead returns the modifying process's command line and parent chain. Classifying the parent chain (e.g., "this `python3` invocation is a legitimate Ansible task vs. an adversary mimicking one") is an interpretive judgment, not a mechanical read. Pre-registered predictions on the process-classification field are warranted.

### Lead selection mode

**Primary-plus-deferred.** `auditd-syscall-audit` is the primary lead: it recovers the modifying process's exact identity (pid, ppid, uid, session-id, full command-line) and partitions all three hypotheses in one query — a CM agent chain, an interactive shell ancestry, and an anomalous parent each produce structurally different process trees. The deferred leads (`cm-deploy-audit` and `session-audit`) are genuinely conditional: they verify authorization only after the primary lead identifies the process class. Running them before knowing the process class is wasteful — `cm-deploy-audit` is irrelevant if auditd shows an interactive bash session, and `session-audit` is irrelevant if auditd shows a CM runner. Primary-plus-deferred is the correct mode here; composite dispatch would not improve the discrimination value of the first query and would couple the deferred leads' scope prematurely.

---

## HYPOTHESIZE (loop 1)

**Active hypotheses:**

- `?cm-deploy` — attaches upstream of `v-001` (the `cron-file-modified` edge on `prod-api-02`) via `written_by`; proposed parent: `{type: process, classification: cm-agent}`. Predicts: (1) the auditd parent chain traces to a recognized CM runner binary (e.g., `ansible-runner`, `python3 /opt/ansible/...`, `salt-minion`, `puppet`), and (2) the session-id on the SYSCALL record corresponds to a non-interactive (no TTY) session. Refutation shape: parent chain terminates in an interactive shell (`bash`, `sh`, `zsh`) with a TTY session-id, or in any binary outside the CM toolchain.

- `?interactive-admin` — attaches upstream of `v-001` via `written_by`; proposed parent: `{type: process, classification: human-operator-shell}`. Predicts: (1) the auditd parent chain traces to an interactive shell (`bash`/`sh`/`zsh`) with a non-null TTY and a session-id matching a concurrent SSH or console login. Refutation shape: parent chain traces to a CM agent binary with no TTY, or to a process with anomalous parentage (web server, container runtime, exploit artifact).

- `?adversary-persistence` — attaches upstream of `v-001` via `written_by`; proposed parent: `{type: process, classification: adversary-controlled}`. Predicts: (1) the auditd parent chain traces to a process with anomalous parentage for a production API host (e.g., web server process → shell, unexpected binary path, first-ever occurrence of this parent→child pair on `prod-api-02` in the 30d window). Refutation shape: parent chain traces cleanly to a CM runner or an interactive admin shell session authenticated within the T−30min window.

**Selected lead:** `auditd-syscall-audit` — recovers the modifying process's pid, ppid, session-id, and full command line from auditd SYSCALL+PATH records at T=2026-04-18T03:47:22Z on `prod-api-02`. This single measurement discriminates all three hypotheses: CM agent chains, interactive shell sessions, and anomalous parent chains produce structurally distinct process trees. Deferred: `cm-deploy-audit` (verify Ansible Tower/SaltStack run targeting `prod-api-02` in T±10min window) and `session-audit` (verify SSH/login sessions in T−30min window) — dispatched in the next loop, conditional on the process classification returned here.

**Pitfalls:**

- `?cm-deploy`: An adversary with CM credentials or access to the CM control plane could trigger a rogue deploy job that writes an attacker-controlled cron entry. The process chain pointing to `ansible-runner` is not by itself authorization evidence — it only establishes *how* the file was written, not that the CM run was sanctioned. Do not grade `?cm-deploy` as refuted solely because the CM agent is the writing process; the `cm-deploy-audit` deferred lead is required to verify a legitimate run actually exists.

- `?interactive-admin`: Off-hours modification (03:47 UTC) by uid=0 on a production host is plausible for emergency maintenance but is also a classic adversary pattern post-initial-access. An interactive shell session in the T−30min window is necessary but not sufficient — the session must be traceable to a known admin identity. An SSH session from an unrecognized source IP would be a strong adversarial signal even if the parent chain looks interactive.

- `?adversary-persistence`: `sync-metrics.sh` invokes `curl` to an external vendor endpoint with no obfuscation. Adversaries sometimes use legitimate-looking curl-based exfiltration/C2 disguised as metrics collection; the absence of obfuscation is attacker-controllable and should not be read as a benign signal. The endpoint (`metrics-ingest.hosted-vendor.example`) has no prior traffic history and is unregistered in ticket-context — treat it as unvalidated until `network-flow` or threat-intel confirms it is a known legitimate vendor.

---

```yaml
hypothesize:
  hypotheses:
    - id: h-001
      name: "?cm-deploy"
      attached_to_vertex: v-001
      proposed_edge:
        relation: written_by
        parent_vertex:
          type: process
          classification: cm-agent
          attributes:
            binary_hint: "ansible-runner | python3 (ansible task) | salt-minion | puppet"
      predictions:
        - id: p1
          claim: "auditd parent chain traces to a CM runner binary (ansible-runner, salt-minion, puppet, or python3 executing an ansible/salt/puppet module path)"
        - id: p2
          claim: "SYSCALL session-id corresponds to a non-interactive (no-TTY) session"
      refutation_shape:
        - id: r1
          claim: "parent chain terminates in an interactive shell (bash/sh/zsh) with a TTY session-id, or in any binary outside the recognized CM toolchain"
      weight: null
      status: active

    - id: h-002
      name: "?interactive-admin"
      attached_to_vertex: v-001
      proposed_edge:
        relation: written_by
        parent_vertex:
          type: process
          classification: human-operator-shell
          attributes:
            session_type: interactive
      predictions:
        - id: p1
          claim: "auditd parent chain traces to an interactive shell (bash/sh/zsh) with a non-null TTY, and session-id matches a concurrent SSH or console login in the T-30min window"
      refutation_shape:
        - id: r1
          claim: "parent chain traces to a CM agent binary with no TTY, or to a process with anomalous parentage (web server, container runtime, unknown binary)"
      weight: null
      status: active

    - id: h-003
      name: "?adversary-persistence"
      attached_to_vertex: v-001
      proposed_edge:
        relation: written_by
        parent_vertex:
          type: process
          classification: adversary-controlled
          attributes:
            anomaly_hint: "unexpected parent for prod API host — web process, exploit artifact, or first-ever parent→child pair"
      predictions:
        - id: p1
          claim: "auditd parent chain traces to a process with anomalous parentage for prod-api-02 (e.g., web server → shell, unknown binary path, or first-ever occurrence of this parent→child pair in the 30d fleet window)"
      refutation_shape:
        - id: r1
          claim: "parent chain traces cleanly to a CM runner or an interactive admin shell session authenticated within the T-30min window via a known admin identity"
      weight: null
      status: active
```

**Pre-registered lead-level predictions for `auditd-syscall-audit`:**

```yaml
lead_predictions:
  - id: lp1
    if: "parent chain traces to a recognized CM runner binary AND session-id is non-interactive (no TTY)"
    read_as: "?cm-deploy hypothesis supported (+); dispatch cm-deploy-audit to verify a sanctioned run exists"
    advance_to: "cm-deploy-audit (deferred lead)"
  - id: lp2
    if: "parent chain traces to an interactive shell (bash/sh/zsh) AND session-id carries a TTY"
    read_as: "?interactive-admin hypothesis supported (+); dispatch session-audit to identify the authenticating actor and source IP"
    advance_to: "session-audit (deferred lead)"
  - id: lp3
    if: "parent chain traces to a web server process, container runtime, or unknown binary path not in the CM or interactive toolchain; OR first-ever parent→child pair on prod-api-02 in 30d"
    read_as: "?adversary-persistence hypothesis strongly supported (++); escalate immediately and dispatch session-audit + network-flow to bound scope"
    advance_to: "HYPOTHESIZE (escalation branch)"
  - id: lp4
    if: "auditd records are missing, truncated, or the SYSCALL record does not contain a resolvable parent chain"
    read_as: "evidence gap — cannot discriminate hypotheses from auditd alone; escalate with data gap noted"
    advance_to: "CONCLUDE (escalated, inconclusive)"
```
