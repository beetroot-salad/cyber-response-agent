## Meta

### Files Actually Read

- `/workspace/docs/experiments/hypothesize-subagent-pilot/fixtures/case-cron-modification/truncated-investigation.md`
- `/workspace/soc-agent/skills/investigate/SKILL.md` (full file — §ASSESS ~line 138, §HYPOTHESIZE ~line 318)
- `/workspace/docs/investigation-language.md` (lines 1–250 — §Philosophy, §Schema, §Hypothesis struct)
- `/workspace/soc-agent/knowledge/common-investigation/leads/process-lineage/definition.md`
- `/workspace/soc-agent/knowledge/common-investigation/leads/authentication-history/definition.md`
- `/workspace/soc-agent/knowledge/environment/context/identity-patterns.md`
- `/workspace/soc-agent/knowledge/environment/context/ip-ranges.md`

### ASSESS Verdict

**Branching: no.** The very next lead is `auditd-syscall-audit` regardless of which explanation is true — it is the universal "who wrote this file" recovery step. All active hypotheses (CM deploy agent, authorized admin session, attacker persistence) route to the same first query. The fork in *lead selection* does not open until the auditd result is in hand: if the output shows a CM agent binary → the branch favors `cm-deploy-audit` next; if it shows an interactive bash shell under sshd → `session-audit`; if it shows an unrecognized binary with no authorized parent → adversarial hypotheses intensify. Step-1 does not branch; step-2 will.

**Interpretation-vulnerable: yes.** The auditd outcome fields are heavily interpretation-loaded. The modifying process's binary name, parent chain, and session membership all require pre-committed reading rules to avoid post-hoc rationalization: a `python3` or `ruby` binary in the parent chain could be either a CM tool (Puppet/Chef) or a dropped payload; a `bash` process parented under `sshd` could be an authorized admin or an attacker's reverse shell. Without pre-registered interpretation commitments, the "CM-deploy" reading and the "attacker-dropped" reading are both plausible post-hoc for many outcome shapes.

Per the ASSESS rubric this is **no / yes** → skip HYPOTHESIZE, pre-register `lead.predictions` in GATHER. However, the task explicitly requests a HYPOTHESIZE (loop 1) block, and the competing explanations are substantive enough that articulating the hypothesis frontier before a novel first lead provides genuine structural value for the investigation record. The HYPOTHESIZE block is produced; the GATHER pre-registrations are especially important and are included below.

### Dispatch Choice

**Single lead: `auditd-syscall-audit`.** The lead is a single-entity, single-data-source query against `prod-api-02`'s auditd SYSCALL+PATH records for the T-window. No cross-lead refinement is needed before running it — the entity bindings and time window are fully determined from the alert. Composite dispatch would be premature: later leads (`cm-deploy-audit`, `session-audit`, `network-flow`) all benefit from the auditd result as a refinement input (narrowing the deploy-run window to the process's session timestamp, restricting the SSH session lookup to the observed SID). Run auditd first; compose later leads once the actor identity is recovered.

---

## HYPOTHESIZE (loop 1)

**Active hypotheses:**

- `?authorized-cm-deploy` — attaches upstream of `v-cron-file` (the `/etc/cron.d/backup-tasks` file-modification edge `e-fim-write`) via `executed_by`; proposed parent: `{type: process, classification: cm-deploy-agent}`. Predicts: (1) the modifying process binary is a recognized CM tool (ansible-pull, puppet agent, chef-client, salt-minion, or a CM wrapper script in a standard CM path); (2) the process's session ID maps to a non-interactive session (no tty, no sshd parent) consistent with a headless CM agent invocation. Refutation shape: modifying process binary is not in any recognized CM tool path, OR process tree terminates in an interactive login shell / sshd session.

- `?authorized-admin-session` — attaches upstream of `v-cron-file` via `executed_by`; proposed parent: `{type: process, classification: interactive-admin-shell}`. Predicts: (1) the modifying process parent chain terminates in `sshd` (the operator connected interactively near T); (2) the session ID for the modifying process matches an authenticated SSH session in the T−30min to T window. Refutation shape: no sshd ancestor in parent chain, OR session timestamp does not co-locate with any SSH login event.

- `?attacker-persistence` — attaches upstream of `v-cron-file` via `executed_by`; proposed parent: `{type: process, classification: adversary-controlled}`. Predicts: (1) the modifying process binary is not a recognized CM tool and not a well-known system shell parented under sshd — either an unrecognized binary path, or a shell whose parent chain does not reach a recognized authorized-entry edge (no sshd, no CM daemon, no recognized service manager entry); (2) the script content (`sync-metrics.sh`) references a domain (`metrics-ingest.hosted-vendor.example`) with no prior outbound history from `prod-api-02` in netflow. Refutation shape: binary is a recognized CM tool OR process lineage cleanly traces to a known authorized entry point.

**Completeness check:**
- Classification coverage: automated/CM (`?authorized-cm-deploy`), human-authorized (`?authorized-admin-session`), adversarial (`?attacker-persistence`). Human-unauthorized (insider acting outside change window) is structurally identical to `?authorized-admin-session` at the auditd level (sshd parent chain present) and will diverge at the CM deploy audit cross-check — the distinction defers to loop 2. No orphaned axis.
- Adversarial: `?attacker-persistence` is active and carries explicit refutation shape.
- Leanness: each hypothesis has exactly 2 predictions. Second prediction on `?attacker-persistence` (network-flow check) is included because the curl-to-unknown-domain observation is a second independent discriminator that does not overlap with the process lineage check — together they are necessary because a compromised CM agent could satisfy prediction-1 alone while still being adversarial.

**Selected lead:** `auditd-syscall-audit` — recovers the modifying process's pid, ppid, session ID, euid, and full command-line from auditd SYSCALL+PATH records for the `openat(O_WRONLY|O_TRUNC)` event on `/etc/cron.d/backup-tasks` at 2026-04-18T03:47:22Z on `prod-api-02`. Its outcome discriminates all three active hypotheses: the process binary and parent chain directly segregate CM-agent vs. interactive shell vs. unrecognized binary.

**Pitfalls:**

- `?authorized-cm-deploy`: A compromised or hijacked CM agent will present with the CM binary in the parent chain — the process lineage alone cannot distinguish a legitimate CM run from an attacker leveraging a CM agent's footprint. Mitigation: cross-check with CM control plane (step-2 `cm-deploy-audit`) before grading `++`.
- `?authorized-admin-session`: Reverse shell / bind shell payloads can create a process tree that terminates in a shell with `sshd`-lookalike parent, especially if the attacker renamed their binary. Mitigation: inspect the full command-line and binary hash, not just the parent name string.
- `?attacker-persistence`: The script content (`curl` POST with system stats, `logger` on error) is consistent with both a legitimate telemetry agent and an exfiltration stub — script plausibility is attacker-controllable. Do not grade the "looks benign" script reading as `+` for `?authorized-*`; it belongs in `script-analysis` not auditd, and must be pre-registered as interpretation-vulnerable.

**Pre-registered lead predictions (for GATHER, `auditd-syscall-audit`):**

These pre-registrations apply to the interpretation-vulnerable fields in the auditd outcome. Record before running the lead:

```
if: modifying process binary path matches recognized CM tool pattern
    (ansible-pull, /usr/bin/puppet, /opt/chef/bin/chef-client, /usr/bin/salt-minion,
     or a wrapper script under /etc/ansible/, /var/lib/puppet/, /var/chef/, /srv/salt/)
    AND no tty in session (sess field non-interactive)
read_as: supports ?authorized-cm-deploy; route to cm-deploy-audit next
advance_to: cm-deploy-audit

if: modifying process parent chain terminates in sshd AND binary is /bin/bash or /usr/bin/bash
    AND session field maps to an interactive tty
read_as: supports ?authorized-admin-session; route to session-audit next to confirm identity
advance_to: session-audit

if: modifying process binary is unrecognized (not in /usr/bin/, /bin/, /usr/local/bin/ standard paths,
    or is a standard-path binary with an anomalous parent not matching CM or sshd lineage)
read_as: supports ?attacker-persistence; escalation posture elevated
advance_to: HYPOTHESIZE (loop 2) to narrow adversarial sub-hypothesis

if: outcome is ambiguous (binary is standard shell but parent chain unclear due to short-lived ppid,
    or auditd records are incomplete for this T window)
read_as: data gap — insufficient to discriminate; do not grade any hypothesis
advance_to: HYPOTHESIZE (loop 2) with data-gap flag; consider data-source-debug lead
```

---

```yaml
hypothesize:
  hypotheses:
    - id: h-001
      name: "?authorized-cm-deploy"
      attached_to_vertex: v-001
      proposed_edge:
        relation: executed_by
        parent_vertex:
          type: process
          classification: cm-deploy-agent
          attributes:
            binary_pattern: "ansible-pull | puppet agent | chef-client | salt-minion | CM wrapper"
            session_type: non-interactive
      predictions:
        - id: p1
          claim: "Modifying process binary path matches a recognized CM tool (ansible-pull, puppet, chef-client, salt-minion, or a wrapper script under a standard CM path)"
        - id: p2
          claim: "Session ID for the modifying process maps to a headless, non-tty session (no interactive sshd parent in process lineage)"
      refutation_shape:
        - id: r1
          claim: "Modifying process binary is not in any recognized CM tool path, OR process tree terminates in an interactive login shell or sshd session"

    - id: h-002
      name: "?authorized-admin-session"
      attached_to_vertex: v-001
      proposed_edge:
        relation: executed_by
        parent_vertex:
          type: process
          classification: interactive-admin-shell
          attributes:
            parent_ancestor: sshd
            session_type: interactive-tty
      predictions:
        - id: p1
          claim: "Modifying process parent chain terminates in sshd (operator connected via SSH near T)"
        - id: p2
          claim: "Session ID for the modifying process co-locates with an authenticated SSH login event in the T−30min to T window"
      refutation_shape:
        - id: r1
          claim: "No sshd ancestor in parent chain, OR session timestamp does not co-locate with any SSH login event on prod-api-02"

    - id: h-003
      name: "?attacker-persistence"
      attached_to_vertex: v-001
      proposed_edge:
        relation: executed_by
        parent_vertex:
          type: process
          classification: adversary-controlled
          attributes:
            binary_pattern: "unrecognized or standard binary with anomalous parent chain"
      predictions:
        - id: p1
          claim: "Modifying process binary is not a recognized CM tool and does not trace to an authorized entry point (sshd with valid session, CM daemon, or recognized service manager)"
        - id: p2
          claim: "metrics-ingest.hosted-vendor.example has no prior outbound connection history from prod-api-02 in netflow (first-ever connection, no baseline)"
      refutation_shape:
        - id: r1
          claim: "Binary is a recognized CM tool OR process lineage cleanly traces to a known authorized entry point (sshd with confirmed identity, or CM agent with control-plane deploy record)"
      concerns:
        - "Script content (curl POST, logger) is attacker-controllable and cannot be treated as a legitimacy signal from auditd alone"
        - "A compromised CM agent will present with CM binary in lineage — auditd alone cannot rule this out; requires cm-deploy-audit cross-check"
```
