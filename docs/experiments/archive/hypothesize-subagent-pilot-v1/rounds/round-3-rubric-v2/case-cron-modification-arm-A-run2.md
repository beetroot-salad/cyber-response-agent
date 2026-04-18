# HYPOTHESIZE Subagent Output — case-cron-modification arm-A run2

---

## Meta

**Files actually read:**
- `/workspace/docs/experiments/hypothesize-subagent-pilot/fixtures/case-cron-modification/truncated-investigation.md`
- `/workspace/soc-agent/skills/investigate/SKILL.md` (full file — §ASSESS ~line 138, §HYPOTHESIZE)
- `/workspace/soc-agent/knowledge/common-investigation/leads/process-lineage/definition.md`
- `/workspace/soc-agent/knowledge/common-investigation/leads/authentication-history/definition.md`
- `/workspace/docs/investigation-language.md` (§Hypothesis schema, §Philosophy, lead schema)

**ASSESS verdict — fork? yes / interp.-vulnerable? yes**

The confirmed anchor is the `file:modified` edge on `/etc/cron.d/backup-tasks` (uid 0, off-hours, novel script). The upstream parent-process classification forks across three observationally distinguishable candidates: a sanctioned CM agent, an interactive admin session, and an adversary-controlled process. This is a real hypothesis-space fork (three competing one-hop classifications with divergent predictions) — not a mechanical enrichment of a single parent. The auditd parent-chain field is interpretation-vulnerable: a process name like `python3` or `ansible-runner` could be read as CM-authorized or as attacker-mimicry depending on framing; pre-registration on that field is warranted.

**Lead selection mode — primary-plus-deferred**

`auditd-syscall-audit` is primary: it recovers the full parent process chain + session ID from the syscall record at T, partitioning all three hypotheses in a single query. `cm-deploy-audit` is deferred: it is only informative if the auditd chain produces a CM-plausible parent name — running it unconditionally would be wasteful and the result would be ambiguous without the auditd anchor. Secondary lead (`cm-deploy-audit`) fires in loop 2 conditional on a CM-consistent parent chain emerging from loop 1.

---

## HYPOTHESIZE (loop 1)

**Active hypotheses:**

- `?cm-deploy` — attaches upstream of `v-cron-file` (the `/etc/cron.d/backup-tasks` file vertex) via `modified_by`; proposed parent: `{type: process, classification: sanctioned-cm-agent}`. Predicts: (1) parent process chain at T terminates in a known CM agent binary (e.g., Ansible runner, Salt minion, Puppet agent) running as root; (2) session ID in auditd record corresponds to a non-interactive (batch) session with no prior `sshd` ancestor in the chain. Refutation shape: parent chain shows an interactive shell (bash/sh with a tty) as the invoking process, or parent chain terminates in a non-CM binary (web server, interpreter without CM context).

- `?interactive-admin` — attaches upstream of `v-cron-file` via `modified_by`; proposed parent: `{type: process, classification: interactive-admin-session}`. Predicts: (1) parent process chain at T includes a shell (bash/sh) descended from `sshd`; (2) session ID resolves to a login session from an org-internal admin IP within the T−30min window. Refutation shape: no sshd ancestor in the chain, or session IP is external / not in the admin subnet range.

- `?adversary-persistence` — attaches upstream of `v-cron-file` via `modified_by`; proposed parent: `{type: process, classification: adversary-controlled-process}`. Predicts: (1) parent process chain at T leads to an unexpected binary — a web application process, a service binary not expected to write to `/etc/cron.d/`, or an unrecognized executable path; (2) the invoking UID maps to a service account or the session has no prior interactive login record consistent with a known admin. Refutation shape: parent chain cleanly terminates in a CM agent with matching control-plane activity, or cleanly terminates in a known admin SSH session from an org-authorized IP.

**Selected lead:** `auditd-syscall-audit` (primary) — queries auditd records at T=2026-04-18T03:47:22Z for the `openat(O_WRONLY|O_TRUNC)` syscall on `/etc/cron.d/backup-tasks`; recovers the invoking process's pid, ppid, session ID, and full command-line, then walks the parent chain. Discriminates all three hypotheses by revealing whether the writer's process ancestry is: a CM agent binary (supports `?cm-deploy`), an sshd-descended shell (supports `?interactive-admin`), or an unexpected service/application binary (supports `?adversary-persistence`). `cm-deploy-audit` deferred to loop 2, conditional on a CM-plausible parent name appearing in the auditd chain.

**Pitfalls:**

- `?cm-deploy`: Attackers with prior root access can launch a process named `ansible-runner` or invoke the real Ansible binary to masquerade as an authorized deploy. The parent chain name alone is not sufficient — the session ID must also resolve to a non-interactive batch session with a corresponding Ansible Tower job record. Treating a CM-looking process name as authoritative without the control-plane corroboration is the primary trap here.

- `?interactive-admin`: A compromised admin account or a stolen SSH key produces a chain that looks identical to a legitimate admin session — sshd ancestor, known admin IP. Without a corresponding change-management ticket or authorized-change record, an apparently valid admin session cannot be graded `++` for benign intent; it only narrows to a human actor, not a sanctioned one.

- `?adversary-persistence`: The `sync-metrics.sh` script content is superficially benign (curl to a metrics endpoint, logger on error, no obfuscation). This is a weak positive signal at best; well-crafted persistence scripts are designed to look like legitimate tooling. Do not weight the script's apparent innocuousness as refuting evidence — only the process ancestry and control-plane record can do that.

---

```yaml
hypothesize:
  hypotheses:
    - id: h-001
      name: "?cm-deploy"
      attached_to_vertex: v-cron-file
      proposed_edge:
        relation: modified_by
        parent_vertex:
          type: process
          classification: sanctioned-cm-agent
      predictions:
        - id: p1
          claim: "Parent process chain at T terminates in a known CM agent binary (Ansible runner / Salt minion / Puppet agent) running as root under a non-interactive batch session ID"
        - id: p2
          claim: "Session ID in the auditd record has no sshd ancestor — batch session, not login shell"
      refutation_shape:
        - id: r1
          claim: "Parent chain shows an interactive shell (bash/sh with tty) as the invoking process, or terminates in a non-CM binary without CM-context arguments"
      weight: null
      status: active

    - id: h-002
      name: "?interactive-admin"
      attached_to_vertex: v-cron-file
      proposed_edge:
        relation: modified_by
        parent_vertex:
          type: process
          classification: interactive-admin-session
      predictions:
        - id: p1
          claim: "Parent process chain at T includes a shell (bash/sh) descended from sshd, with session ID resolving to a login session from an org-internal admin IP in the T−30min window"
      refutation_shape:
        - id: r1
          claim: "No sshd ancestor in the process chain, or the session source IP is external or not in the documented admin subnet range"
      weight: null
      status: active

    - id: h-003
      name: "?adversary-persistence"
      attached_to_vertex: v-cron-file
      proposed_edge:
        relation: modified_by
        parent_vertex:
          type: process
          classification: adversary-controlled-process
      predictions:
        - id: p1
          claim: "Parent process chain at T terminates in a binary not expected to write cron files — a web application worker, an exploited service binary, or an unrecognized executable path outside standard CM or shell tooling"
      refutation_shape:
        - id: r1
          claim: "Parent chain cleanly terminates in an authorized CM agent with matching control-plane job, or in a known admin SSH session from an org-authorized IP"
      weight: null
      status: active
```

**Pre-registered lead-level predictions for `auditd-syscall-audit` (loop 1 gather):**

The parent-chain classification field is interpretation-vulnerable. Pre-committed reading:

```yaml
predictions:
  - id: lp1
    if: "Parent chain terminates in ansible-runner, salt-minion, puppet, chef-client, or equivalent CM binary, running under a session with no tty and no sshd ancestor"
    read_as: "CM-consistent parent — supports ?cm-deploy (+); does not confirm without control-plane corroboration (cm-deploy-audit deferred lead required)"
    advance_to: "cm-deploy-audit"

  - id: lp2
    if: "Parent chain contains sshd → bash/sh lineage, session maps to an org-internal IP"
    read_as: "Interactive admin session — supports ?interactive-admin (+); source IP classification against admin subnet range is the next discriminator"
    advance_to: "session-audit"

  - id: lp3
    if: "Parent chain terminates in a service binary (nginx, gunicorn, node, java, etc.) or an unrecognized binary outside /usr/bin, /usr/sbin, /opt/cm-agent/ paths"
    read_as: "Unexpected writer — strongly supports ?adversary-persistence (++); ?cm-deploy and ?interactive-admin effectively refuted"
    advance_to: "HYPOTHESIZE"

  - id: lp4
    if: "Auditd record present but parent chain is ambiguous (short chain, pid 1 immediate parent, or missing ppid linkage)"
    read_as: "Inconclusive — process telemetry gap; cannot discriminate hypotheses from auditd alone"
    advance_to: "HYPOTHESIZE"
```
