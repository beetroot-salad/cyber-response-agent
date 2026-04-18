## HYPOTHESIZE (loop 1)

**ASSESS verdict:** yes / yes. Multiple plausible classifications of the process that wrote `/etc/cron.d/backup-tasks`; the discriminating lead (`auditd-syscall-audit`) returns the modifying process's pid/ppid/sid + command-line ancestry, whose reading ("is this ancestry consistent with a sanctioned writer?") is interpretation-vulnerable.

All mechanism hypotheses attach upstream of `e-001` (the file-write edge from the modifying process to `/etc/cron.d/backup-tasks`) — the proposed parent vertex is the writing process on v-001, differing by classification.

**Active hypotheses:**

- `?cm-deploy` (h-001) — proposed parent `{type: process, classification: cm-tool-worker}` (Ansible / Puppet / Salt / Chef agent worker). Predicts (p1): process ancestry traces to a CM-agent binary (`ansible-playbook`, `puppet`, `salt-minion`, `chef-client`) invoked by the CM control plane, AND a CM deploy run is logged in the control plane targeting `prod-api-02` within T ± 5min. Refutation shape (r1): no CM-agent process in ancestry OR no concurrent deploy run in the control plane's audit log.

- `?package-manager` (h-002) — proposed parent `{type: process, classification: package-manager}` (apt / dpkg / yum / rpm). Predicts (p1): ancestry traces to a package-manager binary AND the package-history shows a transaction near T. Refutation shape (r1): no package-manager in ancestry OR package-history clean (already largely inferred from CONTEXTUALIZE but needs auditd confirmation). Weight note: preliminary signal is already `-` (CONTEXTUALIZE observed package-history clean), but do not over-commit; the auditd ancestry is the authoritative refutation.

- `?human-operator-ssh` (h-003) — proposed parent `{type: process, classification: human-interactive-session}` (a shell spawned from an SSH session, with a TTY). Predicts (p1): ancestry contains an interactive shell (`bash`, `zsh`, `sh` with TTY attached) whose session traces back to a real SSH authentication event in the session-audit log, AND the SSH session's origin is a known admin workstation or bastion in the approved-origin list. Refutation shape (r1): no interactive shell in ancestry OR session origin is not in the approved-admin-origin list.

- `?adversary-controlled-write` (h-004, adversarial) — proposed parent `{type: process, classification: adversary-controlled}`. Predicts (p1): ancestry does not match a sanctioned writer pattern — i.e., no CM agent, no package manager, and either no interactive-session anchor at all OR an interactive session from an unapproved origin / at an anomalous time. Refutation shape (r1): ancestry matches one of the sanctioned patterns above (CM / package / approved-origin-operator).

**Selected lead:** `auditd-syscall-audit` — query auditd records for the `openat`/`write` syscall sequence targeting `/etc/cron.d/backup-tasks` at T, return `pid`, `ppid`, `ses` (session id), `auid` (audit uid), `comm`, `exe`, `a0..a3`, and the parent-chain via `ppid` walk. Single query returns data that partitions all four hypotheses by the ancestry classification.

**Lead-level `predictions` (pre-registered readings on the interpretive "sanctioned writer?" field):**

- `lp1`: ancestry contains `ansible-playbook` / `puppet` / `salt-minion` / `chef-client` (any CM agent), AND cm-deploy-audit sub-query (follow-on) confirms a deploy run targeting prod-api-02 at T ± 5min — `read_as` h-001 supported (→ `++` if both present; `+` if agent in ancestry but no correlating control-plane record yet queried); h-002 / h-003 / h-004 refuted.
- `lp2`: ancestry contains a package-manager binary (`apt`, `dpkg`, `yum`, `rpm`) — `read_as` h-002 supported (→ `+`); advance_to package-history cross-check before grading `++`.
- `lp3`: ancestry contains an interactive shell with TTY AND session traces to an authenticated SSH session from an approved-admin origin — `read_as` h-003 supported (→ `+`); advance_to session-audit cross-check (origin host, auth method, concurrent ticket reference) before grading `++`.
- `lp4`: ancestry contains an interactive shell whose session originates from an unapproved IP / at an anomalous time / lacks prior auth context — `read_as` h-004 supported (→ `++` after confirmation via session-audit); h-003 refuted.
- `lp5`: ancestry contains no interactive shell, no CM agent, no package manager — `read_as` h-004 strongly supported; advance_to backward-chain the writing process's ancestors via auditd to identify the spawning context (possibly exec'd from a network-facing service).
- `lp6` (fallback): auditd records for T are missing or truncated — data gap; advance_to HYPOTHESIZE with escalation flag, h-004 cannot be refuted without ancestry.

**Pitfalls:**

- `?cm-deploy`: CM-agent ancestry on a host that ALSO had its CM agent credentials compromised does not refute adversary-controlled — an attacker with the CM agent's credentials can push through the control plane. Require BOTH CM agent in ancestry AND an expected deploy run matched in the control plane's audit log (not just a recent deploy run, but one whose playbook/manifest contents actually match this change).
- `?human-operator-ssh`: "approved-admin origin" is a judgment call — treat it strictly as "IP is on the approved-admin-origin list in `environment/operations/admin-origins.md`" (or equivalent), not a plausibility judgment on the IP's reputation. An attacker who pivoted through an admin workstation would appear to originate from an approved IP — this hypothesis's `++` requires additional confirmation via the admin's concurrent ticket / change-request.
- `?adversary-controlled-write`: absence of a sanctioned pattern is the refutation shape, but the 03:47Z timestamp (off-hours) is already a mild supporting signal. Do not over-weight the timestamp alone — many legitimate CM/cron jobs run off-hours. The ancestry classification, not the timing, is the one-hop discriminator.

**Hypothesis refinement (deferred):**

h-004 will decompose via hierarchical IDs once the modifying context is confirmed — `{h-004-01 post-compromise-persistence, h-004-02 supply-chain-compromise-via-package, h-004-03 credential-theft-via-cm-plane}` distinguished by the specific anomalous signature in the ancestry + correlating evidence on preceding authentications or package installations. Do not pre-split here.
