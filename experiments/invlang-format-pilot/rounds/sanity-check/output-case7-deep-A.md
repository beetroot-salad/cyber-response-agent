```yaml
gather:
  - id: l-002
    loop: 2
    name: auditd-write-attribution
    target: v-002
    tests: [h-002, h-003]
    predictions:
      - id: lp1
        if: "auditd (rule 591 or raw audit.log) names a process whose session leader was opened by a user in admin-group / sudoers AND the ssh session originating that leader shows a source IP inside the admin jump-host CIDR range"
        read_as: "admin-interactive-writer with jump-host-origin session — mechanism confirmed for h-002, adversarial-origin signal absent for h-003"
        advance_to: CONCLUDE
      - id: lp2
        if: "auditd names a process whose session leader was opened by a user in admin-group / sudoers BUT the ssh session originating that leader shows a source IP OUTSIDE the admin jump-host CIDR range (or no preceding ssh session, or impossible-travel / concurrent-session signal)"
        read_as: "admin-identity write from unexpected origin — mechanism-level integrity anomaly for h-003 (adversary-controlled-session via admin account)"
        advance_to: CONCLUDE
      - id: lp3
        if: "auditd names a process whose session leader was opened by a non-admin account that is also not a documented automation identity"
        read_as: "non-admin non-automation writer — direct satisfaction of h-003 prediction p1 clause (a); h-002 refuted"
        advance_to: CONCLUDE
      - id: lp4
        if: "auditd has no record of a write to /etc/ssh/sshd_config.d/99-crypto.conf at 2026-04-21T03:47:21Z (±5s), OR auditd is not running / rule 591 is not loaded on target-endpoint"
        read_as: "attribution data unavailable — discriminator not measurable by this channel"
        advance_to: HYPOTHESIZE
```

Selected lead: `auditd-write-attribution` (new) — query auditd / Wazuh rule 591 on target-endpoint for the write syscall touching `/etc/ssh/sshd_config.d/99-crypto.conf` at 2026-04-21T03:47:21Z (±5s), returning `{pid, exe, comm, auid, uid, ses, ppid, tty}`; then resolve the session leader's originating identity and, if an ssh session, its source IP. data_tags: [process-events, auth-events]. Partitions h-002 (admin + jump-host origin) from h-003 (non-admin OR admin-from-unexpected-origin).

Pitfalls:
- lp1: an admin account whose credentials have been phished can produce lp1's signature exactly — jump-host-origin alone does not rule out adversary use of a valid admin credential. Legitimacy contract `h-002.lc1` (approved change-window) must still resolve `authorized` before disposition:benign; a jump-host-origin write outside any approved change window remains indeterminate and should route to the change-window authority, not CONCLUDE benign.
- lp2: "admin account from unexpected origin" can also be a legitimate operator working from a new workstation or on-call location that hasn't been added to the documented jump-host CIDR — the integrity anomaly is weak without corroboration (concurrent session elsewhere, impossible-travel, failed-auth precursor). Read this as `+` for h-003 pending corroboration, not `++`.
- lp3: a misconfigured automation identity (e.g., a CM agent run under a service account not yet in the documented-automation registry) can trip lp3 and look adversarial; cross-check the UID against any local automation service accounts (systemd service units owning the pid's cgroup) before grading h-003 `++`.
- lp4: auditd gaps are common on containers and minimal server images — absence of a rule-591 event is not itself refutation of either h-002 or h-003. Re-enter HYPOTHESIZE to consider alternate attribution channels (shell history on target-endpoint, ssh session log `/var/log/auth.log` correlation at the write timestamp, process-accounting / pacct if enabled) rather than treating the gap as evidence.
