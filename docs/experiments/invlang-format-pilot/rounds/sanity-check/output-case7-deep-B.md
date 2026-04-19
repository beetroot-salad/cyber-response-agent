```yaml
gather:
  - id: l-002
    loop: 2
    name: auditd-process-attribution
    target: v-file-change-99-crypto-conf
    predictions:
      - {id: lp1, if: "auditd attributes the write to a uid mapping to an account in the admin/sudoers group AND the session chain traces back to sshd from a documented admin jump-host source IP", read_as: "admin-interactive-session-confirmed", advance_to: approved-change-window-lookup}
      - {id: lp2, if: "auditd attributes the write to a non-admin uid (non-sudoers, not a documented service/automation account) OR the session originated from a source IP outside the documented admin jump-host range", read_as: "adversary-controlled-session-confirmed", advance_to: CONCLUDE}
      - {id: lp3, if: "auditd attributes the write to a documented service/automation account (e.g., certbot, node_exporter deploy hook) with a sanctioned edit path for sshd_config.d", read_as: "automation-identity-reinstated", advance_to: HYPOTHESIZE}
      - {id: lp4, if: "auditd has no record of the write at mtime_after (no ausearch hit on path or inode within ±5s) OR the auditd daemon was not running / rules not loaded during the window", read_as: "attribution-unavailable", advance_to: CONCLUDE}
```

Selected lead: `auditd-process-attribution` — query auditd on target-endpoint for any `PATH`/`SYSCALL` record naming `/etc/ssh/sshd_config.d/99-crypto.conf` (or its inode) with a write-class syscall (open+O_WRONLY, openat+O_WRONLY/O_CREAT/O_TRUNC, rename, truncate) in the window `2026-04-21T03:47:15Z..03:47:28Z`. For each hit capture uid, auid (login uid), ses (session id), exe, and comm; then pivot on auid+ses to the originating `USER_START` / sshd login record to recover source IP. Single dispatch.

Pitfalls:
- lp1: admin-group membership alone does not confirm legitimacy — an admin account being driven by an adversary (credential theft, stolen ssh key) yields the same auid+ses shape as a legitimate admin edit. Source-IP match to the jump-host range is the discriminator here; without it, do not grade as admin-interactive even if uid is in sudoers.
- lp2: a "non-admin uid" reading is only decisive after checking whether the uid belongs to a documented automation/service identity (certbot, packer, cloud-init, an MDM agent). Skipping the service-identity check risks misclassifying a sanctioned non-admin automation write as adversarial. Cross-check against the h-001 automated-writer refutation — that lead covered apt/dpkg and Ansible/Puppet/Chef controllers, not all service identities on the host.
- lp3: a service account with `sudo` or `NOPASSWD` configured to edit sshd drop-ins may appear as automation *and* as root-equivalent auid — confirm the auid/euid transition matches the account's documented sudo rule, not just the uid.
- lp4: auditd silence during the exact mtime_after second is itself suspicious on this host class (target-endpoint is documented to run auditd with syscheck/auditd correlation enabled — rule 591 pairing). Distinguish "auditd ran but no rule matched the path" (missing audit rule, remediate) from "auditd was stopped or rules were flushed" (active evasion indicator, T1562.006); the second reading strongly elevates h-003 even without positive attribution.
