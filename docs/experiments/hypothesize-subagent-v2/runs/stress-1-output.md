```yaml
gather:
  - id: l-001
    loop: 1
    name: package-manager-log
    target: v-host-prod-api-02
    predictions:
      - {id: lp1, if: "a package-manager transaction log entry timestamped within ±60s of the alert names /etc/sudoers as a managed file", read_as: "sanctioned-bulk-writer; modified by package manager during install/upgrade", advance_to: config-mgmt-run-lookup (corroborate) or conclude-benign if package + CM align}
      - {id: lp2, if: "no package-manager transaction near the alert timestamp touches /etc/sudoers", read_as: "package manager not the writer; source remains unidentified", advance_to: config-mgmt-run-lookup}
  - id: l-002
    loop: 1
    name: config-mgmt-run-lookup
    target: v-host-prod-api-02
    predictions:
      - {id: lp1, if: "a CM agent run record (Ansible/Puppet/Chef) is logged within ±120s of the alert and the sudoers file is within the managed resource set for that run", read_as: "sanctioned-bulk-writer; CM agent wrote the file under an authorized change", advance_to: conclude-benign (if package-manager-log also negative or corroborating)}
      - {id: lp2, if: "no CM run record near the alert timestamp, or CM run exists but does not cover sudoers", read_as: "CM agent not the writer; source unidentified", advance_to: temporal-correlation (widen window) or escalate}
```

Note: HYPOTHESIZE is skipped. Rule-550 carries no process or user attribution — the alert fields are identical under every competing writer classification (package manager, CM agent, operator, adversary). No fork is observable from alert fields alone. The discrimination axis (who wrote the file) is fully gated behind external correlation leads; emit GATHER to resolve the writer classification before forming hypotheses.

Selected lead: `package-manager-log` (l-001) first — it is the most precise: a package-manager transaction log either names `/etc/sudoers` as a managed file at the alert timestamp or it does not. Single dispatch; result determines whether `config-mgmt-run-lookup` (l-002) is corroboration or the primary remaining check.

Pitfalls:
- (lead-level, not hypothesis-level — no hypotheses yet) A package-manager transaction timestamp that is close but not exact could reflect a post-install trigger rather than the direct write; confirm the transaction names `/etc/sudoers` explicitly, not just the package that owns it, before reading as sanctioned.
- A CM run that covers sudoers in its *configured* resource set but was not actually executed (dry-run, check-mode, or failed mid-run) does not confirm a sanctioned write; verify the run completed and applied changes.
