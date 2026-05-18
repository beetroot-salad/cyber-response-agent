# Stub IAM

Mock identity registry for the playground. Stand-in for what an
organization's IAM / directory / runbook collection holds about
service accounts: which accounts exist, who owns them, what hosts
they're allowed to authenticate from and to.

Structured index: `accounts.json`. Narrative notes per account below —
the kind of context an analyst would find in the team's runbook or
IAM-team wiki. CLI adapter: `defender/scripts/tools/stub_iam.py`.

An entry with `active: false` is **explicitly known and explicitly
not authorized** — distinct from a lookup miss (account name has
never been seen in this environment).

## nrpe-check (active, sre)

The only legitimate SSH-monitoring account in this environment. Used
by `monitoring-host` to run NRPE health probes against workload
hosts. Should never appear as a source account from any host other
than `monitoring-host`, and should never target hosts outside the
SRE-managed workload set.

## deploy-bot (active, platform)

CD pipeline SSH identity. Authenticates from CI runners
(`ci-runner-01`, `ci-runner-02`) to `target-endpoint` and the bastion
for application deploys. Bursts of authentication failures from this
account typically indicate a key rotation issue, not an attack —
correlate with the deploy pipeline state.

## legacy-monitoring-accounts (nagios, zabbix, healthcheck)

A cluster of monitoring-flavored account names that are **not
provisioned** in this environment. Historically the SRE team
evaluated nagios- and zabbix-based monitoring before standardizing on
the NRPE-over-SSH approach under `nrpe-check`; the names never moved
beyond evaluation. `healthcheck` was never a real account here either,
but is a common generic name in opportunistic SSH credential sweeps.

Authentication attempts using these names — at any volume, from any
source — should be treated as adversarial credential probing.
Cross-host attempts with this account set in rotation are a
particularly clean signal: a real legacy misconfiguration would pick
one of the three and stick with it, not enumerate.
