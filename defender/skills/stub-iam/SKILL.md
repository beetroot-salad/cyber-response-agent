---
name: defender-stub-iam
description: Stub IAM system reference — playground identity registry mapping account names to owner, status, and authorized source/target hosts. Use to ground legitimacy questions about whether an account that appears in auth events is provisioned and authorized for the observed path.
---

A static registry standing in for what an organization's IAM,
directory service, or service-account runbook holds. Answers "is
this account provisioned," "is it active," "is it allowed to
authenticate from host A to host B."

The file is split by audience. The **Visibility surface** section
informs PLAN routing and ANALYZE-time legitimacy grounding. The
**Execution** section is read by gather when it dispatches a query.

## Visibility surface

### What the registry holds

For each documented account:

- Account name
- Kind (`service`, `human`)
- Owning team
- Active flag
- Allowed source hosts (where the account may authenticate from)
- Allowed target hosts (which hosts the account may authenticate to)
- Purpose (one-line description)
- Reference to a longer narrative note in `README.md`

### Gaps

- **Three account states, not two.** A name can be
  *active-and-listed* (authorized), *inactive-and-listed* (known
  but disauthorized — typically a deprecated service account or a
  known bad-pattern name) or *missing* (never seen). The three carry
  different meanings; don't collapse `inactive` into "absent."
- **Account-level only — no credential or key fingerprint data.**
  The registry does not distinguish "the account exists and was used
  with the right key" from "the account exists and someone is
  guessing its password."
- **No time dimension.** Current-state only; no provisioning history,
  no last-rotation timestamp.
- **No host-level identity binding.** The IAM registry says which
  accounts *may* authenticate to which hosts; it does not say which
  accounts *are configured to exist* on each host. Pair with
  `host-query` for the latter on enrolled hosts.

### Read guidance

- An `active: false` entry is **stronger evidence than a lookup
  miss**: the name has been considered and explicitly not
  provisioned in this environment. Authentication attempts using
  such a name are by definition unauthorized regardless of source.
- A lookup miss is a softer signal — the name might be a typo, an
  account from a recently-onboarded team not yet documented, or a
  reconnaissance probe. Combine with source-host CMDB status to
  disambiguate.
- A documented `active` account authenticating from outside its
  `allowed_source_hosts` is a strong adversarial signal — the
  account exists, but its use here is policy-violating.
- The narrative `README.md` body explains the *intent* behind each
  account or account-group (why it exists, what bursts of failures
  typically mean). Read it directly when the structured fields
  don't carry enough context to disposition a hypothesis.

### When to use

- **Use stub-iam for**: grounding "is this account provisioned and
  authorized for this source-target pair," resolving accounts to
  owning teams for routing escalation.
- **Do not use stub-iam for**: per-host account existence on a
  specific endpoint (`host-query`), credential-level evidence
  (`wazuh`), network-layer authorization (`stub-cmdb`).

## Execution

The registry lives at `/workspace/playground/iam/`:

- `accounts.json` — structured index (one object per documented
  account)
- `README.md` — narrative notes per account or account group,
  grouped by `notes_ref`

Query directly with `jq` against the JSON, or `Read` the markdown
for narrative context. There is no adapter CLI.

```bash
# look up a single account (returns null if not documented)
jq '.accounts[] | select(.name == "nrpe-check")' /workspace/playground/iam/accounts.json

# look up several at once (e.g. accounts tried in an observed credential sweep)
jq '.accounts[] | select(.name == "nagios" or .name == "zabbix" or .name == "healthcheck")' \
  /workspace/playground/iam/accounts.json

# list active accounts authorized for a target host
jq '.accounts[] | select(.active == true and (.allowed_target_hosts // []) | index("target-endpoint"))' \
  /workspace/playground/iam/accounts.json
```

When grounding a legitimacy contract that references an account,
quote the dispositive fields (`active`, `allowed_source_hosts`)
directly in the gather summary. If the contract requires the
*reason* an account is disauthorized (e.g. to write a precise
report rationale), include the relevant narrative paragraph from
`README.md`.
