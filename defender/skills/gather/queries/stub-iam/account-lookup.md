---
id: stub-iam.account-lookup
status: established
---

## Goal

Look up an account in the IAM registry by name. Used to determine whether
an account is provisioned, its kind (service or human), active status,
which source/target hosts it is authorized to use, and owning team.

## What to characterize

- Whether the account is documented in IAM (present/absent)
- Kind (service account vs human-provisioned)
- Active status (active / inactive / missing)
- Owning team
- Allowed source hosts (which hosts the account may authenticate from)
- Allowed target hosts (which hosts the account may authenticate to)
- Purpose / use case

## Query

```bash
jq '.accounts[] | select(.name == "${name}")' /workspace/playground/iam/accounts.json
```

Bind `${name}` to the account name string. If not provided, refuse the dispatch.

## Filter binding

- `name` → account name string (e.g. `nagios`, `app-svc`, `jsmith`).

## Common pitfalls

- **Three account states, not two.** A name can be:
  - *Active and listed* — account is provisioned and authorized.
  - *Inactive and listed* — account is documented but explicitly not
    provisioned in this environment (e.g. deprecated service account).
    This is **stronger evidence than a lookup miss** — the name has been
    considered and rejected.
  - *Missing* — no entry in the registry (softer signal; may be a typo,
    recent onboarding not yet documented, or reconnaissance probe).
- **Account-level authorization only.** The registry does not distinguish
  "account exists and was used with the right key" from "account exists
  and someone is password-guessing it." Pair with `wazuh` auth-event
  success/failure ratios to discriminate.
- **Source/target hosts are at host granularity, not per-credential.**
  The registry lists which hosts the account may use; it does not track
  SSH key fingerprints, password rotation history, or per-session MFA
  status. Pair with `host-query` to confirm the account actually exists
  on a specific endpoint.
