# `connect` — the configure path

Read this when `tenant.py catalog` lists the system: the product already carries its adapter.
Nothing is generated. `SKILL.md` is the entrypoint and owns the common steps (the check, the
knowledge, validation, the handoff); this file is only how you configure the adapter for one
tenant.

## Settings — `config.env`

`catalog` lists every key the adapter reads, prefixed (`JIRA_SERVICE_DESK`, `SERVICENOW_TABLE`,
...). Write exactly those, one `KEY="value"` per line, each value the
maintainer confirmed. The store refuses a missing key, an extra one, a blank or `CHANGE-ME`
value, and an `export` line. If a key's meaning isn't clear from its name, read the adapter's
module docstring (`defender/integrations/{system}_adapter.py`) — do not guess a value.

## Access — `access.yaml`

The same declaration as a generated adapter's (`adapter.md` → "Access declaration"): `access:
http-proxy`, the system's `base` URL, its `auth` (scheme and the field the scheme reads, never a
value), its routes, and `ca` when the system's certificate comes from a private CA (PEM
certificates, inline; then the only trust for this system). If the export has a sibling, copy
its shape and change the base, scheme and routes.

- **Reads.** The proxy admits every `GET` and `HEAD` under the base, so a read that uses either
  needs no route. List a read route only for a read sent with another method (a search sent as
  `POST`, for example). Nothing prints a catalog adapter's reads yet: find them in its module
  (`defender/integrations/{system}_adapter.py`, the method and path of each `transport.request`
  call), or copy them from another tenant's record of the same system.
- **Writes.** Only the routes the adapter writes to. For a case system that is its comment
  route, which depends on the settings: run the validator with `--case` (`SKILL.md` step 6) and
  copy the route it prints — `the comment the host sends: <METHOD> <path>` — into `writes`.
  Never write the route from memory.

## Credential

The adapter's module docstring and its health check say what access the credential needs (for
example, a read-only user plus the privilege its health check calls). Say it to the maintainer.
The operator writes the credential file; you tell them its shape. It is one JSON object,
`{"kind": ..., "fields": {...}}`: `kind` is `static`, or `oauth-client-credentials` for an OAuth
client. A `basic` scheme reads the fields `username` and `password`; a `bearer` or `header`
scheme reads the one field `access.yaml` names (`adapter.md` → "Credentials"). For Jira Cloud,
`basic` is the account's email as `username` and an API token as `password`. Say which fields;
never ask for, or accept, a value.

## A case system — the run-end comment

A case system is the ticketing system an investigation started with `--update-ticket` comments
on when it ends: its findings, as one comment on the ticket the alert names. Today only operator
runs comment; alerts that arrive through the API never do.

**The case record — `case-record.yaml`.** Which system takes the comment and the comment's body
template:

```yaml
system: jira
comment:
  body: |
    Disposition: {disposition}
    {cause}

    {narrative}
```

The body is the tenant's: there is no product default, so agree it with the maintainer. It may
use `{case_id}`, `{signature}`, `{summary}`, `{disposition}`, `{cause}`, `{narrative}` and
`{event_time}`; anything else is refused. The host opens every comment with its own tag line
naming the run, so the body need not.

**The ticket key.** The alert must carry the key of the ticket the run comments on, and the
tenant's alert mapping must point `case_key` at that field (a dotted path into the alert). Ask the
maintainer which field. If the stored mapping already maps `case_key` to it, there is nothing to
change. Otherwise give the operator the one line to change: `set-alert-mapping` replaces the
whole mapping, so they edit their last stored copy, never write a mapping from scratch.

- **ServiceNow addresses a record only by its `sys_id`** (a 32-character hex id), never by its
  number (`INC0012345`): the adapter does not look a number up. The alert automation must put
  the `sys_id` in the field. If the maintainer shows a sample alert whose field holds a number,
  stop and say so — the comment would fail on every run.
- **Jira** takes the issue key (`ABC-123`).

**The check.** A write: one comment on a ticket the maintainer names as disposable, and the
control is that ticket's comments not carrying it before the check runs (`SKILL.md` step 3).
