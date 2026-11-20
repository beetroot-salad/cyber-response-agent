# `connect` — the configure path

Read this when `GET /adapters` lists the system: the product already carries its adapter.
Nothing is generated. `SKILL.md` is the entrypoint and owns the common steps (the check, the
knowledge, validation, the handoff); this file is only how you configure the adapter for one
tenant.

## The adapter's reference

Before anything else, read the reference beside the adapter (`defender/integrations/{system}_adapter.md`; the
same text is the `reference` field of `GET /adapters`). Its **Credential** section says what access the
credential needs and which scheme and fields it holds; its **Pitfalls** section lists the configuration
mistakes no check refuses. Say both to the maintainer, and act on a pitfall as it says.

## Settings — `config.env`

`GET /adapters` lists every key the adapter reads, prefixed (`JIRA_SERVICE_DESK`, `SERVICENOW_TABLE`,
...), with a sample value for each. Write exactly those, one `KEY="value"` per line, each value the
maintainer confirmed. The store refuses a missing key, an extra one, a blank or `CHANGE-ME`
value, and an `export` line. If a key's meaning isn't clear from its name, read the adapter's
module docstring (`defender/integrations/{system}_adapter.py`) — do not guess a value.

## Access — `access.yaml`

The same declaration as a generated adapter's (`adapter.md` → "Access declaration"): `access:
http-proxy`, the system's `base` URL, its `auth` (scheme and the field the scheme reads, never a
value), its routes, and `ca` when the system's certificate comes from a private CA (PEM
certificates, inline; then the only trust for this system). If `GET /systems` has a sibling, copy
its `access` and change the base, scheme and routes.

- **Reads.** The proxy admits every `GET` and `HEAD` under the base, so a read that uses either
  needs no route. List a read route only for a read sent with another method (a search sent as
  `POST`, for example), and list **exactly** the ones the adapter declares: the store refuses a record
  whose non-GET reads differ from its adapter's, naming each missing and each extra route. Run the
  validator with only the system (`python3 defender/skills/connect/validate_scaffold.py {system}`):
  it prints them, and `GET /adapters` carries the same list in the `reads` field. Never write them
  from memory.
- **Writes.** Only the routes the adapter writes to. For a case system that is its comment
  route, which depends on the settings: run the validator with `--case` (`SKILL.md` step 6) and
  copy the route it prints — `the comment the host sends: <METHOD> <path>` — into `writes`.
  Never write the route from memory.

## Credential

The reference's **Credential** section says what access the credential needs (the adapter's
module docstring and its health check say more). Say it to the maintainer.
The tenant admin stores the credential (`PUT /systems/{system}/credentials`); you tell them its
fields. It holds exactly the fields the record's auth scheme reads: a `basic` scheme reads
`username` and `password`; a `bearer` or `header` scheme reads the one field `access.yaml` names;
`oauth-client-credentials` reads `client_id` and `client_secret` (`adapter.md` → "Credentials").
A secret field holds at least 16 characters. Say which fields; never ask for, or accept, a value.

## A case system — the run-end comment

A case system is the ticketing system an investigation comments on when it ends, if its
start-investigation request set `update_ticket`: one comment on the ticket the alert names, naming
the disposition and linking the investigation's screen. The wording is fixed by the product, not
the tenant's; an operator's hand-run investigation never comments.

**The case record — `case-record.yaml`.** Which system takes the comment:

```yaml
system: jira
```

The host opens every comment with its own tag line naming the run.

**The ticket key.** The alert must carry the key of the ticket the run comments on, and the
tenant's alert mapping must point `case_key` at that field (a dotted path into the alert). Ask the
maintainer which field. If the stored mapping already maps `case_key` to it, there is nothing to
change. Otherwise give the tenant admin the one line to change: `PUT /alert-mapping` replaces the
whole mapping, so they edit the mapping `GET /alert-mapping` answers, never write one from scratch.

- The adapter's reference says which identifier the system wants in that field (ServiceNow's
  `sys_id`, Jira's issue key). If the maintainer shows a sample alert whose field holds a different
  one (for ServiceNow, a number such as `INC0012345`), stop and say so — the comment would fail on
  every run.

**The check.** A write: one comment on a ticket the maintainer names as disposable, and the
control is that ticket's comments not carrying it before the check runs (`SKILL.md` step 3).
