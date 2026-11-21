# ServiceNow

## Credential

A user (`basic` scheme: `username` and `password`) whose roles let it read the case table and write work notes on its records.

## Pitfalls

- A record is addressed only by its `sys_id`, a 32-character hex id, never by its number (`INC0012345`): the adapter does not look a number up. The alert automation must put the `sys_id` in the field the tenant's alert mapping points `case_key` at; if a sample alert holds a number there, every comment would fail.
