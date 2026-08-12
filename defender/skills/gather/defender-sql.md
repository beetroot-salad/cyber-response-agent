---
name: defender-gather-sql
description: The defender-sql quirks that cost a query — how the payload becomes the table `data`, the binding each payload shape needs, and the results that lie (a TEXT-typed number, a count over a truncated payload). Read before writing SQL over a payload; assumes you know SQL.
---

You know SQL. What follows is only what this tool does differently, and the places
a query that looks right returns something wrong.

## The payload becomes the table

It parses to one table named `data` — no wrapper envelope to reach through. A
top-level object yields ONE row whose columns are its keys; a top-level array
yields one row per element. External access is disabled, so nothing here reaches a
file or the network.

`DESCRIBE data` names the columns, and for a nested column it prints the field
names AND types inside it — one call, before you guess at a shape. On a query error
the tool prints the columns plus the idiom for that shape.

**Its exit codes are its own, not the `query` tool's:** `1` = query error, fix the
SQL; `2` = the payload never arrived or is not JSON. A `2` here is *not* the
data-source outage `failure-modes.md` sends you to escalate.

## The binding each shape needs

**Nested records under one key** — `{index, total, returned, truncated, hits}`.
`unnest(hits)` yields a STRUCT, and only the subquery form binds it:

```sql
SELECT h.<field> FROM (SELECT unnest(hits) h FROM data) WHERE h.<other> = '<value>'
```

- **The lateral form does not do what it looks like.** In
  `FROM data, unnest(hits) AS h`, `h` names the TABLE, whose single column is
  called `unnest` — so `h.<field>` does not resolve and duckdb answers
  `Candidate bindings: : "unnest"`.
- `@`-prefixed and dotted field names need double quotes (`h."@timestamp"`).

**Positional rows behind a column header** — `{columns, values, row_count}`.
`unnest(values)` yields a POSITIONAL JSON array, NOT a struct, so `v.<field>`
fails. `SELECT columns FROM data` names the positions; index 1-based and unwrap:

```sql
SELECT v[2]->>'$' FROM (SELECT unnest(values) v FROM data)
```

`->>'$'` returns **TEXT**. Cast before comparing or summing a number
(`(v[3]->>'$')::BIGINT`), or the comparison is lexical and the sum fails.

**Flat** — the payload's keys ARE `data`'s columns; no `unnest`.

## Results that lie

- **A count over a truncated payload.** When `truncated` is set the rows are only
  the first `returned` of `total`, so a `0` means "not in the first rows", NOT
  "absent" — it cannot support an absence refutation. The tool says so on stderr.
- **A count over one payload when the lead named several.** Cover every seq, not
  just `0`.

When a system's own row shape has a recipe recorded, it is in the execution
surface your dispatch prompt names — read that rather than re-deriving it here.
Only some systems have a sibling `execution.md`; for the rest that surface is
`SKILL.md`'s `## Execution` section.
