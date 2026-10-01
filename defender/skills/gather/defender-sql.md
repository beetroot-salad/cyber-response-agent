---
name: defender-gather-sql
description: The defender-sql quirks that cost a query — how the payload becomes the table `data`, the binding each payload shape needs, and the results that lie (a count over a truncated payload, a list compared as a value). Read before writing SQL over a payload; assumes you know SQL.
---

You know SQL. What follows is only what this tool does differently, and the places
a query that looks right returns something wrong.

## The payload becomes the table

It parses to one table named `data` — no wrapper envelope to reach through. A
top-level object yields ONE row whose columns are its keys; a top-level array
yields one row per element. Or, with `--rows`/`--names`, `data` is the declared
rows: one row per row, one column per name (below). External access is disabled,
so nothing here reaches a file or the network.

`DESCRIBE data` names the columns, and for a nested column it prints the field
names AND types inside it — one call, before you guess at a shape. On a query error
the tool prints the columns plus the idiom for that shape.

**Its exit codes are its own, not the `query` tool's:** `1` = query error, fix the
SQL — or a wrong `--rows`/`--names` declaration, fix that; `2` = the payload never
arrived or is not JSON. A `2` here is *not* the data-source outage
`failure-modes.md` sends you to escalate.

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

**Positional rows behind a list of column names** — ES|QL's `{columns, values}`,
or any payload whose rows are bare arrays. Undeclared, the whole payload is ONE row
(`count(*)` answers 1, and the tool says so on stderr). Declare where the rows and
the names are, and they become a table with those names:

```bash
cat <payload> | defender-sql --rows values --names columns '<SQL>'
```

`--rows` is the list of rows, `--names` a list of strings or of objects with a
`name`; a nested layout is a path (`--rows tables[0].rows --names tables[0].columns`).
A wrong declaration exits `1` and names the defect.

- **Double-quote a dotted or `@` name** (`"source.ip"`). Unquoted, `source.ip`
  fails; single-quoted, `'source.ip'` is a string constant and compares silently
  false.
- **Each column is typed from its own JSON values:** all numbers → a number, so
  compare and sum with no cast; all text → text, so a time stays the source's own
  string; all booleans → boolean.
- **A column that holds lists** (a multi-valued field) is a LIST: `=` on it fails.
  Filter with `list_contains("host.ip", '10.0.0.5')`; to count or group its
  elements, `unnest` it in a subquery first — `GROUP BY` on the column itself groups
  whole lists. The tool names every list column on stderr.
- **A column of mixed kinds or objects** is JSON, and the tool names it on stderr.
  `(col->>'$')` unpacks a cell to TEXT, so a number compares and sorts as text
  (`'9'` above `'412'`): cast before comparing, sorting or summing one,
  `TRY_CAST((col->>'$') AS DOUBLE)`.

```sql
SELECT "source.ip", failed FROM data WHERE "source.ip" = '203.0.113.7' AND failed > 9
```

**Parenthesise every `->>`** (a JSON column, or a JSON source). `->>`
binds more loosely than the operators written before it (`=`, `<>`, AND, OR, NOT,
`||` …) and takes that whole expression as its JSON: `'x' = col->>'$'` reads `('x' = col)` as
the JSON, and so does everything before a second `->>` after an AND. The answer is
an error or a silent, wrong count. The tool refuses those shapes; write
`(col->>'$') = 'x' AND (other->>'$') = 'y'`.

**Flat** — the payload's keys ARE `data`'s columns; no `unnest`.

## Results that lie

- **A count over a truncated payload.** When `truncated` is set the rows are only
  the first `returned` of `total`, so a `0` means "not in the first rows", NOT
  "absent" — it cannot support an absence refutation. The tool says so on stderr.
- **A count over one payload when the lead named several.** Cover every seq, not
  just `0`.
- **Two projected fields that share a leaf name.** ECS nests them, so an unaliased
  `h.host.name, h.agent.name` projects two columns both called `name`. The second
  and later ones come back as `name_1`, `name_2` and the tool says which on stderr —
  alias them (`AS host_name`, `AS agent_name`) to control the key yourself.

When a system's own row shape has a recipe recorded, it is in the
`execution.md` your dispatch prompt names — read that rather than re-deriving
it here.
