# Elasticsearch `{system}` — execution

Read this file when gather is dispatched against `system: {system}`. The verb roster and each verb's params come from
`list_verbs(system="{system}")`, filtered to your grant: a param it names binds, one it omits is refused. This file
carries what a signature cannot state.

## Calling

Reached with the `query` tool: no command, no shim, no `--help`. Params bind by name with literal JSON types
(`"limit": 20`, never `"20"`). Do not read the adapter's source to discover params.

- `limit` is clamped to 20 documents. Read the envelope's `total` for magnitudes; never pull and count.
- `sort` is `"desc"` (default, newest first) or `"asc"` (oldest first); anything else is refused. It decides which end
  of the window the 20-document cap keeps, so use `"asc"` whenever the question is what came first. It does not page:
  reach the middle by narrowing `start` and `end`, or aggregate with `esql`.
- `start` and `end` bound `@timestamp`, as ISO-8601 strings. Either may be omitted.
- `index` narrows within the configured patterns. Left unset, `query` reads the configured events pattern and `alerts`
  the configured alerts pattern; the envelope's `index` echoes which. An expression that reaches outside the configured
  patterns is refused, and the refusal names them.
- A concrete backing index name (the `.ds-` form an alert document may carry) is refused when no configured pattern
  covers it. Bind its data stream's pattern instead: the part between `.ds-` and the date and generation suffix, with a
  trailing `*`.

`query` and `alerts` return `{"index", "total", "returned", "sort", "truncated", "hits"}`. `hits` holds the `_source`
documents; `sort` echoes the order the cap was taken in, so a payload on disk says which end it holds. That payload is
the output; gather captures it under `gather_raw/`.

`esql` runs one ES|QL pipe server-side and returns `{"query", "columns", "row_count", "values"}`. `values` are bare row
arrays, cell `i` bound to `columns[i]`. The index (`FROM`), the window (an `@timestamp` comparison) and the
aggregation (`STATS`) all live in the pipe, which is why `esql` takes no `start`, `end`, `limit` or `index`.

- `FROM` must name a configured pattern: use the `index` an unscoped `query` or `alerts` envelope echoes. Any other
  source, a subquery, or a source the adapter cannot read is refused before it is sent.
- ES|QL returns at most 1000 grouping rows by default and drops the rest silently. Narrow the `BY` or add `LIMIT`.
- The pipe is one JSON string: `|` and newlines are safe, with no quoting rule to get wrong.

## Connectivity and credentials

The adapter resolves the connection and credentials itself. Never source secrets, export anything, manage a tunnel or
probe the connection.

## Exit codes

- `0` success. A connected, empty result is a finding, not an error.
- `1` the query was refused: the cluster rejected it (a malformed query string), or the adapter refused its target (an
  index outside the configured patterns). An index inside them that does not exist is not an error: it matches nothing.
- `2` no usable answer: the cluster could not be reached, or the system's settings are wrong (a refused read permission
  is one). A setup fault, not yours to fix; do not retry around it.
- `64` a usage mistake in your call: an unknown verb, or an unknown, missing or mistyped param. The rejection names the
  declared roster; re-issue with a declared param. It never counts toward the circuit breaker.

## Query syntax

`query` and `alerts` take a Lucene `query_string` (KQL covers the common case; the string is passed through
unmodified). Forms:

- Field exact: `process.name: "<name>"`.
- Disjunction: `host.name: ("<a>" OR "<b>")`.
- Boolean: `event.category: "authentication" AND event.outcome: "failure"`.
- Range: `http.response.status_code: [500 TO 599]`.
- Free text on `message`: `message: "<phrase>"`, a bare quoted phrase. It is an analyzed text field, so the phrase
  already matches that token sequence anywhere in the value, and punctuation in it does not narrow the match further.
- Exact value on a keyword field: quote it; an unquoted value containing `:` or `-` is parsed as syntax.

**Never wrap a phrase in `*`.** `message: *"<phrase>"*` reads as a substring match and is not one: the bare `*` is a
wildcard term matching every document that has the field, so the clause is a silent no-op, and in a disjunction it
matches all of them. If a query's `total` does not move when you add a `message` clause, this is why. In ES|QL the
wildcard form is correct (`message LIKE "*<phrase>*"`); the two languages differ here.

A field this system's data does not carry matches nothing, and says nothing: a confidently wrong empty result. When a
total is zero where some was expected, test the field with an exists clause (`field: *`) before trusting the zero.
