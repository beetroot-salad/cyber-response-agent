# Gather — suspect-result resolution

Read this when §3.5's gate flagged a result as **suspect** — its absence,
volume, or shape is off. Healthy results skip this file. The check is part
of measuring, so it runs **in your context, every time** a result is
suspect: validate first; investigate only if it's healthy-but-unresolved.

## Absence or sparse volume — is the (near-)nothing real?

Run a **positive control**: a query that *must* return rows if the adapter
is healthy — the system's inventory `list`, the entity named in the alert (a
just-fired alert guarantees its index holds events for it), or another
entity you know is active. Vary only the *query* — keep the
`defender-{system} …` shim form exactly; never the tooling.

- **Control also empty ⇒ the tool, not your query, is at fault.** Escalate as
  a tool fault, citing the control — an adapter that returns nothing for a
  guaranteed-populated probe is an outage, exactly like exit 2. Don't debug
  the harness.
- **Control returns rows ⇒ the adapter is healthy**, so the absence is
  genuine or query-shaped — one narrowing step decides which. Drop the
  most-specific clause (or, for a key lookup, broaden the key) and re-run. If
  the broader query returns what should have matched, a filter value is
  mis-shaped — wrong field, wrong literal type, NAT collapse, or a sibling
  field (`source.ip` vs `client.ip`, `host.name` vs `host.hostname`); report
  the differential. If the broader query is also empty, the absence is
  **genuine** — report "empty (verified: control populated, broader query
  also empty)" so the defender knows which kind of empty it is.

A **sparse** non-zero result runs the same control: if dropping a clause
restores the volume the lead implies, your filter was over-narrow; if it
doesn't, the low count is real — report it as measured. **Truncated** volume
is the exception, not this path (§3): the rows exist but the count is
limit-capped — widen `--limit` or report `payload_status: partial`, don't
hand-count the ceiling.

## Shape — sentinel, absent, or misplaced field

The check fires **per declared field**, not per dispatch (two suspect fields
→ two checks); only fields in `what_to_summarize` gate. §4 may not summarize
a field whose value is sentinel/absent until the check produces one, and you
may **not** inline a substitute you "know" without recording it — your local
fix isn't a system-level fix. Cheap step: read
`{defender_dir}/skills/{system}/SKILL.md` for a "Known data-source quirks"
entry matching the field + sentinel (apply the documented substitute if
found), and sample one raw event to see whether the value sits under a
**sibling/renamed field** or a drifted decoder version.

## Then investigate — only if healthy-but-unresolved

When the source is confirmed healthy but you can't resolve it cheaply (a
stubborn empty whose cause isn't an obvious clause, a mis-routed index /
wrong field vocabulary, or a sentinel with no documented quirk), hand off to
the **investigate** subagent. It runs in a fresh `claude -p` context, so the
open-ended diagnosis doesn't crowd yours, and returns a tight verdict:

```bash
defender-data-source-debug \
    --defender-dir {defender_dir} \
    --system {system} \
    --payload {run_dir}/{raw-payload-path} \
    --question "<NL question grounded in the payload>"
```

`{raw-payload-path}` is the path the capture wrapper reported on stderr
(`[record_query] raw payload: gather_raw/…`). Phrase `--question` as natural
language grounded in the payload — e.g. "`falco.output_fields.container.name`
returned `<NA>` for container id `45388dd0bf3a`; find a substitute field or a
cheap cross-source resolution." It returns `## Verdict`
(`data-source-quirk` | `parser-quirk` | `genuine-missing-data`),
`## Workaround` (substitute field / cross-source query / explanation), and
`## Deposited` (`_draft/` path + scope, or none). Apply the Workaround to
your §4 summary; carry any Deposited path to §6's `## Proposed`.

**The bound:** if a positive control plus one narrowing step can't settle
it, it's an investigate — hand off, don't iterate.

## §6 `## Proposed` block (when the investigate subagent deposited a draft)

```
## Proposed
- system: {system}
  draft: {defender_dir}/skills/{system}/_draft/{kebab-name}.md
  scope: system-wide                       # or: single-template:{template-id}
  summary: <one-line description of the quirk + workaround>
```
