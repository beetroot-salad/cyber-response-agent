# Query template catalog — file format

This directory is the gather subagent's accumulated memory of useful queries,
organized per system of record. A template captures what an experienced
analyst already knows about a data source: the right index, the right field
names, the joins or regex tricks that took someone an afternoon to figure
out the first time. Gather binds parameters and runs; it doesn't re-derive
the query under time pressure.

## Layout

```
queries/
  SCHEMA.md                    # this file
  {system}/                    # one dir per system of record
    {template-id}.md           # one file per template
```

`{system}` is a system the gather subagent knows how to dispatch against
(one dir per onboarded system of record). It doubles as the routing
prefix for the template id and as the optional `system` argument that
narrows a `template_search` to one system's dir.

The two must AGREE, and it is checked: a file's `id:` must begin
`{system}.` where `{system}` is the directory the file sits in. A template
filed under one system's dir while calling itself `{other}.x` routes its
row to the wrong system — `query_id` is `{system}.{kebab-name}` and every
consumer keys on that prefix — so the mismatch is a FAIL at
`validate_scaffold` and refuses the lead author's commit.

`{template-id}` is kebab-case. Name it for **what the query measures**
(`auth-events`), not the axis you happen to filter on (`auth-events-by-host`)
and not why the defender asked for it (`check-if-bastion-was-pivoted`). A
single template can carry several optional filter knobs.

## File format

```markdown
---
id: {system}.sshd-auth-history
status: established        # or `draft` while under curation
verb: esql                # the declared verb this template dispatches; its engine is a
                          # property of the VERB (esql / query / a param-only verb like get-host)
params: [index]           # the verb's declared params, each bound by a `${name}` placeholder
body_substitutions: [start, end, user, src, dst]  # in-body-text `${name}` substitutions —
                          # placeholders inside a query LANGUAGE body, NOT declared verb params
covers: [{system}.hunt-failed-logins]  # coined `query_id`s this template accounts for
                          # (see "Drafts and `covers:`" below)
---

## Goal

What this query measures, in one or two sentences, **plus an explicit note
that it is a wide/superset query you narrow** (see below). **Write for keyword
recall** — name the concrete artifacts a future analyst would type when
searching: daemon names (sshd, sudo), file paths (/etc/passwd), log fields
(`source.ip`, `user.name`), syscalls. This body IS the template's index entry on a dispatch to
its OWN system (a dispatch to any other system sees the id and the path alone, #835), and it is
what `template_search` matches against — so the recall keywords carry more, not less: off-system,
they are the only thing that makes this template findable at all, and a wide template's keywords
are what keep a future narrowing from re-coining a sibling.

## Query

The query the verb runs. For an **engine verb** (elastic `esql`, or `query`/`alerts`)
this is the native query LANGUAGE body, fenced in that language: an ES|QL pipe in
```` ```esql ````, or a Lucene/KQL string in an **untagged** ```` ``` ```` fence (KQL has
no canonical highlighter tag, so its fence carries no language). For a **param-only verb**
(every non-elastic system) the `## Query` is a structured, re-runnable call fenced
```` ```query ````:

```` ```query ````
verb: get-host
params:
  host: ${host}
```` ``` ````

Two kinds of `${name}` placeholder, and the frontmatter classifies each so
`validate_scaffold` can check them:

- a **declared param** (`params:`) — a `${name}` that binds a param the verb declares;
- a **body substitution** (`body_substitutions:`) — a `${name}` interpolated INTO a
  query-language body. The classification is per-VERB, not per-system: `${start}` is a
  *param* of elastic `query`/`alerts` but a *body substitution* inside an ES|QL pipe.

`verb:` and `params:` are **required of every template, drafts included** — the rule is
per-verb, so a file naming no verb is undecidable rather than exempt, and `params:` must name
only params the verb really declares (checked against the adapter's live signature, not against
this file's own claims). A draft auto-minted from an executed query arrives carrying both.
The rule lives in `defender/_scaffold_rules.py` and runs in three places: `validate_scaffold`
at scaffold time, the lead-author loop's commit gate on every promotion, and CI over the whole
corpus. One rule, three callers — not three copies (#901).

This is a **wide/superset** query — carry every filter axis (`user`, `src`,
`dst`, window) and a broad aggregation. **Gather narrows it to the lead**: drops
the predicates the lead doesn't constrain and the `BY` keys it doesn't ask for.
Fork to a new template only for a different *measurement*, never a different
parameter.

**Narrowing examples** — list 2-3 concrete narrowings (each the query above with
axes removed), so the next analyst sees the capability covers their case:

- *<one narrowing>*: keep <axes>, drop <axes>.

## Pitfalls

- <pitfall 1: e.g. a null-heavy field that needs an `IS NOT NULL` guard, a
  structured field an earlier query re-derived out of `message` when the
  integration had already parsed it, NAT collapse, window edge cases>
```

Older templates carried `## What to summarize` and `## Baseline (when
applicable)` sections; the ES|QL migration folded both into `## Query` (the
aggregation *is* the summary; a baseline is the same wide query over a second
window, a narrowing — not a separate section). New and promoted templates use
the shape above.

## Multi-query dispatches and `gather_raw/` naming

Gather runs each query through the typed `query` tool —
`query(system=…, verb=…, params={…}, query_id=…)` — and the runtime captures it
transparently (the capture capability in `runtime/query_tool.py`). There is no adapter
command, no shim, and no wrapper to invoke: bash cannot reach a data source at all.
Capture persists the raw payload by-ref to `{run_dir}/gather_raw/{lead_id}/{seq}.json`
and appends one row to `executed_queries.jsonl` (the queries table, FK `lead_id`);
gather neither redirects stdout nor names files. `seq` disambiguates
N-queries-per-lead — there is no flat `{position}.json` / `{position}{a..z}.json`
projection:

- `gather_raw/l-001/0.json` — first query for lead `l-001`
- `gather_raw/l-001/1.json`, `gather_raw/l-001/2.json` — further queries for `l-001`
- `gather_raw/l-002/0.json` — first query for lead `l-002`

## What is *not* a template

Templates measure **primitives** — a single dataset, a single filter shape,
one verb invocation. Cross-primitive correlations are not templates.

When a lead asks for "X correlated with Y at time T" (e.g. *who was logged
in when /etc/passwd changed?*), the right move is: run the two primitives
that already exist, summarize the join in the gather return. **Do not
mint a "bridge" template** — it bloats the catalog with one-offs that
won't be reused. A lead may run several queries — see
`defender/skills/gather/SKILL.md` §2 (FIND a template, or coin a query).

## Naming a new measurement

When the lead has no matching template, gather does **not** author a
template file — it coins a measurement id and runs under it (see
`defender/skills/gather/SKILL.md` §2). The offline lead-author mints a
draft from the execution record and curates it (see "Drafts and
`covers:`" below). To coin the id:

1. Pick a `{system}` based on which data source the query must hit.
2. Pick a kebab-case `{template-id}` describing what the query measures,
   not why the defender asked for it. Good: `auth-events`,
   `file-integrity-changes`. Bad: `check-bastion-pivot`,
   `auth-events-by-host` (the by-X axis is a parameter, not a separate
   template).

Bias toward coining a fresh id rather than wedging a near-match —
duplicates are cheaper to normalize later than mis-keyed cross-case joins
are to recover. But first check whether an existing template already
carries the **capability** you need with a different parameter binding
(the template body, not the filename, is what determines fit).

This file documents the template *shape* the lead-author produces when
it promotes a coined measurement; gather only supplies the id.

## Drafts and `covers:`

A **minted draft** under `{system}/_draft/` is not a small template — it is a **recording**. The
lead-author loop mints one when a gather call coined a `query_id` no template answered, and
what it writes is a transcript of that one execution. (A hand-authored draft predates the shape
and carries none of it — no digest name, no `covers:`, and a `## Query` rather than a
recording; it is freely discardable, and the checker accepts both.)

- Its **name is a digest**, not a name. `{system}/_draft/{sha256(query_id)[:12]}.md`, and `id:`
  matches. Naming a template for *what it measures* is a decision that needs the recording, the
  neighbor scores and the catalog in hand — none of which the gather subagent had when it
  coined the id mid-investigation. **Naming it is the promoter's job.**
- Its query sits under **`## Executed query`**, not `## Query`. A `## Query` is an interface:
  its `${name}`s are holes a dispatch fills, which is why they are checked against the verb's
  params. A recording has no holes — every `${…}` in it is text that was literally sent. So a
  draft declares no `body_substitutions:`, and the placeholder rule does not apply to it.
- Its **`covers:`** lists every `query_id` it answers — the coined one the row carried **and
  its own derived `id:`**. The second is not redundant: `template_search` publishes `_draft/`
  hits and tells gather to bind the hit's `id` as `query_id`, so rows really are recorded under
  the digest. Copying the whole list onto the promoted file is what keeps both resolving once
  the `id:` is replaced by the name you chose.

`covers:` is what survives the draft. It is the dedup key (`synthesize_drafts` will re-mint an
identity that no template covers), it is how the commit gate matches a deleted draft to the
template that took it over, and it carries gather's own one-line description of the
measurement — the best single input to naming it.

So on **promote**, write the established file under a name that says what it measures and copy
the draft's `covers:` onto it. On **discard-into-widen**, add the entry to the template you
widen. A template may **gain** covered identities and may never lose them; the loop's commit
gate refuses both a dropped entry and a deleted draft whose identities land nowhere.
