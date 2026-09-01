---
name: defender-invlang
description: Compact guide for authoring defender investigation.md invlang blocks.
---

The defender writes `investigation.md` as fenced `​```invlang` blocks under
markdown phase headers (`## ORIENT`, `## PLAN`, `## GATHER (loop N)`,
`## ANALYZE (loop N)`, `## REPORT`).

## Mental model

invlang audits the investigation process, not just the final attack graph.

- **Observed graph:** `:V` vertices are real-world entities; `:E` edges
  are state relations or event interactions between them.
- **Commitments:** `:H` proposes a new parent vertex+edge for a
  *discovery* question (non-obvious upstream). Refinement of an
  existing vertex's class is `??` on the prologue entry, not a
  hypothesis row. `ac*` and `ip*` are edge-check commitments for
  authz and impact.
- **Procedure:** `:L` records what the defender chose to run and why.
- **Results:** `:R` records check results or learned facts; `:T resolutions`
  records belief movement; `:T close` marks one loop complete; `:T conclude`
  records final closure.

The schema is pragmatic — small closed catalogs at the level the alert
speaks at, free text at the level above. Pick the abstraction that
matches what your detector observes: describe a gas with bulk
thermodynamic variables when your instrument measures bulk; describe
trajectories when it tracks particles. Don't reach below the resolution
of your detector. If the SIEM records "lsass.exe memory read by
foo.exe", model the read at that granularity; don't invent a
memory-region vertex you didn't see. Mechanical observation goes in
`:V`/`:E` at the granularity the source provides; the higher-level
effect (e.g. credential theft) lives in `?hypothesis-name`.

## Closed vocabularies — look up at author time

Several fields draw from closed catalogs (vertex `type`, edge `rel`,
authz `anchor_kind`, edge `auth_kind`, per-type `class` and
`attrs.kind` enums). They are not preloaded into this skill — look
them up when you need a value:

```bash
defender-invlang enum                  # list slot names
defender-invlang enum types            # vertex type names
defender-invlang enum relations        # edge rel names
defender-invlang enum compute.role     # compute role slot
defender-invlang enum anchor-kinds     # authz anchor_kind
```

(The `defender-invlang` shim injects the corpus root, so you never pass a
path; `enum` doesn't read the corpus anyway.) Pick from these catalogs.
If your case genuinely doesn't fit, use `unclassified-{type}` in
`class` (type known, sub-kind unknown) or `ambiguous-{a}-or-{b}`
(genuinely indistinguishable).

## Classification grammar

The `class` cell is structured by `type`. For entities in the topology
of trust, it is a packed slash-separated tuple. For artifacts, it is a
single sub-kind token (prefer the corresponding `attrs.kind` enum where
the type has one).

| Type | Grammar | Example |
|---|---|---|
| `compute` | `<role>/<zone>/<provenance>` | `bastion/internal/known-corp` |
| `identity` | `<kind>/<provenance>` | `service-account/known-corp` |
| `application` | `<vendor>/<trust>` | `salesforce/corp-tenant` |
| `session` | single token | `interactive` |
| `process` | image basename | `bash`, `lsass.exe` |
| all others | single sub-kind token | `secrets`, `oauth-token` |

Each slot enum is available via `enum {slot}` (e.g. `enum compute.role`,
`enum identity.kind`, `enum application.vendor`). `:H parent_class`
follows the same grammar as `:V class`, dispatched on `parent_type`, and
takes `??` in the slots the alert has not settled (`ip-only/??/??`).
`??` and `unclassified-{type}` are not interchangeable: only `??` reads
as open (§Open questions), so a slot a lead is meant to close is `??`,
while `unclassified-*` says the catalog has no fitting value.

When the observation is just an IP with no role/zone context, use
`role=ip-only`. Set `attrs.knowledge=partial`. Zone and provenance
still carry signal (where in the topology the IP appears; how known
it is).

### Process — baseline schema

`process` vertices have a locked baseline. Fill when known:

| Slot | Notes |
|---|---|
| `class` | Image basename, lowercase. Never anomaly flags. |
| `ident` | `<basename>[pid=N]` |
| `attrs.image` | Full executable path |
| `attrs.hash` | SHA256 of the image |
| `attrs.cmdline` | Full command line (quote if it contains `\|`) |
| `attrs.user` | Running user (or reference the identity via `authenticated_as` on the spawning session) |
| `attrs.integrity_level` | Windows-only: `low\|medium\|high\|system` |
| `attrs.signing` | e.g. `signed:microsoft`, `unsigned` |
| `attrs.anomaly` | Anomaly flags — go here, not in class |

Parent is recorded via the `spawned` edge from parent to child, not as
a process attribute.

Slots that aren't yet settled mark themselves as **open** with `??`,
or upgrade to **enumerated candidates** with `{a, b, c}`. See
§Open questions below.

## Open questions

When the alert leaves a vertex partially classified, mark the open
slots inline rather than guessing or authoring a hypothesis row whose
lead choice is mechanical.

- **`??`** — open class slot, IDENT, or attribute value. Marks "we
  don't know yet." Use it on the whole triple (`class=??/??/??` for a
  `compute` vertex), a single slot
  (`class=monitoring-agent/??/known-corp`), the `ident` cell
  (`v-003|compute|ip-only/??/??|??|` — "which host is this IP"), or an
  attribute value (`attrs.signing=??`). The `class` cell carries the
  slash-tuple only — no type prefix.

  Class and attribute slots also GATE DISPOSITION: an open one blocks
  `disposition: benign` (§`:T conclude`). An open `ident` does not — it is
  honest bookkeeping about an entity you have not named yet, and it is
  what lets a lesson about naming that entity reach you. Prefer it over
  a guessed identifier.
- **`{a, b, c}`** — enumerated candidate set. Optional upgrade from
  `??`. Primary form is full-triple enumeration
  (`class={monitoring-agent/internal/known-corp,
  ip-only/internet/novel}`) because per-slot enumeration on multiple
  axes produces Cartesian-product nonsense. Per-slot enumeration is
  fine when only one axis is open. It applies to the `ident` cell too
  (`ident={dev-ws-1, dev-ws-2}` — "one of these two hosts"), and reads
  as OPEN there exactly as `??` does: still a question, not a name.
- **Resolution.** A lead closes the slot by writing a `:R attr_updates`
  row with `key=class` (for class refinements), `key=ident` (to sharpen
  the vertex's identifier) or `key=attrs.<name>` (for attribute
  refinements) and the concrete value. Three-state progression:
  `??` → `{a, b, c}` → concrete value. The `:V` declaration itself is
  IMMUTABLE — a sharpened `ident` is a new `:R` row, never a rewrite of
  the row that declared the vertex.
- **One row per slot, per write.** The progression above runs ACROSS
  `append_block` calls: each step is its own write, sent when gather
  returns something the last step could not know. Two rows in ONE write
  giving the same `(target, key)` two DIFFERENT values are refused —
  nothing happened between them to justify the second, and only the last
  would be recorded, silently dropping a value you wrote. The write, not
  the block: a second `:R attr_updates` block inside the same fence is
  the same write and is read the same way. Repeating a row with the SAME
  value is harmless and passes.

**Worked example.** A rule-5710 failed-auth alert names a source IP
with no role/zone context. The defender doesn't yet know whether
v-001 is a monitoring agent, an unknown internet probe, or a
compromised pivot — but the discriminating lead is the same in every
case: ask CMDB whether the IP is documented, then check egress policy
and behavior. The lead is mechanical, so framing this as competing
hypotheses earns nothing. Mark the slot open and let the lead close it:

```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|??/??/??|10.42.7.183|knowledge=partial

:L findings [id|loop|name|target|tests|system|window]
l-001|1|cmdb-lookup|v-001||cmdb|n/a

:R attr_updates [resolved_by|target|key|value]
l-001|v-001|class|monitoring-agent/internal/known-corp
```

Reserve `:H` (see §Discovery hypotheses) for cases where the
how-to-answer is genuinely non-obvious — multiple competing upstreams
where the lead choice itself depends on which story you're testing.

**Disposition gate.** An unresolved slot on any vertex blocks
`disposition: benign` — `??` or a `{a, b, c}` candidate set, in any
slot of the class tuple or as an attribute value. Resolve via
`:R attr_updates` before concluding, or escalate. A companion carrying
NO vertices is blocked too, for the same reason rather than a different
one: with nothing declared there is no slot to resolve, and "every slot
is resolved" would otherwise be satisfied by never declaring one.

A `:H parent_class` slot is not a vertex cell and does not gate. The
proposed parent is a claim the run has not observed, and no
`:R attr_updates` row can target an `h-*` to close it — leaving it `??`
costs the close nothing.

## Core blocks

A header line ends at its column list. Anything after it — a `# loop 2`
comment, a `(loop 3)` note, a stray bracket — makes the line a non-header,
and the block it was meant to open is refused rather than read.

An id is written once per block: a second row repeating `v-001` keeps the
first and discards the later one, so it is refused. Adding to a committed
block means sending a SECOND block, where re-emitting a row is legal and
silent.

A header's `?` marks the columns a row may leave off the end
(`[id|type|class|ident|attrs?]` — four cells is a complete row). Every
other column has to be written, empty if it has no value: a row that
stops short of the last required column is denied, because the alternative
is padding it with empty strings and reading back a record the author
never wrote. Within a cell, a `"` may only wrap a whole value — the whole
cell, a whole `;`-subcell, or the whole right side of a `k=v`. A quote
that opens mid-token swallows the next `|`; write a literal one as `\"`.

`:V` vertices:

```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|bastion/internal/known-corp|bastion-01.corp|kind=physical;os=linux
v-002|identity|user/known-corp|jsmith|
v-003|compute|ip-only/internet/anonymous|10.42.7.183|kind=physical;knowledge=partial
```

`:E` edges:

```invlang
:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-003|v-001|2026-05-05T03:47:12Z|siem-event:siem|outcome=failed
```

State edges (`runs_on`, `member_of`, `authenticated_as`, `contained_in`)
have no meaningful `when` — leave it empty. Event interactions
(`read`, `wrote`, `created`, `deleted`, `attempted_auth`,
`assumed_role`, `granted_consent`) take a timestamp.

`auth_kind:source` is observational authority. Read it as
`obs_kind:source`. Only `siem-event`, `runtime-audit`, and
`authoritative-source` support `++`/`--` resolutions; `client-asserted`
and `inferred-structural` are weaker and do not.

### Quoting cell values with `|`

Cell values that include a literal `|` must be double-quoted; the row
tokenizer doesn't split on `|` inside a quoted span:

```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-002|process|bash|bash[pid=42]|cmdline="bash -c whoami";flags="EXE_WRITABLE|EXE_LOWER_LAYER";user=root
```

For high-cardinality multi-value fields, push them to the raw gather
payload rather than packing into `attrs?`.

### `:L` leads

```invlang
:L findings [id|loop|name|target|mode?|tests|system|window]
l-001|1|auth-history-jsmith-bastion|v-001||h-001,h-002|siem|90d
```

PLAN names the lead by measurement and the `system` it targets; gather
chooses the template and binds params, and writes both as a row in
`executed_queries.jsonl` (the queries table, FK `lead_id`). Do not include
`template` or `query` columns at PLAN time — they are gather's record, not
the defender's. invlang has no comment syntax: a `#` line inside a block is
read as a row and refused against the header.

A lead is a procedure: what was run, against what target, for which
commitments. Route plans go in `:L l-001.lead_preds` — routing rules,
not world-state predictions:

```invlang
:L l-001.lead_preds [id|if|read_as|advance_to]
lp1|"access matches the identity's prior 72h cadence within 1σ"|"periodic tooling"|CONCLUDE
lp2|"burst concentrated in the last 10 min"|"anomalous spike"|HYPOTHESIZE
```

Route ids are `lp<n>`, and all four cells are required: the condition,
what reading it licenses, and where that reading goes. `advance_to` is
`CONCLUDE`, `HYPOTHESIZE`, or another lead's **`name`** — its `name`
cell, never its `l-*` id.

### `:R` observations and learned facts

```invlang
:E l-001.observations.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-002|attempted_auth|v-003|v-001|2026-05-01T10:11:00Z|siem-event:siem|outcome=success;user=jsmith;count=142

:R attr_updates [resolved_by|target|key|value]
l-001|v-003|class|bastion/internal/known-corp
```

Adding `:V`/`:E` changes the observed graph. `:R attr_updates` records
facts learned about existing graph objects — don't create vertices
just for facts. The mirror rule holds too: a lead that declares a
vertex says what it did or what was done to it, so write the `:E`
row in the same block. A fact about an entity that already exists is
an attribute or an `:R attr_updates` row, not a new vertex — a
vertex declared with no edge naming it anywhere in the document is
refused on write. This is also the surface for closing `??` slots
(`key=class` for class refinements; `key=ident` to sharpen the
identifier; `key=attrs.<name>` for attribute refinements) — see
§Open questions. Those three are the ONLY legal keys; any other key
is flagged, and the flagged row blocks the next write until you repair
it with `fix_row`. The `target` must name a vertex some `:V` block
declares, and the `value` cell must carry what the lead obtained: an empty
one is refused, because a blank does not leave the slot open — it closes it
over nothing. If the lead did not settle the slot, leave the `??` standing
and escalate.

### `:R authz` (authz contract resolution)

```invlang
:R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]
l-002|e-001|ac1|unauthorized|approved-source-list|"172.22.0.10 absent from CMDB; documented hosts are 172.22.0.13, 172.22.0.20, 172.22.0.5"
l-001|e-001|ac2|unauthorized|iam-policy|"nagios active:false; never provisioned in this environment"
```

When a lead resolves an authz contract declared under `:H h-NNN.authz`,
write the outcome as a `:R authz` row — **not** as `:R attr_updates`
keyed on the contract id. Columns:

- `resolved_by` — the single lead that closed this contract out. Required on
  every row: there is no fallback to "the lead we were just talking about", so
  an empty cell drops the row. Never a list either — this is where the row is
  filed, so a comma files it under a lead that does not exist.
- `cites_leads?` — other leads whose results the verdict rests on, comma-separated.
  Use this when no one lead answers the question alone — e.g. a CMDB lookup
  identifies the source host and a change-management lead finds no authorizing
  window, and only together do they refute the contract. Attribute the row to
  the lead that closed it; cite the rest here.
- `edge` — the edge the contract attaches to (must match the declaring `ac<n>` row's `edge_ref`).
- `fulfills` — the `ac<n>` contract id from `:H h-NNN.authz` being closed.
  The row names no hypothesis, so `ac<n>` numbers across the DOCUMENT, not
  per hypothesis the way `p<n>`/`r<n>` do — declaring `ac1` on two hypotheses
  that are both still live is denied on write, since one row would discharge
  both.
- `verdict` — `authorized | unauthorized | indeterminate`.
- `anchor_kind` — closed vocab (`enum anchor-kinds`); must match the declaring contract's `anchor_kind`.
- `grounding?` — what KIND of thing the verdict rests on: `org-authority`
  (an affirmative record in a system of record — an IAM policy, an
  approved change, a tacit-knowledge registry entry), a more specific
  label for the same (`iam-policy-binding`), or `past-case`.
  `telemetry-baseline` is **refused here**: a statistical pattern is what
  the estate *has been* doing, never what it is *permitted* to do. Record
  that as a `:R consultations` row instead (below). The refusal reads the
  cell case- and separator-folded, so `telemetry_baseline` is refused too.
- `anchor_id?` — the specific record the verdict cites (a CR id, a policy
  name, a registry entry id). **Required on a `verdict: authorized` row
  whose `anchor_kind` is `tacit-knowledge`**: the citation is the receipt,
  so leaving the column out is the receipt skipped, not a receipt paid. An
  `indeterminate` row owes none — a lookup that came back empty has no
  entry to name.
- `basis?` — on `verdict: indeterminate` only: `retry` (the default, and
  what an absent cell means — this contract has not been worked yet) or
  `exhausted` (every anchor kind applicable to this contract's predicate
  was actually queried this run and none answered). `exhausted` stops the
  run being pushed back to re-work the contract and changes nothing else —
  the verdict and its forced escalation stand. It is checked against this
  run's own transcript: the lead named by `resolved_by` must have come back
  with something, and its `:L findings` `system` cell must name the system
  that answers the contract's anchor kind. Write `retry` (or nothing) when
  there is still somewhere to look.
- `reasoning` — short citation of the supporting fact (quoted).

Disposition gating: `disposition: benign` requires every authz
contract on a surviving hypothesis to have a fulfilling `:R authz`
row with `verdict: authorized`. `unauthorized` or `indeterminate`
forces escalation per the contract's `on_unauth` / `on_indet`. A
declared contract with no fulfilling row is treated as
`indeterminate`.

**`anchor_kind: tacit-knowledge` costs two rows, not one.** The registry
is a human-authored file, so a citation has to be backed by a lookup you
actually ran: record what `tacit-knowledge.lookup` came back with as a
`:R consultations` row on the SAME lead first, then cite that entry's id
as the `:R authz` row's `anchor_id`. A citation no lookup produced —
including one another lead found, and one written beside a recorded miss
— is refused on write. Declare the two optional columns you need:

```invlang
:R consultations [resolved_by|anchor_kind|grounding|anchor_id|result|effective_window|reasoning]
l-001|tacit-knowledge|org-authority|tk-ca-bundle-build-runner|"hit: entry covers uid-0 on build-runner-*.prod"|2026-03-01T00:00:00Z/2026-09-01T00:00:00Z|"one unexpired scope-matching entry"

:R authz [resolved_by|edge|fulfills|verdict|anchor_kind|grounding|anchor_id|reasoning]
l-001|e-001|ac1|authorized|tacit-knowledge|org-authority|tk-ca-bundle-build-runner|"registry entry covers uid-0 on build-runner hosts"
```

The lookup came back empty? Then there is no second row to write:
record the `miss:` and resolve the contract `indeterminate` with no
`anchor_id`, adding `basis: exhausted` only if every registry that could
answer this predicate was actually queried this run.

### `:R consultations` (what an anchor SAID, without deciding anything)

```invlang
:R consultations [resolved_by|anchor_kind|grounding|anchor_id|result|effective_window|reasoning]
l-001|tacit-knowledge|org-authority|tk-ca-bundle-build-runner|"hit: entry covers uid-0 on build-runner-*.prod"|2026-03-01T00:00:00Z/2026-09-01T00:00:00Z|"one unexpired scope-matching entry"
l-001|runtime-evidence|telemetry-baseline|tk-baseline-30d|"1500 occurrences over 30d; actor uid-0 and host build-runner-07.prod throughout"|2026-04-04T00:00:00Z/2026-05-04T00:00:00Z|"nothing adverse fell inside the window"
```

A consultation records **what an anchor answered**, not what the run
concluded from it. The row carries no `fulfills` column and cannot
discharge a contract — that is the point, not an omission.

- `anchor_kind` — closed vocab (`enum anchor-kinds`).
- `grounding` — `enum consultation.grounding`: `org-authority` or
  `telemetry-baseline`. (`past-case` is excluded: grounding a baseline on
  a past case is reasoning from resemblance.)
- `result` — what came back, quoted. On an `anchor_kind: tacit-knowledge`
  row it **opens with `hit:` or `miss:`** (`enum
  consultation.lookup_outcome`) and the rest is yours: a lookup came back
  with an entry or it did not, and the authorization citing this row is
  checked against which. A MISS names no `anchor_id` — there is no entry
  to name, and an id written beside one is refused.
- `effective_window` — `<start>/<end>`, ISO-8601 instants. Required on a
  `runtime-evidence` baseline (see below); on a registry receipt it is the
  ENTRY's validity span.

Two uses, and they are different:

- **A registry receipt.** The lead that dispatched a lookup records what
  it got, which is what an `anchor_kind: tacit-knowledge` `:R authz` row's
  `anchor_id` is checked against. The window here is the ENTRY's validity
  span.
- **A baseline** (`anchor_kind: runtime-evidence`, `grounding:
  telemetry-baseline`). How often this estate does the alerted thing, over
  what window, with what scope, and whether anything adverse fell inside
  it. This is descriptive context for whoever reads the closed case — it
  rides into `report.md`'s body — and it buys the close **nothing**: the
  benign gate never reads it. Its window must end **strictly before** the
  alerted event; a pattern that begins with the incident is the incident.
  That comparison needs the alerted moment, so a document with no
  parseable `when` on any `:E prologue.edges` row cannot carry a baseline
  at all. Because `result` and `reasoning` are published verbatim, they
  may not contain `</report>`, and the accumulated baselines are bounded —
  state the recurrence and its scope, not every occurrence.
  Do not write one as probative when the live hypothesis's own predictions
  turn on novelty or rarity — the same evidence cannot both test for an
  anomaly and rule it out.

### `:R impact` (the impact axis)

*Does this edge's effect matter enough to escalate?* — a third axis,
orthogonal to authorization. Register the predicate at PLAN, grade it at
ANALYZE:

```invlang
:L l-002.impact_preds [id|dim|claim|on_match|on_mismatch|on_indeterminate|escalation_on]
ip1|confidentiality|"session_total_bytes within the 30d baseline ± 2σ"|within|exceeds|indeterminate|exceeds

:R impact [resolved_by|pred_ref|dim|observed|verdict|grounding|anchor_id|anchor_kind|authority|as_of|reasoning]
l-002|ip1|confidentiality|"180GB (3σ above the 60GB μ)"|exceeds|telemetry-baseline|backup-30d-baseline|approved-source-list|partial|2026-04-23T14:32Z|"observed 3σ; threshold 2σ"
```

On the `impact_preds` row every cell is required: register the threshold
AND every outcome before the measurement lands, because a blank
`on_mismatch` lets you decide what exceeding meant after seeing the
answer. On the `:R impact` row, `pred_ref`, `dim`, `verdict`,
`grounding`, `authority`, `as_of` and `reasoning` are required —
`observed` and the anchor columns are not checked here.

`pred_ref` is a bare `ip<n>` when the predicate belongs to
`resolved_by`'s own lead, or `l-NNN.ip<n>` across leads, and `dim` must
match the predicate's. Three closed catalogs — `enum impact.dimension`,
`enum impact.verdict`, `enum impact.grounding`. `past-case` is
deliberately absent from the last: impact is per-instance reasoning about
what THIS event did, and a past case only says what a category of event
was permitted to do. Every `ip<n>` you register must be graded or
deferred by CONCLUDE (below), so do not register one you have no lead
for.

### `:T resolutions` (belief movement)

```invlang
:T resolutions
h-001  null → ++    [l-001 p1,p2 severe ⟂ e-002 :: prior successful bastion auth and timing match]
h-002  null → --    [l-001 r1 severe ⟂ e-002 :: normal source history refutes novelty]
```

`:T resolutions` says how a lead changed a commitment's weight. Cite
prediction/refutation IDs and supporting edges. Head shape is
`[<lead> <ids> <severity> ⟂ <edges> :: <annotation>]`; `<severity>` ∈
{`severe`, `moderate`, `weak`} is positional-last and required — leave
it out and the parser reads your ids as the severity.

`++` says every prediction the hypothesis declared came in, so the head
cites all of them, `p<n>` and `ap<n>` alike. A head naming a subset is
denied on write — grade `+` for partial coverage.

The claim is checked against the predictions declared **now**, so
declaring one more `p<n>`/`ap<n>` on a hypothesis that already carries a
committed `++` re-opens it. You cannot rewrite the committed row, and
citing the new prediction would assert an untested claim came in. The
repair is to **withdraw the coverage claim** by appending
`h-NNN  ++ → +   [<lead> <ids> <severity> ⟂ <edges>]` — the run is no
longer claiming full coverage, which is what declaring an untested
prediction means. Appending `+ → ++` later re-asserts it, and the head
must then cite every prediction. Whatever the grade ends at, every
declared prediction is still owed a citation or a
`:T conclude.deferred_preds` row at CONCLUDE.

### `:T conclude` (REPORT)

```invlang
:T conclude
termination.category   adversarial-refuted
disposition            benign
impact_verdict         none
confidence             high
matched_archetype      routine-admin-login
summary                "Login matched established bastion usage"
```

- `disposition` — closed vocab (`enum disposition`), and the SAME keywords
  `report.md`'s frontmatter carries — FIVE of them, `unresolved` the fifth.
  A value outside the enum is denied on write; there is no `escalate`
  keyword — an escalation is `termination.category exhaustion-escalation`
  with `disposition inconclusive`. `unresolved` is a member of the enum
  because it must be free to name in prose, but it is the HOST's own
  verdict — recorded when a run is cut short without a settled finding —
  and `conclude.disposition unresolved` is denied on write just like a
  garbage value; you never conclude it yourself. THREE keywords carry an
  ENTRY PRICE. `benign` needs at least one `:V prologue.vertices` row — a
  log that never recorded the alerted entity accounts for nothing — plus
  every `??` slot resolved (§Open questions) and every authz contract on a
  live hypothesis `authorized` (§`:R authz`); `false-positive` — the one
  keyword that describes the RULE rather than the alerted entity, for a
  rule that fired on a different kind of behavior than it claims — needs
  `detection_notes` and `entity_check` below; `inconclusive` needs at
  least one `ceiling_test` RECEIPT (below) — a pointer the host verifies
  against this run's own transcript, never a sentence it judges. Rows
  must be distinct. All three prices are charged twice: on the write,
  against the keyword you conclude under, and again by
  `close_investigation`, against the keyword you close under. So
  concluding under a cheaper keyword buys nothing — the log itself still
  has to have paid for the keyword the close commits.
- `ceiling_test` — the checks you could NOT make, as a RECEIPT the host
  verifies mechanically. One row per gap, repeated, shaped
  `state=<state> [ref=<lead-id>|cap=<system[.verb]>] note=<text>` —
  `note=` is always LAST and runs to the end of the line, so it needs no
  quoting or escaping.

  Three states. `state=query-failed` and `state=query-empty` need
  `ref=<lead-id>` naming a `:L findings` row THIS RUN dispatched that
  came back with nothing: `query-failed` when that lead recorded a
  `fail_reason`, `query-empty` when it did not. A `ref` that names no
  lead, or a lead that actually returned a result (an observation, a
  resolution), or the WRONG state for what that lead's own row says
  happened, is refused — the receipt has to match the transcript, not
  read good:

      ceiling_test  state=query-failed ref=l-006 note=Zeek query blocked by a permission gate; no outbound flow data retrieved

  `state=nothing-to-try` is the one lane with no call to point at — a
  capability that does not exist in this deployment at all, so nothing
  was dispatchable. It takes `cap=<system>` or `cap=<system.verb>`
  instead of `ref=`, checked against the same closed roster your `query`
  calls dispatch through (`skills/gather/verb-roster.md`); naming a
  capability the deployment DOES provide is refused — that names a call
  you should have made, or a lead you should point at instead:

      ceiling_test  state=nothing-to-try cap=sandbox.detonate note=confirming ?post-install-implant would require sandbox detonation, and neither is in the runtime tool surface

  `note` is free text FOR THE ANALYST reading the report — explain the
  gap in your own words. It gates NOTHING (only `state`/`ref`/`cap` are
  checked) and rides into the report BODY, not the frontmatter, so a long
  note never risks the close. Two rows claiming the SAME `(state, ref)`
  or `(state, cap)` do not pay for two gaps. Omit the row (or write
  `none`) when nothing was out of reach. `ceiling_rationale` is the
  companion scalar: why concluding anyway is sound despite those gaps.
  The severity-ceiling rule (`termination.category severity-ceiling`)
  reads this same table and wants any row present — write a receipt
  there too.
- `impact_verdict` / `impact_severity` — the roll-up over this run's
  `:R impact` rows (`enum conclude.impact_verdict`), and how large the
  consequence is (`enum conclude.impact_severity`). The pair is checked for
  CONSISTENCY on write: a verdict that CLAIMS a consequence requires a
  severity — the verdict says a threshold was crossed, the severity says how
  far — while the two that claim none (`within`, and the conclude-only
  `none` a run that registered no `ip<n>` rolls up to) forbid one, so write
  `impact_severity null` beside them or leave the row out. Look the members
  up; they are not restated here.
- `detection_notes` — **optional** except under `disposition
  false-positive`, which requires it; and only for a detection defect ORIENT
  actually found:
  `detection_notes  "Claims a same-user pattern but groups by host, so the actor is untested."`
  It is not part of `summary`: the disposition describes the world, this
  describes the rule, and one run can find both. A rule that caught what it
  claims gets no row — a reassuring note reads the same as a defect nobody
  looked for.
- `entity_check` — required by `disposition false-positive`, unused
  otherwise: the `:L findings` lead that tested the ALERTED entity for
  suspicion independent of the alert's claim.
  `entity_check  l-004`
  The lead must have RETURNED a result — not merely be declared, and not a
  row whose only outcome is a `fail_reason` — and must target an entity the
  prologue already carried. A committed lead against something the refutation
  introduced — the source that was failing, the host behind it — does not
  answer whether the alerted host was clean, which is the only question this
  disposition leaves open.

Every row is ONE line. A value that opens a quote and does not close it on
the same row is denied on write, because the lines below it record nothing —
write long values as one long line, as `summary` already does.

**Every commitment is accounted for at CONCLUDE.** A `:T conclude` block is
denied on write while any of these is declared and neither settled nor
deferred:

| declared | settled by | deferred in |
|---|---|---|
| `ac<n>` on `:H h-NNN.authz` | a `:R authz` row whose `fulfills` names it | `:T conclude.deferred_authz [contract_ref\|rationale]` |
| `p<n>`/`ap<n>` on a hypothesis that is not `--` | a `:T resolutions` head that cites it and moves the hypothesis | `:T conclude.deferred_preds [prediction_ref\|rationale]` |
| `ip<n>` on `:L l-NNN.impact_preds` | a `:R impact` row whose `pred_ref` names it | `:T conclude.deferred_impact [prediction_ref\|rationale]` |

```invlang
:T conclude.deferred_authz [contract_ref|rationale]
h-003.ac2|"authority anchor unavailable — CMDB read denied by the environment permission gate"

:T conclude.deferred_preds [prediction_ref|rationale]
none
```

Name the commitment in FULL where you can — `h-003.ac2`, `h-001.p2`,
`l-002.ip1`. The bare `ac2` / `p2` / `ip1` is accepted too, and defers
every owner's commitment of that number; the qualified form is what makes
a deferral specific to one hypothesis or lead. (`:R authz`'s `fulfills`
column is the other way round — it names the bare `ac<n>`.)

The rationale is the point, and a blank one is denied: deferring says WHY the
question could not be answered ("authority anchor unavailable", "superseded by
mechanism refutation at l-007", "escalation forced before the measurement
landed"), not merely that it was not. Write `none` as the single row when
nothing was deferred.

Send the deferral tables FIRST, each in its own `append_block`, and
`:T conclude` last. The whole document is validated on every write, so a
`:T conclude` that lands before them is refused for commitments you were about
to account for — while a `deferred_*` table on its own is not yet a close and
lands clean.

Deferring is not a discharge in the other direction: `disposition benign`
still needs its authz contracts ANSWERED, not accounted for.

### `:T close` (loop boundary)

When you loop back from ANALYZE to PLAN, close the loop you are leaving:

```invlang
:T close
loop  1
```

It means "loop 1 is done — every lead I will gather/analyze in it is
committed above; I am moving to the next loop." One scalar `loop N` row,
nothing else: the invlang above is already the loop's record, so the marker
carries no summary or disposition. Write one `:T close` per loop, in the same
`append_block` call that lands the loop's final `:R`/`:T resolutions`. The
marker is what the runtime folds a completed loop on (see
`runtime/compaction.fold_boundary`); it is rejected if loop N has no committed
finding yet (you cannot close a loop you have only *planned*), so only close a
loop you have actually worked.
The **last** loop goes to REPORT, not back to PLAN — it gets `:T conclude`,
never `:T close`.

## Discovery hypotheses

`:H` proposes a new parent vertex plus an edge anchoring it to an
existing `v-*` vertex. Use it when the alert points at an interaction
whose upstream cause is genuinely non-obvious — competing candidate
upstream stories that imply *different next leads*. (For "what kind of
entity is v-N?" with a mechanical discriminator, use `??` notation on
the prologue entry — see §Open questions.)

The `attached_to` cell is the **anchor**: the `v-*` vertex the
proposed parent attaches to. Edge ids (`e-*`) are rejected at parse
time. For an interaction alert (`attempted_auth`, `queried_dns`,
`read`, …) the natural anchor is *the source vertex of the
interaction* — the entity the proposed upstream parent operates on or
through. Read it as: "what's upstream of v-N?", not "what produced
edge e-N?".

**Worked example: process-discovery behind a DNS interaction.** A DNS
alert names host `app-server-01` (v-001) querying a domain
(v-002). The alert lights up a single edge — but the discovery
question isn't about the edge, it's about *what process on v-001
issued the query*. The answer space forks meaningfully:

- **Tracking-SDK story.** An analytics SDK uses DNS for telemetry.
  Implies leads: package manifest scan, SDK signature lookup.
- **Beacon-implant story.** A DGA implant beacons via DNS A-records.
  Implies leads: full process tree + signature checking, sandbox
  detonation, egress audit.

Different stories, different leads — genuine `:H` territory. Anchor
on **v-001 (the host the process runs on)**, propose competing
`process` parents via `runs_on`:

```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|server/internal/known-corp|app-server-01|os=linux
v-002|socket|dns-name|beacon.example.com|protocol=dns;queried_subdomain=2obsn5wmcw6lyp

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|connected_to|v-001|v-002|2026-04-18T08:04:42Z|siem-event:siem|subdomain=2obsn5wmcw6lyp;query_type=A

:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?tracking-sdk-process|v-001|runs_on|process|??||null|active
h-002|?adversary-implant|v-001|runs_on|process|??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_parent|"subdomain is a stable device fingerprint, reused across all queries to this domain"
p2|proposed_parent|"queries are paced to an SDK heartbeat (session start / N-minute interval)"

:H h-002.preds [id|subject|claim]
p1|proposed_parent|"subdomain rotates per query — DGA pattern, not a stable identifier"
p2|proposed_parent|"queries cluster in rapid-fire bursts (multiple distinct subdomains within seconds) — the beacon-loop signature"
```

Both rows anchor on `v-001` (a vertex), not `e-001` (the edge). The
discovery question is "what process upstream of v-001" — the host
is where the upstream process lives. `parent_class` is `??` because
the basename isn't known yet and a lead is what names it; the
hypotheses fork on the *named story* (the `?name`) and its
predictions, not on `parent_class`.

Keep commitments lean: one proposed upstream vertex plus one edge.
1–2 predictions per hypothesis. `refutes` is a comma-separated list of
prediction ids the refutation would overturn.

A prediction about one ATTRIBUTE of one of the hypothesis's objects goes
in `:H h-NNN.attr_preds` instead — same commitment, said as a value
rather than a sentence:

```invlang
:H h-002.attr_preds [id|target|attribute|claim]
ap1|proposed_parent|signing|"UNSIGNED"
```

`target` names which of the hypothesis's own objects carries the
attribute, never a `v-*`/`e-*` id (`defender-invlang enum
attr-pred.target`). Ids are `ap<n>` here and `p<n>` in `.preds`, and an
`ap<n>` counts toward every rule a `p<n>` does — a resolution head cites
it, a `refutes` list names it, and CONCLUDE requires it settled or
deferred. So a `++` on `h-002` cites all three:

```invlang
:T resolutions
h-002  null → ++    [l-002 p1,p2,ap1 severe ⟂ e-001 :: rotating subdomains, rapid-fire bursts, unsigned binary]
```

### Forking a hypothesis mid-run

Append-only forbids rewriting the loop-1 block, so a hypothesis a
later loop raises is declared by a **new** block — under the lead
whose results raised it:

```invlang
:H l-002.new_hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-010|?stager-dropped-payload|v-001|runs_on|process|??||null|active

:H h-010.preds [id|subject|claim]
p1|proposed_parent|"the writing process is short-lived and not a package manager"
```

Columns are the `:H hypothesize.hypotheses` ones, and a second
`:H hypothesize.hypotheses` block is the spelling for a fork no single
lead raised. Both accumulate — earlier loops' hypotheses stay live and
keep their predictions. Declare an id at exactly one of the two sites;
a `:T resolutions` row naming an `h-*` neither declares is denied on
write.

### Authz contracts

Authz contracts live in `:H h-NNN.authz`:

```invlang
:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|proposed|iam-policy|"service account allowed to read object at event time"|escalate|escalate
```

`ac<n>` numbers across the DOCUMENT, not per hypothesis the way
`p<n>`/`r<n>` do: the resolving `:R authz` row names only the contract
it fulfills, so a second LIVE hypothesis numbering its first contract
`ac1` is denied on write. Refuting one of the two lifts that denial —
append-only leaves no other repair — but it does not make the id
unambiguous: a `:R authz` row for a shared id discharges only the
contract whose `anchor_kind` it matches, and if both declarers ask under
the same anchor kind it discharges neither, and `disposition: benign`
stays blocked.

Authz checks ask whether an interaction edge is permitted; impact
checks whether the edge's effect crosses a threshold. Integrity is
source-side graph work — follow session/identity/process/compute
provenance rather than widening the authz predicate.

## Sibling-fork uniqueness

Sibling hypotheses must differ on at least one **predicted observable**
— the claim a lead splits them on. Topology may differ too, but it is
not what makes the fork legal: a class tuple minted to carry a
difference the predictions already carry is what makes it illegal.
Leave the slots the alert has not settled `??` and let the predictions
fork, the way §Discovery hypotheses forks two parents that share one
`parent_class`; "what kind of entity is this?" is a refinement the same
lead answers under either story (§Open questions). Write the
discriminating claim on its own: packed in with where the parent sits
("external source, failing at high rate"), it is half-matched by a
lookup that says nothing about rate.

**Legitimacy is not a competing cause.** When two candidates share
topology but differ only on "was this action authorized?", collapse
them into ONE hypothesis with an `:H h-NNN.authz` contract carrying
the legitimacy question. Forks enumerate competing upstream **causes**,
not competing interpretations of the same cause.

Integrity is the one reading that IS a competing cause. "Was the
claimed actor the actor?" is not answered by any authority, so it
forks: a `?adversary-controlled-<entity>` peer beside the routine
hypothesis, sharing its authz contract and differing on the
predictions that test the premise. Collapsing that peer is what
`integrity_waived` exists to make you say out loud.

**Wrong:**

```invlang
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?legitimate-admin-gpo-edit|v-003|modified|identity|service-account/known-corp||null|active
h-002|?adversary-credential-abuse|v-003|modified|identity|service-account/known-corp||null|active
```

Both rows propose the same cause. Only intent varies — pointless
enumeration.

**Right:**

```invlang
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?gpo-edit-via-it-admin-svc|v-003|modified|identity|service-account/known-corp||null|active
h-002|?adversary-controlled-it-admin-svc|v-003|modified|identity|service-account/known-corp||null|active

:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-002|iam-policy|"IT-admin-svc permitted to modify Default Domain Policy at this time"|escalate|escalate
ac2|e-002|change-mgmt|"approved change ticket exists for this GPO edit at this time"|escalate|escalate

:H h-002.preds [id|subject|claim]
p1|proposed_parent|"the edit runs from a host, and at an hour, this account has no baseline for"
```

One hypothesis names the observed topology and two authz contracts
encode the legitimacy question. The peer carries the premise no
authority answers, on predictions rather than a contract — the two
share every topological column and the contract, and fork on the
observable. Resolution drives disposition.

## Authoring discipline

- **Append only.** Add rows; never rewrite prior graph or commitment rows.
- **Type-then-class.** Pick the vertex `type` first (via `enum types`),
  then fill `class` per the grammar that type follows.
- **Cloud API calls are edges, not vertices.** `session → created →
  app-object`. Parameters live in edge `attrs`.
- **DNS / TLS / HTTP are sockets** with `attrs.protocol` set. Queried
  name, certificate fingerprint, URL go in `attrs`.
- **Credentials are entities distinct from identities.** Stealing a
  token does not steal the identity; the credential is a separate
  `:V` with its own lineage (`issued`, `read`).
- **Configuration is an entity when modified; a mediator when invoked.**
  A GPO edited at T is a `:V configuration` with a `modified` edge.
  A GPO that silently authorized a logon is `:R authz.anchor_kind=gpo`.
- **App-objects need their application.** Materialize the `application`
  vertex and the `contained_in` edge whenever modeling SaaS-internal
  entities.
- **OAuth clients are two vertices** — the `application` (registered
  system) and an `identity` with `class=application-principal/<provenance>`
  (the principal that acts). Consent flows target the application
  (`identity → granted_consent → application`); auth and action flow
  through the principal. Link with `application → issued →
  application-principal-identity`.
- **Aggregate observations stay in edge attrs.** N occurrences →
  `attrs.count`, `attrs.distinct_sources`, `attrs.bytes` on a single
  edge. Don't materialize per-occurrence or "aggregate" pseudo-vertices.
- **System-fired inferences are `:R` rows, not edges.** A platform's
  own policy decision ("DLP flagged", "anomaly score crossed
  threshold") is an assertion the platform made, not a
  graph-extending interaction. Record under `:R attr_updates` or a
  lead's `:R` resolutions.
- **Authz outcomes are `:R authz` rows, not `:R attr_updates`.**
  Closing a contract declared under `:H h-NNN.authz` writes one
  `:R authz` row per contract — never `:R attr_updates` keyed on
  `h-NNN.ac<n>`. The contract's `fulfills` column ties the resolution
  back to the declaration; disposition gating walks that join.
- **Keep high-cardinality details in raw gather payloads,** not in
  invlang cells.
