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
follows the same grammar as `:V class`, dispatched on `parent_type`.

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

- **`??`** — open class slot or attribute value. Marks "we don't know
  yet, and it gates disposition." Use it on the whole triple
  (`class=??/??/??` for a `compute` vertex), a single slot
  (`class=monitoring-agent/??/known-corp`), or an attribute value
  (`attrs.signing=??`). The `class` cell carries the slash-tuple
  only — no type prefix.
- **`{a, b, c}`** — enumerated candidate set. Optional upgrade from
  `??`. Primary form is full-triple enumeration
  (`class={monitoring-agent/internal/known-corp,
  ip-only/internet/novel}`) because per-slot enumeration on multiple
  axes produces Cartesian-product nonsense. Per-slot enumeration is
  fine when only one axis is open.
- **Resolution.** A lead closes the slot by writing a `:R attr_updates`
  row with `key=class` (for class refinements) or `key=attrs.<name>`
  (for attribute refinements) and the concrete value. Three-state
  progression: `??` → `{a, b, c}` → concrete value.

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

**Disposition gate.** An unresolved `??` on any vertex blocks
`disposition: benign`. Resolve via `:R attr_updates` before
concluding, or escalate.

## Core blocks

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

# PLAN names the lead by measurement and the `system` it targets; gather
# chooses the template and binds params, and writes both as a row in
# `executed_queries.jsonl` (the queries table, FK `lead_id`). Do not include
# `template` or `query` columns at PLAN time — they are gather's record,
# not the defender's.
```

A lead is a procedure: what was run, against what target, for which
commitments. Route plans go in `:L l-001.lead_preds` — routing rules,
not world-state predictions.

### `:R` observations and learned facts

```invlang
:E l-001.observations.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-002|attempted_auth|v-003|v-001|2026-05-01T10:11:00Z|siem-event:siem|outcome=success;user=jsmith;count=142

:R attr_updates [resolved_by|target|key|value]
l-001|v-003|class|bastion/internal/known-corp
```

Adding `:V`/`:E` changes the observed graph. `:R attr_updates` records
facts learned about existing graph objects — don't create vertices
just for facts. This is also the surface for closing `??` slots
(`key=class` for class refinements; `key=attrs.<name>` for attribute
refinements) — see §Open questions.

### `:R authz` (authz contract resolution)

```invlang
:R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]
l-002|e-001|ac1|unauthorized|approved-source-list|"172.22.0.10 absent from CMDB; documented hosts are 172.22.0.13, 172.22.0.20, 172.22.0.5"
l-001|e-001|ac2|unauthorized|iam-policy|"nagios active:false; never provisioned in this environment"
```

When a lead resolves an authz contract declared under `:H h-NNN.authz`,
write the outcome as a `:R authz` row — **not** as `:R attr_updates`
keyed on the contract id. Columns:

- `resolved_by` — lead id(s) that produced the outcome (comma-separated if more than one).
- `edge` — the edge the contract attaches to (must match the declaring `ac<n>` row's `edge_ref`).
- `fulfills` — the `ac<n>` contract id from `:H h-NNN.authz` being closed.
- `verdict` — `authorized | unauthorized | indeterminate`.
- `anchor_kind` — closed vocab (`enum anchor-kinds`); must match the declaring contract's `anchor_kind`.
- `reasoning` — short citation of the supporting fact (quoted).

Disposition gating: `disposition: benign` requires every authz
contract on a surviving hypothesis to have a fulfilling `:R authz`
row with `verdict: authorized`. `unauthorized` or `indeterminate`
forces escalation per the contract's `on_unauth` / `on_indet`. A
declared contract with no fulfilling row is treated as
`indeterminate`.

### `:T resolutions` (belief movement)

```invlang
:T resolutions
h-001  null → ++    [l-001 p1,p2 severe ⟂ e-002 :: prior successful bastion auth and timing match]
h-002  null → --    [l-001 r1 severe ⟂ e-002 :: normal source history refutes novelty]
```

`:T resolutions` says how a lead changed a commitment's weight. Cite
prediction/refutation IDs and supporting edges.

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
Edit that lands the loop's final `:R`/`:T resolutions`. The marker is what the
runtime folds a completed loop on (see `runtime/compaction.fold_boundary`); it
is rejected if loop N has no committed finding yet (you cannot close a
loop you have only *planned*), so only close a loop you have actually worked.
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
h-001|?tracking-sdk-process|v-001|runs_on|process|unclassified-process||null|active
h-002|?adversary-implant|v-001|runs_on|process|unclassified-process||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_parent|"subdomain is a stable device fingerprint, reused across all queries to this domain"
p2|proposed_parent|"queries are paced to an SDK heartbeat (session start / N-minute interval)"

:H h-002.preds [id|subject|claim]
p1|proposed_parent|"subdomain rotates per query — DGA pattern, not a stable identifier"
p2|proposed_parent|"queries cluster in rapid-fire bursts (multiple distinct subdomains within seconds) — the beacon-loop signature"
```

Both rows anchor on `v-001` (a vertex), not `e-001` (the edge). The
discovery question is "what process upstream of v-001" — the host
is where the upstream process lives. `parent_class` is
`unclassified-process` because the basename isn't known yet; the
hypotheses fork on the *named story* (the `?name`) and its
predictions, not on `parent_class`. (If predictions could be expressed
as `parent_class` alternatives that fit the closed catalog, prefer
that; otherwise carry the discriminator in the `?name` + predictions.)

Keep commitments lean: one proposed upstream vertex plus one edge.
1–2 predictions per hypothesis. `refutes` is a comma-separated list of
prediction ids the refutation would overturn.

### Authz contracts

Authz contracts live in `:H h-NNN.authz`:

```invlang
:H h-NNN.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|proposed|iam-policy|"service account allowed to read object at event time"|escalate|escalate
```

Authz checks ask whether an interaction edge is permitted; impact
checks whether the edge's effect crosses a threshold. Integrity is
source-side graph work — follow session/identity/process/compute
provenance rather than widening the authz predicate.

## Sibling-fork uniqueness

Sibling hypotheses must differ on at least one **topological** axis:
`parent_type`, `parent_class`, `attached_to`, or `rel`.

**Legitimacy is not a topological axis.** When two candidates share
topology but differ only on "was this action authorized?", collapse
them into ONE hypothesis with an `:H h-NNN.authz` contract carrying
the legitimacy question. Forks enumerate competing upstream **causes**,
not competing interpretations of the same cause.

**Wrong:**

```invlang
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?legitimate-admin-gpo-edit|v-003|modified|identity|service-account/known-corp||null|active
h-002|?adversary-credential-abuse|v-003|modified|identity|service-account/known-corp||null|active
```

Both rows share every topological column. Only intent varies —
pointless enumeration.

**Right:**

```invlang
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?gpo-edit-via-it-admin-svc|v-003|modified|identity|service-account/known-corp||null|active

:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-002|iam-policy|"IT-admin-svc permitted to modify Default Domain Policy at this time"|escalate|escalate
ac2|e-002|change-mgmt|"approved change ticket exists for this GPO edit at this time"|escalate|escalate
```

One hypothesis names the observed topology. Two authz contracts encode
the legitimacy question. Resolution drives disposition.

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
