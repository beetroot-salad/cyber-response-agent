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
- **Commitments:** `:H` is the current surface for topology commitments.
  `ac*` and `ip*` are edge-check commitments for authz and impact.
- **Procedure:** `:L` records what the defender chose to run and why.
- **Results:** `:R` records check results or learned facts; `:T resolutions`
  records belief movement; `:T conclude` records closure.

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
python3 -m defender.skills.invlang.cli "$DEFENDER_RUNS_BASE" enum                  # list slot names
python3 -m defender.skills.invlang.cli "$DEFENDER_RUNS_BASE" enum types            # vertex type names
python3 -m defender.skills.invlang.cli "$DEFENDER_RUNS_BASE" enum relations        # edge rel names
python3 -m defender.skills.invlang.cli "$DEFENDER_RUNS_BASE" enum compute.role     # compute role slot
python3 -m defender.skills.invlang.cli "$DEFENDER_RUNS_BASE" enum anchor-kinds     # authz anchor_kind
```

(`corpus_root` is positional and required by the parser, but `enum`
does not read the corpus — any path works.) Pick from these catalogs.
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
e-001|attempted_auth|v-003|v-001|2026-05-05T03:47:12Z|siem-event:wazuh|outcome=failed
```

State edges (`runs_on`, `member_of`, `authenticated_as`, `contained_in`)
have no meaningful `when` — leave it empty. Event interactions
(`read`, `wrote`, `created`, `deleted`, `attempted_auth`,
`assumed_role`, `granted_consent`) take a timestamp.

`auth_kind:source` is observational authority. Read it as
`obs_kind:source`. Only `siem-event`, `runtime-audit`, and
`authoritative-source` support `++`/`--` resolutions; `client-asserted`
and `inferred-structural` are weaker and do not.

`:H` topology commitments — thin header plus namespaced sub-blocks
(`{id}.preds`, `{id}.refuts`, `{id}.authz`):

```invlang
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?routine-admin-source|v-001|attempted_auth|compute|bastion/internal/known-corp||null|active
h-002|?novel-adversary-source|v-001|attempted_auth|compute|ip-only/internet/novel||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_parent|"source has prior successful bastion auth"
p2|proposed_edge|"auth timing matches prior admin pattern"

:H h-001.refuts [id|refutes|claim]
r1|p1|"source has no prior successful bastion auth"
```

Keep commitments lean: one proposed upstream vertex plus one edge.
1–2 predictions. `refutes` is a comma-separated list of prediction ids
the refutation would overturn.

Authz contracts live in `:H h-NNN.authz`:

```invlang
:H h-NNN.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|proposed|iam-policy|"service account allowed to read object at event time"|escalate|escalate
```

Authz checks ask whether an interaction edge is permitted; impact
checks whether the edge's effect crosses a threshold. Integrity is
source-side graph work — follow session/identity/process/compute
provenance rather than widening the authz predicate.

### Quoting cell values with `|`

Cell values that include a literal `|` must be double-quoted; the row
tokenizer doesn't split on `|` inside a quoted span:

```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-002|process|bash|bash[pid=42]|cmdline="bash -c whoami";flags="EXE_WRITABLE|EXE_LOWER_LAYER";user=root
```

For high-cardinality multi-value fields, push them to the raw gather
payload rather than packing into `attrs?`.

`:L` leads:

```invlang
:L findings [id|loop|name|target|mode?|tests|system|template|query|window]
l-001|1|auth-history-jsmith-bastion|v-001||h-001,h-002|wazuh|auth-history|user=jsmith host=bastion-01|90d
```

A lead is a procedure: what was run, against what target, for which
commitments. Route plans go in `:L l-001.lead_preds` — routing rules,
not world-state predictions.

Observations and learned facts:

```invlang
:E l-001.observations.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-002|attempted_auth|v-003|v-001|2026-05-01T10:11:00Z|siem-event:wazuh|outcome=success;user=jsmith;count=142

:R attr_updates [resolved_by|target|key|value]
l-001|v-003|class|bastion/internal/known-corp
```

Adding `:V`/`:E` changes the observed graph. `:R attr_updates` records
facts learned about existing graph objects — don't create vertices
just for facts.

Belief movement:

```invlang
:T resolutions
h-001  null → ++    [l-001 p1,p2 severe ⟂ e-002 :: prior successful bastion auth and timing match]
h-002  null → --    [l-001 r1 severe ⟂ e-002 :: normal source history refutes novelty]
```

`:T resolutions` says how a lead changed a commitment's weight. Cite
prediction/refutation IDs and supporting edges.

REPORT:

```invlang
:T conclude
termination.category   adversarial-refuted
disposition            benign
impact_verdict         none
confidence             high
matched_archetype      routine-admin-login
summary                "Login matched established bastion usage"

:T conclude.surviving [hyp_id|final_weight]
h-001|++
```

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
- **Keep high-cardinality details in raw gather payloads,** not in
  invlang cells.
