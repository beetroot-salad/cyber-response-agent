---
name: defender-dense-language
description: Block surface for authoring investigation.md as dense invlang. Tags, row shapes, and a worked snippet for the defender's loop.
---

The defender authors `investigation.md` as dense invlang — fenced
`​```invlang` blocks with tagged rows. The grammar is shared with
production (`docs/dense-investigation-format.md` is the full spec; the
agent runtime reference is `soc-agent/knowledge/invlang/schema.md`).
The defender uses a stripped subset and is not gated by the production
validator.

Use markdown phase headers (`## ORIENT`, `## PLAN`, `## GATHER (loop N)`,
`## ANALYZE (loop N)`, `## REPORT`) to delimit phases. The invlang
blocks live underneath them.

## Block tags

- **`:V`** — vertices (entities). Row shape:
  `[id|type|class|ident|attrs?]`
  Types are *participants in the investigation*: `endpoint`,
  `process`, `identity`, `session`, `file`, `command`, `socket`,
  `storage`, `database`, `container`, `network-device`. Note
  `endpoint` is unified — managed hosts and external IPs / FQDNs are
  all endpoints, discriminated by class (`endpoint:linux`,
  `endpoint:ipv4`, `endpoint:fqdn`, `endpoint:windows`). **Events are
  not vertices** — a failed auth or a process spawn is an `:E` edge,
  not a vertex with an `event` type. `class` is the subclass within a
  type. `ident` is a stable human-readable identifier (hostname, pid,
  username, IP literal). `attrs` is `key=value;...` for technical
  properties intrinsic to the entity (kernel version, process pid).

- **`:E`** — edges (events / relations between entities). Row shape:
  `[id|rel|src|tgt|when|auth_kind:source|attrs?]`
  `rel` describes something that happened between two entities
  (`spawned`, `authenticated_as`, `attempted_auth`, `connected_to`,
  `runs_on`). `src` and `tgt` are vertex ids. `when` is ISO timestamp.
  `auth_kind:source` is the observation authority — common kinds:
  `siem-event:wazuh`, `runtime-audit:falco`,
  `authoritative-source:directory`. The full enum (including
  `client-asserted` and `inferred-structural`, which cap supported
  resolutions at `+`/`-`) lives in the schema. The edge IS the event
  — repeat occurrences of the same edge collapse into one row with
  `count` and `window_*` in `attrs?`, not N rows.

- **`:H`** — hypotheses. Row shape:
  `[id|name|attached_to|preds|refuts?|weight|status]`
  `id` like `h-001`. `name` is a `?descriptive-slug` like
  `?monitoring-probe`. `attached_to` is the vertex id the hypothesis
  predicts an upstream cause for. `preds` is a comma-separated list
  of prediction ids defined inline. `weight` is one of `unweighted`,
  `weak`, `strong`. `status` is `live`, `shelved`, or `refuted`.
  *(Note: production's full `:H` row has additional structural cells
  — `rel`, `parent_type`, `parent_class`, `authz?`, `attr_preds?` —
  that the defender POC omits. See §Inconsistency vs production
  schema for what we lose by stripping them.)*

- **`:L`** — lead headers. Row shape:
  `[id|loop|name|goal|what_to_characterize]`
  One row per gather dispatch. `id` like `l-001`. The full lead
  description PLAN authored lives here.

- **`:R`** — resolutions. Used to grade predictions against gather
  observations. Row shape:
  `[pred_ref|verdict|matched_pred?|reasoning]`
  `verdict` is `++`, `+`, `-`, or `--`. `pred_ref` cites a
  `:H`-declared prediction id.

- **`:T`** — trace / terminal. Used at REPORT for the disposition.
  Row shape: `[disposition|matched_archetype?|reasoning]`.

## Minimal worked snippet

```invlang
:V prologue.vertices
v-001 | endpoint | endpoint:linux | bastion-01.corp |
v-002 | identity | identity:human | jsmith |
v-003 | endpoint | endpoint:ipv4  | 10.42.7.183 |

:E prologue.edges
e-001 | authenticated_as | v-002 | v-001 | 2026-05-05T03:47:12Z | siem-event:wazuh | src=v-003

:H hypothesize.hypotheses
h-001 | ?routine-admin-login    | v-001 | p-key-matches,p-source-known            | weak       | live
h-002 | ?pivoted-via-stolen-key | v-001 | p-source-novel,p-no-prior-bastion-auth  | unweighted | live
```

After a gather dispatch:

```invlang
:L findings
l-001 | 1 | auth-history-jsmith-bastion | "characterize jsmith's auth pattern on bastion-01 over last 30d" | "timing pattern, source diversity, success/failure ratio"

:R l-001.resolutions
p-source-novel          | -- | matched | "jsmith authed from 4 corp IPs over 90d; src 10.42.7.183 unseen but in-corp"
p-no-prior-bastion-auth | -- | matched | "142 prior logins this host, all from 10.42.5.0/24"
```

REPORT:

```invlang
:T conclude
benign | routine-admin-login | "jsmith key fingerprint matches 90d history; source IP corp-internal; concurrent ticket INC-8821 corroborates"
```

## Discipline

- Append-only. Don't edit prior blocks; if a hypothesis is refuted,
  add a `:R` row, don't rewrite the `:H`.
- Cite predictions by id in resolutions. Free-prose grading is harder
  to retrieve.
- Keep `attrs` tight — high-cardinality detail belongs in the gather
  raw payload, not the invlang row.
- The validator is off in this POC, but the surface is the same as
  production so the corpus tooling can index it later.
