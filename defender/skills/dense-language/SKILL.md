---
name: defender-dense-language
description: Block surface for authoring investigation.md as dense invlang. Tags, row shapes, and a worked snippet for the defender's loop.
---

The defender authors `investigation.md` as dense invlang — fenced
`​```invlang` blocks with tagged rows. The grammar is shared with
production (`docs/dense-investigation-format.md` is the full spec); the
defender uses a stripped subset and is not gated by the production
validator.

Use markdown phase headers (`## ORIENT`, `## PLAN`, `## GATHER (loop N)`,
`## ANALYZE (loop N)`, `## REPORT`) to delimit phases. The invlang
blocks live underneath them.

## Block tags

- **`:V`** — vertices (entities). Row shape:
  `[id|type|class|ident|attrs?]`
  Examples of `type`: `host`, `process`, `identity`, `session`,
  `network-endpoint`, `event`. `class` is the subclass within a type
  (e.g. `host:linux`, `identity:human`). `ident` is a stable identifier
  (hostname, pid, username). `attrs` is `key=value;...`.

- **`:E`** — edges (relations / events). Row shape:
  `[id|rel|src|tgt|when|auth_kind:source|attrs?]`
  `rel` is the relation (`logged-into`, `spawned`, `authenticated-as`).
  `src` and `tgt` are vertex ids. `when` is ISO timestamp. `auth_kind:source`
  is the observation authority (`siem-event:wazuh`,
  `runtime-audit:falco`, `authoritative-source:directory`).

- **`:H`** — hypotheses. Row shape:
  `[id|name|attached_to|preds|refuts?|weight|status]`
  `id` like `h-monitoring-probe`. `attached_to` is the vertex the
  hypothesis predicts an upstream cause for. `preds` is a list of
  prediction ids defined inline (or referenced from per-lead
  `lead_preds` blocks). `weight` is one of `unweighted`, `weak`,
  `strong`. `status` is `live`, `shelved`, or `refuted`.

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
v-host-1 | host | host:linux | bastion-01.corp | role=jump
v-user-1 | identity | identity:human | jsmith | groups=infra-admins

:E prologue.edges
e-001 | logged-into | v-user-1 | v-host-1 | 2026-05-05T03:47:12Z | siem-event:wazuh

:H hypothesize.hypotheses
h-routine-admin | routine-admin-login | v-host-1 | p-key-matches,p-source-known | weak | live
h-pivoted-key   | pivoted-via-stolen-key | v-host-1 | p-source-novel,p-no-prior-bastion-auth | unweighted | live
```

After a gather dispatch:

```invlang
:L findings
l-001 | 1 | auth-history-jsmith-bastion | "characterize jsmith's auth pattern on bastion-01 over last 30d" | "timing pattern, source diversity, success/failure ratio"

:R l-001.resolutions
p-source-novel | -- | matched | "jsmith authed from 4 corp IPs over 90d; src 10.42.7.183 unseen but in-corp"
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
