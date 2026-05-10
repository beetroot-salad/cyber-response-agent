---
name: defender-dense-language
description: Compact guide for authoring defender investigation.md dense invlang blocks.
---

The defender writes `investigation.md` as fenced `​```invlang` blocks under
markdown phase headers (`## ORIENT`, `## PLAN`, `## GATHER (loop N)`,
`## ANALYZE (loop N)`, `## REPORT`).

## Mental model

invlang audits the investigation process, not just the final attack graph.

- **Observed graph:** `:V` vertices are real-world entities; `:E` edges are
  state relations or event interactions between them.
- **Commitments:** `:H` is the current surface for topology commitments
  (future/conceptual `:C kind=topology`). `ac*` and `ip*` are edge-check
  commitments for authz and impact.
- **Procedure:** `:L` records what the defender chose to run and why.
- **Results:** `:R` records check results or learned facts; `:T resolutions`
  records belief movement; `:T conclude` records closure.

## Core blocks

`:V` vertices:

```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|endpoint|endpoint:linux|bastion-01.corp|
v-002|identity|identity:human|jsmith|kind=user
v-003|endpoint|endpoint:ipv4|10.42.7.183|
```

Use vertices for entities: endpoint, process, identity, session, file,
command, socket, storage, database, container, network-device. Keep
`attrs?` to seed or identity-defining properties.

`:E` edges:

```invlang
:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-003|v-001|2026-05-05T03:47:12Z|siem-event:wazuh|outcome=failed
```

Edges include both persistent state (`runs_on`, `member_of`,
`authenticated_as`) and event interactions (`read`, `wrote`, `attempted_auth`,
`modified`). A failed attempt is still an edge; put outcome/count/window detail
in `attrs?`. `auth_kind:source` is observational authority; read it as
`obs_kind:source`.

`:H` topology commitments:

```invlang
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|preds|attr_preds?|refuts?|authz?|integrity_waived?|weight|status]
h-001|?routine-admin-source|v-001|attempted_auth|endpoint|known-corp-source||p1:proposed_parent:"source has prior successful bastion auth";p2:proposed_edge:"auth timing matches prior admin pattern"||r1[p1]:"source has no prior successful bastion auth"|||null|active
h-002|?novel-adversary-source|v-001|attempted_auth|endpoint|novel-external-source||p1:proposed_parent:"source is absent from prior auth history";p2:proposed_edge:"auth timing deviates from admin baseline"||r1[p1,p2]:"source and timing match normal admin history"|||null|active
```

Keep commitments lean: one proposed upstream vertex plus one edge. Use 1-2
predictions. Use `r*` refutations to name what would overturn predictions.

Authz and impact are edge checks:

```invlang
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|parent_attrs?|preds|attr_preds?|refuts?|authz?|integrity_waived?|weight|status]
h-003|?approved-service-read|v-010|read|identity|service-account|kind=service-account|p1:proposed_parent:"service account is configured reader"||r1[p1]:"account absent from reader policy"|ac1:proposed:iam-policy:"service account allowed to read object at event time":escalate/escalate||null|active
```

Authorization checks ask whether an interaction edge is permitted. Impact checks
ask whether the edge's effect crosses a threshold. Integrity is source-side
graph work: follow session, identity, process, endpoint, and provenance rather
than widening the authz predicate.

`:L` leads:

```invlang
:L findings [id|loop|name|target|mode?|tests|system|template|query|window]
l-001|1|auth-history-jsmith-bastion|v-001||h-001,h-002|wazuh|auth-history|user=jsmith host=bastion-01|90d
```

A lead is a procedure: what was run, against what target, for which
commitments. Put route plans in `:L l-001.lead_preds`; those are routing rules,
not world-state predictions.

Topology observations and learned facts:

```invlang
:E l-001.observations.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-002|attempted_auth|v-003|v-001|2026-05-01T10:11:00Z|siem-event:wazuh|outcome=success;user=jsmith;count=142

:R attr_updates [resolved_by|target|key|value]
l-001|v-003|classification|known-corp-source
```

Adding `:V` / `:E` changes the observed graph. `:R attr_updates` records facts
learned about existing graph objects; do not create vertices just for facts.

Belief movement:

```invlang
:T resolutions
h-001  null → ++    [l-001 p1,p2 severe ⟂ e-002 :: prior successful bastion auth and timing match both predictions]
h-002  null → --    [l-001 r1 severe ⟂ e-002 :: normal source history refutes adversary-source novelty]
```

`:T resolutions` is not another observation. It says how a lead changed a
commitment's weight. Cite prediction/refutation IDs and supporting edges.

REPORT:

```invlang
:T conclude
termination.category   adversarial-refuted
termination.rationale  "Adversarial topology commitments refuted"
disposition            benign
impact_verdict         none
impact_severity        null
confidence             high
matched_archetype      routine-admin-login
ceiling_rationale      n/a
summary                "Login matched established bastion usage"

:T conclude.surviving [hyp_id|final_weight]
h-001|++
```

## Discipline

- Append only. Add rows; do not rewrite prior graph or commitment rows.
- Keep `:E` for relations/interactions and `:R attr_updates` for learned facts.
- Keep commitments lean and retrieve-friendly: short names, 1-2 predictions,
  explicit refutations.
- Use `:T resolutions` for belief changes; `:R` is for results/facts/checks.
- Keep high-cardinality details in raw gather payloads, not invlang cells.
