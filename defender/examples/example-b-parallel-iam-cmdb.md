---
name: example-b-parallel-iam-cmdb
description: Two parallel single-fact registry leads (CMDB + IAM) plus a Loop-2 host-state follow-up after IAM lookup misses. Demonstrates an unanswered authz contract forcing a structural loop-back — a lookup miss records no verdict, because `indeterminate` would end the benign path for good — and the "one-question = one-lead" rule against composite-lead temptation. Load when an alert involves a registry / identity question and you're tempted to bundle multiple registry checks into one composite lead.
---

# Example B — SSH login by a non-stereotyped account from a documented monitoring source

SSH auth-success on `app-host-12.prod` from `mon-poller-04.sre` using account `metrics-shipper`. The account isn't stereotyped in the SRE monitoring runbook — sanctioned rollout whose IAM update lagged, or unfamiliar process on the source?

```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|monitoring/internal/known-corp|mon-poller-04.sre|kind=vm;ip=10.20.5.41
v-002|compute|app-server/internal/known-corp|app-host-12.prod|kind=vm;ip=10.20.7.118
v-003|identity|service-account/known-corp|metrics-shipper|

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-001|v-002|2026-05-05T03:42:11Z|siem-event:siem|outcome=success;account=metrics-shipper;port=22

:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?packaged-monitoring-daemon|v-001|runs_on|process|??||null|active
h-002|?adversary-controlled-source-process|v-001|runs_on|process|??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_parent|"the SSH client is a distro-packaged unit started by systemd"
p2|proposed_parent|"the same package and version is installed fleet-wide on hosts carrying role=monitoring"

:H h-001.refuts [id|refutes|claim]
r1|p1|"the SSH client has no package or systemd ancestry"

:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-001|iam-policy|"metrics-shipper is provisioned and authorized for this source→target SSH path"|escalate|escalate

:H h-002.preds [id|subject|claim]
p1|proposed_parent|"the SSH client is spawned from an interactive session"
p2|proposed_parent|"the process is present on this host alone, not on its fleet peers"

:H h-002.refuts [id|refutes|claim]
r1|p1,p2|"the SSH client is systemd-spawned and matches its fleet peers"

:L findings [id|loop|name|target|tests|system|window]
l-001|1|cmdb-source-lookup|v-001|h-001,h-002|cmdb|n/a
l-002|1|iam-account-lookup|v-003|h-001|iam|n/a
```

PLAN dispatches `l-001` and `l-002` as **two parallel `Task` calls** —
independent single-fact registry questions, not a correlation across
raw data. Gather picks (or mints) the per-system template and records
the bound params as a row in `executed_queries.jsonl`, keyed by
`lead_id`.

GATHER returned:
- `l-001` (cmdb): `10.20.5.41` documented as `mon-poller-04.sre`,
  role `monitoring`, status `active`, `authorized_outbound:
  ["app-host-12.prod:22 (account=sre-healthcheck)"]`. Source is
  documented; the listed path constrains to `sre-healthcheck`, not
  `metrics-shipper`.
- `l-002` (iam): `metrics-shipper` not present in the IAM catalog — a
  lookup miss, distinct from an `active: false` "explicitly
  disauthorized" entry.

ANALYZE:

```invlang
:T resolutions
h-001  null → +    [l-001 mild ⟂ e-001 :: source documented as monitoring infra; neither p1 nor p2 is a question CMDB answers]
h-002  null → -    [l-001 mild ⟂ e-001 :: source is sanctioned monitoring infra, not raw adversary footprint — but documented hosts can still be compromised]

:T close
loop  1
```

`l-002` answered nothing, so it wrote no `:R authz` row and `ac1` stays
open — which blocks `disposition: benign` regardless of the behavioral
grading on `h-001`. The loop-back is structural: ask host-state the
question IAM couldn't answer — is `metrics-shipper` a packaged daemon
on the source?

Loop 2 PLAN:

```invlang
:L findings [id|loop|name|target|tests|system|window]
l-003|2|metrics-shipper-daemon-on-source|v-001|h-001,h-002|host-state|±14d
```

GATHER returned: `metrics-shipper.service` enabled and active since
`2026-04-29T11:02:14Z`; installed by `apt install
metrics-shipper-agent` triggered by the SRE config-management run;
the same package + version landed on every host carrying `role:
monitoring` in the same window.

```invlang
:R attr_updates [resolved_by|target|key|value]
l-003|v-001|attrs.knowledge|full

:R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]
l-003|e-001|ac1|authorized|iam-policy|"daemon is apt-installed metrics-shipper-agent, fleet-wide on role=monitoring; IAM stale, not unauthorized. Flag to sre-iam-team for catalog update."

:T resolutions
h-001  + → ++   [l-003 p1,p2 severe ⟂ e-001 :: systemd-started package unit, install traced to SRE config-management, same version on every monitoring-role host]
h-002  - → --   [l-003 r1 severe ⟂ e-001 :: systemd ancestry and fleet-wide presence — no interactive session in the tree]

:T close
loop  2
```

REPORT:

```invlang
:T conclude
termination.category   adversarial-refuted
disposition            benign
impact_verdict         none
confidence             high
matched_archetype      packaged-monitoring-daemon
summary                "SSH from mon-poller-04.sre using metrics-shipper traces to a fleet-wide metrics-shipper-agent rollout on 2026-04-29 via SRE config-management. IAM not yet updated; flag to sre-iam-team. Behavior sanctioned; documentation stale."

:T conclude.surviving [hyp_id|final_weight]
h-001|++
```

Three things to read off this shape. **One**, a lookup miss is not a
verdict. `authorized` would have closed `ac1` in Loop 1 and
`unauthorized` would have escalated immediately, but IAM answered
neither — so the lead recorded no verdict at all, and the open contract
forced the next move into PLAN with a sharper question. Writing
`indeterminate` as a way-station would have been terminal instead: a
benign close requires EVERY fulfilling row on a live contract to read
`authorized`, and an append-only document cannot take that row back
(rule #21, `validate._authz_contract_error`). Reach for `indeterminate`
when the anchor answered and its answer is "cannot say", not when the
lookup missed. **Two**, CMDB and IAM
dispatched as two parallel single-fact leads, not one composite — the
defender combines those facts by reasoning, so per the
"one-question = one-lead" rule they're separate `:L` rows. **Three**,
the Loop-2 follow-up is the registry-sparseness escape hatch: when
the registry of record has a gap, the right move is a different
system (host-state) answering the underlying mechanism question, not
a louder query against the same registry.
