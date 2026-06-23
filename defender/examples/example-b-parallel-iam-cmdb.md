---
name: example-b-parallel-iam-cmdb
description: Two parallel single-fact registry leads (CMDB + IAM) plus a Loop-2 host-state follow-up after IAM lookup misses. Demonstrates indeterminate-authz forcing a structural loop-back, and the "one-question = one-lead" rule against composite-lead temptation. Load when an alert involves a registry / identity question and you're tempted to bundle multiple registry checks into one composite lead.
---

# Example B — SSH login by a non-stereotyped account from a documented monitoring source

SSH auth-success on `app-host-12.prod` from `mon-poller-04.sre` using account `metrics-shipper`. The account isn't stereotyped in the SRE monitoring runbook — sanctioned rollout whose IAM update lagged, or unfamiliar process on the source?

```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|endpoint|endpoint:ipv4|10.20.5.41|hostname=mon-poller-04.sre
v-002|endpoint|endpoint:ipv4|10.20.7.118|hostname=app-host-12.prod
v-003|identity|identity:account|metrics-shipper|

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|ssh_auth_success|v-001|v-002|2026-05-05T03:42:11Z|siem-event:siem|account=metrics-shipper;port=22

:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?sre-rollout-lag-in-iam|e-001|ssh_auth_success|process|monitoring-agent||null|active
h-002|?adversary-on-monitoring-source|e-001|ssh_auth_success|process|adversary-shell||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_parent|"source is documented monitoring infrastructure"
p2|proposed_parent|"metrics-shipper runs as a packaged systemd daemon on source, fleet-wide on the monitoring role"

:H h-001.refuts [id|refutes|claim]
r1|p1,p2|"source undocumented, or no such daemon on host"

:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|proposed|iam|"metrics-shipper is provisioned and authorized for this source→target SSH path"|escalate|escalate

:H h-002.preds [id|subject|claim]
p1|proposed_parent|"process initiating SSH is not a packaged systemd unit"

:H h-002.refuts [id|refutes|claim]
r1|p1|"process is a distro-packaged, systemd-spawned daemon"

:L findings [id|loop|name|target|tests|system|window]
l-001|1|cmdb-source-lookup|v-001|h-001,h-002|cmdb|n/a
l-002|1|iam-account-lookup|v-003|h-001|iam|n/a
```

PLAN dispatches `l-001` and `l-002` as **two parallel `Task` calls** —
independent single-fact registry questions, not a correlation across
raw data. Gather picks (or mints) the per-system template and records
the bound params under each lead's `observations.json#queries`.

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
:R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]
l-002|e-001|ac1|indeterminate|iam-policy|"IAM lookup miss; per sparse-registry semantics, ambiguous between 'never provisioned' and 'recently rolled out, not yet in IAM' — neither IAM alone nor CMDB's account-pinned authorized_outbound resolves it"

:T resolutions
h-001  null → +    [l-001 p1 weak ⟂ source documented as monitoring infra; p2 unresolved without host-side evidence]
h-002  null → -    [l-001 weak ⟂ source is sanctioned monitoring infra, not raw adversary footprint — but documented hosts can still be compromised]
```

`ac1` lands `indeterminate`, which blocks `disposition: benign`
regardless of the behavioral grading on `h-001`. The loop-back is
structural: ask host-state the question IAM couldn't answer — is
`metrics-shipper` a packaged daemon on the source?

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
:R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]
l-003|e-001|ac1|authorized|iam-policy|"daemon is apt-installed metrics-shipper-agent, fleet-wide on role=monitoring; IAM stale, not unauthorized. Flag to sre-iam-team for catalog update."

:T resolutions
h-001  + → ++   [l-003 p2 severe ⟂ packaged daemon, install traced to SRE config-management, fleet-wide]
h-002  - → --   [l-003 r1 severe ⟂ process is a packaged systemd-spawned daemon, not an adversary shell]
```

REPORT:

```invlang
:T conclude
termination.category   adversarial-refuted
disposition            benign
confidence             high
matched_archetype      sre-rollout-lag-in-iam
summary                "SSH from mon-poller-04.sre using metrics-shipper traces to a fleet-wide metrics-shipper-agent rollout on 2026-04-29 via SRE config-management. IAM not yet updated; flag to sre-iam-team. Behavior sanctioned; documentation stale."
```

Three things to read off this shape. **One**, the three legitimacy
statuses do distinct work: `authorized` would have closed `ac1` in
Loop 1; `unauthorized` would have escalated immediately; `indeterminate`
did neither — it kept the contract open and structurally forced the
next move into PLAN with a sharper question. **Two**, CMDB and IAM
dispatched as two parallel single-fact leads, not one composite — the
defender combines those facts by reasoning, so per the
"one-question = one-lead" rule they're separate `:L` rows. **Three**,
the Loop-2 follow-up is the registry-sparseness escape hatch: when
the registry of record has a gap, the right move is a different
system (host-state) answering the underlying mechanism question, not
a louder query against the same registry.
