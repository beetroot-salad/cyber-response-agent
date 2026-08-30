---
name: example-c-cumulative-escalation
description: Three competing hypotheses (legitimate-telemetry, dev-tool phone-home, malicious-C2) dispatched as three parallel leads. None reaches ++ individually, but the cumulative circumstantial pattern justifies escalation rather than benign. Load when an alert has multiple plausible parent topologies and the available tooling can refute the benign stories but cannot positively confirm the malicious one.
---

# Example C — Novel outbound DNS from a CI runner

Behavioral signature `egress-dns-query-to-rare-tld` fires on a domain (`telemetry-collect.live`) first observed org-wide 29h ago, zero fleet peers, regular `~30 min ± 3 min` cadence from one process tree. Not a known-pattern alert; the lead set has to enumerate plausible parents.

```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|build-runner/internal/known-corp|build-runner-07.ci|kind=vm;os=linux;role_note=stateless-ci-runner
v-002|process|node|node[pid=2188]|cmdline="npm exec quickmetrics-collect"
v-003|socket|dns-name|telemetry-collect.live|protocol=dns;first_seen_org=2026-05-04T22:11Z
v-004|module|npm-package|@quickmetrics/runtime-collector@0.1.2|published=2026-05-04T20:50Z

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|connected_to|v-002|v-003|2026-05-05T02:14:07Z|siem-event:siem|protocol=dns;cadence=~30min;count_24h=47
e-002|loaded_by|v-002|v-004|2026-05-05T01:58:40Z|runtime-audit:github-runner|via=npm-install
e-003|runs_on|v-002|v-001||inferred-structural:runtime|
```

PLAN authors three competing causes for the egress: which module inside `node[2188]` issues the queries. All three propose the same kind of parent and leave its identity `??` — the alert has not named it, and naming it is what the leads are for. What splits them is their predictions, each naming an observable the other two do not (§Sibling-fork uniqueness):

```invlang
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?declared-package-telemetry|v-002|loaded_by|module|??||null|active
h-002|?ci-tooling-phone-home|v-002|loaded_by|module|??||null|active
h-003|?post-install-implant|v-002|loaded_by|module|??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_parent|"package source repo declares telemetry endpoint and opt-out"

:H h-001.refuts [id|refutes|claim]
r1|p1|"no documented telemetry, or endpoint not declared in source"

:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-001|endpoint-policy|"CI runner egress to package telemetry endpoints permitted"|escalate|escalate

:H h-002.preds [id|subject|claim]
p1|proposed_parent|"node child of npm-exec under github-runner job, no other runtime in process tree"
p2|proposed_edge|"queries cease when build job ends"

:H h-002.refuts [id|refutes|claim]
r1|p1,p2|"queries persist past job lifetime, or process tree includes a non-build runtime"

:H h-003.preds [id|subject|claim]
p1|proposed_parent|"maintainer published recently and has no other packages"
p2|proposed_edge|"destination IP has no historical reputation and was registered shortly before package publication"

:H h-003.refuts [id|refutes|claim]
r1|p1,p2|"maintainer has long publication history, or destination IP has prior reputation"

:L findings [id|loop|name|target|tests|system|window]
l-001|1|package-source-and-maintainer|v-004|h-001,h-003|host-state|n/a
l-002|1|process-tree-and-job-correlation|v-002|h-002,h-003|host-state|±2h
l-003|1|destination-ip-reputation|v-003|h-001,h-003|siem|90d
```

PLAN issued three leads in one turn — each discriminates a different pair on the observable that pair predicts differently, and together they triangulate the parent. Dispatched as three parallel `Task` calls. Gather mints whichever templates the catalog lacks.

ANALYZE on returned summaries (`gather_raw/{lead_id}/`):

- `l-001`: maintainer profile shows zero other packages, account created 2026-04-19; package source repo (a single-commit GitHub repo) declares no telemetry mechanism and the binding to `telemetry-collect.live` is in a post-install script obfuscated via base64.
- `l-002`: process tree confirms `node[2188]` is a child of the github-runner job, but the queries continue 17 minutes past job exit — the daemon does not terminate.
- `l-003`: destination IP `203.0.113.42` registered 2026-04-21, two days after the maintainer account; no historical traffic from any corp host in 90d; SNI `metrics.nginx-cdn-collector.io` (a different domain than the DNS query, registered same week).

```invlang
:T resolutions
h-001  null → --   [l-001 r1 severe ⟂ e-002 :: source repo declares no telemetry; binding is in an obfuscated post-install script]
h-002  null → -    [l-002 p1,p2,r1 mild ⟂ e-001 :: daemon outlives job, but a CI-tool phone-home that survives job exit is unusual rather than refuted outright]
h-003  null → +    [l-001 p1 mild ⟂ e-002 :: recent maintainer with no other packages]
h-003  + → +       [l-003 p2 mild ⟂ e-001 :: IP registered just before publication, SNI/host mismatch — circumstantial, no C2 channel observed]
```

No single lead reaches `++` on `?post-install-implant`: confirming
C2 would require sandbox detonation or traffic-content inspection, and
neither is in the runtime tool surface. The path of least resistance
(stop at three `+`/`-`) underweights the integration. REPORT escalates
on the cumulative pattern.

The deferral table goes FIRST, in its own `append_block`, and `:T conclude`
last — the whole document is validated on every write, so a `:T conclude`
that lands before it is refused for a contract the next call was about to
account for (SKILL.md §`:T conclude`).

```invlang
:T conclude.deferred_authz [contract_ref|rationale]
h-001.ac1|"superseded by mechanism refutation at l-001 — ?declared-package-telemetry reached --, so whether CI-runner egress to package telemetry endpoints is permitted no longer bears on the close"
```

```invlang
:T conclude
termination.category   exhaustion-escalation
termination.rationale  "?post-install-implant cannot be driven to ++ with available tooling; circumstantial pattern is decision-relevant"
disposition            inconclusive
confidence             medium
impact_verdict         none
matched_archetype      novel-dependency-with-anomalous-egress
summary                "build-runner-07.ci is making periodic queries to a recently-registered domain via a post-install daemon in a freshly-published npm package by a single-package maintainer. Legitimate-telemetry path is refuted; malicious-C2 path is supported circumstantially but cannot be confirmed in-loop. Hand off for sandbox detonation + maintainer review."
ceiling_test            state=nothing-to-try cap=sandbox.detonate note=confirming ?post-install-implant would require sandbox detonation or traffic-content inspection, and neither is in the runtime tool surface
```

`disposition` is the run's closed vocabulary (`enum disposition`), the same
three keywords `report.md` carries — escalation is not one of them. The
hand-off is said by `termination.category exhaustion-escalation` plus the
`summary`; the disposition itself is `inconclusive`, because that is what "the
malicious path could not be refuted or confirmed" means.

Every commitment the run made is accounted for at the close. `h-002`'s `p1` and
`p2` are cited in the resolution head that moved it — one held, one failed, and
both are what `r1` fired on — so the closure rule can see they were settled
rather than dropped. `h-003` needed two leads to settle its two predictions, so
it takes **two rows**: `l-001` moves it to `+` and `l-003` confirms at the same
weight with `+ → +`. One row carries one head; a second head packed into the
first row's annotation is prose, and the prediction it names reads as abandoned.
`h-001`'s `ac1` was never resolved, because refuting the mechanism made the
authorization question moot; that is a claim about the case, so it is written as
a `:T conclude.deferred_authz` row rather than left to a reader to infer from
the `--`. A contract or a prediction that is declared and then simply disappears
is refused at CONCLUDE (rules #26 and #34).
