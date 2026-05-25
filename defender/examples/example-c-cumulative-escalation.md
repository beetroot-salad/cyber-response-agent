---
name: example-c-cumulative-escalation
description: Three competing hypotheses (legitimate-telemetry, dev-tool phone-home, malicious-C2) dispatched as three parallel leads. None reaches ++ individually, but the cumulative circumstantial pattern justifies escalation rather than benign. Load when an alert has multiple plausible parent topologies and the available tooling can refute the benign stories but cannot positively confirm the malicious one.
---

# Example C — Novel outbound DNS from a CI runner

Behavioral signature `egress-dns-query-to-rare-tld` fires on a domain (`telemetry-collect.live`) first observed org-wide 29h ago, zero fleet peers, regular `~30 min ± 3 min` cadence from one process tree. Not a known-pattern alert; the lead set has to enumerate plausible parents.

```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|endpoint|endpoint:linux|build-runner-07.ci|role=stateless-ci-runner
v-002|process|process:node|node[2188]|cmdline_via=npm-exec
v-003|endpoint|endpoint:dns-name|telemetry-collect.live|first_seen_org=2026-05-04T22:11Z
v-004|package|package:npm|@quickmetrics/runtime-collector@0.1.2|published=2026-05-04T20:50Z

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|queried_dns|v-002|v-003|2026-05-05T...|siem-event:siem|cadence=~30min;count_24h=47
e-002|loaded|v-002|v-004|2026-05-05T...|runtime-audit:github-runner|via=npm-install
```

PLAN authors three competing topologies under `v-002`'s `loaded`/`queried_dns` parents — they are mutually exclusive on parent class:

```invlang
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?legitimate-dependency-telemetry|v-002|loaded|package|legitimate-published-library||null|active
h-002|?developer-tooling-phone-home|v-002|queried_dns|process|build-tool||null|active
h-003|?malicious-dependency-c2|v-002|loaded|package|adversary-published-library||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_parent|"package source repo declares telemetry endpoint and opt-out"

:H h-001.refuts [id|refutes|claim]
r1|p1|"no documented telemetry, or endpoint not declared in source"

:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|proposed|org-policy|"CI runner egress to package telemetry endpoints permitted"|escalate|escalate

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
l-001|1|package-source-and-maintainer|v-004|h-001,h-003|host-query|n/a
l-002|1|process-tree-and-job-correlation|v-002|h-002,h-003|host-query|±2h
l-003|1|destination-ip-reputation|v-003|h-001,h-003|wazuh|90d
```

PLAN issued three leads in one turn — each discriminates a different pair, and together they triangulate the parent class. Dispatched as three parallel `Task` calls. Gather mints whichever templates the catalog lacks.

ANALYZE on returned summaries (`gather_raw/0..2.json`):

- `l-001`: maintainer profile shows zero other packages, account created 2026-04-19; package source repo (a single-commit GitHub repo) declares no telemetry mechanism and the binding to `telemetry-collect.live` is in a post-install script obfuscated via base64.
- `l-002`: process tree confirms `node[2188]` is a child of the github-runner job, but the queries continue 17 minutes past job exit — the daemon does not terminate.
- `l-003`: destination IP `203.0.113.42` registered 2026-04-21, two days after the maintainer account; no historical traffic from any corp host in 90d; SNI `metrics.nginx-cdn-collector.io` (a different domain than the DNS query, registered same week).

```invlang
:T resolutions
h-001  null → --   [l-001 r1 severe ⟂ source repo declares no telemetry; binding is in obfuscated post-install]
h-002  null → -    [l-002 r1 weak ⟂ daemon outlives job, but a CI-tool phone-home that survives job exit is unusual rather than refuted outright]
h-003  null → +    [l-001 p1 + l-003 p1,p2 moderate ⟂ recent maintainer with no other packages, IP registered just before publication, SNI/host mismatch — circumstantial pattern, no confirmed C2 channel observed]
```

No single lead reaches `++` on `?malicious-dependency-c2`: confirming
C2 would require sandbox detonation or traffic-content inspection, and
neither is in the runtime tool surface. The path of least resistance
(stop at three `+`/`-`) underweights the integration. REPORT escalates
on the cumulative pattern.

```invlang
:T conclude
termination.category   exhaustion-escalation
termination.rationale  "?malicious-dependency-c2 cannot be driven to -- with available tooling; circumstantial pattern is decision-relevant"
disposition            escalate
confidence             medium
matched_archetype      novel-dependency-with-anomalous-egress
summary                "build-runner-07.ci is making periodic queries to a recently-registered domain via a post-install daemon in a freshly-published npm package by a single-package maintainer. Legitimate-telemetry path is refuted; malicious-C2 path is supported circumstantially but cannot be confirmed in-loop. Hand off for sandbox detonation + maintainer review."
```
