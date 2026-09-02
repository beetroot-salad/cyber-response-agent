```invlang
:L findings [id|loop|name|target|tests|system|window]
l-000|0|ancestor resolution|||elastic|n/a
```

```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|??/??/??|soc-playground|knowledge=partial;alert_window=2026-08-30T09:59:51Z
```

```invlang
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?routine-sudo-training|v-001|initiated_by|identity|??||null|active
h-002|?anomalous-sudo-burst|v-001|initiated_by|identity|??||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_parent|"identity has an established sudo baseline on soc-playground"
p2|proposed_parent|"commands match routine lab/training tooling use"

:H h-002.preds [id|subject|claim]
p1|proposed_parent|"identity has no prior sudo baseline on this host"
p2|proposed_parent|"burst falls outside any approved change or training window"

:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|proposed|change-mgmt|"approved change or training window covers the sudo burst at 2026-08-30T09:54Z"|escalate|escalate

:L findings [id|loop|name|target|mode?|tests|system|window]
l-001|1|siem-falco-sudo-events|v-001||h-001,h-002|elastic|alert-window
l-002|1|cmdb-host-lookup|v-001||h-001|cmdb|n/a
l-003|1|change-window-lookup|v-001||h-001|change-mgmt|n/a
```

```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-002|identity|??/??|root|knowledge=partial

:E l-001.observations.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-002|executed|v-002|v-001|2026-08-30T09:54:51.724Z|runtime-audit:falco|cmd="sudo -u postgres psql -v ON_ERROR_STOP=1 --host=localhost --dbname=app";count=3;window=2026-08-30T09:54:51.724Z-2026-08-30T09:54:51.725Z

:R attr_updates [resolved_by|target|key|value]
l-001|v-002|ident|root
l-001|v-002|class|user/known-corp
l-002|v-001|class|??/??/novel

:R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]
l-003|proposed|ac1|unauthorized|change-mgmt|"no active change window, training exercise, or SOC drill documented for soc-playground"
```

```invlang
:L findings [id|loop|name|target|mode?|tests|system|window]
l-004|2|container-root-identity|v-002||h-001|identity-store|n/a
l-005|2|sudo-postgres-baseline|v-001||h-001,h-002|elastic|90d
l-006|2|container-identification|v-003||h-001|container-inspect|n/a
```

```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-003|compute|database-server/??/known-corp|e5b0213bd690|kind=container;image=soc-playground/host-db:22.04;name=db-1;knowledge=partial

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-003|runs_on|v-003|v-001||runtime-audit:container-inspect|postgresql14=true;elastic_agent=true

:R attr_updates [resolved_by|target|key|value]
l-004|v-002|class|user/novel
l-004|v-002|ident|root[container=e5b0213bd690]
```

```invlang
:T resolutions
h-001  null → ++   [l-005 p1,p2 severe ⟂ e-002 :: 50 prior sudo-to-postgres-psql events over Aug 7-22 with the exact alert commands; weekend and same-millisecond clustering are part of the established baseline]
h-002  null → --   [l-005 p1,p2 severe ⟂ e-002 :: baseline exists (p1 refuted) and the burst's same-millisecond cadence is this host's normal execution pattern, so the burst is not outside established behavior (p2 untested but unsupported)]
```

```invlang
:R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]
```

```invlang
:L findings [id|loop|name|target|mode?|tests|system|window]
l-007|3|ticket-system-context-lookup|v-001||h-001|ticket-system|n/a
```