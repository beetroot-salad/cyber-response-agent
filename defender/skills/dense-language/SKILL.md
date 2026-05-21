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
- **Commitments:** `:H` is the current surface for topology commitments.
  `ac*` and `ip*` are edge-check commitments for authz and impact.
- **Procedure:** `:L` records what the defender chose to run and why.
- **Results:** `:R` records check results or learned facts; `:T resolutions`
  records belief movement; `:T conclude` records closure.

The schema corresponds to the metal: model what was observed at the lowest
abstraction the available authority supports. Hypothesize higher-level
effects (e.g. credential theft) when only the mechanical observation
(e.g. lsass memory read) is on disk.

## Type vocabulary (closed)

Pick a vertex `type` from this list. The sub-kind goes in `class` (see
§Classification below).

| Type | Notes |
|---|---|
| `compute` | Any compute substrate. `attrs.kind ∈ {physical, vm, container, function, pod, mobile}`. IP-only observations: `attrs.knowledge=partial`. |
| `process` | Running execution unit on a compute. |
| `thread` | Sub-entity of process; `component_of` + hierarchical ID. |
| `memory-region` | Sub-entity of process; `component_of` + hierarchical ID. |
| `module` | Loaded library/DLL; `component_of` a process. |
| `session` | Authenticated interactive, API, or federated session. |
| `identity` | User, group, role, service account, application principal. |
| `storage` | `attrs.kind ∈ {object-store, block, file, secrets, nfs, archive}`. Bucket, blob, volume, share. |
| `database` | `attrs.kind ∈ {relational, nosql, graph, columnar, cache, search-index}`. |
| `network-device` | `attrs.kind ∈ {firewall, router, switch, load-balancer, waf, proxy, vpn-gateway}`. |
| `file` | Specific file artifact. |
| `socket` | Network socket. `attrs.protocol ∈ {tcp, udp, tls, dns, http, https, smtp, ldap, smb, rdp, ssh, ...}`. DNS / TLS / HTTP observations are sockets with protocol set. |
| `configuration` | Stored config that governs system or application behavior. `attrs.kind ∈ {registry-key, gpo, iam-policy, cap-rule, sysctl, systemd-unit, cron-entry, k8s-config, app-config, env-var, firewall-rule}`. Used as an entity when modified/created/read; used as a mediator via `:R authz.anchor_kind`. |
| `application` | Hosted application / SaaS tenant / platform. `attrs.kind ∈ {salesforce, slack, github, m365, gsuite, jira, servicenow, okta, entra, aws-account, azure-tenant, gcp-project, ...}`. The business-logic layer. |
| `app-object` | Entity inside an application. `attrs.kind ∈ {email, chat-message, ticket, channel, repo, record, document, secret-stored, pipeline, api-resource, calendar-event, dashboard}`. Always `contained_in → application`. |
| `credential` | Authentication material distinct from the identity it represents. `attrs.kind ∈ {access-key, password-hash, kerberos-ticket, oauth-token, jwt, api-token, ssh-key, client-cert, saml-assertion, session-cookie, refresh-token}`. |

**Use `unclassified-{type}` in `class` when type is known but sub-kind isn't;
`ambiguous-{a}-or-{b}` when genuinely indistinguishable.**

**Acting-entity types** (trigger source-side integrity discipline when an
`ac<n>` is declared with `parent_type` from this group): `session`, `identity`,
`process`.

## Relation catalog (closed)

Edges include both state relations and event interactions. Use `attrs?`
for outcome, count, resource path, bytes, method, parameters.

| Relation | Source → Target | Notes |
|---|---|---|
| `spawned` | process → process | |
| `executed` | process → file | Binary execution. |
| `loaded_by` | process → file | Module/library load. |
| `opened` | process → socket | |
| `connected_to` | socket → compute \| application | Transport-layer; for cloud APIs the application is the target. |
| `read` / `wrote` | process \| session → file \| storage \| database \| app-object \| configuration \| credential | Event interaction; attrs for bytes/path/outcome. Covers email delivery (recipient `read` message-app-object). |
| `created` / `deleted` | session \| process \| identity → app-object \| configuration \| identity \| credential \| storage | Event interaction; covers cloud API verbs and SaaS object lifecycle (e.g. send-email = `created` on email app-object). |
| `modified` | session \| process \| identity → app-object \| configuration \| identity \| credential \| storage \| database \| file | State change. |
| `listed` | session \| process \| identity → storage \| database \| application | Enumeration. |
| `runs_on` | process \| session \| application \| compute → compute | Compute-substrate containment. Container-on-host and pod-on-node are both `runs_on` between two `compute` vertices. |
| `contained_in` | app-object → application | Hosted-app object lives inside its application. |
| `authenticated_as` | session → identity | State relation asserted by an auth/session source. |
| `authenticated_via` | session → credential | The credential used to establish this session. Distinct from `authenticated_as` (which names the identity); the credential is the bytes that proved possession. |
| `initiated_by` | session → identity \| compute | |
| `triggered_by` | process \| session → process \| session \| configuration | Includes scheduler-initiated execution (`triggered_by` a cron-entry / scheduled-task configuration). |
| `escalated_privilege` | session → session | Self-edge. |
| `assumed_role` | session \| identity → identity | Federation, cross-account, role-assumption. The target identity is the assumed role. |
| `granted_consent` | identity → application | OAuth consent: identity authorized an application to act on their behalf. |
| `issued` | application \| identity → credential | Credential minting (token issuance, key creation). |
| `member_of` | identity → identity | User→group, role→bundle. |
| `identified_as` | placeholder → real-vertex | Post-hoc attribution; never mutate the placeholder. |
| `component_of` | vertex → vertex | Part-of for inward decomposition. |
| `attempted_auth` | compute \| process \| session → compute \| application | Event interaction; auth attempt, may be failed. |
| `governs` | configuration → vertex | When the configuration's mediating action is itself an observed event in the graph: GPO replication triggers startup-script execution, a CAP policy decision is logged for a specific request, a K8s Deployment spec instantiates a pod. Use `:R authz.anchor_kind` instead when the configuration is invoked silently as a policy mediator without a discrete in-graph event. |

## Classification (`class` cell)

The `class` cell is structured by `type`. For entities in the topology of
trust (compute, identity, application), it is a packed slash-separated
tuple. For artifacts, it is a single sub-kind token.

### Compute — `<role>/<zone>/<provenance>`

| Slot | Enum |
|---|---|
| `role` | `monitoring`, `web-server`, `app-server`, `database-server`, `mail-server`, `dns-server`, `dns-resolver`, `domain-controller`, `directory-server`, `file-server`, `bastion`, `egress-host`, `workstation`, `byod`, `mobile-device`, `build-runner`, `dev-tools`, `kiosk`, `iot`, `container-host`, `function-runtime`, `ip-only`, `unknown` |
| `zone` | `internal`, `dmz`, `partner`, `regulated`, `internet`, `cloud-managed`, `unknown` |
| `provenance` | `known-corp`, `known-partner`, `novel`, `anonymous` |

Examples: `monitoring/internal/known-corp`, `web-server/dmz/known-corp`,
`ip-only/internet/novel`.

**IP-only sentinel.** When the observation is just an IP with no role/zone
context, use role=`ip-only`. Set `attrs.knowledge=partial`. The zone/provenance
slots still carry signal (where in the topology the IP appears; how known it is).

### Identity — `<kind>/<provenance>`

| Slot | Enum |
|---|---|
| `kind` | `user`, `group`, `role`, `service-account`, `application-principal`, `federated-user`, `unknown` |
| `provenance` | `known-corp`, `known-partner`, `novel`, `anonymous` |

Examples: `user/known-corp`, `service-account/known-corp`,
`federated-user/known-partner`.

### Application — `<vendor>/<trust>`

| Slot | Enum |
|---|---|
| `vendor` | one of `attrs.kind` values from §Type vocabulary (`salesforce`, `slack`, `github`, ...) |
| `trust` | `corp-tenant`, `partner-tenant`, `external-tenant`, `unknown` |

Examples: `salesforce/corp-tenant`, `github/external-tenant`.

### Session — single token

Enum: `interactive`, `api`, `federated`, `service`, `scheduled`, `unknown`.

### All other types — single token

`class` is a sub-kind discriminator. Free string is permitted but prefer
the corresponding `attrs.kind` enum from §Type vocabulary when available.

### Process — baseline schema

A `process` vertex has a locked baseline. Fill all of these when known.

| Slot | Required when | Notes |
|---|---|---|
| `class` | always | Image basename, lowercase (`bash`, `powershell.exe`, `lsass.exe`). Never put anomaly flags here. |
| `ident` | always | `<basename>[pid=N]` (e.g. `powershell.exe[pid=3920]`). |
| `attrs.image` | known | Full executable path. |
| `attrs.hash` | known | SHA256 of the image. |
| `attrs.cmdline` | known | Full command line with arguments. Quote if it contains `\|`. |
| `attrs.user` | known | Running user. (Or reference the identity via `authenticated_as` on the spawning session.) |
| `attrs.start_time` | optional | ISO timestamp when the process spawned. |
| `attrs.integrity_level` | optional | Windows-only: `low\|medium\|high\|system`. |
| `attrs.signing` | optional | Authenticode signature / publisher (e.g. `signed:microsoft`, `unsigned`). |
| `attrs.anomaly` | when observed | Anomaly flags (e.g. `parent_spawn_from_explorer`). Goes here, not in class. |

Parent process is recorded via the `spawned` edge from parent to child, not as
a process attribute.

### `:H parent_class`

Same grammar as `:V class`, dispatched on `parent_type`.

### Sibling-fork uniqueness (rule #23)

Sibling hypotheses must differ on at least one **topological** axis:
`parent_type`, `parent_class`, `attached_to`, or `rel`.

**Legitimacy is not a topological axis.** When two candidate hypotheses
share topology but differ only on "was this action authorized?",
collapse them into ONE hypothesis with an `:H h-NNN.authz` contract
carrying the legitimacy question. The contract's resolution drives
disposition.

Forks should enumerate **competing upstream causes**, not **competing
interpretations of the same cause**. If both candidates would be
discriminated by the same leads, they're one hypothesis with an authz
contract — not two siblings.

**Worked example — wrong:**

```invlang
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?legitimate-admin-gpo-edit|v-003|modified|identity|service-account/known-corp||null|active
h-002|?adversary-credential-abuse|v-003|modified|identity|service-account/known-corp||null|active
```

Both rows share `attached_to`, `rel`, `parent_type`, `parent_class`. The
only thing varying is intent. This is the pointless-enumeration trap.

**Worked example — right:**

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
v-003|compute|unknown/internet/anonymous|10.42.7.183|kind=physical;knowledge=partial
```

`:E` edges:

```invlang
:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-003|v-001|2026-05-05T03:47:12Z|siem-event:wazuh|outcome=failed
```

State edges (`runs_on`, `member_of`, `authenticated_as`, `contained_in`)
have no meaningful `when` — leave it empty. Event interactions (`read`,
`wrote`, `created`, `deleted`, `attempted_auth`, `assumed_role`,
`granted_consent`) take a timestamp.

`auth_kind:source` is observational authority. Read it as
`obs_kind:source`. `kind ∈ {siem-event, runtime-audit, authoritative-source,
client-asserted, inferred-structural}`. Only the first three support
`++`/`--` resolutions.

`:H` topology commitments:

The hypothesis header is a thin row with identity-only columns.
Predictions, refutations, authorization contracts, and parent-vertex
attributes each get their own named sub-block under the same `:H` tag,
namespaced by the hypothesis id.

```invlang
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?routine-admin-source|v-001|attempted_auth|compute|bastion/internal/known-corp||null|active
h-002|?novel-adversary-source|v-001|attempted_auth|compute|unknown/internet/novel||null|active

:H h-001.preds [id|subject|claim]
p1|proposed_parent|"source has prior successful bastion auth"
p2|proposed_edge|"auth timing matches prior admin pattern"

:H h-001.refuts [id|refutes|claim]
r1|p1|"source has no prior successful bastion auth"

:H h-002.preds [id|subject|claim]
p1|proposed_parent|"source is absent from prior auth history"
p2|proposed_edge|"auth timing deviates from admin baseline"

:H h-002.refuts [id|refutes|claim]
r1|p1,p2|"source and timing match normal admin history"
```

Keep commitments lean: one proposed upstream vertex plus one edge. Use
1-2 predictions. Use `r*` refutations to name what would overturn
predictions. The `refutes` column on a refutation row is a
comma-separated list of prediction ids it would refute.

Authz and impact are edge checks. Authz contracts live in
`:H h-NNN.authz`:

```invlang
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-003|?approved-service-read|v-010|read|identity|service-account/known-corp||null|active

:H h-003.preds [id|subject|claim]
p1|proposed_parent|"service account is configured reader"

:H h-003.refuts [id|refutes|claim]
r1|p1|"account absent from reader policy"

:H h-003.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|proposed|iam-policy|"service account allowed to read object at event time"|escalate|escalate
```

Authorization checks ask whether an interaction edge is permitted.
Impact checks ask whether the edge's effect crosses a threshold.
Integrity is source-side graph work: follow session, identity, process,
endpoint, and provenance rather than widening the authz predicate.

**`anchor_kind` enum** (the authority being consulted to resolve the
contract): `iam-policy`, `gpo`, `cap-rule`, `change-mgmt`,
`data-classification-policy`, `k8s-policy`, `federation-policy`,
`endpoint-policy`, `approved-source-list`, `runtime-evidence`, `other`.

### Quoting cell values that contain `|`

Cell values that include a literal `|` (e.g. Falco bitmask flags like
`EXE_WRITABLE|EXE_LOWER_LAYER`) must be wrapped in double quotes. The
row tokenizer doesn't split on `|` inside a quoted span:

```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-002|process|bash|bash[pid=42]|cmdline="bash -c whoami";flags="EXE_WRITABLE|EXE_LOWER_LAYER";user=root
```

For high-cardinality multi-value fields, prefer pushing them to the raw
gather payload rather than packing them into `attrs?`.

`:L` leads:

```invlang
:L findings [id|loop|name|target|mode?|tests|system|template|query|window]
l-001|1|auth-history-jsmith-bastion|v-001||h-001,h-002|wazuh|auth-history|user=jsmith host=bastion-01|90d
```

A lead is a procedure: what was run, against what target, for which
commitments. Put route plans in `:L l-001.lead_preds`; those are routing
rules, not world-state predictions.

Topology observations and learned facts:

```invlang
:E l-001.observations.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-002|attempted_auth|v-003|v-001|2026-05-01T10:11:00Z|siem-event:wazuh|outcome=success;user=jsmith;count=142

:R attr_updates [resolved_by|target|key|value]
l-001|v-003|class|bastion/internal/known-corp
```

Adding `:V` / `:E` changes the observed graph. `:R attr_updates` records
facts learned about existing graph objects; do not create vertices just
for facts.

Belief movement:

```invlang
:T resolutions
h-001  null → ++    [l-001 p1,p2 severe ⟂ e-002 :: prior successful bastion auth and timing match both predictions]
h-002  null → --    [l-001 r1 severe ⟂ e-002 :: normal source history refutes adversary-source novelty]
```

`:T resolutions` is not another observation. It says how a lead changed
a commitment's weight. Cite prediction/refutation IDs and supporting
edges.

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

## Authoring discipline

- **Append only.** Add rows; do not rewrite prior graph or commitment rows.
- **Type-then-class.** Pick the vertex `type` from §Type vocabulary first, then
  fill `class` per the grammar that type's `class` follows.
- **Metal-correspondence.** Record what was observed at the lowest abstraction
  the authority supports. Hypothesize the higher-level effect (e.g. credential
  theft) when only the mechanical observation (memory read of lsass) is on disk.
- **Cloud API calls are edges, not vertices.** `session → created → app-object`,
  not a separate command vertex. Parameters go in edge `attrs`.
- **DNS / TLS / HTTP are sockets with `attrs.protocol` set.** Queried name,
  certificate fingerprint, URL → `attrs`.
- **Credentials are entities distinct from identities.** Stealing a token does
  not steal the identity; the credential is a separate `:V` with its own
  lineage (`issued`, `read`, `used_to_authenticate`).
- **Configuration is an entity when modified; a mediator when invoked.** A GPO
  edited at T is a `:V configuration` with a `modified` edge. A GPO that
  silently authorized a logon is `:R authz.anchor_kind=gpo`.
- **App-objects need their application.** Always materialize the `application`
  vertex and the `contained_in` edge when modeling SaaS-internal entities.
- **`attrs.kind` is part of the controlled vocab** on `compute`, `storage`,
  `database`, `network-device`, `socket`, `configuration`, `application`,
  `app-object`, `credential`. Pick from the §Type vocabulary enum.
- **Aggregate observations stay in edge attrs.** N occurrences of the same
  interaction, M distinct sources/targets, P-byte total → record as
  `attrs.count`, `attrs.distinct_sources`, `attrs.bytes` on a single edge.
  Do not materialize per-occurrence vertices or "aggregate" pseudo-vertices.
- **OAuth clients are two vertices.** A registered OAuth client (a Salesforce
  Connected App, an Azure App Registration, a GitHub App) is both an
  `application` (the registered system) and an `identity` with
  `class=application-principal/<provenance>` (the principal that acts).
  Materialize both when the investigation touches either facet. Consent
  flows target the application (`identity → granted_consent → application`);
  authentication and action flow through the principal (`session →
  authenticated_as → application-principal`). Link them with
  `application → issued → application-principal-identity` (not
  `identified_as`, which is for placeholder vertices being attributed
  post-hoc).
- **Phishing pages are `application` vertices.** An attacker-hosted login
  clone (`okta-acme-verify.net`) is an `application` with
  `class=<vendor>/external-tenant` and `attrs.kind=phishing-page` (e.g.
  `class=okta/external-tenant`). The HTTPS connection to it is a
  separate `socket` with `attrs.protocol=https`. Don't conflate the page
  (an application the attacker controls) with the transport (the socket).
- **Token minted from a prior token** (refresh→access flow): record on
  the new credential's row with `attrs.minted_from=<credential-id>`. Do
  not introduce a new relation. The `issued` edge from the issuing
  application still carries; `attrs.minted_from` records the chain.
- **System-fired inferences are `:R` rows, not edges.** A platform's own
  policy decision ("concurrent-session-detection fired", "DLP flagged",
  "anomaly score crossed threshold") is the platform asserting a
  conclusion. Record under `:R attr_updates` or a lead's `:R`
  resolutions, not as an `:E` edge — there was no observed
  graph-extending interaction.
- **Keep high-cardinality details in raw gather payloads,** not invlang cells.
