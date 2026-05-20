# Playground Environment v2 — Design

## Purpose

Define the next-generation playground for exercising the SOC triage agent end-to-end. v1 (documented in `playground-elastic-stack.md`) is a two-endpoint Wazuh+Elastic stack sufficient for smoke tests and single-signature development. v2 targets a richer environment that:

1. **Forces triage discipline** — a population of similar-but-distinguishable entities, so the agent can't reach a correct disposition by brute-forcing "the only host there is."
2. **Produces realistic patterns** — peer baselines, lateral-movement paths, authorization context, role-clustered telemetry. The patterns an analyst actually reasons about.
3. **Is chaotic by default** — common real-world failure modes (schema drift, dropped data, stale CMDB, outages) are first-class features of the playground, not a bolt-on.

This doc fixes the *content* of v2. Deployment topology (local devcontainer vs. VPS vs. cloud) is deliberately deferred pending a resource + risk assessment (§Deployment).

## Relationship to other design docs

- `playground-elastic-stack.md` — v1 playground (implemented). v2 extends it; does not replace the bootstrap mechanics.
- `evaluation-and-chaos-design.md` — eval harness + chaos-on-replay. v2 is the *generation* side: chaos that happens upstream of fixture capture, producing the realistic faults that the eval harness later replays deterministically. The two chaos surfaces are complementary (§Chaos model).

## Goals and non-goals

**Goals**
- A population large enough that "compared to what" questions are meaningful (peer baselines, role clustering, repeat offenders).
- Telemetry coverage sufficient for the archetypes we actually care about — identity, endpoint, network/DNS, baseline activity, ticket history.
- Chaos-from-day-one: real schema drift, real dropped data, real stale CMDB entries, real service outages, as configurable playground modes.
- Reproducibility knobs so the same chaos profile can be reapplied (seeds, not byte-determinism — fixture replay handles that).
- A single stack that serves both interactive development and fixture-capture runs for eval.

**Non-goals**
- Byte-deterministic reruns — that's the eval harness's job via fixture replay.
- A full enterprise simulation. We're modeling SOC triage patterns, not an IT department.
- Multi-tenant or production-grade security for the playground itself. It runs with known credentials in an isolated network.
- Replacing the Wazuh stack. v1's Wazuh services stay for signature-level development and existing test coverage.

## Mental model

A triage decision is a function of two things the v1 playground mostly lacks:

1. **Population context** — the alert names one entity; the agent's job is to understand that entity *relative to its peers*. "Did this user do something unusual" is undefined when there's one user.
2. **Failure context** — real SOCs operate with partially broken observability. The agent will see dropped fields, outdated CMDB, index gaps, misconfigured parsers. A playground that never breaks trains an agent that trusts its tools — and then fails silently in production.

v2 is shaped by those two gaps. Everything else — service count, volume, flashiness — is secondary.

## Deployment — envelope estimate and preferred path

Two hard constraints:
1. **Continuous run** — baseline activity, slow-drift chaos (stale CMDB, schema drift) only make sense when the environment is up around the clock. Laptops off overnight kill this.
2. **Level-down capability** — must be possible to scale the stack down (stop non-essential hosts) during idle periods without reprovisioning.

### Footprint estimate (v2 full stack)

| Component | RAM | Notes |
|---|---|---|
| Elasticsearch | 4 GB | Single-node, dev-sized |
| Kibana | 2 GB | |
| Fleet server | 0.5 GB | |
| 8 hosts × Elastic Agent + role services | ~8 GB | Web ×2, DB, jump-box, dev ws, canary, office ws ×2 |
| Zeek + Packetbeat | 0.5 GB | Network tap |
| MinIO (blob storage) | 0.5 GB | See §Blob storage |
| Keycloak / identity stub | 0.5 GB | |
| Ticket stub, CMDB stub, proxy, TI stub | 1 GB | Combined |
| Chaos control plane | 0.3 GB | Out-of-band, small |
| Headroom | 2 GB | |
| **Total** | **~19 GB** | Plus 60–100 GB disk for indices over time |

CPU: 8 vCPU is adequate; 4 vCPU would be marginal under attack-simulation bursts.

### Options and costs

| Topology | Spec | Monthly | Continuous | Cloud-API alerts |
|---|---|---|---|---|
| Local devcontainer | 32 GB laptop | $0 | No | No |
| VPS — Hetzner CCX23 | 8 vCPU / 32 GB / 240 GB NVMe | ~$60 | Yes | No |
| VPS — Hetzner CCX33 | 16 vCPU / 64 GB | ~$115 | Yes | No |
| AWS m5.2xlarge (on-demand) | 8 vCPU / 32 GB | ~$280 | Yes | Yes |
| AWS m5.2xlarge (reserved) | same | ~$175 | Yes | Yes |
| AWS stop/start for capture | 8h/day | ~$70–100 | No | Yes |
| **Hybrid: VPS + tiny AWS shell** | Hetzner + micro AWS | ~$65–75 | Yes | Yes |

### Risk rank (lowest → highest)

- **Local**: no exposure; chaos can't leak.
- **VPS**: SSH surface, outbound traffic from attack-simulation may draw abuse notices from the provider, persistent data in a place you don't fully control.
- **Cloud**: IAM misconfiguration reach, surprise bills from adjacent services getting pulled in, outbound attack-like traffic triggering provider abuse flags harder.

### Preferred path

**Hybrid: VPS primary + small AWS shell.**

- VPS (Hetzner CCX33 — 8 vCPU / 32 GB / 240 GB, dedicated) hosts the full v2 stack. Continuous operation, affordable, level-down by stopping non-essential containers during idle (canary + one web-tier + office workstations = −4 GB).
- A tiny AWS account (one S3 bucket, one IAM user, a few KMS keys, CloudTrail on) runs alongside. No workloads — just enough to generate realistic cloud API events that Elastic ingests via a CloudTrail→ES pipeline. Budget <$15/mo.
- Local devcontainer remains for feature work against a subset of the stack (v1-style), not for continuous ops.

This gets us: continuous run, peer-baseline population, cloud-API alert coverage where it's uniquely valuable, ~$75/mo total, and a blast radius smaller than cloud-primary.

### Still-open deployment questions

- VPS provider choice (Hetzner, Vultr, DigitalOcean) — cost/reliability trade, not urgent.
- Whether the AWS shell should use LocalStack instead for the first iteration and promote to real AWS only when we want cross-account patterns. Cheaper and lower-risk to start with LocalStack.
- Secret management — for a single-dev VPS, a sealed `.env` is fine; if this ever goes multi-dev, revisit.

## Tech stack

Constraints: OSS or free-tier, lightweight enough to fit the CCX33 footprint alongside a realistic host population, and produce telemetry shaped like real enterprise gear — not toys. This section is the authoritative list of chosen components; §Telemetry stack below keeps the tier-ordering view.

### Network

| Concern | Choice | Notes / alternatives |
|---|---|---|
| Edge firewall | Hetzner Cloud Firewall | Free, IaC-managed, blocks before host even boots |
| Host firewall | nftables | Per-container rules the edge can't express |
| Passive monitoring | Zeek | conn / dns / http / ssl / files logs — richest OSS network telemetry. Alt: Suricata (signature-first) |
| Forward proxy | Squid | User-attributed egress, SOC-standard shape |
| DNS | Unbound + local playground zone | Query logs; controlled zones for exfil / beaconing patterns. Alts: BIND (heavier, more "enterprise-shaped"), CoreDNS (container-native) |
| Admin access | Plain SSH over Hetzner FW allowlist | No VPN for single-dev. Alts: WireGuard if multiple services need direct local access; Tailscale trades purity for convenience |

### Identity

| Concern | Choice | Notes / alternatives |
|---|---|---|
| IdP / SSO | Keycloak | Enterprise-shaped OIDC/SAML + rich event listener. Alts: Authentik (newer, lighter config), Dex (too thin — delegates user mgmt), FreeIPA (heavy AD-like stack) |
| Host auth | sshd + PAM (native) | auth.log + journald — bedrock Linux triage signal |
| User/group mgmt | Flat YAML → `/etc/passwd` + SSH key distribution from repo | Cross-host identity consistency without AD/LDAP complexity |
| Internal PKI | step-ca (deferred, Phase 3+) | Only when mTLS / client-cert patterns are wanted |

### Data

| Concern | Choice | Notes |
|---|---|---|
| SIEM + query + dashboards | Elasticsearch + Kibana | v1 baseline; detection rules + Fleet + Cases native |
| Log shipping | Elastic Agent + Filebeat | Fleet-managed policies |
| Endpoint | Elastic Defend + Falco | Process tree + FIM (Defend); Falco keeps v1 syscall coverage |
| Blob storage | MinIO | S3-compat, real IAM, audit webhook (§Blob storage) |
| Database tier | PostgreSQL + pgaudit | Ubiquitous, realistic query patterns, granular audit extension |
| Ticketing stub | Existing FastAPI `ticket-server` | Keep stub over Elastic Cases per §Open questions |
| CMDB stub | YAML + thin FastAPI | Asset queries + mutation overlay for stale-CMDB chaos |
| Threat intel stub | FastAPI stub | Local VT/OTX shape |
| Change mgmt stub | YAML + thin FastAPI | Authorized-change context. Adds rolling standing CRs (daily/weekly) so baseline-aligned windows are CR-backed; attack runner can post synthetic CRs with `--cr-mode {valid,stale,scope-mismatch}` to exercise host/time/identity scope checks |
| Identity stub | FastAPI over `keycloak/realm.yaml × hosts/inventory.yaml` | Authz API — `can_access?host=`, `authorized_hosts` per user. Surfaces the realm×inventory join that seed-users.py applies on hosts, so agents can resolve legitimacy contracts authoritatively without reading `/etc/passwd` |

### Telemetry sources — who produces what

Overlap is a feature: an SSH login shows up across `auth.log` (PAM), auditd (session syscalls), wtmp, and Zeek (network flow) — real triage leans on correlating across these.

| Signal category | Producer | What it logs |
|---|---|---|
| Endpoint (process/file) | Elastic Defend | Process exec, FIM, outbound conns per host |
| | Falco | eBPF syscall-pattern rule hits |
| | auditd | Raw kernel audit firehose — execve, open, setuid, PAM hooks |
| Network (L3–L7) | Zeek | Passive protocol decode — conn / dns / http / ssl / files |
| | Packetbeat | Flow + protocol events from host POV |
| | Squid access log | Proxied HTTP/S egress with user attribution |
| Host auth | sshd / PAM → journald | SSH attempts, key matches, failures |
| | sudo | Privileged command invocations |
| | auditd PAM rules | Session open/close at syscall level |
| Identity / IdP | Keycloak event listener | OIDC/SAML login, MFA, admin actions — JSON events |
| Data access — blob | MinIO audit webhook | Per-request S3: principal + IP + UA + key + response |
| Data access — DB | pgaudit | PostgreSQL session + object-level audit |
| | Postgres `log_statement` | Query logging |
| Application | nginx / app access logs | HTTP request-level events from the web tier |
| Shipping | Elastic Agent (+ Filebeat edge cases) | Carries all of the above into Elasticsearch |

### Provisioning (meta)

Not part of the playground's runtime surface, but recorded here for completeness. Managed from the devcontainer; see `infra/` for the actual configuration.

| Concern | Choice |
|---|---|
| VPS IaC | Terraform + `hetznercloud/hcloud` provider |
| VPS bootstrap | `cloud-init` (native Hetzner) |
| Container runtime on VPS | Docker + Docker Compose |
| State | Local `terraform.tfstate` (gitignored) — single-dev; move to S3/remote backend only if it becomes multi-dev |

## Environment population

The population design is the load-bearing part of v2. Thin populations don't produce the patterns we need regardless of how much telemetry they emit.

### Hosts — role-clustered

A minimum viable population:

| Role | Count | Purpose |
|---|---|---|
| Web tier | 2 | Peer baseline; lateral target from jump-box; public-ish traffic |
| Database tier | 1 | High-criticality asset; tight access expectations |
| Jump-box / bastion | 1 | SSH hub; where lateral-movement paths originate |
| Dev workstation | 1 | Lower criticality; permissive baseline; noisy-but-benign activity |
| Office user workstation | 2 | No infra access — only blob storage + prod user-facing apps. Models "office user compromise" paths |
| Canary host | 1 | Designated attack target; isolates experiments |

The count (8) is a floor, not a target. The point is *clusters*: two web-tier hosts and two office workstations mean the agent can ask "is this normal for web-tier" or "is this normal for an office user" and get a meaningful answer. Every role with count=1 is a blind spot for peer comparison.

Office workstations are deliberately segregated at the access-policy layer: they authenticate against the blob store and the prod user-facing web endpoints, nothing else. No SSH to infra, no DB credentials. This cluster exists specifically to support credential-theft / phishing-pivot archetypes where the initial compromise target has narrow but high-value access.

Hosts carry differentiating attributes that the CMDB layer exposes:
- **Criticality** — `prod` / `preprod` / `dev` / `sandbox`
- **Owner** — a fake user/team id
- **Change window** — maintenance windows during which some actions are pre-authorized
- **OS + version** — at least two OS variants (e.g., Ubuntu 22.04 and Ubuntu 24.04) so version-sensitive signals exist
- **Trust relationships** — SSH key distribution, NFS mounts, DB credentials — enumerated explicitly so lateral-movement paths are known ground truth

### Identities

10–20 fake user identities, grouped into roles:

| Role | Count | Typical behavior |
|---|---|---|
| SRE / ops | 3–4 | sudo, cron management, multi-host SSH |
| Developer | 5–8 | git, package installs on dev workstations, occasional jump-box |
| DBA | 1–2 | DB-tier access only |
| Service accounts | 3–5 | Automated, predictable patterns (cron, scheduled reports) |
| Contractor / temp | 1–2 | Time-limited access; elevated suspicion surface |

Identities don't need to be real OS accounts everywhere — what matters is *consistent identifiers across logs*. A user id that shows up in `auth.log`, Zeek conn logs, and ticket history with the same label is what makes cross-source correlation work.

### Baseline activity generators

The single biggest difference between a useful playground and an empty one. Without baseline:
- Every alert is the only interesting event in the logs.
- "Is this unusual" is trivially yes.
- False-positive patterns can't form.

Generators needed:
- **Cron-driven scripts** — periodic backups, health checks, log rotation, reporting jobs. Exercises the "scheduled task running as service account" pattern.
- **Scripted user sessions** — timed SSH logins with working sessions (git pulls, edits, builds) tied to each dev/SRE identity.
- **Realistic web traffic** between web-tier and DB-tier — query patterns simulating an app, plus office-workstation fetches against the blob store.
- **Occasional sudo / privilege escalations** by SRE identities, some inside change windows and some outside.
- **Intermittent noise** — failed logins from typos, mistyped commands, accidental `curl` of wrong endpoints. FPs come from looking like noise, so noise must exist.

**Crucial property: baseline must not be cron-regular.** A generator that fires exactly every 5 minutes produces a pathological baseline that no real environment has, and detections tuned against it break in production. Requirements:

- **Jittered intervals** — Poisson-distributed or similar, with mean rate but no fixed period. A job scheduled "~every 10 minutes" should actually fire at irregular 7–14 minute gaps.
- **Bursts and quiet periods** — activity clusters (someone's actually working) interleaved with genuine silence, not constant background hum.
- **Time-of-day shape** — working-hours peak, overnight trough with a non-zero floor (automation runs overnight). Different time zones for different identity groups so there's overlap but not synchronization.
- **Irregular one-offs** — ad-hoc user actions (not on any schedule) injected at random, sized to be distinguishable from scripted activity.
- **Weekday/weekend variation** — weekends much quieter, service accounts keep running, human identities mostly silent.

Implementation: one shared scheduler process per identity/host pair that draws next-action intervals from distributions, not a pile of crontabs. Seeded for reproducibility (same seed → same shape, different seed → different legitimate variation).

### Attack-simulation surface

Attack scenarios run against the canary host (and sometimes a canary user). The set spans three signal categories — auth/metadata, execution, and data access — since the agent needs to reason across all three in real triage.

**Auth / metadata:**
- SSH brute force (external and lateral-from-jump-box variants) → rule-5710 territory.
- File integrity events (legitimate patching vs. unauthorized writes) → rule-550 territory.
- Credential use anomalies (stolen-looking SSH key usage at off-hours from unexpected source).
- Debug/maintenance traffic patterns that look like probing (already a known archetype).

**Execution:**
- Suspicious process lineage — web server spawning `bash`, cron service spawning a network-connecting child, `sshd` → `curl` → `chmod +x` → execute.
- Reverse-shell patterns — outbound TCP from an unusual process, interactive shell signals in network flows.
- Living-off-the-land — `curl`/`wget` fetching script content piped to `bash`, `base64 -d | sh`, python one-liners, `/dev/tcp` redirections.
- Persistence installation — new cron entries, systemd unit creation, `~/.ssh/authorized_keys` modification, shell rc-file tampering.
- In-memory / fileless indicators — short-lived processes with network+exec patterns that leave minimal filesystem trace.

**Data access:**
- Blob-store enumeration — large `ListObjects` from an office-user credential that normally only fetches specific known keys.
- Privilege boundary probes — attempted reads from `secrets/` by non-SRE credentials (should fail; the *attempt* is the signal).
- Staged exfiltration — slow `GetObject` spread over hours from a compromised office workstation, sized to look like normal fetches.
- Cross-credential anomaly — an SRE credential accessing `customer-data/` during off-hours from a residential IP.

**Staged multi-stage timeline** — alert fires mid-chain, earlier artifacts exist upstream if the agent looks for them. Chains should cross signal categories: e.g., phishing-looking email drop (not ingested, just implied) → office workstation auth → credential pivot → blob-store enumeration → exfil pattern. The alert may fire on step 3 or step 4; steps 1–2 are recoverable only by active investigation. This is the shape that exercises the hypothesize→gather loop end-to-end.

Attacks are parameterized so the same scenario can run with variations (different user, different timing, different volume) — that's the raw material for fixture capture.

## Telemetry stack

Elastic is the spine: detection, query, and case/ticket store. Additional sources bolt on around it.

### Tier 0 — required

| Source | Implementation | Notes |
|---|---|---|
| Detection/SIEM | Elasticsearch + Kibana (already in v1) | Detection rules authored per signature |
| Ticketing / cases | Elastic Cases or the existing `ticket-server` mock | One is load-bearing; need a decision (§Open questions) |
| Identity / auth | Keycloak (or Dex) + scripted logins | Provides OIDC events; mapping to fake users kept in CMDB |
| Endpoint | Elastic Defend or continued Falco | Process tree + file events; one per host |
| Auth/audit logs | Native sshd/sudo/systemd, shipped via Elastic Agent | Source of most triage signals |
| CMDB | Flat YAML + a thin HTTP API (stub service) | Query surface for asset context |
| Blob storage | **MinIO** | See §Blob storage — S3-compatible, real IAM + audit |

### Tier 1 — broadens triage coverage

| Source | Implementation | Notes |
|---|---|---|
| Network flow + DNS | Zeek on a span port / Packetbeat on each host | Enables lateral-movement, beaconing, DNS-exfil patterns |
| Proxy / egress | Squid with user attribution | Outbound HTTP with identity context |
| Threat intel | Local stub VT/OTX API | Hash/IP/domain reputation enrichment |
| Change management | YAML file + API stub | Turns "unauthorized change" into "authorized under CR-1234" |

### Tier 2 — archetype-specific, add when needed

| Source | When to add |
|---|---|
| Email gateway logs | Phishing archetypes |
| Vulnerability scanner feed | Exploit-related alerts needing CVE → host context |
| Cloud control plane | Only if we go to cloud deployment and want live CloudTrail |

### Blob storage

A standing data-at-rest host, S3-compatible. Primary purpose: give attack scenarios a realistic exfiltration target and give office workstations a plausible "sensitive data" access pattern to compare against.

**Choice: MinIO.** Rationale:

- S3-compatible API → same shape as real cloud blob access; same kinds of signals (access key + IP + user agent + requested key + response code).
- Real IAM-style bucket policies and user/group permissions, not a stubbed-out mock. Means permission-violation attacks have real ground truth.
- First-class **audit webhook** — structured per-request audit events shipped to an HTTP endpoint (Elastic Agent ingest pipeline in our case). This is the key capability: object-access audit that can be queried the same way as other telemetry.
- Self-hosted single-binary deployment. Fits the VPS footprint.

Alternatives considered:

- **SeaweedFS** — lighter but its audit story is weaker (access logs only, no structured webhook).
- **LocalStack S3** — better AWS fidelity but aimed at unit-test mocking; heavier operational weight as a standing service.
- **Native S3** — real, but couples the playground to AWS and defeats the bare-metal preference.

**Content layout.** Buckets seeded with markdown files representing a realistic corporate document set:

- `shared-docs/` — meeting notes, runbooks, design docs. Read-heavy, wide access.
- `customer-data/` — synthetic customer records. Read restricted to specific roles.
- `secrets/` — credential-shaped files (plausible but fake). Read restricted to SRE role; any access is high-signal.
- `backups/` — archive shape, large blobs. Write-once; any read from a non-backup-service account is anomalous.

Access patterns are documented per bucket in accompanying markdown (both for human reference and so the CMDB/environment KB can cite them). Patterns include: who normally reads from each bucket, what hours, which user agents, typical volume. This is the "normal" that peer-baselined detection compares against.

**Permissions and audit.** Bucket policies encoded in version-controlled JSON; changes to policies are themselves audit events (MinIO logs `PolicyUpdate` via the audit webhook). This lets us ground "who can access what" questions in real configuration, not vibes, and gives the chaos system a real object to corrupt (§Chaos model — stale-CMDB analog for bucket policies).

### What each host runs

Per host, roughly:
- Elastic Agent (auditbeat + filebeat + endpoint security integration)
- Falco (keeping v1 coverage where it's already useful)
- One baseline-activity generator (scheduled via cron)
- Role-specific service (web server, database, etc. — sized for the role, not for realism of the app)

The stack's footprint per host is non-trivial. Resource estimation for deployment-decision: v1 ran two endpoints on local compose; v2 runs six. Needs measurement before committing to local.

## Chaos model

**Core principle: v2 produces chaos at generation time; the eval harness mutates chaos at replay time.** They're the same conceptual framework (see `evaluation-and-chaos-design.md` §Mental model) applied at different stages.

### Why both surfaces

- **Playground-generated chaos** is what the agent encounters during development and fixture capture. It produces the *realistic* shape of degraded-observability failures — misconfigured parsers, partial outages, CMDB rot — that are hard to synthesize from scratch.
- **Replay-time chaos** is what the eval harness applies over captured fixtures for deterministic, reproducible scoring.

Playground chaos is not deterministic (live services, real clocks, real network). That's a feature, not a bug — it's how realistic degradation gets into the fixture corpus. Eval then takes over for byte-comparable grading.

### Day-one chaos modes

The v1 playground is uniformly healthy. v2 must be capable of the following from day one, as configurable modes rather than post-hoc hacks:

**Schema drift**
- Rename a field in a parser config (e.g., `source.ip` → `src_ip` in one ingest pipeline) for a subset of hosts or time windows.
- Change a data type (string → keyword, number → string) in one index template.
- Drop a field from a Filebeat module output.

Implementation: parameterized ingest-pipeline overlays applied via the Elasticsearch API at chaos start, reverted at chaos end. Tracked by a chaos profile.

**Data drops**
- Random per-event drop rate on a specific pipeline (e.g., drop 2% of auth events).
- Full drop of a data stream for a time window (simulates a broken agent or indexer pressure).
- Selective drop of events matching a pattern (simulates a misconfigured filter — the insidious case).

Implementation: a filter stage inserted in the ingest path, configured by the chaos profile.

**Stale CMDB**
- CMDB returns attributes that no longer match reality (host renamed, owner changed, criticality reclassified).
- CMDB has entries for hosts that don't exist (phantom assets).
- CMDB missing an entry for a host that does exist (silent gap — this is the common real-world failure).

Implementation: CMDB stub serves from a mutation overlay rather than the authoritative file, parameterized by chaos profile.

**Service outages**
- Elasticsearch slow/unresponsive for a time window (tests timeout handling).
- Fleet server down (new agents can't enroll; existing agents buffer).
- Ticketing API 5xx for a window.

Implementation: toxiproxy or equivalent between agent and target service, driven by chaos profile.

**Agent-side faults**
- One endpoint's Elastic Agent stops shipping for a window (silent coverage gap).
- Clock skew on one host (events land out of order).
- Parser fails on a specific log line shape (partial coverage loss).

### Chaos API

Chaos profiles are parameterized records that can be activated against a running playground:

```yaml
chaos_profile:
  id: auth-field-rename
  description: "src_ip renamed to source_ip in auth pipeline"
  # fault attributes per evaluation-and-chaos-design.md
  source_layer: L1
  observed_layer: L2
  announcement: silent
  content: wrong
  temporal: persistent
  scope: single-signature
  # activation
  activates_at: t+0
  duration: "30m"
  mutations:
    - type: ingest_pipeline_override
      target: logs-system.auth
      rename: {src_ip: source_ip}
```

Activating a profile is a single command against the playground control plane; deactivating reverts. Profiles compose (multiple active at once) but composition is opt-in and tracked.

### Reproducibility

Playground chaos is not byte-deterministic, but it is *replay-reproducible*:
- Every chaos profile has a seed.
- The profile plus the baseline activity schedule plus the attack scenario, together, reproduce the same *shape* of degraded telemetry across runs.
- Fixtures captured under a chaos profile carry the profile id in their metadata, so the eval harness can distinguish "baseline fixture" from "under-chaos fixture."

### Chaos concealment — keeping the fourth wall intact

**Problem:** if the investigating agent finds a `chaos.sh` script, an `/opt/chaos/` directory, a suspicious-looking process named `chaos-injector`, or log entries tagged `chaos_profile_id=...`, three things go wrong:

1. The fiction breaks — the agent learns it's in a playground, which invalidates any eval using human-analyst reasoning as ground truth.
2. Worse, the chaos artifacts masquerade as a **real threat signal** — a file called `chaos.sh` modifying log configs looks exactly like an insider threat or an attacker tampering with observability. The agent would correctly escalate on that, which scores as a *false positive against the intended ground truth*.
3. Worst, subtle chaos artifacts (an unknown process, an unexplained config change) can *steer* the investigation — the agent hypothesizes around the wrong cause and never reaches the intended conclusion.

**Design principles:**

1. **Control plane lives outside the telemetered surface.** Chaos is orchestrated from the VPS/docker host, not from inside any container the agent can investigate. The agent has no read path into the chaos controller.
2. **Mutations use realistic channels.** Schema drift goes through the Elasticsearch ingest-pipeline API (looks like any config change). Data drops go through a pipeline filter stage (looks like a throughput processor). CMDB rot goes through normal CMDB API writes with realistic timestamps and optional fake "change-request" metadata. Nothing introduces a new file, process, or config key whose name betrays its purpose.
3. **No self-labeling.** No artifact is named `chaos*`, `fault*`, `inject*`, etc. Chaos profile IDs live in the controller's own ledger, never in telemetry the agent queries.
4. **Chaos-event logs are segregated.** The controller writes its own activity to an index the agent's permissions don't include (or to a separate datastore entirely). The eval harness can cross-reference for scoring; the agent cannot.
5. **Artifacts must have mundane cover stories.** Each chaos mode should leave evidence consistent with ordinary environment decay:
   - Schema drift → looks like a deployed parser change or a misconfigured Filebeat module.
   - Data drop → looks like agent backpressure, indexer disk pressure, or a broken ingest filter.
   - Stale CMDB → looks like CMDB not being updated after a host rename (a well-known real pattern).
   - Service outage → looks like the service actually falling over.
   - Clock skew → looks like NTP drift on a misconfigured host.

The goal: if the agent ever correctly diagnoses a chaos condition, its conclusion should read like "the auth ingest pipeline has a field-rename mismatch — CMDB and indexer disagree on field name" — not "something called chaos is running." The first is useful signal; the second is broken fiction.

**Implementation mechanism.** A chaos controller service on the host (not in the response-network) exposes an API. It holds the mutation state and the revert procedures. Mutations are applied via the same APIs the environment normally uses (ES config API, CMDB write API, MinIO policy API, toxiproxy control). The controller is the only component that knows the word "chaos"; every downstream artifact is indistinguishable from organic environment behavior.

**Exception where realism requires traceability.** For eval scoring we need to know *when* chaos was active. This metadata lives in the eval-harness run bundle (outside the agent's surface), keyed by timestamp, not inside telemetry. The agent sees only the effects; the scorer sees both effects and ground-truth cause.

## Fixture capture

The playground's other job: produce the happy-path and chaos fixtures that the eval harness replays.

A capture run:
1. Pins clock, seeds, chaos profile (if any).
2. Runs a named attack scenario against a named target.
3. Records every tool call the agent would make — both the query and the response — keyed per the eval fixture schema (see `evaluation-and-chaos-design.md` §Fixture structure).
4. Packages the result as a fixture bundle.

This is the bridge between v2 (realistic generation) and the eval harness (deterministic scoring). Without it, the eval corpus has to be hand-authored forever.

## Phased build

Rough phasing; the goal is that every phase leaves v2 in a usable state.

- **Phase 0 — Footprint baseline.** Measure v1's resource use; estimate v2 per the populations above; deployment decision.
- **Phase 1 — Population expansion.** Add the additional hosts and identities; wire CMDB stub; no new telemetry yet. Goal: the agent visibly benefits from peer context on an existing signature.
- **Phase 2 — Baseline activity.** Add generators; tune until "normal" traffic exists in non-trivial volume. Goal: FP patterns start appearing organically against existing signatures.
- **Phase 3 — Telemetry Tier 1.** Add Zeek/DNS and proxy. Goal: lateral-movement and egress archetypes become tractable.
- **Phase 4 — Chaos control plane.** Chaos profile schema, activation tooling, the first three chaos modes (schema drift, data drop, stale CMDB). Goal: playground can run healthy or degraded on demand.
- **Phase 5 — Fixture-capture pipeline.** Record/replay tooling bridging v2 to the eval harness.
- **Phase 6 — Tier 2 telemetry + remaining chaos modes.** Threat intel, change management, outages, agent-side faults.

Each phase should end with the playground runnable end-to-end. No phase pile-up of infrastructure without observable behavior.

## Open questions

- **Ticketing authority** — Elastic Cases or the `ticket-server` stub? Elastic Cases is more realistic but couples the ticketing layer to the SIEM, which is the opposite of the abstraction we've cultivated in the plugin. Probably keep the stub for plugin-facing concerns and add Cases only if a specific archetype needs it.
- **Identity provider** — Keycloak is the most realistic option but adds operational weight. A simpler scripted-login approach (no real OIDC) may cover the needed signals at lower cost. Decide alongside the deployment call.
- **Baseline traffic volume** — too low and FPs don't form, too high and the stack bottlenecks. Needs measurement; start low and ramp.
- **Chaos profile catalog** — how many profiles do we want at Phase 4? Proposal: one profile per (fault attribute axis × signature family), seeded from known real-world failure modes. Small set (~10) covers 80% of what matters; grow as patterns emerge.
- **Shared vs. ephemeral instances** — if multiple developers eventually run against the same playground, chaos activation becomes a coordination problem. Defer until the second developer exists.
- **Real CloudTrail path** — if we later want SIR-Bench-style execution-based evaluation, deployment must allow AWS integration. Affects the deployment decision (local/VPS constrain this future).

## Decisions not yet locked in

Unlike the eval-and-chaos design, v2 has fewer pre-committed decisions — by design, since the deployment and scope questions are open.

| Question | Current leaning | Blocker |
|---|---|---|
| Deployment topology | Local if it fits, VPS otherwise | Awaiting footprint measurement |
| Ticketing | Keep stub; add Cases only if needed | None; revisit per archetype |
| Identity provider | Keycloak for realism | Resource cost vs. signal benefit |
| Chaos scope for v2.0 | Schema drift, data drops, stale CMDB from day one | None |
| Fixture capture mechanism | Record-at-tool-boundary (same shape as `wazuh_cli.py --replay`) | Needs integration design with eval harness |
