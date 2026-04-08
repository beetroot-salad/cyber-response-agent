# Hypothesis Catalog → Primitives, Archetypes, Trust Anchors

**Status:** Proposed
**Date:** 2026-04-08
**Companion to:** `design-v3-architecture.md` (which this proposes refining)

---

## TL;DR

The current "hypothesis catalog" in signature playbooks conflates three
distinct concepts: **observable primitives**, **outcome archetypes**, and
**legitimacy attribution**. This conflation makes the catalog impossible to
discriminate at investigation time, forces over-escalation, and duplicates
information that already lives elsewhere in the system.

The proposed redesign is a three-layer separation:

1. **Hypothesis catalog → Investigation primitives.** Small set of
   orthogonal modalities that are directly queryable from telemetry.
2. **Archetype catalog → Precedents.** Story-shaped patterns rooted in real
   tickets, used by the screen phase for fast-path matching and by CONCLUDE
   for disposition assignment. Already partially implemented; needs
   recognition as the canonical archetype layer.
3. **Trust anchors → New knowledge layer.** Org sources of truth (approved
   PRs, change windows, support tickets, on-call schedules) consulted to
   confirm whether a *specific instance* of a known archetype is sanctioned.

The investigation flow becomes: gather primitive evidence → match against
precedent/archetype → check trust anchor for sanction → assign disposition.

This is consistent with the existing skill design (the screen phase, the
ticket-context subagent, the precedent schema all already point in this
direction). The lagging artifacts are the signature `context.md` /
`playbook.md` files and the architecture doc's definition of "hypothesis."

---

## 1. Current state

### 1.1 What "hypothesis" means today

`design-v3-architecture.md §1.1` defines:

> **Hypothesis** — A candidate explanation for the alert. Can be simple
> (`"monitoring probe"`) or a causal chain. Each hypothesis predicts what
> evidence should and should not exist...

The given examples (`?monitoring-probe`, `?brute-force`,
`?credential-stuffing`, `?service-account-rotation`) are all
**story-shaped**: each combines an actor type, an intent, a behaviour
modality, and (implicitly) a context.

In practice this is how every signature's hypothesis catalog has been
written:

| Signature | Hypotheses |
|---|---|
| wazuh-rule-5710 (SSH invalid user) | `?monitoring-probe`, `?brute-force`, `?credential-stuffing`, `?service-account-rotation` |
| wazuh-rule-550 (FIM checksum changed) | `?package-management`, `?automatic-patching`, `?config-management`, `?interactive-admin`, `?adversary-persistence`, `?adversary-tampering` |
| wazuh-rule-100001 (Falco terminal shell) | `?operator-debug`, `?ci-cd-pipeline`, `?image-startup`, `?healthcheck-or-probe`, `?adversary-post-exploit` |
| wazuh-rule-100110 (DNS high-entropy subdomain) | `?cdn-or-cloud-service`, `?analytics-or-tracking`, `?dga-malware`, `?dns-tunneling` |

### 1.2 What `precedents/` looks like today

Precedents are JSON files written as ticket replays (`brute-force-001.json`,
`monitoring-probe-001.json`). They have:

- A `hypotheses` array recording which catalog entries were confirmed/refuted
- A `flow` array recording the actual investigation steps taken
- A `reasoning.conditions` and `reasoning.refutes` block with generalization
  hooks
- A `key_indicators` array

The schema *already* supports generalization via `conditions` and
`key_indicators`. But the convention so far has been "freeze the
investigation that resolved this specific ticket" rather than "author a
generalizable archetype anchored to this ticket."

### 1.3 What the screen phase already does

`skills/investigate/SKILL.md` (and `screen.md`) describes a SCREEN subagent
that runs before the full investigation loop. It pattern-matches the alert
against playbook-defined screen patterns and short-circuits to disposition
on a match. This is **already an archetype-matching mechanism** — it just
operates against a separate "screen patterns" table in `playbook.md` rather
than against precedents directly.

---

## 2. The problem

### 2.1 Stories overlap on observable primitives

Empirical evidence from worker-mode validation (Haiku agents acting as
investigators on synthetic alerts, given only the new signature knowledge):

- **Falco terminal shell:** `?operator-debug` and `?ci-cd-pipeline` share
  every primitive — both have parent ∈ runtime exec primitives, both happen
  on irregular schedules. They differ only in *who pushed the button*. The
  worker noted: "I cannot distinguish these from the playbook text alone."
- **Falco terminal shell:** `?image-startup` and `?healthcheck-or-probe`
  similarly differ only in cadence. Without a baseline query mechanism the
  worker had no way to use the discriminator.
- **DNS:** `?dga-malware` and `?dns-tunneling` ended with identical
  assessment patterns across all leads. The playbook had no tiebreaker.
- **FIM:** `?adversary-persistence` and `?adversary-tampering` were not
  meaningfully discriminated by any of the four leads — the worker lumped
  them together.

The pattern is consistent. **When two hypotheses share the same
primitives, no lead can discriminate them, and the agent over-escalates.**

### 2.2 The conflation breakdown

Each story-shaped hypothesis fuses three layers of information:

1. **Primitive layer:** what does the telemetry actually show? (interactive
   shell? in-container vs runtime-exec spawn? high-entropy subdomain under
   a known parent? package-owned file modified at root ownership?)
2. **Archetype layer:** what familiar narrative explains this primitive
   pattern? ("operator debugging at 3am", "CI pipeline run", "automated
   patching at the patch window", "DGA probing for C2")
3. **Sanction layer:** for *this specific instance*, is the activity
   actually approved? (was there a ticketed change? does it correlate with
   a deploy run? is the operator on-call?)

The current hypothesis catalog tries to do all three in one shape. But:

- Primitives are *observable* and *enumerable* — there are only so many
  shapes a Falco shell event can take.
- Archetypes are *unbounded* and *contextual* — every org has its own set
  of "things that look like this happen here."
- Sanction is *per-instance* and *unobservable from the SIEM alone* — it
  requires querying org systems outside the telemetry pipeline.

Mixing them produces a catalog that is simultaneously too small (it can't
enumerate every story) and too redundant (multiple stories share primitives
and can't be discriminated).

### 2.3 Why this leads to over-escalation

When two hypotheses are indistinguishable by available leads, the
investigation loop has no way to refute one and confirm the other. The
auto-close criteria require "exactly one hypothesis remains with `++`
support" — which can never be reached. The agent escalates by default.

This is the *correct* failure mode (escalation is safe), but it means we
will *always* escalate the boundary cases. The screen phase was designed
to handle these via fast-path matching, but it operates on a separate
"screen patterns" table that has to be authored independently. There's no
single source of truth for "what archetypes exist for this signature."

### 2.4 No legitimacy anchoring

Even when the primitive pattern is clear and the archetype is recognized,
the playbooks try to derive legitimacy from telemetry alone:

- "Looks like a CDN" → benign?
- "Looks like an admin edit" → benign?
- "Parent is the container init binary" → benign?

But telemetry tells us *what happened*, not whether it's *sanctioned*. A
CDN-shaped query *could* be benign, or it could be a domain-fronted C2. An
admin-shaped sshd_config edit *could* be a real admin, or an attacker
mimicking one.

Sanction lives in **org sources of truth** that the SIEM doesn't see:

- Approved pull requests / merged changes
- Ticketed change windows and maintenance approvals
- Support requests linking activity to a user-driven cause
- On-call schedules naming who has the right to be touching production
- Deploy logs / CI run history
- Vulnerability advisory dates that justify out-of-band patching

The current playbooks have no concept of these. Every "looks benign"
assessment is a guess, with no mechanism to confirm it against an external
truth source.

---

## 3. Proposed redesign

### 3.1 Three layers, three jobs

```
┌─────────────────────────────────────────────────────────────────┐
│  TELEMETRY                                                       │
│    │                                                             │
│    ▼                                                             │
│  PRIMITIVE LAYER          ←  hypothesis catalog (rewritten)      │
│    "what does this        ←  small, orthogonal, queryable        │
│     event look like?"                                            │
│    │                                                             │
│    ▼                                                             │
│  ARCHETYPE LAYER          ←  precedents/ (recognized as the      │
│    "what story explains      canonical archetype catalog)        │
│     this pattern?"        ←  ticket-rooted, generalizable        │
│    │                                                             │
│    ▼                                                             │
│  TRUST ANCHOR LAYER       ←  new knowledge layer                 │
│    "is this specific      ←  org sources of truth, queried       │
│     instance sanctioned?"    outside the SIEM                    │
│    │                                                             │
│    ▼                                                             │
│  DISPOSITION                                                     │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Layer 1: Primitives (rewritten hypothesis catalog)

**Definition:** observable, orthogonal modalities that the telemetry
directly answers.

**Properties:**
- Small set per signature (typically 3-6)
- Each is directly queryable from the alert + one or two follow-up queries
- Independent — two primitives can both be true simultaneously
- Stable across orgs — primitives are properties of the *signature*, not
  the *deployment*

**Example for wazuh-rule-100001 (Falco terminal shell):**

| Primitive | What it asks | How to determine |
|---|---|---|
| `*runtime-exec-spawn` | Was the shell spawned by a runtime exec primitive? | `proc.pname ∈ {runc, containerd-shim, docker-exec, crio}` |
| `*in-container-spawn` | Was the shell spawned from inside the container's process tree? | `proc.pname` is an in-container process (and not a runtime exec primitive) |
| `*interactive-modality` | Does the shell have interactive characteristics? | `proc.tty != 0`, `cmdline` contains `-i`, or stdin/stdout to a socket fd |
| `*at-container-start` | Did this happen near container creation? | `evt.time` within N seconds of `container.start_time` |
| `*recurring-cadence` | Does this match a periodic pattern? | Other 100001 events from same `container.id` at strict intervals |

These primitives are orthogonal — `*runtime-exec-spawn` + `*recurring-cadence`
indicates a healthcheck pattern without naming it as such. The investigation
doesn't need to *call it* a healthcheck to gather the right evidence.

**Example for wazuh-rule-5710 (SSH invalid user):**

| Primitive | What it asks |
|---|---|
| `*external-source` | Is the source IP RFC1918 or external? |
| `*high-volume` | More than N attempts from this src in M minutes? |
| `*username-diversity` | One username, or many? |
| `*username-pattern` | Wordlist? Service account? Monitoring probe? Real-looking? |
| `*successful-followup` | Was there a successful login from this source shortly after? |

The catalog is the same shape across signatures: "what does the telemetry
directly tell us, without intent attribution?"

**Notation:** prefix with `*` to distinguish from the old `?` story
hypotheses during the migration. Final notation TBD.

### 3.3 Layer 2: Archetypes (precedents/, recognized)

**Definition:** named patterns of primitives that explain a class of real
tickets, anchored to one or more precedent files.

**Properties:**
- Author primitives → archetype mapping deliberately, not by freezing one
  ticket's investigation
- One archetype can have multiple precedents (different orgs, slightly
  different conditions)
- One precedent contributes to one archetype (multiple precedents per
  archetype is the steady state)
- Archetypes are *ranked* — common archetypes get matched first
- The screen phase matches against the archetype catalog directly; there
  is no separate "screen patterns" table

**Example archetypes for wazuh-rule-100001:**

| Archetype | Primitive pattern | Precedent(s) |
|---|---|---|
| operator-runtime-debug | `*runtime-exec-spawn` + interactive cmdline + irregular timing | `precedents/operator-debug-*.json` |
| ci-pipeline-exec | `*runtime-exec-spawn` + non-interactive cmdline + regular cadence + match deploy schedule | `precedents/ci-exec-*.json` |
| k8s-exec-probe | `*runtime-exec-spawn` + `*recurring-cadence` + identical cmdline | `precedents/probe-*.json` |
| in-container-init-script | `*in-container-spawn` + `*at-container-start` | `precedents/init-script-*.json` |
| app-spawned-shell | `*in-container-spawn` + parent is application binary | `precedents/app-shell-*.json` |
| post-exploit-interactive | `*in-container-spawn` + `*interactive-modality` + parent is application binary + no matching benign archetype | `precedents/post-exploit-*.json` |

Note that several archetypes share `*runtime-exec-spawn` — they're
distinguished by additional primitives, not by a different first-layer
hypothesis.

**Schema changes to precedent.py:**

The current schema is mostly compatible. Additions needed:

- `archetype` (mandatory): the archetype name this precedent contributes to
- `primitive_pattern` (mandatory): the boolean expression over primitives
  that this precedent fingerprints (e.g., `*runtime-exec-spawn AND NOT *recurring-cadence`)
- `trust_anchor_required` (optional): the trust anchor source that must
  confirm sanction for this archetype to resolve as benign
- `hypotheses` field can be deprecated or repurposed to list the primitives
  observed, replacing the old story-name list

### 3.4 Layer 3: Trust anchors (new knowledge layer)

**Definition:** org sources of truth that confirm whether a specific
instance of an archetype is sanctioned.

**Properties:**
- Live outside the SIEM
- Queried via integration (API, MCP, scraping a wiki, etc.)
- Each anchor source covers one or more archetypes
- An archetype that requires trust-anchor confirmation cannot resolve to
  `benign` without a positive anchor result

**Proposed location:** `soc-agent/knowledge/environment/trust-anchors/`

**Proposed entries (org-specific, populated incrementally):**

| File | Anchor type | Confirms |
|---|---|---|
| `change-windows.md` | Approved maintenance windows | Patches, package upgrades, sshd_config edits |
| `deploy-runs.md` | CI/CD run history | CI exec into containers, image rollouts |
| `pull-requests.md` | Merged PRs in infra repos | Config-management changes, ansible/puppet runs |
| `oncall-schedule.md` | Who has prod-touch authority right now | Operator-debug archetypes |
| `support-tickets.md` | Open user-facing tickets | User-driven activity that mimics adversary patterns |
| `cdn-allowlist.md` | Known CDN/cloud parent domains | DNS archetypes |

**Schema for trust anchor file:**

```markdown
---
anchor_type: change-window
provides_confirmation_for: [package-management, automatic-patching, sshd_config-edit]
query_method: api
---

# Change Windows

How to query approved change windows.

## Source

[ServiceNow / Jira Change / wherever]

## Query

`MCP: change_mgmt.list_active_windows(start, end, target_host)`

## Output shape

[...]

## Falsification

If the query returns no active window for the alert's time + target, the
archetype that depends on this anchor cannot resolve as benign — escalate.
```

### 3.5 Investigation flow under the new model

```
CONTEXTUALIZE
  ├── load alert + signature primitives + archetype catalog (precedents)
  ├── ticket-context subagent runs (recent/related alerts)
  └── (no change to existing flow)

SCREEN  ← rewritten
  ├── extract observable primitives from the alert (cheap, deterministic)
  ├── match primitive pattern against archetype catalog
  ├── if exactly one archetype matches:
  │     ├── check trust anchor (if required by archetype)
  │     ├── if anchor confirms → resolve:benign
  │     ├── if anchor refutes  → escalate:potential-mimicry
  │     └── if anchor unknown  → fall through to full loop
  └── if zero or multiple archetypes match → fall through to full loop

HYPOTHESIZE  ← rewritten meaning
  ├── primitives are the hypotheses now
  ├── select leads that resolve uncertain primitives
  └── adversarial requirement: maintain at least one primitive pattern
      that would indicate compromise until refuted

GATHER → ANALYZE → (loop or CONCLUDE)  ← unchanged shape

CONCLUDE  ← rewritten
  ├── primitive pattern is now fully resolved
  ├── re-match against archetype catalog with confirmed primitives
  ├── if matched → check trust anchor → disposition
  └── if no archetype matches → escalate as novel pattern
```

The key shift: archetype matching happens at *two* points (SCREEN for
fast-path, CONCLUDE for full-loop resolution). Both consult the same
precedent-rooted archetype catalog.

---

## 4. Motivation, restated

### 4.1 What this fixes

- **No more indistinguishable story hypotheses.** Primitives are
  orthogonal by construction. Two archetypes can share primitives, but
  archetype matching happens against a labeled catalog, not by
  discrimination during investigation.
- **No more guessing legitimacy from telemetry.** Trust anchors put the
  legitimacy decision where it belongs — in org sources of truth — and
  refuse to mark an alert benign without anchor confirmation.
- **Single source of truth for archetypes.** Precedents are already meant
  to be curated patterns; this proposal makes them the *only* archetype
  catalog and removes the parallel "screen patterns" table.
- **Worker-mode validation becomes meaningful.** Today, worker agents fail
  on every signature because the hypothesis catalog has indistinguishable
  entries. With primitives, workers can actually resolve the primitive
  layer; archetype matching is a separate cheap step that can be
  evaluated in isolation.

### 4.2 What this aligns with

- **Existing skill design.** SCREEN, ticket-context subagent, precedent
  schema, and the 4-layer environment knowledge model all already point
  in this direction. The redesign closes the gap between the skill
  architecture and the knowledge files.
- **The "trust anchor" intuition behind known FPs.** The architecture doc
  already says "Known FPs are abstractions derived from precedents" —
  this makes that explicit and gives the abstractions a structural home.

### 4.3 What this costs

- **All four current signatures need their playbooks rewritten.**
- **Precedent schema needs a small extension** (`archetype`,
  `primitive_pattern`, `trust_anchor_required`).
- **The architecture doc needs an update** (definition of "hypothesis"
  changes; SCREEN and CONCLUDE phases get a clearer relationship to the
  archetype layer).
- **A new knowledge layer** (`environment/trust-anchors/`) needs to be
  scaffolded — initially empty, populated as archetypes are added.
- **Worker-mode validation needs to be re-run** against the new
  structure to confirm the redesign actually fixes the discrimination
  problem.

---

## 5. Open questions

1. **Notation.** `?story` vs `*primitive` is a placeholder. Final
   prefix/naming TBD.
2. **Primitive enumeration: who and how?** Authoring orthogonal primitives
   is harder than authoring stories — there's a "what's the right set"
   question per signature. We need a worked example for one signature
   (probably Falco) before propagating.
3. **Archetype matching algorithm.** Boolean expression match? Indicator
   scoring? The schema needs to support whatever the SCREEN subagent can
   evaluate cheaply.
4. **Trust anchor failure modes.** What happens when a trust anchor query
   times out, returns ambiguous results, or the integration is broken?
   Default: escalate. But this needs to be explicit in the schema.
5. **Migration path for `wazuh-rule-5710`.** The existing signature has
   precedents written in the old shape. Do we re-author them, deprecate
   them, or migrate them in-place?
6. **Backwards compat with the report schema.** Reports currently
   reference hypothesis names. Does the new model require a report schema
   change, or can primitives + archetype name fit the existing fields?
7. **Where does an archetype's `primitive_pattern` live — in the precedent
   file or in a separate archetype index?** Trade-off: putting it in
   precedents is simple but means N precedents for one archetype have to
   stay in sync; a separate index is cleaner but adds another file type.

---

## 6. Migration sketch

**Phase 1 — Pilot (one signature, end-to-end):**
1. Pick `wazuh-rule-100001` (Falco terminal shell). It has the worst
   discrimination problem and is the most concrete.
2. Author the primitive set in the new shape.
3. Convert the existing hypothesis catalog stories into archetype entries.
4. Write 2-3 precedents in the new shape.
5. Scaffold one or two trust anchor files (e.g., `oncall-schedule.md`,
   `deploy-runs.md`) — content can be placeholder.
6. Re-run worker-mode validation. Expected outcome: workers either match
   an archetype cleanly or escalate with a clear "no archetype matched"
   reason.

**Phase 2 — Architecture doc + schema:**
1. Update `design-v3-architecture.md §1.1` to redefine "hypothesis" as
   primitive-shaped, and add the archetype/anchor layers.
2. Extend `schemas/precedent.py` with the new fields.
3. Update the precedent template under `_template/`.
4. Update the playbook template.

**Phase 3 — Propagate:**
1. Rewrite the other three signatures (`wazuh-rule-5710`, `wazuh-rule-550`,
   `wazuh-rule-100110`).
2. Run worker-mode validation per signature.
3. Decide whether to deprecate or migrate the old `wazuh-rule-5710`
   precedents.

**Phase 4 — Trust anchors:**
1. Identify which trust anchors the playground actually has access to
   (probably none initially — they're org-specific).
2. Stub anchor files with documented query mechanisms.
3. Mark archetypes that require unavailable anchors as "always escalate"
   until the anchor is wired up.

---

## 7. What this doc deliberately does NOT decide

- The exact primitive set for any signature beyond the Falco example
- The notation prefix for primitives (`*`, `:`, no prefix, etc.)
- Whether `screen.md` survives as a separate file or merges into the loop
- The exact precedent schema diff
- Whether the existing `wazuh-rule-5710` precedents are kept

These are meant to be decided in the pilot pass on Falco, with the worked
example informing the rest.

---

## 8. Pointers to the conversation that produced this

- Worker-mode validation results that surfaced the discrimination problem:
  evident in the prior PR's review thread on `wazuh-rule-100001`. Three
  Haiku worker agents independently failed to discriminate the
  `?operator-debug` / `?ci-cd-pipeline` / `?image-startup` /
  `?healthcheck-or-probe` cluster.
- Reviewer comment on `playbook.md:12` explicitly identified the
  primitive-vs-story conflation and pointed at precedents as the natural
  archetype home.
- This doc was written before any code changes so the rewrite can pick up
  in a fresh context window.
