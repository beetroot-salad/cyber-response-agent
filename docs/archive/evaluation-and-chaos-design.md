# Agent Evaluation and Chaos Engineering — Design (archived)

> **Archived 2026-07-18. Superseded — do not treat as current guidance.**
> This designs a harness over the PREDECESSOR codebase, which the repo has since
> replaced with `defender/`. The run-dir shape it assumes (including `meta.json`,
> removed in #647) and the orchestrator it drives no longer exist; the live
> measurement layer is `defender/evals/`. Kept for the chaos-regime and metric
> reasoning, which is architecture-independent.

## Purpose

Design a harness that measures the SOC triage agent's quality and reliability in two regimes:

1. **Happy path** — does the agent reach the right disposition on a known corpus of alerts, with good trace, calibration, and precedent match?
2. **Chaos** — does the agent degrade gracefully when the world diverges from its model? Does it escalate and name the gap, or does it hallucinate?

Happy-path eval must come first because chaos tolerance is only definable as a *delta* from a known-good baseline. Both regimes share infrastructure; chaos is a transformation layer on top of the happy-path harness.

The hard constraint on the system is **zero false negatives** — it must never mark a real threat as resolved. Every design choice below is shaped by that constraint.

## Goals and non-goals

**Goals**
- Corpus-scale, deterministic, diffable evaluation of `/investigate` end-to-end.
- Score multiple dimensions (disposition, calibration, trace quality, evidence sufficiency, gap-naming under chaos), not just final label.
- Support fault injection across tool boundary and knowledge base.
- Reuse the existing plugin runtime — no shadow fork of the investigation loop.
- Designed for one developer; favor pragmatism over governance.

**Non-goals**
- Replace `test_e2e_live.py`. It stays as an integration smoke test — different purpose.
- Build a multi-SIEM abstraction. The playground is Wazuh-only and expected to stay that way.
- Model-family ablation as a product feature. We'll pin a model for reproducibility and bump it deliberately.
- Dashboarding / experiment-tracking UI. JSONL scorecards and diff tooling are enough for now.

## Mental model

The agent only produces a correct disposition when a stack of layers is mutually consistent and consistent with reality. A *fault* is a divergence between two of those layers — either because one drifted, was defective from birth, was mutated adversarially, or is silently absent.

### The layers

| Layer | Content |
|---|---|
| **L0 Reality** | What actually happened on the endpoint |
| **L1 Environment** | What the SIEM/infra currently knows about it |
| **L2 Tools** | What the CLI/MCP surfaces when queried |
| **L3 Knowledge base** | Signature KB, common KB, environment KB, precedents, alert metadata |
| **L4 Methodology** | Skill flow, state machine, hooks, permissions |
| **L5 Agent reasoning** | The LLM's within-run judgment |

L1 and L3 are *not decomposed* into sublayers. Decomposition was considered and rejected: the playground isn't large enough to justify the categorization overhead, and as a solo-dev project we can tolerate coarse labels, tagging sub-locations in a free-form field where needed.

### Fault as a multi-attribute record

A fault is *not* a single (source, observed) pair. Research on real SOC failures showed that forcing faults into one pair collapses distinctions that matter (e.g., a field rename is simultaneously L3↔L1 schema drift and L1↔L0 coverage loss). Model a fault as a record with the following attributes:

| Attribute | Values | Notes |
|---|---|---|
| `source_layer` | L0…L5 | Where the fault originates |
| `observed_layer` | L0…L5 | Where the agent would notice (if it could) |
| `announcement` | `loud` \| `silent` | Does the fault surface as an error, or masquerade as success? |
| `content` | `absent` \| `wrong` \| `partial` \| `adversarial` | Byzantine (wrong/partial) is categorically different from absent |
| `temporal` | `transient` \| `persistent` \| `intermittent` \| `drifting` \| `born-broken` | |
| `scope` | `single-lead` \| `single-run` \| `cross-run` \| `cross-signature` \| `corpus` | Blast radius |
| `observable` | `yes` \| `no` \| `side-channel-only` | Some faults are invisible to the agent by construction |
| `origin` | `drift` \| `defect` \| `adversarial` \| `cold-start` | Not every fault is drift |

The key insight for a zero-FN reasoning agent: **Byzantine content (plausible-looking wrong data) is the whole ballgame.** "Loud vs silent" alone doesn't capture it — silent-absent and silent-wrong require completely different mitigations.

### Known blind spots (acknowledged, not solved)

The framework cannot express:

- **Unobservable faults** — a broken YAML rule in Wazuh the agent never learns about. Must be caught by out-of-band monitoring, not this harness.
- **L4 spec↔implementation gaps** — bugs in the state machine or hooks. Outside the scope of agent-quality eval.
- **Feedback-loop pollution** — agent writes a bad precedent that poisons the next run. Needs a separate across-run test mode.
- **Compositional faults** — two benign drifts combining into an FN. Tractable if we enumerate; deferred.
- **Resource exhaustion** — MCP quota, LLM budget cap forcing premature CONCLUDE. Tracked separately as operational metrics, not scored as chaos.

## Evaluation framework

### Substrate: fixture replay, not live queries

Happy-path and chaos both run against **recorded environment fixtures**, not a live SIEM. Live queries are non-deterministic and drift over time; eval needs byte-comparable reruns. `test_e2e_live.py` keeps the live integration concern; eval is a separate substrate.

### Dimensions to grade (ordered by value)

For a zero-FN system, metrics are *not* fungible. A false negative on a real threat is catastrophic and must be tracked separately, not averaged into precision/recall.

1. **Disposition correctness** — final `status` and `disposition` match ground truth. Deterministic.
2. **Recall on true threats** — tracked as a separate, non-fungible metric. Any miss is a red-flag regression.
3. **Calibration** — did the agent escalate at the right confidence? ECE/Brier over `confidence × correctness`.
4. **Gap-naming score (chaos-specific)** — under a fault, does the report explicitly name what was missing or broken? This is the single most important chaos metric — it separates "escalated for the right reason" from "escalated because it gave up."
5. **Evidence sufficiency** — every claim in the report grounded in a captured tool output. Per-claim grading.
6. **Lead coverage** — required leads hit, forbidden leads avoided.
7. **Adversarial-hypothesis integrity** — did the agent maintain at least one threat hypothesis until explicitly refuted?
8. **Precedent match accuracy** — correct precedent chosen; rubric check that the match was semantically valid.
9. **Phase discipline** — no skipped phases, reasonable loop count. From `state.json`.
10. **Tool efficiency** — tool calls per resolution, wall-clock, cost. From `tool_audit.jsonl` and `budget.json`.

### Two-tier judging

The `validate_report.py` pattern (deterministic Tier 1 → LLM Tier 2) is the right shape and extends cleanly:

- **Tier 1 (deterministic)** — structural checks, required fields, claim-to-tool-output cross-reference, precedent-file existence.
- **Tier 2 (LLM rubric)** — reasoning quality, judge-graded dimensions (evidence sufficiency, adversarial-hypothesis integrity, gap-naming).
- **Model selection** — Haiku for narrow structural judgments, Sonnet/Opus for reasoning-quality judgments. Never self-preference: don't use the same model family that generated the report as the sole judge.
- **Bias mitigation** — rubric-anchored scoring (not free-form), reference-based wherever ground truth exists, delimiter-wrapped untrusted content (reuse the existing salt pattern from `validate_report.py`).

### Harness: Inspect (UK AISI)

The research recommended **Inspect** as the orchestration layer. Rationale:

- Subprocess-friendly solvers fit the existing `claude -p --plugin-dir ...` invocation in `conftest.py` — no runtime rewrite.
- Composable scorers let happy-path, calibration, and chaos grade the same run bundle.
- Trajectory representation is native; tool-call traces are first-class.
- Open-source, local-first, no SaaS lock-in.

Alternatives rejected: LangSmith (LangChain-coupled), Braintrust (SaaS, overkill pre-product), Promptfoo (single-turn bias), DeepEval/OpenAI Evals (not agentic).

We do **not** adopt Inspect's full ecosystem. We use it as a runner and scorer harness. Everything plugin-side stays in-repo.

## Technical architecture

### Tool intercept: wrapper CLI

Chaos and fixture replay both need to intercept at the tool boundary. Decision: **extend `wazuh_cli.py` with a replay mode.** Not an MCP shim, not LD_PRELOAD.

Rationale:
- Playground is Wazuh-only and expected to stay that way. A vendor-neutral abstraction would be speculative complexity.
- The CLI is the one component every lead already flows through.
- A `--replay <fixture-bundle>` flag reads query + time window + index from argv, looks up the canned response, optionally mutates it per the chaos profile, writes to stdout. Drop-in replacement for the live path.
- Unit-testable in isolation.

Fixture keys are `(query_template_name, parameters, time_window, index)`. Unmatched queries fail loudly rather than falling through to live — eval must be hermetic.

### Chaos injection points

Two injection points, layered:

**1. Tool-response mutation** — inside `wazuh_cli.py --replay`. Applies a chaos profile (from the fixture or the eval run config) to the canned response before writing it. Supports: drop fields, rename fields, truncate results, return empty, inject error exit code, return stale timestamps, add adversarial content.

**2. Knowledge-base mutation via hooks** — a chaos-mode `PreToolUse` (or equivalent) hook that intercepts Read calls on `knowledge/**` and mutates content before the agent sees it. Two variants:

- **Static overlay** — prebuilt mutated KB files in a run-specific overlay directory, selected by chaos profile. Deterministic, byte-diffable.
- **Dynamic Haiku rewrite** — pass the original content + a mutation directive ("rename field X to Y throughout", "contradict the precedent's disposition") to Haiku, return the mutated text. More flexible, less deterministic; needs a seed and cache to be reproducible across runs.

**Decision: start with static overlay, add dynamic Haiku rewrite once we've hit the limits of static.** Dynamic rewrites trade determinism for coverage; we want the deterministic baseline first so we have something to compare against.

Both variants hook *all* KB reads, not just `resolve_imports.py`. This matters because the agent can read KB files opportunistically mid-investigation (precedents, environment KB), and `resolve_imports.py` only bakes the load-time knowledge.

> **Note:** The exact hook mechanism for rewriting tool *results* (not just blocking or adding context) needs to be verified against Claude Code's hook API. If direct result rewriting isn't supported, the fallback is a filesystem overlay: the harness materializes a mutated KB tree in a temp dir and sets the run's working path to point at it. This is slightly less elegant but has the same observable effect and is definitely supported.

### Tool-output capture

Current `audit_tool_calls.py` logs `tool_input` but not `tool_result`. Evidence-sufficiency scoring cannot be deterministic without tool outputs. Add a new `PostToolUse` hook that appends `tool_result` to a `tool_results.jsonl`. Cheapest instrumentation win in the whole plan; do it first.

### Ground-truth representation

Ground truth is per-fixture, carried inside the fixture file. Not a separate labels database. The fixture is the single source of truth for a case.

### Artifact bundle per run

For each eval run, the harness collects:

- `alert.json`, `meta.json` — inputs
- `state.json`, `investigation.md`, `report.md`, `budget.json` — from agent
- `tool_audit.jsonl`, `tool_trace.jsonl`, `tool_results.jsonl` — from hooks
- `scorecard.json` — from the Inspect scorer, per-dimension scores + overall

The scorer consumes the bundle. Diffs across runs compare scorecards and structured fields (disposition, leads set, phase sequence), not raw markdown.

### Determinism controls

Pinned at the harness level, not per-fixture unless overridden:

- Model ID and temperature
- `now()` — injected into the alert and query time windows via fixture field
- `salt` — pinned per fixture so judge prompts diff byte-for-byte
- `run_id` — deterministic prefix so traces can be compared
- Random seeds for any Haiku-based mutation

## Fixture structure — buckets, not schema

The fixture format must serve both happy-path scoring and chaos injection from a single schema. Chaos fields are optional so happy-path fixtures don't carry dead weight, but the schema must be *capable* of carrying them from day one. Fork-now means two formats to maintain.

Fields group into nine buckets:

1. **Case identity** — id, version, provenance (real-ticket-redacted / synthetic / adversarial), audit status, difficulty, signature_id
2. **Alert input** — alert JSON, pinned `now` timestamp, any extra prompt instructions
3. **Tool-replay data** — canned responses keyed by `(query, parameters, time_window, index)`, per-entry latency/error knobs, composite-lead support, archetype anchor responses
4. **Knowledge references** — expected precedent/archetype match filename, distractor precedents (near-miss wrong answers), KB files in scope for chaos mutation
5. **Ground truth** — expected `status`, `disposition`, `confidence` band, required leads, forbidden leads, escalation reason category, (for chaos) expected "gap name" the agent should cite
6. **Rubric hints** — key claims that must be grounded, key contradictions to detect, plain-English description of correct reasoning for judge context
7. **Chaos profile (optional)** — fault record tuple (see mental model), injection timing (at start / after N tool calls / on specific query), which happy-path metrics become non-applicable under this fault
8. **Harness controls** — model pin, temperature, budget cap, timeout, allowed-tools override
9. **Determinism anchors** — pinned salt, pinned clock, pinned run_id prefix

Exact field names, types, and file format (YAML / JSON / Python dataclass) are a follow-up. This doc fixes the content, not the layout.

## Plumbing gaps to close

Ordered roughly by dependency:

1. **Tool-output capture hook** — `tool_results.jsonl`. Smallest, highest-leverage.
2. **Library-mode invocation** — extract `run_investigation_*` from `conftest.py` into a plain function so Inspect solvers can call it without pytest coupling.
3. **`wazuh_cli.py --replay` mode** — fixture-keyed SIEM replay with optional chaos mutations.
4. **Fixture schema** — the concrete file format implementing the nine buckets above.
5. **Ground-truth corpus seed** — start with the existing `wazuh-rule-5710` precedents; hand-audit each one before admitting it to the corpus.
6. **Chaos mutation layer** — tool-response mutations first (they live inside the replay CLI), then static KB overlay, then dynamic Haiku rewrite.
7. **Inspect scorer** — per-dimension scorers consuming the artifact bundle. Deterministic scorers first, judge-graded second.
8. **Batch runner** — iterate corpus, bounded concurrency, per-run + aggregate scorecard.
9. **Result differ** — scorecard-level diff across runs for regression detection.

## Decisions locked in

| Question | Decision | Notes |
|---|---|---|
| Tool intercept mechanism | Wrapper CLI (`wazuh_cli.py --replay`) | Wazuh-only playground; no multi-SIEM ambition |
| KB mutation mechanism | Hook-based intercept on all KB reads | Static overlay first, dynamic Haiku rewrite later |
| KB mutation scope | All knowledge reads, not just `resolve_imports.py` | Agent can read KB mid-run; must all be mutable |
| L1/L3 decomposition | Not decomposed | Environment too small to justify; tag sub-locations free-form if needed |
| Eval harness | Inspect (UK AISI) | Subprocess solvers, composable scorers |
| Fixture substrate | Recorded replay, not live SIEM | Determinism over realism |
| Ground truth storage | Inside the fixture file | No separate labels DB |
| Happy path vs chaos schema | Single schema, chaos fields optional | Avoid fork |

## Open questions remaining

- **Corpus policy** — held-out precedents or a separate synthetic corpus? Held-out tests "investigate from scratch"; retained tests "can it match." Both matter, they're different tests. Need a deliberate call before seeding.
- **Hook API capability** — can a `PreToolUse`/`PostToolUse` hook rewrite tool *results*, or only block and add context? If not, fall back to a filesystem overlay approach for KB mutation. Needs a quick spike.
- **Fault composition** — start with single-fault profiles; add combination profiles once the single case works. Compositional faults are where real FNs hide but they combinatorially explode, so they need the single case nailed first.
- **Across-run chaos** — feedback-loop pollution (agent writes a bad precedent that corrupts the next run) isn't in scope for v1. Track as a separate mode for later.
- **Cross-signature chaos** — same deferral.

## Phased build (sketch)

Rough phasing, not a committed plan:

- **Phase 0** — tool-output capture hook; library-mode invocation; one hand-audited fixture for `wazuh-rule-5710`. Goal: one run end-to-end through Inspect producing a scorecard.
- **Phase 1** — `wazuh_cli.py --replay`; fixture schema; 5-10 happy-path fixtures; deterministic scorers for dimensions 1/2/5/6/9/10.
- **Phase 2** — judge-graded scorers for dimensions 3/4/7/8; two-tier judge harness parallel to `validate_report.py`.
- **Phase 3** — chaos profiles: tool-response mutations first (drop field, rename field, truncate, empty, error). Gap-naming scorer. Single-fault only.
- **Phase 4** — KB static overlay mutations. First cross-layer chaos cases.
- **Phase 5** — dynamic Haiku KB rewrite; compositional faults; cross-run/feedback-loop mode.

Each phase should end with a runnable scorecard on a real corpus. No phase is allowed to pile up infrastructure without a demonstrable eval result.
