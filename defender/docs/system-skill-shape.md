# `defender/skills/{system}/SKILL.md` — shape and boundary

Per-system knowledge under `defender/skills/{system}/` is split into
two surfaces by audience, across two files:

- **Visibility surface** — `SKILL.md`. Read by the orchestrating
  defender (gather routing, judge), the author skill (template
  scaffolding), and the actor-reviewer judge. Describes what the system
  *can* and *cannot* answer in this deployment, and how to read its
  output. Independent of how queries are dispatched.
- **Execution** — `execution.md`, a sibling file read **only** by the
  gather subagent when it dispatches a query. The `query` tool's verb
  surface, params, connectivity, exit codes, dispatch-time adapter quirks.
  `SKILL.md` keeps a one-line `## Execution` pointer to it.

The two files exist so the orchestrator — which loads `SKILL.md` to
**route** to a system but never queries it — physically cannot ingest
the execution surface. That boundary is load-bearing for data sources
with credentials or connectivity detail (e.g. elastic): a one-file
"named sections" layout leaked the adapter's credential/tunnel
variables into the orchestrator's context, where it groped for them
instead of dispatching gather (issue #261). Splitting the file removes
the trigger structurally rather than with a "don't read this" note.

(Some stub systems still carry their Execution section inline in
`SKILL.md`; they hold no secrets, so the leak doesn't apply. New
systems and any system with real credentials use the `execution.md`
split.)

## Visibility surface — four fields

Each system's Visibility surface section uses the same four fields:

- **available_queries** — the templates / subcommands this system
  answers, with a one-line description of the measurement each
  contract delivers. Source-of-truth for "is this query dispatchable
  as-is?"
- **gaps** — declared "this system cannot answer X here." Critical for
  distinguishing *we did not ask* from *we cannot ask*. Includes
  enrollment limits, schema absences, and known silent-failure modes.
- **read_guidance** — how to interpret results. Pitfalls, aggregation
  semantics, type-mismatch behaviors. Adapter-specific output
  conventions (e.g., salted delimiter wrapping) belong under
  Execution, not here — those are properties of dispatch, not of the
  system's answers.
- **when_to_use** / **when_not_to_use** — scoping. When this system is
  the right reach, when another in this directory is better.

## Execution — what belongs here

- The `query` tool's verb surface — which verbs the system's `VERBS`
  registry exposes.
- What each declared param binds and does at the dispatch layer.
- Output-format conventions imposed by the adapter (e.g., salted
  untrusted-data delimiters, raw payload persistence under
  `{run_dir}/gather_raw/`).
- Pointers to template authoring resources
  (`defender/skills/gather/queries/{system}/`).
- For a **filter-only** source (one with no server-side aggregation),
  the concrete `defender-sql`-over-payload aggregation recipe for the
  adapter's row shape — the path into the payload's rows (e.g. `hits` for
  an elastic query, the top-level list for a `list-*` verb) and the columns
  to group on. This is a dispatch-time property of driving the adapter,
  not a fact about the system's answers, so it lives here rather than in
  `read_guidance`. A source with a native aggregating query language
  needs no such recipe.

If a fact is true regardless of the adapter (e.g., "Wazuh only indexes
events from enrolled agents"), it belongs under Visibility surface, not
here.

## Boundary — v4 vs the future cache loop

The Visibility surface holds anything a human writes fresh after
deploying a new system:

- Which queries the system answers
- Declared gaps (what the system cannot answer here, including
  enrollment limits)
- How to read results (pitfalls, silent-failure modes, output
  conventions)
- When to use this system vs another in the env

It deliberately does not hold:

- Classification heuristics ("172.0.0.10 is a monitoring host") —
  derivable from the investigation corpus, belongs to a future
  self-learning cache loop.
- Trust anchors ("INC-8821 is a real ticket") — answered by querying
  the relevant system, which is itself a `{system}/` entry once an
  adapter ships for it.
- Active-control claims ("all images are cosign-signed at admission")
  — cached past resolutions, surfaces in the cache loop.
- Org-level accepted residuals — currently rolled into per-system
  `gaps`; split out only if cross-system residuals accumulate.

Test for whether a fact belongs in v4: would we know it immediately on
deploying a new system? Yes → v4 (Visibility surface or Execution).
Only after the corpus catches up → cache loop, not here.

## Consumers

- **Actor-reviewer judge**: reads the Visibility surface across all
  systems to route findings. A breaking-evidence query that names a
  template listed under `available_queries` is dispatchable. One that
  targets an entity listed under `gaps` is an observability finding,
  not a playbook gap. One that needs a system not described here at
  all is a tooling-gap finding (deployable in principle but no MCP /
  adapter exists yet).
- **Defender / gather**: cross-system scoping during PREDICT. When a
  measurement contract has multiple plausible source systems, the
  `when_to_use` fields disambiguate. At dispatch, gather reads the
  Execution section.
- **Author skill**: reads the Visibility surface when scaffolding new
  templates — `gaps` defines what cannot be expressed, `available_queries`
  shows the existing coverage to extend, `when_to_use` informs system
  selection for a new measurement contract.
