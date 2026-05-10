# `defender/skills/{system}/SKILL.md` — shape and boundary

Per-system SKILL.md files under `defender/skills/{system}/` are split
into two sections by audience:

- **Visibility surface** — read by the defender (gather routing,
  judge), the author skill (template scaffolding), and the
  actor-reviewer judge. Describes what the system *can* and *cannot*
  answer in this deployment, and how to read its output. Independent
  of how queries are dispatched.
- **Execution** — read only by code paths that dispatch queries
  (defender/gather, template authors). Adapter CLI shape, flag
  conventions, dispatch-time adapter quirks.

Keeping both sections in one file per system keeps per-system knowledge
in one place; keeping them as named sections (not separate files) keeps
the audience boundary explicit without inviting drift between two
parallel trees.

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

- Adapter CLI invocation pattern.
- Flag conventions and what they do at the dispatch layer.
- Output-format conventions imposed by the adapter (e.g., salted
  untrusted-data delimiters, raw payload persistence under
  `{run_dir}/gather_raw/`).
- Pointers to template authoring resources
  (`defender/skills/gather/queries/{system}/`).

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
