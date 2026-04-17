# Investigation Language (invlang)

The structured companion schema the agent writes alongside its narrative during an investigation. Each YAML block co-located in `investigation.md` encodes the phase's reasoning as a typed graph — vertices, edges, hypotheses, leads, resolutions — that a PreToolUse hook validates on every write.

This file is a handbook-level orientation. The **authoritative schema reference** is `knowledge/invlang/schema.md` (resolved inline into the investigate skill at load time via a `!command`). Read that for field-level detail; read this page to understand what role invlang plays in the plugin and why it exists.

## Why invlang

A natural-language investigation log is hard for code to check. "The hypothesis was refuted" reads fine to a human but a validator cannot tell *which* hypothesis, *by which* evidence, with *what* authority. invlang captures the same reasoning in a typed graph so the plugin can check structural invariants that would otherwise depend on LLM self-assessment:

- Every `--` resolution cites evidence of sufficient authority.
- Every lead with hypotheses under test declares which ones, with matching prediction or refutation IDs.
- Trust-anchor results are complete (all five fields present) and temporally dated.
- `++` requires full prediction coverage — partial coverage caps at `+`.
- Companion blocks are append-only — the agent cannot retroactively rewrite a prior lead's outcome.

The narrative log remains agent-owned; the companion blocks give the plugin a machine-checkable record alongside it.

## How it composes with the rest of the plugin

| Phase | Companion block written | When | Notes |
|---|---|---|---|
| CONTEXTUALIZE | `prologue:` | end of phase | vertices + edges derived from alert entities |
| SCREEN | first `gather:` lead with `mode: screen` | after screen subagent returns | `screen_result: match | no_match` on the final screen lead; SCREEN-matched companions omit `hypothesize` |
| HYPOTHESIZE | `hypothesize:` | end of phase | initial proposed frontier of hypotheses |
| GATHER | *(no YAML block)* | narrative only | the lead block is written at ANALYZE |
| ANALYZE | complete `gather:` lead (outcome + resolutions) | end of phase | one entry per lead; entries in the same cycle share `loop:` |
| CONCLUDE | `conclude:` | after `conclusion_checks.json`, before `report.md` | `termination`, `disposition`, `confidence`, `matched_archetype` |

The schema is **graph-first** (Schema v2.7 as of this writing):

- **Entities as vertices** — endpoint, process, session, identity, storage, command, etc. Every observed entity becomes a typed vertex.
- **Relations as edges** — `spawned`, `authenticated_as`, `connected_to`, and so on, each carrying `authority` describing how reliably the source recorded it.
- **Hypotheses as proposed edges** — a hypothesis proposes exactly one upstream vertex connected to a confirmed vertex by exactly one edge. Predictions test the *proposed vertex's existence*, not alert data already in hand.
- **Leads as graph operations** — topology-extending (new vertices or edges in `outcome.observations`), attribute-refining (`attribute_updates` on existing vertices), or both. `tests` declares which hypotheses the lead discriminates; absence signals a non-branching lead that may still carry lead-level `predictions` (pre-committed conditional branch plans).

Field vocabulary (vertex types, relation catalog, authority kinds, termination categories) lives in `knowledge/invlang/schema.md`.

## Validation — `invlang_validate.py`

Registered as a **PreToolUse** hook on `Write|Edit` to `investigation.md` in `plugin.json`. Fires on every proposed write, extracts the YAML companion blocks, and runs a set of structural checks. On failure it prints errors to stderr and exits 2 — the write is blocked before it lands on disk, `state.json` never advances, and the agent's next action is to rewrite the block.

### Error checks (block the write)

From `hooks/scripts/invlang_validate.py::validate_companion`:

1. **YAML parses.** Each extracted block must parse via `yaml.safe_load`.
2. **Append-only.** The proposed text must not shrink an existing companion block. Removing or mutating a prior record is rejected. Decomposition is done by appending sub-vertices with hierarchical IDs (`v-{parent}-{nonce}`); attribute changes go through new `attribute_updates`.
3. **Lead required fields.** Every entry under `gather:` has `id`, `loop`, `name`, `target`, `query_details`, `outcome`.
4. **ID format.** Vertices match `v-…`, edges `e-…`, hypotheses `h-…`, leads `l-…`, predictions `p\d+`, lead-level predictions `lp\d+`, refutations `r\d+`.
5. **ID references resolve.** Every cross-reference (e.g. `resolutions[].hypothesis`, `supporting_edges`, `tests`, `observes[].hypothesis`) names a declared ID.
6. **Edge authority.** Every `++` or `--` resolution must cite at least one `supporting_edge` whose authority kind is `siem-event`, `runtime-audit`, or `authoritative-source`. Client-asserted and inferred edges alone cannot push weight to the strong grades.
7. **Refutation IDs.** Every `--` resolution has non-empty `matched_refutation_ids` referencing IDs that exist in the target hypothesis's `refutation_shape`.
8. **Trust-anchor completeness.** When a lead includes `trust_anchor_result`, all five fields are required: `anchor_id`, `kind`, `result`, `as_of`, `authority_for_question`.
9. **`screen_result` scope.** Only valid on leads with `mode: screen`, and only on the final lead in a SCREEN sequence.
10. **Lead-level predictions.** When present, each entry has `id` (matches `^lp\d+$`, unique within the lead), `if`, `read_as`, and `advance_to` (another lead name in the same or subsequent loop, or one of `CONCLUDE` / `HYPOTHESIZE`).

### Warning checks (do not block)

`collect_warnings` runs after error checks. Warnings print to stderr but exit 0:

- **Route compliance.** When a prior non-branching lead pre-committed to branch plans via lead-level `predictions`, the actually-run next step should match at least one `advance_to`. Mismatches surface as warnings — the agent is free to override the pre-committed route but should do so deliberately.

Warnings are a signal to the agent and a breadcrumb for post-hoc review; they do not fail the hook.

### Partial authority cap

Not a validator check but a modeling rule: a resolution grounded *solely* by `authority_for_question: partial` cannot push a hypothesis past `+` or `-`. Strong grades (`++`/`--`) require at least one full-authority anchor confirmation. The schema encodes this; reports that violate it will typically fail Tier 2 of `validate_report.py` under the EVIDENCE_SUFFICIENCY criterion.

## How invlang relates to the report

At CONCLUDE the agent writes the companion `conclude:` block and then `report.md`. The report's frontmatter enums (`disposition`, `confidence`, `status`, trust-anchor `result`) mirror the invlang vocabulary — the mapping happens at the invlang→report boundary so the richer companion vocabulary (e.g., `partial|no-data` anchor results) collapses to the report's narrower enum (`unavailable`) without lossy downgrading of the investigation record itself.

The companion `matched_archetype` names the archetype directory under `knowledge/signatures/{sig}/archetypes/{name}/`, matching the report's `matched_archetype` frontmatter field. Two-leg resolution (see `content/validation.md#tier-1-checks`) — shape via archetype, grounding via anchors or precedent — is enforced on the report side; invlang's job is to make sure the supporting record inside `investigation.md` is internally consistent.

## Relationship to other validation

invlang validation complements, does not replace, the other CONCLUDE-path checks:

- **Layer 0 `validate_conclude.py`** — ensures the agent authored `conclusion_checks.json` with correct question coverage and resolvable citations before the `## CONCLUDE` header lands.
- **`invlang_validate.py`** — ensures the companion YAML is structurally consistent at every investigation.md write.
- **Tier 1 `validate_report.py`** — ensures the `report.md` artifact is structurally legal (frontmatter, archetype shape, grounding, temporal re-confirmation).
- **Tier 2 semantic judge** — ensures the narrative in `investigation.md` actually supports the report's conclusion.

See `content/validation.md` for the full CONCLUDE-path story.
