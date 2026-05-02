# Investigation Language (invlang)

The structured companion schema the agent writes alongside its narrative during an investigation. Each dense `​```invlang` block co-located in `investigation.md` encodes the phase's reasoning as a typed graph — vertices, edges, hypotheses, leads, resolutions — that a PreToolUse hook validates on every write.

This file is a handbook-level orientation. The **authoritative schema reference** is `knowledge/invlang/schema.md` (resolved inline into the investigate skill at load time via a `!command`). The **on-disk surface grammar** (block tags `:V` / `:E` / `:H` / `:L` / `:R` / `:T` / `:G`, row shapes, sub-cell packing) lives in `docs/dense-investigation-format.md`. Read those for field-level detail; read this page to understand what role invlang plays in the plugin and why it exists.

### Two surfaces, one dict

The canonical artifact the validator and corpus queries operate on is a Python dict — vertices, edges, hypotheses, leads, conclude. That dict has two surface forms:

- **On-disk**, in `investigation.md`: dense `​```invlang` fenced blocks. This is the only surface the plugin writes today (strict cutover; `​```yaml` fences in `investigation.md` are rejected). Parser: `scripts/handlers/_dense_parser.py`.
- **In the spec / examples**: YAML rendered for readability. `knowledge/invlang/schema.md` shows fields in YAML because the field grammar is easier to read that way; the on-disk surface packs the same fields into row cells.

Both project to the same companion dict. Validator rules #1–#36 are written against the dict, not against either surface.

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
| CONTEXTUALIZE | `:V prologue.vertices` + `:E prologue.edges` | end of phase | vertices + edges derived from alert entities |
| SCREEN | first lead row in `:L findings` with `mode: screen` | after screen subagent returns | `screen_result: match | no_match` on the final screen lead; SCREEN-matched companions omit `:H hypothesize.hypotheses` |
| PREDICT | `:H hypothesize.hypotheses` | end of phase | initial proposed frontier of hypotheses |
| GATHER | lead row in `:L findings` (+ lead-scoped `:V` / `:E` observations) | end of phase | resolutions are ANALYZE's; GATHER writes the row + observations only |
| ANALYZE | merge into the same lead via `:R authz` / `:R consultations` / `:R impact` / `:R attr_updates` and `:T resolutions` | end of phase | one lead row per lead; rows in the same cycle share the `loop` column. v2.12 renamed the canonical-dict block from `gather:` to `findings:` (same merge semantics) |
| REPORT | `:T conclude` + `:T conclude.{surviving,deferred_authz,deferred_impact,deferred_preds,ceiling_test}` | after the `## REPORT` header + verdict line, before `report.md` | `termination.category`, `termination.rationale`, `disposition`, `confidence`, `matched_archetype`, `impact_verdict`, `impact_severity`, plus the deferred sub-tables. Block name preserved for corpus backward-compat. |

The schema is **graph-first** (Schema v2.13 as of this writing — see `docs/investigation-language.md` for the running version log):

- **Entities as vertices** — endpoint, process, session, identity, storage, command, etc. Every observed entity becomes a typed vertex.
- **Relations as edges** — `spawned`, `authenticated_as`, `connected_to`, and so on, each carrying `authority` describing how reliably the source recorded it.
- **Hypotheses as proposed edges** — a hypothesis proposes exactly one upstream vertex connected to a confirmed vertex by exactly one edge. Predictions test the *proposed vertex's existence*, not alert data already in hand.
- **Leads as graph operations** — topology-extending (new vertices or edges in `outcome.observations`), attribute-refining (`attribute_updates` on existing vertices), or both. `tests` declares which hypotheses the lead discriminates; absence signals a non-branching lead that may still carry lead-level `predictions` (pre-committed conditional branch plans).

Field vocabulary (vertex types, relation catalog, authority kinds, termination categories) lives in `knowledge/invlang/schema.md`.

## Validation — `invlang_validate.py`

Registered as a **PreToolUse** hook on `Write|Edit` to `investigation.md` in `plugin.json`. Fires on every proposed write, extracts the dense `​```invlang` fenced blocks (rejecting any `​```yaml` fence outright — strict cutover), projects them to the canonical companion dict via `scripts/handlers/_dense_parser.py`, and runs the structural checks against the dict. On failure it prints errors to stderr and exits 2 — the write is blocked before it lands on disk, `state.json` never advances, and the agent's next action is to rewrite the block.

### Error checks (block the write)

From `hooks/scripts/invlang_validate.py::validate_companion` (29 active rules across numbering 1–36; seven preserved-as-redirect gaps from the v2.15 consolidation — see `docs/investigation-language.md` §Validator rules for the authoritative list):

1. **Dense block parses.** Each `​```invlang` fence tokenizes cleanly (block headers, row counts match column counts, sub-cell grammar is well-formed) and projects onto the canonical companion dict shape. A `​```yaml` fence anywhere in the proposed text is itself a hard error.
2. **Append-only.** The proposed text must not shrink an existing companion block. Removing or mutating a prior record is rejected. Decomposition is done by appending sub-vertices with hierarchical IDs (`v-{parent}-{nonce}`); attribute changes go through new `attribute_updates`.
3. **Lead required fields.** Every entry under `findings:` has `id`, `loop`, `name`, `target`, `query_details`, `outcome`.
4. **ID format.** Vertices match `v-…`, edges `e-…`, hypotheses `h-…`, leads `l-…`, predictions `p\d+`, attribute predictions `ap\d+`, impact predictions `ip\d+`, lead-level predictions `lp\d+`, refutations `r\d+`.
5. **ID references resolve.** Every cross-reference (e.g. `resolutions[].hypothesis`, `supporting_edges`, `tests`, `observes[].hypothesis`) names a declared ID.
6. **Edge authority.** Every `++` or `--` resolution must cite at least one `supporting_edge` whose authority kind is `siem-event`, `runtime-audit`, or `authoritative-source`. Client-asserted and inferred edges alone cannot push weight to the strong grades.
7. **Refutation IDs.** Every `--` resolution has non-empty `matched_refutation_ids` referencing IDs that exist in the target hypothesis's `refutation_shape`.
8. **Anchor-consultation completeness (rule #11).** Every `anchor_consultations[]` entry on a lead outcome requires `anchor_id`, `anchor_kind`, `grounding_kind`, `result`, `as_of`, `authority_for_question`. `grounding_kind ∈ {org-authority, telemetry-baseline}` on consultations; `past-case` is authz-only. Authorization resolutions live inline on edges (or via `attribute_updates`) and have their own required-field set (verdict, anchor_id, anchor_kind, grounding_kind, authority_for_question, as_of, resolved_by_lead, fulfills_contract).
9. **`screen_result` scope.** Only valid on leads with `mode: screen`, and only on the final lead in a SCREEN sequence.
10. **Lead-level predictions.** When present, each entry has `id` (matches `^lp\d+$`, unique within the lead), `if`, `read_as`, and `advance_to` (another lead name in the same or subsequent loop, or one of `REPORT` / `PREDICT`).
11. **Authorization-contract orphan gate (rule #26).** Every declared `authorization_contract` on a hypothesis must either resolve via a fulfilling edge-level `authorization_resolutions[]` entry, or appear in `conclude.deferred_authorizations[]` with rationale. Same-shape gates exist for impact predictions (`conclude.deferred_impact_predictions[]`) and v2.13 generalises this to all `p*`/`ap*` predictions on non-refuted hypotheses (`conclude.deferred_predictions[]`, rule #34).
12. **Sibling prediction divergence (rules #32, #35).** Within a sibling group sharing `parent_hypothesis_id` + `attached_to_vertex`, no two siblings may declare identical prediction signatures. Rule #32 fires specifically on integrity peers gated by an authorization contract; rule #35 generalises this to all sibling forks regardless of contract presence.

### Warning checks (do not block)

`collect_warnings` runs after error checks. Warnings print to stderr but exit 0:

- **Route compliance.** When a prior non-branching lead pre-committed to branch plans via lead-level `predictions`, the actually-run next step should match at least one `advance_to`. Mismatches surface as warnings — the agent is free to override the pre-committed route but should do so deliberately.

Warnings are a signal to the agent and a breadcrumb for post-hoc review; they do not fail the hook.

### Partial authority cap

Not a validator check but a modeling rule: a resolution grounded *solely* by `authority_for_question: partial` cannot push a hypothesis past `+` or `-`. Strong grades (`++`/`--`) require at least one full-authority anchor confirmation. The schema encodes this; reports that violate it will typically fail Tier 2 of `validate_report.py` under the EVIDENCE_SUFFICIENCY criterion.

## How invlang relates to the report

At REPORT the agent writes the dense `:T conclude` block (canonical-dict block name `conclude` preserved for corpus backward-compat) and then `report.md`. The report's frontmatter enums (`disposition`, `confidence`, `status`, trust-anchor `result`) mirror the invlang vocabulary — the mapping happens at the invlang→report boundary so the richer companion vocabulary (e.g., `partial|no-data` anchor results) collapses to the report's narrower enum (`unavailable`) without lossy downgrading of the investigation record itself.

The companion `matched_archetype` names the archetype directory under `knowledge/signatures/{sig}/archetypes/{name}/`, matching the report's `matched_archetype` frontmatter field. Two-leg resolution (see `content/validation.md#tier-1-checks`) — shape via archetype, grounding via anchors or precedent — is enforced on the report side; invlang's job is to make sure the supporting record inside `investigation.md` is internally consistent.

**Three orthogonal axes (v2.11 onwards).** A disposition is the join of three independent verdicts: **authorization** (anchor-backed, contract-on-hypothesis, resolution-inline-on-edge), **integrity** (peer-hypothesis discipline — `?adversary-controlled-*` siblings on acting-entity sources, evidential not anchor-backed), and **impact** (threshold-gated — leads declare `impact_predictions[]`, ANALYZE grades them into `impact_resolutions[]`, REPORT rolls up `conclude.impact_verdict` and `conclude.impact_severity`). Authorized-but-impactful (e.g., authorized bulk read at 3σ above baseline) resolves on the impact axis, not by softening authorization. See `docs/investigation-language.md` §Authorization / §Integrity / §Impact.

**Handler-authored synthesis (v2.12 onwards).** Subagents emit dense-block trailers (`:T resolutions`, `:R *`, `:A routing`, etc. — see `docs/dense-investigation-format.md` §ANALYZE trailer dense form); the orchestrator/skill handlers (`scripts/handlers/gather.py`, `scripts/handlers/analyze.py`) synthesize the canonical `findings[]` entries and merge them via the validator. Raw SIEM/anchor payloads are saved off-companion to `runs/{run_id}/raw_details/loop-{N}/{lead-id}.yaml` by the `save_raw_tool_output.py` PostToolUse hook; the analyze handler preloads those per-loop. Keeps companion blocks trim while preserving full evidence under the run.

## Relationship to other validation

invlang validation complements, does not replace, the other REPORT-path checks:

- **Layer 0 `validate_report_precheck.py`** — fires two parallel Haiku judges (log integrity + archetype/grounding) when the `## REPORT` write lands the `:T conclude` block, blocking the write on any FLAG.
- **`invlang_validate.py`** — ensures the dense companion blocks are structurally consistent at every investigation.md write.
- **Tier 1 `validate_report.py`** — ensures the `report.md` artifact is structurally legal (frontmatter, archetype shape, grounding, temporal re-confirmation).
- **Tier 2 semantic judge** — slimmed to validating the report↔log delta plus precedent transfer.

See `content/validation.md` for the full REPORT-path story.
