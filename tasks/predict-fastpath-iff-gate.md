---
title: PREDICT exact-match fast-path (handler-only IFF gate)
status: doing
groups: orchestrator, cost-reduction, predict
---

## What

Add a deterministic gate to `scripts/handlers/predict.py:handle()` that
short-circuits the predict subagent on **exact-match** prior topology +
key-attribute alignment. On `verdict=exact` the handler picks the
precedent's `selected_lead` directly and routes to GATHER without
spawning the Sonnet subagent. On any other verdict the existing
subagent path runs unchanged.

Out of scope: Haiku "screen-predict" middle tier (arm C — deferred);
"primed Sonnet" prompt change (arm B — empirically harmful, dropped);
SCREEN retirement; whole-loop fast-path.

## Why

Empirical result from `tasks-scratch/predict_fastpath_ab/` (2026-04-26,
4 arms × 7 fixtures including 1 adversarial collision):

| Arm | Overall | Adversarial collision |
|---|---|---|
| A — Sonnet, today's priors | 6/7 | **0/1** ❌ |
| B — Sonnet primed | 5/7 | 0/1 ❌ |
| C — Haiku screen-predict | 3/7 | 0/1 ❌ |
| D — handler-only IFF gate | 7/7 | **1/1** ✅ |

The adversarial fixture (`5710-admin-internal-collision`) has identical
prologue topology + classifications to the monitoring-probe seeds —
only the `monitoring-pattern` identifier differs (`admin` vs
`nagios`/`sensu`). All three LLM arms picked the historical lead
(`approved-monitoring-sources`); only the IFF #5 key-attribute gate
caught it. Today's `_format_priors` block uses tier-1/2 prologue
matching that *also* misses this distinction, so the live PREDICT is
currently being injected with misleading priors on this kind of alert.

D's safety contract: **never picks a wrong fast-path lead.** On
non-exact verdicts it returns `selected_lead=None`, the handler falls
through, and the existing subagent runs.

## Spec

### IFF conditions (all must hold against ≥1 precedent)

Topological:
1. `signature_id` identical
2. prologue `vertex_types` set equal
3. prologue `edge_relations` set equal
4. prologue `vertex_classifications` set equal

Key-attribute:
5. discriminating-field equality on every vertex of decision-relevant
   classification (identity-name family pattern; network-endpoint
   subnet bucket; process pname family)
6. no current-alert field present that the precedent didn't have, when
   that field is in the playbook's discriminating_fields

Outcome quality:
7. precedent `disposition` ∈ {benign, true_positive}
8. precedent `selected_lead` exists in current playbook's lead catalog
9. per-lead `fidelity_rate` at this topology ≥ 0.7 (production threshold;
   experiment used same)

Operational guards:
10. exactly one precedent matches OR multiple precedents agree on the
    same `selected_lead`
11. lead `kind` ∈ {branching, interpretive} (never fast-path mechanical)

Reference implementation: `tasks-scratch/predict_fastpath_ab/gate.py`.
That module is pure (no plugin imports) and the prod port can copy the
predicate functions verbatim.

### Handler integration

In `scripts/handlers/predict.py:handle()`, before `_attempt()`:

```python
def handle(ctx: Context) -> PhaseResult:
    expected_loop_n = _compute_loop_n(ctx)

    # Fast-path: only attempt at loop 1 (no prior hypothesize block)
    fastpath = _try_fast_path(ctx, expected_loop_n)
    if fastpath is not None:
        _append_fastpath_marker(ctx, fastpath, expected_loop_n)
        return fastpath  # PhaseResult(next_phase=GATHER, payload={...})

    # ...existing subagent path unchanged...
```

`_try_fast_path` reuses the corpus loaded by `_compute_priors` so
retrieval runs once. On exact verdict, return:

```python
PhaseResult(
    next_phase=Phase.GATHER,
    payload={
        "selected_lead": <precedent's lead>,
        "loop_n": expected_loop_n,
        "composite_secondary": [],
        "fast_path": {
            "verdict": "exact",
            "matched_cases": [...],
            "matched_iff_conditions": [...],
        },
    },
)
```

`_append_fastpath_marker` writes a handler-authored block to
`investigation.md`:

```markdown
## PREDICT (loop N) — fast-path

```yaml
fast_path:
  verdict: exact
  matched_precedent: SEED-XXX
  selected_lead: <lead>
  iff_evidence:
    iff_5_key_attrs: all key attrs aligned
    ...
```
```

No invlang `hypothesize:` block is appended on the fast-path (no new
hypotheses authored). ANALYZE will see this loop's lead choice came
from priors via the `fast_path` payload field.

### Loop-1-only restriction

The gate runs only on loop 1. At loop 2+ the frontier carries proposed
upstream edges that the IFF gate has no model for. Loop 2+ keeps the
existing subagent path. (Reconsider after eval shows loop-1 in prod;
documented in RESULTS.md as an open follow-up.)

### Data-driven `discriminating_classifications`

The experiment hard-codes `KEY_ATTRIBUTE_PATTERNS` in `gate.py`. For
prod, move this into `playbook.md` frontmatter as
`discriminating_classifications:`:

```yaml
---
signature_id: wazuh-rule-5710
discriminating_classifications:
  monitoring-pattern:
    - "^(nagios|sensu|monitor.*|probe.*|check.*|sentinel.*|testuser)$"
  service-account:
    - "^(svc-.*|backup-.*|cron-.*|ansible-.*|deploy-.*)$"
---
```

The gate reads the playbook for the current signature_id at evaluation
time. Signatures without this frontmatter never fast-path (gate is
opt-in per signature).

### Observability

Replace the silent `_safe_priors_section` exception banner with a
JSONL log line written to `runs/predict_priors.jsonl`:

```json
{
  "run_dir": "...",
  "loop_n": 1,
  "status": "ok|degraded",
  "exc_type": "...",  // present only on degraded
  "fastpath_eligible": true,
  "fastpath_taken": true,
  "verdict": "exact|strong|moderate|weak|none",
  "matched_cases": [...],
  "selected_lead": "..."
}
```

The prompt block stays neutral — no status leak to the agent. The file
gives per-run visibility into hit rate and failure causes.

### Precedent retrieval source

Production must retrieve precedents from the real corpus
(`load_corpus()` in `scripts/invlang`), not from a seeded dict. The
gate's `Precedent` shape (case_id, signature_id, prologue,
selected_lead, lead_kind, fidelity_rate, disposition,
discriminating_attrs) is derivable from a Companion plus the loop-1
hypothesize/findings blocks. Add a `precedents_for_signature(corpus,
sig_id)` helper alongside the existing prologue queries.

## Tests

- `test_predict_fastpath_gate.py` — pure-function tests on the gate:
  each IFF condition flipped in isolation against a fixture precedent;
  consensus / disagreement cases for IFF #10; opt-in via missing
  playbook frontmatter.
- `test_predict_fastpath_handler.py` — handler-level tests:
  - exact verdict → subagent never invoked, payload carries `fast_path`,
    `investigation.md` carries the marker block
  - non-exact verdict → subagent invoked, no marker written
  - loop 2+ → subagent invoked regardless of gate verdict
- Update `test_predict_priors.py` to confirm the existing priors block
  still renders when fast-path didn't fire.

## Acceptance

- All adversarial-collision-style fixtures from
  `tasks-scratch/predict_fastpath_ab/fixtures/` pass when ported to
  the test suite.
- A live `/testrun` against the canonical 5710 monitoring-probe alert
  shows `## PREDICT (loop 1) — fast-path` in `investigation.md` and
  the GATHER phase running without a Sonnet subagent invocation in
  between (verifiable via `tool_audit.jsonl` — no `predict` Task call).
- `runs/predict_priors.jsonl` carries one line per loop with
  `fastpath_taken` populated.
- No regression in `pytest -m "not llm"`.

## References

- Experiment: `tasks-scratch/predict_fastpath_ab/RESULTS.md`
- Reference gate: `tasks-scratch/predict_fastpath_ab/gate.py`
- Current handler: `soc-agent/scripts/handlers/predict.py:798`
  (`handle()`) and `:227` (`_safe_priors_section`)
- Current priors block: `_format_prologue_priors` and `_format_priors`
  at `predict.py:320` / `:494`