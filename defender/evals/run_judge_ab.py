#!/usr/bin/env python3
"""Step-2 model A/B driver — run the judge over a frozen case set under two configs
(reference vs candidate) and score verdict agreement. This is the operator front-end
to the pure library in ``judge_equivalence.py`` (EngineConfig / FrozenCase / run_config
/ compare / render_report); assembling the frozen set is documented in that module's
docstring.

Both configs run on the in-process ``pydantic_ai`` engine (``_run_judge_pydantic``), so
this measures the MODEL swap in isolation:

  reference  = pydantic_ai + Sonnet   (the now-incumbent judge, --ref-model/--ref-effort)
  candidate  = pydantic_ai + GLM-5.2  (the ported default,       --cand-model/--cand-effort)

The reference is also run TWICE to establish the same-config self-consistency floor (the
judge is stochastic), so "equivalent" means the candidate's outcome-match is WITHIN that
floor AND there are zero systematic caught↔survived / refuted↔survived flips — a flip on
that axis changes FN/FP accounting and thus which findings get queued as lessons.

Frozen case layout (``--cases DIR``): one subdir per case, each holding
  meta.json               {"direction": "adversarial" | "benign"}
  run_dir/                the investigation run dir (alert.json, report.md, gather_raw/, …)
  actor_story.md          the actor's story for the direction
  projected_telemetry.yaml the oracle's projected telemetry

Researcher-cadence (not CI): makes real model calls; the operator supplies the metered
keys (ANTHROPIC_API_KEY for Sonnet, FIREWORKS_API_KEY for GLM) via <repo>/.env or
$DEFENDER_ENV_FILE — this driver sources them up front with ``config.source_judge_key``.

  python3 defender/evals/run_judge_ab.py --cases <snapshots_dir> --out <scratch_dir>
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

if (_root := str(Path(__file__).resolve().parents[2])) not in sys.path:
    sys.path.insert(0, _root)

from defender.evals.judge_equivalence import (  # noqa: E402
    EngineConfig,
    FrozenCase,
    compare,
    outcome_match_rate,
    render_report,
    run_config,
)
from defender.learning.core import config  # noqa: E402
from defender.learning.core.directions import BY_NAME  # noqa: E402

# NB: the pydantic_ai engine (``_run_judge_pydantic``) is imported LAZILY inside ``main``,
# not at module top — it drags in the heavy pydantic-ai graph, and ``load_cases`` (the one
# unit-tested surface) needs none of it, so the loader stays importable without the runtime
# extra (mirrors the codebase's lazy-pydantic-ai convention).


def load_cases(cases_dir: Path) -> list[FrozenCase]:
    """Load the frozen snapshots under ``cases_dir`` into ``FrozenCase``s, attaching the
    base wiring for each case's direction (run_config overrides only model+effort on it).
    Skips a subdir with a loud warning if it's missing a required artifact — OR carries an
    unreadable/malformed meta.json — so one bad snapshot doesn't abort the whole A/B."""
    cases: list[FrozenCase] = []
    for case_dir in sorted(p for p in cases_dir.iterdir() if p.is_dir()):
        meta_path = case_dir / "meta.json"
        run_dir = case_dir / "run_dir"
        story = case_dir / "actor_story.md"
        telemetry = case_dir / "projected_telemetry.yaml"
        missing = [p.name for p in (meta_path, story, telemetry) if not p.is_file()]
        if not run_dir.is_dir():
            missing.append("run_dir/")
        if missing:
            print(f"skip {case_dir.name}: missing {', '.join(missing)}", file=sys.stderr)
            continue
        # A present-but-corrupt meta.json (truncated/invalid JSON, or an unreadable file)
        # is a bad snapshot too — skip it loudly rather than letting json.loads/read_text
        # abort the whole loader (JSONDecodeError subclasses ValueError). A valid-JSON but
        # non-object payload falls through to the bad-direction skip below (direction=None).
        try:
            meta = json.loads(meta_path.read_text())
        except (OSError, ValueError) as e:
            print(f"skip {case_dir.name}: unreadable/invalid meta.json ({e})", file=sys.stderr)
            continue
        direction = meta.get("direction") if isinstance(meta, dict) else None
        spec = BY_NAME.get(direction)
        if spec is None:
            print(f"skip {case_dir.name}: bad direction {direction!r} (expected "
                  "'adversarial' | 'benign')", file=sys.stderr)
            continue
        cases.append(FrozenCase(
            case_id=case_dir.name, direction=direction, run_dir=run_dir,
            actor_story_path=story, projected_telemetry_path=telemetry,
            wiring=spec.judge_wiring,
        ))
    return cases


def main(argv: list[str]) -> int:  # pragma: no cover — operator harness over the tested core
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.add_argument("--cases", type=Path, required=True, help="dir of frozen case snapshots")
    p.add_argument("--out", type=Path, required=True, help="scratch dir for per-run judge output")
    p.add_argument("--ref-model", default="claude-sonnet-4-6")
    p.add_argument("--ref-effort", default="low")
    p.add_argument("--cand-model", default="glm-5.2")
    p.add_argument("--cand-effort", default="medium")
    args = p.parse_args(argv)

    cases = load_cases(args.cases)
    if not cases:
        print(f"no runnable cases under {args.cases}", file=sys.stderr)
        return 1

    # Lazy: the in-process engine drags in the pydantic-ai graph — imported here, at the
    # one point of use, so importing this module for ``load_cases`` never requires it.
    from defender.learning.pipeline.judge.engine_pydantic import _run_judge_pydantic

    # Source the metered key for each distinct model before any call (fails loud on a
    # missing key → the same FatalConfigError the loop raises, rather than a 401 mid-run).
    for model in {args.ref_model, args.cand_model}:
        config.source_judge_key(model)

    # Both configs on the in-process engine, so only the model+effort vary. The reference
    # runs twice (ref-a / ref-b) for the self-consistency floor.
    ref_a = EngineConfig("ref-a", _run_judge_pydantic, args.ref_model, args.ref_effort)
    ref_b = EngineConfig("ref-b", _run_judge_pydantic, args.ref_model, args.ref_effort)
    cand = EngineConfig("cand", _run_judge_pydantic, args.cand_model, args.cand_effort)

    print(f"reference: pydantic_ai + {args.ref_model} @ {args.ref_effort}  |  "
          f"candidate: pydantic_ai + {args.cand_model} @ {args.cand_effort}  |  "
          f"cases: {len(cases)}", file=sys.stderr)

    ref_a_v = run_config(cases, ref_a, args.out)
    ref_b_v = run_config(cases, ref_b, args.out)
    cand_v = run_config(cases, cand, args.out)

    floor = outcome_match_rate(ref_a_v, ref_b_v)  # same-config self-consistency
    print(render_report(
        f"Step-2 model A/B — {args.cand_model}@{args.cand_effort} vs "
        f"{args.ref_model}@{args.ref_effort}",
        compare(ref_a_v, cand_v),
        self_consistency=floor,
    ))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
