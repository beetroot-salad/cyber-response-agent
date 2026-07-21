#!/usr/bin/env python3
"""Judge engine/model equivalence — the A/B behind the PydanticAI judge migration.

The judge is the loop's GROUND TRUTH: its `outcome` drives FN/FP accounting and its
`defender_findings` become the lessons the author trains on. So a verdict regression
silently poisons training labels. This harness measures whether a candidate judge
config (engine + model + effort) agrees with a proven reference config on the
load-bearing fields, over a FROZEN set of judge inputs, so only the config varies.

Two uses (decoupled, per the migration plan):

  Step 1 — engine equivalence: reference = claude_print+Sonnet, candidate =
           pydantic_ai+Sonnet (model held). Are the verdicts equivalent once only
           the ENGINE changed?
  Step 2 — model A/B: reference = the now-proven pydantic_ai+Sonnet, candidate =
           pydantic_ai+glm-5.2 at low/medium effort. Does GLM judge as well?

Establish the SAME-config self-consistency band first (run the reference against
itself, ≥2 reps): the judge is stochastic, so "equivalent" means "within the band,
with zero systematic caught↔survived / refuted↔survived flips" — a flip on that axis
changes what gets queued, so it is tracked separately and must be zero.

Researcher-cadence (not CI): makes model calls, emits scores. The metric functions
and verdict parsing are pure and unit-tested (`test_judge_equivalence.py`).

Assembling the frozen set (operator step, once): run `defender/run.py` over
`fixtures/held-out/` + a few scenarios to produce run dirs, LEARN each once (the judge
engine is irrelevant here — the snapshots are the judge INPUTS), then snapshot each
run's `(run_dir, actor_story*.md,
projected_telemetry*.yaml)` — those are the deterministic judge inputs
(`build_judge_invocation` is a pure function of them). Point `--cases` at the dir of
snapshots. No external truth oracle exists for a synthetic encounter, so the
reference is agreement-with-the-incumbent — it catches regressions from proven
behavior, which is exactly the poisoning risk; absolute quality stays the province of
the downstream metrics (forward-check + held_out).
"""
from __future__ import annotations

import argparse
import dataclasses
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if (_root := str(Path(__file__).resolve().parents[2])) not in sys.path:
    sys.path.insert(0, _root)

from defender.learning.core.validate import (  # noqa: E402
    normalize_judge_yaml,
    validate_judge_benign_doc,
    validate_judge_doc,
)

if TYPE_CHECKING:
    from defender.learning.core.config import JudgeWiring

_ADVERSARIAL_AXIS = ("caught", "survived")
_BENIGN_AXIS = ("refuted", "survived")
_PUNTS = {"undecidable", "incoherent"}


@dataclass(frozen=True)
class Verdict:

    case_id: str
    direction: str
    outcome: str | None
    finding_keys: frozenset
    parsed_ok: bool


def parse_judge_verdict(text: str, *, case_id: str, direction: str) -> Verdict:
    benign = direction == "benign"
    try:
        import yaml

        doc = yaml.safe_load(normalize_judge_yaml(text))
        validated = (validate_judge_benign_doc if benign else validate_judge_doc)(doc)
    except Exception:  # noqa: BLE001 — an unparseable/invalid verdict is a data point, not a crash
        return Verdict(case_id, direction, None, frozenset(), False)
    keys = frozenset(
        (f.get("type"), f.get("subject_anchor"))
        for f in validated.get("defender_findings", [])
        if isinstance(f, dict)
    )
    return Verdict(case_id, direction, validated.get("outcome"), keys, True)




def _axis_for(direction: str) -> tuple[str, str]:
    return _BENIGN_AXIS if direction == "benign" else _ADVERSARIAL_AXIS


def outcome_match_rate(ref: Sequence[Verdict], cand: Sequence[Verdict]) -> float:
    if not ref:
        return 1.0
    return sum(a.outcome == b.outcome for a, b in zip(ref, cand, strict=True)) / len(ref)


def systematic_flips(ref: Sequence[Verdict], cand: Sequence[Verdict]) -> list[str]:
    flipped = []
    for a, b in zip(ref, cand, strict=True):
        lo, hi = _axis_for(a.direction)
        if {a.outcome, b.outcome} == {lo, hi}:
            flipped.append(a.case_id)
    return flipped


def findings_agreement(ref: Sequence[Verdict], cand: Sequence[Verdict]) -> float:
    if not ref:
        return 1.0
    total = 0.0
    for a, b in zip(ref, cand, strict=True):
        union = a.finding_keys | b.finding_keys
        total += 1.0 if not union else len(a.finding_keys & b.finding_keys) / len(union)
    return total / len(ref)


def punt_rate(verdicts: Sequence[Verdict]) -> float:
    if not verdicts:
        return 0.0
    return sum(v.outcome in _PUNTS for v in verdicts) / len(verdicts)


def parse_failure_rate(verdicts: Sequence[Verdict]) -> float:
    if not verdicts:
        return 0.0
    return sum(not v.parsed_ok for v in verdicts) / len(verdicts)


@dataclass
class Comparison:
    n: int
    outcome_match: float
    flips: list[str]
    findings_agreement: float
    ref_punt_rate: float
    cand_punt_rate: float
    cand_parse_failure_rate: float


def compare(ref: Sequence[Verdict], cand: Sequence[Verdict]) -> Comparison:
    if len(ref) != len(cand):
        raise ValueError(f"paired verdict lists differ in length: {len(ref)} vs {len(cand)}")
    return Comparison(
        n=len(ref),
        outcome_match=outcome_match_rate(ref, cand),
        flips=systematic_flips(ref, cand),
        findings_agreement=findings_agreement(ref, cand),
        ref_punt_rate=punt_rate(ref),
        cand_punt_rate=punt_rate(cand),
        cand_parse_failure_rate=parse_failure_rate(cand),
    )


def render_report(title: str, cmp: Comparison, *, self_consistency: float | None = None) -> str:
    lines = [
        f"# {title}",
        "",
        f"cases: {cmp.n}",
        f"outcome-match: {cmp.outcome_match:.1%}",
        f"systematic caught↔survived/refuted↔survived flips: {len(cmp.flips)}"
        + (f"  {cmp.flips}" if cmp.flips else "  (none — gate PASSES on this axis)"),
        f"findings agreement (Jaccard on type+subject_anchor): {cmp.findings_agreement:.1%}",
        f"punt rate (undecidable/incoherent): ref={cmp.ref_punt_rate:.1%} cand={cmp.cand_punt_rate:.1%}",
        f"candidate parse-failure rate: {cmp.cand_parse_failure_rate:.1%}",
    ]
    if self_consistency is not None:
        verdict = "WITHIN" if cmp.outcome_match >= self_consistency else "BELOW"
        lines += [
            "",
            f"same-config self-consistency floor: {self_consistency:.1%}",
            f"→ candidate outcome-match is {verdict} the noise floor"
            + (" AND zero flips → EQUIVALENT" if verdict == "WITHIN" and not cmp.flips
               else " — NOT yet equivalent"),
        ]
    return "\n".join(lines)




@dataclass
class EngineConfig:

    label: str
    judge_fn: Callable[..., str]
    model: str
    effort: str


@dataclass
class FrozenCase:

    case_id: str
    direction: str
    run_dir: Path
    actor_story_path: Path
    projected_telemetry_path: Path
    wiring: JudgeWiring | None = field(repr=False, default=None)


def run_config(
    cases: Sequence[FrozenCase], config: EngineConfig, out_root: Path,
) -> list[Verdict]:
    from defender.learning.pipeline.judge.run import invoke_judge

    verdicts: list[Verdict] = []
    for case in cases:
        if case.wiring is None:
            raise ValueError(f"FrozenCase {case.case_id!r} has no wiring to run")
        wiring = dataclasses.replace(case.wiring, model=config.model, effort=config.effort)
        lrd = out_root / config.label / case.case_id
        lrd.mkdir(parents=True, exist_ok=True)
        raw = invoke_judge(
            wiring, case.run_dir, case.actor_story_path, case.projected_telemetry_path,
            lrd, judge_fn=config.judge_fn,
        )
        verdicts.append(parse_judge_verdict(raw, case_id=case.case_id, direction=case.direction))
    return verdicts


def main(argv: list[str]) -> int:  # pragma: no cover — thin CLI over the tested core
    p = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    p.parse_args(argv)
    print(
        "judge_equivalence is a library + operator harness. Assemble a frozen case set "
        "(see the module docstring), then in a driver script build FrozenCase list + "
        "two EngineConfigs, call run_config for each, and compare()/render_report(). "
        "Real model calls require the metered key (FIREWORKS_API_KEY / ANTHROPIC_API_KEY in .env).",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
