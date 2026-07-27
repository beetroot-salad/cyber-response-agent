#!/usr/bin/env python3
"""Blind Opus adjudication of the paired judge verdicts.

At n=2 `outcome_match` can only be 0%, 50% or 100%, so it cannot tell "K3 is better" from
"K3 is different" — the harness scores agreement-with-the-reference, and a genuinely
stronger judge is *supposed* to disagree on the hard cases. This asks a stronger model to
read both verdicts against the same evidence the judges saw and say which reasoning holds
up, which is the question the port actually turns on.

**Blind.** The two verdicts are presented as "Judge A" / "Judge B" with no model names, and
the arms SWAP position between cases so a consistent position bias shows up as a
contradiction rather than a clean sweep. The mapping is written to `adjudication/mapping.json`.

    python3 experiments/judge-glm52-vs-kimik3/adjudicate.py \
        --runs   /workspace/experiments/judge-glm52-vs-kimik3/runs \
        --cases  /workspace/experiments/judge-glm52-vs-kimik3/fixtures \
        --out    /workspace/experiments/judge-glm52-vs-kimik3/results/adjudication
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

if (_root := str(Path(__file__).resolve().parents[2])) not in sys.path:
    sys.path.insert(0, _root)

sys.path.insert(0, str(Path(__file__).resolve().parent))
from analyze import read_trace  # noqa: E402

ADJUDICATOR_MODEL = "claude-opus-5"
_TRACE_NAMES = ("judge_trace.jsonl", "judge_benign_trace.jsonl")

RUBRIC = """You are adjudicating two independent judgements of the same security \
investigation. Both judges saw exactly the evidence reproduced below and were asked the \
same question under the same rubric.

The judge's role in this system: it is the ground truth for a learning loop. Its `outcome` \
drives false-negative / false-positive accounting, and its `defender_findings` become the \
lessons a downstream agent trains on. So a verdict that is confidently wrong, or that cites \
evidence which does not support it, actively poisons training labels. Fluency is worth \
nothing here; grounding is worth everything.

Judge them on, in descending order of weight:

1. **Grounding** — is every load-bearing claim traceable to the evidence shown? Quote any \
citation that does not support the claim it is attached to, or any assertion about the \
telemetry that the evidence does not contain. A fabricated or misattributed citation is the \
single most serious defect available here.
2. **Correctness of the outcome** — given this evidence, is the outcome right? Say what you \
think the correct outcome is and why, BEFORE weighing which judge agrees with you.
3. **Findings quality** — are the findings real, specific defects in the investigation, \
anchored to the right lead? Or are they generic process observations that would apply to any \
investigation?
4. **Calibration** — does the confidence match the evidence? Over-calling an ambiguous case \
and under-calling a clear one are both failures.

Do not reward length, structure, or confident tone. If both are weak, say so. If they reach \
the same outcome by different reasoning, judge the reasoning. It is a legitimate result that \
the two are indistinguishable in quality — say that rather than manufacturing a winner.

End your response with exactly one line:

VERDICT: A | B | TIE — <one clause naming the deciding difference>
"""


def _verdict_text(run_dir: Path) -> str:
    for name in _TRACE_NAMES:
        trace = run_dir / name
        if trace.is_file() and trace.stat().st_size:
            return read_trace(trace)["verdict_text"]
    return ""


def build_prompt(case_dir: Path, first: tuple[str, str], second: tuple[str, str]) -> str:
    meta = json.loads((case_dir / "meta.json").read_text(encoding="utf-8"))
    rd = case_dir / "run_dir"

    def read(p: Path) -> str:
        return p.read_text(encoding="utf-8") if p.is_file() else "(absent)"

    sections = [
        RUBRIC,
        f"\n\n# Direction\n\n{meta['direction']}"
        + (
            "\n\nThe adversarial direction hunts a FALSE NEGATIVE: the actor proposes an "
            "attack story consistent with the same alert, and the outcome is `caught` if the "
            "defender's investigation would have surfaced it, `survived` if it would have "
            "slipped through."
            if meta["direction"] == "adversarial"
            else "\n\nThe benign direction hunts a FALSE POSITIVE: the actor proposes a "
            "routine-activity story consistent with the same alert, and the outcome is "
            "`refuted` if the defender's evidence rules that story out, `survived` if the "
            "escalation may have been an over-call."
        ),
        f"\n\n# Alert\n\n```json\n{read(rd / 'alert.json')}\n```",
        f"\n\n# The defender's report\n\n{read(rd / 'report.md')}",
        f"\n\n# The defender's investigation log\n\n{read(rd / 'investigation.md')}",
        f"\n\n# The actor's story\n\n{read(case_dir / 'actor_story.md')}",
        "\n\n# The oracle's projected telemetry\n\n"
        "(A signed diff over the routine baseline: what the story would have added to or "
        "removed from each lead's query results. `events: []` means the story writes no "
        "delta to that lead at all; `- <standard environment noise>` means it lights that "
        "envelope but only with events shape-identical to the baseline, so the lead cannot "
        "distinguish it.)\n\n"
        f"```yaml\n{read(case_dir / 'projected_telemetry.yaml')}\n```",
        f"\n\n# Judge {first[0]}\n\n{first[1]}",
        f"\n\n# Judge {second[0]}\n\n{second[1]}",
    ]
    return "".join(sections)


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--runs", type=Path, required=True)
    p.add_argument("--cases", type=Path, required=True)
    p.add_argument("--out", type=Path, required=True)
    p.add_argument("--model", default=ADJUDICATOR_MODEL)
    args = p.parse_args(argv)

    args.out.mkdir(parents=True, exist_ok=True)
    mapping = {}
    case_dirs = sorted(d for d in args.cases.iterdir() if d.is_dir())

    # GLM disagreed with ITSELF on both cases (self-consistency floor 0%), so "K3 vs the
    # reference" has no single referent — pairing against ref-a alone would just pick one
    # of the incumbent's two coin flips. Each K3 verdict is therefore adjudicated against
    # BOTH GLM reps: a K3 that beats both is a result, a K3 that splits is not.
    pairings = [(case_dir, rep) for case_dir in case_dirs for rep in ("ref-a", "ref-b")]

    for i, (case_dir, rep) in enumerate(pairings):
        case_id = case_dir.name
        pair_id = f"{case_id}-vs-{rep}"
        ref = _verdict_text(args.runs / rep / case_id)
        cand = _verdict_text(args.runs / "cand" / case_id)
        if not ref or not cand:
            print(f"skip {pair_id}: missing verdict "
                  f"(ref={bool(ref)} cand={bool(cand)})", file=sys.stderr)
            continue
        # Swap which arm is presented first between pairings, so position bias contradicts
        # itself instead of producing a clean sweep for whichever arm always went first.
        swap = i % 2 == 1
        a_arm, b_arm = ("kimi-k3", rep) if swap else (rep, "kimi-k3")
        a_text, b_text = (cand, ref) if swap else (ref, cand)
        mapping[pair_id] = {"A": a_arm, "B": b_arm}

        prompt = build_prompt(case_dir, ("A", a_text), ("B", b_text))
        (args.out / f"{pair_id}.prompt.md").write_text(prompt, encoding="utf-8")
        print(f"adjudicating {pair_id} ({len(prompt):,} chars)…", file=sys.stderr)
        # Drop ANTHROPIC_API_KEY so the CLI falls back to the interactive claude.ai login.
        # The repo's key is the metered first-party key the judge arms bill against; it has
        # no credit for the adjudicator, and it takes precedence over the login when set.
        env = {k: v for k, v in os.environ.items() if k != "ANTHROPIC_API_KEY"}
        proc = subprocess.run(
            ["claude", "-p", "--model", args.model],
            input=prompt, capture_output=True, text=True, check=False, env=env,
        )
        if proc.returncode != 0:
            print(f"  adjudicator failed rc={proc.returncode}: {proc.stderr[:400]}",
                  file=sys.stderr)
            continue
        (args.out / f"{pair_id}.adjudication.md").write_text(proc.stdout, encoding="utf-8")
        tail = [ln for ln in proc.stdout.splitlines() if ln.startswith("VERDICT:")]
        line = tail[-1] if tail else "(no VERDICT line)"
        won = line.partition("VERDICT:")[2].strip()[:1]
        print(f"  {line}   [A={a_arm} B={b_arm}"
              + (f" → {mapping[pair_id].get(won, '?')}]" if won in ("A", "B") else "]"),
              file=sys.stderr)

    (args.out / "mapping.json").write_text(json.dumps(mapping, indent=2) + "\n",
                                           encoding="utf-8")
    print(json.dumps(mapping, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
