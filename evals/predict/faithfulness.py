"""Comprehension-faithfulness scorer (D11).

For each PREDICT envelope (parsed dense or YAML), spawn a fresh Haiku auditor
with ONLY the dense envelope text + a fixed 5-question quiz. The auditor must
answer from the envelope alone — no prompt context. Score 0–5.

Goal: bound how well a downstream agent (GATHER, ANALYZE) could read the
envelope without losing information vs. the YAML form. If the dense form is
unreadable, downstream phases will silently degrade — this catches that.

Output: per (variant, case, rep) {raw_answers, score_per_question, total}.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

# 5-question quiz template. Answers parsed structurally from the envelope dict
# and compared against the auditor's free-text answers (substring match,
# normalized).
QUIZ = [
    "Q1. What is the shape (E, A, or M)?",
    "Q2. Which lead is selected (the value of routing.selected_lead)?",
    "Q3. For the first hypothesis (h-001), what is the parent_vertex.classification?",
    "Q4. For the first prediction p1 on h-001 (or for branch-plan lp1 on Shape E), what is its kind (one of geometry/cadence/novel-artifact/absence/presence/absolute)?",
    "Q5. List every refutation id (r1, r2, ...) that appears in the envelope. If none, answer 'none'.",
]

QUIZ_PROMPT_TEMPLATE = """You are a downstream agent reading a PREDICT trailer. Answer the 5 questions below using ONLY the trailer text — no outside knowledge, no inference beyond what is explicitly written. One short answer per question. If the trailer does not contain the answer, write `unknown`.

<trailer>
{trailer}
</trailer>

{quiz}

Format your answer as exactly 5 lines, each `Q<n>: <answer>`. No preamble, no explanation.
"""


@dataclass
class FaithfulnessResult:
    raw_answers: list[str]
    expected: list[str]
    correct: list[bool]
    score: float  # 0..1


def _expected_from_envelope(env: dict) -> list[str]:
    pred = env.get("predict", {})
    shape = pred.get("shape", "")
    routing = pred.get("routing") or {}
    selected = routing.get("selected_lead", "")
    hyps = pred.get("hypotheses") or []
    bp = pred.get("branch_plan") or {}
    if hyps:
        h = hyps[0]
        parent_class = (h.get("proposed_edge", {}).get("parent_vertex", {}) or {}).get("classification", "")
        if h.get("predictions"):
            pred_kind = h["predictions"][0].get("kind", "")
        else:
            pred_kind = ""
    else:
        parent_class = ""
        if bp.get("predictions"):
            pred_kind = bp["predictions"][0].get("kind", "")
        else:
            pred_kind = ""
    refut_ids: list[str] = []
    for h in hyps:
        for r in h.get("refutation_shape") or []:
            refut_ids.append(r["id"])
    return [
        shape,
        selected,
        parent_class,
        pred_kind,
        ",".join(sorted(set(refut_ids))) if refut_ids else "none",
    ]


def _parse_quiz_answers(text: str) -> list[str]:
    out = ["", "", "", "", ""]
    for line in text.splitlines():
        m = re.match(r"^Q(\d):\s*(.+)$", line.strip())
        if m:
            idx = int(m.group(1)) - 1
            if 0 <= idx < 5:
                out[idx] = m.group(2).strip().rstrip(".")
    return out


def _normalize(s: str) -> str:
    return s.strip().lower().rstrip(".").strip("'\"")


def _check(answer: str, expected: str, q_idx: int) -> bool:
    if not expected:
        return _normalize(answer) in ("unknown", "none", "")
    a = _normalize(answer)
    e = _normalize(expected)
    if q_idx == 4:  # refutation list — compare as sets
        a_set = {x.strip() for x in re.split(r"[,\s]+", a) if x.strip()}
        e_set = {x.strip() for x in re.split(r"[,\s]+", e) if x.strip()}
        return a_set == e_set
    return e in a or a in e


def score_faithfulness(envelope: dict, trailer_text: str, *, model: str = "claude-haiku-4-5-20251001", timeout: int = 60) -> FaithfulnessResult:
    quiz_text = "\n".join(QUIZ)
    prompt = QUIZ_PROMPT_TEMPLATE.format(trailer=trailer_text, quiz=quiz_text)
    proc = subprocess.run(
        ["claude", "-p", "--model", model, prompt],
        capture_output=True, text=True, timeout=timeout,
    )
    if proc.returncode != 0:
        return FaithfulnessResult(raw_answers=[], expected=[], correct=[False] * 5, score=0.0)
    raw = _parse_quiz_answers(proc.stdout)
    expected = _expected_from_envelope(envelope)
    correct = [_check(raw[i], expected[i], i) for i in range(5)]
    score = sum(correct) / 5.0
    return FaithfulnessResult(raw_answers=raw, expected=expected, correct=correct, score=score)


if __name__ == "__main__":
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--trailer", required=True, help="path to trailer text file")
    ap.add_argument("--envelope", required=True, help="path to parsed envelope JSON")
    args = ap.parse_args()

    env = json.loads(Path(args.envelope).read_text())
    text = Path(args.trailer).read_text()
    res = score_faithfulness(env, text)
    print(json.dumps({
        "score": res.score,
        "raw_answers": res.raw_answers,
        "expected": res.expected,
        "correct": res.correct,
    }, indent=2))
