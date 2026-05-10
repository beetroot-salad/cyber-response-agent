#!/usr/bin/env python3
"""Replay harness for predict-analyze-format-ab.

Direct `claude -p` invocation (mirrors soc-agent/scripts/handlers/_subagent.py:225)
with a chosen variant as --system-prompt-file. Fixture prompts are reconstructed
from saved subagent_outputs/.

Usage:
    replay.py ab1 control trial-1
    replay.py ab1 treatment trial-1
    replay.py ab2 control trial-1
    replay.py ab2 treatment trial-1   # also runs downstream analyze (control variant)
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SOC_AGENT_ROOT = Path("/workspace/soc-agent")
FIXTURE_RUN = Path(
    "/tmp/soc-agent-orchestrate-eval/20260429-202152-rule5710/runs/"
    "e00fe8c3-7c47-400e-8df0-ee276651ecc1"
)
# Mirror of fixture's investigation.md + alert.json staged inside /workspace
# so the replayed agent's Read tool can access them without permission denials.
FIXTURE_MIRROR = Path(
    "/workspace/tasks-scratch/predict-analyze-format-ab/fixtures/run-mirror"
)


def _rewrite_paths_to_mirror(prompt: str) -> str:
    """Rewrite the fixture's run_dir + <available_context> paths to the mirror
    inside /workspace. Investigation.md + alert.json are staged there;
    `<available_context>` line ranges remain valid since file contents match."""
    return prompt.replace(str(FIXTURE_RUN), str(FIXTURE_MIRROR))
FIXTURE_PREDICT_OUT = (
    FIXTURE_RUN / "subagent_outputs" / "20260429T203448662999Z-predict-57417cd6.txt"
)
FIXTURE_ANALYZE_OUT = (
    FIXTURE_RUN / "subagent_outputs" / "20260429T204243448642Z-analyze-66833cd2.txt"
)

# Path to handlers package (for parsing/metrics).
sys.path.insert(0, str(SOC_AGENT_ROOT))
sys.path.insert(0, str(SOC_AGENT_ROOT / "scripts"))


# ---------------------------------------------------------------------------
# Fixture prompt extraction
# ---------------------------------------------------------------------------


def _extract_section(path: Path, start_marker: str, end_marker: str) -> str:
    text = path.read_text()
    s = text.index(start_marker) + len(start_marker)
    e = text.index(end_marker, s)
    return text[s:e].strip("\n")


def predict_l2_prompt() -> str:
    return _rewrite_paths_to_mirror(
        _extract_section(FIXTURE_PREDICT_OUT, "=== PROMPT ===\n", "\n=== STDOUT ===")
    )


def predict_l2_reference_stdout() -> str:
    text = FIXTURE_PREDICT_OUT.read_text()
    s = text.index("=== STDOUT ===\n") + len("=== STDOUT ===\n")
    return text[s:]


def analyze_l2_prompt() -> str:
    return _rewrite_paths_to_mirror(
        _extract_section(FIXTURE_ANALYZE_OUT, "=== PROMPT ===\n", "\n=== STDOUT ===")
    )


def analyze_l2_prompt_with_dense(predict_dense: str) -> str:
    """Inject <predict_dense loop=2>...</predict_dense> into the analyze prompt
    immediately before <available_context>."""
    base = analyze_l2_prompt()
    inject = (
        f"<predict_dense loop=2>\n{predict_dense.strip()}\n</predict_dense>\n\n"
    )
    # place between <alert-...> and <available_context>
    marker = "<available_context>"
    if marker not in base:
        raise RuntimeError("expected <available_context> marker in analyze prompt")
    return base.replace(marker, inject + marker, 1)


# ---------------------------------------------------------------------------
# Claude invocation
# ---------------------------------------------------------------------------


def run_claude(system_prompt_file: Path, prompt: str, timeout: int = 900) -> dict:
    argv = [
        "claude",
        "-p",
        "--model", "sonnet",
        "--system-prompt-file", str(system_prompt_file),
        "--plugin-dir", str(SOC_AGENT_ROOT),
        "--add-dir", str(FIXTURE_MIRROR),
        "--output-format", "text",
    ]
    started = time.monotonic()
    try:
        result = subprocess.run(
            argv,
            input=prompt,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(SOC_AGENT_ROOT),
        )
        wall_ms = int((time.monotonic() - started) * 1000)
        return {
            "wall_ms": wall_ms,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    except subprocess.TimeoutExpired:
        return {
            "wall_ms": timeout * 1000,
            "returncode": -1,
            "stdout": "",
            "stderr": f"TIMEOUT after {timeout}s",
        }


# ---------------------------------------------------------------------------
# Parsers / metrics
# ---------------------------------------------------------------------------


def parse_predict_metrics(stdout: str, *, treatment: bool = False) -> dict:
    """Parse predict envelope and extract metrics.

    For treatment, monkey-patch the sentence-ID regex to admit `sN:` prefix.
    """
    from handlers import _predict_dense, _output_parser

    saved_re = _predict_dense._SENTENCE_ID_RE
    if treatment:
        _predict_dense._SENTENCE_ID_RE = re.compile(r"^(s\d+)[\.:]")
    try:
        try:
            res = _output_parser.parse_predict_output(stdout, expected_loop_n=2)
            parsed_ok = True
            error = None
            shape = res.telemetry.get("shape")
            hyps = res.invlang_delta.get("hypotheses", []) or []
            n_hypotheses = len(hyps)
            n_pred_rows = sum(len(h.get("predictions", []) or []) for h in hyps)
        except _output_parser.PredictOutputError as exc:
            parsed_ok = False
            error = str(exc)
            shape = None
            n_hypotheses = 0
            n_pred_rows = 0
    finally:
        _predict_dense._SENTENCE_ID_RE = saved_re

    return {
        "parsed_ok": parsed_ok,
        "parse_error": error,
        "shape": shape,
        "n_hypotheses": n_hypotheses,
        "n_pred_rows": n_pred_rows,
        "stdout_chars": len(stdout),
    }


_X_RULES = {"X1", "X2", "X4", "X5", "X6"}


def parse_analyze_metrics(
    stdout: str, declared_hypothesis_names: dict[str, str] | None = None
) -> dict:
    """Parse the dense analyze envelope. X-class violations live in the parser
    error string when present; we surface them along with grade-tier counts."""
    from handlers import _output_parser

    grade_tiers = {"++": 0, "+": 0, "-": 0, "--": 0}
    surviving = []
    disposition = None
    parsed_ok = False
    error = None
    x_violations: list[str] = []

    try:
        env = _output_parser.parse_analyze_envelope_dense(
            stdout,
            expected_loop_n=2,
            declared_hypothesis_names=declared_hypothesis_names,
        )
        parsed_ok = True
        for rows in (env.resolutions_by_lead or {}).values():
            for r in rows:
                w = r.get("weight")
                if w in grade_tiers:
                    grade_tiers[w] += 1
        routing = env.routing or {}
        surviving = routing.get("surviving_hypotheses") or routing.get("surviving") or []
        disposition = routing.get("disposition")
    except _output_parser.AnalyzeOutputError as exc:
        error = str(exc)
        # detect X-class label inside the error message
        for lab in _X_RULES:
            if f"({lab}," in error or f"({lab})" in error or f", {lab}," in error:
                x_violations.append(lab)
        # still try to extract grades by regex from raw stdout
        for line in stdout.splitlines():
            m = re.match(r"^h-\d+\s+(\S+)\s*(?:→|=>)\s*(\S+)", line)
            if m and m.group(2) in grade_tiers:
                grade_tiers[m.group(2)] += 1

    return {
        "parsed_ok": parsed_ok,
        "parse_error": error,
        "x_violations": x_violations,
        "grade_tiers": grade_tiers,
        "surviving": surviving,
        "disposition": disposition,
        "stdout_chars": len(stdout),
    }


# ---------------------------------------------------------------------------
# Trial runner
# ---------------------------------------------------------------------------


VARIANTS = {
    ("ab1", "control"): ROOT / "variants" / "analyze-yaml-current.md",
    ("ab1", "treatment"): ROOT / "variants" / "analyze-dense-proposed.md",
    ("ab2", "control"): ROOT / "variants" / "predict-nl-current.md",
    ("ab2", "treatment"): ROOT / "variants" / "predict-symbolic-proposed.md",
}


def trial_dir(ab: str, arm: str, trial: str) -> Path:
    p = ROOT / "runs" / f"{ab}-{'analyze' if ab == 'ab1' else 'predict'}" / arm / trial
    p.mkdir(parents=True, exist_ok=True)
    return p


def run_trial(ab: str, arm: str, trial: str) -> dict:
    out_dir = trial_dir(ab, arm, trial)
    variant = VARIANTS[(ab, arm)]

    if ab == "ab1":
        if arm == "control":
            prompt = analyze_l2_prompt()
        else:
            # inject the production reference predict stdout as the dense block
            prompt = analyze_l2_prompt_with_dense(predict_l2_reference_stdout())
        (out_dir / "prompt.txt").write_text(prompt)
        result = run_claude(variant, prompt)
        (out_dir / "stdout.txt").write_text(result["stdout"])
        (out_dir / "stderr.txt").write_text(result["stderr"])
        metrics = parse_analyze_metrics(result["stdout"])
        timing = {
            "wall_ms": result["wall_ms"],
            "returncode": result["returncode"],
            **metrics,
        }
        (out_dir / "timing.json").write_text(json.dumps(timing, indent=2))
        return timing

    # ab2 — predict
    prompt = predict_l2_prompt()
    (out_dir / "prompt.txt").write_text(prompt)
    result = run_claude(variant, prompt)
    (out_dir / "stdout.txt").write_text(result["stdout"])
    (out_dir / "stderr.txt").write_text(result["stderr"])
    metrics = parse_predict_metrics(result["stdout"], treatment=(arm == "treatment"))
    timing = {
        "wall_ms": result["wall_ms"],
        "returncode": result["returncode"],
        **metrics,
    }

    # downstream analyze run with the produced predict envelope
    if metrics.get("parsed_ok"):
        analyze_prompt = analyze_l2_prompt_with_dense(result["stdout"])
        analyze_variant = VARIANTS[("ab1", "treatment")]  # use dense-analyze for downstream
        (out_dir / "downstream-analyze-prompt.txt").write_text(analyze_prompt)
        a_result = run_claude(analyze_variant, analyze_prompt)
        (out_dir / "downstream-analyze-stdout.txt").write_text(a_result["stdout"])
        a_metrics = parse_analyze_metrics(a_result["stdout"])
        timing["downstream_analyze"] = {
            "wall_ms": a_result["wall_ms"],
            **a_metrics,
        }

    (out_dir / "timing.json").write_text(json.dumps(timing, indent=2))
    return timing


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print("usage: replay.py {ab1|ab2} {control|treatment} trial-N", file=sys.stderr)
        return 2
    _, ab, arm, trial = argv
    if (ab, arm) not in VARIANTS:
        print(f"unknown variant: {ab}/{arm}", file=sys.stderr)
        return 2
    result = run_trial(ab, arm, trial)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
