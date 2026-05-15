#!/usr/bin/env python3
"""Tier 1 customization-test runner for the defender query catalog.

For each case in a ``customization.yaml`` fixture file, render a prompt
that asks Haiku to adapt the catalog template to a specific need, then
score the resulting SIEM CLI command against an inline rubric
(``expected_substrings`` / ``forbidden_substrings``). The fixture
schema lives in ``defender/skills/gather/queries/tests/SCHEMA.md``.

Per-case verdict: ``pass`` if at least ``ceil(trials * 2/3)`` trials
satisfy the rubric (every expected substring present, no forbidden
substring present). Cases are independent; the file verdict is
``pass`` only when every case passes.

CLI::

    python3 -m defender.learning.customization_test <template-path> <customization-yaml> [--trials 3]

Invoke from the workspace root so ``defender.learning`` resolves as a
package.
"""
from __future__ import annotations

import argparse
import json
import math
import re
import sys
from pathlib import Path
from typing import Any

import yaml

try:
    from defender.learning._agent_stream import AgentStreamError, run_streaming
except ImportError:  # pragma: no cover — direct-script execution fallback
    from _agent_stream import AgentStreamError, run_streaming  # type: ignore[no-redef]


REPO_ROOT = Path(__file__).resolve().parents[2]
PROMPT_PATH = Path(__file__).parent / "customization_prompt.md"

CUSTOMIZATION_MODEL = "haiku"
CUSTOMIZATION_TIMEOUT = 180


_SECTION_RE = re.compile(r"^## (.+)$", re.MULTILINE)


def split_template(text: str) -> tuple[str, str]:
    """Return (definition_md, template_md) for a defender query template.

    Definition keeps the intent surface (Goal, What to characterize,
    Common pitfalls, Baseline). Template keeps the worked example
    (Query, Filter binding). Frontmatter is stripped — the customizer
    doesn't need the ``id:`` key. Section order is preserved.
    """
    body = text
    if body.startswith("---\n"):
        end = body.find("\n---", 4)
        if end != -1:
            body = body[end + 4 :].lstrip("\n")

    definition_sections = {
        "Goal",
        "What to characterize",
        "Common pitfalls",
        "Baseline",
    }
    template_sections = {"Query", "Filter binding"}

    sections: list[tuple[str, str]] = []
    matches = list(_SECTION_RE.finditer(body))
    for i, m in enumerate(matches):
        name = m.group(1).strip()
        start = m.start()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(body)
        sections.append((name, body[start:end].rstrip() + "\n"))

    def_parts = [
        chunk for (name, chunk) in sections if name in definition_sections
    ]
    tpl_parts = [
        chunk for (name, chunk) in sections if name in template_sections
    ]
    return "".join(def_parts).rstrip() + "\n", "".join(tpl_parts).rstrip() + "\n"


def render_prompt(
    *, definition_md: str, template_md: str, case: dict
) -> str:
    """Substitute the four placeholders in the prompt template."""
    if not PROMPT_PATH.is_file():
        raise FileNotFoundError(PROMPT_PATH)
    raw = PROMPT_PATH.read_text()
    alert_excerpt = case.get("alert_excerpt") or {}
    adaptation_note = case.get("adaptation_note") or ""
    return (
        raw
        .replace("{definition_md}", definition_md)
        .replace("{template_md}", template_md)
        .replace("{alert_excerpt}", json.dumps(alert_excerpt, indent=2))
        .replace("{adaptation_note}", adaptation_note)
    )


def score_output(stdout: str, rubric: dict) -> tuple[bool, dict]:
    """Apply expected/forbidden-substring rubric. Returns (pass, detail)."""
    expected = rubric.get("expected_substrings") or []
    forbidden = rubric.get("forbidden_substrings") or []
    missing = [s for s in expected if s not in stdout]
    present_forbidden = [s for s in forbidden if s in stdout]
    passed = not missing and not present_forbidden
    return passed, {
        "missing_expected": missing,
        "present_forbidden": present_forbidden,
    }


def invoke_haiku(prompt: str, *, log_dir: Path, case_id: str) -> str:
    """Spawn ``claude -p --model haiku``; return concatenated assistant text.

    Uses the shared streaming/deadline machinery so a stalled child
    cannot wedge the runner. Raises a runtime error on subprocess
    failure — callers translate to per-case ``error`` results.
    """
    cmd = [
        "claude",
        "--print",
        "--model",
        CUSTOMIZATION_MODEL,
        "--output-format",
        "stream-json",
        "--verbose",
    ]
    log_dir.mkdir(parents=True, exist_ok=True)
    return run_streaming(
        cmd,
        user_prompt=prompt,
        cwd=REPO_ROOT,
        timeout_seconds=CUSTOMIZATION_TIMEOUT,
        log_path=log_dir / f"{case_id}.jsonl",
        log_header={"case_id": case_id, "model": CUSTOMIZATION_MODEL},
        log_prefix="customization",
    )


def run_case(
    *,
    definition_md: str,
    template_md: str,
    case: dict,
    trials: int,
    log_dir: Path,
    invoker: Any = invoke_haiku,
) -> dict:
    """Run ``trials`` independent invocations and aggregate per the 2/3 rule."""
    case_id = case.get("id") or "<anonymous>"
    rubric = case.get("rubric") or {}
    prompt = render_prompt(
        definition_md=definition_md, template_md=template_md, case=case
    )
    needed = math.ceil(trials * 2 / 3)
    trial_records: list[dict] = []
    passes = 0
    for trial in range(1, trials + 1):
        trial_log = log_dir / case_id
        trial_log.mkdir(parents=True, exist_ok=True)
        try:
            stdout = invoker(prompt, log_dir=trial_log, case_id=f"trial-{trial}")
        except AgentStreamError as e:
            trial_records.append(
                {"trial": trial, "passed": False, "error": str(e)}
            )
            continue
        ok, detail = score_output(stdout, rubric)
        trial_records.append(
            {
                "trial": trial,
                "passed": ok,
                "missing_expected": detail["missing_expected"],
                "present_forbidden": detail["present_forbidden"],
                "output_tail": stdout[-400:],
            }
        )
        if ok:
            passes += 1
    return {
        "case_id": case_id,
        "trials": trials,
        "passes": passes,
        "threshold": needed,
        "passed": passes >= needed,
        "trials_detail": trial_records,
    }


def run_file(
    template_path: Path,
    customization_path: Path,
    *,
    trials: int,
    out_dir: Path | None = None,
    invoker: Any = invoke_haiku,
) -> dict:
    """Run every case in ``customization_path`` against ``template_path``."""
    template_text = template_path.read_text()
    definition_md, template_md = split_template(template_text)
    doc = yaml.safe_load(customization_path.read_text())
    if not isinstance(doc, dict) or "cases" not in doc:
        raise ValueError(
            f"{customization_path}: top-level mapping with 'cases:' required"
        )
    cases = doc["cases"]
    if not isinstance(cases, list):
        raise ValueError(f"{customization_path}: 'cases' must be a list")
    log_dir = out_dir or (
        REPO_ROOT
        / "defender"
        / "learning"
        / "_pending"
        / "customization_logs"
        / template_path.stem
    )
    results = []
    for case in cases:
        if not isinstance(case, dict):
            raise ValueError(f"{customization_path}: case must be a mapping")
        results.append(
            run_case(
                definition_md=definition_md,
                template_md=template_md,
                case=case,
                trials=trials,
                log_dir=log_dir,
                invoker=invoker,
            )
        )
    overall = all(r["passed"] for r in results) if results else True
    return {
        "template_path": str(template_path),
        "customization_path": str(customization_path),
        "trials": trials,
        "verdict": "pass" if overall else "fail",
        "cases": results,
    }


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="customization_test")
    p.add_argument("template", type=Path)
    p.add_argument("customization", type=Path)
    p.add_argument("--trials", type=int, default=3)
    p.add_argument("--out-dir", type=Path, default=None)
    args = p.parse_args(argv)
    if not args.template.is_file():
        print(f"template not found: {args.template}", file=sys.stderr)
        return 2
    if not args.customization.is_file():
        print(f"customization not found: {args.customization}", file=sys.stderr)
        return 2
    result = run_file(
        args.template,
        args.customization,
        trials=args.trials,
        out_dir=args.out_dir,
    )
    print(json.dumps(result, indent=2))
    return 0 if result["verdict"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
