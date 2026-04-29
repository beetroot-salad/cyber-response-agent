"""PREDICT variant-calibration runner.

For each (variant, case, rep): stages a temp run dir from the fixture, builds
the production PREDICT user prompt via the handler's `_assemble_prompt`, then
spawns `claude -p --system-prompt-file <variant>` directly (bypasses the
orchestrator — PREDICT in isolation, no GATHER / ANALYZE downstream).

Captures stdout to `runs/{variant}/{case-id}/rep-{N}/predict_output.txt` and
the parsed YAML envelope to `runs/{variant}/{case-id}/rep-{N}/envelope.yaml`.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path

import yaml

REPO_ROOT = Path(os.environ.get("PREDICT_EVAL_REPO_ROOT", "/workspace"))
SOC_AGENT_ROOT = REPO_ROOT / "soc-agent"
EVALS_ROOT = REPO_ROOT / "evals" / "predict"
CASES_DIR = EVALS_ROOT / "cases"
FIXTURES_DIR = EVALS_ROOT / "fixtures"
VARIANTS_DIR = EVALS_ROOT / "variants"
RUNS_DIR = EVALS_ROOT / "runs"

sys.path.insert(0, str(SOC_AGENT_ROOT))
sys.path.insert(0, str(SOC_AGENT_ROOT / "scripts"))

from schemas.state import Phase  # noqa: E402
from scripts.handlers.predict import _assemble_prompt  # noqa: E402


@dataclass
class Cell:
    variant: str
    case_id: str
    rep: int
    case_yaml: dict
    fixture_dir: Path
    out_dir: Path = field(init=False)

    def __post_init__(self) -> None:
        self.out_dir = RUNS_DIR / self.variant / self.case_id / f"rep-{self.rep}"


@dataclass
class FakeContext:
    run_dir: Path
    signature_id: str
    ticket_id: str
    alert: dict
    outputs: dict = field(default_factory=dict)
    history: list = field(default_factory=list)
    current_phase: object = None
    forced_report: bool = False


def _stage_run_dir(cell: Cell) -> Path:
    """Create a fresh run dir mirroring what setup_run.py would produce."""
    run_dir = cell.out_dir / "run"
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True)
    (run_dir / "subagent_checkpoints").mkdir()

    alert_src = cell.fixture_dir / "alert.json"
    if not alert_src.exists():
        raise FileNotFoundError(f"fixture missing alert.json: {alert_src}")
    shutil.copy(alert_src, run_dir / "alert.json")

    inv_src = cell.fixture_dir / "investigation.md"
    if inv_src.exists():
        shutil.copy(inv_src, run_dir / "investigation.md")
    else:
        (run_dir / "investigation.md").write_text("")

    salt = secrets.token_hex(8)
    meta = {
        "run_id": run_dir.name,
        "signature_id": cell.case_yaml["signature_id"],
        "severity": "medium",
        "salt": salt,
    }
    (run_dir / "meta.json").write_text(json.dumps(meta, indent=2))
    return run_dir


def _build_history_for_loop(loop_n: int) -> list[str]:
    """Synthesize a history list that yields the right loop_n.

    `_compute_loop_n` counts prior PREDICT phase entries + 1, minus 1 if the
    current_phase is PREDICT and prior > 0. We set current_phase=PREDICT and
    pad the history with (loop_n) PREDICT entries — the function returns
    `loop_n - 1 + 1 = loop_n`.
    """
    return [Phase.PREDICT.value] * loop_n


def _build_context(cell: Cell, run_dir: Path) -> FakeContext:
    alert = json.loads((run_dir / "alert.json").read_text())
    return FakeContext(
        run_dir=run_dir,
        signature_id=cell.case_yaml["signature_id"],
        ticket_id="EVAL-FIXTURE",
        alert=alert,
        history=_build_history_for_loop(cell.case_yaml.get("loop_n", 1)),
        current_phase=Phase.PREDICT,
    )


def _split_frontmatter(body: str) -> str:
    """Strip YAML frontmatter from a variant prompt file."""
    if body.startswith("---\n"):
        end = body.find("\n---\n", 4)
        if end != -1:
            return body[end + 5:]
    return body


def _invoke_claude(variant_path: Path, user_prompt: str, *, timeout: int = 300) -> tuple[int, str, str]:
    body = _split_frontmatter(variant_path.read_text())
    sys_prompt_file = variant_path.parent / f".tmp-sysprompt-{uuid.uuid4().hex[:8]}.md"
    sys_prompt_file.write_text(body)
    try:
        env = dict(os.environ)
        venv_bin = SOC_AGENT_ROOT / ".venv" / "bin"
        if venv_bin.is_dir():
            env["PATH"] = f"{venv_bin}:{env.get('PATH', '')}"
            env["VIRTUAL_ENV"] = str(SOC_AGENT_ROOT / ".venv")

        argv = [
            "claude", "-p",
            "--model", "sonnet",
            "--system-prompt-file", str(sys_prompt_file),
            "--session-id", str(uuid.uuid4()),
            "--plugin-dir", str(SOC_AGENT_ROOT),
            "--output-format", "text",
            "--allowed-tools", "Bash,Read,Write",
            "--effort", "low",
        ]
        result = subprocess.run(
            argv, input=user_prompt,
            capture_output=True, text=True, timeout=timeout,
            env=env, cwd=str(SOC_AGENT_ROOT),
        )
        return result.returncode, result.stdout, result.stderr
    finally:
        sys_prompt_file.unlink(missing_ok=True)


_YAML_FENCE = re.compile(r"```(?:yaml)?\n(.*?)\n```", re.DOTALL)


def _extract_envelope(stdout: str) -> dict | None:
    """Pull the predict: YAML envelope out of stdout."""
    for match in _YAML_FENCE.finditer(stdout):
        try:
            doc = yaml.safe_load(match.group(1))
        except yaml.YAMLError:
            continue
        if isinstance(doc, dict) and "predict" in doc:
            return doc
    return None


def run_cell(cell: Cell) -> dict:
    """Execute one cell, persist outputs, return a small result record."""
    cell.out_dir.mkdir(parents=True, exist_ok=True)
    started = time.monotonic()
    result_record: dict = {
        "variant": cell.variant,
        "case_id": cell.case_id,
        "rep": cell.rep,
        "started_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    try:
        run_dir = _stage_run_dir(cell)
        ctx = _build_context(cell, run_dir)
        try:
            user_prompt = _assemble_prompt(ctx)
        except Exception as exc:
            result_record.update({"status": "prompt_assembly_failed", "error": repr(exc)})
            (cell.out_dir / "result.json").write_text(json.dumps(result_record, indent=2))
            return result_record
        (cell.out_dir / "user_prompt.txt").write_text(user_prompt)

        variant_path = VARIANTS_DIR / f"{cell.variant}.md"
        rc, stdout, stderr = _invoke_claude(variant_path, user_prompt)

        (cell.out_dir / "predict_output.txt").write_text(stdout)
        (cell.out_dir / "stderr.txt").write_text(stderr)

        envelope = _extract_envelope(stdout)
        if envelope is not None:
            (cell.out_dir / "envelope.yaml").write_text(yaml.safe_dump(envelope, sort_keys=False))
            result_record["status"] = "ok"
            result_record["shape"] = envelope.get("predict", {}).get("shape")
        else:
            checkpoint = run_dir / "subagent_checkpoints" / f"predict-loop-{cell.case_yaml.get('loop_n', 1)}.yaml"
            if checkpoint.exists():
                (cell.out_dir / "envelope.yaml").write_text(checkpoint.read_text())
                result_record["status"] = "ok_via_checkpoint"
            else:
                result_record["status"] = "no_envelope"

        result_record["return_code"] = rc
        result_record["wall_seconds"] = round(time.monotonic() - started, 1)
    except Exception as exc:
        result_record.update({"status": "exception", "error": repr(exc)})
    (cell.out_dir / "result.json").write_text(json.dumps(result_record, indent=2))
    return result_record


def _load_cases(case_filter: list[str] | None) -> list[dict]:
    cases = []
    for path in sorted(CASES_DIR.glob("case-*.yaml")):
        doc = yaml.safe_load(path.read_text())
        if case_filter and doc["case_id"] not in case_filter:
            continue
        cases.append(doc)
    return cases


def _expand_cells(variants: list[str], cases: list[dict], reps: int) -> list[Cell]:
    cells = []
    for variant in variants:
        if not (VARIANTS_DIR / f"{variant}.md").exists():
            raise FileNotFoundError(f"missing variant: {variant}.md")
        for case in cases:
            fixture_dir = REPO_ROOT / case["inputs"]["alert_path"].rsplit("/", 1)[0]
            for rep in range(1, reps + 1):
                cells.append(Cell(
                    variant=variant, case_id=case["case_id"], rep=rep,
                    case_yaml=case, fixture_dir=fixture_dir,
                ))
    return cells


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--variant", action="append", default=None,
                        help="variant to run (repeatable). Default: all under variants/")
    parser.add_argument("--case", action="append", default=None,
                        help="case_id to run (repeatable). Default: all under cases/")
    parser.add_argument("--reps", type=int, default=3, help="reps per cell")
    parser.add_argument("--parallel", type=int, default=4, help="parallel cells")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if args.variant:
        variants = args.variant
    else:
        variants = sorted(p.stem for p in VARIANTS_DIR.glob("V*.md"))
    cases = _load_cases(args.case)
    cells = _expand_cells(variants, cases, args.reps)

    print(f"[runner] {len(cells)} cells: {len(variants)} variants × {len(cases)} cases × {args.reps} reps")
    print(f"[runner] variants: {variants}")
    print(f"[runner] cases: {[c['case_id'] for c in cases]}")
    if args.dry_run:
        return 0

    completed = 0
    failed = 0
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=args.parallel) as pool:
        futures = {pool.submit(run_cell, cell): cell for cell in cells}
        for fut in as_completed(futures):
            cell = futures[fut]
            try:
                rec = fut.result()
                status = rec.get("status", "?")
                shape = rec.get("shape", "-")
                wall = rec.get("wall_seconds", "?")
                if status not in ("ok", "ok_via_checkpoint"):
                    failed += 1
                completed += 1
                print(f"[{completed}/{len(cells)}] {cell.variant}/{cell.case_id}/rep-{cell.rep}: "
                      f"status={status} shape={shape} wall={wall}s")
            except Exception as exc:
                failed += 1
                completed += 1
                print(f"[{completed}/{len(cells)}] {cell.variant}/{cell.case_id}/rep-{cell.rep}: "
                      f"EXCEPTION {exc!r}")

    print(f"[runner] done in {round(time.monotonic() - started, 1)}s; "
          f"{completed - failed}/{completed} ok, {failed} failed")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
