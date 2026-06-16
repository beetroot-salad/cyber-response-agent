"""Invocation test harness for the gather subagent.

Spawns gather via `claude -p --bare` against a fixture-defined dispatch and
records whether gather invoked the `data_source_debug.py` wrapper. The test
question is not "did gather summarize correctly" but "did gather fire the
§3.5 wrapper at the right times and skip it at the wrong times."

The sandbox mirrors enough of the defender layout that gather's prompt
(which references `{defender_dir}/skills/...` and `{defender_dir}/scripts/...`)
resolves to stub paths. Stubs return canned payloads and trace their own
invocations to a JSONL file the test reads back.

Each fixture is a directory under `fixtures/` containing:
    alert.json          # what gather Reads in §1
    elastic_payload.json  # what stub elastic_cli returns to gather
    system_skill.md     # the system SKILL.md gather Reads in §1; controls cache
    dispatch.json       # the dispatch parameters (goal, what_to_summarize, ...)
    expected.json       # assertion targets (wrapper_invoked, return_must_contain)
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

# Locate the defender repo root from this file's path.
_THIS = Path(__file__).resolve()
DEFENDER_ROOT = _THIS.parent.parent.parent   # defender/
HARNESS_ROOT = _THIS.parent
STUBS_DIR = HARNESS_ROOT / "stubs"
FIXTURES_DIR = HARNESS_ROOT / "fixtures"

sys.path.insert(0, str(DEFENDER_ROOT))
from dispatch import render_gather_dispatch  # noqa: E402


@dataclass
class InvocationResult:
    """What one harness run produced."""
    fixture: str
    trial: int
    wrapper_invoked: bool
    wrapper_calls: list[dict]
    stdout: str
    stderr: str
    return_code: int
    duration_s: float
    sandbox_dir: Path

    def diagnostics(self) -> str:
        """Multi-line summary for assertion failures."""
        return (
            f"fixture={self.fixture} trial={self.trial}\n"
            f"  wrapper_invoked={self.wrapper_invoked} ({len(self.wrapper_calls)} call(s))\n"
            f"  return_code={self.return_code} duration={self.duration_s:.1f}s\n"
            f"  sandbox={self.sandbox_dir}\n"
            f"  stdout tail: {self.stdout[-400:]!r}\n"
            f"  stderr tail: {self.stderr[-400:]!r}\n"
        )


def _build_sandbox(sandbox: Path, fixture_dir: Path, system: str) -> None:
    """Materialize {sandbox}/ with the layout gather's prompt references."""
    (sandbox / "skills" / "gather").mkdir(parents=True)
    (sandbox / "skills" / system).mkdir(parents=True)
    (sandbox / "scripts" / "tools").mkdir(parents=True)

    # Real gather SKILL — gather reads it from disk in §1.
    shutil.copy(
        DEFENDER_ROOT / "skills" / "gather" / "SKILL.md",
        sandbox / "skills" / "gather" / "SKILL.md",
    )
    # Fixture system SKILL — controls cache state for §3.5 Step 1.
    shutil.copy(
        fixture_dir / "system_skill.md",
        sandbox / "skills" / system / "SKILL.md",
    )
    # Stub CLIs at the paths gather constructs from {defender_dir}.
    # Copy every .py stub so per-fixture system variation (elastic, cmdb,
    # ...) all resolve without harness changes.
    for stub in STUBS_DIR.glob("*.py"):
        dst = sandbox / "scripts" / "tools" / stub.name
        shutil.copy(stub, dst)
        dst.chmod(0o755)


def _build_run_dir(sandbox: Path, fixture_dir: Path) -> Path:
    """Materialize the run_dir gather Reads alert.json from + writes outputs to."""
    run_id = f"harness-{int(time.time() * 1000)}"
    run_dir = sandbox / "runs" / run_id
    (run_dir / "gather_raw").mkdir(parents=True)
    shutil.copy(fixture_dir / "alert.json", run_dir / "alert.json")
    return run_dir


def _load_dispatch_params(fixture_dir: Path) -> dict:
    """Read the per-fixture dispatch parameters."""
    return json.loads((fixture_dir / "dispatch.json").read_text())


def _load_system_description(fixture_dir: Path) -> str | None:
    """Extract the SKILL.md frontmatter description (mimics the live hook)."""
    text = (fixture_dir / "system_skill.md").read_text()
    if not text.startswith("---"):
        return None
    end = text.find("---", 3)
    if end == -1:
        return None
    front = text[3:end]
    for line in front.splitlines():
        line = line.strip()
        if line.startswith("description:"):
            return line.split(":", 1)[1].strip().strip('"').strip("'")
    return None


def run_fixture(
    fixture_name: str,
    *,
    trial: int = 0,
    tmp_root: Path | None = None,
    model: str = "claude-haiku-4-5-20251001",
    timeout_s: int = 300,
) -> InvocationResult:
    """Run gather against one fixture, return an InvocationResult.

    Production dispatches gather on Haiku; we calibrate against the same
    model. Use `--bare` so project CLAUDE.md / hooks / memory don't leak in.
    """
    fixture_dir = FIXTURES_DIR / fixture_name
    if not fixture_dir.is_dir():
        raise FileNotFoundError(f"fixture not found: {fixture_dir}")

    tmp_root = tmp_root or Path("/tmp")
    sandbox = tmp_root / f"gather-invocation-{fixture_name}-t{trial}-{int(time.time() * 1000)}"
    sandbox.mkdir(parents=True)

    params = _load_dispatch_params(fixture_dir)
    system = params["system"]
    _build_sandbox(sandbox, fixture_dir, system)
    run_dir = _build_run_dir(sandbox, fixture_dir)

    trace_path = sandbox / "dsd_trace.jsonl"
    trace_path.write_text("")  # zero-byte sentinel — easier than try/except on read

    # Per-sandbox settings: explicit allow-list scoped to the sandbox.
    # `bypassPermissions` (and `--dangerously-skip-permissions`) are both
    # blocked under root, so we list each capability gather needs against
    # the sandbox tree. Permissive within the sandbox, nothing outside.
    settings_path = sandbox / "settings.json"
    sb = str(sandbox)
    settings_path.write_text(json.dumps({
        "permissions": {
            "defaultMode": "acceptEdits",
            "allow": [
                f"Read({sb}/**)",
                f"Write({sb}/**)",
                f"Edit({sb}/**)",
                f"Glob({sb}/**)",
                f"Grep({sb}/**)",
                f"Bash(python3 {sb}/scripts/tools/*.py *)",
                "Bash(defender-* *)",
                "Bash(ls *)",
                "Bash(cat *)",
                "Bash(jq *)",
            ],
        }
    }))

    prompt = render_gather_dispatch(
        defender_dir=sandbox,
        run_dir=run_dir,
        lead_id=params.get("lead_id", "l-001"),
        system=system,
        goal=params["goal"],
        what_to_summarize=params["what_to_summarize"],
        system_skill_description=_load_system_description(fixture_dir),
    )

    env = dict(os.environ)
    # Strip the first-party key so this real `claude -p` bills against the
    # subscription, never the metered API key (reserved for PydanticAI). Mirrors
    # run.py's run_env().
    env.pop("ANTHROPIC_API_KEY", None)
    env["STUB_ELASTIC_PAYLOAD"] = str(fixture_dir / "elastic_payload.json")
    env["STUB_DSD_TRACE"] = str(trace_path)
    # Make the `defender-*` invocation shims resolve against the sandbox stubs:
    # the real shims (on PATH) read DEFENDER_DIR at runtime and fall back to
    # system python3 when the sandbox has no venv. Mirrors run.py's spawn env.
    env["PATH"] = f"{DEFENDER_ROOT / 'bin'}{os.pathsep}{env.get('PATH', '')}"
    env["DEFENDER_DIR"] = str(sandbox)
    env["DEFENDER_RUNS_BASE"] = str(sandbox / "runs")
    # Optional per-fixture verdict override.
    verdict = fixture_dir / "dsd_verdict.txt"
    if verdict.exists():
        env["STUB_DSD_VERDICT"] = str(verdict)

    cmd = [
        "claude",
        "-p",
        "--model", model,
        "--settings", str(settings_path),
        "--add-dir", str(sandbox),
    ]

    started = time.time()
    proc = subprocess.run(
        cmd,
        input=prompt,
        env=env,
        cwd=str(sandbox),
        capture_output=True,
        text=True,
        timeout=timeout_s,
    )
    duration = time.time() - started

    wrapper_calls = []
    if trace_path.exists():
        for line in trace_path.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                wrapper_calls.append(json.loads(line))
            except json.JSONDecodeError:
                pass

    return InvocationResult(
        fixture=fixture_name,
        trial=trial,
        wrapper_invoked=len(wrapper_calls) > 0,
        wrapper_calls=wrapper_calls,
        stdout=proc.stdout,
        stderr=proc.stderr,
        return_code=proc.returncode,
        duration_s=duration,
        sandbox_dir=sandbox,
    )


def load_expected(fixture_name: str) -> dict:
    """Read the expected.json next to the fixture."""
    return json.loads((FIXTURES_DIR / fixture_name / "expected.json").read_text())


if __name__ == "__main__":
    # CLI for ad-hoc probing: `python harness.py F1_sentinel_no_cache`.
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("fixture")
    p.add_argument("--trials", type=int, default=1)
    p.add_argument("--keep-sandbox", action="store_true")
    args = p.parse_args()

    for trial in range(args.trials):
        r = run_fixture(args.fixture, trial=trial)
        print(r.diagnostics())
        if not args.keep_sandbox:
            shutil.rmtree(r.sandbox_dir, ignore_errors=True)
