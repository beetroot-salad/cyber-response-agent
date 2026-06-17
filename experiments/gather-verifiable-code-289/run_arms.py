#!/usr/bin/env python3
"""#289 pilot harness — replay ONE gather dispatch in-process, per (variant, fixture).

Isolates the gather subagent (the variable under test) from the main loop:
build the real PydanticAI gather agent (Haiku, the same `register_tools`
surface and in-process permission gate as production), but
  * override its `instructions` with the variant SKILL (current | proposed), and
  * shadow `defender-elastic` with a fake adapter that returns the fixture's
    frozen payload — so gather's query is captured + truncated through the real
    record_query path (the truncation pressure is central to the large-dump arm),
    with no live elastic.

Everything else is production code: tools.py, permission.py, record_query.py,
the (proposed) record_analysis.py wrapper, observe.py logging.

Usage:
    python3 run_arms.py --variant proposed --fixture same-second-session --trials 1
    python3 run_arms.py --variant current  --fixture large-sshd-dump   --trials 10 --idx-start 0

Each trial writes runs/{fixture}__{variant}__{idx}/ with: alert.json, gather_raw/,
executed_queries.jsonl, analyses.jsonl (proposed), llm_requests.jsonl, tool_trace.jsonl,
summary.md (gather's return), meta.json (wall_ms, tokens, requests, exit reason).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Re-exec into defender/.venv (pydantic-ai lives there) — mirrors run_pai.py.
_EXP_DIR = Path(__file__).resolve().parent
_DEFENDER_DIR = _EXP_DIR.parents[1] / "defender"
_VENV_PY = _DEFENDER_DIR / ".venv" / "bin" / "python3"
if __name__ == "__main__" and _VENV_PY.is_file() and Path(sys.executable) != _VENV_PY:
    os.execv(str(_VENV_PY), [str(_VENV_PY), __file__, *sys.argv[1:]])

import argparse  # noqa: E402
import asyncio  # noqa: E402
import json  # noqa: E402
import shutil  # noqa: E402
import time  # noqa: E402

# Workspace root on sys.path → `defender.*` namespace imports resolve, as in run_pai.
if (_root := str(_DEFENDER_DIR.parent)) not in sys.path:
    sys.path.insert(0, _root)

import yaml  # noqa: E402
from pydantic_ai import Agent  # noqa: E402
from pydantic_ai.models.anthropic import AnthropicModel  # noqa: E402
from pydantic_ai.usage import UsageLimits  # noqa: E402
from pydantic_ai.exceptions import UsageLimitExceeded  # noqa: E402

from defender.runtime import driver, observe, tools  # noqa: E402
from defender.hooks.inject_system_skill_description import read_description  # noqa: E402

FIXTURES = _EXP_DIR / "fixtures"
VARIANTS = _EXP_DIR / "variants"
RUNS = _EXP_DIR / "runs"
PROPOSED_BIN = VARIANTS / "proposed" / "bin"
RECORD_ANALYSIS_PY = VARIANTS / "proposed" / "record_analysis.py"
FAKEBIN = VARIANTS / "_fakebin"


def _ensure_fakebin() -> Path:
    """A `defender-elastic` that ignores argv and serves $FAKE_PAYLOAD — shadows
    the real adapter so gather's query is captured against the frozen fixture."""
    FAKEBIN.mkdir(parents=True, exist_ok=True)
    shim = FAKEBIN / "defender-elastic"
    shim.write_text(
        "#!/usr/bin/env bash\n"
        '# fake elastic adapter (#289 harness): return the frozen fixture payload.\n'
        'cat "${FAKE_PAYLOAD:?FAKE_PAYLOAD unset}"\n'
    )
    shim.chmod(0o755)
    return FAKEBIN


def _patched_bash_env(fixture_payload: Path):
    """Wrap tools._bash_env so every gather shell call (the captured adapter, jq,
    defender-record-analysis) runs with: fakebin + proposed bin ahead of defender/bin,
    FAKE_PAYLOAD pointing at the fixture, and RECORD_ANALYSIS_PY for the shim."""
    orig = tools._bash_env

    def wrapper(deps):
        env = dict(orig(deps))
        sep = os.pathsep
        env["PATH"] = f"{FAKEBIN}{sep}{PROPOSED_BIN}{sep}{env.get('PATH', '')}"
        env["FAKE_PAYLOAD"] = str(fixture_payload)
        env["RECORD_ANALYSIS_PY"] = str(RECORD_ANALYSIS_PY)
        return env

    return wrapper


def _build_gather_agent(instructions: str, logger: observe.RequestLogger, agent_id: str) -> Agent:
    """driver.build_gather_agent, but with instructions overridden by the variant
    SKILL text instead of read from disk (the one variable under test)."""
    agent = Agent(
        AnthropicModel(driver.GATHER_MODEL),
        deps_type=tools.GatherDeps,
        instructions=instructions,
        capabilities=[driver._make_hooks(logger, agent_id)],
        model_settings=driver._CACHE_SETTINGS,
        retries=driver.DEFAULT_TOOL_RETRIES,
    )
    tools.register_tools(agent)
    return agent


async def _run_one(variant: str, fixture: str, idx: int, request_limit: int) -> dict:
    fx = FIXTURES / fixture
    lead = yaml.safe_load((fx / "lead.yaml").read_text())
    instructions = (VARIANTS / variant / "gather-SKILL.md").read_text()

    run_id = f"{fixture}__{variant}__{idx:02d}"
    run_dir = RUNS / run_id
    if run_dir.exists():
        shutil.rmtree(run_dir)
    (run_dir / "gather_raw").mkdir(parents=True)
    shutil.copy(fx / "alert.json", run_dir / "alert.json")

    _ensure_fakebin()
    tools._bash_env = _patched_bash_env(fx / "gather_raw" / "0.json")  # type: ignore[assignment]

    logger = observe.RequestLogger(run_dir / "llm_requests.jsonl")
    agent_id = f"gather:{lead['lead_id']}"
    gagent = _build_gather_agent(instructions, logger, agent_id)

    deps = tools.GatherDeps(
        run_dir=run_dir, defender_dir=_DEFENDER_DIR, run_id=run_id,
        salt="exp289", is_main_session=False, lead_id=lead["lead_id"],
    )
    desc = read_description(lead["system"])
    prompt = tools._gather_prompt(
        deps, lead["lead_id"], lead["system"], lead["goal"],
        list(lead["what_to_summarize"]), desc,
    )

    t0 = time.time()
    exit_reason = "ok"
    output = ""
    try:
        result = await gagent.run(
            prompt, deps=deps,
            usage_limits=UsageLimits(request_limit=request_limit),
        )
        output = str(result.output or "")
    except UsageLimitExceeded as e:
        exit_reason = f"request_limit: {e}"
    except Exception as e:  # noqa: BLE001 — record the failure, keep the batch going
        exit_reason = f"error: {type(e).__name__}: {e}"
    wall_ms = (time.time() - t0) * 1000.0

    observe.write_trace(run_dir, logger.messages, wall_ms=wall_ms)
    logger.close()
    (run_dir / "summary.md").write_text(output)

    totals = observe._usage_totals(logger.messages)
    meta = {
        "variant": variant, "fixture": fixture, "idx": idx, "run_id": run_id,
        "request_limit": request_limit,
        "wall_ms": round(wall_ms, 1), "n_requests": logger.n_requests,
        "exit_reason": exit_reason, "usage": totals,
        "n_queries": _count_lines(run_dir / "executed_queries.jsonl"),
        "n_analyses": _count_lines(run_dir / "analyses.jsonl"),
        "summary_chars": len(output),
    }
    (run_dir / "meta.json").write_text(json.dumps(meta, indent=2))
    print(f"  [{run_id}] {exit_reason:14} reqs={logger.n_requests} "
          f"queries={meta['n_queries']} analyses={meta['n_analyses']} "
          f"out_tok={totals.get('output_tokens')} wall={wall_ms/1000:.1f}s")
    return meta


def _count_lines(p: Path) -> int:
    if not p.is_file():
        return 0
    return sum(1 for ln in p.read_text().splitlines() if ln.strip())


async def _main_async(ns) -> int:
    RUNS.mkdir(exist_ok=True)
    metas = []
    for idx in range(ns.idx_start, ns.idx_start + ns.trials):
        metas.append(await _run_one(ns.variant, ns.fixture, idx, ns.request_limit))
    return 0


def main(argv: list[str]) -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--variant", required=True, choices=["current", "proposed"])
    p.add_argument("--fixture", required=True,
                   help="fixture dir name under fixtures/ (e.g. large-sshd-dump)")
    p.add_argument("--trials", type=int, default=1)
    p.add_argument("--idx-start", type=int, default=0)
    # Production GATHER_REQUEST_LIMIT is 20; the validation pass showed that is too
    # tight for either variant to FINISH a 4MB/6-dimension dump (#289 finding). Run
    # the arms at 40 so fidelity is measurable; 20-is-insufficient is reported apart.
    p.add_argument("--request-limit", type=int, default=40)
    ns = p.parse_args(argv)
    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("[run_arms] ERROR: ANTHROPIC_API_KEY unset", file=sys.stderr)
        return 2
    if not (FIXTURES / ns.fixture / "lead.yaml").is_file():
        print(f"[run_arms] no such fixture: {ns.fixture}", file=sys.stderr)
        return 2
    print(f"[run_arms] {ns.variant} × {ns.fixture} × {ns.trials} trial(s)")
    return asyncio.run(_main_async(ns))


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
