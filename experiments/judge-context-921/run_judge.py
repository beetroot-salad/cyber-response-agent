#!/usr/bin/env python3
"""One judge call: --arm {current,proposed} --fixture <name> --trial N → runs/<arm>/<fixture>/t<N>/."""
from __future__ import annotations
import argparse, json, re, sys, time
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, "/workspace"); sys.path.insert(0, str(HERE / "variants"))
import contexts  # noqa: E402
from defender.learning._pydantic_stage import run_stage  # noqa: E402
from defender.learning.branch.questioner import QuestionerDeps  # noqa: E402
from defender.learning.core.config import StageContext, StageWiring, subagent_timeout  # noqa: E402

DEFAULT_FAMILY = HERE / "family" / "episode" / "family.yaml"
ARMS = {
    "current": ("current", HERE / "variants" / "judge.md"),
    "proposed": ("proposed", HERE / "variants" / "judge.md"),
    "proposed+correlate": ("proposed", HERE / "variants" / "judge_correlate.md"),
}
_FENCE = re.compile(r"```(?:yaml|yml)?\s*\n(.*?)```", re.S)


def fixture(name: str) -> tuple[Path, Path]:
    fx = json.loads((HERE / "fixtures" / f"{name}.json").read_text())
    return Path(fx["run_dir"]), (HERE / fx["family"] if fx.get("family") else DEFAULT_FAMILY)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", required=True, choices=sorted(ARMS))
    ap.add_argument("--fixture", required=True)
    ap.add_argument("--trial", type=int, required=True)
    ap.add_argument("--model", default="kimi-k3")
    ap.add_argument("--effort", default="medium")
    ns = ap.parse_args()
    run_dir, family = fixture(ns.fixture)
    renderer, judge_prompt = ARMS[ns.arm]
    trial_dir = HERE / "runs" / ns.arm / ns.fixture / f"t{ns.trial}"
    trial_dir.mkdir(parents=True, exist_ok=True)
    context = contexts.RENDERERS[renderer](run_dir, family)
    prompt = context + "\n\n---\n\nProduce the YAML judgement now, and nothing else.\n"
    (trial_dir / "prompt.md").write_text(prompt, encoding="utf-8")
    t0 = time.time()
    reply = run_stage(
        stage="judge921",
        wiring=StageWiring(prompt_path=judge_prompt, model=ns.model, effort=ns.effort,
                           trace_name="judge_trace.jsonl",
                           label=f"judge921:{ns.arm}:{ns.fixture}:t{ns.trial}"),
        ctx=StageContext(learning_run_dir=trial_dir, user=prompt, request_limit=1,
                         wall_clock_timeout=subagent_timeout()),
        deps=QuestionerDeps(),
    )
    (trial_dir / "reply.raw.md").write_text(reply, encoding="utf-8")
    blocks = _FENCE.findall(reply)
    (trial_dir / "reply.yaml").write_text((blocks[-1] if blocks else reply).strip() + "\n", encoding="utf-8")
    usage = {}
    trace = trial_dir / "wire_logs" / "judge_trace.jsonl"
    if trace.is_file():
        for line in trace.read_text(encoding="utf-8").splitlines():
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            if r.get("kind") == "response" and isinstance(r.get("usage"), dict):
                usage = r["usage"]
    (trial_dir / "meta.json").write_text(json.dumps({
        "arm": ns.arm, "fixture": ns.fixture, "trial": ns.trial, "model": ns.model,
        "effort": ns.effort, "prompt_chars": len(prompt), "seconds": round(time.time() - t0, 1),
        "usage": usage}, indent=2))
    print(f"{ns.arm}/{ns.fixture}/t{ns.trial}: {len(prompt)} chars in, {len(reply)} chars out, "
          f"{round(time.time() - t0)}s, usage={usage}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
