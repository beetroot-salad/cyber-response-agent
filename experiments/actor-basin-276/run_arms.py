#!/usr/bin/env python3
"""Run the #276 reframe arms once each over the frozen benign falco fixture.

arm0  baseline  : current actor.md (unchanged), blind, live corpus.
armA  reframe   : reframed actor.md (defeat-the-analysis objective), blind, live corpus.
armB  whitebox  : reframed+whitebox actor.md + gather_summary.md staged via --add-dir.

Frozen disposition A (benign/high) is held fixed for all arms (same fixture run dir).
Actor seed is PINNED to a constant so archetype + MITRE menu are identical across arms,
isolating the intervention. Each arm: actor -> oracle -> judge (fully offline, claude -p).

Corpus retirement is intentionally NOT applied: the canonical human-mimicry lesson
(ssh-brute-force-timing-mimicry) is sshd-tagged and not retrieval-relevant to a falco
net-tool alert, so retiring it is inert for this fixture. armA therefore isolates the
reframed objective alone. See results/ for the writeup.
"""
import json
import sys
import traceback
from pathlib import Path

LEARNING = Path("/workspace/defender/learning")
sys.path.insert(0, str(LEARNING))

import _loop_subagents as S          # noqa: E402
import lead_repository as LR         # noqa: E402
import _loop_validate as V           # noqa: E402
import yaml                          # noqa: E402

EXP = Path("/workspace/experiments/actor-basin-276")
FX = EXP / "fixtures/falco-net-tool-live"
RUNS = EXP / "runs"
VAR = EXP / "variants"
FIXED_SEED = 0x5EED0276              # constant across arms

# --- helpers that may live in S or a sibling module ---
def _strip(x):
    return V.strip_yaml_fence(x)

def _is_skip(story):
    fn = getattr(S, "is_skip_story", None)
    if fn:
        return fn(story)
    return story.lstrip().startswith("SKIP:")

# --- pin the actor seed so archetype+menu are identical across arms ---
S._actor_seed = lambda name: FIXED_SEED

# --- whitebox injection: inline the gather summary into the actor's user prompt.
# The actor call is the only _run_claude with a non-empty add_dir (the lessons corpora);
# oracle passes none and the judge uses _run_judge_claude. We append a delimited
# gather_summary section to the user prompt (args[1]) exactly as alert/actor_input are
# delivered, so the actor reliably sees it without filesystem navigation (cwd=REPO_ROOT). ---
_orig_run_claude = S._run_claude
_WB = {"text": None}
def _patched_run_claude(*args, **kwargs):
    if _WB["text"] is not None and kwargs.get("add_dir") and len(args) >= 2:
        args = list(args)
        section = ("\n\n=== gather_summary ===\n"
                   "(per-lead telemetry actuals the defender's leads returned for this case; "
                   "telemetry only, no disposition)\n\n" + _WB["text"] + "\n=== end gather_summary ===\n")
        args[1] = args[1] + section
        args = tuple(args)
    return _orig_run_claude(*args, **kwargs)
S._run_claude = _patched_run_claude


def run_arm(arm, actor_prompt, whitebox):
    ldir = RUNS / arm
    ldir.mkdir(parents=True, exist_ok=True)
    S.ACTOR_PROMPT = Path(actor_prompt)
    _WB["text"] = None
    if whitebox:
        summary = (FX / "gather_summary.md").read_text()
        (ldir / "gather_summary.md").write_text(summary)  # archived alongside artifacts
        _WB["text"] = summary

    result = {"arm": arm, "actor_prompt": str(actor_prompt), "whitebox": whitebox}
    try:
        alert_path = FX / "alert.json"
        actor_input = ldir / "actor_input.yaml"
        actor_input.write_text(LR.render_actor_view_yaml(str(FX)))

        print(f"[{arm}] actor...", flush=True)
        story = S.invoke_actor(alert_path, actor_input, ldir)
        (ldir / "actor_story.md").write_text(story)

        if _is_skip(story):
            result.update(status="skip", outcome="skip-passthrough",
                          story_head=story.strip().splitlines()[0][:200])
            print(f"[{arm}] SKIP", flush=True)
            return result

        print(f"[{arm}] oracle...", flush=True)
        oracle_yaml = S.invoke_oracle(FX, ldir / "actor_story.md")
        proj = ldir / "projected_telemetry.yaml"
        proj.write_text(_strip(oracle_yaml))

        print(f"[{arm}] judge...", flush=True)
        judge_yaml = S.invoke_judge(FX, ldir / "actor_story.md", proj, ldir)
        jstr = _strip(judge_yaml)
        (ldir / "judge_findings.yaml").write_text(jstr)
        doc = yaml.safe_load(jstr)
        outcome = (doc or {}).get("outcome", "unknown")
        nfind = len((doc or {}).get("findings", []) or [])
        result.update(status="ok", outcome=outcome, n_findings=nfind)
        print(f"[{arm}] outcome={outcome} findings={nfind}", flush=True)
    except Exception as e:
        result.update(status="error", error=f"{type(e).__name__}: {e}",
                      trace=traceback.format_exc()[-1500:])
        print(f"[{arm}] ERROR: {e}", flush=True)
    return result


ARMS = [
    ("arm0-baseline", LEARNING / "actor.md", False),
    ("armA-reframe", VAR / "actor.md.reframed", False),
    ("armB-whitebox", VAR / "actor.md.reframed-whitebox", True),
]

if __name__ == "__main__":
    RUNS.mkdir(parents=True, exist_ok=True)
    results = []
    for arm, prompt, wb in ARMS:
        results.append(run_arm(arm, prompt, wb))
        (RUNS / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("\n=== SUMMARY ===")
    for r in results:
        print(f"  {r['arm']:16s} status={r.get('status'):6s} outcome={r.get('outcome')}")
    print(f"\nwrote {RUNS/'results.json'}")
