#!/usr/bin/env python3
"""Run the #276 reframe arms over the frozen BENIGN sshd fixture (dev.gabe).

Same three arms as the falco pass, but on the sshd-success-after-failures anchor where the
human-mimicry lesson IS retrieval-relevant — so armA/armB actually RETIRE it (temporarily move
`ssh-brute-force-timing-mimicry.md` out of the live lessons-actor corpus during the actor call,
guaranteed-restore in finally). arm0 keeps it (baseline).

Basin nuance: dev.gabe is a HUMAN fat-finger (defender credited "user retry"), but the real
inter-attempt gaps are 0.68-2.58s while the retired lesson prescribes 8-20s "human" timing — so the
lesson encodes a stale timing prior for THIS deployment. The test: does retiring it (armA) + seeing
the real cadence (armB) help the actor match the actual basin vs the lesson's prior.
"""
import json
import shutil
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
FX = EXP / "fixtures/sshd-gabe-live"
RUNS = EXP / "runs-sshd"
VAR = EXP / "variants"
FIXED_SEED = 0x5EED5588               # constant across arms (distinct from the falco pass)

RETIRE_LESSON = Path("/workspace/defender/lessons-actor/ssh-brute-force-timing-mimicry.md")
RETIRE_STASH = Path("/tmp/retired-ssh-brute-force-timing-mimicry.md")

def _strip(x):
    return V.strip_yaml_fence(x)

def _is_skip(story):
    fn = getattr(S, "is_skip_story", None)
    return fn(story) if fn else story.lstrip().startswith("SKIP:")

S._actor_seed = lambda name: FIXED_SEED

# whitebox: inline gather_summary into the actor user prompt (only call with non-empty add_dir)
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


def run_arm(arm, actor_prompt, whitebox, retire):
    ldir = RUNS / arm
    ldir.mkdir(parents=True, exist_ok=True)
    S.ACTOR_PROMPT = Path(actor_prompt)
    _WB["text"] = None
    if whitebox:
        summary = (FX / "gather_summary.md").read_text()
        (ldir / "gather_summary.md").write_text(summary)
        _WB["text"] = summary

    result = {"arm": arm, "actor_prompt": str(actor_prompt), "whitebox": whitebox, "retired": retire}
    moved = False
    try:
        if retire and RETIRE_LESSON.is_file():
            shutil.move(str(RETIRE_LESSON), str(RETIRE_STASH))
            moved = True
        alert_path = FX / "alert.json"
        actor_input = ldir / "actor_input.yaml"
        actor_input.write_text(LR.render_actor_view_yaml(str(FX)))

        print(f"[{arm}] actor... (retire={retire} lesson_present={RETIRE_LESSON.is_file()})", flush=True)
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
        doc = yaml.safe_load(jstr) if jstr.strip().startswith(("outcome", "defender")) else None
        if doc is None:
            import re
            m = re.search(r'(survived|caught|undecidable|incoherent|skip-passthrough)', jstr)
            outcome = m.group(1) if m else "unknown"
            nfind = len(re.findall(r'^\s*-\s*type:\s', jstr, re.M))
        else:
            outcome = doc.get("outcome", "unknown")
            nfind = len(doc.get("findings", doc.get("defender_findings", [])) or [])
        result.update(status="ok", outcome=outcome, n_findings=nfind)
        print(f"[{arm}] outcome={outcome} findings={nfind}", flush=True)
    except Exception as e:
        result.update(status="error", error=f"{type(e).__name__}: {e}", trace=traceback.format_exc()[-1500:])
        print(f"[{arm}] ERROR: {e}", flush=True)
    finally:
        if moved and RETIRE_STASH.is_file():
            shutil.move(str(RETIRE_STASH), str(RETIRE_LESSON))
            print(f"[{arm}] restored {RETIRE_LESSON.name}", flush=True)
    return result


ARMS = [
    ("arm0-baseline", LEARNING / "actor.md", False, False),
    ("armA-reframe", VAR / "actor.md.reframed", False, True),
    ("armB-whitebox", VAR / "actor.md.reframed-whitebox", True, True),
]

if __name__ == "__main__":
    RUNS.mkdir(parents=True, exist_ok=True)
    results = []
    for arm, prompt, wb, retire in ARMS:
        results.append(run_arm(arm, prompt, wb, retire))
        (RUNS / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    # safety: ensure lesson is restored
    if RETIRE_STASH.is_file() and not RETIRE_LESSON.is_file():
        shutil.move(str(RETIRE_STASH), str(RETIRE_LESSON))
    print("\n=== SUMMARY ===")
    for r in results:
        print(f"  {r['arm']:16s} status={r.get('status'):6s} outcome={r.get('outcome')} retired={r.get('retired')}")
    print(f"\nlesson present at end: {RETIRE_LESSON.is_file()}")
