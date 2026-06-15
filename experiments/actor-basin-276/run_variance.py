#!/usr/bin/env python3
"""Variance study of the production actor prompt, N runs on a pinned input.

Runs the *current* production actor (`defender/learning/actor.md`) over a frozen
benign fixture N times with a PINNED seed, so archetype + MITRE menu are identical
across runs and the only source of divergence is model sampling. You vary the
*prompt* by checking out a different commit before each pass — that is how the
arm-A (reframe-only) vs reframe+levers comparison in `results/variance-prod-armA.md`
was produced.

Usage:
    python3 run_variance.py <label> [--actor-only] [--n N]

    <label>       output subdir under runs-variance/ (e.g. "baseline", "revised")
    --actor-only  stop after the actor (story-level discipline only; no outcome)
    --n           number of runs (default 4)

Requires working `claude` credentials. The configured ANTHROPIC_API_KEY must have
credit, or run with it unset to fall back to the subscription credential:
    env -u ANTHROPIC_API_KEY python3 run_variance.py revised --actor-only

Note: the production lessons-actor corpus state matters. Arm A retires
`ssh-brute-force-timing-mimicry.md`; the assertion below documents that expectation.
"""
import argparse
import json
import sys
import traceback
from pathlib import Path

EXP = Path(__file__).resolve().parent
LEARNING = Path("/workspace/defender/learning")
sys.path.insert(0, str(LEARNING))

import _loop_subagents as S          # noqa: E402
import lead_repository as LR         # noqa: E402
import _loop_validate as V           # noqa: E402
import yaml                          # noqa: E402

FX = EXP / "fixtures/sshd-gabe-live"
PROD_PROMPT = LEARNING / "actor.md"
FIXED_SEED = 0x5EED5588               # same pin as run_arms_sshd.py, for comparability
RETIRED_LESSON = Path("/workspace/defender/lessons-actor/ssh-brute-force-timing-mimicry.md")


def _strip(x):
    return V.strip_yaml_fence(x)


def _is_skip(story):
    fn = getattr(S, "is_skip_story", None)
    return fn(story) if fn else story.lstrip().startswith("SKIP:")


S._actor_seed = lambda name: FIXED_SEED


def run_one(out_dir, i, actor_only):
    ldir = out_dir / f"run{i}"
    ldir.mkdir(parents=True, exist_ok=True)
    S.ACTOR_PROMPT = PROD_PROMPT
    result = {"run": i, "actor_prompt": str(PROD_PROMPT), "actor_only": actor_only}
    try:
        actor_input = ldir / "actor_input.yaml"
        actor_input.write_text(LR.render_actor_view_yaml(str(FX)))
        print(f"[run{i}] actor... (lesson_present={RETIRED_LESSON.is_file()})", flush=True)
        story = S.invoke_actor(FX / "alert.json", actor_input, ldir)
        (ldir / "actor_story.md").write_text(story)
        if _is_skip(story):
            result.update(status="skip", outcome="skip-passthrough", story_bytes=len(story))
            print(f"[run{i}] SKIP", flush=True)
            return result
        if actor_only:
            result.update(status="ok", story_bytes=len(story))
            print(f"[run{i}] ok bytes={len(story)}", flush=True)
            return result

        print(f"[run{i}] oracle...", flush=True)
        proj = ldir / "projected_telemetry.yaml"
        proj.write_text(_strip(S.invoke_oracle(FX, ldir / "actor_story.md")))
        print(f"[run{i}] judge...", flush=True)
        jstr = _strip(S.invoke_judge(FX, ldir / "actor_story.md", proj, ldir))
        (ldir / "judge_findings.yaml").write_text(jstr)
        try:
            doc = yaml.safe_load(jstr)
        except Exception:
            doc = None
        if isinstance(doc, dict):
            outcome = doc.get("outcome", "unknown")
            nfind = len(doc.get("findings", doc.get("defender_findings", [])) or [])
        else:
            import re
            m = re.search(r'(survived|caught|undecidable|incoherent|skip-passthrough)', jstr)
            outcome = m.group(1) if m else "unknown"
            nfind = len(re.findall(r'^\s*-\s*type:\s', jstr, re.M))
        result.update(status="ok", outcome=outcome, n_findings=nfind, story_bytes=len(story))
        print(f"[run{i}] outcome={outcome} findings={nfind} bytes={len(story)}", flush=True)
    except Exception as e:
        result.update(status="error", error=f"{type(e).__name__}: {e}",
                      trace=traceback.format_exc()[-1200:])
        print(f"[run{i}] ERROR: {e}", flush=True)
    return result


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("label", help="output subdir under runs-variance/")
    ap.add_argument("--actor-only", action="store_true")
    ap.add_argument("--n", type=int, default=4)
    args = ap.parse_args()

    out_dir = EXP / "runs-variance" / args.label
    out_dir.mkdir(parents=True, exist_ok=True)
    results = []
    for i in range(1, args.n + 1):
        results.append(run_one(out_dir, i, args.actor_only))
        (out_dir / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print("\n=== SUMMARY ===")
    for r in results:
        print(f"  run{r['run']} status={r.get('status'):6s} "
              f"outcome={r.get('outcome')} bytes={r.get('story_bytes')}")
    print(f"\nwrote {out_dir/'results.json'}")


if __name__ == "__main__":
    main()
