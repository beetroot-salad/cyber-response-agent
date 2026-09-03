#!/usr/bin/env python3
"""Grade one judge reply with Claude Fable 5.1 (xhigh), headless via `claude -p`, blind to arm.

The grader sees: the frozen reference, the judge's reply, the mechanical checks, and the
fixture's artifacts (the arm-independent PROPOSED rendering, so it can verify an unmatched
finding against bytes rather than guess). It never sees which arm produced the reply.
"""
from __future__ import annotations
import argparse, json, os, re, subprocess, sys
from pathlib import Path
HERE = Path(__file__).resolve().parent
sys.path.insert(0, "/workspace"); sys.path.insert(0, str(HERE / "variants")); sys.path.insert(0, str(HERE))
import contexts  # noqa: E402
from checks import run_checks  # noqa: E402

SCRATCH = Path("/tmp/claude-0/-workspace/2624d2cb-d964-4f07-9669-8a9cf4f7451d/scratchpad/grader")
GRADER_MODEL = "claude-fable-5-1"
DEFAULT_FAMILY = HERE / "family" / "episode" / "family.yaml"

SYSTEM = """You are grading the output of a JUDGE that reviewed one finished security investigation. You are not the judge; you check the judge against a frozen human reference and against the investigation's actual artifacts.

You will receive: (1) the REFERENCE — three root-cause findings R1–R3 a human examiner wrote from the artifacts, each with the evidence a hit must name; (2) the JUDGE'S REPLY (YAML); (3) MECHANICAL CHECKS — regex hits and pointer-grounding computed by a script, as hints only; (4) the ARTIFACTS the judge could have used, host-rendered.

Grade strictly on substance, not wording:
- A reference finding is `hit` when a judge finding identifies the same mechanism at the same location (e.g. R2 needs: the CMDB lookup was scoped to the Docker host AND the asset db-1 was in reach / never reconciled — "the host was unregistered" alone is a miss). `partial` when the judge names the symptom or half the mechanism, or the right mechanism under a clearly wrong bucket. `miss` otherwise. One judge finding may hit at most one reference; if two judge findings cover one reference, count it once.
- Every judge finding that hits no reference is UNMATCHED. For each, decide `true` (the artifacts support it as a real, non-trivial defect of this trajectory), `false` (the artifacts contradict it, or it restates the run's own conclusion, or it is a guess with no support), or `duplicate` (a restatement of another finding). Verify against the artifacts; quote the artifact line that settles it.
- Report the share of the judge's evidence pointers that resolve to something real in the artifacts (use the mechanical grounding as a start; correct it where the script was wrong).

Return ONLY a JSON object, no prose outside it:
{"reference": {"R1": {"verdict": "hit|partial|miss", "judge_finding_index": <int or null>, "reason": "<one line>"},
               "R2": {...}, "R3": {...}},
 "unmatched": [{"judge_finding_index": <int>, "claim": "<copied>", "verdict": "true|false|duplicate", "reason": "<one line with the settling artifact>"}],
 "grounded_pointer_share": <0..1>,
 "quality_note": "<two sentences: is this judgement one a human could act on, and why>"}
"""


def grader_prompt(trial_dir: Path, run_dir: Path, reference: Path, family: Path = DEFAULT_FAMILY) -> tuple[str, dict]:
    reply = (trial_dir / "reply.yaml").read_text(encoding="utf-8")
    checks = run_checks(trial_dir / "reply.yaml", run_dir)
    artifacts = contexts.render_proposed(run_dir, family)
    prompt = (
        "# REFERENCE (frozen before any judge output)\n\n" + reference.read_text(encoding="utf-8")
        + "\n\n# JUDGE'S REPLY\n\n```yaml\n" + reply + "\n```\n"
        + "\n\n# MECHANICAL CHECKS (hints, computed by a script)\n\n```json\n" + json.dumps(checks, indent=1) + "\n```\n"
        + "\n\n# ARTIFACTS THE JUDGE COULD HAVE USED (host-rendered)\n\n" + artifacts
        + "\n\n---\n\nReturn the JSON grade now.\n")
    return prompt, checks


def call_claude(prompt: str, effort: str) -> tuple[str, dict]:
    SCRATCH.mkdir(parents=True, exist_ok=True)
    # The API key in this environment has no credit ("Credit balance is too low"); the claude.ai
    # login this session runs on does. Drop the key so `claude -p` falls back to the login.
    env = {k: v for k, v in os.environ.items() if k not in ("CLAUDECODE", "ANTHROPIC_API_KEY")}
    cmd = ["claude", "-p", "--model", GRADER_MODEL, "--effort", effort, "--output-format", "json",
           "--tools", "", "--no-session-persistence", "--system-prompt", SYSTEM]
    proc = subprocess.run(cmd, input=prompt, capture_output=True, text=True, cwd=SCRATCH, env=env, timeout=1800)
    if proc.returncode != 0:
        raise RuntimeError(f"claude -p failed rc={proc.returncode}: {proc.stderr[-2000:]}")
    try:
        envelope = json.loads(proc.stdout)
    except json.JSONDecodeError:
        envelope = {"result": proc.stdout}
    text = envelope.get("result") if isinstance(envelope, dict) else proc.stdout
    return str(text), envelope if isinstance(envelope, dict) else {}


def parse_grade(text: str) -> dict:
    m = re.search(r"```(?:json)?\s*\n(.*?)```", text, re.S)
    body = m.group(1) if m else text
    start = body.find("{")
    return json.loads(body[start:]) if start != -1 else {"_parse_error": text[:500]}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm"); ap.add_argument("--fixture"); ap.add_argument("--trial", type=int)
    ap.add_argument("--all", action="store_true", help="grade every trial dir without a grade.json")
    ap.add_argument("--effort", default="xhigh")
    ap.add_argument("--force", action="store_true")
    ns = ap.parse_args()
    targets: list[Path] = []
    if ns.all:
        targets = sorted(p for p in (HERE / "runs").glob("*/*/t*") if (p / "reply.yaml").is_file())
    else:
        targets = [HERE / "runs" / ns.arm / ns.fixture / f"t{ns.trial}"]
    for trial_dir in targets:
        if (trial_dir / "grade.json").is_file() and not ns.force:
            continue
        fixture_name = trial_dir.parent.name
        fx = json.loads((HERE / "fixtures" / f"{fixture_name}.json").read_text())
        run_dir, reference = Path(fx["run_dir"]), HERE / fx["reference"]
        family = HERE / fx["family"] if fx.get("family") else DEFAULT_FAMILY
        prompt, checks = grader_prompt(trial_dir, run_dir, reference, family)
        (trial_dir / "checks.json").write_text(json.dumps(checks, indent=2))
        (trial_dir / "grader_prompt.md").write_text(prompt, encoding="utf-8")
        text, envelope = call_claude(prompt, ns.effort)
        (trial_dir / "grader_reply.txt").write_text(text, encoding="utf-8")
        grade = parse_grade(text)
        grade["_grader"] = {"model": GRADER_MODEL, "effort": ns.effort,
                            "usage": envelope.get("usage"), "cost_usd": envelope.get("total_cost_usd"),
                            "duration_ms": envelope.get("duration_ms")}
        (trial_dir / "grade.json").write_text(json.dumps(grade, indent=2))
        ref = grade.get("reference", {})
        print(f"{trial_dir.relative_to(HERE / 'runs')}: " + " ".join(f"{k}={v.get('verdict')}" for k, v in ref.items())
              + f" unmatched={[u.get('verdict') for u in grade.get('unmatched', [])]} grounded={grade.get('grounded_pointer_share')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
