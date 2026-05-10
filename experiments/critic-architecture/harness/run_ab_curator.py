#!/usr/bin/env python3
"""A/B curator test: defender+critic vs single-agent self-review.

Both arms feed the same curator with the same addendum-token budget; held-out
test fixtures evaluate the curated addendum's effect on a fresh investigation.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROMPTS = ROOT / "prompts"
FIXTURES = ROOT / "fixtures"
RESULTS = ROOT / "results"
MODEL = "claude-sonnet-4-6"

TRAINING = ["01-ssh-bastion-new-source", "05-terraform-iam-mass-change", "08-router-firmware-anomaly"]
TEST = ["03-novel-outbound-dns", "09-printer-anomalous-smb"]


def load_prompt(name: str) -> str:
    return (PROMPTS / name).read_text()


def load_fixture(fid: str) -> dict:
    return json.loads((FIXTURES / f"{fid}.json").read_text())


def alert_block(fid: str) -> str:
    fx = load_fixture(fid)
    return json.dumps(fx["alert"], indent=2)


def claude_call(prompt: str, label: str, retries: int = 1) -> dict:
    """Invoke claude -p with a stdin prompt; returns parsed JSON."""
    print(f"[{time.strftime('%H:%M:%S')}] -> {label}", file=sys.stderr)
    cmd = ["claude", "-p", "--model", MODEL, "--output-format", "json"]
    last_err = None
    for attempt in range(retries + 1):
        try:
            r = subprocess.run(
                cmd, input=prompt, capture_output=True, text=True, timeout=300,
            )
            if r.returncode != 0:
                last_err = f"exit={r.returncode} stderr={r.stderr[:500]}"
                continue
            data = json.loads(r.stdout)
            if data.get("is_error"):
                last_err = f"is_error: {data.get('result', '')[:300]}"
                continue
            print(f"[{time.strftime('%H:%M:%S')}] <- {label} ${data.get('total_cost_usd', 0):.3f} {data.get('usage', {}).get('output_tokens', 0)}out", file=sys.stderr)
            return data
        except Exception as e:  # noqa: BLE001
            last_err = repr(e)
    return {"_error": last_err, "result": "", "total_cost_usd": 0.0, "usage": {}}


def run_arm_a_training(fid: str) -> dict:
    """Defender + critic, both emit directives."""
    alert = alert_block(fid)
    d_prompt = load_prompt("defender_with_directive.md").replace("{{ALERT_BLOCK}}", alert)
    d = claude_call(d_prompt, f"A:defender:{fid}")
    c_prompt = (
        load_prompt("critic_with_directive.md")
        .replace("{{ALERT_BLOCK}}", alert)
        .replace("{{DEFENDER_BLOCK}}", d.get("result", ""))
    )
    c = claude_call(c_prompt, f"A:critic:{fid}")
    return {"fixture": fid, "defender": d, "critic": c}


def run_arm_b_training(fid: str) -> dict:
    """Single agent: triage + self-review + directive in one call."""
    alert = alert_block(fid)
    prompt = load_prompt("self_review.md").replace("{{ALERT_BLOCK}}", alert)
    r = claude_call(prompt, f"B:single:{fid}")
    return {"fixture": fid, "single": r}


def extract_directives_a(trial: dict) -> list[str]:
    """Pull the two DIRECTIVE-TO-* paragraphs out of a single Arm-A trial."""
    out = []
    for who, key in (("defender", "DIRECTIVE-TO-CRITIC"), ("critic", "DIRECTIVE-TO-DEFENDER")):
        text = trial[who].get("result", "")
        out.append(f"[from {who} on fixture {trial['fixture']}] {key} block:\n{text}")
    return out


def extract_directive_b(trial: dict) -> str:
    text = trial["single"].get("result", "")
    return f"[from single-agent on fixture {trial['fixture']}]\n{text}"


def curate(arm: str, raw_directives: list[str]) -> dict:
    block = "\n\n---\n\n".join(raw_directives)
    prompt = load_prompt("curator.md").replace("{{DIRECTIVE_BLOCK}}", block)
    return claude_call(prompt, f"curator:{arm}")


def run_test(arm: str, fid: str, addendum: str) -> dict:
    alert = alert_block(fid)
    prompt = (
        load_prompt("test_defender_with_addendum.md")
        .replace("{{ALERT_BLOCK}}", alert)
        .replace("{{ADDENDUM_BLOCK}}", addendum)
    )
    r = claude_call(prompt, f"test:{arm}:{fid}")
    return {"arm": arm, "fixture": fid, "result": r}


def write_md(path: Path, content: str) -> None:
    path.write_text(content)


def fmt_call(label: str, data: dict) -> str:
    cost = data.get("total_cost_usd", 0.0)
    usage = data.get("usage", {})
    in_t = usage.get("input_tokens", 0)
    out_t = usage.get("output_tokens", 0)
    cr = usage.get("cache_read_input_tokens", 0)
    cc = usage.get("cache_creation_input_tokens", 0)
    err = data.get("_error")
    head = f"### {label}\n\n- cost: ${cost:.4f}\n- tokens: in={in_t} out={out_t} cache_read={cr} cache_create={cc}\n"
    if err:
        head += f"- ERROR: {err}\n"
    body = f"\n```\n{data.get('result', '')}\n```\n"
    return head + body


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--phase", choices=["training", "curate", "test", "all"], default="all")
    ap.add_argument("--state", default=str(RESULTS / "ab-curator-state.json"))
    args = ap.parse_args()

    state_path = Path(args.state)
    state = json.loads(state_path.read_text()) if state_path.exists() else {}

    # ---- TRAINING ----
    if args.phase in {"training", "all"} and "training" not in state:
        print("== TRAINING phase ==", file=sys.stderr)
        with cf.ThreadPoolExecutor(max_workers=6) as ex:
            futA = {ex.submit(run_arm_a_training, fid): fid for fid in TRAINING}
            futB = {ex.submit(run_arm_b_training, fid): fid for fid in TRAINING}
            arm_a = [f.result() for f in cf.as_completed(futA)]
            arm_b = [f.result() for f in cf.as_completed(futB)]
        # write transcripts
        for t in arm_a:
            md = f"# Arm A training: {t['fixture']}\n\n"
            md += fmt_call("Defender", t["defender"])
            md += fmt_call("Critic", t["critic"])
            write_md(RESULTS / f"ab-curator-A-{t['fixture']}.md", md)
        for t in arm_b:
            md = f"# Arm B training: {t['fixture']}\n\n"
            md += fmt_call("Single agent (triage + self-review + directive)", t["single"])
            write_md(RESULTS / f"ab-curator-B-{t['fixture']}.md", md)
        state["training"] = {"arm_a": arm_a, "arm_b": arm_b}
        state_path.write_text(json.dumps(state, indent=2, default=str))

    # ---- CURATE ----
    if args.phase in {"curate", "all"} and "curate" not in state:
        print("== CURATE phase ==", file=sys.stderr)
        arm_a = state["training"]["arm_a"]
        arm_b = state["training"]["arm_b"]
        raw_a = []
        for t in arm_a:
            raw_a.extend(extract_directives_a(t))
        raw_b = [extract_directive_b(t) for t in arm_b]
        with cf.ThreadPoolExecutor(max_workers=2) as ex:
            fa = ex.submit(curate, "A", raw_a)
            fb = ex.submit(curate, "B", raw_b)
            cur_a = fa.result()
            cur_b = fb.result()
        write_md(RESULTS / "ab-curator-library-A.md",
                 f"# Arm A curated addendum library\n\n{fmt_call('Curator', cur_a)}\n\n## Raw inputs\n\n" +
                 "\n\n---\n\n".join(raw_a))
        write_md(RESULTS / "ab-curator-library-B.md",
                 f"# Arm B curated addendum library\n\n{fmt_call('Curator', cur_b)}\n\n## Raw inputs\n\n" +
                 "\n\n---\n\n".join(raw_b))
        state["curate"] = {"A": cur_a, "B": cur_b}
        state_path.write_text(json.dumps(state, indent=2, default=str))

    # ---- TEST ----
    if args.phase in {"test", "all"} and "test" not in state:
        print("== TEST phase ==", file=sys.stderr)
        addendum_a = state["curate"]["A"]["result"]
        addendum_b = state["curate"]["B"]["result"]
        jobs = []
        with cf.ThreadPoolExecutor(max_workers=4) as ex:
            for fid in TEST:
                jobs.append(ex.submit(run_test, "A", fid, addendum_a))
                jobs.append(ex.submit(run_test, "B", fid, addendum_b))
            results = [j.result() for j in cf.as_completed(jobs)]
        for r in results:
            md = f"# Arm {r['arm']} test: {r['fixture']}\n\n"
            md += fmt_call(f"Test defender (Arm {r['arm']} addendum)", r["result"])
            write_md(RESULTS / f"ab-curator-{r['arm']}-{r['fixture']}.md", md)
        state["test"] = results
        state_path.write_text(json.dumps(state, indent=2, default=str))

    print("DONE. State at:", state_path, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
