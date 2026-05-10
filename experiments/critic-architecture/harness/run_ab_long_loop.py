#!/usr/bin/env python3
"""A/B long-loop test: defender+critic vs single-agent self-review,
both running multi-turn through the tool harness.

Train on fixture 11 (one trial per arm) -> curator distills directive.
Test (held-out) on fixture 01 (one trial per arm with curated addendum).

Each turn = one claude -p call; agent emits <tool_call> blocks; adapter resolves
them against the per-fixture fact base; results are appended to history;
next turn fed full history. Hard cap 5 turns.
"""
from __future__ import annotations

import argparse
import concurrent.futures as cf
import json
import re
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROMPTS = ROOT / "prompts"
FIXTURES = ROOT / "fixtures"
RESULTS = ROOT / "results"
HARNESS = ROOT / "harness"
MODEL = "claude-sonnet-4-6"
MAX_TURNS = 5

sys.path.insert(0, str(HARNESS))
import adapter  # noqa: E402

TRAIN_FID = "11-billing-svc-account-mimicry"
TRAIN_PROTOCOL = HARNESS / "protocol.md"
TRAIN_FACTS = FIXTURES / "11.tool_facts.json"

TEST_FID = "01-ssh-bastion-new-source"
TEST_PROTOCOL = HARNESS / "protocol_01.md"
TEST_FACTS = FIXTURES / "01.tool_facts.json"


def load_text(p: Path) -> str:
    return p.read_text()


def load_alert(fid: str) -> str:
    return json.dumps(json.loads((FIXTURES / f"{fid}.json").read_text())["alert"], indent=2)


def claude_call(prompt: str, label: str, timeout: int = 300) -> dict:
    print(f"[{time.strftime('%H:%M:%S')}] -> {label}", file=sys.stderr)
    cmd = ["claude", "-p", "--model", MODEL, "--output-format", "json"]
    try:
        r = subprocess.run(cmd, input=prompt, capture_output=True, text=True, timeout=timeout)
        if r.returncode != 0:
            return {"_error": f"exit={r.returncode} stderr={r.stderr[:500]}", "result": "", "total_cost_usd": 0.0, "usage": {}}
        data = json.loads(r.stdout)
        cost = data.get("total_cost_usd", 0)
        out_t = data.get("usage", {}).get("output_tokens", 0)
        print(f"[{time.strftime('%H:%M:%S')}] <- {label} ${cost:.3f} {out_t}out", file=sys.stderr)
        return data
    except Exception as e:  # noqa: BLE001
        return {"_error": repr(e), "result": "", "total_cost_usd": 0.0, "usage": {}}


COMMIT_RE = re.compile(r"STATE:\s*committing", re.IGNORECASE)


def is_committed(text: str) -> bool:
    return bool(COMMIT_RE.search(text))


def render_history(turns: list[dict]) -> str:
    """Format the prior-turns block for the next agent prompt."""
    if not turns:
        return "(none — this is turn 1)"
    parts = []
    for t in turns:
        parts.append(f"## TURN {t['n']} (your output)\n\n{t['agent_text']}")
        if t.get("tool_results"):
            parts.append(f"## TURN {t['n']} TOOL RESULTS\n\n{t['tool_results']}")
    return "\n\n".join(parts)


def run_loop(role: str, alert: str, protocol: str, facts_path: Path, addendum: str, label_prefix: str) -> dict:
    """Drive one multi-turn loop. role in {'defender','single'}."""
    prompt_file = "long_defender.md" if role == "defender" else "long_single_agent.md"
    template = load_text(PROMPTS / prompt_file)

    addendum_block = ""
    if addendum.strip():
        addendum_block = f"# ADDENDUM LIBRARY (curated meta-patterns from prior cases)\n\n{addendum.strip()}\n"

    turns: list[dict] = []
    total_cost = 0.0
    total_in = total_out = total_cr = total_cc = 0
    start = time.time()
    committed = False

    for n in range(1, MAX_TURNS + 1):
        prompt = (
            template
            .replace("{{ADDENDUM_BLOCK}}", addendum_block)
            .replace("{{PROTOCOL_BLOCK}}", protocol)
            .replace("{{ALERT_BLOCK}}", alert)
            .replace("{{TURN_NUM}}", str(n))
            .replace("{{HISTORY_BLOCK}}", render_history(turns))
        )
        if n == MAX_TURNS:
            prompt += "\n\nNOTE: this is the final turn. You MUST commit (STATE: committing) — no more tool calls will be resolved.\n"

        data = claude_call(prompt, f"{label_prefix}:T{n}")
        agent_text = data.get("result", "")
        total_cost += data.get("total_cost_usd", 0.0) or 0.0
        u = data.get("usage", {}) or {}
        total_in += u.get("input_tokens", 0) or 0
        total_out += u.get("output_tokens", 0) or 0
        total_cr += u.get("cache_read_input_tokens", 0) or 0
        total_cc += u.get("cache_creation_input_tokens", 0) or 0

        if is_committed(agent_text):
            turns.append({"n": n, "agent_text": agent_text, "tool_results": "", "raw": data})
            committed = True
            break

        # Resolve tool calls
        calls = adapter.parse_tool_calls(agent_text)
        if not calls:
            # No commit, no tool calls — degenerate; force commit message
            turns.append({"n": n, "agent_text": agent_text, "tool_results": "(no tool calls parsed; agent must commit next turn)", "raw": data})
            continue
        fact_base = json.loads(facts_path.read_text())
        pairs = [(c, adapter.lookup(c, fact_base)) for c in calls]
        tool_results = adapter.format_results(pairs)
        turns.append({"n": n, "agent_text": agent_text, "tool_results": tool_results, "raw": data})

    wall = time.time() - start
    return {
        "role": role,
        "turns": turns,
        "committed": committed,
        "turn_count": len(turns),
        "total_cost_usd": total_cost,
        "tokens": {"in": total_in, "out": total_out, "cache_read": total_cr, "cache_create": total_cc},
        "wall_s": wall,
    }


def transcript_for_critic(turns: list[dict]) -> str:
    parts = []
    for t in turns:
        parts.append(f"### TURN {t['n']} agent\n\n{t['agent_text']}")
        if t.get("tool_results"):
            parts.append(f"### TURN {t['n']} tool results\n\n{t['tool_results']}")
    return "\n\n".join(parts)


def run_arm_a(alert: str, protocol: str, facts_path: Path, addendum: str, label: str) -> dict:
    """Defender investigates; critic reviews full transcript at end."""
    d_loop = run_loop("defender", alert, protocol, facts_path, addendum, f"{label}:def")
    transcript = transcript_for_critic(d_loop["turns"])
    critic_prompt = (
        load_text(PROMPTS / "long_critic.md")
        .replace("{{ALERT_BLOCK}}", alert)
        .replace("{{TRANSCRIPT_BLOCK}}", transcript)
    )
    critic = claude_call(critic_prompt, f"{label}:critic")
    return {"defender": d_loop, "critic": critic}


def run_arm_b(alert: str, protocol: str, facts_path: Path, addendum: str, label: str) -> dict:
    """Single agent investigates and self-reviews in same context."""
    s_loop = run_loop("single", alert, protocol, facts_path, addendum, f"{label}:single")
    return {"single": s_loop}


def extract_directives_a(arm_a: dict) -> list[str]:
    out = []
    last_def = arm_a["defender"]["turns"][-1]["agent_text"] if arm_a["defender"]["turns"] else ""
    out.append(f"[from defender on training fixture] DIRECTIVE-TO-CRITIC and final commit:\n{last_def}")
    out.append(f"[from critic on training fixture] DIRECTIVE-TO-DEFENDER block:\n{arm_a['critic'].get('result', '')}")
    return out


def extract_directives_b(arm_b: dict) -> list[str]:
    last = arm_b["single"]["turns"][-1]["agent_text"] if arm_b["single"]["turns"] else ""
    return [f"[from single-agent on training fixture] full commit + self-review + DIRECTIVE:\n{last}"]


def curate(arm: str, raw_directives: list[str]) -> dict:
    block = "\n\n---\n\n".join(raw_directives)
    prompt = load_text(PROMPTS / "curator.md").replace("{{DIRECTIVE_BLOCK}}", block)
    return claude_call(prompt, f"curator:{arm}")


def fmt_loop(label: str, loop: dict) -> str:
    head = (
        f"## {label}\n\n"
        f"- turns: {loop['turn_count']}, committed: {loop['committed']}\n"
        f"- total cost: ${loop['total_cost_usd']:.4f}\n"
        f"- tokens: in={loop['tokens']['in']} out={loop['tokens']['out']} cache_read={loop['tokens']['cache_read']} cache_create={loop['tokens']['cache_create']}\n"
        f"- wall: {loop['wall_s']:.1f}s\n\n"
    )
    body = []
    for t in loop["turns"]:
        body.append(f"### TURN {t['n']}\n\n```\n{t['agent_text']}\n```\n")
        if t.get("tool_results"):
            body.append(f"#### tool results\n\n```\n{t['tool_results']}\n```\n")
    return head + "\n".join(body)


def fmt_call(label: str, data: dict) -> str:
    cost = data.get("total_cost_usd", 0.0) or 0.0
    u = data.get("usage", {}) or {}
    err = data.get("_error")
    head = f"## {label}\n\n- cost: ${cost:.4f}\n- tokens: in={u.get('input_tokens',0)} out={u.get('output_tokens',0)}\n"
    if err:
        head += f"- ERROR: {err}\n"
    return head + f"\n```\n{data.get('result', '')}\n```\n"


def write(p: Path, s: str) -> None:
    p.write_text(s)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--phase", choices=["train", "curate", "test", "all"], default="all")
    ap.add_argument("--state", default=str(RESULTS / "ab-long-loop-state.json"))
    args = ap.parse_args()

    state_path = Path(args.state)
    state = json.loads(state_path.read_text()) if state_path.exists() else {}

    train_alert = load_alert(TRAIN_FID)
    train_protocol = load_text(TRAIN_PROTOCOL)
    test_alert = load_alert(TEST_FID)
    test_protocol = load_text(TEST_PROTOCOL)

    # ---- TRAIN ----
    if args.phase in {"train", "all"} and "train" not in state:
        print("== TRAIN phase (fixture 11) ==", file=sys.stderr)
        with cf.ThreadPoolExecutor(max_workers=2) as ex:
            fa = ex.submit(run_arm_a, train_alert, train_protocol, TRAIN_FACTS, "", "trainA")
            fb = ex.submit(run_arm_b, train_alert, train_protocol, TRAIN_FACTS, "", "trainB")
            arm_a = fa.result()
            arm_b = fb.result()
        # Persist transcripts
        md_a = f"# Arm A training transcript — fixture {TRAIN_FID}\n\n"
        md_a += fmt_loop("Defender loop", arm_a["defender"])
        md_a += "\n\n" + fmt_call("Critic (REPORT-time)", arm_a["critic"])
        write(RESULTS / f"ab-long-loop-A-{TRAIN_FID}-pass1.md", md_a)
        md_b = f"# Arm B training transcript — fixture {TRAIN_FID}\n\n"
        md_b += fmt_loop("Single-agent loop (with self-review on final turn)", arm_b["single"])
        write(RESULTS / f"ab-long-loop-B-{TRAIN_FID}-pass1.md", md_b)
        state["train"] = {"arm_a": arm_a, "arm_b": arm_b}
        state_path.write_text(json.dumps(state, indent=2, default=str))

    # ---- CURATE ----
    if args.phase in {"curate", "all"} and "curate" not in state:
        print("== CURATE phase ==", file=sys.stderr)
        raw_a = extract_directives_a(state["train"]["arm_a"])
        raw_b = extract_directives_b(state["train"]["arm_b"])
        with cf.ThreadPoolExecutor(max_workers=2) as ex:
            fa = ex.submit(curate, "A", raw_a)
            fb = ex.submit(curate, "B", raw_b)
            cur_a = fa.result()
            cur_b = fb.result()
        write(RESULTS / "ab-long-loop-library-A.md",
              f"# Arm A curated addendum library\n\n{fmt_call('Curator', cur_a)}\n\n## Raw inputs\n\n" + "\n\n---\n\n".join(raw_a))
        write(RESULTS / "ab-long-loop-library-B.md",
              f"# Arm B curated addendum library\n\n{fmt_call('Curator', cur_b)}\n\n## Raw inputs\n\n" + "\n\n---\n\n".join(raw_b))
        state["curate"] = {"A": cur_a, "B": cur_b}
        state_path.write_text(json.dumps(state, indent=2, default=str))

    # ---- TEST ----
    if args.phase in {"test", "all"} and "test" not in state:
        print(f"== TEST phase (held-out fixture {TEST_FID}) ==", file=sys.stderr)
        addendum_a = state["curate"]["A"]["result"]
        addendum_b = state["curate"]["B"]["result"]
        with cf.ThreadPoolExecutor(max_workers=2) as ex:
            fa = ex.submit(run_arm_a, test_alert, test_protocol, TEST_FACTS, addendum_a, "testA")
            fb = ex.submit(run_arm_b, test_alert, test_protocol, TEST_FACTS, addendum_b, "testB")
            test_a = fa.result()
            test_b = fb.result()
        md_a = f"# Arm A test transcript — fixture {TEST_FID} (Pass 2 with curated addendum)\n\n"
        md_a += fmt_loop("Defender loop", test_a["defender"])
        md_a += "\n\n" + fmt_call("Critic (REPORT-time)", test_a["critic"])
        write(RESULTS / f"ab-long-loop-A-{TEST_FID}-pass2.md", md_a)
        md_b = f"# Arm B test transcript — fixture {TEST_FID} (Pass 2 with curated addendum)\n\n"
        md_b += fmt_loop("Single-agent loop", test_b["single"])
        write(RESULTS / f"ab-long-loop-B-{TEST_FID}-pass2.md", md_b)
        state["test"] = {"arm_a": test_a, "arm_b": test_b}
        state_path.write_text(json.dumps(state, indent=2, default=str))

    print("DONE. State at:", state_path, file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
