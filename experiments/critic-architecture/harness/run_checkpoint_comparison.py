#!/usr/bin/env python3
"""Checkpoint comparison: post-PREDICT vs pre-COMMIT vs REPORT-time reviewer.

Three checkpoint conditions, n=3 trials each, on fixture 11. Defender runs the
multi-turn loop; reviewer fires once at the configured checkpoint.

- post-PREDICT: reviewer sees turn 1 only. On REDIRECT, redirect text is
  injected into the defender's turn 2 prompt as a [REVIEWER REDIRECT] block.
- pre-COMMIT: defender investigates until it would commit. We re-prompt with a
  "DO NOT COMMIT YET — produce one more investigative turn if any
  decision-relevant tool is uncalled" instruction. Reviewer reads the
  pre-commit transcript; on REDIRECT, redirect text is injected into the
  next defender turn (which then commits).
- REPORT-time: defender commits naturally; reviewer reads everything, no
  feedback to actor.

For all conditions we record: verdict on commit, turns to commit, total tool
calls, total cost, reviewer verdict, whether the redirect changed the call.
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

FID = "11-billing-svc-account-mimicry"
PROTOCOL = HARNESS / "protocol.md"
FACTS = FIXTURES / "11.tool_facts.json"

COMMIT_RE = re.compile(r"STATE:\s*committing", re.IGNORECASE)
DISP_RE = re.compile(
    r"STATE:\s*committing[^\n]*\n+\s*[-•*]?\s*(?:disposition[:\s]+)?"
    r"(benign|suspicious|malicious|escalate)",
    re.IGNORECASE,
)


def claude_call(prompt: str, label: str, timeout: int = 300) -> dict:
    print(f"[{time.strftime('%H:%M:%S')}] -> {label}", file=sys.stderr)
    cmd = ["claude", "-p", "--model", MODEL, "--output-format", "json"]
    try:
        r = subprocess.run(
            cmd, input=prompt, capture_output=True, text=True, timeout=timeout
        )
        if r.returncode != 0:
            return {
                "_error": f"exit={r.returncode} stderr={r.stderr[:500]}",
                "result": "",
                "total_cost_usd": 0.0,
                "usage": {},
            }
        data = json.loads(r.stdout)
        cost = data.get("total_cost_usd", 0)
        out_t = data.get("usage", {}).get("output_tokens", 0)
        print(
            f"[{time.strftime('%H:%M:%S')}] <- {label} ${cost:.3f} {out_t}out",
            file=sys.stderr,
        )
        return data
    except Exception as e:  # noqa: BLE001
        return {
            "_error": repr(e),
            "result": "",
            "total_cost_usd": 0.0,
            "usage": {},
        }


def is_committed(text: str) -> bool:
    return bool(COMMIT_RE.search(text))


def extract_disposition(text: str) -> str | None:
    m = DISP_RE.search(text)
    if m:
        return m.group(1).lower()
    # Fallback: search for disposition word near committing
    if COMMIT_RE.search(text):
        for word in ("malicious", "escalate", "suspicious", "benign"):
            if re.search(rf"\b{word}\b", text, re.IGNORECASE):
                return word
    return None


def load_text(p: Path) -> str:
    return p.read_text()


def load_alert(fid: str) -> str:
    return json.dumps(
        json.loads((FIXTURES / f"{fid}.json").read_text())["alert"], indent=2
    )


def render_history(turns: list[dict]) -> str:
    if not turns:
        return "(none — this is turn 1)"
    parts = []
    for t in turns:
        parts.append(f"## TURN {t['n']} (your output)\n\n{t['agent_text']}")
        if t.get("tool_results"):
            parts.append(f"## TURN {t['n']} TOOL RESULTS\n\n{t['tool_results']}")
        if t.get("redirect_block"):
            parts.append(
                f"## REVIEWER REDIRECT before TURN {t['n']+1}\n\n{t['redirect_block']}"
            )
    return "\n\n".join(parts)


def render_transcript(turns: list[dict], include_commit: bool = True) -> str:
    parts = []
    for t in turns:
        if not include_commit and is_committed(t["agent_text"]):
            continue
        parts.append(f"### TURN {t['n']} agent\n\n{t['agent_text']}")
        if t.get("tool_results"):
            parts.append(f"### TURN {t['n']} tool results\n\n{t['tool_results']}")
    return "\n\n".join(parts)


def run_one_turn(
    template: str,
    alert: str,
    protocol: str,
    addendum_block: str,
    turn_num: int,
    history: str,
    label: str,
    extra_note: str = "",
) -> dict:
    prompt = (
        template.replace("{{ADDENDUM_BLOCK}}", addendum_block)
        .replace("{{PROTOCOL_BLOCK}}", protocol)
        .replace("{{ALERT_BLOCK}}", alert)
        .replace("{{TURN_NUM}}", str(turn_num))
        .replace("{{HISTORY_BLOCK}}", history)
    )
    if extra_note:
        prompt += f"\n\n{extra_note}\n"
    return claude_call(prompt, label)


def parse_reviewer_verdict(text: str) -> str:
    m = re.search(r"VERDICT:\s*(CONCEDE|REDIRECT)", text, re.IGNORECASE)
    return m.group(1).upper() if m else "UNPARSED"


def trial(checkpoint: str, trial_id: int, alert: str, protocol: str) -> dict:
    """Run a single trial under one checkpoint condition."""
    label = f"{checkpoint}/t{trial_id}"
    template = load_text(PROMPTS / "long_defender.md")
    fact_base = json.loads(FACTS.read_text())

    turns: list[dict] = []
    total_cost = 0.0
    total_in = total_out = 0
    reviewer_call: dict | None = None
    reviewer_verdict: str | None = None
    redirect_text: str | None = None
    redirect_changed_call: bool | None = None
    pre_redirect_disposition: str | None = None
    committed = False
    start = time.time()

    n = 1
    while n <= MAX_TURNS and not committed:
        # Add the "do not commit yet" nudge for pre-COMMIT before the would-be
        # final commit turn — implementation: after each non-committed turn,
        # if checkpoint==pre-COMMIT and we've not yet reviewed, peek at the
        # current turn output; if defender is approaching commit (we just
        # detect via is_committed below), back off and inject reviewer.
        history = render_history(turns)
        extra_note = ""
        if n == MAX_TURNS:
            extra_note = (
                "NOTE: this is the final turn. You MUST commit (STATE: "
                "committing) — no more tool calls will be resolved.\n"
            )
        data = run_one_turn(
            template, alert, protocol, "", n, history, f"{label}:def-T{n}", extra_note
        )
        agent_text = data.get("result", "")
        total_cost += data.get("total_cost_usd", 0.0) or 0.0
        u = data.get("usage", {}) or {}
        total_in += u.get("input_tokens", 0) or 0
        total_out += u.get("output_tokens", 0) or 0

        # Resolve tool calls for this turn
        calls = adapter.parse_tool_calls(agent_text)
        tool_results = ""
        if calls:
            pairs = [(c, adapter.lookup(c, fact_base)) for c in calls]
            tool_results = adapter.format_results(pairs)

        turn_record = {
            "n": n,
            "agent_text": agent_text,
            "tool_results": tool_results,
            "tool_calls": [c.get("tool", "") for c in calls],
        }

        # ---- Checkpoint: post-PREDICT ----
        if checkpoint == "post-PREDICT" and n == 1 and reviewer_call is None:
            # Build turn1 block from this turn (no commit expected at n=1)
            turn1_block = (
                f"### Defender turn 1\n\n{agent_text}\n\n"
                f"### Tool results\n\n{tool_results or '(none)'}"
            )
            rprompt = (
                load_text(PROMPTS / "checkpoint_reviewer_post_predict.md")
                .replace("{{ALERT_BLOCK}}", alert)
                .replace("{{TURN1_BLOCK}}", turn1_block)
            )
            reviewer_call = claude_call(rprompt, f"{label}:rev-postPREDICT")
            total_cost += reviewer_call.get("total_cost_usd", 0.0) or 0.0
            ru = reviewer_call.get("usage", {}) or {}
            total_in += ru.get("input_tokens", 0) or 0
            total_out += ru.get("output_tokens", 0) or 0
            reviewer_verdict = parse_reviewer_verdict(reviewer_call.get("result", ""))
            if reviewer_verdict == "REDIRECT":
                redirect_text = reviewer_call.get("result", "")
                turn_record["redirect_block"] = redirect_text

        # ---- Checkpoint: pre-COMMIT ----
        if (
            checkpoint == "pre-COMMIT"
            and is_committed(agent_text)
            and reviewer_call is None
        ):
            # The actor just committed; intercept before we accept the commit.
            pre_redirect_disposition = extract_disposition(agent_text)
            # Build transcript of all turns INCLUDING this would-be commit
            transcript = render_transcript(turns + [turn_record], include_commit=True)
            rprompt = (
                load_text(PROMPTS / "checkpoint_reviewer_pre_commit.md")
                .replace("{{ALERT_BLOCK}}", alert)
                .replace("{{TRANSCRIPT_BLOCK}}", transcript)
            )
            reviewer_call = claude_call(rprompt, f"{label}:rev-preCOMMIT")
            total_cost += reviewer_call.get("total_cost_usd", 0.0) or 0.0
            ru = reviewer_call.get("usage", {}) or {}
            total_in += ru.get("input_tokens", 0) or 0
            total_out += ru.get("output_tokens", 0) or 0
            reviewer_verdict = parse_reviewer_verdict(reviewer_call.get("result", ""))
            if reviewer_verdict == "REDIRECT":
                # Discard the would-be-commit turn; do one more turn with the
                # redirect injected.
                redirect_text = reviewer_call.get("result", "")
                # Mark turn as "rolled back" — agent_text discarded for next-turn
                # history; we keep the record for audit.
                turn_record["agent_text_rolled_back"] = agent_text
                turn_record["agent_text"] = (
                    "[turn rolled back by pre-COMMIT reviewer; see redirect "
                    "below]\n\n" + agent_text.split("STATE: committing")[0]
                )
                turn_record["redirect_block"] = redirect_text
                turn_record["tool_results"] = tool_results
                turns.append(turn_record)
                # Force one more turn
                n += 1
                # Add the redirect-aware nudge in next turn
                extra_note = (
                    "REVIEWER REDIRECT (you must address this before "
                    "committing — run the named check, then commit):\n\n"
                    + redirect_text
                )
                history = render_history(turns)
                data2 = run_one_turn(
                    template,
                    alert,
                    protocol,
                    "",
                    n,
                    history,
                    f"{label}:def-T{n}-postRedirect",
                    extra_note,
                )
                agent_text = data2.get("result", "")
                total_cost += data2.get("total_cost_usd", 0.0) or 0.0
                u2 = data2.get("usage", {}) or {}
                total_in += u2.get("input_tokens", 0) or 0
                total_out += u2.get("output_tokens", 0) or 0
                calls2 = adapter.parse_tool_calls(agent_text)
                tool_results2 = ""
                if calls2:
                    pairs2 = [(c, adapter.lookup(c, fact_base)) for c in calls2]
                    tool_results2 = adapter.format_results(pairs2)
                turn_record = {
                    "n": n,
                    "agent_text": agent_text,
                    "tool_results": tool_results2,
                    "tool_calls": [c.get("tool", "") for c in calls2],
                    "post_redirect": True,
                }
                if is_committed(agent_text):
                    committed = True
                    new_disp = extract_disposition(agent_text)
                    redirect_changed_call = (
                        new_disp != pre_redirect_disposition
                        and new_disp is not None
                    )
                turns.append(turn_record)
                break
            # else CONCEDE: accept the commit
            committed = True
            turns.append(turn_record)
            break

        if is_committed(agent_text):
            committed = True
            turns.append(turn_record)
            break

        # If post-PREDICT and the redirect needs to be visible to defender,
        # render_history already includes redirect_block on the previous turn.
        turns.append(turn_record)
        n += 1

    # ---- Checkpoint: REPORT-time ----
    if checkpoint == "REPORT-time":
        transcript = render_transcript(turns, include_commit=True)
        rprompt = (
            load_text(PROMPTS / "checkpoint_reviewer_report_time.md")
            .replace("{{ALERT_BLOCK}}", alert)
            .replace("{{TRANSCRIPT_BLOCK}}", transcript)
        )
        reviewer_call = claude_call(rprompt, f"{label}:rev-REPORTtime")
        total_cost += reviewer_call.get("total_cost_usd", 0.0) or 0.0
        ru = reviewer_call.get("usage", {}) or {}
        total_in += ru.get("input_tokens", 0) or 0
        total_out += ru.get("output_tokens", 0) or 0
        reviewer_verdict = parse_reviewer_verdict(reviewer_call.get("result", ""))

    final_turn_text = turns[-1]["agent_text"] if turns else ""
    disposition = extract_disposition(final_turn_text) if committed else None
    total_tool_calls = sum(len(t.get("tool_calls", [])) for t in turns)

    return {
        "checkpoint": checkpoint,
        "trial_id": trial_id,
        "turns": turns,
        "turn_count": len([t for t in turns if not t.get("agent_text_rolled_back")]),
        "committed": committed,
        "disposition": disposition,
        "total_tool_calls": total_tool_calls,
        "reviewer_verdict": reviewer_verdict,
        "reviewer_text": reviewer_call.get("result", "") if reviewer_call else "",
        "redirect_text": redirect_text,
        "pre_redirect_disposition": pre_redirect_disposition,
        "redirect_changed_call": redirect_changed_call,
        "total_cost_usd": total_cost,
        "tokens": {"in": total_in, "out": total_out},
        "wall_s": time.time() - start,
    }


def fmt_trial(t: dict) -> str:
    head = (
        f"## {t['checkpoint']} trial {t['trial_id']}\n\n"
        f"- turns: {t['turn_count']} (committed={t['committed']})\n"
        f"- disposition: {t['disposition']}\n"
        f"- total tool calls: {t['total_tool_calls']}\n"
        f"- reviewer verdict: {t['reviewer_verdict']}\n"
        f"- redirect changed call: {t['redirect_changed_call']}\n"
        f"- pre-redirect disposition: {t['pre_redirect_disposition']}\n"
        f"- cost: ${t['total_cost_usd']:.4f}\n"
        f"- tokens: in={t['tokens']['in']} out={t['tokens']['out']}\n"
        f"- wall: {t['wall_s']:.1f}s\n\n"
    )
    body = []
    for tn in t["turns"]:
        body.append(f"### TURN {tn['n']}\n\n```\n{tn['agent_text']}\n```\n")
        if tn.get("tool_results"):
            body.append(f"#### tool results\n\n```\n{tn['tool_results']}\n```\n")
        if tn.get("redirect_block"):
            body.append(f"#### redirect injected\n\n```\n{tn['redirect_block']}\n```\n")
    body.append(f"### REVIEWER OUTPUT\n\n```\n{t['reviewer_text']}\n```\n")
    return head + "\n".join(body)


def summary(results: list[dict]) -> str:
    by_cp: dict[str, list[dict]] = {}
    for r in results:
        by_cp.setdefault(r["checkpoint"], []).append(r)
    rows = ["| Checkpoint | n | Verdicts | Disp | Avg turns | Avg tools | Avg cost | Reviewer CONCEDE/REDIRECT | Redirects that changed call |",
            "|---|---|---|---|---|---|---|---|---|"]
    for cp, ts in by_cp.items():
        n = len(ts)
        disps = [t["disposition"] or "?" for t in ts]
        avg_turns = sum(t["turn_count"] for t in ts) / max(n, 1)
        avg_tools = sum(t["total_tool_calls"] for t in ts) / max(n, 1)
        avg_cost = sum(t["total_cost_usd"] for t in ts) / max(n, 1)
        concede = sum(1 for t in ts if t["reviewer_verdict"] == "CONCEDE")
        redirect = sum(1 for t in ts if t["reviewer_verdict"] == "REDIRECT")
        flips = sum(1 for t in ts if t["redirect_changed_call"] is True)
        verdicts = ", ".join(t["disposition"] or "?" for t in ts)
        rows.append(
            f"| {cp} | {n} | {verdicts} | {','.join(disps)} | {avg_turns:.1f} | "
            f"{avg_tools:.1f} | ${avg_cost:.3f} | {concede}/{redirect} | {flips} |"
        )
    return "\n".join(rows)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=3)
    ap.add_argument(
        "--checkpoints",
        nargs="+",
        default=["post-PREDICT", "pre-COMMIT", "REPORT-time"],
    )
    ap.add_argument("--out", default=str(RESULTS / "checkpoint-comparison.md"))
    ap.add_argument("--state", default=str(RESULTS / "checkpoint-comparison-state.json"))
    args = ap.parse_args()

    alert = load_alert(FID)
    protocol = load_text(PROTOCOL)

    state_path = Path(args.state)
    state = json.loads(state_path.read_text()) if state_path.exists() else {"results": []}
    done_keys = {(r["checkpoint"], r["trial_id"]) for r in state["results"]}

    jobs = []
    for cp in args.checkpoints:
        for i in range(1, args.n + 1):
            if (cp, i) in done_keys:
                continue
            jobs.append((cp, i))

    print(f"Running {len(jobs)} jobs (skipping {len(done_keys)} already done)", file=sys.stderr)

    with cf.ThreadPoolExecutor(max_workers=4) as ex:
        futs = {ex.submit(trial, cp, i, alert, protocol): (cp, i) for cp, i in jobs}
        for f in cf.as_completed(futs):
            cp, i = futs[f]
            try:
                r = f.result()
            except Exception as e:  # noqa: BLE001
                print(f"FAIL {cp}/t{i}: {e}", file=sys.stderr)
                continue
            state["results"].append(r)
            state_path.write_text(json.dumps(state, indent=2, default=str))
            print(
                f"done {cp}/t{i}: disp={r['disposition']} turns={r['turn_count']} "
                f"rev={r['reviewer_verdict']} cost=${r['total_cost_usd']:.3f}",
                file=sys.stderr,
            )

    md_parts = [
        f"# Checkpoint comparison — fixture {FID}\n",
        f"Model: {MODEL}. n={args.n} per checkpoint.\n\n",
        "Ground truth: MALICIOUS / ESCALATE.\n\n",
        "## Summary\n\n",
        summary(state["results"]),
        "\n\n## Trials\n\n",
    ]
    for r in sorted(state["results"], key=lambda x: (x["checkpoint"], x["trial_id"])):
        md_parts.append(fmt_trial(r))
    Path(args.out).write_text("\n".join(md_parts))
    print(f"Wrote {args.out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
