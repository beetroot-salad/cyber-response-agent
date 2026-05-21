#!/usr/bin/env python3
"""NL Bash wrapper for arm B-fake.

Surface: `advisory_nl.py "<NL goal sentence>"`. Logs the NL prompt
the main agent constructed (the data we care about — what does the
agent package into a free-text query?), best-effort spawns Haiku to
translate the NL into CLI args (we log Haiku's output regardless of
correctness), then unconditionally returns the canned fake-advisory
banner so the main agent has something to react to.

Failure mode: Haiku translation can fail (timeout, malformed output,
nonsense args). That's fine — for this experiment we just need to
see what NL the main agent constructed. Translation quality is a
secondary measurement; the wrapper never blocks on it.

Per-call telemetry: emitted on stderr as one JSON line so it lands
in the main agent's Bash tool_result (which captures both streams).
The harness extracts NL prompt + Haiku output from tool_trace.jsonl
post-hoc; no sidecar files.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import subprocess
import sys
import time
from pathlib import Path

HAIKU_MODEL = "claude-haiku-4-5"
HAIKU_TIMEOUT_S = 60
HERE = Path(__file__).resolve().parent
FAKE = HERE / "fake_advisory.py"


HAIKU_PROMPT = """You translate natural-language requests for past
incident precedent into a CLI invocation. The CLI is:

    python3 -m defender.scripts.invlang.cli /tmp/defender-runs advisory \\
        --signature <wazuh-rule-NNNN> \\
        --class lead_discrimination \\
        --frontier '?hyp-name-one' \\
        --frontier '?hyp-name-two' \\
        --top-k 5

Output ONLY the CLI invocation (one line), nothing else. No prose,
no explanation, no backticks. If you can't determine the signature
or at least one frontier hypothesis from the request, output the
literal token `UNABLE`.

Request:
"""


def call_haiku(nl: str) -> dict:
    """Best-effort. Returns telemetry; never raises."""
    t0 = time.monotonic()
    try:
        proc = subprocess.run(
            ["claude", "-p", HAIKU_PROMPT + nl,
             "--model", HAIKU_MODEL,
             "--output-format", "stream-json",
             "--verbose",
             "--permission-mode", "acceptEdits"],
            capture_output=True, text=True, timeout=HAIKU_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        return {"ok": False, "reason": "timeout",
                "wall_clock_s": round(time.monotonic() - t0, 2)}
    except Exception as e:
        return {"ok": False, "reason": f"spawn_error:{e!r}",
                "wall_clock_s": round(time.monotonic() - t0, 2)}
    wall = round(time.monotonic() - t0, 2)
    # Parse stream-json to find the assistant's final text + cost.
    text = ""
    cost = 0.0
    in_tok = out_tok = 0
    for line in (proc.stdout or "").splitlines():
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        if ev.get("type") == "assistant" and not ev.get("parent_tool_use_id"):
            for c in ev.get("message", {}).get("content", []) or []:
                if c.get("type") == "text":
                    text += c.get("text", "")
        if ev.get("type") == "result":
            cost += float(ev.get("total_cost_usd", 0) or 0)
            usage = ev.get("usage", {}) or {}
            in_tok += usage.get("input_tokens", 0) or 0
            out_tok += usage.get("output_tokens", 0) or 0
    return {
        "ok": True,
        "rc": proc.returncode,
        "wall_clock_s": wall,
        "cost_usd": round(cost, 4),
        "input_tokens": in_tok,
        "output_tokens": out_tok,
        "haiku_output": text.strip(),
    }


def main() -> int:
    if len(sys.argv) < 2:
        sys.stderr.write("usage: advisory_nl.py '<NL goal sentence>'\n")
        return 2
    nl = sys.argv[1]

    haiku = call_haiku(nl)

    sys.stderr.write(
        "[advisory_nl] "
        + json.dumps({
            "ts": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            "nl_prompt": nl,
            "haiku": haiku,
        })
        + "\n"
    )

    # Always return the fake banner so the main agent has something to react to.
    subprocess.run([sys.executable, str(FAKE)], check=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
