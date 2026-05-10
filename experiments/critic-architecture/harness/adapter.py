"""Tool-call adapter for the critic-architecture experiment.

Agents emit `<tool_call>{...}</tool_call>` blocks in their output; this module
parses them, looks the call up in a fixture-specific fact base, and formats
results to feed back into the next turn.

The fact base is keyed by tool + canonical-arg-string. Misses return a
`no_results` envelope so the agent can decide how to handle absence — that
behavior (rationalize-the-miss vs ask-a-different-tool) is itself part of what
the experiment measures.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any

TOOL_CALL_RE = re.compile(r"<tool_call>\s*(\{.*?\})\s*</tool_call>", re.DOTALL)


def parse_tool_calls(text: str) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for m in TOOL_CALL_RE.finditer(text):
        try:
            out.append(json.loads(m.group(1)))
        except json.JSONDecodeError:
            continue
    return out


def _canonical_args(args: dict[str, Any]) -> str:
    return "|".join(f"{k}={args[k]}" for k in sorted(args))


def lookup(tool_call: dict[str, Any], fact_base: dict[str, Any]) -> dict[str, Any]:
    tool = tool_call.get("tool", "")
    args = tool_call.get("args", {}) or {}
    direct = f"{tool}:{_canonical_args(args)}"
    if direct in fact_base:
        return fact_base[direct]

    candidates = []
    for key, value in fact_base.items():
        if not key.startswith(f"{tool}:"):
            continue
        key_args_str = key[len(tool) + 1 :]
        score = 0
        for arg_name, arg_val in args.items():
            needle = f"{arg_name}={arg_val}"
            if needle in key_args_str:
                score += 2
            elif str(arg_val).lower() in key_args_str.lower():
                score += 1
        if score > 0:
            candidates.append((score, key, value))
    if candidates:
        candidates.sort(reverse=True)
        return candidates[0][2]

    return {
        "status": "no_results",
        "note": f"no events matched {tool} with {args}",
    }


def format_results(pairs: list[tuple[dict[str, Any], dict[str, Any]]]) -> str:
    parts: list[str] = []
    for call, result in pairs:
        parts.append(
            f'<tool_result tool="{call.get("tool", "")}" args="{_canonical_args(call.get("args", {}))}">\n'
            + json.dumps(result, indent=2)
            + "\n</tool_result>"
        )
    return "\n\n".join(parts)


def resolve(text: str, fact_base_path: str | Path) -> str:
    fact_base = json.loads(Path(fact_base_path).read_text())
    calls = parse_tool_calls(text)
    pairs = [(c, lookup(c, fact_base)) for c in calls]
    return format_results(pairs)


def main() -> None:
    if len(sys.argv) != 2:
        print("usage: adapter.py FACT_BASE_PATH < agent_output", file=sys.stderr)
        sys.exit(2)
    text = sys.stdin.read()
    print(resolve(text, sys.argv[1]))


if __name__ == "__main__":
    main()
