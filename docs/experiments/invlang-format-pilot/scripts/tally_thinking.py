#!/usr/bin/env python3
"""Tally thinking + token counts from a stream-json transcript.

Usage: tally_thinking.py <transcript.jsonl>

Emits a JSON summary with:
  - thinking_chars, thinking_blocks, thinking_tokens_est (chars/3)
  - total tokens (input + output + cache_read + cache_creation)
  - per-turn breakdown
"""
from __future__ import annotations
import json
import sys
from pathlib import Path


def tally(path: Path) -> dict:
    total = {"input": 0, "output": 0, "cache_read": 0, "cache_creation": 0}
    turns = []
    thinking_blocks = []
    assistant_count = 0
    with path.open() as f:
        for line in f:
            try:
                ev = json.loads(line)
            except json.JSONDecodeError:
                continue
            m = ev.get("message", {})
            if m.get("role") != "assistant":
                continue
            assistant_count += 1
            content = m.get("content") or []
            if not isinstance(content, list):
                content = []
            thinking_here = 0
            for block in content:
                if block.get("type") == "thinking":
                    t = block.get("thinking", "")
                    thinking_blocks.append(t)
                    thinking_here += len(t)
            u = m.get("usage") or {}
            tin = u.get("input_tokens", 0)
            tout = u.get("output_tokens", 0)
            tcr = u.get("cache_read_input_tokens", 0)
            tcc = u.get("cache_creation_input_tokens", 0)
            total["input"] += tin
            total["output"] += tout
            total["cache_read"] += tcr
            total["cache_creation"] += tcc
            turns.append({
                "turn": assistant_count,
                "thinking_chars": thinking_here,
                "input": tin,
                "output": tout,
                "cache_read": tcr,
                "cache_creation": tcc,
            })
    thinking_chars = sum(len(t) for t in thinking_blocks)
    return {
        "file": str(path),
        "assistant_turns": assistant_count,
        "thinking_blocks": len(thinking_blocks),
        "thinking_chars": thinking_chars,
        "thinking_tokens_est": thinking_chars // 3,
        "total_tokens": sum(total.values()),
        "by_type": total,
        "turns": turns,
    }


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(__doc__, file=sys.stderr)
        sys.exit(2)
    print(json.dumps(tally(Path(sys.argv[1])), indent=2))
