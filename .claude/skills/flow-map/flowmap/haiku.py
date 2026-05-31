"""Haiku worker: classify dispatch candidates the seed cannot resolve.

The seed mints DispatchCandidates (every `skills/X/SKILL.md` mention in a skill
body). Haiku's narrow job: for each candidate, decide whether the surrounding
prose makes it a real **subagent dispatch** (a Task() that spawns X to do work)
or a mere **doc reference** (prose pointing the reader at X's file). Only
dispatches become `dispatches` edges.

Invariants that keep this trustworthy and cheap:
  * Script owns identity. Haiku receives candidates by integer index and the
    pre-minted target_id; it returns verdicts keyed by that index. It cannot
    name a node the seed didn't mint — a verdict whose index is out of range is
    dropped by the structural gate, not trusted.
  * Strict JSON contract, one shot. The prompt forbids prose; output is parsed
    as a single JSON object. Parse failure / shape mismatch raises rather than
    silently yielding zero edges.
  * Edges are tagged confidence=llm, via=skill-marker, resolved_by=haiku — so a
    later deterministic resolver can supersede them, and a reviewer can see
    exactly which edges are model-judged.
"""
from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from .model import Edge, Gap, Graph
from .orchestration import DispatchCandidate

HAIKU_MODEL = os.environ.get("FLOWMAP_HAIKU_MODEL", "claude-haiku-4-5")
HAIKU_TIMEOUT = int(os.environ.get("FLOWMAP_HAIKU_TIMEOUT", "120"))

_SYSTEM = """You classify references inside a Claude Code skill's markdown body.

Each candidate is a place where the skill text mentions another skill's file,
written as `skills/<NAME>/SKILL.md`. Decide what the mention IS:

- "dispatch": the skill SPAWNS that other skill as a subagent to do work — the
  hallmark is a Task(...) call whose prompt says to *read and follow/execute*
  that SKILL.md (e.g. `Task(prompt="Read .../skills/gather/SKILL.md and follow
  it")`). The mention causes execution.
- "reference": the text merely POINTS the reader at that file for documentation
  ("see .../SKILL.md", "the X subagent reads this", "documents the grammar").
  No execution is caused at this mention.

Judge ONLY from the provided context lines. When the context shows a Task/
follow-it invocation → dispatch. When it is descriptive prose, a "see also", a
bullet describing a file, or says another component reads it → reference.

Output STRICT JSON, no prose, no code fence:
{"verdicts":[{"index":<int>,"kind":"dispatch"|"reference","why":"<<=10 words"}]}
Include exactly one verdict per candidate index given."""


def _build_user_prompt(cands: list[DispatchCandidate]) -> str:
    blocks = []
    for i, c in enumerate(cands):
        blocks.append(
            f"--- candidate {i} ---\n"
            f"mentions skill: {c.target_skill}\n"
            f"at: {c.ref}\n"
            f"context:\n{c.context}\n"
        )
    return (
        "Classify each candidate as dispatch or reference.\n\n"
        + "\n".join(blocks)
        + f"\nReturn one verdict per index 0..{len(cands) - 1}."
    )


def _run_haiku(system: str, user: str) -> str:
    # The system prompt is prepended to the user message rather than passed via
    # --system-prompt-file: it keeps the call to a single stdin channel, and the
    # classification instructions work equally well as a leading user block.
    cmd = [
        "claude", "-p",
        "--model", HAIKU_MODEL,
        "--output-format", "stream-json",
        "--verbose",
    ]
    full = system + "\n\n" + user
    proc = subprocess.run(cmd, input=full, capture_output=True, text=True,
                          timeout=HAIKU_TIMEOUT)
    if proc.returncode != 0:
        raise RuntimeError(f"claude -p failed (rc={proc.returncode}): "
                           f"{proc.stderr[-800:]}")
    return "\n\n".join(_assistant_text(proc.stdout))


def _assistant_text(stdout: str) -> list[str]:
    parts: list[str] = []
    for raw in stdout.splitlines():
        line = raw.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        msg = ev.get("message") or {}
        if msg.get("role") != "assistant":
            continue
        content = msg.get("content")
        if isinstance(content, list):
            for item in content:
                if isinstance(item, dict) and item.get("type") == "text" and item.get("text"):
                    parts.append(item["text"])
        elif isinstance(content, str) and content:
            parts.append(content)
    return parts


def _parse_obj(text: str) -> dict:
    """Extract the single JSON object from a model reply, tolerating a code
    fence or leading prose despite the no-fence instruction. Shared by every
    flow-map model caller so the extraction discipline lives in one place."""
    s = text.strip()
    if s.startswith("```"):
        s = s.split("\n", 1)[1] if "\n" in s else s
        if s.endswith("```"):
            s = s.rsplit("```", 1)[0]
    start = s.find("{")
    end = s.rfind("}")
    if start == -1 or end == -1:
        raise ValueError(f"no JSON object in model output: {text[:200]!r}")
    return json.loads(s[start:end + 1])


def _parse_verdicts(text: str) -> list[dict]:
    doc = _parse_obj(text)
    verdicts = doc.get("verdicts")
    if not isinstance(verdicts, list):
        raise ValueError("haiku output missing 'verdicts' list")
    return verdicts


def classify_candidates(g: Graph, cands: list[DispatchCandidate]) -> dict:
    """Run haiku over candidates; add dispatch edges; gap unresolved ones.

    Returns a summary dict. Mutates g.
    """
    if not cands:
        return {"dispatch": 0, "reference": 0, "dropped": 0}
    raw = _run_haiku(_SYSTEM, _build_user_prompt(cands))
    verdicts = _parse_verdicts(raw)

    by_index = {}
    dropped = 0
    for v in verdicts:
        idx = v.get("index")
        if not isinstance(idx, int) or not (0 <= idx < len(cands)):
            dropped += 1  # structural gate: haiku referenced a non-candidate
            continue
        by_index[idx] = v

    n_dispatch = n_reference = 0
    for i, c in enumerate(cands):
        v = by_index.get(i)
        if v is None:
            g.gaps.append(Gap("unclassified-dispatch", c.ref,
                              f"haiku returned no verdict for {c.target_skill} mention"))
            continue
        kind = v.get("kind")
        if kind == "dispatch":
            g.add_edge(Edge(c.src_id, c.target_id, "dispatches",
                            label=c.target_skill, ref=c.ref, via="skill-marker",
                            confidence="llm", resolved_by="haiku"))
            n_dispatch += 1
        else:
            n_reference += 1
    return {"dispatch": n_dispatch, "reference": n_reference, "dropped": dropped,
            "verdicts": by_index}
