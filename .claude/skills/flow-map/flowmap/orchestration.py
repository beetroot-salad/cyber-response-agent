"""Deterministic seed for the orchestration substrate (cross-substrate flow).

This is the repo-aware seam. It produces, with NO LLM:

  * hook wiring     — settings.json / run-settings.json:
                      `event --fires_hook[matcher]--> hook-script`  (json, ${VAR} expanded)
  * skill nodes     — defender/SKILL.md + defender/skills/*/SKILL.md (frontmatter name)
  * DISPATCH CANDIDATES — every `skills/<X>/SKILL.md` mention in a skill body,
                      with surrounding context. These are NOT edges. They are
                      handed to the haiku classifier, which decides per candidate
                      whether it is a real subagent dispatch or a doc reference.
                      Script mints the candidate's target node id; haiku may only
                      accept/reject candidates, never invent targets.

The deterministic/semantic split is deliberate: hook wiring is declarative JSON
(resolvable), but "is this SKILL.md mention a dispatch?" depends on the prose
around it — that is the haiku boundary.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

from .model import Edge, Graph, Node


SKILL_MENTION_RE = re.compile(r"skills/([a-z0-9][a-z0-9-]*)/SKILL\.md")


def _rel(p: Path, root: Path) -> str:
    try:
        return str(p.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(p)


def _frontmatter_name(md_path: Path) -> str:
    text = md_path.read_text()
    if not text.startswith("---"):
        return md_path.parent.name
    end = text.find("\n---", 3)
    block = text[3:end] if end != -1 else ""
    for line in block.splitlines():
        m = re.match(r"^name:\s*(.+?)\s*$", line)
        if m:
            return m.group(1).strip().strip("'\"")
    return md_path.parent.name


@dataclass
class DispatchCandidate:
    """A `skills/X/SKILL.md` mention awaiting dispatch/reference classification."""
    src_id: str          # skill node that contains the mention
    target_id: str       # script-minted node id for the mentioned skill
    target_skill: str    # X
    ref: str             # path:line of the mention
    line_text: str
    context: str         # a few lines around the mention


def seed_orchestration(root: Path, defender_dir: Path) -> tuple[Graph, list[DispatchCandidate]]:
    root = root.resolve()
    defender_dir = defender_dir.resolve()
    g = Graph(built_from={"root": str(root), "defender_dir": _rel(defender_dir, root)})

    # --- skill nodes --------------------------------------------------------
    skill_paths = [defender_dir / "SKILL.md"] + sorted(
        (defender_dir / "skills").glob("*/SKILL.md")
    )
    skill_id_by_name: dict[str, str] = {}
    for sp in skill_paths:
        if not sp.is_file():
            continue
        name = _frontmatter_name(sp)
        nid = f"skill:{_rel(sp, root)}"
        g.add_node(Node(id=nid, kind="skill", label=name, label_source="harvested",
                        ref=f"{_rel(sp, root)}:1"))
        # index by the directory name (what `skills/X/` mentions resolve to)
        skill_id_by_name[sp.parent.name] = nid

    # --- hook wiring (deterministic) ---------------------------------------
    for settings_rel in (".claude/settings.json", "defender/run-settings.json"):
        sp = root / settings_rel
        if sp.is_file():
            _extract_hooks(g, sp, root)

    # --- dispatch candidates (handed to haiku) ------------------------------
    candidates: list[DispatchCandidate] = []
    main_skill = defender_dir / "SKILL.md"
    if main_skill.is_file():
        candidates += _find_candidates(main_skill, root, skill_id_by_name,
                                       src_id=f"skill:{_rel(main_skill, root)}")
    return g, candidates


def _extract_hooks(g: Graph, settings_path: Path, root: Path) -> None:
    data = json.loads(settings_path.read_text())
    hooks = data.get("hooks", {})
    rel = _rel(settings_path, root)
    for event, groups in hooks.items():
        ev_id = f"event:{event}"
        g.add_node(Node(id=ev_id, kind="event", label=event, ref=f"{rel}:1"))
        for grp in groups:
            matcher = grp.get("matcher", "") or "*"
            for h in grp.get("hooks", []):
                cmd = h.get("command", "")
                m = re.search(r"([\w-]+)\.py", cmd)
                if not m:
                    continue
                hook_name = m.group(1)
                # resolve the hook file deterministically (defender/hooks/<name>.py)
                hook_file = root / "defender" / "hooks" / f"{hook_name}.py"
                ref = f"{_rel(hook_file, root)}:1" if hook_file.is_file() else f"{rel}:1"
                hid = f"hook:{hook_name}"
                g.add_node(Node(id=hid, kind="hook", label=hook_name,
                                label_source="harvested", ref=ref))
                g.add_edge(Edge(ev_id, hid, "fires_hook", label=matcher,
                                ref=f"{rel}:1", via="settings-hook",
                                confidence="deterministic", resolved_by="seed"))


def _find_candidates(md_path: Path, root: Path, skill_id_by_name: dict[str, str],
                     src_id: str) -> list[DispatchCandidate]:
    lines = md_path.read_text().splitlines()
    rel = _rel(md_path, root)
    out: list[DispatchCandidate] = []
    seen_lines: set[int] = set()
    for i, line in enumerate(lines):
        m = SKILL_MENTION_RE.search(line)
        if not m:
            continue
        if i in seen_lines:
            continue
        seen_lines.add(i)
        target = m.group(1)
        target_id = skill_id_by_name.get(target, f"skill:defender/skills/{target}/SKILL.md")
        ctx = "\n".join(lines[max(0, i - 3): i + 4])
        out.append(DispatchCandidate(
            src_id=src_id, target_id=target_id, target_skill=target,
            ref=f"{rel}:{i + 1}", line_text=line.strip(), context=ctx,
        ))
    return out
