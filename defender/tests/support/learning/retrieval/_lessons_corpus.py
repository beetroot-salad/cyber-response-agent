"""Lesson-corpus fixtures shared by the frontier-retrieval suites — and the MAIN `deps`
those suites drive `_frontier_recall` through."""
from __future__ import annotations

from pathlib import Path


def _write_lesson(
    corpus: Path,
    name: str,
    *,
    nodes: tuple[str, ...] = (),
    edges: tuple[str, ...] = (),
    observed: tuple[str, ...] = (),
    signature: str = "v2-cross-tier-ssh-pivot",
    filename: str | None = None,
    raw_nodes: str | None = None,
) -> Path:
    """One lesson file. `nodes` / `edges` are YAML FLOW mappings written exactly as the
    design spells them (`type: process, slot: attrs.loginuid`), so the fixture and the doc
    cannot drift on spelling."""
    lines = [
        f"name: {name}",
        f"description: {name} description",
        f"source_signature: [{signature}]",
    ]
    if observed:
        lines.append("observed_nodes:")
        lines += [f"  - {{{sel}}}" for sel in observed]
    if raw_nodes is not None:
        lines.append(f"frontier_nodes: {raw_nodes}")
    elif nodes:
        lines.append("frontier_nodes:")
        lines += [f"  - {{{sel}}}" for sel in nodes]
    if edges:
        lines.append("frontier_edges:")
        lines += [f"  - {{{sel}}}" for sel in edges]
    path = corpus / (filename or f"{name}.md")
    path.write_text("---\n" + "\n".join(lines) + "\n---\n\nlesson body\n", encoding="utf-8")
    return path


def _main_deps(tmp_path: Path):
    """MAIN deps through the real `bind` seam — real compiled policy, real gate.

    `test_append_only_write_lane_810.py::_main_deps` verbatim, plus the defender tree in the
    return: the corpus `_tool_append_block` recalls against is `deps`-resolved
    (`defender_dir/lessons`, MAIN's own `corpus_dirs` entry), so a hermetic test needs the
    tmp tree the `bind` call was given.

    HERE for the same reason `_write_lesson` is: three suites drive this seam, and reaching for
    it inside a COLLECTED module is what loads that module twice in one session. The two
    imports below stay lazy so this module costs nothing to import without the runtime extra.
    """
    from defender.agents import MAIN_DEF
    from defender.runtime.agent_definition import bind

    from defender.tests.support.shared._fixture_uuid import fixture_uuid

    # #1187 (declared change 1): a run folder's name is its canonical UUID run id.
    run = tmp_path / fixture_uuid("run")
    run.mkdir()
    dfn = tmp_path / "defender"
    dfn.mkdir()
    from dataclasses import replace

    from defender.run_repository import Run

    return replace(bind(MAIN_DEF, run, defender_dir=dfn),
                   run=Run.under(run.parent, run.name)), run, dfn
