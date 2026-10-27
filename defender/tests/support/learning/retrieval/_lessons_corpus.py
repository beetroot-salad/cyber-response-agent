"""Lesson-retrieval fixtures shared by several suites: lesson files, the MAIN `deps` the
frontier suites drive `_frontier_recall` through, and the tracer's tenant runs folder.

They live here, not in a collected test module, so importing one never loads a test module
twice; the imports stay lazy so this module needs no runtime extra."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_runs_base

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


def _run_copy_main_deps(tmp_path: Path):
    """Main's deps through the real `bind` seam (real compiled policy, real gate), bound over a
    run copy's agent root: the recall's corpus is the run copy's `lessons/` (threaded as
    `RunScope(tenant_agent=...)`), never `defender_dir/lessons`.

    Returns `(deps, run, agent_root, defender_dir)`: the caller plants lessons under
    `agent_root / "lessons"` and, to catch a stale reader, a decoy under `defender_dir`."""
    from dataclasses import replace

    from defender.agents import MAIN_DEF
    from defender.records import Run
    from defender.investigation.agent_definition import RunScope, bind
    from defender.tests.support.shared._fixture_uuid import fixture_uuid

    run = tmp_path / fixture_uuid("run")
    run.mkdir()
    dfn = tmp_path / "defender"
    dfn.mkdir()
    agent = tmp_path / "tenant" / "run-knowledge" / run.name / "agent"
    agent.mkdir(parents=True)
    deps = bind(MAIN_DEF, run, defender_dir=dfn, scope=RunScope(tenant_agent=agent))
    return replace(deps, run=Run.under(fixture_runs_base(run.parent), run.name)), run, agent, dfn


def _tenant_runs() -> Path:
    """The tracer's tenant runs folder `<data root>/<T>/runs` (`T` is `_spec1105.T_ID`), with its
    tenant record. Set up on request, so tests that never trace keep a tenant-free data root."""
    from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H1105
    from defender.tests.support.shared.contracts._data_root_1078 import current_data_root

    root = current_data_root()
    H1105.tenant(root, H1105.T_ID)
    runs = root / H1105.T_ID / "runs"
    runs.mkdir(exist_ok=True)
    return runs
