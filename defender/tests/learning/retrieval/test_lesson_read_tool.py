"""The curator `lesson_read` tool: part modes, read gate, bounded reads, trusted (unwrapped) output."""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from defender.tests.support.learning.curation._frames680 import frame_salt_of

pytest.importorskip("pydantic_ai")

from pydantic_ai import RunContext  # noqa: E402
from pydantic_ai.exceptions import ModelRetry  # noqa: E402
from pydantic_ai.messages import ModelResponse, TextPart  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402

import defender.runtime.tools as _rt_tools  # noqa: E402  (the shared read core / char cap)
from defender.runtime import permission  # noqa: E402
from defender.runtime.agent_role import AgentRole  # noqa: E402
from defender.agents import AGENTS  # noqa: E402
from defender.runtime.agent_definition import ToolSet  # noqa: E402
from defender.tests.support.runtime.engine._engine_helpers import fake_model as _fake_model  # noqa: E402
from defender.tests.support.runtime.engine._engine_helpers import replay_once as _replay  # noqa: E402
from defender.runtime.tools import AgentDeps, register_tools  # noqa: E402
from defender.learning.author.curator_engine import (  # noqa: E402
    CORPUS_AUTHOR_DEF,
    CuratorDeps,
)
from defender.tests.support.learning.curation._curator_scene import (
    build_curator_agent,
    curator_deps,
    curator_scene,
    write_prompt,
)


def _scene(tmp_path: Path):
    """Both live corpora — this suite's subject is the curator's read confinement, which is
    vacuous if the sibling root does not exist. (#1108 P4 U5: the retired `lessons-actor`/
    `lessons-environment` are deleted; `lessons-questioner` is the sibling that remains.)"""
    return curator_scene(tmp_path, extra_corpora=("lessons-questioner",))


def _prompt(tmp_path: Path) -> Path:
    return write_prompt(tmp_path, "curator.md", "Curate. Emit AUTHOR_RESULT when done.\n")


def _build_curator_agent(tmp_path):
    return build_curator_agent(tmp_path, _prompt(tmp_path), _fake_model(_replay("")))


def _deps(scene) -> CuratorDeps:
    return curator_deps(scene)


def _tool(agent, name: str):
    """The registered tool, or a clean per-test red naming the missing target."""
    tools = agent._function_toolset.tools
    assert name in tools, f"{name!r} tool not registered on the CORPUS_AUTHOR agent"
    return tools[name]


def _read(agent, deps, **kw) -> str:
    """Drive the CORPUS_AUTHOR agent's registered ``lesson_read`` once; return its text."""
    ctx = RunContext(deps=deps, model=agent.model, usage=None)
    return asyncio.run(_tool(agent, "lesson_read").function(ctx, **kw))


def _lesson(corpus: Path, stem: str, *, name_key: bool = True, body: str = "lesson body") -> str:
    """A minimal fenced lesson; returns the repo-relative operand the agent would type."""
    fm = f"name: {stem}\n" if name_key else "techniques: [T1]\n"
    (corpus / f"{stem}.md").write_text(f"---\n{fm}---\n{body}\n")
    return f"defender/{corpus.name}/{stem}.md"


def test_l1_body_default_strips_frontmatter(tmp_path):
    """demand: L1 — ``lesson_read(path)`` (default part='body') returns the frontmatter-stripped body."""
    scene = _scene(tmp_path)
    lp = _lesson(scene.corpus, "l1", body="L1-BODY-SENTINEL")
    agent, logger = _build_curator_agent(scene.tmp)
    try:
        out = _read(agent, _deps(scene), path=lp)
    finally:
        logger.close()
    assert "L1-BODY-SENTINEL" in out
    assert "name:" not in out
    assert "---" not in out


def test_l2_full_returns_whole_file(tmp_path):
    """demand: L2 — ``part='full'`` returns the whole file including frontmatter, observably != body."""
    scene = _scene(tmp_path)
    lp = _lesson(scene.corpus, "l2", body="L2-BODY")
    agent, logger = _build_curator_agent(scene.tmp)
    try:
        deps = _deps(scene)
        full = _read(agent, deps, path=lp, part="full")
        body = _read(agent, deps, path=lp)
    finally:
        logger.close()
    assert "name: l2" in full
    assert "name: l2" not in body
    assert full != body


def test_l4_part_enum_is_body_or_full(tmp_path):
    """demand: L4 — ``part`` is a Literal enum {body, full}: the tool schema pins exactly those two."""
    scene = _scene(tmp_path)
    agent, logger = _build_curator_agent(scene.tmp)
    try:
        schema = _tool(agent, "lesson_read").tool_def.parameters_json_schema
    finally:
        logger.close()
    assert set(schema["properties"]["part"]["enum"]) == {"body", "full"}


def test_l5_non_fenced_file_degrades_to_whole_text(tmp_path):
    """demand: L5 — a non-fenced file (FrontmatterError) degrades to whole text under body (no raise);
    part='full' returns whole text unconditionally."""
    scene = _scene(tmp_path)
    (scene.corpus / "l5.md").write_text("PLAIN TEXT NO FENCE\nsecond line\n")
    lp = "defender/lessons/l5.md"
    agent, logger = _build_curator_agent(scene.tmp)
    try:
        deps = _deps(scene)
        body = _read(agent, deps, path=lp)
        full = _read(agent, deps, path=lp, part="full")
    finally:
        logger.close()
    assert "PLAIN TEXT NO FENCE" in body
    assert "PLAIN TEXT NO FENCE" in full


def test_l6_pattern_grep_folds_the_selected_text(tmp_path):
    scene = _scene(tmp_path)
    (scene.corpus / "l6.md").write_text(
        "---\nname: l6\ndescription: SHARED-TOKEN in fm\n---\n"
        "SHARED-TOKEN in body\nother body line\n"
    )
    lp = "defender/lessons/l6.md"
    agent, logger = _build_curator_agent(scene.tmp)
    try:
        deps = _deps(scene)
        folded = _read(agent, deps, path=lp, part="body", pattern="SHARED-TOKEN")
        unfolded = _read(agent, deps, path=lp, part="body")
    finally:
        logger.close()
    assert "in body" in folded
    assert "in fm" not in folded
    assert "other body line" not in folded
    assert "other body line" in unfolded


def test_l7_denied_path_raises_no_existence_oracle(tmp_path):
    """demand: L7 — a path outside {run_dir, defender_dir} is denied with ModelRetry (no existence
    oracle, no leaked bytes); positive control: an in-corpus path returns its content."""
    scene = _scene(tmp_path)
    outside = scene.tmp / "outside.md"
    outside.write_text("OUTSIDE-SECRET-CONTENT\n")
    lp_ok = _lesson(scene.corpus, "l7-ok", body="IN-CORPUS-BODY")
    agent, logger = _build_curator_agent(scene.tmp)
    try:
        deps = _deps(scene)
        for bad in (str(outside), "defender/lessons/../../../../etc/passwd"):
            with pytest.raises(ModelRetry) as ei:
                _read(agent, deps, path=bad, part="full")
            assert "OUTSIDE-SECRET-CONTENT" not in str(ei.value)
        assert "IN-CORPUS-BODY" in _read(agent, deps, path=lp_ok)
    finally:
        logger.close()


def test_l10_oversized_lesson_bounded_by_shared_cap(tmp_path):
    scene = _scene(tmp_path)
    cap = _rt_tools._read_char_cap()
    (scene.corpus / "big.md").write_text("---\nname: big\n---\n" + "X" * (cap + 5000) + "\n")
    agent, logger = _build_curator_agent(scene.tmp)
    try:
        out = _read(agent, _deps(scene), path="defender/lessons/big.md", part="full")
    finally:
        logger.close()
    assert len(out) < cap + 5000
    assert "[lesson_read]" in out
    assert "too large" in out
    assert "lesson_read(" in out
    assert "pattern=" in out
    assert "read_file(" not in out


def test_l11_trusted_lesson_returned_raw_no_wrap(tmp_path):
    scene = _scene(tmp_path)
    lp = _lesson(scene.corpus, "l11", body="L11-RAW-BODY")
    assert permission.is_untrusted_read(scene.corpus / "l11.md") is False
    agent, logger = _build_curator_agent(scene.tmp)
    try:
        deps = _deps(scene)
        out = _read(agent, deps, path=lp, part="full")
    finally:
        logger.close()
    assert "L11-RAW-BODY" in out
    # #875: the frame's salt is minted at wrap time, so it is READ off the return, never
    # predicted from deps — which no longer carry one.
    salt = frame_salt_of(out, "untrusted")
    assert out.startswith(f"<run-{salt}-untrusted>\n")
    assert out.endswith(f"\n</run-{salt}-untrusted>")


def test_t2_corpus_author_def_drops_read_adds_lesson_read(tmp_path):
    """demand: T2 — ``CORPUS_AUTHOR_DEF.tools`` has lesson_read=True AND NOT read=True."""
    assert CORPUS_AUTHOR_DEF.tools.lesson_read is True
    assert CORPUS_AUTHOR_DEF.tools.read is False


def test_t3_registers_lesson_read_not_read_file(tmp_path):
    agent, logger = _build_curator_agent(tmp_path)
    try:
        tools = agent._function_toolset.tools
        assert "lesson_read" in tools
        assert "read_file" not in tools
    finally:
        logger.close()
    # The corpus author is the one role granting `lesson_read` (#1166 retired the repair spawn,
    # the other).
    lesson_read_roles = {AgentRole.CORPUS_AUTHOR}
    for role, defn in AGENTS.items():
        assert defn.tools.lesson_read is (role in lesson_read_roles)
    ctrl = _bare_agent()
    register_tools(ctrl, ToolSet(read=True))
    ctrl_tools = ctrl._function_toolset.tools
    assert "read_file" in ctrl_tools
    assert "lesson_read" not in ctrl_tools
    assert "pattern" in ctrl_tools["read_file"].tool_def.parameters_json_schema["properties"]


def test_t4_curator_still_reads_a_body_after_read_dropped(tmp_path):
    """demand: T4 — the curator can still read a lesson body after ``read=True`` was dropped:
    ``lesson_read`` discharges the removed read_file's read capability."""
    scene = _scene(tmp_path)
    lp = _lesson(scene.corpus, "t4", body="T4-SURVIVES")
    agent, logger = _build_curator_agent(scene.tmp)
    try:
        out = _read(agent, _deps(scene), path=lp)
    finally:
        logger.close()
    assert "T4-SURVIVES" in out


def _bare_agent():
    from pydantic_ai import Agent
    return Agent(
        FunctionModel(lambda m, i: ModelResponse(parts=[TextPart(content="x")])),
        deps_type=AgentDeps,
    )
