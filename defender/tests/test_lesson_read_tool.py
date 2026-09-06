"""Executable spec for the curator ``lesson_read`` tool (#559, part C/D).

The lesson curators lose the generic ``read_file`` (``read=True`` dropped from
``CORPUS_AUTHOR_DEF``) and gain ``lesson_read(path, part="body"|"full", pattern=None)`` — a
thin wrapper over ``_tool_read_file``'s gate + bounded-read + wrap core that adds a ``part``
mode (body-default strips frontmatter; full = whole file) and degrades to whole text on a
non-fenced file. The read gate stays root-only (a sibling corpus / ``_TEMPLATE.md`` is
reachable where the corpus-anchored ``cat`` lane is not), a lesson stays trusted (no salted
wrap), and ``_record_lesson_load`` is widened to all three corpora.

Every test drives the REAL registered tool on a CORPUS_AUTHOR agent built by
``build_stage_agent`` (mirroring ``test_forward_check_tool.py``), invoking the tool's function
directly with a constructed ``RunContext`` so a returned str, a raised ``ModelRetry``, and a
``lessons_loaded.jsonl`` row are all observable. The ``lesson_read`` tool / the ``ToolSet``
field do NOT exist yet: the tool reds per-test as "not registered", ``ToolSet(lesson_read=…)``
reds as an unexpected-kwarg ``TypeError``, and ``.tools.lesson_read`` as ``AttributeError`` —
while every import here resolves against HEAD so the harness collects and proves itself.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from defender.tests._frames680 import frame_salt_of

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
from defender.tests._engine_helpers import fake_model as _fake_model  # noqa: E402
from defender.tests._engine_helpers import replay_once as _replay  # noqa: E402
from defender.runtime.tools import AgentDeps, register_tools  # noqa: E402
from defender.learning.author.curator_engine import (  # noqa: E402
    CORPUS_AUTHOR_DEF,
    CuratorDeps,
)
from defender.tests._curator_scene import (
    build_curator_agent,
    curator_deps,
    curator_scene,
    write_prompt,
)




def _scene(tmp_path: Path):
    """All THREE shipped corpora — this suite's subject is the curator's read confinement,
    which is vacuous if two of the three roots do not exist."""
    return curator_scene(
        tmp_path, extra_corpora=("lessons-actor", "lessons-environment"))


def _prompt(tmp_path: Path) -> Path:
    return write_prompt(tmp_path, "curator.md", "Curate. Emit AUTHOR_RESULT when done.\n")


def _build_curator_agent(tmp_path):
    return build_curator_agent(tmp_path, _prompt(tmp_path), _fake_model(_replay("")))


def _deps(scene) -> CuratorDeps:
    return curator_deps(scene, run_verify=lambda *a, **kw: "")


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


def test_l3_default_part_is_body(tmp_path):
    """demand: L3 — the DEFAULT part is 'body': no part arg yields the stripped body (and the tool
    schema records ``default='body'``)."""
    scene = _scene(tmp_path)
    lp = _lesson(scene.corpus, "l3", body="L3-BODY")
    agent, logger = _build_curator_agent(scene.tmp)
    try:
        out = _read(agent, _deps(scene), path=lp)
        schema = _tool(agent, "lesson_read").tool_def.parameters_json_schema
    finally:
        logger.close()
    assert "L3-BODY" in out
    assert "name:" not in out
    assert schema["properties"]["part"]["default"] == "body"


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
    """demand: L6 — ``pattern=`` grep-folds the SELECTED text (part-then-grep): under body only the
    body lines matching the pattern return, and the frontmatter is out of scope; pattern=None is
    unfolded."""
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
    """demand: L10 — an oversized lesson is truncated to the shared ``_read_char_cap`` with the same
    overflow notice as ``_tool_read_file`` (one core; ``part`` is its only added seam).

    The notice and its filter hint name ``lesson_read``, not ``read_file``: the curator has no bash
    reducer (no ``jq``, no ``defender-sql``), so it is precisely the agent that lands on the hint's
    read-tool branch — and ``read=True`` was dropped, so a hardcoded ``read_file`` would tell the
    one agent that reads this hint to call a tool it does not have."""
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
    """demand L11 as superseded by #680 — the legacy path classifier still does not mark
    lessons untrusted, but a learning-role lesson_read frames cross-agent authored bytes at
    the stronger model boundary."""
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










def test_t1_toolset_has_lesson_read_field(tmp_path):
    """demand: T1 — ``ToolSet`` has ``lesson_read: bool = False``."""
    assert ToolSet(lesson_read=True).lesson_read is True
    assert ToolSet().lesson_read is False


def test_t2_corpus_author_def_drops_read_adds_lesson_read(tmp_path):
    """demand: T2 — ``CORPUS_AUTHOR_DEF.tools`` has lesson_read=True AND NOT read=True."""
    assert CORPUS_AUTHOR_DEF.tools.lesson_read is True
    assert CORPUS_AUTHOR_DEF.tools.read is False


def test_t3_registers_lesson_read_not_read_file(tmp_path):
    """demand: T3 — a CORPUS_AUTHOR agent registers ``lesson_read`` and NOT ``read_file``; controls:
    lesson_read is absent from every other role, and a read=True role still registers ``read_file``
    with its ``pattern`` grep-fold."""
    agent, logger = _build_curator_agent(tmp_path)
    try:
        tools = agent._function_toolset.tools
        assert "lesson_read" in tools
        assert "read_file" not in tools
    finally:
        logger.close()
    for role, defn in AGENTS.items():
        assert defn.tools.lesson_read is (role is AgentRole.CORPUS_AUTHOR)
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
