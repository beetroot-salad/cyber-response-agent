"""Learning workspace names agree across host tools, permission gates and execution."""
from __future__ import annotations

from dataclasses import replace
from pathlib import Path, PurePosixPath

import pytest
from pydantic_ai.exceptions import ModelRetry

from defender.box import BoxExecutor, BoxRequest, BoxSpec, Mount
from defender.box._lifecycle import _host_fallback_env, _render_argv
from defender.box._spec import _HostTransport
from defender.learning.author.curator_engine import CuratorDeps, SHIPPED_LESSON_CORPORA
from defender.runtime.agent_definition import AgentDefinition, RunScope, ToolSet, bind
from defender._agent_role import AgentRole
from defender._model_view import ModelView
from defender.runtime.tools import AgentDeps, _tool_bash, _tool_edit_file, _tool_read_file, _tool_write_file
from defender.tests.support.runtime.engine._engine_helpers import fake_model, replay_once


def _curator(base: Path):
    repo, run = base / "checkout", base / "stage"
    run.mkdir(parents=True)
    for name in SHIPPED_LESSON_CORPORA:
        (repo / "defender" / name).mkdir(parents=True)
    view = ModelView.for_learning(run, repo)
    executor = BoxExecutor(transport=_HostTransport({}, view))
    return CuratorDeps.for_run(run, repo, repo / "defender/lessons", box=executor)


@pytest.mark.parametrize("layout", ["one", "different/deeper/place"])
def test_learning_reads_and_deletes_use_the_same_workspace_in_each_layout(tmp_path, layout):
    deps = _curator(tmp_path / layout)
    lesson = deps.corpus_dir / "old.md"
    lesson.write_text("old lesson")
    # #1108 P4 (O1): the lessons are the tenant's, so the model names them under its agent tree
    # (`/agent/lessons/...`), not under the product checkout's `/workspace/defender/lessons`.
    assert deps.view.to_model(lesson) == "/agent/lessons/old.md"
    assert "old lesson" in _tool_read_file(deps, "/agent/lessons/old.md")
    # The host-fallback bash transport only maps the `/workspace` spelling; the model-facing
    # name above is what the tools report, the checkout spelling is what this transport runs.
    assert "old lesson" in _tool_bash(deps, "cat defender/lessons/old.md")
    _tool_bash(deps, "rm /workspace/defender/lessons/old.md")
    assert not lesson.exists()
    assert deps.box.sandboxed is False


def test_learning_writes_and_edits_reach_the_authoritative_tree(tmp_path):
    deps = _curator(tmp_path)
    _tool_write_file(deps, "defender/lessons/new.md", "first")
    _tool_edit_file(deps, "/workspace/defender/lessons/new.md", "first", "second")
    assert (deps.corpus_dir / "new.md").read_text() == "second"
    with pytest.raises(ModelRetry, match="authored"):
        _tool_read_file(deps, "defender/lessons/new.md")


def test_workspace_like_grep_patterns_are_literal_data_in_host_execution(tmp_path):
    deps = _curator(tmp_path)
    (deps.corpus_dir / "paths.md").write_text("literal /workspace\nother line\n")
    result = _tool_bash(deps, "cat /workspace/defender/lessons/paths.md | grep /workspace")
    assert "literal /workspace" in result
    assert "other line" not in result


def test_real_stage_request_preserves_learning_identity_and_declares_its_workspace(tmp_path):
    from pydantic_ai.messages import UserPromptPart
    from pydantic_ai.models import override_allow_model_requests

    from defender.learning._pydantic_stage import run_stage
    from defender.learning.core.config import StageContext, StageWiring

    deps = _curator(tmp_path)
    prompt = tmp_path / "curator.md"
    prompt.write_text("You curate lessons for the defender learning loop.")
    seen = []
    instructions = []
    reply = replay_once("Reviewed.")

    def observe(messages, info):
        seen.append([part.content for message in messages for part in message.parts
                     if isinstance(part, UserPromptPart)])
        instructions.append(info.instructions or "")
        return reply(messages, info)

    with override_allow_model_requests(False):
        assert run_stage(
            stage="curator",
            wiring=StageWiring(prompt_path=prompt, model="test", effort=None,
                               trace_name="workspace.jsonl", label="curator"),
            ctx=StageContext(learning_run_dir=deps.run_dir, user="Review these findings.",
                             request_limit=1, wall_clock_timeout=10),
            deps=deps,
            make_model=fake_model(observe),
        ) == "Reviewed."
    assert "You are part of the defender learning loop." in instructions[0]
    assert "Working directory: /workspace" in instructions[0]
    assert "/learning/current" in instructions[0]
    assert seen[0] == ["Review these findings."]


def test_learning_stage_files_remain_readable_without_new_shell_access(tmp_path):
    deps = _curator(tmp_path)
    (deps.run_dir / "shared.txt").write_text("another stage's output")
    assert "another stage's output" in _tool_read_file(deps, "/learning/current/shared.txt")
    with pytest.raises(ModelRetry):
        _tool_bash(deps, "cat /learning/current/shared.txt")
    (deps.run_dir / "wire_logs").mkdir()
    (deps.run_dir / "wire_logs/context.txt").write_text("private context")
    with pytest.raises(ModelRetry):
        _tool_read_file(deps, "/learning/current/wire_logs/context.txt")


def test_host_paths_and_traversal_are_refused_before_opening(tmp_path):
    deps = _curator(tmp_path)
    lesson = deps.corpus_dir / "secret.md"
    lesson.write_text("not a tool error")
    for path in (str(lesson), "defender/lessons/../lessons/secret.md"):
        with pytest.raises(ModelRetry) as error:
            _tool_read_file(deps, path)
        assert "not a tool error" not in str(error.value)
    with pytest.raises(ModelRetry):
        _tool_bash(deps, f"rm {lesson}")
    assert lesson.exists()


def _reader(tmp_path, scope):
    definition = AgentDefinition(role=AgentRole.MAIN, model=lambda: "test", effort=None,
                                 tools=ToolSet(read=True), deps_cls=AgentDeps)
    return bind(definition, tmp_path / "run", defender_dir=tmp_path / "code", scope=scope)


def test_external_grants_require_names_and_names_do_not_grant_access(tmp_path):
    extra = tmp_path / "extra"
    extra.mkdir()
    (extra / "file.txt").write_text("external bytes")
    roots = ((PurePosixPath("/inputs/source"), extra),)
    with pytest.raises(ValueError, match="none of the model view"):
        _reader(tmp_path, RunScope(add_dirs=(extra,)))
    deps = _reader(tmp_path, RunScope(add_dirs=(extra,), model_roots=roots))
    assert _tool_read_file(deps, "/inputs/source/file.txt") == "external bytes"
    denied = _reader(tmp_path, RunScope(model_roots=roots))
    with pytest.raises(ModelRetry):
        _tool_read_file(denied, "/inputs/source/file.txt")


def test_extra_grant_inside_an_existing_tree_needs_no_new_name(tmp_path):
    extra = tmp_path / "code" / "inputs"
    extra.mkdir(parents=True)
    (extra / "file.txt").write_text("already mapped")
    deps = _reader(tmp_path, RunScope(add_dirs=(extra,)))
    assert _tool_read_file(deps, "/defender/inputs/file.txt") == "already mapped"


def test_read_confine_does_not_introduce_an_external_workspace_tree(tmp_path):
    extra = tmp_path / "private"
    extra.mkdir()
    artifact = extra / "file.txt"
    artifact.write_text("private bytes")
    deps = _reader(tmp_path, RunScope(read_confine=(extra,)))
    assert deps.view.to_host("/private/file.txt") is None
    with pytest.raises(ModelRetry):
        _tool_read_file(deps, str(artifact))


def test_conflicting_roots_are_refused_and_nested_host_roots_use_the_specific_name(tmp_path):
    with pytest.raises(ValueError, match="conflicting model roots"):
        ModelView(((PurePosixPath("/one"), tmp_path / "a"),
                   (PurePosixPath("/one/two"), tmp_path / "b")), PurePosixPath("/one"))
    view = ModelView.for_learning(tmp_path / "checkout/run", tmp_path / "checkout")
    assert view.to_model(tmp_path / "checkout/run/file") == "/learning/current/file"
    assert view.to_host("defender/skills/x.md") == tmp_path / "checkout/defender/skills/x.md"


def test_learning_link_refusal_still_applies_below_mapped_roots(tmp_path):
    deps = _curator(tmp_path)
    target = deps.corpus_dir / "target.md"
    target.write_text("target")
    (deps.corpus_dir / "link.md").symlink_to(target)
    with pytest.raises(ModelRetry):
        _tool_read_file(deps, "defender/lessons/link.md")


def test_draft_request_keeps_host_image_inputs_and_model_execution_paths(tmp_path):
    code, draft = tmp_path / "code", tmp_path / "draft"
    view = ModelView.for_draft(code, draft)
    request = BoxRequest(
        name="learning-workspace", workdir=draft / "agent", defender_dir=code, view=view,
        mounts=(Mount(code, Path("/defender"), kind="code"),
                Mount(draft, Path("/draft"), kind="staged"),
                Mount(draft / "agent/lessons", Path("/draft/agent/lessons"), writable=True)),
        env={"DEFENDER_AGENT_DIR": "/draft/agent"},
        spec=BoxSpec(rootfs="defender-box:test1262"), require_sandbox=True,
    )
    argv = _render_argv(request).argv
    assert argv[argv.index("--workdir") + 1] == "/draft/agent"
    assert "DEFENDER_DIR=/defender" in argv
    assert "DEFENDER_AGENT_DIR=/draft/agent" in argv
    assert request.code_dir == code
    assert _host_fallback_env(replace(request, require_sandbox=False))["DEFENDER_AGENT_DIR"] == str(draft / "agent")


def test_investigation_layout_remains_unchanged(tmp_path):
    view = ModelView.for_run(tmp_path / "run", tmp_path / "code", tmp_path / "agent")
    assert tuple(str(model) for model, _ in view.trees()) == ("/runs/current", "/defender", "/agent")
    assert view.cwd == PurePosixPath("/runs/current")
    assert view.to_host("gather_raw/payload.json") == tmp_path / "run/gather_raw/payload.json"
