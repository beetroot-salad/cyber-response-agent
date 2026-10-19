"""#851: hostile or odd input reaches code that assumed it was well-formed (NUL in a bash/write/edit operand, a symlink-loop operand, a lone surrogate, a numeric rule id or odd alert signature); each must return a typed refusal the caller can act on, never raise, with a positive control that the clean input still works."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from defender.tests._1255_view import model_path

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

from pydantic_ai.exceptions import ModelRetry  # noqa: E402

from defender.agents import MAIN_DEF  # noqa: E402
from defender.runtime import orient, permission  # noqa: E402
from defender.runtime.agent_definition import bind  # noqa: E402
from defender.runtime.box import BoxResult  # noqa: E402
from defender.runtime.tools import _tool_bash, _tool_edit_file, _tool_write_file  # noqa: E402

from defender.tests._curator_691_harness import (  # noqa: E402
    corpus as corpus_dir,
    curator_deps,
    make_worktree,
    pending_run_dir,
    rel,
)
from defender.tests._frames680 import Box, DEFENDER  # noqa: E402
from defender.tests import _tenants1106 as T1106  # noqa: E402

#: A lone surrogate — not UTF-8-encodable, and reachable from a model tool-call JSON arg on a
#: provider that hands `args` back as an already-parsed dict (`json.loads('"\\ud800"')`).
SURROGATE = "\ud800"


def _box_scene(tmp_path: Path, definition, result=None):
    """A bound agent whose box is a fake — the bash lane with no container attached.

    `result` defaults to a clean success so a test asserting a REFUSAL is asserting that the
    refusal beat the box, not that the box happened to fail."""
    run = tmp_path / "run"
    defender_dir = tmp_path / "tree" / "defender"
    (run / "gather_raw" / "l-001").mkdir(parents=True)
    defender_dir.mkdir(parents=True)
    (run / "alert.json").write_text("{}", encoding="utf-8")
    (run / "gather_raw" / "l-001" / "1.json").write_text("{}", encoding="utf-8")
    box = Box(BoxResult(0, b"ok\n", b"") if result is None else result)
    return bind(definition, run, defender_dir=defender_dir, box=box), run, box


def _curator_scene(tmp_path: Path):
    """The curator — one of the two production roles that hold `ToolSet(write=True)`, and so one
    of the only two that can reach `_tool_write_file` / `_tool_edit_file` at all."""
    wt = make_worktree(tmp_path)
    deps = curator_deps(wt, pending_run_dir(tmp_path))
    return deps, corpus_dir(wt, "lessons")


_NUL_COMMANDS = (
    "echo a\x00b",
    "grep -n a\x00b",
    "defender-sql 'SELECT\x00 1'",
)


@pytest.mark.parametrize("command", _NUL_COMMANDS)
def test_f10_a_nul_in_an_opens_nothing_argv_is_denied_by_the_gate(command, tmp_path):
    deps, _run, _box = _box_scene(tmp_path, T1106.fixture_gather_def())
    d = permission.decide_bash(
        command, policy=deps.policy,
        run_dir=deps.run_dir, defender_dir=deps.defender_dir, cwd_anchor=deps.cwd_anchor,
    )
    assert d.allow is False
    assert d.reason == permission.EMBEDDED_NUL_REASON


def test_f10_the_cat_lane_still_denies_a_nul_operand(tmp_path):
    """Regression guard on the one lane that already refused (`test_grant_gate_575.py`'s a9):
    the new whole-string check must not have moved that deny somewhere it can be lost."""
    from defender.runtime.permission import bash as bash_gate

    deps, run, _box = _box_scene(tmp_path, MAIN_DEF)
    command = "cat inv\x00.md"
    d = permission.decide_bash(
        command, policy=deps.policy,
        run_dir=deps.run_dir, defender_dir=deps.defender_dir, cwd_anchor=deps.cwd_anchor,
    )
    assert d.allow is False

    pipelines = bash_gate._parse(command)
    assert pipelines is not None, "the NUL command still tokenizes — the deny is the gate's"
    below = bash_gate._decide_readers(pipelines, deps.policy, run_dir=deps.cwd_anchor)
    assert below is not None
    assert below.allow is False


@pytest.mark.parametrize("command", _NUL_COMMANDS)
def test_f07_the_bash_tool_refuses_a_nul_command_without_reaching_the_box(command, tmp_path):
    deps, _run, box = _box_scene(tmp_path, T1106.fixture_gather_def())
    with pytest.raises(ModelRetry):
        _tool_bash(deps, command)
    assert box.calls == []


def test_f07_a_nul_in_a_LATER_pipeline_stage_is_refused_too(tmp_path):
    deps, run, box = _box_scene(tmp_path, T1106.fixture_gather_def())
    payload = run / "gather_raw" / "l-001" / "1.json"
    with pytest.raises(ModelRetry):
        _tool_bash(deps, f"cat {model_path(payload, run_dir=run)} | grep -n a\x00b")
    assert box.calls == []


def test_f07_an_encoder_valueerror_becomes_a_retry_not_a_dead_run(tmp_path):
    deps, run, _box = _box_scene(
        tmp_path, T1106.fixture_gather_def(), result=ValueError("embedded null byte"),
    )
    with pytest.raises(ModelRetry) as excinfo:
        _tool_bash(deps, f"cat {model_path(run / 'alert.json', run_dir=run)}")
    assert "embedded null byte" in str(excinfo.value)


def test_f07_a_clean_command_still_runs(tmp_path):
    """Positive control: the NUL check is a check on ONE byte, not a new refusal of the bash
    lane. The same shapes without it reach the box and return its output."""
    deps, run, box = _box_scene(tmp_path, T1106.fixture_gather_def())
    assert "ok" in _tool_bash(deps, f"cat {model_path(run / 'alert.json', run_dir=run)}")
    assert len(box.calls) == 1


def test_f25_a_nul_operand_refuses_the_write_instead_of_killing_the_stage(tmp_path):
    deps, corpus = _curator_scene(tmp_path)
    with pytest.raises(ModelRetry):
        _tool_write_file(deps, rel("lessons", "x\x00.md"), "body\n")
    assert list(corpus.iterdir()) == []


def test_f25_a_nul_operand_refuses_the_edit_too(tmp_path):
    """The edit lane resolves through the SAME helper before its own `decide_read`, so it
    carried the identical hole and needs the identical answer."""
    deps, _corpus = _curator_scene(tmp_path)
    with pytest.raises(ModelRetry):
        _tool_edit_file(deps, rel("lessons", "x\x00.md"), "old", "new")


def test_f25_a_symlink_loop_operand_refuses_rather_than_raising(tmp_path):
    """The second trigger, and the one that needs no model output at all — filesystem state a
    previous spawn (or anything else sharing the tree) could have left behind."""
    deps, corpus = _curator_scene(tmp_path)
    a, b = corpus / "a.md", corpus / "b.md"
    os.symlink(b, a)
    os.symlink(a, b)
    with pytest.raises(ModelRetry):
        _tool_write_file(deps, rel("lessons", "a.md"), "body\n")


def test_f25_an_ordinary_corpus_write_still_lands(tmp_path):
    """Positive control: the fail-safe returns False for an UNRESOLVABLE operand only. A
    resolvable one still runs the RS15 check and then the real gate, and commits."""
    deps, corpus = _curator_scene(tmp_path)
    _tool_write_file(deps, rel("lessons", "ok.md"), "body\n")
    assert (corpus / "ok.md").read_text(encoding="utf-8") == "body\n"


def test_f26_a_lone_surrogate_is_denied_on_a_non_artifact_path(tmp_path):
    """The gate's contract is to RETURN a Decision, never propagate (its `RESOLVE_ERRORS`
    rule) — and that contract was only literally true on the artifact branch."""
    deps, corpus = _curator_scene(tmp_path)
    d = permission.decide_write(
        corpus / "x.md", f"body {SURROGATE}\n",
        run_dir=deps.run_dir, defender_dir=deps.defender_dir, policy=deps.policy,
    )
    assert d.allow is False
    assert "UTF-8" in d.reason


def test_f26_the_write_tool_refuses_unencodable_content(tmp_path):
    deps, corpus = _curator_scene(tmp_path)
    with pytest.raises(ModelRetry):
        _tool_write_file(deps, rel("lessons", "x.md"), f"body {SURROGATE}\n")
    assert list(corpus.iterdir()) == []


def test_f26_encodable_content_on_the_same_path_still_commits(tmp_path):
    """Positive control: the check is on encodability, not on the path or on non-ASCII text —
    a lesson body full of real Unicode still lands."""
    deps, corpus = _curator_scene(tmp_path)
    _tool_write_file(deps, rel("lessons", "x.md"), "körper — ok ✅\n")
    assert (corpus / "x.md").read_text(encoding="utf-8") == "körper — ok ✅\n"


def test_f26_an_undecodable_baseline_denies_rather_than_raising(tmp_path):
    deps, _run, _box = _box_scene(tmp_path, MAIN_DEF)
    inv = deps.run_dir / "investigation.md"
    inv.write_bytes(b"\xff\xfe not utf-8\n")
    d = permission.decide_write(
        inv, "```\n:V x | host\n```\n",
        run_dir=deps.run_dir, defender_dir=deps.defender_dir, policy=deps.policy,
    )
    assert d.allow is False
    assert "failing closed" in d.reason


from defender import _alert_input  # noqa: E402
from defender.run_repository import RunPaths  # noqa: E402
from defender.tests._alert_plant import plant_alert  # noqa: E402


def _sig(rule_id):
    """The signature the front door records for an alert carrying `rule_id`."""
    mapping = _alert_input.parse_mapping("signature: rule.id\n")
    return _alert_input.derive_facts({"rule": {"id": rule_id}}, mapping).signature


def _orient(tmp_path, rule_id):
    run_dir = tmp_path / "run"  # one level down: `run_env` makes its parent the shims' corpus root
    run_dir.mkdir()
    plant_alert(run_dir, {"rule": {"id": rule_id}})
    return orient.orientation(run_dir, DEFENDER, RunPaths(run_dir).alert, systems=())


def test_f23_a_numeric_rule_id_orients_instead_of_raising(tmp_path):
    """The shape a hand-authored or foreign-SIEM alert file carries."""
    out = _orient(tmp_path, 5710)
    assert isinstance(out, str)
    assert "## invlang grammar" in out
    assert _sig(5710) == "5710"


def test_f23_a_string_rule_id_is_unchanged():
    """Positive control: the rule is a no-op for every real alert in the corpus."""
    assert _sig("v2-falco-x") == "v2-falco-x"


@pytest.mark.parametrize("rule_id", [
    None,
    "",
    [],
    {},
    ["a"],
    {"a": 1},
    True,
    False,
])
def test_empty_or_non_scalar_rule_id_has_no_signature(rule_id):
    assert _sig(rule_id) is None


def test_f23_a_signature_carrying_a_nul_is_no_signature_and_orients(tmp_path):
    """A NUL in a signature was an argv element `subprocess.run` raised a bare `ValueError` on;
    it is not key-shaped, so it is recorded as no signature and orientation never sees it."""
    assert _sig("rule\x00id") is None
    out = _orient(tmp_path, "rule\x00id")
    assert isinstance(out, str)
    assert "## invlang grammar" in out
