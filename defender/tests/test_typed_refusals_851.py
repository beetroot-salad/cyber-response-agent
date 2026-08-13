"""#851 — five findings where a hostile or merely odd input value reaches code that assumes it
is well-formed, and the process RAISES instead of returning the typed refusal the surrounding
machinery was built to produce.

Every one is the same shape: validation is missing, or ordered after the operation that raises.
The gate already owns a refusal path (`Decision(False)` / `RESOLVE_ERRORS` / the correctable
`ModelRetry` protocol); these inputs route around it and take the run with them. So each section
below asserts the SAME thing in its own lane — a refusal the caller can act on, never a
propagating exception — plus the positive control that keeps "refuse everything" from passing.

They share a file because none is large enough to own one, and the roll-up issue is the record
they trace back to (the `test_hardening_776.py` precedent).

| Ref  | Site                        | The raise that escaped                              |
| F-07 | `runtime/box.py:113`        | `encode_request` -> bare `ValueError` out of the box |
| F-10 | `runtime/tools.py:289`      | the same, ALLOWED first by the gate for OPENS_NOTHING |
| F-25 | `runtime/tools.py:508`      | `p.resolve()` ahead of the gate's fail-closed guard  |
| F-26 | `runtime/tools.py:529`      | `write_guarded` -> `UnicodeEncodeError`              |
| F-23 | `runtime/orient.py:77`      | a numeric `rule.id` -> `TypeError` in `re.escape`    |
"""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

from pydantic_ai.exceptions import ModelRetry  # noqa: E402

from defender.agents import GATHER_DEF, MAIN_DEF  # noqa: E402
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


# =========================================================================== #
# F-07 / F-10 — an embedded NUL in a bash argv.
#
# The gate ALLOWED it for every program whose extractor is OPENS_NOTHING (no `resolve()` runs,
# so the `RESOLVE_ERRORS` deny that saves the `cat` lane never fires), and `encode_request` —
# which sits ABOVE `run_parsed`'s own try — then raised a bare `ValueError` that nothing between
# there and `run.py::main` catches. One command the model could have retried killed the whole
# investigation instead: no `write_trace`, no disposition, no `report.md`.
# =========================================================================== #

#: One per OPENS_NOTHING family that gather actually holds a grant for — a plain program, a
#: reducer, and a `defender-*` shim. Each of these was ALLOWED before the fix; a program the
#: gate refuses for an unrelated shape reason (`wc` takes no operand at all) would prove
#: nothing here.
_NUL_COMMANDS = (
    "echo a\x00b",
    "grep -n a\x00b",
    "defender-sql 'SELECT\x00 1'",
)


@pytest.mark.parametrize("command", _NUL_COMMANDS)
def test_f10_a_nul_in_an_opens_nothing_argv_is_denied_by_the_gate(command, tmp_path):
    """The OPENS_NOTHING programs are the whole hole: `cat` was already saved by `_in_scope`'s
    resolve, and every other granted program was not. The gate must refuse them too, with a
    reason the model can act on rather than the fallthrough silence."""
    deps, _run, _box = _box_scene(tmp_path, GATHER_DEF)
    d = permission.decide_bash(
        command, policy=deps.policy,
        run_dir=deps.run_dir, defender_dir=deps.defender_dir, cwd_anchor=deps.cwd_anchor,
    )
    assert d.allow is False
    assert d.reason == permission.EMBEDDED_NUL_REASON


def test_f10_the_cat_lane_still_denies_a_nul_operand(tmp_path):
    """Regression guard on the one lane that already refused (`test_grant_gate_575.py`'s a9):
    the new whole-string check must not have moved that deny somewhere it can be lost.

    Driven at BOTH altitudes on purpose. The whole-string check sits ahead of the parse, so
    through `decide_bash` it is now the only arm a NUL can ever reach — an assertion there
    would pass with `_in_scope`'s `RESOLVE_ERRORS` arm deleted, and would not be a guard on
    the cat lane at all. `_decide_readers` is therefore driven directly, below the new check,
    where that arm is still the thing answering."""
    from defender.runtime.permission import bash as bash_gate

    deps, run, _box = _box_scene(tmp_path, MAIN_DEF)
    command = f"cat {run}/inv\x00.md"
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
    """The end-to-end observable the finding is about, driven through the real tool: a
    `ModelRetry` (which pydantic-ai hands back to the model as a retryable denial), NOT a
    `ValueError` unwinding out of `run_investigation`. And the box is never called — the refusal
    is the gate's, so nothing unencodable is even offered to the wire."""
    deps, _run, box = _box_scene(tmp_path, GATHER_DEF)
    with pytest.raises(ModelRetry):
        _tool_bash(deps, command)
    assert box.calls == []


def test_f07_a_nul_in_a_LATER_pipeline_stage_is_refused_too(tmp_path):
    """The `cat | reducer` shape gather's own prompt tells it to use. Stage 0 opens a real
    payload and resolves clean; the NUL rides the reducer stage, where no `resolve()` ever ran —
    so a per-operand check alone would have let the frame through."""
    deps, run, box = _box_scene(tmp_path, GATHER_DEF)
    payload = run / "gather_raw" / "l-001" / "1.json"
    with pytest.raises(ModelRetry):
        _tool_bash(deps, f"cat {payload} | grep -n a\x00b")
    assert box.calls == []


def test_f07_an_encoder_valueerror_becomes_a_retry_not_a_dead_run(tmp_path):
    """Belt-and-braces behind the gate's deny, pinned independently of it: whatever else a
    future `encode_request` refuses to frame, the fault must arrive at the model as a refusal.
    `run_parsed`'s exception TYPE is deliberately left alone (`test_540_exec_seam.py` pins
    `pytest.raises(ValueError)` on it) — the mapping belongs at the tool seam."""
    deps, run, _box = _box_scene(
        tmp_path, GATHER_DEF, result=ValueError("embedded null byte"),
    )
    with pytest.raises(ModelRetry) as excinfo:
        _tool_bash(deps, f"cat {run}/alert.json")
    assert "embedded null byte" in str(excinfo.value)


def test_f07_a_clean_command_still_runs(tmp_path):
    """Positive control: the NUL check is a check on ONE byte, not a new refusal of the bash
    lane. The same shapes without it reach the box and return its output."""
    deps, run, box = _box_scene(tmp_path, GATHER_DEF)
    assert "ok" in _tool_bash(deps, f"cat {run}/alert.json")
    assert len(box.calls) == 1


# =========================================================================== #
# F-25 — `_closed_for_investigation_write` resolved a model-supplied operand ONE LINE ahead of
# `decide_write`/`decide_read`, so an operand that makes `resolve()` throw (an embedded NUL ->
# `ValueError`; a symlink loop -> `RuntimeError`) escaped the write/edit tool as an unhandled
# exception, quarantining the authoring spawn instead of becoming the `Decision(False)` that
# `RESOLVE_ERRORS` exists to produce.
# =========================================================================== #

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


# =========================================================================== #
# F-26 — the UTF-8-encodability check lived INSIDE `validate_artifact`, below the artifact
# keying, so it ran for `report.md` / `investigation.md` and for nothing else. Unencodable
# content on any other allowed path was ALLOWED by the gate and then raised
# `UnicodeEncodeError` out of `write_guarded`, which the write tools map to nothing.
# =========================================================================== #

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
    """The same content earns a clean `ModelRetry` on `report.md`; the corpus lane must not be
    the one place where it costs the whole spawn instead. Nothing is left behind — the deny
    happens before `write_guarded` stages anything."""
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
    """The OTHER exception `decide_write` could still hand its caller. investigation.md's
    schema takes the on-disk text as its append-only baseline, and the gate reads it — so
    an investigation.md that is not UTF-8 made `read_text` raise `UnicodeDecodeError` out of
    the gate, the same "propagate instead of decide" shape F-26 is about, one branch over.

    It DENIES rather than falling back to `current=None`: no baseline means no append-only
    check, which would let the faulting write replace the committed document."""
    deps, _run, _box = _box_scene(tmp_path, MAIN_DEF)
    inv = deps.run_dir / "investigation.md"
    inv.write_bytes(b"\xff\xfe not utf-8\n")
    d = permission.decide_write(
        inv, "```\n:V x | host\n```\n",
        run_dir=deps.run_dir, defender_dir=deps.defender_dir, policy=deps.policy,
    )
    assert d.allow is False
    assert "failing closed" in d.reason


# =========================================================================== #
# F-23 — `_alert_signature` is annotated `-> str | None` and returned the parsed JSON value
# RAW, so a numeric `rule.id` detonated in `re.escape` on `orientation()`'s unguarded path and
# killed the run before the first model request — an opaque `TypeError: decoding to str` in
# place of a legible complaint, and a breach of the module's own "orientation must never break
# the run" invariant.
# =========================================================================== #

def _alert(tmp_path: Path, rule_id) -> Path:
    p = tmp_path / "alert.json"
    p.write_text(json.dumps({"rule": {"id": rule_id}}), encoding="utf-8")
    return p


def test_f23_a_numeric_rule_id_orients_instead_of_raising(tmp_path):
    """The shape a hand-authored or foreign-SIEM alert file carries. `orientation()` must
    return its text; the id is a `str` by the time either consumer (`re.escape`, and the
    `subprocess.run` argv in the corpus-vocab section) sees it."""
    out = orient.orientation(tmp_path, DEFENDER, _alert(tmp_path, 5710))
    assert isinstance(out, str)
    assert "## invlang grammar" in out
    assert orient._alert_signature(_alert(tmp_path, 5710)) == "5710"


def test_f23_a_string_rule_id_is_unchanged(tmp_path):
    """Positive control: the coercion is a no-op for every real alert in the corpus."""
    assert orient._alert_signature(_alert(tmp_path, "v2-falco-x")) == "v2-falco-x"


@pytest.mark.parametrize("rule_id", [None, ""])
def test_f23_an_empty_signature_is_no_signature(rule_id, tmp_path):
    """`str(None)` would be the literal `"None"` and `""` would build a `source_signature ~ .*`
    pattern matching every lesson row — both are "no signature", not a signature."""
    assert orient._alert_signature(_alert(tmp_path, rule_id)) is None


@pytest.mark.parametrize("rule_id", [[], {}, ["a"], {"a": 1}, True, False])
def test_f23_a_non_scalar_signature_is_no_signature(rule_id, tmp_path):
    """`str()` is total, so the coercion alone turns every malformed id into a signature-shaped
    string that is not one — `[]` becomes `"[]"`, `false` becomes `"False"` — and hands it to
    the lessons grep and the shim argv as though the alert had declared it."""
    assert orient._alert_signature(_alert(tmp_path, rule_id)) is None


def test_f23_a_signature_carrying_a_nul_orients_instead_of_raising(tmp_path):
    """F-23's other consumer. Coercing to `str` fixes `re.escape`, but the SAME value is an
    argv element — and `subprocess.run` raises a bare `ValueError("embedded null byte")`, not
    an `OSError`, for a NUL in one. `_shim` folded only `OSError`/`TimeoutExpired`, so the
    signature took `orientation()` down before the first model request through the argv rather
    than through the regex: the identical invariant breach, one line over."""
    alert = _alert(tmp_path, "rule\x00id")
    assert orient._alert_signature(alert) == "rule\x00id"
    out = orient.orientation(tmp_path, DEFENDER, alert)
    assert isinstance(out, str)
    assert "## invlang grammar" in out
