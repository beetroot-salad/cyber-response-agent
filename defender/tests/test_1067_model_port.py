"""What the strict-pydantic port (#1067) must NOT change about the records it swapped.

Each test here pins one behaviour the stdlib `@dataclass` gave for free and strict pydantic
takes away unless the record asks for it back: a mistyped field refusing as the DOMAIN
exception every caller's handler names (not pydantic's `ValidationError`), a mutable container
that `dataclasses.replace` must hand to the copy BY IDENTITY, a mapping that must not be
copied into a writable `dict`, a stdlib knob that must not vanish into `ConfigDict`, and a
compiled-pattern field that must not compile a bare string on the caller's behalf.
"""

from __future__ import annotations

import re
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType

import pytest
from pydantic import ValidationError

from defender._model import model


# ---------------------------------------------------------------------------------------
# the decorator itself
# ---------------------------------------------------------------------------------------


def test_model_forwards_kw_only_rather_than_dropping_it_into_config():
    """`@model(frozen=True, kw_only=True)` must build a keyword-only constructor — four
    `@dataclass(frozen=True, kw_only=True)` classes are queued for the later PRs of this
    sequence, and a knob splatted into `ConfigDict` is ignored by pydantic without a word."""
    @model(frozen=True, kw_only=True)
    class K:
        a: int
        b: int = 2

    with pytest.raises(ValidationError):
        K(1)  # type: ignore[misc]
    assert K(a=1).b == 2


def test_model_forwards_order():
    @model(order=True)
    class Ordered:
        a: int

    assert Ordered(1) < Ordered(2)


def test_model_refuses_a_keyword_that_is_neither_a_knob_nor_a_config_key():
    """`init` is the one stdlib knob pydantic only accepts as `False`; a typo lands here too.
    Refused loudly rather than ignored silently."""
    with pytest.raises(TypeError, match=r"@model got \['init'\]"):
        @model(init=False)  # type: ignore[call-overload]
        class Z:
            a: int

    with pytest.raises(TypeError, match=r"\['frozne'\]"):
        @model(frozne=True)  # type: ignore[call-overload]
        class Y:
            a: int


def test_model_still_passes_a_real_config_key_through():
    @model(validate_assignment=True)
    class V:
        a: int

    v = V(1)
    with pytest.raises(ValidationError):
        v.a = "2"  # type: ignore[assignment]


# ---------------------------------------------------------------------------------------
# the branch spec: every mistyped field is a `BranchError`, at construction
# ---------------------------------------------------------------------------------------


_GOOD = dict(source_run_dir=Path("/x"), branch_message_id=3, continuation_prompt="go",
             as_of=datetime(2026, 1, 1, tzinfo=UTC))


@pytest.mark.parametrize(("field_name", "bad"), [
    ("branch_message_id", "59"),
    ("branch_message_id", True),
    ("continuation_prompt", None),
    ("source_run_dir", "/tmp/x"),
    ("as_of", "2026-01-01T00:00:00Z"),
])
def test_branch_spec_refuses_a_mistyped_field_as_branch_error(field_name, bad):
    """`learning/branch/cli.py` builds the spec inside `except BranchError → LauncherRefused`
    and the driver's store-setup handler names `BranchError` alone; pydantic's own
    `ValidationError` would escape both as a traceback."""
    from defender.runtime.branch import BranchError, BranchSpec

    with pytest.raises(BranchError, match=rf"{field_name} must be an? \w+, got "):
        BranchSpec(**{**_GOOD, field_name: bad})


def test_branch_spec_accepts_the_positional_form_too():
    from defender.runtime.branch import BranchSpec

    spec = BranchSpec(Path("/x"), 3, "go", datetime(2026, 1, 1, tzinfo=UTC))
    assert spec.branch_message_id == 3


def test_branch_spec_has_one_as_of_type_refusal_not_two():
    """The datetime check lives on the spec; `_refuse_bad_as_of`'s copy of it was dead code
    once the spec refused first, and a rule spelled twice drifts."""
    import inspect

    from defender.runtime.branch import _frontier

    assert "must be a datetime" not in inspect.getsource(_frontier._refuse_bad_as_of)


# ---------------------------------------------------------------------------------------
# the family manifest: a non-string patch field key is a `FamilyError`
# ---------------------------------------------------------------------------------------


def test_family_overlay_refuses_a_non_string_patch_field_as_family_error():
    """YAML 1.1 reads a bare `on:`/`yes:`/`1:` key as a bool or an int; `Overlay.patches` is
    strictly `dict[str, ...]` all the way down, so without the loader's own check this
    surfaced as pydantic's `ValidationError` — a class `run.py --resume` and the branch CLI's
    handlers do not name."""
    from defender.runtime.branch._family import FamilyError, parse_overlay

    with pytest.raises(FamilyError, match=r"patches\['cmdb'\]\['host1'\] names non-string field"):
        parse_overlay({"patches": {"cmdb": {"host1": {True: 1}}}})


# ---------------------------------------------------------------------------------------
# identity-carrying fields: no rebuild on construction
# ---------------------------------------------------------------------------------------


def test_agent_deps_replace_shares_the_mutable_containers():
    """`review_state` and `authored_paths` are THE ONE mutable container each on a frozen deps
    — `ReviewState.of(deps)` counts turns in the former, `write_file` records into the latter
    — and every `dataclasses.replace(deps, ...)` (sub-agent deps, `LeadStop`'s copy) must
    hand the copy the same object, or the count forks between the two in silence."""
    pytest.importorskip("pydantic_ai")
    from defender.runtime import permission
    from defender.runtime.tools import AgentDeps

    class _Box:
        def run_parsed(self, *a, **k):  # noqa: ARG002 — duck-typed `BoxLike`
            raise AssertionError("never run")

    deps = AgentDeps(run_dir=Path("/r"), defender_dir=Path("/d"), run_id="x",
                     policy=permission.AgentPolicy(), cwd_anchor=Path("/r"), box=_Box())
    copy = replace(deps, run_id="y")
    assert copy.review_state is deps.review_state
    assert copy.authored_paths is deps.authored_paths


def test_learning_deps_subclasses_validate_like_the_base():
    """The four learning-side deps subclasses are ported with the base: a stdlib
    `@dataclass` subclass of a pydantic dataclass gets a stdlib `__init__`, so strict
    validation would have been silently OFF for exactly those roles."""
    pytest.importorskip("pydantic_ai")
    from defender.learning.author.curator_engine import CorpusRepairDeps, CuratorDeps
    from defender.learning.author.verify_forward.engine import VerifierDeps
    from defender.learning.leads.lead_author_engine import LeadAuthorDeps
    from defender.runtime import permission

    class _Box:
        def run_parsed(self, *a, **k):  # noqa: ARG002 — duck-typed `BoxLike`
            raise AssertionError("never run")

    for cls in (CuratorDeps, CorpusRepairDeps, VerifierDeps, LeadAuthorDeps):
        with pytest.raises(ValidationError):
            cls(run_dir=Path("/r"), defender_dir=Path("/d"), run_id=123,  # type: ignore[arg-type]
                policy=permission.AgentPolicy(), cwd_anchor=Path("/r"), box=_Box())


def test_frozen_prefix_holds_the_history_messages_by_identity():
    """`_build_prefix` takes the orientation message straight from `history`; a validated
    `tuple[Message, ...]` would shallow-copy every dict, and each "reused" step would then
    re-send copies the live history no longer shares."""
    from defender.runtime.compaction import FrozenState

    message = {"role": "user", "parts": []}
    state = FrozenState(prefix=(message,), freeze_index=1, frozen_through=0)
    assert state.prefix[0] is message


def test_verb_context_keeps_the_mapping_it_was_handed():
    """A read-only `MappingProxyType` (or the live `os.environ`) must reach the adapter as
    itself, not as a writable snapshot pydantic copied on every `query` call."""
    from defender.runtime.verbs import VerbContext

    env = MappingProxyType({"A": "1"})
    ctx = VerbContext(defender_dir=Path("/d"), run_dir=Path("/r"), env=env)
    assert ctx.env is env


# ---------------------------------------------------------------------------------------
# the gate's patterns: compiled by the caller, never on its behalf
# ---------------------------------------------------------------------------------------


def test_grant_pattern_refuses_a_bare_string():
    """Pydantic's `re.Pattern` schema compiles a `str` even under `strict=True`; a path or
    shape string handed where a `program_shape(...)` was meant would become a live regex
    with its metacharacters unescaped."""
    from defender.runtime.permission.grant import Grant, program_shape
    from defender.runtime.permission.policy import AgentPolicy

    compiled = program_shape("cat")
    assert Grant(program="cat", pattern=compiled).pattern is compiled
    with pytest.raises(ValidationError, match="must be a compiled re.Pattern"):
        Grant(program="cat", pattern="cat .*")  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="must be a compiled re.Pattern"):
        AgentPolicy(write_allow=("/tmp/x",))  # type: ignore[arg-type]
    shape = re.compile("z")
    assert AgentPolicy(write_allow=(shape,)).write_allow[0] is shape
