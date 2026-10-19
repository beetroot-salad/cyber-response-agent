"""What the strict-pydantic port (#1067) must NOT change about the records it swapped."""

from __future__ import annotations

import re
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType

import pytest
from pydantic import ValidationError

from defender._model import model
from defender.tests import _branch_947 as B947


# the decorator itself


def test_model_forwards_kw_only_rather_than_dropping_it_into_config():
    @model(frozen=True, kw_only=True)
    class K:
        a: int
        b: int = 2

    with pytest.raises(ValidationError):
        K(1)  # type: ignore[misc]
    assert K(a=1).b == 2


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


def test_model_refuses_a_keyword_the_class_has_no_field_for():
    @model(frozen=True)
    class R:
        worktree_root: Path
        worktree_base: Path | None = None

    with pytest.raises(ValidationError, match="unexpected_keyword_argument"):
        R(worktree_root=Path("/x"), worktree_bsae=Path("/y"))  # type: ignore[call-arg]
    good = R(worktree_root=Path("/x"))
    with pytest.raises(ValidationError, match="unexpected_keyword_argument"):
        replace(good, worktree_bsae=Path("/y"))
    assert replace(good, worktree_base=Path("/y")).worktree_base == Path("/y")


# the branch spec: every mistyped field is a `BranchError`, at construction


_RETIRED_PROMPT = {B947.RETIRED_PROMPT_FIELD: "go"} if B947.declares_retired_prompt() else {}
_GOOD = dict(source_run_dir=Path("/x"), branch_message_id=3, **_RETIRED_PROMPT,
             as_of=datetime(2026, 1, 1, tzinfo=UTC))


@pytest.mark.parametrize(("field_name", "bad"), [
    ("branch_message_id", "59"),
    ("branch_message_id", True),
    ("source_run_dir", "/tmp/x"),
    ("as_of", "2026-01-01T00:00:00Z"),
])
def test_branch_spec_refuses_a_mistyped_field_as_branch_error(field_name, bad):
    from defender.runtime.branch import BranchError, BranchSpec

    with pytest.raises(BranchError, match=rf"{field_name} must be an? \w+, got "):
        BranchSpec(**{**_GOOD, field_name: bad})


# the family manifest: a non-string fact entity is a `FamilyError`


def test_family_fact_refuses_a_non_string_entity_as_family_error():
    from defender.runtime.branch._family import FamilyError, parse_world

    with pytest.raises(FamilyError, match=r"worlds\['b'\]\.facts\[0\]\.entities names True"):
        parse_world({"world_id": "b", "role": "B", "story": "s", "axis": "x",
                     "disposition_declared": "malicious", "label_basis": "policy-rule",
                     "facts": [{"fact_id": "f1", "statement": "s", "entities": [True]}]})


# identity-carrying fields: no rebuild on construction


def test_verb_context_keeps_the_mapping_it_was_handed():
    """A read-only `MappingProxyType` (or the live `os.environ`) must reach the adapter as
    itself, not as a writable snapshot pydantic copied on every `query` call."""
    from defender.runtime.verbs import VerbContext
    from defender.tests import _tenants1106

    env = MappingProxyType({"A": "1"})
    ctx = VerbContext(defender_dir=Path("/d"), run_dir=Path("/r"), env=env,
                      tenant=_tenants1106.fixture_run_tenant())
    assert ctx.env is env


# the gate's patterns: compiled by the caller, never on its behalf


def test_grant_pattern_refuses_a_bare_string():
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


# PR 3 — defender/learning/


# the second review pass


# PR5: the two model-facing validators batch every problem into one refusal


def test_validate_params_names_every_problem_once_in_one_refusal():
    from defender.runtime.verbs import validate_params, verb

    @verb(wrapper_only=("require_closed",))
    def read(ctx, *, host: str, size: int = 10, require_closed: bool = False):  # noqa: ARG001
        return None

    refusal = validate_params(read, {"require_closed": "yes", "bogus": "x", "size": "10"})
    assert refusal is not None
    assert "param(s) ['require_closed'] are set by the first-party tool" in refusal
    assert "unknown param(s) ['bogus']" in refusal  # not ['bogus', 'require_closed']
    assert "missing required param(s) ['host']" in refusal
    assert "'size' takes int, got str" in refusal
    assert "'require_closed' takes" not in refusal


def test_validate_report_names_every_problem_in_one_refusal():
    """A report wrong two ways — no disposition AND the judge's close delimiter in its body —
    comes back as one refusal naming both, not the first alone."""
    from defender._artifact_schema import REPORT_CLOSE_DELIMITER, validate_report

    refusal = validate_report(f"---\ncase_id: c1\n---\nbody {REPORT_CLOSE_DELIMITER}\n")
    assert refusal is not None
    assert "must carry a top-level `disposition`" in refusal
    assert f"contains the literal {REPORT_CLOSE_DELIMITER!r}" in refusal
    # A malformed frontmatter is still its own gate AHEAD of the batch — there is nothing to
    # check a disposition against until the parse succeeds — so it is the whole refusal.
    malformed = validate_report(f"---\n: [\n---\nbody {REPORT_CLOSE_DELIMITER}\n")
    assert malformed is not None
    assert malformed.startswith("report.md frontmatter is malformed")
    assert "disposition" not in malformed
    assert "contains the literal" not in malformed
    assert validate_report("---\ndisposition: benign\n---\nbody\n") is None


def test_a_domain_exception_raised_inside_a_model_validator_reaches_the_caller_unconverted():
    """`_model`'s convention: a domain exception that is not a `ValueError` propagates out of a
    validator as ITSELF; pydantic wraps only `ValueError`/`AssertionError`."""
    from pydantic import model_validator

    from defender.learning.judge import JudgeRefused

    @model
    class Guarded:
        a: int

        @model_validator(mode="before")
        @classmethod
        def _refuse(cls, data):
            raise JudgeRefused("refused by the rule")

    with pytest.raises(JudgeRefused, match="refused by the rule") as raised:
        Guarded(a=1)
    assert type(raised.value) is JudgeRefused
    assert not isinstance(raised.value, ValueError)
