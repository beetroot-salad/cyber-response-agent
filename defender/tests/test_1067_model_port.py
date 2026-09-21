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


def test_model_refuses_a_keyword_the_class_has_no_field_for():
    """Stdlib `@dataclass` raised `TypeError` on an unknown keyword; pydantic's own default
    (`extra="ignore"`) drops it in silence, so a typo in a constructor call — or in a
    `dataclasses.replace`, which forwards its leftover keys to `__init__` — would have handed
    back a record that quietly kept its old value. `@model` restores the refusal."""
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


def test_complete_finishes_a_schema_that_names_a_later_class():
    """Two records naming each other leave the first decorated one incomplete: pydantic then
    builds its schema on the FIRST construction, from whichever thread gets there. `complete`
    at module end finishes it at import, and the field validates strictly afterwards."""
    from defender._model import complete

    @model(frozen=True)
    class Ctx:
        check: Chk

    @model(frozen=True)
    class Chk:
        name: str

    assert Ctx.__pydantic_complete__ is False
    assert complete(Ctx) is Ctx
    assert Ctx.__pydantic_complete__ is True
    chk = Chk(name="n")
    assert Ctx(check=chk).check is chk
    with pytest.raises(ValidationError):
        Ctx(check="not a check")  # type: ignore[arg-type]


@pytest.mark.parametrize(("module", "name"), [
    ("defender.learning.core.drains", "BatchDisposition"),
    ("defender.learning.author.verify_forward.checks", "CheckContext"),
    ("defender.learning.judge.family", "FamilyGrade"),
])
def test_every_ported_record_with_a_forward_reference_is_complete_at_import(module, name):
    """The three records whose field names a class the module defines later, or another
    module owns: `BatchDisposition.pitfalls` (now `core/pitfalls_disposition`, imported at
    top), `CheckContext.check` (mutually referential with `ForwardCheck`, `complete`d at module
    end) and `FamilyGrade.world_facts` (moved below `WorldFacts`). Each was left for pydantic
    to finish on the first construction — for `CheckContext`, inside `_Judgement.mint`'s
    worker pool, N threads at once with no lock.

    IN A FRESH INTERPRETER, because the flag this reads flips to true on the first
    construction anyway: in this process, any earlier test in the worker that built one of
    these would make a class left lazily incomplete read as complete, and the fix could be
    reverted with this arm still green."""
    import subprocess
    import sys

    probe = (
        f"import importlib; cls = getattr(importlib.import_module({module!r}), {name!r}); "
        "assert cls.__pydantic_complete__ is True, 'left for the first construction to finish'"
    )
    subprocess.run([sys.executable, "-c", probe], check=True, cwd=Path(__file__).parents[2],
                   timeout=120)


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


# ---------------------------------------------------------------------------------------
# PR 3 — defender/learning/
# ---------------------------------------------------------------------------------------


def test_query_row_hands_back_the_record_it_was_read_from():
    """`QueryRow.record()` is "the parsed JSON record, byte-for-byte what
    `record_query.lead_rows` hands the guard live, never a re-projection of the typed fields"
    (#1017 C16), and its docstring makes "`params` is the same object" part of that promise.
    A validated `dict` field is REBUILT on every construction, which turns both into copies
    in silence — the typed view then IS the re-projection the distinction exists to refuse."""
    from defender.learning.lead_repository import QueryRow

    rec = {"lead_id": "l-001", "params": {"host": "h1"}}
    row = QueryRow(
        lead_id="l-001", seq=1, system="cmdb", verb="get-host", query_id="cmdb.get-host",
        params=rec["params"], raw_command="c", exit_code=0, error_class=None,
        payload_status="ok", payload_digest="d", raw_ref=None, _record=rec,
    )
    assert row.record() is rec
    assert row.params is rec["params"]


def test_batch_disposition_validates_its_curator_type_without_loading_the_curator():
    """`BatchDisposition.pitfalls` is typed `PitfallsDisposition`, validated strictly, and the
    class it names lives in `core/pitfalls_disposition` — NOT the curator module, which the
    lessons lane must never pay to import. Both halves matter: typed `Any` the record would
    carry anything, and named under `TYPE_CHECKING` from the curator its schema was left
    unfinished at import and completed by a frame-introspecting rebuild at the lane's entry."""
    import subprocess
    import sys

    probe = (
        "import sys; from defender.learning.core import drains; "
        "assert not [m for m in sys.modules if m.startswith('defender.learning.leads')], "
        "sorted(m for m in sys.modules if m.startswith('defender.learning.leads'))"
    )
    # A fresh interpreter: this process has long since imported the curator for other tests
    # (completeness at import is the census above's, in the same fresh-interpreter shape).
    subprocess.run([sys.executable, "-c", probe], check=True, cwd=Path(__file__).parents[2],
                   timeout=120)

    from defender.learning.core import drains
    from defender.learning.core.pitfalls_disposition import PitfallsDisposition
    from defender.learning.leads import pitfalls_curator

    assert pitfalls_curator.PitfallsDisposition is PitfallsDisposition
    real = PitfallsDisposition(committed_ids=("c:l-000:0",), sha=None, held_ids=())
    assert drains.BatchDisposition(
        served=[], pitfalls=real, lock_wait_seconds=None).pitfalls is real
    assert drains.BatchDisposition(
        served=[], pitfalls=None, lock_wait_seconds=None).pitfalls is None
    with pytest.raises(ValidationError):
        drains.BatchDisposition(
            served=[], pitfalls="a disposition", lock_wait_seconds=None)  # type: ignore[arg-type]


def test_author_branch_accepts_any_structural_forge():
    """`AuthorBranch.forge` is typed `Forge | None`, and `arbitrary_types_allowed` validates a
    class annotation with `isinstance` — which a plain `Protocol` refuses to be the second
    argument of (`SchemaError: 'cls' must be valid as the first argument to 'isinstance'`).
    `@runtime_checkable` is what keeps the structural contract usable as a field type: the
    production `GhForge` and the drain's own doubles both reach the field as themselves, and
    an object holding none of the three methods still does not."""
    from defender.learning.author.branch import AuthorBranch
    from defender.learning.author.forge import GhForge

    class _Forge:
        def list_open_prs(self, head_prefix): return []
        def list_prs_for_head(self, head): return []
        def open_pr(self, *, base, head, title, body): return "url"

    double = _Forge()
    assert AuthorBranch(forge=double).forge is double
    gh = GhForge()
    assert AuthorBranch(forge=gh).forge is gh
    with pytest.raises(ValidationError):
        AuthorBranch(forge=object())  # type: ignore[arg-type]


def test_drain_judgement_resolves_its_counter_annotation():
    """`itertools.count` is generic to a type checker and a plain class at runtime, where
    `itertools.count[int]` raises `TypeError: not subscriptable` — and a pydantic dataclass
    evaluates its field annotations at DECORATION time, which `from __future__ import
    annotations` no longer hides. The whole `author.drain` import tree (the drain, both
    curators' runners, the queue page) failed to load until the alias split the two
    readings, and the field must still reach pydantic as the real class."""
    import itertools

    from defender.learning.author.drain import _Judgement

    counter = _Judgement.__pydantic_fields__["counter"]
    assert counter.annotation is itertools.count
    assert counter.default_factory is itertools.count


# ---------------------------------------------------------------------------------------
# the second review pass
# ---------------------------------------------------------------------------------------


def test_unwrap_before_keeps_pydantics_arity_checks():
    """A before-validator that returns a `dict` has replaced the `ArgsKwargs` pydantic would
    have checked itself, so the helper checks arity: a surplus positional and a keyword
    naming a field a positional already filled are both refused, as stdlib does."""
    from defender.runtime.branch import BranchSpec

    with pytest.raises(TypeError, match="takes 4 positional argument"):
        BranchSpec(Path("/x"), 3, "go", datetime(2026, 1, 1, tzinfo=UTC), "EXTRA")  # type: ignore[call-arg]
    with pytest.raises(TypeError, match=r"multiple values for argument\(s\) \['branch_message_id'\]"):
        BranchSpec(Path("/x"), 3, "go", datetime(2026, 1, 1, tzinfo=UTC), branch_message_id=99)  # type: ignore[call-arg]


def test_branch_spec_field_types_are_read_off_the_class():
    """The before-validator's table is derived from the annotations, so a field added to the
    spec cannot be missed by it; only the per-field reason is hand-kept, and a field without
    one refuses at import."""
    from defender.runtime.branch import _spec

    expected = {"source_run_dir": Path, "branch_message_id": int,
                "continuation_prompt": str, "as_of": datetime}
    assert expected == _spec._FIELD_TYPES
    assert set(_spec._WHY) == set(_spec._FIELD_TYPES)


def test_providers_imports_without_pydantic_ai():
    """`defender.runtime.providers` is on the runtime-free install's import path
    (`run_common.run_env`, `learning.core.config.source_first_party_key`), so no module in
    it may import `pydantic_ai` at module scope."""
    import subprocess
    import sys

    code = (
        "import sys\n"
        "class _Block:\n"
        "    def find_spec(self, name, path=None, target=None):\n"
        "        if name == 'pydantic_ai' or name.startswith('pydantic_ai.'):\n"
        "            raise ModuleNotFoundError(name)\n"
        "sys.meta_path.insert(0, _Block())\n"
        "from defender.runtime import providers\n"
        "from defender.runtime.providers.base import BuiltModel\n"
        "print(BuiltModel(model=object(), settings=None) is not None)\n"
    )
    from defender._paths import PATHS

    out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                         check=False, cwd=str(PATHS.repo_root))
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "True"




def test_gate_wrapper_toolset_survives_replace():
    """`WrapperToolset` rebuilds itself through `dataclasses.replace(self, ...)` on every
    `for_run`/`for_run_step`, re-passing every field explicitly — so a field whose default
    the strict type refuses is constructible once and unusable after. The gate is required."""
    pytest.importorskip("pydantic_ai")
    from pydantic_ai.toolsets import FunctionToolset

    from defender.runtime.toon_gate import _GateWrapperToolset

    with pytest.raises(ValidationError):
        _GateWrapperToolset(wrapped=FunctionToolset())  # type: ignore[call-arg]


# ---------------------------------------------------------------------------------------
# PR5: the two model-facing validators batch every problem into one refusal
# ---------------------------------------------------------------------------------------


def test_validate_params_names_every_problem_once_in_one_refusal():
    """Four categories at once — reserved, unknown, missing, mistyped — and the one refusal
    names each ONCE. The exclusions are what a one-problem call cannot see: a reserved param
    is never ALSO "unknown", and a param already refused as unknown is never ALSO mistyped."""
    from defender.runtime.verbs import validate_params, verb

    @verb(wrapper_only=("require_closed",))
    def read(ctx, *, host: str, size: int = 10, require_closed: bool = False):  # noqa: ARG001
        return None

    # `require_closed="yes"` — a str where a bool is declared — so that ONLY the exclusion
    # keeps it out of the mistyped category; a well-typed `True` would pass that scan on its
    # own and the assertion below could never fail.
    refusal = validate_params(read, {"require_closed": "yes", "bogus": "x", "size": "10"})
    assert refusal is not None
    assert "param(s) ['require_closed'] are set by the first-party tool" in refusal
    assert "unknown param(s) ['bogus']" in refusal  # not ['bogus', 'require_closed']
    assert "missing required param(s) ['host']" in refusal
    assert "'size' takes int, got str" in refusal
    # The exclusions: the reserved name is not ALSO unknown (asserted above), and a name already
    # refused as reserved is not ALSO scanned for its type — a second verdict on a param the
    # model was just told to drop.
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
    """`_model`'s convention: a domain exception that is not a `ValueError` propagates out of
    a validator as ITSELF; pydantic wraps only `ValueError`/`AssertionError`. `JudgeRefused`
    is the one that was a `ValueError` until #1067 PR5 — every caller's `except JudgeRefused`
    would have silently missed it out of any `@model` validator. Asked for the EXACT class:
    `ValidationError` is itself a `ValueError`, so a looser `raises` cannot see the wrap."""
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
