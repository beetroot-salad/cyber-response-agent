"""The session store's path comes from its owner, refusal included (#1077, the leftover of D7).

`runtime/session_store.store_path_for` composed `<runs_base>/../sessions/<case_id>.db` itself,
while the owner's `RunPaths.session_db` — which carries decision 20's case-stability refusal —
had no production caller. So the refusal the owner states was one no store ever met: a case id
that is not case-stable (`id != id.casefold()`) opened a store, and on a filesystem that folds
case two such ids are ONE file.

What this pins, by observable only — the raised class, what is on disk afterwards, and the
exact path a store lands at:

- O2: `store_path_for` and `open_store` refuse a case-unstable id as `InvalidCaseId`, and
  nothing is created for it; the lowercase spelling of the same id opens, at the owner's path.
- O2 at the resume door: a source run whose case pointer carries such an id fails
  `branch.open_source_store` as `BranchError` (the driver's store-setup class), with the
  `InvalidCaseId` as its cause and no store file created; the same run's own lowercase pointer
  opens its store.
- O2 at a fresh run: a store factory handed such an id ends the run through the driver's
  handled `truncated_by="store"` exit — `InvalidCaseId` is a `StoreError` — never an escape.
- D2: the store's owner is `SessionPaths`, built from the runs base (one store spans a run and
  its resumes and forks, so there is no run dir to key it by). It names the store AND the root
  the store is created under; `RunPaths.sessions_dir`/`session_db` answer through it.

O1 — renaming the owner's constants moves the store — is `test_1077_rename_proof.py`'s.
"""
from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest

from defender._run_paths import RunPaths, SessionPaths
from defender.runtime.session_store import (
    CASE_ID_RE,
    InvalidCaseId,
    StoreError,
    open_store,
    store_path_for,
)
from defender.tests.e2e import _replay_harness as replay

#: Ids the case-id pattern ADMITS but that are not case-stable — so a refusal of them is the
#: case-stability rule's, not the pattern's (each test re-checks both facts, by reference).
UNSTABLE = ("Case-Alpha", "ABC", "case-Alpha", "aBc", "caseAlpha")

#: Values that are not strings at all — what a hand-edited or corrupted case pointer can carry.
#: Refused as `InvalidCaseId` like any malformed id, never as whatever the check trips over.
NOT_A_STRING = (None, 7, ["x"])

#: Ids BOTH the store and the owner admit, at the case-id pattern's edges: they must agree on
#: every one of them, not only on the id the tests happen to use.
ADMITTED = ("case-alpha", "a.b_c-d", "0abc", "x", "a" * 128, "7f3c2a9e0b1d4c5e8f6a7b8c9d0e1f2a")


def _tree(root: Path) -> set[Path]:
    return {p.relative_to(root) for p in root.rglob("*")}


@pytest.fixture
def runs_base(tmp_path: Path) -> Path:
    """A runs base with room beside it: the store's directory is a SIBLING of the runs base,
    so everything a store open can create lands under `tmp_path`."""
    base = tmp_path / "defender-runs"
    base.mkdir()
    return base


def _owner_path(runs_base: Path, case_id: str) -> Path:
    return SessionPaths(runs_base).session_db(case_id)


def _is_the_subject(case_id: str) -> None:
    assert CASE_ID_RE.match(case_id), (
        f"{case_id!r} must pass the case-id pattern, or its refusal proves nothing about case "
        "stability")
    assert case_id != case_id.casefold(), f"{case_id!r} is case-stable; it is not the subject"


@pytest.mark.parametrize("case_id", UNSTABLE)
def test_store_path_for_refuses_an_id_that_is_not_case_stable(runs_base, case_id):
    """`store_path_for` refuses a case id that is not case-stable, as `InvalidCaseId`; the
    lowercase spelling of the same id resolves, to exactly the owner's path."""
    _is_the_subject(case_id)
    with pytest.raises(InvalidCaseId):
        store_path_for(case_id, runs_base=runs_base)

    lower = case_id.casefold()
    assert store_path_for(lower, runs_base=runs_base) == _owner_path(runs_base, lower), (
        "positive control: a case-stable id resolves to the owner's path")


@pytest.mark.parametrize("case_id", UNSTABLE)
def test_open_store_refuses_an_id_that_is_not_case_stable_and_creates_nothing(
        tmp_path, runs_base, case_id):
    """`open_store` refuses a case-unstable id as `InvalidCaseId` and leaves the filesystem
    exactly as it found it — whether or not the sessions directory exists yet. Between the
    two refusals, the lowercase spelling of the same id opens a real store at the owner's path.

    The filesystem is the observable, not the raise alone: `open_store` creates-if-missing,
    so a refusal that came after the create would leave a store behind for an id the owner
    says names none."""
    _is_the_subject(case_id)
    lower = case_id.casefold()

    def refuses_and_creates_nothing(when: str) -> None:
        before = _tree(tmp_path)
        raised: BaseException | None = None
        try:
            handle = open_store(case_id=case_id, runs_base=runs_base)
        except InvalidCaseId as exc:
            raised = exc
        else:
            handle.close()
        created = sorted(str(p) for p in _tree(tmp_path) - before)
        assert raised is not None, (
            f"open_store admitted {case_id!r} ({when}) and created {created} — a case id "
            "that is not case-stable names no store")
        assert not created, f"open_store refused {case_id!r} ({when}) but created {created}"

    refuses_and_creates_nothing("before any store exists beside the runs base")

    with open_store(case_id=lower, runs_base=runs_base) as handle:
        assert handle.path == _owner_path(runs_base, lower), (
            "positive control: the lowercase id's store is not at the owner's path")
        assert handle.path.is_file(), "positive control: the lowercase id opened no store file"

    refuses_and_creates_nothing("with the sessions directory already holding a store")


@pytest.mark.parametrize("case_id", NOT_A_STRING, ids=repr)
def test_store_path_for_refuses_a_value_that_is_not_a_string(runs_base, case_id):
    """A case id that is not a string at all is refused as `InvalidCaseId` — the pattern check
    comes first — never as an `AttributeError`/`TypeError` from a check that ran before it
    (those escape the resume door's handler and take the run down). Positive control: a
    well-formed id resolves."""
    with pytest.raises(InvalidCaseId):
        store_path_for(case_id, runs_base=runs_base)
    assert store_path_for("case-alpha", runs_base=runs_base) == _owner_path(
        runs_base, "case-alpha")


@pytest.mark.parametrize("case_id", ADMITTED)
def test_the_store_and_the_owner_agree_on_every_admitted_id(runs_base, case_id):
    """D1: `store_path_for` IS the owner's answer, for every id the pattern admits — including
    its edges (a single character, a digit-leading id, the 128-character maximum, `.`/`_`/`-`),
    not only the id the other tests use."""
    assert CASE_ID_RE.match(case_id)
    assert case_id == case_id.casefold()
    assert store_path_for(case_id, runs_base=runs_base) == _owner_path(runs_base, case_id)


def test_the_store_owner_is_built_from_the_runs_base_and_run_paths_answers_through_it(
        runs_base):
    """D2: `SessionPaths(runs_base)` names the sessions dir, each lineage's database in it, and
    the root they are created under; `RunPaths`' two session accessors answer exactly what it
    answers, refusal included (the #1077 census keeps them on `RunPaths`)."""
    owner = SessionPaths(runs_base)
    run = RunPaths(runs_base / "any-run")
    assert owner.sessions_dir == run.sessions_dir(runs_base) == runs_base.parent / "sessions"
    assert owner.session_db("case-alpha") == run.session_db(runs_base, "case-alpha") == (
        store_path_for("case-alpha", runs_base=runs_base))
    assert owner.session_db("case-alpha").parent == owner.sessions_dir
    assert owner.sessions_dir.parent == owner.trust_root
    for ask in (lambda: owner.session_db("Case-Alpha"),
                lambda: run.session_db(runs_base, "Case-Alpha")):
        with pytest.raises(InvalidCaseId):
            ask()


def test_a_fresh_run_handed_a_case_unstable_id_ends_through_the_handled_store_exit(tmp_path):
    """A fresh run whose store factory is handed a case-unstable id ends through the driver's
    handled `truncated_by="store"` exit, and no store is created: `InvalidCaseId` is a
    `StoreError`, which the driver's store-setup handler catches. Before, it was a bare
    `ValueError` and escaped `run_investigation` with the wire log still registered."""
    assert issubclass(InvalidCaseId, StoreError)
    assert issubclass(InvalidCaseId, ValueError), "callers that catch `ValueError` still do"
    runs = tmp_path / "runs"
    run_dir = replay.materialize(runs, replay.GOLDEN)
    before = _tree(tmp_path)

    def mixed_case_factory(case_id: str, rd: Path):
        return open_store(case_id=f"Case-{case_id}", runs_base=rd.parent)

    summary = replay.drive(run_dir, run_id="1077-mixed-fresh", main=replay.ReplayFn([
        replay.Turn(text="Nothing to do; stopping."),
    ]), store_factory=mixed_case_factory)
    assert summary.get("truncated_by") == "store", summary
    assert summary.get("exit_reason") == "InvalidCaseId", summary
    created_stores = [p for p in _tree(tmp_path) - before if p.suffix == ".db"]
    assert not created_stores, f"the refused id still created {created_stores}"


# ---------------------------------------------------------------------------------------
# The resume door: a source run whose pointer carries a case-unstable id
# ---------------------------------------------------------------------------------------

@pytest.fixture(scope="module")
def _finished_run(tmp_path_factory) -> tuple[Path, Path]:
    """A REAL finished run — the real driver, its default store factory, its own case pointer
    — driven ONCE for the module. `runs/run`, so `open_source_store`'s `runs_base =
    run_dir.parent` is the base the run was handed and its store sits under the returned root."""
    root = tmp_path_factory.mktemp("source")
    run_dir = replay.materialize(root / "runs", replay.GOLDEN)
    summary = replay.drive(run_dir, run_id="1077-session-owner", main=replay.ReplayFn([
        replay.Turn(text="Nothing to do; stopping."),
    ]))
    assert summary.get("truncated_by") is None, (
        f"the source run did not finish ({summary}); nothing below is about its pointer")
    return root, run_dir


@pytest.fixture
def source_run(_finished_run) -> Iterator[tuple[Path, Path]]:
    """The module's finished run, with its case pointer restored after each test — the tests
    below rewrite only the pointer."""
    root, run_dir = _finished_run
    pointer_file = RunPaths(run_dir).session_pointer
    saved = pointer_file.read_bytes()
    yield root, run_dir
    pointer_file.write_bytes(saved)


def test_a_resume_whose_pointer_carries_a_case_unstable_id_fails_as_branch_error(source_run):
    """`branch.open_source_store` over a real run whose case pointer names the run's own case
    id in the wrong case refuses as `BranchError`, caused by the store's `InvalidCaseId`, and
    creates no store; over the same run's own, lowercase pointer it opens the run's store.

    The mixed-case pointer is the real one with the id's case flipped EVERYWHERE it appears —
    the case id and the store path the writer would have recorded for it — so it is
    self-consistent. That is what makes the refusal the case-stability rule's: an inconsistent
    pointer is refused today already, by the derive-and-compare check, for the opposite reason.
    Rewritten through the real pointer writer, keeping every other field the run wrote."""
    from defender.runtime import branch, session_store

    root, run_dir = source_run
    pointer_file = RunPaths(run_dir).session_pointer
    pointer = json.loads(pointer_file.read_text(encoding="utf-8"))
    case_id, recorded = pointer["case_id"], Path(pointer["store_path"])
    assert case_id == case_id.casefold(), f"the run minted a case-unstable id: {case_id!r}"
    # ONE letter flipped, not the whole id upper-cased: a check that only spots all-upper or
    # title-case ids must not pass this.
    letters = [i for i, ch in enumerate(case_id) if ch.isalpha()]
    if not letters:
        pytest.skip(f"the minted id {case_id!r} holds no letter to flip")
    i = letters[len(letters) // 2]
    mixed = case_id[:i] + case_id[i].upper() + case_id[i + 1:]
    _is_the_subject(mixed)

    # Positive control: the run's own pointer opens the run's own store, which holds its run.
    source = branch.open_source_store(run_dir)
    try:
        assert source.path == recorded == _owner_path(run_dir.parent, case_id)
        assert session_store.main_session_id(source), "the store holds no main session"
    finally:
        source.close()

    session_store.write_case_pointer(
        run_dir, case_id=mixed, store_path=recorded.with_name(recorded.name.replace(
            case_id, mixed)),
        session_id=pointer.get("session_id"))
    before = _tree(root)
    raised: BaseException | None = None
    try:
        handle = branch.open_source_store(run_dir)
    except branch.BranchError as exc:
        raised = exc
    else:
        handle.close()
    created = sorted(str(p) for p in _tree(root) - before)
    assert raised is not None, (
        f"open_source_store admitted a pointer carrying {mixed!r} and created {created} — a "
        "resume over a case id that is not case-stable must fail as the driver's store-setup "
        "class")
    assert isinstance(raised.__cause__, InvalidCaseId), (
        f"the resume was refused, but not by the case-stability rule: {raised!r}")
    assert not created, f"the refused resume still created {created}"


def test_a_resume_whose_pointer_carries_no_string_case_id_fails_as_branch_error(source_run):
    """A source run whose pointer's `case_id` is `null` fails `open_source_store` as
    `BranchError` caused by `InvalidCaseId` — the driver's store-setup class — and creates
    nothing. (The pointer writer would not write it; a hand-edited or truncated file can.)
    Positive control: the run's own pointer opens."""
    from defender.runtime import branch

    root, run_dir = source_run
    pointer_file = RunPaths(run_dir).session_pointer
    pointer = json.loads(pointer_file.read_text(encoding="utf-8"))
    branch.open_source_store(run_dir).close()

    pointer_file.write_text(json.dumps({**pointer, "case_id": None}), encoding="utf-8")
    before = _tree(root)
    with pytest.raises(branch.BranchError) as info:
        branch.open_source_store(run_dir)
    assert isinstance(info.value.__cause__, InvalidCaseId), (
        f"refused, but not as a malformed case id: {info.value.__cause__!r}")
    assert _tree(root) == before
