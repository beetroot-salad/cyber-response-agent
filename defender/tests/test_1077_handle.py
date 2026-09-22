"""#1077 — the handle's surface: the constructors, the five sub-collections, `RunRecord`
and the per-kind `RecordHandle`.

Carries 33 demands of `spec-flow/specs/spec_graph_1077.yaml`, each test named after its
demand's `discharged_by` pointer and carrying that demand's prose in its docstring. The
coined names (`_run_handle`, `RecordHandle`, `RunRecord`) and every fixture live in
`defender/tests/_spec1077.py`. Two of the 33 are the final §7 rework's: `h54` (decision 20 — the
bare run id's case fold, which claim RC-3 showed no rule covered) and `h55` (decision 22 — a
`for_tenant` tenant argument the record at the resolved base disagrees with).

RED AGAINST BASE db1af01a by construction: `defender/_run_handle.py` does not exist, and every
test reaches it through `S.handle()` per call, so the failure is the missing module once per
test rather than a collection error hiding the rest.

The file is at the TOP LEVEL of `defender/tests/` on purpose: the graph declares
`tests: defender/tests` and `check_binds` globs `<dir>/*.py` without recursing, so a test
placed under `tests/e2e/` loses its docstring and its demand reports as a prose orphan.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from defender.tests import _spec1077 as S


@pytest.fixture
def base(tmp_path: Path) -> Path:
    return S.make_runs_base(tmp_path)


@pytest.fixture
def run_dir(base: Path) -> Path:
    return S.seed_run_tree(S.make_run_dir(base))


def _tenanted(base: Path, run_id: str = "run-1077"):
    """A handle built the way real application code builds one (decision 1d)."""
    return S.Run().for_tenant(S.DEFAULT_TENANT_ID, run_id, runs_base=base)


# ---------------------------------------------------------------------------------------
# Demand #0 — the return-value contract, RESOLVED at §7 on all four axes
# ---------------------------------------------------------------------------------------

def test_run_handle_exposes_five_subcollections_a_record_and_wrapper_accessors(base, run_dir):
    """A `Run` built by `Run.for_tenant` exposes exactly the five sub-collections `tables`,
    `facts`, `documents`, `observability` and `session`, each carrying one member per kind D5
    places in its group, each member answering a per-kind `RecordHandle` rather than a bare
    `pathlib.Path`, and the twelve D4 fields on a `RunRecord` reached at `run.record`.
    """
    run = _tenanted(base)
    assert tuple(run.subcollections) == S.GROUPS, (
        "the five group cells decision 1a held the pin on, group-then-kind addressed")
    for group, names in S.GROUP_MEMBERS.items():
        coll = getattr(run, group)
        for name in names:
            rec = S.member(run, group, name, *S.member_args(name))
            assert isinstance(rec, S.RecordHandle()), (
                f"run.{group}.{name} answered {type(rec).__name__}, not a RecordHandle")
            assert not isinstance(rec, Path), (
                f"run.{group}.{name} answered a bare pathlib.Path — decision 1c closed that")
        assert set(names) <= set(coll.members), f"run.{group} is missing members of D5's group"
    record = run.record
    assert isinstance(record, S.RunRecord())
    for field in S.RUN_RECORD_FIELDS:
        assert hasattr(record, field), f"run.record does not answer D4's {field}"


# ---------------------------------------------------------------------------------------
# Decision 1b/1c/1d — the three flipped axes
# ---------------------------------------------------------------------------------------

def test_the_handle_exposes_a_named_run_record_rather_than_twelve_properties(base, run_dir):
    """`run.record` answers a named `RunRecord` value object holding D4's twelve descriptive
    fields, and `Run` itself exposes none of the twelve as a property of its own."""
    run = _tenanted(base)
    record = run.record
    assert type(record) is S.RunRecord()
    for field in S.RUN_RECORD_FIELDS:
        assert hasattr(record, field), f"RunRecord does not hold D4's {field}"
        if field == "tenant_id":
            # THE ADDRESS shares a name with a descriptive field. `run.tenant_id` is the tenant
            # the handle was asked for (N4: addressed by `(tenant_id, run_id)`, as `run_dir` is
            # the directory it was asked for); `run.record.tenant_id` is what the STAMP says.
            # `for_tenant` refuses when they disagree; `Run.at` has no address and no attribute.
            assert run.tenant_id == S.DEFAULT_TENANT_ID
            assert not hasattr(S.Run().at(run_dir), "tenant_id")
            continue
        assert not hasattr(run, field), (
            f"Run exposes {field} as a property of its own — fork D-F2 closed AGAINST that pin; "
            "the twelve fields live on RunRecord, a placeholder for #1081/#1082's job record")


def test_every_record_accessor_returns_a_per_kind_wrapper_not_a_bare_path(base, run_dir):
    """Every record accessor on every sub-collection — read-only ones included — answers a thin
    per-kind wrapper object, never a bare `pathlib.Path` and never parsed contents."""
    run = _tenanted(base)
    seen = set()
    for group, names in S.GROUP_MEMBERS.items():
        for name in names:
            rec = S.member(run, group, name, *S.member_args(name))
            assert isinstance(rec, S.RecordHandle()), f"run.{group}.{name}"
            assert not isinstance(rec, (Path, str, bytes, dict, list)), (
                f"run.{group}.{name} answered neither a wrapper nor a path but "
                f"{type(rec).__name__} — decision 1c closed against BOTH literal options")
            seen.add(type(rec))
    assert seen, "no member was reached at all"
    # `RunPaths` itself is UNCHANGED by the flip and still resolves to a Path.
    assert isinstance(S.RunPaths(run_dir).alert, Path)


def test_the_wrappers_path_is_the_owners_path_and_serves_the_mount_and_the_model(base, run_dir):
    """A wrapper's `.path` is the exact `pathlib.Path` the name owner resolves, and it is what
    the box's read-write bind and the model-facing payload string are both built from."""
    run = _tenanted(base)
    owner = S.RunPaths(run_dir)
    for group, names in S.GROUP_MEMBERS.items():
        for name in names:
            accessor = S.MEMBER_ACCESSOR[name]
            if accessor in S.UPWARD_ACCESSORS:
                continue
            args = S.member_args(name)
            rec = S.member(run, group, name, *args)
            target = getattr(owner, accessor)
            expected = target(*args) if args else target
            assert rec.path == expected, (
                f"run.{group}.{name}.path is not RunPaths.{accessor}'s own path")
            assert isinstance(rec.path, Path)
    # O8's model-facing string is composed off `.path`, not off a second spelling.
    payload = S.member(run, "tables", "payloads", *S.member_args("payloads"))
    assert payload.path == owner.payload(S.LEAD_ID, S.SEQ)
    # And the box's one read-write bind is the directory every `.path` sits under.
    assert run.run_dir == run_dir
    assert payload.path.is_relative_to(run.run_dir)


def test_the_wrappers_read_reaches_todays_reader_unchanged(base, run_dir):
    """A wrapper's read method reaches today's reader for that record's shape, with the same
    guard and the same result the call site got before."""
    recorder = S.RecordingIo()
    run = S.Run().for_tenant(S.DEFAULT_TENANT_ID, run_dir.name, runs_base=base, io=recorder)
    S.RunPaths(run_dir).report.write_text("# report\n", encoding="utf-8")

    got = S.member(run, "documents", "report").read()

    assert got == S.io().read_guarded(S.RunPaths(run_dir).report)[0] == "# report\n", (
        "the wrapper's read did not return today's reader's own result")
    assert "read_guarded" in recorder.ops, (
        f"the wrapper reached {recorder.ops} — not today's guarded reader")


def test_the_wrapper_adds_no_parsing_or_validation_of_its_own(base, run_dir):
    """The wrapper parses nothing and validates nothing beyond what today's helper for that
    record's shape already does.

    NEGATIVE, with its positive control inline: the same bytes DO come back through the same
    wrapper when the helper accepts them, so the observation channel can see the difference.
    """
    run = _tenanted(base)
    report = S.member(run, "documents", "report")
    # Positive control: well-formed content reads back verbatim.
    S.RunPaths(run_dir).report.write_text("# ok\n", encoding="utf-8")
    assert report.read() == "# ok\n"
    # Negative: content today's reader accepts is NOT refused, reshaped or parsed by the wrapper.
    for junk in ("{ not json at all", "", "disposition: [a, list]\n"):
        S.RunPaths(run_dir).report.write_text(junk, encoding="utf-8")
        assert report.read() == junk, (
            "the wrapper parsed or validated content today's reader hands back verbatim")
    queries = S.member(run, "tables", "queries")
    S.RunPaths(run_dir).executed_queries.write_text("not jsonl\n", encoding="utf-8")
    assert queries.read() == "not jsonl\n", "the wrapper parsed a table today's reader does not"


def test_application_code_constructs_a_run_through_for_tenant(base, run_dir):
    """`Run.for_tenant(tenant_id, run_id)` is what the host process that creates and operates on
    a run constructs through, and it resolves the run against that tenant's runs base."""
    S.plant_tenant_record(base, tenant_id="acme", base_world_id="feedfacefeedfacefeedfacefeedface")
    run = S.Run().for_tenant("acme", run_dir.name, runs_base=base)
    assert run.run_dir == run_dir, "for_tenant did not resolve the run against the tenant's base"
    assert run.tenant_id == "acme"
    assert run.runs_base == base, (
        "for_tenant must hold the runs base — it is what the upward accessors need (h33)")


def test_run_at_is_documented_and_used_only_by_eval_fixture_and_tooling_callers(base, run_dir):
    """`Run.at` is documented as the eval/fixture/tooling escape hatch, and its callers are
    exactly the bulk directory-walkers, the checked-in fixtures and the archive/branch
    machinery — no live investigation path among them."""
    at = S.Run().at
    doc = (at.__doc__ or "")
    unscoped = (
        "Run.at's own docstring must scope it as the eval/fixture/tooling escape hatch — "
        f"decision 1d scopes it IN WRITING, and it says: {doc!r}")
    for word in ("eval", "fixture", "tooling"):
        assert word in doc, unscoped
    # Driven, not merely documented: `at` carries no runs base, so it is not the live path.
    tooling = S.Run().at(run_dir)
    assert tooling.runs_base is None, (
        "Run.at handed back a handle holding a runs base — it is the bare-directory hatch")
    assert _tenanted(base).runs_base == base, (
        "positive control: the live investigation path DOES hold its base")


def test_run_under_is_an_internal_helper_and_no_caller_outside_the_owner_uses_it(base, run_dir):
    """`Run.under` is an internal helper `Run.for_tenant` is built on, and no caller outside the
    owner's own module reaches it.

    NEGATIVE. Positive control inline: `Run.for_tenant` IS reached and resolves the same
    directory `under` would have.
    """
    import ast
    from defender.tests._by_path import DEFENDER, import_lint_lib
    astlib = import_lint_lib("_astlib")
    # RESOLVED, not grepped: `.under(` is also `_io.Bound.under`, an unrelated method five
    # modules reach — a spelling match reports them and says nothing about `Run.under`.
    handle_origin = f"defender.{S.HANDLE_MODULE}.Run.under"
    hits = []
    for py in sorted(DEFENDER.rglob("*.py")):
        rel = py.relative_to(DEFENDER).as_posix()
        if rel.startswith("tests/") or rel == f"{S.HANDLE_MODULE}.py":
            continue
        try:
            _text, tree = astlib.read_and_parse(py, rel)
        except astlib.ScanBlind:
            hits.append(f"{rel} (unparseable)")
            continue
        env = astlib.module_env(tree)
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and astlib.callee(node, env) == handle_origin:
                hits.append(rel)
                break
    assert hits == [], f"Run.under is reached outside the owner module: {hits}"
    assert _tenanted(base).run_dir == run_dir, (
        "positive control: for_tenant, which under is the helper of, resolves the same directory")


def test_run_at_refuses_a_nonexistent_path_and_a_file(base, tmp_path: Path):
    """`Run.at` refuses at construction when the path does not exist or is not a directory, and
    the refusal says 'not an existing directory', not 'not run-dir-shaped'."""
    missing = tmp_path / "no-such-run"
    a_file = tmp_path / "a-file"
    a_file.write_text("not a directory\n", encoding="utf-8")

    for bad in (missing, a_file):
        with pytest.raises(Exception) as excinfo:  # noqa: PT011 — the type is the contract below
            S.Run().at(bad)
        said = str(excinfo.value)
        assert "existing directory" in said, (
            f"Run.at({bad.name}) refused with {said!r}; decision 8 words the ONE refusal it "
            "carries as 'not an existing directory', never 'not run-dir-shaped'")
    # Positive control: an existing directory — even a wholly empty one — is accepted.
    empty = tmp_path / "empty"
    empty.mkdir()
    assert S.Run().at(empty) is not None


def test_run_id_admission_is_todays_validator_by_reference_not_a_second_one(base):
    """Run-id admission at both surviving public constructors reaches today's validators by
    reference — `is_valid_run_id`, and after §7 decision 20 `is_case_stable_id` beside it —
    and restates neither rule on the handle."""
    from defender._run_id import (
        CASE_STABLE_REQUIRED,
        RUN_ID_ALLOWED,
        is_case_stable_id,
        is_valid_run_id,
    )
    bad = ("", "-leading-dash", "has space", "héllo", "a/b", "..")
    for run_id in bad:
        assert not is_valid_run_id(run_id), f"{run_id!r} is the validator's own refusal"
        with pytest.raises(Exception) as excinfo:  # noqa: PT011
            S.Run().for_tenant(S.DEFAULT_TENANT_ID, run_id, runs_base=base)
        assert RUN_ID_ALLOWED in str(excinfo.value), (
            f"the handle refused {run_id!r} in its own words rather than surfacing today's "
            "validator's — decision 8 delegates BY REFERENCE, it does not restate the rule")
    # The SECOND predicate is delegated the same way. `is_valid_run_id` admits upper case by
    # construction (its own docstring says so), so before decision 20 this whole surface had
    # exactly one rule and the case fold was nobody's — see h54, which drives the collision.
    two_predicates = (
        "the two predicates answer different questions; if `is_valid_run_id` refused mixed "
        "case on its own there would be nothing for decision 20 to add")
    assert is_valid_run_id("Run-1077"), two_predicates
    assert not is_case_stable_id("Run-1077"), two_predicates
    with pytest.raises(Exception) as excinfo:  # noqa: PT011
        S.Run().for_tenant(S.DEFAULT_TENANT_ID, "Run-1077", runs_base=base)
    assert CASE_STABLE_REQUIRED in str(excinfo.value), (
        "a mixed-case run id was admitted, or refused in the handle's own words. Decision 20 "
        "reaches `_run_id.is_case_stable_id` BY REFERENCE, exactly as `_family."
        "refuse_bad_episode_id` already does for the episode id — one rule, not two spellings")
    # Positive control: an id both validators admit is admitted here, unchanged.
    assert is_valid_run_id("run-1077")
    assert is_case_stable_id("run-1077")
    assert S.Run().for_tenant(S.DEFAULT_TENANT_ID, "run-1077", runs_base=base) is not None


def test_two_run_ids_differing_only_by_case_cannot_become_one_run_directory(base):
    """`Run.for_tenant`/`Run.under` apply `is_case_stable_id` beside `is_valid_run_id`, so a
    case-variant of an existing run id is REFUSED rather than silently resolving onto that
    run's directory."""
    from defender._run_id import CASE_STABLE_REQUIRED
    S.seed_run_tree(S.make_run_dir(base, "run-1"))
    S.plant_stamp(base / "run-1", commit="c0ffee", dirty=False, tenant_id=S.DEFAULT_TENANT_ID)

    for variant in ("Run-1", "RUN-1", "rUn-1"):
        with pytest.raises(Exception) as excinfo:  # noqa: PT011
            S.Run().for_tenant(S.DEFAULT_TENANT_ID, variant, runs_base=base)
        said = str(excinfo.value)
        assert CASE_STABLE_REQUIRED in said, (
            f"{variant!r} was not refused by the case-stability rule: {said!r}. On a case-"
            "insensitive filesystem — macOS, which this repo supports, and where the default "
            "runs base lives under a symlinked /tmp — it and `run-1` are ONE inode, so "
            "decision 3's resumable setup would finish `run-1`'s directory as if it were "
            "this run's, re-stamp its identity and clear its three sidecars (h12, h13)")
        assert variant.casefold() in said, (
            "the refusal does not offer the spelling that would work; `_family."
            "refuse_bad_episode_id` names it, and this is the same rule reached by reference")
    # The refusal is the ID's, not the collision's: it holds with no existing directory too,
    # so the handle never has to look at the filesystem to know the id is unusable.
    with pytest.raises(Exception) as excinfo:  # noqa: PT011
        S.Run().for_tenant(S.DEFAULT_TENANT_ID, "Run-2", runs_base=base)
    assert CASE_STABLE_REQUIRED in str(excinfo.value)
    # And nothing was touched on the way to the refusal.
    assert S.Run().at(base / "run-1").record.commit == "c0ffee", (
        "the refused call re-stamped the run whose directory the case variant folds onto")
    assert sorted(p.name for p in base.iterdir()) == ["run-1"], (
        f"the refused call created something: {sorted(p.name for p in base.iterdir())}")
    # Positive control: the case-stable spelling is admitted, unchanged.
    assert S.Run().for_tenant(S.DEFAULT_TENANT_ID, "run-2", runs_base=base) is not None


def test_for_tenant_refuses_a_tenant_id_the_record_at_the_resolved_base_disagrees_with(base):
    """`Run.for_tenant(tenant_id, run_id)` refuses when the `tenant_id` argument disagrees with
    the tenant record actually stored at the resolved runs base, and the refusal names both."""
    S.plant_tenant_record(base, tenant_id="acme",
                          base_world_id="feedfacefeedfacefeedfacefeedface")
    S.seed_run_tree(S.make_run_dir(base, "run-mismatch"))

    with pytest.raises(Exception) as excinfo:  # noqa: PT011
        S.Run().for_tenant("globex", "run-mismatch", runs_base=base)
    said = str(excinfo.value)
    for named in ("globex", "acme"):
        assert named in said, (
            f"the refusal does not name {named!r}: {said!r}. Both sides belong in it — the "
            "caller cannot tell which of the two is wrong from a message carrying one")
    assert S.Run().at(base / "run-mismatch").record.tenant_id is None, (
        "the refused construction stamped the run anyway — decision 22 refuses BEFORE the "
        "constructor's caller can write a run under the tenant it does not belong to")

    # Neither 'trust the argument' nor 'trust the record' was chosen, because both make the
    # mismatch silent, which is what decision 1d promoted `for_tenant` to prevent.
    assert not (base / "_tenant.json").read_text(encoding="utf-8").count("globex"), (
        "the record was rewritten to agree with the argument — `for_tenant` is an enforcement "
        "point, not a migration")
    # POSITIVE CONTROL: the agreeing pair still constructs (h06), so the refusal above is the
    # disagreement and not `for_tenant` refusing every non-default tenant.
    agreeing = S.Run().for_tenant("acme", "run-mismatch", runs_base=base)
    assert agreeing.tenant_id == "acme"
    assert agreeing.runs_base == base


# ---------------------------------------------------------------------------------------
# d42 / d45 / d43 — the fields, the receivers, the archive projection
# ---------------------------------------------------------------------------------------

def test_the_run_record_answers_the_twelve_fields_read_only(base, run_dir):
    """`run.record` answers all twelve run-record fields read-only through the readers that
    already exist, with `None` wherever the record behind a field is absent."""
    run = _tenanted(base)
    S.plant_stamp(run_dir, commit="c0ffee", dirty=False, model="m", scope="defender",
                  tenant_id=S.DEFAULT_TENANT_ID, world_id="w0")
    record = run.record

    assert record.run_id == run_dir.name
    assert record.commit == "c0ffee"
    assert record.dirty is False
    assert record.model == "m"
    assert record.tenant_id == S.DEFAULT_TENANT_ID
    assert record.world_id == "w0"
    assert record.alert_ref == S.alert_ref(run_dir / "alert.json")
    # The records behind the remaining five are absent here, so those fields read None (h16).
    for absent in ("parent_run_id", "fork_turn", "exit_class", "disposition", "review_outcome"):
        assert getattr(record, absent) is None, f"{absent} is not None with its record absent"
    # Read-only: no field is settable, and no `status` exists (N4 — that is #1081/#1082's).
    with pytest.raises(Exception):  # noqa: B017,PT011
        record.commit = "rewritten"
    assert not hasattr(record, "status"), "N4: no status, no job model, no store in this issue"


def test_run_at_accepts_every_run_dir_shaped_directory_and_leaves_identity_none(
        base, tmp_path: Path):
    """`Run.at` accepts a real run, a forked sibling, a checked-in eval fixture, an unstamped
    copy and a wholly empty directory alike, answering `None` for tenant and world where there
    is no stamp."""
    real = S.seed_run_tree(S.make_run_dir(base, "real-run"))
    S.plant_stamp(real, commit="c", dirty=False, tenant_id="acme", world_id="ep.a")
    sibling = S.seed_run_tree(
        S.make_run_dir(S.make_runs_base(tmp_path / "ep", "runs"), "ep-2026-a"))
    fixture = S.seed_run_tree(tmp_path / "fixtures" / "held-out-1")
    stampless = S.seed_run_tree(tmp_path / "loop" / "runs" / "copy-1")
    empty = tmp_path / "empty"
    empty.mkdir(parents=True)

    assert S.Run().at(real).record.tenant_id == "acme", "a stamped run reads its stamp"
    for d in (sibling, fixture, stampless, empty):
        run = S.Run().at(d)
        assert run.run_dir == d
        stampless = (
            f"{d} carries no stamp, so identity reads None — N8 forbids refusing it, because "
            "the learning readers depend on reading exactly these directories")
        assert run.record.tenant_id is None, stampless
        assert run.record.world_id is None, stampless


def test_archived_world_exposes_exactly_the_copied_set_and_is_not_a_run(tmp_path: Path):
    """`ArchivedWorld.at` exposes exactly the copied set and nothing else, and is not a `Run`."""
    world = tmp_path / "episodes" / S.EPISODE_ID / "worlds" / S.LABEL
    world.mkdir(parents=True)
    aw = S.ArchivedWorld().at(world)

    assert set(aw.members) == set(S.ARCHIVED_WORLD_MEMBERS), (
        "the copied set is page §5's enumeration, extended by the four archive.py constants "
        "claim C17 omitted (gather_summaries, lessons_loaded, alert, and the run_dir pointer)")
    for name in S.ARCHIVED_WORLD_MEMBERS:
        assert getattr(aw, name).path.is_relative_to(world)
    for absent in ("tool_trace", "budget", "wire_log", "session_db", "review_record"):
        assert not hasattr(aw, absent), (
            f"{absent} is not in the copied set — an ArchivedWorld exposing it would promise a "
            "file the archive never wrote")
    assert not isinstance(aw, S.Run()), "N5: the archive's world dir gets a read-only projection"
    assert not hasattr(aw, "record"), "an ArchivedWorld is not addressed by (tenant_id, run_id)"


def test_every_writer_method_reaches_todays_seam_unchanged(base, run_dir):
    """Every writer method on a record wrapper reaches the same seam the call site reached
    before — the guarded write (replace for a document, append for a table: what
    `record_query.append_query_row` and `challenge_gate._write_trace_row` reach today, NOT the
    pre-#771 `append_jsonl`, whose `open("a")` follows a planted link), the locked rewrite, the
    request logger, the session store."""
    recorder = S.RecordingIo()
    run = S.Run().for_tenant(S.DEFAULT_TENANT_ID, run_dir.name, runs_base=base, io=recorder)

    S.member(run, "documents", "report").write(S.report_text("# a report\n"))
    assert "write_guarded" in recorder.ops, f"the document write reached {recorder.ops}"

    before = len(recorder.ops)
    S.member(run, "tables", "queries").append([{"q": 1}])
    assert "write_guarded" in recorder.ops[before:], f"the table append reached {recorder.ops}"
    assert "append_jsonl" not in recorder.ops, (
        "`_io.append_jsonl` is the unguarded pre-#771 primitive `lint_unguarded_tree_write` "
        "flags — a table append through the handle lands through the guarded append lane")

    S.member(run, "observability", "budget").update({"spent": 1})
    assert "locked_for_rewrite" in recorder.ops, f"the locked state reached {recorder.ops}"

    assert S.member(run, "observability", "wire_log").logger_factory is S.mod(
        "runtime.observe").RequestLogger, "the wire log's writer is today's RequestLogger"
    assert S.member(run, "session", "session_db", S.LINEAGE_ID).open_store is S.mod(
        "runtime.session_store").open_store, "the session access is today's store seam"

    assert "write_atomic" not in recorder.ops, (
        "flagged fact F13 / decision 16: `_io.write_atomic` takes ANY path and is reachable "
        "from outside the owner modules, so no name-keyed lint can see it — it is a documented "
        "out-of-scope gap, deliberately NOT the seam a writer method reaches")


# ---------------------------------------------------------------------------------------
# Settled premises on the constructors' admission domain
# ---------------------------------------------------------------------------------------

def test_run_under_run_id_containing_path_separator(base):
    """Security dive universal (1): no accessor resolves outside its root for any input — a
    '/'-bearing run_id handed to the constructors must not escape the runs base, whether it
    arrives at the public `Run.for_tenant` or at the internal `Run.under` it is built on."""
    escaped = base.parent / "escaped"
    escaped.mkdir(exist_ok=True)
    for run_id in ("../escaped", "a/b", "/etc"):
        with pytest.raises(Exception):  # noqa: B017,PT011
            S.Run().for_tenant(S.DEFAULT_TENANT_ID, run_id, runs_base=base)
        with pytest.raises(Exception):  # noqa: B017,PT011
            S.Run().under(base, run_id)
    assert not (escaped / "provenance.json").exists(), "a refused construction wrote outside"
    # Positive control: an ordinary run id resolves, inside the base.
    ok = S.Run().for_tenant(S.DEFAULT_TENANT_ID, "run-1077", runs_base=base)
    assert ok.run_dir.is_relative_to(base)


def test_run_under_run_id_containing_parent_traversal(base):
    """The resolved run dir remains inside the runs base regardless of a '..'-shaped run_id, at
    the public constructor and at the internal helper alike."""
    outside = base.parent / "outside"
    outside.mkdir(exist_ok=True)
    for run_id in ("..", "../..", "../outside", "x/../../outside"):
        for build in (lambda r: S.Run().for_tenant(S.DEFAULT_TENANT_ID, r, runs_base=base),
                      lambda r: S.Run().under(base, r)):
            with pytest.raises(Exception):  # noqa: B017,PT011
                build(run_id)
    assert S.Run().for_tenant(
        S.DEFAULT_TENANT_ID, "run-1077", runs_base=base).run_dir.is_relative_to(base), (
        "positive control: a traversal-free id still resolves, inside the base")


def test_handle_over_the_learning_run_directory_that_this_issue_leaves_unowned(tmp_path: Path):
    """Receiver kind (5) stays out of D1-D7's scope: `Run.at` still accepts a
    `LoopPaths.runs_dir/<run_id>` learning run dir as run-dir-shaped (N8), no accessor covers
    it, and no demand may assert that it is unwritten — the forward-check verifier writes a
    wire trace there."""
    learning_run = tmp_path / "state" / "runs" / "source-42"
    S.seed_run_tree(learning_run)
    run = S.Run().at(learning_run)
    assert run.run_dir == learning_run, "N8: it is run-dir-shaped, so Run.at takes it"
    assert run.runs_base is None, "this root is not a runs base and the handle claims none"
    # Claim C16 is REFUTED: this root IS written. A trace landing here is ordinary, not a fault.
    trace_dir = learning_run / "wire_logs"
    trace_dir.mkdir()
    (trace_dir / "forward.a-lesson.2.trace.jsonl").write_text("{}\n", encoding="utf-8")
    assert S.Run().at(learning_run).run_dir == learning_run, (
        "the handle neither refuses nor complains about a learning run dir that has just "
        "gained a verifier trace — this issue leaves receiver kind (5) unowned and UNRESTRICTED")


def test_handle_over_a_companion_corpus_directory_that_is_merely_someones_parent(tmp_path: Path):
    """Receiver kind (6) is also out of scope: `RunPaths` continues to be constructed ad hoc over
    an arbitrary companion-corpus directory, outside the gate's sweep, unaddressed by this
    issue."""
    corpus = tmp_path / "skills" / "invlang" / "corpus"
    corpus.mkdir(parents=True)
    companion = corpus / "a-document.md"
    companion.write_text("# not a run\n", encoding="utf-8")

    # The live site builds from the FILE's parent, which is a directory — unaffected by h09.
    assert S.RunPaths(companion.parent).alert == corpus / "alert.json", (
        "RunPaths still composes ad hoc over an arbitrary companion-corpus directory")
    assert S.Run().at(companion.parent).runs_base is None
    gate = S.gate()
    assert "skills" not in gate.SWEEP_DIRS, (
        "claim G3 / brief red flag R3: `defender/skills/` is outside the sweep, which is why "
        "this live name use is unaddressed rather than a finding")


def test_two_handles_for_one_run_directory(base, run_dir):
    """Two handles built over one run directory are independent: the handle is addressed by
    (tenant_id, run_id) and the file backend locates by directory per call, so nothing implies
    shared state or caching between constructions."""
    a, b = S.Run().at(run_dir), S.Run().at(run_dir)
    assert a is not b, "the scale dive's own sentence is one object construction per call site"
    assert a.run_dir == b.run_dir
    assert S.member(a, "documents", "report") is not S.member(b, "documents", "report")
    # A write through one is observable through the other because the FILE is shared, not state.
    S.member(a, "documents", "report").write(S.report_text("# from a\n"))
    assert S.member(b, "documents", "report").read() == S.report_text("# from a\n")
    # And a record read through one is not cached into the other.
    S.plant_stamp(run_dir, commit="c1", dirty=False, tenant_id="t1", world_id="w1")
    assert a.record.tenant_id == "t1"
    S.plant_stamp(run_dir, commit="c1", dirty=False, tenant_id="t2", world_id="w2")
    assert S.Run().at(run_dir).record.tenant_id == "t2", (
        "a second construction re-reads; nothing is remembered between constructions")


# ---------------------------------------------------------------------------------------
# Decision 4 — 'absent or unreadable', the three arms on RunRecord
# ---------------------------------------------------------------------------------------

def test_a_field_whose_record_is_absent_reads_none(base, run_dir):
    """A run-record field whose backing record is absent reads `None`."""
    run = S.Run().at(run_dir)
    assert not (run_dir / "provenance.json").exists()
    record = run.record
    for field in ("tenant_id", "world_id", "commit", "dirty", "model", "exit_class",
                  "disposition", "review_outcome", "parent_run_id", "fork_turn"):
        assert getattr(record, field) is None, f"{field} with its record absent"
    assert record.faults == (), "absent is not a fault — decision 4's first arm records nothing"
    # Positive control: the same field reads a value once the record is there.
    S.plant_stamp(run_dir, commit="c0ffee", dirty=False)
    assert S.Run().at(run_dir).record.commit == "c0ffee"


def test_a_field_whose_record_is_unparseable_reads_none_and_records_the_fault(base, run_dir):
    """A run-record field whose backing record is present but unparseable reads `None` and the
    fault is recorded, not silently swallowed."""
    (run_dir / "provenance.json").write_text("{ not json at all", encoding="utf-8")
    record = S.Run().at(run_dir).record
    assert record.commit is None
    assert record.tenant_id is None
    assert record.faults, (
        "an unparseable record read as None with NO fault is indistinguishable from an absent "
        "one — decision 4's second arm keeps them apart")
    assert any("provenance" in str(f) for f in record.faults), (
        f"the recorded fault does not name the record it came from: {record.faults}")


def test_a_field_whose_record_is_wrong_shaped_reads_none_and_records_the_fault(base, run_dir):
    """A run-record field whose backing record parses but carries the wrong shape — a `world_id`
    that is a number, a report whose disposition is a list — reads `None` and the fault is
    recorded."""
    S.plant_stamp(run_dir, commit="c0ffee", dirty=False, tenant_id="t", world_id=17)
    (run_dir / "report.md").write_text("disposition: [a, list]\n", encoding="utf-8")
    record = S.Run().at(run_dir).record

    assert record.world_id is None, "a numeric world_id is a wrong shape, not a value"
    assert record.disposition is None
    assert record.faults, "decision 4's third arm records the fault as well as reading None"
    # An explicitly-NULL key is decision 4's non-case (F045): `str | None` admits it, no fault.
    S.plant_stamp(run_dir, commit="c0ffee", dirty=False, tenant_id=None, world_id=None)
    (run_dir / "report.md").write_text("disposition: benign\n", encoding="utf-8")
    quiet = S.Run().at(run_dir).record
    assert quiet.tenant_id is None
    assert quiet.world_id is None
    assert quiet.faults == (), (
        "an explicitly-null tenant_id/world_id is a value the field's declared `str | None` "
        "type admits (D3), not a wrong shape — no fault is recorded for it")


# ---------------------------------------------------------------------------------------
# Decision 10 (dissolved) — each accessor's OWN root
# ---------------------------------------------------------------------------------------

def test_each_accessor_is_checked_against_its_own_root_not_one_assumed_root(base, run_dir):
    """Each accessor is checked against its own root — the sidecars against the runs base, the
    session db against the sessions directory, everything else against the run directory — not
    against one assumed root."""
    owner = S.RunPaths(run_dir)
    sessions = base.parent / "sessions"
    for name in S.SIDECAR_ACCESSORS:
        resolved = getattr(owner, name)(base)
        assert resolved.parent == base, (
            f"{name} resolved under {resolved.parent}, not its own root, the runs base")
        assert resolved.name.startswith(run_dir.name), "a sidecar is keyed `<run_id><suffix>`"
    assert owner.sessions_dir(base) == sessions, (
        "the sessions directory is a SIBLING of the runs base (claims C10/C15)")
    assert owner.session_db(base, S.LINEAGE_ID).parent == sessions
    for name in ("alert", "report", "investigation", "executed_queries", "wire_log",
                 "provenance", "tool_trace"):
        assert getattr(owner, name).is_relative_to(run_dir), f"{name}'s root is the run directory"


def test_a_handle_built_from_a_bare_directory_lacks_the_input_the_upward_accessors_need(
        base, tmp_path: Path):
    """A handle built from a bare directory has no runs base in hand, so the upward accessors
    report a missing precondition rather than a policy denial."""
    world = tmp_path / "episodes" / S.EPISODE_ID / "worlds" / S.LABEL
    S.seed_run_tree(world)
    bare = S.Run().at(world)
    assert bare.runs_base is None

    for group, name in (("facts", "run_end"), ("facts", "scrub_verdict"),
                        ("facts", "accounting"), ("session", "session_db")):
        with pytest.raises(Exception) as excinfo:  # noqa: PT011
            S.member(bare, group, name, *S.member_args(name)).path  # noqa: B018
        said = str(excinfo.value)
        assert "runs base" in said, (
            f"run.{group}.{name} on a bare directory said {said!r}; decision 10 dissolved this "
            "into a MISSING PRECONDITION — no new access-control mechanism, no policy denial")
        assert "denied" not in said.lower()
        assert "forbidden" not in said.lower()
    # Positive control: given a runs base, the same accessors resolve.
    run_dir = S.seed_run_tree(S.make_run_dir(base))
    tenanted = S.Run().for_tenant(S.DEFAULT_TENANT_ID, run_dir.name, runs_base=base)
    assert S.member(tenanted, "facts", "run_end").path.parent == base


# ---------------------------------------------------------------------------------------
# Decision 11 (dissolved) — read everywhere, write where the runtime produces
# ---------------------------------------------------------------------------------------

def test_every_sub_collection_reads_everywhere_and_writes_only_where_the_runtime_produces(
        base, run_dir):
    """Every record reads everywhere and exposes exactly ITS producer's verb — `append` for a
    table or trace, `write` for a document or a write-once fact, `update` for a locked state,
    `open` for the session store — and no other; a record nothing in the host writes through
    the handle exposes none. Including `documents`, writable in place by the investigation
    process during its own run."""
    run = _tenanted(base)
    for group, names in S.GROUP_MEMBERS.items():
        for name in names:
            rec = S.member(run, group, name, *S.member_args(name))
            assert callable(getattr(rec, "read", None)), f"run.{group}.{name} is not readable"
            verb = S.MEMBER_VERB[name]
            exposed = {v for v in S.VERBS if callable(getattr(rec, v, None))}
            assert exposed == ({verb} if verb else set()), (
                f"run.{group}.{name} exposes {sorted(exposed)}; its producer's verb is {verb!r} "
                "— a verb that does not fit the record's shape corrupts it (JSONL appended into "
                "a SQLite store, a whole JSON document appended to)")
    # Driven, not merely present: one member per group actually produces its record.
    S.member(run, "documents", "investigation").write("# in place\n")
    assert S.member(run, "documents", "investigation").read() == "# in place\n", (
        "`documents` is writable in place by the investigation process — that is what decision "
        "11 dissolved, without picking between the group table and the structure")
    S.member(run, "tables", "queries").append([{"seq": 1}])
    assert S.member(run, "tables", "queries").read().strip() == json.dumps({"seq": 1})


def test_run_facts_group_exposes_no_write_accessor(base, run_dir):
    """`run.facts` (alert, provenance, run_end, scrub_verdict, accounting) is readable
    everywhere and exposes a write only to the host that produces it — write-once, outside the
    model's reach — per §7 decision 11's uniform rule.

    NEGATIVE: no accessor on `facts` rewrites a fact that is already written, and none appends.
    Positive control inline: the FIRST write of that same fact lands.
    """
    run = _tenanted(base)
    prov = S.member(run, "facts", "provenance")
    prov.write('{"commit": "c0ffee"}\n')                    # positive control
    assert json.loads(prov.read())["commit"] == "c0ffee"

    with pytest.raises(Exception) as excinfo:  # noqa: PT011
        prov.write('{"commit": "rewritten"}\n')
    assert "write-once" in str(excinfo.value).lower() or "exists" in str(excinfo.value).lower()
    assert json.loads(prov.read())["commit"] == "c0ffee", "the second write changed the fact"

    for name in S.GROUP_MEMBERS["facts"]:
        rec = S.member(run, "facts", name, *S.member_args(name)) if name not in (
            "run_end", "scrub_verdict", "accounting") else None
        if rec is None:
            continue
        assert not hasattr(rec, "append"), f"run.facts.{name} exposes an append"


def test_run_documents_group_write_contract_matches_the_design_tables_rewritten_in_place_reading(
        base, run_dir):
    """`run.documents` (investigation, report, gather_summaries, lead_author, source_refs) is
    readable everywhere and writable in place — schema-gated — only by the investigation process
    that produces it during its own run, per §7 decision 11's uniform rule."""
    run = _tenanted(base)
    doc = S.member(run, "documents", "investigation")
    doc.write("# first\n")
    assert doc.read() == "# first\n"
    doc.write("# rewritten in place\n")
    assert doc.read() == "# rewritten in place\n", (
        "a document IS rewritten in place — the design table's reading, which decision 11 kept "
        "by applying the issue's general rule rather than by picking the table over the structure")
    for name in S.GROUP_MEMBERS["documents"]:
        rec = S.member(run, "documents", name, *S.member_args(name))
        assert callable(rec.read)
        assert not hasattr(rec, "append"), f"run.documents.{name} is rewritten, not appended"
        if S.MEMBER_VERB[name] is None:
            # `lead_author/` is a DIRECTORY of documents the learning drain lands; the handle
            # names it and reads it, and there is no whole-record write of a directory.
            assert not hasattr(rec, "write"), f"run.documents.{name} is a directory"
            continue
        assert callable(rec.write)


def test_run_observability_group_stays_append_only_through_the_handle(base, run_dir):
    """`run.observability` (wire_log, review_trace, forward_check_trace, tool_trace,
    review_record, budget, circuit_breaker, lessons_loaded, ticket_write, runtime_html,
    box_sentinel, session_pointer) is readable everywhere and append-only for the host that
    produces it — no accessor exposes an in-place rewrite of an existing entry — per §7
    decision 11's uniform rule.

    NEGATIVE, with the positive control inline: the append DOES land and both entries survive.
    """
    run = _tenanted(base)
    trace = S.member(run, "observability", "tool_trace")
    trace.append([{"row": 1}])
    trace.append([{"row": 2}])
    rows = [json.loads(line) for line in trace.read().splitlines() if line.strip()]
    assert rows == [{"row": 1}, {"row": 2}], "an append discarded the entry before it"

    for name in S.GROUP_MEMBERS["observability"]:
        rec = S.member(run, "observability", name, *S.member_args(name))
        if name in S.LOCKED_STATE_MEMBERS:
            # The two locked JSON states are a read-modify-write under `flock`, never a blind
            # replace: their update SEES the prior state rather than discarding it.
            rec.update({"a": 1})
            rec.update({"b": 2})
            assert json.loads(rec.read()) == {"a": 1, "b": 2}, (
                f"run.observability.{name}'s update discarded the existing entry")
            continue
        if S.MEMBER_VERB[name] == "append":
            assert not hasattr(rec, "write"), (
                f"run.observability.{name} exposes a whole-record rewrite of an existing entry")
        else:
            # A whole JSON/HTML document the host writes once per run (the ticket write, the
            # session pointer, the rendered page, the review record) is not a log: it has no
            # entries to append to, and appending JSONL to it would corrupt it.
            assert not hasattr(rec, "append"), (
                f"run.observability.{name} is a whole document; an append would corrupt it")


# ---------------------------------------------------------------------------------------
# Decision 9 — read purity
# ---------------------------------------------------------------------------------------

def test_asking_the_handle_or_the_owner_for_a_name_creates_nothing(base, run_dir):
    """Asking the handle or the owner for a name creates nothing on disk — no directory, no
    file, no lock.

    NEGATIVE, and the demand claim G6 is about: `observe.stage_trace_path` MKDIRS on being
    asked for a path today. Positive control inline: the write method DOES create the directory.
    """
    for p in sorted(run_dir.rglob("*")):
        if p.is_file():
            p.unlink()
    for p in sorted(run_dir.rglob("*"), reverse=True):
        p.rmdir()
    before = S.mutation_census(run_dir)

    run = _tenanted(base)
    owner = S.RunPaths(run_dir)
    for group, names in S.GROUP_MEMBERS.items():
        for name in names:
            rec = S.member(run, group, name, *S.member_args(name))
            if S.MEMBER_ACCESSOR[name] in S.UPWARD_ACCESSORS:
                continue
            _ = rec.path
    for acc in S.ACCESSOR_FOR_KIND:
        if acc.owner == "run" and acc.attr not in S.UPWARD_ACCESSORS:
            _ = S.resolve(acc, run_dir=run_dir, runs_base=base)
    _ = owner.wire_log
    _ = run.record

    assert S.mutation_census(run_dir) == before, (
        f"asking for names created {sorted(set(S.mutation_census(run_dir)) - set(before))} — "
        "decision 9 moves the directory-creation side effect into the write method that "
        "needs it, so a READER resolving a name no longer mutates the run it is reading")
    # Positive control: the write method DOES create what it needs.
    S.member(run, "observability", "wire_log").append([{"event_type": "message"}])
    assert (run_dir / "wire_logs").is_dir()


def test_the_write_method_creates_the_directory_the_path_accessor_no_longer_does(base, run_dir):
    """The write method creates the directory its record needs, and it is the only thing that
    does."""
    recorder = S.RecordingIo()
    run = S.Run().for_tenant(S.DEFAULT_TENANT_ID, run_dir.name, runs_base=base, io=recorder)
    trace = S.member(run, "observability", "review_trace", S.ROLE)

    assert not (run_dir / "wire_logs").exists()
    _ = trace.path
    assert not (run_dir / "wire_logs").exists(), "the path accessor created the holding directory"
    assert "guarded_mkdir" not in recorder.ops, f"the path accessor reached {recorder.ops}"

    trace.append([{"role": S.ROLE}])
    assert (run_dir / "wire_logs").is_dir(), "the write method did not create its directory"
    assert "guarded_mkdir" in recorder.ops, (
        "the side effect did not disappear, it relocated to the method that needs it")
