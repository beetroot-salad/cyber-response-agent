"""#1077 — the handle's surface: the constructors, the five sub-collections, `RunRecord` and the
per-kind `RecordHandle`."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path, fixture_runs_base

import json
from pathlib import Path
from typing import Any
from defender.tests.support.shared._fixture_uuid import fixture_uuid

import pytest

from defender.tests.support.shared.contracts import _spec1077 as S


@pytest.fixture
def base(tmp_path: Path) -> Path:
    return S.make_runs_base(tmp_path)


@pytest.fixture
def run_dir(base: Path) -> Path:
    return S.seed_run_tree(S.make_run_dir(base))




def _tenanted(base: Path, run_id: str = S.RUN_ID):
    """Build a tenant-addressed handle over its record-free runs container."""
    return S.Run().under(fixture_runs_base(base), run_id, tenant_id=S.DEFAULT_TENANT_ID)


# Demand #0 — the return-value contract, RESOLVED at §7 on all four axes


# Decision 1b/1c/1d — the three flipped axes


def test_run_at_refuses_a_nonexistent_path_and_a_file(base, tmp_path: Path):
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


def test_two_run_ids_differing_only_by_case_cannot_become_one_run_directory(base):
    from defender.run_repository import RunId, RunRefused
    one, two = fixture_uuid("handle-case-one"), fixture_uuid("handle-case-two")
    S.seed_run_tree(S.make_run_dir(base, one))
    S.plant_stamp(base / one, commit="c0ffee", dirty=False, tenant_id=S.DEFAULT_TENANT_ID)
    mixed = "".join(c.upper() if i % 2 else c for i, c in enumerate(one))

    for variant in (one.upper(), mixed):
        assert variant != one, "fixture: the variant must differ from the id only by case"
        rule = _rule_refusal(RunId.parse, variant)
        assert isinstance(rule, RunRefused), f"fixture: the rule admits {variant!r} ({rule!r})"
        with pytest.raises(RunRefused) as excinfo:
            S.Run().under(fixture_runs_base(base), variant, tenant_id=S.DEFAULT_TENANT_ID)
        said = str(excinfo.value)
        assert (type(excinfo.value), said) == (type(rule), str(rule)), (
            f"the handle's refusal of {variant!r} is not the run-id rule's own: the handle said "
            f"{excinfo.value!r}, RunId.parse says {rule!r}")
        assert repr(variant) in said, (
            f"{variant!r} was not refused by name: {said!r}. On a case-insensitive filesystem — "
            "macOS, which this repo supports, and where the default runs base lives under a "
            "symlinked /tmp — it and the lowercase id are ONE inode, so decision 3's resumable "
            "setup would finish that run's directory as if it were this run's, re-stamp its "
            "identity and clear its three sidecars (h12, h13)")
        assert "\n" not in said, f"the refusal of {variant!r} is not one line: {said!r}"
    # The refusal is the ID's, not the collision's: it holds with no existing directory too,
    # so the handle never has to look at the filesystem to know the id is unusable.
    with pytest.raises(RunRefused) as excinfo:
        S.Run().under(fixture_runs_base(base), two.upper(), tenant_id=S.DEFAULT_TENANT_ID)
    assert str(excinfo.value) == str(_rule_refusal(RunId.parse, two.upper()))
    assert repr(two.upper()) in str(excinfo.value)
    # And nothing was touched on the way to the refusal.
    assert S.Run().at(base / one).record.commit == "c0ffee", (
        "the refused call re-stamped the run whose directory the case variant folds onto")
    assert sorted(p.name for p in base.iterdir()) == [one], (
        f"the refused call created something: {sorted(p.name for p in base.iterdir())}")
    # Positive control: the case-stable spelling is admitted, unchanged.
    assert S.Run().under(fixture_runs_base(base), two, tenant_id=S.DEFAULT_TENANT_ID) is not None


# d42 / d45 / d43 — the fields, the receivers, the archive projection


def test_archived_world_exposes_exactly_the_copied_set_and_is_not_a_run(tmp_path: Path):
    world = tmp_path / "episodes" / S.EPISODE_ID / "worlds" / S.WORLD_ID
    world.mkdir(parents=True)
    aw = S.ArchivedWorld().at(world)

    assert set(aw.members) == set(S.ARCHIVED_WORLD_MEMBERS), (
        "the copied set is page §5's enumeration, extended by the archive.py constants claim "
        "C17 omitted (gather_summaries, lessons_loaded, alert); #1187 R8 retired the run_dir "
        "pointer")
    for name in S.ARCHIVED_WORLD_MEMBERS:
        assert getattr(aw, name).path.is_relative_to(world)
    for absent in ("tool_trace", "budget", "wire_log", "session_db", "review_record"):
        assert not hasattr(aw, absent), (
            f"{absent} is not in the copied set — an ArchivedWorld exposing it would promise a "
            "file the archive never wrote")
    assert not isinstance(aw, S.Run()), "N5: the archive's world dir gets a read-only projection"
    assert not hasattr(aw, "record"), "an ArchivedWorld is not addressed by (tenant_id, run_id)"


# Settled premises on the constructors' admission domain

def test_run_under_run_id_containing_path_separator(base):
    escaped = base.parent / "escaped"
    escaped.mkdir(exist_ok=True)
    for run_id in ("../escaped", "a/b", "/etc"):
        with pytest.raises(Exception):  # noqa: B017,PT011
            S.Run().under(fixture_runs_base(base), run_id, tenant_id=S.DEFAULT_TENANT_ID)
        with pytest.raises(Exception):  # noqa: B017,PT011
            S.Run().under(fixture_runs_base(base), run_id)
    assert not (escaped / "provenance.json").exists(), "a refused construction wrote outside"
    # Positive control: an ordinary run id resolves, inside the base.
    ok = S.Run().under(fixture_runs_base(base), S.RUN_ID, tenant_id=S.DEFAULT_TENANT_ID)
    assert ok.run_dir.is_relative_to(base)


def test_run_under_run_id_containing_parent_traversal(base):
    outside = base.parent / "outside"
    outside.mkdir(exist_ok=True)
    for run_id in ("..", "../..", "../outside", "x/../../outside"):
        for build in (lambda r: S.Run().under(fixture_runs_base(base), r, tenant_id=S.DEFAULT_TENANT_ID),
                      lambda r: S.Run().under(fixture_runs_base(base), r)):
            with pytest.raises(Exception):  # noqa: B017,PT011
                build(run_id)
    assert S.Run().under(
        fixture_runs_base(base), S.RUN_ID, tenant_id=S.DEFAULT_TENANT_ID).run_dir.is_relative_to(base), (
        "positive control: a traversal-free id still resolves, inside the base")


def test_handle_over_the_learning_run_directory_that_this_issue_leaves_unowned(tmp_path: Path):
    learning_run = tmp_path / "state" / "runs" / "source-42"
    S.seed_run_tree(learning_run)
    run = S.Run().at(learning_run)
    assert run.run_dir == learning_run, "N8: it is run-dir-shaped, so Run.at takes it"
    assert location_path(run.runs_base) is None, "this root is not a runs base and the handle claims none"
    # Claim C16 is REFUTED: this root IS written. A trace landing here is ordinary, not a fault.
    trace_dir = learning_run / "wire_logs"
    trace_dir.mkdir()
    (trace_dir / "forward.a-lesson.2.trace.jsonl").write_text("{}\n", encoding="utf-8")
    assert S.Run().at(learning_run).run_dir == learning_run, (
        "the handle neither refuses nor complains about a learning run dir that has just "
        "gained a verifier trace — this issue leaves receiver kind (5) unowned and UNRESTRICTED")


def test_handle_over_a_companion_corpus_directory_that_is_merely_someones_parent(tmp_path: Path):
    corpus = tmp_path / "skills" / "invlang" / "corpus"
    corpus.mkdir(parents=True)
    companion = corpus / "a-document.md"
    companion.write_text("# not a run\n", encoding="utf-8")

    # The live site builds from the FILE's parent, which is a directory — unaffected by h09.
    assert S.RunPaths(companion.parent).alert == corpus / "alert_input" / "alert.json", (
        "RunPaths still composes ad hoc over an arbitrary companion-corpus directory")
    assert location_path(S.Run().at(companion.parent).runs_base) is None
    gate = S.gate()
    assert "skills" not in gate.SWEEP_DIRS, (
        "claim G3 / brief red flag R3: `defender/skills/` is outside the sweep, which is why "
        "this live name use is unaddressed rather than a finding")


# Decision 4 — 'absent or unreadable', the three arms on RunRecord


def test_a_field_whose_record_is_unparseable_reads_none_and_records_the_fault(base, run_dir):
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


# Decision 10 (dissolved) — each accessor's OWN root

def test_each_accessor_is_checked_against_its_own_root_not_one_assumed_root(base, run_dir):
    owner = S.RunPaths(run_dir)
    sessions = base.parent / "sessions"
    for name in S.SIDECAR_ACCESSORS:
        resolved = getattr(owner, name)(fixture_runs_base(base))
        assert resolved.parent == base, (
            f"{name} resolved under {resolved.parent}, not its own root, the runs base")
        assert resolved.name.startswith(run_dir.name), "a sidecar is keyed `<run_id><suffix>`"
    assert location_path(owner.sessions_dir(fixture_runs_base(base))) == sessions, (
        "the sessions directory is a SIBLING of the runs base (claims C10/C15)")
    assert owner.session_db(fixture_runs_base(base), S.LINEAGE_ID).parent == sessions
    for name in ("alert", "report", "investigation", "executed_queries", "wire_log",
                 "provenance", "tool_trace"):
        assert getattr(owner, name).is_relative_to(run_dir), f"{name}'s root is the run directory"


# Decision 11 (dissolved) — read everywhere, write where the runtime produces


def test_run_observability_group_stays_append_only_through_the_handle(base, run_dir):
    run = _tenanted(base)
    trace = S.member(run, "observability", "tool_trace")
    trace.append([{"row": 1}])
    trace.append([{"row": 2}])
    rows = [json.loads(line) for line in trace.read().splitlines() if line.strip()]
    assert rows == [{"row": 1}, {"row": 2}], "an append discarded the entry before it"

    for name in S.GROUP_MEMBERS["observability"]:
        rec = S.member(run, "observability", name, *S.member_args(name))
        # No locked JSON state is left in this group (#1235 moved the budget and the breaker
        # into the run process's memory), so no member takes a read-modify-write `update`.
        assert not hasattr(rec, "update"), f"run.observability.{name} exposes an update"
        if S.MEMBER_VERB[name] == "append":
            assert not hasattr(rec, "write"), (
                f"run.observability.{name} exposes a whole-record rewrite of an existing entry")
        else:
            # A whole JSON/HTML document the host writes once per run (the ticket write, the
            # session pointer, the rendered page, the review record) is not a log: it has no
            # entries to append to, and appending JSONL to it would corrupt it.
            assert not hasattr(rec, "append"), (
                f"run.observability.{name} is a whole document; an append would corrupt it")


# Decision 9 — read purity


def _rule_refusal(rule: Any, text: str) -> BaseException | None:
    """What the one run-id rule (`rule`, `RunId.parse`) raises for `text`, or `None` when it
    admits it — the reference the handle's own refusal is compared against."""
    try:
        rule(text)
    except Exception as refused:  # noqa: BLE001 — the rule's refusal is the value compared
        return refused
    return None
