"""#1105 D3 — `open_run(runs_base, run_id)`: reading a run checks only what protects the read (O3).

One test per `open_run` demand of `spec-flow/specs/spec_graph_1105.yaml`, each named by the
demand's `discharged_by` and carrying its prose. Every fault is REAL (tier 1, `_spec1105`): the
bad record is written, linked or replaced on disk, the unreadable record is a real mode-000 file
read by a reader that obeys mode bits. The one exception is EIO at the record's read, which no
filesystem this suite owns can produce on demand — `EioOnRecord` (tier 2, dep-PO14).

RED against ed5386bc: `defender.run_service` does not exist, so every test fails on `svc()`.
Refuted claims respected: the other-tenant record raises PLAIN `ValueError` (K3, is-PO6), a
record naming a near-default spelling is read verbatim and refused (is-PO6), and at base
`Run.at` raises raw `OSError`/`PermissionError` where J4 now demands the `ValueError` family
(adv-PO7, author-P1) — so those cells are pinned to the correction, never to today's raw error.
"""
from __future__ import annotations

import errno
import os
from pathlib import Path

import pytest

from defender.tests import _spec1105 as S
from defender.tests._by_path import load_trace_lesson


def _open(base: Path, run_id):
    return S.sym("open_run")(base, run_id)


def _is_run(obj) -> bool:
    from defender._run_handle import Run

    return isinstance(obj, Run)


# ---------------------------------------------------------------------------------------
# demand #0 — the return contract
# ---------------------------------------------------------------------------------------


def test_1105_open_run_returns_tenant_handle_when_case_stable_and_bare_handle_otherwise(tmp_path):
    """`open_run(runs_base, run_id)` returns a `Run` in both of these cases: For a case-stable
    `run_id`, the `Run` holds `runs_base`: its `run_dir` is `runs_base / run_id`, and
    `run.facts.scrub_verdict.path` and `run.facts.run_end.path` resolve to
    `<runs_base>/<run_id>.scrub-verdict.json` and `.run-end.json`. For a valid but
    non-case-stable `run_id` naming an existing directory, the `Run` holds no `runs_base`:
    `run.documents.report.path` resolves inside the directory, and `run.facts.scrub_verdict.path`
    raises `ValueError`.
    """
    base = tmp_path / "runs"
    S.write_record(base)
    S.make_run(base, S.CASE_STABLE_ID)
    S.make_run(base, S.FIXTURE_ID)

    run = _open(base, S.CASE_STABLE_ID)
    assert _is_run(run), run
    assert run.run_dir == base / S.CASE_STABLE_ID
    assert run.runs_base == base
    assert run.tenant_id == S.DEFAULT_TENANT, "a case-stable id is opened Run.for_tenant"
    assert run.facts.scrub_verdict.path == base / f"{S.CASE_STABLE_ID}.scrub-verdict.json"
    assert run.facts.run_end.path == base / f"{S.CASE_STABLE_ID}.run-end.json"

    bare = _open(base, S.FIXTURE_ID)
    assert _is_run(bare), bare
    assert bare.run_dir == base / S.FIXTURE_ID
    assert bare.runs_base is None, "a non-case-stable id is opened Run.at — no runs base held"
    assert not hasattr(bare, "tenant_id"), "a Run.at handle carries no tenant address"
    assert bare.documents.report.path == base / S.FIXTURE_ID / "report.md"
    with pytest.raises(ValueError, match="runs base"):
        _ = bare.facts.scrub_verdict.path


def test_1105_open_run_opens_valid_ids_that_are_not_case_stable(tmp_path):
    """`open_run` returns a `Run` whose `run_dir` is `runs_base / run_id` for `run_id` `caseA`,
    `turnN-A` and `20260728T161745Z-fresh-case`, each an existing directory, under a base with no
    tenant record.
    """
    base = tmp_path / "runs"
    for run_id in S.O3_OPENS:
        S.make_run(base, run_id)
    for run_id in S.O3_OPENS:
        run = _open(base, run_id)
        assert _is_run(run), (run_id, run)
        assert run.run_dir == base / run_id, run_id
    assert not (base / S.TENANT_RECORD).exists()


def test_1105_open_run_refuses_unsafe_ids_with_plain_value_error(tmp_path):
    """for `run_id` `../x`, `has space`, `_bindtest`, `héllo`, `.hidden` and the empty string,
    `open_run` raises an exception `e` with `type(e) is ValueError`, never `TenantRecordCorrupt`,
    and returns no `Run`.

    Every name that CAN exist on disk exists, so the refusal is the id rule's and not the
    absence of a directory: `../x` names a real directory beside the base.
    """
    base = tmp_path / "runs"
    S.write_record(base)
    (tmp_path / "x").mkdir()
    for name in ("has space", "_bindtest", "héllo", ".hidden"):
        S.make_run(base, name)
    for run_id in ("../x", "has space", "_bindtest", "héllo", ".hidden", ""):
        e = S.refusal(lambda run_id=run_id: _open(base, run_id))
        assert type(e) is ValueError, (run_id, S.type_name(e), e)


def test_1105_open_run_refuses_a_bad_id_before_reading_a_corrupt_record(tmp_path):
    """under a base whose `tenant_record` (`_tenant.json`) is corrupt, `open_run(runs_base,
    "../x")` raises plain `ValueError` (`type(e) is ValueError`). The id check runs before the
    record is read. The positive control: the same base with a valid id raises
    `TenantRecordCorrupt`.
    """
    base = tmp_path / "runs"
    S.plant_bad_record(base, "corrupt", elsewhere=tmp_path / "elsewhere")
    (tmp_path / "x").mkdir()
    S.make_run(base, S.CASE_STABLE_ID)

    bad_id = S.refusal(lambda: _open(base, "../x"))
    assert type(bad_id) is ValueError, (S.type_name(bad_id), bad_id)

    control = S.refusal(lambda: _open(base, S.CASE_STABLE_ID))
    assert S.type_name(control) == "TenantRecordCorrupt", (S.type_name(control), control)


def test_1105_open_run_opens_under_a_base_with_no_tenant_record(tmp_path):
    """with no `tenant_record` under `runs_base`, `open_run` returns a `Run` for a case-stable
    id, built for `DEFAULT_TENANT_ID`, and writes no `_tenant.json`.
    """
    base = tmp_path / "runs"
    S.make_run(base, S.CASE_STABLE_ID)
    run = _open(base, S.CASE_STABLE_ID)
    assert _is_run(run), run
    assert run.tenant_id == S.DEFAULT_TENANT
    assert run.runs_base == base
    record = base / S.TENANT_RECORD
    assert not record.exists(), 'a READ minted a tenant record'
    assert not record.is_symlink(), 'a READ minted a tenant record'


def test_1105_open_run_refuses_a_present_record_that_is_corrupt_linked_a_directory_or_foreign(
        tmp_path):
    """`open_run` refuses whenever a `tenant_record` is present but bad: For a record that is
    invalid JSON, empty, a symlink to a valid record, a hard link to a valid record, a dangling
    symlink, or a directory at `_tenant.json`, it raises `TenantRecordCorrupt`. For a well-formed
    record naming a tenant other than `DEFAULT_TENANT_ID` (the `acme` alternative), it raises an
    exception `e` with `type(e) is ValueError`, not `TenantRecordCorrupt`. This holds for both
    case-stable and non-case-stable ids.
    """
    for shape, expected in S.BAD_RECORDS.items():
        base = tmp_path / shape / "runs"
        S.plant_bad_record(base, shape, elsewhere=tmp_path / shape / "elsewhere")
        S.make_run(base, S.CASE_STABLE_ID)
        S.make_run(base, S.FIXTURE_ID)
        for run_id in (S.CASE_STABLE_ID, S.FIXTURE_ID):
            e = S.refusal(lambda base=base, run_id=run_id: _open(base, run_id))
            assert S.type_name(e) == expected, (shape, run_id, S.type_name(e), e)
            if expected == S.FOREIGN:
                assert type(e) is ValueError, (shape, run_id, S.type_name(e))


def test_1105_open_run_does_not_refuse_a_case_stable_run_not_yet_on_disk(tmp_path):
    """`open_run` returns a `Run` for a case-stable `run_id` whose directory does not exist, and
    creates nothing. The positive control: a non-case-stable `run_id` whose directory does not
    exist raises `ValueError` (fork F1's pinned reading).
    """
    base = tmp_path / "runs"
    S.write_record(base)
    run = _open(base, S.CASE_STABLE_ID)
    assert _is_run(run), run
    assert run.run_dir == base / S.CASE_STABLE_ID
    assert not (base / S.CASE_STABLE_ID).exists(), "a read created the run directory"

    e = S.refusal(lambda: _open(base, S.FIXTURE_ID))
    assert isinstance(e, ValueError), (S.type_name(e), e)


def test_1105_open_run_reads_through_a_linked_runs_base_as_today(tmp_path):
    """when `runs_base` is a symlink to a real base directory, or has a linked ancestor,
    `open_run` reads the `tenant_record` through the link. It returns a `Run` for a valid record
    and raises `TenantRecordCorrupt` for a corrupt one, exactly as `read_tenant` does today
    (RG-1).
    """
    real = tmp_path / "real-base"
    S.write_record(real)
    S.make_run(real, S.CASE_STABLE_ID)
    S.make_run(real, S.FIXTURE_ID)
    linked = tmp_path / "linked-base"
    linked.symlink_to(real)
    (tmp_path / "real-ancestor").mkdir()
    ancestor = tmp_path / "linked-ancestor"
    ancestor.symlink_to(tmp_path / "real-ancestor")
    under = ancestor / "runs"
    S.write_record(under)
    S.make_run(under, S.CASE_STABLE_ID)

    for base in (linked, under):
        run = _open(base, S.CASE_STABLE_ID)
        assert _is_run(run), base
        assert run.run_dir == base / S.CASE_STABLE_ID
    assert _open(linked, S.FIXTURE_ID).run_dir == linked / S.FIXTURE_ID

    for base, real_dir in ((linked, real), (under, tmp_path / "real-ancestor" / "runs")):
        (real_dir / S.TENANT_RECORD).write_text("{not json", encoding="utf-8")
        e = S.refusal(lambda base=base: _open(base, S.CASE_STABLE_ID))
        assert S.type_name(e) == "TenantRecordCorrupt", (base, S.type_name(e), e)


# ---------------------------------------------------------------------------------------
# settled premises
# ---------------------------------------------------------------------------------------


def test_1105_open_run_non_case_stable_id_whose_directory_is_a_symlink(tmp_path):
    """`open_run(base, 'caseA')` where `caseA` is a symlink to a directory returns a `Run.at`
    handle through the link; the tracer reads through it as today (N-c keeps its follow walk; D4
    keeps its reader): the lesson rows behind the link are reported under `caseA`.
    """
    base = tmp_path / "runs"
    base.mkdir()
    target = S.make_run(tmp_path / "elsewhere", "real-case", lessons=["L1"])
    (base / S.FIXTURE_ID).symlink_to(target)

    run = _open(base, S.FIXTURE_ID)
    assert _is_run(run), run
    assert run.runs_base is None
    assert run.run_dir == base / S.FIXTURE_ID
    assert run.observability.lessons_loaded.read() is not None, "the handle did not follow"

    tracer = load_trace_lesson("trace_lesson_1105_p003")
    hits = tracer.in_context_cases("L1", None, base)
    assert [h.case_id for h in hits] == [S.FIXTURE_ID]


def test_1105_open_run_tenant_id_differs_only_by_case_or_whitespace(tmp_path):
    """A record whose `tenant_id` is `Default`, ` default` or `default ` (or `DEFAULT`) is refused
    and never normalized to the default tenant. The test pins `isinstance(e, ValueError)` for
    both a case-stable id and `caseA`; no `Run` is returned.
    """
    for i, spelling in enumerate(("Default", " default", "default ", "DEFAULT")):
        base = tmp_path / f"b{i}" / "runs"
        S.write_record(base, spelling)
        S.make_run(base, S.CASE_STABLE_ID)
        S.make_run(base, S.FIXTURE_ID)
        for run_id in (S.CASE_STABLE_ID, S.FIXTURE_ID):
            e = S.refusal(lambda base=base, run_id=run_id: _open(base, run_id))
            assert isinstance(e, ValueError), (spelling, run_id, S.type_name(e), e)


def test_1105_open_run_case_duplicate_siblings_on_one_base(tmp_path):
    """`Upper-Run` and `upper-run` both real: `list_run_ids` lists both; `open_run('Upper-Run')`
    is a `Run.at` handle on its own directory, `open_run('upper-run')` a `for_tenant` handle on
    its own; neither id affects the other (each report reads its own bytes).
    """
    base = tmp_path / "runs"
    S.write_record(base)
    S.make_run(base, "Upper-Run", report="upper\n")
    S.make_run(base, "upper-run", report="lower\n")

    assert {"Upper-Run", "upper-run"} <= set(S.sym("list_run_ids")(base))
    upper = _open(base, "Upper-Run")
    lower = _open(base, "upper-run")
    assert upper.run_dir == base / 'Upper-Run'
    assert upper.runs_base is None
    assert lower.run_dir == base / 'upper-run'
    assert lower.runs_base == base
    assert upper.documents.report.read() == "upper\n"
    assert lower.documents.report.read() == "lower\n"


def test_1105_runs_base_gains_its_first_tenant_record_after_older_runs(tmp_path):
    """Runs that predate a base's first tenant record are opened under that record from then on:
    with no record they open; once a default record appears they open as before; once the
    record is bad every one of them refuses (the check is per base, not per run).
    """
    base = tmp_path / "runs"
    older = (S.CASE_STABLE_ID, S.FIXTURE_ID, S.PRE_1077_ID)
    for run_id in older:
        S.make_run(base, run_id)
    for run_id in older:
        assert _is_run(_open(base, run_id)), run_id

    S.write_record(base)
    for run_id in older:
        assert _is_run(_open(base, run_id)), run_id

    (base / S.TENANT_RECORD).write_text("{not json", encoding="utf-8")
    for run_id in older:
        e = S.refusal(lambda run_id=run_id: _open(base, run_id))
        assert S.type_name(e) == "TenantRecordCorrupt", (run_id, S.type_name(e))


# ---------------------------------------------------------------------------------------
# §7 J4 — every refusal inside the ValueError family, never a raw OSError, never a fallback
# ---------------------------------------------------------------------------------------


_UNREADABLE_PROBE = """
    import json
    from pathlib import Path
    from defender.run_service import open_run
    out = []
    for base, run_id in json.loads(CELLS):
        try:
            got = open_run(Path(base), run_id)
            out.append([base, run_id, "returned", type(got).__name__, False, False])
        except Exception as e:
            out.append([base, run_id, "raised", type(e).__name__,
                        isinstance(e, ValueError), isinstance(e, OSError)])
    print(json.dumps(out))
"""


def test_1105_open_run_record_present_but_unreadable_by_permissions(tmp_path):
    """`open_run` refuses inside the `ValueError` family when it cannot read what it must read.
    For a `_tenant.json` with mode 000, and for a runs base the process cannot search (mode 444)
    with and without a record in it, `open_run` raises an exception `e` with
    `isinstance(e, ValueError)` for a case-stable id and for the non-case-stable `caseA`. It
    never raises a raw `OSError`, returns no `Run`, and never falls back to the default tenant.
    The reader is a non-root user, since root ignores the mode bits.
    """
    import json

    unreadable = tmp_path / "unreadable-record" / "runs"
    S.write_record(unreadable).chmod(0)
    with_record = tmp_path / "unsearchable-with-record" / "runs"
    S.write_record(with_record)
    without_record = tmp_path / "unsearchable-without-record" / "runs"
    for base in (unreadable, with_record, without_record):
        S.make_run(base, S.CASE_STABLE_ID)
        S.make_run(base, S.FIXTURE_ID)
    with_record.chmod(0o444)
    without_record.chmod(0o444)
    cells = [[str(b), rid] for b in (unreadable, with_record, without_record)
             for rid in (S.CASE_STABLE_ID, S.FIXTURE_ID)]
    with S.restoring_modes(unreadable / S.TENANT_RECORD, with_record, without_record):
        rows = S.unprivileged(_UNREADABLE_PROBE.replace("CELLS", repr(json.dumps(cells))),
                              cwd=tmp_path)
    assert len(rows) == len(cells), rows
    for base, run_id, outcome, cls, is_value_error, is_os_error in rows:
        assert outcome == "raised", (base, run_id, cls, "a Run was returned over an unreadable "
                                     "record — the default tenant was assumed")
        assert is_value_error, (base, run_id, cls)
        assert not is_os_error, (base, run_id, cls, "a raw OSError reached the caller")


def test_1105_open_run_tenant_record_field_wrong_json_type(tmp_path):
    """a `_tenant.json` that parses as a JSON object whose `tenant_id` is `null`, `1`, a list or
    an object makes `open_run` raise an exception `e` with `isinstance(e, ValueError)`, for a
    case-stable id and for `caseA`, and return no `Run`. The record is never read as naming the
    default tenant.
    """
    for i, wrong in enumerate((None, 1, ["default"], {"id": "default"})):
        base = tmp_path / f"t{i}" / "runs"
        S.write_record(base, wrong)
        S.make_run(base, S.CASE_STABLE_ID)
        S.make_run(base, S.FIXTURE_ID)
        for run_id in (S.CASE_STABLE_ID, S.FIXTURE_ID):
            e = S.refusal(lambda base=base, run_id=run_id: _open(base, run_id))
            assert isinstance(e, ValueError), (wrong, run_id, S.type_name(e), e)


def test_1105_reading_the_tenant_record_hits_a_filesystem_level_failure_unrelated_to_its_content(
        tmp_path):
    """when the read of a present `_tenant.json` fails with `EIO` (injected at the read, through
    the `io` seam `Run.for_tenant` and `read_tenant` already carry), `open_run` raises an
    exception `e` with `isinstance(e, ValueError)`, returns no `Run`, and does not fall back to
    the default tenant — for a case-stable id and for `caseA`.

    Tier 2: `EioOnRecord` answers the record's read with the `(None, <EIO strerror>)` pair the
    real `_io.read_guarded` returns for an EIO read (dep-PO14, executed at ed5386bc); it records
    the read was attempted, so a green here is the record read refusing, not a read skipped.
    """
    base = tmp_path / "runs"
    S.write_record(base)
    S.make_run(base, S.CASE_STABLE_ID)
    S.make_run(base, S.FIXTURE_ID)
    for run_id in (S.CASE_STABLE_ID, S.FIXTURE_ID):
        io = S.EioOnRecord()
        e = S.refusal(lambda run_id=run_id, io=io: S.sym("open_run")(base, run_id, io=io))
        assert isinstance(e, ValueError), (run_id, S.type_name(e), e)
        assert base / S.TENANT_RECORD in io.asked, (run_id, io.asked)
    assert os.strerror(errno.EIO) in S.EIO_REASON


def test_1105_open_run_id_longer_than_the_filesystem_name_limit(tmp_path):
    """for a run id longer than the filesystem's per-component name limit, both the case-stable
    `'a' * 300` and the non-case-stable `'A' + 'a' * 299`, `open_run` raises an exception `e` with
    `isinstance(e, ValueError)`, never a raw `OSError` (errno 36), and returns no `Run`.
    """
    base = tmp_path / "runs"
    S.write_record(base)
    for run_id in ("a" * 300, "A" + "a" * 299):
        e = S.refusal(lambda run_id=run_id: _open(base, run_id))
        assert isinstance(e, ValueError), (len(run_id), S.type_name(e), e)
        assert not isinstance(e, OSError), (len(run_id), S.type_name(e))


def test_1105_open_run_handed_a_run_id_that_is_not_a_str(tmp_path):
    """for a `run_id` of `Path('caseA')`, `b'caseA'`, `7` and `None`, `open_run` raises an
    exception `e` with `isinstance(e, ValueError)` and returns no `Run` — even though a directory
    `caseA` exists, so a coercion to text would have found one.
    """
    base = tmp_path / "runs"
    S.make_run(base, S.FIXTURE_ID)
    S.make_run(base, "7")
    for run_id in (Path(S.FIXTURE_ID), S.FIXTURE_ID.encode(), 7, None):
        e = S.refusal(lambda run_id=run_id: _open(base, run_id))
        assert isinstance(e, ValueError), (run_id, S.type_name(e), e)


# ---------------------------------------------------------------------------------------
# §7 J1 / J3 / F3 — D3 verbatim over entries that are not what the id implies
# ---------------------------------------------------------------------------------------


def test_1105_open_run_case_stable_id_naming_a_plain_file_on_the_runs_base(tmp_path):
    """for a case-stable id whose entry at `runs_base / id` is a regular file (another run's
    sidecar such as `x.run-end.json`) or a dangling symlink, `open_run` returns a `Run` without
    checking the directory (K6), and the migrated tracer over that base observes exactly what the
    base commit's tracer observes over the same path: the entry is not a run, no hit, no new
    wrapping and no new error type. The positive control: the same base's real run directory
    with a lessons file yields its row.
    """
    base = tmp_path / "runs"
    S.write_record(base)
    (base / "x.run-end.json").write_text("{}", encoding="utf-8")
    (base / "run-gone").symlink_to(tmp_path / "no-such-dir")
    S.make_run(base, "run-ok", lessons=["L1"])

    for entry in ("x.run-end.json", "run-gone"):
        run = _open(base, entry)
        assert _is_run(run), entry
        assert run.run_dir == base / entry
        assert run.observability.lessons_loaded.read() is None, entry

    tracer = load_trace_lesson("trace_lesson_1105_p001")
    assert [h.case_id for h in tracer.in_context_cases("L1", None, base)] == ["run-ok"]


def test_1105_open_run_runs_base_directory_itself_missing(tmp_path, monkeypatch):
    """when `runs_base` does not exist at all, `open_run` treats the tenant record as absent. It
    returns a `Run` built for `DEFAULT_TENANT_ID` for a case-stable id, raises an exception `e`
    with `isinstance(e, ValueError)` for the non-case-stable `caseA` (it needs an existing
    directory), and creates nothing. With `DEFENDER_RUNS_BASE` naming that missing directory,
    `host_env.resolve_runs_base()` returns the path unchanged and `open_run` over it behaves the
    same.
    """
    missing = tmp_path / "no-such" / "runs"
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(missing))
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "learn"))
    resolved = S.host_env().resolve_runs_base()
    assert resolved == missing
    for base in (missing, resolved):
        run = _open(base, S.CASE_STABLE_ID)
        assert _is_run(run), run
        assert run.tenant_id == S.DEFAULT_TENANT
        e = S.refusal(lambda base=base: _open(base, S.FIXTURE_ID))
        assert isinstance(e, ValueError), (S.type_name(e), e)
    assert not (tmp_path / "no-such").exists(), "a read created the runs base"


def test_1105_runs_base_holding_a_directory_named_like_a_sidecar(tmp_path):
    """`open_run` and `list_run_ids` apply today's id grammar with no reserved names. A run
    directory named `sessions` is listed and opens like any valid id. A directory named
    `ok-run.run-end.json` beside run `ok-run` is listed, and `open_run(runs_base, "ok-run")`'s
    run-end sidecar member resolves to that path. An id equal to another run's sidecar stem
    (`other-run.scrub-verdict`) opens. `Turn1-A` and `turn1-a`, two directories on the test's
    case-sensitive filesystem, each open to their own directory: no case-insensitive guard runs
    at read time.
    """
    base = tmp_path / "runs"
    S.write_record(base)
    names = ("sessions", "ok-run", "ok-run.run-end.json", "other-run.scrub-verdict",
             "Turn1-A", "turn1-a")
    for name in names:
        S.make_run(base, name)
    assert set(names) <= set(S.sym("list_run_ids")(base))

    assert _open(base, "sessions").run_dir == base / "sessions"
    assert _open(base, "ok-run").facts.run_end.path == base / "ok-run.run-end.json"
    assert _open(base, "other-run.scrub-verdict").run_dir == base / "other-run.scrub-verdict"
    assert _open(base, "Turn1-A").run_dir == base / "Turn1-A"
    assert _open(base, "turn1-a").run_dir == base / "turn1-a"
