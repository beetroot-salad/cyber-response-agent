"""#1105 D3 — the three walks the run service owns: `list_run_ids` (the tracer's follow walk,
O4.2), `bound_runs` (the judge's no-follow walk, moved unchanged, J8's listing) and `run_exists`
(the judge's collision probe, moved unchanged) — plus run SETUP's creation rule, which stays at
creation (`materialize_run_dir`, O3).

Every entry is planted for real: a symlinked run dir, a symlink loop, a dangling link, a mode-000
run dir read by a reader that obeys mode bits (`_spec1105.unprivileged`), a directory swapped for
a link between the listing and the read. No walk is faked.

Refuted claims respected (46-reground.md): a looping entry is SKIPPED by both walks, never an
ELOOP out of the listing (adv-PO6 refuted P012's reading); a mode-000 run dir is LISTED by both
walks — the judge counts it `skipped_unreadable` and the tracer raises `PermissionError` at its
lessons file (adv-PO6); a directory swapped for a link after the listing is still YIELDED from the
snapshot and refused only when read (J-PR2 refuted P055's recommendation text); after the walk a
kept `Bound` answers `Bad file descriptor` (author-P14 refuted P051's reading).

RED against ed5386bc: `defender.run_service` does not exist.
"""
from __future__ import annotations

import json
from pathlib import Path

from defender.tests import _spec1105 as S


def _list(base: Path) -> list[str]:
    return list(S.sym("list_run_ids")(base))


def _exists(base: Path, name) -> bool:
    return S.sym("run_exists")(base, name)


# ---------------------------------------------------------------------------------------
# list_run_ids
# ---------------------------------------------------------------------------------------


def test_1105_list_run_ids_returns_sorted_valid_directory_names(tmp_path):
    """over a base holding the directories `b-run`, `a-run` and `Upper-Run`, the invalid-name
    directories `has space`, `.hidden`, `_x` and `héllo`, a plain file `c-file` and
    `_tenant.json`, `list_run_ids(runs_base)` returns exactly `["Upper-Run", "a-run", "b-run"]` in
    sorted order.
    """
    base = tmp_path / "runs"
    for name in ("b-run", "a-run", "Upper-Run", *S.NEVER_IDS):
        S.make_run(base, name)
    (base / "c-file").write_text("not a run\n", encoding="utf-8")
    S.write_record(base)
    assert _list(base) == ["Upper-Run", "a-run", "b-run"]


def test_1105_list_run_ids_lists_a_symlinked_run_directory(tmp_path):
    """a validly named symlink under `runs_base` that points at a directory elsewhere appears in
    `list_run_ids(runs_base)`, because the listing follows links as the tracer's `is_dir()` walk
    does today; a real directory beside it is listed too.
    """
    base = tmp_path / "runs"
    S.make_run(base, "real-run")
    target = S.make_run(tmp_path / "elsewhere", "target")
    (base / "linked-run").symlink_to(target)
    assert _list(base) == ["linked-run", "real-run"]


def test_1105_list_run_ids_ignores_a_corrupt_record_that_open_run_refuses(tmp_path):
    """with a corrupt `tenant_record` present, `list_run_ids(runs_base)` returns the valid
    directory names without raising. The positive control: `open_run(runs_base, <one of those
    names>)` raises `TenantRecordCorrupt` — the record is corrupt, and only the listing ignores
    it.
    """
    base = tmp_path / "runs"
    S.plant_bad_record(base, "corrupt", elsewhere=tmp_path / "elsewhere")
    S.make_run(base, S.CASE_STABLE_ID)
    S.make_run(base, S.FIXTURE_ID)
    listed = _list(base)
    assert listed == sorted([S.CASE_STABLE_ID, S.FIXTURE_ID])
    for run_id in listed:
        e = S.refusal(lambda run_id=run_id: S.sym("open_run")(base, run_id))
        assert S.type_name(e) == "TenantRecordCorrupt", (run_id, S.type_name(e), e)


# ---------------------------------------------------------------------------------------
# bound_runs
# ---------------------------------------------------------------------------------------


def test_1105_bound_runs_yields_every_real_directory_without_id_filter_or_tenant_read(tmp_path):
    """over a base with a corrupt `tenant_record` and real directories named `ok-run`,
    `Upper-Run`, `has space`, `héllo`, `.hidden` and `_under`, `bound_runs(runs_base)` yields one
    `(run_id, Bound)` pair for each of the six directories. It raises nothing, and each `Bound`
    reads its own directory while the listing is open.
    """
    from defender._io import Bound

    base = tmp_path / "runs"
    S.plant_bad_record(base, "corrupt", elsewhere=tmp_path / "elsewhere")
    names = ("ok-run", "Upper-Run", "has space", "héllo", ".hidden", "_under")
    for name in names:
        S.make_run(base, name, report=f"{name}\n")
    seen: dict[str, str | None] = {}
    with S.sym("bound_runs")(base) as listing:
        for run_id, bound in listing:
            assert isinstance(bound, Bound), (run_id, bound)
            seen[run_id] = bound.read("report.md").text
    assert sorted(seen) == sorted(names)
    assert all(seen[n] == f"{n}\n" for n in names), seen


def test_1105_bound_runs_skips_a_linked_entry_and_yields_a_real_one(tmp_path):
    """a symlink entry under `runs_base` that points at a directory is not yielded by
    `bound_runs(runs_base)`. The positive control: a real directory beside it is yielded.
    """
    base = tmp_path / "runs"
    S.make_run(base, "real-run")
    target = S.make_run(tmp_path / "elsewhere", "target")
    (base / "linked-run").symlink_to(target)
    _listing, pairs = S.walk(base)
    assert [run_id for run_id, _b in pairs] == ["real-run"]


_ONE_PER_STATE = """
    import json
    from pathlib import Path
    from defender.run_service import bound_runs
    out = {}
    for label, base in json.loads(CASES).items():
        with bound_runs(Path(base)) as listing:
            pairs = [run_id for run_id, _b in listing]
            out[label] = {"absent": listing.absent, "reason": listing.reason, "pairs": pairs}
    print(json.dumps(out))
"""


def test_1105_bound_runs_consumer_keeps_a_bound_past_the_walk(tmp_path):
    """`bound_runs(runs_base)` returns a listing used as a context manager. Inside the `with`
    block it yields the `(run_id, Bound)` pairs, and it carries `absent` and `reason`:
    `runs_base_missing` for a base that does not exist (`absent` is true) and
    `runs_base_unreadable` for one that cannot be listed (`reason` names why), each with no
    pairs; a listable base is neither. A `Bound` kept past the block fails on read (`EBADF`),
    and leaving the block early, by `break` or by an exception, closes the bind at exit.
    """
    import errno
    import os

    base = tmp_path / "runs"
    S.make_run(base, "run-a", report="a\n")
    S.make_run(base, "run-b", report="b\n")
    bad_fd = os.strerror(errno.EBADF)

    listing, pairs = S.walk(base)
    assert listing.absent is False, listing.absent
    assert listing.reason is None, listing.reason
    assert [r for r, _b in pairs] == ["run-a", "run-b"]
    kept = dict(pairs)["run-a"].read("report.md")
    assert kept.text is None, kept
    assert kept.reason == bad_fd, kept

    with S.sym("bound_runs")(base) as early:
        for _run_id, bound in early:
            assert bound.read("report.md").text == "a\n", "the Bound reads while the block is open"
            held = bound
            break
    assert held.read("report.md").reason == bad_fd, "leaving by `break` left the bind open"

    class Boom(Exception):
        pass

    try:
        with S.sym("bound_runs")(base) as raising:
            for _run_id, bound in raising:
                held = bound
                raise Boom
    except Boom:
        pass
    assert held.read("report.md").reason == bad_fd, "leaving by an exception left the bind open"

    unlistable = tmp_path / "unlistable"
    unlistable.mkdir()
    S.make_run(unlistable, "run-x")
    unlistable.chmod(0)
    cases = {"missing": str(tmp_path / "no-such-base"), "unlistable": str(unlistable)}
    with S.restoring_modes(unlistable):
        got = S.unprivileged(_ONE_PER_STATE.replace("CASES", repr(json.dumps(cases))),
                             cwd=tmp_path)
    assert got['missing']['absent'] is True, got
    assert got['missing']['pairs'] == [], got
    assert got["unlistable"]["reason"], got
    assert got['unlistable']['absent'] is False, got
    assert got['unlistable']['pairs'] == [], got


# ---------------------------------------------------------------------------------------
# run_exists
# ---------------------------------------------------------------------------------------


def test_1105_run_exists_is_true_for_any_entry_including_a_dangling_link(tmp_path):
    """`run_exists(runs_base, name)` is `True` when a directory, a plain file, a symlink or a
    dangling symlink stands at `runs_base / name`, including a name that fails `is_valid_run_id`.
    It is `False` when nothing stands there. It raises nothing under a corrupt `tenant_record`.
    """
    base = tmp_path / "runs"
    S.plant_bad_record(base, "corrupt", elsewhere=tmp_path / "elsewhere")
    S.make_run(base, "a-dir")
    S.make_run(base, "has space")
    (base / "a-file").write_text("x", encoding="utf-8")
    (base / "a-link").symlink_to(base / "a-dir")
    (base / "a-dangling-link").symlink_to(tmp_path / "nowhere")
    for name in ("a-dir", "has space", "a-file", "a-link", "a-dangling-link"):
        assert _exists(base, name) is True, name
    assert _exists(base, "nothing-here") is False


def test_1105_run_exists_given_a_name_with_path_separators(tmp_path):
    """`run_exists(base, name)` composes `base / name` with no id rule, as today: a name with `/`,
    `..` or an absolute path probes outside the base — each answers whether something stands at
    the composed path. Its only caller (the judge's collision probe) validates the label first.
    """
    base = tmp_path / "runs"
    S.make_run(base, "a-run")
    (base / "a-run" / "inner").mkdir()
    (tmp_path / "outside").mkdir()
    absolute = tmp_path / "absolute-target"
    absolute.mkdir()
    assert _exists(base, "a-run/inner") is True
    assert _exists(base, "../outside") is True
    assert _exists(base, str(absolute)) is True
    assert _exists(base, "a-run/absent") is False
    assert _exists(base, "../no-such") is False


def test_1105_collision_probe_races_a_concurrent_materialize(tmp_path):
    """The collision probe racing another sibling's materialize is today's accepted TOCTOU:
    `run_exists` reports absent for an entry not yet created, and present once it is — the
    test pins "absent before creation", not a race.
    """
    base = tmp_path / "runs"
    base.mkdir()
    name = "20260728t161845z-fresh-case-n59-b"
    assert _exists(base, name) is False
    (base / name).mkdir()
    assert _exists(base, name) is True


# ---------------------------------------------------------------------------------------
# §7 F3 / J3 — the listing over a base that is not a readable directory, and odd entries
# ---------------------------------------------------------------------------------------

_UNLISTABLE_TRACER_WALK = """
    import json
    from pathlib import Path
    from defender.run_service import list_run_ids
    base = Path(BASE)
    def outcome(fn):
        try:
            return ["returned", repr(fn())]
        except Exception as e:
            return ["raised", type(e).__name__]
    # the base commit's tracer walk, verbatim (trace_lesson.py:135-136): the guard, then the walk
    today = outcome(lambda: [p.name for p in sorted(p for p in base.iterdir() if p.is_dir())]
                    if base.is_dir() else [])
    print(json.dumps({"today": today, "list_run_ids": outcome(lambda: list_run_ids(base))}))
"""


def test_1105_listing_a_runs_base_that_is_missing_a_file_or_unreadable(tmp_path):
    """`list_run_ids` returns `[]` for a runs base that does not exist and for one that is a
    regular file. For a base the process cannot list (mode 000, non-root reader) it does what
    the base commit's tracer walk (`runs_dir.is_dir()` guard, then the entry walk) does over the
    same base — measured in the same reader, side by side.
    """
    assert _list(tmp_path / "no-such-base") == []
    as_file = tmp_path / "base-is-a-file"
    as_file.write_text("x", encoding="utf-8")
    assert _list(as_file) == []

    unlistable = tmp_path / "unlistable"
    S.make_run(unlistable, "run-a")
    unlistable.chmod(0)
    with S.restoring_modes(unlistable):
        got = S.unprivileged(_UNLISTABLE_TRACER_WALK.replace("BASE", repr(str(unlistable))),
                             cwd=tmp_path)
    assert got["today"][0] == "raised", got
    assert got["list_run_ids"] == got["today"], got


_UNREADABLE_ENTRY = """
    import json
    from pathlib import Path
    from defender.run_service import bound_runs, list_run_ids
    from defender.learning.judge import render
    from defender.tests._by_path import load_trace_lesson
    base = Path(BASE)
    with bound_runs(base) as listing:
        bound = [run_id for run_id, _b in listing]
    _rows, notes = render.sibling_union(base, alert_id="A1", source_run_id=None)
    try:
        load_trace_lesson("trace_lesson_1105_p049").in_context_cases("L1", None, base)
        tracer = "returned"
    except Exception as e:
        tracer = type(e).__name__
    print(json.dumps({"listed": list_run_ids(base), "bound": bound,
                      "skipped_unreadable": notes["skipped_unreadable"], "tracer": tracer}))
"""


def test_1105_listing_a_base_with_a_symlink_loop_or_unreadable_entry(tmp_path):
    """over a base holding `run-a`, `run-b`, a self-referential symlink, a two-link cycle and a
    dangling link, `list_run_ids` and `bound_runs` list exactly `run-a` and `run-b`, and
    `run_exists` answers True for the dangling link. A mode-000 run directory is listed by both;
    the judge's sibling union counts it `skipped_unreadable`, and the tracer raises
    `PermissionError` at its lessons file, as at base. A directory listed and then swapped for a
    link before the bind is still yielded from the listing snapshot and refused when read.
    """
    base = tmp_path / "runs"
    for name in ("run-a", "run-b"):
        S.make_run(base, name, report="---\ndisposition: benign\n---\n# r\n")
        (base / name / "alert.json").write_text(json.dumps({"alert_id": "A1"}),
                                                encoding="utf-8")
    (base / "loop").symlink_to("loop")
    (base / "ping").symlink_to("pong")
    (base / "pong").symlink_to("ping")
    (base / "dangling").symlink_to("nowhere")
    assert _list(base) == ["run-a", "run-b"]
    assert [r for r, _b in S.walk(base)[1]] == ["run-a", "run-b"]
    assert _exists(base, "dangling") is True
    assert _exists(base, "loop") is True

    closed = tmp_path / "with-unreadable"
    S.make_run(closed, "run-open", lessons=["L1"])
    shut = S.make_run(closed, "run-shut", lessons=["L1"],
                      report="---\ndisposition: benign\n---\n# r\n")
    (shut / "alert.json").write_text(json.dumps({"alert_id": "A1"}), encoding="utf-8")
    shut.chmod(0)
    with S.restoring_modes(shut):
        got = S.unprivileged(_UNREADABLE_ENTRY.replace("BASE", repr(str(closed))),
                             cwd=tmp_path)
    assert got["listed"] == ["run-open", "run-shut"], got
    assert got["bound"] == ["run-open", "run-shut"], got
    assert got["skipped_unreadable"] >= 1, got
    assert got["tracer"] == "PermissionError", got

    elsewhere = S.make_run(tmp_path / "elsewhere", "swap-target", report="planted\n")
    with S.sym("bound_runs")(base) as listing:
        it = iter(listing)
        first, _b = next(it)
        assert first == "run-a"
        import shutil

        shutil.rmtree(base / "run-b")
        (base / "run-b").symlink_to(elsewhere)
        rest = list(it)
        assert [r for r, _b in rest] == ["run-b"], "the snapshot's name was not yielded"
        swapped = rest[0][1].read("report.md")
        assert swapped.text is None, 'a Bound read through a link swapped in after the listing must refuse, never follow'
        assert swapped.reason, 'a Bound read through a link swapped in after the listing must refuse, never follow'


# ---------------------------------------------------------------------------------------
# creation keeps the creation rule (O3)
# ---------------------------------------------------------------------------------------


def test_1105_materialize_run_dir_still_refuses_a_non_case_stable_id(tmp_path, monkeypatch):
    """`materialize_run_dir` refuses to create a run whose `run_id` is `caseA` (valid but not
    case-stable) and creates no directory for it. It still creates a run for the case-folded
    `casea`. Driven through `run.py`'s own `--run-id`, whose default `materialize` seam is the
    service's run setup.
    """
    import pytest

    base = tmp_path / "runs"
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(base))
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(tmp_path / "learn"))
    alert = tmp_path / "alert.json"
    alert.write_text(json.dumps({"alert_id": "A1"}), encoding="utf-8")
    run = S.run_py()
    reached = S.Recorder(result={"output": "", "requests": 0, "truncated_by": None})

    with pytest.raises(SystemExit) as refused:
        run.main([str(alert), "--run-id", S.FIXTURE_ID, "--no-learn"], lifecycle=reached,
                 visualize=lambda p: None, preflight=S.no_preflight)
    assert "case" in str(refused.value.code), refused.value.code
    assert not (base / S.FIXTURE_ID).exists()
    assert reached.calls == []

    rc = run.main([str(alert), "--run-id", "casea", "--no-learn"], lifecycle=reached,
                  visualize=lambda p: None, preflight=S.no_preflight)
    assert rc == 0
    assert (base / "casea").is_dir()
    assert [kw["run_dir"] for _a, kw in reached.calls] == [base / "casea"]
