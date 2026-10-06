"""#1105 PR 1 — run setup's new checks (D3.7, D2.1, D12, OP-2; MF-17 and MF-21; Open item 1).

Run setup (`run_common.materialize_run`, called once from `run._materialize_run`, the seam
`run.main` injects) gains, in this order:

  1. id admission: the `_tenant.json` collision guard first (as today), then `RunId.parse`
     (pinned) or `RunId.mint` (minted) in place of `refuse_bad_run_id` / `mint_run_id`, then the
     sidecar clause, staged shape included, for pinned and minted ids alike (D2.1, MF-21,
     RG-18-a) — refusals stay `sys.exit(str)`: the guard's own message, and `invalid run id: …`
     for the rest. A minted id's label is the alert's file stem, or its folder's name when the
     stem is `alert` (`run_common._alert_label`, unchanged);
  2. the runs-folder state (OP-2): a link (dangling or not) or a non-directory at the runs folder
     this branch uses — `tenant.runs`, or a sibling's episode `runs/` in PR 1 — raises
     `TenantRefused`, which `run.py` surfaces as `[run.py] …`, before anything is created or
     read inside it; an absent folder is created at step 3, as today;
  3. `guarded_mkdir` and `ensure_runs_base_record`, as today (a record naming another tenant
     refuses here, RG-1); a 200,000-deep `_tenant.json` refuses with `TenantRefused`, not
     today's raw `RecursionError` (Open item 1, a declared O5 change);
  4. the claimed-id check, for PINNED ids on the non-sibling branch only: it holds the runs
     folder with `_io.hold(runs_base, follow=False)` and reads `episode_sibling_ids` over its
     view; every refusal there is one stderr line naming the path (`sys.exit(str)`, MF-17);
  5. `Run.for_tenant`, then today's existing-folder handling (odd occupants keep today's
     outcome, RG-21-a).

Every input is real: the runs folder is a real link, the records are written by the writer or
planted by hand on disk, the deep record is a real 200,000-deep JSON. The claimed-id read is
observed with a `sys.setprofile` hook (the calls made, in order) — observation only.

Red at base 80888efb: no claimed-id check, no runs-folder refusal (a link is followed, R-151-a),
no `RunId` admission (ids of 207+ bytes and sidecar-named ids are admitted), and the deep
record raises `RecursionError` (RG-20-a). The tests that import the door (`record_episode_runs`,
`RunId`) fail there at their own import.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

from defender import _tenant
from defender import run as run_py
from defender import run_common
from defender.tests import _triplet_947 as T947
from defender.tests.tenant_1105_run_repository import _spec1105 as H


def _pinned(alert: Path, run_id: str | None, t, **kw):
    """Run setup itself (the function `run.py` calls): `materialize_run`."""
    return run_common.materialize_run(alert, run_id, tenant=t, **kw)


def _via_run_py(alert: Path, run_id: str | None, t, **kw):
    """Run setup through `run.py`'s single call site, which surfaces a `TenantRefused` as
    `sys.exit("[run.py] …")`."""
    return run_py._materialize_run(alert, run_id, tenant=t, model=None, **kw)


def _one_line_exit(err: BaseException | None) -> bool:
    """A `sys.exit(str)` refusal: one stderr line, no traceback."""
    return (isinstance(err, SystemExit) and isinstance(err.code, str)
            and len(err.code.splitlines()) == 1)


class _Calls:
    """The calls run setup makes, in order, observed with `sys.setprofile` (an observation
    hook; it alters nothing): `hold` (with its `root` and `follow`), `episode_sibling_ids`,
    `for_tenant`."""

    WATCHED = ("hold", "episode_sibling_ids", "for_tenant")

    def __init__(self) -> None:
        self.seen: list[tuple[str, object, object]] = []

    def __call__(self, frame, event, _arg):
        if event != "call":
            return
        name = frame.f_code.co_name
        if name in self.WATCHED:
            loc = frame.f_locals
            self.seen.append((name, loc.get("root"), loc.get("follow")))

    def run(self, fn, *args, **kwargs):
        previous = sys.getprofile()
        sys.setprofile(self)
        try:
            return H.raised(fn, *args, **kwargs)
        finally:
            sys.setprofile(previous)

    def names(self) -> list[str]:
        return [n for n, _r, _f in self.seen]


def _link_runs_to(t, outside: Path) -> None:
    """`t.runs` as a link to a real folder elsewhere (another tenant's, say)."""
    outside.mkdir(parents=True, exist_ok=True)
    Path(t.runs).parent.mkdir(parents=True, exist_ok=True)
    os.symlink(outside, t.runs)


def test_1105_run_setup_refuses_a_pinned_id_a_record_claims_and_creates_no_run_folder(
        tmp_path, data_root):
    """Run setup for a pinned run id that a record in tenant.runs/_episodes claims (written by
    record_episode_runs in the test) exits with a str refusal, leaves the runs folder and
    _tenant.json in place, and creates no run folder. Positive control: an unclaimed pinned id
    runs."""
    from defender.run_repository import RunId, record_episode_runs

    t = H.tenant(data_root, H.T_ID)
    runs = H.runs_folder(t)
    record_episode_runs(t, "ep1", RunId.parse("src1"), {"a": RunId.parse("ep1-a")})
    assert (runs / "_episodes" / "ep1.json").is_file(), "the writer recorded the episode"
    alert = H.alert_file(tmp_path / "in")
    before = H.tree_state(runs)
    err = H.raised(_pinned, alert, "ep1-a", t)
    assert _one_line_exit(err), f"a claimed pinned id was not refused by sys.exit(str): {err!r}"
    assert "ep1-a" in H.message(err), f"the refusal names the claimed id: {H.message(err)!r}"
    assert not os.path.lexists(runs / "ep1-a"), "a run folder was created for a claimed id"
    assert H.tree_state(runs) == before, "the runs folder or its _tenant.json changed"
    run = _pinned(alert, "r9", t)
    assert run.run_dir == runs / "r9", f"an unclaimed pinned id runs: {run.run_dir}"
    assert (runs / "r9").is_dir(), "the unclaimed pinned id's run folder exists"


def test_1105_a_corrupt_episode_record_refuses_every_pinned_id_and_never_a_minted_one(
        tmp_path, data_root):
    """With a truncated record in tenant.runs/_episodes, run setup refuses every pinned id, an
    unclaimed one included, with one stderr line naming that record (sys.exit(str), no
    traceback); a minted id (no pinned id given) still runs, because minted ids are not
    checked."""
    t = H.tenant(data_root, H.T_ID)
    runs = H.runs_folder(t)
    good = H.record_text("ep1", t.id, "src1", {"a": "ep1-a"})
    record = H.plant_record(runs, "ep1", t.id, "src1", {"a": "ep1-a"}, raw=H.truncated(good))
    alert = H.alert_file(tmp_path / "in")
    for pinned in ("ep1-a", "r-unclaimed"):
        err = H.raised(_pinned, alert, pinned, t)
        assert _one_line_exit(err), f"pinned {pinned!r} over a torn record gave {err!r}"
        assert "ep1.json" in H.message(err), (
            f"the refusal names the corrupt record {record}: {H.message(err)!r}")
        assert not os.path.lexists(runs / pinned), f"a run folder {pinned!r} was created"
    minted = _pinned(alert, None, t)
    assert Path(minted.run_dir).parent == runs, (
        f"a minted id is not checked against the records and still runs: {minted.run_dir}")
    assert Path(minted.run_dir).is_dir(), "the minted run's folder exists"


def test_1105_run_setup_refuses_a_pinned_id_a_record_naming_another_tenant_claims(
        tmp_path, data_root):
    """A record planted in T's _episodes/ that names another tenant still claims its ids at run
    setup: a pinned id it claims is refused (the fail-safe direction). Positive control: a
    pinned id it does not claim runs."""
    t = H.tenant(data_root, H.T_ID)
    runs = H.runs_folder(t)
    H.plant_record(runs, "ep1", H.U_ID, "src1", {"a": "ep1-a"})
    alert = H.alert_file(tmp_path / "in")
    err = H.raised(_pinned, alert, "ep1-a", t)
    assert _one_line_exit(err), f"a pinned id a foreign record claims was not refused: {err!r}"
    assert "ep1-a" in H.message(err), f"the refusal names the id: {H.message(err)!r}"
    assert not os.path.lexists(runs / "ep1-a"), "a run folder was created for a claimed id"
    assert _pinned(alert, "ep1-b", t).run_dir == runs / "ep1-b", "an unclaimed pinned id runs"


def test_1105_run_setup_admits_the_id_then_checks_the_folder_then_the_record_then_the_claims(
        tmp_path, data_root):
    """Run setup refuses in order: '_tenant.json' as a pinned id gets the collision guard's own
    message; a bad id over a linked runs folder gets 'invalid run id: ...' and nothing is
    created; a linked runs folder gets TenantRefused ('[run.py] ...') with nothing created
    through the link; a foreign _tenant.json with a pinned id a record claims gets TenantRefused
    at the record step before _episodes is read; a claimed pinned id is refused, through the
    claimed-id read over a no-follow hold of the runs folder, before Run.for_tenant and any run
    folder."""
    alert = H.alert_file(tmp_path / "in")
    t = H.tenant(data_root, H.T_ID)
    outside = tmp_path / "elsewhere"
    _link_runs_to(t, outside)
    # 1. id admission comes first: over a linked runs folder, the id refusals fire.
    collision = str(_tenant.refuse_colliding_run_id("_tenant.json"))
    err = H.raised(_via_run_py, alert, "_tenant.json", t)
    assert H.message(err) == collision, f"the collision guard's own message, got {err!r}"
    err = H.raised(_via_run_py, alert, "Bad Name", t)
    assert H.message(err).startswith("invalid run id: "), f"a bad id gave {err!r}"
    assert H.tree_state(outside) == {}, "an id refusal created something through the link"
    # 2. the runs-folder state, before the record and the claims.
    err = H.raised(_via_run_py, alert, "r1", t)
    assert H.message(err).startswith("[run.py] "), f"a linked runs folder gave {err!r}"
    assert H.tree_state(outside) == {}, "run setup created something through a linked runs folder"
    os.unlink(t.runs)
    # 3. the tenant record, before `_episodes` is read: a stray name there would refuse
    #    differently, so a TenantRefused proves the order.
    runs = Path(t.runs)
    H.plant_tenant_record(runs, H.U_ID)
    H.plant_record(runs, "ep1", t.id, "src1", {"a": "ep1-a"})
    (runs / "_episodes" / "README").write_text("stray\n", encoding="utf-8")
    err = H.raised(_pinned, alert, "ep1-a", t)
    assert isinstance(err, _tenant.TenantRefused), (
        f"a foreign _tenant.json did not refuse at the record step first: {err!r}")
    assert "_tenant.json" in str(err), f"the record step's refusal names the record: {err!r}"
    # 4. the claimed-id read, over a no-follow hold, before Run.for_tenant and any run folder.
    (runs / "_episodes" / "README").unlink()
    H.plant_tenant_record(runs, t.id)
    calls = _Calls()
    err = calls.run(_pinned, alert, "ep1-a", t)
    assert _one_line_exit(err), f"a claimed pinned id was not refused: {err!r}"
    nofollow = [i for i, (n, root, follow) in enumerate(calls.seen)
                if n == "hold" and follow is False and Path(str(root)) == runs]
    assert nofollow, f"the claimed-id read held no no-follow handle on {runs}: {calls.seen}"
    assert "episode_sibling_ids" in calls.names()[nofollow[0]:], (
        f"episode_sibling_ids did not read the held folder: {calls.names()}")
    assert "for_tenant" not in calls.names(), (
        f"Run.for_tenant ran before the claimed-id refusal: {calls.names()}")
    assert not os.path.lexists(runs / "ep1-a"), "a run folder was created for a claimed id"


def test_1105_run_setup_refuses_a_pinned_or_minted_id_over_206_bytes_with_the_invalid_run_id_exit(
        tmp_path, data_root):
    """Run setup runs a pinned 206-byte id, and exits 'invalid run id: ...' before creating
    anything for a pinned id of 207, 231 and 256 bytes and for an id minted from an alert
    label of 190 ASCII characters or of 95 x 'ß'; an alert labelled 94 x 'ß' mints a 205-byte
    id and runs."""
    t = H.tenant(data_root, H.T_ID)
    runs = Path(t.runs)
    alert = H.alert_file(tmp_path / "in")
    for n in (207, 231, 256):
        err = H.raised(_pinned, alert, "r" + "1" * (n - 1), t)
        assert H.message(err).startswith("invalid run id: "), (
            f"a pinned {n}-byte id gave {err!r}, not the invalid-run-id exit")
        assert not os.path.lexists(runs), f"a {n}-byte id created {runs} before refusing"
    for label in ("a" * 190, "ß" * 95):
        labelled = H.alert_file(tmp_path / f"in-{len(label)}-{label[0]}", f"{label}.json")
        err = H.raised(_pinned, labelled, None, t)
        assert H.message(err).startswith("invalid run id: "), (
            f"a minted id from {len(label)} x {label[0]!r} gave {err!r}")
        assert not os.path.lexists(runs), "a refused minted id created the runs folder"
    pinned = _pinned(alert, "r" + "1" * 205, t)
    assert pinned.run_dir == runs / ("r" + "1" * 205), f"a pinned 206-byte id runs: {pinned!r}"
    assert Path(pinned.run_dir).is_dir(), "the 206-byte run's folder exists"
    folded = _pinned(H.alert_file(tmp_path / "in-94", f"{'ß' * 94}.json"), None, t)
    name = Path(folded.run_dir).name
    assert name.endswith("ss" * 94), f"94 x 'ß' mints the folded label: {name!r}"
    assert len(name.encode()) == 205, f"94 x 'ß' mints a 205-byte id: {name!r}"


def test_1105_run_setup_refuses_a_sidecar_suffixed_pinned_or_minted_id(tmp_path, data_root):
    """Run setup exits 'invalid run id: ...' for a pinned id ending in each sidecar suffix and
    for a pinned id of the staged shape ('r1.run-end.json.staged-0123456789abcdef'), and for a
    minted id that ends in a sidecar suffix: run setup mints from the alert's file stem, or from
    its folder's name when the stem is 'alert' (run_common._alert_label, unchanged), so an alert
    'x.run-end.json.txt' mints '<stamp>-x.run-end.json' (RG-18-a) and an 'alert.json' in a
    folder 'y.scrub-verdict.json' mints '<stamp>-y.scrub-verdict.json'. No folder named like a
    sidecar or a staged sidecar is created, and a refused minted id creates nothing (today both
    are created, RG-13-b, RG-18-a). Positive control: the plain id r1 runs."""
    t = H.tenant(data_root, H.T_ID)
    runs = Path(t.runs)
    alert = H.alert_file(tmp_path / "in")
    names = [f"r1{s}" for s in H.SIDECAR_SUFFIXES] + [f"r1.run-end.json{H.STAGED_TAIL}"]
    for name in names:
        err = H.raised(_pinned, alert, name, t)
        assert H.message(err).startswith("invalid run id: "), f"pinned {name!r} gave {err!r}"
        assert not os.path.lexists(runs / name), f"a folder named {name!r} was created"
    for minted_from in (H.alert_file(tmp_path / "in-stem", "x.run-end.json.txt"),
                        H.alert_file(tmp_path / "y.scrub-verdict.json")):
        err = H.raised(_pinned, minted_from, None, t)
        assert H.message(err).startswith("invalid run id: "), (
            f"a minted id from {minted_from.relative_to(tmp_path)} ends in a sidecar suffix and "
            f"was not refused: {err!r}")
        assert not os.path.lexists(runs), (
            f"a refused minted id from {minted_from.name} created {runs}: "
            f"{sorted(os.listdir(runs)) if os.path.isdir(runs) else 'a non-directory'}")
    assert _pinned(alert, "r1", t).run_dir == runs / "r1", "the plain id r1 runs"


def test_1105_run_setup_refuses_a_linked_runs_folder_before_creating_anything(
        tmp_path, data_root):
    """When tenant.runs is a link to an outside folder, and when a sibling's episode runs/
    (materialize_run(world=...)) is a link, run setup raises TenantRefused, which run.py prints
    as '[run.py] ...', before creating or reading anything inside it: the outside folder stays
    empty and no raw OSError escapes. Positive control: an absent tenant.runs is created with
    its _tenant.json and the run. The link is P2's one representative state of the runs folder;
    a dangling link and a non-directory there are not driven here: _io.hold(follow=False) tells
    those states apart (test_1105_hold_follow_false_refuses_a_link_root_and_tells_the_states_apart).
    The tenant.runs arm is driven through run.main itself."""
    from defender._episode_handle import Episode

    alert = H.alert_file(tmp_path / "in")
    t = H.tenant(data_root, H.T_ID)
    outside = tmp_path / "outside"
    _link_runs_to(t, outside)
    lifecycles: list[object] = []
    err = H.raised(run_py.main, [str(alert), "--tenant", t.id, "--run-id", "r1", "--no-learn"],
                   preflight=lambda _model: 0,
                   lifecycle=lambda **kw: lifecycles.append(kw) or {},
                   visualize=lambda _run, **_kw: None)
    assert H.message(err).startswith("[run.py] "), (
        f"run.main over a linked tenant.runs did not exit '[run.py] …': {err!r}")
    assert not isinstance(err, OSError), f"a raw OSError escaped: {err!r}"
    assert H.tree_state(outside) == {}, "run setup wrote through the linked runs folder"
    assert lifecycles == [], "the run went on past a refused runs folder"
    err = H.raised(_pinned, alert, "r1", t)
    assert isinstance(err, _tenant.TenantRefused), f"materialize_run raised {err!r}"
    os.unlink(t.runs)

    episode_outside = tmp_path / "episode-outside"
    episode_outside.mkdir()
    ep = T947.episode(tmp_path / "eps")
    with Episode.open(ep) as episode:
        world = run_py.resume_world(episode, "b", tenant=lambda: None)
    os.symlink(episode_outside, Path(world.episode_dir) / "runs")
    err = H.raised(_via_run_py, alert, world.run_id, t, world=world)
    assert H.message(err).startswith("[run.py] "), f"a linked episode runs/ gave {err!r}"
    assert H.tree_state(episode_outside) == {}, "a sibling's setup wrote through the link"

    run = _pinned(alert, "r1", t)
    assert run.run_dir == Path(t.runs) / "r1", f"an absent runs folder is created: {run!r}"
    assert Path(t.runs).is_dir(), "the absent runs folder was created as a real directory"
    assert (Path(t.runs) / "_tenant.json").is_file(), "the runs folder's record was written"


def test_1105_run_setups_refusals_are_one_stderr_line_naming_the_path(tmp_path, data_root):
    """Every claimed-id refusal at run setup exits through sys.exit(str): one stderr line naming
    the path, no traceback, for a truncated record and for a stray name in _episodes; the hold's
    own refusal of a linked runs folder is TenantRefused shown as '[run.py] ...'; 'invalid run
    id: ...' carries RunId's repr-quoted refusal. Odd occupants at a pinned id's name keep
    today's outcome (RG-21-a): a regular file exits '<runs>/r1 is not a directory — refusing to
    materialise a run over it', an empty directory proceeds, and a directory holding
    investigation.md exits 'run dir already exists and a run has been in it: ...'."""
    from defender.run_repository import RunId

    alert = H.alert_file(tmp_path / "in")
    t = H.tenant(data_root, H.T_ID)
    runs = H.runs_folder(t)
    good = H.record_text("ep1", t.id, "src1", {"a": "ep1-a"})
    torn = H.plant_record(runs, "ep1", t.id, "src1", {}, raw=H.truncated(good))
    err = H.raised(_pinned, alert, "r2", t)
    assert _one_line_exit(err), f"a torn record's refusal is not one stderr line: {err!r}"
    assert str(torn) in H.message(err), f"the refusal names {torn}: {H.message(err)!r}"
    torn.unlink()
    stray = runs / "_episodes" / "README"
    stray.write_text("stray\n", encoding="utf-8")
    err = H.raised(_pinned, alert, "r2", t)
    assert _one_line_exit(err), f"a stray name's refusal is not one stderr line: {err!r}"
    assert str(stray) in H.message(err), f"the refusal names {stray}: {H.message(err)!r}"
    stray.unlink()

    bad = "Bad\nName"
    refusal = H.raised(RunId.parse, bad)
    err = H.raised(_pinned, alert, bad, t)
    assert H.message(err) == f"invalid run id: {refusal}", (
        f"the invalid-run-id exit does not carry RunId's refusal {refusal!r}: {err!r}")
    assert _one_line_exit(err), f"the invalid-run-id exit is one stderr line: {err!r}"
    assert repr(bad) in H.message(err), f"the bad id is repr-quoted: {H.message(err)!r}"

    (runs / "r1").write_text("not a run\n", encoding="utf-8")
    err = H.raised(_pinned, alert, "r1", t)
    assert H.message(err) == (f"{runs / 'r1'} is not a directory — refusing to materialise a "
                              "run over it"), f"a file at the run's name gave {err!r}"
    (runs / "r3").mkdir()
    assert _pinned(alert, "r3", t).run_dir == runs / "r3", "an empty directory proceeds"
    (runs / "r4").mkdir()
    (runs / "r4" / "investigation.md").write_text("+ ran\n", encoding="utf-8")
    err = H.raised(_pinned, alert, "r4", t)
    assert H.message(err).startswith(
        f"run dir already exists and a run has been in it: {runs / 'r4'}"), f"got {err!r}"

    os.rename(runs, tmp_path / "moved-runs")
    os.symlink(tmp_path / "moved-runs", runs)
    err = H.raised(_via_run_py, alert, "r5", t)
    assert H.message(err).startswith("[run.py] "), (
        f"the hold's refusal of a linked runs folder is not '[run.py] …': {err!r}")
    assert str(runs) in H.message(err), f"the refusal names {runs}: {H.message(err)!r}"
    plain = H.raised(_pinned, alert, "r5", t)
    assert isinstance(plain, _tenant.TenantRefused), f"the hold's refusal type: {plain!r}"


def test_1105_run_setup_over_a_deeply_nested_tenant_record_refuses_as_tenant_refused(
        tmp_path, data_root):
    """Run setup over a tenant runs folder whose _tenant.json nests 200,000 levels deep exits
    '[run.py] ...' with TenantRefused, not a raw RecursionError (today's value, RG-20-a), and
    creates no run folder: ensure_runs_base_record's read-back uses the nesting-checked decoder
    (_tenant.py:218). A declared O5 change."""
    alert = H.alert_file(tmp_path / "in")
    t = H.tenant(data_root, H.T_ID)
    record = H.plant_tenant_record(t.runs, t.id, raw=H.deep_json())
    err = H.raised(_pinned, alert, "r1", t)
    assert isinstance(err, _tenant.TenantRefused), (
        f"a 200,000-deep _tenant.json raised {type(err).__name__}, not TenantRefused")
    assert "_tenant.json" in str(err), f"the refusal names the record {record}: {err!r}"
    err = H.raised(_via_run_py, alert, "r1", t)
    assert H.message(err).startswith("[run.py] "), f"run.py surfaced {err!r}"
    assert not os.path.lexists(Path(t.runs) / "r1"), "a run folder was created"
