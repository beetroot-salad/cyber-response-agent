"""#1347 O1/O7/D9: capture is ordered, holds the fault until as_of, and is all-or-nothing.

Entry point bound by this contract: `playground-v2/scripts/capture_case.py::capture(case_dir,
*, scenario, chaos, ops, lock_store, parts_dir, clock, history_start, seed=42, settle_s=...)`.
The lab operations are `ops` methods: fire(scenario, chaos, seed, lock_token) -> {"ledger_ref"};
wait_alert(fired) -> alert doc; proc_tree(dest), stub_dumps(dest), commit_hosts(dest, as_of),
copy_volumes(dest) each write part files under `dest` and return their names; revert(ledger_ref);
es_now(); refresh(); fingerprint(window, as_of, arrived_by). `clock` offers sleep_until(moment)
and sleep(seconds). The lock is taken through `chaos.lock` on `lock_store`; parts go under
`parts_dir/<case_dir.name>/`. Writes `case_dir/freeze.yaml`.

Production ops (FR1): `playground-v2/scripts/lab_ops.py::LabOps` implements `es_now()` and
`fingerprint(window, as_of, arrived_by)` (tested in test_1347_lab_ops.py) and is what
`capture_case.py` binds as its default `ops` fingerprint/clock implementation (`capture_case.LabOps`).
Nothing is injected for these: when the passed `ops` lacks `fingerprint` / `es_now`, the script
builds its module-level `LabOps(...)` and uses that for those methods.

O8 report: `capture` prints (stdout) and/or returns a report that names each fingerprinted index
(the part of a fingerprint key before `|`) with its total document count, the window bounds, and
the name of each stored part. The exact format is unpinned.
"""
from __future__ import annotations

import importlib.util
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
import yaml
from _lab_fakes import (ALERT_AT, ES_NOW, FINGERPRINT, PART_BYTES, FakeCaptureOps, FakeClock,
                        FakeLockStore, Journal, instant, sha)

CAPTURE = Path(__file__).resolve().parents[1] / "capture_case.py"
SLUG = "m05-lsass-access"
HISTORY_START = "2026-08-01T00:00:00Z"
STAGES = ["fire", "wait_alert", "wait_as_of", "proc_tree", "stub_dumps", "commit_hosts",
          "copy_volumes", "revert", "settle", "es_now", "refresh", "fingerprint"]


def _module():
    spec = importlib.util.spec_from_file_location("capture_1347", CAPTURE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Rig:
    def __init__(self, tmp_path: Path, fail_at: str | None = None, chaos: str = "stale-cmdb",
                 history_start: str = HISTORY_START, alert_at_ledger: str | None = "chaos-abc123",
                 fingerprint: dict | None = None, exc: type[BaseException] = RuntimeError):
        self.journal = Journal()
        self.store = FakeLockStore(self.journal)
        stages = (fail_at,) if isinstance(fail_at, str) else tuple(fail_at or ())
        self.record_at_fire: str | None = None
        self.held_at_revert: list[bool] = []
        self.clock = FakeClock(self.journal, exc=exc,
                               fail_at=next((s for s in stages if s in ("wait_as_of", "settle")), None))
        self.ops = FakeCaptureOps(self.journal, fail_at=stages, ledger_ref=alert_at_ledger if chaos != "none" else None,
                                 fingerprint_result=fingerprint, exc=exc, on_step=self._watch)
        self.case_dir = tmp_path / "held-out" / SLUG
        self.case_dir.mkdir(parents=True)
        self.parts_dir = tmp_path / "parts"
        (self.parts_dir / "other-case").mkdir(parents=True)
        (self.parts_dir / "other-case" / "keep.bin").write_bytes(b"keep")
        self.chaos, self.history_start = chaos, history_start

    def _watch(self, step: str) -> None:
        if step == "fire":
            self.record_at_fire = self.store.records.get("capture")
        if step == "revert":
            self.held_at_revert.append("capture" in self.store.records)

    def run(self):
        self.result = _module().capture(self.case_dir, scenario="ssh-brute-force-canary", chaos=self.chaos,
                          ops=self.ops, lock_store=self.store, parts_dir=self.parts_dir,
                          clock=self.clock, history_start=self.history_start)

    @property
    def freeze(self) -> dict:
        return yaml.safe_load((self.case_dir / "freeze.yaml").read_text())


def _pos(journal: Journal, op: str) -> int:
    return journal.ops().index(op)


def test_capture_runs_its_steps_in_the_designed_order(tmp_path):
    """O1/O7: fault held through the as_of snapshot (proc-tree and stub dumps first, then
    commits and volume copies), then revert, settle, ES clock, refresh, fingerprint."""
    rig = Rig(tmp_path)
    rig.run()
    ops = rig.journal.ops()
    order = ["lock.create", "fire", "wait_alert", "clock.sleep_until"]
    snaps_first, snaps_then = ["proc_tree", "stub_dumps"], ["commit_hosts", "copy_volumes"]
    tail = ["revert", "clock.sleep", "es_now", "refresh", "fingerprint", "lock.delete"]
    firsts = [ops.index(o) for o in order]
    assert firsts == sorted(firsts)
    assert ops.index("clock.sleep_until") < min(ops.index(o) for o in snaps_first)
    assert max(ops.index(o) for o in snaps_first) < min(ops.index(o) for o in snaps_then)
    assert max(ops.index(o) for o in snaps_then) < ops.index("revert")
    tails = [ops.index(o) for o in tail]
    assert tails == sorted(tails)


def test_capture_waits_for_as_of_and_fires_under_the_lock_token(tmp_path):
    """O7/D14: it sleeps until alert_at + 1 h, and the scenario is fired with the stored token."""
    rig = Rig(tmp_path)
    rig.run()
    waited = [d for op, d in rig.journal if op == "clock.sleep_until"]
    assert [instant(w) for w in waited] == [instant(ALERT_AT) + timedelta(hours=1)]
    token = rig.ops.fire_kwargs["lock_token"]
    assert token and rig.record_at_fire and token in rig.record_at_fire, "not fired under the lock"
    assert rig.ops.fire_kwargs["chaos"] == "stale-cmdb"
    assert "capture" not in rig.store.records, "the lock was not released"


def test_capture_settles_before_reading_the_elasticsearch_clock(tmp_path):
    """O1: a positive settle sleep sits between revert and the ES clock read."""
    rig = Rig(tmp_path)
    rig.run()
    sleeps = [(i, d) for i, (op, d) in enumerate(rig.journal) if op == "clock.sleep"]
    assert len(sleeps) == 1 and sleeps[0][1] > 0
    assert _pos(rig.journal, "revert") < sleeps[0][0] < _pos(rig.journal, "es_now")


def test_a_chaos_free_capture_never_calls_revert(tmp_path):
    """O7 control: with no chaos profile there is no fault to revert."""
    rig = Rig(tmp_path, chaos="none")
    rig.run()
    assert "revert" not in rig.journal.ops()
    assert rig.freeze["chaos"] is None


def test_freeze_yaml_records_times_window_and_clock_read_from_elasticsearch(tmp_path):
    """Data model: as_of = alert_at + 1 h, captured_at is ES's reading, times are quoted strings."""
    rig = Rig(tmp_path)
    rig.run()
    f = rig.freeze
    assert instant(f["alert_at"]) == instant(ALERT_AT)
    assert instant(f["as_of"]) == instant(ALERT_AT) + timedelta(hours=1)
    assert instant(f["captured_at"]) == instant(ES_NOW)
    assert all(isinstance(f[k], str) for k in ("alert_at", "as_of", "captured_at"))
    assert f["fingerprint"] == FINGERPRINT
    kw = rig.ops.fingerprint_kwargs
    assert instant(kw["arrived_by"]) == instant(ES_NOW) and instant(kw["as_of"]) == instant(f["as_of"])


@pytest.mark.parametrize(("history_start", "lower"), [
    ("2026-08-01T00:00:00Z", "2026-09-19T08:00:00Z"),   # alert - 31 d is later: it wins
    ("2026-10-10T00:00:00Z", "2026-10-10T00:00:00Z"),   # history starts later: it wins
], ids=["alert-minus-31d", "history-start"])
def test_the_window_starts_at_the_later_of_history_start_and_alert_minus_31_days(
        tmp_path, history_start, lower):
    """D1: window = [max(history_start, alert_at - 31 d), as_of]."""
    rig = Rig(tmp_path, history_start=history_start)
    rig.run()
    start, end = rig.freeze["window"]
    assert instant(start) == instant(lower) and instant(end) == instant(rig.freeze["as_of"])
    assert [instant(x) for x in rig.ops.fingerprint_kwargs["window"]] == [instant(start), instant(end)]


def test_parts_are_named_by_sha256_and_their_bytes_sit_under_the_parts_dir(tmp_path):
    """D8: each part is listed by name and sha256 and stored under parts_dir/<case>/."""
    rig = Rig(tmp_path)
    rig.run()
    parts = {name: str(d).removeprefix("sha256:") for name, d in rig.freeze["parts"].items()}
    assert parts == {name: sha(b) for name, b in PART_BYTES.items()}
    for name, data in PART_BYTES.items():
        assert (rig.parts_dir / SLUG / name).read_bytes() == data


def test_capture_leaves_confirmation_empty_and_records_the_chaos_ledger_ref(tmp_path):
    """Confirmation/O7: `confirmed` is present and empty; chaos carries profile, seed, ledger ref."""
    rig = Rig(tmp_path)
    rig.run()
    f = rig.freeze
    assert "confirmed" in f and not f["confirmed"]
    assert f["chaos"] == {"profile": "stale-cmdb", "seed": 42, "ledger_ref": "chaos-abc123"}


@pytest.mark.parametrize("stage", STAGES)
def test_a_failure_at_any_stage_reverts_releases_and_writes_nothing(tmp_path, stage):
    """O1: whichever step fails, the fault is reverted once (once it was live), the lock is
    released, and no freeze.yaml or part of this case is left."""
    rig = Rig(tmp_path, fail_at=stage)
    with pytest.raises(RuntimeError, match=f"{stage} failed"):
        rig.run()
    assert not (rig.case_dir / "freeze.yaml").exists()
    mine = rig.parts_dir / SLUG
    assert not mine.exists() or not [p for p in mine.rglob("*") if p.is_file()]
    assert [p.name for p in rig.parts_dir.iterdir() if p.name not in ("other-case", SLUG)] == []
    assert (rig.parts_dir / "other-case" / "keep.bin").read_bytes() == b"keep"
    if stage == "fire":
        assert "revert" not in rig.journal.ops()  # no ledger ref was ever returned
    else:
        assert rig.ops.revert_refs == ["chaos-abc123"]
    if stage != "revert":
        assert not rig.ops.fault_live
        assert "capture" not in rig.store.records
    else:
        assert "capture" in rig.store.records, "a failed revert must keep the capture lock held"


def _stored(rig: Rig, slug: str = SLUG) -> dict[str, bytes]:
    mine = rig.parts_dir / slug
    return {str(p.relative_to(mine)): p.read_bytes() for p in sorted(mine.rglob("*")) if p.is_file()}


@pytest.mark.parametrize("stage", ["wait_alert", "wait_as_of", "copy_volumes"])
def test_an_interrupt_at_any_stage_still_reverts_and_cleans_up(tmp_path, stage):
    """O1: Ctrl-C (a BaseException) while the fault is live reverts it once, frees the lock and
    leaves no part, staging directory or freeze.yaml."""
    rig = Rig(tmp_path, fail_at=stage, exc=KeyboardInterrupt)
    with pytest.raises(KeyboardInterrupt):
        rig.run()
    assert rig.ops.revert_refs == ["chaos-abc123"] and not rig.ops.fault_live
    assert "capture" not in rig.store.records
    assert not (rig.case_dir / "freeze.yaml").exists()
    assert [p.name for p in rig.parts_dir.iterdir()] == ["other-case"]


def test_a_failed_cleanup_revert_keeps_the_lock_held(tmp_path):
    """O1/D9: when the stage failed and the cleanup revert fails too, the fault may be live: an
    error surfaces (the stage's or the revert's) and the capture lock stays held."""
    rig = Rig(tmp_path, fail_at=("copy_volumes", "revert"))
    with pytest.raises(RuntimeError, match="copy_volumes failed|revert failed"):
        rig.run()
    assert rig.ops.revert_refs == ["chaos-abc123"]
    assert "capture" in rig.store.records, "the lock was released with the fault possibly live"
    assert not (rig.case_dir / "freeze.yaml").exists()


@pytest.mark.parametrize("stage", ["wait_alert", "copy_volumes", "fingerprint"])
def test_the_lock_is_still_held_when_the_fault_is_reverted(tmp_path, stage):
    """O1/D9: every revert call, including the cleanup one after a failure, happens under the lock."""
    rig = Rig(tmp_path, fail_at=stage)
    with pytest.raises(RuntimeError):
        rig.run()
    assert rig.held_at_revert == [True]


@pytest.mark.parametrize("stage", ["proc_tree", "fingerprint", "revert"])
def test_a_failed_recapture_leaves_the_earlier_capture_of_the_case_intact(tmp_path, stage):
    """O1/D8: an earlier capture's parts and freeze.yaml survive a failed re-capture of the case."""
    rig = Rig(tmp_path)
    rig.run()
    parts, freeze_text = _stored(rig), (rig.case_dir / "freeze.yaml").read_text()
    assert parts
    again = Rig(tmp_path / "again", fail_at=stage)
    again.case_dir, again.parts_dir = rig.case_dir, rig.parts_dir
    with pytest.raises(RuntimeError, match=f"{stage} failed"):
        again.run()
    assert _stored(rig) == parts
    assert (rig.case_dir / "freeze.yaml").read_text() == freeze_text
    assert [p.name for p in rig.parts_dir.iterdir() if p.name not in ("other-case", SLUG)] == []


def test_a_freeze_yaml_that_cannot_be_written_leaves_the_earlier_parts_in_place(tmp_path):
    """O1/D8: a failure writing freeze.yaml (a non-empty directory sits there) swaps no new parts
    over the earlier ones and leaves no staging directory."""
    rig = Rig(tmp_path)
    mine = rig.parts_dir / SLUG
    mine.mkdir()
    (mine / "old.bin").write_bytes(b"earlier capture")
    blocker = rig.case_dir / "freeze.yaml"
    blocker.mkdir()
    (blocker / "x").write_text("x")
    with pytest.raises(OSError):
        rig.run()
    assert _stored(rig) == {"old.bin": b"earlier capture"}
    assert [p.name for p in rig.parts_dir.iterdir() if p.name not in ("other-case", SLUG)] == []
    assert not rig.ops.fault_live and "capture" not in rig.store.records


def _retake_by_another_holder(rig: Rig) -> list[str]:
    """After the fault is reverted, the operator clears the lock and another holder takes it."""
    from chaos import lock
    taken: list[str] = []
    base = rig.ops.on_step

    def watch(step: str) -> None:
        base(step)
        if step == "refresh":
            lock.clear(rig.store, lock.CAPTURE)
            taken.append(lock.take(rig.store, lock.CAPTURE))

    rig.ops.on_step = watch
    return taken


def test_capture_releases_only_with_its_own_token(tmp_path):
    """D14: if the lock was cleared and re-taken meanwhile, capture's release is refused with
    WrongToken and the other holder's lock survives."""
    from chaos import lock
    rig = Rig(tmp_path)
    taken = _retake_by_another_holder(rig)
    with pytest.raises(lock.WrongToken):
        rig.run()
    assert taken and taken[0] in rig.store.records["capture"]


def test_capture_refuses_while_another_holder_has_the_lock(tmp_path):
    """D9/D14: a held lock stops capture before any lab operation and writes nothing."""
    from chaos import lock
    rig = Rig(tmp_path)
    lock.take(rig.store, lock.CAPTURE)
    with pytest.raises(lock.Held):
        rig.run()
    assert [op for op in rig.journal.ops() if not op.startswith("lock.")] == []
    assert list(rig.case_dir.iterdir()) == []


def test_capture_reports_what_the_guaranteed_window_holds_per_source(tmp_path, capsys):
    """O8/FR13: the report names each fingerprinted index with its document count, the window
    bounds and the stored parts; the format is unpinned."""
    fp = {"logs-system.auth-2026.10.20|2026-10-20T08": [1200, 1200],
          "logs-system.auth-2026.10.20|2026-10-20T09": [300, 300],
          "logs-falco.alerts-2026.10.20|2026-10-20T08": [4321, 4321]}
    rig = Rig(tmp_path, fingerprint=fp)
    rig.run()
    seen = capsys.readouterr()
    text = seen.out + seen.err + repr(rig.result)
    assert "logs-system.auth-2026.10.20" in text and "1500" in text
    assert "logs-falco.alerts-2026.10.20" in text and "4321" in text
    start, end = rig.freeze["window"]
    assert str(instant(start).date()) in text and str(instant(end).date()) in text
    for part in PART_BYTES:
        assert part in text


def test_without_an_injected_clock_and_fingerprint_capture_builds_the_production_lab_ops(
        tmp_path, monkeypatch):
    """FR1/O1: an ops object with no es_now/fingerprint leaves capture to build `LabOps` itself."""
    built, fingerprint = [], {"spy|2026-10-20T08": [3, 3]}

    class SpyLabOps:
        def __init__(self, *args, **kwargs):
            built.append((args, kwargs))

        def es_now(self):
            return ES_NOW

        def fingerprint(self, window, as_of, arrived_by):
            return fingerprint

    class WithoutClockAndFingerprint:
        def __init__(self, inner):
            self._inner = inner

        def __getattr__(self, name):
            if name in ("es_now", "fingerprint"):
                raise AttributeError(name)
            return getattr(self._inner, name)

    rig = Rig(tmp_path)
    module = _module()
    monkeypatch.setattr(module, "LabOps", SpyLabOps)
    module.capture(rig.case_dir, scenario="ssh-brute-force-canary", chaos=rig.chaos,
                   ops=WithoutClockAndFingerprint(rig.ops), lock_store=rig.store,
                   parts_dir=rig.parts_dir, clock=rig.clock, history_start=rig.history_start)
    assert built
    assert rig.freeze["fingerprint"] == fingerprint
    assert instant(rig.freeze["captured_at"]) == instant(ES_NOW)


def test_a_first_capture_whose_freeze_cannot_be_written_leaves_no_parts(tmp_path):
    """O1/D8: with no earlier capture, a failed freeze.yaml write leaves the case's parts absent or empty."""
    rig = Rig(tmp_path)
    blocker = rig.case_dir / "freeze.yaml"
    blocker.mkdir()
    (blocker / "x").write_text("x")
    with pytest.raises(OSError):
        rig.run()
    mine = rig.parts_dir / SLUG
    assert not mine.exists() or not [p for p in mine.rglob("*") if p.is_file()]
    assert [p.name for p in rig.parts_dir.iterdir() if p.name not in ("other-case", SLUG)] == []


def test_a_failed_commit_leaves_no_temporary_freeze_file_in_the_case_dir(tmp_path):
    """O1/D8: a failed commit leaves nothing but the blocker (and alert.json) in the case dir."""
    rig = Rig(tmp_path)
    blocker = rig.case_dir / "freeze.yaml"
    blocker.mkdir()
    (blocker / "x").write_text("x")
    with pytest.raises(OSError):
        rig.run()
    assert {p.name for p in rig.case_dir.iterdir()} <= {"freeze.yaml", "alert.json"}


def test_a_successful_recapture_replaces_parts_and_freeze_and_leaves_no_old_copy(tmp_path):
    """O1/D8: re-capturing a case swaps in the new parts and freeze.yaml; nothing earlier remains."""
    rig = Rig(tmp_path)
    mine = rig.parts_dir / SLUG
    mine.mkdir()
    (mine / "old.bin").write_bytes(b"earlier capture")
    (rig.case_dir / "freeze.yaml").write_text("earlier: freeze\n")
    rig.run()
    assert _stored(rig) == PART_BYTES
    assert rig.freeze.get("earlier") is None and set(rig.freeze["parts"]) == set(PART_BYTES)
    assert sorted(p.name for p in rig.parts_dir.iterdir()) == sorted(["other-case", SLUG])
    assert [p.name for p in rig.case_dir.iterdir() if p.name.startswith(".")] == []


def test_a_failure_swapping_the_new_parts_in_restores_the_earlier_parts(tmp_path, monkeypatch):
    """O1/D8: if moving the staged parts into place fails, the earlier parts are back and no freeze is written."""
    rig = Rig(tmp_path)
    mine = rig.parts_dir / SLUG
    mine.mkdir()
    (mine / "old.bin").write_bytes(b"earlier capture")
    real = Path.rename

    def rename(self, target):
        if self.name.startswith(f".{SLUG}.") and self.name != f".{SLUG}.old" and Path(target) == mine:
            raise OSError("injected: staging rename failed")
        return real(self, target)

    monkeypatch.setattr(Path, "rename", rename)
    with pytest.raises(OSError, match="injected"):
        rig.run()
    assert _stored(rig) == {"old.bin": b"earlier capture"}
    assert not (rig.case_dir / "freeze.yaml").exists()
    assert sorted(p.name for p in rig.parts_dir.iterdir()) == sorted(["other-case", SLUG])


# -- the command line -------------------------------------------------------------------------


def _main(tmp_path, monkeypatch, *flags, hold=False):
    """Drive `capture_case.main` with the docker lock store, LabOps and wall clock replaced by the rig's fakes."""
    from chaos import lock
    rig = Rig(tmp_path)
    module = _module()
    if hold:
        lock.take(rig.store, lock.CAPTURE)
    monkeypatch.setattr(module, "LabOps", lambda: rig.ops)
    monkeypatch.setattr(module, "WallClock", lambda: rig.clock)
    monkeypatch.setattr(module.lock, "DockerLockStore", lambda: rig.store)
    rc = module.main([str(rig.case_dir), "--scenario", "ssh-brute-force-canary",
                      "--history-start", HISTORY_START, "--parts-dir", str(rig.parts_dir), *flags])
    return rig, rc


def test_the_command_line_forwards_chaos_seed_and_settle_to_capture(tmp_path, monkeypatch):
    """O1/O7: `--chaos P --seed N --settle-s S` reach the fire call, the freeze and the settle sleep."""
    rig, rc = _main(tmp_path, monkeypatch, "--chaos", "stale-cmdb", "--seed", "7", "--settle-s", "5")
    assert rc == 0
    assert rig.ops.fire_kwargs["chaos"] == "stale-cmdb" and rig.ops.fire_kwargs["seed"] == 7
    assert rig.freeze["chaos"]["seed"] == 7
    assert [d for op, d in rig.journal if op == "clock.sleep"] == [5.0]


def test_the_command_line_refuses_while_the_lock_is_held_exit_4_naming_it(tmp_path, monkeypatch, capsys):
    """O10: a held capture lock makes the command exit 4 and say which lock refused."""
    rig, rc = _main(tmp_path, monkeypatch, hold=True)
    err = capsys.readouterr().err
    assert rc == 4 and "capture" in err and "held" in err
    assert "fire" not in rig.journal.ops()


def test_the_wall_clock_sleeps_until_the_instant():
    """O7: WallClock.sleep_until returns only once the instant has passed."""
    clock = _module().WallClock()
    moment = datetime.now(UTC) + timedelta(seconds=0.3)
    clock.sleep_until(moment)
    assert datetime.now(UTC) >= moment
