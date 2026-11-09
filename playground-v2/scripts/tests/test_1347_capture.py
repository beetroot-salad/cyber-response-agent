"""#1347 r6.4 O1/O10/A5/A9: one capture per freeze, all-or-nothing, under the capture lock.

Entry point bound by this contract: `playground-v2/scripts/capture_case.py::capture(freeze_dir,
*, T, scenarios, patterns, repository, ops, es, lock_store, parts_dir, clock, captured_by)`.
`freeze_dir` is `held_out/freezes/<freeze-id>/` (the freeze id is its name); parts go under
`parts_dir/<freeze-id>/`; writes `freeze_dir/freeze.yaml`. `es` is the LIVE cluster through
the chaos seam's `es_request(method, path, body=None)`. `ops` offers:
active_faults() -> list; hold_pickups(); release_pickups() (the alert-ticket watcher and every
live defender pickup); fire(scenario, lock_token); proc_tree(dest), stub_dumps(dest),
commit_hosts(dest), copy_volumes(dest), detection_rules(dest) (the rules installed at T) ->
part names written under dest; verify_restore(repository, snapshot) -> {index: count} (a scratch
cluster). The lock is `chaos.lock` (`take/release`, `CAPTURE = "capture"`) on `lock_store`.
The operator registered `repository` once; capture only verifies it (GET `/_snapshot/<repo>` or
POST `/_snapshot/<repo>/_verify`) and never registers it.
"""
from __future__ import annotations

import importlib.util
import re
from datetime import timedelta
from pathlib import Path

import pytest
import yaml
from _lab_fakes import RULES_PART, FakeClock, FakeES, Journal, instant, sha
from _periphery_fakes import TimedLockStore

CAPTURE = Path(__file__).resolve().parents[1] / "capture_case.py"
FREEZE_ID = "f-2026-10-20"
T = instant("2026-10-20T09:00:00Z")
MAX_AGE = timedelta(hours=6)
PATTERNS = ["logs-*", ".internal.alerts-security.alerts-default-*"]
REPO = "frozen-cases"
SNAP_UUID = "dGhlLXNuYXBzaG90LXV1aWQ"
COUNTS = {"logs-system.auth-2026.10": 120_400, ".internal.alerts-security.alerts-default-000001": 37}
SCENARIOS = ["ssh-brute-force-canary", "cron-persistence", "lsass-access"]
PART_BYTES = {
    "proc_tree": {"proc-tree.txt": b"PID PPID\n1 0 init\n"},
    "stub_dumps": {"stubs.tar": b"stub-dump-bytes"},
    "commit_hosts": {"web-1.image": b"image-bytes-web-1"},
    "copy_volumes": {"var-log-web-1.tar": b"volume-bytes"},
    "detection_rules": {RULES_PART: b"rules-at-T"},
}
PART_STEPS = list(PART_BYTES)
SNAP_URL = re.compile(rf"^/_snapshot/{REPO}/(?P<name>[^_/][^/]*)$")


def _module():
    spec = importlib.util.spec_from_file_location("capture_1347", CAPTURE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Ops:
    def __init__(self, rig: "Rig", fail_at: str | None, faults: list) -> None:
        self.rig, self.fail_at, self.faults = rig, fail_at, faults
        self.fired: list[tuple[str, object, str, str]] = []

    def _step(self, name: str, detail=None) -> None:
        r = self.rig
        r.journal.append((name, detail))
        r.held_at.setdefault(name, []).append("capture" in r.store.records)
        r.at.setdefault(name, []).append(r.clock.last)
        if name == self.fail_at:
            raise RuntimeError(f"{name} failed")

    def active_faults(self):
        self._step("active_faults")
        return list(self.faults)

    def hold_pickups(self):
        self._step("hold_pickups")

    def release_pickups(self):
        self._step("release_pickups")

    def fire(self, scenario, lock_token):
        self.fired.append((scenario, self.rig.clock.last, lock_token,
                           self.rig.store.records.get("capture", "")))
        self._step("fire", scenario)

    def _part(self, name, dest):
        self._step(name, dest)
        dest.mkdir(parents=True, exist_ok=True)
        for part, data in PART_BYTES[name].items():
            (dest / part).write_bytes(data)
        return list(PART_BYTES[name])

    def proc_tree(self, dest):
        return self._part("proc_tree", dest)

    def stub_dumps(self, dest):
        return self._part("stub_dumps", dest)

    def commit_hosts(self, dest):
        return self._part("commit_hosts", dest)

    def copy_volumes(self, dest):
        return self._part("copy_volumes", dest)

    def detection_rules(self, dest):
        return self._part("detection_rules", dest)

    def verify_restore(self, repository, snapshot):
        self._step("verify_restore", (repository, snapshot))
        return dict(COUNTS)


class Rig:
    def __init__(self, tmp_path: Path, fail_at: str | None = None, faults: list | None = None,
                 state: str = "SUCCESS", repository_registered: bool = True):
        self.journal = Journal()
        self.clock = FakeClock(self.journal, T - MAX_AGE - timedelta(minutes=5))
        self.store = TimedLockStore(self.journal, self.clock)
        self.held_at: dict[str, list[bool]] = {}
        self.at: dict[str, list] = {}
        self.snapshots: dict[str, dict] = {}  # what the live cluster's repository holds
        self.ops = Ops(self, fail_at, faults or [])

        def route(method, path, body):
            if method in ("PUT", "POST") and (m := SNAP_URL.match(path)):
                self.held_at.setdefault("snapshot", []).append("capture" in self.store.records)
                self.at.setdefault("snapshot", []).append(self.clock.last)
                if fail_at == "snapshot":
                    raise RuntimeError("snapshot failed")
                self.snapshots[m["name"]] = {"snapshot": m["name"], "uuid": SNAP_UUID,
                                             "state": state, "indices": list(COUNTS)}
                return {"snapshot": self.snapshots[m["name"]]}
            if method == "GET" and (m := SNAP_URL.match(path)):
                return {"snapshots": [self.snapshots[m["name"]]]}
            if method == "DELETE" and (m := SNAP_URL.match(path)):
                self.snapshots.pop(m["name"], None)
            return {}

        def fail(method, path, body):
            verifies = (method == "GET" and path.rstrip("/") == f"/_snapshot/{REPO}") or \
                (method == "POST" and path.rstrip("/") == f"/_snapshot/{REPO}/_verify")
            return verifies and not repository_registered

        self.es = FakeES(self.journal, route=route, fail=fail)
        self.freeze_dir = tmp_path / "held_out" / "freezes" / FREEZE_ID
        self.parts_dir = tmp_path / "parts"
        self.module = _module()  # loaded here, so a missing script is never the failure a raises() expects

    def capture(self):
        return self.module.capture(
            self.freeze_dir, T=T, scenarios=SCENARIOS, patterns=PATTERNS, repository=REPO,
            ops=self.ops, es=self.es, lock_store=self.store, parts_dir=self.parts_dir,
            clock=self.clock, captured_by="operator")

    def creates(self) -> list[tuple[str, str, object]]:
        return [r for r in self.es.requests
                if r[0] in ("PUT", "POST") and SNAP_URL.match(r[1].split("?", 1)[0])]


def test_a_capture_writes_one_freeze_of_every_part_with_the_verification_counts(tmp_path):
    """O1/A5: freeze.yaml names T, the snapshot (repository, name, UUID) with each index's count
    from the verification restore, every part (the rules at T included) by sha256, and who captured."""
    rig = Rig(tmp_path)
    rig.capture()

    doc = yaml.safe_load((rig.freeze_dir / "freeze.yaml").read_text())
    assert instant(doc["T"]) == T
    elastic = doc["elastic"]
    assert (elastic["repository"], elastic["uuid"], elastic["indices"]) == (REPO, SNAP_UUID, COUNTS)
    assert list(rig.snapshots) == [elastic["snapshot"]]
    stored = rig.parts_dir / FREEZE_ID
    expected = {n: b for parts in PART_BYTES.values() for n, b in parts.items()}
    assert doc["parts"] == {n: sha(b) for n, b in expected.items()}  # bare lowercase hex (A8)
    assert {p.name: p.read_bytes() for p in stored.rglob("*") if p.is_file()} == expected
    assert doc["captured_by"] == "operator"
    assert rig.ops.fired and rig.journal.ops().count("verify_restore") == 1
    assert rig.at["verify_restore"] and (REPO, elastic["snapshot"]) in \
        [d for op, d in rig.journal if op == "verify_restore"]


def test_the_snapshot_covers_the_configured_patterns_after_a_refresh(tmp_path):
    """O1: one snapshot of every index the events and alerts patterns match, taken after a refresh
    of them (the parts come first, then refresh, then snapshot)."""
    rig = Rig(tmp_path)
    rig.capture()

    creates = rig.creates()
    assert len(creates) == 1, rig.es.requests
    indices = creates[0][2]["indices"]
    indices = indices.split(",") if isinstance(indices, str) else indices
    assert sorted(indices) == sorted(PATTERNS), creates
    j = rig.journal
    snapshot_at = next(i for i, (op, d) in enumerate(j) if op == "es" and SNAP_URL.match(d[1].split("?")[0])
                       and d[0] in ("PUT", "POST"))
    refreshes = [i for i, (op, d) in enumerate(j) if op == "es" and "_refresh" in d[1]]
    assert refreshes and max(refreshes) < snapshot_at
    assert j.first("copy_volumes") < min(refreshes)


def test_capture_only_verifies_the_registered_repository(tmp_path):
    """O1/A9: the operator registers the repository; capture checks it and never PUTs or
    POSTs to the repository itself, nor deletes it."""
    rig = Rig(tmp_path)
    rig.capture()

    repo_path = f"/_snapshot/{REPO}"
    verifies = [r for r in rig.es.requests
                if (r[0] == "GET" and r[1].split("?")[0].rstrip("/") == repo_path)
                or (r[0] == "POST" and r[1].split("?")[0].rstrip("/") == f"{repo_path}/_verify")]
    assert verifies, rig.es.requests
    assert not [r for r in rig.es.requests
                if r[0] in ("PUT", "POST", "DELETE") and r[1].split("?")[0].rstrip("/") == repo_path]


def test_an_unregistered_repository_fails_the_capture_without_registering_it(tmp_path):
    """O1/A9: the repository check fails: nothing registered, no snapshot, no freeze, lock free."""
    rig = Rig(tmp_path, repository_registered=False)
    with pytest.raises(Exception):
        rig.capture()

    assert not [r for r in rig.es.requests if r[0] in ("PUT", "POST")
                and r[1].split("?")[0].rstrip("/") in (f"/_snapshot/{REPO}",)]
    assert rig.snapshots == {} and not (rig.freeze_dir / "freeze.yaml").exists()
    assert "capture" not in rig.store.records


def test_capture_holds_the_lock_and_the_pickups_off_from_the_batch_through_the_snapshot(tmp_path):
    """O1/O10 + held-out isolation: the capture lock is taken before anything fires and held
    through every part and the snapshot, then released before the verification restore; the
    watcher and live pickups are held off from the batch's start through the snapshot. Parts
    are taken at T, in the flow's order, then the snapshot."""
    rig = Rig(tmp_path)
    rig.capture()
    j = rig.journal

    assert j.first("lock.create") < j.first("hold_pickups") < j.first("fire")
    assert all(all(rig.held_at[s]) for s in ("fire", *PART_STEPS, "snapshot"))
    assert rig.held_at["verify_restore"] == [False], "the lock was still held at the verification restore"
    snapshot_at = next(i for i, (op, d) in enumerate(j) if op == "es" and SNAP_URL.match(d[1].split("?")[0])
                       and d[0] in ("PUT", "POST"))
    assert j.first("release_pickups") > snapshot_at
    order = [j.first(s) for s in ("proc_tree", "stub_dumps", "commit_hosts", "copy_volumes")]
    assert order == sorted(order) and max(order) < snapshot_at
    assert j.first("proc_tree") > max(
        i for i, (op, at) in enumerate(j) if op == "clock.sleep_until" and at == T)
    assert all(at >= T for step in (*PART_STEPS, "snapshot") for at in rig.at[step]), rig.at
    assert "capture" not in rig.store.records


def test_the_batch_is_spread_across_the_window_under_the_one_lock_token(tmp_path):
    """O1/O10: every scenario fires once with the lock's own token, inside [T - max_age, T] and
    spread across it (not bunched), while the lock record holds that token."""
    rig = Rig(tmp_path)
    rig.capture()

    fired = rig.ops.fired
    assert sorted(s for s, *_ in fired) == sorted(SCENARIOS)
    times = [at for _s, at, _tok, _rec in fired]
    assert all(T - MAX_AGE <= at <= T for at in times), fired
    assert max(times) - min(times) >= MAX_AGE / 2, times
    assert len({tok for _s, _a, tok, _r in fired}) == 1 and fired[0][2]
    assert all(tok in rec for _s, _a, tok, rec in fired), "the token is not the capture lock's"


def test_the_capture_lock_and_pickup_hold_last_the_whole_batch(tmp_path):
    """O10/A9: the lock is taken no later than the first firing and freed after T, so it is held
    for the whole >= 6 h batch; the pickups are held off over the same span."""
    rig = Rig(tmp_path)
    rig.capture()

    first_fire = min(at for _s, at, _t, _r in rig.ops.fired)
    taken, freed = rig.store.created_at["capture"], rig.store.deleted_at["capture"]
    assert taken <= first_fire and freed >= T and freed - taken >= MAX_AGE
    assert rig.at["hold_pickups"][0] <= first_fire and max(rig.at["release_pickups"]) >= T


@pytest.mark.parametrize("fail_at", [
    "hold_pickups", "fire", "proc_tree", "stub_dumps", "commit_hosts", "copy_volumes",
    "detection_rules", "snapshot", "verify_restore"])
def test_a_failed_capture_writes_nothing_and_frees_the_lock_and_the_pickups(tmp_path, fail_at):
    """O1/A9: all-or-nothing. Whatever step fails: no freeze.yaml, no parts left, no snapshot
    left in the repository, the lock free and the pickups resumed; the failure is raised."""
    rig = Rig(tmp_path, fail_at=fail_at)
    with pytest.raises(Exception):
        rig.capture()

    assert not (rig.freeze_dir / "freeze.yaml").exists()
    stored = rig.parts_dir / FREEZE_ID
    assert not stored.exists() or not any(stored.rglob("*")), list(stored.rglob("*"))
    assert rig.snapshots == {}, "the capture left its own snapshot behind"
    assert "capture" not in rig.store.records
    assert "release_pickups" in rig.journal.ops()


@pytest.mark.parametrize("state", ["PARTIAL", "FAILED"])
def test_a_snapshot_that_did_not_succeed_fails_the_capture_and_is_deleted(tmp_path, state):
    """O1/A9: a snapshot ending in any state but SUCCESS is a failed capture: nothing written,
    and the snapshot capture created is deleted."""
    rig = Rig(tmp_path, state=state)
    with pytest.raises(Exception):
        rig.capture()

    assert len(rig.creates()) == 1
    assert rig.snapshots == {} and not (rig.freeze_dir / "freeze.yaml").exists()
    assert "capture" not in rig.store.records and "verify_restore" not in rig.journal.ops()


def test_a_capture_is_refused_while_a_fault_is_active_or_the_lock_is_held(tmp_path):
    """O1 (no fault is active) and O10: nothing fires and nothing is written. Control: the same
    rig with neither captures (the first test)."""
    faulted = Rig(tmp_path / "a", faults=["data-drop-syslog"])
    with pytest.raises(Exception, match="data-drop-syslog"):
        faulted.capture()
    held = Rig(tmp_path / "b")
    held.store.records["capture"] = "someone-else"
    with pytest.raises(Exception):
        held.capture()

    for rig in (faulted, held):
        assert "fire" not in rig.journal.ops() and not rig.es.requests
        assert not (rig.freeze_dir / "freeze.yaml").exists() and rig.snapshots == {}
    assert held.store.records["capture"] == "someone-else"
    assert "capture" not in faulted.store.records
