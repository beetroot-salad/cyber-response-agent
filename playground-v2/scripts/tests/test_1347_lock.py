"""#1347 r6.4 O10/D14 (re-covered per A10 from e26e34706): the lab-server lock token. Entry points
bound by this contract:

* `chaos/lock.py` (new): `take(store, name, *, clock=time.time) -> token`,
  `release(store, name, token)`, `require(store, name, token=None)`, `clear(store, name)`,
  exceptions `Held` and `WrongToken`, names `CAPTURE = "capture"` and `FROZEN_ENGINE =
  "frozen-engine"`, and `DockerLockStore(run=subprocess.run)`. A store offers
  `create_exclusive(name, record) -> bool`, `read(name) -> str | None`, `delete(name)` and (r6.4.3 finding 9)
  `delete_if_held_by(name, token) -> bool`: one engine-side step that deletes the record only when its token is
  `token`. `release` frees through it, so a lock cleared and retaken between a read and the delete keeps
  its new holder.
* `attacks/runner.py::run_scenario(..., lock_store=None, lock_token=None)` and
  `cmd_run(args, ..., lock_store=None)` with a `--lock-token` flag; `None` = no check at the
  library level, `cmd_run` supplies a `DockerLockStore()` by default.
* `chaos/ctl.py::activate(..., lock_store=None, lock_token=None)` and `activate --lock-token`;
  the CLI (`ctl.main(["activate", ...])`) calls `ctl.activate` with `lock_store=` a
  `DockerLockStore()` and `lock_token=` the flag's value.
* `chaos/lock.py::main(argv) -> int`: `status <name>` prints `free` or the holder, `clear <name>`
  deletes that lock's record; both reach the lab through `DockerLockStore()`.
* Bound argv convention: `DockerLockStore` talks to the lab through
  `docker --context <ctx> exec [-i] <container> <command...>` (stdin allowed). A docker-exec
  transport failure (rc 1/125) must raise, so "absent" / "held" must be signalled by a stdout
  marker or a different exit code, never rc 1.
"""
from __future__ import annotations

import contextlib
import importlib.util
import json
import os
import threading
from types import SimpleNamespace
from pathlib import Path

import pytest
import yaml
from _lab_fakes import FakeLockStore, Journal, instant
from _periphery_fakes import LocalContainer, containers_in, install_fake_docker

PLAYGROUND = Path(__file__).resolve().parents[2]
RUNNER = PLAYGROUND / "attacks" / "runner.py"
SCENARIO = {"id": "ssh-brute-force-canary", "category": "auth-metadata",
            "description": "fixture\n", "target_host": "web-1", "source_host": "dev-ws-1",
            "default_intensity": 1, "steps": [{"cmd": "true"}]}


def _store() -> FakeLockStore:
    return FakeLockStore(Journal())


@pytest.fixture
def lock():
    from chaos import lock as module
    return module


@pytest.fixture
def runner():
    spec = importlib.util.spec_from_file_location("runner_1347", RUNNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# -- the lock itself --------------------------------------------------------------------------


def test_taking_a_free_lock_returns_a_token_and_stores_one_record(lock):
    """D14: a take on a free lock is one exclusive create and hands back a random token."""
    store = _store()
    token = lock.take(store, lock.CAPTURE)
    assert token and token in store.records[lock.CAPTURE]
    assert store.journal.ops().count("lock.create") == 1
    assert lock.take(_store(), lock.CAPTURE) != token, "tokens must be random"


def test_tokens_are_long_random_hex_not_derived_from_the_clock(lock):
    """D14: a token is unguessable: 32+ characters, different for takes at the same instant."""
    tokens = [lock.take(_store(), lock.CAPTURE, clock=lambda: 1_700_000_000.0) for _ in range(2)]
    assert tokens[0] != tokens[1]
    for token in tokens:
        assert len(token) >= 32, token


def test_taking_a_held_lock_is_refused_and_leaves_the_record_alone(lock):
    """D14: a second take raises Held and does not overwrite the holder's record."""
    store = _store()
    lock.take(store, lock.CAPTURE)
    before = dict(store.records)
    with pytest.raises(lock.Held):
        lock.take(store, lock.CAPTURE)
    assert store.records == before


def test_racing_takes_grant_the_lock_to_exactly_one_taker(lock):
    """D14: the take is atomic; of many concurrent takers exactly one gets a token."""
    store, won, lost = _store(), [], []

    def taker():
        try:
            won.append(lock.take(store, lock.CAPTURE))
        except lock.Held:
            lost.append(1)

    threads = [threading.Thread(target=taker) for _ in range(12)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(won) == 1 and len(lost) == 11


def test_a_lock_never_expires_however_old_the_holder(lock):
    """D14: a dead holder's lock is cleared by the operator, never by timeout."""
    store = _store()
    lock.take(store, lock.CAPTURE, clock=lambda: 946684800.0)  # year 2000
    with pytest.raises(lock.Held):
        lock.take(store, lock.CAPTURE, clock=lambda: 4102444800.0)  # year 2100
    lock.clear(store, lock.CAPTURE)
    assert lock.take(store, lock.CAPTURE)


def test_a_lock_held_across_a_whole_capture_batch_is_still_held(lock):
    """O10/A9: the capture lock lasts the >= 6 h scenario batch; seven hours on it is still held
    and a take is refused, with the first record intact."""
    store, t0 = _store(), 1_700_000_000.0
    lock.take(store, lock.CAPTURE, clock=lambda: t0)
    before = dict(store.records)
    with pytest.raises(lock.Held):
        lock.take(store, lock.CAPTURE, clock=lambda: t0 + 7 * 3600)
    assert store.records == before


def test_release_needs_the_holders_token(lock):
    """D14: releasing with another token is refused and keeps the lock; the right token frees."""
    store = _store()
    token = lock.take(store, lock.CAPTURE)
    with pytest.raises(lock.WrongToken):
        lock.release(store, lock.CAPTURE, "not-the-token")
    assert lock.CAPTURE in store.records
    lock.release(store, lock.CAPTURE, token)
    assert lock.CAPTURE not in store.records


def test_the_capture_and_frozen_engine_locks_are_independent(lock):
    """D14: the frozen engine's run lock is the same mechanism under its own name."""
    store = _store()
    lock.take(store, lock.CAPTURE)
    assert lock.take(store, lock.FROZEN_ENGINE)


@pytest.mark.parametrize("record", ["not json", "[]", ""], ids=["garbage", "list", "empty"])
def test_an_empty_token_never_opens_a_record_that_cannot_be_read(lock, record):
    """D14: `--lock-token ""` is not the holder's token for an unreadable record: require and
    release refuse and the record stays."""
    store = _store()
    store.records[lock.CAPTURE] = record
    with pytest.raises((lock.Held, lock.WrongToken)):
        lock.require(store, lock.CAPTURE, "")
    with pytest.raises((lock.Held, lock.WrongToken)):
        lock.release(store, lock.CAPTURE, "")
    assert store.records[lock.CAPTURE] == record


def _docker_store(lock, root):
    box = LocalContainer(root)
    return lock.DockerLockStore(run=box), box


def test_the_lab_store_creates_exclusively_and_each_lock_name_has_its_own_record(lock, tmp_path):
    """D14: run for real (a local shell stands in for the lab container), a second take of a held
    name is Held and keeps the first record, while another name is independent."""
    store, _ = _docker_store(lock, tmp_path)
    first = lock.take(store, lock.CAPTURE)
    before = store.read(lock.CAPTURE)
    assert before and first in before
    with pytest.raises(lock.Held):
        lock.take(store, lock.CAPTURE)
    assert store.read(lock.CAPTURE) == before
    other = lock.take(store, lock.FROZEN_ENGINE)
    assert other != first and other in store.read(lock.FROZEN_ENGINE)
    assert first in store.read(lock.CAPTURE)
    lock.release(store, lock.CAPTURE, first)
    assert store.read(lock.CAPTURE) is None and other in store.read(lock.FROZEN_ENGINE)


def test_racing_takes_on_the_lab_store_grant_the_lock_to_exactly_one_taker(lock, tmp_path):
    """D14: the lab store's create is atomic under real concurrent shells."""
    store, _ = _docker_store(lock, tmp_path)
    won, lost = [], []

    def taker():
        try:
            won.append(lock.take(store, lock.CAPTURE))
        except lock.Held:
            lost.append(1)

    threads = [threading.Thread(target=taker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(won) == 1 and len(lost) == 7
    assert won[0] in store.read(lock.CAPTURE)


class _Failing:
    def __init__(self, returncode):
        self.returncode = returncode

    def __call__(self, argv, **kw):
        class Done:
            stdout, stderr = "", "Error response from daemon: container is not running"
        Done.returncode = self.returncode
        return Done()


@pytest.mark.parametrize("returncode", [1, 125])
def test_an_unreachable_lab_raises_and_never_reads_as_free_or_cleared(lock, returncode):
    """D14: a failing docker exec makes read, delete and create raise instead of reporting
    "free", "deleted" or "taken"."""
    store = lock.DockerLockStore(run=_Failing(returncode))
    for call in (lambda: store.read(lock.CAPTURE), lambda: store.delete(lock.CAPTURE),
                 lambda: store.create_exclusive(lock.CAPTURE, "{}"),
                 lambda: lock.take(store, lock.CAPTURE), lambda: lock.require(store, lock.CAPTURE),
                 lambda: lock.release(store, lock.CAPTURE, "t"), lambda: lock.clear(store, lock.CAPTURE)):
        with pytest.raises(Exception) as caught:
            call()
        assert not isinstance(caught.value, (AttributeError, TypeError, NameError))


def test_the_lock_record_does_not_live_in_a_role_host_container(lock, tmp_path):
    """D14/D2: the container holding the record is not one of the inventory's hosts, whose
    filesystems the agent reads and the freeze commits."""
    store, box = _docker_store(lock, tmp_path)
    lock.take(store, lock.CAPTURE)
    containers = {argv[4] for argv in box.argvs}
    inventory = yaml.safe_load((PLAYGROUND / "hosts" / "inventory.yaml").read_text())
    role_hosts = {h["name"] for h in inventory["hosts"]}
    assert len(containers) == 1 and role_hosts and not containers & role_hosts


def test_the_default_store_lives_on_the_lab_server_over_docker_exec(lock, tmp_path, monkeypatch):
    """D14: the real store reaches the record through `docker --context soc-playground exec`,
    never a local file."""
    monkeypatch.chdir(tmp_path)
    argvs: list[list[str]] = []

    class Done:
        returncode, stdout, stderr = 0, "", ""

    def run(argv, **kw):
        argvs.append(list(argv))
        return Done()

    with contextlib.suppress(Exception):  # the canned reply may not satisfy the store
        lock.take(lock.DockerLockStore(run=run), lock.CAPTURE)
    assert argvs, "the store issued no lab command"
    for argv in argvs:
        assert argv[:5] == ["docker", "--context", "soc-playground", "exec", argv[4]]
    assert list(tmp_path.iterdir()) == []


# -- the attack runner ----------------------------------------------------------------------


class Recorder:
    def __init__(self):
        self.execs, self.chaos = [], []

    def exec_fn(self, host, cmd, user, dry_run):
        self.execs.append(cmd)
        return 0, "", ""

    def plan(self, profile, **kw):
        self.chaos.append("plan")
        return {"profile_id": profile, "seed": kw.get("seed")}

    def apply(self, planned, **kw):
        self.chaos.append("apply")
        return {"ledger_ref": "r-1"}

    def revert(self, ref, **kw):
        self.chaos.append("revert")


def _run(runner, tmp_path, rec, store, token=None, chaos="none", cr_mode="none"):
    return runner.run_scenario(SCENARIO, 42, {}, False, cr_mode, runs_dir=tmp_path / "runs",
                               chaos=chaos, chaos_ctl=rec, exec_fn=rec.exec_fn,
                               post_cr=lambda body: (0, {}), lock_store=store, lock_token=token)


def test_the_runner_refuses_while_the_capture_lock_is_held(runner, lock, tmp_path):
    """O10: with the lock held and no token nothing is dispatched, no fault is applied and no
    run dir is written; the lock stays held."""
    store, rec = _store(), Recorder()
    lock.take(store, lock.CAPTURE)
    with pytest.raises(SystemExit):
        _run(runner, tmp_path, rec, store, chaos="some-profile")
    assert rec.execs == [] and rec.chaos == []
    assert not (tmp_path / "runs").exists() or not any((tmp_path / "runs").iterdir())
    assert lock.CAPTURE in store.records


@pytest.mark.parametrize("cr_mode", ["valid", "stale", "scope-mismatch"])
def test_the_runner_refuses_while_the_capture_lock_is_held_for_every_cr_mode(
        runner, lock, tmp_path, cr_mode):
    """O10: a held capture lock stops a run with a synthetic change request too; nothing fires."""
    store, rec = _store(), Recorder()
    lock.take(store, lock.CAPTURE)
    with pytest.raises(SystemExit):
        _run(runner, tmp_path, rec, store, cr_mode=cr_mode)
    assert rec.execs == [] and lock.CAPTURE in store.records


def test_the_runner_refuses_a_wrong_token_and_fires_with_the_right_one(runner, lock, tmp_path):
    """O10: only the holder's token passes; a free lock needs none."""
    store, rec = _store(), Recorder()
    token = lock.take(store, lock.CAPTURE)
    with pytest.raises(SystemExit):
        _run(runner, tmp_path, rec, store, token="guess")
    assert rec.execs == []
    _run(runner, tmp_path, rec, store, token=token)
    assert rec.execs, "the holder's token did not fire"
    lock.release(store, lock.CAPTURE, token)
    rec2 = Recorder()
    _run(runner, tmp_path, rec2, store)
    assert rec2.execs, "a free lock still refused"


def test_the_runner_cli_takes_a_lock_token_flag_and_forwards_it(runner):
    """O10: `run --lock-token T` reaches run_scenario as lock_token with the store."""
    captured: dict = {}

    def fake_run_scenario(scenario, seed, overrides, dry_run, cr_mode, **kwargs):
        captured.update(kwargs)
        return "rid", Path("."), []

    store = _store()
    args = runner.build_arg_parser().parse_args(["run", "demo", "--lock-token", "T-1"])
    runner.cmd_run(args, run_scenario_fn=fake_run_scenario,
                   load_catalog_fn=lambda: {"demo": SCENARIO}, lock_store=store)
    assert captured["lock_token"] == "T-1" and captured["lock_store"] is store


def test_cmd_run_without_an_injected_store_checks_the_lab_server_lock(runner, lock):
    """O10/D14 (FR2): the production CLI path hands run_scenario the lab-server DockerLockStore."""
    captured: dict = {}

    def fake_run_scenario(scenario, seed, overrides, dry_run, cr_mode, **kwargs):
        captured.update(kwargs)
        return "rid", Path("."), []

    args = runner.build_arg_parser().parse_args(["run", "demo"])
    runner.cmd_run(args, run_scenario_fn=fake_run_scenario,
                   load_catalog_fn=lambda: {"demo": SCENARIO})
    assert isinstance(captured.get("lock_store"), lock.DockerLockStore)
    assert captured["lock_token"] is None


# -- chaos control activate ---------------------------------------------------------------


class RecordingExecer:
    def __init__(self):
        self.calls = []

    def _hit(self, what):
        from chaos.seam import SeamError
        self.calls.append(what)
        raise SeamError("stack not reachable in this test")

    def cmdb_request(self, *a, **k):
        self._hit("cmdb")

    def es_request(self, *a, **k):
        self._hit("es")

    def read_container_file(self, *a, **k):
        self._hit("file")


def test_chaos_activate_refuses_while_the_lock_is_held_without_touching_the_lab(lock, tmp_path):
    """O10: activate raises Held before any exec-seam traffic and writes no ledger record."""
    from chaos import ctl
    store, execer = _store(), RecordingExecer()
    lock.take(store, lock.CAPTURE)
    with pytest.raises(lock.Held):
        ctl.activate("cmdb-stale-owner", seed=1, execer=execer, ledger_dir=tmp_path,
                     lock_store=store, lock_token=None)
    assert execer.calls == [] and list(tmp_path.iterdir()) == []


def test_chaos_activate_proceeds_for_the_holder_and_for_a_free_lock(lock, tmp_path):
    """O10 control: the holder's token (or no lock) reaches the lab (the fake then errors)."""
    from chaos import ctl
    from chaos.seam import SeamError
    store = _store()
    token = lock.take(store, lock.CAPTURE)
    execer = RecordingExecer()
    with pytest.raises(SeamError):
        ctl.activate("cmdb-stale-owner", seed=1, execer=execer, ledger_dir=tmp_path,
                     lock_store=store, lock_token=token)
    assert execer.calls
    lock.release(store, lock.CAPTURE, token)
    execer = RecordingExecer()
    with pytest.raises(SeamError):
        ctl.activate("cmdb-stale-owner", seed=1, execer=execer, ledger_dir=tmp_path, lock_store=store)
    assert execer.calls


def test_chaos_activate_refuses_a_wrong_token_without_touching_the_lab(lock, tmp_path):
    """O10: a token that is not the holder's is refused before any exec-seam traffic."""
    from chaos import ctl
    store, execer = _store(), RecordingExecer()
    lock.take(store, lock.CAPTURE)
    with pytest.raises(lock.WrongToken):
        ctl.activate("cmdb-stale-owner", seed=1, execer=execer, ledger_dir=tmp_path,
                     lock_store=store, lock_token="not-the-token")
    assert execer.calls == [] and list(tmp_path.iterdir()) == []


def test_chaos_activate_cli_takes_a_lock_token_flag():
    """O10: `activate <profile> --lock-token T` parses."""
    from chaos import ctl
    ns = ctl.build_arg_parser().parse_args(["activate", "cmdb-stale-owner", "--lock-token", "T"])
    assert ns.lock_token == "T"


# -- the CLIs against the lab store (a fake `docker` on PATH runs the exec locally) ----------------


@pytest.fixture
def lab(tmp_path, monkeypatch, lock):
    root = tmp_path / "labroot"
    root.mkdir()
    log = install_fake_docker(tmp_path / "bin", root)
    monkeypatch.setenv("PATH", f"{tmp_path / 'bin'}{os.pathsep}{os.environ['PATH']}")
    return SimpleNamespace(store=lock.DockerLockStore(run=LocalContainer(root)), log=log)


def _refused(lock, call) -> bool:
    """A refusal is a raise (Held, WrongToken, SystemExit) or a non-zero exit code."""
    try:
        return bool(call())
    except (lock.Held, lock.WrongToken, SystemExit):
        return True


def test_chaos_activate_cli_checks_the_lab_server_lock_by_default(lock, lab, capsys):
    """O10/D14: `ctl.main(["activate", ...])` with nothing injected finds a held capture lock on
    the lab store, refuses, and sends no command to any container but the lock's."""
    from chaos import ctl
    lock.take(lab.store, lock.CAPTURE)
    assert _refused(lock, lambda: ctl.main(["activate", "cmdb-stale-owner", "--lock-token", "wrong"]))
    assert len(containers_in(lab.log)) == 1, containers_in(lab.log)


def test_chaos_activate_cli_with_the_holders_token_reaches_the_stack(lock, lab):
    """O10 control: the holder's `--lock-token` passes the CLI check and commands reach other
    containers (the stack then errors in this rig)."""
    from chaos import ctl
    token = lock.take(lab.store, lock.CAPTURE)
    with contextlib.suppress(Exception):
        ctl.main(["activate", "cmdb-stale-owner", "--lock-token", token])
    assert len(containers_in(lab.log)) > 1, containers_in(lab.log)


# -- the lock command line --------------------------------------------------------------------


def test_status_says_free_for_a_free_lock_and_not_free_for_a_held_one(lock, lab, capsys):
    """O10: `status <name>` reports that lock only: free when absent, a holder when held."""
    lock.take(lab.store, lock.CAPTURE)
    assert lock.main(["status", lock.FROZEN_ENGINE]) == 0
    assert capsys.readouterr().out.strip() == "free"
    assert lock.main(["status", lock.CAPTURE]) == 0
    held = capsys.readouterr().out.strip()
    assert held and "free" not in held.lower()


@pytest.mark.parametrize("name", ["capture", "frozen-engine"])
def test_clear_removes_the_named_lock_only(lock, lab, name):
    """O10: `clear <name>` deletes that lock's record and leaves the other lock held."""
    for each in (lock.CAPTURE, lock.FROZEN_ENGINE):
        lock.take(lab.store, each)
    other = ({lock.CAPTURE, lock.FROZEN_ENGINE} - {name}).pop()
    assert lock.main(["clear", name]) == 0
    assert lab.store.read(name) is None and lab.store.read(other)


# -- r6.4.3 finding 9: a release is one engine-side check-and-delete ----------------------------------------


def _other_holders_record(lock, name):
    other = _store()
    lock.take(other, name)
    return other.records[name]


@pytest.mark.parametrize("name", ["capture", "frozen-engine"])
def test_a_release_racing_a_clear_and_a_retake_never_removes_the_new_holders_record(lock, name):
    """r6.4.3 finding 9/O10: between the old holder's read and its delete, the operator clears the lock and
    another holder takes it. The old holder's release does not remove the new holder's record."""
    store = _store()
    token = lock.take(store, name)
    newer = _other_holders_record(lock, name)

    def clear_and_retake():
        store.records.pop(name, None)
        store.records[name] = newer

    store.race(name, clear_and_retake)
    try:
        lock.release(store, name, token)
    except (lock.Held, lock.WrongToken):
        pass          # refusing is fine: the old holder no longer holds it

    assert store.records.get(name) == newer, store.records


def _rig_lab_store(lock):
    """`DockerLockStore` over the rig docker: the lab server's lock container, its files and its shell."""
    from _lab_fakes import CONTEXT, FakeClock, Journal
    from _rig_docker import RigDocker

    journal = Journal()
    docker = RigDocker(journal=journal, clock=FakeClock(journal, instant("2026-11-10T09:00:00Z")))
    box = docker.existing(CONTEXT, lock.LOCK_CONTAINER, "docker.elastic.co/elasticsearch/elasticsearch:9.3.3")
    return lock.DockerLockStore(run=docker), docker, box


@pytest.mark.parametrize("name", ["capture", "frozen-engine"])
def test_a_release_on_the_lab_store_racing_a_clear_and_a_retake_keeps_the_new_holders_record(lock, name):
    """r6.4.3 finding 9 (settled mechanism: every take and every release of a lock record runs under `flock` on
    a per-lock lock file, and the release compares the record's token before it deletes, in one exec). On the
    lab store, another operator clears the lock and takes it again at any moment the old holder's release is
    not inside the flock its take held (`RigDocker.race_record`). Outcome only: the new holder's record is
    still there after the old holder's release, which may refuse."""
    store, docker, box = _rig_lab_store(lock)
    token = lock.take(store, name)
    newer = json.dumps({"token": "b" * 32, "taken_at": "2026-11-10T09:05:00+00:00", "holder": "other@lab"})
    path = f"{lock.LOCK_DIR}/{name}"

    def clear_and_retake():
        where, key, _ro = docker.resolve(box, path)
        docker.stores.setdefault(where, {})[key] = newer.encode()

    docker.race_record(box, path, clear_and_retake)
    try:
        lock.release(store, name, token)
    except (lock.Held, lock.WrongToken):
        pass          # refusing is fine: the old holder no longer holds it

    assert store.read(name) == newer, store.read(name)
    assert not docker.unmodelled, f"a gap in the rig docker (repair the fake): {docker.unmodelled}"


def test_a_release_on_the_lab_store_frees_the_holders_own_record(lock):
    """Control for the race test: with no one racing, the holder's release frees the lock and a new take works."""
    store, docker, _box = _rig_lab_store(lock)
    token = lock.take(store, lock.CAPTURE)
    lock.release(store, lock.CAPTURE, token)

    assert store.read(lock.CAPTURE) is None
    assert lock.take(store, lock.CAPTURE)
    assert not docker.unmodelled, docker.unmodelled


def test_the_lab_store_deletes_only_the_holders_record_in_one_step(lock, tmp_path):
    """r6.4.3 finding 9: on the lab store (a real shell), the check-and-delete keeps another holder's
    record, removes the holder's own, and `release` reaches the lab in exactly one exec."""
    store, box = _docker_store(lock, tmp_path)
    mine = lock.take(store, lock.FROZEN_ENGINE)
    assert store.delete_if_held_by(lock.FROZEN_ENGINE, "f" * 32) is False
    assert mine in store.read(lock.FROZEN_ENGINE)
    before = len(box.argvs)
    lock.release(store, lock.FROZEN_ENGINE, mine)
    assert store.read(lock.FROZEN_ENGINE) is None
    assert len(box.argvs) - before - 1 == 1, box.argvs[before:]      # the release's exec, then the read above
