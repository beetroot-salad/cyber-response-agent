"""#1347 O10/D14: the lab-server lock token. Entry points bound by this contract:

* `chaos/lock.py` (new): `take(store, name, *, clock=time.time) -> token`,
  `release(store, name, token)`, `require(store, name, token=None)`, `clear(store, name)`,
  exceptions `Held` and `WrongToken`, names `CAPTURE = "capture"` and `FROZEN_ENGINE =
  "frozen-engine"`, and `DockerLockStore(run=subprocess.run)`. A store offers
  `create_exclusive(name, record) -> bool`, `read(name) -> str | None`, `delete(name)`.
* `attacks/runner.py::run_scenario(..., lock_store=None, lock_token=None)` and
  `cmd_run(args, ..., lock_store=None)` with a `--lock-token` flag; `None` = no check at the
  library level, `cmd_run` supplies a `DockerLockStore()` by default.
* `chaos/ctl.py::activate(..., lock_store=None, lock_token=None)` and `activate --lock-token`;
  the CLI (`ctl.main(["activate", ...])`) calls `ctl.activate` with `lock_store=` a
  `DockerLockStore()` and `lock_token=` the flag's value.
* Bound argv convention: `DockerLockStore` talks to the lab through
  `docker --context <ctx> exec [-i] <container> <command...>` (stdin allowed). A docker-exec
  transport failure (rc 1/125) must raise, so "absent" / "held" must be signalled by a stdout
  marker or a different exit code, never rc 1.
"""
from __future__ import annotations

import contextlib
import importlib.util
import re
import threading
from pathlib import Path

import pytest
import yaml
from _lab_fakes import FakeLockStore, LocalContainer

PLAYGROUND = Path(__file__).resolve().parents[2]
RUNNER = PLAYGROUND / "attacks" / "runner.py"
SCENARIO = {"id": "ssh-brute-force-canary", "category": "auth-metadata",
            "description": "fixture\n", "target_host": "web-1", "source_host": "dev-ws-1",
            "default_intensity": 1, "steps": [{"cmd": "true"}]}


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
    store = FakeLockStore()
    token = lock.take(store, lock.CAPTURE)
    assert token and token in store.records[lock.CAPTURE]
    assert store.journal.ops().count("lock.create") == 1
    assert lock.take(FakeLockStore(), lock.CAPTURE) != token, "tokens must be random"


def test_tokens_are_long_random_hex_not_derived_from_the_clock(lock):
    """D14: a token is unguessable: 32+ characters, different for takes at the same instant."""
    tokens = [lock.take(FakeLockStore(), lock.CAPTURE, clock=lambda: 1_700_000_000.0) for _ in range(2)]
    assert tokens[0] != tokens[1]
    for token in tokens:
        assert len(token) >= 32, token


def test_taking_a_held_lock_is_refused_and_leaves_the_record_alone(lock):
    """D14: a second take raises Held and does not overwrite the holder's record."""
    store = FakeLockStore()
    lock.take(store, lock.CAPTURE)
    before = dict(store.records)
    with pytest.raises(lock.Held):
        lock.take(store, lock.CAPTURE)
    assert store.records == before


def test_racing_takes_grant_the_lock_to_exactly_one_taker(lock):
    """D14: the take is atomic; of many concurrent takers exactly one gets a token."""
    store, won, lost = FakeLockStore(), [], []

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
    store = FakeLockStore()
    lock.take(store, lock.CAPTURE, clock=lambda: 946684800.0)  # year 2000
    with pytest.raises(lock.Held):
        lock.take(store, lock.CAPTURE, clock=lambda: 4102444800.0)  # year 2100
    lock.clear(store, lock.CAPTURE)
    assert lock.take(store, lock.CAPTURE)


def test_release_needs_the_holders_token(lock):
    """D14: releasing with another token is refused and keeps the lock; the right token frees."""
    store = FakeLockStore()
    token = lock.take(store, lock.CAPTURE)
    with pytest.raises(lock.WrongToken):
        lock.release(store, lock.CAPTURE, "not-the-token")
    assert lock.CAPTURE in store.records
    lock.release(store, lock.CAPTURE, token)
    assert lock.CAPTURE not in store.records


def test_the_capture_and_frozen_engine_locks_are_independent(lock):
    """D14: the frozen engine's run lock is the same mechanism under its own name."""
    store = FakeLockStore()
    lock.take(store, lock.CAPTURE)
    assert lock.take(store, lock.FROZEN_ENGINE)


@pytest.mark.parametrize("record", ["not json", "[]", ""], ids=["garbage", "list", "empty"])
def test_an_empty_token_never_opens_a_record_that_cannot_be_read(lock, record):
    """D14: `--lock-token ""` is not the holder's token for an unreadable record: require and
    release refuse and the record stays."""
    store = FakeLockStore()
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


def _run(runner, tmp_path, rec, store, token=None, chaos="none"):
    return runner.run_scenario(SCENARIO, 42, {}, False, runs_dir=tmp_path / "runs",
                               chaos=chaos, chaos_ctl=rec, exec_fn=rec.exec_fn,
                               post_cr=lambda body: (0, {}), lock_store=store, lock_token=token)


def test_the_runner_refuses_while_the_capture_lock_is_held(runner, lock, tmp_path):
    """O10: with the lock held and no token nothing is dispatched, no fault is applied and no
    run dir is written; the lock stays held."""
    store, rec = FakeLockStore(), Recorder()
    lock.take(store, lock.CAPTURE)
    with pytest.raises(SystemExit):
        _run(runner, tmp_path, rec, store, chaos="some-profile")
    assert rec.execs == [] and rec.chaos == []
    assert not (tmp_path / "runs").exists() or not any((tmp_path / "runs").iterdir())
    assert lock.CAPTURE in store.records


def test_the_runner_refuses_a_wrong_token_and_fires_with_the_right_one(runner, lock, tmp_path):
    """O10: only the holder's token passes; a free lock needs none."""
    store, rec = FakeLockStore(), Recorder()
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

    store = FakeLockStore()
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
    store, execer = FakeLockStore(), RecordingExecer()
    lock.take(store, lock.CAPTURE)
    with pytest.raises(lock.Held):
        ctl.activate("cmdb-stale-owner", seed=1, execer=execer, ledger_dir=tmp_path,
                     lock_store=store, lock_token=None)
    assert execer.calls == [] and list(tmp_path.iterdir()) == []


def test_chaos_activate_proceeds_for_the_holder_and_for_a_free_lock(lock, tmp_path):
    """O10 control: the holder's token (or no lock) reaches the lab (the fake then errors)."""
    from chaos import ctl
    from chaos.seam import SeamError
    store = FakeLockStore()
    token = lock.take(store, lock.CAPTURE)
    for tok in (token,):
        execer = RecordingExecer()
        with pytest.raises(SeamError):
            ctl.activate("cmdb-stale-owner", seed=1, execer=execer, ledger_dir=tmp_path,
                         lock_store=store, lock_token=tok)
        assert execer.calls
    lock.release(store, lock.CAPTURE, token)
    execer = RecordingExecer()
    with pytest.raises(SeamError):
        ctl.activate("cmdb-stale-owner", seed=1, execer=execer, ledger_dir=tmp_path,
                     lock_store=store)
    assert execer.calls


def test_chaos_activate_refuses_a_wrong_token_without_touching_the_lab(lock, tmp_path):
    """O10: a token that is not the holder's is refused before any exec-seam traffic."""
    from chaos import ctl
    store, execer = FakeLockStore(), RecordingExecer()
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


def test_chaos_activate_cli_without_an_injected_store_checks_the_lab_server_lock(
        lock, monkeypatch, capsys):
    """O10/D14 (FR2): `ctl.main(["activate", ...])` passes activate a DockerLockStore and the
    flag's token; nothing is injected."""
    from chaos import ctl
    seen: dict = {}

    def fake_activate(profile_id, **kwargs):
        seen.update(kwargs)
        return {"ledger_ref": "r-1"}

    monkeypatch.setattr(ctl, "activate", fake_activate)
    assert ctl.main(["activate", "cmdb-stale-owner", "--lock-token", "T-9"]) == 0
    assert isinstance(seen.get("lock_store"), lock.DockerLockStore)
    assert seen["lock_token"] == "T-9"
