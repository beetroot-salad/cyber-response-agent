"""#1618 K2: readers in real processes, through the production launcher, while main advances and a sweeper loops."""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.tenancy.knowledge_1618 import _slice_a as A
from defender.tests.tenancy.knowledge_1618 import _support as K
from defender.tests.tenancy.tenant_1108_delivery._support import IMPORT_ROOT, git

READERS = 4

CALLER = '''
import json, os, subprocess, sys, time
from pathlib import Path
spec = json.loads(Path(sys.argv[1]).read_text())
from defender.tests.tenancy.knowledge_1618 import _slice_a as A
from defender.tests.tenancy.knowledge_1618 import _support as K
dest = K.owned_dest(Path(spec["run_knowledge"]), "k2")
Path(spec["ready"]).write_text(json.dumps({"pid": os.getpid(), "dest": str(dest)}))
while not Path(spec["go"]).exists():
    time.sleep(0.01)
tip = lambda: subprocess.run(["git", "-C", spec["remote"], "rev-parse", "refs/heads/main"], capture_output=True, text=True).stdout.strip()
before = tip()
line = A.launcher()(spec["tenant_id"], data_root=Path(spec["data_root"]), dest=dest, commit=spec["commit"], budget=120.0, command=spec["command"])
Path(spec["result"]).write_text(json.dumps({"before": before, "after": tip(), "line": line, "dest": str(dest)}))
while not Path(spec["release"]).exists():
    time.sleep(0.05)
'''

SWEEPER = '''
import json, sys, time
from pathlib import Path
spec = json.loads(Path(sys.argv[1]).read_text())
from defender.tests.tenancy.knowledge_1618 import _support as K
from types import SimpleNamespace
t = SimpleNamespace(data_root=Path(spec["data_root"]), tenant_id=spec["tenant_id"])
from defender.tests.tenancy.knowledge_1618 import _slice_a as A
done = 0
seen, bad = set(), set()
while not Path(spec["stop"]).exists():
    try:
        K.sweep(t)
    except BaseException as e:
        Path(spec["errors"]).write_text(repr(e))
        raise
    owned, unowned = A.scan_run_copies(Path(spec["run_knowledge"]))
    seen.update(owned)
    bad.update(unowned)
    Path(spec["watched"]).write_text(json.dumps({"owned": sorted(seen), "unowned": sorted(bad)}))
    done += 1
    Path(spec["count"]).write_text(str(done))
    time.sleep(0.01)
'''


def _spawn(script: Path, spec: Path) -> subprocess.Popen:
    env = {**os.environ, "PYTHONPATH": str(IMPORT_ROOT)}
    return subprocess.Popen([sys.executable, str(script), str(spec)], cwd=IMPORT_ROOT, env=env,  # noqa: S603
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)


def _wait(path: Path, procs, what: str) -> None:
    deadline = time.monotonic() + 120
    while not path.exists() and time.monotonic() < deadline:
        for p in procs:
            if p.poll() not in (None, 0):
                raise AssertionError(f"{what}: process died: {p.stderr.read().decode(errors='replace')[-1500:]}")
        time.sleep(0.02)
    assert path.exists(), what


def _run_processes(t, tmp_path: Path, command: list[str]) -> list:
    """Two real run processes: each renames its copy into place while the sweeper watches from outside (F1, K7)."""
    made = []
    for i in range(2):
        (tmp_path / f"run{i}").mkdir()
        made.append(A.start_run_process(t, tmp_path / f"run{i}", command))
    return made


def _sweeper_sweeps_three_more_times(tmp_path: Path) -> None:
    before = int((tmp_path / "count").read_text())
    deadline = time.monotonic() + 30
    while int((tmp_path / "count").read_text()) < before + 3 and time.monotonic() < deadline:
        time.sleep(0.05)
    assert not (tmp_path / "errors").exists(), (tmp_path / "errors").read_text()
    assert int((tmp_path / "count").read_text()) >= before + 3, "the sweeper stopped sweeping"


def _assert_no_renamed_copy_was_ever_unowned(tmp_path: Path) -> None:
    """F1/A4, observed from outside: the sweeper process saw renamed run copies, and never one without an owner record."""
    watched = json.loads((tmp_path / "watched").read_text())
    assert len(watched["owned"]) >= 2, f"control: the watcher saw no renamed run copy: {watched}"
    assert watched["unowned"] == [], f"a renamed run copy was seen with no owner record: {watched}"
    probe = tmp_path / "probe"
    (probe / "a-final-name").mkdir(parents=True)
    assert A.scan_run_copies(probe) == ([], ["a-final-name"]), "control: the watcher misses an unowned copy"


def test_a16_concurrent_readers_all_succeed_each_at_a_tip_of_its_own_fetch_and_a_live_owners_copy_is_never_swept(t, tmp_path):
    """Four unpinned and one pinned reader process, main advancing, a sweeper process looping: each copy is the commit its fetch saw, kept while its caller lives (K2, K7)."""
    pinned = K.advance_main(t, "K1618-PIN")
    command = A.child_command(t, tmp_path)
    go, release, stop = tmp_path / "go", tmp_path / "release", tmp_path / "stop"
    root = str(location_path(t.data_root))
    script = tmp_path / "caller.py"
    script.write_text(CALLER, encoding="utf-8")
    callers = []
    for i in range(READERS + 1):
        spec = tmp_path / f"caller{i}.json"
        spec.write_text(json.dumps({
            "run_knowledge": str(A.run_copies(t)), "ready": str(tmp_path / f"ready{i}"), "go": str(go),
            "result": str(tmp_path / f"result{i}"), "release": str(release), "remote": str(t.remote),
            "tenant_id": t.tenant_id, "data_root": root, "command": command,
            "commit": pinned if i == READERS else None}), encoding="utf-8")
        callers.append(_spawn(script, spec))
    sweep_script = tmp_path / "sweeper.py"
    sweep_script.write_text(SWEEPER, encoding="utf-8")
    sspec = tmp_path / "sweeper.json"
    sspec.write_text(json.dumps({"data_root": root, "tenant_id": t.tenant_id, "stop": str(stop),
                                 "run_knowledge": str(A.run_copies(t)), "watched": str(tmp_path / "watched"),
                                 "count": str(tmp_path / "count"), "errors": str(tmp_path / "errors")}), encoding="utf-8")
    sweeper = _spawn(sweep_script, sspec)
    runs: list = []
    try:
        for i in range(READERS + 1):
            _wait(tmp_path / f"ready{i}", callers, f"caller {i} ready")
        _wait(tmp_path / "count", [sweeper], "sweeper started")
        runs.extend(_run_processes(t, tmp_path, command))
        history = [t.origin_main()]
        advancing = threading.Event()

        def advance() -> None:
            while not advancing.is_set() and len(history) < 12:
                history.append(K.advance_main(t, f"K1618-ADV-{len(history)}"))

        thread = threading.Thread(target=advance)
        go.write_text("go")
        thread.start()
        for i in range(READERS + 1):
            _wait(tmp_path / f"result{i}", callers, f"caller {i} result")
        advancing.set()
        thread.join(120)
        _sweeper_sweeps_three_more_times(tmp_path)
        _assert_no_renamed_copy_was_ever_unowned(tmp_path)
        results = [json.loads((tmp_path / f"result{i}").read_text()) for i in range(READERS + 1)]
        for i, got in enumerate(results):
            assert got["line"].startswith("ok "), got
            commit = got["line"].split()[1]
            if i == READERS:
                assert commit == pinned
            else:
                window = git(t.remote, "rev-list", f"{got['before']}..{got['after']}").split() + [got["before"]]
                assert commit in window, (commit, got)
            dest = Path(got["dest"])
            assert K.tree_bytes(dest / "agent") == K.half_at(t, commit, "agent"), i
            assert K.tree_bytes(dest / "settings") == K.half_at(t, commit, "settings"), i
        dests = [Path(r["dest"]) for r in results]
        assert all(d.is_dir() for d in dests), "a live owner's copy was swept"
        callers[0].send_signal(signal.SIGKILL)
        callers[0].wait(timeout=30)
        K.sweep(t)
        assert not dests[0].exists(), "control: the killed caller's copy is swept"
        assert all(d.is_dir() for d in dests[1:]), "a live owner's copy was swept"
    finally:
        release.write_text("x")
        stop.write_text("x")
        for p in (*callers, sweeper, *(proc for proc, _dir in runs)):
            p.kill()


TOOL = '''
import json, os, subprocess, sys, time
from pathlib import Path
from types import SimpleNamespace
spec = json.loads(Path(sys.argv[1]).read_text())
from defender.learning.frontend import serialize
from defender.tests.support.shared.contracts._data_root_1078 import tenant_directory
from defender.tests.tenancy.knowledge_1618 import _support as K
tip = lambda: subprocess.run(["git", "-C", spec["remote"], "rev-parse", "refs/heads/main"], capture_output=True, text=True).stdout.strip()
inner = K.Fetch(SimpleNamespace(origin=spec["origin"], tenant_id=spec["tenant_id"]), Path(spec["work"]))
seen = {}


def fetch(tenant_id, dest, *, data_root, commit=None, **_kw):
    seen["before"] = tip()
    line = inner(tenant_id, dest, data_root=data_root, commit=commit)
    seen["after"], seen["line"] = tip(), line
    if line.startswith("ok "):
        for half in ("agent", "settings"):
            seen[half] = {k: v.decode() for k, v in K.tree_bytes(Path(dest) / half).items()}
    return line


Path(spec["ready"]).write_text(str(os.getpid()))
while not Path(spec["go"]).exists():
    time.sleep(0.01)
directory = tenant_directory(Path(spec["data_root"]), spec["tenant_id"], origin=spec["origin"])
rc = serialize.main(["lessons_page.py", "--tenant", spec["tenant_id"]], directory=directory, fetch=fetch)
Path(spec["result"]).write_text(json.dumps({**seen, "rc": rc}))
'''


def test_a16_readers_of_several_kinds_start_at_once_while_main_advances_each_with_the_commit_its_own_fetch_reported(t, tmp_path):
    """Two run starts (the production launcher) and two operator tools (the lessons page) start together while main advances: each succeeds with the tip its own fetch saw (K2). The helper copy is `test_job_helper_learning::test_1618_k2_*`."""
    command = A.child_command(t, tmp_path)
    root = str(location_path(t.data_root))
    go = tmp_path / "go"
    caller, tool = tmp_path / "caller.py", tmp_path / "tool.py"
    caller.write_text(CALLER, encoding="utf-8")
    tool.write_text(TOOL, encoding="utf-8")
    procs, kinds = [], []
    for i, (script, kind) in enumerate([(caller, "run"), (tool, "tool"), (caller, "run"), (tool, "tool")]):
        spec = tmp_path / f"spec{i}.json"
        spec.write_text(json.dumps({
            "run_knowledge": str(A.run_copies(t)), "ready": str(tmp_path / f"ready{i}"), "go": str(go),
            "result": str(tmp_path / f"result{i}"), "release": str(tmp_path / "release"), "remote": str(t.remote),
            "tenant_id": t.tenant_id, "origin": t.origin, "data_root": root, "command": command, "commit": None,
            "work": str(tmp_path / f"work{i}")}), encoding="utf-8")
        procs.append(_spawn(script, spec))
        kinds.append(kind)
    try:
        for i in range(len(procs)):
            _wait(tmp_path / f"ready{i}", procs, f"reader {i} ready")
        history = [t.origin_main()]
        advancing = threading.Event()

        def advance() -> None:
            while not advancing.is_set() and len(history) < 12:
                history.append(K.advance_main(t, f"K1618-ADV-{len(history)}"))

        thread = threading.Thread(target=advance)
        go.write_text("go")
        thread.start()
        for i in range(len(procs)):
            _wait(tmp_path / f"result{i}", procs, f"reader {i} result")
        advancing.set()
        thread.join(120)
        for i, kind in enumerate(kinds):
            got = json.loads((tmp_path / f"result{i}").read_text())
            line = got["line"]
            assert line.startswith("ok "), got
            commit = line.split()[1]
            window = git(t.remote, "rev-list", f"{got['before']}..{got['after']}").split() + [got["before"]]
            assert commit in window, f"{kind} {i}: its copy is a commit that was not a tip during its fetch: {got}"
            if kind == "tool":
                assert got["rc"] == 0, got
                assert got["agent"] == {k: v.decode() for k, v in K.half_at(t, commit, "agent").items()}, i
                assert got["settings"] == {k: v.decode() for k, v in K.half_at(t, commit, "settings").items()}, i
            else:
                dest = Path(got["dest"])
                assert K.tree_bytes(dest / "agent") == K.half_at(t, commit, "agent"), i
    finally:
        (tmp_path / "release").write_text("x")
        for p in procs:
            p.kill()
