"""The create lane (`_io.write_guarded(mode='create')`): its fallback where no unnamed file can be made; a linked tenant folder is refused."""
from __future__ import annotations


import errno
import json
import os
import random
import signal
import stat
import subprocess
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from defender.tests.support.shared.contracts._create_lane import assert_single_plain, no_unnamed_files
from defender.tests.support.shared.filesystem._umask import umask
from defender.tests.tenancy.tenant_1078_pass_a import _spec1078 as H

T_ID = H.VALID_ID


#: Why the create lane's mode is pinned at all: a staged-name sketch (`tempfile.mkstemp`)
#: regressed it to 0600 whatever the umask.
_WHY_0644 = "C-R6 found the naive staged shape regressing to 0600"


def _race(n: int, fn) -> tuple[list, list]:
    """Release `n` callers of `fn` together behind one Barrier. Returns (results, exceptions)."""
    gate = threading.Barrier(n)
    results: list = []
    errors: list = []
    lock = threading.Lock()

    def one() -> None:
        gate.wait(timeout=30)
        try:
            got = fn()
        except BaseException as e:  # noqa: BLE001 - classified by the caller
            with lock:
                errors.append(e)
            return
        with lock:
            results.append(got)

    threads = [threading.Thread(target=one) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    return results, errors


_FIELDS = ("tenant_id", "created_at")
_BODY = json.dumps({"tenant_id": T_ID, "created_at": "2026-01-01T00:00:00Z", "pad": "x" * 4096}) + "\n"


def _complete(path: Path) -> bool:
    try:
        return _complete_bytes(path.read_bytes())
    except OSError:
        return False


class _Bystander:
    """A reader polling one path while writers race to create it; it judges only what it sees:
    absent, or a single-named regular file with a complete JSON body. Anything else is a violation."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.violations: list[str] = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run)

    def _look(self) -> None:
        try:
            st = os.lstat(self.path)
        except FileNotFoundError:
            return
        if not stat.S_ISREG(st.st_mode):
            self.violations.append(f"not a regular file (mode {oct(st.st_mode)})")
            return
        if st.st_nlink != 1:
            self.violations.append(f"two-named window: st_nlink={st.st_nlink}")
        try:
            data = self.path.read_bytes()
        except FileNotFoundError:
            self.violations.append("the name vanished after it appeared")
            return
        if not data:
            self.violations.append("an EMPTY file at the name")
        elif not _complete_bytes(data):
            self.violations.append(f"a partial or incomplete body at the name: {data[:60]!r}")

    def _run(self) -> None:
        while not self._stop.is_set():
            self._look()

    def __enter__(self) -> _Bystander:
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        self._stop.set()
        self._thread.join(timeout=30)
        self._look()


def _complete_bytes(data: bytes) -> bool:
    try:
        doc = json.loads(data)
    except ValueError:
        return False
    return isinstance(doc, dict) and all(f in doc for f in _FIELDS)


#: The crash child loops over the real create lane in fresh directories until it is killed.
_CRASH_CHILD = r"""
import sys
from pathlib import Path
from defender import _io
root = Path(sys.argv[1])
body = sys.argv[2]
print("ready", flush=True)
i = 0
while True:
    d = root / f"d{i}"
    d.mkdir()
    _io.write_guarded(d / "x.json", body, mode="create")
    i += 1
"""


def test_s7_j16_create_lane_complete_or_absent(tmp_path):
    """Racing `write_guarded(mode="create")` writers: one winner, a polling reader never sees an empty or partial
    file or a second name, mode 0644 under umask 022, and a killed writer leaves no stray entry."""
    io_mod = H.mod("_io")
    with umask(0o022):
        for trial in range(20):
            root = tmp_path / "race" / f"d{trial}"
            root.mkdir(parents=True)
            target = root / "x.json"
            with _Bystander(target) as reader:
                results, errors = _race(6, lambda t=target: io_mod.write_guarded(t, _BODY, mode="create"))
            assert len(results) == 1, f"trial {trial}: {len(results)} creates of one name succeeded"
            assert len(errors) == 5
            assert all(isinstance(e, FileExistsError) for e in errors), (
                f"trial {trial}: a losing create escaped with {[type(e).__name__ for e in errors]}")
            assert reader.violations == [], f"trial {trial}: the bystander saw {reader.violations}"
            assert os.listdir(root) == ["x.json"], f"trial {trial}: stray entries beside the file"
            assert target.read_text(encoding="utf-8") == _BODY
            assert_single_plain(target, 0o644, why=_WHY_0644)

    env = dict(os.environ)
    env["PYTHONPATH"] = f"{H.REPO_ROOT}{os.pathsep}{env.get('PYTHONPATH', '')}".rstrip(os.pathsep)

    def crash_one(kill: int) -> list[str]:
        root = tmp_path / "crash" / f"k{kill}"
        root.mkdir(parents=True)
        child = subprocess.Popen(  # noqa: S603 - fixed argv, the test's own interpreter
            [sys.executable, "-c", _CRASH_CHILD, str(root), _BODY], env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            if child.stdout.readline().strip() != "ready":
                return [f"kill {kill}: child did not say ready: {child.stderr.read()}"]
            time.sleep(random.uniform(0.02, 0.25))
            if child.poll() is not None:
                return [f"kill {kill}: the child died on its own: {child.stderr.read()}"]
            child.send_signal(signal.SIGKILL)
        finally:
            child.wait(timeout=30)
            child.stdout.close()
            child.stderr.close()
        bad = []
        for d in sorted(root.iterdir()):
            names = sorted(os.listdir(d))
            if names not in ([], ["x.json"]):
                bad.append(f"kill {kill} {d.name}: stray entries {names}")
            elif names and not _complete(d / "x.json"):
                bad.append(f"kill {kill} {d.name}: a torn file {(d / 'x.json').read_bytes()[:40]!r}")
        return bad

    with ThreadPoolExecutor(max_workers=4) as pool:
        torn = [entry for found in pool.map(crash_one, range(8)) for entry in found]
    assert torn == [], "a crash left a torn or stray entry:\n" + "\n".join(torn)


@pytest.mark.parametrize("unsupported", [errno.EOPNOTSUPP, errno.EISDIR, errno.EINVAL])
def test_create_falls_back_where_no_unnamed_file_can_be_made(tmp_path, unsupported):
    io_mod = H.mod("_io")
    target = tmp_path / "x.json"
    io_mod.write_guarded(target, "{}\n", mode="create", open_unnamed=no_unnamed_files(unsupported))
    assert target.read_text(encoding="utf-8") == "{}\n"
    with pytest.raises(FileExistsError) as again:
        io_mod.write_guarded(target, "{}\n", mode="create",
                             open_unnamed=no_unnamed_files(unsupported))
    assert not getattr(again.value, "write_guarded_alias", False), "the race read as an alias"

    control = tmp_path / "y.json"
    with umask(0o022):
        io_mod.write_guarded(control, "{}\n", mode="create")
    assert_single_plain(control, 0o644, why=_WHY_0644)


def test_create_does_not_swallow_an_unrelated_failure(tmp_path):
    io_mod = H.mod("_io")
    target = tmp_path / "x.json"
    with pytest.raises(OSError, match="No space") as failed:
        io_mod.write_guarded(target, "{}\n", mode="create",
                             open_unnamed=no_unnamed_files(errno.ENOSPC))
    assert failed.value.errno == errno.ENOSPC
    assert not target.exists()


def test_tenant_folder_symlink_swapped_between_o11as_construction_time_check_and_first_write(
        tmp_path):
    """A linked `<root>/T` is refused by acceptance and the link's target is left as it was (#1214 O6: nothing is
    created, so no create to write through the link)."""
    elsewhere = tmp_path / "elsewhere"
    H.place_knowledge(elsewhere, T_ID)
    root = tmp_path / "data"
    root.mkdir()
    (root / T_ID).symlink_to(elsewhere / T_ID, target_is_directory=True)
    before = H.census(elsewhere)
    H.owner_refusal(H.accept, root, T_ID)
    assert H.census(elsewhere) == before, "acceptance wrote through a symlinked tenant folder"
    assert os.readlink(root / T_ID) == str(elsewhere / T_ID), "the planted link was replaced"
    fresh = tmp_path / "fresh"
    H.place_knowledge(fresh, T_ID)
    assert H.accept(fresh, T_ID).id == T_ID
