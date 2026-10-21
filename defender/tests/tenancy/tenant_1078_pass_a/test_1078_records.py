"""The runs-base record _tenant.json: grammar on read, ensure/mint semantics, complete-or-absent create lane, torn reads, mismatch backstop."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_data_root

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


def _race(n: int, fn) -> tuple[list, list]:
    """Release `n` callers of `fn` together behind one Barrier (C-P2's shape). Returns
    (results, exceptions)."""
    gate = threading.Barrier(n)
    results: list = []
    errors: list = []
    lock = threading.Lock()

    def one() -> None:
        gate.wait(timeout=30)
        try:
            got = fn()
        except BaseException as e:  # noqa: BLE001 — classified by the caller
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


class _Bystander:
    """A reader polling one path while writers race to create it. It judges only what it SEES:
    absent, or a single-named regular file whose body is a complete JSON object carrying
    `fields`. Anything else — an empty file, a partial body, a second name — is a violation."""

    def __init__(self, path: Path, fields: tuple[str, ...]) -> None:
        self.path = path
        self.fields = fields
        self.violations: list[str] = []
        self.saw_complete = 0
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
            return
        try:
            doc = json.loads(data)
        except ValueError:
            self.violations.append(f"a PARTIAL body at the name: {data[:60]!r}")
            return
        if not isinstance(doc, dict) or any(f not in doc for f in self.fields):
            self.violations.append(f"an incomplete document at the name: {doc!r}")
            return
        self.saw_complete += 1

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


#: Why a create-lane record's mode is pinned at all: the first staged-name sketch of J16's lane
#: (`tempfile.mkstemp`) regressed it to 0600 whatever the umask.
_WHY_0644 = "C-R6 found the naive staged shape regressing to 0600"


#: The crash child: it loops over ONE real create lane in fresh directories until it is
#: killed. Measured on the old one-open lane, a kill landed inside the runs-base record's create
#: window in 8/40 (record-only loop) but 0/40 for the row (create_tenant's own listing and mkdir
#: dominate its loop) — so the row lane left here is a stray-entry check with weak odds of a torn
#: hit (red-flagged in the author digest). #1187 R1 retired the record lane with the record.
_CRASH_CHILD = {
    "row": r"""
import sys
from pathlib import Path
from defender.tenancy import _tenant
root = Path(sys.argv[1])
print("ready", flush=True)
i = 0
while True:
    _tenant.create_tenant(_tenant.data_root_from_path(root / f"d{i}"), sys.argv[2])
    i += 1
""",
}


def _complete(path: Path, fields: tuple[str, ...]) -> bool:
    try:
        doc = json.loads(path.read_bytes())
    except (OSError, ValueError):
        return False
    return isinstance(doc, dict) and all(f in doc for f in fields)


def _crash_leftovers(root: Path) -> list[str]:
    """Every directory the killed child touched: absent-or-complete, and nothing else."""
    bad: list[str] = []
    for d in sorted(root.iterdir()):
        names = sorted(os.listdir(d))
        if names not in ([], [T_ID]):
            bad.append(f"{d.name}: stray entries {names}")
            continue
        inner = sorted(os.listdir(d / T_ID)) if names else []
        if inner not in ([], [H.ROW_NAME]):
            bad.append(f"{d.name}/{T_ID}: stray entries {inner}")
        elif inner and not _complete(d / T_ID / H.ROW_NAME, ("tenant_id", "created_at")):
            bad.append(f"{d.name}: a torn row {(d / T_ID / H.ROW_NAME).read_bytes()[:40]!r}")
    return bad


# ======================================================================================
# The create lane (J16/J63). #1187 R1 (declared change 6) retired the runs-base record, and
# with it `ensure_runs_base_record`'s semantics (D1), its create race (O6), the record's read
# grammar (O3), its torn read, and `Run.for_tenant`'s mismatch backstop (J34) and rekey
# coherence (G-R7) — replaced by `ids_1187/test_1187_layout_isolation.py`
# (`test_create_makes_the_runs_folder_and_writes_no_tenant_record`,
# `test_a_container_with_no_record_opens_lists_and_hands_out_every_run`,
# `test_the_listing_refuses_a_tenant_record_or_an_episodes_folder`).
# ======================================================================================

def test_s7_j16_create_lane_complete_or_absent(tmp_path):
    """A reader that catches a create-lane writer (create_tenant's tenant row) mid-write sees
    the name absent or the file complete, never empty or partial; the file has exactly one name
    throughout (no two-named alias window), mode 0644 under umask 022 (and the writing
    process's owner), and a crash before the write completes leaves no stray entry in the
    directory."""
    with umask(0o022):
        # (2) + (3) the tenant row
        row_fields = ("tenant_id", "created_at")
        for trial in range(20):
            root = tmp_path / "rows" / f"d{trial}"
            root.parent.mkdir(parents=True, exist_ok=True)
            with _Bystander(root / T_ID / H.ROW_NAME, row_fields) as reader:
                results, errors = _race(6, lambda r=root: H.create_tenant(fixture_data_root(r), T_ID))
            assert len(results) == 1, f"trial {trial}: {len(results)} creates of one row succeeded"
            assert all(isinstance(e, H.tenant().TenantRefused) for e in errors), (
                f"trial {trial}: a losing create escaped with {[type(e).__name__ for e in errors]}")
            assert reader.violations == [], f"trial {trial}: the bystander saw {reader.violations}"
            assert os.listdir(root) == [T_ID], f"trial {trial}: stray entries in the root"
            assert os.listdir(root / T_ID) == [H.ROW_NAME], f"trial {trial}: stray beside the row"
            assert_single_plain(root / T_ID / H.ROW_NAME, 0o644, why=_WHY_0644)

    # (4) the crash
    crash_root = tmp_path / "crash"
    env = H.setup_env(None)
    def crash_one(lane: str, kill: int) -> list[str]:
        root = crash_root / f"{lane}-{kill}"
        root.mkdir(parents=True)
        child = subprocess.Popen(  # noqa: S603 — fixed argv, the test's own interpreter
            [sys.executable, "-c", _CRASH_CHILD[lane], str(root), T_ID], env=env,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            ready = child.stdout.readline().strip()
            if ready != "ready":
                return [f"{lane} kill {kill}: child did not say ready: {child.stderr.read()}"]
            time.sleep(random.uniform(0.02, 0.25))
            if child.poll() is not None:
                return [f"{lane} kill {kill}: the create-lane child died on its own: "
                        f"{child.stderr.read()}"]
            child.send_signal(signal.SIGKILL)
        finally:
            child.wait(timeout=30)
            child.stdout.close()
            child.stderr.close()
        return [f"{lane} kill {kill}: {b}" for b in _crash_leftovers(root)]

    # The 32 kills are independent (own dir, own child), so they run a few at a time: each is
    # mostly interpreter start-up and a sleep.
    jobs = [(lane, kill) for lane, kills in (("row", 8),) for kill in range(kills)]
    with ThreadPoolExecutor(max_workers=4) as pool:
        torn = [entry for found in pool.map(lambda j: crash_one(*j), jobs) for entry in found]
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
    victim = tmp_path / "victim"
    victim.mkdir()
    root = tmp_path / "data"
    root.mkdir()
    (root / T_ID).symlink_to(victim, target_is_directory=True)
    H.owner_refusal(H.create_tenant, root, T_ID)
    assert os.listdir(victim) == [], "create_tenant wrote through a symlinked tenant folder"
    assert os.readlink(root / T_ID) == str(victim), "the planted link was replaced"
    fresh = tmp_path / "fresh"
    H.create_tenant(fixture_data_root(fresh), T_ID)
    assert (fresh / T_ID / H.ROW_NAME).is_file()
