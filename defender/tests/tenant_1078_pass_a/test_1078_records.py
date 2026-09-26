"""#1078 pass (A) — the runs-base RECORD, `<runs_base>/_tenant.json` (D1, D2, O6; §7 J16/J63, J34).

The record keeps #1077's name and fields (`{tenant_id, base_world_id, created_at}`); what
changes is who decides its tenant. `ensure_tenant(runs_base)` becomes
`ensure_runs_base_record(runs_base, tenant_id)`: it mints the record with the REQUEST's id, or
reads it back and refuses on disagreement — never overwrites. `_parse_record` gains the grammar.

§7 J16/J63 (human, COMPLETE-OR-ABSENT WRITES) is pinned here as an OBSERVABLE, never as a
mechanism: a reader that catches a create-lane writer mid-write sees the name absent or the file
complete, never empty or partial; the file has one name throughout; mode 0644 and the writer's
owner; a crash leaves no stray entry. Every fault is the REAL one:

* the create race — N `threading.Barrier`-released callers on a fresh base — is claim C-P2's own
  probe shape (47-probes.md: on the old one-open lane a loser read the winner's EMPTY record in
  9-35% of trials at 2/3/5/8 siblings, and the `TenantRecordCorrupt` propagated uncaught);
* the bystander reader lstat()s and reads the real path while the race runs — an empty file,
  a partial body or a second name (`st_nlink == 2`, the REFUTED hard-link window of C-R5, which
  this tree's own alias guard refuses as a planted alias) is recorded as a violation;
* the crash is a real SIGKILL of a real child process looping over the real create lane —
  measured before authoring against the old lane (`ensure_tenant`, the same one-open create):
  8 of 30 kills left an EMPTY `_tenant.json` behind, the torn state this demand forbids.

`hooks/record_lead.py::claim_lead` is OUT of J16's scope (the demand's `scope_exclusions`,
C-R29..C-R33) and is not driven here.
"""
from __future__ import annotations

import json
import os
import random
import signal
import stat
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from defender.tests.tenant_1078_pass_a import _spec1078 as H

T_ID = H.VALID_ID


# ======================================================================================
# The race and the bystander — the real primitives, in the test itself.
# ======================================================================================

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


def _assert_single_plain_0644(path: Path) -> None:
    st = os.lstat(path)
    assert stat.S_ISREG(st.st_mode), f"{path} is not a regular file"
    assert st.st_nlink == 1, f"{path} has {st.st_nlink} names, not one"
    assert stat.S_IMODE(st.st_mode) == 0o644, (
        f"{path} has mode {oct(stat.S_IMODE(st.st_mode))}, not today's 0644 (C-R6 found the "
        "naive staged shape regressing to 0600)")
    assert st.st_uid == os.geteuid(), f"{path} is not owned by the writing process"


#: The crash children: each loops over ONE real create lane in fresh directories until it is
#: killed. Split per lane because the lanes' odds differ: measured on the old one-open lane,
#: a kill landed inside the record's create window in 8/40 (record-only loop) but 0/40 for the
#: row (create_tenant's own listing and mkdir dominate its loop) — so the record lane carries
#: the discriminating kills and the row lane is a stray-entry check with weak odds of a torn
#: hit (red-flagged in the author digest).
_CRASH_CHILD = {
    "record": r"""
import os, sys
from pathlib import Path
from defender import _tenant
root = Path(sys.argv[1])
print("ready", flush=True)
i = 0
while True:
    base = root / f"r{i}"
    os.mkdir(base)
    _tenant.ensure_runs_base_record(base, "playground")
    i += 1
""",
    "row": r"""
import sys
from pathlib import Path
from defender import _tenant
root = Path(sys.argv[1])
print("ready", flush=True)
i = 0
while True:
    _tenant.create_tenant(root / f"d{i}", "playground")
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
        if d.name.startswith("r"):
            if names not in ([], [H.RECORD_NAME]):
                bad.append(f"{d.name}: stray entries {names}")
            elif names and not _complete(d / H.RECORD_NAME, ("tenant_id", "base_world_id")):
                bad.append(f"{d.name}: a torn record {(d / H.RECORD_NAME).read_bytes()[:40]!r}")
        else:
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
# ensure_runs_base_record (D1) and the record's grammar (O3)
# ======================================================================================

def test_o3_record_read_grammar(tmp_path, monkeypatch):
    """A runs-base record whose tenant_id is '../../x' is refused when read, where at ed5386bc
    it reads back unchallenged.

    Read through the owner's own reader (`read_tenant`, which `Run.for_tenant` uses), through
    `ensure_runs_base_record` and through `tenant_of_run_dir`; the control is the same record
    naming a grammar id, which reads back."""
    base = tmp_path / "data" / T_ID / "runs"
    H.plant_record(base, "../../x")
    tenant = H.tenant()
    with pytest.raises(ValueError, match=r"\.\./\.\./x|tenant"):
        tenant.read_tenant(base)
    H.owner_refusal(H.ensure_runs_base_record, base, T_ID)
    H.set_data_root(monkeypatch, tmp_path / "data")
    H.owner_refusal(H.tenant_of_run_dir, base / "r1")
    good = tmp_path / "good"
    H.plant_record(good, T_ID)
    assert tenant.read_tenant(good).tenant_id == T_ID


def test_o6_ensure_record_semantics(tmp_path):
    """ensure_runs_base_record(runs_base, T) mints a record naming T when absent, returns it
    when present and naming T, and refuses when present and naming another tenant;
    ensure_tenant no longer exists."""
    base = tmp_path / "runs"
    base.mkdir()
    minted = H.ensure_runs_base_record(base, T_ID)
    record = base / H.RECORD_NAME
    doc = json.loads(record.read_text(encoding="utf-8"))
    assert doc["tenant_id"] == T_ID == minted.tenant_id, "the minted record does not name T"
    assert doc["base_world_id"] == minted.base_world_id
    assert doc["base_world_id"], "the minted record carries no base_world_id"
    minted_bytes = record.read_bytes()

    again = H.ensure_runs_base_record(base, T_ID)
    assert (again.tenant_id, again.base_world_id) == (T_ID, minted.base_world_id)
    assert record.read_bytes() == minted_bytes, "a present record was rewritten"

    other = tmp_path / "other"
    H.plant_record(other, "someone-else")
    other_bytes = (other / H.RECORD_NAME).read_bytes()
    refusal = H.owner_refusal(H.ensure_runs_base_record, other, T_ID)
    assert "someone-else" in str(refusal), f"the refusal does not name the disagreement: {refusal}"
    assert (other / H.RECORD_NAME).read_bytes() == other_bytes, "the disagreeing record changed"

    assert not hasattr(H.tenant(), "ensure_tenant"), (
        "ensure_tenant still exists: D1 renames it ensure_runs_base_record(runs_base, tenant_id)")


def test_o6_record_create_exclusive(tmp_path):
    """Two racing ensure_runs_base_record creates for one runs base leave exactly one record,
    and the loser returns the winner's record.

    §7 J63 (human, with J16): both racing creates SUCCEED — no loser is refused — one record
    exists, and every caller carries the winner's base_world_id."""
    for trial in range(40):
        base = tmp_path / f"base-{trial}"
        base.mkdir()
        results, errors = _race(2, lambda b=base: H.ensure_runs_base_record(b, T_ID))
        assert errors == [], f"trial {trial}: a racing create was refused: {errors!r}"
        assert os.listdir(base) == [H.RECORD_NAME], f"trial {trial}: {os.listdir(base)}"
        on_disk = json.loads((base / H.RECORD_NAME).read_text(encoding="utf-8"))
        assert {r.base_world_id for r in results} == {on_disk["base_world_id"]}, (
            f"trial {trial}: the racers disagree about the base world")


def test_s7_j16_create_lane_complete_or_absent(tmp_path):
    """A reader that catches a create-lane writer (ensure_runs_base_record's runs-base record,
    create_tenant's tenant row) mid-write sees the name absent or the file complete, never
    empty or partial; the file has exactly one name throughout (no two-named alias window),
    mode 0644 (and the writing process's owner), and a crash before the write completes leaves
    no stray entry in the directory. N racing ensure_runs_base_record calls on one base all
    succeed, leave one record, and every caller carries the winner's base_world_id.

    Four observations, each against the REAL lane: (1) the record race with a bystander
    reader; (2) the row race with a bystander reader; (3) mode, owner and name count of what
    each leaves; (4) a real SIGKILL of a child looping over each lane.

    PLATFORM-NEUTRAL BY CONSTRUCTION (phase F RC1): the harness uses only POSIX primitives —
    threads, `os.lstat`/`os.listdir`, `os.geteuid`, a child process and SIGKILL — and asserts
    only the OBSERVABLE, never a mechanism (`O_TMPFILE`, `linkat`, `renameat2` are the
    implementer's per-platform choice). So it runs, and means the same thing, on any POSIX
    host; nothing here is Linux-only, so nothing is skipped. Which platforms the guarantee is
    REQUIRED on is RC1's open §7 question, not this test's."""
    # (1) + (3) the runs-base record
    record_fields = ("tenant_id", "base_world_id", "created_at")
    for trial in range(40):
        base = tmp_path / "records" / f"b{trial}"
        base.mkdir(parents=True)
        with _Bystander(base / H.RECORD_NAME, record_fields) as reader:
            results, errors = _race(8, lambda b=base: H.ensure_runs_base_record(b, T_ID))
        assert errors == [], (
            f"trial {trial}: a racing ensure_runs_base_record raised {errors[0]!r} — the "
            "empty-window read C-P2 measured on the old lane")
        assert reader.violations == [], f"trial {trial}: the bystander saw {reader.violations}"
        assert os.listdir(base) == [H.RECORD_NAME], f"trial {trial}: {os.listdir(base)}"
        on_disk = json.loads((base / H.RECORD_NAME).read_text(encoding="utf-8"))
        assert on_disk["tenant_id"] == T_ID
        assert {r.base_world_id for r in results} == {on_disk["base_world_id"]}
        _assert_single_plain_0644(base / H.RECORD_NAME)

    # (2) + (3) the tenant row
    row_fields = ("tenant_id", "created_at")
    for trial in range(20):
        root = tmp_path / "rows" / f"d{trial}"
        root.parent.mkdir(parents=True, exist_ok=True)
        with _Bystander(root / T_ID / H.ROW_NAME, row_fields) as reader:
            results, errors = _race(6, lambda r=root: H.create_tenant(r, T_ID))
        assert len(results) == 1, f"trial {trial}: {len(results)} creates of one row succeeded"
        assert all(isinstance(e, ValueError) for e in errors), (
            f"trial {trial}: a losing create escaped with {[type(e).__name__ for e in errors]}")
        assert reader.violations == [], f"trial {trial}: the bystander saw {reader.violations}"
        assert os.listdir(root) == [T_ID], f"trial {trial}: stray entries in the root"
        assert os.listdir(root / T_ID) == [H.ROW_NAME], f"trial {trial}: stray beside the row"
        _assert_single_plain_0644(root / T_ID / H.ROW_NAME)

    # (4) the crash
    crash_root = tmp_path / "crash"
    env = H.setup_env(None)
    torn: list[str] = []
    for lane, kills in (("record", 24), ("row", 8)):
        for kill in range(kills):
            root = crash_root / f"{lane}-{kill}"
            root.mkdir(parents=True)
            child = subprocess.Popen(  # noqa: S603 — fixed argv, the test's own interpreter
                [sys.executable, "-c", _CRASH_CHILD[lane], str(root)], env=env,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                assert child.stdout.readline().strip() == "ready", child.stderr.read()
                time.sleep(random.uniform(0.02, 0.25))
                if child.poll() is not None:
                    pytest.fail(f"the {lane} create-lane child died on its own: "
                                f"{child.stderr.read()}")
                child.send_signal(signal.SIGKILL)
            finally:
                child.wait(timeout=30)
                child.stdout.close()
                child.stderr.close()
            torn += [f"{lane} kill {kill}: {b}" for b in _crash_leftovers(root)]
    assert torn == [], "a crash left a torn or stray entry:\n" + "\n".join(torn)


def test_runs_base_record_torn_read(tmp_path, monkeypatch):
    """Under the complete-or-absent create lane (J16/J63), no reader of a runs-base record — a
    racing ensure_runs_base_record loser or a bystander such as tenant_of_run_dir — ever
    observes an empty or partial record: it sees the record absent or complete, so the read is
    old-or-new-only by construction.

    §7 corrected settled #32 here: the premise's empty-intermediate (C-P1) grounded the OLD
    lane and does not carry forward. The bystander is `tenant_of_run_dir` itself, at a real
    tenant location: every answer it gives while the record is being created must be either T
    or EXACTLY its absent-record refusal (captured before the race) — a corrupt-record refusal
    is the torn read."""
    root = tmp_path / "data"
    H.set_data_root(monkeypatch, root)
    H.make_tenant(root, T_ID)
    base = H.runs_dir(root, T_ID)
    base.mkdir()
    run_dir = base / "r1"
    absent = str(H.owner_refusal(H.tenant_of_run_dir, run_dir))
    for trial in range(40):
        (base / H.RECORD_NAME).unlink(missing_ok=True)
        seen: list[str] = []
        stop = threading.Event()

        def bystander(stop=stop, seen=seen) -> None:
            while not stop.is_set():
                try:
                    seen.append("T" if H.tenant_of_run_dir(run_dir) == T_ID else "other")
                except ValueError as refused:
                    seen.append("absent" if str(refused) == absent else f"torn: {refused}")

        reader = threading.Thread(target=bystander)
        reader.start()
        try:
            results, errors = _race(8, lambda: H.ensure_runs_base_record(base, T_ID))
        finally:
            stop.set()
            reader.join(timeout=30)
        assert errors == [], f"trial {trial}: a racing loser observed a torn record: {errors!r}"
        assert len({r.base_world_id for r in results}) == 1
        bad = [s for s in seen if s not in ("T", "absent")]
        assert bad == [], f"trial {trial}: the bystander observed {bad[:3]}"


def test_tenant_folder_symlink_swapped_between_o11as_construction_time_check_and_first_write(
        tmp_path):
    """create_tenant's folder creation goes through guarded_mkdir (F12, brief R4(d): _tenant.py
    is hard-gated for a raw mkdir), which re-judges the path's components at mkdir time,
    closing the swap window after O11a's construction-time check.

    The swap, as it lands on disk: `<root>/<T>` is a symlink to a directory elsewhere by the
    time the folder is made (C-P5: guarded_mkdir refuses a symlinked component at any depth
    below its base). The create is refused, nothing is written through the link, and the link
    is left as it was; the control is the same id into a fresh root."""
    victim = tmp_path / "victim"
    victim.mkdir()
    root = tmp_path / "data"
    root.mkdir()
    (root / T_ID).symlink_to(victim, target_is_directory=True)
    H.owner_refusal(H.create_tenant, root, T_ID)
    assert os.listdir(victim) == [], "create_tenant wrote through a symlinked tenant folder"
    assert os.readlink(root / T_ID) == str(victim), "the planted link was replaced"
    fresh = tmp_path / "fresh"
    H.create_tenant(fresh, T_ID)
    assert (fresh / T_ID / H.ROW_NAME).is_file()


# ======================================================================================
# Run.for_tenant — the race backstop and its coherence with a pass-(A) record
# ======================================================================================

def test_s7_j34_run_for_tenant_mismatch_backstop(tmp_path):
    """Run.for_tenant(runs_base, T) over a present record naming U raises its mismatch
    refusal and writes nothing: the race backstop behind ensure_runs_base_record's step-4
    refusal.

    Called with the real signature, `Run.for_tenant(T, run_id, runs_base=...)`; the control is
    a record naming T, which is accepted."""
    Run = H.mod("_run_handle").Run
    base = tmp_path / "runs"
    H.plant_record(base, "someone-else")
    before = H.census(tmp_path)
    with pytest.raises(ValueError, match="someone-else"):
        Run.for_tenant(T_ID, "r1", runs_base=base)
    assert H.census(tmp_path) == before, "the refused Run.for_tenant wrote something"
    same = tmp_path / "same"
    H.plant_record(same, T_ID)
    assert Run.for_tenant(T_ID, "r1", runs_base=same).run_dir == same / "r1"


def test_g_r7_for_tenant_rekey_coherence(tmp_path):
    """Run.for_tenant, driven against a runs-base record minted under pass (A) (tenant_id from
    the request, never DEFAULT_TENANT_ID), still refuses only a genuinely disagreeing record
    and still accepts a record naming the same tenant — the mismatch check
    (`record.tenant_id != tenant_id`, _run_handle.py:349-359) continues to compare like with
    like now that both sides of the comparison changed provenance."""
    Run = H.mod("_run_handle").Run
    base = tmp_path / "runs"
    base.mkdir()
    minted = H.ensure_runs_base_record(base, T_ID)
    assert minted.tenant_id == T_ID != "default", "the record was not minted from the request"
    assert Run.for_tenant(T_ID, "r1", runs_base=base).run_dir == base / "r1"
    with pytest.raises(ValueError, match="someone-else|disagree"):
        Run.for_tenant("someone-else", "r1", runs_base=base)
