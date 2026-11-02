"""#1342 the child's job entry (`run.job_main`, `run.py --job`): run setup in the job lane (O6, M1, M5),
the job-end record's facts (O8 child side, M3), the sidecar split, no outside write (M4), the job lane
never running unsandboxed (R2), and the child's death-tie setup (O7). The tenant is a `tenancy.tenants` row (r6): a migrated database, `DEFENDER_DATABASE_DSN` set, no worker here.

In-process cases drive `job_main` with the real `materialize` over a published fixture tenant, a
planted launch record and alert file, and a lifecycle seam. Death-tie cases run `_job_entry1342.py`
as a real child process and observe through its marks. Every wait is bounded."""
from __future__ import annotations

import contextlib
import ctypes
import ast
import functools
import hashlib
import io
import json
import os
import re
import signal
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from defender.tests.support.jobs._jobs1342 import (
    ALERT_BYTES,
    AWKWARD_ALERT_BYTES,
    DECOMPOSED_ALERT_BYTES,
    DEFENDER,
    FEFF_RICH_ALERT_BYTES,
    PADDED_ALERT_BYTES,
    ZWNBSP_ALERT_BYTES,
    TITLE,
    WORKTREE,
    register_tenant,
    restate_tenant,
    tree,
)
from defender.tests.support.shared._postgres1339 import execute
from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

ENTRY = DEFENDER / "tests" / "support" / "jobs" / "_job_entry1342.py"
OTHER_TENANT = str(uuid.UUID(int=0x1342))
SETTLED = {"setup": "done", "box": "started", "report_committed": True, "scrub_verified": True}


pytestmark = [pytest.mark.postgres, pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="reads /proc/self/fd and uses prctl(PR_SET_PDEATHSIG), Linux only")]


@pytest.fixture(autouse=True)
def _process_state():
    """`job_main` sets the process's parent-death signal and SIGTERM handling; give both back."""
    libc = ctypes.CDLL(None, use_errno=True)
    prior_signal = ctypes.c_int(0)
    libc.prctl(2, ctypes.byref(prior_signal))  # PR_GET_PDEATHSIG
    prior_handler = signal.getsignal(signal.SIGTERM)
    yield
    libc.prctl(1, prior_signal.value)  # PR_SET_PDEATHSIG
    signal.signal(signal.SIGTERM, prior_handler)


# --- the scene -----------------------------------------------------------------------------------

@dataclass
class Scene:
    root: Path
    t: Any
    runs: Path
    token: str = field(default_factory=lambda: uuid.uuid4().hex)  # the worker-minted box token (r5 C1)
    dsn: str = ""  # the database holding this tenant's record (r6)

    def launch_doc(self, run_id: str, **over: Any) -> dict[str, Any]:
        return {"investigation_id": run_id, "tenant_id": self.t.tenant_id, "alert_id": str(uuid.uuid4()),
                "digest": hashlib.sha256(ALERT_BYTES).hexdigest(), "label": TITLE, "box_token": self.token, **over}

    def plant(self, run_id: str, *, launch: Any = "default", alert: bytes | None = ALERT_BYTES) -> None:
        """The worker's two files, create-only, beside the run folder (`<T>/runs/` already made: R1)."""
        if launch == "default":
            launch = json.dumps(self.launch_doc(run_id))
        elif isinstance(launch, dict):
            launch = json.dumps(launch)
        if launch is not None:
            (self.runs / f"{run_id}.launch.json").write_text(launch, encoding="utf-8")
        if alert is not None:
            (self.runs / f"{run_id}.alert.json").write_bytes(alert)

    def job_end(self, run_id: str) -> dict[str, Any] | None:
        path = self.runs / f"{run_id}.job-end.json"
        return json.loads(path.read_text(encoding="utf-8")) if path.exists() else None

    def argv(self, run_id: str, parent: int | None = None) -> list[str]:
        return ["--job", run_id, "--tenant", self.t.tenant_id,
                "--parent-pid", str(os.getppid() if parent is None else parent)]


@pytest.fixture
def scene(tmp_path, monkeypatch, migrated_database):
    root = tmp_path / "data"
    root.mkdir()
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(root))
    monkeypatch.setenv("DEFENDER_DATABASE_DSN", migrated_database)  # the entry reads tenant records here (R6-2)
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    with B.run_tenant(tmp_path, root) as t:
        register_tenant(migrated_database, t.tenant_id, data_root=root)  # active, wired to the fixture's own origin
        runs = root / t.tenant_id / "runs"
        runs.mkdir(exist_ok=True)
        yield Scene(root, t, runs, dsn=migrated_database)


@dataclass
class Ran:
    rc: int | None = None
    exit: BaseException | None = None
    raised: BaseException | None = None
    out: str = ""
    calls: dict[str, int] = field(default_factory=lambda: {"lifecycle": 0, "publish": 0})

    err: str = ""

    @property
    def message(self) -> str:
        """Whatever the entry said about itself, by any channel (D-j: no exit code is pinned)."""
        said = [str(self.exit.code) if self.exit is not None else "", str(self.raised or ""), self.out, self.err]
        return "\n".join(said)


def summary(*, report_committed: bool = True) -> dict[str, Any]:
    return {"output": "x", "requests": 0, "truncated_by": None, "closed_before_cut": False,
            "exit_reason": None, "report_committed": report_committed}


def settle(kw: dict[str, Any], *, report_committed: bool = True, scrub_verified: bool = True) -> None:
    """What a lifecycle that closed the report and verified the tree leaves on the facts holder the job
    entry handed it (`job_facts`, r5 C2): the review state's close, and the scrub's fact. No holder (the
    operator path): nothing to set."""
    from defender.investigation.challenge_gate import ReviewState

    facts = kw.get("job_facts")
    if facts is None:
        return
    if report_committed:
        facts.review_state["state"] = ReviewState(closed=True)
    facts.scrub_verified = scrub_verified


def verified_lifecycle(ran: Ran, *, report_committed: bool = True):
    """A lifecycle seam that records the call, leaves the host scrub verdict a real scrub would, and sets
    its facts on the holder (r5 C2); its summary's `report_committed` agrees, as the driver's does."""
    def lifecycle(**kw: Any) -> dict[str, Any]:
        ran.calls["lifecycle"] += 1
        kw["run"].facts.scrub_verdict.write(json.dumps({"ran": True, "reason": "walk completed"}))
        settle(kw, report_committed=report_committed)
        return summary(report_committed=report_committed)
    return lifecycle


def run_job(s: Scene, run_id: str, *, lifecycle: Any = None, preflight: Any = None, materialize: Any = None,
            visualize: Any = None, ran: Ran | None = None) -> Ran:
    from defender import run as run_py

    result = Ran() if ran is None else ran

    def publish(*_a: Any, **_k: Any) -> str:
        result.calls["publish"] += 1
        return B.fresh(s.t.commit)

    seams: dict[str, Any] = {
        "lifecycle": lifecycle if lifecycle is not None else verified_lifecycle(result),
        "preflight": preflight if preflight is not None else (lambda *a, **k: 0),
        "visualize": visualize if visualize is not None else (lambda *a, **k: None),
        "publish": publish}
    if materialize is not None:
        seams["materialize"] = materialize
    out, err = io.StringIO(), io.StringIO()
    try:
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            result.rc = run_py.job_main(s.argv(run_id), **seams)
    except SystemExit as e:
        result.exit = e
    except Exception as e:  # noqa: BLE001 — kept for the assertions to name
        result.raised = e
    result.out, result.err = out.getvalue(), err.getvalue()
    return result


class ReaderSpies:
    """Records, in order, every reader of the run folder and of the page that `run.py` could reach: listing
    the run folder, the table cross-check, the module-default page render and the renderer beneath it."""

    def __init__(self, monkeypatch: Any, run_dir: Path, *, any_child_of: Path | None = None) -> None:
        from defender import run as run_py  # noqa: F401 — imported first: its seam defaults bind the real readers, never a spy
        from defender import run_common
        from defender.presentation import visualize_run

        self.events: list[str] = []
        real_iterdir, real_cross = Path.iterdir, run_common.cross_check_tables

        def iterdir(path: Path) -> Any:
            if path == run_dir or (any_child_of is not None and path.parent == any_child_of):
                self.events.append("list")
            return real_iterdir(path)

        def cross_check(*a: Any, **k: Any) -> Any:
            self.events.append("cross-check")
            return real_cross(*a, **k)

        def note(event: str) -> Any:
            return lambda *_a, **_k: self.events.append(event)

        monkeypatch.setattr(Path, "iterdir", iterdir)  # lint-monkeypatch: ok — a recording wrapper; no seam lists the run folder
        monkeypatch.setattr(run_common, "cross_check_tables", cross_check)  # lint-monkeypatch: ok — a recording wrapper of the reader the post-steps reach by module attribute
        monkeypatch.setattr(run_common, "visualize", note("module-visualize"))  # lint-monkeypatch: ok — the module default must not be what renders
        monkeypatch.setattr(visualize_run, "publish_page", note("renderer"))  # lint-monkeypatch: ok — beneath the module default, whatever name reached it
        self.seam_calls = 0

    def seam(self, *_a: Any, **_k: Any) -> None:
        """The injected page seam."""
        self.seam_calls += 1
        self.events.append("seam-visualize")


#: Audit events that list a folder; `args[0]` is the path, or a directory descriptor.
_AUDIT_LISTINGS = frozenset({"os.listdir", "os.scandir", "os.walk", "os.fwalk"})
_AUDIT_WATCH: list[tuple[str, str]] | None = None  # the process-wide hook records here while a test sets it
_AUDIT_INSTALLED = False


_AUDIT_SPAWNS: list[list[str]] | None = None  # argv of every process the interpreter launched, while a test sets it


def _audit_hook(event: str, args: tuple[Any, ...]) -> None:
    spawns = _AUDIT_SPAWNS
    if spawns is not None and event in ("subprocess.Popen", "os.exec", "os.posix_spawn", "os.spawn", "os.system"):
        launched = {"os.system": args[:1], "os.spawn": args[2]}.get(event, args[1] if len(args) > 1 else ())
        with contextlib.suppress(TypeError):
            spawns.append([os.fsdecode(part) for part in launched])
    sink = _AUDIT_WATCH
    if sink is None or not (event in _AUDIT_LISTINGS or event == "open"):
        return
    try:
        target = args[0]
        if event == "open" and (not isinstance(args[2], int) or args[2] & (os.O_WRONLY | os.O_RDWR | os.O_DIRECTORY)):
            return  # a write, or a directory opened to be walked (the listing itself is its own event)
        if isinstance(target, int):
            target = os.readlink(f"/proc/self/fd/{target}")
        sink.append((event, os.path.realpath(os.fsdecode(target))))
    except (OSError, TypeError, ValueError, IndexError):
        return


class AuditWatch:
    """Records listings and read-opens beneath the interpreter's names (`sys.addaudithook`), whichever function or alias reached them."""

    def __init__(self) -> None:
        global _AUDIT_INSTALLED, _AUDIT_WATCH
        if not _AUDIT_INSTALLED:  # a hook cannot be removed: one for the process, gated by the module-level sink
            sys.addaudithook(_audit_hook)
            _AUDIT_INSTALLED = True
        self.seen: list[tuple[str, str]] = []
        _AUDIT_WATCH = self.seen

    def stop(self) -> None:
        global _AUDIT_WATCH
        _AUDIT_WATCH = None

    @staticmethod
    def watch_spawns() -> list[list[str]]:
        """Start recording the argv of every process launched; the returned list fills until `stop_spawns`."""
        global _AUDIT_INSTALLED, _AUDIT_SPAWNS
        if not _AUDIT_INSTALLED:
            sys.addaudithook(_audit_hook)
            _AUDIT_INSTALLED = True
        _AUDIT_SPAWNS = []
        return _AUDIT_SPAWNS

    @staticmethod
    def stop_spawns() -> None:
        global _AUDIT_SPAWNS
        _AUDIT_SPAWNS = None

    def reads_of(self, run_dir: Path) -> list[tuple[str, str]]:
        """Listings and read-opens at or below `run_dir`, less the entry's own setup (the alert input it writes, the provenance it announces)."""
        root = os.path.realpath(run_dir)
        own = (os.path.join(root, "alert_input"), os.path.join(root, "provenance.json"))
        return [(event, path) for event, path in list(self.seen)
                if (path == root or path.startswith(root + os.sep))
                and not any(path == p or path.startswith(p + os.sep) for p in own)]


# --- O6 / M1 / M5: setup in the job lane -----------------------------------------------------------

def test_o6_a_job_with_a_valid_launch_record_sets_up_and_runs_the_lifecycle(scene):
    """The id is the launch record's: run folder made, id announced, label is the alert's title, record settled. (O6, M5)"""
    run_id = str(uuid.uuid4())
    scene.plant(run_id)

    ran = run_job(scene, run_id)

    assert ran.raised is None, ran
    assert ran.exit is None or ran.exit.code in (0, None), ran
    assert ran.calls == {"lifecycle": 1, "publish": 1}
    assert ran.out.splitlines()[0] == f"run_id={run_id}"
    assert (scene.runs / run_id).is_dir()
    assert B.read_stamp(scene.runs / run_id)["alert_label"] == TITLE
    assert scene.job_end(run_id) == SETTLED


@pytest.mark.parametrize("raw", [ALERT_BYTES, AWKWARD_ALERT_BYTES, PADDED_ALERT_BYTES, DECOMPOSED_ALERT_BYTES,
                                 ZWNBSP_ALERT_BYTES, FEFF_RICH_ALERT_BYTES],
                         ids=["as the fixture", "crlf tab multibyte", "leading whitespace and trailing spaces",
                              "decomposed unicode", "zero-width no-break space in a string",
                              "feff_rich"])
def test_o6_the_runs_input_alert_is_the_launch_files_exact_bytes_and_hashes_to_the_record(scene, raw):
    """The alert the run holds equals the alert file byte for byte (trailing newline, CRLF, padding whitespace and decomposed text too) and matches the launch digest. (O6, O2, M5)"""
    from defender.records import RunPaths, formats

    run_id = str(uuid.uuid4())
    scene.plant(run_id, launch=scene.launch_doc(run_id, digest=hashlib.sha256(raw).hexdigest()), alert=raw)
    wanted = json.loads((scene.runs / f"{run_id}.launch.json").read_text(encoding="utf-8"))["digest"]

    ran = run_job(scene, run_id)

    assert ran.raised is None, ran
    held = RunPaths(scene.runs / run_id).alert.read_bytes()
    assert raw.endswith((b"\n", b"\r\n")), "premise: the fixture ends in a line end"
    assert held == (scene.runs / f"{run_id}.alert.json").read_bytes() == raw
    assert hashlib.sha256(held).hexdigest() == wanted
    record = formats.parse_alert_record(RunPaths(scene.runs / run_id).alert_record.read_text(encoding="utf-8"))
    assert record is not None, "the run holds an alert record"
    assert record.digest == hashlib.sha256(held).hexdigest(), "the run's alert record digests the held alert"


def test_m5_the_alert_file_is_read_once_and_the_digest_is_checked_on_those_bytes(scene, monkeypatch):
    """One admission read; a file swapped after it changes neither the verdict nor the bytes the run holds. (M5)"""
    from defender.records import RunPaths, formats

    run_id = str(uuid.uuid4())
    scene.plant(run_id)
    alert_file = scene.runs / f"{run_id}.alert.json"
    real, reads = formats.read_operator_alert, []

    def read_then_swap(path: Any) -> bytes:
        raw = real(path)
        reads.append(Path(path).name)
        Path(path).write_bytes(b'{"swapped": true}\n')  # a later read would see these bytes
        return raw

    monkeypatch.setattr(formats, "read_operator_alert", read_then_swap)  # lint-monkeypatch: ok — a counting wrapper of the one read, no seam exists for it

    ran = run_job(scene, run_id)

    assert reads == [alert_file.name], f"the alert file was read {len(reads)} times"
    assert ran.raised is None, ran
    assert ran.calls["lifecycle"] == 1, ran
    assert RunPaths(scene.runs / run_id).alert.read_bytes() == ALERT_BYTES
    assert scene.job_end(run_id) == SETTLED


def test_m5_a_file_that_changes_before_the_admission_read_is_refused_whatever_an_earlier_look_saw(scene, monkeypatch):
    """The digest is checked on the very bytes admitted: a file swapped just before the admission read is refused, not trusted on an earlier look. (M5)"""
    from defender.records import formats

    run_id = str(uuid.uuid4())
    scene.plant(run_id)
    real = formats.read_operator_alert

    def swap_then_read(path: Any) -> bytes:
        Path(path).write_bytes(b'{"swapped": true}\n')  # an earlier read of the path saw the launch bytes
        return real(path)

    monkeypatch.setattr(formats, "read_operator_alert", swap_then_read)  # lint-monkeypatch: ok — a wrapper of the one read that changes the file just before it, no seam exists for it

    ran = run_job(scene, run_id)

    assert ran.raised is None, ran
    assert ran.calls["lifecycle"] == 0, "the run went ahead on bytes its launch record does not name"
    assert not (scene.runs / run_id).exists()
    assert scene.job_end(run_id) == {"setup": "refused", "box": "not_started",
                                     "report_committed": False, "scrub_verified": False}


_REFUSALS = {
    "no-launch-record": dict(launch=None),
    "launch-names-another-tenant": dict(launch="tenant"),
    "launch-names-another-id": dict(launch="id"),
    "launch-not-json": dict(launch="{not json"),
    "launch-empty": dict(launch=""),
    "launch-not-an-object": dict(launch="[]"),
    "launch-lacks-the-digest": dict(launch="nodigest"),
    "launch-lacks-the-box-token": dict(launch="notoken"),
    "no-alert-file": dict(alert=None),
    "digest-mismatch-on-the-admitted-bytes": dict(alert=ALERT_BYTES.replace(b"1.50", b"1.51")),
    "launch-record-symlinked": dict(tamper="launch-link"),
    "launch-record-oversize": dict(tamper="launch-oversize"),
    "alert-file-symlinked": dict(tamper="alert-link"),
}
#: Box tokens that are not 32 lowercase hex characters: the launch check refuses each (r5 C1).
_BAD_TOKENS = {"empty": "", "31-chars": "a" * 31, "33-chars": "a" * 33, "upper-case": "A" * 32,
               "non-hex": "g" * 32, "trailing-newline": "a" * 32 + "\n", "leading-space": " " + "a" * 31,
               "uuid-form": str(uuid.UUID(int=0x1342)), "integer": 12345678901234567890123456789012,
               "null": None, "list": ["a" * 32], "full-width": "\uff41" * 32}
_REFUSALS.update({f"launch-box-token-{name}": dict(launch=("token", value)) for name, value in _BAD_TOKENS.items()})
OVER_THE_LIMIT = 70 * 1024 * 1024


def _tamper(scene: Scene, run_id: str, how: str) -> None:
    """Plant the launch pair with one of its two files a symlink to a valid copy, or the launch record
    padded with blanks past any size limit (still valid JSON)."""
    elsewhere = scene.root.parent / "elsewhere"
    elsewhere.mkdir(exist_ok=True)
    record = json.dumps(scene.launch_doc(run_id))
    scene.plant(run_id, launch=None if how.startswith("launch") else "default",
                alert=None if how == "alert-link" else ALERT_BYTES)
    if how == "launch-link":
        (elsewhere / "launch.json").write_text(record, encoding="utf-8")
        (scene.runs / f"{run_id}.launch.json").symlink_to(elsewhere / "launch.json")
    elif how == "launch-oversize":
        (scene.runs / f"{run_id}.launch.json").write_text(record + " " * OVER_THE_LIMIT, encoding="utf-8")
    else:
        (elsewhere / "alert.json").write_bytes(ALERT_BYTES)
        (scene.runs / f"{run_id}.alert.json").symlink_to(elsewhere / "alert.json")



@pytest.mark.parametrize("kind", sorted(_REFUSALS))
def test_o6_setup_refuses_an_id_without_a_launch_record_that_names_this_tenant_and_checks(scene, kind):
    """No launch record, another tenant's, another id's, unparseable, symlinked or oversize, without a well-formed box token, an alert file that is a symlink, or a digest the alert bytes miss: refused and recorded `setup: refused`; nothing spent, nothing made. (O6, M1, M5, r5 C1)"""
    run_id = str(uuid.uuid4())
    spec = dict(_REFUSALS[kind])
    launch = spec.pop("launch", "default")
    tamper = spec.pop("tamper", None)
    if launch == "tenant":
        launch = scene.launch_doc(run_id, tenant_id=OTHER_TENANT)
    elif launch == "id":
        launch = scene.launch_doc(run_id, investigation_id=str(uuid.uuid4()))
    elif launch == "nodigest":
        launch = {k: v for k, v in scene.launch_doc(run_id).items() if k != "digest"}
    elif launch == "notoken":
        launch = {k: v for k, v in scene.launch_doc(run_id).items() if k != "box_token"}
    elif isinstance(launch, tuple):
        launch = scene.launch_doc(run_id, box_token=launch[1])
    if tamper is None:
        scene.plant(run_id, launch=launch, **spec)
    else:
        _tamper(scene, run_id, tamper)
    before = sorted(p.name for p in scene.runs.iterdir())

    ran = run_job(scene, run_id)

    assert ran.raised is None, ran.raised
    assert ran.calls["lifecycle"] == 0
    assert not (scene.runs / run_id).exists(), "a run folder was made past a refused launch"
    assert "run_id=" not in ran.out
    assert scene.job_end(run_id) == {"setup": "refused", "box": "not_started",
                                     "report_committed": False, "scrub_verified": False}
    after = sorted(p.name for p in scene.runs.iterdir())
    assert after == sorted([*before, f"{run_id}.job-end.json"]), f"{kind}: runs changed: {after}"
    if kind != "digest-mismatch-on-the-admitted-bytes":
        assert ran.calls["publish"] == 0, "the launch check comes before the knowledge publish"
    if kind == "no-launch-record":
        assert "launch" in ran.message.lower(), ran.message


def test_o6_an_alert_that_admission_refuses_is_refused_and_recorded_even_with_a_matching_digest(scene):
    """A launch record whose digest matches inadmissible bytes (a BOM): refused after the launch check, still `setup: refused`. (O6, M1)"""
    run_id = str(uuid.uuid4())
    bom = b"\xef\xbb\xbf" + ALERT_BYTES
    scene.plant(run_id, launch=scene.launch_doc(run_id, digest=hashlib.sha256(bom).hexdigest()), alert=bom)

    ran = run_job(scene, run_id)

    assert ran.calls["lifecycle"] == 0
    assert not (scene.runs / run_id).exists()
    assert scene.job_end(run_id)["setup"] == "refused"


REFUSED = {"setup": "refused", "box": "not_started", "report_committed": False, "scrub_verified": False}


@pytest.mark.parametrize("record", ["creating", "offboarding", "offboarded", "no wiring", "no record", "records unreachable"])
def test_m1_a_tenant_acceptance_refusal_is_recorded_as_setup_refused(scene, monkeypatch, record):
    """The door is opened before tenant acceptance, so a tenant the host refuses (any non-active state, no wiring, no record, unreachable records) leaves `setup: refused`, not `crashed`. (M1, R6-1)"""
    run_id = str(uuid.uuid4())
    scene.plant(run_id)
    if record == "records unreachable":
        monkeypatch.setenv("DEFENDER_DATABASE_DSN", "postgresql://nobody@127.0.0.1:1/none?connect_timeout=2")
    elif record == "no record":
        execute(scene.dsn, "DELETE FROM tenancy.forge_wiring WHERE tenant_id = %s", (scene.t.tenant_id,))
        execute(scene.dsn, "DELETE FROM tenancy.tenants WHERE id = %s", (scene.t.tenant_id,))
    else:
        restate_tenant(scene.dsn, scene.t.tenant_id, state="active" if record == "no wiring" else record,
                       wiring=record != "no wiring", data_root=scene.root)
    if record not in ("records unreachable", "no record"):  # premise: the records are there to be read
        assert execute(scene.dsn, "SELECT count(*) FROM tenancy.tenants WHERE id = %s", (scene.t.tenant_id,)) == [(1,)]
    if record == "no wiring":  # premise: an active tenant, and no forge wiring row
        assert execute(scene.dsn, "SELECT state FROM tenancy.tenants WHERE id = %s", (scene.t.tenant_id,)) == [("active",)]
        assert execute(scene.dsn, "SELECT count(*) FROM tenancy.forge_wiring WHERE tenant_id = %s", (scene.t.tenant_id,)) == [(0,)]

    ran = run_job(scene, run_id)

    assert ran.raised is None, f"a refusal was a crash: {ran.raised!r}"
    assert ran.calls["lifecycle"] == 0
    assert scene.job_end(run_id) == REFUSED
    if record in ("creating", "offboarding", "offboarded"):
        assert record in ran.message, f"the refusal text names the tenant's state: {ran.message!r}"


def _acceptance_release_states(scene: Scene, monkeypatch: Any, run_id: str) -> list[tuple[bool, bool, bool]]:
    """Make the entry's acceptance report, at its release: (job-end record written, exclusive try-once on the tenant's lock refused, this process a recorded holder). The real release runs."""
    from defender.systems.run_tenant import Admitted
    from defender.tenancy import host_lock

    at_release: list[tuple[bool, bool, bool]] = []
    real_exit = Admitted.__exit__

    def exit_recording_the_state(self: Any, *exc: object) -> None:
        fd = host_lock.acquire(scene.root, scene.t.tenant_id, exclusive=True, timeout=0)
        host_lock.release_lock(fd)
        at_release.append((scene.job_end(run_id) is not None, fd is None,
                           os.getpid() in [h.pid for h in host_lock.holders(scene.root, scene.t.tenant_id)]))
        real_exit(self, *exc)

    monkeypatch.setattr(Admitted, "__exit__", exit_recording_the_state)  # lint-monkeypatch: ok — the acceptance's release is the only point that orders "record written" against "lock given back"; the real release runs
    return at_release


def test_r6_6_the_job_end_record_is_written_while_the_entry_still_holds_its_tenant_acceptance(scene, monkeypatch):
    """When the entry's tenant acceptance ends, the job-end record is already written, and until that moment an exclusive try-once on the tenant's host lock fails and the entry is a recorded holder. (R6-6)"""
    run_id = str(uuid.uuid4())
    scene.plant(run_id)
    at_release = _acceptance_release_states(scene, monkeypatch, run_id)

    ran = run_job(scene, run_id)

    assert scene.job_end(run_id) == SETTLED, ran.message
    assert at_release, "premise: the entry's acceptance ended through `with admitted:`"
    assert at_release[-1] == (True, True, True), \
        f"at the acceptance's release (record written, lock still held, entry a holder): {at_release}"


@pytest.mark.parametrize("how", ["preflight refuses", "setup crashes"])
def test_r6_6_a_failed_run_also_writes_its_job_end_record_before_the_acceptance_is_given_back(scene, monkeypatch, how):
    """After the tenant is admitted, a setup that is refused or crashes still leaves its job-end record written while the entry holds its acceptance. (R6-6)"""
    run_id = str(uuid.uuid4())
    scene.plant(run_id)
    at_release = _acceptance_release_states(scene, monkeypatch, run_id)
    boom = RuntimeError("setup blew up")

    def materialize(*_a: Any, **_k: Any) -> Any:
        raise boom

    ran = (run_job(scene, run_id, preflight=lambda *a, **k: 2) if how == "preflight refuses"
           else run_job(scene, run_id, materialize=materialize))

    assert (ran.raised is boom) == (how == "setup crashes"), ran
    assert ran.calls["lifecycle"] == 0
    assert scene.job_end(run_id)["setup"] == ("refused" if how == "preflight refuses" else "crashed")
    assert at_release, "premise: the entry's acceptance ended through `with admitted:`"
    assert at_release[-1] == (True, True, True), \
        f"at the acceptance's release (record written, lock still held, entry a holder): {at_release}"


def _remove_working_tree(scene: Scene) -> Path:
    """Take the tenant's knowledge working tree away and keep its git objects (the folder rules then judge only what remains, as main's run-start acceptance does with `clone_tree=False`)."""
    import shutil

    from defender.tenancy._tenants import AGENT_HALF, SETTINGS_HALF

    knowledge = scene.root / scene.t.tenant_id / "knowledge"
    for half in (SETTINGS_HALF, AGENT_HALF):
        shutil.rmtree(knowledge / half)
    assert (knowledge / ".git").exists(), "premise: the git objects are kept"
    assert not (knowledge / SETTINGS_HALF).exists()
    assert not (knowledge / AGENT_HALF).exists()
    return knowledge


def test_r6_6_a_tenant_folder_without_its_working_tree_is_accepted_by_the_job_entry(scene):
    """A tenant whose knowledge folder keeps its git objects but has no working tree is accepted (run start does not need the tree: it exports from the objects): the job sets up and runs. (R6-3, R6-6)"""
    run_id = str(uuid.uuid4())
    scene.plant(run_id)
    _remove_working_tree(scene)

    ran = run_job(scene, run_id)

    assert ran.raised is None, ran
    assert ran.calls["lifecycle"] == 1, ran.message
    assert scene.job_end(run_id) == SETTLED


def test_r6_6_the_tree_less_folder_is_refused_by_the_acceptance_that_wants_the_tree(scene):
    """Control for the two tests around it: the same folder IS refused by `host_tenant(..., clone_tree=True)`, so `clone_tree=False` is what lets it through. (R6-6)"""
    from defender import tenancy
    from defender.records.formats import TenantRefused
    from defender.run import DEFENDER_DIR
    from defender.systems.run_tenant import host_tenant

    _remove_working_tree(scene)

    with pytest.raises(TenantRefused):
        host_tenant(tenancy.resolve_data_root(), scene.t.tenant_id, defender_dir=DEFENDER_DIR, clone_tree=True)


def test_r6_3_a_tenant_folder_without_its_working_tree_is_accepted_by_the_operator_run(scene, tmp_path):
    """The same folder, `run.main`: accepted, the run starts. (R6-3, R6-6: `main` and `job_main` pass the same acceptance arguments)"""
    _remove_working_tree(scene)

    out = B.launch(scene.t, tmp_path, publish=lambda *a, **k: B.fresh(scene.t.commit))

    assert out.raised is None, out.raised
    assert out.refusal is None, out.refusal
    assert out.rc == 0, out.rc
    assert out.seen, "the operator run did not start"


def test_m1_a_preflight_that_returns_non_zero_is_a_refusal(scene):
    """Preflight's non-zero return, before the lifecycle, is `setup: refused`. (M1, M3)"""
    run_id = str(uuid.uuid4())
    scene.plant(run_id)

    ran = run_job(scene, run_id, preflight=lambda *a, **k: 2)

    assert ran.calls["lifecycle"] == 0
    assert scene.job_end(run_id)["setup"] == "refused"


def test_o8_a_setup_that_raises_otherwise_is_crashed_and_the_exception_reaches_the_caller(scene):
    """Any other exception before the lifecycle: `setup: crashed`, the same exception re-raised. (O8, M3)"""
    run_id = str(uuid.uuid4())
    scene.plant(run_id)
    boom = RuntimeError("setup blew up")

    def materialize(*_a: Any, **_k: Any) -> Any:
        raise boom

    ran = run_job(scene, run_id, materialize=materialize)

    assert ran.raised is boom, ran
    assert ran.calls["lifecycle"] == 0
    assert scene.job_end(run_id) == {"setup": "crashed", "box": "not_started",
                                     "report_committed": False, "scrub_verified": False}


def test_o6_the_run_folder_is_still_made_exclusively(scene):
    """An id whose folder exists is refused and the folder is left as it was; a job-end record beside it refuses too. (O6)"""
    taken, used = str(uuid.uuid4()), str(uuid.uuid4())
    for run_id in (taken, used):
        scene.plant(run_id)
    (scene.runs / taken).mkdir()
    (scene.runs / taken / "mark").write_text("theirs", encoding="utf-8")
    (scene.runs / f"{used}.job-end.json").write_text("{}", encoding="utf-8")

    first, second = run_job(scene, taken), run_job(scene, used)

    assert first.calls["lifecycle"] == second.calls["lifecycle"] == 0
    assert first.raised is None, first.raised
    assert scene.job_end(taken) == {"setup": "refused", "box": "not_started",
                                    "report_committed": False, "scrub_verified": False}
    assert (scene.runs / taken / "mark").read_text(encoding="utf-8") == "theirs"
    assert sorted(p.name for p in (scene.runs / taken).iterdir()) == ["mark"]
    assert not (scene.runs / used).exists()
    assert (scene.runs / f"{used}.job-end.json").read_text(encoding="utf-8") == "{}", \
        "the first job-end record was overwritten (D-i: create-only)"


def test_r1_a_tenant_with_no_runs_container_is_refused_and_the_job_entry_does_not_make_one(scene):
    """`<T>/runs` absent: the job does not go on and `runs/` is still absent after; with `runs/` present the same job runs. (R1)"""
    import shutil

    run_id = str(uuid.uuid4())
    scene.plant(run_id)
    shutil.rmtree(scene.runs)

    ran = run_job(scene, run_id)

    assert ran.calls == {"lifecycle": 0, "publish": 0}, ran
    assert not scene.runs.exists(), "the job entry made the runs container"
    assert not (scene.root / scene.t.tenant_id / "runs").exists()

    scene.runs.mkdir()  # control: the same job with `runs/` present
    scene.plant(run_id)
    control = run_job(scene, run_id)
    assert control.calls["lifecycle"] == 1, control


def test_m3_the_job_lane_removes_its_knowledge_copy_on_the_way_out(scene):
    """The run copy `<T>/run-knowledge/<id>` is gone after a clean job, and after a lifecycle crash. (M3, D-q)"""
    copies = B.run_copies(scene.t)
    clean, crashed = str(uuid.uuid4()), str(uuid.uuid4())
    scene.plant(clean)
    scene.plant(crashed)
    seen: list[bool] = []

    def lifecycle_seeing_the_copy(ran: Ran):
        inner = verified_lifecycle(ran)

        def lifecycle(**kw: Any) -> dict[str, Any]:
            seen.append(any(copies.glob("*")))
            return inner(**kw)
        return lifecycle

    run_job(scene, clean, lifecycle=lifecycle_seeing_the_copy(Ran()))
    assert seen == [True], "control: the copy exists while the lifecycle runs"
    assert not any(copies.glob("*")), "a clean job left its knowledge copy"

    def boom(**_kw: Any) -> dict[str, Any]:
        seen.append(any(copies.glob("*")))
        raise RuntimeError("investigation blew up")

    run_job(scene, crashed, lifecycle=_lifecycle(scene, investigate=boom))
    assert seen == [True, True]
    assert not any(copies.glob("*")), "a crashed job left its knowledge copy"


def test_m3_no_reader_of_the_run_folder_or_the_page_ran_before_the_lifecycle_returned_and_each_ran_after(
        scene, monkeypatch):
    """The lifecycle double sees no listing, cross-check or page render so far; afterwards the listing, one cross-check and one render through the injected seam have run. (M3)"""
    run_id = str(uuid.uuid4())
    scene.plant(run_id)
    spies = ReaderSpies(monkeypatch, scene.runs / run_id)
    ran = Ran()
    inner = verified_lifecycle(ran)
    before_lifecycle: list[list[str]] = []

    def lifecycle(**kw: Any) -> dict[str, Any]:
        before_lifecycle.append(list(spies.events))
        return inner(**kw)

    got = run_job(scene, run_id, ran=ran, lifecycle=lifecycle, visualize=spies.seam)

    assert got.raised is None, got
    assert before_lifecycle == [[]], f"a reader ran before the lifecycle returned the scrubbed folder: {before_lifecycle}"
    assert spies.events.count("cross-check") == 1, spies.events
    assert spies.events.count("seam-visualize") == 1, spies.events
    assert "list" in spies.events, spies.events
    assert "module-visualize" not in spies.events, spies.events
    assert "renderer" not in spies.events, spies.events



@pytest.mark.parametrize("entry", ["job_main", "main"])
def test_m3_beneath_the_names_nothing_listed_or_opened_the_run_folder_before_the_lifecycle_returned(
        scene, monkeypatch, tmp_path, entry):
    """Neither entry's lifecycle double sees a named reader run or a listing or read-only open of the run folder (by name spies and the audit record); afterwards the post-steps read it. Other access paths (`r+`, `dir_fd` opens, stat, child processes) are not observed here. (M3)"""
    from defender import run as run_py

    spies = ReaderSpies(monkeypatch, scene.runs / "unused", any_child_of=scene.runs)
    watch = AuditWatch()
    before: list[tuple[list[str], list[tuple[str, str]]]] = []
    run_dirs: list[Path] = []

    def lifecycle(**kw: Any) -> dict[str, Any]:
        run_dirs.append(kw["run"].run_dir)
        before.append((list(spies.events), watch.reads_of(kw["run"].run_dir)))
        kw["run"].facts.scrub_verdict.write(json.dumps({"ran": True, "reason": "walk completed"}))
        settle(kw)
        return summary()

    class Writer:
        def open_case_ticket(self, *_a: Any, **_k: Any) -> None: ...
        def record_case_ticket(self, *_a: Any, **_k: Any) -> None: ...

    try:
        if entry == "job_main":
            run_id = str(uuid.uuid4())
            scene.plant(run_id)
            got = run_job(scene, run_id, lifecycle=lifecycle, visualize=spies.seam)
            assert got.raised is None, got
            assert got.exit is None, got
        else:
            rc = run_py.main([str(B.plant_alert(tmp_path / "op-alert")), "--tenant", scene.t.tenant_id,
                              "--update-ticket"],
                             lifecycle=lifecycle, preflight=lambda *a, **k: 0, visualize=spies.seam,
                             ticket_writer=Writer(), enqueue=lambda *a, **k: False,
                             publish=lambda *a, **k: B.fresh(scene.t.commit))
            assert rc == 0
    finally:
        watch.stop()

    assert len(before) == 1, before
    assert before[0][0] == [], f"a named reader ran before the lifecycle returned: {before[0][0]}"
    assert before[0][1] == [], f"the run folder was listed or read before the lifecycle returned: {before[0][1]}"
    after = watch.reads_of(run_dirs[0])
    assert after, "premise: the post-steps read the run folder, and the record sees it"
    assert spies.events.count("cross-check") == 1, spies.events
    assert spies.events.count("seam-visualize") == 1, spies.events



def test_m3_the_main_block_calls_both_entries_with_nothing_but_the_arguments():
    """`run.py`'s `__main__` block is exactly the log configuration, the argv read and one `sys.exit` dispatching `job_main` or `main` on that argv: no other statement, and both entries get positional arguments only, so no seam is passed from it. (M3)"""
    from defender.tests.support.shared.contracts import _by_path

    astlib = _by_path.import_lint_lib("_astlib")
    tree_ = ast.parse((DEFENDER / "run.py").read_text(encoding="utf-8"))
    env = astlib.module_env(tree_, "defender.run", "defender")
    blocks = [n for n in tree_.body if isinstance(n, ast.If) and ast.unparse(n.test) == "__name__ == '__main__'"]
    assert len(blocks) == 1, "premise: one __main__ block"
    assert not blocks[0].orelse
    configure, read_argv, leave = blocks[0].body if len(blocks[0].body) == 3 else (None, None, None)
    assert leave is not None, f"the block holds statements beyond the three honest ones: {[ast.unparse(n) for n in blocks[0].body]}"
    assert isinstance(configure, ast.Expr)
    assert isinstance(configure.value, ast.Call)
    assert astlib.callee(configure.value, env) == "defender._log.configure_from_env", ast.unparse(configure)
    assert not configure.value.args
    assert not configure.value.keywords
    assert isinstance(read_argv, ast.Assign)
    assert len(read_argv.targets) == 1
    assert isinstance(read_argv.targets[0], ast.Name)
    assert ast.unparse(read_argv.value) == "sys.argv[1:]", ast.unparse(read_argv)
    argv_name = read_argv.targets[0].id
    assert isinstance(leave, ast.Expr)
    assert isinstance(leave.value, ast.Call)
    assert astlib.callee(leave.value, env) == "sys.exit", ast.unparse(leave)
    assert not leave.value.keywords
    assert len(leave.value.args) == 1
    dispatch = leave.value.args[0]
    assert isinstance(dispatch, ast.IfExp)
    for entry, name in ((dispatch.body, "job_main"), (dispatch.orelse, "main")):
        assert isinstance(entry, ast.Call), ast.unparse(entry)
        assert isinstance(entry.func, ast.Name), ast.unparse(entry)
        assert entry.func.id == name, ast.unparse(entry)
        assert name in env.defines, f"{name} is not defined in run.py"
        assert not entry.keywords, f"{name} is called with a keyword from the __main__ block"
        assert len(entry.args) == 1
        assert isinstance(entry.args[0], ast.Name)
        assert entry.args[0].id == argv_name


def test_m3_the_two_entries_are_plain_functions_defined_in_run_py():
    """`main` and `job_main` are undecorated: no `__wrapped__`, a code object from `run.py`, and their own names. (M3)"""
    import types

    from defender import run as run_py

    for name in ("main", "job_main"):
        fn = getattr(run_py, name)
        assert type(fn) is types.FunctionType, (name, type(fn))
        assert not hasattr(fn, "__wrapped__"), f"{name} is a decorator's wrapper"
        assert fn.__code__.co_filename == run_py.__file__, (name, fn.__code__)
        assert fn.__code__.co_name == name, (name, fn.__code__)
        assert (fn.__module__, fn.__name__, fn.__qualname__) == (run_py.__name__, name, name)


# --- the job-end record's facts (O8 child side, M3) ------------------------------------------------------

def _lifecycle(s: Scene, *, investigate: Any, start_box: Any = None, stop_box: Any = None, scrub: Any = None):
    from defender import box as box_mod
    from defender import run as run_py

    def verdict_scrub(tree: Path, *, write_verdict: Any) -> None:
        write_verdict({"ran": True, "reason": "walk completed"})

    return functools.partial(
        run_py._run_investigation_lifecycle, investigate=investigate,
        start_box=start_box if start_box is not None else (lambda *a, **k: box_mod.unboxed_executor()),
        stop_box=stop_box if stop_box is not None else (lambda *a, **k: None),
        scrub=scrub if scrub is not None else verdict_scrub)


def _closes(job_facts: Any, *, closed: bool = True) -> None:
    """What the driver leaves on the review state when the report is committed (`ReviewState.closed`);
    `closed=False` is a review state that exists (a first review ran) but was never closed."""
    from defender.investigation.challenge_gate import ReviewState

    assert job_facts is not None, "the investigation was not handed the job facts holder (r5 C2)"
    job_facts.review_state["state"] = ReviewState(closed=closed)


def _investigate(ran: Ran, *, without: str | None = None, closes: bool | str = True, **summary_kw: Any):
    """A fake investigation: with `closes` it commits the report on the holder it is handed (the
    protocol's `job_facts` keyword, r5 C2), as the driver's review state does; the summary it returns
    carries `report_committed` as the driver's would."""
    def investigate(*, job_facts: Any = None, **_kw: Any) -> dict[str, Any]:
        ran.calls["lifecycle"] += 1
        if closes and job_facts is not None:  # the operator path hands none
            _closes(job_facts, closed=closes != "open")  # "open": a review state that never closed
        doc = summary(**{"report_committed": closes is True, **summary_kw})
        if without is not None:
            del doc[without]
        return doc
    return investigate


def _verdict_scrub(verdict: dict[str, Any] | None):
    """A scrub seam that leaves this host verdict (`None`: none at all) beside the folder."""
    def scrub(tree: Path, *, write_verdict: Any) -> None:
        if verdict is not None:
            write_verdict(verdict)
    return scrub


@pytest.mark.parametrize(("committed", "verified", "want"), [
    (True, True, SETTLED),
    (False, True, {**SETTLED, "report_committed": False}),
    (True, False, {**SETTLED, "scrub_verified": False}),
    (False, False, {**SETTLED, "report_committed": False, "scrub_verified": False}),
])
def test_o8_report_committed_is_the_review_states_close_and_scrub_verified_the_scrub_verdict(
        scene, committed, verified, want):
    """The job-end record carries whether the review state the driver used closed, and the scrub verdict's `ran`. (O8, M2, r5 C2)"""
    run_id = str(uuid.uuid4())
    scene.plant(run_id)
    ran = Ran()
    scrub = _verdict_scrub({"ran": verified, "reason": "walk"})

    run_job(scene, run_id, ran=ran, lifecycle=_lifecycle(
        scene, investigate=_investigate(ran, closes=committed), scrub=scrub))

    assert scene.job_end(run_id) == want


@pytest.mark.parametrize(("closes", "claims", "want"), [
    (True, None, True), (True, False, True), (False, True, False), ("open", True, False)],
    ids=["summary-lacks-the-key", "summary-says-false-state-closed", "summary-says-true-state-empty",
         "summary-says-true-state-present-not-closed"])
def test_m2_the_record_reads_the_holders_review_state_not_the_summary(scene, closes, claims, want):
    """A committed report is the holder's review state `closed`; the summary's `report_committed` (absent, false or true) does not decide it, and a review state that exists but is not closed is not committed. (M2, r5 C2, D-s)"""
    run_id = str(uuid.uuid4())
    scene.plant(run_id)
    ran = Ran()
    extra = {} if claims is None else {"report_committed": claims}

    run_job(scene, run_id, ran=ran, lifecycle=_lifecycle(
        scene, investigate=_investigate(ran, closes=closes, without="report_committed" if claims is None else None,
                                        **extra)))

    assert scene.job_end(run_id) == {**SETTLED, "report_committed": want}


@pytest.mark.parametrize("verdict", [{"ran": False, "reason": "unreadable entry"}, {"reason": "no ran key"}, None],
                         ids=["ran-false", "ran-missing", "no-verdict-file"])
def test_o8_scrub_verified_comes_from_the_host_scrub_verdict_not_from_the_lifecycle_returning(scene, verdict):
    """A lifecycle that returns normally with `ran: false`, no `ran`, or no verdict file records `scrub_verified: false`. (O8)"""
    run_id = str(uuid.uuid4())
    scene.plant(run_id)
    ran = Ran()

    run_job(scene, run_id, ran=ran, lifecycle=_lifecycle(
        scene, investigate=_investigate(ran), scrub=_verdict_scrub(verdict)))

    assert ran.raised is None, ran
    assert scene.job_end(run_id) == {**SETTLED, "scrub_verified": False}


def test_o8_a_tree_the_scrub_found_tainted_is_not_verified(scene, monkeypatch):
    """The verdict says `ran: true` and the scrub raises `RunTainted`: `scrub_verified` is false. (O8)"""
    from defender.box import RunTainted

    run_id = str(uuid.uuid4())
    scene.plant(run_id)
    ran = Ran()

    def taint(tree: Path, *, write_verdict: Any) -> None:
        write_verdict({"ran": True, "reason": "walk completed"})
        raise RunTainted("a planted link")

    spies = ReaderSpies(monkeypatch, scene.runs / run_id)
    got = run_job(scene, run_id, ran=ran, visualize=spies.seam,
                  lifecycle=_lifecycle(scene, investigate=_investigate(ran), scrub=taint))

    record = scene.job_end(run_id)
    assert record["box"] == "started"
    assert record["scrub_verified"] is False
    assert isinstance(got.raised, RunTainted), got
    assert spies.seam_calls == 0, "the page was rendered from a tainted tree"
    assert spies.events == [], f"a reader of the tainted tree ran: {spies.events}"


def test_c2_a_committed_report_survives_a_teardown_fault(scene):
    """The report closed, then `stop_box` raised `BoxFault`: the record says `report_committed: true`, `scrub_verified: false`, the box started. (C2, O8)"""
    from defender.box import BoxFault

    run_id = str(uuid.uuid4())
    scene.plant(run_id)
    ran = Ran()

    def stop(*_a: Any, **_k: Any) -> None:
        raise BoxFault("could not tear down the box")

    got = run_job(scene, run_id, ran=ran, lifecycle=_lifecycle(scene, investigate=_investigate(ran), stop_box=stop))

    assert isinstance(got.raised, BoxFault), got
    assert scene.job_end(run_id) == {**SETTLED, "scrub_verified": False}


def test_c2_a_committed_report_survives_a_tainted_tree(scene):
    """The report closed, then the scrub wrote `ran: true` and raised `RunTainted`: `report_committed: true`, `scrub_verified: false`. (C2, O8)"""
    from defender.box import RunTainted

    run_id = str(uuid.uuid4())
    scene.plant(run_id)
    ran = Ran()

    def taint(tree: Path, *, write_verdict: Any) -> None:
        write_verdict({"ran": True, "reason": "walk completed"})
        raise RunTainted("a planted link")

    got = run_job(scene, run_id, ran=ran, lifecycle=_lifecycle(scene, investigate=_investigate(ran), scrub=taint))

    assert isinstance(got.raised, RunTainted), got
    assert scene.job_end(run_id) == {**SETTLED, "scrub_verified": False}


def test_c2_a_driver_raise_after_a_clean_close_and_a_clean_teardown_leaves_both_facts_true(scene):
    """The investigation closed the report then raised; teardown and scrub were clean: the exception reaches the caller and the record has both facts true (D-h superseded). (C2)"""
    run_id = str(uuid.uuid4())
    scene.plant(run_id)
    boom = RuntimeError("the driver failed after the close")

    def investigate(*, job_facts: Any = None, **_kw: Any) -> dict[str, Any]:
        _closes(job_facts)
        raise boom

    got = run_job(scene, run_id, lifecycle=_lifecycle(scene, investigate=investigate))

    assert got.raised is boom, got
    assert scene.job_end(run_id) == SETTLED


@pytest.mark.parametrize("scrub_ends", ["returns", "raises"])
def test_c2_the_lifecycle_sets_scrub_verified_only_when_stop_and_scrub_returns(scene, scrub_ends):
    """On the holder the job entry handed it, `scrub_verified` is still false while the scrub runs, true after a clean return, and false after a raise even though the verdict says `ran: true`. (C2, O8)"""
    from defender.box import RunTainted

    run_id = str(uuid.uuid4())
    scene.plant(run_id)
    ran = Ran()
    held: dict[str, Any] = {}

    def scrub(tree: Path, *, write_verdict: Any) -> None:
        write_verdict({"ran": True, "reason": "walk completed"})
        held["during"] = held["facts"].scrub_verified
        if scrub_ends == "raises":
            raise RunTainted("a planted link")

    real = _lifecycle(scene, investigate=_investigate(ran), scrub=scrub)

    def lifecycle(**kw: Any) -> dict[str, Any]:
        held["facts"] = kw["job_facts"]
        return real(**kw)

    run_job(scene, run_id, ran=ran, lifecycle=lifecycle)

    assert held["during"] is False
    assert held["facts"].scrub_verified is (scrub_ends == "returns")
    assert scene.job_end(run_id)["scrub_verified"] is (scrub_ends == "returns")


def test_c2_the_holder_is_the_job_entrys_and_the_investigation_is_handed_it(scene):
    """The one holder the job entry gives its lifecycle is the object the lifecycle gives the investigation; the operator path's lifecycle gets none. (C2)"""
    from defender import run as run_py

    run_id = str(uuid.uuid4())
    scene.plant(run_id)
    ran = Ran()
    given: dict[str, Any] = {}

    def investigate(**kw: Any) -> dict[str, Any]:
        given["investigation"] = kw.get("job_facts")
        return summary()

    real = _lifecycle(scene, investigate=investigate)

    def lifecycle(**kw: Any) -> dict[str, Any]:
        given["lifecycle"] = kw.get("job_facts")
        return real(**kw)

    run_job(scene, run_id, ran=ran, lifecycle=lifecycle)
    assert given["lifecycle"] is not None, given
    assert given["investigation"] is given["lifecycle"], given

    operator: dict[str, Any] = {}

    def operator_lifecycle(**kw: Any) -> dict[str, Any]:
        operator.update(kw)
        kw["run"].facts.scrub_verdict.write(json.dumps({"ran": True, "reason": "walk completed"}))
        return summary()

    rc = run_py.main([str(B.plant_alert(scene.root.parent / "op-alert")), "--tenant", scene.t.tenant_id],
                     lifecycle=operator_lifecycle, preflight=lambda *a, **k: 0, visualize=lambda *a, **k: None,
                     enqueue=lambda *a, **k: False, publish=lambda *a, **k: B.fresh(scene.t.commit))
    assert rc == 0
    assert operator.get("job_facts") is None, "the operator path was handed a job facts holder"


def test_c1_the_job_lanes_box_start_is_handed_the_launch_records_token_and_the_operators_is_not(scene):
    """Each job's box start receives its own launch record's `box_token` as `start_token`; the operator path's start passes none (the box mints its own). (C1)"""
    from defender import box as box_mod
    from defender import run as run_py

    def starts_into(seen: list[dict[str, Any]]) -> Any:
        def start(*_a: Any, **k: Any) -> Any:
            seen.append(k)
            return box_mod.unboxed_executor()
        return start

    for token in (uuid.uuid4().hex, uuid.uuid4().hex):
        run_id = str(uuid.uuid4())
        scene.plant(run_id, launch=scene.launch_doc(run_id, box_token=token))
        seen: list[dict[str, Any]] = []
        ran = Ran()
        run_job(scene, run_id, ran=ran,
                lifecycle=_lifecycle(scene, investigate=_investigate(ran), start_box=starts_into(seen)))
        assert [k.get("start_token") for k in seen] == [token], seen

    operator: list[dict[str, Any]] = []
    ran = Ran()
    rc = run_py.main([str(B.plant_alert(scene.root.parent / "op-alert")), "--tenant", scene.t.tenant_id],
                     lifecycle=_lifecycle(scene, investigate=_investigate(ran), start_box=starts_into(operator)),
                     preflight=lambda *a, **k: 0, visualize=lambda *a, **k: None,
                     enqueue=lambda *a, **k: False, publish=lambda *a, **k: B.fresh(scene.t.commit))
    assert rc == 0
    assert len(operator) == 1, operator
    assert not operator[0].get("start_token"), operator


def test_m3_a_teardown_fault_is_told_from_a_start_fault(scene):
    """The box started and its stop faulted: `box: started`, `scrub_verified` false. (M3)"""
    from defender.box import BoxFault

    run_id = str(uuid.uuid4())
    scene.plant(run_id)
    ran = Ran()

    def stop(*_a: Any, **_k: Any) -> None:
        raise BoxFault("could not tear down the box")

    got = run_job(scene, run_id, ran=ran, lifecycle=_lifecycle(scene, investigate=_investigate(ran), stop_box=stop))

    assert isinstance(got.raised, BoxFault), got
    record = scene.job_end(run_id)
    assert (record["setup"], record["box"], record["scrub_verified"]) == ("done", "started", False)


def test_m3_a_box_start_fault_is_start_failed_and_nothing_ran(scene):
    """The box could not start (no daemon): `box: start_failed`, the investigation never ran. (M3)"""
    from defender import box as box_mod
    from defender.tests.e2e import _replay_harness as RH

    run_id = str(uuid.uuid4())
    scene.plant(run_id)
    ran = Ran()
    start = functools.partial(box_mod.start_box, docker=RH._no_docker_daemon)

    run_job(scene, run_id, ran=ran, lifecycle=_lifecycle(scene, investigate=_investigate(ran), start_box=start))

    assert ran.calls["lifecycle"] == 0
    assert scene.job_end(run_id) == {"setup": "done", "box": "start_failed",
                                     "report_committed": False, "scrub_verified": False}


def test_o8_a_crash_in_the_lifecycle_records_no_report_and_reaches_the_caller(scene):
    """The investigation raises before any close: the same exception re-raised, `report_committed` false (nothing was committed), setup done. (O8, M3, r5 C2)"""
    run_id = str(uuid.uuid4())
    scene.plant(run_id)
    boom = RuntimeError("investigation blew up")

    def investigate(**_kw: Any) -> dict[str, Any]:
        raise boom

    got = run_job(scene, run_id, lifecycle=_lifecycle(scene, investigate=investigate))

    assert got.raised is boom, got
    record = scene.job_end(run_id)
    assert (record["setup"], record["box"], record["report_committed"]) == ("done", "started", False)


def test_o8_a_crash_in_the_post_steps_leaves_the_facts_set_before_it(scene):
    """The run page failing after the report and scrub does not unset them. (O8)"""
    run_id = str(uuid.uuid4())
    scene.plant(run_id)

    def visualize(*_a: Any, **_k: Any) -> None:
        raise RuntimeError("the page failed")

    run_job(scene, run_id, visualize=visualize)

    assert scene.job_end(run_id) == SETTLED


# --- R2: the job lane never runs unsandboxed ---------------------------------------------------------

def test_r2_with_the_opt_out_set_and_no_docker_a_job_is_start_failed_and_nothing_runs(scene, monkeypatch):
    """`DEFENDER_ALLOW_UNSANDBOXED` set, no daemon: `box: start_failed` and the investigation never ran on the host. (R2)"""
    from defender import box as box_mod
    from defender.tests.e2e import _replay_harness as RH

    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", "1")
    start = functools.partial(box_mod.start_box, docker=RH._no_docker_daemon)
    run_id = str(uuid.uuid4())
    scene.plant(run_id)
    job = Ran()

    run_job(scene, run_id, ran=job, lifecycle=_lifecycle(scene, investigate=_investigate(job), start_box=start))

    assert job.calls["lifecycle"] == 0, "the job lane ran the investigation on the host"
    assert scene.job_end(run_id)["box"] == "start_failed"


def test_r2_control_the_operator_path_with_the_same_environment_and_seams_does_run_on_the_host(
        scene, tmp_path, monkeypatch):
    """Control for R2: same opt-out, same no-daemon start; the operator run runs its investigation. (R2)"""
    from defender import box as box_mod
    from defender.tests.e2e import _replay_harness as RH

    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", "1")
    start = functools.partial(box_mod.start_box, docker=RH._no_docker_daemon)
    operator = Ran()

    launched = B.launch(scene.t, tmp_path, publish=lambda *a, **k: B.fresh(scene.t.commit),
                        lifecycle=_lifecycle(scene, investigate=_investigate(operator), start_box=start))

    assert launched.raised is None, launched.text()
    assert operator.calls["lifecycle"] == 1, launched.text()


# --- M4: no outside write ------------------------------------------------------------------------------

class _Tripwire:
    def __init__(self) -> None:
        self.called: list[str] = []

    def __getattr__(self, name: str) -> Any:
        def refuse(*_a: Any, **_k: Any) -> Any:
            self.called.append(name)
            raise AssertionError(f"a job-lane run reached {name}")
        return refuse


def _operator_composition_still_opens_records_and_enqueues(scene: Scene, tmp_path: Path) -> None:
    """Positive control: the operator composition, through its seams, still opens, records and enqueues."""
    from defender import run as run_py

    seen: list[str] = []

    class Writer:
        def open_case_ticket(self, *_a: Any, **_k: Any) -> None:
            seen.append("open")

        def record_case_ticket(self, *_a: Any, **_k: Any) -> None:
            seen.append("record")

    def enq(*_a: Any, **_k: Any) -> bool:
        seen.append("enqueue")
        return False

    alert = B.plant_alert(tmp_path / "op-alert")
    rc = run_py.main([str(alert), "--tenant", scene.t.tenant_id, "--update-ticket"],
                     lifecycle=lambda **kw: summary(), preflight=lambda *a, **k: 0,
                     visualize=lambda *a, **k: None, ticket_writer=Writer(), enqueue=enq,
                     publish=lambda *a, **k: B.fresh(scene.t.commit))
    assert rc == 0
    assert seen == ["open", "record", "enqueue"], seen


@pytest.fixture
def docker_shim(tmp_path, monkeypatch):
    """A `docker` first on PATH that logs and fails, and the audit record of launched processes; returns `docker_execs()`: the `exec` lines the shim logged and the `docker ... exec` argvs launched."""
    shim_log = tmp_path / "docker-shim.log"
    shim = tmp_path / "docker-shim" / "docker"
    shim.parent.mkdir()
    shim.write_text(f'#!/bin/sh\necho "$@" >> {shim_log}\nexit 1\n', encoding="utf-8")
    shim.chmod(0o755)
    monkeypatch.setenv("PATH", f"{shim.parent}{os.pathsep}{os.environ.get('PATH', '')}")
    spawns = AuditWatch.watch_spawns()

    def docker_execs() -> tuple[list[str], list[list[str]]]:
        logged = shim_log.read_text(encoding="utf-8").splitlines() if shim_log.exists() else []
        return ([line for line in logged if "exec" in line.split()],
                [argv for argv in spawns if argv and Path(argv[0]).name == "docker" and "exec" in argv])

    yield docker_execs
    AuditWatch.stop_spawns()


def test_m4_a_job_run_opens_no_ticket_and_enqueues_no_curation_while_the_operator_path_does(
        scene, tmp_path, monkeypatch, docker_shim):
    """The job entry takes no seam for either and calls neither; `run.main` still does, by default. (M4, O11)"""
    import inspect

    from defender import run as run_py
    from defender import run_common

    assert not {"ticket_writer", "enqueue"} & set(inspect.signature(run_py.job_main).parameters)
    tripped: list[str] = []

    def enqueue(*_a: Any, **_k: Any) -> bool:
        tripped.append("enqueue_curation")
        return False

    monkeypatch.setattr(run_common, "enqueue_curation", enqueue)  # lint-monkeypatch: ok — a tripwire on the module attribute the job entry would reach; no seam exists by design
    wire = _Tripwire()
    writer_module = run_py._default_ticket_writer
    real_open, real_record = writer_module.open_case_ticket, writer_module.record_case_ticket
    # the writer's own entry points swallow every fault, and an import-time alias escapes a patch of the
    # public names: trip the names both entry points resolve at call time, recording before raising
    for name in ("open_case_ticket", "record_case_ticket", "_verb_context", "_config_of", "_post_comment",
                 "_write_receipt"):
        monkeypatch.setattr(writer_module, name, getattr(wire, name))  # lint-monkeypatch: ok — same tripwire, ticket writer
    # an import-time alias of the writer's helpers or of `DEFAULT_DEPS.request` escapes all of those: the
    # transport every route ends in is tripped too
    monkeypatch.setattr(writer_module.integrations, "docker_exec_curl", wire.docker_exec_curl)  # lint-monkeypatch: ok — same tripwire, the writer's transport
    # a function object bound at import time escapes even that: trip the process launch beneath it, on
    # any `docker ... exec` (the one thing the transport does), whatever route reached it
    import subprocess

    launched: list[list[str]] = []
    real_run = subprocess.run

    def run_unless_docker_exec(cmd: Any, *a: Any, **k: Any) -> Any:
        argv = [str(part) for part in cmd] if isinstance(cmd, (list, tuple)) else [str(cmd)]
        if argv and Path(argv[0]).name == "docker" and "exec" in argv:
            launched.append(argv)
            raise AssertionError("a job-lane run launched a docker exec")
        return real_run(cmd, *a, **k)

    monkeypatch.setattr(subprocess, "run", run_unless_docker_exec)  # lint-monkeypatch: ok — a tripwire beneath the writer's transport; no seam exists by design
    # a launch bound before any patch escapes that too: a `docker` first on PATH that logs and fails, and the
    # interpreter's own process-launch audit record, both below every Python name
    docker_execs = docker_shim

    run_id = str(uuid.uuid4())
    scene.plant(run_id)
    (scene.root / scene.t.tenant_id / "learning").mkdir()  # tenant setup provides the learning root
    before = set(tree(scene.root))
    got = run_job(scene, run_id)

    assert got.calls["lifecycle"] == 1, got
    assert got.raised is None, got
    assert (tripped, wire.called, launched) == ([], [], [])
    assert docker_execs() == ([], []), "a job-lane run launched a docker exec beneath the Python names"
    # control: the tripwire is live, so an alias of the real entry points would have been caught
    probe = SimpleNamespace(run_dir=tmp_path / "probe")
    real_open(probe, tenant=None, defender_dir=tmp_path, env={})
    with contextlib.suppress(AssertionError):  # the record leg's own handler reaches another tripped name
        real_record(probe, tenant=None, defender_dir=tmp_path, env={}, truncated_by=None, closed_before_cut=False)
    assert wire.called.count("_verb_context") == 2
    wire.called.clear()
    from defender.tests.integrations.credential_proxy_1163._adapter1163 import ctx_for as _ctx_for
    from defender.tests.support.tenancy import _tenants1106
    config = {"URL_BASE": "http://store.invalid", "BASTION_HOST": "bastion.invalid"}
    with pytest.raises(AssertionError):  # control: a call through the writer's default deps reaches the tripped transport
        # #1163: `_request` reads `ctx.tenant` first; a tenant whose ticket system is not proxied reaches the transport
        writer_module.DEFAULT_DEPS.request(config, "POST", "/tickets", {}, ctx=_ctx_for(tmp_path, _tenants1106.fixture_run_tenant(), None, None))
    assert wire.called == ["docker_exec_curl"]
    wire.called.clear()
    with pytest.raises(AssertionError):  # control: the process tripwire is live
        subprocess.run(["docker", "--context", "c", "exec", "box", "curl"], check=False)
    assert launched, "the launch tripwire never saw the docker exec"
    launched.clear()
    real_run(["docker", "--context", "c", "exec", "box", "curl"], check=False)  # control: below the patch, the shim and the audit see it
    shim_seen, audit_seen = docker_execs()
    assert (len(shim_seen), len(audit_seen)) == (1, 1), (shim_seen, audit_seen)
    AuditWatch.stop_spawns()
    # a helper that captured `enqueue_curation` at definition time escapes the module patch: look at disk too
    made = [k for k in set(tree(scene.root)) - before if re.search(r"curat|queue|learn", k, re.IGNORECASE)]
    assert made == [], f"the job lane left curation state behind: {made}"

    _operator_composition_still_opens_records_and_enqueues(scene, tmp_path)

def test_m4_the_job_entry_has_no_open_seam_and_refuses_a_ticket_writer(scene):
    """`job_main` takes no `*args` or `**kwargs`, and a call handing it a `ticket_writer` or an `enqueue` is a `TypeError`. (M4, O11)"""
    import inspect

    from defender import run as run_py

    kinds = {p.kind for p in inspect.signature(run_py.job_main).parameters.values()}
    assert inspect.Parameter.VAR_KEYWORD not in kinds, kinds
    assert inspect.Parameter.VAR_POSITIONAL not in kinds, kinds
    for seam in ("ticket_writer", "enqueue"):
        run_id = str(uuid.uuid4())
        scene.plant(run_id)
        ran = Ran()
        seams: dict[str, Any] = {
            "lifecycle": verified_lifecycle(ran), "preflight": lambda *a, **k: 0,
            "visualize": lambda *a, **k: None, "publish": lambda *a, **k: B.fresh(scene.t.commit),
            seam: _Tripwire()}
        with pytest.raises(TypeError):
            run_py.job_main(scene.argv(run_id), **seams)
        assert ran.calls["lifecycle"] == 0, f"a {seam} seam was accepted and the job ran"



def test_m4_the_job_entry_has_exactly_the_ratified_parameters_and_refuses_any_other_keyword(scene):
    """`job_main` is `argv` and the keyword-only seams `lifecycle`, `visualize`, `preflight`, `materialize`, `roster`, `publish`; any other keyword is a `TypeError`. (M4, O11)"""
    import inspect

    from defender import run as run_py

    parameters = inspect.signature(run_py.job_main).parameters
    assert list(parameters) == ["argv", "lifecycle", "visualize", "preflight", "materialize", "roster", "publish"]
    main_defaults = {n: p.default for n, p in inspect.signature(run_py.main).parameters.items() if n != "argv"}
    for seam in ("lifecycle", "visualize", "preflight", "materialize", "roster", "publish"):
        assert parameters[seam].default is main_defaults[seam], f"{seam}: the job entry's default is not the operator run's own"
    assert main_defaults["lifecycle"] is run_py._run_investigation_lifecycle, "the production lifecycle (D-k)"
    assert [n for n, p in parameters.items() if p.kind is inspect.Parameter.KEYWORD_ONLY] == list(parameters)[1:]
    for extra in ("case_ticket", "ticket_writer", "enqueue", "oracle", "verifier", "update_ticket", "anything_else"):
        run_id = str(uuid.uuid4())
        scene.plant(run_id)
        ran = Ran()
        with pytest.raises(TypeError):
            run_py.job_main(scene.argv(run_id), lifecycle=verified_lifecycle(ran), preflight=lambda *a, **k: 0,
                            visualize=lambda *a, **k: None, publish=lambda *a, **k: B.fresh(scene.t.commit),
                            **{extra: _Tripwire()})
        assert ran.calls["lifecycle"] == 0, f"a {extra} keyword was accepted and the job ran"


def test_m4_run_py_binds_nothing_of_the_ticket_writer_or_its_transport_at_import():
    """No name in `run.py`'s namespace is a function, class or object defined in the ticket writer or the integrations transport (the writer module itself apart). (M4, O11)"""
    import types

    from defender import run as run_py

    homes = ("defender.investigation.ticket_writer", "defender.integrations")
    bound = {name: getattr(value, "__module__", None) for name, value in vars(run_py).items()
             if not isinstance(value, types.ModuleType)
             and (getattr(value, "__module__", None) or "").startswith(homes)}
    assert bound == {}, f"run.py holds import-time aliases of the writer's internals: {bound}"
    assert run_py._default_ticket_writer.__name__ == "defender.investigation.ticket_writer", "premise: the one module binding"


def test_m4_the_disk_check_sees_the_operator_default_enqueue(scene, tmp_path):
    """Control for the M4 disk check: `run.main`'s own default enqueue writes `learning/author-queue/case-*.json`. (M4)"""
    from defender import run as run_py

    class Writer:
        def open_case_ticket(self, *_a: Any, **_k: Any) -> None: ...
        def record_case_ticket(self, *_a: Any, **_k: Any) -> None: ...

    def lifecycle(**kw: Any) -> dict[str, Any]:
        kw["run"].facts.scrub_verdict.write('{"ran": true, "reason": "walk completed"}')
        return summary()

    (scene.root / scene.t.tenant_id / "learning").mkdir()
    before = set(tree(scene.root))
    rc = run_py.main([str(B.plant_alert(tmp_path / "op-alert")), "--tenant", scene.t.tenant_id, "--update-ticket"],
                     lifecycle=lifecycle, preflight=lambda *a, **k: 0, visualize=lambda *a, **k: None,
                     ticket_writer=Writer(), publish=lambda *a, **k: B.fresh(scene.t.commit))
    assert rc == 0
    made = [k for k in set(tree(scene.root)) - before if re.search(r"learning/author-queue/case-.*\.json$", k)]
    assert made, "the operator default enqueue left no queue entry the disk check can see"


# --- the sidecar split --------------------------------------------------------------------------------------

def test_o6_sidecar_lists_split_used_within_accepted():
    """Launch and alert files are accepted only; the job-end record is used and accepted. (O6)"""
    from defender.records._layout import ACCEPTED_SIDECAR_SUFFIXES, USED_SIDECAR_SUFFIXES

    assert set(USED_SIDECAR_SUFFIXES) <= set(ACCEPTED_SIDECAR_SUFFIXES)
    for suffix in (".launch.json", ".alert.json"):
        assert suffix in ACCEPTED_SIDECAR_SUFFIXES
        assert suffix not in USED_SIDECAR_SUFFIXES
    assert ".job-end.json" in USED_SIDECAR_SUFFIXES


def test_o6_runs_listing_lists_a_run_beside_launch_alert_and_job_end_files(tmp_path):
    """The worker's files beside run folders do not refuse the listing; an unknown file still does. (O6)"""
    from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H
    from defender.tests.support.shared._locations_1210 import location_path

    ids = sorted(str(uuid.uuid4()) for _ in range(2))
    _root, t = H.tenant_with_runs(tmp_path, *ids)
    runs = Path(location_path(t.runs))
    H.plant_sidecars(runs, ids[0], job_lane=True)
    queued = str(uuid.uuid4())  # launch files for an id whose child has not yet made its folder
    (runs / f"{queued}.launch.json").write_text("{}\n", encoding="utf-8")
    (runs / f"{queued}.alert.json").write_text("{}\n", encoding="utf-8")

    listed = [str(r) for r in t.runs_repository().list()]

    assert sorted(listed) == ids

    (runs / f"{ids[0]}.not-a-sidecar.json").write_text("{}\n", encoding="utf-8")
    assert H.raised(t.runs_repository().list) is not None, "control: an unknown file beside the runs is refused"


# --- the death tie, child side (O7) ------------------------------------------------------------------------

def _wait(condition: Any, *, timeout: float, what: str) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        if time.monotonic() > deadline:
            raise AssertionError(f"timed out waiting for {what}")
        time.sleep(0.05)


def _gone(pid: int) -> bool:
    try:
        return "\nState:\tZ" in Path(f"/proc/{pid}/status").read_text(encoding="utf-8")
    except FileNotFoundError:
        return True


def _child_cmd(s: Scene, marks: Path, run_id: str, parent: int, mode: str = "hold") -> list[str]:
    return [sys.executable, str(ENTRY), mode, s.t.commit, str(marks), *s.argv(run_id, parent)]


def _env(s: Scene) -> dict[str, str]:
    return {**os.environ, "DEFENDER_DATA_ROOT": str(s.root), "DEFENDER_DATABASE_DSN": s.dsn,
            "PYTHONPATH": f"{WORKTREE}{os.pathsep}{os.environ.get('PYTHONPATH', '')}"}


@pytest.mark.parametrize(("mode", "committed"), [("hold", False), ("hold-committed", True)])
def test_o7_a_sigterm_is_one_keyboard_interrupt_and_later_ones_do_not_interrupt_teardown(
        scene, tmp_path, mode, committed):
    """First SIGTERM reaches the investigation as `KeyboardInterrupt` and the box teardown runs; a second during teardown is ignored; the box start was handed the launch token; a report closed before the signal is still recorded as committed. (O7, r5 C1, C2)"""
    run_id = str(uuid.uuid4())
    scene.plant(run_id)
    marks = tmp_path / "marks"
    # the parent is this process: the child is spawned directly, and `--parent-pid` is our own pid
    proc = subprocess.Popen(_child_cmd(scene, marks, run_id, os.getpid(), mode), env=_env(scene),  # noqa: S603
                            cwd=str(WORKTREE), stderr=subprocess.PIPE)
    try:
        _wait(lambda: (marks / "in-lifecycle").exists() or proc.poll() is not None, timeout=120, what="the lifecycle")
        assert (marks / "in-lifecycle").exists(), proc.stderr.read().decode(errors="replace")[-2000:]
        proc.send_signal(signal.SIGTERM)
        _wait(lambda: (marks / "stop-box-started").exists(), timeout=30, what="the box teardown")
        proc.send_signal(signal.SIGTERM)
        time.sleep(0.5)
        (marks / "go-on").touch()
        proc.wait(timeout=30)
    finally:
        if proc.poll() is None:
            proc.kill()
        proc.wait(timeout=30)
    assert (marks / "interrupted").read_text(encoding="utf-8") == "KeyboardInterrupt"
    assert (marks / "stop-box-done").exists(), "a second SIGTERM interrupted the teardown"
    assert (marks / "start-token").read_text(encoding="utf-8") == scene.token, "the box start was not handed the launch token"
    assert scene.job_end(run_id) == {"setup": "done", "box": "started", "report_committed": committed,
                                     "scrub_verified": False}, "an interrupted run still leaves its job-end record"


_INTERMEDIATE = """
import subprocess, sys, time
child = subprocess.Popen(sys.argv[2:])
open(sys.argv[1], "w").write(str(child.pid))
time.sleep(600)
"""


def test_o7_the_parent_check_runs_with_the_death_signal_already_set(scene, monkeypatch):
    """When the check of the given parent pid runs, the process's parent-death signal is already SIGTERM. (O7)"""
    from defender import run as run_py

    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl(1, 0)  # PR_SET_PDEATHSIG: clear, so only the entry itself can have set it
    real, seen = run_py._require_parent, []

    def observing(parent_pid: int) -> None:
        got = ctypes.c_int(-1)
        libc.prctl(2, ctypes.byref(got))  # PR_GET_PDEATHSIG
        seen.append(got.value)
        real(parent_pid)

    monkeypatch.setattr(run_py, "_require_parent", observing)  # lint-monkeypatch: ok — an observer of the entry's own check, no seam exists for it
    run_id = str(uuid.uuid4())
    scene.plant(run_id)

    ran = run_job(scene, run_id)

    assert ran.raised is None, ran
    assert seen == [int(signal.SIGTERM)], "the parent check ran before the death signal was set (a race with the worker's death)"


def test_o7_a_child_ends_through_its_box_teardown_when_its_parent_is_killed(scene, tmp_path):
    """SIGKILL the parent: the parent-death signal unwinds the child through the stop-box seam and it exits. (O7)"""
    run_id = str(uuid.uuid4())
    scene.plant(run_id)
    marks, pidfile = tmp_path / "marks", tmp_path / "child.pid"
    marks.mkdir()
    (marks / "go-on").touch()
    script = _INTERMEDIATE.replace("subprocess.Popen(sys.argv[2:])",
                                   "subprocess.Popen([a if a != 'PARENT' else str(__import__('os').getpid()) for a in sys.argv[2:]])")
    parent = subprocess.Popen(  # noqa: S603
        [sys.executable, "-c", script, str(pidfile), sys.executable, str(ENTRY), "hold", scene.t.commit,
         str(marks), "--job", run_id, "--tenant", scene.t.tenant_id, "--parent-pid", "PARENT"],
        env=_env(scene), cwd=str(WORKTREE))
    child_pid = None
    try:
        _wait(lambda: (marks / "in-lifecycle").exists() or parent.poll() is not None, timeout=120, what="the lifecycle")
        assert (marks / "in-lifecycle").exists(), "the child never reached its lifecycle"
        child_pid = int(pidfile.read_text(encoding="utf-8"))
        assert not _gone(child_pid), "control: the child is alive while its parent is"
        parent.kill()
        parent.wait(timeout=30)
        _wait(lambda: _gone(child_pid), timeout=60, what="the child to exit")
    finally:
        if parent.poll() is None:
            parent.kill()
        if child_pid is not None and not _gone(child_pid):
            os.kill(child_pid, signal.SIGKILL)
    assert (marks / "stop-box-done").exists(), "the child did not unwind through its box teardown"


def test_o7_a_child_whose_given_parent_is_not_its_parent_exits_at_once(scene, tmp_path):
    """`--parent-pid` naming a live process that did not spawn it: the child exits before its lifecycle. (O7)"""
    run_id = str(uuid.uuid4())
    scene.plant(run_id)
    marks = tmp_path / "marks"
    bystander = subprocess.Popen(["sleep", "300"])  # noqa: S603, S607
    try:
        proc = subprocess.Popen(_child_cmd(scene, marks, run_id, bystander.pid), env=_env(scene),  # noqa: S603
                                cwd=str(WORKTREE), stderr=subprocess.DEVNULL)
        try:
            proc.wait(timeout=120)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait(timeout=30)
    finally:
        bystander.kill()
        bystander.wait(timeout=30)
    assert (marks / "pid").exists(), "premise: the entry script started"
    assert not (marks / "in-lifecycle").exists(), "the child ran on under a foreign parent"
    assert not (scene.runs / run_id).exists()


# --- one real `run.py --job` on a setup refusal (no model) -------------------------------------------------------

@pytest.mark.parametrize("spelling", ["two-words", "equals"])
def test_o6_the_real_run_py_refuses_a_job_id_with_no_launch_record(tmp_path, spelling, migrated_database):
    """`run.py --job <id>` and `--job=<id>` with no launch record: exit 1 naming it, nothing made, the job-end record says what failed. (O6)"""
    root = tmp_path / "data"
    root.mkdir()
    run_id = str(uuid.uuid4())
    with B.run_tenant(tmp_path, root) as t:
        register_tenant(migrated_database, t.tenant_id, data_root=root)
        runs = root / t.tenant_id / "runs"
        runs.mkdir(exist_ok=True)
        proc = subprocess.run(  # noqa: S603 — the real run entry
            [sys.executable, str(DEFENDER / "run.py"), *(["--job", run_id] if spelling == "two-words" else [f"--job={run_id}"]),
             "--tenant", t.tenant_id, "--parent-pid", str(os.getpid())],
            env={**os.environ, "DEFENDER_DATA_ROOT": str(root), "DEFENDER_DATABASE_DSN": migrated_database,
                 "PYTHONPATH": f"{WORKTREE}{os.pathsep}{os.environ.get('PYTHONPATH', '')}"},
            cwd=str(WORKTREE), capture_output=True, text=True, timeout=180, check=False)

        assert "unrecognized arguments" not in proc.stderr, proc.stderr
        assert proc.returncode == 1, proc.stderr[-2000:]
        assert "launch" in proc.stderr.lower(), proc.stderr[-2000:]
        assert not (runs / run_id).exists()
        record = json.loads((runs / f"{run_id}.job-end.json").read_text(encoding="utf-8"))
        assert record == {"setup": "refused", "box": "not_started", "report_committed": False,
                          "scrub_verified": False}



# --- R6-8: a job signs like an operator run (#1163 on the job lane) -----------------------------------

PROXY_ADDRESS = "http://proxy.invalid"
SIGN_ROLE, SIGN_SECRET = "role-1342-sign", "secret-1342-sign"


@pytest.fixture
def proxied_scene(tmp_path, monkeypatch, migrated_database):
    """A factory for a job scene whose tenant has `identity` on `http-proxy` (the declaration #1163's
    operator-path tests plant), with a live generation holding a sign login when `sign`, and the proxy
    address in the environment when `address`. `job_main` takes neither: the environment and the tenant's
    records are all a worker's child has (R6-8)."""
    from defender.kit.access import PROXY_URL_ENV
    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
    from defender.tests.integrations.credential_proxy_1163 import _harness as H
    from defender.tests.support.tenancy._active1214 import insert_generation

    stack = contextlib.ExitStack()

    def make(*, sign: bool, address: bool, proxied: bool = True) -> Scene:
        root = tmp_path / "data"
        root.mkdir()
        monkeypatch.setenv("DEFENDER_DATA_ROOT", str(root))
        monkeypatch.setenv("DEFENDER_DATABASE_DSN", migrated_database)
        monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
        if address:
            monkeypatch.setenv(PROXY_URL_ENV, PROXY_ADDRESS)
        else:
            monkeypatch.delenv(PROXY_URL_ENV, raising=False)
        systems = {"identity": H.declaration("http://x.invalid/api")} if proxied else {}
        t = stack.enter_context(A.published(tmp_path / "forge", root, systems))
        register_tenant(migrated_database, t.tenant_id, data_root=root)
        if sign:
            insert_generation(migrated_database, t.tenant_id, A.generation(
                t.tenant_id, tmp_path / "secrets", sign_role_id=SIGN_ROLE, sign_secret=SIGN_SECRET))
        runs = root / t.tenant_id / "runs"
        runs.mkdir(exist_ok=True)
        return Scene(root, t, runs, dsn=migrated_database)

    with stack:
        yield make


@pytest.mark.parametrize("missing", ["no sign login", "no proxy address"])
def test_r6_8_a_job_whose_tenant_is_proxied_but_cannot_sign_is_refused_at_setup(proxied_scene, missing):
    """A granted `http-proxy` system and no sign login (no live generation), or no proxy address in the
    environment: `setup: refused`, recorded and not a crash, and no run is made - the operator path's own
    refusal (#1163 R7), on the job lane. (R6-8)"""
    scene = proxied_scene(sign=missing != "no sign login", address=missing != "no proxy address")
    run_id = str(uuid.uuid4())
    scene.plant(run_id)

    ran = run_job(scene, run_id)

    assert ran.raised is None, f"a refusal was a crash: {ran.raised!r}"
    assert ran.calls["lifecycle"] == 0, "a run was made for a tenant that cannot sign"
    assert scene.job_end(run_id) == REFUSED
    assert not (scene.runs / run_id).exists(), "the run folder was made before the refusal"


def _openbao_under_httpx(monkeypatch, accounts):
    """An OpenBao stand-in beneath the job entry: httpx's default transport (what the production signer's
    client uses, `job_main` having no issuer seam) hands every request to it. Returns the stand-in."""
    import httpx

    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A

    bao = A.OpenBaoStandIn(accounts)
    monkeypatch.setattr(httpx.HTTPTransport, "handle_request",  # lint-monkeypatch: ok — beneath the job entry, which has no issuer seam; the production signer's client reaches the default transport
                        lambda _self, request: bao.handle_request(request))
    return bao


def test_r6_8_a_job_whose_tenant_can_sign_gets_the_read_access_on_its_investigate_call(proxied_scene, monkeypatch):
    """Control for the refusal: with a sign login and the address, the same job runs, and its lifecycle is
    handed the `RequestAccess` the operator path's is: the proxy's address from the environment and a read
    token signed, when first asked, through the tenant's own sign login at the deployment's OpenBao. (R6-8)"""
    from defender.tests.integrations.credential_proxy_1163 import _adapter1163 as A
    from defender.tests.integrations.credential_proxy_1163._target import request_access_type

    scene = proxied_scene(sign=True, address=True)
    bao = _openbao_under_httpx(monkeypatch, {SIGN_ROLE: SIGN_SECRET})
    run_id = str(uuid.uuid4())
    scene.plant(run_id)
    seen: list[Any] = []
    ran = Ran()
    inner = verified_lifecycle(ran)

    def lifecycle(**kw: Any) -> dict[str, Any]:
        access = kw.get("access")
        seen.append(access)
        if access is not None and callable(access.token):
            seen.append(access.token())
        return inner(**kw)

    got = run_job(scene, run_id, lifecycle=lifecycle, ran=ran)

    assert got.raised is None, got
    assert scene.job_end(run_id) == SETTLED
    access, token = seen
    assert access is not None, "the job's lifecycle was handed no access: its calls carry no token"
    assert isinstance(access, request_access_type())
    assert access.proxy_url == PROXY_ADDRESS
    assert A.SIGNATURE_CANARY in token, "the read token was not signed by OpenBao"
    assert bao.logins == [(SIGN_ROLE, SIGN_SECRET)], "the token was not minted through the tenant's sign login"
    assert len(bao.signs) == 1, "positive control: the read token was signed"
    assert set(bao.origins) == {A.deployment_origin()}, bao.origins


def test_r6_8_a_job_whose_tenant_has_no_http_proxy_system_is_handed_no_access_and_needs_no_signing(proxied_scene, monkeypatch):
    """Control: no `http-proxy` system, and neither a sign login nor an address, still runs; no access is
    handed (the operator path's #1163 R3). (R6-8)"""
    scene = proxied_scene(sign=False, address=False, proxied=False)
    bao = _openbao_under_httpx(monkeypatch, {SIGN_ROLE: SIGN_SECRET})
    run_id = str(uuid.uuid4())
    scene.plant(run_id)
    seen: list[Any] = []
    ran = Ran()
    inner = verified_lifecycle(ran)

    def lifecycle(**kw: Any) -> dict[str, Any]:
        seen.append(kw.get("access"))
        return inner(**kw)

    got = run_job(scene, run_id, lifecycle=lifecycle, ran=ran)

    assert got.raised is None, got
    assert scene.job_end(run_id) == SETTLED
    assert len(seen) == 1, seen
    assert not seen[0], seen  # no access to sign with, and the job was not refused
    assert (bao.requests, bao.logins, bao.signs) == ([], [], []), "the signer was contacted"
