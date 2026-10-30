"""#1342 the child's job entry (`run.job_main`, `run.py --job`): run setup in the job lane (O6, M1, M5),
the job-end record's facts (O8 child side, M3), the sidecar split, no outside write (M4), the job lane
never running unsandboxed (R2), and the child's death-tie setup (O7). No database: the worker is not here.

In-process cases drive `job_main` with the real `materialize` over a published fixture tenant, a
planted launch record and alert file, and a lifecycle seam. Death-tie cases run `_job_entry1342.py`
as a real child process and observe through its marks. Every wait is bounded."""
from __future__ import annotations

import contextlib
import ctypes
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
from typing import Any

import pytest

from defender.tests.support.jobs._jobs1342 import (
    ALERT_BYTES,
    AWKWARD_ALERT_BYTES,
    DECOMPOSED_ALERT_BYTES,
    DEFENDER,
    PADDED_ALERT_BYTES,
    TITLE,
    WORKTREE,
    tree,
)
from defender.tests.tenancy.tenant_1108_p4 import _s_b_support as B

ENTRY = DEFENDER / "tests" / "support" / "jobs" / "_job_entry1342.py"
OTHER_TENANT = str(uuid.UUID(int=0x1342))
SETTLED = {"setup": "done", "box": "started", "report_committed": True, "scrub_verified": True}


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

    def launch_doc(self, run_id: str, **over: Any) -> dict[str, Any]:
        return {"investigation_id": run_id, "tenant_id": self.t.tenant_id, "alert_id": str(uuid.uuid4()),
                "digest": hashlib.sha256(ALERT_BYTES).hexdigest(), "label": TITLE, **over}

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
def scene(tmp_path, monkeypatch):
    root = tmp_path / "data"
    root.mkdir()
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(root))
    monkeypatch.delenv("DEFENDER_ALLOW_UNSANDBOXED", raising=False)
    with B.run_tenant(tmp_path, root) as t:
        runs = root / t.tenant_id / "runs"
        runs.mkdir(exist_ok=True)
        yield Scene(root, t, runs)


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


def verified_lifecycle(ran: Ran, *, report_committed: bool = True):
    """A lifecycle seam that records the call and leaves the host scrub verdict a real scrub would."""
    def lifecycle(**kw: Any) -> dict[str, Any]:
        ran.calls["lifecycle"] += 1
        kw["run"].facts.scrub_verdict.write(json.dumps({"ran": True, "reason": "walk completed"}))
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

    def __init__(self, monkeypatch: Any, run_dir: Path) -> None:
        from defender import run as run_py  # noqa: F401 — imported first: its seam defaults bind the real readers, never a spy
        from defender import run_common
        from defender.presentation import visualize_run

        self.events: list[str] = []
        real_iterdir, real_cross = Path.iterdir, run_common.cross_check_tables

        def iterdir(path: Path) -> Any:
            if path == run_dir:
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


@pytest.mark.parametrize("raw", [ALERT_BYTES, AWKWARD_ALERT_BYTES, PADDED_ALERT_BYTES, DECOMPOSED_ALERT_BYTES],
                         ids=["as the fixture", "crlf tab multibyte", "leading whitespace and trailing spaces",
                              "decomposed unicode"])
def test_o6_the_runs_input_alert_is_the_launch_files_exact_bytes_and_hashes_to_the_record(scene, raw):
    """The alert the run holds equals the alert file byte for byte (trailing newline, CRLF, padding whitespace and decomposed text too) and matches the launch digest. (O6, O2, M5)"""
    from defender.records import RunPaths

    run_id = str(uuid.uuid4())
    scene.plant(run_id, launch=scene.launch_doc(run_id, digest=hashlib.sha256(raw).hexdigest()), alert=raw)
    wanted = json.loads((scene.runs / f"{run_id}.launch.json").read_text(encoding="utf-8"))["digest"]

    ran = run_job(scene, run_id)

    assert ran.raised is None, ran
    held = RunPaths(scene.runs / run_id).alert.read_bytes()
    assert raw.endswith((b"\n", b"\r\n")), "premise: the fixture ends in a line end"
    assert held == (scene.runs / f"{run_id}.alert.json").read_bytes() == raw
    assert hashlib.sha256(held).hexdigest() == wanted


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
    "no-alert-file": dict(alert=None),
    "digest-mismatch-on-the-admitted-bytes": dict(alert=ALERT_BYTES.replace(b"1.50", b"1.51")),
    "launch-record-symlinked": dict(tamper="launch-link"),
    "launch-record-oversize": dict(tamper="launch-oversize"),
    "alert-file-symlinked": dict(tamper="alert-link"),
}
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
    """No launch record, another tenant's, another id's, unparseable, symlinked or oversize, an alert file that is a symlink, or a digest the alert bytes miss: refused and recorded `setup: refused`; nothing spent, nothing made. (O6, M1, M5)"""
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


def test_m1_a_tenant_acceptance_refusal_is_recorded_as_setup_refused(scene):
    """The door is opened before tenant acceptance, so a tenant the host refuses still leaves the record. (M1)"""
    run_id = str(uuid.uuid4())
    scene.plant(run_id)
    (scene.root / scene.t.tenant_id / "tenant.json").write_text("{", encoding="utf-8")

    ran = run_job(scene, run_id)

    assert ran.calls["lifecycle"] == 0
    assert scene.job_end(run_id) == {"setup": "refused", "box": "not_started",
                                     "report_committed": False, "scrub_verified": False}


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
    assert spies.events.index("list") < spies.events.index("cross-check") < spies.events.index("seam-visualize")


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


def _investigate(ran: Ran, *, without: str | None = None, **summary_kw: Any):
    def investigate(**_kw: Any) -> dict[str, Any]:
        ran.calls["lifecycle"] += 1
        doc = summary(**summary_kw)
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
def test_o8_report_committed_comes_from_the_drivers_summary(scene, committed, verified, want):
    """The job-end record carries the driver summary's `report_committed`, and the scrub verdict's `ran`. (O8, M2)"""
    run_id = str(uuid.uuid4())
    scene.plant(run_id)
    ran = Ran()
    scrub = _verdict_scrub({"ran": verified, "reason": "walk"})

    run_job(scene, run_id, ran=ran, lifecycle=_lifecycle(
        scene, investigate=_investigate(ran, report_committed=committed), scrub=scrub))

    assert scene.job_end(run_id) == want


def test_m2_a_summary_without_the_report_committed_key_is_not_a_committed_report(scene):
    """A driver summary that lacks `report_committed` records `report_committed: false`. (M2)"""
    run_id = str(uuid.uuid4())
    scene.plant(run_id)
    ran = Ran()

    run_job(scene, run_id, ran=ran, lifecycle=_lifecycle(
        scene, investigate=_investigate(ran, without="report_committed")))

    assert scene.job_end(run_id) == {**SETTLED, "report_committed": False}


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
    assert (isinstance(got.raised, RunTainted) or (got.exit is not None and got.exit.code not in (0, None))
            or got.rc not in (0, None)), got
    assert spies.seam_calls == 0, "the page was rendered from a tainted tree"
    assert spies.events == [], f"a reader of the tainted tree ran: {spies.events}"


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
    """The investigation raises: the same exception re-raised, `report_committed` false, setup done. (O8, M3)"""
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


def test_m4_a_job_run_opens_no_ticket_and_enqueues_no_curation_while_the_operator_path_does(scene, tmp_path, monkeypatch):
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

    run_id = str(uuid.uuid4())
    scene.plant(run_id)
    (scene.root / scene.t.tenant_id / "learning").mkdir()  # tenant setup provides the learning root
    before = set(tree(scene.root))
    got = run_job(scene, run_id)

    assert got.calls["lifecycle"] == 1, got
    assert got.raised is None, got
    assert (tripped, wire.called, launched) == ([], [], [])
    # control: the tripwire is live, so an alias of the real entry points would have been caught
    from types import SimpleNamespace
    probe = SimpleNamespace(run_dir=tmp_path / "probe")
    real_open(probe, tenant=None, defender_dir=tmp_path, env={})
    with contextlib.suppress(AssertionError):  # the record leg's own handler reaches another tripped name
        real_record(probe, tenant=None, defender_dir=tmp_path, env={}, truncated_by=None, closed_before_cut=False)
    assert wire.called.count("_verb_context") == 2
    wire.called.clear()
    config = {"URL_BASE": "http://store.invalid", "BASTION_HOST": "bastion.invalid"}
    with pytest.raises(AssertionError):  # control: a call through the writer's default deps reaches the tripped transport
        writer_module.DEFAULT_DEPS.request(config, "POST", "/tickets", {}, ctx=None)
    assert wire.called == ["docker_exec_curl"]
    wire.called.clear()
    with pytest.raises(AssertionError):  # control: the process tripwire is live
        subprocess.run(["docker", "--context", "c", "exec", "box", "curl"], check=False)
    assert launched, "the launch tripwire never saw the docker exec"
    launched.clear()
    # a helper that captured `enqueue_curation` at definition time escapes the module patch: look at disk too
    made = [k for k in set(tree(scene.root)) - before if re.search(r"curat|queue|learn", k, re.IGNORECASE)]
    assert made == [], f"the job lane left curation state behind: {made}"

    # positive control: the operator composition, through its seams, still opens, records and enqueues
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


def _child_cmd(s: Scene, marks: Path, run_id: str, parent: int) -> list[str]:
    return [sys.executable, str(ENTRY), "hold", s.t.commit, str(marks), *s.argv(run_id, parent)]


def _env(s: Scene) -> dict[str, str]:
    return {**os.environ, "DEFENDER_DATA_ROOT": str(s.root),
            "PYTHONPATH": f"{WORKTREE}{os.pathsep}{os.environ.get('PYTHONPATH', '')}"}


def test_o7_a_sigterm_is_one_keyboard_interrupt_and_later_ones_do_not_interrupt_teardown(scene, tmp_path):
    """First SIGTERM reaches the investigation as `KeyboardInterrupt` and the box teardown runs; a second during teardown is ignored. (O7)"""
    run_id = str(uuid.uuid4())
    scene.plant(run_id)
    marks = tmp_path / "marks"
    # the parent is this process: the child is spawned directly, and `--parent-pid` is our own pid
    proc = subprocess.Popen(_child_cmd(scene, marks, run_id, os.getpid()), env=_env(scene),  # noqa: S603
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
    assert scene.job_end(run_id) == {"setup": "done", "box": "started", "report_committed": False,
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

def test_o6_the_real_run_py_refuses_a_job_id_with_no_launch_record(tmp_path):
    """`run.py --job <id>` with no launch record: exit 1 naming it, nothing made, the job-end record says what failed. (O6)"""
    root = tmp_path / "data"
    root.mkdir()
    run_id = str(uuid.uuid4())
    with B.run_tenant(tmp_path, root) as t:
        runs = root / t.tenant_id / "runs"
        runs.mkdir(exist_ok=True)
        proc = subprocess.run(  # noqa: S603 — the real run entry
            [sys.executable, str(DEFENDER / "run.py"), "--job", run_id, "--tenant", t.tenant_id,
             "--parent-pid", str(os.getpid())],
            env={**os.environ, "DEFENDER_DATA_ROOT": str(root),
                 "PYTHONPATH": f"{WORKTREE}{os.pathsep}{os.environ.get('PYTHONPATH', '')}"},
            cwd=str(WORKTREE), capture_output=True, text=True, timeout=180, check=False)

        assert "unrecognized arguments" not in proc.stderr, proc.stderr
        assert proc.returncode == 1, proc.stderr[-2000:]
        assert "launch" in proc.stderr.lower(), proc.stderr[-2000:]
        assert not (runs / run_id).exists()
        record = json.loads((runs / f"{run_id}.job-end.json").read_text(encoding="utf-8"))
        assert record == {"setup": "refused", "box": "not_started", "report_committed": False,
                          "scrub_verified": False}
