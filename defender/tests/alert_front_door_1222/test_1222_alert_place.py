"""Where the run's alert and record sit: a read-only input directory the box cannot change, the
lead reading the alert through its file tools, and host-side digest checks on every read."""
from __future__ import annotations

from defender.tests._spec1077 import fixture_run as _run_handle_1165

import contextlib
import functools
import json
import logging
import os
import re
import shutil
import subprocess
import uuid
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from defender.tests import _1255_view as V
from defender.tests import _triplet_947 as T
from defender.tests._1255_snapshot import calls_of, message_at, tool_calling_responses
from defender.tests._branch_947 import spec_at
from defender.tests._data_root_1078 import DATA_ROOT_ENV
from defender.tests._docker import daemon_reachable, docker_runtimes, dood_anchor, is_dood
from defender.tests.alert_front_door_1222 import _spec1222 as S
from defender.tests.e2e import _replay_harness as H

# Markers and spellings

#: The admitted alert's own marker (a top-level member of the fixture alert). The positive
#: controls find it where it IS allowed: MAIN's raw-alert frame and the lead's own read.
MARK = "FRONTDOOR-S08-ALERT-3c9e"
#: What the box — or a host process, or a bind that failed silently — put where the alert was.
DECOY = "FRONTDOOR-S08-DECOY-71b0"
#: A valid ISO time unique to these tests: base's correlation goal carries the alert's
#: `alert_timestamp` verbatim (`_correlation_contract`), so it is an alert byte a goal can show.
UNIQUE_TS = "2026-05-25T15:27:22.424242Z"
#: The tail of an alert longer than one read (PA-27: 65,536 characters).
TAIL = "FRONTDOOR-S08-TAIL-0d4a"
#: A file one directory down that is NOT the input directory (PA-05's refusal case).
OTHER_DIR_FILE = "notes/secret-notes.json"
SECRET = "FRONTDOOR-S08-SECRET-a91f"
#: The env lever that turns a box startup fault into the host executor (PA-07).
ALLOW_UNSANDBOXED = "DEFENDER_ALLOW_UNSANDBOXED"
#: PA-27 (executed): the note a capped read carries, read_file's and the cat lane's alike.
TOO_LARGE = "too large to read whole"


DECOY_BYTES = S.alert_bytes(S.generic_alert(rule_id="R-DECOY-9", message=DECOY))


# The replay scenario

def _resolving(system: str, verb: str, params: dict) -> Any:
    """The backend: an `_id`-predicate fetch answers one document (item 1 resolves at base, so
    l-00c is dispatched there too); every other call is an empty envelope, built by the real
    `search_envelope`."""
    if system == "elastic" and str(params.get("native_query", "")).startswith("_id"):
        return S.envelope([{"_id": "AZ5fuw9rEmDJyXFcPn5t", "@timestamp": "2026-05-25T15:20:00Z",
                            "message": "sshd accepted password"}],
                          index=params.get("index") or "logs-*")
    if system == "elastic":
        return S.envelope([], index=params.get("index") or "logs-*")
    return {"system": system, "verb": verb, "result": []}


def _tenant() -> S.Planted:
    """A tenant whose alert mapping fits the Kibana-projected fixture alerts."""
    return S.plant_tenant(alert_mapping=S.DEFAULT_MAPPING)


def _alert(**over: Any) -> dict[str, Any]:
    """The committed sshd fixture alert carrying `MARK`, top-level members replaced by `over`."""
    return S.kibana_alert(frontdoor_note=MARK, **over)


#: MAIN's default: one harmless read (the run's provenance stamp, never the alert) and done —
#: two requests, so at base the late-injected correlation lead is awaited before MAIN's second
_MAIN_TWO_REQUESTS = [S.call("read_file", path="provenance.json"), S.text(S.DONE)]


def _run(tmp_path: Path, *, alert: Mapping[str, Any] | bytes | None = None,  # noqa: PLR0913 — one scenario's inputs, each defaulted
         tenant: S.Planted | None = None, run_id: str | None = None,
         main: Any = None, leads: Mapping[str, Any] | None = None,
         **kw: Any) -> S.Drive:
    return S.run_alert(
        tmp_path, alert=alert if alert is not None else _alert(),
        tenant=tenant if tenant is not None else _tenant(),
        # Unique per run: a scenario that drives two runs under one tenant must not collide.
        run_id=run_id or f"s08-{uuid.uuid4().hex[:10]}",
        main=main if main is not None else _MAIN_TWO_REQUESTS, leads=leads,
        backend=S.Backend(answer=_resolving), **kw)


def _returns(seen: list[S.Seen]) -> list[str]:
    """Every tool result a conversation received, IN ORDER (tool returns and refusals alike):
    the last request carries the whole history."""
    if not seen:
        return []
    return [t for k, t in seen[-1].parts if k in ("tool-return", "retry-prompt")]


def _all_text(seen: list[S.Seen]) -> str:
    """Everything the host handed a conversation, across every request it made."""
    return "\n".join(s.text + "\n" + s.instructions for s in seen)


def _framed(ret: str, needle: str) -> bool:
    """`needle` sits inside a closed untrusted frame of `ret`."""
    return any(needle in body for body in S.framed_bodies(ret))


def _assert_read_whole_and_framed(ret: str, text: str, what: str) -> None:
    assert _framed(ret, text.strip()), (
        f"{what}: the read did not return the whole file inside an untrusted frame:\n{ret[:600]}")
    assert MARK not in S.harness_text(ret), f"{what}: alert text sits OUTSIDE the frame"


@dataclass(frozen=True)
class _HostStep(S.Turn):
    """A scripted model answer that first runs a host-side step — the host replacing a file while
    the run is live (RG1's "a bind that failed silently", p152's host rename). The model double
    still decides nothing: `step` changes real bytes on the real filesystem, then the answer
    is the scripted one."""

    step: Callable[[], None] | None = None

    def response(self) -> Any:
        if self.step is not None:
            self.step()
        return super().response()


def _replace_alert(run_dir: Path, data: bytes = DECOY_BYTES) -> None:
    """The host replaces the stored alert by an atomic rename inside its own directory, keeping
    the record — the alert's bytes no longer match the recorded digest."""
    from defender.tests._alert_plant import unseal_fixture_input
    unseal_fixture_input(run_dir)
    alert = S.alert_file(run_dir)
    tmp = alert.with_name(f".s08-replace-{uuid.uuid4().hex[:8]}")
    tmp.write_bytes(data)
    os.replace(tmp, alert)


def _replace_alert_and_record(run_dir: Path, data: bytes = DECOY_BYTES) -> None:
    """The host replaces the alert AND rewrites the record's digest to match it: a folder that
    is self-consistent but no longer holds the alert an episode copied from it."""
    doc = S.read_record(run_dir)
    doc[S.COINED["record.digest"]] = S.sha256_hex(data)
    _replace_alert(run_dir, data)
    record = S.record_file(run_dir)
    tmp = record.with_name(f".s08-replace-{uuid.uuid4().hex[:8]}")
    tmp.write_bytes(json.dumps(doc).encode("utf-8"))
    os.replace(tmp, record)


def _refusal_text(exc: BaseException | None, refusal: str | None) -> str:
    """A refusal's whole text: an exception's message with its chained causes, or `run.main`'s
    refusal exit."""
    parts: list[str] = []
    if refusal:
        parts.append(refusal)
    seen: set[int] = set()
    while exc is not None and id(exc) not in seen:
        seen.add(id(exc))
        parts.append(f"{type(exc).__name__}: {exc}")
        exc = exc.__cause__ or exc.__context__
    return "\n".join(parts)


def _assert_names_the_run_and_carries_no_byte(text: str, run_dir: Path, what: str) -> None:
    """RG1's refusal: a fixed reason naming the run, carrying no byte of the alert or the
    record (the decoy's marker, the recorded digest)."""
    assert text, f"{what}: nothing refused"
    assert Path(run_dir).name in text, f"{what}: the refusal does not name the run: {text[:400]!r}"
    assert DECOY not in text, f"{what}: the refusal carries the replaced alert's bytes"
    with contextlib.suppress(AssertionError, OSError, ValueError):
        digest = S.recorded_digest(run_dir)
        assert digest not in text, f"{what}: the refusal carries the record's bytes (its digest)"


def _assert_model_refusal_names_no_run_and_carries_no_byte(text: str, run_dir: Path,
                                                            what: str) -> None:
    """RG1's refusal as a MODEL receives it (a tool result): a fixed reason carrying no byte of
    the alert or the record, and — #1255 design rev 5, C5 ("the alert-digest refusal names no
    run folder name") — no run folder name either: the run's id is an identity an arm would
    differ by (O2), and its host folder is host layout (O3). The operator-facing refusals keep
    naming the run (`_assert_names_the_run_and_carries_no_byte`)."""
    assert text, f"{what}: nothing refused"
    assert Path(run_dir).name not in text, (
        f"{what}: the refusal the model reads names the run folder: {text[:400]!r}")
    assert DECOY not in text, f"{what}: the refusal carries the replaced alert's bytes"
    with contextlib.suppress(AssertionError, OSError, ValueError):
        digest = S.recorded_digest(run_dir)
        assert digest not in text, f"{what}: the refusal carries the record's bytes (its digest)"


def _in_box(host: Path, run_dir: Path) -> str:
    """A file under the run folder as the box names it: #1255 (design rev 4, P1 Box bullet; rev
    5, C8) mounts the run folder at the model view's `/runs/current`, so the host path is not a
    path inside the box. Lexical, through the design's table (`_1255_view.model_path`)."""
    return V.model_path(host, run_dir=run_dir)


# =================================================================================================
# The box scenarios

def _lifecycle() -> Callable[..., dict]:
    """Production's lifecycle, the default of `run.main`'s `lifecycle` seam."""
    return S.sym("run", "_run_investigation_lifecycle")


def _main_boxed(tmp_path: Path, planted: S.Planted, alert: bytes, *,  # noqa: PLR0913 — the run's inputs plus the lifecycle's two seams
                start_box: Callable[..., Any], investigate: Callable[..., dict],
                run_id: str | None = None,
                around: Callable[[Callable[..., dict], dict], dict] | None = None,
                enqueue: Callable[..., bool] | None = None) -> int:
    """`run.main` with production's lifecycle, seamed at `start_box` and `investigate` only.
    `around(prod, kw)` wraps the lifecycle call (a step on the materialized folder just before
    the box starts). `enqueue=None` runs with `--no-learn`."""
    src = tmp_path / f"operator-input-{uuid.uuid4().hex[:6]}"
    src.mkdir(parents=True)
    (src / "alert.json").write_bytes(alert)
    prod = functools.partial(_lifecycle(), start_box=start_box, investigate=investigate)

    def lifecycle(**kw: Any) -> dict:
        return around(prod, kw) if around is not None else prod(**kw)

    argv = [str(src / "alert.json"), "--tenant", planted.tenant_id,
            "--run-id", run_id or f"s08-{uuid.uuid4().hex[:10]}"]
    if enqueue is None:
        argv.append("--no-learn")
    return S.sym("run", "main")(
        argv, lifecycle=lifecycle, preflight=lambda *_a, **_k: 0,
        visualize=lambda *_a, **_k: None, ticket_writer=S.NoTicket(),
        enqueue=enqueue if enqueue is not None else (lambda *_a, **_k: False))


def _scripted_daemon(**kw: Any) -> Any:
    """`e2e/_box665.RecordingDocker`: a healthy scripted daemon (create succeeds, the startup
    sentinel reads back) recording every argv, so `start_box`'s REAL argv build runs without a
    live box."""
    from defender.tests.e2e._box665 import RecordingDocker

    return RecordingDocker(**kw)


def _readonly_binds_inside(mounts: list[dict]) -> list[dict]:
    """The read-only binds whose target lies inside the box's run folder (the input
    directory's shape). Since #1255 (design rev 4, P1) the box mounts the run folder at the
    model view's `/runs/current` whatever run it is, so a bind's TARGET no longer tells one run
    from another — the callers pin which run's directory it is by the bind's SOURCE."""
    return [m for m in mounts if m["readonly"] and m["target"].startswith(V.MODEL_RUN + "/")]


def _assert_mounts_its_own_input_dir(binds: list[dict], run_dir: Path, what: str) -> None:
    """`binds` is exactly one bind: this run's input directory (host source) at its model path
    (box target)."""
    assert [b["target"] for b in binds] == [_in_box(S.input_dir(run_dir), run_dir)], (
        f"{what}: the read-only bind is not the input directory at its model path: {binds}")
    assert [Path(b["source"]).resolve() for b in binds] == [S.input_dir(run_dir).resolve()], (
        f"{what}: the read-only bind's source is not this run's own input directory: {binds}")


@contextlib.contextmanager
def _live_tree(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, *, hard: bool) -> Iterator[Path]:
    """Where a live box's bind sources hang: below `tmp_path` on a native daemon, a fresh dir
    under the shared anchor under docker-outside-of-Docker (`e2e/test_1188_box_fsize.py`'s
    `base`). This test's data root is pointed there, so the run folder and the tenant's agent
    half are both bindable. `hard=True` fails where the environment cannot start a box."""
    def unavailable(why: str) -> None:
        if hard:
            pytest.fail(f"{why} — this cell must run, never skip: CI's `test` job has a daemon "
                        "and registers runsc (78, RG1)")
        pytest.skip(why)

    if not daemon_reachable():
        unavailable("no reachable Docker daemon")
    root = tmp_path / "live"
    if is_dood():
        anchor = dood_anchor()
        if anchor is None:
            unavailable("docker-outside-of-Docker with no shared mount covering the repo tree, "
                        "so no bind source resolves (C46)")
        else:
            root = anchor / f"t1222-{uuid.uuid4().hex[:12]}"
    root.mkdir(parents=True)
    monkeypatch.setenv(DATA_ROOT_ENV, str(root / "data-root"))
    monkeypatch.delenv(ALLOW_UNSANDBOXED, raising=False)
    try:
        yield root
    finally:
        shutil.rmtree(root, ignore_errors=True)


#: One in-box probe per target, every outcome reported as DATA ("ok" or the errno's name), exit
#: 0 either way. The shapes are RJ-08's executed list (and RD-02's, for the record): open for
_FILE_PROBE = r'''
import ctypes, errno, json, os, subprocess, sys
t, scratch = sys.argv[1], sys.argv[2]
def outcome(fn):
    try:
        fn()
        return "ok"
    except OSError as e:
        return errno.errorcode.get(e.errno, str(e.errno))
def open_w():
    with open(t, "w") as f: f.write("FORGED")
def open_a():
    with open(t, "a") as f: f.write("FORGED")
def open_trunc(): os.close(os.open(t, os.O_WRONLY | os.O_TRUNC))
def open_rdwr(): os.close(os.open(t, os.O_RDWR))
def truncate(): os.truncate(t, 0)
def chmod(): os.chmod(t, 0o666)
def utime(): os.utime(t, (0, 0))
def chown(): os.chown(t, 1, 1)
def mount_over():
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.mount(b"none", t.encode(), b"tmpfs", 0, None) != 0:
        raise OSError(ctypes.get_errno(), "mount")
def sed_i():
    r = subprocess.run(["sed", "-i", "s/./X/", t], capture_output=True)
    if r.returncode != 0:
        raise OSError(errno.EIO, "sed -i rc=%d" % r.returncode)
def rename_over():
    src = os.path.join(scratch, ".s08-over-%d" % os.getpid())
    with open(src, "w") as f: f.write("FORGED")
    os.rename(src, t)
def rename_away(): os.rename(t, os.path.join(scratch, ".s08-away-%d" % os.getpid()))
def unlink(): os.unlink(t)
shapes = [("open_w", open_w), ("open_a", open_a), ("open_trunc", open_trunc),
          ("open_rdwr", open_rdwr), ("truncate", truncate), ("chmod", chmod), ("utime", utime),
          ("chown", chown), ("mount_over", mount_over), ("sed_i", sed_i),
          ("rename_over", rename_over), ("rename_away", rename_away), ("unlink", unlink)]
print(json.dumps({name: outcome(fn) for name, fn in shapes}))
'''

#: The directory itself: a new file planted in it, the directory renamed away.
_DIR_PROBE = r'''
import errno, json, os, sys
d = sys.argv[1]
def outcome(fn):
    try:
        fn()
        return "ok"
    except OSError as e:
        return errno.errorcode.get(e.errno, str(e.errno))
def create_in():
    with open(os.path.join(d, "planted-by-the-box.json"), "w") as f: f.write("{}")
def rename_dir(): os.rename(d, d + ".moved")
print(json.dumps({"create_in": outcome(create_in), "rename_dir": outcome(rename_dir)}))
'''

#: The positive controls' in-box read: the sha256 the box sees for a file.
_SHA_PROBE = "import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())"


def _exec(box: Any, *argv: str) -> subprocess.CompletedProcess:
    """`docker exec -w /runs/current <box> …` through the docker the box was created with — the
    in-box view, independent of the permission layer (RJ-08). The box's working directory is
    its run folder's MODEL path (#1255 design rev 5, C8 extended), and every path argument a
    caller hands in is an in-box path (`_in_box`)."""
    return box.docker(["docker", "exec", "-w", V.MODEL_RUN, box.name, *argv])


def _probe(box: Any, script: str, *args: str) -> dict[str, str]:
    done = _exec(box, "python3", "-c", script, *args)
    assert done.returncode == 0, (
        f"the in-box probe did not run (rc={done.returncode}): {done.stderr!r} — a broken probe, "
        "not a refusal")
    return json.loads(done.stdout.strip().splitlines()[-1])


@dataclass
class _BoxSeen:
    """What the box test observed while the box was up, and the host's view around it."""

    run_dir: Path | None = None
    sandboxed: bool | None = None
    alert_sha_before: str | None = None
    alert_shapes: dict[str, str] | None = None
    record_sha_before: str | None = None
    record_shapes: dict[str, str] | None = None
    dir_shapes: dict[str, str] | None = None
    coined_error: BaseException | None = None
    control_written: str | None = None
    box_sha: dict[str, str] | None = None
    transport_cat: Any = None
    raised: BaseException | None = None


def _write_probes(box: Any, run_dir: Path, seen: _BoxSeen) -> None:
    """Every write shape against the alert, then the record, then the directory; then the
    positive controls. Never raises: everything is recorded for the test to assert on after the
    lifecycle has reaped the box."""
    seen.run_dir = Path(run_dir)
    seen.sandboxed = bool(getattr(box, "sandboxed", False))
    alert = S.alert_file(run_dir)
    seen.alert_sha_before = S.sha256_hex(alert.read_bytes())
    # Positive controls first, while both files are intact: a new file in the run folder lands
    # on the host; the box reads the alert's real bytes, raw and through the agent's transport.
    control = f"box-control-{uuid.uuid4().hex[:8]}.txt"
    done = _exec(box, "sh", "-c", f"echo CONTROL > {control}")
    seen.control_written = control if done.returncode == 0 else None
    seen.box_sha = {"alert": _exec(box, "python3", "-c", _SHA_PROBE,
                                   _in_box(alert, run_dir)).stdout.strip()}
    bash_exec = S.mod("runtime.bash_exec")
    command = f"cat {S.alert_rel()}"
    # #1255 C8 (extended): the box receives the working directory as a model path.
    seen.transport_cat = box.run_parsed(bash_exec.parse(command), command=command,
                                        cwd=Path(V.MODEL_RUN), timeout=60)
    try:
        record = S.record_file(run_dir)
        seen.record_sha_before = S.sha256_hex(record.read_bytes())
        seen.box_sha["record"] = _exec(box, "python3", "-c", _SHA_PROBE,
                                       _in_box(record, run_dir)).stdout.strip()
    except (AssertionError, OSError) as e:
        seen.coined_error = e
        record = None
    seen.alert_shapes = _probe(box, _FILE_PROBE, _in_box(alert, run_dir), V.MODEL_RUN)
    if record is not None:
        seen.record_shapes = _probe(box, _FILE_PROBE, _in_box(record, run_dir), V.MODEL_RUN)
        seen.dir_shapes = _probe(box, _DIR_PROBE, _in_box(S.input_dir(run_dir), run_dir))


def _box_write_run(tmp_path: Path, *, start_box: Callable[..., Any]) -> tuple[_BoxSeen, bytes]:
    """One production run whose box meets every write shape, the alert and record placed by
    production's `materialize_run` (inside `_live_tree`, so the binds resolve)."""
    planted = S.plant_tenant()
    alert = S.alert_bytes(S.generic_alert(message=MARK))
    seen = _BoxSeen()

    def investigate(*, run: Any, box: Any, **_kw: Any) -> dict:
        run_dir = run.run_dir
        _write_probes(box, Path(run_dir), seen)
        return {}

    try:
        _main_boxed(tmp_path, planted, alert, start_box=start_box, investigate=investigate)
    except Exception as e:  # noqa: BLE001 — kept: the probes' observations are asserted first
        seen.raised = e
    return seen, alert


def _assert_box_held(seen: _BoxSeen, alert: bytes) -> None:
    """The negative — no write shape changed either file or the directory — and its controls."""
    assert seen.run_dir is not None, f"the box never came up: {seen.raised!r}"
    assert seen.sandboxed, "start_box returned the unsandboxed host fallback, not a box"
    refused = {k: v for k, v in (seen.alert_shapes or {}).items() if v == "ok"}
    assert seen.alert_shapes, f"no write shape was tried on the alert: {seen.raised!r}"
    assert not refused, (
        f"from inside the box these write shapes were NOT refused on the alert: {sorted(refused)} "
        f"(all: {seen.alert_shapes})")
    host_now = S.alert_file(seen.run_dir).read_bytes()
    assert S.sha256_hex(host_now) == seen.alert_sha_before == S.sha256_hex(alert), (
        "the host's alert changed while the box ran")
    # Positive controls: the channel that would have shown a landed write is live.
    assert seen.control_written, "the box could not write its own run folder"
    assert (seen.run_dir / seen.control_written).read_text(
        encoding="utf-8").strip() == "CONTROL", "the box's own write in its run folder did not land"
    assert (seen.box_sha or {}).get("alert") == S.sha256_hex(alert), (
        "the box does not read the alert's real bytes")
    cat = seen.transport_cat
    assert cat is not None, "`cat` of the alert through the agent's transport never ran"
    assert (cat.rc, cat.out) == (0, alert), (
        f"`cat` of the alert through the agent's transport did not return its bytes: {cat!r}")
    if seen.coined_error is not None:
        raise seen.coined_error
    landed = {k: v for k, v in (seen.record_shapes or {}).items() if v == "ok"}
    assert seen.record_shapes, "no write shape was tried on the record"
    assert not landed, (
        f"write shapes NOT refused on the record: {sorted(landed)} (all: {seen.record_shapes})")
    assert (seen.box_sha or {}).get("record") == seen.record_sha_before, "the box misreads the record"
    assert S.sha256_hex(S.record_file(seen.run_dir).read_bytes()) == seen.record_sha_before, (
        "the host's record changed while the box ran")
    landed_dir = {k: v for k, v in (seen.dir_shapes or {}).items() if v == "ok"}
    assert seen.dir_shapes, "no shape was tried on the input directory"
    assert not landed_dir, (
        f"the box changed the input directory itself: {sorted(landed_dir)}")
    assert seen.raised is None, f"the run did not end cleanly: {seen.raised!r}"


def _runtime_spec(runtime: str) -> Any:
    return S.sym("runtime.box", "BoxSpec")(runtime=runtime)


# A3 — the lead reads the alert itself; O12 — no alert byte in a goal or harness prose

def test_a3_correlation_lead_reads_this_runs_alert_through_its_file_tool(tmp_path):
    rel = S.alert_rel()
    d = _run(tmp_path, leads={S.L3: [S.call("read_file", path=rel),
                                     S.call("bash", command=f"cat {rel}"),
                                     S.text(S.DEFAULT_CORRELATION_SUMMARY)]})
    assert d.raised is None, f"the run did not end cleanly: {d.raised!r} {d.refusal!r}"
    assert d.rc == 0, f"the run did not end cleanly: rc={d.rc} {d.refusal!r}"
    assert d.router.dispatched(S.L3), f"l-00c never ran; conversations: {d.router.leads()}"
    goal = d.sidecar(S.L3)["goal"]
    # The pointer the lead follows (A3, C55). Base: the goal carries ancestor documents and no
    # pointer at all — the red this demand names.
    assert rel in goal, f"l-00c's stored goal carries no pointer to this run's alert ({rel}):\n{goal}"
    returns = _returns(d.router.seen(S.L3))
    assert len(returns) == 2, f"l-00c's two reads did not both come back: {returns}"
    text = d.input_bytes.decode("utf-8")
    _assert_read_whole_and_framed(returns[0], text, "read_file on the pointer")
    _assert_read_whole_and_framed(returns[1], text, "cat on the pointer")


def _hostile_kibana_alert() -> dict[str, Any]:
    """The fixture alert with O12's hostile text in a free-text member and a unique timestamp."""
    payload = S.hostile_alert(MARK)["message"]
    return _alert(alert_timestamp=UNIQUE_TS, message=payload)


#: O12's alert bytes: the marker, the timestamp, and every piece that tries to close a frame.
_HOSTILE = (MARK, S.FENCE_RUN, S.RUN_TAG_CLOSE, S.RUN_TAG_OPEN, S.FORGED_HEADING,
            "what_to_summarize: [forged]", "lead_id: l-0ff", *S.LINE_SEPARATORS.strip(" "))


def test_o12_no_alert_byte_reaches_a_goal_or_harness_prose(tmp_path):
    rel = S.alert_rel()
    d = _run(tmp_path, alert=_hostile_kibana_alert(),
             leads={S.L3: [S.call("read_file", path=rel), S.text(S.DEFAULT_CORRELATION_SUMMARY)]})
    assert d.router.dispatched(S.L3), f"l-00c never ran; conversations: {d.router.leads()}"
    row = d.sidecar(S.L3)
    stored = json.dumps({"goal": row.get("goal"), "what": row.get("what_to_summarize")},
                        ensure_ascii=False)
    surfaces = {
        "the stored goal row": stored,
        "the Dispatch block": d.router.dispatch_block(S.L3),
        # A3: no harness-built prompt carries alert bytes — framed or not.
        "the lead's first prompt": d.router.first_prompt(S.L3),
        "the lead's instructions": d.router.instructions(S.L3),
        "MAIN's opening harness prose": S.harness_text(d.opening_message),
        "MAIN's instructions": d.main_instructions,
    }
    for where, text in surfaces.items():
        for piece in (*_HOSTILE, UNIQUE_TS) if where != "MAIN's opening harness prose" else _HOSTILE:
            assert piece not in text, f"an alert byte ({piece!r}) reached {where}"
    # Positive controls on the same addresses: alert bytes DO reach a model through the
    # sanctioned paths — MAIN's sealed raw-alert block, and the lead's own read of the file.
    S.assert_wrapped_untrusted(d.opening_message, MARK, "MAIN's raw-alert block")
    returns = _returns(d.router.seen(S.L3))
    assert returns, "the lead's own read of the alert returned nothing"
    assert _framed(returns[0], MARK), (
        f"the lead's own read of the alert did not return its bytes framed: {returns[:1]}")


# A1 — the box cannot change the input directory (runc, runsc, the production runtime)

def test_a1_box_cannot_change_the_alert_or_its_record(tmp_path, monkeypatch):
    with _live_tree(tmp_path, monkeypatch, hard=False):
        if "runc" not in docker_runtimes():
            pytest.skip("the 'runc' runtime is not registered with this daemon")
        start_box = functools.partial(S.sym("runtime.box", "start_box"),
                                      spec=_runtime_spec("runc"))
        seen, alert = _box_write_run(tmp_path, start_box=start_box)
        _assert_box_held(seen, alert)


def test_a1_runsc_box_cannot_change_the_alert_or_its_record(tmp_path, monkeypatch):
    with _live_tree(tmp_path, monkeypatch, hard=True):
        assert "runsc" in docker_runtimes(), (
            "the 'runsc' runtime is not registered with this daemon — this cell FAILS rather "
            "than skips (78, RG1); CI's `test` job registers runsc")
        start_box = functools.partial(S.sym("runtime.box", "start_box"),
                                      spec=_runtime_spec("runsc"))
        seen, alert = _box_write_run(tmp_path, start_box=start_box)
        _assert_box_held(seen, alert)


def test_p151_production_runtime_meets_every_write_shape(tmp_path, monkeypatch):
    """Under the production runtime, every write shape against the read-only directory and its
    two files leaves the host files unchanged."""
    with _live_tree(tmp_path, monkeypatch, hard=True):
        # The production runtime is the one `start_box` resolves when the operator sets nothing.
        monkeypatch.delenv("DEFENDER_BOX_RUNTIME", raising=False)
        production = S.sym("runtime.box", "BoxSpec").from_env({}).runtime
        assert production in docker_runtimes(), (
            f"the production runtime {production!r} is not registered with this daemon — this "
            "cell FAILS rather than skips (PA-08 never ran; RG1)")
        seen, alert = _box_write_run(tmp_path, start_box=S.sym("runtime.box", "start_box"))
        _assert_box_held(seen, alert)


# The gather lead's instructions, MAIN's coordinates, the host readers


# RG1's second line: every host-side read re-checks the recorded digest


def _finished_run(tmp_path: Path) -> S.Drive:
    d = _run(tmp_path)
    assert d.raised is None, f"the run did not end cleanly: {d.raised!r}"
    assert d.rc == 0, f"the run did not end cleanly: rc={d.rc}"
    return d


def test_a1_a_replaced_alert_is_refused_at_the_next_host_read_whatever_the_runtime(tmp_path):
    rel = S.alert_rel()

    def drive(where: Path, **kw: Any) -> S.Drive:
        # `enqueue=` records every hand-off to the learning loop (`d.enqueued`) and refuses it.
        return _run(where, main=[S.call("read_file", path=rel), S.text(S.DONE)],
                    leads={S.L3: [S.call("read_file", path=rel), S.text("ok")]},
                    tickets=S.ticket_writer(S.TicketStore()), update_ticket=True, no_learn=False,
                    enqueue=lambda *_a, **_k: False, **kw)

    ok = drive(tmp_path / "ok")
    S.assert_wrapped_untrusted(ok.opening_message, MARK, "the untouched alert")
    assert ok.tickets.store.opened(), "the untouched run opened no ticket"
    assert ok.enqueued, "the untouched run was not enqueued for learning"

    d = drive(tmp_path / "bad", before=_replace_alert)
    reached_model = _all_text(d.main.seen) + _all_text(
        d.router.seen(S.L3) if d.router.dispatched(S.L3) else [])
    assert DECOY not in reached_model, "the replaced alert's bytes reached a model"
    tickets = json.dumps(d.tickets.store.calls, ensure_ascii=False, default=str)
    assert DECOY not in tickets, "the replaced alert's bytes reached the case ticket"
    assert not d.enqueued, "a run over a replaced alert was handed to the learning loop"
    _assert_names_the_run_and_carries_no_byte(
        _refusal_text(d.raised, d.refusal), d.folder, "the run's next host read")
    # Orientation on a restart of the same folder refuses again.
    again = S.new_drive(tmp_path / "restart", tenant=d.tenant, main=[S.text(S.DONE)],
                        backend=S.Backend(answer=_resolving))
    assert d.tenant is not None
    with pytest.raises(Exception) as restart:  # noqa: PT011 — the refusal's class is the implementer's; its text is asserted
        S.drive_run(again, d.folder, tenant=d.tenant.accept())
    assert DECOY not in _all_text(again.main.seen), "a restart handed MAIN the replaced alert"
    _assert_names_the_run_and_carries_no_byte(
        _refusal_text(restart.value, None), d.folder, "orientation on a restart")


# The record, the read shape, the pointer, the size


def test_p149_agents_read_permission_and_the_one_directory_dow(tmp_path):
    rel, rec = S.alert_rel(), S.record_rel()
    planted = _tenant()
    run_id = "s08-p149"
    reads = [S.call("read_file", path=rel), S.call("bash", command=f"cat {rel}"),
             S.call("read_file", path=f"{V.MODEL_RUN}/{rel}"),
             S.call("read_file", path=rec), S.call("bash", command=f"cat {rec}"),
             S.call("read_file", path=OTHER_DIR_FILE)]

    def plant_other(run_dir_: Path) -> None:
        other = Path(run_dir_) / OTHER_DIR_FILE
        other.parent.mkdir(parents=True, exist_ok=True)
        other.write_text(json.dumps({"note": SECRET}), encoding="utf-8")

    d = _run(tmp_path, tenant=planted, run_id=run_id, main=[*reads, S.text(S.DONE)],
             leads={S.L3: [*reads, S.text("ok")]}, before=plant_other)
    digest = S.sha256_hex(d.input_bytes)
    for who, seen in (("MAIN", d.main.seen), ("l-00c", d.router.seen(S.L3))):
        returns = _returns(seen)
        assert len(returns) == len(reads), f"{who}'s reads did not all come back: {returns}"
        for spelling, ret in zip(("read_file", "cat", "read_file (absolute)"), returns[:3],
                                 strict=True):
            assert _framed(ret, MARK), f"{who} could not read the alert by {spelling}: {ret[:300]}"
        for spelling, ret in zip(("read_file", "cat"), returns[3:5], strict=True):
            assert digest in ret, f"{who} could not read the record by {spelling}: {ret[:300]}"
        refused = returns[5]
        assert SECRET not in refused, f"{who} read a file one directory down outside the input dir"
        assert Path(OTHER_DIR_FILE).name in refused, (
            f"{who}'s refused read does not name the file it refused: {refused[:300]}")


def test_p192_alert_larger_than_one_read_returns(tmp_path):
    """No new size limit: the lead sees the whole alert, or a read that names its truncation;
    MAIN still gets the whole alert inline."""
    rel = S.alert_rel()
    d = _run(tmp_path, alert=_alert(bulk="x" * 70_000 + " " + TAIL),
             leads={S.L3: [S.call("read_file", path=rel), S.call("bash", command=f"cat {rel}"),
                           S.text(S.DEFAULT_CORRELATION_SUMMARY)]})
    assert d.raised is None, f"run start refused a large alert: {d.raised!r} {d.refusal!r}"
    assert d.rc == 0, f"run start refused a large alert: rc={d.rc} {d.refusal!r}"
    text = d.input_bytes.decode("utf-8")
    assert len(text) > 65_536, "the alert is not past one read (PA-27) — nothing to observe"
    assert _framed(d.opening_message, text.strip()), "MAIN no longer gets the whole alert inline"
    assert rel in d.sidecar(S.L3)["goal"], "the lead was not pointed at the alert"
    returns = _returns(d.router.seen(S.L3))
    assert len(returns) == 2, f"the lead's two reads did not both come back: {returns}"
    for tool, ret in zip(("read_file", "cat"), returns, strict=True):
        bodies = S.framed_bodies(ret)
        assert any(text[:4096] in b for b in bodies), f"the lead's {tool} returned no alert head"
        whole = any(text.strip() in b for b in bodies)
        named = any(TOO_LARGE in b and TAIL not in b for b in bodies)
        assert whole or named, (
            f"the lead's {tool} cut the alert without naming the truncation: {ret[-400:]!r}")


# Box start, siblings, the reap and the archive, the unsandboxed opt-out

def _noop_investigate(**_kw: Any) -> dict:
    return {}


def _start_with(daemon: Any) -> Callable[..., Any]:
    return functools.partial(S.sym("runtime.box", "start_box"), docker=daemon)


def _populated(run_dir: Path) -> None:
    """The input directory as setup left it: the positive control."""


def _missing(run_dir: Path) -> None:
    from defender.tests._alert_plant import unseal_fixture_input
    unseal_fixture_input(run_dir)
    shutil.rmtree(S.input_dir(run_dir))


def _empty(run_dir: Path) -> None:
    from defender.tests._alert_plant import unseal_fixture_input
    unseal_fixture_input(run_dir)
    for child in S.input_dir(run_dir).iterdir():
        child.unlink()


def _not_a_directory(run_dir: Path) -> None:
    from defender.tests._alert_plant import unseal_fixture_input
    unseal_fixture_input(run_dir)
    where = S.input_dir(run_dir)
    shutil.rmtree(where)
    where.write_text("not a directory\n", encoding="utf-8")


def _link(run_dir: Path) -> None:
    """A link at the directory's name, pointing at a directory OUTSIDE the run (PA-10: today the
    box starts and reads the target through it)."""
    from defender.tests._alert_plant import unseal_fixture_input
    unseal_fixture_input(run_dir)
    where = S.input_dir(run_dir)
    elsewhere = Path(run_dir).parent.parent / "s08-elsewhere"
    elsewhere.mkdir(parents=True, exist_ok=True)
    (elsewhere / S.alert_file(run_dir).name).write_text("{}", encoding="utf-8")
    (elsewhere / "secret.txt").write_text(SECRET, encoding="utf-8")
    shutil.rmtree(where)
    where.symlink_to(elsewhere, target_is_directory=True)


_BAD_SOURCES: dict[str, Callable[[Path], None]] = {
    "missing": _missing, "empty": _empty, "not_a_directory": _not_a_directory, "link": _link,
}


def _start_over(tmp_path: Path, shape: Callable[[Path], None]) -> tuple[Any, Any, Path | None]:
    """One run whose input directory is put into `shape` just before its box starts; returns the
    scripted daemon, what `run.main` raised, and the run folder."""
    daemon = _scripted_daemon()
    seen: dict[str, Path] = {}

    def around(prod: Callable[..., dict], kw: dict) -> dict:
        seen["run_dir"] = Path(kw["run"].run_dir)
        shape(Path(kw["run"].run_dir))
        return prod(**kw)

    try:
        _main_boxed(tmp_path, S.plant_tenant(), S.alert_bytes(S.generic_alert()),
                    start_box=_start_with(daemon), investigate=_noop_investigate, around=around)
    except Exception as e:  # noqa: BLE001 — the refusal is the observation
        return daemon, e, seen.get("run_dir")
    return daemon, None, seen.get("run_dir")


def test_p153_box_created_while_the_directory_is_missing_or_no(tmp_path, monkeypatch):
    """Box start refuses a missing, empty or non-directory mount source, or a link at its name,
    naming why. There is no fallback to a writable bind."""
    monkeypatch.delenv(ALLOW_UNSANDBOXED, raising=False)
    daemon, raised, run_dir = _start_over(tmp_path / "populated", _populated)
    assert raised is None, f"a populated input dir refused: {raised!r}"
    assert run_dir is not None, "the populated control never reached start_box"
    binds = _readonly_binds_inside(daemon.mounts())
    assert binds, "the box mounts nothing read-only inside the run folder"
    _assert_mounts_its_own_input_dir(binds, run_dir, "populated")
    box_fault = S.sym("runtime.box", "BoxFault")
    for name, shape in _BAD_SOURCES.items():
        daemon, raised, run_dir = _start_over(tmp_path / name, shape)
        assert isinstance(raised, box_fault), f"{name}: box start did not refuse ({raised!r})"
        assert run_dir is not None, f"{name}: the run never reached start_box"
        assert S.input_dir(run_dir).name in str(raised), (
            f"{name}: the refusal does not name the input directory: {raised}")
        created = daemon.create_argv is not None
        # Writable at the input directory's place in the box (its model path, #1255 P1) or
        # writable over its host folder under any target.
        inside, host = _in_box(S.input_dir(run_dir), run_dir), str(S.input_dir(run_dir))
        writable = [m for m in (daemon.mounts() if created else [])
                    if not m["readonly"] and (m["target"].startswith(inside)
                                              or m["source"].startswith(host))]
        assert not writable, f"{name}: box start fell back to a writable bind: {writable}"
        leaked = [m for m in (daemon.mounts() if created else []) if "s08-elsewhere" in m["source"]]
        assert not leaked, f"{name}: the box was handed the link's target: {leaked}"


def _capture_inputs(store: dict[str, Any]) -> Callable[..., dict]:
    """`investigate`: what the input directory holds once the box is up."""
    def investigate(*, run: Any, **_kw: Any) -> dict:
        run_dir = run.run_dir
        store["run_dir"] = Path(run_dir)
        store["alert"] = S.alert_file(run_dir).read_bytes()
        with contextlib.suppress(AssertionError, OSError):
            store["record"] = S.record_file(run_dir).read_bytes()
        return {}
    return investigate


def test_p154_sibling_and_world_boxes_and_their_directory(tmp_path):
    """A sibling's box and a world resume's box mount the episode's copy read-only, as a fresh
    run's box does."""
    planted = S.plant_tenant()
    fresh_daemon, fresh = _scripted_daemon(), dict[str, Any]()
    _main_boxed(tmp_path, planted, S.alert_bytes(S.generic_alert(message=MARK)),
                start_box=_start_with(fresh_daemon), investigate=_capture_inputs(fresh))
    assert "run_dir" in fresh, f"the fresh run never reached its investigation: {fresh}"
    src = fresh["run_dir"]
    fresh_binds = _readonly_binds_inside(fresh_daemon.mounts())
    assert fresh_binds, "a fresh run's box mounts nothing read-only inside its run folder"
    _assert_mounts_its_own_input_dir(fresh_binds, src, "the fresh run")
    # The launcher's copy in the episode (A1; launch itself is S11's), then a sibling resumed.
    ep = T.episode(tmp_path, root=Path(os.environ[T.EPISODES_BASE_ENV]),
                   doc=T.family_doc(source_run_dir=str(src), source_run_id=src.name))
    from defender._episode_handle import Episode
    with Episode.open(ep) as episode:
        T.episode_view(episode, tenant=planted.accept()).close()
    copy = S.plant_episode_copy(ep, alert=fresh["alert"], record=S.read_record(src))
    _replace_alert_and_record(src)
    sib_daemon, sib = _scripted_daemon(), dict[str, Any]()
    lifecycle = functools.partial(_lifecycle(), start_box=_start_with(sib_daemon),
                                  investigate=_capture_inputs(sib))
    rc = S.sym("run", "main")(
        ["--episode", ep.name, "--world", "b", "--tenant", planted.tenant_id],
        lifecycle=lifecycle, preflight=lambda *_a, **_k: 0, visualize=lambda *_a, **_k: None,
        ticket_writer=S.NoTicket())
    assert rc == 0, f"the sibling run failed (rc={rc})"
    assert "run_dir" in sib, "the sibling never started its box"
    sib_binds = _readonly_binds_inside(sib_daemon.mounts())
    _assert_mounts_its_own_input_dir(sib_binds, sib["run_dir"], "the sibling")
    assert sib["alert"] == copy, (
        "the sibling's box holds an alert other than the episode's copy"
        + (" — the source run's current bytes" if sib["alert"] == DECOY_BYTES else ""))
    assert sib.get("record") == S.episode_record_file(ep).read_bytes(), (
        "the sibling's box holds a record other than the episode's copy")


def test_p155_reap_scan_and_archive_walk_a_former_mountpoint(tmp_path):
    """The reap scan and the episode archive each copy or verify both files; neither fails or
    skips."""
    d = _finished_run(tmp_path)
    alert, record = d.stored_alert, S.record_file(d.folder).read_bytes()
    scrub = S.mod("runtime.scrub")
    scrub.scrub(d.run_dir)
    assert scrub.tree_verified(d.run_dir), "the reap scan did not verify the run folder"
    episode_cls = S.sym("_episode_handle", "Episode")
    ep = tmp_path / "s08-archive-ep"
    ep.mkdir()
    with episode_cls.open(ep) as episode:
        archived = S.sym("learning.branch.archive", "archive_episode")(episode, {"b": d.run_dir})
    world = Path(archived["b"])
    held = [p.read_bytes() for p in world.rglob("*") if p.is_file()]
    assert alert in held, "the archive skipped the run's alert"
    assert record in held, "the archive skipped the run's record"


def _verdict_text(run_dir: Path) -> str:
    path = S.sym("runtime.scrub", "verdict_path")(run_dir)
    assert path.is_file(), f"no reap verdict beside {run_dir}"
    return path.read_text(encoding="utf-8")


def _gated_run(tmp_path: Path, daemon: Any, caplog: pytest.LogCaptureFixture) -> dict[str, Any]:
    """One production run through the curation enqueue (the learning gate's consumer)."""
    out: dict[str, Any] = {"enqueued": []}

    def investigate(*, run: Any, box: Any, **_kw: Any) -> dict:
        run_dir = run.run_dir
        out["run_dir"], out["sandboxed"] = Path(run_dir), bool(box.sandboxed)
        return {}

    def enqueue(*a: Any, **k: Any) -> bool:
        result = S.sym("run_common", "enqueue_curation")(*a, **k)
        out["enqueued"].append(result)
        return result

    caplog.clear()
    with caplog.at_level(logging.INFO):
        _main_boxed(tmp_path, S.plant_tenant(), S.alert_bytes(S.generic_alert()),
                    start_box=_start_with(daemon), investigate=investigate, enqueue=enqueue)
    out["log"] = [r.getMessage() for r in caplog.records]
    return out


def test_p150_unsandboxed_opt_out_runs_without_the_mount(tmp_path, monkeypatch, caplog):
    """An unsandboxed run is marked unsandboxed in its reap verdict and the learning gate refuses
    it, naming why."""
    monkeypatch.setenv(ALLOW_UNSANDBOXED, "1")
    boxed = _gated_run(tmp_path / "boxed", _scripted_daemon(), caplog)
    assert boxed.get("sandboxed") is True, f"the sandboxed control did not run in a box: {boxed}"
    assert boxed["enqueued"] == [True], f"the sandboxed control was not learned from: {boxed}"

    def absent_docker(argv: list[str], **_kw: Any) -> Any:
        # A real startup fault through the real primitive: the docker binary is not there.
        return S.sym("runtime.box._docker", "_docker")(
            [str(tmp_path / "no-docker-here" / "docker"), *argv[1:]])

    bare = _gated_run(tmp_path / "bare", absent_docker, caplog)
    assert bare.get("sandboxed") is False, f"the opt-out did not run on the host executor: {bare}"
    verdict = _verdict_text(bare["run_dir"])
    assert re.search(r"unsandboxed|\"sandboxed\"\s*:\s*false", verdict, re.I), (
        f"the reap verdict does not mark the run unsandboxed: {verdict}")
    assert bare["enqueued"] == [False], "the learning gate accepted an unsandboxed run"
    reasons = [m for m in bare["log"] if "NOT enqueuing" in m]
    assert reasons, "the learning gate logged no refusal"
    assert re.search(r"sandbox", " ".join(reasons), re.I), (
        f"the learning gate's refusal does not name why: {reasons}")


def _state(paths: Mapping[str, Path]) -> dict[str, tuple[int, int, bytes]]:
    """Each file's identity and content: inode, mtime and bytes — a rewrite moves at least one."""
    return {k: (p.stat().st_ino, p.stat().st_mtime_ns, p.read_bytes()) for k, p in paths.items()}


def _held_files(run_dir: Path) -> dict[str, Path]:
    """The run's alert and, where the run has one, its record (none exists at base)."""
    held = {"alert": S.alert_file(run_dir)}
    with contextlib.suppress(AssertionError):
        held["record"] = S.record_file(run_dir)
    return {k: p for k, p in held.items() if p.is_file()}


def _branchable_source(tmp_path: Path, planted: S.Planted) -> S.Drive:
    golden = (H.GOLDEN / "investigation.md").read_text(encoding="utf-8")
    src = _run(tmp_path / "source", tenant=planted,
               main=[S.call("append_block", text=golden),
                     S.gather("l-009", "elastic", "capture one fact"),
                     S.call("bash", command="echo held"), S.text(S.DONE)],
               leads={"l-009": [S.query("elastic", "query", {"native_query": "s08:capture"}),
                                S.text("L9 captured.")]})
    assert src.raised is None, f"the source run did not end cleanly: {src.raised!r}"
    assert src.rc == 0, f"the source run did not end cleanly: rc={src.rc} {src.refusal!r}"
    return src


def _seeded_sibling(tmp_path: Path) -> tuple[dict, dict]:
    """A sibling resumed through the REAL driver (`open_main_session` and its resume seeder),
    over a run folder whose alert and record were placed at its setup — the episode's copy,
    byte for byte the source's. Returns the two files' state at setup and after the run."""
    planted = _tenant()
    src = _branchable_source(tmp_path, planted)
    assert src.run_dir is not None
    store = S.sym("runtime.branch._spec", "open_source_store")(src.run_dir, source_run=_run_handle_1165(src.run_dir))
    # #1255 (D1, C7): a branch point is a MAIN response that called tools, and the arm resumes
    # with no continuation prompt — the source's third one (its `echo`), after the capture.
    point = tool_calling_responses(store)[2]
    assert calls_of(message_at(store, point))[0].tool_name == "bash", (
        "the branch point is not the source's `echo` call")
    spec = spec_at(store, src.run_dir, point)
    sibling_dir = planted.runs / f"{src.run_dir.name}-sibling"
    sibling_dir.mkdir(parents=True)
    for name, source in _held_files(src.run_dir).items():
        target = S.alert_file(sibling_dir) if name == "alert" else S.record_file(sibling_dir)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    placed = _held_files(sibling_dir)
    at_setup = _state(placed)
    sib = S.new_drive(tmp_path / "sibling", tenant=planted, main=[S.text("Resumed and stopping.")])
    S.drive_run(sib, sibling_dir, tenant=planted.accept(), resume=spec)
    assert sib.main.seen, "the sibling never reached its model (the resume did not run)"
    return at_setup, _state(placed)


def test_p152_host_replaces_a_file_inside_the_directory_mid_ru(tmp_path, monkeypatch):
    # A sibling: placed at setup, then resumed through the real seeder while its box would be
    # up. Base's seeder copies the source's alert over the sibling's (PA-09).
    at_setup, after = _seeded_sibling(tmp_path / "sibling")
    for name in at_setup:
        assert after[name] == at_setup[name], (
            f"the resume seeder rewrote the sibling's {name} after its setup")
    # A fresh run: no host step writes either file after setup, its ticket legs included.
    stats: dict[str, Any] = {}

    def snapshot(run_dir: Path) -> dict[str, tuple]:
        return _state({"alert": S.alert_file(run_dir), "record": S.record_file(run_dir)})

    d = _run(tmp_path / "steps", before=lambda run_dir: stats.update(setup=snapshot(run_dir)),
             tickets=S.ticket_writer(S.TicketStore()), update_ticket=True)
    assert d.raised is None, f"the run did not end cleanly: {d.raised!r}"
    assert d.rc == 0, f"the run did not end cleanly: rc={d.rc}"
    assert snapshot(d.folder) == stats["setup"], "a host step rewrote the alert or the record"
    # The box: a host replacement inside the directory is visible to it and still read-only.
    replaced = S.alert_bytes(S.generic_alert(message="FRONTDOOR-S08-HOST-REPLACED"))
    with _live_tree(tmp_path, monkeypatch, hard=False):
        if "runc" not in docker_runtimes():
            pytest.skip("the 'runc' runtime is not registered with this daemon")
        seen: dict[str, Any] = {}

        def investigate(*, run: Any, box: Any, **_kw: Any) -> dict:
            run_dir = run.run_dir
            alert = S.alert_file(run_dir)
            _replace_alert(Path(run_dir), replaced)
            in_box = _in_box(alert, Path(run_dir))
            seen["box_sees"] = _exec(box, "cat", in_box).stdout
            seen["write"] = _probe(box, _FILE_PROBE, in_box, V.MODEL_RUN)
            seen["host_after"] = alert.read_bytes() if alert.is_file() else None
            return {}

        _main_boxed(tmp_path, S.plant_tenant(), S.alert_bytes(S.generic_alert(message=MARK)),
                    start_box=functools.partial(S.sym("runtime.box", "start_box"),
                                                spec=_runtime_spec("runc")),
                    investigate=investigate)
    assert seen.get("box_sees") == replaced.decode("utf-8"), (
        "the box does not see the host's replacement of the alert")
    landed = {k: v for k, v in seen["write"].items() if v == "ok"}
    assert not landed, f"after the host's replacement the box could write the alert: {landed}"
    assert seen["host_after"] == replaced, "the host's replacement did not stand"
