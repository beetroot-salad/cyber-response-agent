"""#1105 D1/D6/N-g/J16 — run end moves into the service in today's ORDER, a sibling's resume is
the service's injected opener, and nothing gains a timeout.

Run end is driven through `run.main`'s own tail with its own seams (`lifecycle=`,
`materialize=`, `preflight=`, and `enqueue=` / `visualize=` only where a test records them); the
cross-check, the curation gate and the visualize launch are the REAL ones wherever the fault is
theirs:
  * a cross-check MISMATCH is a real investigation document whose `:L` rows disagree with the
    run's own tables; a cross-check that RAISES is a real undecodable `investigation.md`
    (`read_text_utf8` raises `UnicodeDecodeError`) — the reground probe (J-PR8) stubbed
    `lead_repository` to get both, which this spec does not do;
  * a visualize child that exits non-zero is the real visualizer over a run dir with no session
    pointer; a visualize SCRIPT that is missing is a real deleted file in a real copy of the
    tree; an interpreter that CANNOT BE SPAWNED is a real deleted interpreter path
    (`_spec1105.deletable_interpreter`) — dep-PO2's two paths;
  * an unreadable held-out folder is a real mode-000 directory read by a reader that obeys mode
    bits, re-pointed through `run.main`'s own `enqueue=` seam exactly as J-PR4 did.

The order G11 / RG-4 / J-PR8 executed — cross-check, THEN enqueue, THEN visualize — is pinned;
the design's Key-flows sentence ("enqueues curation, launches visualize, and runs the
cross-check") is REFUTED (handoff.refuted #2) and is not asserted anywhere.

RED against ed5386bc where the change is new: the resume opener is a `BranchSpec`, not the
service's injected `ResumeOpener`; the driver imports `runtime.branch`; an unreadable held-out
folder crashes run end (J-PR4, J16's fix); `defender.run_service` does not exist.
"""
from __future__ import annotations

import errno
import functools
import inspect
import json
import os
from pathlib import Path

from defender.tests import _spec1105 as S
from defender.tests import _triplet_947 as T

MARK_ENQUEUE = "[1105] ENQUEUE-SEAM-REACHED"
MARK_VISUALIZE = "[1105] VISUALIZE-SEAM-REACHED"
WARN_MISMATCH = "WARN narration cross-check FAILED"
SKIPPED = "narration cross-check skipped:"


def _run_dir_with(base: Path, *, investigation: bytes | None, verdict: bool = True):
    """`run.main`'s `materialize=` seam: a run dir holding one lead that reached the tables
    (a lead sidecar plus one captured call), an `investigation.md` of the given bytes, and a
    completed scrub verdict beside it (the curation gate's certification)."""
    def make(alert: Path, run_id, *, model=None, world=None) -> Path:
        d = base / "20260921t143000z-run-end"
        (d / "gather_raw").mkdir(parents=True, exist_ok=True)
        T.capture_call(d)
        (d / "gather_raw" / "l-001.lead.json").write_text(
            json.dumps({"goal": "g", "what_to_summarize": []}), encoding="utf-8")
        if investigation is not None:
            (d / "investigation.md").write_bytes(investigation)
        if verdict:
            (base / f"{d.name}.scrub-verdict.json").write_text(json.dumps({"ran": True}),
                                                              encoding="utf-8")
        return d
    return make


def _marking(mark: str, result=None):
    import sys

    def seam(*args, **kw):
        print(mark, file=sys.stderr)
        return result
    return seam


def _alert(tmp_path: Path) -> Path:
    tmp_path.mkdir(parents=True, exist_ok=True)
    alert = tmp_path / "alert.json"
    alert.write_text(json.dumps({"alert_id": "A1105"}), encoding="utf-8")
    return alert


def _order(err: str, *needles: str) -> list[int]:
    return [err.index(n) if n in err else -1 for n in needles]


#: `:L` rows that name no lead — the tables hold `l-001`, so the narration misses it.
NARRATION_WITHOUT_THE_LEAD = b"# investigation\n\nNo lead is declared here.\n"
#: Bytes `read_text_utf8` cannot decode — the cross-check's source raises.
UNDECODABLE = b"# investigation\n\xff\xfe\xfa not utf-8\n"


def _tail(tmp_path: Path, monkeypatch, capsys, *, investigation: bytes, **seams):
    runs = S.configure_roots(tmp_path, monkeypatch)
    seams.setdefault("enqueue", _marking(MARK_ENQUEUE, True))
    seams.setdefault("visualize", _marking(MARK_VISUALIZE))
    rc = S.run_py().main([str(_alert(tmp_path))], lifecycle=S.quiet_lifecycle,
                         preflight=S.no_preflight,
                         materialize=_run_dir_with(runs, investigation=investigation), **seams)
    return rc, capsys.readouterr().err


def test_1105_run_end_cross_checks_then_enqueues_curation_then_launches_visualize(
        tmp_path, monkeypatch, capsys):
    """At run end the service does three things in today's order (G11, J-PR8): it runs the
    cross-check (`cross_check_tables`), then enqueues curation, then launches visualize. A
    cross-check mismatch prints `WARN narration cross-check FAILED …` and a raising cross-check
    prints `narration cross-check skipped: …`; in both cases enqueue and visualize still run and
    run.main returns 0. A failing visualize launch (`VisualizeFailed`, the real visualizer over a
    run dir it cannot render) is printed and run end still returns 0.
    """
    rc, err = _tail(tmp_path / "mismatch", monkeypatch, capsys,
                    investigation=NARRATION_WITHOUT_THE_LEAD)
    assert rc == 0
    warn, enq, viz = _order(err, WARN_MISMATCH, MARK_ENQUEUE, MARK_VISUALIZE)
    assert -1 < warn < enq < viz, (warn, enq, viz, err)

    rc, err = _tail(tmp_path / "raising", monkeypatch, capsys, investigation=UNDECODABLE)
    assert rc == 0
    skipped, enq, viz = _order(err, SKIPPED, MARK_ENQUEUE, MARK_VISUALIZE)
    assert -1 < skipped < enq < viz, (skipped, enq, viz, err)

    real_visualize = inspect.signature(S.run_py().main).parameters["visualize"].default
    rc, err = _tail(tmp_path / "visualize-fails", monkeypatch, capsys,
                    investigation=NARRATION_WITHOUT_THE_LEAD, visualize=real_visualize)
    assert rc == 0
    assert "visualize_run failed" in err, err
    assert err.index(MARK_ENQUEUE) < err.index("visualize_run failed"), err


def test_1105_run_end_cross_check_fails_before_curation_is_enqueued(tmp_path, monkeypatch,
                                                                    capsys):
    """at run end, a cross-check mismatch prints `WARN narration cross-check FAILED` and a
    raising cross-check source prints `narration cross-check skipped:`; in both cases curation is
    enqueued and then visualize is launched, in that order, and `run.main` returns 0 — the
    cross-check's failure propagates nowhere.
    """
    for tag, doc, line in (("mismatch", NARRATION_WITHOUT_THE_LEAD, WARN_MISMATCH),
                           ("raising", UNDECODABLE, SKIPPED)):
        enqueued = S.Recorder(result=True)
        visualized = S.Recorder()

        def enqueue(*a, _rec=enqueued, **kw):
            _rec(*a, **kw)
            print(MARK_ENQUEUE, file=__import__("sys").stderr)
            return True

        def visualize(*a, _rec=visualized, **kw):
            _rec(*a, **kw)
            print(MARK_VISUALIZE, file=__import__("sys").stderr)

        rc, err = _tail(tmp_path / tag, monkeypatch, capsys, investigation=doc,
                        enqueue=enqueue, visualize=visualize)
        assert rc == 0, tag
        assert len(enqueued.calls) == 1, tag
        assert len(visualized.calls) == 1, tag
        first, enq, viz = _order(err, line, MARK_ENQUEUE, MARK_VISUALIZE)
        assert -1 < first < enq < viz, (tag, first, enq, viz, err)


def test_1105_run_end_curation_enqueue_fails(tmp_path, monkeypatch, capsys):
    """A failed curation enqueue (the refusal gate, or an unwritable marker) prints and returns
    False — `run.main` never says "enqueued for catalog curation" — while the visualize launch
    still runs and run end continues to 0, as today. The enqueue is run.py's own default: the
    service's curation lane.
    """
    for tag in ("gate", "unwritable"):
        runs = S.configure_roots(tmp_path / tag, monkeypatch)
        if tag == "unwritable":
            not_a_dir = tmp_path / tag / "learning-state-is-a-file"
            not_a_dir.parent.mkdir(parents=True, exist_ok=True)
            not_a_dir.write_text("x", encoding="utf-8")
            monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(not_a_dir))
        truncated = "budget" if tag == "gate" else None
        visualized = S.Recorder()
        rc = S.run_py().main(
            [str(_alert(tmp_path / tag))],
            lifecycle=lambda _t=truncated, **kw: {"output": "", "requests": 0,
                                                  "truncated_by": _t},
            preflight=S.no_preflight, visualize=visualized,
            materialize=_run_dir_with(runs, investigation=None))
        err = capsys.readouterr().err
        assert rc == 0, tag
        assert "NOT enqueuing for curation" in err, (tag, err)
        assert "enqueued for catalog curation" not in err, (tag, err)
        assert len(visualized.calls) == 1, tag


def _default_enqueue():
    return inspect.signature(S.run_py().main).parameters["enqueue"].default


def test_1105_run_end_for_a_held_out_fixture_run_after_the_move(tmp_path, monkeypatch, capsys):
    """Run end over a held-out fixture behaves as today: an alert that IS a held-out fixture (by
    containment) or a COPY of one (by digest) is refused by the curation lane — printed, not
    enqueued — and visualize still runs. `HELD_OUT_FIXTURES` from `host_env` resolves to the
    same path `run_common`'s did (`defender/fixtures/held-out`), and it is the lane's own
    default fixtures folder.
    """
    held_out = S.host_env().HELD_OUT_FIXTURES
    assert held_out == S.DEFENDER / "fixtures" / "held-out"
    default = _default_enqueue()
    assert inspect.signature(default).parameters["fixtures_dir"].default == held_out

    fixtures = tmp_path / "held-out"
    (fixtures / "case-x").mkdir(parents=True)
    (fixtures / "case-x" / "alert.json").write_text('{"alert_id": "HELD"}', encoding="utf-8")
    copy = tmp_path / "copied-alert.json"
    copy.write_bytes((fixtures / "case-x" / "alert.json").read_bytes())
    for tag, alert in (("containment", fixtures / "case-x" / "alert.json"), ("digest", copy)):
        runs = S.configure_roots(tmp_path / tag, monkeypatch)
        visualized = S.Recorder()
        rc = S.run_py().main([str(alert)], lifecycle=S.quiet_lifecycle,
                             preflight=S.no_preflight, visualize=visualized,
                             enqueue=functools.partial(default, fixtures_dir=fixtures),
                             materialize=_run_dir_with(runs, investigation=None))
        err = capsys.readouterr().err
        assert rc == 0, tag
        assert len(visualized.calls) == 1, tag
        assert 'held-out eval fixture' in err, (tag, err)
        assert 'enqueued for catalog curation' not in err, (tag, err)


_HELD_OUT_CHILD = """
    import functools, inspect, json, os, sys
    from pathlib import Path
    from defender import run as run_mod
    out = {}
    tmp = Path(TMP)
    runs = Path(os.environ["DEFENDER_RUNS_BASE"])
    def make(alert, run_id, **kw):
        d = runs / "20260921t143000z-held-out"
        d.mkdir(parents=True, exist_ok=True)
        (runs / (d.name + ".scrub-verdict.json")).write_text('{"ran": true}')
        return d
    visualized = []
    default = inspect.signature(run_mod.main).parameters["enqueue"].default
    # the child returns its own stderr, read at the DESCRIPTOR: a module holding the stream
    # from import time writes to fd 2 whatever `sys.stderr` is rebound to
    err_file = tmp / "child-stderr.txt"
    err_fd = os.open(err_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    saved_fd = os.dup(2)
    sys.stderr.flush()
    os.dup2(err_fd, 2)
    try:
        out["rc"] = run_mod.main(
            [str(tmp / "alert.json")], lifecycle=lambda **k: {"output": "", "requests": 0,
                                                               "truncated_by": None},
            preflight=lambda m: 0, visualize=lambda d: visualized.append(str(d)),
            materialize=make, enqueue=functools.partial(default, fixtures_dir=Path(FIXTURES)))
    except BaseException as e:
        out["raised"] = type(e).__name__
    finally:
        sys.stderr.flush()
        os.dup2(saved_fd, 2)
        os.close(saved_fd)
        os.close(err_fd)
    out["stderr"] = err_file.read_text(encoding="utf-8", errors="replace")
    state = Path(os.environ["DEFENDER_LEARNING_STATE_DIR"])
    out["markers"] = sorted(str(p.relative_to(state)) for p in state.rglob("*.json")) \\
        if state.exists() else []
    out["visualized"] = len(visualized)
    print(json.dumps(out))
"""


def test_1105_run_end_held_out_checks_cannot_read_their_fixtures_directory(tmp_path,
                                                                           monkeypatch):
    """when the held-out fixtures folder is present but unreadable at run end (mode 000,
    non-root reader), run end prints the failure — a stderr line naming the fixtures folder or
    the read failure — does not enqueue curation for that run (no marker is written), still
    draws the run pages (the visualize launch runs), and `run.main` returns 0. The positive
    control: a missing held-out folder is not a failure — no stderr line names the folder or a
    read failure, both held-out nets answer "not held out", curation is enqueued (a marker is
    written) and visualize runs, as at base.
    """
    results, folders = {}, {}
    for tag in ("missing", "unreadable"):
        cell = tmp_path / tag
        cell.mkdir()
        S.configure_roots(cell, monkeypatch)
        (cell / "alert.json").write_text('{"alert_id": "A1105"}', encoding="utf-8")
        fixtures = cell / "held-out"
        if tag == "unreadable":
            (fixtures / "case-a").mkdir(parents=True)
            (fixtures / "case-a" / "alert.json").write_text("{}", encoding="utf-8")
            fixtures.chmod(0)
        code = _HELD_OUT_CHILD.replace("TMP", repr(str(cell))).replace(
            "FIXTURES", repr(str(fixtures)))
        folders[tag] = fixtures
        with S.restoring_modes(fixtures):
            results[tag] = S.unprivileged(code, cwd=cell)
    missing, unreadable = results["missing"], results["unreadable"]
    assert missing.get('rc') == 0, missing
    assert missing['visualized'] == 1, missing
    assert missing["markers"], f"the control enqueued nothing: {missing}"
    assert _held_out_failure_lines(missing["stderr"], folders["missing"]) == [], missing
    assert "raised" not in unreadable, f"run end crashed on the unreadable folder: {unreadable}"
    assert unreadable.get('rc') == 0, unreadable
    assert unreadable['visualized'] == 1, unreadable
    assert unreadable["markers"] == [], f"curation was enqueued past a failed held-out check: " \
                                       f"{unreadable}"
    assert _held_out_failure_lines(unreadable["stderr"], folders["unreadable"]), (
        f"run end did not print the held-out read failure: {unreadable}")


def _held_out_failure_lines(stderr: str, fixtures: Path) -> list[str]:
    """The stderr lines that name the held-out fixtures folder (its full path) or the read
    failure (`PermissionError`, or EACCES's own words). The base run's stderr over a MISSING
    folder holds none (E2-P100); the run dir's own name ends in `held-out`, so the folder is
    matched by its full path, never by that word."""
    marks = (str(fixtures), os.strerror(errno.EACCES), "PermissionError")
    return [ln for ln in stderr.splitlines() if any(m in ln for m in marks)]


_VISUALIZE_CHILD = """
    import json, os, sys
    from pathlib import Path
    from defender import run as run_mod
    out = {"enqueued": 0}
    runs = Path(os.environ["DEFENDER_RUNS_BASE"])
    def make(alert, run_id, **kw):
        d = runs / "20260921t143000z-visualize"
        d.mkdir(parents=True, exist_ok=True)
        return d
    def lifecycle(**kw):
        if DELETE:
            os.unlink(sys.executable)
        return {"output": "", "requests": 0, "truncated_by": None}
    def enqueue(*a, **k):
        out["enqueued"] += 1
        return True
    try:
        out["rc"] = run_mod.main([ALERT], lifecycle=lifecycle, preflight=lambda m: 0,
                                 enqueue=enqueue, materialize=make)
    except BaseException as e:
        out["raised"] = type(e).__name__
    print(json.dumps(out))
"""


def test_1105_visualize_launch_cannot_start_because_the_script_is_unreachable(tmp_path,
                                                                              monkeypatch):
    """at run end, when the visualize script path is missing, the interpreter starts and exits
    2, `VisualizeFailed` is printed and `run.main` returns 0. When the interpreter itself cannot
    be spawned, `FileNotFoundError` propagates out of `run.main`, after curation was enqueued.
    Both are real: the script is deleted from a real copy of the tree the child imports, and the
    interpreter is a real path deleted while its process runs.
    """
    S.configure_roots(tmp_path, monkeypatch)
    alert = _alert(tmp_path)

    root = S.tree_copy(tmp_path)
    (root / "defender" / "scripts" / "visualize" / "visualize_run.py").unlink()
    proc = S.fresh_interpreter(
        _VISUALIZE_CHILD.replace("DELETE", "False").replace("ALERT", repr(str(alert))),
        cwd=tmp_path, env={"PYTHONPATH": str(root)})
    got = S.last_json(proc)
    assert got.get('rc') == 0, (got, proc.stderr)
    assert got['enqueued'] == 1, (got, proc.stderr)
    assert 'visualize_run failed' in proc.stderr, proc.stderr
    assert '(exit 2)' in proc.stderr, proc.stderr

    python = S.deletable_interpreter(tmp_path)
    proc = S.fresh_interpreter(
        _VISUALIZE_CHILD.replace("DELETE", "True").replace("ALERT", repr(str(alert))),
        cwd=tmp_path, python=str(python))
    got = S.last_json(proc)
    assert got.get("raised") == "FileNotFoundError", (got, proc.stderr)
    assert got["enqueued"] == 1, got


def test_1105_sibling_spawn_and_visualize_launch_still_pass_no_timeout(tmp_path, monkeypatch):
    """the sibling spawn and the run-end visualize launch are each observed being called (the
    positive control: the real launch's own `communicate`/`wait`, with the child's argv), and
    neither call passes a `timeout` argument.
    """
    S.configure_roots(tmp_path, monkeypatch)
    _base, src = T.runs_base(tmp_path / "src")
    ep = T.episode(tmp_path / "ep", doc=S.manifest_doc(src))

    with S.watching_waits() as seen:
        exits = S.sym("start_family")(ep, ["zzz"])
    assert exits.get("zzz") not in (None, 0), exits
    spawns = [c for c in seen if "--world" in c["argv"] and "zzz" in c["argv"]]
    assert spawns, f"the sibling spawn was not observed: {seen}"
    assert all(c["timeout"] is None for c in spawns), spawns

    runs = tmp_path / "defender-runs"
    real_visualize = inspect.signature(S.run_py().main).parameters["visualize"].default
    with S.watching_waits() as seen:
        S.run_py().main([str(_alert(tmp_path))], lifecycle=S.quiet_lifecycle,
                        preflight=S.no_preflight, enqueue=lambda *a, **k: False,
                        visualize=real_visualize,
                        materialize=_run_dir_with(runs, investigation=None))
    launches = [c for c in seen if any(a.endswith("visualize_run.py") for a in c["argv"])]
    assert launches, f"the visualize launch was not observed: {seen}"
    assert all(c["timeout"] is None for c in launches), launches


# ---------------------------------------------------------------------------------------
# D6 — the executing run never imports the service; run.py injects its resume opener
# ---------------------------------------------------------------------------------------

OPERATIONS = ("store_factory", "open_session", "attach_pointer", "setup_errors")
SPEC_ATTRIBUTES = ("as_of", "continuation_prompt")


def _protocol_names() -> set[str]:
    opener = S.mod("runtime.driver").ResumeOpener
    names = set(dir(opener))
    for klass in inspect.getmro(opener):
        names |= set(getattr(klass, "__annotations__", {}))
    return names


def _sibling_source(tmp_path: Path, monkeypatch, **manifest_over) -> Path:
    """A source whose session clock is the test's (`clocked_source`), and a post-#1105 episode
    that names it — so a resumed sibling's spec agrees with the source store's own T0."""
    S.configure_roots(tmp_path, monkeypatch)
    src = S.clocked_source(tmp_path / "source-runs", S.PRE_1077_ID)
    doc = S.manifest_doc(src, as_of=S.AT_Z, fences_at=S.FENCES_AT_BRANCH, **manifest_over)
    return T.episode(tmp_path / "ep", doc=doc) / "family.yaml"


def test_1105_run_py_injects_the_service_resume_opener(tmp_path, monkeypatch):
    """the driver declares `ResumeOpener` with `store_factory`, `open_session`, `attach_pointer`
    and `setup_errors`. A `run.py --resume` run passes the service's implementation as
    `run_investigation(resume=…)`, and the driver calls those four operations and no service
    module directly: a recording proxy around the injected opener sees the store opened, the
    session opened and the pointer attached over a legal branch point (one model turn follows),
    and `setup_errors` consulted when a branch point is refused.
    """
    from defender.tests.e2e._replay_harness import ReplayFn, Turn

    assert set(OPERATIONS) <= _protocol_names(), _protocol_names()
    seen: list[str] = []
    handed_openers = []

    def wrap(opener):
        handed_openers.append(opener)
        proxy = S.Proxy(opener)
        object.__setattr__(proxy, "seen", seen)
        return proxy

    legal = _sibling_source(tmp_path / "legal", monkeypatch)
    rc, summaries, _ = S.drive_sibling(
        legal, "b", main=ReplayFn([Turn(text="Holding; the evidence is in hand.")]),
        wrap_resume=wrap)
    assert rc == 0
    assert summaries[0]["truncated_by"] != "store", summaries
    refused = _sibling_source(tmp_path / "refused", monkeypatch, branch_message_id=5999)
    rc, summaries, _ = S.drive_sibling(refused, "b", main=S.NeverAsked(), wrap_resume=wrap)
    assert rc == 0
    assert summaries[0]["truncated_by"] == "store", summaries

    for opener in handed_openers:
        assert type(opener).__module__.startswith(S.SERVICE), type(opener)
        for name in OPERATIONS:
            assert hasattr(opener, name), name
    assert set(OPERATIONS) <= set(seen), seen


def test_1105_refused_branch_point_ends_the_run_truncated_by_store_with_branch_error(
        tmp_path, monkeypatch):
    """when the injected `ResumeOpener` refuses the branch point (including a refused source),
    it raises `BranchError`, which is listed in `setup_errors`. The run summary then has
    `truncated_by == "store"` and `exit_reason == "BranchError"` (the literal string), and no
    model turn is driven.
    """
    manifest = _sibling_source(tmp_path, monkeypatch, branch_message_id=5999)
    model = S.NeverAsked()
    rc, summaries, handed = S.drive_sibling(manifest, "b", main=model)
    assert rc == 0
    assert summaries[0]["truncated_by"] == "store", summaries
    assert summaries[0]["exit_reason"] == "BranchError", summaries
    assert model.calls == 0
    assert S.sym("BranchError") in tuple(handed[0]["resume"].setup_errors)


def test_1105_resume_opener_meets_a_refusal_that_is_not_branch_error(tmp_path, monkeypatch):
    """The service's resume opener turns any `open_run` refusal on the source (`ValueError`,
    `TenantRecordCorrupt`) into `BranchError`; the run ends `truncated_by="store"`,
    `exit_reason == "BranchError"` (exact class — demands F5): a corrupt record
    (`TenantRecordCorrupt`), a record naming another tenant (plain `ValueError`) and a vanished
    non-case-stable source (`Run.at`'s `ValueError`), each arriving after materialize.
    """
    for fault in ("corrupt", "other_tenant", "vanished"):
        manifest = _sibling_source(tmp_path / fault, monkeypatch)
        src = S.read_manifest(manifest.parent)
        source = Path(src[S.SOURCE_RUNS_BASE_FIELD]) / src["source_run_id"]

        def inject(_run_dir, fault=fault, source=source):
            if fault == "vanished":
                source.rename(source.parent / "moved-away")
            else:
                S.plant_bad_record(source.parent, fault, elsewhere=source.parent.parent / "x")

        model = S.NeverAsked()
        rc, summaries, _ = S.drive_sibling(manifest, "b", main=model, after_materialize=inject)
        assert rc == 0, fault
        assert summaries[0]["truncated_by"] == "store", (fault, summaries)
        assert summaries[0]["exit_reason"] == "BranchError", (fault, summaries)
        assert model.calls == 0, fault


def test_1105_resume_spec_attributes_beyond_the_four_opener_operations(tmp_path, monkeypatch):
    """the protocol the driver declares inside the executing run covers the four opener
    operations and the two attributes the prompt code reads off the resume spec, `as_of` and
    `continuation_prompt`. The service's spec satisfies it structurally — the resumed run reads
    both off the injected opener — and the executing run imports no service type.
    """
    import ast

    from defender.tests.e2e._replay_harness import ReplayFn, Turn

    assert set(OPERATIONS + SPEC_ATTRIBUTES) <= _protocol_names(), _protocol_names()
    manifest = _sibling_source(tmp_path, monkeypatch)
    proxies: list[S.Proxy] = []
    rc, _summaries, handed = S.drive_sibling(
        manifest, "b", main=ReplayFn([Turn(text="Holding.")]),
        wrap_resume=lambda o: proxies.append(S.Proxy(o)) or proxies[-1])
    assert rc == 0
    for name in SPEC_ATTRIBUTES:
        assert hasattr(handed[0]["resume"], name), name
        assert name in proxies[0].seen, (name, proxies[0].seen)

    driver_dir = S.DEFENDER / "runtime" / "driver"
    for path in sorted(driver_dir.glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                assert not node.module.startswith(S.SERVICE), (path.name, node.module)
            if isinstance(node, ast.Import):
                assert not any(a.name.startswith(S.SERVICE) for a in node.names), path.name
