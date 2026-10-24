"""Alert admission at run start (strict UTF-8, one parseable JSON object, size bounds) and the
run record (facts plus alert digest) written beside the alert; identity checks read that record."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_data_root, location_path

from defender.run_repository import Run

import json
import os
import re
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.support.sandbox._spec791 import author_markers, marker_body
from defender.tests.tenancy.alert_front_door_1222 import _spec1222 as S
from defender.tests.e2e import _replay_harness as H

#: The admission shapes A8 refuses (every distinguished shape but the two it admits).
REFUSED_SHAPES = tuple(s for s in S.ADMISSION_SHAPES if s not in S.ADMITTED_SHAPES)
#: A1's "refuses anything else, naming why", read as: refusals of DIFFERENT causes differ. The
#: cause classes (92-reconciliation A3); shapes within one class may share a reason, and `bom` /
CAUSE_CLASSES: dict[str, tuple[str, ...]] = {
    "encoding": ("non_utf8", "utf16"),
    "not_one_json_object": ("not_json", "top_level_array", "scalar", "empty"),
    "nesting": ("deep_nesting",),
    "unpaired_surrogate": ("lone_surrogate",),
    "size": ("oversize",),
}
#: The curation request queue under the learning-state root (`_spec791.author_markers` reads it).
CURATION_QUEUE = "author-queue"
#: The rule object every scenario's alert starts from (`S.generic_alert`'s, spelled out so a
#: scenario can add or drop a member without replacing the rest).
BASE_RULE = {"id": "R-1001", "name": "Generic outbound beacon",
             "description": "Host contacted a rare external destination on a fixed cadence."}
EVENT_TIME = "2026-09-30T08:15:00Z"


class _StoppedAfterSetup(Exception):
    """Raised from `before=` — the run stops after setup wrote its folder and before the driver
    (and with it the box) starts: an interrupted run whose folder holds only what setup wrote."""


# Local helpers (scenario plumbing only; every decision is production's)

def _rule(**members: Any) -> dict[str, Any]:
    """`BASE_RULE` with members added or replaced (`None` drops one)."""
    rule = {**BASE_RULE, **members}
    return {k: v for k, v in rule.items() if v is not None}


def _alert(**rule_members: Any) -> dict[str, Any]:
    return S.generic_alert(rule=_rule(**rule_members))


def _drive(tmp_path: Path, planted: S.Planted, **kw: Any) -> S.Drive:
    return S.run_alert(tmp_path, tenant=planted, **kw)


def _snapshot(path: Path) -> tuple[bytes, int, int]:
    """A file's bytes, inode and mtime: equal snapshots mean the file was not rewritten (an
    in-place write moves the mtime, a rename-over moves the inode). A file that is not there is
    the demand's failure, named as such rather than an `os.stat` crash."""
    assert Path(path).is_file(), f"{path} is not there: the run holds no such file"
    st = os.stat(path)
    return Path(path).read_bytes(), st.st_ino, st.st_mtime_ns


Tree = dict[str, tuple[bytes, int, int]]


def _tree(folder: Path) -> Tree:
    """Every file under `folder`, as `_snapshot` sees it, by path relative to the folder. Taken
    without naming any file, so a folder's state is held before any coined name is asked for."""
    root = Path(folder).resolve()
    return {p.relative_to(root).as_posix(): _snapshot(p)
            for p in sorted(root.rglob("*")) if p.is_file()}


def _held(tree: Tree, folder: Path, path: Path) -> tuple[bytes, int, int]:
    """What `tree` held for `path`; fails when the file was not in the folder at that point."""
    rel = Path(path).resolve().relative_to(Path(folder).resolve()).as_posix()
    assert rel in tree, f"{rel} was not in the folder when it was observed: {sorted(tree)}"
    return tree[rel]


def _host_rewrite(path: Path, data: bytes | None) -> None:
    """Change (`data`) or remove (`None`) a run's file ON THE HOST, as an operator or a host
    process can: the input directory is read-only by design (A1), so owner write permission is
    granted on the directory (and file) for the change and the modes are put back after."""
    path = Path(path)
    parent = path.parent
    parent_mode = stat.S_IMODE(parent.stat().st_mode)
    parent.chmod(parent_mode | stat.S_IWUSR | stat.S_IXUSR)
    try:
        if data is None:
            path.unlink()
            return
        file_mode = stat.S_IMODE(path.stat().st_mode)
        path.chmod(file_mode | stat.S_IWUSR)
        path.write_bytes(data)
        path.chmod(file_mode)
    finally:
        parent.chmod(parent_mode)


def _stopped_after_setup(tmp_path: Path, planted: S.Planted, alert: Any) -> Path:
    """Drive `alert` until setup has written the run folder, then stop it there (an
    interrupted run). Returns the folder."""
    folder: dict[str, Path] = {}

    def stop(run_dir: Path) -> None:
        folder["run_dir"] = Path(run_dir)
        raise _StoppedAfterSetup("stopped after setup")

    d = _drive(tmp_path, planted, alert=alert, before=stop)
    assert isinstance(d.raised, _StoppedAfterSetup), (
        f"the interrupted run never reached the point after setup (rc={d.rc!r}, "
        f"refusal={d.refusal!r}, raised={d.raised!r})")
    assert "run_dir" in folder
    return folder["run_dir"]


def _failed_shims() -> S.RecordingShim:
    """ORIENT's shim runner recording every lookup's argv and answering each as a failed shim
    (`orient.ShimRunner`'s own spelling of failure) — the argv is the observation."""
    return S.RecordingShim(fail=("defender-",))


def _handed_signatures(shim: S.RecordingShim) -> list[str]:
    """The signature each corpus-vocabulary lookup was handed (`--signature X` or `--signature=X`)."""
    out: list[str] = []
    for argv in shim.vocabulary_lookups():
        for at, arg in enumerate(argv):
            if arg == "--signature" and at + 1 < len(argv):
                out.append(argv[at + 1])
            elif arg.startswith("--signature="):
                out.append(arg.split("=", 1)[1])
    return out


def _argv_mentions(shim: S.RecordingShim, value: str) -> bool:
    """Whether any orientation lookup's argv carries `value`, verbatim or regex-escaped."""
    joined = "\n".join(" ".join(argv) for argv in shim.argvs())
    return value in joined or re.escape(value) in joined


def _case_mapping_naming_the_signature() -> str:
    """The suite's case-history mapping with the record leg's comment body also naming the run's
    signature as `[sig=<value>]` (`S.SIGNED_COMMENT_BODY`; `{signature}` is a field of the
    comment's context), so the post-run record leg is an observable reader of the signature."""
    return S.case_mapping_text(comment_body=S.SIGNED_COMMENT_BODY)


def _ticket_text(store: S.TicketStore) -> str:
    """Every outbound ticket body (both legs), as one text."""
    return "\n".join(json.dumps(c["body"], ensure_ascii=False, sort_keys=True)
                     for c in store.calls)


def _named_refusal(d: S.Drive) -> bool:
    """Whether `run.main` exited by refusing with text (a named reason), not by raising."""
    return d.raised is None and isinstance(d.refusal, str) and bool(d.refusal.strip())


def _assert_refused_before_any_folder(d: S.Drive, what: str) -> None:
    """A8: refused at run start with a named reason, before any run folder, box, lead or model."""
    assert _named_refusal(d), (
        f"{what}: run start did not refuse the alert with a named reason (rc={d.rc!r}, "
        f"refusal={d.refusal!r}, raised={d.raised!r})")
    assert d.rc not in (0, None), f"{what}: a refused alert exited {d.rc!r}"
    assert d.lifecycle_calls == [], f"{what}: the run's lifecycle (its box) started for a refused alert"
    assert d.main.requests == 0, f"{what}: MAIN was asked for a turn on a refused alert"
    assert d.router.leads() == [], f"{what}: leads were dispatched for a refused alert: {d.router.leads()}"
    # #1187 (R1): run setup writes no `_tenant.json`, so a refused alert leaves the runs base
    # with no entry at all — nothing is excluded from the census.
    left = d.runs_base_entries()
    assert left == [], f"{what}: a refused alert left {left} under the runs base"


def _assert_admitted(d: S.Drive, what: str) -> Path:
    assert (d.raised, d.refusal, d.rc) == (None, None, 0), (
        f"{what}: an admissible alert was not run (rc={d.rc!r}, refusal={d.refusal!r}, "
        f"raised={d.raised!r})")
    assert d.run_dir is not None, f"{what}: no run folder"
    assert d.run_dir.is_dir(), f"{what}: no run folder"
    return d.run_dir


def _admitted_bytes(d: S.Drive) -> bytes:
    """The bytes the scenario wrote to the operator's input file."""
    assert d.input_bytes is not None
    return d.input_bytes


def _learning_enqueue(fixtures: Path) -> Callable[..., bool]:
    """`run.main`'s `enqueue` seam bound to PRODUCTION's curation enqueue
    (`run_common.enqueue_curation`, its learning gate included) over the held-out fixture set
    `fixtures`. The replay lifecycle starts no box, so the REAL reap scan (`box._scrub`) runs
    first, as production's lifecycle runs it before `main` enqueues."""
    def enqueue(run: Any, *args: Any, **kw: Any) -> bool:
        S.sym("box._scrub", "scrub")(run.run_dir)
        return bool(S.sym("run_common", "enqueue_curation")(
            run, *args, fixtures_dir=fixtures, **kw))
    return enqueue


def _held_out_fixtures(tmp_path: Path, *members: bytes) -> Path:
    """A held-out fixture set (`fixtures/held-out` layout: `<slug>/alert.json`) holding
    `members` — planted, since the shipped set holds only a README."""
    fixtures = Path(tmp_path) / "held-out-set"
    fixtures.mkdir(parents=True, exist_ok=True)
    for n, raw in enumerate(members, 1):
        slug = fixtures / f"front-door-{n:02d}"
        slug.mkdir()
        (slug / "alert.json").write_bytes(raw)
    return fixtures


def _curation_requests(run_dir: Path) -> dict[str, Path]:
    """Every curation request on the queue: its case key -> the run folder it names."""
    from defender.learning.core.config import LoopPaths
    from defender.tenancy._tenant import requested_tenant

    root = Path(os.environ["DEFENDER_DATA_ROOT"])
    tenant = requested_tenant(fixture_data_root(root), Path(run_dir).parent.parent.name)
    paths = LoopPaths.for_tenant(tenant)
    out: dict[str, Path] = {}
    for name in author_markers(paths):
        body = marker_body(Path(location_path(paths.state_root)) / CURATION_QUEUE / name)
        out[str(body.get("case_id"))] = (
            Path(os.environ["DEFENDER_DATA_ROOT"]) / str(body["tenant_id"]) / "runs" / str(body["run_id"]))
    return out


def _request_key_for(run_dir: Path) -> str | None:
    """The case key of the curation request naming `run_dir`, or None when none does."""
    for key, named in _curation_requests(run_dir).items():
        if named.resolve() == Path(run_dir).resolve():
            return key
    return None


def _union_shown(tmp_path: Path, source_alert: bytes, runs_base: Path, tag: str) -> str:
    """Grade an accepted episode whose launch copy holds `source_alert` (and its record) over
    `runs_base`, and return everything the judge was SHOWN — the sibling-trials section names
    each run of the union by its run id."""
    # #1187 (Layout A): the episode sits under the planted tenant's `<T>/episodes/`, where the
    # judge reaches it by id; `tmp_path / tag` tells this scene from another (`T.episode`).
    ep = J.accepted_episode(Path(tmp_path) / f"episodes-{tag}",
                            ledgers={"b": [J.oracle_row("b")], "c": []})
    S.plant_episode_copy(ep, alert=source_alert)
    judge = J.FakeJudge(default=J.as_reply_text(J.reply_doc()))
    J.grade(ep, runs_base=runs_base, judge=judge)
    assert judge.prompts, "the judge's grading pass asked the judge nothing"
    return "\n".join(judge.prompts)


def _launch(planted: S.Planted, source_run_dir: Path) -> tuple[Path | None, str | None]:
    """The branch launcher's `prepare_episode(runs, source, *, prime=)` over `source_run_dir`
    (priming stubbed through its `prime=` seam), in the tenant's runs repository (#1187
    declared change 3, review-4 F37: the episode is a fresh UUID `runs.create_episode()`
    claims — no id argument, no `data_root=`). Returns (episode dir, None) or (None, the
    refusal's text)."""
    cli = S.mod("learning.branch.cli")
    capture = S.mod("learning.branch.capture")
    try:
        held = cli.prepare_episode(planted.accept().runs_repository(),
                                   Run.at(Path(source_run_dir)),
                                   prime=lambda _src, _ep: capture.PrimeReport(primed=1))
    except SystemExit as refused:
        return None, str(refused.code if refused.code is not None else refused)
    with held as view:
        return Path(view.episode.dir), None


def _corpus_signatures(runs_base: Path) -> tuple[dict[str, str | None], Any]:
    """The invlang corpus over `runs_base`: each loaded past run's signature, and the report."""
    loaded = S.sym("skills.invlang.corpus", "load_corpus")(runs_base)
    companions, report = loaded[0], loaded[1]
    return {c.case_id: c.signature_id for c in companions}, report


def _golden_investigation() -> str:
    return (H.GOLDEN / "investigation.md").read_text(encoding="utf-8")


# A8 — admission, before any run folder

def _same_shape_other_content() -> dict[str, bytes]:
    """A second spelling of each refused shape over different content: a FIXED reason is the
    same for both."""
    other = S.generic_alert(rule_id="R-7007", host={"hostname": "db-9"})
    deeper = S.DEEP + 7
    return {
        "bom": S.admission_bytes("bom", other),
        "non_utf8": S.admission_bytes("non_utf8", other),
        "utf16": S.admission_bytes("utf16", other),
        "not_json": b"neither JSON nor anything else\n~~~\n",
        "top_level_array": S.admission_bytes("top_level_array", other),
        "scalar": b"4711",
        "whitespace_only": b"\n\n\t",
        "deep_nesting": b'{"z":' * deeper + b'"x"' + b"}" * deeper,
        "lone_surrogate": b'{"note": "tail \\udfff", "rule": {"id": "R-7007"}}',
    }


def test_a8_admission_refuses_a_bad_alert_before_any_run_folder(tmp_path):
    planted = S.plant_tenant()
    reasons: dict[str, str] = {}
    for shape in REFUSED_SHAPES:
        d = _drive(tmp_path, planted, alert=S.admission_bytes(shape))
        _assert_refused_before_any_folder(d, shape)
        # Refused before any run folder, so before any run id exists (#1279): nothing to mask.
        reasons[shape] = str(d.refusal)

    for shape, raw in _same_shape_other_content().items():
        d = _drive(tmp_path, planted, alert=raw)
        _assert_refused_before_any_folder(d, f"{shape} (other content)")
        assert str(d.refusal) == reasons[shape], (
            f"{shape}: the reason changes with the alert's content, so it is not a fixed reason: "
            f"{reasons[shape]!r} vs {d.refusal!r}")

    by_class = {cause: {reasons[shape] for shape in shapes} for cause, shapes in CAUSE_CLASSES.items()}
    for cause, said in by_class.items():
        for other, other_said in by_class.items():
            if cause < other:
                assert not said & other_said, (
                    f"a refusal for {cause} reads exactly like one for {other}, so it does not "
                    f"name why: {sorted(said & other_said)}")

    for shape in S.ADMITTED_SHAPES:
        d = _drive(tmp_path, planted, alert=S.admission_bytes(shape))
        run_dir = _assert_admitted(d, shape)
        assert d.stored_alert == d.input_bytes, f"{shape}: the stored alert is not the admitted bytes"
        assert S.recorded_digest(run_dir) == S.sha256_hex(d.input_bytes), (
            f"{shape}: the record's digest is not the admitted bytes' sha256")


def test_p015_non_json_alert_text_with_fence_lines_of_every_sh(tmp_path):
    marker = "P015-FENCE-MARKER-41c9"
    fence_lines = ["```", marker, "`````", "`" * 20, " ```", "  ```", "   ```yaml", "```yaml",
                   "~~~", "```"]
    text = "\n".join(fence_lines)
    planted = S.plant_tenant()

    d = _drive(tmp_path, planted, alert=(text + "\n").encode("utf-8"))
    _assert_refused_before_any_folder(d, "non-JSON alert with fence lines")
    assert marker not in str(d.refusal), "the refusal echoes the alert's text instead of naming why"

    control = _drive(tmp_path, planted, alert=S.generic_alert(message=text))
    _assert_admitted(control, "the same fence text inside a JSON string")
    prompt = control.router.first_prompt(S.L3)
    assert marker not in prompt, "alert bytes reached the correlation lead's prompt"
    assert "`" * 20 not in prompt, "alert bytes reached the correlation lead's prompt"


def test_p018_alert_bytes_not_utf8(tmp_path):
    planted = S.plant_tenant()
    first, second = S.generic_alert(), S.generic_alert(rule_id="R-3003", user={"login": "ops-9"})
    for shape in ("bom", "non_utf8"):
        reasons = []
        for base in (first, second):
            d = _drive(tmp_path, planted, alert=S.admission_bytes(shape, base))
            _assert_refused_before_any_folder(d, shape)
            reasons.append(str(d.refusal))
        assert reasons[0] == reasons[1], f"{shape}: the reason is not fixed: {reasons}"

    control = _drive(tmp_path, planted, alert=S.admission_bytes("valid_object", first))
    run_dir = _assert_admitted(control, "the same alert without the mark")
    assert control.router.dispatched(S.L3), "the admitted twin dispatched no correlation lead"
    assert S.recorded_digest(run_dir) == S.sha256_hex(_admitted_bytes(control))


def test_p045_alert_nests_deeper_than_the_parser_follows(tmp_path):
    planted = S.plant_tenant()
    d = _drive(tmp_path, planted, alert=S.admission_bytes("deep_nesting"))
    _assert_refused_before_any_folder(d, "deep nesting")

    source = S.alert_bytes(S.generic_alert())
    past = S.plant_run(location_path(planted.runs), "p045-past", alert=source,
                       facts={"signature": "R-1001", "event_time": EVENT_TIME},
                       files={"investigation.md": _golden_investigation(),
                              "report.md": J.report_text("benign")})
    _host_rewrite(S.alert_file(past), S.admission_bytes("deep_nesting"))

    signatures, _report = _corpus_signatures(location_path(planted.runs))
    assert signatures.get("p045-past") == "R-1001", (
        f"the corpus did not take the past run's signature from its record: {signatures}")
    shown = _union_shown(tmp_path, source, location_path(planted.runs), "p045")
    assert "p045-past" not in shown, (
        "the judge's union dropped a trial of this alert whose alert file the parser cannot "
        "follow — it parsed the alert bytes instead of reading the record")


def test_p086_mapped_value_has_an_unpaired_surrogate_escape_at(tmp_path):
    planted = S.plant_tenant()
    refused_store = S.TicketStore()
    d = _drive(tmp_path, planted, alert=S.admission_bytes("lone_surrogate"),
               tickets=S.ticket_writer(refused_store), update_ticket=True)
    _assert_refused_before_any_folder(d, "lone surrogate in the mapped summary")
    assert refused_store.calls == [], f"a ticket leg met the refused alert: {refused_store.calls}"

    store = S.TicketStore()
    summary, event_time = "before\x00after", f"{EVENT_TIME}\x00"
    nul = _drive(tmp_path, planted, alert=S.generic_alert(rule=_rule(description=summary), detected_at=event_time),
                 tickets=S.ticket_writer(store), update_ticket=True)
    run_dir = _assert_admitted(nul, "NUL in summary and event_time")
    opened = store.only_open()
    assert opened.get("summary") == summary, f"the open leg's summary is {opened.get('summary')!r}"
    assert f"evt:{event_time}" in opened.get("labels", []), (
        f"the open leg's event-time label is not the recorded event_time: {opened.get('labels')}")
    assert len(store.comments()) == 1, "the record leg did not post its comment"
    assert S.recorded(run_dir, "summary") == summary
    assert S.recorded(run_dir, "event_time") == event_time


def test_p138_refused_alert_leaves_a_run_folder_without_a_reco(tmp_path):
    planted = S.plant_tenant()
    source = S.alert_bytes(S.generic_alert())
    finished = _drive(tmp_path, planted, alert=source, main=S.closing_main_turns())
    finished_id = _assert_admitted(finished, "the earlier finished run").name
    before = finished.runs_base_entries()

    d = _drive(tmp_path, planted, alert=S.admission_bytes("not_json"))
    assert _named_refusal(d), (
        f"a non-JSON alert was not refused at run start (rc={d.rc!r}, raised={d.raised!r})")
    assert d.lifecycle_calls == [], "a box started for a refused alert"
    assert d.main.requests == 0, "MAIN was asked for a turn on a refused alert"
    assert d.router.leads() == [], "a lead was dispatched for a refused alert"
    assert d.runs_base_entries() == before, (
        f"the refused start changed the runs base: {sorted(set(d.runs_base_entries()) - set(before))}")

    signatures, report = _corpus_signatures(location_path(planted.runs))
    assert set(signatures) == {finished_id}, (
        f"the corpus counted something besides the finished run: {signatures}")
    assert report.scanned == 1, f"the corpus scanned {report.scanned} past runs, not one"
    shown = _union_shown(tmp_path, source, location_path(planted.runs), "p138")
    assert finished_id not in shown, "the union lost the finished trial of this alert"


# A1 — the record, written once beside the alert

def test_facts_are_recorded_beside_the_alert_at_run_start(tmp_path):
    planted = S.plant_tenant(alert_mapping={"signature": "rule.id", "event_time": "detected_at"})
    at_start: dict[str, Tree] = {}

    def at_run_start(run_dir: Path) -> None:
        at_start["tree"] = _tree(run_dir)

    d = _drive(tmp_path, planted, before=at_run_start)
    run_dir = _assert_admitted(d, "an ordinary alert")
    assert "tree" in at_start, "the run never reached the point after setup"
    tree = at_start["tree"]
    assert d.stored_alert == d.input_bytes, "alert.json does not hold exactly the admitted bytes"
    assert _snapshot(S.alert_file(run_dir)) == _held(tree, run_dir, S.alert_file(run_dir)), (
        "the alert was rewritten during the run")

    record_at_start = _held(tree, run_dir, S.record_file(run_dir))
    record = json.loads(record_at_start[0].decode("utf-8"))
    assert record.get(S.COINED["record.digest"]) == S.sha256_hex(_admitted_bytes(d)), (
        f"the record written at run start does not carry the alert's digest: {record}")
    assert record.get("signature") == "R-1001", (
        f"the record written at run start does not hold the mapped signature: {record}")
    assert record.get("event_time") == EVENT_TIME, (
        f"the record written at run start does not hold the mapped event_time: {record}")
    assert record.get("summary") is None, (
        f"an unmapped summary was recorded anyway (a vendor default?): {record.get('summary')!r}")
    assert S.record_file(run_dir).parent == S.alert_file(run_dir).parent == S.input_dir(run_dir), (
        "the record does not sit beside the alert in the run's input directory")
    assert _snapshot(S.record_file(run_dir)) == record_at_start, (
        "the record was rewritten during the run")


def test_alert_mapping_is_read_once_at_run_start(tmp_path):
    planted = S.plant_tenant(
        alert_mapping={"signature": "host.hostname", "event_time": "detected_at",
                       "summary": "rule.description"},
        case_mapping=_case_mapping_naming_the_signature())
    edited: list[Path] = []

    def edit_after_run_start(run_dir: Path) -> None:
        S.remap(planted, S.DEFAULT_MAPPING_GENERIC)
        edited.append(Path(run_dir))

    shim, store = _failed_shims(), S.TicketStore()
    d = _drive(tmp_path, planted, before=edit_after_run_start, orient_shim=shim,
               tickets=S.ticket_writer(store), update_ticket=True, main=S.closing_main_turns())
    run_dir = _assert_admitted(d, "an ordinary alert")
    assert edited, "the mapping was never edited after run start"

    assert _handed_signatures(shim) == ["app-7"], (
        f"orientation's vocabulary lookup was not handed the run-start signature: {shim.argvs()}")
    assert not _argv_mentions(shim, "R-1001"), (
        f"an orientation lookup read the edited mapping: {shim.argvs()}")
    comments = store.comments()
    assert len(comments) == 1, f"the post-run record leg posted {len(comments)} comments"
    assert "[sig=app-7]" in comments[0].get("body", ""), (
        f"the post-run record leg did not carry the run-start signature: {comments}")
    assert "sig:app-7" in store.only_open().get("labels", [])
    assert "R-1001" not in _ticket_text(store), (
        "a ticket leg read the edited mapping")
    assert S.recorded(run_dir, "signature") == "app-7"


def test_p141_record_for_a_value_the_signature_rule_refuses(tmp_path):
    planted = S.plant_tenant(case_mapping=_case_mapping_naming_the_signature())
    over_bound = "X" + "7" * S.SIGNATURE_MAX
    arms: dict[str, dict[str, Any]] = {
        "unmapped": S.generic_alert(rule=_rule(id=None)),
        "unmapped-2": S.generic_alert(rule=_rule(id=None), host={"hostname": "db-4"}),
        "whitespace": _alert(id="R 1001"),
        "over-bound": _alert(id=over_bound),
        "key": _alert(id="K-1"),
    }
    seen: dict[str, tuple[S.Drive, Path, S.RecordingShim, S.TicketStore]] = {}
    for arm, alert in arms.items():
        shim, store = _failed_shims(), S.TicketStore()
        d = _drive(tmp_path, planted, alert=alert, orient_shim=shim,
                   tickets=S.ticket_writer(store), update_ticket=True,
                   main=S.closing_main_turns())
        seen[arm] = (d, _assert_admitted(d, arm), shim, store)

    _key_d, key_dir, key_shim, key_store = seen["key"]
    assert _handed_signatures(key_shim) == ["K-1"], key_shim.argvs()
    assert "sig:K-1" in key_store.only_open().get("labels", [])
    assert "[sig=K-1]" in key_store.comments()[0].get("body", "")

    for arm, refused in (("whitespace", "R 1001"), ("over-bound", over_bound)):
        d, run_dir, shim, store = seen[arm]
        for value in {refused, refused[:S.SIGNATURE_MAX]}:
            assert not _argv_mentions(shim, value), (
                f"{arm}: the refused value reached an orientation lookup: {shim.argvs()}")
            assert value not in _ticket_text(store), f"{arm}: the refused value reached a ticket leg"
            assert value not in S.harness_text(d.opening_message), (
                f"{arm}: the refused value reached MAIN's opening message as harness prose")
            assert value.encode("utf-8") not in S.record_file(run_dir).read_bytes(), (
                f"{arm}: the refused value was written into the record")
        assert S.recorded(run_dir, "signature") is None, f"{arm}: the record holds a signature"

    assert S.recorded(key_dir, "signature") == "K-1"
    first, second = (S.read_record(seen[a][1]) for a in ("unmapped", "unmapped-2"))
    varies = {k for k in set(first) | set(second) if first.get(k) != second.get(k)}
    varies.add(S.COINED["record.digest"])

    def note(arm: str) -> dict[str, Any]:
        doc = S.read_record(seen[arm][1])
        return {k: v for k, v in doc.items() if k not in varies}

    assert note("whitespace") == note("unmapped") == note("over-bound"), (
        "a refused value is not recorded like an unmapped path: "
        f"{note('whitespace')} / {note('over-bound')} vs {note('unmapped')}")


# A8 / C47 — the recorded digest is the alert's one identity

def test_a8_every_identity_check_reads_the_recorded_digest(tmp_path):
    planted = S.plant_tenant()
    location_path(planted.accept().learning).mkdir(exist_ok=True)
    held_out, ordinary = S.alert_bytes(_alert(id="H-1")), S.alert_bytes(_alert())
    enqueue = _learning_enqueue(_held_out_fixtures(tmp_path, held_out))
    entry = S.operator_input(tmp_path)

    def input_becomes(raw: bytes | None) -> Callable[[Path], None]:
        def change(_run_dir: Path) -> None:
            if raw is None:
                entry.unlink()
            else:
                entry.write_bytes(raw)
        return change

    def run(label: str, alert: bytes, change: Callable[[Path], None] | None = None) -> Path:
        """One run; #1279: its id is the one setup minted, read off the run folder."""
        d = _drive(tmp_path, planted, alert=alert, enqueue=enqueue, before=change,
                   main=S.closing_main_turns())
        run_dir = _assert_admitted(d, label)
        assert d.enqueued, f"{label}: the learning enqueue was never reached"
        return run_dir

    held_out_dir = run("dig-held-out", held_out, input_becomes(ordinary))
    assert _request_key_for(held_out_dir) is None, (
        "a run of a held-out alert filed a curation request once its input file changed")

    keys = {}
    dirs: dict[str, Path] = {}
    for label, change in (("dig-untouched", None), ("dig-removed", input_becomes(None)),
                          ("dig-rewritten", input_becomes(held_out))):
        dirs[label] = run(label, ordinary, change)
        keys[label] = _request_key_for(dirs[label])
    assert keys["dig-untouched"] is not None, f"an ordinary run filed no curation request: {keys}"
    assert len(set(keys.values())) == 1, (
        f"the curation key follows the operator's input file, not the recorded digest: {keys}")

    episode, refusal = _launch(planted, dirs["dig-removed"])
    assert refusal is None, f"the launch was refused: {refusal}"
    assert episode is not None
    assert S.episode_alert_file(episode).read_bytes() == ordinary
    assert json.loads(S.episode_record_file(episode).read_text(encoding="utf-8")).get(
        S.COINED["record.digest"]) == S.sha256_hex(ordinary)

    rewritten = dirs["dig-untouched"]
    _host_rewrite(S.alert_file(rewritten), S.alert_bytes(_alert(id="R-9999")))
    episode, refusal = _launch(planted, rewritten)
    assert episode is None, "a launch copied an alert whose bytes no longer match the record"
    assert refusal, "the launch stopped without naming why"

    shown = _union_shown(tmp_path, ordinary, location_path(planted.runs), "dig")
    for label in ("dig-untouched", "dig-removed", "dig-rewritten"):
        assert dirs[label].name not in shown, (
            f"the judge's union did not list {label} ({dirs[label].name}), a trial of this alert")
    assert held_out_dir.name not in shown, "the union listed a run of another alert"


def test_p145_input_file_changes_during_the_run_and_post_run_s(tmp_path):
    planted = S.plant_tenant()
    location_path(planted.accept().learning).mkdir(exist_ok=True)
    held_out, ordinary = S.alert_bytes(_alert(id="H-2")), S.alert_bytes(_alert())
    enqueue = _learning_enqueue(_held_out_fixtures(tmp_path, held_out))
    entry = S.operator_input(tmp_path)

    def change_to(raw: bytes | None) -> Callable[[Path], None]:
        def change(_run_dir: Path) -> None:
            if raw is None:
                entry.unlink()
            else:
                entry.write_bytes(raw)
        return change

    outcomes: dict[str, str | None] = {}
    for label, alert, change in (
            ("p145-held-changed", held_out, change_to(ordinary)),
            ("p145-held-removed", held_out, change_to(None)),
            ("p145-plain", ordinary, None),
            ("p145-plain-changed", ordinary, change_to(held_out)),
            ("p145-plain-removed", ordinary, change_to(None))):
        d = _drive(tmp_path, planted, alert=alert, enqueue=enqueue, before=change)
        run_dir = _assert_admitted(d, label)
        assert d.enqueued, f"{label}: the learning enqueue was never reached"
        outcomes[label] = _request_key_for(run_dir)

    for label in ("p145-held-changed", "p145-held-removed"):
        assert outcomes[label] is None, (
            f"the held-out check followed the changed or removed input file: {outcomes}")
    plain = outcomes["p145-plain"]
    assert plain is not None, "an ordinary run filed no curation request"
    for label in ("p145-plain-changed", "p145-plain-removed"):
        assert outcomes[label] == plain, f"the curation key moved with the input file: {outcomes}"


def test_p128_held_out_copies_of_the_alert_exist_under_the_run(tmp_path):
    planted = S.plant_tenant()
    location_path(planted.accept().learning).mkdir(exist_ok=True)
    held_out, ordinary = S.alert_bytes(_alert(id="H-3")), S.alert_bytes(_alert())
    enqueue = _learning_enqueue(_held_out_fixtures(tmp_path, held_out))
    entry = S.operator_input(tmp_path)

    def input_rewritten(_run_dir: Path) -> None:
        entry.write_bytes(ordinary)

    copy = _drive(tmp_path, planted, alert=held_out, enqueue=enqueue,
                  before=input_rewritten, main=S.closing_main_turns())
    copy_dir = _assert_admitted(copy, "a run of a held-out alert")
    assert copy.enqueued, "the learning enqueue was never reached"
    assert _request_key_for(copy_dir) is None, "the held-out copy was handed to learning"

    plain = _drive(tmp_path, planted, alert=ordinary, enqueue=enqueue,
                   main=S.closing_main_turns())
    assert _request_key_for(_assert_admitted(plain, "an ordinary run")) is not None, (
        "the gate refused an ordinary run")

    shown = _union_shown(tmp_path, held_out, location_path(planted.runs), "p128")
    assert copy_dir.name not in shown, "the held-out copy was dropped from its alert's union"
    assert _assert_admitted(plain, "an ordinary run").name not in shown, "the union listed a run of another alert"


def test_p142_record_present_but_alert_file_gone_or_rewritten_(tmp_path):
    planted = S.plant_tenant()
    source = S.alert_bytes(_alert())
    # #1279: each run's id is minted by setup, so the three runs are named by the label they were
    # driven under and found by the folder each run reports.
    dirs = {label: _assert_admitted(_drive(tmp_path, planted, alert=source,
                                           main=S.closing_main_turns()), label)
            for label in ("rewritten", "gone", "intact")}
    _host_rewrite(S.alert_file(dirs["rewritten"]), S.alert_bytes(_alert(id="R-9999")))
    _host_rewrite(S.alert_file(dirs["gone"]), None)

    signatures, _report = _corpus_signatures(location_path(planted.runs))
    for label, run_dir in dirs.items():
        assert signatures.get(run_dir.name) == "R-1001", (
            f"the corpus did not take {label}'s signature from its record: {signatures}")

    shown = _union_shown(tmp_path, source, location_path(planted.runs), "p142")
    for label, run_dir in dirs.items():
        assert run_dir.name not in shown, (
            f"the judge's union did not list {label} ({run_dir.name}) by its recorded digest")

    for label in ("rewritten", "gone"):
        run_id = dirs[label].name
        episode, refusal = _launch(planted, dirs[label])
        assert episode is None, (
            f"a launch from {run_id} went ahead although its alert no longer matches its record")
        assert refusal is not None
        assert run_id in refusal, f"the launch refusal does not name the run: {refusal!r}"
    episode, refusal = _launch(planted, dirs["intact"])
    assert refusal is None, f"the intact run's launch was refused: {refusal}"
    assert episode is not None
    assert S.episode_alert_file(episode).read_bytes() == source
    assert json.loads(S.episode_record_file(episode).read_text(encoding="utf-8")).get(
        S.COINED["record.digest"]) == S.sha256_hex(source)


# R7 — the shared test builders make admissible alerts
