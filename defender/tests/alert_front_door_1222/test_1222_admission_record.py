"""#1222 spec, slice S02 — the alert's admission and the run's record (A1, A8, C44, C47).

Run start admits the operator's alert bytes once, before any run folder exists (strict UTF-8,
no byte-order mark, exactly one JSON object the parser can follow, no unpaired surrogate, not
over size), derives the three facts once through the tenant's alert mapping and writes them,
with the alert's byte digest, into the run's record beside the alert. From then on the record
is the run's one certificate: the held-out check, the curation key, the launch byte check and
the sibling union take the alert's identity from the recorded digest, and no reader re-derives
a fact from the alert file.

Every scenario drives a production entry point: `run.main` through `S.run_alert` (admission,
`materialize_run`, the ticket legs, the learning enqueue are production's), the invlang corpus
loader, the judge's grading pass and the branch launcher's `prepare_episode`. Faults are real
bytes and real files written here (tier 1): a byte-order mark, a lone-surrogate escape, a
directory squatting the record's name, an operator input file rewritten or removed mid-run, an
alert file rewritten on the host after the run. The coined record and input-directory names are
reached only through `S` (`S.record_file`, `S.input_dir`, `S.read_record`, ...).

Every `run_alert` call pins its own `run_id`: `run.main` mints an id from the input file's stem
and a one-second timestamp, so two unpinned drives in one second collide on one folder.
"""
from __future__ import annotations

from defender.run_repository import Run

import json
import os
import re
import stat
from collections.abc import Callable
from pathlib import Path
from typing import Any

from defender.tests._fixture_uuid import fixture_uuid
from defender.tests import _judge_921 as J
from defender.tests._spec791 import author_markers, marker_body
from defender.tests.alert_front_door_1222 import _spec1222 as S
from defender.tests.e2e import _replay_harness as H

#: The admission shapes A8 refuses (every distinguished shape but the two it admits).
REFUSED_SHAPES = tuple(s for s in S.ADMISSION_SHAPES if s not in S.ADMITTED_SHAPES)
#: A1's "refuses anything else, naming why", read as: refusals of DIFFERENT causes differ. The
#: cause classes (92-reconciliation A3); shapes within one class may share a reason, and `bom` /
#: `whitespace_only` may share one with whichever class the implementation puts them in.
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


# =================================================================================================
# Local helpers (scenario plumbing only; every decision is production's)
# =================================================================================================

def _rule(**members: Any) -> dict[str, Any]:
    """`BASE_RULE` with members added or replaced (`None` drops one)."""
    rule = {**BASE_RULE, **members}
    return {k: v for k, v in rule.items() if v is not None}


def _alert(**rule_members: Any) -> dict[str, Any]:
    return S.generic_alert(rule=_rule(**rule_members))


def _drive(tmp_path: Path, planted: S.Planted, run_id: str, **kw: Any) -> S.Drive:
    return S.run_alert(tmp_path, tenant=planted, run_id=run_id, **kw)


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


def _stopped_after_setup(tmp_path: Path, planted: S.Planted, run_id: str,
                         alert: Any) -> Path:
    """Drive `alert` until setup has written the run folder, then stop it there (an
    interrupted run). Returns the folder."""
    folder: dict[str, Path] = {}

    def stop(run_dir: Path) -> None:
        folder["run_dir"] = Path(run_dir)
        raise _StoppedAfterSetup(f"{run_id} stopped after setup")

    d = _drive(tmp_path, planted, run_id, alert=alert, before=stop)
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
    `fixtures`. The replay lifecycle starts no box, so the REAL reap scan (`runtime.scrub`) runs
    first, as production's lifecycle runs it before `main` enqueues."""
    def enqueue(run: Any, *args: Any, **kw: Any) -> bool:
        S.sym("runtime.scrub", "scrub")(run.run_dir)
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


def _curation_requests() -> dict[str, Path]:
    """Every curation request on the queue: its case key -> the run folder it names."""
    paths = S.sym("learning.core.config", "loop_paths")()
    out: dict[str, Path] = {}
    for name in author_markers(paths):
        body = marker_body(Path(paths.state_root) / CURATION_QUEUE / name)
        out[str(body.get("case_id"))] = (
            Path(os.environ["DEFENDER_DATA_ROOT"]) / str(body["tenant_id"]) / "runs" / str(body["run_id"]))
    return out


def _request_key_for(run_dir: Path) -> str | None:
    """The case key of the curation request naming `run_dir`, or None when none does."""
    for key, named in _curation_requests().items():
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


def _launch(planted: S.Planted, source_run_dir: Path, label: str) -> tuple[Path | None, str | None]:
    """The branch launcher's `prepare_episode` over `source_run_dir` (priming stubbed through its
    `prime=` seam), for the episode `label` names (#1187: the id is its uuid4, `fixture_uuid`).
    Returns (episode dir, None) or (None, the refusal's text)."""
    cli = S.mod("learning.branch.cli")
    capture = S.mod("learning.branch.capture")
    try:
        held = cli.prepare_episode(fixture_uuid(label), Run.at(Path(source_run_dir)), data_root=planted.accept().data_root,
                                   prime=lambda _src, _ep: capture.PrimeReport(primed=1))
    except SystemExit as refused:
        return None, str(refused.code if refused.code is not None else refused)
    with held as episode:
        return Path(episode.dir), None


def _corpus_signatures(runs_base: Path) -> tuple[dict[str, str | None], Any]:
    """The invlang corpus over `runs_base`: each loaded past run's signature, and the report."""
    loaded = S.sym("skills.invlang.corpus", "load_corpus")(runs_base)
    companions, report = loaded[0], loaded[1]
    return {c.case_id: c.signature_id for c in companions}, report


def _golden_investigation() -> str:
    return (H.GOLDEN / "investigation.md").read_text(encoding="utf-8")


# =================================================================================================
# A8 — admission, before any run folder
# =================================================================================================

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
    """Run start checks the input alert's raw bytes before any run folder exists: a byte-order
    mark, non-UTF-8 or UTF-16 bytes, text that is not JSON, a top-level array or scalar, an empty
    or whitespace-only file, nesting the parser cannot follow, an unpaired surrogate escape and
    an over-size file are each refused with a fixed reason naming why and leave nothing under the
    runs base; a valid object — one holding raw U+2028/U+2029/U+0085 included — is admitted.

    Each shape is the real bytes `S.admission_bytes` writes to the operator's input file (PR-02:
    base admits every one; PA-01: base refuses only the over-size file, after the folder exists).
    "Fixed" is observed as: the same shape spelled over other content gets the same reason.
    "Naming why" is observed as: refusals of different causes differ — encoding, not one JSON
    object, nesting, an unpaired surrogate, size (`CAUSE_CLASSES`); shapes of one cause may share
    a reason."""
    planted = S.plant_tenant()
    reasons: dict[str, str] = {}
    for shape in REFUSED_SHAPES:
        run_id = fixture_uuid(f"a8-{shape.replace('_', '-')}")
        d = _drive(tmp_path, planted, run_id, alert=S.admission_bytes(shape))
        _assert_refused_before_any_folder(d, shape)
        reasons[shape] = str(d.refusal).replace(run_id, "<RUN_ID>")

    for shape, raw in _same_shape_other_content().items():
        run_id = fixture_uuid(f"a8-again-{shape.replace('_', '-')}")
        d = _drive(tmp_path, planted, run_id, alert=raw)
        _assert_refused_before_any_folder(d, f"{shape} (other content)")
        assert str(d.refusal).replace(run_id, "<RUN_ID>") == reasons[shape], (
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
        d = _drive(tmp_path, planted, fixture_uuid(f"a8-{shape.replace('_', '-')}"),
                   alert=S.admission_bytes(shape))
        run_dir = _assert_admitted(d, shape)
        assert d.stored_alert == d.input_bytes, f"{shape}: the stored alert is not the admitted bytes"
        assert S.recorded_digest(run_dir) == S.sha256_hex(d.input_bytes), (
            f"{shape}: the record's digest is not the admitted bytes' sha256")


def test_p015_non_json_alert_text_with_fence_lines_of_every_sh(tmp_path):
    """A non-JSON alert is refused at run start, naming why. No alert byte reaches the lead's
    prompt.

    The bytes carry a backtick-fence line of every shape PR-03 drove (three, five and twenty
    backticks, one to three leading spaces, an info string, a tilde fence, a fence as the first
    and the last line) around a unique marker. Positive control: the same text as a string inside
    an admitted JSON alert — the correlation lead is dispatched, and its prompt still carries no
    alert byte (A3)."""
    marker = "P015-FENCE-MARKER-41c9"
    fence_lines = ["```", marker, "`````", "`" * 20, " ```", "  ```", "   ```yaml", "```yaml",
                   "~~~", "```"]
    text = "\n".join(fence_lines)
    planted = S.plant_tenant()

    d = _drive(tmp_path, planted, fixture_uuid("p015-not-json"), alert=(text + "\n").encode("utf-8"))
    _assert_refused_before_any_folder(d, "non-JSON alert with fence lines")
    assert marker not in str(d.refusal), "the refusal echoes the alert's text instead of naming why"

    control = _drive(tmp_path, planted, fixture_uuid("p015-in-a-string"),
                     alert=S.generic_alert(message=text))
    _assert_admitted(control, "the same fence text inside a JSON string")
    prompt = control.router.first_prompt(S.L3)
    assert marker not in prompt, "alert bytes reached the correlation lead's prompt"
    assert "`" * 20 not in prompt, "alert bytes reached the correlation lead's prompt"


def test_p018_alert_bytes_not_utf8(tmp_path):
    """An alert whose bytes carry a byte-order mark or are not UTF-8 is refused at admission,
    before any run folder exists, with a fixed reason; no lead is dispatched and nothing is left
    under the runs base.

    PR-02: base admits both and stores them byte-identical. Each shape is driven over two
    different alerts (the reason must not change). Positive control: the same alert without the
    mark is admitted and its correlation lead is dispatched."""
    planted = S.plant_tenant()
    first, second = S.generic_alert(), S.generic_alert(rule_id="R-3003", user={"login": "ops-9"})
    for shape in ("bom", "non_utf8"):
        reasons = []
        for n, base in enumerate((first, second), 1):
            run_id = fixture_uuid(f"p018-{shape.replace('_', '-')}-{n}")
            d = _drive(tmp_path, planted, run_id, alert=S.admission_bytes(shape, base))
            _assert_refused_before_any_folder(d, shape)
            reasons.append(str(d.refusal).replace(run_id, "<RUN_ID>"))
        assert reasons[0] == reasons[1], f"{shape}: the reason is not fixed: {reasons}"

    control = _drive(tmp_path, planted, fixture_uuid("p018-control"), alert=S.admission_bytes("valid_object", first))
    run_dir = _assert_admitted(control, "the same alert without the mark")
    assert control.router.dispatched(S.L3), "the admitted twin dispatched no correlation lead"
    assert S.recorded_digest(run_dir) == S.sha256_hex(_admitted_bytes(control))


def test_p045_alert_nests_deeper_than_the_parser_follows(tmp_path):
    """An alert the parser cannot follow is refused at run start, naming why. No later reader
    parses alert bytes for facts.

    PR-04: at base a deep alert makes orientation raise RecursionError (the run does not start
    cleanly), and ONE past run whose alert is deep makes `load_corpus` raise and the judge's union
    skip it. The second sentence is driven with a past run whose record holds the facts and whose
    alert file was rewritten on the host to deep bytes: the corpus and the judge's sibling union
    read the record, never the alert bytes."""
    planted = S.plant_tenant()
    d = _drive(tmp_path, planted, fixture_uuid("p045-deep"), alert=S.admission_bytes("deep_nesting"))
    _assert_refused_before_any_folder(d, "deep nesting")

    source = S.alert_bytes(S.generic_alert())
    past = S.plant_run(planted.runs, "p045-past", alert=source,
                       facts={"signature": "R-1001", "event_time": EVENT_TIME},
                       files={"investigation.md": _golden_investigation(),
                              "report.md": J.report_text("benign")})
    _host_rewrite(S.alert_file(past), S.admission_bytes("deep_nesting"))

    signatures, _report = _corpus_signatures(planted.runs)
    assert signatures.get("p045-past") == "R-1001", (
        f"the corpus did not take the past run's signature from its record: {signatures}")
    shown = _union_shown(tmp_path, source, planted.runs, "p045")
    assert "p045-past" not in shown, (
        "the judge's union dropped a trial of this alert whose alert file the parser cannot "
        "follow — it parsed the alert bytes instead of reading the record")


def test_p086_mapped_value_has_an_unpaired_surrogate_escape_at(tmp_path):
    """An alert holding an unpaired surrogate escape is refused at admission, naming why, so
    neither ticket leg meets it; a NUL in summary or event_time is ordinary data on both legs.

    PR-09: a lone surrogate (here in the mapped summary, `rule.description`) is valid JSON that
    no strict UTF-8 sink can write. Both ticket legs are on (`--update-ticket`) through the real
    ticket writer at its request seam. The NUL arm: summary and event_time carrying a NUL escape
    are admitted and reach the open leg's payload as they are, and the record leg still posts."""
    planted = S.plant_tenant()
    refused_store = S.TicketStore()
    d = _drive(tmp_path, planted, fixture_uuid("p086-surrogate"), alert=S.admission_bytes("lone_surrogate"),
               tickets=S.ticket_writer(refused_store), update_ticket=True)
    _assert_refused_before_any_folder(d, "lone surrogate in the mapped summary")
    assert refused_store.calls == [], f"a ticket leg met the refused alert: {refused_store.calls}"

    store = S.TicketStore()
    summary, event_time = "before\x00after", f"{EVENT_TIME}\x00"
    nul = _drive(tmp_path, planted, fixture_uuid("p086-nul"),
                 alert=S.generic_alert(rule=_rule(description=summary), detected_at=event_time),
                 tickets=S.ticket_writer(store), update_ticket=True)
    run_dir = _assert_admitted(nul, "NUL in summary and event_time")
    opened = store.only_open()
    assert opened.get("summary") == summary, f"the open leg's summary is {opened.get('summary')!r}"
    assert f"evt:{event_time}" in opened.get("labels", []), (
        f"the open leg's event-time label is not the recorded event_time: {opened.get('labels')}")
    assert len(store.comments()) == 1, "the record leg did not post its comment"
    assert S.recorded(run_dir, "summary") == summary
    assert S.recorded(run_dir, "event_time") == event_time


def test_p087_mapped_value_has_an_unpaired_surrogate_escape_in(tmp_path):
    """An alert holding an unpaired surrogate escape is refused at admission, so neither the
    judge's enqueue nor the lesson author meets it; the judge's pass and the curator's drain
    neither hang nor corrupt the queue.

    Refused before any run folder, nothing exists to launch, judge or author from, and the
    learning enqueue is never reached: the curation queue stays empty. Positive control: a PAIRED
    surrogate escape (one astral character) is admitted, and production's learning enqueue files
    its request."""
    planted = S.plant_tenant()
    enqueue = _learning_enqueue(_held_out_fixtures(tmp_path))
    d = _drive(tmp_path, planted, fixture_uuid("p087-surrogate"), alert=S.admission_bytes("lone_surrogate"),
               enqueue=enqueue)
    _assert_refused_before_any_folder(d, "lone surrogate")
    assert d.enqueued == [], "the learning enqueue was reached for a refused alert"
    assert _curation_requests() == {}, "a refused alert left a request on the learning queue"

    paired = (b'{"rule": {"id": "R-1001", "description": "x\\ud83d\\ude00y"}, '
              b'"detected_at": "2026-09-30T08:15:00Z"}')
    control = _drive(tmp_path, planted, fixture_uuid("p087-paired"), alert=paired, enqueue=enqueue)
    run_dir = _assert_admitted(control, "a paired surrogate escape")
    assert control.enqueued, "the learning enqueue was never reached"
    assert _request_key_for(run_dir) is not None, "the admitted run filed no curation request"
    assert S.recorded(run_dir, "summary") == "x\U0001F600y"


def test_p138_refused_alert_leaves_a_run_folder_without_a_reco(tmp_path):
    """Admission runs before any run folder is created, so a refused alert leaves nothing under
    the runs base; no box and no lead start, and a refused start is never counted as a trial.

    PA-01: at base the folder is made before the alert is read, so a malformed alert leaves one
    behind. Observed after the refused start: the runs base's listing is unchanged, the invlang
    corpus scans only the earlier finished run, and the judge's sibling union of that alert lists
    only it."""
    planted = S.plant_tenant()
    source = S.alert_bytes(S.generic_alert())
    finished = _drive(tmp_path, planted, fixture_uuid("p138-finished"), alert=source, main=S.closing_main_turns())
    _assert_admitted(finished, "the earlier finished run")
    before = finished.runs_base_entries()

    d = _drive(tmp_path, planted, fixture_uuid("p138-refused"), alert=S.admission_bytes("not_json"))
    assert _named_refusal(d), (
        f"a non-JSON alert was not refused at run start (rc={d.rc!r}, raised={d.raised!r})")
    assert d.lifecycle_calls == [], "a box started for a refused alert"
    assert d.main.requests == 0, "MAIN was asked for a turn on a refused alert"
    assert d.router.leads() == [], "a lead was dispatched for a refused alert"
    assert d.runs_base_entries() == before, (
        f"the refused start changed the runs base: {sorted(set(d.runs_base_entries()) - set(before))}")

    signatures, report = _corpus_signatures(planted.runs)
    assert set(signatures) == {fixture_uuid("p138-finished")}, (
        f"the corpus counted something besides the finished run: {signatures}")
    assert report.scanned == 1, f"the corpus scanned {report.scanned} past runs, not one"
    shown = _union_shown(tmp_path, source, planted.runs, "p138")
    assert fixture_uuid("p138-finished") not in shown, "the union lost the finished trial of this alert"
    assert fixture_uuid("p138-refused") not in shown, "a refused start was shown to the judge as a trial"


def test_p139_record_cannot_be_written_at_run_start(tmp_path):
    """A record that cannot be written stops run start loudly, naming the fault. No box and no
    lead start.

    The fault is a real file-system state: a re-driven folder holding only the input directory,
    with a directory squatting the record's name. Positive control: the same folder shape with
    the name free starts the run and writes the record there."""
    planted = S.plant_tenant()
    squatted = planted.runs / fixture_uuid("p139-squatted")
    squatter = S.record_file(squatted)
    squatter.mkdir(parents=True)
    (squatter / "occupant.txt").write_text("not a record", encoding="utf-8")

    d = _drive(tmp_path, planted, fixture_uuid("p139-squatted"))
    message = d.refusal if isinstance(d.refusal, str) else (str(d.raised) if d.raised else "")
    assert d.rc not in (0, None) or d.raised is not None, (
        f"run start went on although its record could not be written (rc={d.rc!r})")
    assert message, "run start stopped without naming why"
    assert squatter.name in message, f"the stop does not name the record's fault: {message!r}"
    assert d.lifecycle_calls == [], "the box started although the record could not be written"
    assert d.main.requests == 0, "MAIN started although the record could not be written"
    assert d.router.leads() == [], "a lead started although the record could not be written"
    assert (squatter / "occupant.txt").is_file(), "the squatter was removed"

    free = planted.runs / fixture_uuid("p139-free")
    S.input_dir(free).mkdir(parents=True)
    control = _drive(tmp_path, planted, fixture_uuid("p139-free"))
    run_dir = _assert_admitted(control, "the same folder with the record's name free")
    assert control.lifecycle_calls, "the run never started"
    assert S.recorded_digest(run_dir) == S.sha256_hex(_admitted_bytes(control))


# =================================================================================================
# A1 — the record, written once beside the alert
# =================================================================================================

def test_facts_are_recorded_beside_the_alert_at_run_start(tmp_path):
    """After run start the run's record holds the alert's byte digest and the derived signature,
    event_time and summary (a fact absent when unmapped or not a key, with the note an unmapped
    one gets); alert.json holds exactly the admitted bytes; neither is rewritten for the rest of
    the run, by a restart or by a sibling resume.

    Observed at run start — in `before=`, after setup and before the driver — and again after
    the run: the record sits beside the alert in the run's input directory, holds the mapped
    signature and event_time and no summary (the mapping leaves `summary` unmapped although the
    alert carries a description), and neither file's bytes, inode or mtime moved during the run.
    A restart is p118's subject and a sibling resume's seeding is p152's (S08)."""
    planted = S.plant_tenant(alert_mapping={"signature": "rule.id", "event_time": "detected_at"})
    at_start: dict[str, Tree] = {}

    def at_run_start(run_dir: Path) -> None:
        at_start["tree"] = _tree(run_dir)

    d = _drive(tmp_path, planted, fixture_uuid("facts-1"), before=at_run_start)
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
    """The tenant's alert mapping (settings/alert-mapping.yaml) is read once, at run start,
    through the one tenant check; the facts it derives are recorded then, and no later reader
    reads the mapping.

    The mapping keys the signature on `host.hostname` (app-7) when the run starts and is
    rewritten to `rule.id` (R-1001) in `before=` — after setup, before the driver. Every reader
    after that point still carries app-7: orientation's lessons and vocabulary lookups, the
    post-run ticket record leg, and the record; so does the ticket open leg."""
    planted = S.plant_tenant(
        alert_mapping={"signature": "host.hostname", "event_time": "detected_at",
                       "summary": "rule.description"},
        case_mapping=_case_mapping_naming_the_signature())
    edited: list[Path] = []

    def edit_after_run_start(run_dir: Path) -> None:
        S.remap(planted, S.DEFAULT_MAPPING_GENERIC)
        edited.append(Path(run_dir))

    shim, store = _failed_shims(), S.TicketStore()
    d = _drive(tmp_path, planted, fixture_uuid("once-1"), before=edit_after_run_start, orient_shim=shim,
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


def test_p060_mapping_file_edited_between_acceptance_and_the_r(tmp_path):
    """The run holds the version read at run start, and every reader sees that version.

    The tenant is accepted with `signature: rule.id`, then the operator saves `signature:
    rule.uuid` before the run. The run holds U-9 — the version present when it started — in its
    record, in orientation's lookups, in both ticket legs; R-1001 (the accepted version's value)
    reaches none of them."""
    planted = S.plant_tenant(case_mapping=_case_mapping_naming_the_signature())
    planted.accept()
    S.remap(planted, {**S.DEFAULT_MAPPING_GENERIC, "signature": "rule.uuid"})

    shim, store = _failed_shims(), S.TicketStore()
    d = _drive(tmp_path, planted, fixture_uuid("p060-1"), alert=_alert(uuid="U-9"), orient_shim=shim,
               tickets=S.ticket_writer(store), update_ticket=True, main=S.closing_main_turns())
    run_dir = _assert_admitted(d, "an ordinary alert")
    assert _handed_signatures(shim) == ["U-9"], (
        f"orientation did not see the run-start mapping's signature: {shim.argvs()}")
    assert not _argv_mentions(shim, "R-1001"), f"orientation used another version: {shim.argvs()}"
    assert "sig:U-9" in store.only_open().get("labels", []), store.only_open()
    comments = store.comments()
    assert len(comments) == 1, f"the post-run record leg posted {len(comments)} comments"
    assert "[sig=U-9]" in comments[0].get("body", ""), comments
    assert "R-1001" not in _ticket_text(store), "a ticket leg used the accepted version's value"
    assert S.recorded(run_dir, "signature") == "U-9"


def test_p141_record_for_a_value_the_signature_rule_refuses(tmp_path):
    """When the key rule refuses a mapped value, the record holds no signature, with the same
    note as for an unmapped path. The refused value reaches no sink, the record included.

    Signature mapped to `rule.id` throughout. The refused values: "R 1001" (whitespace) and a
    129-character key-shaped value (over the bound; its 128-character prefix must not reach a
    sink either). The unmapped arm: an alert with no `rule.id`, driven twice over different hosts
    so a key that varies per run is told apart from the note. Sinks observed: the record,
    orientation's lookups, MAIN's opening message outside the alert's own frame, both ticket
    legs. Positive control: a key-shaped value reaches each of those sinks."""
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
        d = _drive(tmp_path, planted, fixture_uuid(f"p141-{arm}"), alert=alert, orient_shim=shim,
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


def test_p118_run_restarted_in_the_same_run_directory_after_th(tmp_path):
    """A restart never rewrites the alert or the record. A restart whose input alert differs from
    what the folder holds is refused, naming the difference.

    Three interrupted runs (stopped after setup, before the box; PR-28: such a folder is
    resumed). (a) restarted with the same input: it resumes, and the alert and record keep their
    bytes, inode and mtime. (b) restarted with a different input: refused, neither rewritten.
    (c) the folder's stored alert was rewritten on the host, then restarted with the original
    input: refused, and the alert and record are left exactly as found."""
    planted = S.plant_tenant()
    original, other = _alert(), _alert(id="R-5005")

    same = _stopped_after_setup(tmp_path, planted, fixture_uuid("p118-same"), original)
    held = _tree(same)
    resumed = _drive(tmp_path, planted, fixture_uuid("p118-same"), alert=original)
    _assert_admitted(resumed, "a restart with the same input")
    assert resumed.lifecycle_calls, "the restart did not resume the interrupted run"
    assert _snapshot(S.alert_file(same)) == _held(held, same, S.alert_file(same)), (
        "the restart rewrote the alert")
    assert _snapshot(S.record_file(same)) == _held(held, same, S.record_file(same)), (
        "the restart rewrote the record")

    differs = _stopped_after_setup(tmp_path, planted, fixture_uuid("p118-differs"), original)
    held = _tree(differs)
    d = _drive(tmp_path, planted, fixture_uuid("p118-differs"), alert=other)
    assert _named_refusal(d), (
        f"a restart with a different input was not refused (rc={d.rc!r}, raised={d.raised!r})")
    assert d.lifecycle_calls == [], "the refused restart started the run"
    assert _snapshot(S.alert_file(differs)) == _held(held, differs, S.alert_file(differs)), (
        "the refused restart rewrote the alert")
    assert _snapshot(S.record_file(differs)) == _held(held, differs, S.record_file(differs)), (
        "the refused restart rewrote the record")

    altered = _stopped_after_setup(tmp_path, planted, fixture_uuid("p118-altered"), original)
    _host_rewrite(S.alert_file(altered), S.alert_bytes(other))
    held = _tree(altered)
    d = _drive(tmp_path, planted, fixture_uuid("p118-altered"), alert=original)
    assert _named_refusal(d), (
        "a restart over a folder whose stored alert differs from the input was not refused "
        f"(rc={d.rc!r}, raised={d.raised!r})")
    assert d.lifecycle_calls == [], "the refused restart started the run"
    assert _snapshot(S.alert_file(altered)) == _held(held, altered, S.alert_file(altered)), (
        "the refused restart rewrote the alert")
    assert _snapshot(S.record_file(altered)) == _held(held, altered, S.record_file(altered)), (
        "the refused restart rewrote the record")


def test_p140_setup_only_folder_redriven_after_a_mapping_edit(tmp_path):
    """A re-driven setup-only folder keeps the record it finds, as the alert is kept, and a
    folder holding the new read-only directory is still recognised as setup-only.

    The run is stopped after setup (its folder holds the input directory with the alert and the
    record), the operator re-keys the signature on `rule.alt`, and the same run id is driven
    again. PA-02: at base any name outside setup's set flips the folder to "ran" and the re-drive
    is refused. The re-drive must resume, keep the first record byte for byte, and run on the
    first record's signature (R-1001), never the re-derived one (ALT-7)."""
    planted = S.plant_tenant()
    alert = _alert(alt="ALT-7")
    run_dir = _stopped_after_setup(tmp_path, planted, fixture_uuid("p140"), alert)
    held = _tree(run_dir)

    S.remap(planted, {**S.DEFAULT_MAPPING_GENERIC, "signature": "rule.alt"})
    shim = _failed_shims()
    again = _drive(tmp_path, planted, fixture_uuid("p140"), alert=alert, orient_shim=shim)
    _assert_admitted(again, "the re-driven setup-only folder")
    assert again.lifecycle_calls, "the setup-only folder was not resumed"
    assert _handed_signatures(shim) == ["R-1001"], (
        f"the re-driven run did not run on its first record's signature: {shim.argvs()}")
    assert not _argv_mentions(shim, "ALT-7"), (
        f"the re-driven run re-derived its signature from the edited mapping: {shim.argvs()}")
    assert _snapshot(S.alert_file(run_dir)) == _held(held, run_dir, S.alert_file(run_dir)), (
        "the re-drive rewrote the alert")
    assert _snapshot(S.record_file(run_dir)) == _held(held, run_dir, S.record_file(run_dir)), (
        "the re-drive rewrote the record")
    assert S.recorded(run_dir, "signature") == "R-1001"


# =================================================================================================
# A8 / C47 — the recorded digest is the alert's one identity
# =================================================================================================

def test_a8_every_identity_check_reads_the_recorded_digest(tmp_path):
    """The held-out check, the curation key, the launch byte check and the sibling union all take
    the alert's identity from the record's digest; changing or removing the operator's input file
    after admission changes none of them.

    PA-03: at base the held-out check and the curation key re-read the OPERATOR'S INPUT FILE
    after the run, so a changed input moves both and a removed one loses the request. Driven with
    production's learning enqueue over a planted held-out set holding alert H:
    * held-out check — a run of H whose input is rewritten to an ordinary alert mid-run files no
      request; a run of an ordinary alert O whose input is rewritten to H's bytes still files one;
    * curation key — runs of O with the input untouched, removed, or rewritten all file under
      ONE key;
    * launch byte check — a launch from the run whose input was removed copies O and its record;
      a launch from a run whose stored alert no longer matches its recorded digest is refused;
    * sibling union — the judge's union for an episode of O lists every run of O, the one whose
      stored alert was rewritten on the host included, and not the run of H."""
    planted = S.plant_tenant()
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

    def run(run_id: str, alert: bytes, change: Callable[[Path], None] | None = None) -> Path:
        d = _drive(tmp_path, planted, run_id, alert=alert, enqueue=enqueue, before=change,
                   main=S.closing_main_turns())
        run_dir = _assert_admitted(d, run_id)
        assert d.enqueued, f"{run_id}: the learning enqueue was never reached"
        return run_dir

    assert _request_key_for(run(fixture_uuid("dig-held-out"), held_out, input_becomes(ordinary))) is None, (
        "a run of a held-out alert filed a curation request once its input file changed")

    keys = {}
    for run_id, change in ((fixture_uuid("dig-untouched"), None), (fixture_uuid("dig-removed"), input_becomes(None)),
                           (fixture_uuid("dig-rewritten"), input_becomes(held_out))):
        keys[run_id] = _request_key_for(run(run_id, ordinary, change))
    assert keys[fixture_uuid("dig-untouched")] is not None, f"an ordinary run filed no curation request: {keys}"
    assert len(set(keys.values())) == 1, (
        f"the curation key follows the operator's input file, not the recorded digest: {keys}")

    episode, refusal = _launch(planted, planted.runs / fixture_uuid("dig-removed"), "dig-launch")
    assert refusal is None, f"the launch was refused: {refusal}"
    assert episode is not None
    assert S.episode_alert_file(episode).read_bytes() == ordinary
    assert json.loads(S.episode_record_file(episode).read_text(encoding="utf-8")).get(
        S.COINED["record.digest"]) == S.sha256_hex(ordinary)

    rewritten = planted.runs / fixture_uuid("dig-untouched")
    _host_rewrite(S.alert_file(rewritten), S.alert_bytes(_alert(id="R-9999")))
    episode, refusal = _launch(planted, rewritten, "dig-mismatch")
    assert episode is None, "a launch copied an alert whose bytes no longer match the record"
    assert refusal, "the launch stopped without naming why"

    shown = _union_shown(tmp_path, ordinary, planted.runs, "dig")
    for run_id in (fixture_uuid("dig-untouched"), fixture_uuid("dig-removed"), fixture_uuid("dig-rewritten")):
        assert run_id not in shown, f"the judge's union did not list {run_id}, a trial of this alert"
    assert fixture_uuid("dig-held-out") not in shown, "the union listed a run of another alert"


def test_p145_input_file_changes_during_the_run_and_post_run_s(tmp_path):
    """The held-out check and the curation key use the recorded digest; an input file changed or
    removed while the run is in progress changes neither.

    PA-03 (executed at base): both re-read the operator's input file post-run. Production's
    learning enqueue over a planted held-out set holding alert H, with the input file changed or
    removed in `before=` (after admission, before the driver): runs of H file no request either
    way; runs of an ordinary alert O file one request each, all under the key of an untouched run
    of O — including the run whose input became H's bytes."""
    planted = S.plant_tenant()
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
    for run_id, alert, change in (
            (fixture_uuid("p145-held-changed"), held_out, change_to(ordinary)),
            (fixture_uuid("p145-held-removed"), held_out, change_to(None)),
            (fixture_uuid("p145-plain"), ordinary, None),
            (fixture_uuid("p145-plain-changed"), ordinary, change_to(held_out)),
            (fixture_uuid("p145-plain-removed"), ordinary, change_to(None))):
        d = _drive(tmp_path, planted, run_id, alert=alert, enqueue=enqueue, before=change)
        run_dir = _assert_admitted(d, run_id)
        assert d.enqueued, f"{run_id}: the learning enqueue was never reached"
        outcomes[run_id] = _request_key_for(run_dir)

    for run_id in (fixture_uuid("p145-held-changed"), fixture_uuid("p145-held-removed")):
        assert outcomes[run_id] is None, (
            f"the held-out check followed the changed or removed input file: {outcomes}")
    plain = outcomes[fixture_uuid("p145-plain")]
    assert plain is not None, "an ordinary run filed no curation request"
    for run_id in (fixture_uuid("p145-plain-changed"), fixture_uuid("p145-plain-removed")):
        assert outcomes[run_id] == plain, f"the curation key moved with the input file: {outcomes}"


def test_p128_held_out_copies_of_the_alert_exist_under_the_run(tmp_path):
    """No special case for held-out copies. A run byte-identical to a held-out alert is itself
    held-out, and the learning gate already refuses that episode's learning.

    C47 / A8: the held-out check reads the recorded digest, so the copy is recognised by the
    bytes the run admitted even when the operator's input file is rewritten mid-run. Production's
    learning enqueue over a planted held-out set (PR-18: the check is a byte digest): the copy
    files no curation request, an ordinary run does. No special case in the union: the judge's
    union for an episode of that alert lists the held-out copy like any other trial."""
    planted = S.plant_tenant()
    held_out, ordinary = S.alert_bytes(_alert(id="H-3")), S.alert_bytes(_alert())
    enqueue = _learning_enqueue(_held_out_fixtures(tmp_path, held_out))
    entry = S.operator_input(tmp_path)

    def input_rewritten(_run_dir: Path) -> None:
        entry.write_bytes(ordinary)

    copy = _drive(tmp_path, planted, fixture_uuid("p128-copy"), alert=held_out, enqueue=enqueue,
                  before=input_rewritten, main=S.closing_main_turns())
    copy_dir = _assert_admitted(copy, "a run of a held-out alert")
    assert copy.enqueued, "the learning enqueue was never reached"
    assert _request_key_for(copy_dir) is None, "the held-out copy was handed to learning"

    plain = _drive(tmp_path, planted, fixture_uuid("p128-ordinary"), alert=ordinary, enqueue=enqueue,
                   main=S.closing_main_turns())
    assert _request_key_for(_assert_admitted(plain, "an ordinary run")) is not None, (
        "the gate refused an ordinary run")

    shown = _union_shown(tmp_path, held_out, planted.runs, "p128")
    assert fixture_uuid("p128-copy") not in shown, "the held-out copy was dropped from its alert's union"
    assert fixture_uuid("p128-ordinary") not in shown, "the union listed a run of another alert"


def test_p142_record_present_but_alert_file_gone_or_rewritten_(tmp_path):
    """Every reader of the record trusts it alone and never re-derives from the alert file; any
    host-side read of the alert's bytes, the launcher's included, checks them against the recorded
    digest and refuses a mismatch, naming it (a1_host_reads_recheck_the_recorded_digest).

    Three finished runs of one alert; after they end, one run's alert file is rewritten on the
    host to another alert (rule R-9999) and another's is removed, each record left as it was.
    The corpus takes every run's signature from its record (R-1001), the judge's union lists all
    three by their recorded digest, and a launch from the rewritten or the removed run is refused
    naming that run, while a launch from the intact run copies its alert and record."""
    planted = S.plant_tenant()
    source = S.alert_bytes(_alert())
    for run_id in (fixture_uuid("p142-rewritten"), fixture_uuid("p142-gone"), fixture_uuid("p142-intact")):
        _assert_admitted(_drive(tmp_path, planted, run_id, alert=source,
                                main=S.closing_main_turns()), run_id)
    _host_rewrite(S.alert_file(planted.runs / fixture_uuid("p142-rewritten")), S.alert_bytes(_alert(id="R-9999")))
    _host_rewrite(S.alert_file(planted.runs / fixture_uuid("p142-gone")), None)

    signatures, _report = _corpus_signatures(planted.runs)
    for run_id in (fixture_uuid("p142-rewritten"), fixture_uuid("p142-gone"), fixture_uuid("p142-intact")):
        assert signatures.get(run_id) == "R-1001", (
            f"the corpus did not take {run_id}'s signature from its record: {signatures}")

    shown = _union_shown(tmp_path, source, planted.runs, "p142")
    for run_id in (fixture_uuid("p142-rewritten"), fixture_uuid("p142-gone"), fixture_uuid("p142-intact")):
        assert run_id not in shown, f"the judge's union did not list {run_id} by its recorded digest"

    for run_id in (fixture_uuid("p142-rewritten"), fixture_uuid("p142-gone")):
        episode, refusal = _launch(planted, planted.runs / run_id, f"{run_id}-ep")
        assert episode is None, (
            f"a launch from {run_id} went ahead although its alert no longer matches its record")
        assert refusal is not None
        assert run_id in refusal, f"the launch refusal does not name the run: {refusal!r}"
    episode, refusal = _launch(planted, planted.runs / fixture_uuid("p142-intact"), "p142-intact-ep")
    assert refusal is None, f"the intact run's launch was refused: {refusal}"
    assert episode is not None
    assert S.episode_alert_file(episode).read_bytes() == source
    assert json.loads(S.episode_record_file(episode).read_text(encoding="utf-8")).get(
        S.COINED["record.digest"]) == S.sha256_hex(source)


# =================================================================================================
# R7 — the shared test builders make admissible alerts
# =================================================================================================

def test_r7_the_shared_test_alert_builders_make_alerts_the_front_door_admits(tmp_path):
    """Every alert the repo's shared test builders produce (alert_doc in
    tests/e2e/_lead_zero_808.py and the fixtures of its importers) is a UTF-8 JSON object the
    admission check accepts, and under each fixture tenant's alert mapping derives the signature,
    event_time and summary its tests expect (rule.id, the field the alert carries,
    rule.description). A builder that makes an alert admission refuses fails the suite at
    collection, never mid-replay as an unmapped alert.

    TS06: `alert_doc` has eleven importers. Each builder's alert goes through production's
    admission and the committed fixture and template tenants' own alert-mapping files (read off
    the tree, never restated); this suite's generic builders go through the generic mapping they
    are driven with. Expected in the record: rule.id as text for the signature, the alert's own
    time field for the event time, and rule.description for the summary where the alert carries
    one."""
    from defender.tests.e2e import _lead_zero_808 as LZ

    committed = {}
    for tenant in ("tenant-fixture", "tenant-template"):
        path = S.REPO_ROOT / "knowledge" / tenant / "settings" / S.ALERT_MAPPING_REL
        assert path.is_file(), f"the committed {tenant} ships no alert mapping at {path}"
        committed[tenant] = path.read_text(encoding="utf-8")

    cases: list[tuple[str, dict[str, Any], str, str]] = []
    for tenant, mapping in committed.items():
        cases.append((f"{tenant}-alert-doc", LZ.alert_doc(), mapping, "alert_timestamp"))
        cases += [(f"{tenant}-{slug}", S.fixture_alert(slug), mapping, "alert_timestamp")
                  for slug in S.FIXTURE_SLUGS]
    generic = S.alert_mapping_text(S.DEFAULT_MAPPING_GENERIC)
    cases += [("generic", S.generic_alert(), generic, "detected_at"),
              ("hostile", S.hostile_alert(), generic, "detected_at")]

    planted = S.plant_tenant()
    for name, doc, mapping, time_field in cases:
        planted.alert_mapping.write_text(mapping, encoding="utf-8")
        d = _drive(tmp_path, planted, fixture_uuid(f"r7-{name}"), alert=doc)
        run_dir = _assert_admitted(d, name)
        rule = doc["rule"]
        assert S.recorded(run_dir, "signature") == str(rule["id"]), (
            f"{name}: the recorded signature is not rule.id")
        assert S.recorded(run_dir, "event_time") == str(doc[time_field]), (
            f"{name}: the recorded event_time is not the alert's {time_field}")
        assert S.recorded(run_dir, "summary") == rule.get("description"), (
            f"{name}: the recorded summary is not rule.description")
