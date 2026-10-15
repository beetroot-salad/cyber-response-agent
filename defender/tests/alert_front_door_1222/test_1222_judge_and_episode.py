"""#1222 S11 — the judge and the episode: launch copies the alert and its record into the episode,
the judge reads only that copy, and a folder without a record is not a run.

Spec: `spec-flow/specs/spec_graph_1222.yaml` (demands named below by their `discharged_by`);
design `.spec-flow/design.md` as amended by `.spec-flow/design-amendments.md` (A1, A8, C27, C41,
C47 win). Shared machinery: `_spec1222` (as `S`), `_judge_921` (as `J`), `_triplet_947` (as `T`).

DRIVE POINTS (every one a production entry point, every fake through its own seam)
* The judge: `learning.judge.grade_episode` over an episode `J.accepted_episode` built, with the
  launch's copies planted by `S.plant_episode_copy`; the model is `J.FakeJudge`, which RECORDS
  every prompt it is handed — the union notes are read off what the judge model received.
* The bare re-enqueue: `learning.judge.enqueue.enqueue_report` with no draws handed over (it reads
  the draws on disk, as a later process holding only the episode dir does).
* The launcher's copy step: `learning.branch.cli.prepare_episode` over a source run `T.runs_base`
  stamped and `S.plant_run` gave its alert and record.
* A sibling's setup: `run.main --resume` with a lifecycle that records the run folder the real
  `materialize` built (no investigation is driven).
* The archive (`learning.branch.archive.archive_episode`), the episode page
  (`scripts.visualize.visualize_episode.render_episode`), the invlang corpus
  (`skills.invlang.corpus.load_corpus` and its CLI), the ticket writer's record leg.

THE DECOYS. `J.accepted_episode` archives every world with a Kibana-shaped `alert.json` carrying
`alert_id` / `rule.id` = `J.ALERT_ID`. Base's judge picks the episode's alert among those world
copies and keys findings on `rule.id` (`rule-v2-cross-tier-ssh-pivot`); the design's judge takes
the alert and the signature from the episode's own copy. Every episode copy here is a generic
alert whose `rule.id` is NOT its recorded signature, so a vendor-field fallback shows too.

RED AT BASE, and why. The episode copy (`EpisodePaths.source_alert/.source_record`) and a run's
record (`RunPaths.alert_record`) are coined (`S.COINED`): a test that must plant either fails at
its setup at base on the coined accessor — there is no behavioural observation to put first.
Where setup needs no coined name (a recordless folder; an episode with no copy) the behavioural
assertion comes first and base fails on it: the launcher launches a recordless source, the judge
grades an episode with no record, the walkers neither name nor count a recordless folder. The
per-test table is in `.spec-flow/frontiers/82-writer-judge_and_episode.md`.
"""
from __future__ import annotations

from defender.tests._spec1077 import fixture_run as _run_handle_1165

from defender.run_repository import Run

import json
import os
import re
import threading
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from defender import _yaml
from defender.learning.core.state import FINDINGS
from defender.tests import _judge_921 as J
from defender.tests import _triplet_947 as T
from defender.tests._fixture_uuid import fixture_uuid
from defender.tests._state1135 import env_state
from defender.tests.alert_front_door_1222 import _spec1222 as S

JUDGE = "learning.judge"
ENQUEUE = "learning.judge.enqueue"
CLI = "learning.branch.cli"
ARCHIVE = "learning.branch.archive"
EPISODE_HANDLE = "_episode_handle"
VISUALIZE = "scripts.visualize.visualize_episode"
CORPUS = "skills.invlang.corpus"
INVLANG_CLI = "skills.invlang.cli"
RUN = "run"

#: The judge prompt's union views, by the title each framed section opens with
#: (`learning/judge/run.SECTION_TITLES`).
SIBLINGS = "VIEW 4 — SIBLING TRIALS"
SPREAD = "TRIAL SPREAD"
#: The tenant every launcher scenario plants (`S.plant_tenant`'s default id).
TENANT = "acme"
#: How long a pass may take before "does not hang" fails. A real pass here takes well under a
#: second; a blocked read never returns.
HANG_BOUND_S = 60.0

_TRIAL_LINE = re.compile(r"(?m)^- (.+?): disposition=")
_FORGED_HEADING = re.compile(r"(?m)^\s{0,3}#{1,6}\s*Forged")
_FENCE_OPENER = re.compile(r"(?m)^\s{0,3}```")


# =================================================================================================
# Builders
# =================================================================================================

def _alert(tag: str, **over: Any) -> bytes:
    """A generic (non-Kibana) alert unique per `tag`: no `alert_id`, a `rule.id` that is a valid
    signature but never the one the record carries (`R-VENDOR-<tag>`), and the signature the
    record does carry under its own field (`sig_field`), as an older mapping derived it."""
    return S.alert_bytes(S.generic_alert(rule_id=f"R-VENDOR-{tag}", sig_field=f"SIG-{tag}",
                                         case_tag=tag, **over))


def _episode(tmp_path: Path, name: str, *, raw: bytes | None = None,
             signature: str | None = "", copy: bool = True,
             record: bool | dict[str, Any] = True, **world_kw: Any) -> tuple[Path, bytes]:
    """An accepted, archived episode (`J.accepted_episode`, world copies = the decoys) at
    `<data root>/<T>/episodes/<uuid>` (#1187 Layout A: the only place a door reaches it by id),
    with the launch's copies of `raw` (default `_alert(name)`) and a record carrying `signature`
    (default `SIG-<name>`; None = no signature recorded). `copy=False` plants nothing: the
    episode a pre-change launcher left."""
    ep = J.accepted_episode(tmp_path, **world_kw)
    # Distinct scenarios share a queue, so their episode identities must differ (#1241): each
    # its own uuid (#1187 dc3), and the manifest names that id (R5: every manifest reader
    # refuses a manifest whose `episode_id` is not its folder's name — a mismatch here would be
    # refused for THAT, and a test about the record would pass on the wrong refusal).
    episode_id = fixture_uuid(f"1222-episode-{name}")
    ep = ep.rename(ep.with_name(episode_id))
    doc = _yaml.safe_load((ep / "family.yaml").read_text(encoding="utf-8"))
    T.write_family(ep, {**doc, "episode_id": episode_id})
    alert = _alert(name) if raw is None else raw
    if copy:
        sig = f"SIG-{name}" if signature == "" else signature
        S.plant_episode_copy(ep, alert=alert, record=record,
                             facts={"signature": sig} if sig is not None else {})
    return ep, alert


def _manifest(ep: Path) -> dict[str, Any]:
    doc = _yaml.safe_load((ep / "family.yaml").read_text(encoding="utf-8"))
    assert isinstance(doc, dict)
    return doc


def _set_source_run_id(ep: Path, source_run_id: str) -> None:
    doc = _manifest(ep)
    doc["source_run_id"] = source_run_id
    T.write_family(ep, doc)


def _trial(base: Path, name: str, raw: bytes, *, report: bool = True,
           disposition: str = "benign", **kw: Any) -> Path:
    """A run under `base` holding `raw` and (default) its record — a finished trial of `raw`
    when `report`; `kw` reaches `S.plant_run` (`record=False`, `digest=`, `facts=`)."""
    files = {"report.md": T.report_text(disposition)} if report else {}
    return S.plant_run(base, name, alert=raw, files=files, **kw)


def _grade(ep: Path, base: Path, *, judge: J.FakeJudge | None = None) -> tuple[Any, J.FakeJudge]:
    fake = J.scripted_judge() if judge is None else judge
    grade = J.grade_at(ep, runs_base=base, judge=fake, state=env_state(),
                                       draws=1, git_show=J.FakeGitShow())
    return grade, fake


def _rows() -> list[dict[str, Any]]:
    """The defender queue's rows, read through the learning state's own reader (what the drain
    reads)."""
    return env_state().rows(FINDINGS)


def _keys(rows: list[dict[str, Any]]) -> list[Any]:
    assert rows, "the pass queued no finding row, so no rule key can be observed"
    return [r.get("alert_rule_key") for r in rows]


def _bounded(fn: Callable[[], Any], *, what: str) -> dict[str, Any]:
    """Run `fn` on a daemon thread; fail if it has not returned within `HANG_BOUND_S` (a hang).
    Returns `{"value": ...}` or `{"raised": exc}`."""
    box: dict[str, Any] = {}

    def run() -> None:
        try:
            box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 — handed back for the test to judge
            box["raised"] = exc

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(HANG_BOUND_S)
    assert not worker.is_alive(), f"{what} did not return within {HANG_BOUND_S}s — it hangs"
    return box


# --- what the judge model received -----------------------------------------------------------

def _world_prompts(judge: J.FakeJudge) -> list[str]:
    out = [p for p, a in zip(judge.prompts, judge.agent_ids, strict=True)
           if not str(a).startswith(J.FAMILY_AGENT_PREFIX)]
    assert out, f"the judge model was never called for a world (calls: {judge.agent_ids})"
    return out


def _view(prompt: str, title: str) -> str:
    hits = [b for b in S.framed_bodies(prompt) if b.lstrip("\n").startswith(f"## {title}")]
    assert len(hits) == 1, f"the judge prompt carries {len(hits)} framed '{title}' sections"
    return hits[0]


def _union_notes(judge: J.FakeJudge) -> str:
    """The sibling view and the spread the judge model received — one union per pass, so every
    world's prompt carries the same text (asserted)."""
    views = {_view(p, SIBLINGS) + _view(p, SPREAD) for p in _world_prompts(judge)}
    assert len(views) == 1, "two worlds of one pass were shown different sibling unions"
    return views.pop()


def _trials(judge: J.FakeJudge) -> set[str]:
    """J3: no prior trial or spread enters the judge's prompt."""
    prompts = _world_prompts(judge)
    assert all(SIBLINGS not in p and SPREAD not in p for p in prompts)
    return set()


def _lines_naming(text: str, stem: str) -> list[str]:
    return [line for line in text.splitlines() if stem in line]


def _assert_named_skip(judge: J.FakeJudge, name: str, *, reason: str | None = "record") -> None:
    """J3: neither prior trials nor skipped-folder notes enter the judge's view."""
    assert not _trials(judge)
    assert all(name not in prompt for prompt in _world_prompts(judge))


def _judge_refusal(ep: Path, base: Path) -> str:
    """Grade `ep` expecting a refusal: a raised `JudgeRefused` or a not-graded stamp. Returns its
    text. A refusal makes no model call and queues nothing; the pass does not hang."""
    judge = J.scripted_judge()
    rows_before = len(_rows())
    box = _bounded(lambda: _grade(ep, base, judge=judge), what="the judge pass")
    if "raised" in box:
        refused_cls = S.sym(JUDGE, "JudgeRefused")
        assert isinstance(box["raised"], refused_cls), (
            f"the judge pass failed with {box['raised']!r}, not the judge's refusal")
        text = str(box["raised"])
    else:
        stamp = J.judge_record(ep).get("not_graded") or {}
        assert stamp, ("the judge GRADED an episode whose copy holds no readable record "
                       f"(model calls: {judge.agent_ids})")
        text = f"{stamp.get('outcome')}: {stamp.get('reason')}"
    assert judge.calls == 0, f"a refused pass still called the judge model: {judge.agent_ids}"
    assert len(_rows()) == rows_before, "a refused pass queued finding rows"
    return text


def _assert_names_record(text: str, what: str) -> None:
    assert "record" in text.lower(), f"{what} does not name the missing record: {text!r}"
    # #1187 (R5): a manifest naming another episode is refused too, and its text may say
    # "record"; a refusal of the record is never that one.
    assert "episode_id" not in text, f"{what} is the manifest's id refusal, not the record's: {text!r}"


# --- a pass that predates the change ---------------------------------------------------------

def _old_pass_draws(ep: Path, label: str = "b") -> dict[str, Any]:
    """What a judge pass left on disk before the change: one draw document for world `label`
    (`run._draw_document`'s shape, one defender finding) and the grade naming it — the inputs a
    bare re-enqueue reads back."""
    finding = {**J.finding_doc(), "unresolved_evidence": []}
    doc = {"episode_outcome": "gradable", "bucket": "lead-set", "systems": [J.HOLDING_SYSTEM],
           "noise_floor_note": "one trial", "correlations": [], "scope_checks": [],
           "derivations": [], "findings": [finding], "dropped_findings": 0}
    draws = ep / "worlds" / label / "judge"
    draws.mkdir(parents=True, exist_ok=True)
    (draws / "0.yaml").write_text(_yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")
    return {"verdict_word": "survived",
            "worlds": [{"world": label, "completed_draws": 1, "bucket": "lead-set",
                        "systems": [J.HOLDING_SYSTEM]}]}




# --- the launcher ----------------------------------------------------------------------------

def _source(tmp_path: Path, raw: bytes, *, record: bool = True, digest: str | None = None,
            signature: str | None = None, alert_mapping: Any = S.DEFAULT_MAPPING_GENERIC,
            case_mapping: str | None = None) -> tuple[S.Planted, Path, Path]:
    """A finished source run on tenant `TENANT`: `T.runs_base`'s stamped, branchable run (its
    capture, session and runs-base record), its alert replaced by `raw` at the run's alert
    place and (default) its record beside it. Returns (tenant, runs base, source run)."""
    planted = S.plant_tenant(TENANT, alert_mapping=alert_mapping, case_mapping=case_mapping)
    base, src = T.runs_base(tmp_path, tenant_id=TENANT)
    former = src / "alert.json"
    if former != S.alert_file(src):
        former.unlink()
    S.plant_run(base, src.name, alert=raw, record=record, digest=digest,
                facts={"signature": signature} if signature is not None else {})
    return planted, base, src


def _launch(planted: S.Planted, src: Path, episode_id: str = T.EPISODE_ID) -> Path:
    """`prepare_episode` over `src` (the real primer), then the launcher's RUNS step for the
    manifest's worlds (#1187 R2: `view.start_runs` makes `runs/` and writes the arm roster — it
    replaces `create_container`), the episode handle released."""
    cli = S.mod(CLI)
    with cli.prepare_episode(episode_id, Run.at(src), data_root=planted.accept().data_root) as episode:
        with planted.accept().runs_repository().episode(episode.dir.name, held=episode) as view:
            view.start_runs(list(T.WORLDS))
        return Path(episode.dir)


def _refused_launch(planted: S.Planted, src: Path) -> str:
    with pytest.raises(J.refusals()) as refused:
        _launch(planted, src)
    return str(refused.value)


def _files_under(root: Path) -> dict[str, bytes]:
    if not root.is_dir():
        return {}
    return {str(p.relative_to(root)): p.read_bytes() for p in sorted(root.rglob("*"))
            if p.is_file() and not p.is_symlink()}


def _episode_files() -> dict[str, bytes]:
    """Every file in every episode of every tenant: `<data root>/*/episodes/` (#1187 Layout A,
    where a launch puts its episode and its copies; O9: no configured root). The census a
    refused launch leaves without the source's bytes — and `test_a1`'s accepted launch does not
    (its positive control)."""
    root = Path(os.environ["DEFENDER_DATA_ROOT"])
    found: dict[str, bytes] = {}
    for episodes in sorted(root.glob("*/episodes")):
        found.update({f"{episodes.parent.name}/{k}": v for k, v in _files_under(episodes).items()})
    return found


class _Lifecycle:
    """`run.main`'s lifecycle seam as a recorder: the run folder the real `materialize` built,
    a closed report written into it, no investigation driven."""

    def __init__(self) -> None:
        self.run_dir: Path | None = None

    def __call__(self, **kw: Any) -> dict[str, Any]:
        self.run_dir = Path(kw["run"].run_dir)
        (self.run_dir / "report.md").write_text(T.report_text("benign"), encoding="utf-8")
        return {"output": "done", "requests": 1, "truncated_by": None}


def _resume_sibling(ep: Path, label: str = "b") -> Path:
    """World `label`'s sibling through the REAL `run.main --resume`; returns its run folder."""
    life = _Lifecycle()
    # #1187 (O9): the episode is found under `--tenant`'s own `<T>/episodes/`; no variable.
    return _resume_sibling_at(ep, label, life)


def _resume_sibling_at(ep: Path, label: str, life: _Lifecycle) -> Path:
    rc = S.sym(RUN, "main")(
        ["--episode", ep.name, "--world", label, "--tenant", TENANT, "--no-learn"],
        lifecycle=life, visualize=lambda *_a, **_k: None, preflight=lambda *_a, **_k: 0,
        ticket_writer=S.NoTicket())
    assert life.run_dir is not None, f"the sibling never reached its run (rc={rc!r})"
    return life.run_dir


# =================================================================================================
# O11 — the judge's alert is the episode's copy
# =================================================================================================

def test_o11_episode_alert_is_the_episodes_copy(tmp_path):
    """The judge takes the episode's alert and recorded signature from the copies branch launch
    put in the episode, never from a world's copy, a vendor field, the tenant's mapping or the
    source run folder.

    The tenant's mapping would derive another value, the source run folder holds another alert
    and record, and every world copy is the decoy: the findings key is the copy's recorded
    signature, and the union is the runs whose recorded digest is the copy's."""
    planted = S.plant_tenant(TENANT, alert_mapping={"signature": "user.login",
                                                    "event_time": "detected_at",
                                                    "summary": "rule.description"})
    ep, raw = _episode(tmp_path, "o11", signature="SIG-COPY-O11")
    source = _alert("o11-source")
    _trial(planted.runs, T.SOURCE_RUN_ID, source, facts={"signature": "SIG-SOURCE-O11"})
    _trial(planted.runs, "trial-copy", raw, facts={"signature": "SIG-COPY-O11"})
    decoy = (ep / "worlds" / "b" / "alert.json").read_bytes()
    _trial(planted.runs, "trial-decoy", decoy, facts={"signature": "SIG-DECOY-O11"})

    _grade_, judge = _grade(ep, planted.runs)

    keys = set(_keys(_rows()))
    assert keys == {"SIG-COPY-O11"}, (
        f"the findings key is {keys}: not the copy's recorded signature (a world copy, the "
        "vendor rule.id, the tenant's mapping or the source run folder keyed them)")
    assert not _trials(judge), "J3: same-alert priors must stay outside the judge prompt"


def test_o11_episode_without_a_record_is_refused_by_name(tmp_path):
    """The judge, and a bare re-enqueue, refuse an episode whose copy holds no readable record,
    naming the missing record, and do not hang.

    Arms: no copy at all; the alert copied and no record; a torn record; a directory at the
    record's name. Positive control: the same episode with its record grades and queues."""
    base = tmp_path / "runs"
    base.mkdir()
    bare, _raw = _episode(tmp_path, "nocopy", copy=False)
    _assert_names_record(_judge_refusal(bare, base), "the judge's refusal of an uncopied episode")

    good, _raw = _episode(tmp_path, "good")
    _grade(good, base)
    assert set(_keys(_rows())) == {"SIG-good"}, "positive control: the recorded episode graded"
    S.episode_record_file(good).unlink()
    box = _bounded(lambda: _grade(good, base), what="the bare re-enqueue")
    assert "raised" in box, "the bare re-enqueue queued an episode whose record is gone"
    assert isinstance(box["raised"], J.refusals()), f"not a refusal: {box['raised']!r}"
    _assert_names_record(str(box["raised"]), "the bare re-enqueue's refusal")

    no_record, _raw = _episode(tmp_path, "norecord", record=False)
    _assert_names_record(_judge_refusal(no_record, base), "the refusal of a recordless copy")

    torn, _raw = _episode(tmp_path, "torn")
    S.episode_record_file(torn).write_bytes(b'{"digest": "ab')
    _assert_names_record(_judge_refusal(torn, base), "the refusal of a torn record")

    dirlike, _raw = _episode(tmp_path, "dir")
    rec = S.episode_record_file(dirlike)
    rec.unlink()
    rec.mkdir()
    _assert_names_record(_judge_refusal(dirlike, base), "the refusal of a directory record")


# =================================================================================================
# A1 — the launch copies the alert and its record
# =================================================================================================

def test_a1_launch_copies_the_alert_and_record_into_the_episode(tmp_path):
    """Branch launch copies the source run's alert and record into the episode after checking
    the bytes against the recorded digest, refusing a mismatch by name; each sibling's input
    directory is placed at its setup from the episode's copy, and the episode archive keeps both
    files.

    The source's alert is rewritten after the launch: the sibling still starts from the copy."""
    raw = _alert("a1")
    planted, _base, src = _source(tmp_path, raw, signature="SIG-a1")
    record_bytes = S.record_file(src).read_bytes()

    ep = _launch(planted, src)
    assert raw in _episode_files().values(), (
        "the census p156/p157 take never saw the accepted launch's copy (#1187: <T>/episodes)")
    assert S.episode_alert_file(ep).is_file(), "the launch put no copy of the alert in the episode"
    assert S.episode_record_file(ep).is_file(), "the launch put no copy of the record in the episode"
    assert S.episode_alert_file(ep).read_bytes() == raw, "the episode's alert is not the source's"
    assert S.episode_record_file(ep).read_bytes() == record_bytes, (
        "the episode's record is not the source's")

    T.write_family(ep, T.family_doc(source_run_dir=str(src)))
    S.alert_file(src).write_bytes(_alert("a1-rewritten"))
    sib = _resume_sibling(ep)
    assert S.alert_file(sib).read_bytes() == raw, (
        "the sibling's alert is not the episode's copy (it was taken from the source run)")
    assert S.record_file(sib).read_bytes() == record_bytes, (
        "the sibling's record is not the episode's copy")

    archive = S.mod(ARCHIVE)
    with S.sym(EPISODE_HANDLE, "Episode").open(ep) as handle:
        archive.archive_episode(handle, {"b": sib})
    archived = set(_files_under(ep / "worlds" / "b").values())
    assert raw in archived, "the world archive does not keep the alert"
    assert record_bytes in archived, "the world archive does not keep the record"

    mismatched = _alert("a1-mismatch")
    S.alert_file(src).write_bytes(mismatched)
    message = _refused_launch(planted, src)
    assert any(w in message.lower() for w in ("digest", "mismatch", "differ", "disagree")), (
        f"the refusal does not name the mismatch: {message!r}")


# =================================================================================================
# A8 — a folder without a record is not a run
# =================================================================================================

def test_a8_a_folder_without_a_record_is_not_a_run(tmp_path, capsys):
    """A run folder with no readable record — a pre-change run, a crashed setup — is skipped by
    name and counted by every walker (the corpus, the sibling union) and refused, naming the
    missing record, by the launcher and the judge; the visualizer owes it nothing.

    The folder here is a crashed setup's: the alert at its place, an investigation, a report,
    no record."""
    raw = _alert("a8")
    planted, base, src = _source(tmp_path, raw, record=False)
    _assert_names_record(_refused_launch(planted, src), "the launcher's refusal")

    T.corpus_document(src)
    S.sym(INVLANG_CLI, "main")([str(base), "hypothesis-vocabulary", "--signature", "SIG-a8"])
    err = capsys.readouterr().err
    lines = _lines_naming(err, src.name)
    assert lines, f"the corpus listing does not name the recordless folder {src.name!r}:\n{err}"
    assert any("record" in line.lower() for line in lines), (
        f"the corpus listing names {src.name!r} with no reason naming its record: {lines}")

    uncopied, _raw = _episode(tmp_path, "a8-nocopy", copy=False)
    _assert_names_record(_judge_refusal(uncopied, base), "the judge's refusal")

    ep, _raw = _episode(tmp_path, "a8", raw=raw)
    _trial(base, "trial-a8", raw, facts={"signature": "SIG-a8"})
    _grade_, judge = _grade(ep, base)
    _assert_named_skip(judge, src.name)
    assert not _trials(judge), "J3: same-alert priors must stay outside the judge prompt"


def test_r6_a_skipped_runs_name_cannot_forge_a_line_in_the_judge_notes_or_the_vocabulary(
        tmp_path, capsys):
    """A run folder under the runs base with no readable record, whose name carries a newline, a
    terminal escape, a markdown heading or a fence ('x', newline, '## Forged'; ESC[2K; a 255-byte
    name), is skipped by name and counted: wherever the skip is named (the judge's union note,
    the corpus listing's skip line, orientation's vocabulary count) it is one inert line,
    escaped and bounded, and the count is exact; no note gains a second line, a forged section
    or a closed frame. The union notes the judge receives are recorded by the model fake.
    Positive control: a recordless folder with an ordinary name is named plainly and counted.

    Covered here: the judge's union note and the corpus listing (its CLI's skip lines)."""
    raw = _alert("r6")
    base = tmp_path / "runs"
    hostile = {
        "skip-nl": "skip-nl\n## Forged section",
        "skip-esc-": "skip-esc-\x1b[2K-tail",
        "skip-fence-": "skip-fence-```-tail",
        "skip-long-": "skip-long-" + "y" * 245,
    }
    plain = "skip-plain-norecord"
    assert len(hostile["skip-long-"].encode("utf-8")) == 255
    for name in [*hostile.values(), plain]:
        T.corpus_document(_trial(base, name, raw, record=False))
    recordless = len(hostile) + 1

    S.sym(INVLANG_CLI, "main")([str(base), "hypothesis-vocabulary", "--signature", "SIG-r6"])
    err = capsys.readouterr().err
    assert "\x1b" not in err, "a folder name's terminal escape reached the corpus listing raw"
    assert not _FORGED_HEADING.search(err), "a folder name forged a heading in the listing"
    assert not _FENCE_OPENER.search(err), "a folder name opened a fence in the listing"
    for stem in [*hostile, plain]:
        named = _lines_naming(err, stem)
        assert len(named) == 1, f"the corpus listing names {stem!r} on {len(named)} lines:\n{err}"
        assert "record" in named[0].lower(), f"the skip line gives no reason: {named[0]!r}"
    assert re.search(rf"(?<![\w.]){recordless}(?![\w.])", err), (
        f"the corpus listing does not count the {recordless} recordless folders:\n{err}")

    ep, _raw = _episode(tmp_path, "r6", raw=raw)
    T.corpus_document(_trial(base, "trial-r6", raw, facts={"signature": "SIG-r6"}))
    _grade_, judge = _grade(ep, base)
    control_ep, _raw = _episode(tmp_path, "r6-control", raw=raw)
    control_base = tmp_path / "runs-control"
    _trial(control_base, plain, raw, record=False)
    _grade_, control = _grade(control_ep, control_base)

    assert not _trials(judge)
    for prompt in _world_prompts(judge):
        assert all(stem not in prompt for stem in [*hostile, plain])


def test_p039_pre_change_run_presented_to_branch_judge_or_visu(tmp_path, capsys):
    """A run with no record — whatever made it — is skipped by name and counted by every walker;
    the launcher and the judge refuse it, naming the missing record; the visualizer owes nothing
    (display only, N8, N13).

    The run is a pre-change one: its alert at the former place, an `l-000` leads row, no
    record."""
    planted = S.plant_tenant(TENANT)
    base, src = T.runs_base(tmp_path, tenant_id=TENANT)
    (src / "gather_raw" / f"{S.L0}.lead.json").write_text(json.dumps(
        {"lead_id": S.L0, "goal": "Alert ancestors: resolve the ancestor documents"}),
        encoding="utf-8")
    T.corpus_document(src)
    _assert_names_record(_refused_launch(planted, src), "the launcher's refusal")

    S.sym(INVLANG_CLI, "main")([str(base), "hypothesis-vocabulary", "--signature", "SIG-p039"])
    err = capsys.readouterr().err
    lines = _lines_naming(err, src.name)
    assert lines, f"the corpus listing does not name the pre-change run:\n{err}"
    assert any("record" in line.lower() for line in lines), (
        f"the corpus listing names the pre-change run with no reason naming its record: {lines}")

    uncopied, _raw = _episode(tmp_path, "p039", copy=False)
    _assert_names_record(_judge_refusal(uncopied, base), "the judge's refusal")


# =================================================================================================
# The findings key: the recorded signature, verbatim (C27)
# =================================================================================================

def test_p067_bare_reenqueue_of_an_episode_without_a_tenant(tmp_path):
    """A bare re-enqueue takes the rule key from the episode's record (form per C27), never from
    a tenant, a mapping or rule.id.

    No tenant is set up; every world copy and the alert's own rule.id name another key."""
    base = tmp_path / "runs"
    base.mkdir()
    ep, _raw = _episode(tmp_path, "p067", signature="SIG-p067")
    _grade(ep, base)
    before = _rows()
    _grade(ep, base)
    rows = _rows()
    assert rows == before, "a bare rerun preserves already queued rows"
    assert set(_keys(rows)) == {"SIG-p067"}, (
        f"rows carry the keys {set(_keys(rows))}, not the episode's recorded signature")


def test_p068_grade_episode_called_directly_without_a_tenant(tmp_path):
    """A judge pass with no tenant keys findings by the episode's recorded signature."""
    ep, _raw = _episode(tmp_path, "p068", signature="SIG-p068")
    _grade(ep, tmp_path / "no-tenant-runs")
    assert set(_keys(_rows())) == {"SIG-p068"}


def test_p069_source_alert_readable_but_mapping_absent_or_faul(tmp_path):
    """The union is taken by recorded digest whatever the mapping. The key comes from the
    recorded signature, or is unkeyed when the record holds none.

    The tenant's mapping file is absent; a second episode's record holds no signature."""
    planted = S.plant_tenant(TENANT, alert_mapping=None)
    ep, raw = _episode(tmp_path, "p069", signature="SIG-p069")
    _trial(planted.runs, "trial-p069", raw, facts={"signature": "SIG-p069"})
    _grade_, judge = _grade(ep, planted.runs)
    assert not _trials(judge), "J3: same-alert priors must stay outside the judge prompt"
    assert set(_keys(_rows())) == {"SIG-p069"}

    before = len(_rows())
    unsigned, _raw = _episode(tmp_path, "p069-unsigned", signature=None)
    _grade(unsigned, planted.runs)
    assert set(_keys(_rows()[before:])) == {S.UNKEYED}


def test_p070_mapping_changed_between_source_run_and_judge(tmp_path):
    """The judge's key, the lesson's source_signature and a later lookup all come from the
    recorded signature (the key in C27's form). A later mapping edit changes none of them, and
    there is no rule.id fallback.

    Observed: the queue row's key (what the lesson author is handed) and the corpus's lookup of
    the source run, both after the tenant's mapping was edited."""
    planted = S.plant_tenant(TENANT, alert_mapping={"signature": "sig_field",
                                                    "event_time": "detected_at",
                                                    "summary": "rule.description"})
    ep, raw = _episode(tmp_path, "p070", signature="SIG-p070")
    src = _trial(planted.runs, T.SOURCE_RUN_ID, raw, facts={"signature": "SIG-p070"})
    T.corpus_document(src)
    S.remap(planted, {"signature": "user.login", "event_time": "detected_at",
                      "summary": "rule.description"})

    _grade(ep, planted.runs)
    assert set(_keys(_rows())) == {"SIG-p070"}

    corpus = S.mod(CORPUS)
    companions, _report = corpus.load_corpus(planted.runs)
    by_case = {c.case_id: c.signature_id for c in companions}
    assert by_case.get(T.SOURCE_RUN_ID) == "SIG-p070", (
        f"the corpus looks the source run up as {by_case.get(T.SOURCE_RUN_ID)!r}, not by its "
        "recorded signature")


def test_p075_two_signatures_share_one_rule_key_slug(tmp_path):
    """The rule key is the recorded signature verbatim, `unkeyed` when there is none; 'ET
    Foo/Bar' is no signature (a space), so two distinct signatures never share a key."""
    base = tmp_path / "runs"
    base.mkdir()
    seen: dict[str, set[Any]] = {}
    for name, sig in (("fold-a", "et-foo-bar"), ("fold-b", "ET-Foo-Bar"),
                      ("fold-c", "Et.Foo.Bar"), ("spaced", None)):
        before = len(_rows())
        raw = _alert(name, rule={"id": "ET Foo/Bar", "name": "spaced rule id"})
        ep, _raw = _episode(tmp_path, name, raw=raw, signature=sig)
        _grade(ep, base)
        seen[name] = set(_keys(_rows()[before:]))
    assert seen == {"fold-a": {"et-foo-bar"}, "fold-b": {"ET-Foo-Bar"},
                    "fold-c": {"Et.Foo.Bar"}, "spaced": {S.UNKEYED}}, seen


def test_p076_rule_key_from_an_enormous_or_path_shaped_signatu(tmp_path):
    """The rule key is used only as data, never as a path or file name. The queue row holds it
    without escaping its directory."""
    base = tmp_path / "runs"
    base.mkdir()
    path_shaped = "keyseg-a/../../keyseg-zz"
    longest = ("Q" + "x.:/@+=-" * 16)[:S.SIGNATURE_MAX]
    for sig in (path_shaped, longest):
        assert S.is_signature(sig), sig
    for name, sig in (("path", path_shaped), ("long", longest)):
        before_rows = len(_rows())
        ep, _raw = _episode(tmp_path, name, signature=sig)
        before = set(tmp_path.rglob("*"))
        _grade(ep, base)
        assert set(_keys(_rows()[before_rows:])) == {sig}, "the row does not hold the key verbatim"
        for path in set(tmp_path.rglob("*")) - before:
            assert path.name not in ("keyseg-a", "keyseg-zz"), f"the key named a path: {path}"
            assert sig not in str(path), f"the key became part of a path: {path}"


def test_p105_one_episode_graded_twice_across_a_mapping_edit(tmp_path):
    """Rows stay under their recorded key, which a mapping edit cannot change; a hand re-enqueue
    after a mapping edit never rewrites or re-keys an existing row. Whether the defender channel
    drops the duplicate is base behaviour (77 RG3) and is not asserted."""
    planted = S.plant_tenant(TENANT, alert_mapping={"signature": "sig_field",
                                                    "event_time": "detected_at",
                                                    "summary": "rule.description"})
    ep, _raw = _episode(tmp_path, "p105", signature="SIG-p105")
    _grade(ep, planted.runs)
    first = _rows()
    assert set(_keys(first)) == {"SIG-p105"}
    S.remap(planted, {"signature": "user.login", "event_time": "detected_at",
                      "summary": "rule.description"})
    _grade(ep, planted.runs)
    after = _rows()
    assert after[:len(first)] == first, "the hand re-enqueue rewrote an existing row"
    assert set(_keys(after)) == {"SIG-p105"}, "a row after the mapping edit carries another key"


def test_p110_unmapped_tenant_piles_every_alert_under_one_key(tmp_path):
    """Every unmapped alert's key is unkeyed."""
    base = tmp_path / "runs"
    base.mkdir()
    for name in ("unmapped-1", "unmapped-2", "unmapped-3"):
        before = len(_rows())
        ep, _raw = _episode(tmp_path, name, signature=None)
        _grade(ep, base)
        assert set(_keys(_rows()[before:])) == {S.UNKEYED}, name


# =================================================================================================
# The sibling union: runs under the base whose recorded digest is the copy's
# =================================================================================================



def test_p114_source_runs_box_rewrote_its_alert_to_another_ale(tmp_path):
    """A world whose alert.json was altered changes neither the union nor the key. Nothing after
    the box trusts bytes the box could write.

    Every world copy and the source run's alert are rewritten to another alert B (with its own
    `alert_id`), which has a trial of its own under the base."""
    base = tmp_path / "runs"
    ep, raw = _episode(tmp_path, "p114", signature="SIG-p114")
    other = S.alert_bytes(S.generic_alert(rule_id="R-B-p114", alert_id="AID-B-p114"))
    for world in (ep / "worlds").iterdir():
        (world / "alert.json").write_bytes(other)
    source = _trial(base, T.SOURCE_RUN_ID, raw, facts={"signature": "SIG-p114"})
    S.alert_file(source).write_bytes(other)
    _trial(base, "trial-a", raw, facts={"signature": "SIG-p114"})
    _trial(base, "trial-b", other, facts={"signature": "SIG-B-p114"})
    _grade_, judge = _grade(ep, base)
    assert not _trials(judge), "J3: same-alert priors must stay outside the judge prompt"
    assert set(_keys(_rows())) == {"SIG-p114"}




def test_p119_source_run_dir_gone_when_the_episode_is_judged(tmp_path):
    """The episode's alert and recorded signature come from the episode's copy, and the key is
    derived from it (form per C27). Neither ever comes from a world copy. The pass does not
    hang.

    The source run's folder is gone from the base; the world copies are the decoys."""
    base = tmp_path / "runs"
    ep, raw = _episode(tmp_path, "p119", signature="SIG-p119")
    _trial(base, "trial-p119", raw)
    judge = J.scripted_judge()
    box = _bounded(lambda: _grade(ep, base, judge=judge), what="the judge pass")
    assert "raised" not in box, f"the pass failed: {box.get('raised')!r}"
    assert set(_keys(_rows())) == {"SIG-p119"}
    assert not _trials(judge), "J3: same-alert priors must stay outside the judge prompt"


def test_p120_source_alert_json_is_not_a_regular_file(tmp_path):
    """No hang, no read outside the runs base, no target bytes in the judge's prompt. A
    non-regular or linked candidate is skipped by name and counted.

    Candidates: a record that is a link to a matching record outside the base, a record that is
    a FIFO, a run folder that is a link to a matching run outside the base; the source run's own
    alert is a link to a host file. Each link target carries a marker."""
    marker = "OUTSIDE-MARKER-p120"
    base = tmp_path / "runs"
    outside = tmp_path / "outside"
    ep, raw = _episode(tmp_path, "p120")
    _trial(base, "trial-genuine", raw)

    far = _trial(outside, "far-run", raw, disposition="malicious")
    (far / "report.md").write_text(T.report_text("malicious", body=marker), encoding="utf-8")
    linked_record = _trial(base, "cand-link-record", raw)
    S.record_file(linked_record).unlink()
    S.record_file(linked_record).symlink_to(S.record_file(far))
    fifo = _trial(base, "cand-fifo-record", raw)
    S.record_file(fifo).unlink()
    os.mkfifo(S.record_file(fifo))
    (base / "cand-link-dir").symlink_to(far, target_is_directory=True)
    host_file = outside / "host-alert.json"
    host_file.write_text(json.dumps({"note": marker}), encoding="utf-8")
    source = _trial(base, T.SOURCE_RUN_ID, raw)
    S.alert_file(source).unlink()
    S.alert_file(source).symlink_to(host_file)

    judge = J.scripted_judge()
    box = _bounded(lambda: _grade(ep, base, judge=judge), what="the judge pass")
    assert "raised" not in box, f"the pass failed: {box.get('raised')!r}"
    assert not _trials(judge), "J3: same-alert priors must stay outside the judge prompt"
    for prompt in judge.prompts:
        assert marker not in prompt, "a link target's bytes reached the judge's prompt"
    for name in ("cand-link-record", "cand-fifo-record"):
        _assert_named_skip(judge, name)
    _assert_named_skip(judge, "cand-link-dir", reason=None)


def test_p121_family_record_names_a_hostile_source_run(tmp_path):
    """A source run id that escapes, is absolute or is empty reads no file. The pass uses the
    episode's copy.

    A decoy run with a marker sits where the escaping and the absolute id point. (An empty id is
    already refused by the manifest loader at base and is not re-asserted here.)"""
    marker = "HOSTILE-SOURCE-p121"
    base = tmp_path / "d1" / "d2" / "runs"
    decoy = _alert("p121-decoy")
    for target in (tmp_path / "d1" / "escaped-src", tmp_path / "abs-src"):
        run = _trial(target.parent, target.name, decoy, facts={"signature": "SIG-DECOY-p121"})
        (run / "report.md").write_text(T.report_text("malicious", body=marker), encoding="utf-8")
    for name, source_run_id in (("escape", "../../escaped-src"),
                                ("absolute", str(tmp_path / "abs-src"))):
        before = len(_rows())
        ep, raw = _episode(tmp_path, f"p121-{name}", signature=f"SIG-p121-{name}")
        _set_source_run_id(ep, source_run_id)
        _trial(base, f"trial-{name}", raw)
        _grade_, judge = _grade(ep, base)
        assert set(_keys(_rows()[before:])) == {f"SIG-p121-{name}"}, name
        assert not _trials(judge), "J3: same-alert priors must stay outside the judge prompt"
        for prompt in judge.prompts:
            assert marker not in prompt, f"{name}: the hostile source run's bytes were read"


def test_p122_source_run_id_in_the_episode_record_names_a_diff(tmp_path):
    """The judged alert is the episode's copy, whatever run the id names."""
    base = tmp_path / "runs"
    ep, raw = _episode(tmp_path, "p122", signature="SIG-p122")
    _trial(base, "other-case-run", _alert("p122-other"), facts={"signature": "SIG-OTHER-p122"})
    _set_source_run_id(ep, "other-case-run")
    _trial(base, "trial-p122", raw)
    _grade_, judge = _grade(ep, base)
    assert set(_keys(_rows())) == {"SIG-p122"}
    assert not _trials(judge), "J3: same-alert priors must stay outside the judge prompt"














@dataclass
class _RewritingJudge(J.FakeJudge):
    """`J.FakeJudge` whose first call runs `rewrite` — the episode's record changing on disk
    while the pass runs (after the union is taken, before the findings are keyed)."""

    rewrite: Callable[[], None] | None = None

    def __call__(self, prompt: str, *, role: Any = None, agent_id: str = "judge",
                 **kw: Any) -> str:
        if self.rewrite is not None:
            rewrite, self.rewrite = self.rewrite, None
            rewrite()
        return super().__call__(prompt, role=role, agent_id=agent_id, **kw)




def test_p159_episode_launched_before_the_change_is_judged_aft(tmp_path):
    """The judge and the bare re-enqueue refuse an episode with no copied record, naming the
    missing record, and do not hang."""
    base = tmp_path / "runs"
    base.mkdir()
    ep, _raw = _episode(tmp_path, "p159", copy=False)
    _assert_names_record(_judge_refusal(ep, base), "the judge's refusal")

    _old_pass_draws(ep)
    rows_before = len(_rows())
    box = _bounded(lambda: _grade(ep, base), what="the bare re-enqueue")
    assert "raised" in box, "the bare re-enqueue queued an episode with no copied record"
    assert isinstance(box["raised"], J.refusals()), f"not a refusal: {box['raised']!r}"
    _assert_names_record(str(box["raised"]), "the bare re-enqueue's refusal")
    assert len(_rows()) == rows_before


# =================================================================================================
# The episode page
# =================================================================================================

def _page_rule(ep: Path) -> str:
    """The episode page's rule header, off the page `render_episode` writes."""
    visualize_episode = S.mod(VISUALIZE)
    # #1187 (O8/O9): by id, through the repository of the tenant whose `<T>/episodes/` holds it.
    page = Path(visualize_episode.render_episode(J.episode_runs_for(ep), ep.name))
    html = page.read_text(encoding="utf-8")
    found = re.findall(r'<span class="hd-alert">([^<]*)</span>', html)
    assert len(found) == 1, f"the episode page's header carries {len(found)} alert spans"
    return found[0]


def test_p071_episode_page_after_the_judges_pick_is_replaced(tmp_path):
    """The episode page's display of rule and alert_id is unchanged, and it renders without a
    tenant or the source run (it reads the episode's copy).

    No tenant is set up, no source run exists, and no world carries an alert."""
    rule = {"id": "R-p071", "name": "Copy rule p071", "description": "the copy's rule"}
    with_id = S.alert_bytes(S.generic_alert(rule=rule, alert_id="AID-p071"))
    ep, _raw = _episode(tmp_path, "p071", raw=with_id, alert=False)
    assert _page_rule(ep) == "Copy rule p071", "the page does not show the episode copy's rule"

    without_id = S.alert_bytes(S.generic_alert(rule=rule))
    plain, _raw = _episode(tmp_path, "p071-no-id", raw=without_id, alert=False)
    assert _page_rule(plain) == "alert rule: not on the record", (
        "the page's rule header changed for an alert carrying no alert_id")


# =================================================================================================
# The launcher's copy step (C41, C47)
# =================================================================================================

def test_p156_launch_from_a_source_run_without_a_record(tmp_path):
    """The launcher refuses a source run with no record, naming the missing record; it never
    derives a record and never launches without one."""
    raw = _alert("p156")
    planted, _base, src = _source(tmp_path, raw, record=False)
    before = _files_under(src)
    _assert_names_record(_refused_launch(planted, src), "the launcher's refusal")
    assert _files_under(src) == before, "the launch wrote into the source run (derived a record)"
    assert raw not in _episode_files().values(), "the launch copied the alert anyway"


def test_p157_source_digest_and_alert_bytes_disagree_at_launch(tmp_path):
    """Launch refuses when the source's alert bytes disagree with its recorded digest, naming
    the mismatch; nothing is copied, so no sibling starts and the judge has nothing to take."""
    raw = _alert("p157")
    planted, _base, src = _source(tmp_path, raw, digest=S.sha256_hex(_alert("p157-recorded")),
                                  signature="SIG-p157")
    record_bytes = S.record_file(src).read_bytes()
    message = _refused_launch(planted, src)
    assert any(w in message.lower() for w in ("digest", "mismatch", "differ", "disagree")), (
        f"the refusal does not name the mismatch: {message!r}")
    copied = _episode_files().values()
    assert raw not in copied, "the launch copied the source's alert"
    assert record_bytes not in copied, "the launch copied the source's record"


def test_p158_relaunch_finds_the_episode_copy_already_present(tmp_path):
    """A relaunch never meets an earlier launch's copy. Each launch claims a fresh episode and
    copies the source's alert and record as they are found then, subject to C47's check."""
    first_raw = _alert("p158-first")
    planted, base, src = _source(tmp_path, first_raw, signature="SIG-p158-first")
    first_record = S.record_file(src).read_bytes()
    first = _launch(planted, src)

    second_raw = _alert("p158-second")
    S.plant_run(base, src.name, alert=second_raw, facts={"signature": "SIG-p158-second"})
    second_record = S.record_file(src).read_bytes()
    second = _launch(planted, src)
    assert second != first, "the relaunch reused the first launch's episode"
    assert S.episode_alert_file(second).is_file(), "the relaunch put no copy in its episode"
    assert S.episode_alert_file(second).read_bytes() == second_raw
    assert S.episode_record_file(second).read_bytes() == second_record
    assert S.episode_alert_file(first).read_bytes() == first_raw, "the relaunch touched the first"
    assert S.episode_record_file(first).read_bytes() == first_record

    S.alert_file(src).write_bytes(_alert("p158-unrecorded"))
    message = _refused_launch(planted, src)
    assert any(w in message.lower() for w in ("digest", "mismatch", "differ", "disagree")), (
        f"a relaunch over bytes the record does not certify was not refused by name: {message!r}")
    assert S.episode_alert_file(second).read_bytes() == second_raw


# =================================================================================================
# A sibling resumed after a mapping edit
# =================================================================================================

def test_p062_mapping_edited_between_a_source_run_and_a_resume(tmp_path):
    """A sibling's ticket comment and lookups use the recorded signature copied into the
    episode. Its inherited prompt and its own lookups agree.

    The tenant's mapping is edited after the launch, so a re-derivation would give another
    value; the case mapping's comment carries the signature. Observed: the sibling's record,
    and the comment the ticket writer's record leg posts for the sibling's run."""
    mapping = {"signature": "sig_field", "event_time": "detected_at",
               "summary": "rule.description"}
    case_mapping = S.case_mapping_text(comment_body=S.SIGNED_COMMENT_BODY)
    raw = _alert("p062")
    planted, _base, src = _source(tmp_path, raw, signature="SIG-p062", alert_mapping=mapping,
                                  case_mapping=case_mapping)
    ep = _launch(planted, src)
    T.write_family(ep, T.family_doc(source_run_dir=str(src)))
    S.remap(planted, {**mapping, "signature": "user.login"})

    sib = _resume_sibling(ep)
    assert S.recorded(sib, "signature") == "SIG-p062", (
        "the sibling's record is not the episode copy's (it was re-derived)")

    store = S.TicketStore()
    S.ticket_writer(store).record_case_ticket(
        _run_handle_1165(sib), tenant=planted.run_tenant(dispatches_lead_zero=False), defender_dir=S.DEFENDER,
        env={})
    bodies = [str(c.get("body")) for c in store.comments()]
    assert len(bodies) == 1, f"the record leg posted {len(bodies)} comments: {store.calls}"
    assert "sig=SIG-p062" in bodies[0], (
        f"the sibling's ticket comment does not carry the recorded signature: {bodies[0]!r}")
