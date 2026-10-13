"""#1234 slice 6 — control_and_usability: which runs are usable, and what an unusable one costs.

A3 decides usability from READS. A run is usable only when the one bounded no-follow reader
reads every file its context needs, plain, within limits and well-formed: a report with exactly
one valid disposition, every oracle-store row naming that world's own facts, and A12's call-id
checks on both call records. A planted world that fails is malformed. It is ungradable, named by
file and refusal, and leaves every reference set, and the rest of the family still grades. A
control that fails, or has a world record, stamps the family not graded, naming the control and
the cause. Nothing is graded against a thinned control (X5). The control check runs after the
unchanged gates (door, manifest, outcome, O5, family stamp). A door refusal comes before all of
them and writes nothing.

HOW EACH FAULT ENTERS (author.md's hierarchy, rung 1 unless noted):
  * Damaged archive files are planted on disk through `_spec1234`'s planters: a symlink, a hard
    link, a FIFO, a directory, a sparse file one byte past `_io.READ_LIMIT`, a torn JSONL line, a
    second `disposition:` key, undecodable bytes. The real bounded reader meets them on every
    run. OB5 (p10_fs.py) observed these kinds on main, and observed that the reachable-by-box
    ones are the sparse file and the hard link. The FIFO cases run under a SIGALRM bound, as
    OB5's probe ran (`_within`): a reader that opened one blocking would hang the pass.
  * A failed call-record write (d02d's AN01 arm) is a DIRECTORY the estate's adapter plants at the
    record's name mid-run (`Estate1234.break_write`). It goes through the REAL launcher and the
    REAL sibling. On main the table write raises `NotPlainEntry` out of `run.main` and the ledger
    write is swallowed (AP-01/JP-02, the survey's smoke run).
  * The judge model is `RoutedJudge`. It records every prompt and injects nothing here. The tests
    read what it was HANDED (which worlds were called, which run's archive text reached which
    prompt), never its canned reply.

WHAT IS ASSERTED: names, never wording. A stamp or a row reason must carry the control's label
(the hand-built control is `ctl`, a label no reason spells by accident; the real path's control
is always `a`, matched only in a quoted or path form) and the cause's own name. The cause's name
is a file name, a production constant (`outcome.NOT_ARCHIVED`), the coined call-id field, or the
fixture's own input. Reference-set membership is read off the prompts. Every hand-built text
carries `MARK-<label>-<what>`, so "c left every reference set" is "none of c's archive marks is
in b's or d's prompt", always beside its positive control, "d's marks ARE in b's prompt". On main
no prompt carries a reference run, so the bare negative would be green for the wrong reason.

WHAT IS DELIBERATELY NOT PINNED:
  * The control stamp's word. The design names the stamps "unchanged in kind" and gives the new
    one no word. Only its presence (main's `not_graded` field) and its reason are read, apart from
    g16, which needs O5's own word (`outcome.UNUSABLE`) to tell the two gates apart.
  * AM15's sentence saying "the layer is absent". The only spelling is main's render text, and
    no ruling names it. The test pins that the run stays usable.
  * Where an overflow-refused world's reason sits on its row (#170: "a world-row reason"). Any of
    the reason fields is accepted.
"""
from __future__ import annotations

import dataclasses
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from defender import _yaml
from defender.tests import _triplet_947 as T
from defender.tests._spec923 import finished_run
from defender.tests.judge_contrast_1234 import _spec1234 as S
from defender.tests.live_oracle_1224 import _spec1224 as S24

# --------------------------------------------------------------------------------------
# Vocabulary local to this slice.
# --------------------------------------------------------------------------------------

#: The hand-built control's label: three letters no refusal text spells by accident ("a" is
#: an English word, so `"a" in reason` holds for every reason).
CTL = "ctl"
#: main's EpisodeGrade field for a stamp. The design keeps stamps "unchanged in kind".
STAMP = S.STAMP
MALFORMED = S.COINED["row.malformed"]
UNGRADABLE_REASON = S.COINED["row.ungradable_reason"]
UNREAD = S.COINED["found.unread"]
#: A pre-cut run-end record (`run_end.json` as the host writes it): truncated before the model
#: closed. The truncation word is this fixture's own input, which the stamp must name.
CUT_WORD = "budget"
CUT_SHORT = {"truncated_by": CUT_WORD, "closed_before_cut": False}
#: A secret in a file OUTSIDE the episode, reachable only by following a planted link.
HOST_SECRET = "HOST-SECRET-1234-control-and-usability"
#: The overflow arm's cap and its fact load: 30 facts of ~3.7k characters each (the manifest
#: bounds a statement at 4000), so the world's own computed sections alone are about three
#: times the cap.
OVERFLOW_CAP = 40000
#: A blocked call no run of the family made: if a reader ever kept a foreign row carrying it,
#: it would surface as a found gap.
FOREIGN = {"entity": "foreign-1234"}
GHOST_PARAMS = {"entity": "ghost-1234"}
#: A key no recording holds, so the call reaches the estate adapter (`Estate1234.break_write`).
FRESH = S.query_params("user:bob")
#: A world label the manifest does not declare.
GHOST = "ghost"
ORDERS = (("benign", "malicious"), ("malicious", "benign"))
#: The fourth world of a reference family: healthy, planted, with a call of its own on edr.
_D = {"calls": [S.CallRow(system="edr", params=S.query_params("host:web-9"))],
      "forged_system": "edr"}


def _ctl(worlds: list[S.World]) -> list[S.World]:
    """`worlds` with the control relabelled `ctl`."""
    return [dataclasses.replace(w, label=CTL) if w.is_control else w for w in worlds]


def _triad_ctl(**over: dict[str, Any]) -> list[S.World]:
    """`S.triad(**over)` with the control relabelled `ctl` (`over["a"]` still names it)."""
    return _ctl(S.triad(**over))


def _quad(**over: dict[str, Any]) -> list[S.World]:
    """Control `a`, planted `b`, `c` and a healthy planted `d`. Two clean planted siblings let
    one scenario show both "c left the references" and "d is still one"."""
    return S.triad(**{"d": dict(_D), **over})


def _build(tmp_path: Path, name: str, worlds: list[S.World], **kw: Any) -> S.Built:
    """One hand-built family under its own episodes root (several per test)."""
    return S.family(tmp_path / name, worlds, root=tmp_path / f"{name}-root", **kw)


def _stamp(where: Any) -> dict:
    return S.stamp(where)


def _reason(where: Any) -> str:
    return str(S.stamp(where).get("reason") or "")


def _queues_empty() -> bool:
    return not S.defender_queue() and not S.questioner_queue()


def _assert_stamped(where: Any, judge: S.RoutedJudge, *names: str) -> str:
    """The family is stamped not graded, its reason naming each of `names`. No model call was
    made, nothing was queued, and no world row records a completed draw. Returns the reason."""
    stamp = _stamp(where)
    assert stamp, (f"the family was graded, not stamped: judge.yaml =\n"
                   f"{S.record_text(where)[:1500]}")
    reason = _reason(where)
    for name in names:
        assert name in reason, f"the stamp does not name {name!r}: {reason!r}"
    assert judge.calls == 0, f"a stamped family still called the judge model: {judge.agent_ids}"
    assert _queues_empty(), (f"a stamped family queued rows: {S.defender_queue()} "
                             f"{S.questioner_queue()}")
    drawn = [label for label, r in S.rows(where).items() if r.get("completed_draws")]
    assert not drawn, f"worlds {drawn} were graded under a stamp"
    return reason


def _names_label(text: str, label: str) -> bool:
    """`text` names world `label` in a quoted or path form, so the article "a" never counts."""
    q = re.escape(label)
    return re.search(rf"'{q}'|\"{q}\"|worlds/{q}\b|\.{q}\.jsonl|-{q}\b|"
                     rf"\b(?:world|control|run)\s+{q}\b", text) is not None


def _marks(label: str) -> tuple[str, ...]:
    """The archive-text markers of run `label`: report, document, the lead's summary. These
    are never the manifest's story, which a header may list for every declared world."""
    return (S.marker(label, "report"), S.marker(label, "investigation"),
            S.marker(label, "summary-l-001"))


def _shows(prompt: str, label: str) -> bool:
    return any(m in prompt for m in _marks(label))


def _assert_out_of_references(judge: S.RoutedJudge, gone: str, *,
                              focus: tuple[str, str] = ("b", "d")) -> None:
    """Run `gone` reaches neither healthy planted world's prompt, while each of them reaches
    the other's (the paired positive control: references render at all)."""
    one, other = focus
    for f in focus:
        assert judge.called(f), f"world {f} was not graded beside the unusable {gone}"
        prompt = judge.prompt_for(f)
        assert not _shows(prompt, gone), f"{gone}'s archive text reached {f}'s prompt"
    for f, ref in ((one, other), (other, one)):
        assert _shows(judge.prompt_for(f), ref), (
            f"control: {ref} is not among {f}'s references, so a missing {gone} proves nothing")


def _row_reason(row: dict) -> str:
    """The reason A3 gives a world it leaves out (malformed, cut short, a world record): the
    row's ungradable reason, naming the file and the refusal."""
    return str(row.get(UNGRADABLE_REASON) or "")


def _assert_malformed(where: Any, label: str, *names: str) -> str:
    """World `label`'s row is ungradable AND malformed, and its reason names each of `names`."""
    row = S.row(where, label)
    assert row.get("ungradable") is True, f"world {label} is not ungradable: {row}"
    assert row.get(MALFORMED) is True, f"world {label} is not marked malformed: {row}"
    reason = str(row.get(UNGRADABLE_REASON) or "")
    for name in names:
        assert name in reason, f"world {label}'s reason does not name {name!r}: {reason!r}"
    return reason


def _assert_no_host_text(where: Any, judge: S.RoutedJudge) -> None:
    assert not any(HOST_SECRET in p for p in judge.prompts), "a host file reached a prompt"
    assert HOST_SECRET not in S.record_text(where), "a host file reached judge.yaml"


def _host_rows(tmp_path: Path) -> Path:
    """A JSONL file OUTSIDE the episode whose one row carries `HOST_SECRET` in the shape a
    forged row, a ledger row or a table row would be read in."""
    path = tmp_path / "host" / "outside-the-episode.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    S.rewrite_jsonl(path, lambda _rows: [{
        "forged_id": "fg-host", "fact_id": "f-c", "system": "edr", "verb": "query",
        "source": "refused", "params": {"note": HOST_SECRET}, "row": {"note": HOST_SECRET},
        "payload_text": HOST_SECRET}])
    return path


def _host_report(tmp_path: Path) -> Path:
    path = tmp_path / "host" / "outside-report.md"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(S.report_text("benign", body=HOST_SECRET), encoding="utf-8")
    return path


def _names_run(entry: dict, label: str) -> bool:
    """A found-gap entry belongs to run `label` (its run spelled `S.found_run`: the label)."""
    return entry.get(S.COINED["found.run"]) == S.found_run(label)


def _gaps(where: Any, label: str, system: str, verb: str, params: dict) -> list:
    """The user section's found-gap entries naming run `label` and that blocked call."""
    want = (system, verb, S.canonical(params))
    return [e for e in S.found_gaps(where) if _names_run(e, label)
            and S.gap_key(e)[1:] == want]


def _gap_of(where: Any, label: str, call: S.CallRow) -> list:
    return _gaps(where, label, call.system, call.verb, call.the_params)


def _carries(entry: dict, params: dict) -> bool:
    found = entry.get(S.COINED["found.params"])
    return isinstance(found, dict) and S.canonical(found) == S.canonical(params)


def _finding_reply(focus: str, control: str) -> dict:
    """A world reply that queues one defender row when the world is graded: a `lead-quality`
    investigator finding resting on a two-run conduct pair, the focus world's report against
    the control's."""
    return S.world_reply("lead-quality", ["idp"], investigator=[
        S.inv(contrast=[S.conduct(focus), S.conduct(control)])])


def _shared_id_calls(label: str, first: S.CallRow) -> list[S.CallRow]:
    """`first`, then a table-only reject carrying THE SAME call id: two table rows of the run
    sharing one id (A12). The ledger holds one row, so only the table check can fire."""
    shared = S.call_id(label, 0)
    return [dataclasses.replace(first, call_id=shared),
            S.CallRow(params=S.query_params("user:carol"), source=None,
                      exit_code=S.REJECT_EXIT, call_id=shared)]


def _missing_id_calls(first: S.CallRow) -> list[S.CallRow]:
    """`first`, then a ledger-only row carrying NO call id, which A3's read refuses. It writes
    no table row: an id-less table row would read as an inherited row the other tables lack,
    a failed read of the TABLE under R3 (a), and this case pins the ledger's own check."""
    return [first, S.CallRow(params=S.query_params("user:carol"), call_id=None, table=False)]


def _relabel(built: S.Built, old: str, new: str) -> None:
    """Rename world `old` in the archived manifest. The edit is made after the build, because
    a label off the grammar (`..`, `b/c`) must never become a path the builder writes."""
    path = built.ep / "family.yaml"
    doc = _yaml.safe_load(path.read_text(encoding="utf-8"))
    for world in doc["worlds"]:
        if world["world_id"] == old:
            world["world_id"] = new
    path.write_text(_yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def _refusal_or_stamp(built: S.Built, judge: S.RoutedJudge) -> str:
    """The text the pass refused with (a raised refusal, or a stamp's reason). Fails if the
    pass graded instead."""
    try:
        S.grade(built, judge)
    except S.refusals() as refused:
        return str(refused)
    reason = _reason(built)
    assert reason, f"the pass graded instead of refusing: {S.record_text(built)[:1500]}"
    return reason


# --------------------------------------------------------------------------------------
# Damage tables: one entry per way a run's context read fails (A3, A12).
# Each entry: (world overrides, damage planted after the build, names its refusal must carry).
# --------------------------------------------------------------------------------------

Damage = Callable[[S.Built, str, Path], Any]
Names = Callable[[S.Built, str], tuple[str, ...]]


def _file(name: str) -> Names:
    return lambda _b, _l: (name,)


def _ledger_named(built: S.Built, label: str) -> tuple[str, ...]:
    return (built.ledger_path(label).name,)


def _on(leaf: str, plant: Callable[[Path, Path], Any]) -> Damage:
    """Plant `plant(path, tmp_path)` at world `label`'s archived `leaf` (`ledger`: its served
    ledger; `oracle`: its oracle store's forged rows)."""
    def damage(built: S.Built, label: str, tmp_path: Path) -> Any:
        if leaf == "ledger":
            path = built.ledger_path(label)
        elif leaf == "oracle":
            path = built.oracle_path(label)
        else:
            path = built.world_dir(label) / leaf
        return plant(path, tmp_path)
    return damage


def _to_host_rows(path: Path, tmp_path: Path) -> Any:
    return S.plant_symlink(path, _host_rows(tmp_path))


def _to_host_report(path: Path, tmp_path: Path) -> Any:
    return S.plant_symlink(path, _host_report(tmp_path))


def _hard_linked(path: Path, tmp_path: Path) -> Any:
    return S.plant_hardlink(path, _host_rows(tmp_path))


def _torn(path: Path, _tmp_path: Path) -> Any:
    return S.tear_jsonl(path)


def _fifo(path: Path, _tmp_path: Path) -> Any:
    return S.plant_fifo(path)


def _directory(path: Path, _tmp_path: Path) -> Any:
    return S.plant_dir(path)


def _sparse(path: Path, _tmp_path: Path) -> Any:
    return S.plant_oversize(path)


def _second_key(path: Path, _tmp_path: Path) -> Any:
    return S.second_disposition(path)


def _undecodable(path: Path, _tmp_path: Path) -> Any:
    """Bytes the bounded reader cannot decode as UTF-8: a present but unreadable file."""
    return path.write_bytes(b"\xff\xfe not utf-8 \xc3\x28\n")


#: Context-read failures, keyed by case id. A value of None for overrides means none are needed.
#: `calls` overrides are built per label (the call id names the run).
_READS: dict[str, tuple[Callable[[str, S.CallRow], dict] | None, Damage | None, Names]] = {
    "query-table-is-a-symlink": (None, _on("executed_queries.jsonl", _to_host_rows),
                                 _file("executed_queries.jsonl")),
    "query-table-is-torn": (None, _on("executed_queries.jsonl", _torn),
                            _file("executed_queries.jsonl")),
    "served-ledger-is-a-symlink": (None, _on("ledger", _to_host_rows), _ledger_named),
    "served-ledger-is-torn": (None, _on("ledger", _torn), _ledger_named),
    "ledger-row-without-a-call-id": (
        lambda _label, first: {"calls": _missing_id_calls(first)}, None,
        lambda built, label: (*_ledger_named(built, label), S.CALL_ID)),
    "two-table-rows-sharing-one-call-id": (
        lambda label, first: {"calls": _shared_id_calls(label, first)}, None,
        _file("executed_queries.jsonl")),
    "report-with-no-usable-disposition": (
        lambda _l, _f: {"report": S.report_text("Benign", body="The control closed.")}, None,
        _file("report.md")),
    "report-with-a-look-alike-disposition": (
        lambda _l, _f: {"report": S.report_text("m\u0430licious", body="Cyrillic a.")}, None,
        _file("report.md")),
    "report-with-a-second-disposition-key": (None, _on("report.md", _second_key),
                                             _file("report.md")),
    "report-is-a-symlink": (None, _on("report.md", _to_host_report), _file("report.md")),
    "alert-is-a-fifo": (None, _on("alert.json", _fifo), _file("alert.json")),
    "oracle-store-is-a-symlink": (None, _on("oracle", _to_host_rows), _file("forged.jsonl")),
    "oracle-store-is-a-hard-link": (None, _on("oracle", _hard_linked), _file("forged.jsonl")),
    "oracle-store-is-torn": (None, _on("oracle", _torn), _file("forged.jsonl")),
    "oracle-store-is-a-fifo": (None, _on("oracle", _fifo), _file("forged.jsonl")),
}

#: The special files D14 names, at each file a run's context reads.
_SPECIAL: dict[str, tuple[Damage, Names]] = {
    "report-is-a-fifo": (_on("report.md", _fifo), _file("report.md")),
    "report-is-a-directory": (_on("report.md", _directory), _file("report.md")),
    "report-is-sparse-past-the-read-limit": (_on("report.md", _sparse), _file("report.md")),
    "query-table-is-a-fifo": (_on("executed_queries.jsonl", _fifo),
                              _file("executed_queries.jsonl")),
    "query-table-is-sparse-past-the-read-limit": (_on("executed_queries.jsonl", _sparse),
                                                  _file("executed_queries.jsonl")),
    "alert-is-a-fifo": (_on("alert.json", _fifo), _file("alert.json")),
    "alert-is-a-directory": (_on("alert.json", _directory), _file("alert.json")),
    "lessons-record-is-a-fifo": (_on("lessons_loaded.jsonl", _fifo),
                                 _file("lessons_loaded.jsonl")),
    "gather-summary-is-a-fifo": (_on("gather_summaries/l-001.md", _fifo),
                                 _file("gather_summaries")),
}


def _damaged(tmp_path: Path, case: str, label: str, worlds: Callable[..., list[S.World]],
             first: S.CallRow) -> tuple[S.Built, tuple[str, ...]]:
    """A family whose world `label` carries `_READS[case]`. Returns it and the names the
    refusal must carry."""
    over, damage, names = _READS[case]
    key = "a" if label == CTL else label
    built = _build(tmp_path, case, worlds(**{key: over(label, first)} if over else {}))
    if damage is not None:
        damage(built, label, tmp_path)
    return built, names(built, label)


_CTL_FIRST = S.CallRow()
_C_FIRST = S.CallRow(system="edr", params=S.query_params("host:db-1"))


# ======================================================================================
# The control check (M1, A3): every control state stamps the family, after the unchanged gates.
# ======================================================================================

def test_1234_control_not_archived_stamps_the_family_not_graded(tmp_path):
    """An accepted, comparable family whose control has a world record (`not archived`) is
    stamped not-graded, the stamp naming the control and that reason. The family is past the
    door gate and the unchanged manifest, outcome, O5 and family-stamp gates (A3). No model call
    is made, nothing is queued, and the user section carries the found gaps (A2).

    The control's own served ledger stays in `served/`, because the registry writes it during
    the run, so a not-archived world still has one. A2's census reads it ("not-archived worlds
    included") beside b's. The positive control is the same family with its control archived,
    which grades b and queues b's defender row: the call channel and the queue channel are live."""
    outcome = S.mod(S.OUTCOME)
    b_blocked = S.refused_call()
    b_over = {"calls": [S.CallRow(), S.oracle_call(fact_id="f-b", forged_id="fg-b-1"), b_blocked]}
    built = _build(tmp_path, "stamped", _triad_ctl(
        a={"archived": False, "world_record": outcome.NOT_ARCHIVED}, b=b_over))
    ctl_blocked = S.refused_call(params={"entity": "ctl-blocked"})
    S.rewrite_jsonl(built.ledger_path(CTL), lambda rows: [*rows, S.ledger_row(
        ctl_blocked, label=CTL, token=built.token, cid=S.call_id(CTL, 0))])
    judge = S.judge({"b": _finding_reply("b", CTL)})

    S.grade(built, judge)

    _assert_stamped(built, judge, CTL, outcome.NOT_ARCHIVED)
    assert _gap_of(built, "b", b_blocked), (
        f"the stamped pass's user section lacks b's blocked call: {S.found_gaps(built)}")
    assert _gap_of(built, CTL, ctl_blocked), (
        f"the not-archived control's blocked call is not a found gap: {S.found_gaps(built)}")

    usable = _build(tmp_path, "usable", _triad_ctl(b=b_over))
    graded = S.judge({"b": _finding_reply("b", CTL)})
    S.grade(usable, graded)
    assert not _stamp(usable), f"control: an archived control stamped: {_reason(usable)!r}"
    assert graded.called("b"), "control: an archived control did not let b be graded"
    assert S.from_world(S.defender_queue(), "b"), "control: graded b queued no defender row"


@pytest.mark.parametrize("cut", ["before-the-model-closed", "failed-served-ledger-write"])
def test_1234_control_cut_short_stamps_the_family_not_graded(tmp_path, cut):
    """An accepted, comparable family whose control's run was cut short is stamped not-graded,
    naming the control and the cut. The cut is either before the model closed, or a failed write
    of either call record, which is named (AN01). The check runs after the unchanged gates; no
    model call is made and nothing is queued.

    The first case is the hand-built run-end record: `truncated_by` set, `closed_before_cut`
    false. Its control is a run cut AFTER the model closed, which is no cut, so the family grades. The
    AN01 cases run the REAL launcher and REAL siblings: the control's investigator makes one call
    on a key no recording holds, and the estate's adapter plants a directory at the control's
    query table (on main `NotPlainEntry` out of `run.main`, so the sibling exits 1, AP-01) or at
    its served ledger (on main the write is refused and swallowed, JP-02). On the real path the
    control is always `a`. The stamp must name it in a quoted or path form, and must name the
    record whose write failed."""
    if cut == "before-the-model-closed":
        built = _build(tmp_path, "cut", _triad_ctl(a={"run_end": dict(CUT_SHORT)}))
        judge = S.judge()
        S.grade(built, judge)
        _assert_stamped(built, judge, CTL, CUT_WORD)

        closed = _build(tmp_path, "closed", _triad_ctl(
            a={"run_end": {**CUT_SHORT, "closed_before_cut": True}}))
        after = S.judge()
        S.grade(closed, after)
        assert not _stamp(closed), f"control: a run cut after it closed stamped: {_reason(closed)}"
        assert after.called("b"), "control: a control that closed before the cut blocked b"
        return

    est = S.Estate1234(tmp_path / "estate", withheld=(("edr", "lookup"),))
    pattern = ("{run_dir}/executed_queries.jsonl" if cut == "failed-query-table-write"
               else "{episode}/served/*.{label}.jsonl")
    est.break_write("idp", "query", FRESH, pattern)
    turns = [*S.default_turns()[:-1], S.query_turn("idp", "query", FRESH), S.done_turn()]
    real = S.real_family(tmp_path, {"a": S.RealWorld("a", disposition="benign", turns=turns)},
                         estate=est)
    judge = S.judge()

    S.grade(real, judge)

    reason = _assert_stamped(real, judge)
    assert _names_label(reason, "a"), f"the stamp does not name the control a: {reason!r}"
    record = (("executed_queries.jsonl", "query table") if cut == "failed-query-table-write"
              else (real.ledger_path("a").name, "served ledger", "ledger"))
    assert any(name in reason for name in record), (
        f"the stamp does not name the failed write ({record}): {reason!r}")


def test_1234_control_missing_report_stamps_the_family_not_graded(tmp_path):
    """An accepted, comparable family whose archived control has no report.md is stamped
    not-graded naming the control's missing report, after the unchanged gates. A missing report
    is a failed read of a file its context needs (A3). No model call is made and nothing is
    queued. Today the family is graded and queues rows (E-01)."""
    built = _build(tmp_path, "no-report", _triad_ctl(a={"reached": None}))
    assert not (built.world_dir(CTL) / "report.md").exists(), "fixture: the report is there"
    judge = S.judge({"b": _finding_reply("b", CTL)})

    S.grade(built, judge)

    _assert_stamped(built, judge, CTL, "report.md")


@pytest.mark.parametrize("case", [
    "report-with-no-usable-disposition", "report-with-a-look-alike-disposition",
    "report-with-a-second-disposition-key", "report-is-a-symlink", "alert-is-a-fifo",
    "ledger-row-without-a-call-id", "two-table-rows-sharing-one-call-id"])
def test_1234_control_malformed_stamps_the_family_not_graded(tmp_path, case):
    """An accepted, comparable family whose control's context read fails is stamped not-graded
    naming the control, the file and the refusal (A3, A12). The read fails on: report.md with no
    usable disposition or a second disposition key, a served-ledger row without a call id, two
    table rows of the run sharing one id, or a link, special or torn file. No model call is made
    and nothing is queued. A filter that skips foreign or null-owner ledger rows is not the
    answer (X13). A linked report is never followed: the host file's text reaches nothing."""
    built, names = _damaged(tmp_path, case, CTL, _triad_ctl, _CTL_FIRST)
    judge = S.judge({"b": _finding_reply("b", CTL)})

    with S.no_hang(60, f"grading a control whose {case}"):
        S.grade(built, judge)

    reason = _assert_stamped(built, judge, CTL, *names)
    if case == "two-table-rows-sharing-one-call-id":
        assert S.call_id(CTL, 0) in reason, (
            f"the stamp does not name the shared call id: {reason!r}")
    _assert_no_host_text(built, judge)


@pytest.mark.parametrize("case", [
    "query-table-is-a-symlink", "query-table-is-torn", "served-ledger-is-a-symlink",
    "served-ledger-is-torn", "ledger-row-without-a-call-id",
    "two-table-rows-sharing-one-call-id"])
def test_1234_control_with_a_damaged_query_table_or_ledger(tmp_path, case):
    """A control with any failed read of a file its context needs stamps the family not graded,
    naming the control and the cause (A3, A12). The failed reads are: query table or served
    ledger a link or torn, a ledger row without a call id, two table rows sharing one id. No
    world is graded against a thinned control. On main the query table degrades silently to empty
    and a torn ledger line is skipped and counted (OB5, AP-13), so the family grades."""
    built, names = _damaged(tmp_path, case, CTL, _triad_ctl, _CTL_FIRST)
    judge = S.judge({"b": _finding_reply("b", CTL), "c": _finding_reply("c", CTL)})

    S.grade(built, judge)

    _assert_stamped(built, judge, CTL, *names)
    _assert_no_host_text(built, judge)


@pytest.mark.parametrize("state", ["no-investigation", "short-gather-summaries"])
def test_1234_control_missing_investigation_or_short_gather_summaries(tmp_path, state):
    """A control with a readable report but no investigation.md, or short gather summaries, is
    unusable the same way a planted world with those states is ungradable (malformed/cut short).
    The family is stamped not graded naming which.

    "Short" means the control's `gather_summaries/` exists but lacks the summary of a lead its
    own investigation.md resolves (`l-001`)."""
    if state == "no-investigation":
        built = _build(tmp_path, state, _triad_ctl(a={"investigation": None}))
        named = "investigation.md"
    else:
        built = _build(tmp_path, state, _triad_ctl())
        (built.world_dir(CTL) / "gather_summaries" / "l-001.md").unlink()
        named = "gather_summaries"
    judge = S.judge()

    S.grade(built, judge)

    _assert_stamped(built, judge, CTL, named)


def test_1234_control_declared_verdict_outside_the_vocabulary(tmp_path):
    """A manifest control entry declaring a verdict outside the disposition vocabulary is refused
    by the unchanged manifest gate before any world is read, with its own named reason naming
    the declaration: no model call is made, nothing is queued and no not-graded stamp is written
    (the control check that runs after the gate is never reached; 78-gate-resolutions).

    The control's report carries a valid `benign`, so only the declaration can fire.
    `parse_family`'s `_check_disposition` refuses it for every world, the control included
    (executed at 463833df: "worlds['ctl'].disposition_declared is 'suspicious', outside the
    shipped disposition vocabulary"). Positive control: the same family declaring `benign`
    loads and grades b."""
    built = _build(tmp_path, "declared", _triad_ctl(
        a={"declared": "suspicious", "reached": "benign"}))
    judge = S.judge()

    text = str(S.grade_refused(built, judge))

    assert CTL in text, f"the refusal does not name the control: {text!r}"
    assert "disposition_declared" in text, f"the refusal does not name the field: {text!r}"
    assert "suspicious" in text, f"the refusal does not name the declared value: {text!r}"
    assert judge.calls == 0, f"the family was graded: {judge.agent_ids}"
    assert _queues_empty(), "the family queued rows"
    assert not _stamp(built), f"the control check ran past the manifest gate: {_reason(built)!r}"
    assert not any(r.get("completed_draws") for r in S.rows(built).values())

    plain = _build(tmp_path, "declared-benign", _triad_ctl())
    graded = S.judge()
    S.grade(plain, graded)
    assert graded.called("b"), "control: a vocabulary declaration loads and grades b"


def test_1234_no_planted_world_gradable_while_o5_is_not_unusable(tmp_path):
    """A usable control with no usable planted world grades nothing (A3): no world call and no
    family call. judge.yaml records each world's reason and the user section with every found
    gap.

    In the triad b is malformed (two disposition keys) and c is cut short, and neither has a world
    record, so O5 counts no failure. Each run, the control included, has one refused call."""
    blocked = {label: S.refused_call(params={"entity": f"{label}-blocked"}) for label in "abc"}
    built = _build(tmp_path, "none-gradable", S.triad(
        a={"calls": [S.CallRow(), blocked["a"]]},
        b={"calls": [S.CallRow(), S.oracle_call(fact_id="f-b", forged_id="fg-b-1"), blocked["b"]]},
        c={"calls": [_C_FIRST, blocked["c"]], "run_end": dict(CUT_SHORT)}))
    S.second_disposition(built.world_dir("b") / "report.md")
    judge = S.judge()

    S.grade(built, judge)

    assert judge.calls == 0, f"a family with no usable planted world called: {judge.agent_ids}"
    assert "report.md" in _row_reason(S.row(built, "b")), f"b's row: {S.row(built, 'b')}"
    assert CUT_WORD in _row_reason(S.row(built, "c")), f"c's row: {S.row(built, 'c')}"
    for label, call in blocked.items():
        assert _gap_of(built, label, call), (
            f"run {label}'s blocked call is not a found gap: {S.found_gaps(built)}")


def test_1234_world_record_for_a_label_the_manifest_does_not_declare(tmp_path):
    """A world record for a label the manifest does not declare refuses the family loudly, naming
    the undeclared label. It is never counted or listed as a failed world.

    Two cases. The first is the undeclared record alone, which main ignores, so main grades. The
    second puts it beside one declared failed world, where main's O5 counts two and stamps the
    family unusable, listing the undeclared label as a failed world. The paired positive
    control is the second family without the undeclared record: the declared failure alone grades
    b, and g16 holds the O5 side."""
    outcome = S.mod(S.OUTCOME)
    for name, over in (("alone", {}), ("beside-a-failed-world",
                                       {"c": {"world_record": outcome.BUDGET}})):
        built = _build(tmp_path, name, S.triad(**over))
        S24.world_record(built.ep, GHOST, outcome.DID_NOT_FINISH)
        judge = S.judge()

        text = _refusal_or_stamp(built, judge)

        assert GHOST in text, f"{name}: the refusal does not name {GHOST!r}: {text!r}"
        assert judge.calls == 0, f"{name}: the pass went on: {judge.agent_ids}"
        assert _queues_empty(), f"{name}: the pass queued rows"
        assert GHOST not in S.rows(built), f"{name}: {GHOST} was listed as a world"
        assert S.record(built).get("validity") != outcome.UNUSABLE, (
            f"{name}: the undeclared record was counted toward O5: {_reason(built)!r}")

    counted = _build(tmp_path, "declared-only", S.triad(c={"world_record": outcome.BUDGET}))
    judge = S.judge()
    S.grade(counted, judge)
    assert judge.called("b"), "control: one declared failed world stopped the pass"
    assert outcome.BUDGET in _row_reason(S.row(counted, "c")), S.row(counted, "c")


def test_1234_control_pushed_to_an_unusable_close_by_the_alert(tmp_path):
    """An unusable control voids the family (M1): ungraded, with the stamp naming the cause, and
    the operator sees it loudly.

    The operator's surface is the episode page, which renders the stamp. Two closes are shown: a
    control the alert steered to a report with no headline, and one cut short. Neither grades
    the remaining pair (X5)."""
    for name, over, named in (
            ("closed-without-a-headline",
             {"report": "The alert said the case was closed upstream; no verdict.\n"},
             "report.md"),
            ("cut-short", {"run_end": dict(CUT_SHORT)}, CUT_WORD)):
        built = _build(tmp_path, name, _triad_ctl(a=over))
        judge = S.judge({"b": _finding_reply("b", CTL), "c": _finding_reply("c", CTL)})

        S.grade(built, judge)

        reason = _assert_stamped(built, judge, CTL, named)
        shown = S.page_text(built)
        assert " ".join(reason.split()) in shown, (
            f"{name}: the page does not show the stamp {reason!r}")


# ======================================================================================
# The door precedes everything; O5 and the control check keep their order (I-3, g16).
# ======================================================================================

def _container_record(ep: Path, tenant_id: str) -> None:
    (ep / "runs").mkdir(exist_ok=True)
    S.mod("_tenant").ensure_runs_base_record(ep / "runs", tenant_id)


def test_1234_door_refusal_precedes_the_control_check_and_writes_nothing(tmp_path):
    """An episode whose runs/ container lacks _tenant.json (the pre-#1078 shape), or names
    another tenant, is refused at the door (JudgeRefused) before A3's control read. Nothing is
    written: no judge.yaml, no stamp, no found-gap census, no model call and no queue row, for
    the grade pass and the page alike. An archive the door admits (a valid record, a runs link,
    or no runs/) whose control ledger lacks call ids is stamped not graded instead (I-3).

    Every case carries THE SAME damaged control, a ledger without call ids, as a pre-change
    archive would. So the only thing that decides refuse-or-stamp is the container, which pins
    the door's place before the control check. The id-less row is ledger-only: an id-less
    table row the siblings lack would be a failed read of the table of its own (R3 (a))."""
    judge_refused = S.sym(S.JUDGE, "JudgeRefused")
    pre_change = {"a": {"calls": [S.CallRow(call_id=None, table=False)]}}
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    refused = {"recordless-container": lambda ep: (ep / "runs").mkdir(),
               "another-tenants-container": lambda ep: _container_record(ep, "othertenant")}
    admitted = {"own-tenants-container": lambda ep: _container_record(
                    ep, T.current_tenant().id),
                "runs-link": lambda ep: S.plant_symlink(ep / "runs", elsewhere),
                "no-container": lambda ep: None}

    for name, plant in refused.items():
        built = _build(tmp_path, name, _triad_ctl(**pre_change))
        plant(built.ep)
        judge = S.judge()
        err = S.grade_refused(built, judge)
        assert isinstance(err, judge_refused), f"{name}: refused as {err!r}"
        assert "_tenant.json" in str(err), f"{name}: the refusal names no container: {err}"
        assert not (built.ep / "judge.yaml").exists(), f"{name}: the door wrote judge.yaml"
        assert judge.calls == 0, f"{name}: the door let the pass call {judge.agent_ids}"
        assert _queues_empty(), f"{name}: the door let the pass queue rows"
        with pytest.raises(judge_refused):
            S.page(built)

    for name, plant in admitted.items():
        built = _build(tmp_path, name, _triad_ctl(**pre_change))
        plant(built.ep)
        judge = S.judge()
        S.grade(built, judge)
        _assert_stamped(built, judge, CTL, S.CALL_ID)


def test_1234_o5_count_still_counts_the_control_and_is_not_moved_by_a_malformed_planted_world(
        tmp_path):
    """outcome.failed_worlds still counts a world record under any label, the control's
    included, toward UNUSABLE_AT=2 (E-16), after A3's control check is added behind the unchanged
    gates. A family with an unusable control and one failed planted world is stamped by O5 (the
    first gate that applies), not by the control check. A planted world that is malformed under
    A3 but has no world record is not an O5 failure and does not change the count. The control
    is the same family with one failure, which reaches the control check.

    The two gates are told apart by O5's own word (`outcome.UNUSABLE`) and the family's
    validity."""
    outcome = S.mod(S.OUTCOME)
    o5 = _build(tmp_path, "o5", _triad_ctl(a={"world_record": outcome.DID_NOT_FINISH},
                                           c={"world_record": outcome.BUDGET}))
    judge = S.judge()
    S.grade(o5, judge)
    assert _stamp(o5).get("outcome") == outcome.UNUSABLE, f"not O5's stamp: {_stamp(o5)}"
    assert S.record(o5).get("validity") == outcome.UNUSABLE
    assert CTL in _reason(o5), f"O5 did not count the control's record: {_reason(o5)!r}"
    assert outcome.BUDGET in _reason(o5), f"O5 did not count c's record: {_reason(o5)!r}"
    assert judge.calls == 0

    one_failure = _build(tmp_path, "malformed-is-no-o5-failure", S.triad(
        c={"world_record": outcome.BUDGET}))
    S.tear_jsonl(one_failure.table_path("b"))
    S.grade(one_failure, S.judge())
    assert S.record(one_failure).get("validity") != outcome.UNUSABLE, (
        f"a malformed world without a record was counted toward O5: {_reason(one_failure)!r}")
    assert _stamp(one_failure).get("outcome") != outcome.UNUSABLE

    control_only = _build(tmp_path, "control-check", _triad_ctl(
        a={"world_record": outcome.DID_NOT_FINISH}))
    judge = S.judge()
    S.grade(control_only, judge)
    _assert_stamped(control_only, judge, CTL, outcome.DID_NOT_FINISH)
    assert _stamp(control_only).get("outcome") != outcome.UNUSABLE, (
        "one failure (the control's) was stamped by O5 rather than the control check")
    assert S.record(control_only).get("validity") != outcome.UNUSABLE


def test_1234_verdicts_takes_its_refusal_arm_on_a_report_with_two_disposition_keys(tmp_path):
    """episode.verdicts refuses a report.md carrying a second top-level `disposition:` key by its
    existing unreadable-report arm (EpisodeError naming the world), as every other report reader
    refuses it (A3, K4; human ruling, 78-gate-resolutions.md). verdicts reads the disposition
    through its own parse_frontmatter_or_none path (episode._declared_disposition), and today it
    takes the last key's verdict: benign-then-malicious reads malicious (GT-3). It never returns a
    verdict derived from either key (malicious-then-benign and benign-then-malicious alike), and a
    world with no report.md is still skipped (C15). The control is the same family with
    single-key reports."""
    verdicts = S.sym(S.EPISODE_MOD, "verdicts")
    episode_error = S.sym(S.EPISODE_MOD, "EpisodeError")
    clean = _build(tmp_path, "single-keys", S.triad())
    assert verdicts(clean.ep) == {"a": "benign", "b": "malicious", "c": "malicious"}, (
        "control: verdicts cannot read single-key reports")

    for first, second in ORDERS:
        built = _build(tmp_path, f"{first}-then-{second}", S.triad())
        S.second_disposition(built.world_dir("b") / "report.md", first, second)
        with pytest.raises(episode_error) as refused:
            verdicts(built.ep)
        assert "'b'" in str(refused.value), f"the refusal does not name world b: {refused.value}"

    skipped = _build(tmp_path, "no-report", S.triad(c={"reached": None}))
    assert verdicts(skipped.ep) == {"a": "benign", "b": "malicious"}, (
        "a world with no report.md is no longer skipped")


# ======================================================================================
# A planted world that fails a read leaves every reference set; the rest grades (A3, A12).
# ======================================================================================

@pytest.mark.parametrize("damage", ["report-is-a-symlink", "report-is-undecodable"])
def test_1234_malformed_planted_report_does_not_refuse_the_episode(tmp_path, damage):
    """With planted world c's report.md unreadable, the pass still grades world b against the
    control, records c as ungradable and malformed, and refuses nothing. episode.verdicts would
    refuse the episode (C15).

    "Against the control" is read off b's prompt, which carries the control's archive text. The
    contrast is the old reader over the same archive: `verdicts` raises EpisodeError, and the
    grade pass does not."""
    built = _build(tmp_path, damage, S.triad())
    report = built.world_dir("c") / "report.md"
    if damage == "report-is-a-symlink":
        S.plant_symlink(report, _host_report(tmp_path))
    else:
        _undecodable(report, tmp_path)
    judge = S.judge()

    S.grade(built, judge)

    _assert_malformed(built, "c", "report.md")
    assert not judge.called("c")
    assert judge.called("b"), "b was not graded beside the malformed c"
    assert _shows(judge.prompt_for("b"), "a"), "b was not graded against the control"
    _assert_no_host_text(built, judge)
    with pytest.raises(S.sym(S.EPISODE_MOD, "EpisodeError")):
        S.mod(S.EPISODE_MOD).verdicts(built.ep)


@pytest.mark.parametrize("case", [
    "oracle-store-is-a-symlink", "oracle-store-is-a-hard-link", "oracle-store-is-torn",
    "oracle-store-is-a-fifo", "served-ledger-is-a-symlink", "served-ledger-is-torn",
    "query-table-is-a-symlink", "query-table-is-torn", "ledger-row-without-a-call-id",
    "two-table-rows-sharing-one-call-id"])
def test_1234_reference_world_with_a_damaged_oracle_store_ledger_or_query_table(tmp_path, case):
    """A planted world whose context read fails is malformed (A3, A12), named by file and
    refusal, ungradable, and leaves every reference set. The read fails when the oracle store,
    served ledger, query table or any file its context needs is a link, torn or special; when a
    ledger row lacks the call id; or when two of the run's table rows share one call id. No other
    world's setup is refused and no host file is read (principle 1).

    c is damaged; b and d are healthy planted siblings. Each must be graded, must carry none of
    c's archive text, and must carry the other's. The links point at a file outside the episode
    holding a secret that no prompt and no record may contain."""
    built, names = _damaged(tmp_path, case, "c", _quad, _C_FIRST)
    judge = S.judge()

    with S.no_hang(60, f"grading beside a world whose {case}"):
        S.grade(built, judge)

    _assert_malformed(built, "c", *names)
    assert not judge.called("c"), "the malformed world was graded"
    _assert_out_of_references(judge, "c")
    _assert_no_host_text(built, judge)


@pytest.mark.parametrize("case", sorted(_SPECIAL))
def test_1234_reference_archive_files_are_special_files(tmp_path, case):
    """One bounded no-follow reader reads every file a run's context needs (A3), including
    `executed_queries.jsonl`, `alert.json`, `lessons_loaded.jsonl` and the gather summaries. A
    special file makes the run malformed with file and refusal named. It leaves every reference
    set, the pass never hangs and other worlds are graded.

    On main the table, the alert, the lessons record and the summaries degrade silently (OB5).
    The bound is OB5's alarm."""
    damage, names = _SPECIAL[case]
    built = _build(tmp_path, case, _quad())
    damage(built, "c", tmp_path)
    judge = S.judge()

    with S.no_hang(60, f"grading beside a world whose {case}"):
        S.grade(built, judge)

    _assert_malformed(built, "c", *names(built, "c"))
    assert not judge.called("c")
    _assert_out_of_references(judge, "c")


@pytest.mark.parametrize("stray", ["another-worlds-fact", "a-fact-no-world-declares"])
def test_1234_forged_rows_naming_another_worlds_fact_or_an_unserved_system(tmp_path, stray):
    """An oracle-store row that names a fact outside that world's own facts makes the world
    malformed (A3): named by file and cause, ungradable, out of every reference set. The row never
    enters another world's fact surface.

    c's store holds its own row and one stray row. The stray names b's fact `f-b` or a fact id
    no manifest entry declares (K5: checkable per directory against the world's own manifest
    facts). The stray row's marker reaches no prompt at all. The paired positive control is d's
    own forged row, which IS in d's prompt, so the built layer renders."""
    fact_id = "f-b" if stray == "another-worlds-fact" else "f-nowhere"
    mark = S.marker("c", "forged-stray")
    rows = [{"forged_id": "fg-c-1", "fact_id": "f-c", "system": "edr",
             "row": {"user": "alice", "event_id": "e-c-1", "note": S.marker("c", "forged-f-c")}},
            {"forged_id": "fg-c-9", "fact_id": fact_id, "system": "edr",
             "row": {"user": "alice", "event_id": "e-c-9", "note": mark}}]
    built = _build(tmp_path, stray, _quad(c={"forged": rows}))
    judge = S.judge()

    S.grade(built, judge)

    reason = _assert_malformed(built, "c", "forged.jsonl")
    assert S.label_re(fact_id).search(reason), (
        f"c's reason does not name the stray fact {fact_id!r}: {reason!r}")
    assert not judge.called("c")
    assert not any(mark in p for p in judge.prompts), "the stray forged row reached a prompt"
    _assert_out_of_references(judge, "c")
    assert S.marker("d", "forged-f-d") in judge.prompt_for("d"), (
        "control: d's own forged row is not in d's prompt, so the built layer never renders")


def test_1234_control_and_reference_report_with_two_disposition_lines_or_lookalikes(tmp_path):
    """A report with two disposition keys is refused by parse_report_text (A3). It returns
    disposition None with a reason, so the control is unusable (stamp) and a planted world
    malformed. All three callers take the no-headline arm (K4).

    The three callers are `read_report`, the archive's `read_archived_report` and the run
    record, the last of which is s_AM16's. Both key orders are driven. Today the last key wins
    (OB22, K4). The positive control is the same report with one key, which reads its headline."""
    rpt = S.mod(S.REPORT)
    fam = S.mod(S.JUDGE_FAMILY)
    single = tmp_path / "single" / "report.md"
    single.parent.mkdir(parents=True)
    single.write_text(S.report_text("malicious", body="one headline"), encoding="utf-8")
    assert rpt.read_report(single).disposition == "malicious", "control: one key is unreadable"
    for first, second in ORDERS:
        path = tmp_path / f"{first}-then-{second}" / "report.md"
        path.parent.mkdir(parents=True)
        S.second_disposition(path, first, second)
        read = rpt.parse_report_text(path.read_text(encoding="utf-8"))
        assert read.disposition is None, f"{first}/{second} read a headline: {read}"
        assert read.reason, f"{first}/{second} refused without a reason: {read}"
        assert rpt.read_report(path).disposition is None

    reference = _build(tmp_path, "reference", _quad())
    S.second_disposition(reference.world_dir("c") / "report.md")
    with S.mod("_io").bind(reference.ep) as bound:
        assert fam.read_archived_report(bound, S.conduct("c")).disposition is None
    judge = S.judge()
    S.grade(reference, judge)
    _assert_malformed(reference, "c", "report.md")
    _assert_out_of_references(judge, "c")

    control = _build(tmp_path, "control", _triad_ctl())
    S.second_disposition(control.world_dir(CTL) / "report.md")
    judge = S.judge()
    S.grade(control, judge)
    _assert_stamped(control, judge, CTL, "report.md")


def test_1234_world_setup_faults_while_its_siblings_are_judged(tmp_path):
    """B's unreadable file makes B malformed (A3): its row carries the named reason (the page
    shows it) and B leaves every reference set. C and D grade and enqueue normally. The user
    section carries B's blocked calls like every run's (A2), and carries B's setup fault only if
    it is a gap.

    B's investigation.md is undecodable bytes; its ledger is intact and holds a refused call, so
    the census can read it. C's and D's replies each file a finding on a two-run pair with the
    control, so "enqueue normally" is one defender row each."""
    b_blocked = S.refused_call()
    built = _build(tmp_path, "setup-fault", _quad(
        b={"calls": [S.CallRow(), S.oracle_call(fact_id="f-b", forged_id="fg-b-1"), b_blocked]}))
    _undecodable(built.world_dir("b") / "investigation.md", tmp_path)
    judge = S.judge({"c": _finding_reply("c", "a"), "d": _finding_reply("d", "a")})

    S.grade(built, judge)

    reason = _assert_malformed(built, "b", "investigation.md")
    assert not judge.called("b")
    _assert_out_of_references(judge, "b", focus=("c", "d"))
    for label in ("c", "d"):
        assert S.from_world(S.defender_queue(), label), (
            f"{label} did not enqueue beside the malformed b: {S.defender_queue()}")
    assert " ".join(reason.split()) in S.page_text(built), (
        f"the page does not show b's reason {reason!r}")
    assert _gap_of(built, "b", b_blocked), (
        f"b's blocked call is missing from the user section: {S.found_gaps(built)}")
    user_text = _yaml.safe_dump(S.user(built))
    assert "investigation.md" not in user_text, "b's setup fault (not a gap) is in the user section"


_AM15 = ["absent-layers-are-usable", "missing-report", "missing-investigation",
         "missing-query-table", "torn-lessons-record", "torn-alert",
         "control-missing-query-table"]


def _am15_family(tmp_path: Path, case: str) -> tuple[S.Built, str]:
    """The AM15 family for `case` and the file its refusal must name ("" for the usable case)."""
    if case == "absent-layers-are-usable":
        return _build(tmp_path, case, _triad_ctl(b={"lessons": False})), ""
    if case == "control-missing-query-table":
        built = _build(tmp_path, case, _triad_ctl())
        built.table_path(CTL).unlink()
        return built, "executed_queries.jsonl"
    over = {"missing-report": {"reached": None}, "missing-investigation": {"investigation": None}}
    built = _build(tmp_path, case, _quad(c=over.get(case, {})))
    named = {"missing-report": "report.md", "missing-investigation": "investigation.md",
             "missing-query-table": "executed_queries.jsonl",
             "torn-lessons-record": "lessons_loaded.jsonl", "torn-alert": "alert.json"}[case]
    if case == "missing-query-table":
        built.table_path("c").unlink()
    elif case == "torn-lessons-record":
        S.tear_jsonl(built.world_dir("c") / "lessons_loaded.jsonl")
    elif case == "torn-alert":
        (built.world_dir("c") / "alert.json").write_text('{"alert_id": "v2-', encoding="utf-8")
    return built, named


@pytest.mark.parametrize("case", _AM15)
def test_1234_am_run_file_absent_rather_than_damaged(tmp_path, case):
    """A file a run legitimately lacks is absent, not damaged (K2: absent is a state). A control
    with no oracle store (it has no planted facts), or a planted world with no lessons-loaded
    record (no lesson was loaded), is usable, and its prompt says the layer is absent. A required
    file that is missing (the report, the investigation, the query table), or any file that
    exists but is refused or torn, is a failed read and the run is malformed (A3; M1's 'missing
    its report').

    Not pinned: the sentence saying the layer is absent (main's render text, no ruling). The
    usable case pins that the run grades. A missing required file is asserted ungradable and
    named, and a present-but-torn file additionally malformed. A control missing its query table
    stamps the family."""
    built, named = _am15_family(tmp_path, case)
    judge = S.judge()

    S.grade(built, judge)

    if case == "absent-layers-are-usable":
        assert not built.oracle_path(CTL).parent.exists(), "fixture: the control has a store"
        assert not (built.world_dir("b") / "lessons_loaded.jsonl").exists()
        assert not _stamp(built), f"a control with no oracle store stamped: {_reason(built)!r}"
        assert judge.called("b"), "a world with no lessons record was refused"
        assert judge.called("c"), "a sibling of a store-less control was refused"
        assert not S.row(built, "b").get("ungradable"), S.row(built, "b")
        return
    if case == "control-missing-query-table":
        _assert_stamped(built, judge, CTL, named)
        return
    row = S.row(built, "c")
    assert row.get("ungradable") is True, f"c with its {named} damaged is gradable: {row}"
    assert named in _row_reason(row), f"c's reason does not name {named}: {row}"
    if case.startswith("torn-"):
        assert row.get(MALFORMED) is True, f"a torn {named} is not malformed: {row}"
    assert not judge.called("c")
    _assert_out_of_references(judge, "c")


@pytest.mark.parametrize("reader", ["drain", "questioner", "held-out", "trace-lesson",
                                    "page-primitives", "run-record", "grade-path"])
def test_1234_am_second_disposition_key_reaches_readers_outside_grading(tmp_path, reader):
    """parse_report_text refuses a second disposition key by returning disposition None with a
    reason (A3, K4), and every reader of a run's report takes its existing no-headline arm: the
    learning drain's normalize_disposition raises RunUnprocessable and dead-letters the run; the
    questioner's _captured_disposition, held_out's predicted_disposition, trace_lesson's
    _report_disposition, the page's parse_report and Run._report_fields read no headline; and the
    grade path marks the world malformed (NA09). The answer's 'sibling row' reader (section 7's
    spread) does not exist at 463833df (#1105 J3).

    One case per reader, each DRIVEN over a run whose report carries two keys in both orders,
    beside its positive control: the same reader over a single-key report reads the member.
    Dead-lettering is the drain's existing arm for RunUnprocessable, and is not re-driven here."""
    if reader == "grade-path":
        clean = _build(tmp_path, "single-key", S.triad())
        S.grade(clean, S.judge())
        assert not S.row(clean, "c").get("ungradable"), "control: a single-key c is ungradable"
        for first, second in ORDERS:
            built = _build(tmp_path, f"{first}-{second}", S.triad())
            S.second_disposition(built.world_dir("c") / "report.md", first, second)
            S.grade(built, S.judge())
            _assert_malformed(built, "c", "report.md")
        return

    unknown = S.sym(S.VOCAB, "UNKNOWN_DISPOSITION")
    unprocessable = S.sym(S.CONFIG, "RunUnprocessable")
    read: dict[str, Callable[[Path], Any]] = {
        "drain": lambda d: S.sym("learning.core.validate", "normalize_disposition")(
            d / "report.md"),
        "questioner": lambda d: S.sym("learning.branch.questioner", "_captured_disposition")(d),
        "held-out": lambda d: S.sym("evals.held_out", "predicted_disposition")(d),
        "trace-lesson": lambda d: S.sym("learning.ops.trace_lesson", "_report_disposition")(d),
        "page-primitives": lambda d: S.sym("scripts.visualize.visualize_primitives",
                                           "parse_report")(d).disposition,
        "run-record": lambda d: S.mod("run_repository").Run.at(d).record.disposition,
    }
    assert read[reader](finished_run(tmp_path, disposition="malicious", name="single")) \
        == "malicious", f"control: {reader} cannot read a single-key report"
    for first, second in ORDERS:
        run_dir = finished_run(tmp_path, disposition="benign", name=f"{first}-{second}")
        S.second_disposition(run_dir / "report.md", first, second)
        if reader == "drain":
            with pytest.raises(unprocessable):
                read[reader](run_dir)
            continue
        got = read[reader](run_dir)
        assert got in (None, unknown), (
            f"{reader} read a headline off a report with two keys ({first}, {second}): {got!r}")


def test_1234_am_world_refused_after_siblings_queued_and_on_rerun(tmp_path, monkeypatch):
    """A world recorded malformed after siblings queued carries its refusal on its row and leaves
    every reference set (A3). A later bare re-run derives the verdict again from the archive and
    refuses it again. An overflow-refused world carries the refusal reason. Overflow is a
    prompt-size fact, not a run-usability fact, so it stays a reference for c. A family with a
    usable control and no usable planted world grades nothing (A3) on every re-run.

    Three families. (1) c has two disposition keys while b grades and queues; the re-run is a
    second pass over the same archive with a fresh judge. (2) b's own facts are about three times
    the cap, so its computed sections alone overflow and it is refused, while c, whose own
    sections fit, is graded with b's archive text among its references. (3) b is malformed and c
    is cut short; two passes, no call in either."""
    first = _build(tmp_path, "queued-then-malformed", S.triad())
    S.second_disposition(first.world_dir("c") / "report.md")
    judge = S.judge({"b": _finding_reply("b", "a")})
    S.grade(first, judge)
    _assert_malformed(first, "c", "report.md")
    assert not judge.called("c"), judge.agent_ids
    assert S.from_world(S.defender_queue(), "b"), "b, graded before c was refused, queued nothing"
    assert not _shows(judge.prompt_for("b"), "c"), "the malformed c is still b's reference"
    assert _shows(judge.prompt_for("b"), "a"), "control: b's prompt carries no reference at all"
    record_path = first.ep / "judge.yaml"
    inode = record_path.stat().st_ino
    rerun = S.judge()
    S.grade(first, rerun)
    assert record_path.stat().st_ino != inode, (
        "the re-run made no final write, so its silence below proves nothing (A6)")
    _assert_malformed(first, "c", "report.md")
    assert not rerun.called("c"), "the re-run graded the malformed world"

    monkeypatch.setenv(S.CAP_KNOB, str(OVERFLOW_CAP))
    facts = [S.fact(f"f-b{i}", statement=f"{S.marker('b', f'fact{i}')} " +
                    "alice logged on to db-1 from a host she never used before. " * 60)
             for i in range(30)]
    overflow = _build(tmp_path, "overflow", S.triad(b={"facts": facts, "calls": [
        S.CallRow(), S.oracle_call(fact_id="f-b0", forged_id="fg-b-1")]}))
    judge = S.judge()
    S.grade(overflow, judge)
    assert not judge.called("b"), "a world whose computed sections overflow the cap was called"
    refused_row = S.row(overflow, "b")
    assert refused_row.get(S.COINED["row.measured"]) is False, f"b reads as measured: {refused_row}"
    reason = str(refused_row.get(S.COINED["row.not_measured_reason"]) or "")
    assert re.search(S.COINED["re.cap_reason"], reason, re.IGNORECASE), (
        f"b's row does not name the cap: {refused_row}")
    assert judge.called("c"), "c was not graded beside the overflow-refused b"
    assert _shows(judge.prompt_for("c"), "b") or S.marker("b", "fact0") in judge.prompt_for("c"), (
        "the overflow-refused b left c's references")

    nothing = _build(tmp_path, "nothing-usable", S.triad(c={"run_end": dict(CUT_SHORT)}))
    S.second_disposition(nothing.world_dir("b") / "report.md")
    for attempt in ("first pass", "re-run"):
        judge = S.judge()
        S.grade(nothing, judge)
        assert judge.calls == 0, f"{attempt}: no usable planted world, yet {judge.agent_ids}"


# ======================================================================================
# A row in b's served file that is not b's (A3, A12, NA03 (b), X13) — on the REAL path.
# ======================================================================================

def _ledger_file(ep: Path, label: str, token: str) -> Path:
    return ep / "served" / f"{S.world_token(label, episode_token=token)}.jsonl"


def test_1234_am_foreign_rows_in_a_worlds_served_file(tmp_path):
    """A row in b's served file that is not b's makes b's ledger read not well-formed (A3, A12;
    NA03 (b), X13: no reader skips such a row). Such a row has no world id, another world's id,
    no call id, or another run's call id. b is then malformed: a planted world is ungradable, named
    by file and refusal, and out of every reference set, and a control stamps the family not
    graded. b's found-gap census entry is named unread with its cause (NA04). Such a row never
    pairs with b's table and never enters b's found gaps. Unmapped is only a ledger row carrying
    b's own call id that is in no table row of b (A12). A ledger file in `served/` for a label the
    manifest does not declare is not a run and is read by nothing, the census included (AP-12).

    One real launch. Its archive is copied per variant and the row is appended to the copy's
    archived served file. Ids are read off the real rows, and only the unmapped row mints b's
    spelling. Each foreign row carries a refused call no run made (`FOREIGN`), so a reader that
    kept it would list it as a gap. The paired positive control is the unedited archive plus the
    undeclared label's file: b grades, and its own refused call IS a found gap."""
    real = S.real_family(tmp_path)
    token = real.token
    refused_b = next(r for r in real.ledger_rows("b") if r.get("source") == "refused")
    refused_c = next(r for r in real.ledger_rows("c") if r.get("source") == "refused")
    own_b = {**refused_b, "params": dict(FOREIGN), S.CALL_ID: S.call_id("b", 98, episode_token=token)}
    foreign = {
        "no-world-id": {k: v for k, v in own_b.items() if k != "world_id"},
        "another-worlds-id": {**refused_c, "params": dict(FOREIGN)},
        "no-call-id": {k: v for k, v in own_b.items() if k != S.CALL_ID},
        "another-runs-call-id": {**own_b, S.CALL_ID: refused_c.get(S.CALL_ID)},
    }

    for name, row in foreign.items():
        ep = S.copy_episode(real.ep, tmp_path / f"variant-{name}")
        S.rewrite_jsonl(_ledger_file(ep, "b", token), lambda rows, row=row: [*rows, row])
        judge = S.judge()
        S.grade(ep, judge)
        _assert_malformed(ep, "b", _ledger_file(ep, "b", token).name)
        assert not judge.called("b"), f"{name}: the malformed b was graded"
        assert judge.called("c"), f"{name}: c was not graded beside the malformed b"
        c_prompt = judge.prompt_for("c")
        assert S.marker("b", "report") not in c_prompt, f"{name}: b is still c's reference"
        assert S.marker("a", "report") in c_prompt, f"{name}: control: c has no reference at all"
        unread = [e for e in S.found_gaps(ep) if _names_run(e, "b") and e.get(UNREAD)]
        assert unread, f"{name}: b's census entry is not named unread: {S.found_gaps(ep)}"
        assert not any(_carries(e, FOREIGN) for e in S.found_gaps(ep)), (
            f"{name}: the foreign row entered the found gaps: {S.found_gaps(ep)}")

    unmapped = S.copy_episode(real.ep, tmp_path / "variant-unmapped")
    S.rewrite_jsonl(_ledger_file(unmapped, "b", token), lambda rows: [*rows, {
        **refused_b, "params": dict(GHOST_PARAMS), S.CALL_ID: S.call_id("b", 99, episode_token=token)}])
    judge = S.judge()
    S.grade(unmapped, judge)
    assert judge.called("b"), "an unmapped row of b's own stopped b being graded"
    assert not S.row(unmapped, "b").get("ungradable"), (
        f"an unmapped row of b's own made b unusable: {S.row(unmapped, 'b')}")

    control_file = S.copy_episode(real.ep, tmp_path / "variant-control")
    refused_a = next(r for r in real.ledger_rows("a") if r.get("source") == "refused")
    S.rewrite_jsonl(_ledger_file(control_file, "a", token), lambda rows: [*rows, {
        k: v for k, v in {**refused_a, "params": dict(FOREIGN)}.items() if k != "world_id"}])
    judge = S.judge()
    S.grade(control_file, judge)
    _assert_stamped(control_file, judge, _ledger_file(control_file, "a", token).name)

    clean = S.copy_episode(real.ep, tmp_path / "variant-clean")
    S.rewrite_jsonl(_ledger_file(clean, GHOST, token), lambda _rows: [{
        **refused_b, "world_id": S.world_token(GHOST, episode_token=token),
        "params": dict(GHOST_PARAMS)}])
    judge = S.judge()
    S.grade(clean, judge)
    assert judge.called("b"), "control: the unedited archive did not grade b"
    assert not S.row(clean, "b").get("ungradable"), S.row(clean, "b")
    assert _gaps(clean, "b", "edr", "lookup", S.DENIED_LOOKUP), (
        f"control: b's own refused call is not a found gap: {S.found_gaps(clean)}")
    assert not any(_carries(e, GHOST_PARAMS) or _names_run(e, GHOST)
                   for e in S.found_gaps(clean)), "the undeclared label's file was read"


# ======================================================================================
# A box that edits its own query table after the run (R3 (a), OB10; I-4, I-5): fail closed.
# ======================================================================================

#: The seeded prefix every hand-built table opens with: an ordinary pre-branch row and J3's
#: inherited denial, identical in every run's table and carrying no id of any run (A12).
_PREFIX = [S.CallRow(params=S.query_params("user:prebranch"), inherited=True),
           S.inherited_denial()]
#: J3's found-gap key: the family's entry (A14), listed once.
_J3_KEY = (S.COINED["found.family_run"], "edr", "lookup",
           S.canonical(_PREFIX[1].the_params))


def _edit_prefix(edit: str) -> Callable[[list[dict]], list[dict]]:
    """What a box's rewrite of its own archived table does to the inherited rows (OB10: the
    run dir is the box's rw bind): drop its copy of J3's row, add an id-less row the source
    never wrote, or alter an inherited row's params."""
    def apply(rows: list[dict]) -> list[dict]:
        assert S.CALL_ID not in rows[0], "fixture: the table does not open with inherited rows"
        assert S.CALL_ID not in rows[1], "fixture: the table does not open with inherited rows"
        if edit == "missing":
            return [rows[0], *rows[2:]]
        if edit == "extra":
            return [*rows[:2], {**rows[0], "params": dict(FOREIGN)}, *rows[2:]]
        return [{**rows[0], "params": dict(FOREIGN)}, *rows[1:]]
    return apply


def _j3_and_ordinary_reply(built: S.Built) -> dict:
    """b files an ordinary two-run finding (it queues) and one resting on J3's inherited row in
    b and in the control (`a`): gap-only while J3's row is identified (A14)."""
    return S.world_reply("lead-quality", ["idp"], investigator=[
        S.inv(contrast=[S.conduct("b"), S.conduct("a")], claim=S.marker("b", "ordinary")),
        S.inv(contrast=[built.table("b", 1), built.table("a", 1)], claim=S.marker("b", "j3"))])


def _j3_listed_once(where: Any) -> bool:
    return [S.gap_key(e) for e in S.found_gaps(where)].count(_J3_KEY) == 1


@pytest.mark.parametrize("edit", ["missing", "extra", "altered"])
def test_1234_box_edits_the_inherited_rows_of_its_own_query_table(tmp_path, edit):
    """The inherited prefix must be identical across every readable query table: a table whose
    inherited rows differ from the others' (one missing, one extra, one altered) is a failed
    read under A3 (R3 (a), human 2026-10-12; OB10: a box can rewrite its own table after the
    run). A planted world is malformed, named by the file, and leaves every reference set; a
    control's stamps the family not graded; in a pair family the two tables disagree with each
    other, so both are refused and the family is stamped. A box's edit therefore never
    un-identifies J3's row: it is still listed once as the family's found gap, from the readable
    tables, and a finding resting on it stays gap-only (I-4).

    Hand-built, every table opening with the same two inherited rows (an ordinary pre-branch
    row and J3's denial); the stamped arms run first, since a stamp is read against empty
    queues. The paired positive control is the unedited family: c grades and J3 is listed
    once."""
    control = _build(tmp_path, f"control-{edit}", _triad_ctl(), inherited=_PREFIX)
    S.rewrite_jsonl(control.table_path(CTL), _edit_prefix(edit))
    judge = S.judge({"b": _finding_reply("b", CTL)})
    S.grade(control, judge)
    _assert_stamped(control, judge, CTL, "executed_queries.jsonl")

    pair = _build(tmp_path, f"pair-{edit}", _ctl(S.pair()), inherited=_PREFIX)
    S.rewrite_jsonl(pair.table_path("b"), _edit_prefix(edit))
    judge = S.judge({"b": _finding_reply("b", CTL)})
    S.grade(pair, judge)
    _assert_stamped(pair, judge, CTL, "executed_queries.jsonl")

    edited = _build(tmp_path, f"planted-{edit}", _quad(), inherited=_PREFIX)
    S.rewrite_jsonl(edited.table_path("c"), _edit_prefix(edit))
    judge = S.judge({"b": _j3_and_ordinary_reply(edited)})
    S.grade(edited, judge)
    _assert_malformed(edited, "c", "executed_queries.jsonl")
    assert not judge.called("c"), "the world whose table differs was graded"
    _assert_out_of_references(judge, "c")
    assert _j3_listed_once(edited), (
        f"c's edit un-identified J3's row: {S.found_gaps(edited)}")
    j3_finding, ordinary = edited.finding_id("b", 0, 1), edited.finding_id("b", 0, 0)
    assert S.lane_of(edited, j3_finding) == S.LANES["user_record"], "J3's finding left gap-only"
    assert S.from_world(S.defender_queue(), "b"), "b's ordinary finding did not queue"
    assert all(r.get("finding_id") != j3_finding for r in S.defender_queue()), (
        "b's J3 finding queued")
    assert S.lane_of(edited, ordinary) == S.LANES["defender"]

    clean = _build(tmp_path, "clean", _quad(), inherited=_PREFIX)
    judge = S.judge({"b": _j3_and_ordinary_reply(clean)})
    S.grade(clean, judge)
    assert judge.called("c"), "control: the unedited c was not graded"
    assert not S.row(clean, "c").get("ungradable"), f"control: {S.row(clean, 'c')}"
    assert _j3_listed_once(clean), f"control: J3 is not listed once: {S.found_gaps(clean)}"


#: The column a box's rewrite changes on its own table row, and the value it writes.
_DISAGREE = {"system": "siem-x", "verb": "lookup", "params": FOREIGN}


def _disagree(label: str, column: str) -> Callable[[list[dict]], list[dict]]:
    """Rewrite the table row carrying `label`'s first call id so its (system, verb, params)
    no longer matches the ledger row that id joins."""
    cid = S.call_id(label, 0)

    def apply(rows: list[dict]) -> list[dict]:
        hits = [i for i, r in enumerate(rows) if r.get(S.CALL_ID) == cid]
        assert len(hits) == 1, f"fixture: one table row carries {cid}: {hits}"
        assert rows[hits[0]].get(column) != _DISAGREE[column], "fixture: nothing would change"
        return [{**r, column: _DISAGREE[column]} if i == hits[0] else r
                for i, r in enumerate(rows)]
    return apply


@pytest.mark.parametrize("column", sorted(_DISAGREE))
def test_1234_call_id_joins_a_ledger_row_and_a_table_row_that_disagree(tmp_path, column):
    """Where one host-written call id joins a served-ledger row and a query-table row whose
    (system, verb, params) disagree, the read is not well-formed: a failed read under A3 (R3
    (a), human 2026-10-12; I-5; OB10: the table is the box's to rewrite, the ledger the
    host's). A planted world is malformed, named by the joined call id, and leaves every
    reference set; a control stamps the family not graded, naming the id.

    One table row of c (then of the control) has the named column rewritten after the run. The
    paired positive control is the unedited family: c grades."""
    clean = _build(tmp_path, "clean", _quad())
    judge = S.judge()
    S.grade(clean, judge)
    assert judge.called("c"), "control: the unedited c was not graded"
    assert not S.row(clean, "c").get("ungradable"), f"control: {S.row(clean, 'c')}"

    edited = _build(tmp_path, f"planted-{column}", _quad())
    S.rewrite_jsonl(edited.table_path("c"), _disagree("c", column))
    judge = S.judge()
    S.grade(edited, judge)
    _assert_malformed(edited, "c", S.call_id("c", 0))
    assert not judge.called("c"), "the world whose rows disagree was graded"
    _assert_out_of_references(judge, "c")

    control = _build(tmp_path, f"control-{column}", _triad_ctl())
    S.rewrite_jsonl(control.table_path(CTL), _disagree(CTL, column))
    judge = S.judge({"b": _finding_reply("b", CTL)})
    S.grade(control, judge)
    _assert_stamped(control, judge, CTL, S.call_id(CTL, 0))


# ======================================================================================
# Labels the pointer grammar or the family call would collide with: refused at the manifest.
# ======================================================================================

def _assert_label_refused(tmp_path: Path, label: str) -> None:
    built = _build(tmp_path, "refused-label", S.triad())
    _relabel(built, "c", label)
    judge = S.judge()
    err = S.grade_refused(built, judge)
    assert repr(label) in str(err), f"{label!r}: the refusal does not quote the label: {err!r}"
    assert not (built.ep / "judge.yaml").exists(), f"{label!r}: the family was loaded"
    assert judge.calls == 0, f"{label!r}: the pass went on to call {judge.agent_ids}"


def _assert_label_loads(tmp_path: Path, label: str) -> None:
    built = _build(tmp_path, "valid-label", S.triad())
    _relabel(built, "c", label)
    S.grade(built, S.judge())
    assert (built.ep / "judge.yaml").is_file(), f"control: the valid label {label!r} was refused"


@pytest.mark.parametrize("label", ["b#1", "b.c", "..", ".", "b/c", "b c", "B", "b-c", "-b", "_b"])
def test_1234_world_label_that_collides_with_the_pointer_grammar(tmp_path, label):
    """A world label failing the token grammar is refused at the manifest load. The family is not
    loaded and the pass stops loudly (principle 2).

    The label is written into the archived manifest after the build, so no path is ever made
    from it. The paired positive control is a grammar-valid label (`c_2`), which loads."""
    _assert_label_refused(tmp_path, label)
    _assert_label_loads(tmp_path, "c_2")


@pytest.mark.parametrize("label", ["family", "base", "family_3", "Family", "FAMILY_2", "Base"])
def test_1234_reference_run_with_the_same_label_as_a_family_or_draw_agent(tmp_path, label):
    """A reserved or colliding world label is refused at the manifest load.

    Reserved labels and their casings would share an agent id, a wire-log file or a draw
    directory with the family call. The paired positive control is a near-reserved but legal
    label (`familyx`), which loads."""
    _assert_label_refused(tmp_path, label)
    _assert_label_loads(tmp_path, "familyx")
