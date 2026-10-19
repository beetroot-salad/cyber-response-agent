"""#1234 judge contrast: control/reference usability checks and damaged-archive handling."""
from __future__ import annotations

import dataclasses
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from defender import _yaml
from defender.tests.judge_contrast_1234 import _spec1234 as S


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
#: A blocked call no run of the family made: if a reader ever kept a foreign row carrying it,
#: it would surface as a found gap.
FOREIGN = {"entity": "foreign-1234"}
GHOST_PARAMS = {"entity": "ghost-1234"}
#: A key no recording holds, so the call reaches the estate adapter (`Estate1234.break_write`).
FRESH = S.query_params("user:bob")
#: A world label the manifest does not declare.
GHOST = "ghost"
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
    """`first`, then a table-only reject joined to THE SAME call id: two table rows of the run
    sharing one id (A12). The ledger holds one row, so only the table check can fire.

    #1255 G4/G6: a table row carries no id; the host-only call-join record names one per
    `(lead_id, seq)`. So two table rows share one id by sharing one key — the reject is written
    at `first`'s seq on `first`'s lead (the world's first row: these builds have no inherited
    rows), the shape a box leaves by duplicating a line of its own table. The join record itself
    stays well-formed (one line for the key), so the fault is the table's."""
    shared = S.call_id(label, 0)
    return [dataclasses.replace(first, call_id=shared),
            S.CallRow(params=S.query_params("user:carol"), source=None, lead=first.lead,
                      exit_code=S.REJECT_EXIT, call_id=shared, seq=0)]


def _missing_id_calls(first: S.CallRow) -> list[S.CallRow]:
    """`first`, then a ledger-only row carrying NO call id, which A3's read refuses. It writes
    no table row: an id-less table row would read as an inherited row the other tables lack,
    a failed read of the TABLE under R3 (a), and this case pins the ledger's own check."""
    return [first, S.CallRow(params=S.query_params("user:carol"), call_id=None, table=False)]


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


@pytest.mark.parametrize("fact_id", [[], {}, ["f-c"], {"id": "f-c"}, None, 1])
def test_1234_malformed_forged_fact_id_excludes_only_its_world(tmp_path, fact_id):
    built = S.family(tmp_path, S.triad(d=_D))
    S.rewrite_jsonl(built.oracle_path("c"),
                    lambda rows: [{**row, "fact_id": fact_id} for row in rows])
    judge = S.judge({"b": S.world_reply("lead-quality", ["idp"], investigator=[
        S.inv(contrast=[S.conduct("b"), S.conduct("a")])])})
    S.grade(built, judge)
    _assert_malformed(built, "c", "forged.jsonl")
    assert "fact_id" in S.row(built, "c")[UNGRADABLE_REASON]
    assert not judge.called("c")
    _assert_out_of_references(judge, "c")
    assert judge.called("b")
    assert S.from_world(S.defender_queue(), "b")


@pytest.mark.parametrize("field", ["system", "verb", "lead_id", "query_id"])
@pytest.mark.parametrize("value", [[], None, 1])
def test_1234_malformed_unserved_query_excludes_only_its_world(tmp_path, field, value):
    """Unserved calls must pass the archive boundary before computed views use their fields."""
    built = S.family(tmp_path, S.triad(c={"calls": [S.CallRow(source=None)]}, d=_D))
    S.rewrite_jsonl(built.table_path("c"),
                    lambda rows: [{**row, field: value} for row in rows])
    judge = S.judge({"b": S.world_reply("lead-quality", ["idp"], investigator=[
        S.inv(contrast=[S.conduct("b"), S.conduct("a")])])})
    S.grade(built, judge)
    _assert_malformed(built, "c", "executed_queries.jsonl")
    assert field in S.row(built, "c")[UNGRADABLE_REASON]
    assert not judge.called("c")
    _assert_out_of_references(judge, "c")
    assert S.from_world(S.defender_queue(), "b")


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


def test_1234_control_not_archived_stamps_the_family_not_graded(tmp_path):
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


@pytest.mark.parametrize("case", [
    "report-with-no-usable-disposition", "report-with-a-look-alike-disposition",
    "report-with-a-second-disposition-key", "report-is-a-symlink", "alert-is-a-fifo",
    "ledger-row-without-a-call-id", "two-table-rows-sharing-one-call-id"])
def test_1234_control_malformed_stamps_the_family_not_graded(tmp_path, case):
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
    built, names = _damaged(tmp_path, case, CTL, _triad_ctl, _CTL_FIRST)
    judge = S.judge({"b": _finding_reply("b", CTL), "c": _finding_reply("c", CTL)})

    S.grade(built, judge)

    _assert_stamped(built, judge, CTL, *names)
    _assert_no_host_text(built, judge)


@pytest.mark.parametrize("state", ["no-investigation", "short-gather-summaries"])
def test_1234_control_missing_investigation_or_short_gather_summaries(tmp_path, state):
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


def test_1234_control_pushed_to_an_unusable_close_by_the_alert(tmp_path):
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


@pytest.mark.parametrize("damage", ["report-is-a-symlink", "report-is-undecodable"])
def test_1234_malformed_planted_report_does_not_refuse_the_episode(tmp_path, damage):
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
    built, names = _damaged(tmp_path, case, "c", _quad, _C_FIRST)
    judge = S.judge()

    with S.no_hang(60, f"grading beside a world whose {case}"):
        S.grade(built, judge)

    _assert_malformed(built, "c", *names)
    assert not judge.called("c"), "the malformed world was graded"
    _assert_out_of_references(judge, "c")
    _assert_no_host_text(built, judge)


@pytest.mark.parametrize("stray", ["another-worlds-fact", "a-fact-no-world-declares"])
def test_1234_forged_rows_naming_another_worlds_fact_or_an_unserved_system(tmp_path, stray):
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


def test_1234_world_setup_faults_while_its_siblings_are_judged(tmp_path):
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


def _ledger_file(ep: Path, label: str, token: str) -> Path:
    return ep / "served" / f"{S.world_token(label, episode_token=token)}.jsonl"


def test_1234_am_foreign_rows_in_a_worlds_served_file(tmp_path):
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


#: The seeded prefix every hand-built table opens with: an ordinary pre-branch row and J3's
#: inherited denial, identical in every run's table and carrying no id of any run (A12).
_PREFIX = [S.CallRow(params=S.query_params("user:prebranch"), inherited=True),
           S.inherited_denial()]
#: J3's found-gap key: the family's entry (A14), listed once.
_J3_KEY = (S.COINED["found.family_run"], "edr", "lookup",
           S.canonical(_PREFIX[1].the_params))


def _edit_prefix(edit: str, built: S.Built, label: str) -> Callable[[list[dict]], list[dict]]:
    """What a box's rewrite of world `label`'s own archived table does to the inherited rows
    (OB10: the run dir is the box's rw bind): drop its copy of J3's row, add an id-less row the
    source never wrote, or alter an inherited row's params. (#1255 G6: a row is inherited when
    the run's host-only call-join record names no id for its `(lead_id, seq)`.)"""
    own = built.own_keys(label)

    def apply(rows: list[dict]) -> list[dict]:
        assert own, f"fixture: world {label}'s call-join record names none of its own rows"
        for r in rows[:2]:
            assert (r.get("lead_id"), r.get("seq")) not in own, (
                "fixture: the table does not open with inherited rows")
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
    control = _build(tmp_path, f"control-{edit}", _triad_ctl(), inherited=_PREFIX)
    S.rewrite_jsonl(control.table_path(CTL), _edit_prefix(edit, control, CTL))
    judge = S.judge({"b": _finding_reply("b", CTL)})
    S.grade(control, judge)
    _assert_stamped(control, judge, CTL, "executed_queries.jsonl")

    pair = _build(tmp_path, f"pair-{edit}", _ctl(S.pair()), inherited=_PREFIX)
    S.rewrite_jsonl(pair.table_path("b"), _edit_prefix(edit, pair, "b"))
    judge = S.judge({"b": _finding_reply("b", CTL)})
    S.grade(pair, judge)
    _assert_stamped(pair, judge, CTL, "executed_queries.jsonl")

    edited = _build(tmp_path, f"planted-{edit}", _quad(), inherited=_PREFIX)
    S.rewrite_jsonl(edited.table_path("c"), _edit_prefix(edit, edited, "c"))
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


def _disagree(built: S.Built, label: str, column: str) -> Callable[[list[dict]], list[dict]]:
    """Rewrite the table row joined to `label`'s first call id so its (system, verb, params)
    no longer matches the ledger row that id joins. (#1255 G6: the row is found through the
    host-only call-join record, by its `(lead_id, seq)` — the table carries no id.)"""
    cid = S.call_id(label, 0)
    hits = built.lines_of_call(label, cid)

    def apply(rows: list[dict]) -> list[dict]:
        assert len(hits) == 1, f"fixture: one table row is joined to {cid}: {hits}"
        assert rows[hits[0]].get(column) != _DISAGREE[column], "fixture: nothing would change"
        return [{**r, column: _DISAGREE[column]} if i == hits[0] else r
                for i, r in enumerate(rows)]
    return apply


@pytest.mark.parametrize("column", sorted(_DISAGREE))
def test_1234_call_id_joins_a_ledger_row_and_a_table_row_that_disagree(tmp_path, column):
    clean = _build(tmp_path, "clean", _quad())
    judge = S.judge()
    S.grade(clean, judge)
    assert judge.called("c"), "control: the unedited c was not graded"
    assert not S.row(clean, "c").get("ungradable"), f"control: {S.row(clean, 'c')}"

    edited = _build(tmp_path, f"planted-{column}", _quad())
    S.rewrite_jsonl(edited.table_path("c"), _disagree(edited, "c", column))
    judge = S.judge()
    S.grade(edited, judge)
    _assert_malformed(edited, "c", S.call_id("c", 0))
    assert not judge.called("c"), "the world whose rows disagree was graded"
    _assert_out_of_references(judge, "c")

    control = _build(tmp_path, f"control-{column}", _triad_ctl())
    S.rewrite_jsonl(control.table_path(CTL), _disagree(control, CTL, column))
    judge = S.judge({"b": _finding_reply("b", CTL)})
    S.grade(control, judge)
    _assert_stamped(control, judge, CTL, S.call_id(CTL, 0))
