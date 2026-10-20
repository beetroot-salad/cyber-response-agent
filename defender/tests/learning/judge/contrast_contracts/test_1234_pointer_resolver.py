"""#1234 judge contrast: evidence/contrast pointer resolution."""
from __future__ import annotations

from defender.tests.support.learning.branch import _triplet_947 as T

import json
import os
import shutil
import stat
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

import pytest

from defender.tests.learning.judge.contrast_contracts import _spec1234 as S

DEFENDER = S.LANES["defender"]
QUESTIONER = S.LANES["questioner"]
USER_RECORD = S.LANES["user_record"]
UNRESOLVED = S.LANES["dropped_unresolved"]
OTHER_RUN = S.LANES["dropped_other_run"]
NO_PAIR = S.LANES["dropped_no_pair"]
CITATIONS = S.RULED["row.citations"]
MALFORMED = S.COINED["row.malformed"]
UNGRADABLE = S.COINED["row.ungradable_reason"]

#: The context fragment every scenario cites (pre-flight's record carries the key).
OUTCOME_CTX = S.outcome_ptr("not_replayable")
#: A shown samples section: the default family gives every served system one of real answers.
SAMPLES_CTX = S.samples_ptr("idp")
#: The plan's family-level part (the manifest's `discriminator`), which names no run (A15).
PLAN_FAMILY = S.plan_ptr(None)
#: A row the family's shared capture holds, so `served/base.jsonl#0` names a real line.
BASE_ROWS = [{"system": "idp", "verb": "query", "params": {"q": "user:alice"},
              "payload_text": json.dumps({"rows": []}), "source": "passthrough"}]

#: Seconds a pass may take before the watchdog calls it blocked (a normal pass takes ~1 s).
_WATCHDOG_S = 45


def _claim(label: str, tag: str) -> str:
    """A finding's claim, carrying a unique marker so a test can ask which surface it reached."""
    return f"the lead was never revisited {S.marker(label, tag)}"


def _inv(contrast: Iterable[str], *, label: str = "b", tag: str = "inv") -> dict:
    return S.inv(contrast=list(contrast), claim=_claim(label, tag))


def _wf(evidence: Iterable[str], *, bucket: str = "mislabelled", label: str = "b",
        tag: str = "wf", systems: Sequence[str] = ("idp",)) -> dict:
    return S.wf(bucket, evidence=list(evidence), systems=systems, claim=_claim(label, tag))


def _reply(*, investigator: Sequence[dict] = (), world: Sequence[dict] = (),
           bucket: str = "lead-quality", systems: Sequence[str] = ("idp",)) -> dict:
    return S.world_reply(bucket, list(systems), investigator=investigator, world=world)


def _run(built: Any, replies: dict, *, draws: int = 1, family: Any = None) -> Any:
    """Grade `built` once (under the watchdog) with `replies` routed per world; returns the seam."""
    kw = {} if family is None else {"family_default": family}
    seam = S.judge(replies, **kw)
    with S.no_hang(_WATCHDOG_S, "the pass"):
        S.grade(built, seam, draws=draws)
    return seam


def _row_on(queue: list[dict], finding_id: str) -> dict | None:
    hits = [r for r in queue if r.get("finding_id") == finding_id]
    return hits[0] if hits else None


def _cites(finding_id: str) -> set[str] | None:
    """The citations of the defender row queued for `finding_id` (`None`: no row queued)."""
    row = _row_on(S.defender_queue(), finding_id)
    return None if row is None else set(row.get(CITATIONS) or [])


def _surfaces(built: Any, text: str) -> list[str]:
    """Every output a finding's text could reach that holds `text`: both queues and the user
    record."""
    out = []
    if any(text in json.dumps(r, default=str) for r in S.defender_queue()):
        out.append("defender queue")
    if any(text in json.dumps(r, default=str) for r in S.questioner_queue()):
        out.append("questioner queue")
    if S.in_user_record(built, text):
        out.append("user record")
    return out


def _served(built: Any, label: str, i: int) -> str:
    """The served-ledger pointer at world `label`'s `i`-th own call."""
    return built.served(label, built.served_row(label, i))


def _table(built: Any, label: str, i: int) -> str:
    """The query-table pointer at world `label`'s `i`-th own call."""
    return built.table(label, built.own_row(label, i))


def _plant_device(path: Path) -> Path:
    """Replace `path` with a character device (1, 3 — a null device); skips only this arm when
    the box may not make one."""
    path = Path(path)
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    elif path.exists() or path.is_symlink():
        path.unlink()
    try:
        os.mknod(path, stat.S_IFCHR | 0o600, os.makedev(1, 3))
    except OSError as refused:
        pytest.skip(f"this box cannot make a device node ({refused!r}); the FIFO and directory "
                    "arms carry the parity")
    return path


def _d_spec(**over: Any) -> dict[str, Any]:
    """A fourth planted world `d` with one call of its own."""
    spec: dict[str, Any] = {
        "role": "D", "calls": [S.CallRow(system="siem-x", verb="lookup",
                                         params={"entity": "svc-9"})]}
    spec.update(over)
    return spec


def _with_d(**over: Any) -> list[Any]:
    """The default triad plus the fourth world `d`."""
    return S.triad(d=_d_spec(**over))


def _refusal_calls(**more: dict[str, Any]) -> list[Any]:
    """b: passthrough, altered answer, refused call; a: passthrough, the same refused call."""
    return S.triad(
        a={"calls": [S.CallRow(), S.refused_call()]},
        b={"calls": [S.CallRow(), S.oracle_call(fact_id="f-b", forged_id="fg-b-1"),
                     S.refused_call()]},
        **more)


def _failed_d() -> dict[str, Any]:
    """`d` as an O5-failed world: its world record on disk and no archive."""
    return _d_spec(archived=False, world_record=S.sym(S.OUTCOME, "DID_NOT_FINISH"))


#: How the probe pointer is filed: as the reference half of b's pair, or riding beside a
#: resolving pair (a built-layer pointer is never a half, so it rides).
HALF, RIDE = "half", "ride"


def _probe(built: Any, pointer: str, filed: str) -> dict[str, Any]:
    """Grade with b's reply filing `pointer` three ways, and read back what the resolver
    decided:

    * finding 0, `probe`: an investigator finding citing `pointer` as its reference half beside
      b's report (`half`), or beside the resolving pair of b's and the control's reports
      (`ride`);
    * finding 1, `sibling`: a resolving pair of b's investigation and the control's report — the
      in-reply positive control that b was graded and its rows queue;
    * finding 2, `alone`: a world finding citing `pointer` only — `pointers unresolved` when it
      does not resolve, `names only another run` when it resolves into another run.

    Also read back which outputs (both queues, the user record) each finding's claim reached.
    """
    probe = ([S.conduct("b"), pointer] if filed == HALF
             else [S.conduct("b"), S.conduct("a"), pointer])
    reply = _reply(investigator=[_inv(probe, tag="probe"),
                                 _inv([S.conduct("b", "investigation.md"), S.conduct("a")],
                                      tag="sibling")],
                   world=[_wf([pointer], tag="alone")])
    _run(built, {"b": reply})
    fid = [built.finding_id("b", 0, i) for i in range(3)]
    return {"probe": S.lane_of(built, fid[0]), "sibling": S.lane_of(built, fid[1]),
            "alone": S.lane_of(built, fid[2]), "cites": _cites(fid[0]),
            "reached": {t: _surfaces(built, S.marker("b", t))
                        for t in ("probe", "sibling", "alone")}}


def _probe_expected(pointer: str, filed: str, *, resolves: bool) -> dict[str, Any]:
    """What `_probe` must read back for a pointer into reference run c (or d) that does or does
    not resolve (A1, A13, A15). The lone world finding is dropped either way (unresolved, or
    naming only another run), so its claim reaches no output."""
    queued = ["defender queue"]
    if filed == HALF:
        return {"probe": DEFENDER if resolves else NO_PAIR, "sibling": DEFENDER,
                "alone": OTHER_RUN if resolves else UNRESOLVED,
                "cites": {S.conduct("b"), pointer} if resolves else None,
                "reached": {"probe": queued if resolves else [], "sibling": queued,
                            "alone": []}}
    pair = {S.conduct("b"), S.conduct("a")}
    return {"probe": DEFENDER, "sibling": DEFENDER,
            "alone": OTHER_RUN if resolves else UNRESOLVED,
            "cites": pair | {pointer} if resolves else pair,
            "reached": {"probe": queued, "sibling": queued, "alone": []}}


def _boundary(built: Any, where: str) -> tuple[Path, str, str]:
    """One R3 boundary of reference run c: (the file on disk, the pointer naming it, how the
    pointer is filed). g06/g07 use the conduct file, oracle store, served ledger and query
    table (the manifest is its own branch); g08 adds c's report."""
    if where == "conduct":
        return built.world_dir("c") / "investigation.md", S.conduct("c", "investigation.md"), HALF
    if where == "report":
        return built.world_dir("c") / "report.md", S.conduct("c"), HALF
    if where == "oracle":
        return built.oracle_path("c"), S.oracle_ptr("c"), RIDE
    if where == "served":
        return built.ledger_path("c"), _served(built, "c", 0), HALF
    if where == "table":
        return built.table_path("c"), _table(built, "c", 0), HALF
    raise AssertionError(f"no boundary {where!r}")


def _damage(tmp_path: Path, path: Path, kind: str) -> None:
    """Plant one kind of damage at `path`."""
    if kind == "oversize":
        S.plant_oversize(path)
    elif kind == "fifo":
        S.plant_fifo(path)
    elif kind == "dir":
        S.plant_dir(path)
    elif kind == "device":
        _plant_device(path)
    elif kind == "torn":
        S.tear_jsonl(path)
    elif kind == "second_disposition":
        S.second_disposition(path)
    elif kind == "symlink":
        S.plant_symlink(path, S.scratch_copy(tmp_path, path, f"symlinked-{path.name}"))
    elif kind == "hardlink":
        S.plant_hardlink(path, S.scratch_copy(tmp_path, path, f"hardlinked-{path.name}"))
    elif kind == "linked_dir":
        real = S.scratch_copy(tmp_path, path.parent, f"linked-dir-{path.parent.name}")
        shutil.rmtree(path.parent)
        S.plant_symlink(path.parent, real)
    else:
        raise AssertionError(f"no damage {kind!r}")


def _cell(tmp_path: Path, where: str, kind: str | None) -> tuple[dict, dict, Any, Path]:
    """One boundary of reference run c, damaged with `kind` (`None`: the plain twin): what the
    probe read back, what it must read back, the family, and the damaged path."""
    built = S.family(tmp_path)
    path, pointer, filed = _boundary(built, where)
    if kind is not None:
        _damage(tmp_path, path, kind)
    return (_probe(built, pointer, filed),
            _probe_expected(pointer, filed, resolves=kind is None), built, path)


def _c_row_names(built: Any, path: Path) -> bool:
    """Does c's world row say it is not gradable, naming the refused file?"""
    row_c = S.row(built, "c")
    said = row_c.get(MALFORMED) or row_c.get(UNGRADABLE)
    return bool(said) and path.name in str(row_c.get("ungradable_reason", ""))


def _manifest_case(built: Any, *, damaged: bool) -> dict[str, Any]:
    """The manifest boundary over an already-built (and possibly damaged) family: b's reply
    cites the plan at b's own entry (design). Read back whether the pass refused naming the
    manifest, whether it asked the model, the finding's lane and questioner row."""
    seam = S.judge({"b": _reply(world=[_wf([S.plan_ptr("b")], tag="plan-b")])})
    refusal = None
    with S.no_hang(_WATCHDOG_S, "the pass"):
        try:
            S.grade(built, seam)
        except S.refusals() as refused:
            refusal = str(refused)
    fid = built.finding_id("b", 0, 0)
    q = _row_on(S.questioner_queue(), fid)
    return {"refused_naming_manifest": refusal is not None and "family.yaml" in refusal,
            "asked_model": seam.calls > 0, "lane": S.lane_of(built, fid),
            "questioner_world": None if q is None else q.get("world"),
            "defender_rows": len(S.defender_queue())}


def _manifest_expected(*, damaged: bool) -> dict[str, Any]:
    """Damaged: refused by name before any model call, nothing filed or queued. Plain: b's plan
    pointer resolves, the finding is design and its questioner row carries world b."""
    if damaged:
        return {"refused_naming_manifest": True, "asked_model": False, "lane": None,
                "questioner_world": None, "defender_rows": 0}
    return {"refused_naming_manifest": False, "asked_model": True, "lane": QUESTIONER,
            "questioner_world": "b", "defender_rows": 0}


def test_1234_queued_defender_row_contrast_pointers_resolve_into_two_runs(tmp_path: Path) -> None:
    built = S.family(tmp_path)
    b_reports = [S.conduct("b"), S.conduct("a")]
    b_rows = [_table(built, "b", 0), _served(built, "c", 0), S.plan_ptr("b"), S.oracle_ptr("b")]
    c_pair = [S.conduct("c", "investigation.md"), S.conduct("b")]
    _run(built, {
        "b": _reply(investigator=[_inv(b_reports, tag="reports"), _inv(b_rows, tag="rows")]),
        "c": _reply(investigator=[_inv(c_pair, label="c", tag="pair")], systems=("edr",))})

    expected = {built.finding_id("b", 0, 0): set(b_reports),
                built.finding_id("b", 0, 1): set(b_rows),
                built.finding_id("c", 0, 0): set(c_pair)}
    queued = {r.get("finding_id"): r for r in S.defender_queue()}
    assert {fid: set(r.get(CITATIONS) or []) for fid, r in queued.items()} == expected
    assert all(r.get(S.CONTRAST) for r in queued.values()), (
        "a queued defender row carries no contrast_evidence")


def test_1234_finding_without_a_resolving_two_run_pair_is_dropped(tmp_path: Path) -> None:
    built = S.family(tmp_path)
    draw0 = [
        _inv([S.conduct("b"), S.conduct("b", "investigation.md")], tag="d0-both-in-b"),
        _inv([S.conduct("b"), S.conduct("a")], tag="d0-pair"),
        _inv([S.conduct("b"), S.conduct("a", "no-such-file.md")], tag="d0-ref-unresolvable"),
        _inv([S.oracle_ptr("b"), S.conduct("a")], tag="d0-built-layer-half"),
        _inv([S.plan_ptr("b"), S.conduct("a")], tag="d0-plan-half"),
        _inv([S.conduct("b", "no-such-file.md"), S.conduct("a", "no-such-file.md")],
             tag="d0-nothing-resolves"),
        _inv([S.conduct("a"), S.conduct("c")], tag="d0-other-runs-only"),
    ]
    draw1 = [_inv([S.conduct("b"), S.conduct("a")], tag="d1-pair"),
             _inv([S.conduct("b"), S.conduct("b", "investigation.md")], tag="d1-both-in-b")]
    _run(built, {("b", 0): _reply(investigator=draw0), ("b", 1): _reply(investigator=draw1)},
         draws=2)

    expected = {
        (0, 0): NO_PAIR, (0, 1): DEFENDER, (0, 2): NO_PAIR, (0, 3): NO_PAIR, (0, 4): NO_PAIR,
        (0, 5): UNRESOLVED, (0, 6): OTHER_RUN, (1, 0): DEFENDER, (1, 1): NO_PAIR}
    assert {k: S.lane_of(built, built.finding_id("b", *k)) for k in expected} == expected
    queued = {r.get("finding_id") for r in S.from_world(S.defender_queue(), "b")}
    assert queued == {built.finding_id("b", 0, 1), built.finding_id("b", 1, 0)}
    dropped = ["d0-both-in-b", "d0-ref-unresolvable", "d0-built-layer-half", "d0-plan-half",
               "d0-nothing-resolves", "d0-other-runs-only", "d1-both-in-b"]
    assert {t: _surfaces(built, S.marker("b", t)) for t in dropped} == {t: [] for t in dropped}
    assert _surfaces(built, S.marker("b", "d0-pair")) == ["defender queue"]


def test_1234_evidence_resolves_into_reference_runs_manifest_and_oracle_store(
        tmp_path: Path) -> None:
    built = S.family(tmp_path, base_rows=BASE_ROWS)
    (built.ep / "wire_logs").mkdir(exist_ok=True)
    (built.ep / "wire_logs" / "x_framed_trace.jsonl").write_text(
        json.dumps({"note": "a judge wire log"}) + "\n", encoding="utf-8")
    (built.ep / "not_comparable.yaml").write_text("reason: planted\n", encoding="utf-8")
    b_resolving = [
        S.conduct("b"), S.conduct("a"), S.conduct("c", "investigation.md"),
        S.conduct("c", "gather_summaries/l-001.md"), _table(built, "c", 0),
        _served(built, "c", 0), _served(built, "a", 0), S.oracle_ptr("b"), S.oracle_ptr("c"),
        S.plan_ptr("b"), PLAN_FAMILY, SAMPLES_CTX, OUTCOME_CTX]
    b_never = [*S.never_resolving("c"), S.conduct("b", "judge/0.yaml"), "served/base.jsonl#0"]
    c_resolving = [S.conduct("c"), S.conduct("b", "investigation.md")]
    c_never = [*S.never_resolving("b"), S.conduct("c", "judge/0.yaml"), "served/base.jsonl#0"]
    _run(built, {
        "b": _reply(investigator=[_inv(b_resolving + b_never, tag="every-class")],
                    world=[_wf([S.plan_ptr("b")], tag="plan"),
                           _wf([SAMPLES_CTX, OUTCOME_CTX], tag="context")]),
        "c": _reply(investigator=[_inv(c_resolving + c_never, label="c", tag="every-class")],
                    systems=("edr",))})

    assert _cites(built.finding_id("b", 0, 0)) == set(b_resolving)
    assert _cites(built.finding_id("c", 0, 0)) == set(c_resolving)
    assert (S.lane_of(built, built.finding_id("b", 0, 1)),
            S.lane_of(built, built.finding_id("b", 0, 2))) == (QUESTIONER, USER_RECORD)


#: d05g's cases — each has a plain twin in the same position.
_NO_FOLLOW = ("leaf_symlink_inside_episode", "table_symlink", "under_linked_directory",
              "hard_linked_file", "absolute_path", "traversal_out_of_the_episode",
              "failed_world", "cut_short_world", "malformed_world", "outside_the_classes")


_SUMMARY = "gather_summaries/l-001.md"
_INVESTIGATION = "investigation.md"


def _no_follow_case(tmp_path: Path, case: str, *, damaged: bool) -> tuple[Any, str]:
    """Build the family for one d05g case and return it with the pointer under test."""
    if case.endswith("_world"):
        over = {"failed_world": {"world_record": S.sym(S.OUTCOME, "DID_NOT_FINISH")},
                "cut_short_world": {"run_end": {"truncated_by": "budget",
                                                "closed_before_cut": False}}}.get(case, {})
        built = S.family(tmp_path, _with_d(**(over if damaged else {})))
        if damaged and case == "malformed_world":
            S.second_disposition(built.world_dir("d") / "report.md")
        return built, S.conduct("d", _INVESTIGATION)
    built = S.family(tmp_path)
    c_dir = built.world_dir("c")
    plain, summary, row = S.conduct("c", _INVESTIGATION), S.conduct("c", _SUMMARY), _table(
        built, "c", 0)
    # case -> (the damage planted, the pointer when damaged, the plain twin's pointer)
    plant, damaged_pointer, plain_pointer = {
        "leaf_symlink_inside_episode": (
            lambda: S.plant_symlink(c_dir / _SUMMARY, "../report.md"), summary, summary),
        "table_symlink": (
            lambda: _damage(tmp_path, built.table_path("c"), "symlink"), row, row),
        "under_linked_directory": (
            lambda: _damage(tmp_path, c_dir / _SUMMARY, "linked_dir"), summary, summary),
        "hard_linked_file": (
            lambda: _damage(tmp_path, c_dir / _INVESTIGATION, "hardlink"), plain, plain),
        "absolute_path": (None, str(c_dir / _INVESTIGATION), plain),
        "traversal_out_of_the_episode": (None, f"../{built.ep.name}/{plain}", plain),
        "outside_the_classes": (
            lambda: (c_dir / "stray.md").write_text("a stray file\n", encoding="utf-8"),
            S.conduct("c", "stray.md"), plain),
    }[case]
    if damaged and plant is not None:
        plant()
    return built, damaged_pointer if damaged else plain_pointer


@pytest.mark.parametrize("damaged", [True, False], ids=["damaged", "plain-twin"])
@pytest.mark.parametrize("case", _NO_FOLLOW)
def test_1234_evidence_never_resolves_through_a_link_or_outside_the_reference_set(
        tmp_path: Path, case: str, damaged: bool) -> None:
    built, pointer = _no_follow_case(tmp_path, case, damaged=damaged)
    assert _probe(built, pointer, HALF) == _probe_expected(pointer, HALF, resolves=not damaged)


def _draw_file_replies(framed: Any) -> dict:
    """b cites c's draw file and c's wire log as its reference half, and c's draw file alone; c
    cites b's the same way; each also files a resolving sibling pair."""
    out = {}
    for me, other in (("b", "c"), ("c", "b")):
        out[me] = _reply(
            investigator=[
                _inv([S.conduct(me), S.conduct(other, "judge/0.yaml")], label=me,
                     tag="draw-half"),
                _inv([S.conduct(me), f"wire_logs/{framed(f'judge:{other}:0')}"], label=me,
                     tag="wire-log-half"),
                _inv([S.conduct(me, "investigation.md"), S.conduct("a")], label=me,
                     tag="sibling")],
            world=[_wf([S.conduct(other, "judge/0.yaml")], label=me, tag="draw-alone")],
            systems=("idp",) if me == "b" else ("edr",))
    return out


def test_1234_contrast_pointer_naming_a_reference_worlds_judge_draw(
        tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    framed = S.sym("run_repository._layout", "WIRE_LOG_NAMES").agent_framed_trace
    natural = S.family(tmp_path)
    judged_before = S.family(tmp_path, root=tmp_path / "judged-before")
    (judged_before.ep / "wire_logs").mkdir(exist_ok=True)
    for label in ("b", "c"):
        (judged_before.world_dir(label) / "judge").mkdir(parents=True, exist_ok=True)
        (judged_before.world_dir(label) / "judge" / "0.yaml").write_text(
            S.as_text(S.QUIET), encoding="utf-8")
        (judged_before.ep / "wire_logs" / framed(f"judge:{label}:0")).write_text(
            json.dumps({"agent_id": f"judge:{label}:0", "prompt": "p", "reply": "r"}) + "\n",
            encoding="utf-8")
    expected = {(w, i): lane for w in ("b", "c")
                for i, lane in enumerate((NO_PAIR, NO_PAIR, DEFENDER, UNRESOLVED))}
    seen = {}
    for name, built in (("natural", natural), ("judged-before", judged_before)):
        if name == "judged-before":
            (tmp_path / "second-state").mkdir()
            S.isolate_learning_state(tmp_path / "second-state", monkeypatch)
        _run(built, _draw_file_replies(framed))
        seen[name] = {(w, i): S.lane_of(built, built.finding_id(w, 0, i)) for w, i in expected}
    assert seen == {"natural": expected, "judged-before": expected}


def test_1234_pointer_naming_judge_yaml_or_a_wire_log_record(tmp_path: Path) -> None:
    built = S.family(tmp_path, S.triad(d=_failed_d()), base_rows=BASE_ROWS)
    for name, text in (("staged.yaml", "staged: true\n"), ("review.yaml", "outcome: accepted\n"),
                       ("not_comparable.yaml", "reason: planted\n")):
        (built.ep / name).write_text(text, encoding="utf-8")
    (built.ep / "wire_logs").mkdir(exist_ok=True)
    (built.ep / "wire_logs" / "x_framed_trace.jsonl").write_text(
        json.dumps({"note": "a judge wire log"}) + "\n", encoding="utf-8")

    def listed(other: str) -> list[str]:
        return ["judge.yaml", S.conduct(other, "judge/0.yaml"), "wire_logs/x_framed_trace.jsonl",
                "world_records/d.yaml", "not_comparable.yaml", "served/base.jsonl",
                "served/base.jsonl#0", "staged.yaml", "review.yaml", "provenance.json",
                "runs/_tenant.json", "runs/20260728t161845z-sibling-b/report.md"]

    own_context = S.conduct("b", "provenance.json")
    _run(built, {
        "b": _reply(investigator=[
            _inv([S.conduct("b"), S.conduct("a"), *listed("c"), own_context], tag="keeps-pair"),
            _inv([own_context, S.conduct("a", "provenance.json")], tag="provenance-pair"),
            _inv(listed("c"), tag="inv-only-listed")],
            world=[_wf(listed("c"), tag="wf-only-listed")]),
        "c": _reply(investigator=[_inv([S.conduct("c"), S.conduct("a"), *listed("b")],
                                       label="c", tag="keeps-pair")], systems=("edr",))},
        family=S.family_reply(world=[_wf(listed("b"), label="family", tag="fam-only-listed"),
                                     _wf([PLAN_FAMILY], label="family", tag="fam-plan")]))

    assert _cites(built.finding_id("b", 0, 0)) == {S.conduct("b"), S.conduct("a"), own_context}
    assert _cites(built.finding_id("c", 0, 0)) == {S.conduct("c"), S.conduct("a")}
    ids = [built.finding_id("b", 0, 1), built.finding_id("b", 0, 2), built.finding_id("b", 0, 3),
           built.finding_id("family", 0, 0), built.finding_id("family", 0, 1)]
    assert [S.lane_of(built, f) for f in ids] == [
        NO_PAIR, UNRESOLVED, UNRESOLVED, UNRESOLVED, QUESTIONER]
    gone = [S.marker("b", "inv-only-listed"), S.marker("b", "wf-only-listed"),
            S.marker("family", "fam-only-listed")]
    assert [_surfaces(built, m) for m in gone] == [[], [], []]


def test_1234_pointer_naming_a_served_ledger_row(tmp_path: Path) -> None:
    built = S.family(tmp_path, _refusal_calls(), base_rows=BASE_ROWS)
    rows_pair = [_served(built, "b", 0), _served(built, "c", 0)]
    _run(built, {"b": _reply(investigator=[
        _inv(rows_pair, tag="served-pair"),
        _inv([_served(built, "b", 2), _served(built, "a", 1)], tag="refused-pair"),
        _inv([S.conduct("b"), "served/base.jsonl#0"], tag="capture-half")])})

    fid = [built.finding_id("b", 0, i) for i in range(3)]
    assert _cites(fid[0]) == set(rows_pair)
    assert [S.lane_of(built, f) for f in fid] == [DEFENDER, USER_RECORD, NO_PAIR]
    assert _row_on(S.defender_queue(), fid[1]) is None


#: case -> (the mislabelled finding's pointers, its lane, kept for b)
_MISLABELLED = {
    "about_c_only": ([S.conduct("c"), S.plan_ptr("c")], OTHER_RUN, False),
    "also_names_b": ([S.conduct("c"), S.conduct("b"), S.plan_ptr("b")], QUESTIONER, True),
    "names_no_run": ([PLAN_FAMILY], QUESTIONER, True),
}


@pytest.mark.parametrize("case", sorted(_MISLABELLED))
def test_1234_focus_reply_files_mislabelled_about_a_reference_world(tmp_path: Path,
                                                                    case: str) -> None:
    evidence, lane, kept = _MISLABELLED[case]
    built = S.family(tmp_path)
    _run(built, {"b": _reply(world=[_wf(evidence, tag="mislabelled-c")])})

    fid = built.finding_id("b", 0, 0)
    q = _row_on(S.questioner_queue(), fid)
    seen = {"lane": S.lane_of(built, fid), "b_doubted": S.row(built, "b").get(S.DOUBT) is True,
            "c_doubted": S.row(built, "c").get(S.DOUBT) is True,
            "questioner_world": None if q is None else q.get("world"),
            "surfaces": _surfaces(built, S.marker("b", "mislabelled-c"))}
    assert seen == {"lane": lane, "b_doubted": kept, "c_doubted": False,
                    "questioner_world": "b" if kept else None,
                    "surfaces": ["questioner queue"] if kept else []}


def test_1234_investigator_finding_judging_a_reference_runs_conduct(tmp_path: Path) -> None:
    built = S.family(tmp_path)
    flaw = _claim("c", "the-flaw")
    about_c = [S.conduct("c"), S.conduct("c", "investigation.md")]
    _run(built, {
        "b": _reply(investigator=[S.inv(contrast=about_c, claim=flaw)]),
        "c": _reply(investigator=[S.inv(contrast=[S.conduct("c"), S.conduct("a")], claim=flaw)],
                    systems=("edr",))})

    assert (S.lane_of(built, built.finding_id("b", 0, 0)),
            S.lane_of(built, built.finding_id("c", 0, 0))) == (OTHER_RUN, DEFENDER)
    carrying = [r.get("finding_id") for r in S.defender_queue()
                if S.marker("c", "the-flaw") in json.dumps(r, default=str)]
    assert carrying == [built.finding_id("c", 0, 0)]
    assert _surfaces(built, S.marker("c", "the-flaw")) == ["defender queue"]


@pytest.mark.parametrize("d_state", ["malformed_world", "not_archived_world", "plain_twin"])
def test_1234_am_reference_half_in_a_run_outside_the_reference_set(tmp_path: Path,
                                                                   d_state: str) -> None:
    if d_state == "not_archived_world":
        built = S.family(tmp_path, _with_d(archived=False,
                                           world_record=S.sym(S.OUTCOME, "NOT_ARCHIVED")))
        row = S.ledger_row(S.CallRow(system="siem-x", verb="lookup", params={"entity": "svc-9"}),
                           label="d",
                           cid=S.call_id("d", 0))
        built.ledger_path("d").write_text(json.dumps(row) + "\n", encoding="utf-8")
    else:
        built = S.family(tmp_path, _with_d())
        if d_state == "malformed_world":
            S.second_disposition(built.world_dir("d") / "report.md")
    _run(built, {"b": _reply(investigator=[
        _inv([S.conduct("b"), S.conduct("d", "investigation.md")], tag="d-conduct"),
        _inv([S.conduct("b"), built.served("d", 0)], tag="d-served"),
        _inv([S.conduct("b", "investigation.md"), S.conduct("a")], tag="sibling")])})

    reference = d_state == "plain_twin"
    lanes = [S.lane_of(built, built.finding_id("b", 0, i)) for i in range(3)]
    assert lanes == [DEFENDER if reference else NO_PAIR] * 2 + [DEFENDER]
    assert [_surfaces(built, S.marker("b", t)) for t in ("d-conduct", "d-served")] == [
        ["defender queue"] if reference else []] * 2


@pytest.mark.parametrize("d_state", ["failed_world", "cut_short_world", "malformed_world",
                                     "plain_twin"])
def test_1234_pointer_into_an_excluded_worlds_oracle_store(tmp_path: Path, d_state: str) -> None:
    over = {"failed_world": {"world_record": S.sym(S.OUTCOME, "DID_NOT_FINISH")},
            "cut_short_world": {"run_end": {"truncated_by": "budget",
                                            "closed_before_cut": False}}}.get(d_state, {})
    built = S.family(tmp_path, S.triad(a={"calls": [S.CallRow()], "oracle": True},
                                       d=_d_spec(**over)))
    if d_state == "malformed_world":
        S.second_disposition(built.world_dir("d") / "report.md")
    pair = [S.conduct("b"), S.conduct("a")]
    _run(built, {"b": _reply(
        investigator=[_inv([*pair, S.oracle_ptr("d"), S.oracle_ptr("a")], tag="rides")],
        world=[_wf([S.oracle_ptr("d")], tag="d-store"), _wf([S.oracle_ptr("a")], tag="a-store")])})

    plain = d_state == "plain_twin"
    expected_cites = set(pair) | {S.oracle_ptr("a")} | ({S.oracle_ptr("d")} if plain else set())
    assert _cites(built.finding_id("b", 0, 0)) == expected_cites
    assert (S.lane_of(built, built.finding_id("b", 0, 1)),
            S.lane_of(built, built.finding_id("b", 0, 2))) == (
        OTHER_RUN if plain else UNRESOLVED, OTHER_RUN)


#: D30's hostile pointers: empty, whitespace, only a fragment, absolute, home-relative, a URL, a
#: glob, an embedded newline, an embedded NUL, and one far longer than any path.
_HOSTILE = ["", "   ", "#worlds/b", "/etc/passwd", f"~/worlds/{T.fixture_world_id('b')}/report.md",
            f"https://example.com/worlds/{T.fixture_world_id('b')}/report.md", "worlds/*/report.md",
            f"worlds/{T.fixture_world_id('b')}/report.md\nworlds/{T.fixture_world_id('a')}/report.md", f"worlds/{T.fixture_world_id('b')}/report.md\x00",
            f"worlds/{T.fixture_world_id('b')}/" + "x" * 5000 + ".md"]


def test_1234_pointer_with_hostile_syntax(tmp_path: Path) -> None:
    built = S.family(tmp_path)
    pair = [S.conduct("b"), S.conduct("a")]
    reply = _reply(investigator=[_inv([*pair, *_HOSTILE], tag="pair-and-hostile"),
                                 _inv(_HOSTILE, tag="hostile-only")])
    seam = _run(built, {"b": reply})

    assert _cites(built.finding_id("b", 0, 0)) == set(pair)
    assert S.lane_of(built, built.finding_id("b", 0, 1)) == UNRESOLVED
    assert _surfaces(built, S.marker("b", "hostile-only")) == []
    assert (seam.calls_for("b"), seam.called("c"), seam.called(S.FAMILY)) == (
        [f"judge:{built.world_ids['b']}:0"], True, True)
    S.validate(reply)


@pytest.mark.parametrize("link", ["to_a_byte_copy_of_itself", "to_a_reference_runs_report",
                                  "plain_twin"])
def test_1234_manifest_replaced_by_a_link_and_cited_as_design(tmp_path: Path, link: str) -> None:
    built = S.family(tmp_path)
    manifest = built.ep / "family.yaml"
    if link == "to_a_byte_copy_of_itself":
        S.plant_symlink(manifest, S.scratch_copy(tmp_path, manifest, "manifest-copy.yaml"))
    elif link == "to_a_reference_runs_report":
        S.plant_symlink(manifest, f"worlds/{T.fixture_world_id('c')}/report.md")
    damaged = link != "plain_twin"
    assert _manifest_case(built, damaged=damaged) == _manifest_expected(damaged=damaged)


_FIVE = ("manifest", "conduct", "oracle", "served", "table")


@pytest.mark.parametrize("damaged", [True, False], ids=["oversize", "plain-twin"])
@pytest.mark.parametrize("where", _FIVE)
def test_1234_an_oversize_file_is_refused_by_name_on_every_read_cell(tmp_path: Path, where: str,
                                                                     damaged: bool) -> None:
    if where == "manifest":
        built = S.family(tmp_path)
        if damaged:
            S.plant_oversize(built.ep / "family.yaml")
        assert _manifest_case(built, damaged=damaged) == _manifest_expected(damaged=damaged)
        return
    seen, expected, built, path = _cell(tmp_path, where, "oversize" if damaged else None)
    assert (seen, _c_row_names(built, path)) == (expected, damaged)


@pytest.mark.parametrize("kind", ["fifo", "dir", "device", None],
                         ids=["fifo", "directory", "device-node", "plain-twin"])
@pytest.mark.parametrize("where", _FIVE)
def test_1234_pointer_naming_a_fifo_or_directory_does_not_resolve_and_does_not_hang(
        tmp_path: Path, where: str, kind: str | None) -> None:
    if where == "manifest":
        built = S.family(tmp_path)
        if kind is not None:
            _damage(tmp_path, built.ep / "family.yaml", kind)
        damaged = kind is not None
        assert _manifest_case(built, damaged=damaged) == _manifest_expected(damaged=damaged)
        return
    seen, expected, _built, _path = _cell(tmp_path, where, kind)
    assert seen == expected


_MALFORMED_CELLS = {"table": "torn", "oracle": "torn", "report": "second_disposition"}


@pytest.mark.parametrize("damaged", [True, False], ids=["malformed", "plain-twin"])
@pytest.mark.parametrize("where", sorted(_MALFORMED_CELLS))
def test_1234_pointer_into_a_file_the_reader_refuses_as_malformed_does_not_resolve(
        tmp_path: Path, where: str, damaged: bool) -> None:
    seen, expected, built, path = _cell(tmp_path, where,
                                        _MALFORMED_CELLS[where] if damaged else None)
    assert (seen, _c_row_names(built, path)) == (expected, damaged)


_LINK_CELLS = [("oracle", "symlink"), ("oracle", "linked_dir"), ("oracle", "hardlink"),
               ("oracle", None), ("served", "symlink"), ("served", "hardlink"),
               ("served", None)]


@pytest.mark.parametrize(("where", "kind"), _LINK_CELLS,
                         ids=[f"{w}-{k or 'plain-twin'}" for w, k in _LINK_CELLS])
def test_1234_pointer_through_a_link_is_unresolved_in_the_oracle_store_and_served_ledger_classes(
        tmp_path: Path, where: str, kind: str | None) -> None:
    seen, expected, _built, _path = _cell(tmp_path, where, kind)
    assert seen == expected
