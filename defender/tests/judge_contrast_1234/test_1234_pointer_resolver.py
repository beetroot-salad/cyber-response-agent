"""#1234 slice 2 — the pointer resolver: A1's typed, episode-relative, no-follow resolver, the
two-run contrast rule, A13's drop lanes, A15's quantifiers, and the R3 parity cells (g06-g09).

Every scenario is a HAND-BUILT archived family (`S.family`: control `a`, planted `b` and `c`,
plus a fourth world `d` where a test needs a run outside the reference set), graded through the
judge's one entry point (`S.grade` -> `grade_episode`) with a scripted model seam (`S.judge`, a
`RoutedJudge`) that answers world `b`'s draw with the findings under test. What the resolver
decided is read only off what the pass leaves behind:

* a queued defender row's `citations` — an investigator finding's RESOLVING pointers (A1;
  s_D35: a manifest or oracle-store pointer filed beside a resolving pair rides along and is
  cited when it resolves). A pointer filed beside a resolving two-run pair is among the
  citations exactly when it resolves;
* the ledger lane judge.yaml records for each filed finding id (A13): a routing fate (defender,
  questioner, user record) or one drop reason, precedence pointers unresolved, names only
  another run, no two-run pair. "Pointers unresolved" is the lane of a finding NO filed pointer
  of which resolves: s_A10 ("a finding loses only the unresolved pointer, and is dropped when
  no resolving pointer remains") and s_A59 (the two-run rule is computed over the resolved set)
  fix that reading, so a finding keeping one resolving pointer in b falls to the no-pair lane;
* the questioner queue (a design world finding) and the user record (a serving or gap-only
  finding).

World findings here file `mislabelled` unless the test is about measurement, so a kept world
finding never changes whether `b` is measured (A7's not-measured predicates read `unreachable`,
`incoherent` and flagged gaps only).

Damage is real input through the real primitive (`S.plant_*`, `S.tear_jsonl`,
`S.second_disposition`, `os.mknod`), planted in REFERENCE run `c` (or in `d`) so that focus
world `b` stays gradable however the implementation classes the damaged run; every damaged case
has a plain twin in the same position that resolves. Hard-link and symlink targets are scratch
copies OUTSIDE the episode (a hard link raises `st_nlink` on its target too, so a target inside
the archive would damage a second file; `S.scratch_copy`). Every pass runs under `S.no_hang`, a
SIGALRM watchdog that turns a blocking open (a FIFO) into a named failure instead of a hung
shared test lock.
"""
from __future__ import annotations

import json
import os
import shutil
import stat
from collections.abc import Iterable, Sequence
from pathlib import Path
from typing import Any

import pytest

from defender.tests.judge_contrast_1234 import _spec1234 as S

DEFENDER = S.LANES["defender"]
QUESTIONER = S.LANES["questioner"]
USER_RECORD = S.LANES["user_record"]
NOT_MEASURED = S.LANES["not_measured"]
UNRESOLVED = S.LANES["dropped_unresolved"]
OTHER_RUN = S.LANES["dropped_other_run"]
NO_PAIR = S.LANES["dropped_no_pair"]
CITATIONS = S.RULED["row.citations"]
MEASURED = S.COINED["row.measured"]
MALFORMED = S.COINED["row.malformed"]
UNGRADABLE = S.COINED["row.ungradable_reason"]

#: The context fragment every scenario cites (pre-flight's record carries the key).
OUTCOME_CTX = S.outcome_ptr("not_replayable")
#: A shown samples section: the default family gives every served system one of real answers.
SAMPLES_CTX = S.samples_ptr("idp")
#: The plan's family-level part (the manifest's `discriminator`), which names no run (A15).
PLAN_FAMILY = S.plan_ptr(None)
#: A plan fragment naming an entry no manifest holds.
PLAN_NO_ENTRY = "family.yaml#" + S.COINED["frag.plan_world"].format(label="zz")
#: A row the family's shared capture holds, so `served/base.jsonl#0` names a real line.
BASE_ROWS = [{"system": "idp", "verb": "query", "params": {"q": "user:alice"},
              "payload_text": json.dumps({"rows": []}), "source": "passthrough"}]

#: Seconds a pass may take before the watchdog calls it blocked (a normal pass takes ~1 s).
_WATCHDOG_S = 45


# --------------------------------------------------------------------------------------
# Local helpers: scripting the reply, reading the pass's outputs, planting damage.
# --------------------------------------------------------------------------------------


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


# --------------------------------------------------------------------------------------
# The probe: one pointer under test, filed three ways in b's reply.
# --------------------------------------------------------------------------------------

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


# --------------------------------------------------------------------------------------
# d01a / d01b — the two-run contrast pair.
# --------------------------------------------------------------------------------------


def test_1234_queued_defender_row_contrast_pointers_resolve_into_two_runs(tmp_path: Path) -> None:
    """Every defender row a pass queues carries contrast_evidence whose resolving pointers include
    a conduct pointer in the judged world's run and a conduct pointer in one reference run of this
    episode (A1's classes: conduct, never a built-layer, plan or context pointer).

    World b files two investigator findings and reference world c one: b's report against the
    control's; b's query-table row against c's served-ledger row, with b's plan entry and b's
    oracle store riding along; c's investigation against b's report (b is a reference run for
    c). Exactly those three rows queue, each carrying contrast_evidence, and each row's
    citations are its conduct pair (plus the resolving ride-alongs)."""
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
    """An investigator finding whose contrast_evidence has no conduct pointer in the focus run
    paired with one in a reference run (both pointers in the judged world, the reference pointer
    unresolvable, or a built-layer or plan pointer offered as a half) is dropped with exactly one
    ledger lane (A13's precedence: pointers unresolved, names only another run, no two-run pair),
    keeps its filed index and queues no defender row, while a sibling finding in the same reply
    with a resolving two-run conduct pair is queued.

    Two draws (I-6): draw 0 files seven findings, draw 1 files the resolving pair first and the
    both-in-b pair second, so each id is that draw's filing index. The lanes: both pointers in b,
    the reference half unresolvable, b's oracle store or b's plan entry as the focus half — no
    two-run pair; nothing resolving — pointers unresolved; the control and c only — names only
    another run (ahead of no two-run pair). No dropped finding's claim reaches either queue or
    the user record; both resolving pairs are queued."""
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


# --------------------------------------------------------------------------------------
# d05f / d05g / d12d — what resolves, what never does, and the one resolver.
# --------------------------------------------------------------------------------------


def test_1234_evidence_resolves_into_reference_runs_manifest_and_oracle_store(
        tmp_path: Path) -> None:
    """An evidence pointer resolves when it is episode-relative and names, with no link followed,
    a plain file of one of A1's classes for a run in this episode's reference set: the focus or a
    reference run's conduct (worlds/<X>/ conduct files, served/<token>.<X>.jsonl#<row>), its built
    layer (oracle/<X>/), the plan (family.yaml#...) or context (samples.yaml#...,
    outcome.yaml#...); judge.yaml, worlds/*/judge/, wire_logs/, world_records/,
    not_comparable.yaml and served/base.jsonl never resolve.

    b's resolving pair rides along every class of pointer — c's investigation, gather summary,
    query-table row and served row, the control's served row, b's and c's oracle stores, b's
    plan entry and the plan's family-level part, a shown samples section, pre-flight's record —
    and A1's never-resolve list (the capture ledger with a row, a wire log and
    not_comparable.yaml planted as real files; judge.yaml and the other world's draw file exist
    for whichever of b and c is judged second, and both cite them). The queued rows' citations
    are exactly the resolving pointers. A world finding citing b's plan entry is design
    (questioner queue); one citing only the two context pointers is serving (user record)."""
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
    """A pointer naming a symbolic link (even one whose target is inside the episode), a path
    under a linked directory, a hard-linked file, an absolute path, a traversal out of the
    episode, a file of a world outside the reference set (O5-failed, cut short or malformed), or a
    file outside A1's classes does not resolve (today an in-world leaf link and a hard link
    resolve, E-27).

    Each case files the pointer as the reference half of b's pair and alone in a world finding.
    Damaged, the pair has no two-run partner and the lone finding has nothing resolving; the
    plain twin (the plain file, the relative spelling, an ordinary world d, a conduct file) is a
    resolving pair and a finding naming only another run. b's resolving sibling pair is queued
    either way."""
    built, pointer = _no_follow_case(tmp_path, case, damaged=damaged)
    assert _probe(built, pointer, HALF) == _probe_expected(pointer, HALF, resolves=not damaged)


def test_1234_every_evidence_resolution_goes_through_the_one_resolver(tmp_path: Path) -> None:
    """Every site that decides whether a judge evidence pointer resolves (the draw document,
    routing, gap-only evidence) calls the one resolver; the census names each site, and a planted
    second resolution path is reported.

    The census (one resolver definition, the sites calling it) picks the subjects; each site is
    then driven through the pass with pointers the resolver refuses although a lexical check
    would pass them — a plan fragment naming no manifest entry, a ledger row past the last line,
    a query-table row past the last line, a stray file under b — and each decides as the
    resolver does. The draw document leaves them out of the citations. Routing does not make a
    finding design on the dangling plan pointer: it is serving, beside its twin citing b's
    entry, which is design. Gap-only sets the dangling table pointer aside: the finding stays
    gap-only and goes to the user record, beside its twin citing an ordinary table row, which
    queues."""
    sites = S.call_sites("_resolves", under="learning/judge")
    resolvers = S.defs_named("_resolves", under="learning")
    assert len(resolvers) == 1, f"the census needs exactly one resolver: {resolvers}"
    assert sites, "the census names no site calling the one resolver"

    built = S.family(tmp_path, _refusal_calls())
    (built.world_dir("b") / "stray.md").write_text("a stray file\n", encoding="utf-8")
    blocked = [_served(built, "b", 2), _served(built, "a", 1)]
    _run(built, {"b": _reply(
        investigator=[
            _inv([S.conduct("b"), S.conduct("a"), PLAN_NO_ENTRY, built.served("b", 99),
                  S.conduct("b", "stray.md")], tag="draw-document"),
            _inv([*blocked, built.table("b", 99)], tag="gap-only-dangling"),
            _inv([*blocked, _table(built, "b", 0)], tag="gap-only-twin")],
        world=[_wf([PLAN_NO_ENTRY, S.conduct("b")], tag="routing-dangling"),
               _wf([S.plan_ptr("b"), S.conduct("b")], tag="routing-twin")])})

    fid = [built.finding_id("b", 0, i) for i in range(5)]
    assert _cites(fid[0]) == {S.conduct("b"), S.conduct("a")}
    assert [S.lane_of(built, f) for f in fid] == [
        DEFENDER, USER_RECORD, DEFENDER, USER_RECORD, QUESTIONER]
    assert _row_on(S.questioner_queue(), fid[3]) is None


# --------------------------------------------------------------------------------------
# s_A7 / s_A10 / s_A12 / s_A13 / s_A14 — the never-resolve list, ledgers, context.
# --------------------------------------------------------------------------------------


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
    """A pointer into any judge draw document, judge.yaml, or any file the judge itself wrote
    does not count as a run's archived content: it does not resolve as evidence or as either half
    of a contrast pair, so b's finding's fate is the same whether c was judged before b (P-c, I2).

    b cites c's draw file and c's wire log as its reference half (and c's draw file alone in a
    world finding); c cites b's the same way, so in one pass whichever world is judged second
    meets the other's files on disk. A second episode (its own learning state, so the two
    passes share no queue) has both draw files and both wire logs already on disk before its
    pass. In both episodes every such finding takes the same drop lane (no two-run pair;
    pointers unresolved for the lone world finding) and each world's resolving sibling pair is
    queued."""
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
    """`judge.yaml`, `worlds/*/judge/`, `wire_logs/`, `world_records/`, `not_comparable.yaml` and
    `served/base.jsonl` never resolve (A1's list). `staged.yaml`, `review.yaml`, the episode's
    top-level `provenance.json` and `runs/<sibling>/...` lie outside A1's episode-relative grammar
    and are unresolved; a run's own `worlds/<X>/provenance.json` is a context pointer (T1's class
    list), names no run and never counts as a half. A finding loses only the unresolved pointer,
    and is dropped when no resolving pointer remains.

    Asked for an investigator finding, a world finding and a family finding. The family carries
    a failed fourth world (its world record on disk), the capture ledger with a row, a wire log,
    not_comparable.yaml, staged.yaml and review.yaml as real files beside the top-level family
    stamp provenance.json; judge.yaml and the other world's draw file exist when the second of b
    and c is judged. A resolving pair keeping every such pointer queues citing only the pair and
    b's own provenance.json; a pair of two worlds' provenance.json files has no two-run pair;
    findings citing only the list (b's investigator and world findings, a family finding) are
    dropped as unresolved and reach no output, while a family finding citing the plan's
    family-level part is design."""
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
    """Served ledgers are citable (A1): `served/<token>.<X>.jsonl#<row>` resolves to run X, class
    conduct. It counts as a conduct pointer of X; a pointer at a `refused`/`fault` row is a
    blocked-call row for the gap-only rule. `served/base.jsonl` does not resolve.

    b's served row against c's served row is a two-run conduct pair (queued, citing both); b's
    refused row against the control's refused row is gap-only (the user record, never the
    defender queue); b's report against a row of the capture ledger has no two-run pair."""
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


def test_1234_pointer_naming_the_family_capture_ledger_as_the_reference_half(
        tmp_path: Path) -> None:
    """`served/base.jsonl` never resolves (A1): it is the family tier, not a run. A finding using
    it as the reference half has no conduct pointer in a reference run and is dropped for lacking
    the two-run pair (I1).

    The capture ledger holds a real row. b's report against `served/base.jsonl#0` and against
    the bare `served/base.jsonl` are each dropped with the no-pair lane and reach no output; b's
    report against the control's own served row, in the same reply, is queued."""
    built = S.family(tmp_path, base_rows=BASE_ROWS)
    _run(built, {"b": _reply(investigator=[
        _inv([S.conduct("b"), "served/base.jsonl#0"], tag="capture-row"),
        _inv([S.conduct("b"), "served/base.jsonl"], tag="capture-file"),
        _inv([S.conduct("b"), _served(built, "a", 0)], tag="control-row")])})

    fid = [built.finding_id("b", 0, i) for i in range(3)]
    assert [S.lane_of(built, f) for f in fid] == [NO_PAIR, NO_PAIR, DEFENDER]
    assert [_surfaces(built, S.marker("b", t)) for t in ("capture-row", "capture-file")] == [
        [], []]
    assert _cites(fid[2]) == {S.conduct("b"), _served(built, "a", 0)}


def test_1234_world_finding_citing_world_records_not_comparable_or_outcome(tmp_path: Path) -> None:
    """`world_records/` and `not_comparable.yaml` never resolve; `outcome.yaml#` resolves as a
    context pointer, as does `samples.yaml#` (A1): context names no run and is set aside for the
    two-run rule and the gap-only rule. Only a `family.yaml#` plan pointer can make a finding
    design; none of these counts toward design.

    A failed fourth world's record and not_comparable.yaml are real files. In b's reply: b's
    report beside pre-flight's record has no two-run pair; two refused rows beside both context
    pointers stay gap-only (user record); world findings citing pre-flight's record alone or the
    samples section alone are serving (user record, no questioner row); one citing the world
    record and not_comparable.yaml is unresolved; one citing b's plan entry beside pre-flight's
    record is design (questioner). A family finding citing pre-flight's record is serving, one
    citing the world record and not_comparable.yaml unresolved."""
    built = S.family(tmp_path, _refusal_calls(d=_failed_d()))
    (built.ep / "not_comparable.yaml").write_text("reason: planted\n", encoding="utf-8")
    never = ["world_records/d.yaml", "not_comparable.yaml"]
    blocked = [_served(built, "b", 2), _served(built, "a", 1)]
    _run(built, {"b": _reply(
        investigator=[_inv([S.conduct("b"), OUTCOME_CTX], tag="context-half"),
                      _inv([*blocked, OUTCOME_CTX, SAMPLES_CTX], tag="gap-only-context")],
        world=[_wf([OUTCOME_CTX], tag="outcome-only"), _wf([SAMPLES_CTX], tag="samples-only"),
               _wf(never, tag="records-only"), _wf([S.plan_ptr("b"), OUTCOME_CTX], tag="plan")])},
        family=S.family_reply(world=[_wf([OUTCOME_CTX], label="family", tag="fam-outcome"),
                                     _wf(never, label="family", tag="fam-records")]))

    b = [S.lane_of(built, built.finding_id("b", 0, i)) for i in range(6)]
    fam = [S.lane_of(built, built.finding_id("family", 0, i)) for i in range(2)]
    assert (b, fam) == ([NO_PAIR, USER_RECORD, USER_RECORD, USER_RECORD, UNRESOLVED, QUESTIONER],
                        [USER_RECORD, UNRESOLVED])
    assert {r.get("finding_id") for r in S.questioner_queue()} == {built.finding_id("b", 0, 5)}


def test_1234_two_spellings_of_one_run_offered_as_a_two_run_pair(tmp_path: Path) -> None:
    """One no-follow resolver canonicalises each pointer to exactly one run and one class: two
    spellings of one file name the same run, so a pair of them is not a two-run pair and the
    finding is dropped for that; dot segments, doubled separators and trailing separators
    canonicalise to the file they name (a segment that returns into the same world names the same
    run); a segment that leaves the world's subtree, or a case variant naming no archived label,
    is unresolved.

    b's report paired with itself spelled `worlds/b/./`, `./worlds/b/`, `worlds//b/` and
    `worlds/b/gather_summaries/../` is dropped for no two-run pair, as is b's report paired with
    `worlds/c/../b/report.md` or `worlds/c/../a/report.md` (leaving c's subtree: unresolved,
    never canonicalised into another world) or `worlds/A/report.md` (no archived label). b's
    report spelled with a doubled separator and a dot segment against the control's spelled
    with a dot segment and a trailing separator is a resolving pair and is queued."""
    built = S.family(tmp_path)
    report = S.conduct("b")
    spellings = ["worlds/b/./report.md", "./worlds/b/report.md", "worlds//b/report.md",
                 "worlds/b/gather_summaries/../report.md", "worlds/c/../b/report.md",
                 "worlds/c/../a/report.md", "worlds/A/report.md"]
    findings = [_inv([report, s], tag=f"spelling-{i}") for i, s in enumerate(spellings)]
    findings.append(_inv(["worlds//b/./report.md", "./worlds/a/report.md/"], tag="canonical"))
    _run(built, {"b": _reply(investigator=findings)})

    lanes = [S.lane_of(built, built.finding_id("b", 0, i)) for i in range(len(findings))]
    assert lanes == [NO_PAIR] * len(spellings) + [DEFENDER]
    queued = {r.get("finding_id") for r in S.from_world(S.defender_queue(), "b")}
    assert queued == {built.finding_id("b", 0, len(spellings))}
    assert _cites(built.finding_id("b", 0, len(spellings))) == {
        S.conduct("b"), S.conduct("a")}


@pytest.mark.parametrize("path", ["family.yaml", "./family.yaml", "x/../family.yaml",
                                 ".//family.yaml/"])
def test_1234_plan_spellings_reach_questioner(tmp_path: Path, path: str) -> None:
    """Every accepted spelling of a plan pointer survives routing and queue validation."""
    built = S.family(tmp_path)
    _run(built, {"b": _reply(world=[_wf([path + "#worlds/b"])])})
    fid = built.finding_id("b", 0, 0)
    assert S.lane_of(built, fid) == QUESTIONER
    row = _row_on(S.questioner_queue(), fid)
    assert row is not None
    assert row[CITATIONS] == [S.plan_ptr("b")]


# --------------------------------------------------------------------------------------
# s_A16 / s_A17 / s_D28 / s_AM6 — which pairs are two-run pairs.
# --------------------------------------------------------------------------------------


def test_1234_contrast_pair_between_two_reference_runs_only(tmp_path: Path) -> None:
    """The two-run rule needs a conduct pointer in the focus run and a conduct pointer in a
    reference run (A1). A pair whose pointers lie in the control and in c, neither in b, has no
    conduct pointer in the focus run and the finding is dropped.

    Its lane is names-only-another-run (A13's precedence puts it ahead of no two-run pair), its
    claim reaches neither queue nor the user record, and b's resolving pair in the same reply
    is queued and seen on the defender queue."""
    built = S.family(tmp_path)
    _run(built, {"b": _reply(investigator=[
        _inv([S.conduct("a"), S.conduct("c")], tag="references-only"),
        _inv([S.conduct("b"), S.conduct("a")], tag="pair")])})

    fid = [built.finding_id("b", 0, i) for i in range(2)]
    assert [S.lane_of(built, f) for f in fid] == [OTHER_RUN, DEFENDER]
    assert _surfaces(built, S.marker("b", "references-only")) == []
    assert _surfaces(built, S.marker("b", "pair")) == ["defender queue"]


def test_1234_contrast_pair_naming_a_runs_built_layer(tmp_path: Path) -> None:
    """A world's built layer (`oracle/<X>/…`) is its own pointer class, never conduct: it cannot
    supply either half of the two-run pair. b's report plus b's oracle store has one conduct
    pointer in one run; b's report plus c's forged rows has no conduct pointer in c. Both pairs
    fail the two-run rule and the finding is dropped.

    Both are dropped with the no-pair lane and reach no output. c's forged rows riding beside a
    resolving pair resolve (they are cited on the queued row) without being a half."""
    built = S.family(tmp_path)
    _run(built, {"b": _reply(investigator=[
        _inv([S.conduct("b"), S.oracle_ptr("b")], tag="own-store"),
        _inv([S.conduct("b"), S.oracle_ptr("c")], tag="c-forged-rows"),
        _inv([S.conduct("b"), S.conduct("a"), S.oracle_ptr("c")], tag="rides")])})

    fid = [built.finding_id("b", 0, i) for i in range(3)]
    assert [S.lane_of(built, f) for f in fid] == [NO_PAIR, NO_PAIR, DEFENDER]
    assert [_surfaces(built, S.marker("b", t)) for t in ("own-store", "c-forged-rows")] == [
        [], []]
    assert _cites(fid[2]) == {S.conduct("b"), S.conduct("a"), S.oracle_ptr("c")}


def test_1234_contrast_pair_of_unrelated_files_across_two_runs(tmp_path: Path) -> None:
    """Only conduct records (report, investigation, calls, served rows) satisfy a contrast pair;
    alert.json and provenance.json do not.

    b's alert.json against c's provenance.json, and b's provenance.json against the control's
    alert.json, are each dropped with the no-pair lane and reach no output; b's report against
    c's investigation in the same reply is queued."""
    built = S.family(tmp_path)
    _run(built, {"b": _reply(investigator=[
        _inv([S.conduct("b", "alert.json"), S.conduct("c", "provenance.json")], tag="alert-prov"),
        _inv([S.conduct("b", "provenance.json"), S.conduct("a", "alert.json")], tag="prov-alert"),
        _inv([S.conduct("b"), S.conduct("c", "investigation.md")], tag="conduct-pair")])})

    fid = [built.finding_id("b", 0, i) for i in range(3)]
    assert [S.lane_of(built, f) for f in fid] == [NO_PAIR, NO_PAIR, DEFENDER]
    assert [_surfaces(built, S.marker("b", t)) for t in ("alert-prov", "prov-alert")] == [[], []]
    assert _surfaces(built, S.marker("b", "conduct-pair")) == ["defender queue"]


def test_1234_am_contrast_pair_of_two_served_answers_only(tmp_path: Path) -> None:
    """Two served rows are ledger conduct pointers in two runs, so a pair of served answers
    satisfies the two-run rule (A1; N-e: substance is not judged) (NA08).

    b's altered served answer against the control's served row for the same call — nothing the
    investigator wrote or asked — is queued citing both rows; two served rows of b alone are not
    a two-run pair."""
    altered_q = S.query_params("user:alice host:db-1")
    built = S.family(tmp_path, S.triad(a={"calls": [S.CallRow(), S.CallRow(params=altered_q)]}))
    served_pair = [_served(built, "b", 1), _served(built, "a", 1)]
    _run(built, {"b": _reply(investigator=[
        _inv(served_pair, tag="served-answers"),
        _inv([_served(built, "b", 1), _served(built, "b", 0)], tag="one-run")])})

    fid = [built.finding_id("b", 0, i) for i in range(2)]
    assert _cites(fid[0]) == set(served_pair)
    assert [S.lane_of(built, f) for f in fid] == [DEFENDER, NO_PAIR]


def test_1234_contrast_pair_of_two_inherited_ordinary_rows_is_no_pair(tmp_path: Path) -> None:
    """A contrast pair whose two halves are both inherited, ordinary table rows (pre-branch rows
    carrying no call id of this run, A12, and not blocked calls) is no pair: no divergence lies
    behind two copies of the shared baseline, so the finding is dropped with the no-pair lane and
    reaches no output (R2 (b), human 2026-10-12; I1). An inherited row beside a post-branch row
    still pairs and queues. J3's inherited denial is a blocked call and keeps its gap-only route
    (A14; d11a, T10 unchanged).

    The family's seeded prefix is one ordinary inherited row (`idp query user:prebranch`) at row
    0 of every table. b files: its inherited row against the control's inherited row (no pair);
    its inherited row against the control's own post-branch row, and its own post-branch row
    against the control's inherited row (each queued, the positive controls)."""
    prebranch = S.CallRow(params=S.query_params("user:prebranch"), inherited=True)
    built = S.family(tmp_path, inherited=[prebranch])
    assert built.table_rows("b")[0] == built.table_rows("a")[0], (
        "fixture: the inherited row is identical in both tables")
    assert S.CALL_ID not in built.table_rows("b")[0], "fixture: the inherited row carries no id"
    inherited_b, inherited_a = built.table("b", 0), built.table("a", 0)
    _run(built, {"b": _reply(investigator=[
        _inv([inherited_b, inherited_a], tag="inherited-pair"),
        _inv([inherited_b, _table(built, "a", 0)], tag="inherited-beside-own"),
        _inv([_table(built, "b", 0), inherited_a], tag="own-beside-inherited")])})

    fid = [built.finding_id("b", 0, i) for i in range(3)]
    assert [S.lane_of(built, f) for f in fid] == [NO_PAIR, DEFENDER, DEFENDER]
    assert _surfaces(built, S.marker("b", "inherited-pair")) == []
    assert _cites(fid[1]) == {inherited_b, _table(built, "a", 0)}
    assert _cites(fid[2]) == {_table(built, "b", 0), inherited_a}


# --------------------------------------------------------------------------------------
# s_A24 / s_A25 / s_A27 / s_AM2 / s_AM3 — a finding in b's reply about another run (A15).
# --------------------------------------------------------------------------------------

#: case -> (the mislabelled finding's pointers, its lane, kept for b)
_MISLABELLED = {
    "about_c_only": ([S.conduct("c"), S.plan_ptr("c")], OTHER_RUN, False),
    "also_names_b": ([S.conduct("c"), S.conduct("b"), S.plan_ptr("b")], QUESTIONER, True),
    "names_no_run": ([PLAN_FAMILY], QUESTIONER, True),
}


@pytest.mark.parametrize("case", sorted(_MISLABELLED))
def test_1234_focus_reply_files_mislabelled_about_a_reference_world(tmp_path: Path,
                                                                    case: str) -> None:
    """A finding in b's reply is dropped only when it has at least one run-naming pointer and
    every run-naming pointer names another run (c) (A1, A15): it does not mark b doubted and
    reaches no queue. A mislabelled finding that also has a pointer naming b stays b's; one with
    no run-naming pointer is not dropped by this rule.

    b files a mislabelled world finding about c's declared verdict. Citing only c's report and
    c's plan entry it is dropped (names only another run): b is not doubted, c is not doubted,
    and its claim reaches no output. Also citing b's report and b's plan entry it is kept and
    design: b is doubted and the questioner row carries world b. Citing only the plan's
    family-level part (no run-naming pointer) it is kept and design under world b, b doubted.
    c's own reply files nothing, so c is never doubted."""
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


#: case -> (bucket, the world finding's pointers, its lane, b measured)
_UNREACHABLE = {
    "unreachable_about_c": ("unreachable", [S.conduct("c"), S.plan_ptr("c")], OTHER_RUN, True),
    "incoherent_about_c": ("incoherent", [S.plan_ptr("c")], OTHER_RUN, True),
    "unreachable_about_b_control": ("unreachable", [S.plan_ptr("b"), S.conduct("b")],
                                    QUESTIONER, False),
}


@pytest.mark.parametrize("case", sorted(_UNREACHABLE))
def test_1234_focus_reply_files_unreachable_about_a_reference_world(tmp_path: Path,
                                                                    case: str) -> None:
    """The finding is dropped (A1, A15): it has run-naming pointers and all name c (a
    `family.yaml#` fragment at c's entry names c under A15; only the family-level part names no
    run). A dropped finding is not kept, so it does not mark b not measured and does not mark c.

    b and c each file a lead-quality bucket with a resolving investigator pair. b's unreachable
    finding citing c's report and c's plan entry, or its incoherent finding citing c's plan
    entry alone, is dropped (names only another run): b stays measured and its pair queues, c
    stays measured. The control: the same unreachable finding citing b's plan entry and b's
    report is kept, so b is not measured and its pair is withheld as not measured."""
    bucket, evidence, lane, b_measured = _UNREACHABLE[case]
    built = S.family(tmp_path)
    _run(built, {
        "b": _reply(investigator=[_inv([S.conduct("b"), S.conduct("a")], tag="pair")],
                    world=[_wf(evidence, bucket=bucket, tag="about")]),
        "c": _reply(investigator=[_inv([S.conduct("c"), S.conduct("a")], label="c", tag="pair")],
                    systems=("edr",))})

    seen = {"finding": S.lane_of(built, built.finding_id("b", 0, 1)),
            "b_pair": S.lane_of(built, built.finding_id("b", 0, 0)),
            "b_measured": S.row(built, "b").get(MEASURED),
            "c_measured": S.row(built, "c").get(MEASURED),
            "reached": _surfaces(built, S.marker("b", "about"))}
    assert seen == {"finding": lane, "b_pair": DEFENDER if b_measured else NOT_MEASURED,
                    "b_measured": b_measured, "c_measured": True,
                    "reached": [] if b_measured else ["questioner queue"]}


def test_1234_investigator_finding_judging_a_reference_runs_conduct(tmp_path: Path) -> None:
    """A finding in b's reply whose two conduct pointers are both about c's conduct has no conduct
    pointer in the focus run and at least one run-naming pointer, every one naming another run:
    it is dropped (A1, A15). c's own call filing the same flaw yields its own row; nothing
    combines across worlds.

    b's finding citing c's report and c's investigation is dropped (names only another run);
    c's own reply files the same claim against the control and it queues. Exactly one defender
    row carries that claim, and it is c's."""
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


def test_1234_am_what_counts_as_naming_a_run(tmp_path: Path) -> None:
    """A pointer names run X through X's conduct (report, investigation, query-table rows, gather
    summaries, served-ledger rows) or X's built layer (`oracle/X/`); a `family.yaml#` pointer at
    world X's entry names X and one at the family-level part names no run (A15). Context names no
    run: `samples.yaml#`, `outcome.yaml#`, and a run's files that are not conduct — `alert.json`,
    `provenance.json`, `run_end.json`, `lessons_loaded.jsonl` (T1's class list). Any other file,
    such as a stray file the archive copied under b's subtree, is outside A1's classes, so
    unresolved, and names no run (A15). b's finding citing c's conduct and, from b, only such
    files has at least one run-naming pointer and every one names c, so it is dropped as naming
    only another run. The samples/outcome-only world finding has no run-naming pointer and is not
    dropped by that rule; with no plan pointer and no conduct pointer it is neither design nor
    gap-only, so it is serving and goes to the user record. An investigator finding citing only
    such pointers lacks the two-run pair and is dropped.

    In b's reply (a stray file planted under b): context-only investigator pairs (b's alert.json
    with the control's provenance.json; b's query-table row with the control's
    lessons_loaded.jsonl) have no two-run pair; b's investigation against c's gather summary is
    a conduct pair and queues; c's report beside b's non-conduct files and stray file names only
    c; the samples/outcome-only world finding is serving (user record, among its serving
    findings); c's forged rows alone name only c; the stray file alone is unresolved; b's oracle
    store beside the plan's family-level part is design under world b."""
    built = S.family(tmp_path)
    (built.world_dir("b") / "stray.md").write_text("a stray file\n", encoding="utf-8")
    from_b = [S.conduct("b", leaf) for leaf in ("alert.json", "provenance.json", "run_end.json",
                                                "lessons_loaded.jsonl", "stray.md")]
    _run(built, {"b": _reply(
        investigator=[
            _inv([S.conduct("b", "alert.json"), S.conduct("a", "provenance.json")],
                 tag="context-pair"),
            _inv([S.conduct("b", "investigation.md"), S.conduct("c", "gather_summaries/l-001.md")],
                 tag="conduct-pair"),
            _inv([_table(built, "b", 0), S.conduct("a", "lessons_loaded.jsonl")],
                 tag="row-and-context")],
        world=[_wf([S.conduct("c"), *from_b], tag="c-and-b-context"),
               _wf([SAMPLES_CTX, OUTCOME_CTX], tag="serving"),
               _wf([S.oracle_ptr("c")], tag="c-built-layer"),
               _wf([S.conduct("b", "stray.md")], tag="stray-only"),
               _wf([S.oracle_ptr("b"), PLAN_FAMILY], tag="b-built-layer-plan")])})

    lanes = [S.lane_of(built, built.finding_id("b", 0, i)) for i in range(8)]
    assert lanes == [NO_PAIR, DEFENDER, NO_PAIR, OTHER_RUN, USER_RECORD, OTHER_RUN, UNRESOLVED,
                     QUESTIONER]
    serving = [json.dumps(e, default=str) for e in S.serving_findings(built)]
    assert any(built.finding_id("b", 0, 4) in e or S.marker("b", "serving") in e
               for e in serving), serving
    q = _row_on(S.questioner_queue(), built.finding_id("b", 0, 7))
    assert (None if q is None else q.get("world")) == "b"


def test_1234_am_plan_pointer_naming_another_worlds_entry(tmp_path: Path) -> None:
    """A `family.yaml#` pointer at world X's entry names run X; at the family-level part it names
    no run (A15). It resolves when the fragment names an entry the manifest holds, otherwise it
    is unresolved. A world finding in b's reply whose only run-naming pointer is c's entry is
    dropped (T1's stated cost: c's own call and the family call catch it); beside a pointer into
    b's conduct it names b and c, is kept, and if not gap-only is design, its questioner row
    carrying the focus world b. A fragment naming no manifest entry is unresolved.

    c's entry alone: names only another run. c's entry beside b's report: design, questioner row
    under world b. A fragment naming an entry no manifest holds, alone: unresolved; beside b's
    report: the plan pointer is set aside, so the finding is serving (user record), not
    design."""
    built = S.family(tmp_path)
    _run(built, {"b": _reply(world=[
        _wf([S.plan_ptr("c")], tag="c-entry-only"),
        _wf([S.plan_ptr("c"), S.conduct("b")], tag="c-entry-and-b"),
        _wf([PLAN_NO_ENTRY], tag="no-entry-only"),
        _wf([PLAN_NO_ENTRY, S.conduct("b")], tag="no-entry-and-b")])})

    fid = [built.finding_id("b", 0, i) for i in range(4)]
    assert [S.lane_of(built, f) for f in fid] == [OTHER_RUN, QUESTIONER, UNRESOLVED, USER_RECORD]
    assert {r.get("finding_id"): r.get("world") for r in S.questioner_queue()} == {fid[1]: "b"}
    assert [_surfaces(built, S.marker("b", t)) for t in ("c-entry-only", "no-entry-only")] == [[], []]


# --------------------------------------------------------------------------------------
# s_AM4 / s_AM5 / s_D37 — served-ledger granularity, runs outside the reference set.
# --------------------------------------------------------------------------------------


def _c_second_call(variant: str) -> Any:
    """Reference run c's second call: well-formed, or carrying a row c's ledger read must
    refuse (A3, A12, X13): another world's id, no world id, no call id, another run's call id."""
    over = {"well_formed": {}, "another_worlds_id": {"world_id": S.world_token("a")},
            "no_world_id": {"world_id": None}, "no_call_id": {"call_id": None},
            "another_runs_call_id": {"call_id": S.call_id("a", 7)}}[variant]
    return S.CallRow(system="edr", params=S.query_params("host:web-2"), **over)


@pytest.mark.parametrize("second_call", ["well_formed", "another_worlds_id", "no_world_id",
                                         "no_call_id", "another_runs_call_id"])
def test_1234_am_served_ledger_pointer_granularity(tmp_path: Path, second_call: str) -> None:
    """A1's served form carries a row fragment: a served-ledger pointer with no row fragment, or
    with a fragment past the file's last row, is unresolved (NA03). A row carrying another world's
    id or none, or no call id of b's run, makes b's ledger read not well-formed (A3, A12; NA03
    (b), X13: no reader skips it), so b is malformed and no pointer into a usable run reaches such
    a row; in a usable run every ledger line is a kept row, so a `#row` fragment indexes lines and
    kept rows alike. A pointer at a usable run's `refused` or `fault` row names that run and that
    call and is a blocked-call row; at any other row it is a conduct pointer of that run.

    Asked of the cited run c, whose second call is well-formed or carries another world's id, no
    world id, no call id, or another run's call id: only a well-formed c lets b's pointers at c's
    first or second row resolve (a pair, queued); otherwise both are unresolved (no two-run
    pair). In every case: the control's ledger with no fragment or past its last row is
    unresolved (no pair); its first row is a conduct pointer (a pair, queued); b's refused row
    with the control's refused row, and b's fault row with it, are blocked-call rows (gap-only:
    user record, no defender row); b's refused row with the control's ordinary row is not
    gap-only (queued)."""
    built = S.family(tmp_path, S.triad(
        a={"calls": [S.CallRow(), S.refused_call()]},
        b={"calls": [S.CallRow(), S.oracle_call(fact_id="f-b", forged_id="fg-b-1"),
                     S.refused_call(), S.fault_call()]},
        c={"calls": [S.CallRow(system="edr", params=S.query_params("host:db-1")),
                     _c_second_call(second_call)]}))
    report = S.conduct("b")
    _run(built, {"b": _reply(investigator=[
        _inv([report, built.served("a", None)], tag="no-fragment"),
        _inv([report, built.served("a", 99)], tag="past-last-row"),
        _inv([report, _served(built, "a", 0)], tag="control-row"),
        _inv([_served(built, "b", 2), _served(built, "a", 1)], tag="refused-pair"),
        _inv([_served(built, "b", 3), _served(built, "a", 1)], tag="fault-refused"),
        _inv([_served(built, "b", 2), _served(built, "a", 0)], tag="refused-and-ordinary"),
        _inv([report, built.served("c", 0)], tag="c-first-row"),
        _inv([report, built.served("c", 1)], tag="c-second-row")])})

    c_usable = second_call == "well_formed"
    lanes = [S.lane_of(built, built.finding_id("b", 0, i)) for i in range(8)]
    assert lanes == [NO_PAIR, NO_PAIR, DEFENDER, USER_RECORD, USER_RECORD, DEFENDER,
                     DEFENDER if c_usable else NO_PAIR, DEFENDER if c_usable else NO_PAIR]
    assert [_row_on(S.defender_queue(), built.finding_id("b", 0, i)) for i in (3, 4)] == [
        None, None]
    assert [_surfaces(built, S.marker("b", t)) for t in ("no-fragment", "past-last-row")] == [
        [], []]


@pytest.mark.parametrize("d_state", ["malformed_world", "not_archived_world", "plain_twin"])
def test_1234_am_reference_half_in_a_run_outside_the_reference_set(tmp_path: Path,
                                                                   d_state: str) -> None:
    """The reference half must be a conduct pointer in a run that is a reference for b (A1: a
    conduct pointer in the focus run and one in a reference run); a planted world excluded as
    malformed leaves every reference set (A3) and a not-archived world is not a reference, so a
    pair using either fails the two-run rule and the finding is dropped.

    A fourth world d is malformed (its report carries two dispositions), or not archived (its
    own record says so; its served ledger is on disk, written by its run), or an ordinary
    gradable world (the twin). b's report against d's investigation, and against d's served row,
    are dropped for no two-run pair and reach no output unless d is the ordinary twin, where
    both queue; b's resolving sibling pair queues in every case."""
    if d_state == "not_archived_world":
        built = S.family(tmp_path, _with_d(archived=False,
                                           world_record=S.sym(S.OUTCOME, "NOT_ARCHIVED")))
        row = S.ledger_row(S.CallRow(system="siem-x", verb="lookup", params={"entity": "svc-9"}),
                           label="d", token=built.token,
                           cid=S.call_id("d", 0, episode_token=built.token))
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
    """A pointer into an excluded world's oracle store does not resolve; the control's store
    resolves only if the control is a reference run.

    A fourth world d is O5-failed (its world record on disk beside its archive), cut short, or
    malformed — or an ordinary world (the twin). The control carries an oracle store too. Beside
    b's resolving pair, d's forged rows are cited only for the twin, the control's store always
    (a graded family's control is a reference run). Alone in a world finding, d's forged rows
    are unresolved when d is excluded and name only d otherwise; the control's store alone names
    only the control."""
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


# --------------------------------------------------------------------------------------
# s_D30 / s_D33 — hostile pointers; a manifest that is a link.
# --------------------------------------------------------------------------------------

#: D30's hostile pointers: empty, whitespace, only a fragment, absolute, home-relative, a URL, a
#: glob, an embedded newline, an embedded NUL, and one far longer than any path.
_HOSTILE = ["", "   ", "#worlds/b", "/etc/passwd", "~/worlds/b/report.md",
            "https://example.com/worlds/b/report.md", "worlds/*/report.md",
            "worlds/b/report.md\nworlds/a/report.md", "worlds/b/report.md\x00",
            "worlds/b/" + "x" * 5000 + ".md"]


def test_1234_pointer_with_hostile_syntax(tmp_path: Path) -> None:
    """A hostile pointer is an unresolved pointer: the finding is dropped for its evidence; the
    reply is valid, the pass does not stop.

    Every hostile pointer rides beside b's resolving pair (queued, citing only the pair), and
    another finding cites only hostile pointers (dropped, pointers unresolved). The reply passes
    validation, b is asked once (no re-ask), and the pass goes on to judge c and the family."""
    built = S.family(tmp_path)
    pair = [S.conduct("b"), S.conduct("a")]
    reply = _reply(investigator=[_inv([*pair, *_HOSTILE], tag="pair-and-hostile"),
                                 _inv(_HOSTILE, tag="hostile-only")])
    seam = _run(built, {"b": reply})

    assert _cites(built.finding_id("b", 0, 0)) == set(pair)
    assert S.lane_of(built, built.finding_id("b", 0, 1)) == UNRESOLVED
    assert _surfaces(built, S.marker("b", "hostile-only")) == []
    assert (seam.calls_for("b"), seam.called("c"), seam.called(S.FAMILY)) == (
        ["judge:b:0"], True, True)
    S.validate(reply)


@pytest.mark.parametrize("link", ["to_a_byte_copy_of_itself", "to_a_reference_runs_report",
                                  "plain_twin"])
def test_1234_manifest_replaced_by_a_link_and_cited_as_design(tmp_path: Path, link: str) -> None:
    """A manifest that is a link is not resolved (no-follow, principle 1): a pointer to it does not
    resolve, so the finding is not design-routed and the questioner queue gets nothing from it;
    the pass refuses the family load if the manifest itself is a link.

    family.yaml is replaced by a link — to a byte copy of itself outside the episode (a reader
    that followed it would load a valid manifest), or to reference run c's report.md. The pass
    refuses by naming the manifest, asks the model nothing, and queues nothing. The twin: the
    plain manifest, where b's world finding citing its plan entry is design and reaches the
    questioner queue under world b."""
    built = S.family(tmp_path)
    manifest = built.ep / "family.yaml"
    if link == "to_a_byte_copy_of_itself":
        S.plant_symlink(manifest, S.scratch_copy(tmp_path, manifest, "manifest-copy.yaml"))
    elif link == "to_a_reference_runs_report":
        S.plant_symlink(manifest, "worlds/c/report.md")
    damaged = link != "plain_twin"
    assert _manifest_case(built, damaged=damaged) == _manifest_expected(damaged=damaged)


# --------------------------------------------------------------------------------------
# g06 / g07 / g08 / g09 — the R3 parity cells.
# --------------------------------------------------------------------------------------

_FIVE = ("manifest", "conduct", "oracle", "served", "table")


@pytest.mark.parametrize("damaged", [True, False], ids=["oversize", "plain-twin"])
@pytest.mark.parametrize("where", _FIVE)
def test_1234_an_oversize_file_is_refused_by_name_on_every_read_cell(tmp_path: Path, where: str,
                                                                     damaged: bool) -> None:
    """A file larger than the reader's limit, planted at each of the five boundaries (family.yaml,
    a run's conduct file, an oracle store, a served ledger, a query table), is refused by name on
    both access cells: the bounded fs-read reader refuses it, and an evidence pointer naming it
    does not load it, resolves to nothing and drops the finding without hanging or exhausting
    memory; the other worlds are still graded. The control is the same file under the limit,
    which reads and resolves.

    The file is a sparse one, one byte over the reader's limit, in reference run c (or the
    manifest itself). An oversize manifest refuses the family load by name before any model
    call. Otherwise c's row names the refused file, b's pointer at it does not resolve (no
    two-run pair as a half, not cited riding along, unresolved alone) and b's sibling pair
    queues; the twin resolves."""
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
    """An evidence pointer naming a FIFO, a directory or a device node in each of the five classes
    (manifest plan, conduct file, oracle store, served ledger, query table), and a manifest that
    is itself such a file, is unresolved or refused by name: the pass never blocks on it and no
    finding rests on it. The control is a plain file in the same position, which resolves.

    Every pass runs under the watchdog, so a blocking open fails the test by name. A manifest
    that is a FIFO, a directory or a device node refuses the family load by name before any
    model call; a pointer at such a file in reference run c does not resolve (no two-run pair as
    a half, not cited riding along, unresolved alone) while b's sibling pair queues."""
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
    """A pointer into a file the fs-read reader refuses as malformed (a torn query table or
    oracle-store row, a report with a second disposition key) does not resolve and names no run,
    in the same pass in which that run is malformed and out of every reference set (A3); the
    pointer cannot reach rows the reader would not. The control is the same pointer into a
    well-formed file, which resolves.

    Planted in reference run c: alone in a world finding the pointer is unresolved (it names no
    run) rather than naming only c, it is no two-run half and is not cited riding along, and c's
    row is not gradable in that pass, naming the file. The twin resolves and names c."""
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
    """A pointer naming a symbolic link, a path under a linked directory or a hard-linked file
    inside oracle/<X>/ or served/<token>.<X>.jsonl does not resolve, as in the conduct and
    query-table classes; the control is the plain file, which resolves.

    In reference run c: c's oracle store replaced by a symlink, reached under a linked
    directory, or hard-linked; c's served ledger replaced by a symlink or hard-linked (served/
    is the one directory above a ledger, and linking it would put the control's ledger behind a
    link too). Every link target is a byte copy outside the episode. The pointer does not
    resolve (not cited riding along, no two-run half, unresolved alone); the plain twin
    resolves."""
    seen, expected, _built, _path = _cell(tmp_path, where, kind)
    assert seen == expected
