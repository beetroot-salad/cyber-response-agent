"""#1234 slice 10 — the per-world commit (A6) and the re-run.

What this file pins: judge.yaml's per-world row is the ONE owner of "graded and queued". Each
world (and the family call) commits `queueing` -> its queue appends -> `queued`, the flip
carrying the world's serving findings and named gaps; the final write adds the found gaps and
runs on every pass; every later write carries recorded rows verbatim. A re-run regrades a world
with no row (overwriting its draw files), skips a `queued` one, and refuses loudly, naming the
world, at the first row left `queueing`. No reader reads a draw file judge.yaml does not record.
Plus the three channel-identity obligations the per-world appends touch (g05, g20, g21).

HOW A PASS IS STOPPED HERE (every stop is a real refusal through the real primitive, or the
interpreter's own interrupt):
  * a refused judge.yaml write — `Refuse` gives the record a second hard link outside the
    episode (its bytes untouched), so the guarded writer's next replace refuses (`NotPlainEntry`,
    EMLINK, observed at base 463833df by this writer's smoke run); before the record exists it
    plants an empty directory at its name instead. Planted MID-PASS through a seam (a judge.yaml
    planted before the pass refuses the pass's opening read instead, also observed);
  * a refused queue append — the same plant at the channel's queue file: the state handle's
    read under the append lock refuses it (`StateRefused`, a `BaseException`, observed);
  * an operator's interrupt — `KeyboardInterrupt` raised as a named model call starts (what the
    interpreter raises on SIGINT; it is not an `Exception`, so no containment arm in the pass
    catches it).
`Watch` wraps the pass's two seams (`judge=`, `state=`): it records what the pass had left at
each model call and before each queue append, and fires the one fault a scenario declares. It
never answers, classifies or routes — answers come from the wrapped `S.RoutedJudge`, every
state verb from the real handle.

NOT ON MAIN: at 463833df every amended reply is refused as malformed, nothing is queued, and
judge.yaml is written once at the end — so each "unchanged / verbatim / once" assertion here is
preceded by a presence assertion naming the world's own finding, which is what makes it red on
main rather than vacuously green over empty queues.
"""
from __future__ import annotations

import collections
import contextlib
import json
import multiprocessing
import os
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any


from defender import _yaml
from defender.tests.judge_contrast_1234 import _spec1234 as S

# --------------------------------------------------------------------------------------
# Labels, names and words.
# --------------------------------------------------------------------------------------

#: Distinctive labels, so "the refusal names the world" is a real substring test.
CONTROL, B, C, D = "alpha", "bravo", "charlie", "delta"
FAMILY = S.FAMILY

#: More episodes beside `S.EPISODE_ID`, for scenarios that need two or more.
EP2 = "20260728t161845z-fresh-case-n60"
EP3 = "20260728t161845z-fresh-case-n61"

COMPLETED = S.RULED["row.completed_draws"]
BUCKET = S.RULED["reply.bucket"]
MEASURED = S.COINED["row.measured"]
NOT_MEASURED_REASON = S.COINED["row.not_measured_reason"]
DRAWS_DISAGREE = S.COINED["row.draws_disagree"]
DRAWS = S.COINED["row.draws"]

#: main's not-graded stamp field — "unchanged in kind" by the design's data model.
STAMP = S.STAMP

#: The record fields the design retires from judge.yaml (d00a names these three).
RETIRED_ON_RECORD = ("verdict_word", "episode_outcome", "family_outcome")

#: The page's per-world state words and the queue words a queueing refusal names (`S.COINED`;
#: "not enqueued" is N10's own phrase).
WORDS = {k: S.COINED[k] for k in ("page.in_progress", "page.graded", "page.ungraded",
                                  "page.not_enqueued", "refusal.defender_queue",
                                  "refusal.questioner_queue")}

DEFENDER_Q, QUESTIONER_Q = "defender", "questioner"


def _channel(kind: str) -> Any:
    return S.sym(S.STATE, "FINDINGS" if kind == DEFENDER_Q else "QUESTIONER_FINDINGS")


def _kind_of(channel: Any) -> str:
    return DEFENDER_Q if channel.queue == _channel(DEFENDER_Q).queue else QUESTIONER_Q


def _state_refused() -> type[BaseException]:
    return S.sym(S.STATE, "StateRefused")


# --------------------------------------------------------------------------------------
# The family and its replies.
# --------------------------------------------------------------------------------------


def _worlds(*labels: str) -> list[S.World]:
    """Control `alpha` plus planted worlds in manifest (= grading) order — default bravo,
    charlie. bravo is shown its facts (one altered answer) and has one refused call (a found
    gap of its run, `sent-bravo`); charlie has one passthrough and one refused call
    (`sent-charlie`); delta is shown its facts."""
    planted = {
        B: S.planted(B, calls=[S.CallRow(),
                               S.oracle_call(fact_id=f"f-{B}", forged_id=f"fg-{B}-1"),
                               S.refused_call(params={"entity": f"sent-{B}"})]),
        C: S.planted(C, role="C", forged_system="edr",
                     calls=[S.CallRow(system="edr", params=S.query_params("host:db-1")),
                            S.refused_call(params={"entity": f"sent-{C}"})]),
        D: S.planted(D, role="D",
                     calls=[S.CallRow(),
                            S.oracle_call(fact_id=f"f-{D}", forged_id=f"fg-{D}-1")]),
    }
    return [S.control(CONTROL, calls=[S.CallRow()]),
            *(planted[x] for x in (labels or (B, C)))]


def _built(tmp_path: Path, *labels: str, episode_id: str = S.EPISODE_ID) -> S.Built:
    return S.family(tmp_path, _worlds(*labels), episode_id=episode_id)


def _claim(label: str, tag: str) -> str:
    return f"claim {S.marker(label, tag)}"


def _inv(label: str, tag: str, *, contrast: Sequence[str] | None = None) -> dict:
    """An investigator finding of `label` (default: its report against the control's — a
    resolving two-run conduct pair), its claim carrying `marker(label, tag)`."""
    return S.inv(contrast=list(contrast) if contrast is not None
                 else [S.conduct(label), S.conduct(CONTROL)], claim=_claim(label, tag))


def _nowhere(n: Any) -> list[str]:
    """Contrast pointers into files neither archive holds: every pointer unresolved, so the
    finding is dropped (A13: it keeps its filed index)."""
    return [S.conduct(B, f"nowhere-{n}.md"), S.conduct(CONTROL, f"nowhere-{n}.md")]


def _design(label: str, tag: str) -> dict:
    """A design world finding (a resolving plan pointer at `label`'s entry, not gap-only) —
    `mislabelled`, so the world stays measured."""
    return S.wf("mislabelled", systems=["idp"], evidence=[S.plan_ptr(label)],
                claim=_claim(label, tag))


def _serving(label: str, tag: str) -> dict:
    """A serving world finding: a samples pointer only (no plan, no conduct pointer)."""
    return S.wf("mislabelled", systems=["idp"], evidence=[S.samples_ptr("idp")],
                claim=_claim(label, tag))


def _unreachable(label: str, tag: str) -> dict:
    """An `unreachable` world finding (design-routed): the world is not measured."""
    return S.wf("unreachable", systems=["idp"], evidence=[S.plan_ptr(label)],
                claim=_claim(label, tag))


def _family_design(tag: str) -> dict:
    """A family-scope design finding (the plan's family-level part)."""
    return S.wf("unreachable", systems=["idp"], evidence=[S.plan_ptr(None)],
                claim=_claim(FAMILY, tag))


def _named_gap(built: S.Built, label: str, i: int) -> dict:
    """A deployment gap naming world `label`'s `i`-th own call (a refused one) by its table
    row and its served-ledger row."""
    return S.gap(evidence=[built.table(label, built.own_row(label, i)),
                           built.served(label, built.served_row(label, i))])


def _blocked(label: str) -> tuple[Any, ...]:
    """The blocked-call key of `label`'s refused `edr lookup` (A2/A7: run, system, verb,
    params)."""
    return (label, "edr", "lookup", S.canonical({"entity": f"sent-{label}"}))


def _reply(*, bucket: str = "lead-quality", inv: Iterable[dict] = (),
           world: Iterable[dict] = (), gaps: Iterable[dict] = ()) -> dict:
    return S.world_reply(bucket, ["idp"], investigator=list(inv), world=list(world),
                         gaps=list(gaps))


# --------------------------------------------------------------------------------------
# Reading what the pass left.
# --------------------------------------------------------------------------------------


def _row(record: Mapping[str, Any], label: str) -> dict:
    """World `label`'s row in a judge.yaml document (`{}` when it has none)."""
    for r in record.get("worlds") or []:
        if isinstance(r, dict) and r.get("world") == label:
            return r
    return {}


def _state_of(record: Mapping[str, Any], who: str) -> Any:
    """The A6 state of world `who`'s row, or of the family's row (`who == FAMILY`)."""
    if who == FAMILY:
        fam = record.get(S.FAMILY_ROW)
        return fam.get(S.STATE_KEY) if isinstance(fam, dict) else None
    return _row(record, who).get(S.STATE_KEY)


def _user(record: Mapping[str, Any]) -> dict:
    value = record.get(S.USER)
    return value if isinstance(value, dict) else {}


def _field(obj: Any, name: str) -> Any:
    """`name` off a returned record or a nested part of it (a mapping or a model)."""
    return obj.get(name) if isinstance(obj, Mapping) else getattr(obj, name, None)


def _strings(value: Any) -> Iterator[str]:
    """Every string leaf of a judge.yaml document."""
    if isinstance(value, str):
        yield value
    elif isinstance(value, Mapping):
        for k, v in value.items():
            yield from _strings(k)
            yield from _strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _strings(v)


def _label_of(row: Mapping[str, Any]) -> str:
    """The world (or `family`) a queue row's `<episode>/<label>/<draw>/<index>` id names."""
    return str(row.get("finding_id")).split("/")[1]


def _carrying(rows: Iterable[Mapping[str, Any]], mark: str) -> list[dict]:
    """The rows whose content carries `mark` (a finding's claim marker)."""
    return [dict(r) for r in rows if mark in json.dumps(r)]


def _ids(rows: Iterable[Mapping[str, Any]]) -> list[str]:
    return [str(r.get("finding_id")) for r in rows]


def _bytes_of(paths: Iterable[Path]) -> dict[str, bytes]:
    return {p.name: p.read_bytes() for p in paths}


_VOID_TAGS = frozenset({"area", "base", "br", "col", "embed", "hr", "img", "input", "link",
                        "meta", "source", "track", "wbr"})






def _without(text: str, *episode_ids: str) -> str:
    """`text` with every episode id and token replaced, so two episodes' rows compare."""
    token_for = S.sym(S.FAMILY_LOADER, "episode_token_for")
    for ep in episode_ids:
        text = text.replace(ep, "<ep>").replace(token_for(ep), "<ep>")
    return text


# --------------------------------------------------------------------------------------
# The pass's two seams, watched and (at most once per declared fault) faulted.
# --------------------------------------------------------------------------------------


@dataclass
class Seen:
    """What the pass had left at one moment: judge.yaml as written, and both queues."""

    event: str            # "call" (a model call starting) or "append" (before the append)
    who: str | None       # the world, or "family", the call or the appended rows are about
    kind: str | None      # the appended channel: "defender" / "questioner"
    record: dict
    defender: list[dict] | None
    questioner: list[dict] | None


class Refuse:
    """A refused entry, planted when fired: at `path`, or (`queue="same"` / `"other"`) at the
    queue file of the channel the firing append names / of the other judge channel. A plain
    file standing there gets a second hard link at `spare` (outside the episode; its bytes
    untouched), so the guarded writer or reader refuses it; an absent one becomes an empty
    directory. `clear()` removes the plant, as an operator freeing the disk does."""

    def __init__(self, spare: Path, path: Path | None = None, *, queue: str | None = None):
        self.spare, self.path, self.queue = Path(spare), path, queue
        self.planted: Path | None = None
        self.kind: str | None = None

    @property
    def fired(self) -> bool:
        return self.planted is not None

    def __call__(self, channel: Any = None) -> None:
        if self.path is not None:
            target = Path(self.path)
        else:
            kind = _kind_of(channel)
            if self.queue == "other":
                kind = QUESTIONER_Q if kind == DEFENDER_Q else DEFENDER_Q
            target = Path(S.env_state().describe(_channel(kind)))
        if target.is_file():
            S.plant_hardlink(self.spare, target)
            self.kind = "link"
        else:
            S.plant_dir(target)
            self.kind = "dir"
        self.planted = target

    def clear(self) -> None:
        if self.kind == "link":
            self.spare.unlink()
        elif self.kind == "dir" and self.planted is not None:
            self.planted.rmdir()
        self.kind = None


Action = Callable[[Any], None]


class Watch:
    """The `judge=` seam (wrapping a `RoutedJudge`) and, through `.state`, the `state=` seam
    (wrapping the real learning-state handle). Records a `Seen` as every model call starts and
    before every queue append. Fires only the faults declared: `at_call[(label, n)]` as that
    call starts; `stop_at=(label, n)` raises `KeyboardInterrupt` there; `before_append` /
    `after_append[(label, kind)]` (kind `None`: either channel) around the first append whose
    rows name `label`. Each action is handed the appended channel (`None` at a call)."""

    def __init__(self, built: Any, judge: S.RoutedJudge, *,  # noqa: PLR0913 — one switch per declared fault
                 at_call: Mapping[tuple[str, int], Action] | None = None,
                 stop_at: tuple[str, int] | None = None,
                 before_append: Mapping[tuple[str, str | None], Action] | None = None,
                 after_append: Mapping[tuple[str, str | None], Action] | None = None,
                 state: Any = None) -> None:
        self.built = built
        self.judge = judge
        self.real = state if state is not None else S.env_state()
        self.at_call = dict(at_call or {})
        self.stop_at = stop_at
        self.before_append = dict(before_append or {})
        self.after_append = dict(after_append or {})
        self.seen: list[Seen] = []

    def _queue(self, kind: str) -> list[dict] | None:
        try:
            return self.real.rows(_channel(kind))
        except _state_refused():
            return None

    def snap(self, event: str, who: str | None, kind: str | None) -> None:
        self.seen.append(Seen(event, who, kind, S.record(self.built), self._queue(DEFENDER_Q),
                              self._queue(QUESTIONER_Q)))

    def first(self, event: str, who: str, kind: str | None = None) -> Seen:
        for s in self.seen:
            if s.event == event and s.who == who and (kind is None or s.kind == kind):
                return s
        raise AssertionError(f"the pass made no {event} for {who!r}"
                             + (f" on the {kind} queue" if kind else "")
                             + f"; it made {[(s.event, s.who, s.kind) for s in self.seen]}")

    def __call__(self, prompt: str, **kw: Any) -> str:
        label, n, _attempt = S.parse_agent_id(kw.get("agent_id", "judge"))
        self.snap("call", label, None)
        action = self.at_call.pop((label, n), None) if label is not None else None
        if action is not None:
            action(None)
        if self.stop_at is not None and self.stop_at == (label, n):
            raise KeyboardInterrupt(f"interrupted as judge:{label}:{n} started")
        return self.judge(prompt, **kw)

    def fire(self, table: dict, labels: Iterable[str], kind: str, channel: Any) -> None:
        for label in labels:
            for key in ((label, kind), (label, None)):
                action = table.pop(key, None)
                if action is not None:
                    action(channel)

    @property
    def state(self) -> Any:
        return _WatchedState(self)


class _WatchedState:
    """The real learning-state handle with `append` observed; every other verb delegated."""

    def __init__(self, watch: Watch) -> None:
        self._watch = watch

    def __getattr__(self, name: str) -> Any:
        return getattr(self._watch.real, name)

    def append(self, channel: Any, rows: list[dict], **kw: Any) -> Any:
        w = self._watch
        kind = _kind_of(channel)
        labels = list(dict.fromkeys(_label_of(r) for r in rows))
        for label in labels:
            w.snap("append", label, kind)
        w.fire(w.before_append, labels, kind, channel)
        out = w.real.append(channel, rows, **kw)
        w.fire(w.after_append, labels, kind, channel)
        return out


def _stopped(built: Any, watch: Watch, **kw: Any) -> BaseException:
    """Run a pass expected to stop at its planted fault; return what stopped it."""
    try:
        S.grade(built, watch, state=watch.state, **kw)
    except (*S.stops(), KeyboardInterrupt) as stopped:
        return stopped
    raise AssertionError("the pass was expected to stop at its planted fault and finished")


def _left_queueing(tmp_path: Path, episode_id: str, *, spare: str,
                   reply: dict | None = None) -> S.Built:
    """An episode whose first pass stopped after world bravo's defender append and before its
    flip (the flip write refused): bravo's row is left `queueing`, charlie and the family have
    none. Returns the episode with the plant cleared."""
    built = _built(tmp_path, episode_id=episode_id)
    flip = Refuse(tmp_path / spare, built.ep / "judge.yaml")
    watch = Watch(built, S.judge({B: reply or _reply(inv=[_inv(B, "left")])}),
                  after_append={(B, DEFENDER_Q): flip})
    _stopped(built, watch)
    flip.clear()
    assert flip.fired, "the pass never appended bravo's defender rows"
    assert _state_of(S.record(built), B) == S.QUEUEING, (
        f"bravo's row after a stop between its append and its flip: {_row(S.record(built), B)}")
    return built


def _no_duplicate_ids(*queues: list[dict]) -> None:
    for queue in queues:
        twice = [i for i, n in collections.Counter(_ids(queue)).items() if n > 1]
        assert not twice, f"queued rows duplicated: {twice}"


# ======================================================================================
# d00a, d10a, d10b, d10c — the record, the order, the commit, the re-run.
# ======================================================================================


def test_1234_grade_returns_per_world_measurement_record(tmp_path):
    """grade_episode(runs, episode_id, *, judge, state, draws, git_show) (main's signature at 463833df,
    unchanged by #1234) returns the EpisodeGrade it writes to judge.yaml: each gradable world row carries the world's
    bucket when every completed draw agrees on it (None, with the world withheld and the row saying the draws disagree,
    otherwise), every draw's bucket, completed_draws, measured and (when not measured) a reason, and its A6 state;
    the family row records its completed draws; the record carries a user section; and neither the returned record
    nor the file has a verdict_word, episode_outcome or family_outcome field."""
    built = _built(tmp_path, B, C, D)
    agree = _reply(inv=[_inv(B, "agreed")])
    judge = S.judge({
        (B, 0): agree, (B, 1): agree,
        (C, 0): _reply(bucket="lead-quality", inv=[_inv(C, "split-0")]),
        (C, 1): _reply(bucket="lead-set", inv=[_inv(C, "split-1")]),
        (D, 0): _reply(world=[_unreachable(D, "u-0")]),
        (D, 1): _reply(world=[_unreachable(D, "u-1")]),
    })

    out = S.grade(built, judge, draws=2)

    on_disk = S.record(built)
    assert on_disk, "the pass wrote no judge.yaml"
    assert S.rows(out) == S.rows(built), "the returned record is not the one written"
    rows = S.rows(built)
    for label in (B, C, D):
        assert rows.get(label, {}).get(COMPLETED) == 2, (label, rows.get(label))
        assert rows[label].get(S.STATE_KEY) == S.QUEUED, (label, rows[label])

    unanimous = rows[B]
    assert unanimous.get(BUCKET) == "lead-quality"
    assert [d.get(BUCKET) for d in unanimous.get(DRAWS) or []] == ["lead-quality"] * 2
    assert unanimous.get(MEASURED) is True
    assert _carrying(S.from_world(S.defender_queue(), B), S.marker(B, "agreed")), (
        "bravo is measured and unanimous, yet its finding is not on the defender queue")

    split = rows[C]
    assert split.get(BUCKET) is None, split
    assert split.get(DRAWS_DISAGREE) is True, split
    assert [d.get(BUCKET) for d in split.get(DRAWS) or []] == ["lead-quality", "lead-set"]
    assert S.from_world(S.defender_queue(), C) == [], "a withheld world queued defender rows"

    unmeasured = rows[D]
    assert unmeasured.get(MEASURED) is False, unmeasured
    assert unmeasured.get(NOT_MEASURED_REASON), unmeasured

    family = on_disk.get(S.FAMILY_ROW)
    assert isinstance(family, dict), family
    assert family.get(COMPLETED) == 2, family
    assert _field(_field(out, S.FAMILY_ROW), COMPLETED) == 2
    assert isinstance(on_disk.get(S.USER), dict), "judge.yaml carries no user section"
    assert _field(out, S.USER) is not None, "the returned record carries no user section"
    for retired in RETIRED_ON_RECORD:
        assert retired not in on_disk, f"judge.yaml still has `{retired}`"
        assert _field(out, retired) is None, f"the returned record still has `{retired}`"




def test_1234_world_row_commits_queueing_then_appends_then_queued(tmp_path):
    """For each world and the family, judge.yaml's row is written `queueing` before any of its queue appends
    and flipped to `queued` after them, carrying its serving findings and named gaps; the final write adds the found
    gaps and runs on every pass; every later write carries recorded rows verbatim (A6)."""
    built = _built(tmp_path)
    judge = S.judge({
        B: _reply(inv=[_inv(B, "def")], world=[_design(B, "design"), _serving(B, "serving")],
                  gaps=[_named_gap(built, B, 2)]),
        C: _reply(inv=[_inv(C, "def")]),
        FAMILY: S.family_reply(world=[_family_design("plan")]),
    })
    watch = Watch(built, judge)

    S.grade(built, watch, state=watch.state)

    appends = [s for s in watch.seen if s.event == "append"]
    assert {(s.who, s.kind) for s in appends} >= {
        (B, DEFENDER_Q), (B, QUESTIONER_Q), (C, DEFENDER_Q), (FAMILY, QUESTIONER_Q)}, (
        f"appends seen: {[(s.who, s.kind) for s in appends]}")
    for s in appends:
        assert _state_of(s.record, s.who) == S.QUEUEING, (
            f"{s.who}'s rows went to the {s.kind} queue while its row was "
            f"{_state_of(s.record, s.who)!r}")
    final = S.record(built)
    for who in (B, C, FAMILY):
        assert _state_of(final, who) == S.QUEUED, (who, _state_of(final, who))

    at_b_append = watch.first("append", B)
    at_c = watch.first("call", C)
    serving = S.marker(B, "serving")
    assert serving not in json.dumps(at_b_append.record), "serving finding recorded before the flip"
    assert any(serving in json.dumps(e) for e in _user(at_c.record).get(S.SERVING) or []), (
        "bravo's flip did not carry its serving finding onto the record")
    assert _blocked(B) in {S.gap_key(e) for e in _user(at_c.record).get(S.NAMED_GAPS) or []}, (
        "bravo's flip did not carry its named gap onto the record")
    assert {_blocked(B), _blocked(C)} <= {S.gap_key(e) for e in S.found_gaps(built)}, (
        f"the final write's found gaps: {S.found_gaps(built)}")
    assert _row(final, B) == _row(at_c.record, B), "a later write changed bravo's recorded row"

    record_path = built.ep / "judge.yaml"
    inode = os.stat(record_path).st_ino
    again = S.judge()
    S.grade(built, again)
    assert again.calls == 0
    assert os.stat(record_path).st_ino != inode, "the re-run pass made no final write"
    after = S.record(built)
    for label in (B, C):
        assert _row(after, label) == _row(final, label)
    assert after.get(S.FAMILY_ROW) == final.get(S.FAMILY_ROW)


#: A judge.yaml as the pre-change writer (main at 463833df) wrote it: world bravo completed no
#: draw (so main would grade it again and carry charlie's row), charlie graded.
_PRE_CHANGE_RECORD = {
    "worlds": [
        {"world": B, "declared": "malicious", "verdict": "malicious", "resolution_moved": True,
         "malformed_rows": 0, "served_nothing": False, "completed_draws": 0,
         "malformed_replies": 0, "draws": [], "bucket": None, "systems": None, "findings": []},
        {"world": C, "declared": "malicious", "verdict": "malicious", "resolution_moved": True,
         "malformed_rows": 0, "served_nothing": False, "completed_draws": 1,
         "malformed_replies": 0, "draws": [{"draw": 0, "bucket": "lead-quality",
                                            "systems": ["idp"]}],
         "bucket": "lead-quality", "systems": ["idp"], "findings": []},
    ],
    "verdict_word": "undecidable", "episode_outcome": "gradable", "validity": "usable",
    "enqueued_rows": 0, "enqueued_to": "", "draws": {"configured": 1, "completed": 1},
    "knobs": {"draws": 1, "model": "kimi-k3", "effort": "medium", "payload_cap": 20000},
    "lessons_commit": "deadbee", "queue_malformed_rows": 0, "world_queue_malformed_rows": 0,
    "unqueueable_findings": [], "family_outcome": None, "family_failed_reason": None,
    "family_malformed_replies": 0, "family_completed_draws": 1, "world_enqueued_rows": 0,
    "world_enqueued_to": "", "world_findings": [], "dispositions": [],
}


def test_1234_rerun_grades_only_worlds_without_a_completed_draw_and_keeps_rows_verbatim(tmp_path):
    """After a first pass in which world b's draw failed (no row for b), a bare re-run judges only b (and
    the family call only if the family has no row), leaves every row the first pass queued byte-identical, appends
    only b's rows, and makes no model call once every gradable world and the family are `queued`; a re-run over a
    pre-change judge.yaml refuses by name instead of carrying its rows (A4)."""
    built = _built(tmp_path)
    S.grade(built, S.judge({C: _reply(inv=[_inv(C, "first")], world=[_design(C, "first-q")]),
                            FAMILY: S.family_reply(world=[_family_design("plan")])},
                           fail={B}))
    first = S.record(built)
    assert _row(first, B).get(S.STATE_KEY) is None, f"bravo's failed draw left {_row(first, B)}"
    assert _state_of(first, C) == S.QUEUED
    assert _state_of(first, FAMILY) == S.QUEUED
    defender_before, questioner_before = S.queue_bytes()
    assert S.marker(C, "first") in defender_before
    assert S.marker(C, "first-q") in questioner_before
    assert S.marker(FAMILY, "plan") in questioner_before

    second = S.judge({B: _reply(inv=[_inv(B, "late")], world=[_design(B, "late-q")])})
    S.grade(built, second)

    assert {S.parse_agent_id(a)[0] for a in second.agent_ids} == {B}, second.agent_ids
    defender_after, questioner_after = S.queue_bytes()
    for before, after, mark in ((defender_before, defender_after, "late"),
                                (questioner_before, questioner_after, "late-q")):
        assert after.startswith(before), "a row the first pass queued was rewritten"
        added = [json.loads(line) for line in after[len(before):].splitlines() if line.strip()]
        assert added, _ids(added)
        assert {_label_of(r) for r in added} == {B}, _ids(added)
        assert _carrying(added, S.marker(B, mark))
    second_record = S.record(built)
    assert _row(second_record, C) == _row(first, C)
    assert second_record.get(S.FAMILY_ROW) == first.get(S.FAMILY_ROW)
    assert _state_of(second_record, B) == S.QUEUED

    third = S.judge()
    S.grade(built, third)
    assert third.calls == 0
    assert S.queue_bytes() == (defender_after, questioner_after)

    old = _built(tmp_path, episode_id=EP2)
    (old.ep / "judge.yaml").write_text(_yaml.safe_dump(_PRE_CHANGE_RECORD, sort_keys=False),
                                       encoding="utf-8")
    old_text = S.record_text(old)
    probe = S.judge()
    refused = S.grade_refused(old, probe)
    assert any(S.word_re(name).search(str(refused)) for name in RETIRED_ON_RECORD), (
        f"the refusal does not name a retired field: {refused}")
    assert probe.calls == 0
    assert S.record_text(old) == old_text
    assert S.queue_bytes() == (defender_after, questioner_after)


# ======================================================================================
# The interrupted pass (A1, A3, A4, AM17, AM18, L8, L13, L22) and the stamp (L26).
# ======================================================================================






def test_1234_control_check_fails_on_rerun_after_first_pass_queued_rows(tmp_path):
    """A re-run whose control report no longer reads stamps the family not graded, naming the control and
    the cause (A3; the check runs after the unchanged gates). The stamp carries b's recorded row verbatim (A6), so
    b's queued rows stay on the queue and b's row stays on the record. A stamp pass meeting a `queueing` row writes
    its stamp carrying that row verbatim and names the `queueing` world in it; the next grade pass still refuses,
    naming that world (NA01)."""
    built = _built(tmp_path)
    S.grade(built, S.judge({B: _reply(inv=[_inv(B, "kept")])}, fail={C}))
    graded = _row(S.record(built), B)
    assert graded.get(S.STATE_KEY) == S.QUEUED
    assert _row(S.record(built), C).get(S.STATE_KEY) is None
    queues = S.queue_bytes()
    assert S.marker(B, "kept") in queues[0]

    (built.world_dir(CONTROL) / "report.md").unlink()
    stamp_pass = S.judge()
    S.grade(built, stamp_pass)

    record = S.record(built)
    stamp = json.dumps(record.get(STAMP))
    assert record.get(STAMP), f"no not-graded stamp: {sorted(record)}"
    assert CONTROL in stamp, f"the stamp names neither control nor cause: {stamp}"
    assert "report.md" in stamp, f"the stamp does not name the control's missing report: {stamp}"
    assert stamp_pass.calls == 0
    assert _row(record, B) == graded, "the stamp did not carry bravo's row verbatim"
    assert S.queue_bytes() == queues

    left = _left_queueing(tmp_path, EP2, spare="ep2-alias")
    queueing = _row(S.record(left), B)
    report = left.world_dir(CONTROL) / "report.md"
    text = report.read_text(encoding="utf-8")
    report.unlink()
    S.grade(left, S.judge())
    stamped = S.record(left)
    assert stamped.get(STAMP), f"no stamp over the queueing row: {sorted(stamped)}"
    assert _row(stamped, B) == queueing, "the stamp did not carry the queueing row verbatim"
    assert B in json.dumps(stamped.get(STAMP)), "the stamp does not name the queueing world"
    report.write_text(text, encoding="utf-8")
    refused = S.grade_refused(left, S.judge())
    assert B in str(refused), f"the next grade pass does not refuse naming bravo: {refused}"


def test_1234_am_pass_stops_after_queueing_before_or_between_appends(tmp_path):
    """A pass stopped after the `queueing` write leaves the row; the next pass refuses loudly, naming
    the world and saying its rows may be partly appended on either queue. The record keeps only A6's states, so an
    operator reconciles by hand (NA01; AP-07: the record is always one whole state)."""
    reply = _reply(inv=[_inv(B, "split")], world=[_design(B, "split-q")])
    rows: dict[str, dict] = {}
    for episode_id, when in ((S.EPISODE_ID, "before any append"), (EP2, "between appends")):
        built = _built(tmp_path, episode_id=episode_id)
        if when == "before any append":
            plant = Refuse(tmp_path / f"spare-{episode_id}", queue="same")
            watch = Watch(built, S.judge({B: reply}), before_append={(B, None): plant})
        else:
            plant = Refuse(tmp_path / f"spare-{episode_id}", queue="other")
            watch = Watch(built, S.judge({B: reply}), after_append={(B, None): plant})
        _stopped(built, watch)
        plant.clear()
        assert plant.fired, f"{when}: the pass never reached bravo's appends"
        mine = [[r for r in S.from_world(q, B) if episode_id in str(r.get("finding_id"))]
                for q in (S.defender_queue(), S.questioner_queue())]
        if when == "before any append":
            assert mine == [[], []], f"rows were appended before the stop: {mine}"
        else:
            assert sorted(bool(q) for q in mine) == [False, True], (
                f"the stop between appends left bravo's rows on {[bool(q) for q in mine]}")
        record = S.record(built)
        assert _state_of(record, B) == S.QUEUEING, (when, _row(record, B))
        rows[episode_id] = _row(record, B)
        before = S.queue_bytes()

        rerun = S.judge()
        refused = str(S.grade_refused(built, rerun))

        assert B in refused, f"{when}: the refusal does not name bravo: {refused}"
        assert WORDS["refusal.defender_queue"] in refused, refused
        assert WORDS["refusal.questioner_queue"] in refused, refused
        assert rerun.calls == 0
        assert S.queue_bytes() == before
    first, second = (_without(json.dumps(rows[e], sort_keys=True), S.EPISODE_ID, EP2)
                     for e in (S.EPISODE_ID, EP2))
    assert first == second, "the record tells a stop before the appends from one between them"




def test_1234_rerun_when_draw_files_are_complete_on_disk_but_judge_yaml_is_absent(tmp_path):
    """judge.yaml decides (A6): with no row for the world the pass regrades it and overwrites its draw
    files; draw files on disk are not trusted."""
    built = _built(tmp_path)
    stale = {(B, n): _reply(inv=[_inv(B, f"stale-{n}")]) for n in range(2)}
    stop = Refuse(tmp_path / "unused", built.ep / "judge.yaml")
    _stopped(built, Watch(built, S.judge(stale), at_call={(B, 1): stop}), draws=2)
    stop.clear()
    assert stop.fired
    assert len(S.draw_files(built, B)) == 2
    assert not _row(S.record(built), B), "the stopped pass left a row for bravo"

    fresh = {(B, n): _reply(inv=[_inv(B, f"fresh-{n}")]) for n in range(2)}
    rerun = S.judge(fresh)
    S.grade(built, rerun, draws=2)

    assert rerun.calls_for(B)[:2] == [f"judge:{B}:0", f"judge:{B}:1"], rerun.agent_ids
    for n in range(2):
        doc = json.dumps(S.draw_doc(built, B, n))
        assert S.marker(B, f"fresh-{n}") in doc
        assert S.marker(B, f"stale-{n}") not in doc
    queued = S.from_world(S.defender_queue(), B)
    assert _carrying(queued, S.marker(B, "fresh-0"))
    assert _carrying(queued, S.marker(B, "fresh-1"))
    assert not any(_carrying(queued, S.marker(B, f"stale-{n}")) for n in range(2))


def test_1234_judge_yaml_cannot_be_written_after_rows_were_queued(tmp_path):
    """The refused write is reported loudly (principle 2). Every world whose row had flipped to `queued`
    stays skipped on the next run, which makes no model call for it, recomputes the found gaps and writes the final
    record; no queued row is duplicated. If the refused write was a world's flip, that world's row stays `queueing`
    and the next run refuses naming it (A6)."""
    # The final write follows the family's own commit with no seam between them, so the
    # refusal is planted as the family call starts: the last judge.yaml write any seam reaches
    # (red-flagged in 82-writer-commit_and_rerun.md). Every world has flipped by then.
    built = _built(tmp_path)
    late = Refuse(tmp_path / "judge-alias", built.ep / "judge.yaml")
    first = S.judge({B: _reply(inv=[_inv(B, B)]), C: _reply(inv=[_inv(C, C)]),
                     FAMILY: S.family_reply(world=[_family_design("plan")])})
    stopped = _stopped(built, Watch(built, first, at_call={(FAMILY, 0): late}))
    late.clear()
    assert late.fired, stopped
    assert not isinstance(stopped, KeyboardInterrupt), stopped
    for label in (B, C):
        assert _state_of(S.record(built), label) == S.QUEUED, _row(S.record(built), label)
        assert _carrying(S.from_world(S.defender_queue(), label), S.marker(label, label))

    rerun = S.judge()
    S.grade(built, rerun)

    assert not rerun.called(B), rerun.agent_ids
    assert not rerun.called(C), rerun.agent_ids
    assert {_blocked(B), _blocked(C)} <= {S.gap_key(e) for e in S.found_gaps(built)}
    assert _state_of(S.record(built), FAMILY) == S.QUEUED
    _no_duplicate_ids(S.defender_queue(), S.questioner_queue())
    for label in (B, C):
        assert len(_carrying(S.defender_queue(), S.marker(label, label))) == 1

    flipped = _built(tmp_path, episode_id=EP2)
    flip = Refuse(tmp_path / "ep2-alias", flipped.ep / "judge.yaml")
    stopped = _stopped(flipped, Watch(flipped, S.judge({B: _reply(inv=[_inv(B, "flip")])}),
                                      after_append={(B, DEFENDER_Q): flip}))
    flip.clear()
    assert flip.fired, stopped
    assert not isinstance(stopped, KeyboardInterrupt), stopped
    assert _state_of(S.record(flipped), B) == S.QUEUEING
    assert B in str(S.grade_refused(flipped, S.judge()))




def test_1234_not_graded_stamp_then_the_control_is_repaired(tmp_path):
    """The re-run grades normally; the stamp is replaced, with recorded rows carried verbatim (A6); nothing
    else of the stamp remains."""
    built = _built(tmp_path)
    S.grade(built, S.judge({B: _reply(inv=[_inv(B, "kept")])}, fail={C}))
    graded = _row(S.record(built), B)
    assert graded.get(S.STATE_KEY) == S.QUEUED
    report = built.world_dir(CONTROL) / "report.md"
    text = report.read_text(encoding="utf-8")
    S.second_disposition(report)
    S.grade(built, S.judge())
    stamp = S.record(built).get(STAMP)
    assert stamp, "the malformed control did not stamp the family not graded"
    reason = str(_field(stamp, "reason") or "")
    assert reason, stamp

    report.write_text(text, encoding="utf-8")
    S.grade(built, S.judge({C: _reply(inv=[_inv(C, "repaired")])}))

    record = S.record(built)
    assert STAMP not in record, "the stamp survived the repaired re-run"
    assert reason not in set(_strings(record)), "the stamp's reason survived the repaired re-run"
    assert _row(record, B) == graded, "bravo's recorded row was not carried verbatim"
    assert _state_of(record, C) == S.QUEUED
    assert _carrying(S.from_world(S.defender_queue(), C), S.marker(C, "repaired"))
    assert len(_carrying(S.defender_queue(), S.marker(B, "kept"))) == 1


# ======================================================================================
# The bare re-run (L1, L2, L3, L4).
# ======================================================================================




def test_1234_bare_rerun_grades_only_the_world_with_no_completed_draw(tmp_path):
    """The re-run grades only world C; B's and D's draw files, rows and judge.yaml rows are untouched."""
    built = _built(tmp_path, B, C, D)
    refused_every_ask = "this text is not a reply document"
    S.grade(built, S.judge({B: _reply(inv=[_inv(B, "b")]), C: refused_every_ask,
                            D: _reply(inv=[_inv(D, "d")])}))
    first = S.record(built)
    assert _state_of(first, B) == S.QUEUED
    assert _state_of(first, D) == S.QUEUED
    assert _row(first, C).get(S.STATE_KEY) is None
    assert not _row(first, C).get(COMPLETED)
    draws = {who: _bytes_of(S.draw_files(built, who)) for who in (B, D)}
    defender = S.queue_bytes()[0]
    assert S.marker(B, "b") in defender
    assert S.marker(D, "d") in defender

    rerun = S.judge({C: _reply(inv=[_inv(C, "c")])})
    S.grade(built, rerun)

    assert rerun.called(C), rerun.agent_ids
    assert not rerun.called(B), rerun.agent_ids
    assert not rerun.called(D), rerun.agent_ids
    assert {who: _bytes_of(S.draw_files(built, who)) for who in (B, D)} == draws
    second = S.record(built)
    assert _row(second, B) == _row(first, B)
    assert _row(second, D) == _row(first, D)
    assert S.queue_bytes()[0].startswith(defender), "B's or D's queued rows were rewritten"
    assert _carrying(S.from_world(S.defender_queue(), C), S.marker(C, "c"))
    assert _state_of(second, C) == S.QUEUED






# ======================================================================================
# The readers (L18, AM21).
# ======================================================================================








# ======================================================================================
# The channels under per-world appends (g05, g20, g21).
# ======================================================================================

_G05_PROCESSES, _G05_EPISODES_EACH = 4, 3


def _g05_episode_id(k: int) -> str:
    return f"20260728t161845z-fresh-case-n{70 + k}"


def _g05_judge(k: int) -> S.RoutedJudge:
    """Episode `k`'s replies: bravo three defender findings and one design finding, charlie two
    defender findings, the family one design finding — each claim marked `g05-<k>-<i>`."""
    return S.judge({
        B: _reply(inv=[_inv(B, f"g05-{k}-{i}") for i in range(3)],
                  world=[_design(B, f"g05-{k}-3")]),
        C: _reply(inv=[_inv(C, f"g05-{k}-{i}") for i in range(2)]),
        FAMILY: S.family_reply(world=[_family_design(f"g05-{k}-0")]),
    })


def _g05_marks(k: int) -> list[str]:
    return ([S.marker(B, f"g05-{k}-{i}") for i in range(4)]
            + [S.marker(C, f"g05-{k}-{i}") for i in range(2)]
            + [S.marker(FAMILY, f"g05-{k}-0")])


def _g05_held(state: Any, root: Path, channels: list[Any]) -> tuple[list[dict], int]:
    """Every row both judge channels hold — queued, or retired into consumed — and how many
    lines of either were unreadable."""
    held: list[dict] = []
    unreadable = 0
    for ch in channels:
        rows, bad = state.rows_report(ch)
        held += rows
        unreadable += bad
        consumed = root / ch.consumed
        for line in (consumed.read_text(encoding="utf-8").splitlines()
                     if consumed.is_file() else []):
            try:
                held.append(json.loads(line))
            except ValueError:
                unreadable += 1
    return held, unreadable


def _g05_round(tmp_path: Path, name: str, state_cls: type) -> dict[str, Any]:
    """One race: `_G05_PROCESSES` forked judge processes, each grading its own episodes
    through `state=` (a `state_cls` handle over this round's root), while this process's drain
    retires and rotates both judge channels over the seed episode's rows."""
    config, drain = S.mod(S.CONFIG), S.mod(S.DRAIN)
    root = tmp_path / name
    root.mkdir()
    paths = config.LoopPaths(repo_root=tmp_path / "repo", state_dir=root)
    state = state_cls.open(paths)
    episodes_root = tmp_path / f"{name}-episodes"
    seed = S.family(tmp_path, _worlds(), episode_id=_g05_episode_id(0), root=episodes_root)
    S.grade(seed, _g05_judge(0), state=state)
    channels = [_channel(DEFENDER_Q), _channel(QUESTIONER_Q)]
    seeds = {ch.name: _ids(state.rows(ch)) for ch in channels}
    assert all(seeds.values()), f"the seed pass queued nothing: {seeds}"
    episodes = [S.family(tmp_path, _worlds(), episode_id=_g05_episode_id(k), root=episodes_root)
                for k in range(1, 1 + _G05_PROCESSES * _G05_EPISODES_EACH)]

    def grade_share(share: list[tuple[int, S.Built]]) -> None:
        mine = state_cls.open(paths)
        for k, built in share:
            S.grade(built, _g05_judge(k), state=mine)

    shares = [[(k + 1, episodes[k]) for k in range(p, len(episodes), _G05_PROCESSES)]
              for p in range(_G05_PROCESSES)]
    fork = multiprocessing.get_context("fork")
    procs = [fork.Process(target=grade_share, args=(share,)) for share in shares]
    for p in procs:
        p.start()
    retires = 0
    while any(p.is_alive() for p in procs):
        for ch in channels:
            drain.retire(state, channel=ch, batch_ids=seeds[ch.name], reason="g05 race",
                         max_attempts=10_000)
            retires += 1
    for p in procs:
        p.join()
    for ch in channels:
        drain.retire(state, channel=ch, batch_ids=seeds[ch.name], reason="g05 race",
                     max_attempts=1)
    held, unreadable = _g05_held(state, root, channels)
    marks = [m for k in range(1, 1 + len(episodes)) for m in _g05_marks(k)]
    return {"exitcodes": [p.exitcode for p in procs], "retires": retires,
            "unreadable": unreadable,
            "missing": [m for m in marks if not _carrying(held, m)],
            "twice": [m for m in marks if len(_carrying(held, m)) > 1],
            "ids_twice": [i for i, n in collections.Counter(_ids(held)).items() if n > 1],
            "episodes": episodes, "state": state, "root": root}


def test_1234_per_world_appends_while_the_drain_retires_lose_no_row(tmp_path):
    """Several judge processes append a world's defender rows and questioner rows (per world, A6) while
    the curator drain retires and rotates the same channel: after all finish, every appended finding id is present
    exactly once, in the queue or in consumed, with no duplicate and no unreadable line, and a re-run changes nothing.
    The positive control removes the per-channel append lock (as GT-2 did, which lost 224 of 480 rows) and shows rows
    lost, so the test can fail."""
    learning_state = S.sym(S.STATE, "LearningState")

    class Unlocked(learning_state):
        """The positive control's one fault (GT-2's): the per-channel append lock removed."""

        def _append_lock(self, channel: Any, timeout: Any) -> Any:  # noqa: ARG002 — the lock's own signature
            return contextlib.nullcontext()

    locked = _g05_round(tmp_path, "locked", learning_state)

    assert locked["exitcodes"] == [0] * _G05_PROCESSES, locked["exitcodes"]
    assert locked["retires"] > 0
    assert not locked["missing"], f"rows lost: {locked['missing']}"
    assert not locked["twice"], (locked["twice"], locked["ids_twice"])
    assert not locked["ids_twice"], (locked["twice"], locked["ids_twice"])
    assert locked["unreadable"] == 0
    files = sorted(p for p in (locked["root"] / "_pending").iterdir() if p.suffix == ".jsonl")
    before = _bytes_of(files)
    rerun = S.judge()
    for built in locked["episodes"]:
        S.grade(built, rerun, state=locked["state"])
    assert rerun.calls == 0, "a re-run changed a queue"
    assert _bytes_of(files) == before, "a re-run changed a queue"

    control = _g05_round(tmp_path, "unlocked", Unlocked)
    assert control["exitcodes"] == [0] * _G05_PROCESSES, control["exitcodes"]
    assert control["missing"] or control["twice"] or control["unreadable"], (
        "with the append lock removed no row was lost — this race cannot fail")


@contextlib.contextmanager
def _gate_config(tmp_path: Path, *, questioner: bool) -> Iterator[tuple[Any, Path]]:
    """The real curator config over a corpus under `tmp_path/repo` (never the checkout's):
    `(config, corpus dir)`, its trees held for the block."""
    from defender.tests._curator1134 import author_trees

    paths = S.sym(S.CONFIG, "LoopPaths")(repo_root=tmp_path / "repo",
                                         state_dir=tmp_path / "learning-state")
    (tmp_path / "repo" / "defender").mkdir(parents=True, exist_ok=True)
    trees = author_trees(paths)
    try:
        if questioner:
            corpus = Path(paths.lessons_questioner_dir)
            cfg = S.mod(S.QUESTIONER_RUN).build_questioner_config(paths, trees=trees,
                                                                  state=S.env_state())
        else:
            corpus = Path(paths.lessons_dir)
            cfg = S.mod(S.LESSONS_RUN).build_author_config(paths, trees=trees,
                                                           state=S.env_state())
        corpus.mkdir(parents=True, exist_ok=True)
        yield cfg, corpus
    finally:
        close = getattr(trees, "close", None)
        if close is not None:
            close()


def _author_lesson(corpus: Path, name: str, finding_id: str) -> None:
    """A lesson authored from `finding_id`: its provenance key carries that id."""
    from defender.tests._curator1134 import lesson_text

    (corpus / f"{name}.md").write_text(lesson_text(finding_id), encoding="utf-8")




def test_1234_questioner_dedup_and_gate_resolve_per_draw_ids_with_skipped_indexes(tmp_path):
    """The questioner appender's dedup on finding_id (dedup_key) and _gate_questioner's idempotency
    read resolve the new ids: re-appending one pass's rows adds none, two draws' design findings at the same position
    are both queued under their own ids, and a family-scope finding keeps its draw's id; the control is a re-run
    over a changed draw, which appends only the new id. On the record-less path, built the reachable way (R7 (b), human
    2026-10-12: a pre-change pass queued a questioner row at the colliding id and stopped before its judge.yaml, then a
    new-code pass runs), a new design finding whose id equals that row's is never silently lost to the dedup: it is on
    the questioner queue (under its own or a fresh id) or named on the ledger with a lane other than the questioner's
    (GT-6 showed the dedup drops it today; the mechanism is write-code-from-spec's)."""
    built = _built(tmp_path)
    replies: dict[Any, Any] = {
        (B, n): _reply(inv=[_inv(B, f"skipped-{n}", contrast=_nowhere(n))],
                       world=[_design(B, f"q-{n}")]) for n in (0, 1)}
    replies.update({(FAMILY, n): S.family_reply(world=[_family_design(f"fam-{n}")])
                    for n in (0, 1)})
    S.grade(built, S.judge(replies), draws=2)
    queue = S.questioner_queue()
    by_id = {r["finding_id"]: r for r in queue}
    for n in (0, 1):
        assert _carrying([by_id.get(built.finding_id(B, n, 1), {})], S.marker(B, f"q-{n}")), (
            f"draw {n}'s design finding is not queued under its own id: {sorted(by_id)}")
        assert _carrying([by_id.get(built.finding_id(FAMILY, n, 0), {})],
                         S.marker(FAMILY, f"fam-{n}")), sorted(by_id)

    append_world_rows = S.sym(S.JUDGE_ENQUEUE, "append_world_rows")
    text = S.queue_bytes()[1]
    assert append_world_rows(built.ep, queue, state=S.env_state()) == 0
    assert S.queue_bytes()[1] == text, "re-appending one pass's rows changed the queue"
    changed = {**by_id[built.finding_id(B, 1, 1)], "finding_id": built.finding_id(B, 2, 1)}
    assert append_world_rows(built.ep, [*queue, changed], state=S.env_state()) == 1
    assert _ids(S.questioner_queue()).count(built.finding_id(B, 2, 1)) == 1

    with _gate_config(tmp_path, questioner=True) as (cfg, corpus):
        _author_lesson(corpus, "from-draw-zero", built.finding_id(B, 0, 1))
        held, consumed, to_author = S.mod(S.QUESTIONER_RUN)._gate_questioner(queue, cfg)
    assert _ids(consumed) == [built.finding_id(B, 0, 1)], _ids(consumed)
    assert built.finding_id(B, 1, 1) in _ids(to_author)
    assert built.finding_id(FAMILY, 0, 0) in _ids(to_author)
    assert not held

    # The record-less path, the reachable way (R7 (b)): a pre-change pass queued bravo's world
    # row at the colliding id and stopped before writing judge.yaml; then a new-code pass.
    other = _built(tmp_path, episode_id=EP3)
    fid = other.finding_id(B, 0, 0)
    old = S.pre_change_world_row(fid, finding=f"{_claim(B, 'old')} — stopped early")
    S.env_state().append(_channel(QUESTIONER_Q), [old], dedup_key="finding_id")
    assert [r for r in S.questioner_queue() if r.get("finding_id") == fid] == [old], (
        "fixture: the pre-change row sits on the queue at the colliding id")
    assert not (other.ep / "judge.yaml").exists(), "fixture: the pre-change pass left no record"
    S.grade(other, S.judge({B: _reply(world=[_design(B, "new")])}))
    on_queue = _carrying(S.questioner_queue(), S.marker(B, "new"))
    lane = S.lane_of(other, fid)
    assert on_queue or (lane is not None and lane != S.LANES["questioner"]), (
        f"the dedup silently dropped the new design finding at {fid}: lane {lane!r}")
