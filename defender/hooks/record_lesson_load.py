from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from defender._clock import parse_iso_utc
from defender.runtime.agent_role import AgentRole

#: Every corpus the AUTHOR side may touch.
#:
#: KEPT AS TWO NAMES rather than collapsed to one. They answer different questions — what a
#: curator may read and write, versus what the runtime agent loads at PLAN — and a single
#: constant would make the next author-only corpus silently readable by the runtime.
#: #1007 M7 adds `lessons-questioner` here, on the AUTHOR side alone — the questioner curator's
#: own read/write confine. `RUNTIME_LESSON_CORPORA` stays `{"lessons"}`: a world finding is
#: never a lesson the defender agent itself may read at PLAN time.
LESSON_CORPORA = frozenset({"lessons", "lessons-questioner"})

RUNTIME_LESSON_CORPORA = frozenset({"lessons"})


def lesson_name(file_path: str, corpora: frozenset[str] = LESSON_CORPORA) -> str | None:
    p = Path(file_path)
    if (
        p.suffix == ".md"
        and not p.name.startswith("_")
        and p.parent.name in corpora
        and p.parent.parent.name == "defender"
    ):
        return p.stem
    return None




#: The `kind` a `lessons_loaded.jsonl` row carries (#936): `read` when the MODEL chose to open
#: the lesson (`runtime/tools._gated_read`), `push` when the RUNTIME put its description and
#: dimensions in front of MAIN without a read (`_frontier_recall`'s write return, and the
#: compaction fold's frontier row). The two mean different things about whether the lesson
#: was actually in front of the model, and `learning/ops/trace_lesson.py` renders them as
#: different evidence classes. HERE, beside `lesson_name` and the record's one reader
#: (`exposures`, below), because this leaf is the one the writer (`runtime/tools/_deps.py`)
#: and the readers already share, and it imports nothing heavier than `pathlib`, the clock and
#: the role enum — the trace CLI must not pay for the runtime to agree on a spelling.
LOAD_KIND_READ = "read"
LOAD_KIND_PUSH = "push"
LOAD_KINDS = frozenset({LOAD_KIND_READ, LOAD_KIND_PUSH})


#: What a run's record says about one lesson, strongest first: `read` (MAIN opened the body),
#: `push` (the runtime put its description and dimensions in front of MAIN), `indirect`
#: (another role — a GATHER agent, a curator — read or was pushed it; nothing reached MAIN),
#: `unknown` (a row that cannot say: from before #936, or bytes a forger put there — an honest
#: downgrade of history rather than an assumed read). The first two ARE the writer's `kind`
#: values, aliased so a column and a match cannot drift apart.
EVIDENCE_READ = LOAD_KIND_READ
EVIDENCE_PUSH = LOAD_KIND_PUSH
EVIDENCE_INDIRECT = "indirect"
EVIDENCE_UNKNOWN = "unknown"
EVIDENCE_RANK = {EVIDENCE_READ: 3, EVIDENCE_PUSH: 2, EVIDENCE_INDIRECT: 1, EVIDENCE_UNKNOWN: 0}

_DT_MAX = datetime.max.replace(tzinfo=UTC)


def row_evidence(row: dict) -> str:
    """One row's class, from the closed vocabulary and nothing else — the ONE classifier every
    reader of `lessons_loaded.jsonl` uses (`exposures` below; #785's rule: one parser, not
    several interpreters that drift). `kind` and `role` are both judged: a push says nothing
    about MAIN unless MAIN is the role it was pushed to, and a read by another role is
    `indirect` whichever kind it is. Membership is answered by `AgentRole` itself, not a local
    copy of its values — `AgentRole(x)` raises `ValueError` for a string outside the vocabulary
    AND for a forged unhashable value, so the case that would cost a whole walk under a set
    lookup is the same branch."""
    kind, role = row.get("kind"), row.get("role")
    # `==` against each spelling, not `in LOAD_KINDS`: a forged unhashable `kind` (a list)
    # raises `TypeError` under a set lookup and costs the whole walk, not just this row.
    if kind != LOAD_KIND_READ and kind != LOAD_KIND_PUSH:  # noqa: PLR1714 — see above
        return EVIDENCE_UNKNOWN
    try:
        reader = AgentRole(role)
    except ValueError:
        return EVIDENCE_UNKNOWN
    if reader is not AgentRole.MAIN:
        return EVIDENCE_INDIRECT
    return EVIDENCE_READ if kind == LOAD_KIND_READ else EVIDENCE_PUSH


@dataclass(frozen=True)
class LessonExposure:
    """One lesson's exposure over one run's rows: the strongest class any qualifying row
    carries, and the `ts` of the EARLIEST row of that class — the two describe the same event,
    so "at `evidence_at`, `evidence`" is one statement (a time from one row and a class from
    another read as "MAIN read it at 10:00" when the read came at 11:00)."""
    lesson_name: str
    evidence: str
    evidence_at: str | None


@dataclass(frozen=True)
class Exposures:
    """The record READ AS A SET: one `LessonExposure` per lesson name in first-occurrence
    order, plus the count of rows that named no lesson — a `lesson_name` that is not a string
    cannot name one, and a reader that dropped such rows silently would state "no lessons"
    as fact over a record that holds rows."""
    lessons: list[LessonExposure]
    unnamed: int


def exposures(rows: Iterable[dict], *, since: datetime | None = None) -> Exposures:
    """`lessons_loaded.jsonl` read as a set, from rows read as an EVENT log (a row per time a
    lesson reached an agent; the compaction fold alone writes one per matching lesson per
    boundary). Every reader that wants "what was in front of the model" asks this, so the
    judge's view and the trace CLI cannot disagree about it.

    `since` is the qualifying window: with one, a row whose `ts` is missing, unparseable or
    earlier is not counted at all (a lesson cannot have been in context before it existed —
    `trace_lesson` passes the lesson's `created_at`). The earliest row of a class is picked by
    parsed instant, not string order, with unparseable timestamps last among ties.
    """
    by_name: dict[str, list[tuple[str, datetime | None, str | None]]] = {}
    unnamed = 0
    for row in rows:
        name = row.get("lesson_name")
        if not isinstance(name, str):
            unnamed += 1
            continue
        ts = parse_iso_utc(row.get("ts"))
        if since is not None and (ts is None or ts < since):
            continue
        raw_ts = row.get("ts")
        by_name.setdefault(name, []).append(
            (row_evidence(row), ts, raw_ts if isinstance(raw_ts, str) else None))
    out: list[LessonExposure] = []
    for name, seen in by_name.items():
        strongest = max((e for e, _t, _r in seen), key=EVIDENCE_RANK.__getitem__)
        of_class = [(t, r) for e, t, r in seen if e == strongest]
        _t, at = min(of_class, key=lambda q: (q[0] is None, q[0] or _DT_MAX, q[1] or ""))
        out.append(LessonExposure(name, strongest, at))
    return Exposures(out, unnamed)
