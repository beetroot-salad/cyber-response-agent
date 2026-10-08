from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from defender._clock import parse_iso_utc
from defender._knowledge import LESSON_CORPORA
from defender.runtime.agent_role import AgentRole



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




#: The `kind` a `lessons_loaded.jsonl` row carries: `read` when the model opened the lesson,
#: `push` when the runtime put its description and dimensions in front of MAIN without a read.
#: Defined in this lightweight leaf so the trace CLI can share it without importing the runtime.
LOAD_KIND_READ = "read"
LOAD_KIND_PUSH = "push"
LOAD_KINDS = frozenset({LOAD_KIND_READ, LOAD_KIND_PUSH})


#: What a run's record says about one lesson, strongest first: `read` (MAIN opened the body),
#: `push` (shown to MAIN without a read), `indirect` (another role read or was pushed it),
#: `unknown` (a legacy or forged row — downgraded rather than assumed a read).
EVIDENCE_READ = LOAD_KIND_READ
EVIDENCE_PUSH = LOAD_KIND_PUSH
EVIDENCE_INDIRECT = "indirect"
EVIDENCE_UNKNOWN = "unknown"
EVIDENCE_RANK = {EVIDENCE_READ: 3, EVIDENCE_PUSH: 2, EVIDENCE_INDIRECT: 1, EVIDENCE_UNKNOWN: 0}

_DT_MAX = datetime.max.replace(tzinfo=UTC)


def row_evidence(row: dict) -> str:
    """One `lessons_loaded.jsonl` row's evidence class, judged on both `kind` and `role`: any
    row from a role other than MAIN is `indirect`. `AgentRole(x)` raises `ValueError` for both
    unknown and forged unhashable roles, so both land on `unknown`."""
    kind, role = row.get("kind"), row.get("role")
    # `==`, not `in LOAD_KINDS`: a forged unhashable `kind` would raise `TypeError` in a set
    # lookup and abort the whole walk.
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
    """One lesson's exposure over one run: the strongest class any qualifying row carries, and
    the `ts` of the earliest row of that same class (so time and class describe one event)."""
    lesson_name: str
    evidence: str
    evidence_at: str | None


@dataclass(frozen=True)
class Exposures:
    """One `LessonExposure` per lesson name in first-occurrence order, plus the count of rows
    with no string `lesson_name`, so a reader never reports "no lessons" over a non-empty record."""
    lessons: list[LessonExposure]
    unnamed: int


def exposures(rows: Iterable[dict], *, since: datetime | None = None) -> Exposures:
    """Collapse the `lessons_loaded.jsonl` event log into per-lesson exposures — the one answer
    to "what was in front of the model" for both the judge and the trace CLI.

    With `since`, rows whose `ts` is missing, unparseable, or earlier are ignored (a lesson
    cannot have been in context before it existed). The earliest row of a class is picked by
    parsed instant, with unparseable timestamps last.
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
