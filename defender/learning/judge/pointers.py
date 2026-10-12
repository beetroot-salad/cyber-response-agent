"""The typed, episode-relative, no-follow evidence-pointer resolver (A1, A15, A22), and what a
finding's resolving pointers say about it.

`_resolves` is the ONE resolver: every site that decides whether a judge evidence pointer
resolves — the draw's routing, the two-run rule, gap-only, design-vs-serving, the citations a
queue row carries — calls it. It maps one pointer to exactly one run and one class, or to
nothing ("unresolved"):

* CONDUCT of run X — `worlds/<X>/report.md`, `worlds/<X>/investigation.md`,
  `worlds/<X>/gather_summaries/<lead>.md`, `worlds/<X>/executed_queries.jsonl#<row>`,
  `served/<token>.<X>.jsonl#<row>` (a row fragment is required and must index a line);
* BUILT layer of run X — `oracle/<X>/<leaf>[#frag]`;
* PLAN — `family.yaml#worlds/<X>` (names X) or `family.yaml#<key>` for a family-level key of
  the manifest (names no run);
* CONTEXT (names no run) — `samples.yaml#<section>` (world scope only, A22),
  `outcome.yaml[#<key>]`, and a run's non-conduct files `alert.json`, `provenance.json`,
  `run_end.json`, `lessons_loaded.jsonl`.

Anything else is unresolved: `judge.yaml`, `worlds/*/judge/`, `wire_logs/`, `world_records/`,
`not_comparable.yaml`, `served/base.jsonl`, a stray file under a world, an absolute path, a
traversal out of the episode or out of a world's subtree, a run outside the scope (failed, cut
short, malformed, not archived), and any file the bounded no-follow reader refuses (a link, a
hard link, a FIFO, a directory, an oversize file). Only the archived runs of this episode, its
manifest and its oracle store can be named — never a path a sandbox could have linked.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import field
from typing import Annotated, Any

from pydantic import SkipValidation

from defender._episode_paths import LAYOUT, WORLD_LEAVES
from defender._io import Bound
from defender._model import model
from defender.learning.judge.calls import (
    is_blocked_ledger_row,
    is_blocked_table_row,
    is_inherited,
    blocked_call_key,
)
from defender.learning.judge.family import WorldFacts

#: The four pointer classes (A1).
CONDUCT = "conduct"
BUILT = "built"
PLAN = "plan"
CONTEXT = "context"

#: A pointer longer than any archive path is refused before it is parsed.
_MAX_POINTER = 1024

#: A run's conduct leaves, and its non-conduct (context) leaves, relative to `worlds/<X>/`.
_CONDUCT_LEAVES = frozenset({str(WORLD_LEAVES.report), str(WORLD_LEAVES.investigation)})
_CONTEXT_LEAVES = frozenset({str(WORLD_LEAVES.alert), str(WORLD_LEAVES.provenance),
                             str(WORLD_LEAVES.run_end), str(WORLD_LEAVES.lessons_loaded)})
_TABLE_LEAF = str(WORLD_LEAVES.executed_queries)
#: The manifest fragment naming one world's entry: `worlds/<label>`.
_PLAN_WORLD_PREFIX = str(LAYOUT.worlds) + "/"


@model(frozen=True)
class PointerScope:
    """What one call's pointers may resolve into: the runs of its reference set (the focus and
    every reference run; for the family call, every usable run), the manifest, pre-flight's
    record and — world scope only — the samples record (`None` for the family call, which is
    shown none, A22). `j3` is the request keys of the inherited pre-branch denial (A12, A14)."""

    bound: Annotated[Bound, SkipValidation]
    episode_token: str
    runs: Annotated[dict[str, WorldFacts], SkipValidation]
    manifest: Annotated[dict[str, Any], SkipValidation]
    outcome: Annotated[dict[str, Any], SkipValidation] = field(default_factory=dict)
    samples: Annotated[dict[str, Any] | None, SkipValidation] = None
    j3: frozenset[str] = frozenset()


@model(frozen=True)
class Resolution:
    """One resolving pointer: its class, the run it names (`None`: names no run), and — for a
    conduct pointer at a call row — whether the row is a blocked call (A14) and whether it is an
    inherited ordinary (pre-branch, not blocked) table row (A20). `blocked_key` is the blocked
    call's key (A2)."""

    pointer: str
    kind: str
    run: str | None
    blocked: bool = False
    inherited_ordinary: bool = False
    blocked_key: tuple[str, str] | None = None
    #: The blocked row itself (its `(system, verb, params)`), for a gap entry.
    blocked_row: Annotated[dict[str, Any] | None, SkipValidation] = None


def _canonical_parts(path: str) -> list[str] | None:
    """`path` as plain components: `.` and empty segments dropped, `..` popped. `None` when a
    `..` leaves the episode, or leaves the `worlds/<X>/` subtree it had entered (a segment that
    returns into the same world is that world)."""
    out: list[str] = []
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if not out:
                return None
            in_world = len(out) >= 2 and out[0] == str(LAYOUT.worlds)
            out.pop()
            if in_world and len(out) < 2:
                return None
            continue
        out.append(part)
    return out or None


def _row_index(fragment: str | None, rows: Sequence[Any]) -> int | None:
    """A `#<row>` fragment as a 0-based line index into `rows`, or `None`."""
    if fragment is None or not fragment.isascii() or not fragment.isdigit():
        return None
    index = int(fragment)
    return index if index < len(rows) else None


def _reads_plain(bound: Bound, name: str) -> bool:
    """Does the bounded no-follow reader read `name` as a plain file?"""
    try:
        return bound.read(name, errors="replace").text is not None
    except ValueError:
        return False


def _world_pointer(scope: PointerScope, pointer: str, parts: list[str],
                   fragment: str | None) -> Resolution | None:
    """`worlds/<X>/<leaf>`: conduct or context of run X, when X is in the scope."""
    label, leaf = parts[1], "/".join(parts[2:])
    run = scope.runs.get(label)
    if run is None or not leaf:
        return None
    if leaf in _CONDUCT_LEAVES:
        name = f"{LAYOUT.world(label).dir}/{leaf}"
        return Resolution(pointer=pointer, kind=CONDUCT, run=label) \
            if _reads_plain(scope.bound, name) else None
    if len(parts) == 4 and parts[2] == str(WORLD_LEAVES.gather_summaries) \
            and parts[3].endswith(".md") and parts[3][:-len(".md")] in run.summary_leads:
        return Resolution(pointer=pointer, kind=CONDUCT, run=label)
    if leaf == _TABLE_LEAF:
        index = _row_index(fragment, run.table_rows)
        if index is None:
            return None
        row = run.table_rows[index]
        blocked = is_blocked_table_row(row, run.ledger_rows, run.token, j3=scope.j3)
        return Resolution(
            pointer=pointer, kind=CONDUCT, run=label, blocked=blocked,
            inherited_ordinary=is_inherited(row, run.token) and not blocked,
            blocked_key=blocked_call_key(label, row) if blocked else None,
            blocked_row=dict(row) if blocked else None)
    if leaf in _CONTEXT_LEAVES:
        name = f"{LAYOUT.world(label).dir}/{leaf}"
        return Resolution(pointer=pointer, kind=CONTEXT, run=None) \
            if _reads_plain(scope.bound, name) else None
    return None


def _served_pointer(scope: PointerScope, pointer: str, name: str,
                    fragment: str | None) -> Resolution | None:
    """`served/<token>.<X>.jsonl#<row>`: a ledger row of run X (conduct; blocked when it is a
    `refused`/`fault` row). `served/base.jsonl` is the family tier, never a run."""
    for label, run in scope.runs.items():
        if name != f"{run.token}.jsonl":
            continue
        index = _row_index(fragment, run.ledger_rows)
        if index is None:
            return None
        row = run.ledger_rows[index]
        blocked = is_blocked_ledger_row(row)
        return Resolution(pointer=pointer, kind=CONDUCT, run=label, blocked=blocked,
                          blocked_key=blocked_call_key(label, row) if blocked else None,
                          blocked_row=dict(row) if blocked else None)
    return None


def _plan_pointer(scope: PointerScope, pointer: str, fragment: str | None) -> Resolution | None:
    """`family.yaml#worlds/<X>` (names X) or `family.yaml#<family-level key>` (names none)."""
    if fragment is None:
        return None
    if fragment.startswith(_PLAN_WORLD_PREFIX):
        label = fragment[len(_PLAN_WORLD_PREFIX):]
        declared = {w.get("world_id") for w in scope.manifest.get("worlds") or ()
                    if isinstance(w, dict)}
        return Resolution(pointer=pointer, kind=PLAN, run=label) if label in declared else None
    if fragment != str(LAYOUT.worlds) and fragment in scope.manifest:
        return Resolution(pointer=pointer, kind=PLAN, run=None)
    return None


def _resolves(pointer: Any, scope: PointerScope) -> Resolution | None:  # noqa: C901 — one rule per pointer class, kept in the one resolver
    """The one resolver (A1): `pointer` mapped to exactly one run and one class, or `None`
    (unresolved). Never raises for any pointer a model could write.

    The one resolver: every judge site deciding whether an evidence pointer resolves
    (routing, the two-run rule, gap-only, design, a row's citations) calls this."""
    if not isinstance(pointer, str) or not pointer.strip() or len(pointer) > _MAX_POINTER \
            or any(ch in pointer for ch in "\x00\n\r*?~") or "://" in pointer:
        return None
    path, has_fragment, frag = pointer.partition("#")
    fragment = frag if has_fragment else None
    if path.startswith("/"):
        return None
    parts = _canonical_parts(path)
    if parts is None:
        return None
    head = parts[0]
    if head == str(LAYOUT.worlds) and len(parts) >= 3:
        return _world_pointer(scope, pointer, parts, fragment)
    if head == str(LAYOUT.served) and len(parts) == 2:
        return _served_pointer(scope, pointer, parts[1], fragment)
    if len(parts) >= 3 and parts[1] in scope.runs \
            and "/".join(parts[:2]) == str(LAYOUT.oracle_dir(parts[1])):
        name = "/".join(parts)
        return Resolution(pointer=pointer, kind=BUILT, run=parts[1]) \
            if _reads_plain(scope.bound, name) else None
    if len(parts) != 1:
        return None
    if head == str(LAYOUT.family):
        return _plan_pointer(scope, pointer, fragment)
    if head == str(LAYOUT.samples):
        samples = scope.samples
        if samples is None or fragment is None or not isinstance(samples.get(fragment), dict):
            return None
        return Resolution(pointer=pointer, kind=CONTEXT, run=None)
    if head == str(LAYOUT.outcome):
        if fragment is not None and fragment not in scope.outcome:
            return None
        return Resolution(pointer=pointer, kind=CONTEXT, run=None)
    return None


@model(frozen=True)
class Assessment:
    """What one filed finding's pointers say once resolved: the resolving ones in filed order,
    and the derived facts every routing rule reads (A1, A13, A15). Computed by `assess` and
    nowhere else."""

    filed: list[Any]
    resolving: list[Resolution]

    @property
    def runs_named(self) -> set[str]:
        """The runs the resolving pointers name (conduct, built, plan at a world's entry)."""
        return {r.run for r in self.resolving if r.run is not None}

    @property
    def conduct(self) -> list[Resolution]:
        return [r for r in self.resolving if r.kind == CONDUCT]

    @property
    def gap_only(self) -> bool:
        """A15: at least one resolving conduct pointer, and every one a blocked-call row
        (context — and the plan and built layers — set aside)."""
        conduct = self.conduct
        return bool(conduct) and all(r.blocked for r in conduct)

    @property
    def has_plan(self) -> bool:
        return any(r.kind == PLAN for r in self.resolving)

    @property
    def blocked_keys(self) -> list[tuple[str, str]]:
        """The blocked calls the resolving conduct pointers name, in filed order, once each."""
        out: list[tuple[str, str]] = []
        for r in self.conduct:
            if r.blocked_key is not None and r.blocked_key not in out:
                out.append(r.blocked_key)
        return out

    def names_only_another_run(self, focus: str) -> bool:
        """A15: at least one run-naming resolving pointer, and every one names a run other than
        `focus`."""
        named = self.runs_named
        return bool(named) and focus not in named

    def has_two_run_pair(self, focus: str) -> bool:
        """A1: a conduct pointer in the focus run and one in another run of the scope, not both
        inherited ordinary rows (A20: two copies of the shared baseline are no divergence)."""
        conduct = self.conduct
        return any(a.run == focus and b.run != focus
                   and not (a.inherited_ordinary and b.inherited_ordinary)
                   for a in conduct for b in conduct)

    @property
    def contrast(self) -> list[str]:
        """The resolving conduct pointers — the two-run contrast's halves, the focus run's and
        the reference runs' — in filed order: a defender row's `contrast_evidence`."""
        return [r.pointer for r in self.conduct]

    @property
    def citations(self) -> list[str]:
        """The resolving pointers, in filed order: a queue row's `citations` (A1)."""
        return [r.pointer for r in self.resolving]


def assess(pointers: Iterable[Any], scope: PointerScope) -> Assessment:
    """Resolve every filed pointer of one finding through `_resolves`."""
    filed = list(pointers)
    resolving = [r for p in filed if (r := _resolves(p, scope)) is not None]
    return Assessment(filed=filed, resolving=resolving)


def named_rows(assessment: Assessment) -> Mapping[tuple[str, str], dict[str, Any]]:
    """Each blocked call an assessment names, by key, with the row that names it."""
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for r in assessment.conduct:
        if r.blocked_key is not None and r.blocked_row is not None:
            out.setdefault(r.blocked_key, r.blocked_row)
    return out


__all__ = [
    "BUILT", "CONDUCT", "CONTEXT", "PLAN", "Assessment", "PointerScope", "Resolution", "assess",
    "named_rows",
]
