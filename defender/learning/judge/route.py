"""Routing (design M5 as amended: A1, A7, A13, A15, A16): what becomes of every finding a draw
filed, computed from its typed pointers and its own world's draws — never from a word another
world or the family call said (P-c, I2).

Two decisions, each made here and nowhere else:

* `combine_draws` — a world's completed draws combine by UNANIMITY (A7) into its verdict: the
  outcome (not measured, `none`, or an investigator bucket) and the systems count only when
  every draw agrees; otherwise the world is withheld (`draws_disagree`). The doubt mark is set
  when ANY draw keeps a `mislabelled` finding; a named gap is listed when EVERY draw names the
  same blocked call (A2's key). The family's draws combine by union.
* `fate` — every filed finding's one ledger lane (A13): a drop reason (precedence: pointers
  unresolved, names only another run, no two-run pair), the O16 sample-citation drop, or a
  routing fate (defender, questioner, user record, or one of the world-gate lanes).

The index of a finding runs over the three filed lists in filing order, before any drop
(`filed_findings`), so `finding_id = <episode>/<world>/<draw>/<index>` keeps its form and kept
ids may skip numbers.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import field
from typing import Annotated, Any

from pydantic import SkipValidation

from defender._episode_paths import LAYOUT
from defender._model import model
from defender.learning.judge.pointers import Assessment, PointerScope, assess, named_rows
from defender.learning.judge.run import (
    CONTRAST_EVIDENCE,
    EVIDENCE,
    FILED_LISTS,
    GAPS,
    INVESTIGATOR_FINDINGS,
    KEPT_FACTS,
    MISLABELLED,
    NOT_MEASURED_BUCKETS,
    NO_BUCKET,
    WORLD_FINDINGS,
    cites_sample,
)

# -- the ledger's lanes (A13): one per filed finding ------------------------------------------

#: Routing fates.
LANE_DEFENDER = "defender"
LANE_QUESTIONER = "world"
LANE_USER_RECORD = "user_record"
#: The world gate's fates for an investigator finding (A7, I4, I9).
LANE_NOT_MEASURED = "not_measured"
LANE_UNAUTHORED = "unauthored"
LANE_DRAWS_DISAGREE = "draws_disagree"
#: A named gap's fates when it is not listed (A7, R1).
LANE_GAP_NOT_UNANIMOUS = "gap_not_unanimous"
LANE_GAP_UNKEYED = "gap_no_blocked_call"
#: The drop reasons, in precedence order (A13).
LANE_DROPPED_UNRESOLVED = "dropped_unresolved"
LANE_DROPPED_OTHER_RUN = "dropped_other_run"
LANE_DROPPED_NO_PAIR = "dropped_no_pair"
#: A finding that resolved but no row could be made of (the O16 sample citation; a row its
#: channel's appender rule refuses). `reason` names why.
LANE_UNQUEUEABLE = "unqueueable"

LEDGER_LANES = frozenset({
    LANE_DEFENDER, LANE_QUESTIONER, LANE_USER_RECORD, LANE_NOT_MEASURED, LANE_UNAUTHORED,
    LANE_DRAWS_DISAGREE, LANE_GAP_NOT_UNANIMOUS, LANE_GAP_UNKEYED, LANE_DROPPED_UNRESOLVED,
    LANE_DROPPED_OTHER_RUN, LANE_DROPPED_NO_PAIR, LANE_UNQUEUEABLE})

#: The kinds of filed finding, one per filed list.
KIND_INVESTIGATOR, KIND_WORLD, KIND_GAP = "investigator", "world", "gap"
_KIND_OF = {INVESTIGATOR_FINDINGS: KIND_INVESTIGATOR, WORLD_FINDINGS: KIND_WORLD,
            GAPS: KIND_GAP}
_POINTERS_OF = {KIND_INVESTIGATOR: CONTRAST_EVIDENCE, KIND_WORLD: EVIDENCE, KIND_GAP: EVIDENCE}


def filed_findings(draw_doc: dict[str, Any]) -> Iterator[tuple[int, str, dict[str, Any]]]:
    """`(index, kind, finding)` for every finding a draw filed: one index space over the three
    lists in filing order, counted before any drop (A13).

    The one numbering of the `<index>` of every `finding_id`."""
    index = 0
    for key in FILED_LISTS:
        for finding in draw_doc.get(key) or ():
            yield index, _KIND_OF[key], finding
            index += 1


@model(frozen=True)
class Filed:
    """One filed finding of one draw, its pointers resolved (`assess`)."""

    draw: int
    index: int
    kind: str
    finding: Annotated[dict[str, Any], SkipValidation]
    assessment: Assessment

    def dropped(self, focus: str | None) -> str | None:
        """The drop lane, or `None` when the finding is kept (A13's precedence): no filed
        pointer resolves; it names only another run (world scope, A15); an investigator
        finding with no two-run conduct pair (A1, A20)."""
        if not self.assessment.resolving:
            return LANE_DROPPED_UNRESOLVED
        if focus is None:
            return None
        if self.assessment.names_only_another_run(focus):
            return LANE_DROPPED_OTHER_RUN
        if self.kind == KIND_INVESTIGATOR and not self.assessment.has_two_run_pair(focus):
            return LANE_DROPPED_NO_PAIR
        return None


def assess_draw(draw: int, draw_doc: dict[str, Any], scope: PointerScope) -> list[Filed]:
    """Every finding one draw filed, with its pointers resolved through the one resolver."""
    return [Filed(draw=draw, index=index, kind=kind, finding=finding,
                  assessment=assess(finding.get(_POINTERS_OF[kind]) or (), scope))
            for index, kind, finding in filed_findings(draw_doc)]


@model(frozen=True)
class DrawVerdict:
    """What one completed draw says about its world, off its KEPT findings only (a dropped
    finding is not a finding): its outcome (`not measured`, or its bucket), the systems set,
    whether it keeps a `mislabelled` finding, and the blocked calls its kept gaps name."""

    bucket: str | None
    systems: tuple[str, ...]
    not_measured_reason: str | None
    doubted: bool
    named_keys: frozenset[tuple[str, str]]

    @property
    def outcome(self) -> str | None:
        return "not measured" if self.not_measured_reason is not None else self.bucket


def draw_verdict(draw_doc: dict[str, Any], filed: list[Filed], *, focus: str) -> DrawVerdict:
    """One draw's verdict (A7, A16): not measured when it keeps an `unreachable`/`incoherent`
    world finding or a resolving gap flagged `kept_facts_from_investigator`; the reason names
    which."""
    reasons: list[str] = []
    doubted = False
    keys: set[tuple[str, str]] = set()
    for item in filed:
        if item.dropped(focus) is not None:
            continue
        bucket = item.finding.get("bucket")
        if item.kind == KIND_WORLD and bucket in NOT_MEASURED_BUCKETS:
            reasons.append(f"a draw files {bucket}: {item.finding.get('claim')}")
        if item.kind == KIND_WORLD and bucket == MISLABELLED:
            doubted = True
        if item.kind == KIND_GAP:
            keys.update(item.assessment.blocked_keys)
            if item.finding.get(KEPT_FACTS) is True:
                reasons.append(f"a deployment gap kept the facts from the investigator: "
                               f"{item.finding.get('what')}")
    systems = draw_doc.get("systems")
    return DrawVerdict(
        bucket=draw_doc.get("bucket"),
        systems=tuple(sorted(systems)) if isinstance(systems, list) else (),
        not_measured_reason="; ".join(reasons) if reasons else None, doubted=doubted,
        named_keys=frozenset(keys))


@model(frozen=True)
class WorldVerdict:
    """A world's combined verdict over its completed draws (A7). `disagree` is the withheld
    world: outcome or systems differ across draws, so neither counts and no defender row
    queues. `listed_keys` are the named gaps every draw names."""

    completed: int
    bucket: str | None
    systems: list[str] | None
    measured: bool | None
    not_measured_reason: str | None
    disagree: bool
    doubted: bool
    listed_keys: frozenset[tuple[str, str]] = frozenset()
    draws: Annotated[list[dict[str, Any]], SkipValidation] = field(default_factory=list)


def combine_draws(verdicts: dict[int, DrawVerdict]) -> WorldVerdict:
    """The unanimity rule (A7) over a world's completed draws, by draw index.

    @owns measured — a world row's `measured`/`not_measured_reason`/`draws_disagree`/
    `world_label_doubted` and its row-level `bucket`/`systems` are decided here and nowhere
    else."""
    ordered = [verdicts[n] for n in sorted(verdicts)]
    draws = [{"draw": n, "bucket": verdicts[n].bucket, "systems": list(verdicts[n].systems)}
             for n in sorted(verdicts)]
    doubted = any(v.doubted for v in ordered)
    if not ordered:
        return WorldVerdict(completed=0, bucket=None, systems=None, measured=False,
                            not_measured_reason="no draw completed", disagree=False,
                            doubted=False, draws=draws)
    outcomes = {v.outcome for v in ordered}
    systems = {v.systems for v in ordered}
    buckets = {v.bucket for v in ordered}
    listed = frozenset.intersection(*(v.named_keys for v in ordered))
    bucket = next(iter(buckets)) if len(buckets) == 1 else None
    if len(outcomes) > 1 or len(systems) > 1:
        return WorldVerdict(completed=len(ordered), bucket=bucket,
                            systems=list(next(iter(systems))) if len(systems) == 1 else None,
                            measured=None, not_measured_reason=None, disagree=True,
                            doubted=doubted, listed_keys=listed, draws=draws)
    reason = ordered[0].not_measured_reason
    return WorldVerdict(completed=len(ordered), bucket=bucket, systems=list(next(iter(systems))),
                        measured=reason is None, not_measured_reason=reason, disagree=False,
                        doubted=doubted, listed_keys=listed, draws=draws)


def defender_lane_blocked(verdict: WorldVerdict) -> str | None:
    """The world gate on an investigator finding (A7, I4, I9): the lane that keeps it off the
    defender queue — the world withheld, not measured, or bucketed with no investigator failure
    — or `None` when it passes. Reads the world's own combined draws and nothing else."""
    if verdict.disagree:
        return LANE_DRAWS_DISAGREE
    if not verdict.measured:
        return LANE_NOT_MEASURED
    if verdict.bucket == NO_BUCKET:
        return LANE_UNAUTHORED
    return None


def fate(item: Filed, *, focus: str | None, verdict: WorldVerdict | None, samples: Any,
         served_systems: list[str]) -> tuple[str, str | None]:
    """The one ledger lane of one filed finding, and its reason where the lane is a refusal.

    @owns lane — every ledger entry's `lane` is decided here; readers show the ledger rather
    than re-deciding it. `focus=None`/`verdict=None` is the family call's finding."""
    dropped = item.dropped(focus)
    if dropped is not None:
        return dropped, None
    a = item.assessment
    if item.kind == KIND_GAP:
        assert verdict is not None
        keys = a.blocked_keys
        if keys:
            if any(k in verdict.listed_keys for k in keys):
                return LANE_USER_RECORD, None
            return LANE_GAP_NOT_UNANIMOUS, "not every completed draw names this blocked call"
        if item.finding.get(KEPT_FACTS) is True:
            return LANE_USER_RECORD, None
        return LANE_GAP_UNKEYED, "its resolving pointers name no blocked call"
    if item.kind == KIND_WORLD and focus is not None and cites_sample(
            list(a.filed), samples=samples, served_systems=served_systems):
        return LANE_UNQUEUEABLE, (
            f"cites `{LAYOUT.samples}` somewhere other than a served system's own section of real "
            "answers (O16: samples are shown only for served systems)")
    if a.gap_only:
        return LANE_USER_RECORD, None
    if item.kind == KIND_WORLD:
        return (LANE_QUESTIONER, None) if a.has_plan else (LANE_USER_RECORD, None)
    assert verdict is not None
    blocked = defender_lane_blocked(verdict)
    return (blocked, None) if blocked is not None else (LANE_DEFENDER, None)


def gap_entries(filed: list[Filed], verdict: WorldVerdict, *, world: str,
                ) -> list[dict[str, Any]]:
    """The named gaps a world's draws list (A7: every draw names the same blocked call), once
    each: the blocked call's run and `(system, verb, params)`, and what was blocked, how and
    the evidence pointers as the first kept gap naming it (lowest draw, then filing order)
    states them."""
    from defender.learning.judge.calls import key_fields

    rows: dict[tuple[str, str], tuple[dict[str, Any], Filed]] = {}
    for item in sorted(filed, key=lambda f: (f.draw, f.index)):
        if item.kind == KIND_GAP and item.dropped(world) is None:
            for key, row in named_rows(item.assessment).items():
                rows.setdefault(key, (row, item))
    out = []
    for key in sorted(verdict.listed_keys):
        if key not in rows:
            continue
        row, item = rows[key]
        out.append({"run": key[0], **key_fields(row), "world": world,
                    "what": item.finding.get("what"), "how": item.finding.get("how"),
                    "evidence": list(item.assessment.filed)})
    return out


__all__ = [
    "DrawVerdict", "Filed", "KIND_GAP", "KIND_INVESTIGATOR", "KIND_WORLD", "LANE_DEFENDER",
    "LANE_DRAWS_DISAGREE", "LANE_DROPPED_NO_PAIR", "LANE_DROPPED_OTHER_RUN",
    "LANE_DROPPED_UNRESOLVED", "LANE_GAP_NOT_UNANIMOUS", "LANE_GAP_UNKEYED", "LANE_NOT_MEASURED",
    "LANE_QUESTIONER", "LANE_UNAUTHORED", "LANE_UNQUEUEABLE", "LANE_USER_RECORD", "LEDGER_LANES",
    "WorldVerdict", "assess_draw", "combine_draws", "defender_lane_blocked", "draw_verdict",
    "fate", "filed_findings", "gap_entries",
]
