"""Project recorded finding dispositions into the episode view."""
from __future__ import annotations






from typing import Any











from defender.learning.judge import family

from defender.learning.judge.enqueue import (
    LANE_DEFENDER,
    LANE_UNQUEUEABLE,
    LANE_WORLD,
)

from defender.learning.judge.route import (
    LANE_DROPPED_NO_PAIR,
    LANE_DROPPED_OTHER_RUN,
    LANE_DROPPED_UNRESOLVED,
)


from defender.learning.judge.run import (
    CONTRAST_EVIDENCE,
    GAP_HOW,
    GAP_WHAT,
    GAPS,
    INVESTIGATOR_FINDINGS,
    SUBJECT_DEFENDER,
    SUBJECT_WORLD,
    WORLD_FINDINGS,
)




from defender.scripts.visualize.episode_transcript import _FAMILY_LABEL as _FAMILY_LABEL, _count as _count

from defender.scripts.visualize.episode_worlds import _disposition_heading_raw as _disposition_heading_raw

from defender.scripts.visualize.episode_models import _Episode as _Episode, _Finding as _Finding, _Findings as _Findings, _items as _items




# =========================================================================================
# The findings walk — run once at load, read by the verdict tiles and the findings section
# =========================================================================================


def _coordinate_of(finding_id: Any) -> str | None:
    """`<label>/<draw>/<index>` from a `<run_id>/<label>/<draw>/<index>` finding id (how every
    record list keys a finding), else `None`."""
    if not isinstance(finding_id, str):
        return None
    parts = finding_id.rsplit("/", 3)
    if len(parts) != 4:
        return None
    _prefix, label, draw, index = parts
    return f"{label}/{draw}/{index}"




def _ledger_of(grade: Any) -> dict[str, dict[str, Any]] | None:
    """The record's `dispositions` ledger by coordinate, or `None` when it carries none."""
    if grade is None or grade.dispositions is None:
        return None
    out: dict[str, dict[str, Any]] = {}
    for entry in grade.dispositions:
        coord = _coordinate_of(entry["finding_id"])
        if coord is not None:
            out.setdefault(coord, entry)
    return out




def _bump(counts: dict[str, int], disposition: str) -> None:
    if disposition in _DROPPED_LANES:
        counts["dropped"] += 1
    elif disposition in counts:
        counts[disposition] += 1




def _finding_fields(finding: Any) -> dict[str, Any]:
    """One draw finding's fields as `_Finding` kwargs; a non-mapping finding has none. A gap's
    `what`/`how` stand where a finding's claim and root cause do; an investigator finding's
    pointers are its `contrast_evidence`."""
    if not isinstance(finding, dict):
        return {"raw": finding}
    claim = finding.get("claim") if "claim" in finding else finding.get(GAP_WHAT)
    root = finding.get("root_cause") if "root_cause" in finding else finding.get(GAP_HOW)
    evidence = finding.get(CONTRAST_EVIDENCE) if CONTRAST_EVIDENCE in finding \
        else finding.get("evidence")
    return {"claim": claim, "root_cause": root,
            "anchor": finding.get("anchor"), "topic": finding.get("topic"),
            "bucket": finding.get("bucket"), "evidence": evidence,
            "world_field": finding.get("world"), "raw": finding}




#: The subject a deployment gap addresses: the user, never a queue (A2).
SUBJECT_USER = "user"



#: A draw document's three filed lists, in A13's one index space (investigator, world, gap),
#: each with the subject its findings address.
_FILED_LISTS = ((INVESTIGATOR_FINDINGS, SUBJECT_DEFENDER), (WORLD_FINDINGS, SUBJECT_WORLD),
                (GAPS, SUBJECT_USER))




def _filed(doc: dict[str, Any]) -> list[tuple[Any, Any]]:
    """`(subject, finding)` for every finding one draw filed, indexed as the ledger's ids are:
    over the three lists in filing order, before any drop (A11, A13)."""
    return [(subject, finding) for key, subject in _FILED_LISTS for finding in _items(doc.get(key))]




#: The ledger's lane → the page's disposition word (`_disposition_heading_raw`); every other
#: lane is its own word.
_LANE_WORD = {LANE_DEFENDER: "defender", LANE_WORLD: "world_author",
              LANE_UNQUEUEABLE: "unqueueable"}


_DROPPED_LANES = frozenset({LANE_DROPPED_UNRESOLVED, LANE_DROPPED_OTHER_RUN, LANE_DROPPED_NO_PAIR})




def _off_ledger_disposition(ep: _Episode, label: str) -> tuple[str, str | None]:
    """Why the ledger does not name a finding on disk, without re-deciding a lane: the world's
    row is ungradable, no row names the world, or the pass never saw this document (a leftover
    from an earlier attempt)."""
    entry = ep.entries.get(label)
    row = entry.row if entry is not None else None
    if label != _FAMILY_LABEL and row is None:
        return "no_grade_row", None
    if row is not None and not family.is_gradable_row(row):
        reason = row.get("ungradable_reason")
        return "world_ungradable", reason if isinstance(reason, str) else None
    return "never_on_record", None




def _walk_findings(ep: _Episode) -> _Findings:  # noqa: C901, PLR0912, PLR0915
    """Every finding row the page shows, keyed `(label, draw, index)`.

    Each row's fate is read off the record's ledger (`EpisodeGrade.dispositions`), never
    re-decided here — re-deriving the lane rule drifts from the pass at the edges. The page adds
    only what the record cannot see: documents the ledger never named
    (`_off_ledger_disposition`), and ledger entries whose document is gone (stubs)."""
    out = _Findings()
    rows = out.rows
    counts = out.counts
    grade = ep.grade
    entries = ep.entries
    roster_labels = [*entries, _FAMILY_LABEL]

    def _walked(label: str) -> bool:
        """Does the page walk this label's draws? Without a grade record, every label;
        otherwise the family lane, and worlds a grade row or manifest entry names."""
        if grade is None or label == _FAMILY_LABEL:
            return True
        entry = entries.get(label)
        return entry is not None and (entry.row is not None or entry.in_manifest)

    # Dropped/failed draws come from the same labels the findings are walked from, so the
    # counts on tile 3 share one population.
    walked_labels = [label for label in roster_labels if _walked(label)]

    # Draw-read reports for every loaded label, walked or not, so the findings section's totals
    # and each world section's line count the same directories.
    for label in roster_labels:
        out.world_reports[label] = ep.draws[label][1]

    for label in walked_labels:
        docs, _report = ep.draws[label]
        for draw, doc in docs.items():
            dropped = _count(doc.get("dropped_findings"))
            if dropped is not None:
                counts["dropped"] += dropped
            if not _filed(doc) and doc.get("failure_reason"):
                out.draw_failures.append((label, draw, doc["failure_reason"]))
            elif dropped is not None:
                out.dropped.append((label, draw, dropped))

    ledger = _ledger_of(grade)

    def _dispose(label: str, coord: str) -> tuple[str, str | None, Any]:
        """The row's disposition word, reason and recorded id: the ledger's entry, else the
        record's account of why the pass never reached it."""
        if grade is None:
            return "no_grade", None, None
        if ledger is None:
            return "no_ledger", None, None
        entry = ledger.pop(coord, None)
        if entry is None:
            return (*_off_ledger_disposition(ep, label), None)
        return _LANE_WORD.get(entry["lane"], entry["lane"]), entry.get("reason"), entry["finding_id"]

    for label in walked_labels:
        docs, _report = ep.draws[label]
        for draw, doc in docs.items():
            for index, (subject, finding) in enumerate(_filed(doc)):
                coord = f"{label}/{draw}/{index}"
                disposition, reason, recorded_id = _dispose(label, coord)
                _bump(counts, disposition)
                rows.append(_Finding(
                    row_id=f"f-{label}-{draw}-{index}", label=label, draw=draw, index=index,
                    subject=subject, disposition=disposition, reason=reason, stub=False,
                    recorded_id=recorded_id, **_finding_fields(finding)))


    # A ledger entry whose draw document is gone has no text on the record (#1234: the record
    # carries lanes, not findings), so it shows only in the queue accounting.

    out.group_index = _group_numbering(rows)
    return out




def _group_numbering(rows: list[_Finding]) -> dict[str, int]:
    """Each group heading's `fg-<n>`, by first appearance — shared by the findings section and
    the cards' footers."""
    return {h: n for n, h in enumerate(dict.fromkeys(_disposition_heading_raw(f) for f in rows),
                                       start=1)}
