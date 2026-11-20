"""The derived reader of where an episode's worlds differ (`delta_o`). What each world
concluded is its arm's closing record (#1534), read through the episode view
(`records.closing.for_world`); no archived file carries it."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any


from defender._io import Bound
from defender.records.formats import LAYOUT
from defender.learning.branch import outcome as outcome_mod
from defender.learning.branch.comparator import DELTA_SEAT, Verdict, canonical, compare
from defender.learning.branch.ledger import (
    LedgerError,
    correlation_key_of,
)
from defender.records import EpisodeRuns
from defender.records.formats import BASE_ROLE, family_identities, Family, FamilyError, load_family

#: What a difference is called when nothing attributed it: "differs, and not shown to be the
#: declared axis". Reporting `mutation` would claim a measurement nobody made. Borrowed from the
#: comparator's delta-seat vocabulary rather than re-spelled.
UNATTRIBUTED = Verdict.UNDECLARED.value

Invoke = Callable[..., Any]


class EpisodeError(ValueError):
    """An episode these readers cannot answer over honestly.

    Raised for an outcome other than `accepted` (or no outcome record), an accepted family with
    no readable family stamp, an archived disposition
    outside the shipped
    vocabulary, or an archived world the manifest does not declare. A `ValueError` so callers
    can catch this design's refusals at one boundary.
    """


# ---------------------------------------------------------------------------------------
# the episode's own state
# ---------------------------------------------------------------------------------------


def _recorded_outcome(bound: Bound, family: Family) -> tuple[str, str]:
    """The episode's outcome word and its reason, from pre-flight's outcome record
    (`outcome.yaml`). An absent, torn or refused record is the "no record" state, refused
    rather than read as any word (M05=A). An `accepted` record whose O5 count
    (`outcome.failed_worlds`) reaches two reads as `unusable`, as the judge's gate reads it."""
    try:
        record = outcome_mod.read_outcome(bound)
    except outcome_mod.OutcomeUnreadable as missing:
        raise EpisodeError(
            f"the episode has no outcome record to read ({missing}) — an episode is comparable "
            "only once pre-flight recorded it accepted") from None
    unusable = outcome_mod.unusable_reason(outcome_mod.failed_worlds(bound, record, family=family))
    if record["outcome"] == outcome_mod.ACCEPTED and unusable is not None:
        return outcome_mod.UNUSABLE, unusable
    return record["outcome"], record["reason"]


def _refuse_incomplete(bound: Bound, family: Family) -> None:
    """Refuse an episode whose outcome record is not exactly `accepted`, naming the word and
    its reason, or the missing record — and an accepted one with no readable family stamp."""
    word, reason = _recorded_outcome(bound, family)
    if word != outcome_mod.ACCEPTED:
        raise EpisodeError(
            f"the episode's outcome is {word!r}{f' ({reason})' if reason else ''} — only an "
            "accepted family's worlds are compared; an answer over these would read as a "
            "measurement nobody made")
    not_comparable = outcome_mod.not_comparable_reason(bound)
    if not_comparable is not None:
        raise EpisodeError(
            f"the episode is {outcome_mod.NOT_COMPARABLE} ({not_comparable}) — an answer over "
            "its worlds would read as a measurement nobody made")


def _archived_labels(bound: Bound, family: Family) -> list[str]:
    """Archived UUID directories resolved through the host-written manifest."""
    try:
        return sorted(family.world_by_id(world_id).label
                      for world_id in bound.under(LAYOUT.worlds).entries().dirs())
    except FamilyError as refused:
        raise EpisodeError(str(refused)) from refused


def _walked(view: EpisodeRuns) -> Bound:
    """The no-follow reader over the episode folder `view` holds — the walked handle, never a
    path re-bound by its spelling. Anything but an episode view is a `TypeError`."""
    if not isinstance(view, EpisodeRuns):
        raise TypeError(f"the episode readers take the episode's walked view "
                        f"(`runs.episode(episode_id)`), not {type(view).__name__}")
    return view.episode.view()


# ---------------------------------------------------------------------------------------
# delta_o
# ---------------------------------------------------------------------------------------


def _pair_key(row: dict) -> str | None:
    """The key a row pairs on: the call as it was asked (`ledger.correlation_key_of`).

    A staged world's `params` name its own corpus, so pairing on them would intersect the
    base's keys in the empty set and silently report no difference on the event stream.
    """
    return correlation_key_of(row)


def _canonical(row: dict) -> str | None:
    """One row's answer in canonical spelling (`comparator.canonical`).

    Stored text cannot be compared byte-for-byte: the source run's captured sidecars were
    written without `sort_keys`, so every primed row would differ in a field no world touched.
    Non-JSON text (a torn row, an error digest) is compared as-is, so two worlds recording the
    same unparseable answer still agree.
    """
    text = row.get("payload_text")
    if not isinstance(text, str) or not text:
        return None
    return canonical(text)


def _answers(rows: list[dict]) -> dict[str, str]:
    """One ledger file's rows as `{pair key: canonical answer}`, first row winning (as the
    ledger's own memo does).
    """
    out: dict[str, str] = {}
    for row in rows:
        key, answer = _pair_key(row), _canonical(row)
        if key is None or answer is None:
            continue
        out.setdefault(key, answer)
    return out


def _classify(base: dict[str, str], world: dict[str, str], keys: list[str], axis: str | None,
              invoke: Invoke | None, known_ids: frozenset[str]) -> dict[str, str]:
    """One world's shared keys, each classified against the base's answer.

    Equal canonical text is `same` with no model call. Only a real difference reaches the
    comparator, with the world's own declared axis (the delta seat), asking "is this the
    difference the world said it was making".

    With no model seam (`invoke=None`) a difference is `undeclared`, keeping the reader
    deterministic and offline.
    """
    out: dict[str, str] = {}
    for key in keys:
        if base[key] == world[key]:
            out[key] = Verdict.SAME.value
            continue
        # No axis is answered like no model seam. `axis: null` is legal on a non-base world,
        # and `compare(..., None, ...)` would select the review seat, whose `contradiction`
        # the delta seat does not admit.
        if invoke is None or axis is None:
            out[key] = UNATTRIBUTED
            continue
        # `.value`: callers write this table to YAML and compare bare words, and
        # `str(Verdict.SAME)` renders `'Verdict.SAME'`. Membership is checked against the
        # comparator's own `DELTA_SEAT`.
        verdict = compare(base[key], world[key], axis, known_ids=known_ids, invoke=invoke)
        out[key] = verdict.value if verdict in DELTA_SEAT else _wrong_seat(key, verdict)
    return out


def _wrong_seat(key: str, verdict: Verdict) -> str:
    """Refuse a verdict outside the delta seat.

    Unreachable while `compare` enforces seats, but one `Verdict` type spans both seats, so the
    caller must refuse rather than map it onto an admitted member.
    """
    raise EpisodeError(
        f"the comparator answered {verdict.value!r} for correlation key {key!r} with an axis "
        f"given — that belongs to the other seat, and this one admits "
        f"{sorted(v.value for v in DELTA_SEAT)}")


def delta_o(view: EpisodeRuns, *, invoke: Invoke | None = None) -> dict[str, dict[str, str]]:
    """Per world, per shared correlation key: one member of the comparator's delta seat."""
    return _delta_o(_walked(view), view, invoke)


def _delta_o(bound: Bound, view: EpisodeRuns,
             invoke: Invoke | None) -> dict[str, dict[str, str]]:
    family = load_family(bound, expected_episode_id=view.episode_id)
    _refuse_incomplete(bound, family)
    labels = _archived_labels(bound, family)
    if not labels:
        return {}
    # No roster: the episode never reached RUNS, so it has no arm ids to keep out of a prompt
    # (the design's S-red: the question does not arise). A roster that is there but refused
    # raises its own refusal here.
    arm_ids = view.arm_ids() or {}
    control = next((w.label for w in family.worlds if w.role == BASE_ROLE), None)

    base_rows, _malformed, base_rec = bound.read_jsonl(LAYOUT.served_base)
    if base_rec.text is None:
        # The ordering guarantee: a world only serves once the base is primed, so a family
        # with archived worlds and no base read the live estate for every key.
        raise LedgerError(
            f"no primed base at {LAYOUT.served_base} "
            f"({'absent' if base_rec.absent else base_rec.reason}) — the family's capture is "
            "written once, before any sibling forks, and a world serving without it reads the "
            "live estate for every key while every row it writes still reads correctly")
    base = _answers(base_rows)
    served: dict[str, dict[str, str]] = {}
    for label in labels:
        if label not in {w.label for w in family.worlds}:
            raise EpisodeError(
                f"the archive holds a world {label!r} the manifest does not declare "
                f"({[w.label for w in family.worlds]}) — its axis is what a difference is "
                "classified against, so there is nothing to classify it with")
        name = LAYOUT.served_world(family.world(label).world_id)
        rows, _malformed, rec = bound.read_jsonl(name)
        if rec.text is None and not rec.absent:
            # Absent is a world that served nothing; refused is not, and reading it as nothing
            # would report every key as unshared.
            raise EpisodeError(
                f"world {label!r}'s served file ({name}) is refused ({rec.reason}) — what it "
                "served cannot be read, so its answers cannot be compared")
        served[label] = _answers(rows)

    drift = set()
    if control is not None:
        drift = {key for key, answer in served.get(control, {}).items()
                 if key in base and base[key] != answer}

    # The family's identities, removed from every prompt the comparator sends.
    known_ids = family_identities(family, arm_ids)
    out: dict[str, dict[str, str]] = {}
    for label in labels:
        world = served[label]
        shared = sorted(set(base) & set(world) - drift)
        out[label] = _classify(base, world, shared, family.world(label).axis, invoke, known_ids)
    return out


__all__ = [
    "EpisodeError",
    "delta_o",
]
