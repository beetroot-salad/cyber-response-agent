"""The two derived readers: what each world concluded, and where the worlds differ.

`verdicts` answers "what disposition did each sibling reach"; `delta_o` answers "on which shared
questions did a world's observation differ, and was it the difference that world declared".
Both are derived on read; nothing is stored.

Both read the episode directory and nothing else. Sibling run dirs are disposable and may be
gone by grading time, so `verdicts` reads the archived report, `delta_o` pairs the archived
`served/` ledgers, and the archived `run_dir` pointer is informational only — never opened or
followed.

Both refuse an episode whose recorded outcome is `incomplete`. The launcher records that (with a
reason) when a sibling's scrub or stamp could not be verified, and withholds the family stamp.
The archived worlds are individually readable but not comparable, since nothing guarantees they
ran against one tree; refusing keeps "no differences" distinct from "no comparison possible".

An episode with no archived worlds answers empty rather than refusing: one rejected before
`Step.RUNS` (`branch/steps.py`) never ran a sibling, and `{}` is the honest answer. That is safe
only because the recorded outcome distinguishes it from "the worlds ran and agreed".
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml

from defender import _yaml
from defender._frontmatter import parse_frontmatter_or_none
from defender._io import Bound, bind
from defender._vocab import DISPOSITION_ENUM, normalized_disposition
from defender._episode_paths import LAYOUT
from defender.learning.branch.comparator import DELTA_SEAT, Verdict, canonical, compare
from defender.learning.branch.ledger import (
    LedgerError,
    correlation_key_of,
)
from defender.runtime.branch._family import (
    BASE_ROLE,
    episode_token_for,
    is_reserved_world_label,
    load_family,
    world_token_for,
)

#: The outcome that withholds comparability; the launcher writes it and both readers refuse on it.
INCOMPLETE = "incomplete"

#: What a difference is called when nothing attributed it: "differs, and not shown to be the
#: declared axis". Reporting `mutation` would claim a measurement nobody made. Borrowed from the
#: comparator's delta-seat vocabulary rather than re-spelled.
UNATTRIBUTED = Verdict.UNDECLARED.value

Invoke = Callable[..., Any]


class EpisodeError(ValueError):
    """An episode these readers cannot answer over honestly.

    Raised for a recorded `incomplete` outcome, an archived disposition outside the shipped
    vocabulary, or an archived world the manifest does not declare. A `ValueError` so callers
    can catch this design's refusals at one boundary.
    """


# ---------------------------------------------------------------------------------------
# the episode's own state
# ---------------------------------------------------------------------------------------


def _recorded_outcome(bound: Bound) -> tuple[str | None, str]:
    """The episode's recorded outcome and its reason, or `(None, "")` when none is recorded.

    An absent or unparseable record is not an outcome: it is an episode the launcher has not
    written yet, and must not gate the readers. Only a recorded `incomplete` refuses. A refused
    record (a link, a non-plain entry, undecodable bytes, a YAML alias) is not "none recorded":
    it may be hiding one, so it refuses.
    """
    rec = bound.read(LAYOUT.review)
    if rec.text is None and not rec.absent:
        raise EpisodeError(
            f"the review record ({LAYOUT.review}) is refused ({rec.reason}) — it is where an "
            f"{INCOMPLETE!r} outcome is recorded, so whether this episode is comparable cannot "
            "be read")
    text = rec.text
    if text is None:
        return None, ""
    try:
        record = _yaml.safe_load(text)
    except _yaml.AliasRefused as refused:
        # A document, refused for its aliases (the pre-#1127 writer wrote them), may record an
        # `incomplete` outcome: refused like any refused record, never read as none.
        raise EpisodeError(
            f"the review record ({LAYOUT.review}) is refused ({refused}) — it is where an "
            f"{INCOMPLETE!r} outcome is recorded, so whether this episode is comparable cannot "
            "be read") from refused
    except yaml.YAMLError:
        return None, ""
    if not isinstance(record, dict):
        return None, ""
    episode = record.get("episode")
    if not isinstance(episode, dict):
        return None, ""
    outcome = episode.get("outcome")
    reason = episode.get("reason")
    return (outcome if isinstance(outcome, str) else None,
            reason if isinstance(reason, str) else "")


def _refuse_incomplete(bound: Bound) -> None:
    """Refuse an episode the launcher recorded as `incomplete`."""
    outcome, reason = _recorded_outcome(bound)
    if outcome == INCOMPLETE:
        raise EpisodeError(
            f"the episode recorded outcome {INCOMPLETE!r}"
            f"{f' ({reason})' if reason else ''} — the family stamp was withheld, so the "
            "worlds that ARE archived did not demonstrably run against one tree and a per-key "
            "answer over them would read as a measurement nobody made")


def _archived_labels(bound: Bound) -> list[str]:
    """Every archived world's label, sorted — the single definition of "this episode's worlds".

    Taken from the archive, not the manifest: an incomplete family archives only its clean
    siblings, and the readers answer about what is on disk. Listed through the bind, so an entry
    is judged on what it is rather than what it points at.

    Reserved labels are skipped: the grading pass archives its own draws under
    `worlds/family/`, which no manifest can declare, and counting it would make `delta_o`
    refuse every graded episode. Asked through `is_reserved_world_label` so both gates agree on
    what is reserved.
    """
    return [label for label in bound.under(LAYOUT.worlds).entries().dirs()
            if not is_reserved_world_label(label)]


# ---------------------------------------------------------------------------------------
# verdicts
# ---------------------------------------------------------------------------------------


def _declared_disposition(text: str) -> Any:
    """The `disposition` value an archived report declares, raw and unjudged.

    Frontmatter first (via `_frontmatter`); a fence-less document whose head is a YAML mapping
    is read as that mapping. Anything else yields `None`, reported as no disposition rather than
    a bad one.
    """
    frontmatter = parse_frontmatter_or_none(text)
    if frontmatter is None:
        try:
            loaded = _yaml.safe_load(text)
        except yaml.YAMLError:
            return None
        frontmatter = loaded if isinstance(loaded, dict) else {}
    return frontmatter.get("disposition")


def verdicts(episode_dir: Path) -> dict[str, str]:
    """Each archived world's disposition, keyed by world label.

    Read from each world's own archived `report.md`, never a run dir. Judged by
    `_vocab.normalized_disposition`, which owns the vocabulary including zero-width stripping
    that a local `in DISPOSITION_ENUM` would miss.

    A value outside the vocabulary refuses, naming it: a headline that cannot be read is not the
    same as no headline.
    """
    with bind(Path(episode_dir)) as bound:
        return _verdicts(bound)


def _verdicts(bound: Bound) -> dict[str, str]:
    _refuse_incomplete(bound)
    out: dict[str, str] = {}
    for label in _archived_labels(bound):
        name = LAYOUT.world(label).report
        # Absent and unreadable differ. The archive deliberately archives a world with no
        # report (a sibling that died before writing one), even on an accepted episode, so it
        # is skipped rather than taking every other world's headline down. A present but
        # unreadable report still refuses, decided by the bound reader's own open.
        rec = bound.read(name)
        if rec.absent:
            continue
        if rec.refusal is not None:
            raise EpisodeError(
                f"world {label!r} is archived without a readable report — {rec.refusal} — "
                "the archived report is the only place this reader may learn what that "
                "sibling concluded")
        assert rec.text is not None, "present per the state check above"
        raw = _declared_disposition(rec.text)
        disposition = normalized_disposition(raw)
        if disposition is None:
            raise EpisodeError(
                f"world {label!r} declares disposition {raw!r}, which is outside the shipped "
                f"vocabulary {sorted(DISPOSITION_ENUM)}")
        out[label] = disposition
    return out


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
              invoke: Invoke | None) -> dict[str, str]:
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
        verdict = compare(base[key], world[key], axis, invoke=invoke)
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


def delta_o(episode_dir: Path, *, invoke: Invoke | None = None) -> dict[str, dict[str, str]]:
    """Per world, per shared correlation key: one member of the comparator's delta seat.

    `same`, `formatting`, `mutation` or `undeclared`, as the comparator answers it
    (`formatting` is not folded into `same`).

    Pairs `keys(base) ∩ keys(world)` on the asked form: the family's capture
    (`served/base.jsonl`) against each world's own rows (`served/<world token>.jsonl`).

    The control's drift is subtracted: the base world stages nothing, so a key where it differs
    from the capture is the estate moving underneath the episode (a rolling index, a clock),
    not any world's difference. Computed mechanically before any world is classified.

    Every archived world gets an entry, the control included; an empty entry means the world
    served nothing.
    """
    # One bind for the pass: every read below is a no-follow walk off the same held folder.
    with bind(Path(episode_dir)) as bound:
        return _delta_o(bound, invoke)


def _delta_o(bound: Bound, invoke: Invoke | None) -> dict[str, dict[str, str]]:
    _refuse_incomplete(bound)
    labels = _archived_labels(bound)
    if not labels:
        return {}
    family = load_family(bound)
    token = episode_token_for(family.episode_id)
    control = next((w.world_id for w in family.worlds if w.role == BASE_ROLE), None)

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
        if label not in {w.world_id for w in family.worlds}:
            raise EpisodeError(
                f"the archive holds a world {label!r} the manifest does not declare "
                f"({[w.world_id for w in family.worlds]}) — its axis is what a difference is "
                "classified against, so there is nothing to classify it with")
        name = LAYOUT.served_world(world_token_for(token, label))
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

    out: dict[str, dict[str, str]] = {}
    for label in labels:
        world = served[label]
        shared = sorted(set(base) & set(world) - drift)
        out[label] = _classify(base, world, shared, family.world(label).axis, invoke)
    return out


__all__ = [
    "INCOMPLETE",
    "EpisodeError",
    "delta_o",
    "verdicts",
]
