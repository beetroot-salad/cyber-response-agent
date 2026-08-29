"""The two derived readers: what each world concluded, and where the worlds differ.

#947's M8, read side. `verdicts` answers "what disposition did each sibling reach"; `delta_o`
answers "on which of the questions the family shares did a world's observation differ, and was
the difference the one that world declared". Both are DERIVED ON READ — nothing here is
stored, because a stored answer is a second place for it to live and the one that drifts is
the one nobody re-derives.

**BOTH READ THE EPISODE DIRECTORY AND NOTHING ELSE.** That is D3's self-containment claim, and
it is a claim about this module more than about the archive: the sibling run dirs are
disposable, they live under a root this module is not told about, and one of them may be gone
by the time anyone grades the episode. So the archived report is what `verdicts` reads (never
the run's own `report.md`), the archived `served/` ledgers are what `delta_o` pairs, and the
archived `run_dir` pointer is INFORMATIONAL — a text file naming where the bytes came from,
which nothing here opens, resolves or follows. A test deletes every sibling's directory and
asks both readers the same questions again; a reader that reached for one would answer
differently, or not at all, on an episode that is otherwise complete.

**BOTH REFUSE AN EPISODE WHOSE RECORDED OUTCOME IS `incomplete`.** `incomplete` is a modelled
outcome (§7 FORK-1), not the absence of a file: the launcher writes it into `review.yaml` with
a reason when a sibling's scrub or stamp could not be verified, and it withholds the family
stamp. The worlds that ARE archived are still on disk and still individually readable — but
they are not COMPARABLE, because the thing that failed is the guarantee that the three ran
against one tree. A per-key answer computed over them would carry no marker saying so, and
downstream it would read as a measurement. Refusing is what keeps "no differences" and "no
comparison was possible" from being the same empty dict.

**An episode with no archived worlds answers EMPTY rather than refusing** (§7 FORK-18). An
episode rejected before step 5 never ran a sibling and is a legitimate archived state — its
manifest, staging record and review are the artifacts, and `{}` is the honest reading of "no
world produced anything". That is only safe because the recorded outcome above distinguishes
it from "the worlds ran and agreed".
"""

from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import yaml

from defender._frontmatter import parse_frontmatter_or_none
from defender._io import read_guarded, read_jsonl_rows
from defender._run_paths import artifact_dir, artifact_file
from defender._vocab import DISPOSITION_ENUM, normalized_disposition
from defender.learning.branch.archive import WORLDS_DIRNAME
from defender.learning.branch.comparator import DELTA_SEAT, Verdict, compare
from defender.learning.branch.ledger import (
    Ledger,
    base_file,
    payload_text,
    request_key,
)
from defender.runtime.branch._family import (
    BASE_ROLE,
    MANIFEST_NAME,
    episode_token_for,
    load_family,
    world_token_for,
)

#: The launcher's record, under the episode. Read for ONE field here — the episode's own
#: recorded outcome — and read through the same loader that wrote it.
REVIEW_NAME = "review.yaml"

#: The outcome that withholds comparability. Spelled once: the launcher writes it, both
#: readers refuse on it, and a second spelling is a refusal that stops firing.
INCOMPLETE = "incomplete"

#: What a difference is called when there is no model seam to attribute it with. NOT a
#: degraded `mutation`: `undeclared` says exactly "this world's observation differs and the
#: difference has not been shown to be the axis it declared", which is precisely what is known
#: when nothing classified it. Inventing `mutation` there would report a measurement nobody
#: made. The comparator's own member, borrowed rather than spelled: this reader reports the
#: delta seat's vocabulary and keeps no second copy of it (`comparator.DELTA_SEAT`).
UNATTRIBUTED = Verdict.UNDECLARED.value

Invoke = Callable[..., Any]


class EpisodeError(ValueError):
    """An episode these readers cannot answer over honestly.

    Three things reach it: a recorded outcome that withholds comparability, an archived report
    whose disposition is outside the shipped vocabulary, and an archived world the manifest
    does not declare. A `ValueError`, so a caller that funnels this design's refusals through
    one boundary catch keeps them all.
    """


# ---------------------------------------------------------------------------------------
# the episode's own state
# ---------------------------------------------------------------------------------------


def _recorded_outcome(episode_dir: Path) -> tuple[str | None, str]:
    """The episode's recorded outcome and its reason, or `(None, "")` when none is recorded.

    An absent, unreadable or unparseable record is NOT an outcome. It is how an episode looks
    before the launcher has written anything, and the readers of a hand-built or partially
    written episode must not be gated on a document that does not exist yet — the refusal
    below fires on a recorded `incomplete`, which is a positive statement someone made.
    """
    text, _refusal = read_guarded(episode_dir / REVIEW_NAME)
    if text is None:
        return None, ""
    try:
        record = yaml.safe_load(text)
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


def _refuse_incomplete(episode_dir: Path) -> None:
    """Refuse an episode the launcher recorded as `incomplete` — see the module docstring."""
    outcome, reason = _recorded_outcome(episode_dir)
    if outcome == INCOMPLETE:
        raise EpisodeError(
            f"the episode at {episode_dir} recorded outcome {INCOMPLETE!r}"
            f"{f' ({reason})' if reason else ''} — the family stamp was withheld, so the "
            "worlds that ARE archived did not demonstrably run against one tree and a per-key "
            "answer over them would read as a measurement nobody made")


def _archived_labels(episode_dir: Path) -> list[str]:
    """Every archived world's label, sorted — the ONE definition of "this episode's worlds".

    Taken from the archive rather than from the manifest, because they are different sets and
    the difference is the point: an incomplete family archives the siblings that were
    individually clean and omits the one that was not, and both readers answer about what is
    on disk. `artifact_dir` rather than `is_dir()`: this directory sits inside the episode
    tree, and an entry there is judged on what it IS rather than on what it points at.
    """
    worlds = Path(episode_dir) / WORLDS_DIRNAME
    if not artifact_dir(worlds):
        return []
    return sorted(entry.name for entry in worlds.iterdir() if artifact_dir(entry))


# ---------------------------------------------------------------------------------------
# verdicts
# ---------------------------------------------------------------------------------------


def _declared_disposition(text: str) -> Any:
    """The `disposition` value an archived report declares, raw and unjudged.

    Two shapes, because the archive copies whatever the sibling published and this reader
    must not be the thing that decides which spelling counts. The house form is frontmatter
    (`_frontmatter` owns the fence arithmetic — nothing here counts `---` lines); a document
    with no fences whose head is a YAML mapping is read as that mapping. Anything else yields
    `None`, which the caller reports as a report with no disposition rather than as a report
    with a bad one.
    """
    frontmatter = parse_frontmatter_or_none(text)
    if frontmatter is None:
        try:
            loaded = yaml.safe_load(text)
        except yaml.YAMLError:
            return None
        frontmatter = loaded if isinstance(loaded, dict) else {}
    return frontmatter.get("disposition")


def verdicts(episode_dir: Path) -> dict[str, str]:
    """Each archived world's disposition, keyed by world label.

    Read from each world's OWN archived `report.md` — one report per world, none sourced from
    another, and never from a run dir. Gated by the shipped disposition vocabulary through
    `_vocab.normalized_disposition` rather than by a membership test written here: that
    function owns what a disposition MEANS, including the zero-width strip a locally-written
    `in DISPOSITION_ENUM` would silently drop, and a report laced with a zero-width character
    would otherwise render as `malicious` to a human and refuse for a reader (or worse, the
    other way round).

    A value outside the vocabulary REFUSES and the refusal names it: the disposition is the
    headline #921 grades on, and a world whose headline cannot be read is not a world with no
    headline.
    """
    episode_dir = Path(episode_dir)
    _refuse_incomplete(episode_dir)
    out: dict[str, str] = {}
    for label in _archived_labels(episode_dir):
        report = episode_dir / WORLDS_DIRNAME / label / "report.md"
        text, refusal = read_guarded(report)
        if text is None:
            raise EpisodeError(
                f"world {label!r} is archived without a readable report ({report}): {refusal}"
                " — the archived report is the only place this reader may learn what that "
                "sibling concluded")
        raw = _declared_disposition(text)
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
    """The key a row PAIRS on: the call as it was ASKED.

    The recorded `correlation_key` when the row carries one, and otherwise the same
    derivation `ServedCall.correlation_key` makes — `request_key` over `asked_params` where
    staging rewrote the call, falling back to `params` where nothing was rewritten.

    THE FALLBACK IS THE WHOLE MECHANISM, not a tolerance. A staged world's `params` name that
    world's own corpus by construction (`wv-<token>-logs-`), so a pairing keyed on them
    intersects the base's keys in the EMPTY SET — every world would report no difference from
    a base it never met, silently, and silently on the event stream, where most of a run's
    evidence lives.
    """
    recorded = row.get("correlation_key")
    if isinstance(recorded, str) and recorded:
        return recorded
    asked = row.get("asked_params")
    params = asked if isinstance(asked, dict) else row.get("params")
    system, verb = row.get("system"), row.get("verb")
    if not isinstance(system, str) or not isinstance(verb, str):
        return None
    return request_key(system, verb, params if isinstance(params, dict) else {})


def _canonical(row: dict) -> str | None:
    """One row's answer, in the canonical spelling both sides of a comparison are dumped in.

    Re-dumped through `ledger.payload_text` rather than compared as stored text: `sort_keys`
    is what makes two dumps of one answer compare equal, and the source run's captured
    sidecars were written WITHOUT it — so a byte comparison of stored text would report a
    difference on every row of a primed capture, in a field no world touched.
    """
    text = row.get("payload_text")
    if not isinstance(text, str) or not text:
        return None
    try:
        return payload_text(json.loads(text))
    except (TypeError, ValueError):
        # Not JSON — a torn row, or an error digest. It has no canonical form, so it is
        # compared as the bytes it is rather than dropped: two worlds recording the same
        # unparseable answer still agree, which is the honest reading.
        return text


def _answers(path: Path) -> dict[str, str]:
    """One ledger file as `{pair key: canonical answer}`, first row winning.

    First-row-wins is the append-only reading of "recorded once", and it is the same rule the
    ledger's own memo applies — two readers resolving a duplicate key in opposite directions
    is how one file gets read as two different recordings.
    """
    if not artifact_file(path):
        return {}
    out: dict[str, str] = {}
    for row in read_jsonl_rows(path):
        key, answer = _pair_key(row), _canonical(row)
        if key is None or answer is None:
            continue
        out.setdefault(key, answer)
    return out


def _classify(base: dict[str, str], world: dict[str, str], keys: list[str], axis: str | None,
              invoke: Invoke | None) -> dict[str, str]:
    """One world's shared keys, each classified against the base's answer.

    Mechanical first and by design: equal canonical text is `same` with no model call at all,
    which is what keeps a family of a few hundred replayed calls from being a few hundred
    model calls. Only a genuine difference reaches the comparator, and it reaches it with the
    world's OWN declared axis — the delta seat — so the answer is "is this the difference the
    world said it was making" rather than "do these two payloads disagree".

    With no model seam (`invoke=None`) nothing is attributed: a difference is `undeclared`,
    the member that says exactly that, and the reader stays deterministic and offline instead
    of reaching for a provider a caller did not hand it.
    """
    out: dict[str, str] = {}
    for key in keys:
        if base[key] == world[key]:
            out[key] = Verdict.SAME.value
            continue
        if invoke is None:
            out[key] = UNATTRIBUTED
            continue
        # `.value`, not the member: this reader's answer is a plain-string table a caller
        # writes to YAML and compares against bare words, and `str(Verdict.SAME)` on a
        # `(str, Enum)` renders `'Verdict.SAME'` rather than `'same'`. The membership gate is
        # the comparator's OWN seat set — a second list of the members this seat admits, kept
        # here, is a vocabulary that drifts from the one the refusal beside it is written from.
        verdict = compare(base[key], world[key], axis, invoke=invoke)
        out[key] = verdict.value if verdict in DELTA_SEAT else _wrong_seat(key, verdict)
    return out


def _wrong_seat(key: str, verdict: Verdict) -> str:
    """Unreachable through `compare`, and kept because that is a promise rather than a proof.

    `compare` refuses a verdict outside the seat its axis selected, so this frame answers only
    if that gate is ever loosened or bypassed. F2's cost is exactly this: ONE type spans both
    seats, so nothing structurally prevents a wrong-seat member and the CALLER is what refuses
    one. Reported, never mapped onto a member this seat does admit — that would record a guess
    where a measurement belongs.
    """
    raise EpisodeError(
        f"the comparator answered {verdict.value!r} for correlation key {key!r} with an axis "
        f"given — that belongs to the other seat, and this one admits "
        f"{sorted(v.value for v in DELTA_SEAT)}")


def delta_o(episode_dir: Path, *, invoke: Invoke | None = None) -> dict[str, dict[str, str]]:
    """Per world, per shared correlation key: one member of the comparator's DELTA seat.

    `same`, `formatting`, `mutation` or `undeclared` — the seat's own set, reported as the
    comparator answers it rather than re-spelled here (`formatting` is a member of it: a
    difference in presentation is a real answer to "is this the difference you declared", and
    mapping it onto `same` would be this frame overruling the one that measured).

    THE PAIRING IS `keys(base) ∩ keys(world)` ON THE FORM ASKED. The family's shared capture
    (`served/base.jsonl`) is one side and each world's own rows (`served/<world token>.jsonl`)
    are the other. See `_pair_key` for why the asked form is the only form this can pair on.

    THE CONTROL'S DRIFT IS SUBTRACTED, the way the review subtracts it (design M4: "A first,
    as the control; its mismatch keys are drift"). The base world stages nothing, so a key on
    which IT differs from the capture is the estate moving underneath the episode — a rolling
    index, a clock, a document that aged out — and reporting it as a world's own difference
    turns the one measurement #921 consumes into noise. Computed mechanically, from the
    control's own ledger, so drift costs no model call and is decided before any world is
    classified.

    Every archived world gets an entry, the control included: with its own drift keys removed
    the control's remaining keys are `same` by construction, and an entry that is present and
    empty is the honest record of a world that served nothing.
    """
    episode_dir = Path(episode_dir)
    _refuse_incomplete(episode_dir)
    labels = _archived_labels(episode_dir)
    if not labels:
        return {}
    family = load_family(episode_dir / MANIFEST_NAME)
    token = episode_token_for(family.episode_id)
    control = next((w.world_id for w in family.worlds if w.role == BASE_ROLE), None)

    base = _answers(base_file(episode_dir))
    served: dict[str, dict[str, str]] = {}
    for label in labels:
        if label not in {w.world_id for w in family.worlds}:
            raise EpisodeError(
                f"the archive holds a world {label!r} the manifest does not declare "
                f"({[w.world_id for w in family.worlds]}) — its axis is what a difference is "
                "classified against, so there is nothing to classify it with")
        served[label] = _answers(
            Ledger.for_world(episode_dir, world_token_for(token, label)).path)

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
    "REVIEW_NAME",
    "EpisodeError",
    "delta_o",
    "verdicts",
]
