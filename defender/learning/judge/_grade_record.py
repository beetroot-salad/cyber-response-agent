"""Episode grade records, their validated reader, and persistence."""
from __future__ import annotations



from dataclasses import field, fields as dataclass_fields

from pathlib import Path

from typing import Annotated, Any

from pydantic import AfterValidator, TypeAdapter, ValidationError

from defender._model import model  # noqa: E402


from defender.learning.core.retired import (  # noqa: E402
    RETIRED_LANES,
    retired_keys,
    retired_row_names,
)

from defender.learning.judge._errors import JudgeRefused  # noqa: E402

from defender.episodes._episode_handle import Episode  # noqa: E402

from defender._io import bind  # noqa: E402


from defender.episodes._episode_paths import LAYOUT  # noqa: E402



from defender.learning.judge import enqueue as enqueue_mod  # noqa: E402

from defender.learning.judge import family as family_mod  # noqa: E402






from defender import _yaml



#: A world row's and the family row's commit state (A6): written `queueing` before the row's
#: findings are appended, `queued` after. No key: the row completed no draw (re-graded).
STATE_KEY = "state"


QUEUEING, QUEUED = "queueing", "queued"


#: The family call's label: its draw directory, agent ids and finding ids.
FAMILY_LABEL = "family"



#: The user record's lists (design M7, A2, A7; R1 (c)). `gap_findings` holds the findings
#: whose resolving conduct pointers are all blocked calls (gap-only, A1): beside the serving
#: findings, never inside them.
NAMED_GAPS, FOUND_GAPS = "named_gaps", "found_gaps"


SERVING_FINDINGS, UNKEYED_NAMED_GAPS, GAP_FINDINGS = (
    "serving_findings", "unkeyed_named_gaps", "gap_findings")


_USER_LISTS = (NAMED_GAPS, FOUND_GAPS, SERVING_FINDINGS, UNKEYED_NAMED_GAPS, GAP_FINDINGS)




@model
class NotGradedStamp:
    """Why the pass declined to grade an episode: the word it stopped on and its reason."""

    outcome: str
    reason: str




def _ledger_entries_name_a_lane(entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """What the record asks of a ledger entry is what its writer asks
    (`enqueue.check_disposition_entry`): it names its finding and takes one of the lanes."""
    for entry in entries:
        enqueue_mod.check_disposition_entry(entry)
    return entries




def _rows_name_their_world(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """What the record asks of a world row beyond being a mapping: it names its world, and its
    commit state, when it has one, is one of A6's two (`_check_state`). Every other key belongs
    to the row's declared owners and is carried as written."""
    for row in rows:
        if not isinstance(row.get("world"), str):
            raise ValueError(f"a world row does not name its world: {row!r}")
        _check_state(row, f"world {row['world']!r}")
    return rows




def _check_state(row: dict[str, Any] | None, where: str) -> dict[str, Any] | None:
    """A row's `state` is absent or one of A6's two, `queueing` and `queued`; any other value
    is refused by name — a record whose commit state no pass wrote cannot say whether its
    findings are on a queue."""
    if row is not None and STATE_KEY in row and row[STATE_KEY] not in (QUEUEING, QUEUED):
        raise ValueError(f"{where}'s {STATE_KEY} is {row[STATE_KEY]!r}, not {QUEUEING!r} or "
                         f"{QUEUED!r}")
    return row




def _family_state(row: dict[str, Any] | None) -> dict[str, Any] | None:
    return _check_state(row, f"the {FAMILY_LABEL} row")




def _empty_user() -> dict[str, list[dict[str, Any]]]:
    return {name: [] for name in _USER_LISTS}




@model
class EpisodeGrade:
    """`grade_episode`'s return value and the schema of `judge.yaml`, in both directions.

    Strict (no coercion), so a document of the wrong shape fails at the constructor.
    `episode_dir` and `graded_worlds` are derived: never written, recomputed from the rows on
    every read (`_DERIVED`).

    Each world row carries its combined draws (`route.combine_draws`: `bucket`, `systems`,
    `draws`, `measured`, `not_measured_reason`, `draws_disagree`, `world_label_doubted`),
    `completed_draws`/`malformed_replies`, and its commit `state` (A6); a world that could not
    be judged carries `ungradable` and its reason instead. `family` is the family call's own
    row; `user` the user record (named, found, serving, unkeyed and gap-only entries);
    `dispositions` the ledger — one `{finding_id, lane, reason}` per filed finding (A13).
    """

    episode_dir: Path
    worlds: Annotated[list[dict[str, Any]], AfterValidator(_rows_name_their_world)] = field(
        default_factory=list)
    graded_worlds: frozenset[str] = field(default_factory=frozenset)
    #: O5's verdict on the family (M19=A): `usable`, `unusable`, or `None` where the pass never
    #: counted (a manifest refusal, an outcome other than `accepted`/`unusable`).
    validity: str | None = None
    family: Annotated[dict[str, Any] | None, AfterValidator(_family_state)] = None
    user: dict[str, list[dict[str, Any]]] = field(default_factory=_empty_user)
    #: The ledger, in walk order. `None` for a `not_graded` stamp; a pass that walked nothing
    #: writes `[]`.
    dispositions: Annotated[list[dict[str, Any]],
                            AfterValidator(_ledger_entries_name_a_lane)] | None = None
    enqueued_rows: int = 0
    enqueued_to: str = ""
    world_enqueued_rows: int = 0
    world_enqueued_to: str = ""
    #: The unreadable lines (a torn trailing row, say) the latest append saw on the defender /
    #: questioner queue: skipped and counted, never raised on (#921 F-11).
    queue_malformed_rows: int = 0
    world_queue_malformed_rows: int = 0
    draws: dict[str, int] = field(default_factory=dict)
    knobs: dict[str, Any] = field(default_factory=dict)
    lessons_commit: str | None = None
    not_graded: NotGradedStamp | None = None




#: Fields not written to the file: the path, and the set re-derived from the rows so no
#: top-level list can disagree with them.
_DERIVED = frozenset({"episode_dir", "graded_worlds"})




def _known_keys(record: type, doc: dict[Any, Any]) -> dict[Any, Any]:
    """`doc` minus string keys the schema does not name, so a newer (or older) record still
    reads. A reader-side tolerance only: `@model` still refuses unknown keywords at
    construction. A non-string key is kept, for the constructor's own `TypeError`."""
    names = {f.name for f in dataclass_fields(record)}
    return {k: v for k, v in doc.items() if not isinstance(k, str) or k in names}




def _existing_grade(episode_dir: Path) -> dict[str, Any] | None:
    # Screened read: this is the idempotency record in a box-reachable tree, and a planted one
    # would stop the pass from ever running. Nothing at the name is an ordinary ungraded episode.
    with bind(Path(episode_dir)) as bound:
        return family_mod.screened_yaml_mapping(bound, LAYOUT.judge, what="the family grade")




def read_grade(episode_dir: Path) -> EpisodeGrade | None:
    """The episode's recorded grade off `judge.yaml`, or `None` when there is none.

    The one reader, shared with the episode page and the re-run. A record carrying a name
    #1234 retired (`_retired_names_in`) is `JudgeRefused` naming it, before anything is read
    (A4). Otherwise absent fields take defaults and unknown keys are dropped, never read; a
    planted link, a non-mapping or a schema failure is `JudgeRefused`. A `not_graded` stamp
    reads back as a grade carrying it.
    """
    episode_dir = Path(episode_dir)
    doc = _existing_grade(episode_dir)
    return None if doc is None else _grade_from_document(episode_dir, doc)




def _retired_names_in(doc: dict[str, Any]) -> list[str]:
    """Every place `doc` (a `judge.yaml` mapping) carries a retired name (`core/retired`): a
    retired field at top level, on a world row, a world row's draw or the family row; the
    retired finding type as a world row's or a draw's `bucket`; a retired ledger lane. `[]` for
    a record of the new shape. Each place reads as `<where>: <names>`."""
    found: list[str] = []

    def note(where: str, names: list[str]) -> None:
        if names:
            found.append(f"{where}: {', '.join(names)}")

    note("top level", retired_keys(doc))
    worlds = doc.get("worlds")
    for row in worlds if isinstance(worlds, list) else ():
        if not isinstance(row, dict):
            continue
        where = f"world {row.get('world')!r}"
        note(where, retired_row_names(row, type_key="bucket"))
        draws = row.get("draws")
        for draw in draws if isinstance(draws, list) else ():
            if isinstance(draw, dict):
                note(f"{where} draw {draw.get('draw')!r}",
                     retired_row_names(draw, type_key="bucket"))
    family = doc.get("family")
    if isinstance(family, dict):
        note(f"the {FAMILY_LABEL} row", retired_keys(family))
    ledger = doc.get("dispositions")
    for entry in ledger if isinstance(ledger, list) else ():
        lane = entry.get("lane") if isinstance(entry, dict) else None
        if isinstance(lane, str) and lane in RETIRED_LANES:
            note(f"ledger entry {entry.get('finding_id')!r}", [f"lane {lane}"])
    return found




def _grade_from_document(episode_dir: Path, doc: dict[str, Any]) -> EpisodeGrade:
    retired = _retired_names_in(doc)
    if retired:
        # Before the unknown-key drop: a retired field is never read as the old design meant
        # it, and never silently dropped as though it were merely unknown (A4).
        raise JudgeRefused(
            f"{LAYOUT.judge} carries names #1234 retired ({'; '.join(retired)}): a record "
            "written before the change is refused by name, for the re-run and the page alike — "
            "move it aside to grade the episode afresh")
    # Strictly validated; a wrong shape is refused, not re-graded (a planted record must not
    # buy model calls — a human deletes the file). `TypeError` too: non-string YAML keys fail
    # as keywords before pydantic runs.
    try:
        fields = _known_keys(EpisodeGrade, {k: v for k, v in doc.items() if k not in _DERIVED})
        if isinstance(fields.get("not_graded"), dict):
            fields["not_graded"] = NotGradedStamp(**_known_keys(NotGradedStamp,
                                                                fields["not_graded"]))
        if isinstance(fields.get("user"), dict):
            fields["user"] = {**_empty_user(), **fields["user"]}
        record = EpisodeGrade(**fields, episode_dir=episode_dir)
    except (ValidationError, TypeError) as bad:
        raise JudgeRefused(f"{LAYOUT.judge} is not a family grade record: {bad}") from bad
    record.graded_worlds = frozenset(
        r["world"] for r in record.worlds if family_mod.is_gradable_row(r))
    return record




#: Built once: constructing a `TypeAdapter` is a schema build.
_GRADE_ADAPTER: TypeAdapter[EpisodeGrade] = TypeAdapter(EpisodeGrade)




def _write_judge_yaml(episode: Episode, record: EpisodeGrade) -> None:
    doc = _GRADE_ADAPTER.dump_python(record, mode="json", exclude=set(_DERIVED))
    # The stamp is present or absent, never null.
    if doc["not_graded"] is None:
        del doc["not_graded"]
    episode.judge.write(_yaml.safe_dump(doc, sort_keys=False))
