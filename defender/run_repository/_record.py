"""The episode -> runs record (#1105 D3): which runs an episode's siblings are, kept host-only
at `tenant.runs/_episodes/<episode_id>.json`, beside `_tenant.json` and outside every box bind.

Content is exactly `{episode_id, tenant_id, source_run_id, runs: {label: run_id}}`, run ids as
`RunId` text, in one canonical sorted-key serialisation, at most 64 KiB. Sibling ids are
recorded, never re-derived. A listing hides every id a good record claims, so a sibling never
shows up as an ordinary run (O4).

The reader's rule is a closed list (D3.4, MF-12): every entry of `_episodes` must be a regular
file named `<grammar-valid episode id>.json`, read no-follow and no further than the cap plus one
byte, strict UTF-8 JSON with no duplicate key and exactly the four fields, `episode_id` equal to
the file name minus its final `.json`, and run ids `RunId.parse` admits. Anything else refuses
with `RunRefused` naming it (P2): a torn record fails closed until an operator removes it by
hand. A record that breaks only a WRITER rule (two labels on one id, say) is good on read, so in
PR 1 "a record never hides an ordinary run" holds through the writer.

`episode_sibling_ids(runs)` reads a `Bound` it is handed, with no tenant compare (its callers
judge the tenant themselves); the tenant-keyed functions hold `tenant.runs` like the lookups and
add the compare.
"""
from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from defender import _io
from defender._run_id import (
    CASE_STABLE_REQUIRED, RUN_ID_ALLOWED, is_case_stable_id, is_valid_run_id,
)
from defender._tenant import Tenant
from defender._world_label import reserved_label_fault, world_view_fault
from defender._shown import quoted, shown
from defender.run_repository._errors import RunRefused
from defender.run_repository._held import (
    EPISODES_DIRNAME, HeldRuns, Listing, hold_runs, require_accepted_tenant, require_run_id,
    sidecar_owner,
)
from defender.run_repository._id import RunId

#: The largest record the reader accepts and the writer writes, in bytes (D3.4; owner, OP-4).
_RECORD_CAP = 65536
#: The longest file name the record may take (NAME_MAX).
_NAME_MAX = 255
_RECORD_SUFFIX = ".json"
#: A record's fields, exactly these (D3.2). `_episode_record_text` is their one producer.
_FIELDS = frozenset({"episode_id", "tenant_id", "source_run_id", "runs"})


# -- the record's name and text ------------------------------------------------------------------


def _admit_episode_id(episode_id: object) -> str:
    """`episode_id`, if it may name a record: exactly a `str` (a subclass could format unlike
    its text), a valid, case-stable run id (the family model's `refuse_bad_episode_id`
    rule, judged with the same two `_run_id` checks), and short enough that
    `<episode_id>.json` fits a file name. Else `RunRefused`, before any name is built or folder
    read (OP-5). Not `_run_id.episode_id_fault`: the spec admits ids up to the file-name bound
    here (a reader over such an id answers empty), and no record can be written for an id that
    rule refuses, since every arm must be a `RunId` spelled `<episode_id>-<label>`."""
    if type(episode_id) is not str:
        raise RunRefused(f"an episode id must be exactly a str, not {type(episode_id).__name__}")
    if not (is_valid_run_id(episode_id) and is_case_stable_id(episode_id)):
        raise RunRefused(f"episode id {quoted(episode_id)} is not usable (allowed: "
                         f"{RUN_ID_ALLOWED}; {CASE_STABLE_REQUIRED})") from None
    if len(_record_name(episode_id).encode("utf-8")) > _NAME_MAX:
        raise RunRefused(f"episode id {quoted(episode_id)} is too long: its record's file name "
                         f"would pass {_NAME_MAX} bytes")
    return episode_id


def _record_name(episode_id: str) -> str:
    return f"{episode_id}{_RECORD_SUFFIX}"


def episode_record_path(runs_base: Path, episode_id: str) -> Path:
    """Where episode `episode_id`'s record lives under the runs folder `runs_base`: the one
    accessor that owns the record's name (`run-records-kinds.tsv`'s `episode_runs_record`).
    The repository's own reads and writes go through its held folder, by the same relative
    name; this is the path its refusals name."""
    return Path(runs_base) / EPISODES_DIRNAME / _record_name(_admit_episode_id(episode_id))


def _episode_record_text(episode_id: str, tenant_id: str, source_run_id: RunId,
                 runs: Mapping[str, RunId]) -> str:
    """@owns episode record text — the one canonical serialisation of a record (D3.2, MF-16):
    the four fields, run ids as their text, keys sorted at every level, so equal content is
    equal bytes whatever order the caller's mapping iterates in."""
    doc = {"episode_id": episode_id, "tenant_id": tenant_id,
           "source_run_id": str(source_run_id),
           "runs": {label: str(run_id) for label, run_id in runs.items()}}
    return json.dumps(doc, sort_keys=True, indent=2) + "\n"


# -- the reader (D3.4, R1) -----------------------------------------------------------------------


def _corrupt(path: str, why: str) -> RunRefused:
    return RunRefused(f"{path} is not a good episode record ({why}) — it fails closed until an "
                      "operator removes it by hand")


def _no_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    doc: dict[str, Any] = {}
    for key, value in pairs:
        if key in doc:
            raise ValueError(f"duplicate key {quoted(key)}")
        doc[key] = value
    return doc


def _strict_text(value: object) -> bool:
    """Whether every string in a decoded document is text UTF-8 can hold: JSON may escape a
    lone surrogate (`\\ud800`) that strict decoding of the bytes never yields (NM-04)."""
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            return False
        return True
    if isinstance(value, dict):
        return all(_strict_text(k) and _strict_text(v) for k, v in value.items())
    if isinstance(value, list):
        return all(_strict_text(v) for v in value)
    return True


def _run_id_of(value: object, path: str, what: str) -> RunId:
    if not isinstance(value, str):
        raise _corrupt(path, f"{what} is not text")
    try:
        return RunId.parse(value)
    except RunRefused:
        raise _corrupt(path, f"{what} {quoted(value)} is not a run id") from None


def _parse_episode_record(text: str, *, path: str, stem: str,
                  tenant_id: str | None) -> tuple[RunId, dict[str, RunId]]:
    """The source and `{label: RunId}` of one record's text, or `RunRefused` naming `path` for
    the first rule it breaks (D3.4). `tenant_id=None` makes no tenant compare."""
    if _io.json_nesting_depth(text) > _io.JSON_NESTING_LIMIT:
        raise _corrupt(path, f"nested deeper than {_io.JSON_NESTING_LIMIT}")
    try:
        doc = json.loads(text, object_pairs_hook=_no_duplicate_keys)
    except (ValueError, RecursionError) as exc:
        raise _corrupt(path, f"not one strict JSON document: {exc}") from None
    if not _strict_text(doc):
        raise _corrupt(path, "it escapes a lone surrogate, which no UTF-8 text holds")
    if not isinstance(doc, dict) or set(doc) != _FIELDS:
        raise _corrupt(path, f"not exactly the fields {sorted(_FIELDS)}")
    if not isinstance(doc["tenant_id"], str):
        raise _corrupt(path, "tenant_id is not text")
    if tenant_id is not None and doc["tenant_id"] != tenant_id:
        raise _corrupt(path, f"it names the tenant {quoted(doc['tenant_id'])}, not "
                             f"{quoted(tenant_id)}")
    if doc["episode_id"] != stem:
        raise _corrupt(path, f"its episode_id is not {quoted(stem)}, its file name's")
    source = _run_id_of(doc["source_run_id"], path, "source_run_id")
    runs = doc["runs"]
    if not isinstance(runs, dict) or not runs:
        raise _corrupt(path, "runs is not a non-empty map")
    arms = {label: _run_id_of(value, path, f"the arm {quoted(label)}")
            for label, value in runs.items()}
    return source, arms


def _good_stem(stem: str) -> bool:
    try:
        _admit_episode_id(stem)
    except RunRefused:
        return False
    return True


def _read_one(episodes: _io.Bound, name: str, *, path: str, stem: str,
              tenant_id: str | None, io: Any) -> tuple[RunId, dict[str, RunId]] | None:
    """One record off `episodes`, read no-follow (H5); `None` when it is absent. The cap is
    judged on the file's size, from a no-follow `stat` of the entry, before anything is read;
    then the record is read as strict UTF-8, newlines kept, never past the cap plus one byte
    (a record that grew after its `stat` is still refused as over). Any refused or corrupt
    read is `RunRefused` naming it."""
    entry = io.stat_entry(episodes, name)
    if entry.absent:
        return None
    if entry.st is None:
        raise _corrupt(path, f"it cannot be read: {entry.reason}")
    if entry.st.st_size > _RECORD_CAP:
        raise _corrupt(path, f"it is over {_RECORD_CAP} bytes")
    answer = episodes.read(name, max_bytes=_RECORD_CAP + 1)
    if answer.absent:
        return None
    if answer.text is None:
        raise _corrupt(path, f"it cannot be read (unreadable, or not UTF-8 text): "
                             f"{answer.reason}")
    if len(answer.text.encode("utf-8")) > _RECORD_CAP:
        raise _corrupt(path, f"it is over {_RECORD_CAP} bytes")
    return _parse_episode_record(answer.text, path=path, stem=stem, tenant_id=tenant_id)


def _read_records(runs: _io.Bound, *, where: str, tenant_id: str | None,
                  io: Any) -> dict[str, dict[str, RunId]]:
    """Every record of `runs/_episodes`, by episode id: `{}` when `_episodes` is absent. Every
    entry there must be a good record (R1); anything else is `RunRefused` naming it. `where` is
    how a refusal names the runs folder (empty: relative)."""
    folder = f"{where}/{EPISODES_DIRNAME}" if where else EPISODES_DIRNAME
    episodes = runs.under(EPISODES_DIRNAME)
    listing = episodes.entries()
    if listing.absent:
        return {}
    if listing.entries is None:
        raise RunRefused(f"{folder} cannot be listed (a link, a file or unreadable): "
                         f"{listing.reason}")
    records: dict[str, dict[str, RunId]] = {}
    for name in sorted(listing.entries):
        path = f"{folder}/{shown(name)}"
        stem = name[: -len(_RECORD_SUFFIX)] if name.endswith(_RECORD_SUFFIX) else ""
        if listing.entries[name] != io.ENTRY_FILE or not _good_stem(stem):
            raise RunRefused(f"{path} is not an episode record: only regular files named "
                             f"<episode id>{_RECORD_SUFFIX} belong in {folder}")
        read = _read_one(episodes, name, path=path, stem=stem, tenant_id=tenant_id, io=io)
        if read is None:
            raise RunRefused(f"{path} was listed and then could not be found")
        records[stem] = read[1]
    return records


def episode_sibling_ids(runs: _io.Bound, *, where: str | None = None,
                        io: Any = _io) -> set[RunId]:
    """Every run id any record under `runs/_episodes` claims, with D3.4's file rules and NO
    tenant compare (R1: run setup and PR 2's corpus judge the tenant themselves). `runs` must
    be a `_io.Bound` (else `TypeError`, before any read); the empty set when it is absent or
    `_episodes` is. It is not closed here: the caller owns it. `where` is how a refusal names
    the runs folder; a caller holding only the `Bound` leaves it out and the view says where it
    is (`_io.located`)."""
    if not isinstance(runs, _io.Bound):
        raise TypeError(f"episode_sibling_ids reads a Bound runs folder, not "
                        f"{type(runs).__name__}")
    shown_root = _io.located(runs) if where is None else where
    records = _read_records(runs, where=shown_root, tenant_id=None, io=io)
    return {run_id for arms in records.values() for run_id in arms.values()}


def claimed_ids(runs: HeldRuns) -> set[RunId]:
    """`episode_sibling_ids` over a held runs folder, plus the tenant compare: a record naming
    another tenant is corrupt here (D3.5)."""
    records = _read_records(runs.view, where=str(runs.folder), tenant_id=runs.tenant.id,
                            io=runs.io)
    return {run_id for arms in records.values() for run_id in arms.values()}


def episode_runs(tenant: Tenant, episode_id: str, *, io: Any = _io) -> dict[str, RunId]:
    """`{label: RunId}` from that episode's own record only; `{}` when it has none (DV-7) or
    the runs folder is absent. Another episode's record is never read."""
    tenant = require_accepted_tenant(tenant)
    episode_id = _admit_episode_id(episode_id)
    with hold_runs(tenant, io) as runs:
        if runs.absent:
            return {}
        name = _record_name(episode_id)
        read = _read_one(runs.view.under(EPISODES_DIRNAME), name,
                         path=str(episode_record_path(tenant.runs, episode_id)),
                         stem=episode_id, tenant_id=tenant.id, io=io)
    return {} if read is None else read[1]


def sibling_run_ids(tenant: Tenant, *, io: Any = _io) -> set[RunId]:
    """Every run id any of the tenant's good records claims; the empty set when the runs folder
    or `_episodes` is absent. One corrupt record refuses the whole answer (fail closed)."""
    tenant = require_accepted_tenant(tenant)
    with hold_runs(tenant, io) as runs:
        return set() if runs.absent else claimed_ids(runs)


# -- the writer (D3.3) ---------------------------------------------------------------------------


def _admit_label(label: object, folded: dict[str, str]) -> str:
    """`label`, if the family model admits it as a world label (not reserved, nameable as a
    view, distinct from every label before it under case folding). Exactly a `str`."""
    if type(label) is not str:
        raise RunRefused(f"a label must be exactly a str, not {type(label).__name__}")
    if (why := reserved_label_fault(label) or world_view_fault(label)) is not None:
        raise RunRefused(f"label {quoted(label)} is not a world label the family model "
                         f"admits: {why}")
    if (key := label.casefold()) in folded:
        raise RunRefused(f"labels {quoted(folded[key])} and {quoted(label)} are one label "
                         "wherever the filesystem folds case")
    folded[key] = label
    return label


def _admit_runs(episode_id: str, source: RunId,
                items: Sequence[tuple[object, RunId]]) -> dict[str, RunId]:
    """The arms, if every one is a sibling this episode may record: a label the family model
    admits, an arm shaped `<episode_id>-<label>` and not like a sidecar, none the source. No
    id can come twice: arms are `<episode_id>-<label>` and the labels are distinct even folded."""
    if not items:
        raise RunRefused(f"episode {quoted(episode_id)} records no runs")
    folded: dict[str, str] = {}
    arms: dict[str, RunId] = {}
    for raw_label, run_id in items:
        label = _admit_label(raw_label, folded)
        if sidecar_owner(str(run_id)) is not None:
            raise RunRefused(f"arm {quoted(str(run_id))} is shaped like a host-only sidecar file")
        if str(run_id) != f"{episode_id}-{label}":
            raise RunRefused(f"arm {quoted(str(run_id))} for label {quoted(label)} is not "
                             f"{quoted(f'{episode_id}-{label}')}")
        if run_id == source:
            raise RunRefused(f"arm {quoted(str(run_id))} is the source run itself")
        arms[label] = run_id
    return arms


def record_episode_runs(tenant: Tenant, episode_id: str, source_run_id: RunId,
                        runs: Mapping[str, RunId], *, io: Any = _io) -> None:
    """Record, once, which runs are episode `episode_id`'s siblings (D3.3).

    Writes `tenant.runs/_episodes/<episode_id>.json` through the held folder's create lane, and
    nothing else: never the runs folder or `_tenant.json` (`ensure_runs_base_record` stays that
    record's one writer). Refuses, writing nothing: an unchecked runs folder (`TenantRefused`);
    a non-`RunId` source or arm (`TypeError`); and with `RunRefused` a bad episode id, an empty
    or non-mapping `runs`, a label the family model refuses, an arm not shaped
    `<episode_id>-<label>` or shaped like a sidecar, two labels on one id, an arm equal to the
    source, an arm another record claims or a run or sidecar file already occupies, content
    over 64 KiB, and an unexpected entry anywhere it reads. `runs` is read once.

    The writer's state is the file (MF-16): a byte-identical retry is a no-op; different content
    for a recorded episode is refused, the episode id being spent; nothing it did not create is
    ever removed. A filesystem fault is `RunRefused` naming the path, never a raw `OSError`."""
    tenant = require_accepted_tenant(tenant)
    source = require_run_id(source_run_id, what="source run id")
    items = list(runs.items()) if isinstance(runs, Mapping) else []
    for _label, run_id in items:
        require_run_id(run_id, what="arm run id")
    episode_id = _admit_episode_id(episode_id)
    if not isinstance(runs, Mapping):
        raise RunRefused(f"episode {quoted(episode_id)}: runs is not a mapping of label to "
                         f"RunId, but {type(runs).__name__}")
    arms = _admit_runs(episode_id, source, items)
    text = _episode_record_text(episode_id, tenant.id, source, arms)
    if len(text.encode("utf-8")) > _RECORD_CAP:
        raise RunRefused(f"episode {quoted(episode_id)}'s record would be over "
                         f"{_RECORD_CAP} bytes")
    name = _record_name(episode_id)
    path = episode_record_path(tenant.runs, episode_id)
    with hold_runs(tenant, io) as held:
        view = held.require_present().view
        listing = held.listing()
        records = _read_records(view, where=str(held.folder), tenant_id=tenant.id, io=io)
        if episode_id not in records:
            _refuse_taken_arms(arms, records, listing, folder=Path(tenant.runs))
            try:
                held.write(f"{EPISODES_DIRNAME}/{name}", text, mode="create")
                return
            except FileExistsError:
                pass  # recorded meanwhile: judged against its bytes below
            except OSError as exc:
                raise RunRefused(f"{path} could not be written: {exc.strerror or exc}") from None
        _judge_existing(view.under(EPISODES_DIRNAME).read(
            name, max_bytes=_RECORD_CAP + 1), text, path=path, episode_id=episode_id)


def _judge_existing(existing: _io.RecordRead, text: str, *, path: Path,
                    episode_id: str) -> None:
    """The writer's verdict on the record already at its name: byte-identical to `text` is the
    idempotent retry (no write); anything else refuses, naming why. `existing` is read strict
    and byte-faithful, so equal text is equal bytes."""
    if existing.absent:
        raise RunRefused(f"{path} was created by another writer and is gone again — "
                         "nothing was recorded; retry the episode's setup")
    if existing.text is None:
        raise RunRefused(f"{path} exists but cannot be read ({existing.reason}) — it is "
                         "not judged against this episode's record")
    if existing.text != text:
        raise RunRefused(f"{path} already records episode {quoted(episode_id)} with "
                         "different content; an episode id is spent once recorded — remove "
                         "the file by hand only if that episode never started")


def _refuse_taken_arms(arms: Mapping[str, RunId], records: Mapping[str, Mapping[str, RunId]],
                       listing: Listing, *, folder: Path) -> None:
    """Refuse an arm another record already claims, or whose name already holds a run or a
    sidecar file in the held listing (H6)."""
    claimed = {run_id: episode for episode, recorded in records.items()
               for run_id in recorded.values()}
    for run_id in arms.values():
        if run_id in claimed:
            raise RunRefused(f"arm {quoted(str(run_id))} is already claimed by episode "
                             f"{quoted(claimed[run_id])}'s record")
        if run_id in listing.runs or run_id in listing.sidecar_ids:
            raise RunRefused(f"arm {quoted(str(run_id))} is taken: {folder}/{run_id} holds a "
                             "run or its sidecar files")
