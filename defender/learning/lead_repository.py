#!/usr/bin/env python3

from __future__ import annotations

import shutil
from collections.abc import Sequence
from dataclasses import field
from defender._model import model
from pathlib import Path
from typing import TYPE_CHECKING, Annotated


from defender import _yaml
from pydantic import SkipValidation

from defender._io import (
    load_json_artifact,
    read_guarded,
    read_jsonl_rows_report,
    read_text_utf8,
)
from defender.run_repository import (
    RUN_LAYOUT,
    LEAD_ID_RE as _LEAD_ID_RE,
    RunPaths,
    artifact_dir,
    artifact_file,
    contained_payload,
    plain_file,
)
from defender._text import as_str
from defender.runtime.circuit_breaker import error_class_for_exit
from defender._query_rules import is_reserved_query_id

if TYPE_CHECKING:
    from defender.skills.invlang.schema import CompanionBody


# A valid lead id used only to compose a claim file name, from which both the glob and the
# suffix strip in `load_leads` derive, so the two cannot disagree. Nothing is read or written
# at the composed path.
_SPECIMEN_LEAD_ID = "l-0"


def _as_int(value, default: int = 0) -> int:
    """A stored integer column as `int`, `default` for anything that is not one.
    `OverflowError` because an out-of-range JSON number decodes to `inf`."""
    try:
        return int(value)
    except (TypeError, ValueError, OverflowError):
        return default


@model(frozen=True)
class QueryRow:
    """One queries-table row as the canonical surface reads it: every column
    `record_query.QUERY_ROW_COLUMNS` declares, with the writer's own coercions, and
    `payload_path` read as the containment-checked `raw_ref`.

    The typed fields are a reader's view (e.g. `error_class` derived from `exit_code` when
    absent). The row as written is kept and returned by `record()`, for a reader that must see
    what the live guard saw."""

    lead_id: str
    seq: int
    system: str
    verb: str
    query_id: str
    #: `SkipValidation`: validation would rebuild the dict, and `params` must be the same
    #: object as the record's (see `record()`). The loader already refuses a non-dict.
    params: Annotated[dict, SkipValidation]
    raw_command: str
    exit_code: int
    error_class: str | None
    payload_status: str
    payload_digest: str
    raw_ref: Path | None
    #: The payload's content identity — `sha256` of the persisted sidecar text; `""` when
    #: absent (older rows, fixtures). Its reader, `repeat_note`'s `_result_identity`, treats any
    #: falsy value as "no identity". Not model-facing: renders name their columns, and none
    #: names this.
    payload_sha256: str = ""
    #: The hash half of an above-guard rejection's identity: `sha256` of a model-authored system
    #: string the writer coarsened to `system=""`; `""` elsewhere. Coerced as the guard's `_trip`
    #: coerces it, so an older table replays exactly as it ran. For the guard, not a model.
    system_key: str = ""
    #: The parsed JSON record this row was read from, by identity — see `record()`. Excluded
    #: from equality and repr; `SkipValidation` because validation would copy it.
    _record: Annotated[dict | None, SkipValidation] = field(
        default=None, repr=False, compare=False)

    def record(self) -> dict:
        """The row as read — the parsed JSON record exactly as `record_query.lead_rows` hands
        the guard live, never a re-projection of the typed fields.

        The typed view coerces while the guard reads keys verbatim, so a replay over
        re-projected rows could reach a verdict the live run never reached. This is what makes
        `rejection_trip([r.record() for r in load_queries(run_dir)], ...)` the run's own
        verdict.

        The dict is shared with the typed view (not a copy): read it, do not write to it. A row
        built by keyword (a fixture) has no record to return."""
        if self._record is None:
            raise ValueError("QueryRow.record(): this row was not read from a queries table")
        return self._record

    @property
    def is_sentinel(self) -> bool:
        """Is this row a writer-only `∅.` record (a refused repeat, a rejected call, a failed
        reducer shim) rather than a query the defender ran? Nothing it describes reached a
        system of record. Uses the writer's own predicate, so new sentinels partition too."""
        return is_reserved_query_id(self.query_id)


@model(frozen=True)
class JoinedLead:

    lead_id: str
    goal: str | None
    what_to_summarize: list
    #: The queries the defender ACTUALLY RAN, seq-ordered — every consumer that means
    #: "what did this lead ask" reads this, and gets no sentinel row by construction.
    queries: list
    orphan: bool = False
    #: Absent (`None`) reads as model-authored: rows written before this field existed must
    #: join the same way.
    provenance: str | None = None
    #: The lead's `∅.`-prefixed rows, seq-ordered — split out of `queries` so the safe reading
    #: is the default. Kept because `collect_general_failures` reads them.
    sentinels: list = field(default_factory=list)

    @property
    def rows(self) -> list:
        """Every row this lead has in the queries table, in seq order (`queries` and
        `sentinels` remerged), for readers that mean the table rather than the queries."""
        return sorted([*self.queries, *self.sentinels], key=lambda r: r.seq)




def load_leads(run_dir: Path) -> dict[str, dict]:
    gather = RunPaths(Path(run_dir)).gather_raw
    # `artifact_dir`, not `is_dir()`: a linked `gather_raw` would read another tree's leads.
    if not artifact_dir(gather):
        return {}
    leads: dict[str, dict] = {}
    specimen = RunPaths(gather.parent).lead_claim(_SPECIMEN_LEAD_ID).name
    suffix = specimen[len(_SPECIMEN_LEAD_ID):]
    for path in sorted(gather.glob(f"*{suffix}")):
        lead_id = path.name[: -len(suffix)]
        if not lead_id:
            continue
        # Guarded read of each entry: the glob yields planted links too. `O_NOFOLLOW` + `fstat`
        # judge the object actually opened, so a swapped-in link or a hard link is refused.
        text, _refused = read_guarded(path)
        if text is None:
            continue
        # Not JSON, or nested past the bound: not a lead (never a raise out of `joined()`).
        data, unreadable = load_json_artifact(text)
        if unreadable is not None or not isinstance(data, dict):
            continue
        wts = data.get("what_to_summarize")
        provenance = data.get("provenance")
        entry = {
            "goal": str(data.get("goal", "")),
            "what_to_summarize": list(wts) if isinstance(wts, list) else [],
        }
        if provenance:
            # Only set when present: callers comparing against the exact two-key dict literal
            # `{"goal": ..., "what_to_summarize": ...}` must keep matching untouched rows.
            entry["provenance"] = str(provenance)
        leads[lead_id] = entry
    return leads


def load_queries(run_dir: Path) -> list[QueryRow]:
    """The query rows consumers join, tolerating malformed physical records."""
    return load_queries_report(run_dir)[0]


def load_queries_report(run_dir: Path) -> tuple[list[QueryRow], int]:
    """The query rows and every physical record that could not become one.

    Ordinary consumers intentionally use the tolerant :func:`load_queries` view. Capture
    priming uses this report because each discarded record is a question that may otherwise
    fall through to the live estate without appearing in its non-determinism count.
    """
    run_dir = Path(run_dir)
    log = RunPaths(run_dir).executed_queries
    rows: list[QueryRow] = []
    try:
        # `artifact_file` ahead of the read, which follows links: a link, FIFO or device at the
        # name would read another tree's rows. Absent counts nothing; anything else there is one
        # unreadable record. Inside the `try` for an `EACCES` on the run dir.
        if not artifact_file(log):
            return [], (1 if log.is_symlink() or log.exists() else 0)
        raw_rows, unreadable = read_jsonl_rows_report(log)
    except OSError:
        return [], 1
    for rec in raw_rows:
        lead_id = rec.get("lead_id")
        # The file is box-writable and a lead id can reach a judge prompt heading from this
        # column alone, so a value not shaped like a lead id is an unreadable record.
        if not isinstance(lead_id, str) or not _LEAD_ID_RE.match(lead_id):
            unreadable += 1
            continue
        raw_ref = contained_payload(run_dir, rec.get("payload_path"))
        params = rec.get("params")
        exit_code = _as_int(rec.get("exit_code", 0))
        if "error_class" in rec:
            raw_ec = rec.get("error_class")
            error_class = str(raw_ec) if raw_ec is not None else None
        else:
            error_class = error_class_for_exit(exit_code)
        rows.append(
            QueryRow(
                lead_id=str(lead_id),
                seq=_as_int(rec.get("seq", 0)),
                system=str(rec.get("system", "")),
                verb=str(rec.get("verb", "")),
                query_id=str(rec.get("query_id", "")),
                params=params if isinstance(params, dict) else {},
                raw_command=str(rec.get("raw_command", "")),
                exit_code=exit_code,
                error_class=error_class,
                payload_status=str(rec.get("payload_status", "")),
                payload_digest=str(rec.get("payload_digest", "")),
                raw_ref=raw_ref,
                # `as_str`: the guard's own coercion (absent / `None` / non-string -> `""`).
                payload_sha256=as_str(rec.get("payload_sha256")),
                system_key=as_str(rec.get("system_key")),
                _record=rec,
            )
        )
    return rows, unreadable




def joined(run_dir: Path) -> list[JoinedLead]:
    leads = load_leads(run_dir)
    queries = load_queries(run_dir)

    buckets: dict[str, list[QueryRow]] = {lid: [] for lid in leads}
    first_seen: dict[str, int] = {}
    for idx, q in enumerate(queries):
        buckets.setdefault(q.lead_id, []).append(q)
        first_seen.setdefault(q.lead_id, idx)

    ran = sorted(
        (lid for lid in buckets if buckets[lid]),
        key=lambda lid: first_seen.get(lid, len(queries)),
    )
    queryless = sorted(lid for lid in leads if not buckets.get(lid))
    orphans = sorted(lid for lid in buckets if lid not in leads)

    out: list[JoinedLead] = []
    for lid in [*ran, *queryless]:
        if lid in orphans:
            continue
        lead = leads.get(lid, {})
        issued, observed = _partition(buckets.get(lid, []))
        out.append(
            JoinedLead(
                lead_id=lid,
                goal=lead.get("goal") if lid in leads else None,
                what_to_summarize=lead.get("what_to_summarize", []),
                queries=issued,
                orphan=lid not in leads,
                provenance=lead.get("provenance") if lid in leads else None,
                sentinels=observed,
            )
        )
    for lid in orphans:
        issued, observed = _partition(buckets.get(lid, []))
        out.append(
            JoinedLead(
                lead_id=lid,
                goal=None,
                what_to_summarize=[],
                queries=issued,
                orphan=True,
                sentinels=observed,
            )
        )
    return out


def _partition(rows: list[QueryRow]) -> tuple[list[QueryRow], list[QueryRow]]:
    """`(queries, sentinels)`, each seq-ordered. Never decides whether the lead appears: a lead
    with only sentinels still joins with empty `queries`."""
    ordered = sorted(rows, key=lambda r: r.seq)
    return (
        [r for r in ordered if not r.is_sentinel],
        [r for r in ordered if r.is_sentinel],
    )


def actor_view(run_dir: Path) -> dict:
    """The actor's gray-box view: the queries the defender ran, and nothing else about it.

    Sentinel rows are dropped (shown as queries they would claim runs that never happened, and
    `∅.bash-shim` carries model-authored shell text), but their lead is kept."""
    run_dir = Path(run_dir)
    grouped: dict[str, list[dict]] = {}
    for q in load_queries(run_dir):
        # Registered before the skip, so a sentinel-only lead appears with no queries.
        entries = grouped.setdefault(q.lead_id, [])
        if q.is_sentinel:
            continue
        entries.append({"query_id": q.query_id, "params": q.params})
    return {
        "case_id": run_dir.name,
        "alert_ref": RUN_LAYOUT.alert.name,
        "leads": [
            {"lead_id": lid, "queries": qs} for lid, qs in grouped.items()
        ],
    }




def stage_tables(src_run_dir: Path, dst_dir: Path) -> list[Path]:
    """Copy the two tables into the learning run dir, refusing anything that is not a regular
    file or a real directory; returns what it refused.

    The run dir is box-writable, and a link copied here would become an ordinary file no later
    gate can tell apart. A refusal means the tree skipped the box's exit scrub. Refused rather
    than aborted: every consumer tolerates a missing payload.
    """
    src_run_dir = Path(src_run_dir)
    dst_dir = Path(dst_dir)
    dst_dir.mkdir(parents=True, exist_ok=True)
    refused: list[Path] = []
    queries_src = RunPaths(src_run_dir).executed_queries
    if artifact_file(queries_src):
        # Guarded by the `artifact_file` above; a link here lands in `refused` instead.
        shutil.copy2(  # lint-tree-read-follows-link: ok — screened on the line above
            queries_src, RunPaths(dst_dir).executed_queries)
    elif queries_src.exists() or queries_src.is_symlink():
        refused.append(queries_src)
    gather_src = RunPaths(src_run_dir).gather_raw
    if artifact_dir(gather_src):
        # `symlinks=True` too: the ignore hook's `lstat` precedes the copy, so the flag keeps a
        # link planted in that window from being dereferenced.
        shutil.copytree(  # lint-tree-read-follows-link: ok — root screened, entries preserved, destinations screened by `refusing_copy2`
            gather_src, RunPaths(dst_dir).gather_raw, symlinks=True,
            ignore=refuse_non_artifacts(refused), dirs_exist_ok=True,
            copy_function=refusing_copy2(refused))
    elif gather_src.exists() or gather_src.is_symlink():
        refused.append(gather_src)
    return refused


def refusing_copy2(refused: list[Path]):
    """`shutil.copy2`, refusing a destination that is not absent or a plain, single-linked file.

    `copy2` opens its destination for writing, following a planted link, and
    `copytree(dirs_exist_ok=True)` walks into existing, box-reachable destination trees at any
    depth. Refused rather than raised, so one planted name does not cost a whole archive."""
    def _copy(src, dst, *, follow_symlinks=True):
        target = Path(dst)
        # `plain_file`: a hard link is a regular file to `lstat` but still shares the target.
        if (target.exists() or target.is_symlink()) and not plain_file(target):
            refused.append(target)
            return dst
        return shutil.copy2(  # lint-tree-read-follows-link: ok — destination screened above, source screened by `refuse_non_artifacts`
            src, dst, follow_symlinks=follow_symlinks)
    return _copy


def refuse_non_artifacts(refused: list[Path]):
    """`copytree`'s ignore hook, recording as it goes: drops every entry at every depth that is
    not a regular file or a real directory. Also used by the episode archive."""
    def _ignore(directory, names):
        here = Path(directory)
        dropped = {n for n in names
                   if not (artifact_file(here / n) or artifact_dir(here / n))}
        refused.extend(here / n for n in sorted(dropped))
        return dropped
    return _ignore




def render_actor_view_yaml(run_dir: Path) -> str:
    return _yaml.safe_dump(actor_view(run_dir), sort_keys=False)


def project_leads(
    leads: Sequence[JoinedLead], *, lead_fields: Sequence[str], query_fields: Sequence[str],
) -> list[dict]:
    """The one walk from the join to a model-facing list of dicts: each lead as exactly
    `lead_fields` plus `queries`, each query exactly `query_fields`.

    `.queries`, never `.rows`: sentinels are not queries the defender ran (as in `actor_view`),
    though a sentinel-only lead is kept with `queries: []`. Columns are named, never dumped, so
    a new `QueryRow` column reaches a model only by being named here."""
    return [
        {
            **{name: getattr(jl, name) for name in lead_fields},
            "queries": [{name: getattr(q, name) for name in query_fields} for q in jl.queries],
        }
        for jl in leads
    ]


#: Everything the questioner is shown of a lead and a query. Deliberately absent: `raw_command`
#: and `raw_ref` (a shell string and the host's absolute path), `payload_sha256`/`system_key`
#: (guard identities), `orphan` (reads as `goal: None`), `sentinels`.
QUESTIONER_LEAD_FIELDS: tuple[str, ...] = ("lead_id", "goal", "what_to_summarize", "provenance")
QUESTIONER_QUERY_FIELDS: tuple[str, ...] = (
    "seq", "system", "verb", "query_id", "params", "exit_code", "error_class",
    "payload_status", "payload_digest",
)


def questioner_leads(leads: Sequence[JoinedLead]) -> list[dict]:
    """The questioner's "joined leads" section: `project_leads` over `joined()` with the
    questioner's columns — never a row object or its `repr`.

    @owns questioner_leads — the section's shape is decided by the two field tuples above."""
    return project_leads(
        leads, lead_fields=QUESTIONER_LEAD_FIELDS, query_fields=QUESTIONER_QUERY_FIELDS)


def render_joined_yaml(run_dir: Path) -> str:
    run_dir = Path(run_dir)
    leads = project_leads(
        joined(run_dir),
        lead_fields=("lead_id", "goal", "what_to_summarize"),
        query_fields=("query_id", "verb", "params", "payload_status", "payload_digest"),
    )
    doc = {"case_id": run_dir.name, "alert_ref": RUN_LAYOUT.alert.name, "leads": leads}
    return _yaml.safe_dump(doc, sort_keys=False)




def narration_crosscheck(run_dir: Path, l_ids: set[str]) -> dict:
    lead_ids = set(load_leads(run_dir))
    query_rows = load_queries(run_dir)
    query_lead_ids = {q.lead_id for q in query_rows}
    table_ids = lead_ids | query_lead_ids

    jl = joined(run_dir)
    # `.rows`: the question is whether the lead reached the table at all.
    leads_without_queries = sorted(
        {j.lead_id for j in jl if not j.rows} | (l_ids - table_ids)
    )

    missing_from_narration = sorted(table_ids - l_ids)
    queries_without_lead = sorted(query_lead_ids - lead_ids)

    return {
        "missing_from_narration": missing_from_narration,
        "queries_without_lead": queries_without_lead,
        "leads_without_queries": leads_without_queries,
        "ok": not missing_from_narration and not queries_without_lead,
    }


def narration_crosscheck_from_run(run_dir: Path) -> dict:
    run_dir = Path(run_dir)
    from defender.skills.invlang.parser import parse_dense_companion

    text = read_text_utf8(RunPaths(run_dir).investigation)
    companion, _ = parse_dense_companion(text)
    return narration_crosscheck(run_dir, _lead_ids_from_companion(companion))


def _lead_ids_from_companion(companion: CompanionBody) -> set[str]:
    return {
        f["id"]
        for f in companion.get("findings", [])
        # lint-selection: ok — defence in depth over input the write gate already validated
        # (`validate._check_lead_refs` refuses a malformed `:L findings` id), so nothing is dropped.
        if isinstance(f, dict) and isinstance(f.get("id"), str)
        and _LEAD_ID_RE.match(f["id"])
    }
