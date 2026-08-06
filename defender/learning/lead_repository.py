#!/usr/bin/env python3

from __future__ import annotations

import json
import re
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

import yaml

from defender._io import TEXT_READ_ERRORS, read_jsonl_rows, read_text_utf8
from defender._run_paths import RunPaths, artifact_dir, artifact_file, contained_payload
from defender.runtime.circuit_breaker import error_class_for_exit

if TYPE_CHECKING:
    from defender.skills.invlang.schema import CompanionBody


_LEAD_SUFFIX = ".lead.json"
_LEAD_ID_RE = re.compile(r"^l-[A-Za-z0-9]+$")


def _as_int(value, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class QueryRow:

    lead_id: str
    seq: int
    system: str
    verb: str
    query_id: str
    params: dict
    raw_command: str
    exit_code: int
    error_class: str | None
    payload_status: str
    payload_digest: str
    raw_ref: Path | None


@dataclass(frozen=True)
class JoinedLead:

    lead_id: str
    goal: str | None
    what_to_summarize: list
    queries: list
    orphan: bool = False




def lead_ids(run_dir: Path) -> tuple[str, ...]:
    """Which leads this run executed, by id, sorted — a GLOB, never a parse.

    Deliberately not `sorted(load_leads(run_dir))`, and the difference is not efficiency.
    `load_leads` json-parses each row and silently skips anything corrupt, so a single torn
    `.lead.json` would erase a lead from this answer. The write-time challenge gate closes a
    whole review on it, which means a parse hiccup on one file would quietly change the
    gate's verdict on the run. Existence is the question here; readability is not.

    The suffix and the directory are this module's and `RunPaths`'s respectively — the gate
    used to spell both by hand.
    """
    gather = RunPaths(Path(run_dir)).gather_raw
    if not gather.is_dir():
        return ()
    return tuple(sorted(
        p.name[: -len(_LEAD_SUFFIX)]
        for p in gather.glob(f"*{_LEAD_SUFFIX}")
        if p.name != _LEAD_SUFFIX
    ))


def load_leads(run_dir: Path) -> dict[str, dict]:
    gather = RunPaths(Path(run_dir)).gather_raw
    if not gather.is_dir():
        return {}
    leads: dict[str, dict] = {}
    for path in sorted(gather.glob(f"*{_LEAD_SUFFIX}")):
        lead_id = path.name[: -len(_LEAD_SUFFIX)]
        if not lead_id:
            continue
        try:
            data = json.loads(read_text_utf8(path))
        except (OSError, json.JSONDecodeError, ValueError):
            continue
        if not isinstance(data, dict):
            continue
        wts = data.get("what_to_summarize")
        leads[lead_id] = {
            "goal": str(data.get("goal", "")),
            "what_to_summarize": list(wts) if isinstance(wts, list) else [],
        }
    return leads


def load_queries(run_dir: Path) -> list[QueryRow]:
    run_dir = Path(run_dir)
    log = RunPaths(run_dir).executed_queries
    rows: list[QueryRow] = []
    try:
        raw_rows = read_jsonl_rows(log)
    except OSError:
        return []
    for rec in raw_rows:
        if not isinstance(rec, dict):
            continue
        lead_id = rec.get("lead_id")
        if not lead_id:
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
            )
        )
    return rows




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
        out.append(
            JoinedLead(
                lead_id=lid,
                goal=lead.get("goal") if lid in leads else None,
                what_to_summarize=lead.get("what_to_summarize", []),
                queries=sorted(buckets.get(lid, []), key=lambda r: r.seq),
                orphan=lid not in leads,
            )
        )
    for lid in orphans:
        out.append(
            JoinedLead(
                lead_id=lid,
                goal=None,
                what_to_summarize=[],
                queries=sorted(buckets.get(lid, []), key=lambda r: r.seq),
                orphan=True,
            )
        )
    return out


def first_rendered_payload(
    lead: JoinedLead, render: Callable[[str], str], *, unreadable: str, missing: str
) -> str:
    """The first of `lead`'s by-ref payloads that `render` turns into real content.

    The two stages that show a lead's raw events — the judge's evidence column
    (`pipeline/judge/compare.real_sample_text`, values kept) and the oracle's schema skeleton
    (`pipeline/oracle/sample.lead_sample_text`, values scrubbed) — differ ONLY in the renderer
    and the two fallback strings, so the walk lives here, on the surface that owns
    `QueryRow.raw_ref` in the first place.

    `render` signals "nothing usable here" by returning a parenthesized string, its own
    convention for every empty case; the walk therefore keeps going. One unreadable payload
    likewise does not blind the lead — a by-ref payload is bytes an adapter wrote, so neither
    its encoding nor its readability is guaranteed, and raising took a whole stage down over a
    single bad file. `unreadable` is a template taking `{error}`, reported only when NO
    payload rendered.
    """
    failure: Exception | None = None
    for q in lead.queries:
        if q.raw_ref is None or not q.raw_ref.is_file():
            continue
        try:
            raw = read_text_utf8(q.raw_ref)
        except TEXT_READ_ERRORS as e:
            failure = e
            continue
        body = render(raw)
        if not body.startswith("("):
            return body
    if failure is not None:
        return unreadable.format(error=failure)
    return missing


def actor_view(run_dir: Path) -> dict:
    run_dir = Path(run_dir)
    grouped: dict[str, list[dict]] = {}
    for q in load_queries(run_dir):
        grouped.setdefault(q.lead_id, []).append(
            {"query_id": q.query_id, "params": q.params}
        )
    return {
        "case_id": run_dir.name,
        "alert_ref": "alert.json",
        "leads": [
            {"lead_id": lid, "queries": qs} for lid, qs in grouped.items()
        ],
    }




def stage_tables(src_run_dir: Path, dst_dir: Path) -> list[Path]:
    """Copy the two tables into the learning run dir, refusing anything that is not a regular
    file or a real directory. Returns what it refused, so the caller can say so out loud.

    Only real artifacts cross this boundary (#648). The run dir is the box's rw bind, so a link
    planted at an artifact's name would otherwise have its TARGET copied in — the escape
    happens here, at the copy, and after it the planted bytes are an ordinary in-run file that
    no read-time gate can distinguish. A boxed run whose tree holds a link never reaches this
    point (the exit scrub taints it), so a refusal here means the tree skipped that scrub.

    Refusing rather than aborting: a dangling link left in the gather tree must not cost the
    run its whole learning pass (#705), and every consumer already tolerates a missing payload.
    """
    src_run_dir = Path(src_run_dir)
    dst_dir = Path(dst_dir)
    dst_dir.mkdir(parents=True, exist_ok=True)
    refused: list[Path] = []
    queries_src = RunPaths(src_run_dir).executed_queries
    if artifact_file(queries_src):
        shutil.copy2(queries_src, RunPaths(dst_dir).executed_queries)
    elif queries_src.exists() or queries_src.is_symlink():
        refused.append(queries_src)
    gather_src = RunPaths(src_run_dir).gather_raw
    if artifact_dir(gather_src):
        # `symlinks=True` alongside the ignore hook: the hook decides from an `lstat` taken
        # before the copy, so the flag is what keeps a link planted inside that window from
        # being dereferenced anyway.
        shutil.copytree(gather_src, RunPaths(dst_dir).gather_raw, symlinks=True,
                       ignore=_refuse_non_artifacts(refused), dirs_exist_ok=True)
    elif gather_src.exists() or gather_src.is_symlink():
        refused.append(gather_src)
    return refused


def _refuse_non_artifacts(refused: list[Path]):
    """`copytree`'s ignore hook, recording as it goes: drops every entry at every depth that is
    not a regular file or a real directory."""
    def _ignore(directory, names):
        here = Path(directory)
        dropped = {n for n in names
                   if not (artifact_file(here / n) or artifact_dir(here / n))}
        refused.extend(here / n for n in sorted(dropped))
        return dropped
    return _ignore




def render_actor_view_yaml(run_dir: Path) -> str:
    return yaml.safe_dump(actor_view(run_dir), sort_keys=False)


def render_joined_yaml(run_dir: Path) -> str:
    run_dir = Path(run_dir)
    leads = []
    for jl in joined(run_dir):
        lead = {
            "lead_id": jl.lead_id,
            "goal": jl.goal,
            "what_to_summarize": jl.what_to_summarize,
            "queries": [
                {
                    "query_id": q.query_id,
                    "verb": q.verb,
                    "params": q.params,
                    "payload_status": q.payload_status,
                    "payload_digest": q.payload_digest,
                }
                for q in jl.queries
            ],
        }
        leads.append(lead)
    doc = {"case_id": run_dir.name, "alert_ref": "alert.json", "leads": leads}
    return yaml.safe_dump(doc, sort_keys=False)




def narration_crosscheck(run_dir: Path, l_ids: set[str]) -> dict:
    lead_ids = set(load_leads(run_dir))
    query_rows = load_queries(run_dir)
    query_lead_ids = {q.lead_id for q in query_rows}
    table_ids = lead_ids | query_lead_ids

    jl = joined(run_dir)
    leads_without_queries = sorted(
        {j.lead_id for j in jl if not j.queries} | (l_ids - table_ids)
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
        if isinstance(f, dict) and isinstance(f.get("id"), str)
        and _LEAD_ID_RE.match(f["id"])
    }
