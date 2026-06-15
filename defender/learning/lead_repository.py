#!/usr/bin/env python3
"""The single read/join surface over the two live lead/query tables.

A defender run produces two canonical, append-only tables, each written
*live* by its own generator during the run — no post-run projection:

  leads    gather_raw/{lead_id}.lead.json   (hooks/record_lead.py)
           {goal, what_to_summarize}, keyed on the :L row id (`l-001`).
  queries  executed_queries.jsonl           (scripts/tools/record_query.py)
           one row per executed query, FK `lead_id`, payloads by-ref at
           gather_raw/{lead_id}/{seq}.json.

This module is the *only* place those two tables are joined. Consumers
(lead-author, oracle, judge, eval, classifier, visualizers, the actor
projection) call `joined()` / `actor_view()` / the render helpers instead
of re-parsing the artifacts or hand-joining three of them. Replaces the
old `scripts/project_lead_sequence.py` projection layer.

Pure read-only. The core readers (`load_leads`, `load_queries`, `joined`,
`actor_view`) touch only JSON + JSONL and never raise on a missing or
malformed artifact — a partial run yields a partial view, never an error.
`narration_crosscheck_from_run` lazily imports the invlang parser; that is
the only cross-package dependency and it stays local to the function so the
readers remain importable in minimal contexts.

`actor_view` is the integrity boundary: it groups the *queries* table alone
and **never opens a `*.lead.json`**, so the adversarial actor structurally
cannot see `goal` / `what_to_summarize` — the redaction is a column-set
boundary, not field-by-field stripping.
"""

from __future__ import annotations

import json
import os
import re
import shutil
from dataclasses import dataclass
from pathlib import Path

import yaml


GATHER_DIR = "gather_raw"
QUERIES_LOG = "executed_queries.jsonl"
_LEAD_SUFFIX = ".lead.json"
# A `:L` row id: `l-` + alphanumerics. Used to filter the parsed companion's
# findings down to actual lead rows — the parser also surfaces `:R` resolution
# rows whose "id" is a comma-joined lead *reference* (e.g. `l-001,l-002`), which
# is not a lead id and must not be treated as one.
_LEAD_ID_RE = re.compile(r"^l-[A-Za-z0-9]+$")


def _as_int(value, default: int = 0) -> int:
    """Coerce a JSONL field to int, defaulting on null / non-numeric.

    The readers must never raise on a malformed artifact (a hand-edited or
    partially-written row can carry a null or non-numeric ``seq`` /
    ``exit_code``), so an uncoercible value degrades to ``default`` rather
    than taking down ``load_queries`` and every consumer that joins on it.
    """
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


@dataclass(frozen=True)
class QueryRow:
    """One executed-query row from `executed_queries.jsonl`.

    `raw_ref` is the on-disk payload path *as recorded* (`run_dir /
    payload_path`), or None when the wrapper failed to write the payload
    (`payload_path: null`). It is never reconstructed from `{lead_id}/{seq}`
    — that would hand a consumer a path that may not exist.
    """

    lead_id: str
    seq: int
    system: str
    verb: str
    query_id: str
    params: dict
    raw_command: str
    exit_code: int
    payload_status: str
    payload_digest: str
    raw_ref: Path | None


@dataclass(frozen=True)
class JoinedLead:
    """A leads-table row with its queries nested on the FK."""

    lead_id: str
    goal: str | None
    what_to_summarize: list
    queries: list  # list[QueryRow], seq-sorted
    orphan: bool = False  # True when queries reference a lead_id with no sidecar


# --------------------------------------------------------------------------
# Table readers
# --------------------------------------------------------------------------


def load_leads(run_dir: Path) -> dict[str, dict]:
    """Read every `gather_raw/*.lead.json` → `{lead_id: {goal, what_to_summarize}}`.

    `lead_id` is the sidecar stem (`gather_raw/l-001.lead.json` → `l-001`).
    Missing dir → `{}`; unreadable / non-JSON / non-dict sidecar → skipped.
    A sidecar missing `goal` is still returned (goal=""), so a malformed
    dispatched lead stays visible to the narration cross-check;
    `what_to_summarize` defaults to `[]` when absent or non-list.
    """
    gather = Path(run_dir) / GATHER_DIR
    if not gather.is_dir():
        return {}
    leads: dict[str, dict] = {}
    for path in sorted(gather.glob(f"*{_LEAD_SUFFIX}")):
        lead_id = path.name[: -len(_LEAD_SUFFIX)]
        if not lead_id:
            continue
        try:
            data = json.loads(path.read_text())
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
    """Parse `executed_queries.jsonl` into `QueryRow`s, in execution order.

    Blank lines and non-JSON / non-dict rows are skipped. A row with no
    `lead_id` is skipped (it can't be joined). `raw_ref` is derived from the
    recorded `payload_path` (None when the payload write failed). Missing log
    → `[]`.
    """
    run_dir = Path(run_dir)
    log = run_dir / QUERIES_LOG
    if not log.is_file():
        return []
    rows: list[QueryRow] = []
    try:
        text = log.read_text()
    except OSError:
        return []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except (json.JSONDecodeError, ValueError):
            continue
        if not isinstance(rec, dict):
            continue
        lead_id = rec.get("lead_id")
        if not lead_id:
            continue
        payload_path = rec.get("payload_path")
        # By contract payloads are recorded run-dir-relative; an absolute path
        # would silently escape the run dir under `/` (run_dir / "/abs" == /abs),
        # so treat it as malformed and carry no ref rather than a path outside
        # the run dir.
        if payload_path and not Path(payload_path).is_absolute():
            raw_ref = run_dir / payload_path
        else:
            raw_ref = None
        params = rec.get("params")
        rows.append(
            QueryRow(
                lead_id=str(lead_id),
                seq=_as_int(rec.get("seq", 0)),
                system=str(rec.get("system", "")),
                verb=str(rec.get("verb", "")),
                query_id=str(rec.get("query_id", "")),
                params=params if isinstance(params, dict) else {},
                raw_command=str(rec.get("raw_command", "")),
                exit_code=_as_int(rec.get("exit_code", 0)),
                payload_status=str(rec.get("payload_status", "")),
                payload_digest=str(rec.get("payload_digest", "")),
                raw_ref=raw_ref,
            )
        )
    return rows


# --------------------------------------------------------------------------
# Join surface
# --------------------------------------------------------------------------


def joined(run_dir: Path) -> list[JoinedLead]:
    """Leads with their queries nested on FK `lead_id`.

    The oracle / judge / eval / classifier / visualize join surface. One
    element per lead_id appearing in *either* table:

    - a lead with no queries → `queries: []` (monitor case; never dropped);
    - a query whose `lead_id` has no sidecar → a synthetic `orphan` lead
      (`goal=None`, `orphan=True`) so consumers can surface it.

    Order: leads that ran, by first execution (first appearance in the
    queries log, which is in execution order); then query-less leads in
    `lead_id` sort order; then orphans last. `seq` resets to 0 per lead, so
    it cannot order leads against each other — the global row index does, and
    this matches `actor_view`'s grouping order.
    """
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
    orphans = sorted(lid for lid in buckets if buckets[lid] and lid not in leads)

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
                queries=sorted(buckets[lid], key=lambda r: r.seq),
                orphan=True,
            )
        )
    return out


def actor_view(run_dir: Path) -> dict:
    """Adversarial actor-facing projection — queries ONLY.

    MUST NOT read the leads table: this function never calls `load_leads`,
    so `goal` / `what_to_summarize` physically cannot leak. Per-lead grouping
    comes from the `lead_id` FK carried on every query row.

      {"case_id": <run name>, "alert_ref": "alert.json",
       "leads": [{"lead_id": "l-001",
                  "queries": [{"query_id": ..., "params": {...}}, ...]}, ...]}

    A lead that ran no query does not appear — correct: the actor reasons
    about what queries ran. Group order: first execution.
    """
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


# --------------------------------------------------------------------------
# Table staging (copy the two tables between run dirs)
# --------------------------------------------------------------------------


def _link_or_copy_file(src: Path, dst: Path) -> None:
    """Hardlink `src`→`dst`, falling back to a byte copy across filesystems.

    Hardlinking is cheap (a new name for the same inode, no data copy) and has
    no `..`-escape, but it only works within one filesystem; `os.link` raises
    `OSError` (EXDEV / EMLINK / EPERM) otherwise, and we copy instead. A missing
    `src` is a no-op (a query-less monitor run has no payloads), matching the
    best-effort contract of `stage_tables`.
    """
    src = Path(src)
    dst = Path(dst)
    if not src.is_file():
        return
    dst.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.link(src, dst)
    except OSError:
        shutil.copy2(src, dst)


def _link_or_copy_tree(src_dir: Path, dst_dir: Path) -> None:
    """Replicate a directory tree as REAL dirs, hardlinking (or copying) files.

    Never symlinks a directory: a directory symlink would make `dst_dir/..`
    resolve through the link back to the source's parent (re-exposing a sibling
    like `ground_truth.yaml`), which is exactly the leak the agent surfaces
    exist to close. Real dirs keep `dst_dir/..` pointing at the staged parent.
    """
    src_dir = Path(src_dir)
    dst_dir = Path(dst_dir)
    if not src_dir.is_dir():
        return
    for child in sorted(src_dir.rglob("*")):
        target = dst_dir / child.relative_to(src_dir)
        if child.is_dir():
            target.mkdir(parents=True, exist_ok=True)
        elif child.is_file():
            _link_or_copy_file(child, target)


def stage_tables(src_run_dir: Path, dst_dir: Path, *, link: bool = False) -> None:
    """Copy the two live tables from one run dir into another.

    The queries table (`executed_queries.jsonl`, a flat file) plus the leads
    table + by-ref payloads (the `gather_raw/` tree). Both are best-effort: a
    query-less run has neither, which is a monitor case, not an error. This is
    the single definition of "what files constitute the tables on disk",
    shared by the learning-loop persist stage and the secondary-eval staging
    step so the two can't drift.

    `link=True` hardlinks (with a cross-filesystem copy fallback) instead of
    copying — used when staging a read-only agent surface, where dedup matters
    and the files are never mutated. The default `False` keeps the plain-copy
    semantics the persist / secondary-eval callers rely on.
    """
    src_run_dir = Path(src_run_dir)
    dst_dir = Path(dst_dir)
    dst_dir.mkdir(parents=True, exist_ok=True)
    ledger = src_run_dir / QUERIES_LOG
    gather_src = src_run_dir / GATHER_DIR
    if link:
        _link_or_copy_file(ledger, dst_dir / ledger.name)
        _link_or_copy_tree(gather_src, dst_dir / GATHER_DIR)
        return
    if ledger.is_file():
        shutil.copy2(ledger, dst_dir / ledger.name)
    if gather_src.is_dir():
        shutil.copytree(gather_src, dst_dir / GATHER_DIR, dirs_exist_ok=True)


# --------------------------------------------------------------------------
# Render helpers (stable, diff-reviewable text for prompt sections)
# --------------------------------------------------------------------------


def render_actor_view_yaml(run_dir: Path) -> str:
    """YAML text of `actor_view` — replaces the old `actor_input.yaml`."""
    return yaml.safe_dump(actor_view(run_dir), sort_keys=False)


def render_joined_yaml(run_dir: Path) -> str:
    """YAML text of the joined view — replaces the full `lead_sequence.yaml`
    block the judge consumes. Carries goal + what_to_summarize + the queries
    and their structural status, the authoritative record of what was queried
    per lead."""
    run_dir = Path(run_dir)
    doc = {
        "case_id": run_dir.name,
        "alert_ref": "alert.json",
        "leads": [
            {
                "lead_id": jl.lead_id,
                "goal": jl.goal,
                "what_to_summarize": jl.what_to_summarize,
                "queries": [
                    {
                        "query_id": q.query_id,
                        "params": q.params,
                        "payload_status": q.payload_status,
                        "payload_digest": q.payload_digest,
                    }
                    for q in jl.queries
                ],
            }
            for jl in joined(run_dir)
        ],
    }
    return yaml.safe_dump(doc, sort_keys=False)


# --------------------------------------------------------------------------
# Narration cross-check (run-level consistency, set-match — no doc-order)
# --------------------------------------------------------------------------


def narration_crosscheck(run_dir: Path, l_ids: set[str]) -> dict:
    """Set-match the table lead_ids against the `:L` row id set.

    - `missing_from_narration` — a table lead_id that is not a `:L` row id
      (a dispatched lead the narration forgot)  → WARN.
    - `queries_without_lead` — a query FK with no `*.lead.json` sidecar  → WARN.
    - `leads_without_queries` — a `:L`/lead id with zero queries  → MONITOR
      (likely a permission / tooling gap, not an error).
    - `ok` — True iff there are no WARN-class entries.

    Pure set comparison; no reliance on dispatch order.
    """
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
    """`narration_crosscheck` with the `:L` id set parsed from investigation.md."""
    run_dir = Path(run_dir)
    try:
        from defender.skills.invlang.parser import parse_dense_companion
    except ImportError:  # pragma: no cover — direct-script execution fallback
        import sys

        sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
        from skills.invlang.parser import parse_dense_companion  # type: ignore

    text = (run_dir / "investigation.md").read_text()
    companion, _ = parse_dense_companion(text)
    return narration_crosscheck(run_dir, _lead_ids_from_companion(companion))


def _lead_ids_from_companion(companion: dict) -> set[str]:
    """The `:L` row ids from a parsed companion, filtered to the lead-id grammar.

    The parser also surfaces `:R` resolution rows under `findings`, whose "id"
    is a comma-joined lead *reference* (e.g. `l-001,l-002,l-003`) — not a lead
    id. Filtering on the grammar keeps those out of the `:L` id set so the
    cross-check doesn't report a phantom lead.
    """
    return {
        f["id"]
        for f in companion.get("findings", [])
        if isinstance(f, dict) and isinstance(f.get("id"), str)
        and _LEAD_ID_RE.match(f["id"])
    }
