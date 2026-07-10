"""The comparison "zipper": ground the judge in actuals, lead by lead.

The judge used to score an encounter from the defender's *narrative*
(`investigation.md`, a lossy summary) plus the oracle projection — it never saw the
actual query results in `gather_raw/`. This module is the structural fix shared by both
directions (adversarial attack story and benign routine-operation story): a pure join
that, per lead, places three columns side by side —

  [1] the oracle's projection (what the actor's story *would* have produced),
  [2] a real sample event from the actual payload (orientation; the judge queries the
      full payload with defender-sql for absence-checks), and
  [3] the defender's own per-lead reasoning from the invlang (`:T resolutions` belief
      movement + `:R authz`) — the "why" behind its read of this lead —

into one `comparison/{lead_id}.md` file the judge reads one at a time. The cross-lead
synthesis (hypotheses + final weights + conclusion) is rendered separately as context.

Everything here is read-only over the run dir (it never crashes the judge step: every
column degrades to a labelled placeholder). The only write is `write_comparison_files`,
into the learning state dir. The judge's read-only tool scope (`cat … | defender-sql` and
`read_file` over the two add-dir'd payload trees, plus the benign closed-ticket matcher) is
the in-process gate's concern — see `judge/engine_pydantic.py`.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from defender._run_paths import RunPaths
from defender.learning import lead_repository
from defender.learning.pipeline.oracle.sample import real_sample_text


# ---------------------------------------------------------------------------
# invlang access (lazy — mirrors lead_repository.narration_crosscheck_from_run)
# ---------------------------------------------------------------------------


def _invlang():
    """Return (parser_module, walkers_module); lazily imported so the readers stay
    importable in minimal contexts (the only cross-package dependency)."""
    from defender.skills.invlang import _walkers as w
    from defender.skills.invlang import parser as p
    return p, w


def parse_investigation_companion(run_dir: Path) -> dict:
    """Parse the run's investigation.md into a companion dict, or `{}` on any failure.

    A parse failure must never abort the judge — the judge can still ground against
    the actuals via defender-sql; it just loses the defender's recorded reasoning.
    """
    inv = RunPaths(Path(run_dir)).investigation
    if not inv.is_file():
        return {}
    try:
        parser, _w = _invlang()
        companion, _warnings = parser.parse_dense_companion(inv.read_text())
        return companion if isinstance(companion, dict) else {}
    except Exception:  # noqa: BLE001 — degrade, never crash the judge step
        return {}


# ---------------------------------------------------------------------------
# Per-lead comparison record
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class LeadComparison:
    """One lead's three columns, joined by `lead_id`."""

    lead_id: str
    goal: str | None
    orphan: bool
    queries: list  # list[lead_repository.QueryRow]
    projected_events: list | None  # oracle events, [] (empty projection), or None (none emitted)
    real_sample: str
    resolutions: list = field(default_factory=list)  # per-lead :T resolutions rows
    authz: list = field(default_factory=list)  # per-lead :R authz rows
    note: str = ""  # anomaly annotation (e.g. a projection for a lead absent from the tables)


def _projection_index(projected_telemetry_path: Path) -> dict:
    """`{lead_id: events}` from the oracle doc, defensively (any failure → `{}`)."""
    try:
        doc = yaml.safe_load(Path(projected_telemetry_path).read_text())
    except Exception:  # noqa: BLE001
        return {}
    if not isinstance(doc, dict):
        return {}
    out: dict = {}
    for p in doc.get("projections") or []:
        if isinstance(p, dict) and "lead_id" in p:
            out[p["lead_id"]] = p.get("events", [])
    return out


def _resolutions_by_lead(companion: dict) -> dict:
    if not companion:
        return {}
    try:
        _p, w = _invlang()
    except Exception:  # noqa: BLE001
        return {}
    out: dict = {}
    for lid, res in w.iter_resolutions(companion):
        out.setdefault(lid, []).append(res)
    return out


def _authz_by_lead(companion: dict) -> dict:
    if not companion:
        return {}
    try:
        _p, w = _invlang()
    except Exception:  # noqa: BLE001
        return {}
    out: dict = {}
    for row in w.iter_authz_resolutions(companion):
        lid = row.get("resolved_by_lead")
        if lid:
            out.setdefault(lid, []).append(row)
    return out


def build_comparison(
    run_dir: Path,
    projected_telemetry_path: Path,
    *,
    companion: dict | None = None,
) -> list[LeadComparison]:
    """Join, per lead, the oracle projection + the real actual sample + the defender's
    per-lead invlang reasoning. Driven off `lead_repository.joined` (the authoritative,
    total coverage surface). Pure read-only; never raises on a partial/malformed run.
    """
    run_dir = Path(run_dir)
    if companion is None:
        companion = parse_investigation_companion(run_dir)
    proj = _projection_index(projected_telemetry_path)
    res_by_lead = _resolutions_by_lead(companion)
    authz_by_lead = _authz_by_lead(companion)

    out: list[LeadComparison] = []
    seen: set = set()
    for jl in lead_repository.joined(run_dir):
        seen.add(jl.lead_id)
        out.append(
            LeadComparison(
                lead_id=jl.lead_id,
                goal=jl.goal,
                orphan=jl.orphan,
                queries=list(jl.queries),
                projected_events=proj.get(jl.lead_id),  # None when no projection emitted
                real_sample=real_sample_text(jl),
                resolutions=res_by_lead.get(jl.lead_id, []),
                authz=authz_by_lead.get(jl.lead_id, []),
            )
        )
    # A projection for a lead the executed tables never recorded is anomalous (the
    # oracle projected against a lead the join doesn't know) — surface it, don't drop it.
    for lid in proj:
        if lid not in seen:
            out.append(
                LeadComparison(
                    lead_id=lid,
                    goal=None,
                    orphan=False,
                    queries=[],
                    projected_events=proj[lid],
                    real_sample="(no payload — lead absent from the executed tables)",
                    note="projection-only: lead absent from the executed tables",
                )
            )
    return out


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _yaml_or(obj, placeholder: str) -> str:
    if not obj:
        return placeholder
    return yaml.safe_dump(obj, sort_keys=False, allow_unicode=True).rstrip()


def _payload_paths(c: LeadComparison, gather_raw: Path) -> list[str]:
    """Every payload this lead actually wrote, absolute, in seq order — read off the
    queries table's `raw_ref` rather than assuming `{lead_id}/0.json`. A lead that ran
    N queries has `0.json … {N-1}.json`, and the judge cannot enumerate them itself
    (`ls` is denied, and a `*.json` glob is inert under the shell=False executor). An
    absence check over seq 0 alone is unsound the same way one over a `truncated`
    payload is — the entity may sit in a sibling seq."""
    paths = [str(q.raw_ref) for q in c.queries if q.raw_ref is not None]
    return paths or [str(gather_raw / c.lead_id / "0.json")]


def _render_lead_file(c: LeadComparison, gather_raw: Path) -> str:
    if c.note:
        head = f"# Lead {c.lead_id}  [{c.note}]"
    elif c.orphan:
        head = f"# Lead {c.lead_id}  [orphan — query with no lead sidecar]"
    elif c.goal:
        head = f"# Lead {c.lead_id} — {c.goal}"
    else:
        head = f"# Lead {c.lead_id}"

    q_lines = "\n".join(
        f"- {q.query_id}  params={json.dumps(q.params or {})}  status={q.payload_status}"
        for q in c.queries
    ) or "(no queries executed for this lead)"

    proj = (
        _yaml_or(c.projected_events, "(empty projection — the story does not touch this lead)")
        if c.projected_events is not None
        else "(no projection emitted for this lead)"
    )
    res = _yaml_or(c.resolutions, "(no belief-movement resolutions attributed to this lead)")
    authz = _yaml_or(c.authz, "(no authorization resolutions for this lead)")

    payloads = _payload_paths(c, gather_raw)
    payload_lines = "".join(f">   {p}\n" for p in payloads)
    example = payloads[0]

    return (
        f"{head}\n\n"
        "## Queries executed\n"
        f"{q_lines}\n\n"
        "## [1] Oracle projection — what the story would have produced if it were true\n"
        f"{proj}\n\n"
        "## [2] Actual evidence — sample event (orientation only)\n"
        f"{c.real_sample}\n\n"
        "> The sample is ONE event, for shape orientation. To assert that a projected\n"
        "> entity is ABSENT (the refute primitive), query the FULL payload — never infer\n"
        "> absence from the sample. `DESCRIBE data` first; defender-sql names the columns\n"
        "> and the right idiom for this payload's shape.\n"
        f"> This lead's payloads ({len(payloads)}); an absence claim must cover ALL of them:\n"
        f"{payload_lines}"
        f">   cat {example} | defender-sql \"DESCRIBE data\"\n"
        f">   cat {example} | defender-sql \"SELECT count(*) FROM (SELECT unnest(hits) h FROM data) WHERE h.<field> = '<value>'\"\n\n"
        "## [3] What the defender concluded about this lead (invlang — the \"why\")\n"
        "### Belief movement (:T resolutions)\n"
        f"{res}\n\n"
        "### Authorization (:R authz)\n"
        f"{authz}\n"
    )


def write_comparison_files(
    comparisons: list[LeadComparison], out_dir: Path, gather_raw: Path
) -> list[Path]:
    """Write one `{lead_id}.md` per comparison into `out_dir`; return the paths."""
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    paths: list[Path] = []
    for c in comparisons:
        p = out_dir / f"{c.lead_id}.md"
        p.write_text(_render_lead_file(c, Path(gather_raw)))
        paths.append(p)
    return paths


def render_manifest(comparisons: list[LeadComparison]) -> str:
    """Compact in-prompt list of the per-lead files to read, one at a time."""
    if not comparisons:
        return "(no leads were executed — monitor case; nothing to compare)"
    lines = ["Read each per-lead comparison file at its turn:"]
    for c in comparisons:
        if c.projected_events:
            tag = "has-projection"
        elif c.projected_events == []:
            tag = "empty-projection"
        else:
            tag = "no-projection"
        flags = tag + (", anomaly" if (c.orphan or c.note) else "")
        label = (c.goal or "").strip().splitlines()[0] if c.goal else (c.note or ("orphan" if c.orphan else ""))
        lines.append(f"- {c.lead_id}.md  [{flags}]  {label}")
    return "\n".join(lines)


def _resolution_line(lid: str, r: dict) -> str:
    reasoning = (r.get("reasoning") or "").strip()
    return (
        f"- [{lid}] {r.get('hypothesis')}: {r.get('before')}->{r.get('after')}"
        f"  (severity={r.get('severity_of_test', '')})  {reasoning}"
    )


def render_synthesis(companion: dict) -> str:
    """Cross-lead context: hypotheses + final weights, belief movement, authorization
    reasoning, and the conclusion — the WHY behind the defender's disposition."""
    if not companion:
        return "(no invlang reasoning parsed from investigation.md)"
    try:
        _p, w = _invlang()
    except Exception:  # noqa: BLE001
        return "(invlang walkers unavailable; reasoning not rendered)"

    parts: list[str] = []
    hyps = w.all_hypotheses(companion)
    fw = w.final_weights(companion)
    if hyps:
        hlines = [
            f"- {hid}: {h.get('name', '')}  final_weight={fw.get(hid)}"
            for hid, h in hyps.items()
        ]
        parts.append("## Hypotheses (final weights)\n" + "\n".join(hlines))

    res_rows = list(w.iter_resolutions(companion))
    if res_rows:
        parts.append(
            "## Belief movement (:T resolutions — the defender's evidence->weight inferences)\n"
            + "\n".join(_resolution_line(lid, r) for lid, r in res_rows)
        )

    authz_rows = list(w.iter_authz_resolutions(companion))
    if authz_rows:
        parts.append(
            "## Authorization reasoning (:R authz)\n"
            + "\n\n".join(
                yaml.safe_dump(a, sort_keys=False, allow_unicode=True).rstrip()
                for a in authz_rows
            )
        )

    conclude = companion.get("conclude") or {}
    parts.append(
        "## Conclusion (:T conclude)\n"
        + (
            yaml.safe_dump(conclude, sort_keys=False, allow_unicode=True).rstrip()
            if conclude
            else "(no conclusion recorded)"
        )
    )
    return "\n\n".join(parts)
