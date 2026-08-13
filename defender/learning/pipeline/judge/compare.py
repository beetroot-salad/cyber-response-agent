from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml

from defender._io import read_text_utf8
from defender._run_paths import RunPaths
from defender.learning import lead_repository


_RAW_SAMPLE_HEADER_RE = re.compile(r"^### Raw Sample Events\b.*$", re.MULTILINE)
_JSON_BLOCK_RE = re.compile(r"```json\s*\n(.*?)\n```", re.DOTALL)


def unredacted_exemplar(text: str) -> str:
    header_m = _RAW_SAMPLE_HEADER_RE.search(text)
    if not header_m:
        return "(no sample available for this lead)"
    block = text[header_m.start():]
    header_line = block.split("\n", 1)[0]
    json_m = _JSON_BLOCK_RE.search(block)
    if not json_m:
        return f"{header_line}\n(sample not in JSON form)"
    try:
        sample = json.loads(json_m.group(1))
    except json.JSONDecodeError:
        return f"{header_line}\n(could not parse sample as JSON)"
    if not sample:
        return "(sample block is empty; none for this lead)"
    return (
        f"{header_line} (real values — orientation only)\n\n"
        f"```json\n{json.dumps(sample, indent=2)}\n```"
    )


def real_sample_text(lead) -> str:
    """The judge's own evidence column. Moved out of the retired oracle package (#791): a
    learning run must import nothing from `defender.learning.pipeline.oracle`, and this is
    the one producer the surviving three-to-two cut still calls on every executed lead.

    The payload walk itself is `lead_repository`'s, shared with the oracle's scrubbed
    skeleton — the two differ only in the renderer and the two fallback strings."""
    return lead_repository.first_rendered_payload(
        lead, unredacted_exemplar,
        unreadable="(payload unreadable — {error}; the sample cannot be shown)",
        missing="(no sample available for this lead)",
    )


def _invlang():
    from defender.skills.invlang import _walkers as w
    from defender.skills.invlang import parser as p
    return p, w


def parse_investigation_companion(run_dir: Path) -> dict:
    inv = RunPaths(Path(run_dir)).investigation
    if not inv.is_file():
        return {}
    try:
        parser, _w = _invlang()
        companion, _warnings = parser.parse_dense_companion(read_text_utf8(inv))
        return companion if isinstance(companion, dict) else {}
    except Exception:  # noqa: BLE001 — degrade, never crash the judge step
        return {}




@dataclass(frozen=True)
class LeadComparison:

    lead_id: str
    goal: str | None
    orphan: bool
    queries: list
    real_sample: str
    resolutions: list = field(default_factory=list)
    authz: list = field(default_factory=list)
    note: str = ""


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
    *,
    companion: dict | None = None,
) -> list[LeadComparison]:
    """The judge's input set — the two surviving columns, exactly the leads the defender
    EXECUTED (#791: a lead the retired oracle merely projected no longer gets a row)."""
    run_dir = Path(run_dir)
    if companion is None:
        companion = parse_investigation_companion(run_dir)
    res_by_lead = _resolutions_by_lead(companion)
    authz_by_lead = _authz_by_lead(companion)

    out: list[LeadComparison] = []
    for jl in lead_repository.joined(run_dir):
        sample = real_sample_text(jl)
        note = "unreadable payload" if sample.startswith("(payload unreadable") else ""
        out.append(
            LeadComparison(
                lead_id=jl.lead_id,
                goal=jl.goal,
                orphan=jl.orphan,
                queries=list(jl.queries),
                real_sample=sample,
                resolutions=res_by_lead.get(jl.lead_id, []),
                authz=authz_by_lead.get(jl.lead_id, []),
                note=note,
            )
        )
    return out




def _yaml_or(obj, placeholder: str) -> str:
    if not obj:
        return placeholder
    return yaml.safe_dump(obj, sort_keys=False, allow_unicode=True).rstrip()


_LEAD_FS_UNSAFE = re.compile(r"[^A-Za-z0-9_-]")


def _safe_lead_filename(lead_id: str) -> str:
    """The comparison file's own name, chosen by the run's executed-queries table rather
    than by the actor or an author (#791) — the canonical raw-frame-escape chooser. Every
    character outside a plain filename alphabet is neutralized, so a `../`-shaped lead id
    cannot walk the write out of the comparison directory."""
    slug = _LEAD_FS_UNSAFE.sub("_", lead_id).strip("_.")
    return f"{slug or 'lead'}.md"


class _LeadFilenamer:
    """The ONE owner of the per-lead file names: the writer names the files through this and
    the manifest that tells the judge what to open names them through this too, so the two
    cannot disagree. Two independent spellings could — neutralizing `l-002.a` to `l-002_a.md`
    on disk while the manifest still advertised `l-002.a.md` pointed the judge at a file that
    does not exist, and two ids that neutralize alike silently overwrote one another.

    Stateful and consumed ONE lead at a time, never over a materialized list: the writer
    publishes each comparison file as it is produced, and pre-walking the sequence to
    allocate names would drain a lazily-produced one before the first file was written."""

    def __init__(self) -> None:
        self._used: set[str] = set()

    def name(self, lead_id: str) -> str:
        candidate = _safe_lead_filename(lead_id)
        if candidate in self._used:
            stem = candidate[: -len(".md")]
            n = 2
            while f"{stem}-{n}.md" in self._used:
                n += 1
            candidate = f"{stem}-{n}.md"
        self._used.add(candidate)
        return candidate


def _md_safe(text: str) -> str:
    """A run-chosen value, neutralized before it is interpolated into a raw markdown frame:
    no embedded heading marker, no embedded newline can reopen the frame with a heading of
    the injector's choosing.

    Call `_md_line` rather than this, and the claim below stays true by construction. #875 F-8:
    the docstring here USED to say "applies to EVERY interpolated span" while three of the
    seven spans were raw — `query_id` above all, which is the gather model's own string
    (`query_tool.resolve_query_id` returns it verbatim). A per-span opt-in is a claim about
    every future edit, and this one was already false when it was written."""
    return text.replace("\n", " ").replace("\r", " ").replace("#", "")


def _md_line(template: str, **spans: object) -> str:
    """One rendered markdown line whose EVERY interpolated span is neutralized.

    The unit of the guarantee is the LINE, not the value: a caller cannot interpolate through
    this and forget one, because there is no way to pass a span that skips `_md_safe`. That is
    the whole reason it exists — the opt-in it replaces drifted the moment a span was added
    (#875 F-8), and the next span added here inherits the neutralization without anyone
    remembering to ask for it.

    `template` is HOST text, never run-chosen — it carries the markdown structure, and the
    spans carry only values."""
    return template.format(**{k: _md_safe(str(v)) for k, v in spans.items()})


def _payload_paths(c: LeadComparison, gather_raw: Path) -> list[str]:
    paths = [str(q.raw_ref) for q in c.queries if q.raw_ref is not None]
    if paths:
        return paths
    if not c.queries:
        # #841 — a lead whose only rows are sentinels ran NO query, so it holds no payload.
        # The `0.json` fallback below is for a lead that ran queries whose rows carry no
        # payload path; firing it here would name the sentinel's OWN sidecar (written empty
        # by `runtime/tools.py` for `∅.bash-shim`) and put the refusal record back in front
        # of the judge by another door — under an absence instruction it cannot satisfy.
        return []
    # `_md_safe` on the lead id here too (#875 F-8): this string is interpolated into the
    # absence block's `> ` quote lines exactly like every other span, and the ONLY reason it
    # is not model-reachable today is that the dispatch seam holds `lead_id` to `_LEAD_ID_RE`.
    # That is a constraint one door over, not a property of this render.
    return [str(gather_raw / _md_safe(c.lead_id) / "0.json")]


def _render_lead_file(c: LeadComparison, gather_raw: Path) -> str:
    if c.note:
        head = _md_line("# Lead {id}  [{note}]", id=c.lead_id, note=c.note)
    elif c.orphan:
        head = _md_line("# Lead {id}  [orphan — query with no lead sidecar]", id=c.lead_id)
    elif c.goal:
        head = _md_line("# Lead {id} — {goal}", id=c.lead_id, goal=c.goal)
    else:
        head = _md_line("# Lead {id}", id=c.lead_id)

    # `params` rides `json.dumps` (which escapes its own newlines) and STILL goes through the
    # line builder: the point of #875 F-8 is that no span here is exempt by argument.
    q_lines = "\n".join(
        _md_line(
            "- {qid}  verb={verb}  params={params}  status={status}",
            qid=q.query_id, verb=q.verb, params=json.dumps(q.params or {}),
            status=q.payload_status,
        )
        for q in c.queries
    ) or "(no queries executed for this lead)"

    res = _yaml_or(c.resolutions, "(no belief-movement resolutions attributed to this lead)")
    authz = _yaml_or(c.authz, "(no authorization resolutions for this lead)")

    payloads = _payload_paths(c, gather_raw)
    if payloads:
        payload_lines = "".join(f">   {p}\n" for p in payloads)
        example = payloads[0]
        absence = (
            "> The sample is ONE event, for shape orientation. To assert that an entity is\n"
            "> ABSENT (the refute primitive), query the FULL payload — never infer absence\n"
            "> from the sample. `DESCRIBE data` first; defender-sql names the columns and the\n"
            "> right idiom for this payload's shape.\n"
            f"> This lead's payloads ({len(payloads)}); an absence claim must cover ALL of them:\n"
            f"{payload_lines}"
            f">   cat {example} | defender-sql \"DESCRIBE data\"\n"
            f">   cat {example} | defender-sql \"SELECT count(*) FROM (SELECT unnest(hits) h FROM data) WHERE h.<field> = '<value>'\"\n"
        )
    else:
        absence = (
            "> This lead executed no query, so it holds NO payload. There is nothing here to\n"
            "> search: no absence claim can be grounded in this lead, and its coverage gap is\n"
            "> the finding.\n"
        )

    return (
        f"{head}\n\n"
        "## Queries executed\n"
        f"{q_lines}\n\n"
        "## Evidence — sample event (orientation only)\n"
        f"{c.real_sample}\n\n"
        f"{absence}\n"
        "## Defender reasoning (invlang — the \"why\")\n"
        "### Belief movement (:T resolutions)\n"
        f"{res}\n\n"
        "### Authorization (:R authz)\n"
        f"{authz}\n"
    )


def write_comparison_files(
    comparisons: list[LeadComparison], out_dir: Path, gather_raw: Path
) -> list[Path]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    if not comparisons:
        # #791 R5: the empty comparison set is itself an observable state — an absence is
        # indistinguishable from a comparison step that never ran, so it is RECORDED rather
        # than left as a directory with nothing in it.
        (out_dir / "_empty.md").write_text(
            "(no leads were executed — the comparison set is empty)\n", encoding="utf-8"
        )
        return []
    paths: list[Path] = []
    namer = _LeadFilenamer()
    for c in comparisons:
        p = out_dir / namer.name(c.lead_id)
        p.write_text(_render_lead_file(c, Path(gather_raw)), encoding="utf-8")
        paths.append(p)
    return paths


def render_manifest(comparisons: list[LeadComparison]) -> str:
    if not comparisons:
        return "(no leads were executed — monitor case; nothing to compare)"
    lines = ["Read each per-lead comparison file at its turn:"]
    namer = _LeadFilenamer()
    for c in comparisons:
        name = namer.name(c.lead_id)
        flags = "anomaly" if (c.orphan or c.note) else "ok"
        label = (c.goal or "").strip().splitlines()[0] if c.goal else (c.note or ("orphan" if c.orphan else ""))
        lines.append(f"- {name}  [{flags}]  {_md_safe(label)}")
    return "\n".join(lines)


def _resolution_line(lid: str, r: dict) -> str:
    reasoning = (r.get("reasoning") or "").strip()
    return (
        f"- [{lid}] {r.get('hypothesis')}: {r.get('before')}->{r.get('after')}"
        f"  (severity={r.get('severity_of_test', '')})  {reasoning}"
    )


def render_synthesis(companion: dict) -> str:
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
