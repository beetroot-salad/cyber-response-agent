#!/usr/bin/env python3
"""Project lead_sequence.yaml from a defender run dir.

Reads investigation.md, walks the `:L findings` rows in dispatch order,
and emits {run_dir}/lead_sequence.yaml per
defender/lead_sequence_schema.md. The run dir is the path passed by
the caller (typically $DEFENDER_RUNS_BASE/{run_id}/, default
/tmp/defender-runs/{run_id}/).

Per defender/SKILL.md the investigation log is the source of truth: if
this script can't project a faithful sequence, the log is the bug, not
the schema. The script is intentionally strict and small — it parses
only what `:L findings` rows make structural and fails loudly when a
row is missing the cells the schema requires.

For the POC, `lead_description.goal` is taken from the `name` cell of
the `:L` row. `what_to_characterize` is left empty unless a per-lead
`gather_raw/{position}.lead.json` sidecar exists with a
`what_to_characterize` list — gather/SKILL.md may grow that contract
in a later batch; the projection script accepts it eagerly today.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path


L_BLOCK_RE = re.compile(
    r"^:L\s+findings\s+\[([^\]]+)\]\s*\n((?:^[^\n:`]+(?:\|.*)?$\n?)+)",
    re.MULTILINE,
)


def parse_l_rows(invlang_text: str) -> list[dict]:
    """Return :L findings rows in document order.

    Each row is a dict keyed by the cell names declared in the block
    header. Rows without an `id` cell are skipped (likely malformed).
    """
    rows: list[dict] = []
    for match in L_BLOCK_RE.finditer(invlang_text):
        header = [c.strip().rstrip("?") for c in match.group(1).split("|")]
        body = match.group(2)
        for line in body.splitlines():
            line = line.strip()
            if not line or line.startswith(":") or line.startswith("```"):
                continue
            cells = [c.strip() for c in line.split("|")]
            if len(cells) != len(header):
                continue
            row = dict(zip(header, cells))
            if not row.get("id"):
                continue
            rows.append(row)
    return rows


def parse_query_params(query_cell: str) -> dict:
    """Best-effort: split `k=v k=v` into a dict.

    Whitespace-separated `key=value` pairs is the convention in worked
    examples. Values containing spaces aren't supported by this shape
    yet — gather can quote them with a sentinel later if needed.
    """
    params: dict[str, str] = {}
    for tok in (query_cell or "").split():
        if "=" not in tok:
            continue
        k, _, v = tok.partition("=")
        params[k.strip()] = v.strip()
    return params


def load_lead_sidecar(run_dir: Path, position: int) -> dict | None:
    sidecar = run_dir / "gather_raw" / f"{position}.lead.json"
    if not sidecar.is_file():
        return None
    try:
        return json.loads(sidecar.read_text())
    except json.JSONDecodeError:
        return None


def project(run_dir: Path) -> dict:
    inv = run_dir / "investigation.md"
    if not inv.is_file():
        sys.exit(f"investigation.md not found in {run_dir}")

    rows = parse_l_rows(inv.read_text())
    if not rows:
        sys.exit(f"no :L findings rows parsed from {inv}")

    entries: list[dict] = []
    for position, row in enumerate(rows):
        system = row.get("system") or ""
        template = row.get("template") or ""
        if not system or not template:
            sys.exit(
                f":L row {row.get('id')} missing system/template cells; "
                "projection requires both"
            )
        query_id = f"{system}.{template}" if template != "ad-hoc" else "ad-hoc"
        params = parse_query_params(row.get("query") or "")
        if (window := row.get("window") or "").strip() not in ("", "n/a"):
            params.setdefault("window", window)

        sidecar = load_lead_sidecar(run_dir, position) or {}
        goal = sidecar.get("goal") or row.get("name") or row["id"]
        what_to_characterize = sidecar.get("what_to_characterize") or []

        entries.append({
            "position": position,
            "lead_description": {
                "goal": goal,
                "what_to_characterize": list(what_to_characterize),
            },
            "queries": [{"id": query_id, "params": params}],
            "result_ref": f"gather_raw/{position}.json",
        })

    return {
        "case_id": run_dir.name,
        "alert_ref": "alert.json",
        "entries": entries,
    }


def project_actor(doc: dict) -> dict:
    """Strip lead_description and result_ref for the actor projection.

    The actor sees only `position` + `queries[].id` + `queries[].params`
    per `defender/learning/actor.md` — what raw queries ran, nothing
    about defender intent or what was found. Reasoning about lead
    coverage is judge work; redacting at projection time enforces the
    split structurally.
    """
    return {
        "case_id": doc["case_id"],
        "alert_ref": doc["alert_ref"],
        "entries": [
            {
                "position": e["position"],
                "queries": [
                    {"id": q["id"], "params": q.get("params", {})}
                    for q in e["queries"]
                ],
            }
            for e in doc["entries"]
        ],
    }


def dump_actor_yaml(doc: dict) -> str:
    out: list[str] = []
    out.append(f"case_id: {doc['case_id']}")
    out.append(f"alert_ref: {doc['alert_ref']}")
    out.append("entries:")
    for entry in doc["entries"]:
        out.append(f"  - position: {entry['position']}")
        out.append("    queries:")
        for q in entry["queries"]:
            out.append(f"      - id: {q['id']}")
            if q["params"]:
                params_inline = ", ".join(
                    f"{k}: {_yaml_scalar(v)}" for k, v in q["params"].items()
                )
                out.append(f"        params: {{{params_inline}}}")
            else:
                out.append("        params: {}")
    return "\n".join(out) + "\n"


def dump_yaml(doc: dict) -> str:
    """Tiny YAML dumper covering the shape lead_sequence emits.

    Avoids a PyYAML dependency for a script that only writes one
    structurally-fixed document.
    """
    out: list[str] = []
    out.append(f"case_id: {doc['case_id']}")
    out.append(f"alert_ref: {doc['alert_ref']}")
    out.append("entries:")
    for entry in doc["entries"]:
        out.append(f"  - position: {entry['position']}")
        out.append("    lead_description:")
        out.append(f"      goal: {_yaml_scalar(entry['lead_description']['goal'])}")
        wtc = entry["lead_description"]["what_to_characterize"]
        if wtc:
            out.append("      what_to_characterize:")
            for item in wtc:
                out.append(f"        - {_yaml_scalar(item)}")
        else:
            out.append("      what_to_characterize: []")
        out.append("    queries:")
        for q in entry["queries"]:
            out.append(f"      - id: {q['id']}")
            if q["params"]:
                params_inline = ", ".join(
                    f"{k}: {_yaml_scalar(v)}" for k, v in q["params"].items()
                )
                out.append(f"        params: {{{params_inline}}}")
            else:
                out.append("        params: {}")
        out.append(f"    result_ref: {entry['result_ref']}")
    return "\n".join(out) + "\n"


def _yaml_scalar(value) -> str:
    s = str(value)
    if any(ch in s for ch in ":#{}[],&*!|>'\"%@`") or s != s.strip():
        return json.dumps(s)
    return s


def main(argv: list[str]) -> int:
    args = argv[1:]
    actor_out: Path | None = None
    positional: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--actor-out":
            if i + 1 >= len(args):
                print("--actor-out requires a path", file=sys.stderr)
                return 64
            actor_out = Path(args[i + 1]).resolve()
            i += 2
            continue
        positional.append(a)
        i += 1

    if len(positional) != 1:
        print(
            "usage: project_lead_sequence.py <run_dir> [--actor-out <path>]",
            file=sys.stderr,
        )
        return 64

    run_dir = Path(positional[0]).resolve()
    if not run_dir.is_dir():
        print(f"not a directory: {run_dir}", file=sys.stderr)
        return 1

    doc = project(run_dir)
    out = run_dir / "lead_sequence.yaml"
    out.write_text(dump_yaml(doc))
    print(f"wrote {out}")

    if actor_out is not None:
        actor_out.parent.mkdir(parents=True, exist_ok=True)
        actor_out.write_text(dump_actor_yaml(project_actor(doc)))
        print(f"wrote {actor_out}")

    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
