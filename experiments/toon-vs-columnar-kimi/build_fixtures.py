"""Sample fixtures from the recorded corpus and generate mechanical ground-truth Q/A.

Recorded payloads predate #842, so they carry dict rows. Each is reconstituted into the raw
wire response and pushed back through the REAL `esql_payload`, so the `current` arm is
production-shaped rather than hand-rolled.
"""

from __future__ import annotations

import json
import random
import sys
from pathlib import Path

sys.path.insert(0, "/workspace")

import toons  # noqa: E402

from defender.scripts.adapters.elastic_adapter import esql_payload  # noqa: E402
from defender.scripts.gather_tools.payload_view import passthrough_max_bytes  # noqa: E402

HERE = Path(__file__).parent
CEILING = passthrough_max_bytes()
rng = random.Random(834)


def columnar(rec: dict) -> dict | None:
    """Recorded dict-row payload -> production columnar payload, via the real adapter."""
    cols = rec.get("columns") or []
    names = [c.get("name") for c in cols]
    rows = rec.get("values") or []
    if not rows or not isinstance(rows[0], dict) or not names:
        return None
    if any(list(r.keys()) != names for r in rows):  # #842's census says this holds; verify
        return None
    resp = {"columns": cols, "values": [[r[n] for n in names] for r in rows]}
    return esql_payload(rec.get("query", ""), resp)


def toon_input(payload: dict) -> dict:
    """The TOON arm's encoder input.

    TOON's tabular form (SPEC §9.3) requires an array of OBJECTS with identical key sets. Our
    production payload is array-of-arrays, so the dicts #842 deleted must be materialized again
    — transiently, as encoder input — for TOON to re-flatten them into `values[N]{cols}:`.
    Nothing is persisted; disk stays columnar (#834 constraint N2).
    """
    names = [c.get("name") for c in payload["columns"]]
    return {**payload, "values": [dict(zip(names, row, strict=False)) for row in payload["values"]]}


def is_tabular(payload: dict) -> bool:
    out = toons.dumps(toon_input(payload))
    for line in out.splitlines():
        if line.lstrip().startswith("values["):
            return "{" in line
    return False


def _scalar(v) -> bool:
    return v is not None and not isinstance(v, (list, dict))


def questions(payload: dict) -> list[dict]:
    """Mechanical Q/A — answers computed from the data, never adjudicated."""
    names = [c.get("name") for c in payload["columns"]]
    rows = payload["values"]
    out: list[dict] = []

    # 1. cell lookup (the misbinding probe): a key whose value is UNIQUE, target another column
    if len(rows) >= 2 and len(names) >= 2:
        for _ in range(60):
            ki, ci = rng.randrange(len(names)), rng.randrange(len(names))
            ri = rng.randrange(len(rows))
            if ki == ci:
                continue
            kv, cv = rows[ri][ki], rows[ri][ci]
            if not (_scalar(kv) and _scalar(cv)):
                continue
            if sum(1 for r in rows if r[ki] == kv) != 1:
                continue
            out.append({
                "kind": "cell_lookup",
                "q": f"In the row where {names[ki]} is {kv!r}, what is the value of {names[ci]}?",
                "a": cv,
            })
            break

    # 2. arity
    out.append({"kind": "arity", "q": "How many rows does this payload contain?",
                "a": payload["row_count"]})

    # 3. extremum over a numeric column, labelled by another
    numeric = [i for i, _ in enumerate(names)
               if sum(1 for r in rows if isinstance(r[i], (int, float))
                      and not isinstance(r[i], bool)) == len(rows) and len(rows) >= 2]
    labels = [i for i, _ in enumerate(names)
              if all(isinstance(r[i], str) for r in rows) and len({r[i] for r in rows}) == len(rows)]
    if numeric and labels:
        ci, ki = numeric[0], labels[0]
        best = max(rows, key=lambda r: r[ci])
        out.append({
            "kind": "extremum",
            "q": f"Which {names[ki]} has the largest {names[ci]}?",
            "a": best[ki],
        })
    return out


def main() -> None:
    recs = []
    for p in sorted(Path("/tmp/defender-runs").glob("*/gather_raw/*/*.json")):
        try:
            rec = json.loads(p.read_text())
        except Exception:
            continue
        if not (isinstance(rec, dict) and "columns" in rec and isinstance(rec.get("values"), list)):
            continue
        pay = columnar(rec)
        if pay is None:
            continue
        text = json.dumps(pay)
        recs.append({
            "src": str(p), "payload": pay, "bytes": len(text),
            "rows": pay["row_count"], "cols": len(pay["columns"]),
            "under_ceiling": len(text) <= CEILING, "tabular": is_tabular(pay),
        })

    total = len(recs)
    elig = [r for r in recs if r["under_ceiling"] and r["tabular"]]
    print(f"dict-row ES|QL payloads      : {total}")
    print(f"  under {CEILING}B ceiling         : {sum(r['under_ceiling'] for r in recs)}")
    print(f"  TOON tabular-eligible      : {sum(r['tabular'] for r in recs)}")
    print(f"  BOTH (fixture pool)        : {len(elig)}")
    over_tab = [r for r in recs if r["tabular"] and not r["under_ceiling"]]
    if over_tab:
        w = max(over_tab, key=lambda r: r["cols"])
        print(f"  EXCLUDED over-ceiling      : {len(over_tab)} "
              f"(widest: {w['cols']} cols / {w['rows']} rows / {w['bytes']}B)")

    # stratified by row count, then sample
    elig.sort(key=lambda r: (r["rows"], r["cols"]))
    picks, seen = [], set()
    for r in elig:
        if len(r["payload"]["values"]) < 2:
            continue
        qs = questions(r["payload"])
        if not any(q["kind"] == "cell_lookup" for q in qs):
            continue
        key = (r["rows"], r["cols"])
        if key in seen:
            continue
        seen.add(key)
        picks.append({**r, "questions": qs})
    rng.shuffle(picks)
    picks = picks[:40]

    fx = HERE / "fixtures"
    fx.mkdir(exist_ok=True)
    for i, r in enumerate(picks):
        (fx / f"fx-{i:02d}.json").write_text(json.dumps({
            "src": r["src"], "rows": r["rows"], "cols": r["cols"], "bytes": r["bytes"],
            "payload": r["payload"], "questions": r["questions"],
        }, indent=2))
    kinds: dict[str, int] = {}
    for r in picks:
        for q in r["questions"]:
            kinds[q["kind"]] = kinds.get(q["kind"], 0) + 1
    print(f"\nfixtures written: {len(picks)}  questions: {kinds}")
    print(f"row-count range: {min(r['rows'] for r in picks)}–{max(r['rows'] for r in picks)}, "
          f"cols: {min(r['cols'] for r in picks)}–{max(r['cols'] for r in picks)}")


if __name__ == "__main__":
    main()
