#!/usr/bin/env python3
"""Project a defender lead_sequence.yaml into the actor-facing schema.

Drops `lead_description`, `what_to_characterize`, `result_ref`. Keeps
only `position`, `queries[].id`, `queries[].params`. Top-level case_id
preserved for context; nothing else.

This enforces the gray-box contract specified in
`docs/learning-loop-actor-design.md`: the actor sees raw queries
verbatim and never sees synthesized fields that would leak defender
intent.
"""
import sys, yaml, pathlib

if len(sys.argv) < 2:
    sys.stderr.write("usage: project_lead_sequence.py <src.yaml> [<dst.yaml>]\n")
    sys.exit(2)

src = pathlib.Path(sys.argv[1])
dst = pathlib.Path(sys.argv[2]) if len(sys.argv) > 2 else None

raw = yaml.safe_load(src.read_text())
out = {"case_id": raw.get("case_id"), "entries": []}
for e in raw.get("entries", []):
    out["entries"].append({
        "position": e["position"],
        "queries": [
            {"id": q["id"], "params": q.get("params", {})}
            for q in e.get("queries", [])
        ],
    })
text = yaml.safe_dump(out, sort_keys=False, default_flow_style=False)
if dst:
    dst.write_text(text)
else:
    sys.stdout.write(text)
