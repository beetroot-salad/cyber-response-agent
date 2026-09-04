#!/usr/bin/env python3
"""Fire the real questioner over the fresh-alert run at branch message 32, standalone.

Replicates the launcher's step 2 (`cli.py` "Step 2: the questioner authors the triplet")
without priming a base, staging a corpus or running siblings: the experiment needs the
discriminator and the worlds, not an episode. Leads are filtered to those HELD at the branch
point (`_frontier.leads_at`), which is what the design says the questioner is shown.
"""
from __future__ import annotations
import json
import sys
from pathlib import Path
sys.path.insert(0, "/workspace")
from defender.learning.branch import cli as launcher
from defender.learning.branch import questioner as qmod
from defender.learning.branch.seams import model_seam
from defender.learning.lead_repository import joined
from defender.runtime import session_store as ss
from defender.runtime.branch import _frontier
from defender.runtime.branch._family import check_identities, parse_family, write_family

import argparse
_ap = argparse.ArgumentParser()
_ap.add_argument("--source", default="/workspace/.defender-runs/20260830T100154Z-fresh-alert-input")
_ap.add_argument("--n", type=int, default=32)
_ap.add_argument("--out", default=str(Path(__file__).resolve().parent / "family" / "episode"))
_ns = _ap.parse_args()
SOURCE = Path(_ns.source)
N = _ns.n
EP = Path(_ns.out)
CONT = ("Continue the investigation from where it stands. Dispatch whatever leads the "
        "frontier warrants, then close.")

def main() -> int:
    EP.mkdir(parents=True, exist_ok=True)
    as_of = launcher.branch_point_clock(SOURCE, N)
    fences = launcher._fence_count(SOURCE, N, continuation_prompt=CONT, as_of=as_of)
    store = ss.open_store_for_read(ss.resolve_store_path(SOURCE))
    sid = ss.resolve_session_id(SOURCE) or ss.main_session_id(store)
    held = _frontier.leads_at(store, sid, N, SOURCE)
    store.close()
    all_leads = launcher._joined_leads(SOURCE, joined)
    leads = [lead for lead in all_leads if lead.get("lead_id") in held]
    print(f"as_of={as_of} fences_at={fences} leads_held={sorted(held)} of {len(all_leads)}")
    (EP / "inputs.json").write_text(json.dumps({
        "as_of": str(as_of), "fences_at": fences, "leads_held": sorted(held)}, indent=2))
    raw_invoke = model_seam(EP)

    def invoke(prompt: str, *, role=None, agent_id: str = "questioner") -> str:
        # Kimi K3 wraps its YAML in a ```yaml fence; the shipped `_reply_document` refuses that
        # (observed 2026-09-02, first attempt). Strip an outer fence, leave everything else.
        reply = raw_invoke(prompt, role=role, agent_id=agent_id)
        (EP / f"{agent_id.replace(':', '_')}.reply.txt").write_text(reply, encoding="utf-8")
        import re as _re
        blocks = _re.findall(r"```(?:yaml|yml|json)?\s*\n(.*?)```", reply, _re.S)
        # A K3 reply carries prose reasoning first and the document in a fence after it; the
        # document is the LAST fenced block (earlier ones, when present, are quoted examples).
        stripped = blocks[-1].strip() if blocks else reply.strip()
        return stripped

    doc = qmod.author_family(
        source_run_dir=SOURCE, episode_dir=EP, invoke=invoke, leads=leads,
        alert=launcher._alert_document(SOURCE),
        frontier=qmod.read_frontier(SOURCE, fences_at=fences))
    episode_id = launcher.episode_id_for(SOURCE.name, N)
    doc.update({
        "episode_id": episode_id, "source_run_dir": str(SOURCE), "source_run_id": SOURCE.name,
        "branch_message_id": N, "fences_at": fences,
        "as_of": as_of.isoformat().replace("+00:00", "Z"), "continuation_prompt": CONT,
    })
    (EP / "family.raw.json").write_text(json.dumps(doc, indent=2, default=str))
    # Manifest corrections the first family needed (recorded, not hidden): hyphenated world
    # ids (identity gate refuses '-'), overlay.elastic authored as a list (schema wants a
    # mapping keyed by base pattern). Captured patterns come from the source's own query table.
    import re as _re
    lines = (SOURCE / "executed_queries.jsonl").read_text().splitlines()
    rows = [json.loads(line) for line in lines if line.strip()]
    pats = set()
    for r in rows:
        p = r.get("params") or {}
        q = p.get("query") or ""
        m = _re.search(r"FROM\s+([^\s|]+)", q) if isinstance(q, str) else None
        if m:
            pats.add(m.group(1))
        if isinstance(p.get("index"), str):
            pats.add(p["index"])
    corrections = []
    for w in doc["worlds"]:
        if "-" in w["world_id"]:
            new = w["world_id"].replace("-", "_")
            corrections.append(f"world id {w['world_id']!r} -> {new!r}")
            w["world_id"] = new
        ov = w.get("overlay") or {}
        el = ov.get("elastic")
        if isinstance(el, list):
            mapping = {}
            for entry in el:
                pat = entry.get("base_pattern") or entry.get("pattern")
                mapping[pat] = {"inject": [e.get("document", e) for e in entry.get("inject", [])], "exclude": entry.get("exclude")}
            ov["elastic"] = mapping
            corrections.append(f"world {w['world_id']}: overlay.elastic list->mapping")
        w["overlay"] = ov
    family = parse_family(doc, captured_patterns=tuple(sorted(pats)))
    check_identities(family)
    path = write_family(EP, doc)
    inp = json.loads((EP / "inputs.json").read_text())
    inp["harness_corrections"] = corrections
    inp["captured_patterns"] = sorted(pats)
    (EP / "inputs.json").write_text(json.dumps(inp, indent=2))
    print(f"wrote {path}")
    print("discriminator:", json.dumps(family.discriminator, indent=2))
    for w in family.worlds:
        print(f"world {w.world_id} role={w.role} axis={w.axis!r} declared={w.disposition_declared} touches={w.touches}")
    return 0

if __name__ == "__main__":
    sys.exit(main())
