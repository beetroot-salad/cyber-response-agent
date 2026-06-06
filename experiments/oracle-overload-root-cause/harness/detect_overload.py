"""Overload detector for old-oracle A/B projections.

#247's overload = an out-of-envelope event placed in a lead. The robust, defensible
signal: a projected event whose DATA SOURCE is not targeted by any query in that
position (e.g. a system.auth login emitted under a falco-only position), plus
state-only positions (cmdb/host-state) that emit events at all (they index no event
stream). Reports per-condition mean overloaded events across the 3 runs.
"""
import json
import re
import sys
from pathlib import Path

import yaml

RUN = Path("/tmp/defender-runs-v2/live-falco-nettool-1")
OUT = Path("/tmp/oracle-v2-probe")
ls = yaml.safe_load((RUN / "lead_sequence.yaml").read_text())

def index_to_source(idx):
    if not idx:
        return None
    idx = idx.replace("logs-", "").rstrip("-*.")
    return idx  # falco.alerts / system.auth / zeek.connection / zeek.ssh / elastic_agent / system.syslog

# position -> set of allowed data sources (None entry = a state/lookup query, no event stream)
pos_sources, pos_is_state_only = {}, {}
for e in ls["entries"]:
    p = e["position"]
    if p == 0:
        continue
    srcs, has_event_q = set(), False
    for q in e.get("queries") or []:
        qid = q.get("id", "")
        idx = q.get("params", {}).get("index")
        if qid.startswith(("cmdb.", "host-state.")):
            continue  # state lookup — no event stream
        s = index_to_source(idx)
        if s:
            srcs.add(s); has_event_q = True
        elif "ip-to-host" in qid or "host-agent-by-ip" in qid or "enrollment" in qid:
            srcs.add("elastic_agent"); has_event_q = True  # enrollment-ish lookups
    pos_sources[p] = srcs
    pos_is_state_only[p] = not has_event_q

def event_source(ev):
    if not isinstance(ev, dict):
        return None
    ds = ev.get("data_stream")
    if isinstance(ds, dict) and ds.get("dataset"):
        return ds["dataset"]
    evd = ev.get("event")
    if isinstance(evd, dict) and evd.get("dataset"):
        return evd["dataset"]
    blob = json.dumps(ev).lower()
    for tok, src in [("falco", "falco.alerts"), ("sshd", "system.auth"), ("accepted publickey", "system.auth"),
                     ("zeek", "zeek.connection"), ("enrollment", "elastic_agent")]:
        if tok in blob:
            return src
    return "unknown"

def extract_projections(jsonl):
    parts = []
    for line in Path(jsonl).read_text().splitlines():
        if not line.strip():
            continue
        try:
            o = json.loads(line)
        except Exception:
            continue
        if o.get("type") == "assistant":
            for b in o.get("message", {}).get("content", []):
                if b.get("type") == "text":
                    parts.append(b["text"])
    txt = "\n".join(parts).strip()
    if txt.startswith("```"):
        txt = re.sub(r"^```[a-z]*\n", "", txt).rsplit("```", 1)[0]
    try:
        return yaml.safe_load(txt).get("projections", [])
    except Exception as ex:
        return f"PARSE_ERR:{ex}"

def analyze(jsonl):
    projs = extract_projections(jsonl)
    if isinstance(projs, str):
        return None, projs
    total_ev = cross_src = state_fab = 0
    detail = []
    for pr in projs:
        p = pr.get("position")
        evs = pr.get("events") or []
        total_ev += len(evs)
        if pos_is_state_only.get(p) and evs:
            state_fab += len(evs)
            detail.append(f"  pos{p}: STATE-ONLY but emitted {len(evs)} event(s) [state-fabrication]")
        for ev in evs:
            src = event_source(ev)
            allowed = pos_sources.get(p, set())
            # match on data-source FAMILY (first token after stripping logs-): so
            # 'elastic_agent.internal' matches allowed 'elastic_agent', but 'cmdb.*'
            # (a lookup, not an event stream) matches nothing in an event lead.
            fam = lambda s: s.replace("logs-", "").split(".")[0] if s else s
            allowed_fams = {fam(a) for a in allowed}
            if not pos_is_state_only.get(p) and src != "unknown" and fam(src) not in allowed_fams:
                cross_src += 1
                detail.append(f"  pos{p}: event src={src} NOT IN {sorted(allowed)} [cross-source-smuggle]")
    return dict(total=total_ev, cross_src=cross_src, state_fab=state_fab,
                overload=cross_src + state_fab, detail=detail), None

print("position envelopes:", {p: (sorted(s) if not pos_is_state_only[p] else "STATE-ONLY") for p, s in pos_sources.items()})
print()
for cond in ("A", "B"):
    runs = sorted(glob_ := [str(f) for f in OUT.glob(f"old{cond}_*.jsonl")])
    print(f"=== Condition {cond} ({'original goal+timestamps' if cond=='A' else 'sanitized'}) ===")
    ov_list, tot_list, cs_list, sf_list = [], [], [], []
    for r in runs:
        res, err = analyze(r)
        if err:
            print(f"  {Path(r).name}: {err}"); continue
        ov_list.append(res["overload"]); tot_list.append(res["total"])
        cs_list = cs_list + [res["cross_src"]]; sf_list = sf_list + [res["state_fab"]]
        print(f"  {Path(r).name}: {res['total']} events | cross-source-smuggle={res['cross_src']} state-fabrication={res['state_fab']}")
        for d in res["detail"]:
            print(d)
    if ov_list:
        n=len(ov_list)
        print(f"  -> MEAN: cross-source-smuggle={sum(cs_list)/n:.1f}  state-fabrication={sum(sf_list)/n:.1f}  total-overload={sum(ov_list)/n:.1f}  (events {sum(tot_list)/n:.1f})")
    print()
