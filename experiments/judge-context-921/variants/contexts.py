"""The two context renderers — the ONE variable of this experiment.

`render_current` is the issue's premise: manifest + investigation document + report + queries
table + alert. `render_proposed` is that PLUS four host-rendered joined views (per-lead chain,
coverage against the discriminator and the sibling trials, lessons loaded, trial spread).
Nothing here calls a model.
"""
from __future__ import annotations

import json
import re
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, "/workspace")
from defender.skills.invlang import parser as invparser  # noqa: E402

RUNS_BASE = Path("/workspace/.defender-runs")
LESSONS = Path("/workspace/defender/lessons")
PAYLOAD_CAP = 6000


def _read(path: Path, cap: int | None = None) -> str:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as e:
        return f"(unreadable: {e})"
    if cap is not None and len(text) > cap:
        return text[:cap] + f"\n… (truncated: {len(text) - cap} more bytes)"
    return text


def _rows(run_dir: Path) -> list[dict]:
    path = run_dir / "executed_queries.jsonl"
    if not path.is_file():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def _fence(title: str, body: str, lang: str = "") -> str:
    return f"\n\n## {title}\n\n```{lang}\n{body.rstrip()}\n```\n"


# ---------------------------------------------------------------------------------------
# current
# ---------------------------------------------------------------------------------------

def render_current(run_dir: Path, family_path: Path) -> str:
    run_dir = Path(run_dir)
    parts = ["# JUDGE INPUT — world A (the capture itself)\n",
             f"Run: `{run_dir.name}`\n"]
    parts.append(_fence("FAMILY MANIFEST (family.yaml)", _read(family_path), "yaml"))
    parts.append(_fence("ALERT (alert.json)", _read(run_dir / "alert.json"), "json"))
    parts.append(_fence("INVESTIGATION DOCUMENT (investigation.md)", _read(run_dir / "investigation.md"), "markdown"))
    parts.append(_fence("REPORT (report.md)", _read(run_dir / "report.md"), "markdown"))
    rows = _rows(run_dir)
    table = "\n".join(json.dumps({k: v for k, v in r.items() if k not in ("payload_sha256", "payload_digest")}) for r in rows)
    parts.append(_fence("QUERIES TABLE (executed_queries.jsonl, as recorded)", table, "jsonl"))
    return "".join(parts)


# ---------------------------------------------------------------------------------------
# proposed: the four joined views
# ---------------------------------------------------------------------------------------

_FROM_RE = re.compile(r"\bFROM\s+([^\s|]+)", re.IGNORECASE)


def _index_of(row: dict) -> str:
    p = row.get("params") or {}
    if row.get("system") == "elastic":
        if isinstance(p.get("index"), str):
            return p["index"]
        q = p.get("query") or p.get("native_query") or ""
        m = _FROM_RE.search(q) if isinstance(q, str) else None
        return m.group(1) if m else "(no index)"
    return str(row.get("query_id") or "")


def _scope_of(row: dict) -> str:
    p = row.get("params") or {}
    for k in ("host", "hostname", "user", "container_id", "q", "ip", "account"):
        if k in p and p[k] not in (None, ""):
            return f"{k}={p[k]}"
    return ""


def _companion(run_dir: Path) -> dict:
    text = _read(run_dir / "investigation.md")
    try:
        comp, _warn = invparser.parse_dense_companion(text)
        return comp if isinstance(comp, dict) else {}
    except Exception as e:  # noqa: BLE001 — a corrupt document is itself a finding
        return {"_parse_error": repr(e)}


def _per_lead_chain(run_dir: Path) -> str:
    comp = _companion(run_dir)
    findings = {f.get("id"): f for f in comp.get("findings", []) if isinstance(f, dict)}
    rows_by_lead: dict[str, list[dict]] = defaultdict(list)
    for r in _rows(run_dir):
        rows_by_lead[r.get("lead_id", "?")].append(r)
    out = ["\n\n## VIEW 1 — PER-LEAD CHAIN (goal → queries → raw payloads → summary the main agent received → what the document made of it)\n",
           "Each lead is one gather sub-agent. The MAIN agent never sees raw payloads; it sees only the summary. "
           "Payloads are shown here exactly as recorded under gather_raw/ (capped per row). An EMPTY payload file is shown as such.\n"]
    if "_parse_error" in comp:
        out.append(f"\n(companion parse error on investigation.md: {comp['_parse_error']})\n")
    lead_ids = sorted(set(rows_by_lead) | set(findings))
    for lid in lead_ids:
        out.append(f"\n### {lid}\n")
        lead_json = run_dir / "gather_raw" / f"{lid}.lead.json"
        if lead_json.is_file():
            try:
                lj = json.loads(lead_json.read_text(encoding="utf-8"))
                out.append(f"- goal: {lj.get('goal')}\n- what_to_summarize: {json.dumps(lj.get('what_to_summarize'))}\n")
            except json.JSONDecodeError:
                out.append("- (lead.json unparseable)\n")
        f = findings.get(lid) or {}
        if f:
            out.append(f"- declared in document: name={f.get('name')!r} loop={f.get('loop')} system={f.get('system') or (f.get('query_details') or {}).get('system')} tests={f.get('tests_hypotheses')} window={(f.get('query_details') or {}).get('time_window')}\n")
        for r in sorted(rows_by_lead.get(lid, []), key=lambda r: r.get("seq", 0)):
            out.append(f"\n#### query {lid}/{r.get('seq')} — {r.get('system')}.{r.get('verb')} ({r.get('query_id')}) status={r.get('payload_status')} exit={r.get('exit_code')} error_class={r.get('error_class')}\n")
            out.append("params: " + json.dumps(r.get("params"))[:1500] + "\n")
            ppath = r.get("payload_path")
            pfile = (run_dir / ppath) if ppath else None
            if pfile is None or not pfile.is_file():
                out.append("payload: (no payload file recorded)\n")
            elif pfile.stat().st_size == 0:
                out.append(f"payload: FILE IS EMPTY (0 bytes) — the error text, if any, was never recorded; status={r.get('payload_status')} error_class={r.get('error_class')}\n")
            else:
                out.append("payload:\n```json\n" + _read(pfile, PAYLOAD_CAP) + "\n```\n")
        summ = run_dir / "gather_summaries" / f"{lid}.md"
        if summ.is_file():
            out.append("\n#### summary the main agent received\n```markdown\n" + _read(summ, 8000) + "\n```\n")
        else:
            out.append("\n#### summary the main agent received: (none on disk)\n")
        if f:
            oc = f.get("outcome") or {}
            obs = oc.get("observations") or {}
            out.append("\n#### what the document made of this lead\n")
            for v in obs.get("vertices", []) or []:
                out.append(f"- vertex {v.get('id')}: type={v.get('type')} class={v.get('classification')} ident={v.get('identifier')} attrs={json.dumps(v.get('attributes'))}\n")
            for e in obs.get("edges", []) or []:
                out.append(f"- edge {e.get('id')}: {e.get('source_vertex')} -{e.get('relation')}-> {e.get('target_vertex')} when={json.dumps(e.get('when'))} authority={json.dumps(e.get('authority'))} attrs={json.dumps(e.get('attributes'))}\n")
            for au in oc.get("attribute_updates", []) or []:
                out.append(f"- attr_update: target={au.get('target')} updates={json.dumps(au.get('updates'))}\n")
            for az in oc.get("authorization_resolutions", []) or []:
                out.append(f"- authz resolution: {json.dumps(az)}\n")
            for res in f.get("resolutions", []) or []:
                out.append(f"- resolution: {res.get('hypothesis_id')} {res.get('before')} → {res.get('after')} severity={res.get('severity_of_test')} edges={res.get('supporting_edges')} preds={res.get('matched_prediction_ids')} refuts={res.get('matched_refutation_ids')} :: {res.get('reasoning')}\n")
            if oc.get("failure_reason"):
                out.append(f"- failure_reason: {oc.get('failure_reason')}\n")
    return "".join(out)


def _sibling_trials(run_dir: Path) -> list[Path]:
    try:
        alert_id = json.loads((run_dir / "alert.json").read_text(encoding="utf-8")).get("alert_id")
    except (OSError, ValueError):
        return []
    out = []
    for d in sorted(RUNS_BASE.iterdir()):
        if not d.is_dir() or d == run_dir or not (d / "alert.json").is_file() or not (d / "report.md").is_file():
            continue
        try:
            if json.loads((d / "alert.json").read_text(encoding="utf-8")).get("alert_id") == alert_id:
                out.append(d)
        except (OSError, ValueError):
            continue
    return out


def _coverage(run_dir: Path, family_path: Path) -> str:
    import yaml
    fam = yaml.safe_load(_read(family_path)) or {}
    disc = fam.get("discriminator") or {}
    hold = disc.get("holding_system")
    env = disc.get("envelope") or {}
    rows = _rows(run_dir)
    issued = sorted({(r.get("system"), r.get("verb"), _index_of(r), _scope_of(r)) for r in rows})
    out = ["\n\n## VIEW 2 — COVERAGE (what this run asked, against the discriminator and against what the sibling trials of the same alert asked)\n"]
    out.append(f"\nDiscriminator holding_system: `{hold}`; envelope: `{json.dumps(env)}`\n")
    touched = [i for i in issued if i[0] == hold]
    out.append(f"This run issued {len(touched)} call(s) on the holding system" + (":\n" if touched else " — **the holding system was never queried**.\n"))
    for s, v, idx, scope in touched:
        out.append(f"- {s}.{v} {idx} {scope}\n")
    out.append("\n### This run, every (system, verb, index-or-template, scope) issued\n")
    for s, v, idx, scope in issued:
        out.append(f"- {s}.{v} {idx} {scope}\n")
    sibs = _sibling_trials(run_dir)
    union: Counter = Counter()
    example: dict = {}
    for d in sibs:
        seen = set()
        for r in _rows(d):
            key = (r.get("system"), r.get("verb"), _index_of(r))
            if key in seen:
                continue
            seen.add(key)
            union[key] += 1
            example.setdefault(key, (d.name, _scope_of(r)))
    mine = {(s, v, idx) for s, v, idx, _ in issued}
    out.append(f"\n### What was askable: (system, verb, index-or-template) issued by the {len(sibs)} other trials of this same alert, with how many trials issued it. Rows this run did NOT issue are marked ←\n")
    for key, n in sorted(union.items(), key=lambda kv: (-kv[1], kv[0])):
        s, v, idx = key
        mark = "" if key in mine else "   ← not issued by this run"
        out.append(f"- {s}.{v} {idx} — {n} trial(s) (e.g. {example[key][0]} {example[key][1]}){mark}\n")
    return "".join(out)


def _lessons(run_dir: Path) -> str:
    path = run_dir / "lessons_loaded.jsonl"
    out = ["\n\n## VIEW 3 — LESSONS LOADED INTO THIS RUN (name, when, and the lesson body)\n"]
    if not path.is_file():
        out.append("(none recorded)\n")
        return "".join(out)
    when: dict[str, list[str]] = defaultdict(list)
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                r = json.loads(line)
                when[r.get("lesson_name")].append(r.get("ts", ""))
            except json.JSONDecodeError:
                pass
    for name, stamps in when.items():
        body = LESSONS / f"{name}.md"
        out.append(f"\n### {name} — loaded {len(stamps)}× at {', '.join(s[11:19] for s in stamps)}\n")
        out.append("```markdown\n" + (_read(body, 5000) if body.is_file() else "(lesson file not found)") + "\n```\n")
    return "".join(out)


def _spread(run_dir: Path) -> str:
    sibs = _sibling_trials(run_dir)
    out = [f"\n\n## VIEW 4 — TRIAL SPREAD: {len(sibs) + 1} finished trials of THIS SAME ALERT on disk (this run included)\n",
           "Each line: run id | disposition | termination | systems touched | one-line summary\n\n"]
    def line(d: Path, me: bool) -> str:
        rep = _read(d / "report.md")
        disp = re.search(r"^disposition:\s*(\S+)", rep, re.M)
        inv = _read(d / "investigation.md")
        cat = re.search(r"termination\.category\s+(\S+)", inv)
        summ = re.search(r'^summary\s+"?(.{0,240})', inv, re.M)
        systems = sorted({r.get("system") for r in _rows(d)})
        return (f"- {'**' if me else ''}{d.name}{' (this run)**' if me else ''} | {disp.group(1) if disp else '?'} | "
                f"{cat.group(1) if cat else '?'} | {','.join(s for s in systems if s)} | {(summ.group(1) if summ else '(no summary)').strip()}\n")
    out.append(line(run_dir, True))
    dispositions = Counter()
    for d in sibs:
        out.append(line(d, False))
        rep = _read(d / "report.md")
        m = re.search(r"^disposition:\s*(\S+)", rep, re.M)
        dispositions[m.group(1) if m else "?"] += 1
    rep = _read(run_dir / "report.md")
    m = re.search(r"^disposition:\s*(\S+)", rep, re.M)
    dispositions[m.group(1) if m else "?"] += 1
    out.append("\nDisposition counts across all trials: " + ", ".join(f"{k}={v}" for k, v in dispositions.most_common()) + "\n")
    return "".join(out)


def render_proposed(run_dir: Path, family_path: Path) -> str:
    run_dir = Path(run_dir)
    return (render_current(run_dir, family_path)
            + "\n\n# JOINED VIEWS (host-rendered from the same artifacts; nothing below was written by a model except the quoted summaries and lessons)\n"
            + _per_lead_chain(run_dir)
            + _coverage(run_dir, family_path)
            + _lessons(run_dir)
            + _spread(run_dir))


RENDERERS = {"current": render_current, "proposed": render_proposed}
