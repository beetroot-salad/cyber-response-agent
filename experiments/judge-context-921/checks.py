"""Mechanical checks over one judge reply — handed to the grader as CONTEXT, never as verdict.

Regex hits per reference finding (frozen 2026-09-02 before scale-up), and per-pointer
grounding: does each artifact the judge cites exist in the fixture?
"""
from __future__ import annotations
import json, re, sys
from pathlib import Path
import yaml
sys.path.insert(0, "/workspace"); sys.path.insert(0, str(Path(__file__).resolve().parent / "variants"))
import contexts  # noqa: E402

PATTERNS = {
    "R1": [r"logs-system\.auth", r"auth[\s-]?(log|index)", r"\bsshd?\b", r"ssh (login|session|auth)",
           r"\baccepted\b", r"process (parent|tree|audit|ancestry)", r"parent process", r"proc[-_ ]?tree",
           r"entrypoint", r"role-start", r"who (ran|executed|drove)", r"entry[- ]?point",
           r"behavioral-anomaly-needs-affirmative-explanation", r"source-ip-check-auth-log",
           r"scheduler|cron|automation artifact|interactive (session|login)"],
    "R2": [r"\bdb-1\b", r"wrong (host|scope|asset|key|entity)", r"reconcil", r"inventory", r"list-hosts",
           r"list-all-hosts", r"team\.data", r"change[_ ]window", r"sat(urday)? 04", r"docker host",
           r"host\.name", r"container (name|was named|is named)"],
    "R3": [r"summar(y|ies)", r"aug(ust)?\.?\s*(17|22)", r"2026-08-(17|22)", r"(eight|8)[- ]days?", r"silen",
           r"\bgap\b", r"stopp?ed|ceased|ended", r"\bempty\b", r"0 bytes", r"\b404\b", r"paraphras",
           r"</parameter>|</invoke>", r"markup|leak", r"not (traceable|recorded|captured)",
           r"cadence", r"1[–-]3 days"],
}
EXPECTED_BUCKET = {"R1": "lead-set", "R2": "lead-quality", "R3": "analyze-discipline"}

_POINTER_RES = [
    (r"\bl-\d{3}/\d+\b", "query_row"), (r"\bl-\d{3}\b", "lead"),
    (r"gather_raw/[\w./-]+", "path"), (r"gather_summaries/[\w./-]+", "path"),
    (r"\b[veh]-\d{3}\b", "invlang_id"), (r"\bac\d\b|\bp\d\b|\br\d\b", "invlang_local_id"),
    (r"\b(investigation\.md|report\.md|executed_queries\.jsonl|alert\.json|family\.yaml|lessons_loaded\.jsonl)\b", "file"),
]


def _text(f: dict) -> str:
    return " ".join([str(f.get("claim", "")), str(f.get("root_cause", "")), " ".join(map(str, f.get("evidence") or []))])


def _lenient(text: str) -> dict:
    """Parse the judge's fixed shape without a YAML parser.

    K3 leaves colons unquoted inside `claim:` / `root_cause:` scalars ("entry is human-initiated,"
    ... `:T resolutions`), which `yaml.safe_load` refuses whole. The grader reads the raw text and
    grades anyway; the mechanical hints must not vanish on the same defect.
    """
    doc: dict = {"_lenient": True}
    m = re.search(r"^episode_outcome:\s*(.+)$", text, re.M)
    doc["episode_outcome"] = m.group(1).strip() if m else None
    m = re.search(r"^noise_floor_note:\s*(.*?)(?=^findings:|\Z)", text, re.S | re.M)
    doc["noise_floor_note"] = " ".join(m.group(1).split()) if m else None
    start = text.find("findings:")
    body = text[start:] if start != -1 else text
    findings = []
    for part in re.split(r"^(?=\s*-\s+bucket:)", body, flags=re.M):
        if not re.match(r"\s*-\s+bucket:", part):
            continue
        f: dict = {}
        m = re.search(r"bucket:\s*(\S+)", part)
        f["bucket"] = m.group(1).strip("'\"") if m else None
        for key in ("claim", "root_cause"):
            m = re.search(rf"^\s*{key}:\s*(.*?)(?=^\s*(?:root_cause|evidence|discriminator_related|claim):|\Z)", part, re.S | re.M)
            f[key] = " ".join(m.group(1).split()) if m else ""
        ev = re.search(r"^\s*evidence:\s*\n((?:\s*-\s.*(?:\n|$))+)", part, re.M)
        f["evidence"] = [re.sub(r"^\s*-\s*", "", line).strip() for line in ev.group(1).splitlines() if line.strip().startswith("-")] if ev else []
        m = re.search(r"discriminator_related:\s*(\S+)", part)
        f["discriminator_related"] = m.group(1) if m else None
        findings.append(f)
    doc["findings"] = findings
    return doc


def load_reply(path: Path) -> dict:
    text = path.read_text(encoding="utf-8")
    try:
        doc = yaml.safe_load(text)
        if isinstance(doc, dict) and isinstance(doc.get("findings"), list):
            return doc
    except yaml.YAMLError:
        pass
    return _lenient(text)


def ground(pointer: str, run_dir: Path, rows: list[dict], comp_ids: set[str], lessons: set[str], trials: set[str]) -> tuple[bool, str]:
    p = pointer.strip().strip("`'\"")
    if not p:
        return False, "empty"
    if p in trials:
        return True, "trial"
    if p in lessons or any(name in p for name in lessons):
        return True, "lesson"
    m = re.search(r"\b(l-\d{3})/(\d+)\b", p)
    if m and any(r.get("lead_id") == m.group(1) and str(r.get("seq")) == m.group(2) for r in rows):
        return True, "query_row"
    for path in re.findall(r"(?:gather_raw|gather_summaries)/[\w./-]+", p):
        if (run_dir / path).exists():
            return True, "path"
    ids = re.findall(r"\b[veh]-\d{3}\b", p)
    if ids and all(i in comp_ids for i in ids):
        return True, "invlang_id"
    m = re.search(r"\b(l-\d{3})\b", p)
    if m and any(r.get("lead_id") == m.group(1) for r in rows):
        return True, "lead"
    if re.search(r"\b(investigation\.md|report\.md|executed_queries\.jsonl|alert\.json|family\.yaml|lessons_loaded\.jsonl)\b", p):
        return True, "file"
    if re.search(r"\b(ac\d|p\d|r\d)\b", p):
        return True, "invlang_local_id"
    return False, "unresolved"


def run_checks(reply_path: Path, run_dir: Path) -> dict:
    doc = load_reply(reply_path)
    rows = contexts._rows(run_dir)
    comp = contexts._companion(run_dir)
    comp_ids: set[str] = set()
    for f in comp.get("findings", []) or []:
        obs = (f.get("outcome") or {}).get("observations") or {}
        comp_ids |= {v.get("id") for v in obs.get("vertices", []) or []}
        comp_ids |= {e.get("id") for e in obs.get("edges", []) or []}
    for h in (comp.get("hypothesize") or {}).get("hypotheses", []) or []:
        comp_ids.add(h.get("id"))
    pro = comp.get("prologue") or {}
    comp_ids |= {v.get("id") for v in pro.get("vertices", []) or []} | {e.get("id") for e in pro.get("edges", []) or []}
    lessons = {p.stem for p in contexts.LESSONS.glob("*.md")}
    trials = {d.name for d in contexts.RUNS_BASE.iterdir() if d.is_dir()}
    out = {"parse_error": doc.get("_parse_error"), "episode_outcome": doc.get("episode_outcome"),
           "n_findings": len(doc.get("findings") or []), "findings": []}
    for i, f in enumerate(doc.get("findings") or []):
        if not isinstance(f, dict):
            out["findings"].append({"index": i, "malformed": True}); continue
        text = _text(f).lower()
        hits = {ref: sorted({pat for pat in pats if re.search(pat, text)}) for ref, pats in PATTERNS.items()}
        pointers = [str(p) for p in (f.get("evidence") or [])]
        grounded = [(p, *ground(p, run_dir, rows, comp_ids, lessons, trials)) for p in pointers]
        out["findings"].append({
            "index": i, "bucket": f.get("bucket"), "claim": f.get("claim"),
            "regex_hits": {k: v for k, v in hits.items() if v},
            "bucket_matches": {ref: (f.get("bucket") == b) for ref, b in EXPECTED_BUCKET.items()},
            "pointers_total": len(pointers), "pointers_grounded": sum(1 for _, ok, _ in grounded if ok),
            "pointers_unresolved": [p for p, ok, _ in grounded if not ok],
        })
    return out


if __name__ == "__main__":
    reply, run = Path(sys.argv[1]), Path(sys.argv[2])
    print(json.dumps(run_checks(reply, run), indent=2))
