"""Round 7 — deterministic what_to_characterize timestamp sanitizer + re-run all 5 leads.

The R6 diagnostic proved the lone concrete-time fabrication (lead 5's nc @ 14:08:43)
came from a concrete clock time embedded in what_to_characterize, not from the oracle
inventing it. Fix is upstream and deterministic: rewrite every absolute clock time in
what_to_characterize to the oracle's own `<alert-time>` anchor. Query windows are NOT
touched (they are the legitimate envelope the oracle filters on). System prompt is
unchanged (sys6); only the input what_to_characterize is sanitized -> isolates the
sanitizer as the single variable vs round 6.
"""
import glob
import json
import re
from pathlib import Path

import yaml

RUN = Path("/tmp/defender-runs-v2/live-falco-nettool-1")
STORY = Path("/tmp/ab-effort/medium/live-falco-nettool-1/actor_story.md").read_text()
OUT = Path("/tmp/oracle-v2-probe")

# --- the sanitizer ---------------------------------------------------------
_ISO = re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b")
_CLOCK = re.compile(r"\b\d{1,2}:\d{2}:\d{2}(?:\.\d+)?Z?\b")          # HH:MM:SS(.ms)(Z)
_CLOCK_HM = re.compile(r"(?<![\d:])\d{1,2}:\d{2}Z\b")                # bare HH:MMZ


def sanitize_wtc(item: str) -> str:
    """Replace every absolute clock time with the <alert-time> anchor.

    Relative spans ('within +/-5 minutes', 'a few minutes later') survive untouched —
    they carry salience without a copyable concrete value. Only absolute times go.
    """
    item = _ISO.sub("<alert-time>", item)
    item = _CLOCK.sub("<alert-time>", item)
    item = _CLOCK_HM.sub("<alert-time>", item)
    return item
# ---------------------------------------------------------------------------


def first_event(position):
    for fp in sorted(glob.glob(str(RUN / "gather_raw" / f"{position}[a-z].json"))):
        try:
            o = json.load(open(fp))
        except Exception:
            continue
        hits = o.get("hits") if isinstance(o, dict) else None
        if hits:
            return hits[0], Path(fp).name
    return None, None


ls = yaml.safe_load((RUN / "lead_sequence.yaml").read_text())
SYS = (OUT / "sys6.txt").read_text()          # unchanged system prompt
(OUT / "sys7.txt").write_text(SYS)

changed = []
for entry in ls["entries"]:
    pos = entry["position"]
    if pos == 0:
        continue
    qs = entry.get("queries") or []
    raw_wtc = entry.get("lead_description", {}).get("what_to_summarize", [])
    san_wtc = [sanitize_wtc(x) for x in raw_wtc]
    for r, s in zip(raw_wtc, san_wtc):
        if r != s:
            changed.append((pos, r.strip()[:60], s.strip()[:60]))
    sample, src = first_event(pos)
    q_lines = "\n".join(
        f"  - id: {q.get('id')}\n    params: {json.dumps(q.get('params', {}))}" for q in qs
    )
    wtc = yaml.safe_dump(san_wtc, default_flow_style=False) if san_wtc else "  (none)"
    sample_block = json.dumps(sample, indent=2) if sample is not None else "(no sample available — project from the queries alone)"
    user = f"""## The actor's story

{STORY}

## This lead (position {pos}) — no goal given

what_to_characterize:
{wtc}

queries:
{q_lines}

## Sample event one of these queries returned (shape reference; from {src})

```json
{sample_block}
```

Emit the events the story's activity would produce that surface through this lead's queries.
"""
    (OUT / f"user7_{pos}.txt").write_text(user)

print("sanitizer rewrote these what_to_characterize times:")
for pos, r, s in changed:
    print(f"  lead {pos}: ...{r!r}\n           -> ...{s!r}")
print(f"\n{len(changed)} item(s) changed across leads; sys7.txt = sys6 (unchanged)")
