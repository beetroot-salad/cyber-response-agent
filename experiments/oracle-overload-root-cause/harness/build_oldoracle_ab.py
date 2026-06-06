"""Single-call old-oracle A/B — does input cleaning alone fix overload?

Condition A: the ORIGINAL old oracle (oracle.md, single-call, all-leads) fed the
  original goal-laden lead_sequence + scrubbed exemplars — reproduces #247's setup.
Condition B: same oracle, same exemplars, but lead descriptions sanitized — `goal`
  dropped and concrete timestamps stripped from `what_to_summarize`.
Only the lead-description text differs. Both run single-call on claude-sonnet-4-6,
effort low (the old oracle's pins), so any overload delta is attributable to inputs.
"""
import glob
import json
import re
from pathlib import Path

import yaml

RUN = Path("/tmp/defender-runs-v2/live-falco-nettool-1")
STORY = Path("/tmp/ab-effort/medium/live-falco-nettool-1/actor_story.md").read_text()
OUT = Path("/tmp/oracle-v2-probe")

# --- timestamp sanitizer (from build_prompts_r7) ---------------------------
_ISO = re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?\b")
_CLOCK = re.compile(r"\b\d{1,2}:\d{2}:\d{2}(?:\.\d+)?Z?\b")
_CLOCK_HM = re.compile(r"(?<![\d:])\d{1,2}:\d{2}Z\b")
def sanitize(s):
    s = _ISO.sub("<alert-time>", s); s = _CLOCK.sub("<alert-time>", s)
    return _CLOCK_HM.sub("<alert-time>", s)

# --- scrubbed exemplar (from _loop_exemplars._scrub_skeleton) --------------
def scrub(value, key=None):
    if isinstance(value, dict):
        return {k: scrub(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [scrub(value[0], key)] if value else []
    if isinstance(value, bool):
        return False
    if isinstance(value, (int, float)):
        return 0
    if isinstance(value, str):
        return f"<{key}>" if key else "<string>"
    return value

def exemplar_for(position):
    for fp in sorted(glob.glob(str(RUN / "gather_raw" / f"{position}[a-z].json"))):
        try:
            o = json.load(open(fp))
        except Exception:
            continue
        hits = o.get("hits") if isinstance(o, dict) else None
        if hits:
            return json.dumps(scrub(hits[0]), indent=2)
    return "(no schema sample available for this position)"

alert = json.dumps(json.load(open(RUN / "alert.json")), indent=2)
ls = yaml.safe_load((RUN / "lead_sequence.yaml").read_text())

def build_user(sanitized: bool):
    lead_blocks, exemplar_blocks = [], []
    for e in ls["entries"]:
        pos = e["position"]
        if pos == 0:
            continue
        desc = e.get("lead_description", {})
        goal = desc.get("goal", "")
        wtc = desc.get("what_to_summarize", [])
        qs = e.get("queries") or []
        q_lines = "\n".join(f"    - id: {q['id']}\n      params: {json.dumps(q.get('params', {}))}" for q in qs)
        if sanitized:
            wtc = [sanitize(x) for x in wtc]
            goal_line = ""               # goal dropped
        else:
            goal_line = f"  goal: {json.dumps(goal)}\n"
        wtc_yaml = "\n".join(f"    - {json.dumps(x)}" for x in wtc) or "    (none)"
        lead_blocks.append(f"- position: {pos}\n{goal_line}  what_to_summarize:\n{wtc_yaml}\n  queries:\n{q_lines}")
        exemplar_blocks.append(f"### position {pos}\n```json\n{exemplar_for(pos)}\n```")
    return f"""# alert.json
```json
{alert}
```

# actor_story.md
{STORY}

# lead_sequence.yaml
entries:
{chr(10).join(lead_blocks)}

# exemplars (value-scrubbed schema skeletons, one per position)
{chr(10).join(exemplar_blocks)}
"""

(OUT / "user_oldA.txt").write_text(build_user(sanitized=False))
(OUT / "user_oldB.txt").write_text(build_user(sanitized=True))
print("user_oldA.txt (original goal+timestamps):", len(Path(OUT/'user_oldA.txt').read_text()), "chars")
print("user_oldB.txt (sanitized):", len(Path(OUT/'user_oldB.txt').read_text()), "chars")
print("\n--- diff sample (lead 2 desc) ---")
for tag in ("oldA","oldB"):
    t=Path(OUT/f"user_{tag}.txt").read_text()
    seg=t[t.find("- position: 2"):t.find("- position: 3")]
    print(f"[{tag}]", " ".join(seg.split())[:200])
