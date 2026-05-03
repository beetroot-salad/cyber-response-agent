"""Live observability UI for soc-agent runs.

Reads run dir contents on demand and serves a polling HTML page. No streaming,
no Claude Code internals — only files under runs/.

Run:
    python3 soc-agent/scripts/observe.py [--runs-dir PATH] [--port 8765]

Then open http://127.0.0.1:8765/.
"""

from __future__ import annotations

import argparse
import html
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

DEFAULT_PARENTS = [
    Path(__file__).resolve().parent.parent / "runs",  # soc-agent/runs/
    Path("/workspace/runs"),                          # orchestrate dirs (in-tree)
    Path("/tmp/soc-agent-orchestrate-eval"),          # orchestrate eval dirs
]
SAFE_ID = re.compile(r"^[A-Za-z0-9._-]+$")


def discover_run_dirs(parents: list[Path]) -> list[Path]:
    """Find every run dir under the given parents.

    A run dir is any directory that contains state.json or meta.json (or, as a
    fallback, investigation.md / alert.json). Looks one and two levels deep so
    we catch both `soc-agent/runs/{run}` and `runs/{date-rule}/runs/{uuid}`.
    """
    seen: dict[str, Path] = {}
    def consider(d: Path):
        if not d.is_dir() or d.name.startswith("."):
            return
        if (d / "runs").is_dir():
            return  # outer container; inner runs are picked up separately
        markers = ("state.json", "meta.json", "investigation.md", "alert.json")
        if not any((d / m).exists() for m in markers):
            return
        seen[str(d.resolve())] = d
    for parent in parents:
        if not parent.is_dir():
            continue
        for child in parent.iterdir():
            if not child.is_dir() or child.name.startswith("."):
                continue
            consider(child)
            inner = child / "runs"
            if inner.is_dir():
                for grand in inner.iterdir():
                    consider(grand)
    return list(seen.values())


def _run_id(d: Path) -> str:
    """Stable id: parent/name when nested, else name."""
    if d.parent.name == "runs":
        return f"{d.parent.parent.name}/{d.name}"
    return d.name


def _resolve_run_id(parents: list[Path], run_id: str) -> Path | None:
    for d in discover_run_dirs(parents):
        if _run_id(d) == run_id:
            return d
    return None


def list_runs(parents: list[Path]) -> list[dict]:
    rows = []
    for d in discover_run_dirs(parents):
        meta = _read_json(d / "meta.json") or {}
        state = _read_json(d / "state.json") or {}
        budget = _read_json(d / "budget.json") or {}
        has_report = (d / "report.md").exists()
        rows.append({
            "id": _run_id(d),
            "phase": state.get("phase") or "?",
            "signature_id": meta.get("signature_id") or state.get("signature_id"),
            "ticket_id": meta.get("ticket_id") or state.get("ticket_id"),
            "created_at": meta.get("created_at") or budget.get("started_at"),
            "mtime": d.stat().st_mtime,
            "live": not has_report,
            "tool_calls": budget.get("tool_calls"),
        })
    rows.sort(key=lambda r: r["mtime"], reverse=True)
    return rows


def run_snapshot(parents: list[Path], run_id: str) -> dict | None:
    # run_id may contain a "/" (nested layout); validate each segment.
    for seg in run_id.split("/"):
        if not SAFE_ID.match(seg):
            return None
    d = _resolve_run_id(parents, run_id)
    if d is None:
        return None
    runs_dir = d.parent  # the dir holding .sessions/ and tool_*.jsonl
    meta = _read_json(d / "meta.json") or {}
    state = _read_json(d / "state.json") or {}
    alert = _read_json(d / "alert.json") or {}
    budget = _read_json(d / "budget.json") or {}
    investigation = _read_text(d / "investigation.md")
    report = _read_text(d / "report.md")
    inner_id = d.name
    sessions = _sessions_for_run(runs_dir, inner_id)
    tool_calls = _tool_calls_for_sessions(runs_dir, sessions, limit=200)
    actions = _actions_for_run(runs_dir, inner_id)
    inv_blocks = _split_investigation(investigation) if investigation else []
    return {
        "run_id": run_id,
        "meta": meta,
        "state": state,
        "alert": alert,
        "budget": budget,
        "report": report,
        "investigation_blocks": inv_blocks,
        "tool_calls": tool_calls,
        "actions": actions,
        "sessions": sessions,
        "mtimes": _mtimes(d),
    }


def _read_json(p: Path):
    try:
        return json.loads(p.read_text())
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def _read_text(p: Path) -> str | None:
    try:
        return p.read_text()
    except (FileNotFoundError, OSError):
        return None


def _mtimes(d: Path) -> dict:
    out = {}
    for name in ("investigation.md", "state.json", "report.md"):
        p = d / name
        if p.exists():
            out[name] = p.stat().st_mtime
    return out


def _sessions_for_run(runs_dir: Path, run_id: str) -> list[str]:
    sdir = runs_dir / ".sessions"
    if not sdir.is_dir():
        return []
    out = []
    for sf in sdir.iterdir():
        if sf.suffix != ".json":
            continue
        data = _read_json(sf) or {}
        # mapping schema: {"run_dir": "...", "signature_id": "..."} (path or id)
        rd = data.get("run_dir") or data.get("run_id") or ""
        if rd.endswith(run_id) or rd == run_id:
            out.append(sf.stem)
    return out


def _tool_calls_for_sessions(runs_dir: Path, sessions: list[str], limit: int) -> list[dict]:
    if not sessions:
        return []
    sset = set(sessions)
    rows: list[dict] = []
    for fname in ("tool_audit.jsonl", "tool_trace.jsonl"):
        p = runs_dir / fname
        if not p.exists():
            continue
        try:
            with p.open() as f:
                for line in f:
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if rec.get("session_id") in sset:
                        rec["_source"] = fname
                        rows.append(rec)
        except OSError:
            continue
    rows.sort(key=lambda r: r.get("timestamp", ""))
    return rows[-limit:]


def _actions_for_run(runs_dir: Path, run_id: str) -> list[dict]:
    p = runs_dir / "action_audit.jsonl"
    if not p.exists():
        return []
    rows = []
    try:
        with p.open() as f:
            for line in f:
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("run_id") == run_id:
                    rows.append(rec)
    except OSError:
        return []
    return rows


_PHASES = ("CONTEXTUALIZE", "SCREEN", "HYPOTHESIZE", "PREDICT", "GATHER", "ANALYZE", "REPORT", "CONCLUDE")
_PHASE_RE = re.compile(
    r"^##\s+(" + "|".join(_PHASES) + r")(?:\s+\(loop\s+\d+\))?\s*$", re.MULTILINE
)


def _split_investigation(text: str) -> list[dict]:
    """Split investigation.md into per-PHASE sections.

    Tolerant: if no PHASE headers found, returns single block.
    """
    matches = list(_PHASE_RE.finditer(text))
    if not matches:
        return [{"phase": "(unmarked)", "body": text}]
    blocks = []
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
        header = text[m.start():m.end()].lstrip("# ").strip()
        blocks.append({"phase": header, "body": text[m.end():end].strip()})
    return blocks


# ---------- HTTP ----------

INDEX_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>soc-agent runs</title>
<style>
body{font-family:ui-monospace,monospace;background:#0e1116;color:#d8dee9;margin:2rem;}
a{color:#88c0d0;text-decoration:none;}a:hover{text-decoration:underline;}
table{border-collapse:collapse;width:100%;}
th,td{padding:.4rem .8rem;text-align:left;border-bottom:1px solid #2a2f3a;}
th{color:#81a1c1;font-weight:normal;}
.live{color:#a3be8c;}
.done{color:#5e6675;}
.phase{color:#ebcb8b;}
</style></head><body>
<h1>soc-agent runs</h1>
<table><tr><th>run_id</th><th>phase</th><th>signature</th><th>ticket</th><th>created</th><th>tools</th><th>status</th></tr>
__ROWS__
</table>
</body></html>"""

RUN_HTML = """<!doctype html>
<html><head><meta charset="utf-8"><title>__RUN__</title>
<style>
body{font-family:ui-monospace,monospace;background:#0e1116;color:#d8dee9;margin:1rem 2rem;line-height:1.45;}
a{color:#88c0d0;}
h1,h2,h3{color:#eceff4;margin-top:1.2rem;}
h1{font-size:1.1rem;}h2{font-size:.95rem;border-bottom:1px solid #2a2f3a;padding-bottom:.2rem;}
.meta{display:flex;gap:1.5rem;flex-wrap:wrap;color:#81a1c1;font-size:.85rem;}
.meta b{color:#d8dee9;font-weight:normal;}
.phase-pill{display:inline-block;padding:.1rem .5rem;background:#3b4252;border-radius:.3rem;color:#ebcb8b;}
.live{color:#a3be8c;}
pre{background:#161b22;padding:.6rem .8rem;border-radius:.3rem;overflow-x:auto;font-size:.8rem;white-space:pre-wrap;}
details{margin:.4rem 0;}summary{cursor:pointer;color:#81a1c1;}
.tool{font-size:.78rem;color:#a3a8b3;border-left:2px solid #3b4252;padding:.1rem .6rem;margin:.2rem 0;}
.tool b{color:#88c0d0;}
.note{color:#5e6675;font-size:.75rem;}
.cols{display:grid;grid-template-columns:2fr 1fr;gap:1.5rem;}
@media(max-width:1100px){.cols{grid-template-columns:1fr;}}
</style></head><body>
<p><a href="/">← all runs</a></p>
<main id="root">loading…</main>
<script>
const RUN = __RUN_JSON__;
let lastMtimeKey = "";
function escapeHtml(s){return (s||"").replace(/[&<>"']/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));}
function renderToolCall(t){
  const inp = JSON.stringify(t.tool_input||{}).slice(0,200);
  return `<div class="tool"><b>${escapeHtml(t.tool_name||"?")}</b> <span class="note">${escapeHtml(t.timestamp||"")}</span><br>${escapeHtml(inp)}</div>`;
}
function renderBlock(b){
  return `<details open><summary class="phase-pill">${escapeHtml(b.phase)}</summary><pre>${escapeHtml(b.body)}</pre></details>`;
}
function render(d){
  const m=d.meta||{}, s=d.state||{}, b=d.budget||{};
  const phase = s.phase || "?";
  const live = !d.report;
  const hist = (s.history||[]).join(" → ");
  const html = `
    <h1>${escapeHtml(d.run_id)} <span class="${live?"live":""}">${live?"● LIVE":"○ done"}</span></h1>
    <div class="meta">
      <span>phase: <b class="phase-pill">${escapeHtml(phase)}</b></span>
      <span>signature: <b>${escapeHtml(m.signature_id||"?")}</b></span>
      <span>ticket: <b>${escapeHtml(m.ticket_id||"?")}</b></span>
      <span>created: <b>${escapeHtml(m.created_at||b.started_at||"?")}</b></span>
      <span>started: <b>${escapeHtml(b.started_at||"?")}</b></span>
      <span>tool_calls: <b>${escapeHtml(String(b.tool_calls ?? "?"))}</b></span>
      <span>subagent_spawns: <b>${escapeHtml(String(b.subagent_spawns ?? "?"))}</b></span>
      <span>history: <b>${escapeHtml(hist)}</b></span>
      <span class="note">tokens/cost: TODO (not yet emitted)</span>
    </div>
    <div class="cols">
      <div>
        <h2>investigation</h2>
        ${(d.investigation_blocks||[]).map(renderBlock).join("") || '<p class="note">no investigation.md yet</p>'}
        ${d.report ? `<h2>report</h2><pre>${escapeHtml(d.report)}</pre>` : ""}
      </div>
      <div>
        <h2>tool calls (${(d.tool_calls||[]).length})</h2>
        ${(d.tool_calls||[]).slice().reverse().map(renderToolCall).join("") || '<p class="note">none yet</p>'}
        <h2>actions</h2>
        ${(d.actions||[]).map(a=>`<div class="tool"><b>${escapeHtml(a.action||"?")}</b> → ${escapeHtml(a.status||"?")}<br><span class="note">${escapeHtml(a.timestamp||"")}</span></div>`).join("") || '<p class="note">none</p>'}
        <h2>alert</h2>
        <details><summary>show alert.json</summary><pre>${escapeHtml(JSON.stringify(d.alert,null,2))}</pre></details>
      </div>
    </div>`;
  document.getElementById("root").innerHTML = html;
}
async function poll(){
  try{
    const r = await fetch(`/runs/${RUN}/data.json`, {cache:"no-store"});
    const d = await r.json();
    const key = JSON.stringify(d.mtimes) + ":" + (d.tool_calls||[]).length;
    if(key !== lastMtimeKey){ lastMtimeKey = key; render(d); }
  }catch(e){console.warn(e);}
}
poll(); setInterval(poll, 1500);
</script>
</body></html>"""


class Handler(BaseHTTPRequestHandler):
    parents: list[Path] = list(DEFAULT_PARENTS)

    def log_message(self, format, *args):  # quiet
        return

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            return self._index()
        if path.startswith("/runs/"):
            rest = path[len("/runs/"):]
            if rest.endswith("/data.json"):
                return self._run_json(rest[: -len("/data.json")])
            return self._run_html(rest.rstrip("/"))
        return self._404()

    def _index(self):
        rows_html = []
        for r in list_runs(self.parents):
            cls = "live" if r["live"] else "done"
            status = "● live" if r["live"] else "○ done"
            rows_html.append(
                f'<tr><td><a href="/runs/{html.escape(r["id"])}">{html.escape(r["id"])}</a></td>'
                f'<td class="phase">{html.escape(str(r["phase"]))}</td>'
                f'<td>{html.escape(str(r["signature_id"] or "—"))}</td>'
                f'<td>{html.escape(str(r["ticket_id"] or "—"))}</td>'
                f'<td>{html.escape(str(r["created_at"] or "—"))}</td>'
                f'<td>{html.escape(str(r["tool_calls"]) if r["tool_calls"] is not None else "—")}</td>'
                f'<td class="{cls}">{status}</td></tr>'
            )
        body = INDEX_HTML.replace("__ROWS__", "\n".join(rows_html))
        self._send(200, body, "text/html")

    def _run_html(self, run_id: str):
        body = RUN_HTML.replace("__RUN__", html.escape(run_id)).replace(
            "__RUN_JSON__", json.dumps(run_id)
        )
        self._send(200, body, "text/html")

    def _run_json(self, run_id: str):
        snap = run_snapshot(self.parents, run_id)
        if snap is None:
            return self._404()
        self._send(200, json.dumps(snap), "application/json")

    def _404(self):
        self._send(404, "not found", "text/plain")

    def _send(self, code: int, body: str, ctype: str):
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", f"{ctype}; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--parent", type=Path, action="append", default=None,
                    help="parent dir to scan for runs (repeatable). Defaults to "
                         "soc-agent/runs, /workspace/runs, /tmp/soc-agent-orchestrate-eval.")
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()

    parents = [p.resolve() for p in (args.parent or DEFAULT_PARENTS) if p.exists()]
    if not parents:
        raise SystemExit("no parent dirs exist; pass --parent")
    Handler.parents = parents
    httpd = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"observe: http://{args.host}:{args.port}/")
    for p in parents:
        print(f"  scanning: {p}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
