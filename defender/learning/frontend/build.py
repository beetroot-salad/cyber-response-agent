#!/usr/bin/env python3
"""Render the lessons posture view as one self-contained HTML page.

Orchestrator + view template. Calls the api layer (``serialize.build_view``),
writes the standalone ``lessons.json`` contract, then bakes the same contract
inline into ``lessons.html`` so the page opens in a browser with no server
(the run-visualizer pattern). The view renders purely from the injected
contract — it is the only coupling point to the backend.

Visual language is reused from the run visualizer
(``defender/scripts/visualize_run.py`` CSS tokens); HTML escaping +
markdown rendering happen client-side in the injected template.

Usage:
    build.py            # write lessons.json + lessons.html
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
REPO_ROOT = HERE.parents[3]
DEFENDER = REPO_ROOT / "defender"


def _reexec_into_venv() -> None:
    """Switch to defender/.venv (for PyYAML, via serialize) when run as a script.

    Must run before ``import serialize`` so serialize imports cleanly
    under the venv. Guarded by ``__name__ == "__main__"`` — build.py is
    only ever a CLI entry point, never imported. No-op without a venv.
    """
    venv_py = DEFENDER / ".venv" / "bin" / "python3"
    if venv_py.is_file() and Path(sys.executable) != venv_py:
        os.execv(str(venv_py), [str(venv_py), str(HERE), *sys.argv[1:]])


if __name__ == "__main__":
    _reexec_into_venv()

sys.path.insert(0, str(HERE.parent))           # serialize.py
sys.path.insert(0, str(DEFENDER / "scripts"))  # visualize_run CSS tokens

import serialize
from visualize_run import CSS as RUN_CSS

# Each group's left-accent reuses the run visualizer's stage palette:
# defender=blue, actor=red, environment=amber (oracle).
GROUP_STAGE = {"defender": "stage-defender", "actor": "stage-actor", "environment": "stage-oracle"}


LESSONS_CSS = """
/* ----- Lessons frontend (reuses run-visualizer tokens) ----- */
.controls {
  display: flex; gap: 16px; align-items: center;
  padding: 12px 24px; background: var(--bg-3);
  border-bottom: 1px solid var(--border);
  position: sticky; top: 0; z-index: 15;
}
.controls input[type="search"] {
  flex: 1; max-width: 480px;
  background: var(--bg); color: var(--text);
  border: 1px solid var(--border); border-radius: 5px;
  padding: 7px 11px; font-size: 13px;
}
.controls input[type="search"]:focus { outline: none; border-color: var(--accent); }
.controls label { font-size: 12px; color: var(--text-dim); display: flex; gap: 6px; align-items: center; cursor: pointer; }
.controls .spacer { margin-left: auto; }

main.lessons { padding: 20px 24px 80px; max-width: 1400px; margin: 0 auto; }
section.stage-defender { --accent-group: var(--accent-defender); }
section.stage-actor    { --accent-group: var(--accent-actor); }
section.stage-oracle   { --accent-group: var(--accent-oracle); }
section.stage .blurb { font-size: 12px; color: var(--text-dim); margin: 0 0 4px; max-width: 760px; }
section.stage .count-pill {
  font-family: 'SF Mono', Menlo, Consolas, monospace; font-size: 11px;
  color: var(--text-dim); margin-left: 8px; font-weight: 400;
}

.lesson-grid {
  display: grid; grid-template-columns: repeat(auto-fill, minmax(360px, 1fr));
  gap: 14px; margin-top: 14px;
}
.lesson-card {
  background: var(--bg-3); border: 1px solid var(--border-2);
  border-left: 4px solid var(--accent-group, var(--border));
  border-radius: 6px; padding: 12px 14px;
}
.lesson-card.is-stale { opacity: 0.72; }
.lesson-head { display: flex; align-items: baseline; gap: 8px; }
.lesson-title { color: var(--text-bright); font-weight: 600; font-size: 14px; word-break: break-word; }
.lesson-desc { color: var(--text); margin: 7px 0 9px; line-height: 1.5; }
.lesson-meta { display: flex; flex-wrap: wrap; gap: 6px 10px; margin-bottom: 8px; }
.field { display: inline-flex; align-items: baseline; gap: 5px; }
.field-label {
  font-size: 9px; text-transform: uppercase; letter-spacing: 0.5px;
  color: var(--text-dim); font-family: 'SF Mono', Menlo, Consolas, monospace;
}
.field-text { font-size: 11px; color: var(--text); font-family: 'SF Mono', Menlo, Consolas, monospace; }
.chip {
  font-family: 'SF Mono', Menlo, Consolas, monospace; font-size: 11px;
  background: var(--bg-4); border: 1px solid var(--border-2); border-radius: 3px;
  padding: 1px 6px; color: var(--code);
}
.badge {
  font-size: 10px; text-transform: uppercase; letter-spacing: 0.4px;
  border-radius: 3px; padding: 1px 6px; font-weight: 600;
}
.badge-stale { background: rgba(210, 153, 34, 0.18); color: var(--warn); border: 1px solid var(--warn); }
.lesson-body { margin-top: 6px; }
.lesson-body > summary {
  cursor: pointer; user-select: none; font-size: 11px; color: var(--text-dim);
  padding: 3px 0; list-style: revert;
}
.lesson-body > summary:hover { color: var(--text-bright); }
.md { padding: 8px 2px 2px; line-height: 1.6; color: var(--text); }
.md p { margin: 0 0 8px; }
.md ul { margin: 0 0 8px; padding-left: 20px; }
.md li { margin: 2px 0; }
.md strong { color: var(--text-bright); }
.md code {
  font-family: 'SF Mono', Menlo, Consolas, monospace; font-size: 11px;
  color: var(--code); background: var(--bg); padding: 1px 4px; border-radius: 2px;
}
.lesson-src {
  font-family: 'SF Mono', Menlo, Consolas, monospace; font-size: 10px;
  color: var(--text-dim); margin-top: 9px; word-break: break-all;
}
.no-match { color: var(--text-dim); font-style: italic; font-size: 12px; padding: 8px 0; }
"""


PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Learning loop — Lessons</title>
<style>__CSS__</style></head><body id="top">
<header class="top"><div class="top-row">
  <h1>Learning loop — Lessons</h1>
  <div class="meta" id="headline"></div>
</div></header>
<div class="controls">
  <input type="search" id="filter" placeholder="Filter by title, description, or metadata…" autocomplete="off">
  <div class="spacer"></div>
  <label><input type="checkbox" id="hide-stale"> Hide stale</label>
</div>
<main class="lessons" id="root"></main>
<script>
const DATA = __LESSONS_JSON__;
const STAGE = __STAGE_JSON__;
// Order + identity come from the contract (serialize.GROUPS insertion order),
// so a corpus added there renders without a matching edit here.
const ORDER = Object.keys(DATA.groups);

function escHtml(s){ return String(s).replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c])); }

// Markdown-lite: paragraphs, '-'/'*' bullet lists, **bold**, `code`.
function inlineMd(s){
  return escHtml(s)
    .replace(/\\*\\*(.+?)\\*\\*/g, '<strong>$1</strong>')
    .replace(/`([^`]+?)`/g, '<code>$1</code>');
}
function renderMd(body){
  const lines = (body || "").split("\\n");
  let html = "", para = [], list = [];
  const flushPara = () => { if(para.length){ html += "<p>" + inlineMd(para.join(" ")) + "</p>"; para = []; } };
  const flushList = () => { if(list.length){ html += "<ul>" + list.map(li => "<li>" + inlineMd(li) + "</li>").join("") + "</ul>"; list = []; } };
  for(const raw of lines){
    const line = raw.trim();
    if(!line){ flushPara(); flushList(); continue; }
    const m = line.match(/^[-*]\\s+(.*)/);
    if(m){ flushPara(); list.push(m[1]); }
    else { flushList(); para.push(line); }
  }
  flushPara(); flushList();
  return html;
}

function chipValue(v){
  if(v && typeof v === "object") return Object.values(v).join(":");
  return String(v);
}
function renderField(field, meta){
  const v = meta[field.key];
  if(v === undefined || v === null || (Array.isArray(v) && v.length === 0) || v === "") return "";
  if(field.kind === "chips"){
    const items = (Array.isArray(v) ? v : [v]).map(x => '<span class="chip">' + escHtml(chipValue(x)) + '</span>').join(" ");
    return '<span class="field"><span class="field-label">' + escHtml(field.label) + '</span>' + items + '</span>';
  }
  if(field.kind === "count"){
    const n = Array.isArray(v) ? v.length : v;
    return '<span class="field"><span class="field-label">' + escHtml(field.label) + '</span><span class="chip">' + escHtml(n) + '</span></span>';
  }
  let text = field.kind === "date" ? String(v).slice(0, 10) : String(v);
  return '<span class="field"><span class="field-label">' + escHtml(field.label) + '</span><span class="field-text">' + escHtml(text) + '</span></span>';
}

function renderCard(lesson, fields){
  const stale = lesson.status === "stale";
  const meta = lesson.metadata || {};
  const search = [lesson.title, lesson.description, JSON.stringify(meta)].join(" ").toLowerCase();
  const chips = fields.map(f => renderField(f, meta)).filter(Boolean).join("");
  const staleBadge = stale ? '<span class="badge badge-stale">stale</span>' : "";
  const body = lesson.body ? '<details class="lesson-body"><summary>Read lesson</summary><div class="md">' + renderMd(lesson.body) + '</div></details>' : "";
  return '<div class="lesson-card' + (stale ? " is-stale" : "") + '" data-stale="' + stale + '" data-search="' + escHtml(search) + '">'
    + '<div class="lesson-head"><span class="lesson-title">' + escHtml(lesson.title) + '</span>' + staleBadge + '</div>'
    + (lesson.description ? '<div class="lesson-desc">' + escHtml(lesson.description) + '</div>' : "")
    + (chips ? '<div class="lesson-meta">' + chips + '</div>' : "")
    + body
    + '<div class="lesson-src">' + escHtml(lesson.source_path) + '</div>'
    + '</div>';
}

function renderGroup(name){
  const g = DATA.groups[name];
  const stale = g.lessons.filter(l => l.status === "stale").length;
  const pill = g.lessons.length + " lesson" + (g.lessons.length === 1 ? "" : "s") + (stale ? " · " + stale + " stale" : "");
  const cards = g.lessons.length
    ? '<div class="lesson-grid">' + g.lessons.map(l => renderCard(l, g.fields)).join("") + '</div>'
    : '<div class="empty">No ' + escHtml(name) + ' lessons yet.</div>';
  return '<section class="stage ' + (STAGE[name] || "") + '" data-group="' + name + '">'
    + '<h2>' + escHtml(g.label) + '<span class="count-pill">' + pill + '</span></h2>'
    + '<p class="blurb">' + escHtml(g.blurb) + '</p>'
    + cards + '<div class="no-match" hidden>No lessons match the filter.</div>'
    + '</section>';
}

document.getElementById("root").innerHTML = ORDER.map(renderGroup).join("");

const total = ORDER.reduce((a, n) => a + DATA.groups[n].lessons.length, 0);
document.getElementById("headline").textContent =
  total + " lessons · generated " + (DATA.generated_at || "—");

function applyFilters(){
  const q = document.getElementById("filter").value.trim().toLowerCase();
  const hideStale = document.getElementById("hide-stale").checked;
  for(const section of document.querySelectorAll("section.stage")){
    let shown = 0;
    for(const card of section.querySelectorAll(".lesson-card")){
      const match = (!q || card.dataset.search.includes(q)) && !(hideStale && card.dataset.stale === "true");
      card.hidden = !match;
      if(match) shown++;
    }
    const nm = section.querySelector(".no-match");
    const hasCards = section.querySelectorAll(".lesson-card").length > 0;
    if(nm) nm.hidden = !(hasCards && shown === 0);
  }
}
document.getElementById("filter").addEventListener("input", applyFilters);
document.getElementById("hide-stale").addEventListener("change", applyFilters);
</script>
</body></html>
"""


def render(view: dict) -> str:
    # Replace every "<" with its JS unicode escape so no lesson body or
    # metadata can close the inline <script> early: this covers all
    # script-end variants ("</script ", "</SCRIPT>", "<!--", ...), not
    # just the exact "</script>" literal the old code handled. The
    # decoded JS string is byte-identical, since the escape evaluates
    # back to "<". __LESSONS_JSON__ is substituted last so the CSS/stage
    # payloads are never re-scanned for the marker.
    payload = json.dumps(view, ensure_ascii=False).replace("<", "\\u003c")
    return (
        PAGE.replace("__CSS__", RUN_CSS + LESSONS_CSS)
        .replace("__STAGE_JSON__", json.dumps(GROUP_STAGE))
        .replace("__LESSONS_JSON__", payload)
    )


def main() -> int:
    view = serialize.stamped_view()

    json_out = HERE.parent / "lessons.json"
    json_out.write_text(serialize.dump_contract(view), encoding="utf-8")

    html_out = HERE.parent / "lessons.html"
    html_out.write_text(render(view), encoding="utf-8")

    counts = {k: len(v["lessons"]) for k, v in view["groups"].items()}
    print(f"wrote {json_out.relative_to(REPO_ROOT)} + {html_out.relative_to(REPO_ROOT)} — {counts}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
