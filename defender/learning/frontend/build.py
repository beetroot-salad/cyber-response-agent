#!/usr/bin/env python3
from __future__ import annotations

import json
import sys
from pathlib import Path
from string import Template

HERE = Path(__file__).resolve()
REPO_ROOT = HERE.parents[3]

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from defender.scripts._venv import reexec_into_venv  # noqa: E402

if __name__ == "__main__":
    reexec_into_venv(__file__)

from defender.learning.core.config import LoopPaths  # noqa: E402
from defender.learning.frontend import serialize, serialize_queues  # noqa: E402
from defender.scripts.visualize.visualize_primitives import (  # noqa: E402
    esc_untrusted,
    pretty_json_html,
)
from defender.scripts.visualize.visualize_run import CSS as RUN_CSS  # noqa: E402

GROUP_STAGE = {"defender": "stage-defender", "actor": "stage-actor", "environment": "stage-oracle"}

#: The header link each page carries to the other — one rule, both pages.
NAV_CSS = "header.top nav.views { margin-left: auto; font-size: 12px; }\n"


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
/* Retired: producer gone, files remain. Dimmed and badged rather than hidden — still
   findable, but the page must not read as if the loop is authoring them. */
section.stage.is-retired { opacity: 0.66; }
section.stage.is-retired .lesson-card { border-left-color: var(--border-2); }
section.stage .retired-note {
  font-size: 12px; color: var(--warn); margin: 0 0 4px; max-width: 760px;
}
.badge-retired { background: rgba(110, 118, 129, 0.20); color: var(--text-dim); border: 1px solid var(--border-2); }
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
  <nav class="views"><a href="queues.html">queues →</a></nav>
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
  // Empty-and-live is "nothing authored yet"; empty-and-retired is "nothing was left
  // behind" — different facts, different sentences.
  const cards = g.lessons.length
    ? '<div class="lesson-grid">' + g.lessons.map(l => renderCard(l, g.fields)).join("") + '</div>'
    : '<div class="empty">' + (g.retired ? 'This retired corpus is empty.' : 'No ' + escHtml(name) + ' lessons yet.') + '</div>';
  const badge = g.retired ? '<span class="badge badge-retired">retired</span>' : "";
  const note = (g.retired && g.retired_note) ? '<p class="retired-note">' + escHtml(g.retired_note) + '</p>' : "";
  return '<section class="stage ' + (STAGE[name] || "") + (g.retired ? " is-retired" : "") + '" data-group="' + name + '">'
    + '<h2>' + escHtml(g.label) + ' ' + badge + '<span class="count-pill">' + pill + '</span></h2>'
    + '<p class="blurb">' + escHtml(g.blurb) + '</p>'
    + note
    + cards + '<div class="no-match" hidden>No lessons match the filter.</div>'
    + '</section>';
}

document.getElementById("root").innerHTML = ORDER.map(renderGroup).join("");

// SEPARATE TOTALS: one number over live and retired was the claim this page used to make,
// and only the live corpora are the loop's output. Retired lessons render, but aren't posture.
const live = ORDER.filter(n => !DATA.groups[n].retired)
                  .reduce((a, n) => a + DATA.groups[n].lessons.length, 0);
const archived = ORDER.filter(n => DATA.groups[n].retired)
                      .reduce((a, n) => a + DATA.groups[n].lessons.length, 0);
document.getElementById("headline").textContent =
  live + " live lesson" + (live === 1 ? "" : "s")
  + (archived ? " · " + archived + " archived" : "")
  + " · generated " + (DATA.generated_at || "—");

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


# =========================================================================================
# The queue-state page (#903): what the loop gave up on, parked, or set aside — one host's
# state root, on demand, beside the lessons page. Same spine (RUN_CSS), same self-contained
# shape; its contract is `serialize_queues.build_view`.
# =========================================================================================

QUEUES_CSS = """
/* ----- Queue-state page (reuses the run-visualizer tokens) ----- */
html { color-scheme: dark; }
body { background: var(--bg); }
main.queues { padding: 20px 24px 80px; max-width: 1100px; margin: 0 auto; }
.q-cards { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; align-items: start; }
.q-card { background: var(--bg-2); border: 1px solid var(--border); border-left: 4px solid var(--border); border-radius: 6px; min-width: 0; }
.q-card { --card-accent: var(--border); border-left-color: var(--card-accent); }
.q-card.t-defender { --card-accent: var(--accent-defender); }
.q-card.t-learning { --card-accent: var(--accent-learning); }
.q-card.t-oracle { --card-accent: var(--accent-oracle); }
.q-card.t-raw { --card-accent: var(--accent-raw); }
.q-card > summary { display: flex; align-items: baseline; gap: 16px; padding: 10px 14px; cursor: pointer; list-style: none; user-select: none; }
.q-card > summary::-webkit-details-marker { display: none; }
.q-card > summary::before { content: "▸"; color: var(--text-dim); font-size: 11px; margin-right: -6px; }
.q-card[open] > summary::before { content: "▾"; }
.q-card > summary:hover { background: var(--bg-3); }
.q-card .qc-name { font-size: 14px; font-weight: 600; color: var(--text-bright); }
.q-card .qc-stats { margin-left: auto; display: flex; gap: 14px; font-family: 'SF Mono', Menlo, Consolas, monospace; font-size: 12px; font-variant-numeric: tabular-nums; }
.q-card .qs .qt-key { color: var(--text-dim); margin-right: 5px; }
.q-card .qc-body { padding: 0 14px 12px; border-top: 1px solid var(--border-2); }
.qt-val { color: var(--text); }
.qt-val.n-zero { color: var(--text-dim); }
.qt-val.n-warn { color: var(--warn); font-weight: 600; }
.q-held { font-size: 12.5px; color: var(--text-dim); margin: 10px 0 0; }
.q-held b { color: var(--warn); font-weight: 600; }
.dl { display: flex; flex-direction: column; gap: 6px; margin-top: 10px; }
.dl details { background: var(--bg-3); border: 1px solid var(--border-2); border-left: 3px solid var(--card-accent); border-radius: 4px; }
.dl summary { display: grid; grid-template-columns: minmax(140px, 200px) 1fr auto; gap: 12px; align-items: baseline; padding: 6px 12px; cursor: pointer; list-style: none; font-family: 'SF Mono', Menlo, Consolas, monospace; font-size: 12px; }
.dl summary::-webkit-details-marker { display: none; }
.dl summary:hover { background: var(--bg-4); }
.dl .dl-id { color: var(--code); overflow-wrap: anywhere; }
.dl .dl-reason { color: var(--text-bright); overflow-wrap: anywhere; }
.dl .dl-when { color: var(--text-dim); white-space: nowrap; }
.dl .body { padding: 4px 12px 8px; }
.dl .body pre { margin: 0; }
.q-list { list-style: none; padding: 0; margin: 6px 0 0; display: flex; flex-direction: column; gap: 4px; font-size: 12.5px; }
.q-list li { display: grid; grid-template-columns: minmax(140px, 260px) 1fr; gap: 12px; padding: 4px 0; border-bottom: 1px solid var(--border-2); }
.q-list .k { font-family: 'SF Mono', Menlo, Consolas, monospace; font-size: 12px; color: var(--code); overflow-wrap: anywhere; }
.q-list .v { color: var(--text); overflow-wrap: anywhere; }
.q-list .v .t { color: var(--text-dim); margin-left: 8px; font-size: 11px; }
.q-group { margin-top: 12px; padding: 2px 14px 10px; border-radius: 5px; border: 1px solid var(--border-2); border-left: 3px solid var(--card-accent); background: var(--bg-3); }
.q-group.q-system { opacity: 0.7; }
.q-group-head { font-size: 13px; font-weight: 600; color: var(--text-bright); margin: 10px 0 0; }
.q-group-sub { font-size: 11px; font-weight: 400; color: var(--text-dim); margin-left: 8px; }
.q-group h3 { font-size: 11px; text-transform: uppercase; letter-spacing: 0.6px; color: var(--text-dim); border-bottom: 1px solid var(--border-2); padding-bottom: 4px; margin: 12px 0 6px; }
.q-group h3 .cap { font-weight: 400; margin-left: 8px; color: var(--text-dim); }
.q-group h3 .cap.near { color: var(--warn); }
.q-dir { font-family: 'SF Mono', Menlo, Consolas, monospace; font-size: 11px; color: var(--text-dim); margin: 0 0 4px; overflow-wrap: anywhere; }
@media (max-width: 860px) { .q-cards { grid-template-columns: 1fr; } }
@media (max-width: 700px) {
  main.queues { padding: 16px 16px 60px; }
  .dl summary, .q-list li { grid-template-columns: 1fr; gap: 2px; }
}
.q-fault { margin-bottom: 20px; padding: 10px 14px 8px; border-radius: 6px; border: 1px solid var(--bad); background: rgba(248, 81, 73, 0.07); }
.q-fault .qf-head { font-size: 11px; text-transform: uppercase; letter-spacing: 0.6px; color: var(--bad); font-weight: 600; margin-bottom: 6px; }
.q-fault .qf-row { display: grid; grid-template-columns: minmax(120px, 180px) minmax(120px, 160px) auto auto 1fr; gap: 12px; align-items: baseline; font-size: 12.5px; padding: 3px 0; }
.q-fault .qf-ch { font-weight: 600; color: var(--text-bright); }
.q-fault .qf-class { font-family: 'SF Mono', Menlo, Consolas, monospace; color: var(--bad); }
.q-fault .qf-ticks, .q-fault .qf-when { color: var(--text-bright); white-space: nowrap; }
.q-fault .qf-reason { color: var(--text-dim); overflow-wrap: anywhere; }
.q-fault .qf-note { font-size: 11px; color: var(--text-dim); margin-top: 6px; }
.q-unreadable { font-size: 11px; color: var(--warn); margin: 8px 0 0; }
@media (max-width: 700px) { .q-fault .qf-row { grid-template-columns: 1fr; gap: 2px; } }
"""


QUEUES_PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Learning loop — Queues</title>
<style>${css}</style></head><body id="top">
<header class="top"><div class="top-row">
  <h1>Learning loop — Queues</h1>
  <div class="meta">generated ${generated} · ${state_root}</div>
  <nav class="views"><a href="lessons.html">lessons →</a></nav>
</div></header>
<main class="queues">
${fault_band}
<div class="q-cards">${cards}</div>
</main>
<script>
// The contract this page was rendered from, carried whole so the page stays self-contained
// and a reader can pull the JSON back out of it (`const DATA = ...;` is the one line).
const DATA = ${queues_json};
</script>
</body></html>
"""


# Every value this renderer touches is already the contract's type (`serialize_queues`' rule),
# so the helpers below take strings and ints and do one thing each: `esc_untrusted` is applied
# exactly once, at the point a value is written into markup, never to text that is already
# markup.


def _when(value: str | None) -> str:
    """The date of a contract timestamp, as plain text; the caller escapes it."""
    return value[:10] if value else ""


def _num(value: int, warn_at: int | None = None) -> str:
    cls = "n-zero" if value == 0 else ("n-warn" if warn_at is not None and value >= warn_at else "")
    return f'<span class="qt-val{(" " + cls) if cls else ""}">{value}</span>'


def _plural(n: int, one: str, many: str) -> str:
    return one if n == 1 else many


def _unreadable_line(n: int, unit: str) -> str:
    """`unit` is "line" for a channel (its sidecars are JSONL; a whole sidecar that could not
    be read counts as one) and "file" for the set-aside lists (one record per file)."""
    return (f'<p class="q-unreadable">{n} unreadable {_plural(n, unit, unit + "s")} skipped</p>'
            if n else "")


def _card(cls: str, name: str, stats: str, body: str, open_: bool) -> str:
    return (
        f'<details class="q-card {cls}"{" open" if open_ else ""}>'
        f'<summary><span class="qc-name">{name}</span><span class="qc-stats">{stats}</span></summary>'
        f'<div class="qc-body">{body}</div></details>'
    )


def _stat(key: str, value_html: str) -> str:
    return f'<span class="qs"><span class="qt-key">{key}</span>{value_html}</span>'


def _channel_card(ch: dict) -> str:
    held = ch["held"]
    held_html = ""
    if held["count"]:
        held_html = (
            f'<p class="q-held"><b>{held["count"]} held</b> · {esc_untrusted(ch["hold_means"])} · '
            + ", ".join(esc_untrusted(i) for i in held["ids"]) + "</p>"
        )
    if ch["deadletter"]:
        rows = "".join(
            "<details><summary>"
            f'<span class="dl-id">{"no id" if e["id"] is None else esc_untrusted(e["id"])}</span>'
            f'<span class="dl-reason">{esc_untrusted(e["reason"])}</span>'
            f'<span class="dl-when">{esc_untrusted(_when(e["when"]))}</span>'
            f'</summary><div class="body">{pretty_json_html(e["row"])}</div></details>'
            for e in ch["deadletter"]
        )
        dead_html = f'<div class="dl">{rows}</div>'
    else:
        dead_html = '<div class="empty">No dead letters.</div>'
    stats = _stat("queued", _num(ch["depth"]["queued"])) + _stat("dead", _num(len(ch["deadletter"]), 1))
    return _card(
        f't-{esc_untrusted(ch["accent"])}', esc_untrusted(ch["name"]), stats,
        held_html + dead_html + _unreadable_line(ch["unreadable"], "line"),
        bool(ch["deadletter"]) or held["count"] > 0,
    )


def _list(items: list[str]) -> str:
    return f'<ul class="q-list">{"".join(items)}</ul>' if items else '<div class="empty">None.</div>'


def _li(key: str, value: str, tail: str = "") -> str:
    tail_html = f'<span class="t">{esc_untrusted(tail)}</span>' if tail else ""
    return (f'<li><span class="k">{esc_untrusted(key)}</span>'
            f'<span class="v">{esc_untrusted(value)}{tail_html}</span></li>')


def _cap(tainted: dict) -> str:
    """`held / cap`, warm once two slots or fewer remain — and never on an empty directory,
    whatever the cap. `held` is null when the directory could not be listed: "?" then, not a
    number the writer would not agree with."""
    held, cap = tainted["held"], tainted["cap"]
    near = held is not None and held > 0 and cap - held <= 2
    shown = "?" if held is None else str(held)
    return f'<span class="cap{" near" if near else ""}">{shown} / {cap}</span>'


def _aside_card(q: dict) -> str:
    markers, deliveries, tainted = q["markers"], q["deliveries"], q["tainted"]
    needs_person = len(markers["rows"]) + len(tainted["rows"])
    human = (
        '<div class="q-group q-human"><div class="q-group-head">Needs a person '
        '<span class="q-group-sub">nothing retries these</span></div>'
        "<h3>Markers not served</h3>"
        + _list([_li(r["identity"], r["failed"], r["queue"]) for r in markers["rows"]])
        + _unreadable_line(markers["unreadable"], "file")
        + f"<h3>Tainted worktrees{_cap(tainted)}</h3>"
        + f'<p class="q-dir">{esc_untrusted(tainted["dir"])}</p>'
        + _list([
            _li(r["batch_id"], r["taint"],
                _when(r["quarantined_at"]) + ("" if r["verdict"] else " · no scan recorded"))
            for r in tainted["rows"]
        ])
        + _unreadable_line(tainted["unreadable"], "file")
        + "</div>"
    )
    system = (
        '<div class="q-group q-system"><div class="q-group-head">Retrying itself '
        '<span class="q-group-sub">the lane serves nothing new until this lands</span></div>'
        "<h3>Committed, not delivered</h3>"
        + _list([
            _li(r["branch"], r["reason"], f'since {_when(r["at"]) or "?"}, retried every tick')
            for r in deliveries["rows"]
        ])
        + _unreadable_line(deliveries["unreadable"], "file")
        + "</div>"
    )
    stats = _stat("needs a person", _num(needs_person, 1)) + _stat("retrying", _num(len(deliveries["rows"])))
    return _card("t-raw", "set aside", stats, human + system, needs_person > 0)


def _fault_band(view: dict) -> str:
    """The machinery-health band, present only when a channel has a stuck record, so a page
    whose channels all drained cleanly carries no fault heading at all. The stuck file is
    append-only and nothing clears it, so the band is titled by the record's time: "last
    fault", never "stuck now"."""
    stuck = [ch for ch in view["channels"] if ch.get("stuck")]
    if not stuck:
        return ""
    rows = "".join(
        '<div class="qf-row">'
        f'<span class="qf-ch">{esc_untrusted(ch["name"])}</span>'
        f'<span class="qf-class">{esc_untrusted(ch["stuck"]["fault_class"])}</span>'
        f'<span class="qf-ticks">{ch["stuck"]["consecutive_ticks"]} '
        f'{_plural(ch["stuck"]["consecutive_ticks"], "tick", "ticks")} running</span>'
        f'<span class="qf-when">{esc_untrusted(ch["stuck"]["recorded_at"] or "time unknown")}</span>'
        f'<span class="qf-reason">{esc_untrusted(ch["stuck"]["reason"])}</span>'
        "</div>"
        for ch in stuck
    )
    return (
        '<div class="q-fault"><div class="qf-head">Last fault</div>' + rows
        + '<div class="qf-note">the rows were left queued and retried on the next tick; a '
          'later clean tick leaves this record in place</div></div>'
    )


def render_queues(view: dict) -> str:
    """The whole page from the contract, RENDERED HERE rather than by a script in the page:
    every value a person reads goes through `esc_untrusted` on this side, where a test can
    see it, and the page needs no script to show anything. The template is filled in ONE
    pass, so a value that happens to spell a placeholder is content, never a second
    substitution."""
    payload = json.dumps(view, ensure_ascii=False).replace("<", "\\u003c")
    return Template(QUEUES_PAGE).substitute(
        css=RUN_CSS + NAV_CSS + QUEUES_CSS,
        generated=esc_untrusted(view.get("generated_at") or "—"),
        state_root=esc_untrusted(view["state_root"]),
        fault_band=_fault_band(view),
        cards="".join(_channel_card(ch) for ch in view["channels"]) + _aside_card(view["quarantine"]),
        queues_json=payload,
    )


def render(view: dict) -> str:
    payload = json.dumps(view, ensure_ascii=False).replace("<", "\\u003c")
    return (
        PAGE.replace("__CSS__", RUN_CSS + NAV_CSS + LESSONS_CSS)
        .replace("__STAGE_JSON__", json.dumps(GROUP_STAGE))
        .replace("__LESSONS_JSON__", payload)
    )


def main(paths: LoopPaths | None = None) -> int:
    """Both pages, into this directory. `paths` is the queue page's whole input surface — the
    CLI leaves it None and the state root is resolved at call time; a test hands its own."""
    view = serialize.stamped_view()

    json_out = HERE.parent / "lessons.json"
    json_out.write_text(serialize.dump_contract(view), encoding="utf-8")

    html_out = HERE.parent / "lessons.html"
    html_out.write_text(render(view), encoding="utf-8")

    counts = {k: len(v["lessons"]) for k, v in view["groups"].items()}
    print(f"wrote {json_out.relative_to(REPO_ROOT)} + {html_out.relative_to(REPO_ROOT)} — {counts}")

    queues = serialize_queues.stamped_view(paths)
    q_json = HERE.parent / "queues.json"
    q_json.write_text(serialize_queues.dump_contract(queues), encoding="utf-8")
    q_html = HERE.parent / "queues.html"
    q_html.write_text(render_queues(queues), encoding="utf-8")
    dead = {ch["name"]: len(ch["deadletter"]) for ch in queues["channels"]}
    print(f"wrote {q_json.relative_to(REPO_ROOT)} + {q_html.relative_to(REPO_ROOT)} — dead letters {dead}")
    return 0


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    sys.exit(main())
