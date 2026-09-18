#!/usr/bin/env python3
from __future__ import annotations

import html
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve()
REPO_ROOT = HERE.parents[3]

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from defender.scripts._venv import reexec_into_venv  # noqa: E402

if __name__ == "__main__":
    reexec_into_venv(__file__)

from defender.learning.frontend import serialize, serialize_queues  # noqa: E402
from defender.scripts.visualize.visualize_run import CSS as RUN_CSS  # noqa: E402

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
header.top nav.views { margin-left: auto; font-size: 12px; }

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
header.top nav.views { margin-left: auto; font-size: 12px; }
html { color-scheme: dark; }
body { background: var(--bg); }
main.queues { padding: 20px 24px 80px; max-width: 1100px; margin: 0 auto; }
section.stage-learning { border-left-color: var(--accent-learning); }
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
.qt-val.n-bad { color: var(--bad); font-weight: 600; }
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
.q-group h3 { margin-top: 12px; }
.q-group h3 { font-size: 11px; text-transform: uppercase; letter-spacing: 0.6px; color: var(--text-dim); border-bottom: 1px solid var(--border-2); padding-bottom: 4px; margin: 12px 0 6px; }
.q-group h3 .cap { font-weight: 400; margin-left: 8px; color: var(--text-dim); }
section.stage h3 .cap.near { color: var(--warn); }
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
<style>__CSS__</style></head><body id="top">
<header class="top"><div class="top-row">
  <h1>Learning loop — Queues</h1>
  <div class="meta" id="headline"></div>
  <nav class="views"><a href="lessons.html">lessons →</a></nav>
</div></header>
<main class="queues">
__FAULT_BAND__
<div class="q-cards" id="root"></div>
</main>
<script>
const DATA = __QUEUES_JSON__;
const esc = s => String(s ?? "").replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
const when = s => s ? s.slice(0, 10) : "";
const num = (v, warn) => '<span class="qt-val ' + (v === 0 ? "n-zero" : warn !== undefined && v >= warn ? "n-warn" : "") + '">' + v + '</span>';
const pj = o => esc(JSON.stringify(o, null, 2)).replace(/"([^"]+)":/g, '<span class="j-key">"$1"</span>:').replace(/: "([^"]*)"/g, ': <span class="j-str">"$1"</span>').replace(/: (\\d+)/g, ': <span class="j-num">$1</span>');
const q = DATA.quarantine;

document.getElementById("headline").textContent = "generated " + (DATA.generated_at || "—") + " · " + DATA.state_root;

function card(cls, name, stats, body, open){
  return '<details class="q-card ' + cls + '"' + (open ? ' open' : '') + '><summary><span class="qc-name">' + name + '</span><span class="qc-stats">' + stats + '</span></summary><div class="qc-body">' + body + '</div></details>';
}
function unreadable(n){ return n ? '<p class="q-unreadable">' + n + ' unreadable line' + (n === 1 ? '' : 's') + ' skipped</p>' : ''; }
function channelCard(ch){
  const held = ch.held.count ? '<p class="q-held"><b>' + ch.held.count + ' held</b> until a person moves ' + (ch.held.count === 1 ? 'it' : 'them') + ' · ' + ch.held.ids.map(esc).join(", ") + '</p>' : "";
  const dl = ch.deadletter.length
    ? '<div class="dl">' + ch.deadletter.map(e => '<details><summary><span class="dl-id">' + (e.id === null ? 'no id' : esc(e.id)) + '</span><span class="dl-reason">' + esc(e.reason) + '</span><span class="dl-when">' + when(e.when) + '</span></summary><div class="body"><pre class="json-pretty">' + pj(e.row) + '</pre></div></details>').join("") + '</div>'
    : '<div class="empty">No dead letters.</div>';
  const stats = '<span class="qs"><span class="qt-key">queued</span>' + num(ch.depth.queued) + '</span><span class="qs"><span class="qt-key">dead</span>' + num(ch.deadletter.length, 1) + '</span>';
  return card('t-' + ch.accent, esc(ch.name), stats, held + dl + unreadable(ch.unreadable), ch.deadletter.length > 0 || ch.held.count > 0);
}
function asideCard(){
  const li = (k, v, t) => '<li><span class="k">' + esc(k) + '</span><span class="v">' + esc(v) + (t ? '<span class="t">' + esc(t) + '</span>' : '') + '</span></li>';
  const list = rows => rows.length ? '<ul class="q-list">' + rows.join("") + '</ul>' : '<div class="empty">None.</div>';
  const near = q.tainted.rows.length >= q.tainted.cap - 2;
  const needsYou = q.markers.rows.length + q.tainted.rows.length;
  const human = '<div class="q-group q-human"><div class="q-group-head">Needs a person <span class="q-group-sub">nothing retries these</span></div>'
    + '<h3>Markers not served</h3>' + list(q.markers.rows.map(r => li(r.identity, r.failed, r.queue))) + unreadable(q.markers.unreadable)
    + '<h3>Tainted worktrees<span class="cap' + (near ? ' near' : '') + '">' + q.tainted.rows.length + ' / ' + q.tainted.cap + '</span></h3>'
    + list(q.tainted.rows.map(r => li(r.batch_id, r.taint, when(r.quarantined_at) + (Object.keys(r.verdict).length ? '' : ' · no scan recorded')))) + unreadable(q.tainted.unreadable)
    + '</div>';
  const system = '<div class="q-group q-system"><div class="q-group-head">Retrying itself <span class="q-group-sub">the lane serves nothing new until this lands</span></div>'
    + '<h3>Committed, not delivered</h3>' + list(q.deliveries.rows.map(r => li(r.branch, r.reason, "since " + when(r.at) + ", retried every tick"))) + unreadable(q.deliveries.unreadable)
    + '</div>';
  const stats = '<span class="qs"><span class="qt-key">needs a person</span>' + num(needsYou, 1) + '</span><span class="qs"><span class="qt-key">retrying</span>' + num(q.deliveries.rows.length) + '</span>';
  return card('t-raw', 'set aside', stats, human + system, needsYou > 0);
}

document.getElementById("root").innerHTML = DATA.channels.map(channelCard).join("") + asideCard();
</script>
</body></html>
"""


def _esc(value: object) -> str:
    return html.escape(str(value if value is not None else ""), quote=True)


def _fault_band(view: dict) -> str:
    """The machinery-health band, rendered here rather than in the page's script so a page
    whose channels all drained cleanly carries no fault heading at all. The stuck file is
    append-only and nothing clears it, so the band is titled by the record's time: "last
    fault", never "stuck now"."""
    stuck = [ch for ch in view["channels"] if ch.get("stuck")]
    if not stuck:
        return ""
    rows = "".join(
        '<div class="qf-row">'
        f'<span class="qf-ch">{_esc(ch["name"])}</span>'
        f'<span class="qf-class">{_esc(ch["stuck"].get("fault_class"))}</span>'
        f'<span class="qf-ticks">{_esc(ch["stuck"].get("consecutive_ticks"))} ticks running</span>'
        f'<span class="qf-when">{_esc(ch["stuck"].get("recorded_at") or "time unknown")}</span>'
        f'<span class="qf-reason">{_esc(ch["stuck"].get("reason"))}</span>'
        "</div>"
        for ch in stuck
    )
    return (
        '<div class="q-fault"><div class="qf-head">Last fault</div>' + rows
        + '<div class="qf-note">the rows were left queued and retried on the next tick; a '
          'later clean tick leaves this record in place</div></div>'
    )


def render_queues(view: dict) -> str:
    payload = json.dumps(view, ensure_ascii=False).replace("<", "\\u003c")
    return (
        QUEUES_PAGE.replace("__CSS__", RUN_CSS + QUEUES_CSS)
        .replace("__FAULT_BAND__", _fault_band(view))
        .replace("__QUEUES_JSON__", payload)
    )


def render(view: dict) -> str:
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

    queues = serialize_queues.stamped_view()
    q_json = HERE.parent / "queues.json"
    q_json.write_text(serialize_queues.dump_contract(queues), encoding="utf-8")
    q_html = HERE.parent / "queues.html"
    q_html.write_text(render_queues(queues), encoding="utf-8")
    dead = {ch["name"]: len(ch["deadletter"]) for ch in queues["channels"]}
    print(f"wrote {q_json.relative_to(REPO_ROOT)} + {q_html.relative_to(REPO_ROOT)} — dead letters {dead}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
