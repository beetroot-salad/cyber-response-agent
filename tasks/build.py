#!/usr/bin/env python3
"""
Generate board.html from task files in this directory.

Usage:
    python tasks/build.py

Output:
    board.html (project root) — open in any browser, no server needed.
"""

import json
import re
import sys
from pathlib import Path

TASKS_DIR = Path(__file__).parent
OUTPUT = TASKS_DIR.parent / "board.html"

FRONTMATTER_RE = re.compile(r"^---\n(.*?)\n---\n?", re.DOTALL)


def parse_task(path: Path) -> dict | None:
    text = path.read_text(encoding="utf-8")
    m = FRONTMATTER_RE.match(text)
    if not m:
        print(f"  skip {path.name}: no frontmatter", file=sys.stderr)
        return None

    meta: dict[str, str] = {}
    for line in m.group(1).splitlines():
        if ":" in line:
            key, _, val = line.partition(":")
            meta[key.strip()] = val.strip()

    title = meta.get("title", "").strip()
    if not title:
        print(f"  skip {path.name}: no title", file=sys.stderr)
        return None

    groups_raw = meta.get("groups", "").strip()
    groups = [g.strip() for g in groups_raw.split(",") if g.strip()]

    return {
        "id": path.stem,
        "title": title,
        "status": meta.get("status", "backlog"),
        "groups": groups,
        "body": text[m.end() :].strip(),
    }


def load_tasks() -> list[dict]:
    tasks = []
    for path in sorted(TASKS_DIR.glob("*.md")):
        task = parse_task(path)
        if task:
            tasks.append(task)
    return tasks


HTML_TEMPLATE = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Board — Cyber Response Agent</title>
<style>
:root {
  --bg:          #f8f7f6;
  --col-bg:      #ffffff;
  --card-border: #e5e3e0;
  --card-hover:  #fafaf9;
  --text:        #1a1917;
  --text-muted:  #78716c;
  --header-bg:   #1c1917;
  --col-title:   #44403c;
  --divider:     #e7e5e4;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
  background: var(--bg);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
  color: var(--text);
  min-height: 100vh;
  font-size: 14px;
}

/* ── Header row 1 ─────────────────────────────────────────────────────── */
header {
  background: var(--header-bg);
  padding: 0 20px;
  height: 44px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  position: sticky;
  top: 0;
  z-index: 10;
  gap: 12px;
}

.header-title {
  font-size: 13px;
  font-weight: 500;
  color: #fafaf9;
  white-space: nowrap;
}

.header-right {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-shrink: 0;
}

.header-label {
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: #a8a29e;
  padding: 0 4px;
}

.folder-status {
  font-size: 11px;
  color: #57534e;
  white-space: nowrap;
}
.folder-status.connected { color: #86efac; }

.hbtn {
  background: none;
  border: 1px solid #57534e;
  color: #a8a29e;
  padding: 4px 10px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 500;
  letter-spacing: 0.03em;
  cursor: pointer;
  transition: all 0.15s;
  white-space: nowrap;
}
.hbtn:hover:not(:disabled) { border-color: #a8a29e; color: #fafaf9; }
.hbtn:disabled { opacity: 0.35; cursor: not-allowed; }
.hbtn.accent {
  background: #292524;
  border-color: #44403c;
  color: #d6d3d1;
}
.hbtn.accent:hover:not(:disabled) { background: #3c3836; border-color: #57534e; color: #fafaf9; }

/* ── Header row 2 — tag bar ───────────────────────────────────────────── */
.tag-bar {
  background: #141211;
  padding: 5px 20px;
  display: flex;
  align-items: center;
  gap: 5px;
  overflow-x: auto;
  flex-wrap: nowrap;
  position: sticky;
  top: 44px;
  z-index: 9;
  border-bottom: 1px solid #1c1917;
  min-height: 34px;
  scrollbar-width: none;
}
.tag-bar::-webkit-scrollbar { display: none; }

.tag-bar-label {
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: #57534e;
  margin-right: 4px;
  flex-shrink: 0;
}

.tag-pill {
  background: none;
  border: 1px solid #2c2926;
  color: #57534e;
  padding: 2px 8px;
  border-radius: 3px;
  font-size: 10px;
  font-weight: 600;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  cursor: pointer;
  transition: all 0.12s;
  white-space: nowrap;
  flex-shrink: 0;
}
.tag-pill:hover { border-color: #44403c; color: #a8a29e; }
.tag-pill.active { background: #292524; border-color: #78716c; color: #e7e5e4; }

/* ── Board ────────────────────────────────────────────────────────────── */
.board {
  display: flex;
  gap: 14px;
  padding: 18px 20px;
  align-items: flex-start;
  overflow-x: auto;
  min-height: calc(100vh - 78px);
  justify-content: flex-start;
}

/* ── Column — wide, 2-col card grid ──────────────────────────────────── */
.column {
  background: var(--col-bg);
  border: 1px solid var(--card-border);
  border-radius: 8px;
  width: 568px;
  min-width: 568px;
  flex-shrink: 0;
}

.column-header {
  padding: 11px 13px;
  border-bottom: 1px solid var(--divider);
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.column-title {
  font-size: 11px;
  font-weight: 700;
  letter-spacing: 0.07em;
  text-transform: uppercase;
  color: var(--col-title);
}

.column-count {
  font-size: 11px;
  font-weight: 500;
  color: var(--text-muted);
  background: #f5f5f4;
  padding: 1px 7px;
  border-radius: 10px;
}

.column-cards {
  padding: 5px;
  display: grid;
  grid-template-columns: 1fr 1fr;
  gap: 4px;
}

.empty-col {
  grid-column: 1 / -1;
  padding: 14px 8px;
  text-align: center;
  font-size: 12px;
  color: #c5c1bd;
}

/* ── Card ─────────────────────────────────────────────────────────────── */
.card {
  border: 1px solid var(--card-border);
  border-radius: 6px;
  padding: 5px 7px;
  cursor: pointer;
  transition: background 0.1s, border-color 0.1s, opacity 0.15s;
  user-select: none;
  min-width: 0;
}

.card:not(.no-body):hover { background: var(--card-hover); border-color: #d4d0cb; }
.card.no-body { cursor: default; }
.card.dimmed { opacity: 0.18; }
.card.expanded { grid-column: 1 / -1; }

.card-top {
  display: flex;
  align-items: flex-start;
  gap: 6px;
  margin-bottom: 4px;
}

.card-title {
  flex: 1;
  font-size: 13px;
  line-height: 1.45;
  color: var(--text);
  min-width: 0;
  word-break: break-word;
}

.edit-btn {
  background: none;
  border: none;
  color: #c5c1bd;
  cursor: pointer;
  font-size: 13px;
  padding: 0 2px;
  line-height: 1;
  flex-shrink: 0;
  opacity: 0;
  transition: opacity 0.1s, color 0.1s;
}
.card:hover .edit-btn { opacity: 1; }
.edit-btn:hover { color: var(--text); }

.card-meta {
  display: flex;
  align-items: center;
  gap: 3px;
  flex-wrap: wrap;
}

/* ── Badge — dynamic colours ──────────────────────────────────────────── */
.badge {
  display: inline-block;
  font-size: 10px;
  font-weight: 600;
  padding: 2px 6px;
  border-radius: 3px;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  cursor: pointer;
  transition: filter 0.1s;
}
.badge:hover { filter: brightness(0.92); }

.expand-hint {
  font-size: 10px;
  color: #c5c1bd;
  margin-left: auto;
}

/* ── Expanded body ────────────────────────────────────────────────────── */
.card-body {
  display: none;
  margin-top: 9px;
  padding-top: 9px;
  border-top: 1px solid var(--divider);
  font-size: 12px;
  line-height: 1.65;
  color: #57534e;
  white-space: pre-wrap;
  font-family: ui-monospace, monospace;
  overflow-x: auto;
}
.card.expanded .card-body { display: block; }
.card.expanded .expand-hint { display: none; }

/* ── Modal ────────────────────────────────────────────────────────────── */
#modal-overlay {
  position: fixed;
  inset: 0;
  background: rgba(0,0,0,0.45);
  z-index: 100;
  display: flex;
  align-items: center;
  justify-content: center;
}
#modal-overlay.hidden { display: none; }

#modal {
  background: #fff;
  border-radius: 10px;
  padding: 24px;
  width: 520px;
  max-width: 92vw;
  max-height: 88vh;
  overflow-y: auto;
  box-shadow: 0 24px 64px rgba(0,0,0,0.22);
}

.modal-title {
  font-size: 15px;
  font-weight: 600;
  color: var(--text);
  margin-bottom: 20px;
}

.form-group { margin-bottom: 14px; }

.form-label {
  display: block;
  font-size: 11px;
  font-weight: 600;
  letter-spacing: 0.05em;
  text-transform: uppercase;
  color: var(--text-muted);
  margin-bottom: 5px;
}

.form-group input,
.form-group select,
.form-group textarea {
  width: 100%;
  border: 1px solid var(--card-border);
  border-radius: 5px;
  padding: 7px 10px;
  font-size: 13px;
  color: var(--text);
  background: #fff;
  font-family: inherit;
  outline: none;
  transition: border-color 0.15s;
  -webkit-appearance: none;
}
.form-group input:focus,
.form-group select:focus,
.form-group textarea:focus { border-color: #78716c; }

.form-group textarea {
  height: 130px;
  resize: vertical;
  font-family: ui-monospace, monospace;
  font-size: 12px;
  line-height: 1.6;
}

.form-hint {
  font-size: 11px;
  color: #a8a29e;
  margin-top: 4px;
}

.modal-actions {
  display: flex;
  gap: 8px;
  margin-top: 22px;
  align-items: center;
}
.modal-spacer { flex: 1; }

.btn {
  padding: 7px 16px;
  border-radius: 5px;
  font-size: 13px;
  font-weight: 500;
  cursor: pointer;
  border: 1px solid transparent;
  transition: all 0.15s;
  line-height: 1;
}
.btn-primary { background: #1c1917; color: #fafaf9; border-color: #1c1917; }
.btn-primary:hover { background: #292524; }
.btn-secondary { background: #f5f5f4; color: var(--text); border-color: var(--card-border); }
.btn-secondary:hover { background: #e7e5e4; }
.btn-danger { background: #fff1f2; color: #991b1b; border-color: #fecaca; }
.btn-danger:hover { background: #fee2e2; }
.btn-danger.hidden { display: none; }

/* ── Toast ────────────────────────────────────────────────────────────── */
.toast {
  position: fixed;
  bottom: 24px;
  right: 24px;
  background: #1c1917;
  color: #fafaf9;
  padding: 10px 18px;
  border-radius: 6px;
  font-size: 13px;
  z-index: 200;
  opacity: 0;
  transform: translateY(6px);
  transition: opacity 0.2s, transform 0.2s;
  box-shadow: 0 4px 20px rgba(0,0,0,0.2);
  pointer-events: none;
}
.toast.visible { opacity: 1; transform: none; }
.toast.toast-error { background: #7f1d1d; }
</style>
</head>
<body>

<header>
  <span class="header-title">Cyber Response Agent</span>
  <div class="header-right">
    <span class="folder-status" id="folder-status">○ no folder</span>
    <button id="btn-connect" class="hbtn">Connect folder</button>
    <button id="btn-new"     class="hbtn accent" disabled>+ New task</button>
    <span class="header-label">Board</span>
    <button id="btn-done"    class="hbtn">Show done</button>
  </div>
</header>

<div class="tag-bar" id="tag-bar"></div>

<div class="board" id="board"></div>

<!-- Task modal -->
<div id="modal-overlay" class="hidden">
  <div id="modal">
    <div class="modal-title" id="modal-title">New Task</div>
    <form id="task-form" autocomplete="off">
      <div class="form-group">
        <label class="form-label" for="f-title">Title</label>
        <input id="f-title" type="text" required placeholder="Task title">
      </div>
      <div class="form-group">
        <label class="form-label" for="f-status">Status</label>
        <select id="f-status">
          <option value="backlog">Backlog</option>
          <option value="todo">Todo</option>
          <option value="doing">Doing</option>
          <option value="done">Done</option>
        </select>
      </div>
      <div class="form-group">
        <label class="form-label" for="f-groups">Tags</label>
        <input id="f-groups" type="text" placeholder="mvp, reliability, cost">
        <div class="form-hint">Comma-separated</div>
      </div>
      <div class="form-group">
        <label class="form-label" for="f-body">Body</label>
        <textarea id="f-body" placeholder="Optional description…"></textarea>
        <div class="form-hint">Ctrl+Enter to save</div>
      </div>
      <div class="modal-actions">
        <button type="button" id="btn-delete" class="btn btn-danger hidden">Delete</button>
        <div class="modal-spacer"></div>
        <button type="button" id="btn-cancel" class="btn btn-secondary">Cancel</button>
        <button type="submit"                  class="btn btn-primary">Save</button>
      </div>
    </form>
  </div>
</div>

<script>
// ── Seed data (baked at build time) ────────────────────────────────────────
const SEED = __TASKS_JSON__;
let tasks = SEED.map(t => ({ ...t }));

// ── App state ──────────────────────────────────────────────────────────────
let showDone    = false;
let activeTags  = new Set();
let dirHandle   = null;   // FileSystemDirectoryHandle (granted)
let pendingHandle = null; // stored handle needing re-grant
let editingTask = null;   // task being edited in modal, null = new

// ── Badge colour palette (stable hash per tag name) ────────────────────────
const PALETTE = [
  { bg: '#fef3c7', fg: '#92400e' },
  { bg: '#ede9fe', fg: '#5b21b6' },
  { bg: '#dbeafe', fg: '#1e40af' },
  { bg: '#d1fae5', fg: '#065f46' },
  { bg: '#cffafe', fg: '#164e63' },
  { bg: '#fee2e2', fg: '#991b1b' },
  { bg: '#e0e7ff', fg: '#3730a3' },
  { bg: '#fef9c3', fg: '#713f12' },
  { bg: '#ecfccb', fg: '#3f6212' },
  { bg: '#f1f5f9', fg: '#475569' },
  { bg: '#ffe4e6', fg: '#9f1239' },
  { bg: '#fae8ff', fg: '#86198f' },
  { bg: '#fef2f2', fg: '#7c2d12' },
  { bg: '#f0fdf4', fg: '#14532d' },
];
function tagColor(tag) {
  let h = 0;
  for (let i = 0; i < tag.length; i++) h = (h * 31 + tag.charCodeAt(i)) & 0xffff;
  return PALETTE[h % PALETTE.length];
}

// ── Utilities ──────────────────────────────────────────────────────────────
function esc(s) {
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}
function slugify(s) {
  return s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '') || 'task';
}
function uniqueId(title) {
  const base = slugify(title);
  if (!tasks.find(t => t.id === base)) return base;
  for (let n = 2; n < 1000; n++) {
    const id = `${base}-${n}`;
    if (!tasks.find(t => t.id === id)) return id;
  }
  return `${base}-${Date.now()}`;
}

// ── IndexedDB ──────────────────────────────────────────────────────────────
async function openDB() {
  return new Promise((res, rej) => {
    const r = indexedDB.open('kanban-board-v1', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('kv');
    r.onsuccess = () => res(r.result);
    r.onerror   = () => rej(r.error);
  });
}
async function idbGet(key) {
  const db = await openDB();
  return new Promise((res, rej) => {
    const r = db.transaction('kv', 'readonly').objectStore('kv').get(key);
    r.onsuccess = () => res(r.result);
    r.onerror   = () => rej(r.error);
  });
}
async function idbSet(key, val) {
  const db = await openDB();
  return new Promise((res, rej) => {
    const r = db.transaction('kv', 'readwrite').objectStore('kv').put(val, key);
    r.onsuccess = () => res();
    r.onerror   = () => rej(r.error);
  });
}

// ── File system ────────────────────────────────────────────────────────────
function taskToMarkdown(t) {
  const g  = (t.groups || []).join(', ');
  let md = `---\ntitle: ${t.title}\nstatus: ${t.status}\ngroups: ${g}\n---`;
  if (t.body) md += '\n\n' + t.body;
  return md;
}
async function fsWrite(task) {
  const fh = await dirHandle.getFileHandle(task.id + '.md', { create: true });
  const w  = await fh.createWritable();
  await w.write(taskToMarkdown(task));
  await w.close();
}
async function fsDelete(taskId) {
  await dirHandle.removeEntry(taskId + '.md');
}

// ── Folder UI ──────────────────────────────────────────────────────────────
function updateFolderUI() {
  const statusEl    = document.getElementById('folder-status');
  const connectBtn  = document.getElementById('btn-connect');
  const newBtn      = document.getElementById('btn-new');
  if (dirHandle) {
    statusEl.textContent = '● ' + dirHandle.name;
    statusEl.className   = 'folder-status connected';
    connectBtn.textContent = 'Change folder';
    newBtn.disabled = false;
  } else if (pendingHandle) {
    statusEl.textContent = '○ ' + pendingHandle.name + ' (locked)';
    statusEl.className   = 'folder-status';
    connectBtn.textContent = 'Unlock';
    newBtn.disabled = true;
  } else {
    statusEl.textContent = '○ no folder';
    statusEl.className   = 'folder-status';
    connectBtn.textContent = 'Connect folder';
    newBtn.disabled = true;
  }
}

async function tryRestoreFolder() {
  if (!('showDirectoryPicker' in window)) return;
  try {
    const stored = await idbGet('dir');
    if (!stored) return;
    const perm = await stored.queryPermission({ mode: 'readwrite' });
    if (perm === 'granted') { dirHandle = stored; }
    else                    { pendingHandle = stored; }
  } catch (e) { console.warn('Restore folder:', e); }
  updateFolderUI();
}

async function connectFolder() {
  if (!('showDirectoryPicker' in window)) {
    toast('File System Access API requires Chrome or Edge', 'error'); return;
  }
  try {
    if (pendingHandle) {
      // Re-grant permission (user-gesture available from click)
      const perm = await pendingHandle.requestPermission({ mode: 'readwrite' });
      if (perm === 'granted') {
        dirHandle = pendingHandle;
        pendingHandle = null;
        await idbSet('dir', dirHandle);
        updateFolderUI();
        return;
      }
    }
    dirHandle = await window.showDirectoryPicker({ mode: 'readwrite' });
    pendingHandle = null;
    await idbSet('dir', dirHandle);
    updateFolderUI();
  } catch (e) {
    if (e.name !== 'AbortError') toast('Folder error: ' + e.message, 'error');
  }
}

// ── Toast ──────────────────────────────────────────────────────────────────
function toast(msg, type = '') {
  const el = document.createElement('div');
  el.className = 'toast' + (type ? ' toast-' + type : '');
  el.textContent = msg;
  document.body.appendChild(el);
  requestAnimationFrame(() => el.classList.add('visible'));
  setTimeout(() => { el.classList.remove('visible'); setTimeout(() => el.remove(), 300); }, 3000);
}

// ── Modal ──────────────────────────────────────────────────────────────────
function openModal(task = null) {
  editingTask = task;
  document.getElementById('modal-title').textContent  = task ? 'Edit Task' : 'New Task';
  document.getElementById('f-title').value   = task?.title             ?? '';
  document.getElementById('f-status').value  = task?.status            ?? 'backlog';
  document.getElementById('f-groups').value  = (task?.groups ?? []).join(', ');
  document.getElementById('f-body').value    = task?.body              ?? '';
  document.getElementById('btn-delete').classList.toggle('hidden', !task);
  document.getElementById('modal-overlay').classList.remove('hidden');
  document.getElementById('f-title').focus();
}
function closeModal() {
  document.getElementById('modal-overlay').classList.add('hidden');
  editingTask = null;
}

// ── Tag bar ────────────────────────────────────────────────────────────────
function renderTagBar() {
  const visibleTasks = showDone ? tasks : tasks.filter(t => t.status !== 'done');
  const visibleTags = new Set(visibleTasks.flatMap(t => t.groups || []));
  // Drop any active filters that are no longer visible
  for (const tag of [...activeTags]) {
    if (!visibleTags.has(tag)) activeTags.delete(tag);
  }
  const allTags = [...visibleTags].sort();
  const bar = document.getElementById('tag-bar');
  bar.innerHTML = '';

  if (allTags.length === 0) return;

  const label = document.createElement('span');
  label.className = 'tag-bar-label';
  label.textContent = 'Filter';
  bar.appendChild(label);

  for (const tag of allTags) {
    const btn = document.createElement('button');
    btn.className = 'tag-pill' + (activeTags.has(tag) ? ' active' : '');
    btn.textContent = tag;
    btn.addEventListener('click', () => {
      if (activeTags.has(tag)) activeTags.delete(tag); else activeTags.add(tag);
      renderTagBar();
      renderBoard();
    });
    bar.appendChild(btn);
  }
}

// ── Card ───────────────────────────────────────────────────────────────────
function renderCard(task) {
  const hasBody = !!task.body;
  const dimmed  = activeTags.size > 0 && !(task.groups || []).some(g => activeTags.has(g));

  const card = document.createElement('div');
  card.className = 'card' + (hasBody ? '' : ' no-body') + (dimmed ? ' dimmed' : '');
  card.dataset.id = task.id;

  const badges = (task.groups || []).map(g => {
    const { bg, fg } = tagColor(g);
    return `<span class="badge" style="background:${bg};color:${fg}" data-tag="${esc(g)}">${esc(g)}</span>`;
  }).join('');

  card.innerHTML = `
    <div class="card-top">
      <div class="card-title">${esc(task.title)}</div>
      <button class="edit-btn" title="Edit task">✎</button>
    </div>
    <div class="card-meta">
      ${badges}
      ${hasBody ? '<span class="expand-hint">···</span>' : ''}
    </div>
    ${hasBody ? `<div class="card-body">${esc(task.body)}</div>` : ''}
  `;

  // Badge click → toggle tag filter
  card.querySelectorAll('.badge').forEach(b => {
    b.addEventListener('click', e => {
      e.stopPropagation();
      const tag = b.dataset.tag;
      if (activeTags.has(tag)) activeTags.delete(tag); else activeTags.add(tag);
      renderTagBar();
      renderBoard();
    });
  });

  // Body expand (click card, not badge or edit-btn)
  if (hasBody) {
    card.addEventListener('click', e => {
      if (e.target.closest('.edit-btn') || e.target.closest('.badge')) return;
      card.classList.toggle('expanded');
    });
  }

  // Edit button
  card.querySelector('.edit-btn').addEventListener('click', e => {
    e.stopPropagation();
    if (!dirHandle) { toast('Connect a folder to edit tasks', 'error'); return; }
    openModal(task);
  });

  return card;
}

// ── Board ──────────────────────────────────────────────────────────────────
const COLS = [
  { id: 'backlog', label: 'Backlog' },
  { id: 'todo',    label: 'Todo'    },
  { id: 'doing',   label: 'Doing'  },
  { id: 'done',    label: 'Done'   },
];

function renderBoard() {
  const board = document.getElementById('board');
  board.innerHTML = '';
  const cols = showDone ? COLS : COLS.slice(0, 3);

  for (const col of cols) {
    const colTasks = tasks.filter(t => t.status === col.id);
    const colEl = document.createElement('div');
    colEl.className = 'column';
    colEl.innerHTML = `
      <div class="column-header">
        <span class="column-title">${col.label}</span>
        <span class="column-count">${colTasks.length}</span>
      </div>
      <div class="column-cards"></div>
    `;
    board.appendChild(colEl);
    const cardsEl = colEl.querySelector('.column-cards');
    if (colTasks.length === 0) {
      cardsEl.innerHTML = '<div class="empty-col">—</div>';
    } else {
      colTasks.forEach(t => cardsEl.appendChild(renderCard(t)));
    }
  }
}

// ── Form submit (create / update) ──────────────────────────────────────────
document.getElementById('task-form').addEventListener('submit', async e => {
  e.preventDefault();
  if (!dirHandle) { toast('Connect a folder first', 'error'); return; }

  const title  = document.getElementById('f-title').value.trim();
  const status = document.getElementById('f-status').value;
  const groups = document.getElementById('f-groups').value
    .split(',').map(s => s.trim()).filter(Boolean);
  const body   = document.getElementById('f-body').value.trim();
  if (!title) return;

  try {
    if (editingTask) {
      Object.assign(editingTask, { title, status, groups, body });
      await fsWrite(editingTask);
      toast('Saved');
    } else {
      const task = { id: uniqueId(title), title, status, groups, body };
      await fsWrite(task);
      tasks.push(task);
      toast('Task created');
    }
    closeModal();
    renderTagBar();
    renderBoard();
  } catch (err) {
    toast('Write failed: ' + err.message, 'error');
  }
});

// Delete
document.getElementById('btn-delete').addEventListener('click', async () => {
  if (!editingTask || !confirm(`Delete "${editingTask.title}"?`)) return;
  try {
    await fsDelete(editingTask.id);
    tasks = tasks.filter(t => t.id !== editingTask.id);
    closeModal();
    renderTagBar();
    renderBoard();
    toast('Deleted');
  } catch (err) {
    toast('Delete failed: ' + err.message, 'error');
  }
});

document.getElementById('btn-cancel').addEventListener('click', closeModal);
document.getElementById('modal-overlay').addEventListener('click', e => {
  if (e.target.id === 'modal-overlay') closeModal();
});
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') closeModal();
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    const overlay = document.getElementById('modal-overlay');
    if (!overlay.classList.contains('hidden')) document.getElementById('task-form').requestSubmit();
  }
});

// Header controls
document.getElementById('btn-connect').addEventListener('click', connectFolder);
document.getElementById('btn-new').addEventListener('click', () => openModal());
document.getElementById('btn-done').addEventListener('click', () => {
  showDone = !showDone;
  document.getElementById('btn-done').textContent = showDone ? 'Hide done' : 'Show done';
  renderTagBar();
  renderBoard();
});

// ── Init ───────────────────────────────────────────────────────────────────
tryRestoreFolder().then(() => {
  renderTagBar();
  renderBoard();
});
</script>
</body>
</html>
"""


def main() -> None:
    tasks = load_tasks()
    print(f"  loaded {len(tasks)} tasks")

    tasks_json = json.dumps(tasks, ensure_ascii=False, indent=None)
    # Prevent </script> from closing the script tag prematurely
    tasks_json = tasks_json.replace("</script>", r"<\/script>")
    html = HTML_TEMPLATE.replace("__TASKS_JSON__", tasks_json)

    OUTPUT.write_text(html, encoding="utf-8")
    print(f"  wrote {OUTPUT}")

    by_status: dict[str, int] = {}
    for t in tasks:
        by_status[t["status"]] = by_status.get(t["status"], 0) + 1
    for status, count in sorted(by_status.items()):
        print(f"    {status}: {count}")


if __name__ == "__main__":
    main()
