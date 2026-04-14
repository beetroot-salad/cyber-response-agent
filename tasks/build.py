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
  --bg:           #f8f7f6;
  --col-bg:       #ffffff;
  --card-border:  #e5e3e0;
  --card-hover:   #fafaf9;
  --text:         #1a1917;
  --text-muted:   #78716c;
  --header-bg:    #1c1917;
  --header-text:  #fafaf9;
  --col-title:    #44403c;
  --divider:      #e7e5e4;
}

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

body {
  background: var(--bg);
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
  color: var(--text);
  min-height: 100vh;
  font-size: 14px;
}

/* ── Header ── */
header {
  background: var(--header-bg);
  color: var(--header-text);
  padding: 10px 20px;
  display: flex;
  align-items: center;
  justify-content: space-between;
  position: sticky;
  top: 0;
  z-index: 10;
}

header h1 {
  font-size: 12px;
  font-weight: 600;
  letter-spacing: 0.08em;
  text-transform: uppercase;
  color: #a8a29e;
}

header span {
  font-size: 13px;
  font-weight: 500;
  color: #fafaf9;
}

.header-right {
  display: flex;
  align-items: center;
  gap: 12px;
}

#toggle-done {
  background: none;
  border: 1px solid #57534e;
  color: #a8a29e;
  padding: 4px 12px;
  border-radius: 4px;
  font-size: 11px;
  font-weight: 500;
  letter-spacing: 0.04em;
  text-transform: uppercase;
  cursor: pointer;
  transition: border-color 0.15s, color 0.15s;
}
#toggle-done:hover { border-color: #a8a29e; color: #fafaf9; }

/* ── Board ── */
.board {
  display: flex;
  gap: 14px;
  padding: 18px 20px;
  align-items: flex-start;
  overflow-x: auto;
  min-height: calc(100vh - 44px);
  justify-content: safe center;
}

/* ── Column ── */
.column {
  background: var(--col-bg);
  border: 1px solid var(--card-border);
  border-radius: 8px;
  width: 272px;
  min-width: 272px;
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
  padding: 8px;
  display: flex;
  flex-direction: column;
  gap: 5px;
}

.empty-col {
  padding: 18px 8px;
  text-align: center;
  font-size: 12px;
  color: #c5c1bd;
}

/* ── Card ── */
.card {
  border: 1px solid var(--card-border);
  border-radius: 6px;
  padding: 9px 11px;
  cursor: pointer;
  transition: background 0.1s, border-color 0.1s;
  user-select: none;
}

.card:hover { background: var(--card-hover); border-color: #d4d0cb; }
.card.no-body { cursor: default; }
.card.no-body:hover { background: transparent; border-color: var(--card-border); }

.card-title {
  font-size: 13px;
  line-height: 1.45;
  color: var(--text);
  margin-bottom: 7px;
}

.card-meta {
  display: flex;
  align-items: center;
  gap: 5px;
  flex-wrap: wrap;
}

/* ── Badge ── */
.badge {
  display: inline-block;
  font-size: 10px;
  font-weight: 600;
  padding: 2px 6px;
  border-radius: 3px;
  letter-spacing: 0.04em;
  text-transform: uppercase;
}

.badge-mvp              { background: #fef3c7; color: #92400e; }
.badge-archetype        { background: #ede9fe; color: #5b21b6; }
.badge-reliability      { background: #dbeafe; color: #1e40af; }
.badge-cost             { background: #d1fae5; color: #065f46; }
.badge-sonnet-migration { background: #cffafe; color: #164e63; }
.badge-state            { background: #fee2e2; color: #991b1b; }
.badge-knowledge        { background: #e0e7ff; color: #3730a3; }
.badge-phase-2          { background: #f3f4f6; color: #4b5563; }
.badge-evaluation       { background: #fef9c3; color: #713f12; }
.badge-dns              { background: #ecfccb; color: #3f6212; }
.badge-v3-rewrite       { background: #f1f5f9; color: #475569; }
.badge-post-mortem      { background: #ffe4e6; color: #9f1239; }
.badge-past-runs        { background: #fae8ff; color: #86198f; }
.badge-invlang          { background: #fef2f2; color: #7c2d12; }

.expand-hint {
  font-size: 10px;
  color: #c5c1bd;
  margin-left: auto;
}

/* ── Expanded body ── */
.card-body {
  display: none;
  margin-top: 9px;
  padding-top: 9px;
  border-top: 1px solid var(--divider);
  font-size: 12px;
  line-height: 1.65;
  color: #57534e;
  white-space: pre-wrap;
  font-family: "SF Mono", ui-monospace, "Fira Code", Consolas, monospace;
  overflow-x: auto;
}

.card.expanded .card-body { display: block; }
.card.expanded .expand-hint { display: none; }
</style>
</head>
<body>

<header>
  <span>Cyber Response Agent</span>
  <div class="header-right">
    <h1>Board</h1>
    <button id="toggle-done">Show done</button>
  </div>
</header>

<div class="board" id="board"></div>

<script>
const TASKS = __TASKS_JSON__;

const ALWAYS_COLS = [
  { id: "backlog", label: "Backlog" },
  { id: "todo",    label: "Todo"    },
  { id: "doing",   label: "Doing"   },
];

let showDone = false;

function esc(s) {
  return s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");
}

function renderCard(task) {
  const card = document.createElement("div");
  const hasBody = !!task.body;
  card.className = "card" + (hasBody ? "" : " no-body");

  const badge = (task.groups || [])
    .map(g => `<span class="badge badge-${esc(g)}">${esc(g)}</span>`)
    .join("");
  const hint = hasBody ? `<span class="expand-hint">···</span>` : "";
  const body = hasBody ? `<div class="card-body">${esc(task.body)}</div>` : "";

  card.innerHTML = `
    <div class="card-title">${esc(task.title)}</div>
    <div class="card-meta">${badge}${hint}</div>
    ${body}
  `;

  if (hasBody) {
    card.addEventListener("click", () => card.classList.toggle("expanded"));
  }
  return card;
}

function renderBoard() {
  const board = document.getElementById("board");
  board.innerHTML = "";

  const cols = showDone
    ? [...ALWAYS_COLS, { id: "done", label: "Done" }]
    : ALWAYS_COLS;

  for (const col of cols) {
    const tasks = TASKS.filter(t => t.status === col.id);

    const colEl = document.createElement("div");
    colEl.className = "column";
    colEl.innerHTML = `
      <div class="column-header">
        <span class="column-title">${col.label}</span>
        <span class="column-count">${tasks.length}</span>
      </div>
      <div class="column-cards" id="col-${col.id}"></div>
    `;
    board.appendChild(colEl);

    const cardsEl = colEl.querySelector(".column-cards");
    if (tasks.length === 0) {
      cardsEl.innerHTML = '<div class="empty-col">—</div>';
    } else {
      tasks.forEach(t => cardsEl.appendChild(renderCard(t)));
    }
  }
}

document.getElementById("toggle-done").addEventListener("click", () => {
  showDone = !showDone;
  document.getElementById("toggle-done").textContent = showDone ? "Hide done" : "Show done";
  renderBoard();
});

renderBoard();
</script>
</body>
</html>
"""


def main() -> None:
    tasks = load_tasks()
    print(f"  loaded {len(tasks)} tasks")

    tasks_json = json.dumps(tasks, ensure_ascii=False, indent=None)
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
