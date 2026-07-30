# The session head pointer and the head-move log

**Status:** design, ready for write-tests. Amends the store shipped in #705 /
#744 (`runtime/session_store.py`, `runtime/selection.py`). No data migration —
no runs exist under the current schema.

## What this changes

Today a session's conversation is defined by *insertion order*: `path_row_ids`
takes the highest-id row in the session and walks `parent_id` up from it
(`session_store.py:543-553`). This replaces that with an explicit
`session.head_message_id`, and records every **non-linear** head move —
fork and fold — in one `session_head_log` table.

Fork and fold stop being two mechanisms. Both are *a head move with a reason*.

| Operation | head move | reason | logged |
|---|---|---|---|
| ordinary turn | tip → new row | — | no (linear) |
| fork (#696) | NULL → branch point | `fork` | yes |
| fold (compaction) | old tip → frontier row | `fold` | yes |

## Why

Two defects, both structural rather than behavioural — nothing is broken in a
run today; both are load-bearing the moment #696 forks a live session.

**1. The tip is derived from an ordering convention.** "Newest row wins" is
what makes the fold work at all: `_fold_impl` appends the frontier to the same
session with `parent_id=root` (`selection.py:63-67`), and it takes over the
path only because it has the highest id. So the path is defined by an
invariant nobody states, and any future off-path append into a live session
silently re-routes the conversation. Every comparable system keeps this
explicit — ChatGPT's `current_node`, a git ref, LangGraph's checkpoint id.

**2. The fold records nothing about what it displaced.** `fork()` records its
branch point (`fork_at_message_id`, `session_store.py:96`); the fold records
no equivalent. Once head moves to the frontier, the displaced turns are
reachable from nothing, so "what did this fold cut?" is answerable only by
reconstruction. #705 sold the store partly on folded turns staying
"addressable off-path for forking, for the judge, and for the learning loop" —
addressable in principle, not addressed by any recorded edge.

### Why the branch point is recorded, not derived

Git does not store where a branch forked; `merge-base` derives it from the
shared parent chain. That does not transfer here, and the reason is specific:
**git never re-parents.** We do. If a parent session folds after being forked,
the pre-fork turns orphan, and the newest common ancestor of the two heads
collapses to the root — derivation returns the wrong answer, not no answer.
#696 forks at a GATHER boundary while the source run keeps folding, so this is
the ordinary case.

The principle, stated once so later changes can apply it:

> Reachable lineage may be derived. Unreachable lineage must be recorded — and
> folding is what makes lineage unreachable.

## Schema

```sql
CREATE TABLE session (
    session_id        TEXT PRIMARY KEY,
    case_id           TEXT NOT NULL,
    parent_session_id TEXT REFERENCES session(session_id),
    agent_id          TEXT,
    head_message_id   INTEGER REFERENCES message(id),   -- replaces fork_at_message_id
    truncated_by      TEXT,
    last_render_len   INTEGER
) STRICT;

CREATE TABLE session_head_log (
    id              INTEGER PRIMARY KEY,
    session_id      TEXT NOT NULL REFERENCES session(session_id),
    from_message_id INTEGER REFERENCES message(id),     -- NULL for a fork's first move
    to_message_id   INTEGER NOT NULL REFERENCES message(id),
    reason          TEXT NOT NULL                       -- {fork, fold}
) STRICT;
```

`fork_at_message_id` is **dropped**: a fork's branch point is the log's `fork`
entry, which is immutable where the column was not (the column stopped being
read the moment the fork appended its first row — `_session_tip`,
`session_store.py:343-357`).

`reason` is validated in Python against a module-level closed set, not a SQL
`CHECK`. A `CHECK` turns "add a third reason" into a schema migration, and
rewind/replay reasons are foreseeable.

## The non-linearity rule

The log is written by the store, not by callers deciding to log. One rule,
applied inside `append`:

> Log iff the **first** inserted row's `parent_id` is not the session's
> previous head.

It falls out correctly for every case without either call site knowing about
the log:

- first append into a fresh session — previous head NULL, `parent_id` NULL → linear, no entry;
- ordinary turn — parent is the head → linear, no entry;
- fold — frontier's parent is the root, head is elsewhere → non-linear, `fold`;
- a fork's first append — parent falls back to head, which `fork()` already set to the branch point → linear, and the branch is already recorded by the `fork` entry.

`append` gains `reason: str | None = None`. A non-linear move with no reason
raises `StoreAppendError` — fail closed, so the log cannot silently acquire
unexplained entries.

## Call-site deltas

- **`_session_tip` → `_session_head`** (`session_store.py:343`): collapses to a
  column read. The fork-fallback branch disappears; head is set at fork time.
- **`append`** (`:242`): after inserting, `UPDATE session SET head_message_id`
  to the last inserted id, inside the existing `BEGIN IMMEDIATE`; write the log
  entry in the same transaction when the rule fires.
- **`fork`** (`:223`): sets `head_message_id = at_message_id` and writes the
  `fork` entry. Body otherwise unchanged.
- **`path_row_ids`** (`:543`): read head; NULL → `[]`; else `_walk_parents`.
  The `ORDER BY id DESC LIMIT 1` goes away.
- **`_fold_impl`** (`selection.py:38`): passes `reason="fold"`. Its reuse
  lookup is untouched.
- **`_default_boundary`** (`selection.py:32`) and **`selection.fold_boundary`**
  (`:74`) are **deleted**. The first counts non-synthesized rows *in the
  session*, which over-counts off-path rows after a fold; the driver always
  passes an explicit boundary (`driver.py:354`) and `_fold_impl`'s own comment
  says no production path should take the placeholder. `selection.fold_boundary`
  has no caller at all, and its name collides confusingly with
  `compaction.fold_boundary` (a loop number, not a row id).

New reader helpers, both one-liners over the log: the displaced tip of a fold,
and a session's branch point.

## Versioning

`SCHEMA_VERSION` 1 → 2. `_SESSION_ADDED_COLUMNS` and `_migrate_session_columns`
(`session_store.py:487-493`) are **deleted** — with no runs to migrate, the
ALTER shim exists only for a case that cannot occur, and dropping it means any
pre-existing file fails closed through `_check_schema_version` instead of being
silently re-shaped.

One adjacent fix: `open_store` writes `PRAGMA user_version` only when the file
is fresh (`:510`), and `_check_schema_version` runs only from `hydrate` /
`synthesized_flags`. A stale file therefore opens cleanly and fails at first
read. Call the check in `open_store` too, so it fails at open.

## Out of scope

- **The fold reuse key** stays `(session_id, agent_id, synthesized, seq=boundary)`.
  That is FK10, settled and tested; head changes where a path starts, not when a
  frontier is reused.
- **`last_render_len` / `pending_stamps`** — still per-session, untouched.
- **FK16**, `gather_boundary`'s missing scoping predicate. This change is what
  makes the real fix (path scoping via a recursive walk from head) expressible
  in SQL, but the view is not edited here. Filed separately, blocking #696.
- **Gather legs** stay `agent_id` within one session; they are not sessions and
  get no head of their own.

## Consumers

`visualize_run.py:326-328` picks the main session by
`agent_id = 'main' ORDER BY rowid LIMIT 1`. Compaction does not multiply
sessions under this design, so the heuristic survives today — but #696 will add
sessions to the same file, so it becomes root-of-lineage
(`parent_session_id IS NULL AND agent_id = 'main'`) in this change, while the
column set is already being touched.

## What write-tests should pin

1. The path follows head, not insertion order: an off-path append with a higher
   id than head does not join the conversation.
2. A fold moves head to the frontier and logs `(old_tip → frontier, 'fold')`.
3. The displaced tip is recoverable from the log after the fold, and remains so
   after further appends.
4. A fork logs `(NULL → branch point, 'fork')`, and the entry still names the
   branch point after the parent session has folded past it — the case
   merge-base derivation gets wrong.
5. Two forks from one point produce two sessions, two `fork` entries, one shared
   branch point (the #705 uniqueness demand, re-expressed).
6. A linear turn writes **no** log entry.
7. A non-linear append with no `reason` raises, and writes neither the row nor
   the head move.
8. Head and log move in one transaction: a failed append leaves head unmoved and
   the log unwritten.
9. A store file at `user_version = 1` fails closed at `open_store`.
