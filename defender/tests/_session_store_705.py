"""Shared machinery for the #705 session-store spec suite — NO test scripts.

`runtime/session_store.py` and `runtime/selection.py` do not exist at the base this
spec forks from (`4e4645aa`); this module is the single place that names them, so a
missing target produces one failure *per test* rather than one collection error per
file, and — under `spec-graph nullstub` — every test still reaches its own
demand-specific assertion instead of dying in a shared fixture.

Three things live here and nothing else:

1. **The imports** (`store_mod()` / `selection_mod()`), called per test.
2. **Message and fixture builders** — the nine-row path-exactness fixture, the
   mid-pair session the truncation demands turn on, the part-kind zoo.
3. **`FaultStore`** — the one declarative fault-injection fake, entering through the
   store-factory seam R12 authorized on `run_investigation`. It **injects faults
   only**; it classifies nothing and decides no policy. Its fault content is not an
   authored exception taxonomy: every fault is realized by doing something real to
   the real SQLite file (unlink it, overwrite it with non-database bytes, hold a
   genuine `BEGIN EXCLUSIVE` on a second real connection) and letting the real
   `sqlite3` primitive raise whatever it actually raises. That keeps the fault at
   tier 1 of the author charge's hierarchy — the test re-probes reality on every
   run — while still steering *when* the failure lands, which environment steering
   cannot express (R12's stated reason for the seam).

Ledger citations for the faults this module can produce:
  * `absent` / `corrupt`  — real primitive, induced in-test (no claim needed: the
    exception is not authored, it is observed live).
  * `locked`              — real primitive; `life:po7` shape (3) observed a writer
    holding an uncommitted insert against a concurrent connection. What a contention
    that outlasts `busy_timeout` does is `auth:P7`, **unprobed** — so no test here
    asserts a *specific* exception class for it; the demand asserts the run stops
    through a handled exit, whatever SQLite raises.
  * `disk-full`           — real primitive; `rp-c1` (EXECUTED) measured what the
    installed sqlite3 raises when the database cannot grow:
    `sqlite3.OperationalError("database or disk is full")`, `SQLITE_FULL`/13 — the
    same error a genuinely full filesystem produces for the database file, with
    already-committed rows still readable (exhaustion, not corruption). The same
    probe measured that the ceiling is PER-CONNECTION (so it is applied to the
    store's own handle) and that once the freelist is exhausted an append of a
    render-boundary-sized payload fails on the very next call: 0 survivors in 8/8
    trials at >=5 KB, against real per-append payloads of 33-60 KB in the scenario
    `store_append_is_fail_closed` drives. `auth:P7` stays unprobed and `rp-c1` does
    not stand in for it.
"""
from __future__ import annotations

import importlib
import json
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.messages import (  # noqa: E402
    ModelRequest,
    ModelResponse,
    SystemPromptPart,
    TextPart,
    ThinkingPart,
    ToolCallPart,
    ToolReturnPart,
    UserPromptPart,
)

DEFENDER = Path(__file__).resolve().parents[1]


# --------------------------------------------------------------------------
# the two new targets, imported per test
# --------------------------------------------------------------------------

def store_mod():
    """`defender.runtime.session_store` — M1's module."""
    return importlib.import_module("defender.runtime.session_store")


def selection_mod():
    """`defender.runtime.selection` — M2's module."""
    return importlib.import_module("defender.runtime.selection")


# --------------------------------------------------------------------------
# message builders — real ModelMessage objects, never dicts
# --------------------------------------------------------------------------

def user_request(text: str = "investigate", *, instructions: str | None = None) -> ModelRequest:
    parts: list[Any] = [UserPromptPart(content=text)]
    if instructions is not None:
        parts.insert(0, SystemPromptPart(content=instructions))
    return ModelRequest(parts=parts)


def text_response(text: str = "thinking about it") -> ModelResponse:
    return ModelResponse(parts=[TextPart(content=text)])


def tool_call_response(tool_name: str = "read_file", args: Any = None,
                       *, tool_call_id: str = "call-1") -> ModelResponse:
    return ModelResponse(parts=[ToolCallPart(
        tool_name=tool_name, args=args if args is not None else {"path": "/tmp/alert.json"},
        tool_call_id=tool_call_id,
    )])


def tool_return_request(tool_name: str = "read_file", content: str = "{}",
                        *, tool_call_id: str = "call-1") -> ModelRequest:
    return ModelRequest(parts=[ToolReturnPart(
        tool_name=tool_name, content=content, tool_call_id=tool_call_id,
    )])


def thinking_response(content: str = "hmm") -> ModelResponse:
    return ModelResponse(parts=[ThinkingPart(content=content)])


def part_kind_zoo() -> list[Any]:
    """One message per part kind the runtime actually produces — the round-trip
    demand's subject set (O5/C14)."""
    return [
        user_request("investigate the alert", instructions="SKILL.md resolved body"),
        thinking_response("weighing the two hypotheses"),
        tool_call_response("query", {"system": "elastic", "verb": "probe", "params": {}}),
        tool_return_request("query", json.dumps({"hits": [1, 2, 3]})),
        text_response("done"),
    ]


def complete_pair() -> list[Any]:
    """A (response with a tool call, request carrying its returns) pair — the legal
    cut unit O10 names."""
    return [tool_call_response(), tool_return_request()]


# --------------------------------------------------------------------------
# store fixtures
# --------------------------------------------------------------------------

def runs_base(tmp_path: Path) -> Path:
    base = tmp_path / "defender-runs"
    base.mkdir(parents=True, exist_ok=True)
    return base


def make_store(tmp_path: Path, *, case_id: str = "case-alpha"):
    """Open a real per-case store under a real runs base."""
    ss = store_mod()
    return ss.open_store(case_id=case_id, runs_base=runs_base(tmp_path))


def sql(store, query: str, params: tuple = ()) -> list[tuple]:
    """Read rows straight out of the real file — the observation channel that does
    not go through the reader under test."""
    return list(store.connection.execute(query, params).fetchall())


def mid_pair_session(store, *, agent_id: str = "main"):
    """A session whose last row is an unanswered `ModelResponse` carrying a tool call
    — the shape every truncation demand turns on.

    Returns `(session_id, n_complete_messages)`, where `n_complete_messages` is the
    length of the path up to and including the last COMPLETE pair.
    """
    session_id = store.new_session(agent_id=agent_id)
    complete = [
        user_request("investigate"),
        tool_call_response("read_file", {"path": "/tmp/alert.json"}, tool_call_id="c1"),
        tool_return_request("read_file", "{}", tool_call_id="c1"),
    ]
    store.append(session_id, complete, agent_id=agent_id)
    store.append(session_id,
                 [tool_call_response("query", {"system": "elastic"}, tool_call_id="c2")],
                 agent_id=agent_id)
    return session_id, len(complete)


def nine_row_fixture(store, *, folded_body: str = "pre-fold chatter"):
    """Invariant 7's fixture, built as rows in a real store.

    Nine messages; `main` tips at row 7, `fork-a` tips at row 9, and the synthesized
    frontier (row 5) is parented to the ROOT (row 1), so the folded turns 2,3,4 lie
    on no path from any tip. Returns `{"row_ids": [...], "main": sid, "fork_a": sid}`
    with `row_ids` 1-indexed by the fixture's own numbering.

    `folded_body` is the text of row 4 — an OFF-PATH row after the fold. A caller that
    needs to observe whether some read path can reach a folded row passes a marker
    here, so the observation is over content this fixture demonstrably wrote rather
    than over a string nobody put in the store.
    """
    main = store.new_session(agent_id="main")
    ids: dict[int, int] = {}
    ids[1] = store.append(main, [user_request("orientation")], agent_id="main")[0]
    ids[2] = store.append(main, [tool_call_response("read_file", tool_call_id="t2")],
                          agent_id="main", parent_id=ids[1])[0]
    ids[3] = store.append(main, [tool_return_request("read_file", tool_call_id="t2")],
                          agent_id="main", parent_id=ids[2])[0]
    ids[4] = store.append(main, [text_response(folded_body)],
                          agent_id="main", parent_id=ids[3])[0]
    # the fold: the frontier is re-parented to the ROOT, orphaning 2,3,4. `reason="fold"` is
    # #754's, not #705's: re-parenting off the session's head is a NON-LINEAR move under the
    # head-pointer rule, and a non-linear move with no reason is refused (obligation 7). The
    # fixture hand-builds a fold, so it hands over the reason a fold hands over.
    ids[5] = store.append(main, [user_request("FRONTIER: summary of turns 2-4")],
                          agent_id="main", synthesized=True, parent_id=ids[1],
                          reason="fold")[0]
    ids[6] = store.append(main, [tool_call_response("query", tool_call_id="t6")],
                          agent_id="main", parent_id=ids[5])[0]
    ids[7] = store.append(main, [tool_return_request("query", tool_call_id="t6")],
                          agent_id="main", parent_id=ids[6])[0]
    fork_a = store.fork(main, at_message_id=ids[6])
    ids[8] = store.append(fork_a, [tool_return_request("query", tool_call_id="t6")],
                          agent_id="main", parent_id=ids[6])[0]
    ids[9] = store.append(fork_a, [text_response("fork-a continues")],
                          agent_id="main", parent_id=ids[8])[0]
    return {"row_ids": ids, "main": main, "fork_a": fork_a}


# --------------------------------------------------------------------------
# THE fault-injection fake — one per dependency, driven by data
# --------------------------------------------------------------------------

@dataclass
class StoreFault:
    """A data fault-spec. `mode` names WHAT is done to the real file; `on` and
    `after` name WHEN. Nothing here is an exception class: the real `sqlite3`
    primitive raises whatever it really raises once the file is in that state."""

    on: str = "append"          # "append" | "read" | "open"
    after: int = 1              # let this many successful calls through first
    mode: str = "absent"        # "absent" | "corrupt" | "locked" | "disk-full"
    #: How long the store's REAL connection is allowed to block on the `locked` fault's real
    #: `BEGIN EXCLUSIVE` before the real `sqlite3` gives up. Ignored by every other mode.
    #:
    #: Short by default, and that is not a weakening: `auth:P7` (what a contention outlasting
    #: `busy_timeout` does) is UNPROBED, so no demand here asserts an exception class OR a
    #: wait — only that the run stops. The wait is still real, still served by the real engine,
    #: and still outlasted; only its length is pinned. At the shipped
    #: `session_store.STORE_BUSY_TIMEOUT_MS` (30s) the two blocked appends in
    #: `test_store_append_is_fail_closed[locked]` cost 60s — 13% of CI's whole unit-test step,
    #: and the single largest test in the suite — to observe the same stop.
    busy_timeout_ms: int = 250


class FaultStore:
    """A recording, fault-injecting wrapper around a REAL store handle.

    It delegates everything to the real store, records what each seam call received,
    and — when the fault-spec says so — puts the real database file into a real
    broken state before delegating. It never raises an authored exception, never
    classifies an error and never decides whether the run should stop: that decision
    is the contract under test.
    """

    def __init__(self, real, fault: StoreFault | None = None):
        self._real = real
        self._fault = fault
        self._counts: dict[str, int] = {}
        self._lock_conn: sqlite3.Connection | None = None
        self.appends: list[dict] = []
        self.reads: list[dict] = []

    # -- observation channel -------------------------------------------------
    @property
    def appended_messages(self) -> list[Any]:
        out: list[Any] = []
        for call in self.appends:
            out.extend(call["messages"])
        return out

    # -- delegation ----------------------------------------------------------
    def __getattr__(self, name: str) -> Any:
        return getattr(self._real, name)

    def _maybe_break(self, seam: str) -> None:
        n = self._counts.get(seam, 0) + 1
        self._counts[seam] = n
        f = self._fault
        if f is None or f.on != seam or n <= f.after:
            return
        path = Path(self._real.path)
        if f.mode == "absent":
            self._real.close()
            path.unlink(missing_ok=True)
            for suffix in ("-wal", "-shm"):
                Path(str(path) + suffix).unlink(missing_ok=True)
            path.parent.chmod(0o500)
        elif f.mode == "corrupt":
            self._real.close()
            path.write_bytes(b"this is not a database, it is attacker text\n" * 64)
        elif f.mode == "locked":
            # Re-issued on the REAL connection the store is about to append through, so the
            # wait below is the engine's own busy handler on a real lock — the same code path
            # at a pinned length. Set BEFORE the lock is taken: after `BEGIN EXCLUSIVE` lands,
            # the pragma would itself have to wait out the deadline it is trying to shorten.
            self._real.connection.execute(f"PRAGMA busy_timeout = {int(f.busy_timeout_ms)}")
            self._lock_conn = sqlite3.connect(str(path), timeout=0.0)
            self._lock_conn.execute("BEGIN EXCLUSIVE")
        elif f.mode == "disk-full":
            self._fill_the_disk()
        else:  # pragma: no cover - a typo in a fault-spec must be loud
            raise AssertionError(f"unknown fault mode {f.mode!r}")

    def _fill_the_disk(self) -> None:
        """Take the real database to its real growth ceiling, with real bytes.

        The store's own connection gets its `max_page_count` dropped to the pages the
        file already occupies, and the slack left inside those pages is then consumed
        by writing real blobs until the engine refuses. From that point the file
        cannot grow and the real `sqlite3` raises its own `SQLITE_FULL` — nothing here
        names an exception class (`rp-c1`). The ceiling is per-connection, which is
        why it is applied to the handle the run actually appends through.
        """
        conn = self._real.connection
        conn.execute("CREATE TABLE IF NOT EXISTS _disk_fill (b BLOB)")
        conn.commit()
        pages = conn.execute("PRAGMA page_count").fetchone()[0]
        conn.execute("PRAGMA max_page_count = " + str(pages))
        for _ in range(4096):
            try:
                conn.execute("INSERT INTO _disk_fill (b) VALUES (?)", (b"\0" * 4096,))
                conn.commit()
            except sqlite3.OperationalError:
                conn.rollback()
                return
        raise AssertionError(  # pragma: no cover - the fake failing to establish its fault
            "the disk-full fault never took: the file kept growing past its own "
            "max_page_count ceiling, so the fault this spec asserts on was never induced")

    def append(self, session_id, messages, **kw):
        self.appends.append({"session_id": session_id, "messages": list(messages), **kw})
        self._maybe_break("append")
        return self._real.append(session_id, messages, **kw)

    def read(self, session_id, **kw):
        self.reads.append({"session_id": session_id, **kw})
        self._maybe_break("read")
        return self._real.read(session_id, **kw)

    def release(self) -> None:
        if self._lock_conn is not None:
            self._lock_conn.rollback()
            self._lock_conn.close()
            self._lock_conn = None


def store_factory(tmp_path: Path, *, fault: StoreFault | None = None,
                  case_id: str | None = None, sink: list | None = None):
    """Build the callable R12 threads through `run_investigation(store_factory=…)`.

    The factory signature IS part of the contract: `factory(case_id, run_dir)` returns
    an open per-case store handle. `sink` collects the handles the run opened so a
    scenario can assert on the rows after the run ends.
    """
    base = runs_base(tmp_path)

    def factory(run_case_id: str, run_dir: Path):
        ss = store_mod()
        real = ss.open_store(case_id=case_id or run_case_id, runs_base=base)
        handle = FaultStore(real, fault) if fault is not None else real
        if sink is not None:
            sink.append(handle)
        return handle

    return factory


# --------------------------------------------------------------------------
# small readers used by more than one script
# --------------------------------------------------------------------------

def jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def crafted_html_payload() -> str:
    """Model-authored text shaped to break out of an HTML container.

    Attacker-influenced by construction (`session_store.access` labels every payload
    lane that way); the value itself is ordinary text until something renders it.
    """
    return '</pre></div><script>window.__pwned=1</script><img src=x onerror=alert(1)>'
