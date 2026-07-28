"""The renderer + ingest + fold primitives built on `session_store`'s reader.

`render` always returns the store's own `send`-role render (never its `live` input);
`ingest` appends the length-sliced tail of a live message list with no position or
payload-hash diffing; `fold` mints (or reuses) one synthesized frontier row per fold
boundary, keyed by a store query rather than an in-process cache.
"""
from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from typing import Any

from pydantic_ai.messages import ModelMessagesTypeAdapter, ModelRequest, UserPromptPart

from .session_store import (  # noqa: F401 — re-exported, identity checked by the suite
    IngestTailUnderflow,
    ROLES,
    StoreAppendError,
    UnknownReadRole,
    hydrate,
    path_row_ids,
    synthesized_flags,
)


def _digest_wire(messages: list) -> str:
    dumped = ModelMessagesTypeAdapter.dump_python(messages, mode="json")
    text = json.dumps(dumped, sort_keys=True, ensure_ascii=True)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _default_boundary(store: Any, session_id: str) -> int:
    row = store.connection.execute(
        "SELECT COUNT(*) FROM message WHERE session_id = ? AND synthesized = 0",
        (session_id,),
    ).fetchone()
    return row[0]


def _fold_impl(  # noqa: PLR0913 — mint-time stamping needs the run's identity, not a patch-after
    store: Any, session_id: str, *, agent_id: str, boundary: int | None = None,
    run_id: str | None = None, conversation_id: str | None = None,
    text: str | None = None,
) -> int:
    if boundary is None:
        # correction R2/FE-2 (binding): `_default_boundary` no longer stands in as this
        # fold's placeholder default — it over-counts once a fold has displaced rows off
        # the path (FK16 / #753, deliberately unfixed here) — so a caller with no
        # boundary of its own fails closed rather than silently taking that count.
        raise ValueError(
            "boundary is required; selection.fold no longer defaults it from the "
            "session's own row count")
    existing = store.connection.execute(
        "SELECT id FROM message WHERE session_id = ? AND agent_id = ? "
        "AND synthesized = 1 AND seq = ?",
        (session_id, agent_id, boundary),
    ).fetchone()
    if existing is not None:
        return existing[0]
    ids = path_row_ids(store, session_id)
    if not ids:
        raise StoreAppendError(
            "cannot fold a session whose path is empty: there is no row for the "
            "frontier to parent onto")
    root = ids[0]
    root_session = store.connection.execute(
        "SELECT session_id FROM message WHERE id = ?", (root,)).fetchone()
    if root_session is None or root_session[0] != session_id:
        raise StoreAppendError(
            "a fold refuses to parent its frontier onto a row belonging to another "
            "session — the folding session's own lineage root must be its own row")
    # The caller owns the frontier's CONTENT (the driver passes the invlang record of the
    # loops being folded); the placeholder is a shape-only default for callers that have
    # no record to carry — a fold whose frontier says only "boundary N" discards the
    # folded turns without replacing them, so no production path should take it.
    text = text if text is not None else f"FRONTIER: fold boundary {boundary}"
    frontier = ModelRequest(
        parts=[UserPromptPart(content=text)], run_id=run_id, conversation_id=conversation_id,
        timestamp=datetime.now(UTC),
    )
    new_ids = store.append(session_id, [frontier], agent_id=agent_id,
                           synthesized=True, parent_id=root, seq=boundary, reason="fold")
    return new_ids[0]


def fold(store: Any, session_id: str, *, agent_id: str, boundary: int | None = None,
         text: str | None = None) -> int:
    return _fold_impl(store, session_id, agent_id=agent_id, boundary=boundary, text=text)


def fold_boundary(store: Any, session_id: str) -> Any:
    boundary = _default_boundary(store, session_id)
    row = store.connection.execute(
        "SELECT id FROM message WHERE session_id = ? AND synthesized = 1 AND seq = ?",
        (session_id, boundary),
    ).fetchone()
    return row[0] if row is not None else boundary


def _current_tip(store: Any, session_id: str) -> int | None:
    ids = path_row_ids(store, session_id)
    return ids[-1] if ids else None


def ingest(store: Any, session_id: str, live: list, *, agent_id: str) -> list[int]:
    last = store.last_render_len(session_id) or 0
    if len(live) < last:
        raise IngestTailUnderflow(
            f"live has {len(live)} message(s), shorter than the last render ({last})")
    tail = live[last:]
    store.set_last_render_len(session_id, len(live))
    if not tail:
        return []

    parent = _current_tip(store, session_id)
    pending = getattr(store, "pending_stamps", None)
    stamp = pending.pop(session_id, None) if pending is not None else None
    stamp_used = False

    ids: list[int] = []
    for message in tail:
        kwargs: dict = {}
        if stamp is not None and not stamp_used and isinstance(message, ModelRequest):
            run_step, duration_ms, wire_sha = stamp
            kwargs = {"run_step": run_step, "duration_ms": duration_ms, "wire_sha": wire_sha}
            stamp_used = True
        new_ids = store.append(session_id, [message], agent_id=agent_id,
                               parent_id=parent, **kwargs)
        parent = new_ids[0]
        ids.extend(new_ids)
    return ids


def render(  # noqa: PLR0913 — the renderer's full parameter set
    store: Any, session_id: str, live: list, *, agent_id: str, fold: bool,  # noqa: A002
    run_step: int | None = None, duration_ms: float | None = None,
    run_id: str | None = None, conversation_id: str | None = None,
    boundary: int | None = None, text: str | None = None,
) -> list:
    if fold:
        _fold_impl(store, session_id, agent_id=agent_id, run_id=run_id,
                   conversation_id=conversation_id, boundary=boundary, text=text)
    rendered = hydrate(store, session_id, role="send")
    store.set_last_render_len(session_id, len(rendered))
    if run_step is not None:
        pending = getattr(store, "pending_stamps", None)
        if pending is not None:
            pending[session_id] = (run_step, duration_ms, _digest_wire(rendered))
    return rendered
