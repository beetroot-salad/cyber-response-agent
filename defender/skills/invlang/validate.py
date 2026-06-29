"""Structural validator for defender ```invlang investigation blocks.

Importable rule engine. The runtime invokes `validate_companion` in-process
from `runtime/permission.py` before an `investigation.md` write commits
(raising `ModelRetry` with the errors on a violation); the learning loop and
corpus queries import the same rules. Tests import this module directly.

This is the defender analogue of soc-agent's `invlang_validate.py` +
`invlang_checks_*` family, adapted to the *defender* invlang schema
(`defender/skills/invlang/SKILL.md`). The two invlangs share the
`++/+/-/--` vocabulary and the edge-authority idea but differ in block
shape, so the rules are reimplemented against the defender parser's
canonical companion dict (the shared walkers live in `_walkers.py`)
rather than ported line-for-line.

Design: the defender parser (`parser.parse_dense_companion`) is
deliberately *lenient* — it collects per-row `ParseWarning`s and keeps
going so the offline learning loop always gets a partial companion.
This validator promotes that leniency to *enforcement* at write time:
a structural parse warning blocks the write instead of silently
degrading the on-disk record. Line endings are normalized first so a
CRLF file can't slip past the fence regex into a no-op pass.

Rules (all blocking):

0. surface         — line endings are normalized; a ```yaml/```yml fence
                     in investigation.md is rejected (the on-disk surface
                     is ```invlang), so a non-invlang write can't bypass
                     every rule by yielding an empty companion.
1. parse-clean     — any ParseWarning from the parser blocks the write.
2. append-only     — proposed must not drop ```invlang blocks vs on-disk,
                     and no committed vertex/edge (by id) may be mutated
                     or removed.
3. edge-authority  — a `:T resolutions` row reaching ``++``/``--`` must
                     cite a supporting edge whose ``auth_kind`` is one of
                     siem-event / runtime-audit / authoritative-source.
4. closed-vocab    — vertex ``type``, edge ``rel``, authz ``anchor_kind``,
                     edge ``auth_kind``, and ``:R attr_updates`` keys must
                     be drawn from `vocab` / the `class` | `attrs.<name>`
                     key grammar.
5. benign-gating   — ``disposition: benign`` requires (a) no unresolved
                     ``??`` slot/attr or ``{a,b}`` candidate-set on any
                     vertex and (b) every authz contract on a *live*
                     (not ``--``-refuted) hypothesis resolved
                     ``authorized``. Survival is computed from the
                     resolution record (``:T conclude`` carries no
                     sub-tables).
6. loop-close      — a ``:T close loop=N`` (the per-loop compaction
                     boundary marker) requires loop N to carry ≥1 committed
                     finding, and a loop may not be closed twice. Blocks
                     authoring a close over a bare drafted loop, so the
                     compaction fold can never freeze an empty loop.

Deferred (tracked as follow-ups, intentionally NOT enforced here):
per-type class-slot grammar vocab (the slot enums behind ``compute`` etc.)
and sibling-fork topological uniqueness — both blocked on spec
self-contradictions; see `docs/decisions/defender-invlang-enforcement-ramp.md`.
"""

from __future__ import annotations

import re
from typing import Any

from . import _walkers, vocab
from .parser import INVLANG_FENCE_RE, parse_dense_companion
from .schema import CompanionBody, EdgeRecord, VertexRecord

# Only these observational-authority kinds can carry a ``++``/``--``
# resolution (defender SKILL §Core blocks). Sourced from `vocab` so the
# strong-authority subset and the ladder endpoints have one definition.
STRONG_AUTH_KINDS = vocab.STRONG_AUTH_KINDS
STRONG_WEIGHTS = vocab.STRONG_WEIGHTS

# A ```yaml / ```yml fence in investigation.md is the spec-rejected
# surface (the on-disk surface is ```invlang). Caught explicitly so a
# yaml-fenced or prose write can't yield an empty companion and pass.
_YAML_FENCE_RE = re.compile(r"```ya?ml\b")


def _normalize_newlines(text: str) -> str:
    """CRLF/CR → LF so the ```invlang fence regex (which keys on ``\\n``)
    can't be defeated by Windows line endings, silently turning every
    rule into a no-op pass over an empty companion."""
    return text.replace("\r\n", "\n").replace("\r", "\n")


# ---------------------------------------------------------------------------
# Rule 0 — surface
# ---------------------------------------------------------------------------


def _check_surface(proposed_text: str) -> list[str]:
    if _YAML_FENCE_RE.search(proposed_text):
        return [
            "non-invlang surface: investigation.md contains a ```yaml/```yml "
            "fenced block, but the on-disk surface is ```invlang (defender "
            "SKILL §dense format). Rewrite the block(s) as ```invlang."
        ]
    return []


# ---------------------------------------------------------------------------
# Rule 2 — append-only (block count + record-level immutability)
# ---------------------------------------------------------------------------


def _vertex_core(v: VertexRecord) -> tuple:
    return (v.get("type"), v.get("classification"), v.get("identifier"))


def _auth_kind(e: EdgeRecord) -> str | None:
    """The observational authority ``kind`` on an edge, or None when the edge
    carries no authority cell."""
    auth = e.get("authority")
    return auth.get("kind") if auth else None


def _edge_core(e: EdgeRecord) -> tuple:
    return (
        e.get("relation"),
        e.get("source_vertex"),
        e.get("target_vertex"),
        _auth_kind(e),
    )


def _by_id_first(records, core_fn) -> dict[str, tuple]:
    """Map id → immutable core, keeping the FIRST declaration per id (the
    committed record; a later same-id observation is an addition, not a
    mutation of the original row)."""
    idx: dict[str, tuple] = {}
    for r in records:
        rid = r.get("id")
        if isinstance(rid, str) and rid not in idx:
            idx[rid] = core_fn(r)
    return idx


def _check_append_only(
    proposed_text: str,
    current_text: str | None,
    proposed: CompanionBody | None,
    current: CompanionBody | None,
) -> list[str]:
    if current_text is None:
        return []
    errors: list[str] = []

    cur_fences = len(INVLANG_FENCE_RE.findall(current_text))
    new_fences = len(INVLANG_FENCE_RE.findall(proposed_text))
    if new_fences < cur_fences:
        errors.append(
            f"append-only violation: proposed content has {new_fences} ```invlang "
            f"block(s) but the on-disk file has {cur_fences} — existing blocks must "
            f"not be removed (defender SKILL §Authoring discipline: append only)"
        )

    if not current:
        return errors

    # Record-level immutability: a committed vertex/edge (by id) may gain
    # later observations/attr_updates but its original declaration row must
    # not be rewritten or dropped. Catches in-fence mutation that the block
    # count misses.
    proposed = proposed or CompanionBody()
    for label, records_cur, records_new, core_fn in (
        ("vertex", _walkers.all_vertices(current), _walkers.all_vertices(proposed), _vertex_core),
        ("edge", _walkers.all_edges(current), _walkers.all_edges(proposed), _edge_core),
    ):
        cur_idx = _by_id_first(records_cur, core_fn)
        new_idx = _by_id_first(records_new, core_fn)
        for rid, core in cur_idx.items():
            if rid not in new_idx:
                errors.append(
                    f"append-only violation: committed {label} {rid} present "
                    f"on-disk is missing from the proposed write — existing "
                    f"records must not be removed"
                )
            elif new_idx[rid] != core:
                errors.append(
                    f"append-only violation: committed {label} {rid} was "
                    f"mutated in place ({core} → {new_idx[rid]}) — refine via a "
                    f"new :R attr_updates / observation row, never by rewriting "
                    f"the original declaration"
                )
    return errors


# ---------------------------------------------------------------------------
# Rule 3 — edge authority
# ---------------------------------------------------------------------------


def _check_edge_authority(companion: CompanionBody) -> list[str]:
    """A resolution reaching ``++``/``--`` must cite a strong-authority edge."""
    auth_by_edge: dict[str, str] = {}
    for e in _walkers.all_edges(companion):
        eid = e.get("id")
        kind = _auth_kind(e)
        if isinstance(eid, str) and isinstance(kind, str):
            auth_by_edge[eid] = kind

    errors: list[str] = []
    for lid, res in _walkers.iter_resolutions(companion):
        after = res.get("after")
        if after not in STRONG_WEIGHTS:
            continue
        hyp = res.get("hypothesis", "?")
        supporting = [s for s in (res.get("supporting_edges") or []) if isinstance(s, str)]
        if not supporting:
            errors.append(
                f"lead {lid}: resolution of {hyp} to {after!r} cites no "
                f"supporting edge — a strong (++/--) resolution must cite at "
                f"least one siem-event / runtime-audit / authoritative-source edge"
            )
            continue
        if not any(auth_by_edge.get(s) in STRONG_AUTH_KINDS for s in supporting):
            seen = sorted({auth_by_edge.get(s, "<unknown>") for s in supporting})
            errors.append(
                f"lead {lid}: resolution of {hyp} to {after!r} cites "
                f"{supporting} but none carry strong observational authority "
                f"(found: {seen}); ++/-- needs siem-event / runtime-audit / "
                f"authoritative-source"
            )
    return errors


# ---------------------------------------------------------------------------
# Rule 4 — closed vocabulary (flat slots only)
# ---------------------------------------------------------------------------


def _check_vocab(value: Any, allowed: Any, errmsg: str) -> list[str]:
    """Return `[errmsg]` if `value` is a non-empty string drawn from outside
    `allowed`, else `[]`. The flat closed-vocab guard shared across every
    slot check below."""
    if isinstance(value, str) and value and value not in allowed:
        return [errmsg]
    return []


def _check_vocab_vertices(companion: CompanionBody) -> list[str]:
    """`type` slot on every vertex must be a known vertex type."""
    errors: list[str] = []
    for v in _walkers.all_vertices(companion):
        t = v.get("type")
        errors += _check_vocab(
            t, vocab.TYPES,
            f"vertex {v.get('id', '?')}: type {t!r} is not a known vertex "
            f"type (`enum types`)",
        )
    return errors


def _check_vocab_edges(companion: CompanionBody) -> list[str]:
    """`relation` + observational `authority.kind` slots on every edge."""
    errors: list[str] = []
    for e in _walkers.all_edges(companion):
        rel = e.get("relation")
        errors += _check_vocab(
            rel, vocab.RELATIONS,
            f"edge {e.get('id', '?')}: rel {rel!r} is not a known relation "
            f"(`enum relations`)",
        )
        kind = _auth_kind(e)
        errors += _check_vocab(
            kind, vocab.AUTH_KINDS,
            f"edge {e.get('id', '?')}: auth_kind {kind!r} is not a known "
            f"observational authority (`enum auth-kinds`)",
        )
    return errors


def _check_vocab_hypotheses(companion: CompanionBody) -> list[str]:
    """Proposed parent vertices on hypotheses also carry a type + relation."""
    errors: list[str] = []
    for h in _walkers.all_hypotheses(companion).values():
        pv = (h.get("proposed_edge") or {}).get("parent_vertex") or {}
        pt = pv.get("type")
        errors += _check_vocab(
            pt, vocab.TYPES,
            f"hypothesis {h.get('id', '?')}: parent_type {pt!r} is not a "
            f"known vertex type (`enum types`)",
        )
        rel = (h.get("proposed_edge") or {}).get("relation")
        errors += _check_vocab(
            rel, vocab.RELATIONS,
            f"hypothesis {h.get('id', '?')}: rel {rel!r} is not a known "
            f"relation (`enum relations`)",
        )
    return errors


def _check_vocab_anchor_kinds(companion: CompanionBody) -> list[str]:
    """anchor_kind on contracts and on authz resolutions."""
    errors: list[str] = []
    for h in _walkers.all_hypotheses(companion).values():
        for c in h.get("authorization_contract") or []:
            if not isinstance(c, dict):
                continue
            ak = c.get("anchor_kind")
            errors += _check_vocab(
                ak, vocab.ANCHOR_KINDS,
                f"hypothesis {h.get('id', '?')} contract "
                f"{c.get('id', '?')}: anchor_kind {ak!r} is not known "
                f"(`enum anchor-kinds`)",
            )
    for row in _walkers.iter_authz_resolutions(companion):
        row_ak = row.get("anchor_kind")
        errors += _check_vocab(
            row_ak, vocab.ANCHOR_KINDS,
            f"authz resolution for contract {row.get('fulfills_contract', '?')}: "
            f"anchor_kind {row_ak!r} is not known (`enum anchor-kinds`)",
        )
    return errors


def _check_attr_update_keys(companion: CompanionBody) -> list[str]:
    """`:R attr_updates` key grammar: only `class` or `attrs.<name>` (defender
    SKILL §Open-questions). A bare key (e.g. `provenance`) is silently
    dropped by the resolver, so reject it at write time rather than let it
    land as a no-op refinement."""
    errors: list[str] = []
    for upd in _walkers.iter_attr_updates(companion):
        tgt = upd.get("target", "?")
        for key in (upd.get("updates") or {}):
            if key == "class" or (isinstance(key, str) and key.startswith("attrs.")):
                continue
            errors.append(
                f":R attr_updates on {tgt}: key {key!r} is not a valid "
                f"refinement key — use `class` (class refinement) or "
                f"`attrs.<name>` (attribute); a bare key is dropped silently"
            )
    return errors


def _check_closed_vocab(companion: CompanionBody) -> list[str]:
    errors: list[str] = []
    errors += _check_vocab_vertices(companion)
    errors += _check_vocab_edges(companion)
    errors += _check_vocab_hypotheses(companion)
    errors += _check_vocab_anchor_kinds(companion)
    errors += _check_attr_update_keys(companion)
    return errors


# ---------------------------------------------------------------------------
# Rule 5 — benign disposition gating
# ---------------------------------------------------------------------------


def _has_open_slot(classification: Any) -> bool:
    """True if the class is still unresolved: any ``/``-delimited slot is the
    ``??`` marker, or the whole value is an unresolved ``{a, b}`` candidate
    set (the narrowed-but-not-concrete middle state of the
    ``??`` → ``{a,b}`` → concrete model)."""
    if not isinstance(classification, str) or not classification:
        return False
    c = classification.strip()
    if c.startswith("{") and c.endswith("}") and "," in c:
        return True
    return any(slot.strip() == "??" for slot in c.split("/"))


def _seed_vertex_state(
    companion: CompanionBody, state: dict[str, dict[str, Any]]
) -> None:
    """First pass — baseline per-vertex {classification, attributes} from the
    `:V` declarations themselves. First declaration wins as the baseline; a
    later observation may carry attributes, and may *refine* an open baseline
    with a concrete reading (append-only: the original `??` row stays; the lead
    observes the resolved class). It can never un-resolve a concrete baseline."""
    for v in _walkers.all_vertices(companion):
        vid = v.get("id")
        if not isinstance(vid, str):
            continue
        cls = v.get("classification", "")
        # First declaration wins as the baseline; updates layer on top.
        cur = state.setdefault(
            vid,
            {"classification": cls, "attributes": dict(v.get("attributes") or {})},
        )
        # A later observation may carry attributes, and may *refine* an open
        # baseline with a concrete reading (append-only: the original `??`
        # row stays; the lead observes the resolved class). It can never
        # un-resolve a concrete baseline.
        if cls and _has_open_slot(cur["classification"]) and not _has_open_slot(cls):
            cur["classification"] = cls
        if v.get("attributes"):
            cur["attributes"].update(v["attributes"])


def _apply_attr_updates(
    companion: CompanionBody, state: dict[str, dict[str, Any]]
) -> None:
    """Second pass — layer `:R attr_updates` on top of the baseline. Key
    ``class`` overrides classification; key ``attrs.<name>`` overrides an
    attribute."""
    for upd in _walkers.iter_attr_updates(companion):
        tgt = upd.get("target")
        updates = upd.get("updates") or {}
        if not isinstance(tgt, str) or not isinstance(updates, dict):
            continue
        st = state.setdefault(tgt, {"classification": "", "attributes": {}})
        for key, val in updates.items():
            if key == "class":
                st["classification"] = val
            elif isinstance(key, str) and key.startswith("attrs."):
                st["attributes"][key[len("attrs."):]] = val


def _effective_vertex_state(
    companion: CompanionBody,
) -> dict[str, dict[str, Any]]:
    """Per-vertex effective {classification, attributes} after attr_updates.

    `:R attr_updates` with key ``class`` overrides classification; key
    ``attrs.<name>`` overrides an attribute. Mirrors the parser's own
    three-state ``??`` → ``{a,b}`` → concrete resolution model.
    """
    state: dict[str, dict[str, Any]] = {}
    _seed_vertex_state(companion, state)
    _apply_attr_updates(companion, state)
    return state


def _check_benign_open_slots(companion: CompanionBody) -> list[str]:
    """(a) no unresolved ?? / {a,b} on any vertex (class or attribute)."""
    errors: list[str] = []
    for vid, st in _effective_vertex_state(companion).items():
        if _has_open_slot(st["classification"]):
            errors.append(
                f"disposition benign blocked: vertex {vid} still has an "
                f"unresolved class ({st['classification']!r}) — resolve via "
                f":R attr_updates or escalate"
            )
        for name, val in st["attributes"].items():
            if isinstance(val, str) and val.strip() == "??":
                errors.append(
                    f"disposition benign blocked: vertex {vid} attribute "
                    f"{name!r} is still `??` — resolve via :R attr_updates or "
                    f"escalate"
                )
    return errors


def _check_benign_authz(companion: CompanionBody) -> list[str]:
    """(b) every authz contract on a LIVE hypothesis resolved authorized.
    Survival is computed from final weights (`:T conclude` carries no
    sub-tables), so an unauthorized contract can't slip through by being
    omitted from a restated survivors list."""
    errors: list[str] = []
    live = set(_walkers.live_hypothesis_ids(companion))
    hyps = _walkers.all_hypotheses(companion)

    # Conservative per-contract verdict: a contract counts authorized only if
    # it has ≥1 fulfilling `:R authz` row AND none of its rows are
    # non-authorized — a later `authorized` row must not mask an earlier
    # `unauthorized`/`indeterminate`.
    verdicts: dict[str, list[str]] = {}
    for row in _walkers.iter_authz_resolutions(companion):
        cid = row.get("fulfills_contract")
        if isinstance(cid, str):
            verdicts.setdefault(cid, []).append(row.get("verdict", "indeterminate"))

    for hid in sorted(live):
        hyp = hyps.get(hid)
        if hyp is None:
            continue
        for c in hyp.get("authorization_contract") or []:
            if not isinstance(c, dict):
                continue
            cid = c.get("id", "?")
            rows = verdicts.get(cid)
            if not rows:
                errors.append(
                    f"disposition benign blocked: authz contract {cid} on "
                    f"live hypothesis {hid} resolved 'no fulfilling :R authz "
                    f"row', not 'authorized' — benign requires every contract "
                    f"authorized"
                )
            elif any(v != "authorized" for v in rows):
                bad = next(v for v in rows if v != "authorized")
                errors.append(
                    f"disposition benign blocked: authz contract {cid} on "
                    f"live hypothesis {hid} resolved {bad!r}, not 'authorized' "
                    f"— benign requires every contract authorized"
                )
    return errors


def _check_benign_gating(companion: CompanionBody) -> list[str]:
    conclude = companion.get("conclude") or {}
    if conclude.get("disposition") != "benign":
        return []

    errors: list[str] = []
    errors += _check_benign_open_slots(companion)
    errors += _check_benign_authz(companion)
    return errors


# ---------------------------------------------------------------------------
# Rule 6 — loop-close integrity
# ---------------------------------------------------------------------------


def _check_loop_close(companion: CompanionBody) -> list[str]:
    """A `:T close loop=N` marks loop N complete (the per-loop compaction
    boundary). Block writing one that the fold must never honor:

    - *No empty close.* Loop N must already carry ≥1 committed finding (any
      lead with an `outcome` or a `:T resolutions` entry). This moves the
      draft-ahead guard to write time — the agent cannot author a close over a
      bare planned loop, so `fold_boundary` can never freeze an empty loop.
    - *No double close.* A loop closes once; a second `:T close` for the same
      loop is a mistake (append-only would otherwise let two accumulate).

    Mirrors `runtime/compaction._lead_resolved`'s notion of "committed" without
    importing runtime code (the invlang layer stays below the runtime)."""
    closed = companion.get("closed_loops") or []
    if not closed:
        return []
    resolved_by_loop: dict[int, bool] = {}
    for f in companion.get("findings", []):
        loop = f.get("loop")
        if isinstance(loop, int):
            committed = bool(f.get("resolutions")) or bool(f.get("outcome"))
            resolved_by_loop[loop] = resolved_by_loop.get(loop, False) or committed
    errors: list[str] = []
    seen: set[int] = set()
    for n in closed:
        if n in seen:
            errors.append(f":T close blocked: loop {n} closed more than once")
        seen.add(n)
        if not resolved_by_loop.get(n, False):
            errors.append(
                f":T close blocked: loop {n} has no committed finding "
                f"— cannot close an empty/drafted loop"
            )
    return errors


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def validate_companion(
    proposed_text: str, current_text: str | None = None
) -> list[str]:
    """Validate the proposed investigation.md text. Empty list = pass.

    `current_text` is the pre-write on-disk content (for append-only);
    pass None on first write.
    """
    proposed_text = _normalize_newlines(proposed_text)
    if current_text is not None:
        current_text = _normalize_newlines(current_text)

    errors: list[str] = []
    errors.extend(_check_surface(proposed_text))

    companion, warnings = parse_dense_companion(proposed_text)
    current_companion: CompanionBody | None = None
    if current_text is not None:
        current_companion, _ = parse_dense_companion(current_text)

    # Rule 2 runs even if the proposed text has no blocks (e.g. an Edit that
    # would blow them away — caught by the block-count drop).
    errors.extend(
        _check_append_only(proposed_text, current_text, companion, current_companion)
    )

    # Rule 1 — promote lenient parse warnings to blocking errors.
    for w in warnings:
        errors.append(f"parse error: {w.format()}")

    if not companion:
        return errors

    errors.extend(_check_edge_authority(companion))
    errors.extend(_check_closed_vocab(companion))
    errors.extend(_check_benign_gating(companion))
    errors.extend(_check_loop_close(companion))
    return errors
