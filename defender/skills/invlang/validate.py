
from __future__ import annotations

import re
from typing import Any

from . import _walkers, vocab
from .parser import INVLANG_FENCE_RE, parse_dense_companion
from .schema import CompanionBody, EdgeRecord, VertexRecord

STRONG_AUTH_KINDS = vocab.STRONG_AUTH_KINDS
STRONG_WEIGHTS = vocab.STRONG_WEIGHTS
_STRONG_AUTH_KINDS_STR = " / ".join(sorted(STRONG_AUTH_KINDS))

_YAML_FENCE_RE = re.compile(r"```ya?ml\b")


def _normalize_newlines(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")




def _check_surface(proposed_text: str) -> list[str]:
    if _YAML_FENCE_RE.search(proposed_text):
        return [
            "non-invlang surface: investigation.md contains a ```yaml/```yml "
            "fenced block, but the on-disk surface is ```invlang (defender "
            "SKILL §dense format). Rewrite the block(s) as ```invlang."
        ]
    return []




def _vertex_core(v: VertexRecord) -> tuple:
    return (v.get("type"), v.get("classification"), v.get("identifier"))


def _auth_kind(e: EdgeRecord) -> str | None:
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




def _check_edge_authority(companion: CompanionBody) -> list[str]:
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
                f"least one {_STRONG_AUTH_KINDS_STR} edge"
            )
            continue
        if not any(auth_by_edge.get(s) in STRONG_AUTH_KINDS for s in supporting):
            seen = sorted({auth_by_edge.get(s, "<unknown>") for s in supporting})
            errors.append(
                f"lead {lid}: resolution of {hyp} to {after!r} cites "
                f"{supporting} but none carry strong observational authority "
                f"(found: {seen}); ++/-- needs {_STRONG_AUTH_KINDS_STR}"
            )
    return errors




def _check_vocab(value: Any, allowed: Any, errmsg: str) -> list[str]:
    if isinstance(value, str) and value and value not in allowed:
        return [errmsg]
    return []


def _check_vocab_vertices(companion: CompanionBody) -> list[str]:
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




def _has_open_slot(classification: Any) -> bool:
    if not isinstance(classification, str) or not classification:
        return False
    c = classification.strip()
    if c.startswith("{") and c.endswith("}") and "," in c:
        return True
    return any(slot.strip() == "??" for slot in c.split("/"))


def _seed_vertex_state(
    companion: CompanionBody, state: dict[str, dict[str, Any]]
) -> None:
    for v in _walkers.all_vertices(companion):
        vid = v.get("id")
        if not isinstance(vid, str):
            continue
        cls = v.get("classification", "")
        cur = state.setdefault(
            vid,
            {"classification": cls, "attributes": dict(v.get("attributes") or {})},
        )
        if cls and _has_open_slot(cur["classification"]) and not _has_open_slot(cls):
            cur["classification"] = cls
        if v.get("attributes"):
            cur["attributes"].update(v["attributes"])


def _apply_attr_updates(
    companion: CompanionBody, state: dict[str, dict[str, Any]]
) -> None:
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
    state: dict[str, dict[str, Any]] = {}
    _seed_vertex_state(companion, state)
    _apply_attr_updates(companion, state)
    return state


def _check_benign_open_slots(companion: CompanionBody) -> list[str]:
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
    errors: list[str] = []
    live = set(_walkers.live_hypothesis_ids(companion))
    hyps = _walkers.all_hypotheses(companion)

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




def _check_loop_close(companion: CompanionBody) -> list[str]:
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




def validate_companion(
    proposed_text: str, current_text: str | None = None
) -> list[str]:
    proposed_text = _normalize_newlines(proposed_text)
    if current_text is not None:
        current_text = _normalize_newlines(current_text)

    errors: list[str] = []
    errors.extend(_check_surface(proposed_text))

    companion, warnings = parse_dense_companion(proposed_text)
    current_companion: CompanionBody | None = None
    if current_text is not None:
        current_companion, _ = parse_dense_companion(current_text)

    errors.extend(
        _check_append_only(proposed_text, current_text, companion, current_companion)
    )

    for w in warnings:
        errors.append(f"parse error: {w.format()}")

    if not companion:
        return errors

    errors.extend(_check_edge_authority(companion))
    errors.extend(_check_closed_vocab(companion))
    errors.extend(_check_benign_gating(companion))
    errors.extend(_check_loop_close(companion))
    return errors
