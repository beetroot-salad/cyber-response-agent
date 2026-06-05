"""Structural validator for defender ```invlang investigation blocks.

Importable rule engine; the PreToolUse hook
(`defender/hooks/invlang_validate.py`) is a thin stdin→validate→exit
shim over `validate_companion`. Tests import this module directly so
the rule surface is exercised without spawning a subprocess.

This is the defender analogue of soc-agent's `invlang_validate.py` +
`invlang_checks_*` family, adapted to the *defender* invlang schema
(`defender/skills/invlang/SKILL.md`). The two invlangs share the
`++/+/-/--` vocabulary and the edge-authority idea but differ in block
shape, so the rules are reimplemented against the defender parser's
canonical companion dict rather than ported line-for-line.

Design: the defender parser (`parser.parse_dense_companion`) is
deliberately *lenient* — it collects per-row `ParseWarning`s and keeps
going so the offline learning loop always gets a partial companion.
This validator promotes that leniency to *enforcement* at write time:
a structural parse warning blocks the write instead of silently
degrading the on-disk record.

Rules (all blocking):

1. parse-clean      — any ParseWarning from the parser blocks the write.
2. append-only      — proposed must not drop ```invlang blocks vs on-disk.
3. edge-authority   — a `:T resolutions` row reaching ``++``/``--`` must
                      cite a supporting edge whose ``auth_kind`` is one of
                      siem-event / runtime-audit / authoritative-source.
4. closed-vocab     — vertex ``type``, edge ``rel``, authz ``anchor_kind``
                      and edge ``auth_kind`` must be drawn from `vocab`.
5. benign-gating    — ``disposition: benign`` requires (a) no unresolved
                      ``??`` slot/attr on any vertex and (b) every authz
                      contract on a surviving hypothesis resolved
                      ``authorized``.

Deferred (tracked as follow-ups, intentionally NOT enforced here):
class-slot grammar vocab (the ``??`` / ``{a,b}`` / ``unclassified-*``
escapes make per-slot enforcement easy to get wrong and block valid
writes) and sibling-fork topological uniqueness.
"""

from __future__ import annotations

from typing import Any

from .parser import INVLANG_FENCE_RE, parse_dense_companion
from . import vocab

# Only these observational-authority kinds can carry a ``++``/``--``
# resolution (defender SKILL §Core blocks). Mirrors soc-agent edge
# authority.
STRONG_AUTH_KINDS = frozenset(
    {"siem-event", "runtime-audit", "authoritative-source"}
)
STRONG_WEIGHTS = frozenset({"++", "--"})


# ---------------------------------------------------------------------------
# Companion walkers
# ---------------------------------------------------------------------------


def _all_vertices(companion: dict[str, Any]) -> list[dict[str, Any]]:
    """Every vertex in the companion: prologue + per-lead observations."""
    out: list[dict[str, Any]] = []
    pro = companion.get("prologue") or {}
    out.extend(v for v in (pro.get("vertices") or []) if isinstance(v, dict))
    for lead in companion.get("findings") or []:
        if not isinstance(lead, dict):
            continue
        obs = (lead.get("outcome") or {}).get("observations") or {}
        out.extend(v for v in (obs.get("vertices") or []) if isinstance(v, dict))
    return out


def _all_edges(companion: dict[str, Any]) -> list[dict[str, Any]]:
    """Every edge in the companion: prologue + per-lead observations."""
    out: list[dict[str, Any]] = []
    pro = companion.get("prologue") or {}
    out.extend(e for e in (pro.get("edges") or []) if isinstance(e, dict))
    for lead in companion.get("findings") or []:
        if not isinstance(lead, dict):
            continue
        obs = (lead.get("outcome") or {}).get("observations") or {}
        out.extend(e for e in (obs.get("edges") or []) if isinstance(e, dict))
    return out


def _all_hypotheses(companion: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Hypotheses by id: the PREDICT frontier plus any lead-discovered ones."""
    out: dict[str, dict[str, Any]] = {}
    hyps = (companion.get("hypothesize") or {}).get("hypotheses") or []
    for h in hyps:
        if isinstance(h, dict) and isinstance(h.get("id"), str):
            out[h["id"]] = h
    for lead in companion.get("findings") or []:
        if not isinstance(lead, dict):
            continue
        for h in lead.get("new_hypotheses") or []:
            if isinstance(h, dict) and isinstance(h.get("id"), str):
                out.setdefault(h["id"], h)
    return out


def _iter_resolutions(companion: dict[str, Any]):
    """Yield (lead_id, resolution) for every `:T resolutions` row."""
    for lead in companion.get("findings") or []:
        if not isinstance(lead, dict):
            continue
        lid = lead.get("id", "?")
        for res in lead.get("resolutions") or []:
            if isinstance(res, dict):
                yield lid, res


def _iter_authz_resolutions(companion: dict[str, Any]):
    """Yield every `:R authz` resolution row across all leads."""
    for lead in companion.get("findings") or []:
        if not isinstance(lead, dict):
            continue
        for row in (lead.get("outcome") or {}).get("authorization_resolutions") or []:
            if isinstance(row, dict):
                yield row


# ---------------------------------------------------------------------------
# Rule 2 — append-only
# ---------------------------------------------------------------------------


def _check_append_only(proposed_text: str, current_text: str | None) -> list[str]:
    if current_text is None:
        return []
    cur = len(INVLANG_FENCE_RE.findall(current_text))
    new = len(INVLANG_FENCE_RE.findall(proposed_text))
    if new < cur:
        return [
            f"append-only violation: proposed content has {new} ```invlang "
            f"block(s) but the on-disk file has {cur} — existing blocks must "
            f"not be removed (defender SKILL §Authoring discipline: append only)"
        ]
    return []


# ---------------------------------------------------------------------------
# Rule 3 — edge authority
# ---------------------------------------------------------------------------


def _check_edge_authority(companion: dict[str, Any]) -> list[str]:
    """A resolution reaching ``++``/``--`` must cite a strong-authority edge."""
    auth_by_edge: dict[str, str] = {}
    for e in _all_edges(companion):
        eid = e.get("id")
        kind = (e.get("authority") or {}).get("kind")
        if isinstance(eid, str) and isinstance(kind, str):
            auth_by_edge[eid] = kind

    errors: list[str] = []
    for lid, res in _iter_resolutions(companion):
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


def _check_closed_vocab(companion: dict[str, Any]) -> list[str]:
    errors: list[str] = []

    for v in _all_vertices(companion):
        t = v.get("type")
        if isinstance(t, str) and t and t not in vocab.TYPES:
            errors.append(
                f"vertex {v.get('id', '?')}: type {t!r} is not a known vertex "
                f"type (`enum types`)"
            )

    for e in _all_edges(companion):
        rel = e.get("relation")
        if isinstance(rel, str) and rel and rel not in vocab.RELATIONS:
            errors.append(
                f"edge {e.get('id', '?')}: rel {rel!r} is not a known relation "
                f"(`enum relations`)"
            )
        kind = (e.get("authority") or {}).get("kind")
        if isinstance(kind, str) and kind and kind not in vocab.AUTH_KINDS:
            errors.append(
                f"edge {e.get('id', '?')}: auth_kind {kind!r} is not a known "
                f"observational authority (`enum auth-kinds`)"
            )

    # Proposed parent vertices on hypotheses also carry a type.
    for h in _all_hypotheses(companion).values():
        pv = (h.get("proposed_edge") or {}).get("parent_vertex") or {}
        pt = pv.get("type")
        if isinstance(pt, str) and pt and pt not in vocab.TYPES:
            errors.append(
                f"hypothesis {h.get('id', '?')}: parent_type {pt!r} is not a "
                f"known vertex type (`enum types`)"
            )
        rel = (h.get("proposed_edge") or {}).get("relation")
        if isinstance(rel, str) and rel and rel not in vocab.RELATIONS:
            errors.append(
                f"hypothesis {h.get('id', '?')}: rel {rel!r} is not a known "
                f"relation (`enum relations`)"
            )

    # anchor_kind on contracts and on authz resolutions.
    for h in _all_hypotheses(companion).values():
        for c in h.get("authorization_contract") or []:
            ak = c.get("anchor_kind") if isinstance(c, dict) else None
            if isinstance(ak, str) and ak and ak not in vocab.ANCHOR_KINDS:
                errors.append(
                    f"hypothesis {h.get('id', '?')} contract "
                    f"{c.get('id', '?')}: anchor_kind {ak!r} is not known "
                    f"(`enum anchor-kinds`)"
                )
    for row in _iter_authz_resolutions(companion):
        ak = row.get("anchor_kind")
        if isinstance(ak, str) and ak and ak not in vocab.ANCHOR_KINDS:
            errors.append(
                f"authz resolution for contract {row.get('fulfills_contract', '?')}: "
                f"anchor_kind {ak!r} is not known (`enum anchor-kinds`)"
            )

    return errors


# ---------------------------------------------------------------------------
# Rule 5 — benign disposition gating
# ---------------------------------------------------------------------------


def _effective_vertex_state(
    companion: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    """Per-vertex effective {classification, attributes} after attr_updates.

    `:R attr_updates` with key ``class`` overrides classification; key
    ``attrs.<name>`` overrides an attribute. Mirrors the parser's own
    three-state ``??`` → ``{a,b}`` → concrete resolution model.
    """
    state: dict[str, dict[str, Any]] = {}
    for v in _all_vertices(companion):
        vid = v.get("id")
        if not isinstance(vid, str):
            continue
        # First declaration wins as the baseline; updates layer on top.
        cur = state.setdefault(
            vid,
            {
                "classification": v.get("classification", ""),
                "attributes": dict(v.get("attributes") or {}),
            },
        )
        # A later observation of the same id can carry attributes too.
        if v.get("attributes"):
            cur["attributes"].update(v["attributes"])

    for lead in companion.get("findings") or []:
        if not isinstance(lead, dict):
            continue
        for upd in (lead.get("outcome") or {}).get("attribute_updates") or []:
            if not isinstance(upd, dict):
                continue
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
    return state


def _has_open_slot(classification: Any) -> bool:
    """True if any ``/``-delimited class slot is still the ``??`` marker."""
    if not isinstance(classification, str) or not classification:
        return False
    return any(slot.strip() == "??" for slot in classification.split("/"))


def _check_benign_gating(companion: dict[str, Any]) -> list[str]:
    conclude = companion.get("conclude") or {}
    if conclude.get("disposition") != "benign":
        return []

    errors: list[str] = []

    # (a) no unresolved ?? on any vertex
    for vid, st in _effective_vertex_state(companion).items():
        if _has_open_slot(st["classification"]):
            errors.append(
                f"disposition benign blocked: vertex {vid} still has an open "
                f"`??` class slot ({st['classification']!r}) — resolve via "
                f":R attr_updates or escalate"
            )
        for name, val in st["attributes"].items():
            if isinstance(val, str) and val.strip() == "??":
                errors.append(
                    f"disposition benign blocked: vertex {vid} attribute "
                    f"{name!r} is still `??` — resolve via :R attr_updates or "
                    f"escalate"
                )

    # (b) every authz contract on a surviving hypothesis resolved authorized
    surviving = [
        s for s in (conclude.get("surviving_hypotheses") or []) if isinstance(s, str)
    ]
    hyps = _all_hypotheses(companion)
    authorized: dict[str, str] = {}
    for row in _iter_authz_resolutions(companion):
        cid = row.get("fulfills_contract")
        if isinstance(cid, str):
            # First authorized wins; otherwise remember the (non-authorized) verdict.
            if authorized.get(cid) != "authorized":
                authorized[cid] = row.get("verdict", "indeterminate")

    for hid in surviving:
        hyp = hyps.get(hid)
        if hyp is None:
            continue
        for c in hyp.get("authorization_contract") or []:
            if not isinstance(c, dict):
                continue
            cid = c.get("id", "?")
            verdict = authorized.get(cid)
            if verdict != "authorized":
                shown = verdict if verdict is not None else "no fulfilling :R authz row"
                errors.append(
                    f"disposition benign blocked: authz contract {cid} on "
                    f"surviving hypothesis {hid} resolved {shown!r}, not "
                    f"'authorized' — benign requires every contract authorized"
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
    errors: list[str] = []

    # Rule 2 is text-level and runs even if the proposed text has no blocks
    # (e.g. an Edit that would blow them away).
    errors.extend(_check_append_only(proposed_text, current_text))

    companion, warnings = parse_dense_companion(proposed_text)

    # Rule 1 — promote lenient parse warnings to blocking errors.
    for w in warnings:
        errors.append(f"parse error: {w.format()}")

    if not companion:
        return errors

    errors.extend(_check_edge_authority(companion))
    errors.extend(_check_closed_vocab(companion))
    errors.extend(_check_benign_gating(companion))
    return errors
