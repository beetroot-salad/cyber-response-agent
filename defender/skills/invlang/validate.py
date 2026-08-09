
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from defender._vocab import normalized_disposition
from . import _walkers, vocab
from .parser import (
    INVLANG_FENCE_RE,
    ParseWarning,
    dropped_a_hypothesis_declaration,
    parse_dense_companion,
)
from .schema import CompanionBody, EdgeRecord, HypothesisRecord, VertexRecord

STRONG_AUTH_KINDS = vocab.STRONG_AUTH_KINDS
STRONG_WEIGHTS = vocab.STRONG_WEIGHTS
_STRONG_AUTH_KINDS_STR = " / ".join(sorted(STRONG_AUTH_KINDS))

_YAML_FENCE_RE = re.compile(r"```ya?ml\b")


@dataclass(frozen=True)
class Locus:
    """Where a diagnostic's offending row actually is, when there is one row to point at.

    `row_text` is the row as the author wrote it (parse warnings) or as it reconstructs
    from the block's canonical column order (`:R attr_updates`). `row_index` is the
    ordinal WITHIN the block, not a file line number — nothing in the validator computes
    one — and is absent wherever the row was rebuilt rather than captured."""

    block: str
    row_text: str
    row_index: int | None = None


@dataclass(frozen=True)
class Diagnostic:
    """One validation failure. `message` is the prose the model has always seen and is
    unchanged; `locus` and `fix` are additive.

    Only the families that can name a single offending row populate `locus` — parse
    warnings and `:R attr_updates`. The document-global checks (append-only, lead and
    prediction refs, strong-move provenance, benign gating, loop close, surface) have no
    row to point at and leave it `None`; so do the vocab sub-checks over `:V`/`:E`/`:H`,
    whose rows cannot be rebuilt without the block's declared column list. Those degrade
    to exactly today's behaviour, which is the whole point of the field being optional."""

    message: str
    locus: Locus | None = None
    fix: tuple[str, ...] = field(default_factory=tuple)


def _plain(messages: list[str]) -> list[Diagnostic]:
    """Lift the checks that carry no row into `Diagnostic`s. Keeping those checks on
    `list[str]` is deliberate: they gain nothing from the type, and rewriting all seven
    would be churn with no consumer."""
    return [Diagnostic(m) for m in messages]


def _parse_diagnostic(w: ParseWarning) -> Diagnostic:
    """A parse warning already knows its block, ordinal and raw row — `w.format()` folds
    them into prose and then nobody can get at them again. Keep the prose byte-identical
    and carry the structure alongside it."""
    return Diagnostic(
        message=f"parse error: {w.format()}",
        locus=Locus(block=w.block, row_text=w.row, row_index=w.row_index),
    )


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




def _check_lead_refs(companion: CompanionBody) -> list[str]:
    """`:L findings` is the sole site that declares a lead; every other mention
    must resolve to one.

    The projector opens a bucket for any lead id it meets, so a typo, a forward
    reference, and a comma-joined pair of real ids are all indistinguishable
    from a declaration at projection time — which is how a phantom lead named
    `l-004,l-005` reached the corpus. Only a declared lead carries a name, so
    that is what separates the two here.
    """
    findings = [f for f in (companion.get("findings") or []) if isinstance(f, dict)]
    declared = {
        f["id"] for f in findings
        if isinstance(f.get("id"), str) and f.get("name")
    }
    errors: list[str] = []
    for f in findings:
        fid = f.get("id")
        if not isinstance(fid, str) or fid in declared:
            continue
        hint = (
            " — a resolution is owned by exactly one lead; attribute it to one "
            "and name the others in `cites_leads`"
            if "," in fid else ""
        )
        errors.append(
            f"undeclared lead {fid!r}: referenced by a `:R` / `:T` row or a "
            f"lead sub-block, but no `:L findings` row declares it{hint}"
        )
    for row in _walkers.iter_grounded_resolutions(companion):
        owner = row.get("resolved_by_lead")
        for cited in row.get("cites_leads") or []:
            if cited not in declared:
                errors.append(
                    f"`cites_leads` on the resolution owned by "
                    f"{owner or '<unattributed>'} names {cited!r}, which no "
                    f"`:L findings` row declares"
                )
            elif cited == owner:
                errors.append(
                    f"`cites_leads` on {owner}'s resolution cites {owner} "
                    f"itself — it names the other leads the verdict rests on"
                )
    return errors


def _declared_prediction_ids(hyp: HypothesisRecord) -> set[str]:
    """Both PREDICT blocks: the `⟺` annotation form cites `ap*` next to `p*`, so
    `:H h-NNN.attr_preds` declares matched-prediction ids just as `.preds` does."""
    return {p["id"] for p in hyp.get("predictions") or []} | {
        ap["id"] for ap in hyp.get("attribute_predictions") or []
    }


def _unresolved(cited: list[str], declared: set[str]) -> list[str]:
    # Deduped: `[l-001 p1 + l-003 p1,p2 …]` cites p1 twice, and one undeclared id
    # is one defect however many times the head names it.
    return [c for c in dict.fromkeys(cited) if c not in declared]


def _known_ids(declared: set[str]) -> str:
    return ", ".join(sorted(declared)) or "none"


def _check_prediction_refs(
    companion: CompanionBody, *, declarations_intact: bool
) -> list[str]:
    """A resolution moves a hypothesis that was declared, and matches only the
    predictions and refutations that hypothesis declared.

    `_check_lead_refs`'s analogue for the other reference the parser derives by
    heuristic instead of by lookup: `matched_prediction_ids` is the id-shaped
    head tokens, and nothing joined the result back to the declaring
    `:H h-NNN.preds` block. So a typo, a forward reference, and a *sibling's*
    `p1` all parsed clean and validated clean — a `++` could rest on a prediction
    that does not exist, or on one belonging to the hypothesis it is being
    weighed against.

    The row's `h-*` is the same reference one level up, and it went unchecked
    for the same reason: the projector opens no bucket for it, so a phantom
    moved to `++` in silence and `_walkers.final_weights` reported it live. It
    could not be enforced until `:H` blocks accumulated (#817) — before that, a
    legitimate mid-run fork's earlier hypotheses were dropped by the parser and
    this error would have fired on a correct document.

    `declarations_intact` is what keeps that deference honest now: a `:H`
    DECLARATION block the parser rejected (a stale header, an `attached_to`
    naming an edge) leaves every resolution against it looking phantom, and the
    parse warning already names the cause. One defect, one error. It is keyed to
    the declaring block, not to "the document parsed without a single warning" —
    an unknown block or an unattributed `:R` row drops no hypothesis, so a
    phantom alongside one must still be reported.
    """
    errors: list[str] = []
    declared_by_hyp = {
        hid: (
            _declared_prediction_ids(hyp),
            {r["id"] for r in hyp.get("refutation_shape") or []},
        )
        for hid, hyp in _walkers.all_hypotheses(companion).items()
    }
    declared_hyp_ids = _known_ids(set(declared_by_hyp))
    for lid, res in _walkers.iter_resolutions(companion):
        hid = res.get("hypothesis")
        if not isinstance(hid, str):
            continue
        entry = declared_by_hyp.get(hid)
        if entry is None:
            if declarations_intact:
                errors.append(
                    f"lead {lid}: resolution moves undeclared hypothesis "
                    f"{hid!r} — no `:H hypothesize.hypotheses` or "
                    f"`:H l-NNN.new_hypotheses` row declares it (declared: "
                    f"{declared_hyp_ids}); a hypothesis born "
                    f"mid-run is declared by the lead that found it, before "
                    f"anything resolves it"
                )
            continue
        preds, refuts = entry
        for pid in _unresolved(res.get("matched_prediction_ids") or [], preds):
            errors.append(
                f"lead {lid}: resolution of {hid} cites prediction {pid!r}, "
                f"which {hid} does not declare (`:H {hid}.preds` / "
                f"`.attr_preds` declare: {_known_ids(preds)}) — a resolution "
                f"matches only its own hypothesis's predictions"
            )
        for rid in _unresolved(res.get("matched_refutation_ids") or [], refuts):
            errors.append(
                f"lead {lid}: resolution of {hid} cites refutation {rid!r}, "
                f"which {hid} does not declare (`:H {hid}.refuts` declares: "
                f"{_known_ids(refuts)})"
            )
    return errors


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




def _check_strong_move_provenance(companion: CompanionBody) -> list[str]:
    """Both halves of a strong move's provenance tuple, in one walk: WHICH
    observation it rests on, and WHICH pre-committed claim that observation
    settled.

    The citation half is new (#798) and lives here rather than in a walk of its
    own: it shares this one's `++`/`--` filter and answers the other half of the
    same question, so a row missing both reports both together instead of once
    here and once eighty lines away.

    The citation half also catches how the ids go missing in practice. The head
    is `[<lead> <ids…> <severity> ⟂ <edges>]` and severity is positional-last, so
    a row that omits severity has its ids read as the severity and parses as
    citing nothing — which is how `golden-v2sshd`'s
    `h-002 null → ++ [l-001 p1,p2,p3 ⟂ e-002]` sat in the corpus with three
    predictions written down and none of them bound (#798).
    """
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
        if not (res.get("matched_prediction_ids") or res.get("matched_refutation_ids")):
            errors.append(
                f"lead {lid}: resolution of {hyp} to "
                f"{after!r} cites no prediction or refutation id — a strong (++/--) "
                f"move must name the `p*`/`ap*`/`r*` it turned on, in the "
                f"`[<lead> <ids> <severity> ⟂ <edges>]` head"
            )
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


def _check_attr_update_keys(companion: CompanionBody) -> list[Diagnostic]:
    """The one vocab sub-check that can quote its own row. `:R attr_updates` has a fixed
    column order — `[resolved_by|target|key|value]` — so the row rebuilds from the lead,
    the target and the offending key/value pair, and both legal corrections render from
    the same four fields. The model can then retype one row instead of re-deriving the
    rule from prose."""
    out: list[Diagnostic] = []
    for lead_id, upd in _walkers.iter_attr_updates_with_lead(companion):
        tgt = upd.get("target", "?")
        for key, value in (upd.get("updates") or {}).items():
            if key == "class" or (isinstance(key, str) and key.startswith("attrs.")):
                continue
            out.append(Diagnostic(
                message=(
                    f":R attr_updates on {tgt}: key {key!r} is not a valid "
                    f"refinement key — use `class` (class refinement) or "
                    f"`attrs.<name>` (attribute); a bare key is dropped silently"
                ),
                locus=Locus(block=":R attr_updates", row_text=f"{lead_id}|{tgt}|{key}|{value}"),
                fix=(
                    f"{lead_id}|{tgt}|class|{value}",
                    f"{lead_id}|{tgt}|attrs.{key}|{value}",
                ),
            ))
    return out


def _check_closed_vocab(companion: CompanionBody) -> list[Diagnostic]:
    out: list[Diagnostic] = []
    out += _plain(_check_vocab_vertices(companion))
    out += _plain(_check_vocab_edges(companion))
    out += _plain(_check_vocab_hypotheses(companion))
    out += _plain(_check_conclude_vocab(companion))
    out += _plain(_check_vocab_anchor_kinds(companion))
    out += _check_attr_update_keys(companion)
    return out




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


def _check_conclude_vocab(companion: CompanionBody) -> list[str]:
    """`conclude`'s disposition is the run's headline, and until now invlang accepted any
    string there — the one conclude field carrying a project-general vocabulary was the one
    field with no vocabulary check. An out-of-enum value silently skipped the benign gating
    below, so a typo bought a document past the checks a `benign` conclusion has to pass."""
    disposition = (companion.get("conclude") or {}).get("disposition")
    return _check_vocab(
        disposition, vocab.DISPOSITION,
        f"conclude: disposition {disposition!r} is not a known disposition "
        f"(`enum disposition`)",
    )


def _check_benign_gating(companion: CompanionBody) -> list[str]:
    conclude = companion.get("conclude") or {}
    # Matched on what the value RENDERS as (#722). This branch decides whether the benign
    # structural checks run at all, so a zero-width character clinging to the keyword used to
    # turn them all off — a gate failing open on an invisible character in model-authored text.
    if normalized_disposition(conclude.get("disposition")) != "benign":
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




def diagnose(
    proposed_text: str, current_text: str | None = None
) -> list[Diagnostic]:
    """The validator proper. Same checks in the same order as before; the only change is
    that a failure now arrives as a `Diagnostic` rather than a bare string, so a caller
    that wants to point at the offending row can.

    `validate_companion` remains the string surface and is what nearly everything calls —
    see its docstring."""
    proposed_text = _normalize_newlines(proposed_text)
    if current_text is not None:
        current_text = _normalize_newlines(current_text)

    found: list[Diagnostic] = []
    found.extend(_plain(_check_surface(proposed_text)))

    companion, warnings = parse_dense_companion(proposed_text)
    current_companion: CompanionBody | None = None
    if current_text is not None:
        current_companion, _ = parse_dense_companion(current_text)

    found.extend(_plain(
        _check_append_only(proposed_text, current_text, companion, current_companion)
    ))

    found.extend(_parse_diagnostic(w) for w in warnings)

    if not companion:
        return found

    found.extend(_plain(_check_lead_refs(companion)))
    found.extend(_plain(_check_prediction_refs(
        companion,
        declarations_intact=not dropped_a_hypothesis_declaration(warnings),
    )))
    found.extend(_plain(_check_strong_move_provenance(companion)))
    found.extend(_check_closed_vocab(companion))
    found.extend(_plain(_check_benign_gating(companion)))
    found.extend(_plain(_check_loop_close(companion)))
    return found


def validate_companion(
    proposed_text: str, current_text: str | None = None
) -> list[str]:
    """The string surface over `diagnose`, kept because it is what the validator's callers
    are written against: `learning/core/persist.py`, and thirteen assertion sites across
    five suites that do substring work on the elements. `_artifact_schema` is the one
    caller that wants the structure and calls `diagnose` directly."""
    return [d.message for d in diagnose(proposed_text, current_text)]
