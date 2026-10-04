"""Attribute updates, the effective vertex state they build, and the slots left open.

Unlike the other families, this one derives a value the rest of the system reads
(`effective_vertex_state`). It also owns `_check_vertex_participation`, which needs this
module's open-slot vocabulary: an edge endpoint left `??` connects, a phantom `v-` id does not.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from typing import Any

from defender._model import model

from .. import _walkers, vocab
from .._cells import _row_cells, _row_dict, _split_cells, _split_cells_raw, _unquote
from .._types import Block, RowError
from ..parser import (
    _LEAD_PREFIX_RE,
    _vertex_record,
    iter_fence_blocks,
)
from ..schema import (
    AuthorizationContract,
    CompanionBody,
)
from ._diag import Diagnostic, Locus, _plain
from ._refs import _lead_prefix, _leads
from ._structure import _cell, _check_conclude_vocab, _check_vocab, _check_vocab_anchor_kinds, _check_vocab_edges, _check_vocab_hypotheses, _check_vocab_vertices, _check_vocab_weights


def _swap_cell(cells: list[str], at: int, replacement: str) -> str:
    """One cell replaced, every other left exactly where the author put it."""
    swapped = list(cells)
    swapped[at] = replacement
    return "|".join(swapped)


#: The refinement keys `:R attr_updates` accepts: `class`, `attrs.<name>` and `ident`. `ident`
#: lands in a distinct top-level `identifier` slot, never in `attributes`, because
#: `_check_benign_open_slots` refuses a benign close on any `??` attribute and an unresolved
#: identifier must not block one.
#:
#: These are also the slot names `iter_vertex_cells` reports. Lesson `slot:` selectors are
#: free-form YAML compared by `!=`, so nothing holds lesson authors to these spellings.
SLOT_CLASS = "class"
IDENT_REFINEMENT_KEY = "ident"
SLOT_IDENT = IDENT_REFINEMENT_KEY
ATTR_PREFIX = "attrs."

#: The `Locus.block` label for the one block a row-level repair may reach. It must equal the
#: parse warnings' `f":{block.tag} {block.name}"` label byte for byte, and `runtime.tools`
#: filters `fix_row`'s repair set on it.
ATTR_UPDATES_LOCUS = ":R attr_updates"


def _is_legal_refinement_key(key: str) -> bool:
    return key in (SLOT_CLASS, SLOT_IDENT) or key.startswith(ATTR_PREFIX)


def _unquoted_key(cell: str) -> str:
    """A key cell with one wrapping pair of double quotes removed, for building a repair only.

    Unlike `_cells._unquote` this does not unescape: an escape inside a key cell is part of the
    malformed key, and decoding it would hand back a `use:` line that is not the author's bytes.

    Not a decoding step for validation. In invlang a quote protects a delimiter and is kept, so
    `"class"` is not the key `class` and `_is_legal_refinement_key` must not accept it. The
    repair, though, should suggest the key the author meant (`class`), not `attrs."class"`,
    which `_candidate_refusal` would reject, leaving no repair at all.
    """
    if len(cell) >= 2 and cell.startswith('"') and cell.endswith('"'):
        return cell[1:-1]
    return cell


def _candidate_refusal(
    block: Block, cols: list[str], parsed: list[str], at: int, candidate: str
) -> str | None:
    """Why this rebuilt row cannot be offered, or `None` when it can.

    Four checks, since "the parser accepts it" is only one way a rebuild can go wrong:

      * a cell carrying ``` would close the fence early (the row reader has no notion of it);
      * `_row_cells` must read it back (this also catches a `"` the splice opened);
      * it must split to exactly the declared width: `_row_cells` pads a short row silently,
        but `fix_row`'s guard (`runtime.tools._new_row_shape_reason`) demands equality, and a
        trailing backslash in the author's last cell can escape the rejoining `|`;
      * every other cell must survive unchanged: `key` is spliced from the parsed record, where
        `\\|` is already unescaped, so a key carrying an escaped pipe can shift the value cell
        while passing both width checks.

    Compared against the row as the parser reads it, so normalising padding is allowed and
    moving a byte across a cell boundary is not.
    """
    if "```" in candidate:
        # Rows live inside a ```invlang fence and `_row_cells` has no notion of it, so without
        # this the offer would hand the model a row `fix_row` refuses.
        return (
            "it carries a fence delimiter (```), which would close the block early — the row "
            "cannot be repaired in place at all"
        )
    try:
        _row_cells(block, candidate, len(cols))
    except RowError as e:
        return str(e)
    back = _split_cells(candidate)
    if len(back) != len(cols):
        return (
            f"it splits to {len(back)} cells but the block declares {len(cols)} — "
            f"the rejoined row lost a delimiter"
        )
    moved = [cols[i] for i in range(len(cols)) if i != at and back[i] != parsed[i]]
    if moved:
        return (
            f"it would rewrite the {', '.join(repr(c) for c in moved)} cell(s), which the "
            f"repair must leave exactly as written"
        )
    return None


@model(frozen=True)
class _DeclaredTypes:
    """Every `:V`-declared id mapped to every type its rows give it, in declaration order.

    Wrapped so "can a value stand under any declared type" is one method rather than a rule
    each caller in the repair-offer chain restates: the offer and the gate disagreeing about a
    value would hand the model a repair that is then refused.

    All types, unlike `_walkers.vertex_types`' first-wins string, because a re-declared id has
    no single grammar. Ordered and deduped so a refusal names a deterministic type.
    """

    by_id: Mapping[str, tuple[str, ...]]

    @classmethod
    def of(cls, companion: CompanionBody) -> _DeclaredTypes:
        """Folded from the `:V` rows, once per validation at `_check_closed_vocab`."""
        declared: dict[str, dict[str, None]] = {}
        for v in _walkers.all_vertices(companion):
            vid = v.get("id")
            if isinstance(vid, str) and vid:
                declared.setdefault(vid, {})[v.get("type") or ""] = None
        return cls({vid: tuple(types) for vid, types in declared.items()})

    def types_of(self, vertex_id: str) -> tuple[str, ...]:
        """Declared types, first declaration first; empty for an undeclared id.

        Empty and missing are one answer: both mean there is no grammar to judge against.
        """
        return self.by_id.get(vertex_id) or ()

    def refusal_under_every_type(
        self, vertex_id: str, judge: Callable[[str], list[str]]
    ) -> list[str]:
        """`judge`'s verdict on one cell, returned only when no declared type can hold the
        value; empty otherwise.

        A re-declared id has no single grammar (`_walkers.vertex_types` is first-wins while
        `effective_vertex_state` folds a later row's class over an open one), so judging by
        either fold can refuse a cell nobody wrote. Skipping such ids would let a
        re-declaration smuggle an off-vocabulary refinement past the check; a value no declared
        type can hold is wrong under every reading.

        The message is the first declaring type's: the prologue declares, later blocks
        re-observe.
        """
        per_type = [judge(vertex_type) for vertex_type in self.types_of(vertex_id)]
        return per_type[0] if per_type and all(per_type) else []


def _route_refusal(
    declared: _DeclaredTypes, rec: dict[str, str], key: str
) -> str | None:
    """Why a refinement under this key, keeping this row's value, cannot be offered, or `None`.

    The offer rewrites the key and keeps the author's value, and a landed `class` or
    `attrs.<name>` cell is judged against its vertex type's vocabulary: on a `compute` vertex,
    `owner|svc.config-mgmt` rewritten to `class|svc.config-mgmt` would be refused. Offering a
    repair the validator then rejects gets the model refused for a cell it did not choose. Each
    route asks through the same functions that judge the pasted row (`_class_cell_errors`,
    `_attr_route_errors`), so offer and gate cannot disagree.

    `None` for an undeclared target (no grammar to prove it wrong against), for `ident`, and for
    an `attrs.<name>` naming no closed vocabulary. The reason is carried into the message so a
    withheld `use:` line does not read as the validator contradicting itself; the enums it cites
    are real slot keys `defender-invlang enum` accepts (a glob is not).
    """
    target = rec.get("target") or ""
    types = declared.types_of(target)
    if not types:
        return None
    value = rec.get("value") or ""
    vertex_type = types[0]
    if key == SLOT_CLASS:
        if not declared.refusal_under_every_type(
            target, lambda t: _class_cell_errors(target or "?", t, value)
        ):
            return None
        slot_keys = vocab.class_slot_keys(vertex_type)
        judged = (
            f"a `class` cell is judged per slot against the `{vertex_type}` grammar "
            f"({', '.join(f'`enum {s}`' for s in slot_keys)})"
        )
    elif key.startswith(ATTR_PREFIX):
        if not declared.refusal_under_every_type(
            target, lambda t: _attr_route_errors(target or "?", t, key, value)
        ):
            return None
        judged = (
            f"an `{key}` cell on a `{vertex_type}` vertex is judged against "
            f"`enum {vocab.attr_slot_key(vertex_type, key[len(ATTR_PREFIX):])}`"
        )
    else:
        return None
    return (
        f" — no `{key}` alternative is offered here: {judged} and {value!r} is not a value "
        f"it holds, so keeping this value under `{key}` would only earn a second refusal"
    )


def _repair_routes(
    raw_cells: list[str], at: int, basis: str, *, quoted_legal: bool,
    declared: _DeclaredTypes, rec: dict[str, str],
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """The `use:` alternatives for one illegal refinement key (key cell swapped in place), and
    the reason each withheld route was withheld.

    Route by route, unlike `_candidate_refusal`, which guards against a rebuild that corrupts
    the row. Withholding every route is a legal answer: `kind|imaginary` on a `compute` vertex
    has no key that can carry that value, so offering one would only earn a second refusal.
    """
    # Candidate keys in offer order. If the unquoted text is itself a legal key, that key is
    # the only route (`class` and `attrs.class` are not two readings of `"class"`). The
    # `attrs.` route needs a non-empty name: `attrs.` alone is legal-shaped and would land an
    # attribute named by the empty string.
    keys: tuple[str, ...] = (
        (basis,) if quoted_legal
        else (SLOT_CLASS, *((f"{ATTR_PREFIX}{basis}",) if basis else ()))
    )
    routes: list[str] = []
    withheld: list[str] = []
    for key in keys:
        reason = _route_refusal(declared, rec, key)
        if reason is None:
            routes.append(_swap_cell(raw_cells, at, key))
        else:
            withheld.append(reason)
    return tuple(routes), tuple(withheld)


def _illegal_key_diagnostic(
    block: Block, row: str, cols: list[str], rec: dict[str, str], key: str,
    declared: _DeclaredTypes,
) -> Diagnostic:
    """The warn-severity diagnostic for an `:R attr_updates` row whose `key` is not `class`,
    `ident` or `attrs.<name>`. Split out of `_check_attr_update_keys` for the complexity cap.
    """
    # The last `key` column: `_row_dict` lets a repeated column name's later cell win, so
    # `cols.index` could point at a cell the record never read, and the repair would rewrite
    # an innocent cell and re-earn its own warning forever.
    at = len(cols) - 1 - cols[::-1].index("key")
    raw_cells = _split_cells_raw(row)
    if len(raw_cells) < len(cols):
        # A legal short row under optional trailing columns: pad to the declared width, as
        # `_row_cells` does, so the offered candidate is full-width.
        raw_cells = raw_cells + [""] * (len(cols) - len(raw_cells))
    # Build the repair from the unquoted key, never the raw cell: `attrs.{key}` over a quoted
    # cell would splice already-malformed text behind a legal prefix.
    basis = _unquoted_key(key)
    # `unquoted`: the repair was built from a different string than the author wrote, which the
    # message must explain. `quoted_legal`: the unquoted text is itself a legal key, which
    # collapses the routes into one.
    unquoted = basis != key
    quoted_legal = unquoted and _is_legal_refinement_key(basis)
    candidates, withheld = _repair_routes(
        raw_cells, at, basis, quoted_legal=quoted_legal, declared=declared, rec=rec,
    )
    # All-or-nothing: if any candidate fails `_candidate_refusal`, withhold the whole
    # suggestion; one route silently missing would be worse than none. The refusal is carried
    # verbatim because its grounds call for different fixes.
    #
    # `_row_cells` cannot raise here: `_check_attr_update_keys` reaches this row only after
    # `_row_dict(block, row)` succeeded, which is the same call.
    parsed = _row_cells(block, row, len(cols))
    refusal: str | None = None
    rejected = ""
    for candidate in candidates:
        refusal = _candidate_refusal(block, cols, parsed, at, candidate)
        if refusal is not None:
            rejected = candidate
            break
    # `or`, not `.get`'s default: a blank `target` cell is present in `rec` and would render
    # "on : key ...", naming nothing.
    message = (
        f":R attr_updates on {rec.get('target') or '?'}: key {key!r} is not a "
        f"valid refinement key — use `class` (class refinement), `ident` "
        f"(identifier refinement) or `attrs.<name>` (attribute); a bare key "
        f"is dropped silently"
    )
    # One sentence per withheld route; a route never offered gets none.
    for reason in withheld:
        message += reason
    if unquoted:
        # Explains why a key the author knows is legal was refused, and why the repair drops
        # their quotes.
        message += (
            f" — a quote is part of the cell in this format, never stripped from it, so "
            f"{key} names a different key than {basis}"
        )
    if refusal is not None:
        message += (
            # Quote the rebuilt row the refusal is about: unattributed, it reads as a verdict on
            # the author's row, printed just below it. No `fix_row` instruction here:
            # `runtime.tools` appends one under every rendered warn diagnostic.
            f" — the suggested repair is withheld: rebuilding this row as {rejected!r} "
            f"would not read back as a row of this block ({refusal})"
        )
    return Diagnostic(
        message=message,
        locus=Locus(block=ATTR_UPDATES_LOCUS, row_text=row),
        fix=() if refusal is not None else candidates,
        # The one warn-severity family: the row is inert (it changes no effective vertex
        # state), so its block is kept and the model repairs the row with `fix_row`. Every
        # other family refuses the write.
        severity="warning",
    )


def _check_attr_update_keys(
    proposed_text: str, declared: _DeclaredTypes
) -> list[Diagnostic]:
    """`:R attr_updates` refinement rows — the key and its value — checked over the rows
    rather than the folded records.

    Reads blocks directly because this check quotes a row back and offers a corrected one. The
    fold drops the header, and `_row_dict` zips whatever header the block declares, so
    rebuilding from the fold would assume `resolved_by|target|key|value` order and transpose
    columns under any other header. Here the `key` cell is replaced in place; a block with no
    `key` column yields nothing.

    A blank `value` is refused rather than warned: an empty cell settles nothing, and since
    neither `has_open_slot("")` nor `is_unresolved("")` reads `""` as open, it would otherwise
    pass for a resolution. No `fix` is offered: the missing value is the one thing this check
    cannot supply."""
    out: list[Diagnostic] = []
    for fence_blocks in iter_fence_blocks(proposed_text):
        # One map per fence: `append_block` sends one fence per call, so a fence is one atomic
        # write. Refining a slot again in a later fence is the documented `??` -> candidate
        # set -> value progression; two different values for one slot inside one fence
        # contradict each other and one is silently lost. Per fence rather than per block, so
        # splitting the block in two inside one fence does not evade it; keyed on
        # `(target, key)` rather than the lead, because the fold merges across leads.
        #
        # Here rather than in the parser because only legal keys reach effective state: a
        # repeated illegal key loses nothing and must stay a warning, not a refusal.
        refined_here: dict[tuple[str, str], str] = {}
        for block in fence_blocks:
            cols = block.columns or []
            if block.name != "attr_updates":
                continue
            for row in block.rows:
                try:
                    rec = _row_dict(block, row)
                except RowError:
                    continue  # already a parse warning; not this check's business
                key = rec.get("key")
                if not key:
                    continue
                if _is_legal_refinement_key(key):
                    # Only a lost value is a defect. Identical repeats are harmless, and
                    # `fix_row` rewrites every identical occurrence at once, so repairing two
                    # identical bad rows necessarily yields two identical good ones.
                    target = rec.get("target") or ""
                    slot = (target, key)
                    previous = refined_here.get(slot)
                    if previous is not None and previous != (rec.get("value") or ""):
                        out.append(Diagnostic(
                            message=(
                                f":R attr_updates on {target or '?'}: {key!r} is refined twice in "
                                f"this write, to {previous!r} and then to "
                                f"{rec.get('value') or ''!r}; only the LAST value is recorded and "
                                f"{previous!r} is discarded with nothing said. Give this write one "
                                f"row per slot and re-send it whole — refining the same slot again "
                                f"in a LATER `append_block` is the documented `??` -> candidate "
                                f"set -> concrete value progression and stays legal"
                            ),
                            locus=Locus(block=ATTR_UPDATES_LOCUS, row_text=row),
                        ))
                    refined_here[slot] = rec.get("value") or ""
                    value = rec.get("value")
                    if "value" in cols and not (value or "").strip():
                        out.append(Diagnostic(
                            message=(
                                f":R attr_updates on {rec.get('target') or '?'}: the `value` cell "
                                f"for key {key!r} is empty — a refinement settles a slot by "
                                f"naming the value the lead obtained, and an empty cell settles "
                                f"nothing. Write that value, or leave the `??` standing and "
                                f"escalate"
                            ),
                            locus=Locus(block=ATTR_UPDATES_LOCUS, row_text=row),
                        ))
                    continue
                # A non-empty `key` proves the header has a `key` column to substitute into.
                out.append(_illegal_key_diagnostic(block, row, cols, rec, key, declared))
    return out


def _check_attr_update_targets(companion: CompanionBody) -> list[str]:
    """A `:R attr_updates` row must name a graph object the document declares.

    Otherwise `effective_vertex_state` fabricates the object from the refinement alone, with an
    `ident` that may carry alert content. Edges count: refining one is ordinary
    (`l-001|e-001|attrs.auth_method|password`)."""
    declared = {
        r.get("id")
        for records in (_walkers.all_vertices(companion), _walkers.all_edges(companion))
        for r in records
        if isinstance(r.get("id"), str)
    }
    errors: list[str] = []
    for upd in _walkers.iter_attr_updates(companion):
        tgt = upd.get("target")
        if not isinstance(tgt, str) or not tgt or tgt in declared:
            continue
        errors.append(
            f":R attr_updates refines {tgt!r}, which no `:V` or `:E` block declares — declare "
            f"it before refining it (declared: {sorted(d for d in declared if d)})"
        )
    return errors


def _check_closed_vocab(companion: CompanionBody, proposed_text: str) -> list[Diagnostic]:
    out: list[Diagnostic] = []
    out += _plain(_check_vocab_vertices(companion))
    out += _plain(_check_vocab_edges(companion))
    out += _plain(_check_vocab_hypotheses(companion))
    out += _plain(_check_conclude_vocab(companion))
    out += _plain(_check_vocab_anchor_kinds(companion))
    out += _plain(_check_vocab_weights(companion))
    # Resolved once and shared: the class-cell check dispatches on these types, and the repair
    # offer needs them to know whether a route would survive that check.
    declared = _DeclaredTypes.of(companion)
    out += _plain(_check_vocab_class_cells(companion, declared))
    out += _check_attr_update_keys(proposed_text, declared)
    return out




#: The whole-cell open marker, shared by the predicates below and their readers.
OPEN_MARKER = "??"


def is_unresolved(value: Any) -> bool:
    """Does the whole cell say "not settled yet": `??`, or a `{...}` candidate set.

    SKILL.md's progression is `??` → `{a, b}` → concrete, so a candidate set (even `{internal}`)
    is still open. Anchored to the whole value so an attribute that merely contains braces
    does not block a benign close. A value starting with `{` is open if it ends with `}` or has
    an unclosed brace — a dropped `}` (`{internal, dmz`) must not read as concrete — while
    `{ cd /x && ls; } >out` stays concrete.
    """
    if not isinstance(value, str):
        return False
    v = value.strip()
    if v == OPEN_MARKER:
        return True
    return v.startswith("{") and (v.endswith("}") or v.count("{") > v.count("}"))


def is_ident_open(value: Any) -> bool:
    """Does this `ident` cell still carry an open question, whole-cell or embedded.

    Identifiers are routinely named in part (`bash[pid=??]`, `dev-ws-??`), which `is_unresolved`
    would call settled, breaking lesson retrieval in both directions. The substring test is
    safe here, unlike for attributes, because `??` inside a chosen name is the marker, not
    data; and it feeds retrieval only (`_check_benign_open_slots` passes `include_ident=False`).

    A superset of `is_unresolved`, so a candidate set (`{dev-ws-1, dev-ws-2}`) also reads open.
    """
    return is_unresolved(value) or (isinstance(value, str) and OPEN_MARKER in value)


def class_slots(classification: str) -> list[str]:
    """A class cell's slots: the slash-tuple, minus an optional leading `<type>:` prefix.

    Split only at brace depth 0, so a whole-triple candidate set
    (`{monitoring-agent/internal/known-corp, ip-only/internet/novel}`) is one unresolved slot
    while `role/{internal, dmz}/prov` is three. The `compute:` prefix is stripped because models
    write it, and it would hide a candidate set behind it.

    Public so `runtime/lessons_engine/lessons_frontier.py` splits cells the way `has_open_slot` does.
    """
    c = classification.strip()
    head, sep, rest = c.partition(":")
    if sep and "{" not in head and "/" not in head:
        c = rest.strip()
    slots: list[str] = []
    cur: list[str] = []
    depth = 0
    for ch in c:
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth = max(0, depth - 1)
        elif ch == "/" and depth == 0:
            slots.append("".join(cur))
            cur = []
            continue
        cur.append(ch)
    slots.append("".join(cur))
    return [s.strip() for s in slots]


def is_open_slot(slot: str) -> bool:
    """Is this one already-split class slot unresolved.

    Public for `runtime/lessons_engine/lessons_frontier.py`, which holds split slots and must not
    re-split them through `has_open_slot`. An unclosed `{` counts as open (a dropped `}` must not
    read as concrete); a stray `}` hides nothing.
    """
    return is_unresolved(slot) or slot.count("{") > slot.count("}")


def has_open_slot(classification: Any) -> bool:
    if not isinstance(classification, str):
        return False
    return any(is_open_slot(slot) for slot in class_slots(classification))


#: The lead sub-blocks that record what a lead found (see `_opening_prologue_ids`). Spelled out
#: rather than derived from `parser._LEAD_SUBBLOCKS`, which is prose-only and steers nothing.
_OBSERVATION_SUBBLOCKS = ("observations.vertices", "observations.edges")


def _records_an_observation(block: Block) -> bool:
    m = _LEAD_PREFIX_RE.match(block.name)
    return m is not None and m.group("sub") in _OBSERVATION_SUBBLOCKS


def _opening_prologue_ids(proposed_text: str) -> set[str]:
    """Vertex ids declared by `:V prologue.vertices` blocks written while the document is still
    opening its graph, before any lead recorded an observation.

    Read off the fence stream, not `companion["prologue"]["vertices"]`: the projection folds
    every prologue block into one list, so keying on the block name alone would let a later
    write move an orphan row into a `:V prologue.vertices` block and inherit the exemption.

    The boundary is the first recorded observation, not the first `:L findings` block, because
    the harness writes lead-0's `:L findings` row before main's first turn. Judged per fence
    (the atomic write), so reordering blocks within one write does not help.

    The document's first fence always counts as opening: a document written as one block
    (examples, fixtures) declares and reports together, and in a live run that fence is the
    harness's, never the model's.
    """
    ids: set[str] = set()
    for nth, fence_blocks in enumerate(iter_fence_blocks(proposed_text)):
        if nth and any(_records_an_observation(b) for b in fence_blocks):
            break
        for block in fence_blocks:
            if block.tag != "V" or block.name != "prologue.vertices":
                continue
            for row in block.rows:
                try:
                    rec = _vertex_record(block, row)
                except RowError:
                    continue  # already a parse warning; not this check's business
                ids.add(rec["id"])
    return ids


def _vertex_declarations(companion: CompanionBody) -> list[tuple[str, str]]:
    """Every vertex declaration as `(declaring site, vertex id)`, in document order.

    Keeps the site `_walkers.all_vertices` flattens away: the refusal names the block to repair,
    and one id declared by two leads is two defects.
    """
    out: list[tuple[str, str]] = [
        ("prologue", v["id"])
        for v in (companion.get("prologue") or {}).get("vertices") or []
        if isinstance(v, dict) and isinstance(v.get("id"), str) and v["id"]
    ]
    for lead in _leads(companion):
        lid = lead.get("id", "?")
        obs = (lead.get("outcome") or {}).get("observations") or {}
        out.extend(
            (lid, v["id"])
            for v in obs.get("vertices") or []
            if isinstance(v, dict) and isinstance(v.get("id"), str) and v["id"]
        )
    return out


def _edge_participants(companion: CompanionBody) -> set[str]:
    """Every vertex id some `:E` row connects, which is not every id one mentions.

    Two edge shapes do not count, since both are cheaper than the observation being asked for:
    an edge to an undeclared id (nothing else refuses a phantom endpoint, and downstream readers
    treat it as real), and a self-edge. An endpoint left open (`??`, `{a, b}`) does connect: it
    is the honest spelling of "observed, not yet identified", and the open-slot gates track it
    to the close.
    """
    declared = {
        v.get("id") for v in _walkers.all_vertices(companion)
        if isinstance(v.get("id"), str)
    }
    participants: set[str] = set()
    for e in _walkers.all_edges(companion):
        src, tgt = e.get("source_vertex"), e.get("target_vertex")
        if not isinstance(src, str) or not isinstance(tgt, str) or src == tgt:
            continue
        for near, far in ((src, tgt), (tgt, src)):
            if near and (far in declared or is_unresolved(far)):
                participants.add(near)
    return participants


def _participation_repair(site: str) -> str:
    """The repair text, printed once per refused write rather than once per offending row."""
    block = "prologue.edges" if site == "prologue" else f"{site}.observations.edges"
    return (
        " A vertex is declared because something was observed to DO something or to have "
        "something done to it, and the `:E` row IS that observation: write it (the relation "
        "actually seen — `contained_in`, `spawned`, `executed`, whichever fits) into "
        f"`:E {block}`. If the relation is not yet known, say THAT: a `:H` row whose "
        "`attached_to` names the vertex records the claim without committing an observation, "
        "and discharges this too. If there is neither an observation nor a claim, this is "
        "not a graph object — do not declare the vertex; carry the fact as an attribute on "
        "the vertex it was read off, or as an `:R attr_updates` row. Do NOT infer an edge "
        "from a text field (a `cmdline` attribute, say) the detector never recorded as an "
        "event of its own, and do NOT point one at an id no `:V` block declares: both reach "
        "below the resolution of what the detector actually observed."
    )


def _check_vertex_participation(
    proposed_text: str,
    companion: CompanionBody,
    current_companion: CompanionBody | None,
) -> list[str]:
    """Every vertex this write declares must be an endpoint of some `:E` row, or the
    `attached_to` of some hypothesis, anywhere in the document.

    SKILL.md forbids creating vertices just for facts; this enforces it. A hypothesis anchor
    discharges it because a lead that can only hypothesize how an entity connects has exactly
    one honest record: declare the vertex and attach an `:H` row. `proposed_edge` does not count
    (it names a parent's type and class, never an id), nor does an `:R attr_updates` target,
    which records a fact about an existing object rather than an event.

    Exempt: ids the opening prologue declares (`_opening_prologue_ids`). A lead re-declaring one
    inherits the exemption, matching `_walkers.vertex_types`' first-declaration-wins.

    Scoped to what this write introduces, like `_check_surface`: the document is append-only,
    and `committed_investigation_reason` and `seed_investigation` re-validate a committed
    document as its own baseline, so a document-global reading would dead-letter finished runs
    over bytes no repair can reach.

    One diagnostic per `(site, vertex)`; the repair text is printed once, on the first.
    """
    exempt = _opening_prologue_ids(proposed_text)
    spoken_for = _edge_participants(companion) | {
        h["anchor"] for h in _walkers.all_hypotheses(companion).values()
        if isinstance(h.get("anchor"), str) and h["anchor"]
    }
    committed = (
        set(_vertex_declarations(current_companion))
        if current_companion is not None else set()
    )
    errors: list[str] = []
    for site, vid in _vertex_declarations(companion):
        if vid in exempt or vid in spoken_for or (site, vid) in committed:
            continue
        where = (
            "`:V prologue.vertices`" if site == "prologue"
            else f"`:V {site}.observations.vertices`"
        )
        prefix = "" if site == "prologue" else _lead_prefix(site)
        errors.append(
            f"{prefix}{where} row {vid!r} — no `:E` row anywhere in the document names it "
            f"as `src` or `tgt`, and no `:H` row is attached to it."
            + (_participation_repair(site) if not errors else "")
        )
    return errors


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
            {
                "classification": cls,
                # Seeded from the declared `:V` identifier. Both construction sites must carry
                # the slot, or consumers hit a KeyError.
                "identifier": v.get("identifier", ""),
                "attributes": dict(v.get("attributes") or {}),
            },
        )
        # A concrete class supersedes a held one that is blank or open, never the reverse.
        # Blank counts as unsettled because `classification` is an optional `:V` column, and
        # a latched `""` would make `_class_pins` refuse class-bearing selectors on every cell
        # of the vertex. Never blank -> open: that would newly block benign closes.
        held_cls = cur["classification"]
        if cls and not has_open_slot(cls) and (
            not (isinstance(held_cls, str) and held_cls.strip()) or has_open_slot(held_cls)
        ):
            cur["classification"] = cls
        # The same rule for `ident`: re-observing a vertex is how an append-only document names
        # an entity it opened with `ident=??`. Any non-blank incoming value (even a partly open
        # one like `bash[pid=??]`) supersedes a held one that is blank or still open; a settled
        # name is never re-opened. Otherwise the frontier keeps reporting a named vertex's
        # ident as open, or leaves it `""`, which no lane reads.
        ident = v.get("identifier", "")
        held = cur["identifier"]
        if isinstance(ident, str) and ident.strip() and (
            not (isinstance(held, str) and held.strip()) or is_ident_open(held)
        ):
            cur["identifier"] = ident
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
        st = state.setdefault(
            tgt, {"classification": "", "identifier": "", "attributes": {}}
        )
        for key, val in updates.items():
            # A blank value resolves nothing, and since neither `has_open_slot("")` nor
            # `is_unresolved("")` reads `""` as open, assigning it would read as a resolution
            # (`l-001|v-001|class|` would clear the `??` it meant to settle).
            # `_check_attr_update_keys` refuses such rows; this covers ungated documents.
            if not isinstance(val, str) or not val.strip():
                continue
            if key == SLOT_CLASS:
                st["classification"] = val
            elif key == IDENT_REFINEMENT_KEY:
                # A distinct top-level slot (see IDENT_REFINEMENT_KEY). Last row wins.
                st["identifier"] = val
            elif isinstance(key, str) and key.startswith(ATTR_PREFIX):
                st["attributes"][key[len(ATTR_PREFIX):]] = val


def effective_vertex_state(
    companion: CompanionBody,
) -> dict[str, dict[str, Any]]:
    """Every vertex as it stands now: declared `:V` state with every `:R attr_updates` row
    applied, last row winning.

    Public so the benign gate and `frontier.py`'s lesson retrieval read one fold of the
    document.
    """
    state: dict[str, dict[str, Any]] = {}
    _seed_vertex_state(companion, state)
    _apply_attr_updates(companion, state)
    return state


#: The three states of a vertex cell. Open and held are not complements: an absent cell is
#: neither, and calling it held would report attributes a vertex never carried as known.
CELL_OPEN = "open"
CELL_HELD = "held"
CELL_EMPTY = "empty"


@model(frozen=True)
class VertexCell:
    """One `(vertex, slot)` cell of the folded document, classified open / held / empty.

    The shared node-axis walk: the benign gate (`_check_benign_open_slots`) blocks on open cells,
    and `frontier._node_state` keys lesson retrieval on open and held ones.
    """

    vertex_id: str
    #: The vertex's effective class tuple, on every cell, because lesson selectors match
    #: `{type, class, slot}` together.
    classification: str
    slot: str
    value: str
    state: str

    @property
    def is_open(self) -> bool:
        return self.state == CELL_OPEN

    @property
    def is_held(self) -> bool:
        return self.state == CELL_HELD


def _cell_text(value: Any) -> str:
    """A cell as text; a non-`str` reads as absent rather than crashing the walk on `.strip()`."""
    return value if isinstance(value, str) else ""


def _cell_state(value: str, *, open_test: Callable[[Any], bool]) -> str:
    """Classify one already-folded cell.

    `open_test` varies by slot: a class cell is open when any slash-slot is (`has_open_slot`),
    while `ident` and `attrs` cells are single values. Emptiness is tested first because neither
    predicate reads `""` as open."""
    if not value.strip():
        return CELL_EMPTY
    return CELL_OPEN if open_test(value) else CELL_HELD


def iter_vertex_cells(
    companion: CompanionBody, *, include_ident: bool
) -> Iterator[VertexCell]:
    """Every vertex cell the folded document holds, in document order, class → ident → attrs.

    `include_ident`: the gate passes False (an unresolved identifier must not block a benign
    close); retrieval passes True (it is the most retrieval-worthy open slot).

    Ids with no `:V` row (an `:R attr_updates` target, possibly an `e-*`) are still yielded,
    because the gate blocks on them. Consumers that need a vertex type, like
    `frontier._node_state`, filter them out themselves.
    """
    for vid, st in effective_vertex_state(companion).items():
        cls = _cell_text(st.get("classification"))
        yield VertexCell(
            vid, cls, SLOT_CLASS, cls, _cell_state(cls, open_test=has_open_slot)
        )
        if include_ident:
            ident = _cell_text(st.get("identifier"))
            yield VertexCell(
                vid, cls, SLOT_IDENT, ident, _cell_state(ident, open_test=is_ident_open)
            )
        for name, raw in (st.get("attributes") or {}).items():
            val = _cell_text(raw)
            yield VertexCell(
                vid,
                cls,
                f"{ATTR_PREFIX}{name}",
                val,
                _cell_state(val, open_test=is_unresolved),
            )


#: The two catch-alls SKILL.md gives for a case the catalog does not hold:
#: `unclassified-{type}` and `ambiguous-{a}-or-{b}`. They are outside every enum, so vocabulary
#: checks must accept them by name. Unlike `??` they are settled answers and do not gate a
#: disposition.
CATCHALL_PREFIXES: tuple[str, ...] = ("unclassified-", "ambiguous-")


def is_catchall_slot(value: Any) -> bool:
    """Does this already-split cell name one of the two documented catch-alls."""
    return isinstance(value, str) and value.strip().startswith(CATCHALL_PREFIXES)


def _vocab_cell_errors(
    vertex_id: str, slot_key: str, value: str, where: str
) -> list[str]:
    """One cell against the `SLOTS` enum that closes it.

    Open cells (`??`, candidate sets) and catch-alls are not wrong values and pass. The cell is
    stripped and unquoted first, because the same value arrives bare from a `:V` attrs cell and
    quoted from a `:R attr_updates` value cell, and must get one answer.

    A value that fails its slot but belongs to another vertex slot's vocabulary names that slot
    (`container` is a `compute.kind`, not a `compute.role`), so the model moves the value rather
    than guessing.
    """
    cell = _unquote(value.strip())
    if is_open_slot(cell) or is_catchall_slot(cell):
        return []
    errors = _check_vocab(
        cell, vocab.get_enum(slot_key),
        f"vertex {vertex_id}: {where} {cell!r} is not a known {slot_key} "
        f"(`enum {slot_key}`)",
    )
    if not errors:
        return errors
    other = vocab.vertex_slots_holding(cell, other_than=slot_key)
    if not other:
        return errors
    return [f"{errors[0]} — it is a `{other[0]}` value, not `{slot_key}`"]


def _attr_route_errors(
    vertex_id: str, vertex_type: str, key: str, value: str
) -> list[str]:
    """One `attrs.<name>` refinement key carrying `value`, against the enum closing that pair;
    empty when the pair has no closed vocabulary.

    Shared by the repair offer (`_route_refusal`) and the landed-cell check
    (`_folded_cell_errors`) so the two cannot disagree.
    """
    slot_key = vocab.attr_slot_key(vertex_type, key[len(ATTR_PREFIX):])
    if slot_key is None:
        return []
    return _vocab_cell_errors(vertex_id, slot_key, value, f"`{key}`")


def _class_cell_errors(vertex_id: str, vertex_type: str, value: str) -> list[str]:
    """A whole `class` cell against its type's grammar, slot by slot.

    Shared by `_check_vocab_class_cells` and the repair offer, which must agree or the validator
    offers a repair it then refuses. Zipped, so a short cell is judged only on the slots it
    names (a missing slot is a different defect). Unquoted before splitting, or a whole-cell
    quoted tuple would shred into slots carrying stray quotes.
    """
    errors: list[str] = []
    for slot_key, slot in zip(
        vocab.class_slot_keys(vertex_type),
        class_slots(_unquote(value.strip())),
        strict=False,
    ):
        errors += _vocab_cell_errors(
            vertex_id, slot_key, slot, f"class slot `{slot_key.split('.')[-1]}`"
        )
    return errors


def _folded_cell_errors(
    declared: _DeclaredTypes, cell: VertexCell
) -> list[str]:
    """One folded `class` or `attrs.<name>` cell against its vertex's grammar, under every
    declared type."""
    def judge(vertex_type: str) -> list[str]:
        if cell.slot == SLOT_CLASS:
            return _class_cell_errors(cell.vertex_id, vertex_type, cell.value)
        return _attr_route_errors(cell.vertex_id, vertex_type, cell.slot, cell.value)

    return declared.refusal_under_every_type(cell.vertex_id, judge)


def _declared_row_errors(companion: CompanionBody) -> list[str]:
    """Every `:V` row's own `class` cell and `attrs` siblings, judged by that row's own type.

    Needed beside the folded walk: `_seed_vertex_state` keeps the first concrete class, so a
    later row's concrete class (`container/internal/novel` after
    `web-server/internal/known-corp`) never reaches the fold, yet is on disk forever. Row-wise,
    so there is no type ambiguity to resolve.
    """
    errors: list[str] = []
    for v in _walkers.all_vertices(companion):
        vid = v.get("id")
        vertex_type = v.get("type")
        if not isinstance(vid, str) or not vid:
            continue
        if not isinstance(vertex_type, str) or not vertex_type:
            continue
        errors += _class_cell_errors(vid, vertex_type, _cell_text(v.get("classification")))
        for name, raw in (v.get("attributes") or {}).items():
            errors += _attr_route_errors(
                vid, vertex_type, f"{ATTR_PREFIX}{name}", _cell_text(raw)
            )
    return errors


def _check_vocab_class_cells(
    companion: CompanionBody, declared: _DeclaredTypes
) -> list[str]:
    """A vertex's `class` tuple and its closed-vocabulary `attrs` siblings, per type.

    Reads inside the `class` cell, where the type's grammar lives: `container` in the first slot
    of a `compute` class is a `compute.kind` value in the `compute.role` slot, and would
    otherwise reach the frontier as a held fact that lesson selectors mis-match.

    Two walks, deduped: `_declared_row_errors` sees concrete classes the fold discards, and the
    folded walk sees values only an `:R attr_updates` refinement supplies (the write most likely
    to name a value). Ids with no `:V` row are skipped, having no type to dispatch on
    (`_check_attr_update_targets` refuses a target naming nothing). An id declared under
    several types is refused only where none of them can hold the value.
    """
    errors: list[str] = _declared_row_errors(companion)
    for cell in iter_vertex_cells(companion, include_ident=False):
        if cell.slot == SLOT_CLASS or cell.slot.startswith(ATTR_PREFIX):
            errors += _folded_cell_errors(declared, cell)
    # One message per defect, in first-seen order: both walks may judge the same cell.
    return list(dict.fromkeys(errors))


def _check_benign_open_slots(companion: CompanionBody) -> list[str]:
    """The open cells that block a benign close. Excludes `ident` (see IDENT_REFINEMENT_KEY)."""
    errors: list[str] = []
    for cell in iter_vertex_cells(companion, include_ident=False):
        if not cell.is_open:
            continue
        if cell.slot == SLOT_CLASS:
            errors.append(
                f"disposition benign blocked: vertex {cell.vertex_id} still has an "
                f"unresolved class ({cell.value!r}) — resolve via "
                f":R attr_updates or escalate"
            )
        elif cell.slot.startswith(ATTR_PREFIX):
            errors.append(
                f"disposition benign blocked: vertex {cell.vertex_id} attribute "
                f"{cell.slot[len(ATTR_PREFIX):]!r} is still unresolved ({cell.value!r}) — "
                f"resolve via :R attr_updates or escalate"
            )
        # No `else`: an `ident` cell would render as `attribute ''`. A new slot kind reaching
        # here should be a visible gap, not a mislabelled attribute.
    return errors


def _anchor_kind(record: Any) -> str:
    """The anchor kind a `:H h-NNN.authz` contract or a `:R authz` row carries, normalized.

    Through `_cell` (unquoted) because both sides copy the cell verbatim, and a contract and its
    row must compare equal when the author quotes uniformly.
    """
    return _cell(record, "anchor_kind") if isinstance(record, dict) else ""


def _declarers_by_contract_id(
    companion: CompanionBody,
) -> dict[str, list[tuple[str, str]]]:
    """Every `(hypothesis, anchor kind)` declaring each `ac*` id, live or not.

    Unlike `_check_authz_contract_ids`, refuted declarers count: a `:R authz` row carries no
    hypothesis column, so a refuted declarer competes for the row like a live one.
    """
    declared_by: dict[str, list[tuple[str, str]]] = {}
    for hid, hyp in _walkers.all_hypotheses(companion).items():
        for c in hyp.get("authorization_contract") or []:
            if not isinstance(c, dict):
                continue
            # `_cell` (unquoted): readers match this against a `fulfills` cell read through
            # `_cell`, so a quoted declaring id would otherwise be undischargeable.
            cid = _cell(c, "id")
            if cid:
                declared_by.setdefault(cid, []).append((hid, _anchor_kind(c)))
    return declared_by


def _authz_contract_error(
    hid: str,
    contract: AuthorizationContract,
    declarers: dict[str, list[tuple[str, str]]],
    verdicts: dict[str, list[tuple[str, str]]],
) -> str | None:
    """Why this ONE contract on this LIVE hypothesis does not close benign — or `None`."""
    cid = _cell(contract, "id") or "?"
    anchor = _anchor_kind(contract)
    competing = [(h, a) for h, a in declarers.get(cid, []) if h != hid]
    candidates = verdicts.get(cid) or []

    if competing:
        # The anchor kind is always present (`_hyp_sub_authz_row` requires it), which makes it
        # usable as a discriminator.
        twins = sorted(h for h, a in competing if a == anchor)
        if twins:
            return (
                f"disposition benign blocked: authz contract {cid} on live hypothesis "
                f"{hid} shares BOTH its id and its anchor kind {anchor!r} with a contract "
                f"on {', '.join(twins)} — a `:R authz` row names only the contract it "
                f"fulfills, so no row can be attributed to this one and none discharges "
                f"it; number `ac*` across the document, not per hypothesis"
            )
        rows = [v for v, a in candidates if a == anchor]
        if not rows:
            return (
                f"disposition benign blocked: authz contract {cid} on live hypothesis "
                f"{hid} asks an {anchor!r} question, and {cid} is also declared by "
                f"{', '.join(sorted(h for h, _a in competing))} — so only a `:R authz` row "
                f"carrying anchor kind {anchor!r} discharges it, and the document has none"
            )
    else:
        rows = [v for v, _a in candidates]

    if not rows:
        return (
            f"disposition benign blocked: authz contract {cid} on "
            f"live hypothesis {hid} resolved 'no fulfilling :R authz "
            f"row', not 'authorized' — benign requires every contract "
            f"authorized"
        )
    # A list, not `next(..., None)`: `None` is a verdict a row can carry, and would be
    # indistinguishable from "no row".
    bad = [v for v in rows if v != "authorized"]
    if bad:
        return (
            f"disposition benign blocked: authz contract {cid} on "
            f"live hypothesis {hid} resolved {bad[0]!r}, not 'authorized' "
            f"— benign requires every contract authorized"
        )
    return None


def outstanding_authz_contracts(
    companion: CompanionBody,
) -> list[tuple[str, AuthorizationContract, str]]:
    """Every `(hypothesis, contract, why)` on a live hypothesis that no `:R authz` row
    discharges — the definition of "this authorization question is still open".

    Public so `_check_benign_authz` and `frontier._open_contracts` share one answer. A second
    reading of "discharged" — a bare `fulfills_contract` id set, say — silently disagrees with
    this one on every shared id, and in the harmful direction: the frontier would drop the
    contract that is actually wedging the close. A shared id is scoped by anchor kind
    (`_authz_contract_error`).
    """
    live = set(_walkers.live_hypothesis_ids(companion))
    hyps = _walkers.all_hypotheses(companion)
    declarers = _declarers_by_contract_id(companion)

    verdicts: dict[str, list[tuple[str, str]]] = {}
    for row in _walkers.iter_authz_resolutions(companion):
        # `_cell` (unquoted), matching `_check_authz_contract_closure`; read raw, a quoted
        # `fulfills` would make the two disagree about whether the contract is discharged.
        cid = _cell(row, "fulfills_contract")
        if cid:
            verdicts.setdefault(cid, []).append(
                (row.get("verdict", "indeterminate"), _anchor_kind(row))
            )

    out: list[tuple[str, AuthorizationContract, str]] = []
    for hid in sorted(live):
        hyp = hyps.get(hid)
        if hyp is None:
            continue
        for c in hyp.get("authorization_contract") or []:
            if not isinstance(c, dict):
                continue
            found = _authz_contract_error(hid, c, declarers, verdicts)
            if found is not None:
                out.append((hid, c, found))
    return out


def _check_benign_authz(companion: CompanionBody) -> list[str]:
    """Every authz contract on a live hypothesis is discharged by an `authorized` row
    attributable to it.

    `_check_authz_contract_ids` exempts an id collision whose other declarer is refuted, since
    on an append-only document refuting is the only repair. That is sound for the contract but
    not the row: an `authorized` row written against the refuted declarer's `ac1` would also
    discharge the live one's. So a shared id is scoped by anchor kind, which keeps the rule
    repairable — appending a row with this contract's anchor kind discharges it. Two declarers
    sharing both id and anchor kind are refused outright. An unshared id is discharged by id
    alone.
    """
    return [why for _hid, _c, why in outstanding_authz_contracts(companion)]
