"""Attribute updates, the effective vertex state they build, and the slots left open.

One family of `validate.py`'s rules, split out at 4038 lines. This is the only family
that DERIVES a value the rest of the system reads — `effective_vertex_state` — rather
than only answering yes or no about the text.
"""
from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass
from typing import Any

from .. import _walkers, vocab
from .._cells import _row_cells, _row_dict, _split_cells, _split_cells_raw, _unquote
from .._types import Block, RowError
from ..parser import (
    iter_fence_blocks,
)
from ..schema import (
    AuthorizationContract,
    CompanionBody,
)
from ._diag import Diagnostic, Locus, _plain
from ._structure import _cell, _check_conclude_vocab, _check_vocab, _check_vocab_anchor_kinds, _check_vocab_edges, _check_vocab_hypotheses, _check_vocab_vertices, _check_vocab_weights


def _swap_cell(cells: list[str], at: int, replacement: str) -> str:
    """One cell replaced, every other left exactly where the author put it."""
    swapped = list(cells)
    swapped[at] = replacement
    return "|".join(swapped)


#: The refinement keys `:R attr_updates` accepts. `class` sharpens the classification,
#: `attrs.<name>` an attribute, and `ident` the vertex's effective IDENTIFIER. `ident` lands in
#: a distinct top-level `identifier` slot, never in `attributes`: `_check_benign_open_slots`
#: refuses a benign close on any `??`-valued ATTRIBUTE, so routing it there would make
#: `ident=??` block a benign disposition.
#:
#: These three ARE the slot vocabulary `iter_vertex_cells` reports, and the one this module
#: uses to decide a refinement key is legal — one literal for both, so the spelling that CLOSES
#: a slot and the spelling that NAMES one in a `VertexCell` cannot drift apart INSIDE this file.
#:
#: They stop there. A lesson's `slot:` selector is free-form YAML compared by `!=`
#: (`lessons_frontier._node_match_score`), so nothing holds an AUTHOR to these spellings; the
#: prompt says so and `learning/author/lessons/prompt.md` warns that a typo matches nothing
#: forever. A corpus lint over `vocab` is what would close that, not another constant —
#: `frontier.py` deliberately does not re-export these (see its `__all__` note).
SLOT_CLASS = "class"
IDENT_REFINEMENT_KEY = "ident"
SLOT_IDENT = IDENT_REFINEMENT_KEY
ATTR_PREFIX = "attrs."

#: The `Locus.block` label for the one block a row-level repair may reach. Spelled ONCE because
#: three readers have to agree on it byte for byte: the two families here that mint a `Locus`
#: by hand, the parse warnings, whose label is built as `f":{block.tag} {block.name}"` and
#: lands on this same string for an `attr_updates` block, and `runtime.tools`' repair set,
#: which filters on it to keep `fix_row` inside the scope the warn window used to give it for
#: free. A fourth spelling would silently widen or empty that set.
ATTR_UPDATES_LOCUS = ":R attr_updates"


def _is_legal_refinement_key(key: str) -> bool:
    return key in (SLOT_CLASS, SLOT_IDENT) or key.startswith(ATTR_PREFIX)


def _unquoted_key(cell: str) -> str:
    """A KEY cell with ONE wrapping pair of double quotes removed, or the cell unchanged.

    NAMED APART from `_cells._unquote`, which this module also imports and which is the
    VALUE-side reader: that one additionally unescapes `\\"`, because it decodes a cell back to
    the text the author meant. This one is a REPAIR-side guess at a key and must not decode —
    an escape inside a key cell is part of the malformed key, and rewriting it would hand back
    a `use:` line whose key cell is not the author's bytes. Two functions, one letter apart, is
    exactly how the wrong one gets called; the suffix is what keeps them apart on sight.

    NOT a decoding step, and this file does not use it as one. In invlang a quote PROTECTS a
    delimiter and is KEPT: `_split_quoted` hands back `"v-001|v-002"` with its quotes, and the
    `:V` row declaring that vertex carries them too, so both sides of a target comparison see
    the same bytes. A key cell is read the same way as every other cell — which is why
    `"class"` is not the key `class`, and why `_is_legal_refinement_key` is not taught to
    accept it (#963). Making the key cell the one place quotes fall away would put this check
    at odds with every other reader of the format, including the target match one column left.

    What it is for is the REPAIR. An author who wrote `"class"` meant `class`, and the useful
    suggestion is the key they meant — not `attrs."class"`, which is what prefixing text the
    check has already refused produces: a legal-SHAPED key naming an attribute whose name
    contains quote characters, which nobody wants and which `_candidate_refusal` then rejects
    anyway, withholding the whole suggestion and leaving the author with no repair at all.
    """
    if len(cell) >= 2 and cell.startswith('"') and cell.endswith('"'):
        return cell[1:-1]
    return cell


def _candidate_refusal(
    block: Block, cols: list[str], parsed: list[str], at: int, candidate: str
) -> str | None:
    """Why this rebuilt row cannot be OFFERED, or `None` when it can.

    FOUR questions, because "does the parser accept it" answers only one of them and the rest
    are how a rebuild corrupts a row, or earns a refusal, while re-splitting to a legal width:

      * could it stand inside the fence at all — a cell carrying ``` closes the block early,
        and the row reader, handed one row, has no notion of the fence;
      * does it read back at all — `_row_cells`, the parser's own reader, which also catches
        a `"` the splice opened inside a token (`attrs."class"`);
      * does it split to the DECLARED width — asked separately because `_row_cells` PADS a row
        between `required_cells` and the declared width and returns normally, while
        `runtime.tools._new_row_shape_reason` (the guard the model's `fix_row` actually meets)
        demands equality. Under a header with a trailing `?` column, the padded rejoin
        `…|c:\\path\\` + `|` turns the author's closing backslash into an escaped delimiter,
        the candidate comes back one cell SHORT, `_row_cells` pads it back and says nothing —
        and the paste earns exactly the second refusal F-47 exists to prevent;
      * do the author's OTHER cells survive — the one failure worse than a refusal. `key` is
        spliced in from the PARSED record, where `\\|` has already been unescaped, so a key
        cell carrying an escaped pipe rebuilds as `attrs.a|a\\` and the joining `|` pairs with
        the trailing backslash: `l-001|v-001|a\\|a\\ |hello` re-splits to four cells, passes
        both width gates, pastes with ZERO diagnostics, and leaves the document claiming key
        `attrs.a` / value `a|hello` where the author wrote value `hello`.

    Compared cell-by-cell against the row as the PARSER reads it, not against the raw spans:
    a candidate is allowed to normalise padding the tokenizer would have stripped anyway, and
    is not allowed to move a byte across a boundary.
    """
    if "```" in candidate:
        # An invlang FACT, not a runtime one: rows live inside a ```invlang fence, so a row
        # carrying the delimiter would close its own block early. `_row_cells` has no notion
        # of the fence — it is handed one row — so the offer gate has to say it, or it hands
        # the model a `use:` line `fix_row` refuses for a reason the row reader never checks.
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


@dataclass(frozen=True)
class _DeclaredTypes:
    """Every `:V`-declared id mapped to EVERY type its rows give it, in declaration order.

    A NAMED VALUE rather than the `dict[str, tuple[str, ...]]` it wraps, because this mapping
    travels through six signatures — `_check_vocab_class_cells` and the whole repair-offer
    chain down to `_route_refusal` — and every one of them asks it the same two questions:
    what types is this id declared under, and can a value stand under any of them. As a bare
    dict the second question is a rule each caller restates, and `_route_refusal` DID restate
    it, with an `all(...)` comprehension standing beside the folded walk's identical loop —
    two spellings of the one thing this family cannot afford two answers to, since the offer
    and the gate disagreeing about a value is the F-47 shape (`_repair_routes`).

    ALL the types rather than `_walkers.vertex_types`' first-wins string, because the readers
    below have to be able to say "this id has no ONE grammar" — see `_check_vocab_class_cells`.
    ORDERED and deduped rather than a set, because when a value is off-vocabulary under every
    reading the message has to name ONE of them, and the prologue is the declaring site: an
    order-of-iteration answer would make the refusal text depend on set hashing.
    """

    by_id: Mapping[str, tuple[str, ...]]

    @classmethod
    def of(cls, companion: CompanionBody) -> _DeclaredTypes:
        """Folded from the `:V` rows — ONCE, at `_check_closed_vocab`'s boundary."""
        declared: dict[str, dict[str, None]] = {}
        for v in _walkers.all_vertices(companion):
            vid = v.get("id")
            if isinstance(vid, str) and vid:
                declared.setdefault(vid, {})[v.get("type") or ""] = None
        return cls({vid: tuple(types) for vid, types in declared.items()})

    def types_of(self, vertex_id: str) -> tuple[str, ...]:
        """Declared types, first declaration first — EMPTY for an id no `:V` row declares.

        Empty and missing are ONE answer on purpose: both mean there is no grammar to
        dispatch on, and every caller turns that into "nothing to refuse here". Handing back
        `None` for one of them would make each reader spell that equivalence itself.
        """
        return self.by_id.get(vertex_id) or ()

    def refusal_under_every_type(
        self, vertex_id: str, judge: Callable[[str], list[str]]
    ) -> list[str]:
        """`judge`'s verdict on one cell, taken under EVERY type the id is declared with —
        returned only when NO declared type can hold the value, empty otherwise.

        ONE type is the ordinary case and this is then just `judge(that type)`. A re-declared
        id has no single grammar (`_walkers.vertex_types` is FIRST-DECLARATION-WINS while
        `effective_vertex_state` folds a LATER row's class over an open one), and picking
        either fold refuses a cell nobody wrote — `v-001|session|interactive` read as a
        `compute.role`.

        But SKIPPING such an id, which is what this replaced, made the re-declaration a way to
        smuggle the very write #986 is about past this check: a `:R attr_updates` row refining
        `class` to `container/internal/novel` on an id declared once `compute` and once
        `session` was judged by neither. A value NO declared type can hold is wrong under every
        reading of the document, which is the one verdict the ambiguity still leaves available.

        The message is the FIRST declaring type's, for the reason the fold keeps the order:
        the prologue declares, a later block re-observes.
        """
        per_type = [judge(vertex_type) for vertex_type in self.types_of(vertex_id)]
        return per_type[0] if per_type and all(per_type) else []


def _route_refusal(
    declared: _DeclaredTypes, rec: dict[str, str], key: str
) -> str | None:
    """Why a refinement under THIS key, carrying THIS row's value, cannot be OFFERED, or `None`.

    The offer rewrites the KEY and keeps the author's VALUE, and since #986 a landed `class`
    cell is judged against its vertex type's slot grammar and a landed `attrs.<name>` cell
    against the enum that closes THAT pair — so on a `compute` vertex `owner|svc.config-mgmt`
    becomes `class|svc.config-mgmt` and `kind|imaginary` becomes `attrs.kind|imaginary`, both of
    which `_check_vocab_class_cells` refuses. An offer the validator's own gate rejects is the
    F-47 shape the repair family exists to avoid: the model pastes the bytes it was handed and
    is refused for a cell it did not choose, with the row still flagged and both write verbs
    still shut.

    PER KEY, not per `class`: guarding only the `class` route left the `attrs.<name>` one — the
    single offer on `kind|imaginary`, since `attr_slot_key` closes `compute.kind` — handing back
    a paste this same check refuses, which is the identical defect one route over. The two ask
    the same question through the same functions that will judge the pasted row
    (`_class_cell_errors`, `_vocab_cell_errors`), so the offer and the gate cannot drift into
    disagreeing about one value.

    `None` for an undeclared target, because a route cannot be proven wrong against a grammar
    nobody named, and `None` for `ident` and for an `attrs.<name>` naming no closed vocabulary,
    which are the routes that legally carry an arbitrary value. A target re-declared under two
    types is withheld only when the value stands under NEITHER — literally the same call
    `_DeclaredTypes.refusal_under_every_type` the landed cell goes through, so the offer and
    the gate answer one way about one value.

    The reason is CARRIED into the message rather than dropped: a withheld `use:` line beside a
    sentence that just named the key as legal reads as the validator forgetting itself, and the
    author's next move is to write that row by hand — which is the row this withheld. The
    enums it cites are the REAL slot keys `defender-invlang enum` answers on; a glob
    (`enum compute.*`) is not a slot and exits non-zero on the one lookup the sentence is
    telling the author to make.
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
    """The `use:` alternatives offered for one illegal refinement key — key cell swapped in
    place — and the reason each withheld route was withheld.

    ROUTE BY ROUTE, not the ALL-OR-NOTHING `_candidate_refusal` its output then faces: that
    guard is about a rebuild that CORRUPTS the row, where offering the survivor would hide a
    corruption. This is about a route that is simply not the repair, and the routes beside it
    still stand.

    WITHHOLDING EVERY ROUTE IS A LEGAL ANSWER, and `kind|imaginary` on a `compute` vertex is
    the case: neither `class` nor `attrs.kind` can carry that value, so there is no repair that
    keeps it and the honest output is none plus the two reasons. Offering one anyway is the
    F-47 shape — the model pastes what it was handed and is refused a second time.
    """
    # The candidate KEYS, in offer order. The unquoted text being itself a legal key collapses
    # the two routes into one: `class` and `attrs.class` are not two readings of `"class"`, and
    # offering the pair would invite the author to pick the wrong one.
    #
    # The `attrs.` route needs a NAME to prefix. With the quotes stripped off `""` there is
    # none, and `attrs.` is legal-SHAPED — `_is_legal_refinement_key` accepts anything starting
    # with the prefix — so offering it would land an attribute whose name is the empty string.
    # That is the same "repair worse than the row" #963 is about, reachable here only because
    # the unquoting made the prefix splice succeed where `attrs.""` used to be caught by the
    # offer guard.
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
    """The warn-severity diagnostic for one `:R attr_updates` row whose `key` cell names
    neither `class`, `ident` nor an `attrs.<name>`. Split out of `_check_attr_update_keys`
    only to keep that loop under the mccabe cap; see its docstring for the raw-text rebuild
    this builds `fix` from, and `_route_refusal` for when one of the two routes is not
    offered at all.
    """
    # The LAST `key` column, because that is the cell `key` came from: `_row_dict` zips the
    # header onto the cells and a repeated column name lets the later cell win, so a header
    # spelling `key` twice makes `cols.index` point at a cell the record never read. The
    # suggestion then rewrites an innocent cell and leaves the offending one standing — a
    # repair that re-earns its own warning, forever, since the row still parses.
    at = len(cols) - 1 - cols[::-1].index("key")
    raw_cells = _split_cells_raw(row)
    if len(raw_cells) < len(cols):
        # A legal SHORT row under a header marking its trailing column(s) optional — pad out
        # to the declared width, same as `_row_cells` pads the parsed record, so the pasted
        # candidate is full-width rather than re-opening the same gap.
        raw_cells = raw_cells + [""] * (len(cols) - len(raw_cells))
    # The repair is built from the key with its wrapping quotes removed, never from the raw
    # cell: `attrs.{key}` over a quoted cell splices text the check has ALREADY judged
    # malformed behind a legal prefix (#963). When the unquoted text is itself a legal key the
    # author simply quoted, that key IS the repair and there is no second route to offer —
    # see `_repair_routes`, which owns the route list.
    basis = _unquoted_key(key)
    # TWO different questions off one unquoting. `unquoted` says the repair was BUILT from a
    # different string than the author wrote — which is what the message has to explain, and
    # it is just as surprising for `"owner"` -> `attrs.owner` as for `"class"` -> `class`.
    # `quoted_legal` says the unquoted text is itself a legal key, which is what collapses the
    # two routes into one. Conflating them left the quoted-ILLEGAL author watching their
    # quotes disappear with no sentence saying why.
    unquoted = basis != key
    quoted_legal = unquoted and _is_legal_refinement_key(basis)
    candidates, withheld = _repair_routes(
        raw_cells, at, basis, quoted_legal=quoted_legal, declared=declared, rec=rec,
    )
    # ALL-OR-NOTHING (F-M half one): put each candidate through `_candidate_refusal` — which
    # wraps the parser's OWN row reader rather than substituting it, since that reader RAISES
    # where this check returns a value — and withhold the whole suggestion the moment either
    # candidate would not come back as the author's row with one cell changed. One
    # complete-looking suggestion with the other route silently missing would be worse than
    # none.
    #
    # The refusal is CARRIED, not paraphrased: the three grounds it distinguishes are three
    # different things for the author to fix, and naming only the width sends someone counting
    # pipes on a row whose pipes are already right.
    #
    # `parsed` cannot raise here, and is not wrapped for it: `_check_attr_update_keys` reached
    # this row only by `_row_dict(block, row)` returning, and that is this same call — the
    # `default_cols` arm it resolves collapses to `block.columns or []`, which is `cols`.
    parsed = _row_cells(block, row, len(cols))
    refusal: str | None = None
    rejected = ""
    for candidate in candidates:
        refusal = _candidate_refusal(block, cols, parsed, at, candidate)
        if refusal is not None:
            rejected = candidate
            break
    # `or`, not `.get`'s default: `rec` is keyed on the block's DECLARED columns, so a header
    # that names `target` puts the key there whatever the cell holds — the default fires only
    # for a header that omits the column entirely, and a blank cell renders "on : key ...",
    # naming no object at all. Blank and absent are the same thing to a reader here.
    message = (
        f":R attr_updates on {rec.get('target') or '?'}: key {key!r} is not a "
        f"valid refinement key — use `class` (class refinement), `ident` "
        f"(identifier refinement) or `attrs.<name>` (attribute); a bare key "
        f"is dropped silently"
    )
    # ONE SENTENCE PER WITHHELD ROUTE, and none for a route that was never a candidate: the
    # `quoted_legal` reading offers exactly the key the author quoted, so a `class` refusal
    # printed beside a `"ident"` row explains withholding something nobody was going to be
    # offered.
    for reason in withheld:
        message += reason
    if unquoted:
        # Says WHY a word the author knows is legal was refused. Without it the message reads
        # as the validator not recognising `class`, and the author's next move is to argue
        # with it rather than to drop two characters. It rides on the UNQUOTING, not on the
        # keyword: the repair below drops the author's quotes either way, and an unexplained
        # transformation is the same puzzle whatever the key spells.
        message += (
            f" — a quote is part of the cell in this format, never stripped from it, so "
            f"{key} names a different key than {basis}"
        )
    if refusal is not None:
        message += (
            # QUOTES THE REBUILT ROW the refusal is ABOUT. The carried reason is the row
            # reader's verdict on a MACHINE-BUILT candidate, and it sits two lines above
            # `render_diagnostic`'s `row: <the author's line>` — so unattributed it reads as a
            # verdict on the author's row and prescribes an edit to bytes they never wrote
            # ("row has 5 cells but 4 expected", printed beside a 4-cell row).
            #
            # NO VERB INSTRUCTION HERE. `runtime.tools` already appends "Repair each flagged
            # row with `fix_row(old_row, new_row)` — or delete it with `fix_row(old_row, "")`"
            # under every rendered warn diagnostic, and it owns that vocabulary; a second copy
            # is a third place to keep in step.
            f" — the suggested repair is withheld: rebuilding this row as {rejected!r} "
            f"would not read back as a row of this block ({refusal})"
        )
    return Diagnostic(
        message=message,
        locus=Locus(block=ATTR_UPDATES_LOCUS, row_text=row),
        fix=() if refusal is not None else candidates,
        # THE one warn-severity family. The row is INERT — it changes no effective vertex
        # state — so the block it rides in is worth keeping, and the model repairs the row
        # with `fix_row` instead of re-emitting the whole block. Every other family stays a
        # refusal: nothing is written and the model re-sends.
        severity="warning",
    )


def _check_attr_update_keys(
    proposed_text: str, declared: _DeclaredTypes
) -> list[Diagnostic]:
    """`:R attr_updates` refinement rows — the KEY, and the value that key promises to carry
    — checked over the ROWS rather than the folded records.

    Reads blocks straight from the document because this is the one check that quotes a row
    back and offers a corrected one. The fold keeps `{key: value}` per target and drops the
    header, so rebuilding a row from it means assuming the conventional
    `resolved_by|target|key|value` order — a convention `_row_dict` does not enforce, since it
    zips whatever header the block declares. Against `[…|value|key]` that yields a correction
    with its columns transposed: a "fix" that earns a second refusal.

    Here the `key` CELL is replaced in place and every other cell stays where the author put
    it. A block whose header names no `key` column has no cell to substitute and no row this
    can honestly point at, so it yields nothing — the row is not a refinement at all.

    The VALUE cell is the second family, and a REFUSAL rather than a warning. A present-but-
    blank value is not inert: `_apply_attr_updates` would assign it, and since neither
    `has_open_slot("")` nor `is_unresolved("")` reads `""` as open, the empty cell reads as a
    RESOLUTION — `l-001|v-001|class|` makes a benign-blocking error vanish. The truncated
    3-cell row is already refused by the cell-count rule, so the hole is exactly the cell that
    is present and says nothing. No `fix` is offered: the missing value is the one thing this
    check cannot supply."""
    out: list[Diagnostic] = []
    for fence_blocks in iter_fence_blocks(proposed_text):
        # One map per FENCE, and the scope is the whole point (#962). The unit the rule is
        # about is ONE ATOMIC WRITE: `append_block` sends one ```invlang fence per call, so a
        # slot refined again in a LATER fence is the format's documented `??` -> candidate set
        # -> concrete value progression — written after gather returned something the first
        # could not know — while two rows inside ONE fence had nothing happen between them, so
        # the later row does not refine the earlier one, it contradicts it.
        #
        # THE FENCE AND NOT THE BLOCK, because a fence carries as many `:X` blocks as the
        # author put in it (the prologue's `:V` and `:L` ride in one). Keyed on the block, the
        # rule is evaded by splitting one `:R attr_updates` block into two inside the same
        # fence: same write, same value lost, no diagnostic at all — which is the defect, not
        # a near miss of it.
        #
        # HERE, not in the parser, because the rule needs the legal-key vocabulary to be true.
        # A row whose key is not `class`/`ident`/`attrs.*` never reaches effective state at all
        # (`_apply_attr_updates` skips it), so a repeat of one discards NOTHING and saying it
        # did is a false message — and it would turn the deliberately warn-severity illegal-key
        # family, whose whole point is that the row lands and is repaired in place, into a hard
        # refusal of the block it rides in. Keyed on `(target, key)` and not the resolving
        # lead: `effective_vertex_state` folds across every lead into one `(vertex, slot)`
        # value, so two leads naming one slot lose a value exactly as one lead would.
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
                    # A VALUE LOST is the defect, not a row repeated. Two rows naming one slot
                    # with the SAME value are redundant and destroy nothing — the fold lands what
                    # either row alone would land. Two with DIFFERENT values contradict each other
                    # inside one atomic write and one author-written value disappears in silence.
                    # Narrowing it this way is also what keeps `fix_row` able to repair a
                    # non-unique flagged row: it rewrites EVERY identical occurrence at once
                    # (#836 H4), so repairing two byte-identical bad rows necessarily produces two
                    # byte-identical good ones, which a rule keyed on the slot alone would refuse.
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
                # `rec`'s keys are the block's DECLARED columns, so a non-empty `key` is proof
                # the header names a `key` column to substitute into. Built from the row's RAW
                # text, not from `rec` — see `_illegal_key_diagnostic`.
                out.append(_illegal_key_diagnostic(block, row, cols, rec, key, declared))
    return out


def _check_attr_update_targets(companion: CompanionBody) -> list[str]:
    """A `:R attr_updates` row must name a graph object the document DECLARES.

    Otherwise an undeclared target lands with zero diagnostics and `effective_vertex_state`
    fabricates the object out of the refinement alone — and since `ident` is writable, the
    fabricated vertex's identifier carries a value that flows from alert content.

    EDGES count as declared targets, not only vertices. `:R attr_updates` is the surface for
    recording facts learned about ANY existing graph object, and refining an edge is ordinary
    practice (`l-001|e-001|attrs.auth_method|password` appears in the checked-in goldens)."""
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
    # The declaring types, resolved ONCE at this boundary and threaded into both readers: the
    # class-cell check dispatches a grammar on them, and the repair offer needs them to know
    # whether the route it is about to hand over would survive that same check.
    declared = _DeclaredTypes.of(companion)
    out += _plain(_check_vocab_class_cells(companion, declared))
    out += _check_attr_update_keys(proposed_text, declared)
    return out




#: The whole-cell open marker, named once so the two predicates below and every reader of
#: theirs look for the same token rather than for a literal each spells for itself.
OPEN_MARKER = "??"


def is_unresolved(value: Any) -> bool:
    """Does this cell say "not settled yet" — the WHOLE of it, not a substring.

    The two markers SKILL.md §Open questions defines, and the three-state progression it
    documents (`??` → `{a, b, c}` → concrete) is why both count: a candidate set is an upgrade
    from `??`, not a resolution of it. No comma is required — `{internal}` is a one-member set
    that still has not picked.

    Anchored to the whole value on purpose: a "contains braces" test would refuse a benign
    close over a legitimate `attrs.cmdline` that happens to carry `{...}`.

    An OPENING brace with no close counts as open — otherwise a single dropped `}` reads as
    CONCRETE and closes benign over the class it was still enumerating (`role={internal, dmz`
    satisfies neither of the other two tests).

    That `count("{") > count("}")` test is load-bearing ON TOP of the whole-value anchor, not a
    replacement for it. The anchor alone reads any value that merely BEGINS with a brace as
    open, closed or not — `attrs.cmdline={ cd /x && ls; } >out` and a JSON-shaped attribute
    both start with `{` and carry their close. The anchor still narrows: a shell command
    carrying an unclosed `{` does not START with one, so it stays clean.
    """
    if not isinstance(value, str):
        return False
    v = value.strip()
    if v == OPEN_MARKER:
        return True
    return v.startswith("{") and (v.endswith("}") or v.count("{") > v.count("}"))


def is_ident_open(value: Any) -> bool:
    """Does this `ident` cell still carry an open question — WHOLE-cell or EMBEDDED.

    Unlike a class slot or an attribute value, an identifier is routinely named IN PART, and
    the committed investigations do exactly that: `bash[pid=??]` and `??[pid=??]` for a process
    whose binary is known and whose pid is not, `dev-ws-??` for a host whose prefix is known
    and whose index is not.

    `is_unresolved` is anchored to the whole cell and calls every one of those SETTLED,
    which is the wrong answer for BOTH halves of the retrieval key (#919): a
    `frontier_nodes: {slot: ident}` lesson — "pin the pid before you attribute the process" —
    could never fire on the document that needs it, and an `observed_nodes: {slot: ident}`
    lesson fires instead, asserting the run HOLDS an identifier that literally reads `??`.

    SUBSTRING, deliberately, and only here. `is_unresolved` stays whole-cell anchored because
    an `attrs.cmdline` may legitimately carry braces or a literal `?`; an ident cell is a name
    the document CHOSE, and `??` inside one is the marker rather than data. Scope is retrieval
    only — `_check_benign_open_slots` passes `include_ident=False`, so widening this cannot
    move a disposition gate.

    A SUPERSET of `is_unresolved`, never a replacement for it. The embedded test alone loses
    the OTHER marker: SKILL.md's progression is `??` → `{a, b}` → concrete, so an ident cell
    reading `{dev-ws-1, dev-ws-2}` has not picked a name — and a substring test for `??` calls
    it SETTLED, which is the exact inversion this predicate exists to prevent for `??`. The
    class and attribute arms already read a candidate set as open; the ident arm has to agree.
    """
    return is_unresolved(value) or (isinstance(value, str) and OPEN_MARKER in value)


def class_slots(classification: str) -> list[str]:
    """A class cell's slots — the slash-tuple, minus an optional leading `<type>:` prefix.

    Brace-aware, because the primary candidate-set form enumerates whole triples
    (`{monitoring-agent/internal/known-corp, ip-only/internet/novel}`) and a plain
    `split("/")` would shred it into slots that are neither open nor concrete. Splitting at
    depth 0 only reads that cell as the ONE unresolved slot it is, and still reads the
    per-slot form (`role/{internal, dmz}/prov`) as three.

    The type prefix is stripped rather than tolerated: SKILL.md says the class cell carries
    the slash-tuple only, but `compute:{...}` is a spelling models reach for, and the prefix
    alone would otherwise hide the candidate set behind it.

    PUBLIC for the same reason `effective_vertex_state` below is: `has_open_slot` uses this
    split to decide a class cell is OPEN, and `scripts/lessons/lessons_frontier.py` re-splits
    the same cell to decide which selector matches it. A second, plainer `split("/")` there
    read the whole-triple candidate set as five fragments and kept the `compute:` prefix, so
    the two halves of one join disagreed about what a slot even is (#919).
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
    """Is this ONE ALREADY-SPLIT class slot unresolved.

    PUBLIC and separate from `has_open_slot` because `scripts/lessons/lessons_frontier.py`
    needs exactly this half: it has already run `class_slots` and holds the slots, and calling
    `has_open_slot` on one of them re-splits it and strips a leading `<head>:` prefix — so the
    cell that decided a slot was OPEN and the cell that wildcards it disagreed about the values
    the two exist to agree on (#919). One definition, two readers, rather than a copy per
    reader.

    A `{` the author never closed is an UNTERMINATED candidate set and counts as open: the
    depth-aware split in `class_slots` folds every slot after it into one cell that is neither
    `??` nor a closed `{...}`, so a single dropped `}` would read as CONCRETE. A stray `}` with
    no `{` is left alone — it splits like any other character and hides nothing.
    """
    return is_unresolved(slot) or slot.count("{") > slot.count("}")


def has_open_slot(classification: Any) -> bool:
    if not isinstance(classification, str):
        return False
    return any(is_open_slot(slot) for slot in class_slots(classification))


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
                # Seeded from the DECLARED `:V` identifier. Both construction sites carry the
                # slot — one present at only one of them is a KeyError for the consumer on
                # every document that does not happen to exercise the other.
                "identifier": v.get("identifier", ""),
                "attributes": dict(v.get("attributes") or {}),
            },
        )
        # BLANK counts as unsettled here, exactly as it does on the ident arm below.
        # `classification` is not a required `:V` column, so `v-001|compute|||attrs` is
        # diagnostic-clean, and the pre-#919 test — `has_open_slot(cur["classification"])` —
        # is False for `""`, so the concrete class a later `observations.vertices` row
        # supplies was dropped. That only mattered once `iter_vertex_cells` stamped the class
        # tuple onto EVERY cell: a latched `""` makes `_class_pins` refuse a class-bearing
        # selector against the vertex's ident and attrs cells too, not just its class cell.
        #
        # A SELECTOR NAMING SLOT 0, since #935. `_class_pins` now pads a short cell to the
        # type's arity, and a blank cell splits as `['']` rather than `[]` — so the padding
        # reaches the trailing slots and a selector wildcarding slot 0 matches at zero, while
        # one naming it concretely still refuses, `""` being neither open nor equal to
        # anything. The direction below is unchanged; only the breadth of that refusal is.
        #
        # Still one direction, and still never blank→OPEN: taking an unresolved class over an
        # empty one would newly BLOCK a benign close on a document the gate accepts today.
        held_cls = cur["classification"]
        if cls and not has_open_slot(cls) and (
            not (isinstance(held_cls, str) and held_cls.strip()) or has_open_slot(held_cls)
        ):
            cur["classification"] = cls
        # The IDENT half of the same rule, and it only started mattering when
        # `iter_vertex_cells(include_ident=True)` gave the slot a reader (#919). Re-observing a
        # vertex is how an append-only document NAMES the entity it opened with `ident=??`
        # (SKILL.md §Open questions now recommends that spelling over a guessed identifier), so
        # without this the frontier reports `ident=??` open on a vertex the run already named,
        # re-pushes the "name this entity" lesson forever, and withholds every
        # `observed_nodes: {slot: ident}` selector from the resolved value.
        #
        # UNSETTLED, not just `??`, and BLANK is one of the unsettled states: an empty ident
        # column is neither open nor held and no open predicate reads `""` (see
        # `_apply_attr_updates` on why none may), so without this arm a vertex declared with
        # an empty ident and later named in a lead's `observations.vertices` folds to `""`
        # and the run's answer to "which host is this IP" reaches NO lane at all.
        #
        # The INCOMING value is not required to be settled, only non-blank. `bash[pid=??]` is
        # the shape this arm was written for — a process whose binary the run has and whose
        # pid it has not — and demanding a settled value dropped it, leaving the cell `""`:
        # not an `OpenSlot` either, so the "pin the pid before you attribute the process"
        # lesson could not fire on the document that needs it.
        #
        # One direction only, like the class arm: the guard is on what is HELD, so a later row
        # can supersede a blank or still-open cell and can never re-open a settled name.
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
            # A refinement with nothing in its value cell resolves nothing. The parser defaults
            # an absent value to `""`, and `has_open_slot("")` / `is_unresolved("")` are both
            # False — so assigning it would read not as a downgrade but as a RESOLUTION, and
            # `l-001|v-001|class|` would clear the very `??` the row was meant to settle.
            # `_check_attr_update_keys` refuses the row outright; this keeps the read side
            # honest on a document that never went through the gate.
            if not isinstance(val, str) or not val.strip():
                continue
            if key == SLOT_CLASS:
                st["classification"] = val
            elif key == IDENT_REFINEMENT_KEY:
                # A DISTINCT top-level slot, never `attributes["ident"]` — see
                # IDENT_REFINEMENT_KEY. Last row in document order wins; the fold retains
                # no history, so a superseded value survives only as the rows on disk.
                st["identifier"] = val
            elif isinstance(key, str) and key.startswith(ATTR_PREFIX):
                st["attributes"][key[len(ATTR_PREFIX):]] = val


def effective_vertex_state(
    companion: CompanionBody,
) -> dict[str, dict[str, Any]]:
    """Every vertex as it stands NOW — declared `:V` state with every `:R attr_updates` row
    applied, last row winning.

    PUBLIC because it is the read-side answer to "what does the document currently say",
    which two independent consumers need: the benign-disposition gate below, and the
    frontier derivation `frontier.py` keys lesson retrieval on (#919). Both must see one
    fold of the document, not two that can drift.
    """
    state: dict[str, dict[str, Any]] = {}
    _seed_vertex_state(companion, state)
    _apply_attr_updates(companion, state)
    return state


#: The three states a vertex cell can be in. NOT a bool: open and held are not complements —
#: an absent cell is neither, and collapsing it into `held` would report every attribute a
#: vertex never carried as something the run KNOWS (`frontier.HeldFact`).
CELL_OPEN = "open"
CELL_HELD = "held"
CELL_EMPTY = "empty"


@dataclass(frozen=True)
class VertexCell:
    """One `(vertex, slot)` cell of the folded document, classified open / held / empty.

    THE node-axis walk. Two consumers read it, and they disagree about what to DO with a cell,
    never about what the cell IS: the benign-disposition gate (`_check_benign_open_slots`)
    blocks on the open ones, and `frontier._node_state` keys lesson retrieval on both populated
    halves (#919, PR-930). Before this they were two walks that agreed by inspection.
    """

    vertex_id: str
    #: The vertex's effective class tuple, carried on EVERY cell rather than only the `class`
    #: one, because a lesson selector matches `{type, class, slot}` as a triple — an
    #: `attrs.loginuid` cell still has to say what kind of vertex it sits on.
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
    """A cell as text. A non-`str` is read as ABSENT rather than crashing the walk.

    Both open tests already guard their input and answer False for a non-`str`, so this only
    restates their tolerance for the emptiness test below — which reaches for `.strip()` and
    would otherwise take down a whole document's frontier over one malformed attribute."""
    return value if isinstance(value, str) else ""


def _cell_state(value: str, *, open_test: Callable[[Any], bool]) -> str:
    """Classify one already-folded cell.

    `open_test` varies by slot and the variation is load-bearing: a class cell is open when ANY
    of its slash-slots is (`has_open_slot`), while `ident` and `attrs` cells are single values
    that `is_unresolved` reads whole. Running `is_unresolved` across a class tuple would read
    `a/??/c` as concrete — it is the WHOLE cell that is neither `??` nor a candidate set.

    Emptiness is tested FIRST and independently, because neither predicate reads `""` as open —
    see `_apply_attr_updates` on why a blank value must never read as a resolution."""
    if not value.strip():
        return CELL_EMPTY
    return CELL_OPEN if open_test(value) else CELL_HELD


def iter_vertex_cells(
    companion: CompanionBody, *, include_ident: bool
) -> Iterator[VertexCell]:
    """Every vertex cell the folded document holds, in document order, class → ident → attrs.

    `include_ident` is the first of the two divergences `frontier.py`'s module docstring
    records, hoisted out of a comment and into the signature. The gate passes False — an
    unresolved identifier must not block a benign close, which is the whole reason
    `IDENT_REFINEMENT_KEY` routes `ident` to its own top-level slot instead of into
    `attributes`. Retrieval passes True, because an unresolved identifier is the single most
    retrieval-worthy open slot there is.

    The second divergence is deliberately NOT a parameter. `effective_vertex_state` fabricates
    an entry for any `:R attr_updates` TARGET and the validator admits an `e-*` there, so some
    ids yielded here have no `:V` row at all. This walk reports them: the gate blocks on them
    today and must keep doing so, and dropping them here would narrow it silently. It is the
    CONSUMER that needs a vertex type to match a selector against, so that filter — and the
    limitation it creates — belongs in `frontier._node_state`, where it is recorded.
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


#: The two catch-alls SKILL.md §Closed vocabularies gives an author whose case the catalog does
#: not hold — `unclassified-{type}` ("type known, sub-kind unknown") and `ambiguous-{a}-or-{b}`
#: ("genuinely indistinguishable"). Both are DELIBERATELY outside every enum, so the membership
#: test below has to know them by name or it refuses the two spellings the skill hands out for
#: the case it cannot enumerate. Distinct from `??`: those read as OPEN and gate the disposition,
#: while these are settled answers saying the catalog has no fitting value.
CATCHALL_PREFIXES: tuple[str, ...] = ("unclassified-", "ambiguous-")


def is_catchall_slot(value: Any) -> bool:
    """Does this already-split cell name one of the two documented catch-alls."""
    return isinstance(value, str) and value.strip().startswith(CATCHALL_PREFIXES)


def _vocab_cell_errors(
    vertex_id: str, slot_key: str, value: str, where: str
) -> list[str]:
    """One cell against the `SLOTS` enum that closes it, with the escape hatches taken out first.

    An OPEN cell (`??`, a candidate set) is not a wrong value, it is the absence of one, and
    `_check_benign_open_slots` is what holds a run to closing it; refusing it here would refuse
    the very spelling SKILL.md §Open questions asks for. A CATCH-ALL is a settled answer the
    catalog does not hold. Everything else is a claim about a closed vocabulary and is tested.

    UNQUOTED first, for the reason `_cell` is: a quote PROTECTS a delimiter in this format and
    is kept by the splitter, so the same value reaches this check bare from a `:V` attrs cell
    (`_parse_attrs` unquotes) and quoted from a `:R attr_updates` value cell (`_split_cells`
    does not). Testing the raw bytes refuses `attrs.kind|"container"` while passing
    `kind="container"` — one vocabulary answering two ways about one value. Stripping is the
    same argument one step down: a quoted cell may carry padding INSIDE the quotes, and testing
    the padded bytes while QUOTING the trimmed ones back at the author prints a refusal naming
    a value that is in the enum.

    A value that FAILS its own slot but IS a member of some OTHER VERTEX slot's vocabulary names
    that slot in the message — `container` is not a `compute.role`, but it is a `compute.kind`,
    and the model's next move should be moving the value, not guessing at the right one from
    `enum compute.role` alone. `vocab.vertex_slots_holding` owns which slots may be named and in
    what order; a hint naming `enum relations` or `enum types` points at a catalog no cell on a
    vertex is ever drawn from.
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
    """One `attrs.<name>` REFINEMENT KEY carrying `value`, against the enum that closes the
    pair — empty where the pair names no closed vocabulary, which is the legal case.

    The `attrs` half of what `_class_cell_errors` is for the `class` half: both the offer
    (`_route_refusal`) and the landed cell (`_folded_cell_errors`) ask through here, so a
    route the validator hands over and a row the validator then judges cannot disagree.
    """
    slot_key = vocab.attr_slot_key(vertex_type, key[len(ATTR_PREFIX):])
    if slot_key is None:
        return []
    return _vocab_cell_errors(vertex_id, slot_key, value, f"`{key}`")


def _class_cell_errors(vertex_id: str, vertex_type: str, value: str) -> list[str]:
    """A WHOLE `class` cell against its type's grammar — the one home for the per-slot zip.

    Two callers, and they must agree byte for byte or the validator offers a repair it then
    refuses: `_check_vocab_class_cells` refuses a landed cell, and `_illegal_key_diagnostic`
    asks the same question about a candidate row BEFORE offering it, so the `class` route is
    withheld exactly when this would refuse what it produces.

    ZIPPED, so a cell naming FEWER slots than its type's grammar is judged on the ones it
    named. A short cell is its own defect (#935: `ip-only/??` says nothing about which slot it
    left out) and belongs to whatever rule refuses it, not to a membership test that would
    report the missing slots as off-vocabulary.

    UNQUOTED before the split, not after: `class_slots` splits on `/` at brace depth 0 and a
    `"` is not a brace, so a whole-cell-quoted tuple (`class|"web-server/internal/known-corp"`,
    which `_split_cells` hands back with its quotes) shreds into `"web-server` and
    `known-corp"` and earns two refusals about slots the author spelled correctly.
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
    """One folded `class` or `attrs.<name>` cell against its vertex's grammar.

    Split from `_check_vocab_class_cells`'s loop so the per-type judgement is ONE expression
    `_DeclaredTypes.refusal_under_every_type` can run once per declared type, rather than a
    branch the caller would have to re-enter per type.
    """
    def judge(vertex_type: str) -> list[str]:
        if cell.slot == SLOT_CLASS:
            return _class_cell_errors(cell.vertex_id, vertex_type, cell.value)
        return _attr_route_errors(cell.vertex_id, vertex_type, cell.slot, cell.value)

    return declared.refusal_under_every_type(cell.vertex_id, judge)


def _declared_row_errors(companion: CompanionBody) -> list[str]:
    """Every `:V` ROW's own `class` cell and `attrs` siblings, judged by THAT ROW's own type.

    The fold is not enough on its own, and the gap is the defect's own shape. `_seed_vertex_
    state` upgrades a held classification only when the held one is BLANK or OPEN, so a concrete
    cell written over a concrete one is DROPPED — a prologue reading
    `v-001|compute|web-server/internal/known-corp` followed by an observations row reading
    `v-001|compute|container/internal/novel` folds to the first, and the folded walk below never
    sees the second. It is on disk forever under append-only, it is the write the model just
    made, and it is the exact category confusion #986 is about.

    Judged ROW-WISE, which is also why this needs no `_DeclaredTypes`: a row carries its
    own `type` cell, so there is no pairing of two folds to disagree — the ambiguity that
    makes the folded walk judge a re-declared id under all of its types does not exist here.
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
    """A vertex's `class` tuple and its closed-vocabulary `attrs` siblings, per type (#986).

    `_check_vocab_vertices` refuses an unknown `type` and `_check_vocab_edges` an unknown
    `rel` — but nothing read INSIDE a `class` cell, and the cell is where the type's whole
    grammar lives. A run that resolved a container's identity wrote
    `v-005|compute|container/internal/novel|db-1|`: `container` is a `COMPUTE_KIND`, the
    vertex's deployment form, and the first slot of a `compute` class tuple is its ROLE. The
    write landed clean, the category confusion reached the frontier as a held fact, and every
    lesson selector keyed on `compute.role` then matched — or missed — on a value from another
    axis entirely.

    TWO WALKS, deduped: `_declared_row_errors` reads each `:V` row against its OWN type cell —
    which is the only reading that sees a concrete class the fold DISCARDS — and the folded walk
    below is what reaches a value only a `:R attr_updates` refinement supplies. A cell both
    walks judge yields one message twice; the dedup at the end is what keeps that from
    double-reporting rather than either walk narrowing to avoid the other.

    Over `iter_vertex_cells`, which is the FOLDED document: a `:R attr_updates` row carrying
    `key=class` or `key=attrs.kind` is how SKILL.md §Open questions says a lead closes an open
    slot, so the refinement is the write most likely to name a value, and reading the `:V` rows
    alone would check every cell except the one an author most often fills. Folding also means a
    superseded value is judged by what SUPERSEDED it — which is the only reading append-only
    allows: the earlier row is on disk forever and cannot be rewritten.

    The declaring `:V` rows supply the type, and a cell whose id has no `:V` row is skipped for
    the reason `frontier._node_state` skips it: `effective_vertex_state` fabricates an entry for
    any `:R attr_updates` target and the validator admits an `e-*` there, so there is no vertex
    type to dispatch a grammar on. `_check_attr_update_targets` is what refuses a target naming
    nothing at all.

    A vertex whose `:V` rows disagree on `type` is judged under ALL of them and refused only
    where NONE can hold the value (`_DeclaredTypes.refusal_under_every_type`), and is NOT read
    through `_walkers.vertex_types`, whose own docstring forbids exactly this pairing: it is
    FIRST-DECLARATION-WINS while `effective_vertex_state` folds a LATER row's class over an open
    one, so the two answer about different rows the moment a document re-declares an id under a
    second type — which the validator accepts silently (#919 follow-up). Pairing them judges
    `v-001|session|interactive` by the `compute` grammar of the row above it and refuses
    `interactive` as a `compute.role`, a refusal about a cell nobody wrote. Skipping the id
    outright was the other extreme and the worse one: it made a second declaration a way to
    smuggle a `:R attr_updates` refinement — the write this check exists for — past it.
    """
    errors: list[str] = _declared_row_errors(companion)
    for cell in iter_vertex_cells(companion, include_ident=False):
        if cell.slot == SLOT_CLASS or cell.slot.startswith(ATTR_PREFIX):
            errors += _folded_cell_errors(declared, cell)
    # One message per (vertex, slot, value), in first-seen order: a cell the declared-row walk
    # and the folded walk both judge is ONE defect, and a refusal printed twice reads as two.
    return list(dict.fromkeys(errors))


def _check_benign_open_slots(companion: CompanionBody) -> list[str]:
    """The open cells that block a benign close, over the one shared walk.

    `include_ident=False`: see `IDENT_REFINEMENT_KEY`. An unresolved identifier does not block —
    routing `ident` where this check can see it is the exact mistake that key exists to prevent.
    """
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
        # No `else`. The two arms above are the two slot kinds `include_ident=False` yields
        # today, but the walk is SHARED and takes a knob — a bare `else` would render an
        # `ident` cell as `attribute ''` (`"ident"[len("attrs."):]` is `""`), a nonsense refusal
        # naming an attribute that does not exist, and one that contradicts the whole reason
        # `IDENT_REFINEMENT_KEY` routes `ident` out of `attributes`. A fourth slot kind reaching
        # here should be a visible gap, not a mislabelled attribute.
    return errors


def _anchor_kind(record: Any) -> str:
    """The anchor kind a `:H h-NNN.authz` contract or a `:R authz` row carries, normalized.

    Through `_cell`, because this is the only column the two sides of the shared-`ac<n>`
    discrimination both carry — `_hyp_sub_authz_row` copies it verbatim and
    `_canonicalize_resolution_row` copies it verbatim, so an author who quotes uniformly makes
    the two halves of one comparison disagree about a kind they spell identically, and no row
    can then be attributed to its contract.
    """
    return _cell(record, "anchor_kind") if isinstance(record, dict) else ""


def _declarers_by_contract_id(
    companion: CompanionBody,
) -> dict[str, list[tuple[str, str]]]:
    """Every `(hypothesis, anchor kind)` that declares each `ac*` id — LIVE OR NOT.

    A different question from the one `_check_authz_contract_ids` indexes, which is why the
    live filter is not shared. That check asks "is this collision still repairable"; this one
    asks "which contract does a `:R authz` row naming this id answer", and a refuted declarer
    competes for the row exactly as a live one does — the row carries no hypothesis column.
    """
    declared_by: dict[str, list[tuple[str, str]]] = {}
    for hid, hyp in _walkers.all_hypotheses(companion).items():
        for c in hyp.get("authorization_contract") or []:
            if not isinstance(c, dict):
                continue
            # `_cell`, which unquotes: `_hyp_sub_authz_row` copies `id` verbatim while every
            # reader matches it against a `fulfills` cell read through `_cell`, so a quoted
            # declaring id is a contract no row can ever discharge — and rule #26's refusal
            # then advises a `fulfills="ac1"` cell that unquotes straight back to `ac1`.
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
        # The anchor kind is always present: `_hyp_sub_authz_row` `_require`s it, so a
        # `:H <h>.authz` row without one is a parse error and the contract never reaches the
        # companion. That is what makes the kind a usable discriminator here.
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
    # The LIST, not `next(..., None)`: `None` is a verdict a row can carry, so the sentinel
    # and the value would be the same object and a `None` verdict would discharge the contract
    # it is the strongest evidence against. Emptiness is the only test that cannot collide.
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
    """Every `(hypothesis, contract, why)` on a LIVE hypothesis that no `:R authz` row
    discharges — THE definition of "this authorization question is still open".

    PUBLIC, and published for the same reason `effective_vertex_state` is: two consumers need
    one answer. `_check_benign_authz` below turns each `why` into a benign-close refusal, and
    `frontier._open_contracts` puts each contract on the retrieval frontier (#919). A second
    reading of "discharged" — a bare `fulfills_contract` id set, say — silently disagrees with
    this one on every shared id, and disagrees in the harmful direction: the frontier drops
    the contract that is actually wedging the close, so the lessons about what that anchor can
    conclude are withheld exactly when the run is stuck on it.

    See `_authz_contract_error` for why a shared id is scoped by anchor kind.
    """
    live = set(_walkers.live_hypothesis_ids(companion))
    hyps = _walkers.all_hypotheses(companion)
    declarers = _declarers_by_contract_id(companion)

    verdicts: dict[str, list[tuple[str, str]]] = {}
    for row in _walkers.iter_authz_resolutions(companion):
        # `_cell`, matching `_check_authz_contract_closure`. Read raw, a uniformly quoted
        # `fulfills` keys `'"ac1"'` here and `ac1` there, so the closure gate calls the contract
        # discharged while this — the definition `_check_benign_authz` AND `frontier`
        # `_open_contracts` both read — calls it outstanding. Two answers about one row, and the
        # frontier drops the contract that is actually wedging the close.
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
    """Every authz contract on a LIVE hypothesis is discharged by an `authorized` row.

    The row that discharges it has to be attributable to it, and a bare `fulfills_contract` id
    is not always enough. `_check_authz_contract_ids` exempts a collision whose other side is
    REFUTED, because on an append-only document refuting is the only repair left once the rows
    are on disk. That exemption is sound about the CONTRACT and false about the ROW: a
    `:R authz` row written against the refuted declarer's `ac1` would discharge the LIVE
    declarer's `ac1` too, landing a benign close over a question nobody ever asked.

    So a shared id is scoped by ANCHOR KIND — the one column both sides carry, and the one that
    says which question the row answers. Scoping rather than refusing outright keeps the rule
    repairable: `:H` rows are immutable, so a live contract holding a shared `ac1` can never be
    renumbered, and "an ambiguous id discharges nothing" would make `disposition: benign`
    unreachable for the rest of that document's life. Writing the `:R authz` row that carries
    THIS contract's anchor kind is an ordinary append, and it discharges it.

    Two declarers sharing an id AND an anchor kind has no honest reading left and is refused:
    no row can be attributed, so none discharges.

    The scoping applies only where the id is shared. A contract nobody competes for is
    discharged by its id alone; making the anchor kind load-bearing document-wide would refuse
    every document that left the cell empty.
    """
    return [why for _hid, _c, why in outstanding_authz_contracts(companion)]
