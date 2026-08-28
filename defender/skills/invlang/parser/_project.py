"""The projector: walks blocks and accumulates them into the finished companion body.

Split out of `parser.py` (#god-file), where it was a 993-line class inside a 2128-line
module. It sits at the top of the layering and imports both the tokenizer and the row
builders."""


from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any, TypeVar, cast

from .._cells import (
    _has_unbalanced_quote,
    _row_cells,  # noqa: F401 — re-export: invlang tests import it from `parser`
    _row_dict,
    _split_cells,  # noqa: F401 — re-export: invlang tests import it from `parser`
    _split_quoted,  # noqa: F401 — re-export: invlang tests import it from `parser`
    _split_subcells,  # noqa: F401 — re-export: invlang tests import it from `parser`
    _unquote,
    is_conclude_empty_marker,  # noqa: F401 — re-export: parser is this name's public home
)
from .._types import Block, RowError
from ..schema import (
    AttributeUpdate,
    HypothesisRecord,
)

from ._tokenize import _LEAD_PREFIX_RE, ParseWarning
from ._rows import (
    HYPOTHESIS_ID_RE,
    _CONCLUDE_KEYS_HINT,
    _CONCLUDE_LISTS,
    _CONCLUDE_SCALARS,
    _CONCLUDE_SUBTABLE_FIELDS,
    _CROSS_BLOCK_GUARDED,
    _DEFERRAL_BLOCKS,
    _HYP_PREFIX_RE,
    _IMPACT_PRED_COLS,
    _LEAD_PRED_COLS,
    _LEAD_SUBBLOCKS,
    _MISSING,
    _RESOLUTION_BUCKET_KEY,
    _RETIRED_CEILING_TEST_BLOCK,
    _SURVIVING_COLS,
    _canonicalize_resolution_row,
    _close_loop,
    _conclude_value,
    _edge_record,
    _extend_by_id,
    _hyp_sub_attr_pred_row,
    _hyp_sub_authz_row,
    _hyp_sub_pred_row,
    _hyp_sub_refut_row,
    _hypothesis_record,
    _impact_pred_row,
    _is_current_hyp_header,
    _lead_header_record,
    _lead_pred_row,
    _resolution_record,
    _row_first_cell,
    _two_site_reason,
    _vertex_record,
)

#: One projected row, whatever the block's projector builds them as. `_warn_repeated_ids` hands
#: back the rows it did NOT warn about, and it is the caller that knows their type — a bare
#: `list[Any]` there would launder `list[dict[str, str]]` into `Any` at every call site that
#: consumes the return, which is the narrowing `_lead_header_record`'s `rec["id"]` relies on.
_RowT = TypeVar("_RowT")


@dataclass
class _Projector:

    out: dict[str, Any] = field(default_factory=dict)
    warnings: list[ParseWarning] = field(default_factory=list)
    hypotheses_by_id: dict[str, HypothesisRecord] = field(default_factory=dict)
    #: Ids the `:H hypothesize.hypotheses` table declares. The table outranks a lead's
    #: `new_hypotheses` in `hypotheses_by_id` regardless of document order, because that is
    #: the precedence `_walkers.all_hypotheses` applies on the read side.
    prologue_hypothesis_ids: set[str] = field(default_factory=set)
    findings: dict[str, dict[str, Any]] = field(default_factory=dict)

    # No "current lead" state, deliberately: a fallback to whichever lead a preceding block
    # mentioned last silently files one lead's grounding evidence under another. Every row
    # that lands on a lead names it.

    #: `:T conclude` blocks that recorded nothing, pending the whole-document verdict
    #: `flush_deferred_warnings` reaches. A list rather than a flag: two such blocks are two
    #: defects, and each names its own locus.
    empty_conclude_blocks: list[Block] = field(default_factory=list)

    def lead_bucket(self, lead_id: str) -> dict[str, Any]:
        lead = self.findings.setdefault(lead_id, {"id": lead_id})
        lead.setdefault("outcome", {})
        lead.setdefault("query_details", {})
        lead.setdefault("resolutions", [])
        return lead

    def _warn(
        self,
        block: Block,
        row_index: int,
        row: str,
        reason: str,
        dropped_ids: tuple[str, ...] = (),
    ) -> None:
        self.warnings.append(ParseWarning(
            block=f":{block.tag} {block.name}",
            row_index=row_index,
            row=row,
            reason=reason,
            dropped_ids=dropped_ids,
        ))

    def _project_rows(self, block: Block, project_one) -> list[Any]:
        projected: list[Any] = []
        for idx, row in enumerate(block.rows):
            try:
                projected.append(project_one(block, row))
            except RowError as e:
                self._warn(block, idx, row, str(e))
        return projected

    def _marked_rows(self, block: Block, project_one) -> list[Any]:
        """`_project_rows`, minus the empty-TABLE marker.

        A lone `none` / `n/a` row says the table is empty; `_row_cells` pads it to the block
        width so it reaches `project_one` as a real record with `id == "none"`. The two `:L`
        plan blocks are the callers. `_project_surviving_block` and `_project_deferral_block`
        drop the same marker INLINE rather than through here, because they warn per row and so
        need the `idx`/`row` this generator has already spent — the shared piece between all
        four is `is_conclude_empty_marker`, which is where the rule lives.
        """
        return [
            rec for rec in self._project_rows(block, project_one)
            # lint-row-drop: ok — the empty-TABLE marker, not a row
            if not is_conclude_empty_marker(rec.get("id"))
        ]

    def _for_each_row(
        self, block: Block, default_cols: list[str] | None = None
    ) -> Iterator[tuple[int, str, dict[str, str]]]:
        for idx, row in enumerate(block.rows):
            try:
                rec = _row_dict(block, row, default_cols)
            except RowError as e:
                self._warn(block, idx, row, str(e))
                continue
            yield idx, row, rec


    def _check_one_line_rows(self, block: Block) -> None:
        """Every invlang row is ONE line, in every block.

        `_tokenize_fence` makes a row per line, so a value written across two lines keeps line
        one with its quote dangling and reparses the rest as fresh rows — dropped, or worse,
        landing on whatever key the continuation's first word happens to name. The guard is
        here rather than inside one block's projector because the truncation is a property of
        the line-oriented surface, not of `:T conclude`: a two-line `:L findings` name loses
        the lead's target, loop and system just as quietly.
        """
        for idx, row in enumerate(block.rows):
            if _has_unbalanced_quote(row):
                self._warn(
                    block, idx, row,
                    "row opens a quoted value that does not close on this row — invlang rows "
                    "are ONE line each, so the lines below it are parsed as separate rows and "
                    "the rest of the value is dropped. Write it as ONE line (long is fine — "
                    "`summary` routinely is).",
                )

    def project_block(self, block: Block) -> None:
        tag, name = block.tag, block.name
        self._check_one_line_rows(block)

        # Extend, never assign — same reason as `:H`. Append-only forbids rewriting a
        # committed block, so a second `:V prologue.vertices` is the only legal way to add
        # one, and assignment would delete every vertex the first block declared.
        if tag == "V" and name == "prologue.vertices":
            vertices = self._project_rows(block, _vertex_record)
            self._warn_repeated_ids(block, vertices)
            _extend_by_id(
                self.out.setdefault("prologue", {}).setdefault("vertices", []),
                vertices,
            )
            return
        if tag == "E" and name == "prologue.edges":
            edges = self._project_rows(block, _edge_record)
            self._warn_repeated_ids(block, edges)
            _extend_by_id(
                self.out.setdefault("prologue", {}).setdefault("edges", []),
                edges,
            )
            return
        if tag == "H" and name == "hypothesize.hypotheses":
            self._project_hypothesize_block(block)
            return

        m_hyp_sub = _HYP_PREFIX_RE.match(name) if tag == "H" else None
        if m_hyp_sub:
            self._project_hyp_subblock(
                block, m_hyp_sub.group("hyp"), m_hyp_sub.group("sub"),
            )
            return

        if tag == "L" and name == "findings":
            self._project_findings_block(block)
            return

        m = _LEAD_PREFIX_RE.match(name)
        if m:
            lead_id = "l-" + m.group("id")
            sub = m.group("sub")
            self._project_lead_subblock(tag, sub, block, self.lead_bucket(lead_id))
            return

        if tag == "R" and name in _RESOLUTION_BUCKET_KEY:
            self._project_resolution_block(block)
            return

        if tag == "T" and self._project_t_block(block):
            return

        self._warn(block, -1, "", "unknown block — no projection rule")

    def _land_conclude_row(
        self,
        key: str,
        value: Any,
        conclude: dict[str, Any],
        termination: dict[str, Any],
        seen: set[str],
    ) -> bool:
        """Put ONE recognized `:T conclude` row where it goes. True when something landed.

        Split out of `_project_conclude_scalars` so the caller stays under the complexity gate;
        it is also where "recognized" and "recorded something" come apart. `seen` marks a key
        the projection KNOWS (the duplicate-row warning's question), and the return value marks
        a key that recorded a VALUE — a lone `ceiling_test  none` is the first and not the
        second, which is why `_warn_conclude_recorded_nothing` cannot read `seen`.

        An unrecognized key falls through to `False` and is not warned; the caller records why.
        """
        if key == "termination.category":
            seen.add(key)
            termination["category"] = value
            return True
        if key == "termination.rationale":
            seen.add(key)
            termination["rationale"] = value
            return True
        if key in _CONCLUDE_LISTS:
            seen.add(key)
            # `value is None` is the caller's mapping of the literal `null`, which the format
            # spells beside `none` for the same "nothing to say" — `is_conclude_empty_marker`
            # cannot see it, because by here the string is already gone. Without this arm
            # `ceiling_test  null` appends `None` into a declared `list[str]` AND makes
            # `conclude` truthy, so `validate._is_closing` reads a mid-run block as a close
            # and the three closure gates refuse every commitment the run has not reached.
            if value is None or is_conclude_empty_marker(value):
                return False  # lint-row-drop: ok — the empty-ARRAY marker, not a row
            cast(list[str], conclude.setdefault(key, [])).append(value)
            return True
        if key in _CONCLUDE_SCALARS:
            seen.add(key)
            conclude[key] = value
            return True
        return False

    def _project_conclude_scalars(self, block: Block) -> None:
        conclude: dict[str, Any] = self.out.setdefault("conclude", {})
        termination: dict[str, Any] = {}
        seen: set[str] = set()
        #: Did any row of THIS block reach the projection? Not `seen` — a lone
        #: `ceiling_test  none` is a recognized key that lands nothing — and not `conclude`
        #: emptiness either, since a `:T conclude.surviving` block earlier in the document
        #: already opened that dict.
        landed = False
        for index, row in enumerate(block.rows):
            m = re.match(r"^(\S+)\s+(.*)$", row)
            if not m:
                self._warn(
                    block, index, row,
                    f"conclude: row records nothing — every row is `<key> <value>` on one "
                    f"line, keyed by one of {_CONCLUDE_KEYS_HINT}. If this is the "
                    f"continuation of a value from the row above, join it onto one line.",
                )
                continue
            key = m.group(1)
            raw = m.group(2).strip()
            value: Any = None if raw == "null" else _unquote(raw)
            if key in seen and key not in _CONCLUDE_LISTS:
                # The continuation of a two-line value lands on whatever key its first word
                # names, so this fires on the row that silently overwrote a real conclusion.
                # A list key is exempt: repetition is how it carries more than one item.
                self._warn(
                    block, index, row,
                    f"conclude: {key!r} is set twice in this block; the later row wins and "
                    f"the earlier value is lost. Keep one row per key, and join a value that "
                    f"spilled onto a second line back into one line.",
                )
            elif (
                key in _CROSS_BLOCK_GUARDED
                and _conclude_value(conclude, key) is not _MISSING
                and _conclude_value(conclude, key) != value
            ):
                # The SAME loss one block over. `seen` is per-block while `conclude` is
                # document-wide, so a close that arrives as two `:T conclude` blocks — the
                # shape `_warn_conclude_recorded_nothing` is written around — could restate
                # `disposition` and silently replace it, with every downstream gate
                # (`_check_disposition_gating`, `_check_benign_authz`, `spoken_for`) then
                # running against a keyword the run only half wrote. Narrowed to a CHANGED
                # value: re-stating a key with the same value loses nothing, and append-only
                # means a document already carrying that shape must stay writable.
                self._warn(
                    block, index, row,
                    f"conclude: {key!r} is already set to "
                    f"{_conclude_value(conclude, key)!r} by an earlier "
                    f"`:T conclude` block, and this row replaces it — append-only means the "
                    f"first value cannot be withdrawn, so the two rows are a disagreement "
                    f"rather than a correction. Drop this row, or restate the value the "
                    f"close is actually making everywhere it appears.",
                )
            landed |= self._land_conclude_row(key, value, conclude, termination, seen)
            # An unrecognized key is IGNORED, not warned. It reads like the obvious place to
            # catch an unquoted value that spilled onto a second line, and it cannot be: the
            # lessons corpus can instruct conclude rows this projection does not carry, and
            # `learning/core/persist.py` dead-letters a run whose investigation.md fails
            # validation rather than learning from it — so a warning here turns "the model
            # obeyed a lesson" into a discarded run. The truncation is caught upstream by
            # `_check_one_line_rows` on quote parity, which fires on both halves of a spilled
            # quoted value without needing to know which keys are real. An unquoted spill
            # stays undetected; that is the price of not denying instructed content.
        if termination:
            # MERGED, never assigned. `termination` is a per-BLOCK local while `conclude` is
            # document-wide, so an assignment lets a second `:T conclude` block that restates
            # one of the two rows delete the other — `termination.rationale` alone wipes the
            # `category` `_check_ceiling_test_scope` (#13) reads, and the rule then stands down
            # on a document that named its ceiling. The guard above now warns when a row
            # CHANGES a value; this is what stops a row it does not name from erasing one.
            cast(dict[str, Any], conclude.setdefault("termination", {})).update(termination)
        if not landed:
            # Not `block.rows and not landed`: a `:T conclude` block written with no rows under
            # it — a truncated or interrupted REPORT write — is the plainest case of a close
            # that records nothing, and gating on `block.rows` was the one shape that reached
            # `_is_closing` with `conclude == {}` and no diagnostic anywhere.
            #
            # DEFERRED to `flush_deferred_warnings`, never decided here. See that method.
            self.empty_conclude_blocks.append(block)

    def flush_deferred_warnings(self) -> None:
        """The warnings that can only be decided once EVERY block has been projected.

        `companion_from_blocks` calls this after its loop. A judgement made mid-loop is scoped
        to the blocks projected SO FAR, which for an append-only document means it is scoped to
        a PREFIX — and a prefix-scoped verdict is order-dependent in a format where a close may
        legally arrive as two `:T conclude` blocks in either order.
        """
        for block in self.empty_conclude_blocks:
            self._warn_conclude_recorded_nothing(block)
        self.empty_conclude_blocks.clear()

    def _warn_conclude_recorded_nothing(self, block: Block) -> None:
        """A `:T conclude` block not one of whose rows reached the projection.

        NOT the "unrecognized key" warning `_project_conclude_scalars` deliberately refuses —
        this fires only when the WHOLE block recognized nothing, which is a close that records
        nothing rather than a lesson-instructed row the projection has yet to carry. It has to
        be loud, because the three closure gates read "is this document closing" off a
        non-empty `conclude` (`validate._is_closing`), and a block that projects to `{}` would
        otherwise stand all of them down in silence — a close with every commitment abandoned
        and no diagnostic anywhere.

        Asked of the WHOLE DOCUMENT, which is why the caller defers it to
        `flush_deferred_warnings` instead of deciding inline. Append-only means a close can
        arrive as two `:T conclude` blocks, and one of them may legally carry nothing but keys
        this projection does not name — the lesson-instructed rows `_project_conclude_scalars`
        refuses to warn on, because "`learning/core/persist.py` dead-letters a run whose
        investigation.md fails validation rather than learning from it". A verdict reached
        inline sees only the blocks projected BEFORE this one, so it protects that pair in one
        order and refuses it in the other — and on a document already carrying such a block,
        every later append re-derives the refusal against a block nobody may edit.

        The sub-table fields do not count: neither `:T conclude.surviving` nor a `deferred_*`
        table is a flat close.
        """
        if set(self.out.get("conclude") or {}) - _CONCLUDE_SUBTABLE_FIELDS:
            return
        self._warn(
            block, -1, "",
            f"`:T conclude` recorded nothing — not one row keyed on a field this projection "
            f"carries, so the close projects empty and the CONCLUDE rules (#13, #24, #26, "
            f"#31, #34) all stand down. Key at least `disposition`; the fields are "
            f"{_CONCLUDE_KEYS_HINT}.",
        )

    def _project_t_block(self, block: Block) -> bool:
        name = block.name
        if name == "conclude":
            self._project_conclude_scalars(block)
            return True
        if name == "conclude.surviving":
            self._project_surviving_block(block)
            return True
        deferral = _DEFERRAL_BLOCKS.get(name)
        if deferral is not None:
            self._project_deferral_block(block, *deferral)
            return True
        if name.startswith("conclude."):
            self._warn_unknown_conclude_subblock(block)
            return True
        if name == "close":
            loop = _close_loop(block.rows)
            if loop is None:
                self._warn(
                    block, -1, "\n".join(block.rows)[:200],
                    "`:T close` needs a `loop N` (integer) row",
                )
            else:
                self.out.setdefault("closed_loops", []).append(loop)
            return True
        if name == "resolutions":
            self._project_resolutions_block(block)
            return True
        if name == "shelved":
            self._warn_retired_shelved(block)
            return True
        return False

    def _warn_retired_shelved(self, block: Block) -> None:
        """`:T shelved` is retired, and says so by name rather than as "unknown block".

        The generic fallthrough is an error pointing away from its cause — the same defect
        `_warn_unknown_conclude_subblock` exists to prevent one tag over. A run that writes the
        row is not guessing at a block tag; it is using a spelling every version of the format
        docs taught, so the refusal owes it the replacement rather than a shrug.

        Retired because no investigation on record ever wrote one, while it stayed a discharge
        arm on rules #23, #24 and #34 and two fields on the shipped document — a retirement
        route the validator honoured and the injected SKILL.md never taught, so the only runs
        that could reach it were the ones that guessed the grammar right.
        """
        self._warn(
            block, -1, "",
            "`:T shelved` is retired — a hypothesis leaves the live frontier by being "
            "RESOLVED: move its final weight to `--` in a `:T resolutions` row when the run "
            "refuted it, or NAME it in `:T conclude.surviving` when the run is still carrying "
            "it. Omitting it from a written `:T conclude.surviving` table is not a "
            "retirement — rule #24 refuses exactly that. Neither this block nor its rows are "
            "projected, so nothing here reaches the close.",
        )

    def _stale_hyp_header(self, block: Block) -> bool:
        """True (and warned) when a `:H` DECLARATION block's header is off-schema.

        One owner for both declaration sites: a lead-born record is indexed for sub-block
        attachment, so a hypothesis projected off a stale header would reach every consumer of
        `_walkers.all_hypotheses`.
        """
        if _is_current_hyp_header(block.columns):
            return False
        self._warn(
            block, -1, "",
            (
                f"column header {block.columns!r} does not match the "
                f"current schema (id|name|attached_to|rel|parent_type|"
                f"parent_class|integrity_waived?|weight|status); whole "
                f"block rejected"
            ),
            # The rows are readable even though the header is not, and their first cell is
            # the id. Naming them here is what lets the undeclared-hypothesis rule defer
            # for exactly these ids instead of for the whole document.
            dropped_ids=tuple(_row_first_cell(r) for r in block.rows),
        )
        return True

    def _project_hypothesize_block(self, block: Block) -> None:
        if self._stale_hyp_header(block):
            return
        hyps = self._project_rows(block, _hypothesis_record)
        self._warn_repeated_ids(block, hyps)
        # Extend, never assign. Append-only forbids rewriting the loop-1 block, so a loop that
        # forks a hypothesis writes a SECOND `:H hypothesize.hypotheses`; assignment would
        # delete every earlier loop's hypothesis with no parse warning, and with them the
        # `:H h-NNN.preds` a later resolution resolves against and the `:H h-NNN.authz`
        # contracts benign-gating has to find.
        _extend_by_id(
            self.out.setdefault("hypothesize", {}).setdefault("hypotheses", []), hyps
        )
        self._register_hypotheses(block, hyps, prologue=True)

    def _register_hypotheses(
        self, block: Block, hyps: list[HypothesisRecord], *, prologue: bool
    ) -> None:
        """Index the records a `:H h-NNN.<sub>` sub-block attaches to.

        Re-declaring an id at the SAME site is a re-emission: the first declaration stands,
        silently, matching `_extend_by_id` and `_walkers.all_hypotheses`. Re-declaring it at
        the OTHER site is not recoverable and is warned.

        The two sites disagree on order — `_walkers.all_hypotheses` walks the
        `:H hypothesize.hypotheses` table before any lead's `new_hypotheses`, not the
        document — so an id declared in a lead and then promoted into the table would index the
        LEAD record here and the TABLE record there, landing a `:H h-NNN.authz` between the two
        on a record no consumer reads (and passing `disposition: benign` on an unfulfilled
        contract). `prologue` realigns the precedence; the warning covers what precedence
        cannot, since a sub-block already attached to the loser cannot be moved.
        """
        for h in hyps:
            hid = h.get("id")
            if not isinstance(hid, str):
                # NOT a dropped row, which is why this warns nothing: `_hypothesis_record`
                # `_require`s `id`, so a `:H` row with an empty id cell raises `RowError` and
                # is warned by `_project_rows` before any record exists. Nothing reaching here
                # can fail this test; it narrows the type, and a warning would double-report a
                # defect already named.
                continue  # lint-row-drop: ok — no row here; a bad id was refused upstream
            if prologue:
                if hid in self.prologue_hypothesis_ids:
                    continue
                if hid in self.hypotheses_by_id:
                    self._warn(block, -1, "", _two_site_reason(hid))
                self.prologue_hypothesis_ids.add(hid)
                self.hypotheses_by_id[hid] = h
                continue
            if hid in self.prologue_hypothesis_ids:
                self._warn(block, -1, "", _two_site_reason(hid))
            elif hid not in self.hypotheses_by_id:
                self.hypotheses_by_id[hid] = h

    def _project_hyp_subblock(self, block: Block, hyp_id: str, sub: str) -> None:
        hyp = self.hypotheses_by_id.get(hyp_id)
        if hyp is None:
            self._warn(
                block, -1, "",
                f"sub-block references unknown hypothesis {hyp_id!r}",
            )
            return
        if sub == "parent_attrs":
            attrs: dict[str, str] = {}
            for _idx, _row, rec in self._for_each_row(block, ["key", "value"]):
                key = rec.get("key")
                if not key:
                    self._warn(block, _idx, _row, "parent_attrs row missing key")
                    continue
                attrs[key] = _unquote(rec.get("value", ""))
            if attrs:
                hyp.setdefault("proposed_edge", {}).setdefault(
                    "parent_vertex", {}
                ).setdefault("attributes", {}).update(attrs)
            return
        self._attach_hyp_sub_rows(block, hyp, sub)

    def _attach_hyp_sub_rows(
        self, block: Block, hyp: HypothesisRecord, sub: str
    ) -> None:
        """Project a `:H h-NNN.<sub>` block onto the field it declares.

        The destination is named at each branch rather than looked up in a `{sub: field_name}`
        table: a TypedDict write needs a LITERAL key, so the table form can only type-check by
        widening the record back to `dict[str, Any]`, which loses `HypothesisRecord` for
        everything downstream of the projector. Same reason `_walkers._iter_outcome_rows` takes
        a selector instead of a field name.

        Each branch EXTENDS, for the same reason `:H hypothesize.hypotheses` does: append-only
        forbids rewriting a committed sub-block, so a loop that adds a prediction — or an authz
        contract the benign gate has to find — writes a SECOND `:H h-NNN.<sub>`, and assignment
        would drop everything the first one declared with no parse warning.
        """
        if sub == "preds":
            if preds := self._project_rows(block, _hyp_sub_pred_row):
                self._warn_repeated_ids(block, preds)
                _extend_by_id(hyp.setdefault("predictions", []), preds)
            return
        if sub == "attr_preds":
            if attr_preds := self._project_rows(block, _hyp_sub_attr_pred_row):
                self._warn_repeated_ids(block, attr_preds)
                _extend_by_id(hyp.setdefault("attribute_predictions", []), attr_preds)
            return
        if sub == "refuts":
            if refuts := self._project_rows(block, _hyp_sub_refut_row):
                self._warn_repeated_ids(block, refuts)
                _extend_by_id(hyp.setdefault("refutation_shape", []), refuts)
            return
        if sub == "authz":
            if authz := self._project_rows(block, _hyp_sub_authz_row):
                self._warn_repeated_ids(block, authz)
                _extend_by_id(hyp.setdefault("authorization_contract", []), authz)
            return

    #: The remedy for a repeated id at the TWELVE sites where a second block really does
    #: ADD: `_extend_by_id` seeds `seen` from the destination, so the new rows land and only
    #: the repeat is dropped.
    _REPEAT_REMEDY_SECOND_BLOCK = (
        "Give each row its own id, or send the added rows as a second block."
    )
    #: `:L findings` is NOT one of them, and must not be told it is. A lead re-listed in a
    #: second `:L findings` block MERGES into its existing bucket — `lead.update(identity)`,
    #: with `_lead_header_record` writing `target` UNCONDITIONALLY — so following the advice
    #: above reproduces the very last-wins blend this warning exists to stop, and an amending
    #: row whose `target` cell is blank erases the lead's target with no diagnostic on the
    #: block that does it. `_check_false_positive_gating` then refuses the close over a lead
    #: the author never retargeted, pointing at the wrong turn.
    _REPEAT_REMEDY_ONE_BLOCK = (
        "Give each row its own id and re-send this block whole: a second `:L findings` block "
        "naming the same id AMENDS that lead rather than adding a row, so it would blend the "
        "two readings instead of separating them."
    )

    def _warn_repeated_ids(
        self, block: Block, rows: list[_RowT], remedy: str = _REPEAT_REMEDY_SECOND_BLOCK,
    ) -> list[_RowT]:
        """An id written twice in ONE sub-block DELETES the second row, so say so.

        `_extend_by_id` keeps the first record per id — correct against the re-emission it
        exists for, which is a whole block sent again as a SECOND block — but WITHIN one block
        a repeated id is never a re-emission, and the row it drops carries content nothing else
        does. A second `ac1` with a different predicate simply vanishes, and
        `_check_benign_authz` then discharges the surviving contract and closes benign over a
        legitimacy question no lead ever asked. Same shape for a second `p1`/`r1`: the
        prediction is gone while `:T resolutions` goes on citing the id.

        The four GRAPH-row sites are here for the same reason, and the benign open-slot gate
        reads them: a second `:V prologue.vertices` row repeating `v-001` by an ordinal typo
        deletes the row carrying `integrity=??`, and the document then closes benign over an
        open slot still on the page. Append-only makes that unrecoverable — the committed row
        cannot be rewritten, and a second block with the corrected id declares a DIFFERENT
        vertex — so the drop has to be loud at write time.

        The two `:H` DECLARATION sites carry the sharpest case: a repeated `h-001` in one
        `:H hypothesize.hypotheses` block deletes a whole hypothesis, and every
        `:H h-001.authz` contract then attaches to the SURVIVING row, so the benign gate
        discharges a contract the deleted hypothesis never got to state. `_register_hypotheses`
        cannot see it — it is written against the cross-BLOCK re-emission, where the first
        declaration standing silently is the sanctioned append-only shape.

        `:L findings` is the thirteenth site and the one whose rows the model edits
        individually rather than re-emitting wholesale: a lead id written twice in one block
        is not the cross-block re-listing the amendment path is built on, and the row it drops
        carries the lead's whole header — name, target, loop, system, window — which every
        reader that asks whether a lead is DECLARED then answers from the survivor alone.

        Only the rows of the block in hand are compared, which keeps that legal cross-block
        repeat silent.

        RETURNS THE SURVIVORS — the first row per id, plus every row whose id is unreadable —
        so a caller that has to ENFORCE the "only the FIRST row is kept" this message promises
        (`_project_findings_block`, which folds by `lead_bucket` rather than through
        `_extend_by_id`) reads the partition off the same walk that warned about it. The other
        twelve call sites hand the result to `_extend_by_id`, which drops the repeat itself, and
        ignore the return.
        """
        seen: set[str] = set()
        firsts: list[_RowT] = []
        for r in rows:
            rid = r.get("id") if isinstance(r, dict) else None
            if not isinstance(rid, str) or not rid:
                # A row with no readable id cannot be checked for a repeated one, and the
                # caller still projects it — so nothing is dropped here.
                firsts.append(r)
                continue  # lint-row-drop: ok — no id to compare; the caller still lands it
            if rid in seen:
                self._warn(
                    block, -1, "",
                    f"{rid!r} is declared twice in this block; only the FIRST row is kept "
                    f"and the later one is discarded with everything it declares. {remedy}",
                )
                continue  # lint-row-drop: ok — the warning above IS this row's drop channel
            seen.add(rid)
            firsts.append(r)
        return firsts

    def _off_schema_plan_header(self, block: Block, cols: list[str]) -> bool:
        """True (and warned) when a `:L` plan block's header names a column this projection
        does not read.

        The guard `_project_deferral_block` already carries, for the same defect one block over.
        `_row_dict` keys on the AUTHOR's header, so a column spelled anything else lands its
        cell EMPTY — and rules #18 / #29 then refuse the row for a cell the author filled in,
        naming the very column the header declares. The canonical field names are the reachable
        typo, because they are what `schema.py` and every refusal message use: a header written
        `[id|dimension|claim|…]` or `[id|condition|read_as|advance_to]` blanks the cell whose
        name it spells.

        A SUBSET header is left alone — rules #18 and #29 name each missing cell and what it is
        for, which is the better message. Only a column nothing reads is a block-level defect.
        """
        unread = [c for c in block.columns or () if c not in cols]
        if not unread:
            return False
        self._warn(
            block, -1, "",
            f"column header {block.columns!r} names {', '.join(repr(c) for c in unread)}, "
            f"which `:L l-NNN.{block.name.split('.', 1)[-1]}` does not read — the columns are "
            f"[{'|'.join(cols)}], so a cell under any other name is dropped and the row is then "
            f"refused for a value you wrote; whole block rejected",
        )
        return True

    def _project_lead_plan_subblock(
        self, sub: str, block: Block, lead: dict[str, Any]
    ) -> bool:
        """The `:L l-NNN.<sub>` blocks — a lead's PLAN, as opposed to its results. True when
        this arm owns the name, so the caller can warn on the ones nothing owns.

        `lead_preds` and `impact_preds` were documented and unprojected until #933 (tracked as
        #820): the parser recognized them, consumed them and dropped every row, so rules #18,
        #29, #30 and #31 had nothing to read and the plan they record reached no consumer.
        Projecting them is what makes those rules possible at all — and it is also what gives
        `:L` an allowlist, which is what lets the caller warn on a misspelled sub-block instead
        of staying silent for want of one.

        Both EXTEND, for the reason every sibling does: append-only forbids rewriting a
        committed block, so a loop that adds a route or a predicate writes a SECOND block and
        assignment would delete the first one's rows with no warning.

        Both drop the empty-TABLE marker, the way `_project_surviving_block` and
        `_project_deferral_block` do. `_row_cells` pads a lone `none` to the block width, so
        without the filter it lands as a record whose id IS
        `none` — and rules #18 / #29 then emit four and two refusals respectively, none of
        which says the author wrote the marker (#29 groups its blank cells into ONE message;
        see `_check_impact_prediction_structure`).
        """
        if sub == "lead_preds":
            if self._off_schema_plan_header(block, _LEAD_PRED_COLS):
                return True
            if lead_preds := self._marked_rows(block, _lead_pred_row):
                self._warn_repeated_ids(block, lead_preds)
                _extend_by_id(lead.setdefault("predictions", []), lead_preds)
            return True
        if sub == "impact_preds":
            if self._off_schema_plan_header(block, _IMPACT_PRED_COLS):
                return True
            if impact_preds := self._marked_rows(block, _impact_pred_row):
                self._warn_repeated_ids(block, impact_preds)
                _extend_by_id(lead.setdefault("impact_predictions", []), impact_preds)
            return True
        # `substitutions` is the one `:L` sub-block still documented and unprojected.
        # Allowlisted rather than projected: `query_details.substitutions` has no reader — no
        # rule resolves against it and no prompt renders it — so projecting it would invent a
        # field to hold rows nothing asks for. Allowlisted rather than WARNED because the block
        # is legal (`docs/dense-investigation-format.md` §`:L`), and refusing a legal block is
        # the one outcome worse than dropping it.
        return sub == "substitutions"  # lint-row-drop: ok — no reader; see #820

    def _project_lead_subblock(
        self, tag: str, sub: str, block: Block, lead: dict[str, Any]
    ) -> None:
        # Extend, never assign — a lead whose results arrive as two
        # `:V l-NNN.observations.vertices` blocks would keep only the last one, and
        # append-only leaves no way to write them as one.
        if tag == "V" and sub == "observations.vertices":
            vertices = self._project_rows(block, _vertex_record)
            self._warn_repeated_ids(block, vertices)
            _extend_by_id(
                lead.setdefault("outcome", {}).setdefault(
                    "observations", {}
                ).setdefault("vertices", []),
                vertices,
            )
            return
        if tag == "E" and sub == "observations.edges":
            edges = self._project_rows(block, _edge_record)
            self._warn_repeated_ids(block, edges)
            _extend_by_id(
                lead.setdefault("outcome", {}).setdefault(
                    "observations", {}
                ).setdefault("edges", []),
                edges,
            )
            return
        if tag == "H" and sub == "new_hypotheses":
            if self._stale_hyp_header(block):
                return
            hyps = self._project_rows(block, _hypothesis_record)
            self._warn_repeated_ids(block, hyps)
            _extend_by_id(lead.setdefault("new_hypotheses", []), hyps)
            # A hypothesis born inside a lead declares its predictions the way a prologue one
            # does — in a `:H h-NNN.preds` sub-block. Unregistered, that sub-block is rejected
            # as "unknown hypothesis" and a mid-run hypothesis can carry no prediction for a
            # resolution to cite.
            self._register_hypotheses(block, hyps, prologue=False)
            return
        if tag == "L" and self._project_lead_plan_subblock(sub, block, lead):
            return
        if tag == "H":
            # `new_hypotheses` is the ONLY `:H` sub-block a lead carries, so the singular typo
            # is reachable. Dropping it silently vanishes the fork with zero warnings, and
            # `_check_prediction_refs` then blames the (correct) resolution row for moving an
            # undeclared hypothesis. Its own arm, ahead of the shared one below, because it is
            # the only tag whose dropped rows can name a HYPOTHESIS.
            self._warn(
                block, -1, "",
                f"unknown lead sub-block `:H l-NNN.{sub}` — the only `:H` block "
                f"a lead carries is "
                f"{', '.join(f'`:H l-NNN.{s}`' for s in _LEAD_SUBBLOCKS['H'])}; its rows "
                f"were dropped",
                # Same reason as the stale-header rejection: the rows are readable and their
                # first cell is the id, so `deferred_hypothesis_ids` can defer for exactly
                # these instead of raising one undeclared-`h-*` error at every reference site.
                # Filtered to `h-*` cells, because "these cells are hypothesis ids" holds only
                # for the singular `new_hypothesis` typo this branch was written for. Any
                # OTHER sub-name contributes its own row ids — `:H l-001.preds` contributes
                # `p9` — and `deferred_hypothesis_ids` would then find no id-shaped name,
                # return `None`, and stand the undeclared-hypothesis rule down for the WHOLE
                # DOCUMENT. The typo case is unaffected: its ids ARE `h-*`.
                # lint-selection: ok — the drop is the point, and the comment above says
                # where it goes: a non-`h-*` id here would make `deferred_hypothesis_ids`
                # find no id-shaped name and stand a rule down for the whole document.
                dropped_ids=tuple(
                    # lint-selection: ok — the drop is the point; see above
                    cell
                    for cell in (_row_first_cell(r) for r in block.rows)
                    if HYPOTHESIS_ID_RE.fullmatch(cell)
                ),
            )
            return
        # Every OTHER tag, now that `:L` has an allowlist. Before it, warning here needed one
        # and the comment above said so; `lead_preds` / `impact_preds` were the reason. What
        # this catches is the tag whose typo used to be free: `:V l-001.observations.vertex`
        # drops a lead's whole observed graph in silence, and the resolutions citing those
        # edges then fail `_check_strong_move_provenance` for having no supporting edge — an
        # error naming the resolution rather than the block that deleted its evidence.
        #
        # No `dropped_ids`: only the `:H` arm above can be sure its rows name hypotheses, and
        # a non-`h-*` id reaching `deferred_hypothesis_ids` stands the undeclared-hypothesis
        # rule down for the whole document.
        if tag == "T" and sub == "shelved":
            # `:T l-{id}.shelved` is the OTHER spelling the format docs taught for the block
            # #933 retired, and it reaches here rather than `_project_t_block`. Routed to the
            # retirement message: an author writing it needs the replacement, not a lecture on
            # where a `:T` row names its lead.
            self._warn_retired_shelved(block)
            return
        legal = ", ".join(f"`:{tag} l-NNN.{s}`" for s in _LEAD_SUBBLOCKS.get(tag, ()))
        self._warn(
            block, -1, "",
            f"unknown lead sub-block `:{tag} l-NNN.{sub}` — its rows were dropped. "
            + (
                f"The lead-scoped `:{tag}` blocks are {legal}."
                if legal
                else f"`:{tag}` carries no `l-NNN.`-prefixed block at all; a lead's `:{tag}` "
                     f"rows name their lead in the row itself — a `resolved_by` COLUMN on "
                     f"every `:R` block, the leading `[l-NNN …]` head on a "
                     f"`:T resolutions` row."
            ),
        )

    def _project_findings_block(self, block: Block) -> None:
        # A repeated id WITHIN this one block is never the cross-block amendment
        # `_lead_header_record`'s callers rely on (see `_warn_repeated_ids`): the second row
        # is discarded, loudly, and the first row's values are kept whole. Swept up front,
        # over the rows that actually LAND (id+name present) — `_warn_repeated_ids` cannot be
        # handed the raw row strings, since it reads `r.get("id")` (F-B). It hands back the
        # survivors it warned about, so the drop and the warning are ONE walk: a second `seen`
        # set here would be a copy of the partition that check just made, free to drift from it.
        landed: list[dict[str, str]] = []
        for idx, row, rec in self._for_each_row(block):
            if not rec.get("id") or not rec.get("name"):
                self._warn(block, idx, row, "findings row missing id/name")
                continue
            landed.append(rec)
        for rec in self._warn_repeated_ids(block, landed, self._REPEAT_REMEDY_ONE_BLOCK):
            identity, outcome, query_details = _lead_header_record(rec)
            lead = self.lead_bucket(identity["id"])
            lead.update(identity)
            if outcome:
                lead.setdefault("outcome", {}).update(outcome)
            if query_details:
                lead.setdefault("query_details", {}).update(query_details)

    def _project_resolution_block(self, block: Block) -> None:
        name = block.name
        bucket_key = _RESOLUTION_BUCKET_KEY[name]
        for idx, row, rec in self._for_each_row(block):
            lead_id = rec.get("resolved_by") or rec.get("lead")
            if not lead_id:
                self._warn(block, idx, row, "row has no lead attribution")
                continue
            lead = self.lead_bucket(lead_id)
            if name == "attr_updates":
                self._apply_attr_update(lead, rec, block, idx, row)
            else:
                lead.setdefault("outcome", {}).setdefault(bucket_key, []).append(
                    _canonicalize_resolution_row(rec)
                )

    def _apply_attr_update(
        self, lead: dict[str, Any], rec: dict[str, str], block: Block,
        idx: int, row: str,
    ) -> None:
        tgt = rec.get("target")
        key = rec.get("key")
        val = rec.get("value", "")
        if not tgt or not key:
            self._warn(block, idx, row, "attr_updates missing target/key")
            return
        au = lead.setdefault("outcome", {}).setdefault("attribute_updates", [])
        for entry in au:
            if entry.get("target") == tgt and isinstance(entry.get("updates"), dict):
                entry["updates"][key] = val
                return
        # Literally constructed so the type gate actually checks both keys — this is the only
        # writer, and `AttributeUpdate` is total on the strength of it.
        entry_new: AttributeUpdate = {"target": tgt, "updates": {key: val}}
        au.append(entry_new)

    def _project_resolutions_block(self, block: Block) -> None:
        for idx, row in enumerate(block.rows):
            try:
                lead_id, record = _resolution_record(row)
            except RowError as e:
                self._warn(block, idx, row, str(e))
                continue
            if not lead_id:
                self._warn(block, idx, row, "resolution has no lead attribution")
                continue
            self.lead_bucket(lead_id).setdefault("resolutions", []).append(record)

    def _project_surviving_block(self, block: Block) -> None:
        """`:T conclude.surviving [hyp_id|final_weight]` — the run's own list of what it
        thinks is still standing.

        Projected, where every other `conclude.*` sub-block is discarded, for one reason: it is
        the FOURTH site that names an `h-*`, so discarding it lets a conclude naming an
        undeclared hypothesis pass parser and validator in silence.

        Deliberately NOT wired into benign-gating. Survival there is computed from the
        resolution record precisely because this table is omittable and self-reported
        (enforcement ramp rule 5); projecting it makes the claim checkable, and must not make
        it authoritative.
        """
        conclude: dict[str, Any] = self.out.setdefault("conclude", {})
        rows: list[dict[str, str]] = conclude.setdefault("surviving_hypotheses", [])
        for idx, row, rec in self._for_each_row(block, _SURVIVING_COLS):
            # Unquoted for the reason the `:T shelved` cell is: rule #24 asks whether the table
            # NAMES a hypothesis, by equality, and a quoted row otherwise earns the refusal
            # "the `:T conclude.surviving` table, which names \"h-001\", omits it".
            hid = _unquote(rec.get("hyp_id") or "")
            # `none` / `n/a` is how an EMPTY array is written here, not a hypothesis id
            # (`docs/dense-investigation-format.md`: "Empty arrays render as a single `none`
            # row"). Projecting the marker makes the undeclared-`h-*` rule refuse a run whose
            # hypotheses were all refuted.
            if is_conclude_empty_marker(hid):
                continue  # lint-row-drop: ok — the empty-TABLE marker, not a row
            # An empty `hyp_id` cell is a different case, and a DROP: the row would vanish
            # from `conclude.surviving_hypotheses` with nothing raised, and the close would
            # reason over a shortened survivor set no reader could tell from an honest one.
            if not hid:
                self._warn(
                    block, idx, row,
                    "surviving row has no hypothesis id — the row records WHICH hypothesis "
                    "is still standing, so an empty `hyp_id` cell records nothing. Name the "
                    "`h-*`, or write the whole table as one `none` row if none survived.",
                )
                continue
            # Keyed `hypothesis`, the name `:T resolutions` records already use for the
            # same reference — a reader that knows one shape reads the other.
            entry = {"hypothesis": hid}
            if rec.get("final_weight"):
                entry["final_weight"] = _unquote(rec["final_weight"])
            rows.append(entry)

    def _warn_unknown_conclude_subblock(self, block: Block) -> None:
        """A `:T conclude.<sub>` block name this projection does not carry.

        Loud, where an unrecognized flat `<key> <value>` row in `:T conclude` is deliberately
        silent, and the asymmetry is the point. A flat key can be lesson-instructed content the
        projection has yet to carry, so denying it would dead-letter a run for obeying a lesson
        (see `_project_conclude_scalars`). A sub-block name is GRAMMAR — no lesson names one,
        and the whole grammar is four projected spellings plus the one retired below. Dropping
        a misspelled one in silence has a sharp cost now that the closure rules are armed:
        `:T conclude.deferred_authorizations`
        (the FIELD name, which the spec also uses) drops the whole deferral table, and rule #26
        then refuses the document for an unresolved contract the author DID account for — an
        error pointing away from its cause, which is the failure `deferred_hypothesis_ids`
        exists to prevent one namespace over.

        The write is refused and nothing lands, so the retry costs a re-send and not a run.
        """
        if block.name == _RETIRED_CEILING_TEST_BLOCK:
            # The one spelling let through in silence; see `_RETIRED_CEILING_TEST_BLOCK`.
            return
        legal = ", ".join(sorted({"conclude.surviving", *_DEFERRAL_BLOCKS}))
        self._warn(
            block, -1, "",
            f"unknown conclude sub-block `:T {block.name}` — the sub-tables `:T conclude` "
            f"carries are {legal}; its rows were dropped. Everything else `conclude` records "
            f"is a flat `<key> <value>` row in `:T conclude` itself, keyed by one of "
            f"{_CONCLUDE_KEYS_HINT}.",
        )

    def _project_deferral_block(
        self, block: Block, field: str, ref_col: str
    ) -> None:
        """`:T conclude.deferred_* [<ref>|rationale]` — the commitments this close is NOT
        closing, and why.

        Projected in the same change that arms rules #26, #31 and #34, and not before: each of
        those rules refuses a declared commitment that is neither resolved nor deferred, and
        this table is the ONLY spelling of "deferred". Arming the strict half over an
        unprojected escape hatch refuses documents whose author already wrote the answer.

        Both empty-cell cases are handled the way `:T conclude.surviving` handles them. A lone
        `none` row is the empty-ARRAY marker — the run deferred nothing — and projects as an
        absent table rather than as a deferral of a commitment named "none". An empty ref CELL
        is a drop: the row would vanish and the closure rule would then refuse a commitment the
        author was reaching for.

        A blank RATIONALE is not a drop and is not warned here. The row lands, and the closure
        rule refuses it by name — that check can say what a rationale is for, where a parse
        warning could only say the row was discarded.

        `conclude` and the table are opened LAZILY — on the first row that lands, never on
        entry. Opening them eagerly makes a table whose only row is the empty-ARRAY marker
        project as `conclude = {"deferred_predictions": []}`, and every reader that asks "did
        this run conclude" by presence or truthiness then answers yes for a document that
        recorded nothing: `corpus._load_one` admits the case as complete, `render_synthesis`
        puts `deferred_predictions: []` in front of the judge as the conclusion, and
        `validate._is_closing` needs a bespoke subtraction to say otherwise. `:T
        conclude.surviving` is the deliberate exception one method up — present-and-empty
        there is the CLAIM that nothing survived, and `_check_hypothesis_persistence` reads it
        as one. There is no such claim to make here: "deferred nothing" is what an absent
        table already says.
        """
        # A DECLARED header that names neither cell by the name this projection reads is the
        # one shape whose damage is silent. `_row_dict` keys on the author's header, so
        # `[contract_ref|reason]` lands every row with a blank `rationale` — and the closure
        # rule then refuses the commitment for "an empty rationale" the author DID write,
        # naming the cell rather than the header that discarded it. Refused as a block, the
        # way `_stale_hyp_header` refuses an off-schema `:H` declaration.
        if block.columns and not {ref_col, "rationale"}.issubset(block.columns):
            self._warn(
                block, -1, "",
                f"column header {block.columns!r} does not match `:T {block.name} "
                f"[{ref_col}|rationale]` — this projection reads those two names, so a cell "
                f"under any other one is dropped and the closure rule then refuses the "
                f"commitment for a rationale you wrote; whole block rejected",
            )
            return
        for idx, row, rec in self._for_each_row(block, [ref_col, "rationale"]):
            # `_unquote`d like the rationale beside it. The three closure rules match this
            # cell against `h-001.ac1` / `h-001.p2` / `l-002.ip1` verbatim, so a quoted cell
            # defers nothing while looking exactly like a row that does — and the refusal
            # then tells the author to add a row they already wrote.
            ref = _unquote(rec.get(ref_col, "")).strip() or None
            if is_conclude_empty_marker(ref):
                continue  # lint-row-drop: ok — the empty-TABLE marker, not a row
            if not ref:
                self._warn(
                    block, idx, row,
                    f"deferral row has no `{ref_col}` — the row records WHICH commitment the "
                    f"close is leaving open, so an empty cell defers nothing and the closure "
                    f"rule will still refuse the commitment. Name it, or write the whole "
                    f"table as one `none` row if nothing was deferred.",
                )
                continue
            entry = {ref_col: ref}
            rationale = _unquote(rec.get("rationale", ""))
            if rationale:
                entry["rationale"] = rationale
            conclude: dict[str, Any] = self.out.setdefault("conclude", {})
            rows: list[dict[str, str]] = conclude.setdefault(field, [])
            rows.append(entry)