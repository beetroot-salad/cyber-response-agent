"""The projector: walks blocks and accumulates them into the finished companion body."""


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

#: One projected row. Generic so `_warn_repeated_ids` returns the caller's row type rather
#: than `list[Any]`, keeping `_lead_header_record`'s `rec["id"]` narrowed.
_RowT = TypeVar("_RowT")


# Stdlib `@dataclass`, not `@model`: this is internal mutable scratch, never built from
# external data, and `hypotheses_by_id` holds records that are incomplete mid-projection.
@dataclass
class _Projector:

    out: dict[str, Any] = field(default_factory=dict)
    warnings: list[ParseWarning] = field(default_factory=list)
    hypotheses_by_id: dict[str, HypothesisRecord] = field(default_factory=dict)
    #: Ids the `:H hypothesize.hypotheses` table declares. The table outranks a lead's
    #: `new_hypotheses` regardless of document order, matching `_walkers.all_hypotheses`.
    prologue_hypothesis_ids: set[str] = field(default_factory=set)
    findings: dict[str, dict[str, Any]] = field(default_factory=dict)

    # No "current lead" state: falling back to the last-mentioned lead would file one lead's
    # evidence under another. Every row that lands on a lead names it.

    #: `:T conclude` blocks that recorded nothing, pending the whole-document verdict in
    #: `flush_deferred_warnings`. One entry per block so each warning names its own locus.
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
        """`_project_rows`, minus the empty-table marker.

        A lone `none` / `n/a` row says the table is empty; `_row_cells` pads it to the block
        width, so without this it lands as a record with `id == "none"`.
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
        """Warn on a row whose quoted value does not close on that line.

        `_tokenize_fence` makes a row per line, so a value spilled across two lines is truncated
        and the rest reparses as fresh rows (dropped, or landing on whatever key the next word
        names). Checked for every block because the hazard is the line-oriented surface itself.
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

        # Extend, never assign: the document is append-only, so a second block is the only way
        # to add rows, and assignment would delete the first block's.
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
        """Put one `:T conclude` row where it goes; True when it recorded a value.

        `seen` marks a recognized key (for the duplicate-row warning); the return value marks
        one that recorded something. They differ: `ceiling_test  none` is recognized but empty.
        An unrecognized key returns False unwarned.
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
            # `None` is the literal `null`, the format's other spelling of "nothing". Landing it
            # would make `conclude` truthy, and `validate._is_closing` would then read a mid-run
            # block as a close.
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
        #: Did any row of this block record a value? Neither `seen` nor `conclude` emptiness
        #: answers that: `conclude` may already hold an earlier block's content.
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
                # Catches a spilled continuation that landed on a real key. List keys repeat
                # legitimately.
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
                # The same overwrite across blocks: `seen` is per-block, `conclude` is
                # document-wide. Only a changed value warns; restating the same value loses
                # nothing and must stay writable under append-only.
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
            # An unrecognized key is ignored, not warned: lessons can instruct conclude rows
            # this projection does not carry, and a validation failure dead-letters the run
            # (`learning/core/persist.py`). Spilled quoted values are caught by
            # `_check_one_line_rows`; an unquoted spill goes undetected.
        if termination:
            # Merged, not assigned: a later block restating one termination field must not
            # erase the other.
            cast(dict[str, Any], conclude.setdefault("termination", {})).update(termination)
        if not landed:
            # Includes a block with no rows at all (a truncated write). Decided after the whole
            # document is projected, in `flush_deferred_warnings`.
            self.empty_conclude_blocks.append(block)

    def flush_deferred_warnings(self) -> None:
        """Emit the warnings that can only be decided once every block has been projected.

        A mid-loop verdict would see only a prefix, making it depend on the order of a close's
        `:T conclude` blocks.
        """
        for block in self.empty_conclude_blocks:
            self._warn_conclude_recorded_nothing(block)
        self.empty_conclude_blocks.clear()

    def _warn_conclude_recorded_nothing(self, block: Block) -> None:
        """Warn that a `:T conclude` block recorded nothing, unless another block did.

        Must be loud: the closure gates key "is this document closing" off a non-empty
        `conclude` (`validate._is_closing`), so an empty close would stand them all down
        silently. Asked of the whole document because a close may be split across blocks, one
        of which legally carries only keys this projection ignores. The sub-table fields do not
        count as a flat close.
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
        """Refuse the retired `:T shelved` by name, pointing at its replacement.

        A generic "unknown block" would not tell the author what to write instead.
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
        """True (and warned) when a `:H` declaration block's header is off-schema."""
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
            # Lets the undeclared-hypothesis rule defer for exactly these ids rather than for
            # the whole document.
            dropped_ids=tuple(_row_first_cell(r) for r in block.rows),
        )
        return True

    def _project_hypothesize_block(self, block: Block) -> None:
        if self._stale_hyp_header(block):
            return
        hyps = self._project_rows(block, _hypothesis_record)
        self._warn_repeated_ids(block, hyps)
        # Extend, never assign: a later loop adds hypotheses in a second block.
        _extend_by_id(
            self.out.setdefault("hypothesize", {}).setdefault("hypotheses", []), hyps
        )
        self._register_hypotheses(block, hyps, prologue=True)

    def _register_hypotheses(
        self, block: Block, hyps: list[HypothesisRecord], *, prologue: bool
    ) -> None:
        """Index the records a `:H h-NNN.<sub>` sub-block attaches to.

        Re-declaring an id at the same site is a re-emission: the first stands, silently.
        Re-declaring it at the other site is warned. The table outranks a lead's declaration,
        matching `_walkers.all_hypotheses`; otherwise a sub-block could attach to a record no
        consumer reads.
        """
        for h in hyps:
            hid = h.get("id")
            if not isinstance(hid, str):
                # Type narrowing only: a missing id already raised `RowError` upstream.
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
        """Project a `:H h-NNN.<sub>` block onto the field it declares, extending it.

        Branches rather than a `{sub: field}` table because a TypedDict write needs a literal
        key to keep `HypothesisRecord` typed.
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

    #: Remedy for sites where a second block adds rows (`_extend_by_id` keeps new ids).
    _REPEAT_REMEDY_SECOND_BLOCK = (
        "Give each row its own id, or send the added rows as a second block."
    )
    #: Remedy for `:L findings`, where a second block naming the same id merges into (and can
    #: overwrite) the existing lead, so "send a second block" would be wrong advice.
    _REPEAT_REMEDY_ONE_BLOCK = (
        "Give each row its own id and re-send this block whole: a second `:L findings` block "
        "naming the same id AMENDS that lead rather than adding a row, so it would blend the "
        "two readings instead of separating them."
    )

    def _warn_repeated_ids(
        self, block: Block, rows: list[_RowT], remedy: str = _REPEAT_REMEDY_SECOND_BLOCK,
    ) -> list[_RowT]:
        """Warn on an id repeated within one block; return the first row per id.

        Within one block a repeat is never a re-emission, and `_extend_by_id` silently drops the
        later row, whose content (a contract, a prediction, a vertex's open slot) then vanishes
        unrecoverably under append-only. Repeats across blocks stay silent: that is the legal
        re-emission shape.

        Rows with no readable id are returned too. Callers that fold through `_extend_by_id`
        can ignore the return; `_project_findings_block` uses it to enforce first-row-wins.
        """
        seen: set[str] = set()
        firsts: list[_RowT] = []
        for r in rows:
            rid = r.get("id") if isinstance(r, dict) else None
            if not isinstance(rid, str) or not rid:
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

        `_row_dict` keys on the author's header, so a misnamed column (typically the canonical
        field name) lands its cell empty and the row is then refused for a value the author
        wrote. A subset header is left to the per-row rules, which name each missing cell.
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
        """Project a lead's plan blocks (`:L l-NNN.<sub>`). True when this arm owns `sub`.

        The allowlist lets the caller warn on a misspelled sub-block. Both blocks extend (a
        later loop adds rows in a second block) and drop the empty-table marker.
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
        # `substitutions` is legal but has no reader, so it is allowlisted without projecting.
        return sub == "substitutions"  # lint-row-drop: ok — legal block with no reader

    def _project_lead_subblock(
        self, tag: str, sub: str, block: Block, lead: dict[str, Any]
    ) -> None:
        # Extend, never assign (append-only: more results arrive as a second block).
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
            # Registered so its `:H h-NNN.<sub>` blocks can attach, as for prologue ones.
            self._register_hypotheses(block, hyps, prologue=False)
            return
        if tag == "L" and self._project_lead_plan_subblock(sub, block, lead):
            return
        if tag == "H":
            # Catches the reachable `new_hypothesis` typo, which would otherwise drop a fork
            # silently and blame the resolution row that later cites it.
            self._warn(
                block, -1, "",
                f"unknown lead sub-block `:H l-NNN.{sub}` — the only `:H` block "
                f"a lead carries is "
                f"{', '.join(f'`:H l-NNN.{s}`' for s in _LEAD_SUBBLOCKS['H'])}; its rows "
                f"were dropped",
                # Lets `deferred_hypothesis_ids` defer for exactly these ids. Only `h-*`
                # cells: another sub-name's row ids (e.g. `p9`) would make it find no id-shaped
                # name and stand the undeclared-hypothesis rule down for the whole document.
                # lint-selection: ok — non-`h-*` ids are not hypotheses; the warning covers them
                dropped_ids=tuple(
                    # lint-selection: ok — non-`h-*` ids are not hypotheses; see above
                    cell
                    for cell in (_row_first_cell(r) for r in block.rows)
                    if HYPOTHESIS_ID_RE.fullmatch(cell)
                ),
            )
            return
        # Every other tag: a typo like `:V l-001.observations.vertex` would otherwise drop a
        # lead's observed graph silently. No `dropped_ids`, since only `:H` rows name
        # hypotheses.
        if tag == "T" and sub == "shelved":
            # The lead-scoped spelling of the retired block; give it the retirement message.
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
        # A repeated id within one block is not a cross-block amendment: keep the first row
        # whole and warn on the rest. The partition comes from `_warn_repeated_ids` so the
        # drop and the warning cannot disagree.
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
        # Constructed literally so the type checker verifies both keys of `AttributeUpdate`.
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
        """`:T conclude.surviving [hyp_id|final_weight]`: the run's own list of what is still
        standing.

        Projected so the `h-*` ids it names are checked against declarations. Not used for
        benign-gating, which computes survival from the resolution record because this table is
        omittable and self-reported.
        """
        conclude: dict[str, Any] = self.out.setdefault("conclude", {})
        rows: list[dict[str, str]] = conclude.setdefault("surviving_hypotheses", [])
        for idx, row, rec in self._for_each_row(block, _SURVIVING_COLS):
            # Unquoted: rule #24 compares ids by equality.
            hid = _unquote(rec.get("hyp_id") or "")
            # `none` / `n/a` is the empty-table marker, not an id.
            if is_conclude_empty_marker(hid):
                continue  # lint-row-drop: ok — the empty-TABLE marker, not a row
            # An empty `hyp_id` is a real drop and must warn, or the survivor set shrinks silently.
            if not hid:
                self._warn(
                    block, idx, row,
                    "surviving row has no hypothesis id — the row records WHICH hypothesis "
                    "is still standing, so an empty `hyp_id` cell records nothing. Name the "
                    "`h-*`, or write the whole table as one `none` row if none survived.",
                )
                continue
            # Keyed `hypothesis`, matching `:T resolutions` records.
            entry = {"hypothesis": hid}
            if rec.get("final_weight"):
                entry["final_weight"] = _unquote(rec["final_weight"])
            rows.append(entry)

    def _warn_unknown_conclude_subblock(self, block: Block) -> None:
        """Warn on a `:T conclude.<sub>` block name this projection does not carry.

        Loud, unlike an unrecognized flat key: a sub-block name is grammar, never
        lesson-instructed content. A misspelling (e.g. `deferred_authorizations`) would drop a
        whole deferral table and a closure rule would then refuse a commitment the author did
        account for.
        """
        if block.name == _RETIRED_CEILING_TEST_BLOCK:
            # The retired spelling is accepted silently.
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
        """`:T conclude.deferred_* [<ref>|rationale]`: the commitments this close leaves open,
        and why.

        This table is the only way to defer a commitment the closure rules would otherwise
        refuse. A lone `none` row means nothing was deferred; an empty ref cell is a drop and is
        warned. A blank rationale lands, so the closure rule can refuse it by name.

        `conclude` and the table are opened lazily, on the first row that lands: an empty
        table must stay absent, because readers treat any `conclude` content as "this run
        concluded". (`:T conclude.surviving` differs: present-and-empty there claims nothing
        survived.)
        """
        # A misnamed header column would land every cell under it empty, and the closure rule
        # would then refuse a rationale the author wrote; reject the whole block instead.
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
            # Unquoted: the closure rules match this cell verbatim against ids like `h-001.ac1`.
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