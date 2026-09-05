"""The invlang validator's public face.

The rules themselves live in seven modules, layered one way and split out of this one
when it reached 4038 lines. Each holds one family, and each imports only from the
families above it in this list:

  * `_diag`   — the `Diagnostic`/`Locus` types, the severity vocabulary, and the
                whole-document surface check.
  * `_refs`   — does every id a row cites resolve to something the document declares.
  * `_predictions` — append-only history, weight moves and their provenance, and whether
                a hypothesis' predictions were settled.
  * `_structure` — the shape of a prediction row, and the closed vocabularies.
  * `_state`  — attribute updates, the effective vertex state they build, open slots,
                and whether a declared vertex is ever connected to anything.
  * `_gating` — what a disposition costs: benign grounding, false-positive gating, the
                screen, and the severity ceiling.
  * `_closure` — the three closure gates, which are one sentence over three namespaces.

`diagnose` below is the only place that knows the running ORDER, which is load-bearing
in two places it says so at. Everything else here is a re-export kept because a reader
already imports that name from `validate`.
"""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Callable, Container, Iterable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any, Literal, NamedTuple

from defender._vocab import normalized_disposition
from .. import _walkers, vocab
from .._cells import _row_cells, _row_dict, _split_cells, _split_cells_raw, _unquote
from .._types import Block, RowError
from ..parser import (
    _CONCLUDE_SUBTABLE_FIELDS,
    COMMITMENT_ID_RE,
    HYPOTHESIS_ID_RE,
    ParseWarning,
    deferred_hypothesis_ids,
    is_conclude_empty_marker,
    iter_fence_blocks,
    parse_dense_companion,
    scan_fences,
)
from ..schema import (
    AuthorizationContract,
    CompanionBody,
    DeferralRecord,
    EdgeRecord,
    FindingRecord,
    HypothesisRecord,
    ImpactPrediction,
    VertexRecord,
)
from ._diag import (
    CONFIRMED_WEIGHT,
    Diagnostic,
    Locus,
    REFUTED_WEIGHT,
    STRONG_AUTH_KINDS,
    STRONG_WEIGHTS,
    Severity,
    _DECLARE_IT_YOURSELF,
    _STRONG_AUTH_KINDS_STR,
    _YAML_FENCE_RE,
    _check_surface,
    _normalize_newlines,
    _parse_diagnostic,
    _plain,
)
from ._refs import (
    _HYPOTHESIS_DECLARING_BLOCKS,
    _LEADING_SENTENCE_STOP_RE,
    _LEAD_PRED_ID_RE,
    _SIBLING_FORK_TAG,
    _TestsToken,
    _check_authz_contract_ids,
    _check_fork_distinctness,
    _check_hypothesis_refs,
    _check_lead_refs,
    _check_prediction_refs,
    _check_refutation_scope,
    _check_tested_commitment_refs,
    _check_tested_id_namespaces,
    _cited_hypothesis_ids,
    _classify_tests_token,
    _declared_commitments,
    _declared_prediction_ids,
    _hypothesis_references,
    _known_ids,
    _lead_prefix,
    _leads,
    _normalized_claim,
    _parent_hypothesis_id,
    _predicted_observables,
    _tests_tokens,
    _undeclared_hypothesis,
    _unresolved,
)
from ._predictions import (
    _ATTR_PRED_ID_RE,
    _ATTR_PRED_TARGETS,
    _NEGATED_LITERAL_RE,
    _PRED_ID_RE,
    _by_id_first,
    _check_append_only,
    _check_attribute_prediction_structure,
    _check_prediction_completeness,
    _check_prediction_id_namespace,
    _check_strong_move_provenance,
    _confirmed_and_standing,
    _contradicted_predictions,
    _edge_core,
    _refutation_scopes,
    _resolution_move,
    _settled_predictions,
    _vertex_core,
    auth_kind_of,
)
from ._structure import (
    _IMPACT_PRED_CELLS,
    _IMPACT_PRED_ID_RE,
    _IMPACT_RESOLUTION_REQUIRED,
    _LEAD_PRED_CELLS,
    _ROUTE_SENTINELS,
    _cell,
    _check_conclude_vocab,
    _check_impact_prediction_structure,
    _check_impact_resolution_refs,
    _check_lead_prediction_structure,
    _check_vocab,
    _check_vocab_anchor_kinds,
    _check_vocab_edges,
    _check_vocab_hypotheses,
    _check_vocab_vertices,
    _check_vocab_weights,
    _declared_impact_predictions,
    _qualify,
)
from ._state import (
    ATTR_PREFIX,
    ATTR_UPDATES_LOCUS,
    CATCHALL_PREFIXES,
    CELL_EMPTY,
    CELL_HELD,
    CELL_OPEN,
    IDENT_REFINEMENT_KEY,
    OPEN_MARKER,
    SLOT_CLASS,
    SLOT_IDENT,
    VertexCell,
    _anchor_kind,
    _apply_attr_updates,
    _authz_contract_error,
    _candidate_refusal,
    _cell_state,
    _cell_text,
    _check_attr_update_keys,
    _check_attr_update_targets,
    _check_benign_authz,
    _check_benign_open_slots,
    _check_closed_vocab,
    _check_vertex_participation,
    _check_vocab_class_cells,
    _declarers_by_contract_id,
    _illegal_key_diagnostic,
    _is_legal_refinement_key,
    _seed_vertex_state,
    _swap_cell,
    _unquoted_key,
    class_slots,
    effective_vertex_state,
    has_open_slot,
    is_catchall_slot,
    is_ident_open,
    is_open_slot,
    is_unresolved,
    iter_vertex_cells,
    outstanding_authz_contracts,
)
from ._gating import (
    EntryPrice,
    SCREEN_MATCH,
    SCREEN_MODE,
    SEVERITY_CEILING,
    _BENIGN_PRICE,
    _DISPOSITION_GATES,
    _FALSE_POSITIVE_PRICE,
    _Price,
    CEILING_NOTHING_TO_TRY,
    CEILING_QUERY_EMPTY,
    CEILING_QUERY_FAILED,
    CEILING_STATES,
    CeilingReceipt,
    RuntimeEvidenceReceipt,
    _check_authz_basis,
    _check_authz_row_grounding,
    _check_benign_gating,
    _check_benign_grounding,
    _check_ceiling_test_scope,
    _check_disposition_gating,
    _check_false_positive_gating,
    _check_hypothesis_persistence,
    _check_runtime_evidence_windows,
    _check_screen_structure,
    _check_tacit_lookup_outcomes,
    _lead_returned_a_result,
    _row_states_something,
    _weight_text,
    ceiling_test_block,
    conclude_ceiling_test_rows,
    conclude_runtime_evidence_rows,
    disposition_entry_price,
    entry_price,
    exhausted_contract_ids,
    runtime_evidence_block,
)
from ._closure import (
    _Commitment,
    _NON_CLOSING_FIELDS,
    _SEVERITY_OWING,
    _authz_closure_repair,
    _check_authz_contract_closure,
    _check_impact_closure,
    _check_loop_close,
    _check_prediction_closure,
    _closure_refusal,
    _declarer_kinds,
    _deferral_index,
    _discharged_by_row,
    _is_closing,
    _unclosed_commitments,
)


def _parse_once(proposed_text: str) -> tuple[str, CompanionBody, list[ParseWarning]]:
    """The newline-normalized text and its ONE parse, for a caller that wants both halves.

    Every check below reads the same companion off the same bytes, so the two halves asked
    back to back were tokenizing and projecting the document twice — on the hottest validation
    path in the tree (every write gate, every close gate, every warn-window derivation, and
    `record`'s own retry-or-stop decision). The halves stay independently callable and each
    parses for itself; `partitioned_diagnostics` is what asks for both over one parse."""
    normalized = _normalize_newlines(proposed_text)
    companion, warnings = parse_dense_companion(normalized)
    return normalized, companion, warnings


def structural_diagnostics(
    proposed_text: str, current_text: str | None = None
) -> list[Diagnostic]:
    """The half of `diagnose` a #996 clerk round can clear from the grammar and the document
    alone: surface, append-only, parse, and every reference/structure/vocab check ahead of the
    disposition-priced tail. OWNS `diagnose`'s no-companion early return — with no parseable
    companion the judgment half is asked about a document it never sees, so it answers empty
    and this half carries whatever `diagnose` found up to that point.

    Kept as a literal split of `diagnose`'s own body (not a re-derivation) so the two stay a
    byte-identical partition of it by construction; `diagnose` below is their concatenation."""
    return _structural_over(*_parse_once(proposed_text), current_text=current_text)


def _structural_over(
    proposed_text: str, companion: CompanionBody, warnings: list[ParseWarning],
    *, current_text: str | None,
) -> list[Diagnostic]:
    """`structural_diagnostics`'s body over a parse already in hand. `proposed_text` is the
    NORMALIZED text `_parse_once` returned — the same value the parse was taken from."""
    if current_text is not None:
        current_text = _normalize_newlines(current_text)

    found: list[Diagnostic] = []
    found.extend(_plain(_check_surface(proposed_text, current_text)))

    current_companion: CompanionBody | None = None
    if current_text is not None:
        # THE SAME TEXT IS THE SAME PARSE. Two callers read a committed document as its OWN
        # baseline — `committed_investigation_reason` (a close proposes nothing) and
        # `seed_investigation` (an inherited prefix introduces nothing its source had not
        # already committed) — and for them the second `parse_dense_companion` is a full
        # re-parse of bytes already in hand, feeding an append-only comparison of the document
        # with itself. Both texts are newline-normalized above, so the equality is over the
        # same value the parse would see.
        current_companion = (
            companion if current_text == proposed_text
            else parse_dense_companion(current_text)[0]
        )

    found.extend(_plain(
        _check_append_only(proposed_text, current_text, companion, current_companion)
    ))

    found.extend(_parse_diagnostic(w) for w in warnings)

    if not companion:
        return found

    found.extend(_plain(_check_lead_refs(companion)))
    found.extend(_plain(_check_attr_update_targets(companion)))
    found.extend(_plain(_check_hypothesis_refs(
        companion, deferred=deferred_hypothesis_ids(warnings),
    )))
    found.extend(_plain(_check_prediction_refs(companion)))
    found.extend(_plain(_check_fork_distinctness(companion)))
    found.extend(_plain(_check_refutation_scope(companion)))
    found.extend(_plain(_check_authz_contract_ids(companion)))
    found.extend(_plain(_check_tested_commitment_refs(companion)))
    found.extend(_plain(_check_tested_id_namespaces(companion)))
    found.extend(_plain(_check_strong_move_provenance(companion)))
    found.extend(_plain(_check_prediction_completeness(companion)))
    found.extend(_plain(_check_attribute_prediction_structure(companion)))
    found.extend(_plain(_check_prediction_id_namespace(companion)))
    found.extend(_plain(_check_lead_prediction_structure(companion)))
    found.extend(_plain(_check_impact_prediction_structure(companion)))
    found.extend(_plain(_check_impact_resolution_refs(companion)))
    found.extend(_plain(
        _check_vertex_participation(proposed_text, companion, current_companion)
    ))
    found.extend(_check_closed_vocab(companion, proposed_text))
    # #983's `:R authz` grounding check is JUDGMENT, not structural, on #996's own split (D7):
    # it needs a fact only MAIN can state (whether the row's own authorization holds), so a
    # clerk retrying it from the grammar and the document alone would loop on a refusal it can
    # never clear by itself — the exact shape D7's judgment/structural partition exists to stop.
    # `main`'s own single `diagnose()` computes it here, early, purely for a DEDUP ordering
    # reason (`_check_benign_gating` re-runs the same check and the two must not print the same
    # line twice) that has nothing to do with clerk-retry semantics; #996's split keeps that
    # dedup but moves both the computation and the report into `judgment_diagnostics` below,
    # where the retry-vs-stop distinction actually lives. `_check_authz_basis` and the two
    # write-gate-only checks after it stay here — they price OPEN AUTHZ/CONSULTATION SLOTS,
    # not a row's grounding, and are clearable the same way any other structural fact is.
    found.extend(_plain(_check_authz_basis(companion)))
    found.extend(_plain(_check_tacit_lookup_outcomes(companion)))
    found.extend(_plain(_check_runtime_evidence_windows(companion)))
    found.extend(_plain(_check_screen_structure(companion)))
    return found


def judgment_diagnostics(
    proposed_text: str, current_text: str | None = None  # noqa: ARG001 — same inputs as `diagnose`/`structural_diagnostics`, by contract (#996)
) -> list[Diagnostic]:
    """`diagnose`'s tail: the checks whose repair needs a fact only MAIN can state (the
    disposition's structural price, the ceiling test, hypothesis persistence, the three closure
    gates). Answers EMPTY for a document with no parseable companion — the structural half owns
    that early return, so the tail is never asked about a document it never sees.

    `current_text` is accepted (never read) only to keep the same call shape `diagnose` and
    `structural_diagnostics` take — none of these seven checks reads a baseline."""
    _normalized, companion, _warnings = _parse_once(proposed_text)
    return _judgment_over(companion)


def _judgment_over(companion: CompanionBody) -> list[Diagnostic]:
    """`judgment_diagnostics`'s body over a parse already in hand."""
    if not companion:
        return []
    found: list[Diagnostic] = []
    # #983's `:R authz` row-grounding check lives HERE, not in `structural_diagnostics` — #996's
    # split moves it off the clean-suffix ordering `main`'s own single `diagnose()` uses (see
    # `structural_diagnostics`'s own comment for why): it needs a fact only MAIN can state, so a
    # clerk retrying it from the grammar and the document alone would loop on a refusal it can
    # never clear by itself. Checked for every document rather than only for a benign one — a
    # price owed at the write gate alone is not owed at the close, and the close is the artifact
    # the learning loop and the ticket lane read.
    grounding = _check_authz_row_grounding(companion)
    found.extend(_plain(grounding))
    # Bound, not recomputed: `_check_authz_contract_closure` defers to this gate's OUTPUT on
    # any contract it is already refusing, and running it twice per write is the single most
    # expensive thing in the pass.
    gated = _check_disposition_gating(companion)
    # Collected at both boundaries, REPORTED once. `_check_benign_gating`, reached through
    # `gated` above, re-runs the grounding check too (deliberately — see the comment above) and
    # produces byte-identical diagnostic strings, so a benign document handed the model the same
    # wall of text twice on every refused write. The double COLLECTION is the point and stays;
    # the double PRINT is not.
    already = set(grounding)
    found.extend(_plain([e for e in gated if e not in already]))
    found.extend(_plain(_check_ceiling_test_scope(companion)))
    found.extend(_plain(_check_hypothesis_persistence(companion)))
    # The three closure gates, together and last: they are one sentence over three namespaces
    # (`_unclosed_commitments`), and each is only safe to run because its `deferred_*` table is
    # now projected.
    found.extend(_plain(_check_authz_contract_closure(companion, gated=set(gated))))
    found.extend(_plain(_check_impact_closure(companion)))
    found.extend(_plain(_check_prediction_closure(companion)))
    found.extend(_plain(_check_loop_close(companion)))
    return found


def partitioned_diagnostics(
    proposed_text: str, current_text: str | None = None
) -> tuple[list[Diagnostic], list[Diagnostic]]:
    """`(structural, judgment)` — both halves, over ONE parse of the document.

    The two halves are independently callable and each parses for itself, which is right for a
    caller that wants one of them. Every caller that wants BOTH — `diagnose` below, and
    `record`'s own retry-or-stop decision — was otherwise tokenizing and projecting the whole
    companion twice per call, on the hottest validation path in the tree: every write gate,
    every close gate, every warn-window derivation. One parse, two answers, same results."""
    normalized, companion, warnings = _parse_once(proposed_text)
    return (
        _structural_over(normalized, companion, warnings, current_text=current_text),
        _judgment_over(companion),
    )


def diagnose(
    proposed_text: str, current_text: str | None = None
) -> list[Diagnostic]:
    """The validator proper. Failures arrive as `Diagnostic`s so a caller that wants to point
    at the offending row can. `validate_companion` is the string surface over this and is what
    nearly everything calls.

    Exactly `structural_diagnostics(...) + judgment_diagnostics(...)`, and kept as that
    concatenation: `record` is the one caller that asks the two halves apart, and a `diagnose`
    that answered anything else would let the halves drift from the whole.

    THE SET IS WHAT #996'S SPLIT PRESERVED, NOT THE ORDER. One line moved: the `:R authz`
    row-grounding report is emitted after the structural checks rather than before
    `_check_authz_basis`, because grounding needs a fact only MAIN can state and therefore
    belongs to the judgment half — see `judgment_diagnostics`. A caller that renders these in
    order (the joined refusal string, a flagged-write refusal) sees the same lines in a
    different order on a document that trips both."""
    structural, judgment = partitioned_diagnostics(proposed_text, current_text)
    return structural + judgment


def warn_diagnostics(text: str) -> tuple[Diagnostic, ...]:
    """The REPAIR WINDOW, derived from a document's current bytes and stored nowhere.

    Not state anything records: it is `diagnose`'s warn-severity findings over whatever is on
    disk right now, so it cannot go stale, cannot disagree with the file, and survives a
    freshly constructed deps object. Each finding's `locus.row_text` is how `fix_row` addresses
    the row — the row as PARSED (the tokenizer strips it), which is also the text the warning
    prints, so the model's copy-paste round trip closes.

    No baseline: append-only is judged against history, but a warning is a property of the
    document as it stands."""
    return tuple(d for d in diagnose(text) if d.severity == "warning")


def validate_companion(
    proposed_text: str, current_text: str | None = None
) -> list[str]:
    """The string surface over `diagnose`, which is what the validator's callers are written
    against. `_artifact_schema` is the one caller that wants the structure and calls `diagnose`
    directly.

    ERROR severity only. Its production caller reads this list as "reasons to refuse the
    document" — persist dead-letters a run on any element — and a warn-family row is explicitly
    not that: the run reaches the learning loop with it."""
    return [
        d.message for d in diagnose(proposed_text, current_text) if d.severity != "warning"
    ]


#: Everything imported above is a RE-EXPORT: the name's real home is the module it
#: comes from. Kept because a reader already imports it from here.
__all__ = [
    "ATTR_PREFIX",
    "ATTR_UPDATES_LOCUS",
    "Any",
    "AuthorizationContract",
    "Block",
    "CATCHALL_PREFIXES",
    "CELL_EMPTY",
    "CELL_HELD",
    "CELL_OPEN",
    "COMMITMENT_ID_RE",
    "CONFIRMED_WEIGHT",
    "Callable",
    "CompanionBody",
    "Container",
    "Counter",
    "DeferralRecord",
    "Diagnostic",
    "EdgeRecord",
    "EntryPrice",
    "FindingRecord",
    "HYPOTHESIS_ID_RE",
    "HypothesisRecord",
    "IDENT_REFINEMENT_KEY",
    "ImpactPrediction",
    "Iterable",
    "Iterator",
    "Literal",
    "Locus",
    "Mapping",
    "NamedTuple",
    "OPEN_MARKER",
    "ParseWarning",
    "REFUTED_WEIGHT",
    "RuntimeEvidenceReceipt",
    "RowError",
    "SCREEN_MATCH",
    "SCREEN_MODE",
    "SEVERITY_CEILING",
    "SLOT_CLASS",
    "SLOT_IDENT",
    "STRONG_AUTH_KINDS",
    "STRONG_WEIGHTS",
    "Severity",
    "VertexCell",
    "VertexRecord",
    "_ATTR_PRED_ID_RE",
    "_ATTR_PRED_TARGETS",
    "_BENIGN_PRICE",
    "_CONCLUDE_SUBTABLE_FIELDS",
    "_Commitment",
    "_DECLARE_IT_YOURSELF",
    "_DISPOSITION_GATES",
    "_FALSE_POSITIVE_PRICE",
    "_HYPOTHESIS_DECLARING_BLOCKS",
    "_IMPACT_PRED_CELLS",
    "_IMPACT_PRED_ID_RE",
    "_IMPACT_RESOLUTION_REQUIRED",
    "_LEADING_SENTENCE_STOP_RE",
    "_LEAD_PRED_CELLS",
    "_LEAD_PRED_ID_RE",
    "_NEGATED_LITERAL_RE",
    "_NON_CLOSING_FIELDS",
    "_PRED_ID_RE",
    "_Price",
    "_ROUTE_SENTINELS",
    "_SEVERITY_OWING",
    "_SIBLING_FORK_TAG",
    "_STRONG_AUTH_KINDS_STR",
    "_TestsToken",
    "_YAML_FENCE_RE",
    "_anchor_kind",
    "_apply_attr_updates",
    "_authz_closure_repair",
    "_authz_contract_error",
    "_by_id_first",
    "_candidate_refusal",
    "_cell",
    "_cell_state",
    "_cell_text",
    "_check_append_only",
    "_check_attr_update_keys",
    "_check_attr_update_targets",
    "_check_attribute_prediction_structure",
    "_check_authz_basis",
    "_check_authz_contract_closure",
    "_check_authz_contract_ids",
    "_check_authz_row_grounding",
    "_check_benign_authz",
    "_check_benign_gating",
    "_check_benign_grounding",
    "_check_benign_open_slots",
    "_check_ceiling_test_scope",
    "_check_closed_vocab",
    "_check_conclude_vocab",
    "_check_disposition_gating",
    "_check_false_positive_gating",
    "_check_fork_distinctness",
    "_check_hypothesis_persistence",
    "_check_hypothesis_refs",
    "_check_impact_closure",
    "_check_impact_prediction_structure",
    "_check_impact_resolution_refs",
    "_check_lead_prediction_structure",
    "_check_lead_refs",
    "_check_loop_close",
    "_check_prediction_closure",
    "_check_prediction_completeness",
    "_check_prediction_id_namespace",
    "_check_prediction_refs",
    "_check_refutation_scope",
    "_check_runtime_evidence_windows",
    "_check_tacit_lookup_outcomes",
    "_check_screen_structure",
    "_check_strong_move_provenance",
    "_check_surface",
    "_check_tested_commitment_refs",
    "_check_tested_id_namespaces",
    "_check_vertex_participation",
    "_check_vocab",
    "_check_vocab_anchor_kinds",
    "_check_vocab_class_cells",
    "_check_vocab_edges",
    "_check_vocab_hypotheses",
    "_check_vocab_vertices",
    "_check_vocab_weights",
    "_cited_hypothesis_ids",
    "_classify_tests_token",
    "_closure_refusal",
    "_confirmed_and_standing",
    "_contradicted_predictions",
    "_declared_commitments",
    "_declared_impact_predictions",
    "_declared_prediction_ids",
    "_declarer_kinds",
    "_declarers_by_contract_id",
    "_deferral_index",
    "_discharged_by_row",
    "_edge_core",
    "_hypothesis_references",
    "_illegal_key_diagnostic",
    "_is_closing",
    "_is_legal_refinement_key",
    "_known_ids",
    "_lead_prefix",
    "_lead_returned_a_result",
    "_leads",
    "_normalize_newlines",
    "_normalized_claim",
    "_parent_hypothesis_id",
    "_parse_diagnostic",
    "_plain",
    "_predicted_observables",
    "_qualify",
    "_refutation_scopes",
    "_resolution_move",
    "_row_cells",
    "_row_dict",
    "_row_states_something",
    "_seed_vertex_state",
    "_settled_predictions",
    "_split_cells",
    "_split_cells_raw",
    "_swap_cell",
    "_tests_tokens",
    "_unclosed_commitments",
    "_undeclared_hypothesis",
    "_unquote",
    "_unquoted_key",
    "_unresolved",
    "_vertex_core",
    "_walkers",
    "_weight_text",
    "auth_kind_of",
    "CEILING_NOTHING_TO_TRY",
    "CEILING_QUERY_EMPTY",
    "CEILING_QUERY_FAILED",
    "CEILING_STATES",
    "CeilingReceipt",
    "ceiling_test_block",
    "class_slots",
    "conclude_ceiling_test_rows",
    "conclude_runtime_evidence_rows",
    "dataclass",
    "diagnose",
    "disposition_entry_price",
    "entry_price",
    "judgment_diagnostics",
    "runtime_evidence_block",
    "structural_diagnostics",
    "effective_vertex_state",
    "exhausted_contract_ids",
    "field",
    "has_open_slot",
    "is_catchall_slot",
    "is_conclude_empty_marker",
    "is_ident_open",
    "is_open_slot",
    "is_unresolved",
    "iter_fence_blocks",
    "iter_vertex_cells",
    "normalized_disposition",
    "outstanding_authz_contracts",
    "parse_dense_companion",
    "partitioned_diagnostics",
    "re",
    "scan_fences",
    "validate_companion",
    "vocab",
    "warn_diagnostics",
]
