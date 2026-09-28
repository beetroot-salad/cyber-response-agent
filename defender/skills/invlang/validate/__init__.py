"""The invlang validator's public face.

The rules themselves live in seven modules, layered one way. Each holds one family, and each imports only from the
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

`diagnose` below is the only place that knows the running order, which matters where its
comments say so. Everything else here is a re-export kept because callers import those names
from `validate`.
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
    ceiling_note_block,
    ceiling_test_block,
    conclude_ceiling_test_rows,
    conclude_runtime_evidence_rows,
    disposition_entry_price,
    entry_price,
    exhausted_contract_ids,
    CapabilitiesNotRead,
    hold_capabilities,
    known_capabilities,
    release_capabilities,
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


def diagnose(
    proposed_text: str, current_text: str | None = None
) -> list[Diagnostic]:
    """The validator proper, returning `Diagnostic`s so a caller can point at the offending
    row. `validate_companion` is the string surface over this."""
    proposed_text = _normalize_newlines(proposed_text)
    if current_text is not None:
        current_text = _normalize_newlines(current_text)

    found: list[Diagnostic] = []
    found.extend(_plain(_check_surface(proposed_text, current_text)))

    companion, warnings = parse_dense_companion(proposed_text)
    current_companion: CompanionBody | None = None
    if current_text is not None:
        # The same text is the same parse. `committed_investigation_reason` and
        # `seed_investigation` validate a committed document against itself as baseline, and
        # would otherwise re-parse identical bytes. Both texts are newline-normalized above.
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
    # Checked for every document, not only benign ones. `_check_authz_row_grounding` is also
    # collected by `_check_benign_gating`, because a price owed only at the write gate is not
    # owed at the close, which is what the learning loop and ticket lane read.
    grounding = _check_authz_row_grounding(companion)
    found.extend(_plain(grounding))
    found.extend(_plain(_check_authz_basis(companion)))
    found.extend(_plain(_check_tacit_lookup_outcomes(companion)))
    found.extend(_plain(_check_runtime_evidence_windows(companion)))
    found.extend(_plain(_check_screen_structure(companion)))
    # Bound once: `_check_authz_contract_closure` defers to this output, and running the gate
    # twice is the most expensive thing in the pass.
    gated = _check_disposition_gating(companion)
    # `_check_benign_gating` re-runs the grounding check above and produces identical strings:
    # collect at both boundaries, report once.
    already = set(grounding)
    found.extend(_plain([e for e in gated if e not in already]))
    found.extend(_plain(_check_ceiling_test_scope(companion)))
    found.extend(_plain(_check_hypothesis_persistence(companion)))
    # The three closure gates, together and last: they are one rule over three namespaces
    # (`_unclosed_commitments`), each safe only once its `deferred_*` table is projected.
    found.extend(_plain(_check_authz_contract_closure(companion, gated=set(gated))))
    found.extend(_plain(_check_impact_closure(companion)))
    found.extend(_plain(_check_prediction_closure(companion)))
    found.extend(_plain(_check_loop_close(companion)))
    return found


def warn_diagnostics(text: str) -> tuple[Diagnostic, ...]:
    """The repair window: `diagnose`'s warn-severity findings over the document as it stands.

    Derived, never stored, so it cannot go stale or disagree with the file. `locus.row_text` is
    the row as parsed (and as the warning prints it), which is how `fix_row` addresses it. No
    baseline: a warning is a property of the current document, not of its history."""
    return tuple(d for d in diagnose(text) if d.severity == "warning")


def validate_companion(
    proposed_text: str, current_text: str | None = None
) -> list[str]:
    """Error-severity messages from `diagnose`, as strings.

    Warn-severity findings are excluded: the production caller dead-letters a run on any
    element, and a warned row still lands and reaches the learning loop."""
    return [
        d.message for d in diagnose(proposed_text, current_text) if d.severity != "warning"
    ]


#: Re-exports: each name's real home is the module it comes from. Kept because callers import
#: them from here.
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
    "ceiling_note_block",
    "ceiling_test_block",
    "class_slots",
    "conclude_ceiling_test_rows",
    "conclude_runtime_evidence_rows",
    "dataclass",
    "diagnose",
    "disposition_entry_price",
    "entry_price",
    "runtime_evidence_block",
    "effective_vertex_state",
    "exhausted_contract_ids",
    "CapabilitiesNotRead",
    "hold_capabilities",
    "known_capabilities",
    "release_capabilities",
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
    "re",
    "scan_fences",
    "validate_companion",
    "vocab",
    "warn_diagnostics",
]
