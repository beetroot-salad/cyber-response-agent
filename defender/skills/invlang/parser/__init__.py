"""The invlang parser's public face.

The parsing itself lives in three modules, layered one way and split out of this one
when it reached 2128 lines:

  * `_tokenize` — which bytes of a document are invlang content, and how they cut into
    blocks and rows. Knows nothing of records or of the projector.
  * `_rows` — one row of one block type, projected into one typed record. Pure
    functions; imports the tokenizer, never the projector.
  * `_project` — walks blocks and accumulates them into the finished companion body.

This module keeps the two entry points and re-exports the names its readers already
import from here, so the split is invisible at every call site.
"""

from __future__ import annotations

import contextlib
import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, TypeVar, cast

from .._cells import (
    _has_unbalanced_quote,
    _parse_attrs,
    _require,
    _row_cells,  # noqa: F401 — re-export: invlang tests import it from `parser`
    _row_dict,
    _split_cells,  # noqa: F401 — re-export: invlang tests import it from `parser`
    _split_csv,
    _split_csv_or_semi,
    _split_quoted,  # noqa: F401 — re-export: invlang tests import it from `parser`
    _split_subcells,  # noqa: F401 — re-export: invlang tests import it from `parser`
    _unquote,
    is_conclude_empty_marker,  # noqa: F401 — re-export: parser is this name's public home
)
from .._types import Block, RowError
from ..vocab import UNOBSERVED_EDGE_REF
from ..schema import (
    AttributeUpdate,
    AttrPredictionRecord,
    AuthorityRef,
    AuthorizationContract,
    CompanionBody,
    Conclude,
    EdgeRecord,
    HypothesisRecord,
    ImpactPrediction,
    LeadPrediction,
    ParentVertex,
    PredictionRecord,
    ProposedEdge,
    RefutationRecord,
    ResolutionRecord,
    ResolutionRow,
    VertexRecord,
)
from ._tokenize import (
    FenceScan,
    HEADER_RE,
    INVLANG_FENCE_RE,
    NO_OPEN_BLOCK,
    ParseWarning,
    _FENCE_OPEN_LINE,
    _HEADER_ATTEMPT_RE,
    _LEAD_PREFIX_RE,
    _STORY_HEADER_RE,
    _flush_orphans,
    _header_block,
    _orphan_warning,
    _tokenize_fence,
    iter_blocks,
    iter_fence_blocks,
    scan_fences,
)
from ._rows import (
    COMMITMENT_ID_RE,
    HYPOTHESIS_ID_RE,
    HYP_DECLARATION_BLOCK_RE,
    _CONCLUDE_KEYS_HINT,
    _CONCLUDE_LISTS,
    _CONCLUDE_SCALARS,
    _CONCLUDE_SUBTABLES,
    _CONCLUDE_SUBTABLE_FIELDS,
    _CROSS_BLOCK_GUARDED,
    _DEFERRAL_BLOCKS,
    _EDGE_COLS,
    _HYP_ATTR_PRED_COLS,
    _HYP_AUTHZ_COLS,
    _HYP_COMPARED_CELLS,
    _HYP_HEADER_COLS,
    _HYP_PRED_COLS,
    _HYP_PREFIX_RE,
    _HYP_REFUT_COLS,
    _IFF_LITERAL_RE,
    _IMPACT_PRED_COLS,
    _LEAD_PRED_COLS,
    _LEAD_SUBBLOCKS,
    _MISSING,
    _REF_ID_RE,
    _RESOLUTION_BUCKET_KEY,
    _RESOLUTION_KEY_CANONICAL,
    _RESOLUTION_LINE_RE,
    _RESOLUTION_LIST_KEYS,
    _RETIRED_CEILING_TEST_BLOCK,
    _SUPPORTING_EDGE_RE,
    _SURVIVING_COLS,
    _TERMINATION_ROWS,
    _VERTEX_COLS,
    _build_proposed_edge,
    _canonicalize_resolution_row,
    _close_loop,
    _conclude_value,
    _dedup,
    _edge_record,
    _extend_by_id,
    _extract_iff_literals,
    _hyp_sub_attr_pred_row,
    _hyp_sub_authz_row,
    _hyp_sub_pred_row,
    _hyp_sub_refut_row,
    _hypothesis_record,
    _impact_pred_row,
    _is_current_hyp_header,
    _lead_header_record,
    _lead_pred_row,
    _parse_auth,
    _resolution_record,
    _row_first_cell,
    _two_site_reason,
    _vertex_record,
    deferred_hypothesis_ids,
)
from ._project import (
    _Projector,
    _RowT,
)


def companion_from_blocks(
    blocks: list[Block],
) -> tuple[CompanionBody, list[ParseWarning]]:
    proj = _Projector()
    for block in blocks:
        proj.project_block(block)
    proj.flush_deferred_warnings()
    if proj.findings:
        proj.out["findings"] = list(proj.findings.values())
    return cast(CompanionBody, proj.out), proj.warnings


def parse_dense_companion(
    text: str,
) -> tuple[CompanionBody, list[ParseWarning]]:
    blocks: list[Block] = []
    warnings: list[ParseWarning] = []
    for body in scan_fences(text).bodies:
        fence_blocks, fence_warnings = _tokenize_fence(body)
        blocks.extend(fence_blocks)
        warnings.extend(fence_warnings)
    # Return the warnings, not `[]`. A fence whose FIRST header was rejected opens no block at
    # all, and dropping them here would let that document parse to a clean, empty companion.
    if not blocks:
        return cast(CompanionBody, {}), warnings
    companion, projected = companion_from_blocks(blocks)
    return companion, warnings + projected


#: Everything imported above is a RE-EXPORT: the name's real home is the module it
#: comes from. Kept because a reader already imports it from here.
__all__ = [
    "Any",
    "AttrPredictionRecord",
    "AttributeUpdate",
    "AuthorityRef",
    "AuthorizationContract",
    "Block",
    "COMMITMENT_ID_RE",
    "Conclude",
    "EdgeRecord",
    "FenceScan",
    "HEADER_RE",
    "HYPOTHESIS_ID_RE",
    "HYP_DECLARATION_BLOCK_RE",
    "HypothesisRecord",
    "INVLANG_FENCE_RE",
    "ImpactPrediction",
    "Iterator",
    "LeadPrediction",
    "NO_OPEN_BLOCK",
    "ParentVertex",
    "ParseWarning",
    "PredictionRecord",
    "ProposedEdge",
    "RefutationRecord",
    "ResolutionRecord",
    "ResolutionRow",
    "RowError",
    "TypeVar",
    "UNOBSERVED_EDGE_REF",
    "VertexRecord",
    "_CONCLUDE_KEYS_HINT",
    "_CONCLUDE_LISTS",
    "_CONCLUDE_SCALARS",
    "_CONCLUDE_SUBTABLES",
    "_CONCLUDE_SUBTABLE_FIELDS",
    "_CROSS_BLOCK_GUARDED",
    "_DEFERRAL_BLOCKS",
    "_EDGE_COLS",
    "_FENCE_OPEN_LINE",
    "_HEADER_ATTEMPT_RE",
    "_HYP_ATTR_PRED_COLS",
    "_HYP_AUTHZ_COLS",
    "_HYP_COMPARED_CELLS",
    "_HYP_HEADER_COLS",
    "_HYP_PRED_COLS",
    "_HYP_PREFIX_RE",
    "_HYP_REFUT_COLS",
    "_IFF_LITERAL_RE",
    "_IMPACT_PRED_COLS",
    "_LEAD_PRED_COLS",
    "_LEAD_PREFIX_RE",
    "_LEAD_SUBBLOCKS",
    "_MISSING",
    "_Projector",
    "_REF_ID_RE",
    "_RESOLUTION_BUCKET_KEY",
    "_RESOLUTION_KEY_CANONICAL",
    "_RESOLUTION_LINE_RE",
    "_RESOLUTION_LIST_KEYS",
    "_RETIRED_CEILING_TEST_BLOCK",
    "_RowT",
    "_STORY_HEADER_RE",
    "_SUPPORTING_EDGE_RE",
    "_SURVIVING_COLS",
    "_TERMINATION_ROWS",
    "_VERTEX_COLS",
    "_build_proposed_edge",
    "_canonicalize_resolution_row",
    "_close_loop",
    "_conclude_value",
    "_dedup",
    "_edge_record",
    "_extend_by_id",
    "_extract_iff_literals",
    "_flush_orphans",
    "_has_unbalanced_quote",
    "_header_block",
    "_hyp_sub_attr_pred_row",
    "_hyp_sub_authz_row",
    "_hyp_sub_pred_row",
    "_hyp_sub_refut_row",
    "_hypothesis_record",
    "_impact_pred_row",
    "_is_current_hyp_header",
    "_lead_header_record",
    "_lead_pred_row",
    "_orphan_warning",
    "_parse_attrs",
    "_parse_auth",
    "_require",
    "_resolution_record",
    "_row_cells",
    "_row_dict",
    "_row_first_cell",
    "_split_cells",
    "_split_csv",
    "_split_csv_or_semi",
    "_split_quoted",
    "_split_subcells",
    "_tokenize_fence",
    "_two_site_reason",
    "_unquote",
    "_vertex_record",
    "cast",
    "companion_from_blocks",
    "contextlib",
    "dataclass",
    "deferred_hypothesis_ids",
    "field",
    "is_conclude_empty_marker",
    "iter_blocks",
    "iter_fence_blocks",
    "lru_cache",
    "parse_dense_companion",
    "re",
    "scan_fences",
]
