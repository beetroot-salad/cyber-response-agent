"""The query-id and request-key rules every queries-table reader and writer must agree on.

The request key (`_request_key`) and the params normaliser it keys by (`_json_safe_params`,
bounded by `PARAMS_NESTING_LIMIT`), the reserved `∅.` sentinel ids and their prefix test, and
the screen a model-supplied `query_id` passes (`resolve_query_id`). Request keys are persisted
in the queries table and replayed by learning's branch ledger, so their bytes must not change.

Flat tier: the gather writer and guards (`scripts/gather_tools/record_query.py`), the query
tool and learning all import these from here, below the runtime.
"""
from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

from defender._io import JsonTooDeep, json_nesting_depth, json_safe


def _request_key(system: Any, verb: Any, params: Any) -> str:
    # Cleaned here, not by each caller, so live params and a stored row's key alike.
    call = [system, verb, params if isinstance(params, dict) else {}]
    return json.dumps(json_safe(call, non_finite="text"), sort_keys=True)


#: The deepest a call's params may nest, the params map itself counting as one level. A
#: product bound, not derived from any reader: no real query nests near it, and it sits far
#: enough under `JSON_NESTING_LIMIT` that every record embedding a call's arguments stays
#: readable — the query row and the branch ledger one level down, the gather wire log several.
PARAMS_NESTING_LIMIT = 32


class ParamsTooDeep(Exception):
    """`field` nests past `PARAMS_NESTING_LIMIT`; nothing was stored. Every refusal of a
    too-deep call says it in this sentence, naming the field.

    An `Exception`, not a `ValueError`: `ServedCall` cleans its params as it is built, and
    pydantic would wrap a `ValueError` raised there into its own `ValidationError` (`_model`)."""

    def __init__(self, field: str = "params") -> None:
        # The field alone is the argument, so a copy or a pickle rebuilds the same error.
        super().__init__(field)
        self.field = field

    def __str__(self) -> str:
        return (f"{self.field} nest deeper than {PARAMS_NESTING_LIMIT} levels, the most a "
                "stored call can carry")


def _json_safe_params(value: Any, *, field: str = "params") -> Any:
    """@owns PARAMS_NESTING_LIMIT — params as every table stores them, or `ParamsTooDeep`
    naming `field`.

    Text for a non-finite float: the record is what a reader diagnoses a query from, and a
    `threshold` of infinity is not a missing one. The same rule `_request_key` keys by.

    Refuses rather than cuts: a cut value would key differently from its live call. The walk
    stops at the limit, so no params can exhaust the stack here or anywhere downstream."""
    try:
        return json_safe(value, non_finite="text",
                         max_depth=PARAMS_NESTING_LIMIT, deeper="refuse")
    except JsonTooDeep:
        raise ParamsTooDeep(field) from None


def params_too_deep(value: Any) -> bool:
    """Would `value`, stored as a call's params, be refused as too deep?

    Asks the storing step itself, so no check can disagree with what the writers refuse."""
    try:
        _json_safe_params(value)
    except ParamsTooDeep:
        return True
    return False


def call_args_too_deep(args: Any) -> bool:
    """Would any argument of a model's call, stored as params, be refused as too deep?

    `args` is the call's whole argument object, as text or decoded. Text is judged on its
    bytes, because text too deep for `json.loads` decodes to nothing and would look shallow;
    the argument object sits one level above each argument, hence the `+ 1`."""
    if isinstance(args, str):
        return json_nesting_depth(args) > PARAMS_NESTING_LIMIT + 1
    return isinstance(args, Mapping) and any(params_too_deep(v) for v in args.values())


RESERVED_QUERY_ID_PREFIX = "∅."
"""The prefix every writer-only sentinel `query_id` carries; `resolve_query_id` refuses it.

`∅` fails `draft_synthesis._SAFE_ID_SEGMENT`, so the offline routers partition sentinel rows by
construction. A model able to spell one could stamp a refusal record onto an unrefused query, or
route arbitrary failures with unbounded `params` into the pitfalls residue past
`SHIM_COMMAND_MAX_CHARS`. The whole prefix is refused so new sentinels are covered."""


def is_reserved_query_id(value: str) -> bool:
    return value.startswith(RESERVED_QUERY_ID_PREFIX)


ABOVE_GUARD_QUERY_ID = "∅.above-repeat-guard"
"""Sentinel `query_id` for rows written above the guard's placement in
`QueryCapture.wrap_tool_execute`: `wrap_tool_validate`'s rejection row and `_grant_check`'s
adapter-load-error and non-`GRANTED` rows.

No call that reaches the guard could have such a row refused, so counting them would let a
replay report a trip no live run can produce."""

BASH_SHIM_QUERY_ID = "∅.bash-shim"
"""Sentinel `query_id` for a failed reducer-shim row from the gather bash lane.

`∅` fails `draft_synthesis._SAFE_ID_SEGMENT` and is no catalog id, so the row reaches only
`collect_general_failures` — the pitfalls residue, taught via `skills/gather/defender-sql.md`.
A descriptive id like `{system}.defender-sql-unnest` would pass the safe-segment match and mint
every failed reduce as a candidate catalog template."""

DENIED_QUERY_ID = "∅.denied"
"""Sentinel `query_id` for a call the grant check refused (a verb withheld from the role).

The offline judge grades leads, so a lead whose only activity was a denied verb needs a row to
be found by. Like the other sentinels it stays out of the learning loop: `lead_repository`
splits it onto `JoinedLead.sentinels` and each router partitions on `is_sentinel`. The denial
audit record in `policy_denials.jsonl` is still written first.

Distinct from `ABOVE_GUARD_QUERY_ID` because the judge reports it as `kind=denied` and its
`error_class` is `DENIED_ERROR_CLASS`. It is written above the guard's placement, so it is in
`ABOVE_PLACEMENT_QUERY_IDS`; `in_rejection_domain` excludes it by construction."""

REPEAT_TRIP_QUERY_ID = "∅.repeat-trip"
"""Sentinel `query_id` for the repeat guard's own trip row.

Must not join `ABOVE_PLACEMENT_QUERY_IDS`: a trip row keeps counting toward later checks of the
same key so replays match the live run. The id only changes offline routing. The model's own id
would misroute it: a coined id becomes a `_draft/` template for the refused query, a catalog id
reaches the lead-author as a template failure, and neither reaches the curator."""


#: Characters a `query_id` may not carry: path shapes (traversal out of the directory it names
#: a file in) and render shapes (a newline or `#` would forge markdown structure in the offline
#: collectors' documents).
_QID_FORBIDDEN = ("/", "\\", "..", "\x00", "\n", "\r", "#")

#: The part after the first `.` in a coined `query_id`. No dots: `'system.foo.bar'` would give
#: `draft_synthesis._draft_candidate_segments` a second unvalidated path component.
_KEBAB_SEGMENT = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_-]*\Z")


def resolve_query_id(system: str, verb: str, model_query_id: str | None) -> str:
    """The `query_id` a call is recorded under: the model's `{system}.{kebab-name}` when well
    formed for `system`, else `{system}.{verb}`. Here rather than in the tool so pydantic-ai-free
    callers apply the same rule."""
    # A model-supplied reserved `∅.` id must not reach a real row: the repeat-trip record sits
    # above `_screen`, so nothing else screens it.
    if (
        model_query_id
        and not is_reserved_query_id(model_query_id)
        and not any(t in model_query_id for t in _QID_FORBIDDEN)
    ):
        # The prefix must equal the dispatched system exactly (no case folding or NFC).
        prefix, sep, remainder = model_query_id.partition(".")
        if sep and prefix == system and remainder and _KEBAB_SEGMENT.match(remainder):
            return model_query_id
    return f"{system}.{verb}" if verb else f"{system}.ad-hoc"
