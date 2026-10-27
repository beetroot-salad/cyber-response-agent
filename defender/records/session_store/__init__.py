"""The per-case SQLite session store: the canonical, append-only message log.

One file per `case_id`, sibling of the runs base (never a child): `message` rows form a
parent-chain tree (never updated, never deleted), `message_payload` holds the verbatim
`ModelMessagesTypeAdapter` dump in its own table, and `hydrate()` is the ONE role-scoped
reader (`send` / `analysis` / `actor`) that walks the chain and projects it.

Connections/writes, tree traversal, payload checks, and role projections have separate owners.
"""
from __future__ import annotations
from defender.records._run_id import CASE_ID_RE  # noqa: F401 — re-export; the rule lives with the id rules
from defender.records._store_errors import InvalidCaseId, StoreError  # noqa: F401 — re-exports
from defender.records.run_end import (  # noqa: F401 — re-exports
    TRUNCATED_BY_ABORTED,
    TRUNCATED_BY_BUDGET,
    TRUNCATED_BY_DEAD_END,
    TRUNCATED_BY_EXECUTED_QUERIES,
    TRUNCATED_BY_PROVIDER_DOWN,
    TRUNCATED_BY_REQUEST_LIMIT,
    TRUNCATED_BY_RETRY_EXHAUSTED,
    TRUNCATED_BY_SERVED_LEDGER,
    TRUNCATED_BY_STORE,
    TRUNCATED_BY_TIMED_OUT,
    TRUNCATED_BY_VALUES,
    normalized_truncated_by,
)

from ._schema import (
    CyclicParentChain as CyclicParentChain,
    DDL as DDL,
    HEAD_MOVE_REASONS as HEAD_MOVE_REASONS,
    IncompleteConfig as IncompleteConfig,
    IngestTailUnderflow as IngestTailUnderflow,
    LegacyRunLink as LegacyRunLink,
    PAYLOAD_ENSURE_ASCII as PAYLOAD_ENSURE_ASCII,
    PayloadNotRepresentable as PayloadNotRepresentable,
    PayloadSchemaSkew as PayloadSchemaSkew,
    ROLES as ROLES,
    SCHEMA_VERSION as SCHEMA_VERSION,
    STORE_BUSY_TIMEOUT_MS as STORE_BUSY_TIMEOUT_MS,
    StoreAppendError as StoreAppendError,
    UnknownReadRole as UnknownReadRole,
    UnknownSchemaVersion as UnknownSchemaVersion,
    UnresolvablePathElement as UnresolvablePathElement,
    _CONFIG_REQUIRED_FIELDS as _CONFIG_REQUIRED_FIELDS,
    _LEGACY_LINK_NAME as _LEGACY_LINK_NAME,
    _MAX_PAYLOAD_DEPTH as _MAX_PAYLOAD_DEPTH,
    _TOO_DEEP as _TOO_DEEP,
    _refuse_stale_version as _refuse_stale_version,
)
from ._payload import (
    _children as _children,
    _extract_lead_id as _extract_lead_id,
    _find_nonrepresentable as _find_nonrepresentable,
    _first_wins_pairs as _first_wins_pairs,
    _has_extra_keys as _has_extra_keys,
    _is_nonrepresentable_leaf as _is_nonrepresentable_leaf,
    _lead_id_from_args as _lead_id_from_args,
    _message_from_payload as _message_from_payload,
    _tool_name as _tool_name,
    load_payload as load_payload,
)
from ._write import (
    StoreHandle as StoreHandle,
    _bare_connect as _bare_connect,
    _classify_move as _classify_move,
    _finish_connect as _finish_connect,
    _insert_message as _insert_message,
    _move_head as _move_head,
    _next_seq as _next_seq,
    _session_has_rows as _session_has_rows,
    _validate_batch_shape as _validate_batch_shape,
    _validate_duration_ms as _validate_duration_ms,
    _validate_reason as _validate_reason,
    _validate_seq as _validate_seq,
    open_store as open_store,
    open_store_for_read as open_store_for_read,
    store_path_for as store_path_for,
)
from ._tree import (
    _read_head as _read_head,
    _walk_parents as _walk_parents,
)
from ._pointers import (
    _case_pointer as _case_pointer,
    refuse_legacy_link as refuse_legacy_link,
    resolve_session_id as resolve_session_id,
    resolve_store_path as resolve_store_path,
    write_case_pointer as write_case_pointer,
)
from ._read import (
    _actor_row as _actor_row,
    _check_schema_version as _check_schema_version,
    _complete_prefix_len as _complete_prefix_len,
    _fetch_message_rows as _fetch_message_rows,
    _fetch_payloads as _fetch_payloads,
    _require_resolved as _require_resolved,
    _send_len as _send_len,
    branch_point as branch_point,
    displaced_tip as displaced_tip,
    ends_on_complete_pair as ends_on_complete_pair,
    fold_history as fold_history,
    hydrate as hydrate,
    main_session_id as main_session_id,
    path_row_ids as path_row_ids,
    synthesized_flags as synthesized_flags,
)
