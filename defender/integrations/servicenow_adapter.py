"""ServiceNow ready-made adapter (#1359): the host's one write to a case, a work note on the record.

Reached through the credential proxy only (`http-proxy`): the proxy adds the credential and judges
the request against the system's declared write routes. The adapter grants the agent nothing
(`VERBS` is empty); `add_case_comment` and `read_case_comments` are the host's actions, never verbs.

`SERVICENOW_TABLE` (required, no default) names the Table API table the case records live in.
"""

from __future__ import annotations

import re
import urllib.parse
from typing import TYPE_CHECKING

# Workspace root on sys.path so `defender.*` namespace imports resolve when the verb registry
# loads this module BY PATH.
import sys as _sys
from pathlib import Path as _Path

if (_root := str(_Path(__file__).resolve().parents[2])) not in _sys.path:
    _sys.path.insert(0, _root)

from defender.kit.verbs import CaseComments, VerbContext
from defender.integrations import _stub_transport as transport
from defender.kit.access import HTTP_PROXY
from defender.kit.faults import ConfigFault, TransportFault, UpstreamFault

if TYPE_CHECKING:  # pragma: no cover — typing only
    from defender.kit.verbs import TenantRecord, Verb  # noqa: F401 — named by the VERBS type comment

SYSTEM = "servicenow"
PREFIX = "SERVICENOW"

#: The transport template plus the one ServiceNow-specific key. Required, no default.
REQUIRED_CONFIG_KEYS = (*transport.REQUIRED_CONFIG_KEYS_TEMPLATE, "TABLE")

#: A table name is one path segment: letters, digits and underscores.
_TABLE_NAME = re.compile(r"[A-Za-z0-9_]+")

_NOT_FOUND = 404
#: The one page the host's read-back asks for (#1374).
_READ_PAGE = 100


def _servicenow_settings(tenant: TenantRecord) -> dict[str, str]:
    """The system's config over the run's record, or the `ConfigFault` for why it is unusable."""
    method = transport.record_entry(tenant, SYSTEM).get(f"{PREFIX}_TRANSPORT")
    if method != HTTP_PROXY:
        raise ConfigFault(
            f"{PREFIX}_TRANSPORT={method!r}: the ready-made ServiceNow adapter is reached only "
            f"through the credential proxy — set {PREFIX}_TRANSPORT to {HTTP_PROXY!r}")
    config = transport.record_config(tenant, SYSTEM, PREFIX, REQUIRED_CONFIG_KEYS)
    if not _TABLE_NAME.fullmatch(config["TABLE"]):
        raise ConfigFault(
            f"{PREFIX}_TABLE must be one table name (letters, digits, underscores), "
            f"got {config['TABLE']!r}")
    return config


def check_settings(tenant: TenantRecord) -> None:  # lint-dup: ok — every adapter declares its own settings check (#1256 O-5)
    """This system's settings check (#1256 O-5): every `ConfigFault` `add_case_comment` can
    raise over the run's record, or None when the system is usable."""
    _servicenow_settings(tenant)


def add_case_comment(ctx: VerbContext, *, key: str, body: str) -> str | None:  # lint-dup: ok — every case-recording adapter exports the host's comment action under this one name (#1359)
    """The host's one write to a case (#1359): add the plain-text `body` as a work note on the
    record whose sys_id is `key`. Returns None: there is no link. Not a verb (never in `VERBS`).
    The key is one percent-encoded path segment, so it cannot reshape the request. Faults are the
    shared classes: a 4xx is an `UpstreamFault` carrying the status; a 404 also says records are
    addressed by sys_id."""
    config = _servicenow_settings(ctx.tenant)
    quoted = urllib.parse.quote(key, safe="")
    try:
        transport.http_write(ctx, config, "PATCH", f"/api/now/table/{config['TABLE']}/{quoted}",
                             {"work_notes": body}, system=SYSTEM)
    except UpstreamFault as fault:
        if fault.status != _NOT_FOUND:
            raise
        raise UpstreamFault(f"{fault} ServiceNow addresses records by sys_id.",
                            status=fault.status) from fault
    return None


def _note_text(row: object, key: str) -> str:
    value = row.get("value") if isinstance(row, dict) else None
    if not isinstance(value, str):
        raise TransportFault(f"the journal read of {key} holds a note with no text")
    return value


def read_case_comments(ctx: VerbContext, *, key: str) -> CaseComments:  # lint-dup: ok — every case-recording adapter's read goes by this one name (#1374)
    """The record's work notes from the journal, newest first, for the host's read-back after a
    comment whose answer was lost: one request for one bounded page. Not a verb (never in `VERBS`).
    Never complete: an account without journal access reportedly gets an empty list and no refusal,
    so finding this run's note settles the outcome and not finding it proves nothing. A key
    holding `^` would add conditions to the query, so it is refused here. A reply it cannot read
    raises `TransportFault`."""
    config = _servicenow_settings(ctx.tenant)
    if "^" in key:
        raise TransportFault("the record's key holds `^`, so its journal cannot be queried")
    page = transport.http_get_obj(
        ctx, config, "/api/now/table/sys_journal_field", system=SYSTEM,
        params={"sysparm_query": f"element_id={key}^element=work_notes^ORDERBYDESCsys_created_on",
                "sysparm_fields": "value", "sysparm_limit": _READ_PAGE})
    rows = page.get("result")
    if not isinstance(rows, list):
        raise TransportFault(f"the journal read of {key} carries no `result` list")
    return CaseComments(texts=tuple(_note_text(row, key) for row in rows), complete=False, link=None)


#: A ready-made adapter grants the agent nothing.
VERBS = {}  # type: dict[str, Verb]  # a type comment: the cold roster read sees only a plain `VERBS = {...}` assignment
