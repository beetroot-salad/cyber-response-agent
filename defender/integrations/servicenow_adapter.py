"""ServiceNow ready-made adapter (#1359): the host's one write to a case, a work note on the record.

Reached through the credential proxy only (`http-proxy`): the proxy adds the credential and judges
the request against the system's declared write routes. The adapter grants the agent nothing
(`VERBS` is empty); `add_case_comment` is the host's action, never a verb.

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

from defender.kit.verbs import VerbContext
from defender.integrations import _stub_transport as transport
from defender.kit.access import HTTP_PROXY
from defender.kit.faults import ConfigFault, UpstreamFault

if TYPE_CHECKING:  # pragma: no cover — typing only
    from defender.kit.verbs import TenantRecord, Verb  # noqa: F401 — named by the VERBS type comment

SYSTEM = "servicenow"
PREFIX = "SERVICENOW"

#: The transport template plus the one ServiceNow-specific key. Required, no default.
REQUIRED_CONFIG_KEYS = (*transport.REQUIRED_CONFIG_KEYS_TEMPLATE, "TABLE")

#: A table name is one path segment: letters, digits and underscores.
_TABLE_NAME = re.compile(r"[A-Za-z0-9_]+")

_NOT_FOUND = 404


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


#: A ready-made adapter grants the agent nothing.
VERBS = {}  # type: dict[str, Verb]  # a type comment: the cold roster read sees only a plain `VERBS = {...}` assignment
