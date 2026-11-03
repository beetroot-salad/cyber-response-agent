"""Jira ready-made adapter (#1359): the host's one write to a case, a comment on the issue.

Reached through the credential proxy only (`http-proxy`): the proxy adds the credential and judges
the request against the system's declared write routes. The adapter grants the agent nothing
(`VERBS` is empty); `add_case_comment` is the host's action, never a verb.

`JIRA_SERVICE_DESK` (required, no default) picks the API: `no` is Jira Cloud's REST v3 issue
comment (an Atlassian Document Format body), `yes` is the Jira Service Management request comment
(an internal one, `public: false`).
"""

from __future__ import annotations

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
from defender.kit.faults import ConfigFault

if TYPE_CHECKING:  # pragma: no cover — typing only
    from defender.kit.verbs import TenantRecord, Verb  # noqa: F401 — named by the VERBS type comment

SYSTEM = "jira"
PREFIX = "JIRA"

#: The transport template plus the one Jira-specific key. Required, no default.
REQUIRED_CONFIG_KEYS = (*transport.REQUIRED_CONFIG_KEYS_TEMPLATE, "SERVICE_DESK")

_SERVICE_DESK_VALUES = ("yes", "no")


def _jira_settings(tenant: TenantRecord) -> tuple[dict[str, str], bool]:
    """The system's config over the run's record and whether it is a Service Management project,
    or the `ConfigFault` for why the system is unusable."""
    method = transport.record_entry(tenant, SYSTEM).get(f"{PREFIX}_TRANSPORT")
    if method != HTTP_PROXY:
        raise ConfigFault(
            f"{PREFIX}_TRANSPORT={method!r}: the ready-made Jira adapter is reached only "
            f"through the credential proxy — set {PREFIX}_TRANSPORT to {HTTP_PROXY!r}")
    config = transport.record_config(tenant, SYSTEM, PREFIX, REQUIRED_CONFIG_KEYS)
    value = config["SERVICE_DESK"]
    if value not in _SERVICE_DESK_VALUES:
        raise ConfigFault(
            f"{PREFIX}_SERVICE_DESK must be 'yes' or 'no' (lowercase), got {value!r}")
    return config, value == "yes"


def check_settings(tenant: TenantRecord) -> None:  # lint-dup: ok — every adapter declares its own settings check (#1256 O-5)
    """This system's settings check (#1256 O-5): every `ConfigFault` `add_case_comment` can
    raise over the run's record, or None when the system is usable."""
    _jira_settings(tenant)


def _adf(text: str) -> dict:
    """`text` as an Atlassian Document Format document, one paragraph per line."""
    lines = text.splitlines() or [""]
    return {
        "type": "doc",
        "version": 1,
        "content": [
            {"type": "paragraph", "content": [{"type": "text", "text": line}] if line else []}
            for line in lines
        ],
    }


def add_case_comment(ctx: VerbContext, *, key: str, body: str) -> str | None:  # lint-dup: ok — every case-recording adapter exports the host's comment action under this one name (#1359)
    """The host's one write to a case (#1359): add the plain-text `body` as a comment on issue
    `key`, and return the issue's web link. Not a verb (never in `VERBS`). The key is one
    percent-encoded path segment, so it cannot reshape the request. Faults are the shared
    classes: a 4xx is an `UpstreamFault` carrying the status."""
    config, service_desk = _jira_settings(ctx.tenant)
    quoted = urllib.parse.quote(key, safe="")
    if service_desk:
        path = f"/rest/servicedeskapi/request/{quoted}/comment"
        payload: dict = {"body": body, "public": False}
    else:
        path = f"/rest/api/3/issue/{quoted}/comment"
        payload = {"body": _adf(body)}
    transport.http_write(ctx, config, "POST", path, payload, system=SYSTEM)
    return f"{config['URL_BASE'].rstrip('/')}/browse/{quoted}"


#: A ready-made adapter grants the agent nothing.
VERBS = {}  # type: dict[str, Verb]  # a type comment: the cold roster read sees only a plain `VERBS = {...}` assignment
