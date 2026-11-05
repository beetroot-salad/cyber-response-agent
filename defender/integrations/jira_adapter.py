"""Jira ready-made adapter (#1359): the host's one write to a case, a comment on the issue.

Reached through the credential proxy only (`http-proxy`): the proxy adds the credential and judges
the request against the system's declared write routes. The adapter grants the agent nothing
(`VERBS` is empty); `add_case_comment` and `read_case_comments` are the host's actions, never verbs.

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

from defender.kit.verbs import CaseComments, VerbContext
from defender.integrations import _stub_transport as transport
from defender.kit.access import HTTP_PROXY
from defender.kit.faults import ConfigFault, TransportFault

if TYPE_CHECKING:  # pragma: no cover — typing only
    from defender.kit.verbs import TenantRecord, Verb  # noqa: F401 — named by the VERBS type comment

SYSTEM = "jira"
PREFIX = "JIRA"

#: The transport template plus the one Jira-specific key. Required, no default.
REQUIRED_CONFIG_KEYS = (*transport.REQUIRED_CONFIG_KEYS_TEMPLATE, "SERVICE_DESK")

_SERVICE_DESK_VALUES = ("yes", "no")
#: The one page the host's read-back asks for (#1374).
_READ_PAGE = 100
#: Document-format nodes whose children run on one line; every other node's children are lines.
_ADF_LINES = ("paragraph", "heading")


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
    return _issue_link(config, quoted)


def _issue_link(config: dict[str, str], quoted: str) -> str:
    return f"{config['URL_BASE'].rstrip('/')}/browse/{quoted}"


def _adf_text(node: object) -> str:
    """An Atlassian Document Format node as plain text, with paragraphs and hard breaks as line
    breaks. `TransportFault` for a node it cannot read."""
    if not isinstance(node, dict):
        raise TransportFault(f"a comment holds a document node that is {type(node).__name__}")
    kind = node.get("type")
    if kind == "hardBreak":
        return "\n"
    if kind == "text":
        text = node.get("text")
        if not isinstance(text, str):
            raise TransportFault("a comment holds a text node with no text")
        return text
    content = node.get("content", [])
    if not isinstance(content, list):
        raise TransportFault(f"a comment's {kind} node has content that is not a list")
    return ("" if kind in _ADF_LINES else "\n").join(_adf_text(child) for child in content)


def _rows(page: dict, field: str, key: str) -> list:
    rows = page.get(field)
    if not isinstance(rows, list):
        raise TransportFault(f"the read of {key} carries no `{field}` list")
    return rows


def _desk_text(comment: object) -> str:
    body = comment.get("body") if isinstance(comment, dict) else None
    if not isinstance(body, str):
        raise TransportFault("a request comment has no text body")
    return body


def _cloud_text(comment: object) -> str:
    body = comment.get("body") if isinstance(comment, dict) else None
    if not isinstance(body, dict):
        raise TransportFault("a comment has no document body")
    return _adf_text(body)


def read_case_comments(ctx: VerbContext, *, key: str) -> CaseComments:  # lint-dup: ok — every case-recording adapter's read goes by this one name (#1374)
    """The case's comments, for the host's read-back after a comment whose answer was lost: one
    request for one bounded page, on the API `add_case_comment` writes through. Not a verb (never
    in `VERBS`). Complete only when the first page's own count or last-page mark proves it. The
    service-desk API has no sort, so a long request can end partial. A reply it cannot read raises
    `TransportFault`."""
    config, service_desk = _jira_settings(ctx.tenant)
    quoted = urllib.parse.quote(key, safe="")
    if service_desk:
        page = transport.http_get_obj(
            ctx, config, f"/rest/servicedeskapi/request/{quoted}/comment", system=SYSTEM,
            params={"start": 0, "limit": _READ_PAGE})
        rows = _rows(page, "values", key)
        texts = tuple(_desk_text(c) for c in rows)
        complete = page.get("start") == 0 and page.get("isLastPage") is True
    else:
        page = transport.http_get_obj(
            ctx, config, f"/rest/api/3/issue/{quoted}/comment", system=SYSTEM,
            params={"startAt": 0, "maxResults": _READ_PAGE, "orderBy": "-created"})
        rows = _rows(page, "comments", key)
        texts = tuple(_cloud_text(c) for c in rows)
        total = page.get("total")
        complete = page.get("startAt") == 0 and type(total) is int and total <= len(rows)
    return CaseComments(texts=texts, complete=complete, link=_issue_link(config, quoted))


#: A ready-made adapter grants the agent nothing.
VERBS = {}  # type: dict[str, Verb]  # a type comment: the cold roster read sees only a plain `VERBS = {...}` assignment
