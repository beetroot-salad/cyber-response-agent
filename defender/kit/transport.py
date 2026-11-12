"""The shared transport every adapter reaches its system with: only through the credential proxy,
at the base the system's access declaration names (#1391 O1, P1), and the one judgement of a
system's settings folder against the keys its adapter reads (S1).

An adapter never builds a URL (T1). It names a path template, `"/hosts/{host}"`, and the values
that fill it; each value must be exactly one path segment (`kit.paths`, T2) or the call is
refused before anything is sent. Query parameters are always a separate argument, and a value
that may hold a separator travels there or in the body (T3)."""

from __future__ import annotations

import json
import re
import urllib.parse
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any, Literal

from defender.kit.access import AccessDeclaration
from defender.kit.faults import (
    ORIGIN_ACCESS,
    ORIGIN_SYSTEM,
    USAGE_EXIT_CODE,
    AdapterFault,
    ConfigFault,
    ConfinementFault,
    TransportFault,
    UpstreamFault,
)
from defender.kit.paths import CASE_KEY_REFUSED, KEPT, REFUSED, segment_fault
from defender.kit.proxy_client import proxy_exchange, report_fault, request_token
from defender.kit.settings import (
    NOT_CONFIGURED,
    PLACEHOLDER,
    ConfigAbsent,
    SystemConfig,
    is_blank,
    locator_of,
)
from defender.kit.verbs import VerbContext

if TYPE_CHECKING:  # pragma: no cover — typing only
    from defender.kit.verbs import TenantRecord


#: The keys a stub system's `config.env` holds (prefix stripped). Its base is its access
#: declaration's, never a key (A2).
REQUIRED_CONFIG_KEYS_TEMPLATE = ("TIMEOUT_SEC",)

#: Where an operator whose settings still name a retired key is pointed (#1391 O7).
UPGRADE_POINTER = 'defender/CLAUDE.md, "Upgrade from before the Docker removal"'

#: What an answer must be: a JSON object, a JSON array, or either.
Answer = Literal["object", "list", "any"]

#: How an adapter reads its vendor's own reason out of an error body; `vendor_detail` unless the
#: adapter hands the transport its own (a vendor whose errors have another shape).
ErrorDetail = Callable[[str], object]

#: The most characters of an error body that has no reason to pick out reach a fault.
VENDOR_DETAIL_CAP = 2000

_FIELD = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")

__all__ = [
    "REQUIRED_CONFIG_KEYS_TEMPLATE",
    "UPGRADE_POINTER",
    "USAGE_EXIT_CODE",
    "VENDOR_DETAIL_CAP",
    "Answer",
    "CaseKey",
    "CommentRoute",
    "ErrorDetail",
    "capped_detail",
    "check_settings_of",
    "comment_write",
    "health_check",
    "link",
    "load_config",
    "raise_proxy_fault",
    "record_access",
    "record_config",
    "record_entry",
    "record_outbound",
    "request",
    "require_segment",
    "route_literal",
    "system_entry",
    "timeout_of",
    "host_write",
    "vendor_detail",
]


# --------------------------------------------------------------------------------------------
# The settings judgement (S1): one system folder against the keys its adapter reads.
# --------------------------------------------------------------------------------------------

def system_entry(ctx: VerbContext, system: str) -> SystemConfig:
    """`record_entry` over the call's run record (`ctx.tenant`)."""
    return record_entry(ctx.tenant, system)


def record_entry(tenant: TenantRecord, system: str) -> SystemConfig:
    """`system`'s settings as the RUN's record holds them (prefixed keys), or the `ConfigFault`
    for why there are none: a stored fault is kept, and a system the record does not hold gets
    "this tenant's settings do not configure this system", located by the record's locator
    (#1366 DC6). A fresh instance each call, so a stored fault is never handed a second
    traceback.

    A function of the record alone, so an adapter's settings check (#1256) asks what its verbs
    ask without a call to make."""
    entry = tenant.systems.get(system)
    if entry is None:
        raise ConfigFault(f"{locator_of(tenant).part(system, 'settings')} not found — {NOT_CONFIGURED}")
    if isinstance(entry, ConfigFault):
        raise ConfigFault(str(entry))
    return entry


def load_config(
    ctx: VerbContext, system: str, prefix: str,
    required: tuple[str, ...] = REQUIRED_CONFIG_KEYS_TEMPLATE, *,
    path_keys: tuple[str, ...] = (),
) -> dict[str, str]:
    """`record_config` over the call's run record (`ctx.tenant`): the loader every verb calls."""
    return record_config(ctx.tenant, system, prefix, required, path_keys=path_keys)


#: Keys no adapter may read (O-T3): the base is the access declaration's, a host a verb parameter.
_NEVER_KEYS = frozenset({"URL_BASE", "HOST"})


def record_config(
    tenant: TenantRecord, system: str, prefix: str,
    required: tuple[str, ...] = REQUIRED_CONFIG_KEYS_TEMPLATE, *,
    path_keys: tuple[str, ...] = (),
) -> dict[str, str]:
    """THE judgement of `system`'s settings (S1), over the tenant record: its `required` keys
    (prefix stripped), or the `ConfigFault` naming what is wrong, located by the record's locator
    (#1366 DC6: a stored record names `system <s> settings`, a folder its file). In order:

    0. a stored fault for its settings comes first;
    1. its access declaration is present and usable (P1);
    2. its settings are present, unless the adapter reads no key (O-S1);
    3. it holds no key the adapter does not read (Q4);
    4. every key it reads is set and not blank;
    5. no value still carries the template's `CHANGE-ME` (S2);
    6. every key in `path_keys` (a value the adapter puts in a request path) is one path
       segment (T2, T4);
    7. a `TIMEOUT_SEC` is a whole number of seconds above zero.

    The base is the declaration's, never a key: the dict carries no `URL_BASE` (O-T3)."""
    wrong = [key for key in required if key in _NEVER_KEYS]
    if wrong:
        raise ValueError(f"{system}'s adapter reads {', '.join(wrong)}: a base is its access.yaml's "
                         "and a host a verb parameter, never a config key")
    found = tenant.systems.get(system)
    if isinstance(found, ConfigFault) and not isinstance(found, ConfigAbsent):
        # A folder or file the run could not read hides what else it holds: name that first.
        raise ConfigFault(str(found))
    record_access(tenant, system)
    entry: Mapping[str, str]
    if isinstance(found, ConfigAbsent) and not required:
        entry = {}
    else:
        entry = record_entry(tenant, system)
    shown = locator_of(tenant).part(system, "settings")
    declared = {f"{prefix}_{key}" for key in required}
    undeclared = sorted(key for key in entry if key not in declared)
    if undeclared:
        reads = ", ".join(sorted(declared)) or "no keys"
        raise ConfigFault(
            f"{', '.join(undeclared)} in {shown} is not a setting of {system} "
            f"(it reads {reads}; its base is its access declaration's) — remove it; a key of the "
            f"retired docker access method is removed as {UPGRADE_POINTER} says")
    cfg = {key: entry[f"{prefix}_{key}"] for key in required
           if not is_blank(entry.get(f"{prefix}_{key}", ""))}
    missing = [k for k in required if k not in cfg]
    if missing:
        raise ConfigFault(
            f"missing required config keys in {shown}: "
            f"{', '.join(f'{prefix}_{k}' for k in missing)}")
    placeholders = [f"{prefix}_{k}" for k in required if PLACEHOLDER in cfg[k]]
    if placeholders:
        raise ConfigFault(f"{', '.join(placeholders)} in {shown} still carries the template's "
                          f"{PLACEHOLDER} — replace it; {NOT_CONFIGURED}")
    for key in path_keys:
        why = segment_fault(cfg[key])
        if why is not None:
            raise ConfigFault(f"{prefix}_{key} in {shown} {why}: {system} puts it in a request "
                              "path, where a value is exactly one segment — "
                              f"{NOT_CONFIGURED}")
    _check_timeout(prefix, cfg.get("TIMEOUT_SEC"), shown)
    return cfg


def _check_timeout(prefix: str, timeout: str | None, shown: str) -> None:
    if timeout is not None and not (timeout.isascii() and timeout.isdigit() and len(timeout) <= 9 and int(timeout) > 0):
        raise ConfigFault(
            f"{prefix}_TIMEOUT_SEC in {shown} must be a whole number of seconds above zero, got {timeout!r}")


def timeout_of(config: Mapping[str, str]) -> int:
    """The `TIMEOUT_SEC` of a judged config (`record_config` checked its shape)."""
    return int(config["TIMEOUT_SEC"])


def record_access(tenant: TenantRecord, system: str) -> AccessDeclaration:
    """`system`'s parsed access declaration as the run's record holds it, or its `ConfigFault`."""
    found = tenant.access.get(system)
    if found is None:
        raise ConfigFault(f"{locator_of(tenant).part(system, 'access')} not found — {system} "
                          f"is reached only through the credential proxy, at the base its access "
                          f"declaration names; {NOT_CONFIGURED}")
    if isinstance(found, ConfigFault):
        raise ConfigFault(str(found))
    return found


def check_settings_of(
    tenant: TenantRecord, system: str, prefix: str,
    required: tuple[str, ...] = REQUIRED_CONFIG_KEYS_TEMPLATE, *,
    path_keys: tuple[str, ...] = (),
) -> None:
    """The settings check of an adapter whose verbs load their config (`load_config`) and then
    call through the proxy (#1256 O-5): every `ConfigFault` such a verb can raise, over the run's
    record. None when the system is usable."""
    record_config(tenant, system, prefix, required, path_keys=path_keys)


# --------------------------------------------------------------------------------------------
# The comment route (#1366 C1, K5): what a case adapter's comment action sends, declared once.
# --------------------------------------------------------------------------------------------

#: A case adapter's comment route: (method, path pattern relative to the access base) in the
#: credential proxy's route grammar, the case key the one `*`.
CommentRoute = tuple[str, str]


def route_literal(key: str, settings: Mapping[str, str]) -> str:
    """The setting `key` (prefixed, as a record stores it) as a literal segment of a comment
    route, or the `ConfigFault` naming it: it must be set, non-empty, and hold no `*`, `/` or
    `\\` (C1: a literal is compared raw by the proxy, and the key is the route's only `*`)."""
    value = settings.get(key)
    if value is None:
        raise ConfigFault(f"{key} is not set: the comment route is built from it")
    if not value:
        raise ConfigFault(f"{key} is empty: the comment route needs it as one path segment")
    bad = sorted({ch for ch in value if ch in "*/\\"})
    if bad:
        raise ConfigFault(f"{key} holds {' '.join(f'`{ch}`' for ch in bad)}: the comment route "
                          "needs it as one literal path segment")
    return value


def comment_write(ctx: VerbContext, system: str, route: CommentRoute, *, key: str, body: dict,
                  timeout_sec: int) -> None:
    """The host's comment on case `key`, sent as exactly the declared `route` (#1366 K5): the
    route's one `*` filled with the key, every other segment as declared."""
    method, pattern = route
    segments = pattern.split("/")
    if segments.count("*") != 1:
        raise ValueError(f"a comment route has exactly one `*` (the case key), got {pattern!r}")
    template = "/".join("{key}" if segment == "*" else segment for segment in segments)
    host_write(ctx, system, method, template, {"key": CaseKey(key)}, body=body,
               timeout_sec=timeout_sec)


# --------------------------------------------------------------------------------------------
# Paths (T1, T2): a template and its values, never a URL an adapter built.
# --------------------------------------------------------------------------------------------

class CaseKey(str):
    """A case key (#1359 P3) as a path value: named by the alert, not chosen by the agent, so it
    is escaped into its segment and refused only for what could split one
    (`kit.paths.CASE_KEY_REFUSED`). Every other path value follows the strict rule (T2)."""

    __slots__ = ()


def require_segment(name: str, value: object) -> str:
    """`value` when it is exactly one path segment (`kit.paths.segment_fault`), else the
    `ConfinementFault` naming `name`: the caller chose a value that would reach another route,
    so nothing is sent (T4: refused at the call, never counted against the system)."""
    why = segment_fault(value, refused=CASE_KEY_REFUSED if isinstance(value, CaseKey) else
                        REFUSED)
    if why is not None:
        raise ConfinementFault(f"`{name}` {why}: a value in a request path is exactly one "
                               "segment, so this call was not sent")
    return value  # type: ignore[return-value]  # segment_fault refuses anything but text


def _fill(template: str, values: Mapping[str, object] | None) -> str:
    """`template` with each `{name}` replaced by its value, percent-encoded as one segment."""
    if not template.startswith("/") or "?" in template or "#" in template:
        raise ValueError(f"path template {template!r} must start with `/` and hold no query "
                         "or fragment (query parameters are a separate argument)")
    given = dict(values or {})
    named = _FIELD.findall(template)
    if sorted(set(named)) != sorted(given):
        raise ValueError(f"path template {template!r} names {sorted(set(named))}, given "
                         f"{sorted(given)}")
    filled = _FIELD.sub(lambda m: urllib.parse.quote(
        require_segment(m[1], given[m[1]]), safe="" if isinstance(given[m[1]], CaseKey) else KEPT),
        template)
    return filled


def _url(base: str, template: str, values: Mapping[str, object] | None,
         query: Mapping[str, object] | None = None) -> str:
    qs = ("?" + urllib.parse.urlencode(query)) if query else ""
    return f"{base.rstrip('/')}{_fill(template, values)}{qs}"


def link(tenant: TenantRecord, system: str, template: str,
         values: Mapping[str, object] | None = None) -> str:
    """A human-facing link under `system`'s declared base (a case's web page), built as a
    request path is (O-T1). Nothing is sent."""
    return _url(record_access(tenant, system).base, template, values)


# --------------------------------------------------------------------------------------------
# Requests.
# --------------------------------------------------------------------------------------------

def request(  # noqa: PLR0913 — one request's per-call state
    ctx: VerbContext, system: str, method: str, template: str,
    values: Mapping[str, object] | None = None, *,
    query: Mapping[str, object] | None = None, body: dict | None = None,
    timeout_sec: int, answer: Answer = "object", error_detail: ErrorDetail | None = None,
) -> Any:
    """`method` <base><template filled by values>?<query> through the credential proxy, and its
    parsed JSON answer, which must be `answer`'s shape (O-T4: anything else is a
    `TransportFault`, the system breaking its contract).

    Raises `ConfinementFault` for a path value that is not one segment (nothing sent),
    `TransportFault` for an unreachable system or a 5xx, and `UpstreamFault` (the vendor's own
    reason, read by `error_detail` when the adapter hands one) for a 4xx — a 404 included."""
    url = _url(record_access(ctx.tenant, system).base, template, values, query)
    record_outbound(ctx, system, url, method=method)
    parsed = _proxy_request(ctx, url, system=system, method=method, body=body,
                            timeout_sec=timeout_sec, error_detail=error_detail or vendor_detail)
    if answer == "object" and not isinstance(parsed, dict):
        raise TransportFault(f"expected a JSON object from {system} {template}, got "
                             f"{type(parsed).__name__}")
    if answer == "list" and not isinstance(parsed, list):
        raise TransportFault(f"expected a JSON array from {system} {template}, got "
                             f"{type(parsed).__name__}")
    return parsed


def host_write(  # noqa: PLR0913 — one request's per-call state
    ctx: VerbContext, system: str, method: str, template: str,
    values: Mapping[str, object] | None = None, *, body: dict | None, timeout_sec: int,
) -> None:
    """The HOST's write to a case system (#1359): `method` <base><template> with a JSON `body`.
    Used only by an adapter's `add_case_comment`; no query verb reaches it. The proxy's declared
    write routes judge it. Whether the store took it is `_judge_write`'s: any 2xx is success
    whatever its body, a redirect or a 4xx is an `UpstreamFault` carrying the status, and a 5xx
    or an unreachable store is a `TransportFault`."""
    url = _url(record_access(ctx.tenant, system).base, template, values)
    record_outbound(ctx, system, url, method=method)
    _proxy_request(ctx, url, system=system, method=method, body=body, write=True,
                   timeout_sec=timeout_sec)


def health_check(ctx: VerbContext, system: str, *, timeout_sec: int) -> dict[str, Any]:
    """Standard health-check: GET <base>/health and RETURN the payload.

    Returns data rather than printing, so the queries table records a payload."""
    payload = request(ctx, system, "GET", "/health", timeout_sec=timeout_sec)
    return {"system": system, "connected": True, **payload}


def record_outbound(ctx: Any, system: str, url: str, *, method: str) -> None:
    """Record the request on the call's capture, if it has one: every request to a system, before
    it goes to the credential proxy, whose route check is its guard (#1163 A6)."""
    capture = getattr(ctx, "capture", None)
    if capture is not None:
        capture.record(system=system, url=url, method=method)


# --------------------------------------------------------------------------------------------
# Answers and faults.
# --------------------------------------------------------------------------------------------

def _judge_write(code: int, body_text: str, where: str) -> None:
    """THE judgement of the host's write (#1359), from the store's own status
    alone: a 2xx is success whatever its body (the body is never read), a 5xx is the store down
    (`TransportFault`), and anything else — a redirect, a 4xx — is the store's refusal
    (`UpstreamFault` carrying the status)."""
    if 200 <= code < 300:
        return
    if code >= 500:
        raise TransportFault(f"upstream {where} returned HTTP {code}: {body_text}")
    raise UpstreamFault(f"HTTP {code} from {where}: {vendor_detail(body_text)}", status=code)


def vendor_detail(body_text: str) -> object:
    """The vendor's own reason from an error body: its `detail` (verbatim), else the body whole,
    cut at `VENDOR_DETAIL_CAP` characters. An adapter whose vendor answers errors in another
    shape hands the transport its own reader (`ErrorDetail`)."""
    try:
        payload = json.loads(body_text) if body_text else {}
    except json.JSONDecodeError:
        return capped_detail(body_text)
    if isinstance(payload, dict) and "detail" in payload:
        return payload["detail"]
    return capped_detail(payload)


def capped_detail(value: object) -> object:
    """`value` as it is when its text is within `VENDOR_DETAIL_CAP`, else that text cut there."""
    text = value if isinstance(value, str) else str(value)
    return value if len(text) <= VENDOR_DETAIL_CAP else text[:VENDOR_DETAIL_CAP] + " [cut]"


def raise_proxy_fault(fault: str, detail: str, status: int | None = None, *,
                      origin: str = ORIGIN_ACCESS, sent: bool = True) -> None:
    """Raise the fault class the proxy named, with its detail (A9); an `UpstreamFault` carries
    the store's `status` when the proxy relayed one. It carries `origin`, whose failure it is
    (#1363 B2): the client decides it from the answer, and `proxy_own` follows from it. A
    `TransportFault` may have reached the system unless the proxy said it was not `sent` (#1374)."""
    raised: AdapterFault
    if fault == "UpstreamFault":
        raised = UpstreamFault(detail or fault, status=status or None)
    else:
        classes = {"ConfigFault": ConfigFault, "ConfinementFault": ConfinementFault,
                   "TransportFault": TransportFault}
        raised = classes.get(fault, TransportFault)(detail or fault)
    if isinstance(raised, TransportFault):
        raised.maybe_delivered = sent
    raised.origin = origin
    raise raised


def _proxy_request(  # noqa: PLR0913 — one request's per-call state
    ctx: VerbContext, url: str, *, system: str, method: str, body: dict | None,
    timeout_sec: int, write: bool = False, error_detail: ErrorDetail = vendor_detail,
) -> dict | list:
    """One request through the proxy, its faults raised as the proxy classified them. The
    capture is the caller's."""
    # The token step's fault is the access holder's own refusal, which it already knows: raised,
    # never reported back to it (#1363 B1), so a shut holder is never taken for lost access.
    token = request_token(ctx)
    try:
        return _decided(ctx, token, url, system=system, method=method, body=body,
                        timeout_sec=timeout_sec, write=write, error_detail=error_detail)
    except AdapterFault as fault:
        # The holder of the process's access learns of a `setup` or `access` fault where the
        # client raises it (#1363 B1), once it names the system the fault is about. A fault the
        # exchange did not label is one derived from the system's own answer (its status, its
        # body, a write it refused): `system`.
        if fault.origin is None:
            fault.origin = ORIGIN_SYSTEM
        if fault.system is None:
            fault.system = system
        report_fault(ctx, fault)
        raise


def _decided(  # noqa: PLR0913 — one request's per-call state
    ctx: VerbContext, token: str | None, url: str, *, system: str, method: str,
    body: dict | None, timeout_sec: int, write: bool, error_detail: ErrorDetail,
) -> dict | list:
    """The answer to one proxied request, or the fault the proxy's answer is."""
    answer = proxy_exchange(ctx, token=token, system=system, method=method, url=url, body=body,
                            timeout_sec=timeout_sec)
    if write:
        if answer.status:
            # The store answered: its status alone decides, whatever the proxy made of the body.
            _judge_write(answer.status, answer.body, system)
            return {}
        raise_proxy_fault(answer.fault or "TransportFault", answer.detail,
                          origin=answer.origin, sent=answer.sent)
    if answer.fault in ("UpstreamFault", "TransportFault") and answer.status and not answer.reader_fault:
        # The system answered: its own reason, unaltered by the proxy (#1412), reaches the model
        # and curation.
        # With no body to hand on (withheld, or the reply broke) the proxy's reason says why.
        why = error_detail(answer.body) if answer.body else answer.detail
        raise_proxy_fault(answer.fault, f"HTTP {answer.status} from {system}: {why}",
                          answer.status, origin=ORIGIN_SYSTEM)
    if answer.fault is not None:
        raise_proxy_fault(answer.fault, answer.detail, origin=answer.origin, sent=answer.sent)
    if answer.status >= 400:
        raise UpstreamFault(f"HTTP {answer.status} from {system}: {error_detail(answer.body)}",
                            status=answer.status)
    if not answer.body:
        return {}
    try:
        parsed = json.loads(answer.body)
    except json.JSONDecodeError as e:
        raise TransportFault(f"non-JSON response from {system}: {e}") from e
    if not isinstance(parsed, dict | list):
        raise TransportFault(f"non-object JSON response from {system}")
    return parsed
