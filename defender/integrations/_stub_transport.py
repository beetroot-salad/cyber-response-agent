"""Shared transport for the adapters of systems with network access: every one is reached only
through the credential proxy, at the base its access declaration names (#1391 O1, P1)."""

from __future__ import annotations

import json
import urllib.parse
from typing import TYPE_CHECKING, Any

from defender._proxy_client import proxy_exchange
from defender.kit.access import AccessDeclaration
from defender.kit.settings import (
    NOT_CONFIGURED,
    SystemConfig,
    config_pointer,
    is_blank,
    pointer_to,
)
from defender.kit.verbs import VerbContext
from defender.integrations.confinement import ConfinementFault, record_outbound
from defender.kit.faults import USAGE_EXIT_CODE, AdapterFault, ConfigFault, TransportFault, UpstreamFault

if TYPE_CHECKING:  # pragma: no cover — typing only
    from defender.kit.verbs import TenantRecord


#: The keys a stub system's `config.env` holds (prefix stripped). Its base is its access
#: declaration's, never a key (A2).
REQUIRED_CONFIG_KEYS_TEMPLATE = ("TIMEOUT_SEC",)

#: Where an operator whose settings still name a retired key is pointed (#1391 O7).
UPGRADE_POINTER = 'defender/CLAUDE.md, "Upgrade from before the Docker removal"'

__all__ = [
    "REQUIRED_CONFIG_KEYS_TEMPLATE",
    "UPGRADE_POINTER",
    "USAGE_EXIT_CODE",
    "check_settings_of",
    "health_check",
    "http_get",
    "http_get_obj",
    "http_post",
    "http_timed",
    "load_config",
    "raise_proxy_fault",
    "record_access",
    "record_config",
    "record_entry",
    "system_entry",
]


def system_entry(ctx: VerbContext, system: str) -> SystemConfig:
    """`record_entry` over the call's run record (`ctx.tenant`)."""
    return record_entry(ctx.tenant, system)


def record_entry(tenant: TenantRecord, system: str) -> SystemConfig:
    """`system`'s `config.env` as the RUN's record holds it (parsed once at resolve), or the
    `ConfigFault` for why there is none: a folder with no usable file keeps its own fault, and a
    system with no folder gets "this tenant's settings do not configure this system". A fresh
    instance each call, so a stored fault is never handed a second traceback.

    A function of the record alone, so an adapter's settings check (#1256) asks what its verbs
    ask without a call to make."""
    entry = tenant.systems.get(system)
    if entry is None:
        raise ConfigFault(f"config file not found: {config_pointer(system)} — {NOT_CONFIGURED}")
    if isinstance(entry, ConfigFault):
        raise ConfigFault(str(entry))
    return entry


def load_config(
    ctx: VerbContext, system: str, prefix: str,
    required: tuple[str, ...] = REQUIRED_CONFIG_KEYS_TEMPLATE,
) -> dict[str, str]:
    """`record_config` over the call's run record (`ctx.tenant`): the loader every verb calls,
    under the signature the case-comment writer and the connect example keep."""
    return record_config(ctx.tenant, system, prefix, required)


def record_config(
    tenant: TenantRecord, system: str, prefix: str,
    required: tuple[str, ...] = REQUIRED_CONFIG_KEYS_TEMPLATE,
) -> dict[str, str]:
    """`system`'s settings from the run's record: the `required` keys of its `config.env`
    (prefix stripped), each set and not blank, and `URL_BASE`, the base of its access
    declaration, which holds the only one (A2). The keys an adapter reads are exactly
    `required` (#1391 Q4/D10): any other key in the file — a retired access-method or Docker
    key, a base key, a typo — is a `ConfigFault` naming it, as is a missing declaration (P1)."""
    if "URL_BASE" in required:
        raise ValueError(f"{system}'s adapter lists URL_BASE as a config key: a system's base is "
                         f"its access.yaml's, never a config.env setting")
    entry = record_entry(tenant, system)
    declared = {f"{prefix}_{key}" for key in required}
    undeclared = sorted(key for key in entry if key not in declared)
    if undeclared:
        reads = ", ".join(sorted(declared)) or "no keys"
        raise ConfigFault(
            f"{', '.join(undeclared)} in {config_pointer(system)} is not a setting of {system} "
            f"(it reads {reads}; its base is its access.yaml's) — remove it; a key of the "
            f"retired docker access method is removed as {UPGRADE_POINTER} says")
    declaration = record_access(tenant, system)
    cfg = {key: entry[f"{prefix}_{key}"] for key in required
           if not is_blank(entry.get(f"{prefix}_{key}", ""))}
    missing = [k for k in required if k not in cfg]
    if missing:
        raise ConfigFault(
            f"missing required config keys in {config_pointer(system)}: "
            f"{', '.join(f'{prefix}_{k}' for k in missing)}")
    _check_timeout(prefix, cfg.get("TIMEOUT_SEC"))
    return {"URL_BASE": declaration.base, **cfg}


def _check_timeout(prefix: str, timeout: str | None) -> None:
    if timeout is not None and not (timeout.isascii() and timeout.isdigit() and len(timeout) <= 9 and int(timeout) > 0):
        raise ConfigFault(
            f"{prefix}_TIMEOUT_SEC must be a whole number of seconds above zero, got {timeout!r}")


def record_access(tenant: TenantRecord, system: str) -> AccessDeclaration:
    """`system`'s parsed access declaration as the run's record holds it, or its `ConfigFault`."""
    found = tenant.access.get(system)
    if found is None:
        raise ConfigFault(f"{pointer_to(f'systems/{system}/access.yaml')} not found — {system} "
                          f"is reached only through the credential proxy, at the base its access "
                          f"declaration names; {NOT_CONFIGURED}")
    if isinstance(found, ConfigFault):
        raise ConfigFault(str(found))
    return found


def check_settings_of(
    tenant: TenantRecord, system: str, prefix: str,
    required: tuple[str, ...] = REQUIRED_CONFIG_KEYS_TEMPLATE,
) -> None:
    """The settings check of an adapter whose verbs load their config (`load_config`) and then
    call through the proxy (#1256 O-5): every `ConfigFault` such a verb can raise, over the run's
    record. None when the system is usable."""
    record_config(tenant, system, prefix, required)


def http_get(
    ctx: VerbContext, config: dict[str, str], path: str, *, system: str,
    params: dict | None = None,
) -> dict | list:
    """GET <URL_BASE><path>?<params>, return parsed JSON.

    Raises `TransportFault` (infra) on an unreachable system or a 5xx and `UpstreamFault` (a
    query error, carrying the vendor's own `detail`) on a 4xx — a 404 included.

    `system` is required: it keys the confinement allowlist, and a default would let a caller
    confine against the wrong one.
    """
    qs = ("?" + urllib.parse.urlencode(params)) if params else ""
    url = f"{config['URL_BASE'].rstrip('/')}{path}{qs}"
    return _request(ctx, config, url, system=system, method="GET")


def http_post(
    ctx: VerbContext, config: dict[str, str], path: str, body: dict, *, system: str,
) -> dict | list:
    url = f"{config['URL_BASE'].rstrip('/')}{path}"
    return _request(ctx, config, url, system=system, method="POST", body=body)


def http_timed(  # noqa: PLR0913 — one request's per-call state
    ctx: VerbContext, config: dict[str, str], method: str, path: str, body: dict | None, *,
    system: str, timeout_sec: int,
) -> dict | list:
    """`method` <URL_BASE><path> as `http_get`/`http_post` send it, under the adapter's own
    timeout constant rather than a `TIMEOUT_SEC` setting (Elastic's, #1391 O3)."""
    url = f"{config['URL_BASE'].rstrip('/')}{path}"
    return _perform(ctx, config, url, system=system, method=method, body=body,
                    timeout_sec=timeout_sec)


def http_write(
    ctx: VerbContext, config: dict[str, str], method: str, path: str, body: dict | None, *,
    system: str,
) -> None:
    """The HOST's write to a case system (#1359): `method` <URL_BASE><path> with a JSON `body`.
    Used only by an adapter's `add_case_comment`; no query verb reaches it. The proxy's declared
    write routes judge it. Whether the store took it is `_judge_write`'s: any 2xx is success
    whatever its body, a redirect or a 4xx is an `UpstreamFault` carrying the status, and a 5xx
    or an unreachable store is a `TransportFault`."""
    url = f"{config['URL_BASE'].rstrip('/')}{path}"
    _perform(ctx, config, url, system=system, method=method, body=body, write=True)


def http_get_obj(
    ctx: VerbContext, config: dict[str, str], path: str, *, system: str,
    params: dict | None = None,
) -> dict[str, Any]:
    """`http_get` for endpoints whose contract is a JSON object: narrows the type and fails
    fast on anything else. List endpoints use `http_get` with their own guard."""
    payload = http_get(ctx, config, path, system=system, params=params)
    if not isinstance(payload, dict):
        raise TransportFault(
            f"expected a JSON object from {path}, got {type(payload).__name__}"
        )
    return payload


def _judge_write(code: int, body_text: str, where: str) -> None:
    """THE judgement of the host's write (#1359), from the store's own status
    alone: a 2xx is success whatever its body (the body is never read), a 5xx is the store down
    (`TransportFault`), and anything else — a redirect, a 4xx — is the store's refusal
    (`UpstreamFault` carrying the status)."""
    if 200 <= code < 300:
        return
    if code >= 500:
        raise TransportFault(f"upstream {where} returned HTTP {code}: {body_text}")
    raise UpstreamFault(f"HTTP {code} from {where}: {_vendor_detail(body_text)}", status=code)


#: The most characters of an error body that has no reason to pick out reach a fault.
VENDOR_DETAIL_CAP = 2000


def _vendor_detail(body_text: str) -> object:
    """The vendor's own reason from an error body: its `detail` (verbatim), or Elasticsearch's
    `error` when it is text, else its `error.root_cause` reasons (else `error.reason`), each with
    its type. A body that names none
    is handed on whole, cut at `VENDOR_DETAIL_CAP` characters."""
    try:
        payload = json.loads(body_text) if body_text else {}
    except json.JSONDecodeError:
        payload = {"detail": _capped_detail(body_text)}
    if not isinstance(payload, dict):
        return _capped_detail(payload)
    if "detail" in payload:
        return payload["detail"]
    error = payload.get("error")
    if isinstance(error, str):  # Elasticsearch's plain form, e.g. "no handler found for uri […]"
        return _capped_detail(error)
    if isinstance(error, dict):
        causes = [c for c in error.get("root_cause") or [] if isinstance(c, dict)] or [error]
        reasons = [f"{c.get('type')}: {c['reason']}" if c.get("type") else c["reason"]
                   for c in causes if isinstance(c.get("reason"), str)]
        if reasons:
            return _capped_detail("; ".join(dict.fromkeys(reasons)))
    return _capped_detail(payload)


def _capped_detail(value: object) -> object:
    """`value` as it is when its text is within `VENDOR_DETAIL_CAP`, else that text cut there."""
    text = value if isinstance(value, str) else str(value)
    return value if len(text) <= VENDOR_DETAIL_CAP else text[:VENDOR_DETAIL_CAP] + " [cut]"


def _request(
    ctx: VerbContext, config: dict[str, str], url: str, *, system: str, method: str,
    body: dict | None = None,
) -> dict | list:
    return _perform(ctx, config, url, system=system, method=method, body=body)


def _perform(  # noqa: PLR0913 — one request's per-call state
    ctx: VerbContext, config: dict[str, str], url: str, *, system: str, method: str,
    body: dict | None = None, write: bool = False, timeout_sec: int | None = None,
) -> dict | list:
    timeout = timeout_sec if timeout_sec is not None else int(config.get("TIMEOUT_SEC", "10"))
    # The proxy's route check is the only guard for this system (A6), bar a vendor adapter's
    # own confinement before it calls here (P3); the capture is kept.
    record_outbound(ctx, system, url, method=method)
    return _proxy_request(ctx, url, system=system, method=method, body=body, write=write,
                          timeout_sec=timeout)


def raise_proxy_fault(fault: str, detail: str, status: int | None = None, *,
                      from_system: bool = False, sent: bool = True) -> None:
    """Raise the fault class the proxy named, with its detail (A9); an `UpstreamFault` carries
    the store's `status` when the proxy relayed one. The proxy's own (`proxy_own`) unless the
    system answered (`status`) or the proxy saw its call fail (`from_system`, #1404). A
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
    raised.proxy_own = not (from_system or status)
    raise raised


def _proxy_request(  # noqa: PLR0913 — one request's per-call state
    ctx: VerbContext, url: str, *, system: str, method: str, body: dict | None,
    timeout_sec: int, write: bool = False,
) -> dict | list:
    """One request through the proxy, its faults raised as the proxy classified them. The
    capture is `_perform`'s."""
    answer = proxy_exchange(ctx, system=system, method=method, url=url, body=body,
                            timeout_sec=timeout_sec)
    if write:
        if answer.status:
            # The store answered: its status alone decides, whatever the proxy made of the body.
            _judge_write(answer.status, answer.body, system)
            return {}
        raise_proxy_fault(answer.fault or "TransportFault", answer.detail,
                          from_system=answer.from_system, sent=answer.sent)
    if answer.fault in ("UpstreamFault", "TransportFault") and answer.status and not answer.reader_fault:
        # The system answered: its own reason, unaltered by the proxy (#1412), reaches the model
        # and curation.
        # With no body to hand on (withheld, or the reply broke) the proxy's reason says why.
        why = _vendor_detail(answer.body) if answer.body else answer.detail
        raise_proxy_fault(answer.fault, f"HTTP {answer.status} from {system}: {why}",
                          answer.status, from_system=True)
    if answer.fault is not None:
        raise_proxy_fault(answer.fault, answer.detail, from_system=answer.from_system,
                          sent=answer.sent)
    if answer.status >= 400:
        raise UpstreamFault(f"HTTP {answer.status} from {system}: {_vendor_detail(answer.body)}",
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


def health_check(ctx: VerbContext, config: dict[str, str], system_label: str) -> dict[str, Any]:
    """Standard health-check: GET <URL_BASE>/health and RETURN the payload.

    Returns data rather than printing, so the queries table records a payload."""
    payload = http_get_obj(ctx, config, "/health", system=system_label)
    return {"system": system_label, "connected": True, **payload}
