"""host-state: live state of the hosts an endpoint-security product enrolls, read from that
product's query API through the credential proxy (#1391 O5, D4).

Every verb is one GET under the base the system's access declaration names. The service owns
what may be asked: which hosts are enrolled, which user names and file paths are acceptable, and
the routes below are its whole surface (A6: the proxy's route check is this system's only guard
here). How its answers map to faults is the shared transport's: a 404 (host not enrolled, user
unknown, route unknown) or a 400 (a bad user or path) is the agent's to fix (`UpstreamFault`), a
503 (an enrolled host that is stopped) is the system down (`TransportFault`).

| verb | route (relative to the base) |
|---|---|
| health-check | `/hosts` |
| proc-tree | `/hosts/{host}/processes` |
| passwd | `/hosts/{host}/accounts` |
| authorized-keys | `/hosts/{host}/accounts/{user}/authorized-keys` |
| fim-checksum | `/hosts/{host}/files/sha256?path=…` |
| package-list | `/hosts/{host}/packages` |
| container-inspect | `/containers/{id}` |
"""
from __future__ import annotations

import urllib.parse
from typing import TYPE_CHECKING, Any

import sys as _sys
from pathlib import Path as _Path

if (_root := str(_Path(__file__).resolve().parents[2])) not in _sys.path:
    _sys.path.insert(0, _root)

from defender.kit.verbs import VerbContext
from defender.integrations import _stub_transport as transport
from defender.kit.faults import TransportFault

if TYPE_CHECKING:  # pragma: no cover — typing only
    from defender.kit.verbs import TenantRecord

SYSTEM = "host-state"
PREFIX = "HOST_STATE"
#: host-state reads no config.env key: its base is its declaration's, its timeouts constants.
REQUIRED_CONFIG_KEYS: tuple[str, ...] = ()
DEFAULT_TIMEOUT_SEC = 15
PACKAGES_TIMEOUT_SEC = 30
HEALTH_TIMEOUT_SEC = 10


def _host_state_settings(tenant: TenantRecord) -> dict[str, str]:
    return transport.record_config(tenant, SYSTEM, PREFIX, REQUIRED_CONFIG_KEYS)


def check_settings(tenant: TenantRecord) -> None:  # lint-dup: ok — every adapter declares its own settings check (#1256 O-5)
    """This system's settings check (#1256 O-5): every `ConfigFault` a verb here can raise — a
    key it does not read, no access declaration — over the run's record. None when usable."""
    _host_state_settings(tenant)


def _segment(value: str) -> str:
    """`value` as exactly one path segment: a `/` the agent wrote cannot reach another route."""
    return urllib.parse.quote(value, safe="")


def _get(ctx: VerbContext, path: str, *, timeout_sec: int = DEFAULT_TIMEOUT_SEC) -> dict[str, Any]:
    answer = transport.http_timed(ctx, _host_state_settings(ctx.tenant), "GET", path, None,
                                  system=SYSTEM, timeout_sec=timeout_sec)
    if not isinstance(answer, dict):
        raise TransportFault(f"expected a JSON object from {SYSTEM}, got {type(answer).__name__}")
    return answer


def _answer_field(answer: dict[str, Any], name: str, kind: type) -> Any:
    value = answer.get(name)
    if not isinstance(value, kind):
        raise TransportFault(
            f"{SYSTEM} answered without a {kind.__name__} {name!r}: {sorted(answer)}")
    return value


def _lines(answer: dict[str, Any], name: str) -> list[str]:
    value = _answer_field(answer, name, list)
    if not all(isinstance(line, str) for line in value):
        raise TransportFault(f"{SYSTEM} answered a {name!r} holding something other than text")
    return value


def health_check(ctx: VerbContext) -> dict:
    hosts = _answer_field(_get(ctx, "/hosts", timeout_sec=HEALTH_TIMEOUT_SEC), "hosts", list)
    running: dict[str, bool] = {}
    for host in hosts:
        if not (isinstance(host, dict) and isinstance(host.get("name"), str)
                and isinstance(host.get("running"), bool)):
            raise TransportFault(f"{SYSTEM} answered a host entry without a name and state")
        running[host["name"]] = host["running"]
    return {
        "system": SYSTEM,
        "connected": True,
        "hosts_present": sorted(n for n, up in running.items() if up),
        "hosts_missing": sorted(n for n, up in running.items() if not up),
    }


def container_inspect(ctx: VerbContext, *, container_id: str) -> dict:
    answer = _get(ctx, f"/containers/{_segment(container_id)}")
    return {
        "container_id": container_id,
        "name": _answer_field(answer, "name", str),
        "image": _answer_field(answer, "image", str),
    }


def proc_tree(ctx: VerbContext, *, host: str) -> dict:
    answer = _get(ctx, f"/hosts/{_segment(host)}/processes")
    return {"host": host, "ps_output": _answer_field(answer, "ps_output", str)}


def passwd(ctx: VerbContext, *, host: str) -> dict:
    answer = _get(ctx, f"/hosts/{_segment(host)}/accounts")
    return {"host": host, "entries": _lines(answer, "entries")}


def authorized_keys(ctx: VerbContext, *, host: str, user: str = "root") -> dict:
    answer = _get(ctx, f"/hosts/{_segment(host)}/accounts/{_segment(user)}/authorized-keys")
    return {
        "host": host,
        "user": user,
        "path": _answer_field(answer, "path", str),
        "keys": _lines(answer, "keys"),
    }


def fim_checksum(ctx: VerbContext, *, host: str, path: str) -> dict:
    query = urllib.parse.urlencode({"path": path})
    answer = _get(ctx, f"/hosts/{_segment(host)}/files/sha256?{query}")
    return {"host": host, "path": path, "sha256": _answer_field(answer, "sha256", str)}


def package_list(ctx: VerbContext, *, host: str) -> dict:
    answer = _get(ctx, f"/hosts/{_segment(host)}/packages", timeout_sec=PACKAGES_TIMEOUT_SEC)
    return {"host": host, "packages": _lines(answer, "packages")}


VERBS = {
    "health-check": health_check,
    "container-inspect": container_inspect,
    "proc-tree": proc_tree,
    "passwd": passwd,
    "authorized-keys": authorized_keys,
    "fim-checksum": fim_checksum,
    "package-list": package_list,
}
