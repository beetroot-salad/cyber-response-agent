"""Target fidelity (D3/D4, #632): a verb cannot be aimed outside the system it is declared
under. Two rule forms — an HTTP read-endpoint allowlist for the URL-shaped adapters, and a
program+container-target pair for host-state, which has no URL for the row-shaped rule to
apply to — plus the transport capture seam the endpoint rule is checked through and the
allowlist's own authoring-integrity constructor.
"""
from __future__ import annotations

import fnmatch
import sys as _sys
import urllib.parse
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path as _Path
from typing import Any

if (_root := str(_Path(__file__).resolve().parents[3])) not in _sys.path:
    _sys.path.insert(0, _root)

from defender.scripts.adapters.faults import AdapterFault


class ConfinementFault(AdapterFault):
    """A target-fidelity refusal: never an infra fault (not in circuit_breaker's
    INFRA_EXIT_CODES), and refused before any transport is attempted."""

    exit_code = 1


class AllowlistError(Exception):
    """A read-endpoint allowlist authoring defect — raised at construction, never at use."""


# ── the read-endpoint allowlist ──────────────────────────────────────────────────────────


class ReadEndpointAllowlist(Mapping):
    """A validating `Mapping[system, tuple[(endpoint_pattern, method), ...]]`. Refuses an
    entry naming no HTTP method at AUTHORING time (§7 F1) — the method is what separates the
    ticket store's read from its write on the identical resolved path, so an entry authored
    without one silently reopens that collision."""

    def __init__(self, table: Mapping[str, Iterable[Any]]):
        validated: dict[str, tuple[tuple[str, str], ...]] = {}
        for system, entries in table.items():
            built: list[tuple[str, str]] = []
            for entry in entries:
                if not (isinstance(entry, tuple) and len(entry) == 2):
                    raise AllowlistError(
                        f"{system}: read-endpoint entry {entry!r} is not an "
                        "(endpoint_pattern, method) pair"
                    )
                endpoint, method = entry
                if not method:
                    raise AllowlistError(
                        f"{system}: read-endpoint entry {entry!r} names no HTTP method"
                    )
                built.append((endpoint, method))
            validated[system] = tuple(built)
        self._table = validated

    def __getitem__(self, key: str) -> tuple[tuple[str, str], ...]:
        return self._table[key]

    def __iter__(self):
        return iter(self._table)

    def __len__(self) -> int:
        return len(self._table)


def normalize_endpoint(url: str) -> str:
    """The resolved request target, normalized: percent-decoded, `..` segments resolved,
    duplicate/trailing slashes collapsed, query string dropped (§7 R6)."""
    path = urllib.parse.unquote(urllib.parse.urlsplit(url).path)
    resolved: list[str] = []
    for part in path.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if resolved:
                resolved.pop()
            continue
        resolved.append(part)
    return "/" + "/".join(resolved)


READ_ENDPOINT_ALLOWLIST = ReadEndpointAllowlist({
    "elastic": (
        ("/*/_search", "POST"),
        ("/_query", "POST"),
        ("/_cluster/health", "GET"),
        ("/api/status", "GET"),
    ),
    "change-mgmt": (
        ("/health", "GET"),
        ("/changes", "GET"),
        ("/changes/active", "GET"),
        ("/changes/*", "GET"),
    ),
    "cmdb": (
        ("/health", "GET"),
        ("/hosts", "GET"),
        ("/hosts/*", "GET"),
        ("/roles", "GET"),
    ),
    "identity": (
        ("/health", "GET"),
        ("/users", "GET"),
        ("/roles", "GET"),
        ("/users/*/can_access", "GET"),
        ("/users/*/authorized_hosts", "GET"),
        ("/users/*", "GET"),
    ),
    "threat-intel": (
        ("/health", "GET"),
        ("/indicators", "GET"),
        ("/lookup/*", "GET"),
    ),
    "ticket": (
        ("/health", "GET"),
        ("/tickets", "GET"),
        ("/tickets/*", "GET"),
    ),
})


def confine_read_endpoint(system: str, url: str, *, method: str, verb_class: str) -> str:
    """Refuse a request whose resolved, normalized target is not a declared read endpoint for
    `system` under `method`. Checked against REAL requests via the capture seam, never against
    the allowlist's own entries."""
    path = normalize_endpoint(url)
    entries = READ_ENDPOINT_ALLOWLIST.get(system, ())
    if not any(m == method and fnmatch.fnmatchcase(path, pattern) for pattern, m in entries):
        raise ConfinementFault(
            f"{system} verb attempted {method} {path}, outside its declared read-endpoint "
            f"allowlist (verb_class={verb_class!r})"
        )
    return url


# ── the transport capture seam ───────────────────────────────────────────────────────────


@dataclass(frozen=True)
class CapturedRequest:

    system: str
    url: str
    method: str


@dataclass
class TransportCapture:

    requests: list[CapturedRequest] = field(default_factory=list)

    def record(self, *, system: str, url: str, method: str) -> None:
        self.requests.append(CapturedRequest(system=system, url=url, method=method))


# ── the elastic index (D3) confinement ───────────────────────────────────────────────────


def _reach_ok(index: str, pattern: str) -> bool:
    if index == pattern:
        return True
    if not pattern.endswith("*"):
        return False
    prefix = pattern[:-1]
    if index.endswith("*"):
        return index[:-1].startswith(prefix)
    return index.startswith(prefix)


def confine_index(index: str, configured_patterns: Iterable[str]) -> str:
    """Refuse an index expression whose REACH falls outside every configured pattern — never
    the literal string. Evaluates Elasticsearch's own grammar (a comma-list, `*`, a leading
    `-` exclusion) and refuses the WHOLE call rather than silently narrowing to the in-bounds
    part (§7 R5)."""
    patterns = tuple(configured_patterns)
    if not isinstance(index, str) or not index:
        raise ConfinementFault(f"empty or non-string index {index!r}")
    if "," in index:
        raise ConfinementFault(
            f"index expression {index!r} names a multi-index list — refused whole"
        )
    if index.startswith("-"):
        raise ConfinementFault(f"index expression {index!r} is an exclusion pattern — refused")
    if index == "*":
        raise ConfinementFault("index '*' reaches the whole cluster — refused")
    if any(_reach_ok(index, p) for p in patterns):
        return index
    raise ConfinementFault(
        f"index {index!r} falls outside the configured patterns {patterns}"
    )


# ── the host-state program+target confinement ────────────────────────────────────────────


HOST_STATE_PROGRAMS: frozenset[str] = frozenset({
    "ps", "cat", "getent", "sha256sum", "dpkg-query",
})


def confine_host(host: str) -> str:
    from defender.scripts.adapters import host_state_adapter  # deferred: avoid the cycle

    if host not in host_state_adapter.KNOWN_HOSTS:
        raise ConfinementFault(
            f"host {host!r} is not in the declared host-state inventory "
            f"({', '.join(host_state_adapter.KNOWN_HOSTS)})"
        )
    return host


def confine_host_state_call(program: str, host: str) -> None:
    """Both halves of D3's host-state rule: the PROGRAM against the per-system allowlist, and
    the container TARGET against the declared inventory. Neither alone bounds reach — the
    program alone does not bound reach (`cat` inside the ticket store is the disclosure), and
    the target alone does not bound effect."""
    if program not in HOST_STATE_PROGRAMS:
        raise ConfinementFault(
            f"host-state program {program!r} is not in the declared allowlist "
            f"{sorted(HOST_STATE_PROGRAMS)}"
        )
    confine_host(host)


__all__ = [
    "HOST_STATE_PROGRAMS",
    "READ_ENDPOINT_ALLOWLIST",
    "AllowlistError",
    "CapturedRequest",
    "ConfinementFault",
    "ReadEndpointAllowlist",
    "TransportCapture",
    "confine_host",
    "confine_host_state_call",
    "confine_index",
    "confine_read_endpoint",
    "normalize_endpoint",
]
