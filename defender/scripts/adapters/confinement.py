"""Target fidelity: a verb cannot be aimed outside the system it is declared under.

An HTTP read-endpoint allowlist for the URL-shaped adapters, plus the transport capture seam the
endpoint rule is checked through and the allowlist's authoring-integrity constructor. A system
with no URL keeps its own rule in its adapter (host-state, #1215).
"""
from __future__ import annotations

import fnmatch
import sys as _sys
import urllib.parse
from collections.abc import Iterable, Mapping
from dataclasses import field
from pathlib import Path as _Path
from typing import Any

if (_root := str(_Path(__file__).resolve().parents[3])) not in _sys.path:
    _sys.path.insert(0, _root)

from defender._model import model
from defender.scripts.adapters.faults import AdapterFault


class ConfinementFault(AdapterFault):
    """A target-fidelity refusal: never an infra fault (not in circuit_breaker's
    INFRA_EXIT_CODES), and refused before any transport is attempted."""

    exit_code = 1


class AllowlistError(Exception):
    """A read-endpoint allowlist authoring defect — raised at construction, never at use."""


# the read-endpoint allowlist


class ReadEndpointAllowlist(Mapping):
    """A validating `Mapping[system, tuple[(endpoint_pattern, method), ...]]`. Refuses at
    authoring time an entry naming no HTTP method — the method is what separates the ticket
    store's read from its write on the same path."""

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
    duplicate/trailing slashes collapsed, query string dropped."""
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


# the transport capture seam


@model(frozen=True)
class CapturedRequest:

    system: str
    url: str
    method: str


@model
class TransportCapture:

    requests: list[CapturedRequest] = field(default_factory=list)

    def record(self, *, system: str, url: str, method: str) -> None:
        self.requests.append(CapturedRequest(system=system, url=url, method=method))


def guard_outbound(ctx: Any, system: str, url: str, *, method: str) -> None:
    """Confine, then record — what every outbound HTTP path does before connecting. Both
    transports call this rather than restating the pair."""
    confine_read_endpoint(system, url, method=method, verb_class="r")
    capture = getattr(ctx, "capture", None)
    if capture is not None:
        capture.record(system=system, url=url, method=method)


# the elastic index confinement


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
    """Refuse an index expression whose reach (not literal string) falls outside every
    configured pattern. Evaluates Elasticsearch's grammar (comma lists, `*`, leading `-`
    exclusion) and refuses the whole call rather than narrowing to the in-bounds part.

    A branched run is confined exactly as an ordinary one: its world is served by the oracle
    over the same corpus, never by a renamed copy of it.
    """
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
    raise ConfinementFault(f"index {index!r} falls outside the configured patterns {patterns}")


__all__ = [
    "READ_ENDPOINT_ALLOWLIST",
    "AllowlistError",
    "CapturedRequest",
    "ConfinementFault",
    "ReadEndpointAllowlist",
    "TransportCapture",
    "confine_index",
    "confine_read_endpoint",
    "guard_outbound",
    "normalize_endpoint",
]
