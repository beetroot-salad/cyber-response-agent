"""Target fidelity: a verb cannot be aimed outside the system it is declared under.

Two rule forms — an HTTP read-endpoint allowlist for the URL-shaped adapters, and a
program+container-target pair for host-state, which has no URL — plus the transport capture
seam the endpoint rule is checked through and the allowlist's authoring-integrity constructor.
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


def confine_index(
    index: str, configured_patterns: Iterable[str], *, world_id: str | None = None,
) -> str:
    """Refuse an index expression whose reach (not literal string) falls outside every
    configured pattern. Evaluates Elasticsearch's grammar (comma lists, `*`, leading `-`
    exclusion) and refuses the whole call rather than narrowing to the in-bounds part.

    `world_id` admits that world's views (`is_world_view`), which are named outside the
    configured patterns on purpose. Views are per world, and only of configured corpora: the
    world changes which name is admissible, never which corpus.
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
    if world_id is not None and is_world_view(index, patterns, world_id):
        return index
    raise ConfinementFault(
        f"index {index!r} falls outside the configured patterns {patterns}"
        + (f" and is not a world view of {world_id!r}" if world_id is not None else "")
    )


# the world-view namespace

#: Punctuation an Elasticsearch index or alias name cannot carry (whitespace is checked
#: separately). `:` is absent: legal in the cross-cluster expression `remote:logs-*`.
_ILLEGAL_IN_NAME = frozenset('\\/*?"<>|,')

#: The namespace every world view lives in, as a prefix. A suffixed view (`logs-*` ->
#: `logs-w-a`) would still match `logs-*`, so the base run and unstaged siblings would read the
#: world's staged documents. `world_view` checks the disjointness per name.
VIEW_NAMESPACE = "wv"


class ViewNameError(ValueError):
    """A corpus pattern that cannot carry a world view.

    A plain `ValueError`, not a `ConfinementFault`: the branch stager wraps it in its own
    usage-class fault so the refusal lands in the ledger as evidence.
    """


def world_view(base_pattern: str, world_id: str) -> str:
    """The alias `world_id`'s queries read in place of `base_pattern`.

    Per world (siblings sharing a view would see each other's documents) and outside the
    pattern it derives from (see `VIEW_NAMESPACE`).

    Refuses stems an alias cannot carry: `*` alone (nothing left to name the corpus by), a
    non-trailing wildcard (`logs-*-2026`), and characters a quoted source needed (space, `|`),
    since the view is written back unquoted and would break the query. The world id gets the
    same rule, since it reaches every view the run stages. A view nobody can read would let a
    sibling run green against the base corpus while reporting a world that was never applied.

    Disjointness is checked against `base_pattern`, not assumed: a pattern like `wv-*` reaches
    into the namespace itself.
    """
    world = _nameable_world(world_id)
    stem = _nameable(_view_stem(base_pattern), f"corpus pattern {base_pattern!r}")
    view = f"{VIEW_NAMESPACE}-{world}-{stem}"
    if _reach_ok(view, base_pattern):
        raise ViewNameError(
            f"corpus pattern {base_pattern!r} still reaches {view!r}, the view built from it — "
            "a world view has to fall outside the pattern it stages, or the base run and every "
            "sibling that does not stage this system read this world's documents through it")
    return view


def _view_stem(pattern: str) -> str:
    """The corpus half of a view name: `pattern` without its trailing wildcard.

    Shared by `world_view` (build) and `is_world_view` (read back) so they cannot drift. Only
    the wildcard is trimmed: trimming the separator too would collapse `logs-*`, `logs.*` and
    `logs*` onto one alias. A trailing `-` or `.` is legal in an alias name (only a leading one
    is not, and the namespace prefix rules that out). Anything still unnameable, like
    `logs-**`, is refused by `_nameable`.
    """
    return pattern.removesuffix("*")


def _nameable(part: str, origin: str) -> str:
    """`part`, or a refusal naming what an index or alias cannot hold."""
    if not part:
        raise ViewNameError(
            f"{origin} reduces to nothing an alias can be named by — a world view is built "
            "from the corpus it stages, and a bare wildcard leaves no corpus to name")
    illegal = sorted({c for c in part if c in _ILLEGAL_IN_NAME or c.isspace()})
    if illegal:
        raise ViewNameError(
            f"{origin} carries {illegal}, which an index or alias name cannot hold — the view "
            "is written back unquoted, so the retargeted query would not parse as the one "
            "command it replaced")
    # Lower case only. Elasticsearch does not refuse an upper-case alias here: `_search` uses
    # `ignore_unavailable=true`, so it silently returns zero hits.
    if part != part.lower():
        raise ViewNameError(
            f"{origin} carries upper case, which an index or alias name cannot hold — a view "
            "named above the case rule is not refused by the cluster, it is answered with an "
            "empty result, so the world would read as one that changed nothing")
    return part


def refuse_unnameable_world(world_id: str) -> str:
    """`world_id`, or the `ViewNameError` every view built from it would raise — for callers
    holding a world but no corpus pattern yet, so a bad id fails once rather than per call.
    """
    return _nameable_world(world_id)


def _nameable_world(world_id: str) -> str:
    """`world_id`, held to the alias name rule plus one more: no `-`.

    `-` delimits `wv-{id}-{stem}`, so an id containing it makes one world's view name parse as
    another's (`a-logs-nginx`'s view of `logs-*` reads as world `a`'s view of
    `logs-nginx-logs-*`).
    """
    world = _nameable(world_id, f"world id {world_id!r}")
    if "-" in world:
        raise ViewNameError(
            f"world id {world_id!r} carries '-', which a view name uses to separate the id "
            "from the corpus it stages — an id holding the delimiter makes one view name "
            "readable as another world's, so the boundary between siblings stops holding")
    return world


def is_world_view(index: str, configured_patterns: Iterable[str], world_id: str) -> bool:
    """Is `index` a name `world_id` may read in place of a corpus it configures?

    Two conditions: the name carries this world's prefix (`wv-b-…` is out of bounds in A), and
    its stem is a corpus the base run could itself reach, so `wv-a-other` is refused.

    Not an enumeration of `world_view(p, world_id)` over configured patterns: the stager derives
    views from the index the call named, which may be narrower (`logs-system.auth-*` under
    `logs-*`), and those must be admitted too. The stem is held to `_reach_ok`, the rule every
    unstaged name gets, rather than a bare prefix test (which would admit `wv-a-logsecret`).
    The `==` arm admits the view of the configured pattern itself (`wv-a-logs-`), which
    `_reach_ok` alone does not.

    The world id is matched as a whole segment; `_nameable_world` bars `-` inside one so this
    parse is unambiguous.
    """
    namespace, _, rest = index.partition("-")
    head, _, stem = rest.partition("-")
    # The namespace must be checked, or `evil-a-logs-nginx` would parse as world `a`'s view.
    if namespace != VIEW_NAMESPACE or head != world_id or not stem:
        return False
    return any(
        _view_stem(p) and (stem == _view_stem(p) or _reach_ok(stem, p))
        for p in configured_patterns
    )


# the host-state program+target confinement


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
    """Both halves of the host-state rule: the program against the allowlist, and the container
    target against the declared inventory (`cat` inside the ticket store would pass the program
    check alone)."""
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
    "VIEW_NAMESPACE",
    "ReadEndpointAllowlist",
    "TransportCapture",
    "ViewNameError",
    "confine_host",
    "confine_host_state_call",
    "confine_index",
    "confine_read_endpoint",
    "guard_outbound",
    "is_world_view",
    "refuse_unnameable_world",
    "normalize_endpoint",
    "world_view",
]
