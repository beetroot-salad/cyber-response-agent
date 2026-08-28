"""Target fidelity (D3/D4): a verb cannot be aimed outside the system it is declared under.

Two rule forms — an HTTP read-endpoint allowlist for the URL-shaped adapters, and a
program+container-target pair for host-state, which has no URL — plus the transport capture
seam the endpoint rule is checked through and the allowlist's authoring-integrity constructor.
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


# the read-endpoint allowlist


class ReadEndpointAllowlist(Mapping):
    """A validating `Mapping[system, tuple[(endpoint_pattern, method), ...]]`. Refuses at
    AUTHORING time an entry naming no HTTP method (§7 F1) — the method is what separates the
    ticket store's read from its write on the identical resolved path."""

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


# the transport capture seam


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


def guard_outbound(ctx: Any, system: str, url: str, *, method: str) -> None:
    """Confine, then record — the ONE thing every outbound HTTP path does before opening a
    connection. Both transports (the shared stub transport and elastic's own helper) call this
    rather than restating the pair, so a third transport cannot half-adopt the seam."""
    confine_read_endpoint(system, url, method=method, verb_class="r")
    capture = getattr(ctx, "capture", None)
    if capture is not None:
        capture.record(system=system, url=url, method=method)


# the elastic index (D3) confinement


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
    """Refuse an index expression whose REACH falls outside every configured pattern — never
    the literal string. Evaluates Elasticsearch's own grammar (a comma-list, `*`, a leading
    `-` exclusion) and refuses the WHOLE call rather than silently narrowing to the in-bounds
    part (§7 R5).

    `world_id` DECLARES this call's world views in bounds, and nothing else about them. A
    branched world reads a private view of the corpus rather than the corpus, and that view is
    named OUTSIDE the pattern it stages on purpose (see `world_view`) — so without a
    declaration the staged read is refused as out of bounds, and with one the admissible names
    are `is_world_view`'s: per world, so a model naming `wv-b-logs` in A is still refused, and
    inside the configured corpora, so the world moves which NAME is admissible and never which
    corpus is.
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

#: Characters an Elasticsearch index or alias name cannot carry. Whitespace is checked
#: separately (`str.isspace`), so this names only the punctuation. `:` is NOT here: it is
#: illegal inside a name but legal in the expression `remote:logs-*`, which addresses a
#: cross-cluster source and prefixes correctly.
_ILLEGAL_IN_NAME = frozenset('\\/*?"<>|,')

#: The namespace every world view lives in. A PREFIX, and that is the whole point: a view
#: suffixed onto its own corpus (`logs-*` -> `logs-w-a`) is still matched BY `logs-*`, so the
#: base run and every sibling that does not stage the event stream read each other's staged
#: documents through the pattern they were derived from — the pair measuring contamination
#: rather than a difference, which is the one thing the per-world view exists to prevent.
#: Prefixed, no configured pattern reaches it, and `world_view` proves that per name.
VIEW_NAMESPACE = "wv"


class ViewNameError(ValueError):
    """A corpus pattern that cannot carry a world view.

    A plain `ValueError`, NOT a `ConfinementFault`: naming is not confinement, and the caller
    that builds views (the branch stager) owns how a refusal reaches the model — it wraps this
    in its own usage-class fault so the refusal lands in the ledger as evidence.
    """


def world_view(base_pattern: str, world_id: str) -> str:
    """The alias `world_id`'s queries read in place of `base_pattern`.

    Per WORLD, never shared: siblings reading one view would see each other's staged
    documents. And OUTSIDE the pattern it was derived from, which is the half a per-world
    name alone does not buy — see `VIEW_NAMESPACE`.

    The stem must be a NAME an alias can carry, and three degenerate patterns are not. `*`
    trims to the empty string, so there is nothing left to name the corpus by and every
    pattern would collapse to one view. A pattern wildcarded anywhere but the tail
    (`logs-*-2026`) keeps its `*` inside the derived name, which no alias answers to. The
    third is what a quoted source leaves behind: a source only NEEDS quoting when its name
    carries something a bare token cannot — a space, a `|` — and the view is written back
    UNQUOTED, because a view is a name this function constructs and `"logs-*"-wv` answers to
    nothing. `FROM "logs|weird"` would come back with the `|` reading as a command separator,
    cutting the query in half one step after the quote-aware splitter read it correctly.

    The WORLD ID is held to the same rule as the stem, for the same reason and one step
    earlier: it is authored per run and reaches this name unfiltered, and a `*` or a space in
    it corrupts every view the run stages rather than one.

    All of them are refused rather than guessed: a view nobody reads runs the sibling green
    against the BASE corpus while reporting a world that was never applied.

    And the disjointness is CHECKED, not assumed. The prefix buys it for every pattern that
    names a corpus, but a pattern reaching into the namespace itself (`wv-*`) takes it back,
    and the whole reason this function is not a format string is that the property is what
    matters rather than the spelling. Checked against the pattern the view was derived from —
    the one this function is given, and the one the contamination runs through, since it is
    the base run and the unstaged siblings reading THAT pattern who would collect this world's
    documents.
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
    """The corpus half of a view name: `pattern` with its trailing wildcard and separator gone.

    ONE spelling, because `world_view` BUILDS a name with it and `is_world_view` READS one back;
    two would drift into a boundary that refuses the names the stager constructs.

    THE WILDCARD ONLY. Trimming the separator too — `.removesuffix("-").removesuffix(".")` —
    still collapsed `logs-*`, `logs.*` and `logs*` onto the single stem `logs`, so three
    distinct corpora shared one alias and one ledger memo key: a world staging two of them
    into one view, and a query for the narrow corpus reading the wide one's documents. (The
    `rstrip` this replaced was worse again — a CHARACTER SET, so `logs---*` and `logs-**` went
    the same way.) Keeping the separator, `wv-a-logs-` and `wv-a-logs.` are two names, which is
    what two corpora need. A trailing `-` or `.` is legal in an index or alias name; only a
    LEADING one is not, and the namespace prefix means no view ever starts with either.

    What is left un-trimmed is refused rather than guessed: `logs-**` keeps its `*` and
    `_nameable` says so, which is the honest answer to a pattern this naming cannot carry.
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
    # LOWER CASE IS PART OF THE NAME RULE, and its failure is the silent one: an alias
    # Elasticsearch cannot hold is not refused here, it is READ — `_search` appends
    # `ignore_unavailable=true`, so `wv-A-logs` comes back 200 with zero hits and the sibling
    # loses that evidence class while every ledger row reads honestly. Refused where the name
    # is built, which is the only frame that can say what to rename.
    if part != part.lower():
        raise ViewNameError(
            f"{origin} carries upper case, which an index or alias name cannot hold — a view "
            "named above the case rule is not refused by the cluster, it is answered with an "
            "empty result, so the world would read as one that changed nothing")
    return part


def refuse_unnameable_world(world_id: str) -> str:
    """`world_id`, or the `ViewNameError` every view built from it would have raised.

    The world-id half of `world_view`'s naming rule, asked WITHOUT a corpus pattern, so a caller
    holding a world and no call yet can refuse it. It is the same rule and therefore the same
    answer — an id that fails here fails on every pattern, so the alternative to asking early is
    asking once per served call and losing the whole event stream to a name.
    """
    return _nameable_world(world_id)


def _nameable_world(world_id: str) -> str:
    """`world_id`, held to the alias name rule AND to the one extra rule an id has.

    NO `-`, because the delimiter cannot also be data. `wv-{id}-{stem}` is written by
    `world_view` and read back by `is_world_view`, and an id carrying the delimiter makes that
    parse ambiguous in the direction that matters: world `a-logs-nginx`'s view of `logs-*` is
    `wv-a-logs-nginx-logs-`, which reads equally well as world `a`'s view of `logs-nginx-logs-*`
    — so the boundary hands A a name B staged. Refused here, where an id can still be renamed,
    rather than resolved by a parse that has to guess.
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

    TWO conditions, and the second is what an enumeration got wrong. The name has to carry THIS
    world's prefix — sibling B's `wv-b-…` stays out of bounds inside A — and its corpus stem has
    to be a corpus the base run could itself have reached, so a view of a corpus this run never
    configured (`wv-a-other`) is still refused: the world moves which NAME is admissible, never
    which corpus is.

    Enumerating `world_view(p, world_id)` for each configured `p` was the same test for the
    exact patterns and WRONG for every narrower one. The stager derives its view from the index
    the CALL named, not from the configured pattern — a shipped template scoping to one data
    stream (`logs-system.auth-*` under a `logs-*` corpus) staged to `wv-a-logs-system.auth`,
    which an enumeration of the configured patterns does not contain. The base run answered that
    call by reach and every sibling faulted at this boundary: a base-vs-sibling difference owned
    by the harness rather than the world, which is the one kind this seam must never create.

    The stem is held to `_reach_ok` — the SAME rule every unstaged name is held to — and not to
    a bare `startswith` of the pattern's stem. `_view_stem` drops the separator (`logs-*` ->
    `logs`), so a prefix test admitted `wv-a-logsecret`: a view of `logsecret-*`, a corpus the
    base run refuses outright. That widened D3 for exactly the calls a branched run makes, which
    is the opposite of this function's claim. The `==` arm is what keeps the view of the
    configured pattern ITSELF admissible: `world_view("logs-*", "a")` is `wv-a-logs-`, whose
    stem is the pattern's own stem and which `_reach_ok` does not admit (nothing reaches
    `logs-*` without something after the separator).

    The world id is matched as a WHOLE SEGMENT, which is why `refuse_unnameable_world` bars a
    `-` inside one. With ids free to carry the delimiter, `wv-{id}-{stem}` does not parse: from
    world `a`, sibling `a-logs-nginx`'s view of `logs-*` reads as prefix `wv-a-` plus stem
    `logs-nginx-logs-`, which `_reach_ok` admits against `logs-*` — so A is handed B's staged
    documents by the boundary built to keep them apart. Segmented, the id either IS this
    world's or is not.
    """
    namespace, _, rest = index.partition("-")
    head, _, stem = rest.partition("-")
    # THE NAMESPACE IS THE FIRST OF THE THREE, and dropping it read the world id off whatever
    # segment happened to be second: `evil-a-logs-nginx` and `*-a-logs-*` both parsed as world
    # `a`'s view of a reachable corpus and were handed back through D3 unrefused. The prefix is
    # what `VIEW_NAMESPACE` calls "the whole point" — every name `world_view` builds carries it,
    # and a name that does not is not a view of anything.
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
    """Both halves of D3's host-state rule: the PROGRAM against the per-system allowlist, and
    the container TARGET against the declared inventory. Neither alone suffices — `cat` inside
    the ticket store is a disclosure the program check alone would allow."""
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
