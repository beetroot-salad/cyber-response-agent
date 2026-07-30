"""The per-role verb grant: an enumerated `(system, verb, verb_class)` allowance (#632).

A `VerbGrant` is authored data, not a filter derived from the registry — see the design's
census (c18) for why. It is frozen and hashable so it can live on `AgentDefinition` beside
`bash_shapes`, and it validates its own contents at construction (a bad class token, or one
`(system, verb)` declared twice with conflicting classes) rather than at first use — the
grant's authoring-integrity guarantee, matched by the read-endpoint allowlist's own
constructor (`scripts/adapters/confinement.py`).
"""
from __future__ import annotations

from dataclasses import dataclass, field

VERB_CLASSES: frozenset[str] = frozenset({"r", "rw"})


class GrantError(Exception):
    """Raised for a verb_grant authoring defect, or a decision that fails closed."""


@dataclass(frozen=True)
class VerbGrant:

    role: str
    entries: tuple[tuple[str, str, str], ...] = ()
    _by_pair: dict[tuple[str, str], str] = field(
        default_factory=dict, init=False, repr=False, compare=False, hash=False,
    )

    def __post_init__(self) -> None:
        by_pair: dict[tuple[str, str], str] = {}
        for system, verb, verb_class in self.entries:
            if verb_class not in VERB_CLASSES:
                raise GrantError(
                    f"verb_grant for role {self.role!r} names {system}.{verb} with class "
                    f"{verb_class!r}, outside the closed vocabulary {sorted(VERB_CLASSES)}"
                )
            pair = (system, verb)
            existing = by_pair.get(pair)
            if existing is not None and existing != verb_class:
                raise GrantError(
                    f"verb_grant for role {self.role!r} declares {system}.{verb} twice with "
                    f"conflicting classes ({existing!r} and {verb_class!r})"
                )
            by_pair[pair] = verb_class
        object.__setattr__(self, "_by_pair", by_pair)

    def allows(self, system: str, verb: str) -> bool:
        return (system, verb) in self._by_pair

    def class_of(self, system: str, verb: str) -> str | None:
        return self._by_pair.get((system, verb))

    @property
    def systems(self) -> frozenset[str]:
        return frozenset(s for s, _ in self._by_pair)

    def __hash__(self) -> int:  # entries alone determine identity; the derived index does not
        return hash((self.role, self.entries))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, VerbGrant):
            return NotImplemented
        return self.role == other.role and self.entries == other.entries


DENY_ALL = VerbGrant(role="", entries=())


__all__ = ["DENY_ALL", "VERB_CLASSES", "GrantError", "VerbGrant"]
