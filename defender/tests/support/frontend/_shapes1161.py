"""#1161 piece 1, test-only: S2's piece-1 shapes as the test writes them, a seeded member generator for each, B3's
near-miss generator, and a classifier from the shape text alone (shape name or None), never from code under test.

Membership (S2): the whole string matches a shape, ASCII, case-sensitive, no decoding, normalising or trailing-`/`
tolerance. A near miss may well be a member (a hex digit replaced by another is); consumers take the classifier's
answer with the value (`GeneratedCase`), never "near miss means refused"."""
from __future__ import annotations

import dataclasses
import random
import re
from collections.abc import Iterator

#: The `uuid` placeholder's grammar, written out here (S2: ASCII classes and counted repetition only).
UUID = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"


@dataclasses.dataclass(frozen=True)
class Shape:
    name: str
    template: str  # `/`-separated segments; `{uuid}` is a typed placeholder within one segment
    returnable: bool

    @property
    def pattern(self) -> re.Pattern[str]:
        return re.compile(re.escape(self.template).replace(re.escape("{uuid}"), UUID))


#: Piece 1's shapes (S2). Piece 2 adds the opener.
SHAPES = (
    Shape("root", "/", True),
    Shape("investigation", "/t/{uuid}/investigations/{uuid}", True),
    Shape("sign-in-failed", "/sign-in-failed", False),
)
RETURNABLE = frozenset(s.name for s in SHAPES if s.returnable)


def classify(value: str, shapes: tuple[Shape, ...] = SHAPES) -> str | None:
    """The name of the shape `value` is a member of, else None."""
    found = [s.name for s in shapes if s.pattern.fullmatch(value)]
    assert len(found) <= 1, (value, found)
    return found[0] if found else None


def uuid_text(rng: random.Random) -> str:
    h = "".join(rng.choice("0123456789abcdef") for _ in range(32))
    return f"{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:]}"


def member(shape: Shape, rng: random.Random) -> str:
    """One member of `shape`, from `rng`."""
    out, rest = [], shape.template
    while "{uuid}" in rest:
        before, rest = rest.split("{uuid}", 1)
        out += [before, uuid_text(rng)]
    return "".join(out) + rest


def members(shape: Shape, seed: int, count: int) -> list[str]:
    rng = random.Random(f"{seed}/{shape.name}")
    return [member(shape, rng) for _ in range(count)]


#: B3's edit alphabet: every ASCII character, and a fixed handful beyond: a non-ASCII digit (Arabic-Indic three),
#: characters whose Unicode case mapping folds to ASCII letters that occur in the shapes (long s -> `s`, dotless i
#: -> `I`, Kelvin -> `k`), and a fullwidth `/`.
ALPHABET = tuple(chr(c) for c in range(0x80)) + ("\u0663", "\u017f", "\u0131", "\u212a", "\uff0f")


def near_misses(value: str) -> Iterator[str]:
    """B3's near misses of the member `value`, without repeats and without `value` itself: every single-character
    insert, replace and delete over `ALPHABET`; each letter's case flipped; each `/` doubled; one `/` appended."""
    seen = {value}

    def fresh(candidate: str) -> Iterator[str]:
        if candidate not in seen:
            seen.add(candidate)
            yield candidate

    for i in range(len(value) + 1):
        for ch in ALPHABET:
            yield from fresh(value[:i] + ch + value[i:])
    for i in range(len(value)):
        yield from fresh(value[:i] + value[i + 1:])
        for ch in ALPHABET:
            yield from fresh(value[:i] + ch + value[i + 1:])
        if value[i].isalpha():
            yield from fresh(value[:i] + value[i].swapcase() + value[i + 1:])
        if value[i] == "/":
            yield from fresh(value[:i] + "//" + value[i + 1:])
    yield from fresh(value + "/")


@dataclasses.dataclass(frozen=True)
class GeneratedCase:
    """A value of the generated set, the classifier's answer for it, and the member it was made from (None: it is one)."""
    value: str
    shape: str | None
    origin: str | None

    @property
    def returnable(self) -> bool:
        return self.shape in RETURNABLE


def generated_set(seed: int = 1161, per_shape: int = 2) -> list[GeneratedCase]:
    """B3's one generated set: `per_shape` members of every shape, and every near miss of each; deduplicated."""
    cases: dict[str, GeneratedCase] = {}
    for shape in SHAPES:
        for m in members(shape, seed, per_shape):
            cases.setdefault(m, GeneratedCase(m, classify(m), None))
            for miss in near_misses(m):
                cases.setdefault(miss, GeneratedCase(miss, classify(miss), m))
    return list(cases.values())


def sample(cases: list[GeneratedCase], seed: int, count: int) -> list[GeneratedCase]:
    """A seeded sample for the browser check that keeps at least one member of each shape and one non-member."""
    rng = random.Random(seed)
    picked = [rng.choice([c for c in cases if c.shape == s.name]) for s in SHAPES]
    picked.append(rng.choice([c for c in cases if c.shape is None]))
    rest = [c for c in cases if c not in picked]
    return picked + rng.sample(rest, count - len(picked))
