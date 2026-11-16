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


#: Characters the URL parser treats specially (B3's browser sample takes one near miss for each).
SPECIALS = "?#%\\\t\n./"


def has_special(case: GeneratedCase, special: str) -> bool:
    """`case` carries `special` where its origin does not. Every origin holds `/`, so for `/` the edit is a doubled one:
    more `//` than the origin has."""
    assert case.origin is not None
    if special == "/":
        return case.value.count("//") > case.origin.count("//")
    return special in case.value and special not in case.origin


def special_picks(cases: list[GeneratedCase], seed: int, taken: list[GeneratedCase]) -> list[GeneratedCase]:
    """One near miss per `SPECIALS` character, seeded, none already in `taken`."""
    rng = random.Random(seed)
    picks: list[GeneratedCase] = []
    for special in SPECIALS:
        pool = [c for c in cases if c.origin and has_special(c, special) and c not in taken and c not in picks]
        picks.append(rng.choice(pool))
    return picks


#: The uuid placeholder in the address file's own format: pieces over the `hex` alphabet (no regex in the file).
UUID_PIECES = [["hex", 8], "-", ["hex", 4], "-", ["hex", 4], "-", ["hex", 4], "-", ["hex", 12]]
HEX = "0123456789abcdef"


def _listed(placeholders: object = None, shapes: object = None, alphabets: object = None) -> dict[str, object]:
    base_shapes = [{"name": "root", "template": "/", "returnable": True},
                   {"name": "investigation", "template": "/t/{uuid}/investigations/{uuid}", "returnable": True},
                   {"name": "sign-in-failed", "template": "/sign-in-failed", "returnable": False}]
    return {"alphabets": {"hex": HEX} if alphabets is None else alphabets,
            "placeholders": {"uuid": UUID_PIECES} if placeholders is None else placeholders,
            "shapes": base_shapes if shapes is None else shapes}


def _with_shape(**shape: object) -> dict[str, object]:
    document = _listed()
    return {**document, "shapes": [*document["shapes"], shape]}  # type: ignore[misc]


#: Shape lists both readers refuse, the API's (`addresses._compile`) and the frontend's build (S2): `(id, document,
#: words the refusal holds)`. One table, so the two readers cannot drift apart unnoticed.
REFUSED: tuple[tuple[str, dict[str, object], str], ...] = (
    *((f"pieces {p!r}", _listed({"uuid": p}), "placeholder uuid") for p in (
        "[0-9a-f]+",  # the retired regex form
        [], [["hex", 0]], [["hex", 5, 2]], [["hex", -1]], [["hex", 1.5]], [["hex", True]], [["hex", "8"]], [["hex"]],
        [["hex", 1, 2, 3]], [["nope", 8]], [[["hex"], 8]], ["a/b"], ["a.b"], [""], [7], [None])),
    ("alphabet with a slash", _listed(alphabets={"hex": "0123456789abcdef/"}), "alphabet hex"),
    ("alphabet with a dot", _listed(alphabets={"hex": "0123456789abcdef."}), "alphabet hex"),
    ("empty alphabet", _listed(alphabets={"hex": ""}), "alphabet hex"),
    ("no alphabets", {"placeholders": {}, "shapes": []}, "must hold `alphabets`"),
    ("no placeholders", {"shapes": []}, "must hold"),
    ("shape without returnable", _with_shape(name="x", template="/x"), "a shape needs"),
    ("duplicate name", _with_shape(name="root", template="/again", returnable=True), "duplicate shape name root"),
    ("no leading slash", _with_shape(name="x", template="x/{uuid}", returnable=True), "does not start with /"),
    ("unknown placeholder", _with_shape(name="x", template="/x/{nope}", returnable=True), "unknown placeholder nope"),
    ("brace in a literal", _with_shape(name="x", template="/a{b", returnable=True), "bad literal segment"),
    ("non-ASCII literal", _with_shape(name="x", template="/é", returnable=True), "bad literal segment"),
)
