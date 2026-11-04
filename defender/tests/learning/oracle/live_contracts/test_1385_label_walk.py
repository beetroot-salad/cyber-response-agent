"""The ledger label of a changed answer, over a generated family of facts, claims and cuts (#1385 A1).

One test, many inputs: a verified answer that differs from the live base is `oracle` when the
difference shows the world's facts, `reconstructed` when it does not, `passthrough` when it is
the base. The inputs are generated from a seed and defined by membership in the class (facts of
several entities; removed, changed and dropped entries of any nesting), never by an attacker's
particular instance. The expected label comes from a reference walk written here, apart from the
code under test.
"""
from __future__ import annotations

import json
import random
import types
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from defender.learning.branch.estate.checks import ReAsked  # noqa: E402
from defender.learning.branch.estate.registry import served_label  # noqa: E402
from defender.tests.learning.oracle.live_contracts import _spec1224 as S  # noqa: E402

RECONSTRUCTED = "reconstructed"
SEED = 1385
CASES = 600

#: Names a fact can have in this family. Every filler below is distinct from each of them, is no
#: substring of one, and no case variant of one.
ENTITIES = ("alice", "db-1", "10.0.0.9", "carol", "bob", "svc-backup-01", "web-1", "ghost-7",
            "Mallory", "x")
FILLERS = ("dan", "e-100", "logon", "kinit", "web-9", "10.9.9.9", "erin", "job-77", "tgt", "zed")
KEYS = ("user", "detail", "session", "actor", "tags", "who", "meta", "ctx")


def _canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str)


# --------------------------------------------------------------------------------------
# The reference: what the label should be, from the generated case alone.
# --------------------------------------------------------------------------------------


def _strings(value: Any) -> list[str]:
    """Every string value at any depth (a mapping's keys are not values)."""
    found: list[str] = []
    stack = [value]
    while stack:
        node = stack.pop()
        if isinstance(node, str):
            found.append(node)
        elif isinstance(node, Mapping):
            stack.extend(node.values())
        elif isinstance(node, (list, tuple)):
            stack.extend(node)
    return found


def _expected(case: _Case) -> str:
    if _canonical(case.served) == _canonical(case.base):
        return S.PASSTHROUGH
    names = {n for fact in case.facts for n in _entities_of(fact)}
    if not names:
        return RECONSTRUCTED
    if case.claim["added"]:
        return S.ORACLE_DECISION
    if any(isinstance(e["entity"], str) and e["entity"] in names for e in case.claim["changed"]):
        return S.ORACLE_DECISION
    if any(s in names for e in case.claim["removed"] for s in _strings(e["row"])):
        return S.ORACLE_DECISION
    if any(s in names for row in case.dropped for s in _strings(row)):
        return S.ORACLE_DECISION
    return RECONSTRUCTED


def _entities_of(fact: Any) -> list[str]:
    raw = fact["entities"] if isinstance(fact, dict) else fact.entities
    return [str(e) for e in raw]


# --------------------------------------------------------------------------------------
# The generator.
# --------------------------------------------------------------------------------------


@dataclass
class _Case:
    facts: list[Any]
    base: Any
    served: Any
    claim: dict
    re_asked: ReAsked | None
    #: Rows the live base has that the re-asked answer lacks (what the cut dropped), by
    #: construction.
    dropped: list[Any]
    #: What the case planted, for the coverage count: (site, kind, index of entry, index of
    #: fact, index of entity, nesting, shape).
    plan: tuple = ()


def _near(rng: random.Random, entity: str, names: set[str]) -> str:
    """A string that is not any entity but resembles `entity`: a substring, a superstring, a
    case variant or the empty string."""
    options = ["", entity + "-admin", "x" + entity]
    if len(entity) > 1:
        options += [entity[:-1], entity[1:]]
    if entity.swapcase() != entity:
        options += [entity.swapcase(), entity.upper() if entity.upper() != entity else entity.lower()]
    options = [o for o in options if o not in names]
    return rng.choice(options)


def _filler(rng: random.Random) -> str:
    return rng.choice(FILLERS)


def _decoy(rng: random.Random) -> Any:
    return rng.choice([_filler(rng), rng.randint(0, 9), None, True, {"k": _filler(rng)},
                       [_filler(rng)]])


def _embed(rng: random.Random, leaf: Any, depth: int) -> tuple[Any, tuple[str, ...]]:
    """`leaf` inside `depth` containers (mappings and lists, in any order, with decoy siblings),
    and the chain of container kinds from the outside in."""
    node, chain = leaf, []
    for _ in range(depth):
        if rng.random() < 0.5:
            node = {rng.choice(KEYS): node,
                    **{f"o{i}": _decoy(rng) for i in range(rng.randint(0, 2))}}
            chain.append("dict")
        else:
            items = [node, *(_decoy(rng) for _ in range(rng.randint(0, 2)))]
            rng.shuffle(items)
            node = items
            chain.append("list")
    return node, tuple(reversed(chain))


ESQL_COLUMNS = [{"name": "event_id", "type": "keyword"}, {"name": "action", "type": "keyword"},
                {"name": "host", "type": "keyword"}, {"name": "detail", "type": "keyword"}]


class _Rows:
    """Row factory of one case: every row of a page shares its columns and two of its values (so
    a row replaced by another reads as an edit of it to a pairing rule), and has an id of its
    own."""

    def __init__(self, rng: random.Random, serial: int, esql: bool) -> None:
        self.rng, self.esql, self.serial = rng, esql, serial * 1000

    def row(self, planted: str | None, depth: int) -> tuple[Any, tuple[str, ...]]:
        self.serial += 1
        cell, chain = _embed(self.rng, _filler(self.rng) if planted is None else planted, depth)
        ident = f"ev-{self.serial}"
        if self.esql:
            return [ident, "logon", "gw-1", cell], chain
        return {"event_id": ident, "action": "logon", "host": "gw-1", "detail": cell}, chain

    def removed(self, planted: str | None, depth: int) -> tuple[Any, tuple[str, ...]]:
        """A removed entry's row: a table row, or any other nesting a claim could quote."""
        inner, chain = _embed(self.rng, _filler(self.rng) if planted is None else planted, depth)
        pick = self.rng.randrange(4)
        if pick == 0:
            return self.row(planted, depth)
        if pick == 1:
            return {"id": "r", "x": inner}, ("dict", *chain)
        if pick == 2:
            return [_filler(self.rng), inner], ("list", *chain)
        return [[inner, _filler(self.rng)], [_filler(self.rng)]], ("list", "list", *chain)


def _page(esql: bool, rows: list[Any]) -> dict:
    return {"columns": ESQL_COLUMNS, "values": rows} if esql else {"rows": rows}


def _facts(rng: random.Random) -> tuple[list[Any], list[list[str]]]:
    """k facts of m entities each (m may be 0), as objects or as mappings, and their entities."""
    pool = list(ENTITIES)
    rng.shuffle(pool)
    entities: list[list[str]] = []
    for _ in range(rng.choice([0, 1, 2, 2, 3, 4])):
        size = 0 if rng.random() < 0.1 else rng.randint(1, 3)
        entities.append(pool[:size])
        pool = pool[size:]
    facts = [types.SimpleNamespace(fact_id=f"f{i}", entities=tuple(es)) if i % 2 == 0
             else {"fact_id": f"f{i}", "entities": list(es)}
             for i, es in enumerate(entities)]
    return facts, entities


def _case(rng: random.Random, serial: int) -> _Case:  # noqa: C901 — one generator, one arm per site
    facts, facts_entities = _facts(rng)
    names = {e for es in facts_entities for e in es}
    named = [(i, j, e) for i, es in enumerate(facts_entities) for j, e in enumerate(es)]

    # What the case plants, where: an exact entity, a near miss, or nothing.
    site = rng.choice(["changed", "removed", "dropped", "none"])
    mode = "none" if site == "none" else rng.choice(["exact", "exact", "near", "none"])
    if mode == "exact" and not named:
        mode = "near"
    fact_i = ent_j = -1
    target: str | None = None
    if mode == "exact":
        fact_i, ent_j, target = rng.choice(named)
    elif mode == "near":
        target = _near(rng, rng.choice(named)[2] if named else "alice", names)

    esql = rng.random() < 0.35
    rows = _Rows(rng, serial, esql)
    count = {kind: rng.randint(1, 4) if kind == site else rng.randint(0, 2)
             for kind in ("changed", "removed", "dropped")}
    at = {kind: rng.randrange(max(n, 1)) for kind, n in count.items()}
    index = nest = -1
    chain: tuple[str, ...] = ()

    changed: list[dict] = []
    for n in range(count["changed"]):
        here = target if (site == "changed" and n == at["changed"]) else None
        # An entity's name in the other cells of the entry is no entity of it.
        other = rng.choice(sorted(names)) if names and rng.random() < 0.3 else _filler(rng)
        entity: Any = here if here is not None else rng.choice([_filler(rng), _filler(rng), 7, None])
        changed.append({"entity": entity, "field": other, "old": other, "new": other})
        index = n if here is not None else index
    removed: list[dict] = []
    for n in range(count["removed"]):
        here = target if (site == "removed" and n == at["removed"]) else None
        depth = rng.randint(1, 4)
        row, row_chain = rows.removed(here, depth)
        removed.append({"row": row, "side_query": {"system": "idp", "verb": "query", "params": {}},
                        "count": 1})
        if here is not None:
            index, nest, chain = n, depth, row_chain
    dropped: list[Any] = []
    for n in range(count["dropped"]):
        here = target if (site == "dropped" and n == at["dropped"]) else None
        depth = rng.randint(1, 4)
        row, row_chain = rows.row(here, depth)
        dropped.append(row)
        if here is not None:
            index, nest, chain = n, depth, row_chain

    # The cut: the live page is the shared rows with the dropped ones among them; the re-asked
    # page the shared rows with the older ones the cut brings in (an entity of a fact in them
    # counts for nothing).
    replace_all = bool(dropped) and rng.random() < 0.4
    shared = [] if replace_all else [rows.row(None, 1)[0] for _ in range(rng.randint(0, 3))]
    brought = [rows.row(rng.choice(sorted(names)) if names and rng.random() < 0.3 else None,
                        rng.randint(1, 3))[0] for _ in range(rng.randint(1 if replace_all else 0, 3))]
    cut = bool(dropped) or rng.random() < 0.5
    live, older = list(shared), list(shared)
    for row in dropped:
        live.insert(rng.randint(0, len(live)), row)
    for row in brought:
        older.insert(rng.randint(0, len(older)), row)
    if cut:
        base = _page(esql, live)
        re_asked = ReAsked("idp", "query", {"q": "bounded", "serial": serial}, _page(esql, older))
        served = re_asked.answer
    else:
        dropped = []
        base = {"rows": [{"event_id": f"base-{serial}"}]}
        re_asked = None
        served = {**base, "edited": True}
    if rng.random() < 0.05:
        served = base
    claim = {"added": [{"forged_id": "fg-1", "fact_id": "f0"}] if rng.random() < 0.08 else [],
             "removed": removed, "changed": changed, "counts": [], "entity_refs": []}
    return _Case(facts, base, served, claim, re_asked, dropped,
                 plan=(site, mode, index, fact_i, ent_j, nest, chain, esql, replace_all))


def test_1385_the_label_follows_what_the_difference_shows_of_the_worlds_facts():
    """For generated facts, claims and cuts the label is `passthrough` for the base, `oracle` when
    a forged row, a `changed` entry on a fact entity, or a removed or dropped row with a string
    equal to a fact entity (at any depth) is shown, else `reconstructed`; a near miss (substring,
    superstring, case variant, empty) never counts, nor does a world without facts (T2, A1)."""
    rng = random.Random(SEED)
    cases = [_case(rng, n) for n in range(CASES)]
    seen: Counter[str] = Counter()
    wrong: list[str] = []
    for n, case in enumerate(cases):
        got = served_label(case.base, case.served, case.claim, case.facts, case.re_asked)
        want = _expected(case)
        site, mode, index, fact_i, ent_j, nest, chain, esql, replace_all = case.plan
        if want == S.ORACLE_DECISION:
            seen[f"oracle:{site}:{mode}"] += 1
            if mode == "exact":
                seen[f"exact-entry-{'first' if index == 0 else 'later'}"] += 1
                seen[f"exact-fact-{'first' if fact_i == 0 else 'later'}"] += 1
                seen[f"exact-entity-{'first' if ent_j == 0 else 'later'}"] += 1
                if "list" in chain and any(a == b == "list" for a, b in zip(chain, chain[1:], strict=False)):
                    seen["exact-list-in-list"] += 1
                if site == "removed" and esql:
                    seen["exact-removed-esql"] += 1
                if site == "removed" and nest >= 2:
                    seen["exact-removed-nested"] += 1
                if site == "dropped" and replace_all:
                    seen["exact-dropped-whole-page"] += 1
        elif mode == "near":
            seen[f"near:{site}"] += 1
        if got != want:
            wrong.append(f"case {n}: label {got!r}, expected {want!r}; plan={case.plan}; "
                         f"facts={[_entities_of(f) for f in case.facts]}; claim={case.claim}; "
                         f"dropped={case.dropped}")
    assert not wrong, f"{len(wrong)} of {CASES} labels differ from the reference:\n" + "\n".join(wrong[:3])
    # The generated family reaches every kind of site a wrong rule could hide in.
    needed = ["oracle:changed:exact", "oracle:removed:exact", "oracle:dropped:exact",
              "near:changed", "near:removed", "near:dropped", "exact-entry-later",
              "exact-fact-later", "exact-entity-later", "exact-list-in-list",
              "exact-removed-esql", "exact-removed-nested", "exact-dropped-whole-page"]
    thin = {name: seen[name] for name in needed if seen[name] < 5}
    assert not thin, f"the generated cases leave these kinds thin: {thin}"
