"""The ledger label of a changed answer, over a generated family of facts, claims and cuts (#1385 A1).

One test, many inputs: a verified answer that differs from the live base is `oracle` when the
difference shows the world's facts, `reconstructed` when it does not, `passthrough` when it is
the base. The inputs are generated from a seed and defined by membership in the class (facts of
several entities; removed, changed and dropped entries of any nesting), never by an attacker's
particular instance. The expected label comes from a reference walk written here, apart from the
code under test.

The re-ask of a live base (#1385): what the host admits, keeps and shows, over families of input.

Each test holds a family by its membership rule and walks every member (generated or seeded and
enumerated here), never an attacker's particular instance. The shared fixtures are the contract
map's: this file adds tests beside them and edits none.

A recorded call is replayed as the source received it (#1385 O7, H6).

The platform stamps a reply's time itself and no layer rewrites a recording: whatever a recorded
payload holds — keys the adapters once wrote (`captured_at`, `drift`, `as_of`) among them, at any
depth — comes back byte for byte.
"""
from __future__ import annotations

import json
import random
import types
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
import re

import pytest

from defender.learning.branch.estate.checks import ReAsked, re_asked as _re_asked  # noqa: E402
from defender.learning.branch.estate.registry import served_label  # noqa: E402
from defender.tests.learning.oracle.live_contracts import _spec1224 as S  # noqa: E402
from defender.tests.learning.oracle.live_contracts import test_1224_host_checks as H  # noqa: E402


pytest.importorskip("pydantic_ai")


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
        re_asked = _re_asked(base, "idp", "query", {"q": "bounded", "serial": serial},
                             _page(esql, older))
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


pytest.importorskip("pydantic_ai")


# --------------------------------------------------------------------------------------
# F4 — what a re-ask must be to be admitted at all.
# --------------------------------------------------------------------------------------

CAPPED = S.query_params("user:alice", limit=2)


BOUNDED = S.query_params("user:alice", end=S.AS_OF, limit=2)


LIVE_BASE = {"rows": [H.POST_ROW, H.BASE_ROW]}


def _valid() -> dict:
    return S.re_asked(system="idp", verb="query", params=BOUNDED)


def _malformed_re_asks(rng: random.Random) -> list[tuple[str, Any]]:
    """Every kind of `re_ask` value that is not exactly a string system, a string verb and a
    params mapping, each a member of the class: the falsy values, a value that is no mapping, every
    way of leaving keys out or adding or renaming them, and every wrong type for a field. (JSON
    `null` is not here: a claim that names no re-ask names none.)"""
    keys = ("system", "verb", "params")
    cases: list[tuple[str, Any]] = [(f"falsy {v!r}", v) for v in ({}, [], False, 0, "")]
    cases += [("a list of the values", ["idp", "query", BOUNDED]), ("a string", "idp query"),
              ("a number", 7), ("true", True), ("a list holding a spec", [_valid()])]
    for dropped in ([k] for k in keys):
        cases.append((f"missing {dropped[0]}", {k: v for k, v in _valid().items()
                                                 if k not in dropped}))
    for kept in keys:
        cases.append((f"only {kept}", {kept: _valid()[kept]}))
    extra_names = ["window", "note", "limit", "end", "reason", "index", "query"]
    extra_values = [0, "x", None, {}, 1.5, [], {"end": S.AS_OF}]
    for name in rng.sample(extra_names, 4):
        cases.append((f"extra key {name}", {**_valid(), name: rng.choice(extra_values)}))
    for key in keys:
        renamed = {("param" if k == key else k): v for k, v in _valid().items()}
        cases.append((f"{key} renamed", renamed))
    for field in ("system", "verb"):
        for wrong in (None, 7, ["idp"], {"name": "idp"}, True):
            cases.append((f"{field} is {wrong!r}", {**_valid(), field: wrong}))
    for wrong in (None, [], "", "end=1", 7, False, [["end", S.AS_OF]]):
        cases.append((f"params is {wrong!r}", {**_valid(), "params": wrong}))
    return cases


def _esql(names: list[str], rows: int, rng: random.Random) -> dict:
    return {"columns": [{"name": n, "type": "keyword"} for n in names],
            "values": [[f"{n}-{rng.randint(10, 99)}" for n in names] for _ in range(rows)]}


def _column_cases(rng: random.Random) -> list[tuple[str, Any, Any]]:
    """`(case, live base, re-asked answer)` for an ES|QL base (with rows, and with none) whose
    re-asked answer changes the column list: the same names in another order, the same count
    under other names, one more, one fewer, and answers that are no ES|QL answer at all."""
    pool = ["@timestamp", "user.name", "host.name", "event.action", "source.ip", "process.name"]
    cases: list[tuple[str, Any, Any]] = []
    for rows in (2, 0):
        names = rng.sample(pool, rng.randint(2, 4))
        base = _esql(names, rows, rng)
        permuted = list(names)
        while permuted == names:
            rng.shuffle(permuted)
        order = [names.index(n) for n in permuted]
        renamed = list(names)
        renamed[rng.randrange(len(names))] = "renamed.field"
        fresh = [n for n in pool if n not in names]
        answers = {
            "permuted": {"columns": [{"name": n, "type": "keyword"} for n in permuted],
                         "values": [[row[i] for i in order] for row in base["values"]]},
            "renamed": _esql(renamed, rows, rng),
            "one more": _esql([*names, rng.choice(fresh)], rows, rng),
            "one fewer": _esql(names[:-1], rows, rng),
            "empty columns": {"columns": [], "values": []},
            "no columns": {"values": [["x"]]},
            "a document": {"rows": [H.BASE_ROW]},
            "an error": {"error": "index_not_found_exception"},
            "a list": [],
        }
        cases += [(f"{kind}, base of {rows} rows", base, answer) for kind, answer in answers.items()]
    return cases


def _refused_scene(tmp_path, base: Any, answer: Any, re_ask: Any, *, unreadable: bool = False):
    """A live capped base, a real system that answers any other question with `answer`, and an
    oracle that re-asks with `re_ask`: `(scene, oracle)`. The oracle then submits the answer the
    re-ask would make its base, then the base honestly."""
    live = [("idp", "query", CAPPED, base)]
    sc = H._scene(tmp_path, live=live)
    sc.est.answer("idp", "query", None, answer)
    if unreadable:
        sc.est.fail("idp", "query", BOUNDED)
    o = S.oracle(S.re_ask(re_ask), S.submit(answer, S.EMPTY_CLAIM), S.submit(base, S.EMPTY_CLAIM))
    return sc, o


def test_1385_a_re_ask_is_admitted_only_whole_and_readable_and_keeps_the_calls_columns(tmp_path):
    """A `re_ask` that is not exactly a string system, a string verb and a params mapping, an ES|QL
    re-ask whose answer lists other columns than the base's (in any order, count or name, whether
    or not the base has rows) and a re-ask the host cannot read are each refused at check 1,
    so the answer it would have made the base is not served; nothing of the refused re-ask is kept
    (T1, O4)."""
    rng = random.Random(SEED)
    members: list[tuple[str, Any, Any, Any, bool]] = [
        (f"re_ask {name}", LIVE_BASE, H.AT_BRANCH, value, False)
        for name, value in _malformed_re_asks(rng)]
    members += [(f"columns: {name}", base, answer, _valid(), False)
                for name, base, answer in _column_cases(rng)]
    members.append(("a re-ask the real system fails", LIVE_BASE, H.AT_BRANCH, _valid(), True))
    assert len(members) >= 50, "the family shrank"

    wrong: list[str] = []
    for n, (name, base, answer, re_ask, unreadable) in enumerate(members):
        sc, o = _refused_scene(tmp_path / f"m{n}", base, answer, re_ask, unreadable=unreadable)
        reg = sc.registry(o, retry_cap=4)
        got = sc.call(reg, "idp", "query", **CAPPED)
        taken = [params for r in sc.rows("base") if (params := r["params"]) != CAPPED]
        try:
            H._assert_re_ask_refused(o)
        except AssertionError:
            wrong.append(f"{name}: the re-ask was not refused")
        if got != base or o.submissions() != 2 or o.overrun:
            wrong.append(f"{name}: served {got!r} after {o.submissions()} submission(s)")
        if taken:
            wrong.append(f"{name}: kept a base answer for {taken}")
        if sc.ledger()[0].get("re_ask") is not None:
            wrong.append(f"{name}: the ledger row records a re-ask")
    assert not wrong, f"{len(wrong)} member(s) were admitted:\n" + "\n".join(wrong[:8])

    # Control: the valid re-ask of the same call, over a base with the columns of an ES|QL
    # answer, is admitted whole.
    sc = H._scene(tmp_path / "control", live=[("idp", "query", CAPPED, H.ES_CAPPED),
                                              ("idp", "query", BOUNDED, H.ES_BOUNDED)])
    o = S.oracle(S.re_ask(_valid()), S.submit(H.ES_BOUNDED, S.EMPTY_CLAIM))
    assert sc.call(sc.registry(o), "idp", "query", **CAPPED) == H.ES_BOUNDED
    H._spent(o)
    assert o.submissions() == 1, "positive control: a valid re-ask was refused"


# --------------------------------------------------------------------------------------
# F2 — the re-asked answer a world keeps as a base, and what that makes real.
# --------------------------------------------------------------------------------------


def _alice(n: int, ts: str) -> dict:
    return {"user": "alice", "event_id": f"e-{n:03d}", "action": "logon", "host": "web-1", "ts": ts}


OLDER_98 = _alice(98, "2026-07-28T12:00:00Z")


OLDER_97 = _alice(97, "2026-07-28T11:00:00Z")


Q1 = S.query_params("user:alice", end=S.AS_OF, limit=3)


Q2 = S.query_params("user:alice", end=S.AS_OF, limit=4)


BOB_CAPPED = S.query_params("user:bob", limit=2)


BOB_ROW = {"user": "bob", "event_id": "e-200", "action": "logon", "host": "web-2",
           "ts": H.TS_BASE}


#: The two ways a cut can go: it drops a row dated after the branch point, or it drops nothing
#: and only brings older rows in. `r1` is the first re-ask's answer, `r2` the second's.
CUTS = {
    "drops a post-branch row": {"live": [H.POST_ROW, H.BASE_ROW],
                                "r1": [H.BASE_ROW, H.OLDER_ROW],
                                "r2": [H.BASE_ROW, H.OLDER_ROW, OLDER_98, OLDER_97]},
    "drops nothing": {"live": [H.BASE_ROW, H.OLDER_ROW],
                      "r1": [H.BASE_ROW, H.OLDER_ROW, OLDER_98],
                      "r2": [H.BASE_ROW, H.OLDER_ROW, OLDER_98, OLDER_97]},
}


def _text(payload: Any) -> str:
    """A payload as the world keeps it: the spelling of what the stub adapter handed back."""
    return json.dumps(payload, sort_keys=True)


def _attempts_reusing_ids(rows: list[dict], base_rows: tuple,
                          re_ask: dict | None = None) -> list[S.Move]:
    """One attempt per real row, each re-asking first when `re_ask` is given: a forged row that
    reuses that row's id."""
    out: list[S.Move] = []
    for i, real in enumerate(rows):
        out += [*([S.re_ask(re_ask)] if re_ask else []),
                *H._honest(f"fg-r{i}", row={**H.FORGED_ROW, "event_id": real["event_id"]},
                           base_rows=base_rows)]
    return out


@pytest.mark.parametrize("cut", list(CUTS))
def test_1385_the_kept_re_asked_base_is_what_the_host_read_and_is_real_data_before_and_after_reload(
        tmp_path, cut):
    """Attempt 1 re-asks and the verifier refuses it; attempt 2 re-asks again with a forged row
    beside the answer. Within an attempt a forged row reusing the id of any row of the re-asked
    answer fails check 3; once the answer commits, the base kept under the re-ask's key is the
    answer the host read for it (not the served answer, not the refused attempt's), kept whether or
    not the cut dropped anything and with forged rows served beside it; and a world reloaded from
    its store still refuses a forged row that reuses the id of any of them (T1, O4, A3)."""
    shape = CUTS[cut]
    live, r1, r2 = shape["live"], shape["r1"], shape["r2"]
    sc = H._scene(tmp_path, live=[("idp", "query", CAPPED, {"rows": live}),
                                  ("idp", "query", Q1, {"rows": r1}),
                                  ("idp", "query", Q2, {"rows": r2}),
                                  ("idp", "query", BOB_CAPPED, {"rows": [BOB_ROW]})])
    ask = S.re_asked(system="idp", verb="query", params=Q2)
    o = S.oracle(
        S.re_ask(S.re_asked(system="idp", verb="query", params=Q1)),
        S.submit({"rows": r1}, S.EMPTY_CLAIM),
        *_attempts_reusing_ids(r2, tuple(r2), ask),
        S.re_ask(ask), *H._honest("fg-1", row=H.FORGED_ROW, base_rows=tuple(r2)))
    v = S.verifier(S.verdict(False, "the first re-ask drops what the question asked for"),
                   then=S.verdict(True))
    reg = sc.registry(o, v, retry_cap=len(r2) + 4)

    served = {"rows": [*r2, H.FORGED_ROW]}
    assert sc.call(reg, "idp", "query", **CAPPED) == served
    H._spent(o)
    H._assert_verdict(o, 1, "verifier")
    for k in range(2, len(r2) + 2):
        H._assert_verdict(o, k, "check 3")
    ledger = sc.ledger()
    assert [r.get("attempts") for r in ledger] == [len(r2) + 2], ledger
    kept = {json.dumps(r["params"], sort_keys=True): r["payload_text"] for r in sc.rows("base")}
    assert kept.get(json.dumps(Q2, sort_keys=True)) == _text({"rows": r2}), (
        "the base kept under the re-ask's key is not the answer the host read for it")
    assert json.dumps(Q1, sort_keys=True) not in kept, "a refused attempt's re-ask was kept"

    # The world, reloaded from its store, still holds that answer and treats it as real data.
    store = S.sym("learning.branch.estate._oracle_store", "OracleStore")(S.oracle_dir(sc.ep, "b"))
    key = S.sym("learning.branch.ledger", "request_key")("idp", "query", Q2)
    assert store.base.get(key) == _text({"rows": r2}), "the reloaded store lost the kept base"
    assert ("idp", _text({"rows": r2})) in store.base_answers, (
        "the reloaded store does not index the kept base as real data")
    again = S.oracle(*_attempts_reusing_ids(r2, (BOB_ROW,)),
                     *H._honest("fg-2", row={**H.FORGED_ROW, "event_id": "e-9f02"},
                                base_rows=(BOB_ROW,)))
    reg2 = sc.registry(again, retry_cap=len(r2) + 3)
    assert sc.call(reg2, "idp", "query", **BOB_CAPPED) == {
        "rows": [BOB_ROW, {**H.FORGED_ROW, "event_id": "e-9f02"}]}
    H._spent(again)
    for k in range(1, len(r2) + 1):
        H._assert_verdict(again, k, "check 3")


# --------------------------------------------------------------------------------------
# F1 — everything that reads a re-ask record: serve, commit, ledger, reload, judge, verifier.
# --------------------------------------------------------------------------------------

#: Sentinels no other text holds: D is the live-only row (dated after the branch point) that the
#: cut drops, B an older row the cut brings in, Q the re-ask's own question.
D_ID, B_ID, Q_TAG = "e-DROPPED-7f3a", "e-OLDER-9c1d", "REASK-Q-5b2e"


def _dan(event_id: str, ts: str) -> dict:
    return {"user": "dan", "event_id": event_id, "action": "logon", "host": "web-1", "ts": ts}


ROW_D = _dan(D_ID, "2026-07-28T17:05:00Z")


ROW_K = _dan("e-100", H.TS_BASE)


ROW_B = _dan(B_ID, "2026-07-28T14:00:00Z")


LIVE_ONLY = S.query_params("user:dan", limit=2)


RE_ASK_Q = S.query_params(f"user:dan {Q_TAG}", end=S.AS_OF, limit=2)


def _section(prompt: str, heading: str) -> str:
    """The body of the framed section a prompt gives under `heading` ('' when it has none)."""
    found = re.search(rf"{re.escape(heading)}:\n<run-([0-9a-f]+)-untrusted>\n?(.*?)\n?</run-\1-untrusted>",
                      prompt, re.S)
    return found.group(2) if found else ""


def _assert_cut(record: Any, where: str) -> None:
    """A stored re-ask record: the question, and D as dropped (B never)."""
    assert isinstance(record, dict), f"{where}: no re-ask record: {record!r}"
    assert record.get("params") == RE_ASK_Q, f"{where}: the question is lost: {record!r}"
    assert (record.get("system"), record.get("verb")) == ("idp", "query"), (where, record)
    assert record.get("dropped") == [ROW_D], f"{where}: the rows the cut dropped are {record!r}"
    assert B_ID not in json.dumps(record["dropped"]), f"{where}: an older row shown as dropped"


def test_1385_a_re_ask_is_shown_wherever_a_served_call_is_read_and_its_dropped_rows_are_the_cuts(
        tmp_path, monkeypatch):
    """A `reconstructed` call cut by a re-ask (a live-only row D dropped, an older row B brought
    in, the question Q) carries the question and D as dropped — never B — at every reader: the
    committed answer, the world ledger (also for a repeat served from the store after a reload),
    the reloaded store, the judge's prompt, and the verifier's prompt, whose base section and `$BASE`
    expansion hold B and not D (T2, O4, A3, A4)."""
    sc = H._scene(tmp_path, live=[("idp", "query", LIVE_ONLY, {"rows": [ROW_D, ROW_K]}),
                                  ("idp", "query", RE_ASK_Q, {"rows": [ROW_K, ROW_B]})])
    asked = S.re_asked(system="idp", verb="query", params=RE_ASK_Q)
    o = S.oracle(S.re_ask(asked),
                 S.submit(S.sym("learning.branch.estate._oracle_prompt", "BASE_HANDLE"),
                          S.EMPTY_CLAIM))
    verifier = S.passing_verifier()
    reg = sc.registry(o, verifier)

    # serve: `$BASE` is the re-asked answer, so the call is answered with B and without D.
    served = sc.call(reg, "idp", "query", **LIVE_ONLY)
    assert served == {"rows": [ROW_K, ROW_B]}, "`$BASE` did not stand for the re-asked answer"
    H._spent(o)
    assert o.submissions() == 1

    # commit: the oracle's cache of the answer.
    committed = sc.rows("answers")
    assert [r["decision"] for r in committed] == ["reconstructed"], committed
    _assert_cut(committed[0].get("re_ask"), "the committed answer")

    # ledger.
    first = sc.ledger()
    assert [r["source"] for r in first] == ["reconstructed"], first
    _assert_cut(first[0].get("re_ask"), "the world ledger")

    # reload: the store holds the record and the kept base; a repeat is served from the store
    # (no oracle turn) and its ledger row carries the record too.
    store = S.sym("learning.branch.estate._oracle_store", "OracleStore")(S.oracle_dir(sc.ep, "b"))
    stored = next(iter(store.answers.values()))
    _assert_cut(stored.get("re_ask"), "the reloaded store")
    assert store.base.get(S.sym("learning.branch.ledger", "request_key")(
        "idp", "query", RE_ASK_Q)) == _text({"rows": [ROW_K, ROW_B]})
    quiet = S.oracle()
    assert sc.call(sc.registry(quiet), "idp", "query", **LIVE_ONLY) == served
    assert quiet.requests == 0, "the repeat was not served from the reloaded store"
    ledger = sc.ledger()
    assert [r["source"] for r in ledger] == ["reconstructed", "reconstructed"], ledger
    _assert_cut(ledger[1].get("re_ask"), "the repeat's ledger row")

    # the verifier's prompt: the re-asked answer is its base, D is shown only as dropped.
    seen = verifier.all_seen()
    base, dropped = (_section(seen, "The real base answer, as the re-ask returns it"),
                     _section(seen, "The rows the re-ask dropped from the live answer"))
    question = _section(seen, "The re-ask's question")
    assert B_ID in base, f"the verifier's base is not the re-asked answer: {base!r}"
    assert D_ID not in base, f"the verifier's base holds the live-only row: {base!r}"
    assert D_ID in dropped, f"the verifier was not shown the dropped row: {dropped!r}"
    assert B_ID not in dropped, f"the verifier was shown an older row as dropped: {dropped!r}"
    assert Q_TAG in question, f"the verifier was not shown the question: {question!r}"
    assert seen.count(D_ID) == dropped.count(D_ID), "the dropped row is shown outside its section"

    # the judge's prompt, over the ledger as served: the call's line names the cut.
    from defender.tests.learning.oracle.live_contracts import test_1224_judge as J1224
    from defender.tests.support.learning.core import _state1135

    _state1135.set_state_dir(monkeypatch, tmp_path / "learning-state")
    judged = S.judged_episode(tmp_path / "judged", ledgers={"b": S.ledger_rows(sc.ep, "b")})
    judge = J1224._judge({"b": J1224._world_reply()})
    J1224._grade(tmp_path, judged, judge)
    prompt = J1224._prompt_for(judge, "b")
    cuts = [body for _salt, body in re.findall(
        r"cut by a re-ask at the branch point\s*<run-([0-9a-f]+)-untrusted>(.*?)</run-\1-untrusted>",
        prompt, re.S)]
    assert len(cuts) == 2, f"the judge's prompt does not show each call's cut: {cuts}"
    for body in cuts:
        assert Q_TAG in body, f"the judge's call line lost the question: {body!r}"
        assert D_ID in body, f"the judge's call line lost the dropped row: {body!r}"
        assert B_ID not in body, f"the judge's call line shows an older row as dropped: {body!r}"


def _served_after_re_ask(tmp_path: Any, live: list[dict], re_asked_rows: list[dict]) -> Any:
    """World b serving the dan call over a live base of `live`, re-asked to `re_asked_rows` and
    served as the re-asked answer (`$BASE`)."""
    sc = H._scene(tmp_path, live=[("idp", "query", LIVE_ONLY, {"rows": live}),
                                  ("idp", "query", RE_ASK_Q, {"rows": re_asked_rows})])
    o = S.oracle(S.re_ask(S.re_asked(system="idp", verb="query", params=RE_ASK_Q)),
                 S.submit(S.sym("learning.branch.estate._oracle_prompt", "BASE_HANDLE"),
                          S.EMPTY_CLAIM))
    assert sc.call(sc.registry(o, S.passing_verifier()), "idp", "query", **LIVE_ONLY) == {
        "rows": re_asked_rows}
    H._spent(o)
    return sc


def test_1385_review_an_answer_served_as_the_live_base_carries_no_re_ask(tmp_path):
    """A re-ask that cut nothing leaves the served answer the live base (`passthrough`): no cut
    is stored or shown for it. The re-ask's read is logged as the re-ask's own."""
    sc = _served_after_re_ask(tmp_path, [ROW_K], [ROW_K])

    committed = sc.rows("answers")
    assert [r["decision"] for r in committed] == ["passthrough"], committed
    assert "re_ask" not in committed[0], committed[0]
    assert sc.ledger()[0].get("re_ask") is None, sc.ledger()
    assert H._has_row(sc.rows("ledger"), actor="re-ask", params=RE_ASK_Q), sc.rows("ledger")


@pytest.mark.parametrize(("dropped", "shown"), [
    pytest.param([_dan(f"e-late-{i}", "2026-07-28T17:05:00Z") for i in range(7)], 5,
                 id="seven-rows"),
    pytest.param([{**ROW_D, "detail": "x" * 5000}, ROW_D], 0, id="one-oversized-row"),
])
def test_1385_review_a_ledger_row_keeps_a_bounded_cut_and_the_store_the_whole(
        tmp_path, dropped, shown):
    """The answer store keeps every dropped row once; each ledger row (the judge's call list
    prints it whole) keeps the first rows that fit, and how many were dropped in all."""
    sc = _served_after_re_ask(tmp_path, [*dropped, ROW_K], [ROW_K])

    assert sc.rows("answers")[0]["re_ask"]["dropped"] == dropped
    cut = sc.ledger()[0]["re_ask"]
    assert cut["dropped"] == dropped[:shown], cut
    assert cut["dropped_in_all"] == len(dropped), cut
    assert cut["params"] == RE_ASK_Q, cut


def test_1385_review_a_re_asked_esql_answer_echoes_the_calls_own_query(tmp_path):
    """An ES|QL answer echoes the query it ran. Served as `$BASE`, the re-asked answer echoes the
    investigator's query, never the bounded one (which names the branch point); the verifier is
    still shown the re-ask's question."""
    echo, bounded_echo = "FROM logs-* | LIMIT 2", f'FROM logs-* | WHERE @timestamp <= "{S.AS_OF}"'
    asked, bounded = CAPPED, BOUNDED
    sc = H._scene(tmp_path, live=[("idp", "query", asked, {"query": echo, **H.ES_CAPPED}),
                                  ("idp", "query", bounded, {"query": bounded_echo, **H.ES_BOUNDED})])
    o = S.oracle(S.re_ask(S.re_asked(system="idp", verb="query", params=bounded)),
                 S.submit(S.sym("learning.branch.estate._oracle_prompt", "BASE_HANDLE"),
                          S.EMPTY_CLAIM))
    verifier = S.passing_verifier()

    served = sc.call(sc.registry(o, verifier), "idp", "query", **asked)
    assert served == {"query": echo, **H.ES_BOUNDED}, served
    H._spent(o)
    assert S.AS_OF not in json.dumps(served), "the served answer names the branch point"
    question = _section(verifier.all_seen(), "The re-ask's question")
    assert json.dumps(S.AS_OF) in question, f"the verifier lost the bounded question: {question!r}"


pytest.importorskip("pydantic_ai")


#: The keys an older adapter or pre-flight stamped into what it recorded or served.
STAMPS = ("captured_at", "drift", "as_of")


POSITIONS = ("top", "under a key", "in a row", "in a row of a nested table", "in a list of lists")


def _value(rng: random.Random) -> Any:
    return rng.choice(["2026-07-28T16:18:45Z", "2026-07-28", 1785252120, None, "", [], {},
                       {"status": "drifted", "calls": [1, 2]}, ["a", {"b": None}], False])


def _placed(rng: random.Random, key: str, position: str) -> dict:
    """A payload holding `key` at `position`, beside ordinary content."""
    stamp = {key: _value(rng)}
    row = {"user": "alice", "event_id": f"e-{rng.randint(100, 999)}", **stamp}
    if position == "top":
        return {"rows": [{"user": "alice", "event_id": "e-100"}], **stamp}
    if position == "under a key":
        return {"rows": [], "meta": {"source": "idp", "inner": {"note": "x", **stamp}}}
    if position == "in a row":
        return {"rows": [{"user": "bob", "event_id": "e-101"}, row]}
    if position == "in a row of a nested table":
        return {"result": {"pages": [{"rows": [row]}]}, "total": 1}
    return {"values": [["e-102", [row, [stamp]]]], "columns": [{"name": "id", "type": "keyword"}]}


def _tree(rng: random.Random, depth: int) -> Any:
    if depth == 0 or rng.random() < 0.25:
        return _value(rng)
    if rng.random() < 0.6:
        keys = rng.sample([*STAMPS, "rows", "host", "meta", "items", "ts"], rng.randint(1, 4))
        return {k: _tree(rng, depth - 1) for k in keys}
    return [_tree(rng, depth - 1) for _ in range(rng.randint(0, 3))]


def test_1385_a_recorded_call_is_replayed_byte_for_byte_whatever_keys_it_holds(tmp_path):
    """In a world without facts every recorded payload — each of `captured_at`, `drift` and
    `as_of` placed at the top, under a key, in a row, in a nested table and among lists, and
    generated trees of such keys — is served and rowed exactly as recorded (O7, H6)."""
    rng = random.Random(SEED)
    payloads: list[Any] = [_placed(rng, key, position)
                           for key in STAMPS for position in POSITIONS]
    payloads += [{"wrapper": _tree(rng, 4), **{k: _value(rng) for k in rng.sample(STAMPS, 2)}}
                 for _ in range(20)]
    asked = [S.query_params(f"user:rec{n}") for n in range(len(payloads))]
    est = S.estate(tmp_path)
    ep = S.episode_v2(tmp_path, base_rows=[S.captured("idp", "query", params, payload)
                                           for params, payload in zip(asked, payloads, strict=True)])
    reg = S.sandboxed_registry(ep, "a", est)
    ctx = est.ctx(tmp_path / "run")

    got = [S.call(reg, "idp", "query", ctx, **params) for params in asked]

    assert est.calls("idp", "query") == [], "a recorded call was read live"
    rows = S.ledger_rows(ep, "a")
    recorded = [S.captured("idp", "query", params, payload)["payload_text"]
                for params, payload in zip(asked, payloads, strict=True)]
    assert [r["payload_text"] for r in rows] == recorded, (
        "a replayed payload's bytes differ from the recording's")
    assert [r["source"] for r in rows] == [S.PASSTHROUGH] * len(payloads), rows
    assert got == payloads, "a replayed payload differs from the recording's"
