"""#1579 P1 as a property: mutations over a call kind's valid reply(ies), at every nesting level.

A suite scripts a valid reply (or the three-call script) as a list of mappings, asks this module for
variants, runs each through the real code under a seam fake, and classifies the outcome:

- refused (the check rejected it, so the model would be re-asked), or
- accepted, with EVERY key the reply carried held unchanged by what the host kept (`same`: type
  strict and recursive, so `5` is not `"5"` and `True` is not `1`) and the manifest gate satisfied.

There is no exemption for blank or null values (E4): a value the host would silently replace is a
refusal, never an acceptance. No production symbol is imported here.
"""
from __future__ import annotations

import copy
import json
import random
from collections.abc import Callable
from typing import Any

Mutation = tuple[str, Callable[[list], None]]

#: Wrong-typed (and null) values every key is given. A wrong value equal to the original is skipped.
WRONG_VALUES: tuple[Any, ...] = (5, True, None, ["x"], {"k": 1})
#: What an element of a list is replaced by (null, blank, number, a mapping, a list, text).
ELEMENT_VALUES: tuple[Any, ...] = (None, "", 5, {}, ["x"], "zz extra")


def same(left: Any, right: Any) -> bool:
    """Equal as JSON documents (type strict, recursive, key order irrelevant)."""
    return json.dumps(left, sort_keys=True, default=str) == json.dumps(right, sort_keys=True, default=str)


def at(replies: list, path: tuple) -> Any:
    node: Any = replies
    for step in path:
        node = node[step]
    return node


def _walk(value: Any, path: tuple, dicts: list[tuple], lists: list[tuple]) -> None:
    if isinstance(value, dict):
        dicts.append(path)
        for key, inner in value.items():
            _walk(inner, (*path, key), dicts, lists)
    elif isinstance(value, list):
        lists.append(path)
        for i, inner in enumerate(value):
            _walk(inner, (*path, i), dicts, lists)


def containers(replies: list[dict]) -> tuple[list[tuple], list[tuple]]:
    """Paths (reply index, *keys) of every mapping and of every list in the replies, at every depth."""
    dicts: list[tuple] = []
    lists: list[tuple] = []
    for i, reply in enumerate(replies):
        _walk(reply, (i,), dicts, lists)
    return dicts, lists


def reorder(replies: list, path: tuple) -> None:
    node = at(replies, path)
    items = list(node.items())
    node.clear()
    node.update(reversed(items))


def _blank(value: Any) -> Any:
    return [] if isinstance(value, list) else {} if isinstance(value, dict) else ""


def _key_mutations(replies: list[dict], path: tuple, key: str) -> list[Mutation]:
    value = at(replies, path)[key]
    blank = _blank(value)
    rows: list[Mutation] = [
        (f"drop {path}.{key}", lambda r, p=path, k=key: at(r, p).pop(k)),
        (f"blank {path}.{key}", lambda r, p=path, k=key, v=blank: at(r, p).__setitem__(k, v)),
    ]
    rows += [(f"{path}.{key}={wrong!r}",
              lambda r, p=path, k=key, v=wrong: at(r, p).__setitem__(k, copy.deepcopy(v)))
             for wrong in WRONG_VALUES if not same(wrong, value)]
    if isinstance(value, str):
        rows.append((f"reword {path}.{key}",
                     lambda r, p=path, k=key: at(r, p).__setitem__(k, at(r, p)[k] + " (reworded)")))
    return rows


def _list_mutations(replies: list[dict], path: tuple) -> list[Mutation]:
    items = at(replies, path)
    rows: list[Mutation] = []
    for i, element in enumerate(items):
        rows.append((f"delete {path}[{i}]", lambda r, p=path, n=i: at(r, p).pop(n)))
        rows += [(f"{path}[{i}]={wrong!r}",
                  lambda r, p=path, n=i, v=wrong: at(r, p).__setitem__(n, copy.deepcopy(v)))
                 for wrong in ELEMENT_VALUES if not same(wrong, element)]
    rows.append((f"append text to {path}", lambda r, p=path: at(r, p).append("zz extra")))
    if items:
        rows.append((f"append a copy of {path}[0]",
                     lambda r, p=path: at(r, p).append(copy.deepcopy(at(r, p)[0]))))
    return rows


def single_mutations(replies: list[dict], *, identities: tuple[Any, ...] = ()) -> list[Mutation]:
    """(label, mutation) over every mapping, key and list element of the replies, at every depth:
    an unknown key, each of `identities` as a `world_id`, reorder the keys (valid); per key: drop,
    blank, each wrong-typed or null value, reword (valid); per list element: replace it, delete it;
    per list: append text, append a copy of the first element."""
    rows: list[Mutation] = []
    dicts, lists = containers(replies)
    for path in dicts:
        rows.append((f"unknown key in {path}", lambda r, p=path: at(r, p).__setitem__("zz_extra", "x")))
        rows += [(f"world_id={identity!r} in {path}",
                  lambda r, p=path, v=identity: at(r, p).__setitem__("world_id", v))
                 for identity in identities]
        rows.append((f"reorder {path}", lambda r, p=path: reorder(r, p)))
        for key in list(at(replies, path)):
            rows += _key_mutations(replies, path, key)
    for path in lists:
        rows += _list_mutations(replies, path)
    return rows


def variants(base: list[dict], *, seed: int, pairs: int, extra: list[Mutation] | None = None,
             identities: tuple[Any, ...] = ()) -> list[tuple[str, list[dict]]]:
    """Every single mutation (plus `extra`, the call kind's own) and `pairs` seeded pairs, each
    applied to a deep copy of `base`. A pair whose second target the first removed is skipped."""
    singles = single_mutations(base, identities=identities) + list(extra or [])
    rng = random.Random(seed)
    plans: list[tuple[str, list[Mutation]]] = [(label, [(label, m)]) for label, m in singles]
    for _ in range(pairs):
        (l1, m1), (l2, m2) = rng.sample(singles, 2)
        plans.append((f"{l1} + {l2}", [(l1, m1), (l2, m2)]))
    out: list[tuple[str, list[dict]]] = []
    for label, steps in plans:
        replies = copy.deepcopy(base)
        try:
            for _l, mutate in steps:
                mutate(replies)
        except (KeyError, IndexError, TypeError, AttributeError):
            continue
        out.append((label, replies))
    return out


def gate(family: dict) -> None:
    """The manifest gate the launcher runs on an authored family (`accept_family`), over the
    launcher's own derived fields. Raises `FamilyError` where the gate refuses."""
    from defender.tests.support.learning.branch import _triplet_947 as T

    doc = T.family_doc(worlds=family["worlds"], base_story=family["base_story"],
                       discriminator=family["discriminator"])
    T.mod("records._family").accept_family(doc)
