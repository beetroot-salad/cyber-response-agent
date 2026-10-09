"""The five host checks every oracle submission passes before anything is served (#1224, M4).

`check_submission` is the ONE host checker: the serving path gates each submission with it and
the oracle's advisory `check` tool answers with it, so the two can never disagree. It returns
failure texts, each naming the check it failed (`check <n>`); an empty list passes.

  1. Structure: every difference between the base answer and the served one is claimed — an
     added row is a claimed forged row, a removed row a claimed removal, a changed value a
     claimed change or count — and every claim entry is found. Mapping key order is not a
     difference, list order is, duplicates are a multiset (N09).
  2. Shape: a forged row carries exactly the columns real rows of its system carry at the same
     place, with their value types (M14=B); with no real example there is nothing to compare
     (D2).
  3. Ids: no id-like value of a newly forged row equals a value in this world's real data,
     unless the claim declares it a reference to an entity (M12=A, S21). "Id-like" is judged
     by column name and value shape only: a column whose name ends in id/hash/uuid/guid, or a
     value shaped like a UUID or 16+ hex digits; placeholders ("", "none", "n/a", ...) never
     are. In memory, no lookup.
  4. Facts: a recorded fact is contradicted only by a served mapping whose own string values
     include the entity and which itself carries the field with a different value — the same
     mapping, no nesting or cross-row linkage — and every frozen row a claim names is served
     exactly as frozen (M13=A, S4).
  5. Counting: the claim's counts add up, and each removal's side query, re-run through the
     run-query door, selects the claimed count (H-02).
"""
from __future__ import annotations

import difflib
import json
import re
from collections import Counter
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any

from defender._untrusted import wrap_fresh

#: The claim's structured keys (coined, `_spec1224`). Anything else at the top level is a claim
#: the host cannot read, and fails check 1.
CLAIM_KEYS = ("added", "removed", "changed", "counts", "entity_refs")

#: Values that stand for "no value" and are never ids (check 3).
_PLACEHOLDERS = frozenset({"", "-", "--", "0", "none", "null", "n/a", "na", "unknown", "nil"})
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_LONG_HEX = re.compile(r"^[0-9a-fA-F]{16,}$")


class Refused(Exception):
    """A side query the run-query door would not run (grant, refusal, adapter fault)."""


def canonical_json(value: Any) -> str:
    """One JSON spelling of a value: key order is not a difference (N09)."""
    return json.dumps(value, sort_keys=True, default=str)


@dataclass
class CheckStore:
    """What the checks read beside the submission: the world's frozen forged rows, the rows
    staged this attempt, the recorded facts (committed and staged), and the side-query door.

    A forged row is fresh (`staged`: forged this attempt, judged by checks 2 and 3) or frozen
    (committed with an earlier verified answer: judged once, then served as it is), never
    both — re-forging a frozen row reuses it (`Oracle._forge`)."""

    frozen: Mapping[str, Mapping[str, Any]]
    staged: Mapping[str, Mapping[str, Any]]
    facts: Mapping[tuple[str, str], Any]
    rerun: Callable[[str, str, dict], Any]

    def forged(self, forged_id: str) -> Mapping[str, Any] | None:
        return self.staged.get(forged_id) or self.frozen.get(forged_id)


@dataclass
class RealData:
    """This world's real answers: `(system, payload)` pairs (base answers, the base recording,
    exploration and verifier reads) plus loose real values (the source alert's).

    Indexed as answers arrive (`add`, `add_loose`; an answer already held is not added twice):
    every check reads the index, so a check costs the size of its submission, not of all the
    real data the world has seen."""

    answers: list[tuple[str, Any]] = field(default_factory=list)
    loose: list[Any] = field(default_factory=list)

    def __post_init__(self) -> None:
        given, self.answers = list(self.answers), []
        loose, self.loose = list(self.loose), []
        self._held: set[str] = set()
        #: Every scalar's text; every mapping; the mappings carrying each value's text; the
        #: rows of each `(system, path)` row list (answers only, not loose values).
        self.values: set[str] = set()
        self.maps: list[dict] = []
        self.by_value: dict[str, list[dict]] = {}
        self.rows: dict[tuple[str, tuple[str, ...]], list[dict]] = {}
        for system, payload in given:
            self.add(system, payload)
        self.add_loose(loose)

    def add(self, system: str, payload: Any) -> None:
        key = f"{system}\x00{canonical_json(payload)}"
        if key in self._held:
            return
        self._held.add(key)
        self.answers.append((system, payload))
        self._index(payload)
        for path, row in _row_lists(payload):
            self.rows.setdefault((system, path), []).append(row)

    def add_loose(self, values: list[Any]) -> None:
        for value in values:
            self.loose.append(value)
            self._index(value)

    def _index(self, payload: Any) -> None:
        self.values.update(_value_text(v) for v in _scalars(payload))
        for mapping in _mappings(payload):
            self.maps.append(mapping)
            for text in {_value_text(v) for v in mapping.values()}:
                self.by_value.setdefault(text, []).append(mapping)


@dataclass
class _Claim:
    added: list[dict]
    removed: list[dict]
    changed: list[dict]
    counts: list[dict]
    entity_refs: list[dict]


# --------------------------------------------------------------------------------------------
# The claim document.
# --------------------------------------------------------------------------------------------


def parse_claim(claim: Any) -> tuple[_Claim | None, str | None]:  # noqa: C901 — one validation per claim key, each refusing with its own reason
    """The claim's structured entries, or why it is not a claim the host can read."""
    if not isinstance(claim, Mapping):
        return None, "the claim is not a mapping"
    unknown = sorted(str(k) for k in claim if k not in CLAIM_KEYS)
    if unknown:
        return None, f"the claim carries fields the host does not know: {unknown}"
    parts: dict[str, list[dict]] = {}
    for key in CLAIM_KEYS:
        entries = claim.get(key, [])
        if entries is None:
            entries = []
        if not isinstance(entries, list) or not all(isinstance(e, Mapping) for e in entries):
            return None, f"the claim's {key!r} is not a list of entries"
        parts[key] = [dict(e) for e in entries]
    for entry in parts["added"]:
        if not (isinstance(entry.get("forged_id"), str) and isinstance(entry.get("fact_id"), str)):
            return None, "an `added` entry needs a string forged_id and fact_id"
    for entry in parts["removed"]:
        side = entry.get("side_query")
        if "row" not in entry or not isinstance(side, Mapping) or not isinstance(
                side.get("system"), str) or not isinstance(side.get("verb"), str) or not (
                isinstance(side.get("params", {}), Mapping)):
            return None, "a `removed` entry needs a row and a side_query {system, verb, params}"
    for entry in parts["changed"]:
        if not ({"entity", "field", "old", "new"} <= set(entry)):
            return None, "a `changed` entry needs entity, field, old and new"
    for entry in parts["counts"]:
        if "group" not in entry:
            return None, "a `counts` entry needs a group"
    for entry in parts["entity_refs"]:
        if not all(isinstance(entry.get(k), str) for k in ("forged_id", "column", "entity")):
            return None, "an `entity_refs` entry needs string forged_id, column and entity"
    return _Claim(**parts), None


def structured(claim: _Claim) -> dict:
    """The claim's structured entries only — what the verifier is shown (M17=A): no free text
    beside an entry or the claim."""
    return {
        "added": [{"forged_id": e["forged_id"], "fact_id": e["fact_id"]} for e in claim.added],
        "removed": [{"row": e["row"], "side_query": {
            "system": e["side_query"]["system"], "verb": e["side_query"]["verb"],
            "params": dict(e["side_query"].get("params") or {})},
            "count": e.get("count")} for e in claim.removed],
        "changed": [{k: e[k] for k in ("entity", "field", "old", "new")} for e in claim.changed],
        "counts": [{k: e.get(k) for k in ("group", "base", "added", "removed", "served")}
                   for e in claim.counts],
        "entity_refs": [{k: e[k] for k in ("forged_id", "column", "entity")}
                        for e in claim.entity_refs],
    }


# --------------------------------------------------------------------------------------------
# Check 1: the structural diff.
# --------------------------------------------------------------------------------------------


@dataclass
class _Diff:
    added: list[tuple[tuple[str, ...], Any]] = field(default_factory=list)
    removed: list[tuple[tuple[str, ...], Any]] = field(default_factory=list)
    #: `(key, old, new, base mapping, served mapping)`; key "" is a bare value, no mapping.
    changed: list[tuple[str, Any, Any, dict, dict]] = field(default_factory=list)
    unclaimed: list[str] = field(default_factory=list)


def _shape_kind(value: Any) -> str:
    if isinstance(value, Mapping):
        return "mapping"
    if isinstance(value, list):
        return "list"
    return "scalar"


def _where(path: tuple[str, ...]) -> str:
    return "/".join(path) or "the top level"


def _diff(base: Any, served: Any, path: tuple[str, ...], out: _Diff,  # noqa: C901 — one arm per JSON shape pair
          pair_rows: Callable[[Any, Any], bool]) -> None:
    kb, ks = _shape_kind(base), _shape_kind(served)
    if kb != ks:
        out.unclaimed.append(f"the value at {_where(path)} changed shape ({kb} to {ks})")
        return
    if kb == "mapping":
        for key in sorted(set(base) - set(served)):
            out.unclaimed.append(f"key {key!r} at {_where(path)} was removed")
        for key in sorted(set(served) - set(base)):
            out.unclaimed.append(f"key {key!r} at {_where(path)} was added")
        for key in sorted(set(base) & set(served)):
            b, s = base[key], served[key]
            if _shape_kind(b) == "scalar" and _shape_kind(s) == "scalar":
                if canonical_json(b) != canonical_json(s):
                    out.changed.append((str(key), b, s, dict(base), dict(served)))
            else:
                _diff(b, s, (*path, str(key)), out, pair_rows)
        return
    if kb == "list":
        a = [canonical_json(x) for x in base]
        b = [canonical_json(x) for x in served]
        matcher = difflib.SequenceMatcher(a=a, b=b, autojunk=False)
        for op, i1, i2, j1, j2 in matcher.get_opcodes():
            if op == "equal":
                continue
            olds, news = list(base[i1:i2]), list(served[j1:j2])
            pairs, olds, news = _pair_rows(olds, news, pair_rows)
            for o, n in pairs:
                _diff(o, n, path, out, pair_rows)
            out.removed.extend((path, x) for x in olds)
            out.added.extend((path, x) for x in news)
        return
    if canonical_json(base) != canonical_json(served):
        # A bare value (a scalar count): only a `counts` entry of group "*" can claim it.
        out.changed.append(("", base, served, {}, {}))


def _pair_rows(olds: list[Any], news: list[Any], is_addition: Callable[[Any, Any], bool],
          ) -> tuple[list[tuple[Any, Any]], list[Any], list[Any]]:
    """Pair replaced rows that are edits of one another: same keys, the most equal values (at
    least one). A new row that is a claimed forged row is an addition, never an edit."""
    pairs: list[tuple[Any, Any]] = []
    left: list[Any] = []
    free = list(news)
    for old in olds:
        best, best_score = None, 0
        if isinstance(old, Mapping):
            for i, new in enumerate(free):
                if not isinstance(new, Mapping) or set(new) != set(old) or is_addition(old, new):
                    continue
                score = sum(1 for k in old if canonical_json(old[k]) == canonical_json(new[k]))
                if score > best_score:
                    best, best_score = i, score
        if best is None:
            left.append(old)
        else:
            pairs.append((old, free.pop(best)))
    return pairs, left, free


def _scalar_values(mapping: Mapping[str, Any]) -> list[str]:
    return [canonical_json(v) for v in mapping.values() if _shape_kind(v) == "scalar"]


_Matched = list[tuple[tuple[str, ...], Any, Mapping[str, Any]]]


def _check_structure(base: Any, served: Any, claim: _Claim, store: CheckStore,  # noqa: C901 — check 1's reconciliation of the diff against each claim bucket
                     world_facts: set[str]) -> tuple[list[str], _Matched, list[Mapping[str, Any]]]:
    """Check 1. Returns its failures, the added rows matched to claimed forged rows (with the
    forged record) for checks 2 and 3, and the claimed forged rows missing from the answer
    that no count covers, for check 4."""
    failures: list[str] = []
    claimed: list[tuple[str, Mapping[str, Any]]] = []
    for entry in claim.added:
        fid, fact_id = entry["forged_id"], entry["fact_id"]
        if fact_id not in world_facts:
            failures.append(f"added {fid!r} names fact {fact_id!r}, which is not this world's")
            continue
        record = store.forged(fid)
        if record is None:
            failures.append(f"added {fid!r} names no forged row (forge it first)")
            continue
        claimed.append((canonical_json(record.get("row")), record))
    claimed_texts = Counter(text for text, _ in claimed)

    def pair_rows(old: Any, new: Any) -> bool:
        # A replaced row that IS a claimed forged row is an addition beside a removal, not an
        # edit of the old row.
        return claimed_texts.get(canonical_json(new), 0) > 0

    diff = _Diff()
    _diff(base, served, (), diff, pair_rows)
    failures.extend(diff.unclaimed)

    remaining = list(claimed)
    matched: list[tuple[tuple[str, ...], Any, Mapping[str, Any]]] = []
    counts = list(claim.counts)
    buckets = list(counts)  # each count entry claims at most one new bucket row
    for path, element in diff.added:
        text = canonical_json(element)
        hit = next((i for i, (t, _r) in enumerate(remaining) if t == text), None)
        if hit is not None:
            matched.append((path, element, remaining.pop(hit)[1]))
            continue
        if isinstance(element, Mapping) and _bucket_counted(element, buckets):
            continue
        failures.append(f"an unclaimed row was added at {_where(path)}: "
                        f"{wrap_fresh(text, 'untrusted')}")
    removals = [canonical_json(e["row"]) for e in claim.removed]
    for path, element in diff.removed:
        text = canonical_json(element)
        if text in removals:
            removals.remove(text)
            continue
        failures.append(f"a row was removed at {_where(path)} without a claimed removal: "
                        f"{wrap_fresh(text, 'untrusted')}")
    changes = list(claim.changed)
    for key, old, new, base_map, served_map in diff.changed:
        values = set(_scalar_values(base_map)) | set(_scalar_values(served_map))
        hit = next((i for i, c in enumerate(changes)
                    if key and str(c["field"]) == key and canonical_json(c["old"]) == canonical_json(old)
                    and canonical_json(c["new"]) == canonical_json(new)
                    and canonical_json(c["entity"]) in values), None)
        if hit is not None:
            changes.pop(hit)
            continue
        if any(_counts_change(c, key, old, new, values) for c in counts):
            continue
        failures.append(f"field {key!r} changed from {wrap_fresh(canonical_json(old), 'untrusted')} "
                        f"to {wrap_fresh(canonical_json(new), 'untrusted')} without a claimed change")
    missing = _uncounted([r for _t, r in remaining], counts)
    if missing:
        names = sorted(str(r.get("forged_id")) for r in missing)
        failures.append(f"claimed forged row(s) {names} are not in the served answer")
    if removals:
        failures.append(f"{len(removals)} claimed removal(s) name rows the base answer does not "
                        "lose in the served answer")
    if changes:
        failures.append(f"{len(changes)} claimed change(s) are not differences in the served "
                        "answer")
    return [f"check 1: {f}" for f in failures], matched, missing


def _bucket_counted(element: Mapping[str, Any], buckets: list[dict]) -> bool:
    """A new row that is a count's new bucket: a base-0 count whose group is a value the row
    itself carries, and whose served count the row carries too. The entry is consumed, so one
    count claims one bucket row; "*" names no bucket and claims none."""
    values = set(_scalar_values(element))
    for i, c in enumerate(buckets):
        group = c.get("group")
        if (_is_int(c.get("base")) and c.get("base") == 0 and _is_int(c.get("served"))
                and group != "*" and canonical_json(group) in values
                and canonical_json(c.get("served")) in values):
            buckets.pop(i)
            return True
    return False


def _uncounted(records: list[Mapping[str, Any]], counts: list[dict]) -> list[Mapping[str, Any]]:
    """The claimed forged rows absent from the served answer that no count accounts for. A
    count covers a row only within its own group — "*" (the whole answer) or a group value the
    forged row itself carries — and at most `added` rows."""
    left = {i: c["added"] for i, c in enumerate(counts) if _is_int(c.get("added")) and c["added"] > 0}
    uncovered: list[Mapping[str, Any]] = []
    for record in records:
        row = record.get("row")
        values = set(_scalar_values(row)) if isinstance(row, Mapping) else set()
        hit = next((i for i, n in left.items() if n > 0 and (
            counts[i].get("group") == "*" or canonical_json(counts[i].get("group")) in values)), None)
        if hit is None:
            uncovered.append(record)
        else:
            left[hit] -= 1
    return uncovered


def _counts_change(entry: Mapping[str, Any], key: str, old: Any, new: Any,
                   values: set[str]) -> bool:
    if canonical_json(entry.get("base")) != canonical_json(old) or canonical_json(
            entry.get("served")) != canonical_json(new):
        return False
    group = entry.get("group")
    return group == "*" or (bool(key) and (group == key or canonical_json(group) in values))


# --------------------------------------------------------------------------------------------
# Real data, indexed.
# --------------------------------------------------------------------------------------------


def _row_lists(payload: Any, path: tuple[str, ...] = ()) -> Iterator[tuple[tuple[str, ...], dict]]:
    """Every mapping inside a list, with its list's key path (indices ignored)."""
    if isinstance(payload, Mapping):
        for key, value in payload.items():
            yield from _row_lists(value, (*path, str(key)))
    elif isinstance(payload, list):
        for item in payload:
            if isinstance(item, Mapping):
                yield path, dict(item)
                for key, value in item.items():
                    if isinstance(value, (Mapping, list)):
                        yield from _row_lists(value, (*path, str(key)))
            elif isinstance(item, list):
                yield from _row_lists(item, path)


def _mappings(payload: Any) -> Iterator[dict]:
    if isinstance(payload, Mapping):
        yield dict(payload)
        for value in payload.values():
            yield from _mappings(value)
    elif isinstance(payload, list):
        for item in payload:
            yield from _mappings(item)


def _scalars(payload: Any) -> Iterator[Any]:
    if isinstance(payload, Mapping):
        for value in payload.values():
            yield from _scalars(value)
    elif isinstance(payload, list):
        for item in payload:
            yield from _scalars(item)
    elif payload is not None:
        yield payload


def _json_type(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, (int, float)):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, Mapping):
        return "object"
    if isinstance(value, list):
        return "array"
    return "string"


def _value_text(value: Any) -> str:
    return value if isinstance(value, str) else canonical_json(value)


# --------------------------------------------------------------------------------------------
# Checks 2-5.
# --------------------------------------------------------------------------------------------


def _fresh(matched: list[tuple[tuple[str, ...], Any, Mapping[str, Any]]],
           store: CheckStore) -> list[tuple[tuple[str, ...], Any, Mapping[str, Any]]]:
    """The served forged rows forged this attempt. A frozen row was judged when it froze; real
    data seen since cannot make it fail, since it can never be changed (only its collisions
    are recorded, `frozen_id_collisions`)."""
    return [m for m in matched if str(m[2].get("forged_id")) in store.staged]


def _check_shape(matched: list[tuple[tuple[str, ...], Any, Mapping[str, Any]]],  # noqa: C901 — check 2's per-row rules
                 real: RealData) -> list[str]:
    failures: list[str] = []
    for path, element, record in matched:
        if not isinstance(element, Mapping):
            continue
        rows = real.rows.get((str(record.get("system")), path))
        if not rows:
            continue  # D2: no real example, nothing to compare
        columns = set().union(*(set(r) for r in rows))
        types: dict[str, set[str]] = {}
        for r in rows:
            for col, value in r.items():
                kind = _json_type(value)
                if kind is not None:
                    types.setdefault(col, set()).add(kind)
        fid = record.get("forged_id")
        missing, extra = sorted(columns - set(element)), sorted(set(element) - columns)
        if missing or extra:
            failures.append(f"check 2: forged row {fid!r} does not carry the columns real "
                            f"{record.get('system')} rows carry (missing {missing}, extra {extra})")
            continue
        wrong = sorted(col for col, value in element.items()
                       if _json_type(value) is not None and types.get(col)
                       and _json_type(value) not in types[col])
        if wrong:
            failures.append(f"check 2: forged row {fid!r} gives {wrong} a value type real rows "
                            "never carry")
    return failures


def _id_like(column: str, value: Any) -> bool:
    if value is None or isinstance(value, bool) or _shape_kind(value) != "scalar":
        return False
    text = _value_text(value).strip()
    if text.lower() in _PLACEHOLDERS:
        return False
    name = column.lower()
    if name.endswith(("id", "hash", "uuid", "guid")):
        return True
    return bool(_UUID.match(text) or _LONG_HEX.match(text))


def _check_ids(matched: list[tuple[tuple[str, ...], Any, Mapping[str, Any]]], claim: _Claim,
               store: CheckStore, real: RealData) -> list[str]:
    fresh = [(element, record) for _p, element, record in _fresh(matched, store)
             if isinstance(element, Mapping)]
    if not fresh:
        return []
    failures: list[str] = []
    for element, record in fresh:
        fid = str(record.get("forged_id"))
        for column, value in element.items():
            if not _id_like(str(column), value) or _value_text(value) not in real.values:
                continue
            if _declared_reference(fid, str(column), value, claim, real.maps):
                continue
            failures.append(f"check 3: forged row {fid!r} reuses a real identifier in column "
                            f"{column!r} {wrap_fresh(_value_text(value), 'untrusted')}")
    return failures


def frozen_id_collisions(base: Any, served: Any, claim: Any, *, world: Any, store: CheckStore,
                         real_data: RealData) -> list[dict[str, Any]]:
    """Every identifier a FROZEN forged row serves in this answer that this world's real data
    carries too, with the real rows carrying it (M12=A): the row stays frozen and is still
    served — check 3 only judges fresh rows — and the collision is recorded for the judge.

    `[]` for a claim the host cannot read; called on a submission that already passed."""
    parsed, _malformed = parse_claim(claim)
    if parsed is None:
        return []
    world_facts = {str(getattr(f, "fact_id", None) or (f.get("fact_id") if isinstance(f, Mapping) else ""))
                   for f in (getattr(world, "facts", None) or ())}
    _failures, matched, _missing = _check_structure(base, served, parsed, store, world_facts)
    found: list[dict[str, Any]] = []
    for _path, element, record in matched:
        fid = str(record.get("forged_id"))
        if not isinstance(element, Mapping) or fid not in store.frozen:
            continue
        for column, value in element.items():
            if not _id_like(str(column), value):
                continue
            text = _value_text(value)
            rows = [dict(m) for m in real_data.by_value.get(text, ())
                    if canonical_json(m) != canonical_json(element)]
            if rows:
                found.append({"forged_id": fid, "column": str(column), "value": text,
                              "system": record.get("system"), "real_rows": rows[:3]})
    return found


def _declared_reference(fid: str, column: str, value: Any, claim: _Claim,
                        real_maps: list[dict]) -> bool:
    for ref in claim.entity_refs:
        if ref["forged_id"] != fid or ref["column"] != column:
            continue
        entity = ref["entity"]
        for mapping in real_maps:
            if canonical_json(mapping.get(column)) == canonical_json(value) and entity in [
                    v for v in mapping.values() if isinstance(v, str)]:
                return True
    return False


def _contradicts(mapping: Mapping[str, Any], entity: str, field_: str, value: Any) -> bool:
    """A served row naming `entity` whose `field_` differs from the recorded fact."""
    names = [v for v in mapping.values() if isinstance(v, str)]
    return field_ in mapping and entity in names and canonical_json(mapping[field_]) != canonical_json(value)


def _check_facts(served: Any, claim: _Claim, store: CheckStore,
                 missing: list[Mapping[str, Any]]) -> list[str]:
    failures: list[str] = []
    for (entity, field_), value in store.facts.items():
        if any(_contradicts(mapping, entity, field_, value) for mapping in _mappings(served)):
            failures.append(f"check 4: {wrap_fresh(entity, 'untrusted')}'s {field_!r} "
                            "is served with a value other than the recorded fact")
        for change in claim.changed:
            if change["entity"] == entity and change["field"] == field_ and canonical_json(
                    change["new"]) != canonical_json(value):
                failures.append(f"check 4: the claimed change of {field_!r} contradicts the "
                                "recorded fact")
    for entry in claim.added:
        frozen = store.frozen.get(entry["forged_id"])
        if frozen is not None and frozen.get("fact_id") != entry["fact_id"]:
            failures.append(f"check 4: frozen row {entry['forged_id']!r} was forged for fact "
                            f"{frozen.get('fact_id')!r}, not {entry['fact_id']!r}")
    for record in missing:
        fid = str(record.get("forged_id"))
        if fid in store.frozen:
            failures.append(f"check 4: frozen row {fid!r} is not served exactly as frozen")
    return failures


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _selected(payload: Any) -> list[Any]:
    """The rows a side query's answer selects: the first list in it, breadth first."""
    queue: list[Any] = [payload]
    while queue:
        node = queue.pop(0)
        if isinstance(node, list):
            return node
        if isinstance(node, Mapping):
            queue.extend(node.values())
    return []


def _check_counts(claim: _Claim, store: CheckStore) -> list[str]:
    failures: list[str] = []
    for entry in claim.counts:
        nums = [entry.get(k) for k in ("base", "added", "removed", "served")]
        if not all(_is_int(n) for n in nums):
            failures.append(f"check 5: count for group {wrap_fresh(canonical_json(entry.get('group')), 'untrusted')} "
                            "is not four whole numbers")
            continue
        base, added, removed, served = (int(n) for n in nums if n is not None)
        if base + added - removed != served:
            failures.append(f"check 5: count for group "
                            f"{wrap_fresh(canonical_json(entry.get('group')), 'untrusted')} does not add "
                            f"up ({base} + {added} - {removed} != {served})")
    for entry in claim.removed:
        side = entry["side_query"]
        count = entry.get("count")
        if not _is_int(count):
            failures.append("check 5: a removal's count is not a whole number")
            continue
        try:
            answer = store.rerun(side["system"], side["verb"], dict(side.get("params") or {}))
        except Refused as refused:
            failures.append(f"check 5: a removal's side query could not be re-run: "
                            f"{wrap_fresh(str(refused), 'untrusted')}")
            continue
        rows = _selected(answer)
        if len(rows) != count:
            failures.append(f"check 5: a removal's side query selects {len(rows)} row(s), not "
                            f"the claimed {count}")
        elif canonical_json(entry["row"]) not in {canonical_json(r) for r in rows}:
            failures.append("check 5: a removal's side query does not select the removed row")
    return failures


def check_submission(base: Any, served: Any, claim: Any, *, world: Any, store: CheckStore,
                     real_data: RealData) -> list[str]:
    """Every failure of checks 1-5 for one submission, each naming its check; `[]` passes.

    `world` is the served world (its `facts` give the fact ids a claim may name), `store` the
    world's frozen and staged state plus the side-query door, `real_data` this world's real
    answers. The host gate and the oracle's `check` tool both call this."""
    parsed, malformed = parse_claim(claim)
    if parsed is None:
        return [f"check 1: the claim cannot be read: {malformed}"]
    world_facts = {str(getattr(f, "fact_id", None) or (f.get("fact_id") if isinstance(f, Mapping) else ""))
                   for f in (getattr(world, "facts", None) or ())}
    failures, matched, missing = _check_structure(base, served, parsed, store, world_facts)
    failures += _check_shape(_fresh(matched, store), real_data)
    failures += _check_ids(matched, parsed, store, real_data)
    failures += _check_facts(served, parsed, store, missing)
    failures += _check_counts(parsed, store)
    return failures
