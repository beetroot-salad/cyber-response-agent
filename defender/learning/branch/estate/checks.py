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
  3. Ids: no id-like value of a newly forged row (nested fields included, by their dotted
     column) equals a value in this world's real data,
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

Every check reads an answer's rows through ONE row model (`tables`): a table is a list of rows
at a key path. A list whose items are mappings is a table at its path, each mapping a row; an
ES|QL answer (`{"columns": [{"name": ...}], "values": [[...], ...]}`) is a table at its
`values` path, each value array a row zipped with the column names (the `columns` descriptors
are not rows). A row's cells are its top-level columns; its flat view (`flatten`) spells every
nested field as a dotted column (`process.entity_id`). A list inside a row is ONE cell, never
exploded into columns; a list of mappings inside a row is also a table of its own at the
deeper path, and check 3 judges each scalar inside a list cell under that cell's column.
Check 2 compares cells (top-level columns, or ES|QL column names — the granularity M14=B
ruled on); check 3, the collision record and the real-data index read the flat view.
"""
from __future__ import annotations

import difflib
import hashlib
import json
import re
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

    Indexed as answers arrive (`add`, `add_loose`; an answer already held — by digest — is not
    added twice): every check reads the index, so a check costs the size of its submission, not
    of all the real data the world has seen."""

    answers: list[tuple[str, Any]] = field(default_factory=list)
    loose: list[Any] = field(default_factory=list)

    def __post_init__(self) -> None:
        given, self.answers = list(self.answers), []
        loose, self.loose = list(self.loose), []
        self._held: set[bytes] = set()
        #: Every scalar's text; the flat rows (`flatten`) of every table row and of every
        #: top-level mapping; the flat rows carrying each value's text; the cells of each
        #: `(system, table path)` table's rows (answers only, not loose values).
        self.values: set[str] = set()
        self.maps: list[dict] = []
        self.by_value: dict[str, list[dict]] = {}
        self.rows: dict[tuple[str, _Table], list[dict]] = {}
        for system, payload in given:
            self.add(system, payload)
        self.add_loose(loose)

    def add(self, system: str, payload: Any) -> None:
        key = hashlib.sha256(f"{system}\x00{canonical_json(payload)}".encode()).digest()
        if key in self._held:
            return
        self._held.add(key)
        self.answers.append((system, payload))
        for table, cells in self._index(payload):
            self.rows.setdefault((system, table), []).append(cells)

    def add_loose(self, values: list[Any]) -> None:
        for value in values:
            self.loose.append(value)
            self._index(value)

    def _index(self, payload: Any) -> list[tuple[_Table, dict]]:
        self.values.update(_value_text(v) for v in _scalars(payload))
        found = [(_table(path, names), cells) for path, cells, names in tables(payload)]
        flats = [flatten(cells) for _path, cells in found]
        if isinstance(payload, Mapping):
            # The document itself, less the list cells holding rows (those are tables, indexed
            # above): a value inside a row is never indexed under the whole answer.
            flats.append({c: v for c, v in flatten(payload).items()
                          if not (isinstance(v, list) and any(isinstance(x, (Mapping, list))
                                                              for x in v))})
        for flat in flats:
            self.maps.append(flat)
            for text in {_value_text(v) for _c, v in _leaves(flat)}:
                self.by_value.setdefault(text, []).append(flat)
        return found


# --------------------------------------------------------------------------------------------
# The row model: every answer as named tables of rows.
# --------------------------------------------------------------------------------------------

_Path = tuple[str, ...]
#: A table's identity: its path, and for an ES|QL table its column names — answers to two
#: ES|QL queries projecting different columns are two tables, not one (check 2's "same place").
_Table = tuple[_Path, tuple[str, ...] | None]


def _table(path: _Path, names: list[str] | None) -> _Table:
    return path, (tuple(names) if names is not None else None)


def esql_names(node: Any) -> list[str] | None:
    """The column names of an ES|QL answer (`columns` + `values`), or None for any other node."""
    if not isinstance(node, Mapping):
        return None
    columns, values = node.get("columns"), node.get("values")
    if not (isinstance(columns, list) and isinstance(values, list)):
        return None
    names = [c.get("name") if isinstance(c, Mapping) else c for c in columns]
    return [str(n) for n in names] if names and all(isinstance(n, str) for n in names) else None


def as_row(element: Any, names: list[str] | None = None) -> dict | None:
    """A row's cells: a mapping's own columns, or an ES|QL value array zipped with its table's
    column names. None for anything else (a scalar, a bare list)."""
    if isinstance(element, Mapping):
        return dict(element)
    if names is not None and isinstance(element, list) and len(element) == len(names):
        return dict(zip(names, element, strict=True))
    return None


def flatten(cells: Mapping[str, Any], prefix: str = "") -> dict[str, Any]:
    """A row's flat view: every nested field as a dotted column; a list stays one cell."""
    out: dict[str, Any] = {}
    for key, value in cells.items():
        name = f"{prefix}{key}"
        if isinstance(value, Mapping) and value:
            out.update(flatten(value, f"{name}."))
        else:
            out[name] = value
    return out


def _leaves(flat: Mapping[str, Any]) -> Iterator[tuple[str, Any]]:
    """Every scalar of a flat row with its column; each scalar inside a list cell counts under
    that cell's column."""
    for column, value in flat.items():
        if isinstance(value, list):
            for item in _scalars(value):
                yield column, item
        elif value is not None and _shape_kind(value) == "scalar":
            yield column, value


def tables(payload: Any, path: _Path = ()) -> Iterator[tuple[_Path, dict, list[str] | None]]:
    """Every row in an answer: `(table path, cells, ES|QL column names or None)`. List indices
    are not part of a path; a list of lists is one table."""
    if isinstance(payload, Mapping):
        names = esql_names(payload)
        if names is not None:
            rows = (as_row(item, names) for item in payload["values"])
            yield from (((*path, "values"), row, names) for row in rows if row is not None)
        for key, value in payload.items():
            if names is None or key not in ("columns", "values"):
                yield from tables(value, (*path, str(key)))
    elif isinstance(payload, list):
        for item in payload:
            if isinstance(item, Mapping):
                yield path, dict(item), None
                # A list of mappings inside a row is a table of its own, at the deeper path.
                yield from tables(item, path)
            elif isinstance(item, list):
                yield from tables(item, path)


def _row_text(row: Any, names: list[str] | None) -> str:
    """A row's one spelling in its table: a forged or claimed row given as a value array
    compares equal to the same row given as a mapping of the table's columns."""
    cells = as_row(row, names)
    return canonical_json(row if cells is None else cells)


def _row_values(row: Any) -> set[str]:
    """The scalar values a row carries, nested ones included (counts' groups)."""
    if isinstance(row, Mapping):
        return set(_scalar_values(flatten(row)))
    if isinstance(row, list):
        return {canonical_json(v) for v in _scalars(row)}
    return set()


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


_Names = list[str] | None
#: A row the diff found added or removed: its table path, the row (an ES|QL value array
#: already zipped into cells), and its table's ES|QL column names.
_Found = tuple[_Path, Any, _Names]


@dataclass
class _Diff:
    added: list[_Found] = field(default_factory=list)
    removed: list[_Found] = field(default_factory=list)
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


def _zipped(node: Mapping[str, Any], names: list[str]) -> dict:
    """An ES|QL answer with its value arrays zipped into rows of named cells, so an edited row
    pairs with its old self and a changed cell is named by its column."""
    rows = [as_row(v, names) or v for v in node["values"]]
    return {**node, "values": rows}


def _diff(base: Any, served: Any, path: tuple[str, ...], out: _Diff,  # noqa: C901 — one arm per JSON shape pair
          is_addition: Callable[[Any, _Names], bool], names: _Names = None) -> None:
    kb, ks = _shape_kind(base), _shape_kind(served)
    if kb != ks:
        out.unclaimed.append(f"the value at {_where(path)} changed shape ({kb} to {ks})")
        return
    if kb == "mapping":
        esql = esql_names(base)
        if esql is not None and esql == esql_names(served):
            base, served = _zipped(base, esql), _zipped(served, esql)
        else:
            esql = None
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
                _diff(b, s, (*path, str(key)), out, is_addition,
                      esql if esql is not None and key == "values" else None)
        return
    if kb == "list":
        a = [canonical_json(x) for x in base]
        b = [canonical_json(x) for x in served]
        matcher = difflib.SequenceMatcher(a=a, b=b, autojunk=False)
        for op, i1, i2, j1, j2 in matcher.get_opcodes():
            if op == "equal":
                continue
            olds, news = list(base[i1:i2]), list(served[j1:j2])
            pairs, olds, news = _pair_rows(olds, news, lambda new: is_addition(new, names))
            for o, n in pairs:
                _diff(o, n, path, out, is_addition)
            out.removed.extend((path, x, names) for x in olds)
            out.added.extend((path, x, names) for x in news)
        return
    if canonical_json(base) != canonical_json(served):
        # A bare value (a scalar count): only a `counts` entry of group "*" can claim it.
        out.changed.append(("", base, served, {}, {}))


def _pair_rows(olds: list[Any], news: list[Any], is_addition: Callable[[Any], bool],
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
                if not isinstance(new, Mapping) or set(new) != set(old) or is_addition(new):
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


#: A served forged row: its table, the served row (cells; an ES|QL row zipped), the forged
#: record.
_Matched = list[tuple[_Table, Any, Mapping[str, Any]]]


def _check_structure(base: Any, served: Any, claim: _Claim, store: CheckStore,  # noqa: C901 — check 1's reconciliation of the diff against each claim bucket
                     world_facts: set[str]) -> tuple[list[str], _Matched, list[Mapping[str, Any]]]:
    """Check 1. Returns its failures, the added rows matched to claimed forged rows (with the
    forged record) for checks 2 and 3, and the claimed forged rows missing from the answer
    that no count covers, for check 4."""
    failures: list[str] = []
    claimed: list[Mapping[str, Any]] = []
    for entry in claim.added:
        fid, fact_id = entry["forged_id"], entry["fact_id"]
        if fact_id not in world_facts:
            failures.append(f"added {fid!r} names fact {fact_id!r}, which is not this world's")
            continue
        record = store.forged(fid)
        if record is None:
            failures.append(f"added {fid!r} names no forged row (forge it first)")
            continue
        claimed.append(record)

    def is_addition(new: Any, names: _Names) -> bool:
        # A replaced row that IS a claimed forged row is an addition beside a removal, not an
        # edit of the old row.
        text = canonical_json(new)
        return any(_row_text(r.get("row"), names) == text for r in claimed)

    diff = _Diff()
    _diff(base, served, (), diff, is_addition)
    failures.extend(diff.unclaimed)

    remaining = list(claimed)
    matched: _Matched = []
    counts = list(claim.counts)
    buckets = list(counts)  # each count entry claims at most one new bucket row
    for path, element, names in diff.added:
        text = canonical_json(element)
        hit = next((i for i, r in enumerate(remaining)
                    if _row_text(r.get("row"), names) == text), None)
        if hit is not None:
            matched.append((_table(path, names), element, remaining.pop(hit)))
            continue
        if isinstance(element, Mapping) and _bucket_counted(element, buckets):
            continue
        failures.append(f"an unclaimed row was added at {_where(path)}: "
                        f"{wrap_fresh(text, 'untrusted')}")
    removals = list(claim.removed)
    for path, element, names in diff.removed:
        text = canonical_json(element)
        hit = next((i for i, e in enumerate(removals) if _row_text(e["row"], names) == text), None)
        if hit is not None:
            removals.pop(hit)
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
    missing = _uncounted(remaining, counts)
    if missing:
        ids = sorted(str(r.get("forged_id")) for r in missing)
        failures.append(f"claimed forged row(s) {ids} are not in the served answer")
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
    values = _row_values(element)
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
        values = _row_values(record.get("row"))
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


def _fresh(matched: _Matched, store: CheckStore) -> _Matched:
    """The served forged rows forged this attempt. A frozen row was judged when it froze; real
    data seen since cannot make it fail, since it can never be changed (only its collisions
    are recorded, `frozen_id_collisions`)."""
    return [m for m in matched if str(m[2].get("forged_id")) in store.staged]


def _check_shape(matched: _Matched, real: RealData) -> list[str]:  # noqa: C901 — check 2's per-row rules
    """Check 2 over a row's cells (its top-level columns; an ES|QL row's column names): the
    union of the cells real rows of that table carry, with their value types (M14=B)."""
    failures: list[str] = []
    for table, element, record in matched:
        if not isinstance(element, Mapping):
            continue
        rows = real.rows.get((str(record.get("system")), table))
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


def _forged_leaves(element: Any) -> Iterator[tuple[str, Any]]:
    """A served forged row's scalars by flat column (`process.entity_id`); a forged item of a
    bare list has no column, and is judged by its value's shape alone."""
    yield from _leaves(flatten(element) if isinstance(element, Mapping) else {"": element})


def _check_ids(matched: _Matched, claim: _Claim, store: CheckStore, real: RealData) -> list[str]:
    failures: list[str] = []
    for _t, element, record in _fresh(matched, store):
        fid = str(record.get("forged_id"))
        for column, value in _forged_leaves(element):
            if not _id_like(column, value) or _value_text(value) not in real.values:
                continue
            if _declared_reference(fid, column, value, claim, real.maps):
                continue
            where = f" in column {column!r}" if column else ""
            failures.append(f"check 3: forged row {fid!r} reuses a real identifier{where} "
                            f"{wrap_fresh(_value_text(value), 'untrusted')}")
    return failures


@dataclass
class Checked:
    """One submission's host-check outcome: its failures (`[]` passes) and what check 1 found,
    so the collision record reuses the structural diff instead of recomputing it."""

    failures: list[str]
    matched: _Matched = field(default_factory=list)


def frozen_id_collisions(checked: Checked, *, store: CheckStore,
                         real_data: RealData) -> list[dict[str, Any]]:
    """Every identifier a FROZEN forged row serves in this answer that this world's real data
    carries too, with the real rows (flat) carrying it (M12=A): the row stays frozen and is
    still served — check 3 only judges fresh rows — and the collision is recorded for the
    judge. Read off a submission's `Checked`, after it passed."""
    found: list[dict[str, Any]] = []
    for _t, element, record in checked.matched:
        fid = str(record.get("forged_id"))
        if fid not in store.frozen:
            continue
        own = canonical_json(flatten(element)) if isinstance(element, Mapping) else None
        for column, value in _forged_leaves(element):
            if not _id_like(column, value):
                continue
            text = _value_text(value)
            rows = [dict(m) for m in real_data.by_value.get(text, ())
                    if canonical_json(m) != own]
            if rows:
                found.append({"forged_id": fid, "column": column, "value": text,
                              "system": record.get("system"), "real_rows": rows[:3]})
    return found


def _declared_reference(fid: str, column: str, value: Any, claim: _Claim,
                        real_maps: list[dict]) -> bool:
    """The claim names this forged column a reference to an entity, and some real flat row
    carries that entity beside this very value in that column."""
    text = canonical_json(value)
    for ref in claim.entity_refs:
        if ref["forged_id"] != fid or ref["column"] != column:
            continue
        entity = ref["entity"]
        for mapping in real_maps:
            if column not in mapping:
                continue
            cell = mapping[column]
            held = [canonical_json(v) for v in (_scalars(cell) if isinstance(cell, list) else [cell])]
            if text in held and entity in [v for _c, v in _leaves(mapping) if isinstance(v, str)]:
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


def _selected(payload: Any) -> tuple[list[Any], _Names]:
    """The rows a side query's answer selects, with their table's ES|QL column names: the rows
    of its shallowest table (an ES|QL answer's value arrays, zipped — never its `columns`), or,
    with no table, the first bare list in it, breadth first."""
    found: dict[_Path, tuple[list[Any], _Names]] = {}
    for path, cells, names in tables(payload):
        found.setdefault(path, ([], names))[0].append(cells)
    if found:
        return found[min(found, key=len)]
    queue: list[Any] = [payload]
    while queue:
        node = queue.pop(0)
        if isinstance(node, list):
            return node, None
        if isinstance(node, Mapping):
            queue.extend(node.values())
    return [], None


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
        rows, names = _selected(answer)
        if len(rows) != count:
            failures.append(f"check 5: a removal's side query selects {len(rows)} row(s), not "
                            f"the claimed {count}")
        elif _row_text(entry["row"], names) not in {canonical_json(r) for r in rows}:
            failures.append("check 5: a removal's side query does not select the removed row")
    return failures


def run_checks(base: Any, served: Any, claim: Any, *, world: Any, store: CheckStore,
               real_data: RealData) -> Checked:
    """Checks 1-5 for one submission, the structural diff computed once (`check_submission`)."""
    parsed, malformed = parse_claim(claim)
    if parsed is None:
        return Checked([f"check 1: the claim cannot be read: {malformed}"])
    world_facts = {str(getattr(f, "fact_id", None) or (f.get("fact_id") if isinstance(f, Mapping) else ""))
                   for f in (getattr(world, "facts", None) or ())}
    failures, matched, missing = _check_structure(base, served, parsed, store, world_facts)
    failures += _check_shape(_fresh(matched, store), real_data)
    failures += _check_ids(matched, parsed, store, real_data)
    failures += _check_facts(served, parsed, store, missing)
    failures += _check_counts(parsed, store)
    return Checked(failures, matched)


def check_submission(base: Any, served: Any, claim: Any, *, world: Any, store: CheckStore,
                     real_data: RealData) -> list[str]:
    """Every failure of checks 1-5 for one submission, each naming its check; `[]` passes.

    `world` is the served world (its `facts` give the fact ids a claim may name), `store` the
    world's frozen and staged state plus the side-query door, `real_data` this world's real
    answers. The host gate and the oracle's `check` tool both call this (through
    `run_checks`)."""
    return run_checks(base, served, claim, world=world, store=store,
                      real_data=real_data).failures
