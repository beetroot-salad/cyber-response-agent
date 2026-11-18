"""The five host checks every oracle submission passes before anything is served (#1224, M4)."""
from __future__ import annotations

import copy
import difflib
import hashlib
import json
import re
from collections import Counter
from collections.abc import Callable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import Any

from defender._untrusted import wrap_fresh
from defender.records.formats import FORK_FACT_ID

#: A hand-in's keys (#1543): its patch on the base answer, the forged columns that name real
#: entities, and the optional proofs of its removals. Anything else is a hand-in the host
#: cannot read, and fails check 1.
HANDIN_KEYS = ("patch", "entity_refs", "proofs")
#: The JSON Patch operations a hand-in may use: no `move` or `copy`, which carry no fact.
PATCH_OPS = ("add", "remove", "replace", "test")
#: The reserved `fact_id` of a change that rolls the answer back to how it stood at the branch
#: point (undoing what happened after it, such as the source run's own later writes), rather
#: than serving one of the world's facts: open to every world, the control world included, for
#: a remove or replace only; a forged row always serves a world fact.
FORK_FACT = FORK_FACT_ID
#: The most characters of one rendered row or value.
_RENDER_CAP = 2000

#: Values that stand for "no value" and are never ids (check 3).
_PLACEHOLDERS = frozenset({"", "-", "--", "0", "none", "null", "n/a", "na", "unknown", "nil"})
_UUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_LONG_HEX = re.compile(r"^[0-9a-fA-F]{16,}$")
#: Column names that are ids by themselves (compared without case; check 3).
_ID_WORDS = frozenset({"id", "pid", "ppid", "uid", "gid", "sid", "tid", "uuid", "guid", "hash"})
#: Name endings that make a column an id column (compared without case).
_ID_SUFFIXES = ("_id", "-id", ".id", "_hash", "-hash", ".hash", "uuid", "guid")
#: A camelCase id suffix (`userId`, `hostID`): a lower-case letter or digit, then `Id` / `ID`.
_CAMEL_ID = re.compile(r"[a-z0-9](Id|ID)$")


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
        #: top-level mapping; the flat rows carrying each value's text; the real identifiers
        #: (check 3): each text a value had in an id-like position (`_id_like`), with the
        #: flat rows holding it there (a UUID / long-hex scalar outside any row is an id with
        #: no row); the cells of each `(system, table path)` table's rows (answers only, not
        #: loose values).
        self.values: set[str] = set()
        self.maps: list[dict] = []
        self.by_value: dict[str, list[dict]] = {}
        self.by_id: dict[str, list[dict]] = {}
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
        for value in _scalars(payload):
            text = _value_text(value)
            self.values.add(text)
            if _id_like("", value):
                self.by_id.setdefault(text, [])
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
            leaves = list(_leaves(flat))
            for text in {_value_text(v) for _c, v in leaves}:
                self.by_value.setdefault(text, []).append(flat)
            for text in {_value_text(v) for c, v in leaves if _id_like(c, v)}:
                self.by_id.setdefault(text, []).append(flat)
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



@dataclass
class Handin:
    """A parsed hand-in (#1543): the patch on the call's base answer, the forged columns that
    name real entities, and the optional proofs backing its removals."""

    ops: list[dict]
    entity_refs: list[dict]
    proofs: list[dict]

    @property
    def added(self) -> list[dict]:
        """The forged rows the patch serves: `{forged_id, fact_id}` per operation that adds a
        row or replaces a whole one (`apply_handin` refuses a whole-row replace without one)."""
        return [{"forged_id": op["forged_id"], "fact_id": op["fact_id"]}
                for op in self.ops if op["op"] in ("add", "replace") and "forged_id" in op]


class PatchRefused(Exception):
    """A hand-in whose patch cannot be applied to the call's base: a bad path, a failed `test`,
    or an operation the row model refuses (`apply_handin`)."""


# --------------------------------------------------------------------------------------------
# The hand-in document: a JSON Patch (RFC 6902) on the base answer.
# --------------------------------------------------------------------------------------------


def parse_handin(document: Any) -> tuple[Handin | None, str | None]:  # noqa: C901, PLR0912 — one validation per key and operation member, each refusing with its own reason
    """The hand-in's structured parts, or why it is not a hand-in the host can read. Every
    operation but a `test` names the world fact it serves; an `add` adds one forged row."""
    if not isinstance(document, Mapping):
        return None, "the hand-in is not a mapping"
    unknown = sorted(str(k) for k in document if k not in HANDIN_KEYS)
    if unknown:
        return None, f"the hand-in carries fields the host does not know: {unknown}"
    parts: dict[str, list[dict]] = {}
    for key in HANDIN_KEYS:
        entries = document.get(key) or []
        if not isinstance(entries, list) or not all(isinstance(e, Mapping) for e in entries):
            return None, f"its {key!r} is not a list of entries"
        parts[key] = [dict(e) for e in entries]
    for i, op in enumerate(parts["patch"]):
        kind = op.get("op")
        if kind not in PATCH_OPS:
            return None, (f"patch operation {i} is {kind!r}: the operations are "
                          f"{', '.join(PATCH_OPS)} (no move or copy)")
        if not isinstance(op.get("path"), str):
            return None, f"patch operation {i} needs a string path (a JSON Pointer)"
        if kind != "test" and not isinstance(op.get("fact_id"), str):
            return None, f"patch operation {i} ({kind}) needs the fact_id of the fact it serves"
        if kind == "test" and "value" not in op:
            return None, f"patch operation {i} (test) needs a value"
        if "forged_id" in op and not (isinstance(op["forged_id"], str) and op["forged_id"]):
            return None, f"patch operation {i} has a forged_id that is not a non-empty string"
        if kind == "add" and "forged_id" not in op:
            return None, (f"patch operation {i} is an add without a forged_id: an add adds one "
                          "forged row to a table (to change a value, replace it)")
        if kind == "replace" and "value" not in op and "forged_id" not in op:
            return None, f"patch operation {i} (replace) needs a value"
    for entry in parts["entity_refs"]:
        if not all(isinstance(entry.get(k), str) for k in ("forged_id", "column", "entity")):
            return None, "an `entity_refs` entry needs string forged_id, column and entity"
    for proof in parts["proofs"]:
        if not (isinstance(proof.get("system"), str) and isinstance(proof.get("verb"), str)
                and isinstance(proof.get("params", {}), Mapping)):
            return None, "a proof needs a system, a verb and a params mapping"
    return Handin(ops=parts["patch"], entity_refs=parts["entity_refs"],
                  proofs=parts["proofs"]), None


_Names = list[str] | None


@dataclass
class Change:
    """One patch operation as the host applied it, placed by the base's table map and kept
    whole (never cut: `shown_changes` cuts it for display). `row_at` is the pointer of the row
    it lands in (`[]` outside any table), `table` that table's identity as `tables()` names it,
    `names` its ES|QL column names, `rest` the pointer inside the row (`[]`: the whole row)."""

    op: dict
    row_at: list[str]
    table: _Path
    names: _Names
    rest: list[str]
    #: The operation lands where a row sits but edits no row: a bare (scalar) list item, or a
    #: row replaced by its equal (no new row is served, so none is forged).
    item: bool = False
    row_before: Any = None
    row_after: Any = None
    before: Any = None
    after: Any = None
    record_before: Any = None
    record_after: Any = None

    @property
    def whole_row(self) -> bool:
        return bool(self.row_at) and not self.rest and not self.item


@dataclass
class Applied:
    """A patch applied to a base, once: the served answer and each operation's change."""

    served: Any
    changes: list[Change]

    @property
    def forged(self) -> list[Change]:
        """The changes that serve a forged row: every add, and every whole-row replace."""
        return [c for c in self.changes
                if c.whole_row and c.op["op"] in ("add", "replace")]

    @property
    def removed(self) -> list[tuple[Any, _Names]]:
        """The rows the patch takes out of the base, with their table's ES|QL column names: a
        removed row (or bare list item), or the row a whole-row replace stands in for."""
        return [(c.row_before, c.names) for c in self.changes
                if c.row_at and not c.rest and (c.op["op"] == "remove"
                                                or (c.whole_row and c.op["op"] == "replace"))]


#: Turns a whole-row add or replace into the row the table serves (filling a frozen row in,
#: and staging it as forged): `(operation index, operation, table's ES|QL names) -> row`.
#: Raises `PatchRefused` to refuse the operation.
Stage = Callable[[int, dict, _Names], Any]


def table_row(row: Any, names: _Names, *, what: str) -> Any:
    """`row` in the shape its table serves: in an ES|QL table, a value array in the table's
    column order (a mapping must carry exactly the table's columns); elsewhere as it is."""
    if names is None or not isinstance(row, Mapping):
        return copy.deepcopy(row)
    if set(row) != set(names):
        raise PatchRefused(f"{what} has columns {sorted(row)}; this ES|QL table's are {names}: a "
                           "row is served only where the query projects exactly its columns")
    return [copy.deepcopy(row[n]) for n in names]


def _given_value(i: int, op: dict, names: _Names) -> Any:
    if "value" not in op:
        raise PatchRefused(f"patch operation {i} gives no value, and no frozen row fills it in")
    return table_row(op["value"], names, what=f"patch operation {i}'s row")


def _pointer_tokens(i: int, path: str) -> list[str]:
    import jsonpointer

    try:
        return list(jsonpointer.JsonPointer(path).parts)
    except jsonpointer.JsonPointerException as bad:
        raise PatchRefused(f"patch operation {i} has a path that is no JSON Pointer: "
                           f"{bad}") from None


@dataclass(frozen=True)
class _TableAt:
    """One table of an answer: its identity (`tables()`'s path: mapping keys, no list index)
    and its ES|QL column names."""

    path: _Path
    names: _Names


@dataclass
class TableMap:
    """Where an answer's rows are, read once from the base by the same walk as `tables()`: each
    outermost table by the pointer of the list holding its rows, and the ES|QL column lists, which
    follow the query and are never patched. A list of rows inside a row is part of that row."""

    tables: dict[tuple[str, ...], _TableAt]
    fixed: set[tuple[str, ...]]

    def locate(self, tokens: list[str]) -> tuple[list[str], _TableAt | None, list[str]]:
        """`(row pointer, its table, pointer inside the row)` for `tokens`, or `([], None,
        tokens)` outside every table."""
        for k in range(len(tokens)):
            table = self.tables.get(tuple(tokens[:k]))
            if table is not None:
                return list(tokens[:k + 1]), table, list(tokens[k + 1:])
        return [], None, list(tokens)

    def in_fixed(self, tokens: list[str]) -> bool:
        return any(tuple(tokens[:len(f)]) == f for f in self.fixed)


def table_map(payload: Any) -> TableMap:
    """The `TableMap` of `payload`. A list is a table when it holds a mapping or is empty (a
    forged row may be added to it); an ES|QL answer's `values` is one, with its column names."""
    out = TableMap(tables={}, fixed=set())

    def walk(node: Any, ptr: tuple[str, ...], path: _Path) -> None:
        if isinstance(node, Mapping):
            names = esql_names(node)
            for key, value in node.items():
                at = (*ptr, str(key))
                if names is not None and key == "values":
                    out.tables[at] = _TableAt((*path, "values"), names)
                elif names is not None and key == "columns":
                    out.fixed.add(at)
                else:
                    walk(value, at, (*path, str(key)))
        elif isinstance(node, list):
            if not node or any(isinstance(x, Mapping) for x in node):
                out.tables[ptr] = _TableAt(path, None)
                return
            for i, item in enumerate(node):
                walk(item, (*ptr, str(i)), path)   # a list of lists: one table, as `tables()`

    walk(payload, (), ())
    return out


def _at(doc: Any, tokens: list[str]) -> Any:
    node = doc
    for token in tokens:
        if isinstance(node, Mapping):
            node = node.get(token)
        elif isinstance(node, list) and token.isdigit() and int(token) < len(node):
            node = node[int(token)]
        else:
            return None
    return node


def _record_fields(doc: Mapping[str, Any]) -> dict:
    """A top-level document's own fields, its lists left out: the record a change outside any
    list belongs to."""
    return {k: copy.deepcopy(v) for k, v in doc.items() if not isinstance(v, list)}


def _shape_kind(value: Any) -> str:
    if isinstance(value, Mapping):
        return "mapping"
    if isinstance(value, list):
        return "list"
    return "scalar"


def _holds_rows(value: Any) -> bool:
    """Whether `value` holds a table: a list whose items are mappings or value arrays."""
    if isinstance(value, Mapping):
        return any(_holds_rows(v) for v in value.values())
    if isinstance(value, list):
        return any(isinstance(v, (Mapping, list)) for v in value) or False
    return False


def _field_refusal(i: int, op: dict, doc: Any, tokens: list[str], change: Change) -> str | None:
    """Why an operation on a value (inside a row, a bare list item, or outside any table) is
    refused: it would change the answer's shape."""
    kind, path = op["op"], op["path"]
    if not tokens and (kind != "replace" or _shape_kind(doc) != "scalar"):
        return (f"patch operation {i} ({kind}) targets the whole answer: a patch changes its "
                "parts (only a bare scalar answer is replaced whole)")
    if kind == "add":
        return (f"patch operation {i} adds at {path!r}, inside a row or outside any table: an "
                "add adds a whole row to a table; to change a value, replace it")
    parent = _at(doc, tokens[:-1])
    if kind == "remove" and (not isinstance(parent, list)
                             or _shape_kind(_at(doc, tokens)) != "scalar"
                             or (change.names is not None and len(change.rest) == 1)):
        return (f"patch operation {i} removes {path!r}, a key, an ES|QL cell or a list item that "
                "is no row: that changes the answer's shape; replace its value instead")
    if kind == "replace":
        before, after = _at(doc, tokens), op["value"]
        if _holds_rows(before) or _holds_rows(after):
            return (f"patch operation {i} replaces {path!r}, which holds rows: rows change only "
                    "row by row (remove, add or replace each one)")
        if _shape_kind(before) != _shape_kind(after) or (
                isinstance(before, Mapping) and set(before) != set(after)):
            return (f"patch operation {i} replaces {path!r} with a value of another shape: a "
                    "field keeps its kind and, for a mapping, its keys")
    return None


def apply_handin(base: Any, handin: Handin, *, stage: Stage | None = None) -> Applied:  # noqa: C901, PLR0912 — one arm per kind of operation the row model reads
    """`handin`'s patch applied to a copy of `base`, one operation at a time, read through the
    row model as it goes. A whole-row `add` or `replace` serves a forged row (`stage` gives the
    row; a whole-row replace without a forged_id is refused: it stands in for a new row). Any
    other operation edits a value: it keeps the answer's shape and never touches a row this
    patch forges. `PatchRefused` names the first operation that cannot apply."""
    import jsonpatch
    import jsonpointer

    stage = stage or _given_value
    tmap = table_map(base)
    doc = copy.deepcopy(base)
    forged_rows: set[int] = set()
    changes: list[Change] = []
    for i, given in enumerate(handin.ops):
        op = dict(given)
        tokens = _pointer_tokens(i, op["path"])
        if op["op"] != "test" and tmap.in_fixed(tokens):
            raise PatchRefused(f"patch operation {i} changes an ES|QL answer's columns at "
                               f"{op['path']!r}: they follow the query (re-ask it instead)")
        row_at, table, rest = tmap.locate(tokens)
        names = table.names if table is not None else None
        if row_at and row_at[-1] == "-":
            held = _at(doc, row_at[:-1])
            row_at = [*row_at[:-1], str(len(held) if isinstance(held, list) else 0)]
        change = Change(op=op, row_at=row_at, table=table.path if table is not None else (),
                        names=names, rest=rest)
        if row_at and not rest and op["op"] != "add":
            held = _at(doc, row_at)
            change.item = not (isinstance(held, Mapping)
                               or (names is not None and isinstance(held, list))) or (
                op["op"] == "replace" and "forged_id" not in op and "value" in op
                and _row_text(op["value"], names) == _row_text(held, names))
        if op["op"] not in ("test", "add") and row_at and id(_at(doc, row_at)) in forged_rows:
            raise PatchRefused(f"patch operation {i} changes a row this patch forges: a forged "
                               "row is served as it is forged")
        if op["op"] != "test":
            if change.whole_row and op["op"] == "replace" and "forged_id" not in op:
                raise PatchRefused(f"patch operation {i} replaces the whole row {op['path']!r}: "
                                   "that serves a new row, so it needs a forged_id (or replace "
                                   "only the values that change)")
            if not change.whole_row:
                why = _field_refusal(i, op, doc, tokens, change)
                if why is not None:
                    raise PatchRefused(why)
                if "forged_id" in op:
                    raise PatchRefused(f"patch operation {i} names a forged_id but changes a "
                                       "value, not a whole row")
            if change.whole_row and op["op"] in ("add", "replace"):
                op["value"] = stage(i, op, names)
        if row_at:
            change.row_before = copy.deepcopy(_at(doc, row_at)) if op["op"] != "add" else None
        else:
            change.before = copy.deepcopy(_at(doc, tokens))
            if tokens and isinstance(doc, Mapping):
                change.record_before = _record_fields(doc)
        try:
            doc = jsonpatch.JsonPatch([_rfc_op(op)]).apply(doc, in_place=True)
        except (jsonpatch.JsonPatchException, jsonpointer.JsonPointerException,
                TypeError, ValueError, IndexError, KeyError) as failed:
            raise PatchRefused(f"patch operation {i} ({op['op']} at {op['path']!r}) cannot "
                               f"apply: {failed}") from None
        if row_at and op["op"] != "remove":
            change.row_after = copy.deepcopy(_at(doc, row_at))
            if change.whole_row and op["op"] != "test":
                forged_rows.add(id(_at(doc, row_at)))
        elif not row_at and op["op"] != "remove":
            change.after = copy.deepcopy(op.get("value"))
            if tokens and isinstance(doc, Mapping):
                change.record_after = _record_fields(doc)
        changes.append(change)
    return Applied(served=doc, changes=changes)


def _rfc_op(op: Mapping[str, Any]) -> dict:
    """An operation as RFC 6902 reads it: the host's own members (fact_id, forged_id) left out."""
    return {k: v for k, v in op.items() if k in ("op", "path", "value")}


def _cells(row: Any, names: _Names) -> Any:
    return as_row(row, names) or row


def render_changes(applied: Applied, handin: Handin, *, query: Mapping[str, Any],  # noqa: C901 — one arm per part of a change's view
                   base_was: str, proven: set[str] | None = None) -> dict:
    """The hand-in seen through the call's own query, whole: each operation with its fact,
    where it lands (the table, the row, an ES|QL column by name, or a field) and the row before
    and after it. A removed row a proof selects is `proven`. The ledger label reads it whole;
    what the oracle's `check` shows, the verifier judges and the answer stores is
    `shown_changes` of it."""
    proven = proven or set()
    out: list[dict] = []
    for c in applied.changes:
        op = c.op
        entry: dict[str, Any] = {"op": op["op"], "path": op["path"]}
        if op["op"] != "test":
            entry["fact_id"] = op["fact_id"]
        if "forged_id" in op:
            entry["forged_id"] = op["forged_id"]
        if c.row_at:
            entry["table"] = "/".join(c.table) or "the top level"
            entry["row_index"] = int(c.row_at[-1]) if c.row_at[-1].isdigit() else c.row_at[-1]
        if c.names is not None and c.rest and c.rest[0].isdigit() and int(c.rest[0]) < len(c.names):
            entry["column"] = c.names[int(c.rest[0])]
        elif c.rest:
            entry["field"] = "/".join(c.rest)
        if op["op"] in ("remove", "replace"):
            if c.row_at:
                entry["row_before"] = _cells(c.row_before, c.names)
            else:
                entry["before"] = c.before
                if c.record_before is not None:
                    entry["record_before"] = c.record_before
        if op["op"] in ("add", "replace"):
            if c.row_at:
                entry["row_after"] = _cells(c.row_after, c.names)
            else:
                entry["after"] = c.after
                if c.record_after is not None:
                    entry["record_after"] = c.record_after
        if c.row_at and not c.rest and (op["op"] == "remove" or c.whole_row and op["op"] == "replace"):
            entry["proven"] = _row_text(c.row_before, c.names) in proven
        out.append(entry)
    return {"query": dict(query), "base": base_was, "changes": out,
            "entity_refs": [dict(e) for e in handin.entity_refs],
            "proofs": [dict(p) for p in handin.proofs]}


#: The rendered parts of a change that `shown_changes` bounds.
_SHOWN_PARTS = ("row_before", "row_after", "before", "after", "record_before", "record_after")


def _shown_value(value: Any, cap: int = _RENDER_CAP) -> Any:
    text = canonical_json(value)
    return value if len(text) <= cap else f"{text[:cap]} ... [cut: {len(text)} characters]"


#: The most characters all the shown changes of one hand-in take together.
_SHOWN_TOTAL_CAP = 60_000


def shown_changes(rendering: Mapping[str, Any]) -> dict:
    """A rendering (`render_changes`) as it is shown and stored: each row and value bounded,
    and the changes kept in order until they fill `_SHOWN_TOTAL_CAP`; how many were left out is
    said (`changes_not_shown`)."""
    entries = list(rendering.get("changes") or ())
    changes: list[dict] = []
    room = _SHOWN_TOTAL_CAP
    for entry in entries:
        shown = {k: (_shown_value(v) if k in _SHOWN_PARTS else v) for k, v in entry.items()}
        room -= len(canonical_json(shown))
        if room < 0 and changes:
            break
        changes.append(shown)
    out = {**rendering, "changes": changes}
    if len(changes) < len(entries):
        out["changes_not_shown"] = len(entries) - len(changes)
    return out


# --------------------------------------------------------------------------------------------
# Check 1: every operation serves a fact, every forged row is one the host staged.
# --------------------------------------------------------------------------------------------


#: A served forged row: its table, the served row (cells; an ES|QL row zipped), the forged
#: record.
_Matched = list[tuple[_Table, Any, Mapping[str, Any]]]


def _check_structure(applied: Applied, handin: Handin, store: CheckStore,
                     world_facts: set[str]) -> tuple[list[str], _Matched]:
    """Check 1: every operation serves one of the world's facts (or rolls back to the branch
    point, `FORK_FACT`), and every forged row it serves is one the host staged or froze. The
    patch's shape rules are `apply_handin`'s. Returns the failures and the served forged rows
    matched to their records (for checks 2 and 3)."""
    failures: list[str] = []
    for i, op in enumerate(handin.ops):
        if op["op"] == "test" or op["fact_id"] in world_facts:
            continue
        if op["fact_id"] == FORK_FACT and "forged_id" not in op:
            continue
        failures.append(f"patch operation {i} names fact {op['fact_id']!r}, which is not "
                        f"this world's" + (" (a forged row serves a world fact, never "
                                           f"{FORK_FACT!r})" if op["fact_id"] == FORK_FACT else ""))
    matched: _Matched = []
    for c in applied.forged:
        fid = c.op["forged_id"]
        record = store.forged(fid)
        if record is None:
            failures.append(f"forged row {fid!r} names no forged row")
            continue
        served_row = _cells(c.row_after, c.names)
        if _row_text(record.get("row"), c.names) != _row_text(served_row, c.names):
            failures.append(f"forged row {fid!r} is served with other content than it was "
                            "forged with")
            continue
        matched.append((_table(c.table, c.names), served_row, record))
    return [f"check 1: {f}" for f in failures], matched


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
    forged row's columns equal those of at least one real row of that table, and each value
    has a type real rows of that column set give the column. Equal, not a subset or superset:
    a forged row has the shape of a real row. Where none matches, the failure names the
    closest real column set's missing and extra columns."""
    failures: list[str] = []
    for table, element, record in matched:
        if not isinstance(element, Mapping):
            if table[1] is not None:
                # An ES|QL value array that did not zip: not one value per column.
                failures.append(f"check 2: forged row {record.get('forged_id')!r} is not one "
                                f"value per column of its ES|QL table {list(table[1])}")
            continue
        rows = real.rows.get((str(record.get("system")), table))
        if not rows:
            continue  # D2: no real example, nothing to compare
        fid, own = record.get("forged_id"), frozenset(element)
        shapes: dict[frozenset[str], list[dict]] = {}
        for r in rows:
            shapes.setdefault(frozenset(r), []).append(r)
        same = shapes.get(own)
        if same is None:
            closest = min(shapes, key=lambda cols: (len(cols ^ own), sorted(cols)))
            missing, extra = sorted(closest - own), sorted(own - closest)
            failures.append(
                f"check 2: forged row {fid!r} does not carry the columns of any real "
                f"{record.get('system')} row here ({len(shapes)} real column set(s); the "
                f"closest is missing {missing}, extra {extra}): a forged row's columns equal "
                "one real row's")
            continue
        types: dict[str, set[str]] = {}
        for r in same:
            for col, value in r.items():
                kind = _json_type(value)
                if kind is not None:
                    types.setdefault(col, set()).add(kind)
        wrong = sorted(col for col, value in element.items()
                       if _json_type(value) is not None and types.get(col)
                       and _json_type(value) not in types[col])
        if wrong:
            failures.append(f"check 2: forged row {fid!r} gives {wrong} a value type real rows "
                            "with its columns never carry")
    return failures


def id_column(column: str) -> bool:
    """A column whose name makes its values ids (check 3): exactly `id`; ending in `_id`,
    `-id`, `.id` or a camelCase `Id` (`userId`); a short id word (pid, ppid, uid, gid, sid,
    tid, uuid, guid, hash); or ending in `_hash`, `.hash`, `uuid` or `guid`. A nested column
    is named by its last dotted part too (`process.pid`). `valid`, `paid`, `android` are not."""
    if not column:
        return False
    last = column.rsplit(".", 1)[-1]
    lowered, last_lowered = column.lower(), last.lower()
    return (last_lowered in _ID_WORDS or lowered.endswith(_ID_SUFFIXES)
            or bool(_CAMEL_ID.search(last)))


def _id_like(column: str, value: Any) -> bool:
    if value is None or isinstance(value, bool) or _shape_kind(value) != "scalar":
        return False
    text = _value_text(value).strip()
    if text.lower() in _PLACEHOLDERS:
        return False
    return id_column(column) or bool(_UUID.match(text) or _LONG_HEX.match(text))


def _forged_leaves(element: Any) -> Iterator[tuple[str, Any]]:
    """A served forged row's scalars by flat column (`process.entity_id`); a forged item of a
    bare list has no column, and is judged by its value's shape alone."""
    yield from _leaves(flatten(element) if isinstance(element, Mapping) else {"": element})


def _check_ids(matched: _Matched, handin: Handin, store: CheckStore, real: RealData) -> list[str]:
    failures: list[str] = []
    for _t, element, record in _fresh(matched, store):
        fid = str(record.get("forged_id"))
        for column, value in _forged_leaves(element):
            if not _id_like(column, value) or _value_text(value) not in real.by_id:
                continue
            if _declared_reference(fid, column, value, handin, real):
                continue
            where = f" in column {column!r}" if column else ""
            failures.append(f"check 3: forged row {fid!r} reuses a real identifier{where} "
                            f"{wrap_fresh(_value_text(value), 'untrusted')}")
    return failures


@dataclass
class ReAsked:
    """A re-ask the host accepted and read (#1385): its question, the host's own answer to it,
    and the rows of the live base that answer drops. Made once, by the oracle's `re_ask` tool
    (`re_asked`), and carried from there: the answer is the attempt's base from then on, and the
    check, the verifier, the label and the commit all read this one value."""

    system: str
    verb: str
    params: dict
    answer: Any
    #: The live base's rows the re-asked answer lacks (`cut_rows`), computed once.
    dropped: list[Any] = field(default_factory=list)


def re_asked(live: Any, system: str, verb: str, params: Mapping[str, Any],
             answer: Any) -> ReAsked:
    """The accepted re-ask of `live` (the call's live base) that `answer` answers."""
    return ReAsked(system, verb, dict(params), answer, cut_rows(live, answer)[0])


@dataclass
class Checked:
    """One submission's host-check outcome: its failures (`[]` passes) and what check 1 found,
    so the collision record reuses the structural diff instead of recomputing it."""

    failures: list[str]
    matched: _Matched = field(default_factory=list)
    #: The removed rows' spellings some proof selects (check 5).
    proven: set[str] = field(default_factory=set)


def frozen_id_collisions(checked: Checked, *, store: CheckStore,
                         real_data: RealData) -> list[dict[str, Any]]:
    """Every identifier a FROZEN forged row serves in this answer that this world's real data
    carries as an identifier too (check 3's rule: the real value sat in an id-like column or is
    UUID / long-hex shaped), with the real rows (flat) carrying it there: the row stays frozen and is
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
            rows = [dict(m) for m in real_data.by_id.get(text, ())
                    if canonical_json(m) != own]
            if rows:
                found.append({"forged_id": fid, "column": column, "value": text,
                              "system": record.get("system"), "real_rows": rows[:3]})
    return found


def _declared_reference(fid: str, column: str, value: Any, handin: Handin,
                        real: RealData) -> bool:
    """The hand-in names this forged column a reference to an entity, and some real flat row
    carries that entity beside this very value in that column (looked up by value)."""
    text = canonical_json(value)
    for ref in handin.entity_refs:
        if ref["forged_id"] != fid or ref["column"] != column:
            continue
        entity = ref["entity"]
        for mapping in real.by_value.get(_value_text(value), ()):
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



def _check_facts(served: Any, handin: Handin, store: CheckStore) -> list[str]:
    failures: list[str] = []
    for (entity, field_), value in store.facts.items():
        if any(_contradicts(mapping, entity, field_, value) for mapping in _mappings(served)):
            failures.append(f"check 4: {wrap_fresh(entity, 'untrusted')}'s {field_!r} "
                            "is served with a value other than the recorded fact")
    for entry in handin.added:
        # Fresh or frozen, a row backs the fact it was forged for: the verifier is told the
        # operation's fact, and the commit keeps the forge record's.
        record = store.forged(entry["forged_id"])
        if record is not None and record.get("fact_id") != entry["fact_id"]:
            kind = "frozen" if entry["forged_id"] in store.frozen else "forged"
            failures.append(f"check 4: {kind} row {entry['forged_id']!r} was forged for fact "
                            f"{record.get('fact_id')!r}, not {entry['fact_id']!r}")
    return failures



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



def _check_proofs(handin: Handin, store: CheckStore,
                  removed: list[tuple[Any, _Names]]) -> tuple[list[str], set[str]]:
    """Check 5: each proof the hand-in names is re-run, and must select at least one row the
    patch removed. A proof is optional: a removal without one is judged by the verifier on the
    world's facts. Returns the failures and the removed rows' spellings some proof selects."""
    failures: list[str] = []
    proven: set[str] = set()
    for i, proof in enumerate(handin.proofs):
        try:
            answer = store.rerun(proof["system"], proof["verb"], dict(proof.get("params") or {}))
        except Refused as refused:
            failures.append(f"check 5: proof {i} could not be re-run: "
                            f"{wrap_fresh(str(refused), 'untrusted')}")
            continue
        rows, names = _selected(answer)
        selected = {canonical_json(r) for r in rows} | {_row_text(r, names) for r in rows}
        hits = {_row_text(r, own) for r, own in removed
                if _row_text(r, own) in selected or canonical_json(r) in selected}
        if not hits:
            failures.append(f"check 5: proof {i} selects {len(rows)} row(s), none of them a row "
                            "the patch removes")
        proven |= hits
    return failures, proven


def cut_rows(live: Any, re_asked: Any) -> tuple[list[Any], list[Any]]:
    """`(dropped, brought_in)`: the rows the live base has that the re-asked answer lacks, and the
    older rows the re-asked answer has that the live base lacks (#1385 A3)."""
    dropped: list[Any] = []
    brought_in: list[Any] = []
    _row_diff(live, re_asked, dropped, brought_in)
    # A row the re-ask only reorders reads as removed at one place and added at another: it is
    # neither dropped nor brought in. Cancel each such pair, one for one (a multiset).
    kept = Counter(canonical_json(row) for row in dropped)
    kept &= Counter(canonical_json(row) for row in brought_in)
    if not kept:
        return dropped, brought_in
    return _less_reordered(dropped, Counter(kept)), _less_reordered(brought_in, Counter(kept))


def _less_reordered(rows: list[Any], cancel: Counter[str]) -> list[Any]:
    """`rows` less the first `cancel[text]` rows of each canonical spelling, order kept."""
    out: list[Any] = []
    for row in rows:
        text = canonical_json(row)
        if cancel[text] > 0:
            cancel[text] -= 1
        else:
            out.append(row)
    return out


def _zipped(node: Mapping[str, Any], names: list[str]) -> dict:
    """An ES|QL answer with its value arrays zipped into rows of named cells."""
    return {**node, "values": [as_row(v, names) or v for v in node["values"]]}


def _row_diff(base: Any, other: Any, removed: list[Any], added: list[Any]) -> None:
    """The rows `base` has that `other` lacks (`removed`) and the reverse (`added`), table by
    table: two real answers compared, an ES|QL table's rows as named cells."""
    if isinstance(base, Mapping) and isinstance(other, Mapping):
        names = esql_names(base)
        if names is not None and names == esql_names(other):
            base, other = _zipped(base, names), _zipped(other, names)
        for key in sorted(set(base) & set(other), key=str):
            _row_diff(base[key], other[key], removed, added)
    elif isinstance(base, list) and isinstance(other, list):
        a = [canonical_json(x) for x in base]
        b = [canonical_json(x) for x in other]
        for op, i1, i2, j1, j2 in difflib.SequenceMatcher(a=a, b=b, autojunk=False).get_opcodes():
            if op != "equal":
                removed.extend(base[i1:i2])
                added.extend(other[j1:j2])


def _world_fact_ids(world: Any) -> set[str]:
    return {str(getattr(f, "fact_id", None) or (f.get("fact_id") if isinstance(f, Mapping) else ""))
            for f in (getattr(world, "facts", None) or ())}


def run_checks(applied: Applied, handin: Handin, *, world: Any, store: CheckStore,
               real_data: RealData) -> Checked:
    """Checks 1-5 for one hand-in, its patch already applied to the call's base (or the answer
    of the attempt's accepted re-ask, #1385)."""
    failures, matched = _check_structure(applied, handin, store, _world_fact_ids(world))
    failures += _check_shape(_fresh(matched, store), real_data)
    failures += _check_ids(matched, handin, store, real_data)
    failures += _check_facts(applied.served, handin, store)
    proofs, proven = _check_proofs(handin, store, applied.removed)
    failures += proofs
    return Checked(failures, matched, proven)


def frozen_stage(store: CheckStore) -> Stage:
    """The `Stage` of rows already in `store` (staged or frozen): a row given whole is served as
    given; an add with no value serves the frozen row of its forged_id."""
    def stage(i: int, op: dict, names: _Names) -> Any:
        if "value" in op:
            return _given_value(i, op, names)
        record = store.frozen.get(op["forged_id"])
        if record is None:
            raise PatchRefused(f"patch operation {i} adds {op['forged_id']!r} with no value, and "
                               "no row of that id is frozen in this world")
        return table_row(record.get("row"), names, what=f"frozen row {op['forged_id']!r}")
    return stage


def check_submission(base: Any, handin: Any, *, world: Any, store: CheckStore,
                     real_data: RealData) -> list[str]:
    """Every failure of one hand-in (a document `{patch, entity_refs, proofs}`), each naming
    its check; `[]` passes. A hand-in the host cannot read or apply fails check 1."""
    parsed, why = parse_handin(handin)
    if parsed is None:
        return [f"check 1: the hand-in cannot be read: {why}"]
    try:
        applied = apply_handin(base, parsed, stage=frozen_stage(store))
    except PatchRefused as refused:
        return [f"check 1: {refused}"]
    return run_checks(applied, parsed, world=world, store=store, real_data=real_data).failures
