"""The golden corpus is re-encoded into production's ES|QL shape (#1054).

Written BEFORE the migration exists, against the design posted on the issue. #842
switched the production `esql` verb to the wire's own positional rows and routed
`controls.py` through the same shaper, but the committed corpus under
`cases/*/hidden/` was never migrated — so a rerun of `controls.py` (which
`known_defects.yaml`'s own `repair:` notes instruct) regenerates the controls half
columnar while the observed half stays dict-row, and `judge.load_lead_inputs` builds
ONE prompt carrying two encodings of the same data.

The obligations these tests pin, in the issue's numbering:

  O1  every ES|QL payload a judge prompt can reach is positional — rows are lists of
      length `len(columns)`, never lists of dicts. The guard itself lives in
      `tests/evals/test_controls.py` (M2) beside the shaper pin it protects; what is
      here is the migration that makes it true and the round-trip that makes it safe.
  O2  the re-encode is lossless: re-zipping by `columns[].name` reproduces the
      original dict rows — same keys, same key ORDER, same values — and `query`,
      `columns` and `row_count` do not move.
  O3  the rewrite is reviewable: a file keeps its own serialization, and a file with
      no dict-row payload is byte-identical afterwards.
  O4  nothing is re-scored: `labels/`, `scores/`, `audits/*.json` and
      `held_out_ledger.yaml` are untouched, and the provenance of that decision is
      written down where the tag discipline lives.
  O5  a later `controls.py` rerun cannot re-split the corpus: the migration is
      idempotent and O1's guard catches any regression.

FIXTURE POLICY. Every payload literal below is a REAL corpus payload, copied verbatim
from the tree as it stood at 3249dffb (pre-migration), with its source path named.
They are embedded rather than read from `cases/` at test time on purpose: the corpus is
exactly what the migration rewrites, so after M1 lands there is no dict-row payload left
on disk to build a dict-row fixture from, and a test that sourced one would quietly stop
testing anything.

---------------------------------------------------------------------------------------
CONTRACT ASSUMED OF `defender/evals/oracle_golden/migrate_esql_encoding.py` (M1)
---------------------------------------------------------------------------------------
The script does not exist yet. This is the surface these tests were written against; an
implementer who wants a different one has to change these tests deliberately, which is
the point of writing them first.

CLI
  python defender/evals/oracle_golden/migrate_esql_encoding.py [--cases-dir DIR]

  `--cases-dir` defaults to `<the script's own package>/cases`, so the committed,
  replayable form is the bare command. The flag exists only so the migration can be
  driven over a temp copy of the tree, which is how O3 and O4 are observed at all.
  `main(argv: list[str] | None = None) -> int` returns 0 and prints what it rewrote.

API
  is_esql_payload(obj) -> bool
      True for a dict carrying ALL FOUR of `query`, `columns`, `row_count`, `values`.
      This four-key shape is the classifier everywhere — never an enumerated list of
      document positions. An enumerated sweep is what produced this issue.

  to_columnar(payload) -> dict
      A NEW payload whose `values` are positional rows. Every other key keeps its value
      AND the payload dict keeps its key order, because anything else moves bytes
      outside `values` (O2/O3). A payload whose rows are already lists, or whose
      `values` is empty, comes back equal to its input (O5 idempotence, c9).
      Raises ValueError — message naming "column" — when a row's key list is not
      exactly `[c["name"] for c in payload["columns"]]`. A row is never reordered or
      filled in to make it fit.

  to_dict_rows(payload) -> dict
      The inverse: positional rows re-zipped to dicts in `columns` order. This is the
      round-trip half of O2 and the migration runs it on every payload it rewrites.

  migrate_file(path: Path) -> int
      Rewrites one JSON file in place; returns the number of payloads rewritten.
      A zero-byte file is skipped and returns 0. A file with nothing to migrate is not
      written at all — byte-identical, not re-serialized (O3). A rewritten file keeps
      its own serialization, which is whichever of
          json.dumps(doc)  |  json.dumps(doc, indent=2)  |  json.dumps(doc, indent=2)+"\\n"
      reproduces the file's ORIGINAL bytes; if none does, it raises ValueError — message
      naming "serializ" — and leaves the file untouched rather than reformatting it.

  migrate_tree(cases_dir: Path) -> tuple[int, int]
      `(files_rewritten, payloads_rewritten)` over `cases_dir/*/hidden/observed/**/*.json`
      and `cases_dir/*/hidden/controls/**/*.json`. Idempotent: a second call over an
      already-migrated tree returns `(0, 0)` and writes no file.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path
from typing import Any

import pytest

from defender.evals.oracle_golden import migrate_esql_encoding as MIGRATE

DEFENDER_DIR = Path(__file__).resolve().parents[2]
GOLDEN_DIR = DEFENDER_DIR / "evals" / "oracle_golden"
CASES_DIR = GOLDEN_DIR / "cases"
MIGRATION_SCRIPT = GOLDEN_DIR / "migrate_esql_encoding.py"
REPO_ROOT = DEFENDER_DIR.parent

#: main's tip immediately before #1054's migration landed — the commit the design doc's own
#: fixture-provenance comments already cite ("copied verbatim from the tree as it stood at
#: 3249dffb"). The one anchor in this module that is NOT self-referential: every other O2
#: check compares the migration's output to a fixture THIS FILE built, or to a re-zip of
#: whatever is on disk NOW — either of which a transform that corrupts the corpus
#: consistently with itself (a reversed cell order, a silent truncation to `values: []`)
#: would satisfy just as well. This doesn't: it reads the dict-row bytes git actually has
#: for this ref, independent of whatever `migrate_tree` did to the tree since.
PRE_MIGRATION_REF = "3249dffb"


# ---------------------------------------------------------------------------------
# Real corpus fixtures, copied verbatim from the pre-migration tree.
# ---------------------------------------------------------------------------------

#: `cases/case-012-bruteforce-db1/hidden/observed/l-007/8.json`, compact one-line form.
#: Three columns, three rows, dotted column names and a `null` cell — the shapes a
#: re-encode can get wrong (a missing key vs. a stored null are different facts).
REAL_OBSERVED_TEXT = (
    '{"query": "FROM logs-system.auth-*\\n| WHERE @timestamp >= \\"2026-07-20T09:59:11Z\\"'
    ' AND @timestamp < \\"2026-07-27T09:59:11Z\\"\\n        AND host.name == \\"web-2\\"\\n'
    '        AND (source.ip == \\"172.18.0.16\\" OR host.ip == \\"172.18.0.16\\")\\n'
    '| STATS events = COUNT(*) BY event.outcome, data_stream.dataset\\n| SORT events DESC",'
    ' "columns": [{"name": "events", "type": "long"}, {"name": "event.outcome", "type":'
    ' "keyword"}, {"name": "data_stream.dataset", "type": "keyword"}], "row_count": 3,'
    ' "values": [{"events": 431, "event.outcome": null, "data_stream.dataset":'
    ' "system.auth"}, {"events": 24, "event.outcome": "failure", "data_stream.dataset":'
    ' "system.auth"}, {"events": 10, "event.outcome": "success", "data_stream.dataset":'
    ' "system.auth"}]}'
)

#: The positional form the same payload must hold after the migration. Written out by
#: hand rather than derived, so this test says what the answer IS: cell `i` is the value
#: of `columns[i].name`, `null` survives as a cell and not as an absence.
EXPECTED_POSITIONAL_ROWS = [
    [431, None, "system.auth"],
    [24, "failure", "system.auth"],
    [10, "success", "system.auth"],
]

#: `cases/case-007-lotl-web1/hidden/observed/l-006/5.json` — a real ES|QL payload with
#: `values: []`. 471 of these are on disk and they read identically in either encoding.
REAL_EMPTY_ESQL_TEXT = (
    '{"query": "FROM logs-falco.alerts-*\\n| WHERE host.name == \\"web-1\\"\\n'
    '| STATS count = COUNT(*)\\n        BY data_stream.dataset\\n| SORT count DESC",'
    ' "columns": [{"name": "count", "type": "long"}, {"name": "data_stream.dataset",'
    ' "type": "keyword"}], "row_count": 0, "values": []}'
)

#: `cases/case-001-ssh-bruteforce-canary/hidden/observed/l-003/0.json` — a cmdb host
#: record. Not `esql_payload` output; the judge already reads it as a foreign shape.
REAL_CMDB_TEXT = (
    '{"name": "canary-1", "role": "canary", "criticality": "sandbox", "owner":'
    ' "team.sre", "change_window": null, "os": {"distro": "ubuntu", "version": "22.04"},'
    ' "service": null, "trust_edges_out": [], "users": [{"username": "svc.monitoring",'
    ' "shell": "/usr/sbin/nologin", "sudo": false}, {"username": "svc.config-mgmt",'
    ' "shell": "/bin/bash", "sudo": true}]}'
)

#: `cases/case-002-authorized-keys-falco/hidden/observed/l-002/0.json` — a state-lookup
#: stub, and one of the nine hand-authored files written `indent=2` with NO trailing
#: newline. Two shapes to preserve in one fixture.
REAL_STATE_STUB_TEXT = (
    '{\n  "_note": "state lookup",\n  "params": {\n    "host": "canary-1"\n  }\n}'
)

#: The serializations every hidden file is reproduced by (census: 526 compact, 342
#: indent=2+newline, 9 indent=2, 80 zero-byte, 0 unmatched).
SERIALIZATIONS = {
    "compact": lambda doc: json.dumps(doc),
    "indent2": lambda doc: json.dumps(doc, indent=2),
    "indent2+newline": lambda doc: json.dumps(doc, indent=2) + "\n",
}


def real_observed_payload() -> dict:
    """A fresh copy of the real dict-row payload — never a shared mutable module global."""
    return json.loads(REAL_OBSERVED_TEXT)


def real_control_record() -> dict:
    """A real control record's shape, after `cases/case-005-cross-tier-probe-db1/hidden/
    controls/l-005/3.json`: three named windows, one of them levered down (`live: false`,
    `payload: null`), plus an `attack_contribution`.

    `attack_contribution.payload` never reaches a judge prompt — `load_lead_inputs` builds
    `baseline` from `controls` only — but it is `esql_payload` output living in `hidden/`,
    so O2/O5 hold it to the same encoding and the migration must reach it.
    """
    query = 'FROM logs-*\n| WHERE host.ip == "172.18.0.11"\n| STATS BY host.name'
    return {
        "lead_id": "l-005",
        "seq": 3,
        "controls": [
            {"name": "C-7d", "window": ["2026-07-19T10:34:24.500Z",
                                        "2026-07-19T11:34:24.500Z"],
             "query": query, "live": False, "payload": None},
            {"name": "C-14d", "window": ["2026-07-12T10:34:24.500Z",
                                         "2026-07-12T11:34:24.500Z"],
             "query": query, "live": True, "payload": real_observed_payload()},
            {"name": "C-21d", "window": ["2026-07-05T10:34:24.500Z",
                                         "2026-07-05T11:34:24.500Z"],
             "query": query, "live": True, "payload": json.loads(REAL_EMPTY_ESQL_TEXT)},
        ],
        "attack_contribution": {
            "window": ["2026-07-26T11:04:03.000Z", "2026-07-26T11:04:46.000Z"],
            "query": query,
            "payload": real_observed_payload(),
        },
    }


# ---------------------------------------------------------------------------------
# The test's OWN reading of the corpus — deliberately not the migration's, so a bug
# shared by both cannot pass. Named apart from the guard's helpers in test_controls.py
# for the same reason: two independent readings of one invariant.
# ---------------------------------------------------------------------------------

ESQL_KEYS = ("query", "columns", "row_count", "values")


def _looks_like_esql(obj: Any) -> bool:
    return isinstance(obj, dict) and all(k in obj for k in ESQL_KEYS)


def _esql_payloads_anywhere(doc: Any):
    """Every ES|QL payload at any depth, classified by shape rather than by position."""
    if isinstance(doc, dict):
        if _looks_like_esql(doc):
            yield doc
        for value in doc.values():
            yield from _esql_payloads_anywhere(value)
    elif isinstance(doc, list):
        for value in doc:
            yield from _esql_payloads_anywhere(value)


def _names(payload: dict) -> list[str]:
    return [column["name"] for column in payload["columns"]]


def _to_dict_rows(payload: dict) -> dict:
    """The pre-#842 dict-row form of a payload — the test's own inverse zip.

    A no-op on rows that are already dicts, so this can plant the old form into a tree
    whether it is read before or after the migration has run over it.
    """
    rows = payload["values"]
    if not rows or isinstance(rows[0], dict):
        return payload
    return {**payload, "values": [dict(zip(_names(payload), row, strict=True))
                                  for row in rows]}


def _revert_document(doc: Any) -> int:
    """Rewrite every ES|QL payload in `doc` back to dict rows, in place. Returns how many."""
    reverted = 0
    for payload in _esql_payloads_anywhere(doc):
        rows = payload["values"]
        if rows and not isinstance(rows[0], dict):
            payload["values"] = _to_dict_rows(payload)["values"]
        if payload["values"]:
            reverted += 1
    return reverted


def _dict_row_payloads(doc: Any) -> list[dict]:
    return [p for p in _esql_payloads_anywhere(doc)
            if p["values"] and isinstance(p["values"][0], dict)]


def _hash_tree(root: Path) -> dict[str, str]:
    return {str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*")) if path.is_file()}


def _write(path: Path, doc: Any, form: str = "compact") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(SERIALIZATIONS[form](doc), encoding="utf-8")
    return path


# =================================================================================
# O2 — the re-encode loses nothing
# =================================================================================

def test_the_reencode_of_a_real_payload_is_the_positional_form_of_its_rows():
    """O1/O2. The answer stated, not derived: cell `i` is `columns[i].name`'s value, in
    `columns` order, and a stored `null` survives as a cell rather than as an absence.
    This is the shape `esql_payload` hands the judge for every payload production writes
    today; `judge._bounded` slices it and `_block` YAML-dumps it unchanged."""
    got = MIGRATE.to_columnar(real_observed_payload())

    assert got["values"] == EXPECTED_POSITIONAL_ROWS
    assert [len(row) for row in got["values"]] == [3, 3, 3], (
        "a positional row is exactly as wide as `columns`")


def test_rezipping_a_migrated_payload_reproduces_the_original_dict_rows():
    """O2, the whole of it. `values` is the only place the row's field NAMES lived, so a
    re-encode that drops or reorders one is not a re-encode, it is a measurement change
    under a tag that says nothing changed. Checked against the test's own zip AND against
    the migration's declared inverse, and on key ORDER rather than key set — a dict
    comparison alone is blind to `{"a":1,"b":2}` vs `{"b":2,"a":1}`, which is exactly the
    difference `judge._block`'s YAML dump would show the judge."""
    original = real_observed_payload()
    migrated = MIGRATE.to_columnar(real_observed_payload())

    independently_rezipped = [dict(zip(_names(original), row, strict=True))
                              for row in migrated["values"]]
    assert independently_rezipped == original["values"]
    assert MIGRATE.to_dict_rows(migrated) == original

    for before, after in zip(original["values"],
                             MIGRATE.to_dict_rows(migrated)["values"], strict=True):
        assert list(after.keys()) == list(before.keys()), (
            f"row key order moved: {list(before.keys())} -> {list(after.keys())}")


def test_the_reencode_touches_nothing_but_values():
    """O2/O3. `query`, `columns` and `row_count` are the bytes a reviewer reads the diff
    for; if any of them moves, the diff stops being 'the rows were re-encoded'. The key
    ORDER of the payload dict is pinned too, and not out of fussiness: `json.dumps`
    writes keys in insertion order, so a rebuilt dict reorders the whole file and O3's
    'minimal and reviewable' is gone even though the data is identical."""
    original = real_observed_payload()
    migrated = MIGRATE.to_columnar(real_observed_payload())

    assert migrated["query"] == original["query"]
    assert migrated["columns"] == original["columns"]
    assert migrated["row_count"] == original["row_count"] == 3
    assert list(migrated) == list(original), "the payload's key order moved"
    assert {k: v for k, v in migrated.items() if k != "values"} == {
        k: v for k, v in original.items() if k != "values"}


@pytest.mark.parametrize(("why", "rows"), [
    ("reordered", [{"event.outcome": None, "events": 431,
                    "data_stream.dataset": "system.auth"}]),
    ("missing a column", [{"events": 431, "event.outcome": None}]),
    ("carrying a name no column has", [{"events": 431, "event.outcome": None,
                                        "data_stream.dataset": "system.auth",
                                        "host.name": "web-2"}]),
])
def test_a_row_whose_keys_are_not_the_columns_is_refused_not_guessed(why, rows):
    """O2. Every one of the 27,208 rows on disk has `list(row) == column names`, which is
    the fact that makes a positional re-encode lossless at all. A row that does not is a
    payload this transform cannot claim to preserve — re-zipping it by name would silently
    reorder cells (case 1), invent one (case 2) or drop one (case 3), and the round-trip
    that is supposed to catch that would be comparing against the already-mangled row.
    Refuse it and let a human look, rather than migrate 897 payloads and corrupt one."""
    payload = real_observed_payload()
    payload["values"] = rows

    with pytest.raises(ValueError, match="(?i)column"):
        MIGRATE.to_columnar(payload)


def test_a_mix_of_dict_and_already_positional_rows_migrates_only_the_dict_ones():
    """Adversary finding (Hole 6, #1054). The obvious-but-wrong implementation decides a
    WHOLE payload's fate from `values[0]` alone: if the first row happens to already be a
    list, it assumes every row is and returns the payload untouched. That is exactly the
    shape a partially-applied hand edit or an interrupted `controls.py` rerun leaves behind
    — one row already positional, the rest still dict-row — and a first-row-only check
    would silently pass it straight through with its dict row uncorrected. Each row must be
    judged on its own."""
    payload = real_observed_payload()
    dict_row = payload["values"][0]
    already_positional = [dict_row[name] for name in _names(payload)]
    payload["values"] = [already_positional, dict_row]

    migrated = MIGRATE.to_columnar(payload)

    assert migrated["values"] == [already_positional, already_positional]


def test_a_positional_row_of_the_wrong_width_is_refused_not_waved_through():
    """Adversary finding (Hole 6, #1054). A row that is already a list is not automatically
    'already migrated' — a truncated or corrupted rewrite is ALSO a list, just the wrong
    length, and a check that only asks 'is this a list?' would wave it through unexamined.
    Refuse it exactly as a malformed dict row is refused."""
    payload = real_observed_payload()
    payload["values"] = [[431, None]]  # 2 cells; this payload names 3 columns

    with pytest.raises(ValueError, match="(?i)column"):
        MIGRATE.to_columnar(payload)


def test_a_row_that_is_neither_a_dict_nor_a_list_is_refused():
    """A payload with a `values` entry of some third shape (a bare scalar, `null`) is not a
    row this transform can classify as dict or positional — refuse it rather than guess."""
    payload = real_observed_payload()
    payload["values"] = [None]

    with pytest.raises(ValueError, match="(?i)column"):
        MIGRATE.to_columnar(payload)


def test_an_empty_esql_payload_is_returned_exactly_as_it_is():
    """c9. `values: []` reads identically in both encodings, so rewriting one would be a
    diff hunk with no content — 471 of them. The payload comes back equal, and still
    classifies as ES|QL so the guard keeps counting it."""
    empty = json.loads(REAL_EMPTY_ESQL_TEXT)

    assert MIGRATE.to_columnar(json.loads(REAL_EMPTY_ESQL_TEXT)) == empty
    assert MIGRATE.is_esql_payload(empty)


def test_reencoding_an_already_positional_payload_changes_nothing():
    """O5. The transform is a fixed point on its own output, which is what makes the
    migration idempotent and what makes a `controls.py` rerun — whose writer already goes
    through `esql_payload` — unable to re-split the corpus."""
    once = MIGRATE.to_columnar(real_observed_payload())
    twice = MIGRATE.to_columnar(once)

    assert twice == once
    assert twice["values"] == EXPECTED_POSITIONAL_ROWS


# =================================================================================
# O1 — what counts as an ES|QL payload
# =================================================================================

@pytest.mark.parametrize(("what", "text", "is_esql"), [
    ("a real dict-row observed payload", REAL_OBSERVED_TEXT, True),
    ("a real empty ES|QL payload", REAL_EMPTY_ESQL_TEXT, True),
    ("a real cmdb host record", REAL_CMDB_TEXT, False),
    ("a real state-lookup stub", REAL_STATE_STUB_TEXT, False),
])
def test_an_esql_payload_is_recognised_by_its_four_keys(what, text, is_esql):
    """O1. The classifier is the four-key shape at any dict in the document, because the
    alternative — a list of the positions payloads are known to sit at — is the bug that
    produced #1054: #842 moved the shape and the sweep that should have noticed was
    looking at an enumerated list nobody updated. No non-ES|QL shape in `hidden/` carries
    `columns` and `values` at all, so the four keys separate them cleanly."""
    assert MIGRATE.is_esql_payload(json.loads(text)) is is_esql, what


@pytest.mark.parametrize("dropped", ESQL_KEYS)
def test_a_dict_missing_any_one_of_the_four_keys_is_not_an_esql_payload(dropped):
    """All four, not any of them: `{columns, values}` alone would also match a future
    lookup response, and migrating one would rewrite a shape we do not model."""
    partial = {k: v for k, v in real_observed_payload().items() if k != dropped}

    assert MIGRATE.is_esql_payload(partial) is False


# =================================================================================
# O3 — the rewrite is minimal and reviewable
# =================================================================================

@pytest.mark.parametrize("form", sorted(SERIALIZATIONS))
def test_a_rewritten_file_keeps_its_own_serialization(form, tmp_path):
    """O3. Three forms reproduce all 957 hidden files byte-for-byte, and a rewrite that
    normalised them would turn a 482-file data migration into a 957-file whitespace diff
    no reviewer can read. The file's bytes afterwards are its own form applied to the
    migrated document — nothing else about the text moves."""
    path = _write(tmp_path / "0.json", real_observed_payload(), form)

    assert MIGRATE.migrate_file(path) == 1

    expected_doc = real_observed_payload()
    expected_doc["values"] = EXPECTED_POSITIONAL_ROWS
    assert path.read_text(encoding="utf-8") == SERIALIZATIONS[form](expected_doc)
    assert json.loads(path.read_text(encoding="utf-8"))["values"] == (
        EXPECTED_POSITIONAL_ROWS)


@pytest.mark.parametrize(("what", "text"), [
    ("a real cmdb host record", REAL_CMDB_TEXT),
    ("a real state-lookup stub", REAL_STATE_STUB_TEXT),
    ("a real empty ES|QL payload", REAL_EMPTY_ESQL_TEXT),
])
def test_a_file_with_nothing_to_migrate_comes_out_byte_identical(what, text, tmp_path):
    """O3, and the non-obligation it protects. A file the migration has no business
    rewriting is not re-serialized "harmlessly": it is not written at all. Paired with a
    dict-row file in the same directory that IS rewritten, so this cannot pass by the
    migration having done nothing anywhere."""
    untouched = tmp_path / "untouched.json"
    untouched.write_text(text, encoding="utf-8")
    before = untouched.read_bytes()
    positive_control = _write(tmp_path / "dictrows.json", real_observed_payload())
    control_before = positive_control.read_bytes()

    assert MIGRATE.migrate_file(untouched) == 0
    assert untouched.read_bytes() == before, what

    assert MIGRATE.migrate_file(positive_control) == 1
    assert positive_control.read_bytes() != control_before, (
        "the positive control was not rewritten either — the negative above is vacuous")


def test_a_file_with_nothing_to_migrate_is_never_reopened_for_writing(tmp_path):
    """O3, stronger than byte-equality (adversary finding, Hole 3, #1054): an implementation
    that unconditionally re-serializes every file and happens to reproduce the same bytes
    would also pass a byte-equality check, but it still performed a real write — an mtime
    bump, a moment where a concurrent reader sees a truncated file, an unnecessary fsync on
    957 files instead of 482. 'Nothing to migrate' has to be decided BEFORE opening the file
    to write, not verified after the fact by comparing bytes."""
    untouched = tmp_path / "untouched.json"
    untouched.write_text(REAL_CMDB_TEXT, encoding="utf-8")
    old = 1_700_000_000
    os.utime(untouched, ns=(old * 1_000_000_000, old * 1_000_000_000))
    before_mtime = untouched.stat().st_mtime_ns

    assert MIGRATE.migrate_file(untouched) == 0
    assert untouched.stat().st_mtime_ns == before_mtime, (
        "the file's mtime moved even though nothing needed migrating — it was reopened for "
        "writing rather than recognised up front as having nothing to do")


def test_a_zero_byte_payload_file_is_skipped_rather_than_parsed(tmp_path):
    """80 hidden files are zero bytes, and that is a recorded capture failure the judge
    renders as `unreadable` — not an empty result set. Parsing one raises; writing `{}`
    over it would tell the judge a query returned nothing. Paired with a real file that
    does migrate, so "skipped everything" cannot pass as "skipped the empty one"."""
    empty = tmp_path / "0.json"
    empty.write_bytes(b"")
    positive_control = _write(tmp_path / "1.json", real_observed_payload())

    assert MIGRATE.migrate_file(empty) == 0
    assert empty.read_bytes() == b""
    assert MIGRATE.migrate_file(positive_control) == 1


def test_a_file_whose_serialization_cannot_be_reproduced_is_refused_untouched(tmp_path):
    """O3. The migration only knows how to put a file back the way it found it in three
    forms. A file in some fourth form cannot be rewritten without also reformatting it,
    and a silent reformat is a diff hunk that hides the data change inside it — so the
    file is refused and left exactly as it was, for a human to look at.

    Paired with the same document in a form the migration DOES know, so a migration that
    refused everything could not pass this."""
    doc = real_observed_payload()
    unknown_form = tmp_path / "exotic.json"
    unknown_form.write_text(json.dumps(doc, indent=4), encoding="utf-8")
    before = unknown_form.read_bytes()
    known_form = _write(tmp_path / "known.json", doc, "indent2")

    with pytest.raises(ValueError, match="(?i)serializ"):
        MIGRATE.migrate_file(unknown_form)
    assert unknown_form.read_bytes() == before, (
        "a refused file was rewritten anyway — the refusal has to leave the bytes alone")

    assert MIGRATE.migrate_file(known_form) == 1


# =================================================================================
# O1/O2 — the positions the migration has to reach
# =================================================================================

def test_a_control_record_has_its_controls_and_its_attack_contribution_migrated():
    """O1 for `controls[i].payload` (which `judge._control` renders straight into the
    `<baseline>` block) and O2/O5 for `attack_contribution.payload` (which no prompt
    reads, but which `controls.py` writes through the same shaper and which must not be
    left as the corpus's second encoding)."""
    record = real_control_record()

    for payload in _esql_payloads_anywhere(record):
        if payload["values"]:
            payload["values"] = MIGRATE.to_columnar(payload)["values"]

    baseline = record["controls"][1]["payload"]
    contribution = record["attack_contribution"]["payload"]
    assert baseline["values"] == EXPECTED_POSITIONAL_ROWS
    assert contribution["values"] == EXPECTED_POSITIONAL_ROWS
    assert record["controls"][0]["payload"] is None, "a levered-down window has no payload"
    assert record["controls"][2]["payload"]["values"] == []


def test_a_payload_at_a_position_nobody_enumerated_is_still_migrated(tmp_path):
    """O1's whole reason for recursing. Today's payloads sit at exactly three positions —
    the observed root, `controls[i].payload`, `attack_contribution.payload` — and a sweep
    written against that list is correct until the day a fourth appears, which is the day
    the corpus splits again and nothing notices. The document below carries a dict-row
    payload under a key no census has ever listed; the migration must find it by shape.

    Paired with the levered-down control in the same record, which stays `null`."""
    record = real_control_record()
    record["controls"][1]["re_measured"] = {"at": "2026-08-01",
                                            "payload": real_observed_payload()}
    path = _write(tmp_path / "3.json", record, "indent2+newline")

    assert MIGRATE.migrate_file(path) == 3, (
        "expected the two controls' payloads that carry rows plus the one nested under "
        "an unenumerated key")

    after = json.loads(path.read_text(encoding="utf-8"))
    assert after["controls"][1]["re_measured"]["payload"]["values"] == (
        EXPECTED_POSITIONAL_ROWS)
    assert _dict_row_payloads(after) == [], "a dict-row payload survived the migration"
    assert after["controls"][0]["payload"] is None


# =================================================================================
# The whole tree, through the real entry point
# =================================================================================

#: Files planted with the pre-#842 dict-row form before the migration is run over a copy
#: of the real tree. One per serialization, one observed and one control record, chosen so
#: the run has something to do whether it is driven before or after M1 has landed on the
#: committed corpus — otherwise every "was not touched" assertion below passes vacuously.
PLANTED = (
    # compact one-line observed payload
    "cases/case-001-ssh-bruteforce-canary/hidden/observed/l-001/0.json",
    # `indent=2`, no trailing newline — one of the nine hand-authored seed files
    "cases/case-002-authorized-keys-falco/hidden/observed/l-001/0.json",
    # `indent=2` + newline — a control record: `controls[].payload` and
    # `attack_contribution.payload` in one file
    "cases/case-005-cross-tier-probe-db1/hidden/controls/l-005/3.json",
)


@pytest.fixture(scope="module")
def migrated_tree(tmp_path_factory):
    """A copy of the real `oracle_golden/` tree, three payload files hand-reverted to the
    pre-#842 dict-row form, then migrated twice through `migrate_tree`.

    Copied rather than driven over the checkout for the obvious reason, and copied WHOLE
    rather than just `cases/` so `audits/` and `held_out_ledger.yaml` are in the blast
    radius O4 measures.
    """
    root = tmp_path_factory.mktemp("golden") / "oracle_golden"
    shutil.copytree(GOLDEN_DIR, root)

    planted_docs = {}
    planted_payloads = 0
    for rel in PLANTED:
        path = root / rel
        raw = path.read_text(encoding="utf-8")
        doc = json.loads(raw)
        form = next(name for name, render in SERIALIZATIONS.items()
                    if render(doc) == raw)
        planted_payloads += _revert_document(doc)
        path.write_text(SERIALIZATIONS[form](doc), encoding="utf-8")
        planted_docs[rel] = doc

    before = _hash_tree(root)
    first = MIGRATE.migrate_tree(root / "cases")
    after_first = _hash_tree(root)
    second = MIGRATE.migrate_tree(root / "cases")
    after_second = _hash_tree(root)

    return {
        "root": root, "before": before, "after_first": after_first,
        "after_second": after_second, "first": first, "second": second,
        "planted": planted_docs, "planted_payloads": planted_payloads,
    }


def test_the_planted_dict_row_files_were_rewritten(migrated_tree):
    """The positive control every "was not touched" assertion below leans on. If the run
    rewrote nothing, the rest of this section measures nothing."""
    before, after = migrated_tree["before"], migrated_tree["after_first"]

    assert migrated_tree["planted_payloads"] >= len(PLANTED), (
        "the fixture planted no dict rows — the whole section would be vacuous")
    for rel in PLANTED:
        assert before[rel] != after[rel], f"{rel} was not rewritten"
    files_rewritten, payloads_rewritten = migrated_tree["first"]
    assert files_rewritten >= len(PLANTED)
    assert payloads_rewritten >= migrated_tree["planted_payloads"]


def test_no_dict_row_esql_payload_survives_anywhere_under_hidden(migrated_tree):
    """O1, measured over the real tree rather than a fixture: after the run there is no
    ES|QL payload under any `hidden/` whose rows are not `len(columns)`-long arrays, and
    the sweep found payloads to check."""
    root = migrated_tree["root"]
    offenders, seen = [], 0
    for path in sorted((root / "cases").glob("*/hidden/**/*.json")):
        raw = path.read_bytes()
        if not raw.strip():
            continue
        for payload in _esql_payloads_anywhere(json.loads(raw)):
            seen += 1
            width = len(payload["columns"])
            if any(not isinstance(row, list) or len(row) != width
                   for row in payload["values"]):
                offenders.append(str(path.relative_to(root)))

    assert seen > 0, "swept a tree with no ES|QL payloads in it"
    assert offenders == [], f"{len(offenders)} payload(s) still dict-row: {offenders[:5]}"


def test_every_planted_payload_rezips_to_exactly_what_was_planted(migrated_tree):
    """O2 end to end, on disk: the file the migration wrote re-zips by `columns[].name`
    back to the very dict rows the fixture put there — keys, key order and values — and
    its `query`, `columns` and `row_count` are the ones that went in."""
    root = migrated_tree["root"]
    checked = 0
    for rel, planted in migrated_tree["planted"].items():
        after = json.loads((root / rel).read_text(encoding="utf-8"))
        pairs = list(zip(_esql_payloads_anywhere(planted),
                         _esql_payloads_anywhere(after), strict=True))
        assert pairs, f"{rel} carries no ES|QL payload"
        for original, migrated in pairs:
            assert migrated["query"] == original["query"]
            assert migrated["columns"] == original["columns"]
            assert migrated["row_count"] == original["row_count"]
            assert _to_dict_rows(migrated)["values"] == original["values"]
            for before_row, after_row in zip(original["values"],
                                             _to_dict_rows(migrated)["values"],
                                             strict=True):
                assert list(after_row.keys()) == list(before_row.keys())
            checked += 1
    assert checked >= len(PLANTED)


def test_a_second_run_over_the_migrated_tree_rewrites_nothing(migrated_tree):
    """O5. The script is committed with the corpus so the transform stays replayable, and
    a replay that re-wrote files would make "is the tree migrated?" unanswerable from the
    diff. Every byte in the tree — not just the payload files — is identical after the
    second run."""
    assert migrated_tree["second"] == (0, 0)
    assert migrated_tree["after_second"] == migrated_tree["after_first"]


def test_the_only_files_the_run_rewrote_are_the_ones_carrying_dict_rows(migrated_tree):
    """O3 over the real tree, stated as an equality rather than a sample: the set of files
    whose bytes moved is EXACTLY the set the fixture planted dict rows in. Everything else
    — the 191 non-ES|QL lookups, the 204 files whose only payloads are `values: []`, the
    80 zero-byte capture failures, `controls.yaml`, manifests, stories, prompts — is
    byte-identical, so the PR's diff is the data migration and nothing else.

    This also re-states O1 from the other side: if the committed corpus still held
    dict-row payloads of its own, they would appear here as files the run had to rewrite.
    """
    before, after = migrated_tree["before"], migrated_tree["after_first"]
    assert set(after) == set(before), "the migration added or removed files"

    moved = sorted(rel for rel in before if before[rel] != after[rel])
    assert moved == sorted(PLANTED), (
        f"{len(moved)} file(s) moved, expected only the planted ones. "
        f"Unexpected: {sorted(set(moved) - set(PLANTED))[:5]}")


@pytest.fixture(scope="module")
def pre_migration_cases_dir(tmp_path_factory):
    """The real `cases/` tree exactly as `git` has it at `PRE_MIGRATION_REF` — the one
    fixture in this module that is NOT derived from anything `migrate_tree` or this test
    file itself produced. `git archive` rather than `git show` per file: one subprocess for
    the whole subtree instead of 482."""
    root = tmp_path_factory.mktemp("pre1054")
    rel = "defender/evals/oracle_golden/cases"
    archive = subprocess.run(
        ["git", "-C", str(REPO_ROOT), "archive", PRE_MIGRATION_REF, "--", rel],
        capture_output=True, check=True).stdout
    with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
        tar.extractall(root)  # noqa: S202 — a `git archive` of this repo's own history
    return root / rel


def test_every_committed_payload_rezips_to_its_pre_migration_dict_rows(pre_migration_cases_dir):
    """O2, anchored to git history rather than to anything this test module or the migration
    produced (adversary finding, Hole 1, #1054 — the headline one).

    Every other O2 check in this module either compares the migration's output to an
    embedded fixture literal, or — for the whole-tree checks above — to a re-zip of
    whatever `migrate_tree` itself just wrote, read back off the SAME run. A transform that
    corrupts the corpus consistently with itself (every cell written in reversed column
    order; every payload's rows silently replaced with `values: []` while `row_count` is
    left untouched) satisfies both of those, because neither ever consults a byte that
    predates the run under test.

    This does: for every ES|QL payload under the COMMITTED `cases/` tree today, re-zipping
    its (now positional) `values` by `columns[].name` must reproduce EXACTLY the dict rows
    `git` has for that same file and position at `PRE_MIGRATION_REF` — before this PR's
    migration ever ran. `row_count == len(values)` is checked independently too, which alone
    would catch a payload silently emptied.
    """
    checked = 0
    for path in sorted(CASES_DIR.glob("*/hidden/**/*.json")):
        raw = path.read_bytes()
        if not raw.strip():
            continue
        rel = path.relative_to(CASES_DIR)
        before_path = pre_migration_cases_dir / rel
        if not before_path.exists():
            continue  # a file this PR did not touch, and that pre-dates PRE_MIGRATION_REF too
        before_raw = before_path.read_bytes()
        if not before_raw.strip():
            continue

        now_payloads = list(_esql_payloads_anywhere(json.loads(raw)))
        before_payloads = list(_esql_payloads_anywhere(json.loads(before_raw)))
        assert len(now_payloads) == len(before_payloads), (
            f"{rel}: the number of ES|QL payloads in this file changed")

        for now_p, before_p in zip(now_payloads, before_payloads, strict=True):
            assert now_p["query"] == before_p["query"], rel
            assert now_p["columns"] == before_p["columns"], rel
            assert now_p["row_count"] == before_p["row_count"], rel
            assert now_p["row_count"] == len(now_p["values"]), (
                f"{rel}: row_count no longer matches len(values) — a row was silently "
                "dropped or added")
            assert _to_dict_rows(now_p)["values"] == before_p["values"], (
                f"{rel}: re-zipping the committed payload does not reproduce its "
                f"pre-{PRE_MIGRATION_REF} dict rows — the migration lost or corrupted data")
            checked += 1

    assert checked >= 898, (
        f"only checked {checked} payload(s) against git history; expected the full "
        "898-payload census this issue counted — a shrunk count here would itself be a sign "
        "of lost data")


# =================================================================================
# O4 — nothing is re-scored, and the provenance gap is written down
# =================================================================================

#: The judge tag every committed label, the calibration audit and the held-out entries
#: were measured under, with the judge reading DICT rows. It is deliberately not changed
#: by #1054: folding the corpus encoding into `tag_suffix` would invalidate 15 label
#: caches, the calibration audit and 6 ledger entries, all of which only a hand-run LLM
#: sweep can regenerate, for a number nothing downstream consumes today.
UNCHANGED_JUDGE_TAG = "judge-claude-opus-5-high_47d6044a"

#: The two cases with a corpus and no label cache. If they are ever labelled they will be
#: the first leads measured from the positional form under a tag whose other 85 leads
#: were measured from dict rows. That is the accepted mixing O4 requires be named.
UNCACHED_CASES = ("case-006-authorized-keys-db1", "case-007-lotl-web1")

#: The claim the note has to make, in whichever words its author prefers. Checked as
#: alternatives rather than one exact sentence: the obligation is that the note SAYS the
#: tag was deliberately not changed, not that it says it in a particular way.
TAG_UNCHANGED_PHRASINGS = (
    "tag unchanged", "unchanged tag", "tag was not changed", "tag is not changed",
    "without changing the tag", "tag was deliberately left unchanged",
    "left the tag unchanged", "tag was left unchanged", "the tag does not change",
)


def _says_tag_unchanged(text: str) -> bool:
    lowered = text.lower()
    return any(phrase in lowered for phrase in TAG_UNCHANGED_PHRASINGS)


def test_the_migration_does_not_touch_labels_scores_audits_or_the_ledger(migrated_tree):
    """O4. A re-encode is not a re-measurement, so nothing that records a measurement may
    move: the 15 committed label caches, every `scores/<tag>.json`, the two calibration
    audits and the append-only held-out ledger (whose `check_held_out_ledger` hashes
    `scores/<tag>.json` and would fail on a rewrite). Paired with the planted payload
    files, which did move in the same run."""
    before, after = migrated_tree["before"], migrated_tree["after_first"]

    guarded = [rel for rel in sorted(before)
               if rel == "held_out_ledger.yaml"
               or rel.startswith("audits/")
               or "/labels/" in rel
               or "/scores/" in rel
               or "/projections/" in rel]
    assert len(guarded) >= 20, f"expected the committed measurements, found {guarded}"
    assert any("/labels/" in rel for rel in guarded)
    assert any("/scores/" in rel for rel in guarded)
    assert "held_out_ledger.yaml" in guarded

    moved = [rel for rel in guarded if before[rel] != after[rel]]
    assert moved == [], f"the migration re-wrote committed measurements: {moved}"
    assert any(before[rel] != after[rel] for rel in PLANTED), (
        "nothing moved at all in this run — the assertion above is vacuous")


def test_the_audits_readme_records_the_reencoding_under_the_unchanged_tag():
    """O4/M3. `audits/README.md` is where the tag discipline is written down — "one file
    per judge tag", "editing either prompt invalidates the calibration". #1054 changes the
    judge's input BYTES under an unchanged tag, which is the one thing that discipline
    exists to prevent, so the exception is recorded there rather than left for a future
    reader to discover from a git log.

    The note must name the two cases that have no label cache: their 15 leads would be the
    first ever labelled from the positional form under a tag whose other 85 leads were
    labelled from dict rows, and a cache hit does not protect them because they have none.
    """
    text = (GOLDEN_DIR / "audits" / "README.md").read_text(encoding="utf-8")
    lines = text.splitlines()
    headings = [i for i, line in enumerate(lines)
                if line.startswith("## ") and UNCHANGED_JUDGE_TAG in line]
    assert headings, "the calibration section this note belongs under is gone"
    start = headings[0]
    # Bounded to THIS section, not "to end of file" (adversary finding, Hole 4, #1054): a
    # note filed under a LATER `##` heading — the verdict-selfagreement section, say — would
    # still satisfy a to-EOF slice, but it would not be "under the `47d6044a` section" as M3
    # asks.
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("## ")),
               len(lines))
    section = "\n".join(lines[start:end])
    # An HTML comment is invisible in rendered Markdown, so content that exists only inside
    # one does not count as the note being "written down" (adversary finding, Hole 4).
    note = re.sub(r"<!--.*?-->", "", section, flags=re.S)

    assert "1054" in note, "the note does not cite the issue that re-encoded the corpus"
    assert "re-encod" in note.lower(), (
        "the note does not say the corpus was re-encoded")
    assert _says_tag_unchanged(note), (
        "the note does not say the judge tag was deliberately left unchanged; expected "
        f"one of {TAG_UNCHANGED_PHRASINGS}")
    for case_id in UNCACHED_CASES:
        assert case_id in note, (
            f"{case_id} has no label cache and would be labelled from the new form under "
            f"{UNCHANGED_JUDGE_TAG} — the accepted mixing has to be named")


def test_the_judge_cache_key_comment_points_at_the_accepted_encoding_mix():
    """O4/M3. The comment above `MODEL_LEAD_FIELDS` already names the failure in the
    abstract — "a rebuilt case would be labelled from a different input shape than its
    siblings under one tag" — and it is what a future reader of `labels/<judge-tag>.json` reads
    when they wonder what the cache key does and does not cover. #1054 is a real instance
    of exactly that, accepted deliberately, so the comment has to point at it; the
    abstract warning alone would leave the reader believing it never happened."""
    source = (GOLDEN_DIR / "judge.py").read_text(encoding="utf-8")
    anchor = source.index("MODEL_LEAD_FIELDS = ")
    block = []
    for line in reversed(source[:anchor].splitlines()):
        if not line.lstrip().startswith("#"):
            break
        block.append(line)
    comment = "\n".join(reversed(block))

    assert comment, "no comment block above MODEL_LEAD_FIELDS"
    assert "labelled from a different input shape than its siblings" in comment, (
        "the comment this note attaches to has moved — re-anchor the note, do not drop it")
    lowered = comment.lower()
    assert "1054" in comment, (
        "the cache-key comment does not name the accepted encoding change (#1054)")
    # A comment containing "1054" and "encod" alone is satisfied by a sentence that states
    # the OPPOSITE of what happened (adversary finding, Hole 4, #1054: "#1054 left the
    # corpus encoding alone" contains both tokens). Require it actually say the corpus was
    # RE-encoded, and name the shape — not just gesture at "encoding" in the abstract.
    assert "re-encod" in lowered, (
        "the cache-key comment does not say the corpus was RE-encoded (as opposed to, say, "
        "left alone) — it must state what happened, not just mention 'encoding'")
    assert "positional" in lowered or "columnar" in lowered, (
        "the cache-key comment does not name the shape the corpus was re-encoded to")
    for case_id in UNCACHED_CASES:
        assert case_id in comment, (
            f"the cache-key comment does not name {case_id}, one of the two leads with no "
            "label cache under this tag")


def test_the_readme_says_hidden_payloads_are_positional_and_what_enforces_it():
    """O4/M3. The data-layout section is where someone reads what a `hidden/` file holds.
    After #1054 that is `esql_payload`'s positional form, and the reason it stays that way
    is the guard in `tests/evals/test_controls.py` — a reader who does not know the guard
    exists is a reader who hand-edits a payload back to dict rows."""
    raw = (GOLDEN_DIR / "README.md").read_text(encoding="utf-8")
    # Strip HTML comments (invisible in rendered Markdown) before looking for content.
    text = re.sub(r"<!--.*?-->", "", raw, flags=re.S)

    assert "esql_payload" in text, (
        "the README does not name the shaper that defines the corpus encoding")
    assert "positional" in text.lower() or "columnar" in text.lower(), (
        "the README does not say what shape `hidden/` ES|QL payloads are in")
    assert ("test_the_corpus_speaks_the_SAME_esql_encoding_production_does" in text
            or "test_controls" in text), (
        "the README does not say what keeps the corpus in that shape")

    # Adversary finding (Hole 4, #1054): three scattered tokens, each satisfying one
    # assertion above from an unrelated corner of the file (a footer, a stray comment), is
    # not the same as ONE sentence saying "hidden/ payloads are positional and this test
    # enforces it". Require all three signals to co-occur in a single paragraph.
    paragraphs = [p for p in re.split(r"\n\s*\n", text) if p.strip()]
    hit = [p for p in paragraphs
           if "esql_payload" in p
           and ("positional" in p.lower() or "columnar" in p.lower())
           and ("test_the_corpus_speaks_the_SAME_esql_encoding_production_does" in p
                or "test_controls" in p)]
    assert hit, (
        "no single paragraph of the README names esql_payload, says the hidden/ payload "
        "shape, AND names what enforces it — three tokens scattered across the file is not "
        "the same as a sentence saying so")


# =================================================================================
# The committed command
# =================================================================================

def test_the_migration_runs_as_the_committed_command_over_a_cases_dir(tmp_path):
    """The real entry point, driven the way the repair notes in `known_defects.yaml` will
    send someone: one command, no arguments but the tree to work on. Run as a subprocess
    so what is pinned is the script as a script — `main`'s exit code, its output, and the
    bytes it leaves behind — rather than an import of its internals."""
    cases = tmp_path / "cases"
    observed = _write(
        cases / "case-x" / "hidden" / "observed" / "l-001" / "0.json",
        real_observed_payload(), "compact")
    record = _write(
        cases / "case-x" / "hidden" / "controls" / "l-001" / "0.json",
        real_control_record(), "indent2+newline")
    untouched = cases / "case-x" / "hidden" / "observed" / "l-001" / "1.json"
    untouched.write_text(REAL_CMDB_TEXT, encoding="utf-8")

    proc = subprocess.run(
        [sys.executable, str(MIGRATION_SCRIPT), "--cases-dir", str(cases)],
        capture_output=True, text=True, encoding="utf-8", check=False)

    assert proc.returncode == 0, f"{proc.stdout}\n{proc.stderr}"
    # Adversary finding (Hole 5, #1054): "prints a count" was satisfied by a fixed string
    # that happened to contain a digit (the issue number). Pin the ACTUAL numbers: this
    # fixture has exactly 3 payloads to migrate (the observed file's 1, plus the record's
    # controls[1] and attack_contribution — controls[2]'s `values: []` doesn't count) across
    # exactly 2 files (the untouched cmdb lookup is not one of them).
    payload_count = re.search(r"(\d+)\s*ES\|QL payload", proc.stdout)
    file_count = re.search(r"(\d+)\s*file", proc.stdout)
    assert payload_count, f"stdout doesn't name a payload count: {proc.stdout!r}"
    assert file_count, f"stdout doesn't name a file count: {proc.stdout!r}"
    assert payload_count.group(1) == "3", (
        f"expected 3 payload(s) rewritten, stdout said {payload_count.group(1)}: "
        f"{proc.stdout!r}")
    assert file_count.group(1) == "2", (
        f"expected 2 file(s) rewritten, stdout said {file_count.group(1)}: {proc.stdout!r}")

    migrated_observed = json.loads(observed.read_text(encoding="utf-8"))
    assert migrated_observed["values"] == EXPECTED_POSITIONAL_ROWS
    assert _to_dict_rows(migrated_observed)["values"] == real_observed_payload()["values"]

    migrated_record = json.loads(record.read_text(encoding="utf-8"))
    assert _dict_row_payloads(migrated_record) == []
    assert migrated_record["controls"][1]["payload"]["values"] == EXPECTED_POSITIONAL_ROWS
    assert (migrated_record["attack_contribution"]["payload"]["values"]
            == EXPECTED_POSITIONAL_ROWS)

    assert untouched.read_text(encoding="utf-8") == REAL_CMDB_TEXT, (
        "the run rewrote a file with no ES|QL payload in it")

    second = subprocess.run(
        [sys.executable, str(MIGRATION_SCRIPT), "--cases-dir", str(cases)],
        capture_output=True, text=True, encoding="utf-8", check=False)
    assert second.returncode == 0, f"{second.stdout}\n{second.stderr}"
    second_payloads = re.search(r"(\d+)\s*ES\|QL payload", second.stdout)
    second_files = re.search(r"(\d+)\s*file", second.stdout)
    assert second_payloads, f"stdout doesn't name a payload count: {second.stdout!r}"
    assert second_files, f"stdout doesn't name a file count: {second.stdout!r}"
    assert second_payloads.group(1) == "0", (
        f"a second run over an already-migrated tree should report 0 payloads: "
        f"{second.stdout!r}")
    assert second_files.group(1) == "0", (
        f"a second run over an already-migrated tree should report 0 files: "
        f"{second.stdout!r}")
