from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from defender.evals.oracle_golden import migrate_esql_encoding as MIGRATE

DEFENDER_DIR = Path(__file__).resolve().parents[2]
GOLDEN_DIR = DEFENDER_DIR / "evals" / "oracle_golden"
MIGRATION_SCRIPT = GOLDEN_DIR / "migrate_esql_encoding.py"


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


def test_the_reencode_of_a_real_payload_is_the_positional_form_of_its_rows():
    got = MIGRATE.to_columnar(real_observed_payload())

    assert got["values"] == EXPECTED_POSITIONAL_ROWS
    assert [len(row) for row in got["values"]] == [3, 3, 3], (
        "a positional row is exactly as wide as `columns`")


def test_rezipping_a_migrated_payload_reproduces_the_original_dict_rows():
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
    payload = real_observed_payload()
    payload["values"] = rows

    with pytest.raises(ValueError, match="(?i)column"):
        MIGRATE.to_columnar(payload)


def test_a_mix_of_dict_and_already_positional_rows_migrates_only_the_dict_ones():
    payload = real_observed_payload()
    dict_row = payload["values"][0]
    already_positional = [dict_row[name] for name in _names(payload)]
    payload["values"] = [already_positional, dict_row]

    migrated = MIGRATE.to_columnar(payload)

    assert migrated["values"] == [already_positional, already_positional]


def test_a_positional_row_of_the_wrong_width_is_refused_not_waved_through():
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
    empty = json.loads(REAL_EMPTY_ESQL_TEXT)

    assert MIGRATE.to_columnar(json.loads(REAL_EMPTY_ESQL_TEXT)) == empty
    assert MIGRATE.is_esql_payload(empty)


@pytest.mark.parametrize(("what", "text", "is_esql"), [
    ("a real dict-row observed payload", REAL_OBSERVED_TEXT, True),
    ("a real empty ES|QL payload", REAL_EMPTY_ESQL_TEXT, True),
    ("a real cmdb host record", REAL_CMDB_TEXT, False),
    ("a real state-lookup stub", REAL_STATE_STUB_TEXT, False),
])
def test_an_esql_payload_is_recognised_by_its_four_keys(what, text, is_esql):
    assert MIGRATE.is_esql_payload(json.loads(text)) is is_esql, what


@pytest.mark.parametrize("form", sorted(SERIALIZATIONS))
def test_a_rewritten_file_keeps_its_own_serialization(form, tmp_path):
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


def test_a_file_whose_serialization_cannot_be_reproduced_is_refused_untouched(tmp_path):
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


def test_a_control_record_has_its_controls_and_its_attack_contribution_migrated():
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


def test_no_dict_row_esql_payload_survives_anywhere_under_hidden(migrated_tree):
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


def test_the_migration_runs_as_the_committed_command_over_a_cases_dir(tmp_path):
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
