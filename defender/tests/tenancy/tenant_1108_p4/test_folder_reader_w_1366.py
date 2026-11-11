"""#1366 (repair round 7): the one config.env reader that is left, at the operator's `set-system`.

The run reads RECORDS, so a `config.env` never reaches it (DC7, R10). The only production code that still reads a
system's folder is the operator command (`set-system`, `import`: DC8, O9), which turns a folder into a record. The reader
rules the run-side resolver used to be tested for are pinned here, at that door, as what the record STORES (or that it is
refused and stores nothing): the quote rule and the line rules (moved from `tenant_1107_settings/test_parser.py`), a
`config.env` that is not a plain file (moved from `test_record.py::nf16`), and one far larger than any settings file
(moved from `runtime/permissions/test_review_roots.py`).

NOT pinned (undecided by the design): a duplicate key, an `export K=v` line, a stray file or dot-folder beside the
system folders at `import`.
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — the fixture
from defender.tests.support.tenancy import _systems1366 as R
from defender.tests.tenancy.tenant_1108_p4._support import published_tenant

CMDB_CONFIG, CMDB_ACCESS = R.FIXTURE_FOLDERS["cmdb"]
TICKET_CONFIG, TICKET_ACCESS = R.FIXTURE_FOLDERS["ticket"]


@pytest.fixture
def imported_op(tmp_path, data_root, migrated_database, capsys, monkeypatch):  # noqa: F811 — the fixture tenant, imported
    monkeypatch.setenv("DEFENDER_DATABASE_DSN", migrated_database)
    with published_tenant(tmp_path / "forge", root=data_root, files=R.import_files()) as tenant:
        register_tenant(migrated_database, tenant.tenant_id, data_root=tenant.data_root, records=None)
        op = R.Operator(tenant.tenant_id, migrated_database, tmp_path / "op", capsys)
        rc, said = op.import_()
        assert rc == 0, said
        yield op


def _folder(op: R.Operator, system: str, config: str | bytes | None, access: str) -> Path:
    """A handoff folder for `system` holding exactly `config` (raw bytes) and `access`."""
    where = op.tmp / f"raw-{len(list(op.tmp.glob('raw-*')))}"
    folder = R.system_folder(where, system, config=None, access=access)
    if config is not None:
        (folder / "config.env").write_bytes(config.encode("utf-8") if isinstance(config, str) else config)
    return folder


def _set(op: R.Operator, system: str, folder: Path, replaces: int) -> tuple[int, str]:
    return op.run(R.SET_SYSTEM, op.tid, system, str(folder), R.REPLACES, str(replaces))


def _numbers(op: R.Operator) -> dict[str, list[tuple[int, int, bool]]]:
    return {s: op.numbers(s) for s in sorted(R.FIXTURE_SYSTEMS)}


def _refused_unchanged(op: R.Operator, system: str, rc: int, said: str, before: Any) -> None:
    assert rc != 0, said
    assert system in said, said
    assert "Traceback" not in said, said
    assert "MemoryError" not in said, said
    assert str(op.tmp) not in said, f"the refusal names the host path: {said}"
    assert _numbers(op) == before, "a refused folder stored something"


@pytest.mark.postgres
def test_oversized_config_is_that_system_refused_not_a_crash(imported_op):
    """A sparse `config.env` far larger than any settings file is refused at `set-system` naming the system: no
    `MemoryError` out of the reader, nothing stored, the sibling records untouched. (Moved from 'that system down, the run
    goes on' at the run-side resolver; DC7.)"""
    op = imported_op
    before = _numbers(op)
    folder = _folder(op, "cmdb", None, CMDB_ACCESS)
    with open(folder / "config.env", "wb") as fh:
        fh.truncate(64 << 20)

    rc, said = _set(op, "cmdb", folder, 1)

    _refused_unchanged(op, "cmdb", rc, said, before)
    control = R.system_folder(op.tmp / "control", "cmdb", config=CMDB_CONFIG, access=CMDB_ACCESS)
    assert _set(op, "cmdb", control, 1)[0] == 0, "control: the same system with a normal folder is accepted"


@pytest.mark.postgres
@pytest.mark.parametrize("part", ["config.env", "access.yaml"])
def test_a_part_that_is_not_a_plain_file_is_that_system_refused(imported_op, part):
    """A `config.env` or `access.yaml` that is a directory (reading it raises `IsADirectoryError`), or an unreadable file
    (as root the mode does not deny a read, so that arm is skipped), is refused at `set-system` naming the system,
    with no traceback and no host path, and stores nothing. (Moved from 'an unreadable config.env kept as that system's
    fault' at the run-side resolver; DC7.)"""
    op = imported_op
    before = _numbers(op)
    folder = _folder(op, "cmdb", None, CMDB_ACCESS)
    (folder / "config.env").write_text('CMDB_TIMEOUT_SEC="10"\n', encoding="utf-8")
    (folder / part).unlink()
    (folder / part).mkdir()

    rc, said = _set(op, "cmdb", folder, 1)

    _refused_unchanged(op, "cmdb", rc, said, before)
    if os.geteuid() != 0:
        (folder / part).rmdir()
        (folder / part).write_text("x\n", encoding="utf-8")
        (folder / part).chmod(0)
        try:
            rc, said = _set(op, "cmdb", folder, 1)
        finally:
            (folder / part).chmod(0o644)
        _refused_unchanged(op, "cmdb", rc, said, before)


@pytest.mark.postgres
@pytest.mark.parametrize(("line", "stored"), [
    pytest.param('TICKET_KEY_PATTERN="abc\'"', "abc'", id="double-quoted-with-an-inner-single"),
    pytest.param("TICKET_KEY_PATTERN='single-q1'", "single-q1", id="one-matched-single-pair"),
    pytest.param("TICKET_KEY_PATTERN=\"'nested-q1'\"", "'nested-q1'", id="one-pair-trimmed-inner-kept"),
    pytest.param('TICKET_KEY_PATTERN="unmatched-q1', '"unmatched-q1', id="no-matched-pair-nothing-trimmed"),
    pytest.param("TICKET_KEY_PATTERN=bastion-p15 # the jump host", "bastion-p15 # the jump host",
                 id="mid-line-hash-is-part-of-the-value"),
    pytest.param("# a comment\n\nno equals sign here\nTICKET_KEY_PATTERN=plain-p15", "plain-p15",
                 id="comment-blank-and-no-equals-lines-skipped"),
])
def test_the_folder_reader_stores_the_value_the_one_quote_and_line_rules_give(imported_op, line, stored):
    """`set-system` stores a `config.env` line's value by the one parser's rules: one matched quote pair trimmed (the
    inner quotes kept), no matched pair nothing trimmed, a mid-line `#` part of the value, comment, blank and no-`=`
    lines skipped without refusing the file. (Moved from the run-side 'one parser' tests; DC7.)"""
    op = imported_op
    timeout = f"TICKET_TIMEOUT_SEC=\"{TICKET_CONFIG['TICKET_TIMEOUT_SEC']}\""
    folder = _folder(op, "ticket", f"{timeout}\n{line}\n", TICKET_ACCESS)

    rc, said = _set(op, "ticket", folder, 1)

    assert rc == 0, said
    settings = dict(op.current()["ticket"].settings)
    assert settings["TICKET_KEY_PATTERN"] == stored, settings
    assert settings["TICKET_TIMEOUT_SEC"] == TICKET_CONFIG["TICKET_TIMEOUT_SEC"], settings


@pytest.mark.postgres
def test_a_byte_order_mark_and_crlf_line_endings_store_the_keys_as_written(imported_op):
    """A leading byte-order mark and CRLF endings (or lone CR) are read as the line they end: the first key is the key as
    written (no BOM in it), no stored value ends in a carriage return. (Moved from the run-side nf15; DC7.)"""
    op = imported_op
    for n, ending in enumerate(("\r\n", "\r")):
        text = f'CMDB_TIMEOUT_SEC="2{n}"{ending}'
        folder = _folder(op, "cmdb", b"\xef\xbb\xbf" + text.encode("utf-8"), CMDB_ACCESS)

        rc, said = _set(op, "cmdb", folder, n + 1)

        assert rc == 0, said
        settings = dict(op.current()["cmdb"].settings)
        assert settings == {"CMDB_TIMEOUT_SEC": f"2{n}"}, settings


@pytest.mark.postgres
def test_keys_are_case_sensitive_so_a_lower_case_spelling_is_not_the_setting(imported_op):
    """A key in lower case is not the upper-case key the adapter reads: the record is refused naming the system and the
    spelling (it cannot satisfy the required key and is not a declared one), and stores nothing. (Moved from the run-side
    nf15, where the lower-case key was kept verbatim and the fault named the missing key; P2: what cannot be used cannot
    be stored.)"""
    op = imported_op
    before = _numbers(op)
    folder = _folder(op, "change-mgmt", 'change_mgmt_timeout_sec="10"\n', R.FIXTURE_FOLDERS["change-mgmt"][1])

    rc, said = _set(op, "change-mgmt", folder, 1)

    assert rc != 0, said
    assert "change-mgmt" in said, said
    assert "CHANGE_MGMT_TIMEOUT_SEC" in said or "change_mgmt_timeout_sec" in said, said
    assert "Traceback" not in said, said
    assert _numbers(op) == before
