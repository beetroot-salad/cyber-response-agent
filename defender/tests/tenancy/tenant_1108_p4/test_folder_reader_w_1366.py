"""#1366 R17 and the folder-reader rules, kept after #1470: the one reader of a system's folder (`systems.system_folder.read_folder`)
survives as connect's hand-off reader (`validate_scaffold --handoff`, O11). The operator's `set-system` and `import` doors
that shared it are removed (O10, D-F); a tenant admin's settings travel as the API's key-to-text map. The reader's rules
(the quote and line rules, a part that is not a plain file, one far larger than any settings file, a part that is not UTF-8
text, a byte-order mark and CRLF, case-sensitive keys) are pinned here by driving `read_folder` directly: the value rules
cannot be seen in the validator's report. The duplicate-key / `export` rule is also pinned through the validator, which
proves `--handoff` uses this reader."""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from defender.systems.system_folder import read_folder
from defender.tests.support.tenancy import _systems1366 as R

CMDB_CONFIG, CMDB_ACCESS = R.FIXTURE_FOLDERS["cmdb"]
TICKET_CONFIG, TICKET_ACCESS = R.FIXTURE_FOLDERS["ticket"]


class _FileLocator:
    """A test locator naming each part by its file under `where` (as the hand-off does), so a fault is found by file."""

    def __init__(self, where: Path) -> None:
        self.where = where

    def system(self, system: str) -> str:
        return f"{self.where}/"

    def part(self, system: str, part: str) -> str:
        return str(self.where / {"settings": "config.env", "access": "access.yaml"}[part])

    def case(self) -> str:
        return str(self.where / "case-record.yaml")


def _read(tmp_path: Path, system: str, config: str | bytes | None, access: str):
    folder = R.system_folder(tmp_path / "raw", system, config=None, access=access)
    if config is not None:
        (folder / "config.env").write_bytes(config.encode("utf-8") if isinstance(config, str) else config)
    return folder, read_folder(folder, system, locator=_FileLocator(folder))


def _names(faults, folder: Path, name: str) -> bool:
    return any(str(folder / name) in f for f in faults)

@pytest.mark.parametrize("part", ["config.env", "access.yaml"])
def test_a_part_that_is_not_utf8_text_is_that_parts_fault_naming_the_file(tmp_path, part):
    """A `config.env` or `access.yaml` that is not UTF-8 text is a fault naming that file (no traceback, no decoded
    guess); the sibling part is read as it is. The part is the fixture's text plus ONE comment line of non-UTF-8 bytes,
    so the encoding is the only fault; control: the same folder with text parts has no fault. (#1366 P2, O11)"""
    folder = R.system_folder(tmp_path, "cmdb", config=CMDB_CONFIG, access=CMDB_ACCESS)
    assert read_folder(folder, "cmdb", locator=_FileLocator(folder)).faults == ()  # control: all text
    path = folder / part
    path.write_bytes(path.read_bytes() + b"# \xff\xfe not text \x80\n")
    read = read_folder(folder, "cmdb", locator=_FileLocator(folder))
    assert _names(read.faults, folder, part), read.faults
    assert not _names(read.faults, folder, ({"config.env", "access.yaml"} - {part}).pop()), read.faults


@pytest.mark.parametrize("part", ["config.env", "access.yaml"])
def test_a_part_larger_than_any_settings_file_is_that_parts_fault_not_a_crash(tmp_path, part):
    """A sparse part far larger than any settings file is a fault naming the file: no `MemoryError` out of the reader, no
    traceback. (#1366 O9, P2; moved from the oversized arms of `set-system` and the
    import.)"""
    folder = R.system_folder(tmp_path, "cmdb", config=CMDB_CONFIG, access=CMDB_ACCESS)
    with open(folder / part, "wb") as fh:
        fh.truncate(64 << 20)

    read = read_folder(folder, "cmdb", locator=_FileLocator(folder))

    assert _names(read.faults, folder, part), read.faults


def test_an_oversized_config_is_a_fault_naming_the_file_whatever_the_declaration(tmp_path):
    """An oversized `config.env` beside a sound `access.yaml` faults on the config only, and its settings are not
    half-read. (#1366 O9, P2)"""
    folder = R.system_folder(tmp_path, "cmdb", config=None, access=CMDB_ACCESS)
    with open(folder / "config.env", "wb") as fh:
        fh.truncate(64 << 20)

    read = read_folder(folder, "cmdb", locator=_FileLocator(folder))

    assert _names(read.faults, folder, "config.env"), read.faults
    assert not _names(read.faults, folder, "access.yaml"), read.faults
    assert dict(read.settings) == {}
    assert read.access == CMDB_ACCESS


@pytest.mark.parametrize("part", ["config.env", "access.yaml"])
def test_a_part_that_is_not_a_plain_file_is_that_parts_fault(tmp_path, part):
    """A `config.env` or `access.yaml` that is a directory (reading it raises `IsADirectoryError`), or an unreadable file
    (as root the mode does not deny a read, so that arm is skipped), is a fault naming the file, with no traceback.
    (#1366 O9, DC8; moved from the run-side resolver.)"""
    folder = R.system_folder(tmp_path, "cmdb", config=CMDB_CONFIG, access=CMDB_ACCESS)
    (folder / part).unlink()
    (folder / part).mkdir()

    read = read_folder(folder, "cmdb", locator=_FileLocator(folder))
    assert _names(read.faults, folder, part), read.faults

    if os.geteuid() != 0:
        (folder / part).rmdir()
        (folder / part).write_text("x\n", encoding="utf-8")
        (folder / part).chmod(0)
        try:
            read = read_folder(folder, "cmdb", locator=_FileLocator(folder))
        finally:
            (folder / part).chmod(0o644)
        assert _names(read.faults, folder, part), read.faults


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
def test_the_folder_reader_gives_the_value_the_one_quote_and_line_rules_give(tmp_path, line, stored):
    """The reader takes a `config.env` line's value by the one parser's rules: one matched quote pair trimmed (the inner
    quotes kept), no matched pair nothing trimmed, a mid-line `#` part of the value, comment, blank and no-`=` lines
    skipped without a fault. (Moved from the run-side 'one parser' tests; DC7.)"""
    timeout = f"TICKET_TIMEOUT_SEC=\"{TICKET_CONFIG['TICKET_TIMEOUT_SEC']}\""

    _, read = _read(tmp_path, "ticket", f"{timeout}\n{line}\n", TICKET_ACCESS)

    assert read.faults == (), read.faults
    assert read.settings["TICKET_KEY_PATTERN"] == stored, dict(read.settings)
    assert read.settings["TICKET_TIMEOUT_SEC"] == TICKET_CONFIG["TICKET_TIMEOUT_SEC"], dict(read.settings)


def test_a_byte_order_mark_and_crlf_line_endings_give_the_keys_as_written(tmp_path):
    """A leading byte-order mark and CRLF endings (or lone CR) are read as the line they end: the first key is the key as
    written (no BOM in it), no value ends in a carriage return. (Moved from the run-side nf15; DC7.)"""
    for n, ending in enumerate(("\r\n", "\r")):
        text = f'CMDB_TIMEOUT_SEC="2{n}"{ending}'

        _, read = _read(tmp_path / str(n), "cmdb", b"\xef\xbb\xbf" + text.encode("utf-8"), CMDB_ACCESS)

        assert read.faults == (), read.faults
        assert dict(read.settings) == {"CMDB_TIMEOUT_SEC": f"2{n}"}, dict(read.settings)


def test_keys_are_case_sensitive_so_a_lower_case_spelling_is_not_the_setting(tmp_path):
    """A key in lower case is read as written, not folded to the upper-case key the adapter reads: the reader gives
    `change_mgmt_timeout_sec` and not `CHANGE_MGMT_TIMEOUT_SEC` (the judgement then refuses the record). (Moved from the
    run-side nf15; P2.)"""
    _, read = _read(tmp_path, "change-mgmt", 'change_mgmt_timeout_sec="10"\n', R.FIXTURE_FOLDERS["change-mgmt"][1])

    assert dict(read.settings) == {"change_mgmt_timeout_sec": "10"}, dict(read.settings)


#: (id, extra config.env text, the key the reader's fault names, the secret value it carries, whether the reader also
#: leaves the value out of its settings): lines a config parser may ignore or override. The reader keeps the FIRST value of
#: a repeated key beside the fault (`folder_of_bytes`: the folder is refused whole by whoever judges it), so only the
#: `export` line is also absent from the settings. Whether the reader should withhold the first value too is open (#1470
#: report: r7 does not decide it); the fault naming the key is asserted on every row.
IGNORED_LINE_SECRETS = [
    ("export-line", 'export CMDB_API_TOKEN="sk-live-9f8e7d6c5b4a3f2e1d0c"\n', "CMDB_API_TOKEN", "sk-live-9f8e7d6c5b4a3f2e1d0c", True),
    ("overridden-duplicate", 'CMDB_PASSWORD="hunter2-live"\nCMDB_PASSWORD=""\n', "CMDB_PASSWORD", "hunter2-live", False),
    ("overridden-reference", 'CMDB_TOKEN_SECRET_REF="ghp-AbC!d3f@xyz"\nCMDB_TOKEN_SECRET_REF=""\n', "CMDB_TOKEN_SECRET_REF",
     "ghp-AbC!d3f@xyz", False),
]


@pytest.mark.parametrize("row", IGNORED_LINE_SECRETS, ids=[r[0] for r in IGNORED_LINE_SECRETS])
def test_1366_h2_a_secret_on_a_line_a_parser_ignores_never_enters_the_settings_the_reader_gives(tmp_path, row):
    """Guard: a secret on an ignored `export`/duplicate line is faulted or left out, never in the settings the reader
    gives (successor of the retired `test_validator_finds_secrets_on_lines_the_run_ignores`; the store half is gone with
    the operator's `set-system`). (#1366 H2, P2)"""
    _, extra, key, secret, withheld = row
    base = 'CMDB_TIMEOUT_SEC="20"\n'

    _, read = _read(tmp_path, "cmdb", base + extra, CMDB_ACCESS)

    assert any(key in f for f in read.faults), read.faults
    if withheld:
        assert secret not in repr(dict(read.settings)), f"a secret value was read:\n{dict(read.settings)}"
        assert set(read.settings) <= {"CMDB_TIMEOUT_SEC"}, dict(read.settings)


# --- R17: a line the old parser tolerated is refused ------------------------------------------------------------------------

REPO = Path(__file__).resolve().parents[4]
#: (id, the config.env text, the key the refusal names, a value that must not be stored): the declared key beside a line
#: the old reader silently ignored (`export`) or overrode (a duplicate).
R17_LINES = [
    ("duplicate-key", 'CMDB_TIMEOUT_SEC="10"\nCMDB_TIMEOUT_SEC="9917"\n', "CMDB_TIMEOUT_SEC", "9917"),
    ("duplicate-key-first-wins-looking", 'CMDB_TIMEOUT_SEC="9917"\nCMDB_TIMEOUT_SEC="10"\n', "CMDB_TIMEOUT_SEC", "9917"),
    ("export-line", 'CMDB_TIMEOUT_SEC="10"\nexport CMDB_TIMEOUT_SEC="9918"\n', "CMDB_TIMEOUT_SEC", "9918"),
    ("export-only-declared-key", 'export CMDB_TIMEOUT_SEC="9918"\n', "CMDB_TIMEOUT_SEC", "9918"),
]


@pytest.mark.parametrize("row", R17_LINES, ids=[r[0] for r in R17_LINES])
def test_1366_r17_connects_handoff_validator_refuses_a_duplicate_key_and_an_export_line_naming_the_file_and_the_key(tmp_path, row):
    """`validate_scaffold --handoff` judges the folder as the store does: the lines are a failure naming the key and the
    file (DC6), and the report is not a pass; the same folder with the key once passes. (#1366 R17, O11)"""
    import os

    _, text, key, _value = row

    def validated(config: str, label: str) -> tuple[int, str]:
        folder = R.system_folder(tmp_path / label, "cmdb", config=None, access=CMDB_ACCESS)
        (folder / "config.env").write_text(config, encoding="utf-8")
        done = subprocess.run([sys.executable, "-m", "defender.skills.connect.validate_scaffold", "cmdb",
                               "--handoff", str(folder)], cwd=REPO, env={**os.environ, "PYTHONPATH": str(REPO)},
                              capture_output=True, text=True, timeout=120, check=False)
        return done.returncode, done.stdout + done.stderr

    _rc, clean = validated('CMDB_TIMEOUT_SEC="10"\n', "clean")
    assert "the handoff's config.env and access.yaml are a record the store accepts for cmdb" in clean, clean  # control

    _rc, report = validated(text, "bad")

    assert "the handoff's config.env and access.yaml are a record the store accepts" not in report, report
    assert R.lines_naming(report, key, "config.env"), report
    assert "Traceback" not in report, report


@pytest.mark.parametrize("row", R17_LINES, ids=[r[0] for r in R17_LINES])
def test_1366_r17_the_reader_refuses_a_duplicate_key_and_an_export_line_naming_the_file_and_the_key(tmp_path, row):
    """A `config.env` repeating a key, or spelling a setting as `export KEY=value`, is a fault naming the file and the key
    (the old parser took the last value and skipped the `export` line), and the refused line's value is not among the
    settings. Control: the declared key once reads with no fault. (#1366 R17, H2)"""
    name, text, key, value = row

    folder, read = _read(tmp_path / "bad", "cmdb", text, CMDB_ACCESS)

    if name != "duplicate-key-first-wins-looking":  # the reader keeps a repeated key's first value beside the fault
        assert value not in dict(read.settings).values(), dict(read.settings)
    assert _names(read.faults, folder, "config.env"), read.faults
    assert any(key in f for f in read.faults), read.faults
    _, control = _read(tmp_path / "once", "cmdb", 'CMDB_TIMEOUT_SEC="10"\n', CMDB_ACCESS)
    assert control.faults == (), control.faults  # control: the key once is read
