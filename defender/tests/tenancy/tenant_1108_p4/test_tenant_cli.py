"""#1470 O10 / O11 and #1471 B3: the operator commands the API replaced are removed, `check --folder` stays, and no shipped
text names a removed command. (`update`, `check <id>` and their trail/refusal reporting went with B3: see slice-D.md.)
"""
from __future__ import annotations

import re
import uuid
from typing import Any

import pytest

from defender.tests.support.tenancy import _records1470 as K


def _cli() -> Any:
    from defender.cli import tenant

    return tenant


# --- #1470 O10 / O11: the operator's record commands are removed, and nothing shipped names them ---------------------

#: O10's list, shared with the notes test (`_records1470`): the oracle for both tests below. B3 adds `update` and `propose`.
REMOVED_1470 = K.REMOVED_COMMANDS
#: What `--help` still offers: `check`, which keeps only `--folder` (B3).
KEPT_1470 = frozenset({"check"})
_HYPHENATED = sorted(c for c in REMOVED_1470 if "-" in c)
#: A removed hyphenated command named anywhere, a plain-word one named as `tenant.py <word>`, or `tenant.py check` not
#: followed by `--folder` (B3's `check <id>`, `K.CHECK_BY_ID`).
_NAMES_A_REMOVED_COMMAND = re.compile(
    rf"(?<![\w-])(?:{'|'.join(map(re.escape, _HYPHENATED))})(?![\w-])"
    rf"|tenant\.py[`'\"]?\s+(?:{'|'.join(map(re.escape, sorted(REMOVED_1470 - set(_HYPHENATED))))})(?![\w-])"
    rf"|{K.CHECK_BY_ID.pattern}")

#: The spellings of the text before `check`, the gap after `tenant.py`, and what follows it: each combination is a
#: way shipped text names (or does not name) the command.
_LEADS = ("", "run ", "run `python3 defender/cli/", "$ ./defender/cli/", "python3 /opt/d/cli/")
_GAPS = (" ", "  ", "\t", "` ", "' ", '" ', " \n")
_BY_ID = ("<id>", "<tenant-id>", "<tenant>", "acme", str(uuid.UUID(int=7)), "$TENANT", "--token-file /s/tok <id>",
          "--token-file t --kv-mount kv <id>", "", "`", ".", "`<id>`", "--kv-mount kv", "-x")
_BY_FOLDER = ("--folder <path>", "--folder=<path>", "--folder /tmp/repo", '--folder "a b"', "--folder",
              "--folder ./tenants/acme --other")


def _spelled(lead: str, gap: str, rest: str) -> str:
    return f"{lead}tenant.py{gap}check{' ' + rest if rest else ''}"


def test_1471_b3_the_census_pattern_bans_check_by_id_in_every_spelling_and_allows_check_folder_in_every_spelling():
    """`tenant.py check <tenant>` is named in any prefix, quoting, gap or id form, with or without flags before the id;
    `tenant.py check --folder ...` is named in none. (B3, C6)"""
    banned = [_spelled(lead, gap, rest) for lead in _LEADS for gap in _GAPS for rest in _BY_ID]
    kept = [_spelled(lead, gap, rest) for lead in _LEADS for gap in _GAPS for rest in _BY_FOLDER]
    assert len(banned) > 400, "premise: a class of spellings, not a hand list"  # noqa: PLR2004
    assert len(kept) > 200, "premise: a class of spellings, not a hand list"  # noqa: PLR2004
    assert [t for t in banned if not _NAMES_A_REMOVED_COMMAND.search(t)] == []
    assert [t for t in kept if _NAMES_A_REMOVED_COMMAND.search(t)] == []
    # Prose around it does not change either verdict.
    for text in banned:
        assert _NAMES_A_REMOVED_COMMAND.search(f"Then {text}, and report.")
    for text in kept:
        assert not _NAMES_A_REMOVED_COMMAND.search(f"Then {text}, and report.")


def test_1471_b3_the_census_pattern_does_not_mistake_words_that_only_start_like_check_or_a_folder_flag():
    """`tenant.py checkout`, `check-all`, a `--folders` flag and `check` away from `tenant.py` are not the command. (B3)"""
    for innocent in ("tenant.py checkout", "tenant.py check-all <id>", "tenant.py checks", "run a check <id> first",
                     "the tenant check <id> screen", "tenant.py"):
        assert not _NAMES_A_REMOVED_COMMAND.search(innocent), innocent
    assert _NAMES_A_REMOVED_COMMAND.search("tenant.py check --folders x"), "`--folders` is not `--folder`: still by id"


def test_1470_o11_the_census_pattern_finds_each_way_a_removed_command_is_named_and_not_the_kept_ones():
    """Control for the census below: it finds each removed command (`update` and `propose` included) in the forms shipped
    text names it, and not `check --folder` or plain words. (O11, B3)"""
    assert {"update", "propose"} <= REMOVED_1470, "B3 moved both from kept to removed"
    for command in REMOVED_1470:
        for lead in _LEADS:
            for gap in _GAPS:
                assert _NAMES_A_REMOVED_COMMAND.search(f"{lead}tenant.py{gap}{command} <id>"), (lead, gap, command)
        assert _NAMES_A_REMOVED_COMMAND.search(f"`tenant.py` {command} x"), command
    for command in _HYPHENATED:
        assert _NAMES_A_REMOVED_COMMAND.search(f"use `{command}` then"), command
    for innocent in ("tenant.py check --folder <path>", "the systems list", "set-systems-up", "an import statement",
                     "the catalog of adapters", "tenant.py", "update the docs", "propose a change", "the update tenant.py made",
                     "tenant.py --help"):
        assert not _NAMES_A_REMOVED_COMMAND.search(innocent), innocent


def test_1470_o10_each_removed_command_is_an_invalid_choice_and_only_check_is_offered(capsys):
    """Each removed subcommand (O10's nine, `update`, `propose`) is refused by argparse as an invalid choice (exit 2, no
    pointer shim) and is not offered in `--help`; `check` still is. (O10, B3, principle 3)"""
    with pytest.raises(SystemExit) as helped:
        _cli().main(["--help"])
    assert helped.value.code == 0
    offered = set(re.search(r"\{([\w,-]+)\}", capsys.readouterr().out).group(1).split(","))  # argparse's choices
    assert offered == KEPT_1470
    for command in sorted(REMOVED_1470):
        with pytest.raises(SystemExit) as refused:
            _cli().main([command, str(uuid.uuid4())])
        assert refused.value.code == 2, command  # noqa: PLR2004 — argparse's usage error
        assert "invalid choice" in capsys.readouterr().err, command


_ID = str(uuid.UUID(int=9))


@pytest.mark.parametrize("argv", [["check", _ID], ["check", "--token-file", "/nonexistent", _ID],
                                  ["check", _ID, "--folder", "."]], ids=" ".join)
def test_1471_b3_check_takes_no_tenant_id(argv, capsys):
    """`check <id>` is a usage error (exit 2) before any tenant, database or secret store is touched; `check` offers no
    `<tenant-id>` argument in its help. (B3)"""
    with pytest.raises(SystemExit) as refused:
        _cli().main(argv)
    assert refused.value.code == 2, capsys.readouterr()  # noqa: PLR2004 — argparse's usage error
    with pytest.raises(SystemExit):
        _cli().main(["check", "--help"])
    shown = capsys.readouterr().out
    assert "--folder" in shown, "premise: the help is check's"
    assert not re.search(r"tenant[-_ ]id", shown, re.I), shown


def test_1471_b3_check_folder_still_judges_a_folder(tmp_path, capsys):
    """Positive control on the same channel: `check --folder <path>` still runs and refuses a folder holding a stray file,
    naming it (exit 1, `[tenant.py]`), where `check <id>` is a usage error. (B3)"""
    folder = tmp_path / "repo"
    folder.mkdir()
    (folder / "stray.txt").write_text("x\n", encoding="utf-8")
    rc = _cli().main(["check", "--folder", str(folder)])
    said = capsys.readouterr()
    assert rc == 1, said
    assert "[tenant.py]" in said.err + said.out, said
    assert "stray.txt" in said.err + said.out, said
