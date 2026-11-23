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


@pytest.mark.parametrize("argv", [["--help"], *([c, "--help"] for c in sorted(KEPT_1470))], ids=lambda a: " ".join(a))
def test_1470_o11_the_commands_help_text_names_no_removed_command(argv, capsys):
    """`tenant.py --help` and `check --help` name no removed command (`update`, `propose` and `check <id>` included). (O11, B3)"""
    with pytest.raises(SystemExit) as helped:
        _cli().main(argv)
    assert helped.value.code == 0
    shown = capsys.readouterr().out
    assert len(shown) > 100, "premise: help was printed"  # noqa: PLR2004
    assert [line for line in shown.splitlines() if _NAMES_A_REMOVED_COMMAND.search(line)] == []


_DEFENDER = __import__("pathlib").Path(__file__).resolve().parents[3]
_UPGRADE_NOTES = "## Upgrade from before"


def _tracked() -> list[str]:
    """Every git-tracked path under `defender/`, relative to it (#1471 B3: all shipped text, whatever its suffix)."""
    import subprocess

    out = subprocess.run(["git", "-C", str(_DEFENDER), "ls-files", "-z", "--", "."],  # noqa: S603, S607
                         capture_output=True, check=True).stdout
    return sorted(p.decode("utf-8") for p in out.split(b"\0") if p)


def _shipped_lines() -> list[tuple[str, int, str]]:
    """Every line of shipped text under `defender/`: each git-tracked file that reads as UTF-8 (all but the tests and
    `docs/archive`), less the sections an `## Upgrade from before` heading opens (to the next `## `): the one place a
    removed command may be named."""
    found = []
    for rel in _tracked():
        path = _DEFENDER / rel
        if not path.is_file() or path.is_symlink() or rel.startswith("tests/") or rel.startswith("docs/archive/"):
            continue
        try:
            text = path.read_bytes().decode("utf-8")
        except UnicodeDecodeError:
            continue  # not text
        in_upgrade_notes = False
        for number, line in enumerate(text.splitlines(), 1):
            if line.startswith("## "):
                in_upgrade_notes = line.startswith(_UPGRADE_NOTES)
            if not in_upgrade_notes:
                found.append((rel, number, line))
    return found


def test_1470_o11_no_shipped_text_outside_the_upgrade_notes_names_a_removed_command():
    """No refusal, skill, doc, help or code text under `defender/` names a removed subcommand, except in an
    `## Upgrade from before` section. (O11)"""
    lines = _shipped_lines()
    files = {rel for rel, _, _ in lines}
    assert len(files) > 200, "premise: the scan reads the shipped tree"  # noqa: PLR2004
    assert {"skills", "docs", "cli", "systems"} <= {rel.split("/")[0] for rel in files}, "premise: skills and docs too"
    # #1471 B3: every suffix and none (the frontend's sources, its page, `bin/` scripts), not a list of suffixes
    assert {".ts", ".tsx", ".html", ""} <= {__import__("posixpath").splitext(rel)[1] for rel in files}, "premise: all text"
    naming = [f"{rel}:{n}: {line.strip()[:120]}" for rel, n, line in lines if _NAMES_A_REMOVED_COMMAND.search(line)]
    assert naming == []


def _joined(node: Any) -> str:
    """A string constant as a reader of the code sees it: implicit concatenation is already one constant in the tree; an
    f-string's text parts are joined with `{}` where a value goes."""
    import ast

    if isinstance(node, ast.JoinedStr):
        return "".join(v.value if isinstance(v, ast.Constant) and isinstance(v.value, str) else "{}" for v in node.values)
    return node.value


def _read_as_a_reader(rel: str, lines: list[str]) -> list[str]:
    """The texts of one shipped file as a reader sees them, whitespace runs (line breaks included) collapsed: for Python
    each string constant (implicit concatenation joined) and its comments run together; for anything else its prose,
    the lines `_shipped_lines` keeps run together."""
    import ast
    import io
    import tokenize

    def collapse(text: str) -> str:
        return " ".join(text.split())

    source = "\n".join(lines)
    if not rel.endswith(".py"):
        return [collapse(source)]
    tree = ast.parse(source)
    inner = {id(v) for node in ast.walk(tree) if isinstance(node, ast.JoinedStr) for v in node.values}
    texts = [collapse(_joined(node)) for node in ast.walk(tree) if id(node) not in inner and (
        isinstance(node, ast.JoinedStr) or (isinstance(node, ast.Constant) and isinstance(node.value, str)))]
    comments = [t.string.lstrip("#") for t in tokenize.generate_tokens(io.StringIO(source).readline)
                if t.type == tokenize.COMMENT]
    return [*texts, collapse(" ".join(comments))]


def test_1470_o11_no_shipped_text_names_a_removed_command_across_a_wrapped_line_or_a_joined_string():
    """Read as a reader sees it (a string's implicit concatenation joined, prose and comments with line breaks collapsed),
    no shipped text outside the upgrade notes names a removed subcommand. (O11)"""
    wrapped = ["run `python3 defender/cli/tenant.py", "catalog <id>`"]
    joined = ['ERROR = ("the operator runs `tenant.py "', '        "delete-" "system`")']
    assert [_NAMES_A_REMOVED_COMMAND.search(t) is not None for t in _read_as_a_reader("x.md", wrapped)] == [True], "premise"
    assert any(_NAMES_A_REMOVED_COMMAND.search(t) for t in _read_as_a_reader("x.py", joined)), "premise: the join"
    by_file: dict[str, list[str]] = {}
    for rel, _, line in _shipped_lines():
        by_file.setdefault(rel, []).append(line)
    naming = [f"{rel}: ...{found.group(0)}..." for rel, lines in sorted(by_file.items())
              for text in _read_as_a_reader(rel, lines) for found in _NAMES_A_REMOVED_COMMAND.finditer(text)]
    assert naming == []


def test_1470_o11_the_scan_skips_historical_docs_and_reads_the_rest_of_docs():
    """`docs/archive` (historical, not shipped) is not scanned; the rest of `docs/` is. (O11)"""
    files = {rel for rel, _, _ in _shipped_lines()}
    assert not [rel for rel in files if rel.startswith("docs/archive/")]
    assert any(rel.startswith("docs/") for rel in files)



# --- #1592 F9 / S3-16: the operator's revert machinery is removed whole -------------------------------------------------

def test_1592_f9_the_revert_machinery_is_gone():
    """S3-16: `cli/learning/revert_lesson.py`, `store_delivery.revert_lesson`, `drains.revert_delivery` and `reverts_of`
    are not in the product, and no shipped text still says `revert_lesson.py` stays."""
    import importlib
    import importlib.util

    from defender._git import REPO_ROOT

    assert not (REPO_ROOT / "defender" / "cli" / "learning" / "revert_lesson.py").exists()
    assert importlib.util.find_spec("defender.cli.learning.revert_lesson") is None
    store_delivery = importlib.import_module("defender.learning.author.version_control.store_delivery")
    drains = importlib.import_module("defender.learning.core.drains")
    assert not hasattr(store_delivery, "revert_lesson")
    assert not hasattr(drains, "revert_delivery")
    sources = [p for p in (REPO_ROOT / "defender").rglob("*.py")
               if "tests" not in p.relative_to(REPO_ROOT / "defender").parts[:1] and ".venv" not in p.parts]
    holders = sorted(str(p.relative_to(REPO_ROOT)) for p in sources if "reverts_of" in p.read_text(encoding="utf-8"))
    assert holders == [], f"`reverts_of` is still named: {holders}"
    notes = (REPO_ROOT / "defender" / "CLAUDE.md").read_text(encoding="utf-8")
    assert "revert_lesson.py` stays" not in notes
