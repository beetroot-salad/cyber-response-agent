"""D7's behavioural half: rename every record, and the tree still works (#1077).

WHY A SECOND CHECK AT ALL, when `lint_run_records.py` already reports zero. The gate is a
reader of syntax. It says no module outside the owners SPELLS a record name, HOLDS one, or
joins one onto a root — three checks over an AST. It says nothing about the trees it never
enters (`defender/skills`, top-level `scripts`, `experiments` — its own SCOPE_STATEMENT names
them), nothing about a name assembled so no part is ever a literal, and nothing about a name
that reaches the filesystem through a subprocess or a SQL statement.

So this asks the question the other way round. The gate proves no module SAYS a record's name.
This proves no module NEEDS to: rename every record through the owner, and a real archive
round trip — the writer, the screened readers and the judge's own report reader, spanning six
modules — still finds every file.

HOW THE RENAME IS DONE, and why not with `monkeypatch`. Patching `_run_paths.ALERT` after
import reaches nothing: a module that did `from ... import ALERT` holds its own reference, the
owners' derived constants (`SERVED_DIRNAME`, `PRIMING_LOCK_NAME`, `GATHER_RAW_SHAPE`) were
computed at import, `_episode_paths` took seven names off `_run_paths` at ITS import, and any
regex a consumer compiled at module load is already frozen. Every one of those follows
automatically from a SOURCE rewrite, so that is what this does: a scratch package whose
entries are symlinks to the real ones, except the owner modules, which are copies with every
record-name literal rewritten. The subprocess then imports a tree in which the records are
genuinely called something else.

The negative control is the load-bearing half. A test that passes because it exercises nothing
is the failure mode here, so the second case re-runs the same round trip against a tree where
ONE module hand-composes ONE name, and requires it to fail.
"""
from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGE = REPO_ROOT / "defender"
OWNER_MODULES = ("_run_paths.py", "_episode_paths.py", "_tenant.py")

#: The token every renamed record gains. Arbitrary — what matters is that no module anywhere
#: could have guessed it.
_TOKEN = "zq7"

#: Values that are NOT record names and are left alone: generic suffixes and extensions shared
#: with non-target code, prose, regex bodies, and id vocabulary. Renaming these proves nothing
#: and breaks things that have nothing to do with D7.
_SKIP_NAMES = frozenset({
    "ALIAS_READ_REFUSAL", "CASE_STABLE_REQUIRED", "LEAD_ID_BODY", "GATHER_RAW_SHAPE",
    "GATE_METADATA_KEY", "DEFAULT_TENANT_ID", "PAYLOAD_SUFFIX", "SESSION_DB_SUFFIX",
    "JSONL_EXT",
})
_SKIP_VALUES = frozenset({".json", ".db", ".jsonl", "json"})


def _renamed(value: str) -> str:
    """Rename the record, KEEPING ITS SHAPE — leading dot, extension, trailing slash.

    Shape is deliberately preserved, because shape is not what D7 promises. D7 promises the
    NAME can move through the owner; a reader keying on `.jsonl` to find line-delimited rows
    is reading a format, and a reader keying on the leading dot of a hidden file is reading a
    convention. Renaming those would fail this test for reasons that are not the rule.
    """
    trailing = "/" if value.endswith("/") else ""
    body = value[:-1] if trailing else value
    leading = "." if body.startswith(".") else ""
    body = body[1:] if leading else body
    head, dot, ext = body.partition(".")
    return f"{leading}{_TOKEN}{head}{dot}{ext}{trailing}"


def _rewrite_owner(source: str) -> tuple[str, int]:
    """One owner module's source with every record-name literal renamed."""
    tree = ast.parse(source)
    lines = source.splitlines(keepends=True)
    edits = []
    for node in tree.body:
        if not (isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)):
            continue
        name = node.targets[0].id
        value = node.value
        if (
            name.isupper() and name not in _SKIP_NAMES
            and isinstance(value, ast.Constant) and isinstance(value.value, str)
            and value.value not in _SKIP_VALUES
        ):
            edits.append((value.lineno, value.col_offset, value.end_col_offset,
                          _renamed(value.value)))
    for lineno, col, end_col, new in sorted(edits, reverse=True):
        line = lines[lineno - 1]
        lines[lineno - 1] = line[:col] + repr(new) + line[end_col:]
    return "".join(lines), len(edits)


def _mirror(src: Path, dst: Path, *, replace: dict[Path, str]) -> None:
    """`dst` mirrors `src`: a symlink per entry, except the ones `replace` supplies text for,
    which become real files (and whose parent directories become real too)."""
    dst.mkdir(parents=True, exist_ok=True)
    rewritten_here = {p.name for p in replace if p.parent == src}
    descend = {p.parts[len(src.parts)] for p in replace if p.parent != src and src in p.parents}
    for entry in src.iterdir():
        if entry.name == "__pycache__":
            continue
        if entry.name in rewritten_here:
            (dst / entry.name).write_text(replace[entry], encoding="utf-8")
        elif entry.name in descend:
            _mirror(entry, dst / entry.name, replace=replace)
        else:
            os.symlink(entry, dst / entry.name)


def _renamed_tree(tmp_path: Path, *, sabotage: str | None = None) -> Path:
    """A scratch package whose records are all called something else.

    `sabotage`, when given, additionally replaces one accessor use in `archive.py` with a
    hand-composed name — the negative control.
    """
    root = tmp_path / ("sabotaged" if sabotage else "renamed")
    replace: dict[Path, str] = {}
    total = 0
    for name in OWNER_MODULES:
        text, count = _rewrite_owner((PACKAGE / name).read_text(encoding="utf-8"))
        replace[PACKAGE / name] = text
        total += count
    assert total >= 30, f"the rewrite found only {total} record names — it is not exercising"

    if sabotage:
        archive = PACKAGE / "learning" / "branch" / "archive.py"
        text = archive.read_text(encoding="utf-8")
        assert sabotage in text, f"the sabotage anchor is gone from archive.py: {sabotage!r}"
        replace[archive] = text.replace(
            sabotage, '        summaries_dest = dest.dir / "gather_summaries"', 1)

    _mirror(PACKAGE, root / "defender", replace=replace)
    return root


def _round_trip(tree: Path, work: Path) -> subprocess.CompletedProcess[str]:
    work.mkdir(parents=True, exist_ok=True)
    # `cwd=tree`, not merely `PYTHONPATH=tree`: `python -m` puts the CURRENT DIRECTORY first
    # on `sys.path`, so running from the repo root imports the REAL package and the whole
    # proof passes having renamed nothing. The `ALERT_NAME=` line the payload prints is what
    # the callers below check that against.
    return subprocess.run(
        [sys.executable, "-m", "defender.tests._rename_proof_1077", str(work)],
        capture_output=True, text=True, timeout=300, cwd=str(tree),
        env={**os.environ, "PYTHONPATH": str(tree), "PYTHONDONTWRITEBYTECODE": "1"},
    )


def test_every_record_can_be_renamed_through_the_owner(tmp_path):
    """Rename every run and episode record, and a real archive round trip still finds them
    all.

    The round trip is not a toy: `archive_episode` screens and copies seven single files, two
    tables and a directory; the readers are the screened bound reader and the judge's own
    report reader. Six modules, none of which may spell a name.

    What failure looks like: one of them composes a path out of a name it remembers rather
    than one it asks for, and the file it opens is not the file the writer wrote — reported
    here as a missing record rather than, as in production, a reader silently seeing nothing.
    """
    result = _round_trip(_renamed_tree(tmp_path), tmp_path / "work")
    assert result.returncode == 0, (
        "the archive round trip broke when the records were renamed through their owner — "
        f"something composes a name it was not given:\n{result.stdout}\n{result.stderr}")
    assert "ROUNDTRIP OK" in result.stdout
    assert f"ALERT_NAME={_TOKEN}" in result.stdout, (
        "the subprocess loaded the REAL package, not the renamed one — this run renamed "
        f"nothing and proves nothing:\n{result.stdout}")


def test_the_rename_proof_fails_when_a_single_name_is_hand_composed(tmp_path):
    """The negative control, without which the test above proves nothing.

    One module, one accessor use, replaced by the hand-composed spelling this whole issue
    exists to remove. The round trip must fail — and fail at the record whose name was
    hand-composed, not somewhere incidental.
    """
    tree = _renamed_tree(tmp_path, sabotage="        summaries_dest = dest.gather_summaries")
    result = _round_trip(tree, tmp_path / "work")
    assert result.returncode != 0, (
        "a hand-composed record name survived the rename — this proof is not discriminating, "
        f"so the positive case above means nothing:\n{result.stdout}")
    assert "gather_summary" in result.stderr, (
        "the round trip failed, but not at the record that was hand-composed:\n"
        f"{result.stderr[-2000:]}")


@pytest.mark.parametrize(("value", "want"), [
    ("alert.json", "zq7alert.json"),
    ("wire_logs", "zq7wire_logs"),
    (".box-sentinel", ".zq7box-sentinel"),
    ("served/", "zq7served/"),
])
def test_the_rename_keeps_the_shape_it_promises_to_keep(value, want):
    """`_renamed` moves the NAME and leaves the shape — the leading dot of a hidden entry, the
    extension a format reader keys on, the trailing slash of a directory prefix. Pinned
    because a rename that changed those would fail the proof above for reasons that are not
    D7's rule, and the failure would read as a real finding."""
    assert _renamed(value) == want
