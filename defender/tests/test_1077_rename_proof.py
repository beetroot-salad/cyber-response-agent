"""D7's behavioural half: rename every record, and the tree still works (#1077)."""
from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
PACKAGE = REPO_ROOT / "defender"
#: By path under `defender/`: #1105 moved the run-layout owner into the runs repository (D1.1).
OWNER_MODULES = ("run_repository/_layout.py", "_episode_paths.py", "_tenant.py")

#: The token every renamed record gains. Arbitrary — what matters is that no module anywhere
#: could have guessed it.
_TOKEN = "zq7"

#: Values that are NOT record names and are left alone: generic suffixes and extensions shared
_SKIP_NAMES = frozenset({
    "ALIAS_READ_REFUSAL", "CASE_STABLE_REQUIRED", "LEAD_ID_BODY", "GATHER_RAW_SHAPE",
    "GATE_METADATA_KEY", "PAYLOAD_SUFFIX", "SESSION_DB_SUFFIX",
    "JSONL_EXT",
})
_SKIP_VALUES = frozenset({".json", ".db", ".jsonl", "json"})


def _renamed(value: str) -> str:
    """Rename the record, KEEPING ITS SHAPE — leading dot, extension, trailing slash."""
    trailing = "/" if value.endswith("/") else ""
    body = value[:-1] if trailing else value
    leading = "." if body.startswith(".") else ""
    body = body[1:] if leading else body
    head, dot, ext = body.partition(".")
    return f"{leading}{_TOKEN}{head}{dot}{ext}{trailing}"


def _rewrite_owner(source: str, *, only: frozenset[str] | None = None) -> tuple[str, int]:
    """One owner module's source with every record-name literal renamed — or, given `only`,
    exactly the constants it names and nothing else (the skip lists do not apply: naming a
    constant there is the caller saying it is the subject)."""
    tree = ast.parse(source)
    lines = source.splitlines(keepends=True)
    edits = []
    for node in tree.body:
        if not (isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)):
            continue
        name = node.targets[0].id
        value = node.value
        if not (isinstance(value, ast.Constant) and isinstance(value.value, str)):
            continue
        chosen = (name in only) if only is not None else (
            name.isupper() and name not in _SKIP_NAMES and value.value not in _SKIP_VALUES)
        if chosen:
            edits.append((value.lineno, value.col_offset, value.end_col_offset,
                          _renamed(value.value)))
    for lineno, col, end_col, new in sorted(edits, reverse=True):
        line = lines[lineno - 1]
        lines[lineno - 1] = line[:col] + repr(new) + line[end_col:]
    return "".join(lines), len(edits)


def _owner_text(owner: Path) -> str:
    """The owner module's source. A stale owner path fails here by name, not as a bare
    `FileNotFoundError` deep in a rewrite."""
    assert owner.is_file(), f"no owner module at {owner.relative_to(PACKAGE)} — a stale owner path"
    return owner.read_text(encoding="utf-8")


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
    """A scratch package whose records are all called something else."""
    root = tmp_path / ("sabotaged" if sabotage else "renamed")
    replace: dict[Path, str] = {}
    total = 0
    for name in OWNER_MODULES:
        text, count = _rewrite_owner(_owner_text(PACKAGE / name))
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


def _round_trip(tree: Path, work: Path, *, payload: str = "defender.tests._rename_proof_1077",
                ) -> subprocess.CompletedProcess[str]:
    work.mkdir(parents=True, exist_ok=True)
    return subprocess.run(
        [sys.executable, "-m", payload, str(work)],
        capture_output=True, text=True, timeout=300, cwd=str(tree),
        env={**os.environ, "PYTHONPATH": str(tree), "PYTHONDONTWRITEBYTECODE": "1",
             "PYDANTIC_AI_NO_BANNER": "1"},
    )


def test_every_record_can_be_renamed_through_the_owner(tmp_path):
    """Rename every run and episode record, and a real archive round trip still finds them all."""
    result = _round_trip(_renamed_tree(tmp_path), tmp_path / "work")
    assert result.returncode == 0, (
        "the archive round trip broke when the records were renamed through their owner — "
        f"something composes a name it was not given:\n{result.stdout}\n{result.stderr}")
    assert "ROUNDTRIP OK" in result.stdout
    assert f"ALERT_NAME={_TOKEN}" in result.stdout, (
        "the subprocess loaded the REAL package, not the renamed one — this run renamed "
        f"nothing and proves nothing:\n{result.stdout}")
