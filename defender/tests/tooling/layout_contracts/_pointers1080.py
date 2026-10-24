"""The tracked-text pointer scans #1080's coherence demands run — a doc, comment, config comment,
test table or lint list that still points into `defender/scripts/` at something the move took
away. NO tests."""
from __future__ import annotations

import functools
import re
from collections.abc import Iterator
from pathlib import Path
from typing import NamedTuple

from defender import _git
from defender.tests.tooling.layout_contracts import _spec1080 as S

#: Never scanned (module docstring), as repo-relative directory prefixes.
EXCLUDED_DIRS: tuple[str, ...] = (
    # archival: frozen records of their moment
    "experiments/", "docs/decisions/", "docs/archive/", "defender/docs/decisions/", "defender/docs/archive/", "playground-v2/docs/archive/", ".claude/worktrees/",
    # recorded data that quotes the code of its moment (lint_stale_refs.EXCLUDED_GREP_DIRS)
    "playground-v2/examples/alerts/", "defender/tests/fixtures/e2e/", "defender/lessons/", "defender/lessons-actor/",  # lint-stale-ref: ok — base-era exclusions this suite records on purpose
    "defender/lessons-environment/", "defender/lessons-questioner/",  # lint-stale-ref: ok — base-era exclusions this suite records on purpose
    "evaluations/judge_alignment/", "evaluations/oracle_golden/cases/",
    # this suite: it records the base on purpose
    "defender/tests/tooling/layout_contracts/",
)

_SCRIPTS = "defender/scripts/"

#: A path spelling of a base entry: after `defender/`, after `}/` (`${DEFENDER}/scripts/…`), or
#: a bare `scripts/` that is not the tail of a longer path.
_SLASH = re.compile(r"(?:(?<=defender/)|(?<=}/)|(?<![\w./-]))scripts/([\w./-]+)")
#: A module spelling: `defender.scripts.x.y` or `scripts.x.y`, never `<other>.scripts.x`.
_DOTTED = re.compile(r"(?<![\w.])(?:defender\.)?scripts\.([A-Za-z_][\w.]*)")
#: An import spelling, whose imported names may be the modules: `from defender.integrations
#: import faults, confinement` names `adapters/faults.py` and `adapters/confinement.py`.
_FROM_IMPORT = re.compile(
    r"(?<![\w.])from\s+((?:defender\.)?scripts(?:\.\w+)*)\s+import\s+\(?\s*(\w+(?:\s*,\s*\w+)*)")
#: A join spelling: `"scripts" / "seg" / "seg"`.
_JOIN = re.compile(r"""["']scripts["']((?:\s*/\s*["'][\w.-]+["'])+)""")
_JOIN_SEG = re.compile(r"""["']([\w.-]+)["']""")
#: Characters after a path token that make it a pattern or placeholder, not a path.
_PLACEHOLDER_NEXT = frozenset("*{<$[")


class Pointer(NamedTuple):
    """One pointer: the file (repo-relative), the 1-based line, and the text as spelled."""

    relpath: str
    line: int
    text: str


@functools.lru_cache(maxsize=1)
def base_entries() -> frozenset[str]:
    """Every tracked file and subfolder `defender/scripts/` held at the base, relative to it."""
    inv = S.base_inventory()
    return frozenset(p[len(_SCRIPTS):] for p in (*inv["files"], *inv["subdirs"]))


def _entry_of(parts: list[str]) -> str | None:
    """The longest leading run of `parts` that names a base entry, or None. A module part may
    omit its `.py` (`scripts.pricing`, `scripts/workspace_map`), and a path's last part may carry
    a symbol after the module (`scripts/_venv.reexec_into_venv`)."""
    entries = base_entries()

    def hit(head: str) -> str | None:
        if head in entries:
            return head
        return f"{head}.py" if f"{head}.py" in entries else None

    for k in range(len(parts), 0, -1):
        found = hit("/".join(parts[:k]))
        if found:
            return found
        if k == len(parts) and "." in parts[-1]:
            dots = parts[-1].split(".")
            for j in range(len(dots) - 1, 0, -1):
                found = hit("/".join([*parts[:-1], ".".join(dots[:j])]))
                if found:
                    return found
    return None


def scanned(relpath: str) -> bool:
    """Whether a tracked file is in the scans' scope (not under `EXCLUDED_DIRS`)."""
    return not relpath.startswith(EXCLUDED_DIRS)


def tracked_text(root: Path) -> Iterator[tuple[str, list[str]]]:
    """`(relpath, lines)` for every tracked, in-scope, UTF-8 text file under `root`."""
    out = _git.git(["ls-files", "-z"], cwd=root)  # lint-oracle: ok — the pointer scan's own scope (tracked files), not an expected value for tenant.py's read
    for rel in sorted(p for p in out.split("\0") if p):
        if not scanned(rel):
            continue
        path = root / rel
        if path.is_symlink() or not path.is_file():
            continue
        data = path.read_bytes()
        if b"\0" in data:
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        yield rel, text.splitlines()


def _clean_tail(tail: str) -> str:
    return tail.rstrip(".,:;/")


def _slash_hits(line: str, *, skip_placeholders: bool = False) -> Iterator[tuple[str, str, bool]]:
    """`(text as spelled, cleaned tail, anchored)` for every path spelling on one line; anchored
    when it sits under `defender/` or `${…}/` (the defender tree), with that prefix kept in the
    text."""
    for m in _SLASH.finditer(line):
        if skip_placeholders and m.end() < len(line) and line[m.end()] in _PLACEHOLDER_NEXT:
            continue
        tail = _clean_tail(m.group(1))
        if not tail:
            continue
        before = line[:m.start()]
        anchored = before.endswith(("defender/", "}/"))
        prefix = "defender/" if before.endswith("defender/") else ""
        yield prefix + m.group(0).rstrip(".,:;/"), tail, anchored


def _named_entries(line: str) -> Iterator[tuple[str, str]]:
    """`(text as spelled, base entry)` for every pointer on one line."""
    for text, tail, _anchored in _slash_hits(line):
        entry = _entry_of(tail.split("/"))
        if entry:
            yield text, entry
    for m in _DOTTED.finditer(line):
        entry = _entry_of(m.group(1).rstrip(".").split("."))
        if entry:
            yield m.group(0).rstrip("."), entry
    for m in _FROM_IMPORT.finditer(line):
        module = m.group(1).split(".")
        stem = module[module.index("scripts") + 1:]
        for name in re.split(r"\s*,\s*", m.group(2)):
            entry = _entry_of([*stem, name])
            if entry and entry != _entry_of(stem):
                yield f"from {m.group(1)} import {name}", entry
    for m in _JOIN.finditer(line):
        entry = _entry_of(_JOIN_SEG.findall(m.group(1)))
        if entry:
            yield m.group(0), entry


def _gone(root: Path, entry: str) -> bool:
    p = root / _SCRIPTS / entry
    return not (p.exists() or p.is_symlink())


def stale_scripts_pointers(root: Path) -> list[tuple[str, int, str]]:
    """Every tracked, in-scope pointer under `root` naming a base `defender/scripts/` entry that
    no longer exists there, as `(relpath, line, text)` (module docstring)."""
    found: list[tuple[str, int, str]] = []
    for rel, lines in tracked_text(root):
        for i, line in enumerate(lines, 1):
            for text in sorted({t for t, entry in _named_entries(line) if _gone(root, entry)}):
                found.append(Pointer(rel, i, text))
    return found


def vanished_folders(root: Path) -> tuple[str, ...]:
    """The base subfolders of `defender/scripts/` (relative to it) that no longer exist."""
    return tuple(sorted(d[len(_SCRIPTS):] for d in S.base_inventory()["subdirs"]
                        if not (root / d).is_dir()))


def vanished_folder_mentions(root: Path) -> list[tuple[str, int, str]]:
    """Every pointer into a vanished base subfolder, and every bare `<subfolder>/` path component
    naming one (not preceded by a path character), as `(relpath, line, text)`."""
    gone = vanished_folders(root)
    if not gone:
        return []
    # A name still live as a directory is ambiguous: a bare `<name>/` may mean the live one.
    # Live means under `defender/`, or (#1108 P4, OD6) in a tenant's agent half, where the
    # corpora moved (`agent/lessons/`, `agent/lessons-questioner/`): a bare `lessons/` is the
    # tenant corpus (a branch prefix, a lane), not a pointer to the vanished checkout folder.
    ambiguous = {g for g in gone if (root / "defender" / g).is_dir()
                 or any(p.is_dir() for p in (root / "knowledge").glob(f"*/agent/{g}"))}
    bare_names = sorted(set(gone) - ambiguous, key=len, reverse=True)
    bare = re.compile(r"(?<![\w./-])(?:" + "|".join(re.escape(g) for g in bare_names)
                      + r")/") if bare_names else None
    found: list[tuple[str, int, str]] = []
    for rel, lines in tracked_text(root):
        for i, line in enumerate(lines, 1):
            hits = {text for text, entry in _named_entries(line)
                    if any(entry == g or entry.startswith(g + "/") for g in gone)}
            if bare is not None:
                hits.update(m.group(0) for m in bare.finditer(line))
            found.extend(Pointer(rel, i, t) for t in sorted(hits))
    return found


def dead_scripts_pointers(root: Path) -> list[tuple[str, int, str]]:
    """Every `scripts/<path>` path spelling (module docstring) that resolves under neither
    `root/defender/scripts/` nor `root/scripts/` — base entry or not — as `(relpath, line, text)`.
    A spelling followed by a glob or placeholder character (`lint_*.py`, `{id}`) is skipped."""
    found: list[tuple[str, int, str]] = []
    for rel, lines in tracked_text(root):
        for i, line in enumerate(lines, 1):
            for text, tail, anchored in _slash_hits(line, skip_placeholders=True):
                cands = [root / _SCRIPTS / tail] if anchored else \
                    [root / _SCRIPTS / tail, root / "scripts" / tail]
                if not any(c.exists() or c.is_symlink() for c in cands):
                    found.append(Pointer(rel, i, text))
    return found
