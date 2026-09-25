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


def _round_trip(tree: Path, work: Path, *, payload: str = "defender.tests._rename_proof_1077",
                ) -> subprocess.CompletedProcess[str]:
    work.mkdir(parents=True, exist_ok=True)
    # `cwd=tree`, not merely `PYTHONPATH=tree`: `python -m` puts the CURRENT DIRECTORY first
    # on `sys.path`, so running from the repo root imports the REAL package and the whole
    # proof passes having renamed nothing. The `ALERT_NAME=` line the payload prints is what
    # the callers below check that against.
    return subprocess.run(
        [sys.executable, "-m", payload, str(work)],
        capture_output=True, text=True, timeout=300, cwd=str(tree),
        env={**os.environ, "PYTHONPATH": str(tree), "PYTHONDONTWRITEBYTECODE": "1",
             "PYDANTIC_AI_NO_BANNER": "1"},
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


# ---------------------------------------------------------------------------------------
# The session store — the one record whose path the archive round trip never opens
# ---------------------------------------------------------------------------------------
#
# The lint cannot see the store's path: `"sessions"` and `.db` are deliberately outside its
# match set (too generic). So the rename is the observer (#1077's session-store leftover, O1):
# rename the sessions directory, or the store's suffix, in `_run_paths.py` ALONE, and a real
# run must create its store where the owner now says — and a resume must find it there.
#
# ONLY those constants move, and only in `_run_paths.py`. Renaming every record as the archive
# proof does would also move the run's alert, which the replay harness's `drive` still hands
# the driver by its literal name — a failure that is not this rule's.

_SESSION_PAYLOAD = "defender.tests._rename_proof_1077_session"
_SESSION_NAMES = ("SESSIONS_DIRNAME", "SESSION_DB_SUFFIX")

#: What a store module that REMEMBERS the store's names looks like — the negative control's
#: `store_path_for`. Spliced in by AST, not by anchoring on the delegating line, so the control
#: does not depend on how the delegation happens to be spelled.
_HAND_COMPOSED_STORE_PATH_FOR = '''def store_path_for(case_id: str, *, runs_base: Path) -> Path:
    if not isinstance(case_id, str) or not CASE_ID_RE.match(case_id):
        raise InvalidCaseId(repr(case_id))
    return Path(runs_base).parent / "sessions" / f"{case_id}.db"
'''


def _with_function_replaced(source: str, name: str, replacement: str) -> str:
    tree = ast.parse(source)
    found = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == name]
    assert len(found) == 1, f"expected one top-level `def {name}`, found {len(found)}"
    node = found[0]
    start = min([node.lineno, *(d.lineno for d in node.decorator_list)])
    lines = source.splitlines(keepends=True)
    return "".join(lines[:start - 1]) + replacement + "".join(lines[node.end_lineno:])


def _session_renamed_tree(tmp_path: Path, names: tuple[str, ...], *,
                          hand_compose_store_path: bool = False) -> Path:
    root = tmp_path / ("sabotaged" if hand_compose_store_path else "renamed")
    owner = PACKAGE / "_run_paths.py"
    text, count = _rewrite_owner(owner.read_text(encoding="utf-8"), only=frozenset(names))
    assert count == len(names), (
        f"the rewrite renamed {count} of {names} in _run_paths.py — the owner no longer "
        "spells them as plain module constants, so this proof is not exercising")
    replace = {owner: text}
    if hand_compose_store_path:
        store = PACKAGE / "runtime" / "session_store.py"
        replace[store] = _with_function_replaced(
            store.read_text(encoding="utf-8"), "store_path_for", _HAND_COMPOSED_STORE_PATH_FOR)
    _mirror(PACKAGE, root / "defender", replace=replace)
    return root


def _loaded(result: subprocess.CompletedProcess[str], name: str) -> str:
    """The value the subprocess's OWN owner module holds for `name` — printed by the payload
    before it drives anything. A payload that died before printing it (the mirrored tree failed
    to import, say) is reported with its stderr, where the reason is."""
    for line in result.stdout.splitlines():
        if line.startswith(f"{name}="):
            return line.partition("=")[2]
    raise AssertionError(
        f"the payload never reported {name} (exit {result.returncode}):\n{result.stdout}\n"
        f"{result.stderr[-3000:]}")


@pytest.mark.parametrize("names", [("SESSIONS_DIRNAME",), ("SESSION_DB_SUFFIX",)],
                         ids=["sessions-dirname", "session-db-suffix"])
def test_the_session_store_moves_when_its_owner_renames_it(tmp_path, names):
    """Rename the sessions directory — or the store's suffix — in `_run_paths.py` alone, and a
    REAL run (the real driver, its default store factory, its own case pointer) creates its
    store at the owner's new path, and the resume door (`branch.open_source_store`, the store
    factory a resumed run is handed) finds it there.

    Each constant is renamed ALONE, because the obligation is that either one, alone, moves the
    store: a store module that took the directory from the owner but remembered the suffix
    passes a both-at-once rename only if the suffix happened to be checked some other way.

    What failure looks like: `store_path_for` composes the path out of names it remembers, the
    run writes its store under the OLD name, and the payload reports a store that is not where
    the owner says — the rename silently left every future run writing where it always did."""
    result = _round_trip(_session_renamed_tree(tmp_path, names), tmp_path / "work",
                         payload=_SESSION_PAYLOAD)
    tail = result.stderr[-3000:]
    for name in names:
        assert _TOKEN in _loaded(result, name), (
            f"the subprocess loaded the REAL {name}, not the renamed one — this run renamed "
            f"nothing and proves nothing:\n{result.stdout}")
    assert result.returncode == 0, (
        f"renaming {names} through the owner did not move the session store — something "
        f"composes the store's path out of names it was not given:\n{result.stdout}\n{tail}")
    assert "SESSION ROUNDTRIP OK" in result.stdout


def test_the_session_proof_fails_when_the_store_path_is_hand_composed(tmp_path):
    """The negative control, without which the case above proves nothing.

    `store_path_for` replaced by the hand-composed spelling this leftover exists to remove —
    the old directory and the old suffix, remembered rather than asked for — under the same
    rename. The round trip must fail, and fail at the session store rather than somewhere
    incidental."""
    tree = _session_renamed_tree(tmp_path, _SESSION_NAMES, hand_compose_store_path=True)
    result = _round_trip(tree, tmp_path / "work", payload=_SESSION_PAYLOAD)
    for name in _SESSION_NAMES:
        assert _TOKEN in _loaded(result, name), (
            f"the subprocess loaded the REAL {name} — the control renamed nothing:\n"
            f"{result.stdout}")
    assert result.returncode != 0, (
        "a hand-composed store path survived the rename — this proof is not discriminating, "
        f"so the positive case above means nothing:\n{result.stdout}")
    assert "session store:" in result.stderr, (
        "the round trip failed, but not at the session store:\n"
        f"{result.stderr[-3000:]}")


#: The owner's `sessions_dir` answer, changed IN THE METHOD rather than in a constant. A store
#: module that asks the owner follows it; one that re-composes the path out of the owner's
#: imported constants (the same names, so a constant rename cannot tell them apart) does not.
_SESSIONS_DIR_RETURN = "return self.trust_root / SESSIONS_DIRNAME"
_SESSIONS_DIR_RETURN_MOVED = f'return self.trust_root / (SESSIONS_DIRNAME + "-{_TOKEN}")'


def test_the_session_store_follows_the_owners_method_not_just_its_constants(tmp_path):
    """Change what `SessionPaths.sessions_dir` answers without touching a constant, and a real
    run's store still lands where the owner says and the resume door finds it. This is what
    tells "asks the owner" apart from "composes from the owner's constants"."""
    owner = PACKAGE / "_run_paths.py"
    text = owner.read_text(encoding="utf-8")
    assert text.count(_SESSIONS_DIR_RETURN) == 1, (
        "`SessionPaths.sessions_dir` no longer returns the spelling this proof rewrites — update "
        "the anchor, or this case exercises nothing")
    root = tmp_path / "method-moved"
    _mirror(PACKAGE, root / "defender",
            replace={owner: text.replace(_SESSIONS_DIR_RETURN, _SESSIONS_DIR_RETURN_MOVED)})
    result = _round_trip(root, tmp_path / "work", payload=_SESSION_PAYLOAD)
    assert _TOKEN in _loaded(result, "SESSIONS_DIR_SEEN"), (
        f"the subprocess's owner answered the unchanged sessions dir — this moved nothing:\n"
        f"{result.stdout}")
    assert result.returncode == 0, (
        "the owner's sessions dir moved but the store did not follow — something composes "
        f"the store's path itself:\n{result.stdout}\n{result.stderr[-3000:]}")
    assert "SESSION ROUNDTRIP OK" in result.stdout


#: The owner's `trust_root`, moved IN THE METHOD to a directory that is NOT the runs base's
#: parent — so a store that still anchors its mkdir on `runs_base.parent` by hand refuses the
#: owner's own answer as outside the tree, while one that asks the owner follows it.
_TRUST_ROOT_RETURN = "return self.runs_base.parent\n"
_TRUST_ROOT_RETURN_MOVED = f'return self.runs_base.parent.parent / "{_TOKEN}-state"\n'
_STORE_MKDIR_ASKED = "guarded_mkdir(path.parent, base=SessionPaths(runs_base).trust_root)"
_STORE_MKDIR_HAND_COMPOSED = "guarded_mkdir(path.parent, base=Path(runs_base).parent)"

_OPEN_ONE_STORE = (
    "import sys\n"
    "from pathlib import Path\n"
    "from defender.runtime import session_store\n"
    "with session_store.open_store(case_id='case-alpha', runs_base=Path(sys.argv[1])) as h:\n"
    "    print(f'STORE={h.path}')\n")


def _root_moved_tree(tmp_path: Path, *, hand_composed_mkdir: bool) -> Path:
    owner = PACKAGE / "_run_paths.py"
    text = owner.read_text(encoding="utf-8")
    assert text.count(_TRUST_ROOT_RETURN) == 1, (
        "`SessionPaths.trust_root` no longer returns the spelling this proof rewrites — update "
        "the anchor, or this case exercises nothing")
    replace = {owner: text.replace(_TRUST_ROOT_RETURN, _TRUST_ROOT_RETURN_MOVED)}
    if hand_composed_mkdir:
        store = PACKAGE / "runtime" / "session_store.py"
        store_text = store.read_text(encoding="utf-8")
        assert store_text.count(_STORE_MKDIR_ASKED) == 1
        replace[store] = store_text.replace(_STORE_MKDIR_ASKED, _STORE_MKDIR_HAND_COMPOSED)
    root = tmp_path / ("hand-composed-root" if hand_composed_mkdir else "root-moved")
    _mirror(PACKAGE, root / "defender", replace=replace)
    return root


def _open_one_store(tree: Path, runs_base: Path) -> subprocess.CompletedProcess[str]:
    runs_base.mkdir(parents=True)
    return subprocess.run(
        [sys.executable, "-c", _OPEN_ONE_STORE, str(runs_base)],
        capture_output=True, text=True, timeout=120, cwd=str(tree),
        env={**os.environ, "PYTHONPATH": str(tree), "PYTHONDONTWRITEBYTECODE": "1",
             "PYDANTIC_AI_NO_BANNER": "1"},
    )


def test_the_session_store_is_created_under_the_root_its_owner_names(tmp_path):
    """Move `SessionPaths.trust_root` somewhere that is not the runs base's parent, and the
    store is created there: the owner decides the root the store's directory is created
    under, not only the file's name. The negative control — the store anchoring its mkdir on
    `runs_base.parent` by hand, under the same move — must fail."""
    work = tmp_path / "work" / "inner"
    result = _open_one_store(_root_moved_tree(tmp_path, hand_composed_mkdir=False),
                             work / "runs")
    assert result.returncode == 0, (
        f"the owner's root moved and the store refused it:\n{result.stdout}\n"
        f"{result.stderr[-3000:]}")
    want = tmp_path / "work" / f"{_TOKEN}-state" / "sessions" / "case-alpha.db"
    assert f"STORE={want}" in result.stdout, result.stdout
    assert want.is_file()

    control = _open_one_store(_root_moved_tree(tmp_path, hand_composed_mkdir=True),
                              tmp_path / "control" / "inner" / "runs")
    assert control.returncode != 0, (
        "a store anchoring its mkdir by hand survived the owner's root moving — this proof is "
        f"not discriminating:\n{control.stdout}")
    assert "not inside" in control.stderr, (
        f"the control failed, but not at the store's mkdir root:\n{control.stderr[-3000:]}")
