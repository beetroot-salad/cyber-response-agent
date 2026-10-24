from __future__ import annotations

import ast
import fnmatch
import functools
import hashlib
import json
import re
import sys
from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

import pytest
import yaml

from defender import _git
from defender.tests.support.shared.contracts._by_path import load_lint_gate
from defender.tests.tooling.layout_contracts import _pointers1080 as P
from defender.tests.tooling.layout_contracts import _spec1080 as S


LINT_DIR = S.REPO_ROOT / "tooling" / "lint"
CI = S.REPO_ROOT / ".github" / "workflows" / "ci.yml"


MOVED_HOMES: dict[str, tuple[tuple[str, str | None], ...]] = {
    "defender/scripts/_venv.py": (("reexec_into_venv", S.VENV),),
    "defender/scripts/pricing.py": (("usage_cost", S.PRICING),),
    "defender/scripts/gather_tools/payload_view.py": (("passthrough_max_bytes", None),),
    "defender/scripts/gather_tools/sql.py": (("_load_payload", S.RUNTIME),),
    "defender/scripts/lessons/_lessons_common.py": (("resolve_corpus", None),),
    "defender/scripts/lessons/lessons_fm.py": (("cmd_tags", None),),
    "defender/scripts/lessons/lessons_frontier.py": (("match_lessons", None),),
    "defender/scripts/case_history/case_ticket.py": (("load_case_mapping", S.RUNTIME),),
}

#: The OUT files whose base lint-baseline keys stay keyed at their base paths (cut_edit of
#: m5_baselines_name_no_moved_path and s105: `derive_system`). The case-ticket findings left
#: this list with #1190: their file moves (`MOVED_HOMES`), so they are re-keyed to its home.
OUT_KEYED = ("defender/scripts/gather_tools/record_query.py",)

#: The shims that ran a wrapper at the base and now run their engine as a module (post-review,
#: reversing M-H (a)); every other shim stays byte-identical to the base.
WRAPPER_SHIMS = ("defender-sql", "defender-lessons")

#: The four commands that stay in `scripts/` (D1).
STAYING_COMMANDS = ("tenant", "policy_cli", "box_image", "image_cli", "tacit_cli")

#: The four path-scoped gates s135 plants for, by the idiom each one flags.
GATES = {
    "run_records": "lint_run_records",            # a record-name literal
    "env_reads": "lint_tenant_env_reads",         # a tenant env read
    "tree_write": "lint_unguarded_tree_write",    # an unguarded tree write
    "tree_read": "lint_tree_read_follows_link",   # a link-following tree read
}

#: The plant: every idiom the four gates flag, inside one uniquely named function.
PLANT_FN = "_spec1080_plant"
PLANT = (
    "\n\nimport os as _spec1080_os  # planted by #1080's lint-scope tests\n\n\n"
    f"def {PLANT_FN}(p):\n"
    '    record = "alert.json"\n'
    '    p.write_text(_spec1080_os.environ.get("SPEC1080_PLANT", record))\n'
    "    return p.is_file()\n"
)

#: Staying files each gate covers before and after the move: the plant there is the control
#: that proves the gate's observation channel (and keeps the env-read lint from scanning blind).
CONTROLS = {
    "defender/integrations/cmdb_adapter.py": ("run_records", "env_reads", "tree_write"),
    "defender/learning/branch/episode.py": ("tree_read",),
}


def _golden() -> Mapping[str, Any]:
    return S.golden("lints")


@functools.cache
def _lint(stem: str) -> Any:
    return load_lint_gate(stem, name=f"{stem}_spec1080")


@functools.cache
def _homes(base_path: str) -> list[str]:
    """Where `base_path`'s code lives now: one home per anchor (found by symbol)."""
    return [S.home_of(sym, home=home) for sym, home in MOVED_HOMES[base_path]]


def _drel(relpath: str) -> str:
    """A repo-relative `defender/...` path relative to `defender/` (the tree-read, tree-write
    and run-records lints key their findings that way)."""
    assert relpath.startswith("defender/"), relpath
    return relpath[len("defender/"):]


def _plant(root: Path, relpath: str) -> range:
    """Append `PLANT` to a copy of `relpath`'s CURRENT source (from this checkout) at
    `root/relpath`; the 1-based line range the plant occupies."""
    src = S.REPO_ROOT / relpath
    before = src.read_text(encoding="utf-8") if src.is_file() else ""
    dst = root / relpath
    if dst.exists():
        before = dst.read_text(encoding="utf-8")
    if before and not before.endswith("\n"):
        before += "\n"
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(before + PLANT, encoding="utf-8")
    start = before.count("\n") + 1
    return range(start, start + PLANT.count("\n") + 1)


def _gate_findings(gate: str, root: Path) -> list[str]:
    """One gate's scan over a repo-shaped `root`, as `fingerprint display` strings — the scan
    function itself, so no baseline can hide a plant."""
    lint = _lint(GATES[gate])
    if gate == "env_reads":
        return list(lint.scan(root))
    tree = root / "defender"
    if gate == "run_records":
        found = lint.scan(tree, allow_list={})
    else:
        found = lint._scan(tree)
    return [f"{f.fingerprint} {f.display}" for f in found]


def _reported(gate: str, findings: Iterable[str], relpath: str, lines: range) -> bool:
    """Whether `findings` carry the plant at `relpath` (by the plant's function or line)."""
    rel = relpath if gate == "env_reads" else _drel(relpath)
    for s in findings:
        if not s.startswith(rel + ":"):
            continue
        if PLANT_FN in s:
            return True
        m = re.match(re.escape(rel) + r":(\d+)", s)
        if m and int(m.group(1)) in lines:
            return True
    return False


def plant_and_scan(root: Path, relpaths: Iterable[str]) -> dict[str, list[str]]:
    """Plant every relpath (plus the controls) under `root`, scan once per gate, and return
    relpath -> the gates that reported its plant. Shared with the golden's capture."""
    planted = {r: _plant(root, r) for r in sorted({*relpaths, *CONTROLS})}
    found = {g: _gate_findings(g, root) for g in GATES}
    return {r: sorted(g for g in GATES if _reported(g, found[g], r, planted[r]))
            for r in planted}


def lint_scope_lists() -> dict[str, list[str]]:
    """Every module-level tuple/list/set/frozenset/dict (keys) of string constants in
    `tooling/lint/*.py` that holds a path-shaped entry (a `/`), as `"<file>::<name>"` -> its
    path-shaped entries; plus `lint_run_records.SWEEP_DIRS` (bare folder names under
    `defender/`)."""
    shaped = re.compile(r"^[\w.$-]+(?:/[\w.*-]+)*/?$")
    out: dict[str, list[str]] = {}
    for f in sorted(LINT_DIR.glob("*.py")):
        tree = ast.parse(f.read_text(encoding="utf-8"), filename=str(f))
        for n in tree.body:
            if isinstance(n, ast.Assign) and len(n.targets) == 1 \
                    and isinstance(n.targets[0], ast.Name):
                name, value = n.targets[0].id, n.value
            elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.value:
                name, value = n.target.id, n.value
            else:
                continue
            if isinstance(value, ast.Call) and value.args:
                value = value.args[0]
            if isinstance(value, ast.Dict):
                elts = [k for k in value.keys if k is not None]
            elif isinstance(value, (ast.Tuple, ast.List, ast.Set)):
                elts = list(value.elts)
            else:
                continue
            paths = [e.value for e in elts if isinstance(e, ast.Constant)
                     and isinstance(e.value, str) and "/" in e.value and shaped.match(e.value)]
            if paths:
                out[f"{f.name}::{name}"] = paths
    out["lint_run_records.py::SWEEP_DIRS"] = [
        f"defender/{d}" for d in _lint("lint_run_records").SWEEP_DIRS]
    return out


def resolves(entry: str) -> bool:
    """A lint-list or baseline path resolves against the repo root or `defender/` (the
    tree-read and tree-write lists are relative to `defender/`)."""
    entry = entry.rstrip("/")
    return any((base / entry).exists() or (base / entry).is_symlink()
               for base in (S.REPO_ROOT, S.DEFENDER))


def env_dependent(entry: str) -> bool:
    """An entry naming a directory that exists only in some checkouts (a venv, a cache, the
    linked-worktree folder): its presence is the machine's, not the tree's."""
    parts = entry.rstrip("/").split("/")
    return bool(S.JUNK_DIRS.intersection(parts)) or entry.startswith(".claude/worktrees")


def dead_scope_entries() -> dict[str, list[str]]:
    return {k: sorted(e for e in v if not resolves(e) and not env_dependent(e))
            for k, v in lint_scope_lists().items()}


#: A path-shaped token inside a baseline key.
_KEY_PATH = re.compile(
    r"(?<![\w./-])((?:[\w.-]+/)*[\w.-]+\.(?:py|md|yaml|yml|json|toml|sh|txt|tsv))(?![\w/])")


def baselines() -> dict[str, dict[str, str]]:
    return {f.name: json.loads(f.read_text(encoding="utf-8")).get("entries", {})
            for f in sorted(LINT_DIR.glob("*_baseline.json"))}


def key_paths(key: str) -> list[str]:
    return _KEY_PATH.findall(key)


def baseline_keys_naming_scripts() -> dict[str, list[str]]:
    """Per baseline file: the keys naming a path under `defender/scripts/`."""
    return {name: sorted(k for k in entries if any(S.under(p, "defender/scripts")
                                                   for p in key_paths(k)))
            for name, entries in baselines().items()}


def _git_repo(root: Path, files: Mapping[str, str]) -> Path:
    """A tmp git repo at `root` holding `files` (repo-relative path -> text), all `git add`ed."""
    for rel, text in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
    _git.git(["init", "-q"], cwd=root)
    _git.git(["add", "-A"], cwd=root)
    return root


def usage_block(text: str) -> str:
    """A command's `usage:` paragraph (its CLI surface), up to the first blank line."""
    out: list[str] = []
    for line in text.splitlines():
        if not line.strip() and out:
            break
        if out or line.startswith("usage:"):
            out.append(line.rstrip())
    return "\n".join(out)


def staying_command_runs(tmp_cwd: Path) -> dict[str, Any]:
    """Each staying command, run from a working directory outside the checkout, the way CI, a
    shim or a doc runs it — `--help`, so nothing is written. Shared with the golden's capture."""
    venv_bin = str(Path(sys.executable).parent)
    path = f"{venv_bin}:/usr/local/bin:/usr/bin:/bin"
    bare = S.child_env(pythonpath=False, PATH=path, COLUMNS="100")
    rooted = S.child_env(PATH=path, COLUMNS="100")
    py = sys.executable
    cases = {
        "tenant.py by path": ([py, S.CLI / "tenant.py", "--help"], bare),
        "policy_cli via bin/defender-policy": ([S.BIN / "defender-policy", "--help"], bare),
        "policy_cli by module": ([py, "-m", "defender.cli.policy_cli", "--help"], rooted),
        "tacit_cli by module": ([py, "-m", "defender.cli.tacit_cli", "--help"], rooted),
        "box_image.py by path, bare interpreter": (
            [py, "-I", "-S", S.IMAGE_CLI, "--help"], bare),
    }
    out: dict[str, Any] = {}
    for name, (argv, env) in cases.items():
        r = S.run(argv, cwd=tmp_cwd, env=env)
        out[name] = {"rc": r.returncode,
                     "usage": usage_block(r.stdout.decode("utf-8", "replace"))}
    return out


#: A CI `run:` line invoking a command under `defender/scripts/` by path or by module.
_CI_STAYING = re.compile(r"^\s*(?:-\s*)?run:\s*(.*(?:defender/(?:cli|box)/|-m defender\.cli\.).*)$")


def ci_staying_runs(text: str) -> list[str]:
    return [m.group(1).strip() for m in map(_CI_STAYING.match, text.splitlines()) if m]


#: A command naming a `defender/scripts/` file by path or a `defender.scripts` module.
_CMD_PATH = re.compile(r"(?<![\w.-])(?:defender/)?(?:cli|box)/(\w+)\.py\b")
_CMD_MODULE = re.compile(r"-m\s+defender\.cli\.(\w+)\b")


def _runnable(name: str) -> bool:
    p = S.IMAGE_CLI if name in {"box_image", "image_cli"} else S.CLI / f"{name}.py"
    return p.is_file() and S.has_main_block(p.read_bytes())


def docs_invoking_broken_commands() -> list[tuple[str, int, str]]:
    """Every tracked-text invocation of a staying command (by path or `-m`) that names no file
    with a `__main__` block, and every `python … cli/tenant.py <sub>` whose subcommand the
    command's base usage does not offer."""
    usage = _golden()["staying_command_runs"]["tenant.py by path"]["usage"]
    subcommands = set(re.search(r"\{([\w,-]+)\}", usage).group(1).split(","))
    tenant_sub = re.compile(r"python3?\s+\S*scripts/tenant\.py\s+([a-z][\w-]*)")
    broken: list[tuple[str, int, str]] = []
    for rel, lines in P.tracked_text(S.REPO_ROOT):
        for i, line in enumerate(lines, 1):
            broken += [(rel, i, n) for n in _CMD_PATH.findall(line) + _CMD_MODULE.findall(line)
                       if n in STAYING_COMMANDS and not _runnable(n)]
            broken += [(rel, i, f"tenant.py {sub}") for sub in tenant_sub.findall(line)
                       if sub not in subcommands]
    return broken


def path_triggers_dropping(ci_text: str, homes: Iterable[str]) -> list[tuple[str, str]]:
    """`(event, home)` for every ci.yml `on.<event>` whose `paths` filter fails to match a home,
    or whose `paths-ignore` filter matches one."""
    doc = yaml.safe_load(ci_text)
    events = doc.get("on", doc.get(True, {})) or {}
    out: list[tuple[str, str]] = []
    for event, spec in (events.items() if isinstance(events, dict) else []):
        spec = spec or {}
        for h in homes:
            if spec.get("paths") and not any(fnmatch.fnmatch(h, p) for p in spec["paths"]):
                out.append((event, h))
            if any(fnmatch.fnmatch(h, p) for p in spec.get("paths-ignore", []) or []):
                out.append((event, h))
    return out


def test_1080_the_run_records_lint_sweeps_every_new_home(tmp_path):
    lint = _lint("lint_run_records")
    swept = {S.rel(p) for p in lint.sweep_files(S.DEFENDER)}
    named = {
        "the lessons engine": S.home_of("cmd_tags"),
        "the sql engine (runtime)": S.home_of("_load_payload", home=S.RUNTIME),
        "payload_view (runtime)": S.home_of("passthrough_max_bytes", home=S.RUNTIME),
        "pricing (flat tier)": S.home_of("usage_cost", home=S.PRICING),
        "the flat tier": S.home_of("reexec_into_venv", home=S.VENV),
    }
    unswept = {k: h for k, h in named.items() if h not in swept}
    assert not unswept, f"lint_run_records does not sweep these new homes: {unswept}"
    every = sorted({h for base in MOVED_HOMES for h in _homes(base)} - swept)
    assert not every, f"lint_run_records does not sweep these homes of moved modules: {every}"

    engine = S.home_of("match_lessons")
    root = tmp_path / "tree"
    lines = _plant(root, engine)
    found = _gate_findings("run_records", root)
    assert _reported("run_records", found, engine, lines), (
        f"a record-name literal planted in {engine} was not reported: {found}")


def test_gate_scope_that_walks_a_fixed_set_of_top_level_directories_meets_a_new_top_level_package(tmp_path):
    at_base = _golden()["plant_reported_at_base"]
    owed: dict[str, set[str]] = {}
    for base, gates in at_base.items():
        if base in MOVED_HOMES:
            for home in _homes(base):
                owed.setdefault(home, set()).update(gates)
    assert owed, "no moved module to plant in"

    reported = plant_and_scan(tmp_path / "tree", owed)
    for control, gates in CONTROLS.items():
        assert set(gates) <= set(reported[control]), (
            f"control: {control} reported by {reported[control]}, expected {gates}")
    narrowed = {t: sorted(g - set(reported[t])) for t, g in owed.items() if g - set(reported[t])}
    assert not narrowed, (
        "a gate that reported the plant at the old location does not report it at the new one "
        f"(home -> silent gates): {narrowed}")



def test_1080_every_path_a_lint_scope_names_exists():
    lists = lint_scope_lists()
    assert {"lint_shippable_surface.py", "lint_ci_hygiene.py", "lint_tenant_env_reads.py",
            "lint_tree_read_follows_link.py"} <= {k.split("::")[0] for k in lists}, sorted(lists)
    base_dead = _golden()["scope_dead_at_base"]
    new_dead = {k: sorted(set(v) - set(base_dead.get(k, []))) for k, v in dead_scope_entries().items()}
    new_dead = {k: v for k, v in new_dead.items() if v}
    assert not new_dead, f"lint scope lists name paths that no longer exist: {new_dead}"


def _moved_keys() -> dict[str, list[str]]:
    """Per baseline: the base keys that named a base module the design moves (golden)."""
    return {name: [k for k in keys if any(p in MOVED_HOMES for p in key_paths(k))]
            for name, keys in _golden()["baseline_keys_naming_scripts"].items()}


def _out_keys() -> dict[str, list[str]]:
    """Per baseline: the base keys that named an `OUT_KEYED` file, which the cut leaves in
    place (golden: the vulture baseline's `derive_system`)."""
    return {name: [k for k in keys if any(p in OUT_KEYED for p in key_paths(k))]
            for name, keys in _golden()["baseline_keys_naming_scripts"].items()}


def _misplaced_out_keys(current: Mapping[str, Mapping[str, str]]) -> list[tuple[str, str, str]]:
    """Each OUT key whose file stays: (baseline, key, path) for every place the current
    baseline carries its finding OTHER than the base path."""
    out: list[tuple[str, str, str]] = []
    for name, keys in _out_keys().items():
        for key in keys:
            old = key_paths(key)[0].replace("defender/scripts/gather_tools/record_query.py", "defender/runtime/record_query.py")
            assert (S.REPO_ROOT / old).is_file(), f"{old} must stay in place under the cut"
            out += [(name, key, p) for p in _rekeyed(current[name], key) if p != old]
    return out


_SYMBOL_IN_KEY = re.compile(r"'(\w+)'")


def _rekeyed(entries: Mapping[str, str], key: str) -> list[str]:
    """Where the current baseline carries `key`'s finding: the path of every current key that
    is a path followed by exactly `key`'s text after its path."""
    old = key_paths(key)[0]
    assert key.startswith(old), f"golden key does not start with its path: {key}"
    tail = key[len(old):]
    return [k[:-len(tail)] for k in entries
            if k.endswith(tail) and key_paths(k[:-len(tail)]) == [k[:-len(tail)]]]


def test_1080_no_lint_baseline_keys_a_path_that_no_longer_exists():
    stale = [(name, k, p) for name, entries in baselines().items() for k in entries
             for p in key_paths(k) if not resolves(p)]
    assert not stale, f"baseline keys naming paths that no longer exist: {stale}"
    current = baselines()
    misplaced = []
    for name, keys in _moved_keys().items():
        for key in keys:
            sym = _SYMBOL_IN_KEY.search(key)
            assert sym, f"golden key carries no quoted symbol: {key}"
            home = S.home_of(sym.group(1))
            misplaced += [(name, key, p) for p in _rekeyed(current[name], key) if p != home]
    assert not misplaced, f"a moved finding is keyed somewhere other than its symbol's home: {misplaced}"
    moved_out = _misplaced_out_keys(current)
    assert not moved_out, f"a finding of a file the cut leaves in place was re-keyed: {moved_out}"


@pytest.mark.gate
def test_vulture_baseline_holds_fingerprints_keyed_by_files_that_moved(monkeypatch):
    current = baselines()
    for name in ("lint_vulture_baseline.json", "lint_unnarrowed_parse_baseline.json"):
        dead = [k for k in current[name] for p in key_paths(k) if not resolves(p)]
        assert not dead, f"{name} keys paths that no longer exist: {dead}"
    owed = _out_keys()["lint_vulture_baseline.json"]
    assert owed, "golden: no base vulture key named a derive_system finding"
    moved_out = _misplaced_out_keys({n: current[n] for n in _out_keys()})
    assert not moved_out, f"a finding of a file the cut leaves in place was re-keyed: {moved_out}"
    monkeypatch.setenv("PATH", f"{Path(sys.executable).parent}:{S.child_env()['PATH']}")
    assert _lint("lint_vulture").main([]) == 0, "the vulture gate is red after the change"
    assert _lint("lint_unnarrowed_parse").main([]) == 0, "the unnarrowed-parse gate is red"


def test_1080_no_tracked_doc_or_comment_names_a_moved_scripts_path(tmp_path):
    stale = P.stale_scripts_pointers(S.REPO_ROOT)
    assert not stale, (
        f"{len(stale)} tracked pointer(s) name a defender/scripts/ path that no longer exists: "
        f"{stale[:40]}")
    target = sorted(MOVED_HOMES)[0]
    surfaces = ("defender/docs/notes.md", "docs/notes.md", "defender/bin/README.md",
                "knowledge/tenant-x/settings/systems/demo/config.env", "defender/CLAUDE.md",
                "defender/run_notes.py")
    repo = _git_repo(tmp_path / "repo", {s: f"# Read by {target}\n" for s in surfaces})
    seen = {rel for rel, _, _ in P.stale_scripts_pointers(repo)}
    assert seen == set(surfaces), f"the scan missed surfaces: {sorted(set(surfaces) - seen)}"


def test_vanished_directory_name_that_is_also_a_live_identifier(tmp_path):
    S.home_of("match_lessons")
    real = P.stale_scripts_pointers(S.REPO_ROOT) + P.vanished_folder_mentions(S.REPO_ROOT)
    assert not real, f"stale references to an old location: {real[:40]}"

    doc = [
        "Call `match_lessons(...)`; lessons_frontier is the module.",                  # 1 live
        "Lessons live in `defender/lessons/one.md`.",                                 # 2 content
        "The wrapper `defender/scripts/lessons/lessons_fm.py` stays (stem lessons_fm).",  # 3 alive
        "The old engine was `defender/scripts/lessons/lessons_frontier.py`.",        # 4 stale
        "from defender.scripts.lessons import lessons_frontier",                      # 5 stale
        "The lessons/ folder holds the wrapper.",                                     # 6 bare, alive
    ]
    repo = _git_repo(tmp_path / "repo", {
        "defender/scripts/lessons/lessons_fm.py": "# the wrapper\n",
        "defender/lessons/one.md": "a lesson\n",
        "defender/notes.md": "\n".join(doc) + "\n",
    })
    stale_lines = {line for rel, line, _ in P.stale_scripts_pointers(repo) if rel == "defender/notes.md"}
    mention_lines = {line for rel, line, _ in P.vanished_folder_mentions(repo)
                     if rel == "defender/notes.md"}
    assert stale_lines == {4, 5}, f"path references found on lines {sorted(stale_lines)}, expected [4, 5]"
    assert mention_lines == set(), f"folder mentions on lines {sorted(mention_lines)}, expected none"

    # With the folder gone too: a path into it is still a mention, a bare `lessons/` names the
    # live content folder and is not, and a gone folder with no live namesake still is.
    gone = _git_repo(tmp_path / "gone", {
        "defender/lessons/one.md": "a lesson\n",
        "defender/notes.md": "The lessons/ folder holds lessons.\n"
                             "Old: `defender/scripts/lessons/lessons_fm.py`.\n"
                             "The case_history/ layout.\n",
    })
    assert "lessons" in P.vanished_folders(gone)
    mentions = {(line, text) for rel, line, text in P.vanished_folder_mentions(gone)
                if rel == "defender/notes.md"}
    assert mentions == {(2, "defender/scripts/lessons/lessons_fm.py"), (3, "case_history/")}, \
        mentions


def test_path_scan_for_stale_text_meets_dead_pins_that_predate_the_change(tmp_path):
    assert not P.stale_scripts_pointers(S.REPO_ROOT), "a pointer names a moved scripts path"
    debt = {(r, t) for r, t in _golden()["dead_pointer_debt"]}
    assert debt, "golden: the base held no dead scripts/ pin"
    files: dict[str, list[str]] = {}
    for rel, text in sorted(debt):
        files.setdefault(rel, []).append(f"pin: {text}")
    first = sorted(files)[0]
    new_ptr = sorted(MOVED_HOMES)[0]
    files[first].append(f"new: {new_ptr}")
    repo = _git_repo(tmp_path / "repo", {r: "\n".join(v) + "\n" for r, v in files.items()})
    dead = {(r, t) for r, _, t in P.dead_scripts_pointers(repo)}
    in_scope = {(r, t) for r, t in debt if P.scanned(r)}
    assert in_scope <= dead, f"debt pins the scan no longer sees: {sorted(in_scope - dead)[:10]}"
    assert dead - debt == {(first, new_ptr)}, f"new misses beyond the debt: {sorted(dead - debt)}"
    stale = {(r, t) for r, _, t in P.stale_scripts_pointers(repo)}
    assert (first, new_ptr) in stale
    moved_debt = [(r, t) for r, t in debt
                  if f"defender/scripts/{P._entry_of(t.split('scripts/', 1)[1].split('/'))}"
                  in MOVED_HOMES]
    assert moved_debt, "golden: no debt pin names a module the design moves"
    assert set(moved_debt) <= stale, (
        f"debt pins naming a moved module hidden from the moved-path scan: {sorted(set(moved_debt) - stale)}")


def test_staying_commands_import_modules_that_have_moved(tmp_path):
    home = S.home_of("load_case_mapping", home=S.RUNTIME)
    stmts = list(S.import_statements("defender/cli/tenant.py",
                                     (S.CLI / "tenant.py").read_bytes()))
    named = {st.module for st in stmts} | {f"{st.module}.{n}" for st in stmts for n in st.names}
    assert S.dotted(home) in named, f"tenant.py does not import the case-mapping module {S.dotted(home)}"
    if not S.under(home, "defender/scripts"):  # (the authoring self-check resolves the base home)
        old = [st for st in stmts if st.module.startswith("defender.integrations.case_ticket")
               or (st.module == "defender.integrations" and "case_ticket" in st.names)]  # lint-ast-resolve: ok — a static census over a fixed module's own source; its import spellings are the observation
        assert not old, f"tenant.py still imports the case-mapping module from its old path: {old}"

    runs = staying_command_runs(tmp_path)
    assert runs == _golden()["staying_command_runs"], (
        f"a staying command no longer runs as at the base: {runs}")

    venv_bin = str(Path(sys.executable).parent)
    bare = S.child_env(pythonpath=False, PATH=f"{venv_bin}:/usr/bin:/bin")
    r = S.run([sys.executable, "-I", "-S", S.IMAGE_CLI, "tag"], cwd=tmp_path, env=bare)
    from defender.box import _image

    assert r.returncode == 0, f"box_image.py tag under the bare interpreter: {r.stderr!r}"
    assert r.stdout.decode().strip() == _image.image_tag(S.DEFENDER), (
        f"box_image.py tag printed {r.stdout!r}, not this tree's image tag")
    # #1108 P4 (O1, O-U5): the registry is tenant knowledge and the product tree ships none, so
    # the staying command is run over the committed fixture tenant's agent half (`--defender-dir`
    # names the tree whose `skills/tacit-knowledge/registry.yaml` it reads).
    fixture_agent = S.DEFENDER.parent / "knowledge" / "tenant-fixture" / "agent"
    assert (fixture_agent / "skills" / "tacit-knowledge" / "registry.yaml").is_file(), (
        "the fixture tenant carries no tacit-knowledge registry to check")
    r = S.run([sys.executable, "-m", "defender.cli.tacit_cli", "check",
               "--defender-dir", str(fixture_agent)], cwd=tmp_path,
              env=S.child_env(PATH=f"{venv_bin}:/usr/bin:/bin"))
    assert r.returncode == 0, f"tacit_cli check: {r.stdout!r} {r.stderr!r}"


def _tenant_registry_step(command: str) -> str:
    """`command` as CI runs it after #1108 P4: the `tacit_cli check` step over the fixture tenant."""
    if command.endswith("-m defender.cli.tacit_cli check"):
        return f"{command} --defender-dir knowledge/tenant-fixture/agent"
    return command


def test_ci_step_and_docs_invoke_a_command_by_a_path_or_module_that_must_keep_working(tmp_path):
    ci = CI.read_text(encoding="utf-8")
    runs = ci_staying_runs(ci)
    # #1108 P4 (O1, O-U5): the product tree ships no tacit-knowledge registry, so the staying
    # `tacit_cli check` step names the committed fixture tenant's agent half, exactly as
    # `test_staying_commands_import_modules_that_have_moved` runs it. The golden is the pre-move
    # recording; the moves are applied to it here, one each.
    expected = [
        "python3 " + S.current_path(command[len("python3 "):])
        if command.startswith("python3 ")
        else _tenant_registry_step(
            command.replace("defender.scripts.tacit_cli", "defender.cli.tacit_cli"))
        for command in _golden()["ci_staying_runs"]
    ]
    assert runs == expected, f"CI's staying-command steps changed: {runs}"
    for cmd in runs:
        names = _CMD_PATH.findall(cmd) + _CMD_MODULE.findall(cmd)
        assert names, f"CI step names no command: {cmd}"
        assert all(_runnable(n) for n in names), f"CI step no longer runnable: {cmd}"

    broken = docs_invoking_broken_commands()
    assert not broken, f"docs invoke staying commands that do not run: {broken[:40]}"

    assert S.shim_exec_module("defender-policy") == "defender.cli.policy_cli"
    for shim, digest in S.base_inventory()["shims"].items():
        # The operator shim changes only its module target; executable help is checked above.
        if shim in (*WRAPPER_SHIMS, "defender-policy"):
            continue
        assert hashlib.sha256((S.BIN / shim).read_bytes()).hexdigest() == digest, \
            f"bin/{shim} changed (M-H (a): the shims are unchanged)"

    homes = sorted({h for base in MOVED_HOMES for h in _homes(base)})
    dropped = path_triggers_dropping(ci, homes)
    assert not dropped, f"ci.yml's path triggers no longer select these moved homes: {dropped}"
