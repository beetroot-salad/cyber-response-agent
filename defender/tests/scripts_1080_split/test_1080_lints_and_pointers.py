"""#1080 (group `lints`) — the path-keyed lints, their baselines, the spec-flow profile and the
tracked pointers follow the move (M5), and the commands that stay keep working.

THE NET FOR THE SILENT SCOPES (RG1, RG2). Four lint scopes narrow SILENTLY when a module they
sweep moves out from under them: `lint_tenant_env_reads.SWEPT` (and its test twin
`_census_1107.SWEPT`), `lint_tree_read_follows_link.LINT_TREE_READER_MODULES` and
`lint_run_records.SWEEP_DIRS`. Each test here DRIVES the lint: it plants the offending idiom into
a tmp copy of the moved module at the path the REAL tree gives it (found by the symbol the
module defines, `_spec1080.home_of`), runs the lint's own scan function over that copy, and reads
the finding — or runs the lint's own file-set function over the real tree. None builds a root
from the lint's own list (RG1: such a root stays green after a move). The scan functions, never
`main`, are called for the plants, so a baseline cannot hide a planted finding.

THE BASE IS THE REFERENCE. What a gate reported for a plant IN PLACE at the base, which files
the env-read lint swept, which scope entries and baseline keys were already dead, which profile
rows named `defender/scripts/` paths, the dead `scripts/` pins that predate the change, and the
staying commands' usage lines are captured once at 80888efb into `goldens/lints.json`. A test
compares the tree to that record; it never runs old code.

RED AT BASE. A test about a moved module finds the module's new home by symbol, so it fails at
the base until the move happens. Tests that are green at the base by design (the coherence
checks whose failure only a move can produce) say so in their docstrings.

The pointer scans live in `_pointers1080.py` (shared with the placement group's s003 test).
"""
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
from defender.tests._by_path import load_lint_gate, load_module
from defender.tests.scripts_1080_split import _pointers1080 as P
from defender.tests.scripts_1080_split import _spec1080 as S

# ======================================================================================
# Fixed tables
# ======================================================================================

LINT_DIR = S.REPO_ROOT / "scripts" / "lint"
SPEC_GRAPH_DIR = S.REPO_ROOT / "spec-flow" / "scripts" / "spec_graph"
PROFILE = S.REPO_ROOT / ".claude" / "spec-flow.json"
CI = S.REPO_ROOT / ".github" / "workflows" / "ci.yml"

#: Every base module of `defender/scripts/` the design moves, and the symbols whose homes now
#: hold its code (each with the home it must sit under, None = wherever it is outside
#: `scripts/`). The anchors are the placement group's (`MODULE_ANCHORS`), filtered alike to the
#: seven modules the 2026-10-04 scope cut moves (E2), plus `case_history/case_ticket.py`, which
#: the case_ticket follow-up #1190 moves whole under `defender/runtime/` (F-C): its baseline
#: keys, profile rows and lint plants follow it. The OUT modules (`adapters/`,
#: `case_history/ticket_writer.py`, `record_query.py`, `visualize/`, `workspace_map.py`) stay
#: where they are. The two engines' base paths keep no wrapper (post-review: the shims run the
#: engines with `-m`, reversing M-H (a)); the anchor names the engine.
MOVED_HOMES: dict[str, tuple[tuple[str, str | None], ...]] = {
    "defender/scripts/_venv.py": (("reexec_into_venv", S.FLAT_TIER),),
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
STAYING_COMMANDS = ("tenant", "policy_cli", "box_image", "tacit_cli")

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
    "defender/scripts/adapters/cmdb_adapter.py": ("run_records", "env_reads", "tree_write"),
    "defender/learning/branch/episode.py": ("tree_read",),
}


# ======================================================================================
# Helpers
# ======================================================================================


def _golden() -> Mapping[str, Any]:
    return S.golden("lints")


@functools.cache
def _lint(stem: str) -> Any:
    return load_lint_gate(stem, name=f"{stem}_spec1080")


@functools.cache
def _spec_graph_config() -> Any:
    return load_module(SPEC_GRAPH_DIR / "_config.py", name="spec1080_spec_graph_config",
                       sys_path=(SPEC_GRAPH_DIR,))


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
    `scripts/lint/*.py` that holds a path-shaped entry (a `/`), as `"<file>::<name>"` -> its
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


def profile_rows() -> list[tuple[str, str, str]]:
    """`(resource, side, sink)` for every writer and reader row of the profile's resources."""
    res = json.loads(PROFILE.read_text(encoding="utf-8"))["specGraph"].get("resources", {})
    return [(name, side, sink) for name, row in res.items()
            for side in ("writers", "readers") for sink in row.get(side, []) or []]


def _defines(relpath: str, sym: str) -> bool:
    p = S.REPO_ROOT / relpath
    return p.is_file() and sym in S.module_level_names(p.read_bytes(), relpath)


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
        "tenant.py by path": ([py, S.SCRIPTS / "tenant.py", "--help"], bare),
        "policy_cli via bin/defender-policy": ([S.BIN / "defender-policy", "--help"], bare),
        "policy_cli by module": ([py, "-m", "defender.scripts.policy_cli", "--help"], rooted),
        "tacit_cli by module": ([py, "-m", "defender.scripts.tacit_cli", "--help"], rooted),
        "box_image.py by path, bare interpreter": (
            [py, "-I", "-S", S.SCRIPTS / "box_image.py", "--help"], bare),
    }
    out: dict[str, Any] = {}
    for name, (argv, env) in cases.items():
        r = S.run(argv, cwd=tmp_cwd, env=env)
        out[name] = {"rc": r.returncode,
                     "usage": usage_block(r.stdout.decode("utf-8", "replace"))}
    return out


#: A CI `run:` line invoking a command under `defender/scripts/` by path or by module.
_CI_STAYING = re.compile(r"^\s*(?:-\s*)?run:\s*(.*(?:defender/scripts/|-m defender\.scripts\.).*)$")


def ci_staying_runs(text: str) -> list[str]:
    return [m.group(1).strip() for m in map(_CI_STAYING.match, text.splitlines()) if m]


#: A command naming a `defender/scripts/` file by path or a `defender.scripts` module.
_CMD_PATH = re.compile(r"(?<![\w.-])(?:defender/)?scripts/(\w+)\.py\b")
_CMD_MODULE = re.compile(r"-m\s+defender\.scripts\.(\w+)\b")


def _runnable(name: str) -> bool:
    p = S.SCRIPTS / f"{name}.py"
    return p.is_file() and S.has_main_block(p.read_bytes())


def docs_invoking_broken_commands() -> list[tuple[str, int, str]]:
    """Every tracked-text invocation of a staying command (by path or `-m`) that names no file
    with a `__main__` block, and every `python … scripts/tenant.py <sub>` whose subcommand the
    command's base usage does not offer."""
    usage = _golden()["staying_command_runs"]["tenant.py by path"]["usage"]
    subcommands = set(re.search(r"\{([\w,]+)\}", usage).group(1).split(","))
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


# ======================================================================================
# m5 — the path-keyed lints sweep the new homes
# ======================================================================================


def test_1080_the_run_records_lint_sweeps_every_new_home(tmp_path):
    """`lint_run_records`' swept trees cover every new home of a moved module: under the 2026-10-04 scope cut, the lessons engine, the `runtime/` homes and the flat tier. A record-name literal planted in a moved lessons-engine module is reported.

    Observed through the lint's own `sweep_files` over the REAL `defender/` tree: every home of
    every moved module (found by symbol) is in it — the lessons engine, the sql engine's and
    `payload_view`'s `runtime/` homes and the flat tier (`_venv`, `_pricing`) among them.
    Driven: a record-name literal planted in a tmp copy of the moved `lessons_frontier` is
    reported by `scan`.
    """
    lint = _lint("lint_run_records")
    swept = {S.rel(p) for p in lint.sweep_files(S.DEFENDER)}
    named = {
        "the lessons engine": S.home_of("cmd_tags"),
        "the sql engine (runtime)": S.home_of("_load_payload", home=S.RUNTIME),
        "payload_view (runtime)": S.home_of("passthrough_max_bytes", home=S.RUNTIME),
        "pricing (flat tier)": S.home_of("usage_cost", home=S.PRICING),
        "the flat tier": S.home_of("reexec_into_venv", home=S.FLAT_TIER),
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


def test_gate_scope_that_walks_a_fixed_set_of_top_level_directories_meets_a_new_top_level_package(tmp_path, monkeypatch):
    """A plant of a record-name literal, a tenant env read, an unguarded tree write and a tree read in a module under every new home (under the 2026-10-04 scope cut: the lessons engine, the `runtime/` homes, the flat tier) is reported by each path-scoped gate that reported the same plant at the old location, so no gate's scope narrows silently. Gate sweeps and profile code roots that were fixed lists are extended to the new top-level packages (M5).

    The expected side is the base: one plant carrying all four idioms was appended to every
    base module of `defender/scripts/` in place, and which of the four gates reported it was
    captured at 80888efb (golden). Now the same plant goes into a tmp copy of every home of every
    moved module (found by symbol; no wrapper is left in scripts/), the four gates' own scans
    run once over that copy, and every gate that reported the plant at the old location must
    report it at each new one. Controls: plants in a staying adapter and a staying listed tree
    reader are reported. The profile half: every planted home is in the spec-flow census
    (`_config.source_files` over `codeRoots`).
    """
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

    monkeypatch.chdir(S.REPO_ROOT)
    cfg = _spec_graph_config()
    census = {S.rel(p) for p in cfg.source_files(cfg.load(str(PROFILE)))}
    uncovered = sorted(t for t in owed if t not in census)
    assert not uncovered, f"the profile's codeRoots do not reach these homes: {uncovered}"


def test_1080_every_path_a_lint_scope_names_exists():
    """Every repo-relative path in a `scripts/lint/*.py` scope, exclusion or sweep list exists in the tree, so no list names a moved `scripts/` path. That covers `lint_shippable_surface`, `lint_ci_hygiene`, `lint_tenant_env_reads` and `lint_tree_read_follows_link`.

    The lists are read off every lint's source (each module-level collection of path-shaped
    string constants, plus `lint_run_records.SWEEP_DIRS`), resolved against the repo root and
    `defender/`. Entries already dead at 80888efb (golden: retired vendor skills, a settings
    file, `runtime/branch.py`) predate this change and are accounted for separately; a
    directory that exists only in some checkouts (a venv, a cache, the linked-worktree folder)
    is the machine's. GREEN AT THE BASE BY DESIGN: every base `scripts/` path a list names
    exists until something moves.
    """
    lists = lint_scope_lists()
    assert {"lint_shippable_surface.py", "lint_ci_hygiene.py", "lint_tenant_env_reads.py",
            "lint_tree_read_follows_link.py"} <= {k.split("::")[0] for k in lists}, sorted(lists)
    base_dead = _golden()["scope_dead_at_base"]
    new_dead = {k: sorted(set(v) - set(base_dead.get(k, []))) for k, v in dead_scope_entries().items()}
    new_dead = {k: v for k, v in new_dead.items() if v}
    assert not new_dead, f"lint scope lists name paths that no longer exist: {new_dead}"


# ======================================================================================
# m5 — the baselines are re-keyed
# ======================================================================================


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
            old = key_paths(key)[0]
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
    """No `scripts/lint/*_baseline.json` entry keys a file path that no longer exists, so a moved file's baselined finding is re-keyed rather than reappearing as new.

    Every path-shaped token of every key of every baseline resolves against the repo root or
    `defender/`. For each base key that named a module the design moves, the finding is at the
    home of the symbol it names (found by symbol) wherever the current baseline still carries it
    — never at the old path. Under the 2026-10-04 scope cut no base key names an IN module but
    `case_ticket`, which the case_ticket follow-up #1190 moves under `defender/runtime/`: the
    vulture baseline's four case-ticket findings are keyed at the home of the function each
    names. The key that named `defender/scripts/` code the cut leaves in place (golden: the
    vulture baseline's `derive_system`) stays at its base path wherever the current baseline
    still carries it.
    """
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
    """No baseline entry (vulture, unnarrowed-parse) names a moved path: findings carried by moved files are re-keyed to their new paths, entries for files that no longer exist are removed, and a finding re-introduced at the old path is not excused by a stale entry. The gates are green after the change. (M5: update the path-keyed baselines.) Under the 2026-10-04 scope cut the golden key for `derive_system` stays at its base path: its file does not move. (The four `case_ticket` keys move with their file, #1190: `test_1080_no_lint_baseline_keys_a_path_that_no_longer_exists` holds them to its home.)

    Read from the two baselines and the base record of their keys (golden; at 80888efb the only
    `scripts/` keys are vulture's case-ticket and `derive_system` findings, `tenant.py`'s, and
    unnarrowed-parse's adapters — none of them an IN module of the cut). No key of either
    baseline names a path that no longer exists; the `derive_system` key's file is still at its
    base path and, wherever the current baseline still carries the finding, it is keyed there.
    Then both gates' `main` run over the real tree and exit 0 (a `gate` test: a repo-wide
    re-run).
    """
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


# ======================================================================================
# m5 — the spec-flow profile
# ======================================================================================


def _moved_rows() -> list[dict[str, Any]]:
    """The base profile rows naming a module the design moves (golden)."""
    return [r for r in _golden()["profile_rows_naming_scripts"]
            if r["sink"].partition("::")[0] in MOVED_HOMES]


def _current_rows_for(row: Mapping[str, Any]) -> list[str]:
    sym = row["sink"].partition("::")[2]
    return [sink for res, side, sink in profile_rows()
            if res == row["resource"] and side == row["side"] and sink.partition("::")[2] == sym]


def test_1080_the_spec_flow_profile_covers_the_new_homes_and_names_no_moved_path(monkeypatch):
    """`.claude/spec-flow.json`'s `codeRoots` cover every new home. Every `resources` writer and reader row naming a moved file names its new path, and the file exists.

    Coverage is the spec-flow tool's own census: `_config.source_files` over the profile holds
    every home of every moved module (found by symbol). Every row's file exists; each base row
    that named a moved module for a symbol that module defined (golden) is carried now by a row
    for the same resource, side and symbol whose file exists, is outside `defender/scripts/`, and
    defines that symbol.
    """
    monkeypatch.chdir(S.REPO_ROOT)
    cfg = _spec_graph_config()
    census = {S.rel(p) for p in cfg.source_files(cfg.load(str(PROFILE)))}
    homes = sorted({h for base in MOVED_HOMES for h in _homes(base)})
    uncovered = [h for h in homes if h not in census]
    assert not uncovered, f"codeRoots do not cover these new homes: {uncovered}"

    missing = [(res, side, sink) for res, side, sink in profile_rows()
               if not (S.REPO_ROOT / sink.partition("::")[0]).is_file()]
    assert not missing, f"profile rows naming files that do not exist: {missing}"
    wrong: list[tuple[str, list[str]]] = []
    for row in _moved_rows():
        if not row["defined_at_base"]:
            continue
        sym = row["sink"].partition("::")[2]
        now = _current_rows_for(row)
        good = [s for s in now if not S.under(s.partition("::")[0], "defender/scripts")
                and _defines(s.partition("::")[0], sym)]
        if not good or len(good) != len(now):
            wrong.append((f"{row['resource']}.{row['side']} {row['sink']}", now))
    assert not wrong, f"rows naming a moved file that do not name its new home: {wrong}"


def test_profile_code_roots_leave_a_new_top_level_package_uncovered(monkeypatch):
    """The profile's code roots include every new top-level package the moves create, so a trace over actors and drivers sees the moved modules' callers. (M5: update .claude/spec-flow.json codeRoots/resources.)

    A new top-level package is the first folder under `defender/` of a moved module's home
    (found by symbol) that `defender/` did not hold at 80888efb (golden). Every non-test `.py`
    under each such package is in the spec-flow census (`_config.source_files` over the
    profile), and so is every moved module's home, the flat-tier ones included.
    """
    monkeypatch.chdir(S.REPO_ROOT)
    cfg = _spec_graph_config()
    census = {S.rel(p) for p in cfg.source_files(cfg.load(str(PROFILE)))}
    homes = sorted({h for base in MOVED_HOMES for h in _homes(base)})
    base_tops = set(_golden()["defender_top_level_dirs_at_base"])
    new_tops = sorted({"/".join(h.split("/")[:2]) for h in homes
                       if len(h.split("/")) > 2 and h.split("/")[1] not in base_tops})
    uncovered = [f for top in new_tops for f in S.py_files(S.REPO_ROOT, (top,)) if f not in census]
    assert not uncovered, f"new top-level packages {new_tops} leave these uncovered: {uncovered}"
    missing = [h for h in homes if h not in census]
    assert not missing, f"codeRoots do not cover these homes: {missing}"


# ======================================================================================
# m5 — tracked pointers
# ======================================================================================


def test_1080_no_tracked_doc_or_comment_names_a_moved_scripts_path(tmp_path):
    """No tracked non-archival text file names a `defender/scripts/…` path that no longer exists. That covers markdown under `defender/` and `docs/`, `bin/README.md`, `knowledge/*/settings/**/config.env` comments and `defender/CLAUDE.md`.

    Observed by `_pointers1080.stale_scripts_pointers` over the real checkout (tracked files
    only; archival trees and this suite excluded — see that module). Positive control: in a tmp
    git repo, a pointer to a base `defender/scripts/` file the repo lacks, written into each of
    the named surfaces, is reported from every one. GREEN AT THE BASE BY DESIGN: every base
    pointer names a file that exists until something moves.
    """
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
    """Moving a scripts module whose folder shares its name with a surviving content folder (`lessons`) or whose stem is a live identifier leaves no stale path reference to the old location in tests and docs, and does not false-flag the live identifier, the surviving `lessons` content folder or the surviving wrapper: the check distinguishes path references from live names. (The `visualize` case is parked with #1105 by the 2026-10-04 scope cut: `scripts/visualize/` does not move.)

    The lessons engine moved (found by symbol outside `defender/scripts/`) and the real checkout
    holds no stale pointer and no vanished-folder mention. (Post-review the wrapper went too, so
    the real `scripts/lessons/` folder is gone; a bare `lessons/` there names the live content
    folder and is not counted, while path pointers into the gone folder still are.) Both sides of the distinction, in a
    tmp git repo that keeps `defender/scripts/lessons/lessons_fm.py` (the wrapper) and the
    `defender/lessons/` content folder but not `defender/scripts/lessons/lessons_frontier.py`:
    the path and module spellings of the moved engine's old location are reported; the word
    `lessons_frontier` used as a name, the content folder, the surviving wrapper and its stem
    are not, and the `lessons/` folder (which keeps the wrapper) is no vanished folder.
    """
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
    """The scan for tracked text naming a path that no longer exists reports a new miss from this change even when pre-existing dead pins (box-mount tests, retired helper names, archived specs, decision records) are present: the old debt is accounted for separately and does not hide a new moved-path pointer.

    The old debt is the base's own dead `scripts/` pins (golden: what
    `_pointers1080.dead_scripts_pointers` found at 80888efb, by file and spelling — retired
    adapters and helpers, planted-file names in tests; archived specs and decision records are
    not scanned at all). On the real checkout the change leaves no pointer naming a base
    `defender/scripts/` entry that is gone. Driven, in a tmp git repo holding every debt pin
    in its own file: one new pointer to a moved module is the ONLY finding the debt-filtered
    dead scan reports, and a debt pin that itself names a moved module (`scripts/_venv.…`) is
    still reported by the moved-path scan, the debt notwithstanding. GREEN AT THE BASE BY
    DESIGN: the base points at nothing gone.
    """
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


# ======================================================================================
# s095 / s112 — the commands that stay
# ======================================================================================


def test_staying_commands_import_modules_that_have_moved(tmp_path):
    """The staying commands (tenant, policy_cli, box_image, tacit_cli) run by path and by module name from CI, the shims and the docs from any working directory as they do today; the tenant command imports the case-mapping module from its new home under `defender/runtime/` (an import from scripts/ outward is allowed, only the reverse is census-checked; the case_ticket follow-up #1190 restored this cell), and `box_image.py` still runs under the runner's bare interpreter before dependency sync.

    `tenant.py`'s import statements name the case-mapping module's home (found by symbol, under
    `defender/runtime/`) and nothing under the old case-history folder. Each command, run from a working directory
    outside the checkout — by path with no `PYTHONPATH`, through `bin/defender-policy`, and by
    module with the checkout importable — exits as at the base and prints the base's usage block
    (golden). The runner's bare interpreter is stood in for by this interpreter with `-I -S` (no
    site-packages, no environment), under which `box_image.py tag` prints exactly the tag the
    image module computes for this tree; `tacit_cli check`, as CI runs it, exits 0.
    """
    home = S.home_of("load_case_mapping", home=S.RUNTIME)
    stmts = list(S.import_statements("defender/scripts/tenant.py",
                                     (S.SCRIPTS / "tenant.py").read_bytes()))
    named = {st.module for st in stmts} | {f"{st.module}.{n}" for st in stmts for n in st.names}
    assert S.dotted(home) in named, f"tenant.py does not import the case-mapping module {S.dotted(home)}"
    if not S.under(home, "defender/scripts"):  # (the authoring self-check resolves the base home)
        old = [st for st in stmts if st.module.startswith("defender.scripts.case_history.case_ticket")
               or (st.module == "defender.scripts.case_history" and "case_ticket" in st.names)]  # lint-ast-resolve: ok — a static census over a fixed module's own source; its import spellings are the observation
        assert not old, f"tenant.py still imports the case-mapping module from its old path: {old}"

    runs = staying_command_runs(tmp_path)
    assert runs == _golden()["staying_command_runs"], (
        f"a staying command no longer runs as at the base: {runs}")

    venv_bin = str(Path(sys.executable).parent)
    bare = S.child_env(pythonpath=False, PATH=f"{venv_bin}:/usr/bin:/bin")
    r = S.run([sys.executable, "-I", "-S", S.SCRIPTS / "box_image.py", "tag"], cwd=tmp_path, env=bare)
    from defender.runtime.box import _image

    assert r.returncode == 0, f"box_image.py tag under the bare interpreter: {r.stderr!r}"
    assert r.stdout.decode().strip() == _image.image_tag(S.DEFENDER), (
        f"box_image.py tag printed {r.stdout!r}, not this tree's image tag")
    r = S.run([sys.executable, "-m", "defender.scripts.tacit_cli", "check"], cwd=tmp_path,
              env=S.child_env(PATH=f"{venv_bin}:/usr/bin:/bin"))
    assert r.returncode == 0, f"tacit_cli check: {r.stdout!r} {r.stderr!r}"


def test_ci_step_and_docs_invoke_a_command_by_a_path_or_module_that_must_keep_working(tmp_path):
    """The CI steps and docs that invoke staying commands by path or module keep working unchanged after the moves: `box_image.py build`, `-m defender.scripts.tacit_cli check`, `-m defender.scripts.policy_cli` (via its shim), and the tenant setup instructions; CI's path triggers (if any) still select the jobs for the moved files.

    ci.yml's `run:` steps that invoke a `defender/scripts/` command are the base's, unchanged
    (golden), and each names a file that exists with a `__main__` block; so does every staying
    command a tracked doc invokes by path or `-m`, and every `tenant.py <subcommand>` a doc gives
    is one the command's usage offers. Every `bin/` shim but the two that now run their engine
    with `-m` is byte-identical to the base (M-H (a), narrowed post-review). Path triggers: every `on.<event>.paths` filter in ci.yml (there are none at
    80888efb) must match each moved module's home (found by symbol), and no `paths-ignore`
    filter may.
    """
    ci = CI.read_text(encoding="utf-8")
    runs = ci_staying_runs(ci)
    assert runs == _golden()["ci_staying_runs"], f"CI's staying-command steps changed: {runs}"
    for cmd in runs:
        names = _CMD_PATH.findall(cmd) + _CMD_MODULE.findall(cmd)
        assert names, f"CI step names no command: {cmd}"
        assert all(_runnable(n) for n in names), f"CI step no longer runnable: {cmd}"

    broken = docs_invoking_broken_commands()
    assert not broken, f"docs invoke staying commands that do not run: {broken[:40]}"

    for shim, digest in S.base_inventory()["shims"].items():
        if shim in WRAPPER_SHIMS:
            continue
        assert hashlib.sha256((S.BIN / shim).read_bytes()).hexdigest() == digest, \
            f"bin/{shim} changed (M-H (a): the shims are unchanged)"

    homes = sorted({h for base in MOVED_HOMES for h in _homes(base)})
    dropped = path_triggers_dropping(ci, homes)
    assert not dropped, f"ci.yml's path triggers no longer select these moved homes: {dropped}"
