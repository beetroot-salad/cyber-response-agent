# PRE-CUT COPY 2026-10-04 (scope cut of #1080, human-decided; 94-reconciliation-cut.md F-2): preserved, NOT collected.
# This is defender/tests/scripts_1080_split/test_1080_lints_and_pointers.py as it stood before the cut, copied verbatim
# from the cut author's scratch backup; the only additions are these `#` comment lines. It keeps
# the cells the cut removed from KEPT tests: the OUT halves of narrowed tests, and the tables and
# helpers the cut narrowed or deleted. Each such node carries a `# PRE-CUT …` marker naming the
# issue(s) that own its cut cells; an owner adopts those cells when its module moves. Nodes without
# a marker are unchanged in the live suite, or were parked whole (their canonical copy is
# ../parked_lints_and_pointers.py, annotated with their owners). The file name does not match test_*.py, so pytest never
# collects it. It imports the LIVE helper modules; their pre-cut versions are
# parked_precut__spec1080.py and parked_precut__census1080.py beside this file (_pointers1080.py did
# not change). The goldens it reads are split between the suite's goldens/ and ../goldens/. Each
# narrowed kept demand's `parked_cells` block in spec-flow/specs/spec_graph_1080-scripts-split.yaml
# points at its pre-cut function here.
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
import importlib
import json
import re
import socket
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
from defender.tests.tenant_1107_settings import _census_1107 as C1107

# ======================================================================================
# Fixed tables
# ======================================================================================

LINT_DIR = S.REPO_ROOT / "scripts" / "lint"
SPEC_GRAPH_DIR = S.REPO_ROOT / "spec-flow" / "scripts" / "spec_graph"
PROFILE = S.REPO_ROOT / ".claude" / "spec-flow.json"
CI = S.REPO_ROOT / ".github" / "workflows" / "ci.yml"
HANDBOOK = S.DEFENDER / "skills" / "handbook"
HANDBOOK_PAGE = HANDBOOK / "content" / "run-artifacts.md"
CONNECT = S.DEFENDER / "skills" / "connect"
EXAMPLE_ADAPTER = CONNECT / "examples" / "example_adapter.py"
VALIDATE_SCAFFOLD = CONNECT / "validate_scaffold.py"

# PRE-CUT 2026-10-04 (scope cut): narrowed in the live suite; the cut part is owned by #1105, #1165, #1172 and the case_ticket follow-up.
#: Every base module of `defender/scripts/` the design moves, and the symbols whose homes now
#: hold its code (each with the home it must sit under, None = wherever it is outside
#: `scripts/`). The anchors are the placement group's (`MODULE_ANCHORS`); confinement and
#: record_query split, so they carry one anchor per piece. The two engines' wrappers stay at the
#: base path (M-H (a)); the anchor names the engine.
MOVED_HOMES: dict[str, tuple[tuple[str, str | None], ...]] = {
    "defender/scripts/_venv.py": (("reexec_into_venv", S.FLAT_TIER),),
    "defender/scripts/pricing.py": (("usage_cost", S.PROVIDERS),),
    "defender/scripts/workspace_map.py": (("_template_counts", None),),
    "defender/scripts/adapters/faults.py": (("AdapterFault", S.INTEGRATIONS),),
    "defender/scripts/adapters/confinement.py": (("guard_outbound", S.INTEGRATIONS),
                                                 ("world_view", None)),
    "defender/scripts/adapters/esql_text.py": (("split_first_command", None),),
    "defender/scripts/case_history/case_ticket.py": (("load_case_mapping", None),),
    "defender/scripts/case_history/ticket_writer.py": (("record_case_ticket", None),),
    "defender/scripts/gather_tools/payload_view.py": (("passthrough_max_bytes", None),),
    "defender/scripts/gather_tools/record_query.py": (("append_query_row", None),
                                                      ("derive_system", S.VERBS)),
    "defender/scripts/gather_tools/sql.py": (("_load_payload", S.RUNTIME),),
    "defender/scripts/lessons/_lessons_common.py": (("resolve_corpus", None),),
    "defender/scripts/lessons/lessons_fm.py": (("cmd_tags", None),),
    "defender/scripts/lessons/lessons_frontier.py": (("match_lessons", None),),
    "defender/scripts/visualize/_mirror_write.py": (("write_page", S.REPORTS),),
    "defender/scripts/visualize/_page_failed.py": (("VisualizeFailed", S.REPORTS),),
    "defender/scripts/visualize/visualize_data.py": (("phase_attribution", S.REPORTS),),
    "defender/scripts/visualize/visualize_episode.py": (("render_episode", S.REPORTS),),
    "defender/scripts/visualize/visualize_messages.py": (("load_messages", S.REPORTS),),
    "defender/scripts/visualize/visualize_primitives.py": (("esc_untrusted", S.REPORTS),),
    "defender/scripts/visualize/visualize_run.py": (("publish_page", S.REPORTS),),
    "defender/scripts/visualize/visualize_runtime.py": (("render_runtime_investigation",
                                                         S.REPORTS),),
}

#: The shims whose exec targets are the wrappers that stay (M-H (a)).
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


def _wrapper_paths() -> list[str]:
    return [S.rel(S.shim_exec_target(shim)) for shim in WRAPPER_SHIMS]


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


def _trace(tmp_path: Path, resources: Mapping[str, Mapping[str, list[str]]], tag: str) -> Any:
    """`spec-graph trace resource` (the real tool, `spec-flow/scripts/spec_graph/trace.py`) run
    over a copy of the profile whose resources are exactly `resources`."""
    profile = json.loads(PROFILE.read_text(encoding="utf-8"))
    profile["specGraph"]["resources"] = {k: dict(v) for k, v in resources.items()}
    cfg = tmp_path / f"spec-flow-{tag}.json"
    cfg.write_text(json.dumps(profile), encoding="utf-8")
    return S.python(SPEC_GRAPH_DIR / "trace.py", "resource", "--config", cfg,
                    cwd=S.REPO_ROOT, timeout=300)


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


def test_1080_the_env_read_lint_still_sweeps_the_moved_case_history_modules(tmp_path):
    """Every entry in `lint_tenant_env_reads`' swept list exists. The modules defining `record_case_ticket` and `load_case_mapping` are swept. An `os.environ` read planted in the moved write-back module is reported.

    Observed through the lint's own file set over the REAL tree (`_swept_files`), and by
    planting an environment read into a tmp copy of the moved write-back module at the path the
    real tree gives it and running the lint's `scan` over that copy (RG1). [100] and [101]
    (auto): the test twin `_census_1107.SWEPT` is held to the same three facts — each entry
    exists, the two lists agree, and its `swept_py` over the real tree holds both moved modules
    (its empty-result semantics unchanged). Positive control: a plant in the cmdb adapter, a
    tree that stays, is reported by the same scan.
    """
    lint = _lint("lint_tenant_env_reads")
    missing = [e for e in lint.SWEPT if not (S.REPO_ROOT / e).exists()]
    assert not missing, (
        f"lint_tenant_env_reads.SWEPT names {missing}, which no longer exist: the lint skips a "
        f"missing tree silently (K18), so the modules that lived there left the sweep")
    twin_missing = [e for e in C1107.SWEPT if not (S.REPO_ROOT / e).exists()]
    assert not twin_missing, f"_census_1107.SWEPT names {twin_missing}, which no longer exist"
    assert set(lint.SWEPT) == set(C1107.SWEPT), (
        f"the env-read lint and its test twin sweep different trees: lint only "
        f"{sorted(set(lint.SWEPT) - set(C1107.SWEPT))}, twin only "
        f"{sorted(set(C1107.SWEPT) - set(lint.SWEPT))}")

    writer = S.home_of("record_case_ticket")
    mapping = S.home_of("load_case_mapping")
    swept = {S.rel(p) for p in lint._swept_files(S.REPO_ROOT)}
    twin = {S.rel(p) for p in C1107.swept_py(S.REPO_ROOT)}
    for module in (writer, mapping):
        assert module in swept, f"{module} (moved) is outside lint_tenant_env_reads' sweep"
        assert module in twin, f"{module} (moved) is outside _census_1107.swept_py"

    root = tmp_path / "tree"
    lines = _plant(root, writer)
    control = "defender/scripts/adapters/cmdb_adapter.py"
    control_lines = _plant(root, control)
    found = lint.scan(root)
    assert _reported("env_reads", found, control, control_lines), (
        f"control: the env read planted in {control} was not reported: {found}")
    assert _reported("env_reads", found, writer, lines), (
        f"an os.environ read planted in the moved write-back module {writer} was not reported "
        f"by lint_tenant_env_reads: {found}")
    assert writer in {S.rel(p, root) for p in C1107.swept_py(root)}, (
        f"_census_1107.swept_py does not reach the planted copy of {writer}")


def test_env_read_lint_sweep_list_names_one_moved_tree_and_one_existing_tree(tmp_path):
    """After the move the env-read lint's swept trees still cover every moved module (the old case_history tree's modules are swept at their new home), and a listed path that no longer exists is reported, not silently dropped. The move does not narrow the sweep (M5: update the path-keyed lints).

    "Does not narrow" is read off the base: every file under `defender/scripts/` the lint swept
    at 80888efb (golden: the adapters folder, including the confinement, Elastic-text and fault
    modules, and the case-history folder) is swept now — at its own path if it stayed, at every
    home that holds its code if it moved. A listed path that no longer exists is reported here,
    by name (the lint itself skips a missing tree while another exists, K18; [100] keeps that).
    Driven: a plant in a module of a tree that stays (the cmdb adapter) and a plant in each
    moved case-history module's new home, in one tmp copy, are both reported by one scan.
    """
    lint = _lint("lint_tenant_env_reads")
    dead = [e for e in lint.SWEPT if not (S.REPO_ROOT / e).exists()]
    assert not dead, f"lint_tenant_env_reads.SWEPT lists {dead}, which no longer exist"

    swept = {S.rel(p) for p in lint._swept_files(S.REPO_ROOT)}
    narrowed: list[tuple[str, str]] = []
    for base in _golden()["env_swept_at_base"]:
        if not S.under(base, "defender/scripts"):
            continue
        now = _homes(base) if base in MOVED_HOMES else [base]
        narrowed += [(base, h) for h in now if h not in swept]
    assert not narrowed, (
        "the move narrowed lint_tenant_env_reads' sweep — (swept at the base, now at): "
        f"{narrowed}")

    root = tmp_path / "tree"
    existing = "defender/scripts/adapters/cmdb_adapter.py"
    targets = [existing, *_homes("defender/scripts/case_history/ticket_writer.py"),
               *_homes("defender/scripts/case_history/case_ticket.py")]
    planted = {t: _plant(root, t) for t in dict.fromkeys(targets)}
    found = lint.scan(root)
    missed = [t for t, lines in planted.items() if not _reported("env_reads", found, t, lines)]
    assert not missed, f"env reads planted in {missed} were not reported: {found}"


def test_1080_the_tree_read_lint_still_covers_the_moved_episode_renderer(tmp_path):
    """`lint_tree_read_follows_link`'s module list names the episode renderer at its new path, and every listed module exists.

    The renderer is found by the symbol it defines (`render_episode`, under
    `defender/reports/`). "Every listed module exists" is pinned as: no entry is dead that was
    alive at the base — the one entry dead at 80888efb (`runtime/branch.py`, a package now:
    RG2, golden) predates this change (s102). Driven: a link-following `is_file()` planted in a
    tmp copy of the renderer at its new path is reported by the lint's `_scan`.
    """
    lint = _lint("lint_tree_read_follows_link")
    page = S.home_of("render_episode", home=S.REPORTS)
    listed = set(lint.LINT_TREE_READER_MODULES)
    assert _drel(page) in listed, (
        f"LINT_TREE_READER_MODULES does not name the moved episode renderer {_drel(page)}: "
        f"the gate goes silent on it (RG2)")
    dead = sorted(m for m in listed if not (S.DEFENDER / m).exists())
    new_dead = sorted(set(dead) - set(_golden()["tree_read_dead_at_base"]))
    assert not new_dead, f"LINT_TREE_READER_MODULES names modules that no longer exist: {new_dead}"

    root = tmp_path / "tree"
    lines = _plant(root, page)
    found = _gate_findings("tree_read", root)
    assert _reported("tree_read", found, page, lines), (
        f"an is_file() planted in the moved episode renderer {page} was not reported: {found}")


def test_tree_read_lint_module_list_holds_a_dead_entry_and_a_stale_entry(tmp_path):
    """The tree-read lint's opt-in module list names the episode renderer at its new path, so the renderer remains covered; the entry dead before the move (runtime/branch.py) is not this change's, and a reader at a new home is covered only if added, so adding the moved reader is part of the move.

    Every module the list named at the base under `defender/scripts/` (golden) is named now at
    each home that holds its code; the list's dead entries are at most the ones dead at the base.
    Driven, both sides of "covered only if added": in one tmp copy, an `is_file()` planted in
    the moved renderer is reported, and the same plant in an unlisted module beside it in the
    same package is not.
    """
    lint = _lint("lint_tree_read_follows_link")
    listed = set(lint.LINT_TREE_READER_MODULES)
    stale: list[tuple[str, str]] = []
    for base in _golden()["tree_read_listed_at_base"]:
        full = f"defender/{base}"
        if S.under(full, "defender/scripts"):
            homes = _homes(full) if full in MOVED_HOMES else [full]
            stale += [(base, _drel(h)) for h in homes if _drel(h) not in listed]
    assert not stale, f"a moved tree reader is no longer listed — (listed at the base, now at): {stale}"
    dead = {m for m in listed if not (S.DEFENDER / m).exists()}
    assert dead <= set(_golden()["tree_read_dead_at_base"]), (
        f"entries dead now that were alive at the base: {sorted(dead - set(_golden()['tree_read_dead_at_base']))}")

    page = S.home_of("render_episode", home=S.REPORTS)
    unlisted = f"{page.rsplit('/', 1)[0]}/_spec1080_unlisted_reader.py"
    assert _drel(unlisted) not in listed
    root = tmp_path / "tree"
    lines = _plant(root, page)
    unlisted_lines = _plant(root, unlisted)
    found = _gate_findings("tree_read", root)
    assert _reported("tree_read", found, page, lines), (
        f"the moved renderer {page} is not covered: {found}")
    assert not _reported("tree_read", found, unlisted, unlisted_lines), (
        f"an unlisted module {unlisted} was reported — the list is no longer opt-in: {found}")


# PRE-CUT 2026-10-04 (scope cut): narrowed in the live suite (kept demand m5_run_records_lint_sweeps_new_homes); the cut cells are owned by #1105 (reports), #1172 (integrations) and the case_ticket follow-up (the tenants home).
def test_1080_the_run_records_lint_sweeps_every_new_home(tmp_path):
    """`lint_run_records`' swept trees cover every new home of a moved module: reports, integrations, the lessons engine and the tenants home. A record-name literal planted in a moved reports module is reported.

    Observed through the lint's own `sweep_files` over the REAL `defender/` tree: every home of
    every moved module (found by symbol) is in it — `defender/reports/`, `defender/integrations/`,
    the lessons engine, the tenants home and the flat tier among them. Driven: a record-name
    literal planted in a tmp copy of the moved episode renderer is reported by `scan`.
    """
    lint = _lint("lint_run_records")
    swept = {S.rel(p) for p in lint.sweep_files(S.DEFENDER)}
    named = {
        "reports": S.home_of("publish_page", home=S.REPORTS),
        "integrations": S.home_of("AdapterFault", home=S.INTEGRATIONS),
        "the lessons engine": S.home_of("cmd_tags"),
        "the tenants home": S.home_of("load_case_mapping"),
    }
    unswept = {k: h for k, h in named.items() if h not in swept}
    assert not unswept, f"lint_run_records does not sweep these new homes: {unswept}"
    every = sorted({h for base in MOVED_HOMES for h in _homes(base)} - swept)
    assert not every, f"lint_run_records does not sweep these homes of moved modules: {every}"

    page = S.home_of("render_episode", home=S.REPORTS)
    root = tmp_path / "tree"
    lines = _plant(root, page)
    found = _gate_findings("run_records", root)
    assert _reported("run_records", found, page, lines), (
        f"a record-name literal planted in {page} was not reported: {found}")


# PRE-CUT 2026-10-04 (scope cut): narrowed in the live suite (kept demand s135); the cut cells are owned by #1105, #1172 and the case_ticket follow-up (docstring: the reports, integrations and tenants homes).
def test_gate_scope_that_walks_a_fixed_set_of_top_level_directories_meets_a_new_top_level_package(tmp_path, monkeypatch):
    """A plant of a record-name literal, a tenant env read, an unguarded tree write and a tree read in a module under every new home (reports, integrations, the lessons engine, the tenants home, the flat tier) and in a thin wrapper in scripts/ is reported by each path-scoped gate that reported the same plant at the old location, so no gate's scope narrows silently. Gate sweeps and profile code roots that were fixed lists are extended to the new top-level packages (M5).

    The expected side is the base: one plant carrying all four idioms was appended to every
    base module of `defender/scripts/` in place, and which of the four gates reported it was
    captured at 80888efb (golden). Now the same plant goes into a tmp copy of every home of every
    moved module (found by symbol) and of each wrapper a shim execs, the four gates' own scans
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
    for wrapper in _wrapper_paths():
        owed.setdefault(wrapper, set()).update(at_base[wrapper])
    assert owed, "no moved module or wrapper to plant in"

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


_SYMBOL_IN_KEY = re.compile(r"'(\w+)'")


def _rekeyed(entries: Mapping[str, str], key: str) -> list[str]:
    """Where the current baseline carries `key`'s finding: the path of every current key that
    is a path followed by exactly `key`'s text after its path."""
    old = key_paths(key)[0]
    assert key.startswith(old), f"golden key does not start with its path: {key}"
    tail = key[len(old):]
    return [k[:-len(tail)] for k in entries
            if k.endswith(tail) and key_paths(k[:-len(tail)]) == [k[:-len(tail)]]]


# PRE-CUT 2026-10-04 (scope cut): narrowed in the live suite (kept demand m5_baselines_name_no_moved_path); the cut cells are owned by the case_ticket follow-up and #1172 (derive_system): the re-keying of their baseline keys.
def test_1080_no_lint_baseline_keys_a_path_that_no_longer_exists():
    """No `scripts/lint/*_baseline.json` entry keys a file path that no longer exists, so a moved file's baselined finding is re-keyed rather than reappearing as new.

    Every path-shaped token of every key of every baseline resolves against the repo root or
    `defender/`. For each base key that named a module the design moves (golden: the vulture
    baseline's four case-ticket findings and `derive_system`), the finding is at the home of the
    symbol it names (found by symbol) wherever the current baseline still carries it — never at
    the old path.
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


# PRE-CUT 2026-10-04 (scope cut): narrowed in the live suite (kept demand s105); the cut cells are owned by the case_ticket follow-up and #1172 (derive_system): the re-keying of their baseline keys.
@pytest.mark.gate
def test_vulture_baseline_holds_fingerprints_keyed_by_files_that_moved(monkeypatch):
    """No baseline entry (vulture, unnarrowed-parse) names a moved path: findings carried by moved files are re-keyed to their new paths, entries for files that no longer exist are removed, and a finding re-introduced at the old path is not excused by a stale entry. The gates are green after the change. (M5: update the path-keyed baselines.)

    Read from the two baselines and the base record of their keys (golden; at 80888efb only
    vulture's carries moved paths — its unnarrowed-parse `scripts/` keys are adapters, which
    stay). For each moved key: its file no longer exists, the key is gone, and the finding, if
    still carried, is keyed at the home of the symbol it names. Then both gates' `main` run over
    the real tree and exit 0 (a `gate` test: a repo-wide re-run).
    """
    current = baselines()
    for name in ("lint_vulture_baseline.json", "lint_unnarrowed_parse_baseline.json"):
        dead = [k for k in current[name] for p in key_paths(k) if not resolves(p)]
        assert not dead, f"{name} keys paths that no longer exist: {dead}"
    moved = _moved_keys()
    owed = [(n, k) for n in ("lint_vulture_baseline.json", "lint_unnarrowed_parse_baseline.json")
            for k in moved.get(n, [])]
    assert owed, "golden: no base vulture/unnarrowed-parse key named a moved module"
    for name, key in owed:
        old = key_paths(key)[0]
        assert not (S.REPO_ROOT / old).exists(), f"{old} has not moved (its key: {key})"
        assert key not in current[name], f"{name} still carries {key!r}"
        home = S.home_of(_SYMBOL_IN_KEY.search(key).group(1))
        wrong = [p for p in _rekeyed(current[name], key) if p != home]
        assert not wrong, f"{key!r} re-keyed at {wrong}, not at its symbol's home {home}"
    monkeypatch.setenv("PATH", f"{Path(sys.executable).parent}:{S.child_env()['PATH']}")
    assert _lint("lint_vulture").main([]) == 0, "the vulture gate is red after the change"
    assert _lint("lint_unnarrowed_parse").main([]) == 0, "the unnarrowed-parse gate is red"


def test_baseline_entry_keyed_to_a_path_that_no_longer_exists_while_another_file_is_created_there(tmp_path):
    """A baseline entry keyed to a path that no longer exists is removed with the move, so a later file created at that path with the same finding is reported by the vulture and unnarrowed-parse gates and the ratchet, not excused by the stale entry.

    Driven end to end: the vulture gate (`scripts/lint/lint_vulture.py`, with `_baseline.py`
    and the CURRENT `lint_vulture_baseline.json` copied beside it) runs over a tmp tree holding,
    at each old path of a moved vulture key (golden), a file re-creating that key's finding
    (an unused function of the same name). Every such finding must come back NEW and the gate
    must exit 1. At the base the stale keys still excuse them. The unnarrowed-parse baseline
    held no key at a moved path at the base (its `scripts/` keys are the staying adapters), so
    its half is the key-path check: none of its keys names a path that no longer exists.
    """
    owed = _moved_keys()["lint_vulture_baseline.json"]
    assert owed, "golden: no base vulture key named a moved module"
    plants: dict[str, list[str]] = {}
    for key in owed:
        assert "unused function" in key, f"a moved vulture key of another kind: {key}"
        plants.setdefault(key_paths(key)[0], []).append(_SYMBOL_IN_KEY.search(key).group(1))
    root = tmp_path / "tree"
    lint_copy = root / "scripts" / "lint"
    lint_copy.mkdir(parents=True)
    for name in ("lint_vulture.py", "_baseline.py", "lint_vulture_baseline.json"):
        (lint_copy / name).write_bytes((LINT_DIR / name).read_bytes())
    for rel, syms in plants.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text("".join(f"def {s}():\n    return None\n\n\n" for s in syms), encoding="utf-8")
    venv_bin = str(Path(sys.executable).parent)
    r = S.python(lint_copy / "lint_vulture.py", cwd=root,
                 env=S.child_env(pythonpath=False, PATH=f"{venv_bin}:/usr/bin:/bin"))
    out = r.stdout.decode("utf-8", "replace")
    assert r.returncode == 1, (
        f"the vulture gate excused findings re-created at moved paths (exit {r.returncode}): "
        f"{out[-2000:]}{r.stderr.decode('utf-8', 'replace')[-500:]}")
    new = out.split("NEW finding(s)", 1)[-1] if "NEW finding(s)" in out else ""
    excused = [k for k in owed if f"unused function '{_SYMBOL_IN_KEY.search(k).group(1)}'" not in new]
    assert not excused, f"still excused by a stale entry: {excused}\n{out[-2000:]}"
    dead = [k for k in baselines()["lint_unnarrowed_parse_baseline.json"]
            for p in key_paths(k) if not resolves(p)]
    assert not dead, f"unnarrowed-parse keys naming paths that no longer exist: {dead}"


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


@pytest.mark.gate
def test_profile_resource_row_names_a_moved_file_and_the_trace_is_run(tmp_path):
    """After the change the profile's resource rows and the committed spec graphs name files that exist (M5 updates them), so the trace over each resource finds its writers and readers; a row naming a missing file is surfaced rather than read as a resource with no writers. K11 is refuted: CI does not force this, so the update is hygiene the change owns.

    Driven with the real tool, `spec-graph trace resource` (`spec-flow/scripts/spec_graph/trace.py`):
    over the profile's current rows for every base row that named a moved module (golden), it
    exits 0 with no `UNRESOLVED` sink; over one row spelled at a moved module's OLD path it
    exits 2 and names the sink `UNRESOLVED`. A `gate` test: the trace walks the repo (~10s).
    The committed spec graphs carry `defender/scripts/` paths only in prose evidence fields
    (`where:`, `probe:`, comments) that no tool resolves (K11) and are archival here; see the
    group report.
    """
    moved = _moved_rows()
    assert moved, "golden: no base profile row named a moved module"
    gone = [r["sink"] for r in moved if (S.REPO_ROOT / r["sink"].partition("::")[0]).exists()]
    assert not gone, f"these rows' base files have not moved: {gone}"
    resources: dict[str, dict[str, list[str]]] = {}
    for row in moved:
        for sink in _current_rows_for(row):
            resources.setdefault(row["resource"], {"writers": [], "readers": []})[row["side"]].append(sink)
    assert resources, "no current profile row carries a moved module's symbol"
    r = _trace(tmp_path, resources, "rekeyed")
    out = (r.stdout + r.stderr).decode("utf-8", "replace")
    assert r.returncode == 0, f"trace over the re-keyed rows exited {r.returncode}: {out[-3000:]}"
    assert "UNRESOLVED" not in out, f"trace over the re-keyed rows: {out[-3000:]}"

    stale = moved[0]["sink"]
    r = _trace(tmp_path, {"spec1080_stale": {"writers": [stale], "readers": []}}, "stale")
    err = r.stderr.decode("utf-8", "replace")
    assert r.returncode == 2, f"a row at a moved module's old path exited {r.returncode}: {err}"
    assert "UNRESOLVED" in err, f"a row at a moved module's old path was not surfaced: {err}"
    assert stale in err, f"the trace did not name the stale sink {stale}: {err}"


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


def test_profile_resource_row_naming_a_moved_file_with_a_symbol_suffix(tmp_path):
    """A profile resource row or committed spec graph writing a writer as `path::symbol` has the path updated to the file that now holds the symbol; a symbol that still exists elsewhere does not let the stale path resolve silently.

    For every base row naming a moved module (golden), each current row for the same
    resource, side and symbol names a file outside `defender/scripts/` that defines the symbol
    now. Driven with the real `spec-graph trace resource`: a row at the OLD path whose symbol now
    lives elsewhere exits 2 and is named `UNRESOLVED` — the tool never resolves it by symbol.
    """
    wrong: list[tuple[str, list[str]]] = []
    for row in _moved_rows():
        sym = row["sink"].partition("::")[2]
        now = _current_rows_for(row)
        homes = [d for d in S.definitions(sym) if not S.under(d, "defender/scripts")]
        bad = [s for s in now if s.partition("::")[0] not in homes]
        if bad or (row["defined_at_base"] and not now):
            wrong.append((row["sink"], now))
    assert not wrong, f"rows not naming the file that now holds their symbol: {wrong}"

    elsewhere = [r["sink"] for r in _moved_rows()
                 if [d for d in S.definitions(r["sink"].partition("::")[2])
                     if not S.under(d, "defender/scripts")]]
    assert elsewhere, "no moved row's symbol is defined outside defender/scripts/ yet"
    stale = elsewhere[0]
    r = _trace(tmp_path, {"spec1080_stale": {"writers": [stale], "readers": []}}, "stale")
    err = r.stderr.decode("utf-8", "replace")
    assert r.returncode == 2, f"a stale path whose symbol lives elsewhere exited {r.returncode}: {err}"
    assert "UNRESOLVED" in err, f"a stale path whose symbol lives elsewhere resolved silently: {err}"
    assert stale in err, f"the trace did not name the stale sink {stale}: {err}"


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


def _should_vanish() -> list[str]:
    """The base subfolders of `defender/scripts/` none of whose base `.py` files stays (every one
    is a moved module, none a wrapper): the change empties them."""
    inv = S.base_inventory()
    keep = set(_wrapper_paths())
    out = []
    for d in inv["subdirs"]:
        pys = [f for f in inv["py_names"] if S.under(f, d)]
        if all(f in MOVED_HOMES and f not in keep for f in pys):
            out.append(d[len("defender/scripts/"):])
    return sorted(out)


def test_stale_reference_lint_meets_a_vanished_directory_name_in_unchanged_files(tmp_path):
    """After the change no comment, test name, lint list, config comment or baseline key still names a vanished scripts subfolder (gather_tools, case_history, and the others) where it denotes the old location, including references beyond the stale-reference lint's reporting limit; the gate reports clean and the author's own sweep covers names the lint will not surface.

    The vanished subfolders are computed: the base subfolders the change empties (every base
    `.py` in them is a moved module and none a wrapper — so `gather_tools/` and `lessons/`, which
    keep the two wrappers under M-H (a), do not vanish) must be gone, and
    `_pointers1080.vanished_folder_mentions` over the real checkout finds no pointer into one
    and no bare `<subfolder>/` path component naming one. The sweep has no hit cap: in a tmp git
    repo, more references to a vanished folder than `lint_stale_refs.HIT_CAP` are each reported.
    The gate itself (`lint_stale_refs`, ci.yml) runs in CI against `origin/main`.
    """
    owed = _should_vanish()
    assert owed, "the base inventory names no subfolder the change empties"
    gone = set(P.vanished_folders(S.REPO_ROOT))
    assert set(owed) <= gone, f"subfolders whose every module moved still exist: {sorted(set(owed) - gone)}"
    mentions = P.vanished_folder_mentions(S.REPO_ROOT)
    assert not mentions, f"{len(mentions)} mention(s) of a vanished subfolder: {mentions[:40]}"

    cap = _lint("lint_stale_refs").HIT_CAP
    folder = owed[0]
    body = "".join(f"# old home {i}: defender/scripts/{folder}/x.py\n" for i in range(cap + 5))
    repo = _git_repo(tmp_path / "repo", {"defender/notes.py": body,
                                         "defender/CLAUDE.md": f"  scripts/   # {folder}/, x.py\n"})
    found = P.vanished_folder_mentions(repo)
    assert len([f for f in found if f[0] == "defender/notes.py"]) == cap + 5, (
        f"the sweep capped its hits: {len(found)}")
    assert any(f[0] == "defender/CLAUDE.md" for f in found), f"the bare layout mention was missed: {found}"


# PRE-CUT 2026-10-04 (scope cut): narrowed in the live suite (kept demand s199); the cut cells are owned by #1105 (the visualize case).
def test_vanished_directory_name_that_is_also_a_live_identifier(tmp_path):
    """Removing a scripts subdirectory whose name is also a live identifier (`visualize`) or a surviving content folder (`lessons`) or a still-existing stem leaves no stale path reference to the old location in tests and docs, and does not false-flag the live identifier or the surviving `lessons` content folder: the check distinguishes path references from live names.

    The visualize folder's modules moved (its renderer found by symbol under `defender/reports/`)
    and the real checkout holds no stale pointer and no vanished-folder mention. Both sides of the
    distinction, in a tmp git repo that keeps `defender/scripts/lessons/lessons_fm.py` and the
    `defender/lessons/` content folder but not `defender/scripts/visualize/`: the path, module
    and bare-folder spellings of the old visualize location are reported; the word `visualize`
    used as a name, the content folder, the surviving wrapper, its stem and the new
    `defender/reports/` spelling are not.
    """
    S.home_of("render_episode", home=S.REPORTS)
    real = P.stale_scripts_pointers(S.REPO_ROOT) + P.vanished_folder_mentions(S.REPO_ROOT)
    assert not real, f"stale references to an old location: {real[:40]}"

    doc = [
        "Call `visualize(run)` to visualize a run; visualize_run is the module.",   # 1 live
        "Lessons live in `defender/lessons/one.md`.",                                 # 2 content
        "The wrapper `defender/scripts/lessons/lessons_fm.py` stays (stem lessons_fm).",  # 3 alive
        "The old page was `defender/scripts/visualize/visualize_run.py`.",           # 4 stale
        "from defender.scripts.visualize import visualize_episode",                   # 5 stale
        "The visualize/ folder held the renderers.",                                  # 6 bare
        "The page lives in `defender/reports/visualize_run.py` now.",                 # 7 new home
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
    assert mention_lines == {4, 5, 6}, f"folder mentions on lines {sorted(mention_lines)}, expected [4, 5, 6]"


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
# H5 (a) — the handbook points at the function in its new home
# ======================================================================================

_SPAN = re.compile(r"`([^`\n]+)`")
_PATHY = re.compile(r"[\w.*{}<>-]*(?:/[\w.*{}<>-]+)+/?|[\w*-]+\.py\b")
_QUALIFIED = re.compile(r"([\w./-]+\.py)::(\w+)")
_DOTTED = re.compile(r"\bdefender(?:\.\w+)+")
_RUN_BY_PATH = re.compile(r"\bpython3?\s+([\w./-]+\.py)\b")


@functools.cache
def _tree_basenames() -> frozenset[str]:
    """The file names of every tracked-tree `.py` under `defender/` and `scripts/` (junk
    directories skipped, tests included)."""
    return frozenset(f.rsplit("/", 1)[-1] for f in
                     S.py_files(S.REPO_ROOT, ("defender", "scripts"), include_tests=True))


_PAGE_BASES = (S.REPO_ROOT, S.DEFENDER, HANDBOOK)


def _first(path: str) -> Path | None:
    return next((b / path for b in _PAGE_BASES if (b / path).is_file()), None)


def _qualified_unresolved(span: str) -> list[str]:
    out = []
    for path, sym in _QUALIFIED.findall(span):
        hit = _first(path)
        if hit is None or sym not in S.module_level_names(hit.read_bytes(), path):
            out.append(f"{path}::{sym}")
    return out


def _dotted_resolves(name: str) -> bool:
    """`defender.a.b[.symbol]`: the longest leading module that is a file (or a package with an
    `__init__.py`, or a folder named exactly) defines what follows it, if anything."""
    parts = name.split(".")
    for k in range(len(parts), 0, -1):
        mod = S.REPO_ROOT.joinpath(*parts[:k])
        src = mod.with_suffix(".py") if mod.with_suffix(".py").is_file() else mod / "__init__.py"
        rest = parts[k:]
        if src.is_file():
            return not rest or (len(rest) == 1
                                and rest[0] in S.module_level_names(src.read_bytes(), str(src)))
        if mod.is_dir() and not rest:
            return True
    return False


def _path_unresolved(tok: str) -> bool:
    """Whether one path token of a page names a repo path that does not exist (`page_unresolved`
    says what counts)."""
    if "/" not in tok:
        return not fnmatch.filter(_tree_basenames(), tok)
    if not any((b / tok.split("/", 1)[0]).exists() for b in _PAGE_BASES):
        return False  # a run-dir record name, not a repo path
    if "*" in tok:
        return not any(any(b.glob(tok)) for b in _PAGE_BASES)
    return not any((b / tok.rstrip("/")).exists() for b in _PAGE_BASES)


def page_unresolved(text: str) -> list[str]:
    """Every repo path, `path::symbol` or `defender.…` name a page's backticked spans name that
    does not exist, and every `python <file>.py` it tells an operator to run that is not a file
    with a `__main__` block. A path counts when its first segment is a real top folder (of the
    repo, `defender/`, or the handbook skill) — run-dir record names (`gather_raw/…`,
    `wire_logs/…`) are not repo paths; a bare `X.py` must name some file under `defender/` or
    `scripts/`; a span with a placeholder (`{…}`, `<…>`) is skipped; a glob must match."""
    out: list[str] = []
    for span in _SPAN.findall(text):
        out += _qualified_unresolved(span)
        out += [n for n in _DOTTED.findall(span) if not _dotted_resolves(n)]
        for tok in _PATHY.findall(span):
            tok = tok.rstrip(".,:;")
            if not (any(c in tok for c in "{}<>") or tok.startswith("/")) and _path_unresolved(tok):
                out.append(tok)
    for path in _RUN_BY_PATH.findall(text):
        hit = _first(path)
        if hit is None or not S.has_main_block(hit.read_bytes()):
            out.append(f"python {path}")
    return sorted(set(out))


def test_1080_the_handbook_names_no_page_command_that_no_longer_exists():
    """`skills/handbook/content/run-artifacts.md` (lines 98, 103 and 175 at the base) no longer tells an operator to re-render a finished run's page by running the page script by path, because the `__main__` block is dropped (M-D (a)). It points at the function that publishes a run's page from its run directory, in that function's new home, and every path or symbol the page names exists.

    The function is `publish_page`, found by symbol under `defender/reports/`; the page names
    it and spells its module (as a repo path, a `defender/`-relative path or a dotted name).
    Every repo path, `path::symbol` and `defender.…` name in the page's code spans resolves, and
    every `python <file>.py` it tells an operator to run is a file with a `__main__` block
    (`page_unresolved`, whose rules exclude run-dir record names).
    """
    home = S.home_of("publish_page", home=S.REPORTS)
    text = HANDBOOK_PAGE.read_text(encoding="utf-8")
    assert re.search(r"\bpublish_page\b", text), "the page does not name publish_page"
    spellings = (home, _drel(home), S.dotted(home))
    assert any(sp in text for sp in spellings), (
        f"the page names publish_page but not its home (any of {spellings})")
    unresolved = page_unresolved(text)
    assert not unresolved, f"the page names things that do not exist: {unresolved}"


# ======================================================================================
# W4 — validate_scaffold's adapters literal
# ======================================================================================


def _div_operands(node: ast.expr) -> list[ast.expr]:
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):
        return [*_div_operands(node.left), node.right]
    return [node]


def test_1080_validate_scaffolds_adapters_folder_literal_equals_adapters_under_for_a_given_defender_dir(tmp_path):
    """The adapters folder that `skills/connect/validate_scaffold.py` spells literally (line 81 at the base) is the folder `adapters_under(defender_dir)` returns for the same `defender_dir`, so the literal cannot drift from the helper that `workspace_map` goes through when the folder moves at #1172.

    The folder feeds only the adapter's file name in the report, so it is not observable through
    the command's output; the expression itself is evaluated instead. The assignment to
    `adapter` in `check_registry` is evaluated in the loaded module's namespace for two
    defender dirs (this checkout's and an arbitrary one), and its parent must equal
    `adapters_under` for that dir; so must every other `/`-chain in the file that spells the
    `adapters` folder, cut at that segment. GREEN AT THE BASE BY DESIGN (a #1172 drift guard).
    """
    from defender._paths import adapters_under

    module = importlib.import_module("defender.skills.connect.validate_scaffold")
    tree = ast.parse(VALIDATE_SCAFFOLD.read_bytes(), filename=str(VALIDATE_SCAFFOLD))
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "check_registry")
    assigns = [n for n in ast.walk(fn) if isinstance(n, ast.Assign)
               and any(isinstance(t, ast.Name) and t.id == "adapter" for t in n.targets)]
    assert len(assigns) == 1, "check_registry builds no single `adapter` path"
    expr = compile(ast.Expression(assigns[0].value), str(VALIDATE_SCAFFOLD), "eval")
    dirs = (S.DEFENDER, tmp_path / "elsewhere" / "defender")
    for d in dirs:
        value = eval(expr, dict(vars(module)), {"defender": d, "system": "probe-sys"})  # noqa: S307
        assert Path(value).parent == adapters_under(d), (
            f"validate_scaffold's adapter folder {Path(value).parent} != adapters_under({d})")

    inner = {id(n.left) for n in ast.walk(tree) if isinstance(n, ast.BinOp)}
    chains = [n for n in ast.walk(tree) if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Div)
              and id(n) not in inner]
    for chain in chains:
        ops = _div_operands(chain)
        at = [i for i, o in enumerate(ops) if isinstance(o, ast.Constant) and o.value == "adapters"]
        if not at or not isinstance(ops[0], ast.Name):
            continue
        cut: ast.expr = ops[0]
        for o in ops[1:at[0] + 1]:
            cut = ast.BinOp(left=cut, op=ast.Div(), right=o)
        code = compile(ast.fix_missing_locations(ast.Expression(cut)), str(VALIDATE_SCAFFOLD), "eval")
        for d in dirs:
            value = eval(code, {}, {ops[0].id: d})  # noqa: S307
            assert Path(value) == adapters_under(d), (
                f"validate_scaffold.py:{chain.lineno} spells the adapters folder as {value}, "
                f"not adapters_under({d})")


# ======================================================================================
# s032 — the connect skill and its example adapter
# ======================================================================================

_TAUGHT_FROM = re.compile(r"^\s*from\s+(defender(?:\.\w+)+)\s+import\s+(.+)$")
_TAUGHT_IMPORT = re.compile(r"^\s*import\s+(defender(?:\.\w+)+)")


def _binds(src: Path) -> set[str]:
    """What a module binds at module level: definitions and import bindings (a re-export)."""
    tree = ast.parse(src.read_bytes(), filename=str(src))
    names = set(S.module_level_names(src.read_bytes(), str(src)))
    for n in tree.body:
        if isinstance(n, (ast.Import, ast.ImportFrom)):
            names.update((a.asname or a.name).split(".")[0] for a in n.names)  # lint-ast-resolve: ok — a static census over a fixed module's own source; its import spellings are the observation
    return names


def _module_file(dotted: str) -> Path | None:
    p = S.REPO_ROOT.joinpath(*dotted.split("."))
    if p.with_suffix(".py").is_file():
        return p.with_suffix(".py")
    if p.is_dir():
        return p
    return None


def taught_imports_unresolved(text: str) -> list[str]:
    """Every `from defender.… import …` / `import defender.…` line a doc teaches whose module
    or imported name does not exist in this tree."""
    out: list[str] = []
    for line in text.splitlines():
        if m := _TAUGHT_FROM.match(line):
            mod = _module_file(m.group(1))
            names = [n.strip().split(" as ")[0].strip("() \\") for n in m.group(2).split(",")]
            if mod is None:
                out.append(line.strip())
                continue
            for n in filter(None, names):
                if mod.is_dir():
                    init = mod / "__init__.py"
                    if _module_file(f"{m.group(1)}.{n}") is None and not (
                            init.is_file() and n in _binds(init)):
                        out.append(line.strip())
                elif n not in _binds(mod):
                    out.append(line.strip())
        elif m := _TAUGHT_IMPORT.match(line):
            if _module_file(m.group(1)) is None:
                out.append(line.strip())
    return sorted(set(out))


def test_template_adapter_and_the_connect_skill_after_the_fault_types_moved(tmp_path, monkeypatch):
    """After the fault types move, the connect skill's text and its example adapter import the fault types (and the transport helper, wherever it is) from their new homes, so an adapter written from them loads through the registry and raises a fault the platform catches. The skill's pointers are part of M5's pointer update. A template that teaches the old dotted path is a failure.

    The fault types' home is found by symbol (`AdapterFault`, under `defender/integrations/`).
    The example adapter's import statements name that module and never the old
    `defender.scripts.adapters.faults`; every `defender.…` import the skill's markdown teaches
    resolves in this tree, one of them names the new home, and no skill line points at the old
    faults file. Driven: the example, loaded by path as the connect skill's checks load it,
    addresses a closed local port through its configured record entry and raises a fault that
    is an instance of the `AdapterFault` the platform's query tool catches (`TransportFault`, the
    unreachable-system fault). Loading through the registry proper (an adapters folder under a
    defender tree) is not reproduced; see the group report.
    """
    faults = S.moved_module("AdapterFault", home=S.INTEGRATIONS)
    new = faults.__name__
    old = "defender.scripts.adapters.faults"
    rel = S.rel(EXAMPLE_ADAPTER)
    stmts = list(S.import_statements(rel, EXAMPLE_ADAPTER.read_bytes()))
    named = {st.module for st in stmts} | {f"{st.module}.{n}" for st in stmts for n in st.names}
    assert new in named, f"the example adapter does not import the fault types from {new}"
    if new != old:
        assert old not in named, f"the example adapter still imports {old}"
    teaching = {p.name: p.read_text(encoding="utf-8") for p in sorted(CONNECT.glob("*.md"))}
    unresolved = {n: taught_imports_unresolved(t) for n, t in teaching.items()}
    unresolved = {n: u for n, u in unresolved.items() if u}
    assert not unresolved, f"the connect skill teaches imports that do not resolve: {unresolved}"
    leaf = new.rsplit(".", 1)
    assert any(re.search(rf"from\s+{re.escape(new)}\s+import|import\s+{re.escape(new)}\b|"
                         rf"from\s+{re.escape(leaf[0])}\s+import\s+.*\b{leaf[1]}\b", t)
               for t in teaching.values()), f"no connect skill page teaches the import from {new}"
    stale = [(n, i, txt) for n, t in teaching.items() for i, line in enumerate(t.splitlines(), 1)
             for txt, entry in P._named_entries(line)
             if entry == "adapters/faults.py" and P._gone(S.REPO_ROOT, entry)]
    assert not stale, f"the connect skill points at the old faults file: {stale}"

    from defender.runtime import query_tool
    from defender.tests.tenant_1107_settings import _spec1107 as T

    for var in ("http_proxy", "HTTP_PROXY", "all_proxy", "ALL_PROXY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("no_proxy", "*")
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    root = tmp_path / "t"
    folder = T.plant(root, marker="s032")
    T.write_config(folder, "example", T.render_env({
        "URL_BASE": base, "TIMEOUT_SEC": "3", "EXAMPLE_URL_BASE": base,
        "EXAMPLE_TIMEOUT_SEC": "3", "EXAMPLE_TRANSPORT": T.DOCKER_EXEC,
        "EXAMPLE_DOCKER_CONTEXT": T.context_name("s032", "example")}))
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    ctx = T.verb_context(T.resolve(root), run_dir, {})
    example = load_module(EXAMPLE_ADAPTER, name="example_adapter_spec1080", register=False)
    try:
        example.VERBS["health-check"](ctx)
    except Exception as exc:  # noqa: BLE001 — the raised fault is the observation
        fault: BaseException | None = exc
    else:
        fault = None
    assert isinstance(fault, query_tool.AdapterFault), (
        f"the example's fault on an unreachable system is not the AdapterFault the query tool "
        f"catches: {fault!r}")
    assert isinstance(fault, faults.AdapterFault), f"not the moved AdapterFault: {fault!r}"
    assert type(fault).__name__ == "TransportFault", f"expected TransportFault, got {fault!r}"


# ======================================================================================
# s095 / s112 — the commands that stay
# ======================================================================================


# PRE-CUT 2026-10-04 (scope cut): narrowed in the live suite (kept demand s095); the cut cells are owned by the case_ticket follow-up (the tenant command -> case_ticket cell).
def test_staying_commands_import_modules_that_have_moved(tmp_path):
    """The staying commands (tenant, policy_cli, box_image, tacit_cli) run by path and by module name from CI, the shims and the docs from any working directory as they do today; the tenant command imports the case-mapping module from its new home (an import from scripts/ outward is allowed, only the reverse is census-checked), and `box_image.py` still runs under the runner's bare interpreter before dependency sync.

    `tenant.py`'s import statements name the case-mapping module's home (found by symbol) and
    nothing under the old case-history folder. Each command, run from a working directory
    outside the checkout — by path with no `PYTHONPATH`, through `bin/defender-policy`, and by
    module with the checkout importable — exits as at the base and prints the base's usage block
    (golden). The runner's bare interpreter is stood in for by this interpreter with `-I -S` (no
    site-packages, no environment), under which `box_image.py tag` prints exactly the tag the
    image module computes for this tree; `tacit_cli check`, as CI runs it, exits 0.
    """
    home = S.home_of("load_case_mapping")
    stmts = list(S.import_statements("defender/scripts/tenant.py",
                                     (S.SCRIPTS / "tenant.py").read_bytes()))
    named = {st.module for st in stmts} | {f"{st.module}.{n}" for st in stmts for n in st.names}
    assert S.dotted(home) in named, f"tenant.py does not import the case-mapping module {S.dotted(home)}"
    if not S.under(home, "defender/scripts"):  # (the authoring self-check resolves the base home)
        old = [st for st in stmts if st.module.startswith("defender.scripts.case_history")
               or (st.module == "defender.scripts" and "case_history" in st.names)]  # lint-ast-resolve: ok — a static census over a fixed module's own source; its import spellings are the observation
        assert not old, f"tenant.py still imports the old case-history folder: {old}"

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
    is one the command's usage offers. The three `bin/` shims are byte-identical to the base
    (M-H (a)). Path triggers: every `on.<event>.paths` filter in ci.yml (there are none at
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
        assert hashlib.sha256((S.BIN / shim).read_bytes()).hexdigest() == digest, \
            f"bin/{shim} changed (M-H (a): the shims are unchanged)"

    homes = sorted({h for base in MOVED_HOMES for h in _homes(base)})
    dropped = path_triggers_dropping(ci, homes)
    assert not dropped, f"ci.yml's path triggers no longer select these moved homes: {dropped}"
