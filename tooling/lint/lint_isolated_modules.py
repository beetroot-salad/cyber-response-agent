#!/usr/bin/env python3
"""Isolated-module fence (#1092, #983, #631, #1107): four rules over modules held to a narrow contract by what they import
or call.

* The box image scripts (`box/_image.py`, `box/image_cli.py`) run before the package can be
  imported, so they import only the standard library and use no package-relative import.
* The tacit-knowledge registry adapter (`integrations/tacit_knowledge_adapter.py`) is a read-only
  lane over a human-authored file: it makes no filesystem mutation (`write_text`, `write_bytes`,
  `mkdir`, `unlink`, `rmdir`, `rename`, `touch`, `yaml` dumps, `shutil`, `os.remove`/`os.replace`)
  and opens no file for writing or appending.

* The budget enforcer (`hooks/budget_enforcer.py`) reads no environment variable, config file or
  JSON: its caps are set by the caller, so nothing in the environment can move them (`os.environ`,
  `environ.get`, `env_int(`, `open(`, `json.load(`).

* The ticket writer (`investigation/ticket_writer.py`) finds nothing for itself: no call to
  `process_defender_dir` or `cwd`. It, every `investigation/lead_zero/*.py` and `systems/correlation.py`
  (the correlation lead's dispatch identity) build and read no environment: no `run_env` call and
  no `os.environ` / `os.getenv` (run.py and the driver hand the environment in).

A missing file is a finding (re-site the rule), never a pass. A file that does not parse or decode
is exit 2. There is no baseline and no suppression: fix the code.

Run from anywhere:  python tooling/lint/lint_isolated_modules.py [--root DIR]
Exit 0 = clean, 1 = a finding, 2 = could not scan.
"""
from __future__ import annotations

import argparse
import ast
import sys
from pathlib import Path

import _astlib

#: The checkout's own `defender/`, so a run from any directory or worktree sweeps itself.
DEFENDER = Path(__file__).resolve().parents[2] / "defender"

_IMAGE_SCRIPTS = ("box/_image.py", "box/image_cli.py")
_REGISTRY = "integrations/tacit_knowledge_adapter.py"
_MUTATING_ATTRS = frozenset({"write_text", "write_bytes", "mkdir", "unlink", "rmdir", "rename",
                             "touch", "safe_dump", "dump", "remove", "replace"})
_MUTATING_MODULES = frozenset({"shutil"})
_TICKET_WRITER = "investigation/ticket_writer.py"
_LEAD_ZERO = "investigation/lead_zero"
_CORRELATION = "systems/correlation.py"
_BUDGET = "hooks/budget_enforcer.py"
_BUDGET_CALLS = frozenset({"env_int", "open"})


def _tree(root: Path, rel: str, findings: list[str]) -> ast.Module | None:
    path = root / rel
    if not path.is_file():
        findings.append(f"{rel}: missing; the isolated-module rule has nothing to hold")
        return None
    return _astlib.read_and_parse(path, rel)[1]


def _image_script(rel: str, tree: ast.Module) -> list[str]:
    out: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            names = [alias.name.split(".")[0] for alias in node.names]
        elif isinstance(node, ast.ImportFrom):
            if node.level:
                out.append(f"{rel}:{node.lineno}: package-relative import; this script runs "
                           "before the package can be imported")
                continue
            names = [(node.module or "").split(".")[0]]
        else:
            continue
        out.extend(f"{rel}:{node.lineno}: imports `{n}`, which is not the standard library; "
                   "this script runs before the package can be imported"
                   for n in names if n and n not in sys.stdlib_module_names)
    return out


def _registry(rel: str, tree: ast.Module) -> list[str]:
    out: list[str] = []
    env = _astlib.module_env(tree)
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in _MUTATING_ATTRS:
                root_name = _astlib.root_name(func.value)
                if func.attr in {"safe_dump", "dump", "remove", "replace"} and root_name not in {
                        "yaml", "os"}:
                    continue
                out.append(f"{rel}:{node.lineno}: calls `.{func.attr}(`; the registry lane "
                           "is a read end to end")
            mode = _astlib.open_mode(node, env)
            if mode and any(flag in mode for flag in "wax+"):
                out.append(f"{rel}:{node.lineno}: opens a file in mode {mode!r}; the registry "
                           "lane is a read end to end")
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name) \
                and node.value.id in _MUTATING_MODULES:
            out.append(f"{rel}:{node.lineno}: uses `{node.value.id}.{node.attr}`; the registry "
                       "lane is a read end to end")
    return out


def _budget(rel: str, tree: ast.Module) -> list[str]:
    out: list[str] = []
    for node in ast.walk(tree):
        if (isinstance(node, ast.Attribute) and node.attr == "environ") or (
                isinstance(node, ast.Name) and node.id == "environ"):
            out.append(f"{rel}:{node.lineno}: reads `environ`; the budget caps are set by the "
                       "caller and nothing in the environment may move them")
        elif isinstance(node, ast.Call):
            func = node.func
            name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)
            if name in _BUDGET_CALLS or (name == "load" and _astlib.root_name(func) == "json"):
                out.append(f"{rel}:{node.lineno}: calls `{name}(`; the budget enforcer reads no "
                           "file, JSON or environment")
    return out


def _called_name(node: ast.Call) -> str | None:
    func = node.func
    return func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", None)


def _hands_in_environment(rel: str, tree: ast.Module, banned_calls: frozenset[str]) -> list[str]:
    out: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and _called_name(node) in banned_calls:
            out.append(f"{rel}:{node.lineno}: calls `{_called_name(node)}(`; this module is "
                       "handed its location and environment, it does not find them")
        elif (isinstance(node, ast.Attribute) and node.attr in {"environ", "getenv"}
                and isinstance(node.value, ast.Name) and node.value.id == "os"):
            out.append(f"{rel}:{node.lineno}: reads `os.{node.attr}`; the environment is handed "
                       "in by run.py and the driver")
    return out


def scan(root: Path) -> list[str]:
    root = Path(root).resolve()
    if not root.is_dir():
        raise _astlib.ScanBlind(f"{root} is not a directory")
    findings: list[str] = []
    for rel in _IMAGE_SCRIPTS:
        if (tree := _tree(root, rel, findings)) is not None:
            findings.extend(_image_script(rel, tree))
    if (tree := _tree(root, _REGISTRY, findings)) is not None:
        findings.extend(_registry(_REGISTRY, tree))
    if (tree := _tree(root, _BUDGET, findings)) is not None:
        findings.extend(_budget(_BUDGET, tree))
    if (tree := _tree(root, _TICKET_WRITER, findings)) is not None:
        findings.extend(_hands_in_environment(
            _TICKET_WRITER, tree, frozenset({"process_defender_dir", "cwd", "run_env"})))
    lead_zero = root / _LEAD_ZERO
    if not lead_zero.is_dir():
        findings.append(f"{_LEAD_ZERO}: missing; the lead-zero environment rule has nothing to hold")
    else:
        for path in sorted(lead_zero.glob("*.py")):
            rel = path.relative_to(root).as_posix()
            findings.extend(_hands_in_environment(
                rel, _astlib.read_and_parse(path, rel)[1], frozenset({"run_env"})))
    if (tree := _tree(root, _CORRELATION, findings)) is not None:
        findings.extend(_hands_in_environment(_CORRELATION, tree, frozenset({"run_env"})))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=DEFENDER,
                        help="a defender/-shaped tree to sweep (default: this checkout's)")
    args = parser.parse_args(argv)
    try:
        found = scan(args.root)
    except _astlib.ScanBlind as exc:
        print(f"[lint_isolated_modules] {exc}", file=sys.stderr)
        return 2
    for line in found:
        print(line)
    print(f"[lint_isolated_modules] {len(found)} finding(s).")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
