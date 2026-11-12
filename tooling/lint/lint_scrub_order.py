#!/usr/bin/env python3
"""Scrub-order fence (#540, re-sited by #1342): four rules over the entrypoint and the bash tool.

* `run.py` has two compositions, the operator's `main` (which is also a learning sibling's
  inside its job container, #1170 A6) and the job entry's `job_main`. Each
  calls the box lifecycle (which scrubs the run folder) and then the shared `_post_steps`, in
  that order. The readers of the run folder — listing it, the table cross-check and the page
  render — live only in `_post_steps`: any reference to one anywhere else in `run.py` is a
  finding, whatever its form (a call, an alias, a `partial`, a lambda, a class body, a
  `getattr` string, `os.listdir` or `glob` for `iterdir`). The one allowance is the page-render
  seam: a parameter named `visualize` defaulting to the reader, and `visualize=visualize`
  handed to `_post_steps` or to a composition (the job container's process wiring,
  `serve_job`, hands the seam to the composition it runs, which is held to this rule
  itself). The operator's own readers, the case ticket and the curation
  enqueue, come after its lifecycle.
* The compositions, `_post_steps` and `_run_investigation_lifecycle` are each bound exactly once
  in `run.py` (a second `def`, assignment, import, class, match capture or `except ... as` of the
  name would shadow the one this rule reads), and none carries a decorator (which would wrap the
  function this rule reads).
* None of those four has an `except` that would swallow the taint signal: none names
  `RunTainted`, `Exception` or `BaseException`, and none is bare; none has a `with` that names one
  of those or `suppress` (which swallows without an `except`).
* The bash tool never calls `run_parsed` on the in-process executor `bash_exec`: a box failure
  has no in-process fallback.

False positives, accepted (the rule is a name census, not a flow analysis): any `glob`, `rglob`,
`iglob`, `walk`, `listdir` or `scandir` name, and the exact string `"walk"`, `"glob"` or
`"visualize"`, anywhere in `run.py` outside `_post_steps` is a finding, whatever it is used for;
a local `main = 1` (or any other binding of a composition's name) in a helper counts as a second
binding of that name.

Not covered, by design (name-based evasions): a reader named by a computed string (`"cross_" +
"check_tables"`, a variable), reached from another module, through a function's `__defaults__`,
or a read of the folder by a means the census does not name (`open`, `read_text`, `shutil`, a
subprocess); the post-steps called from a helper before the lifecycle; a swallow by a helper
context manager of one's own; a rebinding of a composition at run time (`globals()`, `setattr`,
`exec`).

The behaviour test (`tests/jobs/test_job_entry.py`,
`test_m3_beneath_the_names_...`) backs this lint but does not replace it. It observes, in the
test process, the named readers (by spy) and, through `sys.addaudithook`, listings and read-only
`open` calls of the run folder made before the lifecycle double returns. It does not see: `r+`
opens, `dir_fd`-relative opens, reads made later by another thread, `stat`/`exists`/`readlink`,
child processes (in the m3 test), or a ticket POST made through a shell.

Order is source position inside the one function; attribute calls read as their attribute
name. A file or function that is missing, or a named call that is gone, is a finding (the rule
must be re-sited, never silently pass). A file that does not parse or decode is exit 2.

There is no baseline and no suppression: fix the code.

Run from anywhere:  python tooling/lint/lint_scrub_order.py [--root DIR]
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

_RUN = "run.py"
_BASH = "investigation/tools/_bash.py"
#: The readers of the scrubbed folder that live only in the shared post-steps.
_READERS = ("iterdir", "cross_check_tables", "visualize")
#: Other ways to list a folder, which count as the listing reader wherever they appear.
_LISTERS = ("listdir", "scandir", "walk", "glob", "rglob", "iglob")
_CENSUS = (*_READERS, *_LISTERS)
#: The operator composition's own readers, after its lifecycle.
_OPERATOR_READERS = ("record_case_ticket", "enqueue_curation")
_COMPOSITIONS = ("main", "job_main")
_LIFECYCLE = "lifecycle"
_POST_STEPS = "_post_steps"
#: The page-render seam, which the compositions take as a parameter and hand to the post-steps.
_SEAM = "visualize"
_SWALLOWERS = ("RunTainted", "Exception", "BaseException")


def _function(root: Path, rel: str, name: str, findings: list[str]) -> ast.AST | None:
    path = root / rel
    if not path.is_file():
        findings.append(f"{rel}: missing; the scrub-order rules have nothing to hold")
        return None
    _text, tree = _astlib.read_and_parse(path, rel)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == name:
            return node
    findings.append(f"{rel}: defines no `{name}`; re-site the scrub-order rule")
    return None


def _bindings(tree: ast.AST, name: str) -> list[int]:
    """The lines at which `name` is bound in the module: a def, a class, a stored name, an import, a match capture, an `except ... as`."""
    lines = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node.name == name:
            lines.append(node.lineno)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store) and node.id == name:
            lines.append(node.lineno)
        elif isinstance(node, ast.alias) and (node.asname or node.name.split(".")[0]) == name:
            lines.append(getattr(node, "lineno", 0))
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name == name:
            lines.append(node.lineno)  # `case name`, `case [*name]`
        elif isinstance(node, ast.MatchMapping) and node.rest == name:
            lines.append(node.lineno)  # `case {**name}`
        elif isinstance(node, ast.ExceptHandler) and node.name == name:
            lines.append(node.lineno)  # `except ... as name`
    return sorted(lines)


def _call_order(fn: ast.AST) -> list[str]:
    hits = []
    for node in ast.walk(fn):
        if isinstance(node, ast.Call):
            f = node.func
            name = f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)
            if name:
                hits.append(((node.lineno, node.col_offset), name))
    return [name for _pos, name in sorted(hits)]


def _caught(fn: ast.AST) -> list[tuple[int, str]]:
    out = []
    for node in ast.walk(fn):
        if isinstance(node, ast.ExceptHandler):
            if node.type is None:
                out.append((node.lineno, "(bare except)"))
                continue
            for sub in ast.walk(node.type):
                if isinstance(sub, ast.Name):
                    out.append((node.lineno, sub.id))
                elif isinstance(sub, ast.Attribute):
                    out.append((node.lineno, sub.attr))
    return out


def _swallowing_withs(fn: ast.AST) -> list[tuple[int, str]]:
    """A `with` whose context names a swallower or `suppress`: it ends the taint signal as an `except` would."""
    out = []
    for node in ast.walk(fn):
        if isinstance(node, (ast.With, ast.AsyncWith)):
            names = [sub.id if isinstance(sub, ast.Name) else sub.attr
                     for item in node.items for sub in ast.walk(item.context_expr)
                     if isinstance(sub, (ast.Name, ast.Attribute))]
            hit = next((name for name in names if name in (*_SWALLOWERS, "suppress")), None)
            if hit is not None:
                out.append((node.lineno, hit))
    return out


def _composition_findings(name: str, order: list[str]) -> list[str]:
    """One composition's order: the lifecycle, then the post-steps (and, for `main`, its own
    readers) after it. A reader named here instead is found by `_readers_elsewhere`."""
    if _LIFECYCLE not in order:
        return [f"{_RUN}: `{name}` no longer drives the lifecycle through its `{_LIFECYCLE}` seam; "
                "re-site the scrub-order rule"]
    reap = order.index(_LIFECYCLE)
    found = []
    after = (_POST_STEPS, *(_OPERATOR_READERS if name == "main" else ()))
    for call in after:
        if call not in order:
            found.append(f"{_RUN}: `{name}` no longer calls `{call}`; re-site the scrub-order rule")
        elif order.index(call) < reap:
            found.append(f"{_RUN}: `{name}` calls `{call}` before the lifecycle has scrubbed the "
                         "run folder")
    return found


def _readers_elsewhere(root: Path) -> list[str]:
    """A reference to a reader, in any form, anywhere in `run.py` but the module-level `_post_steps`: a
    name or attribute, a `"reader"` string, an import of one. A reference in a helper, a composition,
    a lambda, a class body or the module itself reads the folder before the scrub or hands the
    reader on, whatever order the compositions show."""
    path = root / _RUN
    if not path.is_file():
        return []
    _text, tree = _astlib.read_and_parse(path, _RUN)
    found: list[str] = []
    allowed: set[int] = set()  # `visualize=visualize` handed to the post-steps or a composition, and the seam's default

    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "id", None) in (_POST_STEPS, *_COMPOSITIONS):
            allowed.update(id(kw.value) for kw in node.keywords
                           if kw.arg == _SEAM and isinstance(kw.value, ast.Name) and kw.value.id == _SEAM)
        elif isinstance(node, ast.arguments):
            named = [*node.posonlyargs, *node.args]
            pairs = [*zip(named[len(named) - len(node.defaults):], node.defaults, strict=True),
                     *((a, d) for a, d in zip(node.kwonlyargs, node.kw_defaults, strict=True) if d is not None)]
            allowed.update(id(d) for a, d in pairs if a.arg == _SEAM and _reference(d) == _SEAM)

    def report(lineno: int, owner: str, name: str) -> None:
        found.append(f"{_RUN}:{lineno}: `{owner}` refers to `{name}`; the readers of the run "
                     f"folder live only in `{_POST_STEPS}`")

    def visit(node: ast.AST, owner: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not (node is tree and child.name == _POST_STEPS):
                    visit(child, child.name)
                continue
            if isinstance(child, ast.ClassDef):
                visit(child, child.name)
                continue
            if id(child) not in allowed:
                name = _reference(child)
                if name in _CENSUS:
                    report(child.lineno, owner, name)
                elif isinstance(child, ast.alias) and child.name.rsplit(".", 1)[-1] in _CENSUS:
                    report(child.lineno, owner, child.name)
            visit(child, owner)

    visit(tree, "<module>")
    return found


def _reference(node: ast.AST) -> str | None:
    """The reader-shaped name `node` refers to: a name, an attribute, or a string that is exactly one."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def scan(root: Path) -> list[str]:
    root = Path(root).resolve()
    if not root.is_dir():
        raise _astlib.ScanBlind(f"{root} is not a directory")
    findings: list[str] = []

    functions = {name: _function(root, _RUN, name, findings)
                 for name in (*_COMPOSITIONS, _POST_STEPS, "_run_investigation_lifecycle")}
    if (root / _RUN).is_file():
        _text, run_tree = _astlib.read_and_parse(root / _RUN, _RUN)
        for name in functions:
            lines = _bindings(run_tree, name)
            if len(lines) > 1:
                findings.append(f"{_RUN}: `{name}` is bound {len(lines)} times (lines "
                                f"{', '.join(map(str, lines))}); exactly one definition, or a second "
                                "shadows the one this rule reads")

    for name in _COMPOSITIONS:
        fn = functions[name]
        if fn is not None:
            findings.extend(_composition_findings(name, _call_order(fn)))

    steps = functions[_POST_STEPS]
    if steps is not None:
        order = _call_order(steps)
        for reader in _READERS:
            if reader not in order:
                findings.append(f"{_RUN}: `{_POST_STEPS}` no longer calls `{reader}`; re-site the "
                                "scrub-order rule")

    findings.extend(_readers_elsewhere(root))

    for name, fn in functions.items():
        if fn is None:
            continue
        for decorator in getattr(fn, "decorator_list", []):
            findings.append(f"{_RUN}:{decorator.lineno}: `{name}` is decorated; a decorator wraps the "
                            "function this rule reads")
        for lineno, caught in _caught(fn):
            if caught == "(bare except)" or caught in _SWALLOWERS:
                findings.append(f"{_RUN}:{lineno}: `{name}` has an `except` naming {caught} "
                                "that would swallow the run-tainted signal")
        for lineno, caught in _swallowing_withs(fn):
            findings.append(f"{_RUN}:{lineno}: `{name}` has a `with` naming {caught} that would "
                            "swallow the run-tainted signal")

    bash = _function(root, _BASH, "_tool_bash", findings)
    if bash is not None:
        if "run_parsed" not in _call_order(bash):
            findings.append(f"{_BASH}: `_tool_bash` no longer calls `run_parsed`; re-site the "
                            "no-in-process-fallback rule")
        for node in ast.walk(bash):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "run_parsed"
                    and isinstance(node.func.value, ast.Name)
                    and node.func.value.id == "bash_exec"):
                findings.append(f"{_BASH}:{node.lineno}: the bash tool reaches the in-process "
                                "executor directly; a box failure must not fall back to it")
    # One finding per fault: a missing `run.py` is found once, not once per function.
    return list(dict.fromkeys(findings))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=DEFENDER,
                        help="a defender/-shaped tree to sweep (default: this checkout's)")
    args = parser.parse_args(argv)
    try:
        found = scan(args.root)
    except _astlib.ScanBlind as exc:
        print(f"[lint_scrub_order] {exc}", file=sys.stderr)
        return 2
    for line in found:
        print(line)
    print(f"[lint_scrub_order] {len(found)} finding(s).")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
