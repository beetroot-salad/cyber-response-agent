#!/usr/bin/env python3
"""Close single-read fence (#991): the close reads and parses the investigation companion once.

* `runtime/close_tool.py` makes exactly one `parse_dense_companion(` call and one
  `read_companion(` call, and `_close_investigation_async` takes no `read_text` / `read_bytes` of
  its own beside the one read it hands to every gate.
* `runtime/challenge_gate.py` reads and parses nothing: no `read_text`, `read_bytes`,
  `parse_dense_companion` or `parse_investigation` call (it is handed the parsed document).
* The one parse sits inside `_refuse_if_entry_price_is_owed`, which catches and raises
  `ModelRetry`, so a parse fault is a refusal and never a traceback.

Calls are matched by the name they call (a bare name or an attribute). A missing file or function
is a finding (re-site the rule), never a pass. A file that does not parse or decode is exit 2. No
baseline, no suppression.

Run from anywhere:  python tooling/lint/lint_close_single_read.py [--root DIR]
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

_CLOSE = "runtime/close_tool.py"
_GATE = "runtime/challenge_gate.py"
_CLOSE_FN = "_close_investigation_async"
_GUARD_FN = "_refuse_if_entry_price_is_owed"
_OWN_READS = ("read_text", "read_bytes")
_GATE_BANNED = (*_OWN_READS, "parse_dense_companion", "parse_investigation")


def _name(call: ast.Call) -> str | None:
    f = call.func
    return f.attr if isinstance(f, ast.Attribute) else getattr(f, "id", None)


def _calls(node: ast.AST, *names: str) -> list[ast.Call]:
    return [n for n in ast.walk(node) if isinstance(n, ast.Call) and _name(n) in names]


def _tree(root: Path, rel: str, findings: list[str]) -> ast.Module | None:
    path = root / rel
    if not path.is_file():
        findings.append(f"{rel}: missing; the close single-read rule has nothing to hold")
        return None
    return _astlib.read_and_parse(path, rel)[1]


def _function(tree: ast.Module, rel: str, name: str, findings: list[str]) -> ast.AST | None:
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef) and node.name == name:
            return node
    findings.append(f"{rel}: defines no `{name}`; re-site the close single-read rule")
    return None


def _catches_model_retry(guard: ast.AST) -> bool:
    return any(isinstance(n, ast.ExceptHandler) and n.type is not None
               and any(isinstance(s, ast.Name) and s.id == "ModelRetry" for s in ast.walk(n.type))
               for n in ast.walk(guard))


def _raises_model_retry(guard: ast.AST) -> bool:
    return any(isinstance(n, ast.Raise) and n.exc is not None
               and any(isinstance(s, ast.Name) and s.id == "ModelRetry" for s in ast.walk(n.exc))
               for n in ast.walk(guard))


def scan(root: Path) -> list[str]:
    root = Path(root).resolve()
    if not root.is_dir():
        raise _astlib.ScanBlind(f"{root} is not a directory")
    findings: list[str] = []

    close = _tree(root, _CLOSE, findings)
    if close is not None:
        for name in ("parse_dense_companion", "read_companion"):
            n = len(_calls(close, name))
            if n != 1:
                findings.append(f"{_CLOSE}: {n} `{name}(` calls; the close takes one read and "
                                "one parse of the document and hands them to every gate")
        if (fn := _function(close, _CLOSE, _CLOSE_FN, findings)) is not None:
            findings.extend(f"{_CLOSE}:{c.lineno}: `{_CLOSE_FN}` takes its own `{_name(c)}` "
                            "beside the one read it hands out" for c in _calls(fn, *_OWN_READS))
        if (guard := _function(close, _CLOSE, _GUARD_FN, findings)) is not None:
            if not _calls(guard, "parse_dense_companion"):
                findings.append(f"{_CLOSE}: the close's one parse is not inside `{_GUARD_FN}`, "
                                "so a parse fault would unwind as a traceback")
            if not _catches_model_retry(guard) or not _raises_model_retry(guard):
                findings.append(f"{_CLOSE}: `{_GUARD_FN}` no longer both catches and raises "
                                "`ModelRetry`; the parse is bare again")

    gate = _tree(root, _GATE, findings)
    if gate is not None:
        findings.extend(f"{_GATE}:{c.lineno}: the gate takes its own `{_name(c)}` of a document "
                        "the close already parsed and handed in"
                        for c in _calls(gate, *_GATE_BANNED))
    return findings


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=DEFENDER,
                        help="a defender/-shaped tree to sweep (default: this checkout's)")
    args = parser.parse_args(argv)
    try:
        found = scan(args.root)
    except _astlib.ScanBlind as exc:
        print(f"[lint_close_single_read] {exc}", file=sys.stderr)
        return 2
    for line in found:
        print(line)
    print(f"[lint_close_single_read] {len(found)} finding(s).")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
