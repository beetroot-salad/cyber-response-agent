"""#1135 — the front door: O1's census, O5's surface pin, O4's root routes, D2's census words.

R17 makes O1's census (no state-tree touch outside the handle's module) and O5's surface pin the
main discharge of the change. Every scan here is an AST walk over the checkout this file sits in
(derived from `__file__`, never from an import: the shared venv's editable install points at the
main checkout), over WHAT THE DESIGN'S REPLAY WALKS (JF10 c): every `.py` under the repo root
except test files (`tests/` folders, `test_*.py`, `conftest.py`) and dot-folders, `.venv` and
`__pycache__`. A hit is anchored at `(module, qualname, kind, text)` — `text` is
`ast.unparse` of the node — never a line number, as #1134's census is.

THE CENSUS'S VOCABULARY (`STATE_MEMBERS`, `CHANNEL_MEMBERS`, `CHANNEL_FIELDS`, JF10 a) and its
FLOOR, stated rather than hidden:
  * it keys on attribute NAMES (G70's walk): a state path that reaches a module only as a plain
    `Path` parameter is seen where it was BUILT (the member read), not where it is touched;
  * a channel property (`.findings` / `.questioner_findings` / `.pitfalls`) counts only on a
    receiver named `*paths` or a `loop_paths()` / `LoopPaths(...)` call — `.findings` on other
    objects is a homonym (G70: quarantine.py, judge/run.py, runtime/scrub.py, ...), so a
    `lambda p: p.findings` is unobserved by this rule (its module is seen through its other
    reads);
  * a `QueueChannel` path field (`.file` / `.consumed` / `.append_lock` / `.drain_lock`) counts
    on a receiver whose name says `channel`, or on a channel property;
  * `runs_dir` (N4, #1166) is not in the vocabulary: `runs/` under the root is out of scope,
    so N4's compositions need no row;
  * sources outside the vocabulary (the package folder spelled by hand, the env var read
    directly, a `describe` string turned back into a path) are accepted as unobserved at R17's
    scale (JF10 d).
"""
from __future__ import annotations

import ast
import dataclasses
import functools
import importlib
import inspect
import io
import json
import os
import sys
import tokenize
from collections.abc import Callable, Iterable
from pathlib import Path, PurePath
from typing import Any

import pytest

from defender.tests.learning_state_1135 import _spec1135 as S

REPO_ROOT = S.REPO_ROOT

#: The handle's module, as a census module path (the one module the allow-list holds whole).
STATE_MODULE_REL = str(S.STATE_MODULE_FILE.relative_to(REPO_ROOT))

# ---------------------------------------------------------------------------------------------
# The walk
# ---------------------------------------------------------------------------------------------

_SKIP_DIRS = frozenset({"tests", "venv", "__pycache__", "node_modules"})


def _is_test_file(name: str) -> bool:
    return name.startswith("test_") or name.endswith("_test.py") or name == "conftest.py"


@functools.cache
def production_modules() -> tuple[str, ...]:
    """Every production `.py` of this checkout, repo-relative, sorted (JF10 c)."""
    out: list[str] = []
    for dirpath, dirnames, filenames in os.walk(REPO_ROOT):
        dirnames[:] = sorted(d for d in dirnames if d not in _SKIP_DIRS and not d.startswith("."))
        for f in sorted(filenames):
            if f.endswith(".py") and not _is_test_file(f):
                out.append(str((Path(dirpath) / f).relative_to(REPO_ROOT)))
    return tuple(out)


@functools.cache
def _source(module: str) -> str:
    return (REPO_ROOT / module).read_text(encoding="utf-8")


@functools.cache
def _parsed(module: str) -> ast.Module | None:
    try:
        return ast.parse(_source(module))
    except SyntaxError:
        return None


#: Production modules every scan here must see, all kept by the design: a walk that misses one
#: is looking at the wrong tree (a wrong root, a skip rule that swallowed a package).
_WALK_SENTINELS = (
    "defender/run_common.py",
    "defender/learning/core/config.py",
    "defender/learning/core/drains.py",
    "defender/learning/author/drain.py",
    "defender/learning/frontend/serialize_queues.py",
)


def _assert_the_walk_sees_the_tree() -> None:
    """The scans' shared precondition, so none of them can pass by seeing nothing: the walk
    holds the sentinel modules, and every walked module parsed (a module that does not parse
    would be skipped silently)."""
    walked = production_modules()
    missing = [m for m in _WALK_SENTINELS if m not in walked]
    assert not missing, f"the production walk ({len(walked)} modules) misses {missing}"
    unparsed = [m for m in walked if _parsed(m) is None]
    assert not unparsed, f"production modules the scans skip because they do not parse: {unparsed}"


def _handle_source() -> Path | None:
    """The file the imported learning-state module was loaded from. Every scan here exempts the
    handle's module BY PATH (`STATE_MODULE_REL`), so a control's exemption means something only
    when that path is the file the handle is actually defined in (F1) — a same-named module
    loaded from anywhere else leaves the exempted file unproven."""
    where = getattr(sys.modules.get(S.STATE_MODULE), "__file__", None)
    return Path(where).resolve() if where else None


@dataclasses.dataclass(frozen=True)
class Touch:
    module: str
    qualname: str
    kind: str
    text: str
    line: int

    @property
    def anchor(self) -> tuple[str, str, str, str]:
        return (self.module, self.qualname, self.kind, self.text)

    def show(self) -> str:
        return f"{self.module}:{self.line} [{self.qualname}] {self.kind}: {self.text}"


def _terminal(expr: ast.AST) -> str:
    """The last identifier an expression names: `a.b.c` -> `c`, `f()` -> `f`, `x[0]` -> `x`."""
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        return expr.attr
    if isinstance(expr, ast.Call):
        return _terminal(expr.func)
    if isinstance(expr, ast.Subscript):
        return _terminal(expr.value)
    return ""


def _walk_scoped(tree: ast.AST) -> Iterable[tuple[ast.AST, tuple[ast.AST, ...]]]:
    """Every node with its enclosing class/def chain (outermost first)."""
    def go(node: ast.AST, chain: tuple[ast.AST, ...]) -> Iterable[tuple[ast.AST, tuple[ast.AST, ...]]]:
        for child in ast.iter_child_nodes(node):
            yield child, chain
            scoped = isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
            yield from go(child, (*chain, child) if scoped else chain)
    yield from go(tree, ())


def _qualname(chain: tuple[ast.AST, ...]) -> str:
    names = [n.name for n in chain if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
    return ".".join(names) or "<module>"


# ---------------------------------------------------------------------------------------------
# O1's census
# ---------------------------------------------------------------------------------------------

#: `LoopPaths`' state members (config.py; brief S1-S3), unambiguous by name.
STATE_MEMBERS = frozenset({
    "state_root", "state_dir", "pending_dir", "lead_pending_dir", "pitfalls_pending_dir",
    "author_lock_file", "author_queue_dir", "author_drain_lock_file",
    "lead_author_drain_lock_file", "pending_delivery_dir", "pending_file", "findings_lock_file",
    "questioner_findings_file",
})
#: `LoopPaths`' channel properties (each a `QueueChannel` of state paths).
CHANNEL_MEMBERS = frozenset({"findings", "questioner_findings", "pitfalls"})
#: `QueueChannel`'s path fields.
CHANNEL_FIELDS = frozenset({"file", "consumed", "append_lock", "drain_lock"})
#: D2's two core functions: callers are the learning-state module only.
CORE_WORDS = frozenset({"move_at", "open_lock_at"})
#: The class whose own property bodies define the members (`self.state_root` there is a
#: definition, not a touch).
_DEFINING_CLASSES = frozenset({"LoopPaths"})
#: Path verbs a value handed out by `stage_dir` must not be the receiver of in the caller.
_PATH_VERBS = frozenset({
    "open", "mkdir", "write_text", "write_bytes", "read_text", "read_bytes", "unlink", "rmdir",
    "touch", "rename", "replace", "glob", "rglob", "iterdir", "exists", "is_file", "is_dir",
    "joinpath", "symlink_to", "hardlink_to", "stat", "lstat", "resolve",
})


def _contains_stage_dir_call(node: ast.AST) -> bool:
    return any(isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
               and n.func.attr == "stage_dir" for n in ast.walk(node))


def _stage_bound_names(fn: ast.AST) -> set[str]:
    """Names a function binds from an expression holding a `.stage_dir(...)` call."""
    out: set[str] = set()
    for n in ast.walk(fn):
        if isinstance(n, ast.Assign) and _contains_stage_dir_call(n.value):
            out |= {t.id for t in n.targets if isinstance(t, ast.Name)}
        elif isinstance(n, (ast.AnnAssign, ast.NamedExpr)) and n.value is not None \
                and _contains_stage_dir_call(n.value) and isinstance(n.target, ast.Name):
            out.add(n.target.id)
    return out


def _is_stage_value(expr: ast.AST, stage_names: set[str]) -> bool:
    if isinstance(expr, ast.Name):
        return expr.id in stage_names
    return isinstance(expr, ast.Call) and isinstance(expr.func, ast.Attribute) \
        and expr.func.attr == "stage_dir"


def _is_flock_import(node: ast.AST) -> bool:
    if isinstance(node, ast.Import):
        return any(a.name.split(".")[-1] == "_flock" for a in node.names)
    if isinstance(node, ast.ImportFrom):
        return (node.module or "").split(".")[-1] == "_flock" or any(
            a.name == "_flock" for a in node.names)
    return False


def scan_state_touches(module: str, tree: ast.Module) -> list[Touch]:  # noqa: C901, PLR0912 — one flat dispatch over the census's node shapes
    """One module's state-tree touches (kinds: member, channel-field, flock, core, escape,
    compose). The learning-state module itself is never scanned (`state_touches`)."""
    hits: list[Touch] = []
    flock_aliases = {a.asname or a.name.split(".")[0] for n in ast.walk(tree)
                     if _is_flock_import(n) for a in n.names}
    stage_names_by_fn: dict[int, set[str]] = {}

    def add(kind: str, node: ast.AST, chain: tuple[ast.AST, ...]) -> None:
        hits.append(Touch(module, _qualname(chain), kind, ast.unparse(node),
                          getattr(node, "lineno", 0)))

    for node, chain in _walk_scoped(tree):
        in_defining_class = any(isinstance(c, ast.ClassDef) and c.name in _DEFINING_CLASSES
                                for c in chain)
        if isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
            own = in_defining_class and isinstance(node.value, ast.Name) and node.value.id == "self"
            recv = _terminal(node.value)
            if node.attr in STATE_MEMBERS and not own or node.attr in CHANNEL_MEMBERS and not own and (
                    recv.lower().endswith("paths") or (
                        isinstance(node.value, ast.Call) and recv in ("loop_paths", "LoopPaths"))):
                add("member", node, chain)
            elif node.attr in CHANNEL_FIELDS and (
                    "channel" in recv.lower() or recv in CHANNEL_MEMBERS):
                add("channel-field", node, chain)
            elif node.attr in CORE_WORDS and module != "defender/_io.py":
                add("core", node, chain)
            elif node.attr == "_flock" and module != "defender/_flock.py":
                add("flock", node, chain)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load):
            if node.id in CORE_WORDS and module != "defender/_io.py":
                add("core", node, chain)
            elif node.id in flock_aliases and module != "defender/_flock.py":
                add("flock", node, chain)
        elif isinstance(node, (ast.Import, ast.ImportFrom)):
            if _is_flock_import(node) and module != "defender/_flock.py":
                add("flock", node, chain)
            elif isinstance(node, ast.ImportFrom) and module != "defender/_io.py" and any(
                    a.name in CORE_WORDS for a in node.names):
                add("core", node, chain)
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr == "stage_dir":
            add("escape", node, chain)
        if isinstance(node, (ast.BinOp, ast.Call)):
            fn = next((c for c in reversed(chain)
                       if isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef))), None)
            if fn is None:
                continue
            names = stage_names_by_fn.setdefault(id(fn), _stage_bound_names(fn))
            if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div) \
                    and _is_stage_value(node.left, names) or isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                    and node.func.attr in _PATH_VERBS and _is_stage_value(node.func.value, names):
                add("compose", node, chain)
    return hits


@functools.cache
def state_touches() -> tuple[Touch, ...]:
    """O1's census over the checkout: every state-tree touch outside the learning-state module."""
    out: list[Touch] = []
    for module in production_modules():
        if module == STATE_MODULE_REL:
            continue
        tree = _parsed(module)
        if tree is not None:
            out.extend(scan_state_touches(module, tree))
    return tuple(out)


_N3 = ("N3: agent-stage records stay with #1142; `stage_dir(lane)` is the handle's one path "
       "escape, handing `learning_run_dir` to the stage harness at this site")
_N7 = ("N7: evals/ is not application code (#1105 R2); it keeps touching its own temporary "
       "state tree by path (and points a CLI at one through the env var)")

#: O1's allow-list. Each row is `(module, qualname, kind, text)` with its reason; `*` matches
#: anything. N3's rows are one per stage-harness site (JF10 b) — today's five, named by the
#: function that hands the stage its folder (S4, G54); their call text is the implementer's
#: (`*`), the kind is pinned to the escape itself, so a composition onto the folder (`compose`)
#: is never admitted. N7's two modules are allowed whole. The learning-state module is not
#: scanned at all.
ALLOW: dict[tuple[str, str, str, str], str] = {
    ("defender/learning/author/lessons/run.py", "invoke_agent", "escape", "*"): _N3,
    ("defender/learning/author/questioner/run.py", "invoke_agent", "escape", "*"): _N3,
    ("defender/learning/author/shared.py", "invoke_repair", "escape", "*"): _N3,
    ("defender/learning/leads/pitfalls_curator.py", "_invoke_pitfalls_agent", "escape", "*"): _N3,
    ("defender/learning/leads/_lead_spine.py", "_spawn_author_agent", "escape", "*"): _N3,
    ("defender/evals/harness.py", "*", "*", "*"): _N7,
    ("defender/evals/harness_lead.py", "*", "*", "*"): _N7,
}


def allowed(touch: Touch, allow: dict[tuple[str, str, str, str], str] = ALLOW) -> str | None:
    for (mod, qual, kind, text), reason in allow.items():
        if mod == touch.module and qual in ("*", touch.qualname) and kind in ("*", touch.kind) \
                and text in ("*", touch.text):
            return reason
    return None


def _listing(hits: list[Touch], n: int = 40) -> str:
    modules = sorted({h.module for h in hits})
    shown = "\n  ".join(h.show() for h in hits[:n])
    more = f"\n  ... and {len(hits) - n} more" if len(hits) > n else ""
    return (f"{len(hits)} state-tree touch(es) outside the handle in {len(modules)} module(s) "
            f"{modules}:\n  {shown}{more}")


#: X7's eight `lint-unguarded-tree-write: ok` waivers O1 says are gone, by (module, function).
X7_WAIVERS = frozenset({
    ("defender/learning/author/shared.py", "invoke_repair"),
    ("defender/learning/author/shared.py", "write_disposition_report"),
    ("defender/learning/author/drain.py", "_bump_rows"),
    ("defender/learning/author/drain.py", "_append_gap_record"),
    ("defender/learning/author/drain.py", "_retire_unkeyable"),
    ("defender/learning/author/drain.py", "_record_stuck"),
    ("defender/learning/author/questioner/run.py", "invoke_agent"),
    ("defender/learning/leads/pitfalls_curator.py", "_graveyard_dropped_rows"),
})
_WAIVER = "lint-unguarded-tree-write: ok"


def _waivers_by_function(module: str) -> set[tuple[str, str]]:
    """`(module, enclosing top-level-or-method qualname)` of every `_WAIVER` comment in `module`."""
    path = REPO_ROOT / module
    if not path.is_file():
        return set()
    tree = _parsed(module)
    spans: list[tuple[int, int, str]] = []
    for node, chain in _walk_scoped(tree) if tree is not None else ():
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            spans.append((node.lineno, node.end_lineno or node.lineno,
                          _qualname((*chain, node))))
    out: set[tuple[str, str]] = set()
    for tok in tokenize.generate_tokens(io.StringIO(_source(module)).readline):
        if tok.type == tokenize.COMMENT and _WAIVER in tok.string:
            line = tok.start[0]
            inner = [s for s in spans if s[0] <= line <= s[1]]
            qual = max(inner, key=lambda s: s[0])[2] if inner else "<module>"
            out.add((module, qual))
    return out


#: The write lint's ratchet (scripts/lint/lint_unguarded_tree_write.py): keys are
#: `<file relative to defender/>:<innermost enclosing function name>`.
_WRITE_LINT_BASELINE = REPO_ROOT / "scripts" / "lint" / "lint_unguarded_tree_write_baseline.json"


def _baseline_keys_of_deleted_functions() -> list[str]:
    """Every baseline key whose file or function no longer exists in this checkout."""
    entries = json.loads(_WRITE_LINT_BASELINE.read_text(encoding="utf-8"))["entries"]
    orphaned: list[str] = []
    for key in sorted(entries):
        rel, _, fn = key.rpartition(":")
        module = f"defender/{rel}"
        tree = _parsed(module) if (REPO_ROOT / module).is_file() else None
        names = {n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))} \
            if tree is not None else set()
        if fn != "<module>" and fn not in names:
            orphaned.append(key)
    return orphaned


def test_no_production_module_touches_the_state_tree_outside_the_handle() -> None:
    """A census in test_1134_census's style over every production module (JF10 c: what the
    design's replay walks, scripts included) flags any path-seam call, plain filesystem call or
    _flock call whose operand derives from a LoopPaths state member or the handle's root, any
    read outside the module of a LoopPaths state member, a QueueChannel path field or a root
    route (JF10 a), and any call of move_at or open_lock_at. Its allow-list holds only the
    learning-state module itself; N3's stage_dir escape, one row per stage-harness touch (JF10
    b); N4's runs_dir compositions (author/drain.py around 1221/1232, lessons/run.py:113,
    verify_forward/forward.py:19, verify_forward/checks.py:90, ops/trace_lesson.py:77); and N7's
    evals (evals/harness.py, evals/harness_lead.py). Each entry carries its reason and is keyed
    by (module, qualname, kind, call text), never a line number. The eight
    `lint-unguarded-tree-write: ok` waivers O1 lists (X7) are gone, and the write lint's
    baseline keeps no key for a function this change deletes (JF10 e): every
    `lint_unguarded_tree_write_baseline.json` key names a function that still exists at that
    file, so a deleted writer's key cannot grandfather a later unguarded write of the same name.

    Here `runs_dir` is outside the census vocabulary (`runs/` is #1166's), so N4's compositions
    need no row. A root-route read is flagged by #10's scan, whose allow-list is the named entry
    points (they hand the root inward only through LearningState.open); this census reuses it.
    The census's floor is the module docstring's (attribute names, G70; JF10 d). The
    learning-state module the allow-list exempts is the one that defines LearningState (F1).
    The walk is checked first: it holds the kept modules and every walked module parsed."""
    # rejected: N5 — no-writer records are not touched; N6 — quarantine_dir and frontend build
    # outputs are not state records; N2 — run-tree touches such as <run_dir>/lead_author/done
    # are #1105's; JF10 d — sources outside the census vocabulary are accepted as unobserved
    # at R17's scale.
    _assert_the_walk_sees_the_tree()
    unexpected = [h for h in state_touches() if allowed(h) is None]
    assert not unexpected, _listing(unexpected)

    stray_routes = [h for h in root_routes() if not route_allowed(h)]
    assert not stray_routes, "root-route reads outside the entry points (JF10 a):\n  " + "\n  ".join(
        h.show() for h in stray_routes[:40])

    left = set().union(*(_waivers_by_function(m) for m in {m for m, _ in X7_WAIVERS}))
    stale = sorted(left & X7_WAIVERS)
    assert not stale, f"O1's `{_WAIVER}` waivers are still in place (X7): {stale}"

    orphaned = _baseline_keys_of_deleted_functions()
    assert not orphaned, (
        "lint_unguarded_tree_write's baseline keeps keys for functions that no longer exist "
        f"(JF10 e: prune them, or a later write under the same name is grandfathered): {orphaned}")

    assert S.LearningState.__module__ == S.STATE_MODULE, (
        f"the module the census exempts ({STATE_MODULE_REL}) must be the one that defines "
        f"LearningState; it is defined in {S.LearningState.__module__}")


_PLANTED_TOUCHES = '''
from pathlib import Path
from defender import _flock
from defender._io import move_at, open_lock_at
from defender.learning.core.config import AUTHOR_DRAIN_LABEL, LoopPaths


def reads(paths: LoopPaths) -> str:
    return paths.pending_file.read_text(encoding="utf-8")


def writes(paths: LoopPaths) -> None:
    (paths.author_queue_dir / "case-x.json").write_text("{}", encoding="utf-8")


def lists(paths: LoopPaths) -> list[Path]:
    return sorted(paths.pending_dir.glob("*.jsonl"))


def locks(paths: LoopPaths):
    return _flock.open_lock(paths.author_lock_file)


def renames(paths: LoopPaths, staged: Path) -> None:
    staged.replace(paths.state_root / "author-queue" / "case-x.json")


def channel_field(cfg) -> Path:
    return cfg.channel.consumed


def channel_property(paths: LoopPaths) -> object:
    return paths.findings


def core_calls(held) -> None:
    move_at(held, "author-queue/case-x.json", "author-queue/inflight/case-x.json")
    with open_lock_at(held, "_author.lock"):
        pass


def composes_onto_the_stage_folder(state) -> Path:
    folder = state.stage_dir(AUTHOR_DRAIN_LABEL)
    return folder / "findings.jsonl"


def through_the_handle(state, findings) -> object:
    return state.rows(findings)
'''

#: What the census must say of each planted function: the kinds it must flag there.
_PLANTED_EXPECT: dict[str, set[str]] = {
    "reads": {"member"}, "writes": {"member"}, "lists": {"member"},
    "locks": {"member", "flock"}, "renames": {"member"}, "channel_field": {"channel-field"},
    "channel_property": {"member"}, "core_calls": {"core"},
    "composes_onto_the_stage_folder": {"escape", "compose"},
}


def test_the_state_census_flags_a_planted_touch_of_each_kind() -> None:
    """The state census flags a synthetic module that, outside the handle, composes a LoopPaths
    state member and reads, writes, lists, locks (_flock.open_lock) or renames it, and it flags a
    call of move_at or open_lock_at from outside the module. So the census in #3 cannot pass by
    seeing nothing.

    Also: a channel path field read through a channel, a channel property, and a composition
    onto the folder `stage_dir` hands out are flagged (and that composition is never admitted
    by an N3 row); a call through the handle's own verbs is not a touch; the same source placed
    AT the learning-state module (the one that defines LearningState) is not scanned."""
    module = "defender/learning/core/planted_touch.py"
    hits = scan_state_touches(module, ast.parse(_PLANTED_TOUCHES))
    by_fn: dict[str, set[str]] = {}
    for h in hits:
        by_fn.setdefault(h.qualname.split(".")[0], set()).add(h.kind)
    for fn, kinds in _PLANTED_EXPECT.items():
        assert kinds <= by_fn.get(fn, set()), (
            f"the census missed a planted touch in {fn}: wanted {sorted(kinds)}, "
            f"saw {sorted(by_fn.get(fn, set()))}")
    assert "through_the_handle" not in by_fn, (
        f"a call through the handle's verbs is not a touch: {by_fn.get('through_the_handle')}")
    import_hits = {h.kind for h in hits if h.qualname == "<module>"}
    assert {"flock", "core"} <= import_hits, (
        f"importing _flock / move_at outside the handle is a touch: saw {sorted(import_hits)}")

    composed = [h for h in hits if h.kind == "compose"]
    n3_site = {(m, q, k, t): r for (m, q, k, t), r in ALLOW.items() if k == "escape"}
    n3_site[(module, "composes_onto_the_stage_folder", "escape", "*")] = _N3
    assert composed, "the census missed the composition onto the stage folder"
    admitted = [h for h in composed if allowed(h, n3_site) is not None]
    assert not admitted, f"a composition onto the stage folder must stay a hit at an N3 site: {admitted}"

    own = [h for h in state_touches() if h.module == STATE_MODULE_REL]
    assert not own, f"the learning-state module itself is never a census hit: {own}"
    assert S.LearningState.__module__ == S.STATE_MODULE, (
        "the allow-listed module must be the one that defines LearningState (F1)")
    assert _handle_source() == S.STATE_MODULE_FILE.resolve(), (
        f"the census allow-lists {STATE_MODULE_REL}, but the handle was loaded from {_handle_source()}")


# ---------------------------------------------------------------------------------------------
# O5's surface pin
# ---------------------------------------------------------------------------------------------

#: D1's verbs as the design spells them (F1, auto at §7: the provisional reading is kept; the
#: implementer may rename within this pin). `stuck(channel)`'s read / append / count spelling is
#: left to the implementer (the design gives one word for three operations).
D1_VERBS = (
    "open",
    "enqueue_curation", "has_requests", "claim", "stamp", "requeue", "done", "quarantine",
    "failed_requests",
    "record_delivery", "deliveries", "delivered", "quarantine_delivery", "failed_deliveries",
    "append", "rows", "rows_report", "rotate", "deadletter", "deadletter_rows", "gap_record",
    "disposition_report",
    "lock", "describe", "stage_dir",
)
#: Annotation words that name a place in the tree, a lock descriptor or a folder handle.
_PATHISH = ("Path", "PurePath", "PathLike", "IO", "TextIOWrapper", "BufferedRandom", "Held",
            "Bound")
#: Each coined lock role and the one lock file taking it may make below the root (brief O3's
#: lock table). None of them is a channel's append lock (the lock nesting rule).
ROLE_FILES = {
    "REPO_LOCK": "_author.lock",
    "AUTHOR_DRAIN_LOCK": ".author-drain.lock",
    "LEAD_AUTHOR_DRAIN_LOCK": ".lead-author-drain.lock",
    "LEAD_QUEUE_LOCK": "_pending_leads/.lock",
    "CURATOR_DRAIN_LOCK": "_pending/.lock",
}
APPEND_LOCK_FILES = ("_pending/.findings.lock", "_pending/.questioner_findings.lock",
                     "_pending_pitfalls/.pitfalls.lock")


def _pathish(annotation: object) -> bool:
    if isinstance(annotation, str):
        text = annotation
    elif isinstance(annotation, type):
        text = annotation.__name__
    else:
        text = repr(annotation)
    for ch in "[],|.()'\"":
        text = text.replace(ch, " ")
    return any(w in text.split() for w in _PATHISH)


def _path_valued(obj: object) -> dict[str, object]:
    """`obj`'s Path-valued attributes, whatever its record shape (instance dict, dataclass
    fields, slots, named-tuple fields)."""
    names = set(getattr(obj, "__dict__", None) or {})
    if dataclasses.is_dataclass(obj):
        names |= {f.name for f in dataclasses.fields(obj)}
    for klass in type(obj).__mro__:
        slots = getattr(klass, "__slots__", ())
        names |= {slots} if isinstance(slots, str) else set(slots)
    names |= set(getattr(obj, "_fields", ()) or ())
    values = {n: getattr(obj, n, None) for n in sorted(names)}
    return {n: v for n, v in values.items() if isinstance(v, PurePath)}


def _surface_offenders(cls: type) -> list[str]:  # noqa: C901 — one rule per signature part
    """O5's pin over every public verb's signature."""
    offenders: list[str] = []
    for name, member in inspect.getmembers(cls):
        if name.startswith("_") or not (inspect.isfunction(member) or inspect.ismethod(member)):
            continue
        sig = inspect.signature(member)
        for p in sig.parameters.values():
            if p.name in ("self", "cls"):
                continue
            if p.annotation is inspect.Parameter.empty:
                offenders.append(f"{name}({p.name}) is unannotated")
            elif _pathish(p.annotation):
                offenders.append(f"{name} takes {p.name}: {p.annotation}")
        ret = sig.return_annotation
        if ret is inspect.Signature.empty:
            offenders.append(f"{name}() has no return annotation")
        elif name == "stage_dir":
            if "Path" not in str(ret):
                offenders.append(f"stage_dir returns {ret}, not a Path (N3's escape)")
        elif _pathish(ret):
            offenders.append(f"{name} returns {ret}")
        elif name != "describe" and str(ret).strip("'\"") == "str":
            offenders.append(f"{name} returns a display string; describe is the only one")
    return offenders


def _annotations_of(cls: type) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for klass in reversed(cls.__mro__):
        out.update(getattr(klass, "__annotations__", {}) or {})
    return out


def _enter(cm: Any) -> None:
    with cm:
        pass


def test_the_handle_surface_takes_and_returns_no_tree_path(tmp_path: Path) -> None:
    """The learning-state module's public names and signatures are pinned. No verb takes or
    returns a Path into the tree, a lock descriptor or a folder; the one exception is
    stage_dir(lane) -> Path. describe(record) -> str is the only display-string verb. Channel
    and Claimed carry names (channel, request key, delivery id, lock role) and no Path field.
    lock(role, *, wait) accepts only the repo-lock and drain-lock roles: no channel append-lock
    role is exposed (the lock nesting rule), and wait is one of try-once, deadline-with-poll or
    block. An unknown role, lane or channel is the handle's own input error, neither
    StateRefused nor an OSError, raised before any filesystem call (JF20).

    The pin reads annotations (A6, auto at §7: signature level), so every public verb's
    parameters and return are annotated; a `Channel` value and a `Claimed` from a real claim
    are checked for Path-valued fields at runtime too."""
    paths = S.built_paths(tmp_path)
    state = S.LearningState.open(paths)
    cls = S.LearningState
    assert inspect.isclass(cls), f"LearningState is not a class: {cls!r}"

    missing = [v for v in D1_VERBS if not callable(getattr(cls, v, None))]
    assert not missing, f"D1's verbs absent from LearningState: {missing}"

    offenders = _surface_offenders(cls)
    assert not offenders, f"the handle's surface carries a tree path: {offenders}"
    assert str(inspect.signature(cls.describe).return_annotation).strip("'\"") == "str", (
        "describe(record) must return str")

    lock_params = [p for p in inspect.signature(cls.lock).parameters.values()
                   if p.name not in ("self", "cls")]
    shape = [(p.name, p.kind.name) for p in lock_params]
    assert [p.name for p in lock_params[:1]] == ["role"], f"lock must be lock(role, *, wait): {shape}"
    assert ("wait", "KEYWORD_ONLY") in shape, f"lock must be lock(role, *, wait): {shape}"

    for kind_name, kind in (("Channel", S.Channel), ("Claimed", S.Claimed)):
        assert inspect.isclass(kind), f"{kind_name} is not a class: {kind!r}"
        typed = {f: a for f, a in _annotations_of(kind).items() if _pathish(a)}
        assert not typed, f"{kind_name} declares a Path-like field: {typed}"
    for channel_name in ("FINDINGS", "QUESTIONER_FINDINGS", "PITFALLS"):
        value = S.coined(channel_name)
        assert isinstance(value, S.Channel), f"{channel_name} is not a Channel: {value!r}"
        held = _path_valued(value)
        assert not held, f"{channel_name} carries a Path: {held}"

    S.seed_request(paths, "case-0000000000000001", tmp_path / "runs" / "r1")
    claims = list(state.claim("case_id"))
    assert len(claims) == 1, f"one queued request must claim once: {claims!r}"
    assert isinstance(claims[0], S.Claimed), f"a claim must be a Claimed: {claims[0]!r}"
    held_paths = _path_valued(claims[0])
    assert not held_paths, f"a Claimed carries a Path field: {held_paths}"
    state.done(claims[0])

    for role_name, lock_file in ROLE_FILES.items():
        before = set(S.tree_snapshot(paths.state_root))
        _enter(state.lock(S.coined(role_name), wait=S.coined("TRY_ONCE")))
        made = sorted(set(S.tree_snapshot(paths.state_root)) - before)
        touched = sorted(set(made) & set(APPEND_LOCK_FILES))
        assert not touched, f"taking {role_name} made a channel append lock: {touched}"
        assert (paths.state_root / lock_file).is_file(), (
            f"{role_name} did not take {lock_file} (made {made})")

    before = S.tree_snapshot(paths.state_root)
    unknown: dict[str, Callable[[], Any]] = {
        "unknown role": lambda: _enter(state.lock("no-such-role", wait=S.coined("TRY_ONCE"))),
        "a channel as a lock role": lambda: _enter(
            state.lock(S.coined("FINDINGS"), wait=S.coined("TRY_ONCE"))),
        "unknown lane": lambda: state.stage_dir("no-such-lane"),
        "unknown channel": lambda: list(state.rows("no-such-channel")),
    }
    for what, call in unknown.items():
        exc = S.caught(call)
        assert exc is not None, f"{what}: the handle answered instead of raising its input error"
        assert not S.is_refusal(exc), f"{what}: an input error is not a StateRefused: {exc!r}"
        assert not isinstance(exc, OSError), f"{what}: an input error is not an OSError: {exc!r}"
        assert S.tree_snapshot(paths.state_root) == before, (
            f"{what}: the handle touched the tree before refusing its input")


# ---------------------------------------------------------------------------------------------
# O5: the seams that carried state
# ---------------------------------------------------------------------------------------------

#: Parameter / field names that are state Paths or lock callables today (G24).
_STATE_PATH_NAMES = frozenset({
    "pending_dir", "pending_file", "repo_lock_file", "held_report", "skip_report", "queue_dir",
    "lock_file", "queue_lock_file", "pending", "consumed_file",
})
#: Annotation words a reshaped seam must not carry: today's path-field channel and claim.
_STATE_TYPES = ("QueueChannel", "ClaimedMarker")

#: The seams D1 / RF6 name that do learning-state I/O: each must take the handle or a Channel
#: (a parameter annotated with either, or named `state`), and carry no state Path.
TAKES_HANDLE = (
    ("defender.learning.core.drains", "_maybe_trigger_author"),
    ("defender.learning.core.drains", "_has_curator_work"),
    ("defender.learning.core.drains", "_has_lead_author_work"),
    ("defender.learning.core.drains", "_drain_curators"),
    ("defender.learning.core.drains", "_drain_one_curator"),
    ("defender.learning.core.drains", "_invoke_lead_author"),
    ("defender.learning.core.drains", "_invoke_pitfalls"),
    ("defender.learning.core.drains", "_drain_lead_author"),
    ("defender.learning.core.drains", "BatchDisposition.apply"),
    ("defender.learning.core.pitfalls_disposition", "PitfallsDisposition.apply"),
    ("defender.learning.core.pitfalls_disposition", "_retire_exhausted_holds"),
    ("defender.learning.leads.pitfalls_curator", "_graveyard_dropped_rows"),
    ("defender.learning.leads.lead_author", "run_under_held_queue_lock"),
    ("defender.learning.leads.lead_author", "build_lead_author_deps"),
    ("defender.learning.leads.lead_author._handoff", "acquire_queue_lock"),
    ("defender.learning.ops.revert_lesson", "revert"),
    ("defender.learning.frontend.serialize_queues", "build_view"),
    ("defender.learning.frontend.serialize_queues", "stamped_view"),
    ("defender.learning.judge.enqueue", "enqueue_report"),
)
#: Seams that keep their shape otherwise (an entry point may hold a `LoopPaths` for the repo
#: trees and open the handle itself): no state Path, no path-field channel or claim.
NO_STATE_PATH = (
    ("defender.learning.leads.lead_author", "run"),
    ("defender.learning.frontend.build", "main"),
)
#: Records and configs reshaped per O5 (fields).
RECORDS = (
    ("defender.learning.author._config", "CorpusAuthorConfig"),
    ("defender.learning.author.lessons.run", "AuthorConfig"),
    ("defender.learning.author.questioner.run", "QuestionerAuthorConfig"),
    ("defender.learning.author.verify_forward.checks", "CheckContext"),
    ("defender.learning.leads.lead_author", "LeadAuthorDeps"),
    ("defender.learning.core.drains", "PendingDelivery"),
    ("defender.learning.core.drains", "ServedMarker"),
    ("defender.learning.frontend.serialize_queues", "_ChannelSpec"),
)
#: Names that carry a state path and must not exist at all.
GONE = (
    ("defender.learning.leads.lead_author._handoff", "queue_lock_file"),
)
#: The listed seams and records the graph itself binds (o5_seams_take_the_handle, all 14 names):
#: reshaped, never removed, so each must still resolve. A seam missing from these three tables
#: may be removed outright (it then carries nothing); one listed here that stops resolving was
#: renamed past this pin. By import: the function seams and the five record classes.
MUST_RESOLVE = (
    ("defender.learning.core.drains", "BatchDisposition.apply"),
    ("defender.learning.core.pitfalls_disposition", "PitfallsDisposition.apply"),
    ("defender.learning.leads.lead_author", "run_under_held_queue_lock"),
    ("defender.learning.leads.lead_author", "build_lead_author_deps"),
    ("defender.learning.ops.revert_lesson", "revert"),
    ("defender.learning.frontend.serialize_queues", "build_view"),
    ("defender.learning.judge.enqueue", "enqueue_report"),
    ("defender.learning.author._config", "CorpusAuthorConfig"),
    ("defender.learning.author.verify_forward.checks", "CheckContext"),
    ("defender.learning.leads.lead_author", "LeadAuthorDeps"),
    ("defender.learning.core.drains", "PendingDelivery"),
    ("defender.learning.core.drains", "ServedMarker"),
)
#: A bound seam that is a parameter, not a name: the corpus drain's `trigger_author` keyword
#: (its callers, the loop's tests and this suite's tick, pass it by that name).
MUST_TAKE = (("defender.learning.core.drains", "author_drain", "trigger_author"),)
#: A bound seam resolved by its definition in the walk, not by import: evals/harness.py imports
#: its sibling `_harness_util` as a top-level module, so it loads only with evals/ on sys.path.
MUST_DEFINE = (("defender/evals/harness.py", "run_author"),)


def _resolve(module: str, qual: str) -> Any:
    obj: Any = importlib.import_module(module)
    for part in qual.split("."):
        obj = getattr(obj, part, None)
        if obj is None:
            return None
    return obj


def _unresolved_bound_seams() -> list[str]:
    """The graph-bound seams (MUST_RESOLVE, MUST_TAKE, MUST_DEFINE) that no longer resolve."""
    out = [f"{m}.{q}" for m, q in MUST_RESOLVE if _resolve(m, q) is None]
    for module, fn_name, param in MUST_TAKE:
        fn = _resolve(module, fn_name)
        if fn is None or param not in inspect.signature(fn).parameters:
            out.append(f"{module}.{fn_name}({param}=)")
    for rel, name in MUST_DEFINE:
        tree = _parsed(rel) if (REPO_ROOT / rel).is_file() else None
        if tree is None or not any(
                isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name
                for n in tree.body):
            out.append(f"{rel}::{name}")
    return out


def _state_field_problems(where: str, name: str, annotation: object) -> list[str]:
    text = str(annotation)
    out: list[str] = []
    if name in _STATE_PATH_NAMES:
        out.append(f"{where} keeps {name}: {text}")
    if any(t in text for t in _STATE_TYPES):
        out.append(f"{where}.{name} is a path-field channel or claim: {text}")
    if "lock" in name.lower() and "Callable" in text:
        out.append(f"{where}.{name} is a lock callable: {text}")
    return out


def test_state_carrying_seams_take_the_handle_or_a_channel() -> None:
    """No seam that carries learning state today keeps a state Path, a LoopPaths state member or
    a lock callable; each takes the handle, a Channel, or neither. The seams: trigger_author and
    the has_work/do_work/run_lead_author/run_pitfalls seams; CorpusAuthorConfig's pending_dir,
    repo_lock_file, channel, held_report and skip_report; LeadAuthorDeps.paths and its
    queue-lock callables; BatchDisposition.apply, PitfallsDisposition.apply,
    _retire_exhausted_holds, _graveyard_dropped_rows; PendingDelivery.path, ServedMarker.claim;
    build_lead_author_deps, lead_author.run, run_under_held_queue_lock;
    _handoff.queue_lock_file, acquire_queue_lock; revert(paths=);
    serialize_queues.build_view/stamped_view, frontend/build.main; enqueue_report. CheckContext.pending no
    longer exists. The handle is opened on the entry's own paths, never re-derived from a
    worktree's (F34).

    Signature level: a parameter or field named for a state path, typed as today's path-field
    QueueChannel / ClaimedMarker, or a lock callable is a finding; each seam that does state
    I/O takes a parameter annotated with the handle (or a Channel) or named `state`. The list is
    examples (RF6): the same rule runs over every production signature and class field in the
    tree (`seam_signature_hits`). A `LoopPaths` a seam keeps for the repo trees is not a
    finding here: its state-member reads are #3's census hits.
    evals/harness.run_author (N7) keeps its own temporary root by path and is not pinned.

    Neither half can pass by seeing nothing: every seam the graph binds by name must still
    resolve (a listed seam the reshape removes outright carries nothing, but a bound one is
    reshaped, not removed): the function seams and the five record classes by import,
    trigger_author as author_drain's parameter, and run_author as a definition in
    evals/harness.py. And the tree-wide walk holds the kept modules, every one parsed."""
    _assert_the_walk_sees_the_tree()
    unresolved = _unresolved_bound_seams()
    assert not unresolved, (
        f"seams the graph binds no longer resolve (renamed past the pin?): {unresolved}")
    problems, takers = _listed_seam_problems()
    assert not problems, "seams still carry learning state:\n  " + "\n  ".join(problems)

    derived = [h for h in seam_signature_hits() if not h.module.startswith("defender/evals/")]
    assert not derived, (
        f"{len(derived)} signature(s) across the tree still carry learning state:\n  "
        + "\n  ".join(h.show() for h in derived[:40]))

    handle_words = (S.LearningState.__name__, S.Channel.__name__)
    lacking = [where for where, sig in takers if not any(
        p.name == "state" or any(w in str(p.annotation) for w in handle_words)
        for p in sig.parameters.values())]
    assert not lacking, f"seams doing state I/O that take neither the handle nor a Channel: {lacking}"


def _listed_seam_problems() -> tuple[list[str], list[tuple[str, inspect.Signature]]]:  # noqa: C901 — one pass per seam table
    """The named seams' findings, and the signatures of those that must take the handle."""
    problems: list[str] = []
    takers: list[tuple[str, inspect.Signature]] = []
    for module, qual in (*TAKES_HANDLE, *NO_STATE_PATH):
        fn = _resolve(module, qual)
        if fn is None:
            continue  # a seam the reshape removed carries nothing
        sig = inspect.signature(fn)
        for p in sig.parameters.values():
            problems += _state_field_problems(f"{module}.{qual}()", p.name, p.annotation)
        if (module, qual) in TAKES_HANDLE:
            takers.append((f"{module}.{qual}", sig))
    for module, qual in RECORDS:
        cls = _resolve(module, qual)
        if cls is None:
            continue
        for name, ann in _annotations_of(cls).items():
            problems += _state_field_problems(f"{module}.{qual}", name, ann)
        if qual == "PendingDelivery" and "path" in _annotations_of(cls):
            problems.append(f"{module}.PendingDelivery keeps .path (a delivery id instead)")
    for module, qual in GONE:
        if _resolve(module, qual) is not None:
            problems.append(f"{module}.{qual} still hands out a state lock path")
    return problems, takers


#: State-path parameter / field names unambiguous across the tree (a Path-typed or unannotated
#: one is a finding; `pending: dict` in the runtime is a homonym).
_SEAM_NAMES = frozenset(_STATE_PATH_NAMES)


@functools.cache
def seam_signature_hits() -> tuple[Touch, ...]:
    """RF6: the seam pin derived over the whole tree, not only the named list. Every production
    function parameter or class field (the learning-state module excepted) that is named for a
    state path and typed as a Path (or untyped), typed as today's path-field QueueChannel /
    ClaimedMarker, or is a lock callable field."""
    out: list[Touch] = []
    for module in production_modules():
        tree = _parsed(module)
        if module == STATE_MODULE_REL or tree is None:
            continue
        for node, chain in _walk_scoped(tree):
            pairs: list[tuple[str, ast.expr | None, str]] = []
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                args = [*node.args.posonlyargs, *node.args.args, *node.args.kwonlyargs]
                pairs = [(a.arg, a.annotation, _qualname((*chain, node))) for a in args]
            elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and chain \
                    and isinstance(chain[-1], ast.ClassDef):
                pairs = [(node.target.id, node.annotation, _qualname(chain))]
            for name, annotation, qual in pairs:
                ann = ast.unparse(annotation) if annotation is not None else ""
                field = isinstance(node, ast.AnnAssign)
                if (name in _SEAM_NAMES and (not ann or "Path" in ann)) \
                        or any(t in ann for t in _STATE_TYPES) \
                        or (field and "lock" in name.lower() and "Callable" in ann):
                    out.append(Touch(module, qual, "field" if field else "param",
                                     f"{name}: {ann}", node.lineno))
    return tuple(out)


# ---------------------------------------------------------------------------------------------
# D2: the two core functions are census words
# ---------------------------------------------------------------------------------------------


def test_move_at_and_open_lock_at_are_core_census_words(tmp_path: Path) -> None:
    """move_at and open_lock_at are module functions in defender._io beside Held, not methods on
    it. Both are words in #1133's census vocabulary (test_1133_census.IO_WRITERS or its
    successor) and in #1134's (derived from _io's exports). Held's and Bound's pinned public
    surfaces are unchanged (#1133's HELD_SURFACE / VIEW_SURFACE).

    The handle's module carries no copy of its own under either name: where it binds one, the
    binding is defender._io's function, so a census that derives its words from _io sees the
    handle's calls. That no module outside the handle calls them is #3's census. Whether the
    handle's own verbs reach them is not read from its source: the move and lock-open guards and
    controls (#20, #21, #22, #23) and #38/#39 pin the behaviour those calls give."""
    from defender import _io
    from defender.tests import _census1134 as C1134
    from defender.tests import _spec1133 as S1133
    from defender.tests import test_1133_census as T1133

    for word in sorted(CORE_WORDS):
        fn = S.core_fn(word)
        assert inspect.isfunction(fn), f"{word} must be a module function: {fn!r}"
        assert fn.__module__ == "defender._io", f"{word} must live in defender._io: {fn.__module__}"
        assert not hasattr(_io.Held, word), f"{word} must sit beside Held, not on it"
        assert not hasattr(_io.Bound, word), f"{word} must sit beside Bound, not on it"
    assert CORE_WORDS <= T1133.IO_WRITERS, (
        f"#1133's census vocabulary lacks {sorted(CORE_WORDS - T1133.IO_WRITERS)}")
    vocab_1134 = C1134.tree_of(REPO_ROOT).io_vocab
    assert vocab_1134 >= CORE_WORDS, (
        f"#1134's census vocabulary (derived from _io) lacks {sorted(CORE_WORDS - vocab_1134)}")

    held = _io.hold(tmp_path)
    try:
        assert S1133.public_names(held) == S1133.HELD_SURFACE, (
            f"Held's pinned surface moved: {sorted(S1133.public_names(held))}")
        assert S1133.public_names(held.view()) == S1133.VIEW_SURFACE, (
            f"Bound's pinned surface moved: {sorted(S1133.public_names(held.view()))}")
    finally:
        held.close()

    state = importlib.import_module(S.STATE_MODULE)
    for word in sorted(CORE_WORDS):
        bound = getattr(state, word, None)
        assert bound is None or bound is S.core_fn(word), (
            f"{S.STATE_MODULE}.{word} is a copy of its own ({bound!r}), not defender._io's: "
            "a census that derives its words from _io would not see the handle's calls")


# ---------------------------------------------------------------------------------------------
# O4: one root, resolved once per entry point
# ---------------------------------------------------------------------------------------------


def _judge_queue_dir_takers() -> list[str]:
    from defender.learning import judge as judge_mod
    from defender.learning.judge import enqueue as enqueue_mod

    fns: dict[str, Any] = {"judge.grade_episode": getattr(judge_mod, "grade_episode", None)}
    for name in dir(enqueue_mod):
        if name in ("enqueue_report", "enqueue") or name.startswith("append_rows"):
            fns[f"judge.enqueue.{name}"] = getattr(enqueue_mod, name)
    return sorted(n for n, fn in fns.items()
                  if callable(fn) and "queue_dir" in inspect.signature(fn).parameters)


def test_the_second_root_routes_are_gone() -> None:
    """None of these exist any more: config.learning_state_root, enqueue._queue_trust_root,
    _lead_spine.PENDING_DIR, _handoff.QUEUE_LOCK_FILE; markers.enqueue_for_authoring; the judge's
    queue_dir= parameter on enqueue_report/enqueue/append_rows*/grade_episode; the per-call
    loop_paths() resolutions inside judge/enqueue.py; config.findings_lock_file's docstring
    reference to persist.append_findings, if that property survives.

    A module the change deletes outright takes its names with it. The handle is the one place
    the root reaches past the entry point: `LearningState.open(paths)`."""
    present: list[str] = []
    for module, name in (
        ("defender.learning.core.config", "learning_state_root"),
        ("defender.learning.judge.enqueue", "_queue_trust_root"),
        ("defender.learning.leads._lead_spine", "PENDING_DIR"),
        ("defender.learning.leads.lead_author._handoff", "QUEUE_LOCK_FILE"),
        ("defender.learning.leads.lead_author", "QUEUE_LOCK_FILE"),
        ("defender.learning.leads.lead_author", "PENDING_DIR"),
        ("defender.learning.core.markers", "enqueue_for_authoring"),
    ):
        try:
            mod = importlib.import_module(module)
        except ModuleNotFoundError:
            continue
        if hasattr(mod, name):
            present.append(f"{module}.{name}")
    assert not present, f"second root routes still exist: {present}"

    takers = _judge_queue_dir_takers()
    assert not takers, f"the judge still takes queue_dir=: {takers}"

    enqueue_rel = "defender/learning/judge/enqueue.py"
    calls = [ast.unparse(n) for n in ast.walk(_parsed(enqueue_rel) or ast.Module([], []))
             if isinstance(n, ast.Call) and _terminal(n.func) == "loop_paths"]
    assert not calls, f"judge/enqueue.py still resolves the root per call: {calls}"

    from defender.learning.core.config import LoopPaths

    prop = getattr(LoopPaths, "findings_lock_file", None)
    doc = (prop.__doc__ or "") if prop is not None else ""
    assert "append_findings" not in doc, (
        "config.findings_lock_file's docstring still names persist.append_findings (D5)")

    params = [p for p in inspect.signature(S.LearningState.open).parameters.values()
              if p.name not in ("self", "cls")]
    assert [p.name for p in params] == ["paths"], (
        f"LearningState.open must take the entry point's paths and nothing else: {params}")


def test_the_kept_root_routes_still_resolve(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The routes the design keeps still work: config.loop_paths() resolves the root from
    DEFENDER_LEARNING_STATE_DIR at call time; LoopPaths(state_dir=...) still names a root;
    _tenant._refuse_widened_learning_state_overlap still reads DEFENDER_LEARNING_STATE_DIR
    directly and still refuses an overlapping data root (D4 "Kept").

    And the handle opened on loop_paths() holds that root: describe of a channel queue is under
    it (JF8 reading A: an absolute path string)."""
    from defender import _tenant
    from defender.learning.core import config

    root = tmp_path / "learning-state"
    root.mkdir()
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(root))
    resolved = config.loop_paths()
    assert resolved.state_root == root.resolve(), (
        f"loop_paths() did not resolve the env's root at call time: {resolved.state_root}")
    other = tmp_path / "elsewhere"
    assert config.LoopPaths(repo_root=tmp_path / "repo", state_dir=other).state_root == other, (
        "LoopPaths(state_dir=...) no longer names its root")

    data_root = tmp_path / "data"
    data_root.mkdir()
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(data_root / "t" / "learning"))
    refused = S.caught(lambda: _tenant._refuse_widened_learning_state_overlap(data_root))
    assert isinstance(refused, _tenant.TenantRefused), (
        f"an overlapping state dir was not refused: {refused!r}")
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(root))
    clear = S.caught(lambda: _tenant._refuse_widened_learning_state_overlap(data_root))
    assert clear is None, f"a disjoint state dir was refused: {clear!r}"

    state = S.LearningState.open(config.loop_paths())
    described = state.describe(S.coined("FINDINGS"))
    assert isinstance(described, str), f"describe must give a display string: {described!r}"
    assert Path(described).is_relative_to(root.resolve()), (
        f"the handle on loop_paths() does not hold the env's root: describe gave {described!r}")


# ---------------------------------------------------------------------------------------------
# O4: the root-route scan
# ---------------------------------------------------------------------------------------------

#: The names that resolve the state root.
ROUTE_NAMES = frozenset({"loop_paths", "DEFAULT_PATHS", "_env_state_dir", "learning_state_root"})

#: The entry points D4 (as revised by RF5) names, `(module, top-level qualname)`: the only places
#: a production resolution of the root may sit.
ENTRY_POINTS: dict[tuple[str, str], str] = {
    ("defender/run_common.py", "enqueue_curation"): "the run-end enqueue (E1)",
    ("defender/learning/core/drains.py", "author_drain"): "a drain entry",
    ("defender/learning/core/drains.py", "lead_author_drain"): "a drain entry",
    ("defender/learning/core/cli.py", "main"): "a drain entry: the stage runner's caller",
    ("defender/learning/branch/cli.py", "_grade"): "the judge launcher (RF5)",
    ("defender/learning/frontend/build.py", "main"): "the frontend build",
    ("defender/learning/ops/revert_lesson.py", "main"): "revert_lesson",
    ("defender/learning/leads/pitfalls_curator.py", "run_pitfalls"): "pitfalls_curator.run_pitfalls",
    ("defender/learning/author/lessons/run.py", "main"): "the by-hand lessons CLI",
    ("defender/learning/author/questioner/run.py", "main"): "the by-hand questioner CLI",
    ("defender/learning/leads/lead_author/__init__.py", "main"): "lead_author/__main__ -> main",
}
#: The allow-list, by `(module, top-level qualname)` (`*` = the whole module), with reasons.
ROUTE_ALLOW: dict[tuple[str, str], str] = {
    ("defender/learning/core/config.py", "*"): "the kept routes' own definitions (D4 Kept)",
    ("defender/_tenant.py", "_refuse_widened_learning_state_overlap"):
        "the kept overlap refusal: reads the env var directly (D4 Kept, until D11/#1186)",
    ("defender/evals/harness.py", "*"): _N7,
    ("defender/evals/harness_lead.py", "*"): _N7,
    ("defender/learning/ops/trace_lesson.py", "_default_runs_dir"):
        "N4: resolves DEFAULT_PATHS.runs_dir, the runs tree (#1166's), not a state record (G53)",
}


def scan_root_routes(module: str, tree: ast.Module) -> list[Touch]:
    """One module's root resolutions: `default` (a parameter defaulting to DEFAULT_PATHS) and
    `route` (a load of a route name, or a `LoopPaths(...)` construction)."""
    hits: list[Touch] = []
    in_defaults: set[int] = set()
    for node, chain in _walk_scoped(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            for d in [*node.args.defaults, *[k for k in node.args.kw_defaults if k is not None]]:
                if _terminal(d) == "DEFAULT_PATHS":
                    hits.append(Touch(module, _qualname((*chain, node)) if not isinstance(
                        node, ast.Lambda) else _qualname(chain), "default", ast.unparse(d),
                        node.lineno))
                    in_defaults |= {id(n) for n in ast.walk(d)}
        if id(node) in in_defaults:
            continue
        if isinstance(node, (ast.Name, ast.Attribute)) and isinstance(node.ctx, ast.Load) \
                and _terminal(node) in ROUTE_NAMES or isinstance(node, ast.Call) and _terminal(node.func) == "LoopPaths":
            hits.append(Touch(module, _qualname(chain), "route", ast.unparse(node), node.lineno))
    return hits


def route_allowed(touch: Touch) -> bool:
    top = touch.qualname.split(".")[0]
    if touch.kind == "default":
        return (touch.module, "*") in ROUTE_ALLOW
    return (touch.module, top) in ENTRY_POINTS or (touch.module, "*") in ROUTE_ALLOW or (
        touch.module, top) in ROUTE_ALLOW


@functools.cache
def root_routes() -> tuple[Touch, ...]:
    out: list[Touch] = []
    for module in production_modules():
        tree = _parsed(module)
        if tree is not None:
            out.extend(scan_root_routes(module, tree))
    return tuple(out)


def test_the_root_is_resolved_only_at_entry_points() -> None:
    """No learning-state function takes `paths: LoopPaths = DEFAULT_PATHS` as a default. Every
    production loop_paths(), DEFAULT_PATHS, LoopPaths(...) and _env_state_dir() resolution of
    the state root sits in one of the named entry points: run_common.enqueue_curation; each
    drain entry; branch/cli._grade (RF5); the frontend build; revert_lesson;
    pitfalls_curator.run_pitfalls; the lessons/run.py and questioner/run.py CLIs;
    lead_author/__main__ -> main. The kept _tenant overlap refusal and N7's evals are
    allow-listed with their reasons.

    What this scan pins is where a resolution may sit. That an entry point then hands the root
    inward only through LearningState.open(paths) (O4) is pinned elsewhere: no module outside
    the handle reads a LoopPaths state member (#3's census), and open(paths) is the handle's only
    constructor (#2); here it is only checked that open is a class-level constructor. The walk
    is checked first: it holds the kept modules and every walked module parsed."""
    _assert_the_walk_sees_the_tree()
    unexpected = [h for h in root_routes() if not route_allowed(h)]
    assert not unexpected, (
        f"{len(unexpected)} root resolution(s) outside the entry points:\n  "
        + "\n  ".join(h.show() for h in unexpected[:40])
        + (f"\n  ... and {len(unexpected) - 40} more" if len(unexpected) > 40 else ""))
    assert inspect.ismethod(getattr(S.LearningState, "open", None)), (
        "LearningState.open(paths) must be the handle's class-level constructor")


_PLANTED_ROUTES = '''
from defender.learning.core.config import DEFAULT_PATHS, LoopPaths, loop_paths


def drains_a_queue(paths: LoopPaths = DEFAULT_PATHS) -> None:
    pass


def resolves_its_own(row: dict) -> object:
    return loop_paths()


def enqueue_curation(run_dir, alert) -> object:
    return loop_paths()
'''


def test_the_root_route_scan_flags_a_planted_default() -> None:
    """The root-route scan flags a synthetic learning-state function with a
    `paths: LoopPaths = DEFAULT_PATHS` default, and a synthetic non-entry-point call of
    loop_paths(). So #10 cannot pass by seeing nothing.

    The same `loop_paths()` call inside a named entry point (run_common.enqueue_curation) is not
    flagged; placed in the learning-state module (which takes the root from open(paths) and
    never resolves it) it is."""
    planted = scan_root_routes("defender/learning/core/planted_route.py",
                               ast.parse(_PLANTED_ROUTES))
    flagged = {(h.qualname, h.kind) for h in planted if not route_allowed(h)}
    assert ("drains_a_queue", "default") in flagged, f"the planted default was missed: {flagged}"
    assert ("resolves_its_own", "route") in flagged, (
        f"the planted non-entry loop_paths() was missed: {flagged}")

    at_entry = scan_root_routes("defender/run_common.py", ast.parse(_PLANTED_ROUTES))
    entry_flags = {h.qualname for h in at_entry if not route_allowed(h)}
    assert "enqueue_curation" not in entry_flags, (
        f"a resolution at a named entry point was flagged: {entry_flags}")

    in_handle = scan_root_routes(STATE_MODULE_REL, ast.parse(_PLANTED_ROUTES))
    assert {h.qualname for h in in_handle if not route_allowed(h)} >= {"resolves_its_own"}, (
        "the learning-state module is no entry point: a resolution there must be flagged")
    assert S.LearningState.__module__ == S.STATE_MODULE, (
        f"the handle must live in {S.STATE_MODULE} (F1), where this scan treats it as no entry")
    assert _handle_source() == S.STATE_MODULE_FILE.resolve(), (
        f"the scan treats {STATE_MODULE_REL} as the handle, but it was loaded from {_handle_source()}")


# ---------------------------------------------------------------------------------------------
# D28: a removed name still imported by a lazily loaded module
# ---------------------------------------------------------------------------------------------

#: The names the design removes (O4, D5; O3's rewritten tier names the helpers), each a stale
#: import's or a stale call's target at the first tick.
REMOVED_NAMES = frozenset({
    "learning_state_root", "_queue_trust_root", "PENDING_DIR", "QUEUE_LOCK_FILE",
    "enqueue_for_authoring",
    "claim_markers", "requeue_marker", "quarantine_marker", "queue_lock", "acquire_flock",
    "flock_or_skip", "graveyard_file", "stuck_report_file", "rotate_queue_locked",
    "_pending_deliveries",
})
#: The judge functions whose `queue_dir=` parameter decision 4 removes.
_QUEUE_DIR_TAKERS = frozenset({"enqueue_report", "enqueue", "grade_episode", "append_rows",
                               "append_world_rows"})


def scan_removed_references(module: str, tree: ast.Module) -> list[Touch]:
    """Every reference to a removed name: a load, an attribute, an import (a re-export
    included), a string naming it (`getattr(m, "...")`, `__all__`, a string-loaded module's
    attribute), and a `queue_dir=` keyword handed to a judge function."""
    hits: list[Touch] = []
    for node, chain in _walk_scoped(tree):
        found: str | None = None
        if isinstance(node, ast.Name) and node.id in REMOVED_NAMES:
            found = "name"
        elif isinstance(node, ast.Attribute) and node.attr in REMOVED_NAMES:
            found = "attribute"
        elif isinstance(node, (ast.Import, ast.ImportFrom)) and any(
                a.name.split(".")[-1] in REMOVED_NAMES for a in node.names):
            found = "import"
        elif isinstance(node, ast.Constant) and isinstance(node.value, str) \
                and node.value in REMOVED_NAMES:
            found = "string"
        elif isinstance(node, ast.Call) and _terminal(node.func) in _QUEUE_DIR_TAKERS and any(
                k.arg == "queue_dir" for k in node.keywords) or isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) \
                and module.startswith("defender/learning/judge/") and any(
                a.arg == "queue_dir" for a in [*node.args.args, *node.args.kwonlyargs]):
            found = "queue_dir"
        if found is not None:
            hits.append(Touch(module, _qualname(chain), found,
                              ast.unparse(node).splitlines()[0][:160], getattr(node, "lineno", 0)))
    return hits


_PLANTED_REFERENCES = {
    "loaded-by-string": '''
import importlib


def tick():
    mod = importlib.import_module("defender.learning.core.config")
    return getattr(mod, "learning_state_root")()
''',
    "by-hand-cli": '''
import sys

if __name__ == "__main__":
    from defender.learning.core.markers import enqueue_for_authoring
    enqueue_for_authoring(sys.argv[1], None)
''',
    "package-re-export": '''
from defender.learning.leads.lead_author._handoff import QUEUE_LOCK_FILE as QUEUE_LOCK_FILE

__all__ = ["QUEUE_LOCK_FILE"]
''',
    "stale-call": '''
def grade(rows, report, state):
    from defender.learning.judge.enqueue import enqueue_report
    return enqueue_report(report, rows, queue_dir="/tmp/q")
''',
}


@pytest.mark.parametrize("where", ["tree", *_PLANTED_REFERENCES])
def test_1135_removed_name_still_imported_by_a_lazily_loaded_module(where: str) -> None:
    """No production module imports a name the design removes, whether it is loaded at tick time
    by string, is a by-hand command line, or is a package re-export: the removed names
    (learning_state_root, _queue_trust_root, the two import-frozen constants, and the helpers
    and path fields D5 and O5 drop) have no remaining reference anywhere in the production tree
    (O4, D5), so the first tick is not where a stale import first fails.

    Named: learning_state_root, _queue_trust_root, the import-frozen PENDING_DIR and
    QUEUE_LOCK_FILE, enqueue_for_authoring, the judge's queue_dir= parameter, and O3's removed
    helpers (G31's list). `tree` scans the checkout (the learning-state module excepted: its
    internals are #5's); the other rows are this negative's planted-reference positive control
    (deviation D-5): the scan flags a synthetic module that loads a removed name by string,
    imports one in a by-hand CLI, re-exports one from a package, or still passes queue_dir= to
    the judge. Removed path FIELDS (generic names like `path`) are #6's signature pin."""
    if where != "tree":
        hits = scan_removed_references(f"defender/learning/planted_{where}.py",
                                       ast.parse(_PLANTED_REFERENCES[where]))
        assert hits, f"the removed-name scan missed the planted {where} reference"
        assert S.LearningState.__module__ == S.STATE_MODULE, (
            f"the module this scan excepts must be the one that defines LearningState ({S.STATE_MODULE})")
        assert _handle_source() == S.STATE_MODULE_FILE.resolve(), (
            f"the scan excepts {STATE_MODULE_REL}, but the handle was loaded from {_handle_source()}")
        return

    _assert_the_walk_sees_the_tree()
    hits = [h for module in production_modules() if module != STATE_MODULE_REL
            for h in scan_removed_references(module, _parsed(module) or ast.Module([], []))]
    assert not hits, (
        f"{len(hits)} reference(s) to removed names in "
        f"{sorted({h.module for h in hits})}:\n  " + "\n  ".join(h.show() for h in hits[:40])
        + (f"\n  ... and {len(hits) - 40} more" if len(hits) > 40 else ""))
    reexported = sorted(n for n in REMOVED_NAMES if hasattr(S.LearningState, n))
    assert not reexported, f"the handle re-homes removed names: {reexported}"
