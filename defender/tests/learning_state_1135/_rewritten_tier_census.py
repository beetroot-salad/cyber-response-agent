"""Clause #41's old-assert census: the generator of `rewritten_tier_map.yaml`. NO test functions.

#1135's O3 (revision 3 / R17) keeps two test tiers. The regression tier changes only imports and
fixtures. The REWRITTEN tier is every unit test of a helper the design removes, rewritten
against the handle's verbs WITH EACH OF ITS ASSERTS KEPT, and the old-assert -> new-assert map is
committed beside the suite (`o3_rewritten_tier_keeps_every_assert`, a clause). JF11 (auto, §7)
draws the tier PER TEST: any test edited beyond imports, fixtures and the one named arity site
(`test_drain719_locks.py:307`) has a map entry, whatever file it is in.

This module seeds the map's OLD side at phase E, against base d9128afa: it walks
`defender/tests/**/*.py` (this suite's own directory and `__pycache__` excluded) and records
every test function (module-level, or a method of a test class) whose body reaches a name the
design removes or reshapes, directly or through a helper it calls (same-file, or a function of
another test module it imports), with every `assert` in its body (and each `pytest.raises(...)`
context) as `ast.unparse` text and `new: null`. write-code-from-spec fills each `new` as it
rewrites the test, or marks the reference a pure import/fixture edit.

What reaches a removed name (`REMOVED`): a `Name` bound by an import of it, an attribute access
`<x>.<name>`, a `queue_dir=` keyword (the judge's override, decision 4), a call of
`trigger_author` / `_maybe_trigger_author` with five positional arguments or a starred argument
(the 5-positional seam), a `trigger_author=` fake written as a lambda that names any positional
parameter (it binds the seam's positional shape, so it changes when the seam takes the handle;
`lambda *a, **k: ...` names none and stays a fixture edit), or a string constant naming it
exactly (a census row pinned by name).

JF11's planted-folder class is seeded by hand (`PLANTED_FOLDER_TESTS`): a test that plants a
folder where a state record belongs to inject an ordinary fault is a rewritten-tier test with
its asserts, because under 3.1 A that plant is now a refusal (StateRefused, exit 2, no stuck
record), whatever route it reaches a removed name by.

Run from the repo root (rewrites the map in place):
    PYTHONPATH=<worktree> python defender/tests/learning_state_1135/_rewritten_tier_census.py
"""
from __future__ import annotations

import ast
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
# The repo's scope-aware name resolver (`scripts/lint/_astlib.py`, the declared owner of "what
# does this name refer to"): an import alias, a function-local shadow and an attribute chain
# all resolve through it, never through a spelling match.
sys.path.insert(0, str(REPO_ROOT / "scripts" / "lint"))
from _astlib import ModuleEnv, module_env, origin  # noqa: E402
TESTS = REPO_ROOT / "defender" / "tests"
MAP_FILE = HERE / "rewritten_tier_map.yaml"
BASE = "d9128afa"

#: The rewritten tier's helpers: design O3's list (revision 1, kept by revision 3's "What
#: stays") plus RF7's `acquire_flock_within` (revision 2.1: its composite verb replaces it).
O3_HELPERS = (
    "claim_markers", "requeue_marker", "quarantine_marker", "queue_lock", "acquire_flock",
    "acquire_flock_within", "flock_or_skip", "graveyard_file", "stuck_report_file",
    "rotate_queue_locked", "_pending_deliveries",
)
#: O4's and D5's removals (design O4 observable; D4 "Removed"; D5).
O4_D5_REMOVALS = (
    "learning_state_root", "_queue_trust_root", "PENDING_DIR", "QUEUE_LOCK_FILE",
    "enqueue_for_authoring",
)
REMOVED: dict[str, str] = {
    **{n: "O3 rewritten-tier helper" for n in O3_HELPERS},
    **{n: "O4/D5 removal" for n in O4_D5_REMOVALS},
}
QUEUE_DIR_KW = "queue_dir"
TRIGGER_CALLEES = ("trigger_author", "_maybe_trigger_author")
#: The seam keyword whose lambda fakes bind the 5-positional shape when they name a positional.
TRIGGER_SEAM_KW = "trigger_author"
LAMBDA_IMPLEMENTOR = "trigger_author (lambda implementor)"
#: JF11's planted-folder tests (92-reconciliation F4): each plants a folder where a state record
#: belongs (a lock path, the held report, the gap ledger) to inject an ordinary I/O fault. Under
#: revision 3.1 A that plant is a refusal, so each is rewritten to an ordinary-failure injector
#: at the same point and keeps every assert. Its siblings
#: `test_881_a_fault_before_the_rotation_in_the_unkeyable_retirement_is_recorded_too` and
#: `test_drain719_retire.py::test_a_failing_retirement_write_stops_the_drain_and_leaves_the_queue_intact`
#: already reach a removed name in their own body.
PLANTED_FOLDER = "planted folder (JF11): now a refusal; rewrite to an ordinary-failure injector"
PLANTED_FOLDER_TESTS: dict[tuple[str, str], str] = {
    ("defender/tests/test_drain719_guard.py",
     "test_a_plain_oserror_from_a_lock_acquisition_is_classified_systemic"): "the drain lock path",
    ("defender/tests/test_881_loop_plumbing.py",
     "test_881_a_tick_whose_gate_held_the_whole_batch_names_those_rows_when_it_sticks"):
        "the held report path",
    ("defender/tests/test_773_gap_ledger.py",
     "test_a_crash_between_the_commit_and_the_gap_ledger_write_773"): "the gap ledger path",
    ("defender/tests/test_773_gap_ledger.py",
     "test_gap_ledger_append_raises_an_io_error_773"): "the gap ledger path",
}
#: The 5-positional seam's parameter names (`drains._maybe_trigger_author`, base).
TRIGGER_SEAM_PARAMS = ("paths", "pending_file", "threshold_env", "module_name", "pending_label")

#: Design O3's volume note (revision 1) and revision 2's correction, for the cross-check.
DESIGN_VOLUME_NOTE = (
    "rev 1 O3: 21 files, largest test_903 x20, test_author_shared x15, test_952 x12, "
    "test_1134_lead_author_handle x11; rev 2: 22 files, test_1134_lead_author_handle has 2 "
    "hits, the rev-1 counts do not reproduce (claims G31, X8: 22 files, 93 refs)"
)


@dataclass
class Fn:
    """One function of a scanned module: what it reaches directly, and what it calls."""

    module: str
    qualname: str
    node: ast.FunctionDef | ast.AsyncFunctionDef
    direct: set[str] = field(default_factory=set)
    local_calls: set[str] = field(default_factory=set)
    foreign_calls: set[str] = field(default_factory=set)


@dataclass
class Module:
    rel: str
    dotted: str
    tree: ast.Module
    env: ModuleEnv | None = None
    fns: dict[str, Fn] = field(default_factory=dict)
    #: module-level names whose assigned value reaches a removed name (a census table pinning
    #: a row by text, say): name -> what it reaches.
    consts: dict[str, set[str]] = field(default_factory=dict)


def _dotted(path: Path) -> str:
    return ".".join(path.relative_to(REPO_ROOT).with_suffix("").parts)


def _scan_files() -> list[Path]:
    out = []
    for p in sorted(TESTS.rglob("*.py")):
        if "__pycache__" in p.parts or HERE in p.parents or p.parent == HERE:
            continue
        out.append(p)
    return out


def _is_trigger_call(node: ast.Call) -> bool:
    f = node.func
    name = f.id if isinstance(f, ast.Name) else f.attr if isinstance(f, ast.Attribute) else None
    if name not in TRIGGER_CALLEES:
        return False
    starred = any(isinstance(a, ast.Starred) for a in node.args)
    return starred or len(node.args) >= len(TRIGGER_SEAM_PARAMS)


def _docstrings(node: ast.AST) -> set[int]:
    """The ids of every docstring constant under `node` (a mention there is prose, not a pin)."""
    out: set[int] = set()
    for n in ast.walk(node):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)) \
                and n.body and isinstance(n.body[0], ast.Expr) \
                and isinstance(n.body[0].value, ast.Constant):
            out.add(id(n.body[0].value))
    return out


def _call_hits(n: ast.Call) -> set[str]:
    hits = {f"{QUEUE_DIR_KW}= ({ast.unparse(n.func)})" for kw in n.keywords if kw.arg == QUEUE_DIR_KW}
    if _is_trigger_call(n):
        hits.add("trigger_author (5-positional)")
    if any(kw.arg == TRIGGER_SEAM_KW and isinstance(kw.value, ast.Lambda)
           and (kw.value.args.posonlyargs or kw.value.args.args) for kw in n.keywords):
        hits.add(LAMBDA_IMPLEMENTOR)
    return hits


def _string_hits(text: str) -> set[str]:
    """A removed name pinned by text (a census row, a message) — a short string only."""
    if len(text) >= 200:
        return set()
    return {f"'{name}' (named in a string)" for name in REMOVED
            if re.search(rf"(?<!\w){re.escape(name)}(?!\w)", text)}


def _direct(fn_node: ast.AST, env: ModuleEnv) -> set[str]:
    hits: set[str] = set()
    prose = _docstrings(fn_node)
    for n in ast.walk(fn_node):
        if isinstance(n, ast.Name):
            leaf = (origin(n, env) or "").rsplit(".", 1)[-1]
            if leaf in REMOVED:
                hits.add(leaf)
        elif isinstance(n, ast.Attribute) and n.attr in REMOVED:
            hits.add(n.attr)
        elif isinstance(n, ast.Call):
            hits |= _call_hits(n)
        elif isinstance(n, ast.Constant) and isinstance(n.value, str) and id(n) not in prose:
            hits |= _string_hits(n.value)
    return hits


def _calls(fn_node: ast.AST, module: Module, local_names: set[str]) -> tuple[set[str], set[str]]:
    """(same-file defs it references, dotted origins of imported names it references)."""
    assert module.env is not None
    local: set[str] = set()
    foreign: set[str] = set()
    for n in ast.walk(fn_node):
        if isinstance(n, ast.Name) and n.id in local_names:
            local.add(n.id)
        elif isinstance(n, (ast.Name, ast.Attribute)):
            resolved = origin(n, module.env)
            if resolved:
                foreign.add(resolved)
    if isinstance(fn_node, (ast.FunctionDef, ast.AsyncFunctionDef)):
        # A pytest fixture reached by parameter name.
        for a in fn_node.args.args:
            if a.arg in local_names:
                local.add(a.arg)
    return local, foreign


def _defs(tree: ast.Module) -> list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]]:
    """Module-level functions and class methods, by qualname."""
    defs: list[tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]] = []
    for node in tree.body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            defs.append((node.name, node))
        elif isinstance(node, ast.ClassDef):
            defs += [(f"{node.name}.{sub.name}", sub) for sub in node.body
                     if isinstance(sub, (ast.FunctionDef, ast.AsyncFunctionDef))]
    return defs


def _consts(tree: ast.Module, env: ModuleEnv) -> dict[str, set[str]]:
    """Module-level names whose assigned value reaches a removed name."""
    out: dict[str, set[str]] = {}
    for node in tree.body:
        if not isinstance(node, (ast.Assign, ast.AnnAssign)) or node.value is None:
            continue
        hits = _direct(node.value, env)
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
        for t in targets:
            if isinstance(t, ast.Name) and hits:
                out.setdefault(t.id, set()).update(hits)
    return out


def _load(path: Path) -> Module:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    m = Module(rel=str(path.relative_to(REPO_ROOT)), dotted=_dotted(path), tree=tree)
    m.env = module_env(tree)
    defs = _defs(tree)
    m.consts = _consts(tree, m.env)
    local_names = {q.split(".")[0] for q, _ in defs} | {q for q, _ in defs}
    for qual, node in defs:
        fn = Fn(module=m.dotted, qualname=qual, node=node, direct=_direct(node, m.env))
        for n in ast.walk(node):
            if isinstance(n, ast.Name) and n.id in m.consts:
                fn.direct.update(f"{r} via {n.id}" for r in m.consts[n.id])
        fn.local_calls, fn.foreign_calls = _calls(node, m, local_names - {qual})
        m.fns[qual] = fn
    return m


def _resolve(dotted: str, importer: Module, modules: dict[str, Module]) -> tuple[Module, str] | None:
    """A test-tree function an imported name resolves to: `(its module, its qualname)`.

    The origin is a full dotted name (`defender.tests._drain719.graveyard`) or a bare sibling
    one (`_drain719.graveyard`, from `import _drain719 as h` under pytest's rootdir import)."""
    parts = dotted.split(".")
    pkg = importer.dotted.split(".")[:-1]
    for cut in range(len(parts) - 1, 0, -1):
        mod, rest = ".".join(parts[:cut]), parts[cut:]
        for candidate in (mod, ".".join([*pkg, mod]), f"defender.tests.{mod}"):
            target = modules.get(candidate)
            if target is not None and rest[0] in {q.split(".")[0] for q in target.fns}:
                return target, rest[0]
    return None


def _reach(modules: dict[str, Module], *, foreign: bool = True) -> dict[tuple[str, str], set[str]]:
    """Fixed point: (module, qualname) -> the removed names it reaches, labelled by route.
    `foreign=False` follows same-file calls only."""
    reach: dict[tuple[str, str], set[str]] = {
        (m.dotted, q): set(f.direct) for m in modules.values() for q, f in m.fns.items()
    }
    changed = True
    while changed:
        changed = False
        for m in modules.values():
            for q, f in m.fns.items():
                got = reach[(m.dotted, q)]
                before = len(got)
                got |= _step(m, f, reach, modules if foreign else {})
                changed = changed or len(got) != before
    return reach


def _members(m: Module, name: str) -> list[str]:
    """`name` and, for a class, its methods."""
    return [name, *[k for k in m.fns if k.startswith(name + ".")]]


def _step(m: Module, f: Fn, reach: dict[tuple[str, str], set[str]],
          modules: dict[str, Module]) -> set[str]:
    """What `f` reaches through one call: same-file always, other test modules when given."""
    got: set[str] = set()
    for callee in f.local_calls:
        for cq in _members(m, callee):
            got |= {r if " via " in r else f"{r} via {cq}" for r in reach.get((m.dotted, cq), ())}
    for dotted in f.foreign_calls if modules else ():
        found = _resolve(dotted, m, modules)
        if found is None:
            continue
        target, name = found
        for cq in _members(target, name):
            got |= {f"{r.split(' via ')[0]} via {target.rel.split('/')[-1][:-3]}.{cq}"
                    for r in reach.get((target.dotted, cq), ())}
    return got


def _asserts(node: ast.AST) -> list[str]:
    out: list[str] = []
    for n in ast.walk(node):
        if isinstance(n, ast.Assert):
            out.append(ast.unparse(n))
        elif isinstance(n, ast.withitem):
            ctx = n.context_expr
            if isinstance(ctx, ast.Call) and ast.unparse(ctx.func).endswith("pytest.raises"):
                out.append(f"with {ast.unparse(ctx)}")
        elif isinstance(n, ast.Call) and ast.unparse(n.func) == "pytest.raises" and n.args \
                and len(n.args) > 1:
            out.append(ast.unparse(n))  # the callable form: pytest.raises(E, fn, ...)
    return out


def _is_test(qual: str) -> bool:
    parts = qual.split(".")
    if len(parts) == 1:
        return parts[0].startswith("test")
    return parts[0].startswith("Test") and parts[-1].startswith("test")


def _seam_implementors(m: Module) -> list[str]:
    out = []
    for q, f in m.fns.items():
        params = [a.arg for a in f.node.args.args if a.arg != "self"]
        if tuple(params[: len(TRIGGER_SEAM_PARAMS)]) == TRIGGER_SEAM_PARAMS:
            out.append(q)
    return out


def _q(s: object) -> str:
    """A YAML scalar: JSON's double-quoted string is valid YAML."""
    return "null" if s is None else json.dumps(s, ensure_ascii=False)


def _o3_ref_counts() -> dict[str, int]:
    """G31's own probe re-run: whole-word O3-helper references per test file (rev 1's list)."""
    rx = re.compile(r"\b(" + "|".join(n for n in O3_HELPERS if n != "acquire_flock_within") + r")\b")
    out = {}
    for p in _scan_files():
        n = len(rx.findall(p.read_text(encoding="utf-8")))
        if n:
            out[str(p.relative_to(REPO_ROOT))] = n
    return out


def _classify(modules: dict[str, Module]) -> tuple[list, list, list]:
    """(tests reaching a removed name in-file, tests reaching one only via a shared test module,
    non-test helpers reaching one), each in stable file/definition order."""
    reach = _reach(modules)
    local = _reach(modules, foreign=False)
    tests: list[tuple[str, str, list[str], list[str]]] = []
    shared: list[tuple[str, str, list[str]]] = []
    helpers: list[tuple[str, str, list[str], list[str]]] = []
    for m in sorted(modules.values(), key=lambda x: x.rel):
        for q, f in m.fns.items():
            got = sorted(reach[(m.dotted, q)])
            planted = PLANTED_FOLDER_TESTS.get((m.rel, q))
            if planted is not None:
                tests.append((m.rel, q, [*got, f"{PLANTED_FOLDER} ({planted})"], _asserts(f.node)))
                continue
            if not got:
                continue
            if not (_is_test(q) and not m.rel.split("/")[-1].startswith("_")):
                helpers.append((m.rel, q, got, _asserts(f.node)))
            elif local[(m.dotted, q)]:
                tests.append((m.rel, q, sorted(local[(m.dotted, q)]), _asserts(f.node)))
            else:
                shared.append((m.rel, q, got))
    return tests, shared, helpers


def build() -> str:
    modules = {m.dotted: m for m in (_load(p) for p in _scan_files())}
    tests, shared, helpers = _classify(modules)
    seams = [(m.rel, q) for m in sorted(modules.values(), key=lambda x: x.rel)
             for q in _seam_implementors(m)]
    files = sorted({t[0] for t in tests})
    n_asserts = sum(len(t[3]) for t in tests)
    refs = _o3_ref_counts()
    per_file_tests = {f: sum(1 for t in tests if t[0] == f) for f in files}

    lines = [
        "# rewritten_tier_map.yaml — clause #41's old-assert -> new-assert map",
        "# (o3_rewritten_tier_keeps_every_assert; spec_graph_1135-learning-state-handle.yaml).",
        "#",
        "# WHAT: every test (per test, JF11 — never per file) that reaches a name #1135 removes or",
        "# reshapes, with each of its asserts. The OLD side was seeded at phase E against base",
        f"# {BASE}; every `new` is null. write-code-from-spec fills each `new` as it rewrites the",
        "# test against the handle's verbs, KEEPING EACH ASSERT (an assert with no successor is a",
        "# dropped assert, which the clause forbids), or marks the entry `fixture-only` when the",
        "# test's only change is an import or a fixture (a built state root in place of queue_dir=",
        "# or a bare path) — those stay in the regression tier.",
        "#",
        "# TIERS (JF11): a test edited beyond imports, fixtures and the ONE named arity site",
        "# (test_drain719_locks.py:307, the trigger_author lambda) is a rewritten-tier test and",
        "# keeps a map entry here, whatever file it is in. A planted-folder test whose plant is now",
        "# a refusal (StateRefused, exit 2, no stuck record) keeps its guard property by switching",
        "# to an ordinary-failure injector at the same point (#41's outcome; JF11's D22 reading).",
        "# Those are seeded by hand (`PLANTED_FOLDER_TESTS` in the generator) and carry a",
        "# `planted folder (JF11)` reach tag, whatever route they reach a removed name by.",
        "#",
        "# REGENERATE (old side only; it overwrites this file, so carry filled `new` values over):",
        "#   PYTHONPATH=<worktree> python defender/tests/learning_state_1135/_rewritten_tier_census.py",
        "#",
        "# `tests` reach a removed name in their own body or through a SAME-FILE helper (or",
        "# fixture); `reaches` names the name and its route (`X via helper`). A same-file route",
        "# may be a fixture (a fixture-only edit) or an assert helper: the implementer decides per",
        "# test. A `'X' (named in a string)` hit is a census row or message pinning the name by",
        "# text. `via_shared_helpers_only` tests reach one only through another test module's",
        "# helper (listed without asserts). `helpers` are the non-test functions that reach one.",
        "# `seam_implementors` implement the 5-positional trigger_author seam; every test that",
        "# injects one changes with the seam (O5), as a harness edit. A test that injects the seam",
        "# as a lambda naming any positional parameter is in `tests` itself",
        "# (`trigger_author (lambda implementor)`); `lambda *a, **k: ...` binds no shape.",
        "summary:",
        f"  base: {_q(BASE)}",
        f"  tests: {len(tests)}",
        f"  files: {len(files)}",
        f"  asserts: {n_asserts}",
        f"  via_shared_helpers_only: {len(shared)}",
        f"  helpers: {len(helpers)}",
        f"  seam_implementors: {len(seams)}",
        "  removed_names:",
        *[f"    {_q(n)}: {_q(k)}" for n, k in REMOVED.items()],
        f"    {_q(QUEUE_DIR_KW + '=')}: {_q('decision 4 removal (the judge override keyword)')}",
        f"    {_q('trigger_author (5-positional)')}: {_q('O3 rewritten-tier seam (O5 reshape)')}",
        f"    {_q(LAMBDA_IMPLEMENTOR)}: {_q('a lambda fake that binds the seam positionally (O5)')}",
        f"    {_q('planted folder (JF11)')}: {_q('seeded by hand: the plant is now a refusal')}",
        f"  planted_folder_tests: {len(PLANTED_FOLDER_TESTS)}",
        f"  design_volume_note: {_q(DESIGN_VOLUME_NOTE)}",
        "  o3_helper_refs_per_file:   # G31's probe re-run: whole-word refs of rev 1's O3 list",
        f"    total_files: {len(refs)}",
        f"    total_refs: {sum(refs.values())}",
        *[f"    {_q(f)}: {n}" for f, n in sorted(refs.items(), key=lambda kv: (-kv[1], kv[0]))],
        "  tests_per_file:",
        *[f"    {_q(f)}: {n}" for f, n in sorted(per_file_tests.items(), key=lambda kv: (-kv[1], kv[0]))],
        "tests:",
    ]
    for rel, q, got, asserts in tests:
        lines += [f"  - file: {_q(rel)}", f"    test: {_q(q)}", "    reaches:"]
        lines += [f"      - {_q(r)}" for r in got]
        if asserts:
            lines.append("    asserts:")
            for a in asserts:
                lines += [f"      - old: {_q(a)}", "        new: null"]
        else:
            lines.append("    asserts: []   # no assert in its own body: it asserts through a helper")
    lines += [
        "via_shared_helpers_only:   # reach a removed name ONLY through a shared test module's helper:",
        "  # the helper is harness (a fixture edit); the test is regression tier unless its own body",
        "  # changes, and then it moves to `tests` with its asserts (JF11).",
    ]
    for rel, q, got in shared:
        lines.append(f"  - {{file: {_q(rel)}, test: {_q(q)}, reaches: [{', '.join(_q(r) for r in got)}]}}")
    lines.append("helpers:")
    for rel, q, got, asserts in helpers:
        lines += [f"  - file: {_q(rel)}", f"    function: {_q(q)}", "    reaches:"]
        lines += [f"      - {_q(r)}" for r in got]
        lines.append(f"    asserts: {len(asserts)}")
    lines.append("seam_implementors:")
    lines += [f"  - {{file: {_q(rel)}, qualname: {_q(q)}}}" for rel, q in seams]
    return "\n".join(lines) + "\n"


def main() -> int:
    MAP_FILE.write_text(build(), encoding="utf-8")
    print(f"wrote {MAP_FILE.relative_to(REPO_ROOT)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
