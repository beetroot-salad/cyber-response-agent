"""Generated net under the lint_adapter_replay_blind gate (#1385 L1): every spelling of a wall-clock
read, reached through every import style and every flow into a host-state reply, in a `def` and an
`async def`, is found at the line of the read; so is every way an adapter reads the branch point or
the run state, and every way the kit or the platform context declares one (or the kit a clock).

Each case is a synthesized `defender/` tree under `case_dir`, run through `main(["--root", ...])`
the way CI reaches the lint — the exit code and the printed `path:line:` findings are the contract,
so a lint that drops one spelling, one flow form or one declaration shape fails here by name.
"""
from __future__ import annotations

import re
import tempfile
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from _by_path import load_lint_gate

_GATE = load_lint_gate("lint_adapter_replay_blind")

_HOST_STATE = "integrations/host_state_adapter.py"
_KIT = "kit/verbs.py"
_PLATFORM = "systems/verbs.py"
_TEMPLATE = "skills/connect/examples/example_adapter.py"
#: A kit that is not itself a finding, so the scan is never the exit-2 "saw nothing" case.
_MINIMAL_KIT = "from typing import Protocol\nclass VerbContext(Protocol):\n    env: dict\n"
_FINDING = re.compile(r"^(?P<rel>[\w/.\-]+):(?P<line>\d+): ")
_DEF = {False: "def", True: "async def"}
_DEF_ID = {False: "def", True: "asyncdef"}


@pytest.fixture(scope="module")
def _cases_root(tmp_path_factory: pytest.TempPathFactory) -> Path:
    return tmp_path_factory.mktemp("replay_blind")


@pytest.fixture
def case_dir(_cases_root: Path) -> Path:
    """A fresh empty directory for one case (one `tmp_path` per generated case costs more than
    the scan it holds)."""
    return Path(tempfile.mkdtemp(dir=_cases_root))


def _tree(case_dir: Path, files: dict[str, str]) -> Path:
    root = case_dir / "defender"
    for rel, text in {_KIT: _MINIMAL_KIT, **files}.items():
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _run(root: Path, capsys: pytest.CaptureFixture[str]) -> tuple[int, dict[str, set[int]]]:
    """`(exit code, {file: lines found})` of `main(["--root", root])`."""
    code = _GATE.main(["--root", str(root)])
    found: dict[str, set[int]] = {}
    for text in capsys.readouterr().out.splitlines():
        hit = _FINDING.match(text)
        if hit:
            found.setdefault(hit["rel"], set()).add(int(hit["line"]))
    return code, found


def _line_of(lines: list[str], token: str) -> int:
    """The 1-based line of the one source line holding `token`."""
    holding = [i for i, text in enumerate(lines, 1) if token in text]
    assert len(holding) == 1, (token, lines)
    return holding[0]


# --------------------------------------------------------------------------------------------
# Host-state: clock spelling x import style x flow form x def / async def
# --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class _Spelling:
    name: str
    module: str  # the stdlib module the reader lives in
    owner: str | None  # the class holding it (`datetime.datetime.now`); None for a module function
    attr: str
    args: str = ""


_SPELLINGS = (
    _Spelling("now", "datetime", "datetime", "now"),
    _Spelling("utcnow", "datetime", "datetime", "utcnow"),
    _Spelling("datetime-today", "datetime", "datetime", "today"),
    _Spelling("date-today", "datetime", "date", "today"),
    _Spelling("time", "time", None, "time"),
    _Spelling("time_ns", "time", None, "time_ns"),
    _Spelling("gmtime", "time", None, "gmtime"),
    _Spelling("localtime", "time", None, "localtime"),
    _Spelling("ctime", "time", None, "ctime"),
    _Spelling("asctime", "time", None, "asctime"),
    _Spelling("strftime", "time", None, "strftime", args="'%Y-%m-%d'"),
)
_STYLES = ("attribute", "from-import", "aliased-module", "aliased-from", "bound-module",
           "bound-local", "bound-default", "bound-partial")


@dataclass(frozen=True)
class _Rendered:
    imports: list[str]
    module_setup: list[str]  # a name bound to the reader at module level
    local_setup: list[str]  # ... or inside the function
    expr: str  # the call that reads the clock
    at_module_level: bool  # the call may stand outside a function
    params: str = ""  # a parameter the function takes, defaulting to the reader


def _render(sp: _Spelling, style: str) -> _Rendered:
    """The source lines that reach `sp` in `style`, and the call expression that reads it."""
    module, owner, attr = sp.module, sp.owner, sp.attr
    dotted = f"{owner}.{attr}" if owner else attr
    if owner is None:
        spelled = {"attribute": f"{module}.{attr}", "aliased-module": f"tm.{attr}",
                   "from-import": attr, "aliased-from": "clk"}
        imports = {"attribute": [f"import {module}"], "aliased-module": [f"import {module} as tm"],
                   "from-import": [f"from {module} import {attr}"],
                   "aliased-from": [f"from {module} import {attr} as clk"],
                   "bound-module": [f"import {module}"], "bound-local": [f"import {module}"]}
        local_target = f"{module}.{attr}"
    else:
        spelled = {"attribute": f"{module}.{dotted}", "aliased-module": f"dt.{dotted}",
                   "from-import": dotted, "aliased-from": f"Clk.{attr}"}
        imports = {"attribute": [f"import {module}"], "aliased-module": [f"import {module} as dt"],
                   "from-import": [f"from {module} import {owner}"],
                   "aliased-from": [f"from {module} import {owner} as Clk"],
                   "bound-module": [f"import {module}"],
                   "bound-local": [f"from {module} import {owner}"]}
        local_target = dotted
    if style == "bound-module":
        return _Rendered(imports[style], [f"_read = {module}.{dotted}"], [],
                         f"_read({sp.args})", True)
    if style == "bound-default":
        return _Rendered([f"import {module}"], [], [], f"clock({sp.args})", False,
                         f", clock={module}.{dotted}")
    if style == "bound-partial":
        return _Rendered([f"import {module}", "import functools"],
                         [f"_read = functools.partial({module}.{dotted})"], [],
                         f"_read({sp.args})", True)
    if style == "bound-local":
        return _Rendered(imports[style], [], [f"read = {local_target}"], f"read({sp.args})", False)
    return _Rendered(imports[style], [], [], f"{spelled[style]}({sp.args})", True)


@dataclass(frozen=True)
class _Flow:
    name: str
    body: tuple[str, ...]  # the function body, `<E>` standing where the clock is read
    module: tuple[str, ...] = ()  # module-level lines before the function (may hold `<E>`)
    sync_only: bool = False  # `yield from` is a syntax error in an `async def`


_FLOWS = (
    _Flow("inline-return", ("return {'seen': <E>}",)),
    _Flow("assign", ("stamp = <E>", "return {'seen': stamp}")),
    _Flow("ann-assign", ("stamp: object = <E>", "return {'seen': stamp}")),
    _Flow("aug-assign", ("stamp = ''", "stamp += <E>", "return {'seen': stamp}")),
    _Flow("walrus", ("if (stamp := <E>) is None:", "    raise RuntimeError(q)",
                     "return {'seen': stamp}")),
    _Flow("yield-inline", ("yield {'seen': <E>}",)),
    _Flow("yield-name", ("stamp = <E>", "yield {'seen': stamp}")),
    _Flow("yield-from", ("yield from [<E>]",), sync_only=True),
    _Flow("chain-2", ("first = <E>", "stamp = first", "return {'seen': stamp}")),
    _Flow("chain-5", ("a0 = <E>", "a1 = a0", "a2 = a1", "a3 = [a2]", "a4 = {'k': a3}",
                      "return a4")),
    _Flow("chain-5-reversed", ("a4 = {'k': a3}", "a3 = [a2]", "a2 = a1", "a1 = a0", "a0 = <E>",
                               "return a4")),
    _Flow("loop-carried", ("prev2 = prev1 = None", "for _ in q:", "    out = prev2",
                           "    prev2 = prev1", "    prev1 = <E>", "return {'seen': out}")),
    _Flow("in-try", ("try:", "    stamp = <E>", "except OSError:", "    stamp = None",
                     "return {'seen': stamp}")),
    _Flow("in-with", ("with open(q) as fh:", "    stamp = <E>", "    fh.read()",
                      "return {'seen': stamp}")),
    _Flow("in-if", ("if q:", "    stamp = <E>", "else:", "    stamp = None",
                    "return {'seen': stamp}")),
    _Flow("in-for", ("stamp = None", "for _ in q:", "    stamp = <E>", "return {'seen': stamp}")),
    _Flow("dict-value", ("out = {}", "out['seen'] = <E>", "return out")),
    _Flow("dict-key", ("out = {}", "out[<E>] = 1", "return out")),
    _Flow("tuple-unpack", ("stamp, other = <E>, 1", "return {'seen': stamp}")),
    _Flow("attribute-target", ("holder = ctx", "holder.seen = <E>", "return holder")),
    _Flow("list-append", ("rows = []", "rows.append(<E>)", "return rows")),
    _Flow("dict-update", ("out = {}", "out.update(seen=<E>)", "return out")),
    _Flow("setdefault", ("out = {}", "out.setdefault('seen', <E>)", "return out")),
    _Flow("comprehension", ("stamps = [<E> for _ in q]", "return stamps")),
    _Flow("comprehension-source", ("stamps = [item for item in [<E>]]", "return stamps")),
    _Flow("loop-target", ("for stamp in [<E>]:", "    pass", "return {'seen': stamp}")),
    _Flow("with-target", ("with wrap(<E>) as stamp:", "    pass", "return {'seen': stamp}")),
    _Flow("module-seed", ("return {'seen': STAMP}",), module=("STAMP = <E>",)),
)

#: Reads with no path into the reply: the lint must leave them be.
_KEPT_FROM_THE_REPLY = (
    _Flow("age-check", ("age = <E> - 0", "if age > 3:", "    raise RuntimeError('stale')",
                        "return {'q': q}")),
    _Flow("kept-local", ("started = <E>", "ctx.log(started)", "return {'q': q}")),
    _Flow("deadline-loop", ("deadline = <E>", "while not ctx.env.get('UP') and deadline:",
                            "    deadline = deadline - 1", "return {'q': q}")),
)


def _host_state(sp: _Spelling, style: str, flow: _Flow, is_async: bool,
                ) -> tuple[str, int] | None:
    """`(source, line of the read)` of host-state reading `sp` through `style` into `flow`, or None
    when the combination is not code (a module-level read of a function-local alias; `yield from`
    in a coroutine)."""
    rendered = _render(sp, style)
    if (flow.module and not rendered.at_module_level) or (flow.sync_only and is_async):
        return None
    lines = [*rendered.imports, *rendered.module_setup, *flow.module,
             f"{_DEF[is_async]} query(ctx, *, q{rendered.params}):",
             *(f"    {text}" for text in (*rendered.local_setup, *flow.body))]
    line = _line_of(lines, "<E>")
    return "\n".join(lines).replace("<E>", rendered.expr) + "\n", line


def _cases(flows: tuple[_Flow, ...]) -> Iterator[pytest.ParameterSet]:
    for sp in _SPELLINGS:
        for style in _STYLES:
            for flow in flows:
                for is_async in (False, True):
                    if _host_state(sp, style, flow, is_async) is not None:
                        yield pytest.param(sp, style, flow, is_async,
                                           id=f"{sp.name}-{style}-{flow.name}-{_DEF_ID[is_async]}")


@pytest.mark.parametrize(("sp", "style", "flow", "is_async"), list(_cases(_FLOWS)))
def test_a_clock_read_that_reaches_the_host_state_reply_is_found_at_the_read(
        case_dir, capsys, sp, style, flow, is_async):
    """Whatever the clock's spelling, how the module reaches it, how its value flows to the reply
    and whether the adapter is a coroutine, the lint exits 1 with one finding: the read's line
    (L1, O7)."""
    built = _host_state(sp, style, flow, is_async)
    assert built is not None
    source, line = built
    assert _run(_tree(case_dir, {_HOST_STATE: source}), capsys) == (1, {_HOST_STATE: {line}}), source


@pytest.mark.parametrize(("sp", "style", "flow", "is_async"), list(_cases(_KEPT_FROM_THE_REPLY)))
def test_a_clock_read_that_never_reaches_the_reply_is_not_found(
        case_dir, capsys, sp, style, flow, is_async):
    """Positive control: an age check, a deadline, a logged start — a clock read with no path into
    a `return` — exits 0 in every spelling and style (L1)."""
    built = _host_state(sp, style, flow, is_async)
    assert built is not None
    assert _run(_tree(case_dir, {_HOST_STATE: built[0]}), capsys) == (0, {}), built[0]


@pytest.mark.parametrize("sp", _SPELLINGS, ids=lambda sp: sp.name)
def test_another_adapter_putting_a_clock_read_in_its_reply_is_not_found(case_dir, capsys, sp):
    """Positive control: only host-state is held to the no-time-stamp rule (L1)."""
    built = _host_state(sp, "attribute", _FLOWS[0], False)
    assert built is not None
    assert _run(_tree(case_dir, {"integrations/x_adapter.py": built[0]}), capsys) == (0, {})


_NOT_A_CLOCK = {
    "monotonic": "import time\ndef query(ctx, *, q):\n    return {'t': time.monotonic()}\n",
    "monotonic-ns-from": ("from time import monotonic_ns\ndef query(ctx, *, q):\n"
                          "    return {'t': monotonic_ns()}\n"),
    "perf-counter": "import time\ndef query(ctx, *, q):\n    return {'t': time.perf_counter()}\n",
    "strftime-with-a-time": ("import time\nWHEN = (2026, 1, 1, 0, 0, 0, 3, 1, 0)\n"
                             "def query(ctx, *, q):\n    return {'d': time.strftime('%Y', WHEN)}\n"),
    "strftime-from-with-a-time": (
        "from time import strftime\nWHEN = (2026, 1, 1, 0, 0, 0, 3, 1, 0)\n"
        "def query(ctx, *, q):\n    return {'d': strftime('%Y', WHEN)}\n"),
    "strftime-aliased-with-a-time": (
        "import time as tm\nWHEN = (2026, 1, 1, 0, 0, 0, 3, 1, 0)\n"
        "def query(ctx, *, q):\n    return {'d': tm.strftime('%Y', WHEN)}\n"),
    "gmtime-of-seconds": "import time\ndef query(ctx, *, q):\n    return {'t': time.gmtime(0)}\n",
    "ctime-of-seconds": "import time\ndef query(ctx, *, q):\n    return {'t': time.ctime(0)}\n",
    "datetime-time-attribute": ("import datetime\ndef query(ctx, *, q):\n"
                                "    return {'t': datetime.time(12, 0)}\n"),
    "datetime-time-aliased": ("import datetime as dt\ndef query(ctx, *, q):\n"
                              "    return {'t': dt.time(12, 0)}\n"),
    "datetime-time-from": ("from datetime import time\ndef query(ctx, *, q):\n"
                           "    return {'t': time(12, 0)}\n"),
    "datetime-time-from-aliased": ("from datetime import time as tod\ndef query(ctx, *, q):\n"
                                   "    return {'t': tod()}\n"),
    "datetime-literal": ("import datetime as dt\ndef query(ctx, *, q):\n"
                         "    return {'t': dt.datetime(2026, 1, 1, tzinfo=dt.UTC)}\n"),
}
_LOCAL_READERS = ("time", "time_ns", "now", "utcnow", "today", "gmtime", "localtime", "ctime",
                  "asctime", "strftime")
_NOT_A_CLOCK |= {f"local-{name}": (f"def {name}(*args):\n    return 5\n"
                                   f"def query(ctx, *, q):\n    return {{'t': {name}()}}\n")
                 for name in _LOCAL_READERS}


@pytest.mark.parametrize("src", _NOT_A_CLOCK.values(), ids=_NOT_A_CLOCK.keys())
def test_a_name_that_is_not_the_wall_clock_in_the_reply_is_not_found(case_dir, capsys, src):
    """Positive control: a monotonic timer, a render of a given time, the `datetime.time`
    constructor and a locally defined `time()` are no clock read (L1)."""
    assert _run(_tree(case_dir, {_HOST_STATE: src}), capsys) == (0, {}), src


# --------------------------------------------------------------------------------------------
# Adapters: the replay attribute x its access form x the file it is in
# --------------------------------------------------------------------------------------------

_ACCESS = {
    "attribute": ("", "ctx.{a}"),
    "getattr-two-args": ("", "getattr(ctx, '{a}')"),
    "getattr-three-args": ("", "getattr(ctx, '{a}', None)"),
    "attrgetter-module": ("import operator", "operator.attrgetter('{a}')(ctx)"),
    "attrgetter-from": ("from operator import attrgetter", "attrgetter('{a}')(ctx)"),
    "attrgetter-dotted": ("from operator import attrgetter", "attrgetter('{a}.now')(ctx)"),
}
_ADAPTER_FILES = (_HOST_STATE, "integrations/x_adapter.py", "integrations/sub/y_adapter.py",
                  _TEMPLATE)


@pytest.mark.parametrize("rel", _ADAPTER_FILES)
@pytest.mark.parametrize("is_async", [False, True], ids=["def", "asyncdef"])
@pytest.mark.parametrize("access", _ACCESS)
@pytest.mark.parametrize("attr", ["as_of", "run_state"])
def test_an_adapter_reading_a_replay_attribute_in_any_form_is_found(
        case_dir, capsys, attr, access, is_async, rel):
    """`.as_of` / `.run_state`, read by attribute, two- or three-argument `getattr` or `attrgetter`,
    in any adapter file or the template, is a finding at its line (L1, O1)."""
    header, expr = _ACCESS[access]
    lines = [*header.splitlines(), f"{_DEF[is_async]} query(ctx, *, q):",
             f"    at = {expr.format(a=attr)}", "    return {'q': q}"]
    source = "\n".join(lines) + "\n"
    assert _run(_tree(case_dir, {rel: source}), capsys) == (1, {rel: {_line_of(lines, "at = ")}})


@pytest.mark.parametrize("rel", ["tests/t_adapter.py", "integrations/tests/t_adapter.py",
                                 "systems/queries.py", "learning/replay.py"])
@pytest.mark.parametrize("access", _ACCESS)
def test_tests_and_the_platform_side_may_read_a_replay_attribute(case_dir, capsys, access, rel):
    """Positive control: the same reads in a test or on the platform side are no finding (L1)."""
    header, expr = _ACCESS[access]
    src = f"{header}\ndef query(ctx):\n    return {expr.format(a='as_of')}\n"
    adapter = "def query(ctx, *, q):\n    return {'q': q, 'base': ctx.env.get('BASE')}\n"
    files = {rel: src, "integrations/x_adapter.py": adapter}
    assert _run(_tree(case_dir, files), capsys) == (0, {})


# --------------------------------------------------------------------------------------------
# Kit and platform context: declaration form x base-class form
# --------------------------------------------------------------------------------------------

_DECLARATIONS = {
    "ann-assign": ("{n}: object", None),
    "ann-assign-valued": ("{n}: object = None", None),
    "assign": ("{n} = None", None),
    "method": ("def {n}(self): ...", None),
    "async-method": ("async def {n}(self): ...", None),
    "property": ("def {n}(self): ...", "@property"),
}
_PROTOCOL_BASES = {
    "Protocol": ("from typing import Protocol", "(Protocol)"),
    "typing.Protocol": ("import typing", "(typing.Protocol)"),
    "aliased-Protocol": ("from typing import Protocol as P", "(P)"),
    "aliased-typing": ("import typing as t", "(t.Protocol)"),
    "subscripted": ("from typing import Protocol, TypeVar\nT = TypeVar('T')", "(Protocol[T])"),
}
_BASES = {"no-base": ("", ""), **_PROTOCOL_BASES}


def _class(header: str, bases: str, name: str, decl: str, decorator: str | None,
           ) -> tuple[str, int]:
    """`(source, line of the declaration)` of a class `name` declaring `decl`."""
    lines = [*header.splitlines(), f"class {name}{bases}:", "    env: dict",
             *([f"    {decorator}"] if decorator else []), f"    {decl}  # <D>"]
    return "\n".join(lines) + "\n", _line_of(lines, "<D>")


@pytest.mark.parametrize("base", _BASES)
@pytest.mark.parametrize("form", _DECLARATIONS)
@pytest.mark.parametrize("name", ["as_of", "run_state"])
def test_any_kit_class_declaring_a_replay_input_in_any_form_is_found(
        case_dir, capsys, name, form, base):
    """A kit class — a protocol under any spelling of the base, or a plain class — declaring
    `as_of` or `run_state` as a field, assignment, method, async method or property is a finding at
    its line (L1, O1)."""
    decl, decorator = _DECLARATIONS[form]
    source, line = _class(*_BASES[base], "Surface", decl.format(n=name), decorator)
    assert _run(_tree(case_dir, {_KIT: source}), capsys) == (1, {_KIT: {line}}), source


@pytest.mark.parametrize("base", _BASES)
@pytest.mark.parametrize("form", _DECLARATIONS)
@pytest.mark.parametrize("name", ["as_of", "run_state"])
def test_the_platform_verb_context_declaring_a_replay_input_in_any_form_is_found(
        case_dir, capsys, name, form, base):
    """`systems.verbs.VerbContext`, whatever its base and however it declares `as_of` or
    `run_state`, is a finding at its line (L1, O1)."""
    decl, decorator = _DECLARATIONS[form]
    source, line = _class(*_BASES[base], "VerbContext", decl.format(n=name), decorator)
    assert _run(_tree(case_dir, {_PLATFORM: source}), capsys) == (1, {_PLATFORM: {line}}), source


@pytest.mark.parametrize("form", _DECLARATIONS)
@pytest.mark.parametrize("base", [*_PROTOCOL_BASES, "subclass-of-a-protocol"])
def test_a_kit_protocol_offering_now_in_any_form_is_found(case_dir, capsys, base, form):
    """A kit protocol — spelled any way, or a subclass of one — declaring `now` is a finding at its
    line, the kit carrying no run clock (L1, O1)."""
    decl, decorator = _DECLARATIONS[form]
    if base == "subclass-of-a-protocol":
        header = "from typing import Protocol\nclass Base(Protocol):\n    env: dict"
        source, line = _class(header, "(Base)", "Clock", decl.format(n="now"), decorator)
    else:
        source, line = _class(*_PROTOCOL_BASES[base], "Clock", decl.format(n="now"), decorator)
    assert _run(_tree(case_dir, {_KIT: source}), capsys) == (1, {_KIT: {line}}), source


# --------------------------------------------------------------------------------------------
# A scan that saw nothing proved nothing
# --------------------------------------------------------------------------------------------


def _write(root: Path, files: dict[str, str]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    for rel, text in files.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_text(text, encoding="utf-8")
    return root


@pytest.mark.parametrize("files", [
    {},
    {"tests/t_adapter.py": "x = 1\n", "integrations/tests/t_adapter.py": "x = 1\n"},
    {"systems/verbs.py": "class VerbContext:\n    env: dict\n", "learning/x.py": "x = 1\n"},
    {"integrations/README.md": "notes\n"},
], ids=["empty", "only-tests", "only-the-platform", "no-python"])
def test_a_tree_holding_no_adapters_and_no_kit_exits_2(case_dir, capsys, files):
    """No integrations and no kit means the scan saw nothing: exit 2, never a clean 0 (L1)."""
    root = _write(case_dir / "defender", files)
    assert _GATE.main(["--root", str(root)]) == 2
    assert "nothing was scanned" in capsys.readouterr().err


def test_a_root_that_does_not_exist_and_a_root_flag_without_a_path_exit_2(case_dir, capsys):
    """A `--root` pointing nowhere scans nothing (2); a bare `--root` is a usage error (2)."""
    assert _GATE.main(["--root", str(case_dir / "nowhere")]) == 2
    assert _GATE.main(["--root"]) == 2
    capsys.readouterr()


@pytest.mark.parametrize("files", [
    {"integrations/x_adapter.py": "def query(ctx, *, q):\n    return {'q': q}\n"},
    {_KIT: _MINIMAL_KIT},
], ids=["adapter-only", "kit-only"])
def test_a_tree_with_an_adapter_or_a_kit_is_scanned_and_clean(case_dir, capsys, files):
    """Positive control: either half alone is a scan, and a clean one exits 0 (L1)."""
    assert _run(_write(case_dir / "defender", files), capsys) == (0, {})
