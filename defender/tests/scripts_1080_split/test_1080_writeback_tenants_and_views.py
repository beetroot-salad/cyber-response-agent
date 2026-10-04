"""#1080 (group `tenants`) — the write-back home, the tenants home and the two model-facing views.

SCOPE CUT (2026-10-04, human): of this group only the payload view moves (and the first-import
check covers the cut's IN modules). The case mapping, the write-back and the workspace map stay
in `scripts/`; their tests are parked with their owners
(`spec-flow/specs/parked/1080/parked_writeback_tenants_and_views.py`). The list below is the
group as it was designed.

What moves, and how each test reaches it (homes are FOUND BY SYMBOL, dF0):

  * the case-mapping format (`case_ticket.py`) — into the tenants home, a package that may import
    runtime (M-G (b)): `S.home_of("load_case_mapping")`. Its readers do not move:
    `runtime/run_tenant.py` (the record built at run start), `runtime/query_tool.py` and
    `learning/branch/estate/applier.py`.
  * the ticket write-back (`ticket_writer.py`) — `S.home_of("record_case_ticket")`. It keeps
    importing `scripts/adapters/_stub_transport` (H4 (i): a named O1 exception). `run.py`'s
    `--update-ticket` post-steps reach it through `run.main`'s `ticket_writer` seam, whose
    production default is the module itself.
  * the workspace map (`workspace_map.py`, its `__main__` dropped, M-D (a)) —
    `S.home_of("workspace_map")`; `runtime/orient.py` splices it into message zero under
    `## Workspace`, with `_(unavailable: …)_` as the fallback (G8, RG4).
  * the payload view (`gather_tools/payload_view.py`) — `S.home_of("passthrough_max_bytes")`
    (`render` and `walk` are reached as attributes of that module: `render` has six homes).

Nothing from a new home is imported at module level: a missing home is one failing test, never a
collection error.

GOLDENS ARE THE BASE. Every "as today" expectation is `goldens/tenants.json`, captured once at
80888efb by running the `_observe_*` functions below — the very code the tests run — with
`SPEC1080_AT_BASE` set to 1, so the locator resolved the base definitions. `_norm` is the ONE place a
volatile string is rewritten (the case's tmp root, the data root, this checkout's root), used by
the capture and the tests alike.

FAULTS ARE REAL INPUTS: the mapping files are real files (BOM, undecodable bytes, a link out of
the tenant folder, a directory, a 1 MiB + 1 file), the run-dir entries are real names, the
checkout copies are real directory trees at awkward paths, the environment variable is really
set. The one dependency too expensive to drive is the docker CLI, faked the way CX8 (executed)
says it can be: a `docker` executable first on the PATH the transport forks with
(`_spec1107.DockerShim`), recording every argv and answering in curl's body + status-line shape
(the transport's own contract; AP3 for `curl_refused`). The interrupted post-step is a real
SIGKILL of the real writer process, sent by a shim at the moment the store accepts the comment.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

import pytest

from defender.tests.scripts_1080_split import _spec1080 as S

GOLDEN = "tenants"

DATA_ROOT_ENV = "DEFENDER_DATA_ROOT"
PASSTHROUGH_ENV = "DEFENDER_GATHER_PASSTHROUGH_MAX_BYTES"


# ======================================================================================
# Goldens and the one normalization
# ======================================================================================


def _golden(demand: str) -> Mapping[str, Any]:
    data = S.golden(GOLDEN)
    assert demand in data, f"goldens/{GOLDEN}.json holds no entry for {demand}"
    return data[demand]


def _norm(value: Any, tmp: Path | None = None) -> Any:
    """THE normalization: inside every string of `value` (a canon record), the case's tmp root
    reads `<TMP>`, the test's data root `<DATA_ROOT>` and this checkout's root `<REPO>`. The
    capture and the tests both go through here."""
    subs: list[tuple[str, str]] = []
    if tmp is not None:
        subs.append((str(tmp), "<TMP>"))
    data_root = os.environ.get(DATA_ROOT_ENV)
    if data_root:
        subs.append((data_root, "<DATA_ROOT>"))
    subs.append((str(S.REPO_ROOT), "<REPO>"))
    subs.sort(key=lambda s: -len(s[0]))

    def fix(v: Any) -> Any:
        if isinstance(v, str):
            for old, new in subs:
                v = v.replace(old, new)
            return v
        if isinstance(v, list):
            return [fix(x) for x in v]
        if isinstance(v, dict):
            return {fix(k): fix(x) for k, x in v.items()}
        return v

    return fix(value)


def _text_digest(text: str) -> Any:
    """A long view kept small in the golden: its length, its hash and both ends."""
    if len(text) <= 2000:
        return text
    return {"len": len(text), "sha256": hashlib.sha256(text.encode("utf-8", "surrogatepass"))
            .hexdigest(), "head": text[:400], "tail": text[-200:]}


def _outcome_of(fn: Callable[..., Any], *args: Any, view: Callable[[Any], Any] = S.canon,
                **kw: Any) -> dict[str, Any]:
    """`S.outcome` with a caller-chosen view of the return value (a `CaseMapping`'s repr carries
    an address, so it is viewed through `.plain()`)."""
    try:
        value = fn(*args, **kw)
    except Exception as e:  # noqa: BLE001 — the exception IS the observed outcome
        return {"raises": type(e).__name__, "message": str(e)}
    return {"returns": view(value)}


def _children(argvs: Sequence[Sequence[str]], *, env: Mapping[str, str] | None = None,
              limit: int = 6, timeout: float = 120) -> list[subprocess.CompletedProcess[bytes]]:
    """Each argv as a fresh child of this interpreter (cwd this checkout, PYTHONPATH this
    checkout, `S.child_env`), at most `limit` at once; results in input order."""
    env = dict(S.child_env(PYTHONDONTWRITEBYTECODE="1", PYTHONUTF8="1") if env is None else env)
    results: list[subprocess.CompletedProcess[bytes] | None] = [None] * len(argvs)
    pending = list(enumerate(argvs))
    running: list[tuple[int, list[str], subprocess.Popen[bytes]]] = []
    while pending or running:
        while pending and len(running) < limit:
            i, argv = pending.pop(0)
            full = [sys.executable, *argv]
            running.append((i, full, subprocess.Popen(  # noqa: S603 — argv built by the test
                full, cwd=S.REPO_ROOT, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE)))
        i, full, proc = running.pop(0)
        out, err = proc.communicate(timeout=timeout)
        results[i] = subprocess.CompletedProcess(full, proc.returncode, out, err)
    return [r for r in results if r is not None]


# ======================================================================================
# The payload view
# ======================================================================================


def _view() -> Any:
    return S.moved_module("passthrough_max_bytes")


#: `DEFENDER_GATHER_PASSTHROUGH_MAX_BYTES` spellings; `None` is unset.
CEILING_ENV: dict[str, str | None] = {
    "unset": None,
    "empty": "",
    "zero": "0",
    "negative": "-1",
    "padded": "  4096\t\n",
    "plus_sign": "+64",
    "underscored": "1_024",
    "float": "1.5",
    "exponent": "1e3",
    "hex": "0x10",
    "non_numeric": "eight kilobytes",
    "non_ascii_digits": "٤٠٩٦",
    "oversized": "9" * 40,
    "past_the_digit_limit": "9" * 4301,
}


def _observe_ceiling(case: str, tmp: Path, mp: Any) -> dict[str, Any]:
    view = _view()
    value = CEILING_ENV[case]
    if value is None:
        mp.delenv(PASSTHROUGH_ENV, raising=False)
    else:
        mp.setenv(PASSTHROUGH_ENV, value)
    payload = json.dumps({"rows": [{"i": i, "v": "x" * 20} for i in range(40)]})
    rendered = _outcome_of(view.render, payload, None, tmp, view=_text_digest)
    return _norm({"ceiling": S.outcome(view.passthrough_max_bytes), "render": rendered}, tmp)


@pytest.mark.parametrize("case", list(CEILING_ENV))
def test_passthrough_ceiling_env_in_unusual_forms(case, tmp_path, monkeypatch):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster
    and rename; O5 where it applies). DEFENDER_GATHER_PASSTHROUGH_MAX_BYTES unset, empty, 0,
    negative, padded, float, hex, non-numeric or oversized resolves to the same ceiling as today
    through the same parser (probe PO1).

    The variable really set (or removed) in this process; the moved `passthrough_max_bytes`
    outcome and the view it governs (`render` with no explicit ceiling, over a 2 KB payload)
    against the base golden."""
    assert _observe_ceiling(case, tmp_path, monkeypatch) == _golden("s172")[case]


def _ceiling_cases() -> dict[str, tuple[str, int | None]]:
    """(payload text, explicit ceiling or None for the variable's) per case."""
    c = 64
    rows = json.dumps({"total": 3, "returned": 3, "rows": ["a" * 10, "b" * 10, "c" * 10]})
    return {
        "text_one_under": ("t" * (c - 1), c),
        "text_at": ("t" * c, c),
        "text_one_over": ("t" * (c + 1), c),
        "json_one_under": (json.dumps({"v": "j" * (c - 1 - 9)}), c),
        "json_at": (json.dumps({"v": "j" * (c - 9)}), c),
        "json_one_over": (json.dumps({"v": "j" * (c + 1 - 9)}), c),
        "envelope_at": (rows, len(rows)),
        "envelope_one_over": (rows, len(rows) - 1),
        "multibyte_across_the_cut": ("a" * 30 + "🙂é中" * 20, 40),
        "multibyte_at_the_cut_json": (json.dumps({"v": "é" * 40}, ensure_ascii=False), 40),
        "ceiling_smaller_than_a_character": ("🙂" * 4, 1),
        "ceiling_zero": ("🙂" * 4, 0),
        "ceiling_negative": ('{"a": 1}', -5),
        "through_the_variable": ("v" * 200, None),
    }


def _observe_at_ceiling(case: str, tmp: Path, mp: Any) -> dict[str, Any]:
    view = _view()
    text, ceiling = _ceiling_cases()[case]
    mp.setenv(PASSTHROUGH_ENV, "100")
    kw = {} if ceiling is None else {"ceiling": ceiling}
    return _norm({"render": _outcome_of(view.render, text, None, tmp, view=_text_digest, **kw)},
                 tmp)


@pytest.mark.parametrize("case", list(_ceiling_cases()))
def test_payload_at_the_ceiling(case, tmp_path, monkeypatch):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster
    and rename; O5 where it applies). A payload one byte under, at and one over the ceiling,
    with a multi-byte character across the cut and a ceiling smaller than one character, is
    clipped at the same boundary as today.

    The moved `render` over plain text, a JSON document and a server envelope at each side of
    the ceiling, multi-byte text cut mid-character, ceilings of one, zero and below zero, and
    once through the variable; the view against the base golden."""
    assert _observe_at_ceiling(case, tmp_path, monkeypatch) == _golden("s173")[case]


def _nested(depth: int) -> Any:
    value: Any = "leaf"
    for i in range(depth):
        value = {"k": value} if i % 2 else [value]
    return value


def _shape_cases() -> dict[str, tuple[str, int | None]]:
    """(payload text, explicit ceiling or None) per awkward shape."""
    leaf = 600
    return {
        "empty": ("", 64),
        "plain_text": ("plain words, not JSON. " * 20, 64),
        "deeply_nested": (json.dumps(_nested(60)), 64),
        "nested_past_the_parser": ("[" * 100000 + "]" * 100000, 64),  # quirk pin: base behavior, not a requirement
        "leaf_at_the_string_bound": (json.dumps({"a": "s" * leaf, "pad": "p" * 300}), 400),
        "leaf_one_over_the_string_bound": (json.dumps({"a": "s" * (leaf + 1), "pad": "p" * 300}),
                                           400),
        "invalid_utf8_as_surrogates": (
            b'{"msg": "bad \xff\xfe bytes", "rows": [1, 2, 3]}'.decode("utf-8",
                                                                     "surrogateescape"), 16),
        "escaped_lone_surrogate": ('{"msg": "\\udcff lone", "rows": [1, 2, 3]}', 16),
        "scalar_number": ("1234567890" * 10, 16),
        "scalar_string": (json.dumps("s" * 100), 16),
        "scalar_null": ("null", 2),
        "top_level_list": (json.dumps(list(range(200))), 64),
        "ten_thousand_items": (json.dumps([{"i": i, "host": f"h-{i}"} for i in range(10000)]),
                               None),
        "wide_flat_object": (json.dumps({f"field_{i}": i for i in range(300)}), 256),
        "wide_row": (json.dumps({"columns": ["a"], "values": [list(range(400))]}), 256),
    }


def _observe_shape(case: str, tmp: Path, mp: Any) -> dict[str, Any]:
    view = _view()
    text, ceiling = _shape_cases()[case]
    mp.delenv(PASSTHROUGH_ENV, raising=False)
    kw = {} if ceiling is None else {"ceiling": ceiling}
    return _norm({"render": _outcome_of(view.render, text, None, tmp, view=_text_digest, **kw)},
                 tmp)


@pytest.mark.parametrize("case", list(_shape_cases()))
def test_payload_shapes_the_view_must_not_choke_on(case, tmp_path, monkeypatch):
    """Behavior is exactly the pre-move behavior (the 10-03 scope is a pure move: wrap, cluster
    and rename; O5 where it applies). Empty, plain-text, deeply nested JSON, boundary-length
    string leaves, invalid UTF-8, scalar-top-level and ten-thousand-item payloads are viewed as
    today without a new failure.

    `render` takes text (`query_tool` hands it `json.dumps(payload)`), so invalid UTF-8 reaches
    it as the surrogate-escaped characters a lossless decode leaves; each shape through the
    moved `render` against the base golden (a long view by its length, hash and ends).

    Case `nested_past_the_parser` (the view raises `RecursionError`): quirk pin: base behavior,
    not a requirement."""
    assert _observe_shape(case, tmp_path, monkeypatch) == _golden("s174")[case]


# ======================================================================================
# s204 / s205 — fresh-process imports and module-level state
# ======================================================================================

#: One symbol per moved module (and the home pinned by the design or the demand text, if any).
#: E2 of the 2026-10-04 scope cut: the IN rows only — pricing, the query rules, the lessons
#: engine, the venv helper, the payload view and the sql engine. The OUT rows (world-view
#: naming, the case mapping, the write-back, the row writers, integrations, the renderers, the
#: exit codes, the workspace map, system naming) are parked with their owners.
FIRST_IMPORTS: tuple[tuple[str, str, str | None], ...] = (
    ("pricing", "usage_cost", S.PROVIDERS),
    ("query rules", "resolve_query_id", None),
    ("lessons engine", "cmd_tags", None),
    ("venv helper", "reexec_into_venv", None),
    ("payload view", "passthrough_max_bytes", None),
    ("sql engine", "EXIT_NO_RUNTIME", None),
)


def test_each_moved_module_imported_first_in_a_fresh_process():
    """Each moved module comes up as the first project import in a fresh interpreter, whichever
    module is chosen: no module depends on another having been imported first, and no import
    cycle among the new homes (under the 2026-10-04 scope cut: pricing, the query rules, the
    lessons engine, the venv helper, the payload view, the sql engine) makes the first-import
    order matter.

    The modules are found by symbol in the parent; each module — and each package a home sits
    in below `defender/` — is then the FIRST import of its own fresh child."""
    targets: dict[str, str] = {}
    for label, symbol, home in FIRST_IMPORTS:
        dotted = S.dotted(S.home_of(symbol, home=home))
        targets.setdefault(dotted, label)
        parts = dotted.split(".")
        for i in range(2, len(parts)):
            targets.setdefault(".".join(parts[:i]), f"package of {label}")
    names = sorted(targets)
    results = _children([["-c", "import importlib, sys; importlib.import_module(sys.argv[1])",
                          name] for name in names])
    failed = [(targets[n], n, r.stderr.decode(errors="replace")[-500:])
              for n, r in zip(names, results, strict=True) if r.returncode != 0]
    assert not failed, f"imported first, these fail: {failed}"


def _observe_state(tmp: Path, mp: Any) -> dict[str, Any]:
    """s205's payload-view cell (the 2026-10-04 cut keeps it; the capture and row-writer cells
    are parked with #1172 / #1165): the moved view rendered under three ceilings in a row."""
    view = _view()
    payload = json.dumps({"rows": [{"i": i, "v": "x" * 30} for i in range(300)]})  # ~14 KB
    renders = []
    for setting in ("48", "100000", None):
        if setting is None:
            mp.delenv(PASSTHROUGH_ENV, raising=False)
        else:
            mp.setenv(PASSTHROUGH_ENV, setting)
        renders.append(_text_digest(view.render(payload, None, tmp)))
    return _norm({"renders": renders}, tmp)


def test_module_level_state_in_a_moved_module_across_two_runs_in_one_process(tmp_path,
                                                                             monkeypatch):
    """Module-level state in a moved module (a cache, a compiled table, an installed capture)
    serves each run as it did before: a second consecutive run in the same process sees nothing
    a first run left that it did not see pre-move. The move does not turn per-run state into
    process-wide state.

    In one process: the moved payload view rendered under three ceilings in a row (the variable
    set, changed, removed — no ceiling remembered), against the base golden's `renders`. The
    other two cells (each run's own `TransportCapture`, and the row writer's sequence and repeat
    notes across two run dirs) read modules the 2026-10-04 scope cut leaves in place; they are
    parked with #1172 and #1165."""
    got = _observe_state(tmp_path, monkeypatch)
    assert got == {"renders": _golden("s205")["renders"]}


# ======================================================================================
# Shared by the capture script (the `_observe_*` functions above ARE the capture)
# ======================================================================================

#: demand -> (observer, its case names or None). The capture runs each at the base under
#: `SPEC1080_AT_BASE=1`, each case in a fresh data root and tmp dir: `observer(case, tmp, mp)`,
#: or `observer(tmp, mp)` for a demand with one case.
OBSERVERS: dict[str, tuple[Callable[..., Any], Sequence[str] | None]] = {
    "s172": (_observe_ceiling, list(CEILING_ENV)),
    "s173": (_observe_at_ceiling, list(_ceiling_cases())),
    "s174": (_observe_shape, list(_shape_cases())),
    "s205": (_observe_state, None),
}
