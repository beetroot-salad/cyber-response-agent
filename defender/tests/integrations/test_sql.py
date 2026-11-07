"""The defender-sql shim: aggregation over a stdin payload exposed as table `data`, and a sealed sandbox (no file read/write, no re-enabling access). Skipped without duckdb."""
from __future__ import annotations

import importlib.util
import io
import json
import types

from defender.tests.support.shared.contracts._by_path import DEFENDER, load_module

import pytest

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("duckdb") is None,
    reason="duckdb isn't installed (it lives in the `runtime` extra, not dev/CI)",
)

defender_sql = load_module(DEFENDER / "investigation" / "sql_engine" / "sql.py", name="defender_sql")


def _run_full(monkeypatch, capsys, payload, query: str,
              *declared: str) -> tuple[int, str, str]:
    """`declared` is the (rows, names) pair of `--rows`/`--names`, or nothing."""
    data = payload.encode() if isinstance(payload, str) else payload
    fake_stdin = types.SimpleNamespace(buffer=io.BytesIO(data))
    monkeypatch.setattr("sys.stdin", fake_stdin)
    code = defender_sql._run(query, *declared)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _run(monkeypatch, capsys, payload, query: str) -> tuple[int, str]:
    code, out, _err = _run_full(monkeypatch, capsys, payload, query)
    return code, out


_PAYLOAD = json.dumps({
    "index": "logs-*", "total": 4, "returned": 4, "truncated": False,
    "hits": [
        {"user": "root", "src_ip": "203.0.113.4"},
        {"user": "root", "src_ip": "203.0.113.4"},
        {"user": "root", "src_ip": "203.0.113.9"},
        {"user": "sre.alice", "src_ip": "10.0.0.5"},
    ],
})


def test_aggregates_over_the_payload(monkeypatch, capsys):
    code, out = _run(
        monkeypatch, capsys, _PAYLOAD,
        "SELECT h.user AS user, count(*) c, count(DISTINCT h.src_ip) ips "
        "FROM (SELECT unnest(hits) h FROM data) GROUP BY user ORDER BY c DESC",
    )
    assert code == defender_sql.EXIT_OK
    assert json.loads(out) == [
        {"user": "root", "c": 3, "ips": 2},
        {"user": "sre.alice", "c": 1, "ips": 1},
    ]


def test_aggregates_ndjson(monkeypatch, capsys):
    code, out = _run(
        monkeypatch, capsys, '{"u":"a"}\n{"u":"b"}\n{"u":"a"}\n',
        "SELECT u, count(*) c FROM data GROUP BY u ORDER BY u",
    )
    assert code == defender_sql.EXIT_OK
    assert json.loads(out) == [{"u": "a", "c": 2}, {"u": "b", "c": 1}]


_ECS_PAYLOAD = json.dumps({
    "index": "logs-*", "total": 1, "returned": 1, "truncated": False,
    "hits": [
        {
            "user": {"name": "sre.alice"},
            "process": {"name": "nc"},
            "host": {"name": "web-04"},
            "agent": {"name": "wazuh-agent-2"},
        },
    ],
})


@pytest.mark.parametrize(("case", "sql", "rows", "notes", "absent"), [
    ("two-way-collision",
     "SELECT h.user.name, h.process.name FROM (SELECT unnest(hits) h FROM data)",
     [{"name": "sre.alice", "name_1": "nc"}],
     ["name -> name_1"], []),

    ("three-way-collision-renames-stably",
     "SELECT h.user.name, h.process.name, h.host.name "
     "FROM (SELECT unnest(hits) h FROM data)",
     [{"name": "sre.alice", "name_1": "nc", "name_2": "web-04"}],
     ["name -> name_1", "name -> name_2"], []),

    # The control: aliased projections do not collide, so nothing is renamed and the note is
    # ABSENT — without this row, an implementation that renamed unconditionally would pass.
    ("unique-columns-emit-no-note",
     "SELECT h.user.name AS user_name, h.process.name AS process_name "
     "FROM (SELECT unnest(hits) h FROM data)",
     [{"user_name": "sre.alice", "process_name": "nc"}],
     [], ["renamed"]),
], ids=lambda v: v if isinstance(v, str) and len(v) < 50 and "SELECT" not in v else "")
def test_colliding_output_columns_all_survive_and_are_reported(
    monkeypatch, capsys, case, sql, rows, notes, absent
):
    """A projection whose leaf names collide keeps EVERY value, under a deterministic
    `_1`/`_2` suffix, and says on stderr what it renamed."""
    code, out, err = _run_full(monkeypatch, capsys, _ECS_PAYLOAD, sql)
    assert code == defender_sql.EXIT_OK
    assert json.loads(out) == rows
    for note in notes:
        assert note in err
    for fragment in absent:
        assert fragment not in err


def test_rename_does_not_collide_with_a_literal_alias_of_the_same_name():
    assert defender_sql._disambiguate_columns(["name", "name_1", "name"]) == (
        ["name", "name_1", "name_2"], ["name -> name_2"])
    assert defender_sql._disambiguate_columns(["name", "name", "name_1"]) == (
        ["name", "name_2", "name_1"], ["name -> name_2"])
    assert defender_sql._disambiguate_columns(["name", "name", "name", "name_1", "name_2"]) == (
        ["name", "name_3", "name_4", "name_1", "name_2"],
        ["name -> name_3", "name -> name_4"])
    assert defender_sql._disambiguate_columns(["a", "b"]) == (["a", "b"], [])


def test_bad_sql_is_query_error(monkeypatch, capsys):
    code, out = _run(monkeypatch, capsys, _PAYLOAD, "SELECT no_such_col FROM data")
    assert code == defender_sql.EXIT_QUERY_ERROR
    assert out == ""


def test_utf8_payload_round_trips(monkeypatch, capsys):
    code, out = _run(
        monkeypatch, capsys, '{"u":"André"}\n{"u":"André"}\n',
        "SELECT u, count(*) c FROM data GROUP BY u",
    )
    assert code == defender_sql.EXIT_OK
    assert json.loads(out) == [{"u": "André", "c": 2}]


@pytest.mark.parametrize("payload", ["   ", b'{"u":"a\xff b"}\n'], ids=["empty_stdin", "non_utf8_payload"])
def test_an_unreadable_payload_is_a_clean_input_error(monkeypatch, capsys, payload):
    code, out = _run(monkeypatch, capsys, payload, "SELECT 1")
    assert code == defender_sql.EXIT_INPUT_ERROR
    assert out == ""


@pytest.mark.parametrize("declared", [False, True], ids=["undeclared", "declared"])
def test_binary_garbage_is_a_clean_input_error(monkeypatch, capsys, declared):
    """Bytes that are no text at all (a UTF-16 BOM, NUL, a stray continuation byte) are
    refused as not-JSON, with or without --rows/--names, never answered or crashed on."""
    flags = ("values", "columns") if declared else ()
    code, out, err = _run_full(monkeypatch, capsys, b"\xff\xfe\x00\x01garbage\x80",
                               "SELECT count(*) FROM data", *flags)
    assert code == defender_sql.EXIT_INPUT_ERROR
    assert out == ""
    assert err.startswith("defender-sql: stdin is not "), err


def test_non_finite_floats_serialize_as_null(monkeypatch, capsys):
    code, out = _run(
        monkeypatch, capsys, '{"hits":1,"total":0}',
        "SELECT hits::DOUBLE / total::DOUBLE AS ratio FROM data",
    )
    assert code == defender_sql.EXIT_OK
    assert "Infinity" not in out
    assert "NaN" not in out
    assert json.loads(out) == [{"ratio": None}]


def test_tmpdir_with_quote_does_not_break_materialization(monkeypatch, capsys, tmp_path):
    qdir = tmp_path / "has'quote"
    qdir.mkdir()
    monkeypatch.setattr("tempfile.tempdir", str(qdir))
    code, out = _run(monkeypatch, capsys, '{"u":"x"}\n{"u":"y"}\n',
                     "SELECT count(*) c FROM data")
    assert code == defender_sql.EXIT_OK
    assert json.loads(out) == [{"c": 2}]


@pytest.mark.parametrize("hostile", [
    "SELECT * FROM read_csv('/etc/hostname')",
    "SELECT * FROM read_json_auto('/workspace/x/ground_truth.json')",
    "ATTACH '/etc/hostname' AS e",
    "SET enable_external_access=true",
])
def test_sandbox_blocks_filesystem_and_unlock(monkeypatch, capsys, tmp_path, hostile):
    code, out = _run(monkeypatch, capsys, _PAYLOAD, hostile)
    assert code == defender_sql.EXIT_QUERY_ERROR
    assert out == ""


def test_sandbox_blocks_file_write(monkeypatch, capsys, tmp_path):
    target = tmp_path / "exfil.csv"
    code, _ = _run(monkeypatch, capsys, _PAYLOAD, f"COPY (SELECT 1 x) TO '{target}'")
    assert code == defender_sql.EXIT_QUERY_ERROR
    assert not target.exists()


# ---- #1421: the tool holds itself under the box's cap, so size failures are refusals ---------
# Each runs the tool's `main()` as a process, since the limit is set there and a refusal exits
# at once. Faults are injected under it by `_FAULTING_MAIN`, a test-owned wrapper.

import contextlib  # noqa: E402
import os  # noqa: E402
import resource  # noqa: E402
import signal  # noqa: E402
import subprocess  # noqa: E402
import sys  # noqa: E402
import threading  # noqa: E402
import time  # noqa: E402
from pathlib import Path  # noqa: E402

from defender.tests.support.integrations._defender_sql import (  # noqa: E402
    SQL_ARGV, SQL_PY, run_sql_py, sql_env,
)

PAYLOAD_MAX = 64 << 20
RESULT_BUDGET = 32 << 20
DECLARED = ("--rows", "values", "--names", "columns")
ROWS = '{"columns":["a","b"],"values":[[1,2],[3,4]]}'
FLAT = '{"a":1,"b":"x"}\n{"a":2,"b":"y"}\n'

_FAULTING_MAIN = '''\
import errno, importlib.util, json, os, resource, signal, sys, tempfile
import duckdb

where, _, kind = os.environ["FAULT"].partition(":")


def make():
    if kind == "memory":
        return MemoryError()
    if kind == "oom":
        return duckdb.OutOfMemoryException("Out of Memory Error: injected")
    return RuntimeError("injected")  # the control: not a memory error


class Conn:
    def __init__(self, con):
        self._con = con

    def execute(self, sql, *a, **k):
        # The query fault fires only on the user's statement, not on a describe wrapped around it.
        hit = sql.lstrip().startswith(where) if where == "SELECT 41" else where in sql
        if where not in ("fetch", "none") and hit:
            raise make()
        done = self._con.execute(sql, *a, **k)
        log_path = os.environ.get("RLIMIT_LOG")
        if log_path and not os.path.exists(log_path):  # the first statement: what covers the load
            with open(log_path, "w") as log:
                log.write(json.dumps(resource.getrlimit(resource.RLIMIT_AS)))
        return self if done is self._con else done

    def fetchmany(self, *a, **k):
        if where == "fetch":
            raise make()
        return self._con.fetchmany(*a, **k)

    def __getattr__(self, name):
        return getattr(self._con, name)


real_connect = duckdb.connect
duckdb.connect = lambda *a, **k: Conn(real_connect(*a, **k))
if where == "parse":
    def refuse(*a, **k):
        raise make()
    json.loads = refuse
if where.startswith("scratch-full"):
    # Any write-open of a path under the tool's scratch directory lands on /dev/full, whatever the
    # file is called, and is logged so a test can tell the fault was reached.
    import builtins
    real_mkdtemp, real_open, real_os_open = tempfile.mkdtemp, builtins.open, os.open
    scratch_dirs = []

    def tracked_mkdtemp(*a, **k):
        scratch_dirs.append(real_mkdtemp(*a, **k))
        return scratch_dirs[-1]

    def in_scratch(path):
        return isinstance(path, (str, os.PathLike)) and any(str(path).startswith(d) for d in scratch_dirs)

    def note():
        with real_open(os.environ["FULL_HITS"], "a") as hits:
            hits.write("hit")

    def full_open(file, mode="r", *a, **k):
        if in_scratch(file) and any(c in mode for c in "wax+"):
            note()
            return real_open("/dev/full", mode, *a, **k)
        return real_open(file, mode, *a, **k)

    def full_os_open(path, flags, *a, **k):
        if in_scratch(path) and flags & (os.O_WRONLY | os.O_RDWR):
            note()
            return real_os_open("/dev/full", flags & ~os.O_CREAT & ~os.O_EXCL, *a, **k)
        return real_os_open(path, flags, *a, **k)

    tempfile.mkdtemp, builtins.open, os.open = tracked_mkdtemp, full_open, full_os_open
if where == "scratch-fsize":
    signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
    resource.setrlimit(resource.RLIMIT_FSIZE, (1 << 20, 1 << 20))
if "HARD_AS" in os.environ:
    hard = int(os.environ["HARD_AS"])
    resource.setrlimit(resource.RLIMIT_AS, (hard, hard))

spec = importlib.util.spec_from_file_location("sql_under_test", os.environ["SQL_PY"])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
sys.argv = ["defender-sql", *sys.argv[1:]]
raise SystemExit(module.main())
'''


def _faulted(tmp_path: Path, fault: str, *args: str, stdin: str = FLAT, extra: dict | None = None):
    """The tool's `main()` with `fault` ("<where in the statement text>:<memory|oom|generic>")
    raised in the connection; the scratch parent is `tmp_path/scratch`, listed after."""
    scratch = tmp_path / "scratch"
    scratch.mkdir(parents=True, exist_ok=True)
    script = tmp_path / "faulting_main.py"
    script.write_text(_FAULTING_MAIN, encoding="utf-8")
    env = sql_env({**os.environ, "FAULT": fault, "SQL_PY": str(SQL_PY), "TMPDIR": str(scratch),
                   **(extra or {})})
    res = subprocess.run([sys.executable, "-P", str(script), *args], input=stdin, text=True,
                         capture_output=True, env=env, timeout=120)
    res.leftover = sorted(p.name for p in scratch.iterdir())
    return res


def _is_size_refusal(res, *, room: tuple[str, ...] = ("memory", "room")) -> str:
    """P5 at the box boundary, with the exit pinned (the memory error was injected): the one
    reason line, fixed-length, naming memory or room. Returns it."""
    assert res.returncode == defender_sql.EXIT_INPUT_ERROR, (res.returncode, res.stderr[-300:])
    assert res.stdout == "", "a size failure is never an observation (P2)"
    assert "Traceback" not in res.stderr, res.stderr[-400:]
    lines = [line for line in res.stderr.splitlines() if line.strip()]
    assert len(lines) == 1, res.stderr[-400:]
    assert len(res.stderr.strip()) <= 160, f"P1: the digest keeps 160 characters: {res.stderr!r}"
    assert any(word in lines[0].lower() for word in room), lines[0]
    assert "not valid JSON" not in res.stderr
    assert "could not be loaded" not in res.stderr
    return res.stderr


#: stage -> (fault location in the statement or parse, tool arguments, stdin, query)
STAGES = {
    "load": ("read_json", (), FLAT),
    "load-declared": ("read_json", DECLARED, ROWS),
    "parse": ("parse", (), ROWS),
    "describe": ("DESCRIBE data", (), FLAT),
    "arrow": ("json_serialize_sql", (), FLAT),
    "truncation": ("SELECT truncated FROM data", (), '{"truncated":false,"a":1}\n'),
    "query": ("SELECT 41", (), FLAT),
    "fetch": ("fetch", (), FLAT),
}
_QUERY = {"arrow": "SELECT (CAST(a AS JSON)->>'$') AS v FROM data", "query": "SELECT 41 + 1 AS x"}


def _stage(tmp_path, stage: str, kind: str):
    where, args, stdin = STAGES[stage]
    query = _QUERY.get(stage, "SELECT count(*) AS n FROM data")
    return _faulted(tmp_path, f"{where}:{kind}", *args, query, stdin=stdin)


@pytest.mark.parametrize("stage", list(STAGES))
def test_o2_o3_a_memory_error_anywhere_in_a_run_is_one_size_refusal_that_cleans_up(tmp_path, stage):
    """Both memory errors, in loading, in each advisory step, in the query, in the fetch: exit 2,
    one fixed line, scratch gone, never an answer with a warning missing. (O2, O3, P5)"""
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    texts = []
    for kind, root in (("memory", tmp_path / "a"), ("oom", tmp_path / "b")):
        res = _stage(root, stage, kind)
        texts.append(_is_size_refusal(res))
        assert res.leftover == [], f"the refusal left scratch behind: {res.leftover}"
    assert texts[0] == texts[1], "P1: byte-identical whichever memory error"


def test_the_load_and_the_query_refusals_tell_the_model_different_things(tmp_path):
    """The fixed text is chosen by phase: shrink the payload, or shrink the query. (O2, O3)"""
    load = _is_size_refusal(_stage(tmp_path, "load", "memory"))
    query = _is_size_refusal(_stage(tmp_path / "q", "query", "memory"), room=("memory",))
    assert load != query


@pytest.mark.parametrize("stage", ["describe", "arrow", "truncation"])
def test_an_advisory_step_failing_for_another_reason_is_still_skipped(tmp_path, stage):
    """The control for the re-raise: only memory errors stop the run; other failures of these
    steps still lose just their warning. (O2)"""
    res = _stage(tmp_path, stage, "generic")
    assert res.returncode == defender_sql.EXIT_OK, res.stderr[-400:]
    assert json.loads(res.stdout)


def test_o2_losing_the_document_parse_cannot_silently_drop_the_positional_rows_note(tmp_path):
    """Undeclared positional rows answer `count(*)` = 1; without a parse the note goes, so the run must not answer. (O2)"""
    res = _faulted(tmp_path, "parse:memory", "SELECT count(*) AS n FROM data", stdin=ROWS)
    _is_size_refusal(res)
    control = _faulted(tmp_path / "c", "none:none", "SELECT count(*) AS n FROM data", stdin=ROWS)
    assert json.loads(control.stdout) == [{"n": 1}]
    assert "positional rows" in control.stderr


@pytest.mark.parametrize("declared", [False, True], ids=["undeclared", "declared"])
def test_o2_a_full_scratch_disk_is_a_size_refusal_with_its_own_wording(tmp_path, declared):
    """Real ENOSPC on a scratch write, hit whatever the file is named: a room refusal unlike the memory ones. (O2)"""
    args, stdin = (DECLARED, ROWS) if declared else ((), FLAT)
    hits = tmp_path / "full.hits"
    res = _faulted(tmp_path, "scratch-full:none", *args, "SELECT 1 AS x", stdin=stdin,
                   extra={"FULL_HITS": str(hits)})
    assert hits.exists(), "no scratch file was opened for writing: the fault was never reached"
    full = _is_size_refusal(res, room=("room", "space", "disk"))
    assert res.leftover == []
    assert full != _is_size_refusal(_stage(tmp_path / "m", "load", "memory"))
    assert full != _is_size_refusal(_stage(tmp_path / "q", "query", "memory"), room=("memory",))


@pytest.mark.parametrize("declared", [False, True], ids=["undeclared", "declared"])
def test_o2_a_scratch_file_past_the_file_limit_is_a_size_refusal(tmp_path, declared):
    """The box's own file limit (C2), reproduced with a real `RLIMIT_FSIZE`. (O2)"""
    big = '{"columns":["a"],"values":[' + ",".join(["[1234567]"] * 400_000) + "]}"
    args = DECLARED if declared else ()
    stdin = big if declared else "\n".join(['{"a":1234567,"b":"xxxxxxxxxxxxxxxx"}'] * 100_000)
    res = _faulted(tmp_path, "scratch-fsize:none", *args, "SELECT 1 AS x", stdin=stdin)
    _is_size_refusal(res, room=("room", "space", "disk", "memory"))
    assert res.leftover == []


@pytest.mark.parametrize("junk_over", [1, 0], ids=["over", "at-the-maximum"])
@pytest.mark.parametrize("args", [(), DECLARED], ids=["undeclared", "declared"])
def test_o1_a_payload_over_the_maximum_is_refused_before_parsing(args, junk_over):
    """Bytes no parser accepts: only a check before parsing gives the size message, and the maximum itself is not over it. (O1)"""
    res = run_sql_py(*args, "SELECT 1 AS x", stdin="x" * (PAYLOAD_MAX + junk_over))
    assert res.returncode == defender_sql.EXIT_INPUT_ERROR
    assert res.stdout == ""
    assert "Traceback" not in res.stderr
    over = run_sql_py(*args, "SELECT 1 AS x", stdin="x" * (PAYLOAD_MAX + 1))
    if junk_over:
        assert len([ln for ln in res.stderr.splitlines() if ln.strip()]) == 1
        assert len(res.stderr.strip()) <= 160
        assert "narrow" in res.stderr.lower()
        assert "not valid JSON" not in res.stderr
    else:
        assert res.stderr != over.stderr, "the maximum itself was refused as over it"


@pytest.mark.parametrize(("cap", "size", "too_big"), [("512m", 700 << 20, True), ("256m", PAYLOAD_MAX + (1 << 20), False)],
                         ids=["stream-past-the-cap", "small-cap"])
def test_o1_a_payload_past_the_maximum_under_a_box_cap_is_refused_in_one_line_never_a_crash(cap, size, too_big):
    """Streamed bytes beyond the cap: exit 2, nothing printed, one refusal line (the payload-too-big one where the cap holds the maximum) and no traceback, so the payload is never read whole. (O1)"""
    reader, writer = os.pipe()
    proc = subprocess.Popen([*SQL_ARGV, "SELECT 1 AS x"], stdin=reader, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            env=sql_env({**os.environ, "DEFENDER_BOX_MEMORY": cap}))
    os.close(reader)

    def feed() -> None:
        chunk = b"x" * (1 << 20)
        with contextlib.suppress(BrokenPipeError), os.fdopen(writer, "wb") as pipe:
            for _ in range(size >> 20):
                pipe.write(chunk)

    feeder = threading.Thread(target=feed)
    feeder.start()
    out, err = proc.communicate(timeout=120)
    feeder.join(timeout=60)
    text = err.decode("utf-8", "replace")
    assert proc.returncode == defender_sql.EXIT_INPUT_ERROR, text[-300:]
    assert out == b""
    assert "Traceback" not in text
    assert len([ln for ln in text.splitlines() if ln.strip()]) == 1, text[-300:]
    if too_big:  # a cap too small to hold the maximum may refuse in the memory words instead
        assert text == run_sql_py("SELECT 1 AS x", stdin="x" * (PAYLOAD_MAX + 1)).stderr, "not the payload-too-big line"


def test_o1_the_same_message_on_both_load_paths():
    """One message, whichever load path. (O1)"""
    junk = "x" * (PAYLOAD_MAX + 1)
    assert run_sql_py("SELECT 1", stdin=junk).stderr == run_sql_py(*DECLARED, "SELECT 1", stdin=junk).stderr


def _big_result(rows: int, width: int = 1024) -> str:
    return f"SELECT repeat('x', {width}) AS s FROM range({rows})"


def test_o4_a_result_over_the_budget_prints_nothing_and_refuses_with_one_fixed_line(tmp_path):
    """Under the budget the same query prints in full; over it nothing is printed, in words unlike the load and query refusals. (O4, P1)"""
    control = run_sql_py(_big_result(24 * 1024), stdin=FLAT)
    assert control.returncode == defender_sql.EXIT_OK, control.stderr[-300:]
    assert len(json.loads(control.stdout)) == 24 * 1024
    many = run_sql_py(_big_result(RESULT_BUDGET // 512), stdin=FLAT)
    one_wide = run_sql_py(f"SELECT repeat('x', {RESULT_BUDGET + (1 << 20)}) AS s", stdin=FLAT)
    for res in (many, one_wide):
        assert res.returncode == defender_sql.EXIT_INPUT_ERROR, res.stderr[-300:]
        assert res.stdout == ""
        assert "Traceback" not in res.stderr
        assert len([ln for ln in res.stderr.splitlines() if ln.strip()]) == 1, res.stderr[-300:]
        assert len(res.stderr.strip()) <= 160
    assert many.stderr == one_wide.stderr, "P1: one text, whatever the shape of the result"
    for stage in ("load", "query"):
        other = _stage(tmp_path / stage, stage, "memory").stderr
        assert many.stderr != other, f"the result refusal repeats the {stage} refusal: the model cannot tell what to shrink"


@pytest.mark.parametrize("width", [1 << 10, 16 << 10, 256 << 10, 1 << 20])
def test_o4_the_result_budget_falls_within_one_row_of_32_mib_whatever_the_row_width(width):
    """A result one row below 32 MiB is answered in full and one row above it is refused with nothing printed. (O4)"""
    each = len(json.dumps({"s": "x" * width})) + 2  # a row and its ", "; the printed result is `each * rows`
    under, over = (RESULT_BUDGET - 2) // each, RESULT_BUDGET // each + 1
    assert RESULT_BUDGET - under * each < 2 * each
    assert over * each - RESULT_BUDGET < each
    answered = run_sql_py(_big_result(under, width), stdin=FLAT)
    assert answered.returncode == defender_sql.EXIT_OK, answered.stderr[-300:]
    assert len(json.loads(answered.stdout)) == under
    refused = run_sql_py(_big_result(over, width), stdin=FLAT)
    assert refused.returncode == defender_sql.EXIT_INPUT_ERROR, refused.stderr[-300:]
    assert refused.stdout == ""


def test_the_engine_runs_two_threads_with_no_spill_and_its_own_memory_figure():
    """The box's CPU cap sets the threads, a blocked spill stays an out-of-memory error, and no
    engine figure decides the memory (the address-space limit does). (O3)"""
    import duckdb

    default = duckdb.connect(":memory:").execute("SELECT current_setting('memory_limit')").fetchone()[0]
    res = run_sql_py("SELECT current_setting('threads') AS t, current_setting('max_temp_directory_size') AS s, "
                     "current_setting('memory_limit') AS m", stdin=FLAT)
    assert res.returncode == defender_sql.EXIT_OK, res.stderr
    [row] = json.loads(res.stdout)
    assert int(row["t"]) == 2
    assert row["s"].startswith("0 "), row["s"]
    assert row["m"] == default


def test_the_address_space_limit_is_set_by_main_only_and_under_a_lower_hard_limit(
        tmp_path, monkeypatch, capsys):
    """`_run` (which tests call in-process) leaves the process alone; `main()` limits it, never
    above a lower hard limit, and a small query still answers at that size (C15). (O3, P5)"""
    before = resource.getrlimit(resource.RLIMIT_AS)
    assert _run(monkeypatch, capsys, FLAT, "SELECT 1 AS x")[0] == defender_sql.EXIT_OK
    assert resource.getrlimit(resource.RLIMIT_AS) == before
    hard = 450 << 20
    log = tmp_path / "limit.log"
    res = _faulted(tmp_path, "none:none", "SELECT 41 + 1 AS x",
                   extra={"HARD_AS": str(hard), "RLIMIT_LOG": str(log)})
    assert res.returncode == defender_sql.EXIT_OK, res.stderr[-300:]
    assert json.loads(res.stdout) == [{"x": 42}]
    soft, hard_seen = json.loads(log.read_text())
    assert hard_seen == hard
    assert 0 < soft <= hard, "main() set no limit, or one above the hard limit"


_UNITS = {"KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40, "bytes": 1}


def _engine_figure() -> int:
    """DuckDB's own default `memory_limit`, in bytes."""
    import duckdb

    amount, unit = duckdb.connect(":memory:").execute("SELECT current_setting('memory_limit')").fetchone()[0].split()
    return int(float(amount) * _UNITS[unit])


def _limit_main_sets(tmp_path, monkeypatch, cap: str | None, **extra) -> tuple[int, int, object]:
    """(soft, hard, result) of the address-space limit `main()` holds when its first statement runs."""
    monkeypatch.delenv("DEFENDER_BOX_MEMORY", raising=False)
    log = tmp_path / "limit.log"
    env = {"RLIMIT_LOG": str(log), **extra, **({} if cap is None else {"DEFENDER_BOX_MEMORY": cap})}
    res = _faulted(tmp_path, "none:none", "SELECT 41 + 1 AS x", extra=env)
    soft, hard = json.loads(log.read_text()) if log.exists() else (resource.RLIM_INFINITY, resource.RLIM_INFINITY)
    return soft, hard, res


@pytest.mark.parametrize(("cap", "bytes_"), [
    ("512m", 512 << 20), ("2g", 2 << 30), ("1073741824", 1 << 30), ("1024M", 1 << 30),
], ids=["m", "g", "plain-bytes", "upper-case"])
def test_main_limits_the_address_space_to_about_four_fifths_of_the_box_cap(tmp_path, monkeypatch, cap, bytes_):
    """`DEFENDER_BOX_MEMORY` in any form docker takes sets the limit near 80% of it. (P5)"""
    soft, _hard, res = _limit_main_sets(tmp_path, monkeypatch, cap)
    assert res.returncode == defender_sql.EXIT_OK, res.stderr[-300:]
    assert 0.75 * bytes_ <= soft <= 0.85 * bytes_, (soft, bytes_)


def test_the_default_box_cap_parses(tmp_path, monkeypatch):
    """The cap `BoxSpec()` really carries is understood, not dropped. (P5)"""
    from defender.box._spec import BoxSpec

    cap = BoxSpec().memory
    soft, _hard, _res = _limit_main_sets(tmp_path, monkeypatch, cap)
    size = int(cap[:-1]) * {"m": 1 << 20, "g": 1 << 30}[cap[-1]]
    assert 0.75 * size <= soft <= 0.85 * size, (cap, soft)


def test_a_lower_hard_limit_caps_what_main_asks_for(tmp_path, monkeypatch):
    """A 450 MiB hard limit under a 2g cap: the soft limit is the hard one at most. (P5)"""
    hard = 450 << 20
    soft, hard_seen, res = _limit_main_sets(tmp_path, monkeypatch, "2g", HARD_AS=str(hard))
    assert res.returncode == defender_sql.EXIT_OK, res.stderr[-300:]
    assert hard_seen == hard
    assert 0 < soft <= hard


def test_without_the_box_cap_main_uses_the_engines_own_figure(tmp_path, monkeypatch):
    """No variable (the unsandboxed fallback): a finite limit from the engine's figure, not none. (P5)"""
    engine = _engine_figure()
    soft, _hard, res = _limit_main_sets(tmp_path, monkeypatch, None)
    assert res.returncode == defender_sql.EXIT_OK, res.stderr[-300:]
    assert soft != resource.RLIM_INFINITY, "no limit was set"
    assert 0.75 * engine <= soft <= 1.05 * engine, (soft, engine)


@pytest.mark.parametrize("cap", ["lots", "", "2gb", "-1", "0"], ids=["word", "empty", "bad-unit", "negative", "zero"])
def test_a_cap_the_parser_cannot_read_never_silently_loses_the_limit(tmp_path, monkeypatch, cap):
    """An unreadable cap is refused aloud, or the engine's figure holds: never no limit. (P5)"""
    soft, _hard, res = _limit_main_sets(tmp_path, monkeypatch, cap)
    if res.returncode == defender_sql.EXIT_OK:
        assert soft != resource.RLIM_INFINITY, "the limit was silently lost"
    else:
        assert res.stderr.strip(), "a refusal with no reason"
        assert "Traceback" not in res.stderr


@pytest.mark.parametrize("declared", [False, True], ids=["undeclared", "declared"])
def test_c17_scratch_is_gone_once_the_load_finishes_so_a_killed_query_leaves_none(tmp_path, declared):
    """Nothing after the load uses the scratch files, so a query killed mid-run (the 120 s
    timeout) leaves no directory behind. (O2, C17)"""
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    payload = tmp_path / "payload.json"
    if declared:
        payload.write_text('{"columns":["a","b"],"values":[' + ",".join(["[1,2]"] * 2_000_000) + "]}")
    else:
        payload.write_text('{"a":1,"b":"x"}\n' * 1_500_000)
    long_query = "SELECT sum(i) AS s FROM range(100000000000) t(i)"
    args = (*DECLARED, long_query) if declared else (long_query,)
    with payload.open("rb") as stdin:
        proc = subprocess.Popen([*SQL_ARGV, *args], stdin=stdin, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=sql_env({**os.environ, "TMPDIR": str(scratch)}))
        try:
            deadline = time.monotonic() + 60
            while not any(scratch.iterdir()) and proc.poll() is None and time.monotonic() < deadline:
                time.sleep(0.005)
            assert any(scratch.iterdir()), f"the load never made scratch: {proc.poll()} {proc.stderr.read()[-300:] if proc.poll() is not None else ''}"
            deadline = time.monotonic() + 60
            while any(scratch.iterdir()) and proc.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            assert proc.poll() is None, "the query finished: it was meant to outlast the check"
            assert not any(scratch.iterdir()), "the load finished and its scratch is still there"
        finally:
            proc.send_signal(signal.SIGKILL)
            proc.communicate()
