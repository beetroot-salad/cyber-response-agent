"""The structured-logging framework (`defender/_log.py`) and its one wiring point, `run.main`.

Formatters are driven through a handler on a `StringIO`, so what is asserted is the exact line a
log collector would receive.
"""
from __future__ import annotations

import asyncio
import contextlib
import io
import json
import logging
from concurrent.futures import ThreadPoolExecutor

import pytest

from defender import _log
from defender.tests import _triplet_947 as T


@pytest.fixture
def emit():
    """A `defender.test` logger writing JSON into a buffer; returns (logger, lines())."""
    buf = io.StringIO()
    handler = logging.StreamHandler(buf)
    handler.setFormatter(_log.JsonFormatter())
    logger = logging.getLogger("defender.test.log")
    saved = (logger.level, logger.propagate)
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False

    def lines() -> list[dict]:
        return [json.loads(line) for line in buf.getvalue().splitlines()]

    yield logger, lines, buf
    logger.removeHandler(handler)
    logger.level, logger.propagate = saved


@pytest.fixture
def restore_root():
    """`configure` touches the process-wide root; put it back after."""
    root = logging.getLogger()
    saved = (list(root.handlers), root.level, logging.getLogger(_log.ROOT_LOGGER).level)
    yield
    root.handlers[:] = saved[0]
    root.setLevel(saved[1])
    logging.getLogger(_log.ROOT_LOGGER).setLevel(saved[2])


def test_a_line_carries_exactly_the_core_and_always_on_fields(emit):
    logger, lines, _ = emit
    logger.info("hello %s", "world")
    [line] = lines()
    assert set(line) == {"timestamp", "severity", "logger", "message", "run_id", "tenant_id"}
    assert line["message"] == "hello world"
    assert line["severity"] == "INFO"
    assert line["logger"] == "defender.test.log"
    assert line["run_id"] is None
    assert line["tenant_id"] is None
    assert line["timestamp"].endswith("+00:00")


def test_bound_context_nests_and_restores_including_on_exception(emit):
    logger, lines, _ = emit
    with _log.log_context(run_id="r1", tenant_id="t1"):
        logger.info("outer")
        with _log.log_context(run_id="r2"):
            logger.info("inner")
        logger.info("outer again")
    with pytest.raises(RuntimeError), _log.log_context(run_id="r3"):
        raise RuntimeError
    logger.info("after")
    got = [(ln["run_id"], ln["tenant_id"]) for ln in lines()]
    assert got == [("r1", "t1"), ("r2", "t1"), ("r1", "t1"), (None, None)]


def test_concurrent_asyncio_tasks_each_log_their_own_run(emit):
    """The server case: two requests in flight at once must never swap tenants."""
    logger, lines, _ = emit

    async def job(run_id: str, tenant: str) -> None:
        with _log.log_context(run_id=run_id, tenant_id=tenant):
            for _ in range(3):
                await asyncio.sleep(0)
                logger.info(run_id)

    async def both() -> None:
        await asyncio.gather(job("a", "ta"), job("b", "tb"))

    asyncio.run(both())
    got = lines()
    assert len(got) == 6
    assert all(ln["run_id"] == ln["message"] and ln["tenant_id"] == "t" + ln["message"]
               for ln in got)


def test_a_reused_pool_thread_does_not_carry_the_previous_jobs_run(emit):
    logger, lines, _ = emit

    def first() -> None:
        with _log.log_context(run_id="first"):
            logger.info("first")

    def second() -> None:
        logger.info("second")

    with ThreadPoolExecutor(max_workers=1) as pool:
        pool.submit(first).result()
        pool.submit(second).result()
    assert [ln["run_id"] for ln in lines()] == ["first", None]


def test_lead_zero_s_thread_hop_keeps_the_run_bound():
    """Lead-0 runs its coroutine on a pool thread when a loop is already running (inside the
    driver); what it logs there must still name the run."""
    from defender.runtime.lead_zero._capture import _run_sync

    async def inner():
        return dict(_log.current_context())

    async def driver():
        with _log.log_context(run_id="R", tenant_id="T"):
            return _run_sync(inner())

    assert asyncio.run(driver()) == {"run_id": "R", "tenant_id": "T"}


@pytest.mark.parametrize("brk", ["\n", "\r", "\u2028", "\u2029", "\x85"])
def test_a_forged_line_inside_a_message_stays_one_record(emit, brk):
    """Every character some splitter treats as a line break — `str.splitlines` counts all five
    — stays escaped, so a message cannot become two records."""
    logger, lines, buf = emit
    logger.info(f'alert text{brk}{{"severity": "ERROR", "message": "forged"}}')
    assert len(buf.getvalue().splitlines()) == 1
    assert buf.getvalue().isascii()
    [line] = lines()
    assert line["severity"] == "INFO"


def test_an_exception_is_one_line_with_its_traceback(emit):
    logger, lines, buf = emit
    try:
        raise ValueError("boom")
    except ValueError:
        logger.exception("failed")
    assert len(buf.getvalue().splitlines()) == 1
    [line] = lines()
    assert line["severity"] == "ERROR"
    assert "ValueError: boom" in line["exception"]


def test_extra_fields_are_emitted_but_cannot_replace_core_fields_or_the_tenant(emit):
    logger, lines, _ = emit
    marker = object()
    with _log.log_context(run_id="ambient", tenant_id="bound"):
        logger.info("x", extra={"lead_id": "L3", "obj": marker, "severity": "DEBUG",
                                "run_id": "named", "tenant_id": "other"})
    [line] = lines()
    assert line["lead_id"] == "L3"
    assert line["obj"] == str(marker)
    assert line["severity"] == "INFO"
    assert line["run_id"] == "named", "a run named on the line beats the ambient one"
    assert line["tenant_id"] == "bound", "one call must not file its line under another tenant"


@pytest.mark.parametrize("value", [{(1, 2): "tuple key"}, float("nan")])
def test_an_extra_json_cannot_hold_still_leaves_one_valid_line(emit, value):
    """A non-string key or NaN in `extra=` degrades that field to its repr; the record is not
    lost to logging's error handler, and the line stays strict JSON."""
    logger, lines, buf = emit
    logger.info("kept", extra={"odd": value, "lead_id": "L1"})
    raw = buf.getvalue().strip()
    [line] = [json.loads(raw, parse_constant=lambda c: pytest.fail(f"non-strict JSON: {c}"))]
    assert line["message"] == "kept"
    assert line["odd"] == repr(value)


def test_context_refuses_a_core_field_name():
    with pytest.raises(ValueError, match="severity"), _log.log_context(severity="ERROR"):
        pass


def test_configure_owns_one_handler_and_keeps_third_party_info_out(restore_root, capsys):
    _log.configure(fmt="json", level="INFO")
    _log.configure(fmt="json", level="INFO")
    owned = [h for h in logging.getLogger().handlers if isinstance(h, _log._DefenderHandler)]
    assert len(owned) == 1
    capsys.readouterr()
    logging.getLogger("defender.some.module").info("ours")
    logging.getLogger("httpx").info("HTTP Request: POST ...")
    logging.getLogger("httpx").warning("theirs, but worth seeing")
    got = [json.loads(line)["message"] for line in capsys.readouterr().err.splitlines()]
    assert got == ["ours", "theirs, but worth seeing"]


def test_the_handler_writes_where_stderr_points_now(restore_root):
    """A redirect made AFTER setup still captures log lines — the eval harness captures a
    curator's output this way, as it did when that output was printed."""
    _log.configure(fmt="text", level="INFO")
    buf = io.StringIO()
    with contextlib.redirect_stderr(buf):
        logging.getLogger("defender.x").info("into the redirect")
    assert buf.getvalue().rstrip().endswith("INFO defender.x into the redirect")


def test_text_format_is_readable_and_names_the_bound_run(restore_root, capsys):
    _log.configure(fmt="text", level="INFO")
    capsys.readouterr()
    with _log.log_context(run_id="r9", tenant_id="t9"):
        logging.getLogger("defender.x").warning("careful")
    out = capsys.readouterr().err.strip()
    assert out.endswith("WARNING defender.x [run_id=r9 tenant_id=t9] careful")


@pytest.mark.parametrize(("var", "value"), [(_log.FORMAT_ENV, "yaml"), (_log.LEVEL_ENV, "LOUD")])
def test_an_unknown_setting_falls_back_and_says_so(monkeypatch, restore_root, capsys, var, value):
    """The logging setup never decides whether a process runs: a bad value costs the setting,
    names itself as the first line, and the process carries on."""
    monkeypatch.setenv(var, value)
    capsys.readouterr()
    _log.configure_from_env()
    [line] = [json.loads(ln) for ln in capsys.readouterr().err.splitlines()]
    assert line["severity"] == "ERROR"
    assert var in line["message"]
    assert value.upper() in line["message"].upper()
    logging.getLogger("defender.x").info("still logging")
    assert json.loads(capsys.readouterr().err)["message"] == "still logging"


@pytest.mark.parametrize("value", ["info", " Warning ", "CRITICAL"])
def test_any_standard_level_name_is_accepted_in_any_case(monkeypatch, restore_root, capsys, value):
    monkeypatch.setenv(_log.LEVEL_ENV, value)
    capsys.readouterr()
    _log.configure_from_env()
    assert capsys.readouterr().err == "", "a valid level was reported as a bad one"
    assert logging.getLogger(_log.ROOT_LOGGER).level == logging.getLevelName(value.strip().upper())


def test_run_main_binds_the_run_id_and_tenant_for_the_whole_run(tmp_path, monkeypatch):
    """The wiring: everything `run.main` does after the run dir exists — the lifecycle
    included — logs under this run's id and its tenant."""
    monkeypatch.setenv(T.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(T.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    base, src = T.runs_base(tmp_path)
    seen: dict = {}

    def lifecycle(**kw):
        seen["run_dir"] = kw["run_dir"]
        seen["ctx"] = dict(_log.current_context())
        (kw["run_dir"] / "report.md").write_text("disposition: malicious\n", encoding="utf-8")
        return {"output": "done", "requests": 1, "truncated_by": None}

    T.mod("run").main([str(src / "alert.json"), "--no-learn"], lifecycle=lifecycle,
                      visualize=lambda p: None, preflight=T.no_preflight)
    tenant = json.loads((base / "_tenant.json").read_text(encoding="utf-8"))["tenant_id"]
    assert seen["ctx"] == {"run_id": seen["run_dir"].name, "tenant_id": tenant}
    assert _log.current_context() == {}, "the binding outlived the run"
