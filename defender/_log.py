"""Structured logging for the defender — one JSON object per line on the error stream.

Three rules the rest of the tree relies on:

  * ONLY ENTRY POINTS CONFIGURE. Library code writes through `logging.getLogger(__name__)` and
    never decides format or destination; an entry point calls `configure_from_env()` once. A
    future HTTP server is then one more entry point, and its request middleware binds context
    through `log_context` like everything else.
  * CONTEXT FOLLOWS THE TASK, NOT THE PROCESS. `run_id` / `tenant_id` live in a `ContextVar`,
    so two requests served concurrently can never stamp each other's tenant on a line. asyncio
    tasks inherit the context they were created in; THREAD-POOL WORKERS DO NOT
    (`ThreadPoolExecutor.submit` copies nothing) — bind inside the worker function.
  * CONTEXT UNDOES ITSELF. `log_context` resets to the previous mapping on exit, exception
    included, so a reused thread cannot carry the last job's run id into the next one.

Prints are still right for two things this module is NOT for: a command's own output (a
report, a table), and text a model reads back as a tool result.
"""
from __future__ import annotations

import contextlib
import contextvars
import datetime as _dt
import json
import logging
import sys
from collections.abc import Iterator, Mapping
from types import MappingProxyType
from typing import Any, TextIO

from defender._env import env_str

#: Emitted on every line, `null` when unbound — one shape per line keeps log queries simple.
ALWAYS_FIELDS = ("run_id", "tenant_id")
#: Neither bound context nor `extra=` can replace these.
CORE_FIELDS = ("timestamp", "severity", "logger", "message", "exception")

#: Settable only through `log_context`, never through one call's `extra=` — a line filed under
#: another tenant than the one bound is a cross-tenant leak in the log store (#1112).
BIND_ONLY_FIELDS = ("tenant_id",)

FORMAT_ENV = "DEFENDER_LOG_FORMAT"
LEVEL_ENV = "DEFENDER_LOG_LEVEL"
FORMATS = ("json", "text")
LEVELS = ("DEBUG", "INFO", "WARNING", "ERROR")

#: The logger every `defender.*` module's `getLogger(__name__)` sits under.
ROOT_LOGGER = "defender"

_EMPTY: Mapping[str, str | None] = MappingProxyType({})
_context: contextvars.ContextVar[Mapping[str, str | None]] = contextvars.ContextVar(
    "defender_log_context", default=_EMPTY)

#: `LogRecord` attributes that are logging's own bookkeeping — everything else on a record
#: arrived through `extra=` and is emitted as a field.
_RECORD_ATTRS = frozenset(vars(logging.LogRecord("", 0, "", 0, "", None, None))) | {
    "message", "asctime", "taskName"}


def current_context() -> Mapping[str, str | None]:
    """The fields bound for the current task (read-only)."""
    return _context.get()


@contextlib.contextmanager
def log_context(**fields: str | None) -> Iterator[None]:
    """Bind `fields` onto every log line written inside the block, over whatever is bound
    already; the previous binding is restored on exit.

    A core field name is refused rather than silently losing to the formatter: a caller who
    binds `severity` meant something, and the line would not say it."""
    clash = sorted(set(fields) & set(CORE_FIELDS))
    if clash:
        raise ValueError(f"log_context cannot bind core field(s) {clash}")
    token = _context.set(MappingProxyType({**_context.get(), **fields}))
    try:
        yield
    finally:
        _context.reset(token)


def _timestamp(record: logging.LogRecord) -> str:
    return _dt.datetime.fromtimestamp(record.created, _dt.UTC).isoformat(timespec="milliseconds")


def _context_fields() -> dict[str, str | None]:
    return {**dict.fromkeys(ALWAYS_FIELDS), **current_context()}


class JsonFormatter(logging.Formatter):
    """One record → one JSON line. `json.dumps` escapes newlines, so text copied from an alert
    (attacker-controlled) cannot forge a second line."""

    def format(self, record: logging.LogRecord) -> str:
        out: dict[str, Any] = {
            "timestamp": _timestamp(record),
            "severity": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        # Bound context, then `extra=` over it: a value named on the line itself is more
        # specific than the ambient one (a batch job naming the run it is on). Neither may
        # replace a core field, and `extra=` may not name the tenant.
        fields: dict[str, Any] = _context_fields()
        fields.update((k, v) for k, v in vars(record).items()
                      if k not in _RECORD_ATTRS and k not in BIND_ONLY_FIELDS)
        out.update((k, v) for k, v in fields.items() if k not in CORE_FIELDS)
        if record.exc_info:
            out["exception"] = self.formatException(record.exc_info)
        return json.dumps(out, default=str, ensure_ascii=False)


class TextFormatter(logging.Formatter):
    """The human form, for a person at a terminal (`DEFENDER_LOG_FORMAT=text`). Not for
    collection: multi-line messages stay multi-line here."""

    def format(self, record: logging.LogRecord) -> str:
        ctx = " ".join(f"{k}={v}" for k, v in current_context().items())
        line = (f"{_timestamp(record)} {record.levelname} {record.name}"
                f"{f' [{ctx}]' if ctx else ''} {record.getMessage()}")
        if record.exc_info:
            line += "\n" + self.formatException(record.exc_info)
        return line


class _DefenderHandler(logging.StreamHandler[TextIO]):
    """Marks the one handler `configure` owns, so a second call replaces it and leaves every
    other handler (pytest's capture among them) alone."""


def configure(*, fmt: str, level: str, stream: TextIO) -> None:
    """Install the defender's handler on the root logger.

    The root stays at WARNING so third-party libraries only speak up when something is wrong
    (httpx alone logs every HTTP request at INFO); `level` applies to the `defender` logger."""
    handler = _DefenderHandler(stream)
    handler.setFormatter(JsonFormatter() if fmt == "json" else TextFormatter())
    root = logging.getLogger()
    for old in [h for h in root.handlers if isinstance(h, _DefenderHandler)]:
        root.removeHandler(old)
    root.addHandler(handler)
    root.setLevel(logging.WARNING)
    logging.getLogger(ROOT_LOGGER).setLevel(level)


def configure_from_env() -> None:
    """`configure` from `DEFENDER_LOG_FORMAT` (json|text, default json) and
    `DEFENDER_LOG_LEVEL` (default INFO), writing to the error stream. A value outside the
    choices raises `FatalConfigError` rather than guessing."""
    configure(
        fmt=env_str(FORMAT_ENV, "json", choices=FORMATS),
        level=env_str(LEVEL_ENV, "INFO", choices=LEVELS),
        stream=sys.stderr,
    )
