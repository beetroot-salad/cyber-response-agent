"""Structured logging for the defender — one JSON object per line on the error stream.

  * Only programs configure. Library code uses `logging.getLogger(__name__)`; a program's
    `__main__` block calls `configure_from_env()` (enforced by `scripts/lint/lint_log_setup.py`).
  * A program's own lines carry its real module name: `configure` gives `__main__` the same
    level and the formatters print it as e.g. `defender.run`.
  * `run_id` / `tenant_id` live in a `ContextVar`, so concurrent tasks never stamp each other's
    tenant. Thread-pool workers do not inherit it — bind inside the worker or submit through
    `contextvars.copy_context().run`. `log_context` restores the previous binding on exit.

`print` remains right for a command's own stdout output and for text a model reads back as a
tool result. Argparse usage errors, `sys.exit("…")` refusals and crash tracebacks stay plain
text; a program that must tie its crash to a run logs it inside the run's context (`run.main`).
"""
from __future__ import annotations

import contextlib
import contextvars
import datetime as _dt
import json
import logging
import math
import sys
from collections.abc import Iterator, Mapping
from pathlib import Path
from types import MappingProxyType, ModuleType
from typing import Any

from defender._env import env_str

#: Emitted on every line, `null` when unbound — one shape per line keeps log queries simple.
ALWAYS_FIELDS = ("run_id", "tenant_id")
#: Built from the record itself; neither bound context nor `extra=` can replace them.
CORE_FIELDS = ("timestamp", "severity", "logger", "message", "exception", "stack")
#: Settable only through `log_context`, never through one call's `extra=` — a line filed under
#: another tenant than the one bound is a cross-tenant leak in the log store.
BIND_ONLY_FIELDS = ("tenant_id",)

FORMAT_ENV = "DEFENDER_LOG_FORMAT"
LEVEL_ENV = "DEFENDER_LOG_LEVEL"
FORMATS = ("json", "text")
DEFAULT_FORMAT = "json"
DEFAULT_LEVEL = "INFO"

#: The logger every `defender.*` module's `getLogger(__name__)` sits under.
ROOT_LOGGER = "defender"
#: Where a program's own module logs from; printed under its real module name.
MAIN_LOGGER = "__main__"

_EMPTY: Mapping[str, str | None] = MappingProxyType({})
_context: contextvars.ContextVar[Mapping[str, str | None]] = contextvars.ContextVar(
    "defender_log_context", default=_EMPTY)

#: `LogRecord` attributes that are logging's own bookkeeping — everything else on a record
#: arrived through `extra=` and is emitted as a field.
_RECORD_ATTRS = frozenset(vars(logging.LogRecord("", 0, "", 0, "", None, None))) | {
    "message", "asctime", "taskName"}
_TRACES = logging.Formatter()  # formatException / formatStack only
_MAX_DEPTH = 6

#: What `__main__` is printed as; set by `configure`.
_program = MAIN_LOGGER


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


@contextlib.contextmanager
def run_context(run_id: str, tenant_id: str | None, *, logger: logging.Logger) -> Iterator[None]:
    """`log_context` for one run, plus logging an escaping failure as CRITICAL while the run is
    still bound (so the crash record carries its run id). The exception propagates unchanged."""
    with log_context(run_id=run_id, tenant_id=tenant_id):
        try:
            yield
        except Exception:
            logger.critical("the run failed", exc_info=True)
            raise


def program_name(main: ModuleType | None) -> str:
    """The dotted module name of the running program: its spec's name under `python -m`, else
    derived from its file's path under the `defender` package (`defender/run.py` →
    `defender.run`), else `__main__` as it stands."""
    spec = getattr(main, "__spec__", None)
    if spec is not None and spec.name:
        return str(spec.name).removesuffix(".__main__")
    file = getattr(main, "__file__", None)
    if file:
        path = Path(file).resolve()
        package_parent = Path(__file__).resolve().parent.parent
        if path.is_relative_to(package_parent):
            return ".".join(path.relative_to(package_parent).with_suffix("").parts)
    return MAIN_LOGGER


def _logger_name(name: str) -> str:
    if name == MAIN_LOGGER or name.startswith(MAIN_LOGGER + "."):
        return _program + name[len(MAIN_LOGGER):]
    return name


def _jsonable(value: Any, depth: int = 0) -> Any:
    """`value` as something `json.dumps(allow_nan=False)` always accepts, so a line is never lost
    to what a caller put in `extra=` or the context."""
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else repr(value)
    if depth >= _MAX_DEPTH:
        return repr(value)
    if isinstance(value, Mapping):
        return {k if isinstance(k, str) else repr(k): _jsonable(v, depth + 1)
                for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        return [_jsonable(v, depth + 1) for v in value]
    return str(value)


def record_fields(record: logging.LogRecord) -> dict[str, Any]:
    """A record as fields; both formatters render exactly this.

    Core fields, then the bound context, then `extra=` over it (more specific) — except the
    tenant, which only `log_context` sets. Neither may replace a core field."""
    out: dict[str, Any] = {
        "timestamp": _dt.datetime.fromtimestamp(record.created, _dt.UTC).isoformat(
            timespec="milliseconds"),
        "severity": record.levelname,
        "logger": _logger_name(record.name),
        "message": record.getMessage(),
    }
    fields: dict[str, Any] = {**dict.fromkeys(ALWAYS_FIELDS), **current_context()}
    fields.update((k, v) for k, v in vars(record).items()
                  if k not in _RECORD_ATTRS and k not in BIND_ONLY_FIELDS)
    out.update((k, _jsonable(v)) for k, v in fields.items() if k not in CORE_FIELDS)
    if record.exc_info:
        out["exception"] = _TRACES.formatException(record.exc_info)
    if record.stack_info:
        out["stack"] = _TRACES.formatStack(record.stack_info)
    return out


class JsonFormatter(logging.Formatter):
    """One record → one JSON line, pure ASCII, so attacker-controlled alert text cannot forge a
    second line (U+2028, U+2029 and U+0085 are line breaks to some splitters)."""

    def format(self, record: logging.LogRecord) -> str:
        return json.dumps(record_fields(record), ensure_ascii=True, allow_nan=False)


class TextFormatter(logging.Formatter):
    """The same fields for a person at a terminal (`DEFENDER_LOG_FORMAT=text`): the head, the
    fields that carry a value in brackets, then any traceback. Not for collection — multi-line
    messages stay multi-line here."""

    def format(self, record: logging.LogRecord) -> str:
        f = record_fields(record)
        rest = " ".join(f"{k}={v}" for k, v in f.items()
                        if k not in CORE_FIELDS and v is not None)
        line = (f"{f['timestamp']} {f['severity']} {f['logger']}"
                f"{f' [{rest}]' if rest else ''} {f['message']}")
        for trace in ("exception", "stack"):
            if trace in f:
                line += "\n" + f[trace]
        return line


class _DefenderHandler(logging.StreamHandler):
    """Writes to whatever `sys.stderr` is at emit time, so redirects (`capsys`,
    `redirect_stderr`) capture log lines. Its type also marks the handler `configure` owns and
    replaces on a second call."""

    @property
    def stream(self) -> Any:
        return sys.stderr

    @stream.setter
    def stream(self, _value: Any) -> None:
        pass


def configure(*, fmt: str, level: int | str) -> None:
    """Install the defender's handler on the root logger.

    The root stays at WARNING so third-party libraries only speak up when something is wrong
    (httpx alone logs every HTTP request at INFO); `level` applies to the `defender` logger and
    to the program's own `__main__`."""
    global _program
    _program = program_name(sys.modules.get(MAIN_LOGGER))
    handler = _DefenderHandler()
    handler.setFormatter(JsonFormatter() if fmt == "json" else TextFormatter())
    root = logging.getLogger()
    for old in [h for h in root.handlers if isinstance(h, _DefenderHandler)]:
        root.removeHandler(old)
    root.addHandler(handler)
    root.setLevel(logging.WARNING)
    for name in (ROOT_LOGGER, MAIN_LOGGER):
        logging.getLogger(name).setLevel(level)


def _level(raw: str) -> int | None:
    """A level name (any case) or number, or `None`. NOTSET and below are `None` too: on a
    logger they mean "inherit" the root's WARNING, silently hiding INFO."""
    name = raw.strip().upper()
    try:
        level = int(name)
    except ValueError:
        level = logging.getLevelNamesMapping().get(name, logging.NOTSET)
    return level if level > logging.NOTSET else None


def configure_from_env() -> None:
    """`configure` from `DEFENDER_LOG_FORMAT` (json|text, default json) and
    `DEFENDER_LOG_LEVEL` (any level name `logging` knows, any case, or a number; default INFO).

    Never fatal: an unusable value falls back to its default and a notice is handed straight
    to the handler, so no level setting can hide it."""
    raw_fmt = env_str(FORMAT_ENV, DEFAULT_FORMAT)
    raw_level = env_str(LEVEL_ENV, DEFAULT_LEVEL)
    fmt = raw_fmt.strip().lower()
    level = _level(raw_level)
    notices = []
    if fmt not in FORMATS:
        notices.append(f"{FORMAT_ENV}={raw_fmt!r} is not one of {FORMATS}; using {DEFAULT_FORMAT!r}")
        fmt = DEFAULT_FORMAT
    if level is None:
        notices.append(f"{LEVEL_ENV}={raw_level!r} is not a usable logging level; using {DEFAULT_LEVEL!r}")
    configure(fmt=fmt, level=DEFAULT_LEVEL if level is None else level)
    handler = next(h for h in logging.getLogger().handlers if isinstance(h, _DefenderHandler))
    for message in notices:
        handler.handle(logging.getLogger(__name__).makeRecord(
            __name__, logging.ERROR, __file__, 0, message, (), None))
