"""Shared machinery for #1243 part 1's contract — "one retrier for temporary provider failures; a
provider that stays down ends the run by name". NO test functions; underscore-prefixed so pytest
never collects it.

The design is the issue's current revision (r2, base `d7b1886d`). Its obligations: O1 retry (408,
409, 429, >=500 and no response; at most 4 wire attempts; Retry-After honoured; no attempt starts
10 min after the first began; a retry is invisible to the run, P3), O2 nothing else retried, O3
provider-down ends the run (MAIN, its leads, the correlation lead, a review stage), O4 no report,
O5 legible downstream, O6 a branched sibling records "did not finish"; P1 one retry owner below
every caller (client libraries' own retries off).

THE SUITE IS WRITTEN BEFORE THE IMPLEMENTATION. Every new surface is reached through `mod()` /
`sym()` PER TEST, so a missing target is one failure per test, never a collection error.

COINED NAMES (the design names `ProviderDown` and "the policy, injected through the `make_model`
seam"; the spellings below are this contract's, binding on the implementer):

  * `runtime.providers.ProviderDown(model, status, attempts)` — `.model`, `.status` (`None` = no
    response), `.attempts`; raised `from` the last original error.
  * `runtime.providers.RetryPolicy(sleep=, clock=, jitter=)` — every field defaulted to the real
    thing: `sleep` an async `(seconds) -> None`, `clock` a monotonic `() -> float` in seconds,
    `jitter` a `() -> float` in `[0, 1)`.
  * `runtime.providers.with_retries(model, policy)` — the retrier applied to any pydantic-ai model.
  * `runtime.providers.build_for_effort(name, effort, *, retry=...)` — the two-argument
    `make_model` shape kept; the returned model carries the retrier.
  * each retry's WARNING line (O1: "call site, status, attempt n/4, wait") names the model's
    `model_name` (the call site the wrapper knows, AF2), the status when there is one, `n/4`,
    and the wait it is about to take, in SECONDS, as a number.

The run-end value is the literal `"provider-down"` and `run.py`'s exit the literal 4 (D4).

FAULTS ARE DATA, grounded in the installed pydantic-ai 2.43 (C1, C17): an HTTP failure is a
`ModelHTTPError(status, model, body, headers=...)` (its `headers` are lowercased; `retry-after` is
the documented read); no response is a `ModelAPIError` with no status (`_spec1222.provider_timeout`,
PA-15's observed shape). The fakes decide nothing: which status retries is production's.
"""
from __future__ import annotations

import asyncio
import json
import re
import socket
import sqlite3
import threading
import time
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from defender.run_repository import RunPaths
from defender.tests.tenancy.alert_front_door_1222 import _spec1222 as S

mod = S.mod
sym = S.sym

#: The design's literal run-end value (O3, O5) and run.py's exit for it (D4).
PROVIDER_DOWN = "provider-down"
PROVIDER_DOWN_EXIT = 4
#: The exits run.py already uses (0 ok, 2 preflight refusal, 3 unservable sibling).
TAKEN_EXITS = frozenset({0, 2, 3})
#: O1's bounds: 4 wire attempts at most; no attempt starts once this long has passed since the
#: first attempt began.
MAX_ATTEMPTS = 4
WINDOW_S = 600.0

#: O1's temporary statuses, and statuses that are not (O2: part 2 owns 4xx). O1 says ">=500",
#: not a list: unlisted 5xx (501, 505, 507, 599) are in, so a retrier keyed on a set of named
#: statuses fails; O2 says "all other 4xx", so unlisted 4xx (402, 405, 410, 418, 451) are in
#: the other list, and a retrier keyed on a denylist of named 4xx fails.
RETRIED_STATUSES = (408, 409, 429, 500, 501, 502, 503, 504, 505, 507, 529, 599)
NOT_RETRIED_STATUSES = (400, 401, 402, 403, 404, 405, 410, 413, 418, 422, 451)

L3 = S.L3


# =================================================================================================
# The coined surfaces, reached per test
# =================================================================================================

def providers() -> Any:
    return mod("runtime.providers")


def provider_down_cls() -> type[BaseException]:
    return sym("runtime.providers", "ProviderDown")


def provider_down(model: str = "fake", status: int | None = 503, attempts: int = MAX_ATTEMPTS) -> BaseException:
    """A `ProviderDown` as the retrier would raise it — for a site test whose subject is what a
    caller does with one, not how it arose."""
    return provider_down_cls()(model=model, status=status, attempts=attempts)


def provider_down_fault(model: str = "fake") -> Callable[[], BaseException]:
    return lambda: provider_down(model)


def with_retries(model: Any, policy: Any) -> Any:
    return sym("runtime.providers", "with_retries")(model, policy)


def retry_policy(*, sleep: Any = None, clock: Any = None, jitter: Any = None) -> Any:
    kw = {k: v for k, v in (("sleep", sleep), ("clock", clock), ("jitter", jitter)) if v is not None}
    return sym("runtime.providers", "RetryPolicy")(**kw)


# =================================================================================================
# Faults (C1, C17, PA-15)
# =================================================================================================

def http_error(status: int, model: str = "fake", *, retry_after: str | None = None) -> BaseException:
    from pydantic_ai.exceptions import ModelHTTPError

    headers = {"retry-after": retry_after} if retry_after is not None else {}
    return ModelHTTPError(status, model, body={"error": {"message": f"status {status}"}},
                          headers=headers)


def no_response(model: str = "fake") -> BaseException:
    """A request that got no response (a timeout): `ModelAPIError` with no status (PA-15)."""
    return S.provider_timeout(model)


def connection_error(model: str = "fake") -> BaseException:
    from pydantic_ai.exceptions import ModelAPIError

    return ModelAPIError(model, "Connection error.")


def server_disconnected(model: str = "fake") -> BaseException:
    """No response, in words the suite never otherwise uses (httpx's own text for a peer that
    closed the connection): the design classifies by "status code or its absence; body text
    never parsed", so this is exactly as temporary as a timeout."""
    from pydantic_ai.exceptions import ModelAPIError

    return ModelAPIError(model, "Server disconnected without sending a response.")


def opaque_api_error(model: str = "fake") -> BaseException:
    """A status-less model API error whose message names nothing at all."""
    from pydantic_ai.exceptions import ModelAPIError

    return ModelAPIError(model, "zq-7f3a")


Fault = Callable[[], BaseException]


# =================================================================================================
# Faults inside exception groups (D6: the human's ruling after code review)
# =================================================================================================

#: The message every group this suite builds carries — the words pydantic-ai/anyio-style bundling
#: of concurrent tool-task failures would use; nothing reads it.
GROUP_MESSAGE = "unhandled errors in a task group"


def exception_group(*members: Fault) -> Fault:
    """A fault raising ONE `ExceptionGroup` around `members()`, each built when it is raised (a
    member may itself be an `exception_group(...)`, which nests)."""
    return lambda: ExceptionGroup(GROUP_MESSAGE, [m() for m in members])


def ordinary_error(detail: str = "a sibling tool task broke") -> Fault:
    """A non-provider failure for a group's other member (O2: never a provider end)."""
    return lambda: RuntimeError(detail)


#: The grouped shapes a `ProviderDown` can arrive in, keyed by test id. `flat`: the group holds
#: it alone; `nested`: a group inside a group holds it (a one-level peel misses it); `mixed`:
#: a group holding an ordinary error FIRST and it second (a reader of `exceptions[0]`, or an
#: peel of one-member groups only, misses it). A group with NO `ProviderDown` is the control
#: (`GROUPED_WITHOUT_PROVIDER_DOWN`).
GROUPED_PROVIDER_DOWN: dict[str, Callable[[Fault], Fault]] = {
    "flat": lambda down: exception_group(down),
    "nested": lambda down: exception_group(exception_group(down)),
    "mixed": lambda down: exception_group(ordinary_error(), down),
}
GROUPED_WITHOUT_PROVIDER_DOWN: dict[str, Fault] = {
    "flat": exception_group(ordinary_error()),
    "nested": exception_group(exception_group(ordinary_error(), lambda: ValueError("another"))),
}


class Recorded:
    """A fault that keeps every exception it put on the model's path (`raised`), so a test can
    assert the fault actually fired, in the shape it claims, and compare identity with what
    escaped. A fault that could not even be built (a coined class missing) is recorded as the
    error building it raised, which is then what the model raises."""

    def __init__(self, fault: Fault) -> None:
        self.fault = fault
        self.raised: list[BaseException] = []
        self._lock = threading.Lock()

    def __call__(self) -> BaseException:
        try:
            exc = self.fault()
        except Exception as build_error:
            with self._lock:
                self.raised.append(build_error)
            raise
        with self._lock:
            self.raised.append(exc)
        return exc


def carries(exc: BaseException | None, cls: type[BaseException]) -> bool:
    """`exc` is a `cls`, or an exception group holding one at any depth."""
    if isinstance(exc, cls):
        return True
    return isinstance(exc, BaseExceptionGroup) and exc.subgroup(cls) is not None


@dataclass(frozen=True)
class Plan:
    """Which ATTEMPTS fail, and with what, as data: `fail` lists the 1-based attempts that
    raise `exc()`; `fail_from` makes every attempt from that one on raise (`fail_from=1` =
    always down); `steps` scripts attempts one by one — attempt n raises `steps[n-1]()`, or
    answers where that entry is None — and attempts past it follow `fail`/`fail_from`."""

    exc: Fault = lambda: http_error(503)
    fail: frozenset[int] = frozenset()
    fail_from: int | None = None
    steps: tuple[Fault | None, ...] = ()

    def fault(self, n: int) -> Fault | None:
        if 1 <= n <= len(self.steps):
            return self.steps[n - 1]
        if n in self.fail or (self.fail_from is not None and n >= self.fail_from):
            return self.exc
        return None


ALWAYS_503 = Plan(fail_from=1)
UP = Plan()


def first_n(n: int, exc: Fault = lambda: http_error(503)) -> Plan:
    return Plan(exc=exc, fail=frozenset(range(1, n + 1)))


def steps(*faults: Fault | None) -> Plan:
    """A plan scripted attempt by attempt (None = that attempt answers); every attempt past
    the script answers."""
    return Plan(steps=tuple(faults))


# =================================================================================================
# A fake timeline: one clock, one sleep (the sleep advances the clock)
# =================================================================================================

class Timeline:
    """`RetryPolicy`'s `sleep` and `clock` over one fake time line. Every wait the retrier asks
    for is recorded and advances the clock; a model fault can advance it too (`advance`), which
    is how "an attempt that hangs until its timeout" is expressed without waiting for real."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start
        self.waits: list[float] = []

    def clock(self) -> float:
        return self.now

    async def sleep(self, seconds: float) -> None:
        self.waits.append(float(seconds))
        self.now += float(seconds)
        await asyncio.sleep(0)

    def advance(self, seconds: float) -> None:
        self.now += seconds

    def policy(self, jitter: float = 0.5) -> Any:
        return retry_policy(sleep=self.sleep, clock=self.clock, jitter=lambda: jitter)


def instant_policy() -> Any:
    """The retrier with no waiting at all (a fresh `Timeline`'s sleep)."""
    return Timeline().policy()


# =================================================================================================
# Model doubles that fail per ATTEMPT
# =================================================================================================

def dump(messages: Sequence[Any]) -> list[Any]:
    """Messages as JSON data, for comparing what two attempts received."""
    from pydantic_ai.messages import ModelMessagesTypeAdapter

    return json.loads(ModelMessagesTypeAdapter.dump_json(list(messages)))


class Attempts:
    """A `FunctionModel` function: each call is one wire attempt. Attempts the plan fails raise;
    the rest are answered by `answer(messages, info)` (default: one text part). Records every
    attempt's inbound messages (as JSON data) and model settings (`settings`) and, with a
    `timeline`, the fake time each attempt began; `hang_s` advances that timeline per FAILED
    attempt (an attempt that hung to its timeout)."""

    __name__ = "Attempts"

    def __init__(self, plan: Plan = UP, *, answer: Callable[[Any, Any], Any] | None = None,
                 timeline: Timeline | None = None, hang_s: float = 0.0, text: str = "done") -> None:
        self.plan = plan
        self._answer = answer
        self.timeline = timeline
        self.hang_s = hang_s
        self.text = text
        self.inbound: list[list[Any]] = []
        self.settings: list[Any] = []
        self.began: list[float] = []
        self.raised: list[BaseException] = []
        self._lock = threading.Lock()

    def __call__(self, messages: Any, info: Any) -> Any:
        from pydantic_ai.messages import ModelResponse, TextPart

        with self._lock:
            self.inbound.append(dump(messages))
            settings = getattr(info, "model_settings", None)
            self.settings.append(dict(settings) if settings is not None else None)
            if self.timeline is not None:
                self.began.append(self.timeline.now)
            n = len(self.inbound)
            fault = self.plan.fault(n)
            if fault is not None:
                if self.timeline is not None and self.hang_s:
                    self.timeline.advance(self.hang_s)
                exc = fault()
                self.raised.append(exc)
                raise exc
        if self._answer is not None:
            return self._answer(messages, info)
        return ModelResponse(parts=[TextPart(content=self.text)])

    @property
    def attempts(self) -> int:
        return len(self.inbound)


def function_model(fn: Callable[..., Any]) -> Any:
    from pydantic_ai.models.function import FunctionModel

    return FunctionModel(fn)


def run_agent(model: Any, prompt: str = "hello", **kw: Any) -> Any:
    """One `Agent(model).run(prompt)` on a fresh loop; `kw` goes to `Agent(...)` except
    `usage_limits`, which goes to `run`."""
    from pydantic_ai import Agent

    limits = kw.pop("usage_limits", None)
    agent = Agent(model, **kw)
    return asyncio.run(agent.run(prompt, usage_limits=limits))


class MainFailing(S.MainScript):
    """MAIN's double (`_spec1222.MainScript`) behind a per-ATTEMPT fault plan: an attempt the
    plan fails raises before the script sees it, so the script's turns line up with the
    requests that succeeded. `attempts` counts every attempt; `inbound` holds each one's
    messages."""

    __name__ = "MainFailing"

    def __init__(self, turns: Sequence[S.Turn] | None = None, plan: Plan = UP) -> None:
        super().__init__(turns)
        self._attempts = Attempts(plan, answer=lambda m, i: S.MainScript.__call__(self, m, i))

    def __call__(self, messages: Any, info: Any) -> Any:
        return self._attempts(messages, info)

    @property
    def attempts(self) -> int:
        return self._attempts.attempts

    @property
    def inbound(self) -> list[list[Any]]:
        return self._attempts.inbound


class LeadsFailing(S.LeadRouter):
    """The gather double (`_spec1222.LeadRouter`) behind a per-lead, per-ATTEMPT fault plan: an
    attempt a lead's plan fails raises before the lead's script sees it. `attempts(lead)` counts
    every attempt, failed ones included."""

    __name__ = "LeadsFailing"

    def __init__(self, scripts: Mapping[str, Sequence[S.Turn]] | None = None,
                 plans: Mapping[str, Plan] | None = None, **kw: Any) -> None:
        super().__init__(scripts, **kw)
        self.plans = dict(plans or {})
        self.inbound: dict[str, list[list[Any]]] = {}
        self._attempt_lock = threading.Lock()

    def __call__(self, messages: Any, info: Any) -> Any:
        lead = S.dispatch_lead_id(messages)
        assert lead is not None, "a gather conversation with no Dispatch lead id"
        with self._attempt_lock:
            seen = self.inbound.setdefault(lead, [])
            seen.append(dump(messages))
            n = len(seen)
        plan = self.plans.get(lead)
        fault = plan.fault(n) if plan is not None else None
        if fault is not None:
            raise fault()
        return super().__call__(messages, info)

    def attempts(self, lead: str) -> int:
        return len(self.inbound.get(lead, []))


def wrap_with(policy: Any, *, kinds: Iterable[str] = ("main", "gather")) -> Callable[[str, Any], Any]:
    """`drive(wrap_model=...)`: the REAL retrier over the named kinds' scripted models."""
    chosen = frozenset(kinds)

    def wrap(kind: str, model: Any) -> Any:
        return with_retries(model, policy) if kind in chosen else model

    return wrap


# =================================================================================================
# Observation channels
# =================================================================================================

_NUMBER = re.compile(r"\d+(?:\.\d+)?")


def numbers_besides(message: str, *, status: int | None = None, spelled: Iterable[str] = ()) -> list[float]:
    """The numbers a retry line carries besides the ones it names for other reasons: `status`
    (removed only as a whole number, so a wait such as `5.03` survives) and every string in
    `spelled` (the model name, `n/4`). What is left holds the wait (coined: in seconds)."""
    text = message
    for s in spelled:
        if s:
            text = text.replace(s, " ")
    if status is not None:
        text = re.sub(rf"(?<![\d.]){status}(?![\d.])", " ", text)
    return [float(m) for m in _NUMBER.findall(text)]


def sessions(store_path: Path) -> dict[str, str | None]:
    """agent_id -> `truncated_by` for every session in the real store file (a fresh connection,
    so a store the run closed still reads). Asserts each agent has one session."""
    con = sqlite3.connect(str(store_path))
    try:
        rows = con.execute("SELECT agent_id, truncated_by FROM session").fetchall()
    finally:
        con.close()
    out: dict[str, str | None] = {}
    for agent_id, truncated_by in rows:
        assert agent_id not in out, f"two sessions for {agent_id}: {rows!r}"
        out[agent_id] = truncated_by
    return out


def session_rows(store_path: Path) -> dict[str, list[tuple[str, str | None]]]:
    """agent_id -> its stored messages as `(kind, tool_name)` in order — the "one set of store
    rows" channel (P3): a run whose request was retried stores what a clean run stores."""
    con = sqlite3.connect(str(store_path))
    try:
        rows = con.execute(
            "SELECT s.agent_id, m.kind, m.tool_name FROM message m "
            "JOIN session s ON s.session_id = m.session_id ORDER BY m.session_id, m.seq, m.id"
        ).fetchall()
    finally:
        con.close()
    out: dict[str, list[tuple[str, str | None]]] = {}
    for agent_id, kind, tool_name in rows:
        out.setdefault(agent_id, []).append((kind, tool_name))
    return out


def gather_agent(lead: str) -> str:
    return f"{sym('runtime.agent_role', 'GATHER_AGENT_ID_PREFIX')}{lead}"


def sidecar(run_dir: Path) -> dict[str, Any] | None:
    """The host-side run-end record beside `run_dir`, parsed by the production reader."""
    path = RunPaths(run_dir).run_end_sidecar()
    if not path.is_file():
        return None
    doc = json.loads(path.read_text(encoding="utf-8"))
    rec = sym("runtime.run_end", "parse_record")(doc)
    return None if rec is None else {"truncated_by": rec.truncated_by,
                                     "closed_before_cut": rec.closed_before_cut, "raw": doc}


def wire_responses(run_dir: Path, agent_id: str) -> list[dict[str, Any]]:
    """The wire log's response records for one agent — one per request the run made (P3)."""
    from defender._io import read_jsonl_rows

    path = RunPaths(run_dir).wire_log
    if not path.is_file():
        return []
    return [r for r in read_jsonl_rows(path)
            if r.get("agent_id") == agent_id and r.get("kind") == "response"]


def trace_rows(run_dir: Path, role: str) -> list[dict[str, Any]]:
    """A review role's trace rows (raw reply lines between rows are skipped, as readers do)."""
    from defender._io import read_jsonl_rows

    path = RunPaths(run_dir).review_trace(role)
    if not path.is_file():
        return []
    return [r for r in read_jsonl_rows(path) if isinstance(r, dict)]


def assert_ended_provider_down(d: S.Drive, *, rc: bool = True) -> None:
    """The run ended `provider-down` through a run-level end (O3): no crash, the summary and the
    run-end record name the class, the exit reason says so, no report.md (O4), exit 4 (D4)."""
    assert d.raised is None, f"the run crashed instead of ending provider-down: {d.raised!r}"
    summary = d.summary or {}
    assert summary.get("truncated_by") == PROVIDER_DOWN, (
        f"the run did not end provider-down: truncated_by {summary.get('truncated_by')!r}, "
        f"exit {summary.get('exit_reason')!r}")
    reason = str(summary.get("exit_reason") or "")
    assert "provider" in reason.lower(), (
        f"the exit reason does not say the provider was down: {reason!r}")
    rec = sidecar(d.folder)
    assert rec is not None, "no run-end record (or one the production reader refuses)"
    assert rec["truncated_by"] == PROVIDER_DOWN, rec
    assert not d.paths.report.exists(), (
        "a provider-down run wrote report.md — an infrastructure end writes no report (O4, C15)")
    if rc:
        assert d.rc == PROVIDER_DOWN_EXIT, (
            f"run.py exited {d.rc!r} on a provider-down run; D4 says {PROVIDER_DOWN_EXIT}")


# =================================================================================================
# A local fake provider over real HTTP (P1: the real builders, the real client libraries)
# =================================================================================================

ANTHROPIC_OK = {
    "id": "msg_1243", "type": "message", "role": "assistant", "model": "claude-test-1243",
    "content": [{"type": "text", "text": "wire-ok"}], "stop_reason": "end_turn",
    "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 1},
}
OPENAI_OK = {
    "id": "chatcmpl-1243", "object": "chat.completion", "created": 0, "model": "m",
    "choices": [{"index": 0, "message": {"role": "assistant", "content": "wire-ok"},
                 "finish_reason": "stop"}],
    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
}


@dataclass
class WireAnswer:
    status: int
    body: Mapping[str, Any]
    headers: Mapping[str, str] = field(default_factory=dict)


def wire_error(status: int, *, retry_after: str | None = None) -> WireAnswer:
    headers = {"retry-after": retry_after} if retry_after is not None else {}
    return WireAnswer(status, {"type": "error", "error": {"type": "overloaded_error",
                                                          "message": f"status {status}"}}, headers)


class FakeProvider:
    """A provider endpoint on 127.0.0.1: answers each POST from `answers` in order (the last one
    repeats) and counts every hit, with the real monotonic time it arrived (`hit_times`). A
    context manager; `url` is its base URL."""

    def __init__(self, answers: Sequence[WireAnswer]) -> None:
        assert answers, "a fake provider needs at least one answer"
        self.answers = list(answers)
        self.hits: list[str] = []
        self.hit_times: list[float] = []
        self._lock = threading.Lock()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:  # noqa: N802 — the stdlib's name
                length = int(self.headers.get("content-length") or 0)
                self.rfile.read(length)
                with owner._lock:
                    owner.hits.append(self.path)
                    owner.hit_times.append(time.monotonic())
                    answer = owner.answers[min(len(owner.hits), len(owner.answers)) - 1]
                payload = json.dumps(answer.body).encode("utf-8")
                self.send_response(answer.status)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(payload)))
                for k, v in answer.headers.items():
                    self.send_header(k, v)
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_a: Any) -> None:
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def __enter__(self) -> FakeProvider:
        self._thread.start()
        return self

    def __exit__(self, *_exc: Any) -> None:
        self._server.shutdown()
        self._server.server_close()


class RefusingProxy:
    """An HTTP proxy on 127.0.0.1 that refuses every tunnel: each `CONNECT host:port` is counted
    (`hits`, the target) and answered 502, so a client sent through it (`HTTPS_PROXY`) gets no
    response from the provider at all — a connection error — and nothing leaves the host.

    The channel for the OpenAI-compatible provider's REAL base URL, which the builder hard-codes
    (https, so it cannot be pointed at `FakeProvider`): the client libraries read the proxy
    from the environment when the builder constructs them (C1 probe: today's Fireworks client
    makes 3 tunnels through it)."""

    def __init__(self) -> None:
        self.hits: list[str] = []
        self._lock = threading.Lock()
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_CONNECT(self) -> None:  # noqa: N802 — the stdlib's name
                with owner._lock:
                    owner.hits.append(self.path)
                self.send_response(502)
                self.send_header("content-length", "0")
                self.end_headers()

            def log_message(self, *_a: Any) -> None:
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        host, port = self._server.server_address[:2]
        return f"http://{host}:{port}"

    def __enter__(self) -> RefusingProxy:
        self._thread.start()
        return self

    def __exit__(self, *_exc: Any) -> None:
        self._server.shutdown()
        self._server.server_close()


#: The proxy variables a client library reads; every one is set or cleared by `through_proxy`.
_PROXY_VARS = ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY",
               "all_proxy", "NO_PROXY", "no_proxy")


def through_proxy(monkeypatch: Any, proxy: RefusingProxy) -> None:
    """Every https request a client library built from here on makes goes to `proxy`: the https
    proxy variables name it, every other proxy variable (and the no-proxy list) is cleared."""
    for var in _PROXY_VARS:
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("HTTPS_PROXY", proxy.url)
    monkeypatch.setenv("https_proxy", proxy.url)


def closed_port_url() -> str:
    """A base URL nothing listens on: every connection is refused (no response at all)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    return f"http://127.0.0.1:{port}"


ANTHROPIC_NAME = "claude-test-1243"
