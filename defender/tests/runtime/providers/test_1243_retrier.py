from __future__ import annotations

import asyncio
import contextlib
import logging
from pathlib import Path
from typing import Any

import pytest


from defender.tests.tenancy.alert_front_door_1222 import _spec1222 as S
from defender.tests.runtime.providers import _spec1243 as P


def _raised(fn: Any) -> BaseException:
    """What `fn()` raised — any exception, since which one is the observation."""
    try:
        fn()
    except BaseException as e:  # noqa: BLE001 — the type is asserted by the caller
        return e
    pytest.fail("the call returned; it was expected to raise")


def _down(exc: BaseException) -> Any:
    assert isinstance(exc, P.provider_down_cls()), (
        f"an exhausted retry raised {type(exc).__name__}: {exc!r}, not ProviderDown")
    return exc


def _retry_lines(caplog: pytest.LogCaptureFixture) -> list[str]:
    """The retry lines: WARNING records naming an attempt out of 4 (whatever else they say —
    what they must say is each test's assertion)."""
    return [r.getMessage() for r in caplog.records
            if r.levelno == logging.WARNING and "/4" in r.getMessage()]


def _names_the_wait(msg: str, wait: float, *, n: int, model_name: str,
                    status: int | None = None) -> bool:
    """`msg` carries `wait` (seconds, to within 5% or 0.05 s) as a number of its own — not one
    of the numbers it names for other reasons (status, `n/4`, the model name)."""
    nums = P.numbers_besides(msg, status=status, spelled=(model_name, f"{n}/4"))
    return any(abs(x - wait) <= max(0.05, 0.05 * wait) for x in nums)


@pytest.mark.parametrize("status", P.RETRIED_STATUSES)
def test_o1_a_temporary_status_is_retried_and_success_after_a_retry_is_a_plain_success(status: int) -> None:
    t = P.Timeline()
    fake = P.Attempts(P.first_n(2, lambda: P.http_error(status)), timeline=t, text="answered")
    result = P.run_agent(P.with_retries(P.function_model(fake), t.policy()))
    assert fake.attempts == 3, f"{status}: {fake.attempts} attempts; two failures then a success is 3"
    assert result.output == "answered"


@pytest.mark.parametrize("make", [P.no_response, P.connection_error, P.server_disconnected,
                                  P.opaque_api_error],
                         ids=["timeout", "connection", "server-disconnected", "opaque-message"])
def test_o1_no_response_is_retried(make: Any) -> None:
    t = P.Timeline()
    fake = P.Attempts(P.first_n(1, make), timeline=t)
    result = P.run_agent(P.with_retries(P.function_model(fake), t.policy()))
    assert fake.attempts == 2
    assert result.output == "done"


def test_o1_at_most_four_wire_attempts_then_provider_down_from_the_original() -> None:
    t = P.Timeline()
    fake = P.Attempts(P.ALWAYS_503, timeline=t)
    model = P.function_model(fake)
    wrapped = P.with_retries(model, t.policy())
    caught = _raised(lambda: P.run_agent(wrapped))
    down = _down(caught)
    assert fake.attempts == P.MAX_ATTEMPTS, f"{fake.attempts} wire attempts; the bound is 4"
    assert down.attempts == P.MAX_ATTEMPTS
    assert down.status == 503
    assert down.model == model.model_name
    assert down.__cause__ is fake.raised[-1], (
        "ProviderDown is not raised from the last original error")


def test_o1_provider_down_after_no_response_says_no_status() -> None:
    """O1: exhausted on no response, `ProviderDown.status` is None ("no response"), and the
    original timeout is its cause."""
    t = P.Timeline()
    fake = P.Attempts(P.Plan(exc=P.no_response, fail_from=1), timeline=t)
    wrapped = P.with_retries(P.function_model(fake), t.policy())
    caught = _raised(lambda: P.run_agent(wrapped))
    down = _down(caught)
    assert down.status is None
    assert down.attempts == fake.attempts == P.MAX_ATTEMPTS
    assert down.__cause__ is fake.raised[-1]


def test_o1_every_attempt_sends_the_same_request() -> None:
    settings = {"temperature": 0.0, "max_tokens": 77}
    t = P.Timeline()
    fake = P.Attempts(P.first_n(3), timeline=t)
    P.run_agent(P.with_retries(P.function_model(fake), t.policy()), "the one prompt",
                model_settings=settings)
    assert fake.attempts == 4
    first = fake.inbound[0]
    for n, inbound in enumerate(fake.inbound[1:], start=2):
        assert inbound == first, f"attempt {n} sent something other than attempt 1 did"
    assert "retry-prompt" not in str(first)
    # The settings channel carries the caller's values on attempt 1 (so equality below is not
    # two empty readings), and every retry carries the same.
    assert fake.settings[0] is not None, "attempt 1 carried no model settings at all"
    assert fake.settings[0].get("max_tokens") == 77, (
        f"attempt 1 did not carry the caller's model settings: {fake.settings[0]!r}")
    for n, got in enumerate(fake.settings[1:], start=2):
        assert got == fake.settings[0], (
            f"attempt {n} was sent with model settings {got!r}, attempt 1 with "
            f"{fake.settings[0]!r}: a retry is the same request")


def _first_wait(exc: Any, jitter: float = 0.5) -> float:
    """The retrier's own wait before its first retry after `exc()`, on a fake timeline."""
    t = P.Timeline()
    fake = P.Attempts(P.first_n(1, exc), timeline=t)
    P.run_agent(P.with_retries(P.function_model(fake), t.policy(jitter)))
    assert t.waits, "the retrier never waited before retrying"
    return t.waits[0]


@pytest.mark.parametrize("status", [429, 503, 529])
def test_o1_retry_after_is_honoured(status: int) -> None:
    own = _first_wait(lambda: P.http_error(status))
    header = int(own) + 100
    assert header < P.WINDOW_S, f"the header-less first wait is already {own}s"
    t = P.Timeline()
    fake = P.Attempts(P.first_n(1, lambda: P.http_error(status, retry_after=str(header))),
                      timeline=t)
    P.run_agent(P.with_retries(P.function_model(fake), t.policy()))
    assert fake.attempts == 2
    assert t.waits, "the retrier never waited"
    assert t.waits[0] >= header, (
        f"{status} with Retry-After: {header} was not honoured: waited {t.waits[0]}s "
        f"(own backoff {own}s)")


@pytest.mark.parametrize(("header", "may_stop"), [
    ("abc", False),
    ("", False),
    ("-5", False),
    ("Wed, 21 Oct 2015 07:28:00 GMT", False),
    ("1e999", True),
    ("Fri, 01 Jan 2100 00:00:00 GMT", True),
], ids=["word", "empty", "negative", "http-date-past", "overflow", "http-date-future"])
def test_o1_a_retry_after_that_is_not_a_number_of_seconds_is_never_a_crash(header: str,
                                                                            may_stop: bool) -> None:
    t = P.Timeline()
    fake = P.Attempts(P.first_n(1, lambda: P.http_error(429, retry_after=header)), timeline=t)
    wrapped = P.with_retries(P.function_model(fake), t.policy())
    ended: Any
    try:
        ended = P.run_agent(wrapped)
    except BaseException as e:  # noqa: BLE001 — which one is the observation
        ended = e
    if isinstance(ended, BaseException):
        assert isinstance(ended, P.provider_down_cls()), (
            f"Retry-After: {header!r} on a 429 ended the request with {type(ended).__name__}: "
            f"{ended!r} after {fake.attempts} attempt(s) — neither a retry nor ProviderDown")
        assert may_stop, (
            f"Retry-After: {header!r} names no wait past the window, yet the retrier gave up "
            f"after {fake.attempts} attempt(s) with {ended!r}: the 429 is still temporary")
        return
    assert fake.attempts == 2, f"{fake.attempts} attempts; one 429 then an answer is 2"
    assert ended.output == "done"


def test_o1_retry_after_past_the_window_never_spends_past_it() -> None:
    t = P.Timeline()
    start = t.now
    fake = P.Attempts(P.Plan(exc=lambda: P.http_error(429, retry_after="3600"), fail_from=1),
                      timeline=t)
    wrapped = P.with_retries(P.function_model(fake), t.policy())
    caught = _raised(lambda: P.run_agent(wrapped))
    _down(caught)
    assert t.now - start <= P.WINDOW_S, (
        f"the retrier spent {t.now - start}s of (fake) time on a Retry-After past the window")


def test_o1_backoff_exists_and_grows() -> None:
    t = P.Timeline()
    fake = P.Attempts(P.ALWAYS_503, timeline=t)
    wrapped = P.with_retries(P.function_model(fake), t.policy(jitter=0.5))
    _down(_raised(lambda: P.run_agent(wrapped)))
    assert len(t.waits) == 3, f"waits between 4 attempts: {t.waits}"
    assert all(w > 0 for w in t.waits), f"a retry was sent with no wait: {t.waits}"
    first, second, third = t.waits
    assert first < second, f"the backoff did not grow after the first retry: {t.waits}"
    assert second <= third, f"the backoff shrank: {t.waits}"


def test_o1_backoff_has_jitter() -> None:
    """O1 (R4): the wait depends on the policy's jitter — two jitter values give two waits."""
    low = _first_wait(lambda: P.http_error(503), jitter=0.1)
    high = _first_wait(lambda: P.http_error(503), jitter=0.9)
    assert low != high, f"jitter 0.1 and 0.9 gave the same first wait ({low}s): no jitter"


def test_o1_each_request_retries_on_its_own_window() -> None:
    """N2 (R6): the window and the attempt count belong to each request, not to the wrapper —
    a second request 700 s (fake) after the first still gets its retry."""
    t = P.Timeline()
    fake = P.Attempts(P.Plan(fail=frozenset({2})), timeline=t)
    wrapped = P.with_retries(P.function_model(fake), t.policy())
    assert P.run_agent(wrapped).output == "done"
    t.advance(700.0)
    assert P.run_agent(wrapped).output == "done", "the second request did not recover"
    assert fake.attempts == 3, f"{fake.attempts} calls; 1 + (1 failed + 1 retried) is 3"


def test_n2_a_request_after_provider_down_retries_on_its_own() -> None:
    t = P.Timeline()
    fake = P.Attempts(P.steps(*[lambda: P.http_error(503)] * 5), timeline=t)
    wrapped = P.with_retries(P.function_model(fake), t.policy())
    down = _down(_raised(lambda: P.run_agent(wrapped)))
    assert down.attempts == fake.attempts == P.MAX_ATTEMPTS
    result = P.run_agent(wrapped)
    assert result.output == "done", "the request after a ProviderDown did not recover"
    assert fake.attempts == P.MAX_ATTEMPTS + 2, (
        f"{fake.attempts} attempts in all: the second request's own 503 and its retry are 2 more")


@pytest.mark.parametrize(("plan", "last_status"), [
    ((lambda: P.http_error(503),) * 3 + (P.no_response,), None),
    ((P.no_response,) * 3 + (lambda: P.http_error(529),), 529),
    ((lambda: P.http_error(503), lambda: P.http_error(429), P.connection_error,
      lambda: P.http_error(502)), 502),
], ids=["5xx-then-timeout", "timeouts-then-529", "mixed-ending-502"])
def test_o1_provider_down_names_the_last_failure(plan: tuple[Any, ...], last_status: int | None) -> None:
    """Design: `ProviderDown` carries "the LAST status or 'no response'" — the failure the
    provider ended on, not the first one it met — and is raised from that last error."""
    t = P.Timeline()
    fake = P.Attempts(P.steps(*plan), timeline=t)
    wrapped = P.with_retries(P.function_model(fake), t.policy())
    down = _down(_raised(lambda: P.run_agent(wrapped)))
    assert fake.attempts == P.MAX_ATTEMPTS
    assert down.status == last_status, (
        f"ProviderDown.status is {down.status!r}; the last failure was {fake.raised[-1]!r}")
    assert down.__cause__ is fake.raised[-1], "ProviderDown is not raised from the last error"


def test_p2_provider_down_is_an_ordinary_exception() -> None:
    """P2 (R5): `ProviderDown` is an `Exception`, so every caller's existing `except Exception`
    catch-all outside a run (oracle, learning stage) still decides what it means."""
    assert issubclass(P.provider_down_cls(), Exception)


@pytest.mark.parametrize("hang_s", [250.0, 400.0, 550.0])
def test_o1_no_attempt_starts_ten_minutes_after_the_first_began(hang_s: float) -> None:
    t = P.Timeline()
    fake = P.Attempts(P.Plan(exc=P.no_response, fail_from=1), timeline=t, hang_s=hang_s)
    wrapped = P.with_retries(P.function_model(fake), t.policy())
    caught = _raised(lambda: P.run_agent(wrapped))
    down = _down(caught)
    began = fake.began
    assert began, "no attempt was made"
    late = [b - began[0] for b in began if b - began[0] >= P.WINDOW_S]
    assert not late, f"attempts started {late}s after the first — past the 10-minute window"
    assert fake.attempts < P.MAX_ATTEMPTS, (
        f"{fake.attempts} attempts of {hang_s} s each: the 4th could only start past the window")
    assert down.attempts == fake.attempts


def test_o1_short_hangs_still_get_all_four_attempts() -> None:
    """O1 positive control for the window: attempts that time out quickly (10 s) all start inside
    10 minutes, so the bound of 4 is reached."""
    t = P.Timeline()
    fake = P.Attempts(P.Plan(exc=P.no_response, fail_from=1), timeline=t, hang_s=10.0)
    wrapped = P.with_retries(P.function_model(fake), t.policy())
    caught = _raised(lambda: P.run_agent(wrapped))
    assert _down(caught).attempts == fake.attempts == P.MAX_ATTEMPTS


def test_o1_each_retry_logs_one_warning(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING)
    t = P.Timeline()
    fake = P.Attempts(P.first_n(2, lambda: P.http_error(529)), timeline=t)
    model = P.function_model(fake)
    caplog.clear()
    P.run_agent(P.with_retries(model, t.policy()))
    lines = _retry_lines(caplog)
    assert len(lines) == 2, [r.getMessage() for r in caplog.records]
    assert len(t.waits) == 2, t.waits
    for n, (msg, wait) in enumerate(zip(lines, t.waits, strict=True), start=2):
        assert "529" in msg, f"the retry warning does not name the status: {msg!r}"
        assert f"{n}/4" in msg, f"the retry warning does not name attempt {n}/4: {msg!r}"
        assert model.model_name in msg, (
            f"the retry warning does not name its call site ({model.model_name!r}): {msg!r}")
        assert _names_the_wait(msg, wait, n=n, model_name=model.model_name, status=529), (
            f"the retry warning does not name its wait ({wait}s): {msg!r}")


def test_o1_a_retry_after_no_response_logs_its_warning_too(caplog: pytest.LogCaptureFixture) -> None:
    """O1: "each retry logs one warning line" — a retry after NO response (a timeout) as much
    as one after a status: one line, naming the call site, the attempt (2/4) and the wait."""
    caplog.set_level(logging.WARNING)
    t = P.Timeline()
    fake = P.Attempts(P.first_n(1, P.no_response), timeline=t)
    model = P.function_model(fake)
    caplog.clear()
    P.run_agent(P.with_retries(model, t.policy()))
    assert fake.attempts == 2
    lines = _retry_lines(caplog)
    assert len(lines) == 1, (
        f"a retry after no response logged {len(lines)} retry lines: "
        f"{[r.getMessage() for r in caplog.records]}")
    msg = lines[0]
    assert "2/4" in msg, msg
    assert model.model_name in msg, (
        f"the retry warning does not name its call site ({model.model_name!r}): {msg!r}")
    assert t.waits, "the retrier never waited"
    assert _names_the_wait(msg, t.waits[0], n=2, model_name=model.model_name), (
        f"the retry warning does not name its wait ({t.waits[0]}s): {msg!r}")


def test_o1_a_cancelled_caller_cuts_the_backoff() -> None:
    from pydantic_ai.messages import ModelRequest, UserPromptPart
    from pydantic_ai.models import ModelRequestParameters

    async def scenario() -> tuple[Any, int]:
        waiting = asyncio.Event()

        async def sleep(_seconds: float) -> None:
            # Only the first backoff stalls (that is where the cancel lands); a retrier that
            # swallowed the cancel then runs on at once and is seen doing so, not hung.
            if waiting.is_set():
                return
            waiting.set()
            await asyncio.sleep(3600)

        fake = P.Attempts(P.ALWAYS_503)
        model = P.with_retries(P.function_model(fake), P.retry_policy(sleep=sleep))
        request = model.request([ModelRequest(parts=[UserPromptPart("hello")])], None,
                                ModelRequestParameters())
        task = asyncio.ensure_future(request)
        await asyncio.wait_for(waiting.wait(), timeout=10)
        task.cancel()
        try:
            await asyncio.wait_for(task, timeout=10)
        except asyncio.CancelledError:
            return "cancelled", fake.attempts
        except BaseException as e:  # noqa: BLE001 — the observation is which exception
            return e, fake.attempts
        return "returned", fake.attempts

    outcome, attempts = asyncio.run(scenario())
    assert outcome == "cancelled", f"a request cancelled mid-backoff ended with {outcome!r}"
    assert attempts == 1, f"{attempts} attempts: the backoff was not where the cancel landed"


class _HangsFirst:
    """A model function whose FIRST attempt hangs `hang_s` on the event loop (a provider that
    accepted the connection and went quiet — cancellable, as a real socket read is) before
    answering; every later attempt answers at once. `started` is set when attempt 1 begins."""

    def __init__(self, hang_s: float) -> None:
        self.hang_s = hang_s
        self.attempts = 0
        self.started = asyncio.Event()

    def model(self) -> Any:
        from pydantic_ai.messages import ModelResponse, TextPart

        async def hangs_first(_messages: Any, _info: Any) -> Any:
            self.attempts += 1
            if self.attempts == 1:
                self.started.set()
                await asyncio.sleep(self.hang_s)
                return ModelResponse(parts=[TextPart(content="first")])
            return ModelResponse(parts=[TextPart(content="late")])

        return P.function_model(hangs_first)


def _one_request(model: Any) -> Any:
    from pydantic_ai.messages import ModelRequest, UserPromptPart
    from pydantic_ai.models import ModelRequestParameters

    return model.request([ModelRequest(parts=[UserPromptPart("hello")])], None,
                         ModelRequestParameters())


@pytest.mark.parametrize(("hang_s", "expect"), [(30.0, "timed out"), (0.05, "first")],
                         ids=["hung-attempt", "control-quick-attempt"])
def test_o1_a_deadline_landing_during_a_hung_attempt_ends_the_request(hang_s: float, expect: str) -> None:
    async def scenario() -> tuple[Any, int, float]:
        hang = _HangsFirst(hang_s)
        model = P.with_retries(hang.model(), P.instant_policy())
        loop = asyncio.get_running_loop()
        began = loop.time()
        try:
            async with asyncio.timeout(0.3):
                response = await _one_request(model)
        except TimeoutError:
            return "timed out", hang.attempts, loop.time() - began
        except BaseException as e:  # noqa: BLE001 — the observation is which exception
            return e, hang.attempts, loop.time() - began
        text = "".join(getattr(p, "content", "") for p in response.parts)
        return text, hang.attempts, loop.time() - began

    outcome, attempts, elapsed = asyncio.run(scenario())
    assert outcome == expect, (
        f"a 0.3 s deadline over a first attempt hanging {hang_s}s ended with {outcome!r} after "
        f"{attempts} attempt(s)")
    assert attempts == 1, f"{attempts} attempts: the cut attempt was retried"
    assert elapsed < 5.0, f"the request outlived its deadline by {elapsed:.1f}s"


def test_o1_a_cancel_landing_during_a_hung_attempt_ends_cancelled() -> None:
    async def scenario() -> tuple[Any, int]:
        hang = _HangsFirst(30.0)
        model = P.with_retries(hang.model(), P.instant_policy())
        task = asyncio.ensure_future(_one_request(model))
        await asyncio.wait_for(hang.started.wait(), timeout=10)
        task.cancel()
        try:
            await asyncio.wait_for(task, timeout=10)
        except asyncio.CancelledError:
            return "cancelled", hang.attempts
        except BaseException as e:  # noqa: BLE001 — the observation is which exception
            return e, hang.attempts
        return "returned", hang.attempts

    outcome, attempts = asyncio.run(scenario())
    assert outcome == "cancelled", f"a request cancelled mid-attempt ended with {outcome!r}"
    assert attempts == 1, f"{attempts} attempts: the cancelled attempt was retried"


def test_o1_the_default_policy_waits_and_reads_time_for_real() -> None:
    policy = P.retry_policy()

    async def scenario() -> tuple[float, float, str, float]:
        loop = asyncio.get_running_loop()
        began, clock_began = loop.time(), policy.clock()
        await policy.sleep(0.3)
        slept, clocked = loop.time() - began, policy.clock() - clock_began
        cut_began = loop.time()
        try:
            await asyncio.wait_for(policy.sleep(5.0), timeout=0.2)
            cut = "not cut"
        except TimeoutError:
            cut = "cut"
        return slept, clocked, cut, loop.time() - cut_began

    slept, clocked, cut, cut_after = asyncio.run(scenario())
    assert slept >= 0.25, f"the default sleep asked for 0.3 s returned after {slept:.3f}s"
    assert clocked >= 0.25, f"the default clock moved {clocked:.3f}s across a 0.3 s sleep"
    assert cut == "cut", (
        f"a 0.2 s deadline over the default 5 s sleep was {cut}: the default sleep is not "
        "awaited on the loop")
    assert cut_after < 2.0, (
        f"the default sleep took {cut_after:.2f}s to give way to a 0.2 s deadline: it blocks")


def test_o1_the_default_policy_jitters() -> None:
    """D1/O1 ("with jitter"): the default policy's jitter is a random draw in [0, 1) — not a
    constant, which would put every concurrent lead's retries in lockstep."""
    jitter = P.retry_policy().jitter
    draws = [jitter() for _ in range(16)]
    assert all(0.0 <= d < 1.0 for d in draws), f"default jitter outside [0, 1): {draws}"
    assert len(set(draws)) > 1, f"the default jitter drew the same value 16 times: {draws[0]}"


@pytest.mark.parametrize("status", P.NOT_RETRIED_STATUSES)
def test_o2_other_4xx_are_not_retried_and_propagate_unchanged(status: int) -> None:
    """O2 + scenario 6: every other 4xx (part 2's) gets one attempt and propagates as the very
    error the model raised — not a `ProviderDown`."""
    t = P.Timeline()
    fake = P.Attempts(P.Plan(exc=lambda: P.http_error(status), fail_from=1), timeline=t)
    wrapped = P.with_retries(P.function_model(fake), t.policy())
    caught = _raised(lambda: P.run_agent(wrapped))
    assert fake.attempts == 1, f"{status} was retried ({fake.attempts} attempts)"
    assert caught is fake.raised[0], (
        f"{status} did not propagate unchanged: got {type(caught).__name__}")
    assert t.waits == []


@pytest.mark.parametrize("make", [
    lambda: RuntimeError("not a provider fault"),
    lambda: S.unexpected_behavior("model misbehaved"),
], ids=["runtime-error", "unexpected-behavior"])
def test_o2_non_provider_errors_are_not_retried(make: Any) -> None:
    """O2: an error that is not a provider failure gets one attempt and propagates unchanged."""
    t = P.Timeline()
    fake = P.Attempts(P.Plan(exc=make, fail_from=1), timeline=t)
    wrapped = P.with_retries(P.function_model(fake), t.policy())
    caught = _raised(lambda: P.run_agent(wrapped))
    assert fake.attempts == 1
    assert caught is fake.raised[0]


@pytest.mark.parametrize(("first", "then"), [
    (lambda: P.http_error(503), lambda: P.http_error(400)),
    (P.no_response, lambda: P.http_error(401)),
    (lambda: P.http_error(529), lambda: RuntimeError("not a provider fault")),
], ids=["503-then-400", "timeout-then-401", "529-then-runtime-error"])
def test_o2_a_rejection_after_a_temporary_failure_propagates_unchanged(first: Any, then: Any) -> None:
    t = P.Timeline()
    fake = P.Attempts(P.steps(first, then), timeline=t)
    wrapped = P.with_retries(P.function_model(fake), t.policy())
    caught = _raised(lambda: P.run_agent(wrapped))
    assert fake.attempts == 2, f"{fake.attempts} attempts; the second failure is not retried"
    assert caught is fake.raised[1], (
        f"the second error did not propagate unchanged: got {type(caught).__name__}: {caught!r}")


def test_p3_a_retried_request_is_one_request_against_the_limit() -> None:
    """P3 (C3): two temporary failures then a success count as ONE request against the request
    limit, and the history processors run once."""
    from pydantic_ai.capabilities import ProcessHistory
    from pydantic_ai.usage import UsageLimits

    processed = {"n": 0}

    async def count(messages: list) -> list:
        processed["n"] += 1
        return messages

    t = P.Timeline()
    fake = P.Attempts(P.first_n(2), timeline=t)
    result = P.run_agent(P.with_retries(P.function_model(fake), t.policy()),
                         capabilities=[ProcessHistory(count)],
                         usage_limits=UsageLimits(request_limit=1))
    assert fake.attempts == 3
    assert result.output == "done"
    assert result.usage.requests == 1, f"{result.usage.requests} requests counted for one request"
    assert processed["n"] == 1, f"history processed {processed['n']} times for one request"


LEAD_TURNS = [S.list_verbs("cmdb"), S.text("LEAD-1243: one host answered.")]


def _scenario1(tmp: Path, tenant: S.Planted, kind: str, plans: dict[str, P.Plan]) -> dict[str, Any]:
    """MAIN dispatches one lead (`l-001`, cmdb) that lists the system's verbs and summarizes;
    the gather model sits behind the REAL retrier (no waiting); `plans` fails attempts."""
    stores: list = []
    router = P.LeadsFailing({"l-001": LEAD_TURNS}, plans)
    d = S.run_alert(tmp, tenant=tenant,
                    main=[S.gather("l-001", "cmdb"), S.text(S.DONE)], router=router,
                    store_factory=S.store_factory(tmp, sink=stores), stores=stores,
                    wrap_model=P.wrap_with(P.instant_policy(), kinds=("gather",)))
    return {"d": d, "stores": stores, "router": router}


def test_p3_scenario1_a_lead_retried_twice_runs_as_if_it_never_failed(tmp_path: Path) -> None:
    tenant = S.plant_tenant()
    clean = _scenario1(tmp_path / "clean", tenant, "clean", {})
    retried = _scenario1(tmp_path / "retried", tenant, "retried",
                         {"l-001": P.first_n(2, lambda: P.http_error(529))})
    for run in (clean, retried):
        assert run["d"].raised is None, run["d"].raised
        assert run["router"].dispatched("l-001"), "MAIN's lead never ran"
    assert retried["router"].attempts("l-001") == clean["router"].attempts("l-001") + 2, (
        "the retried lead did not see exactly its two failed attempts on top of the clean run's")
    assert retried["d"].rc == 0, f"a recovered lead changed the run's exit: {retried['d'].rc}"
    assert (retried["d"].summary or {}).get("truncated_by") is None, retried["d"].summary
    assert "LEAD-1243" in (retried["d"].gather_summary("l-001") or ""), (
        "the recovered lead's summary did not reach the run")
    agent = P.gather_agent("l-001")
    clean_log = P.wire_responses(clean["d"].folder, agent)
    retried_log = P.wire_responses(retried["d"].folder, agent)
    assert clean_log, "the clean run logged no response for the lead"
    assert len(retried_log) == len(clean_log), (
        f"the retried lead logged {len(retried_log)} responses, the clean one {len(clean_log)}: "
        "a retry wrote a wire record of its own (P3: one record per request)")
    assert (retried["d"].summary or {}).get("requests") == (clean["d"].summary or {}).get("requests"), (
        "the retried run counted a different number of model requests than the clean run")
    assert P.session_rows(retried["stores"][-1].path) == P.session_rows(clean["stores"][-1].path), (
        "the retried run stored different rows than the clean run (P3: one set of store rows)")


def _wire_run(model: Any) -> Any:
    from pydantic_ai.models import override_allow_model_requests

    with override_allow_model_requests(True):
        return P.run_agent(model)


def test_p1_the_anthropic_builder_makes_one_wire_attempt(monkeypatch: pytest.MonkeyPatch) -> None:
    """P1: the Anthropic provider builder's client does not retry — a 503 reaches the fake
    provider exactly once through it (the client's own default is 3, C1)."""
    with P.FakeProvider([P.wire_error(503)]) as fake:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "k-1243")
        monkeypatch.setenv("ANTHROPIC_BASE_URL", fake.url)
        model = P.providers().ANTHROPIC.build_model(P.ANTHROPIC_NAME)
        with pytest.raises(Exception):  # noqa: B017, PT011 — the count is the observation
            _wire_run(model)
    assert len(fake.hits) == 1, f"the Anthropic client made {len(fake.hits)} wire attempts on a 503"


def test_p1_the_openai_compatible_builder_makes_one_wire_attempt(monkeypatch: pytest.MonkeyPatch) -> None:
    """P1: the OpenAI-compatible provider builder's client does not retry — a 503 reaches the
    fake provider exactly once (the client's own default is 3, C1)."""
    cls = P.sym("runtime.providers.openai_compat", "OpenAICompatProvider")
    with P.FakeProvider([P.WireAnswer(503, {"error": {"message": "overloaded"}})]) as fake:
        monkeypatch.setenv("T1243_API_KEY", "k-1243")
        provider = cls(id="t1243", base_url=f"{fake.url}/v1", api_key_var="T1243_API_KEY",
                       aliases={}, main_effort="low", gather_effort="none")
        model = provider.build_model("t1243:m")
        with pytest.raises(Exception):  # noqa: B017, PT011 — the count is the observation
            _wire_run(model)
    assert len(fake.hits) == 1, f"the OpenAI-compatible client made {len(fake.hits)} attempts"


@pytest.mark.parametrize("which", ["DEFAULT_MODEL", "DEFAULT_GATHER_MODEL"])
def test_p1_the_shared_builder_retries_the_default_openai_compatible_models(
        which: str, monkeypatch: pytest.MonkeyPatch) -> None:
    name = P.sym("runtime.driver", which)
    provider = P.providers().provider_for(name)
    assert isinstance(provider, P.sym("runtime.providers.openai_compat", "OpenAICompatProvider")), (
        f"{which}={name!r} is no longer an OpenAI-compatible model; this test is about that path")
    monkeypatch.setenv(provider.api_key_var, "k-1243")
    with P.RefusingProxy() as proxy:
        P.through_proxy(monkeypatch, proxy)
        built = P.providers().build_for_effort(name, None, retry=P.instant_policy())
        caught = _raised(lambda: _wire_run(built.model))
    assert proxy.hits, (
        f"{name}'s request never reached the proxy (raised {caught!r}): this test's channel "
        "is gone — the client no longer reads HTTPS_PROXY")
    assert len(proxy.hits) == P.MAX_ATTEMPTS, (
        f"{name} made {len(proxy.hits)} wire attempt(s) on no response; the bound is 4")
    down = _down(caught)
    assert down.status is None
    assert down.attempts == P.MAX_ATTEMPTS


def test_p1_the_retrier_recovers_an_openai_compatible_request_on_the_wire(
        monkeypatch: pytest.MonkeyPatch) -> None:
    cls = P.sym("runtime.providers.openai_compat", "OpenAICompatProvider")
    overloaded = P.WireAnswer(503, {"error": {"message": "overloaded"}})
    with P.FakeProvider([overloaded, overloaded, P.WireAnswer(200, P.OPENAI_OK)]) as fake:
        monkeypatch.setenv("T1243_API_KEY", "k-1243")
        provider = cls(id="t1243", base_url=f"{fake.url}/v1", api_key_var="T1243_API_KEY",
                       aliases={}, main_effort="low", gather_effort="none")
        result = _wire_run(P.with_retries(provider.build_model("t1243:m"), P.instant_policy()))
    assert result.output == "wire-ok"
    assert len(fake.hits) == 3, f"{len(fake.hits)} wire attempts; two 503s then an answer is 3"


def test_p1_the_shared_builder_retries_exactly_four_times_on_the_wire(monkeypatch: pytest.MonkeyPatch) -> None:
    with P.FakeProvider([P.wire_error(503, retry_after="0")]) as fake:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "k-1243")
        monkeypatch.setenv("ANTHROPIC_BASE_URL", fake.url)
        built = P.providers().build_for_effort(P.ANTHROPIC_NAME, None, retry=P.instant_policy())
        caught = _raised(lambda: _wire_run(built.model))
    down = _down(caught)
    assert len(fake.hits) == P.MAX_ATTEMPTS, f"{len(fake.hits)} wire attempts; the bound is 4"
    assert down.status == 503


def test_p1_the_shared_builder_recovers_after_temporary_failures(monkeypatch: pytest.MonkeyPatch) -> None:
    """P1/O1 + scenario 1 at the wire: two 529s then a good answer — the caller gets the answer,
    after exactly 3 wire attempts."""
    answers = [P.wire_error(529), P.wire_error(529), P.WireAnswer(200, P.ANTHROPIC_OK)]
    with P.FakeProvider(answers) as fake:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "k-1243")
        monkeypatch.setenv("ANTHROPIC_BASE_URL", fake.url)
        built = P.providers().build_for_effort(P.ANTHROPIC_NAME, None, retry=P.instant_policy())
        result = _wire_run(built.model)
    assert result.output == "wire-ok"
    assert len(fake.hits) == 3


def test_p1_the_shared_builder_reads_retry_after_off_the_wire(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k-1243")
    own_t = P.Timeline()
    with P.FakeProvider([P.wire_error(429), P.WireAnswer(200, P.ANTHROPIC_OK)]) as plain:
        monkeypatch.setenv("ANTHROPIC_BASE_URL", plain.url)
        _wire_run(P.providers().build_for_effort(P.ANTHROPIC_NAME, None, retry=own_t.policy()).model)
    assert own_t.waits, "the retrier never waited after a header-less 429"
    header = int(own_t.waits[0]) + 100
    t = P.Timeline()
    answers = [P.wire_error(429, retry_after=str(header)), P.WireAnswer(200, P.ANTHROPIC_OK)]
    with P.FakeProvider(answers) as fake:
        monkeypatch.setenv("ANTHROPIC_BASE_URL", fake.url)
        built = P.providers().build_for_effort(P.ANTHROPIC_NAME, None, retry=t.policy())
        _wire_run(built.model)
    assert len(fake.hits) == 2
    assert t.waits, "the retrier never waited after a 429"
    assert t.waits[0] >= header, f"waited {t.waits} after Retry-After: {header}"


def test_p1_the_shared_builder_retries_a_refused_connection(monkeypatch: pytest.MonkeyPatch) -> None:
    """O1 at the wire: a provider nothing answers for (connection refused — no response) is
    retried to the bound and ends `ProviderDown` with no status."""
    monkeypatch.setenv("ANTHROPIC_API_KEY", "k-1243")
    monkeypatch.setenv("ANTHROPIC_BASE_URL", P.closed_port_url())
    built = P.providers().build_for_effort(P.ANTHROPIC_NAME, None, retry=P.instant_policy())
    caught = _raised(lambda: _wire_run(built.model))
    down = _down(caught)
    assert down.status is None
    assert down.attempts == P.MAX_ATTEMPTS


def test_p1_the_shared_builder_does_not_retry_a_rejection(monkeypatch: pytest.MonkeyPatch) -> None:
    """O2 at the wire: a 400 from the provider is one wire attempt, propagated as the model's
    own HTTP error (part 2 owns it)."""
    from pydantic_ai.exceptions import ModelHTTPError

    with P.FakeProvider([P.wire_error(400)]) as fake:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "k-1243")
        monkeypatch.setenv("ANTHROPIC_BASE_URL", fake.url)
        built = P.providers().build_for_effort(P.ANTHROPIC_NAME, None, retry=P.instant_policy())
        with pytest.raises(ModelHTTPError) as caught:
            _wire_run(built.model)
    assert caught.value.status_code == 400
    assert len(fake.hits) == 1


def test_p1_the_default_builder_path_carries_the_retrier(monkeypatch: pytest.MonkeyPatch,
                                                        caplog: pytest.LogCaptureFixture) -> None:
    from pydantic_ai.messages import ModelRequest, UserPromptPart
    from pydantic_ai.models import ModelRequestParameters, override_allow_model_requests

    caplog.set_level(logging.WARNING)
    ceiling_s = 200.0
    with P.FakeProvider([P.wire_error(503)]) as fake:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "k-1243")
        monkeypatch.setenv("ANTHROPIC_BASE_URL", fake.url)
        built = P.providers().build_for_effort(P.ANTHROPIC_NAME, None)

        async def scenario() -> Any:
            task = asyncio.ensure_future(built.model.request(
                [ModelRequest(parts=[UserPromptPart("hello")])], None, ModelRequestParameters()))
            loop = asyncio.get_running_loop()
            until = loop.time() + ceiling_s
            while len(fake.hits) < 2 and not task.done() and loop.time() < until:
                await asyncio.sleep(0.05)
            outcome: Any = None
            if task.done():
                outcome = task.exception()
            task.cancel()
            with contextlib.suppress(BaseException):
                await task
            return outcome

        with override_allow_model_requests(True):
            outcome = asyncio.run(scenario())
    assert len(fake.hits) >= 2, (
        f"the default builder path made {len(fake.hits)} wire attempt(s) on a 503 "
        f"(ended with {outcome!r}): it carries no retrier")
    second = [m for m in _retry_lines(caplog) if "2/4" in m]
    assert len(second) == 1, (
        f"the default path's first retry logged {len(second)} '2/4' lines: "
        f"{[r.getMessage() for r in caplog.records]}")
    named = P.numbers_besides(second[0], status=503,
                              spelled=(built.model.model_name, P.ANTHROPIC_NAME, "2/4"))
    assert named, f"the default path's retry line names no wait: {second[0]!r}"
    gap = fake.hit_times[1] - fake.hit_times[0]
    assert gap >= 0.8 * min(named), (
        f"the default path resent {gap:.3f}s after the first hit, but its retry line says it "
        f"waits {min(named)}s ({second[0]!r}): the default backoff does not really wait")
