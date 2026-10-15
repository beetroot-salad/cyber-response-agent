"""#1243 part 1 — the retrier itself (O1, O2, P1, P3).

One retry owner, below every caller: a model request failing temporarily (408, 409, 429, >=500,
or no response) is resent unchanged, at most 4 wire attempts in all, honouring `Retry-After`,
starting no attempt once 10 minutes have passed since the first began; exhausted, it raises one
typed `ProviderDown` from the original error. Every other failure propagates exactly as today.
The client libraries' own retries are off, so the wire sees our attempts and no more. A retry is
invisible to the run's accounting.

Three levels, each with its own evidence:
* the retrier over a scripted `FunctionModel` (`with_retries`), on a fake timeline (sleep and clock
  are the policy's fields, injected — no `monkeypatch`);
* the REAL builders over real HTTP to a local fake provider (`FakeProvider`): the Anthropic
  builder reached through `ANTHROPIC_BASE_URL` (the SDK reads it when no base URL is passed —
  anthropic 1.6 `_client.py`), the OpenAI-compatible builder through its own `base_url`;
* the run: a scripted run under the real retrier (`drive(wrap_model=...)`), where the wire log,
  the store and the request count are observed.

Bounds, not schedule constants: the backoff's shape is the implementer's.
"""
from __future__ import annotations

import asyncio
import contextlib
import logging
from pathlib import Path
from typing import Any

import pytest

from defender.tests.alert_front_door_1222 import _spec1222 as S
from defender.tests.provider_down_1243 import _spec1243 as P


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


def _retry_warnings(caplog: pytest.LogCaptureFixture, status: str) -> list[logging.LogRecord]:
    """The retry lines: WARNING records naming the status and an attempt out of 4."""
    return [r for r in caplog.records if r.levelno == logging.WARNING
            and status in r.getMessage() and "/4" in r.getMessage()]


# =================================================================================================
# O1 — what is retried, how many times, and what an exhausted retry raises
# =================================================================================================

@pytest.mark.parametrize("status", P.RETRIED_STATUSES)
def test_o1_a_temporary_status_is_retried_and_success_after_a_retry_is_a_plain_success(status: int) -> None:
    """O1 + scenario 1: a request failing with a temporary status (408, 409, 429, >=500 incl.
    529) is resent; when a later attempt answers, the caller gets that answer as if nothing
    had failed."""
    t = P.Timeline()
    fake = P.Attempts(P.first_n(2, lambda: P.http_error(status)), timeline=t, text="answered")
    result = P.run_agent(P.with_retries(P.function_model(fake), t.policy()))
    assert fake.attempts == 3, f"{status}: {fake.attempts} attempts; two failures then a success is 3"
    assert result.output == "answered"


@pytest.mark.parametrize("make", [P.no_response, P.connection_error], ids=["timeout", "connection"])
def test_o1_no_response_is_retried(make: Any) -> None:
    """O1: a request that got no response at all (timeout, connection error — a model error
    with no status) is temporary and resent."""
    t = P.Timeline()
    fake = P.Attempts(P.first_n(1, make), timeline=t)
    result = P.run_agent(P.with_retries(P.function_model(fake), t.policy()))
    assert fake.attempts == 2
    assert result.output == "done"


def test_o1_at_most_four_wire_attempts_then_provider_down_from_the_original() -> None:
    """O1/P2/D1: a provider that stays down gets 4 attempts in all (3 retries), then ONE typed
    `ProviderDown` carrying the model, the last status and the attempt count, raised `from` the
    last original error."""
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
    """O1/P3: a retry is the SAME request, resent unchanged — not a new turn carrying a retry
    prompt (a `ModelRetry`-shaped retry appends one, C2)."""
    t = P.Timeline()
    fake = P.Attempts(P.first_n(3), timeline=t)
    P.run_agent(P.with_retries(P.function_model(fake), t.policy()), "the one prompt")
    assert fake.attempts == 4
    first = fake.inbound[0]
    for n, inbound in enumerate(fake.inbound[1:], start=2):
        assert inbound == first, f"attempt {n} sent something other than attempt 1 did"
    assert "retry-prompt" not in str(first)


def _first_wait(exc: Any, jitter: float = 0.5) -> float:
    """The retrier's own wait before its first retry after `exc()`, on a fake timeline."""
    t = P.Timeline()
    fake = P.Attempts(P.first_n(1, exc), timeline=t)
    P.run_agent(P.with_retries(P.function_model(fake), t.policy(jitter)))
    assert t.waits, "the retrier never waited before retrying"
    return t.waits[0]


def test_o1_retry_after_is_honoured() -> None:
    """O1 + scenario 4: a 429 carrying `Retry-After` waits (at least) what the header says.
    Differential, so a schedule that ignores the header cannot pass: the header is set 100 s
    beyond the retrier's own header-less first wait (still inside the window)."""
    own = _first_wait(lambda: P.http_error(429))
    header = int(own) + 100
    assert header < P.WINDOW_S, f"the header-less first wait is already {own}s"
    t = P.Timeline()
    fake = P.Attempts(P.first_n(1, lambda: P.http_error(429, retry_after=str(header))), timeline=t)
    P.run_agent(P.with_retries(P.function_model(fake), t.policy()))
    assert fake.attempts == 2
    assert t.waits, "the retrier never waited"
    assert t.waits[0] >= header, (
        f"Retry-After: {header} was not honoured: waited {t.waits[0]}s (own backoff {own}s)")


def test_o1_retry_after_past_the_window_never_spends_past_it() -> None:
    """O1 (R2): a `Retry-After` longer than the whole window (3600 s) never makes the retrier
    spend more than 10 minutes — whether it stops at once or waits to the cutoff is the
    implementer's (design silent, AF1); it ends `ProviderDown` either way."""
    t = P.Timeline()
    start = t.now
    fake = P.Attempts(P.Plan(exc=lambda: P.http_error(429, retry_after="3600"), fail_from=1),
                      timeline=t)
    wrapped = P.with_retries(P.function_model(fake), t.policy())
    caught = _raised(lambda: P.run_agent(wrapped))
    _down(caught)
    assert t.now - start <= P.WINDOW_S, (
        f"the retrier spent {t.now - start}s of (fake) time on a Retry-After past the window")


def test_o1_backoff_exists_and_does_not_shrink() -> None:
    """O1 (R4): a provider that stays down gets 3 waits between its 4 attempts, each > 0 and
    none shorter than the one before (exponential backoff); no floor value is pinned."""
    t = P.Timeline()
    fake = P.Attempts(P.ALWAYS_503, timeline=t)
    wrapped = P.with_retries(P.function_model(fake), t.policy(jitter=0.5))
    _down(_raised(lambda: P.run_agent(wrapped)))
    assert len(t.waits) == 3, f"waits between 4 attempts: {t.waits}"
    assert all(w > 0 for w in t.waits), f"a retry was sent with no wait: {t.waits}"
    assert t.waits == sorted(t.waits), f"the backoff shrank: {t.waits}"


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


def test_p2_provider_down_is_an_ordinary_exception() -> None:
    """P2 (R5): `ProviderDown` is an `Exception`, so every caller's existing `except Exception`
    catch-all outside a run (oracle, learning stage) still decides what it means."""
    assert issubclass(P.provider_down_cls(), Exception)


def test_o1_no_attempt_starts_ten_minutes_after_the_first_began() -> None:
    """O1 + scenario 3: a provider that accepts the connection and hangs costs at most ~10 min
    plus one attempt: no NEW attempt starts once 10 minutes have passed since the first began.
    Each attempt here hangs 250 s (fake time) before timing out, so a 4th attempt would start
    past the window; the run ends `ProviderDown` with the attempts actually made."""
    t = P.Timeline()
    fake = P.Attempts(P.Plan(exc=P.no_response, fail_from=1), timeline=t, hang_s=250.0)
    wrapped = P.with_retries(P.function_model(fake), t.policy())
    caught = _raised(lambda: P.run_agent(wrapped))
    down = _down(caught)
    began = fake.began
    assert began, "no attempt was made"
    late = [b - began[0] for b in began if b - began[0] >= P.WINDOW_S]
    assert not late, f"attempts started {late}s after the first — past the 10-minute window"
    assert fake.attempts < P.MAX_ATTEMPTS, (
        f"{fake.attempts} attempts of 250 s each: the 4th could only start past the window")
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
    """O1 + scenario 1: each retry logs exactly one warning naming the status and the attempt
    (n/4); a success after two retries logs two."""
    caplog.set_level(logging.WARNING)
    t = P.Timeline()
    fake = P.Attempts(P.first_n(2, lambda: P.http_error(529)), timeline=t)
    caplog.clear()
    P.run_agent(P.with_retries(P.function_model(fake), t.policy()))
    warnings = _retry_warnings(caplog, "529")
    assert len(warnings) == 2, [r.getMessage() for r in caplog.records]
    for n, record in enumerate(warnings, start=2):
        msg = record.getMessage()
        assert "529" in msg, f"the retry warning does not name the status: {msg!r}"
        assert f"{n}/4" in msg, f"the retry warning does not name attempt {n}/4: {msg!r}"


def test_o1_a_cancelled_caller_cuts_the_backoff() -> None:
    """O1/Design: the backoff is awaited on the event loop and the retrier never catches
    `CancelledError` — a request cancelled mid-backoff ends cancelled (not `ProviderDown`, not a
    further attempt). Driven on the model's own `request`, below the agent framework, whose
    task machinery would re-raise a cancellation the retrier swallowed and hide it."""
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


# =================================================================================================
# O2 — anything else is not retried, and propagates exactly as today
# =================================================================================================

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


# =================================================================================================
# P3 — a retry is invisible to the run's accounting
# =================================================================================================

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
    d = S.run_alert(tmp, tenant=tenant, run_id=f"r1243-s1-{kind}",
                    main=[S.gather("l-001", "cmdb"), S.text(S.DONE)], router=router,
                    store_factory=S.store_factory(tmp, sink=stores), stores=stores,
                    wrap_model=P.wrap_with(P.instant_policy(), kinds=("gather",)))
    return {"d": d, "stores": stores, "router": router}


def test_p3_scenario1_a_lead_retried_twice_runs_as_if_it_never_failed(tmp_path: Path) -> None:
    """Scenario 1 / P3: a lead whose first request gets 529 twice and then succeeds runs to a
    normal end; the run records ONE wire-log response per request the lead made (not one per
    attempt), the same store rows and the same request count as a clean run."""
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


# =================================================================================================
# P1 — one retry owner: the client libraries' retries are off; the builder carries ours
# =================================================================================================

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


def test_p1_the_shared_builder_retries_exactly_four_times_on_the_wire(monkeypatch: pytest.MonkeyPatch) -> None:
    """P1/O1 + scenario 2 at the wire: the model every caller gets from the shared builder
    (`build_for_effort`) makes exactly 4 wire attempts against a provider that stays at 503,
    then raises `ProviderDown` — not 3 (the client alone), not 12 (two stacked layers)."""
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
    """O1 + scenario 4 at the wire: the provider's own `Retry-After` on a 429 sets the wait
    before the retry. Differential: the header is 100 s past the retrier's own header-less wait
    on the same wire, so only a header read off the response can meet it."""
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


def test_p1_the_default_builder_path_carries_the_retrier(monkeypatch: pytest.MonkeyPatch) -> None:
    """P1 (R1): production's own call — `build_for_effort(name, effort)`, the two-argument
    `make_model` shape every caller uses, no policy passed — retries: against a provider that
    stays at 503 a request reaches the wire at least twice. Real waits; the request is
    cancelled once the second hit lands (generous ceiling, so any conforming first backoff
    fits)."""
    from pydantic_ai.messages import ModelRequest, UserPromptPart
    from pydantic_ai.models import ModelRequestParameters, override_allow_model_requests

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
