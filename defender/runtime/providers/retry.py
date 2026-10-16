"""The one place a model request is retried (#1243, P1).

A request that fails *temporarily* (HTTP 408, 409, 429, >=500, or no response at all) is resent
unchanged, up to `MAX_ATTEMPTS` wire attempts in all; no new attempt starts once `WINDOW_S` has
passed since the first began. Exhausted, it raises `ProviderDown` from the last original error.
Everything else propagates exactly as the model raised it. The client libraries' own retries are
off (the provider builders set them to 0), so these are the only retries on the wire.

The wrapper sits on the model object, below every caller: the run's agents, the review stages,
the learning stages and the branching oracle all get their model from `build_for_effort`, so one
fault gets one handling. A retry is the same request resent inside one `request` call, so the
framework above counts one request, runs its history processors once and writes one wire record.

pydantic_ai names are imported inside functions: this package is imported by the runtime-free
install.
"""
from __future__ import annotations

import asyncio
import logging
import random
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from functools import cache
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from pydantic_ai.messages import ModelMessage, ModelResponse
    from pydantic_ai.models import Model, ModelRequestParameters
    from pydantic_ai.settings import ModelSettings

_logger = logging.getLogger(__name__)

#: Wire attempts per request: the first and up to three retries.
MAX_ATTEMPTS = 4
#: No new attempt starts once this long has passed since the first began.
WINDOW_S = 600.0
#: Backoff before retry n is `BACKOFF_BASE_S * BACKOFF_FACTOR ** (n - 1)`, scaled by jitter into
#: its upper half: long enough to outlast an ordinary provider blip, short against `WINDOW_S`.
BACKOFF_BASE_S = 4.0
BACKOFF_FACTOR = 3.0
#: HTTP statuses besides >=500 that name a temporary condition.
_TEMPORARY_STATUSES = frozenset({408, 409, 429})


class ProviderDown(Exception):  # noqa: N818 — named for the state it reports, like `RunAborted`
    """A model request kept failing temporarily until its retries ran out.

    `status` is the last HTTP status, or `None` when the last attempt got no response. Raised
    `from` the last original error. What it means is the caller's: inside an investigation run
    it ends the run `provider-down`; elsewhere each caller's own catch-all decides."""

    def __init__(self, model: str, status: int | None, attempts: int) -> None:
        self.model = model
        self.status = status
        self.attempts = attempts
        seen = "no response" if status is None else f"HTTP {status}"
        super().__init__(f"the provider for {model} stayed down: {seen} on all {attempts} attempt(s)")

    def __reduce__(self) -> tuple[type, tuple[Any, ...]]:
        return self.__class__, (self.model, self.status, self.attempts)


@dataclass(frozen=True)
class RetryPolicy:
    """The retrier's clock, sleep and jitter, injectable so a test never waits.

    `sleep` is awaited on the event loop (a caller's deadline or cancellation cuts it mid-backoff);
    `clock` is monotonic seconds; `jitter` is in `[0, 1)`."""

    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep
    clock: Callable[[], float] = time.monotonic
    jitter: Callable[[], float] = random.random


def _temporary(exc: BaseException) -> tuple[bool, int | None]:
    """`(whether exc is a temporary provider failure, its HTTP status or None for no response)`.
    Classified by status alone, never by body text."""
    from pydantic_ai.exceptions import ModelAPIError, ModelHTTPError

    if isinstance(exc, ModelHTTPError):
        status = exc.status_code
        return (status in _TEMPORARY_STATUSES or status >= 500), status
    return isinstance(exc, ModelAPIError), None


def _retry_after(exc: BaseException) -> float:
    """The seconds the provider's `Retry-After` asks for; 0 when absent or not a number."""
    headers = getattr(exc, "headers", None) or {}
    try:
        return max(0.0, float(headers.get("retry-after", 0)))
    except (TypeError, ValueError):
        return 0.0


def _backoff(attempt: int, policy: RetryPolicy) -> float:
    """The wait before the retry that follows failed attempt `attempt` (1-based)."""
    return BACKOFF_BASE_S * BACKOFF_FACTOR ** (attempt - 1) * (0.5 + 0.5 * policy.jitter())


@cache
def _wrapper_class() -> type:
    from pydantic_ai.models.wrapper import WrapperModel

    class RetryingModel(WrapperModel):
        """`wrapped`, with every `request` retried as the module docstring says."""

        def __init__(self, wrapped: Model, policy: RetryPolicy) -> None:
            super().__init__(wrapped)
            self.policy = policy

        async def request(
            self, messages: list[ModelMessage], model_settings: ModelSettings | None,
            model_request_parameters: ModelRequestParameters,
        ) -> ModelResponse:
            policy = self.policy
            started = policy.clock()
            attempt = 0
            while True:
                attempt += 1
                try:
                    return await self.wrapped.request(
                        messages, model_settings, model_request_parameters)
                except Exception as e:  # noqa: BLE001 — classified below; non-temporary re-raised as is
                    temporary, status = _temporary(e)
                    if not temporary:
                        raise
                    wait = max(_backoff(attempt, policy), _retry_after(e))
                    if attempt >= MAX_ATTEMPTS or policy.clock() + wait - started >= WINDOW_S:
                        raise ProviderDown(self.wrapped.model_name, status, attempt) from e
                    _logger.warning(
                        f"{self.wrapped.model_name}: request failed "
                        f"({'no response' if status is None else f'HTTP {status}'}); "
                        f"retrying, attempt {attempt + 1}/{MAX_ATTEMPTS} in {wait:.1f}s")
                    await policy.sleep(wait)

    return RetryingModel


def with_retries(model: Any, policy: RetryPolicy | None = None) -> Any:
    """`model` behind the retrier. `policy` defaults to the real clock, sleep and jitter."""
    return _wrapper_class()(model, policy if policy is not None else RetryPolicy())
