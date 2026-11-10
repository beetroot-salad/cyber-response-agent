"""Spend is recorded at the model (#1377 r7.3 T3).

Every agent's model is wrapped here, where the agent is built and outside the retrier, so the
ledger row is the request's final outcome (r7 S2a) and only requests actually handed to the model
are recorded: a capability that answers a request without the model writes no row, and an error
raised after the model answered (an output check asking for a retry) leaves the response row in
place. The wrapper is built with the model name the agent asked for, which alone prices its rows
(r7 S1, r7.1 D). The request log stays in the agent's hooks, which see the run step."""
from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from pydantic_ai.models.wrapper import WrapperModel

from .. import observe


class SpendRecordingModel(WrapperModel):
    """`wrapped`, each request's end written to the run's spend ledger through `logger` (which never
    raises), then returned or re-raised unchanged."""

    def __init__(self, wrapped: Any, *, logger: observe.RequestLogger, agent_id: str, requested_model: str) -> None:
        super().__init__(wrapped)
        self._logger, self._agent_id, self._requested = logger, agent_id, requested_model

    def _record(self, *, response: Any = None, failure: BaseException | None = None) -> None:
        self._logger.record_spend(observe.RequestEnd.of(self._agent_id, self._requested, response=response, failure=failure))

    async def request(self, messages: Any, model_settings: Any, model_request_parameters: Any) -> Any:
        try:
            response = await self.wrapped.request(messages, model_settings, model_request_parameters)
        except BaseException as failure:  # noqa: BLE001 — recorded, then re-raised unchanged
            # One synchronous write, so it lands even while the task is being cancelled (r7 S2a).
            self._record(failure=failure)
            raise
        self._record(response=response)
        return response

    @asynccontextmanager
    async def request_stream(self, messages: Any, model_settings: Any, model_request_parameters: Any,
                             run_context: Any = None) -> AsyncIterator[Any]:
        try:
            async with self.wrapped.request_stream(messages, model_settings, model_request_parameters,
                                                   run_context) as streamed:
                yield streamed
        except BaseException as failure:  # noqa: BLE001 — recorded, then re-raised unchanged
            self._record(failure=failure)
            raise
        self._record(response=streamed.get())
