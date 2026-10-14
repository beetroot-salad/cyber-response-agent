"""Every error the API answers, in one shape: RFC 9457 problem details, `application/problem+json`.

A refusal raised anywhere — a route's `HTTPException`, a port's `NotFound` / `Conflict` /
`UnknownReference`, a body or parameter that fails validation, a route the router does not have,
or an unexpected failure — reaches a handler here and leaves as a `Problem` (`models.py`). Every
route declares the problems it can answer (`responses`), so the published contract says what a
client actually receives.

`type` is `about:blank` and `title` the status's phrase: the status alone says what kind of
problem it is (RFC 9457 §4.2.1); `detail` says what happened to this request. A 422 from
validation also lists each failing part of the request (`errors`), but never the refused value
itself: it may be a credential. A 500 says nothing about its cause.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable, Mapping
from http import HTTPStatus
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from .models import FieldError, Problem

PROBLEM_MEDIA_TYPE = "application/problem+json"


class ProblemResponse(JSONResponse):
    """A `Problem`, with every non-ASCII character escaped: a refusal may quote what it refused,
    and a lone surrogate in it cannot be encoded as UTF-8 — rendered raw, the refusal itself
    would fail."""

    def render(self, content: Any) -> bytes:
        return json.dumps(content, ensure_ascii=True, allow_nan=False, separators=(",", ":")).encode("ascii")


def problem(status: int, detail: str | None, *, errors: list[FieldError] | None = None,
            headers: Mapping[str, str] | None = None) -> ProblemResponse:
    body = Problem(title=HTTPStatus(status).phrase, status=status, detail=detail, errors=errors)
    return ProblemResponse(body.model_dump(mode="json", exclude_none=True), status_code=status,
                           headers=headers, media_type=PROBLEM_MEDIA_TYPE)


def _http(_request: Request, exc: Exception) -> ProblemResponse:
    if not isinstance(exc, StarletteHTTPException):
        raise exc
    return problem(exc.status_code, str(exc.detail), headers=exc.headers)


def _invalid(_request: Request, exc: Exception) -> ProblemResponse:
    if not isinstance(exc, RequestValidationError):
        raise exc
    errors = [FieldError(loc=list(e["loc"]), msg=e["msg"], type=e["type"]) for e in exc.errors()]
    return problem(422, "the request is not valid; see `errors`", errors=errors)


def _unexpected(_request: Request, _exc: Exception) -> ProblemResponse:
    return problem(500, "internal error")


def refusal(status: int) -> Callable[[Request, Exception], Awaitable[ProblemResponse]]:
    """The handler for a port's refusal: its message is the detail."""
    async def handle(_request: Request, exc: Exception) -> ProblemResponse:
        return problem(status, str(exc))
    return handle


def _async(handler: Callable[[Request, Exception], ProblemResponse]) -> Callable[[Request, Exception], Awaitable[ProblemResponse]]:
    async def handle(request: Request, exc: Exception) -> ProblemResponse:
        return handler(request, exc)
    return handle


#: The handlers every app installs, by what they handle. `Exception` is the last resort: it
#: answers the 500 (the server still logs the failure).
HANDLERS: dict[type[Exception], Callable[[Request, Exception], Awaitable[ProblemResponse]]] = {
    StarletteHTTPException: _async(_http),
    RequestValidationError: _async(_invalid),
    Exception: _async(_unexpected),
}


def install(app: FastAPI) -> None:
    """Answer every error as a problem, and publish the problems under their own media type."""
    for exc_class, handler in HANDLERS.items():
        app.add_exception_handler(exc_class, handler)
    generate = app.openapi

    def openapi() -> dict[str, Any]:
        # FastAPI files a declared response model under `application/json`; a problem is served
        # as `application/problem+json`, so its schema moves there.
        schema = generate()
        for operations in schema["paths"].values():
            for operation in operations.values():
                for response in operation.get("responses", {}).values():
                    content = response.get("content", {})
                    if PROBLEM_MEDIA_TYPE in content and "application/json" in content:
                        content[PROBLEM_MEDIA_TYPE] = content.pop("application/json")
        return schema

    app.openapi = openapi  # type: ignore[method-assign]  # FastAPI's documented hook


def responses(*statuses: int) -> dict[int | str, dict[str, Any]]:
    """The problems a route can answer, for its OpenAPI declaration."""
    return {
        status: {
            "model": Problem,
            "description": HTTPStatus(status).phrase,
            "content": {PROBLEM_MEDIA_TYPE: {}},
        }
        for status in statuses
    }
