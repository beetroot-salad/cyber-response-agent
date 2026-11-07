"""One HTTP request to a service the product drives (Forgejo, OpenBao), described but not sent (#1440).

`_forgejo_api` and `_openbao_api` build these: every path, query, body and fixed header of those
services lives there, once. A caller sends one with its own client, sync or async, and its own
credential and error handling: `client.request(call.method, call.path, **call.options())`. No
HTTP stack is imported here, so a module that builds calls loads without one."""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class ApiCall:
    """A request below the service's address: `path` starts with `/`."""

    method: str
    path: str
    params: Mapping[str, str | int] | None = None
    json: Any = None
    headers: Mapping[str, str] | None = None

    def options(self, *, headers: Mapping[str, str] | None = None) -> dict[str, Any]:
        """The request's keyword arguments for an `httpx` client, only those it sets; `headers`
        (a caller's credential) is added to the call's own."""
        merged = {**(self.headers or {}), **(headers or {})}
        given = {"params": self.params, "json": self.json, "headers": merged or None}
        return {key: value for key, value in given.items() if value is not None}
