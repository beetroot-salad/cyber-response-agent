"""In-memory replacement for the slice of `opensearchpy.OpenSearch` that
`wazuh_cli.query_alerts` exercises — namely `.search(**kwargs) -> dict`.

Programmable: pre-load a list of response pages; each `.search()` call returns
the next one, then an empty page thereafter. Records every call's kwargs so
tests can assert on body shape (search_after cursor, size, etc.).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


_EMPTY_PAGE: dict[str, Any] = {"hits": {"total": {"value": 0}, "hits": []}}


@dataclass
class FakeOpenSearchClient:
    pages: list[dict[str, Any]] = field(default_factory=list)
    calls: list[dict[str, Any]] = field(default_factory=list)

    def search(self, **kwargs) -> dict[str, Any]:
        self.calls.append(kwargs)
        idx = len(self.calls) - 1
        if idx < len(self.pages):
            return self.pages[idx]
        return _EMPTY_PAGE

    @property
    def call_count(self) -> int:
        return len(self.calls)
