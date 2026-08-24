from __future__ import annotations


class Metrics:
    def __init__(self) -> None:
        self.counts: dict[str, int] = {}

    def increment(self, name: str) -> None:
        self.counts[name] = self.counts.get(name, 0) + 1
