"""#1256 — a fault planted in an adapter AFTER the run's start check."""
from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import Any


class Relink:
    """`adapter` (a file of a roster's adapters directory) and the source of a module that
    cannot be imported. The broken module is written beside the adapters directory, never in
    it (a later roster read must not see a second adapter)."""

    def __init__(self, adapter: Path, broken_source: str) -> None:
        self.adapter = Path(adapter)
        self.good = self.adapter.read_bytes()
        self.target = self.adapter.parent.parent / "_broken_after_start_1256" / self.adapter.name
        self.broken_source = broken_source
        self.broken = 0

    def break_(self) -> None:
        """The adapter becomes a link to the module that cannot be imported."""
        self.target.parent.mkdir(parents=True, exist_ok=True)
        self.target.write_text(self.broken_source, encoding="utf-8")
        self.adapter.unlink()
        self.adapter.symlink_to(self.target)
        self.broken += 1

    def restore(self) -> None:
        """The original file, byte for byte, back where the roster read it."""
        if self.adapter.is_symlink() or self.adapter.exists():
            self.adapter.unlink()
        self.adapter.write_bytes(self.good)


class AfterStart:
    """One scripted model turn (`turn`: anything with `tool_calls` and `text`) that runs
    `before` once, when the model double reads it — i.e. when the model asks for this turn."""

    def __init__(self, turn: Any, before: Callable[[], Any]) -> None:
        self._turn = turn
        self._before = before
        self.fired = False

    def _fire(self) -> None:
        if not self.fired:
            self.fired = True
            self._before()

    @property
    def text(self) -> str:
        self._fire()
        return self._turn.text

    @property
    def tool_calls(self) -> list:
        self._fire()
        return self._turn.tool_calls


__all__ = ["AfterStart", "Relink"]
