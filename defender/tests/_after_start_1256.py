"""#1256 — a fault planted in an adapter AFTER the run's start check.

Since #1256 a run imports every granted adapter at its start (gather's system index did so
before it, C5): an adapter that cannot be imported then is down for the whole run with its cause
(O-5a), and no call to it is made. A call that fails to LOAD its adapter is therefore only
possible when the adapter changes after that start — something that can change during a run,
which the breaker still counts as an infra failure (DP2).

The loader (`runtime.verbs._load_adapter_module`) keeps one module per RESOLVED file, so new
bytes written over a file already loaded change nothing a later call sees. What a later call does
load afresh is a different file: `Relink.break_` replaces the adapter by a link to a module that
cannot be imported (the link resolves elsewhere, so the call loads that module, and fails), and
`Relink.restore` puts the original file back (it resolves to what the run loaded at start).
Nothing is patched in process; the fault is real input through the real loader.

`AfterStart` fires such an action when the model ASKS for one scripted turn: after the run
started and every earlier call of that conversation was answered, before this turn's calls run.
"""
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
