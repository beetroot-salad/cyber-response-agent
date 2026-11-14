"""The port of a family nothing real backs yet: every call refuses, naming the issue that will back it (#1083 O8)."""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from typing import Any, NoReturn


class NotImplementedYet(Exception):
    """A port call whose family is not yet backed by real data; the app answers it as a 501."""


class Refusing:
    """One port, whole: any method called on it raises `NotImplementedYet` naming `issue`, so the routes it backs
    answer 501 once sign-in, membership and permission have passed."""

    def __init__(self, issue: str) -> None:
        self._issue = issue

    def __getattr__(self, name: str) -> Callable[..., Coroutine[Any, Any, NoReturn]]:
        if name.startswith("_"):
            raise AttributeError(name)

        async def refuse(*_args: object, **_kwargs: object) -> NoReturn:
            raise NotImplementedYet(f"not implemented yet; it is backed by {self._issue}")
        return refuse
