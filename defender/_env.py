from __future__ import annotations

import os
from collections.abc import Sequence


class FatalConfigError(ValueError):
    pass


def env_int(name: str, default: int) -> int:
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        raise FatalConfigError(f"{name} must be an integer; got {raw!r}") from None


_TRUE_TOKENS = frozenset({"1", "on", "true", "yes"})
_FALSE_TOKENS = frozenset({"", "0", "off", "false", "no"})


def env_bool(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    tok = raw.strip().lower()
    if tok in _TRUE_TOKENS:
        return True
    if tok in _FALSE_TOKENS:
        return False
    raise FatalConfigError(
        f"{name} must be a boolean ({sorted(_TRUE_TOKENS)} / {sorted(_FALSE_TOKENS)}); got {raw!r}"
    )


def env_str(name: str, default: str, *, choices: Sequence[str] | None = None) -> str:
    value = os.environ.get(name, default)
    if choices is not None and value not in choices:
        raise FatalConfigError(f"{name} must be one of {tuple(choices)}; got {value!r}")
    return value
