from __future__ import annotations

import logging
import os
from collections.abc import Sequence

_logger = logging.getLogger(__name__)


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


def env_choice(name: str, default: str, choices: Sequence[str]) -> tuple[str, str | None]:
    """A setting that is one of `choices`, read leniently: never fatal, so a typo in a
    deployment costs what the setting decides, not the process. Stripped and lowercased; unset
    or blank is `default`. Anything else is `default` too, and comes back with a notice naming
    the variable, the value, the choices and the default — the caller reports it its own way
    (logging may not be set up yet when the caller is the logging setup itself)."""
    raw = env_str(name, "")
    value = raw.strip().lower()
    if not value:
        return default, None
    if value in choices:
        return value, None
    return default, f"{name}={raw!r} is not one of {tuple(choices)}; using {default!r}"


#: The deployment type (#1110): `dev` turns on the run page's local copy; everything else is a
#: deployment with no operator filesystem to copy into.
DEPLOYMENT_ENV = "DEFENDER_DEPLOYMENT"
DEPLOYMENTS = ("dev", "production")


def deployment() -> str:
    """`dev` or `production`, read from `DEPLOYMENT_ENV` at call time.

    Unset or empty is `production`: a dev shell that misses the variable loses a convenience it
    can see, while a worker that missed it under the other default would write copies into
    itself. Never inferred from `.git`, the image, the uid or pytest. An unrecognised value is
    `production` too — never `dev`, so a typo cannot turn the copy on — and is logged as an
    error on every read rather than raised, so a typo cannot abort a run either."""
    value, notice = env_choice(DEPLOYMENT_ENV, "production", DEPLOYMENTS)
    if notice:
        _logger.error(notice)
    return value
