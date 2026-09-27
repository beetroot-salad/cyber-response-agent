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
    raw = env_str(DEPLOYMENT_ENV, "")
    value = raw.strip().lower()
    if value in DEPLOYMENTS:
        return value
    if value:
        _logger.error("%s=%r is not one of %s; treating it as 'production'",
                      DEPLOYMENT_ENV, raw, DEPLOYMENTS)
    return "production"
