"""Single canonical env-var coercion surface shared by runtime/, scripts/, and learning/.

One contract for "read a tuning knob from the environment and coerce it, failing
loud on a typo'd operator value", so each module stops hand-rolling a crash-prone
``int(os.environ.get(...))`` with its own copy of the default.

``FatalConfigError`` is the layer-neutral *condition* — "an operator knob is
misconfigured". It subclasses ``ValueError`` so any caller that does not catch it
fails loud with a *named* message (``ORACLE_MAX_CONCURRENCY must be an integer;
got 'high'``) rather than an opaque ``int()`` traceback. The learning loop
*enrolls* it into its drain ``StageAbort``/exit-2 handling at the catch sites
(``learning.core.orchestrate``); the runtime, which has no drains, simply lets it
propagate to a loud startup exit. The disposition lives at the catch site, not
here — this module only knows what a *valid* value looks like.

Lives at the ``defender.`` namespace root (no ``__init__.py`` — PEP 420 namespace
package) so ``defender.runtime.*`` / ``defender.scripts.*`` / ``defender.learning.*``
all import it without inverting the layering or a ``sys.path`` dance (see the
``_frontmatter`` precedent, #322/#323).
"""
from __future__ import annotations

import os
from collections.abc import Sequence


class FatalConfigError(ValueError):
    """An operator knob is misconfigured (a non-numeric threshold, an out-of-set
    enum). Layer-neutral and loud-by-default (a ``ValueError`` subclass). The
    learning drains map it to the contracted exit 2; the runtime lets it surface
    at the import/startup that set the bad value."""


def env_int(name: str, default: int) -> int:
    """Read an integer env override, raising ``FatalConfigError`` on a non-numeric
    value. Returns ``default`` when the var is unset."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        raise FatalConfigError(f"{name} must be an integer; got {raw!r}") from None


# Bool tokens are deliberately closed sets: an unrecognized value is a typo we
# surface, not silently coerce to False (the old hand-rolled behavior). The empty
# string counts as false (so ``NAME=`` reads as a False toggle, matching the old
# hand-rolled ``os.environ.get(NAME, "")`` behavior) — note this coincides with an
# unset ``NAME`` only when ``default`` is False; an unset ``NAME`` always returns
# ``default``.
_TRUE_TOKENS = frozenset({"1", "on", "true", "yes"})
_FALSE_TOKENS = frozenset({"", "0", "off", "false", "no"})


def env_bool(name: str, default: bool) -> bool:
    """Read a boolean env toggle, raising ``FatalConfigError`` on an unrecognized
    token. ``{1,on,true,yes}`` → True, ``{"",0,off,false,no}`` → False (case- and
    whitespace-insensitive). Returns ``default`` when the var is unset."""
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
    """Read a string env override. When ``choices`` is given, raise
    ``FatalConfigError`` if the value (override *or* default) is not in the set —
    so a typo'd enum fails loud at the read. Returns ``default`` when unset."""
    value = os.environ.get(name, default)
    if choices is not None and value not in choices:
        raise FatalConfigError(f"{name} must be one of {tuple(choices)}; got {value!r}")
    return value
