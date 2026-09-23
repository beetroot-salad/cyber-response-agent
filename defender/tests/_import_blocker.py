"""One way to ask "does this import cleanly without that package installed?".

Six tests had hand-rolled this: a `-c` source string that puts a finder on `sys.meta_path`
which raises for the packages under test, then imports something and prints a verdict. The
copies had drifted on the one detail that decides whether the block actually happens.

**Three of them used `find_module`, which does not exist any more.** The import system dropped
it in 3.12; 3.11 still honours it, but only through a deprecated fallback that emits
`ImportWarning: X.find_spec() not found; falling back to find_module()`. This project's
`requires-python` is `>=3.11`, so on 3.12 those finders are simply skipped — the package
imports fine, the body passes, and the test goes green having blocked nothing. That is the
failure this module exists to make impossible: it emits `find_spec` and nothing else, and
`test_import_blocker.py` pins that the mechanism fires by blocking a module that is certainly
importable and watching the import fail.

Two shapes, because the tests want opposite things:

  * `block=` names what must NOT be importable — "this code path does not need pydantic".
  * `allow_only=` names the only things that may be imported — "this closure is stdlib plus
    our own tree, and a dependency added to it later must fail here". A denylist cannot say
    that: it passes anything nobody thought to list.

Matching is on the TOP-LEVEL package name, so blocking `pydantic` blocks `pydantic.fields`
too. An entry ending in `*` is a prefix: `pydantic*` also covers `pydantic_core`,
`pydantic_ai`, `pydantic_graph` and `pydantic_settings`, which is stronger than naming three
of the five and is what one caller relied on.
"""
from __future__ import annotations

import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

__all__ = ["blocker_source", "run_blocked"]

#: Every caller had its own (120 or 180) and none had a reason; a blocked import either fails
#: in milliseconds or the child is wedged.
_TIMEOUT_S = 180


def blocker_source(*, block: Sequence[str] = (), allow_only: Sequence[str] | None = None) -> str:
    """The prelude that installs the finder. Exposed for a caller that must build its own
    command line; everyone else wants `run_blocked`."""
    if (allow_only is None) == (not block):
        raise ValueError("pass exactly one of `block=` or `allow_only=`")
    if allow_only is not None:
        rule = (f"    _ALLOW = {tuple(allow_only)!r}\n"
                "    return top not in _ALLOW and top not in sys.stdlib_module_names\n")
    else:
        exact = tuple(n for n in block if not n.endswith("*"))
        prefixes = tuple(n[:-1] for n in block if n.endswith("*"))
        rule = (f"    return top in {exact!r} or top.startswith({prefixes!r})\n"
                if prefixes else f"    return top in {exact!r}\n")
    return (
        "import sys\n"
        "def _refused(top):\n"
        + rule +
        "class _Blocker:\n"
        # `find_spec`, never `find_module`: see this module's docstring.
        "    def find_spec(self, name, path=None, target=None):\n"
        "        top = name.split('.')[0]\n"
        "        if _refused(top):\n"
        "            raise ModuleNotFoundError(\n"
        "                f'{name!r} is refused by the test import blocker')\n"
        "        return None\n"
        "sys.meta_path.insert(0, _Blocker())\n"
    )


def run_blocked(
    body: str,
    *,
    block: Sequence[str] = (),
    allow_only: Sequence[str] | None = None,
    argv: Sequence[str] = (),
    cwd: Path | str | None = None,
    env: Mapping[str, str] | None = None,
    stdin: bytes | None = None,
    no_site: bool = False,
) -> subprocess.CompletedProcess[bytes]:
    """Run `body` in a child interpreter that refuses the named imports.

    A child, not this process: an import already done cannot be undone, and by the time a test
    runs, pytest has imported most of the tree. `stdout`/`stderr` come back as BYTES, because
    one caller reads a binary protocol frame off stdout; decode at the call site.

    `no_site` adds `-S`, for a caller checking what a bare interpreter can reach.
    """
    cmd = [sys.executable]
    if no_site:
        cmd.append("-S")
    cmd += ["-c", blocker_source(block=block, allow_only=allow_only) + body, *argv]
    return subprocess.run(
        cmd, input=stdin, capture_output=True, check=False,
        cwd=None if cwd is None else str(cwd), env=None if env is None else dict(env),
        timeout=_TIMEOUT_S,
    )
