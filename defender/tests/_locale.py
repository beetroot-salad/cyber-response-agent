"""The one spelling of "a shell with no locale", for every test that spawns one.

A bare `LC_ALL=C` does NOT reproduce it: PEP 538 coerces `C` to `C.UTF-8` and PEP 540 turns
UTF-8 mode on, so both have to be switched off explicitly. Python's own bin dir is on `PATH`
because the child is usually `sys.executable` re-spawning itself. Spelled once so that the
next interpreter knob is added in one place.
"""
from __future__ import annotations

import sys
from pathlib import Path

C_LOCALE_ENV = {
    "PATH": f"{Path(sys.executable).parent}:/usr/bin:/bin",
    "PYTHONCOERCECLOCALE": "0",
    "PYTHONUTF8": "0",
    "LC_ALL": "C",
    "LANG": "C",
}
