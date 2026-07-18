"""The salted quarantine delimiter around untrusted data.

`wrap` frames one untrusted payload — data-source output, the raw alert, a read of
an attacker-influenced file, the gather subagent's returned summary — in run-scoped
delimiters carrying the run's per-run trust token. `defender/SKILL.md` tells MAIN to
read anything inside `<run-{salt}-…>` as evidence and never as instructions; because
the token is minted per run from `secrets` (`run_common.materialize_run_dir`) and
never leaves the process, a payload author cannot forge the closing delimiter.

Lives under `runtime/` beside its four callers (orient, the generic tools, the query
tool, gather dispatch) — this is a runtime concern, not a hook. It was relocated here
from a retired PostToolUse hook module (#647), whose entrypoint nothing had called
since the in-process driver replaced the `claude -p` runtime; the delimiter format is
unchanged by that move.
"""

from __future__ import annotations


def wrap(content: str, tag: str, salt: str) -> str:
    """`content` framed in the run-scoped `tag` delimiters for `salt`.

    The body passes through byte-for-byte; the frame is the only addition.
    """
    return f"<run-{salt}-{tag}>\n{content}\n</run-{salt}-{tag}>"
