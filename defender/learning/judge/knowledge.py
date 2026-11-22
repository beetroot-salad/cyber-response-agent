"""Where a post-move sibling's lesson bodies are read (#1618 K5): a copy of the tenant's knowledge at one commit, made by a
copy seam (the job helper's `copy.make` by default), never anything kept on this host."""
from __future__ import annotations

import contextlib
import dataclasses
import os
from collections.abc import Callable
from contextlib import AbstractContextManager
from pathlib import Path
from typing import Any

from defender import _io
from defender.learning.judge._errors import KnowledgeRefused

#: The agent root's folder inside a copy.
AGENT_DIR = "agent"

#: A copy of the tenant's knowledge at a commit: opened for a body's read and released at the pass's end (`KnowledgeBodies.close`);
#: it yields the copy's folder, and a refusal is `KnowledgeRefused` naming why.
KnowledgeCopy = Callable[[str], AbstractContextManager[Path]]


def helper_copy(commit: str) -> AbstractContextManager[Path]:
    """The default copy path, in a job container (#1618 F3): the job helper's `copy.make(commit=)` over the job socket. The helper
    fetches (the judge holds no credential and no git connection), owns the copy and removes it at its end; a refusal of the
    helper's is `KnowledgeRefused`, naming the commit and the helper's reason."""
    from defender import job_socket

    ask = job_socket.from_environ(os.environ)
    if ask is None:
        raise KnowledgeRefused(f"knowledge commit {commit}: this pass has no job socket and no copy seam to read it through")
    try:
        path = Path(ask("copy.make", commit=commit)["path"])
    except job_socket.Refused as refused:
        raise KnowledgeRefused(f"knowledge commit {commit} could not be copied: {refused}") from None
    except (OSError, ValueError, KeyError, TypeError) as broken:
        raise KnowledgeRefused(f"knowledge commit {commit} could not be copied: the job socket failed ({broken!r})") from None
    return contextlib.nullcontext(path)


@dataclasses.dataclass
class KnowledgeBodies:
    """Where a post-move sibling's lesson bodies are read (O6, #1108 P4): a copy of the tenant's knowledge at the family's
    knowledge pin (`records._knowledge_pin`), made by `copy` (the helper's, in a job container) and fetched by commit id from
    Forgejo, never `main`'s tip nor anything kept on this host. `why` names what made the bodies unreadable (an `unversioned`
    or `unavailable` stamp, none recorded, or a commit that is not an object id); a copy `copy` refuses is `JudgeRefused`, the
    pass's (`KnowledgeRefused`). The copy is made once, on the first read, so a pass that never needs it touches nothing; `close` releases it."""

    knowledge: Any
    copy: KnowledgeCopy = helper_copy
    _copy_dir: Path | None = None
    _why: str | None = None
    _resolved: bool = False
    _held: contextlib.ExitStack = dataclasses.field(default_factory=contextlib.ExitStack, repr=False)

    def read(self, rel: str) -> tuple[str | None, str | None]:
        """`(body, None)` for the copy's `agent/<rel>`, or `(None, why)`."""
        self._resolve()
        if self._copy_dir is None:
            return None, self._why
        try:
            text, why = _io.rooted_read(self._copy_dir, f"{AGENT_DIR}/{rel}")
        except ValueError as not_a_name:
            return None, f"unreadable: {AGENT_DIR}/{rel} is not a name in the copy ({not_a_name})"
        if text is None:
            return None, f"unreadable: {AGENT_DIR}/{rel} in the copy could not be read ({why})"
        return text, None

    def close(self) -> None:
        self._held.close()

    def _resolve(self) -> None:
        if self._resolved:
            return
        self._resolved = True
        from defender.records.formats import OID, KnowledgeRevision

        revision = KnowledgeRevision.from_wire(self.knowledge)
        if revision is None:
            self._why = "unreadable: no knowledge commit is recorded for this sibling"
        elif revision.unavailable is not None:
            self._why = ("unreadable: the sibling's knowledge was unavailable: "
                         f"{revision.unavailable}")
        elif revision.commit is None:
            self._why = "unreadable: the sibling's knowledge was unversioned"
        elif not OID.fullmatch(revision.commit):
            self._why = f"unreadable: {revision.commit!r} is not a knowledge commit id"
        else:
            self._copy_dir = self._held.enter_context(self.copy(revision.commit))
