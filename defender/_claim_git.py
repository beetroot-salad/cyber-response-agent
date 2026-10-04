"""Git over a worktree an agent can write, as one claim sees it (#1175).

The agent writes into the corpus (`corpus_rel`), and git opens a worktree `.gitignore` or
`.gitattributes` when it walks or hashes there: one left as a FIFO blocks that call for good, a
plain one rewrites what a check sees (a `*` hides every new file from `status`) or what git
hashes. `ClaimGit` is every git call such a lane makes over the worktree, and none opens either:

- attributes come from HEAD's tree (`_git.committed_view_env`), and no repo hook or automatic
  maintenance runs in any call (`_LOCAL_ONLY`, as `GIT_CONFIG_*` so every call carries it);
- `changes` lists tracked paths with `status --untracked-files=no` (no folder walk) and new
  files under the corpus with `ls-files --others`, filtered by HEAD's root `.gitignore` read
  from the commit, never from the worktree;
- `commit` stages from those same records onto an index reset to HEAD and commits the index
  alone: it reads nothing from the worktree;
- `claim`'s cleanup runs `clean` with `-x` (no ignore rules), scoped to the corpus.

Each call is bounded by the session's `timeout`, and an overrun is `GitOverran`: a `GitError`,
so a caller routes it as a systemic fault, and not a `SubprocessError`, which a transient
handler would swallow. A FIFO git never opens is left standing; git does not list special files,
and a later scrub refuses the tree.
"""
from __future__ import annotations

import contextlib
import functools
import logging
import tempfile
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import TypeVar

from defender import _git
from defender._env import FatalConfigError

_logger = logging.getLogger(__name__)

_T = TypeVar("_T")

#: Every call a local operation only: no repo hook, no automatic `gc` or maintenance. A call
#: still running after the bound is then blocked, not busy.
_LOCAL_ONLY = (("core.hooksPath", "/dev/null"), ("gc.auto", "0"), ("maintenance.auto", "false"))


def _session_env() -> dict[str, str]:
    """`committed_view_env` plus `_LOCAL_ONLY` as `GIT_CONFIG_KEY_n`/`VALUE_n`, appended after any
    the process already exports. Built per call, never cached: it is this process's environment
    at the moment git runs."""
    env = _git.committed_view_env()
    base = int(env.get("GIT_CONFIG_COUNT", "0") or "0")
    for i, (key, value) in enumerate(_LOCAL_ONLY, start=base):
        env[f"GIT_CONFIG_KEY_{i}"] = key
        env[f"GIT_CONFIG_VALUE_{i}"] = value
    env["GIT_CONFIG_COUNT"] = str(base + len(_LOCAL_ONLY))
    return env


class GitOverran(_git.GitError):
    """A git call that did not answer within its bound."""

    def __init__(self, args: Sequence[str], timeout: float | None) -> None:
        self.returncode = -1
        self.stderr = ""
        self.timeout = timeout
        RuntimeError.__init__(
            self, f"git {' '.join(args)} did not answer within {timeout}s — refusing the tick")


def _or_overran(fn: Callable[..., _T], *args: object, **kwargs: object) -> _T:
    """`fn(*args, **kwargs)`, its `GitTimeout` re-raised as `GitOverran`."""
    try:
        return fn(*args, **kwargs)
    except _git.GitTimeout as e:
        cmd = e.cmd if isinstance(e.cmd, list) else [str(e.cmd)]
        raise GitOverran([str(c) for c in cmd[1:]], e.timeout) from e


class ClaimGit:
    """One claim's git over the worktree at `root`, whose agent-writable corpus is the
    `*.md` files under `corpus_rel`. `timeout` bounds every call. Building one runs no git."""

    def __init__(self, root: Path, corpus_rel: str, *, timeout: float) -> None:
        self.root = root
        self.corpus_rel = corpus_rel
        self.timeout = timeout

    def in_corpus(self, path: str) -> bool:
        """Whether a repo-relative path is a corpus file, the only kind the agent may change."""
        return path.startswith(self.corpus_rel) and path.endswith(".md")

    def _git(self, args: Sequence[str], **kwargs: object) -> str:
        return _or_overran(_git.git, args, cwd=self.root, timeout=self.timeout,
                           env=_session_env(), **kwargs)

    @functools.cached_property
    def _ignore_rules(self) -> bytes:
        """HEAD's root `.gitignore`, the only ignore rules `changes` applies, read once.

        A `.gitignore` committed on the path to the corpus or inside it is refused instead: its
        rules would be dropped silently, listing what it ignores as strays."""
        parts = self.corpus_rel.strip("/").split("/")
        ancestors = ["/".join(parts[:i]) + "/.gitignore" for i in range(1, len(parts))]
        listing = self._git(["ls-tree", "-r", "-z", "--full-name", "--name-only", "HEAD", "--",
                             *ancestors, self.corpus_rel])
        found = sorted(p for p in listing.split("\0") if p.rsplit("/", 1)[-1] == ".gitignore")
        if found:
            raise FatalConfigError(
                f"a .gitignore is committed on the path to or inside {self.corpus_rel}: "
                f"{found}; only the root .gitignore's rules are read from HEAD — refusing the tick"
            )
        rules = _or_overran(_git.git_show_file, self.root, "HEAD", ".gitignore",
                            timeout=self.timeout, env=_session_env())
        return (rules or "").encode("utf-8", "surrogateescape")

    def changes(self) -> list[tuple[str, str]]:
        """What changed, as `(XY, path)` records: tracked paths anywhere in the repo, and new
        files under the corpus as `??`.

        Untracked files outside the corpus are not listed: the agent cannot write there, and
        listing them would walk the corpus under the worktree's own ignore files (#1175 N1)."""
        records = _or_overran(_git.git_status, self.root, untracked="no", timeout=self.timeout,
                              env=_session_env())
        with tempfile.TemporaryDirectory() as tmp:
            # Outside the worktree, so the rules file is never itself a new file.
            exclude_from = Path(tmp) / "exclude"
            exclude_from.write_bytes(self._ignore_rules)  # lint-unguarded-tree-write: ok — a private temp dir outside every shared tree
            untracked = _or_overran(_git.git_untracked, self.root, self.corpus_rel,
                                    exclude_from=exclude_from, timeout=self.timeout,
                                    env=_session_env())
        return [*records, *(("??", path) for path in untracked)]

    def changed_outside_corpus(self) -> list[str]:
        """The changed paths that are not corpus files: the before-agent baseline a scope check
        subtracts."""
        return [path for _xy, path in self.changes() if not self.in_corpus(path)]

    def commit(self, admitted: Sequence[str], message: str) -> str | None:
        """Commit exactly `admitted`, paths a scope check let through from `changes`; `None` when
        nothing changed.

        Each path's change is read from `changes` again, the same view the check judged: a
        deletion is removed from the index, anything else added (`add -f`, so no ignore rules
        are read). The index is reset to HEAD first and committed alone, without a pathspec, so
        nothing else staged rides in and nothing at an admitted path is read from the worktree
        at commit time."""
        if not admitted:
            return None
        current = {path: xy for xy, path in self.changes()}
        missing = sorted(p for p in admitted if p not in current)
        if missing:
            raise _git.GitError(["commit"], -1,
                                f"admitted paths no longer changed: {missing}")
        deleted = [p for p in admitted if "D" in current[p]]
        present = [p for p in admitted if "D" not in current[p]]
        self._git(["read-tree", "HEAD"])
        if present:
            self._git(["add", "-f", "--", *present])
        if deleted:
            self._git(["rm", "--cached", "--ignore-unmatch", "-q", "--", *deleted])
        nothing_staged = _or_overran(_git.git_ok, ["diff", "--cached", "--quiet"], cwd=self.root,
                                     timeout=self.timeout, env=_session_env())
        if nothing_staged:
            return None
        self._git(["commit", "-q", "-F", "-"], input=message)
        return self._git(["rev-parse", "HEAD"])

    def reset(self) -> None:
        """Put the worktree back to HEAD: `reset --hard`, then `clean -x` over the corpus
        (whole-repo `-x` would delete ignored worktree state such as the `.venv` link)."""
        if not (self.root / ".git").exists():
            return
        self._git(["reset", "--hard", "--quiet"])
        self._git(["clean", "-fdqx", "--", self.corpus_rel])

    @contextlib.contextmanager
    def claim(self) -> Iterator[ClaimGit]:
        """Run one claim, then `reset`.

        With a fault propagating, any cleanup failure is logged and dropped, so that fault keeps
        its routing. Otherwise — served, dead-lettered, re-queued — it is raised: the next claim
        would run, and commit, over this one's leftovers."""
        try:
            yield self
        except BaseException:
            try:
                self.reset()
            except Exception as e:  # noqa: BLE001 — the propagating fault outranks any cleanup failure
                _logger.error(f"worktree cleanup failed under an in-flight fault: {e!r}")
            raise
        self.reset()
