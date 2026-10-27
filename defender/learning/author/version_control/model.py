"""Validated changes, delivery results and refusal boundaries."""

from __future__ import annotations

import contextlib
import re
from collections.abc import Iterable, Iterator, Sequence
from dataclasses import dataclass
from enum import StrEnum

from defender import _git
from defender.tenancy._exports import DeliveryRefused
from defender.records._tenant_id import TenantRefused

from .auth import ForgejoAuthError
from .forgejo import ForgeError, PullRequest


class LockBusy(DeliveryRefused):
    """Another process holds the tenant's knowledge lock: raised at once, naming its pid."""


@contextlib.contextmanager
def _refusals() -> Iterator[None]:
    """Every fault below a public call, as the one refusal type callers handle. A `TypeError`
    (a caller handing the commit-maker something that is not a `ChangeSet`) is a programming
    error and passes through."""
    try:
        yield
    except DeliveryRefused:
        raise
    except (
        _git.GitError,
        _git.GitTimeout,
        ForgeError,
        ForgejoAuthError,
        TenantRefused,
        OSError,
        ValueError,
    ) as e:
        raise DeliveryRefused(str(e)) from e


#: Names no change may carry at any depth: git's own metadata and the files that reconfigure
#: how git reads a tree (amendment 2, O-C). Compared without case, as a case-folding checkout
#: would read them.
_GIT_CONTROL_NAMES = frozenset({".git", ".gitattributes", ".gitignore", ".gitmodules"})
#: The tenant's identity marker, checked once at publish and never changed by a commit.
_TENANT_ID_PARTS = ("agent", ".tenant-id")
#: What a batch id or a reverted lesson's name may be: one word that is at once a branch-name
#: component, a folder name and a container-name part.
_WORD = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
#: A full git object id (SHA-1 or SHA-256).
_OID = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
#: Tree entry modes of a regular file.
_REGULAR_MODES = frozenset({"100644", "100755"})


def _plain_component(part: str) -> bool:
    """A path component that names one plain entry: not empty, not a dot segment, no control
    character, not led by whitespace, and UTF-8 (a name that does not encode is refused)."""
    if part in {"", ".", ".."} or part[0].isspace():
        return False
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in part):
        return False
    try:
        part.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _agent_path(path: object) -> str:
    """`path` as a commit path: repo-relative POSIX below `agent/`, every component plain, never
    `agent/.tenant-id` and never a git control name at any depth. A refusal names it."""
    if not isinstance(path, str):
        raise TypeError(f"an agent path is a str, not {type(path).__name__}")
    parts = tuple(path.split("/"))
    if (
        len(parts) < 2
        or parts[0] != "agent"
        or not all(_plain_component(p) for p in parts)
    ):
        raise DeliveryRefused(f"{path!r} is not a plain path below agent/")
    if parts == _TENANT_ID_PARTS:
        raise DeliveryRefused(
            "agent/.tenant-id is the tenant's identity: no change may touch it"
        )
    if any(part.casefold() in _GIT_CONTROL_NAMES for part in parts):
        raise DeliveryRefused(
            f"{path!r} names a git control file: no change may carry one"
        )
    return path


def _lane(lane: object) -> tuple[str, ...]:
    """A lane, a folder below `agent/` a batch's box may write, as its components."""
    if not isinstance(lane, str):
        raise TypeError(f"a lane is a str, not {type(lane).__name__}")
    parts = tuple(lane.split("/"))
    if not all(_plain_component(p) for p in parts) or any(
        p.casefold() in _GIT_CONTROL_NAMES for p in parts
    ):
        raise DeliveryRefused(f"lane {lane!r} is not a plain folder below agent/")
    return parts


def _lanes(lanes: object) -> tuple[str, ...]:
    if isinstance(lanes, str) or not isinstance(lanes, Iterable):
        raise TypeError("lanes are a sequence of folder names below agent/")
    declared = tuple(lanes)
    for lane in declared:
        _lane(lane)
    if not declared or len(set(declared)) != len(declared):
        raise DeliveryRefused(
            f"a batch declares one or more distinct lanes, not {declared!r}"
        )
    return declared


def _in_lanes(path: str, lanes: Sequence[str]) -> bool:
    """`agent/<lane>/...`: strictly below one lane, compared by components, so a sibling whose
    name begins with a lane's (`lessons-questioner` beside `lessons`) is outside it."""
    below = path.split("/")[1:]
    return any(
        len(below) > len(parts) and tuple(below[: len(parts)]) == parts
        for parts in map(_lane, lanes)
    )


def _require_in_lanes(path: str, lanes: Sequence[str]) -> None:
    if not _in_lanes(path, lanes):
        raise DeliveryRefused(
            f"{path!r} is outside the lanes {list(lanes)}: no change may carry it"
        )


def _one_word(word: object, what: str) -> str:
    if not isinstance(word, str) or not _WORD.fullmatch(word):
        raise DeliveryRefused(
            f"{what} {word!r} is not one word of letters, digits, '-' or '_'"
        )
    return word


# ==========================================================================================
# ChangeSet: the commit-maker's sole input
# ==========================================================================================


@dataclass(frozen=True)
class AgentChange:
    """One file's new state: `path` repo-relative POSIX below `agent/`; `content` its exact
    bytes, or `None` when the file is deleted."""

    path: str
    content: bytes | None

    def __post_init__(self) -> None:
        _agent_path(self.path)
        if self.content is not None and not isinstance(self.content, bytes):
            raise TypeError(
                f"the content of {self.path!r} is bytes or None, not "
                f"{type(self.content).__name__}"
            )
        # Plain `str` and `bytes`, whatever subclass was given: nothing reachable from a change
        # can be changed after it is built.
        object.__setattr__(self, "path", str.__str__(self.path))
        if self.content is not None:
            object.__setattr__(self, "content", bytes(self.content))


@dataclass(frozen=True)
class ChangeSet:
    """An immutable set of `AgentChange`s, at most one per path: the only thing the
    commit-maker commits. Built from a draft (`Batch.change_set`) or from history (revert)."""

    changes: tuple[AgentChange, ...]

    def __post_init__(self) -> None:
        changes = tuple(self.changes)
        if not all(isinstance(change, AgentChange) for change in changes):
            raise TypeError("a ChangeSet holds AgentChange values only")
        paths = [change.path for change in changes]
        if len(set(paths)) != len(paths):
            raise DeliveryRefused(f"a change set names a path twice: {sorted(paths)}")
        object.__setattr__(self, "changes", changes)

    def __iter__(self) -> Iterator[AgentChange]:
        return iter(self.changes)

    def __len__(self) -> int:
        return len(self.changes)


class DeliveryStatus(StrEnum):
    """Where a batch (or a revert) stands with the forge."""

    OPENED = "opened"
    """A PR this call opened."""
    OPEN = "open"
    """An open PR this call found; nothing was pushed or opened."""
    MERGED = "merged"
    CLOSED = "closed"
    """Closed unmerged: a rejection (D-closed)."""
    NOTHING = "nothing to deliver"
    """No branch, or a branch holding nothing past its base."""


@dataclass(frozen=True)
class Delivered:
    """`status`, and the PR's `url` for `opened` and `open` (also kept for `merged` and
    `closed`)."""

    status: DeliveryStatus
    url: str | None = None


#: When several of the forge's PRs carry a batch's commits, the one answered: an open one
#: first (the live review), then a merged one, then a closed one.
_PRECEDENCE = {"open": 0, "merged": 1, "closed": 2}


def _answer(pr: PullRequest) -> Delivered:
    statuses = {
        "open": DeliveryStatus.OPEN,
        "merged": DeliveryStatus.MERGED,
        "closed": DeliveryStatus.CLOSED,
    }
    return Delivered(status=statuses[pr.status], url=pr.url)
