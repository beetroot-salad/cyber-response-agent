"""The adoption delivery step (#1471 A3, P-9): a carried adapter's base files offered to a tenant's repository as one pull request.

`adopt(repository, *, system, rendering, digest)` fetches `origin/main` itself, reads the repository's pull requests in every state,
and answers one `AdoptionRecord`, deciding in A3's order from the digest `d` of the current rendering:

1. any pull request of the system (head label `adopt/<system>/...`, any digest) is open: `already_open`;
2. one on `adopt/<system>/<d>` was merged: `nothing_to_adopt`;
3. `main` already holds every rendered file, as blobs of the same bytes in mode 100644: `nothing_to_adopt`;
4. one on `adopt/<system>/<d>` was closed unmerged: `rejected`;
5. otherwise the rendering is committed once off the fetched `main` (adding or replacing those paths only), pushed to
   `adopt/<system>/<d>`, and one pull request is opened: `opened`.

A pull request is matched by its head label, which keeps the branch name after the branch is deleted (G-A11). A refused push or a
refused or lost pull-request create is settled by reading the forge again: a pull request that now names the branch is answered by
steps 1-4; none, and the branch (when it is pushed) holds the rendering at every path, opens it; anything else is `delivery_failed`.
The step never merges, closes, deletes or force-pushes, and makes no store record. Fetching has one owner, here, and a ref-lock
collision on the shared clone is `repository_busy`.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass

from defender import _git
from defender.records.job_lane import AdoptionRecord
from defender.system_rules import base_files

from .forgejo import ForgeError, PullRequest
from .model import AgentChange, ChangeSet
from .repository import GitRepository

_logger = logging.getLogger(__name__)

#: The fixed reasons `adopt` answers (`job_lane.ADOPTION_CONTAINER_REASONS`).
REPOSITORY_BUSY = "repository_busy"
DELIVERY_FAILED = "delivery_failed"
#: How many times a pull-request create is made (a refused or lost first one is read back, then made once more).
_CREATE_ATTEMPTS = 2


@dataclass(frozen=True)
class _Matches:
    """What the repository's pull requests say of one system's adoption branches, each list in ascending number."""

    open: list[PullRequest]
    merged_on_d: list[PullRequest]
    closed_on_d: list[PullRequest]


def adopt(repository: GitRepository, *, system: str, rendering: dict[str, bytes], digest: str) -> AdoptionRecord:
    """Offer `rendering` (`{agent/<path>: bytes}`, digest `digest`) to the repository's `main` for `system` (module doc)."""
    branch = base_files.branch_of(system, digest)
    refused = _fetch(repository)
    if refused is not None:
        return refused
    try:
        decided = _decide(repository, system, branch, rendering)
        if decided is not None:
            return decided
        main = repository.revision("refs/remotes/origin/main")
        commit, _after = repository.make_commit(main, _change_set(rendering), _commit_message(system, digest))
        return _push_and_open(repository, system, branch, rendering, commit, digest)
    except Exception:  # noqa: BLE001 — A3: whatever a step raised, a fixed reason; the cause goes to the log
        _logger.exception("adoption of %s: the delivery failed", system)
        return AdoptionRecord.failed(DELIVERY_FAILED)


def _fetch(repository: GitRepository) -> AdoptionRecord | None:
    """The one fetch of `origin` both of `adopt`'s fetches use: None when it succeeded, else the failed record, a ref-lock
    collision on the shared clone being `repository_busy` and any other fault `delivery_failed`."""
    try:
        repository.fetch()
    except _git.GitError as fault:
        return AdoptionRecord.failed(REPOSITORY_BUSY if _ref_lock_collision(fault) else DELIVERY_FAILED)
    except Exception:  # noqa: BLE001 — A3: any other fetch fault, the forge token's refusal included, is a fixed reason
        _logger.exception("adoption: the fetch of origin failed")
        return AdoptionRecord.failed(DELIVERY_FAILED)
    return None


def _ref_lock_collision(fault: _git.GitError) -> bool:
    """Whether a failed fetch collided on a ref the shared clone holds locked: its one local ref transaction
    (`update-ref --stdin`, `GitTransport.fetch`) names `cannot lock ref` (git 2.47, probed)."""
    return "update-ref" in str(fault) and "cannot lock ref" in fault.stderr


def _adoption_matches(prs: list[PullRequest], system: str, branch: str) -> _Matches:
    prefix = f"adopt/{system}/"
    ours = sorted((pr for pr in prs if pr.head_label is not None and pr.head_label.startswith(prefix)), key=lambda pr: pr.number)
    return _Matches(
        open=[pr for pr in ours if pr.status == "open"],
        merged_on_d=[pr for pr in ours if pr.status == "merged" and pr.head_label == branch],
        closed_on_d=[pr for pr in ours if pr.status == "closed" and pr.head_label == branch],
    )


def _decide(repository: GitRepository, system: str, branch: str, rendering: dict[str, bytes]) -> AdoptionRecord | None:
    """A3 steps 1-4 over the forge's pull requests now and the fetched `main`: the record they give, or `None` for step 5."""
    found = _adoption_matches(repository.forge.pull_requests(), system, branch)
    if found.open:
        return AdoptionRecord("already_open", pr_number=found.open[0].number)
    if found.merged_on_d:
        return AdoptionRecord("nothing_to_adopt")
    if _tree_holds(repository, "refs/remotes/origin/main", rendering):
        return AdoptionRecord("nothing_to_adopt")
    if found.closed_on_d:
        return AdoptionRecord("rejected", pr_number=found.closed_on_d[0].number)
    return None


def _tree_holds(repository: GitRepository, rev: str, rendering: dict[str, bytes]) -> bool:
    """Whether `rev` holds every rendered path as a blob of exactly the rendered bytes in mode 100644 (what the offer's commit
    would write: P-9), compared as the tree's blobs, never a checkout, which an attribute could rewrite."""
    entries = repository.entries(rev, sorted(rendering), recursive=False)
    held = {path: oid for mode, kind, oid, path in entries if kind == "blob" and mode == "100644"}
    if set(held) != set(rendering):
        return False
    stored = repository.blobs(held.values())
    return all(stored[held[path]] == content for path, content in rendering.items())


def _change_set(rendering: dict[str, bytes]) -> ChangeSet:
    return ChangeSet(tuple(AgentChange(path, content) for path, content in sorted(rendering.items())))


def _push_and_open(repository: GitRepository, system: str, branch: str, rendering: dict[str, bytes], commit: str,
                   digest: str) -> AdoptionRecord:
    try:
        repository.push(commit, branch)
    except _git.GitError:
        return _after_refused_push(repository, system, branch, rendering, digest)
    return _open_pull_request(repository, system, branch, rendering, digest)


def _after_refused_push(repository: GitRepository, system: str, branch: str, rendering: dict[str, bytes],
                        digest: str) -> AdoptionRecord:
    """The branch refused our push (git refuses a non-fast-forward: a racer's commit of the same tree has another id).
    The branch is fetched; a pull request now naming it is answered by steps 1-4; none, and its tip holding the rendering at
    every path, the pull request is opened on that tip; anything else fails. The branch is never moved."""
    refused = _fetch(repository)
    if refused is not None:
        return refused
    decided = _decide(repository, system, branch, rendering)
    if decided is not None:
        return decided
    tip = f"refs/remotes/origin/{branch}"
    if not repository.holds_ref(tip) or not _tree_holds(repository, tip, rendering):
        return AdoptionRecord.failed(DELIVERY_FAILED)
    return _open_pull_request(repository, system, branch, rendering, digest)


def _open_pull_request(repository: GitRepository, system: str, branch: str, rendering: dict[str, bytes], digest: str) -> AdoptionRecord:
    """The pull request of `branch`, made once. A create the forge refused or whose reply was lost (a 409 for an open pull
    request on the head, a 5xx, a cut connection) is read back from the forge: a pull request naming the branch is answered by
    steps 1-4, and with none the create is made once more; never a second pull request."""
    for attempt in range(_CREATE_ATTEMPTS):
        try:
            opened = repository.open_pr(branch=branch, title=_title(system), body=_adoption_pr_body(system, branch, digest))
        except ForgeError:
            decided = _decide(repository, system, branch, rendering)
            if decided is not None:
                return decided
            if attempt + 1 == _CREATE_ATTEMPTS:
                break
        else:
            return AdoptionRecord("opened", pr_number=opened.number)
    return AdoptionRecord.failed(DELIVERY_FAILED)


def _title(system: str) -> str:
    return f"adopt: base files for {system}"


def _commit_message(system: str, digest: str) -> str:
    return f"Adopt the base files for {system} (rendering {digest[:16]})\n"


def _adoption_pr_body(system: str, branch: str, digest: str) -> str:
    return (
        f"The product's base files for `{system}` (rendering `{digest[:16]}`), offered on `{branch}`. The pull request "
        "adds or replaces the files it lists under `agent/` and deletes nothing: a file you edited at one of those "
        "paths is replaced when this merges, so review it or edit it first. Close it to decline; this rendering is not "
        "offered again until a release changes it."
    )
