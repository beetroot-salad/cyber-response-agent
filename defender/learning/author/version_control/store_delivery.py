"""Delivery over the learning store (#1278): the commit-maker's record as the store holds it, a batch's
PR opened and looked up by its branch, cited ids read from a commit's tree, and the lesson revert as a
batch of kind revert.

The store owns unpublished work and the commit record; Git and the forge own what was published and
reviewed (P1). Nothing here decides a batch's phase: callers do, through the store's verbs."""

from __future__ import annotations

import secrets
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from defender._frontmatter import FrontmatterError, split_frontmatter

from .commits import CommitMaker, _Line
from .delivery import TenantDelivery
from .forgejo import ForgeError
from .model import (
    AgentChange,
    ChangeSet,
    Delivered,
    DeliveryRefused,
    DeliveryStatus,
    _agent_path,
    _one_word,
    _refusals,
)
from .record import _BatchKey, _Made
from .repository import GitRepository

#: Regular-file tree modes (a link or a submodule entry cites nothing).
_REGULAR = frozenset({"100644", "100755"})


@dataclass(frozen=True)
class NetChange:
    """One batch's net change to one path in the store's record: the blob at the batch's base
    (`before`) and the blob its last commit there left (`after`), `None` for absent. `batch` is the
    batch id (a branch for imported history with none). `order` is the position of the last
    commit that touched it (larger is newer)."""

    batch: str
    branch: str
    path: str
    before: str | None
    after: str | None
    order: int


def _batch_of(row: Any) -> str:
    return str(row.batch_id) if row.batch_id is not None else str(row.branch)


@dataclass(frozen=True)
class StoreRecord:
    """The commit-maker's record (`store.commit_record`), tenant-wide, oldest row first."""

    rows: tuple[Any, ...]

    @classmethod
    def of(cls, rows: Iterable[Any]) -> StoreRecord:
        return cls(tuple(rows))

    def commits_of(self, batch_id: str) -> frozenset[str]:
        return frozenset(r.commit for r in self.rows if r.batch_id is not None and str(r.batch_id) == str(batch_id))

    def changed_paths(self, batch_id: str) -> tuple[str, ...]:
        """Every path the batch's commits changed (revert rows included), in record order."""
        seen: dict[str, None] = {}
        for r in self.rows:
            if r.batch_id is not None and str(r.batch_id) == str(batch_id):
                for path, _before, _after in r.changes:
                    seen.setdefault(path)
        return tuple(seen)

    def net_changes(self, path: str) -> list[NetChange]:
        """Every batch's net change to `path`, newest first. A revert commit is provenance only: it
        changes no batch's net change."""
        net: dict[str, NetChange] = {}
        for order, r in enumerate(self.rows):
            if r.reverts:
                continue
            for changed, before, after in r.changes:
                if changed != path:
                    continue
                key = _batch_of(r)
                first = net.get(key)
                net[key] = NetChange(batch=key, branch=r.branch, path=path,
                                     before=first.before if first is not None else before, after=after, order=order)
        return sorted(net.values(), key=lambda c: c.order, reverse=True)

    def reverts_of(self, change: NetChange) -> list[Any]:
        """The revert rows made of `change`, oldest first (a pair names the batch by id, or by branch for
        imported history)."""
        names = {change.batch, change.branch}
        return [r for r in self.rows if any(target in names and p == change.path for target, p in (r.reverts or ()))]


def pr_number(url: str) -> int | None:
    """The PR number a forge PR URL ends with (`.../pulls/<n>`), or `None`."""
    tail = url.rstrip("/").rsplit("/", 1)[-1]
    return int(tail) if tail.isdecimal() else None


def open_pr_on(repository: GitRepository, *, branch: str, title: str, body: str) -> tuple[int, str]:
    """Open the PR of `branch` against `main`: `(number, url)`. A URL naming no number is looked up by
    the branch among the open PRs."""
    url = repository.open_pr(branch=branch, title=title, body=body)
    number = pr_number(url)
    if number is None:
        found = [row for row in repository.forge.list_open_prs(branch) if row["headRefName"] == branch]
        if not found:
            raise ForgeError(f"the PR opened for {branch} ({url}) names no number and cannot be found")
        number = int(found[0]["number"])
    return number, url


def cited_in_tree(repository: GitRepository, commit: str, folder: str, field: str) -> set[str]:
    """Every id the `field` frontmatter list cites in a regular `*.md` file below `folder` of `commit`'s
    tree (no such folder: none)."""
    entries = repository.entries(commit, [folder], recursive=True)
    oids = [oid for mode, kind, oid, path in entries
            if kind == "blob" and mode in _REGULAR and path.startswith(f"{folder}/") and path.endswith(".md")]
    return _cited(repository.blobs(oids).values(), field)


def cited_in_paths(repository: GitRepository, commit: str, paths: Sequence[str], folder: str, field: str) -> set[str]:
    """As `cited_in_tree`, over only `paths` (the files a batch's commits changed) as `commit` holds them."""
    mine = [p for p in paths if p.startswith(f"{folder}/") and p.endswith(".md")]
    if not mine:
        return set()
    blobs = repository.regular_blobs(commit, mine)
    return _cited(repository.blobs(blobs.values()).values(), field)


def _cited(texts: Iterable[bytes], field: str) -> set[str]:
    cited: set[str] = set()
    for data in texts:
        try:
            fm, _raw, _body = split_frontmatter(data.decode("utf-8"))
        except (FrontmatterError, UnicodeDecodeError):
            continue
        value = fm.get(field)
        if isinstance(value, list):
            # As the drain reads a citation (`drain._cited_ids_in`): a numeric id (a feedback comment's, #1414)
            # parses as an int and is cited under its text.
            cited.update(str(c) for c in value if isinstance(c, (str, int)) and not isinstance(c, bool))
    return cited


def tip_commits_recorded(repository: GitRepository, base: str, tip: str, mine: frozenset[str]) -> bool:
    """Whether every commit between `base` and `tip` is one the record holds for the batch (and there is
    at least one): only our commits are pushed (O5)."""
    if not repository.holds_commit(tip) or not repository.holds_commit(base):
        return False
    sent = repository.commits_since(base, tip)
    return bool(sent) and all(commit in mine for commit in sent)


def remote_tip(repository: GitRepository, branch: str) -> str | None:
    """The tip of `branch` as the last fetch saw it on the origin, or `None`."""
    ref = f"refs/remotes/origin/{branch}"
    return repository.revision(ref) if repository.holds_ref(ref) else None


# --- reverts (#1278 Reverts: a batch of kind revert, no items) ------------------------------------------


def _peel(record: StoreRecord, path: str, current: str | None,
          batches: Mapping[str, Any]) -> tuple[NetChange, Any | None]:
    """D-peel over the store: the newest batch's net change to `path` whose result is `current` and which
    has no merged revert, with its last revert's batch (`None`: it has none). Refused when there is none."""
    for change in record.net_changes(path):
        if change.after != current or change.before == change.after:
            continue
        reverts = [batches.get(str(r.batch_id)) for r in record.reverts_of(change) if r.batch_id is not None]
        known = [b for b in reverts if b is not None]
        if any(b.phase == "ended" and b.outcome == "merged" for b in known):
            continue
        return change, (known[-1] if known else None)
    raise DeliveryRefused(
        f"no change the commit-maker made to {path} is what main holds there now, with no merged revert: "
        "nothing to revert")


def revert_lesson(delivery: TenantDelivery, store: Any, *, lesson_path: str, lesson_name: str,
                  owner: str, lanes: Sequence[str]) -> Delivered:
    """Flow 4, D-peel, over the learning store (sync facade `store`): undo the newest batch's net change
    to `lesson_path` that `origin/main` still holds exactly, as a revert batch's one commit on `main`,
    pushed to the batch's own branch with its PR, the batch then in review.

    The change's last revert decides first: in review, its PR is the answer; closed unmerged, a
    rejection, refused and never made again. Refused, claiming nothing, when no change is eligible.
    A working batch of the lane is `LaneBusy` from the claim. A refusal before the commit ends the
    batch at once; one after it (the push, the PR) leaves the batch working, for a takeover."""
    tenant_id = str(delivery.tenant.id)
    repository = delivery.repository
    with _refusals():
        path = _agent_path(lesson_path)
        name = _one_word(lesson_name, "lesson name")
        repository.fetch()
        main = repository.revision("refs/remotes/origin/main")
        record = StoreRecord.of(store.commit_record(tenant_id))
        batches = {str(b.id): b for b in store.batches(tenant_id)}
        change, last = _peel(record, path, repository.regular_blob_on(main, path), batches)
        if last is not None and last.phase != "ended":
            if last.phase == "in_review" and last.pr_number is not None:
                return Delivered(status=DeliveryStatus.OPEN, url=_pr_url(repository, last.branch, last.pr_number))
            raise DeliveryRefused(f"the revert of {path} in batch {last.id} is {last.phase}: it is not made again")
        if last is not None and last.outcome == "closed":
            raise DeliveryRefused(
                f"the revert of {path} the commit-maker last made (batch {last.id}, PR #{last.pr_number}) was "
                "closed unmerged: a rejection, so it is not made again")
        content = None if change.before is None else repository.blobs([change.before])[change.before]
    held = store.claim_revert(tenant_id, owner=owner)
    try:
        with _refusals():
            line = _Line(batch=_BatchKey(branch=held.branch, base=main, start=secrets.token_hex(8)), lanes=tuple(lanes))

            def record_revert(made: _Made) -> None:
                store.record_commit(held, made.commit, made.batch.base, made.batch.start, list(made.changes),
                                    reverts=[[change.batch, path]])

            commit = CommitMaker(delivery.tenant, repository, record_revert).commit(
                line, ChangeSet((AgentChange(path, content),)), f"revert lesson: {name}")
    except BaseException:
        # Nothing reached a branch: the batch ends now, so no refused revert holds the lane.
        _end_quietly(store, held)
        raise
    with _refusals():
        tip = repository.branch_tip(held.branch)
        if tip != commit:
            raise DeliveryRefused(f"the revert branch {held.branch} moved from the commit-maker's commit {commit} "
                                  f"(now {tip}): nothing is pushed")
        repository.push(tip, held.branch)
        number, url = open_pr_on(repository, branch=held.branch, title=f"revert lesson: {name}", body=(
            f"Reverts `{path}` to what it held before the commit-maker's change in batch `{change.batch}`, "
            "which `main` still holds exactly."))
    store.in_review(held, number, {})
    return Delivered(status=DeliveryStatus.OPENED, url=url)


def _pr_url(repository: GitRepository, branch: str, number: int) -> str | None:
    for row in repository.forge.list_open_prs(branch):
        if row["number"] == number:
            return str(row["url"])
    return None


def _end_quietly(store: Any, held: Any) -> None:
    try:
        store.abandon_clean(held)
    except Exception:  # noqa: BLE001 — the refusal in flight is what the caller reports
        import logging

        logging.getLogger(__name__).exception(f"the revert batch {held.batch_id} could not be ended; "
                                              "it lapses for a takeover")


__all__ = ["NetChange", "StoreRecord", "cited_in_paths", "cited_in_tree", "open_pr_on", "pr_number", "remote_tip",
           "revert_lesson", "tip_commits_recorded"]
