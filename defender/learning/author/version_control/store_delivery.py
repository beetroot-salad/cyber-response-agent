"""Delivery over the learning store (#1278): the commit-maker's record as the store holds it, a batch's
PR opened and looked up by its branch, and cited ids read from a commit's tree. A lesson is reverted by a person in
Forgejo's editor (#1592 F3, F9), not here.

The store owns unpublished work and the commit record; Git and the forge own what was published and
reviewed (P1). Nothing here decides a batch's phase: callers do, through the store's verbs."""

from __future__ import annotations

from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import Any

from defender._frontmatter import FrontmatterError, split_frontmatter

from .repository import GitRepository

#: Regular-file tree modes (a link or a submodule entry cites nothing).
_REGULAR = frozenset({"100644", "100755"})


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
        """Every path the batch's commits changed, in record order."""
        seen: dict[str, None] = {}
        for r in self.rows:
            if r.batch_id is not None and str(r.batch_id) == str(batch_id):
                for path, _before, _after in r.changes:
                    seen.setdefault(path)
        return tuple(seen)


def open_pr_on(repository: GitRepository, *, branch: str, title: str, body: str) -> tuple[int, str]:
    """Open the PR of `branch` against `main`: `(number, url)`, the number the forge's create response gave (#1471)."""
    opened = repository.open_pr(branch=branch, title=title, body=body)
    return opened.number, opened.url


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


__all__ = ["StoreRecord", "cited_in_paths", "cited_in_tree", "open_pr_on", "tip_commits_recorded"]
