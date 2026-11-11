"""The one-time import of a tenant's file learning state into the store (#1278 Migration), and the cutover after it.

`import_learning_state` reads today's layout under the tenant's learning folder (queues, consumed ledgers,
dead-letters, curation requests, retained deliveries, the commit-maker's record) and the tenant's open PRs, settles
every row's fate in memory, and only then writes, in ONE transaction: anything it refuses (`ImportRefused`) or any
failure writes no row, and it never changes a file (G-I10). `cut_over_learning_state` is the separate later step that
retires the folder.

The layout is spelled here, not borrowed from the file state's handle: the handle goes at cutover (A1, O10), and this
reader must read what it wrote until then."""

from __future__ import annotations

import json
import logging
import os
import shutil
import stat
import uuid
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, cast

from sqlalchemy import Table, func
from sqlalchemy.exc import IntegrityError

from defender import _frontmatter, _git, _io
from defender.records.formats import BatchId, TenantId, unwrap_worktrees_root

from ._store import (
    BRANCH_PREFIX,
    REVERT_PREFIX,
    ImportRefused,
    ItemRefused,
    LearningStore,
    _digest,
    _refuse_nul,
    _str_or_none,
    lanes_of_branch,
)
from defender.jobs.learning_models import AUTHOR_LANE, LEAD_LANE, BatchRow, CommitChangeRow, CommitRow


class _Repository(Protocol):
    """What the import reads of a tenant's clone and its forge: the delivery's repository, named by shape so this
    module does not import the delivery package (the run process imports the store; it never reaches delivery)."""

    path: Path
    forge: Any

    def fetch(self) -> Any: ...
    def revision(self, ref: str) -> str: ...
    def holds_ref(self, ref: str) -> bool: ...
    def branch_tip(self, branch: str) -> str | None: ...
    def entries(self, rev: str, paths: Sequence[str], *, recursive: bool) -> Any: ...
    def blobs(self, oids: Iterable[str]) -> Mapping[str, bytes]: ...


class TenantDelivery(Protocol):
    """The tenant's `TenantDelivery`, as far as the import reads it."""

    @property
    def repository(self) -> _Repository: ...

_logger = logging.getLogger(__name__)

_B = cast(Table, BatchRow.__table__)
_C = cast(Table, CommitRow.__table__)
_CC = cast(Table, CommitChangeRow.__table__)

# -- today's layout (state.py's record names, base 071f47d43) ------------------------------------------------------


@dataclass(frozen=True)
class _Channel:
    queue: str
    consumed: str
    deadletter: str
    id_key: str


_CHANNELS: dict[str, _Channel] = {
    "finding": _Channel("_pending/findings.jsonl", "_pending/consumed.jsonl",
                        "_pending/findings.deadletter.jsonl", "finding_id"),
    "questioner_finding": _Channel("_pending/questioner_findings.jsonl", "_pending/questioner_consumed.jsonl",
                                   "_pending/questioner_findings.deadletter.jsonl", "finding_id"),
    "pitfall": _Channel("_pending_pitfalls/pitfalls.jsonl", "_pending_pitfalls/pitfalls.consumed.jsonl",
                        "_pending_pitfalls/pitfalls.deadletter.jsonl", "pitfall_id"),
}
_REQUESTS = "author-queue"
#: #1414's feedback records under the learning folder (A4 'The records, today and after'). Owner ruling Q1 (b): the
#: import refuses while any exists, naming it, and the cutover removes none.
_FEEDBACK_FOLDERS = ("feedback-issue-queue", "feedback-cases", "feedback-seen", "feedback-cursor", "feedback-items",
                     "feedback-decisions")
#: The feedback lessons channel's files under `_pending/` (queue, consumed ledger, dead-letter, stuck, skip report).
_FEEDBACK_CHANNEL = "feedback_lessons"
#: A retained feedback delivery's record name (`<prefix slug>-<batch>.json`) and drain label, and its branch prefix.
_FEEDBACK_DELIVERY = "feedback-"
_FEEDBACK_LABEL = "feedback_drain"
_FEEDBACK_BRANCH = "feedback/"
_DELIVERY = "_pending_delivery"
_COMMIT_RECORD = "commit-maker.jsonl"
_WORKTREES = "worktrees"

#: What a ledger row adds to the row as queued (`state.rotate`, the curators' reason fields).
_LEDGER_FIELDS = ("consumed_category", "consumed_at", "consumed_commit", "skip_reason")
#: What a flat dead-letter record (the file queue's unkeyable-row retirement) adds beside the row's own fields.
_DEADLETTER_FIELDS = ("deadletter_reason", "retired_at")
#: Today's separate counters (G-I5): carried as columns, and no part of a row's identity (a retirement bumps one).
_COUNTERS = ("attempts", "deferrals", "offers_declined")

#: Ledger category -> (status, reason when the row carries none). An unknown category refuses the import (G-I1).
_CATEGORIES: dict[str, tuple[str, str | None]] = {
    "consumed_committed": ("published", None),
    "consumed_idempotent": ("published", None),
    "consumed_skip": ("skipped", "skipped by its curator"),
    "consumed_no_systems": ("skipped", "the row names no systems, so no tenant could select its lesson"),
    "consumed_retired": ("dead", "retired by the drain before the import (consumed_retired)"),
    "consumed_unattributable": ("dead", "dropped as unattributable before the import (consumed_unattributable)"),
}


def _drain_lanes() -> dict[str, str]:
    """A delivery record's drain label -> its lane (imported here, as `lanes_of_branch` does, so the store's door
    loads no drain configuration)."""
    from defender.learning.core.config import AUTHOR_DRAIN_LABEL, LEAD_AUTHOR_DRAIN_LABEL

    return {str(AUTHOR_DRAIN_LABEL): AUTHOR_LANE, str(LEAD_AUTHOR_DRAIN_LABEL): LEAD_LANE}

#: The corpus each findings kind is cited from, under `agent/`, and the frontmatter list that cites it.
_CITED_CORPORA = {"agent/lessons/": "finding", "agent/lessons-questioner/": "questioner_finding"}
_CITATION_FIELD = "source_finding_ids"
_LEAD_REASON = "an imported lead-lane PR: its feedback starts no replacement for imported lead PRs"


@dataclass
class _Item:
    kind: str
    key: str
    payload: dict[str, Any]
    status: str
    reason: str | None = None
    source_run: str | None = None
    coalesce_key: str | None = None
    mistake_key: str | None = None
    counters: dict[str, int] = field(default_factory=dict)
    batch: str | None = None  # the importing batch's branch


@dataclass
class _Batch:
    kind: str
    lane: str
    branch: str
    phase: str
    pr_number: int | None
    reason: str | None
    tip: str | None
    named: str  # how a refusal names it
    base: str | None = None
    start: str | None = None


@dataclass(frozen=True)
class _Commit:
    commit: str
    branch: str
    base: str
    start: str
    changes: tuple[tuple[str, str | None, str | None], ...]
    reverts: list[list[str]] | None


# -- reading the files ------------------------------------------------------------------------------------------------


def _jsonl(bound: _io.Bound, name: str) -> list[dict[str, Any]]:
    rows, malformed, read = bound.read_jsonl(name)
    if read.reason is not None:
        raise ImportRefused(f"{name} could not be read: {read.reason}")
    if malformed:
        _logger.warning("import: %s holds %d unreadable line(s); they import nothing", name, malformed)
    return rows


def _folder_records(bound: _io.Bound, folder: str) -> list[tuple[str, dict[str, Any] | None, str]]:
    """`(name, body or None when unreadable, text)` of each `*.json` file directly in `folder`."""
    listing = bound.under(folder).entries()
    if listing.reason is not None:
        raise ImportRefused(f"{folder}/ could not be listed: {listing.reason}")
    out: list[tuple[str, dict[str, Any] | None, str]] = []
    for name in listing.files():
        if not name.endswith(".json"):
            continue
        read = bound.read(f"{folder}/{name}")
        if read.text is None:
            raise ImportRefused(f"{folder}/{name} could not be read: {read.reason}")
        try:
            body = json.loads(read.text)
        except ValueError:
            body = None
        out.append((name, body if isinstance(body, dict) else None, read.text))
    return out


def _counter(value: object) -> int:
    return value if type(value) is int and value >= 0 else 0


def _dropping(row: Mapping[str, Any], fields: Iterable[str]) -> dict[str, Any]:
    drop = set(fields)
    return {k: v for k, v in row.items() if k not in drop}


def _row_key(row: Mapping[str, Any], id_key: str) -> tuple[str, bool]:
    """The row's key and whether it has one: a keyless row is keyed by the digest of the row as queued, its counters
    aside, so the same original row seen in several files is one item (G-I4)."""
    value = row.get(id_key)
    if isinstance(value, str) and value.strip():
        return value, True
    return _digest(_dropping(row, _COUNTERS)), False


def _new_item(kind: str, key: str, row: dict[str, Any], status: str, reason: str | None) -> _Item:
    item = _Item(kind=kind, key=key, payload=row, status=status, reason=reason,
                 counters={c: _counter(row.get(c)) for c in _COUNTERS})
    if kind == "pitfall":  # lint-half-table: ok — the pitfall's own row shape (mistake key), not its lane
        item.source_run = _str_or_none(row.get("source_run"))
        item.mistake_key = _digest([row.get("system"), row.get("stderr_digest")])
    else:
        item.source_run = _str_or_none(row.get("run_id"))
    return item


def _channel_items(bound: _io.Bound, kind: str) -> list[_Item]:
    """One kind's items. Dead-letter wins over the ledger, the ledger over the queue (Migration, G-I3); a row with no
    key is dead whatever else holds it."""
    channel = _CHANNELS[kind]
    queued: dict[str, tuple[dict[str, Any], bool]] = {}
    for row in _jsonl(bound, channel.queue):
        key, keyed = _row_key(row, channel.id_key)
        queued.setdefault(key, (row, keyed))  # a repeated pitfall id once, as today
    ledgered: dict[str, tuple[dict[str, Any], bool, str, str | None]] = {}
    for rec in _jsonl(bound, channel.consumed):
        category = rec.get("consumed_category")
        if not isinstance(category, str) or category not in _CATEGORIES:
            raise ImportRefused(f"{channel.consumed} holds a row of an unknown ledger category {category!r}: the "
                                "import does not guess its fate")
        row = _dropping(rec, _LEDGER_FIELDS)
        status, default = _CATEGORIES[category]
        reason = rec.get("skip_reason") if isinstance(rec.get("skip_reason"), str) else None
        key, keyed = _row_key(row, channel.id_key)
        ledgered[key] = (rec, keyed, status, reason or default)
    dead: dict[str, tuple[dict[str, Any], bool, str, int]] = {}
    for rec in _jsonl(bound, channel.deadletter):
        nested = rec.get("row")
        row = dict(nested) if isinstance(nested, dict) else _dropping(rec, (*_DEADLETTER_FIELDS, "attempts"))
        key, keyed = _row_key(row, channel.id_key)
        if not keyed and isinstance(rec.get(channel.id_key), str) and rec[channel.id_key].strip():
            key, keyed = rec[channel.id_key], True
        reason = rec.get("deadletter_reason")
        dead[key] = (row, keyed, reason if isinstance(reason, str) and reason else "dead-lettered",
                     _counter(rec.get("attempts")))
    items: list[_Item] = []
    for key in dict.fromkeys([*queued, *ledgered, *dead]):
        items.append(_settle(kind, key, channel.id_key, queued.get(key), ledgered.get(key), dead.get(key)))
    return items


def _settle(kind: str, key: str, id_key: str, queued: Any, ledgered: Any, dead: Any) -> _Item:
    if queued is not None:
        row, keyed = queued
    elif ledgered is not None:
        row, keyed = _dropping(ledgered[0], _LEDGER_FIELDS), ledgered[1]
    else:
        row, keyed = dead[0], dead[1]
    if dead is not None:
        item = _new_item(kind, key, row, "dead", dead[2])
        if queued is None:
            item.counters["attempts"] = max(item.counters["attempts"], dead[3])
    elif ledgered is not None and keyed:
        item = _new_item(kind, key, row, ledgered[2], ledgered[3])
    elif not keyed:
        item = _new_item(kind, key, row, "dead", f"the row has no {id_key}: it is keyed by its digest")
    else:
        item = _new_item(kind, key, row, "waiting", None)
    if not keyed and item.status != "dead":
        item.status, item.reason = "dead", f"the row has no {id_key}: it is keyed by its digest"
    return item


def _requests(bound: _io.Bound) -> list[_Item]:
    """Curation requests: failed ones dead, queued and in-flight ones waiting under the coalesce rule (a queued request
    is the later run for its case: an in-flight one beside it is skipped, superseded)."""
    found: dict[str, _Item] = {}
    for folder, status in ((f"{_REQUESTS}/failed", "dead"), (_REQUESTS, "waiting"), (f"{_REQUESTS}/inflight", "inflight")):
        for name, body, text in _folder_records(bound, folder):
            item = _request(f"{folder}/{name}", body, text, status)
            found.setdefault(item.key, item)
    queued_cases = {i.coalesce_key for i in found.values() if i.status == "waiting" and i.coalesce_key}
    for item in found.values():
        if item.status != "inflight":
            continue
        if item.coalesce_key in queued_cases:
            item.status, item.reason = "skipped", "superseded by a later run"
        else:
            item.status = "waiting"
    return list(found.values())


def _request(name: str, body: dict[str, Any] | None, text: str, status: str) -> _Item:
    if body is None:
        return _Item(kind="curation_request", key=_digest(text), payload={"unreadable": name}, status="dead",
                     reason=f"the request file {name} is not a JSON object")
    run_id, case_id = _str_or_none(body.get("run_id")), _str_or_none(body.get("case_id"))
    keyed = run_id is not None and bool(run_id.strip())
    item = _Item(kind="curation_request", key=run_id if run_id is not None and keyed else _digest(body),
                 payload=dict(body), status=status, source_run=run_id if keyed else None, coalesce_key=case_id)
    if status == "dead":
        failed = body.get("failed")
        item.reason = failed if isinstance(failed, str) and failed else f"a quarantined request ({name})"
    elif not keyed:
        item.status, item.reason = "dead", "the request names no run_id: it is keyed by its digest"
    return item


def _commits(bound: _io.Bound) -> list[_Commit]:
    """The whole commit-maker record, in its order. A row of another shape records nothing, as today (`_Record.read`:
    a torn line's commit is refused by every push route); a row whose lanes are not its branch's lane refuses, and a
    row on a feedback branch refuses (Q1 b)."""
    made: list[_Commit] = []
    malformed = 0
    for row in _jsonl(bound, _COMMIT_RECORD):
        try:
            commit = _record_row(row)
        except ValueError:
            malformed += 1
            continue
        if commit.branch.startswith(_FEEDBACK_BRANCH):
            _refuse_feedback(bound, [commit])
        if tuple(row["lanes"]) != lanes_of_branch(commit.branch):
            raise ImportRefused(f"the commit-maker's row for {commit.commit} on {commit.branch} names lanes "
                                f"{row['lanes']}, not its branch's lane's {list(lanes_of_branch(commit.branch))}")
        made.append(commit)
    if malformed:
        _logger.warning("import: the commit-maker's record holds %d row(s) of another shape; they import nothing",
                        malformed)
    return made


def _oid(value: object, *, absent: bool = True) -> str | None:
    if value is None and absent:
        return None
    if isinstance(value, str) and len(value) == 40 and all(c in "0123456789abcdef" for c in value):
        return value
    raise ValueError(f"not an object id: {value!r}")


def _batch_key(value: object) -> tuple[str, str, str]:
    if not isinstance(value, dict):
        raise ValueError("not a batch")
    branch, base, start = value.get("branch"), value.get("base"), value.get("start")
    if not isinstance(branch, str) or not isinstance(start, str):
        raise ValueError("not a batch")
    return branch, str(_oid(base, absent=False)), start


def _record_row(row: dict[str, Any]) -> _Commit:
    lanes, changes = row.get("lanes"), row.get("changes")
    if not isinstance(lanes, list) or not all(isinstance(lane, str) for lane in lanes) or not isinstance(changes, list):
        raise ValueError("not a commit-maker record row")
    parsed: list[tuple[str, str | None, str | None]] = []
    for change in changes:
        if not isinstance(change, dict) or not isinstance(change.get("path"), str):
            raise ValueError("not a commit-maker change")
        parsed.append((change["path"], _oid(change.get("before")), _oid(change.get("after"))))
    reverts = None
    if "reverts" in row:
        target = row["reverts"]
        if not isinstance(target, dict) or not isinstance(target.get("path"), str):
            raise ValueError("not a revert's target")
        # Imported history has no batch ids: the target batch is named by its branch, which its own rows carry.
        reverts = [[_batch_key(target.get("batch"))[0], target["path"]]]
    branch, base, start = _batch_key(row.get("batch"))
    return _Commit(commit=str(_oid(row.get("commit"), absent=False)), branch=branch, base=base, start=start,
                   changes=tuple(parsed), reverts=reverts)


def _records_below(bound: _io.Bound, folder: str, found: list[str]) -> None:
    """Every entry in or below `folder` but its subfolders, by its path, into `found`; nothing is followed."""
    listing = bound.under(folder).entries()
    if listing.absent:
        return
    if listing.reason is not None or listing.entries is None:
        raise ImportRefused(f"{folder}/ could not be listed: {listing.reason}")
    dirs = set(listing.dirs())
    for name in sorted(listing.entries):
        if name in dirs:
            _records_below(bound, f"{folder}/{name}", found)
        else:  # a file, or anything else standing where a record would: named, never followed
            found.append(f"{folder}/{name}")


def _files_named(bound: _io.Bound, folder: str, prefix: str) -> list[str]:
    listing = bound.under(folder).entries()
    if listing.reason is not None and not listing.absent:
        raise ImportRefused(f"{folder}/ could not be listed: {listing.reason}")
    return [f"{folder}/{name}" for name in listing.files() if name.startswith(prefix)]


def _feedback_records(bound: _io.Bound) -> list[str]:
    """Every #1414 feedback record under the learning folder, by its path there: an entry in (or below) one of the
    feedback record folders, a feedback lessons channel file, or a retained feedback delivery."""
    found: list[str] = []
    for folder in _FEEDBACK_FOLDERS:
        _records_below(bound, folder, found)
    found += _files_named(bound, "_pending", _FEEDBACK_CHANNEL)
    found += _files_named(bound, _DELIVERY, _FEEDBACK_DELIVERY)
    found += [f"{_DELIVERY}/{name}" for name, body, _text in _folder_records(bound, _DELIVERY)
              if body is not None and body.get("label") == _FEEDBACK_LABEL and f"{_DELIVERY}/{name}" not in found]
    return found


def _refuse_feedback(bound: _io.Bound, commits: Sequence[_Commit] = ()) -> None:
    """Owner ruling Q1 (b), A4 O13: while the tenant holds any #1414 feedback record (or a commit row on a feedback
    branch), the import refuses, naming each; an operator decides per tenant."""
    named = _feedback_records(bound)
    named += sorted({f"the commit-maker's row for {c.commit} on {c.branch}" for c in commits
                     if c.branch.startswith(_FEEDBACK_BRANCH)})
    if named:
        raise ImportRefused("the tenant holds #1414 feedback records, which the import does not take (owner ruling: "
                            "an operator decides per tenant): " + ", ".join(named))


# -- reading git and the forge ------------------------------------------------------------------------------------------


def _tip(delivery: TenantDelivery, branch: str, *, remote_first: bool) -> str | None:
    repo = delivery.repository
    remote = f"refs/remotes/origin/{branch}"
    remote_tip = repo.revision(remote) if repo.holds_ref(remote) else None
    local_tip = repo.branch_tip(branch)
    return (remote_tip or local_tip) if remote_first else (local_tip or remote_tip)


def _lane_of_branch(branch: str) -> tuple[str, str] | None:
    """`(batch kind, lane)` a branch of ours is on, or `None` for a branch learning never made."""
    if branch.startswith(REVERT_PREFIX):
        return "revert", AUTHOR_LANE
    for lane, prefix in BRANCH_PREFIX.items():
        if branch.startswith(prefix):
            return "author", lane
    return None


def _open_prs(delivery: TenantDelivery) -> list[_Batch]:
    """Every open PR of ours on a learning branch: an in-review batch. Lead-lane PRs hold no items, and their feedback
    is visibly not acted on (G-I6)."""
    batches: list[_Batch] = []
    for pr in sorted(delivery.repository.forge.list_open_prs(""), key=lambda p: p["number"]):
        branch, number = pr["headRefName"], pr["number"]
        placed = _lane_of_branch(branch)
        if placed is None:
            _logger.info("import: open PR #%s on %s is not a learning branch; no batch", number, branch)
            continue
        kind, lane = placed
        batches.append(_Batch(kind=kind, lane=lane, branch=branch, phase="in_review", pr_number=number,
                              reason=_LEAD_REASON if lane == LEAD_LANE else None,
                              tip=_tip(delivery, branch, remote_first=True), named=f"PR #{number} ({branch})"))
    return batches


def _retained(bound: _io.Bound, delivery: TenantDelivery, open_branches: set[str]) -> list[_Batch]:
    """A delivery record still present at quiesce: a batch for a person, per lane (Migration); a quarantined one is
    logged and dropped."""
    for name, body, _unused in _folder_records(bound, f"{_DELIVERY}/failed"):
        why = body.get("failed") if body is not None else None
        _logger.warning("import: the failed delivery record %s is dropped (%s)", name.removesuffix(".json"),
                        why if isinstance(why, str) else "unreadable")
    batches: list[_Batch] = []
    for name, body, _unused in _folder_records(bound, _DELIVERY):
        branch = body.get("branch") if body is not None else None
        label = body.get("label") if body is not None else None
        lanes = _drain_lanes()
        if not isinstance(branch, str) or not isinstance(label, str) or label not in lanes:
            raise ImportRefused(f"the delivery record {_DELIVERY}/{name} names no branch and drain label the import "
                                f"knows (branch {branch!r}, label {label!r})")
        if branch in open_branches:
            continue  # its PR opened after all: the open PR's batch is the one
        why = body.get("reason") if body is not None else None
        batches.append(_Batch(kind="author", lane=lanes[label], branch=branch, phase="needs_person",
                              pr_number=None, tip=_tip(delivery, branch, remote_first=False),
                              reason=f"a delivery retained at import ({why if isinstance(why, str) else 'no reason'})",
                              named=f"retained delivery {name.removesuffix('.json')} ({branch})"))
    return batches


def _corpus_blobs(delivery: TenantDelivery, rev: str) -> dict[str, str]:
    entries = delivery.repository.entries(rev, [c.rstrip("/") for c in _CITED_CORPORA], recursive=True)
    return {path: oid for _mode, kind, oid, path in entries if kind == "blob" and path.endswith(".md")}


def _cites(data: bytes) -> set[str]:
    try:
        fm, _raw, _body = _frontmatter.split_frontmatter(data.decode("utf-8"))
    except (UnicodeDecodeError, _frontmatter.FrontmatterError):
        return set()
    cited = fm.get(_CITATION_FIELD)
    return {c for c in cited if isinstance(c, str)} if isinstance(cited, list) else set()


def _cited_by_branch(delivery: TenantDelivery, main: str, tip: str) -> set[tuple[str, str]]:
    """`(kind, id)` the branch's own commits cite: what a lesson changed past the merge base cites at the tip and did
    not cite at the base. A citation already on `main` is not this branch's."""
    repo = delivery.repository
    base = _git.git(["merge-base", main, tip], cwd=repo.path, env=_git.env_for_cwd())
    at_tip, at_base = _corpus_blobs(delivery, tip), _corpus_blobs(delivery, base)
    changed = {path: oid for path, oid in at_tip.items() if at_base.get(path) != oid}
    blobs = repo.blobs([*changed.values(), *(at_base[p] for p in changed if p in at_base)])
    cited: set[tuple[str, str]] = set()
    for path, oid in changed.items():
        kind = next(k for prefix, k in _CITED_CORPORA.items() if path.startswith(prefix))
        before = _cites(blobs[at_base[path]]) if path in at_base else set()
        cited.update((kind, fid) for fid in _cites(blobs[oid]) - before)
    return cited


def _place_members(delivery: TenantDelivery, batches: list[_Batch], items: list[_Item]) -> None:
    """An author-lane authoring batch's members are the queued items its branch cites: membership wins over "queue
    rows wait", since committed findings are still queued today (Migration, G-I8)."""
    waiting = {(i.kind, i.key): i for i in items if i.status == "waiting"}
    main = delivery.repository.revision("refs/remotes/origin/main")
    for batch in batches:
        if batch.kind != "author" or batch.lane != AUTHOR_LANE or batch.tip is None:
            continue
        for ref in sorted(_cited_by_branch(delivery, main, batch.tip)):
            item = waiting.get(ref)
            if item is not None and item.batch is None:
                item.status, item.batch = "in_batch", batch.branch


def _refuse_two_open(batches: list[_Batch]) -> None:
    """One not-ended author batch per lane (O3): two open authoring PRs (or retained deliveries) on a lane refuse the
    import, naming each (G-I7)."""
    for lane in (AUTHOR_LANE, LEAD_LANE):
        open_ = [b for b in batches if b.kind == "author" and b.lane == lane]
        if len(open_) > 1:
            raise ImportRefused(f"the {lane} lane has {len(open_)} open authoring batches, where the store holds one: "
                                + ", ".join(b.named for b in open_))


# -- the import ----------------------------------------------------------------------------------------------------


async def import_learning_state(store: LearningStore, tid: str, root: Path, *, delivery: TenantDelivery) -> None:
    """Import tenant `tid`'s file learning state under `root` and its open PRs (read through `delivery`) into `store`,
    in one transaction. `ImportRefused` (nothing written, no file changed) for what the import will not guess: an
    unknown ledger category, two open authoring batches on one lane, a record of another shape it cannot place."""
    with _io.bind(Path(root)) as bound:
        _refuse_feedback(bound)
        items = [item for kind in _CHANNELS for item in _channel_items(bound, kind)]
        items += _requests(bound)
        commits = _commits(bound)
        delivery.repository.fetch()
        batches = _open_prs(delivery)
        batches += _retained(bound, delivery, {b.branch for b in batches})
    _refuse_two_open(batches)
    for batch in batches:
        first = next((c for c in commits if c.branch == batch.branch), None)
        if first is not None:
            batch.base, batch.start = first.base, first.start
    _place_members(delivery, batches, items)
    for item in items:
        try:
            _refuse_nul(item.payload)
        except ItemRefused:
            raise ImportRefused(f"the {item.kind} {item.key} holds a NUL character, which the store cannot hold") from None
    try:
        await _write(store, tid, batches, items, commits)
    except IntegrityError as refused:
        raise ImportRefused(f"the store refused the import: {refused.orig}") from None
    except ItemRefused as refused:
        raise ImportRefused(f"the store refused an item: {refused}") from None
    _logger.info("import: tenant %s: %d item(s), %d batch(es), %d commit row(s)", tid, len(items), len(batches),
                 len(commits))


async def _write(store: LearningStore, tid: str, batches: list[_Batch], items: list[_Item],
                 commits: list[_Commit]) -> None:
    """One transaction. A commit row is linked to the imported batch that shares its branch (so the revert lookup and
    the merge reading see an open PR's history as theirs); history whose batch is not imported has no batch."""
    tenant = TenantId(tid)
    async with store._sessions.begin() as s:
        await store._require_active(s, tid)
        ids: dict[str, BatchId] = {}
        for b in batches:
            ids[b.branch] = BatchId.mint()
            await s.execute(_B.insert().values(
                id=ids[b.branch], tenant_id=tenant, kind=b.kind, lane=b.lane, branch=b.branch, base=b.base,
                start=b.start, phase=b.phase, fencing_token=1, cancel_requested=False, pr_number=b.pr_number,
                generation=0, refusals=0, reason=b.reason, created_at=func.clock_timestamp()))
        for i in items:
            await store._insert_item(
                s, tid, i.kind, i.key, i.payload, status=i.status, source_run=i.source_run,
                coalesce_key=i.coalesce_key, mistake_key=i.mistake_key, reason=i.reason,
                batch_id=ids[i.batch] if i.batch is not None else None, **i.counters)
        for c in commits:
            row_id = str(uuid.uuid4())
            await s.execute(_C.insert().values(
                id=row_id, tenant_id=tenant, batch_id=ids.get(c.branch), commit=c.commit, branch=c.branch, base=c.base,
                start=c.start, reverts=c.reverts, created_at=func.clock_timestamp()))
            for ordinal, (path, before, after) in enumerate(c.changes):
                await s.execute(_CC.insert().values(commit_row=row_id, ordinal=ordinal, tenant_id=tenant, path=path,
                                                    blob_base=before, blob_left=after))


# -- the cutover ---------------------------------------------------------------------------------------------------


def cut_over_learning_state(tenant: Any, root: Path) -> None:
    """Retire the tenant's learning folder `root` once its import is in: its batch worktrees move to the tenant's
    worktrees location, and everything else under it goes (queues, ledgers, reports, markers, locks, the commit
    record now in the store, and the curator traces written before cutover, which have no batch to attach to: A1).

    Nothing below `root` is followed: a link where a worktree or the folder itself should be is refused. An absent
    `root` is already cut over. The worktrees location must lie outside `root` (the tenant scratch location, A2 D10);
    while it does not, the cutover refuses and removes nothing. While a #1414 feedback record is there (the import
    took none, Q1 b), the cutover refuses and removes nothing (A4 O13)."""
    root = Path(root)
    if not _io.entry_present(root):
        return
    with _io.bind(root) as bound:
        _refuse_feedback(bound)
    destination = unwrap_worktrees_root(tenant.worktrees)
    if destination.resolve().is_relative_to(root.resolve()):
        raise ImportRefused(f"the tenant's worktrees location {destination} is still under its learning folder "
                            f"{root}: the cutover needs it moved to the tenant scratch location first (A2 D10)")
    _move_worktrees(root, destination)
    _remove_folder(root)
    _logger.info("cutover: the learning folder %s is removed; its worktrees are at %s", root, destination)


def _move_worktrees(root: Path, destination: Path) -> None:
    with _io.bind(root) as bound:
        listing = bound.under(_WORKTREES).entries()
    if listing.absent:
        return
    if listing.entries is None:
        raise ImportRefused(f"{root / _WORKTREES} could not be listed: {listing.reason}")
    with _io.hold(root) as held, _io.hold_under(held, _WORKTREES) as source, \
            _io.hold_new(destination.parent, destination.name) as target:
        for name in sorted(listing.entries):
            _io.rename_into(source, name, target)


def _remove_folder(root: Path) -> None:
    """Remove the folder `root` with nothing below it followed (`rmtree` relative to its parent's descriptor)."""
    fd = os.open(root.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        st = os.stat(root.name, dir_fd=fd, follow_symlinks=False)
        if not stat.S_ISDIR(st.st_mode):
            raise ImportRefused(f"{root} is not a plain folder: the cutover removes nothing through it")
        shutil.rmtree(root.name, dir_fd=fd)
    finally:
        os.close(fd)
