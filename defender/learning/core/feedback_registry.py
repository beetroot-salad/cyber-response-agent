"""Step 4 and the replies of the feedback tick (#1414 F2): approved entries become one registry-only PR a
person merges or closes, and every decided comment gets one reply where the person spoke.

Each approved entry is judged once (A1): drafted onto a PR, covered by an entry already on `main` or earlier
in the batch, or not writable. The judgement is recorded on the decision after the fact it records; a crash
before the record is a redo, because the PR the bot opened names its ids in its body (A2/P6).
"""
from __future__ import annotations

import datetime as dt
import logging
import re
import tempfile
import uuid
from pathlib import Path
from typing import Any

import yaml

from defender.learning.author.version_control import DeliveryRefused
from defender.learning.author.version_control.forgejo import ForgeError
from defender.learning.core import feedback_decide
from defender.learning.core.config import FEEDBACK_DRAIN_LABEL
from defender.learning.core.state import FEEDBACK_DECISIONS, LearningState
from defender.systems import tacit_registry

_logger = logging.getLogger(__name__)

REGISTRY = "agent/skills/tacit-knowledge/registry.yaml"
FEEDBACK_PREFIX = "feedback/"
_ENTRY_ID = re.compile(r"fb-\d+-\d+-\d+")
_COVERED_LINE = re.compile(r"^covered: (fb-\d+-\d+-\d+) by (\S+)", re.M)
_TOP_KEY = re.compile(r"^([A-Za-z_][\w-]*)[ \t]*:")
_RANK = {"open": 0, "merged": 1, "closed": 2}


class ShapeRefused(Exception):
    """The registry file is not in a shape entries may be appended to (A7), or the append broke the reader."""


def marker(comment_id: int) -> str:
    return f"<!-- defender-feedback-reply:{comment_id} -->"


# ------------------------------------------------------------------ the entry

def entry_for(decision: dict, approved: dict) -> dict[str, str]:
    """The entry an approved lookup becomes: everything but the justification from records the host holds (P2)."""
    added = feedback_decide.comment_day(decision)
    review = decision.get("review_by") or (added + dt.timedelta(days=feedback_decide.REVIEW_DAYS)).isoformat()
    lookup = approved["lookup"]
    return {
        "id": approved["id"], "pattern": lookup["pattern"], "actor_scope": lookup["actor"],
        "host_scope": lookup["host"], "added_by": decision["author"], "added_at": added.isoformat(),
        "review_by": review,
        "justification": f"{decision['body']}\n({decision['issue_url']}, comment {decision['comment_id']})",
    }


def unwritable(entry: dict[str, str]) -> str | None:
    """Why the entry cannot be drafted, or None: a glob in a scope would let the model's call choose a wider
    scope than the run asked about (P3); otherwise the reader's own verdict."""
    for field in ("actor_scope", "host_scope"):
        if any(ch in entry[field] for ch in "*?[]"):
            return f"`{field}` {entry[field]!r} holds a glob character"
    return tacit_registry.entry_problem(entry)


# ------------------------------------------------------------------ the registry file

def _read(text: str) -> tacit_registry.RegistryRead:
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "registry.yaml"
        path.write_text(text, encoding="utf-8")
        return tacit_registry.read_registry(path)


def _dash_indent(lines: list[str]) -> str:
    for line in lines:
        if (m := re.match(r"^(\s*)- ", line)):
            return m.group(1)
    return "  "


def append_entries(text: str, entries: list[dict[str, str]]) -> str:
    """`text` with `entries` appended line-wise (its comments and layout kept byte for byte). Only two shapes
    take an append (A7): `entries:` as the last top-level key holding a block list, or exactly `entries: []`,
    which the first append rewrites once. Any other shape, or an append the shared reader does not take whole,
    is refused."""
    lines = text.splitlines(keepends=True)
    keys = [(i, m.group(1)) for i, ln in enumerate(lines) if (m := _TOP_KEY.match(ln))]
    if [k for _, k in keys].count("entries") != 1 or keys[-1][1] != "entries":
        raise ShapeRefused("`entries:` is not the file's one last top-level key")
    at = keys[-1][0]
    head = lines[at].rstrip("\r\n")
    if head == "entries: []":
        lines[at], indent = "entries:\n", "  "
    elif re.fullmatch(r"entries:[ \t]*", head):
        indent = _dash_indent(lines[at + 1:])
    else:
        raise ShapeRefused(f"`{head.strip()}` is neither a block list nor exactly `entries: []`")
    grown = "".join(lines)
    grown += "" if grown.endswith("\n") else "\n"
    dumped = yaml.safe_dump([dict(e) for e in entries], sort_keys=False, default_flow_style=False,
                            allow_unicode=True, width=10_000)
    grown += "".join(indent + ln + "\n" for ln in dumped.splitlines())
    _verify(text, grown, entries)
    return grown


def _verify(before: str, after: str, entries: list[dict[str, str]]) -> None:
    """The shared reader accepts every appended entry and drops nothing it did not already drop (O6)."""
    old, new = _read(before), _read(after)
    appended = {e["id"] for e in entries}
    if (new.fatal is not None or not appended <= {e["id"] for e in new.entries}
            or len(new.refusals) != len(old.refusals)):
        raise ShapeRefused(f"the reader does not take the appended entries whole: {new.problems}")


def main_registry(delivery: Any) -> tuple[str, list[dict[str, str]]]:
    """The registry text on the remote `main`, and the entries the reader loads from it."""
    repo = delivery.repository
    repo.fetch()
    oid = repo.regular_blob_on("refs/remotes/origin/main", REGISTRY)
    text = repo.blobs([oid])[oid].decode("utf-8") if oid else ""
    return text, list(_read(text).entries) if text else []


# ------------------------------------------------------------------ settlement

def _decisions(state: LearningState, *, open_only: bool = False) -> list[dict]:
    found = [state.records(FEEDBACK_DECISIONS)[k] for k in sorted(state.records(FEEDBACK_DECISIONS), key=int)]
    return [d for d in found if not (open_only and d.get("settled"))]


def _unsettled(state: LearningState) -> list[tuple[dict, dict]]:
    return [(d, a) for d in _decisions(state) for a in d["approved"] if a["settled"] is None]


def _settle(state: LearningState, decision: dict, approved: dict, how: dict) -> None:
    approved["settled"] = how
    state.put_record(FEEDBACK_DECISIONS, str(decision["comment_id"]), decision)


def feedback_prs(forge: Any, bots: frozenset[str]) -> dict[str, Any]:
    """Entry id -> the PR that names it, among PRs the tenant's bot opened under the feedback prefix (P6/A2);
    open beats merged beats closed."""
    found: dict[str, Any] = {}
    for pr in forge.pull_requests():
        if not pr.branch.startswith(FEEDBACK_PREFIX) or pr.author not in bots:
            continue
        for eid in _ENTRY_ID.findall(pr.body):
            if eid not in found or _RANK[pr.status] < _RANK[found[eid].status]:
                found[eid] = pr
    return found


def settle_from_prs(state: LearningState, forge: Any, bots: frozenset[str]) -> None:
    """Settle every entry a bot feedback PR already names: `covered` when its body lists it so, else `drafted`."""
    named = feedback_prs(forge, bots)
    if not named:
        return
    for decision, approved in _unsettled(state):
        pr = named.get(approved["id"])
        if pr is None:
            continue
        covered = dict(_COVERED_LINE.findall(pr.body)).get(approved["id"])
        _settle(state, decision, approved,
                {"how": "covered", "by": covered, "pr": pr.url} if covered else {"how": "drafted", "pr": pr.url})


def _judge(state: LearningState, main_entries: list[dict[str, str]]) -> tuple[list, list]:
    """Judge every unsettled entry once. Not writable and covered-by-`main` are recorded now; the rest are
    returned: (to draft, covered by an earlier draft of this batch)."""
    today = dt.datetime.now(dt.UTC).date()
    drafts: list[tuple[dict, dict, dict]] = []
    within: list[tuple[dict, dict, str]] = []
    for decision, approved in _unsettled(state):
        entry = entry_for(decision, approved)
        key = {"actor": entry["actor_scope"], "host": entry["host_scope"], "pattern": entry["pattern"], "now": today}
        if (why := unwritable(entry)) is not None:
            _settle(state, decision, approved, {"how": "not-draftable", "why": why})
        elif (hit := tacit_registry.find_entry(main_entries, **key)) is not None:
            _settle(state, decision, approved, {"how": "covered", "by": hit["id"]})
        elif (earlier := tacit_registry.find_entry([e for _, _, e in drafts], **key)) is not None:
            within.append((decision, approved, earlier["id"]))
        else:
            drafts.append((decision, approved, entry))
    return drafts, within


def _pr_body(drafts: list, within: list) -> str:
    def whose(d: dict) -> str:
        return f"issue #{d['issue']}, comment {d['comment_id']}, approved by {d['author']}"

    lines = [f"drafted: {a['id']} ({whose(d)})" for d, a, _ in drafts]
    lines += [f"covered: {a['id']} by {by} ({whose(d)})" for d, a, by in within]
    return ("Registry entries drafted from feedback comments. A person merges this to approve them, or closes it "
            "to decline them for good.\n\n" + "\n".join(lines))


def draft(state: LearningState, delivery: Any, bots: frozenset[str], drains: Any) -> None:
    """Step 4, under the registry lane's writer lease. A retained batch or an open feedback PR holds the lease:
    nothing new is judged or started, but entries a PR already names are still settled."""
    label = FEEDBACK_DRAIN_LABEL
    forge = delivery.repository.forge
    try:
        clear = drains._deliver_pending(state, delivery, label)
        settle_from_prs(state, forge, bots)
        if not clear or delivery.open_pr_exists() or not _unsettled(state):
            return
        text, main_entries = main_registry(delivery)
        drafts, within = _judge(state, main_entries)
        if drafts:
            _start_and_land(state, delivery, drains, text, drafts, within)
            settle_from_prs(state, forge, bots)
    except (ForgeError, DeliveryRefused) as e:
        _logger.error(f"feedback: the registry batch could not be made: {e}")
    except ShapeRefused as e:
        _logger.warning(f"feedback: the registry draft is refused, retried next tick: {e}")


def _start_and_land(state: LearningState, delivery: Any, drains: Any, text: str, drafts: list, within: list) -> None:
    entries = [e for _, _, e in drafts]
    append_entries(text, entries)  # refuse a registry shape before any batch exists
    batch = delivery.start_batch(uuid.uuid4().hex[:12], lanes=FEEDBACK_DRAIN_LABEL.lanes)
    try:
        path = Path(batch.draft_root) / REGISTRY
        path.write_text(append_entries(path.read_text(encoding="utf-8"), entries), encoding="utf-8")
        batch.commit(batch.change_set(), _pr_body(drafts, within))
        drains._land_batch(state, delivery, batch, FEEDBACK_DRAIN_LABEL, body_from_commit=True)
    finally:
        batch.discard()


# ------------------------------------------------------------------ replies

def _describe(entry_id: str, approved: dict, decision: dict) -> str:
    how = approved["settled"]
    if how["how"] == "drafted":
        return f"Entry {entry_id} is on a registry PR for a person to merge or close: {how['pr']}"
    if how["how"] == "covered":
        return f"Entry {entry_id} is already covered by entry {how['by']}."
    lookup = approved["lookup"]
    return (f"Entry {entry_id} cannot be written as an entry: {how['why']} "
            f"(actor {lookup['actor']!r}, host {lookup['host']!r}).")


def reply_text(decision: dict) -> str:
    lines = [_describe(a["id"], a, decision) for a in decision["approved"]]
    if decision.get("instruction"):
        lines.append("Your instruction was handed to the lessons author.")
    if decision.get("no_change"):
        lines.append(f"No change: {decision['no_change']}")
    return "\n".join(lines) + "\n\n" + marker(decision["comment_id"])


def _settled(state: LearningState, decision: dict) -> None:
    decision["settled"] = True
    state.put_record(FEEDBACK_DECISIONS, str(decision["comment_id"]), decision)


def _answer(forge: Any, seen: dict[int, str], bots: frozenset[str], decision: dict) -> bool:
    """Make sure `decision`'s reply is on its issue; False while its outcome does not exist yet."""
    number = decision["issue"]
    if number not in seen:
        seen[number] = "\n".join(c["body"] for c in forge.list_comments(number) if c["user"]["login"] in bots)
    if marker(decision["comment_id"]) in seen[number]:
        return True
    if not all(a["settled"] for a in decision["approved"]):
        return False
    forge.create_comment(number, reply_text(decision))
    return True


def reply(state: LearningState, forge: Any, bots: frozenset[str]) -> None:
    """Post the reply each decision is owed. Whether one is owed is read from the issue: a bot comment carrying
    the comment's marker settles it, and a settled decision is never read again. A reply waits until its
    outcome exists (every approved entry judged and, if drafted, on its PR)."""
    seen: dict[int, str] = {}
    for decision in _decisions(state, open_only=True):
        try:
            done = _answer(forge, seen, bots, decision)
        except ForgeError as e:
            if e.status != 404:
                _logger.error(f"feedback: the reply to comment {decision['comment_id']} failed, retried next tick: {e}")
                continue
            _logger.warning(f"feedback: issue {decision['issue']} is gone from the forge; the reply to comment "
                            f"{decision['comment_id']} is dropped")
            done = True
        if done:
            _settled(state, decision)
