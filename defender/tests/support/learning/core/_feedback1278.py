"""#1278 feedback and reconcile: the scene a tick test runs in, and a curator that records what it saw.

Nothing here implements store or tick policy. `Scene` is the tenant bound to its forge fake, active in
the database the tick's store reads. `FeedbackCurator` is the drain's `trigger_author` seam as a curator
that writes corpus files into its batch's draft lanes and commits them through the batch's own
commit-maker, recording every argument it is handed (so a case can read what text reached it, H13).
The store and drain targets are imported inside each helper, so a missing module is a per-test red.
"""
from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defender.tests.support.learning.core._store1278 import AUTHOR_LANE, DSN_ENV, batches, call, finding, work

#: The kinds a claim takes, each at one item (every case wakes the curators at a single item).
ONE_ITEM = {"finding": 1, "questioner_finding": 1, "pitfall": 1, "curation_request": 1}


@dataclass
class Scene:
    t: Any
    dsn: str
    paths: Any
    scratch: Path

    def items(self) -> dict[str, Any]:
        return work(self.dsn, self.t.tenant_id)

    def statuses(self) -> dict[str, str]:
        return {key: item.status for key, item in self.items().items()}

    def batch_rows(self) -> dict[str, Any]:
        return {b.id: b for b in batches(self.dsn, self.t.tenant_id)}

    def bot_login(self) -> str:
        """The tenant's real forge login: the live generation's `bot-<tenant>-<salt>` (what `bind_forge` recorded)."""
        [generation] = self.t.__dict__["_bound"]["generations"]
        return generation["bot_login"]

    def stored_text(self) -> str:
        """Every row of every `learning.*` table, cast to text, as one string (a scan for text that must not be stored)."""
        from defender.tests.support.shared._postgres1339 import execute

        tables = [name for (name,) in execute(
            self.dsn, "SELECT table_name FROM information_schema.tables WHERE table_schema = 'learning' "
                      "AND table_type = 'BASE TABLE'")]
        assert tables, "no learning tables to scan"
        return "\n".join(text for table in tables
                         for (text,) in execute(self.dsn, f'SELECT t::text FROM learning."{table}" t'))

    def seed(self, *ids: str, kind: str = "finding") -> None:
        call(self.dsn, "publish_findings", self.t.tenant_id, "run-1", [finding(i) for i in ids], kind=kind)


def make_scene(p4_tenant: Any, dsn: str, scratch: Path, monkeypatch: Any, threshold: int = 1) -> Scene:
    """`p4_tenant` bound to its forge and registered in `dsn`; both curators wake at `threshold` items."""
    from defender.tests.support.jobs._jobs1342 import register_tenant
    from defender.tests.tenancy.tenant_1108_p4._drain_support import drain_paths, product_repo
    from defender.tests.tenancy.tenant_1108_p4._support import bind_forge

    bind_forge(p4_tenant)
    register_tenant(dsn, p4_tenant.tenant_id)
    monkeypatch.setenv(DSN_ENV, dsn)
    scene = Scene(p4_tenant, dsn, drain_paths(p4_tenant, product_repo(scratch, adapters=("cmdb",))), scratch)
    wake_at(monkeypatch, threshold)
    return scene


def wake_at(monkeypatch: Any, threshold: int) -> None:
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", str(threshold))
    monkeypatch.setenv("LEARNING_QUESTIONER_THRESHOLD", str(threshold))


def tick(scene: Scene, curator: Any) -> int:
    from defender.tests.tenancy.tenant_1108_p4._drain_support import BoxSpy, author_drain

    return author_drain(scene.t, scene.paths, trigger=curator, box=BoxSpy())


def opened(scene: Scene, curator: Any, caplog: Any) -> tuple[str, str, int]:
    """One tick that authors and opens a PR: `(batch id, branch, PR number)`."""
    from defender.tests.tenancy.tenant_1108_p4._drain_support import critical_text, remote_branches

    rc = tick(scene, curator)
    assert curator.served, f"the tick served no batch (rc {rc}): {critical_text(caplog)}"
    [(branch, _tip)] = remote_branches(scene.t.remote).items()
    [pr] = [r for r in scene.t.forge.prs if r["head"]["ref"] == branch]
    return curator.served[-1], branch, pr["number"]


def end_closed_by_hand(scene: Scene, batch_id: str) -> None:
    """The reconcile's end of a closed-with-feedback batch, done by hand: its items stay in the batch
    and no replacement is claimed yet (the state a crash between the two leaves)."""
    call(scene.dsn, "end_review", scene.t.tenant_id, batch_id, expect_phase="in_review", outcome="closed",
         published=[], held=[])


def claim_by_hand(scene: Scene, owner: str) -> Any:
    return call(scene.dsn, "claim", scene.t.tenant_id, AUTHOR_LANE, owner=owner, thresholds=ONE_ITEM)


def reviewer_removes_citation(lesson_name: str, text: str) -> Callable[[Path], None]:
    """A merge-dialog edit that rewrites `lesson_name` in the merge result as `text`."""
    def edit(checkout: Path) -> None:
        (checkout / "agent" / "lessons" / lesson_name).write_text(text, encoding="utf-8")
    return edit


class FeedbackCurator:
    """The drain's `trigger_author` seam as a curator writing `files` (repo-relative path below
    `agent/`, e.g. `lessons/x.md`) into its batch's draft and committing them once per batch.
    `before_commit(batch)` runs between the write and the commit. Records the batches served, every
    positional and keyword argument of every call (`handed`), and the text of all of them
    (`seen_text()`), which is what a real curator's prompt would be assembled from (H13)."""

    def __init__(self, files: dict[str, str] | None = None, *,
                 before_commit: Callable[[Any], None] | None = None) -> None:
        self.files = files or {}
        self.before_commit = before_commit
        self.served: list[str] = []
        self.commits: list[str] = []
        self.handed: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    def __call__(self, *args: Any, batch: Any, **kw: Any) -> None:
        self.handed.append((args, {"batch": batch, **kw}))
        if batch.id in self.served:
            return
        self.served.append(batch.id)
        for rel, text in self.files.items():
            target = Path(batch.draft_root) / "agent" / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        if self.before_commit is not None:
            self.before_commit(batch)
        if self.files:
            self.commits.append(batch.commit(batch.change_set(), f"learning: batch {batch.id}"))

    def calls(self) -> list[tuple[str, Any]]:
        """Per call: the text of its positional and keyword arguments but `feedback` (what names the curator and its
        items), and the `feedback` it was handed (None when none)."""
        out = []
        for args, kw in self.handed:
            rest = {k: v for k, v in kw.items() if k not in ("batch", "feedback")}
            out.append(("\n".join(_strings((args, rest))), kw.get("feedback")))
        return out

    def seen_text(self) -> str:
        """Every string a call was handed (items, feedback, whatever the seam carries), flattened;
        the batch handle itself is left out."""
        out: list[str] = []

        def walk(value: Any) -> None:
            if isinstance(value, str):
                out.append(value)
            elif isinstance(value, dict):
                for k, v in value.items():
                    walk(k)
                    walk(v)
            elif isinstance(value, (list, tuple, set, frozenset)):
                for v in value:
                    walk(v)
            elif hasattr(value, "__dict__") and type(value).__module__.startswith("defender.learning"):
                walk(vars(value))
        for args, kw in self.handed:
            walk(args)
            walk({k: v for k, v in kw.items() if k != "batch"})
        return "\n".join(out)


def _strings(value: Any) -> list[str]:
    """Every string in `value`, through containers and the learning package's own objects."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, dict):
        return [s for k, v in value.items() for s in (*_strings(k), *_strings(v))]
    if isinstance(value, (list, tuple, set, frozenset)):
        return [s for v in value for s in _strings(v)]
    if hasattr(value, "__dict__") and type(value).__module__.startswith("defender.learning"):
        return _strings(vars(value))
    return []


def framed(text: str, needle: str) -> bool:
    """`needle` sits verbatim inside one `<run-SALT-TAG>...</run-SALT-TAG>` frame of `text` (the
    repo's untrusted-data frame, `_untrusted.wrap`): the salt is not in the framed body."""
    for m in re.finditer(r"<run-([0-9a-f]+)-([\w-]+)>\n(.*?)\n</run-\1-\2>", text, flags=re.S):
        if needle in m.group(3) and m.group(1) not in m.group(3):
            return True
    return False
