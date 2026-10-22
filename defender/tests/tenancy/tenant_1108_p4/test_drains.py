"""#1108 P4 slice S-D — flow 4 (the drain), O7 (its writes go through `TenantDelivery`), O9 (its
refusals), D-closed on the retained-batch path, and O-SWEEP's draft half.

Flow 4: `--tenant T` → forge binding + issuer config → login → `TenantDelivery.open` → publish →
batches (draft, box windows, ChangeSet per claim, commit-maker) → finish/deliver status
(D-closed) → `discard()`.

Every case drives the REAL drain entry (`defender.learning.core.drains.author_drain`) through the
stage runner the CLI uses (`learning.core.cli._run_stage`), over S0's fixture tenant published
for real (`p4_tenant`: a real clone, a loopback smart-HTTP origin, P3's forge and issuer fakes).
The lessons curator that runs inside the tick is the REAL one (`learning.author.lessons.run`):
only its model spawn (`cfg.invoke_agent`) is replaced, by `_spec773.FakeCurator`, which writes a
lesson where the curator's config says its corpus is. Everything between the spawn and the forge
(draft, ChangeSet, commit-maker, push, PR) is the code under test's.

The drain's `paths.repo_root` is a scratch product checkout (a real git repo), so "nothing lands
in the product repo" is observed on a repo the legacy drain WOULD commit to (positive control:
a hand commit there shows on the same observation).

ASSUMED SEAMS (reported; the implementer provides them; mirror S-C's `tenant.py update` and
TenantDelivery.open's own keywords):
  author_drain(paths, *, trigger_author=, client=, identity=, issuer_config=, issuer_transport=,
               start_box=, stop_box=)
    - `client`: the forge's HTTP client (production builds one); `identity`: a ForgejoIdentity,
      given -> the AppRole login is skipped; absent -> `issuer_login(tenant,
      issuer_config=...)` (orchestrator decision OD4; `issuer_transport` reaches its HTTP client,
      see test_drain_credentials.py).
    - `start_box(request) -> executor` / `stop_box(executor)`: the batch's box (default:
      `TenantDelivery.start_box` / `box.stop_box`). The `branch=` and `scrub=` seams are gone.
    - `trigger_author` keeps its call shape `(paths, state, channel, threshold_env,
      module_name, pending_label, *, box)`; whatever else the drain hands it arrives as keywords
      and is forwarded to the curator's config builder.
"""
from __future__ import annotations

import dataclasses
import importlib
import logging
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

from defender import box as box_mod
from defender.tests.support.learning.curation import _spec773 as S
from defender.tests.support.learning.curation._drain719 import seed
from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.tenancy.tenant_1108_delivery._scenarios import _AnswerLost
from defender.tests.tenancy.tenant_1108_delivery._support import (
    close_on_remote,
    fresh_process_env,
)
from defender.tests.tenancy.tenant_1108_p4._support import (
    bind_forge,
    current_commit,
    git,
)

#: The lesson the fake curator writes, below the corpus dir its config names (the draft's lane).
LESSON_NAME = "p4-drain-lesson.md"
LESSON_PATH = f"agent/lessons/{LESSON_NAME}"
LESSONS_PREFIX = "lessons/"

# ---------------------------------------------------------------------------------------------
# Machinery shared by S-D's files (test_writers.py, test_drain_credentials.py import it; S0 is
# asked to host it in _support.py).
# ---------------------------------------------------------------------------------------------


def drains() -> Any:
    return importlib.import_module("defender.learning.core.drains")


def run_stage(stage) -> int:
    """The CLI's stage runner (`loop.py --author-drain`'s): a systemic fault or configuration
    refusal is logged `critical` and exits 2."""
    from defender.learning.core.cli import _run_stage

    return _run_stage(stage)


def product_repo(tmp_path: Path) -> Path:
    """A scratch product checkout: a real git repo with a `defender/` tree and one commit, used
    as the drain's `paths.repo_root` (where the legacy drain cut worktrees and committed)."""
    repo = tmp_path / "product"
    (repo / "defender" / "lessons").mkdir(parents=True)
    (repo / "defender" / "lessons" / "product-era.md").write_text("product era\n", encoding="utf-8")
    (repo / "defender" / "README.md").write_text("scratch product checkout\n", encoding="utf-8")
    git(repo, "init", "-b", "main")
    git(repo, "add", "-A")
    git(repo, "commit", "-m", "product checkout")
    return repo


def product_state(repo: Path) -> dict:
    """Everything a product-repo delivery would move: HEAD, every ref, the worktree list, the
    status, and the files under `defender/`."""
    return {
        "head": git(repo, "rev-parse", "HEAD"),
        "refs": git(repo, "for-each-ref", "--format=%(refname) %(objectname)"),
        "worktrees": git(repo, "worktree", "list", "--porcelain"),
        "status": git(repo, "status", "--porcelain", "--untracked-files=all"),
        "files": sorted(str(p.relative_to(repo)) for p in (repo / "defender").rglob("*")),
    }


def drain_paths(t: Any, product: Path) -> Any:
    """The accepted tenant's learning paths over the scratch product checkout (what
    `LoopPaths.for_tenant` builds over `REPO_ROOT`)."""
    from defender.learning.core.config import LoopPaths

    return t.tenant.learning_paths(LoopPaths, repo_root=product)


def queue(paths: Any, rows: list[dict], *, channel: Any = None) -> None:
    from defender.learning.core.state import FINDINGS

    seed(paths, channel if channel is not None else FINDINGS, rows)


_BUILDERS = {
    "author": ("defender.learning.author.lessons.run", "build_author_config"),
    "questioner_curator": ("defender.learning.author.questioner.run", "build_questioner_config"),
}


class CuratorTrigger:
    """The drain's `trigger_author` seam: runs the REAL curator module for the module it is asked
    for, as the default step does (the lane's held trees, the real config builder, the module's
    `run_batch`), with only the model spawn (`cfg.invoke_agent`) replaced by `curators[module]`.
    A module with no fake is recorded and not run. Records each call's module."""

    def __init__(self, **curators: Any) -> None:
        self.curators = curators
        self.calls: list[str] = []
        self.handed: list[dict] = []

    def __call__(self, paths: Any, state: Any, channel: Any, threshold_env: str,
                 module_name: str, pending_label: str, **kw: Any) -> None:
        from defender.learning.core.config import AUTHOR_DRAIN_LABEL
        from defender.learning.core.lane_trees import open_drain_trees

        self.calls.append(module_name)
        self.handed.append(dict(kw))
        curator = self.curators.get(module_name)
        if curator is None:
            return
        module, builder = _BUILDERS[module_name]
        mod = importlib.import_module(module)
        box = kw.pop("box", None)
        with open_drain_trees(paths, AUTHOR_DRAIN_LABEL) as trees:
            cfg = getattr(mod, builder)(paths, state=state, trees=trees, box=box, **kw)
            cfg = dataclasses.replace(cfg, invoke_agent=curator)
            mod.run_batch(hold_committed=True, cfg=cfg, box=box)


class BoxSpy:
    """The drain's `start_box`/`stop_box` seams: records each `BoxRequest` and hands back an
    unboxed executor (the box itself is P3's, tested there)."""

    def __init__(self) -> None:
        self.requests: list[Any] = []
        self.stopped = 0

    def start(self, request: Any, **_kw: Any) -> Any:
        self.requests.append(request)
        return box_mod.unboxed_executor()

    def stop(self, _box: Any, **_kw: Any) -> None:
        self.stopped += 1


def author_drain(t: Any, paths: Any, *, trigger: Any, box: BoxSpy, **seams: Any) -> int:
    """`author_drain` through the stage runner, the tenant's forge fake as its forge client and
    a fresh identity over its issuer fake (login skipped) unless the case passes others."""
    seams.setdefault("client", t.forge.client)
    if "issuer_config" not in seams:
        seams.setdefault("identity", t.vault.identity())
    return run_stage(lambda: drains().author_drain(
        paths, trigger_author=trigger, start_box=box.start, stop_box=box.stop, **seams))


def remote_branches(remote: Path, prefix: str = LESSONS_PREFIX) -> dict[str, str]:
    """`{branch: tip}` of the bare origin's branches under `prefix`."""
    out = git(remote, "for-each-ref", "--format=%(refname:strip=2) %(objectname)",
              f"refs/heads/{prefix}")
    return dict(line.split(" ", 1) for line in out.splitlines() if line)


def touched(cwd: Path, base: str, tip: str) -> list[str]:
    """Every path any commit in `base..tip` touched (git's word, renames off)."""
    out = git(cwd, "log", "--no-renames", "--name-only", "--format=", f"{base}..{tip}")
    return sorted({line for line in out.splitlines() if line})


def drafts_dir(t: Any) -> Path:
    return Path(location_path(t.tenant.tenant_root)) / "drafts"


def draft_entries(t: Any) -> list[str]:
    d = drafts_dir(t)
    return sorted(p.name for p in d.iterdir()) if d.is_dir() else []


def under(path: Path, root: Path) -> bool:
    """`path` is `root` or below it (both resolved)."""
    return Path(path).resolve().is_relative_to(Path(root).resolve())


def critical_text(caplog) -> str:
    return "\n".join(r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR)


@pytest.fixture
def thresholds(monkeypatch):
    """Both curators wake at one authorable row (env-backed knobs, read at call time)."""
    monkeypatch.setenv("LEARNING_AUTHOR_THRESHOLD", "1")
    monkeypatch.setenv("LEARNING_QUESTIONER_THRESHOLD", "1")


# ---------------------------------------------------------------------------------------------
# Flow 4 / O7: one drain tick lands on the tenant forge and nowhere else
# ---------------------------------------------------------------------------------------------


def test_flow4_author_drain_publishes_then_delivers_a_lesson_pr_on_the_tenant_forge_O7(
        p4_tenant, tmp_path, thresholds, caplog):
    """Flow 4, O7: a drain tick publishes first (a human merge already on the origin's `main`
    becomes `current` and the batch's base), the curator's lesson is one commit-maker commit on a
    `lessons/` branch of the TENANT clone touching only `agent/lessons/<lesson>` (never
    `agent/.tenant-id`), pushed to the tenant origin with a PR against `main` on the tenant
    forge; no checkout moved (the clone sits clean on `main`, one worktree); the draft is
    discarded; the box mounted the draft, never the clone; the row is consumed; and the product
    checkout's git state is byte-for-byte what it was."""
    t = p4_tenant
    bind_forge(t)
    merged = t.merge({"agent/lessons/human-merged.md": "a human-reviewed lesson\n"})
    product = product_repo(tmp_path)
    paths = drain_paths(t, product)
    queue(paths, [S.finding_row("f1", run_id="f1")])
    before = product_state(product)
    curator = S.FakeCurator(writes={LESSON_NAME: S.lesson("f1")})
    trigger, box = CuratorTrigger(author=curator), BoxSpy()

    with caplog.at_level(logging.INFO):
        rc = author_drain(t, paths, trigger=trigger, box=box)

    assert rc == 0, critical_text(caplog)
    assert curator.calls, "the curator's model step never ran"
    # One tick serves both curators of the lane into its one batch.
    assert trigger.calls == ["author", "questioner_curator"], trigger.calls
    # Publish ran first: the merge is `current`, the clone fast-forwarded to it.
    assert current_commit(t.tenant) == merged
    assert git(t.clone, "rev-parse", "HEAD") == merged
    # One batch branch on the tenant origin, based on the merge, touching the lesson alone.
    branches = remote_branches(t.remote)
    assert len(branches) == 1, branches
    (branch, tip), = branches.items()
    assert git(t.remote, "merge-base", tip, "refs/heads/main") == merged
    assert touched(t.remote, merged, tip) == [LESSON_PATH]
    assert git(t.remote, "show", f"{tip}:{LESSON_PATH}") + "\n" == S.lesson("f1")
    # Its PR, on the tenant forge, against `main`.
    assert [(c["head"], c["base"]) for c in t.forge.creates] == [(branch, "main")]
    assert [row["head"]["ref"] for row in t.forge.prs if row["state"] == "open"] == [branch]
    # The clone: no checkout but the publish's fast-forward, no worktree, nothing left dirty.
    assert git(t.clone, "symbolic-ref", "HEAD") == "refs/heads/main"
    assert git(t.clone, "status", "--porcelain", "--untracked-files=all") == ""
    assert len(git(t.clone, "worktree", "list", "--porcelain").split("\n\n")) == 1
    # The draft is gone (discard), and the box mounted it, never git.
    assert draft_entries(t) == []
    assert len(box.requests) == 1, box.requests
    mounts = box.requests[0].mounts
    staged = [m for m in mounts if m.kind == "staged"]
    assert len(staged) == 1, mounts
    assert under(staged[0].source, drafts_dir(t)), mounts
    assert not [m for m in mounts if under(m.source, t.clone) or under(t.clone, m.source)], mounts
    writable = sorted(Path(m.source).relative_to(staged[0].source).as_posix()
                      for m in mounts if m.writable)
    assert writable == ["agent/lessons", "agent/lessons-questioner"], writable
    # The row was consumed; the product checkout never moved.
    assert [r["finding_id"] for r in S.pending(paths, S.channel_of("findings"))] == []
    assert product_state(product) == before
    # Positive control: the same observation shows a product commit.
    (product / "defender" / "lessons" / "x.md").write_text("x\n", encoding="utf-8")
    git(product, "add", "-A")
    git(product, "commit", "-m", "a product-repo lesson")
    assert product_state(product) != before


# ---------------------------------------------------------------------------------------------
# O9: refusals before any model call, named
# ---------------------------------------------------------------------------------------------


def test_o9_a_tenant_with_no_forge_binding_refuses_the_drain_before_any_model_call(
        p4_tenant, tmp_path, thresholds, caplog):
    """O9: no `forge` binding in the tenant row is a misconfiguration, decidable locally: the
    drain refuses (exit 2, the refusal logged naming the forge binding) before the issuer, the
    forge, a draft, a box or the curator is touched. Positive control on the same channels: once
    bound, the same tick calls the curator and reaches the forge."""
    t = p4_tenant
    paths = drain_paths(t, product_repo(tmp_path))
    queue(paths, [S.finding_row("f1", run_id="f1")])
    trigger, box = CuratorTrigger(author=S.FakeCurator(writes={LESSON_NAME: S.lesson("f1")})), BoxSpy()
    t.vault.calls.clear()

    with caplog.at_level(logging.INFO):
        rc = author_drain(t, paths, trigger=trigger, box=box)

    assert rc == 2
    assert "forge" in critical_text(caplog).lower(), critical_text(caplog)
    assert trigger.calls == []
    assert box.requests == []
    assert t.forge.requests == []
    assert t.vault.calls == []
    assert draft_entries(t) == []
    assert remote_branches(t.remote) == {}

    bind_forge(t)
    assert author_drain(t, paths, trigger=trigger, box=box) == 0
    assert trigger.calls
    assert t.forge.requests
    assert t.vault.calls


def test_o9_an_unprotected_tenant_main_surfaces_as_a_drain_refusal_naming_it(
        p4_tenant, tmp_path, thresholds, caplog):
    """O9: a delivery refusal at open (the forge says `main` is unprotected) is the drain's
    refusal: exit 2, logged naming the protection, and no curator, box, draft or branch. (Control:
    the flow-4 case, protected `main`, delivers.)"""
    t = p4_tenant
    bind_forge(t)
    t.forge.protection = {"name": "main", "protected": False, "user_can_push": True}
    paths = drain_paths(t, product_repo(tmp_path))
    queue(paths, [S.finding_row("f1", run_id="f1")])
    trigger, box = CuratorTrigger(author=S.FakeCurator(writes={LESSON_NAME: S.lesson("f1")})), BoxSpy()

    with caplog.at_level(logging.INFO):
        rc = author_drain(t, paths, trigger=trigger, box=box)

    assert rc == 2
    assert "protect" in critical_text(caplog).lower(), critical_text(caplog)
    assert trigger.calls == []
    assert box.requests == []
    assert draft_entries(t) == []
    assert remote_branches(t.remote) == {}


# ---------------------------------------------------------------------------------------------
# D-closed on the retained-batch path
# ---------------------------------------------------------------------------------------------


def test_flow4_a_retained_batch_whose_pr_was_closed_is_delivered_as_closed_and_never_reopened(
        p4_tenant, tmp_path, thresholds, caplog):
    """Flow 4 + D-closed: a tick whose PR request reached the forge but lost its answer keeps the
    batch for delivery (the failure is logged, never silent). A human then closes that PR. The
    next tick delivers the retained batch first: the forge's answer is `closed`, so nothing is
    pushed and no PR is opened, and the closed status is logged."""
    t = p4_tenant
    bind_forge(t)
    paths = drain_paths(t, product_repo(tmp_path))
    queue(paths, [S.finding_row("f1", run_id="f1")])
    trigger, box = CuratorTrigger(author=S.FakeCurator(writes={LESSON_NAME: S.lesson("f1")})), BoxSpy()
    lost = _AnswerLost(remote=t.remote, origin=t.origin)

    with caplog.at_level(logging.INFO):
        author_drain(t, paths, trigger=trigger, box=box, client=lost.client)
    assert critical_text(caplog), "a lost PR answer was silent"
    # Carried policy (#952): consumption precedes the push, so tick 2 has nothing new to author
    # and any PR it opens could only be the closed batch's again.
    assert S.pending(paths, S.channel_of("findings")) == [], "tick 1 left its row queued"
    (branch, tip), = remote_branches(t.remote).items()
    assert [c["head"] for c in lost.creates] == [branch]
    close_on_remote(t.p3, branch)
    refs_before = git(t.remote, "for-each-ref", "--format=%(refname) %(objectname)")
    caplog.clear()

    with caplog.at_level(logging.INFO):
        rc = author_drain(t, paths, trigger=trigger, box=box)

    assert rc == 0, critical_text(caplog)
    assert t.forge.creates == [], "a closed batch's PR was opened again"
    assert git(t.remote, "for-each-ref", "--format=%(refname) %(objectname)") == refs_before
    said = "\n".join(r.getMessage() for r in caplog.records)
    assert "closed" in said, said
    assert branch in said, said


# ---------------------------------------------------------------------------------------------
# O-SWEEP (draft half): a draft whose owner is dead is swept by the next publish
# ---------------------------------------------------------------------------------------------

_DRAFT_OWNER = """
import sys, time
from pathlib import Path
from defender.tests.support.tenancy import _tenants1106 as tenants
from defender.tests.tenancy.tenant_1108_delivery._support import DEFENDER, ForgeHTTP, target
from defender.tests.tenancy.tenant_1108_delivery._identity import VaultHTTP
root, tenant_id, remote, origin, batch_id, ready, release = sys.argv[1:8]
tenant = tenants.accept(Path(root), tenant_id)
forge = ForgeHTTP(remote=remote, origin=origin)
d = target().TenantDelivery.open(tenant, defender_dir=DEFENDER, client=forge.client,
                                 identity=VaultHTTP(tenant_id).identity(), origin=origin)
d.start_batch(batch_id, lanes=("lessons",))
Path(ready).write_text("ready", encoding="utf-8")
started = time.monotonic()
while release != "-" and not Path(release).exists() and time.monotonic() - started < 120:
    time.sleep(0.05)
"""


def _owner_process(t: Any, tmp_path: Path, batch_id: str, *, hold: bool) -> subprocess.Popen:
    """Another process that builds draft `batch_id` through P3's real `start_batch` and then
    exits (`hold=False`) or waits for `<tmp>/release-<id>` (`hold=True`)."""
    ready = tmp_path / f"ready-{batch_id}"
    release = tmp_path / f"release-{batch_id}" if hold else "-"
    proc = subprocess.Popen(
        [sys.executable, "-c", _DRAFT_OWNER, str(location_path(t.data_root)), t.tenant_id,
         str(t.remote), t.origin, batch_id, str(ready), str(release)],
        env=fresh_process_env(t.tenant, tmp_path / f"owner-{batch_id}"),
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if not hold:
        _out, err = proc.communicate(timeout=300)
        assert proc.returncode == 0, err
    else:
        import time

        started = time.monotonic()
        while not ready.exists():
            assert proc.poll() is None, proc.communicate()[1]
            assert time.monotonic() - started < 120, "the owner never built its draft"
            time.sleep(0.05)
    assert (drafts_dir(t) / batch_id).is_dir(), "the owner built no draft"
    return proc


def test_o_sweep_publish_sweeps_a_draft_whose_owner_died_and_keeps_a_live_owners(
        p4_tenant, tmp_path):
    """O-SWEEP: a draft records its owner; the next publish (under the tenant lock) sweeps a
    draft whose owner process is dead. A draft this live process built survives the same
    publish (positive control on the same observation)."""
    t = p4_tenant
    _owner_process(t, tmp_path, "orphan", hold=False)
    mine = t.open_delivery().start_batch("mine", lanes=("lessons",))

    t.publish()

    assert draft_entries(t) == ["mine"], draft_entries(t)
    assert mine.draft_root.is_dir()


def test_o_sweep_a_live_owners_draft_survives_publish_until_its_owner_exits(p4_tenant, tmp_path):
    """O-SWEEP: liveness is the owner's, not the draft's age: while the owner process runs, a
    publish keeps its draft; once it has exited, the next publish sweeps it."""
    t = p4_tenant
    owner = _owner_process(t, tmp_path, "held", hold=True)
    try:
        t.publish()
        assert draft_entries(t) == ["held"], "a live owner's draft was swept"
    finally:
        (tmp_path / "release-held").write_text("go", encoding="utf-8")
        owner.communicate(timeout=300)
    assert owner.returncode == 0

    t.publish()

    assert draft_entries(t) == [], draft_entries(t)


def test_o_sweep_a_draft_never_shows_an_unowned_moment_to_a_publisher(p4_tenant):
    """O-SWEEP: a draft is built as a dot-named temporary with its owner record inside and only
    then renamed into place, so a draft present under its batch id always names a live owner: a
    publish right after `start_batch` in this (live) process keeps it, and no dot-named entry is
    left beside it."""
    t = p4_tenant
    batch = t.open_delivery().start_batch("fresh", lanes=("lessons",))

    t.publish()

    assert draft_entries(t) == ["fresh"]
    assert batch.draft_root.is_dir()


__all__ = [
    "LESSON_NAME",
    "LESSON_PATH",
    "BoxSpy",
    "CuratorTrigger",
    "author_drain",
    "critical_text",
    "draft_entries",
    "drain_paths",
    "drains",
    "product_repo",
    "product_state",
    "queue",
    "remote_branches",
    "run_stage",
    "touched",
    "under",
]
