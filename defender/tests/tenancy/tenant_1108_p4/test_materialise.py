"""#1108 P4 flow 2: `version_control.materialise_export(tenant, commit)` writes `exports/<commit>/`
for any commit in the clone from its git objects (exports are derived and rebuildable): no
network, no issuer, the same validation as publish (`DeliveryRefused`), never touching `current`,
under the tenant lock with a short bounded retry (`LockBusy` after it).

"No network" is observed on the fakes' own call records (`GitHTTP.seen`, `ForgeHTTP.requests`,
`VaultHTTP.calls`); a real publish on the same tenant is the control that those records move.
"""
from __future__ import annotations

import threading
from pathlib import Path

import pytest

from ._support import (
    OTHER_TENANT_ID,
    agent_blobs,
    current_commit,
    export_dir,
    files_under,
    git,
    index_entry,
    push_to_remote,
)

#: A full object id the clone does not hold.
ABSENT_COMMIT = "fedcba9876543210" * 2 + "fedcba98"
#: A lesson only the unpublished commit holds.
LATER = ("agent/lessons/merged-not-yet-published.md", "merged on origin, fetched, never published\n")


def _vc():
    from defender.learning.author import version_control

    return version_control


def _materialise(tenant, commit):
    return _vc().materialise_export(tenant, commit)


def _fetch(t) -> None:
    """Bring origin's objects into the clone the way a fetch does — straight from the bare
    remote's path, so no fake records it — without publishing (no fast-forward, no export)."""
    git(t.clone, "fetch", str(t.remote), "+refs/heads/main:refs/remotes/origin/main")


def _calls(t) -> tuple[int, int, int]:
    return len(t.server.seen), len(t.forge.requests), len(t.vault.calls)


def _temporaries(t) -> list[str]:
    exports = export_dir(t.tenant, t.commit).parent
    return sorted(p.name for p in exports.iterdir() if p.name.startswith("."))


def test_flow2_materialise_writes_a_clone_commits_export_without_network_or_moving_current(
        p4_tenant):
    """A merged and fetched (never published) commit gets an export holding exactly its
    `agent/` and `settings/` blobs, with `current` and the clone untouched and no call to the
    origin, forge or issuer. Control: a real publish calls all three."""
    t = p4_tenant
    later = t.merge(dict([LATER]))
    _fetch(t)
    head = git(t.clone, "rev-parse", "HEAD")
    before = _calls(t)

    export = _materialise(t.tenant, later)

    assert export.commit == later
    assert Path(export.path) == export_dir(t.tenant, later)
    assert files_under(export_dir(t.tenant, later) / "agent") == agent_blobs(t.clone, later), (
        "the export's agent/ is not the commit's agent/ blobs")
    assert files_under(export_dir(t.tenant, later) / "settings") == agent_blobs(
        t.clone, later, prefix="settings"), "the export's settings/ is not the commit's"
    assert current_commit(t.tenant) == t.commit, "materialise moved `current`"
    assert git(t.clone, "rev-parse", "HEAD") == head, "materialise moved the clone's HEAD"
    assert not (t.clone / LATER[0]).exists(), "materialise checked the commit out in the clone"
    assert _calls(t) == before, (
        f"materialise reached the network: (origin, forge, issuer) calls {before} -> {_calls(t)}")
    assert _temporaries(t) == [], "materialise left a staging folder behind"

    t.publish()
    after = _calls(t)
    assert all(a > b for a, b in zip(after, before, strict=True)), (
        f"control: a publish did not call the origin, forge and issuer ({before} -> {after}), "
        "so their records cannot show materialise's silence")


def test_flow2_materialise_rebuilds_a_deleted_export_and_never_writes_current(p4_tenant):
    """A deleted export is rebuilt byte-identical from the clone; with no `current` at all,
    materialise still works and writes none."""
    t = p4_tenant
    first = files_under(export_dir(t.tenant, t.commit))
    exports = export_dir(t.tenant, t.commit).parent
    import shutil

    shutil.rmtree(export_dir(t.tenant, t.commit))
    (exports / "current").unlink()

    export = _materialise(t.tenant, t.commit)

    assert export.commit == t.commit
    assert files_under(export_dir(t.tenant, t.commit)) == first, (
        "the rebuilt export differs from the published one")
    assert current_commit(t.tenant) is None, "materialise wrote `current`"


def test_flow2_materialise_keeps_an_existing_export_as_it_is(p4_tenant):
    """Exports are immutable: materialising a commit whose export exists returns it untouched
    (same folder, same files)."""
    t = p4_tenant
    folder = export_dir(t.tenant, t.commit)
    inode, files = folder.stat().st_ino, files_under(folder)

    export = _materialise(t.tenant, t.commit)

    assert Path(export.path) == folder
    assert folder.stat().st_ino == inode, "an existing export was replaced"
    assert files_under(folder) == files


def _link(w: Path) -> None:
    index_entry(w, "120000", "agent/lessons/linked.md", data=b"../../settings/verb-grants.yaml")


def _gitlink(t):
    def edit(w: Path) -> None:
        index_entry(w, "160000", "agent/vendored", blob=t.commit)
    return edit


def _foreign_marker(w: Path) -> None:
    (w / "agent" / ".tenant-id").write_text(f"{OTHER_TENANT_ID}\n", encoding="utf-8")
    git(w, "add", "-A")


@pytest.mark.parametrize("bad", ["link", "gitlink", "foreign-tenant-id"])
def test_flow2_materialise_refuses_what_publish_refuses_and_leaves_nothing(p4_tenant, bad):
    """A link, a gitlink or a foreign `agent/.tenant-id` is refused as publish refuses it,
    leaving no export, no staging folder and `current` unchanged. Control: the first test."""
    t = p4_tenant
    edit = {"link": _link, "gitlink": _gitlink(t), "foreign-tenant-id": _foreign_marker}[bad]
    commit = push_to_remote(t.p3, t.scratch, edit, f"a merged {bad}", stage=False)
    _fetch(t)
    refusal = _vc().DeliveryRefused

    with pytest.raises(refusal):
        _materialise(t.tenant, commit)

    assert not export_dir(t.tenant, commit).exists(), f"a {bad} commit was exported"
    assert _temporaries(t) == [], "a refused materialise left a staging folder behind"
    assert current_commit(t.tenant) == t.commit


def test_flow2_a_commit_absent_from_the_clone_is_refused_naming_it(p4_tenant):
    """Only a commit in the clone can be rebuilt: one it does not hold is refused
    naming the commit, and no folder is made for it; nothing is fetched to find it."""
    t = p4_tenant
    before = _calls(t)
    refusal = _vc().DeliveryRefused

    with pytest.raises(refusal) as raised:
        _materialise(t.tenant, ABSENT_COMMIT)

    assert ABSENT_COMMIT in str(raised.value), f"the refusal does not name the commit: {raised.value}"
    assert not export_dir(t.tenant, ABSENT_COMMIT).exists()
    assert _calls(t) == before, "materialise went to the network looking for the commit"


class _Holder:
    """Holds the tenant's real lock (`version_control.tenant_lock`) on its own thread — a second
    open of the lock file, so a taker in this process contends with it as another process
    would (`flock` is per open file) — until `release()` or `after` seconds."""

    def __init__(self, tenant, *, after: float | None = None) -> None:
        self.taken, self.done = threading.Event(), threading.Event()
        self._after = after
        self._thread = threading.Thread(target=self._hold, args=(tenant,), daemon=True)
        self._thread.start()
        assert self.taken.wait(10), "fixture bug: the holder never took the lock"

    def _hold(self, tenant) -> None:
        with _vc().tenant_lock(tenant):
            self.taken.set()
            self.done.wait(self._after)

    def release(self) -> None:
        self.done.set()
        self._thread.join(10)


def _plant_dead_temporary(t) -> Path:
    exports = export_dir(t.tenant, t.commit).parent
    dead = exports / f".publishing-{ABSENT_COMMIT}-dead0001"
    dead.mkdir()
    (dead / "half-written").write_text("a dead publisher's leftovers\n", encoding="utf-8")
    return dead


def test_flow2_materialise_waits_out_a_briefly_held_lock(p4_tenant):
    """A lock released 0.2 s after materialise starts does not fail it (the retry's length is
    not designed; 0.2 s is well inside any short one)."""
    t = p4_tenant
    later = t.merge(dict([LATER]))
    _fetch(t)
    holder = _Holder(t.tenant, after=0.2)
    try:
        export = _materialise(t.tenant, later)
    finally:
        holder.release()
    assert export.commit == later
    assert (export_dir(t.tenant, later) / LATER[0]).is_file()


def test_flow2_materialise_gives_up_on_a_held_lock_and_writes_nothing_outside_it(p4_tenant):
    """With the lock held throughout, materialise gives up with `LockBusy` (within 60 s here)
    having written nothing to `exports/`, not even its temp sweep. Control: once the lock is
    free, the same call sweeps the dead staging folder and writes the export."""
    t = p4_tenant
    later = t.merge(dict([LATER]))
    _fetch(t)
    dead = _plant_dead_temporary(t)
    holder = _Holder(t.tenant)
    outcome: dict = {}

    def attempt() -> None:
        try:
            outcome["export"] = _materialise(t.tenant, later)
        except BaseException as failed:  # noqa: BLE001 — recorded for the main thread to judge
            outcome["raised"] = failed

    worker = threading.Thread(target=attempt, daemon=True)
    worker.start()
    worker.join(60)
    gave_up = not worker.is_alive()
    seen = dict(outcome)
    swept_while_held = not dead.exists()
    exported_while_held = export_dir(t.tenant, later).exists()
    holder.release()
    worker.join(30)

    assert gave_up, "materialise kept retrying a held lock past 60 s (the retry is bounded)"
    assert isinstance(seen.get("raised"), _vc().LockBusy), (
        f"a lock held throughout did not end in LockBusy: {seen}")
    assert not exported_while_held, "materialise wrote an export without holding the lock"
    assert not swept_while_held, "materialise swept staging folders without holding the lock"

    export = _materialise(t.tenant, later)
    assert export.commit == later
    assert not dead.exists(), "control: the free-lock materialise did not sweep the dead staging"
    assert (export_dir(t.tenant, later) / LATER[0]).is_file()
