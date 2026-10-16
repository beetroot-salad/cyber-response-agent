"""O-C/O-D, fuzzed (amendment 2's "fuzzed derivation" discharge): random box output, the
invariant as the oracle.

`hypothesis` is not a dependency of this tree, so a seeded `random.Random` drives it; a
failure names its seed and round, and replays exactly. Each round lays random lane edits
(adds at any depth, changes, deletions, random bytes); every other round adds one entry no
claim may carry, at a random place. The oracle: such a claim is refused whole; otherwise the change set is exactly the
draft against the batch's base (git's blobs at the branch's tip, or at the export commit
before the first commit; amendment 3 has no worktree), and every `AgentChange` is in a lane,
never a forbidden name, and a regular file in the draft holding exactly its bytes (or gone,
for a deletion). No link is followed: the host folder links point at keeps its bytes and no
change carries them. Some rounds commit; every round resets, after which the draft equals the
base's blobs. The clone itself never changes."""
from __future__ import annotations

import os
import random
import shutil
from pathlib import PurePosixPath

import pytest

from defender import _io

from ._support import (
    LANES,
    ForgeHTTP,
    agent_blobs,
    batch_base,
    bounded,
    delivery,
    files_under,
    git,
    odd_entries,
    plain_file,
    push_to_remote,
    target,
)

LANE = "agent/lessons"
SECRET = b"host only; no change may carry this\n"
ROUNDS = 12
SEEDS = range(4)
FORBIDDEN = (".gitattributes", ".gitignore", ".gitmodules")


class _Box:
    """Writes random box output into one batch's draft; names it plants are fresh."""

    def __init__(self, rng, batch, clone, outside):
        self.rng, self.outside = rng, outside
        self.batch, self.clone = batch, clone
        self.agent = batch.draft_root / "agent"
        self.lane = batch.draft_root / LANE
        self.count = 0
        self.fifos = []

    def fresh(self, stem, suffix=".md"):
        self.count += 1
        dirs = [f"d{self.rng.randint(0, 2)}" for _ in range(self.rng.randint(0, 2))]
        path = self.lane.joinpath(*dirs, f"{stem}{self.count}{suffix}")
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def content(self):
        return bytes(self.rng.choice(b"ab \r\n\x00\xff#") for _ in range(self.rng.randint(0, 40)))

    def existing(self):
        files = sorted(rel for rel, data in files_under(self.lane).items() if isinstance(data, bytes))
        return self.lane / self.rng.choice(files) if files else None

    def in_base(self, *, dirs=False):
        """A place in the draft's lane where the batch's base holds a file (or, with `dirs`, a
        subdirectory), so a reset must put the base's entry back there."""
        files = sorted(_base_lane(self.batch, self.clone))
        found = sorted({str(parent) for rel in files for parent in PurePosixPath(rel).parents
                        if str(parent) != "."}) if dirs else files
        return self.lane / self.rng.choice(found) if found else None

    @staticmethod
    def clear(entry):
        if entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry)
        elif os.path.lexists(entry):
            entry.unlink()
        entry.parent.mkdir(parents=True, exist_ok=True)
        return entry

    # Lane edits a claim may carry.
    def add(self):
        self.fresh("f").write_bytes(self.content())

    def change(self):
        target_file = self.existing()
        if target_file is not None:
            target_file.write_bytes(self.content())

    def delete(self):
        target_file = self.existing()
        if target_file is not None:
            target_file.unlink()

    # Entries no claim may carry; each returns what it planted, for the failure message.
    def file_link(self):
        link = self.fresh("l")
        link.symlink_to(self.outside / "secret.md")
        return link

    def relative_link(self):
        link = self.fresh("r")
        link.symlink_to(os.path.relpath(self.outside / "secret.md", link.parent))
        return link

    def replace_with_link(self):
        victim = self.clear(self.in_base() or self.fresh("l"))
        victim.symlink_to(self.outside / "secret.md")
        return victim

    def dir_link(self):
        place = self.in_base(dirs=True) if self.rng.random() < 0.5 else None
        victim = self.clear(place or self.fresh("dl", suffix=""))
        victim.symlink_to(self.outside, target_is_directory=True)
        return victim

    def fifo(self):
        place = self.in_base() if self.rng.random() < 0.5 else None
        victim = self.clear(place or self.fresh("p"))
        os.mkfifo(victim)
        self.fifos.append(victim)
        return victim

    def oversized(self):
        big = self.fresh("big")
        with open(big, "wb") as handle:
            handle.truncate(_io.READ_LIMIT + 1)
        return big

    def out_of_lane(self):
        path = self.agent / f"notes{self.count}.md"
        self.count += 1
        path.write_bytes(self.content())
        return path

    def prefix_sibling(self):
        path = self.agent / f"lessons-{self.rng.randint(0, 9)}" / "x.md"
        path.parent.mkdir(exist_ok=True)
        path.write_bytes(self.content())
        return path

    def forbidden_name(self):
        """Below the lane's root, where a root-only check misses it (the enumerated rows
        cover the root)."""
        parent = self.lane.joinpath(*[f"d{self.rng.randint(0, 2)}" for _ in range(self.rng.randint(1, 3))])
        parent.mkdir(parents=True, exist_ok=True)
        path = parent / self.rng.choice(FORBIDDEN)
        path.write_bytes(b"* filter=planted\n")
        return path

    def tenant_id(self):
        path = self.agent / ".tenant-id"
        path.write_text("red\n", encoding="utf-8")
        return path


_CARRIED = ("add", "change", "delete")
_REFUSED = ("file_link", "relative_link", "replace_with_link", "dir_link", "fifo", "oversized",
            "out_of_lane", "prefix_sibling", "forbidden_name", "tenant_id")


def _base_lane(batch, clone):
    """The lane's blobs at the batch's base, by path below the lane."""
    return agent_blobs(clone, batch_base(clone, batch), prefix=LANE)


def _expected(batch, clone):
    """The change set the draft must yield: every lane file that differs from the base's blob,
    with its bytes, and every base lane file the draft lacks, as `None`."""
    draft = files_under(batch.draft_root / LANE)
    base = _base_lane(batch, clone)
    changed = {f"{LANE}/{rel}": data for rel, data in draft.items() if base.get(rel) != data}
    gone = {f"{LANE}/{rel}": None for rel in base if rel not in draft}
    return changed | gone


def _check_carried(batch, change_set, expected, where):
    changes = {change.path: change.content for change in change_set}
    assert changes == expected, where
    for path, content in changes.items():
        parts = path.split("/")
        assert path.startswith(f"{LANE}/"), (where, path)
        assert ".." not in parts, (where, path)
        assert not set(parts) & {*FORBIDDEN, ".tenant-id", ".git"}, (where, path)
        entry = batch.draft_root / path
        if content is None:
            assert not os.path.lexists(entry), (where, path)
        else:
            assert plain_file(entry, content), (where, path)
            assert SECRET not in content, (where, path)


def _nested_base(checkout):
    for rel in ("d0/base.md", "d1/d2/base.md"):
        target_file = checkout / LANE / rel
        target_file.parent.mkdir(parents=True, exist_ok=True)
        target_file.write_bytes(b"in the base, below the lane's root\n")


@pytest.mark.parametrize("seed", SEEDS)
def test_derivation_keeps_its_invariant_on_random_box_output(repo, tmp_path, seed):
    rng = random.Random(1108_000 + seed)
    push_to_remote(repo, tmp_path, _nested_base)
    batch = delivery(repo, ForgeHTTP()).start_batch(f"fuzz-{seed}", lanes=LANES)
    outside = tmp_path / "host-folder"
    outside.mkdir()
    (outside / "secret.md").write_bytes(SECRET)
    clone = repo[0].knowledge
    box = _Box(rng, batch, clone, outside)
    for round_ in range(ROUNDS):
        for _ in range(rng.randint(1, 4)):
            getattr(box, rng.choice(_CARRIED))()
        # Every other round plants one refused entry (where is random); the kinds rotate so
        # that the four seeds together plant each kind at least twice.
        refused = _REFUSED[(round_ // 2 + seed * 3) % len(_REFUSED)] if round_ % 2 else None
        planted = getattr(box, refused)() if refused else None
        where = f"seed {seed}, round {round_}, refused entry {refused}: {planted}"
        expected = None if refused else _expected(batch, clone)
        head = batch_base(clone, batch)

        change_set, error, hung = bounded(batch.change_set, fifos=box.fifos)
        assert not hung, f"{where}: deriving blocked on box output"
        if refused:
            assert isinstance(error, target().DeliveryRefused), f"{where}: {error!r}"
        else:
            assert error is None, f"{where}: {error!r}"
            _check_carried(batch, change_set, expected, where)
            if expected and rng.random() < 0.5:
                sha = batch.commit(change_set, f"fuzz {seed}.{round_}")
                assert git(clone, "rev-parse", f"{sha}^") == head, where
                rows = git(clone, "diff-tree", "--no-commit-id", "-r", sha).splitlines()
                assert {row.split("\t", 1)[1] for row in rows} == set(expected), where
                assert {row.split()[1] for row in rows} <= {"100644", "000000"}, where
                head = sha
        assert batch_base(clone, batch) == head, where
        assert git(clone, "status", "--porcelain") == "", where
        assert files_under(outside) == {"secret.md": SECRET}, f"{where}: a link was followed"

        _, error, hung = bounded(batch.reset, fifos=box.fifos)
        assert not hung, f"{where}: the reset blocked on box output"
        assert error is None, f"{where}: reset {error!r}"
        assert odd_entries(batch.draft_root) == [], where
        assert files_under(batch.draft_root / "agent") == agent_blobs(clone, head), where
        assert files_under(outside) == {"secret.md": SECRET}, f"{where}: the reset followed a link"
        box.fifos.clear()
