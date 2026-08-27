"""What a run ran against, recorded at the moment the run dir is made.

Every other file in a run dir is CONTENT THE RUN PRODUCED — the alert it was handed, the
investigation it wrote, the payloads it fetched. This one is the first fact the run records
ABOUT ITSELF, and the distinction is why it lives in its own module rather than as one more
accessor's worth of code: the census in `_run_paths.RunPaths` is a layout fact, while this is
a claim about the world outside the run dir that has to be captured while it is still true.

WHY A RUN NEEDS ONE (#976). The box mounts `defender/` read-only off whatever is checked out
on the host, so the code a run executes — the agent, the shims on the box's PATH, the query
templates, and the three lesson corpora, which are git-tracked inside that same tree — is
"whatever HEAD happened to be". Nothing recorded that. Two consequences, both silent:

- **A sibling family is not a controlled comparison.** #947 forks one finished run into worlds
  that must differ in exactly the one axis the questioner declared. Run them across a checkout
  that moved and they also differ in their code, with nothing anywhere to notice it.
- **An archived episode cannot be recomputed.** #947 requires the episode to archive as one
  recoverable object whose `ΔO` recomputes with no re-run. Recompute against a tree that has
  since moved and you are comparing two code versions without knowing you are.

WHAT IT DOES NOT COVER, spelled out because a commit sha invites over-reading: it pins how the
world was BUILT, never what the world currently HOLDS. The state systems are mutable at
runtime — the ticket store is a real system the `ticket` verbs write — and the event store
is fed continuously by the collection agents, so its documents were never in git to begin
with. Corpus drift is a separate problem with a separate mechanism (#947's timestamped
windows); this record removes CODE drift and should not be read as claiming more.

CAPTURED, NEVER ENFORCED. A dirty tree is recorded as dirty and the run proceeds: nearly all
real work happens with uncommitted edits, and a stamp that refuses to exist is worse than one
that admits what it could not promise. The refusal belongs to the caller that needs the
guarantee — a run being archived or forked — and is #976's, not this module's.

THE RUN DIR IS THE BOX'S RW BIND, so a model can overwrite this file the same way it can
overwrite any run-dir artifact — see `_run_paths.artifact_file`, which exists for exactly that
reason. The stamp is written by the host BEFORE the box is created and before any agent is
alive, so a consumer that must trust it reads it off a run it is not concurrently hosting.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path

from defender import _git
from defender._io import read_text_soft, write_guarded

#: The dirty-path sample's ceiling. The paths are a debugging affordance — `dirty` is the bit
#: that carries meaning — and `--untracked-files=all` over a tree with a vendored directory in
#: it can enumerate tens of thousands. The TRUE total is always recorded beside the sample
#: (`dirty_path_count`), so the cap costs detail and never costs the fact: a reader can always
#: tell a 3-file edit from a 30,000-file one, which is what a silent truncation would hide.
DIRTY_PATH_SAMPLE = 50

#: `git` missing from PATH entirely — `subprocess` raises before git can report anything, so
#: it is not a `GitError` and would otherwise escape as an unhandled OSError out of run-dir
#: creation.
_GIT_ABSENT = (FileNotFoundError, NotADirectoryError, PermissionError)


@dataclass(frozen=True)
class RunProvenance:
    """The recorded answer to "what code was this run made against?".

    `dirty` is THREE-VALUED on purpose. `False` means git was asked and reported a clean tree;
    `None` means git could not be asked at all. Collapsing the second into the first would
    record an unknown as a clean bill of health — the one error a provenance record must not
    make, because every downstream consumer of this file trusts `dirty is False` to mean the
    sha names the bytes that ran."""

    commit: str | None
    dirty: bool | None
    dirty_paths: tuple[str, ...] = ()
    dirty_path_count: int = 0
    unavailable: str | None = None

    def as_json(self) -> str:
        return json.dumps(
            {
                "commit": self.commit,
                "dirty": self.dirty,
                "dirty_paths": list(self.dirty_paths),
                "dirty_path_count": self.dirty_path_count,
                "unavailable": self.unavailable,
            },
            indent=2,
            sort_keys=True,
        ) + "\n"

    @classmethod
    def from_obj(cls, obj: object) -> RunProvenance | None:
        """A record read back off disk, or `None` when the file is not one.

        Typed `object` and forgiving for the reason `_run_paths.contained_payload` is: this
        file sits in the box's rw bind, so a reader must treat anything there as arbitrary —
        a list, a truncated write, a model-planted string — and answer "no usable record"
        rather than raise out of whatever archive walk is calling it."""
        if not isinstance(obj, dict):
            return None
        commit, dirty = obj.get("commit"), obj.get("dirty")
        if not (commit is None or isinstance(commit, str)):
            return None
        if not (dirty is None or isinstance(dirty, bool)):
            return None
        raw_paths = obj.get("dirty_paths")
        paths = tuple(p for p in raw_paths if isinstance(p, str)) if isinstance(raw_paths, list) else ()
        count = obj.get("dirty_path_count")
        unavailable = obj.get("unavailable")
        return cls(
            commit=commit,
            dirty=dirty,
            dirty_paths=paths,
            dirty_path_count=count if isinstance(count, int) and not isinstance(count, bool) else 0,
            unavailable=unavailable if isinstance(unavailable, str) else None,
        )


def capture_tree(repo_root: Path) -> RunProvenance:
    """Ask git what `repo_root` is sitting on, right now.

    NEVER RAISES. A run that cannot be stamped still has to run — this is a record, not a gate
    — so every way git can refuse (absent binary, not a repository, an unborn HEAD in a
    freshly-`init`ed tree, a broken index) lands as a record that says so in `unavailable`
    rather than as an exception out of `materialize_run_dir`. The reason string is kept because
    "no sha" and "no sha BECAUSE there are no commits yet" send an operator at different knobs.
    """
    try:
        commit = _git.git_head_sha(repo_root)
    except _git.GitError as e:
        return RunProvenance(commit=None, dirty=None, unavailable=f"git: {e.stderr or e}")
    except (subprocess.SubprocessError, *_GIT_ABSENT) as e:
        return RunProvenance(commit=None, dirty=None, unavailable=f"git unavailable: {e!r}")
    try:
        records = _git.git_status(repo_root)
    except (_git.GitError, subprocess.SubprocessError, *_GIT_ABSENT) as e:
        # The sha is already in hand and is worth keeping on its own; what is unknown is
        # whether it describes the bytes that ran, and `dirty=None` is exactly that statement.
        return RunProvenance(commit=commit, dirty=None, unavailable=f"git status: {e!r}")
    paths = sorted(path for _xy, path in records)
    return RunProvenance(
        commit=commit,
        dirty=bool(paths),
        dirty_paths=tuple(paths[:DIRTY_PATH_SAMPLE]),
        dirty_path_count=len(paths),
    )


def write(path: Path, prov: RunProvenance) -> None:
    """Stamp the record at `path`. Through the guarded seam, like every other shared-tree
    write, so a symlink planted at the name is replaced rather than followed."""
    write_guarded(path, prov.as_json())


def read(path: Path) -> RunProvenance | None:
    """The record at `path`, or `None` if there is not a usable one there.

    `read_text_soft` and a swallowed decode error together mean a missing, unreadable or
    non-JSON file all answer the same way: the caller asked whether this run carries a stamp,
    and the answer is no. The read error itself is DROPPED rather than raised or returned: no
    caller can act on "the stamp was unreadable" differently from "there is no stamp", and a
    second return channel would put that choice in front of every one of them."""
    raw, _err = read_text_soft(path)
    if raw is None:
        return None
    try:
        parsed: object = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        return None
    # The shape check belongs to the seam that performed the parse, not to `from_obj` alone:
    # `json.loads` is typed `Any`, and an `Any` flowing straight into a call whose return is
    # annotated `RunProvenance | None` type-checks clean while promising a reader something
    # the runtime never verified. One `isinstance` here is what makes the annotation true.
    if not isinstance(parsed, dict):
        return None
    return RunProvenance.from_obj(parsed)
