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

`dirty` IS THE WHOLE REPO, not `defender/`, and a consumer must read it that way: it answers
"does this sha name the bytes on disk anywhere in the checkout", which OVER-reports relative
to the code a run executes (an edit in `docs/` or `experiments/` sets it). Deliberately the
conservative direction — a bit that under-reported would be the lie the record exists to
prevent — but it means the bit alone cannot distinguish "the agent changed" from "a doc
changed", and the same width reaches the sample: `dirty_paths` is the alphabetical head of the
whole repo's dirt, so on a busy tree it can be 50 paths none of which is under `defender/`. A
caller that needs the narrower question has `_git.git_status(cwd, pathspec=...)` and should
ask it rather than reading more into this field than it says.

`dirty is False` IS ONLY A CLAIM ABOUT TRACKED AND UNTRACKED PATHS, never about IGNORED ones —
`git status` does not report them at any `--untracked-files` setting, and that is the one place
this record genuinely under-reports. It matters here rather than in the abstract: `defender/`
is bind-mounted into the box whole and `.venv/` is gitignored, so the interpreter and every
installed dependency the box runs against are outside what a clean bit can speak for. Read
`dirty is False` as "no TRACKED source moved", and pin the dependency set with the lockfile,
which is tracked and therefore is covered.

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
from defender._run_paths import artifact_file

#: The dirty-path sample's ceiling. The paths are a debugging affordance — `dirty` is the bit
#: that carries meaning — and `--untracked-files=all` over a tree with a vendored directory in
#: it can enumerate tens of thousands. The TRUE total is always recorded beside the sample
#: (`dirty_path_count`), so the cap costs detail and never costs the fact: a reader can always
#: tell a 3-file edit from a 30,000-file one, which is what a silent truncation would hide.
DIRTY_PATH_SAMPLE = 50

#: Wall clock each git call gets. NOT decoration: this runs on the critical path of every
#: run-dir creation, before the box exists and before any lifecycle bound applies, so a git
#: that never returns — a checkout on a stalled network mount, an `fsmonitor` helper that
#: hangs, a contended `index.lock` — would otherwise hang run startup with no diagnostic and
#: no bound. The generous value is deliberate: `--untracked-files=all` over a genuinely huge
#: tree is slow but honest, and a timeout that fired on it would file a real answer as an
#: unknown. `TimeoutExpired` is a `SubprocessError`, so it lands in the handlers below.
GIT_TIMEOUT_S = 60.0

#: Asking git can fail without git ever answering, and `OSError` is the whole family rather
#: than the three subclasses that are easy to name. An absent binary is `FileNotFoundError`,
#: but a corrupt or arch-mismatched `git` on PATH raises a BARE `OSError` (ENOEXEC), and so do
#: fork/pipe failures under load (ENOMEM, EMFILE) — none of them a `GitError`, none a
#: `SubprocessError`, and every one of them fatal to `materialize_run_dir` if this tuple is a
#: hand-picked list. `_io.TEXT_READ_ERRORS` names the parent for the same reason.
_GIT_UNREACHABLE: tuple[type[BaseException], ...] = (subprocess.SubprocessError, OSError)

#: The same set plus git's own non-zero exit — everything `capture_tree` must absorb.
_GIT_FAILED: tuple[type[BaseException], ...] = (_git.GitError, *_GIT_UNREACHABLE)


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
        # SPELLED OUT rather than `asdict(self)`: the wire shape is a contract a reader off
        # disk parses, so the fields that reach the file are chosen here rather than following
        # whatever the class happens to hold. That makes this a SECOND census of the fields,
        # which is a census that can drift — the field planned next (the branch point's moment,
        # the source-run pointer; see `_run_paths.RunPaths`) would otherwise be dropped by the
        # writer while every round-trip test still passed on the fields it does spell. The arm
        # that stops that is `test_every_field_reaches_the_wire_and_comes_back`, which derives
        # the expected key set from `dataclasses.fields` rather than from a list typed twice.
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
        # `""` IS NOT A SHA, and `isinstance(commit, str)` admits it. Left standing it reads as
        # a commit that is PRESENT, so it walks straight past the guard below and a truncated or
        # planted `{"commit": "", "dirty": false}` comes back as a clean bill of health with
        # nothing behind it — the identical error a missing `commit` is refused for, and
        # `_announce_provenance` then prints the bare `commit=`. Folded into the absent case
        # rather than refused on its own line, because "no sha" is what both shapes say.
        if commit == "":
            commit = None
        unavailable = obj.get("unavailable")
        unavailable = unavailable if isinstance(unavailable, str) else None
        # TYPE-CHECKING EACH FIELD ALONE IS NOT ENOUGH — the two shapes below are well-typed
        # and `capture_tree` cannot produce either, so accepting them would let a truncated or
        # planted file read back as a legitimate record:
        #
        #   `{}` (and any object whose three answers are all absent) says nothing at all, and
        #   `read` would report it as "this run carries a stamp" to a caller whose only
        #   question is whether one exists.
        #
        #   ANY answer about the dirt with no `commit` behind it. `dirty is False` is the clean
        #   bill of health with nothing behind it — the ONE error the class docstring says this
        #   record must not make — and `dirty is True` is no more producible: every
        #   `commit is None` path in `capture_tree` leaves `dirty` at `None` and sets a reason,
        #   so the guard is written against that rule rather than against the one shape of it
        #   that is scariest. Admitting `{"commit": null, "dirty": true}` also put an announce
        #   line reading `commit=unavailable (None)` in front of an operator.
        if commit is None and dirty is None and unavailable is None:
            return None
        if dirty is not None and commit is None:
            return None
        # The non-string entries are dropped rather than refused, and the record still stands:
        # `dirty_paths` is a LOSSY SAMPLE by construction (capped at `DIRTY_PATH_SAMPLE`), so a
        # dropped entry is indistinguishable from a capped one and breaks no invariant the
        # field carries. `dirty_path_count` beside it is the authority on how many there were,
        # which is why that one is the field the class refuses to let lie. Contrast `commit`
        # and `dirty`, where a wrong type IS a claim and the whole record goes.
        raw_paths = obj.get("dirty_paths")
        paths = tuple(p for p in raw_paths if isinstance(p, str)) if isinstance(raw_paths, list) else ()
        count = obj.get("dirty_path_count")
        return cls(
            commit=commit,
            dirty=dirty,
            dirty_paths=paths,
            dirty_path_count=count if isinstance(count, int) and not isinstance(count, bool) else 0,
            unavailable=unavailable,
        )


def capture_tree(repo_root: Path) -> RunProvenance:
    """Ask git what `repo_root` is sitting on, right now.

    NEVER RAISES. A run that cannot be stamped still has to run — this is a record, not a gate
    — so every way git can refuse (absent binary, not a repository, an unborn HEAD in a
    freshly-`init`ed tree, a broken index, a `git` that cannot be exec'd, a fork that fails
    under load) lands as a record that says so in `unavailable` rather than as an exception out
    of `materialize_run_dir`. The reason string is kept because "no sha" and "no sha BECAUSE
    there are no commits yet" send an operator at different knobs.

    NEVER HANGS EITHER, which is the same promise: both calls carry `GIT_TIMEOUT_S`, so a git
    that never returns lands here as a `TimeoutExpired` record rather than as a run that
    started and produced no output.
    """
    try:
        commit = _git.git_head_sha(repo_root, timeout=GIT_TIMEOUT_S)
    except _git.GitError as e:
        # `e`, not `e.stderr`: `GitError.__str__` already carries the command and the return
        # code, and which of the two git calls refused is half of what sends an operator at
        # the right knob.
        return RunProvenance(commit=None, dirty=None, unavailable=f"git rev-parse: {e}")
    except _GIT_UNREACHABLE as e:
        return RunProvenance(commit=None, dirty=None, unavailable=f"git unavailable: {e!r}")
    try:
        records = _git.git_status(repo_root, timeout=GIT_TIMEOUT_S, no_renames=True)
    except _GIT_FAILED as e:
        # The sha is already in hand and is worth keeping on its own; what is unknown is
        # whether it describes the bytes that ran, and `dirty=None` is exactly that statement.
        return RunProvenance(commit=commit, dirty=None, unavailable=f"git status: {e!r}")
    # A KEY SET, not the record list (`defender/CLAUDE.md`, "a render list is not a key set").
    # `git status -z` emits one record per (path, reason), and one path can earn two: `git rm
    # --cached foo` leaves `D  foo` AND `?? foo`, so `len(records)` counts that path twice and
    # the sample spends two of its 50 slots on it. `dirty_path_count` is the field a reader is
    # told can always tell a 3-file edit from a 30,000-file one, which a per-record count
    # cannot — it overstates, in exactly the direction the cap's comment promises it never
    # does. The status letters are dropped here rather than kept: the record answers HOW MANY
    # paths the sha does not name, never why each one differs.
    #
    # `no_renames=True` closes the OTHER direction, which is the one that would be a lie. With
    # detection on, `git mv a b` is a single `R  b` record whose original `a` the parser
    # consumes as the record's trailing field and drops — so a 30,000-file rename counts 15,000
    # and the vanished halves are named nowhere. Off, the same move is `D  a` + `A  b`: two
    # paths, both of which the sha genuinely fails to describe.
    paths = sorted({path for _xy, path in records})
    return RunProvenance(
        commit=commit,
        dirty=bool(paths),
        dirty_paths=tuple(paths[:DIRTY_PATH_SAMPLE]),
        dirty_path_count=len(paths),
    )


def write(path: Path, prov: RunProvenance) -> None:
    """Stamp the record at `path`. Through the guarded seam, like every other shared-tree
    write, so a symlink or other non-plain entry planted at the name is REFUSED rather than
    followed — `write_guarded`'s `_refuse_unless_plain` raises there rather than writing
    through the alias. That refusal is the one way stamping can fail a run, and it is the
    right way round: a planted entry at the stamp's name is not a run to record, it is a run
    dir someone else has already been in."""
    write_guarded(path, prov.as_json())


def read(path: Path) -> RunProvenance | None:
    """The record at `path`, or `None` if there is not a usable one there.

    `read_text_soft` and a swallowed decode error together mean a missing, unreadable or
    non-JSON file all answer the same way: the caller asked whether this run carries a stamp,
    and the answer is no. The read error itself is DROPPED rather than raised or returned: no
    caller can act on "the stamp was unreadable" differently from "there is no stamp", and a
    second return channel would put that choice in front of every one of them."""
    # `artifact_file` (an `lstat`), not the plain read: this file sits in the box's rw bind, so
    # an entry at its name may be a link the model planted, and `read_text_soft` would follow
    # it and hand back whatever it points at AS this run's stamp — the read-side twin of the
    # refusal `write` already makes. `scripts/lint/lint_tree_read_follows_link` is the census
    # this module is listed in for exactly that reason.
    if not artifact_file(path):
        return None
    raw, _err = read_text_soft(path)
    if raw is None:
        return None
    try:
        parsed: object = json.loads(raw)
    except (ValueError, RecursionError):
        # `JSONDecodeError` IS a `ValueError`, so the parent alone is the guard (`_io.parse_
        # jsonl_row`'s convention). `RecursionError` is NOT one and `json.loads` raises it on a
        # deeply nested payload — `learning/branch/capture.py` already paid for that omission
        # once, where one such row escaped every frame and killed the episode.
        return None
    # The shape check belongs to the seam that performed the parse, not to `from_obj` alone:
    # `json.loads` is typed `Any`, and an `Any` flowing straight into a call whose return is
    # annotated `RunProvenance | None` type-checks clean while promising a reader something
    # the runtime never verified. One `isinstance` here is what makes the annotation true.
    if not isinstance(parsed, dict):
        return None
    return RunProvenance.from_obj(parsed)
