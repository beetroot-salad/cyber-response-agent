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

THE COMMIT IS REPO-WIDE AND THE DIRT IS NOT, which is a pairing rather than an inconsistency.
HEAD names the whole checkout because that is the only thing a sha can name. `dirty` is scoped
to `CODE_SCOPE` — the subtree the box actually mounts and the interpreter actually imports —
and `scope` records that pathspec IN the file, so no reader has to infer which question was
asked.

Scoped because the wide bit could not be acted on. `dirty` exists for one consumer: the
refusal a fork or an archive makes when the sha does not name the bytes that ran. A bit that a
scratch file in `docs/` or an untracked note in `experiments/` sets is True on a working
machine nearly always, so that consumer would either refuse every run or learn to ignore the
field — and a bit everyone ignores protects nothing. The width reached the sample too: 50
alphabetically-first paths out of a busy repo can contain no `defender/` path at all, leaving
the debugging affordance empty exactly when it is wanted.

Nothing outside the scope executes: the estate's own tree is configuration for the systems
this queries over a socket rather than code it imports, the repo-root scripts are dev tooling,
and the rest is prose. An edit to that configuration IS a real difference between two runs —
it is corpus drift, which the paragraph above says this record does not cover and which #947
answers with its own mechanism. Widening this bit would not have covered it either; it would
only have made the narrow claim look like the wide one.

`dirty is False` IS ONLY A CLAIM ABOUT TRACKED AND UNTRACKED PATHS, never about IGNORED ones —
`git status` does not report them at any `--untracked-files` setting, and that is the one place
this record genuinely under-reports. It matters here rather than in the abstract: `defender/`
is bind-mounted into the box whole and `.venv/` is gitignored, so the interpreter and every
installed dependency the box runs against are outside what a clean bit can speak for. Read
`dirty is False` as "no TRACKED source moved", and pin the dependency set with the lockfile,
which is tracked and therefore is covered.

THE RUN DIR IS THE BOX'S RW BIND, so a model can overwrite this file the same way it can
overwrite any run-dir artifact. The stamp is written by the host BEFORE the box is created and
before any agent is alive, so a consumer that must trust it reads it off a run it is not
concurrently hosting — and since #976 the read gate DENIES the file to every agent on both
surfaces (`permission.files.names_run_provenance`), because this is the one run-root file
whose subject is the HOST tree rather than the run: a sha plus up to fifty repo-relative paths
of somebody's uncommitted work is reconnaissance, and every other file at that root is about
the run alone.

WHEN GIT CANNOT BE ASKED AT ALL, a BUILD STAMP is the fallback. The shipped runtime image
carries no git and no repository metadata — it is `FROM python:3.11-slim` plus the package
directory — so without this every containerised run would record `unavailable` while carrying
a file that looks like the drift problem was solved. `BUILD_COMMIT_ENV` is baked at image
build time from the tree the image was built from. The recovered commit ships with
`dirty=None` and NEVER with the build's own clean bit, however clean that build was: the image
documents mounting a workspace over its code, so at runtime nothing can confirm the bytes on
disk are the bytes that were built, and a fallback that claimed clean would be inventing
exactly the assurance this record exists to refuse.
"""

from __future__ import annotations

import json
import os
import subprocess
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from defender import _git
from defender._io import plain_unaliased_file, read_text_soft, write_guarded

#: The dirty-path sample's ceiling. The paths are a debugging affordance — `dirty` is the bit
#: that carries meaning — and `--untracked-files=all` over a tree with a vendored directory in
#: it can enumerate tens of thousands. The TRUE total is always recorded beside the sample
#: (`dirty_path_count`), so the cap costs detail and never costs the fact: a reader can always
#: tell a 3-file edit from a 30,000-file one, which is what a silent truncation would hide.
DIRTY_PATH_SAMPLE = 50

#: The subtree `dirty` speaks for, as a git pathspec relative to the repo root: the directory
#: the box bind-mounts read-only and the only package the interpreter imports. Spelled once
#: here and RECORDED in every stamp (`RunProvenance.scope`), so a reader never has to guess
#: which question a given file answered — the answer travels with the answer.
CODE_SCOPE = "defender"

#: Where a commit comes from when git cannot be asked. Baked into the shipped runtime image at
#: build time (`.devcontainer/Dockerfile.runtime`), which carries neither git nor repository
#: metadata; see the module docstring for why the recovered commit never carries a clean bit.
BUILD_COMMIT_ENV = "DEFENDER_BUILD_COMMIT"

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
    #: The pathspec `dirty` was measured over — `CODE_SCOPE` for anything `capture_tree`
    #: produced. Carried IN the record rather than assumed by its readers, because the day
    #: this scope changes is the day every already-archived stamp starts meaning something
    #: different, and an episode recomputed later has no other way to know which it holds.
    scope: str | None = None

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
                "scope": self.scope,
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
        # `scope` is dropped rather than refused when it is the wrong type, and a record with
        # no scope still stands: a stamp written before this field existed is a real record of
        # a real run, and refusing it would make every archived episode unreadable to settle a
        # question about a field it never carried. `None` reads as "this record does not say".
        scope = obj.get("scope")
        return cls(
            commit=commit,
            dirty=dirty,
            dirty_paths=paths,
            dirty_path_count=count if isinstance(count, int) and not isinstance(count, bool) else 0,
            unavailable=unavailable,
            scope=scope if isinstance(scope, str) else None,
        )


def _from_build_stamp(environ: Mapping[str, str], why: str) -> RunProvenance:
    """The record a git-less environment can still produce, or the bare failure if it cannot.

    `dirty=None` unconditionally — see the module docstring. The build's own cleanliness is
    deliberately NOT carried: the runtime image documents mounting a workspace over its baked
    code, so a stamp that answered `False` here would be describing a tree it has no way to
    look at."""
    baked = (environ.get(BUILD_COMMIT_ENV) or "").strip()
    if not baked:
        return RunProvenance(commit=None, dirty=None, unavailable=why, scope=CODE_SCOPE)
    return RunProvenance(
        commit=baked, dirty=None, scope=CODE_SCOPE,
        unavailable=(
            f"{why}; commit recovered from the {BUILD_COMMIT_ENV} build stamp, which names the "
            "tree the image was BUILT from — nothing here can confirm it describes the code on "
            "disk, so the working tree's state is unknown rather than clean"
        ),
    )


def capture_tree(
    repo_root: Path, *, environ: Mapping[str, str] | None = None
) -> RunProvenance:
    """Ask git what `repo_root` is sitting on, right now.

    `environ` is the injection seam for the build-stamp fallback, defaulted at the boundary
    rather than re-coalesced in the body (`defender/CLAUDE.md`, "anchor a default in one
    place").

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
    env = os.environ if environ is None else environ
    try:
        commit = _git.git_head_sha(repo_root, timeout=GIT_TIMEOUT_S)
    except _git.GitError as e:
        # `e`, not `e.stderr`: `GitError.__str__` already carries the command and the return
        # code, and which of the two git calls refused is half of what sends an operator at
        # the right knob.
        return _from_build_stamp(env, f"git rev-parse: {e}")
    except _GIT_UNREACHABLE as e:
        return _from_build_stamp(env, f"git unavailable: {e!r}")
    try:
        records = _git.git_status(
            repo_root, pathspec=CODE_SCOPE, timeout=GIT_TIMEOUT_S, no_renames=True
        )
    except _GIT_FAILED as e:
        # The sha is already in hand and is worth keeping on its own; what is unknown is
        # whether it describes the bytes that ran, and `dirty=None` is exactly that statement.
        # NOT the build-stamp path: a live git already named a better commit than any baked
        # value, and falling back here would REPLACE a true sha with a stale one.
        return RunProvenance(
            commit=commit, dirty=None, unavailable=f"git status: {e!r}", scope=CODE_SCOPE
        )
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
        scope=CODE_SCOPE,
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
    # `plain_unaliased_file`, not the plain read: this file sits in the box's rw bind, so an
    # entry at its name may be an alias the model planted, and `read_text_soft` would follow it
    # and hand back whatever it points at AS this run's stamp.
    #
    # THE SAME PREDICATE `write_guarded` REFUSES ON, which is the point of it being a shared
    # function rather than a matching pair of lstats. `_run_paths.artifact_file` stood here
    # first and is strictly weaker: it is an `S_ISREG` test, so it ACCEPTS a hard link — the
    # one alias shape `O_NOFOLLOW` cannot refuse (`_io`, B9) and therefore the one the write
    # side goes out of its way to catch. Twins by construction; the comment that claimed it
    # before was describing an intention.
    if not plain_unaliased_file(path):
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
