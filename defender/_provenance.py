"""What a run ran against, recorded at the moment the run dir is made.

Unlike the rest of a run dir, which is content the run produced, this is a fact about the
host tree that must be captured while it is still true. The box mounts `defender/` read-only
off whatever is checked out, so without it a sibling family could silently differ in code and
an archived episode could be recomputed against a different version.

It pins how the world was built, never what it currently holds: state systems and the event
store change at runtime (corpus drift is handled separately). It is captured, never enforced:
a dirty tree is recorded and the run proceeds; callers needing the guarantee (archive, fork)
refuse.

The commit is repo-wide (a sha can only name the checkout), but `dirty` is scoped to
`CODE_SCOPE` — what the box mounts and the interpreter imports — and the scope is recorded in
the file. A repo-wide bit would be set by any stray note and so be ignored. `dirty is False`
says nothing about git-ignored paths; the box's dependencies come from an image whose tag
hashes the tracked lockfile, so a stale image is misnamed rather than silently stale.

The run dir is the box's rw bind, so the stamp is written by the host before the box exists,
and the read gate denies the file to every agent (it names host paths of uncommitted work).

Without git (the shipped runtime image), the commit comes from a build stamp baked at image
build time, always with `dirty=None`: a workspace may be mounted over the built code, so
nothing can confirm the bytes on disk are the bytes that were built.

The run also reads the tenant's own knowledge clone (settings; lessons after #1108), which no
product commit names. `knowledge` records which commit of that clone was checked out at run
start (#1204), read from its `.git` files directly because the runtime image has no git. It is
the commit only: no dirty bit, and nothing pins it for the rest of the run.
"""

from __future__ import annotations

import dataclasses
import json
import os
import re
import stat
import subprocess
from collections.abc import Mapping
from pathlib import Path

from defender import _git
from defender._io import Bound, bind, load_json_artifact, read_guarded, stat_entry, write_guarded
from defender._model import model

#: The dirty-path sample's ceiling (the paths are a debugging aid). The true total is always
#: recorded in `dirty_path_count`.
DIRTY_PATH_SAMPLE = 50

#: The subtree `dirty` speaks for, as a repo-relative git pathspec: what the box mounts and
#: the interpreter imports. Recorded in every stamp as `RunProvenance.scope`.
CODE_SCOPE = "defender"

#: Where a commit comes from when git cannot be asked; baked into the runtime image at build
#: time (`.devcontainer/Dockerfile.runtime`).
BUILD_COMMIT_ENV = "DEFENDER_BUILD_COMMIT"

#: Wall clock per git call. This is on the critical path of run-dir creation with no other
#: bound, so a hung git (stalled mount, `fsmonitor`, `index.lock`) would hang startup.
#: Generous because `--untracked-files=all` over a huge tree is slow but honest.
GIT_TIMEOUT_S = 60.0

#: Git failing without answering. All of `OSError`, not chosen subclasses: an unexecutable
#: binary (ENOEXEC) or fork/pipe failures (ENOMEM, EMFILE) raise a bare `OSError`, and a
#: hand-picked list would let one escape `materialize_run`.
_GIT_UNREACHABLE: tuple[type[BaseException], ...] = (subprocess.SubprocessError, OSError)

#: The same set plus git's own non-zero exit — everything `capture_tree` must absorb.
_GIT_FAILED: tuple[type[BaseException], ...] = (_git.GitError, *_GIT_UNREACHABLE)


#: A commit as the knowledge reader accepts it: SHA-1 (40) or SHA-256 (64) lowercase hex.
_SHA = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?")

#: The wire spelling of a knowledge folder that is not a repository.
_UNVERSIONED = "unversioned"


@model(frozen=True)
class KnowledgeRevision:
    """Which revision of the tenant knowledge clone a run started with: a commit, unversioned
    (the folder is not a repository), or unavailable with the reason. Built by `at`,
    `unversioned` or `unavailable_because`; both fields `None` is the unversioned variant."""

    commit: str | None = None
    unavailable: str | None = None

    def __post_init__(self) -> None:
        if self.commit is not None and self.unavailable is not None:
            raise ValueError("a knowledge revision is a commit or a reason, never both")
        if self.commit is not None and not _SHA.fullmatch(self.commit):
            raise ValueError(f"not a 40- or 64-hex lowercase sha: {self.commit!r}")
        if self.unavailable is not None and not self.unavailable.strip():
            raise ValueError("an unavailable knowledge revision names its reason")

    @classmethod
    def at(cls, commit: str) -> KnowledgeRevision:
        return cls(commit=commit)

    @classmethod
    def unversioned(cls) -> KnowledgeRevision:
        return cls()

    @classmethod
    def unavailable_because(cls, reason: str) -> KnowledgeRevision:
        return cls(unavailable=reason)

    def as_wire(self) -> object:
        """`{"commit": sha}` | `"unversioned"` | `{"unavailable": reason}`."""
        if self.commit is not None:
            return {"commit": self.commit}
        if self.unavailable is not None:
            return {"unavailable": self.unavailable}
        return _UNVERSIONED

    @classmethod
    def from_wire(cls, value: object) -> KnowledgeRevision | None:
        """The revision a wire value names, or `None` for anything else (absent, `null`, or
        malformed). Never raises: the stamp sits in the box's rw bind."""
        if value == _UNVERSIONED and isinstance(value, str):
            return cls.unversioned()
        if not isinstance(value, dict) or len(value) != 1:
            return None
        commit, reason = value.get("commit"), value.get("unavailable")
        try:
            if isinstance(commit, str):
                return cls.at(commit)
            if isinstance(reason, str):
                return cls.unavailable_because(reason)
        except ValueError:
            return None
        return None


@model(frozen=True)
class RunProvenance:
    """The recorded answer to "what code was this run made against?".

    `dirty` is three-valued: `False` means git reported a clean tree, `None` means git could
    not be asked. Consumers trust `dirty is False` to mean the sha names the bytes that ran, so
    an unknown must never read as clean."""

    commit: str | None
    dirty: bool | None
    dirty_paths: tuple[str, ...] = ()
    dirty_path_count: int = 0
    unavailable: str | None = None
    #: The pathspec `dirty` was measured over, carried in the record so archived stamps stay
    #: interpretable if `CODE_SCOPE` changes.
    scope: str | None = None
    #: The model this run resolved (per process), so a family comparison can check it is
    #: constant like the commit. `None` means the record does not say.
    model: str | None = None
    #: The tenant that owns this run and the world it was stamped into (a bare world id for an
    #: unforked run, `<episode>.<label>` for a forked sibling). `materialize_run` always writes
    #: both; on read, absent or wrong-typed values fold to `None`, as `scope`/`model` do.
    tenant_id: str | None = None
    world_id: str | None = None
    #: A forked sibling's lineage (source run, branch point), from the launcher's manifest;
    #: `None` when unforked. Stamped so the run's own files answer it.
    parent_run_id: str | None = None
    fork_turn: int | None = None
    #: The tenant knowledge revision the run started with (`capture_knowledge`); `None` means
    #: the record does not say (a stamp written before #1204, or a malformed value read back).
    knowledge: KnowledgeRevision | None = None

    def __post_init__(self) -> None:
        """Refuse a record no capture could have produced, so both the writer and `from_obj`
        (which catches the `ValueError`) are held to the same rules.
        """
        # `""` is not a sha; it would otherwise pass as a present commit.
        if self.commit is not None and not self.commit.strip():
            raise ValueError("commit is present but empty — an empty string is not a sha")
        # Says nothing at all, yet `read` would report it as a stamp.
        if self.commit is None and self.dirty is None and self.unavailable is None:
            raise ValueError("a record with no commit, no dirt and no reason says nothing")
        # No answer about the dirt without a commit behind it.
        if self.dirty is not None and self.commit is None:
            raise ValueError("the working tree was answered for but no commit was")
        # A clean tree has no dirty paths.
        if self.dirty is False and (self.dirty_paths or self.dirty_path_count):
            raise ValueError("a clean tree cannot carry dirty paths")
        # The sample cannot exceed its total (this also refuses a negative count).
        if len(self.dirty_paths) > self.dirty_path_count:
            raise ValueError(
                f"the dirty-path sample ({len(self.dirty_paths)}) is larger than the count it "
                f"samples ({self.dirty_path_count}) — a negative count lands here too"
            )

    def as_json(self) -> str:
        # Spelled out rather than `asdict(self)`: the wire shape is a contract.
        # `test_every_field_reaches_the_wire_and_comes_back` keeps it in step with the fields.
        return json.dumps(
            {
                "commit": self.commit,
                "dirty": self.dirty,
                "dirty_paths": list(self.dirty_paths),
                "dirty_path_count": self.dirty_path_count,
                "unavailable": self.unavailable,
                "scope": self.scope,
                "model": self.model,
                "tenant_id": self.tenant_id,
                "world_id": self.world_id,
                "parent_run_id": self.parent_run_id,
                "fork_turn": self.fork_turn,
                "knowledge": None if self.knowledge is None else self.knowledge.as_wire(),
            },
            indent=2,
            sort_keys=True,
        ) + "\n"

    @classmethod
    def from_obj(cls, obj: object) -> RunProvenance | None:
        """A record read back off disk, or `None` when the file is not one. The file sits in
        the box's rw bind, so anything there is treated as arbitrary rather than raised on."""
        if not isinstance(obj, dict):
            return None
        commit, dirty = obj.get("commit"), obj.get("dirty")
        if not (commit is None or isinstance(commit, str)):
            return None
        if not (dirty is None or isinstance(dirty, bool)):
            return None
        # On disk, an empty sha is a truncated write meaning "no sha"; the class refuses it.
        if commit == "":
            commit = None
        unavailable = obj.get("unavailable")
        unavailable = unavailable if isinstance(unavailable, str) else None
        # Non-string sample entries are dropped: the sample is lossy anyway, and
        # `dirty_path_count` is the authority. (A wrong-typed `commit`/`dirty` voids the record.)
        raw_paths = obj.get("dirty_paths")
        paths = tuple(p for p in raw_paths if isinstance(p, str)) if isinstance(raw_paths, list) else ()
        count = obj.get("dirty_path_count")
        # Optional fields fold to `None` when wrong-typed, so older stamps stay readable.
        scope = obj.get("scope")
        model = obj.get("model")
        tenant_id = obj.get("tenant_id")
        world_id = obj.get("world_id")
        parent_run_id = obj.get("parent_run_id")
        fork_turn = obj.get("fork_turn")
        # Coherence is `__post_init__`'s job; this only types each field.
        try:
            return cls(
                commit=commit,
                dirty=dirty,
                dirty_paths=paths,
                dirty_path_count=(
                    count if isinstance(count, int) and not isinstance(count, bool) else 0
                ),
                unavailable=unavailable,
                scope=scope if isinstance(scope, str) else None,
                model=(model if isinstance(model, str) else None),
                tenant_id=(tenant_id if isinstance(tenant_id, str) else None),
                world_id=(world_id if isinstance(world_id, str) else None),
                parent_run_id=(parent_run_id if isinstance(parent_run_id, str) else None),
                fork_turn=(
                    fork_turn if isinstance(fork_turn, int) and not isinstance(fork_turn, bool)
                    else None),
                # Folded here, before the record is built, so a bad value never voids the rest.
                knowledge=KnowledgeRevision.from_wire(obj.get("knowledge")),
            )
        except ValueError:
            return None


def _from_build_stamp(environ: Mapping[str, str], why: str) -> RunProvenance:
    """The record a git-less environment can still produce, or the bare failure. Always
    `dirty=None`: a workspace may be mounted over the baked code, so its state is unknown."""
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

    `environ` is the injection seam for the build-stamp fallback.

    Never raises and never hangs (`GIT_TIMEOUT_S`): this is a record, not a gate, so every git
    failure lands in `unavailable` with its reason, which tells the operator what to fix.
    """
    env = os.environ if environ is None else environ
    try:
        commit = _git.git_head_sha(repo_root, timeout=GIT_TIMEOUT_S)
    except _git.GitError as e:
        # `e`, not `e.stderr`: its `__str__` names the command and return code.
        return _from_build_stamp(env, f"git rev-parse: {e}")
    except _GIT_UNREACHABLE as e:
        return _from_build_stamp(env, f"git unavailable: {e!r}")
    try:
        records = _git.git_status(
            repo_root, pathspec=CODE_SCOPE, timeout=GIT_TIMEOUT_S, no_renames=True
        )
    except _GIT_FAILED as e:
        # Keep the live sha (better than any baked one); only the dirt is unknown.
        return RunProvenance(
            commit=commit, dirty=None, unavailable=f"git status: {e!r}", scope=CODE_SCOPE
        )
    # A set of paths, not the record list: one path can have two records (`git rm --cached`
    # leaves `D  foo` and `?? foo`). `no_renames=True` above keeps a rename's source path from
    # being dropped.
    paths = sorted({path for _xy, path in records})
    return RunProvenance(
        commit=commit,
        dirty=bool(paths),
        dirty_paths=tuple(paths[:DIRTY_PATH_SAMPLE]),
        dirty_path_count=len(paths),
        scope=CODE_SCOPE,
    )


def capture_knowledge(knowledge_dir: Path) -> KnowledgeRevision:
    """Read which commit the tenant knowledge clone at `knowledge_dir` has checked out.

    @owns knowledge — `RunProvenance.knowledge`, every stamp's tenant knowledge revision. The
    run stamp and the fork launcher's live capture both take it from here.

    Read from `.git` files, never by running git (the runtime image has none), through the
    rooted no-follow reader, so a link anywhere below `knowledge_dir` is refused rather than
    followed. Only `<knowledge_dir>/.git` as a real directory counts: there is no upward search,
    so a plain folder inside another repository (the product checkout, in dev) is unversioned
    rather than stamped with that repository's commit. Never raises: this is a record, not a
    gate, and every failure lands in the reason.
    """
    try:
        with bind(knowledge_dir) as root:
            return _read_knowledge(root)
    except (OSError, ValueError) as e:
        return KnowledgeRevision.unavailable_because(f"the knowledge clone could not be read: {e!r}")


def _read_knowledge(root: Bound) -> KnowledgeRevision:
    unavailable = KnowledgeRevision.unavailable_because
    git_dir = stat_entry(root, ".git")
    if git_dir.absent:
        return KnowledgeRevision.unversioned()
    if git_dir.st is None:
        return unavailable(f".git could not be judged: {git_dir.reason}")
    if not stat.S_ISDIR(git_dir.st.st_mode):
        return unavailable(".git is not a real directory (a gitfile or a link is not followed)")
    if not stat_entry(root, ".git/reftable").absent:
        return unavailable("reftable refs: this reader reads files-backend refs only")
    head = root.read(".git/HEAD")
    if head.text is None:
        return unavailable(f"HEAD is {'absent' if head.absent else 'unreadable'}"
                           f"{'' if head.reason is None else f' ({head.reason})'}")
    text = head.text.strip()
    if not text.startswith("ref:"):
        return (KnowledgeRevision.at(text) if _SHA.fullmatch(text)
                else unavailable(f"HEAD is neither a ref nor a commit: {text[:80]!r}"))
    name = text[len("ref:"):].strip()
    if not _is_ref_name(name):
        return unavailable(f"HEAD names {name[:80]!r}, which is not a ref under refs/")
    return _resolve_ref(root, name)


def _resolve_ref(root: Bound, name: str) -> KnowledgeRevision:
    """The commit the ref `name` holds: its loose file, else its `packed-refs` line."""
    unavailable = KnowledgeRevision.unavailable_because
    loose = root.read(f".git/{name}")
    if loose.text is not None:
        sha = loose.text.strip()
        return (KnowledgeRevision.at(sha) if _SHA.fullmatch(sha)
                else unavailable(f"the ref {name} does not hold a commit: {sha[:80]!r}"))
    # Only an ABSENT loose ref falls through to packed-refs: a refused one shadows it, as
    # git's loose-over-packed rule does.
    if not loose.absent:
        return unavailable(f"the ref {name} could not be read: {loose.reason}")
    packed = root.read(".git/packed-refs")
    if packed.text is None and not packed.absent:
        return unavailable(f"packed-refs could not be read: {packed.reason}")
    for line in (packed.text or "").splitlines():
        # The `#` header and the `^` peeled lines name no ref.
        if not line or line[0] in "#^":
            continue
        sha, _sep, ref = line.partition(" ")
        if ref == name:
            return (KnowledgeRevision.at(sha) if _SHA.fullmatch(sha)
                    else unavailable(f"packed-refs holds no commit for {name}: {sha[:80]!r}"))
    return unavailable(f"unborn branch: HEAD names {name}, which no ref holds yet")


def _is_ref_name(name: str) -> bool:
    """`refs/<component>/...`, each component a plain name: nothing that could step out of
    `.git` (`..`, an absolute path) or name a non-ref file inside it (`ORIG_HEAD`)."""
    parts = name.split("/")
    return (len(parts) >= 2 and parts[0] == "refs"
            and all(part and part not in (".", "..") and part.isprintable()
                    and not any(ch.isspace() for ch in part) for part in parts))


def capture_run(repo_root: Path, knowledge_dir: Path) -> RunProvenance:
    """The code stamp of `repo_root` with the knowledge revision of `knowledge_dir` beside it —
    what a run is stamped with and what the fork launcher compares a source against."""
    record = capture_tree(repo_root)
    return dataclasses.replace(record, knowledge=capture_knowledge(knowledge_dir))


def write(path: Path, prov: RunProvenance) -> None:
    """Stamp the record at `path` through the guarded seam, which refuses a planted non-plain
    entry rather than following it."""
    write_guarded(path, prov.as_json())


def read(path: Path) -> RunProvenance | None:
    """The record at `path`, or `None` if there is not a usable one — missing, unreadable,
    aliased and non-JSON alike, since no caller acts on the difference. `read_guarded` because
    the model may have planted an entry at this name."""
    raw, _err = read_guarded(path)
    if raw is None:
        return None
    # The shared decoder for box-written JSON (handles non-JSON and excessive nesting).
    parsed, unreadable = load_json_artifact(raw)
    if unreadable is not None:
        return None
    # Narrowed at the parse seam: `json.loads` is typed `Any`.
    if not isinstance(parsed, dict):
        return None
    return RunProvenance.from_obj(parsed)
