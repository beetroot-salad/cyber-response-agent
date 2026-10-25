"""What a run ran against, recorded at the moment the run dir is made."""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections.abc import Mapping
from pathlib import Path

from defender import _git
from defender._io import load_json_artifact, read_guarded, write_guarded
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
    #: The tenant that owns this run and the world it was stamped into: a forked sibling's world
    #: opaque world UUID, `None` for a natural run (#1187 R1b retired the base
    #: world a natural run used to copy from its tenant record). On read, absent or
    #: wrong-typed values fold to `None`, as `scope`/`model` do.
    tenant_id: str | None = None
    world_id: str | None = None
    #: A forked sibling's lineage (source run, branch point), from the launcher's manifest;
    #: `None` when unforked. Stamped so the run's own files answer it.
    parent_run_id: str | None = None
    fork_turn: int | None = None
    #: The tenant knowledge revision the run started with (the export it copied, #1108 P4);
    #: `None` means the record does not say (a stamp written before #1204, or a malformed
    #: value read back).
    knowledge: KnowledgeRevision | None = None
    #: Display facts (#1187 O7): when run setup started the run (ISO-8601 UTC text) and the
    #: alert's label, which the opaque run id no longer spells. The file sits in the box's rw
    #: bind, so no decision reads them (N5): the run page shows them, escaped. Absent or
    #: wrong-typed on read, each folds to `None` without voiding the record.
    started_at: str | None = None
    alert_label: str | None = None

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

    def as_json(self, *, knowledge_source: Mapping[str, str | None] | None = None) -> str:
        """The stamp's wire text. `knowledge_source` is how the run came by its knowledge
        (#1108 P4, OD17): `{kind, commit, stale_kind}` of the run's host-held knowledge-source
        record, informational and never the reason. It is not a field of the record: the host
        record beside the run dir is authoritative for every reader, and readers of the stamp
        ask only whether the key is there (`records._knowledge_status`). Without it the stamp
        keeps its pre-P4 shape."""
        # Spelled out rather than `asdict(self)`: the wire shape is a contract.
        # `test_every_field_reaches_the_wire_and_comes_back` keeps it in step with the fields.
        doc: dict[str, object] = {
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
            "started_at": self.started_at,
            "alert_label": self.alert_label,
        }
        if knowledge_source is not None:
            doc["knowledge_source"] = {k: knowledge_source.get(k) for k in KNOWLEDGE_SOURCE_KEYS}
        return json.dumps(doc, indent=2, sort_keys=True) + "\n"

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
        started_at = obj.get("started_at")
        alert_label = obj.get("alert_label")
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
                started_at=(started_at if isinstance(started_at, str) else None),
                alert_label=(alert_label if isinstance(alert_label, str) else None),
            )
        except ValueError:
            return None


#: The keys the stamp's `knowledge_source` may carry (OD17): never the publish's reason.
KNOWLEDGE_SOURCE_KEYS = ("kind", "commit", "stale_kind")


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
