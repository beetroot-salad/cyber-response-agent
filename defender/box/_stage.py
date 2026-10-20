"""The unboxed fallback's model view: a per-run staging tree (#1255 P1 "Every mode", C6, C8)."""
from __future__ import annotations

import os
import shutil
import stat
import tempfile
import threading
import weakref
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from defender._io import guarded_mkdir
from defender.execution import bash_exec
from defender.execution.box_codec import BoxResult, RawExec, decode_request, encode_response
from defender.runtime.model_view import MODEL_AGENT, MODEL_DEFENDER, MODEL_RUN

from ._spec import BoxExecutor, BoxSpec

_STAGE_PREFIX = "defender-view-"


def _remove(entry: Path) -> None:
    if entry.is_dir() and not entry.is_symlink():
        shutil.rmtree(entry)
    else:
        entry.unlink()


def _same_bytes(a: Path, b: Path) -> bool:
    with open(a, "rb") as fa, open(b, "rb") as fb:  # lint-whole-read: ok — compared in chunks
        while True:
            ca, cb = fa.read(1 << 16), fb.read(1 << 16)
            if ca != cb:
                return False
            if not ca:
                return True


def _carry_file(entry: os.DirEntry[str], target: Path) -> None:
    """Copy the regular file `entry` over `target` unless `target` already holds its bytes."""
    st = entry.stat(follow_symlinks=False)
    try:
        have = target.lstat()
    except FileNotFoundError:
        have = None
    if have is not None and stat.S_ISREG(have.st_mode) and (
            have.st_size == st.st_size and have.st_mtime_ns == st.st_mtime_ns
            and _same_bytes(Path(entry.path), target)):
        return
    if have is not None:
        _remove(target)
    shutil.copy2(entry.path, target, follow_symlinks=False)


def _mirror_tree(src: Path, dst: Path, *, base: Path, skip: frozenset[str]) -> None:
    """Make `dst` hold what `src` holds: its folders and regular files, compared by size and
    mtime and then by bytes, so an edit of the same size in the same clock tick is still
    carried. Anything else at a name (a link, a FIFO) is not carried — a run folder holds none
    the host made, and none is followed."""
    seen: set[str] = set()
    with os.scandir(src) as entries:
        for e in entries:
            if e.name in skip:
                continue
            target = dst / e.name
            if e.is_dir(follow_symlinks=False):
                seen.add(e.name)
                if target.is_symlink() or (target.exists() and not target.is_dir()):
                    _remove(target)
                guarded_mkdir(target, base=base)
                _mirror_tree(Path(e.path), target, base=base, skip=frozenset())
            elif e.is_file(follow_symlinks=False):
                seen.add(e.name)
                _carry_file(e, target)
    for name in os.listdir(dst):
        if name not in seen:
            _remove(dst / name)


@dataclass(frozen=True)
class StagingTree:
    """One run's staging tree: where each model root lives on the host for the unboxed lane."""

    root: Path
    run_dir: Path
    #: Run-folder entries not carried (the wire logs: no role may read them).
    unmirrored: frozenset[str]
    #: Held across a refresh: concurrent gather leads run their commands at once, and two walks
    #: over one `runs/current` would remove and copy under each other.
    _refreshing: threading.Lock = field(default_factory=threading.Lock, compare=False, repr=False)

    @property
    def run_view(self) -> Path:
        return self.root / MODEL_RUN.relative_to("/")

    def roots(self) -> tuple[tuple[PurePosixPath, Path], ...]:
        return (
            (MODEL_RUN, self.run_view),
            (MODEL_DEFENDER, self.root / MODEL_DEFENDER.relative_to("/")),
            (MODEL_AGENT, self.root / MODEL_AGENT.relative_to("/")),
        )

    def place(self, word: str) -> str:
        """`word` resolved into the staging tree when it is a model path, else unchanged."""
        for model, staged in self.roots():
            root = str(model)
            if word == root:
                return str(staged)
            if word.startswith(root + "/"):
                return str(staged) + word[len(root):]
        return word

    def refresh(self) -> None:
        """Carry the run folder's current content into `runs/current` (C6)."""
        with self._refreshing:
            _mirror_tree(Path(self.run_dir), self.run_view, base=self.root, skip=self.unmirrored)


def make_staging_tree(
    run_dir: Path, defender_dir: Path, tenant_agent: Path | None, *, unmirrored: frozenset[str],
) -> StagingTree:
    root = Path(tempfile.mkdtemp(prefix=_STAGE_PREFIX))
    tree = StagingTree(root=root, run_dir=Path(run_dir), unmirrored=unmirrored)
    guarded_mkdir(tree.run_view, base=root)
    (root / MODEL_DEFENDER.relative_to("/")).symlink_to(Path(defender_dir).resolve())
    if tenant_agent is not None:
        (root / MODEL_AGENT.relative_to("/")).symlink_to(Path(tenant_agent).resolve())
    tree.refresh()
    return tree


@dataclass(frozen=True)
class _StagedHostTransport:
    """The host transport over a staging tree: refresh the tree, resolve the command's model
    paths into it, run it on the host under the model-view environment."""

    env: dict[str, str]
    tree: StagingTree

    def __call__(self, frame: bytes, *, cwd: Path, timeout: float) -> RawExec:
        self.tree.refresh()
        pipelines = [
            bash_exec.Pipeline(pl.connector, [
                bash_exec.Stage([self.tree.place(w) for w in st.argv], st.stderr)
                for st in pl.stages
            ])
            for pl in decode_request(frame)
        ]
        rc, out, err = bash_exec.run_parsed(
            pipelines, command="", env=self.env, cwd=Path(self.tree.place(str(cwd))),
            timeout=timeout,
        )
        return RawExec(rc=rc, stdout=encode_response(BoxResult(
            rc=rc,
            out=out.encode("utf-8", "replace"),
            err=err.encode("utf-8", "replace"),
        )), stderr=b"")


def staged_executor(
    spec: BoxSpec, run_dir: Path, defender_dir: Path, tenant_agent: Path | None,
    *, unmirrored: frozenset[str],
) -> BoxExecutor:
    """The unboxed fallback's executor: the model view over a fresh staging tree, its programs
    run under the run's environment pointing into that tree (`run_common.run_env` over the
    staged trees), so no variable names the real runs folder or the run folder."""
    from defender import run_common

    tree = make_staging_tree(run_dir, defender_dir, tenant_agent, unmirrored=unmirrored)
    env = run_common.run_env(
        tree.root / MODEL_DEFENDER.relative_to("/"), tree.run_view,
        tenant_agent=(tree.root / MODEL_AGENT.relative_to("/")) if tenant_agent is not None else None,
    )
    executor = BoxExecutor(spec=spec, transport=_StagedHostTransport(env, tree), name="")
    weakref.finalize(executor, shutil.rmtree, tree.root, True)
    return executor


__all__ = ["StagingTree", "make_staging_tree", "staged_executor"]
