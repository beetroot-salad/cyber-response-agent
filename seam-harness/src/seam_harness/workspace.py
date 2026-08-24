"""Read-only, content-addressed workspace snapshots for recursive dossiers."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .recursive_models import (
    RecursivePolicy,
    WorkspaceDocument,
    WorkspaceIndexEntry,
    WorkspaceLimitError,
)


IGNORED_DIRECTORY_NAMES = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".venv",
    "__pycache__",
    "node_modules",
    "outputs",
    "runs",
}


@dataclass(frozen=True, slots=True)
class WorkspaceSnapshot:
    root: Path
    entries: tuple[WorkspaceIndexEntry, ...]
    _documents: dict[str, WorkspaceDocument]

    def documents(self, paths: list[str]) -> list[WorkspaceDocument]:
        normalized = [normalize_relative_path(path) for path in paths]
        missing = sorted(set(normalized) - self._documents.keys())
        if missing:
            raise KeyError(f"Workspace paths are absent from the snapshot: {missing}")
        return [self._documents[path] for path in dict.fromkeys(normalized)]

    @property
    def paths(self) -> set[str]:
        return set(self._documents)


def normalize_relative_path(value: str) -> str:
    candidate = PurePosixPath(value.replace("\\", "/"))
    if candidate.is_absolute() or ".." in candidate.parts:
        raise ValueError(f"Workspace path must be relative and contained: {value!r}")
    normalized = candidate.as_posix()
    while normalized.startswith("./"):
        normalized = normalized[2:]
    if normalized in {"", "."}:
        raise ValueError("Workspace path must name a file")
    return normalized


def snapshot_workspace(root: Path, policy: RecursivePolicy) -> WorkspaceSnapshot:
    resolved = root.resolve(strict=True)
    if not resolved.is_dir():
        raise ValueError(f"Workspace is not a directory: {resolved}")

    documents: dict[str, WorkspaceDocument] = {}
    total_bytes = 0
    candidates = sorted(
        path
        for path in resolved.rglob("*")
        if path.is_file()
        and not path.is_symlink()
        and not any(
            part in IGNORED_DIRECTORY_NAMES for part in path.relative_to(resolved).parts
        )
    )
    if len(candidates) > policy.max_workspace_files:
        raise WorkspaceLimitError(
            f"Workspace has {len(candidates)} candidate files; limit is "
            f"{policy.max_workspace_files}. Point --workspace at a narrower tree."
        )

    for path in candidates:
        raw = path.read_bytes()
        if len(raw) > policy.max_workspace_file_bytes:
            continue
        if b"\x00" in raw:
            continue
        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        total_bytes += len(raw)
        if total_bytes > policy.max_workspace_total_bytes:
            raise WorkspaceLimitError(
                "UTF-8 workspace content exceeds the configured total byte limit; "
                "point --workspace at a narrower tree or raise the policy limit."
            )
        relative = path.relative_to(resolved).as_posix()
        document = WorkspaceDocument(
            path=relative,
            size_bytes=len(raw),
            content_sha256=hashlib.sha256(raw).hexdigest(),
            content=content,
        )
        documents[relative] = document

    entries = tuple(
        WorkspaceIndexEntry(
            path=document.path,
            size_bytes=document.size_bytes,
            content_sha256=document.content_sha256,
        )
        for document in documents.values()
    )
    return WorkspaceSnapshot(root=resolved, entries=entries, _documents=documents)
