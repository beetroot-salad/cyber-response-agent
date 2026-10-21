"""Opaque record locations. Layout owners construct them; storage owners convert them.

These values carry a location, not proof of acceptance. They intentionally implement no
filesystem protocol, path arithmetic, child selector, or filesystem-string conversion.
"""
from __future__ import annotations

from pathlib import Path


class _Location:
    __slots__ = ("_record_location_path",)
    _record_location_path: Path

    def __init__(self, path: Path) -> None:
        if not isinstance(path, Path):
            raise TypeError("a record location requires a Path")
        object.__setattr__(self, "_record_location_path", path)

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("record locations are immutable")

    def __delattr__(self, name: str) -> None:
        raise AttributeError("record locations are immutable")

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, _Location) or type(other) is not type(self):
            return NotImplemented
        return self._record_location_path == other._record_location_path

    def __hash__(self) -> int:
        return hash((type(self), self._record_location_path))

    def __reduce__(self) -> tuple[type[_Location], tuple[Path]]:
        # Accepted Tenant snapshots already support copy/deepcopy/pickle (#1105).
        return type(self), (self._record_location_path,)

    def __repr__(self) -> str:
        return f"<{type(self).__name__}>"


class DataRoot(_Location):
    """The opaque data root location."""
    __slots__ = ()


def _unwrap_data_root(location: DataRoot) -> Path:
    if not isinstance(location, DataRoot):
        raise TypeError("expected DataRoot")
    return location._record_location_path


class TenantRoot(_Location):
    """The opaque tenant root location."""
    __slots__ = ()


def _unwrap_tenant_root(location: TenantRoot) -> Path:
    if not isinstance(location, TenantRoot):
        raise TypeError("expected TenantRoot")
    return location._record_location_path


class TenantRecord(_Location):
    """The opaque tenant record location."""
    __slots__ = ()


class RunsBase(_Location):
    """The opaque runs base location."""
    __slots__ = ()


def _unwrap_runs_base(location: RunsBase) -> Path:
    if not isinstance(location, RunsBase):
        raise TypeError("expected RunsBase")
    return location._record_location_path


class SessionsRoot(_Location):
    """The opaque sessions root location."""
    __slots__ = ()


def _unwrap_sessions_root(location: SessionsRoot) -> Path:
    if not isinstance(location, SessionsRoot):
        raise TypeError("expected SessionsRoot")
    return location._record_location_path


class EpisodesRoot(_Location):
    """The opaque episodes root location."""
    __slots__ = ()


def _unwrap_episodes_root(location: EpisodesRoot) -> Path:
    if not isinstance(location, EpisodesRoot):
        raise TypeError("expected EpisodesRoot")
    return location._record_location_path


class LearningRoot(_Location):
    """The opaque learning root location."""
    __slots__ = ()


def _unwrap_learning_root(location: LearningRoot) -> Path:
    if not isinstance(location, LearningRoot):
        raise TypeError("expected LearningRoot")
    return location._record_location_path


class WorktreesRoot(_Location):
    """The opaque worktrees root location."""
    __slots__ = ()


class ExportsRoot(_Location):
    """The opaque exports root location."""
    __slots__ = ()


def _unwrap_exports_root(location: ExportsRoot) -> Path:
    if not isinstance(location, ExportsRoot):
        raise TypeError("expected ExportsRoot")
    return location._record_location_path


class DraftsRoot(_Location):
    """The opaque drafts root location."""
    __slots__ = ()


def _unwrap_drafts_root(location: DraftsRoot) -> Path:
    if not isinstance(location, DraftsRoot):
        raise TypeError("expected DraftsRoot")
    return location._record_location_path


class KnowledgeLock(_Location):
    """The opaque knowledge lock location."""
    __slots__ = ()


def _unwrap_knowledge_lock(location: KnowledgeLock) -> Path:
    if not isinstance(location, KnowledgeLock):
        raise TypeError("expected KnowledgeLock")
    return location._record_location_path


class CommitRecord(_Location):
    """The opaque commit record location."""
    __slots__ = ()


def _unwrap_commit_record(location: CommitRecord) -> Path:
    if not isinstance(location, CommitRecord):
        raise TypeError("expected CommitRecord")
    return location._record_location_path


class LegacyRunsRoot(_Location):
    """The opaque legacy runs root location."""
    __slots__ = ()


def _unwrap_legacy_runs_root(location: LegacyRunsRoot) -> Path:
    if not isinstance(location, LegacyRunsRoot):
        raise TypeError("expected LegacyRunsRoot")
    return location._record_location_path


class LegacyEpisodesRoot(_Location):
    """The opaque legacy episodes root location."""
    __slots__ = ()


def _unwrap_legacy_episodes_root(location: LegacyEpisodesRoot) -> Path:
    if not isinstance(location, LegacyEpisodesRoot):
        raise TypeError("expected LegacyEpisodesRoot")
    return location._record_location_path


class SessionTrustRoot(_Location):
    """The opaque session trust root location."""
    __slots__ = ()


def _unwrap_session_trust_root(location: SessionTrustRoot) -> Path:
    if not isinstance(location, SessionTrustRoot):
        raise TypeError("expected SessionTrustRoot")
    return location._record_location_path
