"""Tenants: the tenant id, the one acceptance of a tenant, and its row."""
from __future__ import annotations

import dataclasses
import json
import os
import re
import stat
from collections.abc import Callable, Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, TypeVar

from pydantic import ValidationError
from pydantic_core import core_schema

from defender.records._locations import (
    DataRoot, TenantRoot, TenantRecord, RunsBase, SessionsRoot, EpisodesRoot, LearningRoot, WorktreesRoot, ExportsRoot, DraftsRoot, KnowledgeLock, CommitRecord, LegacyRunsRoot, LegacyEpisodesRoot, _unwrap_data_root, _unwrap_tenant_root, _unwrap_runs_base, _unwrap_episodes_root,
)
from defender.records import _alert_input
from defender.records._run_id import mint_uuid, uuid_id_fault
from defender import _io as _real_io
from defender import _paths
from defender._model import model
from defender._shown import escaped, quoted, shown
from defender.tenancy._tenants import (
    AGENT_HALF,
    REQUIRED_SETTINGS,
    SETTINGS_HALF,
    TENANT_ID_FILE,
    TOP_LEVEL_ALLOWED,
)

if TYPE_CHECKING:
    from defender.records._lookup import RunsRepository

_R = TypeVar("_R")
_P = TypeVar("_P")

#: The tenant's row, inside its own folder under the data root.
ROW_NAME = "tenant.json"

_ROW_FIELDS = ("tenant_id", "created_at")

#: The data-root knob (D2). Private: the design exports no public string constant from this
#: module (J05 — a public `str` here is an import-refused "record name" under
#: `lint_run_records`'s import arm).
_DATA_ROOT_ENV = "DEFENDER_DATA_ROOT"


class TenantRefused(Exception):
    """The one refusal shape (#0, F0/J29) for every tenant owner — this module (acceptance
    and its knowledge-folder rules included) and the run's grants (`run_tenant`): the
    message names the value that was refused, and every entry catches THIS and surfaces it
    verbatim. An `Exception`, not a `ValueError` (#1067's `_model.py` convention): pydantic
    wraps a `ValueError` raised inside a validator into its own `ValidationError`, where an
    `except TenantRefused` would silently miss it."""

    def __init__(self, message: object = "") -> None:
        # Escaped where it is built, as `RunRefused` is: a path or a value read off disk can
        # carry a control character, and no raising site has to remember to escape it.
        super().__init__(escaped(message))


class TenantId(str):
    """An opaque tenant id in canonical lowercase UUID text — the ONE place it is checked. Constructing one
    is the check: `TenantId(raw)` returns the id or raises `TenantRefused` naming `raw`, and a
    `TenantId` handed back in is returned as-is. It IS a `str` (paths, JSON, argv and log lines
    take it unchanged, and its repr is the string's), but a function that declares `TenantId`
    tells mypy a plain, unchecked `str` does not belong there. Entry points build one from the
    request; records and rows build one as they parse."""

    __slots__ = ()

    def __new__(cls, raw: object) -> TenantId:
        if isinstance(raw, TenantId):
            return raw
        fault = uuid_id_fault(raw, "tenant")
        if fault is not None:
            raise TenantRefused(fault)
        assert isinstance(raw, str)
        return super().__new__(cls, raw)

    @classmethod
    def mint(cls) -> TenantId:
        """Mint a tenant UUID without creating a tenant or writing any state."""
        return cls(mint_uuid())

    @classmethod
    def __get_pydantic_core_schema__(cls, _source: Any, _handler: Any) -> Any:
        return core_schema.no_info_after_validator_function(cls, core_schema.str_schema())


@model(frozen=True)
class TenantRow:
    tenant_id: TenantId
    created_at: str


def is_valid_tenant_id(tenant_id: object) -> bool:
    try:
        TenantId(tenant_id)
    except TenantRefused:
        return False
    return True


def _parse_json_record(
    text: str, record: type[_R], fields: tuple[str, ...], *, source: Path,
    refusal: type[TenantRefused],
) -> _R:
    """`text` as a `record` (the tenant row), or `refusal` naming `source`. Keys beyond
    `fields` are ignored; `TenantId` checks the id as the field is set."""
    # The nesting-checked decoder, not `json.loads`: a deeply nested record is refused as
    # corrupt, naming it, rather than escaping as a `RecursionError` (#1105, P2).
    obj, bad_json = _real_io.load_json_artifact(text)
    if bad_json is not None:
        raise refusal(f"{source} is not valid JSON: {bad_json}")
    if not isinstance(obj, dict):
        raise refusal(f"{source} is not a JSON object")
    try:
        return record(**{k: obj[k] for k in fields if k in obj})
    except ValidationError as bad:
        detail = "; ".join(
            f"{'.'.join(map(str, e['loc'])) or 'record'}: {e['msg']}" for e in bad.errors())
        raise refusal(f"{source}: {detail}") from bad
    except TenantRefused as bad:
        raise refusal(f"{source}: {bad}") from bad


# ==========================================================================================
# The tenant's layout (D1), and its guarded form the pre-acceptance sites use (M4).
# ==========================================================================================

class _TenantLayout:
    """The tenant's layout below its folder `dir` — the ONE place it is spelled (D1); inside
    the knowledge folder, the halves' and `.tenant-id`'s names are `_tenants`' constants. Joins
    only: it reads nothing and guards nothing. `Tenant` reads its paths here (an accepted
    tenant was guarded once, at acceptance); the pre-acceptance sites reach it through
    `_TenantPaths`, which guards first."""

    def __init__(self, tenant_dir: Path) -> None:
        self.tenant_root = tenant_dir

    @property
    def row(self) -> Path:
        return self.tenant_root / ROW_NAME

    @property
    def runs(self) -> Path:
        return self.tenant_root / "runs"

    @property
    def sessions(self) -> Path:
        return self.tenant_root / "sessions"

    @property
    def episodes(self) -> Path:
        return self.tenant_root / "episodes"

    @property
    def runs_legacy(self) -> Path:
        """Where the one-time command (#1187 Flow 6) moves `runs/`'s pre-#1187 entries. Nothing
        reads it."""
        return self.tenant_root / "runs-legacy"

    @property
    def episodes_legacy(self) -> Path:
        """Where the one-time command moves the old shared episodes root's entries. Nothing
        reads it."""
        return self.tenant_root / "episodes-legacy"

    @property
    def learning(self) -> Path:
        return self.tenant_root / "learning"

    @property
    def worktrees(self) -> Path:
        return self.learning / "worktrees"

    @property
    def knowledge(self) -> Path:
        return self.tenant_root / "knowledge"

    @property
    def exports(self) -> Path:
        return self.tenant_root / "exports"

    @property
    def drafts(self) -> Path:
        return self.tenant_root / "drafts"

    @property
    def run_knowledge(self) -> Path:
        return self.tenant_root / "run-knowledge"

    @property
    def publish_status(self) -> Path:
        return self.tenant_root / "publish-status.json"

    @property
    def knowledge_lock(self) -> Path:
        return self.tenant_root / "knowledge.lock"

    @property
    def commit_record(self) -> Path:
        return self.learning / "commit-maker.jsonl"

    @property
    def settings(self) -> Path:
        return self.knowledge / SETTINGS_HALF

    @property
    def agent(self) -> Path:
        return self.knowledge / AGENT_HALF


class _TenantPaths(_TenantLayout):
    """The tenant's layout under a data root, guarded (M4). Private: the sites that need a
    tenant's locations before (or without) accepting it — acceptance itself (`accept_tenant`,
    setup's `accept_placed_knowledge`), `create_tenant`, `require_tenant` — use it; everything after acceptance reads
    `Tenant`. Constructing one creates nothing, and carries the two guards every such site
    must meet first: the data root is absolute (J03), and the tenant's folder is not inside
    the running checkout's box-mounted `defender/` (O11a)."""

    def __init__(self, root: DataRoot, tenant_id: str) -> None:
        #: The id, parsed: a plain string handed in is checked here (a `TenantId` passes as-is).
        self.tenant_id = TenantId(tenant_id)
        root_path = _unwrap_data_root(root)
        _refuse_unusable_data_root(root_path)
        _refuse_inside_defender_tree(_resolve_or_refuse(root_path / self.tenant_id), root_path)
        super().__init__(root_path / self.tenant_id)


def _refuse_unusable_data_root(root: Path) -> None:
    """J03 and O11a on the data root itself, before anything under it is named: it must be
    absolute, and it may not lie inside the running checkout's `defender/` tree."""
    if not root.is_absolute():
        raise TenantRefused(f"data root {str(root)!r} must be an absolute path")
    _refuse_inside_defender_tree(_resolve_or_refuse(root), root)


def _refuse_inside_defender_tree(resolved: Path, root: Path) -> None:
    """O11a: a tenant folder may not land inside THIS checkout's box-mounted `defender/` tree
    (comparison against `PATHS.defender_dir` specifically — not any directory named
    'defender', so another checkout's own `defender/` tree is untouched, N13). `resolved` is
    already resolved: the root's, or the tenant folder's (a linked `<T>` judged by where it
    leads)."""
    defender_dir = _resolve_or_refuse(_paths.PATHS.defender_dir)
    if resolved.is_relative_to(defender_dir):
        raise TenantRefused(
            f"{resolved} (data root {root}) is inside the checkout's defender/ tree "
            f"({defender_dir}) — a tenant folder must live outside the box-mounted checkout")


def _resolve_or_refuse(path: Path) -> Path:
    """`path` with every link resolved, or `TenantRefused` naming it — the ONE translation of a
    failed resolution (an unreadable component, a link loop — Python 3.11 raises
    `RuntimeError` for one, not `OSError` — or a NUL in a caller's path). What is resolved:
    what an operator or a caller hands in (the data root, `defender_dir`, the box-mounted
    trees, a run dir), and two names below the root that are judged by where they lead — the
    tenant's folder (O11a, before acceptance) and its `runs/` (step 7). The knowledge folder
    is never resolved: acceptance walks it no-follow."""
    try:
        return Path(path).resolve()
    except (OSError, RuntimeError, ValueError) as unresolvable:
        raise TenantRefused(f"{path} could not be resolved: {unresolvable}") from unresolvable


# ==========================================================================================
# The accepted tenant (D1).
# ==========================================================================================

#: The token only `accept_tenant` holds: `Tenant` refuses construction without it, so a value
#: of that type is one acceptance passed (N10). A copy or a pickle of an accepted tenant does
#: not run `__init__` and is allowed.
_ACCEPTED = object()


@dataclasses.dataclass(frozen=True)
class Tenant:
    """One accepted tenant: its id, the data root it was accepted under, and its row — built
    ONLY by `accept_tenant`, and frozen. Record locations are opaque values; knowledge
    content paths remain ordinary paths.

    A point-in-time value (M3): it says the tree passed acceptance when it was built."""

    id: TenantId
    data_root: DataRoot
    row: TenantRow
    _token: dataclasses.InitVar[object]

    def __post_init__(self, _token: object) -> None:
        if _token is not _ACCEPTED:
            raise TenantRefused(
                "a Tenant is built only by accept_tenant — accept the tenant instead")

    @property
    def _layout(self) -> _TenantLayout:
        return _TenantLayout(_unwrap_data_root(self.data_root) / self.id)

    @property
    def tenant_root(self) -> TenantRoot:
        return TenantRoot(self._layout.tenant_root)

    @property
    def row_path(self) -> TenantRecord:
        """The row FILE's path; `row` is the row itself."""
        return TenantRecord(self._layout.row)

    @property
    def runs(self) -> RunsBase:
        return RunsBase(self._layout.runs)

    @property
    def sessions(self) -> SessionsRoot:
        return SessionsRoot(self._layout.sessions)

    @property
    def episodes(self) -> EpisodesRoot:
        return EpisodesRoot(self._layout.episodes)

    @property
    def runs_legacy(self) -> LegacyRunsRoot:
        return LegacyRunsRoot(self._layout.runs_legacy)

    @property
    def episodes_legacy(self) -> LegacyEpisodesRoot:
        return LegacyEpisodesRoot(self._layout.episodes_legacy)

    @property
    def learning(self) -> LearningRoot:
        return LearningRoot(self._layout.learning)

    @property
    def worktrees(self) -> WorktreesRoot:
        return WorktreesRoot(self._layout.worktrees)

    @property
    def knowledge(self) -> Path:
        return self._layout.knowledge

    @property
    def exports(self) -> ExportsRoot:
        """Host-made, immutable copies of the knowledge at one commit each (`<commit>/`), and
        the `current` pointer naming the latest (#1108 amendment 2)."""
        return ExportsRoot(self._layout.exports)

    @property
    def drafts(self) -> DraftsRoot:
        """Host-made, git-free copies of `agent/` a drain box writes into, one per batch."""
        return DraftsRoot(self._layout.drafts)

    @property
    def run_knowledge(self) -> Path:
        """Host-made per-run copies of one export (`<run_id>/{owner, settings/, stage/}`,
        #1108 P4 U9): what a run reads, removed when the run ends and swept by a publish once
        their owner is dead."""
        return self._layout.run_knowledge

    def export_folder(self, commit: str) -> Path:
        """`<T>/exports/<commit>/`, the published export of one commit, for a reader that judges
        it itself (a run's copy, a map of what a run read). `commit` must be one path segment:
        anything else is `TenantRefused`, never joined (callers hold it to a commit id first)."""
        if not commit or "/" in commit or commit in (".", ".."):
            raise TenantRefused(f"{commit!r} does not name an export (one commit id, no path)")
        return self._layout.exports / commit

    @property
    def publish_status(self) -> Path:
        """The outcome of the tenant's last publish attempt, by any trigger (a run launch, a
        drain start, `tenant.py update`): its refusal, or the commit it published. What
        `tenant.py check` reports a stalled publish from (#1108 P4 O-SEE)."""
        return self._layout.publish_status

    @property
    def knowledge_lock(self) -> KnowledgeLock:
        """The per-tenant lock over the knowledge clone and its exports: held for a
        fast-forward, export publication, filter configuration and draft build or sweep,
        never across network I/O, a box window or commit creation."""
        return KnowledgeLock(self._layout.knowledge_lock)

    @property
    def commit_record(self) -> CommitRecord:
        """The commit-maker's record of every tenant commit it made, which outlives the
        process that made them: push routes send only commits it lists."""
        return CommitRecord(self._layout.commit_record)

    @property
    def settings(self) -> Path:
        return self._layout.settings

    @property
    def agent(self) -> Path:
        return self._layout.agent

    def root_names(self) -> dict[str, str]:
        """How text shown to a model or an operator names this tenant's host roots instead of
        locating them: each spelling (`_paths.root_spellings`) of its own folder
        (`<tenant folder>`) and of the data root it was accepted under (`<data root>`). For text
        whose host paths no layout rule chose — an adapter's crash, a repr of the run's record
        (#1256's reasons) — handed to `_paths.name_roots`, which names whole paths only and the
        longest spelling first, so the tenant's folder is never cut into `<data root>/<id>`.
        Read here because this module owns the root (#1210)."""
        return {**_paths.root_spellings(_unwrap_data_root(self.data_root), "<data root>"),
                **_paths.root_spellings(_unwrap_tenant_root(self.tenant_root), "<tenant folder>")}

    def runs_repository(self) -> RunsRepository:
        """This tenant's runs repository (#1105 PR 2, decision C): bound to this tenant, and
        below it everything is ids. Only an accepted `Tenant` exists, so this is the one way a
        repository is built. The package is imported here, lazily: it imports this module."""
        from defender.records._lookup import RunsRepository

        return RunsRepository(self)

    def learning_state_exists(self) -> bool:
        """Whether the tenant's learning state root is there (any entry, a link included):
        without one no drain has run or can run (only `tenant.py setup` creates it)."""
        return self._layout.learning.is_symlink() or self._layout.learning.exists()

    def learning_paths(self, paths_type: Callable[..., _P], *, repo_root: Path) -> _P:
        """Build learning configuration where the tenant's record root is owned."""
        return paths_type(repo_root=repo_root, state_dir=self.learning, tenant=self)

    def accept_requested_tenant(self, raw_id: object) -> Tenant:
        """Fresh acceptance of an addressed tenant under this identity's data root.

        Queue ownership remains the caller's check; this keeps the root inside its owner
        while preserving request-time validation rather than reusing an acceptance snapshot.
        """
        return requested_tenant(self.data_root, raw_id)


def clone_halves(tenant: Tenant) -> tuple[Path, Path]:
    """`(agent/, settings/)` of `tenant`'s clone working tree. No run reads them (#1108 P4, O-B:
    run start hands its run copy's roots); they are the default roots of a tenant record resolved
    over the tenant's own folder by a caller that names no export (REPLAY-WT)."""
    return tenant.agent, tenant.settings


def requested_tenant_id(raw: object) -> TenantId:
    """The tenant a request names (`--tenant`), checked against the id grammar — the ONE rule
    every entry point applies to it before accepting: absent is refused (there is no default
    tenant), anything else is held to `TenantId`. Reads nothing, so an entry point applies it
    before it resolves the data root."""
    if raw is None:
        raise TenantRefused(
            "--tenant is required: every request names its tenant, and there is no default "
            "tenant")
    return TenantId(raw)


def accept_tenant(
    data_root: DataRoot, raw_id: object, *, defender_dir: Path, box_mounted: Iterable[Path | RunsBase | EpisodesRoot] = (),
    clone_tree: bool = True,
) -> Tenant:
    """`raw_id` under `data_root`, checked whole — the ONE acceptance of a tenant, and the
    only constructor of `Tenant`. Refused with `TenantRefused` naming the refused value, at the
    FIRST check that fails, in this order:

    `clone_tree=False` is run start's acceptance (#1108 P4, flow 3: "accept tenant" first). A run
    reads its own copy of an export and nothing of the clone's working tree (P-1), and the run
    copy's settings are held to `check_run_settings`. The folder rules still judge the clone
    whenever it has a working tree, so a tenant whose folder is faulted is refused at run start
    with the tenant check's own reason (#1222 A5), snapshot or none; only a clone whose working
    tree is gone altogether (both halves absent, its git objects kept: R-I5) is not asked."""
    tenant_id = TenantId(raw_id)
    paths = _TenantPaths(data_root, tenant_id)
    row = _read_row(paths)
    _accept_knowledge(paths, defender_dir=defender_dir, box_mounted=box_mounted,
                      clone_tree=clone_tree)
    return Tenant(id=tenant_id, data_root=data_root, row=row, _token=_ACCEPTED)


def box_mounted_episodes(data_root: DataRoot, raw_id: object) -> EpisodesRoot:
    """The tenant's episodes folder, `<data root>/<T>/episodes` — every arm container a box of
    its episodes mounts lies inside it, so the launcher names it as `box_mounted` (#1187 S-acc;
    no environment names it). Judged as every pre-acceptance site judges the root and the id
    (`TenantRefused`). A join: nothing is read or made."""
    return EpisodesRoot(_TenantPaths(data_root, TenantId(raw_id)).episodes)


def box_mounted_arm_container(data_root: DataRoot, raw_id: object, episode_id: str) -> RunsBase:
    """The arm container a sibling's box mounts — `<data root>/<T>/episodes/<episode id>/runs`
    — named BEFORE the tenant is accepted, so the sibling hands it to acceptance as
    `box_mounted` (step 7 holds the settings half out of it, judging it by where it leads, so a
    link planted there is seen). The episode id is judged first (`EpisodeRefused`), the root and
    the id as every pre-acceptance site judges them (`TenantRefused`). A join: nothing is read
    or made."""
    from defender.episodes._episode_handle import refuse_bad_episode_id
    from defender.episodes._episode_paths import LAYOUT

    episode_id = refuse_bad_episode_id(episode_id)
    return RunsBase(_unwrap_episodes_root(box_mounted_episodes(data_root, raw_id)) / episode_id / LAYOUT.runs)


def requested_tenant(data_root: DataRoot, raw: object) -> Tenant:
    """The tenant a request names — a command line's raw `--tenant` text, or the `TenantId` a
    stored row carries — accepted under `data_root`: the ONE acceptance step every request
    without a box of its own shares (the tracer, the pages, the `--tenant T <run_id>` opener,
    the curation drain's rehydration). The id is held to `requested_tenant_id` (absent is
    refused; no default tenant), then `accept_tenant` with the running process's `defender/`
    and no box mount beside the runs base — a process that mounts more (`run.py`, a sibling)
    accepts with its own mounts. `TenantRefused` at the first check that fails."""
    from defender._paths import process_defender_dir

    return accept_tenant(data_root, requested_tenant_id(raw),
                         defender_dir=process_defender_dir())


def accept_placed_knowledge(
    data_root: DataRoot, raw_id: object, *, defender_dir: Path, box_mounted: Iterable[Path | RunsBase | EpisodesRoot] = (),
) -> tuple[Path, bool]:
    """Setup's half of acceptance, for a tenant whose row may not exist yet: every check
    `accept_tenant` makes except that the row must exist — a row that IS there must still read
    as this tenant's. Returns `(the settings folder, whether the row exists)`, or refuses as
    `accept_tenant` would. Reads only."""
    tenant_id = TenantId(raw_id)
    paths = _TenantPaths(data_root, tenant_id)
    has_row = os.path.lexists(paths.row)
    if has_row:
        _read_row(paths)
    _accept_knowledge(paths, defender_dir=defender_dir, box_mounted=box_mounted)
    return paths.settings, has_row


def learning_root_for_setup(data_root: DataRoot, tenant_id: TenantId) -> LearningRoot:
    """The learning root of a tenant that may not be accepted yet: setup builds its learning
    state before the row exists. For setup's use only; every run-time reader goes through an
    accepted `Tenant`."""
    return LearningRoot(_TenantPaths(data_root, tenant_id).learning)


def _accept_knowledge(
    paths: _TenantPaths, *, defender_dir: Path, box_mounted: Iterable[Path | RunsBase | EpisodesRoot],
    clone_tree: bool = True,
) -> None:
    """Steps 3-7 of `accept_tenant` over an id and root its layout class already guarded.
    The knowledge folder is neither followed nor resolved: the walk opens `<T>` and
    `knowledge` no-follow off the root's handle, so a linked `<T>` or `knowledge` is refused,
    and the settings half's real path is then the root's own resolution joined below it.
    Both relative names come from the layout (`_TenantLayout`), never spelled here."""
    root = paths.tenant_root.parent
    knowledge_name = paths.knowledge.relative_to(root).as_posix()
    with _real_io.bind(root) as bound:
        _knowledge_is_real(paths, _real_io.stat_entry(bound, knowledge_name))
        if clone_tree or _has_working_tree(bound, knowledge_name):
            _check_knowledge(bound.under(knowledge_name), paths.knowledge,
                             tenant_id=paths.tenant_id)
    root_real = _resolve_or_refuse(root)
    settings_real = root_real / paths.settings.relative_to(root)
    halves_real = (settings_real, root_real / paths.agent.relative_to(root))
    knowledge_real = root_real / paths.knowledge.relative_to(root)
    for mounted in (Path(defender_dir), paths.runs, *(_unwrap_runs_base(m) if isinstance(m, RunsBase) else _unwrap_episodes_root(m) if isinstance(m, EpisodesRoot) else m for m in box_mounted)):
        mounted_real = _resolve_or_refuse(mounted)
        if settings_real.is_relative_to(mounted_real):
            raise TenantRefused(
                f"tenant {paths.tenant_id!r}'s settings {paths.settings} are inside {mounted}, "
                "which a box mounts — the settings half is host-only; keep the data root "
                "outside the code tree and the runs base")
        # The tenant's own runs base, where every run writes, stays out of the whole knowledge
        # folder (its git working tree: a push would publish run data); any other mounted tree
        # is held out of the two halves — the spec's near-miss cells name trees beside them.
        inside = (knowledge_real,) if mounted == paths.runs else halves_real
        if any(mounted_real.is_relative_to(tree) for tree in inside):
            raise TenantRefused(
                f"{mounted}, which a box mounts, lies inside tenant {paths.tenant_id!r}'s "
                f"knowledge folder {paths.knowledge} — a run's writes would land in the "
                "tenant's repo; keep the runs base and every mounted tree outside it")


def _has_working_tree(bound: _real_io.Bound, knowledge_name: str) -> bool:
    """Whether the knowledge folder has either half of a working tree (judged no-follow): any
    entry at `settings` or `agent`, sound or not, counts, so only a tree that is gone
    altogether escapes the folder rules."""
    return any(not _real_io.stat_entry(bound, f"{knowledge_name}/{half}").absent
               for half in (SETTINGS_HALF, AGENT_HALF))


def _knowledge_is_real(paths: _TenantPaths, found: _real_io.StatRead) -> None:
    """Step 3's first half: `<T>/knowledge`, reached without following `<T>` or itself, is a
    real directory. Absent, it is the operator's to place, so the refusal says how — and, for
    a tenant from before #1120, names the one-off `tenant.py migrate`."""
    knowledge = paths.knowledge
    if found.absent:
        raise TenantRefused(
            f"tenant {paths.tenant_id!r} has no knowledge folder: {knowledge} does not "
            f"exist — clone the tenant repo into it on the host, then run "
            f"tenant.py setup {paths.tenant_id} (a tenant set up before #1120, whose settings "
            f"the product repo committed until then, has no repo to clone: build the folder "
            f"from the repo's history with tenant.py migrate {paths.tenant_id} {knowledge} "
            f"instead)")
    if found.st is None or not stat.S_ISDIR(found.st.st_mode):
        why = found.reason or ("it is a link" if found.st is not None
                               and stat.S_ISLNK(found.st.st_mode) else "it is not a directory")
        raise TenantRefused(
            f"tenant {paths.tenant_id!r}'s knowledge folder {knowledge} must be a real "
            f"directory, never a link or a file, under an unlinked {paths.tenant_root}: {why}")


def check_knowledge_folder(folder: Path, *, tenant_id: TenantId | None) -> None:
    """The folder rules — everything about a knowledge folder that needs no data root: its top
    level holds only `TOP_LEVEL_ALLOWED`; its `settings/` and `agent/` halves are real
    directories inside it; `REQUIRED_SETTINGS` are files; neither half holds a link or a
    special file; and `agent/.tenant-id` reads as `tenant_id`. With `tenant_id` None (a tenant
    repo checked on its own, `tenant.py check --folder`, CI's census lint) the file may be
    absent, and is held only to the id grammar when present. Raises `TenantRefused` naming the
    path at the first rule that fails. Reads only, and opens no file but `.tenant-id`."""
    folder = Path(folder)
    with _real_io.bind(folder) as bound:
        _check_knowledge(bound, folder, tenant_id=tenant_id)


def _check_knowledge(
    bound: _real_io.Bound, folder: Path, *, tenant_id: TenantId | None,
) -> None:
    """`check_knowledge_folder`'s rules over `bound`, the knowledge folder's no-follow reader;
    `folder` is its path, used only to name what is refused."""
    top = bound.entries()
    if top.entries is None:
        raise TenantRefused(f"{folder} could not be listed: "
                            f"{top.reason or 'it does not exist'}")
    stray = sorted(name for name in top.entries if name not in TOP_LEVEL_ALLOWED)
    if stray:
        raise TenantRefused(
            f"{folder}/{shown(stray[0])} is not allowed at the top of a tenant's "
            "knowledge folder — "
            f"it may hold only {sorted(TOP_LEVEL_ALLOWED)}; keep anything else (an .env, "
            "secrets) out of the data root")
    for name in (SETTINGS_HALF, AGENT_HALF):
        _half(_real_io.stat_entry(bound, name), folder / name, name)
    for rel in REQUIRED_SETTINGS:
        _required_setting(_real_io.stat_entry(bound, f"{SETTINGS_HALF}/{rel}"),
                          folder / SETTINGS_HALF / rel)
    # The two mapping files (#1222 A5): every fault, one fixed reason each, in one refusal. Asked
    # before the link walk, so a link or FIFO at a mapping's name is that mapping's reason (the
    # reader refuses it without opening it), not the walk's first-found refusal alone.
    mapping_faults = _alert_input.settings_reasons(bound.under(SETTINGS_HALF))
    if mapping_faults:
        raise TenantRefused("; ".join(mapping_faults))
    for name in (SETTINGS_HALF, AGENT_HALF):
        _refuse_links_and_special_files(bound, folder, name)
    tenant_id_file = folder / TENANT_ID_FILE
    if tenant_id is None and _real_io.stat_entry(bound, TENANT_ID_FILE).absent:
        return
    claimed = read_tenant_id_file(tenant_id_file)
    if tenant_id is not None and claimed != tenant_id:
        raise TenantRefused(
            f"{tenant_id_file} names tenant {claimed!r}, not {tenant_id!r} — this knowledge "
            "folder is another tenant's")


def check_run_settings(settings: Path) -> None:
    """The settings rules a run holds its copy of an export's `settings/` to (#1108 P4): the
    `REQUIRED_SETTINGS` are plain files and the two mapping files stand — the refusals
    acceptance gives a tenant's own folder, each naming what to fix. `TenantRefused` at the
    first rule that fails. Reads only."""
    settings = Path(settings)
    with _real_io.bind(settings) as bound:
        for rel in REQUIRED_SETTINGS:
            _required_setting(_real_io.stat_entry(bound, rel), settings / rel)
        mapping_faults = _alert_input.settings_reasons(bound)
    if mapping_faults:
        raise TenantRefused("; ".join(mapping_faults))


def _required_setting(found: _real_io.StatRead, path: Path) -> None:
    if found.absent:
        raise TenantRefused(f"a required settings file is missing: {path}")
    if found.reason == _real_io.ALIAS_READ_REFUSAL:
        raise TenantRefused(
            f"a required settings file is reached through a link: {path} — a tenant's "
            "knowledge holds no links")
    if found.st is None:
        raise TenantRefused(f"{path} could not be checked: {found.reason}")
    if not stat.S_ISREG(found.st.st_mode):
        raise TenantRefused(f"a required settings file must be a regular file: {path}")


def _half(found: _real_io.StatRead, half: Path, name: str) -> None:
    if found.absent:
        raise TenantRefused(f"the knowledge folder has no {name}/ half: {half} is missing")
    if found.st is None:
        raise TenantRefused(f"{half} could not be checked: {found.reason}")
    if not stat.S_ISDIR(found.st.st_mode):
        raise TenantRefused(
            f"the knowledge folder's {name}/ half must be a real directory at {half}, never "
            "a link or a file")


def _refuse_links_and_special_files(bound: _real_io.Bound, folder: Path, half: str) -> None:
    """Refuse any symlink, hard-linked file, FIFO, socket or device inside one half, judged by
    a no-follow `stat` and never opened (a FIFO opened for reading would block). A directory
    the walk cannot list is refused too, since skipping it would hide what is below it."""
    # rejected: filesystem-portable hard-link detection — `st_nlink > 1` is the rule (N11).
    pending = [half]
    while pending:
        current = pending.pop()
        listed = _real_io.stat_entries(bound.under(current))
        if listed.stats is None:
            raise TenantRefused(f"{folder}/{shown(current)} could not be checked for links: "
                                f"{listed.reason or 'it vanished during the check'}")
        for name, st in sorted(listed.stats.items()):
            rel = f"{current}/{name}"
            entry = f"{folder}/{shown(rel)}"
            mode = st.st_mode
            if stat.S_ISLNK(mode):
                raise TenantRefused(
                    f"{entry} is a link — a tenant's knowledge holds no links: a link can "
                    "hand this tenant another's settings or knowledge")
            if stat.S_ISDIR(mode):
                pending.append(rel)
            elif not stat.S_ISREG(mode):
                raise TenantRefused(
                    f"{entry} is not a regular file or directory — a tenant's knowledge holds "
                    "no FIFOs, sockets or devices")
            elif _real_io.is_hard_linked(st):
                raise TenantRefused(
                    f"{entry} is a hard link ({st.st_nlink} names for one file) — its "
                    "bytes may be another tenant's")


#: The most a `.tenant-id` may hold: a 63-character id and a CRLF fit many times over, and an
#: oversize file is refused unread past this.
_TENANT_ID_FILE_MAX = 128


def read_tenant_id_file(path: Path) -> TenantId:
    """The id an `agent/.tenant-id` holds: exactly an id plus at most one LF or CRLF, read
    bounded, as UTF-8. Anything else — a BOM, a space, a second line, an empty file, a
    non-file, an oversize file — is `TenantRefused` naming the file.

    The byte reader and parser below also serve the read-back from the run box."""
    return parse_tenant_id_bytes(read_tenant_id_bytes(path), path)


def read_tenant_id_bytes(path: Path) -> bytes:
    """Read a marker without following a link, blocking on a FIFO, or exceeding its cap."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        raise TenantRefused(
            f"{path} is missing — a tenant's knowledge folder names its tenant there") from None
    except OSError as unreadable:
        raise TenantRefused(f"{path} could not be read: {unreadable}") from unreadable
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise TenantRefused(f"{path} must be a regular file holding the tenant id")
        data = os.read(fd, _TENANT_ID_FILE_MAX + 1)
    except OSError as unreadable:
        raise TenantRefused(f"{path} could not be read: {unreadable}") from unreadable
    finally:
        os.close(fd)
    if len(data) > _TENANT_ID_FILE_MAX:
        raise TenantRefused(
            f"{path} is larger than {_TENANT_ID_FILE_MAX} bytes — it holds only a tenant id")
    return data


def parse_tenant_id_bytes(data: bytes, path: Path) -> TenantId:
    """Judge marker bytes read on the host or read back through the run box.

    @owns tenant-id — exactly an id plus at most one LF or CRLF, bounded as UTF-8."""
    if len(data) > _TENANT_ID_FILE_MAX:
        raise TenantRefused(
            f"{path} is larger than {_TENANT_ID_FILE_MAX} bytes — it holds only a tenant id")
    for ending in (b"\r\n", b"\n"):
        if data.endswith(ending):
            data = data[: -len(ending)]
            break
    try:
        text = data.decode("utf-8")
        return TenantId(text)
    except (UnicodeDecodeError, TenantRefused):
        raise TenantRefused(
            f"{path} must hold exactly a tenant id and at most one line ending; it holds "
            f"{quoted(data)}") from None


def tenant_id_file_text(tenant_id: TenantId) -> str:
    """What `agent/.tenant-id` holds for `tenant_id`, as `read_tenant_id_file` reads it back:
    the id and one newline."""
    return f"{TenantId(tenant_id)}\n"


# ==========================================================================================
# The forge binding (#1108 P4): operator configuration in the row, never tenant content.
# ==========================================================================================

#: The row field holding the binding.
_FORGE_FIELD = "forge"
_FORGE_KEYS = ("origin", "audience", "issuer_role", "issuer_config")
#: An issuer role name: what `ForgejoIdentity` will accept, judged when the binding is read, so a
#: bad one is a refused binding before any login, never a login whose identity is then refused.
ISSUER_ROLE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}")


@dataclasses.dataclass(frozen=True)
class ForgeBinding:
    """Where the tenant's repository is served and how its delivery identity is minted: the
    repository's network `origin`, the Forgejo integration's `audience`, the issuer role
    that signs the tenant's tokens, and `issuer_config`, the absolute path of the operator's
    issuer client config file holding this tenant's AppRole login (P-4: a path, handed by
    the row, never the login material itself). Not secret."""

    origin: str
    audience: str
    issuer_role: str
    issuer_config: Path


def read_forge_binding(tenant: Tenant) -> ForgeBinding:
    """The tenant row's `forge: {origin, audience, issuer_role, issuer_config}`, read from the
    row file NOW (an operator may bind or re-bind after the tenant was accepted). Absent, any
    of the four missing or not a non-empty string, an `issuer_role` that is not a plain name,
    or an `issuer_config` that is not an absolute path, is `TenantRefused` naming the row."""
    path = _unwrap_tenant_root(tenant.tenant_root) / ROW_NAME
    try:
        with _real_io.bind(path.parent) as bound:
            answer = bound.read(ROW_NAME)
    except OSError as unreadable:
        raise TenantRefused(f"{path}: {unreadable}") from unreadable
    if answer.text is None:
        raise TenantRefused(f"{path}: {'absent' if answer.absent else answer.reason}")
    obj, bad_json = _real_io.load_json_artifact(answer.text)
    if bad_json is not None or not isinstance(obj, dict):
        raise TenantRefused(f"{path} is not a JSON object")
    forge = obj.get(_FORGE_FIELD)
    if forge is None:
        raise TenantRefused(
            f"{path} has no forge binding "
            "(`forge: {origin, audience, issuer_role, issuer_config}`): "
            "the tenant's repository is not bound to a forge")
    fields = forge if isinstance(forge, dict) else {}
    found = {key: fields.get(key) for key in _FORGE_KEYS}
    bad = [key for key, value in found.items() if not isinstance(value, str) or not value]
    if bad:
        raise TenantRefused(f"{path}'s forge binding lacks {', '.join(bad)}")
    if not ISSUER_ROLE.fullmatch(str(found["issuer_role"])):
        raise TenantRefused(f"{path}'s forge binding names an issuer_role that is not a plain "
                            "name (letters, digits, `_` and `-`, at most 128)")
    issuer_config = Path(str(found["issuer_config"]))
    if not issuer_config.is_absolute():
        raise TenantRefused(
            f"{path}'s forge binding names a relative issuer_config: it must be an absolute path")
    return ForgeBinding(origin=str(found["origin"]), audience=str(found["audience"]),
                        issuer_role=str(found["issuer_role"]), issuer_config=issuer_config)


# ==========================================================================================
# The row: create_tenant / require_tenant (D1, O2, O10).
# ==========================================================================================

def _now() -> str:
    return datetime.now(UTC).isoformat()


def create_tenant(root: DataRoot, tenant_id: TenantId) -> TenantRow:
    """Mint tenant_id's row exactly once, into a FRESH data root (O10: tenant 1 only). The
    folder is made and held by `hold_new` off the root's handle (F12: no raw mkdir here), which
    judges `<T>` with no link followed at mkdir time, closing an O11a-vs-write-time symlink swap;
    the row itself is created off that held folder through the core's complete-or-absent lane
    (J16/J63, #1137), never overwritten (O2, D1)."""
    paths = _TenantPaths(root, tenant_id)
    refuse_foreign_data_root(root, paths.tenant_id)
    root_path = _unwrap_data_root(root)
    row = TenantRow(tenant_id=paths.tenant_id, created_at=_now())
    body = json.dumps(
        {"tenant_id": row.tenant_id, "created_at": row.created_at}, indent=2, sort_keys=True,
    ) + "\n"
    try:
        held = _real_io.hold_new(root_path, paths.tenant_id)
    except OSError as blocked:
        raise TenantRefused(f"{paths.tenant_root}: {blocked}") from blocked
    # The close is inside the mapping, as `_read_row`'s is: a failing close is a refusal too.
    try:
        with held:
            held.write(ROW_NAME, body, mode="create")
    except FileExistsError as taken:
        raise TenantRefused(f"{paths.row} already exists — a tenant is created once") from taken
    except OSError as blocked:
        raise TenantRefused(f"{paths.row}: {blocked}") from blocked
    return row


def refuse_foreign_data_root(root: DataRoot, tenant_id: TenantId) -> None:
    """O10: a tenant is created only into a FRESH data root — one whose only entry, if any, is
    this tenant's own folder. While that folder has NO row it is an unfinished setup, and
    anything in it the setup protocol did not sanction is foreign too: the protocol sanctions
    exactly the NAME `knowledge` (the operator places the tenant's knowledge there before
    setup, MF1 — what it is, acceptance judges) and the row's own name (J60: an alias planted
    there is the guarded write's refusal to make, never this one's). Once the row exists the
    folder's other contents (runs/, sessions/) are the tenant's own business and never
    re-checked. Any OTHER entry at `root`, or any other id's folder however it is shaped, is
    always foreign. Refuses, naming what it found — or, when the root or the tenant's folder
    cannot be read, naming that; called both by `create_tenant` and, directly, by setup — so a
    caller that skips `create_tenant` on a re-run still meets it."""
    tenant_id = TenantId(tenant_id)  # before anything under `root` is named with it
    try:
        _refuse_foreign_entries(_unwrap_data_root(root), tenant_id)
    except OSError as unreadable:
        raise TenantRefused(
            f"the data root {_unwrap_data_root(root)} could not be checked for other tenants: {unreadable}",
        ) from unreadable


def _refuse_foreign_entries(root: Path, tenant_id: TenantId) -> None:
    if not root.is_dir():
        return
    entries = sorted(p.name for p in root.iterdir())
    foreign = [e for e in entries if e != tenant_id]
    if foreign:
        raise TenantRefused(
            f"the data root is not empty: {root} holds {foreign} — a tenant is created only "
            "into a fresh data root")
    own = root / tenant_id
    if own.is_dir() and not (own / ROW_NAME).exists():
        sanctioned = {ROW_NAME, "knowledge"}
        inside = [f"{tenant_id}/{name}" for name in sorted(p.name for p in own.iterdir())
                  if name not in sanctioned]
        if inside:
            raise TenantRefused(
                f"the data root is not empty: {root} holds {inside} — a tenant is created only "
                "into a fresh data root")


def require_tenant(root: DataRoot, tenant_id: TenantId) -> TenantRow:
    """`tenant_id`'s row, or the refusal: absent, corrupt (bad JSON, a non-object top level, an
    undecodable byte, a missing or non-string field), anything but a plain file at the row's
    name (a directory, a link live or dangling, a FIFO, a hard link: the core's alias refusal),
    or a row naming another tenant. Every refusal
    names the row's path."""
    return _read_row(_TenantPaths(root, tenant_id))


def _read_row(paths: _TenantPaths) -> TenantRow:
    # Read off `<T>`, its spelling followed as the folders above a path read's leaf are; the row
    # itself is opened no-follow and judged by the core (#1137). A reason never names a path.
    try:
        with _real_io.bind(paths.tenant_root) as bound:
            answer = bound.read(ROW_NAME)
    except OSError as unreadable:
        # Only the platform fault reaches here (no `O_PATH`, or a failing close): `bind` and
        # `read` answer every refused shape with a reason, handled below.
        raise TenantRefused(f"{paths.row}: {unreadable}") from unreadable
    text = answer.text
    if text is None:
        raise TenantRefused(f"{paths.row}: {'absent' if answer.absent else answer.reason}")
    row = _parse_json_record(text, TenantRow, _ROW_FIELDS, source=paths.row, refusal=TenantRefused)
    if row.tenant_id != paths.tenant_id:
        raise TenantRefused(f"{paths.row} names {row.tenant_id!r}, not {paths.tenant_id!r}")
    return row


# ==========================================================================================
# The data root (D2): typed selection and explicit owner comparisons/display.
# ==========================================================================================

def resolve_data_root() -> DataRoot:
    """The one path from `DEFENDER_DATA_ROOT` to an absolute, symlink-resolved root. No
    default: an unset or empty value is refused, naming the variable (settled by the user).
    Called once by an entry point; the root is handed inward from there. Learning state now
    belongs to the selected tenant below this root; there is no ambient state-root override."""
    raw = os.environ.get(_DATA_ROOT_ENV, "")
    if not raw:
        raise TenantRefused(f"{_DATA_ROOT_ENV} is not set — there is no default data root")
    root = Path(raw)
    if not root.is_absolute():
        raise TenantRefused(f"{_DATA_ROOT_ENV}={raw!r} must be an absolute path")
    resolved = _resolve_or_refuse(root)
    return data_root_from_path(resolved)


def data_root_from_path(path: Path) -> DataRoot:
    """Mark an explicit host-selected root; acceptance still performs every check."""
    return DataRoot(path)


def data_root_for_child(root: DataRoot) -> Path:
    """Explicit owner export of a configured root to a child process, which is handed
    identifiers only (the tenant id and this root, #1108 P4 O8) and accepts the tenant itself."""
    return _unwrap_data_root(root)
