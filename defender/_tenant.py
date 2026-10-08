"""Tenants: the tenant id, the one acceptance of a tenant, its row, and the runs-base record.

Every run names its tenant on the request; there is no default. `TenantId` is the one check
of an id. A tenant's tree is `<data root>/<T>/`: its row `tenant.json` (`create_tenant`,
`require_tenant`), its runs, sessions, episodes and learning state, and `knowledge/` — the
settings and agent halves the operator placed there (`_tenants`). `accept_tenant` is the ONE
function that accepts a tenant, and the only constructor of `Tenant`, the value every entry
point hands inward; `resolve_data_root` reads the required `DEFENDER_DATA_ROOT`, once per entry
point. Each runs base records the tenant it serves at `<runs_base>/_tenant.json`
(`ensure_runs_base_record`): created once, never overwritten, and a run for another tenant is
refused rather than stamped.

Both files are created complete-or-absent — the runs-base record through
`write_guarded(mode="create")`, the row off its held folder (`_io.hold_new`, `Held.write`) — so
a reader sees them absent or complete. Every refusal is a `TenantRefused` naming the refused value — an id, or the
content of an `agent/.tenant-id`, escaped and bounded (`_shown`); a path, operator-set, as it
is — which entry points catch and print verbatim; a corrupt record refuses the run rather than
reading as `None`. `refuse_colliding_run_id` keeps run ids off the record's filename.

Acceptance is a point-in-time check: a `Tenant` says the tree passed when it was accepted, not
that it still does.
"""
from __future__ import annotations

import dataclasses
import json
import os
import re
import stat
import uuid
from collections.abc import Iterable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar

from pydantic import ValidationError
from pydantic_core import core_schema

from defender import _io as _real_io
from defender import _paths
from defender._model import model
from defender._shown import escaped, quoted, shown
from defender._tenants import (
    AGENT_HALF,
    REQUIRED_SETTINGS,
    SETTINGS_HALF,
    TENANT_ID_FILE,
    TOP_LEVEL_ALLOWED,
)

_R = TypeVar("_R")

#: Lives under the runs base beside the run sidecars, at their trust level.
TENANT_RECORD_NAME = "_tenant.json"

#: The tenant's row, inside its own folder under the data root.
ROW_NAME = "tenant.json"

TENANT_FIELDS = ("tenant_id", "base_world_id", "created_at")
_ROW_FIELDS = ("tenant_id", "created_at")

#: The data-root knob (D2). Private: the design exports no public string constant from this
#: module (J05 — a public `str` here is an import-refused "record name" under
#: `lint_run_records`'s import arm).
_DATA_ROOT_ENV = "DEFENDER_DATA_ROOT"

#: The learning-state knob O13's widened refusal compares the data root against.
_LEARNING_STATE_ENV = "DEFENDER_LEARNING_STATE_DIR"

#: O3's grammar, matched with `re.fullmatch` (a `$`-anchored `re.match` would accept a trailing
#: newline — settled by the user).
_GRAMMAR = re.compile(r"^[a-z][a-z0-9-]{0,62}$")

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
    """A tenant id that has passed O3's grammar — the ONE place it is checked. Constructing one
    is the check: `TenantId(raw)` returns the id or raises `TenantRefused` naming `raw`, and a
    `TenantId` handed back in is returned as-is. It IS a `str` (paths, JSON, argv and log lines
    take it unchanged, and its repr is the string's), but a function that declares `TenantId`
    tells mypy a plain, unchecked `str` does not belong there. Entry points build one from the
    request; records and rows build one as they parse.

    The first custom pydantic type in this tree: `__get_pydantic_core_schema__` makes a
    `@model` field typed `TenantId` accept a string and run this constructor on it, so a
    record naming an off-grammar tenant is refused as it is read."""

    __slots__ = ()

    def __new__(cls, raw: object) -> TenantId:
        if isinstance(raw, TenantId):
            return raw
        if not isinstance(raw, str) or not _GRAMMAR.fullmatch(raw):
            raise TenantRefused(
                f"{quoted(raw)} is not a valid tenant id (must match {_GRAMMAR.pattern!r})")
        return super().__new__(cls, raw)

    @classmethod
    def __get_pydantic_core_schema__(cls, _source: Any, _handler: Any) -> Any:
        return core_schema.no_info_after_validator_function(cls, core_schema.str_schema())


@model(frozen=True)
class TenantRecord:
    tenant_id: TenantId
    base_world_id: str
    created_at: str


class TenantRecordCorrupt(TenantRefused):
    """The runs-base record fails to parse, lacks a required field, has one of the wrong type,
    or names an off-grammar tenant. Refuses the whole run rather than degrading."""


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


class TenantRecordMismatch(TenantRefused):
    """A runs base's record names another tenant than the one a run is for. The run refuses
    rather than stamp a record its settings did not come from."""


def record_path(runs_base: Path) -> Path:
    return Path(runs_base) / TENANT_RECORD_NAME


def _parse_json_record(
    text: str, record: type[_R], fields: tuple[str, ...], *, source: Path,
    refusal: type[TenantRefused],
) -> _R:
    """`text` as a `record` (the runs-base record or the tenant row), or `refusal` naming
    `source`. Keys beyond `fields` are ignored; `TenantId` checks the id as the field is set."""
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


def _parse_record(text: str, *, source: Path) -> TenantRecord:
    return _parse_json_record(
        text, TenantRecord, TENANT_FIELDS, source=source, refusal=TenantRecordCorrupt)


def _record_doc(record: TenantRecord) -> dict[str, Any]:
    return {
        "tenant_id": record.tenant_id, "base_world_id": record.base_world_id,
        "created_at": record.created_at,
    }


def read_tenant(runs_base: Path, *, io: Any = _real_io) -> TenantRecord:
    """The tenant record at `runs_base`; absent or corrupt raises `TenantRecordCorrupt`."""
    path = record_path(runs_base)
    text, reason = io.read_guarded(path)
    if text is None:
        raise TenantRecordCorrupt(f"{path} could not be read: {reason}")
    return _parse_record(text, source=path)


def refuse_colliding_run_id(run_id: str) -> Exception | None:
    """Explicit guard against a run id equal to the tenant record's filename. Without it only
    coincidences keep them apart (the leading underscore, the sidecar clear's keying, the
    runs-base walkers' `is_dir()` filter). Returns the refusal rather than raising; the caller
    (`materialize_run`) decides how to surface it."""
    if run_id == TENANT_RECORD_NAME:
        return ValueError(
            f"run id {run_id!r} collides with the tenant record's own filename "
            f"({TENANT_RECORD_NAME}) — refused before anything is created")
    return None


def ensure_runs_base_record(
    runs_base: Path, tenant_id: TenantId, *, io: Any = _real_io,
) -> TenantRecord:
    """Mint the runs-base record naming `tenant_id` when absent; read it back and hand it over
    when present and naming `tenant_id`; refuse when present and naming another tenant —
    never overwrite (D1, O6; §7 J16/J63's complete-or-absent creator).

    READ FIRST: every run after a base's first, and every sibling, finds the record there.
    The create is EXCLUSIVE, so a lost race re-reads the winner's record rather than trusting
    or overwriting ours; a name this process cannot read (an alias planted at it, a directory
    squatting it) refuses rather than being minted over."""
    tenant_id = TenantId(tenant_id)
    runs_base = Path(runs_base)
    path = record_path(runs_base)
    existing, _reason = io.read_guarded(path)
    if existing is not None:
        record = _parse_record(existing, source=path)
    else:
        record = TenantRecord(
            tenant_id=tenant_id, base_world_id=uuid.uuid4().hex, created_at=_now())
        body = json.dumps(_record_doc(record), indent=2, sort_keys=True) + "\n"
        try:
            io.write_guarded(path, body, mode="create")
        except FileExistsError:
            # Lost the race: the winner's record is the identity; ours is discarded unwritten.
            record = read_tenant(runs_base, io=io)
        except OSError as blocked:
            # An alias or a directory at the name, or this call's own failure (ENOSPC, EACCES):
            # the record cannot be created, and the run is refused naming it — never retried.
            raise TenantRefused(f"{path} could not be created: {blocked}") from blocked
    if record.tenant_id != tenant_id:
        raise TenantRefused(
            f"{path} names {record.tenant_id!r}, not {tenant_id!r} — ensure_runs_base_record "
            "never overwrites a disagreeing record")
    return record


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
        self.dir = tenant_dir

    @property
    def row(self) -> Path:
        return self.dir / ROW_NAME

    @property
    def runs(self) -> Path:
        return self.dir / "runs"

    @property
    def sessions(self) -> Path:
        return self.dir / "sessions"

    @property
    def episodes(self) -> Path:
        return self.dir / "episodes"

    @property
    def learning(self) -> Path:
        return self.dir / "learning"

    @property
    def worktrees(self) -> Path:
        return self.learning / "worktrees"

    @property
    def knowledge(self) -> Path:
        return self.dir / "knowledge"

    @property
    def settings(self) -> Path:
        return self.knowledge / SETTINGS_HALF

    @property
    def agent(self) -> Path:
        return self.knowledge / AGENT_HALF


class _TenantPaths(_TenantLayout):
    """The tenant's layout under a data root, guarded (M4). Private: the sites that need a
    tenant's locations before (or without) accepting it — acceptance itself (`accept_tenant`,
    setup's `accept_placed_knowledge`), `create_tenant`, `require_tenant`, `tenant_of_run_dir`
    — use it; everything after acceptance reads
    `Tenant`. Constructing one creates nothing, and carries the two guards every such site
    must meet first: the data root is absolute (J03), and the tenant's folder is not inside
    the running checkout's box-mounted `defender/` (O11a)."""

    def __init__(self, root: Path | str, tenant_id: str) -> None:
        #: The id, parsed: a plain string handed in is checked here (a `TenantId` passes as-is).
        self.tenant_id = TenantId(tenant_id)
        root = Path(root)
        _refuse_unusable_data_root(root)
        _refuse_inside_defender_tree(_resolve_or_refuse(root / self.tenant_id), root)
        super().__init__(root / self.tenant_id)


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
    ONLY by `accept_tenant`, and frozen. Its other members are its layout, as paths.

    A point-in-time value (M3): it says the tree passed acceptance when it was built."""

    id: TenantId
    data_root: Path
    row: TenantRow
    _token: dataclasses.InitVar[object]

    def __post_init__(self, _token: object) -> None:
        if _token is not _ACCEPTED:
            raise TenantRefused(
                "a Tenant is built only by accept_tenant — accept the tenant instead")

    @property
    def _layout(self) -> _TenantLayout:
        return _TenantLayout(self.data_root / self.id)

    @property
    def dir(self) -> Path:
        return self._layout.dir

    @property
    def row_path(self) -> Path:
        """The row FILE's path; `row` is the row itself."""
        return self._layout.row

    @property
    def runs(self) -> Path:
        return self._layout.runs

    @property
    def sessions(self) -> Path:
        return self._layout.sessions

    @property
    def episodes(self) -> Path:
        return self._layout.episodes

    @property
    def learning(self) -> Path:
        return self._layout.learning

    @property
    def worktrees(self) -> Path:
        return self._layout.worktrees

    @property
    def knowledge(self) -> Path:
        return self._layout.knowledge

    @property
    def settings(self) -> Path:
        return self._layout.settings

    @property
    def agent(self) -> Path:
        return self._layout.agent


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
    data_root: Path, raw_id: object, *, defender_dir: Path, box_mounted: Iterable[Path] = (),
) -> Tenant:
    """`raw_id` under `data_root`, checked whole — the ONE acceptance of a tenant, and the
    only constructor of `Tenant`. Refused with `TenantRefused` naming the refused value, at the
    FIRST check that fails, in this order:

      1. the id grammar (`TenantId`), before anything under the root is named;
      2. the root is absolute and outside the running checkout's `defender/` (the layout
         class's guards), then the row (`require_tenant`);
      3. `knowledge/` is a real directory at `<T>/knowledge`, reached without following `<T>`
         or itself, holding nothing at its top level outside `_tenants.TOP_LEVEL_ALLOWED`;
      4. its `settings/` and `agent/` halves, and `REQUIRED_SETTINGS`;
      5. no link and no special file inside either half (`knowledge/.git` is never walked: a
         local clone's objects are hard links);
      6. `agent/.tenant-id` holds this id;
      7. `settings/` lies outside `defender_dir`, the tenant's own `runs/` and every
         `box_mounted` tree — the settings half is host-only — and none of those trees lies
         inside either half, nor the runs base anywhere inside the knowledge folder, where a
         run's writes would become the tenant's knowledge or land in its repo. A path
         comparison: the halves' real paths are the data root's resolution joined below it
         (steps 3-5 saw no link there), against each tree's resolution.

    Reads only. The knowledge folder is walked through `_io.bind`'s no-follow reader, from the
    data root down, so no link below the root is followed there; the row is read off `<T>`
    (no-follow at the file itself), and step 7 judges `runs/` by where it leads. Any read a check cannot complete — an `OSError`, or a link
    loop where a path given to it is resolved — is the refusal, naming the path and the
    reason."""
    tenant_id = TenantId(raw_id)
    paths = _TenantPaths(data_root, tenant_id)
    row = _read_row(paths)
    _accept_knowledge(paths, defender_dir=defender_dir, box_mounted=box_mounted)
    return Tenant(id=tenant_id, data_root=Path(data_root), row=row, _token=_ACCEPTED)


def accept_placed_knowledge(
    data_root: Path, raw_id: object, *, defender_dir: Path, box_mounted: Iterable[Path] = (),
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


def _accept_knowledge(
    paths: _TenantPaths, *, defender_dir: Path, box_mounted: Iterable[Path],
) -> None:
    """Steps 3-7 of `accept_tenant` over an id and root its layout class already guarded.
    The knowledge folder is neither followed nor resolved: the walk opens `<T>` and
    `knowledge` no-follow off the root's handle, so a linked `<T>` or `knowledge` is refused,
    and the settings half's real path is then the root's own resolution joined below it.
    Both relative names come from the layout (`_TenantLayout`), never spelled here."""
    root = paths.dir.parent
    knowledge_name = paths.knowledge.relative_to(root).as_posix()
    with _real_io.bind(root) as bound:
        _knowledge_is_real(paths, _real_io.stat_entry(bound, knowledge_name))
        _check_knowledge(bound.under(knowledge_name), paths.knowledge,
                         tenant_id=paths.tenant_id)
    root_real = _resolve_or_refuse(root)
    settings_real = root_real / paths.settings.relative_to(root)
    halves_real = (settings_real, root_real / paths.agent.relative_to(root))
    knowledge_real = root_real / paths.knowledge.relative_to(root)
    for mounted in (Path(defender_dir), paths.runs, *(Path(m) for m in box_mounted)):
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
            f"directory, never a link or a file, under an unlinked {paths.dir}: {why}")


def check_knowledge_folder(folder: Path, *, tenant_id: TenantId | None) -> None:
    """The folder rules — everything about a knowledge folder that needs no data root: its top
    level holds only `TOP_LEVEL_ALLOWED`; its `settings/` and `agent/` halves are real
    directories inside it; `REQUIRED_SETTINGS` are files; neither half holds a link or a
    special file; and `agent/.tenant-id` reads as `tenant_id`. With `tenant_id` None (a tenant
    repo checked on its own, `tenant.py check --folder`, CI's census lint) the file may be
    absent, and is held only to the id grammar when present. Raises `TenantRefused` naming the
    path at the first rule that fails. Reads only, and opens no file but `.tenant-id`.

    `folder` itself is opened as spelled (the operator's own path, a link to it included); the
    walk below it follows nothing. `.tenant-id` is then opened by its path, no-follow at the
    file itself, once the walk has seen `agent/` as a real directory."""
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

    @owns tenant-id — the `agent/.tenant-id` file's content, read here and nowhere else."""
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
# The row: create_tenant / require_tenant (D1, O2, O10).
# ==========================================================================================

def _now() -> str:
    return datetime.now(UTC).isoformat()


def create_tenant(root: Path, tenant_id: TenantId) -> TenantRow:
    """Mint tenant_id's row exactly once, into a FRESH data root (O10: tenant 1 only). The
    folder is made and held by `hold_new` off the root's handle (F12: no raw mkdir here), which
    judges `<T>` with no link followed at mkdir time, closing an O11a-vs-write-time symlink swap;
    the row itself is created off that held folder through the core's complete-or-absent lane
    (J16/J63, #1137), never overwritten (O2, D1)."""
    paths = _TenantPaths(root, tenant_id)
    root = Path(root)
    refuse_foreign_data_root(root, paths.tenant_id)
    try:
        held = _real_io.hold_new(root, paths.tenant_id)
    except OSError as blocked:
        raise TenantRefused(f"{paths.dir}: {blocked}") from blocked
    row = TenantRow(tenant_id=paths.tenant_id, created_at=_now())
    body = json.dumps(
        {"tenant_id": row.tenant_id, "created_at": row.created_at}, indent=2, sort_keys=True,
    ) + "\n"
    with held:
        try:
            held.write(ROW_NAME, body, mode="create")
        except FileExistsError as taken:
            raise TenantRefused(
                f"{paths.row} already exists — a tenant is created once") from taken
        except OSError as blocked:
            raise TenantRefused(f"{paths.row}: {blocked}") from blocked
    return row


def refuse_foreign_data_root(root: Path, tenant_id: TenantId) -> None:
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
        _refuse_foreign_entries(root, tenant_id)
    except OSError as unreadable:
        raise TenantRefused(
            f"the data root {root} could not be checked for other tenants: {unreadable}",
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


def require_tenant(root: Path, tenant_id: TenantId) -> TenantRow:
    """`tenant_id`'s row, or the refusal: absent, corrupt (bad JSON, a non-object top level, an
    undecodable byte, a missing or non-string field), a directory or dangling link at the row's
    name (folded as corrupt/absent, §7 J22), or a row naming another tenant. Every refusal
    names the row's path."""
    return _read_row(_TenantPaths(root, tenant_id))


def _read_row(paths: _TenantPaths) -> TenantRow:
    # Read off `<T>`, its spelling followed as the folders above a path read's leaf are; the row
    # itself is opened no-follow and judged by the core (#1137). A reason never names a path.
    try:
        with _real_io.bind(paths.dir) as bound:
            answer = bound.read(ROW_NAME)
    except OSError as unreadable:
        raise TenantRefused(f"{paths.row}: {unreadable}") from unreadable
    text = answer.text
    if text is None:
        raise TenantRefused(f"{paths.row}: {'absent' if answer.absent else answer.reason}")
    row = _parse_json_record(text, TenantRow, _ROW_FIELDS, source=paths.row, refusal=TenantRefused)
    if row.tenant_id != paths.tenant_id:
        raise TenantRefused(f"{paths.row} names {row.tenant_id!r}, not {paths.tenant_id!r}")
    return row


# ==========================================================================================
# The data root (D2) and runs_base_for.
# ==========================================================================================

def resolve_data_root() -> Path:
    """The one path from `DEFENDER_DATA_ROOT` to an absolute, symlink-resolved root. No
    default: an unset or empty value is refused, naming the variable (settled by the user).
    Carries O13's widened learning-state-overlap refusal (moved here by fork J24: it must run
    wherever the data root resolves, siblings included). Called ONCE, by an entry point; the
    root is handed inward from there."""
    raw = os.environ.get(_DATA_ROOT_ENV, "")
    if not raw:
        raise TenantRefused(f"{_DATA_ROOT_ENV} is not set — there is no default data root")
    root = Path(raw)
    if not root.is_absolute():
        raise TenantRefused(f"{_DATA_ROOT_ENV}={raw!r} must be an absolute path")
    resolved = _resolve_or_refuse(root)
    _refuse_widened_learning_state_overlap(resolved)
    return resolved


def _refuse_widened_learning_state_overlap(data_root: Path) -> None:
    raw = os.environ.get(_LEARNING_STATE_ENV)
    if not raw:
        return
    learning = _resolve_or_refuse(Path(raw))
    if learning == data_root or data_root in learning.parents or learning in data_root.parents:
        raise TenantRefused(
            f"{_LEARNING_STATE_ENV}={learning} overlaps the data root {data_root} — learning "
            "state and tenant data must not share a tree")


def runs_base_for(tenant: Tenant) -> Path:
    """The accepted tenant's runs base, `<root>/<tenant>/runs`."""
    return tenant.runs


def tenant_of_run_dir(data_root: Path, run_dir: Path) -> TenantId:
    """The tenant a run dir belongs to, learned from its source's HOST-ONLY runs-base record
    (never a stamp a box can write): the record at `run_dir.parent`, refused unless
    `run_dir.parent` resolves to that tenant's runs base under `data_root` — a run dir left
    over from before its tenant's current data root, or under an unrelated tree, is refused
    rather than silently trusted. The data root is guarded before the record is read."""
    data_root = Path(data_root)
    _refuse_unusable_data_root(data_root)
    run_dir = Path(run_dir)
    runs_base = run_dir.parent
    record = read_tenant(runs_base)
    expected = _TenantPaths(data_root, record.tenant_id).runs
    if _resolve_or_refuse(runs_base) != _resolve_or_refuse(expected):
        raise TenantRefused(
            f"{runs_base} does not match the current runs base for tenant "
            f"{record.tenant_id!r} ({expected}) — refusing a run directory outside its "
            "tenant's own tree")
    require_tenant(data_root, record.tenant_id)
    return record.tenant_id
