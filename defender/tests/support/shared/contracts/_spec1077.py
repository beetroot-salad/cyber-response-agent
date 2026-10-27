"""Shared machinery for #1077's run-handle spec — NO test scripts."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_runs_base

from defender.tests.support.shared._fixture_uuid import fixture_uuid

import dataclasses
import hashlib
import inspect
import json
import os
import subprocess
from collections.abc import Callable, Iterable
from pathlib import Path, PurePosixPath
from typing import Any

from defender.tests.support.learning.branch import _triplet_947 as T
from defender import records as _records_door

mod = T.mod
sym = T.sym

REPO_ROOT = Path(__file__).resolve().parents[5]
DEFENDER = REPO_ROOT / "defender"
KINDS_TSV = DEFENDER / "docs" / "run-records-kinds.tsv"
PAGE = DEFENDER / "docs" / "run-records.md"


# ======================================================================================
# The coined module names. ONE place, so a rename is one edit.
# ======================================================================================

HANDLE_MODULE = "records._handle"
TENANT_MODULE = "tenancy._tenant"
EPISODE_MODULE = "records._episode_paths"
#: The owner modules by path under `defender/`: `records/`'s door and every submodule its `_HOMES`
#: map serves (a module the door gains is an owner without a list edit; the record-format modules
#: beside them are not), then the owners outside the door.
RUN_REPOSITORY_FILES = tuple(sorted(
    f"records/{m}.py" for m in {"__init__", *_records_door._HOMES.values()}))
OWNER_MODULE_FILES = (*RUN_REPOSITORY_FILES, "records/_episode_paths.py", "records/_episode_handle.py", "tenancy/_tenant.py")


def handle() -> Any:
    """`defender/records/_handle.py` — `Run`, `RunRecord`, `RecordHandle`, `ArchivedWorld`."""
    return mod(HANDLE_MODULE)


def tenant() -> Any:
    """`defender/tenancy/_tenant.py` — the tenant record's owner."""
    return mod(TENANT_MODULE)


def episode_paths() -> Any:
    """`defender/records/_episode_paths.py::EpisodePaths` — the episode layout's owner."""
    return mod(EPISODE_MODULE)


def run_paths_mod() -> Any:
    return mod("records._layout")


def RunPaths(run_dir: Path) -> Any:  # noqa: N802 — it is the class's own name
    return run_paths_mod().RunPaths(run_dir)


def EpisodePaths(episode_dir: Path) -> Any:  # noqa: N802
    return episode_paths().EpisodePaths(episode_dir)


def Run() -> Any:  # noqa: N802
    return handle().Run


def ArchivedWorld() -> Any:  # noqa: N802
    return handle().ArchivedWorld


def RecordHandle() -> Any:  # noqa: N802
    return handle().RecordHandle


def RunRecord() -> Any:  # noqa: N802
    return handle().RunRecord


def io() -> Any:
    return mod("_io")


def provenance_mod() -> Any:
    return mod("records._provenance")


def run_common() -> Any:
    return mod("run_common")


def branch_cli() -> Any:
    return mod("learning.branch.cli")


# ======================================================================================
# The tenant record and the grouped surface: the vocabulary the tests assert against.
# ======================================================================================

#: The retired runs-folder tenant record: no runs folder holds one now (a listing that meets one
#: refuses), so this names the OLD entry a test plants or censuses.
TENANT_RECORD_NAME = "_tenant.json"

#: The tenant a fresh runs base belongs to (the committed `playground` tenant): a bootstrap
#: default, NOT an enforced constant.
DEFAULT_TENANT_ID = fixture_uuid("tenant:playground")

#: Five group-named sub-collections, addressed group-then-kind.
GROUPS = ("tables", "facts", "documents", "observability", "session")

#: The group table, as member accessor names per group (`run.tables.queries`).
GROUP_MEMBERS: dict[str, tuple[str, ...]] = {
    "tables": ("queries", "policy_denials", "leads", "payloads", "ticket_reads"),
    "facts": ("alert", "alert_record", "provenance", "run_end", "scrub_verdict"),
    "documents": ("investigation", "report", "gather_summaries", "lead_author"),
    "observability": (
        "wire_log", "review_trace", "tool_trace", "review_record",
        "lessons_loaded", "ticket_write", "runtime_html", "box_sentinel", "session_pointer"),
    "session": ("session_db",),
}

#: The owner accessor behind each member: what `RecordHandle.path` must equal and which seam the
#: writer method must reach.
MEMBER_ACCESSOR: dict[str, str] = {
    "queries": "executed_queries", "policy_denials": "policy_denials", "leads": "lead_claim",
    "payloads": "payload", "ticket_reads": "ticket_read",
    "alert": "alert", "alert_record": "alert_record", "provenance": "provenance", "run_end": "run_end_sidecar",
    "scrub_verdict": "scrub_verdict",
    "investigation": "investigation", "report": "report",
    "gather_summaries": "gather_summary", "lead_author": "lead_author",
    "wire_log": "wire_log", "review_trace": "review_trace",
    "tool_trace": "tool_trace",
    "review_record": "review_record", "lessons_loaded": "lessons_loaded",
    "ticket_write": "ticket_write", "runtime_html": "runtime_html",
    "box_sentinel": "box_sentinel", "session_pointer": "session_pointer",
    "session_db": "session_db",
}

#: Each record's writer verb, PER RECORD rather than per group (a group-wide verb would hand the
#: session db a JSONL `append`): `append` for a JSONL table or trace, `write` for a whole document
#: or write-once fact, `open` for the session store, `None` where nothing in the host writes
#: through the handle. The spec side of `defender.records._handle.MEMBER_VERB`.
MEMBER_VERB: dict[str, str | None] = {
    "queries": "append", "policy_denials": "append", "leads": "write", "payloads": "write",
    "ticket_reads": "write",
    "alert": "write", "alert_record": "write", "provenance": "write", "run_end": "write", "scrub_verdict": "write",
    "investigation": "write", "report": "write", "gather_summaries": "write",
    "lead_author": None,
    "wire_log": "append", "review_trace": "append",
    "tool_trace": "append", "review_record": "write", "lessons_loaded": "append",
    "ticket_write": "write",
    "runtime_html": "write", "box_sentinel": "write", "session_pointer": "write",
    "session_db": "open",
}
# `MEMBER_VERB` is compatibility metadata; these are the operations each record actually
# supports (encoded telemetry uses `append_text`, without JSON re-encoding).
MEMBER_CAPABILITIES: dict[str, frozenset[str]] = {
    name: frozenset({verb}) if verb is not None else frozenset()
    for name, verb in MEMBER_VERB.items()
}
MEMBER_CAPABILITIES.update({
    "payloads": frozenset({"write", "ensure_parent"}),
    "gather_summaries": frozenset({"write", "ensure_parent"}),
    "alert_record": frozenset({"write", "replace"}),
    "queries": frozenset({"append", "seed"}),
    "policy_denials": frozenset({"append_text", "start_stream"}),
    "investigation": frozenset({"write", "seed"}),
    "wire_log": frozenset({"append_text", "start_stream"}),
    "review_trace": frozenset({"append_text"}),
    "ticket_write": frozenset({"write", "delete"}),
})
VERBS = ("write", "append", "update", "open", "append_text", "start_stream", "create", "seed", "delete", "replace", "ensure_parent")

#: The archive's copied set, as `ArchivedWorld` accessor names.
ARCHIVED_WORLD_MEMBERS = (
    "report", "investigation", "provenance", "scrub_verdict", "run_end", "lessons_loaded",
    "alert", "gather_summaries", "executed_queries", "gather_raw")


# ======================================================================================
# The kinds table: the walk reads each EXPECTED NAME off the TSV; this map says which run or
# episode accessor owns each row.
# ======================================================================================

@dataclasses.dataclass(frozen=True)
class Accessor:
    """One row of the kinds table and the single accessor that owns its name.

    `owner` is "run" (`RunPaths`) or "episode" (`EpisodePaths`); `attr` is the accessor's name on
    that owner; `args` are the components a composing accessor takes, in call order, as the
    concrete values this suite drives it with.
    """
    kind: str
    owner: str
    attr: str
    args: tuple[Any, ...] = ()
    composing: bool = False


LEAD_ID = "l-abc123"
SEQ = 7
TURN = 3
ROLE = "support"
#: Descriptive metadata is kept separate from the world's storage identity.
LABEL = "overlay_a"
#: The fixture episode's opaque identity.
EPISODE_ID = "1d7e3c5b-2a4f-4b6c-9e8d-7f6a5b4c3d2e"
LINEAGE_ID = "case-0011223344556677"
WORLD_ID = fixture_uuid("world:overlay_a")
#: The fixture run's id (a UUID, all `RunId` admits): the name `make_run_dir` gives a run folder
#: by default.
RUN_ID = "5e8f1a2b-3c4d-4e5f-a6b7-c8d9e0f1a2b3"


def report_text(body: str) -> str:
    """A `report.md` that MEETS its schema (a frontmatter fence carrying a `disposition`): the
    handle refuses a fence-less one at the write, as `permission.decide_write` does."""
    return f"---\ndisposition: inconclusive\n---\n{body}"
STAGE = "questioner"

ACCESSOR_FOR_KIND: tuple[Accessor, ...] = (
    Accessor("alert", "run", "alert"),
    Accessor("report", "run", "report"),
    Accessor("investigation", "run", "investigation"),
    Accessor("queries", "run", "executed_queries"),
    Accessor("gather_raw", "run", "payload", (LEAD_ID, SEQ), composing=True),
    Accessor("lead_claim", "run", "lead_claim", (LEAD_ID,), composing=True),
    Accessor("gather_summaries", "run", "gather_summary", (LEAD_ID,), composing=True),
    Accessor("lead_author", "run", "lead_author"),
    Accessor("wire_log", "run", "wire_log"),
    Accessor("review_trace", "run", "review_trace", (ROLE,), composing=True),
    Accessor("review_record", "run", "review_record", (TURN,), composing=True),
    Accessor("tool_trace", "run", "tool_trace"),
    Accessor("policy_denials", "run", "policy_denials"),
    Accessor("lessons_loaded", "run", "lessons_loaded"),
    Accessor("ticket_write", "run", "ticket_write"),
    Accessor("ticket_reads", "run", "ticket_read", (SEQ,), composing=True),
    Accessor("session_pointer", "run", "session_pointer"),
    # Two host-only JSONL sidecars beside the run folder (`JSONL_SIDECAR_ACCESSORS`).
    Accessor("call_join", "run", "call_join"),
    Accessor("ticket_comments", "run", "ticket_comments"),
    Accessor("runtime_html", "run", "runtime_html"),
    Accessor("box_sentinel", "run", "box_sentinel"),
    Accessor("provenance", "run", "provenance"),
    Accessor("run_end", "run", "run_end_sidecar"),
    Accessor("scrub_verdict", "run", "scrub_verdict"),
    Accessor("session_db", "run", "session_db", (LINEAGE_ID,), composing=True),
    Accessor("family", "episode", "family"),
    Accessor("family_stamp", "episode", "family_stamp"),
    Accessor("review_yaml", "episode", "review"),
    Accessor("samples", "episode", "samples"),
    Accessor("judge_yaml", "episode", "judge"),
    Accessor("judge_draw", "episode", "judge_draw", (WORLD_ID, 1), composing=True),
    Accessor("timing", "episode", "timing"),
    Accessor("staged", "episode", "staged"),
    Accessor("served", "episode", "served_base"),
    Accessor("priming_lock", "episode", "priming_lock"),
    Accessor("stage_trace", "episode", "stage_trace", (STAGE,), composing=True),
    Accessor("learning_html", "episode", "learning_html"),
    Accessor("archive_proj", "episode", "world_dir", (WORLD_ID,), composing=True),
    # The host-written arm roster, named by `_episode_paths.LAYOUT`.
    Accessor("arm_roster", "episode", "arm_roster"),
)

#: The UPWARD accessors: their root is the runs base, not the run directory (`session_db`'s is
#: the sessions directory, a sibling of the runs base).
SIDECAR_ACCESSORS = ("run_end_sidecar", "scrub_verdict", "ticket_write", "session_pointer")
#: Two more host-only records beside the run folder, keyed by run id: the call join and the
#: ticket comments. UPWARD like the four above, but JSONL logs, so kept out of
#: `SIDECAR_ACCESSORS` (whose members `test_1077_tree_identity` parses as whole JSON documents).
JSONL_SIDECAR_ACCESSORS = ("call_join", "ticket_comments")
UPWARD_ACCESSORS = (*SIDECAR_ACCESSORS, *JSONL_SIDECAR_ACCESSORS, "sessions_dir", "session_db")


def upward_root(attr: str, runs_base: Path) -> Path:
    """The root an UPWARD accessor is confined to: the runs base for the sidecars, its parent
    for the sessions directory (`<runs_base>/../sessions`) and the session db."""
    return runs_base.parent if attr in ("sessions_dir", "session_db") else runs_base

#: Every accessor that builds a path from a caller-supplied component, with an ordinary value.
COMPOSING = tuple(a for a in ACCESSOR_FOR_KIND if a.composing) + (
    Accessor("served", "episode", "served_world", (WORLD_ID,), composing=True),
    Accessor("gather_raw", "run", "payload_relpath", (LEAD_ID, SEQ), composing=True),
)

def kinds_rows() -> list[dict[str, str]]:
    """The kinds table as dicts, read off the file the gate reads."""
    lines = KINDS_TSV.read_text(encoding="utf-8").splitlines()
    header = lines[0].split("\t")
    return [dict(zip(header, line.split("\t"), strict=False)) for line in lines[1:] if line.strip()]


def resolve(acc: Accessor, *, run_dir: Path, runs_base: Path | None = None,
            episode_dir: Path | None = None, args: tuple[Any, ...] | None = None) -> Path:
    """Drive ONE accessor and hand back the path it resolved. Each owner is built through its
    own constructor every time, so walking the kinds table drives every real accessor."""
    values = acc.args if args is None else args
    owner = RunPaths(run_dir) if acc.owner == "run" else EpisodePaths(episode_dir)
    member = getattr(owner, acc.attr)
    if acc.attr in UPWARD_ACCESSORS:
        return member(fixture_runs_base(runs_base), *values) if values else member(fixture_runs_base(runs_base))
    return member(*values) if values else member


# ======================================================================================
# Filesystem scaffolding — real trees, planted here, re-probed every run.
# ======================================================================================

def member(run: Any, group: str, name: str, *args: Any) -> Any:
    """`run.<group>.<name>` — the `RecordHandle` that member answers.

    A composed kind is CALLED with its caller-supplied components; a plain one is read as an
    attribute. Everything goes through the real handle, so this is a drive, not a lookup.
    """
    m = getattr(getattr(run, group), name)
    return m(*args) if args else m


def member_args(name: str) -> tuple[Any, ...]:
    """The components this suite drives one member with, in call order."""
    table: dict[str, tuple[Any, ...]] = {
        "leads": (LEAD_ID,), "payloads": (LEAD_ID, SEQ), "ticket_reads": (SEQ,),
        "gather_summaries": (LEAD_ID,), "review_trace": (ROLE,), "review_record": (TURN,),
        "session_db": (LINEAGE_ID,),
    }
    return table.get(name, ())


def fixture_run(directory: Path) -> Any:
    """A fixture's real Run, including its sidecar root, built without reading the tree."""
    from defender.tests.support.shared._fixture_uuid import is_fixture_uuid_shape

    directory = Path(directory)
    if not is_fixture_uuid_shape(directory.name):
        raise AssertionError(
            f"fixture_run({directory}): a run folder's name is its canonical UUID run id "
            "(#1187) — make the folder at fixture_uuid(<label>) where it is created")
    return Run().under(fixture_runs_base(directory.parent), directory.name)


def make_runs_base(tmp_path: Path) -> Path:
    base = tmp_path / "runs"
    base.mkdir(parents=True, exist_ok=True)
    return base


def make_run_dir(runs_base: Path, run_id: str = RUN_ID) -> Path:
    d = runs_base / run_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def make_episode_dir(tmp_path: Path) -> Path:
    d = tmp_path / "episodes" / EPISODE_ID
    d.mkdir(parents=True, exist_ok=True)
    return d


def plant_tenant_record(runs_base: Path, body: str | bytes | None = None, *,
                        tenant_id: str = DEFAULT_TENANT_ID,
                        base_world_id: str = "0123456789abcdef0123456789abcdef",
                        created_at: str = "2026-09-21T00:00:00Z",
                        drop: str | None = None, wrong_type: str | None = None) -> Path:
    """Write `<runs_base>/_tenant.json` — well-formed, or with a REAL corruption on disk.

    `body` writes raw bytes verbatim (the malformed-JSON, empty-file and truncated cases);
    `drop` removes a required field; `wrong_type` replaces one with a number.
    """
    path = runs_base / TENANT_RECORD_NAME
    if body is not None:
        path.write_bytes(body.encode("utf-8") if isinstance(body, str) else body)
        return path
    obj: dict[str, Any] = {
        "tenant_id": tenant_id, "base_world_id": base_world_id, "created_at": created_at}
    if drop is not None:
        obj.pop(drop)
    if wrong_type is not None:
        obj[wrong_type] = 17
    path.write_text(json.dumps(obj, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def plant_stamp(run_dir: Path, **fields: Any) -> Path:
    """A `provenance.json` with exactly the keys given, including a MISSING or explicitly-null
    `tenant_id`/`world_id`."""
    path = run_dir / "provenance.json"
    path.write_text(json.dumps(fields, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def seed_run_tree(run_dir: Path) -> Path:
    """The minimum a fixture run dir carries: an alert and the gather-raw directory."""
    (run_dir / "gather_raw").mkdir(parents=True, exist_ok=True)
    (run_dir / "alert.json").write_text('{"alert": "seed"}\n', encoding="utf-8")
    return run_dir


# ======================================================================================
# The tree observer: one run directory's name set against a captured baseline.
#
#   `snapshot` / `tree_diff`: the SAME SET OF NAMES, each with its kind (and a symlink's
#   target); no bytes at all. Files carry timestamps, per-run salts and random ids, so there
#   is deliberately no exemption list and no `exclude` argument.
#   `capture_baseline` also records the digests of `investigation.md` and `report.md`
#   (`content_digests`); no test compares them now.
# ======================================================================================

@dataclasses.dataclass(frozen=True)
class Entry:
    """One tree entry: its name and kind, nothing it contains. `target` is a symlink's link
    target and `None` otherwise."""
    rel: str
    kind: str                # "file" | "dir" | "symlink"
    target: str | None       # the link's target for a symlink; None otherwise


def snapshot(root: Path) -> dict[str, Entry]:
    """The structural snapshot of one tree: every entry by relative name, with no exemption."""
    out: dict[str, Entry] = {}
    for p in sorted(root.rglob("*")):
        rel = p.relative_to(root).as_posix()
        if p.is_symlink():
            out[rel] = Entry(rel, "symlink", os.readlink(p))
        elif p.is_dir():
            out[rel] = Entry(rel, "dir", None)
        else:
            out[rel] = Entry(rel, "file", None)
    return out


def tree_diff(a: dict[str, Entry], b: dict[str, Entry]) -> list[str]:
    """The structural observer's findings: a name in one tree and not the other, or an entry
    whose KIND (or, for a symlink, whose link target) changed."""
    findings = []
    for rel in sorted(set(a) | set(b)):
        if rel not in b:
            findings.append(f"only in the baseline: {rel}")
        elif rel not in a:
            findings.append(f"only in the comparison: {rel}")
        elif a[rel] != b[rel]:
            findings.append(f"differs: {rel}")
    return findings


#: The two documents whose digests `capture_baseline` records.
O3_CONTENT = ("investigation.md", "report.md")


def content_digests(root: Path) -> dict[str, str | None]:
    """The sha256 of each `O3_CONTENT` file's bytes, `None` where the run produced no such
    file."""
    out: dict[str, str | None] = {}
    for name in O3_CONTENT:
        p = root / name
        out[name] = hashlib.sha256(p.read_bytes()).hexdigest() if p.is_file() else None
    return out


def mutation_census(root: Path) -> dict[str, tuple[str, str | None]]:
    """Every entry AND every regular file's bytes: the before/after census a read-purity test
    needs. Separate from `snapshot`: one tree compared to itself across one operation has
    stable bytes; two runs do not.
    """
    out: dict[str, tuple[str, str | None]] = {}
    for rel, e in snapshot(root).items():
        p = root / rel
        if e.kind == "file":
            out[rel] = ("file", hashlib.sha256(p.read_bytes()).hexdigest())
        else:
            out[rel] = (e.kind, e.target)
    return out


#: The baseline is a GOLDEN like `tests/e2e/test_replay_skeleton.py`'s: re-captured with
#: `capture_baseline` when the tree is meant to change, and the re-capture reviewed as a diff. Its
#: `commit` field is for the reader only (a committed file cannot carry the sha of the commit
#: that contains it).
TREE_BASELINE = Path(__file__).with_name("_tree_baseline_1077.json")


def head_commit() -> str:
    """The commit the capture runs on, through `defender._git.git_head_sha`: a second
    `rev-parse` here would be the shared-oracle shape `tooling/lint/lint_shared_oracle.py` flags.
    """
    return mod("_git").git_head_sha(REPO_ROOT)


def load_baseline() -> dict[str, Any]:
    """The captured baseline: `commit` (informational), the structural `entries` and the two
    `content` digests."""
    return json.loads(TREE_BASELINE.read_text(encoding="utf-8"))


def baseline_entries(doc: dict[str, Any]) -> dict[str, Entry]:
    return {rel: Entry(rel, kind, target) for rel, (kind, target) in doc["entries"].items()}


def capture_baseline(run_dir: Path, *, path: Path = TREE_BASELINE) -> dict[str, Any]:
    """Write the tree baseline for `run_dir`: the whole name set, the two documents' bytes, and
    the commit it was taken on."""
    doc = {
        "commit": head_commit(),
        "entries": {rel: [e.kind, e.target] for rel, e in snapshot(run_dir).items()},
        "content": content_digests(run_dir),
    }
    path.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return doc


def structural_findings(run_dir: Path, doc: dict[str, Any]) -> list[str]:
    """The run directory's name set against the baseline's, in full."""
    return tree_diff(baseline_entries(doc), snapshot(run_dir))


# ======================================================================================
# The `_io` recorder / fault injector — one fake, driven by a data fault-spec, injecting only.
# ======================================================================================

@dataclasses.dataclass(frozen=True)
class IoFault:
    """A declarative fault-spec for `RecordingIo`. The fake classifies nothing and decides no
    policy: it raises what it is told to raise, where it is told to raise it."""
    fail_on: tuple[str, ...] = ()
    error: BaseException | None = None
    raise_after: int = 0
    before_write: Callable[[Path], None] | None = None


def bound_arguments(op: str, args: tuple, kwargs: dict) -> dict[str, Any]:
    """One recorded `_io` call's arguments BY NAME, bound against the real function's own
    signature with its defaults applied — so a positional and a keyword spelling of the same
    call read the same, and a seam test asserts on `root` / `name` / `mode` / `text` rather than
    on argument positions."""
    bound = inspect.signature(getattr(io(), op)).bind(*args, **kwargs)
    bound.apply_defaults()
    return dict(bound.arguments)


#: The `_io` calls `IoFault.before_write` fires before.
_WRITE_OPS = frozenset({"write_guarded", "write_atomic", "rooted_write",
                        "rooted_locked_for_rewrite"})


def _recorded_path(op: str, args: tuple, kwargs: dict) -> Path:
    """The path one `_io` call is about: a rooted call's trust root joined with the name (or
    folder) under it, else the call's first argument."""
    if op.startswith("rooted_"):
        b = bound_arguments(op, args, kwargs)
        return Path(b["root"]) / PurePosixPath(b.get("name", b.get("folder_name")))
    first = args[0] if args else next(iter(kwargs.values()))
    # An op over an already-open record (`locked_json_update` takes the opener) is about no path
    # of its own; the opener's own call carries the record's path.
    return Path(first) if isinstance(first, (str, os.PathLike)) else Path()


class RecordingIo:
    """A pass-through recorder over the real `defender._io`, entering through the owner's
    `io=` injection seam (never `monkeypatch.setattr`).

    `calls` keeps each call's path (a rooted call's trust root joined with its name);
    `invocations` keeps every argument, where a seam test reads a rooted call's name, mode and
    payload.
    """

    def __init__(self, fault: IoFault | None = None) -> None:
        self.fault = fault or IoFault()
        self.calls: list[tuple[str, Path]] = []
        self.invocations: list[tuple[str, tuple, dict]] = []
        self._real = io()

    @property
    def ops(self) -> list[str]:
        return [name for name, _ in self.calls]

    def arguments(self, op: str) -> list[dict[str, Any]]:
        """Every recorded call of `op`, in order, its arguments bound by name."""
        return [bound_arguments(name, a, kw) for name, a, kw in self.invocations if name == op]

    def _dispatch(self, name: str):
        real = getattr(self._real, name)

        def call(*a, **kw):
            path = _recorded_path(name, a, kw)
            self.calls.append((name, path))
            self.invocations.append((name, a, dict(kw)))
            prior = sum(1 for n, _ in self.calls[:-1] if n == name)
            if name in self.fault.fail_on and self.fault.raise_after <= prior:
                    raise self.fault.error or FileExistsError(
                        f"{path}: the guarded exclusive create collided")
            if name in _WRITE_OPS and self.fault.before_write is not None:
                self.fault.before_write(path)
            return real(*a, **kw)

        return call

    def __getattr__(self, name: str):
        if name.startswith("_"):
            raise AttributeError(name)
        return self._dispatch(name)


# ======================================================================================
# The alias-ban probe's docker seam — the one dependency too costly to drive for a timeout.
# ======================================================================================

@dataclasses.dataclass(frozen=True)
class ProbeFault:
    """`timeout` raises what `box/_docker.py`'s fixed `subprocess.run(..., timeout=120)`
    raises; `malformed` returns the probe's own control-failed shape, which the real probe
    treats as "could not be OBSERVED". `clean` is the control."""
    mode: str = "clean"


class ProbeDocker:
    """A fake `DockerFn` for `box/_alias`'s probe, injected at the `docker=` argument
    the real call site already threads. It injects a fault and nothing else."""

    def __init__(self, fault: ProbeFault | None = None) -> None:
        self.fault = fault or ProbeFault()
        self.argv: list[list[str]] = []

    def __call__(self, argv: list[str], **kw: Any):
        self.argv.append(list(argv))
        if self.fault.mode == "timeout":
            raise subprocess.TimeoutExpired(cmd=argv, timeout=120)
        if self.fault.mode == "malformed":
            return subprocess.CompletedProcess(argv, 1, stdout="", stderr="CONTROL-FAILED")
        return subprocess.CompletedProcess(argv, 0, stdout="", stderr="")


# ======================================================================================
# The gate (`tooling/lint/lint_run_records.py`): every call goes through these two helpers, so
# renaming its entry point is two edits, not one per test.
# ======================================================================================

def gate():
    """The gate, loaded the way CI reaches it (a standalone program, not a package)."""
    from defender.tests.support.shared.contracts._by_path import load_lint_gate
    return load_lint_gate("lint_run_records")


def plant(root: Path, rel: str, text: str) -> Path:
    p = root / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")
    return p


def gate_findings(root: Path, rel: str | None = None, text: str | None = None) -> list[Any]:
    """Run the gate's sweep (`lint_run_records.scan(root)`) over `root` and hand back its
    findings; `rel`/`text` plant one source file first."""
    if rel is not None:
        plant(root, rel, text or "")
    return list(gate().scan(root))


def displays(found: Iterable[Any]) -> str:
    return "\n".join(getattr(f, "display", str(f)) for f in found)


def reports(found: Iterable[Any], needle: str) -> bool:
    return needle in displays(found)
