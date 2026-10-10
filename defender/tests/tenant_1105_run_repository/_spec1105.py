"""Shared machinery for #1105 PR 1's spec — the runs repository. NO test functions.

The change (`spec-flow/specs/spec_graph_1105-pr1-run-repository.yaml`; design rev 4 as amended
by rev 4.1, `.spec-flow/design-rev4.md`, read through `.spec-flow/frontiers/70-resolutions.md`):
a package `defender/run_repository/` absorbs the run handle (`_run_handle.py` -> `_handle.py`)
and the layout owner (`_run_paths.py` -> `_layout.py`), and gains `RunId` (`_id.py`), the
lookups (`_lookup.py`: `open_run`, `list_run_ids`, `bound_runs`, `run_exists`), the
episode -> runs record (`_record.py`: `record_episode_runs`, `episode_runs`,
`sibling_run_ids`, `episode_sibling_ids`) and `RunRefused` (`_errors.py`). The door
(`__init__.py`) serves the public surface lazily. Every lookup and tenant-keyed record function
takes an accepted `Tenant` and, where it names a run, a `RunId`; it opens `tenant.runs` ONCE
with `_io.hold(tenant.runs, follow=False)` and works only relative to that handle (amendment A).

P1 and P2 (owner, round 4) bind every test here. P1: the host is not malicious (mid-call
changes are outside the threat model), but nothing read from disk is trusted. P2: an unexpected
state raises ONE named error — `TenantRefused` for the runs folder and its `_tenant.json`,
`RunRefused` for everything else — naming the path and the fault, never a raw `OSError`, at the
first failed check, before any write. The expected states, and only these, answer normally: the
runs folder absent (empty answers), `_episodes` absent (no claims), and the known sidecar files
beside run folders (a staged one included).

NONE OF THE NEW NAMES EXISTS AT BASE 80888efb. Every test imports what it drives from
`defender.run_repository` INSIDE ITS OWN BODY, so a missing package is one failure per test
(`ModuleNotFoundError` at the seam the test needs), never a collection error that hides every
other test in the file, and the tests that pin unchanged behaviour stay green at base.

THE REFUSAL CHECK. No test wraps a door name in `pytest.raises(...)`, and no helper here
asserts on a demand's behalf. `raised()` hands back what a call raised (or `None`), `is_a()`
answers whether that is an instance of a class — `False` when the "class" is not a class — and
the TEST asserts, with the demand's own content (the error type, the path the message names, no
raw control character). That keeps every assertion in the test that owns it: a shared helper's
assert would certify one test's discrimination for every test that funnels through it.

EVERY FAULT IS A REAL INPUT THROUGH THE REAL PRIMITIVE: the links, FIFOs, truncated records,
stray names, other-tenant records and deep-nested records are made on the real filesystem by
the test that needs them. The repository's injected `io=` seam (NM-10) is used here to OBSERVE
calls (`RecordingIO`), never to inject a fault (the owner's test shape; `w_fault_injected_io`).

COINED NAMES. The design names every public function, `RunId.parse` / `RunId.mint(label, *,
clock=)`, `bound_runs(tenant)`'s `absent`, `_io.hold(root, *, follow=)` and
`Bound.read(name, *, max_bytes=)`. It names the injected seam only as "a keyword-only injected
I/O seam, default the real `defender._io`, as `Run.for_tenant` takes" — this suite spells it
`io=` (`Run.for_tenant(..., io=)`'s own name, ledger 20-demands F-2). If write-code-from-spec
names anything differently it renames it HERE and in the tests, never through an alias.

Underscore-prefixed so pytest does not collect it; it defines no tests.
"""
from __future__ import annotations

import datetime as _dt
import json
import os
import shutil
import stat
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path
from typing import Any

WORKTREE = Path(__file__).resolve().parents[3]
DEFENDER = WORKTREE / "defender"
#: The package this spec pins (D1.1), by path.
PACKAGE = DEFENDER / "run_repository"
#: The committed fixture tenant (#1120 H2): the knowledge every test tenant is set up from.
FIXTURE = WORKTREE / "knowledge" / "tenant-fixture"

#: The two tenants a test may need. `create_tenant` admits ONE tenant per data root (F36), so
#: the second one's row is planted by hand, in the row's own shape — `accept_tenant` accepts it.
T_ID = "acme"
U_ID = "beta"

#: The five host-only sidecar suffixes (D2.1, R4-35; #1224 added the oracle-held record),
#: spelled HERE rather than imported from the layout: the suite pins the design's list, so a
#: layout that drops one is caught.
SIDECAR_SUFFIXES = (".run-end.json", ".scrub-verdict.json", ".accounting_failures.json",
                    ".ticket-write.json", ".oracle-held.json")
#: The staged-name tail a sidecar write creates first (`_io.staged_leaf`: `.staged-` plus 16
#: lowercase hex digits, R41-23) — the shape MF-21 (DV-5) adds to the sidecar clause.
STAGED_TAIL = ".staged-0123456789abcdef"
#: The bound on a run id's bytes (D12.3; owner, OP-4/OP-8).
RUN_ID_BOUND = 206
#: The episode record's size cap (D3.4; owner, OP-4).
RECORD_CAP = 65536
#: A fixed clock for `RunId.mint(label, clock=...)` — the shape `mint_run_id`'s takes.
FIXED_NOW = _dt.datetime(2026, 10, 4, 12, 0, 0, tzinfo=_dt.UTC)


def fixed_clock() -> _dt.datetime:
    return FIXED_NOW


#: What `RunId.mint` prefixes under `fixed_clock`: `<%Y%m%dT%H%M%SZ>-`, case-folded (17 chars).
MINT_PREFIX = f"{FIXED_NOW.strftime('%Y%m%dT%H%M%SZ')}-".casefold()


# ==========================================================================================
# Refusals: hand back, never assert.
# ==========================================================================================

def raised(fn: Callable[..., Any], *args: Any, **kwargs: Any) -> BaseException | None:
    """What `fn(*args, **kwargs)` raised — a `SystemExit` included — or `None` when it
    returned. Never asserts: the test that calls it does."""
    try:
        fn(*args, **kwargs)
    except KeyboardInterrupt:
        raise
    except BaseException as exc:  # noqa: BLE001 — the point is to hand ANY refusal back
        return exc
    return None


def is_a(err: object, cls: object) -> bool:
    """`err` is an instance of the class `cls`; `False` (never a `TypeError`) when `cls` is not
    a class at all."""
    return isinstance(cls, type) and isinstance(err, cls)


def message(err: BaseException | None) -> str:
    """A refusal's text: `SystemExit`'s code when it is a string (`sys.exit(msg)`), else the
    exception's own text; `""` for `None`."""
    if err is None:
        return ""
    if isinstance(err, SystemExit):
        return err.code if isinstance(err.code, str) else repr(err.code)
    return str(err)


def has_raw_control(text: str) -> bool:
    """Whether `text` carries a raw character a repr-style quote of a name never leaves raw
    (design NF-8): any character `str.isprintable` rejects, so a newline, a tab, an ESC, NUL,
    DEL, a C1 control and U+2028 / U+2029 alike (91 BF-09)."""
    return any(not ch.isprintable() for ch in text)


# ==========================================================================================
# Tenants, runs folders and records — real inputs on the real filesystem.
# ==========================================================================================

def tenant(root: Path, tenant_id: str = T_ID) -> Any:
    """`tenant_id` set up under the data root `root` and accepted by the REAL `accept_tenant`.

    The committed fixture's knowledge is copied to `<root>/<id>/knowledge` with its
    `agent/.tenant-id`, and the row is written in `create_tenant`'s own shape. The first tenant
    of a root goes through the real `create_tenant`; any further one is planted by hand, since
    `create_tenant` admits one tenant per root (F36). Nothing under `<id>/runs` is made."""
    from defender import _tenant

    root = Path(root)
    knowledge = root / tenant_id / "knowledge"
    if not knowledge.exists():
        shutil.copytree(FIXTURE, knowledge, symlinks=True)
        (knowledge / "agent" / ".tenant-id").write_text(f"{tenant_id}\n", encoding="utf-8")
    row = root / tenant_id / "tenant.json"
    if not row.is_file():
        others = [p for p in root.iterdir() if p.name != tenant_id]
        if not others:
            _tenant.create_tenant(root, _tenant.TenantId(tenant_id))
        else:
            row.write_text(json.dumps(
                {"tenant_id": tenant_id, "created_at": "2026-10-04T00:00:00+00:00"},
                indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return _tenant.accept_tenant(root, tenant_id, defender_dir=DEFENDER)


def tenant_record_text(tenant_id: str) -> str:
    """`_tenant.json` naming `tenant_id`, in `ensure_runs_base_record`'s own shape."""
    return json.dumps({"tenant_id": tenant_id, "base_world_id": "0" * 32,
                       "created_at": "2026-10-04T00:00:00+00:00"},
                      indent=2, sort_keys=True) + "\n"


def plant_tenant_record(runs: Path, tenant_id: str, *, raw: str | bytes | None = None) -> Path:
    """`<runs>/_tenant.json` naming `tenant_id` — or holding `raw` verbatim. Makes `runs`."""
    runs = Path(runs)
    runs.mkdir(parents=True, exist_ok=True)
    path = runs / "_tenant.json"
    body = tenant_record_text(tenant_id) if raw is None else raw
    if isinstance(body, bytes):
        path.write_bytes(body)
    else:
        path.write_text(body, encoding="utf-8")
    return path


def runs_folder(t: Any) -> Path:
    """`t.runs` as run setup leaves it: a real folder holding `_tenant.json` naming `t.id`."""
    plant_tenant_record(t.runs, t.id)
    return Path(t.runs)


def make_run(runs: Path, run_id: str, *, alert: str = '{"alert": "seed"}\n') -> Path:
    """A real run folder `<runs>/<run_id>` holding an `alert.json`."""
    run_dir = Path(runs) / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "alert.json").write_text(alert, encoding="utf-8")
    return run_dir


def plant_sidecars(runs: Path, run_id: str, *, staged: bool = True) -> list[Path]:
    """The four known sidecar files `<runs>/<run_id><suffix>` beside the run (regular files),
    plus the staged one a sidecar write creates first (`<id>.run-end.json.staged-<16 hex>`)."""
    made = []
    for suffix in SIDECAR_SUFFIXES:
        p = Path(runs) / f"{run_id}{suffix}"
        p.write_text("{}\n", encoding="utf-8")
        made.append(p)
    if staged:
        p = Path(runs) / f"{run_id}{SIDECAR_SUFFIXES[0]}{STAGED_TAIL}"
        p.write_text("{}\n", encoding="utf-8")
        made.append(p)
    return made


def record_doc(episode_id: str, tenant_id: str, source_run_id: str,
               runs: Mapping[str, str]) -> dict[str, Any]:
    """An episode record's content (D3.2): exactly the four fields, run ids as text."""
    return {"episode_id": episode_id, "tenant_id": tenant_id,
            "source_run_id": source_run_id, "runs": dict(runs)}


def record_text(episode_id: str, tenant_id: str, source_run_id: str,
                runs: Mapping[str, str]) -> str:
    """A HOST-WRITTEN record body (a test planting one by hand): JSON of `record_doc`."""
    return json.dumps(record_doc(episode_id, tenant_id, source_run_id, runs), sort_keys=True)


def plant_record(runs: Path, episode_id: str, tenant_id: str, source_run_id: str,
                 arms: Mapping[str, str], *, raw: str | bytes | None = None,
                 name: str | None = None) -> Path:
    """`<runs>/_episodes/<name or episode_id>.json`, written by hand (a host-written record):
    `record_text(...)`, or `raw` verbatim. Makes `_episodes/`."""
    folder = Path(runs) / "_episodes"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{name if name is not None else episode_id}.json"
    body = record_text(episode_id, tenant_id, source_run_id, arms) if raw is None else raw
    if isinstance(body, bytes):
        path.write_bytes(body)
    else:
        path.write_text(body, encoding="utf-8")
    return path


def truncated(text: str) -> str:
    """A good record cut short — the torn write P2's representative names."""
    return text[: len(text) // 2]


def deep_json(depth: int = 200_000) -> str:
    """A JSON document nested `depth` levels deep (F42, R4-17: `read_tenant` raises
    `RecursionError` on it today)."""
    return "[" * depth + "]" * depth


def alert_file(folder: Path, name: str = "alert.json") -> Path:
    """An alert file run setup can materialise a run from."""
    folder = Path(folder)
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    path.write_text('{"alert": "spec-1105"}\n', encoding="utf-8")
    return path


def make_fifo(path: Path) -> Path:
    os.mkfifo(path)
    return path


# ==========================================================================================
# Observation channels.
# ==========================================================================================

def tree_state(root: Path) -> dict[str, tuple[str, bytes | str | None]]:
    """Every entry under `root`, judged without following links: kind plus, for a regular
    file its bytes, for a link its target. Two calls compare equal iff nothing under `root`
    was created, removed, retyped or rewritten."""
    root = Path(root)
    out: dict[str, tuple[str, bytes | str | None]] = {}
    if not os.path.lexists(root):
        return out
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in [*dirnames, *filenames]:
            p = Path(dirpath) / name
            rel = str(p.relative_to(root))
            st = os.lstat(p)
            if stat.S_ISLNK(st.st_mode):
                out[rel] = ("link", os.readlink(p))
            elif stat.S_ISDIR(st.st_mode):
                out[rel] = ("dir", None)
            elif stat.S_ISREG(st.st_mode):
                out[rel] = ("file", p.read_bytes())
            else:
                out[rel] = ("other", None)
    return out


def open_fd_count() -> int:
    """How many descriptors this process holds open (`/proc/self/fd`). The listing's own
    descriptor is counted every time, so two counts compare like for like (R41-13's probe)."""
    return len(os.listdir("/proc/self/fd"))


class RecordingIO:
    """The repository's injected `io=` seam, observed: delegates every attribute to the real
    `defender._io` and records each call to one of its functions as `(name, args, kwargs)`.

    It injects NOTHING — no fault, no altered answer (the owner's test shape). Classes and
    constants pass through unwrapped, so `isinstance` against `_io`'s types still holds."""

    def __init__(self) -> None:
        from defender import _io

        self._real = _io
        self.calls: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []

    def __getattr__(self, name: str) -> Any:
        attr = getattr(self._real, name)
        if not callable(attr) or isinstance(attr, type):
            return attr

        def recorded(*args: Any, **kwargs: Any) -> Any:
            self.calls.append((name, args, kwargs))
            return attr(*args, **kwargs)

        return recorded

    def named(self, name: str) -> list[tuple[tuple[Any, ...], dict[str, Any]]]:
        return [(a, k) for n, a, k in self.calls if n == name]


def iter_py(root: Path) -> Iterator[Path]:
    """Every `.py` under `root`, caches skipped."""
    for p in sorted(Path(root).rglob("*.py")):
        if "__pycache__" not in p.parts:
            yield p
