"""Shared fakes, the writer census and production-seam wrappers for the #771 alias-ban tests.

`cite=` tags (E1, X5, B8, ...) are claim ids in `docs/archive/spec-graphs/spec_graph_771.yaml`."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_data_root, fixture_runs_base

from defender.tests.support.shared.contracts._spec1077 import fixture_run

import errno
import json
import os
import re
import shutil
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from collections.abc import Callable
from typing import Any

import pytest

from defender import box as box_mod

from defender.tests.support.shared.contracts._by_path import load_lint_gate, load_module
from defender.tests.e2e._box665 import (  # noqa: F401
    DockerFault,
    RecordingDocker,
    _cp,
    requires_live_box,
)
from defender.tests.support.sandbox._docker import daemon_reachable, docker_runtimes, is_dood
from defender.records import SessionPaths
from defender.tests.support.shared._fixture_uuid import fixture_uuid
import contextlib
from collections.abc import Iterator

DEFENDER = Path(__file__).resolve().parents[2]
#: `run_tree`'s run folder (run ids are canonical UUIDs, #1187).
RUN_771 = fixture_uuid("run-771")
CENSUS_TENANT = fixture_uuid("tenant:census-tenant")
REPO_ROOT = DEFENDER.parent
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
#: The write lint's ratchet baseline.
LINT_BASELINE = REPO_ROOT / "tooling" / "lint" / "lint_unguarded_tree_write_baseline.json"
LINT_MODULE_PATH = REPO_ROOT / "tooling" / "lint" / "lint_unguarded_tree_write.py"
#: The generator that derives the shipped seccomp profile from the vendored platform default.
SECCOMP_GEN_PATH = REPO_ROOT / "tooling" / "gen_seccomp_profile.py"


def load_seccomp_generator():
    """Import the profile generator by path (it lives in `tooling/`, outside every package).

    Tests call its pure `build()` to re-derive the shipped profile rather than re-list it.
    `register=False` leaves the `sys.modules` slot free."""
    return load_module(SECCOMP_GEN_PATH, register=False)


def load_write_lint():
    """Import the write lint by path (it lives in `tooling/lint/`, outside every package)."""
    return load_lint_gate("lint_unguarded_tree_write")


def ban_dependency_files() -> dict[str, Path]:
    """Every file in this repository the alias ban's correctness depends on."""
    return {
        "the seccomp profile the ban is": alias_profile_path(),
        "the vendored platform default it derives from": load_seccomp_generator().MOBY_DEFAULT_PATH,
        "the generator that derives it": SECCOMP_GEN_PATH,
        "the write lint's ratchet baseline": LINT_BASELINE,
        "the CI workflow that registers the runtime": CI_WORKFLOW,
    }


# The real-box guard
# Not marked `live`: CI deselects `live` and `box-dood` collects only test_540, so these run in
# the `test` job, which starts real gVisor boxes. Skip predicates mirror test_540's (restated,
# not imported: importing a test module couples collection). Deliberately no skip for "runsc
# registered without --oci-seccomp": that is the state the ban fault must report.
def _runtime_registered() -> bool:
    # Once-per-process probe: a daemon answering non-zero registers nothing; an unreachable one raises.
    return box_mod.BoxSpec.from_env(os.environ).runtime in docker_runtimes()


def _real_box_skip_reason() -> str | None:
    if not daemon_reachable():
        return "no reachable Docker daemon"
    if is_dood() and not box_mod._covered(DEFENDER, box_mod._shared_mounts(box_mod._docker)):
        return ("docker-outside-of-Docker with no shared mount covering the repo tree, so no "
                "bind source resolves (C46)")
    if not _runtime_registered():
        return ("the levered box runtime is not registered with this daemon; CI hard-fails its "
                "gVisor install step, so this branch is unreachable in the gate")
    return None


_REAL_BOX_SKIP = _real_box_skip_reason()

requires_real_box = pytest.mark.skipif(_REAL_BOX_SKIP is not None, reason=str(_REAL_BOX_SKIP))

#: Weaker than `requires_real_box` on purpose: the platform-default comparison runs the rootfs
#: directly (no box, no bind mount), so it also runs where only the levered runtime is missing,
#: e.g. a developer machine, catching a stale vendored default early.
requires_daemon = pytest.mark.skipif(
    not daemon_reachable(), reason="no reachable Docker daemon"
)


def daemon_engine_version() -> tuple[int, ...]:
    """The version of the daemon actually serving this host, as a comparable tuple."""
    probe = subprocess.run(
        ["docker", "version", "--format", "{{.Server.Version}}"],
        capture_output=True, text=True, encoding="utf-8", timeout=30,
    )
    assert probe.returncode == 0, f"could not read the daemon version: {probe.stderr.strip()}"
    raw = probe.stdout.strip().split("-")[0].split("+")[0]
    return tuple(int(part) for part in raw.split(".") if part.isdigit())


#: Witnesses for the platform-default comparison. Each is reachable unprivileged, so a denial is
#: seccomp's doing: `mount` would be useless (EPERM from the missing CAP_SYS_ADMIN under any
#: profile), while `unshare(CLONE_NEWUSER)` and `keyctl` reach the kernel under allow-all and are
#: EPERM under the daemon default. A sample, but it reads the live daemon rather than the vendored
#: document, so a daemon upgrade that moves the default shows up here.
PLATFORM_COMPARISON_PROBE = r"""
import ctypes, ctypes.util, errno, json, os, socket, stat, sys, tempfile

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
CLONE_NEWUSER = 0x10000000
NRS = {"x86_64": {"keyctl": 250, "userfaultfd": 323, "pivot_root": 155, "add_key": 248},
       "aarch64": {"keyctl": 219, "userfaultfd": 282, "pivot_root": 41, "add_key": 217}}
nr = NRS.get(os.uname().machine)
if nr is None:
    print(json.dumps({"unsupported_arch": os.uname().machine}))
    sys.exit(0)

out = {}

def attempt(name, fn):
    try:
        fn()
        out[name] = "ok"
    except OSError as e:
        out[name] = errno.errorcode.get(e.errno, str(e.errno))

def raw(name, *args):
    ctypes.set_errno(0)
    rc = libc.syscall(*[ctypes.c_long(a) for a in args])
    if rc == -1:
        out[name] = errno.errorcode.get(ctypes.get_errno(), str(ctypes.get_errno()))
    else:
        out[name] = "ok"
    return rc

d = tempfile.mkdtemp()
os.chdir(d)
dfd = os.open(".", os.O_RDONLY)
with open("src", "w") as fh:
    fh.write("x")

# the ban's six — the ONLY members expected to differ between the two profiles
attempt("symlink", lambda: os.symlink("t", "a-symlink"))
attempt("symlinkat", lambda: os.symlink("t", "a-symlinkat", dir_fd=dfd))
attempt("link", lambda: os.link("src", "a-link"))
attempt("linkat", lambda: os.link("src", "a-linkat", dst_dir_fd=dfd))
attempt("mknod", lambda: os.mknod("a-mknod", mode=stat.S_IFIFO | 0o600))
attempt("mknodat", lambda: os.mknod("a-mknodat", mode=stat.S_IFIFO | 0o600, dir_fd=dfd))

# escape witnesses — unprivileged-reachable, so their denial is seccomp's doing
if libc.unshare(CLONE_NEWUSER) == -1:
    out["unshare_newuser"] = errno.errorcode.get(ctypes.get_errno(), "?")
else:
    out["unshare_newuser"] = "ok"
raw("keyctl", nr["keyctl"], 0, -1, 0, 0, 0)
fd = raw("userfaultfd", nr["userfaultfd"], 0)
if fd not in (-1, None) and out["userfaultfd"] == "ok":
    os.close(fd)
raw("add_key", nr["add_key"], 0, 0, 0, 0, 0)
raw("pivot_root", nr["pivot_root"], 0, 0)

# ordinary controls — a subtraction that took these would fault every box at startup
attempt("create", lambda: open("a-create", "w").close())
attempt("mkdir", lambda: os.mkdir("a-dir"))
attempt("rename", lambda: os.rename("a-create", "a-renamed"))
attempt("unlink", lambda: os.unlink("a-renamed"))

def af_unix_bind():
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.bind(os.path.join(d, "a.sock"))
        s.listen(1)
    finally:
        s.close()

attempt("af_unix_bind", af_unix_bind)
os.close(dfd)
print(json.dumps(out))
"""


def run_probe_under_profile(
    script: str, profile: Path | None, *, run: Callable[..., Any] = subprocess.run,
) -> dict[str, str]:
    """Run `script` in the box rootfs and return its verdict map, under `profile` or — when
    `profile` is None — under whatever the daemon applies by ITSELF."""
    try:
        rootfs = box_mod.resolve_rootfs(None, DEFENDER)
        box_mod.require_image(
            lambda argv: run(argv, capture_output=True, text=True, encoding="utf-8", timeout=300),
            rootfs,
        )
    except box_mod.BoxFault as e:
        raise AssertionError(str(e)) from e
    argv = ["docker", "run", "--rm", "-i"]
    if profile is not None:
        argv += ["--security-opt", f"seccomp={profile}"]
    argv += ["--pull=never", rootfs.image, "python3", "-"]
    probe = run(
        argv, input=script, capture_output=True, text=True, encoding="utf-8", timeout=300,
    )
    if probe.returncode != 0:
        raise AssertionError(
            f"the probe container failed under "
            f"{'the daemon default' if profile is None else profile}: "
            f"{(probe.stderr or '').strip()}"
        )
    return json.loads(probe.stdout)

#: The six banned shapes; each must be shown denied individually (a partial ban is a fault).
BANNED_SHAPES = ("symlink", "symlinkat", "link", "linkat", "mknod", "mknodat")

#: Deliberately NOT banned: AF_UNIX `bind(2)` succeeds under the profile and leaves a socket the
#: reap scan refuses (X2). A probe set derived from the scan's refusals would fault every box.
SCAN_ONLY_SHAPES = ("af_unix_bind",)

#: Shape names the argv reader recognizes: the ban's six plus the scan-only one a probe must not
#: attempt.
KNOWN_SHAPES: frozenset[str] = frozenset((*BANNED_SHAPES, *SCAN_ONLY_SHAPES))

#: Whole-token matching closes the suite's sharpest DISCRIMINATION hole: three banned names  # lint-stale-ref: ok — the English word, about this suite's discriminating power; unrelated to the retired AgentRole.DISCRIMINATION lens whose name it happens to spell
#: contain others (`symlinkat` holds `symlink`, `linkat`, `link`; `mknodat` holds `mknod`), so a
#: substring reader reads a probe naming only `symlinkat` and `mknodat` as all six attempted.
_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def shapes_named_in(argv_text: str) -> set[str]:
    """The shape names `argv_text` NAMES, matched as whole tokens and never as substrings."""
    return {t for t in _TOKEN.findall(argv_text) if t in KNOWN_SHAPES}

#: The registration that makes runsc enforce the ban: `runsc install -- --oci-seccomp` writes
#: `runtimeArgs: ["--oci-seccomp"]` into the runtime's daemon.json entry (observed, runsc
#: release-20260727.0).
OCI_SECCOMP_FLAG = "--oci-seccomp"
RUNSC_INSTALL_CMD = "runsc install -- --oci-seccomp"
DAEMON_RUNTIME_ARGS_KEY = "runtimeArgs"

#: The scan-verdict marker, `<tree>.scrub-verdict.json`: a SIBLING of the tree it judges, because
#: the box is root inside the tree and could redirect or forge an in-tree verdict. A tree with no
#: verdict reads unverified. `ran: true` means the walk completed, NOT that the contents are
#: intact: a file a box emptied or rewrote still passes the scan.
SCRUB_VERDICT_SUFFIX = ".scrub-verdict.json"

#: The in-tree name a box would forge a verdict at (same string as the suffix; a plant target).
FORGED_IN_TREE_VERDICT_NAME = ".scrub-verdict.json"


# Real trees, and real aliases planted in them (tier 1)
def run_tree(tmp_path: Path) -> Path:
    """A live run dir holding only what host-side writers need beside them while a box runs
    (unlike test_540's frozen post-run `_clean_run_dir`)."""
    run = tmp_path / RUN_771
    (run / "gather_raw" / "l-001").mkdir(parents=True)
    (run / "gather_summaries").mkdir(parents=True)
    (run / "wire_logs").mkdir(parents=True)
    from defender.tests.support.storage import _alert_plant

    _alert_plant.plant_alert(run, {"id": "a-771"})  # the admitted alert and its record (#1222)
    return run


def worktree_tree(at: Path) -> Path:
    """The second shared root's shape: a curator drain worktree with a lesson corpus and a mount
    sentinel, so "either shared root" tests drive two distinct shapes."""
    at.mkdir(parents=True, exist_ok=True)
    (at / "defender" / "lessons").mkdir(parents=True)
    (at / "defender" / "lessons" / "lesson-a.md").write_text("# a lesson\n", encoding="utf-8")
    (at / ".box-sentinel-771abc").write_text("token-771\n", encoding="utf-8")
    return at


def outside(tmp_path: Path, name: str = "secret.txt", text: str = "ORIGINAL OUTSIDE\n") -> Path:  # lint-stale-ref: ok — a marker word in test data, not the retired curator-test constant
    """A file outside every shared tree (beside the run dir, inside `tmp_path`): the target an
    alias redirects a write at."""
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def plant_symlink(at: Path, target: Path) -> Path:
    """Plant a real symlink at `at` pointing at `target`, re-checking that the plant took."""
    at.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(target, at)
    assert os.path.islink(at), f"the premise did not hold: {at} is not a symlink"
    return at


def plant_dir_symlink(at: Path, target_dir: Path) -> Path:
    """Plant a symlink-to-directory at a path component a writer will mkdir through: the leaf's
    `O_NOFOLLOW` does not protect it, and `mkdir(exist_ok=True)` over it succeeds silently."""
    at.parent.mkdir(parents=True, exist_ok=True)
    target_dir.mkdir(parents=True, exist_ok=True)
    os.symlink(target_dir, at, target_is_directory=True)
    assert os.path.islink(at), "the planted component is not a symlink"
    assert at.is_dir(), "the planted component does not resolve to a directory"
    return at


def plant_hardlink(at: Path, target: Path) -> Path:
    """Plant a hard link at `at` aliasing `target`'s inode, re-checking nlink.

    Neither `Path.resolve()` nor `O_NOFOLLOW` sees a hard link, so a path-based gate passes it.
    Both paths must share a filesystem (`os.link` fails EXDEV across mounts); `tmp_path` does."""
    at.parent.mkdir(parents=True, exist_ok=True)
    os.link(target, at)
    assert os.lstat(at).st_ino == os.lstat(target).st_ino, "the plant is not an alias"
    assert os.lstat(at).st_nlink == 2, "the plant did not raise the target's link count"
    return at


def plant_component_for(writer: Writer, run: Path, outside_dir: Path) -> Path:
    """Swap the directory component `writer` mkdirs through for a symlink to `outside_dir`.

    It displaces the real directory `run_tree` made, as a box swaps one it can see. Only
    `Writer.mkdirs_component` rows qualify."""
    component = (run / writer.artifact).parent
    assert component != run, (
        f"{writer.id}'s artifact sits at the tree root — it has no component to plant at, so "
        f"it is not a mkdirs_component row"
    )
    if component.is_dir() and not component.is_symlink():
        shutil.rmtree(component)
    return plant_dir_symlink(component, outside_dir)


def snapshot_outside(root: Path) -> dict[str, tuple]:
    """Every entry under `root`, not dereferenced: relpath -> (type, inode, nlink, bytes).

    Unlike `target.read_text() == original`, comparing snapshots also catches a NEW file
    written beside the target."""
    out: dict[str, tuple] = {}
    for dirpath, dirs, files in os.walk(root, followlinks=False):
        for name in (*dirs, *files):
            p = Path(dirpath) / name
            st = os.lstat(p)
            if stat.S_ISLNK(st.st_mode):
                body: object = os.readlink(p)
            elif stat.S_ISREG(st.st_mode):
                body = p.read_bytes()
            else:
                body = None
            out[str(p.relative_to(root))] = (stat.S_IFMT(st.st_mode), st.st_ino, st.st_nlink, body)
    return out


# Wrappers over the production seams
def write_guarded(path: Path, text: str, *, mode: str = "replace", **kw: Any) -> None:
    """`defender._io.write_guarded`, the alias-refusing write every shared-tree writer routes
    through. `mode`: `replace` (atomic), `append` (JSONL) or `update` (locked read-modify-write)."""
    from defender import _io

    return _io.write_guarded(path, text, mode=mode, **kw)  # type: ignore[attr-defined]


def guarded_mkdir(path: Path, *, base: Path) -> None:
    """`defender._io.guarded_mkdir`: creates parents, refusing an aliased component at any depth
    (a leaf's `O_NOFOLLOW` cannot protect a component)."""
    from defender import _io

    return _io.guarded_mkdir(path, base=base)  # type: ignore[attr-defined]


def sweep_staged(tree: Path) -> list[Path]:
    """`defender._io.sweep_staged`: removes orphaned staged files (their unpredictable names mean
    nothing overwrites them), through the same guarded primitive."""
    from defender import _io

    return _io.sweep_staged(tree)  # type: ignore[attr-defined]


def allowed_syscalls(profile: dict) -> set[str]:
    """Every syscall name the profile can let through — the names under an `SCMP_ACT_ALLOW`
    rule, whatever that rule's conditions are."""
    return {
        name
        for rule in profile.get("syscalls", [])
        if rule.get("action") == "SCMP_ACT_ALLOW"
        for name in rule.get("names", [])
    }


def alias_profile_path() -> Path:
    """`box.ALIAS_PROFILE_PATH`: both argv builders must carry this one value, or a lane ships
    without the ban."""
    return box_mod.ALIAS_PROFILE_PATH  # type: ignore[attr-defined]


def ban_not_in_force_error() -> type[BaseException]:
    """`box.AliasBanNotInForce`: its own type, not a `BoxFault`, so the broad handler that lets
    other startup faults degrade (the unsandboxed opt-out) cannot catch it."""
    return box_mod.AliasBanNotInForce  # type: ignore[attr-defined]


def tree_verified(tree: Path) -> bool:
    """`scrub.tree_verified`: a tree with no verdict reads unverified, like one marked `ran: false`."""
    from defender.box import _scrub as scrub_mod

    return scrub_mod.tree_verified(tree)  # type: ignore[attr-defined]


def verdict_sidecar(tree: Path) -> Path:
    """The scan verdict's path: `<tree>.scrub-verdict.json`, beside the tree."""
    tree = Path(tree)
    return tree.parent / f"{tree.name}{SCRUB_VERDICT_SUFFIX}"


def read_verdict(tree: Path) -> dict:
    """The scan's verdict as data, or `{}` when no verdict exists for this tree."""
    p = verdict_sidecar(tree)
    if not p.is_file():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def write_verdict(tree: Path, doc: dict) -> Path:
    """Hand-write a verdict where the scan would, for tests driving the consumer side."""
    p = verdict_sidecar(tree)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


# The docker fault-injection fake (tier 2) — the probe's verdict as DATA
@dataclass(frozen=True)
class ProbeVerdict:
    """One in-box alias-probe outcome, as data.

    `allowed` names banned shapes the box could still create. `create_ok` is the ordinary-create
    control: without it a probe that never ran reads like one that was refused. `cite` is the
    ledger claim that observed this on a real daemon."""

    allowed: tuple[str, ...] = ()
    create_ok: bool = True
    exec_rc: int | None = None
    cite: str = ""

    def as_completed(self) -> subprocess.CompletedProcess:
        if self.exec_rc is not None:                       # the exec itself never reported
            return _cp(self.exec_rc, "", "docker exec: connection reset\n")
        if not self.create_ok:
            return _cp(1, "", "alias-probe: ordinary create did not succeed\n")
        if self.allowed:
            return _cp(1, "", "alias-probe: " + " ".join(f"{s} was ALLOWED" for s in self.allowed))
        return _cp(0, "alias-probe: all banned shapes denied; ordinary create ok\n", "")


#: An enforcing daemon: every banned shape EPERM; ordinary create, mkdir and AF_UNIX bind succeed.
BAN_IN_FORCE = ProbeVerdict(cite="E1,X2,G4")
#: runsc without the `--oci-seccomp` registration: every banned shape succeeds.
BAN_ABSENT = ProbeVerdict(allowed=BANNED_SHAPES, cite="E2,G6")


class AliasProbeDocker(RecordingDocker):
    """`RecordingDocker` plus the alias probe's in-box verdict.

    A probe exec is recognized by the shape names its argv carries, the same observable the
    attempted-set tests read. The fake only injects the verdict; it never decides what is a fault."""

    def __init__(self, verdict: ProbeVerdict = BAN_IN_FORCE, **kw: Any):
        super().__init__(**kw)
        self.verdict = verdict
        self.probe_argvs: list[list[str]] = []

    def __call__(self, argv, **kw) -> subprocess.CompletedProcess:
        argv = list(argv)
        if (len(argv) > 1 and argv[1] == "exec"
                and argv[-4:-2] == ["python3", "-c"] and argv[-1].endswith("/.tenant-id")):
            # A marker path may itself name a banned shape; the base answers this read without
            # consuming an alias verdict.
            return super().__call__(argv, **kw)
        # Whole tokens: an unrelated exec whose argv merely contains "link" is not a probe.
        if (len(argv) > 1 and argv[1] == "exec"
                and shapes_named_in(" ".join(argv)) & set(BANNED_SHAPES)):
            self.calls.append(argv)
            self.probe_argvs.append(argv)
            return self.verdict.as_completed()
        return super().__call__(argv, **kw)

    def probe_count(self) -> int:
        return len(self.probe_argvs)

    def shapes_attempted(self) -> set[str]:
        """The shape names (whole tokens, see `_TOKEN`) across every probe exec's argv."""
        return shapes_named_in(" ".join(" ".join(a) for a in self.probe_argvs))


# The writer census
@dataclass(frozen=True)
class Writer:
    """One host-side writer into a shared tree while a box is alive."""

    id: str
    artifact: str
    idiom: str
    posture: str
    invoke: Callable[[Path], Any]
    module: str
    cite: str = ""
    mkdirs_component: bool = False
    #: True only where an EMPTY artifact is the contract (the fault-exit trace is
    #: `write_text("")`); the positive control's non-empty check skips these rows.
    lands_empty: bool = False


def _invoke_write_trace(run_dir: Path) -> None:
    from defender.investigation import observe
    from defender.records import session_store

    with session_store.open_store(case_id="c-771", sessions=SessionPaths(
            fixture_runs_base(run_dir.parent / "stores"))) as store:
        sid = store.new_session("main")
        observe.write_trace(run_dir, store=store, session_id=sid, wall_ms=1.0)


def _invoke_observe_logger(run_dir: Path) -> None:
    from defender.investigation import observe

    # The logger creates its file eagerly; logging one row makes the positive control see bytes.
    logger = observe.RequestLogger.from_record(fixture_run(run_dir).observability.wire_log)
    try:
        logger.log_budget_refusal(tool_name="bash")
    finally:
        logger.close()


def _invoke_denial_logger(run_dir: Path) -> None:
    from defender.investigation import observe

    observe.denial_logger(fixture_run(run_dir)).log_policy_denial(
        role="main", system="elastic", verb="search", call_id="c1", params={},
    )


def _invoke_case_pointer(run_dir: Path) -> None:
    from defender.records import session_store

    session_store.write_case_pointer(fixture_run(run_dir), case_id="c-771", store_path=run_dir / "s.db")


def _invoke_query_payload(run_dir: Path) -> Any:
    from defender.investigation import query_tool

    return query_tool._persist_payload(fixture_run(run_dir), "l-001", 0, '[{"a": 1}]')


def _invoke_gather_summary(run_dir: Path) -> None:
    from defender.investigation import tools_gather

    tools_gather._persist_gather_summary(fixture_run(run_dir), "l-001", "## summary\nfindings\n")


def _invoke_claim_lead(run_dir: Path) -> Any:
    from defender.hooks import record_lead

    return record_lead.claim_lead(
        {"run_dir": str(run_dir), "lead_id": "l-001", "goal": "g", "what_to_summarize": ["x"]}, run=fixture_run(run_dir)
    )


def _invoke_lesson_load(run_dir: Path) -> None:
    # Driven at the production site, not the appender under it: the site swallows exceptions
    # (best-effort), so the appender's raise is not what a caller sees.
    from defender.agents import MAIN_DEF
    from defender.investigation import tools as runtime_tools
    from defender.investigation.agent_definition import bind

    from dataclasses import replace

    from defender.tests.support.tenancy import _tenants1106

    # A lesson belongs to the run's tenant (`<agent root>/lessons/`), never the checkout (#1108).
    run_tenant = _tenants1106.fixture_run_tenant()
    deps = replace(bind(MAIN_DEF, run_dir, defender_dir=DEFENDER), run=fixture_run(run_dir),
                   tenant=run_tenant)
    runtime_tools._record_lesson_load(deps, Path(run_tenant.agent) / "lessons" / "spec-771.md",
                                      kind="read")


def _invoke_queries_table(run_dir: Path) -> Any:
    """The query tool's second artifact, the queries table, through the real capture path (one
    writer, two plant targets)."""
    import asyncio
    from dataclasses import replace

    from defender.investigation.agent_definition import bind
    from defender.investigation.query_tool import QueryCapture
    from defender.tests.support.tenancy import _tenants1106

    # Gather is bound with a run's grant, never a process-level one (#1106).
    from defender.investigation.run_state import RunState

    # Driven outside a run, so deps carry the `RunState` a started run would record into.
    deps = replace(bind(_tenants1106.fixture_gather_def(), run_dir, defender_dir=DEFENDER),
                   lead_id="l-001", run=fixture_run(run_dir), run_state=RunState(run_dir, run_dir.name))
    return asyncio.run(QueryCapture(registry=None, known_ids=frozenset())._record(
        deps, system="elastic", verb="search", query_id="elastic.ad-hoc", params={},
        payload=[{"a": 1}], exit_code=0, detail="", system_key="",
    ))


def _invoke_sentinel_plant(run_dir: Path) -> None:
    """The run-dir sentinel plant; `_plant` itself turns a failed write into a `BoxFault`."""
    box_mod._plant(run_dir / ".box-sentinel", "token-771")


def _invoke_fault_exit_trace(run_dir: Path) -> None:
    """The driver's fault-exit trace write: `write_text("")` onto `write_trace`'s `tool_trace.jsonl`."""
    drive_fault_exit_trace(run_dir)


def _invoke_write_guarded(run_dir: Path) -> None:
    write_guarded(run_dir / "report.md", "guarded body\n")


def _invoke_tenant_row_writer(run_dir: Path) -> None:
    """The tenant row's writer, `create_tenant`, under a fresh `tenant-root/` in the run dir:
    it refuses a data root holding anything else, and `run_dir.parent` holds the run."""
    from defender.tenancy import _tenant

    _tenant.create_tenant(fixture_data_root(run_dir / "tenant-root"), CENSUS_TENANT)


#: Host-side writers into a shared tree while a box is alive, one row per artifact. A floor, not a
#: closed list: grep-derived censuses have missed writers (e.g. `run_investigation`'s fault-exit
#: trace write).
CENSUS: tuple[Writer, ...] = (
    # `unmeasured`: at this altitude `write_trace` raises (IsADirectoryError over a squatted
    # name); the driver one frame up is what swallows.
    Writer("write_trace", "tool_trace.jsonl", "write_text", "unmeasured",
           _invoke_write_trace, "investigation/observe.py", cite="C1,X10"),
    Writer("run_investigation", "tool_trace.jsonl", "write_text", "unmeasured",
           _invoke_fault_exit_trace, "investigation/driver/", cite="C1,X10", lands_empty=True),
    Writer("observe_logger", "wire_logs/llm_requests.jsonl", "append-open", "unmeasured",
           _invoke_observe_logger, "investigation/observe.py", cite="C1", mkdirs_component=True),
    Writer("denial_logger", "policy_denials.jsonl", "append-open", "unmeasured",
           _invoke_denial_logger, "investigation/observe.py", cite="C1,G12"),
    # The run -> case pointer is a host-only sidecar beside the run dir (#1235), named relative to it.
    Writer("write_case_pointer", f"../{RUN_771}.session-pointer.json", "write_text", "unmeasured",
           _invoke_case_pointer, "records/session_store/_write.py", cite="C1,R4"),
    # No budget or breaker rows: both live in the run process's memory and write nothing.
    Writer("query_tool", "gather_raw/l-001/0.json", "write_text", "return-none",
           _invoke_query_payload, "investigation/query_tool.py", cite="X5,G15",
           mkdirs_component=True),
    Writer("query_tool_queries_table", "executed_queries.jsonl", "append_jsonl", "unmeasured",
           _invoke_queries_table, "investigation/query_tool.py", cite="C1,G1"),
    Writer("gather_dispatch", "gather_summaries/l-001.md", "write_text", "unmeasured",
           _invoke_gather_summary, "investigation/tools_gather.py", cite="B11,G15",
           mkdirs_component=True),
    # The observable depends on the fault: a file squatting the parent component returns 0 (X5),
    # but a directory squatting the artifact makes the exclusive create EEXIST and returns 2,
    # reporting a write failure as a duplicate claim.
    Writer("claim_lead", "gather_raw/l-001.lead.json", "excl-create", "return-zero",
           _invoke_claim_lead, "hooks/record_lead.py", cite="X5,C1", mkdirs_component=True),
    Writer("record_lesson_load", "lessons_loaded.jsonl", "append_jsonl", "unmeasured",
           _invoke_lesson_load, "investigation/tools/", cite="G15"),
    Writer("start_box", ".box-sentinel", "write_text", "fault-startup",
           _invoke_sentinel_plant, "box/", cite="X5,G10"),
    Writer("write_guarded", "report.md", "guarded", "unmeasured",
           _invoke_write_guarded, "_io.py", cite="F1"),
    # Guarded idiom: `Held.write`'s create lane refuses an alias like `write_guarded` (#1137).
    # This row also keeps `tenancy/_tenant.py` in the census-derived hard-gate set.
    Writer("tenant_row_writer", f"tenant-root/{CENSUS_TENANT}/tenant.json", "guarded", "unmeasured",
           _invoke_tenant_row_writer, "tenancy/_tenant.py", cite="#1078 D1"),
)

#: The four failure-posture classes X5 measured. A record, not a per-row expectation: a row only
#: carries a posture label where one was measured.
POSTURES = ("swallow-continue", "return-none", "return-zero", "fault-startup")


# X5's measured postures: the anchor
# A per-row "ordinary failure vs aliased" comparison passes even if a site changes in both
# lanes, so X5's measured sites, faults and observables are pinned here. The faults use the
# real filesystem, never permission bits, so they hold under root.
@dataclass(frozen=True)
class MeasuredSite:
    """One of X5's call sites, the fault it was measured under, and what it did.

    `site` is the production symbol X5 drove, not a census row id."""

    posture: str
    site: str
    fault: str
    drive: Callable[[Path], object]
    #: What X5 recorded, checked against `posture_class`.
    observed: str


def _x5_query_payload_site(run_dir: Path) -> object:
    """`query_tool._persist_payload` — X5's return-none site, under a directory squatting the
    by-ref payload name."""
    from defender.investigation import query_tool

    target = run_dir / "gather_raw" / "l-001" / "0.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.mkdir()
    return query_tool._persist_payload(fixture_run(run_dir), "l-001", 0, '[{"a": 1}]')


def _x5_claim_lead_site(run_dir: Path) -> object:
    """`record_lead.claim_lead`, X5's return-zero site, under X5's fault: a plain file squatting
    the parent component (the census row's fault yields a different observable)."""
    from defender.hooks import record_lead

    component = run_dir / "gather_raw"
    if component.is_dir():
        shutil.rmtree(component)          # a live run dir already has it; the fault displaces it
    component.write_text("not a directory\n", encoding="utf-8")
    return record_lead.claim_lead(
        {"run_dir": str(run_dir), "lead_id": "l-001", "goal": "g", "what_to_summarize": []}, run=fixture_run(run_dir))


def _x5_sentinel_site(run_dir: Path) -> object:
    """`box._plant` — X5's fault-startup site, under a directory squatting the sentinel name."""
    (run_dir / ".box-sentinel").mkdir()
    return box_mod._plant(run_dir / ".box-sentinel", "token-771")


#: Three of X5's four sites: the swallow-continue one no longer writes (the budget lives in memory).
X5_MEASURED_SITES: tuple[MeasuredSite, ...] = (
    MeasuredSite("return-none", "query_tool._persist_payload",
                 "a directory squatting gather_raw/l-001/0.json", _x5_query_payload_site,
                 observed="returned:None"),
    MeasuredSite("return-zero", "record_lead.claim_lead",
                 "a plain file squatting the gather_raw component", _x5_claim_lead_site,
                 observed="returned:0"),
    MeasuredSite("fault-startup", "box._plant",
                 "a directory squatting .box-sentinel", _x5_sentinel_site,
                 observed="raised:BoxFault"),
)

#: Modules the write lint must hard-gate, derived from the census (plus the drain lane's
#: writers) so a hand-typed list cannot silently drop one.
CENSUS_MODULES: frozenset[str] = frozenset(w.module for w in CENSUS)
DRAIN_MODULES: frozenset[str] = frozenset({"learning/author/drain.py"})
LINT_HARD_GATED_MODULES: frozenset[str] = CENSUS_MODULES | DRAIN_MODULES | {
    "_filesystem/", "investigation/query_catalog.py", "records/session_store/_pointers.py",
}


def posture_class(outcome: object) -> str:
    """The observable CLASS of one site's reaction to a failed write."""
    if isinstance(outcome, BaseException):
        return f"raised:{type(outcome).__name__}"
    return f"returned:{outcome!r}"


def drive_writer_at(site: MeasuredSite, run_dir: Path) -> object:
    """Drive one of X5's measured sites; same observable convention as `drive_writer`."""
    try:
        return site.drive(run_dir)
    except BaseException as e:  # noqa: BLE001 — the exception IS the observable
        return e


def drive_writer(writer: Writer, run_dir: Path) -> object:
    """Drive one census writer; return the raised exception or the value. `BaseException`
    because the sentinel row fails with a `BoxFault`, not an `OSError`."""
    try:
        return writer.invoke(run_dir)
    except BaseException as e:  # noqa: BLE001 — the exception IS the observable
        return e


class _StaleVersionStore:
    """A real session store with its schema version bumped past the reader's, so reads refuse
    (`_refuse_stale_version`) while the run's writes proceed: the only condition under which the
    driver's fault-exit trace write runs."""

    def __init__(self, inner: Any, *, version: int = 99):
        self._inner = inner
        inner.connection.execute(f"PRAGMA user_version = {version}")

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def drive_fault_exit_trace(run_dir: Path, *, run_id: str = "r-771", salt: str = "0" * 16) -> Any:
    """Drive the real `driver.run_investigation` (replay harness) with a store whose reads
    refuse, so the fault-exit trace write runs."""
    from defender.records import session_store as ss

    from defender.tests.e2e._replay_harness import ReplayFn, Turn, drive

    @contextlib.contextmanager
    def factory(case_id: str, target: Path) -> Iterator[Any]:
        with ss.open_store(case_id=case_id,
                           sessions=SessionPaths(fixture_runs_base(Path(target).parent))) as real:
            yield _StaleVersionStore(real)

    replay = ReplayFn([Turn(text="done.")])
    drive(run_dir, run_id=run_id, main=replay, store_factory=factory)
    return replay


def drive_normal_exit_trace(run_dir: Path, *, run_id: str = "r-771-happy",
                            salt: str = "0" * 16) -> Any:
    """Drive the real `driver.run_investigation` with the production store, so the normal trace
    write runs and the fault-exit handler does not. Both sit in one `try/except` in the driver,
    so only a whole unbroken run shows the handler leaves a completed trace alone."""
    from defender.tests.e2e._replay_harness import ReplayFn, Turn, drive

    replay = ReplayFn([Turn(text="done.")])
    drive(run_dir, run_id=run_id, main=replay)
    return replay


def is_eexist(exc: BaseException) -> bool:
    """`EEXIST` from an exclusive create: the refusal signal for an occupied staged name."""
    return isinstance(exc, OSError) and exc.errno == errno.EEXIST


