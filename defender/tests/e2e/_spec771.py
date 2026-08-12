"""Shared fakes, the writer census, and the future-symbol shims for #771's executable spec
— NOT a test module (the leading underscore keeps pytest from collecting it).

Imported by `test_771_write_backstop.py`, `test_771_alias_ban.py` and
`test_771_lifecycle_and_scope.py`. Every demand of
`spec-flow/specs/spec_graph_771.yaml` is exactly one test in those three files, named by
that demand's `discharged_by`.

THE FAULT-INJECTION HIERARCHY, applied (phases/author.md):

  tier 1 — REAL input through the REAL primitive, in the test itself. Every alias is built
  with `os.symlink` / `os.link` / `os.mkfifo` on a real tree, and the premise is re-probed
  (`os.path.islink`, `st_ino`, `st_nlink`) before the outcome is asserted. The taxonomy
  assumption therefore ceases to exist rather than being pinned once. This is how EVERY
  filesystem fault in this suite is built — including the ones that look expensive.

  tier 2 — a declarative fake whose fault CONTENT cites the ledger claim that observed it on
  the real dependency. Only the docker daemon and the model qualify. `RecordingDocker` (from
  `_box665`) is reused rather than re-plumbed; `AliasProbeDocker` below extends it with the
  in-box probe's verdict, and every canned verdict carries `cite=`.

  tier 3 — an author-imagined fault is BANNED. Where a fault has no ledger claim, the test is
  not written; the probe request is in `82-author-digest.md`'s red flags instead.

RED AGAINST HEAD, and that is the expected state of a spec. The guarded write primitive
(`_io.write_guarded`), the startup probe (`box._probe_alias_ban`), the shipped seccomp profile
(`box.ALIAS_PROFILE_PATH`), the scan verdict marker (`scrub.tree_verified`, sited OUTSIDE the
tree by §7 D8) and the new lint do not exist at `c98bc86c`. Every reference to them is
LAZY — inside a call site a test invokes — so all three modules still COLLECT at HEAD and each
test fails on its own missing symbol rather than taking the suite's collection down with it.

No `monkeypatch.setattr` anywhere: fakes enter through `docker=`, `store_factory=`, `box=`,
`limits=`, `start_box=`/`stop_box=`/`scrub=` — the seams the code already carries — because
`scripts/lint/lint_monkeypatch.py` is a blocking ratcheted gate. `monkeypatch.setenv` is used
for env knobs and is explicitly outside that gate.

A note on ROOT: `defender/CLAUDE.md` records four #631 tests that invert under root because
they simulate an unwritable target with a permission bit. Nothing here does. Every refusal in
this suite is forced by a PLANTED ALIAS, a real occupied name, or a REAL DIRECTORY squatting
an artifact name — all three of which root respects.

THE CENSUS IS THE INSTRUMENT EVERY WRITE-SIDE DEMAND KEYS ON, so its two late additions are
worth reading before anything else: the DRIVER'S FAULT-EXIT trace write (one of the two sites
the original issue reported, absent from this census, from the lint's gate list and from the
project profile's writer list at the same time) and the QUERY TOOL'S QUERIES TABLE (the second
artifact of a writer counted once). The lint's hard-gate module set is derived from the census
rather than typed beside it, so the next added row cannot go missing from the gate the way
this one did.
"""
from __future__ import annotations

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

from defender.runtime import box as box_mod

from defender.tests._by_path import load_lint_gate, load_module
from defender.tests.e2e._box665 import (  # noqa: F401
    DockerFault,
    RecordingDocker,
    _cp,
    requires_live_box,
)
from defender.tests._docker import daemon_reachable, is_dood

DEFENDER = Path(__file__).resolve().parents[2]
REPO_ROOT = DEFENDER.parent
CI_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
#: The write lint's ratchet baseline. Named once and shared, because two demands read it and a
#: second spelling of the same path is how one of them silently stops looking at anything.
LINT_BASELINE = REPO_ROOT / "scripts" / "lint" / "lint_unguarded_tree_write_baseline.json"
LINT_MODULE_PATH = REPO_ROOT / "scripts" / "lint" / "lint_unguarded_tree_write.py"
#: The generator that DERIVES the shipped profile from the vendored platform default, and the
#: vendored default it derives from. Both are named here rather than inline because three
#: demands read them (the profile's shape, the escape-surface non-regression, and the
#: dependency sweep) and a second spelling of either path is how one demand ends up asserting
#: about a file nothing produces.
SECCOMP_GEN_PATH = REPO_ROOT / "scripts" / "gen_seccomp_profile.py"


def load_seccomp_generator():
    """Import the profile generator as a module, by path.

    Same reason as `load_write_lint`: it lives under `scripts/`, outside every importable
    package. The demands that use it need `build()` — the pure function from vendored bytes to
    shipped profile — so that "the shipped profile is the platform default minus the ban" is
    asserted by RE-DERIVING it, not by re-listing its contents in a second place that can drift
    from the first.

    `register=False`: the generator is read for one pure function and nothing imports it by
    name, so the `sys.modules` slot stays free for a caller that means it."""
    return load_module(SECCOMP_GEN_PATH, register=False)


def load_write_lint():
    """Import the write lint as a module, by path.

    It lives at the repo root, outside every importable package, so `import` cannot reach it —
    and two demands need it (the wrapper-detection one and the hard-gate one). Loaded through
    the shared loader rather than inline: a second copy of the loader is a second chance for one
    demand to end up pointed at a file that no longer exists while still reporting green."""
    return load_lint_gate("lint_unguarded_tree_write")


def ban_dependency_files() -> dict[str, Path]:
    """Every file in this repository the alias ban's correctness depends on.

    THE SWEEP'S RULE IS GENERAL AND WAS APPLIED TO ONE CASE. The containment argument is: the
    drain box writes into a checkout of this repo, and that lane's job is opening a PR from it,
    so a file the box can rewrite is a file it can get MERGED — and the weakened version then
    reaches every later box through main. That is true of the seccomp profile, and it is just
    as true of every other file the ban leans on. Five qualify and all five are out of reach
    today for the same reason the profile was: an accident of where they sit, not a rule.

      * the profile itself — the syscall set the ban IS;
      * the vendored platform default it is DERIVED from — rewrite that and the next
        regeneration ships a weakened profile the generator will call correct;
      * the generator that performs the subtraction — it decides what "derived" MEANS, so it
        can define the ban away as surely as editing the output can;
      * the write lint's ratchet baseline — ratchet a census row into it and the backstop
        stops gating that writer, with no test turning red;
      * the CI workflow — it is what registers the runtime with `--oci-seccomp`, without which
        the shipped default runtime enforces nothing at all (C1-fix, executed).

    THE SECOND AND THIRD ENTRIES ARE THE SWEEP'S OWN RULE APPLIED TO THIS PR'S CHANGE. Deriving
    the profile rather than hand-writing it replaced ONE file the ban rests on with THREE, and
    a sweep still naming only the output would have shrunk its coverage while looking untouched.

    The profile is a future symbol, so this raises `AttributeError` at HEAD like every other
    reference to one — `alias_profile_path()` is evaluated first for exactly that reason."""
    return {
        "the seccomp profile the ban is": alias_profile_path(),
        "the vendored platform default it derives from": load_seccomp_generator().MOBY_DEFAULT_PATH,
        "the generator that derives it": SECCOMP_GEN_PATH,
        "the write lint's ratchet baseline": LINT_BASELINE,
        "the CI workflow that registers the runtime": CI_WORKFLOW,
    }


# --------------------------------------------------------------------------- #
# The real-box guard — and WHICH CI JOB SELECTS IT
# --------------------------------------------------------------------------- #
# The obvious idiom here is `@pytest.mark.live`, and it is the wrong one. The gate runs
# `pytest tests/ -m "not live"`, so a `live`-marked test is DESELECTED in the `test` job; the
# `box-dood` job collects one path only (`tests/e2e/test_540_box_boundary.py`) and never sees
# this file at all. A mechanism confirmation carried on `live` is therefore selected by NO CI
# job — the property would be specified and never exercised by the gate that actually runs.
#
# 48-reground settled the fact this turns on: CI DOES start real boxes, in both jobs. The
# blanket docker-outside-of-Docker skip is retired posture; the `test` job runs pytest on the
# runner (so the DooD predicate is false outright) and hard-fails its gVisor step unless the
# daemon lists runsc. So the tests below run in the `test` job, under the same skipif
# discipline `test_540_box_boundary.py` uses, and carry NO `live` marker.
#
# CALL THAT JOB WHAT IT IS. It is not a merge gate: `main` carries no branch protection and no
# ruleset, no job declares a dependency on another, and there is no aggregating required check.
# The `test` job is a signal a human chooses to respect, and everything below that says these
# obligations are "verified in CI" means verified in a job whose red a human can merge past.
# Turning on branch protection for it is what would make the stronger sentence true; until
# someone does, the accurate claim is SELECTED, not ENFORCED.
#
# There is an order-of-operations rider on top of that. The boxes this job starts do not
# enforce the ban until the workflow itself is edited to register the runtime with
# `--oci-seccomp` — which is one of this suite's own demands. The chain closes, but the two
# obligations the real-box confirmations alone pin are first verified for real only after that
# edit lands, and only if someone reads a job that blocks nothing.
#
# The three predicates are 540's, restated rather than imported (importing a collected test
# module to reuse a marker is how a collection error in one file takes out another):
#   * no reachable daemon;
#   * DooD with no shared mount covering the repo tree (bind sources unresolvable);
#   * the levered runtime not registered with the daemon.
# There is deliberately NO fourth predicate for "runsc is registered but WITHOUT
# --oci-seccomp". That state is exactly what the ban fault exists to report, and skipping on
# it would let the suite go green on a host where the ban is not in force.
def _runtime_registered() -> bool:
    probe = subprocess.run(
        ["docker", "info", "--format", "{{range $k, $v := .Runtimes}}{{$k}} {{end}}"],
        capture_output=True, text=True, encoding="utf-8", timeout=30,
    )
    if probe.returncode != 0:
        return False
    return box_mod.BoxSpec.from_env(os.environ).runtime in set(probe.stdout.split())


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

#: Selected by CI's `test` job (`pytest tests/ -m "not live"`) — no `live` marker, so that job
#: runs these against a real box under the shipped runtime. Selected, not enforced: nothing
#: mechanically blocks a merge on that job's result (see the note above).
requires_real_box = pytest.mark.skipif(_REAL_BOX_SKIP is not None, reason=str(_REAL_BOX_SKIP))

#: A WEAKER guard than `requires_real_box`, and the difference is the point. The two demands
#: that compare our profile against the daemon's OWN default do not start a box: they run the
#: rootfs directly with the probe on stdin, so they need neither the levered runtime registered
#: nor a bind source that resolves under docker-outside-of-Docker. Gating them on
#: `requires_real_box` would skip them on every host where only the runtime is missing — which
#: includes the ordinary developer machine, and which is exactly where a stale vendored default
#: wants to be caught early.
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


#: The witness set for the platform-default comparison, and every member is chosen for one
#: reason: an unprivileged process on a stock kernel can reach it, so a denial is attributable
#: to SECCOMP and to nothing else.
#:
#: THAT CONSTRAINT IS WHAT MAKES THE COMPARISON READABLE, and it is easy to get wrong. `mount`
#: looks like the obvious escape witness and is useless as one — it is EPERM from the missing
#: CAP_SYS_ADMIN whether seccomp denied it or not, so it reports the same value under every
#: profile and discriminates nothing. `unshare(CLONE_NEWUSER)` and `keyctl` need no capability
#: at all: executed against Docker 29.6.1, the first SUCCEEDS and the second returns ENOKEY —
#: the errno of a syscall that reached the kernel — under an allow-all profile, while both are
#: EPERM under the daemon's own default. They are the members that would turn red if the shipped
#: profile ever stopped being a subtraction from that default.
#:
#: The comparison is a SAMPLE and cannot be anything else: there is no way to attempt every
#: syscall, and most of the ones worth attempting destroy the container or need privilege. What
#: it buys over a digest check is that it reads the daemon in front of it rather than the
#: document we vendored, so a daemon upgrade that moves the default is visible here and nowhere
#: else.
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


def run_probe_under_profile(script: str, profile: Path | None) -> dict[str, str]:
    """Run `script` in the box rootfs and return its verdict map, under `profile` or — when
    `profile` is None — under whatever the daemon applies by ITSELF.

    The `None` arm is the whole mechanism: there is no way to ask a daemon what its default
    profile contains, but there is a way to ask what it DOES, which is to run a container
    without `--security-opt` and observe. That turns "our profile does not widen the platform
    default" from a claim about two documents into a claim about two containers on the daemon
    in front of us — and it stays true across a daemon upgrade that moves the default out from
    under the vendored copy, which no digest check can see.

    The script arrives on STDIN rather than through a bind mount so the comparison also runs
    under docker-outside-of-Docker, where a host path need not exist on the daemon's side."""
    argv = ["docker", "run", "--rm", "-i"]
    if profile is not None:
        argv += ["--security-opt", f"seccomp={profile}"]
    argv += [box_mod.BoxSpec.from_env(os.environ).rootfs, "python3", "-"]
    probe = subprocess.run(
        argv, input=script, capture_output=True, text=True, encoding="utf-8", timeout=300,
    )
    assert probe.returncode == 0, (
        f"the probe container failed under "
        f"{'the daemon default' if profile is None else profile}: {probe.stderr.strip()}"
    )
    return json.loads(probe.stdout)

#: The six shapes `alias_profile.domain.distinguished` names. Each must be individually
#: demonstrated denied — five denied and one admitted is exactly the partial enforcement O2
#: refuses to grade (45-dispositions firm consensus #3).
BANNED_SHAPES = ("symlink", "symlinkat", "link", "linkat", "mknod", "mknodat")

#: DELIBERATELY NOT in the deny set. Under this exact profile `bind(2)` on AF_UNIX SUCCEEDS
#: and leaves a socket the reap scan refuses — executed twice, independently (X2, G5). A probe
#: set derived from the scan's refusal predicate would demand this fail and would fault every
#: box at startup (C5-fix / F3). NO4's boundary, now load-bearing.
SCAN_ONLY_SHAPES = ("af_unix_bind",)

#: Every shape name the probe's argv may legitimately carry: the ban's six, plus the scan-only
#: one it must NOT attempt.
KNOWN_SHAPES: frozenset[str] = frozenset((*BANNED_SHAPES, *SCAN_ONLY_SHAPES))

#: An identifier-shaped token. THE READER BELOW MATCHES WHOLE TOKENS, AND THAT IS THE REPAIR OF
#: THIS SUITE'S SHARPEST DISCRIMINATION HOLE. Three of the six banned names are substrings of  # lint-stale-ref: ok — the English word, about this suite's discriminating power; unrelated to the retired AgentRole.DISCRIMINATION lens whose name it happens to spell
#: others — `symlinkat` contains `symlink`, `linkat` and `link`; `mknodat` contains `mknod` —
#: so a substring reader answers "all six attempted" for a probe whose argv names only
#: `symlinkat` and `mknodat`. A probe narrowed to two read as full coverage, in the one demand
#: that carries O2's per-member requirement: the oracle could not fail in the place the design's
#: whole claim rests on, which is that enforcement is OBSERVED rather than trusted.
_TOKEN = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


def shapes_named_in(argv_text: str) -> set[str]:
    """The shape names `argv_text` NAMES, matched as whole tokens and never as substrings.

    The suite's oracle for "which shapes did the probe attempt", read off the probe's own argv
    rather than off a verdict the probe reports about itself. Whole-token matching is what makes
    it falsifiable: `shapes_named_in("... symlinkat ... mknodat ...")` is exactly
    `{symlinkat, mknodat}`, so a probe that quietly narrowed its set fails the equality the
    demand asserts instead of satisfying it by spelling.

    The probe therefore owes the test one thing, and it is part of the contract: each attempted
    shape appears in the exec's argv as its own bare token (`symlink`, not `SYMLINK_DENIED`)."""
    return {t for t in _TOKEN.findall(argv_text) if t in KNOWN_SHAPES}

#: The registration that carries the ban on the shipped default runtime. Settled by an
#: EXECUTED probe against real runsc release-20260727.0 (48-reground-ci, claim Q2): `runsc
#: install -- --oci-seccomp` writes `runtimeArgs: ["--oci-seccomp"]` into the named runtime's
#: daemon.json entry. X19 is closed; nothing below is authored around a guessed spelling.
OCI_SECCOMP_FLAG = "--oci-seccomp"
RUNSC_INSTALL_CMD = "runsc install -- --oci-seccomp"
DAEMON_RUNTIME_ARGS_KEY = "runtimeArgs"

#: §7 D2's marker, SITED BY §7 D8. ONE artifact carries the scan's verdict, and a tree
#: carrying NO verdict is unverified — that is the fail-closed half of the human's decision,
#: and it is what makes the `tree of a box that never started` pin (§7 H10.2) fall under the
#: same rule rather than needing one of its own.
#:
#: WHERE IT LIVES, AND WHY THAT IS MECHANISM (§7 D8). The marker is a SIBLING of the tree it
#: judges — `<tree>.scrub-verdict.json`, keyed by the tree's own identity — exactly where D7
#: put the alias-refusal record, and for the identical reason. In-tree it was a host-side
#: write into an attacker-owned tree: no census counted it, no lint gated it, the project
#: profile listed that module as a reader only, and the box could both REDIRECT it (plant an
#: alias at the verdict's own name on the crash path, where the walk that would have caught
#: the alias is precisely the walk that did not run) and FORGE it (the box is root on that
#: mount, and the consumer rule fails closed on ABSENCE, never on PRESENCE). A verdict the
#: adversary can author is a verdict that can say "clean".
#:
#: WHAT THE MARKER ASSERTS, AND WHAT IT DOES NOT (§7 D6). `ran: true` says THE WALK COMPLETED
#: — it never says the tree's contents are intact. The scan permits any regular file, so an
#: artifact a box emptied, rewrote or removed is indistinguishable from an untouched one and
#: is detected by nothing in this change. A consumer that reads this marker as a
#: contents-intact claim is reading it wrong, and that misreading is worse than no marker at
#: all: it certifies a destroyed tree as verified.
SCRUB_VERDICT_SUFFIX = ".scrub-verdict.json"

#: The name an in-tree verdict would carry — the siting D8 rejected, and therefore the name a
#: box forges at. Same string as the suffix, a different role: this one is a plant target, and
#: `verdict_is_never_forgeable_from_inside_the_tree` is what keeps a consumer from reading it.
FORGED_IN_TREE_VERDICT_NAME = ".scrub-verdict.json"


# --------------------------------------------------------------------------- #
# Real trees, and real aliases planted in them (tier 1)
# --------------------------------------------------------------------------- #
def run_tree(tmp_path: Path) -> Path:
    """A LIVE run dir — the shape the host-side writers write into while a box is alive.

    Distinct from `test_540_scrub_lifecycle._clean_run_dir`, which is a FROZEN post-run tree
    for the scan to walk. This one carries only what a writer needs to exist beside."""
    run = tmp_path / "run-771"
    (run / "gather_raw" / "l-001").mkdir(parents=True)
    (run / "gather_summaries").mkdir(parents=True)
    (run / "observe").mkdir(parents=True)
    (run / "alert.json").write_text('{"id": "a-771"}\n', encoding="utf-8")
    return run


def worktree_tree(at: Path) -> Path:
    """The SECOND shared root's shape — a curator drain worktree, not a run dir.

    Distinct from `run_tree` in the way that matters to anything walking it: a checked-out
    repo leaf with a corpus directory and a per-mount sentinel, rather than a run dir's
    gather/alert artifacts. A test that claims to cover "either shared root" while building
    a run dir twice under two different names has driven one shape twice."""
    at.mkdir(parents=True, exist_ok=True)
    (at / "defender" / "lessons").mkdir(parents=True)
    (at / "defender" / "lessons" / "lesson-a.md").write_text("# a lesson\n", encoding="utf-8")
    (at / ".box-sentinel-771abc").write_text("token-771\n", encoding="utf-8")
    return at


def outside(tmp_path: Path, name: str = "secret.txt", text: str = "ORIGINAL OUTSIDE\n") -> Path:
    """A file OUTSIDE every shared tree — the redirect target an alias aims a write at.

    Sited as a sibling of the run dir rather than under it, because `run_dir.parent` is where
    the accounting-failure sidecar already lives (X6) and because a target inside `tmp_path`
    keeps the test hermetic."""
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return p


def plant_symlink(at: Path, target: Path) -> Path:
    """Plant a real symlink at `at` pointing at `target`, and RE-PROBE the premise.

    B1/B2/B3/B4 all observed a truncating/append/locked write following exactly this shape.
    The link is created with the real `os.symlink`, so the claim is re-established on every
    run rather than inherited from the ledger."""
    at.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(target, at)
    assert os.path.islink(at), f"the premise did not hold: {at} is not a symlink"
    return at


def plant_dir_symlink(at: Path, target_dir: Path) -> Path:
    """Plant a symlink-to-DIRECTORY at a path COMPONENT the writer will mkdir through.

    B8: `O_NOFOLLOW` on the leaf does not protect a swapped component. B10:
    `mkdir(parents=True, exist_ok=True)` over a symlink-to-directory succeeds SILENTLY. Both
    are re-probed here by construction."""
    at.parent.mkdir(parents=True, exist_ok=True)
    target_dir.mkdir(parents=True, exist_ok=True)
    os.symlink(target_dir, at, target_is_directory=True)
    assert os.path.islink(at), "the planted component is not a symlink"
    assert at.is_dir(), "the planted component does not resolve to a directory"
    return at


def plant_hardlink(at: Path, target: Path) -> Path:
    """Plant a real hard link at `at` aliasing `target`'s inode, and re-probe nlink.

    This is the shape X17/G3 were REFUTED on: `Path.resolve()` does not dereference a hard
    link, so the model's write gate resolves the operand to itself, matches the allowlist, and
    `write_text` truncates the shared inode. B9 observed the same defeat of `O_NOFOLLOW`.

    `os.link` refuses across a mount boundary with EXDEV (R6), so a test that needs this must
    keep both paths on one filesystem — which `tmp_path` guarantees."""
    at.parent.mkdir(parents=True, exist_ok=True)
    os.link(target, at)
    assert os.lstat(at).st_ino == os.lstat(target).st_ino, "the plant is not an alias"
    assert os.lstat(at).st_nlink == 2, "the plant did not raise the target's link count"
    return at


def plant_component_for(writer: Writer, run: Path, outside_dir: Path) -> Path:
    """Replace the directory COMPONENT `writer` will create or traverse with a
    symlink-to-directory pointing outside the tree, and return the planted component.

    `run_tree` pre-creates the components a live run already has, so the plant has to displace
    a real directory rather than appear beside one — which is also the honest shape: the box
    swaps a component it can already see. Only rows whose write mkdirs a component are
    plantable this way (`Writer.mkdirs_component`)."""
    component = (run / writer.artifact).parent
    assert component != run, (
        f"{writer.id}'s artifact sits at the tree root — it has no component to plant at, so "
        f"it is not a mkdirs_component row"
    )
    if component.is_dir() and not component.is_symlink():
        shutil.rmtree(component)
    return plant_dir_symlink(component, outside_dir)


def snapshot_outside(root: Path) -> dict[str, tuple]:
    """Every entry under `root`, WITHOUT dereferencing: relpath -> (type, inode, nlink, bytes).

    The oracle for "the write reached nothing out here". A bare `assert target.read_text() ==
    original` is the vacuous shape this replaces: it is also green when the writer created a
    NEW file beside the target."""
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


# --------------------------------------------------------------------------- #
# Future symbols — referenced LAZILY so HEAD still collects
# --------------------------------------------------------------------------- #
def write_guarded(path: Path, text: str, *, mode: str = "replace", **kw: Any) -> None:
    """`defender._io.write_guarded` — M3's alias-refusing write primitive, and the single seam
    every shared-tree writer routes through. AttributeError at HEAD.

    `mode` names the idiom the caller had: `replace` (the truncating/atomic lane),
    `append` (the JSONL lane) and `update` (the locked read-modify-write lane) are the three
    the census's five idioms collapse to."""
    from defender import _io

    return _io.write_guarded(path, text, mode=mode, **kw)  # type: ignore[attr-defined]


def guarded_mkdir(path: Path, *, base: Path) -> None:
    """`defender._io.guarded_mkdir` — the parents-creating half of M3. Separate from
    `write_guarded` because B8 shows the leaf's own `O_NOFOLLOW` cannot protect a component:
    the rule is stated over the whole call and is DEPTH-AGNOSTIC (firm consensus #13).

    `base` ANCHORS the walk at the shared tree's root, and #13's depth-agnosticism is stated
    BELOW it rather than below `/`. The box's writable mounts start at the tree, so a component
    it can plant is a component under `base`; a symlinked ANCESTOR is a host configuration the
    box cannot influence, and refusing on one refuses everything — `/tmp` is a symlink on
    macOS, which is where the default runs base lives, so an unanchored walk means no run opens
    its session store and every sidecar write degrades to a permanent silent no-op. Required
    keyword-only, so a new call site must NAME the tree it trusts instead of inheriting an
    anchor by default."""
    from defender import _io

    return _io.guarded_mkdir(path, base=base)  # type: ignore[attr-defined]


def sweep_staged(tree: Path) -> list[Path]:
    """`defender._io.sweep_staged` — §7 D1's accepted cost made mechanism.

    An unpredictable staged name means an interrupted write leaves an orphan nothing will ever
    replace by name, so the orphans need a sweep; the human's resolution states the sweep is
    itself a write into the tree and inherits the same primitive."""
    from defender import _io

    return _io.sweep_staged(tree)  # type: ignore[attr-defined]


def allowed_syscalls(profile: dict) -> set[str]:
    """Every syscall name the profile can let through — the names under an `SCMP_ACT_ALLOW`
    rule, whatever that rule's conditions are.

    CONDITIONS ARE DELIBERATELY IGNORED, and the direction of that choice is the point. A
    capability-gated allow (`includes: {caps: [CAP_SYS_ADMIN]}`) counts here as allowed even
    though a box without the capability can never reach it. That OVER-counts the shipped
    profile's surface and equally over-counts the platform default's, so a widening comparison
    built on it can only ever be too strict — it cannot miss a widening, which is the failure
    that matters. A predicate that tried to model the conditions would be a second, unverified
    implementation of dockerd's profile loader sitting inside the assertion."""
    return {
        name
        for rule in profile.get("syscalls", [])
        if rule.get("action") == "SCMP_ACT_ALLOW"
        for name in rule.get("names", [])
    }


def alias_profile_path() -> Path:
    """`box.ALIAS_PROFILE_PATH` — resolved ONCE, so both argv builders carry the identical
    value. Fork R16: a profile-path drift between the two ships one lane without the ban, and
    C8-new made the second builder serve the drain lane AND the learning run-cycle."""
    return box_mod.ALIAS_PROFILE_PATH  # type: ignore[attr-defined]


def ban_not_in_force_error() -> type[BaseException]:
    """`box.AliasBanNotInForce` — §7 D5: the ban fault carries its OWN exception type.

    Taken by the orchestrator and FLAGGED FOR OVERRIDE. It is mechanical rather than a policy
    choice: F4 makes this one startup fault not opt-out-able, and that is only enforceable if
    the fault cannot be caught by the broad `BoxFault` handler every other startup fault
    degrades through. Sharing the class leaves a security-critical caller constructible in
    exactly the state F4 exists to close."""
    return box_mod.AliasBanNotInForce  # type: ignore[attr-defined]


def tree_verified(tree: Path) -> bool:
    """`scrub.tree_verified` — §7 D2's consumer-side rule. A tree whose verdict marker is
    ABSENT reads as unverified, exactly like one marked `ran: false`."""
    from defender.runtime import scrub as scrub_mod

    return scrub_mod.tree_verified(tree)  # type: ignore[attr-defined]


def verdict_sidecar(tree: Path) -> Path:
    """Where §7 D8 sites the scan's verdict: `<tree>.scrub-verdict.json`, a SIBLING of the
    tree, keyed by the tree's own directory name.

    The location is computed here rather than read back from the implementation deliberately.
    A helper that asked the production code where it put the marker would agree with any
    siting the implementer chose, including the in-tree one D8 rejected — the assertion would
    then be about self-consistency instead of about where the artifact landed. This is the
    same discipline `accounting_sidecar`'s callers apply from the other direction: that one
    reads the production path AND the test asserts it is not under the run dir."""
    tree = Path(tree)
    return tree.parent / f"{tree.name}{SCRUB_VERDICT_SUFFIX}"


def read_verdict(tree: Path) -> dict:
    """The scan's verdict as data, or `{}` when no verdict exists for this tree."""
    p = verdict_sidecar(tree)
    if not p.is_file():
        return {}
    return json.loads(p.read_text(encoding="utf-8"))


def write_verdict(tree: Path, doc: dict) -> Path:
    """Hand-write a verdict where the scan would have written it — the test-side stand-in for
    a scan that already ran, used only where the arm being driven is the CONSUMER's."""
    p = verdict_sidecar(tree)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


# --------------------------------------------------------------------------- #
# The docker fault-injection fake (tier 2) — the probe's verdict as DATA
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class ProbeVerdict:
    """One in-box alias-probe outcome, declaratively.

    `allowed` names the banned shapes the box was still able to create — the partial or total
    non-enforcement M2 exists to observe. `create_ok` is the ORDINARY-CREATE control: without
    it a probe that never ran reads identically to a probe that was refused (O2's own
    oracle-can-be-wrong answer, firm consensus #2), and R20 pins an interrupted or truncated
    sequence as FAILED rather than as a pass.

    `cite` is the ledger claim that observed this on a real daemon — never an author guess.
    """

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


#: The enforcing daemon, as observed: every banned shape EPERM, ordinary create/mkdir fine,
#: AF_UNIX bind still succeeding (E1 + X2 + G4 + G6, all executed).
BAN_IN_FORCE = ProbeVerdict(cite="E1,X2,G4")
#: The shipped default with no `--oci-seccomp` registration: every shape succeeds (C1-fix's
#: two-arm probe on real runsc release-20260727.0, and G6 on the platform default).
BAN_ABSENT = ProbeVerdict(allowed=BANNED_SHAPES, cite="E2,G6")


class AliasProbeDocker(RecordingDocker):
    """`RecordingDocker` plus the alias probe's in-box verdict.

    The probe's exec is told apart from the sentinel's by the shape names the probe's own
    argv carries — which is also the observable `probe_set_matches_ban` asserts on, so the
    attempted set is read off the argv rather than off an invented wire format. The fake
    injects the verdict ONLY; it never decides whether a verdict is a fault."""

    def __init__(self, verdict: ProbeVerdict = BAN_IN_FORCE, **kw: Any):
        super().__init__(**kw)
        self.verdict = verdict
        self.probe_argvs: list[list[str]] = []

    def __call__(self, argv, **kw) -> subprocess.CompletedProcess:
        argv = list(argv)
        # WHOLE-TOKEN, not substring. Under the old substring test an unrelated `docker exec`
        # whose argv merely contained the letters "link" was counted as a probe; the token
        # reader requires the shape to be named as itself.
        if (len(argv) > 1 and argv[1] == "exec"
                and shapes_named_in(" ".join(argv)) & set(BANNED_SHAPES)):
            self.calls.append(argv)
            self.probe_argvs.append(argv)
            return self.verdict.as_completed()
        return super().__call__(argv, **kw)

    def probe_count(self) -> int:
        return len(self.probe_argvs)

    def shapes_attempted(self) -> set[str]:
        """The shape set the probe's own argv named, across every probe exec — whole tokens.

        `shapes_named_in` carries the reasoning; the short version is that a substring reader
        cannot tell a six-shape probe from a two-shape one, because two of the six names
        contain the other four between them."""
        return shapes_named_in(" ".join(" ".join(a) for a in self.probe_argvs))


# --------------------------------------------------------------------------- #
# The writer census (C1 as re-derived by C3-fix: >=14 writers, >=5 idioms)
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class Writer:
    """One host-side writer into a shared tree while a box is alive.

    `artifact` is the run-dir-relative name it writes; `invoke` drives the REAL production
    entry point over a run dir, AT THE ALTITUDE WHERE THE SITE'S POSTURE IS DECIDED. That
    altitude is part of the row, not an implementation detail: the sentinel row driven at the
    low-level plant helper measures the helper's error and not the startup fault the design
    cares about, and the lesson-load row driven at the shared appender measures a raise the
    production site swallows.

    `module` is the repo-relative module the write lives in — the lint's hard-gate list is
    DERIVED from this field rather than typed out beside it, because a hand-typed list is how
    the driver's fault-exit write went missing from the gate while staying in the census.

    `posture` carries X5's label WHERE THE LEDGER NAMED THE SITE AT THIS ALTITUDE, and
    `unmeasured` everywhere else. It is documentation, never an expectation: the parity test
    measures each row's today-observable in the test itself (see `POSTURES`), so no row's
    outcome is an author's prior about a site the ledger never looked at. The ledger's four
    MEASURED postures are anchored separately, at X5's own four sites and under X5's own
    faults, by `X5_MEASURED_SITES` below — parity alone cannot see a site that moved in both
    lanes, and re-deriving X5's labels from a census row's altitude is what misattributed two
    of them (see `write_trace`'s row).

    `idiom` names which of the five write idioms it reaches the tree through; `cite` is the
    ledger claim behind the row."""

    id: str
    artifact: str
    idiom: str
    posture: str
    invoke: Callable[[Path], Any]
    module: str
    cite: str = ""
    mkdirs_component: bool = False
    #: True only where landing an EMPTY artifact is the site's contract — the driver's
    #: fault-exit trace write is literally `write_text("")`. The positive control's
    #: anti-vacuity check exempts exactly these rows and no others.
    lands_empty: bool = False


def _invoke_write_trace(run_dir: Path) -> None:
    from defender.runtime import observe, session_store

    store = session_store.open_store(case_id="c-771", runs_base=run_dir.parent / "stores")
    sid = store.new_session("main")
    observe.write_trace(run_dir, store=store, session_id=sid, wall_ms=1.0)


def _invoke_observe_logger(run_dir: Path) -> None:
    from defender.runtime import observe

    # Constructing the logger IS the write: it opens the wire log mode="w", which is the
    # truncating open a planted link redirects (B1's shape at C1's row 3). The budget-refusal
    # record is appended after so the control observes real bytes and not just an empty file.
    # Driven through `wire_log_path` because that is the production entry point since the log
    # moved under `<run>/observe/` — and it carries the row's `guarded_mkdir` of that
    # component, which is what this row's component plant now judges.
    logger = observe.RequestLogger(observe.wire_log_path(run_dir))
    try:
        logger.log_budget_refusal(tool_name="bash")
    finally:
        logger.close()


def _invoke_denial_logger(run_dir: Path) -> None:
    from defender.runtime import observe

    observe.denial_logger(run_dir).log_policy_denial(
        role="main", system="elastic", verb="search", call_id="c1", params={},
    )


def _invoke_case_pointer(run_dir: Path) -> None:
    from defender.runtime import session_store

    session_store.write_case_pointer(run_dir, case_id="c-771", store_path=run_dir / "s.db")


def _invoke_budget_locked(run_dir: Path) -> None:
    from defender.hooks import budget_enforcer

    budget_enforcer.update_budget_locked(run_dir, "r-771", "bash")


def _invoke_breaker(run_dir: Path) -> None:
    from defender.runtime import circuit_breaker

    circuit_breaker.record_outcome(run_dir, "elastic", 2)


def _invoke_query_payload(run_dir: Path) -> Any:
    from defender.runtime import query_tool

    return query_tool._persist_payload(run_dir, "l-001", 0, '[{"a": 1}]')


def _invoke_gather_summary(run_dir: Path) -> None:
    from defender.runtime import tools_gather

    tools_gather._persist_gather_summary(run_dir, "l-001", "## summary\nfindings\n")


def _invoke_claim_lead(run_dir: Path) -> Any:
    from defender.hooks import record_lead

    return record_lead.claim_lead(
        {"run_dir": str(run_dir), "lead_id": "l-001", "goal": "g", "what_to_summarize": ["x"]}
    )


def _invoke_lesson_load(run_dir: Path) -> None:
    # Driven at the PRODUCTION site, not at the shared appender underneath it. The site wraps
    # the append in `except Exception: pass` (best-effort observability), so driving
    # `_io.append_jsonl` directly measures a raise the real call site never lets out — the
    # altitude error F3 names, one row over.
    from defender.agents import MAIN_DEF
    from defender.runtime import tools as runtime_tools
    from defender.runtime.agent_definition import bind

    deps = bind(MAIN_DEF, run_dir, salt="0" * 16, defender_dir=DEFENDER)
    runtime_tools._record_lesson_load(deps, DEFENDER / "lessons" / "spec-771.md")


def _invoke_queries_table(run_dir: Path) -> Any:
    """The query tool's SECOND artifact — the queries table — through its real capture path.

    C1 counts `query_tool` once, and the census drove only its by-ref payload write. One
    writer with two artifacts is one bound edge and two plant targets; the table is the one
    an aliased append lands OUTSIDE the tree, verbatim, on the row it writes."""
    import asyncio
    from dataclasses import replace

    from defender.agents import GATHER_DEF
    from defender.runtime.agent_definition import bind
    from defender.runtime.query_tool import QueryCapture

    deps = replace(bind(GATHER_DEF, run_dir, salt="0" * 16, defender_dir=DEFENDER),
                   lead_id="l-001")
    return asyncio.run(QueryCapture(registry=None)._record(
        deps, system="elastic", verb="search", query_id="elastic.ad-hoc", params={},
        payload=[{"a": 1}], exit_code=0, detail="",
    ))


def _invoke_sentinel_plant(run_dir: Path) -> None:
    """The run-dir sentinel plant — and the plant helper IS where the conversion happens.

    MEASURED, because the altitude question was raised against this row and the answer was not
    the expected one: driven here, a failed write already comes back as a box STARTUP fault and
    not as a plain OSError. So the row sits at the right altitude and the defect was on the
    reading side — the tests that touched it caught `OSError`, which a startup fault is not, so
    the row carrying X5's one fatal posture class ERRORED instead of asserting. `drive_writer`
    catches `BaseException` for exactly that reason.

    Driving `start_box` itself is the wrong instrument here for a second reason: a start that
    SUCCEEDS clears the sentinel again, so the census's "every writer lands its artifact"
    positive control would have nothing left to observe — measured, not assumed."""
    box_mod._plant(run_dir / ".box-sentinel", "token-771")


def _invoke_fault_exit_trace(run_dir: Path) -> None:
    """The DRIVER's fault-exit trace write — `write_text("")` onto the same fixed
    `tool_trace.jsonl` name `observe.write_trace` owns.

    C1's row 2, and one of the two sites the issue itself reported. It went missing from the
    census, from the lint's gate list and from the profile's writer list at once, because all
    three were re-derived by hand from an instrument that only sees the happy-path writer.

    RETURNS NOTHING, like every other census driver whose site has no meaningful return value —
    and that is a fix to the INSTRUMENT, not a relaxation of the demand it feeds. This used to
    hand back the `ReplayFn` the drive built, whose `repr` carries its address; `posture_class`
    keys a return BY VALUE, so two arms of the parity demand could never compare equal on it,
    and no caller ever read it. The row was therefore able to pass on one posture only — a
    RAISE — silently pinning "this site must raise", which is not what the demand states and
    not a claim F1 ever made about this site. `None` in both arms restores the comparison the
    demand asks for; the anti-vacuity guard above (a missing symbol reads as
    `raised:AttributeError`) is what still keeps `None` from meaning "nothing happened"."""
    drive_fault_exit_trace(run_dir)


def _invoke_write_atomic(run_dir: Path) -> None:
    from defender import _io

    _io.write_atomic(run_dir / "budget.json", '{"tool_calls": 1}')


def _invoke_write_guarded(run_dir: Path) -> None:
    write_guarded(run_dir / "report.md", "guarded body\n")


#: The census, one row per `no_write_through_planted_leaf` bind. It is a FLOOR, not a closed
#: list: C1 counted twelve writers in three idioms and was refuted twice (C3-fix, X1/G15), and
#: `writer_the_census_instrument_cannot_see` is the demand that a grep is not a census
#: instrument (firm consensus #17).
#:
#: FIFTEEN ROWS, and the two additions are not bookkeeping. `run_investigation` is the
#: driver's fault-exit trace write — the SECOND of the two sites the original issue reported,
#: dropped by every hand-derived instrument in this change at once (census, lint gate list,
#: project-profile writer list). `query_tool_queries_table` is the second artifact of a writer
#: the census counted once: one bound edge, two plant targets, and the one an aliased append
#: lands outside the tree verbatim.
CENSUS: tuple[Writer, ...] = (
    # MEASURED, and the label the census carried here was wrong. X5's swallow-continue site is
    # `driver._account_executed_call` — the ACCOUNTING call site — not the trace writer, and at
    # this row's own altitude `observe.write_trace` RAISES (IsADirectoryError over a squatted
    # name; the driver is what swallows, one frame up). Re-deriving a ledger label from the
    # nearest census row is how a measurement gets reattached to the wrong site, so this row is
    # `unmeasured` and X5's swallow-continue is anchored where X5 measured it.
    Writer("write_trace", "tool_trace.jsonl", "write_text", "unmeasured",
           _invoke_write_trace, "runtime/observe.py", cite="C1,X10"),
    Writer("run_investigation", "tool_trace.jsonl", "write_text", "unmeasured",
           _invoke_fault_exit_trace, "runtime/driver.py", cite="C1,X10", lands_empty=True),
    Writer("observe_logger", "observe/llm_requests.jsonl", "append-open", "unmeasured",
           _invoke_observe_logger, "runtime/observe.py", cite="C1", mkdirs_component=True),
    Writer("denial_logger", "policy_denials.jsonl", "append-open", "unmeasured",
           _invoke_denial_logger, "runtime/observe.py", cite="C1,G12"),
    Writer("write_case_pointer", "session_store_pointer.json", "write_text", "unmeasured",
           _invoke_case_pointer, "runtime/session_store.py", cite="C1,R4"),
    Writer("budget_enforcer", "budget.json", "locked-rmw", "unmeasured",
           _invoke_budget_locked, "hooks/budget_enforcer.py", cite="B3,X12"),
    Writer("circuit_breaker", "circuit_breaker.json", "locked-rmw", "unmeasured",
           _invoke_breaker, "runtime/circuit_breaker.py", cite="B3,G17"),
    Writer("query_tool", "gather_raw/l-001/0.json", "write_text", "return-none",
           _invoke_query_payload, "runtime/query_tool.py", cite="X5,G15",
           mkdirs_component=True),
    Writer("query_tool_queries_table", "executed_queries.jsonl", "append_jsonl", "unmeasured",
           _invoke_queries_table, "runtime/query_tool.py", cite="C1,G1"),
    Writer("gather_dispatch", "gather_summaries/l-001.md", "write_text", "unmeasured",
           _invoke_gather_summary, "runtime/tools_gather.py", cite="B11,G15",
           mkdirs_component=True),
    # X5's site, and the label is the site's — but the OBSERVABLE is fault-shaped: under X5's
    # own fault (a plain file squatting the parent component) it returns 0, and under this
    # row's fault (a directory squatting the artifact name) the exclusive create reports
    # EEXIST and the site returns 2, i.e. reports a write failure as a DUPLICATE CLAIM. Both
    # are today's behaviour; only the first is what X5 measured, which is why the anchor drives
    # X5's fault rather than reusing this row's.
    Writer("claim_lead", "gather_raw/l-001.lead.json", "excl-create", "return-zero",
           _invoke_claim_lead, "hooks/record_lead.py", cite="X5,C1", mkdirs_component=True),
    Writer("record_lesson_load", "lessons_loaded.jsonl", "append_jsonl", "unmeasured",
           _invoke_lesson_load, "runtime/tools.py", cite="G15"),
    Writer("start_box", ".box-sentinel", "write_text", "fault-startup",
           _invoke_sentinel_plant, "runtime/box.py", cite="X5,G10"),
    Writer("write_atomic", "budget.json", "tmp-then-replace", "unmeasured",
           _invoke_write_atomic, "_io.py", cite="B4,C3-fix"),
    Writer("write_guarded", "report.md", "guarded", "unmeasured",
           _invoke_write_guarded, "_io.py", cite="F1"),
)

#: The four posture CLASSES X5 measured — the reason F1's "every call site keeps the posture
#: it has today" is testable at all, and the thing a collapse-to-one-posture implementation
#: has to break. They are asserted as a SET the census exhibits, never as a per-row
#: expectation: X5 named four sites, the census has fifteen rows, and assigning a label to the
#: other eleven would be an author's prior standing in for a measurement.
POSTURES = ("swallow-continue", "return-none", "return-zero", "fault-startup")


# --------------------------------------------------------------------------- #
# X5's FOUR MEASURED POSTURES — the anchor, at the sites and under the faults the
# ledger actually drove
# --------------------------------------------------------------------------- #
# F1's content is "every call site keeps the posture it has TODAY". Measuring "today" during
# the test run makes the demand vacuous for any site that moves in BOTH lanes — a per-row
# self-comparison is satisfied by an implementation that changed a site consistently. So the
# four postures X5 measured are anchored here, against X5's own probe: its four sites, its
# four faults, and the four observables its `observed:` field records verbatim.
#
# The faults are the ones X5 named — "a directory squatting the staging name, a plain file
# squatting a parent component, an absent bind source" — rebuilt with the real filesystem in
# the test, so the taxonomy assumption is re-probed on every run rather than pinned once. All
# three are root-proof: nothing here simulates an unwritable target with a permission bit.
@dataclass(frozen=True)
class MeasuredSite:
    """One of X5's four call sites, with the fault it was measured under and what it did.

    `site` is the production symbol X5 drove — NOT a census row id. Two of the four are not
    census rows at all, and one (`write_trace`) sits one frame BELOW the site X5 measured,
    which is exactly how its swallow-continue label ended up on the wrong writer."""

    posture: str
    site: str
    fault: str
    drive: Callable[[Path], object]
    #: What X5 recorded. Checked against `posture_class` for the return classes; the
    #: swallow-continue site's second half (the counter advanced) is checked by its own driver.
    observed: str


def _x5_accounting_site(run_dir: Path) -> object:
    """`driver._account_executed_call` — X5's swallow-continue site, under a directory
    squatting the artifact the accounting write lands on.

    Returns the pair the ledger recorded: what the call returned, and whether the silent
    failure counter advanced. "Returns normally" alone is also true of a call that did
    nothing at all."""
    from defender.agents import MAIN_DEF
    from defender.hooks import budget_enforcer
    from defender.runtime import driver
    from defender.runtime.agent_definition import bind

    (run_dir / "budget.json").mkdir()
    deps = bind(MAIN_DEF, run_dir, salt="0" * 16, defender_dir=DEFENDER)
    returned = driver._account_executed_call(
        deps, "bash", active=True, limits=budget_enforcer.DEFAULT_LIMITS)
    advanced = budget_enforcer.accounting_failure_state(run_dir)["consecutive_failures"] > 0
    return (returned, advanced)


def _x5_query_payload_site(run_dir: Path) -> object:
    """`query_tool._persist_payload` — X5's return-none site, under a directory squatting the
    by-ref payload name."""
    from defender.runtime import query_tool

    target = run_dir / "gather_raw" / "l-001" / "0.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    target.mkdir()
    return query_tool._persist_payload(run_dir, "l-001", 0, '[{"a": 1}]')


def _x5_claim_lead_site(run_dir: Path) -> object:
    """`record_lead.claim_lead` — X5's return-zero site, under X5's OWN fault: a plain file
    squatting the parent component, so the sidecar directory cannot be created.

    Not the census row's fault. A directory squatting the artifact NAME makes the exclusive
    create report `EEXIST`, which this site reads as a duplicate claim and answers 2 — a
    different observable, and one that reports a write failure as an id reuse."""
    from defender.hooks import record_lead

    component = run_dir / "gather_raw"
    if component.is_dir():
        shutil.rmtree(component)          # a live run dir already has it; the fault displaces it
    component.write_text("not a directory\n", encoding="utf-8")
    return record_lead.claim_lead(
        {"run_dir": str(run_dir), "lead_id": "l-001", "goal": "g", "what_to_summarize": []})


def _x5_sentinel_site(run_dir: Path) -> object:
    """`box._plant` — X5's fault-startup site, under a directory squatting the sentinel name."""
    (run_dir / ".box-sentinel").mkdir()
    return box_mod._plant(run_dir / ".box-sentinel", "token-771")


X5_MEASURED_SITES: tuple[MeasuredSite, ...] = (
    MeasuredSite("swallow-continue", "driver._account_executed_call",
                 "a directory squatting budget.json", _x5_accounting_site,
                 observed="returned:(None, True)"),
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

#: The modules the lint must HARD-GATE (fork R25) — DERIVED from the census, plus the drain
#: lane's own writers. Typing this list by hand is what dropped `runtime/driver.py` from the
#: gate while the demand still bound its edge, so the derivation is the repair.
CENSUS_MODULES: frozenset[str] = frozenset(w.module for w in CENSUS)
DRAIN_MODULES: frozenset[str] = frozenset({"learning/author/drain.py"})
LINT_HARD_GATED_MODULES: frozenset[str] = CENSUS_MODULES | DRAIN_MODULES


def posture_class(outcome: object) -> str:
    """The observable CLASS of one site's reaction to a failed write.

    Two writes land in the same class iff a caller cannot tell them apart: a raise is keyed by
    its exception type (a startup fault is not an ordinary OSError, and that distinction IS
    X5's fourth class), and a return is keyed by its value. Used to compare a site's reaction
    to an ALIAS refusal against its reaction to an ordinary write failure MEASURED IN THE SAME
    TEST — which is what lets the parity demand cover every census row without inventing a
    posture for the eleven rows X5 never looked at."""
    if isinstance(outcome, BaseException):
        return f"raised:{type(outcome).__name__}"
    return f"returned:{outcome!r}"


def drive_writer_at(site: MeasuredSite, run_dir: Path) -> object:
    """Drive one of X5's measured sites and return its observable, same convention as
    `drive_writer`: the raised exception, or the returned value."""
    try:
        return site.drive(run_dir)
    except BaseException as e:  # noqa: BLE001 — the exception IS the observable
        return e


def drive_writer(writer: Writer, run_dir: Path) -> object:
    """Drive one census writer and return its observable — the raised exception, or the value.

    Catches `BaseException` deliberately: `start_box` converts its write failure into a box
    startup fault, which is NOT an `OSError`, and a test that catches only `OSError` errors out
    on exactly the row carrying X5's fatal posture class instead of asserting about it."""
    try:
        return writer.invoke(run_dir)
    except BaseException as e:  # noqa: BLE001 — the exception IS the observable
        return e


class _StaleVersionStore:
    """A REAL session store whose recorded schema version is bumped past the reader's — so
    every read through `hydrate` refuses, while the run's own writes proceed.

    Not an author-imagined fault: this is the exact condition the store's own
    `_refuse_stale_version` exists for (a file whose last writer used a different schema), and
    it is the only condition under which the driver's fault-exit trace write runs — the branch
    whose own comment says "a broken store must not swallow the artifact entirely". The real
    store is used unchanged; only its recorded version is moved."""

    def __init__(self, inner: Any, *, version: int = 99):
        self._inner = inner
        inner.connection.execute(f"PRAGMA user_version = {version}")

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def drive_fault_exit_trace(run_dir: Path, *, run_id: str = "r-771", salt: str = "0" * 16) -> Any:
    """Drive the REAL `driver.run_investigation` through the committed replay harness with a
    store whose reads refuse, so the FAULT-EXIT trace write runs.

    This is the only production route to `interacts(run_investigation->run_dir)` — C1's row 2,
    the second writer of the one fixed `tool_trace.jsonl` name."""
    from defender.runtime import session_store as ss

    from defender.tests.e2e._replay_harness import ReplayFn, Turn, drive

    def factory(case_id: str, target: Path) -> Any:
        return _StaleVersionStore(
            ss.open_store(case_id=case_id, runs_base=Path(target).parent))

    replay = ReplayFn([Turn(text="done.")])
    drive(run_dir, run_id=run_id, salt=salt, main=replay, store_factory=factory)
    return replay


def drive_normal_exit_trace(run_dir: Path, *, run_id: str = "r-771-happy",
                            salt: str = "0" * 16) -> Any:
    """Drive the REAL `driver.run_investigation` through the committed replay harness with the
    production store, so the NORMAL trace write runs and the fault-exit handler does not.

    The sibling of `drive_fault_exit_trace`, and the reason it exists: both writers live in one
    `try/except` inside the driver, so the only way to observe that the handler leaves a
    completed trace alone is to run the whole thing with nothing broken. Calling
    `observe.write_trace` directly instead exercises a tree the handler was never in."""
    from defender.tests.e2e._replay_harness import ReplayFn, Turn, drive

    replay = ReplayFn([Turn(text="done.")])
    drive(run_dir, run_id=run_id, salt=salt, main=replay)
    return replay


def is_eexist(exc: BaseException) -> bool:
    """`EEXIST` from an exclusive create — B6's observation, and §7 D1's refusal signal."""
    return isinstance(exc, OSError) and exc.errno == errno.EEXIST


# --------------------------------------------------------------------------- #
# §7 D7 — where the alias-refusal record lives, and where it must NOT
# --------------------------------------------------------------------------- #
def accounting_sidecar(run_dir: Path) -> Path:
    """The accounting-failure sidecar — `<run_dir>.accounting_failures.json`, a SIBLING of the
    run dir (X6), outside the bind and outside every box mount.

    §7 D7 sites the alias-refusal record HERE and nowhere else. An in-tree sink would be a
    sixteenth writer into the attacker-controlled tree: absent from the census, absent from
    the lint's gate list, and reachable by the exact plant this change exists to stop — the box
    plants an alias at the record's own name, the record write is refused, and D3's accepted
    cost (a refused write may be swallowed at its site) makes the suppression silent. The
    mechanism that observes the attack would have been suppressible by the attack."""
    from defender.hooks import budget_enforcer

    return budget_enforcer._accounting_failure_path(run_dir)


def alias_refusals(run_dir: Path) -> list[dict]:
    """The refusals recorded in the sidecar, as data. AttributeError/KeyError at HEAD.

    Read back through the sidecar's own file rather than through a new reader, so the test
    observes WHERE the record landed and not merely that some accessor answers."""
    p = accounting_sidecar(run_dir)
    if not p.is_file():
        return []
    return list(json.loads(p.read_text(encoding="utf-8")).get("alias_refusals", []))


# --------------------------------------------------------------------------- #
# The second shared root's own production writers (F6)
# --------------------------------------------------------------------------- #
def quarantine_a_tainted_tree(
    tree: Path, quarantine_dir: Path, *, batch_id: str = "b-771", verdict: dict | None = None,
):
    """Drive #747's REAL quarantine path over a real tainted tree, and return
    `(archive, manifest_doc)` — the manifest of THIS batch, never whatever sorted first.

    The taint is real: a symlink is planted with `os.symlink` and the production `scrub` walks
    it, so the `RunTainted` handed to the preserve step carries findings the production walk
    produced. This is the path §7 D8's accepted cost lands on — quarantine exists to hand a
    human a tainted tree, and under D8 the verdict is no longer inside the thing it hands over.

    TWO REPAIRS, AND BOTH ARE WHAT MADE THE FAIL-CLOSED ARM UNSATISFIABLE BY ANY CORRECT
    IMPLEMENTATION. This helper used to return the manifest by globbing the quarantine
    directory and taking the first entry alphabetically. Both arms of the demand quarantine
    into ONE directory on purpose, and the judged tree's batch id sorts first — so the arm that
    asserts an UNJUDGED tree's manifest records the absence read the JUDGED tree's manifest and
    fired on a real verdict. The manifest is now keyed by the batch id the caller gave, which
    is the name the production code writes it under.

    The second is `verdict`, and it exists because the walk that produces the taint is the same
    walk that writes the tree's verdict: left alone, the "unjudged" tree is judged by this
    helper's own drive before the quarantine step ever sees it. So the arm's premise is
    established BETWEEN the walk and the preserve step — `verdict=None` removes any verdict the
    walk left (an unjudged tree, which is the fail-closed arm's whole condition), and a dict
    writes that verdict where the scan would have. Neither touches what the manifest must say."""
    from defender.learning.core.quarantine import preserve_tainted_tree
    from defender.runtime import scrub as scrub_mod

    os.symlink("/root/.ssh/id_rsa", tree / "stolen.json")
    try:
        scrub_mod.scrub(tree)
    except scrub_mod.RunTainted as taint:
        if verdict is None:
            verdict_sidecar(tree).unlink(missing_ok=True)
        else:
            write_verdict(tree, verdict)
        archive = preserve_tainted_tree(
            tree, quarantine_dir, batch_id=batch_id, branch=f"lessons-{batch_id}",
            label="[771]", taint=taint)
    else:
        raise AssertionError("the planted symlink did not taint the tree — the drive is vacuous")
    manifest = quarantine_dir / f"{batch_id}.json"
    doc = json.loads(manifest.read_text(encoding="utf-8")) if manifest.is_file() else {}
    return archive, doc


def drive_drain_restore(worktree: Path, corpus: Path, snapshot: dict[str, bytes]) -> None:
    """Drive the drain lane's fault-path corpus restore — a REAL second-root production writer.

    X9's shape, executed here rather than described: `mkdir(parents=True, exist_ok=True)` then
    `write_bytes`, over paths composed from snapshot keys, from an `except` around the agent
    call. Both halves redirect at HEAD — a symlink at a snapshot leaf truncates the outside
    file, and a symlink-to-directory at a snapshot key's parent component lands the restored
    blob inside the outside directory."""
    from defender.learning.author import drain

    drain._restore_corpus(worktree, corpus, snapshot)
