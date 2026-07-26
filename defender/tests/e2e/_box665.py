"""Shared fakes for the #665 box-delivery spec — NOT a test module (leading underscore
keeps pytest from collecting it). Imported by the `test_665_*` files.

Every fake enters the target through a real injection seam (a `docker=` fn, a `box=`
constructor/param, an injected `start_box`/`stop_box`/`agents`/`branch`) — never a
monkeypatch (`scripts/lint/lint_monkeypatch.py` is a blocking ratcheted gate). No fake
classifies or decides policy; each injects faults ONLY and RECORDS what it received, so
a demand asserts on the captured inbound geography/argv/box rather than a canned answer.

Fault content is DECLARATIVE and cites the ledger claim (see
`spec_graph_665-box-learning-roles.yaml` `claims:`) that observed the exact failure on a
real daemon — never author-imagined (`DockerFault.cite`).

RED-AGAINST-HEAD: the target (box delivery param, the two creation sites, box.py's
`BoxRequest` geography, the mount model) does not exist yet. These helpers reference the
future symbols only INSIDE call sites the tests invoke, so the modules still COLLECT at
HEAD and the tests fail (import at HEAD is clean; the future entry points raise
TypeError/AttributeError until built).
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from defender.runtime import box as box_mod

DEFENDER = Path(__file__).resolve().parents[2]
REPO_ROOT = DEFENDER.parent


# --------------------------------------------------------------------------- #
# Live-daemon skip convention (mirrors test_540_box_boundary.py): the `[live]`
# mechanism-confirmation tests carry the marker to write-code-from-spec's first
# live box run; `-m "not live"` (the gate) never runs them, and under
# docker-outside-of-Docker they skip because bind SOURCES resolve on the daemon
# host, invisible to this process.
# --------------------------------------------------------------------------- #
def _daemon_reachable() -> bool:
    try:
        return subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True, timeout=30,
        ).returncode == 0
    except (OSError, subprocess.SubprocessError):
        return False


def _is_dood() -> bool:
    if not Path("/.dockerenv").exists():
        return False
    probe = subprocess.run(
        ["docker", "info", "--format", "{{.DockerRootDir}}"],
        capture_output=True, text=True, encoding="utf-8", timeout=30,
    )
    root = probe.stdout.strip()
    return probe.returncode == 0 and bool(root) and not Path(root).exists()


_NO_DAEMON = not _daemon_reachable()
_DOOD = (not _NO_DAEMON) and _is_dood()

requires_live_box = pytest.mark.skipif(
    _NO_DAEMON or _DOOD,
    reason=("needs a native docker daemon that can bind this process's filesystem "
            "(no daemon, or docker-outside-of-Docker where bind sources are invisible)"),
)


# --------------------------------------------------------------------------- #
# The declarative docker fault-injection fake — the tier-2 seam of the
# fault-injection hierarchy (the daemon is too expensive/nondeterministic to
# drive host-side, so its faults are data whose content cites the ledger claim
# that observed them on a real box). box.py's REAL argv build + framing run
# unchanged, so a geography demand asserts on `create_argv`.
# --------------------------------------------------------------------------- #
def _cp(rc: int, out: str = "", err: str = "") -> subprocess.CompletedProcess:
    return subprocess.CompletedProcess(args=["docker"], returncode=rc, stdout=out, stderr=err)


def framed(rc: int, out: bytes = b"", err: bytes = b"") -> box_mod.RawExec:
    """A RawExec whose stdout is a WELL-FORMED response frame (the in-box entrypoint ran and
    reported the program's own rc/out/err) — the REAL framing codec still decodes it."""
    return box_mod.RawExec(
        rc=rc, stdout=box_mod.encode_response(box_mod.BoxResult(rc=rc, out=out, err=err)),
        stderr=b"",
    )


class ScriptedTransport:
    """An injected box transport (BoxExecutor(transport=…)): records the frames it received
    and replies from a script. A reply is a RawExec (returned) or a BaseException instance
    (raised — models a transport that could not reach the daemon). Never classifies."""

    def __init__(self, *replies):
        self._replies = list(replies) or [framed(0)]
        self.calls: list = []

    def __call__(self, frame: bytes, *, cwd, timeout) -> box_mod.RawExec:
        self.calls.append((frame, cwd, timeout))
        r = self._replies[min(len(self.calls) - 1, len(self._replies) - 1)]
        if isinstance(r, BaseException):
            raise r
        return r


@dataclass(frozen=True)
class DockerFault:
    """One docker subcommand's declarative failure. `cite` is the ledger claim id that
    OBSERVED this rc/stderr on a real daemon (never an author guess)."""

    rc: int
    stderr: str = ""
    stdout: str = ""
    cite: str = ""


class RecordingDocker:
    """Injectable `docker` fn for `start_box(..., docker=…)`.

    Records every argv and replies with canned `CompletedProcess`. Defaults model a
    healthy daemon: no same-name container running, create succeeds, and the startup
    sentinel reads back — the fake echoes the sentinel file box.py just wrote, so
    `start_box` completes host-side with NO live container and a test can read the
    captured `create_argv`. Faults are injected per subcommand and cite a claim."""

    def __init__(
        self, *, running: bool = False, create: DockerFault | None = None,
        sentinel: DockerFault | None = None, reap: DockerFault | None = None,
        exec_replies: list | None = None,
    ):
        self.running = running          # _is_running → a LIVE same-name container (F3/po4)
        self.create = create            # DockerFault on `docker run` (create)
        self.sentinel = sentinel        # DockerFault on the sentinel exec readback
        self.reap = reap                # DockerFault on `docker rm -f`
        self._exec_replies = list(exec_replies or [])
        self.calls: list[list[str]] = []
        self.create_argv: list[str] | None = None

    def __call__(self, argv, **_kw) -> subprocess.CompletedProcess:
        argv = list(argv)
        self.calls.append(argv)
        sub = argv[1] if len(argv) > 1 else ""
        if sub == "inspect":
            return _cp(0, "running\n") if self.running else _cp(1, "", "No such object\n")
        if sub == "rm":
            f = self.reap
            return _cp(f.rc, f.stdout, f.stderr) if f else _cp(0)
        if sub == "run":
            self.create_argv = argv
            f = self.create
            return _cp(f.rc, f.stdout, f.stderr) if f else _cp(0, "container-id\n")
        if sub == "exec":
            if self.sentinel is not None:
                return _cp(self.sentinel.rc, self.sentinel.stdout, self.sentinel.stderr)
            if self._exec_replies:
                return self._exec_replies.pop(0)
            path = Path(argv[-1])            # sentinel readback: `cat <sentinel>`
            try:
                return _cp(0, path.read_text(encoding="utf-8"))
            except OSError:
                return _cp(1, "", "cat: no such file or directory\n")
        return _cp(0)

    # ---- argv readers (parse the captured `docker run` argv) ----------------
    def _argv(self) -> list[str]:
        assert self.create_argv is not None, "docker create was never invoked"
        return self.create_argv

    def mounts(self) -> list[dict]:
        """Every `--mount type=bind,...` spec on the create argv, as a parsed dict with
        keys source/target/readonly."""
        out: list[dict] = []
        argv = self._argv()
        for i, tok in enumerate(argv):
            if tok == "--mount" and i + 1 < len(argv):
                spec = argv[i + 1]
                parts = dict(
                    p.split("=", 1) for p in spec.split(",") if "=" in p
                )
                out.append({
                    "source": parts.get("source", ""),
                    "target": parts.get("target", ""),
                    "readonly": "readonly" in spec.split(","),
                })
        return out

    def env(self) -> dict[str, str]:
        """The rendered `--env KEY=VALUE` pairs on the create argv."""
        out: dict[str, str] = {}
        argv = self._argv()
        for i, tok in enumerate(argv):
            if tok == "--env" and i + 1 < len(argv):
                k, _, v = argv[i + 1].partition("=")
                out[k] = v
        return out

    def flag_value(self, flag: str) -> str | None:
        argv = self._argv()
        for i, tok in enumerate(argv):
            if tok == flag and i + 1 < len(argv):
                return argv[i + 1]
        return None

    def has_flag(self, flag: str) -> bool:
        return flag in self._argv()

    def tmpfs(self) -> str | None:
        return self.flag_value("--tmpfs")


# --------------------------------------------------------------------------- #
# The future box.py geography seam (O8/M2: callers own the geography, box.py
# renders + validates the boundary). Referenced lazily so HEAD still collects.
# --------------------------------------------------------------------------- #
def Mount(source: Path, target: Path, writable: bool = False):
    """box.Mount(source, target, writable) — future symbol; AttributeError at HEAD."""
    return box_mod.Mount(source=source, target=target, writable=writable)  # type: ignore[attr-defined]


def BoxRequest(*, name: str, mounts, workdir: Path, env, spec=None):
    """box.BoxRequest(name, mounts, workdir, env, spec) — future symbol; the caller-owned
    geography box.py renders. AttributeError/TypeError at HEAD (the boundary is unbuilt)."""
    kw: dict[str, Any] = dict(name=name, mounts=tuple(mounts), workdir=workdir, env=dict(env))
    if spec is not None:
        kw["spec"] = spec
    return box_mod.BoxRequest(**kw)  # type: ignore[attr-defined]


def start_box_request(request, *, docker):
    """Drive the future box.py render/create over a caller-composed BoxRequest.
    box.start_box(request, docker=…) — signature change (M2); TypeError at HEAD."""
    return box_mod.start_box(request, docker=docker)  # type: ignore[call-arg]


# --------------------------------------------------------------------------- #
# Composition-frame seams: run_one / _run_worktree_batch gain injectable
# `start_box`/`stop_box` (matching box.py's own names) so a test observes the
# box's creation geography, its delivery to the roles, and its teardown order
# WITHOUT a live daemon. These are part of the contract (the design gives box
# creation no observation seam — pin it). TypeError at HEAD (no such kwarg).
# --------------------------------------------------------------------------- #
@dataclass
class FakeBox:
    """A stand-in BoxExecutor a creation seam produced — identity is what tests assert."""

    name: str = "box-665"
    request: Any = None
    sandboxed: bool = True


class BoxLifecycleRecorder:
    """Injectable `start_box`/`stop_box` pair. `start_box(request)` records the composed
    geography and returns a FakeBox; `stop_box(box)` records teardown order (and can fault
    to model a failed teardown — F13/dec8). Records nothing about policy."""

    def __init__(self, *, stop_fault: Exception | None = None, events: list | None = None):
        self.requests: list = []
        self.boxes: list[FakeBox] = []
        self.stopped: list[FakeBox] = []
        self.scrubbed: list = []
        self.events: list[str] = events if events is not None else []
        self._stop_fault = stop_fault

    def start_box(self, request, *_a, **_kw) -> FakeBox:
        b = FakeBox(name=getattr(request, "name", "box-665"), request=request)
        self.requests.append(request)
        self.boxes.append(b)
        self.events.append(f"start:{b.name}")
        return b

    def stop_box(self, box, *_a, **_kw) -> None:
        self.events.append(f"stop:{getattr(box, 'name', '?')}")
        self.stopped.append(box)
        if self._stop_fault is not None:
            raise self._stop_fault

    def scrub(self, path, *_a, **_kw) -> None:
        """Injectable `scrub=` seam (the S7 tree scan) — records its ORDER in the shared
        event log relative to stop_box (rw bind released) and finish_batch (commit+push).
        Records only order; the scan's own tainting-entry behavior is pinned separately by
        box_mod.scrub over a real tree. TypeError at HEAD (no such kwarg on _run_worktree_batch)."""
        self.events.append(f"scrub:{path}")
        self.scrubbed.append(path)

    def only_request(self):
        assert len(self.requests) == 1, (
            f"expected exactly ONE box created for the invocation, got {len(self.requests)}"
        )
        return self.requests[0]


class RecordingSubagents:
    """Fake `Subagents` recording the box each bash-reaching method received (the future
    per-call `box=` param, R1). Returns a SKIP story from actor/actor_benign so `run_one`
    persists and completes WITHOUT reaching the oracle/judge LLM stages (the SKIP branch of
    run_direction). Records nothing but delivery."""

    def __init__(self, *, actor_fault: Exception | None = None):
        self.actor_box: Any = None
        self.actor_benign_box: Any = None
        self.judge_box: Any = None
        self.calls: list[str] = []
        self._actor_fault = actor_fault

    def actor(self, run_dir, learning_run_dir, *, box=None) -> str:
        self.calls.append("actor")
        self.actor_box = box
        if self._actor_fault is not None:
            raise self._actor_fault
        return "SKIP: spec fake — no story"

    def actor_benign(self, run_dir, learning_run_dir, alert_rule_key, *, box=None) -> str:
        self.calls.append("actor_benign")
        self.actor_benign_box = box
        return "SKIP: spec fake — no story"

    def oracle(self, run_dir, actor_story_path, learning_run_dir) -> str:
        self.calls.append("oracle")
        return "projections: []\n"

    def judge(self, wiring, run_dir, actor_story_path, projected_telemetry_path,
              learning_run_dir, *, box=None) -> str:
        self.calls.append("judge")
        self.judge_box = box
        return "classification: skip-passthrough\nfindings: []\n"


class RecordingBranch:
    """Fake `AuthorBranch` recording the worktree lifecycle order relative to box teardown.
    `start_batch` mints a real temp leaf dir; `finish_batch` is the supply-chain step
    (commit+push+PR) whose ordering vs box teardown S7 pins."""

    def __init__(self, worktree_base: Path, *, branch_prefix: str = "lessons/",
                 events: list | None = None):
        self.branch_prefix = branch_prefix
        self._base = worktree_base
        self.events: list[str] = events if events is not None else []
        self.finished: list[str] = []

    def open_pr_exists(self) -> bool:
        self.events.append("open_pr_exists")
        return False

    def start_batch(self, batch_id: str) -> Path:
        wt = self._base / f"{self.branch_prefix.rstrip('/').replace('/', '-')}-{batch_id}"
        wt.mkdir(parents=True, exist_ok=True)
        self.events.append(f"start_batch:{batch_id}")
        return wt

    def finish_batch(self, batch_id: str, wt: Path) -> str | None:
        self.events.append(f"finish_batch:{batch_id}")
        self.finished.append(batch_id)
        return f"https://example/pr/{batch_id}"

    def cleanup(self, wt: Path) -> None:
        self.events.append("cleanup")


# --------------------------------------------------------------------------- #
# run_dir / learning setup + provider-key satisfaction for driving run_one.
# --------------------------------------------------------------------------- #
def make_run_dir(tmp_path: Path, *, disposition: str = "inconclusive",
                 gather_raw: bool = True) -> Path:
    """A finished defender run dir run_one accepts: alert.json + report.md (its
    disposition drives which direction legs dispatch) + investigation.md + gather_raw/.
    `gather_raw=False` omits the evidence dir (the legitimately-absent conditional-mount
    case, decision 9)."""
    run_dir = tmp_path / "inv-665"
    run_dir.mkdir(parents=True)
    if gather_raw:
        (run_dir / "gather_raw").mkdir()
    (run_dir / "alert.json").write_text('{"rule": {"key": "spec.rule"}}\n', encoding="utf-8")
    (run_dir / "report.md").write_text(
        f"---\ndisposition: {disposition}\n---\n\nspec run\n", encoding="utf-8"
    )
    (run_dir / "investigation.md").write_text("+ spec investigation\n", encoding="utf-8")
    return run_dir


def loop_paths(tmp_path: Path):
    from defender.learning.core.config import LoopPaths

    repo = tmp_path / "repo"
    (repo / "defender").mkdir(parents=True, exist_ok=True)
    return LoopPaths(repo_root=repo, state_dir=tmp_path / "state")


def drive_run_one(tmp_path, monkeypatch, rec, *, agents=None, disposition="inconclusive",
                  gather_raw=True, **kw):
    """Drive the REAL run_one with the future injectable start_box/stop_box seams. TypeError
    at HEAD (no such kwargs); the recorder captures the composed run-cycle box request."""
    from defender.learning.core.orchestrate import run_one

    satisfy_engine_keys(monkeypatch, disposition)
    run_dir = make_run_dir(tmp_path, disposition=disposition, gather_raw=gather_raw)
    return run_one(
        run_dir, paths=loop_paths(tmp_path), agents=agents or RecordingSubagents(),
        start_box=rec.start_box, stop_box=rec.stop_box, **kw,
    )


def drive_worktree_batch(tmp_path, rec, *, do_work, has_work=None, branch=None,
                         label="author_drain", **kw):
    """Drive the REAL _run_worktree_batch with the future injectable box seams."""
    from defender.learning.core.orchestrate import _run_worktree_batch

    paths = loop_paths(tmp_path)
    branch = branch or RecordingBranch(tmp_path / "wt", events=rec.events)
    return _run_worktree_batch(
        paths, branch, label=label, has_work=has_work or (lambda p: True), do_work=do_work,
        start_box=rec.start_box, stop_box=rec.stop_box, scrub=rec.scrub, **kw,
    )


def _path_matches(value, needle: str) -> bool:
    """Does `value` (a path) match `needle`?

    An ABSOLUTE needle matches by path identity (it, or a tree under it). A RELATIVE needle
    is a run of whole path COMPONENTS and must match component-wise — never a bare substring.
    The substring spelling was non-discriminating in the false-POSITIVE direction: pytest names
    `tmp_path` after the test function, so under `test_gather_raw_.../` every mount's path
    contains the literal "gather_raw" and `mount_for(req, "gather_raw")` answered with an
    unrelated mount instead of None. Same distinction the gate draws at
    runtime/permission/files.py:222-228 (the `gather_raw` path component vs. the word).

    A MULTI-component relative needle ("defender/skills") is matched as a contiguous run of
    components. Testing the raw needle string against `p.parts` could never match one, so an
    `is None` assertion over such a needle would pass vacuously.
    """
    p = Path(str(value))
    n = Path(needle)
    if n.is_absolute():
        return p == n or p.is_relative_to(n)
    want, have = n.parts, p.parts
    if not want:
        return False
    return any(
        have[i:i + len(want)] == want for i in range(len(have) - len(want) + 1)
    )


def mount_for(request, needle: str):
    """The Mount on `request` whose source or target matches `needle` (None if unmounted).

    `needle` is an absolute path (matched by identity) or a single path component (matched
    whole — see `_path_matches`).
    """
    for m in getattr(request, "mounts", ()):
        if _path_matches(getattr(m, "source", ""), needle) or \
                _path_matches(getattr(m, "target", ""), needle):
            return m
    return None


def satisfy_engine_keys(monkeypatch, disposition: str = "inconclusive") -> None:
    """Give `run_one`'s `_prepare_engines_for` an ambient provider key per direction model
    so key-sourcing does not FatalConfigError before the box seam is reached (setenv, not
    setattr — the sanctioned env seam)."""
    from defender.learning.core.config import ORACLE_MODEL
    from defender.learning.core.directions import BY_NAME
    from defender.learning.core.orchestrate import _directions_for
    from defender.runtime import providers

    models = {ORACLE_MODEL}
    for name in _directions_for(disposition):
        d = BY_NAME[name]
        models.add(d.judge_wiring.model)
        models.add(d.actor_model)
    for model in models:
        try:
            var = providers.provider_for(model).api_key_var
        except Exception:  # noqa: BLE001 — best-effort; a red test does not depend on it
            continue
        monkeypatch.setenv(var, "spec-test-key")
