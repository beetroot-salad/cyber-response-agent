"""#1279 box-start helpers — NOT a test module. Layouts for the run lane and the request lane,
the publish-root environment, and readers of what a started box actually mounted.

The refusal class is `box.BoxStartConflict`, a `BoxFault` subtype (the name this contract chose;
the design leaves it to the implementer). It is reached at call time, so a missing symbol is a
red at the test, not a collection error."""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defender import box as box_mod
from defender.box._clock import clock_dir
from defender.tests.e2e import _box665 as B
from defender.tests.support.shared._fixture_uuid import fixture_uuid

TENANT = fixture_uuid("tenant:blue")
REQUEST_NAME = "defender-runcycle-1279"

DEPLOYMENT_ENV = "DEFENDER_DEPLOYMENT"
PUBLISH_ROOT_ENV = "DEFENDER_RUN_VISUALIZATIONS_DIR"
ALLOW_ENV = "DEFENDER_ALLOW_UNSANDBOXED"


def conflict_type() -> type:
    """The `BoxFault` subtype of both the O3 overlap and the O6 existing-container refusals."""
    return box_mod.BoxStartConflict


# -- the environment ----------------------------------------------------------------------


def dev_root(monkeypatch: Any, root: Path) -> Path:
    """A dev deployment whose publish root is `root` (the mirror's override), the opt-out unset."""
    monkeypatch.setenv(DEPLOYMENT_ENV, "dev")
    monkeypatch.setenv(PUBLISH_ROOT_ENV, str(root))
    monkeypatch.delenv(ALLOW_ENV, raising=False)
    return root


def non_dev_root(monkeypatch: Any, root: Path) -> Path:
    """Not dev (the variable unset, as in production) with the override still naming `root`."""
    monkeypatch.delenv(DEPLOYMENT_ENV, raising=False)
    monkeypatch.setenv(PUBLISH_ROOT_ENV, str(root))
    monkeypatch.delenv(ALLOW_ENV, raising=False)
    return root


def allow_unsandboxed(monkeypatch: Any) -> None:
    monkeypatch.setenv(ALLOW_ENV, "1")


def dev_default_root(monkeypatch: Any) -> None:
    """A dev deployment with the publish-root override UNSET (the conftest sets it for every
    test), so the root owner's own default resolution answers; the opt-out unset."""
    monkeypatch.setenv(DEPLOYMENT_ENV, "dev")
    monkeypatch.delenv(PUBLISH_ROOT_ENV, raising=False)
    monkeypatch.delenv(ALLOW_ENV, raising=False)


BREAKAGES = ("dangling-gitdir", "main-without-defender")


def fake_main_and_worktree(base: Path, *, broken: str | None = None) -> tuple[Path, Path]:
    """A main checkout (`.git` a directory, a `defender/`) and one worktree of it (`.git` a file
    pointing back, with a `defender/` holding the product check file), written the way git
    leaves them (as test_1084_mirror's layouts). Returns `(main, worktree)`.

    `broken` makes the main checkout undeterminable (A7): "dangling-gitdir" points the worktree's
    `.git` file at an admin dir that does not exist; "main-without-defender" leaves the pointer
    intact but the checkout it leads to has no `defender/`."""
    import shutil

    main, wt = base / "main", base / "trees" / "wt"
    admin = main / ".git" / "worktrees" / "wt"
    admin.mkdir(parents=True)
    (main / "defender").mkdir()
    (admin / "commondir").write_text("../..\n", encoding="utf-8")
    (admin / "gitdir").write_text(f"{wt / '.git'}\n", encoding="utf-8")
    (admin / "HEAD").write_text("ref: refs/heads/wt\n", encoding="utf-8")
    (wt / "defender").mkdir(parents=True)
    (wt / ".git").write_text(f"gitdir: {admin}\n", encoding="utf-8")
    from defender.box._image import HASH_INPUTS

    # What a real start reads back from its code mount: the product check file and the image inputs.
    for name in (box_mod.CODE_CHECK_FILE, *HASH_INPUTS):
        shutil.copyfile(B.DEFENDER / name, wt / "defender" / name)
    if broken == "dangling-gitdir":
        (wt / ".git").write_text(f"gitdir: {base / 'nowhere' / '.git' / 'worktrees' / 'wt'}\n", encoding="utf-8")
    elif broken == "main-without-defender":
        (main / "defender").rmdir()
    elif broken is not None:
        raise ValueError(broken)
    return main, wt


# -- the run lane --------------------------------------------------------------------------


@dataclass(frozen=True)
class RunLane:
    """A run on `base`: `base/runs/<run>` (rw), `base/agent` (the tenant half, ro), the product
    code (ro) and the run clock's directory `base/clocks/<run>` (ro)."""

    base: Path
    run_dir: Path
    agent: Path
    defender_dir: Path = B.DEFENDER
    tenant_id: str = TENANT

    @property
    def clock(self) -> Path:
        return clock_dir(self.run_dir)

    def sources(self) -> dict[str, Path]:
        """Each mount kind's host source, by the name it goes by."""
        return {"run dir": self.run_dir, "defender dir": self.defender_dir,
                "tenant agent": self.agent, "run clock directory": self.clock}

    def start(self, docker: Any, **kw: Any) -> Any:
        return box_mod.start_box(self.run_dir, self.defender_dir, tenant_agent=self.agent,
                                 tenant_id=self.tenant_id, docker=docker, **kw)


def run_lane(base: Path) -> RunLane:
    run_dir = B.make_run_dir(base / "runs")
    agent = base / "agent"
    agent.mkdir(parents=True)
    (agent / ".tenant-id").write_text(f"{TENANT}\n", encoding="utf-8")
    return RunLane(base, run_dir, agent)


# -- the request lane ----------------------------------------------------------------------


@dataclass(frozen=True)
class RequestLane:
    """A caller-composed request on `base`: product code (ro, `code`), a data tree (ro) and a
    writable lane."""

    base: Path
    data: Path
    lane: Path
    code: Path = B.DEFENDER

    def sources(self) -> dict[str, Path]:
        return {"code": self.code, "data": self.data, "writable lane": self.lane}

    def request(self, *, require_sandbox: bool = False, name: str = REQUEST_NAME) -> Any:
        mounts = (
            box_mod.Mount(source=self.code, target=self.code, writable=False, kind="code"),
            box_mod.Mount(source=self.data, target=self.data, writable=False, kind="data"),
            box_mod.Mount(source=self.lane, target=self.lane, writable=True),
        )
        return box_mod.BoxRequest(name=name, mounts=mounts, workdir=B.REPO_ROOT, env={},
                                  require_sandbox=require_sandbox)


def request_lane(base: Path) -> RequestLane:
    data, lane = base / "data-ro", base / "lane-rw"
    data.mkdir(parents=True)
    (data / "entry.txt").write_text("x", encoding="utf-8")
    lane.mkdir(parents=True)
    return RequestLane(base, data, lane)


# -- what a started box mounted --------------------------------------------------------------


def bound_sources(calls: list[list[str]]) -> list[Path]:
    """The bind sources on the (first) `docker run` among `calls`; none when nothing was created."""
    run = next((c for c in calls if len(c) > 1 and c[1] == "run"), None)
    out: list[Path] = []
    for i, token in enumerate(run or []):
        if token == "--mount":
            spec = dict(p.split("=", 1) for p in run[i + 1].split(",") if "=" in p)
            out.append(Path(spec["source"]))
    return out


def created(calls: list[list[str]]) -> bool:
    return any(len(c) > 1 and c[1] == "run" for c in calls)


def removed(calls: list[list[str]]) -> bool:
    return any(c[:3] == ["docker", "rm", "-f"] for c in calls)


def names_path(message: str, path: Path) -> bool:
    """`path` appears as a whole path in `message`, not only as the prefix of a longer one."""
    return re.search(re.escape(str(path)) + r"(?![^\s'\":,)])", message) is not None


def _spellings(path: Path) -> list[Path]:
    return [path.resolve(), path]


def assert_refused_for_overlap(refused: BaseException, *, root: Path, mounts: list[Path],
                               rendered: list[Path]) -> None:
    """`refused` is the non-degradable `BoxFault` subtype, it names the root and at least one of
    the candidate `mounts` (each spelled as given or resolved), and every candidate it names is
    one the box really renders into its argv (`rendered`, from a clear start of the same layout)."""
    assert isinstance(refused, box_mod.BoxFault), type(refused)
    assert isinstance(refused, conflict_type()), f"{type(refused).__name__} is not the subtype"
    said = str(refused)
    assert any(names_path(said, r) for r in _spellings(root)), (
        f"the refusal does not name the root {root}: {said!r}")
    named = [m for m in mounts if any(names_path(said, s) for s in _spellings(m))]
    assert named, f"the refusal names none of the overlapping mounts {mounts}: {said!r}"
    rendered_resolved = {p.resolve() for p in rendered}
    for mount in named:
        assert mount.resolve() in rendered_resolved, (
            f"{mount} is not among the mounts the argv is rendered from: {rendered}")


def overlapping(sources: list[Path], root: Path) -> list[Path]:
    """The sources that contain `root`, are contained by it, or equal it (resolved paths)."""
    r = root.resolve()
    return [s for s in sources if s.resolve() == r or s.resolve().is_relative_to(r)
            or r.is_relative_to(s.resolve())]
