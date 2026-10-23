"""Shared machinery for #1108 P4 slice S-D (drains, writers, revert, connect, credentials).

Nothing here implements P4 policy: it builds a scratch product checkout, seeds queues, records
box requests, wraps the real drain entry in the CLI's stage runner, runs the REAL curator modules
with only their model spawn replaced, and reads git state back. `AppRoleVault` is P3's issuer
fake (`VaultHTTP`) plus OpenBao's AppRole login as its API documents it.

ASSUMED SEAMS (the implementer provides them; see each S-D test file's doc):
  author_drain(paths, *, trigger_author=, client=, identity=, issuer_config=, issuer_transport=,
               start_box=, stop_box=)
  OD16: the drain hands its tick's batch (P3's `Batch`) to every lane entry as `batch=`
  (`trigger_author(..., batch=)`, `run_lead_author(paths, state, run, *, batch, ...)`,
  `run_pitfalls(paths, state, *, batch, ...)`); `paths` stays the product-rooted `LoopPaths`
  (`repo_root` = the product checkout, learning state); the lane's corpus is the batch's draft.
  lead_author_drain(paths, *, run_lead_author=, run_pitfalls=, client=, identity=,
                    issuer_config=, issuer_transport=, start_box=, stop_box=, git_timeout=)
  version_control.issuer_login(tenant, *, issuer_config, transport=None)   # OD4 + transport
ASSUMED SHAPE: the issuer client config is JSON `{"issuer", "ca_cert" (PEM path), "role_id",
"secret_id"}` (`issuer.json`, under `<repo>/playground-issuer/client/` in dev).
"""
from __future__ import annotations

import dataclasses
import importlib
import json
import logging
import shutil
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

import certifi
import httpx

from defender import box as box_mod
from defender._git import REPO_ROOT
from defender.tests.support.learning.curation._drain719 import seed
from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.tenancy.tenant_1108_delivery._identity import ISSUER, VaultHTTP
from defender.tests.tenancy.tenant_1108_delivery._identity import token as issuer_token
from defender.tests.tenancy.tenant_1108_p4._support import git

#: The lesson the fake curator writes, below the corpus dir its config names (the draft's lane).
LESSON_NAME = "p4-drain-lesson.md"
LESSON_PATH = f"agent/lessons/{LESSON_NAME}"
LESSONS_PREFIX = "lessons/"



def drains() -> Any:
    return importlib.import_module("defender.learning.core.drains")


def run_stage(stage) -> int:
    """The CLI's stage runner (`loop.py --author-drain`'s): a systemic fault or configuration
    refusal is logged `critical` and exits 2."""
    from defender.learning.core.cli import _run_stage

    return _run_stage(stage)


def product_repo(tmp_path: Path, *, adapters: tuple[str, ...] = ()) -> Path:
    """A scratch product checkout: a real git repo with a `defender/` tree and one commit, used
    as the drain's `paths.repo_root` (where the legacy drain cut worktrees and committed).
    `adapters`: systems whose shipped adapter module (this checkout's
    `defender/integrations/<system>_adapter.py`) the scratch product carries, for the lanes that
    resolve declared systems and verbs from the product's adapters (adapters stay in the
    product repo, #1172)."""
    from defender.tests.tenancy.tenant_1108_p4._support import DEFENDER

    repo = tmp_path / "product"
    (repo / "defender" / "lessons").mkdir(parents=True)
    (repo / "defender" / "lessons" / "product-era.md").write_text("product era\n", encoding="utf-8")
    (repo / "defender" / "README.md").write_text("scratch product checkout\n", encoding="utf-8")
    if adapters:
        (repo / "defender" / "integrations").mkdir()
        for system in adapters:
            name = f"{system.replace('-', '_')}_adapter.py"
            shutil.copyfile(DEFENDER / "integrations" / name, repo / "defender" / "integrations" / name)
    git(repo, "init", "-b", "main")
    git(repo, "add", "-A")
    git(repo, "commit", "-m", "product checkout")
    return repo


def product_state(repo: Path) -> dict:
    """Everything a product-repo delivery would move: HEAD, every ref, the worktree list, the
    status, and the files under `defender/`."""
    return {
        "head": git(repo, "rev-parse", "HEAD"),
        "refs": git(repo, "for-each-ref", "--format=%(refname) %(objectname)"),
        "worktrees": git(repo, "worktree", "list", "--porcelain"),
        "status": git(repo, "status", "--porcelain", "--untracked-files=all"),
        "files": sorted(str(p.relative_to(repo)) for p in (repo / "defender").rglob("*")),
    }


def drain_paths(t: Any, product: Path) -> Any:
    """The accepted tenant's learning paths over the scratch product checkout (what
    `LoopPaths.for_tenant` builds over `REPO_ROOT`)."""
    from defender.learning.core.config import LoopPaths

    return t.tenant.learning_paths(LoopPaths, repo_root=product)


def queue(paths: Any, rows: list[dict], *, channel: Any = None) -> None:
    from defender.learning.core.state import FINDINGS

    seed(paths, channel if channel is not None else FINDINGS, rows)


_BUILDERS = {
    "author": ("defender.learning.author.lessons.run", "build_author_config"),
    "questioner_curator": ("defender.learning.author.questioner.run", "build_questioner_config"),
}


#: The lanes each drain's box mounts writable, relative to the batch's draft root (OD6).
AUTHOR_DRAFT_LANES = ("agent/lessons", "agent/lessons-questioner")
LEAD_DRAFT_LANES = ("agent/skills",)


def draft_root_of(batch: Any) -> Path:
    """The draft a batch's lane works in (P3's `Batch.draft_root`)."""
    return Path(batch.draft_root)


def draft_lane_trees(batch: Any, lanes: tuple[str, ...]) -> Any:
    """The held mounts over `batch`'s draft lanes (`DrainTrees.open`, as S-H's `draft_trees`):
    the fakes' trees come from the batch the drain handed them, never from `paths` (OD16)."""
    from defender.learning.core.lane_trees import DrainTrees

    root = draft_root_of(batch)
    return DrainTrees.open(tuple(root / lane for lane in lanes))


class CuratorTrigger:
    """The drain's `trigger_author` seam: runs the REAL curator module for the module it is asked
    for, as the default step does (held trees over the batch's draft lanes, the real config
    builder with `batch=`, the module's `run_batch`), with only the model spawn
    (`cfg.invoke_agent`) replaced by `curators[module]`. A module with no fake is recorded and
    not run. Records each call's module, its keywords, the batch and the paths it was handed.

    OD16 ASSUMED SEAM: the drain calls `trigger_author(paths, state, channel, threshold_env,
    module_name, pending_label, *, batch, box, ...)`; the builders take `batch=` (S-H's spelling)."""

    def __init__(self, **curators: Any) -> None:
        self.curators = curators
        self.calls: list[str] = []
        self.handed: list[dict] = []
        self.batches: list[Any] = []
        self.paths_seen: list[Any] = []

    def __call__(self, paths: Any, state: Any, channel: Any, threshold_env: str,
                 module_name: str, pending_label: str, *, batch: Any, **kw: Any) -> None:
        self.calls.append(module_name)
        self.handed.append(dict(kw))
        self.batches.append(batch)
        self.paths_seen.append(paths)
        curator = self.curators.get(module_name)
        if curator is None:
            return
        module, builder = _BUILDERS[module_name]
        mod = importlib.import_module(module)
        box = kw.pop("box", None)
        with draft_lane_trees(batch, AUTHOR_DRAFT_LANES) as trees:
            cfg = getattr(mod, builder)(paths, state=state, trees=trees, box=box, batch=batch,
                                        **kw)
            cfg = dataclasses.replace(cfg, invoke_agent=curator)
            mod.run_batch(hold_committed=True, cfg=cfg, box=box)


class BoxSpy:
    """The drain's `start_box`/`stop_box` seams: records each `BoxRequest` and hands back an
    unboxed executor (the box itself is P3's, tested there)."""

    def __init__(self) -> None:
        self.requests: list[Any] = []
        self.stopped = 0

    def start(self, request: Any, **_kw: Any) -> Any:
        self.requests.append(request)
        return box_mod.unboxed_executor()

    def stop(self, _box: Any, **_kw: Any) -> None:
        self.stopped += 1


def author_drain(t: Any, paths: Any, *, trigger: Any, box: BoxSpy, **seams: Any) -> int:
    """`author_drain` through the stage runner, the tenant's forge fake as its forge client and
    a fresh identity over its issuer fake (login skipped) unless the case passes others."""
    seams.setdefault("client", t.forge.client)
    if "issuer_config" not in seams:
        seams.setdefault("identity", t.vault.identity())
    return run_stage(lambda: drains().author_drain(
        paths, trigger_author=trigger, start_box=box.start, stop_box=box.stop, **seams))


LEAD_PREFIX = "lead-author/"


def lead_author_drain(t: Any, paths: Any, *, box: BoxSpy, **seams: Any) -> int:
    """`lead_author_drain` through the stage runner, as `author_drain` above: the tenant's
    forge fake and a fresh issuer-fake identity unless the case passes others; the lane's work
    steps (`run_lead_author=`, `run_pitfalls=`) as the case gives them (else the defaults)."""
    seams.setdefault("client", t.forge.client)
    if "issuer_config" not in seams:
        seams.setdefault("identity", t.vault.identity())
    return run_stage(lambda: drains().lead_author_drain(
        paths, start_box=box.start, stop_box=box.stop, **seams))


def remote_branches(remote: Path, prefix: str = LESSONS_PREFIX) -> dict[str, str]:
    """`{branch: tip}` of the bare origin's branches under `prefix`."""
    out = git(remote, "for-each-ref", "--format=%(refname:strip=2) %(objectname)",
              f"refs/heads/{prefix}")
    return dict(line.split(" ", 1) for line in out.splitlines() if line)


def touched(cwd: Path, base: str, tip: str) -> list[str]:
    """Every path any commit in `base..tip` touched (git's word, renames off)."""
    out = git(cwd, "log", "--no-renames", "--name-only", "--format=", f"{base}..{tip}")
    return sorted({line for line in out.splitlines() if line})


def drafts_dir(t: Any) -> Path:
    return Path(location_path(t.tenant.tenant_root)) / "drafts"


def draft_entries(t: Any) -> list[str]:
    d = drafts_dir(t)
    return sorted(p.name for p in d.iterdir()) if d.is_dir() else []


def under(path: Path, root: Path) -> bool:
    """`path` is `root` or below it (both resolved)."""
    return Path(path).resolve().is_relative_to(Path(root).resolve())


def critical_text(caplog) -> str:
    return "\n".join(r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR)


def _p4_caught(fn: Callable[[], Any]) -> BaseException | None:
    """`_box1195.caught`, but a drain refusing the P4 seams (`client=`/`identity=`) fails here,
    named, rather than as a downstream observation of a drain that never ran."""
    from defender.tests.support.sandbox._box1195 import caught

    got = caught(fn)
    assert not (isinstance(got, TypeError) and "unexpected keyword" in str(got)), (
        f"the drain does not take the P4 seams yet: {got}")
    return got


#: OpenBao's address as the issuer fake serves it (its identity endpoint is `ISSUER`).
ADDRESS = ISSUER.split("/v1/", 1)[0]
LOGIN_PATH = "/v1/auth/approle/login"
ROLE_ID = "p4-role-id-5a1c"
SECRET_ID = "p4-secret-id-9e7f3b"
CLIENT_TOKEN = "hvs.p4-client-token-0d2a"
#: The dev issuer client config folder the design names (O8): under the repo, outside `defender/`.
DEV_CLIENT_DIR = REPO_ROOT / "playground-issuer" / "client"


def vc() -> Any:
    return importlib.import_module("defender.learning.author.version_control")


class AppRoleVault(VaultHTTP):
    """P3's issuer fake plus OpenBao's AppRole login (see the module doc). Tokens are minted at
    the real clock (`now`), as a production identity checks them against `time.time()`."""

    def __init__(self, tenant: str, *, role_id: str = ROLE_ID, secret_id: str = SECRET_ID) -> None:
        super().__init__(tenant, now=int(time.time()))
        self.role_id, self.secret_id = role_id, secret_id
        self.transport = httpx.MockTransport(self.reply)

    def reply(self, request: httpx.Request) -> httpx.Response:
        if request.url.path == LOGIN_PATH:
            self.calls.append(request)
            try:
                body = json.loads(request.content or b"{}")
            except ValueError:
                body = None
            if request.method != "POST" or body != {"role_id": self.role_id,
                                                    "secret_id": self.secret_id}:
                return httpx.Response(400, json={"errors": ["invalid role or secret ID"]})
            return httpx.Response(200, json={"auth": {
                "client_token": CLIENT_TOKEN, "lease_duration": 600, "renewable": True}})
        if request.headers.get("X-Vault-Token") != CLIENT_TOKEN:
            self.calls.append(request)
            return httpx.Response(403, json={"errors": ["permission denied"]})
        return super().reply(request)

    def logins(self) -> list[dict]:
        return [json.loads(r.content) for r in self.calls if r.url.path == LOGIN_PATH]

    def token_requests(self) -> list[httpx.Request]:
        return [r for r in self.calls if r.url.path != LOGIN_PATH]

    def minted(self) -> str:
        return issuer_token(self.tenant, issued=self.now)


def write_issuer_config(folder: Path, **overrides: Any) -> Path:
    """The issuer client config file (assumed shape, module doc) in `folder`, with a real PEM
    bundle as its CA (certifi's), so building a CA-trusting client from it succeeds."""
    folder.mkdir(parents=True, exist_ok=True)
    ca = folder / "ca.pem"
    shutil.copyfile(certifi.where(), ca)
    doc = {"issuer": ADDRESS, "ca_cert": str(ca), "role_id": ROLE_ID, "secret_id": SECRET_ID,
           **overrides}
    path = folder / "issuer.json"
    path.write_text(json.dumps(doc, indent=2) + "\n", encoding="utf-8")
    return path


# ---------------------------------------------------------------------------------------------
# The lead-author lane's work steps, real code with only the model spawn (and the run's
# extraction) replaced
# ---------------------------------------------------------------------------------------------


class LeadStep:
    """The drain's `run_lead_author` seam: the REAL lead author for one served run
    (`lead_author.run_under_held_queue_lock`, over held trees on the batch's draft skills lane and
    the real `build_lead_author_deps(..., batch=)`), with only the run's extraction
    (`deps.extract`, `deps.build_handoff`, `deps.discover_system_drafts`) and the model spawn
    (`deps.invoke_agent`) replaced. Draft synthesis (`deps.synthesize`) stays real.

    `executed[run_name]` is the run's extracted leads; `edits[run_name]` maps a path under the
    draft's skills lane (`<batch.draft_root>/agent/skills`, taken from the batch the drain
    handed — `paths` stays product-rooted, OD16) to the text the fake model appends there;
    `rc[run_name]` is what the spawn returns after writing (default 0). A non-zero rc is raised
    as `LeadAuthorError`, as the default step does. Records each call's batch and paths.

    ASSUMED SEAMS: `run_lead_author(paths, state, run, *, batch, box, on_done, ...)` (OD16);
    `build_lead_author_deps(paths, *, state, trees, batch)` (S-H);
    `run_under_held_queue_lock(run, *, paths, state, trees, box, on_done, git_timeout=,
    deps=None)` — `deps` given are used as built."""

    def __init__(self, *, executed: dict, edits: dict, rc: dict | None = None) -> None:
        self.executed, self.edits, self.rc = executed, edits, rc or {}
        self.served: list[str] = []
        self.batches: list[Any] = []
        self.paths_seen: list[Any] = []

    def __call__(self, paths: Any, state: Any, run: Any, *, batch: Any, box: Any = None,
                 on_done: Any = None, **kw: Any) -> None:
        from defender.learning.leads import lead_author as la
        from defender.learning.leads.lead_extraction import LeadAuthorError

        name = Path(run.run_dir).name
        self.served.append(name)
        self.batches.append(batch)
        self.paths_seen.append(paths)
        skills_dir = draft_root_of(batch) / LEAD_DRAFT_LANES[0]
        with draft_lane_trees(batch, LEAD_DRAFT_LANES) as trees:
            deps = la.build_lead_author_deps(paths, state=state, trees=trees, batch=batch)

            def spawn(_run_dir: Any, _handoffs: Any, _drafts: Any, *, box: Any = None) -> int:
                for rel, text in self.edits.get(name, {}).items():
                    target = skills_dir / rel
                    target.parent.mkdir(parents=True, exist_ok=True)
                    before = target.read_text(encoding="utf-8") if target.is_file() else ""
                    target.write_text(before + text, encoding="utf-8")
                return self.rc.get(name, 0)

            deps = dataclasses.replace(
                deps, extract=lambda _rd: ([], list(self.executed.get(name, []))),
                build_handoff=lambda *_a, **_k: [{"path": rel} for rel in self.edits.get(name, {})],
                discover_system_drafts=lambda: [], invoke_agent=spawn)
            rc = la.run_under_held_queue_lock(run, paths=paths, state=state, trees=trees,
                                              box=box, on_done=on_done, deps=deps, **kw)
        if rc not in (0, None):
            raise LeadAuthorError(f"lead-author for {name} returned rc={rc}")


class PitfallsStep:
    """The drain's `run_pitfalls` seam: the REAL pitfalls curation (`run_pitfalls` over the
    lane's held trees) with only its model spawn (`invoke=`) replaced by one that appends
    `bullet` to each handed-off surface (`handoff["path"]`, `agent/skills/...` (OD6), under the
    draft root of the batch the drain handed — never a draft-rooted `paths`, OD16). Records the
    handoffs, the `repo_root` the curator handed the spawn, and each call's batch and paths.

    ASSUMED SEAMS: `run_pitfalls(paths, state, *, batch, box, on_curated, ...)` as the drain's
    step (OD16); `pitfalls_curator.run_pitfalls(*, paths, state, trees, batch, invoke, ...)` (S-H)."""

    def __init__(self, bullet: str) -> None:
        self.bullet = bullet
        self.handoffs: list[list[dict]] = []
        self.repo_roots: list[Path] = []
        self.batches: list[Any] = []
        self.paths_seen: list[Any] = []

    def __call__(self, paths: Any, state: Any, *, batch: Any, box: Any = None,
                 on_curated: Any = None, **kw: Any) -> int:
        from defender.learning.leads import pitfalls_curator

        self.batches.append(batch)
        self.paths_seen.append(paths)
        root = draft_root_of(batch)

        def invoke(handoffs: list[dict], *, state: Any, repo_root: Any, box: Any = None) -> int:
            self.handoffs.append(list(handoffs))
            self.repo_roots.append(Path(repo_root))
            for h in handoffs:
                target = root / h["path"]
                target.write_text(target.read_text(encoding="utf-8").rstrip("\n") + "\n"
                                  + self.bullet + "\n", encoding="utf-8")
            return 0

        with draft_lane_trees(batch, LEAD_DRAFT_LANES) as trees:
            return pitfalls_curator.run_pitfalls(paths=paths, state=state, trees=trees,
                                                 batch=batch, invoke=invoke, box=box,
                                                 on_curated=on_curated, **kw)


def executed_lead(query_id: str, *, system: str = "cmdb", verb: str = "get-host",
                  lead_id: str = "l-001") -> Any:
    """One executed lead as the offline extraction yields it (a successful call)."""
    from defender.learning.leads.lead_extraction import ExecutedLead

    return ExecutedLead(
        lead_id=lead_id, query_index=0, is_multi_query=False, entry_index=0,
        query_id=query_id, system=system, verb=verb, params={"host": "h1"},
        raw_command=f"{verb} host=h1", goal_text="who owns h1", what_to_summarize=("owner",),
        raw_ref=None, payload_status="ok", payload_digest="digest-1", error_class=None)


def queued_run(t: Any, paths: Any, label: str) -> Path:
    """A finished run of `t` under its runs folder, with its curation request queued as run end
    files it (`enqueue_curation`'s row: the run's address)."""
    from defender.learning.core.state import LearningState
    from defender.tests.support.learning.core._state1135 import enqueue_case
    from defender.tests.support.sandbox._spec791 import make_run_dir
    from defender.tests.support.shared._fixture_uuid import fixture_uuid

    # The learning root exists as `tenant.py setup` provisions it (the queue opens over it).
    Path(location_path(t.tenant.learning)).mkdir(exist_ok=True)
    runs = Path(location_path(t.tenant.tenant_root)) / "runs"
    runs.mkdir(exist_ok=True)
    run_dir = make_run_dir(runs, name=fixture_uuid(label), disposition="benign")
    with LearningState.open(paths) as state:
        enqueue_case(state, f"case-{label}", run_dir)
    return run_dir
