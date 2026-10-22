"""Slice S-B's local helpers (run start + launch-time publish child), built on S0's `_support`.

Nothing here implements P4 policy: it launches `run.main` through its seams, records what the
seams were handed, and spells the outcome vocabulary ONCE so a representation change is one
edit. Underscore-prefixed: pytest collects no tests from it.

ASSUMED SEAMS (reported; the implementer provides them):

- `run.main(argv, *, publish=...)` (design O11). `publish` is called once per unpinned launch
  and returns the child's report line (orchestrator decision): `"fresh <commit>"`,
  `"stale:transient <reason>"`, `"stale:operator <reason>"`. Misconfiguration (no issuer config
  file, no forge binding) is reported on the same channel as `"misconfigured <reason>"` (this
  slice's pick: one text channel between the child process and the parent), and the parent
  refuses the run on it. What the parent passes `publish` is only identifiers (the tenant id and
  the data root); the tests below never depend on positional vs keyword.
- `run.py --knowledge-commit <sha>` (O-PIN): starts on `<T>/exports/<sha>/`, skips `publish`.
- The child's in-process entry (O11 "the child is tested in-process against P3's fake forge"):
  `defender.learning.author.version_control.publish_for_run(tenant_id, *, data_root,
  issuer_config: Path, client=None, identity=None, network_timeout=None) -> str` — accepts the
  tenant itself from id + data root, reads the tenant row's forge binding and the issuer config
  file itself (misconfiguration decided before any network call, whatever is injected), logs in
  through `issuer_login(tenant, issuer_config=...)` (OD4) unless `identity=` is injected (the
  in-process stand-in for the login, as S-C's `tenant.py update` takes it), opens P3's
  `TenantDelivery` with `client=` (the forge client) and publishes, and returns the report line.
"""
from __future__ import annotations

import contextlib
import functools
import importlib
import io
import json
import os
import re
import shutil
import sys
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.tenancy.tenant_1108_p4._support import published_tenant

#: The lead-zero template the fixture's `settings/lead-zero.yaml` names (S0's fixture `agent/`
#: carries it; the product catalog has its own copy).
CORRELATE_PATH = "agent/skills/gather/queries/elastic/correlate-alerts-by-entity.md"
CORRELATE_ID = "elastic.correlate-alerts-by-entity"

#: A lesson whose bytes change between the seeded commit and a later merge, so "which revision
#: did the run read" is answerable from content alone.
LESSON = "agent/lessons/fixture-owner-before-close.md"
LESSON_REL = "lessons/fixture-owner-before-close.md"
SEEDED_MARK = "S-B-SEEDED-REVISION-MARK"
MERGED_MARK = "S-B-MERGED-REVISION-MARK"
CLONE_ONLY_MARK = "S-B-CLONE-WORKTREE-ONLY-MARK"


def lesson_text(mark: str) -> str:
    return ("---\nname: fixture-owner-before-close\ndescription: Made-up fixture lesson "
            f"{mark} - look up the host's inventory owner before closing.\n"
            "telemetry_source: [cmdb]\nattack_phase: [discovery]\n"
            "source_signature: [fixture-unclaimed-host]\nsource_finding_ids:\n"
            "  - fixture-run-1/1\ncreated_at: 2026-10-01T00:00:00Z\n---\n\n"
            f"Fixture content for tests (#1108 P4). {mark}\n")


#: Settings marker: the cmdb system's `config.env` gains a key whose value names the revision.
CMDB_ENV = "settings/systems/cmdb/config.env"
MARK_KEY = "CMDB_S_B_REVISION_MARK"


def cmdb_env(mark: str) -> str:
    from defender.tests.tenancy.tenant_1108_p4._support import FIXTURE_SETTINGS

    base = (FIXTURE_SETTINGS / "systems" / "cmdb" / "config.env").read_text(encoding="utf-8")
    return base + f'\n{MARK_KEY}="{mark}"\n'


SEED_FILES = {LESSON: lesson_text(SEEDED_MARK), CMDB_ENV: cmdb_env(SEEDED_MARK)}
MERGE_FILES = {LESSON: lesson_text(MERGED_MARK), CMDB_ENV: cmdb_env(MERGED_MARK)}


@contextlib.contextmanager
def run_tenant(tmp_path: Path, data_root: Path, **kw: Any) -> Iterator[Any]:
    """S0's `published_tenant` with the revision marks above written over the fixture."""
    files = {**SEED_FILES, **kw.pop("files", {})}
    with published_tenant(tmp_path / "forge", root=data_root, files=files, **kw) as t:
        yield t


# --- the outcome vocabulary, spelled once -----------------------------------------------------

def fresh(commit: str) -> str:
    return f"fresh {commit}"


def stale(kind: str, reason: str) -> str:
    assert kind in ("transient", "operator"), kind
    return f"stale:{kind} {reason}"


def misconfigured(reason: str) -> str:
    return f"misconfigured {reason}"


OUTCOME_CLASSES = ("fresh", "stale:transient", "stale:operator", "misconfigured")


def outcome_class(line: object) -> str:
    """The class of a child report line (its first word), asserted to be one of the vocabulary."""
    assert isinstance(line, str), f"the child's outcome is not a report line: {line!r}"
    head, _, _rest = line.partition(" ")
    assert head in OUTCOME_CLASSES, f"not an outcome of the design's vocabulary: {line!r}"
    return head


def outcome_detail(line: str) -> str:
    return line.partition(" ")[2].strip()


# --- paths ------------------------------------------------------------------------------------

def tenant_root(t: Any) -> Path:
    return Path(location_path(t.tenant.tenant_root))


def run_copies(t: Any) -> Path:
    """`<T>/run-knowledge/` (design data model)."""
    return tenant_root(t) / "run-knowledge"


def clone_dir(t: Any) -> Path:
    return Path(t.clone)


def tree_bytes(root: Path) -> dict[str, bytes]:
    root = Path(root)
    return {p.relative_to(root).as_posix(): p.read_bytes()
            for p in sorted(root.rglob("*")) if p.is_file() and not p.is_symlink()}


def export_half(t: Any, commit: str, half: str) -> dict[str, bytes]:
    from defender.tests.tenancy.tenant_1108_p4._support import export_dir

    return tree_bytes(export_dir(t.tenant, commit) / half)


# --- issuer config (assumed shape; the design fixes only the folder) --------------------------

ISSUER_SECRET_ID = "s-b-secret-id-5f0c1a9e-never-in-a-run"
ISSUER_ROLE_ID = "s-b-role-id-0d3e"


def write_issuer_config(where: Path) -> Path:
    """An issuer client config FILE under `<where>/playground-issuer/client/` (design O8: dev
    path). ASSUMED SHAPE (reported): JSON `{issuer, ca_cert, role_id, secret_id}`."""
    from defender.tests.tenancy.tenant_1108_delivery._identity import ISSUER

    client = Path(where) / "playground-issuer" / "client"
    client.mkdir(parents=True, exist_ok=True)
    ca = client / "ca.pem"
    ca.write_text("-----BEGIN CERTIFICATE-----\nZml4dHVyZQ==\n-----END CERTIFICATE-----\n",
                  encoding="utf-8")
    path = client / "issuer.json"
    path.write_text(json.dumps({"issuer": ISSUER, "ca_cert": str(ca), "role_id": ISSUER_ROLE_ID,
                                "secret_id": ISSUER_SECRET_ID}, indent=2), encoding="utf-8")
    return path


def child_entry() -> Callable[..., str]:
    """The child's in-process entry (assumed seam, see module doc). Imported lazily."""
    vc = importlib.import_module("defender.learning.author.version_control")
    return vc.publish_for_run


def run_child(t: Any, issuer_config: Path, *, identity: Any = None, client: Any = None,
              **kw: Any) -> str:
    """The real child, in-process, against P3's fakes: forge client and (unless given) a fresh
    identity over the issuer fake (`t.vault`, so a fault set there is seen)."""
    return child_entry()(
        t.tenant_id, data_root=t.data_root, issuer_config=issuer_config,
        client=client if client is not None else t.forge.client,
        identity=identity if identity is not None else t.vault.identity(), **kw)


# --- run.main ---------------------------------------------------------------------------------

def plant_alert(where: Path) -> Path:
    where.mkdir(parents=True, exist_ok=True)
    path = where / "alert.json"
    path.write_text(json.dumps({"rule": {"id": "r-s-b", "description": "slice S-B fixture"},
                                "alert_timestamp": "2026-10-20T00:00:00Z"}), encoding="utf-8")
    return path


@dataclass
class Seen:
    """What the lifecycle seam saw, read WHILE the run was live (the copy is removed after)."""
    kw: dict[str, Any]
    run_dir: Path
    agent: Path
    settings: Path
    agent_files: dict[str, bytes]
    settings_files: dict[str, bytes]
    stamp: dict[str, Any] | None
    copies_listing: list[str]
    environ: dict[str, str]
    during: Any = None


@dataclass
class Launch:
    rc: int | None = None
    refusal: str | None = None
    raised: BaseException | None = None
    publish_calls: list[tuple[tuple, dict]] = field(default_factory=list)
    seen: list[Seen] = field(default_factory=list)
    stamp_after: dict[str, Any] | None = None
    run_dir: Path | None = None

    @property
    def reached(self) -> bool:
        return bool(self.seen)

    def text(self) -> str:
        return f"rc={self.rc!r} refusal={self.refusal!r} raised={self.raised!r}"


def read_stamp(run_dir: Path) -> dict[str, Any] | None:
    from defender.run_repository import RunPaths

    path = RunPaths(run_dir).provenance
    if not path.is_file():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def launch(t: Any, tmp_path: Path, *, publish: Callable[..., Any] | None,
           argv_extra: tuple[str, ...] = (), during: Callable[[Seen], Any] | None = None,
           lifecycle: Callable[..., Any] | None = None, alert_dir: Path | None = None,
           **seams: Any) -> Launch:
    """`run.main` for `t` with the REAL `materialize` (run start: resolve the export, copy,
    stamp) and a recording lifecycle that snapshots the run's tenant and copy while live.
    `publish=None` passes no publish seam (a pinned launch must not need one)."""
    from defender import run as run_py

    out = Launch()

    def recording_lifecycle(**kw: Any) -> dict[str, Any]:
        run_dir = Path(kw["run"].run_dir)
        tenant = kw["tenant"]
        agent, settings = Path(tenant.agent), Path(tenant.settings)
        copies = run_copies(t)
        seen = Seen(kw=kw, run_dir=run_dir, agent=agent, settings=settings,
                    agent_files=tree_bytes(agent) if agent.is_dir() else {},
                    settings_files=tree_bytes(settings) if settings.is_dir() else {},
                    stamp=read_stamp(run_dir),
                    copies_listing=sorted(os.listdir(copies)) if copies.is_dir() else [],
                    environ=dict(os.environ))
        out.seen.append(seen)
        if during is not None:
            seen.during = during(seen)
        if lifecycle is not None:
            return lifecycle(**kw)
        return {"output": "s-b", "requests": 0, "truncated_by": None}

    def recording_publish(*args: Any, **kwargs: Any) -> Any:
        out.publish_calls.append((args, kwargs))
        assert publish is not None
        return publish(*args, **kwargs)

    alert = (alert_dir / "alert.json") if alert_dir is not None else plant_alert(tmp_path / "alert")
    argv = [str(alert), "--tenant", t.tenant_id, "--no-learn", *argv_extra]
    kwargs: dict[str, Any] = {
        "lifecycle": recording_lifecycle, "preflight": lambda *a, **k: 0,
        "visualize": lambda *a, **k: None, "enqueue": lambda *a, **k: False, **seams}
    if publish is not None:
        kwargs["publish"] = recording_publish
    err = io.StringIO()
    try:
        with contextlib.redirect_stderr(err):
            out.rc = run_py.main(argv, **kwargs)
    except SystemExit as exit_:
        # argparse exits with a code and writes its reason to stderr: keep both.
        out.refusal = f"{exit_.code}\n{err.getvalue()}".strip()
    except Exception as e:  # noqa: BLE001 — kept for the assertions to name
        out.raised = e
    if out.seen:
        out.run_dir = out.seen[0].run_dir
        out.stamp_after = read_stamp(out.run_dir)
    return out


def knowledge_source(stamp: dict[str, Any] | None) -> dict[str, Any]:
    assert stamp is not None, "the run has no provenance stamp"
    source = stamp.get("knowledge_source")
    assert isinstance(source, dict), (
        f"O-STALE: the run record carries no `knowledge_source`: {sorted(stamp)}")
    return source


def stamped_commit(stamp: dict[str, Any] | None) -> Any:
    assert stamp is not None, "the run has no provenance stamp"
    return stamp.get("knowledge")


#: Environment keys an issuer/login value could ride in (P-4: never environment).
ISSUER_ENV = re.compile(r"BAO|VAULT|OPENBAO|ISSUER|APPROLE|ROLE_ID|SECRET_ID|FORGEJO_TOKEN",
                        re.IGNORECASE)


def flat_values(value: Any) -> list[Any]:
    """Every leaf of a nested args/kwargs structure."""
    if isinstance(value, dict):
        return [leaf for k, v in value.items() for leaf in (*flat_values(k), *flat_values(v))]
    if isinstance(value, (list, tuple, set, frozenset)):
        return [leaf for v in value for leaf in flat_values(v)]
    return [value]


def python() -> str:
    return sys.executable


def rmtree(path: Path) -> None:
    shutil.rmtree(path, ignore_errors=True)



# --- e2e: run.main over the real driver with replay models ------------------------------------

def drive_main(  # noqa: PLR0913 — the e2e entry: one keyword per seam
        t: Any, tmp_path: Path, monkeypatch: Any, *, main: Any, gather: Any = None,
        orient_shim: Any = None, publish: Callable[..., Any] | None = None,
        signature: str = "r-s-b", during: Callable[[Seen], Any] | None = None,
        publish_seam: bool = True) -> Launch:
    """`run.main` end to end: real `materialize`, production's lifecycle with production's
    `start_box` in its unsandboxed opt-out (no daemon, `DEFENDER_ALLOW_UNSANDBOXED=1`, as the
    replay harness reaches it), and the REAL driver over replay models
    (`investigate_as_handed`). `signature` is the alert's `rule.id` (the run's signature)."""
    from defender import box as box_mod
    from defender import run as run_py
    from defender.tests.e2e import _replay_harness as RH

    monkeypatch.setenv("DEFENDER_ALLOW_UNSANDBOXED", "1")
    monkeypatch.delenv(box_mod.BoxSpec.ENV_VAR, raising=False)
    final = RH.investigate_as_handed(main, gather, orient_shim=orient_shim)
    investigate = functools.partial(run_py._drive_investigation, investigate=final)
    lifecycle = functools.partial(
        run_py._run_investigation_lifecycle, investigate=investigate,
        start_box=functools.partial(box_mod.start_box, docker=RH._no_docker_daemon))
    alert_dir = tmp_path / "alert"
    alert_dir.mkdir(parents=True, exist_ok=True)
    (alert_dir / "alert.json").write_text(json.dumps({
        "rule": {"id": signature, "description": "slice S-B e2e"},
        "alert_timestamp": "2026-10-20T00:00:00Z"}), encoding="utf-8")
    if publish is None:
        commit = t.commit

        def publish(*_a: Any, **_k: Any) -> str:
            return fresh(commit)
    # `publish_seam=False` drives today's `main` (no seam) — machinery checks only.
    return launch(t, tmp_path, publish=publish if publish_seam else None,
                  lifecycle=lifecycle, during=during,
                  alert_dir=alert_dir)


# --- O-BUDGET parent half (OD11) --------------------------------------------------------------
#
# ASSUMED SEAMS (reported):
# - the parent launcher, the callable the CLI binds to `run.main(publish=...)`:
#   `defender.run.launch_publish(tenant_id, *, data_root, budget: float = 60.0,
#   command: Sequence[str] | None = None) -> str` — spawns the child process (`command`
#   replaces the default argv prefix of the real child's process entry; the parent appends its
#   own arguments after it), waits up to `budget` seconds while the child is in its network
#   phase, never kills a child that holds the tenant lock, and returns the report line
#   (`stale:transient <reason>` when it stopped waiting).
# - the real child's process entry: `defender.learning.author.version_control.publish_child_main(
#   argv, *, issuer_config=None, client=None, identity=None, network_timeout=None,
#   locked_hook=None) -> int` — `argv` is what the parent appended; the keywords are the
#   in-process fakes (as `publish_for_run`) and `locked_hook`, the ONE injectable slow point of
#   the locked phase: called once, while the child holds the tenant lock, before it touches the
#   clone.

def launcher() -> Callable[..., str]:
    run_py = importlib.import_module("defender.run")
    return run_py.launch_publish


#: The child process a budget test spawns: the REAL child process entry, its fakes rebuilt
#: inside the subprocess (P3's issuer fake has a fixed clock, so it mints the token the test's
#: `GitHTTP` accepts), forwarding whatever arguments the parent appended.
CHILD_WRAPPER = '''
import json, sys, time
from pathlib import Path

spec = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
marks = Path(spec["marks"])
(marks / "started").write_text(repr(time.time()), encoding="utf-8")

from defender.learning.author import version_control as vc
from defender.tests.tenancy.tenant_1108_delivery._identity import VaultHTTP
from defender.tests.tenancy.tenant_1108_delivery._support import ForgeHTTP


def locked_hook():
    (marks / "locked").write_text(repr(time.time()), encoding="utf-8")
    time.sleep(spec["locked_sleep"])
    (marks / "locked-done").write_text(repr(time.time()), encoding="utf-8")


forge = ForgeHTTP(remote=Path(spec["remote"]), origin=spec["origin"])
sys.exit(vc.publish_child_main(
    sys.argv[2:], issuer_config=Path(spec["issuer_config"]), client=forge.client,
    identity=VaultHTTP(spec["tenant_id"]).identity(), network_timeout=spec["network_timeout"],
    locked_hook=locked_hook if spec["locked_sleep"] else None))
'''


def child_command(t: Any, tmp_path: Path, issuer_config: Path, *, network_timeout: float,
                  locked_sleep: float) -> tuple[list[str], Path, Path]:
    """`(command, spec path, marks dir)` for a budget test's child process."""
    marks = tmp_path / "child-marks"
    marks.mkdir(parents=True, exist_ok=True)
    wrapper = tmp_path / "publish_child_wrapper.py"
    wrapper.write_text(CHILD_WRAPPER, encoding="utf-8")
    spec = tmp_path / "publish_child_spec.json"
    spec.write_text(json.dumps({
        "tenant_id": t.tenant_id, "remote": str(t.remote), "origin": t.origin,
        "issuer_config": str(issuer_config), "marks": str(marks),
        "network_timeout": network_timeout, "locked_sleep": locked_sleep}), encoding="utf-8")
    return [sys.executable, str(wrapper), str(spec)], spec, marks
