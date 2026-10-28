"""Shared machinery for #947's questioner-authored-triplet spec — NO test scripts."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import fixture_data_root, fixture_runs_base, location_path


import hashlib
import importlib
import json
import os
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defender import _yaml

from defender.tests.support.shared._fixture_uuid import fixture_uuid

DEFENDER = Path(__file__).resolve().parents[4]

#: Fixed identity for hand-built scenes; real launches mint and persist their own UUIDs.
EPISODE_ID = "6f1c2d3e-4a5b-4c6d-8e7f-90a1b2c3d4e5"
#: The fixture source run's id: a uuid4, the shape `RunId.parse` admits.
SOURCE_RUN_ID = "3b8d5e2a-1c4f-4a7b-9d6e-2f0c1a3b5d7e"
BRANCH_MESSAGE_ID = 59
AS_OF = "2026-07-28T16:18:45Z"
WORLDS = ("a", "b", "c")

#: A retired runs-base knob: some scenarios still set it as a stale value; nothing reads it to
#: place a run.
RUNS_BASE_ENV = "DEFENDER_RUNS_BASE"
#: A retired episodes-base knob: nothing reads it (an episode lives at
#: `<data root>/<T>/episodes/<uuid>/`). Scenarios set it only as a decoy.
EPISODES_BASE_ENV = "DEFENDER_EPISODES_BASE"
#: The arm roster in an episode folder (production's `ARM_ROSTER_NAME`): `{world id: arm run id}`,
#: one entry per manifest world, host-written when RUNS starts.
ROSTER_NAME = "arms.json"

#: A committed invlang document, not a stub: `load_corpus` counts only a document that parses
#: (three required top-level keys), so over stubs every corpus assertion would pass as 0 == 0.
GOLDEN_INVESTIGATION = DEFENDER / "tests" / "fixtures" / "e2e" / "golden-v2sshd" / "investigation.md"

#: The two index patterns the elastic system is configured with (its `config.env`).
EVENTS_PATTERN = "logs-*"
ALERTS_PATTERN = ".internal.alerts-security.alerts-default-*"
CONFIGURED = (EVENTS_PATTERN, ALERTS_PATTERN)
#: The systems a v2 manifest records as served (`served_systems`).
SERVED_SYSTEMS = ("elastic", "identity")


def mod(dotted: str):
    """Import `defender.<dotted>` at CALL time, never at collection time."""
    return importlib.import_module(f"defender.{dotted}")


def sym(dotted: str, name: str):
    """One attribute off a lazily-imported module — `AttributeError` is a real red."""
    return getattr(mod(dotted), name)


def no_preflight(_model: str | None = None, *, branching: bool = False) -> int:
    """The role-model preflight, neutralised — for every scenario that is not about it."""
    return 0


def fixture_world_id(label: str) -> str:
    """Explicit identity for fixed fixture worlds; launcher worlds are read from disk."""
    return fixture_uuid(f"world:{label}")


def world_id(episode_dir: Path, label: str) -> str:
    """Read the persisted identity bound to exactly one manifest label."""
    doc = _yaml.safe_load((Path(episode_dir) / "family.yaml").read_text(encoding="utf-8"))
    matches = [world for world in doc["worlds"] if world["label"] == label]
    assert len(matches) == 1, (label, matches)
    return matches[0]["world_id"]


def declaration(doc: dict) -> dict:
    """Questioner-authored fields, before the host assigns world identities."""
    authored = {k: v for k, v in doc.items() if k != "world_id"}
    if "worlds" in authored:
        authored["worlds"] = [declaration(world) for world in authored["worlds"]]
    return authored


# --------------------------------------------------------------------------------------
# The untrusted wrap, read off the TEXT rather than re-minted: `wrap_fresh` mints a fresh salt
# per frame, so a second call never reproduces the frame the target emitted. Match the frame
# shape and read what sits inside it.
# --------------------------------------------------------------------------------------

#: `<run-{salt}-untrusted>`, opening or closing (the replay harness's `_FRAME_TAG_RE` shape).
UNTRUSTED_FRAME = re.compile(r"<(/?)(run-[0-9a-f]+-untrusted)>")


def untrusted_frames(text: str) -> list[tuple[int, int, int, int]]:
    """Every CLOSED untrusted frame in `text`, as `(open_start, open_end, close_start, close_end)`.

    An opening tag with no close is not a frame: it leaves everything after it in the host-text
    region, the failure the frame exists to prevent.
    """
    spans: list[tuple[int, int, int, int]] = []
    for m in UNTRUSTED_FRAME.finditer(text):
        if m.group(1):          # a closing tag
            continue
        close = f"</{m.group(2)}>"
        at = text.find(close, m.end())
        if at == -1:
            continue
        spans.append((m.start(), m.end(), at, at + len(close)))
    return spans


def outside_untrusted_frames(text: str) -> str:
    """Everything in `text` that is NOT inside a closed untrusted frame."""
    kept, cursor = [], 0
    for start, _open_end, _close_start, close_end in untrusted_frames(text):
        if start < cursor:      # a nested/overlapping frame: already accounted for
            continue
        kept.append(text[cursor:start])
        cursor = close_end
    kept.append(text[cursor:])
    return "".join(kept)


def assert_wrapped_untrusted(text: str, payload: str, what: str) -> None:
    """`payload` reaches `text` INSIDE an untrusted frame and nowhere outside one. The second half
    fails an implementation that wraps a copy while also rendering the payload bare."""
    frames = untrusted_frames(text)
    assert frames, f"{what}: the prompt carries no untrusted frame at all"
    inside = [text[open_end:close_start] for _s, open_end, close_start, _e in frames]
    assert any(payload in body for body in inside), (
        f"{what}: reached the prompt outside the untrusted wrap")
    assert payload not in outside_untrusted_frames(text), (
        f"{what}: is ALSO present outside the wrap, so it is still offered as instruction")


# --------------------------------------------------------------------------------------
# The fault spec: data, not behaviour.
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Fault:
    """How a dependency misbehaves, as data. Inert until a fake reads it; what the fault MEANS is
    left to the production code under test."""

    #: Substrings of the target name (an index, an alias, a run id) whose call fails.
    fail_on: tuple[str, ...] = ()
    #: Succeed this many calls, then raise. `None` = never.
    raise_after: int | None = None
    #: A malformed response shape: "no-status-line", "truncated-json" or "empty-body".
    malformed: str | None = None
    #: Seconds a call blocks before answering — for the ordering scenarios only.
    delay: float | None = None

    def hits(self, name: str) -> bool:
        return any(needle in name for needle in self.fail_on)


CLEAN = Fault()


def _transport_fault(detail: str) -> Exception:
    """The real `TransportFault` — what the transport raises when the docker exec itself fails."""
    return sym("kit.faults", "TransportFault")(detail)


def _upstream_fault(detail: str) -> Exception:
    """The real `UpstreamFault` — what an adapter raises when the far side refuses."""
    return sym("kit.faults", "UpstreamFault")(detail)




# --------------------------------------------------------------------------------------
# The model seams: the questioner's three calls and the comparator's one.
# --------------------------------------------------------------------------------------


class FakeAgent:
    """A recording stand-in for one model-backed call (`invoke=` on the questioner and the
    comparator): replies are scripted and prompts captured. Payload tests assert on `prompts`,
    because a fake that only returns answers leaves the outbound channel unpinned.
    """

    def __init__(self, *replies: Any, fault: Fault = CLEAN) -> None:
        self.replies = list(replies)
        self.fault = fault
        self.prompts: list[str] = []
        self.kwargs: list[dict[str, Any]] = []
        self.agent_ids: list[str] = []

    def __call__(self, prompt: str, **kw: Any) -> Any:
        self.prompts.append(prompt)
        self.kwargs.append(dict(kw))
        if "agent_id" in kw:
            self.agent_ids.append(kw["agent_id"])
        if self.fault.raise_after is not None and len(self.prompts) > self.fault.raise_after:
            raise RuntimeError("model provider degraded mid-fan-out")
        if not self.replies:
            raise AssertionError(f"FakeAgent ran out of replies at call {len(self.prompts)}")
        reply = self.replies.pop(0)
        return reply

    @property
    def calls(self) -> int:
        return len(self.prompts)


class FakeSpawn:
    """The launcher's process seam (`spawn=`; a sibling is a `run.py` process).

    Records each child's argv and env and whether starts overlapped, so "started together" is
    observed rather than read off a config flag. Runs no code: `exits` scripts return codes.
    """

    def __init__(self, *, exits: dict[str, int] | None = None, fault: Fault = CLEAN) -> None:
        self.exits = dict(exits or {})
        self.fault = fault
        self.launches: list[dict[str, Any]] = []
        self.overlap = False
        self._live = 0
        self._lock = threading.Lock()

    def __call__(self, argv: list[str], *, env: dict[str, str] | None = None,
                 **kw: Any) -> int:
        with self._lock:
            self._live += 1
            if self._live > 1:
                self.overlap = True
        self.launches.append({"argv": list(argv), "env": dict(env or {}), "kw": dict(kw)})
        # The delay is what makes `overlap` observable: a pure-Python call finishes within one
        # GIL switch interval, so launches started together would still pass through here one at
        # a time. It stands in for a real `run.py` child blocking for an investigation.
        if self.fault.delay:
            time.sleep(self.fault.delay)
        world = _world_of(argv)
        if self.fault.hits(world or ""):
            with self._lock:
                self._live -= 1
            raise RuntimeError(f"could not start a box for world {world}")
        with self._lock:
            self._live -= 1
        return self.exits.get(world or "", 0)

    @property
    def worlds(self) -> list[str]:
        return [w for w in (_world_of(la["argv"]) for la in self.launches) if w]


def _world_of(argv: list[str]) -> str | None:
    for i, tok in enumerate(argv):
        if tok == "--world" and i + 1 < len(argv):
            return argv[i + 1]
    return None


# --------------------------------------------------------------------------------------
# The builders.
# --------------------------------------------------------------------------------------


def fact(fact_id: str = "f1", statement: str = "web-1's owner is the platform team",
         entities: tuple[str, ...] = ("web-1",)) -> dict:
    """One fact a world asserts: an id, its natural-language statement, the entities it names."""
    return {"fact_id": fact_id, "statement": statement, "entities": list(entities)}


def world_doc(label: str, *, world_id: str | None = None, role: str = "B", story: str = "a story",
              axis: str | None = "an axis", disposition_declared: str = "malicious",
              label_basis: str = "policy-rule", facts: list[dict] | None = None) -> dict:
    """One v2 world. `facts=None` gives one default fact; pass `[]` for the control world."""
    return {
        "label": label, "world_id": fixture_world_id(label) if world_id is None else world_id,
        "role": role, "story": story, "axis": axis,
        "disposition_declared": disposition_declared, "label_basis": label_basis,
        "facts": [fact()] if facts is None else facts,
    }


def base_world() -> dict:
    """World A: the control — explicit `facts: []`, `axis: null`, role A."""
    return world_doc("a", role="A", axis=None, facts=[])


def family_doc(*, worlds: list[dict] | None = None, source_run_dir: str = "/runs/source",
               as_of: str = AS_OF, **over: Any) -> dict:
    """A v2 `Family` document: the launcher's derived half, the operator's instrument field and
    the questioner's authored half, one document."""
    doc: dict[str, Any] = {
        "episode_id": EPISODE_ID,
        "source_run_dir": source_run_dir,
        "source_run_id": SOURCE_RUN_ID,
        "branch_message_id": BRANCH_MESSAGE_ID,
        "fences_at": 4,
        "as_of": as_of,
        "base_story": "the captured story",
        # The launcher records the systems the tenant's gather grant served (#1224); the loader
        # reads no settings.
        "served_systems": list(SERVED_SYSTEMS),
        "discriminator": {"predicate": "p"},
        "worlds": worlds if worlds is not None else [
            base_world(),
            world_doc("b", facts=[fact("f1", "a second login to web-1 came from 10.0.0.9",
                                       ("web-1", "10.0.0.9"))]),
            world_doc("c", role="C", facts=[fact("f2")]),
        ],
    }
    doc.update(over)
    return doc


def write_family(episode_dir: Path, doc: dict | None = None) -> Path:
    """Materialise `episodes/<id>/family.yaml` and return its path."""
    episode_dir.mkdir(parents=True, exist_ok=True)
    manifest = episode_dir / "family.yaml"
    manifest.write_text(_yaml.safe_dump(doc if doc is not None else family_doc()),
                        encoding="utf-8")
    return manifest


#: Whether the builders plant what the front door leaves (#1222): a source run's alert record
#: and the episode's copies. `tests/conftest.py` turns it on except for #1222's own suite, which
#: plants (or omits) each record itself.
PLANT_RECORDS = False


#: Tenant episodes folder -> the tmp_path of the first scene placed there (see `_default_root`).
#: Keyed by the folder, which is per test, so nothing carries between tests.
_FIRST_SCENE: dict[str, str] = {}


def _default_root(tmp_path: Path) -> Path:
    """Where `episode` puts a scene built with no `root=`: the first `tmp_path` a test builds for
    goes under this data root's tenant; any other `tmp_path` gets a data root of its own
    (`tenant_episodes`). Layout A holds one episode per id under a tenant, so a second scene at
    the default `EPISODE_ID` would otherwise be built into the first."""
    home = location_path(current_tenant().episodes)
    first = _FIRST_SCENE.setdefault(str(Path(home).absolute()), str(Path(tmp_path).absolute()))
    if first == str(Path(tmp_path).absolute()):
        return home
    return tenant_episodes(Path(tmp_path) / "scene-data-root")


def episode(tmp_path: Path, *, doc: dict | None = None,
            episode_id: str = EPISODE_ID, root: Path | None = None) -> Path:
    """An episode dir with its manifest and an empty `served/` — the shape `Step.QUESTIONER`
    leaves."""
    if root is None:
        root = _default_root(tmp_path)
    ep = Path(root) / episode_id
    (ep / "served").mkdir(parents=True, exist_ok=True)
    # An empty primed base, as `prepare_episode` always leaves: `Ledger` refuses a missing base
    # (priming must precede any fork). `base_capture` overwrites it where a scenario has rows.
    base = ep / "served" / "base.jsonl"
    if not base.exists():
        base.write_text("", encoding="utf-8")
    # Manifest readers refuse an `episode_id` that is not the folder's name.
    write_family(ep, doc if doc is not None else family_doc(episode_id=episode_id))
    if PLANT_RECORDS:
        _plant_source_input(ep, (doc or {}).get("source_run_dir"), (doc or {}).get("source_run_id"))
    return ep


def _plant_source_input(ep: Path, source_run_dir: str | None, source_run_id: str | None = None) -> None:
    """The source run's alert and record, as a launch copies them into the episode (#1222 A1):
    the source run's own when it holds them, else a plain one."""
    from defender.records._episode_paths import EpisodePaths
    from defender.records import RunPaths
    from defender.tests.support.storage._alert_plant import plant_alert

    if source_run_id:
        from defender.records import RunId, RunRefused
        from contextlib import suppress
        with suppress(RunRefused):
            source_run_dir = str(current_tenant().runs_repository().open(RunId.parse(source_run_id)).run_dir)
    mine = EpisodePaths(ep)
    source = RunPaths(Path(source_run_dir)) if source_run_dir else None
    if source is not None and source.alert.is_file() and source.alert_record.is_file():
        mine.source_alert.write_bytes(source.alert.read_bytes())
        mine.source_record.write_bytes(source.alert_record.read_bytes())
        return
    scratch = ep / ".source-input"
    raw = plant_alert(scratch, {"rule": {"id": "v2-cross-tier-ssh-pivot"}})
    scratch_paths = RunPaths(scratch)
    mine.source_alert.write_bytes(raw)
    mine.source_record.write_bytes(scratch_paths.alert_record.read_bytes())
    import shutil
    shutil.rmtree(scratch)


def branchable_investigation() -> str:
    """A one-fence investigation document a branch may actually be TAKEN from."""
    from defender.skills.invlang.parser import scan_fences

    bodies = scan_fences(GOLDEN_INVESTIGATION.read_text(encoding="utf-8")).bodies
    assert bodies, f"{GOLDEN_INVESTIGATION} carries no invlang fence — the fixture moved"
    return f"# investigation\n\n```invlang\n{bodies[0]}\n```\n"


#: The tenant the fixture's SOURCE run is stamped with (siblings are seeded from it). Set up from
#: the committed fixture, so a launch that accepts it finds a complete tenant.
SOURCE_TENANT = fixture_uuid("tenant:playground")


def current_tenant() -> Any:
    """The one tenant in this test's `DEFENDER_DATA_ROOT` (whichever a builder already set up), as
    an accepted `Tenant`; set up from the committed fixture when the root has none yet."""
    from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant

    root = Path(os.environ["DEFENDER_DATA_ROOT"])
    existing = sorted(p.name for p in root.iterdir()
                      if (p / "tenant.json").is_file()) if root.is_dir() else []
    return set_up_tenant(root, existing[0] if existing else SOURCE_TENANT)


def tenant_episodes(data_root: Path) -> Path:
    """`<data_root>/<T>/episodes/` for this suite's tenant, set up under a scene's own data root.
    Layout A allows one episode per id under a tenant, so a test building several scenes at the
    default `EPISODE_ID` passes each its own, as `episode(root=...)`."""
    from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant

    return location_path(set_up_tenant(Path(data_root), current_tenant().id).episodes)


def runs_base(tmp_path: Path, *, source_run_id: str = SOURCE_RUN_ID,
              tenant_id: str | None = None, recorded: bool | None = None,
              pre_snapshot: bool = False,
              land_calls: Callable[[Path], None] | None = None,
              published: bool = False) -> tuple[Path, Path]:
    """A runs base holding ONE ordinary finished run. Returns (base, source_run_dir).

    `published=True` sets the tenant up as published, so the source's default knowledge stamp
    (`scene_knowledge`) names a commit its clone holds, as a branch launch over it needs."""
    from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant

    root = Path(os.environ["DEFENDER_DATA_ROOT"])
    if tenant_id is None:
        existing = sorted(p.name for p in root.iterdir()
                          if (p / "tenant.json").is_file()) if root.is_dir() else []
        tenant_id = existing[0] if existing else SOURCE_TENANT
    tenant = set_up_tenant(root, tenant_id, published=published)
    location_path(tenant.learning).mkdir(exist_ok=True)  # setup provisions the real launcher queue root
    base = location_path(tenant.runs)
    base.mkdir(parents=True, exist_ok=True)
    src = base / source_run_id
    (src / "gather_raw").mkdir(parents=True, exist_ok=True)
    if PLANT_RECORDS if recorded is None else recorded:
        from defender.tests.support.storage._alert_plant import plant_alert

        plant_alert(src, {"rule": {"id": "v2-cross-tier-ssh-pivot"}})
    else:
        (src / "alert.json").write_text(json.dumps({"rule": {"id": "v2-cross-tier-ssh-pivot"}}),
                                        encoding="utf-8")
    (src / "investigation.md").write_text(branchable_investigation(), encoding="utf-8")
    (src / "report.md").write_text("disposition: malicious\n", encoding="utf-8")
    (src / "executed_queries.jsonl").write_text("", encoding="utf-8")
    # One captured call: `branch.validate` refuses a source that captured nothing (every world
    # would agree with an empty prefix). `land_calls` lands other rows instead, before seeding.
    if land_calls is None:
        capture_call(src)
    else:
        land_calls(src)
    # The stamp `materialize_run` gives every ordinary run dir; containment walks read it to tell
    # an ordinary run from an episode's contents.
    (src / "provenance.json").write_text(
        json.dumps(provenance_record(tenant_id=tenant_id)), encoding="utf-8")
    seed_source_session(base, src, pre_snapshot=pre_snapshot)
    return base, src


#: The fixture source run's case. The run's case pointer and the store it names must agree
#: (`open_source_store` checks), which is how a branch finds its source's session.
SOURCE_CASE_ID = "case-947-fresh"


def source_case_id(src: Path) -> str:
    """`SOURCE_CASE_ID` for the default source, a case of its own for any other: row ids are per
    store (per case), so a second source in the first's case would start past
    `BRANCH_MESSAGE_ID` and never reach its branch point."""
    if src.name == SOURCE_RUN_ID:
        return SOURCE_CASE_ID
    digest = hashlib.sha256(src.name.encode("utf-8")).hexdigest()[:16]
    return f"{SOURCE_CASE_ID}-{digest}"


def _source_handle(src: Path) -> Any:
    """The source run's handle, for writing its case pointer: `fixture_run` for a canonical-UUID
    folder; for an old-shaped or hostile id planted on purpose (so the launcher refuses it), a
    `Run` built at that folder directly."""
    from defender.records import Run
    from defender.tests.support.shared._fixture_uuid import is_fixture_uuid_shape
    from defender.tests.support.shared.contracts._spec1077 import fixture_run

    src = Path(src)
    if is_fixture_uuid_shape(src.name):
        return fixture_run(src)
    return Run(src, runs_base=fixture_runs_base(src.parent))


def seed_source_session(base: Path, src: Path, *, pre_snapshot: bool = False) -> None:
    """Give the source run the session store a branch is actually taken from."""
    from defender.records import RunPaths, SessionPaths

    ss = mod("records.session_store")
    # The case pointer is a host-only sidecar beside the run dir (#1235).
    if RunPaths(src).session_pointer().exists():
        return
    from defender.tests.support.storage import _session_store_705 as S

    from defender.tests.support.shared._fixture_uuid import is_fixture_uuid_shape

    assert isinstance(pre_snapshot, bool), pre_snapshot

    # The store opens on the layout owner's `SessionPaths` for the runs base.
    case_id = source_case_id(src)
    with ss.open_store(case_id=case_id, sessions=SessionPaths(fixture_runs_base(base))) as store:
        ss.write_case_pointer(_source_handle(src), case_id=case_id, store_path=store.path)
        session_id = store.new_session(agent_id="main")
        store.append(session_id, [S.user_request("investigate the alert")], agent_id="main")
        # A branch point is a MAIN response that called tools: one leading row shifts every
        # pair so `BRANCH_MESSAGE_ID` lands on a call, not its return.
        store.append(session_id, [S.text_response("orienting")], agent_id="main")
        while BRANCH_MESSAGE_ID not in ss.path_row_ids(store, session_id):
            store.append(session_id, list(S.complete_pair()), agent_id="main")
        if not pre_snapshot and is_fixture_uuid_shape(src.name):
            # Legacy or hostile source ids are refused before the snapshot gate.
            from defender.tests.support.runtime.state._fork_snapshot_plant import plant_fork_snapshots

            plant_fork_snapshots(store, session_id, src)


def capture_call(run_dir: Path, *, system: str = "elastic", verb: str = "query",
                 params: dict | None = None, payload: Any = None, lead: str = "l-001",
                 seq: int = 0) -> dict:
    """Land ONE captured call in a source run: the queries-table row and the sidecar it names."""
    rq = mod("investigation.record_query")
    breaker = mod("systems.circuit_breaker")
    p = dict(params or {"index": EVENTS_PATTERN})
    body = payload if payload is not None else {"hits": [{"_id": "d1"}]}
    text = json.dumps(body, sort_keys=True)
    row = {
        "lead_id": lead, "seq": seq, "system": system, "verb": verb,
        "query_id": f"{system}.{verb}", "params": p,
        "raw_command": rq.raw_command(system, verb, p),
        "payload_path": f"gather_raw/{lead}/{seq}.json",
        "exit_code": 0, "error_class": breaker.error_class_for_exit(0),
        "payload_status": rq.payload_status(0, body), "payload_digest": "",
        "payload_sha256": rq.payload_sha256(text), "system_key": "",
    }
    table = run_dir / "executed_queries.jsonl"
    with table.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")
    sidecar = run_dir / str(row["payload_path"])
    sidecar.parent.mkdir(parents=True, exist_ok=True)
    sidecar.write_text(text, encoding="utf-8")
    return row


#: The reasons `capture_tree` pairs with its non-clean shapes (each refuses without
#: `--allow-dirty`): a `dirty: None` record that keeps a commit comes only from a failed git
#: status; git being unavailable means `commit: None`. Either shape without its reason is a
#: record no capture produces.
GIT_STATUS_FAILED = "git status: GitError('git status --porcelain=v1 -z', 128)"
GIT_UNAVAILABLE = "git unavailable: FileNotFoundError('git')"

#: The tenant knowledge commit every default stamp carries (#1204), so a source, its siblings and
#: the live capture agree on it, as a family launched from one tenant clone does. A FULL 40-hex
#: lowercase sha: the reader folds any other shape to "the record does not say", a waivable
#: fault that would turn every accept-without-the-flag scenario red.
KNOWLEDGE_SHA = "1204" + "d" * 36

#: A second, distinct knowledge commit, for the scenarios about a family across two of them.
OTHER_KNOWLEDGE_SHA = "1204" + "e" * 36


class _OmitKnowledge:
    """The type of `NO_KNOWLEDGE_KEY` (a named sentinel, so a failing assertion prints it)."""

    def __repr__(self) -> str:
        return "NO_KNOWLEDGE_KEY"


#: `provenance_record(knowledge=NO_KNOWLEDGE_KEY)` OMITS the `knowledge` key (a pre-#1204
#: stamp); `knowledge=None` writes JSON `null`. Both read back as `knowledge is None`.
NO_KNOWLEDGE_KEY: Any = _OmitKnowledge()

#: The default `knowledge=` of `provenance_record` — a sentinel so each call builds a fresh dict.
_DEFAULT_KNOWLEDGE: Any = object()


def scene_knowledge(tenant_id: str | None = None) -> str:
    """The knowledge commit a DEFAULT stamp names: what `exports/current` names for `tenant_id`,
    or for the data root's one published tenant, so stamps name a commit the clone really holds.
    Otherwise the placeholder `KNOWLEDGE_SHA`."""
    raw = os.environ.get("DEFENDER_DATA_ROOT")
    if not raw:
        return KNOWLEDGE_SHA
    root = Path(raw)
    if tenant_id is None:
        published = sorted(p.name for p in root.iterdir()
                           if (p / "exports" / "current").is_file()) if root.is_dir() else []
        if len(published) != 1:
            return KNOWLEDGE_SHA
        tenant_id = published[0]
    pointer = root / tenant_id / "exports" / "current"
    return pointer.read_text(encoding="utf-8").strip() if pointer.is_file() else KNOWLEDGE_SHA


def provenance_record(*, commit: str | None = "deadbee", dirty: bool | None = False,
                      unavailable: str | None = None, model: str | None = "m-1",
                      scope: str | None = "repo",
                      tenant_id: str | None = None,
                      knowledge: Any = _DEFAULT_KNOWLEDGE) -> dict:
    """One `provenance.json` document, in a shape `capture_tree` can produce."""
    doc: dict[str, Any] = {
        "commit": commit, "dirty": dirty, "dirty_paths": [], "dirty_path_count": 0,
        "unavailable": unavailable, "scope": scope, "model": model,
    }
    if knowledge is _DEFAULT_KNOWLEDGE:
        doc["knowledge"] = {"commit": scene_knowledge(tenant_id)}
    elif knowledge is not NO_KNOWLEDGE_KEY:
        doc["knowledge"] = knowledge
    if dirty:
        doc["dirty_paths"] = ["defender/investigation/driver/__init__.py"]
        doc["dirty_path_count"] = 1
    # Every stamp carries its tenant (siblings seed theirs from the source's); `None`, the
    # default, omits the field.
    if tenant_id is not None:
        doc["tenant_id"] = tenant_id
    return doc


def source_stamp(src: Path, **overrides: Any) -> Path:
    """Rewrite the SOURCE run's `provenance.json` — the anchor #976 reads at preflight — with the
    builder `runs_base` uses, so the file is one `materialize_run` could have written. A missing
    or planted stamp is not spelled here: such scenarios unlink or symlink the real path.
    """
    path = Path(src) / "provenance.json"
    # The source's tenant rides unless the scenario overrides it (`tenant_id=None` is the legacy
    # stamp the launcher refuses).
    overrides.setdefault("tenant_id", SOURCE_TENANT)
    path.write_text(json.dumps(provenance_record(**overrides)), encoding="utf-8")
    return path


class FakeCapture:
    """The launcher's live-tree seam (`live_tree=` on `cli.main`), scripted and counted.

    Production asks git about the checkout the launcher runs in, so every end-to-end launcher
    scenario injects one matching the source's stamp. `calls` counts captures (once per launch).
    """

    def __init__(self, record: dict) -> None:
        self.record = dict(record)
        self.calls = 0
        #: A capture built before its scene's tenant was published carries the placeholder;
        #: it names the scene's knowledge commit once there is one (`scene_knowledge`).
        self._scene_knowledge = self.record.get("knowledge") == {"commit": KNOWLEDGE_SHA}

    def __call__(self):
        from defender.records._provenance import RunProvenance

        self.calls += 1
        if self._scene_knowledge:
            self.record["knowledge"] = {"commit": scene_knowledge(self.record.get("tenant_id"))}
        built = RunProvenance.from_obj(self.record)
        if built is None:
            raise AssertionError(f"FakeCapture was scripted with a record no capture produces: "
                                 f"{self.record}")
        return built


#: Explicit test scratch setting for injected state handles; production ignores this variable.
LEARNING_STATE_ENV = "DEFENDER_LEARNING_STATE_DIR"


def isolate_learning_state(tmp_path: Path, monkeypatch: Any) -> Path:
    """Create and name explicit test scratch state for helpers that inject a state handle.

    Production launchers select tenant.learning and ignore this retired environment setting.
    """
    root = tmp_path / "learning-state"
    root.mkdir(exist_ok=True)
    monkeypatch.setenv(LEARNING_STATE_ENV, str(root))
    return root


def source_capture(**overrides: Any) -> FakeCapture:
    """A live-tree capture built from `provenance_record(**overrides)`.

    With no overrides it matches the source `runs_base` stamps, as an accepted launch needs. The
    other shapes a real `capture_tree` answers with: `commit="0ther"`, `dirty=True`,
    `dirty=None, unavailable=GIT_STATUS_FAILED`, `commit=None, dirty=None,
    unavailable=GIT_UNAVAILABLE`. `knowledge=` is the live tenant clone's revision.
    """
    return FakeCapture(provenance_record(**overrides))


def report_text(disposition: str, *, extra: str = "", body: str = "") -> str:
    """`report.md` AS THE CLOSE GATE WRITES IT — YAML frontmatter, not a bare line."""
    return (
        "---\n"
        f"disposition: {disposition}\n"
        "outcome: stands\n"
        "cause: the disposition was recorded without a challenge review\n"
        f"{extra}"
        "---\n"
        f"{body or 'Disposition recorded by the close gate. outcome=stands.'}\n"
    )


def archived_world(episode_dir: Path, label: str, *, disposition: str = "malicious",
                   scrub_ran: bool = True, commit: str | None = "deadbee",
                   dirty: bool | None = False, unavailable: str | None = None) -> Path:
    """One archived `worlds/<X>/` directory with every artifact the archive writes. No `run_dir`
    pointer (the arm roster supersedes it): a scenario about an old archive's leftover pointer
    plants one itself."""
    w = episode_dir / "worlds" / world_id(episode_dir, label)
    (w / "gather_raw").mkdir(parents=True, exist_ok=True)
    (w / "report.md").write_text(report_text(disposition), encoding="utf-8")
    (w / "investigation.md").write_text(f"# world {label}\n", encoding="utf-8")
    (w / "executed_queries.jsonl").write_text("", encoding="utf-8")
    (w / "provenance.json").write_text(
        json.dumps(provenance_record(commit=commit, dirty=dirty, unavailable=unavailable)),
        encoding="utf-8")
    (w / "scrub_verdict.json").write_text(json.dumps({"ran": scrub_ran}), encoding="utf-8")
    return w


def read_roster(episode_dir: Path) -> dict[str, str]:
    """`<episode_dir>/arms.json` as plain JSON (`{world UUID: arm id}`); `{}` when there is none."""
    path = Path(episode_dir) / ROSTER_NAME
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def write_roster(episode_dir: Path, roster: dict[str, str]) -> Path:
    """Plant `roster` as the arm roster a launch writes when RUNS starts. Overwrites."""
    path = Path(episode_dir) / ROSTER_NAME
    path.write_text(json.dumps(dict(roster), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _manifest_world_ids(episode_dir: Path) -> list[str]:
    """Explicit persisted world UUIDs of a hand-built episode, in manifest order."""
    doc = _yaml.safe_load((Path(episode_dir) / "family.yaml").read_text(encoding="utf-8"))
    return [world["world_id"] for world in doc["worlds"]]


def plant_roster(episode_dir: Path) -> dict[str, str]:
    """Take the RUNS step for a hand-built scene (no launcher ran), as `start_runs` does: make
    `runs/`, then write the roster once, a fresh uuid4 per manifest world; return it. Refuses
    (AssertionError) a second roster or a manifest naming no world. A stray arm no roster names
    is planted at `runs/<uuid4>` directly, never by extending the roster."""
    import uuid

    episode_dir = Path(episode_dir)
    if not episode_dir.is_dir():
        raise AssertionError(f"plant_roster: no episode at {episode_dir} (a launch that made "
                             "none?) — there is no scene to take the RUNS step for")
    if (episode_dir / ROSTER_NAME).exists():
        raise AssertionError(f"plant_roster: {episode_dir / ROSTER_NAME} already exists — the "
                             "RUNS step writes the roster once")
    world_ids = _manifest_world_ids(episode_dir)
    if not world_ids:
        raise AssertionError(f"plant_roster: {episode_dir / 'family.yaml'} names no world — a "
                             "roster names exactly the manifest's worlds (#1187 R2)")
    (episode_dir / "runs").mkdir(parents=True, exist_ok=True)
    roster = {world_id: str(uuid.uuid4()) for world_id in world_ids}
    write_roster(episode_dir, roster)
    return roster


def roster_arm_id(episode_dir: Path, world_id: str) -> str:
    """The arm id the episode's roster holds for `world_id`. READ-ONLY: with no roster, or a
    world UUID the roster does not name, it fails loudly rather than writing one."""
    episode_dir = Path(episode_dir)
    if not (episode_dir / ROSTER_NAME).is_file():
        raise AssertionError(
            f"roster_arm_id: no arm roster at {episode_dir / ROSTER_NAME} — take the RUNS step "
            "first (the launcher, `plant_roster` or `episode_view`); this reader never writes one")
    roster = read_roster(episode_dir)
    if world_id not in roster:
        raise AssertionError(
            f"roster_arm_id: the roster at {episode_dir / ROSTER_NAME} names {sorted(roster)}, "
            f"not {world_id!r} — a stray arm is planted at `runs/<uuid4>` directly")
    return roster[world_id]


def sibling_run_dir(  # noqa: PLR0913 — one keyword per stamp field a scenario varies, plus the arm id the spawn double passes
        base: Path, label: str, *, arm_id: str | None = None,
                    scrub_ran: bool = True,
                    commit: str | None = "deadbee", dirty: bool | None = False,
                    unavailable: str | None = None,
                    model: str = "m-1", stamp: bool = True, **record: Any) -> Path:
    """A finished sibling run dir plus its scrub-verdict SIDECAR, under `base`."""
    base = Path(base)
    run_dir = base / (arm_id if arm_id is not None else _arm_name(base, label))
    (run_dir / "gather_raw").mkdir(parents=True, exist_ok=True)
    (run_dir / "report.md").write_text(report_text("malicious"), encoding="utf-8")
    (run_dir / "investigation.md").write_text(f"# world {label}\n", encoding="utf-8")
    (run_dir / "executed_queries.jsonl").write_text("", encoding="utf-8")
    if stamp:
        (run_dir / "provenance.json").write_text(
            json.dumps(provenance_record(commit=commit, dirty=dirty, unavailable=unavailable,
                                         model=model, **record)),
            encoding="utf-8")
    if scrub_ran is not None:
        (base / f"{run_dir.name}.scrub-verdict.json").write_text(
            json.dumps({"ran": scrub_ran}), encoding="utf-8")
    return run_dir


def _arm_name(base: Path, label: str) -> str:
    """The folder name `sibling_run_dir` gives `label`'s arm under `base` (see there)."""
    from defender.tests.support.shared._fixture_uuid import fixture_uuid

    episode_dir = Path(base).parent
    if (episode_dir / "family.yaml").is_file() or (episode_dir / ROSTER_NAME).is_file():
        return roster_arm_id(episode_dir, world_id(episode_dir, label))
    return fixture_uuid(f"{Path(base).absolute()}/{label}")


def arm_run_dir(episode_dir: Path, label: str, **kw: Any) -> Path:
    """A finished arm at `<episode_dir>/runs/<arm id>`, the id the roster holds for `label`:
    `sibling_run_dir` over `<episode_dir>/runs`, every keyword passed through."""
    return sibling_run_dir(Path(episode_dir) / "runs", label, **kw)


def corpus_document(run_dir: Path) -> Path:
    """Give `run_dir` a REAL orientation-corpus document, a copy of `GOLDEN_INVESTIGATION` (see
    there for why not a stub)."""
    run_dir.mkdir(parents=True, exist_ok=True)
    path = run_dir / "investigation.md"
    path.write_text(GOLDEN_INVESTIGATION.read_text(encoding="utf-8"), encoding="utf-8")
    # A run's record is what makes a folder a run to the corpus reader (#1222 A8).
    from defender.records import RunPaths
    from defender.tests.support.storage._alert_plant import plant_alert

    if PLANT_RECORDS and not RunPaths(run_dir).alert_record.exists():
        plant_alert(run_dir, {"rule": {"id": "v2-cross-tier-ssh-pivot"}})
    return path


def open_source(src: Path) -> Any:
    """The source `Run` the launcher opens: the run at `src` (`<data root>/<T>/runs/<run id>`),
    by id through tenant T's runs repository. What `preflight_episode(source=)` and
    `preflight_replay(source=)` take."""
    from defender.tenancy import _tenant
    from defender.records import RunId

    src = Path(src)
    tenant = _tenant.accept_tenant(fixture_data_root(src.parent.parent.parent), src.parent.parent.name,
                                   defender_dir=DEFENDER)
    return tenant.runs_repository().open(RunId.parse(src.name))


def episode_view(episode: Any, *, tenant: Any = None) -> Any:
    """The episode's view (`EpisodeRuns`) in `tenant`'s runs repository (default
    `current_tenant()`), adopting the held `episode`. An episode with no arm roster yet never
    reached RUNS, so this takes the launcher's RUNS step (`view.start_runs(<manifest world
    UUIDs>)`); a roster a scene already planted is kept."""
    owner = current_tenant() if tenant is None else tenant
    view = owner.runs_repository().episode(episode.dir.name, held=episode)
    if view.arm_ids() is None:
        view.start_runs(_manifest_world_ids(Path(episode.dir)))
    return view


def family_arms(episode: Any, labels: Any, *, tenant: Any = None) -> dict[str, Any]:
    """`verify_family`'s UUID-keyed `arms`: each label's arm opened by roster id through
    `episode_view`, as the launcher's `_finished_arms` does. A refused open (`RunAbsent`: not
    started) is kept as that world UUID's value."""
    from defender.records import RunRefused

    view = episode_view(episode, tenant=tenant)
    arms: dict[str, Any] = {}
    for label in labels:
        wid = world_id(Path(episode.dir), label)
        try:
            arms[wid] = view.open(view.arm_id(wid))
        except RunRefused as refused:
            arms[wid] = refused
    return arms


def configured_layout(tmp_path: Path, monkeypatch) -> tuple[Path, Path, Path]:
    """The source's runs base, the source run, and the episodes folder — the relocated layout."""
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(tmp_path / "configured-data-root"))
    base, src = runs_base(tmp_path, recorded=True)
    monkeypatch.setenv(RUNS_BASE_ENV, str(base))
    return base, src, base.parent / "episodes"


def lesson_row(run_dir: Path, name: str = "L1",
               loaded_at: str = "2026-07-28T17:00:00Z") -> None:
    """One `lessons_loaded.jsonl` row — what `trace_lesson.in_context_cases` selects on."""
    (run_dir / "lessons_loaded.jsonl").write_text(
        json.dumps({"lesson_name": name, "loaded_at": loaded_at}) + "\n", encoding="utf-8")


class FakeAdapters:
    """The real adapter bodies' stand-in behind the serving registry (`adapters=`).

    The serving path answers from the primed capture BEFORE calling any adapter, so an adapter
    call is only visible if recorded: this records `(system, verb, params)` per call and answers
    from a scripted table.
    """

    def __init__(self, answers: dict[tuple[str, str], Any] | None = None, *,
                 by_target: dict[str, Any] | None = None, fault: Fault = CLEAN) -> None:
        self.answers = dict(answers or {})
        #: Keyed by a SUBSTRING of the bound params, so one fake answers two calls differently
        #: without ever being told which world is asking.
        self.by_target = dict(by_target or {})
        self.fault = fault
        self.calls: list[tuple[str, str, dict]] = []
        #: Every world `for_world` was asked for, in order. Production returns a copy whose
        #: context declares the world (what admits a `wv-<world>-<corpus>` alias at
        #: `confine_index`); the fake records the request instead, for tests about which world a
        #: staged read went out under.
        self.world_views: list[str] = []

    def for_world(self, world_id: str) -> FakeAdapters:
        """The per-world view `seams.EpisodeAdapters` provides. SELF, not a copy, so every world's
        reads land on the one `calls` list tests assert on."""
        self.world_views.append(world_id)
        return self

    def __call__(self, system: str, verb: str, **params: Any) -> Any:
        self.calls.append((system, verb, dict(params)))
        rendered = json.dumps(params, sort_keys=True, default=str)
        for needle, answer in self.by_target.items():
            if needle in rendered:
                return answer
        if self.fault.raise_after is not None and len(self.calls) > self.fault.raise_after:
            raise _upstream_fault("Elasticsearch query failed (HTTP 503)")
        if self.fault.hits(rendered) or self.fault.hits(f"{system}.{verb}"):
            raise _upstream_fault(f"{system}.{verb} is unavailable")
        if self.fault.malformed == "truncated-json":
            raise ValueError("Expecting value: line 1 column 1 (char 0)")
        return self.answers.get((system, verb), {"hits": []})

    @property
    def asked(self) -> list[tuple[str, str]]:
        return [(s, v) for s, v, _p in self.calls]


def base_capture(episode_dir: Path, rows: list[dict]) -> Path:
    """Prime `served/base.jsonl` — the family's shared recording every world replays."""
    served = episode_dir / "served"
    served.mkdir(parents=True, exist_ok=True)
    path = served / "base.jsonl"
    path.write_text("".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8")
    return path


def captured_row(system: str = "elastic", verb: str = "query", *, key: str = "k1",
                 payload: dict | None = None, params: dict | None = None) -> dict:
    """One `ServedCall`-shaped capture row, keyed on the form ASKED."""
    return {
        "system": system, "verb": verb, "correlation_key": key,
        "params": params or {"index": EVENTS_PATTERN},
        "payload_text": json.dumps(payload if payload is not None else {"hits": [{"_id": "d1"}]},
                                   sort_keys=True),
        "source": "run",
    }


def refusals() -> tuple[type[BaseException], ...]:
    """Every class a refusal in this design may be — and NEVER bare `Exception`, which a
    `ModuleNotFoundError` satisfies. Evaluated before the `raises` block opens, so a missing
    target fails the test at the call.
    """
    from defender.learning.branch.estate.registry import EstateError
    from defender.learning.branch.ledger import LedgerError
    from defender.investigation.branch import BranchError
    from defender.integrations.confinement import ConfinementFault
    from defender.kit.faults import AdapterFault
    out: list[type[BaseException]] = [
        SystemExit, EstateError, LedgerError, BranchError, ConfinementFault,
        AdapterFault, ValueError,
    ]
    for dotted, name in (("records._family", "FamilyError"),
                         ("learning.judge", "JudgeRefused")):
        out.append(sym(dotted, name))
    return tuple(out)


__all__ = [
    "ALERTS_PATTERN", "AS_OF", "BRANCH_MESSAGE_ID", "CLEAN", "CONFIGURED", "DEFENDER",
    "EPISODE_ID", "EPISODES_BASE_ENV", "EVENTS_PATTERN",
    "GIT_STATUS_FAILED", "GIT_UNAVAILABLE", "GOLDEN_INVESTIGATION", "RUNS_BASE_ENV",
    "KNOWLEDGE_SHA", "NO_KNOWLEDGE_KEY", "OTHER_KNOWLEDGE_SHA",
    "branchable_investigation",
    "SOURCE_RUN_ID", "WORLDS",
    "FakeAdapters", "FakeAgent", "FakeSpawn", "SERVED_SYSTEMS",
    "UNTRUSTED_FRAME", "assert_wrapped_untrusted", "outside_untrusted_frames", "untrusted_frames",
    "Fault", "base_capture", "captured_row",
    "archived_world", "base_world", "capture_call", "configured_layout", "ROSTER_NAME",
    "read_roster", "write_roster", "roster_arm_id", "plant_roster",
    "report_text",
    "corpus_document",
    "episode", "episode_view", "fact", "family_arms", "family_doc", "open_source",
    "provenance_record",
    "FakeCapture", "source_capture", "source_stamp", "isolate_learning_state", "LEARNING_STATE_ENV",
    "lesson_row", "mod", "refusals", "runs_base",
    "arm_run_dir", "sibling_run_dir",
    "sym", "world_doc", "fixture_world_id", "world_id", "declaration", "write_family",
]
