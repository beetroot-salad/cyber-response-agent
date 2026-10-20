"""Shared machinery for #947's questioner-authored-triplet spec — NO test scripts."""
from __future__ import annotations


import hashlib
import importlib
import json
import os
import re
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from defender import _yaml

from defender.tests.support.shared._fixture_uuid import fixture_uuid

DEFENDER = Path(__file__).resolve().parents[4]

#: Fixed identity for hand-built scenes; real launches mint and persist their own UUIDs.
EPISODE_ID = "6f1c2d3e-4a5b-4c6d-8e7f-90a1b2c3d4e5"
#: The fixture source run's id (#1187: a uuid4, as `RunId.parse` admits and `RunId.mint()` mints).
#: The launcher and the sibling open the source by id through the tenant's repository.
SOURCE_RUN_ID = "3b8d5e2a-1c4f-4a7b-9d6e-2f0c1a3b5d7e"
BRANCH_MESSAGE_ID = 59
AS_OF = "2026-07-28T16:18:45Z"
WORLDS = ("a", "b", "c")

#: The operator runs base a child inherits (`run_common.resolve_runs_base`'s retired knob, J46):
#: still SET by some scenarios, as a stale configured value, never read to place anything.
RUNS_BASE_ENV = "DEFENDER_RUNS_BASE"
#: The episodes base #1187 retires (O9, declared change 5): NOTHING reads it — an episode lives at
#: `<data root>/<T>/episodes/<uuid>/`, derived from its tenant. The name stays only so a
#: scenario can set it as a DECOY and show it changes nothing; no builder here sets or reads it.
EPISODES_BASE_ENV = "DEFENDER_EPISODES_BASE"
#: The arm roster's name in an episode folder (#1187 R2; owned by `_episode_paths.LAYOUT`,
#: `ARM_ROSTER_NAME`): `{label: arm run id}`, one entry per manifest world, host-written at the
#: start of RUNS. Spelled here (the builders below plant it) as `ids_1187/_spec1187` spells it.
ROSTER_NAME = "arms.json"

#: A committed `\`\`\`invlang` companion document — the orientation corpus's own input shape.
#: `skills/invlang/corpus.load_corpus` only counts a document that PARSES (three required
#: top-level keys), so a stub would make every corpus assertion read 0 == 0 and pass on the
#: absence of the thing it measures.
GOLDEN_INVESTIGATION = DEFENDER / "tests" / "fixtures" / "e2e" / "golden-v2sshd" / "investigation.md"

#: The two configured corpus patterns (G11: 11 distinct patterns across the shipped query
#: corpus; these two are the configured pair, `knowledge/environment/systems/elastic/config.env`).
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
# The untrusted wrap, read off the TEXT rather than re-minted.
#
# `_untrusted.wrap_fresh` mints a FRESH salt per frame and puts it in both delimiters
# (`_untrusted.py:50`, `while (salt := secrets.token_hex(8)) in content`), because #875 F-1 is a
# token that outlives the string it delimits. So a marker built here by calling `wrap_fresh` a
# SECOND time names a frame the target never emitted: two calls on the same content differ at
# 2^-64 and neither contains the other, and an assertion comparing them can never hold for ANY
# implementation. Match the frame SHAPE and read what sits inside it instead.
# --------------------------------------------------------------------------------------

#: `<run-{salt}-untrusted>` in either direction — the same shape the replay harness's own
#: `_FRAME_TAG_RE` and `test_947_triplet_served.py` spell.
UNTRUSTED_FRAME = re.compile(r"<(/?)(run-[0-9a-f]+-untrusted)>")


def untrusted_frames(text: str) -> list[tuple[int, int, int, int]]:
    """Every CLOSED untrusted frame in `text`, as `(open_start, open_end, close_start, close_end)`.

    An opening tag with no matching close is not a frame: a wrap that opens and never closes
    leaves everything after it in the model's host-text region, which is the failure the frame
    exists to prevent.
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
    """`payload` reaches `text` INSIDE an untrusted frame and nowhere outside one.

    Both halves are load-bearing. The first fails an implementation that hands the payload over
    as bare text; the second fails one that wraps a copy while ALSO rendering the same text in
    the host region, which is the whole of "no payload text is presented as instruction".
    """
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
    """How a dependency misbehaves, as DATA a scenario writes in one line.

    Every field is inert until a fake reads it. The fake decides nothing about what the
    fault MEANS — that is the production code's job, and the whole point of the test.
    """

    #: Substrings of the target name (an index, an alias, a run id) whose call fails.
    fail_on: tuple[str, ...] = ()
    #: Succeed this many calls, then raise. `None` = never.
    raise_after: int | None = None
    #: A response SHAPE, each spelling citing the claim that observed it. See the module
    #: docstring: "no-status-line" (PO-C3), "truncated-json", "empty-body".
    malformed: str | None = None
    #: Seconds a call blocks before answering — for the ordering scenarios only.
    delay: float | None = None

    def hits(self, name: str) -> bool:
        return any(needle in name for needle in self.fail_on)


CLEAN = Fault()


def _transport_fault(detail: str) -> Exception:
    """The real `TransportFault` — what the transport raises when the docker exec itself fails."""
    return sym("integrations.faults", "TransportFault")(detail)


def _upstream_fault(detail: str) -> Exception:
    """The real `UpstreamFault` — what an adapter raises when the far side refuses."""
    return sym("integrations.faults", "UpstreamFault")(detail)


class FakeTransport:
    """`transport.docker_exec_curl`'s shape, as a recording fake (X9's executed signature).

    Returns `(returncode, stdout, stderr)` with stdout = body + "\\n" + http_code, which is
    what `split_status` is built to recover. `malformed="no-status-line"` drops the trailing
    line — PO-C3's executed fault: `split_status` then returns `("", <whole body>)` and the
    caller that compares the second element to "200" reads a FAILED create as a success.

    Records `argv`-shaped call state so a test can assert a derived name reached the
    transport as a DISCRETE argument rather than concatenated into a shell string (S39).
    """

    def __init__(self, *, fault: Fault = CLEAN, status: str = "200",
                 body: dict | None = None) -> None:
        self.fault = fault
        self.status = status
        self.body = body if body is not None else {"acknowledged": True}
        self.calls: list[dict[str, Any]] = []

    def __call__(  # noqa: PLR0913 — mirrors `docker_exec_curl`'s own signature (X9)
            self, ctx: Any, container: str, url: str, *, method: str = "GET",
                 headers: dict | None = None, body: dict | None = None,
                 timeout_sec: int = 10, insecure: bool = False,
                 auth: str | None = None, system: str | None = None,
                 secrets: tuple[str, ...] = ()) -> tuple[int, str, str]:
        self.calls.append({
            "ctx": ctx, "container": container, "url": url, "method": method,
            "headers": dict(headers or {}), "body": body, "timeout_sec": timeout_sec,
            "insecure": insecure, "auth": auth, "system": system, "secrets": secrets,
        })
        if self.fault.raise_after is not None and len(self.calls) > self.fault.raise_after:
            raise _transport_fault(f"docker exec failed: {url}")
        payload = json.dumps(self.body)
        if self.fault.malformed == "no-status-line":
            return 0, payload, ""
        if self.fault.malformed == "truncated-json":
            return 0, payload[: len(payload) // 2] + f"\n{self.status}", ""
        if self.fault.malformed == "empty-body":
            return 0, "", ""
        if self.fault.hits(url):
            return 0, json.dumps({"error": {"reason": f"refused {url}"}}) + "\n400", ""
        return 0, payload + f"\n{self.status}", ""

    @property
    def methods(self) -> list[str]:
        return [c["method"] for c in self.calls]

    @property
    def urls(self) -> list[str]:
        return [c["url"] for c in self.calls]


# --------------------------------------------------------------------------------------
# The model seams: the questioner's three calls and the comparator's one.
# --------------------------------------------------------------------------------------


class FakeAgent:
    """A recording stand-in for one model-backed call (`invoke=` on the questioner and the
    comparator).

    It is the second tier of the fault hierarchy and nothing more: an LLM is neither cheap nor
    deterministic to drive, so the reply is scripted and the PROMPT is captured. Every payload
    demand in this suite asserts against `agent.prompts` — what the seam was handed — because a
    fake that only returns answers leaves the outbound channel unpinned.
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
    """The launcher's process seam (`spawn=`) — D1's "a sibling is a `run.py` PROCESS".

    Records the argv and env of every child it was asked to start, and the wall-clock order in
    which the starts happened, so "started together" is an OBSERVATION rather than an
    inspection of a config flag. Runs no code: `exits` scripts each child's return code.
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
        # THE DELAY IS WHAT MAKES `overlap` OBSERVABLE. A child that answers in microseconds of
        # pure Python is never preempted mid-call — CPython hands the GIL over at a switch
        # interval measured in milliseconds — so N launchers released together still enter and
        # leave this frame one at a time, and `overlap` reads False for an implementation that
        # did start them together. A real `run.py` child blocks for the length of an
        # investigation; `delay` is the fake's stand-in for that, and it is what the fault spec
        # has always documented it as ("seconds a call blocks before answering").
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


#: Manifest fields #1255 retires: the continuation prompt (P4, stated). `family_doc` writes it
#: only while `Family` still declares it. NOT `fences_at` (recheck review RC-L5): the design
#: retires fence counting as a CUT RULE (P2) and says nothing of the field, which the judge
#: reads and `test_947_triplet_manifest` requires — an implementer who drops it from `Family`
#: must fail that suite loudly, not have this helper quietly stop writing it.
RETIRED_FAMILY_FIELDS = ("continuation_prompt",)


def _declared_family_fields() -> set[str]:
    import dataclasses

    return {f.name for f in dataclasses.fields(sym("runtime.branch._family", "Family"))}


def family_doc(*, worlds: list[dict] | None = None, source_run_dir: str = "/runs/source",
               as_of: str = AS_OF, continuation_prompt: str = "Continue from here.",
               **over: Any) -> dict:
    """A v2 `Family` document: the launcher's derived half, the operator's instrument field and
    the questioner's authored half, one document."""
    doc: dict[str, Any] = {
        "episode_id": EPISODE_ID,
        "source_run_dir": source_run_dir,
        "source_run_id": SOURCE_RUN_ID,
        "branch_message_id": BRANCH_MESSAGE_ID,
        "fences_at": 4,
        "as_of": as_of,
        "continuation_prompt": continuation_prompt,
        "base_story": "the captured story",
        # #1224: the launcher records the systems the tenant's gather grant served (the loader
        # reads no settings), so the authored document carries them.
        "served_systems": list(SERVED_SYSTEMS),
        "discriminator": {"predicate": "p"},
        "worlds": worlds if worlds is not None else [
            base_world(),
            world_doc("b", facts=[fact("f1", "a second login to web-1 came from 10.0.0.9",
                                       ("web-1", "10.0.0.9"))]),
            world_doc("c", role="C", facts=[fact("f2")]),
        ],
    }
    declared = _declared_family_fields()
    for retired in RETIRED_FAMILY_FIELDS:
        if retired not in declared:
            doc.pop(retired, None)
    doc.update(over)
    return doc


def retired_continuation_argv() -> list[str]:
    """`["--continuation-prompt", "go"]` while the branch CLI still requires the flag, else `[]`.

    #1255 (P4) removes the argument. Asked of the CLI's own parser (a bare request naming no
    prompt either parses or is refused for the missing flag), so a launcher scenario keeps
    reaching what it tests on both sides of the change. Whether the flag is GONE is
    `test_947_branch_cli`'s demand, never answered here. Delete once #1255 has landed."""
    import contextlib
    import io

    parse = sym("learning.branch.cli", "parse_branch_args")
    with contextlib.redirect_stderr(io.StringIO()):
        try:
            parse(["--tenant", SOURCE_TENANT, "run-x", "1"])
        except SystemExit:
            return ["--continuation-prompt", "go"]
    return []


def write_family(episode_dir: Path, doc: dict | None = None) -> Path:
    """Materialise `episodes/<id>/family.yaml` and return its path."""
    episode_dir.mkdir(parents=True, exist_ok=True)
    manifest = episode_dir / "family.yaml"
    manifest.write_text(_yaml.safe_dump(doc if doc is not None else family_doc()),
                        encoding="utf-8")
    return manifest


#: Whether the builders here plant what the front door leaves (#1222): a source run's alert
#: record, and the episode's copies of them. The older suites are written for runs the front door
#: made, so `tests/conftest.py` turns it on for them; #1222's own suite plants each of those
#: itself, including their absence, so it runs with it off.
PLANT_RECORDS = False


#: `tenant episodes folder -> the tmp_path of the first scene placed there by default` — see
#: `_default_root`. Keyed by the folder, which is per test (each test has its own data root), so
#: nothing carries between tests.
_FIRST_SCENE: dict[str, str] = {}


def _default_root(tmp_path: Path) -> Path:
    """Where `episode` puts a scene built with no `root=`: the FIRST scene a test builds — and
    every later call with the same `tmp_path` (a builder re-entered for one scene names one
    folder) — under this data root's tenant, `<T>/episodes/`; a scene built for a DIFFERENT
    `tmp_path` (a test's second scene, `accepted_episode(tmp_path / "linked")`) under a data root
    of its own, `<tmp_path>/scene-data-root/<T>/episodes/` (`tenant_episodes`). Every scene keeps
    `EPISODE_ID` and its tokens, as each did when it sat under its own `tmp_path`; Layout A holds
    one episode per id under a tenant, so without this a second scene would be built INTO the
    first (a FIFO the first planted then blocks the second's writes). The judge and the page
    reach either by id through the tenant whose folder holds it (`_judge_921.episode_runs_for`)."""
    home = current_tenant().episodes
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
    # THE BASE IS PRIMED, EMPTY, because that is the shape `prepare_episode` always leaves and
    # an episode holding a manifest and no base is a state production never produces. `Ledger`
    # refuses a missing base as the ordering guarantee that priming ran before any sibling
    # forked, so a fixture without one makes every world registry unbuildable for a reason the
    # scenario is not about. `base_capture` overwrites it wherever a scenario has rows.
    base = ep / "served" / "base.jsonl"
    if not base.exists():
        base.write_text("", encoding="utf-8")
    # #1187 (R5): every manifest reader refuses a manifest whose `episode_id` is not its
    # folder's name, so the default manifest names THIS episode's id.
    write_family(ep, doc if doc is not None else family_doc(episode_id=episode_id))
    if PLANT_RECORDS:
        _plant_source_input(ep, (doc or {}).get("source_run_dir"), (doc or {}).get("source_run_id"))
    return ep


def _plant_source_input(ep: Path, source_run_dir: str | None, source_run_id: str | None = None) -> None:
    """The source run's alert and record, as a launch copies them into the episode (#1222 A1):
    the source run's own when it holds them, else a plain one."""
    from defender.episodes._episode_paths import EpisodePaths
    from defender.run_repository import RunPaths
    from defender.tests.support.storage._alert_plant import plant_alert

    if source_run_id:
        from defender.run_repository import RunId, RunRefused
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


#: The tenant the fixture's SOURCE run was stamped with (#1077 stamps every run's tenant; #1106
#: M2 seeds each sibling's runs base from it). Set up from the committed fixture under the test's
#: data root (#1120 H2), so a launch that accepts it finds a complete tenant.
SOURCE_TENANT = fixture_uuid("tenant:playground")


def current_tenant() -> Any:
    """#1078: the ONE tenant O10 permits in this test's `DEFENDER_DATA_ROOT` (whichever
    `runs_base()`, `d9_tenant` or the like already set up there), as an accepted `Tenant`
    (#1120 D1) — for callers (`episode_dir`, `prepare_episode`, the runs repository) that need
    the tenant rather than its runs base alone. Set up from the committed fixture when the root has none yet."""
    from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant

    root = Path(os.environ["DEFENDER_DATA_ROOT"])
    existing = sorted(p.name for p in root.iterdir()
                      if (p / "tenant.json").is_file()) if root.is_dir() else []
    return set_up_tenant(root, existing[0] if existing else SOURCE_TENANT)


def tenant_episodes(data_root: Path) -> Path:
    """`<data_root>/<T>/episodes/` of this suite's tenant (`current_tenant().id`) set up under a
    data root of a scene's OWN (`_data_root_1078.set_up_tenant`; a second call is the first's
    tenant). #1187 Layout A allows one episode per id under a tenant and reaches an episode by id
    only there, so a test that builds several scenes at the default `EPISODE_ID` "each under its
    own episodes root" gives each its own data root, and the judge and the page reach each through
    that tenant's repository (`_judge_921.episode_runs_for` reads the data root off the episode's
    location). Pass the result as `episode(root=...)`."""
    from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant

    return set_up_tenant(Path(data_root), current_tenant().id).episodes


def runs_base(tmp_path: Path, *, source_run_id: str = SOURCE_RUN_ID,
              tenant_id: str | None = None, recorded: bool | None = None,
              pre_snapshot: bool = False,
              land_calls: Callable[[Path], None] | None = None) -> tuple[Path, Path]:
    """A runs base holding ONE ordinary finished run. Returns (base, source_run_dir)."""
    from defender.tenancy import _tenant
    from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant

    root = Path(os.environ["DEFENDER_DATA_ROOT"])
    if tenant_id is None:
        existing = sorted(p.name for p in root.iterdir()
                          if (p / "tenant.json").is_file()) if root.is_dir() else []
        tenant_id = existing[0] if existing else SOURCE_TENANT
    tenant = set_up_tenant(root, tenant_id)
    tenant.learning.mkdir(exist_ok=True)  # setup provisions the real launcher queue root
    base = _tenant.runs_base_for(tenant)
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
    # ONE CAPTURED CALL, because a source that captured nothing is not branchable: every
    # proposed world agrees with an empty prefix by construction, which is the generated-world
    # design the redesign rejected, and `branch.validate` refuses it at the launch. A scenario
    # that wants other rows lands them through `land_calls` (before the session is seeded);
    # one that lands this same call again writes a duplicate the primer skips, so the primed
    # key set is unchanged for it.
    if land_calls is None:
        capture_call(src)
    else:
        land_calls(src)
    # THE STAMP EVERY ORDINARY RUN DIR CARRIES. `materialize_run` writes one at the single
    # place a run the box will execute is ever created, so a source run without one is not a run
    # any production path could have produced — and the containment walks read exactly this file
    # to tell an ordinary run from an episode's contents.
    (src / "provenance.json").write_text(
        json.dumps(provenance_record(tenant_id=tenant_id)), encoding="utf-8")
    seed_source_session(base, src, pre_snapshot=pre_snapshot)
    return base, src


#: The case this fixture's source run belongs to. One id, because the run's case POINTER (the
#: sidecar beside the run dir) and the store the pointer names have to agree — that reconciliation is what
#: `open_source_store` checks, and it is the whole reason a branch can find its source's session.
SOURCE_CASE_ID = "case-947-fresh"


def source_case_id(src: Path) -> str:
    """The case a fixture source run belongs to: `SOURCE_CASE_ID` for the default source, and a
    case of its own for any other source id. The store is per case (`<sessions>/<case>.db`), and
    its row ids are the STORE's, so a second source seeded into the first source's case starts
    its session past `BRANCH_MESSAGE_ID` and the branch point can never land on its main path —
    each source run gets its own case, as each real investigation does."""
    if src.name == SOURCE_RUN_ID:
        return SOURCE_CASE_ID
    digest = hashlib.sha256(src.name.encode("utf-8")).hexdigest()[:16]
    return f"{SOURCE_CASE_ID}-{digest}"


def _source_handle(src: Path) -> Any:
    """The source run's handle, for writing its case pointer. A canonical-UUID folder (every
    run after #1187) through `_spec1077.fixture_run`, production's own rule. A source a test
    plants under an OLD-shaped or hostile id ON PURPOSE (to see the launcher refuse it before
    anything is spent, #1187 declared change 1) is a folder production can no longer name, so
    its handle is built at that folder directly — the fixture still seeds the session such a
    run had, and the refusal under test is the launcher's, not this fixture's."""
    from defender.run_repository import Run
    from defender.tests.support.shared._fixture_uuid import is_fixture_uuid_shape
    from defender.tests.support.shared.contracts._spec1077 import fixture_run

    src = Path(src)
    if is_fixture_uuid_shape(src.name):
        return fixture_run(src)
    return Run(src, runs_base=src.parent)


def seed_source_session(base: Path, src: Path, *, pre_snapshot: bool = False) -> None:
    """Give the source run the session store a branch is actually taken from."""
    from defender.run_repository import RunPaths, SessionPaths

    ss = mod("runtime.session_store")
    # #1235: the case pointer is a host-only sidecar beside the run dir, not a file in it.
    if RunPaths(src).session_pointer().exists():
        return
    from defender.tests.support.learning.branch import _branch_947
    from defender.tests.support.storage import _session_store_705 as S

    from defender.tests.support.shared._fixture_uuid import is_fixture_uuid_shape

    assert isinstance(pre_snapshot, bool), pre_snapshot

    # #1105 fork S(b): the store takes the layout owner's hand-out for the runs base.
    case_id = source_case_id(src)
    store = ss.open_store(case_id=case_id, sessions=SessionPaths(base))
    try:
        ss.write_case_pointer(_source_handle(src), case_id=case_id, store_path=store.path)
        session_id = store.new_session(agent_id="main")
        store.append(session_id, [S.user_request("investigate the alert")], agent_id="main")
        if not _branch_947.declares_retired_prompt():
            # #1255 (D1): a branch point is a MAIN response that CALLED tools, so the id must
            # land on a call, not on its return — one leading row shifts every pair by one.
            # Keyed on the same switch `_branch_947.spec_at` uses (is this tree past #1255?);
            # before it, `validate` refuses a call as "unanswered", so the old shape stays.
            store.append(session_id, [S.text_response("orienting")], agent_id="main")
        while BRANCH_MESSAGE_ID not in ss.path_row_ids(store, session_id):
            store.append(session_id, list(S.complete_pair()), agent_id="main")
        if not pre_snapshot and is_fixture_uuid_shape(src.name):
            # Legacy or hostile source ids are refused before the snapshot gate.
            # #1255 deferred verification 4: the fixture-only planter (see its module).
            from defender.tests.support.runtime.state._fork_snapshot_plant import plant_fork_snapshots

            plant_fork_snapshots(store, session_id, src)
    finally:
        store.close()


def capture_call(run_dir: Path, *, system: str = "elastic", verb: str = "query",
                 params: dict | None = None, payload: Any = None, lead: str = "l-001",
                 seq: int = 0) -> dict:
    """Land ONE captured call in a source run: the queries-table row and the sidecar it names."""
    rq = mod("runtime.record_query")
    breaker = mod("runtime.circuit_breaker")
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


#: The three NON-CLEAN stamp shapes `_provenance.capture_tree` can actually return, spelled once
#: because §7 round 2 settled that all three refuse absent `--allow-dirty` (FORK-10's answer, F4).
#: A `dirty: None` record that KEEPS a commit is only producible on the git-status arm, and only
#: with a reason beside it (`records/_provenance.py:338-345`); the git-could-not-be-asked arm is
#: `commit: None` (`_from_build_stamp`, `records/_provenance.py:293`). A fixture spelling either without
#: its reason is a shape no capture produced, which is how the old one read `dirty: None` as
#: covering "git could not be asked" while asserting over a record with a sha in it.
GIT_STATUS_FAILED = "git status: GitError('git status --porcelain=v1 -z', 128)"
GIT_UNAVAILABLE = "git unavailable: FileNotFoundError('git')"

#: The tenant knowledge commit every default stamp carries (#1204): every run materialised after
#: #1204 stamps `knowledge` from its tenant's clone, so a source, its siblings and the live
#: capture that agree on everything else agree on this too — which is what a real family
#: launched from one tenant clone looks like. A FULL 40-hex lowercase sha, never an abbreviation:
#: the reader folds any other shape to "the record does not say" (#1204 O4), which would make
#: every default stamp read as knowledge-absent — a waivable fault — and turn every
#: accept-without-the-flag scenario red for a reason it is not about. Before #1204 is
#: implemented `RunProvenance.from_obj` ignores the key, so the default is inert there.
KNOWLEDGE_SHA = "1204" + "d" * 36

#: A second, distinct knowledge commit, for the scenarios about a family across two of them.
OTHER_KNOWLEDGE_SHA = "1204" + "e" * 36


class _OmitKnowledge:
    """The type of `NO_KNOWLEDGE_KEY` (a named sentinel, so a failing assertion prints it)."""

    def __repr__(self) -> str:
        return "NO_KNOWLEDGE_KEY"


#: `provenance_record(knowledge=NO_KNOWLEDGE_KEY)` OMITS the `knowledge` key altogether: the
#: shape every stamp written before #1204 has. Distinct from `knowledge=None`, which writes JSON
#: `null` — the shape `as_json` writes for a record that does not say. Both read back as
#: `knowledge is None`; the two spellings exist so a scenario can name the one it means.
NO_KNOWLEDGE_KEY: Any = _OmitKnowledge()

#: The default `knowledge=` of `provenance_record` — a sentinel so each call builds a fresh dict.
_DEFAULT_KNOWLEDGE: Any = object()


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
        doc["knowledge"] = {"commit": KNOWLEDGE_SHA}
    elif knowledge is not NO_KNOWLEDGE_KEY:
        doc["knowledge"] = knowledge
    if dirty:
        doc["dirty_paths"] = ["defender/runtime/driver/__init__.py"]
        doc["dirty_path_count"] = 1
    # #1106 M2: the stamp every run materialised since #1077 carries its tenant, and a branched
    # episode seeds its siblings' tenant record FROM the SOURCE's. `None` (the default, so the
    # sibling-stamp call sites that spell their own `tenant_id` keep doing so) omits the field.
    if tenant_id is not None:
        doc["tenant_id"] = tenant_id
    return doc


def source_stamp(src: Path, **overrides: Any) -> Path:
    """Rewrite the SOURCE run's `provenance.json` — the anchor #976 reads at preflight.

    `runs_base` stamps the source with `provenance_record()` (commit `deadbee`, clean, scope
    `repo`); a scenario about the anchor's other shapes rewrites it here with the same builder,
    so the file on disk is always one `materialize_run` could have written. Absence and
    aliasing are NOT spelled here: a scenario about a missing or planted stamp unlinks or
    symlinks the real path itself, because the fault has to be the real one.
    """
    path = Path(src) / "provenance.json"
    # The source's tenant rides unless the scenario is ABOUT it (#1106 M2: a legacy stamp with
    # no tenant — `tenant_id=None` — is the one the launcher refuses, N10).
    overrides.setdefault("tenant_id", SOURCE_TENANT)
    path.write_text(json.dumps(provenance_record(**overrides)), encoding="utf-8")
    return path


class FakeCapture:
    """The launcher's live-tree seam (`live_tree=` on `cli.main`, #976 M2), scripted and counted.

    Production resolves it to `_provenance.capture_tree(REPO_ROOT)`, which asks git about the
    checkout the launcher is running in — so every end-to-end launcher scenario has to inject
    one whose answer matches the fixture source's stamp, or the live HEAD of whatever tree the
    suite runs in is what gets compared and refused. It is a zero-argument callable returning a
    `RunProvenance`, and it COUNTS: the design says the capture is taken once per launch, and
    "once" is an observation over `calls`, not a reading of the code.
    """

    def __init__(self, record: dict) -> None:
        self.record = dict(record)
        self.calls = 0

    def __call__(self):
        from defender.records._provenance import RunProvenance

        self.calls += 1
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

    With no overrides it matches the source `runs_base` stamps (commit `deadbee`, clean, scope
    `repo`, knowledge `KNOWLEDGE_SHA`), which is what an accepted launch needs;
    `source_capture(commit="0ther")`, `(dirty=True)`, `(dirty=None, unavailable=GIT_STATUS_FAILED)`
    and `(commit=None, dirty=None, unavailable=GIT_UNAVAILABLE)` are the four other shapes a real
    `capture_tree` answers with. `knowledge=` spells the live tenant clone's revision (#1204 D3:
    production's live capture reads it from the episode tenant's clone).
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
    """One `worlds/<X>/` directory carrying every artifact M8's row declares. No
    `worlds/<X>/run_dir` pointer: #1187 (R8, declared change 12) stops the archive writing it
    (nothing reads it; the arm roster supersedes it), so a scenario about an OLD archive's
    leftover pointer plants one itself."""
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
    """`<episode_dir>/arms.json` as plain JSON (`{world UUID: arm id}`) — the test reading back what a
    builder or the launcher wrote; `{}` when there is none."""
    path = Path(episode_dir) / ROSTER_NAME
    if not path.is_file():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def write_roster(episode_dir: Path, roster: dict[str, str]) -> Path:
    """`<episode_dir>/arms.json` holding `roster` — the host-written arm roster a launch leaves
    at the start of RUNS (#1187 R2), planted by hand. Overwrites."""
    path = Path(episode_dir) / ROSTER_NAME
    path.write_text(json.dumps(dict(roster), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return path


def _manifest_world_ids(episode_dir: Path) -> list[str]:
    """Explicit persisted world UUIDs of a hand-built episode, in manifest order."""
    doc = _yaml.safe_load((Path(episode_dir) / "family.yaml").read_text(encoding="utf-8"))
    return [world["world_id"] for world in doc["worlds"]]


def plant_roster(episode_dir: Path) -> dict[str, str]:
    """The fixture's EXPLICIT RUNS step for a hand-built scene (no launcher ran): makes
    `<episode_dir>/runs/` and then writes the arm roster once, a fresh uuid4 for EVERY manifest
    world (#1187 R2: `start_runs` makes `runs/`, then writes a roster naming exactly the
    manifest's worlds). Returns the roster. Refuses loudly (AssertionError) when a roster is
    already there (it is written once) or the manifest names no world. A scene that wants a
    stray arm no roster names plants `runs/<uuid4>` directly; it never extends the roster
    (review-3 F33)."""
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
    """The arm id the episode's roster holds for `world_id`. READ-ONLY (review-3 F33): it never
    writes or extends a roster, so a scene whose launcher (or explicit RUNS step,
    `plant_roster` / `episode_view`) wrote none fails here loudly, and so does a world UUID the
    roster does not name (a roster names exactly the manifest's worlds, #1187 R2)."""
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
    """A finished arm in the episode's own container, `<episode_dir>/runs/<arm id>` — the arm id
    the episode's roster holds for `label` (#1187: an arm is opened by its roster id through
    the episode's view, `family_arms`): `sibling_run_dir` over `<episode_dir>/runs`, every
    keyword passed through."""
    return sibling_run_dir(Path(episode_dir) / "runs", label, **kw)


def corpus_document(run_dir: Path) -> Path:
    """Give `run_dir` a REAL orientation-corpus document, copied from the committed golden run.

    `load_corpus` counts a document only when `parse_dense_companion` finds its three required
    top-level keys, so a `# investigation` stub is scanned and skipped — and a corpus assertion
    written over stubs compares 0 against 0 whatever the layout is. Copying the shipped golden
    keeps the fixture a real input through the real parser (tier 1) rather than a guess at the
    grammar.
    """
    run_dir.mkdir(parents=True, exist_ok=True)
    path = run_dir / "investigation.md"
    path.write_text(GOLDEN_INVESTIGATION.read_text(encoding="utf-8"), encoding="utf-8")
    # A run's record is what makes a folder a run to the corpus reader (#1222 A8).
    from defender.run_repository import RunPaths
    from defender.tests.support.storage._alert_plant import plant_alert

    if PLANT_RECORDS and not RunPaths(run_dir).alert_record.exists():
        plant_alert(run_dir, {"rule": {"id": "v2-cross-tier-ssh-pivot"}})
    return path


def open_source(src: Path) -> Any:
    """The source `Run` the launcher opens (#1105 PR 2): the run at `src` —
    `<data root>/<T>/runs/<run id>` — by its id, through tenant T's runs repository, T accepted
    under that data root. What `preflight_episode(source=)` / `preflight_replay(source=)` take
    where a test once handed the folder."""
    from defender.tenancy import _tenant
    from defender.run_repository import RunId

    src = Path(src)
    tenant = _tenant.accept_tenant(src.parent.parent.parent, src.parent.parent.name,
                                   defender_dir=DEFENDER)
    return tenant.runs_repository().open(RunId.parse(src.name))


def episode_view(episode: Any, *, tenant: Any = None) -> Any:
    """The episode's view (`EpisodeRuns`) in `tenant`'s runs repository (default: this data
    root's one tenant, `current_tenant()`), adopting the held `episode` — `runs.episode(<id>,
    held=episode)`. #1187: no container record is judged or planted (R1). An episode with no
    arm roster yet never reached RUNS, so the fixture takes the launcher's RUNS step for it:
    `view.start_runs(<every manifest world UUID>)` makes `runs/` and writes the roster (R2).
    A roster a scene already planted (`arm_run_dir`) is the episode's own and is kept.
    `start_family` callers reach RUNS this way; `verify_family` callers open their arms through
    it (`family_arms`)."""
    owner = current_tenant() if tenant is None else tenant
    view = owner.runs_repository().episode(episode.dir.name, held=episode)
    if view.arm_ids() is None:
        view.start_runs(_manifest_world_ids(Path(episode.dir)))
    return view


def family_arms(episode: Any, labels: Any, *, tenant: Any = None) -> dict[str, Any]:
    """`verify_family`'s UUID-keyed `arms`, resolving the fixture labels through the manifest
    before `view.arm_id(world_uuid)`, opened by id through the episode's view (`episode_view`), as
    the launcher's `_finished_arms` does — the `RunRefused` an open raises (`RunAbsent` for a
    roster id with no folder: "not started") kept as that world UUID's value."""
    from defender.run_repository import RunRefused

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

    The serving path answers from the primed capture BEFORE calling any adapter (C15) — so "no
    post-branch query reaches a real adapter unasked" is only observable if something records
    what the adapter layer was asked for. That is this fake's whole job: it records `(system, verb, params)` per call and
    answers from a scripted table, so an unrecorded call is a demand failing rather than a
    silence nobody can see.
    """

    def __init__(self, answers: dict[tuple[str, str], Any] | None = None, *,
                 by_target: dict[str, Any] | None = None, fault: Fault = CLEAN) -> None:
        self.answers = dict(answers or {})
        #: Keyed by a SUBSTRING of the bound params, so one fake answers two calls differently
        #: without ever being told which world is asking.
        self.by_target = dict(by_target or {})
        self.fault = fault
        self.calls: list[tuple[str, str, dict]] = []
        #: Every world token `for_world` was asked for, in order. The production read side
        #: hands back a copy whose context DECLARES the world, which is the only thing that
        #: makes a `wv-<world>-<corpus>` alias admissible at `confine_index`; a fake carries no
        #: confinement, so it records the request and answers as itself. A test that wants to
        #: know a staged read went out under its own world's declaration reads this.
        self.world_views: list[str] = []

    def for_world(self, world_id: str) -> FakeAdapters:
        """The per-world view `seams.EpisodeAdapters` provides and the review requires.

        SELF, not a copy: `calls` is what every demand in this suite asserts on, and a copy per
        world would split one world's staged reads off the list its base reads are on.
        """
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
    """Every class a refusal in this design may be — and NEVER bare `Exception`.

    `pytest.raises(Exception)` is the shape that turns a spec suite green on its own absence: a
    module the design has not built yet raises `ModuleNotFoundError`, which is an `Exception`, so
    the assertion passes while proving nothing at all. Every refusal assertion in this suite
    names this tuple instead, and because it is EVALUATED before the `raises` block opens, a
    missing target fails the test at the call rather than satisfying it.
    """
    from defender.learning.branch.estate.registry import EstateError
    from defender.learning.branch.ledger import LedgerError
    from defender.runtime.branch import BranchError
    from defender.integrations.confinement import ConfinementFault
    from defender.integrations.faults import AdapterFault
    out: list[type[BaseException]] = [
        SystemExit, EstateError, LedgerError, BranchError, ConfinementFault,
        AdapterFault, ValueError,
    ]
    for dotted, name in (("runtime.branch._family", "FamilyError"),
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
    "FakeAdapters", "FakeAgent", "FakeSpawn", "FakeTransport", "SERVED_SYSTEMS",
    "UNTRUSTED_FRAME", "assert_wrapped_untrusted", "outside_untrusted_frames", "untrusted_frames",
    "Fault", "base_capture", "captured_row",
    "archived_world", "base_world", "capture_call", "configured_layout", "ROSTER_NAME",
    "read_roster", "write_roster", "roster_arm_id", "plant_roster",
    "report_text",
    "corpus_document",
    "episode", "episode_view", "fact", "family_arms", "family_doc", "open_source",
    "provenance_record",
    "FakeCapture", "source_capture", "source_stamp", "isolate_learning_state", "LEARNING_STATE_ENV",
    "lesson_row", "mod", "refusals", "replace", "runs_base",
    "arm_run_dir", "sibling_run_dir",
    "sym", "world_doc", "fixture_world_id", "world_id", "declaration", "write_family",
]
