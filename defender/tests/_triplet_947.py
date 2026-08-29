"""Shared machinery for #947's questioner-authored-triplet spec — NO test scripts.

This is the spec suite for the design in `.spec-flow/design-doc.md`: an operator names
(source run, N); a deny-all QUESTIONER role authors a triplet of worlds into
`episodes/<id>/family.yaml`; staging writes a per-world Elasticsearch corpus under the `wv-`
namespace, write-ahead-recorded in `staged.yaml`; a replay review rejects any world that
contradicts the capture or whose declared difference is unreachable; each accepted world then
runs as its own `run.py --resume` PROCESS; the launcher verifies every scrub and stamp,
archives each world under `worlds/<X>/`, and two derived readers compute from the episode dir.

**Eight of the modules these tests drive do not exist at the base commit** (X16:
`learning/branch/{staging,review,comparator,archive,episode}.py`, `learning/branch/questioner/`,
`runtime/branch/_family.py`). That is the expected state of a spec — RED against HEAD. Every
import goes through `mod()` PER TEST (the `_session_store_705` / `_branch_947` idiom) so a
missing target is one failure per test rather than one collection error that hides the other
hundred-odd assertions.

Four things live here and nothing else.

1. **`mod()` / `sym()`** — the per-test import.

2. **The declarative fault-injection fakes.** One fake per dependency, each driven by a data
   `Fault(...)` spec (`fail_on`, `raise_after`, `malformed`, `delay`). A fake INJECTS ONLY: it
   never classifies a fault, never decides policy, and never answers a question the production
   code is supposed to answer. Every fake RECORDS what it was handed, because a fake that only
   returns answers leaves the whole outbound channel unpinned — the assertion a payload demand
   makes is against `fake.calls`, not against the canned reply.

   Every fault SHAPE here cites the ledger claim that observed it on the real dependency
   (`spec-flow/specs/spec_graph_947.yaml`, `claims:`). No fault in this suite is imagined:
   * `malformed="no-status-line"` — PO-C3, executed and refuted: `split_status` over stdout
     with no parseable trailing status line yields `("", <whole body>)`, and a failed create
     then reads as SUCCESS against a write-ahead-recorded name. That is the behaviour of the
     one write door that ships today.
   * `raise_after=n` with `TransportFault` — the real class at `scripts/adapters/faults.py`,
     exit_code 2, which `docker_exec_curl` raises when the docker exec itself fails (X9).
   * `fail_on=(<name>,)` — a per-name cluster-side refusal, S30/S34's "the guard is a pre-flight
     check on the target NAME, not a promise the cluster accepts the call".
   Anything else a test wants induced is a PROBE REQUEST, not a fake: see 80-author-digest.md.

3. **The builders** — an episode on disk, a runs base with a source run, an archived world.
   A new scenario is a few lines of data against these, not fresh plumbing.

4. **The untrusted-frame reader** (`assert_wrapped_untrusted`). `wrap_fresh` mints a fresh salt
   per frame, so a test that calls it a SECOND time to build a marker names a frame the target
   never emitted — an assertion no implementation can satisfy. Read the frame off the text.

Fakes enter through the entry point's INJECTION SEAMS (a `deps`-shaped keyword, a constructor
argument) and never by `monkeypatch.setattr` — the project profile's `tests.idioms`, ratcheted
in CI by `scripts/lint/lint_monkeypatch.py`. Where the design named no seam, the seam is part of
the contract and is pinned by a `kind: seam` demand rather than reached around.

Underscore-prefixed so pytest does not collect it; it defines no tests.
"""
from __future__ import annotations

import importlib
import json
import re
import threading
import time
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any

DEFENDER = Path(__file__).resolve().parents[1]

#: The episode token / world token shapes the design fixes (design-doc "Two ids per world, one
#: rule"), executed as nameable by G12 with the realistic token
#: `20260728t161845z.fresh.case.n59.b`. Kept here so every scenario spells them once.
#: CASEFOLDED, and not merely by taste: `cli.refuse_bad_episode_id` holds an episode id to
#: `is_case_stable_id` at b8a63e66 (executed — the mixed-case spelling exits 2 naming the
#: casefolded one), because the id names one directory and two spellings of it are one directory
#: wherever the filesystem folds case. The design DERIVES this id rather than taking it from the
#: operator, so the derivation is held to the same rule; `EPISODE_TOKEN` is the same string with
#: separators normalised.
EPISODE_ID = "20260728t161845z-fresh-case-n59"
EPISODE_TOKEN = "20260728t161845z.fresh.case.n59"
SOURCE_RUN_ID = "20260728T161845Z-fresh-case"
BRANCH_MESSAGE_ID = 59
AS_OF = "2026-07-28T16:18:45Z"
WORLDS = ("a", "b", "c")

#: The two CONFIGURED roots this design reads. `DEFENDER_RUNS_BASE` is the shipped one
#: (`run_common.resolve_runs_base`); `DEFENDER_EPISODES_BASE` is the second the §7 round-2 seam
#: added — the episodes root is a CONFIGURED location, outside both the runs base and the
#: checkout, and is never derived from the runs base. Environment steering, not
#: `monkeypatch.setattr`: `resolve_runs_base` already reads its root off the environment, so this
#: is the seam the shipped resolver already has (project profile, `tests.idioms`).
RUNS_BASE_ENV = "DEFENDER_RUNS_BASE"
EPISODES_BASE_ENV = "DEFENDER_EPISODES_BASE"

#: A committed `\`\`\`invlang` companion document — the orientation corpus's own input shape.
#: `skills/invlang/corpus.load_corpus` only counts a document that PARSES (three required
#: top-level keys), so a stub would make every corpus assertion read 0 == 0 and pass on the
#: absence of the thing it measures.
GOLDEN_INVESTIGATION = DEFENDER / "fixtures-e2e" / "golden-v2sshd" / "investigation.md"

#: The two configured corpus patterns (G11: 11 distinct patterns across the shipped query
#: corpus; these two are the configured pair, `knowledge/environment/systems/elastic/config.env`).
EVENTS_PATTERN = "logs-*"
ALERTS_PATTERN = ".internal.alerts-security.alerts-default-*"
CONFIGURED = (EVENTS_PATTERN, ALERTS_PATTERN)


def mod(dotted: str):
    """Import `defender.<dotted>` at CALL time, never at collection time."""
    return importlib.import_module(f"defender.{dotted}")


def sym(dotted: str, name: str):
    """One attribute off a lazily-imported module — `AttributeError` is a real red."""
    return getattr(mod(dotted), name)


def no_preflight(_model: str | None = None) -> int:
    """The role-model preflight, neutralised — for every scenario that is not about it.

    `preflight_role_models` sources a BILLABLE provider key and exits 2 when there is none, so a
    launcher scenario that leaves it to the ambient environment passes or fails on whether the
    host happens to be credentialed rather than on the thing it asserts. CI is not credentialed
    and a developer's machine usually is, which is the shape that makes a suite look flaky.

    The second cost is worse than the first: a scenario asserting "this refuses" is SATISFIED by
    the preflight's own refusal, so it goes green in an uncredentialed runner without ever
    reaching the check it names. Injected here, those arms refuse for their own reason or not
    at all.

    The family-level preflight is not left unexercised by this — it has its own demand and its
    own test, `test_947_role_preflight_runs_once_for_the_family_and_again_in_each_sibling`,
    which injects a RECORDING seam and observes the call. That test deliberately does not use
    this one.
    """
    return 0


def world_token(world_id: str, *, episode_token: str = EPISODE_TOKEN) -> str:
    """`f"{episode_token}.{X}"` — the ONE spelling the four comparing sites use."""
    return f"{episode_token}.{world_id}"


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


# --------------------------------------------------------------------------------------
# The cluster's write door (M3's host-side seam) and the transport under it.
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class DoorCall:
    """One thing the staging write door was ASKED to do."""

    op: str                       # create_index | create_alias | delete | exists | count | resolve
    name: str
    payload: dict[str, Any] = field(default_factory=dict)


class FakeDoor:
    """The host-side Elasticsearch write door as a recording, fault-injecting fake.

    It is the injection seam M3's staging, teardown and sweep take (`door=`), and it stands in
    for the ONE production door that reaches `transport.docker_exec_curl` with PUT/DELETE.
    It holds a set of names that "exist on the cluster" so teardown's delete-then-verify and
    the sweep's list-then-remove have something real to be right or wrong about.

    It classifies nothing. `fail_on` raises for a name; `malformed` hands back a body shape the
    ledger observed; neither decides whether the caller should treat that as a failure — which
    is exactly the reading PO-C3 says the staging door must get right.
    """

    def __init__(self, *, fault: Fault = CLEAN, existing: tuple[str, ...] = (),
                 counts: dict[str, int] | None = None,
                 resolves: dict[str, tuple[str, ...]] | None = None) -> None:
        self.fault = fault
        self.names: set[str] = set(existing)
        self.calls: list[DoorCall] = []
        self.connections = 0
        self._counts = dict(counts or {})
        self._resolves = dict(resolves or {})

    # -- the observation channel ---------------------------------------------------------
    @property
    def ops(self) -> list[tuple[str, str]]:
        return [(c.op, c.name) for c in self.calls]

    def created(self) -> list[str]:
        return [c.name for c in self.calls if c.op in {"create_index", "create_alias"}]

    def deleted(self) -> list[str]:
        return [c.name for c in self.calls if c.op == "delete"]

    def only(self, op: str) -> DoorCall:
        hits = [c for c in self.calls if c.op == op]
        assert len(hits) == 1, f"expected exactly one {op}, got {self.ops}"
        return hits[0]

    # -- the fault gate ------------------------------------------------------------------
    def _gate(self, op: str, name: str, payload: dict[str, Any]) -> None:
        self.calls.append(DoorCall(op=op, name=name, payload=dict(payload)))
        if op in {"create_index", "create_alias", "delete", "count"}:
            self.connections += 1
        if self.fault.raise_after is not None and self.connections > self.fault.raise_after:
            raise self._transport_fault(f"docker exec failed reaching {name}")
        if self.fault.hits(name):
            raise self._upstream_fault(f"cluster refused {name}")

    @staticmethod
    def _transport_fault(detail: str) -> Exception:
        return sym("scripts.adapters.faults", "TransportFault")(detail)

    @staticmethod
    def _upstream_fault(detail: str) -> Exception:
        return sym("scripts.adapters.faults", "UpstreamFault")(detail)

    # -- the door's surface --------------------------------------------------------------
    def create_index(self, name: str, *, docs: list[dict]) -> None:
        self._gate("create_index", name, {"docs": docs})
        self.names.add(name)

    def create_alias(self, name: str, *, over: list[str], filter: dict | None) -> None:
        self._gate("create_alias", name, {"over": list(over), "filter": filter})
        self.names.add(name)

    def delete(self, name: str) -> None:
        self._gate("delete", name, {})
        self.names.discard(name)

    def exists(self, name: str) -> bool:
        self._gate("exists", name, {})
        return name in self.names

    def list_names(self, glob: str) -> list[str]:
        self._gate("list_names", glob, {})
        head = glob.rstrip("*")
        return sorted(n for n in self.names if n.startswith(head))

    def count(self, index: str, *, query: dict | None = None) -> int:
        self._gate("count", index, {"query": query})
        return self._counts.get(index, 0)

    def resolve(self, pattern: str) -> list[str]:
        self._gate("resolve", pattern, {})
        return list(self._resolves.get(pattern, (f"{pattern.rstrip('*')}000001",)))


class FakeTransport:
    """`transport.docker_exec_curl`'s shape, as a recording fake (X9's executed signature).

    Returns `(returncode, stdout, stderr)` with stdout = body + "\\n" + http_code, which is
    what `split_status` is built to recover. `malformed="no-status-line"` drops the trailing
    line — PO-C3's executed fault: `split_status` then returns `("", <whole body>)` and the
    caller that compares the second element to "200" reads a FAILED create as a success.

    Records `argv`-shaped call state so a test can assert a derived staging name reached the
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
                 auth: str | None = None) -> tuple[int, str, str]:
        self.calls.append({
            "ctx": ctx, "container": container, "url": url, "method": method,
            "headers": dict(headers or {}), "body": body, "timeout_sec": timeout_sec,
            "insecure": insecure, "auth": auth,
        })
        if self.fault.raise_after is not None and len(self.calls) > self.fault.raise_after:
            raise FakeDoor._transport_fault(f"docker exec failed: {url}")
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


def overlay(*, patches: dict | None = None, elastic: dict | None = None) -> dict:
    """An `Overlay` document. Empty halves are omitted, so the base world is `{}`."""
    doc: dict[str, Any] = {}
    if patches:
        doc["patches"] = patches
    if elastic:
        doc["elastic"] = elastic
    return doc


def elastic_overlay(pattern: str = EVENTS_PATTERN, *, inject: list[dict] | None = None,
                    exclude: dict | None = None) -> dict:
    """The elastic half, keyed by the base pattern it stages."""
    return {pattern: {"inject": inject or [], "exclude": exclude}}


def world_doc(world_id: str, *, role: str = "B", story: str = "a story",
              axis: str | None = "an axis", disposition_declared: str = "malicious",
              label_basis: str = "policy-rule", ov: dict | None = None) -> dict:
    return {
        "world_id": world_id, "role": role, "story": story, "axis": axis,
        "disposition_declared": disposition_declared, "label_basis": label_basis,
        "overlay": ov if ov is not None else {},
    }


def base_world() -> dict:
    """World A: the base — empty overlay, `axis: null`, role A."""
    return world_doc("a", role="A", axis=None, ov={})


def family_doc(*, worlds: list[dict] | None = None, source_run_dir: str = "/runs/source",
               as_of: str = AS_OF, continuation_prompt: str = "Continue from here.",
               **over: Any) -> dict:
    """A `Family` document: the launcher's derived half, the operator's instrument field and
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
        "discriminator": {"predicate": "p", "holding_system": "elastic",
                          "envelope": {"system": "elastic", "verb": "esql",
                                       "params": {"query": f"FROM {EVENTS_PATTERN} | LIMIT 5"}}},
        "worlds": worlds if worlds is not None else [
            base_world(),
            world_doc("b", ov=overlay(elastic=elastic_overlay(inject=[{"_id": "i1"}]))),
            world_doc("c", ov=overlay(patches={"identity": {"web-1": {"owner": "platform"}}})),
        ],
    }
    doc.update(over)
    return doc


def write_family(episode_dir: Path, doc: dict | None = None) -> Path:
    """Materialise `episodes/<id>/family.yaml` and return its path."""
    import yaml

    episode_dir.mkdir(parents=True, exist_ok=True)
    manifest = episode_dir / "family.yaml"
    manifest.write_text(yaml.safe_dump(doc if doc is not None else family_doc()),
                        encoding="utf-8")
    return manifest


def episode(tmp_path: Path, *, doc: dict | None = None,
            episode_id: str = EPISODE_ID, root: Path | None = None) -> Path:
    """An episode dir with its manifest and an empty `served/` — the shape step 2 leaves.

    HAND-BUILT, and deliberately so: this is the episode's CONTENTS for the scenarios that are
    not about where an episode lives. Where it lives is a demand of its own — the episodes root
    is a CONFIGURED location outside both the runs base and the checkout (§7 round 2), pinned by
    `test_947_the_episodes_root_is_read_from_configuration_not_the_runs_base` and its neighbours
    in `test_947_triplet_archive.py`, every one of which resolves the path through
    `cli.episode_dir_for` rather than composing one here.

    `root=` puts the episode under a CONFIGURED episodes root — pass `configured_layout`'s third
    return value where a scenario must be able to tell the episodes root and the runs base apart.
    Without it the two are indistinguishable under one `tmp_path`, and an assertion about which
    one a value is holds for both.
    """
    ep = (root if root is not None else tmp_path / "episodes") / episode_id
    (ep / "served").mkdir(parents=True, exist_ok=True)
    # THE BASE IS PRIMED, EMPTY, because that is the shape `prepare_episode` always leaves and
    # an episode holding a manifest and no base is a state production never produces. `Ledger`
    # refuses a missing base as the ordering guarantee that priming ran before any sibling
    # forked, so a fixture without one makes every world registry unbuildable for a reason the
    # scenario is not about. `base_capture` overwrites it wherever a scenario has rows.
    base = ep / "served" / "base.jsonl"
    if not base.exists():
        base.write_text("", encoding="utf-8")
    write_family(ep, doc)
    return ep


def runs_base(tmp_path: Path, *, source_run_id: str = SOURCE_RUN_ID) -> tuple[Path, Path]:
    """A runs base holding ONE ordinary finished run. Returns (base, source_run_dir).

    The source carries the two artifacts a sibling seeds from — `alert.json` and
    `investigation.md` — because both are model-writable (the run dir is a prior box's rw bind)
    and the containment demands drive exactly those reads.
    """
    base = tmp_path / "defender-runs"
    src = base / source_run_id
    (src / "gather_raw").mkdir(parents=True, exist_ok=True)
    (src / "alert.json").write_text(json.dumps({"rule": {"id": "v2-cross-tier-ssh-pivot"}}),
                                    encoding="utf-8")
    (src / "investigation.md").write_text("# investigation\n\n```invlang\n?h1\n```\n",
                                          encoding="utf-8")
    (src / "report.md").write_text("disposition: malicious\n", encoding="utf-8")
    (src / "executed_queries.jsonl").write_text("", encoding="utf-8")
    # THE STAMP EVERY ORDINARY RUN DIR CARRIES. `materialize_run_dir` writes one at the single
    # place a run the box will execute is ever created, so a source run without one is not a run
    # any production path could have produced — and the containment walks read exactly this file
    # to tell an ordinary run from an episode's contents.
    (src / "provenance.json").write_text(json.dumps(provenance_record()), encoding="utf-8")
    seed_source_session(base, src)
    return base, src


#: The case this fixture's source run belongs to. One id, because the case POINTER in the run
#: dir and the store the pointer names have to agree — that reconciliation is what
#: `open_source_store` checks, and it is the whole reason a branch can find its source's session.
SOURCE_CASE_ID = "case-947-fresh"


def seed_source_session(base: Path, src: Path) -> None:
    """Give the source run the session store a branch is actually taken from.

    A RUN WITHOUT ONE IS NOT BRANCHABLE, and pretending otherwise pushed the cost into the
    production code: T0 is the moment the branch point was written, `branch_point_time` reads it
    off the store because the store is the only thing that knows, and a fixture with no store
    forces every caller into a fallback. Seeded here, once, so every launcher scenario derives
    its clock the way a real episode does.

    LONG ENOUGH TO HOLD THE BRANCH POINT. `BRANCH_MESSAGE_ID` is a row id on the run's own main
    path, so the session has to have at least that many rows before the id names anything —
    complete pairs are appended until it does, which is also the shape `validate` admits as a
    branch point (a resolved call/return boundary rather than a dangling call).

    Idempotent: `runs_base` is called more than once in some scenarios, and a second session
    under one case id would make "the run's own main session" ambiguous.
    """
    ss = mod("runtime.session_store")
    if (src / "session_store_pointer.json").exists():
        return
    from defender.tests import _session_store_705 as S

    store = ss.open_store(case_id=SOURCE_CASE_ID, runs_base=base)
    try:
        ss.write_case_pointer(src, case_id=SOURCE_CASE_ID, store_path=store.path)
        session_id = store.new_session(agent_id="main")
        store.append(session_id, [S.user_request("investigate the alert")], agent_id="main")
        while BRANCH_MESSAGE_ID not in ss.path_row_ids(store, session_id):
            store.append(session_id, list(S.complete_pair()), agent_id="main")
    finally:
        store.close()


def capture_call(run_dir: Path, *, system: str = "elastic", verb: str = "query",
                 params: dict | None = None, payload: Any = None, lead: str = "l-001",
                 seq: int = 0) -> dict:
    """Land ONE captured call in a source run: the queries-table row and the sidecar it names.

    The shape `query_tool` writes and `prime_base` reads — a real `query_id` (so the row is a
    capture rather than a writer-only sentinel), `exit_code: 0` (so it is an ANSWER, which is
    the only thing the family tier has a representation for), and a payload file at the path the
    row names.

    Here rather than inside one scenario because it is the only way to give a LAUNCHER test a
    primed capture at all: the launcher primes from the source run's own table, so a test that
    needs the episode's base to hold a key has to put that key in the source.
    """
    row = {
        "lead_id": lead, "seq": seq, "system": system, "verb": verb,
        "query_id": f"{system}.{verb}", "params": params or {"index": EVENTS_PATTERN},
        "payload_path": f"gather_raw/{lead}/{seq}.json",
        "exit_code": 0, "error_class": None, "payload_status": "ok",
    }
    table = run_dir / "executed_queries.jsonl"
    with table.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")
    sidecar = run_dir / str(row["payload_path"])
    sidecar.parent.mkdir(parents=True, exist_ok=True)
    sidecar.write_text(
        json.dumps(payload if payload is not None else {"hits": [{"_id": "d1"}]},
                   sort_keys=True),
        encoding="utf-8")
    return row


#: The three NON-CLEAN stamp shapes `_provenance.capture_tree` can actually return, spelled once
#: because §7 round 2 settled that all three refuse absent `--allow-dirty` (FORK-10's answer, F4).
#: A `dirty: None` record that KEEPS a commit is only producible on the git-status arm, and only
#: with a reason beside it (`_provenance.py:338-345`); the git-could-not-be-asked arm is
#: `commit: None` (`_from_build_stamp`, `_provenance.py:293`). A fixture spelling either without
#: its reason is a shape no capture produced, which is how the old one read `dirty: None` as
#: covering "git could not be asked" while asserting over a record with a sha in it.
GIT_STATUS_FAILED = "git status: GitError('git status --porcelain=v1 -z', 128)"
GIT_UNAVAILABLE = "git unavailable: FileNotFoundError('git')"


def provenance_record(*, commit: str | None = "deadbee", dirty: bool | None = False,
                      unavailable: str | None = None, model: str = "m-1") -> dict:
    """One `provenance.json` document, in a shape `capture_tree` can produce.

    Four shapes and no others: the clean tree, the dirty tree, the git-status failure (a sha in
    hand and no answer about the tree, with the reason beside it) and the git-unavailable case
    (no sha at all). `scope` is carried because the record does.
    """
    doc: dict[str, Any] = {
        "commit": commit, "dirty": dirty, "dirty_paths": [], "dirty_path_count": 0,
        "unavailable": unavailable, "scope": "repo", "model": model,
    }
    if dirty:
        doc["dirty_paths"] = ["defender/runtime/driver/__init__.py"]
        doc["dirty_path_count"] = 1
    return doc


def archived_world(episode_dir: Path, world_id: str, *, disposition: str = "malicious",
                   scrub_ran: bool = True, commit: str | None = "deadbee",
                   dirty: bool | None = False, unavailable: str | None = None) -> Path:
    """One `worlds/<X>/` directory carrying every artifact M8's row declares."""
    w = episode_dir / "worlds" / world_id
    (w / "gather_raw").mkdir(parents=True, exist_ok=True)
    (w / "report.md").write_text(f"disposition: {disposition}\n", encoding="utf-8")
    (w / "investigation.md").write_text(f"# world {world_id}\n", encoding="utf-8")
    (w / "executed_queries.jsonl").write_text("", encoding="utf-8")
    (w / "provenance.json").write_text(
        json.dumps(provenance_record(commit=commit, dirty=dirty, unavailable=unavailable)),
        encoding="utf-8")
    (w / "scrub_verdict.json").write_text(json.dumps({"ran": scrub_ran}), encoding="utf-8")
    (w / "run_dir").write_text(f"/runs/{EPISODE_ID}-{world_id}\n", encoding="utf-8")
    return w


def sibling_run_dir(base: Path, world_id: str, *, scrub_ran: bool = True,
                    commit: str | None = "deadbee", dirty: bool | None = False,
                    unavailable: str | None = None,
                    model: str = "m-1", stamp: bool = True) -> Path:
    """A finished sibling run dir plus its scrub-verdict SIDECAR, under `base`.

    `base` is the runs base the sibling's own PROCESS was handed — after §7 FORK-13 that is
    `<episode_dir>/runs`, never the operator's runs base, so a scenario about containment passes
    the relocated root here rather than hand-placing a directory the production path never makes.

    The verdict is written at `scrub.verdict_path(run_dir)` — `tree.parent /
    f"{tree.name}.scrub-verdict.json"` — because G17 REFUTED the design's "inside the run dir"
    reading; a fixture that put it in the tree would make the archive test green on a path the
    production writer never uses.
    """
    run_dir = base / f"{EPISODE_ID}-{world_id}"
    (run_dir / "gather_raw").mkdir(parents=True, exist_ok=True)
    (run_dir / "report.md").write_text("disposition: malicious\n", encoding="utf-8")
    (run_dir / "investigation.md").write_text(f"# world {world_id}\n", encoding="utf-8")
    (run_dir / "executed_queries.jsonl").write_text("", encoding="utf-8")
    if stamp:
        (run_dir / "provenance.json").write_text(
            json.dumps(provenance_record(commit=commit, dirty=dirty, unavailable=unavailable,
                                         model=model)),
            encoding="utf-8")
    if scrub_ran is not None:
        (base / f"{run_dir.name}.scrub-verdict.json").write_text(
            json.dumps({"ran": scrub_ran}), encoding="utf-8")
    return run_dir


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
    return path


def configured_layout(tmp_path: Path, monkeypatch) -> tuple[Path, Path, Path]:
    """The two CONFIGURED roots, both under `tmp_path`, and the source run — the relocated layout.

    Returns `(runs_base, source_run_dir, episodes_root)`. The episodes root is a sibling of the
    runs base here only because `tmp_path` is where a test may write; what the demands assert is
    that it is READ FROM CONFIGURATION and is neither inside the runs base nor inside the
    checkout. Both roots are steered with `monkeypatch.setenv` because `resolve_runs_base` is
    already an environment-read; nothing here patches a module attribute.
    """
    base, src = runs_base(tmp_path)
    root = tmp_path / "episodes-root"
    monkeypatch.setenv(RUNS_BASE_ENV, str(base))
    monkeypatch.setenv(EPISODES_BASE_ENV, str(root))
    return base, src, root


def staged_rows(episode_dir: Path) -> list[dict]:
    """`staged.yaml`'s rows, in written order."""
    import yaml

    text = (episode_dir / "staged.yaml").read_text(encoding="utf-8")
    return list(yaml.safe_load(text) or [])


def review_doc(episode_dir: Path) -> dict:
    import yaml

    return yaml.safe_load((episode_dir / "review.yaml").read_text(encoding="utf-8"))


def lesson_row(run_dir: Path, name: str = "L1",
               loaded_at: str = "2026-07-28T17:00:00Z") -> None:
    """One `lessons_loaded.jsonl` row — what `trace_lesson.in_context_cases` selects on."""
    (run_dir / "lessons_loaded.jsonl").write_text(
        json.dumps({"lesson_name": name, "loaded_at": loaded_at}) + "\n", encoding="utf-8")


class FakeAdapters:
    """The real adapter bodies' stand-in behind the serving registry (`adapters=`).

    The review replays the captured set through a `WorldRegistry`, and the serving path answers
    from the primed capture BEFORE calling any adapter (C15) — so "no post-branch query reaches
    a real adapter unasked" is only observable if something records what the adapter layer was
    asked for. That is this fake's whole job: it records `(system, verb, params)` per call and
    answers from a scripted table, so an unrecorded call is a demand failing rather than a
    silence nobody can see.
    """

    def __init__(self, answers: dict[tuple[str, str], Any] | None = None, *,
                 by_target: dict[str, Any] | None = None, fault: Fault = CLEAN) -> None:
        self.answers = dict(answers or {})
        #: Keyed by a SUBSTRING of the bound params — a staged world's params carry its own
        #: world token, so this is how one fake answers a control and a staged sibling
        #: differently without ever being told which world is asking.
        self.by_target = dict(by_target or {})
        self.fault = fault
        self.calls: list[tuple[str, str, dict]] = []

    def __call__(self, system: str, verb: str, **params: Any) -> Any:
        self.calls.append((system, verb, dict(params)))
        rendered = json.dumps(params, sort_keys=True, default=str)
        for needle, answer in self.by_target.items():
            if needle in rendered:
                return answer
        if self.fault.raise_after is not None and len(self.calls) > self.fault.raise_after:
            raise FakeDoor._upstream_fault("Elasticsearch query failed (HTTP 503)")
        if self.fault.hits(f"{system}.{verb}"):
            raise FakeDoor._upstream_fault(f"{system}.{verb} is unavailable")
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
    from defender.scripts.adapters.confinement import ConfinementFault, ViewNameError
    from defender.scripts.adapters.faults import AdapterFault
    out: list[type[BaseException]] = [
        SystemExit, EstateError, LedgerError, BranchError, ConfinementFault, ViewNameError,
        AdapterFault, ValueError,
    ]
    for dotted, name in (("learning.branch.staging", "StagingRefused"),
                         ("runtime.branch._family", "FamilyError"),
                         ("learning.branch.review", "ReviewError")):
        out.append(sym(dotted, name))
    return tuple(out)


__all__ = [
    "ALERTS_PATTERN", "AS_OF", "BRANCH_MESSAGE_ID", "CLEAN", "CONFIGURED", "DEFENDER",
    "EPISODE_ID", "EPISODE_TOKEN", "EPISODES_BASE_ENV", "EVENTS_PATTERN",
    "GIT_STATUS_FAILED", "GIT_UNAVAILABLE", "GOLDEN_INVESTIGATION", "RUNS_BASE_ENV",
    "SOURCE_RUN_ID", "WORLDS",
    "DoorCall", "FakeAdapters", "FakeAgent", "FakeDoor", "FakeSpawn", "FakeTransport",
    "UNTRUSTED_FRAME", "assert_wrapped_untrusted", "outside_untrusted_frames", "untrusted_frames",
    "Fault", "base_capture", "captured_row",
    "archived_world", "base_world", "capture_call", "configured_layout",
    "corpus_document",
    "elastic_overlay", "episode", "family_doc", "provenance_record",
    "lesson_row", "mod", "overlay", "refusals", "replace", "review_doc", "runs_base",
    "sibling_run_dir",
    "staged_rows", "sym", "world_doc", "world_token", "write_family",
]
