"""Shared machinery for #947's questioner-authored-triplet spec — NO test scripts.

This is the spec suite for the design in `.spec-flow/design-doc.md`: an operator names
(source run, N); a deny-all QUESTIONER role authors a triplet of worlds into
`episodes/<id>/family.yaml`; each world then runs as its own `run.py --resume` PROCESS; the
launcher verifies every scrub and stamp, archives each world under `worlds/<X>/`, and two
derived readers compute from the episode dir. (#1224 replaced #947's cluster staging, its write
door and the replay review with each world's live oracle: a world is now the natural-language
`facts` it asserts, and the family records its `served_systems`. The builders below write that
v2 manifest; the write-door fake and the staging/review readers went with the design.)

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
   * `malformed="no-status-line"` — PO-C3: `split_status` over stdout with no parseable
     trailing status line yields `("", <whole body>)`.
   * `raise_after=n` with `TransportFault` — the real class at `scripts/adapters/faults.py`,
     exit_code 2, which `docker_exec_curl` raises when the docker exec itself fails (X9).
   * `fail_on=(<name>,)` — a per-name refusal from the far side.
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
import os
import re
import threading
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from defender import _yaml

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
#: The source run's id, CASE-FOLDED (#1105 PR 2): the launcher and the sibling open the source
#: by id through the tenant's repository, and `RunId.parse` refuses a spelling that is not
#: case-stable (a minted run id is folded). The derived episode id is unchanged
#: (`episode_id_for` folds either way).
SOURCE_RUN_ID = "20260728t161845z-fresh-case"
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
#: The systems a v2 manifest records as served (`served_systems`).
SERVED_SYSTEMS = ("elastic", "identity")


def mod(dotted: str):
    """Import `defender.<dotted>` at CALL time, never at collection time."""
    return importlib.import_module(f"defender.{dotted}")


def sym(dotted: str, name: str):
    """One attribute off a lazily-imported module — `AttributeError` is a real red."""
    return getattr(mod(dotted), name)


def no_preflight(_model: str | None = None, *, branching: bool = False) -> int:
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


def _transport_fault(detail: str) -> Exception:
    """The real `TransportFault` — what the transport raises when the docker exec itself fails."""
    return sym("scripts.adapters.faults", "TransportFault")(detail)


def _upstream_fault(detail: str) -> Exception:
    """The real `UpstreamFault` — what an adapter raises when the far side refuses."""
    return sym("scripts.adapters.faults", "UpstreamFault")(detail)


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


def world_doc(world_id: str, *, role: str = "B", story: str = "a story",
              axis: str | None = "an axis", disposition_declared: str = "malicious",
              label_basis: str = "policy-rule", facts: list[dict] | None = None) -> dict:
    """One v2 world. `facts=None` gives one default fact; pass `[]` for the control world."""
    return {
        "world_id": world_id, "role": role, "story": story, "axis": axis,
        "disposition_declared": disposition_declared, "label_basis": label_basis,
        "facts": [fact()] if facts is None else facts,
    }


def base_world() -> dict:
    """World A: the control — explicit `facts: []`, `axis: null`, role A."""
    return world_doc("a", role="A", axis=None, facts=[])


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
            world_doc("c", facts=[fact("f2")]),
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


def episode(tmp_path: Path, *, doc: dict | None = None,
            episode_id: str = EPISODE_ID, root: Path | None = None) -> Path:
    """An episode dir with its manifest and an empty `served/` — the shape `Step.QUESTIONER`
    leaves.

    HAND-BUILT, and deliberately so: this is the episode's CONTENTS for the scenarios that are
    not about where an episode lives. Where it lives is a demand of its own — the episodes root
    is a CONFIGURED location outside both the runs base and the checkout (§7 round 2), pinned by
    `test_947_the_episodes_root_is_read_from_configuration_not_the_runs_base` and its neighbours
    in `test_947_triplet_archive.py`, every one of which resolves the path through the episode
    owner's `_episode_handle.episode_dir` rather than composing one here.

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


def branchable_investigation() -> str:
    """A one-fence investigation document a branch may actually be TAKEN from.

    `branch.validate` refuses a branch point with nothing OPEN in its frontier — no slot and no
    contract is no question for a pair of worlds to divide, which is "branched too late" — and
    the launcher asks that rule before it pays the questioner. The earlier fixture document was
    a single `?h1` row, whose frontier is empty in all three cells: every launcher scenario was
    therefore running against a source no production launcher would accept, and the whole suite
    was green only while the check was missing from the launch path.

    THE GOLDEN'S FIRST FENCE, rather than a hand-written open row, because "what makes a
    frontier open" is `skills/invlang/frontier`'s answer and not this file's — a fixture that
    spelled its own open slot would be a second opinion about the document format, and it would
    go stale silently the day that vocabulary moves. Measured: block 1 of the golden holds 2
    open slots and 7 held facts.

    ONE fence, because the seeded session lands one `append_block` and `fence_count_at` scores
    the branch point at 1. A document with more would make the branch point's fence index run
    short of the total — legal, but it would mean the questioner is shown a prefix while
    `validate` judges the same prefix, and a fixture whose two halves agree is the one that
    makes a launcher test about the launcher.
    """
    from defender.skills.invlang.parser import scan_fences

    bodies = scan_fences(GOLDEN_INVESTIGATION.read_text(encoding="utf-8")).bodies
    assert bodies, f"{GOLDEN_INVESTIGATION} carries no invlang fence — the fixture moved"
    return f"# investigation\n\n```invlang\n{bodies[0]}\n```\n"


#: The tenant the fixture's SOURCE run was stamped with (#1077 stamps every run's tenant; #1106
#: M2 seeds each sibling's runs base from it). Set up from the committed fixture under the test's
#: data root (#1120 H2), so a launch that accepts it finds a complete tenant.
SOURCE_TENANT = "playground"


def current_tenant() -> Any:
    """#1078: the ONE tenant O10 permits in this test's `DEFENDER_DATA_ROOT` (whichever
    `runs_base()`, `d9_tenant` or the like already set up there), as an accepted `Tenant`
    (#1120 D1) — for callers (`episode_dir`, `prepare_episode`, the runs repository) that need
    the tenant rather than its runs base alone. Set up from the committed fixture when the root has none yet."""
    from defender.tests._data_root_1078 import set_up_tenant

    root = Path(os.environ["DEFENDER_DATA_ROOT"])
    existing = sorted(p.name for p in root.iterdir()
                      if (p / "tenant.json").is_file()) if root.is_dir() else []
    return set_up_tenant(root, existing[0] if existing else SOURCE_TENANT)


def runs_base(tmp_path: Path, *, source_run_id: str = SOURCE_RUN_ID,
              tenant_id: str | None = None) -> tuple[Path, Path]:
    """A runs base holding ONE ordinary finished run. Returns (base, source_run_dir).

    #1078: `base` is a real tenant's runs base (`<data root>/<tenant>/runs`) — the data root
    the autouse `data_root` fixture already pointed this test's `DEFENDER_DATA_ROOT` at, with a
    tenant created (and its runs-base record minted) on first use, so the tenant's runs
    repository (which the launcher opens its source through) sees an ordinary, well-formed
    tenant location.

    O10 permits only ONE tenant per data root, so when `tenant_id` is not given this reuses
    whichever tenant already exists there (e.g. one a `d9_tenant` fixture already created)
    rather than colliding with it, and falls back to `SOURCE_TENANT` for a still-empty root.

    The source carries the two artifacts a sibling seeds from — `alert.json` and
    `investigation.md` — because both are model-writable (the run dir is a prior box's rw bind)
    and the containment demands drive exactly those reads.
    """
    from defender import _tenant
    from defender.tests._data_root_1078 import set_up_tenant

    root = Path(os.environ["DEFENDER_DATA_ROOT"])
    if tenant_id is None:
        existing = sorted(p.name for p in root.iterdir()
                          if (p / "tenant.json").is_file()) if root.is_dir() else []
        tenant_id = existing[0] if existing else SOURCE_TENANT
    base = _tenant.runs_base_for(set_up_tenant(root, tenant_id))
    base.mkdir(parents=True, exist_ok=True)
    if not (base / "_tenant.json").is_file():
        _tenant.ensure_runs_base_record(base, tenant_id)
    src = base / source_run_id
    (src / "gather_raw").mkdir(parents=True, exist_ok=True)
    (src / "alert.json").write_text(json.dumps({"rule": {"id": "v2-cross-tier-ssh-pivot"}}),
                                    encoding="utf-8")
    (src / "investigation.md").write_text(branchable_investigation(), encoding="utf-8")
    (src / "report.md").write_text("disposition: malicious\n", encoding="utf-8")
    (src / "executed_queries.jsonl").write_text("", encoding="utf-8")
    # ONE CAPTURED CALL, because a source that captured nothing is not branchable: every
    # proposed world agrees with an empty prefix by construction, which is the generated-world
    # design the redesign rejected, and `branch.validate` refuses it at the launch. A scenario
    # that wants more lands its own rows on top; one that lands this same call again writes a
    # duplicate the primer skips, so the primed key set is unchanged for it.
    capture_call(src)
    # THE STAMP EVERY ORDINARY RUN DIR CARRIES. `materialize_run` writes one at the single
    # place a run the box will execute is ever created, so a source run without one is not a run
    # any production path could have produced — and the containment walks read exactly this file
    # to tell an ordinary run from an episode's contents.
    (src / "provenance.json").write_text(
        json.dumps(provenance_record(tenant_id=tenant_id)), encoding="utf-8")
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

    from defender.run_repository import SessionPaths

    # #1105 fork S(b): the store takes the layout owner's hand-out for the runs base.
    store = ss.open_store(case_id=SOURCE_CASE_ID, sessions=SessionPaths(base))
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
    """One `provenance.json` document, in a shape `capture_tree` can produce.

    Four shapes and no others: the clean tree, the dirty tree, the git-status failure (a sha in
    hand and no answer about the tree, with the reason beside it) and the git-unavailable case
    (no sha at all). `scope` is carried because the record does; `scope=None` is the shape a
    stamp written before the field existed reads back as (#976: compared on commit alone), and
    `model=None` is what `capture_tree` itself produces — the model is the sibling's own
    per-process fact, never the live tree's.

    `knowledge` (#1204) is the tenant knowledge revision's WIRE value, written verbatim: by
    default `{"commit": KNOWLEDGE_SHA}` (what every post-#1204 run from one tenant clone
    carries); `"unversioned"` or `{"unavailable": "<reason>"}` for the other two shapes
    `capture_knowledge` answers with; `None` for an explicit JSON `null`; `NO_KNOWLEDGE_KEY` to
    omit the key (a pre-#1204 stamp). Anything else is written as given, for forgery scenarios.
    """
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
        from defender._provenance import RunProvenance

        self.calls += 1
        built = RunProvenance.from_obj(self.record)
        if built is None:
            raise AssertionError(f"FakeCapture was scripted with a record no capture produces: "
                                 f"{self.record}")
        return built


#: The learning state root's override (`learning/core/config.py::loop_paths`, read at call time).
LEARNING_STATE_ENV = "DEFENDER_LEARNING_STATE_DIR"


def isolate_learning_state(tmp_path: Path, monkeypatch: Any) -> Path:
    """Point the learning state root inside `tmp_path`. An ACCEPTED launch ends in the family
    judge, which appends its findings (e.g. the mechanical `unreachable-difference` one) to the
    questioner queue under `loop_paths().state_root` — by default `defender/learning/` in the
    checkout itself, where a later test asserting nothing was written outside a run's records
    finds it. The root must exist: nothing creates it."""
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
    """`report.md` AS THE CLOSE GATE WRITES IT — YAML frontmatter, not a bare line.

    `close_tool._render_report` is the only writer of this file in production and it emits a
    `---` block carrying `disposition`/`outcome`/`cause`. A fixture writing a bare
    `disposition: x` line produces a shape no production path makes, and a reader built against
    it — `_report.read_report`, which every other consumer of a report in this repo goes
    through — answers `None` for it. Every fixture report in this suite therefore renders here,
    so a reader tested against them is tested against the shape it will actually meet.

    `extra` adds further frontmatter lines (already newline-terminated); `body` is the prose
    under the fence.
    """
    return (
        "---\n"
        f"disposition: {disposition}\n"
        "outcome: stands\n"
        "cause: the disposition was recorded without a challenge review\n"
        f"{extra}"
        "---\n"
        f"{body or 'Disposition recorded by the close gate. outcome=stands.'}\n"
    )


def archived_world(episode_dir: Path, world_id: str, *, disposition: str = "malicious",
                   scrub_ran: bool = True, commit: str | None = "deadbee",
                   dirty: bool | None = False, unavailable: str | None = None) -> Path:
    """One `worlds/<X>/` directory carrying every artifact M8's row declares."""
    w = episode_dir / "worlds" / world_id
    (w / "gather_raw").mkdir(parents=True, exist_ok=True)
    (w / "report.md").write_text(report_text(disposition), encoding="utf-8")
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
                    model: str = "m-1", stamp: bool = True, **record: Any) -> Path:
    """A finished sibling run dir plus its scrub-verdict SIDECAR, under `base`.

    `base` is the runs base the sibling's own PROCESS was handed — after §7 FORK-13 that is
    `<episode_dir>/runs`, never the operator's runs base, so a scenario about containment passes
    the relocated root here rather than hand-placing a directory the production path never makes.

    The verdict is written at `scrub.verdict_path(run_dir)` — `tree.parent /
    f"{tree.name}.scrub-verdict.json"` — because G17 REFUTED the design's "inside the run dir"
    reading; a fixture that put it in the tree would make the archive test green on a path the
    production writer never uses.

    Any further keyword (`scope=`, `knowledge=`) passes through to `provenance_record` (#1204:
    one sibling differing on an anchored field is the fork check's behavioural arm); left out,
    each takes the record's own default.
    """
    run_dir = base / f"{EPISODE_ID}-{world_id}"
    (run_dir / "gather_raw").mkdir(parents=True, exist_ok=True)
    (run_dir / "report.md").write_text(report_text("malicious"), encoding="utf-8")
    (run_dir / "investigation.md").write_text(f"# world {world_id}\n", encoding="utf-8")
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


def arm_run_dir(episode_dir: Path, world_id: str, **kw: Any) -> Path:
    """A finished arm in the episode's own container, `<episode_dir>/runs/<episode id>-<world>`
    (#1105 PR 2: an arm is opened by id through the episode's view — `family_arms` — so it lives
    in that episode's container under that episode's id): `sibling_run_dir`'s run dir and
    scrub-verdict sidecar, every keyword passed through, renamed to the episode's own arm id
    when the episode is not `EPISODE_ID`."""
    episode_dir = Path(episode_dir)
    runs = episode_dir / "runs"
    run_dir = sibling_run_dir(runs, world_id, **kw)
    arm = runs / f"{episode_dir.name}-{world_id}"
    if arm != run_dir:
        run_dir.rename(arm)
        verdict = runs / f"{run_dir.name}.scrub-verdict.json"
        if verdict.exists():
            verdict.rename(runs / f"{arm.name}.scrub-verdict.json")
    return arm


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


def open_source(src: Path) -> Any:
    """The source `Run` the launcher opens (#1105 PR 2): the run at `src` —
    `<data root>/<T>/runs/<run id>` — by its id, through tenant T's runs repository, T accepted
    under that data root. What `preflight_episode(source=)` / `preflight_replay(source=)` take
    where a test once handed the folder."""
    from defender import _tenant
    from defender.run_repository import RunId

    src = Path(src)
    tenant = _tenant.accept_tenant(src.parent.parent.parent, src.parent.parent.name,
                                   defender_dir=DEFENDER)
    return tenant.runs_repository().open(RunId.parse(src.name))


def episode_view(episode: Any, *, tenant: Any = None) -> Any:
    """The episode's view (`EpisodeRuns`) in `tenant`'s runs repository (default: this data
    root's one tenant, `current_tenant()`), adopting the held `episode` (#1105 PR 2). Its
    container is made with the tenant's record when absent — what the launcher does at RUNS
    before the first sibling (`EpisodeRuns.create_container`) — and a container a fixture
    planted as a plain folder without a record is given the tenant's, so a scene's hand-planted
    arms are reachable through the view. `start_family` callers make the container this way;
    `verify_family` callers open their arms through it (`family_arms`)."""
    from defender import _tenant

    owner = current_tenant() if tenant is None else tenant
    runs = Path(episode.dir) / "runs"
    if runs.is_dir() and not runs.is_symlink() and not os.path.lexists(runs / "_tenant.json"):
        _tenant.ensure_runs_base_record(runs, owner.id)
    view = owner.runs_repository().episode(episode.dir.name, held=episode)
    if view.state == "absent":
        view.create_container()
    return view


def family_arms(episode: Any, labels: Any, *, tenant: Any = None) -> dict[str, Any]:
    """`verify_family`'s `arms` (#1105 PR 2): each label's arm `<episode>/runs/<ep>-<label>`
    opened by id through the episode's view (`episode_view`), as the launcher's
    `_finished_arms` does — the `RunRefused` an open raises (`RunAbsent` for a missing arm
    folder) kept as that label's value."""
    from defender.run_repository import RunRefused

    view = episode_view(episode, tenant=tenant)
    arms: dict[str, Any] = {}
    for label in labels:
        try:
            arms[label] = view.open(view.arm_id(label))
        except RunRefused as refused:
            arms[label] = refused
    return arms


def configured_layout(tmp_path: Path, monkeypatch) -> tuple[Path, Path, Path]:
    """The two CONFIGURED roots, both under `tmp_path`, and the source run — the relocated layout.

    Returns `(runs_base, source_run_dir, episodes_root)`. The episodes root is a sibling of the
    runs base here only because `tmp_path` is where a test may write; what the demands assert is
    that it is READ FROM CONFIGURATION and is neither inside the runs base nor inside the
    checkout.

    #1078: `runs_base()`'s base IS the source's real tenant runs base now (the launcher's own
    derivation needs it to be). Pointed at its OWN fresh data root under `tmp_path` — isolated
    from whatever tenant an ambient fixture (`d9_tenant`) may already have created — so O10's
    one-tenant-per-root rule never collides with it, and this base is trivially distinct from
    `runs_base_for` of any other tenant. The retired `DEFENDER_RUNS_BASE` knob is still set
    here, to `base` itself — today's "stale configured value" a child inherits unchanged
    (J46) — never one the launcher composes.
    """
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(tmp_path / "configured-data-root"))
    base, src = runs_base(tmp_path)
    root = tmp_path / "episodes-root"
    monkeypatch.setenv(RUNS_BASE_ENV, str(base))
    monkeypatch.setenv(EPISODES_BASE_ENV, str(root))
    return base, src, root


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
    from defender.scripts.adapters.confinement import ConfinementFault
    from defender.scripts.adapters.faults import AdapterFault
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
    "EPISODE_ID", "EPISODE_TOKEN", "EPISODES_BASE_ENV", "EVENTS_PATTERN",
    "GIT_STATUS_FAILED", "GIT_UNAVAILABLE", "GOLDEN_INVESTIGATION", "RUNS_BASE_ENV",
    "KNOWLEDGE_SHA", "NO_KNOWLEDGE_KEY", "OTHER_KNOWLEDGE_SHA",
    "branchable_investigation",
    "SOURCE_RUN_ID", "WORLDS",
    "FakeAdapters", "FakeAgent", "FakeSpawn", "FakeTransport", "SERVED_SYSTEMS",
    "UNTRUSTED_FRAME", "assert_wrapped_untrusted", "outside_untrusted_frames", "untrusted_frames",
    "Fault", "base_capture", "captured_row",
    "archived_world", "base_world", "capture_call", "configured_layout",
    "report_text",
    "corpus_document",
    "episode", "episode_view", "fact", "family_arms", "family_doc", "open_source",
    "provenance_record",
    "FakeCapture", "source_capture", "source_stamp", "isolate_learning_state", "LEARNING_STATE_ENV",
    "lesson_row", "mod", "refusals", "replace", "runs_base",
    "arm_run_dir", "sibling_run_dir",
    "sym", "world_doc", "world_token", "write_family",
]
