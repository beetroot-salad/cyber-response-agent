"""Shared machinery for #996's clerk spec — NO test scripts.

This is the executable form of `.spec-flow/design-996-v2.md`, its dispositions
(`45-dispositions.md`) and the human's §7 resolutions (`70-resolutions.md`). MAIN loses the
invlang grammar and both document verbs and gains ONE verb, `record`, that takes prose; a
zero-grant CLERK role compiles that prose into invlang rows and lands them through the
existing `_tool_append_block` writer with MAIN's own deps; `StoreHandle.append` stamps a
`document_state` row per MAIN request row; the close gains a conclude gate; a
`clerk_trace.jsonl` lands under `wire_logs/`.

**None of that exists at `7fa49f04`.** `AgentRole.CLERK`, `defender/runtime/clerk.py`,
`defender/runtime/tools/_clerk.py`, `session_store.document_state_at`,
`validate.structural_diagnostics` / `judgment_diagnostics` and
`defender/skills/clerk/SKILL.md` are all absent, and `run_investigation` does not accept
`clerk=`. RED against HEAD is the expected state of a spec. Every import of a
not-yet-written symbol goes through `mod()` / `sym()` PER TEST (the `_triplet_947` /
`_session_store_705` idiom) so a missing target is one failure per test rather than one
collection error that hides the rest of the suite.

Five things live here and nothing else.

1. **`mod()` / `sym()`** — the per-test import.

2. **The declarative fault-injection fake, `ScriptedClerk`.** One fake for the one
   dependency this design adds — the clerk LLM seam — driven by a data `Fault(...)` spec
   (`raise_after`, `raise_with`, `hang_after`). It INJECTS ONLY: it never classifies a fault,
   never decides policy and never answers a question the production code owes. It RECORDS
   every prompt it was handed, because a fake that only returns answers leaves the whole
   outbound channel unpinned — a `kind: shape` demand asserts against `clerk.prompts`, never
   against the canned reply.

   Every fault SHAPE cites the ledger claim or resolution that observed it. No fault here is
   imagined:
   * `raise_with=ConnectionError` / `raise_after=n` — cluster K's "anything that is not a
     parsed response and not a `ModelRetry`" (AR-4); the transport class the OpenAI-compatible
     provider raises through `httpx` on a dropped connection.
   * `hang_after=n` — cluster K's premise [5], the call that never returns. Its DEADLINE VALUE
     is the one open parameter `70-resolutions.md` leaves unfixed (AR-4's red flag), so this
     suite pins the observable (the call is bounded and pends like any other fault) and reads
     the deadline off the seam rather than restating a number.
   * `malformed=` — a reply the round loop cannot split into fences, which is what a model
     that answers in prose produces. Cluster K's "not a parsed response" arm.
   Anything else a scenario wants induced is a PROBE REQUEST, not a fake — see
   `80-author-digest.md`.

3. **The wire between `ClerkCaller` and the clerk, spelled once.** `clerk_reply()` and
   `repair_reply()` build what a clerk model answers with (flow 3: "call clerk → split fences
   / GAPS"; flow 0: "the clerk answers `fix_row(old, new)` pairs"), and `PENDING_LABEL` is the
   one slot label the turn's grammar is pinned on. These are the CONTRACT, not conveniences: a
   fake that spoke a private dialect would leave the real parse untested.

4. **The documents.** Reused from `_invlang_warn_836` wherever that suite already executed
   one against the real validator, so a fixture cannot quietly carry a second fault.

5. **The drivers.** `record_run()` is one `drive(...)` with an injected clerk and MAIN turns
   that call `record`; `MainWithReceipts` is the observation channel for what MAIN was handed
   back. A new scenario is a few lines of data against these, not fresh plumbing.

Fakes enter through the entry point's INJECTION SEAMS (`run_investigation(clerk=…)`, the
harness's `drive(clerk=…)`) and never by `monkeypatch.setattr` — the project profile's
`tests.idioms`, ratcheted in CI by `scripts/lint/lint_monkeypatch.py`. The clerk seam is
itself part of the contract (`replay_seam_accepts_a_clerk`, `kind: seam`) rather than
something reached around.

Underscore-prefixed so pytest does not collect it; it defines no tests.
"""
from __future__ import annotations

import importlib

import re
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.messages import (  # noqa: E402
    ModelResponse,
    RetryPromptPart,
    ToolReturnPart,
)

from defender._io import read_jsonl_rows  # noqa: E402
from defender._run_paths import RunPaths  # noqa: E402
from defender.tests._invlang_warn_836 import (  # noqa: E402
    CONCLUDE_BENIGN,
    PROLOGUE,
    REPAIRED_ROW_ATTRS,
    SECOND_WARN_ROW,
    WARN_ROW,
    attr_block,
)
from defender.tests.e2e._replay_harness import (  # noqa: E402
    GOLDEN,
    ReplayFn,
    Turn,
    drive,
    materialize,
)

DEFENDER = Path(__file__).resolve().parents[1]

RUN_ID = "clerk-996"

#: The clerk's own two knobs (design v2:78). Environment steering, not `monkeypatch.setattr`:
#: both are read off the environment by the shipped resolver, so this is the seam the
#: production code already has.
MODEL_ENV = "DEFENDER_CLERK_MODEL"
EFFORT_ENV = "DEFENDER_CLERK_EFFORT"

#: The clerk call's own deadline knob. THE DESIGN GIVES THE DEADLINE NO SEAM AT ALL, so the
#: seam is part of the contract (write-tests' rule for a dependency the design left unreachable)
#: and it is spelled as the sibling the run already has —
#: `DEFENDER_REVIEW_STAGE_TIMEOUT_SECONDS` on `challenge_gate.stage_timeout()`. Its DEFAULT
#: VALUE is the one open parameter `70-resolutions.md` leaves unfixed and is deliberately NOT
#: pinned here: the resolution's own guidance is to derive it from a constant the run already
#: has, and choosing a number in a test file would be taking that seam decision silently.
TIMEOUT_ENV = "DEFENDER_CLERK_TIMEOUT_SECONDS"

#: The shipped defaults the design fixes (v2:78) — the Fireworks GLM 5.3 Flash alias and a
#: reasoning-effort literal on the definition.
DEFAULT_CLERK_MODEL = "glm-5p3-flash"
DEFAULT_CLERK_EFFORT = "low"
CLERK_PRICE_KEY = "glm-5.3-flash"
CLERK_PROVIDER_MODEL = "accounts/fireworks/models/glm-5p3-flash"

#: `wire_logs/clerk_trace.jsonl` — the location D4/S4 relocate the throwaway's run-root file
#: to, and the location that earns it the existing `names_wire_log_dir` component deny.
CLERK_TRACE_NAME = "clerk_trace.jsonl"

#: The row's own fields, verbatim from the design (v2:76). A `kind: shape` demand asserts the
#: whole key set, not a sample: the trace is the ONLY provenance binding a landed row to the
#: clerk that compiled it, and a field nobody pinned is a field that can be dropped silently.
TRACE_FIELDS = (
    "n", "phase_header", "repair_rounds", "rounds", "refusals", "stopped_on_judgment",
    "held", "gaps", "prose_chars", "rows_chars", "committed", "pending", "ids",
)

#: The clerk `agent_id` namespace in the run's ONE wire log, beside `gather:` and `review:`
#: (O5). Published on `agent_role` like its two siblings, and read here through `sym()` in the
#: tests that assert on it; spelled here for the scenarios that only need to bucket rows.
CLERK_PREFIX = "clerk:"

#: THE ONE SLOT LABEL THE TURN'S GRAMMAR IS PINNED ON. `pending` is the only slot whose EMPTY
#: rendering is itself a demand (`d_pending_empty_state_is_inert`, the gate's R4 obligation):
#: a falsy default read through an `x or DEFAULT`-shaped expression renders a placeholder, and
#: nothing but the label lets a test see the difference between "empty" and "coerced". Every
#: other slot is asserted by its VALUE — the grammar text, the document bytes, MAIN's prose —
#: so the turn's layout stays the implementer's.
PENDING_LABEL = re.compile(r"(?mi)^[ \t]*pending[ \t]*:[ \t]*$")

#: Tokens an `x or DEFAULT` read leaves behind where an empty list should have rendered
#: nothing. Not exhaustive and not meant to be: the assertion is that the section is BLANK.
PLACEHOLDERS = ("none", "(none)", "empty", "(empty)", "n/a", "null", "[]", "-")


def mod(dotted: str):
    """Import `defender.<dotted>` at CALL time, never at collection time."""
    return importlib.import_module(f"defender.{dotted}")


def sym(dotted: str, name: str):
    """One attribute off a lazily-imported module — `AttributeError` is a real red."""
    return getattr(mod(dotted), name)


# ---------------------------------------------------------------------------------------
# the documents
# ---------------------------------------------------------------------------------------

#: A clean `:R attr_updates` block over `PROLOGUE`'s declared vertex. `attr_block
#: (REPAIRED_ROW_ATTRS)`, NOT `_invlang_warn_836.CLEAN_BLOCK` (which is `attr_block
#: (REPAIRED_ROW)`, a `key=class` row) — this module's own positive-control assertions check
#: for the substring `"attrs.owner"`, which `REPAIRED_ROW_ATTRS` ("l-001|v-001|attrs.owner|
#: svc.config-mgmt") carries and `REPAIRED_ROW` does not. A #996-local constant rather than
#: repointing `CLEAN_BLOCK` itself, so `test_invlang_warn_window_836.py`'s 13 sites (which DO
#: mean the `key=class` row) are untouched. EXECUTED against the real `diagnose`: zero
#: diagnostics, same as `CLEAN_BLOCK` — `REPAIRED_ROW_ATTRS` is `WARN_ROW`'s own legal repair,
#: not a different document shape.
CLEAN_ROWS = attr_block(REPAIRED_ROW_ATTRS)

#: The warn-family block: a refinement key outside `class` / `attrs.*` / `ident`. EXECUTED by
#: the #836 suite as exactly one warn diagnostic, which is what opens the repair window.
WARN_ROWS = attr_block(WARN_ROW)
SECOND_WARN_ROWS = attr_block(SECOND_WARN_ROW)
#: The legal `attrs.<name>` repair of `WARN_ROW`, keeping the author's value cell verbatim.
REPAIR_PAIR = (WARN_ROW, REPAIRED_ROW_ATTRS)

#: A STRUCTURAL refusal: a refinement whose target vertex no `:V` block declares. Clearable
#: from the grammar and the document alone — the clerk can re-emit it against a declared
#: vertex with no fact from MAIN, which is D7's own test for the structural partition.
UNDECLARED_TARGET_ROWS = attr_block("l-001|v-404|attrs.owner|svc.config-mgmt")

#: The clearest #986-era structural refusal, and the one premise [27] promoted: a `class`-tuple
#: cell holding a value from the sibling enum (`container` is a `compute.kind` value, not a
#: `compute.role` one). EXECUTED at THIS BASE by `test_class_vocab_986` — it is `7fa49f04`'s
#: own gate.
VOCAB_CLASS_CELL_DOC = (
    "```invlang\n"
    ":V prologue.vertices [id|type|class|ident|attrs?]\n"
    "v-001|compute|container/internal/novel|db-1|\n"
    "```\n"
)

#: A JUDGMENT-only refusal: a `benign` conclude landed onto a record that leaves a slot open,
#: which `_check_disposition_gating` prices. No fact in the grammar or the document settles
#: it — only MAIN's prose can — so D7 stops the loop here.
OPEN_SLOT_PROLOGUE = """```invlang
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|bastion/internal/??|bastion-01.corp|kind=physical
v-002|identity|user/??|jsmith|

:L findings [id|loop|name|target|tests|system|window]
l-001|1|cmdb-lookup|v-001||cmdb|n/a
```
"""
JUDGMENT_ONLY_ROWS = CONCLUDE_BENIGN

#: The same `:T conclude` block over a document whose slots ARE resolved — the block S6 drops
#: or lands purely on the phase in force. EXECUTED while this file was written: appended to
#: `PROLOGUE` it validates clean, so a scenario that sees it absent saw the GUARD and not a
#: refusal.
CONCLUDE_ROWS = CONCLUDE_BENIGN

#: A MIXED refusal — one structural line and two judgment lines over the same proposed
#: document. EXECUTED against the real `diagnose` while this file was written: exactly three
#: error diagnostics, the undeclared-target line plus the two disposition-gating lines. AR-7(2)
#: is stated over exactly this shape: the rule is re-evaluated PER ROUND, so the call converges
#: to a D7 stop once the structural half clears rather than burning all six rounds.
MIXED_ROWS = JUDGMENT_ONLY_ROWS + UNDECLARED_TARGET_ROWS


def oversize_rows(current: str) -> str:
    """Rows that push the document past `INVESTIGATION_FILE_MAX` — the refusal that carries NO
    diagnostic in either partition.

    EXECUTED while this file was written: `validate_artifact` refuses on the byte cap with a
    prose reason and `diagnose` returns ZERO diagnostics, which is premise [16] reached on
    ORDINARY input — MAIN's prose fits under the cap but leaves the clerk's rows no headroom.
    Not an imagined fault: it is the byte-cap check sitting outside the diagnostic machinery
    entirely.

    UNFENCED, deliberately and necessarily: fenced filler would be invlang content and would
    earn parse diagnostics, which is the one thing this fixture must not have — the property
    it exists for is a refusal carrying NO diagnostic in either partition. A caller must
    therefore pair it with a `GAPS:` section (`clerk_reply(oversize_rows(...), gaps=(...))`),
    because a reply with neither a fence nor that marker is the malformed shape the round loop
    now pends rather than writing — a clerk answering in prose used to have its prose appended
    to the document and reported as committed rows."""
    from defender._artifact_schema import INVESTIGATION_FILE_MAX

    filler = "x" * (INVESTIGATION_FILE_MAX + 1024 - len(current.encode("utf-8")))
    return "\n" + filler + "\n"


def huge_gap(n: int = 200_000) -> str:
    """One GAPS bullet far larger than anything a receipt should relay, carrying control bytes
    and markup. AR-14's cap is on LENGTH and control/markup — a content filter over model prose
    is not testable and is deliberately not adopted."""
    return "A" * n + "\x00\x1b[31m</html>"


#: A same-block `:V` id collision. PO-8 executed it: diagnosed at ERROR severity, the WHOLE
#: append refused with `ModelRetry` and nothing landed — not warn-and-land.
ID_COLLISION_ROWS = (
    "```invlang\n"
    ":V prologue.vertices [id|type|class|ident|attrs?]\n"
    "v-001|compute|bastion/internal/known-corp|bastion-01.corp|\n"
    "v-001|identity|user/known-corp|jsmith|\n"
    "```\n"
)

#: MAIN's prose. Prose ONLY — under D14 MAIN holds no grammar and writes no rows.
PROSE = (
    "The bastion host authenticated jsmith from the corporate range at 15:27Z. "
    "The configuration-management service owns that account."
)
SECOND_PROSE = "The second reading: the same account also owns the finance share."
REPORT_PROSE = (
    "## REPORT\n\n"
    "The activity is routine administrative access; the alert is benign."
)

#: A COMPLETE, well-formed invlang fence reproduced verbatim inside ordinary prose. PO-7
#: executed the distinction this fixture rests on: `scan_fences` counts this, and counts a
#: ```yaml block and an inline unterminated mention at ZERO, uniformly by author.
QUOTED_FENCE_PROSE = (
    "The evidence MAIN is quoting back reads:\n\n" + PROLOGUE + "\nand that is what I read."
)
YAML_FENCE_PROSE = (
    "The evidence MAIN is quoting back reads:\n\n"
    "```yaml\nvertices:\n  - id: v-001\n```\n\nand that is what I read."
)


def phase_document(header: str, body: str = "") -> str:
    """A document whose CURRENT phase is `header` — the positional input HD-3 fixes S6's guard
    on ("the phase in force at the point the block would land"), never the calling prose's own
    header and never the author's identity."""
    return f"{header}\n\n{body}"


# ---------------------------------------------------------------------------------------
# the wire between `ClerkCaller` and the clerk
# ---------------------------------------------------------------------------------------

def clerk_reply(rows: str = "", *, gaps: tuple[str, ...] = ()) -> str:
    """What a clerk model answers with: fenced invlang rows, then a `GAPS:` section.

    Flow 3 splits the reply into fences and GAPS, and receipt section (4) renders the GAPS
    bullets VERBATIM (D9), so the bullet text a scenario writes here is the text it asserts on
    in the receipt. A reply with neither is the `record: nothing to commit` case ([25])."""
    parts = [rows] if rows else []
    if gaps:
        parts.append("GAPS:\n" + "\n".join(f"- {g}" for g in gaps))
    return "\n\n".join(parts)


def repair_reply(*pairs: tuple[str, str]) -> str:
    """The repair round's answer: one `fix_row(old, new)` per line (flow 0, D14).

    An EMPTY pair list is the clerk declining to repair — the arm that exhausts the round
    budget with the window still open."""
    return "\n".join(f'fix_row({old!r}, {new!r})' for old, new in pairs)


def gaps_of(reply: str) -> tuple[str, ...]:
    """The GAPS bullets a reply carries, as the receipt must render them."""
    if "GAPS:" not in reply:
        return ()
    tail = reply.split("GAPS:", 1)[1]
    return tuple(line[2:].strip() for line in tail.splitlines() if line.startswith("- "))


def pending_section(turn: str) -> str | None:
    """The rendered `pending:` slot's body, or `None` when the turn carries no such slot.

    The section runs to the next label line or to the end of the turn. Used by exactly one
    demand — `d_pending_empty_state_is_inert` — for the reason `PENDING_LABEL` states."""
    m = PENDING_LABEL.search(turn)
    if m is None:
        return None
    rest = turn[m.end():]
    nxt = re.search(r"(?m)^[ \t]*[A-Za-z_][A-Za-z0-9_ ]*[ \t]*:[ \t]*$", rest)
    return rest[: nxt.start()] if nxt else rest


# ---------------------------------------------------------------------------------------
# the fake
# ---------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Fault:
    """A DATA fault-spec for `ScriptedClerk`. The fake injects; it never classifies.

    `raise_after=n` — answer `n` calls, then raise `raise_with` on every later one.
    `hang_after=n` — answer `n` calls, then block until the caller's own deadline fires.
    `malformed=` — answer with text the round loop cannot split into fences at all.
    """

    raise_after: int | None = None
    raise_with: type[BaseException] = ConnectionError
    hang_after: int | None = None
    malformed: str | None = None


class ScriptedClerk:
    """The injected clerk seam — the drop-in for the live `ClerkCaller`'s model call.

    ONE async callable taking the rendered turn and returning the reply text, mirroring
    `_review_bundle.stage()` exactly, because HD-1 resolved the seam to mirror `review_stages=`
    and not `store_factory=`: the harness DEFAULTS a scripted clerk and only a production
    `run_investigation` with none builds the live one.

    RECORDS EVERY PROMPT. `prompts` is the observation channel every payload demand asserts
    against; the canned replies pin nothing about what was sent.

    Past the script the LAST reply repeats, so a scenario that scripts one answer and drives
    six rounds does not silently fall off the end into a different behaviour.
    """

    def __init__(self, *replies: str, fault: Fault | None = None) -> None:
        self._replies = list(replies) or [clerk_reply(CLEAN_ROWS)]
        self._fault = fault or Fault()
        self.prompts: list[str] = []

    @property
    def calls(self) -> int:
        return len(self.prompts)

    def only(self) -> str:
        assert len(self.prompts) == 1, f"expected exactly 1 clerk call, got {self.calls}"
        return self.prompts[0]

    async def __call__(self, request: Any) -> str:
        text = request if isinstance(request, str) else str(request)
        self.prompts.append(text)
        n = len(self.prompts) - 1
        f = self._fault
        if f.hang_after is not None and n >= f.hang_after:
            import asyncio

            await asyncio.Event().wait()  # never set: the caller's deadline is the only exit
        if f.raise_after is not None and n >= f.raise_after:
            raise f.raise_with("scripted clerk transport fault")
        if f.malformed is not None:
            return f.malformed
        return self._replies[min(n, len(self._replies) - 1)]


# ---------------------------------------------------------------------------------------
# driving a run
# ---------------------------------------------------------------------------------------

class MainWithReceipts(ReplayFn):
    """`ReplayFn` + what `record` handed MAIN back.

    Two channels, because the port has two: an ACCEPT returns the receipt string as a
    `ToolReturnPart`, and a refusal on MAIN's own bytes reaches MAIN as a `ModelRetry`, which
    the framework records as a `RetryPromptPart`. Reading the receipt off the message history
    rather than off a return value is what keeps the observation honest — it is the text the
    MODEL was actually sent."""

    __name__ = "MainWithReceipts"

    def __init__(self, turns: list[Turn], *, verb: str = "record") -> None:
        super().__init__(turns)
        self._verb = verb
        self.returns: dict[str, list[str]] = {}
        self.refusals: dict[str, list[str]] = {}

    def __call__(self, messages, info) -> ModelResponse:
        for msg in messages:
            for part in getattr(msg, "parts", []):
                name = getattr(part, "tool_name", None)
                if not isinstance(name, str):
                    continue
                if isinstance(part, ToolReturnPart):
                    sink = self.returns.setdefault(name, [])
                elif isinstance(part, RetryPromptPart):
                    sink = self.refusals.setdefault(name, [])
                else:
                    continue
                content = getattr(part, "content", "")
                text = content if isinstance(content, str) else str(content)
                if text not in sink:
                    sink.append(text)
        return super().__call__(messages, info)

    @property
    def receipts(self) -> list[str]:
        """What the verb under test handed MAIN back, in order, duplicates collapsed."""
        return self.returns.get(self._verb, [])

    @property
    def retries(self) -> list[str]:
        """What reached MAIN as a refusal for the verb under test."""
        return self.refusals.get(self._verb, [])

    @property
    def receipt(self) -> str:
        assert self.receipts, (
            "MAIN was handed no `record` receipt at all — the verb is not registered, or the "
            "call never returned"
        )
        return self.receipts[-1]


@contextmanager
def bounded(seconds: float, what: str):
    """Fail — never HANG — if the block does not finish inside `seconds`.

    A demand about a call being BOUNDED cannot be discharged by a test that hangs when it is
    not: an unbounded run in CI is a timeout with no failing assertion and no named demand.
    `SIGALRM` rather than a worker thread because the driver's own `asyncio.run` owns the main
    thread and a thread-based guard could not interrupt it."""
    import signal

    def _fire(_sig, _frame):
        raise TimeoutError(what)

    prev = signal.signal(signal.SIGALRM, _fire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, prev)


def new_run_dir(tmp_path: Path, *, name: str = "run") -> Path:
    """A materialized run dir — `gather_raw/`, the copied alert and the provenance stamp, the
    same file set production writes."""
    root = tmp_path / name
    root.mkdir(parents=True, exist_ok=True)
    return materialize(root, GOLDEN)


def seed(run_dir: Path, text: str) -> Path:
    """Put `text` on disk as the run's `investigation.md`, bypassing the write verbs.

    Deliberately not through a verb: several scenarios need a document the write gate would
    refuse today (a warn-only one, a conclude under the wrong phase header) as their STARTING
    state, and staging it through the mechanism under test would make the fixture depend on
    what it exists to exercise. The #836 suite's own `seed_investigation` idiom."""
    p = RunPaths(Path(run_dir)).investigation
    p.write_text(text, encoding="utf-8")
    return p


def record_turn(text: str) -> Turn:
    """One MAIN turn calling `record` with prose. MAIN's ONLY document verb under D14."""
    return Turn(tool_calls=[("record", {"text": text})])


def record_run(  # noqa: PLR0913 — one parameter per seam the scenario varies
    tmp_path: Path, *, prose: list[str] | None = None, clerk: Any = None,
    main: Any = None, run_dir: Path | None = None, run_id: str = RUN_ID,
    limits: dict | None = None, store_factory: Any = None,
    resume: Any = None, extra_turns: list[Turn] | None = None,
):
    """One driven investigation whose MAIN records prose and whose clerk is injected.

    Returns `(run_dir, main, clerk)`. The clerk is threaded through the harness's own seam,
    which threads it to `run_investigation(clerk=…)` — the seam `replay_seam_accepts_a_clerk`
    demands and the one every scenario here drives.

    `clerk=None` means the scenario is about the harness's DEFAULT, not about a scripted
    answer: HD-1 makes that default a scripted clerk of the same shape and at the same layer
    as `review_stages`', so a conforming replay never reaches a live call."""
    target = run_dir if run_dir is not None else materialize(tmp_path, GOLDEN)
    turns: list[Turn] = [record_turn(p) for p in (prose or [PROSE])]
    turns.extend(extra_turns or [])
    turns.append(Turn(text="Holding here."))
    model = main if main is not None else MainWithReceipts(turns)
    seams: dict[str, Any] = {}
    if clerk is not None:
        seams["clerk"] = clerk
    if limits is not None:
        seams["limits"] = limits
    if store_factory is not None:
        seams["store_factory"] = store_factory
    if resume is not None:
        seams["resume"] = resume
    drive(target, run_id=run_id, main=model, **seams)
    return target, model, clerk


# ---------------------------------------------------------------------------------------
# readers — the observation channels
# ---------------------------------------------------------------------------------------

def document(run_dir: Path) -> str:
    p = RunPaths(Path(run_dir)).investigation
    return p.read_text(encoding="utf-8") if p.is_file() else ""


def trace_path(run_dir: Path) -> Path:
    """`<run_dir>/wire_logs/clerk_trace.jsonl` — a SIBLING of the wire log, which is what puts
    it inside the `names_wire_log_dir` deny class rather than at the run root the throwaway
    used (G22/F13)."""
    return RunPaths(Path(run_dir)).wire_log.parent / CLERK_TRACE_NAME


def trace_rows(run_dir: Path) -> list[dict]:
    p = trace_path(run_dir)
    return list(read_jsonl_rows(p)) if p.is_file() else []


def wire_rows(run_dir: Path) -> list[dict]:
    p = RunPaths(Path(run_dir)).wire_log
    return list(read_jsonl_rows(p)) if p.is_file() else []


def clerk_agent_ids(run_dir: Path) -> list[str]:
    """Every `clerk:` agent id the run's ONE wire log carries, in order, duplicates kept —
    the uniqueness demand is asserted over this list, so it must not be a set."""
    return [
        str(r.get("agent_id"))
        for r in wire_rows(run_dir)
        if str(r.get("agent_id", "")).startswith(CLERK_PREFIX)
    ]


def fences(text: str) -> int:
    """The document's invlang fence count through the validator's own scanner — the unit
    `frontier_at` indexes and the unit D6 stamps."""
    from defender.skills.invlang.parser import scan_fences

    return len(scan_fences(text).bodies)


def outcome_lines(receipt: str) -> list[str]:
    """Every `record: …` outcome line the receipt carries. Section (2) is EXACTLY ONE of them
    (v2:73); a receipt carrying two has two outcomes and MAIN cannot tell which happened."""
    return [ln for ln in receipt.splitlines() if ln.startswith("record: ")]


#: The #919 lessons-recall block's own lead line, straight from `lessons_frontier.render` —
#: what `_tool_append_block` appends to its return when the append MOVED the invlang frontier,
#: and therefore what receipt section (1) carries it in.
#:
#: PO-9 executed the asymmetry this pins, three runs: `_document.py`'s fast-path guard returns
#: before frontier derivation runs whenever the appended text lands no backtick fence, so a
#: prose-only append cannot carry a recall — STRUCTURALLY, not merely usually — while MAIN prose
#: smuggling a COMPLETE invlang fence moves the frontier and does carry one. DC-1 makes the
#: absence a design correction an implementer must not "restore", so the receipt is where both
#: halves are pinned rather than left to prose.
LESSONS_RECALL_LEAD = "### Lessons matched against your record"

#: The five outcome lines the design fixes verbatim (v2:73). AR-7 adds a SIXTH for a refusal
#: carrying no diagnostic in either partition; its wording is not fixed anywhere, so the tests
#: that reach it assert "exactly one outcome line, and it is none of these five" plus the
#: content the resolution requires, rather than inventing a string.
OUTCOME_COMMITTED = "record: committed rows for "
OUTCOME_COMMITTED_ANON = "record: committed rows (no id-carrying row)"
OUTCOME_NOTHING = "record: nothing to commit"
OUTCOME_PENDING = "record: rows pending (provider fault:"
OUTCOME_HELD = "record: rows held — the close price is owed:"
OUTCOME_GIVEUP = "record: rows could not be committed after "
FIXED_OUTCOMES = (
    OUTCOME_COMMITTED, OUTCOME_COMMITTED_ANON, OUTCOME_NOTHING,
    OUTCOME_PENDING, OUTCOME_HELD, OUTCOME_GIVEUP,
)
