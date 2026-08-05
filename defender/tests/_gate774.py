"""#774 — shared machinery for the LIVE WRITE-TIME GATE's executable spec. NOT a test module.

Scope: PR 2 only, the live gate (`.spec-flow/input/README-scope.md`). The offline
measurement PR is skipped and will not be built; nothing here speaks to a corpus, a sweep
over finished run dirs, or the curators-unwired interim guarantee.

THE SURFACE THIS SUITE PINS DOES NOT EXIST YET, and every module named below is a surface
the implementation must build. Unlike the #632 spec, the imports of the absent surface are
DEFERRED to call time (`spec_import`) so the suite COLLECTS clean and each test reports as a
FAILURE naming what is missing — a collection error hides the other 60 contracts behind one
traceback. The `TYPE_CHECKING` block below is what keeps the absent modules visible to
`spec-graph calls` / `nullstub`, which identify the target from the suite's own imports.

    defender/runtime/close_tool.py (new)
        `close_investigation(deps, disposition, *, stages) -> CloseResult` — the host-level
        close, and the ONLY writer of report.md once R1 lands. `_tool_close_investigation`
        is its model-facing adapter; `register_close_tool` registers it at MAIN's
        composition root ONLY (K14: a verb grant cannot express this — a verb is a
        data-source operation and a non-empty grant on the investigator role fails at
        policy compile).
        `CLOSE_RETURNS` / `COMMITTED_OUTCOMES` — the two closed vocabularies (see below).
        `REPORT_CAUSES` — the host's OWN sentences, the only strings the cause may be.
        `FAILURE_KINDS` — the typed, countable half (see below).
        `CloseResult(outcome, message, material, record_path, cause, failure_kind, detail)`.
        `RecommendedLead(lead_id, requirement, origin)` — typed, no free-text limb.
        `BUDGET_EXEMPT_TOOLS` — RS16's explicit, recorded exemption.
        `render_report(disposition, *, outcome, ...)` — RS12: the body is host-rendered
        from TYPED arguments and routed through `validate_artifact`; the tool accepts no
        model-supplied body.

    defender/runtime/challenge_gate.py (new)
        `challenge_gate(deps, disposition, *, stages, bounds) -> GateVerdict`.
        `ReviewState` — the per-run turn/grace counters. K9: the deps object is frozen and
        carries exactly one mutable container and NO integer counter, so the counters need
        a container or a small holder; an int field cannot follow that precedent.
        `Bounds(extra_turns, grace_rounds)` — both INJECTED, never literal.
        `EXTRA_TURN_BOUND = 2`, `GRACE_BOUND = 1` (RS14), `raised_request_limit(bounds)`
        (RS7: read FROM the cap, never restated as a literal).
        `review_record_path(run_dir, turn)` / `write_review_record(...)` — RS11: beside the
        run, written temp-plus-rename.

    defender/runtime/review_roles.py (new)
        `CHALLENGER_DEF`, `COHERENCE_CHECKER_DEF` — NO read grant and NO bash grant at all
        (K28: narrowing read roots discharges nothing, because at write time the role's run
        dir IS the investigation's dir and both grant surfaces admit it unconditionally).
        `bind_review_role(defn, run_dir, ...)` — PR7/PR8: mints its OWN salt and never
        receives the session's, following the learning-stage precedent rather than the
        main→gather bind, which is the tree's sole shared-salt case.
        `build_challenger_input` / `build_coherence_checker_input` / `build_projection_input`.

    defender/runtime/agent_role.py (modified)  `AgentRole.CHALLENGER`, `.COHERENCE_CHECKER`.
    defender/runtime/driver.py (modified)      report.md leaves `_main_write_shape`;
                                               `run_investigation(review_stages=…)`.
    defender/run.py (modified)                 `preflight_role_models` — an ALL-ROLES
                                               startup preflight (PR9/PR10/PR11: none
                                               exists, live or offline).

RED AGAINST HEAD IS THE EXPECTED STATE. Where a probe refuted the design, the demanded
CORRECTION is pinned and today's behaviour is not:
  * the forced turn is NOT a tool refusal (K12 — a refusal is a raw retry, the budget is
    10, and the eleventh raises past every driver handler);
  * salt inheritance is NOT general (PR7/PR8), so a review role mints its own;
  * no preflight reaches a new role and "fails at build" is provider-dependent (PR12), so
    the demand is a STARTUP failure;
  * the trace hazard is NOT overwrite (PC7 — rounds append) but colliding record ids across
    rounds with no field marking the boundary (PC9);
  * the record's nearest precedent writes in place with no cleanup (PB1/PB5/PB6), so
    atomicity is demanded rather than inherited.

FAKES ENTER THROUGH INJECTION SEAMS ONLY — `drive(review_stages=…)` /
`close_investigation(stages=…)` / `bind(...)`. No `monkeypatch.setattr` anywhere (the
project profile records the CI ratchet). Every fake here injects FAULTS and RECORDS what it
was handed; none of them classifies an outcome or decides policy — that is the gate's job,
and a fake that decided it would grade its own homework.

REPAIR PASS. A second write-tests pass ran over the SHIPPED implementation and the human seam
settled seventeen forks. Three consequences reach this module:

  * `run_dir_with_alert` now seeds the leads the suite's projection fixtures NAME. A run
    directory that projects a lead the investigation never executed is an inconsistent
    fixture, and once the reply's identifiers are bounded to the list the host sent out it is
    a review failure. `l-999` stays absent on purpose — it is the out-of-list violation.
  * `monkeypatch.setenv` / `delenv` ARE used, deliberately: the CI ratchet is on `setattr`
    alone, and establishing an environment state is not patching a collaborator out from
    under the target. Establishing a state is also not the same as ASSERTING one — the
    budget-enforcement cell is now SET by the test rather than read off whatever the runner
    happened to choose, which is what made one committed test unpassable in CI.
  * The bounds object reaches the entry point, because the request ceiling's own base has no
    other path and moving it is the only way to tell a live read from a restated literal.
  * An EIGHTH seam: the close takes its artifact validator as a defaulted injected value
    (`RecordingValidator` below). Same reason and same sanction as the bounds object — the
    call is otherwise unobservable on the ordinary evidence-free close, and unobservable is
    exactly where a validator gated on the evidence argument hides.
  * THE FORCED-TURN COUNT IS VARIABLE, NOT FIXED. A forced turn whose discriminating leads
    were ALL already raised is not spent, so a run can terminate before the bound. Every
    multi-attempt scenario therefore scripts one genuinely new discriminating lead per attempt
    (`one_fresh_lead_per_turn`) instead of letting one lead repeat — see that helper for what
    a repeating lead silently turns each of those scenarios into.

VOCABULARY COLLAPSE (this pass). The close vocabulary had ten spellings for three things, and
a census established that no shipped consumer read any of them: every reader of report.md
routes on `disposition` alone. The human's decision is to keep only the outcomes that
genuinely differ and carry the CAUSE beside them in a sentence. Four consequences reach every
test in this suite:

  * THERE ARE TWO VOCABULARIES, NOT ONE, AND CONFLATING THEM IS WHAT PRODUCED THE TEN.
    `CLOSE_RETURNS` answers "what did this close ATTEMPT do" and is what the tool returns and
    what the review record's `verdict` carries. `COMMITTED_OUTCOMES` answers "what did this
    COMMIT record" and is what report.md carries. They differ by exactly one member —
    `challenged`, which by construction never commits and so can never appear on disk.
  * AN ASSERTION THAT MATCHED AN ARM NAME IS NOT AUTOMATICALLY AN ASSERTION ABOUT BEHAVIOUR.
    Where a retired arm encoded a real behavioural difference the test now keys on that
    difference directly — the disposition that survived, whether a turn was spent, the typed
    failure kind, the rounds the grace budget bought, the numbered record series. Where it
    encoded only a label, the assertion is gone and the digest says which.
  * REPORT.MD IS ENTIRELY HOST-AUTHORED, AND THE CAUSE IS NOT AN EXCEPTION. That file rides
    VERBATIM into the judge's prompt and out through the ticket bridge's HTTP egress, and
    every review stage composes its text after reading attacker-influenced payload. So the
    cause is one of the CLOSE'S OWN sentences (`REPORT_CAUSES`), and the stage-derived
    diagnostic — the close's `detail` — stays on the numbered review record, which no prompt
    reads verbatim. The suite never spells one of those sentences. What it pins is MEMBERSHIP
    in production's own set, that the set is COARSER than the set of conditions (one sentence
    per condition is the retired enum back under a longer name), and — driven, not asserted
    about a field's shape — that a marker planted in a payload-derived limb reaches the record
    and never the report.
  * THE FAILURE KIND IS THE TYPED, COUNTABLE HALF, AND THE CAUSE IS NOT. A sentence is a poor
    counting key and this suite deliberately never fixes its wording, so "how often does the
    review break, and how" cannot be asked of the cause. `FAILURE_KINDS` is where that lives:
    four members, each a different owner and a different fix, absent entirely when the review
    did not fail. It is what keeps a projection the gate could not read countable apart from a
    counter-story that never became coherent, now that both commit the same outcome.
"""
from __future__ import annotations

import asyncio
import importlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:  # pragma: no cover — never executed; keeps the target visible to the tools
    from defender.runtime.challenge_gate import (  # noqa: F401
        EXTRA_TURN_BOUND,
        GRACE_BOUND,
        Bounds,
        ReviewState,
        challenge_gate,
        raised_request_limit,
        review_record_path,
    )
    from defender.runtime.close_tool import (  # noqa: F401
        BUDGET_EXEMPT_TOOLS,
        CLOSE_RETURNS,
        COMMITTED_OUTCOMES,
        FAILURE_KINDS,
        REPORT_CAUSES,
        CloseResult,
        RecommendedLead,
        close_investigation,
        register_close_tool,
        render_report,
    )
    from defender.runtime.review_roles import (  # noqa: F401
        CHALLENGER_DEF,
        COHERENCE_CHECKER_DEF,
        bind_review_role,
        build_challenger_input,
    )

DEFENDER = Path(__file__).resolve().parents[1]
GOLDEN = DEFENDER / "fixtures-e2e" / "golden-sshpivot-ab3"


# --------------------------------------------------------------------------------------
# The deferred import of the not-yet-built surface.
# --------------------------------------------------------------------------------------

class SpecSurfaceMissing(AssertionError):
    """The demanded surface is absent. An AssertionError so pytest reports a FAILING
    contract rather than an infrastructure error — the spec is red, not broken."""


def spec_import(dotted: str, *names: str) -> Any:
    """Import a module (or its named attributes) that the implementation must build.

    Deferred to call time on purpose: at module scope this would be a collection error and
    would take every other test in the file down with it, so one missing module would read
    as one finding instead of sixty unbuilt contracts."""
    try:
        mod = importlib.import_module(dotted)
    except ImportError as e:  # noqa: F841 — the message carries it
        raise SpecSurfaceMissing(
            f"#774 demands `{dotted}`, which does not exist at this base ({e}). "
            f"The spec is the contract; build the module."
        ) from e
    if not names:
        return mod
    out = []
    for n in names:
        if not hasattr(mod, n):
            raise SpecSurfaceMissing(f"#774 demands `{dotted}.{n}`, which does not exist.")
        out.append(getattr(mod, n))
    return out[0] if len(out) == 1 else tuple(out)


# --------------------------------------------------------------------------------------
# The declarative fault-spec, and one recording fake per review-stage dependency.
# --------------------------------------------------------------------------------------

#: WHAT A CLOSE ATTEMPT DID — three values, because three things can happen to the disposition
#: the investigator drafted. The ten spellings this replaces differed only in WHY, and the
#: census found no shipped consumer reading any of them. This is what the tool returns and what
#: the review record's `verdict` carries.
#:
#: The investigation continues: nothing is committed, and the discriminating material comes back.
CHALLENGED = "challenged"
#: The drafted disposition is committed unchanged — because the gate never ran, or because it
#: ran and the counter-story did not survive, or because the challenger declined to argue one.
STANDS = "stands"
#: The drafted CONFIDENT disposition is overridden to inconclusive. Every way the gate can
#: refuse to let a confident finding stand lands here; which way is the cause's job, and the
#: cause is prose for a human rather than a value anything branches on.
FORCED_INCONCLUSIVE = "forced-inconclusive"

CLOSE_RETURNS = (CHALLENGED, STANDS, FORCED_INCONCLUSIVE)

#: WHAT A COMMIT RECORDED — a strictly smaller set, and the distinction one enum over both
#: sinks hid. The challenged path returns before the write, so `challenged` can never appear in
#: report.md; spanning both sinks with one vocabulary meant every reader of either had to know
#: which members its own sink could not hold.
COMMITTED_OUTCOMES = (STANDS, FORCED_INCONCLUSIVE)

#: HOW THE REVIEW FAILED — the typed half of "why", and the one vocabulary this pass ADDS back
#: after collapsing the other. It exists because the cause cannot do this job: the cause is a
#: sentence whose wording the spec deliberately leaves free, and a fleet query counting broken
#: reviews cannot key on prose nobody promised to keep stable. Absent (`None`) whenever the
#: review did not fail — an override the EVIDENCE produced is a finding about the case, not a
#: failure, and the control legs drive that so no assertion here is green on an always-set field.
#:
#: Four members, and the bar each had to clear is a different owner and a different fix:
#:   timeout    — a stage was still pending at its deadline. Capacity: move the bound, or chase
#:                the provider's latency. The one member whose right response may be "do nothing".
#:   error      — a stage call raised. A defect: something in the call path is broken, and the
#:                traceback is the artifact to read.
#:   unreadable — a stage ANSWERED, outside its own output contract: a reply that will not parse,
#:                rows missing the fields the classifier reads, or identifiers naming leads the
#:                investigation never executed. Nothing is down; the prompt or the contract is.
#:   incoherent — a stage answered INSIDE its contract and the content still could not be used:
#:                the counter-story never settled into internal consistency across the grace
#:                budget. This is the challenger-quality signal, and it is the member the whole
#:                field exists for — folding it into `unreadable` is exactly the inflated
#:                incoherence rate `test_unparseable_output_never_scores_as_challenger_incoherence`
#:                refuses, and after the collapse the outcome can no longer carry that split.
TIMEOUT = "timeout"
STAGE_ERROR = "error"
UNREADABLE = "unreadable"
INCOHERENT = "incoherent"

FAILURE_KINDS = (TIMEOUT, STAGE_ERROR, UNREADABLE, INCOHERENT)

#: RS14. Two forced turns matches the issue's stated intent and leaves headroom under the
#: framework's shared retry budget of 10 (K12); one refinement round, reset PER GATE
#: ATTEMPT — per-run means a second challenge inherits an exhausted budget and can never
#: refine at all. The same integer sets every run's raised request ceiling (RS7).
TURNS = 2
ROUNDS = 1
RETRY_BUDGET = 10          # K12 — the framework's shared tool-retry budget
BASE_REQUEST_LIMIT = 60    # K7 — what actually terminates a run


#: How long a `hangs` fake stays pending. It is the TEST's own safety net, never the
#: contract: a spec suite must not be able to wedge CI, so a gate with no deadline fails the
#: assertion after this rather than hanging forever the way the real precedent would (PS1).
#: Every scenario drives an injected deadline far below it, so a correct implementation ends
#: the call in milliseconds and never waits this out.
HANG_SECONDS = 2.0

#: The deadline scenarios inject. Small enough to keep the suite fast, large enough that a
#: correct implementation is not racing its own setup.
FAST_TIMEOUT = 0.05


@dataclass(frozen=True)
class StageFault:
    """A DATA fault-spec for one review stage. Every field cites the ledger claim that
    observed its fault class on the real dependency; nothing here is author-imagined.

    raises    — the stage call raises (K15: the gather tool, the only in-tree precedent for
                awaiting a subagent from a tool body, degrades three failure classes into
                result text; PR12: a provider raises at build on a missing key).
    malformed — the stage returns text that will not parse into the declared structure
                (C26: the merged pilot fixed the tail spec to a typed unsettled-requirement
                list, so "will not parse" is a real shape of this dependency's output).
    hangs     — the stage call is still pending when the gate's own deadline should fire.
                GROUNDED, no longer author-imagined: the live path's own precedent for
                awaiting a subagent from a tool body carries NO wall-clock bound (PS1) — its
                three catches are a request-COUNT cap and two structured-failure classes, and
                a count cap cannot fire on a call that is simply still pending. A hang there
                hangs forever. The fake therefore stays pending rather than raising a
                synthetic exception: the fault the tree really produces is a coroutine that
                never completes, and only the gate's own deadline can end it.

    from_call — WHEN the fault starts, zero-based; earlier calls take the scripted reply.
                Default 0 keeps the every-call behaviour every other scenario here relies on.

                It exists because a whole class of arm was inexpressible without it. The gate
                loops: a first ask, then one refinement per grace round. "Faults on every
                call" can only ever reach the FIRST round, so every fault arm this suite drove
                was a round-zero fault — and the arithmetic that records how many rounds a
                faulting run consumed is only wrong from round one onward. A live defect sat
                under that blind spot through the whole delta and was found by a probe with
                its own per-call script, not by this suite. This is that script, brought in.
    """

    raises: BaseException | None = None
    malformed: str | None = None
    hangs: bool = False
    from_call: int = 0


@dataclass(frozen=True)
class StageCall:
    """One invocation a stage fake received — the OUTBOUND payload, kept so a test can
    assert on what the gate BUILT rather than on the fake's canned reply. A fake that only
    returns answers leaves the whole outbound channel unpinned."""

    role: str
    request: Any

    @property
    def prompt(self) -> str:
        return str(getattr(self.request, "prompt", self.request))

    @property
    def salt(self) -> str | None:
        return getattr(self.request, "salt", None)

    @property
    def timeout(self) -> float | None:
        return getattr(self.request, "timeout", None)


class FakeStage:
    """One dependency, one fake. It injects the fault it was handed and records what it was
    handed; it never classifies an outcome and never decides policy."""

    def __init__(self, role: str, replies: list[str], fault: StageFault | None = None):
        self.role = role
        self._replies = list(replies)
        self._fault = fault or StageFault()
        self.calls: list[StageCall] = []

    async def __call__(self, request: Any) -> str:
        self.calls.append(StageCall(self.role, request))
        faulting = len(self.calls) - 1 >= self._fault.from_call
        if faulting and self._fault.hangs:
            # Stay pending. Nothing here converts the stall into an outcome — that is exactly
            # what the gate's deadline must do, and what PS1 shows the adjacent live
            # precedent does not.
            await asyncio.sleep(HANG_SECONDS)
        if faulting and self._fault.raises is not None:
            raise self._fault.raises
        if faulting and self._fault.malformed is not None:
            return self._fault.malformed
        # Past the script the last reply repeats, so a scenario scripts only the turns it
        # is about rather than padding to whatever the gate happens to ask for.
        return self._replies.pop(0) if len(self._replies) > 1 else self._replies[0]

    def only(self) -> StageCall:
        assert len(self.calls) == 1, f"expected one {self.role} call, got {len(self.calls)}"
        return self.calls[0]


class FakeReviewStages:
    """The injected review-stage bundle — the seam `run_investigation(review_stages=…)` and
    `close_investigation(stages=…)` take. One fake per dependency, each driven by its own
    data fault-spec, all three recording.

    This is the seam `review_stages_enter_through_an_injection_seam` pins. Without it the
    three stages are real agent runs against a live provider and NO scenario in this suite
    is drivable — which is why the seam is part of the contract, not test scaffolding."""

    def __init__(
        self,
        *,
        challenger: list[str] | None = None,
        coherence_checker: list[str] | None = None,
        projection: list[str] | None = None,
        challenger_fault: StageFault | None = None,
        coherence_checker_fault: StageFault | None = None,
        projection_fault: StageFault | None = None,
    ):
        self.challenger = FakeStage("challenger", challenger or [tail(())], challenger_fault)
        self.coherence_checker = FakeStage(
            "coherence_checker", coherence_checker or ["COHERENT"], coherence_checker_fault,
        )
        self.projection = FakeStage(
            "projection", projection or [projection_of(())], projection_fault,
        )

    @property
    def calls(self) -> list[StageCall]:
        return self.challenger.calls + self.coherence_checker.calls + self.projection.calls


# --------------------------------------------------------------------------------------
# Real inputs for the real primitives — no canned taxonomy where a fixture will do.
# --------------------------------------------------------------------------------------

def tail(requirements, *, story: str = "the pivot was an authorized developer workflow") -> str:
    """The challenger's output in the contract the merged pilot fixed (C26): per assertion a
    `settled_by` limb and an `if_false` limb, and the fold may drop no unsettled item.

    `requirements` is [(assertion, settled_by_lead_id_or_None, if_false), ...]."""
    return json.dumps({
        "counter_story": story,
        "requirements": [
            {"assertion": a, "settled_by": s, "if_false": f} for a, s, f in requirements
        ],
    })


def decline(reason: str = "the evidence supports no alternative account") -> str:
    """The challenger's DELIBERATE decline: it read the case and has no counter-story to write.

    Well-formed and parseable on purpose — a decline is a verdict, not a parse failure, and the
    suite's only near neighbour before RS17 scored a non-verdict reply as infrastructure noise."""
    return json.dumps({"counter_story": None, "declined": True, "reason": reason,
                       "requirements": []})


def lead_rows(prompt: str) -> list[list[str]]:
    """Every pipe-delimited row under the working document's lead block, split into columns.

    Row altitude, not tag altitude: RS18's resolution constrains which COLUMNS of a lead row
    reach the challenger, and a test that asserts a tag is present cannot see that."""
    out, inside = [], False
    for line in prompt.splitlines():
        if line.startswith(":L "):
            inside = True
            continue
        if inside:
            if not line.strip() or line.startswith((":", "`", "#")):
                inside = False
                continue
            out.append([c.strip() for c in line.split("|")])
    return out


def projection_of(rows) -> str:
    """The projection stage's per-lead reply: one of the three tags C19 established already
    exists as computed, host-rendered structure — `has-projection`, `empty-projection`,
    `no-projection`. `rows` is [(lead_id, tag), ...]; both silence tags mean the story does
    not touch that lead."""
    return json.dumps({"leads": [{"lead_id": lid, "tag": tag} for lid, tag in rows]})


def golden_document() -> str:
    """A REAL completed working document off the golden fixture — the observation rows, the
    hypothesis blocks, the resolution/authorization verdicts and the conclusion all present.

    Read from disk rather than hand-written so the observation-layer cut is re-probed against
    a real document on every run: K29 established on three of three real documents that the
    resolution and authorization rows restate the reached verdict in plain English, which is
    what refutes dropping the conclusion block alone."""
    return (GOLDEN / "investigation.md").read_text(encoding="utf-8")


#: The invlang block tags the observation layer is (PX3, and the design's own text draws the
#: same line): the observed graph plus the learned-fact updates. The lead block is here for its
#: IDENTITY only — the challenger's output contract requires a lead id per settled assertion —
#: and RS18 constrains which of its columns arrive, which is a row-content property this tuple
#: cannot express. See `lead_rows`.
OBSERVATION_TAGS = (":V ", ":E ", ":R attr_updates")
LEAD_TAG = ":L "

#: A lead row's columns, from the block header the working document declares. `tests` names the
#: hypotheses the lead was run to test — belief structure, on the inference side of the line —
#: and `loop` is scheduling state. RS18 keeps identity and target; those two are withheld.
LEAD_IDENTITY_COLUMNS = ("id", "name", "target")
LEAD_INFERENCE_COLUMNS = ("tests", "loop")
#: Everything else the projector recognizes carries a hypothesis weight, a resolved verdict,
#: or the final conclusion.
INFERENCE_TAGS = (":H ", ":R authz", "conclude", "CONCLUDE")


def report_text(disposition: str, *, body: str = "Concise.") -> str:
    """A report.md the CURRENT validator accepts — used as the on-disk baseline a test writes
    directly, never through the tool path (K18 splits those two populations).

    It carries `disposition` alone on purpose: that is the only key the schema validates, and
    this fixture stands for what a MODEL would try to write, not for what the close renders.
    It used to emit an optional `reason:` key that no caller ever set — a retired spelling of a
    field the close now splits in two."""
    return f"---\ndisposition: {disposition}\n---\n{body}\n"


#: The lead ids this suite's projection fixtures name. They are seeded as REAL executed leads
#: on disk because the host computes the executed-lead list from exactly these files and puts
#: it in the projection stage's prompt: a run dir that projects a lead it never executed is an
#: inconsistent fixture, and once reply identifiers are bounded to the list that went out it is
#: a review failure. `l-999` is deliberately absent — it is the out-of-list violation.
SUITE_EXECUTED_LEADS: tuple[str, ...] = ("l-001", "l-002", "l-009")


def one_fresh_lead_per_turn(turns: int) -> list[str]:
    """One projection reply per gate attempt, each naming a discriminating lead none of the
    earlier attempts raised.

    THE FORCED-TURN COUNT IS VARIABLE, NOT FIXED, and this helper is what every multi-attempt
    scenario in this suite is built on because of it. Scripting ONE lead and letting the fake
    repeat it makes attempt two a fully-overlapping attempt — every discriminating lead it
    names was already handed back — and a fully-overlapping attempt is refused its turn
    (`a_fully_overlapping_attempt_spends_no_turn`). Such a run terminates at attempt two and
    never reaches the bound, so a scenario about the BOUND, about per-run counters, or about
    what N attempts cost would silently stop being about any of those.

    Scripted this way the run advances one genuine turn per attempt, and the only thing that
    can stop it is the bound itself — which is what those scenarios mean to observe. The lead
    ids come from the executed list, so every reply also stays inside the subset rule."""
    assert turns <= len(SUITE_EXECUTED_LEADS), (
        f"{turns} genuine forced turns need {turns} distinct executed leads; the run dir "
        f"seeds {len(SUITE_EXECUTED_LEADS)}"
    )
    return [projection_of([(lead_id, "empty-projection")])
            for lead_id in SUITE_EXECUTED_LEADS[:turns]]


def run_dir_with_alert(tmp_path: Path, *, executed=SUITE_EXECUTED_LEADS) -> Path:
    """The on-disk shape a live investigation starts from: the run dir, `gather_raw/` with the
    leads the scenario will project, and the real alert fixture."""
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    (run_dir / "alert.json").write_bytes((GOLDEN / "alert.json").read_bytes())
    for lead_id in executed:
        (run_dir / "gather_raw" / f"{lead_id}.lead.json").write_text(
            json.dumps({"lead_id": lead_id, "system": "elastic"}), encoding="utf-8",
        )
    return run_dir


def main_deps(tmp_path: Path):
    """MAIN's deps through the REAL `bind` seam — the real compiled policy, the real gate.
    Returns `(deps, run_dir)`."""
    from defender.agents import MAIN_DEF
    from defender.runtime.agent_definition import bind

    run_dir = run_dir_with_alert(tmp_path)
    dfn = tmp_path / "defender"
    dfn.mkdir(exist_ok=True)
    return bind(MAIN_DEF, run_dir, defender_dir=dfn, salt="sess-salt"), run_dir


def frontmatter_of(path: Path) -> dict:
    from defender._frontmatter import split_frontmatter

    fm, _raw, _body = split_frontmatter(path.read_text(encoding="utf-8"))
    return fm


@dataclass
class Recorded:
    """A tiny recorder for surfaces a test needs to observe more than once."""

    seen: list[Any] = field(default_factory=list)

    def __call__(self, value: Any) -> Any:
        self.seen.append(value)
        return value


# --------------------------------------------------------------------------------------
# THE CLOSE'S CONDITION SET, in ONE place — thirteen conditions, twelve of which commit.
#
# WHY IT MOVED HERE. Two tests used to keep their own list of the conditions the gate can
# reach: a nine-entry table in the close-tool file, and a ten-entry census in the record
# file. Neither number was the code's. Ten was the size of the RETIRED close vocabulary, and
# the census asserted it as "all the conditions that exist" — so the one assertion whose
# stated job is to notice a dropped condition was a stale mirror of a count that had been
# withdrawn, green while three conditions went undriven. Two hand-maintained copies of a set
# neither of them derived is the drift itself; one table both read is the only fix that does
# not just re-set the same trap at a corrected number.
#
# HOW THE COUNT IS DERIVED — from `challenge_gate.py` and `close_tool.py`, never from a
# document. One condition per TERMINAL CLASSIFICATION SITE, and a site that takes its typed
# failure kind from the stage outcome counts once per kind it can emit:
#
#   the close's own pre-gate arm (a drafted `inconclusive` is not reviewed)             1
#   a stage call that did not return   — `_call_stage` emits `timeout` or `error`       2
#   the challenger's reply would not parse                                              1
#   the challenger DECLINED to argue                                                    1
#   the projection cannot be USED — unreadable, or naming an unexecuted lead: ONE site
#     and one member on purpose (different conditions, same response)                   1
#   the counter-story never became coherent inside the grace budget                     1
#   `_finalize_verdict`: settled / evidence-silent / all-confirmed / nothing-left-to-ask
#     / turn-budget-spent / challenged                                                  6
#                                                                                      ---
#                                                                                       13
#
# Twelve commit; `challenged` returns before the write and is the one that does not. The
# STAGE a fault came from (challenger vs the concurrent pair) is not a condition: it changes
# only the `detail`, which never reaches report.md.
#
# WHAT A CONSUMER MUST STILL CHECK ITSELF. The count alone is a backstop, not the guard —
# it is a literal, and a literal is what went stale. The real anti-drift assertions are the
# ones this table makes DRIVABLE: that the conditions between them witness every member of
# production's own `REPORT_CAUSES` and `FAILURE_KINDS`, both read off the shipped module.
# Add a condition the code can reach and forget it here, and those close-set assertions fire
# the moment it carries a cause or a kind nothing else produces.
# --------------------------------------------------------------------------------------

#: The challenger's requirement lists the table scripts. `_SETTLED` gives the tail an
#: already-settled requirement (nothing left to discriminate); `_UNSETTLED` leaves one open,
#: which is what routes an attempt into the projection's discriminator rule at all.
_SETTLED = (("the pivot was provisioned", "l-001", "the session was unauthorized"),)
_UNSETTLED = (("the pivot was provisioned", None, "the session was unauthorized"),)


@dataclass(frozen=True)
class CloseCondition:
    """One condition the close can reach, with the outcome it must reach and enough script
    to drive it end to end.

    `attempts` is why this is a table of DRIVERS rather than of stage bundles: two conditions
    are only reachable across several close calls against the SAME deps — the overlap rule
    needs a first attempt to have raised the lead the second one repeats, and the forced-turn
    bound needs the bound's worth of genuine turns before it. A table of single-call fixtures
    cannot express either, which is how both stayed out of the census."""

    label: str
    disposition: str
    outcome: str
    stages: Any                       # () -> FakeReviewStages
    attempts: int = 1
    fast_deadline: bool = False       # inject a deadline a `hangs` fake will actually trip

    @property
    def commits(self) -> bool:
        """`challenged` returns before the write; every other outcome lands a report."""
        return self.outcome != CHALLENGED


def drive_close_condition(condition: CloseCondition, deps: Any) -> Any:
    """Drive one condition to its terminal close and return the LAST `CloseResult`.

    Every attempt shares one stage bundle and one deps, because that is what makes the
    multi-attempt conditions the conditions they are — a fresh bundle per attempt resets the
    raised-lead set and the turn counter, and the two conditions that depend on those would
    quietly become a third copy of the single-attempt discriminated arm."""
    close_investigation = spec_import("defender.runtime.close_tool", "close_investigation")
    kw: dict[str, Any] = {}
    if condition.fast_deadline:
        bounds_cls = spec_import("defender.runtime.challenge_gate", "Bounds")
        kw["bounds"] = bounds_cls(
            extra_turns=TURNS, grace_rounds=ROUNDS, stage_timeout=FAST_TIMEOUT,
        )
    stages = condition.stages()
    result = None
    for _ in range(condition.attempts):
        result = close_investigation(deps, condition.disposition, stages=stages, **kw)
    return result


CLOSE_CONDITIONS: tuple[CloseCondition, ...] = (
    # ---- the close's own arm: a drafted `inconclusive` is never reviewed.
    CloseCondition("unchallenged", "inconclusive", STANDS, lambda: FakeReviewStages()),
    # ---- the challenger's three ways of ending the gate before the other stages run.
    CloseCondition("refuted", "malicious", STANDS,
                   lambda: FakeReviewStages(challenger=[tail(_SETTLED)])),
    CloseCondition("declined", "malicious", STANDS,
                   lambda: FakeReviewStages(challenger=[decline()])),
    CloseCondition("malformed", "malicious", FORCED_INCONCLUSIVE,
                   lambda: FakeReviewStages(challenger_fault=StageFault(malformed="{"))),
    # ---- the two stage-call faults. They are two conditions and not one because the typed
    #      kind differs, which is the whole point of the field: a deadline to move versus a
    #      traceback to read.
    CloseCondition("review-failed", "malicious", FORCED_INCONCLUSIVE,
                   lambda: FakeReviewStages(
                       challenger_fault=StageFault(raises=RuntimeError("stage down")))),
    CloseCondition("stage-timeout", "malicious", FORCED_INCONCLUSIVE,
                   lambda: FakeReviewStages(challenger_fault=StageFault(hangs=True)),
                   fast_deadline=True),
    # ---- the counter-story that never held together across the grace budget.
    CloseCondition("incoherent", "malicious", FORCED_INCONCLUSIVE,
                   lambda: FakeReviewStages(challenger=[tail(_UNSETTLED)],
                                            coherence_checker=["INCOHERENT"])),
    # ---- the projection the gate cannot USE. `l-999` is not in the run dir's executed set.
    CloseCondition("out-of-list-projection", "malicious", FORCED_INCONCLUSIVE,
                   lambda: FakeReviewStages(
                       challenger=[tail(_UNSETTLED)],
                       projection=[projection_of([("l-001", "empty-projection"),
                                                  ("l-999", "empty-projection")])])),
    # ---- the discriminator rule's two "the evidence cannot separate them" shapes.
    CloseCondition("nondiscriminating", "malicious", FORCED_INCONCLUSIVE,
                   lambda: FakeReviewStages(
                       challenger=[tail(_UNSETTLED)],
                       projection=[projection_of([("l-001", "has-projection")])])),
    CloseCondition("evidence-silent", "malicious", FORCED_INCONCLUSIVE,
                   lambda: FakeReviewStages(challenger=[tail(_UNSETTLED)],
                                            projection=[projection_of([])])),
    # ---- the two reasons a DISCRIMINATING attempt still spends no turn, which are different
    #      claims and carry different sentences: this turn can surface nothing new, versus
    #      the run has no turns left to spend.
    CloseCondition("nothing-left-to-ask", "malicious", FORCED_INCONCLUSIVE,
                   lambda: FakeReviewStages(
                       challenger=[tail(_UNSETTLED)],
                       projection=[projection_of([("l-001", "empty-projection")])]),
                   attempts=2),
    CloseCondition("turn-budget-spent", "malicious", FORCED_INCONCLUSIVE,
                   lambda: FakeReviewStages(challenger=[tail(_UNSETTLED)],
                                            projection=one_fresh_lead_per_turn(TURNS + 1)),
                   attempts=TURNS + 1),
    # ---- and the one that commits nothing.
    CloseCondition("challenged", "malicious", CHALLENGED,
                   lambda: FakeReviewStages(
                       challenger=[tail(_UNSETTLED)],
                       projection=[projection_of([("l-001", "empty-projection")])])),
)

#: The twelve that write a report. Derived, never restated — a condition added above with a
#: committing outcome joins this set and every assertion keyed on it without a second edit.
COMMITTING_CONDITIONS: tuple[CloseCondition, ...] = tuple(
    c for c in CLOSE_CONDITIONS if c.commits
)


# --------------------------------------------------------------------------------------
# REPAIR (phase E). Everything below this line was added by the repair pass.
# --------------------------------------------------------------------------------------

@pytest.fixture(scope="session", autouse=True)
def worktree_package_guard():
    """Fail the whole module loudly, naming the ENVIRONMENT cause, when the suite has
    imported a different checkout's copy of the package than the one holding these tests.

    The main checkout carries its own installed copy, so any invocation whose working
    directory is the main checkout silently loads THAT copy instead — probed, and it
    answered a registry query with eight roles where this tree has eleven. Every "every role"
    claim in this suite is then made against the wrong tree and passes or fails for a reason
    that has nothing to do with the change.

    The guard is keyed on the MODULE PATH, never on a role count — which is why it still
    guards after the resolutions that took the count to eleven, where a guard written on the
    count would have needed editing to keep passing and would have stopped meaning anything."""
    import defender.agents as agents_mod

    here = Path(__file__).resolve().parents[2]
    loaded = Path(agents_mod.__file__).resolve()
    assert here in loaded.parents, (
        f"ENVIRONMENT: this suite lives under {here} but imported the package from "
        f"{loaded} — a different checkout's installed copy. Run from a neutral directory "
        f"with PYTHONPATH={here}; every all-roles claim below is meaningless otherwise."
    )


def review_records(run_dir: Path) -> dict[int, dict]:
    """Every numbered review record the run left behind, parsed, keyed by turn.

    The close-shape distinction lives in this SERIES, not in report.md: a first-time close
    and a close committed after the gate forced turns render a byte-identical report (same
    disposition, same reason, same body — the renderer takes no turn count). Cardinality
    alone is not enough either, because a commit-type close reuses the previous commit's
    record path, so a caller must OPEN each record and read that turn's own material."""
    out: dict[int, dict] = {}
    for path in run_dir.glob("review_record.*.json"):
        turn = int(path.name.split(".")[1])
        out[turn] = json.loads(path.read_text(encoding="utf-8"))
    return out


def permuted_lead_document(*, swap=("name", "target")) -> str:
    """The golden working document with two lead columns exchanged in BOTH the declared
    header and every data row — a document that says exactly what it means and means exactly
    what it says, just in a different column order.

    This is a REAL input through the real primitive: the investigator authors this table
    itself, and nothing anywhere validates the order it chooses. A reader keyed on the
    declared header sees the same values under the same names; a reader keyed on fixed
    column positions silently relabels one lead's target as its name."""
    header_i, header_j = swap
    out: list[str] = []
    positions: tuple[int, int] | None = None
    inside = False
    for line in golden_document().splitlines():
        if line.startswith(LEAD_TAG):
            names = line[line.index("[") + 1: line.rindex("]")].split("|")
            stripped = [n.strip().rstrip("?") for n in names]
            positions = (stripped.index(header_i), stripped.index(header_j))
            names[positions[0]], names[positions[1]] = names[positions[1]], names[positions[0]]
            out.append(f"{line[: line.index('[') + 1]}{'|'.join(names)}]")
            inside = True
            continue
        if inside:
            if not line.strip() or line.startswith((":", "`", "#")):
                inside = False
                out.append(line)
                continue
            cells = line.split("|")
            assert positions is not None
            a, b = positions
            cells[a], cells[b] = cells[b], cells[a]
            out.append("|".join(cells))
            continue
        out.append(line)
    return "\n".join(out) + "\n"


def declared_lead_columns(document: str) -> list[str]:
    """The lead block's own declared column names, in the order the document declares them."""
    for line in document.splitlines():
        if line.startswith(LEAD_TAG):
            return [c.strip().rstrip("?")
                    for c in line[line.index("[") + 1: line.rindex("]")].split("|")]
    return []


def lead_cell(document: str, row_index: int, column: str) -> str:
    """One lead row's value for a column named by the document's OWN declared header."""
    columns = declared_lead_columns(document)
    return lead_rows(document)[row_index][columns.index(column)]


class RecordingStore:
    """A recording proxy over the per-case session store, entering through the
    `store_factory` injection seam the entry point already carries.

    It counts the calls the RENDER path makes (`set_last_render_len` is written once per
    row the render commits, and only by the render path), because the round on which
    compaction stops running is the observable the message store's request-limit mirror
    moves — the store's eventual CONTENTS are identical either way, since the round after a
    withheld one re-ingests what was withheld."""

    def __init__(self, inner: Any):
        self._inner = inner
        self.sessions: list[str] = []
        self.renders = 0

    def new_session(self, **kw: Any) -> str:
        session_id = self._inner.new_session(**kw)
        self.sessions.append(session_id)
        return session_id

    def set_last_render_len(self, *a: Any, **k: Any) -> Any:
        self.renders += 1
        return self._inner.set_last_render_len(*a, **k)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)


def recording_store_factory() -> tuple[Any, dict[str, RecordingStore]]:
    """`(factory, captured)` — hand `factory` to the entry point's `store_factory` seam and
    read `captured["store"]` after the run."""
    captured: dict[str, RecordingStore] = {}

    def factory(case_id: str, run_dir: Path) -> RecordingStore:
        from defender.runtime import driver

        store = RecordingStore(driver._default_store_factory(case_id, run_dir))
        captured["store"] = store
        return store

    return factory, captured


class RenderWatcher:
    """A model that never stops (so the run ends on its request ceiling) and samples the
    store's cumulative render count at every round — the per-round deltas are what say
    which rounds reached the compaction path and which were withheld from it."""

    __name__ = "RenderWatcher"

    def __init__(self, run_dir: Path, captured: dict[str, RecordingStore]):
        self.calls = 0
        self._alert = str(run_dir / "alert.json")
        self._captured = captured
        self.marks: list[int] = []

    def __call__(self, messages: Any, info: Any) -> Any:
        from pydantic_ai.messages import ModelResponse, ToolCallPart

        self.calls += 1
        store = self._captured.get("store")
        self.marks.append(store.renders if store is not None else -1)
        return ModelResponse(parts=[ToolCallPart(tool_name="read_file",
                                                 args={"path": self._alert})])

    def render_deltas(self, captured: dict[str, RecordingStore]) -> list[int]:
        """One entry per round the run drove, INCLUDING the doomed round the framework
        refuses — that last one is the whole point: it is the only round a correct mirror
        withholds."""
        final = captured["store"].renders
        marks = [*self.marks, final]
        return [marks[i + 1] - marks[i] for i in range(len(marks) - 1)]


class RecordingValidator:
    """A recording proxy over the artifact validator, entering through the close's own
    `validator=` seam.

    WHY THE SEAM EXISTS AT ALL. The ordinary close passes no evidence and renders its own
    body, so nothing it produces is content the report schema would refuse — which means a
    test can observe that a refusal HAPPENED but never that the validator RAN on the
    ordinary path. That gap is not cosmetic: it is precisely the difference between a
    validator guarding every commit and one gated on the evidence argument, and the second
    is the implementation the adversarial pass demonstrated. Handing the close its validator
    is the only injection-seam-shaped way to close it, and it is the same move the request
    ceiling's base already carries.

    It RECORDS `(artifact name, proposed body)` per call and injects at most one fault: a
    canned refusal reason. That is not an author-imagined fault class — `str | None` IS the
    real validator's return contract and a refusal reason is what it genuinely returns on
    content the report schema rejects, which the demand's own control leg establishes before
    any fake is involved.

    It DECIDES NOTHING. With no fault set it delegates to the real validator, so which arm
    the close takes is production's verdict rather than the fake's opinion.
    """

    def __init__(self, *, refuse: str | None = None):
        self.calls: list[tuple[str, str]] = []
        self.refuse = refuse

    def __call__(self, name: str, proposed_text: str, current: str | None) -> str | None:
        from defender._artifact_schema import validate_artifact

        self.calls.append((name, proposed_text))
        if self.refuse is not None:
            return self.refuse
        return validate_artifact(name, proposed_text, current)
