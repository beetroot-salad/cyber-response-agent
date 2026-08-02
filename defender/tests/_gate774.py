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
        `CLOSE_OUTCOMES` — the closed vocabulary, NINE arms (RS13 added the ninth).
        `CloseResult(outcome, message, material, record_path, reason)`.
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
"""
from __future__ import annotations

import asyncio
import importlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

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
        CLOSE_OUTCOMES,
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

#: The ten arms of the close tool's typed result. Eight from the demand set, RS13's
#: third discriminator arm, which exists because "every executed lead silent" and "no lead
#: executed at all" are read by the two-branch split as opposite evidence when both mean the
#: evidence cannot speak to the story.
UNCHALLENGED = "closed-unchallenged"
REFUTED = "closed-refuted"
INCOHERENT = "closed-incoherent"
#: The CHALLENGER's own deliberate decline — it read the case and had no counter-story to
#: write. The decline is recorded and judged and the investigator's confident close STANDS.
#: This is the design's own O8/D8 output and it is NOT an unresolvable case.
DECLINED = "closed-declined"
#: The REVIEW MACHINERY failing to complete — RS9's fail-closed outcome, which forces the
#: disposition to inconclusive. Split from the decline by RS17: the two meant opposite things
#: and shared one value and one downstream handling, which is the collapse the sixth-arm
#: resolution refused to accept in the mirror direction.
REVIEW_FAILED = "forced-inconclusive-review-failed"
MALFORMED = "closed-malformed"
CHALLENGED = "challenged"
FORCED_NONDISCRIMINATING = "forced-inconclusive-nondiscriminating"
FORCED_CAP = "forced-inconclusive-cap"
EVIDENCE_SILENT = "closed-evidence-cannot-speak"

ARMS = (
    UNCHALLENGED, REFUTED, INCOHERENT, DECLINED, REVIEW_FAILED, MALFORMED, CHALLENGED,
    FORCED_NONDISCRIMINATING, FORCED_CAP, EVIDENCE_SILENT,
)

#: The three arms on which the gate MANUFACTURES an unresolved disposition — what the coverage
#: waiver's population is counted over. The decline is deliberately not among them.
MANUFACTURED_UNRESOLVED = (FORCED_CAP, REVIEW_FAILED, EVIDENCE_SILENT)

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
    """

    raises: BaseException | None = None
    malformed: str | None = None
    hangs: bool = False


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
        if self._fault.hangs:
            # Stay pending. Nothing here converts the stall into an outcome — that is exactly
            # what the gate's deadline must do, and what PS1 shows the adjacent live
            # precedent does not.
            await asyncio.sleep(HANG_SECONDS)
        if self._fault.raises is not None:
            raise self._fault.raises
        if self._fault.malformed is not None:
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
        self.projection = FakeStage("oracle", projection or [projection_of(())], projection_fault)

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


def report_text(disposition: str, *, reason: str | None = None, body: str = "Concise.") -> str:
    """A report.md the CURRENT validator accepts — used as the on-disk baseline a test writes
    directly, never through the tool path (K18 splits those two populations)."""
    fm = f"disposition: {disposition}\n" + (f"reason: {reason}\n" if reason else "")
    return f"---\n{fm}---\n{body}\n"


def run_dir_with_alert(tmp_path: Path) -> Path:
    """The on-disk shape a live investigation starts from: the run dir, `gather_raw/`, and
    the real alert fixture."""
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    (run_dir / "alert.json").write_bytes((GOLDEN / "alert.json").read_bytes())
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
