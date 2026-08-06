"""#797 — the retirement's own negatives, and the fail-closed posture it leaves behind.

A deletion needs its own tests for the same reason a feature does: nothing else in the tree
fails when a retired symbol quietly comes back, and the arms below are the only place the
INTERIM state — a gate with no reviewer — is written down as intended rather than as an
outage. #796 replaces this module when it lands its lenses and composer; until then these
are the live witnesses for what #797 removed.

Two of the arms below stand in for #791 demands whose subject #797 deletes. #791 asked that
the surviving live projection stage stop being spelled with the retired offline oracle's
name, and that the older spec graph stop addressing that stage's id. The stage and the graph
are both gone, so those demands are WAIVED in
`spec_graph_791-retire-offline-oracle.yaml` — and what they were protecting is asserted here
against what actually survives: no role in the live registry is named for the offline oracle,
and the retirement itself is recorded in the graph rather than dropped from it.
"""
from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFENDER = REPO_ROOT / "defender"
RUNTIME = DEFENDER / "runtime"
SPEC_CORPUS = REPO_ROOT / "spec-flow" / "specs"
GOLDEN = DEFENDER / "fixtures-e2e" / "golden-v2sshd"

#: The three roles #797 retired. Spelled once, read by every arm below.
RETIRED_ROLES = ("challenger", "coherence_checker", "projection")

#: The retired offline stage's name. `AgentRole.PROJECTION` existed so the LIVE stage would
#: not join by name to this; with the live stage gone, the rule that survives is simply that
#: no review role carries it.
RETIRED_OFFLINE_STAGE = "oracle"

#: The vocabulary the counter-story machinery was built out of. Every one of these was a
#: symbol, a JSON key or a record field in `challenge_gate` / `review_roles` / `close_tool`.
COUNTER_STORY_VOCABULARY = (
    "counter_story",
    "counter-story",
    "CHALLENGER_DEF",
    "COHERENCE_CHECKER_DEF",
    "PROJECTION_DEF",
    "build_challenger_input",
    "build_coherence_checker_input",
    "build_projection_input",
    "build_refinement_input",
    "_extract_observation_layer",
    "_classify_projection",
    "_unexecuted_leads",
    "GRACE_BOUND",
    "grace_rounds",
    "REQUIREMENT_MAX",
    "requirement_list",
    "projection_response",
    "attacked_disposition",
)

#: The gate's own modules. The negatives below are scoped to these rather than to the whole
#: tree: `defender/learning/` keeps its own actor, its own counter-dispositions and its own
#: projection vocabulary, and #797 does not touch any of it.
GATE_MODULES = (
    RUNTIME / "challenge_gate.py",
    RUNTIME / "review_roles.py",
    RUNTIME / "close_tool.py",
    RUNTIME / "agent_role.py",
)


def _main_deps(tmp_path: Path):
    """MAIN's deps through the REAL `bind` seam — the real compiled policy, the real gate."""
    from defender.agents import MAIN_DEF
    from defender.runtime.agent_definition import bind

    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    (run_dir / "alert.json").write_bytes((GOLDEN / "alert.json").read_bytes())
    dfn = tmp_path / "defender"
    dfn.mkdir(exist_ok=True)
    return bind(MAIN_DEF, run_dir, defender_dir=dfn, salt="sess-salt"), run_dir


def test_797_no_review_role_survives_the_retirement():
    """The three retired roles are gone from the enum AND from the agent registry, and no
    surviving role is named for the retired offline stage.

    Both surfaces, because they fail differently. An enum member with no definition is a
    compiled grant nothing claims and a trace filename nothing writes; a registry entry with
    no enum member cannot exist, but a registry that still BUILDS a retired definition would
    keep its policy alive while every caller was gone.

    The second half re-sites #791's `live_projection_stage_sheds_the_retired_name`. That
    demand protected a live stage from joining by name to the offline oracle #791 deleted;
    the stage is gone, the rule is not, and the registry is where it now has to hold.

    Positive control: the surviving roles are enumerated and non-empty, so an emptied enum
    passes nothing here."""
    from defender.agents import AGENTS
    from defender.runtime.agent_role import AgentRole

    members = {role.value for role in AgentRole}
    assert members, "the enum is empty; every absence below is vacuous"
    assert "main" in members, f"the investigator role left the enum: {sorted(members)}"
    assert "gather" in members, f"the gather role left the enum: {sorted(members)}"

    for retired in RETIRED_ROLES:
        assert retired not in members, (
            f"AgentRole still carries {retired!r} — an enum key grants compiled policy and "
            "names a trace file, so a member with no definition behind it is a live grant "
            "nothing claims"
        )
        assert not any(r.value == retired for r in AGENTS), (
            f"the agent registry still builds a definition for {retired!r}"
        )

    for role in AGENTS:
        # The offline learning oracle keeps its own role; a REVIEW role must not be named for
        # it. Nothing in the registry is a review role after #797, which is what makes this
        # arm a guard on #796's roster rather than an assertion about today.
        if role.value == RETIRED_OFFLINE_STAGE:
            continue
        assert RETIRED_OFFLINE_STAGE not in role.value, (
            f"role {role.value!r} joins by name to the retired offline stage"
        )


def _code_tokens(path: Path) -> set[str]:
    """Every name and non-docstring string literal the module's CODE carries.

    Parsed, not grepped, and deliberately blind to comments and docstrings: this file and the
    three it reads all EXPLAIN the retirement in prose, naming what went, and a raw substring
    scan cannot tell "the challenger is gone" from `build_challenger_input(...)`. A scan that
    forces the explanation out is a scan that trades the record for the check.

    What it does see is what a reader could wire back up: a definition, a call, an attribute,
    a keyword, a dict key — including a helper that is defined and never called, which an
    import-shaped check would miss entirely."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    docstrings = {
        node.body[0].value
        for node in ast.walk(tree)
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef))
        and node.body
        and isinstance(node.body[0], ast.Expr)
        and isinstance(node.body[0].value, ast.Constant)
        and isinstance(node.body[0].value.value, str)
    }
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if node not in docstrings:
                out.add(node.value)
        elif isinstance(node, ast.Name):
            out.add(node.id)
        elif isinstance(node, ast.Attribute):
            out.add(node.attr)
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            out.add(node.name)
        elif isinstance(node, (ast.arg, ast.keyword)) and node.arg:
            out.add(node.arg)
        elif isinstance(node, ast.alias):
            out.add(node.asname or node.name)
    return out


def test_797_the_gate_modules_carry_no_counter_story_vocabulary():
    """No symbol, JSON key or record field of the counter-story machinery survives in the
    gate's own modules' code.

    Scoped to `GATE_MODULES`. `defender/learning/` keeps its actor, its counter-dispositions
    and its own projection vocabulary — #797 retires the LIVE gate's three stages, not the
    offline loop, and a tree-wide scan would assert the opposite.

    Positive control: each module parses to a non-empty token set, and the survivors from the
    issue's own "stays" list are asserted PRESENT — so an emptied or deleted module fails
    here rather than passing every absence."""
    for path in GATE_MODULES:
        tokens = _code_tokens(path)
        assert tokens, f"{path.name} carries no code at all; the absences below mean nothing"
        for word in COUNTER_STORY_VOCABULARY:
            hits = sorted(t for t in tokens if word in t)
            assert hits == [], (
                f"{path.name} still carries {word!r} in code ({hits}) — #797 retires the "
                "party that produced a counter-story and every consumer it had"
            )

    gate = _code_tokens(RUNTIME / "challenge_gate.py")
    for survivor in ("_call_stage", "_write_trace_row", "_mark_traces_incomplete",
                     "_fresh_stage_request", "raised_request_limit", "write_review_record",
                     "StageRequest", "StageOutcome", "ReviewState", "Bounds"):
        assert survivor in gate, (
            f"the harness lost {survivor!r} — #797 retires the stages, not the machinery "
            "they ran inside"
        )


def test_797_the_two_vocabularies_carry_no_member_without_a_producer():
    """`FAILURE_KINDS` sheds `incoherent` and `REPORT_CAUSES` sheds the no-story cause, and
    no surviving cause still points at an alternative account.

    A vocabulary member no producer can reach is worse than a missing one: every fleet query
    counts it as legitimately empty. `incoherent` was the coherence checker's quality signal
    and the checker is gone; the no-story cause named the challenger's deliberate decline and
    nothing declines any more.

    The reworded causes are asserted on the RETIRED PHRASE, not on their new wording — a test
    that transcribed the new sentence would freeze prose the issue explicitly reserves the
    right to reword, and would fail for a comma."""
    from defender.runtime import close_tool

    assert "incoherent" not in close_tool.FAILURE_KINDS, (
        "`incoherent` survives with no producer — the coherence checker that scored it and "
        "the grace budget it was measured across are both retired"
    )
    assert not hasattr(close_tool, "INCOHERENT"), \
        "the retired failure kind is still exported as a name"
    assert not hasattr(close_tool, "CAUSE_NO_STORY"), \
        "the challenger's decline cause is still exported as a name"
    assert set(close_tool.FAILURE_KINDS) == {"timeout", "error", "unreadable"}, (
        f"the failure vocabulary is {close_tool.FAILURE_KINDS} — the three survivors are the "
        "ones a stage call, a deadline and an unusable reply can still produce"
    )

    for cause in close_tool.REPORT_CAUSES:
        assert "alternative account" not in cause, (
            f"a report cause still names an alternative account: {cause!r} — nothing in the "
            "tree offers one"
        )
    assert len(close_tool.REPORT_CAUSES) == 6, (
        f"the cause set is {close_tool.REPORT_CAUSES} — six survive the retirement of the "
        "seventh, and the set was neither emptied nor regrown"
    )


def test_797_a_confident_close_fails_closed_when_no_stage_is_bound(tmp_path):
    """A confident disposition reviewed through an UNBOUND bundle commits `inconclusive`, and
    says on disk that the MACHINERY is what failed.

    #797 asserted this of a gate with no reviewer at all. #796 bound one, and the property it
    was really about survives the binding: a bundle whose stages are not bound — the shape
    `driver.build_agent` produces, having no run dir to bind against — must fail a confident
    close closed rather than let it through. RS9 gives the gate two options and picks the
    override; silently committing would look identical to a review that ran and found nothing.

    The run dir carries a real investigation.md so the fault is provably the unbound stage
    rather than a document the projector could not read — both fail closed, and only one is
    what this test names.

    `failure_kind` is what separates this from an override the EVIDENCE produced: both commit
    `forced-inconclusive`, and only a machinery failure names a kind. Asserting the
    disposition alone would pass just as well if the gate had decided the case on evidence it
    never looked at.

    An `inconclusive` close is the positive control: it bypasses the gate entirely, so it
    still commits its own disposition and names no failure kind — which is what shows the
    override above is the gate acting rather than the close tool being broken."""
    pytest.importorskip("pydantic_ai")
    from defender._frontmatter import split_frontmatter
    from defender.runtime.close_tool import (
        CAUSE_NOT_REVIEWED,
        CAUSE_REVIEW_INCOMPLETE,
        FORCED_INCONCLUSIVE,
        STAGE_ERROR,
        STANDS,
        close_investigation,
    )
    from defender.runtime.review_roles import ReviewStages

    deps, run_dir = _main_deps(tmp_path)
    (run_dir / "investigation.md").write_bytes((GOLDEN / "investigation.md").read_bytes())
    result = close_investigation(deps, "malicious", stages=ReviewStages())

    assert result.outcome == FORCED_INCONCLUSIVE, (
        f"a confident close returned {result.outcome!r} with no reviewer bound"
    )
    assert result.cause == CAUSE_REVIEW_INCOMPLETE
    assert result.failure_kind == STAGE_ERROR, (
        f"the override names {result.failure_kind!r} — a gate with no reviewer is the "
        "machinery failing, not a finding about the evidence"
    )

    fm, _raw, _body = split_frontmatter((run_dir / "report.md").read_text(encoding="utf-8"))
    assert fm["disposition"] == "inconclusive", (
        f"report.md committed {fm['disposition']!r} — the drafted confident disposition "
        "reached disk unreviewed"
    )
    assert fm["outcome"] == FORCED_INCONCLUSIVE
    assert fm["failure_kind"] == STAGE_ERROR

    record = json.loads(Path(result.record_path).read_text(encoding="utf-8"))
    assert record["failure_kind"] == STAGE_ERROR
    assert "not bound" in record["detail"], (
        "the review record does not say WHY the review could not run — an operator reading "
        f"the run gets an anonymous stage error: {record['detail']!r}"
    )

    # Positive control: the gate reviews CONFIDENT closes only.
    bypass_deps, bypass_dir = _main_deps(tmp_path / "bypass")
    bypass = close_investigation(bypass_deps, "inconclusive", stages=ReviewStages())
    assert bypass.outcome == STANDS
    assert bypass.cause == CAUSE_NOT_REVIEWED
    assert bypass.failure_kind is None, (
        "the un-gated path names a failure kind, so the assertion above is about the close "
        "tool rather than about the gate"
    )
    bypass_fm, _r, _b = split_frontmatter(
        (bypass_dir / "report.md").read_text(encoding="utf-8")
    )
    assert bypass_fm["disposition"] == "inconclusive"
    assert "failure_kind" not in bypass_fm, (
        "the un-gated close writes a failure kind, so its absence proves nothing above"
    )


#: The two #791 demands whose SUBJECT #797 deletes — the live projection stage, and the spec
#: graph that specified it. Named here because the arm below is what stops them from being
#: silently dropped or silently left dangling.
ORPHANED_791_DEMANDS = (
    "live_projection_stage_sheds_the_retired_name",
    "rekey_live_projection_graph_id",
)


def test_797_the_retired_graph_is_gone_and_the_demands_it_stranded_are_recorded():
    """`spec_graph_774.yaml` leaves the corpus, and the two #791 demands whose subject went
    with it are recorded as WAIVED rather than deleted or left pointing at nothing.

    Three outcomes were available for those demands and only one is honest. Deleting them
    rewrites #791 into a change that never asked. Leaving them as `form: test` leaves a
    `discharged_by` naming a function that no longer exists — a pointer that resolves to
    nothing, which reads exactly like a demand nobody ever wrote, and which is the precise
    failure #791 itself was about. A waiver keeps the record and says what happened to it.

    The rules those demands carried do not lapse with them: no review role may be named for
    the retired offline stage (asserted above, against the live registry), and no graph may
    address a file that is gone — which is why the waiver's own binds are the last addresses
    in the corpus naming the deleted graph, and why they are stated rather than swept.

    Positive control: the graph parses and still carries its other demands, so an emptied or
    unreadable file does not pass."""
    retired = SPEC_CORPUS / "spec_graph_774.yaml"
    assert not retired.exists(), (
        "spec_graph_774.yaml survives — it is the executable spec for the three stages #797 "
        "retires, and #796's spec replaces it rather than amending it"
    )

    graph_path = SPEC_CORPUS / "spec_graph_791-retire-offline-oracle.yaml"
    graph = yaml.safe_load(graph_path.read_text(encoding="utf-8"))
    demands = {d["id"]: d for d in graph["demands"]}
    assert len(demands) > 10, (
        f"{graph_path.name} declares only {len(demands)} demands — it was emptied rather than "
        "amended, and the assertions below are about a file that lost its content"
    )

    for did in ORPHANED_791_DEMANDS:
        assert did in demands, (
            f"#791's demand {did!r} was deleted rather than waived — the graph now reads as a "
            "change that never asked for it"
        )
        demand = demands[did]
        assert demand.get("form") == "waiver", (
            f"{did} is still `form: {demand.get('form')}` — its subject is gone, so any "
            "`discharged_by` it carries names a test that cannot exist"
        )
        assert "discharged_by" not in demand, (
            f"{did} still carries a `discharged_by` pointer alongside its waiver"
        )
        rationale = (demand.get("outcome", {}) or {}).get("nl", "")
        assert "797" in rationale, (
            f"{did}'s waiver does not say which change retired its subject: {rationale!r}"
        )
