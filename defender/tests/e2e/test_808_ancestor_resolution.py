"""#808 item 1 — resolving the alert's ancestors and rendering them into ORIENT.

Every test here is one demand of `spec-flow/specs/spec_graph_808.yaml`, named after its
`discharged_by` pointer and carrying that demand's observable-outcome prose in its docstring.
THE CODE DOES NOT EXIST YET: this suite is RED by construction.

ITEM 1 IS TWO CALLS, AND THE FIRST ONE IS ALWAYS THE SAME
----------------------------------------------------------
Call 1 fetches the alert's OWN SHELL DOCUMENT by `alert_id` against the index the alert says
it came from (`signal_index`). `kibana.alert.group.id` is read off THAT document — never off
the run-dir `alert.json`, because brief R3 / `g17` (executed) show nothing under `defender/`
produces that file, so F4 arm (a) ("the projection must start carrying group.id") cannot be
demanded of shipped code. §7 took arm (b) in round 1 and again in round 2.

Call 2 is the branch: group-scoped building blocks if the shell carries a group id, the
batched `_id` fetch over `ancestor_events` if it does not. Two calls in the ordinary case;
one per distinct mapped backing index when the ancestors span more than one, never one per
ancestor. THE FIRST CUT OF THIS FILE ASSERTED `== ["alerts"]` / `== ["query"]` — exactly one
call — which would have FAILED an implementation doing what §7 resolved twice. That is the
pinned-green shape, caught at phase F, and it is why these assertions are written as a
SEQUENCE (shell, then branch) rather than as a count.

WHAT THE RESOLUTIONS CHANGED, AND WHY A TEST HERE CANNOT PIN TODAY'S BEHAVIOUR
------------------------------------------------------------------------------
Three more of this file's demands were rewritten by the ledger before they were written down;
pinning the refuted reading would harden a probed bug into a contract by its own spec:

  * `d3` was "render in `kibana.alert.group.index` order". r3/a1 (executed) refute it: the
    adapter's `resolve_sort` admits exactly `('desc','asc')` and `_build_search_body`
    hardcodes `@timestamp`. K4 resolved CHRONOLOGICAL, sorted CLIENT-SIDE, on BOTH paths —
    backend order would present the issue's own worked example backwards (three failures,
    then the success), on the only path any checked-in fixture exercises.
  * `d5` ("one backend call regardless of ancestor count") is FALSE AS WRITTEN: c4 (executed)
    shows a comma-joined multi-index expression is refused WHOLE, so two backing indices
    cannot share a call.
  * K13, execution-grounded by P1a: an empty id predicate does NOT fail. It falls through to
    `must = [{"match_all": {}}]` and returns the confined pattern's NEWEST 20 DOCUMENTS with
    the same total/returned shape a genuine match carries — 20 unrelated documents rendered
    under the heading "this alert's ancestors", which nothing downstream can detect (K3's
    shortfall note never fires: 20 returned against 4 requested never trips
    `returned < len(ancestor_events)`). It applies at BOTH id-bearing predicates now: the
    ancestor list and the `alert_id` the shell fetch is built from.
"""
from __future__ import annotations

import pytest

pytest.importorskip("pydantic_ai")

from defender._io import read_jsonl_rows  # noqa: E402
from defender._run_paths import RunPaths  # noqa: E402
from defender.scripts.adapters.confinement import ConfinementFault, confine_index  # noqa: E402
from defender.scripts.adapters.faults import TransportFault  # noqa: E402
from defender.tests.e2e._lead_zero_808 import (  # noqa: E402
    ALERT_ID,
    ALERT_ID_FIELD,
    ALERTS_INDEX,
    AUTH_BACKING,
    ELIDED,
    EVENTS_INDEX,
    FALCO_BACKING,
    L0,
    L3,
    SALT,
    SHORTFALL,
    UNAVAILABLE,
    alert_doc,
    ancestor,
    answer_by_index,
    answer_hits,
    answer_raising,
    answer_sequence,
    building_block,
    defender_dir,
    elastic_backend,
    envelope,
    hit,
    materialize_alert,
    run,
    shell_doc,
)
from defender.tests.e2e._replay_harness import VerbRecorder  # noqa: E402

pytestmark = pytest.mark.e2e

PATTERNS = (EVENTS_INDEX, ALERTS_INDEX)

# The issue's own motivating narrative, in the order it happened: three failures, then the
# success. The fake hands it back NEWEST-FIRST, the way the adapter's default sort would
# (r3/g15) — so a block that echoes the backend's order renders the story backwards.
FAILED_1 = hit(ts="2026-05-25T15:22:00.000Z", message="Failed password for dev.dana")
FAILED_2 = hit(ts="2026-05-25T15:23:00.000Z", message="Failed password for dev.dana")
SUCCESS = hit(ts="2026-05-25T15:26:00.000Z", message="Accepted password for dev.dana")
NEWEST_FIRST = [SUCCESS, FAILED_2, FAILED_1]

FOUR_ANCESTORS = [ancestor(f"anc-{i}") for i in range(1, 5)]
SEQUENCE_SHELL = shell_doc(group_id="grp-0")

# The three sentences the empty-body arms render, spelled as production spells them. Pinned
# whole rather than by a fragment because what #880 F-14 is about is WHICH of them a run gets:
# all three are `_(unavailable: …)`, and a test that matched only the shared prefix read the
# false one as green.
RESOLVED_ABSENCE = "the resolution reached the backend and found nothing"
ANCESTOR_CALLS_FAILED = "every backend call that could have resolved an ancestor failed"
#: Nothing answered at all, and no ancestor call was ever issuable because the shell fetch
#: that decides whether one exists is what failed.
SHELL_ONLY_FAILED = "every backend call this resolution attempted failed"


def _order(section: str, *needles: str) -> list[int]:
    return [section.index(n) for n in needles]


# --------------------------------------------------------------------------------------- #
# Call 1 — the shell alert
# --------------------------------------------------------------------------------------- #

def test_item_one_fetches_the_shell_alert_by_alert_id_against_its_own_signal_index(tmp_path):
    """F4(b) — item 1's FIRST backend call fetches the alert's own shell document by
    `alert_id`, against the index the alert declares it came from (`signal_index`), before any
    ancestor work. That document is where `kibana.alert.group.id` is read, and reading it is
    the only way lead-0 can learn whether this alert is an EQL sequence at all.

    The alternative — extending the alert projection to carry `group.id` — is F4 arm (a), and
    brief R3 / `g17` (executed) show it cannot be demanded of shipped code: nothing under
    `defender/` produces the run-dir `alert.json`. `r6`/`g20` (executed) supply this arm's
    other half: all five checked-in fixtures carry `signal_index`, so the index the shell
    fetch needs is already in hand and costs no new input.

    The predicate is built from the alert's own id, not from `ancestor_events` — a shell fetch
    that carried ancestor ids would be the ancestor fetch wearing the wrong name — and it names
    the DOCUMENT FIELD that id maps to. `alert_id` is a key of the run-dir `alert.json`, not of
    an alert document: the only mapping in this tree is `project_alert.py:62`'s
    `"alert_id": s.get("kibana.alert.uuid")` (claim `a6`, which carries its own caveat that
    brief R3 / g17 refuted that same file as a producer). Without the field pinned, this
    assertion cannot tell `kibana.alert.uuid:"…"` from `_id:"…"`, and an implementer who picks
    the other one ships green while the primary path silently never runs against a real
    cluster. Whether the alerts index actually answers on that field is a live-cluster
    question and sits in `handoff.deferred` beside `c3`.

    AND IT REACHES THE ALERT'S OWN VALUE WHEN THE TWO DIVERGE. All five checked-in fixtures
    carry `signal_index` identical to the configured `ELASTIC_ALERTS_INDEX` (r6/g20, executed),
    so K16's decision — read the alert's own value, not the constant — is pinned nowhere the
    two disagree, and the FIRST call of every run is where it decides. The divergent value is
    SYNTHESIZED rather than deferred, and it is faithful to what the environment produces: a
    concrete `…-default-000001` is what an alert carries once the configured pattern resolves,
    and r13 (executed) records the shipped gate accepting exactly that string. The gate is
    re-run on the synthesized value here so the scenario cannot pass by testing the gate."""
    res = run(tmp_path, run_id="lz808-shell", answer=answer_hits([hit(ts="2026-05-25T15:22:00.000Z")]))

    shell = res.shell_call
    assert shell.verb == "alerts", \
        f"the shell fetch did not go through the alerts verb: {shell.verb}"
    assert shell.params["index"] == ALERTS_INDEX, \
        "the shell fetch did not target the index the alert says it came from"
    assert ALERT_ID in shell.params["native_query"], \
        f"the shell fetch's predicate does not name the alert's own id: {shell.params}"
    assert ALERT_ID_FIELD in shell.params["native_query"], (
        f"the shell fetch's predicate does not name {ALERT_ID_FIELD!r}, the document field the "
        f"alert's `alert_id` maps to (a6): {shell.params['native_query']!r}"
    )
    for entry in ("anc-1", "anc-2"):
        assert entry not in shell.params["native_query"], \
            "the shell fetch carries ancestor ids — it is the ancestor fetch, misnamed"

    diverging = ".internal.alerts-security.alerts-default-000001"
    assert diverging != ALERTS_INDEX, "the scenario stopped diverging from the constant"
    assert confine_index(diverging, PATTERNS) == diverging, \
        "the synthesized divergent index is not one the shipped gate accepts — the scenario " \
        "would be testing the gate rather than which value item 1 reads"
    apart = run(tmp_path / "diverging", run_id="lz808-shell-diverging",
                alert=alert_doc(signal_index=diverging),
                answer=answer_hits([hit(ts="2026-05-25T15:22:00.000Z")]))
    assert apart.shell_call.params["index"] == diverging, (
        "the shell fetch reached the configured ELASTIC_ALERTS_INDEX on an alert that declares "
        "a different one — K16 reads the alert's OWN signal_index, and no checked-in fixture "
        "can tell the two readings apart because all five carry them identical (r6/g20)"
    )


def test_a_shell_alert_unresolvable_by_alert_id_falls_back_to_the_batched_fetch(tmp_path):
    """K5 — when the by-`alert_id` fetch resolves NO document, no `group.id` is in hand, so
    item 1 takes the same branch it takes when the alert carries no group at all: the batched
    `_id` fetch over `ancestor_events`, which is read off the alert itself and needs no shell.
    The ancestors still reach MAIN.

    That is F10's own resolved rule ("fall back on no group OR no building blocks") applied to
    the state one step earlier, and it is the arm that keeps the change's obligation intact: a
    shell fetch that finds nothing is not evidence that this alert has no ancestors, and
    treating it as such would silently drop the evidence item 1 exists to supply."""
    res = run(tmp_path, run_id="lz808-noshell", shell=[],
              answer=answer_hits([hit(ts="2026-05-25T15:22:00.000Z",
                                      message="Accepted password for dev.dana")]))

    assert [c.verb for c in res.ancestor_calls] == ["query"], (
        "an unresolvable shell alert did not fall back to the batched _id fetch: "
        f"{[c.verb for c in res.rec.calls]}"
    )
    assert "anc-1" in res.ancestor_calls[0].params["native_query"]
    assert "Accepted password for dev.dana" in res.section(), \
        "the ancestors were dropped because the shell alert could not be found"


def test_a_shell_fetch_that_raises_falls_through_to_the_ancestor_branch(tmp_path):
    """R2-F6 — a shell fetch that RAISES is not evidence the alert has no ancestors, so item 1
    continues into the ancestor branch: the batched `_id` fetch over `ancestor_events`, which
    is read off the alert itself and needs no shell document. The ancestors still reach MAIN.

    ON EVERY FAULT CLASS. The first cut of this demand drove a confinement refusal only, and
    the infra arm was answered by `d61`'s cap asserting a call count — so what shipped fell
    through for non-budget-consuming faults and stopped for the others. Nobody decided that
    split and nothing recorded it; it emerged from two demands meeting, which is the second
    time this run a pair of separately-sound resolutions composed into something neither said.
    §7 round 5 removed it: the cap bounds RECORDED FAILURES, not calls, so fall-through and the
    cap hold together — item 1 still issues the branch call and still cannot trip the breaker.

    `d58` decided the resolves-nothing arm and `d59` the no-usable-`alert_id` arm. Both fault
    classes are driven here, and the ledger supplies the difference between them rather than
    this suite: a confinement refusal carries an exit code outside `INFRA_EXIT_CODES = {2, 124}`
    so `record_outcome` writes no state at all, while a transport fault is infra-class and
    records one (g10/E2, executed). The fall-through is identical across both; only the breaker
    bookkeeping differs, and `d61` owns that."""
    for label, fault, breaker_expected in (
        ("confinement", ConfinementFault("index 'nope-*' falls outside the configured patterns"), 0),
        ("infra", TransportFault("docker exec failed"), 1),
    ):
        res = run(tmp_path / label, run_id=f"lz808-shellraise-{label}", shell=fault,
                  answer=answer_hits([hit(ts="2026-05-25T15:22:00.000Z",
                                          message="Accepted password for dev.dana")]))

        assert [c.verb for c in res.rec.calls] == ["alerts", "query"], (
            f"[{label}] a raising shell fetch ended item 1 instead of falling through to the "
            f"ancestor branch: {[c.verb for c in res.rec.calls]} — fall-through is not "
            "conditional on the fault class, and a transport blip is the likeliest one"
        )
        assert "anc-1" in res.rec.calls[1].params["native_query"]
        assert "Accepted password for dev.dana" in res.section(), (
            f"[{label}] one failed call cost MAIN the ancestor evidence ancestor_events "
            "could still supply"
        )
        recorded = res.breaker.get("systems", {}).get("elastic", {}).get("failures", 0)
        assert recorded == breaker_expected, (
            f"[{label}] the run recorded {recorded} elastic failures, not {breaker_expected} — "
            "the exit-code partition is the adapter's and the breaker's, not this suite's"
        )


def test_a_shell_fetch_that_answers_does_not_stand_in_for_the_ancestor_calls(tmp_path):
    """#880 F-14 — the resolution's success flag counts only calls that COULD have produced an
    ancestor. The shell fetch is not one of them: it resolves the alert's own document, it
    answers on every alert with a resolvable `alert_id`, and it used to set the same flag both
    empty-body readers spend — the `_(unavailable: … found nothing)` sentence and the only path
    to `STATUS_FAILED`. Once it answered, no fault on the ancestor calls could be reported: an
    absence of ancestors, which is triage evidence, was asserted over a backend outage.

    THE SPLIT IS THE POINT, so it is driven at the seam the old suite could not reach. The
    shipped FAILED arm (`test_808_lead_zero_contract.py`) faults EVERY call through
    `answer_raising`, shell included, so a flag set from any call and a flag set only from the
    ancestor calls are indistinguishable there — the defect shipped with that arm green. Here
    the shell fetch ANSWERS and only the ancestor branch faults, and the run dir shows both
    halves: row `seq 0` is the shell fetch at `exit_code 0`, row `seq 1` the faulted batched
    query at a nonzero code. Every classification in that table is production's — the fake
    raises the adapter's own `TransportFault` and maps nothing.

    Read at `resolve_lead_zero`'s own return rather than off the block, because the status is
    the half no rendered text can carry and `prepare_correlation_lead` refuses FAILED and EMPTY
    alike (so no dispatch decision distinguishes them either).

    FOUR ARMS, ASSERTED AGAINST EACH OTHER. An ancestor call that faults is FAILED; one that
    answers and matches nothing is EMPTY; an alert with no usable ancestor to ask about stays
    EMPTY, because a resolution that issued no ancestor call has no failed call to report — and
    that same "no ancestor call issued" shape with the SHELL FETCH FAILING is FAILED, because
    the group id that decides whether an ancestor branch exists at all is read off the shell
    document. Splitting the flag WITHOUT the fourth arm turns the likeliest real outage — a
    transport blip on an alert carrying no usable `ancestor_events` — into
    `_(unavailable: … found nothing)`, reintroducing this finding's own defect through the
    branch it did not name."""
    from defender.runtime import lead_zero

    def _resolve(name, alert=None, **kw):
        """One arm in its OWN run dir — the shared-run-dir starvation
        `test_lead_zero_returns_section_text_entities_and_status` documents applies here too: these
        arms carry identical shell predicates."""
        run_dir = materialize_alert(tmp_path / name, alert if alert is not None else alert_doc())
        rec = VerbRecorder()
        result = lead_zero.resolve_lead_zero(
            run_dir=run_dir, defender_dir=defender_dir(),
            alert_path=run_dir / "alert.json", salt=SALT,
            verbs=elastic_backend(rec, **kw),
        )
        return result, rec, run_dir

    faulted, rec, run_dir = _resolve(
        "ancestor_fault", answer=answer_raising(TransportFault("docker exec failed")))

    assert [c.verb for c in rec.calls] == ["alerts", "query"], (
        f"the scenario never reached the split it is about: {[c.verb for c in rec.calls]} — "
        "the shell fetch must ANSWER and the ancestor call must fault"
    )
    rows = read_jsonl_rows(RunPaths(run_dir).executed_queries)
    assert len(rows) == 2, f"the two calls did not both record a row: {rows}"
    shell_row, ancestor_row = rows
    assert shell_row["exit_code"] == 0, \
        f"the shell fetch did not succeed, so this arm proves nothing: {shell_row}"
    assert ancestor_row["exit_code"] != 0, \
        f"the ancestor call did not fault, so this arm proves nothing: {ancestor_row}"

    assert faulted.status == lead_zero.STATUS_FAILED, (
        f"the resolution reports {faulted.status!r} while every call that could have produced "
        "an ancestor faulted — the shell fetch's own success is being spent as theirs, and "
        "STATUS_FAILED is unreachable on any alert whose alert_id resolves"
    )
    assert ANCESTOR_CALLS_FAILED in faulted.text, \
        f"the failed resolution carries no failed-call note: {faulted.text!r}"
    assert RESOLVED_ABSENCE not in faulted.text, (
        "MAIN is told this alert HAS no ancestors while the calls that would have found them "
        "never answered — an absence is triage evidence and this one was never established"
    )

    # Complementary condition #1: the same shape with the ancestor call ANSWERING empty. The
    # resolved absence is real here, and it must still read as one.
    empty, empty_rec, _ = _resolve("ancestor_empty", answer=answer_hits([]))
    assert [c.verb for c in empty_rec.calls] == ["alerts", "query"]
    assert empty.status == lead_zero.STATUS_EMPTY, \
        "a resolution whose ancestor call answered and matched nothing now reads as a failure"
    assert RESOLVED_ABSENCE in empty.text
    assert ANCESTOR_CALLS_FAILED not in empty.text

    # Complementary condition #2: no ancestor call was ISSUED at all (K13's degenerate
    # predicate) and the shell fetch answered. Nothing failed, so nothing is reported failed.
    none_asked, none_rec, _ = _resolve(
        "no_ancestor_call", alert=alert_doc(ancestors=[ancestor("")]),
        answer=answer_hits([hit(ts="2026-05-25T15:22:00.000Z")]))
    assert [c.verb for c in none_rec.calls] == ["alerts"], \
        "an ancestor call was issued with no usable id — this arm is not about that"
    assert none_asked.status == lead_zero.STATUS_EMPTY, (
        "an alert with nothing to ask about reports a FAILED resolution — the flag now means "
        "'an ancestor call answered' but the reader that spends it forgot that no ancestor "
        "call was made"
    )
    assert RESOLVED_ABSENCE in none_asked.text
    assert ANCESTOR_CALLS_FAILED not in none_asked.text

    # Complementary condition #3 — THE ARM THAT SPLITTING THE FLAG BREAKS IF `answered_any` IS
    # NOT TRACKED BESIDE IT. Same "no ancestor call was issued" shape as #2, but the shell
    # fetch FAILED instead of answering. "No ancestor call to report as failed" is true and
    # irrelevant: the group id that decides whether an ancestor branch exists at all is read
    # off the shell document, so a shell fetch that never answered leaves the branch
    # unreachable rather than empty. A resolution that establishes nothing must not report a
    # resolved absence — which is the whole of F-14, arriving through the other door.
    shell_only, shell_rec, _ = _resolve(
        "shell_only_fault", alert=alert_doc(ancestors=[]), answer=answer_hits([]),
        shell=TransportFault("docker exec failed"))
    assert [c.verb for c in shell_rec.calls] == ["alerts"], \
        f"this arm is about the shell fetch being the ONLY call: {[c.verb for c in shell_rec.calls]}"
    assert shell_only.status == lead_zero.STATUS_FAILED, (
        "the resolution's only backend call failed and it reports "
        f"{shell_only.status!r} — an alert with nothing left to ask about because the answer "
        "that would have said what to ask never came is not an alert with nothing to ask"
    )
    assert RESOLVED_ABSENCE not in shell_only.text, (
        "MAIN is told this alert HAS no ancestors on the strength of a call that faulted — "
        "the same false absence the ancestor-call arm above rules out"
    )
    assert SHELL_ONLY_FAILED in shell_only.text, \
        f"the failed resolution carries no failed-call note: {shell_only.text!r}"


def test_item_one_stops_at_one_recorded_per_system_failure(tmp_path):
    """K8(ii) / R2-F1, amended by §7 round 5 — lead-0 tracks its OWN contribution to the
    elastic per-system breaker and stops CONTRIBUTING after one recorded failure. It never
    leaves the breaker tripped before MAIN's first prompt, because a tripped elastic hands
    every later gather lead `down_message` instead of data in a run whose whole purpose is
    gathering elastic evidence.

    THE CAP BOUNDS RECORDED FAILURES, NOT CALLS. That is the amendment, and it is what lets
    this demand and `d63` both hold: item 1 still issues its remaining calls — fall-through is
    unconditional — and simply stops feeding the per-system counter. An implementation that
    suppresses the CALL instead satisfies the counter and fails this demand, because it throws
    away the evidence `d63` exists to preserve. Each arm below therefore asserts BOTH: the
    calls that were issued, and the contribution that was recorded.

    THE ARITHMETIC IS RE-DERIVED, NOT ENCODED. This demand was first written as a clause
    asserting the cap held by side effect ("the breaker SCREEN runs ahead of the second call"),
    inherited from a verifier's recommendation and never re-checked: `is_tripped` returns
    `failures >= PER_SYSTEM_FAIL_LIMIT`, so after ONE failure the screen PASSES and the second
    call executes. The guard below asserts the constant and drives the real primitive across
    the trip boundary before this demand's own observables are touched.

    THREE ARMS, because F1 gave item 1 three shapes and a cap discharged on one of them reads
    as a cap. Arm A puts the fault on CALL 0 (the shell fetch) — the arm `d13` cannot reach,
    since `d13` passes no `shell=` and its fault first bites on the branch call. Arms B and C
    put two failing calls in the BRANCH, which is where two recorded failures are reachable
    without the shell failing at all: an implementation that stops when the shell fails passes
    arm A alone and still trips elastic on `d5`'s own four-ancestor two-backing-index shape."""
    from defender.runtime import circuit_breaker

    assert circuit_breaker.PER_SYSTEM_FAIL_LIMIT == 2, (
        "the per-system limit moved; re-derive this demand's arithmetic before trusting it — "
        "encoding a number a previous pass asserted is how this demand was wrong the first time"
    )
    probe_dir = tmp_path / "probe"
    probe_dir.mkdir()
    circuit_breaker.record_outcome(probe_dir, "elastic", 2)
    assert not circuit_breaker.is_tripped(probe_dir, "elastic"), \
        "one infra failure now trips the breaker — the cap below is arguing about the wrong number"
    circuit_breaker.record_outcome(probe_dir, "elastic", 2)
    assert circuit_breaker.is_tripped(probe_dir, "elastic"), \
        "two infra failures no longer trip elastic; re-derive before relying on the cap"

    down = TransportFault("docker exec failed")

    def _capped(res, label):
        failures = res.breaker.get("systems", {}).get("elastic", {}).get("failures", 0)
        assert failures <= 1, (
            f"[{label}] item 1 recorded {failures} elastic failures before MAIN's first "
            f"prompt — at {circuit_breaker.PER_SYSTEM_FAIL_LIMIT} the breaker trips and every "
            "later elastic lead in this run gets down_message instead of data"
        )
        assert not circuit_breaker.is_tripped(res.run_dir, "elastic"), \
            f"[{label}] lead-0 tripped the elastic breaker before the investigation began"
        assert UNAVAILABLE in res.section(), \
            f"[{label}] the failed slots were dropped silently rather than degrading"
        assert res.main.calls >= 1, f"[{label}] the cap ended the run instead of degrading it"

    # ARM A — the fault lands on CALL 0. The branch call is still issued: the cap suppresses
    # the RECORDING, never the attempt, which is the whole of R2-F6's fall-through.
    arm_a = run(tmp_path / "shell", run_id="lz808-cap-shell",
                shell=down, answer=answer_raising(down))
    assert [c.verb for c in arm_a.rec.calls] == ["alerts", "query"], (
        "item 1 stopped calling after its first recorded failure: "
        f"{[c.verb for c in arm_a.rec.calls]} — the cap bounds what is RECORDED, and "
        "suppressing the call instead discards the ancestor evidence d63 preserves"
    )
    _capped(arm_a, "shell-fault")

    # ARM B — two failing BRANCH calls, from K3's general rule with no group anywhere. `d5`
    # requires one call per distinct mapped backing index, so this shape issues two of them
    # and both fail; the shell fetch succeeds, so nothing about arm A applies.
    arm_b = run(tmp_path / "multi", run_id="lz808-cap-multi",
                alert=alert_doc(ancestors=[
                    ancestor("auth-1", AUTH_BACKING), ancestor("auth-2", AUTH_BACKING),
                    ancestor("falco-1", FALCO_BACKING), ancestor("falco-2", FALCO_BACKING)]),
                answer=answer_raising(down))
    assert len(arm_b.rec.calls) == 3, (
        f"the multi-index branch issued {len(arm_b.rec.calls) - 1} of its two per-index calls "
        "— the cap must bound the contribution, not cancel the second index's fetch"
    )
    _capped(arm_b, "multi-index")

    # ARM C — the group-then-fallback shape, both branch calls failing. WHICH calls those are,
    # and in what order, is not this demand's to say: `d55` pins the fallback on a group that
    # returns ZERO BLOCKS, not on one that faults, so asserting a verb sequence here would
    # invent a rule `d61` does not own. A COUNT FLOOR says the thing the cap needs said without
    # inventing it — an implementation that stops after its first branch fault records one
    # failure and passes a cap-only assertion, which is not the cap holding, it is the cap
    # never being reached.
    arm_c = run(tmp_path / "group", run_id="lz808-cap-group",
                alert=alert_doc(ancestors=FOUR_ANCESTORS), shell=SEQUENCE_SHELL,
                answer=answer_raising(down))
    assert len(arm_c.rec.calls) >= 3, (
        f"the group-then-fallback shape issued {len(arm_c.rec.calls)} calls — item 1 stopped "
        "after its first failed branch call, so the cap was never under test on this arm and "
        "an implementation that gives up early passes it for the wrong reason"
    )
    _capped(arm_c, "group-then-fallback")


def test_an_alert_id_that_is_not_a_document_id_issues_no_shell_fetch(tmp_path):
    """K5/K13 (NEGATIVE) — when the alert carries no usable `alert_id`, item 1 issues NO shell
    fetch at all: no call, no queries row, no payload. It does not send a degenerate predicate
    and read `group.id` off whatever comes back.

    This is K13's mechanism at its second site, and the same executed probe covers it: P1a
    shows an empty or whitespace-only predicate falls through to `must=[{"match_all":{}}]` and
    returns the confined pattern's NEWEST 20 DOCUMENTS, raising nothing. At the ancestor
    predicate that renders 20 unrelated documents as this alert's ancestors; at the `alert_id`
    predicate it is worse, because `group.id` would then be read off a stranger's document and
    every later branch would follow it.

    Item 1 continues to the branch it can still take — the batched `_id` fetch over
    `ancestor_events`, which needs no `alert_id`. The paired POSITIVE CONTROL on the same
    address under the complementary condition is
    `test_item_one_fetches_the_shell_alert_by_alert_id_against_its_own_signal_index`."""
    res = run(tmp_path, run_id="lz808-badid", alert=alert_doc(alert_id="   "),
              shell=shell_doc(group_id="SOMEONE ELSES GROUP"),
              answer=answer_hits([hit(ts="2026-05-25T15:22:00.000Z",
                                      message="Accepted password for dev.dana")]))

    verbs = [c.verb for c in res.rec.calls]
    assert verbs == ["query"], (
        f"a shell fetch was issued with no usable alert_id: {verbs} — and `match_all` would "
        "have answered it with the newest 20 documents of the confined pattern (P1a)"
    )
    assert "SOMEONE ELSES GROUP" not in res.message_zero, \
        "a group id read off a document no alert_id asked for reached MAIN"
    assert len(res.rows_for(L0)) == 1, \
        "a queries row records a shell fetch that must not have happened"
    assert "Accepted password for dev.dana" in res.section(), \
        "the refused shell fetch took the ancestors with it"


# --------------------------------------------------------------------------------------- #
# Call 2 — the branch
# --------------------------------------------------------------------------------------- #

def test_group_id_present_fetches_building_blocks_from_the_alerts_own_signal_index(tmp_path):
    """d2 — when the shell document carries `kibana.alert.group.id`, item 1's SECOND call
    fetches the sequence's building-block alerts, group-scoped, through the `alerts` verb
    against the same index the alert declares (`signal_index`), and reaches no `logs-*` index
    at all. Two calls, and the `.ds-` → datastream mapping is the FALLBACK, never this path.

    The group id arrives on the shell document, not on `alert.json`: no checked-in alert
    carries one (c5/r5, executed) and nothing under `defender/` projects the run-dir alert
    (g17), so `alert_group_id.domain.distinguished[grp-0]` is pinned on the response the shell
    fetch returns. `signal_index` is set to a value that DIVERGES from the config constant,
    because all five fixtures carry them identical and no fixture can otherwise tell K16's two
    readings apart."""
    own_index = ".internal.alerts-security.alerts-default-000001"
    assert confine_index(own_index, PATTERNS) == own_index, \
        "the fixture's own signal_index is not one the shipped gate accepts — the scenario " \
        "would be testing the gate, not the reading"

    res = run(tmp_path, run_id="lz808-primary",
              alert=alert_doc(signal_index=own_index), shell=SEQUENCE_SHELL,
              answer=answer_hits([building_block(ts="2026-05-25T15:22:00.000Z", group_index=0)]))

    assert [c.verb for c in res.rec.calls] == ["alerts", "alerts"], (
        "the sequence path is not the shell fetch followed by one group-scoped fetch: "
        f"{[c.verb for c in res.rec.calls]}"
    )
    params = res.ancestor_calls[0].params
    assert params["index"] == own_index, \
        "the building-block fetch reached the configured constant, not the index this alert " \
        "says it came from"
    assert "grp-0" in params["native_query"], "the fetch is not scoped to the alert's group"
    assert EVENTS_INDEX not in str(params), "the primary path reached a telemetry index"


def test_no_group_falls_back_to_batched_id_fetch(tmp_path):
    """d4 — when the shell document carries no `kibana.alert.group.id`, item 1's SECOND call
    is one batched `_id` fetch through the `query` verb, naming every ancestor id from
    `ancestor_events[]` in a single predicate, against the datastream pattern derived from
    that entry's backing index. Two calls, never one per ancestor.

    This is the state of every checked-in fixture: the absent-group member is what all five
    carry and what the tree's only projector emits (c5/r5, executed)."""
    res = run(tmp_path, run_id="lz808-fallback",
              alert=alert_doc(ancestors=FOUR_ANCESTORS),
              answer=answer_hits([hit(ts=f"2026-05-25T15:2{i}:00.000Z") for i in range(4)]))

    assert [c.verb for c in res.rec.calls] == ["alerts", "query"], (
        "the fallback is not the shell fetch followed by one batched _id fetch: "
        f"{[c.verb for c in res.rec.calls]}"
    )
    predicate = res.ancestor_calls[0].params["native_query"]
    for entry in FOUR_ANCESTORS:
        assert entry["id"] in predicate, f"{entry['id']} was dropped from the batched predicate"


def test_one_backend_call_per_distinct_backing_index_never_one_per_ancestor(tmp_path):
    """d5 — past the shell fetch, item 1 makes ONE call per distinct mapped backing index,
    never one per ancestor: four ancestors spanning two backing indices is two ancestor calls
    (three in total), and each call's predicate carries only the ids that live in that index.

    Carried as the design's own sentence ("one backend call regardless of ancestor count") and
    KNOWN FALSE AS WRITTEN: c4 (executed) shows `confine_index` refuses a comma-joined
    multi-index expression WHOLE — it never silently narrows to the in-bounds part — so a
    single call structurally cannot address two backing indices."""
    ancestors = [
        ancestor("auth-1", AUTH_BACKING), ancestor("auth-2", AUTH_BACKING),
        ancestor("falco-1", FALCO_BACKING), ancestor("falco-2", FALCO_BACKING),
    ]
    res = run(tmp_path, run_id="lz808-two-index",
              alert=alert_doc(ancestors=ancestors),
              answer=answer_hits([hit(ts="2026-05-25T15:22:00.000Z")]))

    calls = res.ancestor_calls
    assert len(calls) == 2, (
        f"four ancestors over two backing indices produced {len(calls)} ancestor calls, not "
        "two — one per distinct mapped backing index, never one per ancestor"
    )
    for call in calls:
        assert "," not in call.params["index"], \
            "a comma-joined multi-index expression is refused WHOLE by confine_index (c4) — " \
            "this call reaches nothing at all"
    per_index = {c.params["index"]: c.params["native_query"] for c in calls}
    auth_pred = next(p for i, p in per_index.items() if "auth" in i)
    falco_pred = next(p for i, p in per_index.items() if "falco" in i)
    assert "auth-1" in auth_pred
    assert "auth-2" in auth_pred
    assert "falco-1" not in auth_pred, \
        "an ancestor's id was sent to an index the document does not live in"
    assert "falco-1" in falco_pred
    assert "falco-2" in falco_pred


def test_a_group_that_resolves_to_no_building_blocks_falls_back(tmp_path):
    """F10/K5 — the fallback fires on "no group OR no building blocks": a `group.id` that
    resolves to zero building blocks is not a resolved sequence, so item 1 continues to the
    batched `_id` fetch rather than reporting an empty ancestor set.

    This is the ONE arm on which item 1 exceeds "at most two backend calls" — shell,
    group-scoped, fallback — because "at most two" was stated in `45-dispositions.md` before
    the shell fetch was added to the front of the sequence. The sequence is asserted here, not
    a global cap, and 80-author-digest.md red-flags the arithmetic rather than quietly picking
    one of the two §7 sentences over the other.

    The design's own sentence is a pure presence check ("No group → fall back") and says
    nothing about a group that returns nothing; leaving it there makes an empty sequence
    indistinguishable from an alert with no ancestors at all."""
    res = run(tmp_path, run_id="lz808-empty-group",
              alert=alert_doc(ancestors=FOUR_ANCESTORS), shell=SEQUENCE_SHELL,
              answer=answer_sequence(
                  envelope([], index=ALERTS_INDEX),
                  envelope([hit(ts="2026-05-25T15:22:00.000Z")]),
              ))

    assert [c.verb for c in res.rec.calls] == ["alerts", "alerts", "query"], (
        "a group with no building blocks did not fall back: "
        f"{[c.verb for c in res.rec.calls]}"
    )
    assert "anc-1" in res.ancestor_calls[1].params["native_query"]


def test_the_group_scoped_fetch_filters_the_shell_alert_out_of_its_own_result(tmp_path):
    """K22 — the shell alert and its building blocks share `group.id` (c2), so the
    group-scoped fetch returns BOTH. Item 1 filters on the building-block stamp c2 also names,
    because `_raw_alert` already inlines the shell alert in the same message: rendering it
    again both duplicates message 0's own content and miscounts the constituent events.

    The complementary condition is in the same scenario: the two STAMPED documents survive the
    same filter that removes the unstamped one."""
    echoed_shell = shell_doc(group_id="grp-0", message="THE SHELL ALERT ITSELF")
    res = run(tmp_path, run_id="lz808-shellfilter",
              alert=alert_doc(ancestors=[ancestor("a"), ancestor("b")]), shell=SEQUENCE_SHELL,
              answer=answer_hits([
                  echoed_shell,
                  building_block(ts="2026-05-25T15:22:00.000Z", group_index=0,
                                 message="Failed password for dev.dana"),
                  building_block(ts="2026-05-25T15:26:00.000Z", group_index=1,
                                 message="Accepted password for dev.dana"),
              ]))

    section = res.section()
    assert "THE SHELL ALERT ITSELF" not in section, \
        "the alert under investigation is rendered inside its own ancestor block"
    assert "Failed password for dev.dana" in section, "the filter took the evidence with it"
    assert "Accepted password for dev.dana" in section


# --------------------------------------------------------------------------------------- #
# The `.ds-` → datastream mapping (K2)
# --------------------------------------------------------------------------------------- #

def test_ds_backing_index_maps_to_a_confined_datastream_pattern(tmp_path):
    """d6 — a concrete `.ds-logs-falco.alerts-default-2026.04.30-000003` backing index is
    rewritten to the datastream pattern derived from its own `.ds-<name>-<namespace>-<date>-
    <generation>` shape, and the DERIVED pattern is one the shipped `confine_index` accepts.
    Never a bare `logs-*`: the rewrite is a widening transformation applied to external input
    UPSTREAM of the only index-confinement gate.

    The falco value is a shipped fixture and the rejected form's counterexample: r7 (executed)
    shows `project_alert.py`'s `"system.auth" in index` substring test leaves it unmapped and
    `confine_index` then REFUSES it — the mapping must be a general rule, not a special case.

    The derived pattern is checked through the REAL gate in the test, so the taxonomy
    assumption is re-probed on every run rather than pinned once."""
    res = run(tmp_path, run_id="lz808-falco",
              alert=alert_doc(ancestors=[ancestor("falco-1", FALCO_BACKING)]),
              answer=answer_hits([hit(ts="2026-05-25T15:03:00.000Z", message="falco alert")]))

    assert res.ancestor_calls, "no ancestor fetch was issued, so nothing was mapped"
    sent = res.ancestor_calls[0].params["index"]
    assert sent != FALCO_BACKING, "the concrete backing index went to the gate unmapped"
    assert sent != EVENTS_INDEX, \
        "the mapping widened to a bare logs-* — a pattern the document need not live in"
    assert confine_index(sent, PATTERNS) == sent, \
        f"the derived pattern {sent!r} is refused by the shipped confinement gate"
    assert sent.startswith("logs-falco.alerts"), \
        f"the derived pattern {sent!r} does not name this document's own datastream"


def test_the_system_auth_backing_index_maps_by_the_same_general_rule(tmp_path):
    """R4 `ancestor_events.domain.distinguished[.ds-logs-system.auth-default-2026.05.24-000002]`
    — the OTHER concrete backing index across the five checked-in fixtures (g7) maps by the
    same general derivation, with no per-integration entry of its own. Per-cell discharge is
    exact-match by design, and a mapping that needs a second entry to cover the second shipped
    fixture is the closed table `d6`'s `rejected:` clause forbids."""
    res = run(tmp_path, run_id="lz808-auth",
              alert=alert_doc(ancestors=[ancestor("auth-1", AUTH_BACKING)]),
              answer=answer_hits([hit(ts="2026-05-25T15:22:00.000Z")]))

    assert res.ancestor_calls, "no ancestor fetch was issued, so nothing was mapped"
    sent = res.ancestor_calls[0].params["index"]
    assert sent == "logs-system.auth-*", \
        f"{sent!r} is not the datastream pattern this backing index derives to"
    assert confine_index(sent, PATTERNS) == sent


def test_an_unmapped_backing_index_passes_through_unchanged_and_is_refused(tmp_path):
    """K2's no-match arm — when even the general rule cannot map a backing index, the string
    is passed through UNCHANGED so `confine_index` refuses it and that ancestor's slot renders
    unavailable. It is never silently widened to a pattern the document does not live in.

    The refusal is re-probed here through the REAL gate rather than asserted: pass-through is
    only a safe answer if the gate really does refuse what was passed through."""
    weird = "not-a-datastream-backing-index"
    res = run(tmp_path, run_id="lz808-unmapped",
              alert=alert_doc(ancestors=[ancestor("x", weird)]), answer=answer_hits([]))

    if res.ancestor_calls:
        sent = res.ancestor_calls[0].params["index"]
        assert sent == weird, \
            f"an unmappable backing index was rewritten to {sent!r} — a widening the gate " \
            "would then have accepted on the document's behalf"
    with pytest.raises(ConfinementFault):
        confine_index(weird, PATTERNS)
    assert UNAVAILABLE in res.section(), \
        "the unmappable ancestor's slot does not say the resolution was unavailable"


def test_an_ancestor_with_no_backing_index_degrades_that_slot_only(tmp_path):
    """R4 `ancestor_events.domain.distinguished[""]` — an ancestor entry whose `index` is
    missing or empty degrades that entry alone: the ancestors that DO carry a usable backing
    index still resolve and still render, and the block says the set is incomplete rather than
    reporting a smaller set as complete.

    `confine_index` raises on an empty or non-string index before the pattern check, so the
    inherited gate supplies the fault — but only if the empty value is never batched into a
    predicate alongside good ones, which is what makes this a per-entry observable."""
    res = run(tmp_path, run_id="lz808-noindex",
              alert=alert_doc(ancestors=[ancestor("good-1"), ancestor("bad-1", "")]),
              answer=answer_hits([hit(ts="2026-05-25T15:22:00.000Z", message="the good one")]))

    assert len(res.ancestor_calls) == 1, \
        "the empty backing index became a call of its own, or was batched into a good one"
    assert "good-1" in res.ancestor_calls[0].params["native_query"]
    assert "the good one" in res.section(), "one bad entry cost the block every ancestor"
    assert SHORTFALL in res.section(), \
        "one ancestor of two resolved and the block reports the set as complete"


def test_an_absent_signal_index_falls_back_to_the_configured_alerts_index(tmp_path):
    """R4 `signal_index.domain.distinguished[""]` — an alert with no `signal_index` field
    falls back to the `ELASTIC_ALERTS_INDEX` config constant for its shell fetch. The falsy
    member is well-defined and un-forked; it just needs pinning, because K16 makes the alert's
    own value the PRIMARY reading and a fallback nothing exercises is a fallback nobody has
    run."""
    res = run(tmp_path, run_id="lz808-nosignal", alert=alert_doc(signal_index=None),
              answer=answer_hits([hit(ts="2026-05-25T15:22:00.000Z")]))

    assert res.shell_call.params["index"] == ALERTS_INDEX, \
        "an alert with no signal_index did not fall back to the configured alerts pattern"


# --------------------------------------------------------------------------------------- #
# Rendering
# --------------------------------------------------------------------------------------- #

def test_resolved_ancestors_render_chronologically_on_both_paths(tmp_path):
    """d3/K4 — resolved ancestors are presented CHRONOLOGICALLY, sorted CLIENT-SIDE, on both
    the primary and the fallback path. The issue's whole discriminator is an ordering — three
    failures, then the success — and the adapter's default is newest-first, so echoing the
    backend's order renders the motivating narrative backwards.

    Client-side because the adapter CANNOT be asked for it: `resolve_sort` admits exactly
    `('desc','asc')` and raises `UpstreamFault` on anything else, and `_build_search_body`
    hardcodes the `@timestamp` time field (r3/a1, executed). `kibana.alert.group.index` is
    therefore unusable as a sort key at the backend, which is what makes this a client-side
    obligation rather than a parameter.

    Both paths, in one scenario: the fallback drives the same newest-first response the
    primary does, and both must come out oldest-first."""
    fallback = run(tmp_path / "fb", run_id="lz808-order-fb",
                   alert=alert_doc(ancestors=[ancestor(f"a{i}") for i in range(3)]),
                   answer=answer_hits(NEWEST_FIRST))
    positions = _order(fallback.section(), "Failed password", "Accepted password")
    assert positions[0] < positions[1], \
        "the fallback rendered the backend's newest-first order — the success is shown " \
        "before the failures that preceded it"

    primary = run(tmp_path / "pr", run_id="lz808-order-pr", shell=SEQUENCE_SHELL,
                  answer=answer_hits([
                      building_block(ts="2026-05-25T15:26:00.000Z", group_index=1,
                                     message="Accepted password"),
                      building_block(ts="2026-05-25T15:22:00.000Z", group_index=0,
                                     message="Failed password"),
                  ]))
    positions = _order(primary.section(), "Failed password", "Accepted password")
    assert positions[0] < positions[1], \
        "the primary path rendered the backend's order rather than sorting client-side"


def test_resolved_ancestor_docs_carry_timestamp_message_and_structured_fields(tmp_path):
    """d7 — each resolved ancestor renders with its timestamp, its `message`, and the
    structured fields the integration extracted, per document. This is also the POSITIVE
    CONTROL for `d24`: the documents the block DOES carry, against the rule's join keys it
    must not assert anything about.

    Written per-document over `_source` fields only, because P1c (executed) settles that
    `_search` keeps ONLY `_source` per hit — `_id` and `_index` never leave the adapter — so a
    missing ancestor is detectable by COUNT and never by name, and no all-or-nothing rule
    applies: each document renders whatever subset of fields it carries."""
    docs = [
        hit(ts="2026-05-25T15:22:00.000Z", message="Failed password for dev.dana",
            host="office-ws-1", user="dev.dana", ip="172.18.0.15"),
        hit(ts="2026-05-25T15:26:00.000Z", message="Accepted password for svc.config-mgmt",
            host="db-1", user="svc.config-mgmt", ip="172.18.0.4"),
    ]
    del docs[1]["host.name"]      # a document missing a field its sibling carries
    res = run(tmp_path, run_id="lz808-fields", answer=answer_hits(docs))

    section = res.section()
    for needle in ("2026-05-25T15:22:00.000Z", "Failed password for dev.dana", "office-ws-1",
                   "dev.dana", "172.18.0.15", "2026-05-25T15:26:00.000Z",
                   "Accepted password for svc.config-mgmt", "svc.config-mgmt", "172.18.0.4"):
        assert needle in section, f"{needle!r} never reached MAIN"


def test_a_short_or_truncated_ancestor_fetch_carries_an_explicit_shortfall_note(tmp_path):
    """K3 — the block carries an explicit shortfall note whenever
    `returned < len(ancestor_events)` OR the envelope's `truncated` flag is set, and carries
    NO such note when the fetch was complete.

    Both arms matter and they are different faults. `RETURNED_DOC_CAP = 20` clamps silently
    and `truncated` is the ONLY thing that says a slice was taken (E3/P1a, executed:
    `limit=50` emits `size: 20`, and a 25-hit response comes back `returned=20, total=25,
    truncated=True`), so a sequence with more than 20 constituent events otherwise renders 20
    documents as if complete. After P1c the signal can only ever be a COUNT comparison, never
    a named missing ancestor."""
    short = run(tmp_path / "short", run_id="lz808-short",
                alert=alert_doc(ancestors=FOUR_ANCESTORS),
                answer=answer_hits([hit(ts="2026-05-25T15:22:00.000Z")], total=4))
    assert SHORTFALL in short.section(), \
        "one document came back for four ancestors and the block reports it as complete"
    assert "4" in short.section(), "the note does not say how many ancestors were asked for"

    truncated = run(tmp_path / "trunc", run_id="lz808-trunc",
                    alert=alert_doc(ancestors=FOUR_ANCESTORS),
                    answer=answer_hits([hit(ts=f"2026-05-25T15:2{i}:00.000Z")
                                        for i in range(4)], total=25, truncated=True))
    assert SHORTFALL in truncated.section(), \
        "the envelope's truncated flag was ignored — the clamp is silent again"

    complete = run(tmp_path / "ok", run_id="lz808-complete",
                   alert=alert_doc(ancestors=FOUR_ANCESTORS),
                   answer=answer_hits([hit(ts=f"2026-05-25T15:2{i}:00.000Z")
                                       for i in range(4)]))
    assert SHORTFALL not in complete.section(), \
        "a complete fetch carries a shortfall note — the note says nothing if it always fires"


def test_an_oversized_ancestor_message_is_elided_with_a_pointer_to_its_payload(tmp_path):
    """K17 — a per-document `message` over the block's rendering budget is elided with an
    explicit marker and a pointer to `gather_raw/l-000/{seq}.json`, where `d9` already
    requires the full payload to exist. `RETURNED_DOC_CAP` bounds the document COUNT, not
    their size, and the block now carries a mandated wrap and a mandated shortfall note but no
    bound at all.

    Asserted as a property rather than a magic number: the rendered block is materially
    smaller than the payload it points at, the elision is announced, and the pointer names a
    file that is really there.

    THE PATH IS RESOLVED, NOT PREFIX-MATCHED (#867 review fix). `f"gather_raw/{L0}/" in section`
    is green for every seq the implementation could print, and the implementation printed the
    DOCUMENT'S POSITION in the block rather than the seq of the call that returned it — which
    coincides at position 0 and at nothing else, so a single-document scenario could not see it.
    The second arm below drives four documents off one batched fetch: three of the four pointers
    named a file no writer ever produced, and the first named the SHELL fetch's payload — a
    different document. Every pointer the block prints is now opened."""
    import re

    huge = "A" * 200_000
    res = run(tmp_path, run_id="lz808-huge",
              answer=answer_hits([hit(ts="2026-05-25T15:22:00.000Z", message=huge)]))

    section = res.section()
    assert huge not in section, "a 200KB message field was inlined whole into message 0"
    assert len(section) < len(huge), "the block grew with the payload rather than bounding it"
    assert ELIDED in section, "the block was truncated with nothing saying so"
    assert f"gather_raw/{L0}/" in section, \
        "the elision points nowhere — the full payload is on disk and unreferenced"
    assert res.payloads(L0), "the pointer's target was never persisted"

    # FOUR documents off ONE batched fetch, so a pointer built from the document's own position
    # in the block and a pointer built from the call's queries-table seq are different numbers.
    many = run(tmp_path / "many", run_id="lz808-huge-many",
               alert=alert_doc(ancestors=[ancestor(f"a{i}") for i in range(4)]),
               answer=answer_hits([
                   hit(ts=f"2026-05-25T15:22:{10 + 10 * i}.000Z", message=huge, user=f"u{i}")
                   for i in range(4)
               ]))
    pointers = re.findall(rf"gather_raw/{L0}/(\d+)\.json", many.section())
    assert len(pointers) == 4, \
        f"four elided documents rendered {len(pointers)} payload pointers: {pointers}"
    for seq in pointers:
        assert (many.run_dir / "gather_raw" / L0 / f"{seq}.json").is_file(), (
            f"the elision points at gather_raw/{L0}/{seq}.json, which no call wrote — the "
            "pointer is built from the document's position in the block rather than from the "
            "seq of the fetch that returned it"
        )


def test_the_rendered_block_survives_a_failed_queries_table_write(tmp_path):
    """K8(iii) — item 1 RENDERS FROM ITS IN-MEMORY RESULT AND WRITES THE TABLES AFTER, so the
    run dir and the ORIENT text can never disagree about whether item 1 happened: a queries
    table that cannot be written costs the run its evidence row, not its evidence.

    Two thirds of K8's recommendation left no trace through two §7 rounds; this is the ordering
    half. The premise behind it is a promoted one —
    `test_orient_text_says_unavailable_while_the_run_dir_shows_a_completed_write` — whose own
    settled answer conceded that "no sentence states an ordering (write-then-render, or the
    reverse) that would prevent it".

    Ordering is only observable when one of the two steps fails, so the fault is REAL and made
    in the test with the real primitive: a directory squatting the queries table's own name,
    which no append can write through. What production does with that failure is production's;
    what this demand requires is that the rendered block still carries what was resolved.

    The complementary condition is the same scenario without the squat: the block carries the
    same content AND the row lands."""
    control = run(tmp_path / "ok", run_id="lz808-order-ok",
                  answer=answer_hits([hit(ts="2026-05-25T15:22:00.000Z",
                                          message="Accepted password for dev.dana")]))
    assert "Accepted password for dev.dana" in control.section()
    assert control.rows_for(L0), "the control run wrote no queries row at all"

    root = tmp_path / "squat"
    root.mkdir()
    try:
        res = run(root, run_id="lz808-order-fail",
                  answer=answer_hits([hit(ts="2026-05-25T15:22:00.000Z",
                                          message="Accepted password for dev.dana")]),
                  before=lambda run_dir: RunPaths(run_dir).executed_queries.mkdir(parents=True))
    except BaseException as exc:   # noqa: BLE001 — surfaced as this test's own assertion
        raise AssertionError(
            f"a queries-table write that cannot land ended the run: {exc!r} — item 1 wrote "
            "before it rendered, so the failure took the evidence with it"
        ) from exc

    assert "Accepted password for dev.dana" in res.section(), (
        "the block lost the ancestors it had already resolved because their row could not be "
        "written — the ORIENT text and the run dir now disagree in the other direction"
    )


# --------------------------------------------------------------------------------------- #
# K13 — the degenerate id predicate, and its positive control
# --------------------------------------------------------------------------------------- #

def test_no_usable_ancestor_identifier_issues_no_fetch_at_all(tmp_path):
    """K13 (NEGATIVE) — when no usable ancestor identifier survives, item 1 issues NO ancestor
    fetch: past the shell fetch no verb is called, no further queries row is written, no
    payload is persisted, no breaker budget is spent, and item 3 does not dispatch. The slot
    renders `_(unavailable: …)` and the resolution status is a resolved-empty state rather
    than a set of documents.

    THE HIGHEST-SEVERITY ITEM IN THE CHANGE, and it is execution-grounded rather than
    imagined: P1a (executed) shows an empty or whitespace-only predicate does not fail — it
    sends `must=[{"match_all":{}}]`, returns the confined pattern's NEWEST 20 DOCUMENTS with
    `truncated=True` on 25 hits, and raises nothing. Rendered under item 1's heading that is 20
    unrelated documents presented as this alert's ancestors — inside the
    `wrap(…, "untrusted", …)` frame K1 mandates, which frames them as untrusted evidence and
    not as WRONG evidence. Detecting it afterwards is impossible (`_id` is stripped, P1c) and
    the shortfall note demonstrably does not fire (20 returned against 4 requested never trips
    `returned < len(ancestor_events)`), so the refusal has to be structural.

    Every surface the fetch could reach is bound here, not just the obvious one; the paired
    positive control on the same address under the complementary condition is
    `test_usable_ancestor_identifiers_do_issue_the_batched_fetch`."""
    res = run(tmp_path, run_id="lz808-degenerate",
              alert=alert_doc(ancestors=[ancestor(""), ancestor("   "), {"type": "event",
                                                                        "index": AUTH_BACKING,
                                                                        "depth": 0}]),
              answer=answer_hits([hit(ts="2026-05-25T15:22:00.000Z",
                                      message="SOMEONE ELSE'S NEWEST DOCUMENT")]))

    assert res.ancestor_calls == [], (
        "an ancestor fetch was issued with no usable id: "
        f"{[c.params for c in res.ancestor_calls]}"
    )
    assert len(res.rows_for(L0)) == 1, \
        "a queries row records an ancestor call that must not have happened"
    assert len(res.payloads(L0)) <= 1, "a payload was persisted for a call that must not happen"
    assert not (res.run_dir / "circuit_breaker.json").is_file(), \
        "the refused fetch spent breaker budget"
    assert "SOMEONE ELSE'S NEWEST DOCUMENT" not in res.message_zero, \
        "documents no ancestor asked for reached MAIN under this alert's own heading"
    assert UNAVAILABLE in res.section()
    assert not res.has_sidecar(L3), \
        "item 3 dispatched off entities read from documents that answer no ancestor"


def test_usable_ancestor_identifiers_do_issue_the_batched_fetch(tmp_path):
    """K13's POSITIVE CONTROL — the same address under the complementary condition: with
    usable ancestor ids the fetch IS issued, the row IS written, the payload IS persisted and
    the documents DO reach MAIN. Proof that the refusal above is a decision and not a channel
    that never carried anything (`assert x not in out` is also green when `out` is empty)."""
    res = run(tmp_path, run_id="lz808-degenerate-control",
              alert=alert_doc(ancestors=[ancestor("anc-1"), ancestor("anc-2")]),
              answer=answer_hits([hit(ts="2026-05-25T15:22:00.000Z",
                                      message="A DOCUMENT AN ANCESTOR ASKED FOR")]))

    assert len(res.ancestor_calls) == 1
    assert "anc-1" in res.ancestor_calls[0].params["native_query"]
    assert res.rows_for(L0), "the ordinary batched fetch wrote no row"
    assert res.payloads(L0), "the ordinary batched fetch persisted no payload"
    assert "A DOCUMENT AN ANCESTOR ASKED FOR" in res.section()


def test_the_batched_predicate_never_reaches_a_second_backing_index(tmp_path):
    """R4 `alert_group_id.domain.distinguished[""]` — the absent-group member, bound at its
    own cell: when the shell document carries no group id the fallback is the only branch
    taken, and the predicate it builds is confined to the datastream the entries name. The
    distinguished value is the state of every checked-in fixture, so the cell the whole suite
    runs through is the one no demand named."""
    res = run(tmp_path, run_id="lz808-nogroup-cell",
              alert=alert_doc(ancestors=[ancestor("anc-1")]),
              answer=answer_by_index({"logs-system.auth-*": envelope(
                  [hit(ts="2026-05-25T15:22:00.000Z")], index="logs-system.auth-*")}))

    assert [c.verb for c in res.ancestor_calls] == ["query"]
    assert res.ancestor_calls[0].params["index"] == "logs-system.auth-*"
