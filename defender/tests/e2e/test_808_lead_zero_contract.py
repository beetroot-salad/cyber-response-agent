"""#808 — the entry point's contract: what lead-0 returns, when it runs, and what it takes.

Every test here is one demand of `spec-flow/specs/spec_graph_808.yaml`, named after its
`discharged_by` pointer and carrying that demand's observable-outcome prose in its docstring
(a `form: test` demand is a POINTER — `check_binds` scans the docstring in place of an
`outcome`).

THE CODE DOES NOT EXIST YET. `defender/runtime/lead_zero.py` is the module this spec mints;
this suite is RED by construction and that is the point — the tests are the contract the code
is written against.

THE SURFACE THIS FILE PINS (spell it exactly; a private synonym costs the check, not a config
entry — schema.md, "Coin ids from the code's name")
---------------------------------------------------------------------------------------------
`defender/runtime/lead_zero.py`
    `resolve_lead_zero(*, run_dir, defender_dir, alert_path, salt, verbs) -> LeadZeroResult`
        ONE ORIENT-time entry point, SYNCHRONOUS (r9/r10, executed: the verbs are plain sync
        functions and `orientation()` is `def … -> str`, so the await cannot live inside it).
        It takes the INJECTED registry because 62 of 95 `drive()` sites omit `verbs=` (g8) and
        a scenario that never asked for a backend must not acquire one (K12) — which means
        `orientation()` and `_user_prompt` gain that parameter, a new bound surface.
    `LeadZeroResult(text, status)`
        `text`   — item 1's rendered section, IN ITS ENTIRETY inside one
                   `wrap(text, "untrusted", salt)` frame, `_(unavailable: …)` notes and
                   shortfall notes included (K1). Since #867 this is ALSO item 3's entity
                   evidence: the correlation lead is handed this block and chooses its own
                   correlation axes off it.
        `status` — one of `STATUS_FAILED` / `STATUS_EMPTY` / `STATUS_TRUNCATED` /
                   `STATUS_RESOLVED`. `d22`'s gate is written against this VALUE because K13
                   makes the distinction load-bearing and P1b makes "empty" ambiguous at the
                   wire.

    THE THIRD FIELD IS RETIRED (#867). `entities` — `Entities(hosts, users, source_ips)`,
    deduplicated and deterministically sorted SETS — was a harness-side extraction of three
    fixed ECS fields. K9 was right that the bind had to be set-shaped rather than singular; the
    error was one level up, in fixing WHICH fields at all. Half the environment's detection
    rules fire on `logs-falco.alerts-*`, where that triple resolves to the shared VPS host and
    nothing else. `STATUS_WITH_ENTITIES` was renamed to `STATUS_RESOLVED` in the same change:
    it was computed from resolved document counts and never from an entity.
    `RESERVED_LEAD_IDS = ("l-000", "l-00c")`, `CORRELATION_REQUEST_LIMIT = 8` (F5/F6).

    IT DOES NOT NEVER-RAISE, and the restated `d0` says so: a fault inside an item renders
    `_(unavailable: …)` in that item's slot, but the QueryCapture path's `BudgetKill`,
    `RunAborted` and breaker-trip arms PROPAGATE (P3, executed: both arms stamp their
    terminator and re-raise, and a direct awaiter with no model in the loop sees it), and
    `_user_prompt` sits at driver.py:838 OUTSIDE every handler. Which of the two a given
    fault gets is part of the contract, not an accident of where the `try` happens to sit.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender.runtime import circuit_breaker  # noqa: E402
from defender.scripts.adapters.faults import TransportFault  # noqa: E402
from defender.tests.e2e._lead_zero_808 import (  # noqa: E402
    L0,
    L3,
    LEAD_ZERO_HEADING,
    UNAVAILABLE,
    Res,
    alert_doc,
    answer_hits,
    answer_raising,
    defender_dir,
    elastic_backend,
    hit,
    materialize_alert,
    run,
)
from defender.tests.e2e._replay_harness import ReplayFn, Turn, VerbRecorder  # noqa: E402

pytestmark = pytest.mark.e2e

TWO_ACTORS = [
    hit(ts="2026-05-25T15:26:10.000Z", user="dev.dana", ip="172.18.0.15", host="office-ws-1"),
    hit(ts="2026-05-25T15:26:50.000Z", user="svc.config-mgmt", ip="172.18.0.4", host="db-1"),
]
# The same two actors across FOUR documents: `dev.dana` three times, `office-ws-1` twice,
# `172.18.0.15` twice. A per-document bind yields four users; the resolved set-shaped bind
# yields two, which is what makes "deduplicated" an assertion rather than a word.
REPEATED_ACTORS = [
    TWO_ACTORS[0],
    hit(ts="2026-05-25T15:26:20.000Z", user="dev.dana", ip="172.18.0.15", host="office-ws-1"),
    hit(ts="2026-05-25T15:26:30.000Z", user="dev.dana", ip="172.18.0.4", host="db-1"),
    TWO_ACTORS[1],
]


def _lead_zero():
    """Imported INSIDE each test that needs the module, never at file scope: a module-level
    import of a module that does not exist yet turns every test in this file into one
    collection error, and `spec-graph nullstub` cannot tell a suite that discriminates from a
    file that is broken."""
    from defender.runtime import lead_zero

    return lead_zero


class _Watcher(ReplayFn):
    """A MAIN replay that snapshots the leads table at each request — the only honest way to
    observe "before MAIN's first model turn", which is an ORDERING, not a final state."""

    def __init__(self, turns: list[Turn], run_dir: Path):
        super().__init__(turns)
        self._root = run_dir / "gather_raw"
        self.leads_at_request: list[list[str]] = []

    def __call__(self, messages, info):
        self.leads_at_request.append(
            sorted(p.name for p in self._root.iterdir()) if self._root.is_dir() else []
        )
        return super().__call__(messages, info)


def test_lead_zero_returns_section_text_entities_and_status(tmp_path):
    """d0 — `resolve_lead_zero` returns ONE value carrying (a) `text`, item 1's rendered
    section entirely inside a single `wrap_fresh(text, "untrusted")` frame, and
    (b) a `status` distinguishing failed / succeeded-empty / succeeded-truncated /
    succeeded-resolved.

    THE SECOND COMPONENT IS GONE, and deliberately (#867). It was `entities` — the `host.name`
    / `user.name` / `source.ip` values read off the resolved ancestor documents as
    deduplicated, sorted sets — and the demand rested on the premise that a rendered `str`
    could not carry what `d17` binds. That premise was the defect. The triple fits the four
    detection rules that fire on `logs-system.auth-*` and measures nothing on the four that
    fire on `logs-falco.alerts-*`, where the only resolvable host is the shared VPS every
    containerized alert reports from. So item 3 now binds the RENDERED BLOCK itself and the
    correlation lead reads the documents and picks its own axes, which is what every other
    gather lead in this tree already does. Nothing typed replaced the field; `text` carries it.

    The status arm is unchanged in substance and renamed in one value: `succeeded-with-entities`
    was never computed from an entity and is now `succeeded-resolved`. It always meant "every
    requested ancestor document resolved", which is exactly what `d22`'s gate needs.

    Driven at the entry point because the return value is what every other demand reads its
    observable off: `d22`'s gate cannot tell "resolution failed" from "resolution found
    nothing" without the status.

    ALL FOUR STATUSES ARE ASSERTED BY VALUE, and `d22` reads their consequence rather than
    their name. Prose in a docstring that no test asserts reads as covered and pins nothing,
    and `check_binds` scans this docstring in place of the demand's `outcome`, so naming the
    four here without checking them is exactly the shape that passes review while binding
    nothing.

    THE RESOLVED DOCUMENTS REACH THE BLOCK, and that is now the whole of the payload
    obligation: the four documents this scenario resolves name `dev.dana` three times, and the
    rendered frame carries that content rather than a summary of it — which is what makes the
    correlation lead's own entity judgement possible downstream.

    EACH ARM GETS ITS OWN RUN DIR, and that is load-bearing rather than tidy. The first cut of
    these four arms shared one, so all four shell fetches carried an identical request key —
    same `native_query`, same `index`, same `limit`/`sort`; only the injected answer differed,
    and the injected answer is not part of the key. `QueryCapture`'s repeat guard reads
    `lead_rows(deps.run_dir, deps.lead_id)` off DISK, keys on
    `(lead_id, system, verb, canonical(params))`, and trips at `REPEAT_THRESHOLD = 3`
    (`occurrence = len(matches) + 1`, executed): resolves #3 and #4 were refused before the
    injected envelope could reach lead-0, making `STATUS_TRUNCATED` UNSATISFIABLE for any
    implementation that routes through the capture — which `d10` and this demand's own
    restatement both require. The cheapest way to turn that green was to stop routing through
    `QueryCapture`, i.e. to take the direct-registry via K7 forecloses.

    The guard is production behaviour and is not disabled, stubbed or dodged here: varying the
    predicate per arm would also have avoided the trip, and would have made this demand depend
    on the guard's own matching rule, which is not what `d0` binds. Separate run dirs remove
    the shared state instead — and they remove two more shared-state artefacts with it: each
    arm now claims `l-000` freshly rather than meeting `claim_lead`'s EEXIST return-2 arm, and
    the `failed` arm's recorded infra failures can no longer arm the breaker screen against a
    later arm's call.

    EVERY ARM PROVES ITS ENVELOPE ARRIVED before it reads a status. A screened call returns a
    refusal without ever invoking the injected verb, so an arm whose scenario is starved would
    otherwise assert against a status the implementation reached by some other route — silent
    starvation is exactly why nothing caught the shared-run-dir defect."""
    lead_zero = _lead_zero()

    def _resolve(name, **kw):
        """One arm, in its OWN run dir with its OWN recorder — see the docstring."""
        run_dir = materialize_alert(tmp_path / name, alert_doc())
        rec = VerbRecorder()
        return lead_zero.resolve_lead_zero(
            run_dir=run_dir, defender_dir=defender_dir(),
            alert_path=run_dir / "alert.json",
            verbs=elastic_backend(rec, **kw),
        ), rec

    def _reached(rec, name, expected=2):
        assert len(rec.calls) == expected, (
            f"the {name} arm's injected backend was called {len(rec.calls)} times, not "
            f"{expected} — its scenario never reached lead-0, so whatever status it returned "
            "was reached by some other route. A repeat-guard or breaker refusal looks exactly "
            "like this, and it is what made STATUS_TRUNCATED unsatisfiable when these four "
            "arms shared one run dir"
        )

    result, rec = _resolve("resolved", answer=answer_hits(REPEATED_ACTORS))
    _reached(rec, "resolved")

    assert result.status == lead_zero.STATUS_RESOLVED

    # The resolved documents' own values reach the block. #867 deleted the extracted entity
    # sets that used to be asserted here; what replaces them is not a weaker version of the
    # same check but the thing that made the extraction unnecessary — every actor the
    # documents name is IN the rendered text, so the correlation lead can read them itself.
    for named in ("dev.dana", "svc.config-mgmt", "office-ws-1", "db-1"):
        assert named in result.text, (
            f"{named!r} was resolved off an ancestor document but does not appear in item 1's "
            "rendered block — item 3 now binds that block as its whole entity evidence, so a "
            "value missing from it is a value the correlation lead cannot correlate on"
        )

    # #875: the frame's salt is minted at wrap time, so it is read off the result rather than
    # predicted. Matching the OPEN tag's own salt in the closer is the stronger check anyway —
    # it is what makes this one frame rather than two lookalikes.
    opened = re.match(r"<run-([0-9a-f]+)-untrusted>", result.text)
    assert opened is not None, \
        "item 1's block is not inside the untrusted frame every other externally-sourced " \
        "ORIENT section carries"
    assert result.text.rstrip().endswith(f"</run-{opened.group(1)}-untrusted>")
    assert "dev.dana" in result.text

    # The other three states, each by value. `failed` and `succeeded-empty` were exercised
    # only indirectly, through `d22`'s dispatch gating, so nothing pinned that they are
    # distinct values rather than two spellings of "nothing resolved".
    empty, empty_rec = _resolve("empty", answer=answer_hits([]))
    _reached(empty_rec, "empty")
    assert empty.status == lead_zero.STATUS_EMPTY, (
        "a resolution that reached the backend and found nothing does not report "
        "succeeded-empty — d22's gate then cannot tell it from a failure, and K13 makes that "
        "distinction load-bearing"
    )

    failed, failed_rec = _resolve(
        "failed", shell=TransportFault("docker exec failed"),
        answer=answer_raising(TransportFault("docker exec failed")))
    _reached(failed_rec, "failed")
    assert failed.status == lead_zero.STATUS_FAILED, \
        "a resolution whose calls all faulted reports the same status as one that found nothing"
    assert failed.status != empty.status, \
        "failed and succeeded-empty are the same value — the three-state return is two-state"

    truncated, trunc_rec = _resolve(
        "truncated", answer=answer_hits(REPEATED_ACTORS, total=25, truncated=True))
    _reached(trunc_rec, "truncated")
    assert truncated.status == lead_zero.STATUS_TRUNCATED, \
        "a truncated but nonempty resolution reports as if it were complete"
    assert "dev.dana" in truncated.text, \
        "a truncated resolution dropped the documents it did resolve; d22 still dispatches on it"

    # ALL FOUR, PAIRWISE. `failed != empty` above catches one pair; a by-value equality
    # assertion against each status individually is satisfied by an implementation that
    # collapses any OTHER two into one value too (e.g. STATUS_TRUNCATED == STATUS_RESOLVED
    # would leave every assertion above still green) — the four-state return is then a
    # two- or three-state one wearing four names, which is exactly the shape this demand
    # exists to rule out.
    assert len({result.status, empty.status, failed.status, truncated.status}) == 4, (
        f"the four statuses are not four distinct values: resolved={result.status!r} "
        f"empty={empty.status!r} failed={failed.status!r} truncated={truncated.status!r} — "
        "d22's gate reads the VALUE, so two states sharing one value are indistinguishable to it"
    )


def test_lead_zero_resolves_before_main_first_request(tmp_path):
    """d1 — lead-0's work is DONE before MAIN's first model request: its section is already in
    message 0, and both reserved ids are already claimed in the leads table when MAIN is first
    asked for a turn (F5: `l-000` and `l-00c`, claimed at run start before MAIN's first turn,
    so the pathological harness-side collision with no model in the loop cannot arise).

    Observed as an ordering, not as a final state: the replay model reads the leads table at
    each request, so "already claimed" is checked at the moment MAIN is asked."""
    run_dir = materialize_alert(tmp_path, alert_doc())
    watcher = _Watcher([
        Turn(tool_calls=[("read_file", {"path": str(run_dir / "alert.json")})]),
        Turn(text="Investigation complete."),
    ], run_dir)
    rec = VerbRecorder()
    from defender.tests.e2e._replay_harness import drive

    drive(run_dir, run_id="lz808-order", main=watcher,
          gather=ReplayFn([Turn(text="correlation summary")]),
          verbs=elastic_backend(rec, answer_hits(TWO_ACTORS)))

    assert watcher.leads_at_request, "main was never asked for a turn"
    at_first = watcher.leads_at_request[0]
    assert f"{L0}.lead.json" in at_first, \
        "item 1's lead row was not claimed before MAIN's first turn"
    assert f"{L3}.lead.json" in at_first, \
        "the correlation id was not reserved before MAIN's first turn — a model that picks " \
        "it first meets a harness-side collision with no model in the loop to retry (E7a)"
    assert LEAD_ZERO_HEADING in watcher.seen[0], \
        "message 0 carries no lead-0 section — the resolution did not happen before ORIENT"
    assert rec.calls, "no backend call was made before MAIN's first request"


def test_lead_zero_issues_its_backend_calls_through_the_query_capture_seam(tmp_path):
    """d10 — lead-0 issues its backend calls through the model's OWN `QueryCapture` path,
    bound to `lead_id="l-000"`, inheriting all eight screens (verb-grant, breaker,
    repeat-guard, traversal-screen, param-validation, self-ticket-screen, `confine_index`,
    `guard_outbound`).

    Re-formed from a row-shape PARITY demand into a SEAM demand: with one writer for both
    lead-0's rows and the model's, parity holds by construction and no implementation can
    fail it — a demand that cannot fail is not a demand. What CAN fail is the routing, and
    P2 (executed) is why it matters: on the direct-registry path a DENIED verb executed
    anyway and a TRIPPED breaker was ignored, because six of the eight screens live inside
    `QueryCapture` and are not inherited.

    Observed at the writer, which only `QueryCapture._record` reaches: a thirteen-key row under
    `l-000`, a persisted payload sidecar at `gather_raw/l-000/{seq}.json` allocated by the
    shared `record_query._next_seq`, and a breaker outcome recorded on the same tail.

    And observed at the SCREEN, which is the half the row cannot show: against an already
    tripped elastic breaker lead-0 DOES NOT ATTEMPT — it takes the down-path response and
    renders `_(unavailable: …)` without a call. That is `verb_registry.access[direct-registry]`'s
    parity cell, the via K7 forecloses, and it is exactly what P2 (executed) demonstrated the
    direct-registry path does NOT do: a tripped breaker was ignored and the call ran anyway.
    The breaker is tripped here through the REAL primitive, twice, because
    `PER_SYSTEM_FAIL_LIMIT` is 2 and one call would leave the screen passing."""
    res = run(tmp_path, answer=answer_hits(TWO_ACTORS), run_id="lz808-capture")

    rows = res.rows_for(L0)
    assert rows, "lead-0 wrote no queries row — its calls did not reach QueryCapture._record"
    assert set(rows[0]) == {
        "lead_id", "seq", "system", "verb", "query_id", "params", "raw_command",
        "payload_path", "exit_code", "error_class", "payload_status", "payload_digest",
        "payload_sha256",
    }, "lead-0's row is not the row QueryCapture._record builds — a second writer " \
       "re-implemented the schema, which is exactly what the tree's other queries-table " \
       "writer already did (g4)"
    assert rows[0]["system"] == "elastic"
    assert rows[0]["exit_code"] == 0
    assert res.payloads(L0), \
        "no raw payload was persisted — `_persist_payload` is on the same `_record` tail"
    assert (res.run_dir / rows[0]["payload_path"]).is_file()

    def _trip(run_dir):
        for _ in range(circuit_breaker.PER_SYSTEM_FAIL_LIMIT):
            circuit_breaker.record_outcome(run_dir, "elastic", 2)
        assert circuit_breaker.is_tripped(run_dir, "elastic"), \
            "the seed did not trip elastic — the screen below would have nothing to refuse"

    tripped = run(tmp_path / "tripped", run_id="lz808-tripped",
                  answer=answer_hits(TWO_ACTORS), before=_trip)
    assert tripped.rec.calls == [], (
        "lead-0 reached the backend through a TRIPPED elastic breaker — the direct-registry "
        "via inherits neither the breaker screen nor the five others (P2, executed), and this "
        "is the observable that says which via lead-0's calls actually take"
    )
    assert UNAVAILABLE in tripped.section(), \
        "the down-path response was not rendered as an unavailable slot"


def test_lead_zero_rides_the_injected_verb_registry_seam(tmp_path):
    """d14 — `runtime/lead_zero.py` owns every backend call, run-dir write and dispatch the
    change adds, and it reaches the backend ONLY through the registry the run was handed:
    the `VerbContext` its call arrives with carries THIS run's tree and THIS run's run_dir,
    never an import-time constant.

    That is the seam the whole suite drives, and the reason it is a demand rather than a
    detail: with no seam, an ORIENT-time call resolves the production `ModuleVerbRegistry`
    and the real docker-exec transport at 61 of 96 `drive()` sites (P9, AST census,
    executed at this base)."""
    res = run(tmp_path, answer=answer_hits(TWO_ACTORS), run_id="lz808-seam")

    call = res.shell_call
    assert call.ctx.run_dir == res.run_dir, \
        "lead-0's verb context names a run dir other than the run's own"
    assert call.ctx.defender_dir == defender_dir(), \
        "lead-0's verb context names a tree other than the one the run was anchored on"

    lead_zero = _lead_zero()
    assert lead_zero.RESERVED_LEAD_IDS == (L0, L3), \
        "the reserved ids are not a constant the runtime owns — 'reserved' then means only " \
        "collision-then-retry, whose retry arm is the model's (E7a)"


def test_a_scenario_that_injects_no_registry_reaches_no_backend_at_all(tmp_path):
    """d49 — with NO registry injected, lead-0 renders `_(unavailable: …)` and reaches
    nothing: no backend call, no queries row, no payload, no breaker state, and no
    correlation dispatch. A scenario that never asked for a backend must not acquire one.

    K12, applied: the design's own determinism rationale ("it lands at a phase boundary …
    which keeps the hermetic replay suite deterministic") is inverted by its placement —
    61 of 96 `drive()` sites omit `verbs=` and would otherwise resolve the production
    registry and the real docker-exec transport at ORIENT time (P9, executed — and its other
    marginal retires K12's second half: 0 of 96 sites inject `verbs=` WITHOUT `gather=`, so
    the turn-shifting regression K12 warned about has no site it can occur at). The positive
    control on the same address under the complementary condition is
    `test_lead_zero_rides_the_injected_verb_registry_seam`, which drives the identical
    scenario WITH a registry and observes the call, the row and the payload."""
    res = run(tmp_path, verbs=None, run_id="lz808-noseam")

    assert LEAD_ZERO_HEADING in res.message_zero, \
        "the section vanished rather than degrading — the other slots lose their context too"
    assert UNAVAILABLE in res.section(), \
        "no registry, but the block does not say the resolution was unavailable"
    assert res.rows_for(L0) == [], "a queries row was written for a call never made"
    assert res.payloads(L0) == [], "a payload was persisted for a call never made"
    assert not (res.run_dir / "circuit_breaker.json").is_file(), \
        "a run that reached no backend spent breaker budget"
    assert not res.has_sidecar(L3), \
        "the correlation lead dispatched off a resolution that never happened"


def test_each_item_fails_independently_into_an_unavailable_note(tmp_path):
    """d13 — a fault inside an item renders `_(unavailable: <repr>)` INSIDE that item's slot
    and leaves the rest of orientation intact: message 0 still carries the raw alert, the
    workspace map and the invlang catalog, and MAIN is still prompted.

    The fault content is probe-derived, not authored: `TransportFault` is the adapter's own
    infra class (exit 2, `INFRA_EXIT_CODES`), and the note lands INSIDE the untrusted frame
    because the restated `d0` places it there — `_(unavailable: {e!r})` interpolates a repr
    of an exception whose message can carry attacker-influenced text.

    THE FAULT LANDS ON THE BRANCH CALL, not on the shell fetch: no `shell=` is passed, so the
    harness's default answers call 0 with a resolved shell document and the injected fault
    first bites on the ancestor call. That is the only scenario in the suite shaped this way,
    and `d61`'s arm A is its mirror (the fault on call 0). Named here because the difference is
    a harness default rather than anything visible at the call site, and "harmonising" the two
    by adding `shell=` here would silently delete the branch-fault arm."""
    res = run(tmp_path, answer=answer_raising(TransportFault("docker exec failed")),
              run_id="lz808-degrade")

    assert UNAVAILABLE in res.section(), \
        "item 1 failed and its slot does not say so"
    assert "## Alert (raw" in res.message_zero, "a lead-0 fault took the rest of ORIENT with it"
    assert "## Workspace" in res.message_zero
    assert res.main.calls >= 1, "the run never reached MAIN's first prompt"
    assert res.summary_dict.get("output") is not None, "the run produced no summary at all"


def test_a_run_ending_arm_inside_lead_zero_still_produces_a_run_summary(tmp_path):
    """N3/K8 — a `RunAborted` (or `BudgetKill`) raised INSIDE lead-0 is caught at lead-0's own
    call site: the run still writes its trace and returns a `_run_summary`, rather than ending
    before MAIN's first prompt with a raw traceback, no summary, no `write_trace` and an
    unclosed `RequestLogger`.

    This is the arm P3 (executed) turned from hypothetical into certain: both of the gather
    dispatch's run-ending arms stamp their terminator and RE-RAISE, K7 puts the breaker arm on
    lead-0's own call path, and `_user_prompt` is called at driver.py:838 — outside every
    handler (the store-setup `try` closes at :827 and `_drive_agent`'s catch begins after
    :841). The old contract's "it never raises" was the only thing standing between the two.

    Driven through the REAL breaker: four infra failures are seeded on OTHER systems (so
    elastic's own per-system count stays below `PER_SYSTEM_FAIL_LIMIT` and lead-0's call is
    not screened away before it runs), leaving lead-0's own failure as the fifth — exactly
    `RUN_FAIL_KILL_LIMIT`, which `record_outcome` answers with `RunAborted` (g10/E2)."""
    run_dir_seed = materialize_alert(tmp_path / "seeded", alert_doc())
    for system in ("cmdb", "cmdb", "identity", "identity"):
        circuit_breaker.record_outcome(run_dir_seed, system, 2)
    assert not circuit_breaker.is_tripped(run_dir_seed, "elastic"), \
        "the seed tripped elastic itself — lead-0's call would be screened, not executed"

    rec = VerbRecorder()
    from defender.tests.e2e._replay_harness import drive

    main = ReplayFn([Turn(text="Investigation complete.")])
    summary = drive(
        run_dir_seed, run_id="lz808-aborted", main=main,
        gather=ReplayFn([Turn(text="correlation summary")]),
        verbs=elastic_backend(rec, answer_raising(TransportFault("transport down"))),
    )

    assert summary is not None, \
        "a run-ending arm inside lead-0 escaped `_user_prompt` — no `_run_summary` at all"
    assert "truncated_by" in summary, f"the run summary is not a run summary: {summary!r}"
    assert (run_dir_seed / "tool_trace.jsonl").is_file(), \
        "the run ended before `write_trace`, so nothing records that it happened"
    res = Res(run_dir_seed, main, None, rec)
    assert UNAVAILABLE in res.section(), \
        "the run-ending arm was swallowed silently rather than degrading the slot"
