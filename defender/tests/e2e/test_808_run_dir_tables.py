"""#808 — the two append-only tables lead-0 joins as a writer.

Every test here is one demand of `spec-flow/specs/spec_graph_808.yaml`, named after its
`discharged_by` pointer and carrying that demand's observable-outcome prose in its docstring.
THE CODE DOES NOT EXIST YET: this suite is RED by construction.

THE TABLES, AND WHY LEAD-0 IS A HARD WRITER TO ADD
--------------------------------------------------
  leads    `gather_raw/{lead_id}.lead.json`, claimed `O_CREAT|O_EXCL` by
           `hooks/record_lead.claim_lead`, keyed `[lead_id]`.
  queries  `executed_queries.jsonl`, keyed `(lead_id, seq)` with FK `lead_id`; raw payloads
           by-ref at `gather_raw/{lead_id}/{seq}.json`, keyed `[lead_id, seq]`.

Three executed facts shape every demand in this file.

  * `claim_lead` returns `0` for BOTH "written" and "silently refused" (r1/r14, executed): a
    falsy `goal`, a non-list `what_to_summarize` or an id outside `LEAD_ID_RE` all return the
    SUCCESS code and write nothing at all. A lead-0 dispatch built from an empty goal
    therefore reports success, writes no sidecar, and the rows it goes on to write make
    `joined()` mark `l-000` `orphan=True` — contradicting `d11`.
  * A reuse returns `2`, prints to stderr and leaves the first sidecar byte-identical — but
    the same collision routed through `gather_dispatch` raises `ModelRetry` (E7a, executed),
    and a harness dispatch has no model to retry, so that exception escapes into
    `_user_prompt`, which sits outside every handler in `run_investigation`.
  * `record_query._next_seq` allocates from the rows already on disk for that lead, BEFORE
    the payload write. A lead-0-private counter would re-claim a slot the shared one already
    handed out, silently overwriting a payload sidecar.

Two checked-in prose surfaces say `claim_lead` "raises" on a reused id (CLAUDE.md:75,
skills/handbook/content/runtime-loop.md:89). r1/r15 (executed) refute it: it returns 2 and
prints. The stale prose is itself a finding, and no test here may assert it.
"""
from __future__ import annotations

import json

import pytest

pytest.importorskip("pydantic_ai")

from defender._io import append_jsonl, read_jsonl_rows  # noqa: E402
from defender._run_paths import RunPaths, _PAYLOAD_SHAPES  # noqa: E402
from defender.hooks.record_lead import LEAD_ID_RE, claim_lead  # noqa: E402
from defender.tests.e2e._lead_zero_808 import (  # noqa: E402
    HARNESS_PROVENANCE,
    L0,
    L3,
    PROVENANCE_KEY,
    SALT,
    alert_doc,
    ancestor,
    answer_hits,
    hit,
    materialize_alert,
    run,
)
from defender.tests.e2e._replay_harness import Turn  # noqa: E402

pytestmark = pytest.mark.e2e

DOCS = [hit(ts="2026-05-25T15:22:00.000Z"), hit(ts="2026-05-25T15:26:00.000Z",
                                                user="svc.config-mgmt", ip="172.18.0.4")]

MAIN_LEAD = "l-001"


def _main_dispatches_its_own() -> list[Turn]:
    return [
        Turn(tool_calls=[("gather", {
            "lead_id": MAIN_LEAD, "system": "elastic", "goal": "measure this lead",
            "what_to_summarize": ["auth events"]})]),
        Turn(text="Investigation complete."),
    ]


def test_lead_zero_claims_l000_lead_row(tmp_path):
    """d8 — item 1 claims `l-000` in the leads table before it writes any query row: a
    sidecar at `gather_raw/l-000.lead.json` exists, carries a non-empty `goal` and a non-empty
    list `what_to_summarize`, and its id is one `lead_repository`'s own reader half accepts.

    Goal construction is VALIDATED, not assumed, and the docstring says so because the
    mechanism does not: `claim_lead`'s falsy-goal arm returns the SUCCESS code and writes
    nothing (r14, executed), so "the claim succeeded" is not evidence that the row exists."""
    res = run(tmp_path, run_id="lz808-claim", answer=answer_hits(DOCS))

    sidecar = res.sidecar(L0)
    assert isinstance(sidecar.get("goal"), str), f"l-000's goal is not a string: {sidecar!r}"
    assert sidecar["goal"].strip(), \
        "l-000's goal is falsy — claim_lead's swallow arm returns 0 and writes nothing"
    assert isinstance(sidecar.get("what_to_summarize"), list), \
        "l-000's what_to_summarize is not a list — the same swallow arm"
    assert sidecar["what_to_summarize"], "l-000's what_to_summarize is empty"
    assert LEAD_ID_RE.match(L0), "the reserved id is outside the namespace's own regex"


def test_lead_zero_goal_construction_never_hits_claim_leads_silent_zero(tmp_path):
    """R4 `claim_lead.domain.distinguished[0]` — the falsy member is the swallow shape, and
    lead-0 never produces it: no queries row is ever written under a reserved id whose leads
    row is missing, on the happy path or on a degraded one.

    The swallow arm is re-executed here against the REAL primitive rather than assumed, so
    the taxonomy assumption is re-probed on every run: `claim_lead` with an empty goal
    returns 0 — the SUCCESS code — and writes no file. That is the state `joined()` reports as
    `orphan=True`, which is exactly what `d11` says must not happen."""
    probe_dir = materialize_alert(tmp_path / "probe", alert_doc())
    assert claim_lead({"run_dir": str(probe_dir), "lead_id": "l-777",
                       "goal": "", "what_to_summarize": ["x"]}) == 0, \
        "claim_lead's falsy-goal arm no longer reports success — re-read r14 before relying " \
        "on the guard this demand asks for"
    assert not (probe_dir / "gather_raw" / "l-777.lead.json").exists(), \
        "the falsy-goal arm now writes a sidecar; the swallow this demand guards is gone"

    happy = run(tmp_path / "ok", run_id="lz808-goal-ok", answer=answer_hits(DOCS))
    assert happy.has_sidecar(L0), (
        "the happy path produced no leads row for l-000 — the guard below would be green "
        "over a lead that never existed, which is the vacuous shape"
    )
    assert happy.rows_for(L0), "the happy path produced no query rows for l-000"

    degraded = run(tmp_path / "deg", run_id="lz808-goal-deg",
                   alert=alert_doc(ancestors=[]), answer=answer_hits([]))
    assert degraded.has_sidecar(L0), \
        "a degraded resolution left l-000 claimed nowhere, so its rows have no owner"

    for label, res in (("happy", happy), ("degraded", degraded)):
        for lead in (L0, L3):
            assert not (res.rows_for(lead) and not res.has_sidecar(lead)), (
                f"[{label}] rows exist under {lead} with no leads row — joined() marks it "
                "orphan=True, and the claim reported success"
            )


def test_a_harness_side_reclaim_takes_claim_leads_return_two_arm(tmp_path):
    """R4 `claim_lead.domain.distinguished[2]` — a harness-side re-claim of a reserved id
    goes through `claim_lead` DIRECTLY and takes its return-2 arm: the first sidecar is left
    byte-identical, nothing raises, and the run reaches MAIN. It is not routed through
    `gather_dispatch`, whose reuse arm raises `ModelRetry` (E7a, executed) with no model in
    the loop to retry — an exception that escapes into `_user_prompt` and ends a run that has
    not yet begun.

    Which mechanism produces that collision is now named rather than left to the implementer
    (§7 round 3, F3): the reserved ids are claimed at RUN START (F5), and K15's extracted
    gather seam ACCEPTS A PRE-CLAIMED LEAD ID AND DOES NOT RE-CLAIM. `_run_gather` claims the
    lead itself at tools_gather.py:277-285 and raises `ModelRetry` on reuse, so a seam that
    re-claimed would raise on EVERY run, not on a pathological one — claim `a3` (executed)
    records exactly that sequence. Round 1's rationale said the pre-claim removes the
    collision; the executed claim in the same ledger says it guarantees one, and that
    sentence is retracted.

    Driven by planting the collision the only way a harness can meet one: the reserved id is
    already claimed on the run dir before the run starts."""
    run_dir = materialize_alert(tmp_path, alert_doc())
    planted = json.dumps({"goal": "an earlier claim", "what_to_summarize": ["earlier"]},
                         indent=2) + "\n"
    (run_dir / "gather_raw" / f"{L3}.lead.json").write_text(planted, encoding="utf-8")

    from defender.tests.e2e._lead_zero_808 import elastic_backend
    from defender.tests.e2e._replay_harness import ReplayFn, drive
    from defender.tests.e2e._lead_zero_808 import answer_hits as _ah
    from defender.tests.e2e._replay_harness import VerbRecorder

    rec = VerbRecorder()
    main = ReplayFn([Turn(text="Investigation complete.")])
    summary = drive(run_dir, run_id="lz808-reclaim", salt=SALT, main=main,
                    gather=ReplayFn([Turn(text="correlation summary")]),
                    verbs=elastic_backend(rec, _ah(DOCS)))

    assert summary is not None, \
        "the re-claim raised ModelRetry out of `_user_prompt` — the run ended before MAIN"
    assert main.calls >= 1, "the run never reached MAIN's first prompt"
    assert (run_dir / "gather_raw" / f"{L0}.lead.json").is_file(), (
        "lead-0 never claimed anything on this run dir, so nothing met the planted "
        "collision — the survival assertion below would be green over a run that did nothing"
    )
    assert (run_dir / "gather_raw" / f"{L3}.lead.json").read_text(encoding="utf-8") == planted, \
        "the re-claim overwrote the first sidecar; claim_lead's O_EXCL arm leaves it untouched"


def test_lead_zero_appends_query_rows_keyed_l000(tmp_path):
    """d9 — every backend call item 1 makes appends one row to `executed_queries.jsonl` keyed
    `(lead_id="l-000", seq)`, with `seq` allocated per lead and monotonic within the run, and
    its raw payload persisted at `gather_raw/l-000/{seq}.json` — a path shape the run-dir
    payload whitelist already admits.

    The rows are appended BEFORE `orientation()` finishes, which is why `executed_queries.jsonl`
    becomes a new name in message 0's own run-dir listing (g12, executed)."""
    ancestors = [ancestor("auth-1"), ancestor("falco-1",
                                              ".ds-logs-falco.alerts-default-2026.04.30-000003")]
    res = run(tmp_path, run_id="lz808-rows", alert=alert_doc(ancestors=ancestors),
              answer=answer_hits(DOCS))

    rows = res.rows_for(L0)
    assert len(rows) == 3, (
        f"the shell fetch plus two backing indices produced {len(rows)} rows, not three"
    )
    assert [r["seq"] for r in rows] == [0, 1, 2], "seq is not allocated per lead and monotonic"
    for row in rows:
        assert row["lead_id"] == L0
        assert (res.run_dir / row["payload_path"]).is_file()
    assert res.payloads(L0) == ["0.json", "1.json", "2.json"]
    shape = f"gather_raw/{L0}/0.json"
    assert any(pattern.fullmatch(shape) for pattern in _PAYLOAD_SHAPES), \
        f"{shape} is outside the run-dir payload whitelist — the pointer is uncontained"


def test_lead_zero_and_the_model_share_one_payload_seq_counter(tmp_path):
    """R2 `gather_payloads.identity` — lead-0 allocates its payload `seq` from the SAME
    counter the model's query path uses (`record_query._next_seq`, which counts this lead's
    rows already on disk), never from a lead-0-private one. A private counter re-claims a slot
    the shared one already handed out, and `gather_raw/{lead_id}/{seq}.json` is a
    unique-key sink: the second writer silently overwrites the first's payload.

    Driven at the composition frame, over a run dir that already carries a row for the
    reserved id — the only way one writer's allocation can be observed against another's."""
    run_dir = materialize_alert(tmp_path, alert_doc(ancestors=[ancestor("anc-1")]))
    prior = {"lead_id": L0, "seq": 0, "system": "elastic", "verb": "query",
             "query_id": "elastic.ad-hoc", "params": {}, "raw_command": "elastic query",
             "payload_path": f"gather_raw/{L0}/0.json", "exit_code": 0,
             "error_class": None, "payload_status": "persisted", "payload_digest": "exit=0"}
    append_jsonl(RunPaths(run_dir).executed_queries, [prior])
    slot = run_dir / "gather_raw" / L0 / "0.json"
    slot.parent.mkdir(parents=True, exist_ok=True)
    slot.write_text('["THE EARLIER PAYLOAD"]', encoding="utf-8")

    from defender.tests.e2e._lead_zero_808 import elastic_backend
    from defender.tests.e2e._replay_harness import ReplayFn, VerbRecorder, drive

    rec = VerbRecorder()
    drive(run_dir, run_id="lz808-seq", salt=SALT,
          main=ReplayFn([Turn(text="Investigation complete.")]),
          gather=ReplayFn([Turn(text="correlation summary")]),
          verbs=elastic_backend(rec, answer_hits(DOCS)))

    rows = [r for r in read_jsonl_rows(RunPaths(run_dir).executed_queries)
            if r.get("lead_id") == L0]
    assert [r["seq"] for r in rows] == [0, 1, 2], \
        f"lead-0 allocated {[r['seq'] for r in rows]} — a private counter re-claimed seq 0"
    assert slot.read_text(encoding="utf-8") == '["THE EARLIER PAYLOAD"]', \
        "lead-0's payload write overwrote a slot the shared counter had already handed out"


def test_the_leads_table_marks_lead_zeros_row_as_harness_authored(tmp_path):
    """K11/N1 — the leads table gains a PROVENANCE field, and the harness-authored rows carry
    it: both reserved ids are marked `harness`, and a lead the model dispatched is not. An
    absent field means model-authored, because the table is append-only and every row already
    on disk predates the schema addition.

    This is the seam the human's decision bought and it is the reason
    `test_reserved_lead_id_forgery_via_message_content` inverts: with the harness — not MAIN —
    authoring lead-0's declaring row, injected content can no longer steer that row's goal or
    disposition language at all. The residual vector is MAIN's CITATION of the row, not its
    authorship.

    The field's NAME and VALUE are minted by this spec (`provenance` / `harness`); §7 resolved
    that the field exists and left both unnamed."""
    res = run(tmp_path, run_id="lz808-prov", answer=answer_hits(DOCS),
              main_turns=_main_dispatches_its_own(),
              gather_turns=[Turn(text="correlation summary"), Turn(text="lead summary")])

    for lead in (L0, L3):
        assert res.sidecar(lead).get(PROVENANCE_KEY) == HARNESS_PROVENANCE, \
            f"{lead}'s leads row does not mark itself harness-authored"
    model_row = res.sidecar(MAIN_LEAD)
    assert model_row.get(PROVENANCE_KEY) != HARNESS_PROVENANCE, \
        "a lead the MODEL dispatched is marked harness-authored — the field distinguishes " \
        "nothing and every reader taught to trust it is now wrong"


def test_reserved_harness_lead_ids_never_collide_with_main_minted_ids(tmp_path):
    """d12 — `l-000` and `l-00c` are constants the runtime owns, distinct from each other and
    outside the `l-001, l-002, …` sequence MAIN mints, so a run in which MAIN dispatches its
    own leads writes three distinct leads rows and no id is claimed twice.

    The literal values are pinned here, not just their shape: `d12` binds "outside the
    sequence" and F5 chose the strings, and they are now the join key the learning loop and
    the review gate cite. Both match `LEAD_ID_RE` and both produce a payload path the run-dir
    whitelist admits — `l-00c` in particular, because a hex-looking id that failed either
    check would be a claim that succeeds and a payload that cannot be written."""
    res = run(tmp_path, run_id="lz808-ids", answer=answer_hits(DOCS),
              main_turns=_main_dispatches_its_own(),
              gather_turns=[Turn(text="correlation summary"), Turn(text="lead summary")])

    names = res.gather_raw_names()
    for lead in (L0, L3, MAIN_LEAD):
        assert f"{lead}.lead.json" in names, f"{lead} has no leads row: {names}"
    assert L0 != L3
    assert len({L0, L3, MAIN_LEAD}) == 3, "a reserved id collided with MAIN's own sequence"
    for lead in (L0, L3):
        assert LEAD_ID_RE.match(lead), f"{lead} is outside the lead-id namespace's regex"
        assert any(p.fullmatch(f"gather_raw/{lead}/1.json") for p in _PAYLOAD_SHAPES), \
            f"{lead}'s payload path is outside the run-dir whitelist"
