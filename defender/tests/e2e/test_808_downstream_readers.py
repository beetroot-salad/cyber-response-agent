"""#808 — the readers of a namespace that stops being all model-minted.

Every test here is one demand of `spec-flow/specs/spec_graph_808.yaml`, named after its
`discharged_by` pointer and carrying that demand's observable-outcome prose in its docstring.
THE CODE DOES NOT EXIST YET: this suite is RED by construction.

WHY EVERY DEMAND HERE IS BOUND AT ONE READER'S OWN EDGE
--------------------------------------------------------
The change alters a CONTRACT — lead ids stop being all model-minted — while five existing
readers keep the old reading. A demand bound at the boundary itself is green when two of the
three readers moved, and that is precisely the bug: R7's whole point is that nothing is added
and nothing is removed, so every add/remove rule stays quiet and each reader is correct read
alone. One test per reader, driving the change and observing THAT reader.

The four collisions, each executed:
  1. `cross_check_tables` warns on any table `lead_id` with no `:L` row in `investigation.md`,
     and `:L` rows are authored by MAIN at PLAN — AFTER lead-0 — so it reports
     `missing_from_narration: ['l-000'], ok: False` on EVERY run (g13).
  2. `invlang_validate` refuses a citation of a lead no `:L findings` row declares (P6:
     declared → zero errors, undeclared → exactly one), which would turn "MAIN cites lead-0's
     evidence" — the entire point of the change — into a refused write.
  3. `build_case` takes `joined(run_dir)` UNFILTERED (P4a: `joined`'s signature has no
     lead-set parameter at all, so there is nothing to pass a filter into) and the scorer's
     first gate is lead-set integrity, refusing to score rather than scoring wrong (P4b).
  4. Six checked-in prose surfaces tell the model it owns every lead id; the design updates
     none of them.

`run_dir_listing`'s two readers are here for the same reason: `workspace_map` skips only
`gather_raw` and `budget.json` (g12/E5, executed), so `executed_queries.jsonl` becomes a NEW
NAME in message 0's listing on every run once lead-0 writes before `orientation()` runs.
`test_salt_origin_647.py:480-516` pins the OLD listing and must be updated by this change —
the design does not mention it.
"""
from __future__ import annotations

import json
import os
import re

import pytest

pytest.importorskip("pydantic_ai")

from defender.learning import lead_repository  # noqa: E402
from defender.runtime import scrub as scrub_mod  # noqa: E402
from defender.scripts.adapters.elastic_adapter import load_config  # noqa: E402
from defender.runtime.verbs import VerbContext  # noqa: E402
from defender.skills.invlang.validate import validate_companion  # noqa: E402
from defender.tests.e2e._lead_zero_808 import (  # noqa: E402
    ALERTS_INDEX,
    EVENTS_INDEX,
    HARNESS_PROVENANCE,
    L0,
    L3,
    PROVENANCE_KEY,
    alert_doc,
    answer_hits,
    defender_dir,
    hit,
    run,
)
from defender.tests.e2e._replay_harness import Turn  # noqa: E402

pytestmark = pytest.mark.e2e

DOCS = [hit(ts="2026-05-25T15:22:00.000Z"),
        hit(ts="2026-05-25T15:26:00.000Z", user="svc.config-mgmt", ip="172.18.0.4")]

_AUTHZ_HEADER = (
    ":R authz [resolved_by|cites_leads?|edge|fulfills|verdict|anchor_kind|reasoning]"
)

# The same reader `test_salt_origin_647.py` uses to pin message 0's run-dir listing — asserted
# against the SECTION rather than against the whole prompt, because the artifact names also
# appear in the shipped system prompt and a whole-prompt search is green before lead-0 exists.
RUN_DIR_SECTION = re.compile(r"^## Run dir — .*$((?:\n- .*)*)", re.M)


def _lead_ref_errors(text: str) -> list[str]:
    return [e for e in validate_companion(text)
            if "undeclared lead" in e or "cites_leads" in e]


def test_joined_sees_l000_as_a_non_orphan_lead(tmp_path):
    """d11 — `lead_repository.joined(run_dir)`, the single read/join surface every downstream
    consumer uses, returns `l-000` as a NON-ORPHAN lead: a leads row with a goal and
    dimensions, joined to the query rows lead-0 wrote under it.

    `orphan=True` is the shape a claim that silently failed produces — rows under a lead id
    with no leads row — and r14/E4 (executed) show `claim_lead` reports SUCCESS on exactly
    that path, so "the claim returned 0" is not evidence that this holds."""
    res = run(tmp_path, run_id="lz808-joined", answer=answer_hits(DOCS))

    leads = {lead.lead_id: lead for lead in lead_repository.joined(res.run_dir)}
    assert L0 in leads, f"l-000 is absent from the join surface: {sorted(leads)}"
    zero = leads[L0]
    assert zero.orphan is False, \
        "l-000 joins as an ORPHAN — its rows exist and its leads row does not"
    assert zero.goal, "l-000 joined with no goal"
    assert zero.queries, "l-000's query rows did not join onto its leads row"


def test_the_join_surface_carries_lead_zeros_provenance_to_its_readers(tmp_path):
    """R7 `interacts(lead_repository->lead_id)` — the provenance the leads table gained
    reaches the readers through the ONE join surface they all use, and a row written before
    the schema addition still joins: an absent field reads as model-authored rather than as a
    parse failure.

    The absent-value arm is not optional. This is a schema addition to an APPEND-ONLY table,
    so every row already on disk carries no such field, and a reader that treats absence as
    an error rejects every historical run."""
    res = run(tmp_path, run_id="lz808-prov-join", answer=answer_hits(DOCS))
    legacy = res.run_dir / "gather_raw" / "l-009.lead.json"
    legacy.write_text(json.dumps({"goal": "a row from before the field existed",
                                  "what_to_summarize": ["x"]}) + "\n", encoding="utf-8")

    leads = {lead.lead_id: lead for lead in lead_repository.joined(res.run_dir)}
    assert L0 in leads, f"the join surface never saw {L0} at all: {sorted(leads)}"
    assert getattr(leads[L0], PROVENANCE_KEY) == HARNESS_PROVENANCE, \
        "the join surface drops the provenance field, so no reader downstream can act on it"
    assert getattr(leads["l-009"], PROVENANCE_KEY) != HARNESS_PROVENANCE, \
        "a pre-schema row joined as harness-authored — absence must read as model-authored"


def test_the_narration_cross_check_no_longer_warns_on_the_harness_lead(tmp_path):
    """R7 `interacts(cross_check_tables->lead_id)` — the narration cross-check knows about the
    reserved ids, so a run that used lead-0 exactly as intended reports `ok: True` and no
    `missing_from_narration` entry for them.

    g13 (executed) is the collision: the check warns on any table `lead_id` with no `:L` row
    in `investigation.md` and reported `missing_from_narration: ['l-000'], ok: False`. Left
    alone it fires on EVERY run — a warning that is always on is a warning nobody reads, and
    it is the cheapest possible way to hide the run where the check would have been right."""
    res = run(tmp_path, run_id="lz808-xcheck", answer=answer_hits(DOCS))

    assert res.investigation, (
        "no investigation.md was written for this run — the cross-check has nothing to read "
        "(investigation.md's row is K11/N6's harness-authored write, the same one "
        "test_the_harness_writes_lead_zeros_declaring_l_findings_row pins)"
    )
    xcheck = lead_repository.narration_crosscheck_from_run(res.run_dir)
    assert L0 not in xcheck["missing_from_narration"], (
        "the cross-check reports l-000 as missing from the narration on a run that used it "
        "as designed — it now warns on every run"
    )
    assert L3 not in xcheck["missing_from_narration"]
    assert xcheck["ok"] is True, f"the cross-check failed a correct run: {xcheck}"


def test_the_harness_writes_lead_zeros_declaring_l_findings_row(tmp_path):
    """K11/N6 — the HARNESS writes lead-0's declaring `:L findings` row into
    `investigation.md`, making lead-0 the first non-MAIN writer of that file. The row carries
    the reserved id and a NON-EMPTY `name`, because `_check_lead_refs` treats a finding id
    WITHOUT a name as undeclared, and it is written before MAIN's first turn so it cannot race
    MAIN's own authoring of the same append-only artifact.

    This is what makes the residual injection vector MAIN's CITATION of the row rather than
    its authorship: with the harness authoring lead-0's row, steered content can no longer
    reach that row's goal or disposition language at all."""
    res = run(tmp_path, run_id="lz808-lrow", answer=answer_hits(DOCS))

    doc = res.investigation
    assert ":L findings" in doc, \
        "investigation.md carries no `:L findings` table — nothing declares lead-0 at all"
    rows = [line for line in doc.splitlines() if line.startswith(f"{L0}|")]
    assert rows, f"no `:L findings` row declares {L0}: {doc[:400]!r}"
    name = rows[0].split("|")[2]
    assert name.strip(), \
        "the declaring row's `name` is empty, and a finding id without a name is exactly " \
        "what `_check_lead_refs` reads as undeclared (P6)"
    assert _lead_ref_errors(doc) == [], \
        f"the harness's own row does not validate: {_lead_ref_errors(doc)}"


def test_main_can_cite_lead_zeros_evidence_without_an_undeclared_lead_error(tmp_path):
    """R7 `interacts(invlang_validate->lead_id)` — MAIN citing lead-0's evidence VALIDATES:
    a grounded row naming `l-000` as its `resolved_by` produces zero "undeclared lead" errors
    against the document the harness wrote.

    P6 (executed) is both arms of this and the reason it is a demand rather than an
    assumption: with a declaring `:L findings` row, `validate_companion` produced zero
    undeclared-lead errors; without one, exactly one — `"undeclared lead 'l-000': referenced
    by a `:R` / `:T` row or a lead sub-block, but no `:L findings` row declares it"`. Left
    unhandled, "MAIN cites lead-0's evidence" — the entire point of the change — is a REFUSED
    WRITE, and the control below shows the validator really would refuse it."""
    res = run(tmp_path, run_id="lz808-cite", answer=answer_hits(DOCS))
    citation = (f"\n```invlang\n{_AUTHZ_HEADER}\n"
                f"{L0}||e-001|ac1|unauthorized|approved-source-list|\"x\"\n```\n")

    assert _lead_ref_errors(res.investigation + citation) == [], (
        "MAIN cannot cite the harness lead's evidence: the validator refuses the write, "
        "which is the change's own stated obligation turned into an error"
    )

    # The complementary condition, on the same address: without the declaring row the same
    # citation IS refused — so the pass above is the harness's row doing work, not the
    # validator having stopped checking.
    bare = f"```invlang\n{_AUTHZ_HEADER}\n" \
           f"{L0}||e-001|ac1|unauthorized|approved-source-list|\"x\"\n```\n"
    errors = _lead_ref_errors(bare)
    assert len(errors) == 1, \
        f"the undeclared-lead rule is not the rule this demand rests on: {errors}"
    assert L0 in errors[0], f"the refusal names some other lead: {errors}"


def test_the_golden_case_builder_keeps_a_scoreable_lead_set(tmp_path):
    """R7 `interacts(build_case->lead_id)` — a golden case rebuilt from a run that used lead-0
    carries a lead set a projection can still match: the harness-authored leads are excluded
    from the case's frozen `oracle_visible/leads.jsonl`, so the scorer's lead-set integrity
    gate has nothing new to refuse.

    P4a/P4b, executed: `build_case`'s `leads = lead_repository.joined(ns.run_dir)` is
    unconditional and `joined`'s signature has NO lead-set parameter — the fix cannot be
    discovering an unused filter argument, it has to be made in `build_case` explicitly or
    upstream. And `score_case()` refuses a projection whose lead set differs, returning
    `judged: False` with empty rows and never calling the judge model at all. Every rebuilt
    case would fail integrity rather than score."""
    from defender.evals.oracle_golden import build_case

    res = run(tmp_path / "run", run_id="lz808-case", answer=answer_hits(DOCS),
              main_turns=[
                  Turn(tool_calls=[("gather", {
                      "lead_id": "l-001", "system": "elastic", "goal": "measure this lead",
                      "what_to_summarize": ["auth events"]})]),
                  Turn(text="Investigation complete."),
              ])
    story = tmp_path / "story.md"
    story.write_text("the ground-truth story\n", encoding="utf-8")
    controls = tmp_path / "controls.yaml"
    controls.write_text("windows: []\n", encoding="utf-8")
    out = tmp_path / "cases" / "lz808"

    joined_ids = {lead.lead_id for lead in lead_repository.joined(res.run_dir)}
    assert {L0, L3} <= joined_ids, (
        f"the run dir carries no harness leads to filter ({sorted(joined_ids)}) — the "
        "exclusion below would be green over an empty set, which is the vacuous negative"
    )

    assert build_case.main([str(res.run_dir), str(story), str(controls), str(out)]) == 0
    captured = [json.loads(line) for line in
                (out / "oracle_visible" / "leads.jsonl").read_text().splitlines() if line]
    ids = {row["lead_id"] for row in captured}
    assert ids, "the case captured no leads at all"
    assert not (ids & {L0, L3}), (
        f"the case froze the harness-authored leads into its expectation ({sorted(ids)}) — "
        "every projection of this case now fails lead-set integrity instead of scoring"
    )


def test_main_is_told_the_reserved_ids_are_already_taken(tmp_path):
    """R7 `interacts(main_agent->lead_id)` — MAIN is TOLD which ids the harness reserved,
    rather than finding out by collision. Both reserved ids are named in what MAIN is handed
    before it picks its own.

    Six checked-in prose surfaces tell the model it owns every lead id and the revised design
    updates none of them, so today "reserved" is a convention enforced only by
    collision-then-retry. F5 claims both ids at run start before MAIN's first turn, which
    makes the leads table right; this demand makes what MAIN READS right, and they are
    different surfaces."""
    res = run(tmp_path, run_id="lz808-told", answer=answer_hits(DOCS))

    for lead in (L0, L3):
        assert lead in res.message_zero, (
            f"{lead} is reserved by the harness and MAIN is never told — it learns by "
            "collision, on a namespace it is documented to own outright"
        )


def test_message_zeros_run_dir_listing_names_the_queries_table(tmp_path):
    """R7 `interacts(workspace_map->run_dir_listing)` — message 0's own run-dir listing names
    `executed_queries.jsonl`, because lead-0's rows are appended BEFORE `orientation()` runs
    and `workspace_map` skips only `gather_raw` and `budget.json` (g12/E5, executed).

    The listing is a pinned surface — `test_salt_origin_647.py:480-516` asserts its contents —
    so this is not cosmetic: a new name appears in it on every run, the design does not
    mention it, and the reader that renders it is one of two that must agree about a run dir
    lead-0 now writes into before the first model turn."""
    res = run(tmp_path, run_id="lz808-listing", answer=answer_hits(DOCS))

    match = RUN_DIR_SECTION.search(res.message_zero)
    assert match, "message 0 carries no run-dir listing at all"
    listing = match.group(1)
    assert "executed_queries.jsonl" in listing, (
        "the queries table lead-0 wrote before ORIENT is absent from message 0's own run-dir "
        f"listing — the listing and the run dir disagree at the moment MAIN reads it: {listing!r}"
    )
    assert "gather_raw" not in listing, \
        "the listing started enumerating gather_raw, which it has always skipped"
    assert "budget.json" not in listing, \
        "the listing started enumerating budget.json, which it has always skipped"


def test_scrub_walks_the_run_dir_lead_zero_wrote_into(tmp_path):
    """R7 `interacts(scrub->run_dir_listing)` — the run dir's OTHER walker sees lead-0's
    artifacts: `scrub` covers the queries table and the payload tree lead-0 wrote before
    MAIN's first turn, rather than meeting names its walk was never told about.

    Bound at this reader's own edge and not shared with `workspace_map`'s, because R7's
    canonical escape is exactly "two of the three readers moved". Driven through `scrub`'s own
    `lister=` injection seam, which records what the walk was handed."""
    res = run(tmp_path, run_id="lz808-scrub", answer=answer_hits(DOCS))
    walked: list = []

    def recording_lister(*args, **kwargs):
        # `scrub.scrub`'s own default lister IS `os.walk` (runtime/scrub.py:184) — there is
        # no `scrub.walk`; wrapping the real default is what makes this a recording seam
        # rather than a second, hand-rolled walk that could disagree with the real one.
        entries = list(os.walk(*args, **kwargs))
        walked.extend(entries)
        return entries

    scrub_mod.scrub(res.run_dir, lister=recording_lister)

    names = [str(entry) for entry in walked]
    assert any("executed_queries.jsonl" in n for n in names), \
        f"scrub's walk never reached the queries table lead-0 wrote: {names[:20]}"
    assert any(f"gather_raw/{L0}" in n.replace("\\", "/") for n in names), \
        f"scrub's walk never reached lead-0's payload tree: {names[:20]}"


def test_the_adapters_own_default_index_read_still_agrees_with_lead_zeros(tmp_path):
    """N7 / R7 `interacts(elastic_adapter->ELASTIC_ALERTS_INDEX)` — lead-0 reading the alert's
    OWN `signal_index` leaves the adapter's existing default-resolution read of
    `ELASTIC_ALERTS_INDEX` coherent with it: the value the alert declares is one the shipped
    configuration still admits, so the two readers of the same source do not disagree about
    where this alert's own index lives.

    K16 minted this check: no checked-in input distinguishes the two readings (all five
    fixtures carry `signal_index` identical to the configured constant, r6/g20), which is
    exactly why the design never had to decide — and exactly why the unmoved reader needs its
    own demand rather than being covered by lead-0's."""
    res = run(tmp_path, run_id="lz808-coherence",
              alert=alert_doc(signal_index=ALERTS_INDEX), answer=answer_hits(DOCS))

    config = load_config(VerbContext(defender_dir=defender_dir(), run_dir=res.run_dir, env={}))
    assert config["ELASTIC_ALERTS_INDEX"] == ALERTS_INDEX, \
        "the adapter's configured alerts pattern moved out from under this fixture"
    assert config["ELASTIC_EVENTS_INDEX"] == EVENTS_INDEX
    assert res.shell_call.params["index"] == config["ELASTIC_ALERTS_INDEX"], (
        "lead-0 and the adapter's own default resolution now name different alerts indices "
        "for the same alert"
    )
