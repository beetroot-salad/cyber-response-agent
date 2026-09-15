"""#860 end to end — the family judge sees every refused attempt a lead made, by lead.

THE GAP. A verb withheld from the role (`decide` -> DENIED in `query_tool._grant_check`)
writes a record to `<run_dir>/policy_denials.jsonl` with no `lead_id`, and that file is not in
`archive._single_files`, so it never reaches `worlds/<w>/`. The `∅.`-prefixed sentinel rows
(`JoinedLead.sentinels`) DO reach the archive, but `family.lead_chain` reads `.queries` only.
So a lead whose only activity was refused or denied is invisible to the judge's VIEW 1 — or
absent from it altogether when it is cited by neither `investigation.md` nor a gather
summary — and the judge concludes the defender never queried that system (`lead-set`), and the
curator writes a lesson telling the runtime to run a query the role does not hold.

WHAT IS DRIVEN, and why live where it can be: the denial record through the REAL gather entry
point (`run_gather`: real dispatch, real grant check, real denial writer); the archive through
the REAL `archive_episode` over a REAL symlink on disk; the join through the REAL
`lead_repository.joined`; VIEW 1 through the REAL `learning.judge.render.render`; the prompt
through the REAL judge pass with the `judge=` seam recording what it was shown. Hand-written
rows carry the key set the real writers leave (`record_query.QUERY_ROW_COLUMNS` via the #1017
fixtures; the denial record's keys, cross-checked against the real writer below).

Obligation ids (O1–O5), non-obligations (N1–N8) and mechanisms (M1–M6) are the design doc's
(issue #860, "Intent + design — settled 2026-09-15").
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender._io import append_jsonl, read_jsonl_rows  # noqa: E402
from defender.learning.lead_repository import joined  # noqa: E402
from defender.runtime import observe  # noqa: E402
from defender.runtime.circuit_breaker import (  # noqa: E402
    AGENT_FIXABLE_ERROR_CLASS,
    INFRA_ERROR_CLASS,
)
from defender.scripts.gather_tools.record_query import (  # noqa: E402
    ABOVE_GUARD_QUERY_ID,
    BASH_SHIM_QUERY_ID,
    REJECTION_BUDGET,
    REPEAT_TRIP_QUERY_ID,
    RESERVED_QUERY_ID_PREFIX,
)
from defender.tests import _judge_921 as J  # noqa: E402
from defender.tests import _triplet_947 as T  # noqa: E402
from defender.tests._verb_authorization_632 import (  # noqa: E402
    DONE,
    LEAD,
    q,
    run_gather,
)
from defender.tests.e2e._replay_harness import VerbRecorder  # noqa: E402
# The #1017 judge-world builders: an accepted #947 episode whose graded world `b` is run-dir
# shaped, rendered through the REAL `render` with the runs-base seam pointed at the test's own.
from defender.tests.e2e.test_1017_query_row_surface import (  # noqa: E402
    _judge_world,
    _leads_view,
    _world_row,
)
from defender.tests.test_1017_row_schema import (  # noqa: E402
    KEY_MARKER,
    SHA_MARKER,
    _lead_file,
    _table,
)
from defender.tests.test_denial_gather_632 import DENIED_PAIR, _registry  # noqa: E402

pytestmark = pytest.mark.e2e

#: M1 — the denial record's key set AFTER the change, spelled as a literal (an expectation
#: recovered from the writer could not fail). `test_m1_*` below ties the fixture rows this file
#: hand-writes to what the REAL writer leaves, so the two cannot drift apart silently.
DENIAL_KEYS = frozenset({
    "event_type", "ts", "seq", "role", "system", "verb", "call_id", "params_digest", "lead_id",
})

#: M6 — the per-lead chain's key set and each `refused` entry's, as literals.
CHAIN_KEYS = frozenset({"goal", "params", "payload", "summary", "resolutions", "refused"})
SENTINEL_ENTRY_KEYS = frozenset({"kind", "system", "external"})
DENIAL_ENTRY_KEYS = frozenset({"kind", "system", "verb", "external"})

#: The columns the design says a `refused` entry NEVER carries (O4/M4). Key names, checked
#: against the entries; their VALUES are planted as markers and checked against the text.
NEVER_RENDERED = (
    "params", "detail", "raw_command", "payload_digest", "payload_sha256", "system_key",
    "params_digest",
)



@pytest.fixture
def judge_roots(tmp_path, monkeypatch):
    """Mirrors `test_1017_query_row_surface.judge_roots` — the three roots #921's suite points
    inside `tmp_path` (runs base, episodes root, learning state dir), so a render or a judge
    pass here reads and writes nothing of the checkout's. Kept local rather than imported so
    the fixture name, used as a parameter below, never collides with a module-level import
    binding (ruff F811) — the `test_984` idiom. `setenv`, never `setattr`."""
    monkeypatch.setenv(J.RUNS_BASE_ENV, str(tmp_path / "defender-runs"))
    monkeypatch.setenv(J.EPISODES_BASE_ENV, str(tmp_path / "episodes-root"))
    monkeypatch.setenv(J.STATE_DIR_ENV, str(tmp_path / "learning-state"))


DENIED_LEAD = "l-002"
SENTINEL_LEAD = "l-003"
ORPHAN_LEAD = "l-004"
EMPTY_LEAD = "l-005"


def _denial_row(seq: int, *, lead_id, system: str = "ticket", verb: str = "get-ticket",
                **overrides) -> dict:
    """One policy-denial record as the REAL writer keys it (`DENIAL_KEYS`), with a DISTINCTIVE
    value in the two columns the judge must never see (`call_id`, `params_digest`) so each can
    be searched for in the rendered leads section. `lead_id` is keyword-only and required:
    which lead a fixture row names is the whole of what each scenario states."""
    row = {
        "event_type": observe.POLICY_DENIAL_EVENT_TYPE,
        "ts": "2026-09-15T12:00:00+00:00",
        "seq": seq,
        "role": "gather",
        "system": system,
        "verb": verb,
        "call_id": f"CALLID_MARKER_{seq}",
        "params_digest": f"PDIGEST_MARKER_{seq}",
        "lead_id": lead_id,
    }
    row.update(overrides)
    return row


def _denials(run_dir: Path, rows: list[dict]) -> Path:
    """`rows` appended as `run_dir`'s denial stream, at the name the runtime writer uses."""
    path = run_dir / observe.POLICY_DENIALS
    append_jsonl(path, rows)
    return path


def _sentinel(seq: int, query_id: str, *, error_class: str = AGENT_FIXABLE_ERROR_CLASS,
              system: str = "elastic", lead_id: str = SENTINEL_LEAD, **overrides) -> dict:
    """One `∅.` row on `lead_id`, full fourteen columns, with a DISTINCTIVE value in every
    column O4 says must not reach the judge: `params` and `raw_command` (`_world_row`'s own
    markers), the writer's `detail` (which lands in `payload_digest` as `exit=N; <detail>`),
    `payload_sha256`, `system_key`, and a model-authored `verb`. `exit_code` follows the
    class the way the writers leave it (2 for `infra`, 64 otherwise)."""
    exit_code = 2 if error_class == INFRA_ERROR_CLASS else 64
    return _world_row(
        seq, lead_id=lead_id, query_id=query_id, system=system, verb=f"VERB_MARKER_{seq}",
        exit_code=exit_code, error_class=error_class, payload_status="error",
        payload_digest=f"exit={exit_code}; DETAIL_MARKER_{seq}",
        payload_sha256=SHA_MARKER, system_key=KEY_MARKER, **overrides,
    )


def _entry(kind: str, system: str, external: bool, verb: str | None = None) -> dict:
    """One expected `refused` entry, in the design's key order (M4)."""
    if verb is None:
        return {"kind": kind, "system": system, "external": external}
    return {"kind": kind, "system": system, "verb": verb, "external": external}


def _refusal_world(tmp_path: Path):
    """The O1 world: graded world `b` whose lead `l-001` (referenced by `investigation.md`,
    with a gather summary) ran nothing, plus four leads cited by NEITHER `investigation.md`
    NOR a `gather_summaries/*.md`:

    * `l-002` — a lead file and ONE withheld-verb denial (`ticket.get-ticket`), no rows;
    * `l-003` — a lead file and ONE `∅.above-repeat-guard` row (a schema rejection), no summary;
    * `l-004` — NO lead file, ONE `∅.repeat-trip` row (an orphan the join still yields);
    * `l-005` — a lead file and nothing else at all.

    Returns `(episode_dir, runs_base, world_dir)`."""
    rows = [
        _sentinel(0, ABOVE_GUARD_QUERY_ID, system="", lead_id=SENTINEL_LEAD),
        _sentinel(0, REPEAT_TRIP_QUERY_ID, lead_id=ORPHAN_LEAD),
    ]
    ep, base, world = _judge_world(tmp_path, rows)
    _lead_file(world, "DENIED_LEAD_GOAL", lead_id=DENIED_LEAD)
    _lead_file(world, "SENTINEL_LEAD_GOAL", lead_id=SENTINEL_LEAD)
    _lead_file(world, "EMPTY_LEAD_GOAL", lead_id=EMPTY_LEAD)
    _denials(world, [_denial_row(0, lead_id=DENIED_LEAD)])
    # The shape O1 is stated over: none of the four is cited anywhere the old builder looked.
    investigation = (world / "investigation.md").read_text(encoding="utf-8")
    for lid in (DENIED_LEAD, SENTINEL_LEAD, ORPHAN_LEAD, EMPTY_LEAD):
        assert lid not in investigation, f"the fixture cites {lid} in investigation.md"
        assert not (world / "gather_summaries" / f"{lid}.md").exists(), \
            f"the fixture wrote a summary for {lid}"
    return ep, base, world


# ---------------------------------------------------------------------------------------
# O1 / M4 / M4b — the refusal-only lead is on VIEW 1, with its refusal
# ---------------------------------------------------------------------------------------


def test_o1_a_lead_with_only_a_denial_is_on_view_1_with_its_refusal(tmp_path, judge_roots):
    """O1/M3/M4/M4b — a lead whose ONLY activity is a withheld-verb denial, cited by neither
    `investigation.md` nor a gather summary, is on VIEW 1 with its goal and a `refused` entry
    naming the system, the verb, and that the refusal was external; the rendered leads
    section carries the lead's heading and the entry's own values.

    Observed failing by: the lead missing from VIEW 1 (today: the lead-id set is built from
    references and summaries alone), or present with an empty `refused:`."""
    ep, base, _world = _refusal_world(tmp_path)
    leads, text = _leads_view(ep, base)

    assert DENIED_LEAD in leads, f"the denial-only lead is not on VIEW 1: {sorted(leads)}"
    chain = leads[DENIED_LEAD]
    assert chain["goal"] == "DENIED_LEAD_GOAL"
    assert chain["params"] is None, "a denial rendered as a query with params"
    assert chain["payload"] == [], "a denial rendered as a query with a payload"
    assert chain["refused"] == [_entry("denied", "ticket", True, verb="get-ticket")]
    assert f"### {DENIED_LEAD}" in text
    assert "- refused: " in text
    for token in ("'kind': 'denied'", "'system': 'ticket'", "'verb': 'get-ticket'",
                  "'external': True"):
        assert token in text, f"the leads section does not carry {token}"


def test_o1_a_lead_with_only_a_sentinel_row_is_on_view_1_with_its_refusal(tmp_path, judge_roots):
    """O1/M4/M4b — a lead whose only row is a `∅.above-repeat-guard` schema rejection (no
    query, no summary, no reference) is on VIEW 1 with `refused` naming the rejection as the
    defender's own conduct (`external: False`); and an ORPHAN lead (no lead file, one
    `∅.repeat-trip` row) is on VIEW 1 too, since `joined()` yields it and its `sentinels` is
    non-empty. Neither renders as a query: `params` is `None`, `payload` is empty.

    Observed failing by: either lead missing from VIEW 1, or on it with an empty `refused:`."""
    ep, base, _world = _refusal_world(tmp_path)
    leads, text = _leads_view(ep, base)

    assert SENTINEL_LEAD in leads, f"the sentinel-only lead is not on VIEW 1: {sorted(leads)}"
    assert leads[SENTINEL_LEAD]["goal"] == "SENTINEL_LEAD_GOAL"
    assert leads[SENTINEL_LEAD]["params"] is None
    assert leads[SENTINEL_LEAD]["payload"] == []
    assert leads[SENTINEL_LEAD]["refused"] == [_entry("rejected-before-dispatch", "", False)]

    assert ORPHAN_LEAD in leads, f"the orphan sentinel-only lead is not on VIEW 1: {sorted(leads)}"
    assert leads[ORPHAN_LEAD]["goal"] is None
    assert leads[ORPHAN_LEAD]["refused"] == [_entry("repeat-refused", "elastic", False)]

    assert f"### {SENTINEL_LEAD}" in text
    assert f"### {ORPHAN_LEAD}" in text
    assert "'kind': 'rejected-before-dispatch'" in text
    assert "'kind': 'repeat-refused'" in text
    assert "'external': False" in text


def test_m4b_the_lead_id_set_grows_by_refusals_only(tmp_path, judge_roots):
    """M4b — the boundary of the widened lead-id set: a lead with a lead file and NOTHING
    else (no query, no sentinel, no denial, no summary, no reference) stays ABSENT from VIEW 1,
    while — the positive control in the same world — the refusal-only leads are present. The
    builder adds the ids whose lead has a non-empty `sentinels` or `denials`, not every id the
    join knows.

    Observed failing by: `l-005` on VIEW 1 (the builder took every joined lead), or the
    refusal-only leads absent (the builder took none)."""
    ep, base, world = _refusal_world(tmp_path)
    assert (world / "gather_raw" / f"{EMPTY_LEAD}.lead.json").is_file(), \
        "the fixture did not write the empty lead's file — the boundary claim is vacuous"
    leads, text = _leads_view(ep, base)

    assert EMPTY_LEAD not in leads, "a lead with no refusal and no citation reached VIEW 1"
    assert f"### {EMPTY_LEAD}" not in text
    assert "EMPTY_LEAD_GOAL" not in text
    assert {DENIED_LEAD, SENTINEL_LEAD, ORPHAN_LEAD} <= set(leads), \
        f"the refusal-only leads are not all on VIEW 1: {sorted(leads)}"
    # The old sources are still honoured: the referenced/summarised lead is there too.
    assert "l-001" in leads


# ---------------------------------------------------------------------------------------
# M4 — the kind mapping, `external`, and the order of a mixed `refused` list
# ---------------------------------------------------------------------------------------


def test_m4_every_sentinel_origin_maps_to_its_kind_and_external_follows_infra(
    tmp_path, judge_roots,
):
    """M4 — on one lead, one row per sentinel origin, and the `refused` list is EXACTLY, in
    seq order:

    * `∅.above-repeat-guard` + `infra`          -> `adapter-fault`, external True (the one
      external sentinel origin — the adapter could not load);
    * `∅.above-repeat-guard` + `agent-fixable`  -> `rejected-before-dispatch`, external False;
    * `∅.repeat-trip`                           -> `repeat-refused`, external False;
    * `∅.bash-shim`                             -> `reducer-failed`, external False;
    * an unknown `∅.` literal                   -> `refused`, external False;
    * `∅.repeat-trip` + `infra`                 -> `repeat-refused`, external TRUE — the design
      makes `external` `row.error_class == "infra"` for EVERY sentinel row and keys `kind` on
      the literal alone (only `∅.above-repeat-guard` splits on the class); this row is not a
      shape today's writers leave, and it is pinned so the two derivations stay separate.

    `system` is the row's own (`""` where the writer coarsened it). No entry carries a `verb`.

    Observed failing by: any kind wrong, `external` not following `error_class`, or the list
    not in seq order."""
    rows = [
        _sentinel(0, ABOVE_GUARD_QUERY_ID, error_class=INFRA_ERROR_CLASS, system="elastic"),
        _sentinel(1, ABOVE_GUARD_QUERY_ID, system=""),
        _sentinel(2, REPEAT_TRIP_QUERY_ID),
        _sentinel(3, BASH_SHIM_QUERY_ID, system=""),
        _sentinel(4, f"{RESERVED_QUERY_ID_PREFIX}some-future-origin"),
        _sentinel(5, REPEAT_TRIP_QUERY_ID, error_class=INFRA_ERROR_CLASS),
    ]
    ep, base, world = _judge_world(tmp_path, rows)
    _lead_file(world, "MAPPED", lead_id=SENTINEL_LEAD)
    leads, _text = _leads_view(ep, base)

    assert leads[SENTINEL_LEAD]["refused"] == [
        _entry("adapter-fault", "elastic", True),
        _entry("rejected-before-dispatch", "", False),
        _entry("repeat-refused", "elastic", False),
        _entry("reducer-failed", "", False),
        _entry("refused", "elastic", False),
        _entry("repeat-refused", "elastic", True),
    ]


def test_m4_both_origins_on_one_lead_render_sentinels_first_then_each_by_its_own_seq(
    tmp_path, judge_roots,
):
    """M4 — a lead with rows from BOTH origins: `refused` lists every sentinel row (by the
    table's seq) and THEN every denial (by the denial stream's own seq). The seqs are chosen
    so a naive merge on the number orders differently — sentinels at 5 and 7, denials at 0
    and 1 — and each origin is written to its file in REVERSE seq order, so file order is
    ruled out too. The two counters are different streams (M1: "denial `seq` stays the denial
    stream's own"), which is why they are not merged.

    Observed failing by: denials before sentinels, or either origin in file order."""
    rows = [
        _sentinel(7, BASH_SHIM_QUERY_ID, lead_id=DENIED_LEAD),
        _sentinel(5, REPEAT_TRIP_QUERY_ID, lead_id=DENIED_LEAD),
    ]
    ep, base, world = _judge_world(tmp_path, rows)
    _lead_file(world, "MIXED", lead_id=DENIED_LEAD)
    _denials(world, [
        _denial_row(1, lead_id=DENIED_LEAD, verb="key-pattern"),
        _denial_row(0, lead_id=DENIED_LEAD, verb="get-ticket"),
    ])
    leads, _text = _leads_view(ep, base)

    assert leads[DENIED_LEAD]["refused"] == [
        _entry("repeat-refused", "elastic", False),
        _entry("reducer-failed", "elastic", False),
        _entry("denied", "ticket", True, verb="get-ticket"),
        _entry("denied", "ticket", True, verb="key-pattern"),
    ]


# ---------------------------------------------------------------------------------------
# M6 / O4 — the key sets are pinned, and no model-authored text crosses
# ---------------------------------------------------------------------------------------


def test_m6_the_chain_and_each_refused_entry_carry_exactly_their_named_keys(
    tmp_path, judge_roots,
):
    """M6 — the per-lead chain's key set is `{goal, params, payload, summary, resolutions,
    refused}`; a sentinel-origin entry's is exactly `{kind, system, external}` (NO `verb` —
    above the guard it is the model's raw string); a denial-origin entry's is exactly `{kind,
    system, verb, external}`. A column reaches the model only by being named here. And for a
    lead id the surface does not know (referenced by `investigation.md`, but with no lead
    file and no row), `refused` is `[]` — the chain still carries every key.

    Observed failing by: a key set differing from the literal, or a never-rendered column's
    name appearing as an entry key."""
    rows = [_sentinel(0, ABOVE_GUARD_QUERY_ID, lead_id=SENTINEL_LEAD)]
    ep, base, world = _judge_world(tmp_path, rows)
    _lead_file(world, "S", lead_id=SENTINEL_LEAD)
    _lead_file(world, "D", lead_id=DENIED_LEAD)
    _denials(world, [_denial_row(0, lead_id=DENIED_LEAD)])
    leads, _text = _leads_view(ep, base)

    for lid in ("l-001", SENTINEL_LEAD, DENIED_LEAD):
        assert set(leads[lid]) == CHAIN_KEYS, \
            f"{lid}: the chain carries {sorted(set(leads[lid]) ^ CHAIN_KEYS)} beyond/short of the pin"
    (sentinel_entry,) = leads[SENTINEL_LEAD]["refused"]
    (denial_entry,) = leads[DENIED_LEAD]["refused"]
    assert set(sentinel_entry) == SENTINEL_ENTRY_KEYS, \
        f"a sentinel-origin entry is keyed {sorted(sentinel_entry)}"
    assert set(denial_entry) == DENIAL_ENTRY_KEYS, \
        f"a denial-origin entry is keyed {sorted(denial_entry)}"
    for name in NEVER_RENDERED:
        assert name not in sentinel_entry, f"{name!r} is a key of a sentinel-origin entry"
        assert name not in denial_entry, f"{name!r} is a key of a denial-origin entry"
    assert leads["l-001"]["refused"] == [], "a lead with no refusal carries a refused entry"

    # The unknown-id arm: referenced by the document, unknown to the surface.
    ep2 = J.accepted_episode(tmp_path / "unknown", ledgers={"b": [J.staged_row("b")], "c": []})
    base2, _src = J.runs_base(tmp_path / "unknown")
    world2 = ep2 / "worlds" / "b"
    assert not (world2 / "gather_raw" / "l-001.lead.json").exists()
    leads2, _text2 = _leads_view(ep2, base2)
    assert leads2["l-001"]["goal"] is None, "the arm's lead is known to the surface after all"
    assert set(leads2["l-001"]) == CHAIN_KEYS
    assert leads2["l-001"]["refused"] == []


def test_o4_no_model_authored_text_reaches_view_1_through_the_refused_section(
    tmp_path, judge_roots,
):
    """O4/M4 — with a DISTINCTIVE value planted in every column the design says is never
    rendered (`params`, the writer's `detail` inside `payload_digest`, `raw_command`,
    `payload_sha256`, `system_key`, the denial's `params_digest` and `call_id`) AND a hostile
    model-authored `verb` on every sentinel row (an above-guard row's `verb` is whatever the
    model sent), NONE of those values reaches the rendered leads section — while, on the SAME
    string, the `refused` entries' own `kind` / `system` / `verb` / `external` values DO, so
    the negatives are not satisfied by an empty section.

    Observed failing by: any marker in the leads section — a `verb` copied onto a sentinel
    entry, a `detail` rendered as a reason, a row stringified whole."""
    rows = [
        _sentinel(0, ABOVE_GUARD_QUERY_ID, system="", lead_id=SENTINEL_LEAD),
        _sentinel(1, REPEAT_TRIP_QUERY_ID, lead_id=SENTINEL_LEAD),
        _sentinel(2, BASH_SHIM_QUERY_ID, lead_id=SENTINEL_LEAD),
        _sentinel(3, ABOVE_GUARD_QUERY_ID, error_class=INFRA_ERROR_CLASS, lead_id=SENTINEL_LEAD),
    ]
    ep, base, world = _judge_world(tmp_path, rows)
    _lead_file(world, "S", lead_id=SENTINEL_LEAD)
    _lead_file(world, "D", lead_id=DENIED_LEAD)
    _denials(world, [_denial_row(0, lead_id=DENIED_LEAD)])
    leads, text = _leads_view(ep, base)

    # Positive control first: the section carries what it is for.
    assert leads[SENTINEL_LEAD]["refused"] == [
        _entry("rejected-before-dispatch", "", False),
        _entry("repeat-refused", "elastic", False),
        _entry("reducer-failed", "elastic", False),
        _entry("adapter-fault", "elastic", True),
    ]
    assert leads[DENIED_LEAD]["refused"] == [_entry("denied", "ticket", True, verb="get-ticket")]
    for kept in (
        "'kind': 'rejected-before-dispatch'", "'kind': 'repeat-refused'",
        "'kind': 'reducer-failed'", "'kind': 'adapter-fault'", "'kind': 'denied'",
        "'system': 'ticket'", "'verb': 'get-ticket'", "'external': True", "'external': False",
    ):
        assert kept in text, f"the leads section lost {kept} — VIEW 1's refused content"

    for seq in range(4):
        for marker in (f"VERB_MARKER_{seq}", f"PARAMS_MARKER_{seq}", f"RAWCMD_MARKER_{seq}",
                       f"DETAIL_MARKER_{seq}"):
            assert marker not in text, f"{marker!r} reached the judge's prompt"
    for marker in (SHA_MARKER, KEY_MARKER, "CALLID_MARKER_0", "PDIGEST_MARKER_0", "exit=64",
                   "exit=2"):
        assert marker not in text, f"{marker!r} reached the judge's prompt"
    for name in ("params_digest", "system_key", "payload_sha256", "raw_command", "call_id",
                 "detail", "error_class", "exit_code"):
        assert name not in text, f"the column name {name!r} reached the judge's prompt"


# ---------------------------------------------------------------------------------------
# N4 / M3 — attribution: by `lead_id`, and only to a lead the surface knows
# ---------------------------------------------------------------------------------------


def test_n4_an_unattributable_denial_attaches_to_no_lead_and_renders_nowhere(
    tmp_path, judge_roots,
):
    """N4/M3 — three denial records the join cannot attribute — one whose `lead_id` names no
    lead file and no query row, one LEGACY record with no `lead_id` key at all (written before
    M1), one with `lead_id: null` (no lead context) — are on no `JoinedLead.denials`, put no
    lead on VIEW 1 and reach no `refused` entry; their systems are searched for in the leads
    section. The positive control in the SAME world is a record whose `lead_id` names a lead
    file, which is attached and rendered.

    Observed failing by: `l-999` on VIEW 1, a ghost system in the section, or a stray denial
    attached to whichever lead came first."""
    ep, base, world = _judge_world(tmp_path, [])
    _lead_file(world, "D", lead_id=DENIED_LEAD)
    legacy = _denial_row(1, lead_id=None, system="ghostsys-legacy")
    del legacy["lead_id"]
    _denials(world, [
        _denial_row(0, lead_id="l-999", system="ghostsys-unknown"),
        legacy,
        _denial_row(2, lead_id=None, system="ghostsys-null"),
        _denial_row(3, lead_id=DENIED_LEAD),
    ])
    assert set(read_jsonl_rows(world / observe.POLICY_DENIALS)[1]) == DENIAL_KEYS - {"lead_id"}, \
        "the legacy fixture row grew the column"

    surface = {lead.lead_id: lead for lead in joined(world)}
    assert "l-999" not in surface, "the join invented a lead out of a denial"
    attached = {(lead_id, d.system) for lead_id, lead in surface.items() for d in lead.denials}
    assert attached == {(DENIED_LEAD, "ticket")}, f"denials attached: {attached}"

    leads, text = _leads_view(ep, base)
    assert leads[DENIED_LEAD]["refused"] == [_entry("denied", "ticket", True, verb="get-ticket")]
    assert "'system': 'ticket'" in text
    assert "l-999" not in leads, "a denial with no lead put a lead on VIEW 1"
    assert "l-999" not in text
    for ghost in ("ghostsys-unknown", "ghostsys-legacy", "ghostsys-null"):
        assert ghost not in text, f"an unattributable denial's system {ghost!r} reached VIEW 1"
    assert leads["l-001"]["refused"] == [], "an unattributable denial landed on another lead"


def test_m3_the_join_attaches_denials_by_lead_id_and_changes_nothing_else(tmp_path):
    """M3 — over a run-dir-shaped tree holding a lead with one query row, one sentinel row
    and one denial: `queries` is the one query, `sentinels` the one sentinel, `denials` the one
    denial typed `(seq, system, verb, lead_id)` off the record; and `queries` and `sentinels`
    are EXACTLY what the join answered before the denial file existed (the positive control:
    the same tree, the file removed). A denial whose `lead_id` names a lead that has a query
    row but NO lead file (an orphan) is attached too — "no lead file AND no query row" is the
    drop rule, not "no lead file".

    Observed failing by: `denials` missing or mis-typed, a denial widening `queries` or
    `sentinels`, or the orphan's denial dropped."""
    run_dir = tmp_path / "run"
    _lead_file(run_dir, "G", lead_id=DENIED_LEAD)
    _table(run_dir, [
        _world_row(0, lead_id=DENIED_LEAD),
        _sentinel(1, REPEAT_TRIP_QUERY_ID, lead_id=DENIED_LEAD),
        _world_row(0, lead_id=ORPHAN_LEAD),
    ])
    before = {lead.lead_id: lead for lead in joined(run_dir)}
    assert set(before) == {DENIED_LEAD, ORPHAN_LEAD}
    assert before[ORPHAN_LEAD].orphan, "the fixture's orphan has a lead file after all"

    _denials(run_dir, [
        _denial_row(3, lead_id=DENIED_LEAD),
        _denial_row(4, lead_id=ORPHAN_LEAD, system="cmdb", verb="list-roles"),
    ])
    after = {lead.lead_id: lead for lead in joined(run_dir)}
    assert set(after) == set(before), "the denial file changed which leads join"
    for lid in before:
        assert after[lid].queries == before[lid].queries, f"{lid}: queries changed"
        assert after[lid].sentinels == before[lid].sentinels, f"{lid}: sentinels changed"
    assert len(after[DENIED_LEAD].queries) == 1
    assert len(after[DENIED_LEAD].sentinels) == 1
    assert [(d.seq, d.system, d.verb, d.lead_id) for d in after[DENIED_LEAD].denials] \
        == [(3, "ticket", "get-ticket", DENIED_LEAD)]
    assert [(d.seq, d.system, d.verb, d.lead_id) for d in after[ORPHAN_LEAD].denials] \
        == [(4, "cmdb", "list-roles", ORPHAN_LEAD)]
    assert isinstance(after[DENIED_LEAD].denials[0].seq, int)


# ---------------------------------------------------------------------------------------
# M1 — the record carries its lead, through the real gather entry point
# ---------------------------------------------------------------------------------------


def test_m1_a_real_denial_inside_a_dispatched_lead_records_that_leads_id(tmp_path):
    """M1 — a REAL denied call (`elastic.esql`, declared and withheld) inside a REAL dispatched
    gather lead leaves a record in `policy_denials.jsonl` whose `lead_id` is that lead's and
    whose key set is exactly `{event_type, ts, seq, role, system, verb, call_id, params_digest,
    lead_id}`. The positive control that the id is the DISPATCHING lead's and not a constant:
    lead-0's own harness-authored `elastic.alerts` attempt (declared, ungranted under this
    registry, issued before main's first turn) is the stream's first record and carries
    `l-000`. And the fixture rows this file hand-writes are keyed exactly as the real writer
    keys its record, so the rendered-view scenarios above are stated over the real shape.

    Observed failing by: no `lead_id` on the record (today), a `lead_id` that is not the
    lead's, or a key set that differs from the pin."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=_registry(rec), turns=[q(*DENIED_PAIR), DONE], run_id="d860")

    assert rec.calls == [], "the denied verb body ran"
    assert r.own_rows == [], "a denied call wrote an evidence row"
    assert len(r.own_denials) == 1, "the denial was not audited"
    own = r.own_denials[0]
    assert set(own) == DENIAL_KEYS, f"the record is keyed {sorted(own)}"
    assert own["lead_id"] == LEAD, f"the record names {own['lead_id']!r}, not the dispatched lead"
    assert (own["system"], own["verb"]) == DENIED_PAIR

    first = r.denials[0]
    assert first["verb"] == "alerts", "lead-0's attempt is not the stream's first record"
    assert first["lead_id"] == "l-000", f"lead-0's denial names {first['lead_id']!r}"
    assert {d["lead_id"] for d in r.denials} == {"l-000", LEAD}

    assert set(_denial_row(0, lead_id=LEAD)) == set(own), \
        "this file's fixture rows are keyed differently from the real writer's record"


# ---------------------------------------------------------------------------------------
# O3 — recording the lead changes nothing about the live run (unchanged behaviour)
# ---------------------------------------------------------------------------------------


def test_o3_denials_count_toward_no_guard_no_budget_and_no_abort(tmp_path):
    """O3 — a run with more identical denied calls than the rejection budget on one identity
    (`REJECTION_BUDGET + 1`, past the repeat guard's third occurrence and past
    `RUN_FAIL_KILL_LIMIT`) followed by a GRANTED call: the granted call still executes (the
    lead was not dead-ended), no `∅.repeat-trip` row is written, the run reaches its close
    (no abort), the breaker holds no charge, and every denial is on the stream. The positive
    control that the guard CAN dead-end this shape: the same count of an UNDECLARED verb
    (which writes `∅.above-repeat-guard` rows) ends the lead before its granted call runs.

    GREEN BY DESIGN against today's code — the denial path writes no table row and charges
    nothing, and this pins that M1 keeps it so (N5).

    Observed failing by: the granted call not running, a trip row, `main.calls != 2`, or a
    breaker charge."""
    n = REJECTION_BUDGET + 1
    granted = q("elastic", "query", {"native_query": "FROM logs"})
    rec = VerbRecorder()
    r = run_gather(tmp_path / "denied", verbs=_registry(rec),
                   turns=[*(q(*DENIED_PAIR) for _ in range(n)), granted, DONE], run_id="d860-o3")
    assert len(r.own_denials) == n, "not every denial was audited"
    assert len(rec.calls) == 1, "the granted call after the denials never ran — the lead dead-ended"
    assert [row["query_id"] for row in r.own_rows] == ["elastic.query"], \
        f"the denials left rows: {[row['query_id'] for row in r.own_rows]}"
    assert r.main.calls == 2, "the run did not reach its close"
    assert r.breaker.get("total_failures", 0) == 0
    assert r.breaker.get("systems", {}) == {}

    control = VerbRecorder()
    c = run_gather(tmp_path / "undeclared", verbs=_registry(control),
                   turns=[*(q("elastic", "nosuch-verb") for _ in range(n)), granted, DONE],
                   run_id="d860-o3-control")
    assert control.calls == [], "the undeclared-verb control did not dead-end — the guard is inert"
    assert c.own_rows, "the control left no rows — it did not reach the guard"
    assert all(row["query_id"] == ABOVE_GUARD_QUERY_ID for row in c.own_rows)


def test_o3_a_denial_leaves_no_pitfalls_row(tmp_path):
    """O3 — through the real join and the real pitfalls collector, a lead whose only activity
    was a denied call contributes NO pitfalls record; the positive control is the same shape
    with an undeclared verb, which contributes exactly one (the `agent-fixable` rejection row
    #823 routes to the curator).

    GREEN BY DESIGN against today's code; pinned so recording the lead never turns a denial
    into a curator input.

    Observed failing by: a pitfalls record for the denied lead."""
    from defender.learning.leads import lead_extraction
    from defender.learning.leads.lead_extraction import collect_general_failures

    def own_pitfalls(run_dir: Path) -> list[dict]:
        leads = [lead for lead in lead_extraction.extract_from_joined(joined(run_dir))
                 if lead.lead_id == LEAD]
        return [p for p in collect_general_failures(leads, run_dir)
                if p.get("pitfall_id", "").split(":")[1:2] == [LEAD]]

    rec = VerbRecorder()
    denied = run_gather(tmp_path / "denied", verbs=_registry(rec),
                        turns=[q(*DENIED_PAIR), DONE], run_id="d860-pf")
    assert len(denied.own_denials) == 1
    assert own_pitfalls(denied.run_dir) == []

    undeclared = run_gather(tmp_path / "undeclared", verbs=_registry(rec),
                            turns=[q("elastic", "nosuch-verb"), DONE], run_id="d860-pf-control")
    assert len(own_pitfalls(undeclared.run_dir)) == 1, \
        "the undeclared-verb control reached no pitfalls record — the negative above is vacuous"


# ---------------------------------------------------------------------------------------
# O5 / M2 — the denial file is archived, and a link at its name is refused
# ---------------------------------------------------------------------------------------


def _real_denial_file(run_dir: Path, *, lead_id: str | None = None, verb: str = "get-ticket") -> Path:
    """`policy_denials.jsonl` in `run_dir`, written by the REAL writer (one record)."""
    path = run_dir / observe.POLICY_DENIALS
    logger = observe.RequestLogger(path)
    kwargs = {} if lead_id is None else {"lead_id": lead_id}
    logger.log_policy_denial(role="gather", system="ticket", verb=verb, call_id=f"ticket.{verb}",
                             params={"ticket_id": "T-1"}, **kwargs)
    logger.close()
    assert path.is_file()
    assert path.stat().st_size > 0, "the real writer left an empty stream"
    return path


def test_o5_a_link_at_the_denial_files_name_is_refused_and_a_file_is_copied_byte_for_byte(
    tmp_path,
):
    """O5/M2 — three worlds through the REAL `archive_episode`:

    * `b`: a SYMLINK at `policy_denials.jsonl` pointing at a real denial stream elsewhere ->
      `ArchiveRefused`, and nothing is written at the archived name (the target's bytes are
      searched for);
    * `c`: a regular `policy_denials.jsonl` written by the real writer -> copied byte for
      byte to `worlds/c/policy_denials.jsonl` (the positive control);
    * `d`: no such file -> archived cleanly, with nothing at the name (absent is the common
      case, not a refusal).

    Observed failing by: the link followed (today: the name is not screened, and not copied
    either), the regular file not copied, or the absent file refused."""
    base, _src = T.runs_base(tmp_path)
    archive = T.mod("learning.branch.archive")

    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    target = _real_denial_file(elsewhere, verb="key-pattern")
    ep_link = T.episode(tmp_path / "link")
    linked = T.sibling_run_dir(base, "b")
    os.symlink(target, linked / observe.POLICY_DENIALS)
    assert (linked / observe.POLICY_DENIALS).is_symlink()
    assert read_jsonl_rows(linked / observe.POLICY_DENIALS)[0]["verb"] == "key-pattern", \
        "the link does not resolve to the planted stream, so the refusal below is vacuous"
    with pytest.raises(T.refusals()):
        archive.archive_episode(ep_link, {"b": linked})
    archived_name = ep_link / "worlds" / "b" / observe.POLICY_DENIALS
    assert not archived_name.exists(), \
        "the archive wrote something at the denial file's name after refusing the world"
    assert not archived_name.is_symlink(), "the archive re-planted the link"
    for p in ((ep_link / "worlds").rglob("*") if (ep_link / "worlds").exists() else ()):
        if p.is_file():
            assert "key-pattern" not in p.read_text(encoding="utf-8", errors="replace"), \
                f"the link's target bytes landed in the archive at {p}"

    ep_ok = T.episode(tmp_path / "ok")
    regular = T.sibling_run_dir(base, "c")
    source = _real_denial_file(regular)
    absent = T.sibling_run_dir(base, "d")
    assert not (absent / observe.POLICY_DENIALS).exists()
    archive.archive_episode(ep_ok, {"c": regular, "d": absent})
    copied = ep_ok / "worlds" / "c" / observe.POLICY_DENIALS
    assert copied.is_file(), "the regular denial file was not archived"
    assert not copied.is_symlink()
    assert copied.read_bytes() == source.read_bytes(), "the archived copy differs from the source"
    assert not (ep_ok / "worlds" / "d" / observe.POLICY_DENIALS).exists()
    assert (ep_ok / "worlds" / "d" / "report.md").is_file(), "the absent-file world did not archive"


def test_o5_a_link_at_the_archived_destination_name_is_refused_too(tmp_path):
    """O5/M2 — the destination side: with a regular denial file in the run dir and a SYMLINK
    planted at `worlds/<label>/policy_denials.jsonl` (the episode dir is reachable from a
    sibling box's rw bind), the archive refuses rather than writing the world's record
    wherever the link points.

    Observed failing by: the link's target receiving the run dir's bytes."""
    base, _src = T.runs_base(tmp_path)
    archive = T.mod("learning.branch.archive")
    ep = T.episode(tmp_path)
    run_dir = T.sibling_run_dir(base, "b")
    _real_denial_file(run_dir)
    sink = tmp_path / "sink.jsonl"
    sink.write_text("", encoding="utf-8")
    dest_dir = ep / "worlds" / "b"
    dest_dir.mkdir(parents=True)
    os.symlink(sink, dest_dir / observe.POLICY_DENIALS)
    with pytest.raises(T.refusals()):
        archive.archive_episode(ep, {"b": run_dir})
    assert sink.read_bytes() == b"", "the archive wrote through the planted destination link"


# ---------------------------------------------------------------------------------------
# M5 — the prompt says what `refused:` means
# ---------------------------------------------------------------------------------------


def _prompt_for_world_b(ep: Path, base: Path) -> str:
    """Drive the REAL episode-grading pass and hand back the prompt the model seam was shown
    for world `b`'s first draw."""
    judge = J.FakeJudge(default=J.as_reply_text(J.reply_doc()))
    J.mod("learning.judge").grade_episode(ep, judge=judge, runs_base=base)
    return judge.prompts[judge.agent_ids.index("judge:b:0")]


def test_m5_the_prompt_states_the_refused_rule_in_host_text(tmp_path, judge_roots):
    """O2/M5 — the judge's prompt, in its HOST text (outside every untrusted frame), states
    the rule for `refused:`: an entry with `external: true` on the family's holding system is
    an `observability` finding, never `lead-set`; `external: false` is the defender's own
    conduct; `evidence` may cite `executed_queries.jsonl` or `policy_denials.jsonl`. Pinned
    by its load-bearing tokens in ONE host paragraph rather than verbatim, so wording may move
    and a prompt without the rule still fails. The rule is host text and not a frame title: a
    heading inside a frame is data by the reader contract.

    Observed failing by: today's prompt, whose host text names neither `refused` nor
    `external` nor either evidence file."""
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    base, _src = J.runs_base(tmp_path)
    prompt = _prompt_for_world_b(ep, base)
    host = J.outside_untrusted_frames(prompt)

    for token in ("refused", "external", "observability", "lead-set",
                  "policy_denials.jsonl", "executed_queries.jsonl"):
        assert token in host, f"the prompt's host text does not name {token!r}"
    paragraphs = [p for p in host.split("\n\n") if "refused" in p]
    assert paragraphs, "no host paragraph mentions refused"
    assert any(
        "external" in p and "observability" in p and "lead-set" in p for p in paragraphs
    ), "no single host paragraph relates `refused` to `external`, `observability` and `lead-set`"
    assert any(
        "policy_denials.jsonl" in p and "executed_queries.jsonl" in p for p in paragraphs
    ), "the rule does not tell the judge which files `evidence` may cite for a refusal"


def test_m5_every_description_of_the_per_lead_chain_names_its_refused_link(tmp_path, judge_roots):
    """M5, and the attack deck's 2026-07-23 shape (PR #700): prose that DESCRIBES a section's
    content stays green while the content moves. The chain now carries `refused`, so every
    trusted sentence that enumerates the chain's links — the task's "per-lead chain (goal,
    params, payload, summary, resolutions)" in the host text, and VIEW 1's own title line
    inside its frame (`## VIEW 1 — PER-LEAD CHAIN (goal -> params -> ...)`) — names `refused`
    too; a description that lists the links and omits the new one tells the judge the line is
    not part of the view it was told to compare against.

    Observed failing by: a host paragraph or a VIEW 1 title line that enumerates the links
    (mentions `goal`, `params` and `payload`) without `refused`."""
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    base, _src = J.runs_base(tmp_path)
    prompt = _prompt_for_world_b(ep, base)
    host = J.outside_untrusted_frames(prompt)

    enumerations = [p for p in host.split("\n\n") if "goal" in p and "params" in p and "payload" in p]
    assert enumerations, "no host paragraph enumerates the chain's links — the fixture moved"
    for paragraph in enumerations:
        assert "refused" in paragraph, \
            f"a host description of the per-lead chain omits its refused link:\n{paragraph}"
    titles = [line for line in prompt.splitlines() if line.startswith("## ") and "VIEW 1" in line]
    assert len(titles) == 1, f"VIEW 1's title line is not where the port put it: {titles}"
    assert "goal" in titles[0], f"VIEW 1's title no longer enumerates the chain: {titles[0]}"
    assert "refused" in titles[0], \
        f"VIEW 1's title enumerates the chain without its refused link: {titles[0]}"


# ---------------------------------------------------------------------------------------
# The key flow, end to end
# ---------------------------------------------------------------------------------------


def test_key_flow_a_real_denial_record_reaches_the_judges_prompt_for_its_lead(
    tmp_path, judge_roots,
):
    """The design's key flow — `log_policy_denial(..., lead_id=<lead>)` in the sibling's run
    dir -> the REAL archive -> `worlds/b/policy_denials.jsonl` -> `joined()` attaches ->
    `lead_chain` renders -> the REAL judge pass shows the model, for lead `l-002` (cited by
    nothing else in the world), the line
    `- refused: [{'kind': 'denied', 'system': 'ticket', 'verb': 'get-ticket', 'external': True}]`
    inside VIEW 1, along with the lead's heading and goal. The record is written by the REAL
    writer with the M1 keyword, so this is red until M1, M2, M3 and M4 all hold.

    Observed failing by: the writer refusing `lead_id=`, the archive not copying the file,
    the join not attaching it, or the prompt for world `b` lacking the line."""
    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    base, _src = J.runs_base(tmp_path)
    world = ep / "worlds" / "b"
    run_dir = T.sibling_run_dir(base, "b")
    # The archive copies the run dir's documents over the fixture's; keep the ones the fixture
    # graded on, so the only difference the archive introduces is the denial file.
    for name in ("report.md", "investigation.md"):
        shutil.copyfile(world / name, run_dir / name)
    _lead_file(run_dir, "REFUSED_LEAD_GOAL", lead_id=DENIED_LEAD)
    _real_denial_file(run_dir, lead_id=DENIED_LEAD)

    T.mod("learning.branch.archive").archive_episode(ep, {"b": run_dir})
    archived = world / observe.POLICY_DENIALS
    assert archived.is_file(), "the denial stream did not reach the archived world"
    assert read_jsonl_rows(archived)[0]["lead_id"] == DENIED_LEAD

    prompt = _prompt_for_world_b(ep, base)
    expected = f"- refused: {[_entry('denied', 'ticket', True, verb='get-ticket')]}"
    assert f"### {DENIED_LEAD}" in prompt, "the refusal-only lead is not in the judge's prompt"
    assert "REFUSED_LEAD_GOAL" in prompt
    at = prompt.index(f"### {DENIED_LEAD}")
    lead_block = prompt[at:prompt.find("### ", at + 1) if prompt.find("### ", at + 1) != -1 else None]
    assert expected in lead_block, \
        f"the lead's block carries no refused line for the denial:\n{lead_block}"
    J.assert_wrapped_untrusted(prompt, expected, "the refused line")


def test_key_flow_rows_a_real_run_wrote_render_as_the_pinned_kinds(tmp_path, judge_roots):
    """The sentinel half of the key flow, over rows REAL writers left: one dispatched lead that
    (1) calls an undeclared verb on a declared system — `∅.above-repeat-guard`, `agent-fixable`
    — (2) calls the withheld `elastic.esql` — a denial record with the lead's id — and
    (3) runs a granted query. The run dir is archived by the REAL archive into an accepted
    episode and rendered by the REAL judge pass: the lead's `refused` is exactly the
    rejection (the defender's own conduct) followed by the denial (external), its `payload`
    is the one executed query's digest, and the prompt for world `b` carries both kinds. The
    hand-written rows every other scenario uses are thereby tied to what the writers produce.

    Observed failing by: a real above-guard row not mapping to `rejected-before-dispatch`, a
    real denial not attributed to the lead, or either missing from the prompt."""
    rec = VerbRecorder()
    r = run_gather(tmp_path / "live", verbs=_registry(rec), turns=[
        q("elastic", "nosuch-verb"), q(*DENIED_PAIR),
        q("elastic", "query", {"native_query": "FROM logs"}), DONE,
    ], run_id="d860-flow")
    assert [row["query_id"] for row in r.own_rows] == [ABOVE_GUARD_QUERY_ID, "elastic.query"]
    assert len(rec.calls) == 1, "the granted call did not run"
    assert len(r.own_denials) == 1, "the denial was not audited"

    ep = J.accepted_episode(tmp_path, ledgers={"b": [J.staged_row("b")], "c": []})
    base, _src = J.runs_base(tmp_path)
    T.mod("learning.branch.archive").archive_episode(ep, {"b": r.run_dir})
    world = ep / "worlds" / "b"
    assert (world / observe.POLICY_DENIALS).is_file()
    assert (world / "executed_queries.jsonl").is_file()

    prompt = _prompt_for_world_b(ep, base)
    judge_input = J.mod("learning.judge.render").render(ep, "b", runs_base=base)
    chain = judge_input.leads[LEAD]
    assert chain["refused"] == [
        _entry("rejected-before-dispatch", "elastic", False),
        _entry("denied", "elastic", True, verb="esql"),
    ]
    assert len(chain["payload"]) == 1, "the executed query is not the lead's one payload"
    assert f"### {LEAD}" in prompt
    assert "'kind': 'rejected-before-dispatch'" in prompt
    assert "'kind': 'denied'" in prompt
    assert "'verb': 'esql'" in prompt
