"""#767 — the surfaces this change re-pins: reach, the deleted lane, the censuses, the prose.

Every test is one demand of `spec-flow/specs/spec_graph_767-ticket-store-approval.yaml`,
named by that demand's `discharged_by`. Some of these are green at HEAD already — O6 holds
today and this change re-pins it on the REAL program set (D8) rather than on
`bash_policy.json`, which carries only `read_deny` (c2/g9) — and the rest are red until D5,
D6 and D7 land.

RF4 BOUNDS WHAT THE CONFINEMENT WITNESS CAN MEAN, and every assertion here is scoped by it:
the host writer never consults `READ_ENDPOINT_ALLOWLIST` at all (g2/g3 — it calls
`transport.docker_exec_curl` directly, so its POSTs meet neither the allowlist nor
`guard_outbound`'s capture recorder, and there is no `case-history` key in the table). The
allowlist is a control over the MODEL's door and nothing else, so every test below says which
door it is about.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from defender._paths import PATHS
from defender.runtime import verb_dispositions
from defender.runtime.verb_grant import VERB_CLASSES
from defender.scripts.adapters import confinement
from defender.scripts.adapters.confinement import ConfinementFault
from defender.scripts.case_history import case_ticket
from defender.tests._spec767 import (
    AGENT_AUTHOR,
    APPROVED_LABEL,
    COMMENTS_SUFFIX,
    LABELS_SUFFIX,
    TICKETS_PATH,
    TRANSITIONS_SUFFIX,
    FakeStore,
    agent_comments,
    comment,
    listing,
    make_run,
    mapping_doc,
    record,
    screen_list,
    served_tickets,
    ticket,
    use_mapping,
)

DEFENDER_DIR = PATHS.defender_dir
REPO_ROOT = PATHS.repo_root
URL_BASE = "http://case-history.test"

#: Every source file the shipping tree collects, tests excluded — the population every census
#: below is a claim about.
SHIPPED_PY = tuple(
    p for p in sorted(DEFENDER_DIR.rglob("*.py"))
    if "tests" not in p.relative_to(DEFENDER_DIR).parts
)


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _shipped_hits(pattern: str) -> dict[str, list[int]]:
    """Every shipped (non-test) source line matching `pattern`, by repo-relative path."""
    rx = re.compile(pattern)
    out: dict[str, list[int]] = {}
    for p in SHIPPED_PY:
        lines = [i for i, line in enumerate(_text(p).splitlines(), 1) if rx.search(line)]
        if lines:
            out[str(p.relative_to(REPO_ROOT))] = lines
    return out


# =======================================================================================
# O6 / S2 / N9 — no model role can reach a ticket write
# =======================================================================================


def test_767_no_model_role_reaches_a_ticket_write(tmp_path):
    """o6_no_model_write_reach — NEGATIVE. No model role can reach a ticket write, on any of
    the three surfaces a role's reach is actually made of: the grant table, the adapter's
    confinement allowlist, and the model's real bash program set.

    D8 RE-POINTS THE THIRD (c2/g9): the program set is `permission/policies/_common.py`'s
    `reader_grants` — `cat` plus the stdin viewers plus the non-adapter shims plus the inert
    pair — and NOT `runtime/bash_policy.json`, which carries only `version` and `read_deny`
    and whose own `_README` says the program set is not a JSON list. A test pinned on that
    file would be vacuous.

    Each surface is DRIVEN rather than enumerated: the grant table is projected onto the role
    through its real projection, the allowlist is exercised by the real `guard_outbound` over
    real write URLs, and the program set is built by its real producer. Its positive control
    is `o6_read_verb_still_granted` — the read verb the same three surfaces DO admit."""
    rows = verb_dispositions.shipped_dispositions()
    for role in sorted(verb_dispositions.KNOWN_ROLES):
        grant = verb_dispositions.grant_for(role, rows)
        for system, verb, verb_class in grant.entries:
            assert verb_class == verb_dispositions.READ_CLASS, (
                f"{role} holds {system}.{verb} at class {verb_class!r} — every shipped verb is "
                "read-class, and a write class is what O6 forbids"
            )
            if system == "ticket":
                assert verb in ("health-check", "list-tickets"), (
                    f"{role} holds an unexpected ticket verb {verb!r}; a write verb in the "
                    "grant table is O6's own failure witness"
                )

    for path in (TICKETS_PATH, f"{TICKETS_PATH}/SOC-1{COMMENTS_SUFFIX}",
                 f"{TICKETS_PATH}/SOC-1{TRANSITIONS_SUFFIX}",
                 f"{TICKETS_PATH}/SOC-1{LABELS_SUFFIX}"):
        with pytest.raises(ConfinementFault):
            confinement.guard_outbound(None, "ticket", f"{URL_BASE}{path}", method="POST")
    with pytest.raises(ConfinementFault):
        confinement.guard_outbound(None, "case-history", f"{URL_BASE}{TICKETS_PATH}",
                                   method="GET")

    from defender.runtime.permission.policies import _common

    programs = {g.program for g in _common.reader_grants(tmp_path, DEFENDER_DIR, raw=False)}
    assert programs, "the program set is empty — this assertion would pass over anything"
    for network in ("curl", "wget", "nc", "ncat", "socat", "ssh", "docker", "python3", "sh"):
        assert network not in programs, (
            f"the model's bash program set grants {network!r}: a network-capable program is a "
            "route to the store's write endpoints that no grant table can see"
        )

    policy = json.loads(_text(DEFENDER_DIR / "runtime" / "bash_policy.json"))
    assert set(policy) <= {"version", "read_deny", "_README"}, (
        "bash_policy.json now carries a program set; D8 re-pointed this demand at "
        "`_common.reader_grants` precisely because it did not (c2)"
    )


def test_767_list_tickets_still_granted_to_gather():
    """o6_read_verb_still_granted — the POSITIVE CONTROL for every reach negative in this
    file: `ticket.list-tickets` IS granted to gather, and its GET reaches the store through
    the adapter's own confined door. Without it, "no model role reaches a ticket write"
    passes just as well over a role that reaches nothing at all.

    The ungranted ticket verbs stay in the table as rows granted to NOBODY with a reason —
    that is this file's way of spelling an examined no, and it is why a future re-grant is a
    decision rather than a restoration."""
    rows = verb_dispositions.shipped_dispositions()
    by_pair = {d.pair: d for d in rows}
    gather = verb_dispositions.grant_for("gather", rows)

    assert ("ticket", "list-tickets") in {(s, v) for s, v, _ in gather.entries}
    for verb in ("get-ticket", "key-pattern", "case-opened-at"):
        row = by_pair[("ticket", verb)]
        assert row.roles == frozenset(), f"ticket.{verb} is granted to {sorted(row.roles)}"
        assert row.reason, f"ticket.{verb} is granted to nobody with no recorded reason"

    confinement.guard_outbound(None, "ticket", f"{URL_BASE}{TICKETS_PATH}", method="GET")
    confinement.guard_outbound(None, "ticket", f"{URL_BASE}{TICKETS_PATH}/SOC-1", method="GET")


def test_767_verb_class_vocabulary_stays_closed_at_two():
    """n9_no_third_effect_tier — NEGATIVE. #632's verb-class vocabulary stays closed at two,
    `{r, rw}`: nothing this lane adds is a verb. The writer is a host post-step no role can
    call (O6), so the third effect tier #632 deferred to exactly this work is NOT NEEDED —
    issue item 3, answered.

    Its positive control is `o6_read_verb_still_granted`: the two classes that exist are live,
    so "no third" is not "no vocabulary". A grant naming a third class is refused by the real
    constructor, which is the observable rather than the constant."""
    from defender.runtime.verb_grant import GrantError, VerbGrant

    assert frozenset({"r", "rw"}) == VERB_CLASSES, (
        f"the verb-class vocabulary is now {sorted(VERB_CLASSES)}; N9 answers issue item 3 "
        "with 'not needed' and keeps it closed at two"
    )
    VerbGrant(role="gather", entries=(("ticket", "list-tickets", "r"),))
    with pytest.raises(GrantError):
        VerbGrant(role="gather", entries=(("ticket", "record-comment", "w"),))

    rows = verb_dispositions.shipped_dispositions()
    assert not [d for d in rows if d.system == "case-history"], (
        "the host writer's system appeared in the verb table — it is a post-step, not a verb"
    )


def test_767_labels_route_is_not_on_the_confinement_allowlist(tmp_path):
    """d6_labels_route_not_confined — NEGATIVE. D6's `POST /tickets/{key}/labels` is the
    OPERATOR's route, and it is not on the adapter's confinement allowlist, which is GET-only:
    a model driving the adapter's door cannot add the approved tag.

    RF4 bounds this: the allowlist is the MODEL's door. D6's route inherits the host writer's
    bypass of `guard_outbound` (g2), so this demand is a control over model reach and NOT a
    control over who may really call the route — on the playground nothing authenticates it at
    all (N6), which the clause `n6_approve_action_is_unattributable_on_the_playground` records
    rather than tests.

    Its positive control is `o6_read_verb_still_granted`."""
    allowlist = confinement.READ_ENDPOINT_ALLOWLIST["ticket"]
    assert all(method == "GET" for _, method in allowlist), (
        f"the ticket allowlist is no longer GET-only: {allowlist}"
    )
    assert not any(pattern.endswith("labels") for pattern, _ in allowlist)

    for method in ("POST", "PUT", "PATCH", "DELETE"):
        with pytest.raises(ConfinementFault):
            confinement.guard_outbound(
                None, "ticket", f"{URL_BASE}{TICKETS_PATH}/SOC-1{LABELS_SUFFIX}", method=method
            )

    rows = verb_dispositions.shipped_dispositions()
    for d in rows:
        if d.system == "ticket":
            assert "label" not in d.verb, (
                f"a label verb ({d.verb}) entered the grant table: approval is a person's act, "
                "outside every role"
            )


def test_767_adapter_http_confinement_and_capture_hold(tmp_path):
    """d_adapter_http_confinement_capture_positive_control — PARITY, and the baseline the two
    vias this design adds are a parity demand AGAINST. `adapter-http` is the ESTABLISHED via
    on the store, and it carries BOTH constraints: `confine_read_endpoint` and
    `guard_outbound`'s capture record. No demand pinned that baseline before the gate leaf
    minted this one, so `host-curl` and `operator-labels` had nothing to be compared with.

    Cites g2 (guard_outbound's two callers, both adapter transports — and `guard_outbound` IS
    the capture recorder, which is why a door that skips it records nothing anywhere) and
    g3/c2 (the allowlist's ticket entry, GET-only, with no `case-history` key at all).

    Driven through the real seam with a real capture object, so the recorded request is an
    observation rather than a reading: the sanctioned GET is confined AND captured; the POST
    is refused, and refused BEFORE it is captured."""
    capture = confinement.TransportCapture()
    ctx = type("Ctx", (), {"capture": capture})()

    confinement.guard_outbound(ctx, "ticket", f"{URL_BASE}{TICKETS_PATH}", method="GET")
    assert [(r.system, r.method) for r in capture.requests] == [("ticket", "GET")], (
        "the established via no longer records what it sent — `guard_outbound` is the capture "
        "recorder, so a door that stops calling it stops recording"
    )

    with pytest.raises(ConfinementFault):
        confinement.guard_outbound(
            ctx, "ticket", f"{URL_BASE}{TICKETS_PATH}/SOC-1{COMMENTS_SUFFIX}", method="POST")
    assert len(capture.requests) == 1, "a refused request was still recorded as sent"

    assert "case-history" not in confinement.READ_ENDPOINT_ALLOWLIST, (
        "the host writer's system gained an allowlist entry; g2/g3 record that it consults "
        "none, and RF4 bounds every witness in this file on that fact"
    )


def test_767_ticket_adapter_edge_carries_no_model_reachable_comment_content(tmp_path):
    """d_ticket_adapter_read_stays_non_model_facing — COHERENCE, bound at the UNMOVED reader's
    own edge (R7). `ticket_adapter` reads the same store D4's screen now wraps, and the screen
    wraps only `query_tool`'s edge — so this reader has to be dismissed on its own evidence,
    not on a demand at the boundary's altitude that reads green when only the moved reader was
    observed.

    The evidence is a JOIN, asserted rather than recalled: every ticket verb the adapter
    exposes that ANY role can reach must be one D4's screen covers. `health-check` carries no
    ticket content at all; `list-tickets` and `get-ticket` are the two the screen dispatches
    on (r5). A newly-granted adapter verb the screen does not cover — a `key-pattern` or a
    `case-opened-at` re-grant — fails here, which is exactly the coherence break R7 exists to
    catch.

    Cites c13 (after D5 the query tool is the only code handing ticket-store content to a
    model) and the grant census."""
    from defender.runtime.ticket_screen import TICKET_GET, TICKET_LIST

    screened = {TICKET_LIST, TICKET_GET}
    contentless = {"health-check"}

    rows = verb_dispositions.shipped_dispositions()
    reachable = {
        d.verb for d in rows
        if d.system == "ticket" and d.roles
    }
    assert reachable, "no ticket verb reaches any role — the coherence check is vacuous"
    unscreened = reachable - screened - contentless
    assert not unscreened, (
        f"the unmoved reader exposes {sorted(unscreened)} to a role, and D4's screen covers "
        f"only {sorted(screened)}: a ticket verb reaching a model outside the screened pair is "
        "O2's failure witness on a path nothing else in this suite observes"
    )

    adapter = _text(DEFENDER_DIR / "scripts" / "adapters" / "ticket_adapter.py")
    for seam in ("screen_list", "screen_get"):
        assert seam not in adapter, (
            f"the adapter calls `{seam}` itself: D4 attaches at the query tool's single "
            "insertion point (r5), and a second screen is a second policy to keep in step"
        )


# =======================================================================================
# D5 / N10 / S3′ — the resolution-decoding lane, closed structurally
# =======================================================================================

_RETIRED_CASE_TICKET = (
    "parse_disposition_from_resolution",
    "ticket_disposition",
    "ticket_reason",
    "append_resolution_method",
    "resolution_method_from_resolution",
    "ticket_resolution_method",
    "_disposition_separator",
    "_resolution_method_marker",
    "case_record_to_close",
)
#: The four seed-era helpers D5 deliberately LEAVES — they serve no obligation here, and
#: retiring them would be scope this change did not take (RF1/g13: the vulture baseline holds
#: EIGHT case_ticket rows, not c15's seven; D5 retires exactly four and leaves exactly four).
_KEPT_CASE_TICKET = ("signature_label", "ticket_event_time", "ticket_created", "alert_event_time")
_RETIRED_BASELINE_ROWS = (
    "append_resolution_method", "ticket_disposition", "ticket_reason", "ticket_resolution_method",
)


def test_767_resolution_decoding_lane_is_gone(tmp_path):
    """d5_resolution_lane_deleted — SURVIVAL. The second model-facing read path is closed
    STRUCTURALLY: the `resolution`-decoding lane is deleted, and the workflow that ran through
    it — the forward check — still completes through its substitute, which is having no cited
    policy section at all.

    c5 is the ground: the lane's one non-test consumer read `resolution` through a `get-ticket`
    SUBPROCESS keyed on `past_tickets.txt`, which no non-test code writes, so
    `load_cited_policy` has always answered `_NO_CITED_POLICY`. Removing it removes a prompt
    section that was already empty on every run, and there is no survivor to reconnect.

    The survival half is driven: a run dir carrying a `past_tickets.txt` that cites a closed
    case still yields the forward check's own inputs, and no store is contacted to do it."""
    from defender.learning.author.verify_forward import checks, forward

    for name in _RETIRED_CASE_TICKET:
        assert not hasattr(case_ticket, name), (
            f"`case_ticket.{name}` survives D5 — the resolution lane is closed structurally, "
            "not by leaving its decoder unreferenced"
        )
    for name in _KEPT_CASE_TICKET:
        assert hasattr(case_ticket, name), (
            f"`case_ticket.{name}` was deleted: D5 leaves the four seed-era helpers alone "
            "(RF1/g13), and deleting them is scope this change did not take"
        )

    for name in ("load_cited_policy", "_fetch_closed_resolution", "_cited_case_ids",
                 "_NO_CITED_POLICY", "_TICKET_CLI"):
        assert not hasattr(forward, name), (
            f"`verify_forward.forward.{name}` survives: the out-of-process ticket read is the "
            "second model-facing path D5 closes"
        )
    assert "cited_covering_policy" not in _text(
        Path(checks.__file__)
    ), "the forward check still assembles a `cited_covering_policy` prompt section"

    # Survival: the workflow that ran through the removed element still completes.
    runs = tmp_path / "runs"
    run_id = "20260101T000000Z-prior"
    (runs / run_id).mkdir(parents=True)
    (runs / run_id / "past_tickets.txt").write_text("- SOC-1: a cited closed case\n",
                                                    encoding="utf-8")
    (runs / run_id / "investigation.md").write_text("+ prior work\n", encoding="utf-8")
    (runs / run_id / "report.md").write_text(
        "---\ndisposition: benign\nconfidence: high\n---\nprior notes\n", encoding="utf-8")
    (runs / run_id / "source_refs.yaml").write_text(
        "normalized_disposition: benign\n", encoding="utf-8")
    transcript, recorded = forward.load_run_context(run_id, runs_dir=runs)
    assert transcript, (
        "the forward check can no longer read its own transcript — the substitute does not "
        "carry the workflow"
    )
    assert recorded == "benign", "the forward check lost the case's recorded disposition"
    assert forward.expected_disposition("benign", recorded) == "benign"

    baseline = json.loads(_text(REPO_ROOT / "scripts" / "lint" / "lint_vulture_baseline.json"))
    rows = [k for k in baseline["entries"] if "case_ticket.py" in k]
    for retired in _RETIRED_BASELINE_ROWS:
        assert not any(f"'{retired}'" in row for row in rows), (
            f"the vulture baseline still carries a row for `{retired}`, which D5 deletes — a "
            "baselined row naming a symbol that resolves to nothing reads exactly like a row "
            "nobody wrote"
        )
    assert len(rows) == 4, (
        f"the baseline holds {len(rows)} case_ticket rows; D5 retires exactly four of the "
        "eight and leaves exactly four (RF1/g13 — c15's count of seven is REFUTED)"
    )


def test_767_a_typed_resolution_reaches_no_reader(tmp_path, monkeypatch):
    """n10_hand_typed_resolution_is_inert — NEGATIVE. After D5, nothing decodes a ticket's
    `resolution`: a person may type anything into that field and no reader turns it into a
    disposition.

    That shrinks the #923 authoring-surface census by exactly one entry (c12): `case_ticket.py`
    was the only surface whose author is neither the host nor the investigating model, and its
    refusal of a hand-typed host-only verdict defended a decoder D5 deletes. Both grains of
    that census move — the module and its named entry point.

    Its positive control is `d0_screen_shape`: a `resolution` field is still SERVED untouched
    (§7 R9/FK05's examined no, on c3's ground), so "no reader" is not "no field"."""
    from defender.tests import test_923_authoring_surfaces as census

    rel = "scripts/case_history/case_ticket.py"
    assert rel not in census._AUTHORING_SURFACES, (
        "the #923 authoring-surface census still lists the ticket resolution line: after D5 "
        "nothing decodes `resolution`, so it is no longer an authoring surface (N10/c12)"
    )
    assert not any(e.startswith(rel) for e in census._AUTHORING_ENTRY_POINTS), (
        "the #923 entry-point census still names `case_ticket.py::"
        "parse_disposition_from_resolution`, which D5 deletes"
    )

    use_mapping(monkeypatch, tmp_path / "dfn", mapping_doc())
    typed = ticket("SOC-TYPED", labels=["sig:5710"],
                   comments=[comment("agent notes")])
    typed["resolution"] = "unresolved — whatever an analyst felt like typing"
    payload, code, _ = screen_list(listing(typed))
    assert code == 0
    assert served_tickets(payload)[0]["resolution"] == typed["resolution"], (
        "the served record's `resolution` was rewritten — it is inert, not screened"
    )
    assert not _shipped_hits(r"\bparse_disposition_from_resolution\b"), (
        "a shipped module still decodes a hand-typed resolution"
    )


def test_767_query_tool_is_only_ticket_reader(tmp_path):
    """s3p_single_model_facing_reader — NEGATIVE, the path census O2's own text demands: "on
    every read path into the store, not only the query tool's". After D5 the query tool is the
    only code that hands ticket-store content to a model (c13, S3′).

    RFJ5 is why this is a CENSUS test and not a behavioural one: all three readers treated the
    second-consumer question as unaddressed, and O2 decides it — O2 binds any consumer by
    construction, and this demand is what pins the current population at ONE. The probe
    `auth_P16` remains open on whether `ticket_screen`'s own docstring still advertises two
    consumers; a stale docstring is doc-vs-code drift for `finalize`, not a design fork, and
    this test does not assert prose.

    Its positive control is `o2_approved_serves_latest`: the one reader in the census DOES
    hand screened ticket content to a model."""
    consumers = _shipped_hits(r"(?<!def )\bscreen_(?:list|get)\s*\(")
    assert set(consumers) == {"defender/runtime/query_tool.py"}, (
        f"the screen protocol has consumers beyond the query tool: {sorted(consumers)} — O2 "
        "binds every one of them, and this census is what says how many there are"
    )

    forward_dir = DEFENDER_DIR / "learning" / "author" / "verify_forward"
    for p in sorted(forward_dir.rglob("*.py")):
        assert "ticket" not in _text(p).lower(), (
            f"{p.name} still reaches the ticket store: D5 deletes the whole lane, and its "
            "prompt section with it"
        )

    subprocess_readers = _shipped_hits(r"get-ticket")
    allowed = {
        "defender/scripts/adapters/ticket_adapter.py",
        "defender/runtime/ticket_screen.py",
        "defender/runtime/query_tool.py",
        # A pre-existing, unrelated docstring example — `render_refused`'s illustration of one
        # rendered denial line, predating #767 and untouched by D1-D8. Not a reader of the
        # ticket store: the module never calls the verb at all.
        "defender/learning/judge/family.py",
    }
    assert set(subprocess_readers) <= allowed, (
        "a shipped module outside the adapter/screen/query-tool trio names `get-ticket`: "
        f"{sorted(set(subprocess_readers) - allowed)}"
    )


def test_767_every_checked_in_census_of_this_surface_moves_together(tmp_path):
    """d_checked_in_censuses_move_together — COHERENCE, settled premise 68. Every checked-in
    census of this surface moves with the change, including the one no D-row names.

    Four censuses move and RF5 is why this demand exists: D2 carries the callsite list, D5
    carries the vulture rows and the #923 authoring surfaces, and NOBODY named `WRITE_ENDPOINTS`
    (g4) — the checked-in list of estate-write endpoint triples, which D6's labels route makes
    a fifth.

    The callsite half is the sharp one (RF2): c11's census under-counts the duck-typed
    `ticket_writer=` seam by a whole file, because its "non-definition reference" wording
    excuses a test's own `class Writer`. Asserted as an absence over the WHOLE repository
    rather than over c11's list, so a site nobody censused is caught by the same assertion."""
    stranded = _shipped_hits(r"\bclose_case_ticket\b")
    assert not stranded, f"shipped code still calls the retired writer: {stranded}"

    # A REAL reference, not a mention: an attribute access on the retired name, or a method
    # DEFINING it — never a backtick-quoted docstring mention (this very file's own prose, and
    # every `test_767_*` module's, has to say what D2 renamed) or a quoted string literal
    # proving the name is gone (the positive control for the rename itself, over `hasattr`).
    _retired_writer_method = "close_case_ticket"
    stale_ref = re.compile(rf"\.{_retired_writer_method}\b|\bdef {_retired_writer_method}\b")
    repo_hits: dict[str, list[int]] = {}
    for p in sorted(REPO_ROOT.rglob("*.py")):
        if ".venv" in p.parts or ".git" in p.parts or ".spec-flow" in p.parts:
            continue
        lines = [i for i, line in enumerate(_text(p).splitlines(), 1)
                 if stale_ref.search(line)]
        if lines:
            repo_hits[str(p.relative_to(REPO_ROOT))] = lines
    assert not repo_hits, (
        "the rename left callsites behind, and a duck-typed implementor of the "
        f"`ticket_writer=` seam is silent when it does (RF2/g10): {repo_hits}"
    )

    from defender.tests import test_target_confinement_632 as confinement_census

    triples = set(confinement_census.WRITE_ENDPOINTS)
    system = confinement_census.TICKET_WRITER_SYSTEM
    assert (system, f"{TICKETS_PATH}/SOC-1{LABELS_SUFFIX}", "POST") in triples, (
        "WRITE_ENDPOINTS does not carry D6's labels route: it is the fourth census this "
        "change moves and no D-row names it (RF5/g4)"
    )
    assert (system, f"{TICKETS_PATH}/SOC-1{COMMENTS_SUFFIX}", "POST") in triples, (
        "the comments route left the estate-write census, which is the one write this "
        "change keeps"
    )


# =======================================================================================
# O5 — the vendor spellings live in the mapping, and one loader serves both sides
# =======================================================================================


def test_767_no_tag_or_author_literal_in_writer_or_screen(tmp_path, monkeypatch):
    """o5_no_vendor_literals_in_code — COHERENCE. The vendor spellings this lane introduces —
    the approved tag, the agent author identity, the comment field — live in the mapping, and
    changing them there changes what the WRITER sends AND what the SCREEN keeps, with no code
    edit.

    §7 FK54 settled the shape: ONE loader, one resolution, asserted as a single test that
    changes the mapping ONCE and observes both sides. That test fails if the two sides ever
    diverge, which is the observable worth having — the probe `auth_P6` (does every execution
    context resolve the same root?) stays open, and a divergence there surfaces here.

    REJECTED, and deliberately not asserted (N8): `ticket_screen`'s existing binding of the
    stub's envelope — `tickets`, `key`, `comments`, `author` — is the stub adapter's own and
    stays in code, outside O5's scope."""
    use_mapping(monkeypatch, tmp_path / "dfn",
                mapping_doc(comment_author="acme-bot", approved_label="acme-released"))

    run_dir = make_run(tmp_path, name="20260101T000000Z-acme")
    store = FakeStore()
    record(run_dir, store)
    assert store.only_comment()["author"] == "acme-bot", "the writer did not follow the mapping"

    tagged = ticket("SOC-ACME", labels=["acme-released"],
                    comments=[comment("prior notes", author="acme-bot")])
    payload, code, _ = screen_list(listing(tagged))
    assert code == 0
    assert [c["body"] for c in agent_comments(served_tickets(payload)[0], authors=("acme-bot",))] \
        == ["prior notes"], "the screen did not follow the same mapping the writer did"

    for path, why in (
        (DEFENDER_DIR / "scripts" / "case_history" / "ticket_writer.py", "the writer"),
        (DEFENDER_DIR / "runtime" / "ticket_screen.py", "the screen"),
        (DEFENDER_DIR / "runtime" / "query_tool.py", "the query tool"),
    ):
        source = _text(path)
        assert APPROVED_LABEL not in source, f"{why} spells the approved tag as a code literal"
        for quoted in (f'"{AGENT_AUTHOR}"', f"'{AGENT_AUTHOR}'"):
            assert quoted not in source, (
                f"{why} spells the agent author identity as a code literal"
            )


# =======================================================================================
# D7 — the briefing the model reads about where rationale lives
# =======================================================================================


def test_767_ticket_skill_md_describes_the_approval_lane(tmp_path):
    """d7_briefing_rewrite — settled premise 69 (and §7 FK55's first half, which keeps the
    SKILL.md rewrite IN the suite). `skills/ticket/SKILL.md` is MODEL-FACING prose, and D4
    makes three of its sentences false.

    RF3/g14 is the finding this carries: D7's own line ranges omit lines 58-60 — "Comments are
    signal-bearing. Resolution rationale and related-ticket references typically live in
    comment bodies, not in structured fields." — which is exactly the read_guidance sentence
    D4 falsifies for unapproved cases. The close/`resolution` lifecycle text goes with D5, and
    line 78's duplicated "`run.py` / `run.py`" is a stale-reference artifact the same rewrite
    should clear.

    §7 FK43 adds the meaning that must be said out loud: the tag is RELEASE-FOR-READING, not
    an endorsement of the verdict. §7 FK42 adds the other: what a person approves is the
    record AS DISPLAYED, visibly truncated when cut.

    FK55's second half is NOT here and deliberately so: `defender/docs/case-history-write-path.md`
    is human-facing architecture prose named by no D-row, and stale prose there is a
    `finalize`-stage concern (probe `auth_P9` is open on whether the file exists at all)."""
    skill = _text(DEFENDER_DIR / "skills" / "ticket" / "SKILL.md")
    lowered = skill.lower()

    stale = {
        "the close-lifecycle sentence": "closes it with the disposition",
        "the RF3 read_guidance sentence": "resolution rationale and related-ticket references",
        "the duplicated run.py artifact": "`run.py` / `run.py`",
    }
    for why, text in stale.items():
        assert text.lower() not in lowered, (
            f"{why} survives the rewrite: D4/D5 make it false, and this file is what a MODEL "
            "reads about where rationale lives"
        )

    for why, needle in (
        ("the approved tag's own spelling", APPROVED_LABEL),
        ("that agent comments are a prior run's output", "prior run"),
        ("that the tag is a release to read, not an endorsement", "endors"),
        ("that the comment a person approves may be visibly truncated", "truncat"),
        ("that the disposition is the human's", "disposition"),
    ):
        assert needle.lower() in lowered, (
            f"the rewritten briefing never says {why} ({needle!r} appears nowhere)"
        )
