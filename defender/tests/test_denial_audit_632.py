"""#632 part 3 — the durable denial record, its two sites, and the analyst who reads it.

One test per demand of `spec_graph_632-verb-authorization.yaml`, named by its
`discharged_by`. RED against `d01001e6` by construction.

§7 R1 settles where a judge-side denial is audited: ONE fixed policy-denial stream per
site — the same writer class and the same filename at the runtime and at the judge, each
under its own run directory. The rejected readings were discharging the judge's half with
the judge's own page (which is how an assertion gets written that proves nothing at the
second site) and a second writer on the design's existing filename (partly unbuildable —
the writer refuses a second open of one path). The "this record is not best-effort"
guarantee is a property of the RECORD, not of the file, and reaches both sites however the
destination lands.

Two authoring hazards this file is written around rather than into:

* The run-page renderer drops an unrecognized record kind SILENTLY (g23) — the probe drove
  the real renderer with an unrecognized kind and with a lone budget-refusal stream, and
  both rendered fine while the record appeared NOWHERE. "It renders" is therefore not the
  observable; the denial's OWN CONTENT in the rendered output is.
* There is no serialization safety net on the audit path (g24, executed): the writer
  normalizes nothing, a non-serializable value raises uncaught on one route and is
  swallowed to zero bytes on the other. What is pinned below is §7 R12's demanded
  correction — a bounded, normalized projection — never today's behaviour.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender._io import read_jsonl_rows  # noqa: E402
from defender.runtime import observe  # noqa: E402
from defender.scripts.visualize.visualize_run import render_runtime_page  # noqa: E402
from defender.tests._closed_ticket_672 import (  # noqa: E402
    CASE,
    DONE as JUDGE_DONE,
    OTHER_KEY,
    _drive,
    _get,
    _list,
)
from defender.tests._verb_authorization_632 import (  # noqa: E402
    BENIGN_JUDGE_PAIRS,
    DONE,
    ScopedFakeVerbs,
    grant_of,
    q,
    recording_table,
    run_gather,
    scoped_ticket_registry,
)
from defender.tests.e2e._replay_harness import VerbRecorder  # noqa: E402

pytestmark = pytest.mark.e2e

GRANTED_PAIR = ("elastic", "query")
DENIED_PAIR = ("elastic", "esql")

# The judge's grant minus `get-ticket`: the one shape that makes a denial observable at the
# second model-facing site, whose two tools otherwise hardcode their system and verb.
JUDGE_WITHOUT_GET = tuple(p for p in BENIGN_JUDGE_PAIRS if p != ("ticket", "get-ticket"))


def _gather_registry(rec: VerbRecorder) -> ScopedFakeVerbs:
    return ScopedFakeVerbs(
        recording_table(rec, {"elastic": ("query", "esql")}),
        grant_of("gather", (GRANTED_PAIR,)),
    )


def _denials(run) -> list[dict]:
    """The judge run dir's policy-denial stream, or [] when it was never written — so an
    absent stream fails a count assertion on its own message rather than raising."""
    p = run.lrd / observe.POLICY_DENIALS
    return read_jsonl_rows(p) if p.is_file() else []




def test_a_denial_appends_a_policy_event_to_the_durable_request_stream(tmp_path: Path):
    """A denial appends its own event type to the durable policy-denial stream at the
    decision point, flushed per record so it survives an abort, and takes its place in that
    stream's own append ordering as its own event rather than being folded into the
    conversation records. `tool_trace.jsonl` cannot serve: it is rebuilt from the message
    store at end of run, so an abort erases it."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=_gather_registry(rec),
                   turns=[q(*DENIED_PAIR), q(*GRANTED_PAIR), q(*DENIED_PAIR), DONE], run_id="d6")

    stream = r.run_dir / observe.POLICY_DENIALS
    assert stream.is_file(), "no durable policy-denial stream was written at all"
    records = read_jsonl_rows(stream)
    assert [rec_["event_type"] for rec_ in records] == [observe.POLICY_DENIAL_EVENT_TYPE] * 2
    assert [rec_["seq"] for rec_ in records] == [0, 1], "the stream carries no append ordering"
    assert records[0]["verb"] == "esql"


def test_a_judge_side_denial_is_audited_where_an_analyst_looks(tmp_path: Path):
    """A denial at the judge's closed-ticket tool is audited to the SAME fixed
    policy-denial filename, written by the same writer class, under the JUDGE's own run
    directory (§7 R1) — not to the per-batch, per-pid stage trace whose name interpolates
    the pid, and not discharged by the judge's own page.

    The second site's artifacts have different names and key sets from the runtime's, so an
    assertion written once against the runtime's paths passes vacuously here; this one
    reads the judge run dir explicitly."""
    rec = VerbRecorder()
    run = _drive(tmp_path, [_get(OTHER_KEY), JUDGE_DONE],
                 registry=scoped_ticket_registry(rec, JUDGE_WITHOUT_GET))

    stream = run.lrd / observe.POLICY_DENIALS
    assert stream.is_file(), "the judge site wrote no policy-denial stream under its own run dir"
    records = read_jsonl_rows(stream)
    assert len(records) == 1
    assert records[0]["event_type"] == observe.POLICY_DENIAL_EVENT_TYPE
    assert (records[0]["system"], records[0]["verb"]) == ("ticket", "get-ticket")
    assert not list(run.lrd.glob("*.trace.jsonl")) or all(
        observe.POLICY_DENIAL_EVENT_TYPE not in p.read_text(encoding="utf-8")
        for p in run.lrd.glob("*.trace.jsonl")
    ), "the denial landed in the per-pid stage trace instead of the fixed stream"
    assert "get-ticket" not in [c.verb for c in rec.calls]


def test_the_denial_record_carries_a_timestamp_and_a_seq_and_does_not_swallow_a_failed_write(
    tmp_path: Path,
):
    """The denial record carries a timestamp and a sequence, and a failed write is NOT
    silently swallowed — it propagates, after the refusal has already taken effect (§7 R2).

    This deliberately does not inherit the precedent it sits beside: `log_budget_refusal`
    wraps its write in a blanket suppressor and emits neither timestamp nor sequence
    (c12/g8), so its record can vanish while the refusal still happens. The differential
    below is the assertion — the same failure that the budget refusal swallows must reach
    the caller from the denial writer. A record that can vanish while the refusal still
    takes effect is the precedent this design named and rejected.

    Driven at the shared writer rather than once per site, on §7 R1's explicit rider: the
    not-best-effort guarantee is a property of the RECORD, not of the file, and both sites
    construct the same writer class (g8), so one drive of that class covers both. Recorded
    here rather than left silent, because the sibling demands at this boundary are the ones
    that had to be driven per-site — a judge-side assertion written against the runtime's
    names passes vacuously, and d7/d4/d32 each drive the judge leg for exactly that reason."""
    path = tmp_path / observe.POLICY_DENIALS
    logger = observe.RequestLogger(path)
    written = logger.log_policy_denial(
        role="gather", system="elastic", verb="esql", call_id="elastic.ad-hoc", params={"q": "x"},
    )
    assert written["ts"], "the denial record carries no timestamp"
    assert written["seq"] == 0
    logger.close()

    record = read_jsonl_rows(path)[0]
    assert record["ts"] == written["ts"]
    assert record["seq"] == 0

    logger.log_budget_refusal(tool_name="query")  # the precedent: silent on a closed handle
    with pytest.raises(Exception, match="closed"):
        logger.log_policy_denial(
            role="gather", system="elastic", verb="esql", call_id="elastic.ad-hoc", params={},
        )


def test_the_denial_record_is_a_bounded_normalized_projection_of_the_call(tmp_path: Path):
    """The denial record carries a BOUNDED PROJECTION — role, system, verb, call id and a
    truncated or hashed parameter digest — normalized before writing, never the raw
    parameter blob (§7 R12).

    The blob is model-controlled, unbounded and never validated, because parameter
    validation never runs for a denied verb. There is no shared serialization safety net
    (g24, executed): a non-serializable value raises uncaught on one route and is swallowed
    to zero bytes on the other. Combined with the decision that a failed audit write is
    loud, a caller who can make the record unserializable is a caller who can turn every
    denial into an infrastructure fault. The record's purpose is the policy fact, not the
    payload.

    The projection also carries a load this demand did not originally have. Once the grant
    check runs AHEAD of the traversal screen, normalization is the only thing standing
    between a hostile model-authored call id and the durable record — the job R23's ordering
    used to do. That half is asserted at the runtime drive that produces it."""
    class Unserializable:
        pass

    hostile = {
        "blob": "A" * 100_000,
        "nested": {"a": {"b": {"c": {"d": {"e": list(range(1000))}}}}},
        "nan": float("nan"),
        "object": Unserializable(),
    }
    path = tmp_path / observe.POLICY_DENIALS
    logger = observe.RequestLogger(path)
    logger.log_policy_denial(role="gather", system="elastic", verb="esql",
                             call_id="elastic.ad-hoc", params=hostile)
    logger.log_policy_denial(role="gather", system="elastic", verb="esql",
                             call_id="elastic.ad-hoc", params={"native_query": "FROM logs"})
    logger.close()

    line, control = path.read_text(encoding="utf-8").splitlines()
    record = json.loads(line)

    # The expected side is written HERE, as literals. Comparing against the target's own
    # DENIAL_RECORD_KEYS let the implementation define what it was being checked against —
    # an assertion that holds whatever ships, and under which `role` and the call id (the
    # two members nothing else in this suite pins) could be dropped and stay green. "Which
    # role was refused" is the policy fact this record exists to carry.
    assert set(record) == {
        "event_type", "ts", "seq", "role", "system", "verb", "call_id", "params_digest",
    }, "the record's shape is not the bounded projection §7 R12 names"
    assert record["role"] == "gather", "the record does not say which role was refused"
    assert record["call_id"] == "elastic.ad-hoc", "the record does not identify the call"
    assert (record["system"], record["verb"]) == ("elastic", "esql")
    assert "params" not in record, "the raw model-controlled blob was written to the audit stream"
    assert isinstance(record["params_digest"], str)
    assert len(line) < 4096, "the record is unbounded — a caller sizes the audit stream"
    for token in ("NaN", "Infinity"):
        assert token not in line, \
            f"a non-finite float survived as bare {token}, which no strict JSON parser reads"

    assert json.loads(control)["params_digest"], \
        "a well-formed call's digest is empty — the projection identifies nothing"




def test_a_denial_is_visible_in_the_rendered_run_html(tmp_path: Path):
    """A denial appears in the rendered run HTML, where an analyst opens it — its OWN
    CONTENT, the system and the verb it refused, not merely a page that built without
    error.

    The probe drove the real renderer with an unrecognized record kind and with a lone
    budget-refusal stream: both rendered fine, and the record appeared nowhere, because
    every consumer filters on a closed set of record kinds (g9/g23). So a denial can be
    durably on disk and absent from the analyst's page with every test green — teaching a
    consumer to stop filtering it is the actual work this demand names."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=_gather_registry(rec), turns=[q(*DENIED_PAIR), DONE],
                   run_id="d9")
    assert r.denials, "the drive produced no denial to render"

    html = render_runtime_page(r.run_dir)

    assert "esql" in html, "the denied verb does not appear in the analyst's page"
    assert "elastic" in html
    assert observe.POLICY_DENIAL_EVENT_TYPE in html or "denied" in html.lower(), \
        "the page renders the call but never says it was refused by policy"


def test_a_stream_written_before_the_denial_record_existed_still_renders(tmp_path: Path):
    """A stream that predates the change — no policy-denial file at all, or only the older
    refusal record — renders as "nothing happened here", without error. The complementary
    control for the visibility demand above, and the half the probe already holds: the
    renderer tolerates both an unrecognized kind and an old-shape-only stream.

    Without it the visibility assertion could be satisfied by a renderer that crashes on
    every run it does not find a denial in."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=_gather_registry(rec), turns=[q(*GRANTED_PAIR), DONE],
                   run_id="d54")
    assert not (r.run_dir / observe.POLICY_DENIALS).exists(), \
        "a run with no denial still wrote a denial stream"

    html = render_runtime_page(r.run_dir)
    assert html, "an old-shape stream rendered nothing at all"
    assert observe.POLICY_DENIAL_EVENT_TYPE not in html, \
        "the page claims a policy denial in a run that had none"

    legacy = r.run_dir / observe.POLICY_DENIALS
    legacy.write_text(json.dumps({"event_type": "budget_refusal", "tool_name": "query"}) + "\n",
                      encoding="utf-8")
    assert render_runtime_page(r.run_dir), "an older refusal record in the stream broke the page"




def test_a_denied_closed_ticket_verb_leaves_no_row_and_no_ticket_reads_file(tmp_path: Path):
    """A denied closed-ticket verb allocates no capture sequence and writes neither an
    `executed_queries.jsonl` row under the JUDGE run dir nor a `ticket_reads/{seq}.json`
    payload. Different artifact names from the runtime site on purpose — the judge's capture
    sink is its own run dir, keyed by sequence alone, and one assertion written against the
    runtime's names passes vacuously here.

    No "well-formed" narrowing: under the grant-first ordering the grant check precedes this
    tool's own screens too, so a denied call writes nothing here whatever else is wrong with
    its key.

    The second site is NOT a blank slate, and this demand does not flatten its reasoned
    split: for calls the grant ADMITS, the key-grammar and self-case-key refusals still raise
    with no sequence and no payload, while the missing-grammar path still deliberately writes
    a row so the audit trail evidences zero store attempts. Only the GRANT denial is what
    this pins; the ordering between the two is d72's."""
    rec = VerbRecorder()
    run = _drive(tmp_path, [_get(OTHER_KEY), JUDGE_DONE],
                 registry=scoped_ticket_registry(rec, JUDGE_WITHOUT_GET))

    assert [c.verb for c in rec.calls if c.verb == "get-ticket"] == [], "the denied verb ran"
    assert [row for row in run.rows() if row["verb"] == "get-ticket"] == [], \
        "a denied closed-ticket verb wrote a row into the judge's capture sink"
    assert not (run.lrd / "ticket_reads").exists() or not list(
        (run.lrd / "ticket_reads").glob("*.json")
    ), "a denied closed-ticket verb left a ticket_reads payload behind"
    assert run.breaker().get("total_failures", 0) == 0


def test_the_judge_sites_grant_check_precedes_its_own_key_screens(tmp_path: Path):
    """At the judge's closed-ticket tool the GRANT CHECK runs first — ahead of the key-grammar
    resolution, the key screen and the self-case-key screen — exactly as it does at the
    runtime. The human decided which refusal wins for the runtime's call; this is the second
    model-facing site, and leaving its ordering to whoever implements it is how one site ends
    up with the audit hole the other one closed.

    The negative half: a denied call whose key ALSO fails the grammar screen, and a denied
    call naming the case's own in-flight key, both take the DENIAL path — no row in the
    judge's capture sink, and a policy-denial record under the judge's run dir. Under the
    opposite ordering each of those keys is a free way to be refused without being recorded.

    The positive control is what keeps this from flattening the reasoned split `n5` warns
    against: with the grant NAMING get-ticket, the two screens still fire and still differ
    from each other — a bad key raises with no row and no store attempt, while a store whose
    grammar cannot be resolved deliberately DOES write a row, filed under the verb that
    actually ran and failed, so the audit trail evidences zero store attempts. The grant
    check sitting in front of them does not merge them."""
    denied_rec = VerbRecorder()
    bad_key = "not a key/../../etc/passwd"

    denied = _drive(tmp_path / "a", [_get(bad_key), JUDGE_DONE],
                    registry=scoped_ticket_registry(denied_rec, JUDGE_WITHOUT_GET))
    assert [c for c in denied_rec.calls if c.verb != "key-pattern"] == [], \
        "a denied call reached the store"
    assert denied.rows() == [], "the key screen ran first and wrote its own row for a denied call"
    denials = _denials(denied)
    assert len(denials) == 1, "a malformed key suppressed the judge site's denial record"
    assert denials[0]["verb"] == "get-ticket"

    self_rec = VerbRecorder()
    self_key = _drive(tmp_path / "b", [_get(CASE), JUDGE_DONE],
                      registry=scoped_ticket_registry(self_rec, JUDGE_WITHOUT_GET))
    assert self_key.rows() == [], "the self-case-key screen ran ahead of the grant check"
    assert len(_denials(self_key)) == 1, \
        "naming the case's own key suppressed the judge site's denial record"

    # Positive control — the grant admits the verb, and the site's own split survives intact.
    granted_rec = VerbRecorder()
    screened = _drive(tmp_path / "c", [_get(bad_key), JUDGE_DONE],
                      registry=scoped_ticket_registry(granted_rec, BENIGN_JUDGE_PAIRS))
    assert [c for c in granted_rec.calls if c.verb == "get-ticket"] == [], \
        "the key screen stopped screening once the grant check moved in front of it"
    assert screened.rows() == [], "the key-grammar refusal started writing a row"
    assert not (screened.lrd / observe.POLICY_DENIALS).exists(), \
        "a granted call refused by the key screen was audited as a policy denial"

    ungrammared = VerbRecorder()
    misconfigured = _drive(
        tmp_path / "d", [_get(OTHER_KEY), JUDGE_DONE],
        registry=scoped_ticket_registry(ungrammared, BENIGN_JUDGE_PAIRS,
                                         declare_key_pattern=False),
    )
    assert [row["verb"] for row in misconfigured.rows()] == ["key-pattern"], \
        "the missing-grammar path stopped writing the row that evidences zero store attempts"
    assert [c for c in ungrammared.calls if c.verb != "key-pattern"] == [], \
        "a store with no resolvable key grammar was asked for a ticket anyway"


def test_a_granted_closed_ticket_verb_still_writes_its_row_and_its_payload(tmp_path: Path):
    """A granted closed-ticket verb still writes its row into the judge's capture sink and
    its `ticket_reads/{seq}.json` payload, unchanged. The positive control at the second
    site: proof the judge's own artifacts are observable, so `no row` there is a difference
    the channel can see rather than a run that never reached the tool."""
    rec = VerbRecorder()
    run = _drive(tmp_path, [_list(label=None), JUDGE_DONE],
                 registry=scoped_ticket_registry(rec, BENIGN_JUDGE_PAIRS))

    rows = [row for row in run.rows() if row["verb"] == "list-tickets"]
    assert len(rows) == 1, "the granted closed-ticket verb wrote no row"
    assert rows[0]["exit_code"] == 0
    assert (run.lrd / rows[0]["payload_path"]).is_file()
    assert not (run.lrd / observe.POLICY_DENIALS).exists(), \
        "a granted judge call was audited as a policy denial"
