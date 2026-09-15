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
import re
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from defender._io import read_jsonl_rows  # noqa: E402
from defender.runtime import observe  # noqa: E402
from defender.scripts.visualize.visualize_run import render_runtime_page  # noqa: E402
from defender.tests._verb_authorization_632 import (  # noqa: E402
    DONE,
    ScopedFakeVerbs,
    grant_of,
    q,
    recording_table,
    run_gather,
)
from defender.tests.e2e._replay_harness import VerbRecorder  # noqa: E402

pytestmark = pytest.mark.e2e

GRANTED_PAIR = ("elastic", "query")
DENIED_PAIR = ("elastic", "esql")

# The judge's grant minus `get-ticket`: the one shape that makes a denial observable at the
# second model-facing site, whose two tools otherwise hardcode their system and verb.


def _gather_registry(rec: VerbRecorder) -> ScopedFakeVerbs:
    return ScopedFakeVerbs(
        recording_table(rec, {"elastic": ("query", "esql")}),
        grant_of("gather", (GRANTED_PAIR,)),
    )


_COMMENT = re.compile(r"<!--.*?-->", re.S)
_SCRIPT = re.compile(r"<script\b.*?</script\s*>", re.S | re.I)
_DOC = re.compile(r"<html\b.*?</html\s*>", re.S | re.I)


def _visible_html(html: str) -> str:
    """The part of a rendered page an analyst can actually see: inside the document element,
    with comments and script bodies removed.

    Written as a filter rather than as a substring assertion because the two are not the same
    claim. `"esql" in html` is satisfied by a denial rendered as a comment, or appended after
    `</html>`, or parked in a script's data — all of which leave the analyst's page blank of
    the thing this demand exists to put on it, and all of which a file-level grep calls a
    pass. A page with no document element at all is treated as invisible, because a renderer
    that stopped emitting one is exactly the regression this would otherwise hide."""
    found = _DOC.search(html)
    if found is None:
        return ""
    return _SCRIPT.sub(" ", _COMMENT.sub(" ", found.group(0)))


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

    THE DIGEST IS OVER THE PARAMETER VALUES, not over the parameter names. A digest of the
    sorted key set makes two denials that differ only in what was asked for byte-identical in
    the audit stream — the analyst can see that gather was refused `esql` a hundred times and
    never that ninety-nine of them probed one index and one probed another, which is the only
    reason the column exists. It also kills the non-finite guard below by making it dead code:
    if no value is ever serialized, no value can ever arrive as a bare `NaN`. The three
    drives below are the discrimination: same keys and different values must differ, same
    values must agree, and the hostile blob must still normalize.

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
    # Same key, different value — the pair a name-only digest cannot separate.
    logger.log_policy_denial(role="gather", system="elastic", verb="esql",
                             call_id="elastic.ad-hoc", params={"native_query": "FROM secrets"})
    # Same key, same value again — the digest must be a function of the call, not of a clock
    # or a counter, or "these two differ" says nothing.
    logger.log_policy_denial(role="gather", system="elastic", verb="esql",
                             call_id="elastic.ad-hoc", params={"native_query": "FROM logs"})
    logger.close()

    line, control, other_value, repeat = path.read_text(encoding="utf-8").splitlines()
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
    assert json.loads(control)["params_digest"] != json.loads(other_value)["params_digest"], (
        "two denials differing only in their parameter VALUES carry the same digest — the "
        "digest is over the parameter names, so the audit stream cannot tell one probe from "
        "another and the non-finite guard above is dead code"
    )
    assert json.loads(control)["params_digest"] == json.loads(repeat)["params_digest"], \
        "the same call digests differently twice — the digest is not a function of the call"




def test_a_denial_is_visible_in_the_rendered_run_html(tmp_path: Path):
    """A denial appears in the rendered run HTML, where an analyst opens it — its OWN
    CONTENT, the system and the verb it refused, not merely a page that built without
    error.

    The probe drove the real renderer with an unrecognized record kind and with a lone
    budget-refusal stream: both rendered fine, and the record appeared nowhere, because
    every consumer filters on a closed set of record kinds (g9/g23). So a denial can be
    durably on disk and absent from the analyst's page with every test green — teaching a
    consumer to stop filtering it is the actual work this demand names.

    THE CONTENT MUST BE IN THE DOCUMENT THE BROWSER RENDERS, which is a stricter and more
    honest reading of "where an analyst opens it" than a substring of the file. A plain
    substring assertion is satisfied by a denial emitted as an HTML COMMENT, or appended
    outside the document element: every string is present, the file parses, and the analyst
    sees a page with no denial on it — a page that is, from the reader's side,
    indistinguishable from the silent drop the probe already found. The comparison below
    strips comments and everything outside the document element first, so what is asserted is
    what renders."""
    rec = VerbRecorder()
    r = run_gather(tmp_path, verbs=_gather_registry(rec), turns=[q(*DENIED_PAIR), DONE],
                   run_id="d9")
    assert r.denials, "the drive produced no denial to render"

    html = render_runtime_page(r.run_dir)
    visible = _visible_html(html)

    assert "esql" in visible, \
        "the denied verb does not appear in the page's rendered body — it is commented out, " \
        "or sits outside the document element, where an analyst never sees it"
    assert "elastic" in visible
    assert observe.POLICY_DENIAL_EVENT_TYPE in visible or "denied" in visible.lower(), \
        "the page renders the call but never says it was refused by policy"
    assert "esql" not in _visible_html("<html><body>ok</body></html>"), \
        "the visibility filter is inert — it would pass a page with no denial in it"


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








