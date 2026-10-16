"""#1255 slice E — the twin check's comparator and scanner DISCRIMINATE (O5's machinery).

The twin check (`test_1255_twin_check.py`) is only as good as two instruments: the comparator
that says where an arm differs from its natural continuation, and the scanner that finds host
layout and arm identity in what the model reads. A comparator that forgives too much makes the
twin green over a real tell; one that forgives too little makes it red over the O4 list the
design allows. So each instrument is shown here, on recordings built from real pydantic-ai
messages through the twin's own wire projection, to:

* catch a planted difference and NAME it — its channel (role, lead, request, part, tool) and
  the first content that differs on each side — so a red is actionable;
* forgive exactly the O4 list — part timestamps (never sent), RUN-CLOCK times in any spelling
  inside the window from the natural run's reading R at the branch response to R plus a
  run-length bound, duration fields, frame salts, the framework's tool-call ids, uuids — and
  not a near-miss of any of them (a content digest, a sequence number, an unpaired call id, a
  run id whose name embeds a time, a time before R, a time off the arm's own clock source or
  the wall, a time past the bound, an in-window time that runs backwards, any time at all when
  the natural run was never clocked);
* compare concurrent gather leads per lead, count requests per stream, and start after the
  branch response;
* flag a planted host path, tenant name or home directory in a request, a file or a tool
  definition — and not a longer name that merely contains one.

No run is driven here; these are fast and deterministic.
"""
from __future__ import annotations

import base64
import copy
import datetime as dt
import hashlib
import json
import re
import uuid
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.messages import (  # noqa: E402
    ModelRequest,
    ModelResponse,
    TextPart,
    ToolCallPart,
    ToolReturnPart,
    UserPromptPart,
)
from pydantic_ai.tools import ToolDefinition  # noqa: E402

from defender.tests.e2e import _1255_twin as W  # noqa: E402

pytestmark = pytest.mark.e2e

T0 = W.NATURAL_CLOCK_START
SECOND = dt.timedelta(seconds=1)
#: The natural run's clock source read twenty times, one second apart.
READINGS = [(T0 + i * SECOND).isoformat() for i in range(20)]
#: The natural run had read its clock this many times by MAIN's branch-turn request, so R —
#: its reading at the branch response — is the fourth reading, T0 + 3s.
BRANCH_READS = 4
R = T0 + (BRANCH_READS - 1) * SECOND
#: A time of the inherited history (the alert's), before R: the same on both sides.
SEEN = "2026-05-25T15:27:22.928Z"

#: The O4 values one side carries and the other side's counterparts, each in the shape its
#: producer mints (`_1255_twin.fresh_ids`): a frame salt of `wrap_fresh` (16 hex) and a review
#: stage's (`uuid4().hex`), the framework's tool-call id (`pyd_ai_` + `uuid4().hex`), the
#: session store's id (`uuid4().hex`, here under `session_id`), a duration under a named key
#: (`duration_ms`). The arm's run-clock time is R + 6s where the natural run's is R + 2s, in
#: another spelling; its part timestamps come off its own clock source (never sent, so never
#: compared).
NAT = {"ts": T0, "salt": "aabbccddeeff0011", "salt2": "5e0d1c2b3a49f8e7",
       "stage": "53ac8f7b7e2f4f14b2080f174dbce5f6",
       "call": "pyd_ai_4661543327634e72b3df2fff4563975c",
       "stamp": "2026-05-25T15:30:05+00:00", "duration": 1234,
       "session": "4203acc07b3c4b8883318710a8490096"}
ARM = {"ts": W.ARM_CLOCK_START, "salt": "0123456789abcdef", "salt2": "fedcba9876543210",
       "stage": "dd9ec9cb5ed14a418a6072262dbf3b37",
       "call": "pyd_ai_ae5d9f747c49471aad336b953b76086b",
       "stamp": "2026-05-25T15:30:09Z", "duration": 98765,
       "session": "f6bd115c0eb64a4a9a4d847f3435d137"}
#: A third fresh tool-call id, minted by neither side's run above.
OTHER_CALL = "pyd_ai_a7b5673b294240f18b6da0fe932acf01"
#: The fork turn an arm could know (its branch message id) and its world's label (finding F2-T,
#: the adversary's `twin_fresh_id_probe`).
FORK_TURN = 59
LABEL = W.CONTROL

DIGEST = "b39475bda43f761c0aeaaf2033840699d975801e98c7c0b893dba31de681ff90"


def _info(description: str = "Run one bash pipeline in the run folder.") -> Any:
    """The `AgentInfo` fields the wire projection reads, with a real `ToolDefinition`."""
    return SimpleNamespace(
        function_tools=[ToolDefinition(
            name="bash", description=description,
            parameters_json_schema={"type": "object",
                                    "properties": {"command": {"type": "string"}}})],
        output_tools=[], allow_text_output=True, model_settings=None, instructions=None)


def _conversation(o4: dict[str, Any], *, tool_out: str | None = None,
                  return_call: str | None = None, opening_extra: str | None = None,
                  ) -> list[Any]:
    """A MAIN conversation up to one bash call and its answer, stamped with `o4`'s values: the
    opening carries the history's time, the bash result a run-clock time."""
    framed = (f"Begin the investigation.\n<run-{o4['salt']}-untrusted>\n"
              f"{{\"rule\": \"v2-sshd-success-after-failures\", \"seen\": \"{SEEN}\"}}\n"
              f"</run-{o4['salt']}-untrusted>")
    if tool_out is None:
        tool_out = f"exit=0\nchecked at {o4['stamp']}\n"
    opening = [UserPromptPart(content=framed, timestamp=o4["ts"])]
    answer = [ToolReturnPart(tool_name="bash", content=tool_out,
                             tool_call_id=return_call or o4["call"], timestamp=o4["ts"])]
    if opening_extra is not None:
        answer.append(UserPromptPart(content=opening_extra, timestamp=o4["ts"]))
    return [
        ModelRequest(parts=opening, timestamp=o4["ts"]),
        ModelResponse(parts=[TextPart(content="reading the table"),
                             ToolCallPart(tool_name="bash",
                                          args={"command": "cat executed_queries.jsonl"},
                                          tool_call_id=o4["call"])],
                      timestamp=o4["ts"], model_name=f"m-{o4['duration']}"),
        ModelRequest(parts=answer, timestamp=o4["ts"]),
    ]


def _table(o4: dict[str, Any], *, call_id: str | None = "20261015t150031z-input/0",
           digest: str = DIGEST, seq: int = 0) -> str:
    """One queries-table row. `call_id=None` leaves the column out, as #1255 does (P3: the
    join moves host-side) — the shape an O2 scan of the table is run over."""
    call = f'"call_id": "{call_id}", ' if call_id is not None else ""
    return (f'{{"lead_id": "l-001", "seq": {seq}, "payload_sha256": "{digest}", '
            f'{call}"session_id": "{o4["session"]}"}}\n')


def _lessons(o4: dict[str, Any], stamp: str | None = None) -> str:
    return (f'{{"lesson_name": "x", "ts": "{stamp or o4["stamp"]}", "kind": "push", '
            f'"duration_ms": {o4["duration"]}}}\n')


def _review_prompt(o4: dict[str, Any]) -> dict[str, str]:
    """A review stage's request: its prompt framed on the stage's own salt."""
    return {"prompt": f"review\n<run-{o4['stage']}-untrusted>\nthe record\n"
                      f"</run-{o4['stage']}-untrusted>"}


def _request(role: str, lead: str | None, seq: int, wire: dict, files: dict,
             clock_reads: int = 0) -> dict[str, Any]:
    return {"role": role, "lead": lead, "seq": seq, "wire": wire, "files": files,
            "clock_reads": clock_reads}


def _natural(o4: dict[str, Any] = NAT, **kw: Any) -> dict[str, Any]:
    """A clocked natural run: two MAIN requests up to and including the one the branch turn
    answers (`BRANCH_TURN == 1`), the branch-turn lead's gather, then MAIN's next request."""
    assert W.BRANCH_TURN == 1
    pre = W.wire_request(_conversation(o4)[:1], _info())
    files = {"executed_queries.jsonl": _table(o4), "lessons_loaded.jsonl": _lessons(o4)}
    return {"requests": [
        _request("gather", W.CORRELATION_LEAD, 0, {"prompt": "correlate"}, {}, 1),
        _request("main", None, 0, pre, {}, 2),
        _request("main", None, 1, pre, {}, BRANCH_READS),
        _request("gather", W.LEAD, 0, W.wire_request(_conversation(o4)[:1], _info()), files, 6),
        _request("main", None, 2, W.wire_request(_conversation(o4, **kw), _info()), files, 8),
        _request("review:composer", None, 0, _review_prompt(o4), files, 10),
    ], "corpus": {}, "clock_readings": list(READINGS)}


def _arm(o4: dict[str, Any] = ARM, *, conversation: dict | None = None,
         description: str | None = None, files: dict | None = None) -> dict[str, Any]:
    """The arm: what the natural run did after its branch response, with `o4`'s values."""
    conv = _conversation(o4, **(conversation or {}))
    info = _info(description) if description is not None else _info()
    usual = {"executed_queries.jsonl": _table(o4), "lessons_loaded.jsonl": _lessons(o4)}
    return {"requests": [
        _request("gather", W.LEAD, 0, W.wire_request(_conversation(o4)[:1], _info()), usual),
        # every planted difference sits in MAIN's first request after the fork, alone
        _request("main", None, 0, W.wire_request(conv, info),
                 files if files is not None else usual),
        _request("review:composer", None, 0, _review_prompt(o4), usual),
    ], "corpus": {}}


# ---------------------------------------------------------------------------------------
# The comparator
# ---------------------------------------------------------------------------------------


def test_1255_twin_comparator_forgives_exactly_the_o4_list():
    """O4, O5: an arm that differs from its natural continuation ONLY by O4 values — part
    timestamps (never sent, here off the arm's own clock source), run-clock times inside the
    window (R + 2s against R + 6s, in two spellings, in a tool result and a file), a duration
    under its named key, frame salts (`wrap_fresh`'s 16 hex, a review stage's uuid4), the
    framework's tool-call id (paired in call and return on both sides), a session id, and the
    model's own bookkeeping — compares equal: nothing to report. Also when the arm's fork
    turn is known (no duration of either side equals it).

    The fixture's own control: every one of those values does differ between the two sides,
    so "equal" is the normaliser's doing, not the fixture's."""
    for key in ("salt", "stage", "call", "stamp", "duration", "session"):
        assert NAT[key] != ARM[key], key
    for o4 in (NAT, ARM):
        assert all(_a_uuid4_hex(o4[key].removeprefix("pyd_ai_"))
                   for key in ("stage", "call", "session")), o4
    assert W.compare(_natural(), _arm()) == []
    assert W.compare(_natural(), _arm(), fork_turn=FORK_TURN) == []


def _arm_stamped(stamp: str) -> dict[str, Any]:
    return {"files": {"executed_queries.jsonl": _table(ARM),
                      "lessons_loaded.jsonl": _lessons(ARM, stamp)}}


@pytest.mark.parametrize(("mutation", "arm_kw", "where", "shows"), [
    ("a content digest is not an id",
     {"files": {"executed_queries.jsonl": _table(ARM, digest="0" * 64),
                "lessons_loaded.jsonl": _lessons(ARM)}},
     "executed_queries.jsonl", "000000"),
    ("a sequence number is not a duration",
     {"files": {"executed_queries.jsonl": _table(ARM, seq=1),
                "lessons_loaded.jsonl": _lessons(ARM)}},
     "executed_queries.jsonl", '"seq": 1'),
    ("a run id that embeds a time is identity, not a timestamp",
     {"files": {"executed_queries.jsonl": _table(ARM, call_id="20261015t150031z-input-n10-a/0"),
                "lessons_loaded.jsonl": _lessons(ARM)}},
     "executed_queries.jsonl", "-n10-a/0"),
    ("a file only one side has",
     {"files": {"executed_queries.jsonl": _table(ARM)}},
     "lessons_loaded.jsonl", "absent"),
    ("a tool result's content",
     {"conversation": {"tool_out": "exit=0\nskipped '20261015t150031z-input-n10-a'\n"}},
     "(tool-return bash)", "-n10-a"),
    ("a call id that no longer pairs with its return",
     {"conversation": {"return_call": OTHER_CALL}},
     "(tool-return bash)", "<ID"),
    ("an injected opening (P4)",
     {"conversation": {"opening_extra": "Continue from here.\n\nrun_dir: /runs/x\nnow: y\n"}},
     "messages[2].parts[1]", "Continue from here."),
    ("a tool definition's text",
     {"description": "Run one bash pipeline in /srv/data/acme/runs/x."},
     "tool[bash]", "/srv/data/acme"),
    ("a time before the fork (O4: never earlier than the history)",
     _arm_stamped("2026-05-25T15:29:00Z"), "lessons_loaded.jsonl", "2026-05-25T15:29:00Z"),
    ("a time off the arm's own clock source",
     _arm_stamped((W.ARM_CLOCK_START + 7 * SECOND).isoformat()), "lessons_loaded.jsonl",
     "2026-09-01T09:00:07"),
    ("a wall-clock time", _arm_stamped("2026-10-15T16:00:00Z"), "lessons_loaded.jsonl",
     "2026-10-15T16:00:00Z"),
    ("a time past the run-length bound", _arm_stamped("2026-05-25T18:00:00Z"),
     "lessons_loaded.jsonl", "2026-05-25T18:00:00Z"),
])
def test_1255_twin_comparator_names_a_planted_difference(mutation, arm_kw, where, shows):
    """O5: one planted non-O4 difference is reported exactly once, by its channel (role and
    request, the part and tool it sits in, or the file) and the first content that differs —
    each a near-miss of something the comparison does forgive, or a tell the design names."""
    diffs = W.compare(_natural(), _arm(**arm_kw))
    assert len(diffs) == 1, f"{mutation}: {[str(d) for d in diffs]}"
    d = diffs[0]
    assert d.channel.startswith("main#0 "), (mutation, str(d))
    assert where in d.where, (mutation, str(d))
    assert shows in d.second or shows in d.first, (mutation, str(d))
    rendered = str(d)
    for piece in (d.channel, where, "natural=", "arm="):
        assert piece in rendered, rendered


def test_1255_twin_comparator_compares_concurrent_leads_per_lead():
    """O4 (the order of concurrent work): two gather leads recorded in the opposite order on
    the two sides compare equal; a difference inside one of them is attributed to that lead."""
    def lead(name: str, seq: int, text: str) -> dict[str, Any]:
        return _request("gather", name, seq, {"prompt": text}, {})

    natural = {"requests": [
        _request("main", None, 0, {"prompt": "m0"}, {}),
        _request("main", None, 1, {"prompt": "m1"}, {}),
        lead("l-001", 0, "a0"), lead("l-002", 0, "b0"), lead("l-001", 1, "a1"),
        lead("l-002", 1, "b1"),
    ], "corpus": {}}
    arm = {"requests": [lead("l-002", 0, "b0"), lead("l-002", 1, "b1"), lead("l-001", 0, "a0"),
                        lead("l-001", 1, "a1")], "corpus": {}}
    assert W.compare(natural, arm) == []
    changed = copy.deepcopy(arm)
    changed["requests"][1]["wire"]["prompt"] = "b1 + /srv/data/acme"
    diffs = W.compare(natural, changed)
    assert [d.channel for d in diffs] == ["gather/l-002#1 request"], [str(d) for d in diffs]


def test_1255_twin_comparator_counts_requests_per_stream():
    """O1: a request the arm never made, or one it made extra, is a named difference — the
    stream and both counts — not a silently shorter comparison."""
    natural = _natural()
    short = _arm()
    short["requests"] = [r for r in short["requests"] if r["role"] != "review:composer"]
    diffs = W.compare(natural, short)
    assert [(d.channel, d.first, d.second) for d in diffs] == [
        ("review:composer request count", "1 request(s)", "0 request(s)")]
    extra = _arm()
    extra["requests"].append(copy.deepcopy(extra["requests"][1]))
    assert [d.channel for d in W.compare(natural, extra)] == ["main request count"]


def test_1255_twin_comparison_starts_after_the_branch_response():
    """O1's scope: the natural run is compared from the request after the one its branch turn
    answered — MAIN's request `BRANCH_TURN` — onward. What it did before (the correlation lead,
    MAIN's first two requests) is the arm's inherited past, not compared; the lead the branch
    turn dispatched is."""
    natural = _natural()
    after = W.after_fork(natural, W.BRANCH_TURN)
    assert [(r["role"], r["lead"], r["seq"]) for r in after] == [
        ("gather", W.LEAD, 0), ("main", None, 2), ("review:composer", None, 0)]
    before = copy.deepcopy(natural)
    before["requests"][1]["wire"] = {"prompt": "anything at all before the fork"}
    assert W.compare(before, _arm()) == []


def test_1255_twin_layout_comparison_covers_every_request_and_the_corpus():
    """O3's comparison: two recordings of one run kind under two layouts are compared from the
    first request on (no fork), and the read-only corpus with them."""
    first = _natural()
    second = _natural(ARM)
    windows = (W.start_window(first), W.start_window(second))
    assert W.compare_layouts(first, second, windows=windows) == []
    second["requests"][0]["wire"]["prompt"] = "correlate under /srv/data/acme"
    second["corpus"] = {"checkout:skills/x/SKILL.md": "differs"}
    diffs = W.compare_layouts(first, second, sides=("alpha", "beta"), windows=windows)
    assert [d.channel for d in diffs] == [f"gather/{W.CORRELATION_LEAD}#0 request", "corpus"]
    assert "alpha=" in str(diffs[0]), str(diffs[0])
    assert "beta=" in str(diffs[0]), str(diffs[0])


def test_1255_twin_comparator_compares_the_corpus_in_read_scope():
    """O1 ("files in read scope"), O5; finding F2-T2 (the adversary's `twin_corpus_probe`): the
    arm is compared with its natural continuation over the read-only corpus too — the checkout's
    and the tenant agent half's lessons, skills and examples MAIN's gate admits — not only over
    the run folder. A page only the arm has (an arm-specific copy of the agent half, say) is
    named with the page and which side has it; a page whose text differs is named with its
    first differing content; the same corpus on both sides is nothing to report."""
    page = {"checkout:skills/handbook/content/runtime-loop.md": "# Runtime loop\n"}
    natural, arm = _natural(), _arm()
    natural["corpus"], arm["corpus"] = dict(page), dict(page)
    assert W.compare(natural, arm) == []
    extra = copy.deepcopy(arm)
    extra["corpus"]["agent:skills/arm-notice.md"] = (
        "# You are in a branch arm (world a, fork turn 59)\n")
    diffs = W.compare(natural, extra)
    assert [(d.channel, d.where, d.first, d.second) for d in diffs] == [
        ("corpus", "agent:skills/arm-notice.md", "absent", "present")], [str(d) for d in diffs]
    changed = copy.deepcopy(arm)
    changed["corpus"]["checkout:skills/handbook/content/runtime-loop.md"] = (
        "# Runtime loop\nThis run is a branch arm.\n")
    diffs = W.compare(natural, changed)
    assert [(d.channel, d.where) for d in diffs] == [
        ("corpus", "checkout:skills/handbook/content/runtime-loop.md")], [str(d) for d in diffs]
    assert "branch arm" in diffs[0].second, str(diffs[0])


def test_1255_twin_normalisation_keeps_ids_paired():
    """O4's fresh ids are renamed by first appearance within one value, so an id used twice
    stays one id: equal pairing is forgiven, broken pairing is not."""
    same = W.normalize_o4(f"call {NAT['call']} answered by {NAT['call']}")
    assert same == W.normalize_o4(f"call {ARM['call']} answered by {ARM['call']}")
    assert same != W.normalize_o4(f"call {ARM['call']} answered by {NAT['call']}")
    assert W.normalize_o4(DIGEST) == DIGEST, "a content digest was normalised as an id"


# ---------------------------------------------------------------------------------------
# Time (O4: consistent, not equal)
# ---------------------------------------------------------------------------------------


def test_1255_twin_clock_window_runs_from_R_to_a_run_length_bound():
    """O4: the window an arm's run-clock times are forgiven in opens at R — the natural run's
    last clock reading before its branch response, taken from the natural recording — and
    closes a run-length bound later (at least an hour). It holds R and R + δ; it holds no time
    before R, nor the arm's own clock source's start, nor the wall clock."""
    window = W.branch_window(_natural())
    assert window is not None
    assert window.start == R
    assert window.end >= R + dt.timedelta(hours=1)
    for inside in (R, R + 6 * SECOND, R + dt.timedelta(minutes=59)):
        assert window.holds(inside.isoformat()), inside
    for outside in (R - SECOND, W.ARM_CLOCK_START, dt.datetime.now(dt.UTC),
                    R + dt.timedelta(hours=3)):
        assert not window.holds(outside.isoformat()), outside
    assert W.start_window(_natural()).start == T0


def test_1255_twin_comparator_names_an_in_window_time_that_runs_backwards():
    """O4 "never runs earlier": a run-clock time inside the window still may not run backwards.
    An arm whose second MAIN request shows, as new, a time earlier than one its first already
    showed is named (stream, request, both times) — although each time alone is forgiven, and
    the files compare equal once normalised. The natural run, whose times only advance, has no
    such fault (the rule is one a natural run keeps)."""
    def extra_main(rec: dict[str, Any], seq: int, stamps: list[str], o4: dict) -> None:
        rows = "".join(_lessons(o4, s) for s in stamps)
        rec["requests"].insert(-1, _request(
            "main", None, seq, W.wire_request(_conversation(o4), _info()),
            {"executed_queries.jsonl": _table(o4), "lessons_loaded.jsonl": rows}, 12))

    natural, arm = _natural(), _arm()
    extra_main(natural, 3, [NAT["stamp"], "2026-05-25T15:30:12Z"], NAT)
    extra_main(arm, 1, [ARM["stamp"], "2026-05-25T15:30:04Z"], ARM)
    assert W.clock_order_faults(natural, W.start_window(natural), label="natural") == []
    diffs = W.compare(natural, arm)
    assert [d.channel for d in diffs] == ["arm main#1 run-clock order"], [str(d) for d in diffs]
    assert diffs[0].first.startswith("2026-05-25T15:30:09"), str(diffs[0])
    assert diffs[0].second.startswith("2026-05-25T15:30:04"), str(diffs[0])


def test_1255_twin_unclocked_natural_run_forgives_no_time():
    """O4, O5: a natural run that was never handed a clock has no window, so no time is
    forgiven — the arm's R + 6s against the natural R + 2s is named in the tool result and the
    file — rather than every time being waved through as before."""
    natural = _natural()
    del natural["clock_readings"]
    assert W.branch_window(natural) is None
    diffs = W.compare(natural, _arm())
    named = {(d.channel.split(" ")[0], d.where.split(" ")[0]) for d in diffs}
    assert ("main#0", "lessons_loaded.jsonl") in named, [str(d) for d in diffs]
    assert any("tool-return bash" in d.where and "15:30:09" in d.second for d in diffs), (
        [str(d) for d in diffs])


# ---------------------------------------------------------------------------------------
# The scanner
# ---------------------------------------------------------------------------------------

META = {"data_root": "/srv/data", "data_root_resolved": "/srv/data", "tenant": "acmecorp",
        "defender_dir": "/opt/ck/defender", "repo_root": "/opt/ck", "home": "/home/sam",
        "user": "sam"}


def _surface(tool_out: str = "exit=0\nok\n", files: dict | None = None,
             description: str | None = None) -> dict[str, Any]:
    conv = _conversation(NAT, tool_out=tool_out)
    info = _info(description) if description is not None else _info()
    return {"requests": [_request("main", None, 0, W.wire_request(conv, info),
                                  files or {"report.md": "disposition: inconclusive\n"})],
            "corpus": {"checkout:skills/elastic/SKILL.md": "# elastic\n"}}


def test_1255_twin_scanner_reads_the_content_and_finds_nothing_in_a_clean_one():
    """O2/O3 scan, positive control: the scanner reads the request, the files and the corpus
    (a token present in each is found where it is), and finds no host token in a recording
    that carries none."""
    rec = _surface()
    assert W.scan(rec, W.host_tokens(META)) == []
    found = W.scan(rec, {"rule": "v2-sshd-success-after-failures",
                         "report": "disposition: inconclusive", "corpus": "# elastic"})
    assert sorted((f.channel, f.what) for f in found) == [
        ("corpus:checkout:skills/elastic/SKILL.md", "corpus"),
        ("main#0 files:report.md", "report"),
        ("main#0 request", "rule")]


@pytest.mark.parametrize(("planted", "surface_kw", "what", "channel"), [
    ("a data-root path in a tool result",
     {"tool_out": "raw payload: /srv/data/acmecorp/runs/x/gather_raw/l-001/0.json"},
     {"data root", "data root (resolved)", "tenant name"}, "main#0 request"),
    ("the checkout path in a tool definition",
     {"description": "Read skills under /opt/ck/defender/skills on demand."},
     {"checkout path", "checkout repo root"}, "main#0 request"),
    ("the tenant folder in a file",
     {"files": {"report.md": "see acmecorp's table pointer\n"}},
     {"tenant name"}, "main#0 files:report.md"),
    ("the host user's home in a refusal",
     {"tool_out": "could not read /home/sam/.cache/x: [Errno 2]"},
     {"host home", "host user dir"}, "main#0 request"),
])
def test_1255_twin_scanner_flags_a_planted_host_value(planted, surface_kw, what, channel):
    """O3 scan: a host value planted in a request, a tool definition or a file is reported with
    the surface it sits in and the token found."""
    found = W.scan(_surface(**surface_kw), W.host_tokens(META))
    assert {f.what for f in found} == what, (planted, [str(f) for f in found])
    assert {f.channel for f in found} == {channel}, (planted, [str(f) for f in found])


def test_1255_twin_scanner_matches_whole_names_only():
    """The scan's tokens are whole paths and names: a longer name that merely contains one
    (another tenant `acmecorporate`, a folder `/srv/database`, `/home/samuel`) is not that
    host value, while the value itself followed by a path separator is."""
    rec = _surface(tool_out="acmecorporate /srv/database /home/samuel /srv/data/")
    found = W.scan(rec, W.host_tokens(META))
    assert {f.what for f in found} == {"data root", "data root (resolved)"}, \
        [str(f) for f in found]


def test_1255_twin_identity_tokens_name_every_scannable_arm_identity():
    """O2's scannable list: the arm's own run id, its source run's id, its sibling's run id,
    the episode id, and the episode and world tokens production composed; a natural run's own
    run id for the natural side."""
    pair = {"natural": {"run_id": "20261015t150031z-input"},
            "arm": {"run_id": "20261015t150031z-input-n10-a"},
            "sibling": {"run_id": "20261015t150031z-input-n10-r"},
            "episode_id": "20261015t150031z-input-n10",
            "episode_token": "20261015t150031z.input.n10",
            "world_token": "20261015t150031z.input.n10.a",
            "sibling_world_token": "20261015t150031z.input.n10.r"}
    assert W.identity_tokens(pair, "natural") == {"natural run id": "20261015t150031z-input"}
    base = {
        "source run id": "20261015t150031z-input",
        "arm run id": "20261015t150031z-input-n10-a",
        "sibling run id": "20261015t150031z-input-n10-r",
        "episode id": "20261015t150031z-input-n10",
        "episode token": "20261015t150031z.input.n10",
        "world token": "20261015t150031z.input.n10.a",
        "sibling world token": "20261015t150031z.input.n10.r"}
    assert W.identity_tokens(pair, "arm") == base
    # F2-T: once the pair names its branch message, the fork turn and each launched world's
    # label are listed too, in the spellings an id or a salt would carry them in
    with_fork = W.identity_tokens(pair | {"branch_message_id": FORK_TURN}, "arm")
    assert with_fork.items() >= base.items()
    for label in ("a", "r"):
        folded = (FORK_TURN << 8) | ord(label)
        assert with_fork[f"world label {label} with the fork turn (uuid int)"] == (
            uuid.UUID(int=folded).hex)
        assert with_fork[f"world label {label} with the fork turn (uuid int, hyphenated)"] == (
            str(uuid.UUID(int=folded)))
        assert with_fork[f"world label {label} (uuid int)"] == uuid.UUID(int=ord(label)).hex
        assert with_fork[f"world label {label} (16-hex int)"] == f"{ord(label):016x}"
    assert with_fork["fork turn (uuid int)"] == uuid.UUID(int=FORK_TURN).hex
    assert with_fork["fork turn (uuid int, hyphenated)"] == str(uuid.UUID(int=FORK_TURN))
    assert with_fork["fork turn (16-hex int)"] == f"{FORK_TURN:016x}"


#: A layout's arm identities (`identity_tokens(…, "arm")` over the pair the test above spells).
ARM_PAIR = {"natural": {"run_id": "20261015t150031z-input"},
            "arm": {"run_id": "20261015t150031z-input-n10-a"},
            "sibling": {"run_id": "20261015t150031z-input-n10-r"},
            "episode_id": "20261015t150031z-input-n10",
            "episode_token": "20261015t150031z.input.n10",
            "world_token": "20261015t150031z.input.n10.a",
            "sibling_world_token": "20261015t150031z.input.n10.r"}
_WORLD_TOKEN = ARM_PAIR["world_token"]
_MD5_OF_WORLD = hashlib.md5(_WORLD_TOKEN.encode("utf-8")).hexdigest()
_UUID5_OF_WORLD = uuid.uuid5(uuid.NAMESPACE_URL, _WORLD_TOKEN)
#: The same two derivations forced into a uuid4's shape (version nibble and variant bits set):
#: what the comparison's producer-shape rule alone would forgive as a fresh id.
_MD5_AS_FRESH = uuid.UUID(bytes=hashlib.md5(_WORLD_TOKEN.encode("utf-8")).digest(),
                          version=4).hex
_UUID5_AS_FRESH = uuid.UUID(bytes=_UUID5_OF_WORLD.bytes, version=4).hex
_B64_RECORD = base64.b64encode(json.dumps(
    {"lead_id": "l-001", "seq": 0, "w": _WORLD_TOKEN}).encode("utf-8")).decode("ascii")


def _a_uuid4_hex(value: str) -> bool:
    """The test's own reading of a `uuid.uuid4().hex` (never the instrument's predicate): 32
    lowercase hex whose uuid is RFC 4122 version 4."""
    return (re.fullmatch(r"[0-9a-f]{32}", value) is not None
            and uuid.UUID(hex=value).variant == uuid.RFC_4122
            and uuid.UUID(hex=value).version == 4)


def _review_frame(salt: str) -> str:
    return f"<run-{salt}-untrusted>\nholds\n</run-{salt}-untrusted>\n"


@pytest.mark.parametrize(("planted", "surface_kw", "forgiven", "how"), [
    ("an md5 of the world token in a uuid4's shape, as a review frame's salt in a readable file",
     {"files": {"report.md": _review_frame(_MD5_AS_FRESH)}}, _MD5_AS_FRESH, "md5 hex"),
    ("a uuid5 over the world token in a uuid4's shape, as a tool-call id in a tool result",
     {"tool_out": f"exit=0\nretry pyd_ai_{_UUID5_AS_FRESH}\n"}, _UUID5_AS_FRESH, "uuid5(url)"),
    ("the world token base64-encoded inside a record in a readable file",
     {"files": {"report.md": f"ref: {_B64_RECORD}\n"}}, None, "inside an encoded run"),
], ids=["md5", "uuid5", "base64-record"])
def test_1255_twin_identity_scan_finds_a_derived_identity_the_comparison_forgives(
        planted, surface_kw, forgiven, how):
    """O2, R-2, F2-T: the comparison forgives a fresh id in its producer's shape (a uuid4 as a
    review frame's salt or a tool-call id), and a literal scan cannot see an identity written as
    a digest or a uuid over it forced into that shape, or inside base64 — so an arm that names
    its world that way would pass both. The O2 identity scan (`encoded=True`, what the twin
    check runs) finds each and names the encoding (a derived form, or a derived form "as a
    fresh id": equal outside the uuid version and variant nibbles).

    Shown on the same surface: the planted id IS forgiven by the O4 normaliser (it is gone once
    normalised), the literal scan finds nothing, and the encoded scan finds nothing on the clean
    surface (its positive and negative halves). The same derivations in their own shapes — a
    bare md5 hex, a uuid5 — are not fresh ids at all: the comparison names them
    (`test_1255_twin_comparator_forgives_no_id_its_producer_did_not_mint`)."""
    tokens = W.identity_tokens(ARM_PAIR, "arm")
    assert tokens["world token"] == _WORLD_TOKEN
    assert W.scan(_surface(), tokens, encoded=True) == [], "the encoded scan flags a clean surface"
    rec = _surface(**surface_kw)
    if forgiven is not None:
        assert _a_uuid4_hex(forgiven), f"fixture: {planted} is not in a uuid4's shape"
        shown = json.dumps(rec, ensure_ascii=False)
        assert forgiven in shown, f"fixture: {planted} is not on the surface"
        assert forgiven not in W.normalize_o4(shown), (
            f"fixture: {planted} is not one the comparison forgives")
    assert W.scan(rec, tokens) == [], f"fixture: the literal scan already finds {planted}"
    found = W.scan(rec, tokens, encoded=True)
    assert any(f.what.startswith(f"world token ({how}") for f in found), (
        planted, [str(f) for f in found])


# ---------------------------------------------------------------------------------------
# Arm identity in a value the comparison forgives (finding F2-T; the adversary's
# `twin_fresh_id_probe`, turned into tests)
# ---------------------------------------------------------------------------------------

#: The arm's pair, now naming its branch message: the fork turn and labels join the scan.
FORK_PAIR = ARM_PAIR | {"branch_message_id": FORK_TURN}
#: A uuid1 (version 1: a timestamp and a host node), spelled deterministically.
_UUID1 = uuid.UUID(fields=(0x1D2C3B4A, 0x5E6F, 0x11F1, 0x92, 0x34, 0x0123456789AB))


def _no_call_ids(recording: dict[str, Any]) -> dict[str, Any]:
    """`recording` with the queries table's `call_id` column gone from every snapshot, as #1255
    leaves the table (the fixture's call id names the source run, which the O2 scan would find
    — rightly, but not the point here)."""
    out = copy.deepcopy(recording)
    for request in out["requests"]:
        for name, text in request["files"].items():
            request["files"][name] = re.sub(r'"call_id": "[^"]*", ', "", text)
    return out


def _arm_with_session(value: str) -> dict[str, Any]:
    """The arm, its queries table carrying `value` where the natural run's carries its fresh
    session id."""
    arm = ARM | {"session": value}
    return _no_call_ids(_arm(files={"executed_queries.jsonl": _table(arm),
                                    "lessons_loaded.jsonl": _lessons(arm)}))


@pytest.mark.parametrize(("planted", "value", "scanned_as"), [
    ("the fork turn as a uuid integer", uuid.UUID(int=FORK_TURN).hex, "fork turn (uuid int)"),
    ("the fork turn and the world label folded into a hyphenated uuid",
     str(uuid.UUID(int=(FORK_TURN << 8) | ord(LABEL))),
     f"world label {LABEL} with the fork turn (uuid int, hyphenated)"),
    ("a uuid1 (a time and a host node)", _UUID1.hex, None),
    ("a constant marker", "a" * 32, None),
    ("an md5 of the world token", _MD5_OF_WORLD, "world token (md5 hex)"),
    ("a uuid5 over the world token", _UUID5_OF_WORLD.hex, "world token (uuid5(url) hex)"),
], ids=["uuid-int-fork-turn", "uuid-with-label", "uuid1", "constant-marker", "md5", "uuid5"])
def test_1255_twin_comparator_forgives_no_id_its_producer_did_not_mint(planted, value,
                                                                     scanned_as):
    """O2, O4 ("fresh random ids"), O5; finding F2-T: a value that stands where the run mints a
    fresh id but is not one its producer would mint — here the session store's id (a
    `uuid4().hex`) — is compared exactly, so the arm that writes the fork turn as
    `UUID(int=k)`, the world label folded into a uuid, a uuid1, a constant marker, or an
    identity's digest or uuid5 there is named (one difference: the file and the planted value).
    Where the value spells an arm identity as an id, the O2 scan names it too.

    Control on the same fixture: the arm with a genuine fresh session id compares equal and
    scans clean, so each red is the planted value's."""
    tokens = W.identity_tokens(FORK_PAIR, "arm")
    natural = _no_call_ids(_natural())
    control = _arm_with_session(ARM["session"])
    assert W.compare(natural, control) == []
    assert W.scan(control, tokens, encoded=True) == []
    assert not _a_uuid4_hex(value), f"fixture: {planted} is a uuid4"
    arm = _arm_with_session(value)
    diffs = W.compare(natural, arm)
    assert [(d.channel, d.where) for d in diffs] == [("main#0 files", "executed_queries.jsonl")], (
        planted, [str(d) for d in diffs])
    assert value[:20] in diffs[0].second, (planted, str(diffs[0]))
    found = {f.what for f in W.scan(arm, tokens, encoded=True)}
    if scanned_as is not None:
        assert scanned_as in found, (planted, sorted(found))


def test_1255_twin_comparator_forgives_a_uuid4_only_where_a_producer_mints_one():
    """O4, finding F2-T: a genuine uuid4 under a key no producer owns is not a fresh id the
    design lists, so it is compared exactly — the shape alone forgives nothing. (The same
    values under `session_id` compare equal: `test_1255_twin_comparator_forgives_exactly_…`.)"""
    def keyed_case(recording: dict[str, Any]) -> dict[str, Any]:
        out = copy.deepcopy(recording)
        for request in out["requests"]:
            for name, text in request["files"].items():
                request["files"][name] = text.replace('"session_id"', '"case"')
        return out

    diffs = W.compare(keyed_case(_natural()), keyed_case(_arm()))
    assert diffs, "a uuid4 under a key no producer owns was forgiven"
    assert {d.where for d in diffs} == {"executed_queries.jsonl"}, [str(d) for d in diffs]
    assert all(ARM["session"][:20] in d.second for d in diffs), [str(d) for d in diffs]


@pytest.mark.parametrize(("planted", "salt", "compared", "scanned_as"), [
    ("the fork turn in a salt of the wrong length", f"{FORK_TURN:x}00ff", True, None),
    ("the fork turn as a 32-hex salt that is no uuid4", uuid.UUID(int=FORK_TURN).hex, True,
     "fork turn (uuid int)"),
    ("the fork turn as a salt-length integer", f"{FORK_TURN:016x}", False,
     "fork turn (16-hex int)"),
], ids=["short-salt", "uuid-int-salt", "16-hex-int-salt"])
def test_1255_twin_comparator_forgives_only_a_salt_its_producer_mints(planted, salt, compared,
                                                                      scanned_as):
    """O2, O4, finding F2-T: a frame's salt is forgiven only in the shape its producer mints —
    `wrap_fresh`'s 16 hex, or a review stage's uuid4 — so a salt carrying the fork turn in any
    other shape is compared exactly and named; one in the right shape whose value spells the
    fork turn (`f"{k:016x}"`) is forgiven by the comparison and named by the O2 scan."""
    tokens = W.identity_tokens(FORK_PAIR, "arm")
    natural = _no_call_ids(_natural())
    arm = _no_call_ids(_arm(ARM | {"salt": salt}))
    diffs = W.compare(natural, arm)
    if compared:
        assert diffs, f"{planted}: forgiven"
        assert all(salt in d.second for d in diffs), (planted, [str(d) for d in diffs])
    else:
        assert diffs == [], (planted, [str(d) for d in diffs])
    found = {f.what for f in W.scan(arm, tokens, encoded=True)}
    if scanned_as is not None:
        assert scanned_as in found, (planted, sorted(found))


def test_1255_twin_comparator_names_a_constant_where_the_run_mints_two_fresh_ones():
    """O4 ("fresh random ids"), finding F2-T: two frames in one request are two salts — the
    natural run mints one per frame. An arm that frames both on one constant shows one id where
    the natural run shows two, and is named at the second frame; the same arm with a second
    fresh salt compares equal (the control)."""
    def framed(salt: str) -> str:
        return f"exit=0\n<run-{salt}-untrusted>\nrow\n</run-{salt}-untrusted>\n"

    natural = _natural(tool_out=framed(NAT["salt2"]))
    assert W.compare(natural, _arm(conversation={"tool_out": framed(ARM["salt2"])})) == []
    diffs = W.compare(natural, _arm(conversation={"tool_out": framed(ARM["salt"])}))
    assert [d.channel for d in diffs] == ["main#0 request"], [str(d) for d in diffs]
    assert "tool-return bash" in diffs[0].where, str(diffs[0])


def _with_field(recording: dict[str, Any], key: str, value: int) -> dict[str, Any]:
    """`recording` with `key: value` added to every lessons-log row in every snapshot."""
    out = copy.deepcopy(recording)
    for request in out["requests"]:
        files = request["files"]
        if "lessons_loaded.jsonl" in files:
            # a new dict per request: the fixture's requests share one `files` mapping
            request["files"] = {**files, "lessons_loaded.jsonl": files[
                "lessons_loaded.jsonl"].replace("}\n", f', "{key}": {value}}}\n')}
    return out


@pytest.mark.parametrize("key", ["wall_ms", "elapsed_seconds", "wall_clock_timeout",
                                 "grace_seconds"])
def test_1255_twin_comparator_forgives_a_duration_only_under_its_named_keys(key):
    """O4 ("durations"), D2, finding F2-T: only production's own elapsed-measure keys
    (`DURATION_KEYS`) are forgiven as durations. A number under any other key that merely
    sounds like timing — the fork turn written as a `wall_ms`, an `elapsed_seconds`, or a limit
    the arm inherits (`wall_clock_timeout`, `grace_seconds`) — is compared exactly: named
    where it differs, nothing to report where it does not."""
    assert key not in W.DURATION_KEYS
    natural = _with_field(_natural(), key, 1234)
    assert W.compare(natural, _with_field(_arm(), key, 1234)) == []
    diffs = W.compare(natural, _with_field(_arm(), key, FORK_TURN))
    assert diffs, f"{key}: forgiven"
    assert all(d.where == "lessons_loaded.jsonl" and f'"{key}": {FORK_TURN}' in d.second
               for d in diffs), [str(d) for d in diffs]


def test_1255_twin_comparator_never_forgives_a_duration_equal_to_the_fork_turn():
    """O2, O4, finding F2-T: a duration under a named key is forgiven — except, on the arm, one
    equal to the arm's fork turn (`compare(fork_turn=)`), which is the fork turn written as a
    timing. Without the fork turn the same arm compares equal (the carve-out is what names it);
    the natural run's own durations are never held to it."""
    arm = _arm(ARM | {"duration": FORK_TURN})
    assert W.compare(_natural(), arm) == []
    diffs = W.compare(_natural(), arm, fork_turn=FORK_TURN)
    assert diffs, "a duration equal to the fork turn was forgiven"
    assert all(d.where == "lessons_loaded.jsonl" and f'"duration_ms": {FORK_TURN}' in d.second
               for d in diffs), [str(d) for d in diffs]
    natural = _natural(NAT | {"duration": FORK_TURN})
    assert W.compare(natural, _arm(), fork_turn=FORK_TURN) == []


@pytest.mark.parametrize(("rel", "main", "gather"), [
    ("investigation.md", True, True),
    ("executed_queries.jsonl", True, True),
    ("lessons_loaded.jsonl", True, True),
    ("provenance.json", False, False),
    ("wire_logs/llm_requests.jsonl", False, False),
    ("gather_summaries/l-001.md", True, True),
    ("gather_summaries/l-001/x.md", False, False),
    ("gather_raw/l-001/0.json", False, True),
    ("gather_raw/l-001.lead.json", False, False),
    ("alert_input/alert.json", True, True),
    ("alert_input/nested/alert.json", False, False),
])
def test_1255_twin_read_scope_parity(tmp_path, rel, main, gather):
    """The twin snapshots, at each request, the files that role's REAL gate admits
    (`permission.decide_read` over the compiled MAIN and gather policies, as the driver binds
    them). This holds that gate to the static table written from the read shapes
    (`in_read_scope`): the run root one segment deep but not the provenance stamp; gather
    summaries one deep; the alert input one deep; gather's raw payloads for gather alone; never
    `wire_logs/`. A rule change shows here, by role, instead of as a quietly different
    snapshot."""
    from pathlib import Path
    from types import SimpleNamespace

    from defender.tests import _tenants1106

    run_dir = tmp_path / "runs" / "20261015t150031z-input"
    target = run_dir / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("x\n", encoding="utf-8")
    tenant = SimpleNamespace(agent=None, grants=_tenants1106.fixture_grants())
    policies = W.read_policies(run_dir, W.DEFENDER, tenant)
    for role, expected in (("main", main), ("gather", gather)):
        assert W.in_read_scope(Path(rel), role) is expected, (role, rel, "static table")
        gate = W._readable(target, run_dir=run_dir, defender_dir=W.DEFENDER,
                           policy=policies[role])
        assert gate is expected, (role, rel, "the gate disagrees with the static table")
        snapshot = W.files_snapshot(run_dir, defender_dir=W.DEFENDER, policy=policies[role])
        assert (rel in snapshot) is expected, (role, rel, sorted(snapshot))


def test_1255_twin_review_roles_read_no_file():
    """Why the twin records no files for a review request (`READING_ROLES`): every review
    stage — the two lenses (`support`, and `ablation` staged on the same definition) and the
    composer — runs on a definition that holds no tool at all, so its whole model-visible input
    is the prompt its request records. Held to the definitions, so a review role that gains a
    tool shows here rather than as a silently empty snapshot."""
    from defender.runtime.agent_definition import ToolSet
    from defender.runtime.challenge_gate import REVIEW_ROLES
    from defender.runtime.review_roles import COMPOSER_DEF, SUPPORT_DEF

    assert set(REVIEW_ROLES) == {"support", "ablation", "composer"}, REVIEW_ROLES
    for defn in (SUPPORT_DEF, COMPOSER_DEF):
        assert defn.tools == ToolSet(), (defn.role, defn.tools)
    assert set(W.READING_ROLES) == {"main", "gather"}
