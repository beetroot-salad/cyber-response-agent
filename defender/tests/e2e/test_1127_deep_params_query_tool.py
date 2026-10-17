"""#1127 e2e: a `query` call whose arguments nest past the limit (32) is a counted schema rejection, never reaches the verb, leaves one readable `{}`-params row, is answered with one fixed host sentence echoing nothing the model sent, counts toward the rejection budget and repeat guard at every depth, and costs no other row its seq/sidecar. Depths are chosen for the regimes where pydantic and json.loads stop; each arm asserts its own regime."""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

import pytest

pytest.importorskip("pydantic_ai")

from pydantic import BaseModel, TypeAdapter, ValidationError  # noqa: E402

from defender._io import (  # noqa: E402
    JSON_NESTING_LIMIT,
    json_nesting_depth,
    parse_jsonl_row,
    read_jsonl_rows,
)
from defender.run_repository import RunPaths  # noqa: E402
from defender.runtime import session_store  # noqa: E402
from defender.runtime.verbs import VerbContext  # noqa: E402
from defender import _query_rules  # noqa: E402
from defender.scripts.gather_tools import record_query as rq  # noqa: E402
from defender.tests._verb_authorization_632 import (  # noqa: E402
    DONE,
    LEAD,
    ScopedFakeVerbs,
    evidence_snapshot,
    grant_of,
    q,
    run_gather,
)
from defender.tests.e2e._replay_harness import Turn, VerbRecorder  # noqa: E402
from defender.tests.e2e.test_1015_rejection_budget import (  # noqa: E402
    _assert_budget_stop,
    _terminator,
)
from defender.tests.e2e.test_855_model_named_systems import (  # noqa: E402
    _above_guard,
    _bad_args,
)
from defender.tests.e2e.test_repeat_breaker_807 import _replay_rejections  # noqa: E402

pytestmark = pytest.mark.e2e

B = rq.REJECTION_BUDGET

#: The deepest params map a call may carry (the map counted as 1). Spelled: the product
#: constant it must equal is pinned in `test_1127_params_nesting_limit`.
LIMIT = 32

#: The first depth a row cannot carry. Pydantic accepts it in either form, so it is where an
#: off-by-one at the tool shows: one level more lenient and the call runs.
ONE_PAST = LIMIT + 1
ACCEPTED = 150
REFUSED = 300
RECURSION = 680
UNDECODABLE = 5000

#: Distinctive, digit-free strings placed inside the deep params: one as a KEY in the deep part,
#: one as the VALUE of the shallow `native_query`. Digit-free so a search for the limit's own
#: number can never be satisfied by one of them.
SENTINEL_KEY = "ZqNestCanaryKey"
SENTINEL_VALUE = "ZqNestCanaryValue"
#: An UNDECLARED system name, digit-free for the same reason: the row coarsens it away, so the
#: only way it could reach the model or the row is an echo of the call.
SENTINEL_SYSTEM = "ZqNestCanarySystem"

#: The valid call a lead makes when nothing stopped it.
VALID = {"native_query": "FROM logs"}


# ── the calls ──────────────────────────────────────────────────────────────────────────────


def _chain(depth: int) -> Any:
    value: Any = "leaf"
    for _ in range(depth):
        value = {"k": value}
    return value


def _chain_text(depth: int) -> str:
    """`_chain(depth)` as JSON text, built as a STRING:"""
    return '{"k":' * depth + '"leaf"' + "}" * depth


def deep_params(depth: int) -> dict:
    """Params nested `depth` deep with the map itself counted, carrying both sentinels."""
    return {"filt": {SENTINEL_KEY: _chain(depth - 2)}, "native_query": SENTINEL_VALUE}


def deep_params_text(depth: int) -> str:
    return (f'{{"filt": {{"{SENTINEL_KEY}": {_chain_text(depth - 2)}}}, '
            f'"native_query": "{SENTINEL_VALUE}"}}')


def deep_list_text(depth: int) -> str:
    """A params value that is a LIST nested `depth` deep (the list itself counted), with the value sentinel at..."""
    return "[" * depth + json.dumps(SENTINEL_VALUE) + "]" * depth


#: Params that are shallow but carry both sentinels — for the shapes whose excess depth is in
#: ANOTHER argument, so a refusal that stored them, or echoed them, shows.
SHALLOW_PARAMS = deep_params(2)


@dataclass(frozen=True)
class Shape:
    """One way a too-deep call arrives:"""

    name: str
    form: str
    depth: int


def args_text(shape: Shape, system: str, verb: str) -> str:
    """The whole argument body as a provider sends it."""
    if shape.form.startswith("qid-"):
        return (f'{{"query_id": {deep_list_text(shape.depth)}, '
                f'"params": {json.dumps(SHALLOW_PARAMS)}, "system": {json.dumps(system)}, '
                f'"verb": {json.dumps(verb)}}}')
    params = (deep_list_text(shape.depth) if shape.form == "list-text"
              else deep_params_text(shape.depth))
    return (f'{{"params": {params}, "system": {json.dumps(system)}, '
            f'"verb": {json.dumps(verb)}}}')


DICT_ONE_PAST = Shape("dict-one-past", "dict", ONE_PAST)
TEXT_ONE_PAST = Shape("text-one-past", "text", ONE_PAST)
DICT_ACCEPTED = Shape("dict-accepted", "dict", ACCEPTED)
TEXT_ACCEPTED = Shape("text-accepted", "text", ACCEPTED)
TEXT_LIST = Shape("text-list", "list-text", ACCEPTED)
TEXT_REFUSED = Shape("text-refused", "text", REFUSED)
TEXT_RECURSION = Shape("text-recursion", "text", RECURSION)
TEXT_UNDECODABLE = Shape("text-undecodable", "text", UNDECODABLE)
#: One past the limit in `query_id`, params shallow: the scan covers EVERY argument.
DICT_QUERY_ID = Shape("dict-query-id", "qid-dict", ONE_PAST)
TEXT_QUERY_ID = Shape("text-query-id", "qid-text", ONE_PAST)

EVERY_SHAPE = [DICT_ONE_PAST, TEXT_ONE_PAST, TEXT_LIST, TEXT_REFUSED, TEXT_RECURSION,
               TEXT_UNDECODABLE, TEXT_QUERY_ID]

#: The otherwise-valid calls pydantic accepts, which would therefore RUN unless refused.
WOULD_RUN = [DICT_ONE_PAST, TEXT_ONE_PAST]


def deep_call(shape: Shape, *, system: str = "elastic", verb: str = "query") -> Turn:
    if shape.form == "dict":
        args: Any = {"params": deep_params(shape.depth), "system": system, "verb": verb}
    elif shape.form == "qid-dict":
        args = {"query_id": json.loads(deep_list_text(shape.depth)), "params": SHALLOW_PARAMS,
                "system": system, "verb": verb}
    else:
        args = args_text(shape, system, verb)
    return Turn(tool_calls=[("query", args)])


_ARGS = TypeAdapter(dict[str, Any])


class _QueryArgs(BaseModel):
    """The `query` tool's own argument schema, restated for the list shape's precondition."""

    system: str
    verb: str
    params: dict[str, Any]
    query_id: str | None = None


def assert_regime(shape: Shape) -> None:
    """The precondition every arm states for its own shape:"""
    text = args_text(shape, "elastic", "query")
    assert json_nesting_depth(text) == shape.depth + 1, "the builder's depth arithmetic moved"
    if shape.form.startswith("qid-"):
        # The depth is all in `query_id`; params are shallow. Pydantic's parser reads it, the
        # SCHEMA refuses `query_id` (not a string), and that error would carry the body.
        decoded = json.loads(text)
        assert decoded["params"] == SHALLOW_PARAMS
        assert json_nesting_depth(json.dumps(decoded["params"])) == 2
        assert json_nesting_depth(json.dumps(decoded["query_id"])) == shape.depth
        with pytest.raises(ValidationError) as refused:
            _QueryArgs.model_validate_json(text)
        assert [err["type"] for err in refused.value.errors()] == ["string_type"]
        assert SENTINEL_VALUE in str(refused.value.errors()), \
            "pydantic's own error no longer echoes the input, so the O4 arm is vacuous here"
        return
    if shape.form == "list-text":
        # The parser reads it and `json.loads` decodes it; the SCHEMA refuses it, and the error
        # pydantic would hand the model carries the body.
        assert isinstance(json.loads(text)["params"], list)
        with pytest.raises(ValidationError) as refused:
            _QueryArgs.model_validate_json(text)
        assert [err["type"] for err in refused.value.errors()] == ["dict_type"]
        assert SENTINEL_VALUE in str(refused.value.errors()), \
            "pydantic's own error no longer echoes the input, so the O4 arm is vacuous here"
        return
    if shape.depth <= ACCEPTED:
        _ARGS.validate_json(text)
        assert json.loads(text)["params"] == deep_params(shape.depth), \
            "the dict and text forms of one shape are not the same call"
        return
    with pytest.raises(ValidationError):
        _ARGS.validate_json(text)
    if shape.depth < UNDECODABLE:
        assert json.loads(text)["system"] == "elastic"
    else:
        with pytest.raises(RecursionError):
            json.loads(text)


# ── the estate ─────────────────────────────────────────────────────────────────────────────


def registry(rec: VerbRecorder) -> ScopedFakeVerbs:
    """`elastic` declaring two verbs with a dict-typed `filt`, only `query` granted — so `esql` is DECLARED AND..."""

    def query(ctx: VerbContext, *, native_query: str, filt: dict | None = None) -> list[dict]:
        rec.record("query", ctx, {"native_query": native_query, "filt": filt})
        return [{"answered": native_query, "call": len(rec.calls)}]

    def esql(ctx: VerbContext, *, native_query: str, filt: dict | None = None) -> list[dict]:
        rec.record("esql", ctx, {"native_query": native_query, "filt": filt})
        return [{"answered": native_query, "call": len(rec.calls)}]

    return ScopedFakeVerbs({"elastic": {"query": query, "esql": esql}},
                           grant_of("gather", [("elastic", "query")]))


def drive(tmp_path, name: str, turns: list[Turn], *, watch: bool = False):
    rec = VerbRecorder()
    r = run_gather(tmp_path / name, verbs=registry(rec), turns=turns,
                   run_id=f"d1127-{name}", watch=watch)
    return r, rec


# ── observations ───────────────────────────────────────────────────────────────────────────


def raw_lines(r) -> list[str]:
    """The queries table's physical lines — every one, including those its reader skips."""
    table = RunPaths(r.run_dir).executed_queries
    if not table.is_file():
        return []
    return [line for line in table.read_text(encoding="utf-8").splitlines() if line.strip()]


def unreadable(r) -> list[str]:
    return [line[:120] for line in raw_lines(r) if parse_jsonl_row(line) is None]


def own_raw_lines(r) -> list[str]:
    needle = f'"lead_id": {json.dumps(LEAD)}'
    return [line for line in raw_lines(r) if needle in line]


def retry_texts(r) -> list[str]:
    """What each gather call's answer added to the model's context, one entry per call:"""
    seen = r.gather.seen
    for earlier, later in zip(seen, seen[1:], strict=False):
        assert later.startswith(earlier), "the model's history is not append-only"
    return [later[len(earlier):] for earlier, later in zip(seen, seen[1:], strict=False)]


def denied_verbs(r) -> list[str]:
    path = RunPaths(r.run_dir).policy_denials
    return [rec.get("verb") for rec in read_jsonl_rows(path)] if path.is_file() else []


def names_the_limit(text: str) -> bool:
    return re.search(rf"(?<!\d){LIMIT}(?!\d)", text) is not None


def assert_speaks_of_the_arguments(text: str) -> None:
    """D's wording:"""
    assert re.search(r"\barguments? nest", text, re.IGNORECASE), \
        f"the answer does not say the call's arguments nest too deep: {text[:300]!r}"
    assert "params nest" not in text.lower(), f"the answer says params nest: {text[:300]!r}"


def model_text_in(text: str) -> list[str]:
    """Every fragment of the call's own arguments, or of pydantic's rendering of them, that `text` carries."""
    fragments = (SENTINEL_KEY, SENTINEL_VALUE, SENTINEL_SYSTEM, "input_value", "'input'",
                 "'loc'", "type=", '{"k"', "{'k'")
    return [f for f in fragments if f in text]


# ── O1 / O3 / C12: every too-deep call leaves exactly one readable, counted row ────────────


@pytest.mark.parametrize("shape", EVERY_SHAPE, ids=lambda s: s.name)
def test_every_too_deep_call_leaves_one_readable_rejection_row_with_no_params(tmp_path, shape):
    """O1 and O3's "any deep call leaving no row":"""
    assert_regime(shape)
    r, rec = drive(tmp_path, shape.name, [deep_call(shape), DONE])

    assert unreadable(r) == [], "the run wrote a line its own reader skips"
    rows = r.own_rows
    assert len(rows) == 1, f"the deep call left {len(rows)} readable rows, not one"
    row = rows[0]
    assert rq.in_rejection_domain(row), \
        f"the deep call's row is outside the rejection domain: {row['query_id']!r}, " \
        f"{row['error_class']!r} — neither guard counts it"
    assert row["params"] == {}
    assert len(own_raw_lines(r)) == 1
    assert rec.calls == [], "a too-deep call reached the verb"


# ── O2: a too-deep call never runs ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("shape", WOULD_RUN, ids=lambda s: s.name)
def test_a_too_deep_call_pydantic_accepts_never_reaches_the_verb(tmp_path, shape):
    """O2, at the only regime where it can fail:"""
    assert_regime(shape)
    shallow = {"native_query": "FROM logs", "filt": {"a": 1}}
    r, rec = drive(tmp_path, shape.name, [
        deep_call(shape), q("elastic", "query", shallow), DONE])

    assert [(c.verb, c.params) for c in rec.calls] == [("query", shallow)], \
        "the verb was called for the too-deep call, or not for the shallow one"
    assert [row["query_id"] for row in r.own_rows] == [_query_rules.ABOVE_GUARD_QUERY_ID, "elastic.query"]


@pytest.mark.parametrize("form", ["dict", "text"])
def test_a_call_at_the_limit_runs_and_is_recorded_whole(tmp_path, form):
    """The positive control at the boundary, through the tool:"""
    shape = Shape(f"{form}-at-limit", form, LIMIT)
    assert_regime(shape)
    r, rec = drive(tmp_path, shape.name, [deep_call(shape), DONE])

    assert [(c.verb, c.params) for c in rec.calls] == [("query", deep_params(LIMIT))], \
        "a call at the limit did not reach the verb with its params whole"
    assert unreadable(r) == []
    rows = r.own_rows
    assert [(row["query_id"], row["exit_code"]) for row in rows] == [("elastic.query", 0)]
    assert rows[0]["params"] == deep_params(LIMIT)
    assert len(own_raw_lines(r)) == 1


@pytest.mark.parametrize("form", ["dict", "text"])
def test_a_call_at_the_limit_leaves_every_wire_log_line_readable(tmp_path, form):
    """A's margin, on the real wire log (`observe.RequestLogger`, `wire_logs/llm_requests.jsonl`):"""
    shape = Shape(f"{form}-at-limit", form, LIMIT)
    assert_regime(shape)
    r, rec = drive(tmp_path, shape.name, [deep_call(shape), DONE])
    assert [c.verb for c in rec.calls] == ["query"], "the call at the limit did not run"

    path = RunPaths(r.run_dir).wire_log
    lines = ([line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
             if path.is_file() else [])
    assert lines, "the run wrote no wire log, so this arm tests nothing"
    carrying = [line for line in lines if SENTINEL_KEY in line]
    assert carrying, "the call's arguments never reached the wire log, so this arm tests nothing"
    if form == "dict":
        assert max(json_nesting_depth(line) for line in carrying) > LIMIT, \
            "the wire log carried the arguments flattened, so the margin was not exercised"

    skipped = [(json_nesting_depth(line), line[:80]) for line in lines
               if parse_jsonl_row(line) is None]
    assert skipped == [], \
        f"the wire log holds lines its reader skips (reader bound {JSON_NESTING_LIMIT}): {skipped}"
    assert len(read_jsonl_rows(path)) == len(lines)


#: Past the session store's own bound (200 levels of payload): the depth at which a refused
#: call still in the history ended the lead. Past pydantic's own message dump (about 252) the
#: replay harness's model cannot run at all (it serializes every argument to estimate usage);
#: the wire log's side of that depth is pinned on the logger itself (`test_1127_wire_log`).
PAST_THE_STORE = 205


def test_a_refused_dict_call_leaves_nothing_deep_in_the_history_the_lead_goes_on(tmp_path):
    """#1127 second review:"""
    shape = Shape("dict-past-the-store", "dict", PAST_THE_STORE)
    r, rec = drive(tmp_path, shape.name, [deep_call(shape), q("elastic", "query", VALID), DONE])

    assert [c.verb for c in rec.calls] == ["query"], \
        "the call after the refusal did not run: the lead ended on the refused call's history"
    path = RunPaths(r.run_dir).wire_log
    lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    skipped = [(json_nesting_depth(line), line[:80]) for line in lines
               if parse_jsonl_row(line) is None]
    assert skipped == [], f"the wire log holds lines its reader skips: {skipped}"
    records = [json.loads(line) for line in lines]
    responses = [rec for rec in records
                 if rec.get("kind") == "response" and str(rec.get("agent_id")).startswith("gather")
                 and rec.get("agent_id") != "gather:l-00c"]   # the correlation lead's own turns are not the lead under test
    assert len(responses) == 3, \
        f"a response record was dropped: {len(responses)} of the lead's 3 responses logged"


@pytest.mark.parametrize("shape", [DICT_ACCEPTED, TEXT_ACCEPTED], ids=lambda s: s.name)
def test_a_too_deep_call_to_a_withheld_verb_is_a_schema_rejection_not_a_denial(tmp_path, shape):
    """C11 and the design's non-obligation:"""
    assert_regime(shape)
    r, rec = drive(tmp_path, shape.name, [
        q("elastic", "esql", VALID), deep_call(shape, verb="esql"), DONE])

    assert denied_verbs(r).count("esql") == 1, \
        f"expected the shallow call's one denial record, got {denied_verbs(r)}"
    denied_needle = f'"query_id": {json.dumps(_query_rules.DENIED_QUERY_ID)}'
    assert sum(denied_needle in line for line in own_raw_lines(r)) == 1, \
        "the deep call wrote a `∅.denied` row (or the shallow one did not)"
    rejections = _above_guard(r)
    assert [(row["system"], row["verb"], row["params"]) for row in rejections] == [
        ("elastic", "esql", {})], "the deep call was not recorded as a schema rejection"
    assert rec.calls == [], "a withheld verb ran"


# ── O4: the model is told why, and nothing it sent comes back ──────────────────────────────


@pytest.mark.parametrize("system", ["elastic", SENTINEL_SYSTEM], ids=["declared", "undeclared"])
@pytest.mark.parametrize("shape", EVERY_SHAPE, ids=lambda s: s.name)
def test_the_model_is_told_the_limit_and_nothing_it_sent(tmp_path, shape, system):
    """O4:"""
    assert_regime(shape)
    r, _rec = drive(tmp_path, shape.name, [
        q("elastic", "query", {"native_query": SENTINEL_VALUE}),
        deep_call(shape, system=system), DONE])

    answers = retry_texts(r)
    assert len(answers) == 2, "the lead did not make exactly the two scripted calls"
    told = answers[1]
    assert told.strip(), "the model was told nothing about its too-deep call"
    assert model_text_in(told) == [], \
        f"the answer to a too-deep call carries model text or pydantic's rendering: {told[:300]!r}"

    rows = r.own_rows
    assert len(rows) == 2, "the deep call's row was not read back"
    assert rows[0]["params"] == {"native_query": SENTINEL_VALUE}, \
        "the shallow call's params were not stored verbatim, so the negative below is vacuous"
    deep_row = json.dumps(rows[1], ensure_ascii=False)
    assert rows[1]["params"] == {}
    for sentinel in (SENTINEL_KEY, SENTINEL_VALUE, SENTINEL_SYSTEM):
        assert sentinel not in deep_row, \
            f"the deep call's row carries a fragment of its params: {deep_row[:300]}"

    assert names_the_limit(told), f"the answer does not name the limit: {told[:300]!r}"
    assert_speaks_of_the_arguments(told)


# ── O3 / security control: the rejection budget counts them at every depth ───────────────


@pytest.mark.parametrize("shape", [DICT_ACCEPTED, TEXT_REFUSED], ids=lambda s: s.name)
def test_a_budget_of_too_deep_calls_ends_the_lead_exactly_as_shallow_rejections_do(
        tmp_path, shape):
    """THE SECURITY CONTROL (the design's negative universal:"""
    assert_regime(shape)
    deep, deep_rec = drive(tmp_path, "deep", [
        *[deep_call(shape, system=f"ghost{i}") for i in range(B)],
        deep_call(shape, system="ghostafter"), q("elastic", "query", VALID), DONE])
    shallow, shallow_rec = drive(tmp_path, "shallow", [
        *[_bad_args(f"ghost{i}") for i in range(B)],
        q("elastic", "query", VALID), DONE])

    for label, r, rec in (("shallow", shallow, shallow_rec), ("deep", deep, deep_rec)):
        assert len(_above_guard(r)) == B, \
            f"{label}: {len(_above_guard(r))} counted rejections against a budget of {B}"
        _assert_budget_stop(r)
        assert _replay_rejections(r.rows) == [(LEAD, B - 1, "budget")], \
            f"{label}: the replay of the table disagrees"
        assert rec.calls == [], f"{label}: the lead ran on past its dead end"

    assert unreadable(deep) == []
    assert [row["params"] for row in _above_guard(deep)] == [{}] * B
    assert len({row["system_key"] for row in _above_guard(deep)}) == B, \
        "the deep calls did not key distinctly, so the REPEAT guard could have taken this stop"


@pytest.mark.parametrize("shape", [DICT_ACCEPTED, TEXT_UNDECODABLE, None],
                         ids=lambda s: s.name if s else "shallow-control")
def test_repeating_one_too_deep_call_trips_the_repeat_guard(tmp_path, shape):
    """O3's repeat half:"""
    call = _bad_args("ghostone") if shape is None else deep_call(shape)
    if shape is not None:
        assert_regime(shape)
    r, rec = drive(tmp_path, shape.name if shape else "shallow",
                   [call] * rq.REPEAT_THRESHOLD + [q("elastic", "query", VALID), DONE])

    rows = _above_guard(r)
    assert len(rows) == rq.REPEAT_THRESHOLD
    assert _terminator(r) == session_store.TRUNCATED_BY_DEAD_END
    assert "turned back at seq" in rows[-1]["payload_digest"], \
        "the lead was not stopped by the repeat guard"
    assert _replay_rejections(r.rows) == [(LEAD, rq.REPEAT_THRESHOLD - 1, "repeat")]
    assert rec.calls == [], "the lead ran on past its dead end"


# ── C13: a too-deep call never costs another row its seq or its sidecar ────────────────────


@pytest.mark.parametrize("shape", [DICT_ACCEPTED, TEXT_REFUSED], ids=lambda s: s.name)
def test_a_too_deep_call_neither_reuses_a_seq_nor_rewrites_a_sidecar(tmp_path, shape):
    """C13 through the tool:"""
    assert_regime(shape)
    r, rec = drive(tmp_path, shape.name, [
        q("elastic", "query", {"native_query": "FROM a"}), deep_call(shape),
        q("elastic", "query", {"native_query": "FROM b"}), DONE], watch=True)

    assert [(row["seq"], row["query_id"]) for row in r.own_rows] == [
        (0, "elastic.query"), (1, _query_rules.ABOVE_GUARD_QUERY_ID), (2, "elastic.query")]
    assert [c.params["native_query"] for c in rec.calls] == ["FROM a", "FROM b"]

    prefix = f"gather_raw/{LEAD}/"
    states = [*r.snapshots, evidence_snapshot(r.run_dir)]
    for earlier, later in zip(states, states[1:], strict=False):
        for name, content in earlier.items():
            if name.startswith(prefix):
                assert later.get(name) == content, f"payload sidecar {name} was rewritten"
    final = states[-1]
    assert "FROM a" in final[f"{prefix}0.json"].decode("utf-8")
    assert "FROM b" in final[f"{prefix}2.json"].decode("utf-8")
