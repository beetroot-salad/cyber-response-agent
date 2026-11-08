from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from defender._io import read_jsonl_rows
from defender.investigation import observe
from defender.investigation.review_roles import REVIEW_AGENT_ID_PREFIX, live_review_stages
from defender.configuration._pricing import usage_cost
from defender.records import SessionPaths
from defender.records import session_store as ss
from defender.tests.support.jobs._jobs1342 import insert_spend
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._locations_1210 import fixture_runs_base

from defender.presentation.visualize_data import (
    deduped_main_records,
    load_messages,
    gather_cost_by_model,
    review_cost_by_model,
    review_cost_by_lens,
)

DEFENDER_DIR = Path(__file__).resolve().parents[3]

_LENSES = ("support", "ablation", "composer")

_USAGE = {"input_tokens": 4000, "output_tokens": 1000, "cache_read_input_tokens": 2000,
          "cache_creation_input_tokens": 500}


# The write side: a live stage on the run's own logger.


def _response(text: str = "reads sound"):
    """A real `ModelResponse` and not a dict: `RequestLogger.log` runs the pydantic-ai type
    adapter over what it is handed, so a dict double would exercise a serialisation path
    production never takes."""
    from pydantic_ai.messages import ModelResponse, TextPart
    from pydantic_ai.usage import RequestUsage

    return ModelResponse(
        parts=[TextPart(content=text)], model_name="kimi-k3",
        usage=RequestUsage(
            input_tokens=_USAGE["input_tokens"], output_tokens=_USAGE["output_tokens"],
            cache_read_tokens=_USAGE["cache_read_input_tokens"],
            cache_write_tokens=_USAGE["cache_creation_input_tokens"],
        ),
    )


class _FakeAgent:
    """An agent that logs one round through whatever logger it was built with, then answers."""

    def __init__(self, logger: Any, agent_id: str) -> None:
        self._logger = logger
        self._agent_id = agent_id

    async def run(self, prompt: str, deps: Any = None) -> Any:
        self._logger.log(
            request_messages=[], response=_response(), agent_id=self._agent_id,
        )
        from types import SimpleNamespace

        return SimpleNamespace(output=f"{self._agent_id} answered")


def _recording_build(seen: dict):
    def build(defn, *, deps_type, instructions, logger, agent_id, **_kw):  # noqa: ARG001
        seen[agent_id] = logger
        return _FakeAgent(logger, agent_id)

    return build


_RUN = fixture_uuid("787-review-cost")


def _ledger(tmp_path: Path, requested: dict[str, str], *, case: str = "r787"):
    """The run's ledger through the one read (#1377 r7 S5): one row per agent, at the model that agent requested.
    The page prices only through this (r7.2 P1)."""
    with ss.open_store(case_id=case, sessions=SessionPaths(fixture_runs_base(tmp_path / "runs"))) as store:
        for agent_id, model in requested.items():
            insert_spend(store.path, _RUN, [(model, _USAGE)], agent_id=agent_id)
        return ss.read_ledger(store, _RUN)


def _stage_request(prompt: str = "the projection"):
    from defender.investigation.challenge_gate import StageRequest

    return StageRequest(prompt=prompt, salt="00", timeout=30.0)


@pytest.fixture
def run_dir(tmp_path: Path) -> Path:
    run = tmp_path / "run"
    run.mkdir()
    return run


def _drive_every_lens(run: Path, logger: Any, seen: dict) -> None:
    stages = live_review_stages(
        run, DEFENDER_DIR, logger=logger, build=_recording_build(seen),
    )
    for lens in _LENSES:
        asyncio.run(stages.stage(lens)(_stage_request()))


def test_every_live_stage_is_built_on_the_run_s_own_logger(run_dir):
    """Not one of them mints its own. A private logger is a file no cost reader opens."""
    logger = observe.RequestLogger(observe.wire_log_path(run_dir))
    seen: dict = {}
    try:
        _drive_every_lens(run_dir, logger, seen)
    finally:
        logger.close()

    assert set(seen) == {f"{REVIEW_AGENT_ID_PREFIX}{lens}" for lens in _LENSES}
    assert all(bound is logger for bound in seen.values()), (
        "a stage was built on a logger that is not the run's — its calls land outside every "
        "accounted total"
    )


def test_a_stage_does_not_close_the_logger_it_shares(run_dir):
    """The run is still going when a review stage returns."""
    logger = observe.RequestLogger(observe.wire_log_path(run_dir))
    try:
        _drive_every_lens(run_dir, logger, {})
        logger.log(request_messages=[], response=_response("main turn"), agent_id="main")
    finally:
        logger.close()

    rows = read_jsonl_rows(observe.wire_log_path(run_dir))
    assert [r.get("agent_id") for r in rows if r.get("kind") == "response"] == [
        *(f"{REVIEW_AGENT_ID_PREFIX}{lens}" for lens in _LENSES), "main",
    ], "the main agent's turn did not reach the log after a review stage ran"


def test_the_two_support_calls_stay_apart_in_the_log(run_dir):
    """SUPPORT is dispatched twice — as itself and as the ablation — and `observe` keys its
    sequence and record ids on `agent_id`."""
    logger = observe.RequestLogger(observe.wire_log_path(run_dir))
    try:
        _drive_every_lens(run_dir, logger, {})
    finally:
        logger.close()

    rows = read_jsonl_rows(observe.wire_log_path(run_dir))
    assert [r["agent_id"] for r in rows] == [
        f"{REVIEW_AGENT_ID_PREFIX}{lens}" for lens in _LENSES
    ], "two review calls share an agent id — their readings collapse into one"
    ids = [r["id"] for r in rows]
    assert len(set(ids)) == len(ids), f"two review calls share a record id: {ids}"
    ledger = _ledger(run_dir, {f"{REVIEW_AGENT_ID_PREFIX}{lens}": "kimi-k3" for lens in _LENSES})
    assert set(review_cost_by_lens(run_dir, load_messages(run_dir), ledger)) == set(_LENSES)


# The read side: the review is priced, and it is disjoint from main's and gather's.


def _wire(agent_id: str, model: str, usage: dict | None = None, kind: str = "response") -> dict:
    return {
        "agent_id": agent_id, "seq": 0, "id": f"{agent_id}#0", "kind": kind,
        "model": model, "usage": usage if usage is not None else _USAGE,
        "message": {"kind": kind, "parts": [{"part_kind": "text", "content": "x"}]},
    }


#: One run's wire log with all three namespaces present, which is the only fixture that can
#: discriminate a reader keyed on the wrong prefix from one keyed on the right one.
_MIXED = [
    _wire("main", "claude-sonnet-4-6"),
    _wire("gather:l-001", "claude-haiku-4-5"),
    _wire(f"{REVIEW_AGENT_ID_PREFIX}support", "kimi-k3"),
    _wire(f"{REVIEW_AGENT_ID_PREFIX}ablation", "kimi-k3"),
    _wire(f"{REVIEW_AGENT_ID_PREFIX}composer", "kimi-k3"),
]

_ONE_CALL = usage_cost("kimi-k3", _USAGE)


#: The ledger for `_MIXED`: each agent requested the model its wire records say (so the reported name is not what decides).
_MIXED_REQUESTED = {
    "main": "claude-sonnet-4-6", "gather:l-001": "claude-haiku-4-5",
    **{f"{REVIEW_AGENT_ID_PREFIX}{lens}": "kimi-k3" for lens in _LENSES},
}


def test_the_review_s_spend_is_priced_per_lens(tmp_path):
    """Lens attribution survives; the dollars come from the ledger's requested model (r7 S5, r7.1 C)."""
    by_lens = review_cost_by_lens(tmp_path, _MIXED, _ledger(tmp_path, _MIXED_REQUESTED))

    assert set(by_lens) == {"support", "ablation", "composer"}, (
        "the lens is read off the agent id, so a key carrying the prefix means the reader "
        "and the writer disagree about where the namespace ends"
    )
    assert all(cost == pytest.approx(_ONE_CALL) for cost in by_lens.values())
    assert sum(by_lens.values()) == pytest.approx(3 * _ONE_CALL)


def test_the_review_s_spend_is_priced_per_model(tmp_path):
    """The review runs on its own pinned default, apart from the investigator's, so it is
    normally a row of its own in the by-model breakdown, priced at the model it requested (r7.1 C)."""
    same_usage_as_main = usage_cost("claude-sonnet-4-6", _USAGE)
    assert pytest.approx(same_usage_as_main) != _ONE_CALL, (
        "fixture no longer discriminates — pick a review model whose price row differs"
    )
    ledger = _ledger(tmp_path, _MIXED_REQUESTED)
    assert review_cost_by_model(tmp_path, _MIXED, ledger) == {"kimi-k3": pytest.approx(3 * _ONE_CALL)}


def test_the_review_is_priced_at_the_requested_model_not_the_reported_one(tmp_path):
    """Retires the old reported-name pricing (r7.2 P1, r7.1 C "never the reported name"): the wire records here
    report the investigator's model for every review call, the ledger says kimi-k3 was requested."""
    reported_as_main = [{**r, "model": "claude-sonnet-4-6"} if str(r["agent_id"]).startswith(REVIEW_AGENT_ID_PREFIX) else r
                        for r in _MIXED]
    ledger = _ledger(tmp_path, _MIXED_REQUESTED)

    assert review_cost_by_model(tmp_path, reported_as_main, ledger) == {"kimi-k3": pytest.approx(3 * _ONE_CALL)}
    assert all(c == pytest.approx(_ONE_CALL) for c in review_cost_by_lens(tmp_path, reported_as_main, ledger).values())


def test_without_a_readable_ledger_no_reader_prices_the_wire_log(tmp_path):
    """r7.2 P1: with no ledger there are no dollars, and no fallback to the name the log reports (an empty name once
    priced as Sonnet). Lens attribution of the review's rows needs the ledger too."""
    assert review_cost_by_lens(tmp_path, _MIXED, None) == {}
    assert review_cost_by_model(tmp_path, _MIXED, None) == {}
    assert gather_cost_by_model(tmp_path, _MIXED, None) == {}


def test_the_three_namespaces_do_not_read_each_other(tmp_path):
    """Disjointness in both directions. The review rows must not move gather's figure or the
    main transcript, and the review reader must not pick up either of theirs."""
    ledger = _ledger(tmp_path, _MIXED_REQUESTED)
    assert gather_cost_by_model(tmp_path, _MIXED, ledger) == {
        "haiku-4-5": pytest.approx(usage_cost("claude-haiku-4-5", _USAGE))
    }
    assert [r["agent_id"] for r in deduped_main_records(_MIXED)] == ["main"]

    without_review = [r for r in _MIXED if not str(r["agent_id"]).startswith(REVIEW_AGENT_ID_PREFIX)]
    assert gather_cost_by_model(tmp_path, without_review, ledger) == gather_cost_by_model(tmp_path, _MIXED, ledger)
    assert deduped_main_records(without_review) == deduped_main_records(_MIXED)
    assert review_cost_by_lens(tmp_path, without_review, ledger) == {}


def test_a_request_record_is_not_priced(tmp_path):
    """Only responses carry usage. A reader that counted requests would multiply the review's
    cost by however many turns of history the wire log restates."""
    ledger = _ledger(tmp_path, _MIXED_REQUESTED)
    with_request = [*_MIXED, _wire(f"{REVIEW_AGENT_ID_PREFIX}support", "kimi-k3", kind="request")]
    assert review_cost_by_lens(tmp_path, with_request, ledger) == review_cost_by_lens(tmp_path, _MIXED, ledger)
