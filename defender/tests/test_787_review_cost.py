"""#787 — the review gate's model calls land in the run's accounted cost.

The gate makes up to three model calls per close attempt and a run that forces turns pays
for up to three attempts. Every operator-facing cost figure is derived from the run's one
`RequestLogger` (`llm_requests.jsonl`) or from the session store, and until now a review
stage minted a PRIVATE logger and wrote to `review_{lens}_live_trace.jsonl` — a file whose
only reader anywhere in the tree was a test asserting it did not exist. The calls charged a
real provider and appeared in no accounted total.

The fix is the shape gather already had: one shared logger, one `agent_id` namespace, and a
reader that filters on the prefix. What is pinned here is that shape's two halves —

  - the WRITE: a live stage logs through the run's own logger, under `review:{lens}`, and
    does not close it on the way out (the private logger's `finally: logger.close()` on a
    SHARED one takes `llm_requests.jsonl` down mid-investigation, and no live run is a
    reasonable place to discover that);
  - the READ: the review's spend is priced, split by lens, and disjoint from main's and
    gather's — a prefix that drifted on either side silently reopens the whole defect.

What is deliberately NOT pinned: the review charging the investigation's request ceiling. It
must not, it structurally cannot (a review role is a separate `Agent` with its own history,
so `_main_extra_capabilities`' limit can never see it), and this issue is only ever about
where those calls land INSTEAD.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest

from defender._io import read_jsonl_rows
from defender.runtime import observe
from defender.runtime.review_roles import REVIEW_AGENT_ID_PREFIX, live_review_stages
from defender.scripts.pricing import usage_cost

# Through `visualize_data`, which is how every other visualizer test reaches these: the two
# modules are mutually importing (`visualize_data` re-exports from `visualize_messages` at its
# foot, `visualize_messages` takes `phase_verb` from its head), so naming the messages module
# first is an ImportError on a partially-initialised module.
from defender.scripts.visualize.visualize_data import (
    deduped_main_records,
    gather_cost_by_model,
    review_cost_by_model,
    review_cost_by_role,
)

DEFENDER_DIR = Path(__file__).resolve().parents[1]

_LENSES = ("support", "ablation", "composer")

#: One priced round. Chosen so `usage_cost` returns a number no other row in a fixture can
#: coincidentally equal, and so input/output/cache are all non-zero — a reader that dropped
#: a term would still return something plausible against a usage dict of one field.
_USAGE = {"input_tokens": 4000, "output_tokens": 1000, "cache_read_input_tokens": 2000,
          "cache_creation_input_tokens": 500}


# --------------------------------------------------------------------------------------
# The write side: a live stage on the run's own logger.
# --------------------------------------------------------------------------------------


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
    """An agent that logs one round through whatever logger it was built with, then answers.

    It stands in for the provider-backed one at the `build` seam, which is the whole reason
    that seam exists: `_make_live_stage` is otherwise reachable only by calling a real model,
    so the wiring it performs — which logger, which agent id — had no hermetic witness."""

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


def _stage_request(prompt: str = "the projection"):
    from defender.runtime.challenge_gate import StageRequest

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
    logger = observe.RequestLogger(run_dir / "llm_requests.jsonl")
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
    """The run is still going when a review stage returns.

    The private-logger shape closed its own in a `finally`, which was correct while the
    logger was its own. Carried onto the shared one it closes `llm_requests.jsonl` out from
    under the main agent mid-investigation — so the write below must land, and it is the
    whole point of this test that it is made AFTER a stage has run."""
    logger = observe.RequestLogger(run_dir / "llm_requests.jsonl")
    try:
        _drive_every_lens(run_dir, logger, {})
        logger.log(request_messages=[], response=_response("main turn"), agent_id="main")
    finally:
        logger.close()

    rows = read_jsonl_rows(run_dir / "llm_requests.jsonl")
    assert [r.get("agent_id") for r in rows if r.get("kind") == "response"] == [
        *(f"{REVIEW_AGENT_ID_PREFIX}{lens}" for lens in _LENSES), "main",
    ], "the main agent's turn did not reach the log after a review stage ran"


def test_a_live_stage_leaves_no_private_trace_file(run_dir):
    """The per-lens `review_*_live_trace.jsonl` files are gone, not merely unread. Two homes
    for one record is how the second one stops being maintained."""
    logger = observe.RequestLogger(run_dir / "llm_requests.jsonl")
    try:
        _drive_every_lens(run_dir, logger, {})
    finally:
        logger.close()

    assert not list(run_dir.glob("*_live_trace.jsonl"))
    assert [p.name for p in run_dir.iterdir()] == ["llm_requests.jsonl"]


def test_the_two_support_calls_stay_apart_in_the_log(run_dir):
    """SUPPORT is dispatched twice — as itself and as the ablation — and `observe` keys its
    sequence and record ids on `agent_id`. One id for both would collapse two readings into
    one, silently, which is the failure the per-lens split has always existed to prevent; it
    used to be carried by the filename and is now carried by the id."""
    logger = observe.RequestLogger(run_dir / "llm_requests.jsonl")
    try:
        _drive_every_lens(run_dir, logger, {})
    finally:
        logger.close()

    ids = [r["id"] for r in read_jsonl_rows(run_dir / "llm_requests.jsonl")]
    assert len(set(ids)) == len(ids), f"two review calls share a record id: {ids}"


# --------------------------------------------------------------------------------------
# The read side: the review is priced, and it is disjoint from main's and gather's.
# --------------------------------------------------------------------------------------


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


def test_the_review_s_spend_is_priced_per_lens(tmp_path):
    by_role = review_cost_by_role(tmp_path, _MIXED)

    assert set(by_role) == {"support", "ablation", "composer"}, (
        "the lens is read off the agent id, so a key carrying the prefix means the reader "
        "and the writer disagree about where the namespace ends"
    )
    assert all(cost == pytest.approx(_ONE_CALL) for cost in by_role.values())
    assert sum(by_role.values()) == pytest.approx(3 * _ONE_CALL)


def test_the_review_s_spend_is_priced_per_model(tmp_path):
    """The review runs on its own pinned default, apart from the investigator's, so it is
    normally a row of its own in the by-model breakdown."""
    assert review_cost_by_model(tmp_path, _MIXED) == {"kimi-k3": pytest.approx(3 * _ONE_CALL)}


def test_the_review_is_priced_at_its_own_model_s_rate(tmp_path):
    """Not at the investigator's. `usage_cost` keys on the record's OWN model, and a review
    priced at the main model's rate would be wrong by the ratio between two price rows while
    still looking like a number."""
    same_usage_as_main = usage_cost("claude-sonnet-4-6", _USAGE)
    assert pytest.approx(same_usage_as_main) != _ONE_CALL, (
        "fixture no longer discriminates — pick a review model whose price row differs"
    )
    assert sum(review_cost_by_role(tmp_path, _MIXED).values()) == pytest.approx(3 * _ONE_CALL)


def test_the_three_namespaces_do_not_read_each_other(tmp_path):
    """Disjointness in both directions. The review rows must not move gather's figure or the
    main transcript, and the review reader must not pick up either of theirs."""
    assert gather_cost_by_model(tmp_path, _MIXED) == {
        "haiku-4-5": pytest.approx(usage_cost("claude-haiku-4-5", _USAGE))
    }
    assert [r["agent_id"] for r in deduped_main_records(_MIXED)] == ["main"]

    without_review = [r for r in _MIXED if not str(r["agent_id"]).startswith(REVIEW_AGENT_ID_PREFIX)]
    assert gather_cost_by_model(tmp_path, without_review) == gather_cost_by_model(tmp_path, _MIXED)
    assert deduped_main_records(without_review) == deduped_main_records(_MIXED)
    assert review_cost_by_role(tmp_path, without_review) == {}


def test_a_request_record_is_not_priced(tmp_path):
    """Only responses carry usage. A reader that counted requests would multiply the review's
    cost by however many turns of history the wire log restates."""
    with_request = [*_MIXED, _wire(f"{REVIEW_AGENT_ID_PREFIX}support", "kimi-k3", kind="request")]
    assert review_cost_by_role(tmp_path, with_request) == review_cost_by_role(tmp_path, _MIXED)


def test_a_run_with_no_review_prices_nothing(tmp_path):
    """An `inconclusive` close bypasses the gate entirely, and a replay's injected stages
    call no provider. Both must read as zero rows rather than as a zero-dollar review."""
    (tmp_path / "llm_requests.jsonl").write_text(
        json.dumps(_wire("main", "claude-sonnet-4-6")) + "\n", encoding="utf-8",
    )
    assert review_cost_by_role(tmp_path) == {}
    assert review_cost_by_model(tmp_path) == {}
