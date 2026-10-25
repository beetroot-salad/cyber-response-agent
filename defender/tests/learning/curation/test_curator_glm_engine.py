from __future__ import annotations

import logging
import os
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")

from pydantic_ai.models import override_allow_model_requests  # noqa: E402

from defender.run_repository import WIRE_LOG_DIR  # noqa: E402
from defender.tests.support.learning.core._stage_args import as_curator_stage_args  # noqa: E402
from defender.learning.author import shared as _shared  # noqa: E402
from defender.learning.core import config  # noqa: E402
from defender.learning.core.config import (  # noqa: E402
    FatalConfigError,
    RunUnprocessable,
    StageAbort,
    StageContext,
    StageWiring,
)
from defender.learning.author.curator_engine import (  # noqa: E402
    run_curator_stage,
)
from defender.tests.support.runtime.engine._engine_helpers import fake_model as _fake_model  # noqa: E402
from defender.tests.support.runtime.engine._engine_helpers import replay_once as _replay  # noqa: E402

AuthorError = _shared.AuthorError

_AUTHOR_RESULT_OK = (
    'AUTHOR_RESULT: {"committed": [], "consumed_skip": [], "commit_message": "noop"}'
)


def _repo_root(tmp_path: Path) -> Path:
    """The batch worktree root: <root>/defender/<corpus> exists so a real spawn has a tree."""
    return tmp_path / "wt"


def _corpus(tmp_path: Path) -> Path:
    # `lessons` since #922: it is the one shipped corpus, and `bind` refuses any other
    # name — a corpus outside the confine is an unbuildable write scope.
    c = _repo_root(tmp_path) / "defender" / "lessons"
    c.mkdir(parents=True, exist_ok=True)
    return c


def _run_dir(tmp_path: Path) -> Path:
    d = tmp_path / "runs" / "run-A"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _prompt(tmp_path: Path) -> Path:
    p = tmp_path / "curator.md"
    p.write_text("Curate the corpus. Enumerate lessons via bash. Emit AUTHOR_RESULT when done.\n")
    return p


def _stage(tmp_path: Path, *, wiring: StageWiring | None = None, **over):
    """run_curator_stage with hermetic defaults (no-op key + a text-returning fake transport);
    override any kwarg per case."""
    kw = dict(
        system_prompt_file=_prompt(tmp_path),
        batch_id="batch-A",
        user_prompt="u",
        corpus_dir=_corpus(tmp_path),
        repo_root=_repo_root(tmp_path),
        learning_run_dir=_run_dir(tmp_path),
        model="glm-5.3",
        effort="low",
        request_limit=250,
        timeout=180,
        log=logging.getLogger("defender.test"),
        source_key=lambda model, label=None: None,
        run_author=lambda wiring, ctx, **kw: _AUTHOR_RESULT_OK,
    )
    kw.update(over)
    args = as_curator_stage_args(kw)
    if wiring is not None:
        args["wiring"] = wiring
    return run_curator_stage(**args)


def test_return_contract_returns_parsed_dict_not_text(tmp_path):
    text = (
        "the agent authored, then:\n"
        'AUTHOR_RESULT: {"committed": ["obs-1"], '
        '"consumed_skip": [{"observation_id": "obs-2", "reason": "dup"}], '
        '"commit_message": "Fold obs-1"}'
    )
    out = _stage(tmp_path, run_author=lambda *a, **kw: text)
    assert isinstance(out, dict)
    assert out == {
        "committed": ["obs-1"],
        "consumed_skip": [{"observation_id": "obs-2", "reason": "dup"}],
        "commit_message": "Fold obs-1",
    }
    assert out != text


def test_marker_parse_from_last_occurrence_balanced_and_faults(tmp_path):
    text = (
        'AUTHOR_RESULT: {"committed": ["decoy"], "consumed_skip": [], "commit_message": "old"}\n'
        "the agent revised and re-emitted:\n"
        'AUTHOR_RESULT: {"committed": ["real"], "consumed_skip": [], '
        '"commit_message": "note with {braces} inside a string"}'
    )
    out = _stage(tmp_path, run_author=lambda *a, **kw: text)
    assert out["committed"] == ["real"]
    assert out["commit_message"] == "note with {braces} inside a string"
    with pytest.raises(AuthorError):
        _stage(tmp_path, run_author=lambda *a, **kw: "the agent forgot to emit the marker")
    with pytest.raises(AuthorError):
        _stage(tmp_path, run_author=lambda *a, **kw: "AUTHOR_RESULT: {not: valid, json}")


def test_content_less_curator_text_is_no_edits_not_a_missing_marker(tmp_path):
    """A curator turn that produced nothing readable is "made no edits" ({}), not a marker-parse
    failure."""
    for blank in ("", "  ", "\u200b", "\ufeff", "\x00", "\u00a0"):
        assert _stage(tmp_path, run_author=lambda *a, _b=blank, **kw: _b) == {}
    with pytest.raises(AuthorError, match="emitted no AUTHOR_RESULT marker"):
        _stage(tmp_path, run_author=lambda *a, **kw: "I decided not to author anything.")


def test_marker_empty_commit_message_rejected(tmp_path):
    result = _stage(
        tmp_path,
        run_author=lambda *a, **kw: (
            'AUTHOR_RESULT: {"committed": ["obs-1"], "consumed_skip": [], "commit_message": "   "}'
        ),
    )
    with pytest.raises(AuthorError):
        _shared.commit_message(result, "observations")
    ok = _stage(
        tmp_path,
        run_author=lambda *a, **kw: (
            'AUTHOR_RESULT: {"committed": ["obs-1"], "consumed_skip": [], "commit_message": "Fold obs-1"}'
        ),
    )
    assert _shared.commit_message(ok, "observations") == "Fold obs-1"


# #1108 P4 OD12(i): `test_marker_commit_message_with_trailer_rejected` deleted. It pinned only
# `_shared.commit_corpus`'s trailer guard, the legacy checkout commit P4 removes (O7: every
# corpus write goes through P3's commit-maker, which composes no trailers; see the matching
# deletion note in test_author_shared.py). The commit message the drain reads from the result is
# still pinned by `test_marker_empty_commit_message_rejected` above.


def test_marker_malformed_result_types_rejected(tmp_path):
    to_author = [{"observation_id": "obs-1"}]

    def _parsed(body: str) -> dict:
        return _stage(tmp_path, run_author=lambda *a, **kw: "AUTHOR_RESULT: " + body)

    def _validate(result: dict) -> None:
        _shared.validate_agent_result_partition(
            result, to_author, id_key="observation_id",
            buckets=("committed", "consumed_skip"), noun="observations",
        )

    with pytest.raises(AuthorError):
        _validate(_parsed('{"committed": "obs-1", "consumed_skip": [], "commit_message": "m"}'))
    with pytest.raises(AuthorError):
        _validate(_parsed('{"committed": [""], "consumed_skip": [], "commit_message": "m"}'))
    with pytest.raises(AuthorError):
        _validate(_parsed('{"committed": [], "consumed_skip": ["obs-1"], "commit_message": "m"}'))
    _validate(_parsed('{"committed": ["obs-1"], "consumed_skip": [], "commit_message": "m"}'))


def test_inproc_transport_runs_run_stage_and_writes_trace(tmp_path):
    from defender.learning.author.curator_engine import _run_curator_pydantic

    rd = _run_dir(tmp_path)
    fn = _replay(_AUTHOR_RESULT_OK)

    def _inproc(wiring, ctx, **kw):
        return _run_curator_pydantic(wiring, ctx, **kw, make_model=_fake_model(fn))

    with override_allow_model_requests(False):
        out = _stage(tmp_path, run_author=_inproc, learning_run_dir=rd)
    assert out["committed"] == []
    traces = [p for p in rd.rglob("*.jsonl") if p.is_file()]
    assert traces, "the stage wrote no trace at all"
    assert all(WIRE_LOG_DIR in p.parts for p in traces), (
        f"a stage trace landed outside observe/: {[str(p) for p in traces]}"
    )
    assert any(p.read_text().strip() for p in traces)


def test_require_output_true_quarantines_empty_final(tmp_path):
    from defender.learning.author.curator_engine import _run_curator_pydantic

    ctx = StageContext(
        learning_run_dir=_run_dir(tmp_path), user="u",
        request_limit=4, wall_clock_timeout=config.author_timeout(),
        repo_root=_repo_root(tmp_path),
    )
    corpus_dir = _corpus(tmp_path)

    def _wiring(trace_name: str) -> StageWiring:
        return StageWiring(
            prompt_path=_prompt(tmp_path), model="m", effort=None,
            trace_name=trace_name, label="curator",
        )

    with override_allow_model_requests(False), pytest.raises(RunUnprocessable):
        _run_curator_pydantic(
            _wiring("ro-empty.jsonl"), ctx, corpus_dir=corpus_dir,
            make_model=_fake_model(_replay("   ")),
        )
    with override_allow_model_requests(False):
        out = _run_curator_pydantic(
            _wiring("ro-full.jsonl"), ctx, corpus_dir=corpus_dir,
            make_model=_fake_model(_replay("real final text")),
        )
    assert out == "real final text"


def test_perrun_run_unprocessable_wrapped_as_author_error(tmp_path):
    def _boom(*a, **kw):
        raise RunUnprocessable("model timed out")
    with pytest.raises(AuthorError):
        _stage(tmp_path, run_author=_boom)


def test_systemic_faults_propagate_uncaught(tmp_path):
    def _boom_key(model, label=None):
        raise FatalConfigError("needs FIREWORKS_API_KEY")
    with pytest.raises(FatalConfigError):
        _stage(tmp_path, source_key=_boom_key)

    def _boom_build(*a, **kw):
        raise FatalConfigError("unroutable model")
    with pytest.raises(FatalConfigError):
        _stage(tmp_path, run_author=_boom_build)

    def _boom_abort(*a, **kw):
        raise StageAbort("deployment-wide")
    with pytest.raises(StageAbort):
        _stage(tmp_path, run_author=_boom_abort)


def test_key_sourced_before_spawn(tmp_path):
    """run_curator_stage calls source_key(model) BEFORE the in-process spawn (the drain worktree
    carries only the ambient credential) — so a metered-billing spawn never precedes its key."""
    events: list[tuple[str, object]] = []
    _stage(
        tmp_path, model="glm-5.3",
        source_key=lambda model, label=None: events.append(("key", model)),
        run_author=lambda wiring, ctx, **kw: events.append(("run", wiring.model)) or _AUTHOR_RESULT_OK,
    )
    assert [e[0] for e in events] == ["key", "run"]
    assert events[0][1] == "glm-5.3"

    ran: list[int] = []

    def _boom(model, label=None):
        raise FatalConfigError("no key")
    with pytest.raises(FatalConfigError):
        _stage(tmp_path, source_key=_boom, run_author=lambda *a, **kw: ran.append(1) or _AUTHOR_RESULT_OK)
    assert ran == []


def test_trace_anchor_established_before_spawn(tmp_path):
    rd = _run_dir(tmp_path)
    seen: list[str] = []

    def _cap(wiring, ctx, **kw):
        seen.append(wiring.trace_name)
        return _AUTHOR_RESULT_OK

    for bid in ("batch-A", "batch-B"):
        _stage(tmp_path, batch_id=bid, learning_run_dir=rd, run_author=_cap)
    assert all(n for n in seen)
    assert len(set(seen)) == 2
    pid = str(os.getpid())
    assert all(pid in n for n in seen)
    assert any("batch-A" in n for n in seen)
    assert any("batch-B" in n for n in seen)


def test_stage_refuses_a_wiring_that_did_not_come_from_for_batch(tmp_path, caplog):
    """ONE batch identity per spawn."""
    fixed = StageWiring(
        prompt_path=_prompt(tmp_path), model="glm-5.3", effort="low",
        trace_name="curator_trace.jsonl", label="curator",
    )
    assert fixed.batch_id is None
    ran: list[int] = []
    with pytest.raises(ValueError, match="for_batch"):
        _stage(tmp_path, run_author=lambda *a, **kw: ran.append(1) or _AUTHOR_RESULT_OK,
               wiring=fixed)
    assert ran == []

    # Positive control: the same call with the real builder runs, and the batch it reports is
    # the one the trace file is keyed on.
    from_builder = StageWiring.for_batch(
        _prompt(tmp_path), "glm-5.3", "low", batch_id="batch-Z", label="curator",
    )
    assert from_builder.batch_id == "batch-Z"
    assert "batch-Z" in from_builder.trace_name
    caplog.clear()
    _stage(tmp_path, wiring=from_builder, log=logging.getLogger("defender.test"))
    assert any("batch-Z" in line for line in caplog.messages)
