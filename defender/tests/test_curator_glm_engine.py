"""Hermetic spec for the in-process PydanticAI curator engine (no API key, no network).

The four lesson curators (A findings/lessons, B actor-tradecraft, C env-benign,
D env-adversarial) are ported off ``claude -p`` onto the shared ``_pydantic_stage``
transport, mirroring the lead-author port (#543). Their two invoke seams
(``lessons.run.invoke_agent`` for A, ``curator.invoke_curator_agent`` for B/C/D) are
rewritten to call a new ``curator_engine.run_curator_stage`` wrapper. These tests drive
the REAL wrapper (key-sourcing order + fault mapping + the relocated ``AUTHOR_RESULT``
parse), with a ``FunctionModel`` injected through the transport's ``make_model`` DI seam
under ``override_allow_model_requests(False)`` so any real provider call raises, and with
the ``source_key`` / ``run_author`` DI seams injected as kwargs (never ``monkeypatch``).

Pins the port's load-bearing decisions:

- ``run_curator_stage`` returns the PARSED ``AUTHOR_RESULT`` dict (not run_stage's text) —
  the marker parse relocated out of the retired ``claude -p`` transport into the wrapper,
  balanced-brace walk from the LAST marker; missing marker / bad JSON → ``AuthorError``.
- The KEPT transaction-envelope guards (empty commit message, the ``commit_corpus`` trailer
  refusal, the result-partition type validation) still reject the dict the new in-process
  parse produces.
- ``require_output=True`` (the OPPOSITE of the lead author's ``False``): an empty final —
  GLM burned its budget in the thinking channel — becomes ``RunUnprocessable`` BEFORE any
  parse, never a silent empty commit, because the curator's final text carries the
  load-bearing marker.
- Fault split: a per-run ``RunUnprocessable`` maps to ``AuthorError`` (→ rc 2, retry); a
  systemic ``FatalConfigError`` / ``StageAbort`` PROPAGATES (exit 2, never wrapped).
- The metered key is sourced BEFORE the spawn (the drain strips provider keys); the trace
  anchor (batch_id + pid) is established before the spawn too — both hold.
- The model/effort defaults flip to glm-5.2 @ low, the documented claude-* @ low A/B still
  builds, and a NEW generous per-curator request cap (default 250) is threaded.

NOTE (seams assumed beyond the tight contract): ``_run_curator_pydantic`` — the module
default of ``run_author``, the mirror of ``lead_author_engine._run_author_pydantic`` — is
imported LOCALLY inside only the two tests that need the genuine in-process transport, so a
naming divergence in the impl fails only those two rather than the whole binding suite.
"""
from __future__ import annotations

import os
from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

from pydantic_ai.messages import ModelResponse, TextPart  # noqa: E402
from pydantic_ai.models import override_allow_model_requests  # noqa: E402
from pydantic_ai.models.function import FunctionModel  # noqa: E402

from defender.learning.author import shared as _shared  # noqa: E402
from defender.learning.core import config  # noqa: E402
from defender.learning.core.config import (  # noqa: E402
    FatalConfigError,
    RunUnprocessable,
    StageAbort,
)
# The port target — missing until implemented, so this import is the EXPECTED red.
from defender.learning.author.curator_engine import run_curator_stage  # noqa: E402
from defender.runtime import providers  # noqa: E402
from defender.runtime.providers import BuiltModel  # noqa: E402

AuthorError = _shared.AuthorError

# A well-formed AUTHOR_RESULT the fake transport returns as its final TEXT; run_curator_stage
# relocates the marker parse and returns the dict.
_AUTHOR_RESULT_OK = (
    'AUTHOR_RESULT: {"committed": [], "consumed_skip": [], "commit_message": "noop"}'
)


# ---------------------------------------------------------------------------
# Hermetic fixtures + DI-seam helpers (mirror test_lead_author_engine.py)
# ---------------------------------------------------------------------------


def _replay(text: str):
    """A FunctionModel fn returning one scripted turn: a single text part (no tool calls)."""
    def fn(messages, info):
        return ModelResponse(parts=[TextPart(content=text)])
    return fn


def _fake_model(fn):
    # settings=None — a FunctionModel needs no provider settings (mirrors the lead-author test).
    return lambda model, effort: BuiltModel(FunctionModel(fn), None)


def _repo_root(tmp_path: Path) -> Path:
    """The batch worktree root: <root>/defender/<corpus> exists so a real spawn has a tree."""
    return tmp_path / "wt"


def _corpus(tmp_path: Path) -> Path:
    c = _repo_root(tmp_path) / "defender" / "lessons-actor"
    c.mkdir(parents=True, exist_ok=True)
    return c


def _run_dir(tmp_path: Path) -> Path:
    d = tmp_path / "runs" / "run-A"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _verifiers(tmp_path: Path) -> tuple[Path, ...]:
    base = _repo_root(tmp_path) / "defender" / "learning" / "author" / "verify_forward"
    return (base / "batch.py", base / "actor.py")


def _prompt(tmp_path: Path) -> Path:
    p = tmp_path / "curator.md"
    p.write_text("Curate the corpus. Enumerate lessons via bash. Emit AUTHOR_RESULT when done.\n")
    return p


def _stage(tmp_path: Path, **over):
    """run_curator_stage with hermetic defaults (no-op key + a text-returning fake transport);
    override any kwarg per case. The two DI seams (``source_key`` / ``run_author``) OWN their
    production defaults; tests inject fakes to exercise the orchestration without a metered key
    or the pydantic-ai graph — no ``monkeypatch`` of module globals."""
    kw = dict(
        system_prompt_file=_prompt(tmp_path),
        batch_id="batch-A",
        user_prompt="u",
        corpus_dir=_corpus(tmp_path),
        verifier_scripts=_verifiers(tmp_path),
        repo_root=_repo_root(tmp_path),
        learning_run_dir=_run_dir(tmp_path),
        model="glm-5.2",
        effort="low",
        request_limit=250,
        timeout=180,
        log=lambda *a, **k: None,
        source_key=lambda model, label=None: None,
        run_author=lambda **kw: _AUTHOR_RESULT_OK,
    )
    kw.update(over)
    return run_curator_stage(**kw)


# ===========================================================================
# state-root — carried on the deps into the bash-tool env, NOT a process global
# ===========================================================================

def test_state_root_threads_through_deps_not_os_environ(tmp_path, monkeypatch):
    """The shared state root reaches the forward-check subprocess via the curator deps →
    ``run_common.run_env`` (DEFENDER_LEARNING_STATE_DIR), the in-process twin of the retired
    ``curator_agent_env`` ``env=``. The transport must NOT mutate the process-global
    ``os.environ`` (a leak that contaminated sibling in-process runs/tests)."""
    from defender.learning.author.curator_engine import CuratorDeps
    from defender.runtime import tools

    monkeypatch.delenv("DEFENDER_LEARNING_STATE_DIR", raising=False)
    state = tmp_path / "state"
    seen = {}
    _stage(tmp_path, state_root=state, run_author=lambda **kw: seen.update(kw) or _AUTHOR_RESULT_OK)

    # 1) the transport threads state_root down the seam (→ CuratorDeps.for_run), not the global
    assert seen["state_root"] == state
    assert "DEFENDER_LEARNING_STATE_DIR" not in os.environ

    # 2) the deps carry it, and run_env projects it into the bash-tool subprocess env
    deps = CuratorDeps.for_run(
        _run_dir(tmp_path), _repo_root(tmp_path), _corpus(tmp_path), _verifiers(tmp_path),
        state_root=state,
    )
    assert deps.state_root == state
    assert tools._bash_env(deps)["DEFENDER_LEARNING_STATE_DIR"] == str(state)

    # 3) a deps without a state root leaves the var unset (the runtime agents' behavior)
    bare = CuratorDeps.for_run(
        _run_dir(tmp_path), _repo_root(tmp_path), _corpus(tmp_path), _verifiers(tmp_path),
    )
    assert "DEFENDER_LEARNING_STATE_DIR" not in tools._bash_env(bare)


# ===========================================================================
# return-contract — the invoke seam's whole output is the PARSED dict, not text
# ===========================================================================

def test_return_contract_returns_parsed_dict_not_text(tmp_path):
    """The ported invoke seam returns the ``AUTHOR_RESULT`` dict — committed:[bare-id-strings],
    consumed_skip:[{id,reason}], commit_message:str — parsed out of run_stage's returned TEXT.
    The DICT (not run_stage's text) is the whole output the envelope consumes."""
    text = (
        "the agent authored, then:\n"
        'AUTHOR_RESULT: {"committed": ["obs-1"], '
        '"consumed_skip": [{"observation_id": "obs-2", "reason": "dup"}], '
        '"commit_message": "Fold obs-1"}'
    )
    out = _stage(tmp_path, run_author=lambda **kw: text)
    assert isinstance(out, dict)                       # a dict, never the raw transport text
    assert out == {
        "committed": ["obs-1"],
        "consumed_skip": [{"observation_id": "obs-2", "reason": "dup"}],
        "commit_message": "Fold obs-1",
    }
    assert out != text


# ===========================================================================
# marker-parse-relocated — extract_marked_result (LAST marker, balanced walk) + json.loads
# ===========================================================================

def test_marker_parse_from_last_occurrence_balanced_and_faults(tmp_path):
    """run_curator_stage parses AUTHOR_RESULT out of the returned text via the balanced-brace
    walk from the LAST marker occurrence (an earlier decoy marker is ignored; braces inside a
    JSON string are not miscounted). A missing marker or invalid JSON raises AuthorError — the
    wrapper never returns text where the envelope expects a dict."""
    text = (
        'AUTHOR_RESULT: {"committed": ["decoy"], "consumed_skip": [], "commit_message": "old"}\n'
        "the agent revised and re-emitted:\n"
        'AUTHOR_RESULT: {"committed": ["real"], "consumed_skip": [], '
        '"commit_message": "note with {braces} inside a string"}'
    )
    out = _stage(tmp_path, run_author=lambda **kw: text)
    assert out["committed"] == ["real"]                             # LAST marker, not the decoy
    assert out["commit_message"] == "note with {braces} inside a string"
    # missing marker → AuthorError (never text-where-a-dict-is-expected)
    with pytest.raises(AuthorError):
        _stage(tmp_path, run_author=lambda **kw: "the agent forgot to emit the marker")
    # marker present but the JSON body is invalid → AuthorError
    with pytest.raises(AuthorError):
        _stage(tmp_path, run_author=lambda **kw: "AUTHOR_RESULT: {not: valid, json}")


# ===========================================================================
# marker-empty-commit-msg — non-empty committed + blank commit_message → AuthorError
# ===========================================================================

def test_marker_empty_commit_message_rejected(tmp_path):
    """A parsed result with non-empty committed but a whitespace-only commit_message trips the
    KEPT envelope guard (_commit_message) → AuthorError; never a silent empty-message commit.
    Positive control: a real message is accepted."""
    result = _stage(
        tmp_path,
        run_author=lambda **kw: (
            'AUTHOR_RESULT: {"committed": ["obs-1"], "consumed_skip": [], "commit_message": "   "}'
        ),
    )
    with pytest.raises(AuthorError):
        _shared._commit_message(result, "observations")
    ok = _stage(
        tmp_path,
        run_author=lambda **kw: (
            'AUTHOR_RESULT: {"committed": ["obs-1"], "consumed_skip": [], "commit_message": "Fold obs-1"}'
        ),
    )
    assert _shared._commit_message(ok, "observations") == "Fold obs-1"


# ===========================================================================
# marker-trailer-guarded — a smuggled provenance trailer → commit_corpus AuthorError
# ===========================================================================

def test_marker_commit_message_with_trailer_rejected(tmp_path):
    """A commit_message that already carries a ``Generation:``/trailer key is rejected by
    commit_corpus's trailer guard as AuthorError — model-authored text cannot smuggle a
    provenance trailer the loop owns. Positive control: a clean message passes the guard (any
    failure past it is a git error, not the AuthorError refusal)."""
    result = _stage(
        tmp_path,
        run_author=lambda **kw: (
            'AUTHOR_RESULT: {"committed": ["obs-1"], "consumed_skip": [], '
            '"commit_message": "Fold obs-1\\n\\nGeneration: 5"}'
        ),
    )
    trailers = [("Generation", "5"), ("Actor-Model", "glm-5.2")]
    with pytest.raises(AuthorError):
        _shared.commit_corpus(
            _repo_root(tmp_path), _corpus(tmp_path), result["commit_message"], trailers=trailers
        )
    # positive control: a clean message passes the trailer guard (a git failure past it, in a
    # tmp dir that is no repo, is a DIFFERENT lane — the guard is specific to the trailer).
    try:
        _shared.commit_corpus(
            _repo_root(tmp_path), _corpus(tmp_path), "Fold obs-1", trailers=trailers
        )
    except AuthorError:
        pytest.fail("a clean commit_message must pass the trailer guard")
    except Exception:
        pass


# ===========================================================================
# marker-malformed-types — structurally-wrong result → AuthorError, not a partial commit
# ===========================================================================

def test_marker_malformed_result_types_rejected(tmp_path):
    """A structurally-wrong AUTHOR_RESULT — committed not a list, an empty-string committed id,
    a consumed_skip entry that is a bare string rather than an {id, reason} object — is rejected
    by the KEPT partition validator → AuthorError (never a silent bad/partial commit). Positive
    control: a well-formed result validates cleanly."""
    to_author = [{"observation_id": "obs-1"}]

    def _parsed(body: str) -> dict:
        return _stage(tmp_path, run_author=lambda **kw: "AUTHOR_RESULT: " + body)

    def _validate(result: dict) -> None:
        _shared.validate_agent_result_partition(
            result, to_author, id_key="observation_id",
            buckets=("committed", "consumed_skip"), noun="observations",
        )

    with pytest.raises(AuthorError):  # committed is not a list
        _validate(_parsed('{"committed": "obs-1", "consumed_skip": [], "commit_message": "m"}'))
    with pytest.raises(AuthorError):  # committed carries an empty-string id
        _validate(_parsed('{"committed": [""], "consumed_skip": [], "commit_message": "m"}'))
    with pytest.raises(AuthorError):  # a consumed_skip entry is a bare string, missing its object
        _validate(_parsed('{"committed": [], "consumed_skip": ["obs-1"], "commit_message": "m"}'))
    # positive control: a well-formed result partitions cleanly (no raise)
    _validate(_parsed('{"committed": ["obs-1"], "consumed_skip": [], "commit_message": "m"}'))


# ===========================================================================
# inproc-transport — the LLM is driven through the in-process run_stage (RequestLogger trace),
# NOT runner.invoke_claude_print
# ===========================================================================

def test_inproc_transport_runs_run_stage_and_writes_trace(tmp_path):
    """Each curator drives the LLM through run_curator_stage → the in-process run_stage
    (PydanticAI), not a ``claude -p`` subprocess: a RequestLogger trace lands in the run dir and
    the wrapper returns the dict parsed from that in-process run's final text. Driven end-to-end
    through run_curator_stage with the GENUINE transport (its make_model DI seam feeds a
    FunctionModel), so no real provider request is made."""
    from defender.learning.author.curator_engine import _run_curator_pydantic

    rd = _run_dir(tmp_path)
    fn = _replay(_AUTHOR_RESULT_OK)

    def _inproc(**kw):
        return _run_curator_pydantic(**kw, make_model=_fake_model(fn))

    with override_allow_model_requests(False):
        out = _stage(tmp_path, run_author=_inproc, learning_run_dir=rd)
    assert out["committed"] == []                       # parsed from the in-process run_stage text
    traces = [p for p in rd.iterdir() if p.is_file()]
    assert traces                                        # a RequestLogger trace landed (in-process)
    assert any(p.read_text().strip() for p in traces)


# ===========================================================================
# require-output-true — an empty final → RunUnprocessable BEFORE any parse (opposite of the
# lead author's require_output=False)
# ===========================================================================

def test_require_output_true_quarantines_empty_final(tmp_path):
    """The curator transport runs run_stage with require_output=True, so a CONTENT-LESS final
    (whitespace — the observable content-less case; a truly-empty '' is rejected by pydantic-ai
    before the guard) raises RunUnprocessable BEFORE any AUTHOR_RESULT parse — never a silent
    empty commit. Diverges deliberately from the lead author's require_output=False, which would
    RETURN the content-less text. Positive control: a non-empty final is returned VERBATIM (the
    transport returns text; run_curator_stage — not the transport — parses the marker)."""
    from defender.learning.author.curator_engine import _run_curator_pydantic

    common = dict(
        model="m", effort=None, label="curator", user="u",
        learning_run_dir=_run_dir(tmp_path), repo_root=_repo_root(tmp_path),
        corpus_dir=_corpus(tmp_path), verifier_scripts=_verifiers(tmp_path),
        request_limit=4,
    )
    with override_allow_model_requests(False), pytest.raises(RunUnprocessable):
        _run_curator_pydantic(
            prompt_path=_prompt(tmp_path), trace_name="ro-empty.jsonl",
            make_model=_fake_model(_replay("   ")), **common,
        )
    with override_allow_model_requests(False):
        out = _run_curator_pydantic(
            prompt_path=_prompt(tmp_path), trace_name="ro-full.jsonl",
            make_model=_fake_model(_replay("real final text")), **common,
        )
    assert out == "real final text"


# ===========================================================================
# fault-perrun-authorerror — RunUnprocessable → AuthorError (per-run, → rc 2 / retry)
# ===========================================================================

def test_perrun_run_unprocessable_wrapped_as_author_error(tmp_path):
    """A per-run authoring fault surfaced by the transport as RunUnprocessable (timeout /
    usage-limit / model error / empty final) is wrapped as AuthorError so run_batch returns rc 2
    and the drain keeps the queue intact for retry. The wrap is RunUnprocessable-ONLY."""
    def _boom(**kw):
        raise RunUnprocessable("model timed out")
    with pytest.raises(AuthorError):
        _stage(tmp_path, run_author=_boom)


# ===========================================================================
# fault-systemic-propagates — FatalConfigError / StageAbort ESCAPE uncaught (exit 2)
# ===========================================================================

def test_systemic_faults_propagate_uncaught(tmp_path):
    """A systemic FatalConfigError (unroutable model / missing key from source_key, or a build
    ValueError surfaced by run_stage as FatalConfigError) or a StageAbort ESCAPES
    run_curator_stage uncaught — a deployment-wide misconfig fails once, loudly, and is never
    wrapped into an rc-2 retry loop (the wrap is RunUnprocessable/parse-error only)."""
    def _boom_key(model, label=None):
        raise FatalConfigError("needs FIREWORKS_API_KEY")
    with pytest.raises(FatalConfigError):
        _stage(tmp_path, source_key=_boom_key)

    def _boom_build(**kw):
        raise FatalConfigError("unroutable model")
    with pytest.raises(FatalConfigError):
        _stage(tmp_path, run_author=_boom_build)

    def _boom_abort(**kw):
        raise StageAbort("deployment-wide")
    with pytest.raises(StageAbort):
        _stage(tmp_path, run_author=_boom_abort)


# ===========================================================================
# request-limit-generous — the NEW per-curator cap (default 250) is threaded to the transport
# ===========================================================================

def test_request_limit_generous_default_and_threaded(tmp_path):
    """Each curator runs under a NEW generous per-curator REQUEST_LIMIT knob (default 250,
    mirroring LEAD_AUTHOR_REQUEST_LIMIT), not a read-only-sized cap — the subprocess path had NO
    request cap, so a small cap would kill a multi-file curator on its 2nd tool call. The cap is
    threaded to the transport (→ UsageLimits(request_limit))."""
    assert config.AUTHOR_REQUEST_LIMIT == 250
    assert config.AUTHOR_ACTOR_REQUEST_LIMIT == 250
    assert config.AUTHOR_ENV_REQUEST_LIMIT == 250
    seen: list[int] = []
    _stage(
        tmp_path, request_limit=config.AUTHOR_REQUEST_LIMIT,
        run_author=lambda **kw: seen.append(kw.get("request_limit")) or _AUTHOR_RESULT_OK,
    )
    assert seen == [config.AUTHOR_REQUEST_LIMIT]
    assert seen[0] >= 50                               # generous — not a read-only-sized cap


# ===========================================================================
# key-sourced-before-spawn — the metered key is sourced BEFORE the transport runs
# ===========================================================================

def test_key_sourced_before_spawn(tmp_path):
    """run_curator_stage calls source_key(model) BEFORE the in-process spawn (the drain worktree
    carries only the ambient credential) — so a metered-billing spawn never precedes its
    key. Ordered spy proves the order; the key is sourced for the configured model. Up-front: a
    key fault raises before the spawn, so the engine never runs."""
    events: list[tuple[str, object]] = []
    _stage(
        tmp_path, model="glm-5.2",
        source_key=lambda model, label=None: events.append(("key", model)),
        run_author=lambda **kw: events.append(("run", kw.get("model"))) or _AUTHOR_RESULT_OK,
    )
    assert [e[0] for e in events] == ["key", "run"]    # key sourced BEFORE the spawn
    assert events[0][1] == "glm-5.2"                   # for the configured model

    ran: list[int] = []

    def _boom(model, label=None):
        raise FatalConfigError("no key")
    with pytest.raises(FatalConfigError):
        _stage(tmp_path, source_key=_boom, run_author=lambda **kw: ran.append(1) or _AUTHOR_RESULT_OK)
    assert ran == []                                   # up-front: transport never spawned


# ===========================================================================
# trace-anchor-before-partition — the batch_id/trace anchor is established before the spawn
# ===========================================================================

def test_trace_anchor_established_before_spawn(tmp_path):
    """The trace anchor (batch_id + pid) is established before the agent spawn and handed to the
    transport, so a partial failure still leaves a complete, locatable, per-batch-distinct trace
    (a distinct concern from key ordering — both hold). Capture the trace_name the wrapper hands
    the transport for two batch_ids into one run dir."""
    rd = _run_dir(tmp_path)
    seen: list[str] = []

    def _cap(**kw):
        seen.append(kw.get("trace_name"))
        return _AUTHOR_RESULT_OK

    for bid in ("batch-A", "batch-B"):
        _stage(tmp_path, batch_id=bid, learning_run_dir=rd, run_author=_cap)
    assert all(n for n in seen)                        # a trace anchor established each spawn
    assert len(set(seen)) == 2                         # distinct per batch_id
    pid = str(os.getpid())
    assert all(pid in n for n in seen)                 # carries the pid
    assert any("batch-A" in n for n in seen)
    assert any("batch-B" in n for n in seen)


# ===========================================================================
# model-flip-glm — the defaults flip to glm-5.2 @ low, and that flows to the transport
# ===========================================================================

def test_model_flip_glm_low_defaults_flow_to_transport(tmp_path):
    """AUTHOR_MODEL / AUTHOR_ACTOR_MODEL / AUTHOR_ENV_MODEL default to glm-5.2 and the three
    efforts to low. Leaving claude-sonnet-4-6 while routing in-process would silently move
    curator billing from the subscription to the metered first-party key. The flipped default is
    what the in-process transport is asked to build."""
    assert config.AUTHOR_MODEL == "glm-5.2"
    assert config.AUTHOR_ACTOR_MODEL == "glm-5.2"
    assert config.AUTHOR_ENV_MODEL == "glm-5.2"
    assert config.AUTHOR_EFFORT == "low"
    assert config.AUTHOR_ACTOR_EFFORT == "low"
    assert config.AUTHOR_ENV_EFFORT == "low"
    seen: list[tuple[object, object]] = []
    _stage(
        tmp_path, model=config.AUTHOR_MODEL, effort=config.AUTHOR_EFFORT,
        run_author=lambda **kw: seen.append((kw.get("model"), kw.get("effort"))) or _AUTHOR_RESULT_OK,
    )
    assert seen == [("glm-5.2", "low")]


# ===========================================================================
# model-override-crosses — claude-* @ low stays valid at build (the documented A/B override)
# ===========================================================================

def test_model_override_claude_low_crosses_validation(tmp_path, monkeypatch):
    """Overriding AUTHOR_*_MODEL back to a claude-* model with effort=low stays valid: low is a
    valid effort on BOTH the Anthropic and Fireworks providers, so the documented A/B override
    does not fail through the wrapper. Guarded control at the builder: glm-5.2 @ low and
    claude-sonnet-4-6 @ low both BUILD, while claude-* + ``none`` (a Fireworks-only effort) raises
    ValueError — proving ``low`` is the load-bearing reconciled choice."""
    seen: list[tuple[object, object]] = []
    out = _stage(
        tmp_path, model="claude-sonnet-4-6", effort="low",
        run_author=lambda **kw: seen.append((kw.get("model"), kw.get("effort"))) or _AUTHOR_RESULT_OK,
    )
    assert isinstance(out, dict)                       # no FatalConfigError through the wrapper
    assert seen == [("claude-sonnet-4-6", "low")]

    pytest.importorskip("pydantic_ai.models.openai")
    monkeypatch.setenv("FIREWORKS_API_KEY", "fw-test")
    monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
    providers.build_for_effort("glm-5.2", "low")            # default builds
    providers.build_for_effort("claude-sonnet-4-6", "low")  # A/B override builds
    with pytest.raises(ValueError, match="unsupported Anthropic effort"):
        providers.build_for_effort("claude-sonnet-4-6", "none")  # Fireworks-only effort
