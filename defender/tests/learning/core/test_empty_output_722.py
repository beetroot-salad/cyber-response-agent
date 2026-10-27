"""The pipeline's did-this-stage-produce-output test classifies by rendering (zero-width and wide spaces), not by str.isspace."""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

from pydantic_ai.messages import (  # noqa: E402
    ModelRequest,
    ModelResponse,
    TextPart,
    UserPromptPart,
)
from pydantic_ai.models import override_allow_model_requests  # noqa: E402

from defender.learning.core.config import StageContext, StageWiring  # noqa: E402
from defender.learning.core import config  # noqa: E402
from defender.learning.core.config import RunUnprocessable  # noqa: E402
from defender.learning.leads.lead_author_engine import LEAD_AUTHOR_DEF  # noqa: E402
from defender.learning._pydantic_stage import (  # noqa: E402
    _last_response_is_empty_text,
    run_stage,
)
from defender.learning.branch.questioner import QuestionerDeps  # noqa: E402
from defender.tests.support.shared.contracts._repo import seed_adapter_stubs  # noqa: E402
from defender.investigation import observe  # noqa: E402
from defender.investigation.agent_definition import bind  # noqa: E402
from defender.tests.support.runtime.engine._engine_helpers import fake_model as _fake_model  # noqa: E402
from defender.tests.support.runtime.engine._engine_helpers import replay_once as _replay  # noqa: E402

# Every spelling of "the model said nothing", labelled with which side of isspace()
# it falls on — the split that made the old guard steerable in two directions.
CONTENT_LESS = [
    ("truly-empty", ""),
    ("ascii-spaces", "   "),
    ("ascii-newlines", "\n\n\t"),
    ("U+00A0-no-break-space", " "),            # isspace() True, renders as space
    ("U+3000-ideographic-space", "　"),         # isspace() True, renders as space
    ("U+2028-line-separator", " "),            # isspace() True
    ("U+0085-next-line", ""),                 # isspace() True
    ("U+001F-unit-separator", ""),            # isspace() True
    ("U+200B-zero-width-space", "​"),          # isspace() False, renders as NOTHING
    ("U+FEFF-byte-order-mark", "﻿"),           # isspace() False, renders as NOTHING
    ("U+00AD-soft-hyphen", "­"),               # isspace() False, renders as NOTHING
    ("U+2060-word-joiner", "⁠"),               # isspace() False, renders as NOTHING
    ("U+0000-nul", "\x00"),                         # isspace() False, renders as NOTHING
    ("U+E0041-tag-latin-a", "\U000e0041"),          # isspace() False, renders as NOTHING
    ("mixed", "​ ﻿\n\x00"),
]

# Positive controls: real output, including real output that CARRIES invisible
# characters. One visible character is content — the guard must pass these through.
CONTENT = [
    ("prose", "disposition: benign"),
    ("bom-prefixed-prose", "﻿disposition: benign"),
    ("zero-width-inside-a-word", "be​nign"),
    ("nbsp-around-prose", " ok "),
    ("lone-punctuation", "."),
    ("digit-zero", "0"),
    ("private-use-glyph", ""),  # Co: may carry a glyph — deliberately not "invisible"
]


def _prompt(tmp_path: Path) -> Path:
    p = tmp_path / "stage.md"
    p.write_text("Project this lead's telemetry. Emit the events YAML.\n")
    return p


def _reader_stage(tmp_path: Path, text: str, tag: str) -> str:
    """A REAL shipped `require_output=True` stage on a scripted final."""
    lrd = tmp_path / "learning_run"
    lrd.mkdir(exist_ok=True)
    with override_allow_model_requests(False):
        return run_stage(
            stage="questioner",
            wiring=StageWiring(
                prompt_path=_prompt(tmp_path), model="kimi-k3", effort="none",
                trace_name=f"questioner-{tag}.trace.jsonl", label=f"questioner:{tag}",
            ),
            ctx=StageContext(
                learning_run_dir=lrd, user="author this family", request_limit=1,
                wall_clock_timeout=config.subagent_timeout(),
            ),
            deps=QuestionerDeps(),
            make_model=_fake_model(_replay(text)),
        )


def _lead_author(tmp_path: Path, text: str, tag: str, **over) -> str:
    """The REAL shipped ``require_output=False`` lane (the lead author, a writer stage)."""
    wt = tmp_path / "wt"
    (wt / "defender" / "skills").mkdir(parents=True, exist_ok=True)
    # The lead author's write lanes are compiled per DECLARED system (#772), so the tree has
    # to declare one for the policy to have any lane at all.
    seed_adapter_stubs(wt / "defender", ("elastic",))
    rd = tmp_path / "runs" / "run-A"
    rd.mkdir(parents=True, exist_ok=True)
    deps = bind(LEAD_AUTHOR_DEF, rd, defender_dir=wt / "defender")
    kw = {"require_output": False}
    kw.update(over)
    with override_allow_model_requests(False):
        return run_stage(
            stage="lead_author",
            wiring=StageWiring(
                prompt_path=_prompt(tmp_path), model="m", effort=None,
                trace_name=f"la-{tag}.trace.jsonl", label="la",
            ),
            ctx=StageContext(
                learning_run_dir=rd, user="u", request_limit=4,
                wall_clock_timeout=config.lead_author_timeout(),
            ),
            deps=deps,
            make_model=_fake_model(_replay(text)), **kw,
        )


def _logged(tmp_path: Path, parts, tag: str) -> list[dict]:
    """``logger.messages`` after a REAL request/response pair goes through observe."""
    logger = observe.RequestLogger(tmp_path / f"{tag}.trace.jsonl")
    try:
        logger.log(
            request_messages=[ModelRequest(parts=[UserPromptPart(content="u")])],
            response=ModelResponse(parts=parts),
        )
    finally:
        logger.close()
    return logger.messages


# run_stage's tail guard — the content-driven abort

@pytest.mark.parametrize(("tag", "text"), CONTENT_LESS, ids=[t for t, _ in CONTENT_LESS])
def test_reader_stage_aborts_on_any_content_less_final(tmp_path, tag, text):
    """A final the reader would see as nothing — of ANY spelling, on either side of isspace() — is
    "empty output", so the stage aborts instead of handing the caller a blank verdict."""
    with pytest.raises(RunUnprocessable, match="returned empty output"):
        _reader_stage(tmp_path, text, tag)


@pytest.mark.parametrize(("tag", "text"), CONTENT, ids=[t for t, _ in CONTENT])
def test_reader_stage_returns_real_output_verbatim(tmp_path, tag, text):
    """The controls, and the guard's blast radius: one visible character is content, and the stage's
    output crosses the guard BYTE-FOR-BYTE."""
    assert _reader_stage(tmp_path, text, tag) == text


# require_output=False — the opt-in lane stays opted out

@pytest.mark.parametrize(
    ("tag", "text"),
    [("spaces", "  "), ("nbsp", " "), ("zwsp", "​"), ("nul", "\x00")],
)
def test_require_output_false_still_accepts_a_content_less_final(tmp_path, tag, text):
    """Regression guard on the writer lane (#680): a lead author may end with no prose, and the
    widened predicate must not start quarantining it."""
    assert _lead_author(tmp_path, text, tag) == text


# the fault-path classifier — which message a failed run reports

@pytest.mark.parametrize(("tag", "text"), CONTENT_LESS, ids=[t for t, _ in CONTENT_LESS])
def test_a_logged_response_of_only_content_less_text_reads_as_empty(tmp_path, tag, text):
    assert _last_response_is_empty_text(_logged(tmp_path, [TextPart(content=text)], tag))


def test_a_truly_empty_final_reports_empty_output_through_the_fault_path(tmp_path):
    with pytest.raises(RunUnprocessable, match="returned empty output"):
        _lead_author(tmp_path, "", "empty-on", require_output=True)
    with pytest.raises(RunUnprocessable, match="failed:"):
        _lead_author(tmp_path, "", "empty-off")
