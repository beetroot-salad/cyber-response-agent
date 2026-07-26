"""Hermetic spec for the pipeline's "did this stage produce output" test (#722).

``_pydantic_stage`` decides, on the model's OWN text, whether a stage returned real
output or nothing: the ``RunUnprocessable("... returned empty output")`` abort at
``run_stage``'s tail (the load-bearing, content-driven decision) and the message the
two fault-path raise sites pick. That text is steerable by the alert/gather content
the stage was asked to analyze, so the predicate must classify by what RENDERS.

``not text.strip()`` was not that predicate. strip() keys off ``str.isspace()``, which
splits the invisible characters the wrong way in BOTH directions — True for the
visible-width separators (U+00A0, U+3000, U+2028, U+0085, U+001C-1F), False for the
zero-width ones (U+200B, U+FEFF, U+00AD, U+2060) and for NUL — so a response rendering
as nothing at all was accepted as real stage output while one carrying only spacing
aborted the run.

Driven through the real seams: the shipped read-only ``oracle`` stage and the shipped
``require_output=False`` lead-author lane, each with a ``FunctionModel`` injected at
the ``make_model`` DI seam under ``override_allow_model_requests(False)``; and the
response classifier fed by a real ``observe.RequestLogger.log()`` of real
``ModelResponse`` objects — the same ``ModelMessagesTypeAdapter`` dump the on-disk
trace carries, not hand-written record dicts. No setattr, no monkeypatching.
"""
from __future__ import annotations

from pathlib import Path

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

from pydantic_ai.messages import (  # noqa: E402
    ModelRequest,
    ModelResponse,
    TextPart,
    ThinkingPart,
    ToolCallPart,
    UserPromptPart,
)
from pydantic_ai.models import override_allow_model_requests  # noqa: E402

from defender.learning.core import config  # noqa: E402
from defender.learning.core.config import RunUnprocessable  # noqa: E402
from defender.learning.leads.lead_author_engine import LEAD_AUTHOR_DEF  # noqa: E402
from defender._text import is_content_less  # noqa: E402
from defender.learning.pipeline._pydantic_stage import (  # noqa: E402
    _last_response_is_empty_text,
    run_stage,
)
from defender.learning.pipeline.oracle_engine import _run_oracle_pydantic  # noqa: E402
from defender.runtime import observe  # noqa: E402
from defender.runtime.agent_definition import bind  # noqa: E402
from defender.tests._engine_helpers import fake_model as _fake_model  # noqa: E402
from defender.tests._engine_helpers import replay_once as _replay  # noqa: E402

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


def _oracle(tmp_path: Path, text: str, tag: str) -> str:
    """The REAL shipped oracle stage (require_output defaulted True) on a scripted final."""
    lrd = tmp_path / "learning_run"
    lrd.mkdir(exist_ok=True)
    with override_allow_model_requests(False):
        return _run_oracle_pydantic(
            _prompt(tmp_path), "glm-5.2", "none", f"oracle-{tag}.trace.jsonl",
            f"oracle:{tag}", "project this lead", lrd,
            make_model=_fake_model(_replay(text)),
        )


def _lead_author(tmp_path: Path, text: str, tag: str, **over) -> str:
    """The REAL shipped ``require_output=False`` lane (the lead author, a writer stage)."""
    wt = tmp_path / "wt"
    (wt / "defender" / "skills").mkdir(parents=True, exist_ok=True)
    rd = tmp_path / "runs" / "run-A"
    rd.mkdir(parents=True, exist_ok=True)
    deps = bind(LEAD_AUTHOR_DEF, rd, defender_dir=wt / "defender")
    kw = {"require_output": False}
    kw.update(over)
    with override_allow_model_requests(False):
        return run_stage(
            stage="lead_author", prompt_path=_prompt(tmp_path), model="m", effort=None,
            trace_name=f"la-{tag}.trace.jsonl", label="la", user="u",
            learning_run_dir=rd, deps=deps, request_limit=4,
            wall_clock_timeout=config.lead_author_timeout(),
            make_model=_fake_model(_replay(text)), **kw,
        )


def _logged(tmp_path: Path, parts, tag: str) -> list[dict]:
    """``logger.messages`` after a REAL request/response pair goes through observe.

    The classifier reads the dumped record shape, so build it the only way production
    does: hand real ModelRequest/ModelResponse objects to ``RequestLogger.log``.
    """
    logger = observe.RequestLogger(tmp_path / f"{tag}.trace.jsonl")
    try:
        logger.log(
            request_messages=[ModelRequest(parts=[UserPromptPart(content="u")])],
            response=ModelResponse(parts=parts),
        )
    finally:
        logger.close()
    return logger.messages


# ===========================================================================
# run_stage's tail guard — the content-driven abort
# ===========================================================================

@pytest.mark.parametrize(("tag", "text"), CONTENT_LESS, ids=[t for t, _ in CONTENT_LESS])
def test_oracle_stage_aborts_on_any_content_less_final(tmp_path, tag, text):
    """A final the reader would see as nothing — of ANY spelling, on either side of
    isspace() — is "empty output", so the stage aborts instead of handing the caller a
    blank verdict. Before #722 the zero-width half of this table (U+200B, U+FEFF,
    U+00AD, U+2060, NUL, tag characters) was returned as real oracle output."""
    with pytest.raises(RunUnprocessable, match="returned empty output"):
        _oracle(tmp_path, text, tag)


@pytest.mark.parametrize(("tag", "text"), CONTENT, ids=[t for t, _ in CONTENT])
def test_oracle_stage_returns_real_output_verbatim(tmp_path, tag, text):
    """The controls, and the guard's blast radius: one visible character is content, and
    the stage's output crosses the guard BYTE-FOR-BYTE. The guard classifies; it never
    rewrites — a BOM-prefixed or zero-width-joined real verdict is not silently mangled,
    and NBSP padding does not cost the payload it wraps."""
    assert _oracle(tmp_path, text, tag) == text


def test_the_abort_is_the_same_predicate_on_both_sides_of_isspace(tmp_path):
    """The steering pair, side by side through the real stage: U+00A0 (isspace True,
    visible width) and U+200B (isspace False, zero width) now reach the SAME verdict.
    Under `.strip()` they reached opposite ones — abort vs. accepted-as-output — which
    is exactly the fork attacker-influenced text could pick between."""
    for tag, text in (("nbsp", " "), ("zwsp", "​")):
        with pytest.raises(RunUnprocessable, match="returned empty output"):
            _oracle(tmp_path, text, tag)


def test_content_less_classifies_by_rendering_not_by_isspace():
    """The predicate itself, against ``str`` ground truth: it is not a `.strip()` rename.
    The zero-width characters survive strip() untouched and are still content-less; the
    wide separators are content-less too. Controls: prose, and prose that merely CARRIES
    an invisible character, are content."""
    for ch in ("​", "﻿", "­", "⁠", "\x00"):
        assert not ch.isspace()
        assert ch.strip() == ch  # strip() cannot see these
        assert is_content_less(ch)
    for ch in (" ", "　", " "):
        assert ch.isspace()
        assert ch.strip() == ""   # strip() already saw these
        assert is_content_less(ch)
    assert is_content_less("")
    assert not is_content_less("x")
    assert not is_content_less("​﻿x ")


# ===========================================================================
# require_output=False — the opt-in lane stays opted out
# ===========================================================================

@pytest.mark.parametrize(
    ("tag", "text"),
    [("spaces", "  "), ("nbsp", " "), ("zwsp", "​"), ("nul", "\x00")],
)
def test_require_output_false_still_accepts_a_content_less_final(tmp_path, tag, text):
    """Regression guard on the writer lane (#680): a lead author may end with no prose,
    and the widened predicate must not start quarantining it. The flag suppresses the
    guard wholesale, so every spelling comes back verbatim. (A truly-empty "" cannot be
    tested here — pydantic-ai rejects it before run_stage sees a result.)"""
    assert _lead_author(tmp_path, text, tag) == text


def test_default_require_output_still_quarantines_the_writer_lane(tmp_path):
    """The guarded negative for the case above: the SAME stage without the flag aborts,
    so the pass-through is the flag's doing and not a hole in the guard."""
    with pytest.raises(RunUnprocessable, match="returned empty output"):
        _lead_author(tmp_path, "​", "default", require_output=True)


# ===========================================================================
# the fault-path classifier — which message a failed run reports
# ===========================================================================

@pytest.mark.parametrize(("tag", "text"), CONTENT_LESS, ids=[t for t, _ in CONTENT_LESS])
def test_a_logged_response_of_only_content_less_text_reads_as_empty(tmp_path, tag, text):
    """The fault-path classifier over a REAL logged response: a lone text part carrying
    nothing visible reads as "empty output", so a run that faulted after emitting only
    invisible characters reports what happened rather than the transport's repr."""
    assert _last_response_is_empty_text(_logged(tmp_path, [TextPart(content=text)], tag))


@pytest.mark.parametrize(("tag", "text"), CONTENT, ids=[t for t, _ in CONTENT])
def test_a_logged_response_carrying_visible_text_does_not_read_as_empty(tmp_path, tag, text):
    """The control: a response with real text is not "empty output" — the fault gets its
    own message, whatever invisible characters the text happens to carry."""
    assert not _last_response_is_empty_text(_logged(tmp_path, [TextPart(content=text)], tag))


def test_classifier_shape_rules_are_unchanged(tmp_path):
    """#722 widened WHICH characters count as content-less, nothing else. The structural
    rules still hold: every part must be content-less text (two blank parts qualify; a
    ThinkingPart or a ToolCallPart alongside means the turn did something and is not
    "empty output"), a partless response does not qualify, and neither does a transcript
    with no response in it at all."""
    blank, ok = TextPart(content="​"), TextPart(content="real")
    assert _last_response_is_empty_text(_logged(tmp_path, [blank, TextPart(content=" ")], "two"))
    assert not _last_response_is_empty_text(_logged(tmp_path, [blank, ok], "mixed"))
    assert not _last_response_is_empty_text(
        _logged(tmp_path, [blank, ThinkingPart(content="thought")], "think"))
    assert not _last_response_is_empty_text(
        _logged(tmp_path, [blank, ToolCallPart(tool_name="read_file", args={})], "tool"))
    assert not _last_response_is_empty_text(_logged(tmp_path, [], "partless"))
    assert not _last_response_is_empty_text([])


def test_a_truly_empty_final_reports_empty_output_through_the_fault_path(tmp_path):
    """End-to-end proof that the classifier is what SELECTS the fault message: pydantic-ai
    rejects a truly-empty final itself, so run_stage lands in its ``except`` arm — with
    require_output on, the classifier turns that into "returned empty output"; with it
    off, the same fault reports the raw transport failure. The abort is not the
    classifier's to make (both arms raise); only the message is."""
    with pytest.raises(RunUnprocessable, match="returned empty output"):
        _lead_author(tmp_path, "", "empty-on", require_output=True)
    with pytest.raises(RunUnprocessable, match="failed:"):
        _lead_author(tmp_path, "", "empty-off")
