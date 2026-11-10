"""The feedback tick's real decide seam (#1414 A3): one no-tools model request over the comment, the framing
run's outcome and its captured lookups, all framed as data (P4). The answer is parsed here and validated by
the host (`feedback_decide.validate`); a reply that is no JSON object is a refused answer."""
from __future__ import annotations

import json
import re
import secrets
import tempfile
from pathlib import Path
from typing import Any

from defender.learning._prompt import stage_user_message, titled_section
from defender.learning.core.config import StageContext, StageWiring, feedback_effort, feedback_model, subagent_timeout
from defender.learning.core.feedback_decide import InvalidAnswer

_PROMPT = Path(__file__).with_name("feedback_decide.md")
_FENCE = re.compile(r"^```(?:json)?\s*(.*?)\s*```$", re.S)


def decide_message(item: dict) -> str:
    """The user message: every section framed on one fresh salt, the comment's author left out."""
    salt = secrets.token_hex(8)
    lookups = [{"index": i, **lk} for i, lk in enumerate(item["lookups"])]
    return stage_user_message(
        salt,
        titled_section("Comment", item["body"], salt=salt),
        titled_section("How the investigation ended", item.get("outcome") or "unknown", salt=salt),
        titled_section("Lookups the investigation made", lookups or "none", salt=salt),
    )


def parse_reply(text: str) -> Any:
    """The reply's JSON object, a code fence tolerated; anything else is an invalid answer."""
    body = text.strip()
    if (m := _FENCE.match(body)):
        body = m.group(1)
    try:
        return json.loads(body)
    except ValueError as e:
        raise InvalidAnswer(f"the reply is not a JSON object: {e}") from e


def model_decide(item: dict, *, box: Any = None) -> Any:  # noqa: ARG001 — the seam's shape: a model-only call takes no box
    """Ask the model once about one queued comment."""
    from defender.learning._pydantic_stage import run_stage
    from defender.learning.feedback_role import FeedbackDeps

    label = f"feedback:{item['comment_id']}"
    with tempfile.TemporaryDirectory(prefix="defender-feedback-") as scratch:
        reply = run_stage(
            stage="feedback",
            wiring=StageWiring(prompt_path=_PROMPT, model=feedback_model(), effort=feedback_effort(),
                               trace_name=label.replace(":", "-"), label=label),
            ctx=StageContext(learning_run_dir=Path(scratch), user=decide_message(item), request_limit=1,
                             wall_clock_timeout=subagent_timeout()),
            deps=FeedbackDeps(),
        )
    return parse_reply(reply)
