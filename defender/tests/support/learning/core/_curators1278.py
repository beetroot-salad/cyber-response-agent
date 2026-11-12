"""#1278 scripted-model curators: the REAL curators run, and only the model's replies are scripted.

`ScriptedModel` is the `make_model` seam's FunctionModel. A curator's request is answered the way a model
answers it: `write_file` tool calls (through the curator's own tools and permission gate, into the batch's
draft) and then a final `AUTHOR_RESULT: {...}` text. Nothing here decides a fate: which item is committed,
skipped, deferred, held or published is the real curator's, gate's and store's. The harness only records what
the model was shown (`seen`) so a test can observe which items each curator was handed.

Interface request (seam, not policy): `author_drain(..., make_model=)` and `lead_author_drain(..., make_model=)`
hand `make_model` to the curators' `run_stage` (default `providers.build_for_effort`); `fake_model` below is
its test value.
"""
from __future__ import annotations

import json
import re
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from defender.tests.support.runtime.engine._engine_helpers import fake_model

#: The curators, as the prompt tells them apart: the lessons dir the user turn names.
LESSONS, QUESTIONER, PITFALLS = "lessons", "questioner", "pitfalls"
#: A4: the feedback curator (items of kind `feedback_instruction`), told apart by its rows' label in the user turn.
FEEDBACK = "feedback"


@dataclass(frozen=True)
class Reply:
    """What the model does on one call: write `writes` (path below the curator's folder -> text; the lessons
    curators' folder is their corpus dir, the pitfalls curator's the draft root),
    then answer `result` as its AUTHOR_RESULT (`raw` instead replaces the whole final text)."""

    writes: dict[str, str] = field(default_factory=dict)
    result: dict[str, Any] | None = None
    raw: str | None = None

    def final(self) -> str:
        if self.raw is not None:
            return self.raw
        return "AUTHOR_RESULT: " + json.dumps(self.result if self.result is not None else
                                              {"committed": [], "consumed_skip": [], "commit_message": "noop"})


def result(committed=(), skipped=(), message: str = "learning: scripted batch") -> dict[str, Any]:
    """An AUTHOR_RESULT body: ids committed, and `skipped` as (id, reason) pairs the curator reports consumed."""
    return {"committed": list(committed),
            "consumed_skip": [{"finding_id": i, "reason": why} for i, why in skipped],
            "commit_message": message}


@dataclass
class Seen:
    """One model call as the curator framed it: which curator, the item keys in its rows frame, the user turn."""

    curator: str
    keys: list[str]
    prompt: str


_KEY = re.compile(r'"(?:finding_id|pitfall_id|comment_id)":\s*"?([^",}\s]+)"?')
_LESSONS_DIR = re.compile(r"^lessons_dir:\s*(\S+)", re.M)
_DRAFT_ROOT = re.compile(r"^draft_root:\s*(\S+)", re.M)


class ScriptedModel:
    """`ScriptedModel(lessons=Reply(...), questioner=Reply(...), pitfalls=Reply(...))`: one reply per curator,
    given on every call that curator makes (a curator with no reply answers an empty no-op)."""

    def __init__(self, **replies: Reply) -> None:
        unknown = set(replies) - {LESSONS, QUESTIONER, PITFALLS, FEEDBACK}
        assert not unknown, f"unknown curators {unknown}"
        self.replies = replies
        self.seen: list[Seen] = []

    # -- the FunctionModel -------------------------------------------------------------------------

    def __call__(self, messages: list[Any], _info: Any) -> Any:
        from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart, ToolReturnPart

        prompt = _first_user_text(messages)
        curator = _curator_of(prompt)
        reply = self.replies.get(curator, Reply())
        returned = any(isinstance(p, ToolReturnPart) for m in messages for p in getattr(m, "parts", ()))
        if not returned and not self._recorded(prompt):
            self.seen.append(Seen(curator, _KEY.findall(prompt), prompt))
        if reply.writes and not returned:
            where = (_DRAFT_ROOT if curator == PITFALLS else _LESSONS_DIR).search(prompt)
            assert where is not None, f"the {curator} curator's prompt names no folder to write below"
            folder = where.group(1).rstrip("/")
            return ModelResponse(parts=[
                ToolCallPart(tool_name="write_file", args={"path": f"{folder}/{name}", "content": text})
                for name, text in reply.writes.items()])
        return ModelResponse(parts=[TextPart(content=reply.final())])

    def _recorded(self, prompt: str) -> bool:
        return bool(self.seen) and self.seen[-1].prompt == prompt

    # -- what a test reads ---------------------------------------------------------------------------

    def keys_shown(self, curator: str) -> list[str]:
        """Every item key the curator's model was shown, in call order."""
        return [k for s in self.seen if s.curator == curator for k in s.keys]

    def called(self, curator: str) -> bool:
        return any(s.curator == curator for s in self.seen)

    @property
    def make_model(self) -> Any:
        """The `make_model=` value to hand `author_drain` / `lead_author_drain`."""
        return fake_model(self)


def _first_user_text(messages: list[Any]) -> str:
    from pydantic_ai.messages import UserPromptPart

    for m in messages:
        for p in getattr(m, "parts", ()):
            if isinstance(p, UserPromptPart):
                return p.content if isinstance(p.content, str) else " ".join(map(str, p.content))
    return ""


def _curator_of(prompt: str) -> str:
    if "skills_dir:" in prompt:
        return PITFALLS
    if re.search(r"^feedback instructions \(\d+\)", prompt, re.M):
        return FEEDBACK
    return QUESTIONER if re.search(r"^lessons_dir:\s*\S*lessons-questioner", prompt, re.M) else LESSONS


@contextmanager
def scripted(model: ScriptedModel, monkeypatch: Any) -> Iterator[ScriptedModel]:
    """The environment a real curator needs to reach its (scripted) model: a stand-in key for the key check, and
    real model requests refused, so an unscripted path fails instead of reaching a provider."""
    from pydantic_ai.models import override_allow_model_requests

    monkeypatch.setenv("FIREWORKS_API_KEY", "scripted-not-a-key")
    with override_allow_model_requests(False):
        yield model
