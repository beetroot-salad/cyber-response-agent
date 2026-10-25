from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable
from dataclasses import replace
from pathlib import Path
from typing import Any, ClassVar

from uuid import uuid4

from defender._model import model
from defender._text import is_content_less
from defender._untrusted import wrap
from defender.knowledge._knowledge import LESSON_CORPORA as _LESSON_CORPORA, KnowledgePaths
from defender.learning.author import shared as _shared
from defender.learning.core import config
from defender.learning.core.config import RunUnprocessable, StageContext, StageWiring
from defender.learning._pydantic_stage import run_stage
from defender.learning._prompt import stage_user_message
from defender.runtime import providers
from defender.runtime.agent_definition import AgentDefinition, ResolvedRoots, RunScope, ToolSet, bind
from defender.runtime.agent_role import AgentRole
from defender.runtime.driver import MakeModel
from defender.runtime.permission import build_scoped_write_allow
from defender.runtime.permission.grant import (
    TREE,
    Grant,
    PathShapes,
    program_shape,
    under,
)
from defender.runtime.tools import AgentDeps
from defender.runtime.model_view import MODEL_WORKSPACE

AuthorError = _shared.AuthorError




def extract_marked_result(text: str, marker: str) -> str | None:
    pat = re.compile(re.escape(marker) + r"\s*(?=\{)")
    matches = list(pat.finditer(text))
    if not matches:
        return None
    return _find_balanced_json_object(text, matches[-1].end())


def _find_balanced_json_object(text: str, start: int) -> str | None:
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : i + 1]
    return None

_SEG = r"(?!\.\.(?:/| |$))[^/ ]+"

_CORPUS_AUTHOR_DENY_REASON = (
    "Blocked: the lesson curator writes and edits .md lessons under its OWN corpus only. It reads the "
    "corpus (cat, or `cat <file> | grep <pattern>`), takes its inventory from the corpus manifest, "
    "and rm's a single draft it promotes or discards — no WRITES outside the corpus, and no "
    "arbitrary shell."
)

# The shipped lesson corpora: the curator's read confine and, since `bind` refuses a corpus
# name outside the confine, also its corpus-name membership set. Sorted from the author-side
# `LESSON_CORPORA`.
SHIPPED_LESSON_CORPORA: tuple[str, ...] = tuple(sorted(_LESSON_CORPORA))


def lesson_read_confine(agent_root: Path) -> tuple[Path, ...]:
    """The curators' read confine: every shipped lesson corpus of the knowledge rooted at
    `agent_root` (a batch draft's `agent/`), resolved."""
    knowledge = KnowledgePaths(agent_root=agent_root)
    return tuple(knowledge.corpus_dir(name).resolve() for name in SHIPPED_LESSON_CORPORA)


def _corpus_spellings(corpus_dir: Path) -> str:
    # The corpus as the spawn types it from its cwd (the folder holding the knowledge root),
    # under the model's workspace, and on the host.
    rel = f"{corpus_dir.parent.name}/{corpus_dir.name}"
    # The operator's policy API still accepts host operands; model tools additionally map
    # and scope-check every operand before execution, so that spelling grants no host alias.
    return "|".join(re.escape(s) for s in (rel, str(MODEL_WORKSPACE / rel), str(corpus_dir)))


def _rm_grant(corpus_dir: Path) -> Grant:
    corpus = corpus_dir.resolve()
    return Grant(
        program="rm",
        pattern=re.compile(rf"^rm (?:{_corpus_spellings(corpus_dir)})(?:/{_SEG})+$"),
        scope=PathShapes([under(corpus, TREE)]),
        pins_path=True,
        resolve_operand=True,
    )


def _corpus_author_grants(roots: ResolvedRoots) -> tuple[Grant, ...]:
    assert roots.corpus_dir is not None
    corpus_dir = roots.corpus_dir
    corpus = corpus_dir.resolve()
    scope = PathShapes([under(corpus, TREE)])
    return (
        _rm_grant(corpus_dir),
        Grant(program="cat", pattern=program_shape("cat"), scope=scope),
        Grant(program="grep", pattern=program_shape("grep")),
    )


def _corpus_author_write_shapes(roots: ResolvedRoots) -> tuple[re.Pattern[str], ...]:
    assert roots.corpus_dir is not None
    return (build_scoped_write_allow(roots.corpus_dir, suffix=".md"),)


@model(frozen=True)
class CuratorDeps(AgentDeps):

    role: ClassVar[AgentRole] = AgentRole.CORPUS_AUTHOR

    @property
    def agent_root(self) -> Path | None:
        """The agent root this curator serves: the batch draft's `agent/` it works over. Its
        read confine drops the scope's `tenant_agent`, so the knowledge root `bind` was handed
        is the answer — a read of its lesson then leaves its `lessons_loaded` row."""
        return Path(self.roots.defender_dir) if self.roots is not None else super().agent_root

    @property
    def corpus_dir(self) -> Path:
        assert self.roots is not None
        assert self.roots.corpus_dir is not None
        return self.roots.corpus_dir

    @classmethod
    def for_run(cls, run_dir: Path, repo_root: Path, corpus_dir: Path, *, box: Any) -> CuratorDeps:
        """A thin wrapper over `bind`, taking the corpus name from `corpus_dir`'s basename and
        the knowledge root its corpora share from its parent (a batch draft's `agent/`, which
        `repo_root` — the box's `staged` root — holds). `box` is required, so a missing one
        fails loudly rather than silently disabling the curator's bash lane."""
        knowledge_root = corpus_dir.parent
        if knowledge_root.parent != repo_root:
            raise ValueError(
                f"the corpus {corpus_dir} is not a corpus of a knowledge root in {repo_root}"
            )
        scope = RunScope(
            corpus_name=corpus_dir.name,
            read_confine=lesson_read_confine(knowledge_root),
        )
        deps = bind(
            CORPUS_AUTHOR_DEF, run_dir, scope=scope, defender_dir=knowledge_root,
            box=box,
        )
        assert isinstance(deps, CuratorDeps)
        return deps


CORPUS_AUTHOR_DEF = AgentDefinition(
    role=AgentRole.CORPUS_AUTHOR,
    model=config.author_model,
    effort=config.author_effort(),
    tools=ToolSet(bash=True, write=True, lesson_read=True),
    bash_shapes=(_corpus_author_grants,),
    write_shapes=(_corpus_author_write_shapes,),
    deps_cls=CuratorDeps,
    requires_confine=True,
    requires_explicit_tree=True,
    anchors_on_tree=True,
    requires_corpus=True,
    # The read view spans the multi-corpus confine while `cat` stays on one corpus, so
    # read_allow is forced empty rather than derived from the cat grant (breaking the
    # read↔bash parity other roles keep).
    read_allow_override=PathShapes(),
    deny_reason=_CORPUS_AUTHOR_DENY_REASON,
)


def _run_curator_pydantic(
    wiring: StageWiring,
    ctx: StageContext,
    *,
    corpus_dir: Path,
    make_model: MakeModel = providers.build_for_effort,
) -> str:
    """Both limits vary per spawn here, so the caller owns the whole context."""
    # Required here, though optional on the shared context. A raise, not an assert, since
    # `python -O` strips asserts.
    repo_root = ctx.repo_root
    if repo_root is None:
        raise ValueError(
            "curator stage needs ctx.repo_root: it binds a corpus off the repo tree"
        )
    deps = CuratorDeps.for_run(ctx.learning_run_dir, repo_root, corpus_dir, box=ctx.box)
    return run_stage(
        stage="curator",
        wiring=wiring, ctx=ctx, deps=deps,
        make_model=make_model, require_output=True,
    )


def run_curator_stage(
    *,
    wiring: StageWiring,
    ctx: StageContext,
    corpus_dir: Path,
    log: logging.Logger,
    source_key: Callable[..., object] = config.source_first_party_key,
    run_author: Callable[..., str] = _run_curator_pydantic,
) -> dict:
    """`wiring` is the spawn's prompt/model/effort/trace/label/batch, `ctx` its roots, user
    prompt and two env-backed limits.

    Every model/effort/limit/timeout knob is caller-supplied: each is env-backed and differs
    per corpus, so a default evaluated at import would freeze it. Sources only the author's
    key; the drain handles the verifier key."""
    # The batch id comes off the wiring, so the log line, AuthorErrors and trace filename
    # can't disagree. A raise, not an assert, since `python -O` strips asserts.
    batch_id = wiring.batch_id
    if batch_id is None:
        raise ValueError(
            "curator stage needs a wiring built by StageWiring.for_batch: its log line and "
            "its AuthorErrors name the same batch its trace file is keyed on"
        )
    log.info(
        f"spawn curator {batch_id} in-process (model={wiring.model}, "
        f"effort={wiring.effort}, timeout={ctx.wall_clock_timeout}s)"
    )
    stage_salt = ctx.salt if ctx.salt is not None else uuid4().hex
    user_prompt = ctx.user
    if f"<run-{stage_salt}-" not in user_prompt:
        user_prompt = stage_user_message(
            stage_salt, wrap(user_prompt, "lesson_rows", stage_salt)
        )
    source_key(wiring.model, label="curator")
    try:
        text = run_author(
            wiring,
            replace(ctx, user=user_prompt, salt=stage_salt),
            corpus_dir=corpus_dir,
        )
    except RunUnprocessable as e:
        raise AuthorError(f"curator ({batch_id}) did not complete: {e}") from e
    body = extract_marked_result(text, "AUTHOR_RESULT:")
    if body is None:
        if is_content_less(text):
            return {}
        raise AuthorError(
            f"curator ({batch_id}) emitted no AUTHOR_RESULT marker:\n{text[-2000:]}"
        )
    try:
        return json.loads(body)
    except json.JSONDecodeError as e:
        raise AuthorError(
            f"curator ({batch_id}) AUTHOR_RESULT JSON invalid: {e}\n{body}"
        ) from e
