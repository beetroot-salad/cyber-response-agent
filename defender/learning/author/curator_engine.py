from __future__ import annotations

import json
import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from defender.learning.author import shared as _shared
from defender.learning.author.verify_forward.checks import ForwardCheck
from defender.learning.author.verify_forward.engine import _run_verify_pydantic
from defender.learning.core import config
from defender.learning.core.config import RunUnprocessable
from defender.learning.pipeline._pydantic_stage import run_stage
from defender.runtime import providers
from defender.runtime.agent_definition import AgentDefinition, ToolSet
from defender.runtime.agent_role import AgentRole
from defender.runtime.driver import MakeModel
from defender.runtime.permission import AgentPolicy, build_write_allow
from defender.runtime.permission.grant import (
    TREE,
    Grant,
    PathShapes,
    program_shape,
    under,
)
from defender.runtime.tools import AgentDeps

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
    "and rm's a single draft it promotes or discards — no writes outside the corpus, no other "
    "corpus, no arbitrary shell. Forward-check with the forward_check tool."
)


def _corpus_spellings(corpus_dir: Path) -> str:
    rel = f"defender/{corpus_dir.name}"
    return "|".join(re.escape(s) for s in (rel, str(corpus_dir)))


def _rm_grant(corpus_dir: Path) -> Grant:
    return Grant(
        program="rm",
        pattern=re.compile(rf"^rm (?:{_corpus_spellings(corpus_dir)})(?:/{_SEG})+$"),
        pins_path=True,
    )


def _corpus_author_grants(corpus_dir: Path) -> tuple[Grant, ...]:
    corpus = corpus_dir.resolve()
    scope = PathShapes([under(corpus, TREE)])
    return (
        _rm_grant(corpus_dir),
        Grant(program="cat", pattern=program_shape("cat"), scope=scope),
        Grant(program="grep", pattern=program_shape("grep")),
    )


def _corpus_author_policy(corpus_dir: Path) -> AgentPolicy:
    return AgentPolicy(
        bash_allow=_corpus_author_grants(corpus_dir),
        read_roots=(),
        read_confine=(),
        write_allow=(build_write_allow(corpus_dir, suffix=".md"),),
        deny_reason=_CORPUS_AUTHOR_DENY_REASON,
    )


@dataclass(frozen=True)
class CuratorDeps(AgentDeps):

    role: ClassVar[AgentRole] = AgentRole.CORPUS_AUTHOR

    corpus_dir: Path = field(kw_only=True)
    check: ForwardCheck = field(kw_only=True)
    runs_dir: Path = field(kw_only=True)
    pending: Path = field(kw_only=True)
    queued_ids: frozenset[str] = field(kw_only=True)
    run_verify: Callable[..., str] = field(kw_only=True)

    @classmethod
    def for_run(  # noqa: PLR0913 — the spawn's roots + its bound check + the transport seam
        cls, run_dir: Path, repo_root: Path, corpus_dir: Path,
        *, check: ForwardCheck, runs_dir: Path, pending: Path,
        queued_ids: frozenset[str], run_verify: Callable[..., str] = _run_verify_pydantic,
    ) -> CuratorDeps:
        defender_dir = repo_root / "defender"
        return cls._for_run(
            run_dir,
            _corpus_author_policy(corpus_dir),
            defender_dir=defender_dir,
            cwd_anchor=repo_root,
            corpus_dir=corpus_dir,
            check=check,
            runs_dir=runs_dir,
            pending=pending,
            queued_ids=queued_ids,
            run_verify=run_verify,
        )


CORPUS_AUTHOR_DEF = AgentDefinition(
    role=AgentRole.CORPUS_AUTHOR,
    model=lambda: config.AUTHOR_MODEL,
    effort=config.AUTHOR_EFFORT,
    tools=ToolSet(bash=True, write=True, forward_check=True, lesson_read=True),
    bindable=False,
    deny_reason=_CORPUS_AUTHOR_DENY_REASON,
)


def _run_curator_pydantic(  # noqa: PLR0913 — the transport signature plus the make_model test seam; every param is load-bearing per-call state
    *,
    prompt_path: Path,
    model: str,
    effort: str | None,
    trace_name: str,
    label: str,
    user: str,
    learning_run_dir: Path,
    repo_root: Path,
    corpus_dir: Path,
    check: ForwardCheck,
    runs_dir: Path,
    pending: Path,
    queued_ids: frozenset[str],
    run_verify: Callable[..., str] = _run_verify_pydantic,
    request_limit: int = config.AUTHOR_REQUEST_LIMIT,
    wall_clock_timeout: int = config.AUTHOR_TIMEOUT,
    make_model: MakeModel = providers.build_for_effort,
) -> str:
    deps = CuratorDeps.for_run(
        learning_run_dir, repo_root, corpus_dir,
        check=check, runs_dir=runs_dir, pending=pending,
        queued_ids=queued_ids, run_verify=run_verify,
    )
    return run_stage(
        stage="curator",
        prompt_path=prompt_path, model=model, effort=effort,
        trace_name=trace_name, label=label, user=user,
        learning_run_dir=learning_run_dir, deps=deps,
        request_limit=request_limit, make_model=make_model,
        require_output=True,
        wall_clock_timeout=wall_clock_timeout,
    )


def run_curator_stage(  # noqa: PLR0913 — the spawn contract (per-spawn inputs + logger) + its config knobs + 2 DI seams; every param is load-bearing per-call state
    *,
    system_prompt_file: Path,
    batch_id: str,
    user_prompt: str,
    corpus_dir: Path,
    check: ForwardCheck,
    runs_dir: Path,
    pending: Path,
    queued_ids: frozenset[str],
    repo_root: Path,
    learning_run_dir: Path,
    log: Callable[[str], None],
    model: str = config.AUTHOR_MODEL,
    effort: str | None = config.AUTHOR_EFFORT,
    request_limit: int = config.AUTHOR_REQUEST_LIMIT,
    timeout: int = config.AUTHOR_TIMEOUT,
    source_key: Callable[..., object] = config.source_first_party_key,
    run_author: Callable[..., str] = _run_curator_pydantic,
    run_verify: Callable[..., str] = _run_verify_pydantic,
) -> dict:
    log(f"spawn curator {batch_id} in-process (model={model}, effort={effort}, timeout={timeout}s)")
    source_key(model, label="curator")
    if check.prompt_path is not None and (
        providers.provider_for(config.VERIFIER_MODEL).api_key_var
        != providers.provider_for(model).api_key_var
    ):
        source_key(config.VERIFIER_MODEL, label=f"verify:{check.error_prefix}")
    trace_name = f"{batch_id}.{os.getpid()}.trace.jsonl"
    try:
        text = run_author(
            prompt_path=system_prompt_file, model=model, effort=effort,
            trace_name=trace_name, label=f"curator:{batch_id}", user=user_prompt,
            learning_run_dir=learning_run_dir, repo_root=repo_root,
            corpus_dir=corpus_dir, check=check, runs_dir=runs_dir, pending=pending,
            queued_ids=queued_ids, run_verify=run_verify,
            request_limit=request_limit, wall_clock_timeout=timeout,
        )
    except RunUnprocessable as e:
        raise AuthorError(f"curator ({batch_id}) did not complete: {e}") from e
    body = extract_marked_result(text, "AUTHOR_RESULT:")
    if body is None:
        if not text.strip():
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
