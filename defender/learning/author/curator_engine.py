from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, ClassVar

from uuid import uuid4

from pydantic_ai.exceptions import ModelRetry

from defender._text import is_content_less
from defender._untrusted import wrap
from defender.hooks.record_lesson_load import LESSON_CORPORA as _LESSON_CORPORA
from defender.learning.author import shared as _shared
from defender.learning.author.verify_forward.checks import ForwardCheck
from defender.learning.author.verify_forward.engine import _run_verify_pydantic
from defender.learning.core import config
from defender.learning.core.config import RunUnprocessable, StageContext, StageWiring
from defender.learning.pipeline._pydantic_stage import run_stage
from defender.learning.pipeline._prompt import stage_user_message
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


# The three lesson corpora ever shipped — the curator's fixed R4 read confine AND, by
# construction, its MD-6 exact-match corpus-name membership set: a name that does not resolve
# INTO this confine can never bind (the generic MD-1 confine-containment check in `bind`
# refuses it), so no separate membership list is needed. DERIVED from the one canonical set
# (`hooks/record_lesson_load.LESSON_CORPORA`, the author-side superset of RUNTIME_LESSON_CORPORA)
# so the shipped-corpus roster has a single source of truth; sorted for a deterministic order
# (containment is order-independent).
SHIPPED_LESSON_CORPORA: tuple[str, ...] = tuple(sorted(_LESSON_CORPORA))


def _corpus_spellings(corpus_dir: Path) -> str:
    rel = f"defender/{corpus_dir.name}"
    return "|".join(re.escape(s) for s in (rel, str(corpus_dir)))


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


@dataclass(frozen=True)
class ForwardCheckConfig:
    """The curator's tool-config slot payload (#691 M4): the five per-spawn forward-check
    inputs, collapsed off `CuratorDeps`' bare fields and onto the base `AgentDeps.tool_config`
    slot. Carries NO corpus (F51) — `corpus_dir` stays derived off the retained `roots` (M6),
    read directly off `deps`, never duplicated into this config."""

    check: ForwardCheck
    runs_dir: Path
    pending: Path
    queued_ids: frozenset[str]
    run_verify: Callable[..., str] = _run_verify_pydantic


@dataclass(frozen=True)
class CuratorDeps(AgentDeps):

    role: ClassVar[AgentRole] = AgentRole.CORPUS_AUTHOR

    @property
    def corpus_dir(self) -> Path:
        assert self.roots is not None
        assert self.roots.corpus_dir is not None
        return self.roots.corpus_dir

    def _forward_check_config(self) -> ForwardCheckConfig:
        if self.tool_config is None:
            raise ModelRetry(
                "forward_check: this curator spawn's tool_config is not set — bind() leaves it "
                "unset by default (M5); attach a ForwardCheckConfig before calling forward_check."
            )
        return self.tool_config

    @property
    def check(self) -> ForwardCheck:
        return self._forward_check_config().check

    @property
    def runs_dir(self) -> Path:
        return self._forward_check_config().runs_dir

    @property
    def pending(self) -> Path:
        return self._forward_check_config().pending

    @property
    def queued_ids(self) -> frozenset[str]:
        return self._forward_check_config().queued_ids

    @property
    def run_verify(self) -> Callable[..., str]:
        return self._forward_check_config().run_verify

    @classmethod
    def for_run(
        cls, run_dir: Path, repo_root: Path, corpus_dir: Path,
        *, cfg: ForwardCheckConfig, box: Any, salt: str | None = None,
    ) -> CuratorDeps:
        """A thin wrapper over `bind` (M9): resolves the corpus NAME off `corpus_dir`'s own
        basename and binds through the one seam, then attaches the forward-check config into
        the base `tool_config` slot. `corpus_dir` stays the caller's contract (unchanged from
        before #691) — only its *derivation* moved onto `bind`. `box` is REQUIRED (R1): a
        loud TypeError at construction beats a silent inert default that re-deads the curator's
        bash lane (#665 F1).

        Since #713 the `ForwardCheckConfig` arrives already built: `run_curator_stage` owns
        its construction, so the five forward-check fields stop being re-declared here."""
        defender_dir = repo_root / "defender"
        scope = RunScope(
            corpus_name=corpus_dir.name,
            read_confine=tuple(
                (defender_dir / name).resolve() for name in SHIPPED_LESSON_CORPORA
            ),
        )
        deps = bind(
            CORPUS_AUTHOR_DEF, run_dir, scope=scope, defender_dir=defender_dir,
            box=box,
        )
        assert isinstance(deps, CuratorDeps)
        return replace(deps, tool_config=cfg)


CORPUS_AUTHOR_DEF = AgentDefinition(
    role=AgentRole.CORPUS_AUTHOR,
    model=config.author_model,
    effort=config.author_effort(),
    tools=ToolSet(bash=True, write=True, forward_check=True, lesson_read=True),
    bash_shapes=(_corpus_author_grants,),
    write_shapes=(_corpus_author_write_shapes,),
    deps_cls=CuratorDeps,
    requires_confine=True,
    requires_explicit_tree=True,
    anchors_on_tree=True,
    requires_corpus=True,
    # R4/O6: the read VIEW spans the three-corpus confine while the shell (cat) VIEW stays at one
    # corpus — a deliberate divergence, so read_allow is forced empty rather than derived from the
    # cat grant's own-corpus scope (the read↔bash parity every OTHER role keeps).
    read_allow_override=PathShapes(),
    deny_reason=_CORPUS_AUTHOR_DENY_REASON,
)


def _run_curator_pydantic(
    wiring: StageWiring,
    ctx: StageContext,
    *,
    corpus_dir: Path,
    cfg: ForwardCheckConfig,
    make_model: MakeModel = providers.build_for_effort,
) -> str:
    """Both limits vary per spawn here, so the caller owns the whole context — this is one
    of the two stages where the transport really was threaded through three layers (#713)."""
    # `repo_root` is optional on the SHARED context (the pure-prediction stages bind off the
    # run dir alone) but required here: the corpus confine is resolved off the repo tree.
    # A raise, not an assert — `python -O` strips asserts, and the fallout would be a
    # `NoneType / str` TypeError several frames down inside `bind`.
    repo_root = ctx.repo_root
    if repo_root is None:
        raise ValueError(
            "curator stage needs ctx.repo_root: it binds a corpus off the repo tree"
        )
    deps = CuratorDeps.for_run(
        ctx.learning_run_dir, repo_root, corpus_dir,
        cfg=cfg, salt=ctx.salt, box=ctx.box,
    )
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
    cfg: ForwardCheckConfig,
    log: Callable[[str], None],
    source_key: Callable[..., object] = config.source_first_party_key,
    run_author: Callable[..., str] = _run_curator_pydantic,
) -> dict:
    """`wiring` is the spawn's prompt/model/effort/trace/label/batch, `ctx` its roots, user
    prompt and two env-backed limits; `cfg` is the forward-check group, built by the caller
    since #713 rather than five parameters re-declared all the way down to
    `CuratorDeps.for_run`.

    Every model/effort/limit/timeout knob is caller-supplied with no default here: each is
    env-backed and differs per corpus, so a default evaluated at import would freeze it
    (#717)."""
    # ONE batch identity, read off the wiring that already derived `trace_name` and `label`
    # from it. Taking it a second time as a parameter let a caller log `spawn curator B`,
    # raise `AuthorError("curator (B) ...")` and write `A.<pid>.trace.jsonl` — three artifacts
    # naming two batches, with nothing asserting they agree. A raise, not an assert: `python
    # -O` strips asserts, and `for_batch` is the only builder that sets the field.
    batch_id = wiring.batch_id
    if batch_id is None:
        raise ValueError(
            "curator stage needs a wiring built by StageWiring.for_batch: its log line and "
            "its AuthorErrors name the same batch its trace file is keyed on"
        )
    log(
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
    if cfg.check.prompt_path is not None and (
        providers.provider_for(config.verifier_model()).api_key_var
        != providers.provider_for(wiring.model).api_key_var
    ):
        source_key(config.verifier_model(), label=f"verify:{cfg.check.error_prefix}")
    try:
        text = run_author(
            wiring,
            replace(ctx, user=user_prompt, salt=stage_salt),
            corpus_dir=corpus_dir, cfg=cfg,
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
