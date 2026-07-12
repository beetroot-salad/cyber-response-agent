"""The four lesson curators on the in-process PydanticAI engine — a writer-stage transport.

Mirror of ``leads/lead_author_engine.py``: the curators' specifics (one ``CuratorDeps``
identity + a per-spawn ``AgentPolicy`` that confines the corpus WRITERS to ``<corpus>/**.md``
and grants a flat corpus-anchored reader/rm bash lane) live here, and the generic in-process
transport they share with the five other in-process stages lives in
``pipeline/_pydantic_stage.py``.

ONE engine serves all FOUR curators — findings (A → ``defender/lessons/``), actor-tradecraft
(B → ``defender/lessons-actor/``), env-benign (C) and env-adversarial (D → the shared
``defender/lessons-environment/``) — the way ``verify_forward``'s one engine serves both
forward-checks: the per-curator variation (its prompt, corpus, bound forward-check, batch id,
trace anchor, model/effort) is threaded through ``run_curator_stage``'s args, not a second
engine module. Each curator's invoke seam (``lessons.run.invoke_agent`` for A,
``curator.invoke_curator_agent`` for B/C/D) delegates here.

Two divergences from the lead author:

  - ``run_curator_stage`` returns the PARSED ``AUTHOR_RESULT`` dict, not an int rc — the marker
    parse (``extract_marked_result``) lives in this wrapper, on the returned final text. A per-run
    ``RunUnprocessable`` (timeout / usage-limit / model error /
    empty final) OR an unparseable marker maps to ``AuthorError`` (→ the envelope's rc 2, the
    single-run quarantine the drain retries); a systemic ``FatalConfigError`` / ``StageAbort``
    PROPAGATES (exit 2, never wrapped) — the same systemic-vs-per-run split ``run_stage`` and the
    lead author make. There is no rc-124 lane (the invoke seam returns a dict, not an rc).
  - ``require_output=True`` (the OPPOSITE of the lead author's ``False``): the curator's final
    text carries the load-bearing ``AUTHOR_RESULT:`` marker, so an empty final (GLM spent its
    budget in the thinking channel) is ``RunUnprocessable`` BEFORE any parse — never a silent
    empty commit.

The per-spawn policy is built DIRECTLY (``CuratorDeps.for_run`` → ``_corpus_author_policy``), not
via ``compile_policy``/``bind`` (whose ``write_allow`` roots at ``run_dir``): it needs the
worktree's ``corpus_dir``, exactly like ``LeadAuthorDeps.for_run``.

Imported LAZILY by the invoke seams (pulls the pydantic-ai graph via ``_pydantic_stage``) — only
when a curator actually spawns, never at loop import; ``agents.AGENTS`` (already heavy) imports
``CORPUS_AUTHOR_DEF`` at top for the role→toolset lookup.
"""
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


# ---------------------------------------------------------------------------
# AUTHOR_RESULT marker extraction (relocated here from the retired claude -p
# transport — this wrapper is its sole consumer; see run_curator_stage below).
# ---------------------------------------------------------------------------


def extract_marked_result(text: str, marker: str) -> str | None:
    """Return the JSON object body following the last ``marker`` occurrence.

    Walks forward from the opening brace counting balanced braces while
    respecting JSON string quoting; this handles nested objects/arrays
    that a non-greedy regex would truncate. Returns ``None`` if no
    marker or no balanced object is found. ``marker`` is treated as a
    literal prefix; trailing whitespace before ``{`` is tolerated.
    """
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

# One path segment that is NOT a `..` traversal: `..` as a WHOLE segment (followed by `/`, a
# token-boundary space, or end-of-token) is rejected TEXTUALLY. The `rm` grant needs this because
# `rm` unlinks the LINK, not the target — `resolve()` is the wrong operand model for it, so its
# path stays in the PATTERN (`pins_path`) and the traversal must be rejected literally there.
_SEG = r"(?!\.\.(?:/| |$))[^/ ]+"

# PROMPT SURFACE: names only programs this lane grants (`cat`, `grep`, `rm`). The corpus listing
# (`ls`) is gone — the #574 corpus manifest replaces it — and so is grep's file operand, so the
# reason must not teach either.
_CORPUS_AUTHOR_DENY_REASON = (
    "Blocked: the lesson curator writes and edits .md lessons under its OWN corpus only. It reads the "
    "corpus (cat, or `cat <file> | grep <pattern>`), takes its inventory from the corpus manifest, "
    "and rm's a single draft it promotes or discards — no writes outside the corpus, no other "
    "corpus, no arbitrary shell. Forward-check with the forward_check tool."
)


def _corpus_spellings(corpus_dir: Path) -> str:
    """The `re.escape`-d alternation of the corpus's two bash-operand spellings: the fixed
    repo-relative ``defender/<name>`` (the agent runs with cwd=worktree and types repo-relative
    paths) and the worktree-absolute ``<wt>/defender/<name>``. Derived from ``defender/<name>``
    rather than ``corpus_dir.relative_to(repo_root)`` because ``repo_root`` is the throwaway
    worktree — a corpus always sits directly under ``<repo>/defender/``."""
    rel = f"defender/{corpus_dir.name}"
    return "|".join(re.escape(s) for s in (rel, str(corpus_dir)))


def _rm_grant(corpus_dir: Path) -> Grant:
    """The curator's ONE mutating bash grant: ``rm`` of a SINGLE path under its own corpus (promote
    = write the lesson + rm the draft; discard = rm the draft). ``pins_path=True``, the same R1
    exemption the lead author's ``rm`` carries and for the same reason: ``rm`` acts on the LINK, so
    resolving the operand would FALSELY DENY a legitimate symlinked draft and would check the wrong
    inode besides. The traversal guard is therefore textual, in the pattern."""
    return Grant(
        program="rm",
        pattern=re.compile(rf"^rm (?:{_corpus_spellings(corpus_dir)})(?:/{_SEG})+$"),
        pins_path=True,
    )


def _corpus_author_grants(corpus_dir: Path) -> tuple[Grant, ...]:
    """The curator's bash lane, folded onto the SAME model as every other agent (#575): `cat` is
    the sole opener, scoped to its own corpus at ``resolve()`` time, and `grep` is a stdin-only
    pipe stage (`cat <file> | grep <pattern>`).

    This lane is the one with NO secret denylist and NO ``compile_policy`` (it is built per-spawn
    from the worktree ``corpus_dir``), which is exactly why it must not keep a private copy of the
    viewer grammar: its `_LS_FLAG` had already drifted from the runtime lane's (it still admitted
    `-R` after #579 dropped it there), and a private grammar is a second place for the next
    fail-open to hide. It now compiles the shared ``program_shape``s and its policy passes the same
    program-table check as every other agent's.

    ``ls`` is gone: the corpus manifest (#574) is the inventory, and it needs no gate at all."""
    corpus = corpus_dir.resolve()
    scope = PathShapes([under(corpus, TREE)])
    return (
        _rm_grant(corpus_dir),
        Grant(program="cat", pattern=program_shape("cat"), scope=scope),
        Grant(program="grep", pattern=program_shape("grep")),
    )


def _corpus_author_policy(corpus_dir: Path) -> AgentPolicy:
    """The curator's declarative gate policy, built PER-SPAWN from the worktree ``corpus_dir``.

    ``write_allow`` is a single flat pattern admitting ``<corpus>/**.md`` ONLY (the corpus is
    ``.md``): the file writers may author a lesson ``.md`` under their own corpus and NOTHING else
    — not a sibling corpus, not the run dir (a flat allowlist, NOT a run-dir root, so ``run_dir`` /
    ``_pending`` stay unwritable). ``bash_allow`` is the corpus-scoped ``cat``/``grep``/``rm`` lane
    above; it admits NO python interpreter — the forward-check is the in-process ``forward_check``
    tool (#558), because an allowlist that pins a program token cannot constrain the operands that
    program then acts on (#565).

    ``read_allow`` is deliberately EMPTY while the ``cat`` grant carries a scope: the curator reads
    sibling corpora and the schema docs through ``lesson_read`` (root-only under ``defender_dir``),
    but may only ``cat`` its OWN corpus. Read ⊋ bash here — the two surfaces are different sets on
    purpose, which is why the def-compiled identity (``read_allow_of``) is not used for this lane.

    Built DIRECTLY (not ``compile_policy``/``bind``, whose ``write_allow`` roots at run_dir) because
    it needs the worktree's ``corpus_dir`` — and ``AgentPolicy.__post_init__`` still runs the
    program-table check on it, so the one lane that skips ``compile_policy`` cannot skip the check
    that makes an untabled (=ungated) program impossible."""
    return AgentPolicy(
        bash_allow=_corpus_author_grants(corpus_dir),
        read_roots=(),
        read_confine=(),
        write_allow=(build_write_allow(corpus_dir, suffix=".md"),),
        deny_reason=_CORPUS_AUTHOR_DENY_REASON,
    )


@dataclass(frozen=True)
class CuratorDeps(AgentDeps):
    """The curator's per-spawn deps — an ``AgentDeps`` with a WRITER ``policy``, plus everything
    its ``forward_check`` tool reads. ``role`` is a CORPUS_AUTHOR identity label — the gate keys
    on ``policy``, not this.

    The four checks vary by DEPS, never by tool argument: ``check`` is bound here at spawn, so
    the tool exposes no script operand the model could point at a program of its choosing. The
    three roots are fields for the same reason ``corpus_dir`` is — a module constant frozen at
    import reads the main checkout, while the curator edits a throwaway worktree.
    """

    role: ClassVar[AgentRole] = AgentRole.CORPUS_AUTHOR

    # kw_only: the base's `policy` is kw_only, so a positional field after it is a TypeError.
    corpus_dir: Path = field(kw_only=True)
    check: ForwardCheck = field(kw_only=True)
    runs_dir: Path = field(kw_only=True)
    pending: Path = field(kw_only=True)
    # The source ids this batch actually queued. The tool confines the model-supplied `source_id`
    # to this set, so a pair naming an unrelated case cannot load its transcript into the metered
    # prompt or the trace.
    queued_ids: frozenset[str] = field(kw_only=True)
    # The verify transport. A pydantic-ai tool is handed only `(ctx, args)`, so a per-call deps
    # field is the ONLY seam a fake can enter through without monkeypatching a module global.
    run_verify: Callable[..., str] = field(kw_only=True)

    @classmethod
    def for_run(  # noqa: PLR0913 — the spawn's roots + its bound check + the transport seam
        cls, run_dir: Path, repo_root: Path, corpus_dir: Path,
        *, check: ForwardCheck, runs_dir: Path, pending: Path,
        queued_ids: frozenset[str], run_verify: Callable[..., str] = _run_verify_pydantic,
    ) -> CuratorDeps:
        """The curator's front door. ``corpus_dir`` and ``check`` are REQUIRED — a CORPUS_AUTHOR
        cannot be constructed without naming the corpus that confines both its writes and its
        forward-check lesson operand, nor without naming which check it runs (the footgun-A
        safe-by-construction regression: no run-dir-rooted / whole-defender_dir ``write_allow``,
        and no unbound check). Overrides ``_for_run``'s ``defender_dir`` default: the drain edits
        a throwaway git WORKTREE, so the gate resolves reads/writes against ``repo_root/defender``
        (else every worktree write is denied against the main checkout). ``run_dir`` is only the
        trace anchor + a read root."""
        defender_dir = repo_root / "defender"
        return cls._for_run(
            run_dir,
            _corpus_author_policy(corpus_dir),
            defender_dir=defender_dir,
            corpus_dir=corpus_dir,
            check=check,
            runs_dir=runs_dir,
            pending=pending,
            queued_ids=queued_ids,
            run_verify=run_verify,
        )


# The curator's AgentDefinition (#538). Like the lead author it is a WRITER, so its ToolSet grants
# the file writers (write=True → write_file/edit_file) on top of the scoped ``lesson_read`` (#559 —
# replaces the generic ``read``: read_file with a body/full part mode) + the corpus-anchored bash
# lane. ``model``/``effort`` are the declarative stage defaults; each spawn re-binds its own
# per-curator model/effort in ``build_stage_agent``. The real per-spawn policy (the corpus-scoped
# ``write_allow`` + bash matchers) is built by ``CuratorDeps.for_run`` / ``_corpus_author_policy`` —
# NOT ``compile_policy``/``bind`` — since it needs the worktree's ``corpus_dir``; this def is only
# the toolset source in ``AGENTS`` (the curator is not bound).
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
    """Run one curator spawn in-process and return the model's final text VERBATIM (the wrapper —
    not this — parses the AUTHOR_RESULT marker out of it). Builds the writer ``CuratorDeps`` (worktree
    ``defender_dir`` + corpus ``write_allow`` + the flat bash lane) and delegates to the shared
    ``run_stage`` with ``require_output=True`` (the curator's final text carries the load-bearing
    marker, so an empty final is ``RunUnprocessable``, unlike the lead author's ``False``). The file
    writers (and the ``forward_check`` tool) are registered from ``CORPUS_AUTHOR_DEF``'s ToolSet by
    role in ``build_stage_agent``."""
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
    """Source the metered Fireworks key, run the in-process curator spawn on GLM, and return the
    PARSED ``AUTHOR_RESULT`` dict the transaction envelope consumes (``committed`` / ``consumed_skip``
    / ``commit_message``, + curator A's ``held_forward_bad``). The whole path all four invoke seams
    share, so ``lessons.run.invoke_agent`` / ``curator.invoke_curator_agent`` stay thin.

    Sources the key here (not the transport) because the drain worktree carries only the ambient
    credential (or none); ``source_first_party_key`` re-reads the metered key from ``.env`` — reaching
    the MAIN checkout's ``.env`` even from the throwaway worktree. A CONFIG fault (no key / unroutable
    model / cross-provider effort) raises ``FatalConfigError`` and is left to PROPAGATE (systemic,
    exit 2), never wrapped into the per-run rc-2 lane.

    Fault mapping: a per-run ``RunUnprocessable`` (timeout / usage-limit / model error / empty final)
    OR an unparseable / missing ``AUTHOR_RESULT`` marker → ``AuthorError`` (the envelope's rc 2, the
    single-run quarantine the drain retries; the DLQ rides on top of that in the curator envelope). A
    systemic ``FatalConfigError`` / ``StageAbort`` from ``source_key`` or ``run_stage``'s build is NOT
    caught here — it propagates as the systemic exit-2 lane.

    ``source_key`` / ``run_author`` / ``run_verify`` are DI seams that OWN their production defaults
    (the lead author's shape): production calls with none; tests inject fakes to exercise the
    orchestration (key ordering + fault mapping + the relocated marker parse) without a metered key or
    the pydantic-ai graph — so no ``monkeypatch`` of module globals is needed. ``run_verify`` rides all
    the way onto the deps, since a pydantic-ai tool is handed only ``(ctx, args)``."""
    log(f"spawn curator {batch_id} in-process (model={model}, effort={effort}, timeout={timeout}s)")
    # ONCE per spawn, for the whole batch: the nested forward-checks call the verify transport
    # directly and source no key of their own (the retired CLI wrapper re-read `.env` per check).
    source_key(model, label="curator")  # FatalConfigError PROPAGATES (systemic)
    # The curator's key covers the nested checks only while they share a provider. It is one
    # `.env` var per provider, and `LEARNING_VERIFIER_MODEL` is documented as routing anywhere
    # `providers.provider_for` does (`claude-haiku-4-5`, to A/B the pre-migration gate) — so a
    # cross-provider verifier needs its own key sourced, else every check dies unauthenticated
    # and the gate silently degrades to all-ERROR. Still once per SPAWN, never per check; and
    # only for a model-backed check, since ENV_CHECK runs no model and must not acquire a
    # phantom key dependency.
    if check.prompt_path is not None and (
        providers.provider_for(config.VERIFIER_MODEL).api_key_var
        != providers.provider_for(model).api_key_var
    ):
        source_key(config.VERIFIER_MODEL, label=f"verify:{check.error_prefix}")
    # Anchor the trace (batch_id + pid) BEFORE the spawn so a partial failure still leaves a
    # complete, per-spawn-distinct trace (RequestLogger opens truncate → two spawns into one drain
    # dir would clobber a shared name). The nested checks trace into the SOURCE bundle, a different
    # directory, keyed on a per-check counter — in-process the pid no longer varies between them.
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
        # A per-run authoring fault only — the envelope maps AuthorError to rc 2 (queue intact,
        # retry / DLQ). StageAbort / FatalConfigError are NOT caught here (systemic exit-2 lane).
        raise AuthorError(f"curator ({batch_id}) did not complete: {e}") from e
    # Parse AUTHOR_RESULT out of the returned text: balanced-brace walk from the LAST marker; a
    # missing marker or invalid JSON is an authoring fault (never return the raw text where the
    # envelope expects a dict).
    body = extract_marked_result(text, "AUTHOR_RESULT:")
    if body is None:
        if not text.strip():
            # An empty final is caught as RunUnprocessable by the real transport's
            # ``require_output=True`` BEFORE it can reach this parse, so production never lands here;
            # a content-less final has no marker to parse and no partial commit to guard, so return an
            # empty result rather than a spurious raise (the trace-anchor tests drive run_author → "").
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
