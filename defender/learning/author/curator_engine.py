"""The four lesson curators on the in-process PydanticAI engine — a writer-stage transport.

Mirror of ``leads/lead_author_engine.py``: the curators' specifics (one ``CuratorDeps``
identity + a per-spawn ``AgentPolicy`` that confines the corpus WRITERS to ``<corpus>/**.md``
and grants a flat corpus-anchored reader/forward-check/rm bash lane) live here, and the
generic in-process transport they share with the five other in-process stages lives in
``pipeline/_pydantic_stage.py``.

ONE engine serves all FOUR curators — findings (A → ``defender/lessons/``), actor-tradecraft
(B → ``defender/lessons-actor/``), env-benign (C) and env-adversarial (D → the shared
``defender/lessons-environment/``) — the way ``verify_forward``'s one engine serves both
forward-checks: the per-curator variation (its prompt, corpus, verifier scripts, batch id,
trace anchor, model/effort) is threaded through ``run_curator_stage``'s args, not a second
engine module. Each curator's invoke seam (``lessons.run.invoke_agent`` for A,
``curator.invoke_curator_agent`` for B/C/D) delegates here.

Two divergences from the lead author:

  - ``run_curator_stage`` returns the PARSED ``AUTHOR_RESULT`` dict, not an int rc — the
    marker parse RELOCATED out of the retired ``claude -p`` transport (``runner.invoke_claude_print``)
    into this wrapper. A per-run ``RunUnprocessable`` (timeout / usage-limit / model error /
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
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from defender._paths import DefenderPaths
from defender.learning.author import runner as _runner
from defender.learning.author import shared as _shared
from defender.learning.core import config
from defender.learning.core.config import RunUnprocessable
from defender.learning.pipeline._pydantic_stage import run_stage
from defender.runtime import providers
from defender.runtime.agent_definition import AgentDefinition, BashGrammar, ToolSet
from defender.runtime.agent_role import AgentRole
from defender.runtime.driver import MakeModel
from defender.runtime.permission import AgentPolicy, build_write_allow
from defender.runtime.tools import AgentDeps

AuthorError = _shared.AuthorError

# The verify_forward scripts' repo-relative offset (trailing slash), owned once by DefenderPaths. A
# curator's bash_allow admits ITS forward-check scripts by this repo-relative spelling (what the
# agent types, running with cwd=worktree) OR the worktree-absolute one — the repo-relative form is a
# FIXED offset rather than ``script.relative_to(repo_root)`` because a tmp batch worktree is NOT under
# the main-checkout REPO_ROOT (the reason the lead author's ``_rm_skills_pattern`` uses ``SKILLS_REL``).
_VERIFY_FORWARD_REL = DefenderPaths.verify_forward_dir_rel

# One path segment that is NOT a `..` traversal: `..` as a WHOLE segment (followed by `/`, a
# token-boundary space, or end-of-token) is rejected TEXTUALLY, since the bash lane never
# resolve()s (copied from the lead author's `_rm_skills_pattern` / policies._common._SEG). A real
# path operand carries no embedded space, so `[^/ ]+` matches exactly one dir/file name and a
# real space keeps a multi-path `rm a b` from matching as one long "segment".
_SEG = r"(?!\.\.(?:/| |$))[^/ ]+"

# Safe short-flag bundle for the corpus viewers — any letter EXCEPT lowercase `f`, the
# file-opening flag (`grep -f patternfile` would read an out-of-corpus file, and the operand
# gate can't see a second file the flag pulls in). Recursion (`-r`/`-R`) and `-l` stay in-corpus
# because the file/dir operand is corpus-anchored; there is no auto secret-denylist on this
# hand-built lane, so the anchored operand is the sole containment (bash lane: no resolve()).
_VIEW_FLAG = r"-[a-eg-zA-Z]+"

_CORPUS_AUTHOR_DENY_REASON = (
    "Blocked: the lesson curator writes/edits .md lessons under its OWN corpus only. It reads the "
    "corpus (ls/grep/cat), runs its pinned forward-check verifier, and rm's a single draft it "
    "promotes or discards — no writes outside the corpus, no other corpus, no arbitrary shell."
)


def _corpus_spellings(corpus_dir: Path) -> str:
    """The `re.escape`-d alternation of the corpus's two bash-operand spellings: the fixed
    repo-relative ``defender/<name>`` (the agent runs with cwd=worktree and types repo-relative
    paths) and the worktree-absolute ``<wt>/defender/<name>``. Derived from ``defender/<name>``
    rather than ``corpus_dir.relative_to(repo_root)`` for the same worktree reason as
    ``_VERIFY_FORWARD_REL`` — a corpus always sits directly under ``<repo>/defender/``."""
    rel = f"defender/{corpus_dir.name}"
    return "|".join(re.escape(s) for s in (rel, str(corpus_dir)))


def _corpus_file_operand(corpus_dir: Path) -> str:
    """A file UNDER the corpus (>=1 non-`..` segment): ``<corpus>/<seg>+``."""
    return rf"(?:{_corpus_spellings(corpus_dir)})(?:/{_SEG})+"


def _corpus_dir_operand(corpus_dir: Path) -> str:
    """The corpus itself OR a dir under it (for the `ls` operand), with an OPTIONAL trailing slash
    — the agent idiomatically types ``ls defender/lessons-actor/`` (a real GLM smoke did exactly
    that), so a dir operand admits the trailing ``/`` a file operand never carries."""
    return rf"(?:{_corpus_spellings(corpus_dir)})(?:/{_SEG})*/?"


def _viewer_patterns(corpus_dir: Path) -> tuple[re.Pattern[str], ...]:
    """The corpus-anchored ls/grep/cat reader lane — the in-process replacement for the absent
    Glob/Grep tools (the agent enumerates existing lessons to fold duplicates via bash). Every
    file/dir operand must TEXTUALLY sit under the spawn's OWN corpus (anti-`..`); there is no auto
    secret-denylist here, so the anchored operand is the sole containment."""
    f = _corpus_file_operand(corpus_dir)
    d = _corpus_dir_operand(corpus_dir)
    # A free-text grep search pattern (one token; may look like a path). The leading `(?!-)`
    # is load-bearing: without it this slot swallows any `-`-prefixed token, so a file-opening
    # option the `_VIEW_FLAG` `-f` exclusion is meant to block (`grep --file=<out-of-corpus>`,
    # `grep --exclude-from=…`, `grep -r -f <corpus-probe>`) would fall through here and grep
    # would OPEN an out-of-corpus file — the anchored operand is the sole containment on this
    # denylist-free lane, so the search token must not be a flag.
    pat = r"(?!-)[^ ]+"
    return (
        re.compile(rf"^cat(?: {_VIEW_FLAG})*(?: {f})+$"),
        re.compile(rf"^grep(?: {_VIEW_FLAG})*(?: {pat})(?: {f})+$"),
        re.compile(rf"^ls(?: {_VIEW_FLAG})*(?: {d})+$"),  # `+`: bare `ls` (=cwd recon) denied
    )


def _rm_pattern(corpus_dir: Path) -> re.Pattern[str]:
    """The curator's ONE mutating bash grant: ``rm`` of a SINGLE path under its own corpus
    (promote = write the lesson + rm the draft; discard = rm the draft). Anti-`..` textual (the
    bash lane does no resolve()), single path, no flags — the shape of the lead author's
    ``_rm_skills_pattern`` at the corpus root."""
    return re.compile(rf"^rm (?:{_corpus_spellings(corpus_dir)})(?:/{_SEG})+$")


def _verifier_pattern(script: Path) -> re.Pattern[str]:
    """Allow the curator's pinned forward-check: ``python[3] <script> <args…>`` whose script token
    is ``script`` — matched by its repo-relative spelling (``defender/learning/author/verify_forward/
    <name>.py``, what the agent types) OR its worktree-absolute one, both `re.escape`-d. The program
    is ``python3`` or any ``…/python3`` (the resolved venv interpreter the forward-check needs for
    pyyaml). The shape of the actor's ``_script_pattern``; the pattern can't constrain the script's
    internals, so the pinned verify_forward scripts MUST stay read-only over the corpus/run bundle."""
    rel = f"{_VERIFY_FORWARD_REL}{script.name}"  # _VERIFY_FORWARD_REL carries the trailing slash
    spellings = "|".join(re.escape(s) for s in (rel, str(script)))
    # `python3?(?:\.\d+)?` also admits a version-suffixed interpreter (`python3.11`): the prompt's
    # command uses ``resolve_verifier_python``, which falls back to ``sys.executable`` (commonly a
    # versioned launcher) when the `.venv/bin/python3` walk misses — a bare `python3?` would DENY
    # the curator's own mandated forward-check. Containment is the pinned SCRIPT token, not the
    # interpreter name, so broadening the interpreter half opens no new surface.
    return re.compile(rf"^(?:[^ ]*/)?python3?(?:\.\d+)? (?:{spellings})(?: .*)?$")


def _corpus_author_policy(
    corpus_dir: Path, verifier_scripts: tuple[Path, ...]
) -> AgentPolicy:
    """The curator's declarative gate policy, built PER-SPAWN from the worktree ``corpus_dir``.
    ``write_allow`` is a single flat pattern admitting ``<corpus>/**.md`` ONLY (the corpus is
    ``.md``): the file writers may author a lesson ``.md`` under their own corpus and NOTHING else —
    not a sibling corpus, not the run dir (a flat allowlist, NOT a run-dir root, so ``run_dir`` /
    ``_pending`` stay unwritable). ``bash_allow`` is the flat corpus-anchored lane: the curator's own
    forward-check verifier(s), a single-draft ``rm``, and the ls/grep/cat viewers (no Glob/Grep tool
    in-process). ``read_confine`` is empty — reads under ``defender_dir`` stay allowed by
    ``decide_read``'s defaults (it reads sibling lessons + the schema docs). Every other capability
    bit off. Built DIRECTLY (not ``compile_policy``/``bind``, whose ``write_allow`` roots at run_dir)
    because it needs the worktree's ``corpus_dir``."""
    return AgentPolicy(
        bash_allow=(
            *(_verifier_pattern(s) for s in verifier_scripts),
            _rm_pattern(corpus_dir),
            *_viewer_patterns(corpus_dir),
        ),
        jq_operand_gated=False,
        adapters=False,
        adapter_sql_pipe=False,
        raw_reads=False,
        read_roots=(),
        read_confine=(),
        write_allow=(build_write_allow(corpus_dir, suffix=".md"),),
        deny_reason=_CORPUS_AUTHOR_DENY_REASON,
    )


@dataclass(frozen=True)
class CuratorDeps(AgentDeps):
    """The curator's per-spawn deps — a plain ``AgentDeps`` shape with a WRITER ``policy``.
    ``role`` is a CORPUS_AUTHOR identity label — the gate keys on ``policy``, not this."""

    role: ClassVar[AgentRole] = AgentRole.CORPUS_AUTHOR

    @classmethod
    def for_run(
        cls, run_dir: Path, repo_root: Path,
        corpus_dir: Path, verifier_scripts: tuple[Path, ...],
        *, state_root: Path | None = None,
    ) -> CuratorDeps:
        """The curator's front door. ``corpus_dir`` + ``verifier_scripts`` are POSITIONAL and
        REQUIRED — a CORPUS_AUTHOR cannot be constructed without naming the corpus it writes (the
        footgun-A safe-by-construction regression: no run-dir-rooted / whole-defender_dir
        ``write_allow``). Overrides ``_for_run``'s ``defender_dir`` default: the drain edits a
        throwaway git WORKTREE, so the gate resolves reads/writes against ``repo_root/defender``
        (else every worktree write is denied against the main checkout). ``run_dir`` is only the
        trace anchor + a read root. ``state_root`` rides on the deps so the forward-check subprocess
        resolves the real source-case bundle off ``DEFENDER_LEARNING_STATE_DIR`` (#425) — set into
        the bash-tool env by ``run_common.run_env``, not a process-global mutation."""
        defender_dir = repo_root / "defender"
        return cls._for_run(
            run_dir,
            _corpus_author_policy(corpus_dir, verifier_scripts),
            defender_dir=defender_dir,
            state_root=state_root,
        )


# The curator's AgentDefinition (#538). Like the lead author it is a WRITER, so its ToolSet grants
# the file writers (write=True → write_file/edit_file) on top of read + the corpus-anchored bash
# lane. ``model``/``effort`` are the declarative stage defaults; each spawn re-binds its own
# per-curator model/effort in ``build_stage_agent``. The real per-spawn policy (the corpus-scoped
# ``write_allow`` + bash matchers) is built by ``CuratorDeps.for_run`` / ``_corpus_author_policy`` —
# NOT ``compile_policy``/``bind`` — since it needs the worktree's ``corpus_dir``; this def is only
# the toolset source in ``AGENTS`` (the curator is not bound).
CORPUS_AUTHOR_DEF = AgentDefinition(
    role=AgentRole.CORPUS_AUTHOR,
    model=lambda: config.AUTHOR_MODEL,
    effort=config.AUTHOR_EFFORT,
    tools=ToolSet(read=True, bash=BashGrammar(), write=True),
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
    verifier_scripts: tuple[Path, ...],
    state_root: Path | None = None,
    request_limit: int = config.AUTHOR_REQUEST_LIMIT,
    wall_clock_timeout: int = config.AUTHOR_TIMEOUT,
    make_model: MakeModel = providers.build_for_effort,
) -> str:
    """Run one curator spawn in-process and return the model's final text VERBATIM (the wrapper —
    not this — parses the AUTHOR_RESULT marker out of it). Builds the writer ``CuratorDeps`` (worktree
    ``defender_dir`` + corpus ``write_allow`` + the flat bash lane) and delegates to the shared
    ``run_stage`` with ``require_output=True`` (the curator's final text carries the load-bearing
    marker, so an empty final is ``RunUnprocessable``, unlike the lead author's ``False``). The file
    writers are registered from ``CORPUS_AUTHOR_DEF``'s ToolSet by role in ``build_stage_agent``."""
    deps = CuratorDeps.for_run(
        learning_run_dir, repo_root, corpus_dir, verifier_scripts, state_root=state_root,
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
    verifier_scripts: tuple[Path, ...],
    repo_root: Path,
    learning_run_dir: Path,
    log: Callable[[str], None],
    state_root: Path | None = None,
    model: str = config.AUTHOR_MODEL,
    effort: str | None = config.AUTHOR_EFFORT,
    request_limit: int = config.AUTHOR_REQUEST_LIMIT,
    timeout: int = config.AUTHOR_TIMEOUT,
    source_key: Callable[..., object] = config.source_first_party_key,
    run_author: Callable[..., str] = _run_curator_pydantic,
) -> dict:
    """Source the metered Fireworks key, run the in-process curator spawn on GLM, and return the
    PARSED ``AUTHOR_RESULT`` dict the transaction envelope consumes (``committed`` / ``consumed_skip``
    / ``commit_message``, + curator A's ``held_forward_bad``). The whole path all four invoke seams
    share, so ``lessons.run.invoke_agent`` / ``curator.invoke_curator_agent`` stay thin.

    Sources the key here (not the transport) because the drain strips every provider key from its env
    (``config.subscription_env``); ``source_first_party_key`` re-reads it from ``.env`` — reaching the
    MAIN checkout's ``.env`` even from the throwaway worktree. A CONFIG fault (no key / unroutable
    model / cross-provider effort) raises ``FatalConfigError`` and is left to PROPAGATE (systemic,
    exit 2), never wrapped into the per-run rc-2 lane.

    Fault mapping: a per-run ``RunUnprocessable`` (timeout / usage-limit / model error / empty final)
    OR an unparseable / missing ``AUTHOR_RESULT`` marker → ``AuthorError`` (the envelope's rc 2, the
    single-run quarantine the drain retries; the DLQ rides on top of that in the curator envelope). A
    systemic ``FatalConfigError`` / ``StageAbort`` from ``source_key`` or ``run_stage``'s build is NOT
    caught here — it propagates as the systemic exit-2 lane.

    ``source_key`` / ``run_author`` are DI seams that OWN their production defaults (the lead author's
    shape): production calls with neither; tests inject fakes to exercise the orchestration (key
    ordering + fault mapping + the relocated marker parse) without a metered key or the pydantic-ai
    graph — so no ``monkeypatch`` of module globals is needed."""
    log(f"spawn curator {batch_id} in-process (model={model}, effort={effort}, timeout={timeout}s)")
    source_key(model, label="curator")  # FatalConfigError PROPAGATES (systemic)
    # The shared state root rides on the curator deps (→ ``run_common.run_env`` sets
    # ``DEFENDER_LEARNING_STATE_DIR`` for the bash-tool subprocess), so a forward-check spawned in
    # the throwaway worktree resolves the REAL source-case bundle off it rather than the worktree's
    # empty ``runs/`` (#425 silent-revert). Threaded through the deps — the in-process twin of the
    # retired ``curator_agent_env`` env= — rather than mutating the process-global ``os.environ``.
    # Anchor the trace (batch_id + pid) BEFORE the spawn so a partial failure still leaves a
    # complete, per-spawn-distinct trace (RequestLogger opens truncate → two spawns into one drain
    # dir would clobber a shared name).
    trace_name = f"{batch_id}.{os.getpid()}.trace.jsonl"
    try:
        text = run_author(
            prompt_path=system_prompt_file, model=model, effort=effort,
            trace_name=trace_name, label=f"curator:{batch_id}", user=user_prompt,
            learning_run_dir=learning_run_dir, repo_root=repo_root,
            corpus_dir=corpus_dir, verifier_scripts=verifier_scripts,
            state_root=state_root,
            request_limit=request_limit, wall_clock_timeout=timeout,
        )
    except RunUnprocessable as e:
        # A per-run authoring fault only — the envelope maps AuthorError to rc 2 (queue intact,
        # retry / DLQ). StageAbort / FatalConfigError are NOT caught here (systemic exit-2 lane).
        raise AuthorError(f"curator ({batch_id}) did not complete: {e}") from e
    # The AUTHOR_RESULT parse relocated out of the retired claude -p transport into the wrapper:
    # balanced-brace walk from the LAST marker; a missing marker or invalid JSON is an authoring
    # fault (never return the raw text where the envelope expects a dict).
    body = _runner.extract_marked_result(text, "AUTHOR_RESULT:")
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
