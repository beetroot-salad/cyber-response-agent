"""The per-agent **AgentDefinition** — one source of truth for an agent's tools +
permissions + model/effort (#538).

Today "what can this agent do" is answered by two carriers with different
lifecycles: the build-time toolset (which tools get registered) and the runtime
``AgentPolicy`` (how each tool is gated). #538 collapses them into one declarative
``AgentDefinition`` that BOTH the build site (``driver.build_agent_core``) and the
permission gate read, and — the forcing function — lets the pure-prediction stages
(oracle + verify-forward) be genuinely **tool-free** (register nothing).

This module is the primitive layer:

  - ``AgentDefinition`` / ``ToolSet`` / ``BashGrammar`` — the declarative shape.
  - ``RunScope`` — the per-invocation carriage (judge comparison roots, actor
    confine + pinned scripts, benign-judge ticket cli).
  - ``resolve_roots`` → ``ResolvedRoots`` — folds a run + corpus names + scope into
    the resolved read roots.
  - ``compile_policy`` — projects a ``ToolSet`` + roots into the gate's ``AgentPolicy``:
    the reader ``bash_allow`` is compiled from the grammar's declared viewer/shim contents
    and the read-tool ``read_shapes`` filename filter from the def's shape-builders (#545 —
    read↔bash parity, one grammar source), so ``bind``'s policy is the production end-state,
    not a step-one characterization.
  - ``bind`` — the single deps + policy resolution seam for all seven roles:
    ``resolve_roots`` → ``compile_policy`` → the role's ``AgentDeps`` subtype, carrying the
    run's salt (MAIN/GATHER keep the persisted trust token; the stages mint a fresh one) and
    — for the lead-author writer — the worktree ``repo_root`` its write scope anchors on.
  - ``build_registry`` — the guarded collector behind ``agents.AGENTS``.

Kept LIGHT on purpose: it imports only the permission gate types + the repo-layout
primitive, never ``pydantic_ai`` — so ``driver`` can define MAIN/GATHER defs off it
without pulling the learning graph. The one cross-layer reach (``bind`` returning the
learning stages' ``AgentDeps`` subtypes, ``compile_policy`` reusing the judge/actor
policy builders) is done with LAZY, function-body imports (the ``bash.policy_for``
idiom): no module-load cycle, and it only fires for those shapes.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from defender._paths import PATHS

from .agent_role import AgentRole
from .permission import AgentPolicy, build_write_allow
from .permission.policies._common import reader_patterns_for

if TYPE_CHECKING:
    from .tools import AgentDeps

# The fall-through deny shown to the model when no field carries a more specific
# reason. Every real agent def sets its own (main/gather/judge/actor/oracle/verify
# reasons live with their policies); this is only the bare-``AgentDefinition``
# default a shape test constructs.
_DEFAULT_DENY_REASON = (
    "Blocked: this command is not permitted for this agent (its declared "
    "capabilities only)."
)


# ── Declarative shape ────────────────────────────────────────────────────────

@dataclass(frozen=True)
class BashGrammar:
    """STATIC declaration of an agent's bash program grammar — which programs it may
    run and which structural routes are open. ``bind`` compiles it against the run's
    roots into the gate's anchored ``bash_allow`` (step one delegates main/gather to
    ``reader_patterns``, the judge/actor to their pinned builders).

      - ``shims`` / ``viewers`` — the reader-lane program set (the ``defender-*`` shims
        + the read-only viewers). Non-empty ⇒ this is a main/gather reader agent.
      - ``adapters`` — may invoke a data-source adapter (captured transparently).
      - ``adapter_sql_pipe`` — may run ``adapter --raw | defender-sql '<SQL>'``.
      - ``jq_operand_gated`` — the judge's ``jq``-only lane (file operands path-gated
        to the read roots)."""

    shims: tuple[str, ...] = ()
    viewers: tuple[str, ...] = ()
    adapters: bool = False
    adapter_sql_pipe: bool = False
    jq_operand_gated: bool = False


@dataclass(frozen=True)
class ToolSet:
    """An agent's tool PRESENCE (+ static bash capability). The read-only / no-tool
    safe default is every field off. ``bash=None`` UNREGISTERS the bash tool;
    ``bash=BashGrammar()`` (present but empty) registers it — absence vs present-but-
    empty are observably distinct."""

    read: bool = False
    bash: BashGrammar | None = None
    write: bool = False


@dataclass(frozen=True)
class AgentDefinition:
    """The single per-agent source of truth. ``model`` is a zero-arg THUNK (late env
    resolution, so a ``--model`` / ``$DEFENDER_MODEL`` override is honored at build,
    not frozen at import); ``effort`` is the static reasoning knob (``None`` omits it).
    ``tools`` drives registration; ``corpus_dirs`` + ``read_shapes`` + ``deny_reason``
    drive the gate via ``compile_policy``. Frozen, so ``bind``/``build`` can't corrupt a
    shared definition.

    ``read_shapes`` is a tuple of per-run shape-builders ``(run_dir, defender_dir) ->
    tuple[re.Pattern]`` (#545 — decision 3): ``compile_policy`` resolves each against the run's
    roots into the read-tool filename filter ``decide_read`` enforces. The reader defs carry
    ``reader_read_shapes`` so the read tool admits exactly the filename set the bash ``cat`` lane
    does (one grammar source); empty (every non-reader stage) leaves the read gate root-only."""

    role: AgentRole
    model: Callable[[], str]
    effort: str | None
    tools: ToolSet = ToolSet()
    corpus_dirs: tuple[str, ...] = ()
    read_shapes: tuple[Callable[[Path, Path], tuple[Any, ...]], ...] = ()
    deny_reason: str = _DEFAULT_DENY_REASON


# ── Per-invocation carriage + resolved roots ─────────────────────────────────

@dataclass(frozen=True)
class RunScope:
    """The per-invocation inputs a static ``AgentDefinition`` cannot carry — the
    superset of the judge's ``_ToolScope`` and the actor's ``_ActorScope``. All default
    empty (the runtime main/gather agents pass none):

      - ``add_dirs`` — judge comparison + gather_raw roots → the policy's ``read_roots``.
      - ``read_confine`` — actor gray-box confine (REPLACES the ``defender_dir`` base).
      - ``scripts`` — actor pinned lesson scripts → one ``bash_allow`` pattern each.
      - ``ticket_cli`` — the benign judge's pinned closed-ticket read."""

    add_dirs: tuple[Path, ...] = ()
    read_confine: tuple[Path, ...] = ()
    scripts: tuple[Path, ...] = ()
    ticket_cli: tuple[str, Path] | None = None


# One shared frozen default, anchored in ``bind``'s signature (the endorsed
# ``repo_root: Path = REPO_ROOT`` shape — no in-body re-defaulting, no B008
# call-in-default).
_DEFAULT_SCOPE = RunScope()


@dataclass(frozen=True)
class ResolvedRoots:
    """The output of ``resolve_roots`` — a run-anchored view ``compile_policy`` projects
    into an ``AgentPolicy``. ``run_dir``/``defender_dir`` anchor the reader allowlist;
    ``corpus_roots`` are the resolved corpus absolutes; the remaining fields are the
    scope's per-invocation inputs, run-folded."""

    run_dir: Path
    defender_dir: Path
    corpus_roots: tuple[Path, ...]
    read_roots: tuple[Path, ...]
    read_confine: tuple[Path, ...]
    scripts: tuple[Path, ...]
    ticket_cli: tuple[str, Path] | None


def _resolve_corpus_dir(name: str) -> Path:
    """Resolve one relative corpus name to its absolute under ``defender_dir``. FAILS
    LOUD (``ValueError`` naming the offending ``corpus`` entry) on a ``..`` segment or an
    absolute path — the path-traversal defense on this confinement primitive; never a
    silent drop/normalize (the roots are baked into the anchored bash allowlist, so a
    traversal here would widen reads)."""
    p = Path(name)
    if p.is_absolute() or ".." in p.parts:
        raise ValueError(
            f"corpus dir {name!r} must be a clean relative name under defender_dir "
            "(no '..' segment, not absolute)"
        )
    return PATHS.defender_dir / name


def resolve_roots(
    run_dir: Path, corpus_dirs: tuple[str, ...], scope: RunScope
) -> ResolvedRoots:
    """Fold a run + its corpus names + a ``RunScope`` into ``ResolvedRoots``. Per-run
    (keyed on ``run_dir``, no cache) so two runs get distinct roots — no cross-run bleed
    via a corpus-only cache key (the #497/#534 hazard). Corpus names resolve to
    absolutes under ``defender_dir`` (traversal-guarded)."""
    corpus_roots = tuple(_resolve_corpus_dir(name) for name in corpus_dirs)
    return ResolvedRoots(
        run_dir=run_dir,
        defender_dir=PATHS.defender_dir,
        corpus_roots=corpus_roots,
        read_roots=tuple(scope.add_dirs),
        read_confine=tuple(scope.read_confine),
        scripts=tuple(scope.scripts),
        ticket_cli=scope.ticket_cli,
    )


# ── ToolSet → AgentPolicy ────────────────────────────────────────────────────

def _bash_allow(bash: BashGrammar, roots: ResolvedRoots) -> tuple[Any, ...]:
    """Compile a ``BashGrammar`` + roots into the gate's anchored ``bash_allow`` tuple:

      - a reader agent (``viewers``/``shims`` present, main/gather) → the anchored per-run
        reader lane built from the grammar's DECLARED viewers/shims CONTENTS (#545 — a
        tighter ``BashGrammar.viewers`` compiles a tighter lane, so the contents are
        load-bearing, not merely their non-emptiness); the reader defs declare the full
        set, so their lane equals the kept ``reader_patterns`` / ``policy_for`` API;
      - the judge (``jq_operand_gated``) → its pinned ``jq`` (+ benign ticket) patterns;
      - the actor (``scope.scripts``) → one anchored ``python3 <script>`` pattern each.

    The judge/actor patterns are REUSED from their authoritative policy builders (via
    a lazy import — the same cross-layer reach ``bind`` already makes for the deps
    subtypes) so parity is guaranteed with zero regex duplication/drift."""
    patterns: list[Any] = []
    if bash.viewers or bash.shims:
        patterns.extend(reader_patterns_for(
            roots.run_dir, roots.defender_dir,
            frozenset(bash.viewers), frozenset(bash.shims),
        ))
    if bash.jq_operand_gated:
        from defender.learning.pipeline.judge.engine_pydantic import _judge_policy
        patterns.extend(_judge_policy(roots.read_roots, roots.ticket_cli).bash_allow)
    if roots.scripts:
        from defender.learning.pipeline.actor_engine import _actor_policy
        patterns.extend(_actor_policy(roots.scripts, read_confine=()).bash_allow)
    return tuple(patterns)


def compile_policy(
    tools: ToolSet,
    read_shapes: tuple[Callable[[Path, Path], tuple[Any, ...]], ...],
    roots: ResolvedRoots,
    deny_reason: str,
) -> AgentPolicy:
    """Project a ``ToolSet`` + resolved ``roots`` into the gate's ``AgentPolicy`` — the
    derived runtime artifact ``decide_bash``/``decide_read`` key on.

    A genuine projection: the capability bits come straight off the grammar (a bit is
    set only when its source bit is), ``raw_reads`` is derived (an agent that runs
    adapters or path-gated ``jq`` reads ``gather_raw``; main/actor/oracle/verify do not),
    ``write_allow`` is the run-dir write subtree when the ToolSet grants writers (main —
    the #543 write gate; the read-only stages get none), and the read roots/confine come
    from the scope. ``read_shapes`` (#545 — decision 3) is CONSUMED here: each shape-builder
    the def carries is resolved against the run's roots into the read-tool filename filter
    (``decide_read`` then admits exactly the filename set the bash ``cat`` lane does). Empty
    ``read_shapes`` ⇒ no filter (the legacy root-only read gate, for every non-reader stage)."""
    bash = tools.bash
    if bash is None:
        adapters = adapter_sql_pipe = jq_gated = False
        bash_allow: tuple[Any, ...] = ()
    else:
        adapters = bash.adapters
        adapter_sql_pipe = bash.adapter_sql_pipe
        jq_gated = bash.jq_operand_gated
        bash_allow = _bash_allow(bash, roots)
    return AgentPolicy(
        bash_allow=bash_allow,
        jq_operand_gated=jq_gated,
        adapters=adapters,
        adapter_sql_pipe=adapter_sql_pipe,
        raw_reads=adapters or adapter_sql_pipe or jq_gated,
        read_roots=roots.read_roots,
        read_confine=roots.read_confine,
        write_allow=(build_write_allow(roots.run_dir),) if tools.write else (),
        read_shapes=tuple(
            pat for build in read_shapes for pat in build(roots.run_dir, roots.defender_dir)
        ),
        deny_reason=deny_reason,
    )


# ── bind: the single resolution seam ─────────────────────────────────────────

def _deps_class(role: AgentRole) -> type[AgentDeps]:
    """Map a role to its ``AgentDeps`` subtype. Lazy imports keep this module light
    and free of a load-time cycle: the runtime deps live in ``runtime.tools``, the
    learning stages' in their engine modules (the cross-layer reach the F1 fork
    resolves — ``bind`` returns the real subtype so gather's ``isinstance`` capture,
    the actor confine, and role identity all survive)."""
    from defender.runtime.tools import AgentDeps, GatherDeps

    if role is AgentRole.MAIN:
        return AgentDeps
    if role is AgentRole.GATHER:
        return GatherDeps
    if role is AgentRole.JUDGE:
        from defender.learning.pipeline.judge.engine_pydantic import JudgeDeps
        return JudgeDeps
    if role is AgentRole.ACTOR:
        from defender.learning.pipeline.actor_engine import ActorDeps
        return ActorDeps
    if role is AgentRole.ORACLE:
        from defender.learning.pipeline.oracle_engine import OracleDeps
        return OracleDeps
    if role is AgentRole.VERIFIER:
        from defender.learning.author.verify_forward.engine import VerifierDeps
        return VerifierDeps
    if role is AgentRole.LEAD_AUTHOR:
        from defender.learning.leads.lead_author_engine import LeadAuthorDeps
        return LeadAuthorDeps
    raise ValueError(f"no AgentDeps subtype for role {role!r}")


def bind(
    defn: AgentDefinition, run_dir: Path, *,
    scope: RunScope = _DEFAULT_SCOPE, salt: str | None = None, repo_root: Path | None = None,
) -> AgentDeps:
    """Resolve a definition for a run into ready-to-use ``AgentDeps``: resolve the roots,
    compile the policy, then construct the role's ``AgentDeps`` subtype carrying it (via the
    shared ``_for_run`` spine — ``run_id`` = the run dir basename).

    ``salt`` is the untrusted-data trust token (decision 1a): ``None`` mints a fresh uuid4
    (the stages' behaviour), a carried value is threaded verbatim so the MAIN/GATHER reroute
    keeps the run's ONE persisted salt across the deps' tool-output wrapper AND orient's alert
    wrapper (a fresh uuid4 there would split the tag and fail the injection defence open).

    ``LEAD_AUTHOR`` is the writer (decision 2): its policy is the worktree-anchored
    ``defender/skills/**.md`` write scope + the scoped ``rm``-of-drafts grant (NOT the generic
    run-dir ``write_allow`` ``compile_policy`` would emit), so bind reuses its authoritative
    ``_lead_author_policy`` builder — the same cross-layer reuse ``_bash_allow`` makes for the
    judge/actor — and REQUIRES ``repo_root`` (the worktree) to anchor it: fail loud without it,
    never a silent ``PATHS.defender_dir``/run-dir fallback that would author the main checkout.
    Stays PER-RUN — no ``lead_id`` parameter; gather's per-dispatch id rides a thin wrapper that
    stamps it post-bind."""
    if defn.role is AgentRole.LEAD_AUTHOR:
        if repo_root is None:
            raise ValueError(
                "bind(LEAD_AUTHOR_DEF, …) requires repo_root — the worktree root its "
                "defender/skills write scope anchors on; there is no safe default (a "
                "PATHS/run-dir fallback would author the main checkout, not the worktree)."
            )
        from defender.learning.leads.lead_author_engine import (
            LeadAuthorDeps,
            _lead_author_policy,
        )
        defender_dir = repo_root / "defender"
        policy = _lead_author_policy(defender_dir / "skills")
        return LeadAuthorDeps._for_run(
            run_dir, policy, defender_dir=defender_dir, salt=salt,
        )
    if defn.role is AgentRole.ACTOR and not scope.read_confine:
        # Footgun A (R5 safe-by-construction): an empty read_confine falls back to the whole
        # defender_dir (files._resolved_read_roots), reopening the #512 gray-box rubric leak —
        # bind must fail loud, never silently mint an unconfined actor. Mirrors _ActorScope's
        # required-read_confine kw-only field: the actor scope must NAME its confine explicitly.
        raise ValueError(
            "bind(ACTOR_DEF, …) requires a non-empty read_confine in the RunScope — an empty "
            "confine widens the actor's reads to the whole defender_dir (the #512 gray-box "
            "rubric leak); name the lesson-corpus confine explicitly (there is no unconfined actor)."
        )
    roots = resolve_roots(run_dir, defn.corpus_dirs, scope)
    policy = compile_policy(defn.tools, defn.read_shapes, roots, defn.deny_reason)
    return _deps_class(defn.role)._for_run(run_dir, policy, salt=salt)


def build_registry(defs: tuple[AgentDefinition, ...]) -> dict[AgentRole, AgentDefinition]:
    """Fan a tuple of definitions into the role-keyed registry, RAISING (``ValueError``
    naming the ``role``) on a duplicate — the safe-by-construction replacement for the
    dict-comp's silent last-wins overwrite, which could drop an agent's whole
    definition unnoticed."""
    registry: dict[AgentRole, AgentDefinition] = {}
    for d in defs:
        if d.role in registry:
            raise ValueError(f"duplicate agent role {d.role!r} in the definition registry")
        registry[d.role] = d
    return registry


__all__ = [
    "AgentDefinition",
    "BashGrammar",
    "ResolvedRoots",
    "RunScope",
    "ToolSet",
    "bind",
    "build_registry",
    "compile_policy",
    "resolve_roots",
]
