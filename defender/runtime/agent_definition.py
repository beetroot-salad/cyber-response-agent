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
    the reader ``bash_allow`` is compiled from the grammar's declared viewer/shim contents,
    the read-tool ``read_shapes`` filename filter and the ``write_allow`` write scope from the
    def's shape-builders (#545/#551 — read↔bash parity + the write twin, one grammar source),
    so ``bind``'s policy is the production end-state for every role, not a characterization.
  - ``bind`` — the SINGLE deps + policy resolution seam for all seven roles (#551 finishes the
    #545 wiring): ``resolve_roots`` → ``compile_policy`` → the role's ``AgentDeps`` subtype,
    carrying the run's salt (MAIN/GATHER keep the persisted trust token; the stages mint a fresh
    one) and the ``defender_dir`` tree the gate anchors on (``PATHS`` by default; the lead-author
    drain threads its worktree ``<wt>/defender`` — the unified tree param, into BOTH the policy
    anchor and the deps field). Per-role preconditions are DATA (``requires_confine`` /
    ``requires_explicit_tree``), so no ``if role is X`` branch remains.
  - ``build_registry`` — the guarded collector behind ``agents.AGENTS``.

Kept LIGHT on purpose: it imports only the permission gate types + the repo-layout
primitive, never ``pydantic_ai`` — so ``driver`` can define MAIN/GATHER defs off it
without pulling the learning graph. The one cross-layer reach (``bind`` returning the
learning stages' ``AgentDeps`` subtypes, ``compile_policy`` reusing the judge/actor bash-pattern
builders + the lead author's ``rm`` matcher) is done with LAZY, function-body imports: no
module-load cycle, and it only fires for those shapes.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from defender._paths import PATHS

from .agent_role import AgentRole
from .permission import AgentPolicy, require_anchor_root
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
    roots into the gate's anchored ``bash_allow`` (main/gather via ``reader_patterns_for``,
    the judge/actor/lead-author to their pinned pattern builders).

      - ``shims`` / ``viewers`` — the reader-lane program set (the ``defender-*`` shims
        + the read-only viewers). Non-empty ⇒ this is a main/gather reader agent.
      - ``adapters`` — may invoke a data-source adapter (captured transparently).
      - ``adapter_sql_pipe`` — may run ``adapter --raw | defender-sql '<SQL>'``.
      - ``operand_gated`` — the judge's ``cat | defender-sql`` lane: every file operand
        of a file-opening stage is path-gated to the read roots at ``resolve()`` time
        (``bash._OPERAND_GATED_PROGRAMS``), which is what lets it reach ``gather_raw``
        — a tree the textual anchors cannot see, since it is not under its ``run_dir``.
      - ``raw_reads`` — may read ``gather_raw/**``. DECLARED, never inferred from a
        sibling bit: gather declares it (it owns the payloads it captures) and so does
        the judge, which has neither ``adapters`` nor ``adapter_sql_pipe`` — the
        ``defender-sql`` *shim* is not the ``adapter_sql_pipe`` *route*. Inferring it
        from the bash lane is how the judge silently loses ``gather_raw`` to the clamp
        in ``bash.decide_bash``; inferring it FOR an adapter agent would make a declared
        ``raw_reads=False`` a lie. main/actor/oracle/verify leave it off.
      - ``skills_rm`` — the lead author's scoped ``rm``-of-drafts grant: ``compile_policy``
        anchors the single ``rm <defender_dir>/skills/<draft>`` matcher on the run's
        ``defender_dir`` (the worktree). A per-run bash pattern like the actor's pinned
        scripts, but declared on the def (the lead author carries no ``RunScope``)."""

    shims: tuple[str, ...] = ()
    viewers: tuple[str, ...] = ()
    adapters: bool = False
    adapter_sql_pipe: bool = False
    operand_gated: bool = False
    raw_reads: bool = False
    skills_rm: bool = False


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
    does (one grammar source); empty (every non-reader stage) leaves the read gate root-only.

    ``write_shapes`` is the WRITE twin of ``read_shapes`` (#551 — decision 2): per-run builders
    ``compile_policy`` resolves into ``write_allow`` (MAIN → the run-dir subtree; LEAD_AUTHOR →
    ``<defender_dir>/skills/**.md``). ``compile_policy`` ASSERTS the co-constraint — a writer
    (``tools.write``) must declare non-empty ``write_shapes`` and a non-writer must declare none.

    ``requires_confine`` / ``requires_explicit_tree`` are per-role safe-by-construction DATA bits
    (#551 — decision Q2), checked GENERICALLY in ``bind`` (no role branch): the actor's empty-
    ``read_confine`` fail-loud (True on ACTOR_DEF — an empty confine widens to the whole
    ``defender_dir``, the #512 gray-box leak), and the lead author's must-be-a-worktree tree
    guard (True on LEAD_AUTHOR_DEF — a ``None``/``PATHS`` tree would author the MAIN checkout).

    ``bindable`` (False on CORPUS_AUTHOR_DEF — #556) is the third such bit: a def whose per-spawn
    policy needs run inputs ``RunScope`` cannot carry (the curator's worktree ``corpus_dir``) is
    registered for its ToolSet alone and built by its own front door (``CuratorDeps.for_run``).
    ``bind`` fails loud on it rather than mint a ``run_dir``-rooted ``write_allow``, and the
    writer⟺``write_shapes`` co-constraint skips it — its write scope is resolved elsewhere."""

    role: AgentRole
    model: Callable[[], str]
    effort: str | None
    tools: ToolSet = ToolSet()
    corpus_dirs: tuple[str, ...] = ()
    read_shapes: tuple[Callable[[Path, Path], tuple[Any, ...]], ...] = ()
    write_shapes: tuple[Callable[[Path, Path], tuple[Any, ...]], ...] = ()
    requires_confine: bool = False
    requires_explicit_tree: bool = False
    bindable: bool = True
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


def _resolve_corpus_dir(name: str, defender_dir: Path) -> Path:
    """Resolve one relative corpus name to its absolute under ``defender_dir`` (the CALLER's
    tree — the worktree for the lead-author drain, ``PATHS`` for every other role — #551, no
    longer hardcoded). FAILS LOUD (``ValueError`` naming the offending ``corpus`` entry) on a
    ``..`` segment or an absolute path — the path-traversal defense on this confinement
    primitive, on the NAME (independent of which tree it anchors); never a silent drop/normalize
    (the roots are baked into the anchored bash allowlist, so a traversal here would widen reads)."""
    p = Path(name)
    if p.is_absolute() or ".." in p.parts:
        raise ValueError(
            f"corpus dir {name!r} must be a clean relative name under defender_dir "
            "(no '..' segment, not absolute)"
        )
    return defender_dir / name


def resolve_roots(
    run_dir: Path, corpus_dirs: tuple[str, ...], scope: RunScope,
    defender_dir: Path = PATHS.defender_dir,
) -> ResolvedRoots:
    """Fold a run + its corpus names + a ``RunScope`` into ``ResolvedRoots``. Per-run
    (keyed on ``run_dir``, no cache) so two runs get distinct roots — no cross-run bleed
    via a corpus-only cache key (the #497/#534 hazard). Corpus names resolve to
    absolutes under ``defender_dir`` (traversal-guarded).

    ``defender_dir`` defaults to the ``PATHS`` primitive (the MAIN checkout) but is threaded
    through by ``bind`` for a caller anchoring on a different tree — the lead-author drain's
    throwaway worktree (#551 — one 'thread the caller's tree root' mechanism). The gate then
    validates reads/writes against the SAME tree ``bind`` stamps on ``deps.defender_dir``."""
    corpus_roots = tuple(_resolve_corpus_dir(name, defender_dir) for name in corpus_dirs)
    return ResolvedRoots(
        run_dir=run_dir,
        defender_dir=defender_dir,
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
        set, so their lane equals the ``reader_patterns_for`` builder;
      - the judge (``operand_gated``) → its pinned ``cat``/``defender-sql`` (+ benign
        ticket) patterns;
      - the actor (``scope.scripts``) → one anchored ``python3 <script>`` pattern each.

    The judge/actor/lead-author patterns are REUSED from their authoritative pattern builders
    (via a lazy import — the same cross-layer reach ``bind`` already makes for the deps
    subtypes) so parity is guaranteed with zero regex duplication/drift."""
    patterns: list[Any] = []
    if bash.viewers or bash.shims:
        patterns.extend(reader_patterns_for(
            roots.run_dir, roots.defender_dir,
            frozenset(bash.viewers), frozenset(bash.shims),
        ))
    if bash.operand_gated:
        from defender.learning.pipeline.judge.engine_pydantic import _judge_policy
        patterns.extend(_judge_policy(roots.read_roots, roots.ticket_cli).bash_allow)
    if roots.scripts:
        from defender.learning.pipeline.actor_engine import _actor_policy
        patterns.extend(_actor_policy(roots.scripts, read_confine=()).bash_allow)
    if bash.skills_rm:
        # The lead author's ONE bash grant: a scoped `rm` of a draft under the run's
        # `<defender_dir>/skills` (the worktree). Anchored on `roots.defender_dir` so it
        # rides the same tree the write scope + read surface anchor on — a per-run pattern
        # like the actor's scripts, declared on the def (the lead author carries no scope).
        from defender.learning.leads.lead_author_engine import _rm_skills_pattern
        patterns.append(_rm_skills_pattern(roots.defender_dir / "skills"))
    return tuple(patterns)


def _require_write_co_constraint(
    tools: ToolSet, write_shapes: tuple[Callable[[Path, Path], tuple[Any, ...]], ...],
) -> None:
    """The writer⟺``write_shapes`` co-constraint (Q3 — safe-by-construction): a writer ToolSet
    (``write=True``) MUST declare non-empty ``write_shapes`` (else it would deny every write — a
    dead writer) and a non-writer MUST declare NONE (a dead scope). ONE implementation, enforced
    at TWO seams: ``build_registry`` runs it per registered def, so a production def typo (a new
    writer that forgets ``write_shapes``, or a read-only def carrying a dead scope) fails loud at
    AGENTS IMPORT — not at first ``bind`` — and ``compile_policy`` re-runs it defensively for
    callers passing a raw ``tools``/``write_shapes`` pair (the direct-compile tests)."""
    if tools.write and not write_shapes:
        raise ValueError(
            "a writer ToolSet (write=True) must declare non-empty write_shapes — an empty "
            "write scope would deny every write (a dead writer)."
        )
    if not tools.write and write_shapes:
        raise ValueError(
            "write_shapes were declared but the ToolSet grants no writer (write=False) — "
            "dead scope; drop the shapes or grant the writer."
        )


def compile_policy(
    tools: ToolSet,
    read_shapes: tuple[Callable[[Path, Path], tuple[Any, ...]], ...],
    write_shapes: tuple[Callable[[Path, Path], tuple[Any, ...]], ...],
    roots: ResolvedRoots,
    deny_reason: str,
) -> AgentPolicy:
    """Project a ``ToolSet`` + resolved ``roots`` into the gate's ``AgentPolicy`` — the
    derived runtime artifact ``decide_bash``/``decide_read`` key on.

    A genuine projection: EVERY capability bit comes straight off the grammar (a bit is
    set only when its source bit is) — ``raw_reads`` included, so the declared value is
    never overridden by an inference (gather and the judge declare it; main/actor/oracle/
    verify do not), and the read roots/confine come from the scope. ``read_shapes`` (#545 — decision 3) is
    CONSUMED here: each shape-builder the def carries is resolved against the run's roots into
    the read-tool filename filter (``decide_read`` then admits exactly the filename set the bash
    ``cat`` lane does). Empty ``read_shapes`` ⇒ no filter (the legacy root-only read gate).

    ``write_shapes`` (#551 — decision 2) is the WRITE twin: each builder resolves into
    ``write_allow`` (MAIN → the run-dir subtree; LEAD_AUTHOR → ``<defender_dir>/skills/**.md``),
    so the per-writer write scope is DATA on the def, resolved against the caller's tree exactly
    as ``read_shapes`` is. The co-constraint is ASSERTED (Q3 — safe-by-construction) via the
    shared ``_require_write_co_constraint``: a writer ToolSet (``tools.write``) must declare
    non-empty ``write_shapes`` (else it would deny every write — a dead writer) and a non-writer
    must declare NONE (a dead scope). ``build_registry`` runs the SAME check on every registered
    def at AGENTS import, so a production def typo fails loud there; this call is the defensive
    twin for direct callers passing a raw ``tools``/``write_shapes`` pair."""
    _require_write_co_constraint(tools, write_shapes)
    bash = tools.bash
    if bash is None:
        adapters = adapter_sql_pipe = operand_gated = raw_reads = False
        bash_allow: tuple[Any, ...] = ()
    else:
        adapters = bash.adapters
        adapter_sql_pipe = bash.adapter_sql_pipe
        operand_gated = bash.operand_gated
        raw_reads = bash.raw_reads
        bash_allow = _bash_allow(bash, roots)
    return AgentPolicy(
        bash_allow=bash_allow,
        operand_gated=operand_gated,
        adapters=adapters,
        adapter_sql_pipe=adapter_sql_pipe,
        raw_reads=raw_reads,
        read_roots=roots.read_roots,
        read_confine=roots.read_confine,
        write_allow=tuple(
            pat for build in write_shapes for pat in build(roots.run_dir, roots.defender_dir)
        ),
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


def _require_absolute_root(label: str, p: Path) -> None:
    """``bind``'s per-run root guard (run_dir / defender_dir / each scope read root): delegates
    to the shared ``require_anchor_root`` (``permission.bash``) — the ONE root-anchor validator,
    so the absolute/``..``/whitespace rejection has a single implementation and a future
    hardening lands in one place — with the ``bind {label}`` framing."""
    require_anchor_root(f"bind {label}", p)


def _resolved_tree(defender_dir: Path | None) -> Path:
    """The gate-anchor tree: the caller's explicit ``defender_dir``, else the ``PATHS`` default
    (the MAIN checkout). ONE owner for the 'which tree' default so ``compile_policy_for``'s policy
    anchor and ``bind``'s ``deps.defender_dir`` field can never disagree (a split would brick every
    worktree read/write)."""
    return defender_dir if defender_dir is not None else PATHS.defender_dir


def compile_policy_for(
    defn: AgentDefinition, run_dir: Path, *,
    scope: RunScope = _DEFAULT_SCOPE, defender_dir: Path | None = None,
) -> AgentPolicy:
    """Resolve + compile a definition's ``AgentPolicy`` WITHOUT minting deps — the policy-only
    half of ``bind`` (validate the roots, check the per-role DATA preconditions, resolve the
    roots, compile the policy). A caller that needs only ``.policy`` (no run_id/salt) — the gate
    tests — calls THIS rather than ``bind(...).policy``, so no discarded uuid4 salt + deps object
    is minted per call. ``bind`` = this + the ``_for_run`` deps mint, so the policy-only projection
    and the bound policy are IDENTICAL (no drift).

    ``defender_dir`` (#551) is the tree the gate anchors reads/writes on — ``None`` defaults to the
    ``PATHS`` primitive (the MAIN checkout), the LEAD_AUTHOR drain passes its throwaway
    ``<worktree>/defender``. The per-role preconditions are DATA (no ``if role is X`` branch):
    ``requires_confine`` (True on ACTOR_DEF) fails loud on an empty ``read_confine`` (an empty
    confine widens the actor to the whole ``defender_dir`` — the #512 gray-box leak), and
    ``requires_explicit_tree`` (True on LEAD_AUTHOR_DEF) fails loud on a ``None``/``PATHS`` tree (a
    writer that must author a worktree, never the MAIN checkout — the main-checkout-authoring state
    is UNBUILDABLE)."""
    if not defn.bindable:
        raise ValueError(
            f"bind({defn.role.name}_DEF, …) is not supported — this agent's per-spawn policy needs "
            "run inputs RunScope cannot carry (its worktree corpus dir), so compiling it here would "
            "root its write_allow at run_dir; build it via its own front door instead."
        )
    _require_absolute_root("run_dir", run_dir)
    if defender_dir is not None:
        _require_absolute_root("defender_dir", defender_dir)
    for member in (*scope.add_dirs, *scope.read_confine, *scope.scripts):
        _require_absolute_root("scope read root", member)
    if defn.requires_confine and not scope.read_confine:
        raise ValueError(
            f"bind({defn.role.name}_DEF, …) requires a non-empty read_confine in the RunScope — "
            "an empty confine widens the agent's reads to the whole defender_dir (the #512 "
            "gray-box rubric leak); name the confine explicitly (there is no unconfined agent)."
        )
    if defn.requires_explicit_tree and (
        defender_dir is None or Path(defender_dir).resolve() == PATHS.defender_dir.resolve()
    ):
        raise ValueError(
            f"bind({defn.role.name}_DEF, …) requires an explicit NON-PATHS defender_dir — the "
            "worktree tree its write scope anchors on; a None/PATHS tree would author the MAIN "
            "checkout, not the worktree (the main-checkout-authoring state is unbuildable)."
        )
    roots = resolve_roots(
        run_dir, defn.corpus_dirs, scope, defender_dir=_resolved_tree(defender_dir),
    )
    return compile_policy(defn.tools, defn.read_shapes, defn.write_shapes, roots, defn.deny_reason)


def bind(
    defn: AgentDefinition, run_dir: Path, *,
    scope: RunScope = _DEFAULT_SCOPE, salt: str | None = None, defender_dir: Path | None = None,
) -> AgentDeps:
    """Resolve a definition for a run into ready-to-use ``AgentDeps``: compile the policy (via
    ``compile_policy_for`` — the shared validate → resolve → compile half), then construct the
    role's ``AgentDeps`` subtype carrying it (via the shared ``_for_run`` spine — ``run_id`` =
    the run dir basename).

    ``salt`` is the untrusted-data trust token (decision 1a): ``None`` mints a fresh uuid4
    (the stages' behaviour), a carried value is threaded verbatim so the MAIN/GATHER reroute
    keeps the run's ONE persisted salt across the deps' tool-output wrapper AND orient's alert
    wrapper (a fresh uuid4 there would split the tag and fail the injection defence open).

    ``defender_dir`` (#551) is the tree the gate anchors reads/writes on (see ``compile_policy_for``
    for the ``None``→``PATHS`` default + the per-role preconditions). It is threaded into BOTH the
    policy (``compile_policy_for``) AND ``_for_run`` (the ``deps.defender_dir`` FIELD the runtime
    gate reads for containment) via the shared ``_resolved_tree``, so the two anchors are ONE tree:
    threading only the policy would leave ``deps.defender_dir`` at ``PATHS`` and brick every
    worktree read/write. LEAD_AUTHOR flows through this same spine as every other role — no bespoke
    early-return.

    Stays PER-RUN — no ``lead_id`` parameter; gather's per-dispatch id rides a thin wrapper that
    stamps it post-bind."""
    policy = compile_policy_for(defn, run_dir, scope=scope, defender_dir=defender_dir)
    return _deps_class(defn.role)._for_run(
        run_dir, policy, defender_dir=_resolved_tree(defender_dir), salt=salt,
    )


def build_registry(defs: tuple[AgentDefinition, ...]) -> dict[AgentRole, AgentDefinition]:
    """Fan a tuple of definitions into the role-keyed registry, RAISING (``ValueError``
    naming the ``role``) on a duplicate — the safe-by-construction replacement for the
    dict-comp's silent last-wins overwrite, which could drop an agent's whole
    definition unnoticed. Also runs the writer⟺``write_shapes`` co-constraint on each BINDABLE def
    (``_require_write_co_constraint``), so a misconfigured registered def fails loud at AGENTS
    IMPORT rather than only when that role is first bound (#551 F9). A ``bindable=False`` def
    (CORPUS_AUTHOR — #556) is exempt: it never reaches ``compile_policy``, so it carries no
    ``write_shapes`` and its writer scope is built by its own per-spawn front door."""
    registry: dict[AgentRole, AgentDefinition] = {}
    for d in defs:
        if d.role in registry:
            raise ValueError(f"duplicate agent role {d.role!r} in the definition registry")
        if d.bindable:
            _require_write_co_constraint(d.tools, d.write_shapes)
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
    "compile_policy_for",
    "resolve_roots",
]
