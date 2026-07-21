"""The per-agent **AgentDefinition** — one source of truth for an agent's tools +
permissions + model/effort (#538).

Today "what can this agent do" is answered by two carriers with different
lifecycles: the build-time toolset (which tools get registered) and the runtime
``AgentPolicy`` (how each tool is gated). #538 collapses them into one declarative
``AgentDefinition`` that BOTH the build site (``driver.build_agent_core``) and the
permission gate read, and — the forcing function — lets the pure-prediction stages
(oracle + verify-forward) be genuinely **tool-free** (register nothing).

This module is the primitive layer:

  - ``AgentDefinition`` / ``ToolSet`` — the declarative shape.
  - ``RunScope`` — the per-invocation carriage (judge comparison roots, actor
    confine + pinned scripts, benign-judge ticket cli).
  - ``resolve_roots`` → ``ResolvedRoots`` — folds a run + corpus names + scope into
    the resolved read roots.
  - ``compile_policy`` — projects a definition + roots into the gate's ``AgentPolicy``: each
    def's own ``bash_shapes`` builders emit its ``Grant``s, the ``cat`` grant's scope IS the
    read surface (``read_allow`` — parity by identity, #575), and ``write_shapes`` emits the
    write scope, so ``bind``'s policy is the production end-state for every role.
  - ``bind`` — the SINGLE deps + policy resolution seam for all seven roles (#551 finishes the
    #545 wiring): ``resolve_roots`` → ``compile_policy`` → the role's ``AgentDeps`` subtype,
    carrying the run's salt (MAIN/GATHER keep the run's minted trust token; the stages mint a fresh
    one) and the ``defender_dir`` tree the gate anchors on (``PATHS`` by default; the lead-author
    drain threads its worktree ``<wt>/defender`` — the unified tree param, into BOTH the policy
    anchor and the deps field). Per-role preconditions are DATA (``requires_confine`` /
    ``requires_explicit_tree``), so no ``if role is X`` branch remains.
  - ``build_registry`` — the guarded collector behind ``agents.AGENTS``.

Kept LIGHT on purpose: it imports only the permission gate types + the repo-layout primitive,
never ``pydantic_ai`` — so ``driver`` can define MAIN/GATHER defs off it without pulling the
learning graph. Since #575 it also imports NOTHING from ``learning``: the cross-layer reach it
used to make (lazy function-body imports of ``_judge_policy`` / ``_actor_policy`` /
``_rm_skills_pattern``, and a role→deps-class ladder) is INVERTED — each agent hangs its own
``bash_shapes`` builder and its own ``deps_cls`` on its OWN definition, so this module composes
what the defs bring instead of reaching up to ask each agent what it wants.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from defender._paths import PATHS

from .agent_role import AgentRole
from .permission import AgentPolicy, require_anchor_root
from .permission.grant import Grant, PathShapes

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
class ToolSet:
    """An agent's tool PRESENCE. The read-only / no-tool safe default is every field off.
    ``bash=False`` UNREGISTERS the bash tool; ``bash=True`` registers it — and WHAT the agent
    may then run is its ``bash_shapes`` grants. Presence and permission are two different
    facts (#575), so they are two fields: an agent can hold the tool and be granted nothing."""

    read: bool = False
    bash: bool = False
    write: bool = False
    # The lesson curators' author-time forward check (#558). A tool rather than a bash
    # grant because a bash allowlist pins a program token and cannot constrain the
    # operands that program then acts on.
    forward_check: bool = False
    # The lesson curators' scoped read tool (#559): read_file with an added ``part`` mode
    # (body-default strips the YAML frontmatter; full = whole file). Replaces the generic
    # ``read`` for the curator — its read surface is IDENTICAL (root-only ``decide_read``),
    # it only adds the part seam + degrades to whole text on a non-fenced file.
    lesson_read: bool = False
    # Gather's query-template grep (#585). A tool rather than a bash grant for the same reason
    # forward_check is one: the corpus root must be HARNESS-owned, and a bash allowlist pins the
    # program token, not the operand it then opens. Gather's discovery of the catalog was dead on
    # every bash route it had left, and this is the replacement.
    template_search: bool = False
    # Gather's typed data-source access (#611) — the tool that replaced the bash lane's adapter
    # route. PRESENCE stays here and not in a call-site ``capabilities=`` argument, for two
    # reasons that both bite: a capability-owned toolset lands OUTSIDE ``agent._function_toolset``,
    # where every #538 tool-freeness assertion looks (so "registers NOTHING" would stay green while
    # the invariant it encodes was false), and ``capabilities=`` is a build-site param, so "which
    # agent may reach a data source" would migrate out of policy-as-data into an argument
    # ``compile_policy`` and ``defender-policy explain`` cannot see. Declaring the bit is ALSO what
    # constructs the capture capability (``driver.build_agent_core``): the tool and its queries-table
    # row cannot be separated, which is what keeps that table an integrity gate rather than a hint.
    query: bool = False
    # The benign judge's two closed-ticket tools (#672) — the typed, host-side replacement for
    # the removed bash ticket lane (#338). Set PER-LEG from ``JudgeWiring.closed_ticket_read`` on
    # the stage-build ``replace`` seam; the frozen ``JUDGE_DEF`` default keeps it OFF, so the
    # adversarial leg is built without the tools (absence by registration, not a runtime direction
    # check). Registration follows this bit and threads the ticket verb registry like ``query``.
    closed_tickets: bool = False


@dataclass(frozen=True)
class AgentDefinition:
    """The single per-agent source of truth. ``model`` is a zero-arg THUNK (late env resolution,
    so a ``--model`` / ``$DEFENDER_MODEL`` override is honored at build, not frozen at import);
    ``effort`` is the static reasoning knob (``None`` omits it). ``tools`` drives registration;
    ``bash_shapes`` + ``write_shapes`` + ``corpus_dirs`` + ``deny_reason`` drive the gate via
    ``compile_policy``. Frozen, so ``bind``/``build`` can't corrupt a shared definition.

    ``bash_shapes`` is a tuple of per-run builders ``(ResolvedRoots) -> tuple[Grant, ...]``
    (#575): each agent hangs its OWN builder on its OWN def, so ``compile_policy`` composes what
    the defs bring instead of reaching up into ``learning`` to ask each agent what it wants (the
    lazy ``_judge_policy`` / ``_actor_policy`` / ``_rm_skills_pattern`` imports existed only to
    break the cycle that inversion created — invert it and they disappear). A ``Grant`` naming a
    program absent from ``permission.grant.PROGRAMS`` fails loud at compile
    (``AgentPolicy.__post_init__``), so an untabled — therefore ungated — program cannot ship.

    ``read_allow`` is NOT a field: the read surface IS the ``cat`` grant's scope (the same tuple
    OBJECT), so read↔bash parity holds by construction rather than by a second grammar kept in
    sync (#545's two grammars drifted; there is now nothing to sync).

    ``write_shapes`` is the write twin — per-run builders ``compile_policy`` resolves into
    ``write_allow`` (MAIN → the run-dir subtree; LEAD_AUTHOR → ``<defender_dir>/skills/**.md``).
    ``compile_policy`` ASSERTS the co-constraint: a writer (``tools.write``) must declare
    non-empty ``write_shapes`` and a non-writer must declare none.

    ``deps_cls`` is the role's ``AgentDeps`` subtype, carried BY the def (#575) — the last
    ``runtime`` → ``learning`` reach: a role→class ladder in this module had to lazily import
    five learning classes, while a def built in its own engine module simply names the class
    that lives beside it. Required for a ``bindable`` def.

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
    bash_shapes: tuple[Callable[[ResolvedRoots], tuple[Grant, ...]], ...] = ()
    write_shapes: tuple[Callable[[ResolvedRoots], tuple[Any, ...]], ...] = ()
    deps_cls: type[AgentDeps] | None = None
    requires_confine: bool = False
    requires_explicit_tree: bool = False
    #: Where this role's RELATIVE file operands anchor (#540). The default is the run dir —
    #: the boxed bash lane's cwd and its rw bind, so the gate, the file tools and the executor
    #: all name one directory. A TREE-anchored role addresses its own worktree instead
    #: (`defender_dir.parent`): the curators and the lead author edit a throwaway git worktree
    #: and are handed repo-relative paths (`defender/lessons/{slug}.md`) by their own prompts,
    #: while their `run_dir` is only a trace anchor and a read root — often not under the repo
    #: at all. One global anchor cannot serve both, so it is per-role DATA like the two bits
    #: above rather than an `if role is X` branch.
    anchors_on_tree: bool = False
    bindable: bool = True
    deny_reason: str = _DEFAULT_DENY_REASON
    # The budget-posture bit (#631, decision M2): True → the budget hook refuses the
    # over-cap tool and kills the run at tail exhaustion; False (the DEFAULT) → accounting
    # only. Gated to MAIN/GATHER; every learning stage keeps the default. A safe-by-
    # construction DATA bit like `requires_confine`/`bindable`, checked generically (no
    # role branch) — so a new agent that fails open would have to declare the bit True.
    budget_enforced: bool = False


# ── Per-invocation carriage + resolved roots ─────────────────────────────────

@dataclass(frozen=True)
class RunScope:
    """The per-invocation inputs a static ``AgentDefinition`` cannot carry — the
    superset of the judge's ``_ToolScope`` and the actor's ``_ActorScope``. All default
    empty (the runtime main/gather agents pass none):

      - ``add_dirs`` — judge comparison + gather_raw roots → the policy's ``read_roots``.
      - ``read_confine`` — actor gray-box confine (REPLACES the ``defender_dir`` base).
      - ``scripts`` — actor pinned lesson scripts → one ``bash_allow`` pattern each."""

    add_dirs: tuple[Path, ...] = ()
    read_confine: tuple[Path, ...] = ()
    scripts: tuple[Path, ...] = ()


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
    )


# ── AgentDefinition → AgentPolicy ────────────────────────────────────────────

def _require_write_co_constraint(
    tools: ToolSet, write_shapes: tuple[Callable[[ResolvedRoots], tuple[Any, ...]], ...],
) -> None:
    """The writer⟺``write_shapes`` co-constraint (safe-by-construction): a writer ToolSet
    (``write=True``) MUST declare non-empty ``write_shapes`` (else it would deny every write — a
    dead writer) and a non-writer MUST declare NONE (a dead scope). ONE implementation, enforced
    at TWO seams: ``build_registry`` runs it per registered def, so a production def typo (a new
    writer that forgets ``write_shapes``, or a read-only def carrying a dead scope) fails loud at
    AGENTS IMPORT — not at first ``bind`` — and ``compile_policy`` re-runs it defensively for a
    caller compiling a hand-built definition."""
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


def read_allow_of(bash_allow: tuple[Grant, ...]) -> PathShapes:
    """The agent's READ surface: the scope of its ``cat`` grant — the same tuple OBJECT, not a
    copy (#575). `cat` is the one program that opens a path on the bash lane, so the set of paths
    an agent may `cat` IS the set it may read; handing the read tool that very object is what
    makes read↔bash parity structural. Two grammars built from one source still drifted (#545,
    whose two builders needed OPPOSITE resolution semantics from the shared operand); one object
    cannot.

    An agent with no ``cat`` grant (the actor, the pure-prediction stages) gets ``()`` — no shape
    filter, so ``decide_read`` stays root-only for it, bounded by its confine/roots."""
    return next((g.scope for g in bash_allow if g.program == "cat"), PathShapes())


def compile_policy(defn: AgentDefinition, roots: ResolvedRoots) -> AgentPolicy:
    """Project a definition + resolved ``roots`` into the gate's ``AgentPolicy`` — the derived
    runtime artifact ``decide_bash``/``decide_read``/``decide_write`` key on.

    A genuine projection with nothing to infer: the grants come from the def's OWN
    ``bash_shapes`` builders, the read surface IS the ``cat`` grant's scope (``read_allow_of``),
    the write scope from ``write_shapes``, and the roots/confine from the scope. The old
    capability BITS (``adapters``/``adapter_sql_pipe``/``raw_reads``/``operand_gated``) are gone:
    each was a fact the grant list now carries directly, and each was a place a declared value
    could disagree with the lane that enforced it."""
    _require_write_co_constraint(defn.tools, defn.write_shapes)
    bash_allow = tuple(g for build in defn.bash_shapes for g in build(roots))
    return AgentPolicy(
        bash_allow=bash_allow,
        read_allow=read_allow_of(bash_allow),
        read_roots=roots.read_roots,
        read_confine=roots.read_confine,
        write_allow=tuple(pat for build in defn.write_shapes for pat in build(roots)),
        deny_reason=defn.deny_reason,
        budget_enforced=defn.budget_enforced,
    )


# ── bind: the single resolution seam ─────────────────────────────────────────

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
    return compile_policy(defn, roots)


def bind(
    defn: AgentDefinition, run_dir: Path, *,
    scope: RunScope = _DEFAULT_SCOPE, salt: str | None = None, defender_dir: Path | None = None,
    box: Any = None,
) -> AgentDeps:
    """Resolve a definition for a run into ready-to-use ``AgentDeps``: compile the policy (via
    ``compile_policy_for`` — the shared validate → resolve → compile half), then construct the
    role's ``AgentDeps`` subtype carrying it (via the shared ``_for_run`` spine — ``run_id`` =
    the run dir basename).

    ``salt`` is the untrusted-data trust token (decision 1a): ``None`` mints a fresh uuid4
    (the stages' behaviour), a carried value is threaded verbatim so the MAIN/GATHER reroute
    keeps the run's ONE minted salt across the deps' tool-output wrapper AND orient's alert
    wrapper (a fresh uuid4 there would split the tag and fail the injection defence open).

    ``defender_dir`` (#551) is the tree the gate anchors reads/writes on (see ``compile_policy_for``
    for the ``None``→``PATHS`` default + the per-role preconditions). It is threaded into BOTH the
    policy (``compile_policy_for``) AND ``_for_run`` (the ``deps.defender_dir`` FIELD the runtime
    gate reads for containment) via the shared ``_resolved_tree``, so the two anchors are ONE tree:
    threading only the policy would leave ``deps.defender_dir`` at ``PATHS`` and brick every
    worktree read/write. LEAD_AUTHOR flows through this same spine as every other role — no bespoke
    early-return.

    ``box`` (#540) is the bash lane's execution boundary, threaded onto ``deps.box``. ``None``
    leaves the deps carrying the INERT default executor, which refuses on first use — so a role
    bound without a box cannot execute bash at all, rather than executing it on the host. The
    box rides here rather than being resolved inside the tool because whether execution is
    confined is a property of the RUN, and the one place a run's identity becomes an agent's
    deps is this seam.

    Stays PER-RUN — no ``lead_id`` parameter; gather's per-dispatch id rides a thin wrapper that
    stamps it post-bind."""
    policy = compile_policy_for(defn, run_dir, scope=scope, defender_dir=defender_dir)
    if defn.deps_cls is None:
        raise ValueError(
            f"{defn.role.name}_DEF declares no deps_cls — a bindable def must name the "
            "AgentDeps subtype that lives beside it (that is what keeps runtime/ from "
            "importing the learning stages to look it up)."
        )
    return defn.deps_cls._for_run(
        run_dir, policy, defender_dir=_resolved_tree(defender_dir), salt=salt, box=box,
        # Resolved ONCE, here, from the role's own data bit — the three coupled sites then read
        # one field instead of each re-deriving an anchor and drifting apart.
        cwd_anchor=(
            _resolved_tree(defender_dir).parent if defn.anchors_on_tree else run_dir
        ),
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
    "ResolvedRoots",
    "RunScope",
    "ToolSet",
    "bind",
    "build_registry",
    "compile_policy",
    "compile_policy_for",
    "read_allow_of",
    "resolve_roots",
]
