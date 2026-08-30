from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass, fields, replace
from pathlib import Path
from typing import TYPE_CHECKING, Any

from defender._paths import PATHS

from .agent_role import AgentRole
from .permission import AgentPolicy, require_anchor_root
from .permission.grant import Grant, PathShapes
from .verb_grant import DENY_ALL, GrantError, VerbGrant

if TYPE_CHECKING:
    from .tools import AgentDeps

_DEFAULT_DENY_REASON = (
    "Blocked: this command is not permitted for this agent (its declared "
    "capabilities only)."
)



@dataclass(frozen=True)
class ToolSet:

    read: bool = False
    bash: bool = False
    #: The general write lane: `write_file` + `edit_file`, anchored replace over a whole
    #: document. What a corpus author needs.
    write: bool = False
    #: The append lane: `append_block`, no anchor and no position — what an append-only
    #: artifact (`investigation.md`) needs. Disjoint from `write` in practice but not
    #: enforced so; both are writer grants and both require `write_shapes`.
    append: bool = False
    forward_check: bool = False
    lesson_read: bool = False
    template_search: bool = False
    query: bool = False
    #: The verb-surface read lane: `list_verbs`, the grant-filtered discovery tool that
    #: answers "what does this system declare, and what params does each verb bind" from the
    #: live signatures. Verb-bearing like `query` — it reads the role's grant to filter — so
    #: it counts toward the R7 agreement below.
    list_verbs: bool = False
    closed_tickets: bool = False
    close: bool = False

    def __iter__(self) -> Iterator[str]:
        """The names of the lanes this set GRANTS, in declaration order.

        A ToolSet reads as a row of booleans, which makes "what does this role actually hold?"
        a question every caller answers by hand — and a deny-all role's answer, the one worth
        asserting, is the empty one, which a hand-written check states by NOT mentioning a bit
        it forgot. Iterating yields only the True lanes, so `tuple(defn.tools) == ()` is the
        whole deny-all claim over every lane that exists now or is added later.

        Through `dataclasses.fields`, never `__dataclass_fields__`: the raw mapping also holds
        ClassVar/InitVar pseudo-fields (#965)."""
        return (f.name for f in fields(self) if getattr(self, f.name))


@dataclass(frozen=True)
class AgentDefinition:

    role: AgentRole
    model: Callable[[], str]
    effort: str | None
    tools: ToolSet = ToolSet()
    corpus_dirs: tuple[str, ...] = ()
    bash_shapes: tuple[Callable[[ResolvedRoots], tuple[Grant, ...]], ...] = ()
    write_shapes: tuple[Callable[[ResolvedRoots], tuple[Any, ...]], ...] = ()
    #: The deps type `bind` builds for this role. Normally an `AgentDeps` subtype; typed
    #: loosely for the one shape that cannot be one — a role holding NO grant and no run-scoped
    #: state at all (#947's questioner), whose deps carry only their `role` ClassVar. `AgentDeps`
    #: IS the run scope (run dir, policy, box, anchors), so a deps type with none of that cannot
    #: inherit it; `bind` refuses such a def loudly rather than reaching for a `_for_run` that
    #: is not there.
    deps_cls: type[Any] | None = None
    requires_confine: bool = False
    requires_explicit_tree: bool = False
    anchors_on_tree: bool = False
    requires_corpus: bool = False
    read_allow_override: PathShapes | None = None
    deny_reason: str = _DEFAULT_DENY_REASON
    budget_enforced: bool = False
    verb_grant: VerbGrant = DENY_ALL



@dataclass(frozen=True)
class RunScope:

    add_dirs: tuple[Path, ...] = ()
    read_confine: tuple[Path, ...] = ()
    scripts: tuple[Path, ...] = ()
    corpus_name: str | None = None


_DEFAULT_SCOPE = RunScope()


@dataclass(frozen=True)
class ResolvedRoots:

    run_dir: Path
    defender_dir: Path
    corpus_roots: tuple[Path, ...]
    read_roots: tuple[Path, ...]
    read_confine: tuple[Path, ...]
    scripts: tuple[Path, ...]
    corpus_dir: Path | None = None


def _resolve_corpus_dir(name: str, defender_dir: Path) -> Path:
    p = Path(name)
    if p.is_absolute() or ".." in p.parts or len(p.parts) != 1:
        raise ValueError(
            f"corpus name {name!r} must be a single clean relative path segment under "
            "defender_dir (no '..' segment, not absolute, exactly one path component)"
        )
    return defender_dir / p.parts[0]


def resolve_roots(
    run_dir: Path, corpus_dirs: tuple[str, ...], scope: RunScope,
    defender_dir: Path = PATHS.defender_dir,
) -> ResolvedRoots:
    corpus_roots = tuple(_resolve_corpus_dir(name, defender_dir) for name in corpus_dirs)
    corpus_dir = (
        _resolve_corpus_dir(scope.corpus_name, defender_dir)
        if scope.corpus_name is not None else None
    )
    return ResolvedRoots(
        run_dir=run_dir,
        defender_dir=defender_dir,
        corpus_roots=corpus_roots,
        read_roots=tuple(scope.add_dirs),
        read_confine=tuple(scope.read_confine),
        scripts=tuple(scope.scripts),
        corpus_dir=corpus_dir,
    )



def _require_write_co_constraint(
    tools: ToolSet, write_shapes: tuple[Callable[[ResolvedRoots], tuple[Any, ...]], ...],
) -> None:
    # Either grant makes the agent a writer: `append_block` faces the same allowlist and the
    # same content schema `write_file`/`edit_file` do, so it needs the same scope.
    writes = tools.write or tools.append
    if writes and not write_shapes:
        raise ValueError(
            "a writer ToolSet (write=True or append=True) must declare non-empty "
            "write_shapes — an empty write scope would deny every write (a dead writer)."
        )
    if not writes and write_shapes:
        raise ValueError(
            "write_shapes were declared but the ToolSet grants no writer (write=False, "
            "append=False) — dead scope; drop the shapes or grant the writer."
        )


def read_allow_of(bash_allow: tuple[Grant, ...]) -> PathShapes:
    return next((g.scope for g in bash_allow if g.program == "cat"), PathShapes())


def effective_tools_for(defn: AgentDefinition) -> ToolSet:
    """The ToolSet a generic, out-of-band consumer (the operator policy CLI, a permission-gate
    probe) should compile a role's policy against when the static `defn.tools` does not show
    its real capability.

    The judge is the one such role: its `closed_tickets` bit is switched per LEG by a runtime
    `replace()` well past `AGENTS`, so `defn.tools` alone reads as the benign-off, grant-on
    disagreement `bind()`/`compile_policy` would refuse to build (§7 R7). A generic consumer
    gets the richer (benign) leg's shape. The ONE place that knows any role's typed-capability
    switching; a consumer never names a bit itself (N4 — the operator surface must not carry a
    map of typed capabilities to attack)."""
    if defn.role is AgentRole.JUDGE:
        return replace(defn.tools, closed_tickets=True)
    return defn.tools


def _require_verb_grant_agreement(defn: AgentDefinition, tools: ToolSet) -> None:
    """§7 R7: a role's verb_grant and the bit that reaches a verb-bearing tool agree, in EITHER
    direction. A grant naming verbs while every verb-bearing bit (`query`, `list_verbs`,
    `closed_tickets`) is off is a stale grant behind a switched-off capability; a verb-bearing
    bit on with an empty grant is a capability with nothing behind it. Checked against the
    EFFECTIVE `tools`, not only what `defn` declares, because a stage can switch its capability
    on with a runtime `replace()` after `bind` compiled its policy.

    `list_verbs` joins the disjunction rather than sitting outside it: it does not DISPATCH a
    verb, but it reads the grant to decide what to name, so a role holding it over an empty
    grant is a discovery tool that can only ever answer "nothing"."""
    has_verb_tool = bool(tools.query or tools.list_verbs or tools.closed_tickets)
    has_grant = bool(defn.verb_grant.entries)
    if has_verb_tool != has_grant:
        raise GrantError(
            f"{defn.role.name}: verb_grant/tool-capability disagreement — "
            f"verb-bearing tool bit is {'on' if has_verb_tool else 'off'} while the "
            f"verb_grant is {'non-empty' if has_grant else 'empty'} ({defn.verb_grant.entries})"
        )


def compile_policy(
    defn: AgentDefinition, roots: ResolvedRoots, *, tools: ToolSet | None = None,
) -> AgentPolicy:
    _require_write_co_constraint(defn.tools, defn.write_shapes)
    _require_verb_grant_agreement(defn, tools if tools is not None else defn.tools)
    bash_allow = tuple(g for build in defn.bash_shapes for g in build(roots))
    read_allow = (
        read_allow_of(bash_allow) if defn.read_allow_override is None
        else defn.read_allow_override
    )
    return AgentPolicy(
        bash_allow=bash_allow,
        read_allow=read_allow,
        read_roots=roots.read_roots,
        read_confine=roots.read_confine,
        write_allow=tuple(pat for build in defn.write_shapes for pat in build(roots)),
        deny_reason=defn.deny_reason,
        budget_enforced=defn.budget_enforced,
        verb_allow=defn.verb_grant,
    )



def _require_absolute_root(label: str, p: Path) -> None:
    require_anchor_root(f"bind {label}", p)


def _resolved_tree(defender_dir: Path | None) -> Path:
    return defender_dir if defender_dir is not None else PATHS.defender_dir


def _build_roots(
    defn: AgentDefinition, run_dir: Path, scope: RunScope, defender_dir: Path | None,
) -> ResolvedRoots:
    _require_absolute_root("run_dir", run_dir)
    if defender_dir is not None:
        _require_absolute_root("defender_dir", defender_dir)
    for member in (*scope.add_dirs, *scope.read_confine, *scope.scripts):
        _require_absolute_root("scope read root", member)
    if defn.requires_explicit_tree and (
        defender_dir is None or Path(defender_dir).resolve() == PATHS.defender_dir.resolve()
    ):
        raise ValueError(
            f"bind({defn.role.name}_DEF, …) requires an explicit NON-PATHS defender_dir — the "
            "worktree tree its write scope anchors on; a None/PATHS tree would author the MAIN "
            "checkout, not the worktree (the main-checkout-authoring state is unbuildable)."
        )
    if defn.requires_corpus and scope.corpus_name is None:
        raise ValueError(
            f"bind({defn.role.name}_DEF, …) requires a corpus_name in its RunScope — this "
            "agent's per-spawn corpus; there is no default corpus to fall back on."
        )
    if defn.requires_confine and not scope.read_confine:
        raise ValueError(
            f"bind({defn.role.name}_DEF, …) requires a non-empty read_confine in the RunScope — "
            "an empty confine widens the agent's reads to the whole defender_dir (the #512 "
            "gray-box rubric leak); name the confine explicitly (there is no unconfined agent)."
        )
    roots = resolve_roots(
        run_dir, defn.corpus_dirs, scope, defender_dir=_resolved_tree(defender_dir),
    )
    if defn.requires_corpus:
        assert roots.corpus_dir is not None
        # Compare RESOLVED to RESOLVED, the same collapse `decide_write`'s containment half
        # applies at runtime. A lexical `is_relative_to` on the UNresolved corpus_dir would
        # spuriously reject every bind whenever the tree path carries a symlink component (a
        # symlinked worktree base, macOS `/tmp`→`/private/tmp`).
        resolved_corpus = roots.corpus_dir.resolve()
        if not any(resolved_corpus.is_relative_to(c.resolve()) for c in roots.read_confine):
            raise ValueError(
                f"bind({defn.role.name}_DEF, …) corpus {scope.corpus_name!r} resolves to "
                f"{resolved_corpus} which is outside this agent's read confine/scope — a write "
                "scope that cannot author within its own read containment is unbuildable."
            )
    return roots


def compile_policy_for(
    defn: AgentDefinition, run_dir: Path, *,
    scope: RunScope = _DEFAULT_SCOPE, defender_dir: Path | None = None,
    tools: ToolSet | None = None,
) -> AgentPolicy:
    roots = _build_roots(defn, run_dir, scope, defender_dir)
    return compile_policy(defn, roots, tools=tools)


def bind(
    defn: AgentDefinition, run_dir: Path, *,
    scope: RunScope = _DEFAULT_SCOPE, defender_dir: Path | None = None,
    box: Any = None,
) -> AgentDeps:
    roots = _build_roots(defn, run_dir, scope, defender_dir)
    policy = compile_policy(defn, roots)
    if defn.deps_cls is None:
        raise ValueError(
            f"{defn.role.name}_DEF declares no deps_cls — a bindable def must name the "
            "AgentDeps subtype that lives beside it (that is what keeps runtime/ from "
            "importing the learning stages to look it up)."
        )
    if not hasattr(defn.deps_cls, "_for_run"):
        # A deps type outside the AgentDeps hierarchy — a role that carries no run scope
        # because it holds no grant. There is nothing to bind, and answering with a half-built
        # deps object would hand a caller something whose `.policy` does not exist; refuse by
        # name instead, the way the curator's non-bindable def already does.
        raise ValueError(
            f"{defn.role.name}_DEF is not bindable: its deps type "
            f"{defn.deps_cls.__name__} is not an AgentDeps subtype (it carries no run scope), "
            "so there is no run-scoped deps for bind to build."
        )
    return defn.deps_cls._for_run(
        run_dir, policy, defender_dir=roots.defender_dir, box=box,
        cwd_anchor=(roots.defender_dir.parent if defn.anchors_on_tree else run_dir),
        roots=roots,
    )


def build_registry(defs: tuple[AgentDefinition, ...]) -> dict[AgentRole, AgentDefinition]:
    registry: dict[AgentRole, AgentDefinition] = {}
    for d in defs:
        if d.role in registry:
            raise ValueError(f"duplicate agent role {d.role!r} in the definition registry")
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
    "effective_tools_for",
    "read_allow_of",
    "resolve_roots",
]
