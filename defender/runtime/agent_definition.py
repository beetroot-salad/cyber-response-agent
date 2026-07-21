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

_DEFAULT_DENY_REASON = (
    "Blocked: this command is not permitted for this agent (its declared "
    "capabilities only)."
)



@dataclass(frozen=True)
class ToolSet:

    read: bool = False
    bash: bool = False
    write: bool = False
    forward_check: bool = False
    lesson_read: bool = False
    template_search: bool = False
    query: bool = False
    closed_tickets: bool = False


@dataclass(frozen=True)
class AgentDefinition:

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
    anchors_on_tree: bool = False
    bindable: bool = True
    deny_reason: str = _DEFAULT_DENY_REASON
    budget_enforced: bool = False



@dataclass(frozen=True)
class RunScope:

    add_dirs: tuple[Path, ...] = ()
    read_confine: tuple[Path, ...] = ()
    scripts: tuple[Path, ...] = ()


_DEFAULT_SCOPE = RunScope()


@dataclass(frozen=True)
class ResolvedRoots:

    run_dir: Path
    defender_dir: Path
    corpus_roots: tuple[Path, ...]
    read_roots: tuple[Path, ...]
    read_confine: tuple[Path, ...]
    scripts: tuple[Path, ...]


def _resolve_corpus_dir(name: str, defender_dir: Path) -> Path:
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
    corpus_roots = tuple(_resolve_corpus_dir(name, defender_dir) for name in corpus_dirs)
    return ResolvedRoots(
        run_dir=run_dir,
        defender_dir=defender_dir,
        corpus_roots=corpus_roots,
        read_roots=tuple(scope.add_dirs),
        read_confine=tuple(scope.read_confine),
        scripts=tuple(scope.scripts),
    )



def _require_write_co_constraint(
    tools: ToolSet, write_shapes: tuple[Callable[[ResolvedRoots], tuple[Any, ...]], ...],
) -> None:
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
    return next((g.scope for g in bash_allow if g.program == "cat"), PathShapes())


def compile_policy(defn: AgentDefinition, roots: ResolvedRoots) -> AgentPolicy:
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



def _require_absolute_root(label: str, p: Path) -> None:
    require_anchor_root(f"bind {label}", p)


def _resolved_tree(defender_dir: Path | None) -> Path:
    return defender_dir if defender_dir is not None else PATHS.defender_dir


def compile_policy_for(
    defn: AgentDefinition, run_dir: Path, *,
    scope: RunScope = _DEFAULT_SCOPE, defender_dir: Path | None = None,
) -> AgentPolicy:
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
    policy = compile_policy_for(defn, run_dir, scope=scope, defender_dir=defender_dir)
    if defn.deps_cls is None:
        raise ValueError(
            f"{defn.role.name}_DEF declares no deps_cls — a bindable def must name the "
            "AgentDeps subtype that lives beside it (that is what keeps runtime/ from "
            "importing the learning stages to look it up)."
        )
    return defn.deps_cls._for_run(
        run_dir, policy, defender_dir=_resolved_tree(defender_dir), salt=salt, box=box,
        cwd_anchor=(
            _resolved_tree(defender_dir).parent if defn.anchors_on_tree else run_dir
        ),
    )


def build_registry(defs: tuple[AgentDefinition, ...]) -> dict[AgentRole, AgentDefinition]:
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
