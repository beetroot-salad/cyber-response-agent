from __future__ import annotations

import logging
import re
from collections.abc import Callable
from pathlib import Path
from typing import Any, ClassVar

from defender._model import model
from defender._paths import adapters_under
from defender.learning.core import config
from defender.learning.core.config import RunUnprocessable, StageContext, StageWiring
from defender.learning.leads.declared_systems import adapter_systems_under
from defender.learning.leads.path_validation import CATALOG_REL, SKILLS_REL
from defender.learning._pydantic_stage import run_stage as _run_stage_fn
from defender.runtime import providers
from defender.runtime.agent_definition import AgentDefinition, ResolvedRoots, ToolSet, bind
from defender.runtime.agent_role import AgentRole
from defender.runtime.driver import MakeModel
from defender.runtime.permission.grant import SEG, Grant
from defender.runtime.tools import AgentDeps

_LEAD_AUTHOR_DENY_REASON = (
    "Blocked: the lead author curates the gather query catalog and the per-SYSTEM skill docs. "  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir
    "Its write scope is the catalog under defender/skills/gather/queries/{system}/, plus "
    "defender/skills/{system}/SKILL.md and defender/skills/{system}/_draft/ — where {system} is "
    "a system this tree declares an adapter for. Every OTHER directory under defender/skills/ "
    "is an authored surface this lane does not write — including two that are agent system "
    "prompts. It rm's a draft it promotes or discards "
    "— no data-source adapters, no gather_raw reads, no shell beyond the scoped rm."
)


def _systems_or_raise(defender_dir: Path) -> tuple[str, ...]:
    """The systems this tree declares, sorted — refusing to build a lane-less policy.

    The adapter half alone, not the `declared_systems` union the commit gate uses: this runs
    inside `bind` per spawn, and the marker half needs a `git ls-tree`. A marker-only system is
    thus refused here but admitted at commit — stricter on write, the safe direction (a
    recoverable tool denial rather than a batch discard).

    No declared adapter means a writer whose `write_allow` admits nothing, which would burn its
    request budget on denials; this is the runtime twin of `_require_write_co_constraint`.
    """
    # Rooted on the bound tree itself: `.parent / "defender"` would read a sibling tree's
    # adapters whenever the directory isn't literally named `defender`.
    adapters_dir = adapters_under(defender_dir)
    systems = tuple(sorted(adapter_systems_under(adapters_dir)))
    if not systems:
        raise ValueError(
            f"lead-author write scope is empty: {adapters_dir} declares no system, so no "
            "per-system write lane compiles and the spawned agent could not write the edits "
            "its own handoff asks for"
        )
    return systems


#: The catalog's tail under `<skills>/`, derived so the write and `rm` lanes name the same
#: directory.
_CATALOG_TAIL = CATALOG_REL[len(SKILLS_REL):]

#: Basenames no variable lane segment may mint, because the commit gates refuse them by
#: discarding the batch: `SCHEMA.md` (`_is_schema_md`) and `execution.md`
#: (`_skills_path_rule`), both at any depth. The pitfalls curator's `{system}/execution.md` is
#: reached by L5 as a literal.
_REFUSED_BASENAMES = ("SCHEMA.md", "execution.md")


def _md_name(*also: str) -> str:
    """A `{name}.md` filename segment: `SEG`-shaped, and not a basename a commit gate refuses.

    The lookahead is anchored with `\\Z` so it doesn't also refuse e.g. `README.md.md`; both
    consumers put this segment last.
    """
    names = "|".join(re.escape(n) for n in (*also, *_REFUSED_BASENAMES))
    return rf"(?!(?:{names})\Z){SEG}\.md"


def _draft_tail(prefix: str, sys_alt: str) -> str:
    """`{prefix}(?:{sys_alt})/_draft/{name}.md`, minus `README.md`.

    `sys_alt` is the pre-joined regex alternation of system names, not a `systems` tuple.
    Shared by the catalog-draft and system-skill-draft lanes. `README.md` is excluded here
    because the drain's `_is_draft_readme` would discard the whole batch, while a write-gate
    refusal is recoverable.
    """
    return rf"{prefix}(?:{sys_alt})/_draft/{_md_name('README.md')}"


def _skill_write_lanes(skills_dir: Path, systems: tuple[str, ...]) -> tuple[re.Pattern[str], ...]:
    """The lead lane's write allow: one compiled pattern per named lane.

    Not a blanket `<skills>/**.md`: that subtree holds `gather/SKILL.md` and `invlang/SKILL.md`,
    agent system prompts, which a lane fed attacker-influenced run text must not rewrite.

    Separate patterns so `defender-policy show` prints one named lane per line.

    Every variable segment is `SEG`, so no lane admits a space or newline in a filename; the
    commit gate reads unquoted `git status -z` and would otherwise accept one.

    A strict subset of the two commit gates' union, so a refusal here is a recoverable tool
    denial rather than a batch discard.
    """
    base = re.escape(str(skills_dir.resolve()))
    sys_alt = "|".join(re.escape(s) for s in systems)
    cat = _CATALOG_TAIL
    return tuple(
        re.compile(base + "/" + tail)
        for tail in (
            # L1 — established catalog templates and `{system}/README.md` notes. `SCHEMA.md` is
            # excluded by name, since `_is_schema_md` refuses it at any depth.
            rf"{cat}(?:{sys_alt})/{_md_name()}",
            # L2 — catalog drafts, minted by `synthesize_drafts`, promoted or discarded by the
            # agent.
            _draft_tail(cat, sys_alt),
            # L3 — the per-system skill doc, only under declared systems, so non-system
            # siblings (e.g. `gather/`, `invlang/`) get no lane.
            rf"(?:{sys_alt})/SKILL\.md",
            # L4 — system-skill drafts, the pending lifts `discover_system_drafts` hands over.
            _draft_tail("", sys_alt),
            # L5 — the pitfalls curator's lane. Both curators spawn under
            # `AgentRole.LEAD_AUTHOR` and the definition is derived by role, so this allow is
            # the union of both commit scopes. The lead author's commit gate still refuses
            # `execution.md`.
            rf"(?:{sys_alt})/execution\.md",
        )
    )


def _rm_skills_grant(skills_dir: Path, systems: tuple[str, ...]) -> Grant:
    """`rm` of one draft — the only removal `lead_author.md` gives this lane.

    Narrowed to the `_draft/` lanes so a disallowed delete is a recoverable denial rather than
    a batch discard at the commit gate. `SEG` excludes spaces and newlines, matching the write
    side; `..` can't match since system names are `SEG`-shaped and `_draft` is literal.
    """
    spellings = "|".join(re.escape(s) for s in (SKILLS_REL.rstrip("/"), str(skills_dir)))
    sys_alt = "|".join(re.escape(s) for s in systems)
    lanes = "|".join((_draft_tail(_CATALOG_TAIL, sys_alt), _draft_tail("", sys_alt)))
    return Grant(
        program="rm",
        pattern=re.compile(rf"^rm (?:{spellings})/(?:{lanes})$"),
        pins_path=True,
    )


def _lead_author_bash_shapes(roots: ResolvedRoots) -> tuple[Grant, ...]:
    return (
        _rm_skills_grant(
            roots.defender_dir / "skills", _systems_or_raise(roots.defender_dir)
        ),
    )


def _lead_author_write_shape(roots: ResolvedRoots) -> tuple[re.Pattern[str], ...]:
    return _skill_write_lanes(
        roots.defender_dir / "skills", _systems_or_raise(roots.defender_dir)
    )


@model(frozen=True)
class LeadAuthorDeps(AgentDeps):

    role: ClassVar[AgentRole] = AgentRole.LEAD_AUTHOR


LEAD_AUTHOR_DEF = AgentDefinition(
    role=AgentRole.LEAD_AUTHOR,
    model=config.lead_author_model,
    effort=config.lead_author_effort(),
    tools=ToolSet(read=True, bash=True, write=True),
    bash_shapes=(_lead_author_bash_shapes,),
    write_shapes=(_lead_author_write_shape,),
    deps_cls=LeadAuthorDeps,
    requires_explicit_tree=True,
    anchors_on_tree=True,
    deny_reason=_LEAD_AUTHOR_DENY_REASON,
)


def _run_lead_author_pydantic(
    wiring: StageWiring,
    ctx: StageContext,
    *,
    make_model: MakeModel = providers.build_for_effort,
    run_stage: Callable[..., Any] = _run_stage_fn,
) -> str:
    """Both limits vary per spawn here, so the caller owns the whole context."""
    # Required here, though optional on the shared context. A raise, not an assert, since
    # `python -O` strips asserts.
    repo_root = ctx.repo_root
    if repo_root is None:
        raise ValueError(
            "lead-author stage needs ctx.repo_root: it binds the skills tree off the repo"
        )
    deps = bind(
        LEAD_AUTHOR_DEF, ctx.learning_run_dir,
        # `ctx.salt` isn't bound: it scopes the prompt frames, while tool returns are framed
        # by `wrap_fresh` with their own salt.
        defender_dir=repo_root / "defender", box=ctx.box,
    )
    return run_stage(
        stage="lead_author",  # lint-run-records: ok — the lead-author role/drain/module's own name, not the `lead_author/` record dir
        wiring=wiring, ctx=ctx, deps=deps,
        make_model=make_model, require_output=False,
    )


def run_author_stage(
    *,
    wiring: StageWiring,
    ctx: StageContext,
    log_label: str,
    log: logging.Logger,
    source_key: Callable[..., object] = config.source_first_party_key,
    run_author: Callable[..., str] = _run_lead_author_pydantic,
) -> int:
    """`wiring` and `ctx` are built per spawn by the caller, since their knobs are env-backed
    and must not be evaluated at import."""
    log.info(
        f"spawn {log_label} in-process "
        f"(model={wiring.model}, effort={wiring.effort}, "
        f"timeout={ctx.wall_clock_timeout}s)"
    )
    source_key(wiring.model, label=log_label)
    try:
        run_author(wiring, ctx)
    except RunUnprocessable as e:
        log.error(f"{log_label} did not complete (per-run fault): {e}")
        return 124
    log.info(f"{log_label} done")
    return 0
