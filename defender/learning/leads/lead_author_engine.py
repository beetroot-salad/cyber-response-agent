from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, ClassVar

from defender.learning.core import config
from defender.learning.core.config import RunUnprocessable, StageContext, StageWiring
from defender.learning.leads.declared_systems import ADAPTERS_REL, adapter_declared_systems
from defender.learning.leads.path_validation import SKILLS_REL
from defender.learning.pipeline._pydantic_stage import run_stage as _run_stage_fn
from defender.runtime import providers
from defender.runtime.agent_definition import AgentDefinition, ResolvedRoots, ToolSet, bind
from defender.runtime.agent_role import AgentRole
from defender.runtime.driver import MakeModel
from defender.runtime.permission.grant import SEG, Grant
from defender.runtime.tools import AgentDeps

_LEAD_AUTHOR_DENY_REASON = (
    "Blocked: the lead author curates the gather query catalog and the per-SYSTEM skill docs. "
    "Its write scope is the catalog under defender/skills/gather/queries/{system}/, plus "
    "defender/skills/{system}/SKILL.md and defender/skills/{system}/_draft/ — where {system} is "
    "a system this tree declares an adapter for. The other directories under defender/skills/ "
    "(gather, invlang, handbook, connect, advisory, judge) are authored surfaces this lane does "
    "not write: two of them ARE agent system prompts. It rm's a draft it promotes or discards "
    "— no data-source adapters, no gather_raw reads, no shell beyond the scoped rm."
)


def _systems_or_raise(defender_dir: Path) -> tuple[str, ...]:
    """The systems this tree declares, sorted — refusing to build a lane-less policy.

    The ADAPTER half alone (`adapter_declared_systems`), not the `declared_systems` union the
    commit gate resolves. Two reasons, and the second is why the difference is safe:

    * this runs inside `bind`, once per spawn, and the marker half is a `git ls-tree` against
      HEAD — the permission layer should not need a resolvable git tree to compile a regex, and
      #869's NF2 already establishes the adapter half as a legitimate resolution point of its
      own (the pitfalls lane reads exactly this value);
    * a system declared ONLY by a committed `execution.md` marker is therefore admitted by the
      commit gate and refused here. That is write-stricter-than-commit, the direction this
      whole change is about: the agent gets a denied tool call it can recover from, never a
      refusal that discards the batch at the drain.

    A tree that declares no adapter yields no per-system lane, and a writer whose `write_allow`
    admits nothing is a dead writer: the spawn burns its whole request budget returning denials
    for every edit the handoff just asked for. `_require_write_co_constraint` forbids that state
    at DEFINITION level; this is its runtime twin, and it raises for the same reason
    `_run_lead_author_pydantic` raises on a missing `ctx.repo_root` — a stage that cannot be
    built against this tree says so at the seam, rather than one frame down and inexplicably.
    """
    # `defender_dir.parent` is the repo root `bind` was handed — `AgentDefinition` threads the
    # tree as `<repo>/defender`, and the resolver's own contract is repo-rooted.
    systems = tuple(sorted(adapter_declared_systems(defender_dir.parent)))
    if not systems:
        raise ValueError(
            f"lead-author write scope is empty: {defender_dir.parent}/{ADAPTERS_REL} declares "
            "no system, so no per-system write lane compiles and the spawned agent could not "
            "write the edits its own handoff asks for"
        )
    return systems


def _draft_tail(prefix: str, systems: str) -> str:
    """`{prefix}(?:{systems})/_draft/{name}.md`, minus `README.md`.

    One spelling for the two `_draft/` lanes (catalog drafts and system-skill drafts) because
    they ARE one shape at two depths; two copies of it is how the pair drifts. `README.md` is
    excluded here rather than left to the commit gate for the reason this whole change is
    about: `_is_draft_readme` refuses it at the DRAIN, which discards the batch, while a write
    gate refusal is one denied tool call the agent can recover from.
    """
    return rf"{prefix}(?:{systems})/_draft/(?!README\.md){SEG}\.md"


def _skill_write_lanes(skills_dir: Path, systems: tuple[str, ...]) -> tuple[re.Pattern[str], ...]:
    """The lead lane's write allow: one compiled pattern per NAMED lane (#772).

    Replaces a single `build_write_allow(skills_dir, suffix=".md")` — `<skills>/[^\\x00]*\\.md`,
    which admitted every `.md` at every depth under `defender/skills/`. That subtree also holds
    `gather/SKILL.md` (the gather subagent's entire system prompt) and `invlang/SKILL.md`
    (inlined verbatim into the main agent's ORIENT message), so the lane whose inputs are
    attacker-influenced run text could rewrite the prompt of the agent that reads attacker
    payloads, and have the loop commit it.

    Separate patterns rather than one alternation, for the reason `build_named_write_allow`
    returns one per name: `defender-policy show` prints `write_allow` one entry per line, so an
    operator reads five named lanes instead of a single unreadable regex.

    Every variable segment is `SEG` — the read side's `Grant.scope` alphabet — so no lane admits
    a space or a newline in a filename. That is the narrowing `build_scoped_write_allow` was
    given for the frame-injection channel (#691 MD-7), and it was genuinely open here: the
    porcelain reader this lane's commit gate uses runs `git status -z`, which does NOT quote,
    so a `queries/{system}/a b.md` reached `_is_catalog_path` raw and in scope.

    The result is a strict subset of the union of the two commit gates this definition serves,
    which is the safe direction: anything refused here is refused as a recoverable tool denial
    rather than as a batch discard at the drain.
    """
    base = re.escape(str(skills_dir.resolve()))
    sys_alt = "|".join(re.escape(s) for s in systems)
    cat = "gather/queries/"
    return tuple(
        re.compile(base + "/" + tail)
        for tail in (
            # L1 — established catalog templates, and a system's `{system}/README.md` catalog
            # notes. `SCHEMA.md` sits at the catalog ROOT, one segment up, so no lane reaches it.
            rf"{cat}(?:{sys_alt})/{SEG}\.md",
            # L2 — catalog drafts. The lane `synthesize_drafts` mints into and the agent
            # promotes or discards out of.
            _draft_tail(cat, sys_alt),
            # L3 — THE per-system skill doc. Named exactly, so the sibling authored surfaces
            # (`gather`, `invlang`, `handbook`, `connect`, `advisory`, `judge`) have no lane at
            # all: they are not systems, and `_scaffold_rules.VerbResolver.is_system` — the same
            # answer the commit gate reads — is what says so.
            rf"(?:{sys_alt})/SKILL\.md",
            # L4 — system-skill drafts, the pending lifts `discover_system_drafts` hands over.
            _draft_tail("", sys_alt),
            # L5 — the PITFALLS CURATOR's lane, not the lead author's. Both roles spawn under
            # `AgentRole.LEAD_AUTHOR` and `_pydantic_stage.build_stage_agent` re-derives the
            # definition by ROLE from the registry, so one write allow serves both and it must
            # be the union of their two commit scopes. The lead author's own commit gate refuses
            # `execution.md`, so writing one still costs it the batch; splitting the role is the
            # fix and it is filed as follow-up work, not smuggled in here.
            rf"(?:{sys_alt})/execution\.md",
        )
    )


def _rm_skills_grant(skills_dir: Path, systems: tuple[str, ...]) -> Grant:
    """`rm` of ONE draft — the only removal `lead_author.md` gives this lane.

    Narrowed to the `_draft/` lanes for the same recoverable-vs-discard reason as the write
    allow: the old shape matched `rm defender/skills/gather/SKILL.md`, which the gate allowed
    and the commit-gate delete-prohibition then refused by throwing away the batch. Its old
    segment class `[^/ ]+` also excluded a space but not a newline; `SEG` excludes both, which
    is the cross-lane parity `test_cross_surface_parity_out_of_scope_denied_on_both_lanes`
    exists to hold. `..` needs no lookahead now — it is not a `SEG`-shaped system name, and the
    two `_draft` segments are literals.
    """
    spellings = "|".join(re.escape(s) for s in (SKILLS_REL.rstrip("/"), str(skills_dir)))
    sys_alt = "|".join(re.escape(s) for s in systems)
    lanes = "|".join((_draft_tail("gather/queries/", sys_alt), _draft_tail("", sys_alt)))
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


@dataclass(frozen=True)
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
    """Both limits vary per spawn here, so the caller owns the whole context — this is one
    of the two stages where the transport really was threaded through three layers (#713)."""
    # `repo_root` is optional on the SHARED context (the pure-prediction stages bind off the
    # run dir alone) but required here: the skills tree is resolved off the repo. A raise,
    # not an assert — `python -O` strips asserts, and the fallout would be a `NoneType / str`
    # TypeError one frame down.
    repo_root = ctx.repo_root
    if repo_root is None:
        raise ValueError(
            "lead-author stage needs ctx.repo_root: it binds the skills tree off the repo"
        )
    deps = bind(
        LEAD_AUTHOR_DEF, ctx.learning_run_dir,
        # `ctx.salt` is NOT bound (#875): it scopes this stage's PROMPT frames — the set
        # `stage_user_message` announces as one message — while a tool return is framed by
        # `wrap_fresh`, which mints its own salt after the content is in hand.
        defender_dir=repo_root / "defender", box=ctx.box,
    )
    return run_stage(
        stage="lead_author",
        wiring=wiring, ctx=ctx, deps=deps,
        make_model=make_model, require_output=False,
    )


def run_author_stage(
    *,
    wiring: StageWiring,
    ctx: StageContext,
    log_label: str,
    log: Callable[[str], None],
    source_key: Callable[..., object] = config.source_first_party_key,
    run_author: Callable[..., str] = _run_lead_author_pydantic,
) -> int:
    """`wiring` and `ctx` are both built per spawn by the caller — the four model/effort/
    limit/timeout knobs are env-backed, so nothing here may be evaluated at import (#717)."""
    log(
        f"spawn {log_label} in-process "
        f"(model={wiring.model}, effort={wiring.effort}, "
        f"timeout={ctx.wall_clock_timeout}s)"
    )
    source_key(wiring.model, label=log_label)
    try:
        run_author(wiring, ctx)
    except RunUnprocessable as e:
        log(f"{log_label} did not complete (per-run fault): {e}")
        return 124
    log(f"{log_label} done")
    return 0
