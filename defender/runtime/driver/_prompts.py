"""What the model is actually shown: the opening prompt, and the message each turn opens with.

Split out of `driver.py` at 1221 lines. Nothing here builds an agent or spends a budget —
it only assembles text, which is what makes the resume's substitution testable on its own.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Any



from .. import orient
from ..circuit_breaker import RunAborted

from defender import _clock
from defender._env import env_bool
from defender._frontmatter import strip_frontmatter
from defender.hooks.budget_enforcer import (
    DEFAULT_LIMITS,
    BudgetKill,
)


BUDGET_ENFORCE_FLAG = "DEFENDER_BUDGET_ENFORCE"


def enforcement_enabled() -> bool:
    return env_bool(BUDGET_ENFORCE_FLAG, False)

DEFAULT_MODEL = "glm-5.2"
DEFAULT_GATHER_MODEL = "kimi-k2.6"
DEFAULT_REQUEST_LIMIT = 60
GATHER_REQUEST_LIMIT = 40
DEFAULT_TOOL_RETRIES = 10



def _main_instructions(defender_dir: Path) -> str:
    """MAIN's system prompt: the SKILL's BODY, without its frontmatter.

    The frontmatter is file metadata nothing here parses, and it can carry an `allowed-tools:`
    line naming verbs the `ToolSet` does not register. The roster has exactly one enforced
    owner (`MAIN_DEF.tools` → `register_tools`); a second copy in prose can only drift, and
    drifting it teaches the model to call a tool it does not have."""
    return strip_frontmatter((defender_dir / "SKILL.md").read_text(encoding="utf-8"))


def _user_prompt(  # noqa: PLR0913 — the harness's own pre-turn seams (#808)
    run_dir: Path, alert_path: Path, defender_dir: Path,
    *, verbs: Any = None, limits: dict = DEFAULT_LIMITS, run_id: str | None = None,
) -> tuple[str, str, str]:
    """Lead-0's call site, with its OWN exception handler: a `BudgetKill` or
    `circuit_breaker.RunAborted` raised inside `resolve_lead_zero` is caught HERE so it cannot
    end the run before MAIN's first prompt — the section degrades instead.

    Returns `(prompt, ancestor_block, status)`; the block/status feed item 3's dispatch gate,
    computed once here rather than re-resolved by a second lead_zero call."""
    from .. import lead_zero as lead_zero_mod

    ancestor_block = ""
    status = lead_zero_mod.STATUS_FAILED
    try:
        result = lead_zero_mod.resolve_lead_zero(
            run_dir=run_dir, defender_dir=defender_dir, alert_path=alert_path,
            verbs=verbs, limits=limits, run_id=run_id,
        )
        lead_zero_text = lead_zero_mod.render_orient_section(result, run_dir)
        ancestor_block = result.text
        status = result.status
    except (BudgetKill, RunAborted) as e:
        print(f"[run.py] lead-0 degraded ({e!r}); continuing without it", file=sys.stderr)
        degraded = lead_zero_mod.LeadZeroResult(
            text=lead_zero_mod._render_section(
                lead_zero_mod._unavailable(f"a run-level fault interrupted resolution: {e!r}"),
            ),
            status=lead_zero_mod.STATUS_FAILED,
        )
        # `run_dir` here too, not just on the resolved arm: this limb is reached when the
        # resolution was INTERRUPTED, which is the case in which lead-0's declaring `:L
        # findings` row is least likely to be on the page — so it is the arm that most needs
        # the heading's "declare it yourself; that is not reuse" line (#964).
        lead_zero_text = lead_zero_mod.render_orient_section(degraded, run_dir)

    orientation = orient.orientation(
        run_dir, defender_dir, alert_path, lead_zero_section=lead_zero_text,
    )
    prompt = f"Begin the investigation.\n\n{_coordinates(run_dir, alert_path)}\n{orientation}"
    return prompt, ancestor_block, status


def _coordinates(run_dir: Path, alert_path: Path) -> str:
    """The two lines telling MAIN where THIS run's tree is.

    ONE home, because a resumed run needs them for a reason a fresh one does not — every path
    in the inherited prefix names the SOURCE run's dir, and `permission.decide_read` resolves
    its roots from `deps.run_dir`, so a model re-reading `<source>/investigation.md` off its own
    history is denied with no correct path to substitute. Two copies of the header is how a
    third coordinate line gets added to the fresh scaffold and silently never reaches the one
    run that cannot do without it.
    """
    return f"run_dir: {run_dir}\nalert: {alert_path}\n"


def _opening_prompt(  # noqa: PLR0913 — `_user_prompt`'s parameters plus the resume it chooses between
    resume: Any, run_dir: Path, alert_path: Path, defender_dir: Path,
    *, verbs: Any, limits: dict, run_id: str | None,
) -> tuple[str, str, str]:
    """MAIN's first message — for a fresh run or a resumed one.

    A RESUMED run does not orient. Lead-0 and the correlation dispatch are turn-0 work: they
    read the alert cold and resolve its ancestors, and a branch point is by construction past
    that — the defender already holds the payloads. Re-running them would put a second
    orientation section in front of a history that already contains the first, and dispatch a
    lead the source run already ran. `run_investigation` gates that dispatch on `resume is None`
    directly, so the skip is stated where it happens rather than smuggled through a registry
    this function nulls.

    THE COORDINATE HEADER RIDES ALONG, even though the wording of the continuation itself is
    the caller's (the 2026-08-16 experiment's own caveat was that its continuation wording
    biased the run toward closing). It has to: a sibling gets its OWN run dir, while every path
    in the inherited prefix names the SOURCE run's — and `permission.decide_read` resolves its
    roots from `deps.run_dir`, so a model re-reading `<source>/investigation.md` off its own
    history is denied with no correct path to substitute. It is `_coordinates`, the same call
    `_user_prompt` makes; they are coordinates, not instruction.
    """
    if resume is None:
        return _user_prompt(
            run_dir, alert_path, defender_dir, verbs=verbs, limits=limits, run_id=run_id,
        )
    prompt = (
        f"{resume.continuation_prompt}\n\n"
        f"{_coordinates(run_dir, alert_path)}{_branch_clock(resume)}")
    return prompt, "", ""


def _branch_clock(resume: Any) -> str:
    """The line telling a resumed run WHEN it is.

    A COORDINATE, not an instruction, which is why it rides here beside `_coordinates` and not
    in `continuation_prompt`. That field is deliberately the caller's — the 2026-08-16
    experiment's caveat was that its own continuation wording biased the run toward closing — so
    putting the clock there would make it optional (a caller forgets it and the episode silently
    has no clock statement) and per-caller (two siblings' prompts are authored separately, so
    they could disagree about when they are, which is a difference in the one part of the
    prompt that is supposed to be shared).

    It is NOT what closes the ES|QL window — `elastic_adapter.bounded_esql` does that on the
    wire, by splicing a bound in as its own pipe stage, and MAIN is not the role that writes
    those queries anyway (the GATHER subagent is, and its deps carry no clock; see the corpus
    stager's docstring). What this line buys is MAIN's own reasoning: a resumed run reads back
    a history full of dated evidence and has to place "now" against it, and a model that
    silently assumes the wall clock reasons about a gap that does not exist in the world it is
    resuming into.

    `resume.as_of` DIRECTLY, not `getattr(..., None)` with a `""` fallback. `BranchSpec.as_of`
    is a required, non-`Optional` field precisely so a resume without a moment cannot be
    spelled, and re-coalescing it here reopened that: a shape carrying no clock produced a
    prompt with no clock line, silently, which is the failure the field's own docstring says it
    exists to remove. `defender/CLAUDE.md` names the rule — "Resolve an optional input once at
    the boundary, thread it inward non-`Optional`; don't re-coalesce in the body" — and the
    boundary already did the work. An `AttributeError` here is the honest answer for a resume
    shape that is not a `BranchSpec`.
    """
    return f"now: {_clock.z_seconds(resume.as_of)}\n"
