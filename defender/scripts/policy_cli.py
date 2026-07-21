"""`defender-policy` — the gate's audit CLI: what may this agent do, and why was that denied?

Two subcommands:

    defender-policy show <agent> --run-dir <dir> [--defender-dir <tree>]
    defender-policy explain <agent> '<command>' --run-dir <dir> [--defender-dir <tree>] [--json]

The reason "how did this resolve?" took effort before is that there was NO tool: everyone
hand-rolled a `bind(MAIN_DEF, …)` probe in a REPL, which is both tedious and a second model of
the gate waiting to drift from it.

So the one rule this module lives by: **it is a second CONSUMER of the gate, never a second
implementation.** `explain` calls `permission.decide_bash` — the same function the driver calls
— and prints what it returns. An audit tool that models the gate separately is worse than no
audit tool, because it certifies a policy nobody runs.

It is an OPERATOR tool, not an agent one: `hooks/_cmd_segments.OPERATOR_TOOLS` keeps it out of
the adapter taxonomy, and no agent's grant list names it, so every agent's lane denies it. An
agent that could read its own gate would hold a map of what to attack — and the judge, a map of
exactly which grants stand between it and the answer key."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from defender._paths import PATHS
from defender.agents import AGENTS
from defender.runtime import permission
from defender.runtime.agent_definition import (
    AgentDefinition,
    RunScope,
    compile_policy_for,
)
from defender.runtime.agent_role import AgentRole
from defender.runtime.permission import AgentPolicy
from defender.runtime.permission.grant import OPENS_NOTHING, PROGRAMS, Grant

_ROLES = {r.name.lower(): r for r in AgentRole}


def _scope_for(role: AgentRole, defender_dir: Path) -> RunScope:
    """The per-invocation inputs a static def cannot carry. `show`/`explain` audit the agent's
    MAXIMAL surface — the actor with both pinned scripts. The judge's benign-only closed-ticket
    read is a typed tool now (#672), authorized by registration rather than a bash grant, so it
    carries no per-invocation scope here; both legs compile the same cat + defender-sql lane.
    Imported lazily: the learning config pulls the pipeline, and `show main` should not pay for
    it."""
    if role is AgentRole.ACTOR:
        from defender.learning.core import config
        return RunScope(
            scripts=(config.LESSONS_ENV_RETRIEVE_SCRIPT, config.LESSONS_ACTOR_INDEX_SCRIPT),
            read_confine=(config.LESSONS_ACTOR_DIR, config.LESSONS_ENVIRONMENT_DIR),
        )
    return RunScope()


def _policy(defn: AgentDefinition, run_dir: Path, defender_dir: Path) -> AgentPolicy:
    if not defn.bindable:
        # The curator's policy is per-SPAWN, built from a worktree corpus dir its def cannot
        # carry, so there is no run-dir-only projection of it to print. Say so rather than
        # print a policy the curator never runs under.
        raise SystemExit(
            f"{defn.role.name.lower()} builds its policy per-spawn from a worktree corpus dir "
            "(bindable=False) — there is nothing to compile from a run dir alone. Read "
            "learning/author/curator_engine._corpus_author_policy."
        )
    return compile_policy_for(
        defn, run_dir, scope=_scope_for(defn.role, defender_dir), defender_dir=defender_dir,
    )


def _containment(g: Grant) -> str:
    """What CONFINES this grant's operands. An exempt (`pins_path`) grant must report its
    PATTERN, never a bare `scope: []` — an empty scope reads as "unconfined" when the pattern IS
    the confinement (the actor's pinned lesson scripts are the case: the exact command lives in
    the pattern, and there is no file operand for a scope to bound)."""
    if g.pins_path:
        return f"scope: the pattern pins the path (pins_path) — {g.pattern.pattern}"
    if PROGRAMS[g.program] is OPENS_NOTHING:
        return "scope: opens nothing (its shape admits no file-opening flag)"
    return "scope: [" + ", ".join(s.pattern for s in g.scope) + "]"


def _show(policy: AgentPolicy, name: str, run_dir: Path, defender_dir: Path) -> int:
    print(f"agent: {name}")
    print(f"run-dir: {run_dir}")
    print(f"defender-dir: {defender_dir}\n")
    print("bash:")
    for g in policy.bash_allow:
        route = "" if g.route is permission.Route.PLAIN else f"  route: {g.route.value}"
        print(f"  {g.program}{route}")
        print(f"      shape: {g.pattern.pattern}")
        print(f"      {_containment(g)}")
    print("\nread:")
    for s in policy.read_allow or ():
        print(f"  {s.pattern}")
    if not policy.read_allow:
        print("  (no shape filter — reads are bounded by the roots alone)")
    print("\nwrite:")
    for s in policy.write_allow or ():
        print(f"  {s.pattern}")
    if not policy.write_allow:
        print("  (nothing — this agent may not write)")
    return 0


def _explain(  # noqa: PLR0913 — the gate's own call shape, plus the output-format flag
    policy: AgentPolicy, command: str, run_dir: Path, defender_dir: Path, as_json: bool,
    *, cwd_anchor: Path,
) -> int:
    # `cwd_anchor` is threaded because this CLI is a second CONSUMER of the gate, never a second
    # implementation — and since #540 the anchor a RELATIVE operand rebases on is per-role data.
    # Omit it and `explain` would silently answer for the run-dir anchor while a tree-anchored
    # role (lead author) really runs on its worktree root: the audit tool would report DENY for
    # a command production ALLOWs, which is the one failure mode an audit tool cannot have.
    d = permission.decide_bash(
        command, policy=policy, run_dir=run_dir, defender_dir=defender_dir,
        cwd_anchor=cwd_anchor,
    )
    grants = [g.program for g in d.grants]
    if as_json:
        out: dict[str, Any] = {
            "allow": d.allow,
            "grant": grants,
            "reason": d.reason or "",
        }
        print(json.dumps(out))
        return 0
    print("ALLOW" if d.allow else "DENY")
    if d.allow:
        print("matched: " + ", ".join(grants))
    else:
        print(f"reason: {d.reason}")
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="defender-policy", description=__doc__)
    sub = ap.add_subparsers(dest="cmd", required=True)
    for name in ("show", "explain"):
        p = sub.add_parser(name)
        p.add_argument("agent", choices=sorted(_ROLES))
        if name == "explain":
            p.add_argument("command")
            p.add_argument("--json", action="store_true", dest="as_json")
        p.add_argument("--run-dir", required=True, type=Path)
        p.add_argument("--defender-dir", type=Path, default=PATHS.defender_dir)
    args = ap.parse_args(argv)

    role = _ROLES[args.agent]
    defn = AGENTS[role]
    policy = _policy(defn, args.run_dir, args.defender_dir)
    if args.cmd == "show":
        return _show(policy, args.agent, args.run_dir, args.defender_dir)
    # The same resolution `agent_definition.bind` performs, off the same `anchors_on_tree` bit —
    # so the CLI and the runtime cannot answer differently about where an operand anchors.
    anchor = args.defender_dir.parent if defn.anchors_on_tree else args.run_dir
    return _explain(
        policy, args.command, args.run_dir, args.defender_dir, args.as_json, cwd_anchor=anchor,
    )


if __name__ == "__main__":
    raise SystemExit(main())
