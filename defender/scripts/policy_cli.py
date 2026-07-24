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


def _scope_for(
    role: AgentRole, defender_dir: Path, corpus_name: str | None = None,
) -> RunScope:
    if role is AgentRole.ACTOR:
        from defender.learning.core import config
        return RunScope(
            scripts=(config.LESSONS_ENV_RETRIEVE_SCRIPT, config.LESSONS_ACTOR_INDEX_SCRIPT),
            read_confine=(config.LESSONS_ACTOR_DIR, config.LESSONS_ENVIRONMENT_DIR),
        )
    if role is AgentRole.CORPUS_AUTHOR:
        from defender.learning.author.curator_engine import SHIPPED_LESSON_CORPORA
        return RunScope(
            corpus_name=corpus_name,
            read_confine=tuple(
                (defender_dir / name).resolve() for name in SHIPPED_LESSON_CORPORA
            ),
        )
    return RunScope()


def _policy(
    defn: AgentDefinition, run_dir: Path, defender_dir: Path, corpus_name: str | None = None,
) -> AgentPolicy:
    return compile_policy_for(
        defn, run_dir, scope=_scope_for(defn.role, defender_dir, corpus_name),
        defender_dir=defender_dir,
    )


def _containment(g: Grant) -> str:
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
        p.add_argument(
            "--corpus-name", default=None,
            help="the per-spawn corpus name (required for a corpus-requiring role, e.g. corpus_author)",
        )
    args = ap.parse_args(argv)

    role = _ROLES[args.agent]
    defn = AGENTS[role]
    policy = _policy(defn, args.run_dir, args.defender_dir, args.corpus_name)
    if args.cmd == "show":
        return _show(policy, args.agent, args.run_dir, args.defender_dir)
    anchor = args.defender_dir.parent if defn.anchors_on_tree else args.run_dir
    return _explain(
        policy, args.command, args.run_dir, args.defender_dir, args.as_json, cwd_anchor=anchor,
    )


if __name__ == "__main__":
    raise SystemExit(main())
