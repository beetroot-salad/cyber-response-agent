"""`defender-policy` — the gate's audit CLI: what may this agent do, and why was that denied?

Two subcommands:

    defender-policy show <agent> --run-dir <dir> [--defender-dir <tree>]
    defender-policy explain <agent> '<command>' --run-dir <dir> [--defender-dir <tree>] [--json]

`<agent>` is a role name, except that the actor role is bound by two legs with different
scopes and is therefore named per leg: `actor` (adversarial) and `actor_benign`.

The one rule this module lives by: **it is a second CONSUMER of the gate, never a second
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
    effective_tools_for,
)
from defender.runtime.agent_role import AgentRole
from defender.runtime.permission import AgentPolicy
from defender.runtime.permission.grant import OPENS_NOTHING, PROGRAMS, Grant

_ROLES = {r.name.lower(): r for r in AgentRole}

# `actor` is ONE role bound by TWO legs with different scopes: the adversarial leg runs both
# lesson scripts and reads both corpora, the FP-hunting benign leg binds strictly less. A bare
# `actor` therefore names no single answer, so each leg gets its own CLI name and each leg
# module owns the scope it actually binds (there is no copy here to drift).
_ACTOR_LEGS = {
    "actor": "defender.learning.pipeline.malicious_actor.run",
    "actor_benign": "defender.learning.pipeline.benign_actor.run",
}

AGENT_NAMES = sorted(set(_ROLES) | set(_ACTOR_LEGS))


def _role_for(agent: str) -> AgentRole:
    return AgentRole.ACTOR if agent in _ACTOR_LEGS else _ROLES[agent]


def _scope_for(
    role: AgentRole, defender_dir: Path, corpus_name: str | None = None,
    *, agent: str | None = None,
) -> RunScope:
    # `agent` is the CLI NAME and has no default anywhere on this path: a default would have to
    # be one of the two legs, answering every caller that named none with the ADVERSARIAL leg's
    # wider grants. `None` means "no leg was named" — for the actor role, a question with no
    # answer rather than one with a default.
    if role is AgentRole.ACTOR:
        from importlib import import_module

        if agent is None:
            raise ValueError(
                "the actor role is bound by two legs with different scopes — name one of "
                f"{sorted(_ACTOR_LEGS)} rather than being answered with either"
            )
        leg = import_module(_ACTOR_LEGS[agent])
        return RunScope(scripts=leg.ACTOR_SCRIPTS, read_confine=leg.ACTOR_READ_CONFINE)
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
    *, agent: str | None = None,
) -> AgentPolicy:
    # effective_tools_for is the one place that knows any role's typed-capability switching.
    # This tool asks it for "the effective tools for this role" and never names a bit itself, so
    # its own source carries no map of typed capabilities to attack (N4).
    return compile_policy_for(
        defn, run_dir, scope=_scope_for(defn.role, defender_dir, corpus_name, agent=agent),
        defender_dir=defender_dir, tools=effective_tools_for(defn),
    )


def _read_roots(policy: AgentPolicy, run_dir: Path, defender_dir: Path) -> list[str]:
    """The roots a read must land within, straight off the gate's own resolver (N1: a second
    CONSUMER of the gate, never a second model of it).

    The resolver may raise on a hostile operand (symlink cycle, embedded NUL); where the gate
    fails CLOSED, the audit tool reports the fault rather than raising — "this cannot be
    resolved" is an honest answer, a traceback is not."""
    from defender.runtime.permission.files import _resolved_read_roots

    try:
        return [str(p) for p in _resolved_read_roots(policy, run_dir, defender_dir)]
    except (OSError, RuntimeError, ValueError) as e:
        return [f"(unresolvable — the gate refuses every read here: {e})"]


def _shapes(g: Grant) -> str:
    return "[" + ", ".join(s.pattern for s in g.scope) + "]"


def _containment(g: Grant) -> str:
    if g.pins_path:
        base = f"scope: the pattern pins the path (pins_path) — {g.pattern.pattern}"
        # A pins_path grant that ALSO opted into a resolve()+scope recheck on its operand (the
        # curator's `rm`) is not pattern-pinned alone: surface the recheck so the audit does not
        # hide a real containment the gate applies.
        if g.resolve_operand:
            base += f"; operand resolve()d + rechecked against {_shapes(g)}"
        return base
    if PROGRAMS[g.program] is OPENS_NOTHING:
        return "scope: opens nothing (its shape admits no file-opening flag)"
    return "scope: " + _shapes(g)


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
    # The ROOTS are the containment every read is checked against, and for most roles they are
    # the whole answer (`read_allow` is empty) — they are also the one thing that differs
    # between the two actor legs (the adversarial leg confines to both lesson corpora, the
    # benign leg to one). Read off the gate's OWN resolver, never re-derived here.
    print("  roots:")
    for root in _read_roots(policy, run_dir, defender_dir):
        print(f"    {root}")
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
            # The argv half of the verdict (#959 F2/O3): allow/grant/reason alone cannot show
            # the class of change where allow does not move but the argv the gate authorises
            # does, and this is the one surface a human audits.
            "pipelines": None if d.pipelines is None else [
                [list(st.argv) for st in pl.stages] for pl in d.pipelines
            ],
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
        p.add_argument("agent", choices=AGENT_NAMES)
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

    role = _role_for(args.agent)
    defn = AGENTS[role]
    policy = _policy(defn, args.run_dir, args.defender_dir, args.corpus_name, agent=args.agent)
    if args.cmd == "show":
        return _show(policy, args.agent, args.run_dir, args.defender_dir)
    anchor = args.defender_dir.parent if defn.anchors_on_tree else args.run_dir
    return _explain(
        policy, args.command, args.run_dir, args.defender_dir, args.as_json, cwd_anchor=anchor,
    )


if __name__ == "__main__":
    raise SystemExit(main())
