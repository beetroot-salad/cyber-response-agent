"""`defender-policy` — the gate's audit CLI: what may this agent do, and why was that denied?

Two subcommands:

    defender-policy show <agent> --run-dir <dir> [--defender-dir <tree>]
    defender-policy explain <agent> '<command>' --run-dir <dir> [--defender-dir <tree>] [--json]

Gather's verb grant belongs to a run and is projected from one tenant's table, so `gather` also
takes `--tenant <id>`, accepted under `$DEFENDER_DATA_ROOT` exactly as a run accepts it: the
policy shown is the one a run for that tenant would compile.

`<agent>` is a role name.

This is a second consumer of the gate, never a second implementation: `explain` calls
`permission.decide_bash`, the same function the driver calls, and prints what it returns. An
audit tool that modelled the gate separately would certify a policy nobody runs.

An operator tool, not an agent one: `hooks/_cmd_segments.OPERATOR_TOOLS` keeps it out of the
adapter taxonomy and no agent's grant names it. An agent able to read its own gate would hold a
map of what to attack."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from defender._paths import PATHS
from defender._tenants import add_tenant_arguments
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

# One CLI name per role. A role bound by two legs with different scopes would need its own
# per-leg names reintroduced explicitly.
AGENT_NAMES = sorted(_ROLES)


def _role_for(agent: str) -> AgentRole:
    return _ROLES[agent]


def _scope_for(
    role: AgentRole, defender_dir: Path, corpus_name: str | None = None,
    *, agent: str | None = None,
) -> RunScope:
    if role in (AgentRole.CORPUS_AUTHOR, AgentRole.CORPUS_REPAIR):
        from defender.learning.author.curator_engine import lesson_read_confine
        return RunScope(corpus_name=corpus_name, read_confine=lesson_read_confine(defender_dir))
    return RunScope()


def _policy(
    defn: AgentDefinition, run_dir: Path, defender_dir: Path, corpus_name: str | None = None,
    *, agent: str | None = None,
) -> AgentPolicy:
    # `effective_tools_for` owns any role's typed-capability switching, so this source carries
    # no map of capabilities to attack.
    return compile_policy_for(
        defn, run_dir, scope=_scope_for(defn.role, defender_dir, corpus_name, agent=agent),
        defender_dir=defender_dir, tools=effective_tools_for(defn),
    )


def _definition(role: AgentRole, defender_dir: Path, tenant: str | None) -> AgentDefinition:
    """The role's definition as a run would bind it. Gather's grant is the named tenant's,
    accepted and resolved the way a run does (and refused, like a run, when gather could query
    nothing); other roles carry their own grant."""
    defn = AGENTS[role]
    if role is not AgentRole.GATHER:
        return defn
    from defender import _tenant
    from defender.runtime import run_tenant as run_tenant_mod
    from defender.runtime.driver import gather_def_for

    try:
        requested = _tenant.requested_tenant_id(tenant)
        run = run_tenant_mod.resolve_tenant(
            _tenant.resolve_data_root(), requested, defender_dir=defender_dir,
            dispatches_lead_zero=False)
    except run_tenant_mod.TenantRefused as refusal:
        sys.exit(f"defender-policy: {refusal}")
    return gather_def_for(run.grants.gather)


def _read_roots(policy: AgentPolicy, run_dir: Path, defender_dir: Path) -> list[str]:
    """The roots a read must land within, straight off the gate's own resolver.

    The resolver may raise on a hostile operand (symlink cycle, embedded NUL); where the gate
    fails closed, this reports the fault rather than a traceback."""
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
        # A pins_path grant that also rechecks its resolved operand (the curator's `rm`):
        # show the recheck too.
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
    # The roots bound every read and, with `read_allow` usually empty, are most roles' whole
    # answer. Read off the gate's own resolver.
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
            # The authorised argv: allow/grant/reason alone cannot show a change where the
            # verdict holds but the argv moves.
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
    # The authorised argv here too, since this is the surface an operator reads. Connector and
    # stderr routing are included: `A && B` demoted to `A ; B`, or a rerouted stderr, leave both
    # argv and verdict identical.
    for pl in d.pipelines or ():
        stages = " | ".join(
            " ".join(repr(t) for t in st.argv)
            + ("" if st.stderr == "capture" else f"  2>{st.stderr}")
            for st in pl.stages
        )
        print(f"  argv ({pl.connector}): {stages}")
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
        add_tenant_arguments(p, reads="verb-grants.yaml a gather policy is built from")
        p.add_argument(
            "--corpus-name", default=None,
            help="the per-spawn corpus name (required for a corpus-requiring role, e.g. corpus_author)",
        )
    args = ap.parse_args(argv)

    role = _role_for(args.agent)
    defn = _definition(role, args.defender_dir, args.tenant)
    policy = _policy(defn, args.run_dir, args.defender_dir, args.corpus_name, agent=args.agent)
    if args.cmd == "show":
        return _show(policy, args.agent, args.run_dir, args.defender_dir)
    anchor = args.defender_dir.parent if defn.anchors_on_tree else args.run_dir
    return _explain(
        policy, args.command, args.run_dir, args.defender_dir, args.as_json, cwd_anchor=anchor,
    )


if __name__ == "__main__":
    from defender._log import configure_from_env
    configure_from_env()
    raise SystemExit(main())
