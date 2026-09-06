"""#922 — the capability census (O1) and the reachability census (O5).

O1 is stated as a negative universal: **no compiled policy, capability bit, tool-registration
branch, or deployment grant row survives its last caller.** The design doc's S1/S2 dive says
the discharge is a PATH CENSUS over the registry, the capability bits and the grant table —
"not prose". So every census here DERIVES its answer from the live structures:

  * the role registry, walked as `AGENTS` / `AgentRole` / the operator CLI's own name surface;
  * the capability bits, walked as `dataclasses.fields(ToolSet)` cross-checked against what
    `AGENTS` actually grants and against the `tools.<bit>` guards the production tree spells;
  * the deployment table, PARSED from `knowledge/environment/verb-grants.yaml` through the
    loader that owns it, cross-checked against the live `AgentRole` values.

**None of them holds a list of names a careless deletion could edit into agreement.** That is
the whole design constraint: the first draft of the deletion set stopped at the `ToolSet` bit
and left the grant table's `get-ticket` / `key-pattern` rows with zero grantees (C4), and a
census written as a expected-value snapshot would have been "fixed" by deleting the row from
the snapshot.

O5 is the reachability half: **no production or ops entry point reaches a deleted stage.**
C5 records that a dotted-import grep is NOT sufficient — `learning/ops/replay_actor.py:90`
loads the old actor by FILESYSTEM PATH, and `scripts/policy_cli.py` names two of its modules
as dotted STRINGS it imports at run time. The scanner below covers all three spellings, and
carries its own positive control over a surviving package so it cannot pass by seeing nothing.
"""
from __future__ import annotations

import ast
import dataclasses
import importlib.util
from pathlib import Path

import pytest

from defender.agents import AGENTS
from defender.runtime.agent_definition import ToolSet, effective_tools_for
from defender.runtime.agent_role import AgentRole
from defender.runtime.verb_dispositions import (
    KNOWN_ROLES,
    dispositions_path,
    load_dispositions,
)

DEFENDER = Path(__file__).resolve().parents[1]
REPO_ROOT = DEFENDER.parent

#: Directory names that are not production code. `tests` is excluded because a test naming a
#: deleted stage is a test the deletion takes with it (D10); O5 is about the PRODUCTION and OPS
#: entry points, which is exactly what the obligation says.
_NOT_PRODUCTION = frozenset({".venv", "__pycache__", "tests", ".git", "node_modules", "build"})

#: The package the cutover deletes, in the two spellings a reach can take: the dotted module
#: path an import or an `import_module` string uses, and the path COMPONENT a filesystem load
#: joins. Data, not a symbol — this file must still collect after the package is gone.
DELETED_PACKAGE_DOTTED = "learning.pipeline"
DELETED_PACKAGE_COMPONENT = "pipeline"
DELETED_PACKAGE_DIR = DEFENDER / "learning" / "pipeline"

#: The positive control for the scanner: a package that SURVIVES the cut and is reached by the
#: dotted-import spelling. If the scanner reports nothing for this, it is blind and its silence
#: about the deleted package means nothing.
SURVIVING_PACKAGE_DOTTED = "learning.branch"
#: The path-arm's control, chosen separately and deliberately: `branch` is never spelled as a
#: `/`-joined literal anywhere in production, so using it here would have made the control
#: itself vacuous. `lessons` is — `_paths.py:61`, `learning/ops/trace_lesson.py:57` and the
#: curator config all compose a path through it, and every one of them survives the cut.
SURVIVING_PATH_COMPONENT = "lessons"


def production_sources() -> list[Path]:
    """Every production `.py` in the checkout — `defender/` and the sibling trees beside it.

    The whole checkout rather than `specGraph.codeRoots`, because C5's own census found a
    reacher OUTSIDE those roots (`experiments/oracle-telemetry-fidelity/run_oracle.py`), and a
    census scoped to the roots would have missed it exactly as the first pass did.
    """
    return [
        p for p in sorted(REPO_ROOT.rglob("*.py"))
        if not (set(p.relative_to(REPO_ROOT).parts) & _NOT_PRODUCTION)
    ]


def _dotted_import_reaches(tree: ast.AST, dotted: str) -> bool:
    """Does this module import `dotted` (or something under it) as a MODULE?"""
    for node in ast.walk(tree):
        if (isinstance(node, ast.ImportFrom) and node.module
                and (node.module == dotted or f".{dotted}." in f".{node.module}.")):
            return True
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == dotted or f".{dotted}." in f".{alias.name}.":
                    return True
    return False


def _dotted_string_reaches(tree: ast.AST, dotted: str) -> bool:
    """Does this module carry `dotted` as a MODULE-PATH STRING?

    `scripts/policy_cli.py` reaches two stages this way — `_ACTOR_LEGS` maps a CLI name to
    `"defender.learning.pipeline.malicious_actor.run"` and `_scope_for` hands it to
    `import_module`. An import census cannot see that, and neither can a reader of the import
    block. Whitespace-free is what separates a module path from prose that happens to mention
    the package.
    """
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            text = node.value
            if dotted in text and not any(ch.isspace() for ch in text):
                return True
    return False


def _path_join_reaches(tree: ast.AST, component: str) -> bool:
    """Does this module BUILD a filesystem path through `component`?

    `learning/ops/replay_actor.py:90` composes `learning / "pipeline" / "malicious_actor" /
    "run.py"` and loads the result with `importlib`. That reach is invisible to both censuses
    above, and C5 records it as the one the first pass missed. A `"pipeline"` constant used as
    an operand of `/` is a path segment; the same word in prose is not.
    """
    for node in ast.walk(tree):
        if not (isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div)):
            continue
        for side in (node.left, node.right):
            if isinstance(side, ast.Constant) and side.value == component:
                return True
    return False


def reachers(dotted: str, component: str) -> dict[str, list[str]]:
    """Every production file that reaches `dotted`/`component`, keyed by HOW it reaches.

    Three keys, because the three spellings are three different blind spots and a failure
    message that merged them would send a reader looking in the import block for a path join.
    """
    found: dict[str, list[str]] = {"import": [], "dotted-string": [], "path-join": []}
    for path in production_sources():
        rel = path.relative_to(REPO_ROOT).as_posix()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        if _dotted_import_reaches(tree, dotted):
            found["import"].append(rel)
        if _dotted_string_reaches(tree, dotted):
            found["dotted-string"].append(rel)
        if _path_join_reaches(tree, component):
            found["path-join"].append(rel)
    return found


# ---------------------------------------------------------------------------------------
# O1, layer 1 — the role registry and the surfaces that name a role
# ---------------------------------------------------------------------------------------


def test_922_every_role_key_has_exactly_one_definition_and_every_definition_a_key():
    """CENSUS (derived from the live registry and the live enum).

    O1's first layer, and the invariant D4 says must never be red across the two merges: a role
    KEY with no definition behind it is a compiled grant nothing claims, and a definition whose
    `role` is not a live key is a policy nothing can reach.

    Derived from `AgentRole` and `AGENTS` in both directions, with no expected count and no
    expected name list — D4 moves the roster from eleven to eight here and #1008 takes it to
    nine, and a census that pinned the number would have to be edited by every one of those
    changes, which is precisely the edit that makes a census stop witnessing anything.
    """
    keys = set(AGENTS)
    members = set(AgentRole)
    assert keys == members, (
        f"registry/enum disagreement — keys with no member: {sorted(r.name for r in keys - members)}; "
        f"members with no definition: {sorted(r.name for r in members - keys)}")
    assert members, "positive control: the enum is empty, so this census asserted nothing"
    for role, defn in AGENTS.items():
        assert defn.role is role, (
            f"{role.name} is keyed on a definition that declares role {defn.role.name}")


def test_922_the_operator_policy_cli_names_only_live_roles_and_importable_modules():
    """CENSUS (derived from the CLI's own name surface).

    `scripts/policy_cli.py` compiles and prints a role's policy for an operator, and it carries
    THREE agent names the cutover touches (D2): two actor legs whose scope it resolves by
    importing a dotted module string, and the retired role names behind them.

    The census walks `AGENT_NAMES` — the surface the CLI itself publishes — and demands that
    each one resolves to a live `AgentRole` and, where it names a module, that the module is
    findable. A leftover leg entry pointing into the deleted package fails at `find_spec`,
    which is exactly the O1 defect one layer out from the registry: an operator-facing grant
    surface outliving the thing it grants for.
    """
    from defender.scripts import policy_cli

    assert policy_cli.AGENT_NAMES, "positive control: the CLI publishes no agent names at all"
    for name in policy_cli.AGENT_NAMES:
        role = policy_cli._role_for(name)
        assert role in AGENTS, (
            f"the policy CLI offers agent {name!r}, which resolves to {role}, a role the "
            "registry does not define")
    for name, dotted in policy_cli._ACTOR_LEGS.items():
        assert name in policy_cli.AGENT_NAMES, f"{name} is a leg the CLI does not publish"
        assert importlib.util.find_spec(dotted) is not None, (
            f"the policy CLI's leg {name!r} names module {dotted!r}, which does not exist — "
            "an operator grant surface pointing at a deleted stage")


# ---------------------------------------------------------------------------------------
# O1, layer 2 — the capability bits and their registration branches
# ---------------------------------------------------------------------------------------


def granted_lanes() -> set[str]:
    """Every capability lane some REGISTERED role actually holds.

    Through `effective_tools_for`, not `defn.tools`: it is the one place that knows a role
    whose capability is switched on by a runtime `replace()` past `AGENTS`, and a census that
    read the static bits alone would report a live capability as unclaimed and demand its
    deletion.
    """
    lanes: set[str] = set()
    for defn in AGENTS.values():
        lanes |= set(effective_tools_for(defn))
    return lanes


def guarded_lanes() -> dict[str, list[str]]:
    """Every capability lane the production tree branches on, keyed by lane.

    Found as an attribute access `tools.<lane>` / `<x>.tools.<lane>` over the whole production
    tree rather than over one file: `register_tools` and `_register_deferred_tools` hold ten of
    the eleven guards, and `close` is guarded a package away in `runtime/driver/_build.py`. A
    census pinned to the tool builder would have declared `close` branch-less and been wrong.
    """
    fields = {f.name for f in dataclasses.fields(ToolSet)}
    out: dict[str, list[str]] = {}
    for path in production_sources():
        rel = path.relative_to(REPO_ROOT).as_posix()
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Attribute) and node.attr in fields):
                continue
            base = node.value
            spelled = (base.id if isinstance(base, ast.Name)
                       else base.attr if isinstance(base, ast.Attribute) else None)
            if spelled in ("tools", "toolset", "tool_set"):
                out.setdefault(node.attr, []).append(rel)
    return out


def test_922_no_capability_bit_outlives_the_last_role_that_holds_it():
    """CENSUS (derived from `dataclasses.fields(ToolSet)` and the live registry).

    O1's second layer, stated as an EQUALITY rather than a subset so it bites in both
    directions: every declared `ToolSet` field is granted by at least one registered role, and
    no role grants a lane the dataclass does not declare.

    `closed_tickets` is the live instance the cutover creates. Its only claimant is the old
    benign judge (C4, at every layer that carries it); delete the judge's definition and leave
    the field and this census names it. Nothing here lists `closed_tickets` — the census reads
    the dataclass and the registry, so it will name whatever bit the NEXT retirement strands
    without anyone having thought of it in advance.
    """
    declared = {f.name for f in dataclasses.fields(ToolSet)}
    granted = granted_lanes()
    assert declared, "positive control: ToolSet declares no fields"
    assert granted, "positive control: no registered role grants any lane"
    assert declared - granted == set(), (
        f"capability bit(s) {sorted(declared - granted)} are declared on ToolSet but no "
        "registered role holds them — a compiled grant with no claimant (O1/S2)")
    assert granted - declared == set(), (
        f"role(s) grant lane(s) {sorted(granted - declared)} that ToolSet does not declare")


def test_922_no_tool_registration_branch_outlives_the_last_role_that_holds_its_bit():
    """CENSUS (derived by walking the production tree's own `tools.<bit>` guards).

    O1's second layer again, at the surface the design doc separates from the bit itself: a
    REGISTRATION BRANCH is a grant too — `if tools.closed_tickets:` is what actually reaches
    into the closed-ticket store — and the first draft of the deletion set stopped at the
    `ToolSet` field and left the branch behind (C4).

    Every lane the production tree branches on must be a lane some registered role holds. The
    guard set is derived from the AST, so a branch left behind in ANY module is caught, not
    only one left in `runtime/tools/__init__.py`.
    """
    guarded = guarded_lanes()
    granted = granted_lanes()
    assert "bash" in guarded, (
        f"positive control: the AST walk found only {sorted(guarded)} — it is not seeing the "
        "tool builder's own guards, so its silence about a stranded branch means nothing")
    assert "read" in guarded, (
        f"positive control: the AST walk found only {sorted(guarded)} — it is not seeing the "
        "tool builder's own guards, so its silence about a stranded branch means nothing")
    stranded = {lane: sites for lane, sites in guarded.items() if lane not in granted}
    assert stranded == {}, (
        f"tool-registration/dispatch branch(es) survive their last claimant: {stranded} — the "
        "bit is gone from every registered role but the branch that reaches the capability is "
        "still compiled in (O1/S2)")


# ---------------------------------------------------------------------------------------
# O1, layer 3 — the deployment grant table
# ---------------------------------------------------------------------------------------


def shipped_table():
    """The deployment table of THIS tree, through the loader that owns it.

    `load_dispositions` rather than a hand-rolled `yaml.safe_load`: it is the parser production
    reads the file with, so a table this census called well-formed is one the product would
    actually load. Read from the path rather than `shipped_dispositions()` because that reader
    is `lru_cache`d for the process.
    """
    return load_dispositions(dispositions_path(DEFENDER))


def test_922_no_deployment_grant_row_names_a_role_that_no_longer_exists():
    """CENSUS (derived from the parsed grant table and the live `AgentRole`).

    O1's THIRD layer — the one the first draft missed entirely (C4/S2). `verb-grants.yaml` is
    AUTHORED and per-deployment, so nothing regenerates it; a role deleted from `AgentRole`
    leaves its rows granting to a name nothing answers to, and `KNOWN_ROLES` — which sources
    its members from `AgentRole` precisely so this cannot happen silently — leaves the table's
    own gate blind to it.

    Both directions are asserted: every role NAMED in the table is a live enum value that the
    table's own role vocabulary admits, and every member of that vocabulary is a role the
    registry defines. `judge` sits on three rows today (`list-tickets`, `get-ticket`,
    `key-pattern`).
    """
    rows = shipped_table()
    assert rows, "positive control: the deployment table parsed to zero rows"
    named: set[str] = set()
    for row in rows:
        named |= set(row.roles)
    assert named, "positive control: no row in the table grants to any role"

    live = {role.value for role in AgentRole}
    assert named <= live, (
        f"deployment grant row(s) name role(s) {sorted(named - live)}, which are not members "
        f"of AgentRole — a grant nothing can claim (O1's third layer, {dispositions_path(DEFENDER)})")
    assert named <= set(KNOWN_ROLES), (
        f"the table grants to {sorted(named - set(KNOWN_ROLES))}, outside its own role "
        "vocabulary KNOWN_ROLES")
    assert set(KNOWN_ROLES) <= live, (
        f"KNOWN_ROLES admits {sorted(set(KNOWN_ROLES) - live)}, which AgentRole does not define")


def test_922_every_role_the_grant_table_names_can_actually_dispatch_a_verb():
    """CENSUS (derived from the parsed table and the registry's effective capabilities).

    The complementary direction of the same layer, and the one that catches the OTHER careless
    order of edits: the enum member is kept, the table's rows are kept, and the definition's
    verb-bearing capability goes. `_require_verb_grant_agreement` (S4's guard, a keeper that
    D2 says needs an edit rather than a delete) polices the definition's OWN `verb_grant`; it
    knows nothing about the deployment table, so this arm has no guard today.

    A role granted verbs in the deployment table must hold one of the three verb-bearing bits
    (`query`, `list_verbs`, `closed_tickets`) on its registered definition — otherwise the
    deployment is granting a verb to something that cannot call one.
    """
    rows = shipped_table()
    named: set[str] = set()
    for row in rows:
        named |= set(row.roles)
    assert named, "positive control: no row in the table grants to any role"

    by_value = {role.value: defn for role, defn in AGENTS.items()}
    for value in sorted(named):
        defn = by_value.get(value)
        assert defn is not None, f"the table grants to {value!r}, which the registry does not define"
        lanes = set(effective_tools_for(defn))
        assert lanes & {"query", "list_verbs", "closed_tickets"}, (
            f"the deployment table grants verbs to {value!r}, whose registered definition "
            f"holds no verb-bearing capability (lanes: {sorted(lanes)}) — a deployment grant "
            "with nothing behind it")


def test_922_a_verb_granted_to_nobody_records_why():
    """CENSUS (derived from the parsed table).

    The table's own rule, restated where the cutover can break it: `roles: []` is a DECISION
    and requires `reason:`. D2 has `get-ticket` and `key-pattern` losing their only grantee, so
    the shipped diff must either drop those rows or withhold them deliberately — and a row
    silently emptied is the one outcome neither the file's gate nor a green suite would show.
    """
    rows = shipped_table()
    ungranted = [row for row in rows if not row.roles]
    assert ungranted, (
        "positive control: no row in the table is granted to nobody, so this census had "
        "nothing to check — the rule is unexercised, not satisfied")
    for row in ungranted:
        recorded = (row.reason or "").strip()
        assert recorded, (
            f"{row.system}/{row.verb} is granted to nobody with no reason recorded — absence "
            "of a grantee must be a decision, never residue")


# ---------------------------------------------------------------------------------------
# O5 — no production or ops entry point reaches a deleted stage
# ---------------------------------------------------------------------------------------


def test_922_the_reach_scanner_sees_all_three_spellings():
    """CENSUS positive control — RED-FIRST's paired control, and it must run FIRST.

    The O5 census below is a negative universal, and a negative universal over a scanner that
    finds nothing is a false witness. This drives the SAME scanner over a package the cutover
    keeps (`learning/branch/`) and demands it report reachers, so a later "no reacher" verdict
    is a fact about the tree rather than about the scanner.

    The path-join arm is controlled separately, over the component the ops replayer's own
    filesystem load spells, because it is the arm C5 records the first census as missing and
    the one a reader is most likely to assume is covered by the import arm.
    """
    found = reachers(SURVIVING_PACKAGE_DOTTED, SURVIVING_PATH_COMPONENT)
    assert found["import"], (
        "the scanner found no dotted import of the surviving package — its import arm is blind")
    assert found["path-join"], (
        "the scanner found no filesystem path join through a surviving package component — "
        "its path arm is blind, which is exactly the arm the ops replayer's reach needs")

    # The dotted-STRING arm has no reacher on a surviving package to control it with, so it is
    # controlled on a synthetic module instead: the same predicate, over source it is known to
    # have to match, so the arm is proven live rather than assumed.
    probe = ast.parse('MODULES = {"leg": "defender.learning.pipeline.malicious_actor.run"}\n')
    assert _dotted_string_reaches(probe, DELETED_PACKAGE_DOTTED), (
        "the dotted-string arm does not match a run-time import string — it could not have "
        "seen scripts/policy_cli.py's two legs")
    prose = ast.parse('"""the offline learning pipeline is described here."""\n')
    assert not _dotted_string_reaches(prose, DELETED_PACKAGE_DOTTED), (
        "the dotted-string arm matches prose, so its findings are not module references")


def test_922_no_production_or_ops_entry_point_reaches_a_deleted_stage():
    """CENSUS (post-image of C5; RED at HEAD, which is the deletion's whole point).

    O5. C14 is filed `deferred` in the design doc — "the deletion does not exist yet" — and C5
    is its pre-image: dotted reachers in `agents.py`, `learning/loop.py`,
    `learning/core/subagents.py`, `runtime/tools/__init__.py`, `scripts/policy_cli.py`, the two
    eval files and the experiment driver, PLUS the one no dotted census sees —
    `learning/ops/replay_actor.py:90`, which loads `pipeline/malicious_actor/run.py` by
    filesystem path.

    This is the post-image. It fails at HEAD by construction and turns green exactly when the
    package and its last reacher are gone together. The paired positive control above proves
    the scanner is not simply blind.

    AT HEAD: the deleted package still exists and eleven production files reach it.
    """
    found = reachers(DELETED_PACKAGE_DOTTED, DELETED_PACKAGE_COMPONENT)
    # The path-join arm matches the component wherever it is joined, so it is narrowed to files
    # that ALSO name the deleted tree — the ops replayer composes `learning / "pipeline" / …`.
    path_reachers = [
        rel for rel in found["path-join"]
        if DELETED_PACKAGE_COMPONENT in Path(rel).parts or "learning" in Path(rel).parts
    ]
    assert not DELETED_PACKAGE_DIR.exists(), (
        f"{DELETED_PACKAGE_DIR.relative_to(REPO_ROOT)} still exists — the cutover deletes the "
        "package, and every census below is about what may still point at it")
    assert found["import"] == [], (
        f"production files still import the deleted stages: {found['import']}")
    assert found["dotted-string"] == [], (
        f"production files still name a deleted stage as a run-time import string: "
        f"{found['dotted-string']}")
    assert path_reachers == [], (
        f"production files still load a deleted stage by filesystem path: {path_reachers} — "
        "the reach C5 records a dotted-import census as unable to see")


@pytest.mark.parametrize("dotted", ["learning.core.run_cycle", "learning.core.subagents"])
def test_922_no_production_entry_point_reaches_the_deleted_per_case_cycle(dotted):
    """CENSUS (post-image; RED at HEAD).

    The same rule over the two modules D2 deletes IN FULL beside the stage packages: the
    per-case cycle (`core/run_cycle.py`, whose `run_one` / `learn_drain` are the two CLI stages
    D9 removes) and the stage dispatch protocol (`core/subagents.py`, every import in which is
    a deleted stage).

    Parameterised over the two rather than folded into the sweep above, so a failure names
    which module still has a claimant.

    AT HEAD: `learning/loop.py` and `learning/core/cli.py` import both.
    """
    found = reachers(dotted, "___no_such_component___")
    assert found["import"] == [], (
        f"production files still import {dotted}: {found['import']}")
    assert found["dotted-string"] == [], (
        f"production files still name {dotted} as an import string: {found['dotted-string']}")


# ---------------------------------------------------------------------------------------
# D2/C9 — the keepers: the deletion must not take a symbol the surviving spine still needs
# ---------------------------------------------------------------------------------------

#: The three packages that carry the surviving training spine: the branch loop that produces an
#: episode, the family judge that grades it and appends its rows, and the findings curator that
#: authors them. Named as PACKAGE PATHS rather than as symbol lists — the point of the census
#: below is that the keeper set is read off these packages' own imports.
SPINE_PACKAGES = ("learning/branch", "learning/judge", "learning/author/lessons")

#: The touched modules the keeper set is checked against — the three D2 marks for PARTIAL
#: deletion, where an over-broad cut is the live hazard. `core/persist.py` keeps `queue_lock`
#: and `derive_alert_rule_key`; `core/validate.py` keeps `normalize_judge_yaml` and
#: `strip_yaml_fence`; `core/config.py` keeps everything but the two outcome vocabularies.
PARTIALLY_DELETED = "defender.learning.core"


def spine_imports() -> dict[str, set[str]]:
    """What the surviving spine imports out of the partially-deleted modules, per module.

    Derived by walking the three spine packages' own import blocks, so the keeper set is
    whatever the shipped code asks for on the day the census runs. C9 lists eleven symbols; the
    first draft of the design named three of them, which is the size of the gap a hand-written
    list leaves.
    """
    wanted: dict[str, set[str]] = {}
    for package in SPINE_PACKAGES:
        for path in sorted((DEFENDER / package).rglob("*.py")):
            try:
                tree = ast.parse(path.read_text(encoding="utf-8"))
            except (SyntaxError, UnicodeDecodeError):
                continue
            for node in ast.walk(tree):
                if (isinstance(node, ast.ImportFrom) and node.module
                        and node.module.startswith(PARTIALLY_DELETED)):
                    wanted.setdefault(node.module, set()).update(
                        alias.name for alias in node.names)
    return wanted


def test_922_every_symbol_the_surviving_spine_imports_still_resolves():
    """CENSUS (derived from the spine packages' own import blocks).

    D2's partial-deletion rows are where an over-broad cut does its damage, and C10 is the
    near-miss on record: the design's first draft listed the findings gate for deletion, in the
    wrong file — one row that would have destroyed the thing D8 calls the oracle.

    So the keeper set is not a list here. It is read off what `learning/branch/`,
    `learning/judge/` and `learning/author/lessons/` actually import out of `learning.core.*`,
    and every one of those names is then resolved on the live module. A deletion that takes a
    keeper fails here naming it; a deletion that also removes the importer moves the census
    with it, which is correct — the symbol has genuinely lost its last caller by then.
    """
    wanted = spine_imports()
    assert wanted, (
        f"positive control: the spine packages {SPINE_PACKAGES} import nothing from "
        f"{PARTIALLY_DELETED} — the AST walk is not reading their import blocks")

    missing: dict[str, list[str]] = {}
    for dotted, names in sorted(wanted.items()):
        module = importlib.import_module(dotted)
        gone = sorted(name for name in names if not hasattr(module, name))
        if gone:
            missing[dotted] = gone
    assert missing == {}, (
        f"the surviving spine imports symbol(s) that no longer exist: {missing} — the deletion "
        "took a keeper the branch/judge/curator path still needs (D2's partial rows, C9)")


def test_922_the_findings_gate_and_its_family_partition_are_still_the_channels_one_gate():
    """CENSUS (derived from the shipped author config, not from a module path).

    C10, as an executable claim. The findings channel has ONE gate — `CorpusAuthorConfig.gate`
    — and D8 names the `direction: family` partition inside it as the spine's last stop. The
    design's first draft listed that gate for deletion under the wrong file name, so the fact
    worth pinning is not "a function called `_gate_findings` exists somewhere" but that the
    SHIPPED CONFIG's gate is the one carrying the family partition.

    Derived by building the real config and asking IT which callable is wired in, then driving
    that callable over a family row and a non-family row. A structural check on the function's
    name or module would pass on a config wired to something else entirely.
    """
    from defender.learning.author.lessons.run import build_author_config
    from defender.learning.core.config import LoopPaths

    paths = LoopPaths(repo_root=DEFENDER.parent, state_dir=DEFENDER.parent / "___absent___")
    gate = build_author_config(paths).gate
    assert gate is not None, "the findings channel's config carries no gate"

    family = {"schema_version": 1, "finding_id": "ep/b/0/0", "run_id": "ep",
              "direction": "family", "type": "decision-discipline",
              "judge_outcome": "survived", "subject_anchor": "l-001",
              "subject_topic": "t", "source_run_dir": "episodes/ep/worlds/b"}
    caught = dict(family, finding_id="ep/b/0/1", judge_outcome="caught")

    held, consumed, to_author = gate([family, caught], build_author_config(paths))
    assert [r["finding_id"] for r in to_author] == ["ep/b/0/0"], (
        f"the shipped gate did not admit the `survived` family row for authoring: "
        f"{[r['finding_id'] for r in to_author]}")
    assert [r["finding_id"] for r in consumed] == ["ep/b/0/1"], (
        f"the shipped gate did not consume the `caught` family row: {consumed}")
    assert held == [], f"the shipped gate held a well-formed family row: {held}"


# ---------------------------------------------------------------------------------------
# The two boundaries the design lists as EXPLICIT NON-OBLIGATIONS — pinned, so a wider
# deletion cannot quietly cross them
# ---------------------------------------------------------------------------------------


def test_922_the_ticket_surface_does_not_import_the_old_outcome_vocabulary():
    """CENSUS (derived from `case_history/`'s own import blocks).

    The design's non-obligation, made checkable: the OLD outcome vocabulary is deleted
    (`config.OUTCOME_ENUM`, `BENIGN_OUTCOME_ENUM`), and it "does not vanish" — `case_ticket.py`
    holds its own literal copy of two members for seed eligibility. The doc's reason is that
    the copy "was never an import", and that is exactly the fact worth pinning: the ticket
    surface survives the vocabulary's deletion iff it never reaches into `learning/` for it.

    Derived by walking the package's imports rather than by asserting the literal set, so the
    census stays true if the two members change and fails if the module is "tidied" into
    importing the vocabulary from the module the cutover deletes.
    """
    package = DEFENDER / "scripts" / "case_history"
    assert package.is_dir(), f"positive control: {package} does not exist"

    reaching: dict[str, list[str]] = {}
    seen = 0
    for path in sorted(package.rglob("*.py")):
        seen += 1
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom) and node.module:
                if node.module.startswith("defender.learning"):
                    reaching.setdefault(path.name, []).append(node.module)
            elif isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name.startswith("defender.learning"):
                        reaching.setdefault(path.name, []).append(alias.name)
    assert seen, f"positive control: no modules found under {package}"
    assert reaching == {}, (
        f"the ticket surface imports out of `defender.learning`: {reaching} — the design's "
        "non-obligation rests on it holding its own copy of the seed-eligibility words, and "
        "an import makes deleting the old outcome vocabulary break the ticket lane")


def test_922_the_eval_harness_seeds_the_same_queue_file_the_drain_reads():
    """CENSUS (derived by resolving both sides' paths from the same `LoopPaths`).

    `evals/harness.py::materialize` is a WRITER of the findings queue's shape that no
    import-following census sees: it `shutil.copy`s a scenario's own `findings.jsonl` into a
    temp tree and then runs the real curator against it. It is a harness edge, not a loop edge,
    and it is the reason a row-shape or path change has a second consumer.

    Both sides are resolved from one `LoopPaths` over a synthetic root, so the assertion is an
    identity rather than two spellings of a filename agreeing by luck: whatever the harness
    composes must be exactly the file `LoopPaths.findings` names.
    """
    import tempfile

    from defender.learning.core.config import LoopPaths
    from defender.tests._by_path import load_module

    # By PATH with its own directory on `sys.path`: `evals/harness.py` is a standalone program
    # that imports `_harness_util` by bare name, so a dotted import of it fails at HEAD for a
    # reason that has nothing to do with this demand.
    harness = load_module(DEFENDER / "evals" / "harness.py", name="evals_harness_922",
                          sys_path=(DEFENDER / "evals",))

    with tempfile.TemporaryDirectory() as raw:
        tmp = Path(raw) / "tree"
        scenario = Path(raw) / "scenario"
        scenario.mkdir(parents=True)
        (scenario / "findings.jsonl").write_text("", encoding="utf-8")
        harness.materialize(scenario, tmp)

        expected = LoopPaths(repo_root=tmp).findings.file
        assert expected.is_file(), (
            f"the eval harness materialized a tree whose findings queue is not at {expected} — "
            "the harness seeds a path the curator it then runs does not read")
