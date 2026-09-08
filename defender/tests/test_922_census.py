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
import importlib.util
from pathlib import Path


from defender.agents import AGENTS
from defender.runtime.agent_definition import effective_tools_for
from defender.runtime.agent_role import CORRELATION_GRANT_HOLDER, AgentRole
from defender.runtime.verb_dispositions import (
    dispositions_path,
    load_dispositions,
)

#: The names a table row may carry that are NOT roles, mapped to the role whose registered
#: definition actually makes their calls. One entry since #999: the turn-zero correlation lead
#: is bound from `GATHER_DEF`, so gather's compiled policy and tools are what it dispatches
#: through, and only its PROJECTION of the table is narrower. Spelled here rather than skipped,
#: because the census's question — is there something behind this grant that can call a verb —
#: has a real answer for such a holder, and skipping it would leave the one grant #999 added
#: uncensused.
NON_ROLE_HOLDERS = {CORRELATION_GRANT_HOLDER: AgentRole.GATHER}

DEFENDER = Path(__file__).resolve().parents[1]











def _dotted_module_strings(tree: ast.AST) -> set[str]:
    """Every string constant in this module that LOOKS like an importable `defender.` module.

    The complement of `_dotted_string_reaches`: that one asks whether a KNOWN deleted package
    is named, this one enumerates what is named so each can be resolved. Written for the
    surface that used to carry a name->module-path table (`scripts/policy_cli.py`) — with the
    table gone, the check that no such string dangles has to enumerate rather than look for one
    package it already knows about, or it stops constraining anything the moment the spelling
    changes.
    """
    out: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            text = node.value
            if (text.startswith("defender.") and "." in text[9:]
                    and not any(ch.isspace() for ch in text)):
                out.add(text)
    return out






# ---------------------------------------------------------------------------------------
# O1, layer 1 — the role registry and the surfaces that name a role
# ---------------------------------------------------------------------------------------




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
    # THE LEG TABLE IS GONE, and its absence is the assertion. It mapped a CLI name to a
    # module path string handed to `import_module`, which is how this surface reached two
    # stages without an import a census could see. #922 deleted the multi-leg mechanism rather
    # than leaving it behind as an empty map, because an empty map is machinery with no
    # claimant — the same defect one layer out. Asserted as an absence rather than by walking
    # an empty dict, which would have passed vacuously either way.
    assert not hasattr(policy_cli, "_ACTOR_LEGS"), (
        "the policy CLI still carries a leg table; a name->module-path map on this surface is "
        "a reach no import census can see, and no shipped role binds two scopes")
    # The property that table needed checking for, asked of the whole module instead: no
    # module-path STRING anywhere in this file names something that will not import.
    tree = ast.parse((DEFENDER / "scripts" / "policy_cli.py").read_text(encoding="utf-8"))
    for dotted in _dotted_module_strings(tree):
        assert importlib.util.find_spec(dotted) is not None, (
            f"the policy CLI names module {dotted!r} as a string, which does not exist — "
            "an operator grant surface pointing at a deleted stage")


# ---------------------------------------------------------------------------------------
# O1, layer 2 — the capability bits and their registration branches
# ---------------------------------------------------------------------------------------










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

    A name in `roles:` need not BE a role: since #999 the table also names the turn-zero
    correlation lead, which dispatches through gather's definition. `NON_ROLE_HOLDERS` resolves
    such a holder to that definition, so the same question is asked of it rather than skipped.
    """
    rows = shipped_table()
    named: set[str] = set()
    for row in rows:
        named |= set(row.roles)
    assert named, "positive control: no row in the table grants to any role"

    by_value = {role.value: defn for role, defn in AGENTS.items()}
    for value in sorted(named):
        runs_as = NON_ROLE_HOLDERS.get(value)
        defn = by_value.get(runs_as.value if runs_as else value)
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








# ---------------------------------------------------------------------------------------
# D2/C9 — the keepers: the deletion must not take a symbol the surviving spine still needs
# ---------------------------------------------------------------------------------------








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
