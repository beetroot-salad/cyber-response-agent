"""#1342 O11: a job-lane run can write nowhere outside — the structural check that is P1b's
revisit trigger. Adding a write-capable verb class, grant, mount or tool fails it.

Explicit exemption: the launch-time knowledge publish (pushes to the tenant's forge) is lock-guarded,
safe to repeat and kept by #1081; it is not checked here."""
from __future__ import annotations

import importlib
from pathlib import Path

DEFENDER = Path(__file__).resolve().parents[2]


def _shipped_adapters() -> list[str]:
    return sorted(p.stem for p in (DEFENDER / "integrations").glob("*_adapter.py"))


def test_o11_every_shipped_adapter_verb_is_read_class():
    """Each `VERBS` entry of every shipped adapter declares class `r`. (O11)"""
    from defender.kit.verbs import verb_class_of

    adapters = _shipped_adapters()
    assert len(adapters) >= 5, f"premise: the adapters were found: {adapters}"
    declared = {}
    for stem in adapters:
        module = importlib.import_module(f"defender.integrations.{stem}")
        for name, fn in getattr(module, "VERBS", {}).items():
            declared[(stem, name)] = verb_class_of(fn)
    assert declared, "premise: verbs were read"
    assert {k: v for k, v in declared.items() if v != "r"} == {}


def test_o11_the_grant_table_can_grant_only_the_read_class():
    """A disposition naming every role projects to read-class entries only, for every role. (O11)"""
    from defender.systems.verb_dispositions import KNOWN_ROLES, READ_CLASS, Disposition, grant_for

    everyone = Disposition(system="any", verb="write_things", roles=frozenset(KNOWN_ROLES))
    for role in sorted(KNOWN_ROLES):
        entries = grant_for(role, (everyone,)).entries
        assert entries, f"premise: {role} was granted the pair"
        assert {cls for _s, _v, cls in entries} == {READ_CLASS}


def test_o11_the_box_lane_has_no_network_and_the_run_folder_is_its_only_writable_mount(tmp_path):
    """The create argv says `--network none` and binds read-write only the run folder. (O11)"""
    from defender.box import BoxSpec
    from defender.box._lifecycle import _create_argv, _run_lane_mounts
    from defender.records import RUN_LAYOUT

    run_dir = tmp_path / "runs" / "r"
    (run_dir / RUN_LAYOUT.alert_input_dir).mkdir(parents=True)
    (run_dir / RUN_LAYOUT.alert_input_dir / "alert.json").write_text("{}\n", encoding="utf-8")
    mounts = _run_lane_mounts(run_dir, DEFENDER, tmp_path / "agent")
    assert len(mounts) >= 2, "premise: more than the run folder is mounted"
    assert [(m.what, m.source) for m in mounts if not m.readonly] == [("run dir", run_dir)]
    argv = _create_argv("defender-run-1342", run_dir, DEFENDER, BoxSpec(), (), lane=mounts).argv
    assert argv[argv.index("--network") + 1] == "none"
    binds = [a for a in argv if a.startswith("type=bind")]
    assert len(binds) == len(mounts)
    assert [b for b in binds if not b.endswith(",readonly")] == [
        f"type=bind,source={run_dir},target={mounts[0].target}"]


def test_o11_the_job_entry_takes_no_ticket_writer_or_curation_seam():
    """The job entry composes refusing stubs itself: a caller cannot hand it a ticket writer or an enqueue. (O11)"""
    import inspect

    from defender import run as run_py

    params = inspect.signature(run_py.job_main).parameters
    assert "lifecycle" in params, "premise: the job entry takes its seams by keyword"
    assert not {"ticket_writer", "enqueue"} & set(params)


#: The reviewed snapshot (#1342 O11), captured from today's code: the tool names each investigation
#: role registers, from `driver/_build.py` (MAIN_DEF, GATHER_DEF) and `review_roles.py`. Lead zero
#: is a gather lead (`lead_zero/_items.py` builds it from `gather_def_for(grant)`), so it holds the
#: gather names. Adding a tool fails this and forces a look at P1b's revisit trigger.
REVIEWED_TOOLS = {
    "main": ["append_block", "bash", "close_investigation", "fix_row", "read_file"],
    "gather": ["bash", "list_verbs", "query", "read_file", "template_search"],
    "lead-zero": ["bash", "list_verbs", "query", "read_file", "template_search"],
    "support": [],
    "composer": [],
}


class _Recorder:
    """Stands in for the agent: records the name of each tool registered on it."""

    def __init__(self) -> None:
        self.names: list[str] = []

    def tool(self, fn=None, **_kw):
        if fn is not None:
            self.names.append(fn.__name__)
            return fn

        def register(f):
            self.names.append(f.__name__)
            return f
        return register


def _registered(defn) -> list[str]:
    from defender.investigation.close_tool import register_close_tool
    from defender.investigation.tools import register_tools

    agent = _Recorder()
    register_tools(agent, defn.tools, object())
    if defn.tools.close:
        register_close_tool(agent, stages=None, bounds=None)
    return sorted(agent.names)


def test_o11_investigation_role_tools_match_the_reviewed_snapshot():
    """MAIN, gather, lead zero and the review roles register exactly the reviewed tool names. (O11)"""
    from defender.investigation import review_roles
    from defender.investigation.driver import _build

    lead_zero = _build.gather_def_for(_build.GATHER_DEF.verb_grant)
    got = {"main": _registered(_build.MAIN_DEF), "gather": _registered(_build.GATHER_DEF),
           "lead-zero": _registered(lead_zero), "support": _registered(review_roles.SUPPORT_DEF),
           "composer": _registered(review_roles.COMPOSER_DEF)}
    assert got == REVIEWED_TOOLS
    assert got["main"], "premise: the recorder saw real registrations"
    assert got["gather"], "premise: the recorder saw real registrations"
