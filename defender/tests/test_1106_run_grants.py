"""#1106 — permissions are per run, built from the run's tenant's table (O3, M4).

Before #1106 the verb-disposition table was read ONCE per process, at import, from the checkout
(`shipped_dispositions()`, an `lru_cache`), and three grants were projected from it into module
constants: gather's (`driver._build._GATHER_GRANT` → `GATHER_DEF.verb_grant`), the correlation
lead's (`lead_zero._spec.CORRELATION_GRANT`) and the correlation system
(`CORRELATION_SYSTEM`). A process could therefore only ever hold ONE tenant's permissions, and
whichever table the checkout carried was every run's.

After it, a run loads its own tenant's table at start and builds the grants as a VALUE that
travels with the run: `verb_dispositions.run_grants(settings_dir) -> RunGrants` with `path` (the
resolved table), `gather`, `correlation` and `correlation_system`.

The O3 demand is the two-tenant test: ONE process builds grants for two tenants whose tables
differ, and each run's verb registry admits EXACTLY its own tenant's pairs — the same pair
granted under one and refused under the other. The M4 demand is that nothing reads a table at
import any more, observed with an audit hook on the real `open`, not by grepping for a name.

The refusal text follows the value: a registry built over a run's grant names THAT run's
resolved table when it denies (M4: "those messages name the run's resolved path instead").
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from defender.tests import _tenants1106 as T


def _pairs(grant) -> set[tuple[str, str]]:
    return {(s, v) for s, v, _ in grant.entries}


def _registry(grant, **kw):
    from defender._paths import adapters_under
    from defender.runtime.verbs import ModuleVerbRegistry, read_roster

    return ModuleVerbRegistry(read_roster(adapters_under(T.DEFENDER)), grant, **kw)


# ---- the value ------------------------------------------------------------------------------

def test_run_grants_projects_the_settings_folders_own_table(tmp_path):
    a = T.plant_tenant(tmp_path / "tenants", "acme", table=T.TABLE_A)
    grants = T.run_grants(a / "settings")
    assert Path(grants.path).resolve() == (a / "settings" / "verb-grants.yaml").resolve()
    assert grants.gather.role == "gather"
    assert _pairs(grants.gather) == set(T.GATHER_PAIRS_A)
    assert grants.correlation.role == "lead-zero-correlation"
    assert _pairs(grants.correlation) == set(T.CORRELATION_PAIRS_A)
    assert grants.correlation_system == "elastic"


def test_a_table_that_withholds_the_lead_projects_no_correlation_system(tmp_path):
    b = T.plant_tenant(tmp_path / "tenants", "bravo", table=T.TABLE_B)
    grants = T.run_grants(b / "settings")
    assert _pairs(grants.gather) == set(T.GATHER_PAIRS_B)
    assert grants.correlation.entries == ()
    assert grants.correlation_system is None


def test_a_missing_table_refuses_rather_than_projecting_nothing(tmp_path):
    """An absent table is not a deny-all (#995's standing rule) — it raises, naming the file."""
    vd = T.mod("runtime.verb_dispositions")
    settings = tmp_path / "empty" / "settings"
    settings.mkdir(parents=True)
    with pytest.raises(vd.DispositionError) as caught:
        T.run_grants(settings)
    assert str(settings / "verb-grants.yaml") in str(caught.value)


# ---- O3: two tenants, one process ---------------------------------------------------------------

def test_one_process_holds_two_tenants_grants_and_each_admits_exactly_its_own_pairs(tmp_path):
    """THE O3 test. Both registries are built in this one process, A first then B then A again,
    over the real adapters. `cmdb.get-host` is granted under A and refused under B;
    `identity.get-user` the other way round — positive and negative on the SAME pair. A grant
    fixed per process (the pre-#1106 cache, or a first-tenant-wins memo) answers both tenants
    with one table and fails one side."""
    root = tmp_path / "tenants"
    a = T.plant_tenant(root, "acme", table=T.TABLE_A)
    b = T.plant_tenant(root, "bravo", table=T.TABLE_B)
    grants_a = T.run_grants(a / "settings")
    grants_b = T.run_grants(b / "settings")
    again_a = T.run_grants(a / "settings")

    assert _pairs(grants_a.gather) == set(T.GATHER_PAIRS_A)
    assert _pairs(grants_b.gather) == set(T.GATHER_PAIRS_B)
    assert _pairs(again_a.gather) == set(T.GATHER_PAIRS_A)

    reg_a, reg_b = _registry(grants_a.gather), _registry(grants_b.gather)
    assert reg_a.decide("cmdb", "get-host").outcome == "GRANTED"
    assert reg_b.decide("cmdb", "get-host").outcome != "GRANTED"
    assert reg_b.decide("identity", "get-user").outcome == "GRANTED"
    assert reg_a.decide("identity", "get-user").outcome != "GRANTED"
    # Every pair a table grants is granted by its registry, and none of the other's extras.
    for s, v in T.GATHER_PAIRS_A:
        assert reg_a.decide(s, v).outcome == "GRANTED", (s, v)
    for s, v in T.GATHER_PAIRS_B:
        assert reg_b.decide(s, v).outcome == "GRANTED", (s, v)
    for s, v in T.GATHER_PAIRS_A - T.GATHER_PAIRS_B:
        assert reg_b.decide(s, v).outcome != "GRANTED", (s, v)
    for s, v in T.GATHER_PAIRS_B - T.GATHER_PAIRS_A:
        assert reg_a.decide(s, v).outcome != "GRANTED", (s, v)


def test_a_table_edited_between_two_runs_is_read_again(tmp_path):
    """No per-process cache stands between a run and its tenant's file: the same folder, edited
    between two builds in one process, projects the edit."""
    a = T.plant_tenant(tmp_path / "tenants", "acme", table=T.TABLE_A)
    assert ("cmdb", "get-host") in _pairs(T.run_grants(a / "settings").gather)
    (a / "settings" / "verb-grants.yaml").write_text(T.TABLE_B, encoding="utf-8")
    assert _pairs(T.run_grants(a / "settings").gather) == set(T.GATHER_PAIRS_B)


# ---- M4: no table is read at import ----------------------------------------------------------------

_IMPORT_PROBE = textwrap.dedent("""
    import json, sys
    opened = []
    def hook(event, args):
        if event == "open" and args and isinstance(args[0], (str, bytes)):
            p = args[0].decode() if isinstance(args[0], bytes) else args[0]
            if p.endswith(("verb-grants.yaml", "lead-zero.yaml", "mapping.yaml", "config.env")):
                opened.append(p)
    sys.addaudithook(hook)
    import defender.agents  # noqa: F401 — AGENTS, GATHER_DEF, MAIN_DEF
    import defender.runtime.driver  # noqa: F401
    import defender.runtime.lead_zero  # noqa: F401
    import defender.runtime.verb_dispositions  # noqa: F401
    import defender.scripts.policy_cli  # noqa: F401
    print(json.dumps(opened))
""")


def test_importing_the_runtime_opens_no_settings_file():
    """M4, observed on the real primitive: an audit hook on `open` records every settings-kind
    file the interpreter opens while importing the runtime's grant consumers. Before #1106 the
    table was opened here (the import-time projection); after it, nothing may be — a grant read
    at import is a grant fixed per process, whatever it is named."""
    proc = subprocess.run(
        [sys.executable, "-c", _IMPORT_PROBE],
        capture_output=True, text=True, cwd=T.REPO_ROOT,
        env={**os.environ, "PYTHONPATH": str(T.REPO_ROOT)},
        timeout=300,
    )
    assert proc.returncode == 0, proc.stderr[-4000:]
    opened = json.loads(proc.stdout.strip().splitlines()[-1])
    assert opened == [], opened


def test_the_import_probe_does_see_a_settings_read_when_one_happens(tmp_path):
    """Positive control on the probe itself: the same hook, around a real `run_grants` call,
    records the table it opened — so an empty list above means nothing was opened, not that
    the hook saw nothing."""
    T.plant_tenant(tmp_path / "tenants", "acme")
    settings = tmp_path / "tenants" / "acme" / "settings"
    probe = _IMPORT_PROBE.replace(
        "print(json.dumps(opened))",
        "from defender.runtime.verb_dispositions import run_grants\n"
        f"run_grants(__import__('pathlib').Path({str(settings)!r}))\n"
        "print(json.dumps(opened))",
    )
    proc = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, cwd=T.REPO_ROOT,
        env={**os.environ, "PYTHONPATH": str(T.REPO_ROOT)},
        timeout=300,
    )
    assert proc.returncode == 0, proc.stderr[-4000:]
    opened = json.loads(proc.stdout.strip().splitlines()[-1])
    assert any(p.endswith("verb-grants.yaml") and "acme" in p for p in opened), opened


# ---- the refusal names the run's own table ----------------------------------------------------

def test_a_denied_verb_names_the_runs_own_table_path(tmp_path):
    """A DENIED refusal points at the table the withholding is written in — the RUN's resolved
    table (M4), handed to the registry as `grant_home`. The control: tenant B's registry names
    B's table, not A's, for the same verb."""
    root = tmp_path / "tenants"
    a = T.plant_tenant(root, "acme", table=T.TABLE_A)
    b = T.plant_tenant(root, "bravo", table=T.TABLE_B)
    grants_a, grants_b = T.run_grants(a / "settings"), T.run_grants(b / "settings")
    # A's gather reaches cmdb and does not hold `list-roles`, a verb the cmdb adapter really
    # declares: DENIED, and the pointer names A's table.
    decision_a = _registry(grants_a.gather, grant_home=str(grants_a.path)).decide(
        "cmdb", "list-roles")
    assert decision_a.outcome == "DENIED", decision_a
    assert str(grants_a.path) in (decision_a.refusal or ""), decision_a.refusal
    assert str(grants_b.path) not in (decision_a.refusal or "")
    # B's gather reaches identity and does not hold `can-access`: DENIED, naming B's table.
    decision_b = _registry(grants_b.gather, grant_home=str(grants_b.path)).decide(
        "identity", "can-access")
    assert decision_b.outcome == "DENIED", decision_b
    assert str(grants_b.path) in (decision_b.refusal or ""), decision_b.refusal
    assert str(grants_a.path) not in (decision_b.refusal or "")


def test_the_narrowed_correlation_registry_names_its_inner_registrys_table(tmp_path):
    """Item 3's registry re-grants the production registry under the lead's narrower grant;
    its refusal points at the same run's table as the registry it wraps."""
    from defender.runtime.lead_zero._items import _NarrowedRegistry

    a = T.plant_tenant(tmp_path / "tenants", "acme", table=T.TABLE_A)
    grants = T.run_grants(a / "settings")
    inner = _registry(grants.gather, grant_home=str(grants.path))
    narrowed = _NarrowedRegistry(inner, grants.correlation)
    assert narrowed.decide("elastic", "alerts").outcome == "GRANTED"
    decision = narrowed.decide("elastic", "query")
    assert decision.outcome == "DENIED", decision
    assert str(grants.path) in (decision.refusal or ""), decision.refusal


def test_the_withheld_lead_heading_names_the_runs_table(tmp_path):
    """ORIENT's note for a withheld lead names the run's resolved table; with a target, no
    note. `correlation_system` is the RUN's value — there is no process-level default for it."""
    from defender.runtime.lead_zero import L3, LeadZeroResult, render_orient_section

    b = T.plant_tenant(tmp_path / "tenants", "bravo", table=T.TABLE_B)
    grants = T.run_grants(b / "settings")
    result = LeadZeroResult(text="", status="resolved")
    withheld = render_orient_section(
        result, None, correlation_system=grants.correlation_system, grant_home=str(grants.path))
    assert L3 in withheld and str(grants.path) in withheld, withheld
    dispatched = render_orient_section(
        result, None, correlation_system="elastic", grant_home=str(grants.path))
    assert str(grants.path) not in dispatched, dispatched


# ---- the verb context carries the run's settings folder ------------------------------------------

def test_a_verb_context_without_a_settings_folder_cannot_be_built(tmp_path):
    """M3: `settings_dir` is a REQUIRED field with no default, so every construction site has
    to supply the run's folder — a default would let a site silently read some other one."""
    from defender.runtime.verbs import VerbContext

    with pytest.raises((TypeError, ValueError), match="settings_dir"):
        VerbContext(defender_dir=T.DEFENDER, run_dir=tmp_path, env={})
    ctx = VerbContext(defender_dir=T.DEFENDER, run_dir=tmp_path, env={}, settings_dir=tmp_path)
    assert ctx.settings_dir == tmp_path


# ---- the operator's audit CLI is an entry point too -------------------------------------------------

def test_the_policy_cli_builds_gathers_policy_from_an_injected_root_and_named_tenant(
        tmp_path, capsys):
    """M2: `defender-policy` reached the table at import through `agents.py` → `GATHER_DEF`.
    With no process-level grant it must build gather's grant from a root and a tenant it is
    HANDED — a complete tenant shows gather's policy; an absent one is refused naming the path."""
    policy_cli = T.mod("scripts.policy_cli")
    root = tmp_path / "tenants"
    T.plant_tenant(root, "acme")
    run_dir = tmp_path / "run"
    (run_dir / "gather_raw").mkdir(parents=True)
    base = ["show", "gather", "--run-dir", str(run_dir), "--tenants-root", str(root)]
    assert policy_cli.main([*base, "--tenant", "acme"]) == 0
    assert "agent: gather" in capsys.readouterr().out

    text = ""
    try:
        rc = policy_cli.main([*base, "--tenant", "ghost"])
    except SystemExit as e:
        text = str(e.code)
    except Exception as e:  # noqa: BLE001 — the refusal's text is what is asserted
        text = str(e)
    else:
        assert rc != 0
    text += capsys.readouterr().err
    assert "unrecognized arguments" not in text, text
    assert str(root / "ghost") in text, text
