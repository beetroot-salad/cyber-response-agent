"""#1359 the comment action is never a verb (cold read refuses it); an adapter with no agent actions is valid."""
from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from defender.tests.tenancy.case_comment_1359 import _spec1359 as C
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S

ACTION = C.COMMENT_ACTION
DASHED = ACTION.replace("_", "-")


def _source(verbs_body: str, *, export: bool = True) -> str:
    comment = f"\n\ndef {ACTION}(ctx: VerbContext, *, key: str, body: str):\n    return None\n" if export else ""
    return textwrap.dedent("""\
        from defender.systems.verbs import VerbContext


        def check_settings(tenant):
            return None


        def health_check(ctx: VerbContext):
            return {}
        """) + comment + f"\n\nVERBS = {verbs_body}\n"


#: VERBS tables that expose the comment action, by the three spellings r4 names.
HOLDING = {
    "dashed key": f'{{"health-check": health_check, "{DASHED}": {ACTION}}}',
    "underscored key": f'{{"health-check": health_check, "{ACTION}": health_check}}',
    "bare-name value": f'{{"health-check": health_check, "other": {ACTION}}}',
}
CLEAN = '{"health-check": health_check}'


def _tree(tmp_path: Path, source: str, system: str = "casesys") -> Path:
    """A defender-shaped tree whose `integrations/` holds the one adapter."""
    adapters = tmp_path / "integrations"
    adapters.mkdir(parents=True)
    (adapters / f"{system}_adapter.py").write_text(source, encoding="utf-8")
    return tmp_path


def _roster(tree: Path):
    return S.mod("systems.verbs").read_roster(tree / "integrations")


def test_o4_the_cold_read_reports_an_adapter_whose_verbs_expose_the_comment_action(tmp_path):
    """Each spelling of the action in VERBS is reported with a reason naming it and grants no verb; a clean adapter is not. O4 (r4 first layer)."""
    clean = _roster(_tree(tmp_path / "clean", _source(CLEAN)))
    assert "casesys" not in clean.unparsed, "positive control: the clean adapter reads"
    assert "health-check" in clean.declared_verbs("casesys")
    for label, body in HOLDING.items():
        roster = _roster(_tree(tmp_path / label.replace(" ", "-"), _source(body)))
        reason = roster.unparsed.get("casesys", "")
        assert ACTION in reason or DASHED in reason, f"[{label}] no reason naming the action: {dict(roster.unparsed)}"
        assert roster.declared_verbs("casesys") == frozenset(), f"[{label}] verbs were granted"
        assert "casesys" not in roster.refused, f"[{label}] reported as an anomalous file name"


def test_o4_the_census_fails_naming_an_adapter_that_exposes_the_comment_action(tmp_path):
    """`take_census` refuses a tree holding such an adapter, naming it and the action; the clean tree is censused. O4."""
    census = S.mod("cli._tenant_census")
    ok = census.take_census(_tree(tmp_path / "clean", _source(CLEAN)))
    assert ok.walked["casesys"] == frozenset({"health-check"}), "positive control"
    for label, body in HOLDING.items():
        with pytest.raises(census.CensusUnavailable) as caught:
            census.take_census(_tree(tmp_path / label.replace(" ", "-"), _source(body)))
        text = str(caught.value)
        assert "casesys" in text, f"[{label}] {text}"
        assert ACTION in text or DASHED in text, f"[{label}] {text}"


def test_o4_no_checkout_adapter_exposes_the_comment_action(checkout_roster):
    """No adapter in the checkout lists the comment action; the playground ticket adapter exports it. O4."""
    assert checkout_roster.declared_verbs("ticket"), "positive control: verbs were read"
    held = sorted(s for s in checkout_roster.verbs
                  if {DASHED, ACTION} & checkout_roster.declared_verbs(s))
    assert held == [], held
    assert checkout_roster.unparsed == {}, dict(checkout_roster.unparsed)
    module = S.mod("systems.verbs").fresh_adapter_module(checkout_roster, "ticket")
    assert callable(getattr(module, ACTION, None)), "the ticket adapter exports no comment action"


def test_r1_an_empty_verbs_literal_is_a_valid_adapter_with_no_verbs(tmp_path):
    """`VERBS = {}` reads as an accepted adapter with no grantable verb (a regression guard: base already does; the no-readable-VERBS half is the census and resolver arms below). r4."""
    roster = _roster(_tree(tmp_path / "empty", _source("{}")))
    assert "casesys" in roster.adapter_files
    assert "casesys" not in roster.unparsed
    assert roster.declared_verbs("casesys") == frozenset()


def test_r1_the_census_accepts_an_empty_verbs_adapter_and_still_refuses_no_readable_verbs(tmp_path):
    """The census walks `VERBS = {}` as no verbs; an unreadable table (built, not a literal) still blinds it. r4."""
    census = S.mod("cli._tenant_census")
    taken = census.take_census(_tree(tmp_path / "empty", _source("{}")))
    assert taken.walked["casesys"] == frozenset(), taken.walked
    for label, body in (("built", "dict(a=health_check)"), ("absent", None)):
        source = _source("{}") if body is None else _source(body)
        if body is None:
            source = source.rsplit("VERBS", 1)[0]
        with pytest.raises(census.CensusUnavailable):
            census.take_census(_tree(tmp_path / label, source))


def test_r1_the_verb_resolver_accepts_empty_verbs_and_refuses_no_readable_verbs(tmp_path):
    """`VerbResolver.verbs` answers an empty mapping for `VERBS = {}`, but still raises for an unreadable table. r4."""
    rules = S.mod("systems._scaffold_rules")
    assert dict(rules.VerbResolver(_tree(tmp_path / "empty", _source("{}"))).verbs("casesys")) == {}
    bare = _source("{}").rsplit("VERBS", 1)[0]
    with pytest.raises(rules.ScaffoldRuleError):
        rules.VerbResolver(_tree(tmp_path / "bare", bare)).verbs("casesys")
    positive = rules.VerbResolver(_tree(tmp_path / "ok", _source(CLEAN))).verbs("casesys")
    assert "health-check" in positive


def _check_registry_failures(where: Path, source: str) -> list[str]:
    """The failure rows connect's scaffold `check_registry` gives one `casesys` adapter source."""
    scaffold = S.mod("skills.connect.validate_scaffold")
    report = scaffold.Report()
    scaffold.check_registry(report, _tree(where, source), "casesys")
    return [m for status, m in report.rows if status == scaffold.FAIL and "settings check" not in m]


def test_r1_connect_check_registry_needs_no_health_check_for_a_comment_only_adapter(tmp_path):
    """`check_registry` passes an adapter with `VERBS = {}` that exports the comment action; one with verbs still needs health-check. r4."""
    assert _check_registry_failures(tmp_path / "empty", _source("{}")) == []
    no_health = _source('{"other": health_check}')
    assert any("health-check" in m for m in _check_registry_failures(tmp_path / "nh", no_health)), (
        "control: health-check still required")


def test_o4_connect_check_registry_refuses_an_adapter_whose_verbs_hold_the_comment_action(tmp_path):
    """The `/connect` scaffold check fails an adapter whose `VERBS` holds the action (each spelling), naming it; a clean adapter passes. O4 (roster/scaffold check)."""
    assert _check_registry_failures(tmp_path / "clean", _source(CLEAN)) == [], "positive control"
    for label, body in HOLDING.items():
        failed = _check_registry_failures(tmp_path / label.replace(" ", "-"), _source(body))
        assert any(ACTION in m or DASHED in m for m in failed), (
            f"[{label}] the scaffold check does not refuse it, naming the action: {failed}")


def _registry(tree: Path):
    verbs = S.mod("systems.verbs")
    grant = S.mod("systems.verb_grant").VerbGrant(role="gather", entries=())
    return verbs.ModuleVerbRegistry(verbs.read_roster(tree / "integrations"), grant)


def test_r1_the_agents_verb_listing_offers_nothing_for_an_empty_verbs_adapter_and_not_unavailable(
        tmp_path):
    """`list_verbs`' declared-verbs step for a granted-nothing `VERBS = {}` adapter that exports
    the comment action gives no "UNAVAILABLE" line (it offers nothing). Control: an adapter with
    no usable `VERBS` (absent, or not a mapping) is still UNAVAILABLE. r4 no agent actions."""
    catalog = S.mod("investigation.query_catalog")

    def listing(source: str) -> str:
        registry = _registry(_tree(tmp_path / f"t{abs(hash(source))}", source))
        _declared, degradation = catalog._list_verbs_declared(registry, "casesys", "casesys")
        return degradation or ""

    bare = _source("{}").rsplit("VERBS", 1)[0]
    for label, source in (("absent", bare), ("not a mapping", _source("None"))):
        assert "UNAVAILABLE" in listing(source), f"control [{label}]: a broken adapter must stay broken"
    # Why a private call: `_tool_list_verbs` answers "not reachable" before it reads the adapter
    # unless the grant reaches the system, and the grant of an empty-VERBS adapter can reach it only
    # through a row naming a verb the adapter lacks (which no honest tenant plants). So the
    # declared-verbs step is not reachable by a public path for `VERBS = {}`; the implementer who
    # restructures `list_verbs` repairs this one call (FR-2b, repair-1 gap 3).
    assert "UNAVAILABLE" not in listing(_source("{}")), "an empty VERBS adapter is listed as broken"
    # Regression pin on the tool's whole answer (the grant reaches nothing, so it answers before
    # the adapter is read; it must not call the adapter broken either).
    assert "UNAVAILABLE" not in catalog._tool_list_verbs(
        _registry(_tree(tmp_path / "whole", _source("{}"))), "casesys"), (
        "the tool's whole answer for a granted-nothing empty-VERBS system says UNAVAILABLE")


READBACK = C.READBACK_ACTION
READBACK_HOLDING = {
    "dashed key": f'{{"health-check": health_check, "{READBACK.replace("_", "-")}": {READBACK}}}',
    "underscored key": f'{{"health-check": health_check, "{READBACK}": health_check}}',
    "bare-name value": f'{{"health-check": health_check, "other": {READBACK}}}',
}


def _readback_source(verbs_body: str, *, tail: str = "") -> str:
    head, table = _source(verbs_body).rsplit("\n\nVERBS = ", 1)
    return (head + f"\n\ndef {READBACK}(ctx: VerbContext, *, key: str):\n"
            "    return None\n\n\nVERBS = " + table + tail)


def test_1374_the_read_back_action_is_never_a_verb(tmp_path):
    """#1374: the read-back is a host action like the comment: an adapter whose `VERBS` lists it
    in any spelling is refused whole by the cold read and by `/connect`'s scaffold check, and one
    whose table holds it by identity (filled in after the literal) is served no verbs. Control: an
    adapter exporting it outside `VERBS` reads clean."""
    clean = _tree(tmp_path / "clean", _readback_source(CLEAN))
    assert "health-check" in _roster(clean).declared_verbs("casesys"), "positive control"
    assert "health-check" in _registry(clean).verbs("casesys"), "positive control"
    for label, body in READBACK_HOLDING.items():
        where = tmp_path / label.replace(" ", "-")
        roster = _roster(_tree(where, _readback_source(body)))
        reason = roster.unparsed.get("casesys", "")
        assert READBACK in reason or READBACK.replace("_", "-") in reason, (label, dict(roster.unparsed))
        assert roster.declared_verbs("casesys") == frozenset(), label
        failed = _check_registry_failures(tmp_path / f"s-{label.replace(' ', '-')}",
                                          _readback_source(body))
        assert any(READBACK in m or READBACK.replace("_", "-") in m for m in failed), (label, failed)
    hidden = _tree(tmp_path / "hidden",
                   _readback_source(CLEAN, tail=f'\nVERBS["other"] = {READBACK}\n'))
    assert dict(_registry(hidden).verbs("casesys")) == {}, "the identity check let it through"
