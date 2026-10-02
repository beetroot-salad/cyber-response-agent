"""#1120 piece 1 — a lead-zero refusal names the file its fault is in (code review, third
pass): a correlation grant of the wrong shape is the grant table's, never `lead-zero.yaml`'s.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.runtime.lead_zero import CorrelationDispatchError, resolve_correlation_dispatch
from defender.runtime.verb_grant import GrantError, VerbGrant

_CONFIG = Path("/t/settings/lead-zero.yaml")
_TABLE = Path("/t/settings/verb-grants.yaml")


def _grant(*pairs: tuple[str, str]) -> VerbGrant:
    return VerbGrant(role="lead-zero", entries=tuple((s, v, "r") for s, v in pairs))


@pytest.mark.parametrize("pairs", [
    pytest.param((("elastic", "query"), ("splunk", "query")), id="two-systems"),
    pytest.param((("elastic", "query"), ("elastic", "search")), id="two-query-pairs"),
])
def test_a_grant_of_the_wrong_shape_names_the_table(pairs) -> None:
    with pytest.raises(GrantError) as refused:
        resolve_correlation_dispatch("elastic.x", [], _grant(*pairs), source=_CONFIG,
                                     table=_TABLE)
    assert str(refused.value).startswith(f"{_TABLE}: "), refused.value
    assert str(_CONFIG) not in str(refused.value), refused.value


def test_a_template_fault_names_the_config() -> None:
    """Control: an id no template carries is the config's."""
    with pytest.raises(CorrelationDispatchError) as refused:
        resolve_correlation_dispatch("elastic.nothing", [], _grant(("elastic", "query")),
                                     source=_CONFIG, table=_TABLE)
    assert str(refused.value).startswith(f"{_CONFIG}: "), refused.value


def test_correlation_dispatch_names_the_table_for_a_wrong_shaped_grant(tmp_path: Path) -> None:
    """Through run start's own `correlation_dispatch` over a settings folder holding the
    fixture's `lead-zero.yaml`: a two-system grant names `verb-grants.yaml`, not the config."""
    from defender.runtime.run_tenant import correlation_dispatch
    from defender.tests.tenant_1120_piece1 import _spec1120 as H

    settings = tmp_path / "settings"
    settings.mkdir()
    (settings / "lead-zero.yaml").write_bytes(
        (H.FIXTURE / "settings" / "lead-zero.yaml").read_bytes())
    with pytest.raises(GrantError) as refused:
        correlation_dispatch(settings, [], _grant(("elastic", "query"), ("splunk", "query")))
    assert str(refused.value).startswith(f"{settings / 'verb-grants.yaml'}: "), refused.value
