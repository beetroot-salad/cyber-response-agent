"""Unit tests for `scripts.postmortem.leads.extract`.

Fixtures live in `tests/fixtures/postmortem_leads/`. They cover three
shapes the extractor must distinguish:

  - `inv_with_adhoc.md`   — three real ad-hoc findings (from the
                            rule100001 gold sample).
  - `inv_no_adhoc.md`     — one catalog-templated GATHER lead and one
                            SCREEN-mode lead. Should yield zero ad-hoc
                            records (SCREEN is excluded; templated is
                            not ad-hoc).
  - `inv_template_missing.md` — a catalog lead invoked with a vendor
                            for which no template file exists.
                            Should be classified `template_missing`.

The tests stand up a real path under `knowledge/common-investigation/leads/`
to exercise `_lead_template_path` against actual disk state — the test
process runs from the worktree, so the catalog is whatever the worktree
ships with. That's fine: the catalog is committed and stable.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.postmortem.leads.extract import (
    AdHocLead,
    extract_ad_hoc_leads,
    has_ad_hoc_leads,
)

FIXTURES = Path(__file__).parent / "fixtures" / "postmortem_leads"


def _run_dir_with(fixture_name: str, tmp_path: Path) -> Path:
    """Materialize a fake run dir whose `investigation.md` is a copy of
    `fixtures/postmortem_leads/{fixture_name}` and `meta.json` is the
    shared synthetic meta.
    """
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "investigation.md").write_text(
        (FIXTURES / fixture_name).read_text()
    )
    (run_dir / "meta.json").write_text(
        (FIXTURES / "meta.json").read_text()
    )
    return run_dir


class TestExtractAdHocLeads:
    def test_gold_run_yields_three_findings(self, tmp_path: Path) -> None:
        run_dir = _run_dir_with("inv_with_adhoc.md", tmp_path)
        leads = extract_ad_hoc_leads(run_dir, vendor="wazuh")
        assert len(leads) == 3
        assert [l.finding_id for l in leads] == ["l-001", "l-002", "l-003"]

    def test_explicit_adhoc_template_is_classified(self, tmp_path: Path) -> None:
        run_dir = _run_dir_with("inv_with_adhoc.md", tmp_path)
        leads = extract_ad_hoc_leads(run_dir, vendor="wazuh")
        for lead in leads:
            assert lead.catalog_status == "template_explicit_adhoc"

    def test_query_details_extracted(self, tmp_path: Path) -> None:
        run_dir = _run_dir_with("inv_with_adhoc.md", tmp_path)
        leads = extract_ad_hoc_leads(run_dir, vendor="wazuh")
        l1 = leads[0]
        assert l1.lead_name == "correlated-falco-events"
        assert l1.data_source == "wazuh-indexer"
        assert "rule.groups:falco" in l1.query
        assert l1.substitutions == {"container_id": "2427c46c4575"}
        assert "composition-rule check" in l1.selection_rationale

    def test_literal_adhoc_name_supported(self, tmp_path: Path) -> None:
        run_dir = _run_dir_with("inv_with_adhoc.md", tmp_path)
        leads = extract_ad_hoc_leads(run_dir, vendor="wazuh")
        l3 = next(l for l in leads if l.finding_id == "l-003")
        assert l3.lead_name == "ad-hoc"
        assert l3.data_source == "deploy-runs"

    def test_screen_findings_excluded(self, tmp_path: Path) -> None:
        # `inv_no_adhoc.md` includes a SCREEN-mode finding with
        # template: ad-hoc. SCREEN should be filtered before the
        # ad-hoc check fires.
        run_dir = _run_dir_with("inv_no_adhoc.md", tmp_path)
        leads = extract_ad_hoc_leads(run_dir, vendor="wazuh")
        assert leads == []

    def test_catalog_templated_lead_excluded(self, tmp_path: Path) -> None:
        run_dir = _run_dir_with("inv_no_adhoc.md", tmp_path)
        leads = extract_ad_hoc_leads(run_dir, vendor="wazuh")
        # l-001 is `authentication-history` with template: wazuh, and
        # the catalog ships templates/wazuh.md for it.
        assert all(l.lead_name != "authentication-history" for l in leads)

    def test_template_missing_routes_to_ad_hoc(self, tmp_path: Path) -> None:
        # `process-lineage` has a definition.md but ships no
        # templates/wazuh.md. The agent declared template: wazuh; this
        # is the catalog-exists-but-template-missing branch.
        run_dir = _run_dir_with("inv_template_missing.md", tmp_path)
        leads = extract_ad_hoc_leads(run_dir, vendor="wazuh")
        assert len(leads) == 1
        assert leads[0].lead_name == "process-lineage"
        assert leads[0].catalog_status == "template_missing"

    def test_missing_investigation_md_returns_empty(self, tmp_path: Path) -> None:
        run_dir = tmp_path / "empty-run"
        run_dir.mkdir()
        assert extract_ad_hoc_leads(run_dir, vendor="wazuh") == []

    def test_result_shape_useful(self, tmp_path: Path) -> None:
        run_dir = _run_dir_with("inv_with_adhoc.md", tmp_path)
        leads = extract_ad_hoc_leads(run_dir, vendor="wazuh")
        # l-001 has attribute_updates → useful
        l1 = next(l for l in leads if l.finding_id == "l-001")
        assert l1.result_shape == "useful"

    def test_result_shape_errored_on_failure_reason(self, tmp_path: Path) -> None:
        run_dir = _run_dir_with("inv_with_adhoc.md", tmp_path)
        leads = extract_ad_hoc_leads(run_dir, vendor="wazuh")
        # l-003 has failure_reason: adapter-error
        l3 = next(l for l in leads if l.finding_id == "l-003")
        assert l3.result_shape == "errored"


class TestHasAdHocLeads:
    def test_true_for_gold_fixture(self, tmp_path: Path) -> None:
        text = (FIXTURES / "inv_with_adhoc.md").read_text()
        assert has_ad_hoc_leads(text, vendor="wazuh") is True

    def test_false_for_no_adhoc_fixture(self, tmp_path: Path) -> None:
        text = (FIXTURES / "inv_no_adhoc.md").read_text()
        assert has_ad_hoc_leads(text, vendor="wazuh") is False

    def test_true_for_template_missing(self, tmp_path: Path) -> None:
        text = (FIXTURES / "inv_template_missing.md").read_text()
        assert has_ad_hoc_leads(text, vendor="wazuh") is True

    def test_false_on_empty_text(self) -> None:
        assert has_ad_hoc_leads("", vendor="wazuh") is False

    def test_false_when_no_yaml_blocks(self) -> None:
        text = "# REPORT\n\nThis is narrative-only.\n"
        assert has_ad_hoc_leads(text, vendor="wazuh") is False
