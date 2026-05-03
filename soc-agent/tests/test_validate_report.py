"""Tests for report validation (Tier 1 + Tier 2 hook architecture).

Tests the validate_report.py hook: PostToolUse event parsing, run directory
extraction, Tier 1 deterministic validation, and Tier 2 helper functions.
"""

import json
import sys
from pathlib import Path

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from schemas.report_frontmatter import (
    ReportFrontmatter,
    parse_frontmatter,
)
import hooks.scripts.validate_report as vr
from hooks.scripts.validate_report import (
    check_archetype_exists,
    check_precedent_exists,
    extract_run_dir,
    get_precedent_max_age,
    get_run_salt,
    is_screen_resolved,
    load_archetype_frontmatter,
    playbook_has_screen_section,
    validate_archetype_anchors,
    validate_precedent_content,
    validate_temporal_anchors_reconfirmed,
    validate_tier1,
    wrap_untrusted,
)
from schemas.precedent import DEFAULT_MAX_AGE_DAYS, check_recency, parse_captured_at

FIXTURES = SOC_AGENT_ROOT / "tests" / "fixtures" / "reports"


# --- ReportFrontmatter validation ---


class TestReportFrontmatter:
    def _make_valid(self, **overrides):
        defaults = dict(
            ticket_id="SEC-001",
            signature_id="wazuh-rule-5710",
            status="escalated",
            disposition="true_positive",
            confidence="high",
            leads_pursued=3,
        )
        defaults.update(overrides)
        return ReportFrontmatter(**defaults)

    def test_valid_escalate(self):
        r = self._make_valid()
        assert r.validate() == []

    def test_valid_resolved(self):
        r = self._make_valid(
            status="resolved",
            disposition="benign",
            matched_archetype="monitoring-probe",
            matched_ticket_id="SEC-2024-001",
        )
        assert r.validate() == []

    def test_missing_ticket_id(self):
        r = self._make_valid(ticket_id="")
        errors = r.validate()
        assert any("ticket_id" in e for e in errors)

    def test_invalid_status(self):
        r = self._make_valid(status="closed")
        errors = r.validate()
        assert any("status" in e for e in errors)

    def test_invalid_disposition(self):
        r = self._make_valid(disposition="malware")
        errors = r.validate()
        assert any("disposition" in e for e in errors)

    def test_invalid_confidence(self):
        r = self._make_valid(confidence="very_high")
        errors = r.validate()
        assert any("confidence" in e for e in errors)

    def test_resolved_requires_archetype(self):
        r = self._make_valid(status="resolved", matched_archetype=None)
        errors = r.validate()
        assert any("matched_archetype" in e for e in errors)

    def test_ticket_id_without_archetype_rejected(self):
        r = self._make_valid(
            status="resolved",
            disposition="benign",
            matched_archetype=None,
            matched_ticket_id="SEC-2024-001",
        )
        errors = r.validate()
        assert any("matched_ticket_id" in e for e in errors)

    def test_negative_leads(self):
        r = self._make_valid(leads_pursued=-1)
        errors = r.validate()
        assert any("leads_pursued" in e for e in errors)


# --- parse_frontmatter ---


class TestParseFrontmatter:
    def test_missing_required_fields(self):
        report, errors = parse_frontmatter({"ticket_id": "SEC-001"})
        assert report is None
        assert len(errors) >= 4

    def test_valid_dict(self):
        fields = {
            "ticket_id": "SEC-001",
            "signature_id": "wazuh-rule-5710",
            "status": "escalated",
            "disposition": "true_positive",
            "confidence": "high",
            "leads_pursued": 3,
        }
        report, errors = parse_frontmatter(fields)
        assert errors == []
        assert report.ticket_id == "SEC-001"

    def test_coerces_leads_to_int(self):
        fields = {
            "ticket_id": "SEC-001",
            "signature_id": "wazuh-rule-5710",
            "status": "escalated",
            "disposition": "true_positive",
            "confidence": "high",
            "leads_pursued": "3",
        }
        report, errors = parse_frontmatter(fields)
        assert errors == []
        assert report.leads_pursued == 3


# --- Tier 1 validation with fixtures ---


class TestValidateFixtures:
    def test_valid_resolved_report(self):
        passed, errors, _ = validate_tier1(FIXTURES / "valid_resolved.md")
        assert passed, f"Expected valid but got errors: {errors}"

    def test_valid_escalate_report(self):
        passed, errors, _ = validate_tier1(FIXTURES / "valid_escalate.md")
        assert passed, f"Expected valid but got errors: {errors}"

    def test_invalid_missing_fields(self):
        passed, errors, _ = validate_tier1(FIXTURES / "invalid_missing_fields.md")
        assert not passed
        assert any("missing required field" in e for e in errors)

    def test_invalid_no_precedent(self):
        passed, errors, _ = validate_tier1(FIXTURES / "invalid_no_precedent.md")
        assert not passed
        assert any("not found" in e for e in errors)

    def test_invalid_bad_enums(self):
        passed, errors, _ = validate_tier1(FIXTURES / "invalid_bad_enums.md")
        assert not passed
        assert any("status" in e for e in errors)


# --- Screen-resolved validation ---


class TestScreenResolved:
    """Tests for screen-resolved report validation in Tier 1."""

    SCREEN_REPORT = """\
---
ticket_id: SEC-SCREEN-001
signature_id: wazuh-rule-5710
status: resolved
disposition: benign
confidence: high
matched_archetype: monitoring-probe
trust_anchors_consulted:
  - anchor: approved-monitoring-sources
    kind: org-authority
    result: confirmed
    citation: playground monitoring-host cron
leads_pursued: 1
trace: "screen(monitoring-probe, auth-history) -> benign:monitoring-probe"
---

# Investigation Report: SEC-SCREEN-001

## Summary
Screen-resolved monitoring probe.
"""

    def _setup_screen_run(self, tmp_path, history):
        """Create a run dir with state.json and report.md."""
        run_dir = tmp_path / "run-screen"
        run_dir.mkdir()
        state = {"phase": history[-1], "history": history}
        (run_dir / "state.json").write_text(json.dumps(state))
        (run_dir / "report.md").write_text(self.SCREEN_REPORT)
        return run_dir

    def test_screen_resolved_passes_tier1(self, tmp_path):
        """Screen-resolved report passes Tier 1 (leads floor is enforced at
        REPORT transition now, not report validation)."""
        run_dir = self._setup_screen_run(
            tmp_path, ["CONTEXTUALIZE", "SCREEN", "REPORT"]
        )
        passed, errors, _ = validate_tier1(run_dir / "report.md")
        assert passed, f"Expected pass but got: {errors}"

    def test_screen_resolved_requires_screen_section(self, tmp_path):
        """Screen-resolved report fails if playbook has no ## Screen section."""
        report_text = self.SCREEN_REPORT.replace(
            "wazuh-rule-5710", "nonexistent-sig"
        )
        run_dir = tmp_path / "run-no-playbook"
        run_dir.mkdir()
        state = {"phase": "REPORT", "history": ["CONTEXTUALIZE", "SCREEN", "REPORT"]}
        (run_dir / "state.json").write_text(json.dumps(state))
        (run_dir / "report.md").write_text(report_text)
        passed, errors, _ = validate_tier1(run_dir / "report.md")
        assert not passed
        assert any("Screen section" in e for e in errors)

    def test_is_screen_resolved_no_state(self, tmp_path):
        """No state.json means not screen-resolved."""
        assert is_screen_resolved(tmp_path) is False

    def test_is_screen_resolved_with_hypothesize(self, tmp_path):
        """SCREEN in history but also PREDICT means fallthrough, not screen-resolved."""
        state = {
            "history": ["CONTEXTUALIZE", "SCREEN", "PREDICT", "GATHER", "ANALYZE", "REPORT"]
        }
        (tmp_path / "state.json").write_text(json.dumps(state))
        assert is_screen_resolved(tmp_path) is False

    def test_playbook_has_screen_section_true(self):
        assert playbook_has_screen_section("wazuh-rule-5710") is True

    def test_playbook_has_screen_section_nonexistent(self):
        assert playbook_has_screen_section("nonexistent-sig") is False


# --- Precedent existence check ---


# --- Precedent content validation ---


@pytest.fixture
def fake_root(tmp_path, monkeypatch):
    """Redirect SOC_AGENT_ROOT to a temp dir and restore after test."""
    monkeypatch.setattr(vr, "SOC_AGENT_ROOT", tmp_path)
    return tmp_path


def _make_precedent_file(
    root: Path, sig: str, archetype: str, ticket_id: str, data: dict
) -> Path:
    """Helper: create a precedent JSON file under a fake SOC_AGENT_ROOT.

    New layout: archetypes/{archetype}/{TICKET-ID}.json.
    """
    arch_dir = (
        root / "knowledge" / "signatures" / sig / "archetypes" / archetype
    )
    arch_dir.mkdir(parents=True, exist_ok=True)
    filename = ticket_id if ticket_id.endswith(".json") else f"{ticket_id}.json"
    path = arch_dir / filename
    path.write_text(json.dumps(data))
    return path


def _valid_precedent_dict(**overrides):
    """Build a schema-valid precedent dict for use in fake_root tests."""
    data = {
        "ticket_id": "SEC-2026-001",
        "archetype": "test-arch",
        "captured_at": "2026-04-01",
        "disposition": "benign",
        "narrative": "Test precedent narrative.",
        "alert": {"rule": {"id": "test"}},
        "anchors_at_time": [],
    }
    data.update(overrides)
    return data


def _make_permissions_yaml(root: Path, sig: str, content: str) -> Path:
    """Helper: create a permissions.yaml under a fake SOC_AGENT_ROOT."""
    cfg_dir = root / "config" / "signatures" / sig
    cfg_dir.mkdir(parents=True, exist_ok=True)
    path = cfg_dir / "permissions.yaml"
    path.write_text(content)
    return path


class TestValidatePrecedentContent:
    def test_valid_precedent(self, fake_root):
        """Valid precedent with matching archetype and recent captured_at."""
        _make_precedent_file(
            fake_root, "test-sig", "test-arch", "SEC-001",
            _valid_precedent_dict(ticket_id="SEC-001"),
        )
        errors = validate_precedent_content(
            "test-arch", "SEC-001", "test-sig"
        )
        assert errors == []

    def test_archetype_field_mismatch(self, fake_root):
        """Precedent with archetype field that doesn't match parent dir is rejected."""
        _make_precedent_file(
            fake_root, "test-sig", "test-arch", "SEC-001",
            _valid_precedent_dict(archetype="OTHER-ARCH"),
        )
        errors = validate_precedent_content(
            "test-arch", "SEC-001", "test-sig"
        )
        assert any("does not match parent directory" in e for e in errors)

    def test_missing_captured_at(self, fake_root):
        """Precedent without captured_at is flagged."""
        data = _valid_precedent_dict()
        del data["captured_at"]
        _make_precedent_file(fake_root, "test-sig", "test-arch", "SEC-001", data)
        errors = validate_precedent_content(
            "test-arch", "SEC-001", "test-sig"
        )
        assert any("captured_at" in e for e in errors)

    def test_stale_precedent(self, fake_root):
        """Precedent older than max_age is rejected."""
        _make_precedent_file(
            fake_root, "test-sig", "test-arch", "SEC-001",
            _valid_precedent_dict(captured_at="2020-01-01"),
        )
        errors = validate_precedent_content(
            "test-arch", "SEC-001", "test-sig"
        )
        assert any("days old" in e for e in errors)

    def test_malformed_json(self, fake_root):
        """Malformed precedent JSON is caught."""
        arch_dir = (
            fake_root / "knowledge" / "signatures" / "test-sig"
            / "archetypes" / "test-arch"
        )
        arch_dir.mkdir(parents=True)
        (arch_dir / "SEC-001.json").write_text("not json {{{")
        errors = validate_precedent_content(
            "test-arch", "SEC-001", "test-sig"
        )
        assert any("not valid JSON" in e for e in errors)

    def test_multiple_errors_accumulated(self, fake_root):
        """Both archetype mismatch and missing captured_at are reported together."""
        data = _valid_precedent_dict(archetype="WRONG-ARCH")
        del data["captured_at"]
        _make_precedent_file(fake_root, "test-sig", "test-arch", "SEC-001", data)
        errors = validate_precedent_content(
            "test-arch", "SEC-001", "test-sig"
        )
        assert len(errors) >= 2
        assert any("does not match parent directory" in e for e in errors)
        assert any("captured_at" in e for e in errors)

    def test_auto_extension_json(self, fake_root):
        """Finds precedent when called without .json extension."""
        _make_precedent_file(
            fake_root, "test-sig", "test-arch", "SEC-001.json",
            _valid_precedent_dict(),
        )
        errors = validate_precedent_content(
            "test-arch", "SEC-001", "test-sig"
        )
        assert errors == []

    def test_nonexistent_file_returns_empty(self, fake_root):
        """Non-existent precedent returns [] (existence checked elsewhere)."""
        errors = validate_precedent_content(
            "test-arch", "missing", "test-sig"
        )
        assert errors == []

    def test_custom_max_age_from_permissions(self, fake_root):
        """Custom precedent_max_age_days in permissions.yaml is respected."""
        _make_precedent_file(
            fake_root, "strict-sig", "test-arch", "SEC-001",
            _valid_precedent_dict(captured_at="2026-02-01"),  # ~70 days ago
        )
        _make_permissions_yaml(
            fake_root, "strict-sig", "precedent_max_age_days: 30\n"
        )
        errors = validate_precedent_content(
            "test-arch", "SEC-001", "strict-sig"
        )
        assert any("days old" in e for e in errors)

    def test_default_max_age_when_no_permissions(self, fake_root):
        """Falls back to DEFAULT_MAX_AGE_DAYS when no permissions.yaml."""
        _make_precedent_file(
            fake_root, "no-config-sig", "test-arch", "SEC-001",
            _valid_precedent_dict(captured_at="2026-04-01"),  # recent
        )
        errors = validate_precedent_content(
            "test-arch", "SEC-001", "no-config-sig"
        )
        assert errors == []


class TestTemporalAnchorReconfirmation:
    """Rule: precedents citing temporal anchors require re-confirmation today.

    A `temporal: true` anchor in the precedent's anchors_at_time means the
    grounding fact was time-bounded at ticket close (business trip, change
    window, on-call shift). It does not transfer forward — the current
    investigation must re-confirm it via trust_anchors_consulted.
    """

    def _with_temporal_anchor(self, name: str = "travel-authorization"):
        return _valid_precedent_dict(anchors_at_time=[
            {"anchor": name, "result": "confirmed", "temporal": True, "citation": "x"},
        ])

    def test_no_temporal_anchors_passes(self, fake_root):
        _make_precedent_file(
            fake_root, "sig", "arch", "SEC-001",
            _valid_precedent_dict(anchors_at_time=[
                {"anchor": "cdn-allowlist", "result": "confirmed", "temporal": False},
            ]),
        )
        errors = validate_temporal_anchors_reconfirmed(
            "arch", "SEC-001", "sig", anchors_consulted=[],
        )
        assert errors == []

    def test_temporal_anchor_reconfirmed_passes(self, fake_root):
        _make_precedent_file(
            fake_root, "sig", "arch", "SEC-001", self._with_temporal_anchor(),
        )
        errors = validate_temporal_anchors_reconfirmed(
            "arch", "SEC-001", "sig",
            anchors_consulted=[
                {"anchor": "travel-authorization", "kind": "authoritative-source",
                 "result": "confirmed", "citation": "HR trip #42"},
            ],
        )
        assert errors == []

    def test_temporal_anchor_not_consulted_fails(self, fake_root):
        _make_precedent_file(
            fake_root, "sig", "arch", "SEC-001", self._with_temporal_anchor(),
        )
        errors = validate_temporal_anchors_reconfirmed(
            "arch", "SEC-001", "sig", anchors_consulted=[],
        )
        assert len(errors) == 1
        assert "travel-authorization" in errors[0]
        assert "did not re-consult" in errors[0]

    def test_temporal_anchor_refuted_fails(self, fake_root):
        _make_precedent_file(
            fake_root, "sig", "arch", "SEC-001", self._with_temporal_anchor(),
        )
        errors = validate_temporal_anchors_reconfirmed(
            "arch", "SEC-001", "sig",
            anchors_consulted=[
                {"anchor": "travel-authorization", "kind": "authoritative-source",
                 "result": "refuted", "citation": "no active trip"},
            ],
        )
        assert len(errors) == 1
        assert "stale" in errors[0]

    def test_mixed_permanent_and_temporal(self, fake_root):
        _make_precedent_file(
            fake_root, "sig", "arch", "SEC-001",
            _valid_precedent_dict(anchors_at_time=[
                {"anchor": "approved-monitoring-sources", "result": "confirmed",
                 "temporal": False},
                {"anchor": "travel-authorization", "result": "confirmed",
                 "temporal": True},
            ]),
        )
        errors = validate_temporal_anchors_reconfirmed(
            "arch", "SEC-001", "sig",
            anchors_consulted=[
                {"anchor": "approved-monitoring-sources", "kind": "authoritative-source",
                 "result": "confirmed"},
            ],
        )
        assert len(errors) == 1
        assert "travel-authorization" in errors[0]

    def test_missing_precedent_file_no_error(self, fake_root):
        errors = validate_temporal_anchors_reconfirmed(
            "arch", "MISSING", "sig", anchors_consulted=[],
        )
        assert errors == []


class TestPrecedentRecency:
    def test_fresh_precedent(self):
        fresh, msg = check_recency("2026-04-01", max_age_days=90)
        assert fresh
        assert msg == ""

    def test_stale_precedent(self):
        fresh, msg = check_recency("2020-01-01", max_age_days=90)
        assert not fresh
        assert "days old" in msg

    def test_iso_datetime_format(self):
        fresh, _ = check_recency("2026-04-01T00:00:00Z", max_age_days=90)
        assert fresh

    def test_invalid_format(self):
        fresh, msg = check_recency("not-a-date")
        assert not fresh
        assert "invalid date format" in msg

    def test_max_age_zero_rejects_everything(self):
        """max_age_days=0 means only today is fresh."""
        fresh, msg = check_recency("2026-04-05", max_age_days=0)
        assert not fresh

    def test_parse_captured_at_date(self):
        dt = parse_captured_at("2026-03-15")
        assert dt.year == 2026
        assert dt.month == 3

    def test_parse_captured_at_datetime(self):
        dt = parse_captured_at("2026-03-15T10:30:00Z")
        assert dt.hour == 10

    def test_parse_captured_at_with_tz_offset(self):
        dt = parse_captured_at("2026-03-15T10:30:00+02:00")
        assert dt.hour == 10

    def test_parse_captured_at_invalid_raises(self):
        with pytest.raises(ValueError, match="invalid date format"):
            parse_captured_at("not-a-date")


class TestGetPrecedentMaxAge:
    def test_returns_default_when_no_permissions(self, fake_root):
        assert get_precedent_max_age("nonexistent-sig") == DEFAULT_MAX_AGE_DAYS

    def test_returns_default_when_key_absent(self, fake_root):
        """permissions.yaml exists but has no precedent_max_age_days."""
        _make_permissions_yaml(fake_root, "test-sig", "mode:\n  default: recommend\n")
        assert get_precedent_max_age("test-sig") == DEFAULT_MAX_AGE_DAYS

    def test_reads_custom_value(self, fake_root):
        _make_permissions_yaml(fake_root, "test-sig", "precedent_max_age_days: 30\n")
        assert get_precedent_max_age("test-sig") == 30

    def test_plaintext_fallback_when_yaml_unavailable(self, fake_root, monkeypatch):
        """Falls back to line scanning when yaml import fails."""
        _make_permissions_yaml(fake_root, "test-sig", "precedent_max_age_days: 45\n")
        # Force yaml import to fail
        import builtins
        real_import = builtins.__import__
        def mock_import(name, *args, **kwargs):
            if name == "yaml":
                raise ImportError("no yaml")
            return real_import(name, *args, **kwargs)
        monkeypatch.setattr(builtins, "__import__", mock_import)
        assert get_precedent_max_age("test-sig") == 45

    def test_malformed_value_returns_default(self, fake_root, monkeypatch):
        """Non-integer value falls back to default."""
        _make_permissions_yaml(fake_root, "test-sig", "precedent_max_age_days: notanumber\n")
        import builtins
        real_import = builtins.__import__
        def mock_import(name, *args, **kwargs):
            if name == "yaml":
                raise ImportError("no yaml")
            return real_import(name, *args, **kwargs)
        monkeypatch.setattr(builtins, "__import__", mock_import)
        assert get_precedent_max_age("test-sig") == DEFAULT_MAX_AGE_DAYS


# --- Precedent existence check ---


class TestCheckPrecedentExists:
    def test_existing_precedent(self, fake_root):
        _make_precedent_file(
            fake_root, "test-sig", "test-arch", "SEC-001",
            _valid_precedent_dict(),
        )
        assert check_precedent_exists(
            "test-arch", "SEC-001", "test-sig"
        ) is True

    def test_nonexistent_precedent(self, fake_root):
        _make_precedent_file(
            fake_root, "test-sig", "test-arch", "SEC-001",
            _valid_precedent_dict(),
        )
        assert check_precedent_exists(
            "test-arch", "does-not-exist", "test-sig"
        ) is False

    def test_nonexistent_archetype(self, fake_root):
        assert check_precedent_exists(
            "ghost-arch", "SEC-001", "test-sig"
        ) is False

    def test_empty_args_return_false(self, fake_root):
        assert check_precedent_exists("", "SEC-001", "test-sig") is False
        assert check_precedent_exists("test-arch", "", "test-sig") is False


# --- Archetype + trust anchor validation ---


def _make_archetype_file(
    root: Path, sig: str, name: str, required_anchors: list
) -> Path:
    """Helper: write an archetype's trust-anchors.md under archetypes/{name}/."""
    arch_dir = root / "knowledge" / "signatures" / sig / "archetypes" / name
    arch_dir.mkdir(parents=True, exist_ok=True)
    path = arch_dir / "trust-anchors.md"
    anchors_yaml = "\n".join(f"  - {a}" for a in required_anchors)
    if required_anchors:
        anchors_block = f"required_anchors:\n{anchors_yaml}"
    else:
        anchors_block = "required_anchors: []"
    path.write_text(
        f"---\n"
        f"archetype: {name}\n"
        f"signature_id: {sig}\n"
        f"{anchors_block}\n"
        f"---\n\n"
        f"# {name}\n"
    )
    return path


class TestArchetypeValidation:
    def test_load_archetype_frontmatter_real(self):
        """Loads an existing archetype from the real signature directory."""
        fm = load_archetype_frontmatter(
            "operator-runtime-debug", "wazuh-rule-100001"
        )
        assert fm is not None
        assert fm["archetype"] == "operator-runtime-debug"
        assert "oncall-schedule" in fm["required_anchors"]
        assert "change-windows" in fm["required_anchors"]

    def test_load_archetype_fake_root(self, fake_root):
        """Loads an archetype's trust-anchors.md from a synthetic signature dir."""
        _make_archetype_file(fake_root, "test-sig", "my-arch", ["a1"])
        fm = load_archetype_frontmatter("my-arch", "test-sig")
        assert fm is not None
        assert fm["archetype"] == "my-arch"
        assert fm["required_anchors"] == ["a1"]

    def test_load_archetype_missing(self, fake_root):
        assert load_archetype_frontmatter("nonexistent", "test-sig") is None

    def test_check_archetype_exists_real(self):
        assert check_archetype_exists(
            "operator-runtime-debug", "wazuh-rule-100001"
        ) is True

    def test_check_archetype_exists_missing(self, fake_root):
        assert check_archetype_exists("nope", "test-sig") is False

    def test_anchors_all_confirmed(self, fake_root):
        _make_archetype_file(fake_root, "test-sig", "ok", ["a1", "a2"])
        anchors = [
            {"anchor": "a1", "kind": "org-authority", "result": "confirmed"},
            {"anchor": "a2", "kind": "org-authority", "result": "confirmed"},
        ]
        errors = validate_archetype_anchors("ok", "test-sig", anchors)
        assert errors == []

    def test_anchors_missing_one(self, fake_root):
        _make_archetype_file(fake_root, "test-sig", "ok", ["a1", "a2"])
        anchors = [
            {"anchor": "a1", "kind": "org-authority", "result": "confirmed"},
        ]
        errors = validate_archetype_anchors("ok", "test-sig", anchors)
        assert any("a2" in e and "not consulted" in e for e in errors)

    def test_anchors_one_refuted(self, fake_root):
        _make_archetype_file(fake_root, "test-sig", "ok", ["a1"])
        anchors = [
            {"anchor": "a1", "kind": "org-authority", "result": "refuted"},
        ]
        errors = validate_archetype_anchors("ok", "test-sig", anchors)
        assert any("a1" in e and "refuted" in e for e in errors)

    def test_anchors_one_unavailable(self, fake_root):
        _make_archetype_file(fake_root, "test-sig", "ok", ["a1"])
        anchors = [
            {"anchor": "a1", "kind": "org-authority", "result": "unavailable"},
        ]
        errors = validate_archetype_anchors("ok", "test-sig", anchors)
        assert any("a1" in e and "unavailable" in e for e in errors)

    def test_anchors_archetype_no_requirements(self, fake_root):
        """Archetype with empty required_anchors needs no consultations."""
        _make_archetype_file(fake_root, "test-sig", "esc", [])
        errors = validate_archetype_anchors("esc", "test-sig", [])
        assert errors == []

    def test_validate_tier1_resolved_with_archetype_and_confirmed_anchors(
        self, fake_root, tmp_path
    ):
        """A resolved report citing an archetype with all anchors confirmed passes."""
        _make_archetype_file(fake_root, "test-sig", "benign-arch", ["a1"])
        # context.md so severity defaults to medium (needs >= 2 leads)
        ctx_dir = fake_root / "knowledge" / "signatures" / "test-sig"
        ctx_dir.mkdir(parents=True, exist_ok=True)
        (ctx_dir / "context.md").write_text(
            "---\nseverity: low\n---\n# context\n"
        )

        run_dir = tmp_path / "run"
        run_dir.mkdir()
        (run_dir / "report.md").write_text(
            "---\n"
            "ticket_id: T-001\n"
            "signature_id: test-sig\n"
            "status: resolved\n"
            "disposition: benign\n"
            "confidence: high\n"
            "matched_archetype: benign-arch\n"
            "trust_anchors_consulted:\n"
            "  - anchor: a1\n"
            "    kind: org-authority\n"
            "    result: confirmed\n"
            "    citation: 'CHG-1234'\n"
            "leads_pursued: 2\n"
            "---\n\n# Report\n"
        )
        passed, errors, _ = validate_tier1(run_dir / "report.md")
        assert passed, f"Expected pass but got: {errors}"

    def test_validate_tier1_resolved_with_archetype_missing_anchor(
        self, fake_root, tmp_path
    ):
        """A resolved report whose archetype requires an anchor that wasn't consulted fails."""
        _make_archetype_file(fake_root, "test-sig", "benign-arch", ["a1"])
        ctx_dir = fake_root / "knowledge" / "signatures" / "test-sig"
        ctx_dir.mkdir(parents=True, exist_ok=True)
        (ctx_dir / "context.md").write_text(
            "---\nseverity: low\n---\n# context\n"
        )

        run_dir = tmp_path / "run"
        run_dir.mkdir()
        (run_dir / "report.md").write_text(
            "---\n"
            "ticket_id: T-001\n"
            "signature_id: test-sig\n"
            "status: resolved\n"
            "disposition: benign\n"
            "confidence: high\n"
            "matched_archetype: benign-arch\n"
            "leads_pursued: 2\n"
            "---\n\n# Report\n"
        )
        passed, errors, _ = validate_tier1(run_dir / "report.md")
        assert not passed
        assert any("a1" in e and "not consulted" in e for e in errors)

    def test_validate_tier1_resolved_with_unknown_archetype(
        self, fake_root, tmp_path
    ):
        """Citing an archetype that doesn't exist fails."""
        ctx_dir = fake_root / "knowledge" / "signatures" / "test-sig"
        ctx_dir.mkdir(parents=True, exist_ok=True)
        (ctx_dir / "context.md").write_text(
            "---\nseverity: low\n---\n# context\n"
        )

        run_dir = tmp_path / "run"
        run_dir.mkdir()
        (run_dir / "report.md").write_text(
            "---\n"
            "ticket_id: T-001\n"
            "signature_id: test-sig\n"
            "status: resolved\n"
            "disposition: benign\n"
            "confidence: high\n"
            "matched_archetype: ghost\n"
            "leads_pursued: 2\n"
            "---\n\n# Report\n"
        )
        passed, errors, _ = validate_tier1(run_dir / "report.md")
        assert not passed
        assert any("ghost" in e and "not found" in e for e in errors)


class TestReportFrontmatterArchetypeFields:
    """Schema-level checks for the new archetype/anchor frontmatter fields."""

    def _make_resolved(self, **overrides):
        defaults = dict(
            ticket_id="T-001",
            signature_id="test-sig",
            status="resolved",
            disposition="benign",
            confidence="high",
            leads_pursued=2,
        )
        defaults.update(overrides)
        return ReportFrontmatter(**defaults)

    def test_resolved_with_archetype_only_passes(self):
        r = self._make_resolved(matched_archetype="some-arch")
        assert r.validate() == []

    def test_resolved_with_archetype_missing_fails(self):
        r = self._make_resolved()
        errors = r.validate()
        assert any("matched_archetype" in e for e in errors)

    def test_resolved_with_archetype_and_ticket_passes(self):
        r = self._make_resolved(
            matched_archetype="arch", matched_ticket_id="SEC-001"
        )
        assert r.validate() == []

    def test_anchor_entry_invalid_kind(self):
        r = self._make_resolved(
            matched_archetype="arch",
            trust_anchors_consulted=[
                {"anchor": "a", "kind": "wishful-thinking", "result": "confirmed"}
            ],
        )
        errors = r.validate()
        assert any("kind" in e for e in errors)

    def test_anchor_entry_invalid_result(self):
        r = self._make_resolved(
            matched_archetype="arch",
            trust_anchors_consulted=[
                {"anchor": "a", "kind": "org-authority", "result": "maybe"}
            ],
        )
        errors = r.validate()
        assert any("result" in e for e in errors)

    def test_anchor_entry_missing_anchor_field(self):
        r = self._make_resolved(
            matched_archetype="arch",
            trust_anchors_consulted=[
                {"kind": "org-authority", "result": "confirmed"}
            ],
        )
        errors = r.validate()
        assert any("anchor" in e for e in errors)

    def test_anchor_entry_well_formed(self):
        r = self._make_resolved(
            matched_archetype="arch",
            trust_anchors_consulted=[
                {
                    "anchor": "oncall-schedule",
                    "kind": "org-authority",
                    "result": "confirmed",
                    "citation": "alice on-call",
                }
            ],
        )
        assert r.validate() == []


# --- PostToolUse event parsing ---


class TestExtractRunDir:
    def test_report_write_in_runs(self, tmp_path, monkeypatch):
        """Write to runs/{id}/report.md extracts the run dir."""
        runs = tmp_path / "runs"
        run_dir = runs / "abc-123"
        run_dir.mkdir(parents=True)
        monkeypatch.setenv("SOC_AGENT_RUNS_DIR", str(runs))

        hook_data = {
            "tool_name": "Write",
            "tool_input": {"file_path": str(run_dir / "report.md")},
        }
        result = extract_run_dir(hook_data)
        assert result == run_dir

    def test_non_report_file_ignored(self, tmp_path, monkeypatch):
        """Write to a non-report file returns None."""
        runs = tmp_path / "runs"
        run_dir = runs / "abc-123"
        run_dir.mkdir(parents=True)
        monkeypatch.setenv("SOC_AGENT_RUNS_DIR", str(runs))

        hook_data = {
            "tool_name": "Write",
            "tool_input": {"file_path": str(run_dir / "investigation.md")},
        }
        assert extract_run_dir(hook_data) is None

    def test_file_outside_runs_ignored(self, tmp_path, monkeypatch):
        """Write to report.md outside runs/ returns None."""
        runs = tmp_path / "runs"
        runs.mkdir(parents=True)
        monkeypatch.setenv("SOC_AGENT_RUNS_DIR", str(runs))

        hook_data = {
            "tool_name": "Write",
            "tool_input": {"file_path": "/tmp/other/report.md"},
        }
        assert extract_run_dir(hook_data) is None

    def test_missing_file_path(self):
        """No file_path in tool_input returns None."""
        hook_data = {"tool_name": "Write", "tool_input": {}}
        assert extract_run_dir(hook_data) is None

    def test_edit_tool_also_works(self, tmp_path, monkeypatch):
        """Edit tool events are also handled."""
        runs = tmp_path / "runs"
        run_dir = runs / "abc-123"
        run_dir.mkdir(parents=True)
        monkeypatch.setenv("SOC_AGENT_RUNS_DIR", str(runs))

        hook_data = {
            "tool_name": "Edit",
            "tool_input": {"file_path": str(run_dir / "report.md")},
        }
        result = extract_run_dir(hook_data)
        assert result == run_dir


# --- Salt handling ---


class TestRunSalt:
    def test_reads_salt_from_meta(self, tmp_path):
        """Salt is read from meta.json when present."""
        meta = {"run_id": "test", "salt": "abc123"}
        (tmp_path / "meta.json").write_text(json.dumps(meta))
        assert get_run_salt(tmp_path) == "abc123"

    def test_fallback_when_no_meta(self, tmp_path):
        """Generates a fallback salt when meta.json doesn't exist."""
        salt = get_run_salt(tmp_path)
        assert len(salt) == 16  # secrets.token_hex(8) = 16 chars

    def test_fallback_when_meta_corrupt(self, tmp_path):
        """Generates a fallback salt when meta.json is invalid."""
        (tmp_path / "meta.json").write_text("not json")
        salt = get_run_salt(tmp_path)
        assert len(salt) == 16


class TestWrapUntrusted:
    def test_wraps_with_salted_tags(self):
        result = wrap_untrusted("hello", "alert-data", "abc123")
        assert result == "<run-abc123-alert-data>\nhello\n</run-abc123-alert-data>"

    def test_different_salts_produce_different_tags(self):
        a = wrap_untrusted("x", "data", "salt1")
        b = wrap_untrusted("x", "data", "salt2")
        assert a != b
        assert "salt1" in a
        assert "salt2" in b
