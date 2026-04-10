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

from schemas.enums import VALID_CONFIDENCES, VALID_DISPOSITIONS, VALID_STATUSES
from schemas.report_frontmatter import (
    ReportFrontmatter,
    parse_frontmatter,
)
import hooks.scripts.validate_report as vr
from hooks.scripts.validate_report import (
    check_archetype_exists,
    check_precedent_exists,
    check_ticket_context_spawned,
    extract_run_dir,
    get_precedent_max_age,
    get_run_salt,
    is_screen_resolved,
    load_archetype_frontmatter,
    playbook_has_screen_section,
    validate_archetype_anchors,
    validate_precedent_content,
    validate_tier1,
    wrap_untrusted,
)
from schemas.precedent import DEFAULT_MAX_AGE_DAYS, check_recency, parse_validated_at

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
            matched_precedent=None,
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
            matched_precedent="monitoring-probe-001.json",
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

    def test_resolved_requires_precedent(self):
        r = self._make_valid(status="resolved", matched_precedent=None)
        errors = r.validate()
        assert any("matched_precedent" in e for e in errors)

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
            "matched_precedent": None,
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
            "matched_precedent": None,
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

    def test_invalid_low_leads(self):
        passed, errors, _ = validate_tier1(FIXTURES / "invalid_low_leads.md")
        assert not passed
        assert any("leads_pursued" in e for e in errors)

    def test_invalid_bad_enums(self):
        passed, errors, _ = validate_tier1(FIXTURES / "invalid_bad_enums.md")
        assert not passed
        assert any("status" in e for e in errors)


# --- Screen-resolved validation ---


class TestScreenResolved:
    """Test that screen-resolved reports are exempt from MIN_LEADS_BY_SEVERITY."""

    SCREEN_REPORT = """\
---
ticket_id: SEC-SCREEN-001
signature_id: wazuh-rule-5710
status: resolved
disposition: benign
confidence: high
matched_precedent: monitoring-probe-001.json
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

    def test_screen_resolved_skips_leads_check(self, tmp_path):
        """Screen-resolved report with 1 lead passes (medium severity needs 2)."""
        run_dir = self._setup_screen_run(
            tmp_path, ["CONTEXTUALIZE", "SCREEN", "CONCLUDE"]
        )
        passed, errors, _ = validate_tier1(run_dir / "report.md")
        assert passed, f"Expected pass but got: {errors}"

    def test_non_screen_still_checks_leads(self, tmp_path):
        """Non-screen report with 1 lead fails for medium severity."""
        run_dir = tmp_path / "run-full"
        run_dir.mkdir()
        state = {
            "phase": "CONCLUDE",
            "history": ["CONTEXTUALIZE", "HYPOTHESIZE", "GATHER", "ANALYZE", "CONCLUDE"],
        }
        (run_dir / "state.json").write_text(json.dumps(state))
        (run_dir / "report.md").write_text(self.SCREEN_REPORT)
        passed, errors, _ = validate_tier1(run_dir / "report.md")
        assert not passed
        assert any("leads_pursued" in e for e in errors)

    def test_screen_resolved_requires_screen_section(self, tmp_path):
        """Screen-resolved report fails if playbook has no ## Screen section."""
        report_text = self.SCREEN_REPORT.replace(
            "wazuh-rule-5710", "nonexistent-sig"
        )
        run_dir = tmp_path / "run-no-playbook"
        run_dir.mkdir()
        state = {"phase": "CONCLUDE", "history": ["CONTEXTUALIZE", "SCREEN", "CONCLUDE"]}
        (run_dir / "state.json").write_text(json.dumps(state))
        (run_dir / "report.md").write_text(report_text)
        passed, errors, _ = validate_tier1(run_dir / "report.md")
        assert not passed
        assert any("Screen section" in e for e in errors)

    def test_is_screen_resolved_no_state(self, tmp_path):
        """No state.json means not screen-resolved."""
        assert is_screen_resolved(tmp_path) is False

    def test_is_screen_resolved_with_hypothesize(self, tmp_path):
        """SCREEN in history but also HYPOTHESIZE means fallthrough, not screen-resolved."""
        state = {
            "history": ["CONTEXTUALIZE", "SCREEN", "HYPOTHESIZE", "GATHER", "ANALYZE", "CONCLUDE"]
        }
        (tmp_path / "state.json").write_text(json.dumps(state))
        assert is_screen_resolved(tmp_path) is False

    def test_playbook_has_screen_section_true(self):
        assert playbook_has_screen_section("wazuh-rule-5710") is True

    def test_playbook_has_screen_section_nonexistent(self):
        assert playbook_has_screen_section("nonexistent-sig") is False


# --- Ticket-context subagent spawn check ---


class TestCheckTicketContextSpawned:
    """Validates the audit-log scan that enforces ticket-context spawning."""

    def _make_run_with_audit(self, tmp_path: Path, audit_lines: list[str]) -> Path:
        runs_dir = tmp_path / "runs"
        runs_dir.mkdir()
        run_dir = runs_dir / "run-uuid"
        run_dir.mkdir()
        (runs_dir / "tool_audit.jsonl").write_text("\n".join(audit_lines) + "\n")
        return run_dir

    def test_passes_when_task_with_ticket_context_path(self, tmp_path):
        entry = json.dumps({
            "tool_name": "Task",
            "tool_input": {
                "subagent_type": "general-purpose",
                "description": "ticket-context for SEC-001",
                "prompt": "Read /workspace/soc-agent/skills/investigate/ticket-context.md ...",
            },
        })
        run_dir = self._make_run_with_audit(tmp_path, [entry])
        assert check_ticket_context_spawned(run_dir) is None

    def test_passes_when_keyword_in_description(self, tmp_path):
        entry = json.dumps({
            "tool_name": "Task",
            "tool_input": {"description": "ticket-context scan", "prompt": "..."},
        })
        run_dir = self._make_run_with_audit(tmp_path, [entry])
        assert check_ticket_context_spawned(run_dir) is None

    def test_fails_when_no_task_calls(self, tmp_path):
        entries = [
            json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}}),
            json.dumps({"tool_name": "Write", "tool_input": {"file_path": "x"}}),
        ]
        run_dir = self._make_run_with_audit(tmp_path, entries)
        msg = check_ticket_context_spawned(run_dir)
        assert msg is not None
        assert "ticket-context" in msg

    def test_fails_when_task_unrelated(self, tmp_path):
        entry = json.dumps({
            "tool_name": "Task",
            "tool_input": {
                "subagent_type": "general-purpose",
                "description": "scan precedents",
                "prompt": "Read all JSON files in precedents/ ...",
            },
        })
        run_dir = self._make_run_with_audit(tmp_path, [entry])
        msg = check_ticket_context_spawned(run_dir)
        assert msg is not None

    def test_skips_silently_when_no_audit_log(self, tmp_path):
        runs_dir = tmp_path / "runs"
        runs_dir.mkdir()
        run_dir = runs_dir / "run-uuid"
        run_dir.mkdir()
        # No tool_audit.jsonl exists
        assert check_ticket_context_spawned(run_dir) is None

    def test_handles_malformed_audit_lines(self, tmp_path):
        entries = [
            "not json at all",
            json.dumps({"tool_name": "Bash"}),
            "",
            json.dumps({
                "tool_name": "Task",
                "tool_input": {"prompt": "use ticket-context.md"},
            }),
        ]
        run_dir = self._make_run_with_audit(tmp_path, entries)
        assert check_ticket_context_spawned(run_dir) is None


# --- Precedent existence check ---


# --- Precedent content validation ---


@pytest.fixture()
def fake_root(tmp_path, monkeypatch):
    """Redirect SOC_AGENT_ROOT to a temp dir and restore after test."""
    monkeypatch.setattr(vr, "SOC_AGENT_ROOT", tmp_path)
    return tmp_path


def _make_precedent_file(root: Path, sig: str, name: str, data: dict) -> Path:
    """Helper: create a precedent JSON file under a fake SOC_AGENT_ROOT."""
    prec_dir = root / "knowledge" / "signatures" / sig / "precedents"
    prec_dir.mkdir(parents=True, exist_ok=True)
    path = prec_dir / name
    path.write_text(json.dumps(data))
    return path


def _make_permissions_yaml(root: Path, sig: str, content: str) -> Path:
    """Helper: create a permissions.yaml under a fake SOC_AGENT_ROOT."""
    cfg_dir = root / "config" / "signatures" / sig
    cfg_dir.mkdir(parents=True, exist_ok=True)
    path = cfg_dir / "permissions.yaml"
    path.write_text(content)
    return path


class TestValidatePrecedentContent:
    def test_matching_signature_and_recent(self):
        """Valid precedent with matching signature_id and recent validated_at."""
        errors = validate_precedent_content(
            "monitoring-probe-001.json", "wazuh-rule-5710"
        )
        assert errors == []

    def test_signature_id_mismatch(self, fake_root):
        """Precedent with wrong signature_id is rejected."""
        _make_precedent_file(fake_root, "test-sig", "test.json", {
            "signature_id": "WRONG-SIG",
            "validated_at": "2026-04-01",
        })
        errors = validate_precedent_content("test.json", "test-sig")
        assert any("does not match" in e for e in errors)

    def test_missing_validated_at(self, fake_root):
        """Precedent without validated_at is flagged."""
        _make_precedent_file(fake_root, "test-sig", "test.json", {
            "signature_id": "test-sig",
        })
        errors = validate_precedent_content("test.json", "test-sig")
        assert any("validated_at" in e for e in errors)

    def test_stale_precedent(self, fake_root):
        """Precedent older than max_age is rejected."""
        _make_precedent_file(fake_root, "test-sig", "test.json", {
            "signature_id": "test-sig",
            "validated_at": "2020-01-01",
        })
        errors = validate_precedent_content("test.json", "test-sig")
        assert any("days old" in e for e in errors)

    def test_malformed_json(self, fake_root):
        """Malformed precedent JSON is caught."""
        prec_dir = fake_root / "knowledge" / "signatures" / "test-sig" / "precedents"
        prec_dir.mkdir(parents=True)
        (prec_dir / "test.json").write_text("not json {{{")
        errors = validate_precedent_content("test.json", "test-sig")
        assert any("not valid JSON" in e for e in errors)

    def test_multiple_errors_accumulated(self, fake_root):
        """Both signature mismatch and missing validated_at are reported together."""
        _make_precedent_file(fake_root, "test-sig", "test.json", {
            "signature_id": "WRONG-SIG",
            # no validated_at
        })
        errors = validate_precedent_content("test.json", "test-sig")
        assert len(errors) >= 2
        assert any("does not match" in e for e in errors)
        assert any("validated_at" in e for e in errors)

    def test_auto_extension_json(self, fake_root):
        """Finds precedent when called without .json extension."""
        _make_precedent_file(fake_root, "test-sig", "probe.json", {
            "signature_id": "test-sig",
            "validated_at": "2026-04-01",
        })
        errors = validate_precedent_content("probe", "test-sig")
        assert errors == []

    def test_nonexistent_file_returns_empty(self, fake_root):
        """Non-existent precedent returns [] (existence checked elsewhere)."""
        errors = validate_precedent_content("missing.json", "test-sig")
        assert errors == []

    def test_custom_max_age_from_permissions(self, fake_root):
        """Custom precedent_max_age_days in permissions.yaml is respected."""
        _make_precedent_file(fake_root, "strict-sig", "test.json", {
            "signature_id": "strict-sig",
            "validated_at": "2026-02-01",  # ~64 days ago
        })
        # 30-day max age should reject this
        _make_permissions_yaml(fake_root, "strict-sig",
            "precedent_max_age_days: 30\n"
        )
        errors = validate_precedent_content("test.json", "strict-sig")
        assert any("days old" in e for e in errors)

    def test_default_max_age_when_no_permissions(self, fake_root):
        """Falls back to DEFAULT_MAX_AGE_DAYS when no permissions.yaml."""
        _make_precedent_file(fake_root, "no-config-sig", "test.json", {
            "signature_id": "no-config-sig",
            "validated_at": "2026-04-01",  # recent
        })
        # No permissions.yaml exists — should use default (90 days)
        errors = validate_precedent_content("test.json", "no-config-sig")
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

    def test_parse_validated_at_date(self):
        dt = parse_validated_at("2026-03-15")
        assert dt.year == 2026
        assert dt.month == 3

    def test_parse_validated_at_datetime(self):
        dt = parse_validated_at("2026-03-15T10:30:00Z")
        assert dt.hour == 10

    def test_parse_validated_at_with_tz_offset(self):
        dt = parse_validated_at("2026-03-15T10:30:00+02:00")
        assert dt.hour == 10

    def test_parse_validated_at_invalid_raises(self):
        with pytest.raises(ValueError, match="invalid date format"):
            parse_validated_at("not-a-date")


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
    def test_existing_precedent(self):
        assert check_precedent_exists(
            "monitoring-probe-001.json", "wazuh-rule-5710"
        ) is True

    def test_nonexistent_precedent(self):
        assert check_precedent_exists("does-not-exist.json", "wazuh-rule-5710") is False

    def test_nonexistent_signature(self):
        assert check_precedent_exists("anything.json", "nonexistent-sig") is False


# --- Archetype + trust anchor validation ---


def _make_archetype_file(
    root: Path, sig: str, name: str, required_anchors: list
) -> Path:
    """Helper: write an archetype .md file with the given required_anchors."""
    arch_dir = root / "knowledge" / "signatures" / sig / "archetypes"
    arch_dir.mkdir(parents=True, exist_ok=True)
    path = arch_dir / f"{name}.md"
    anchors_yaml = "\n".join(f"  - {a}" for a in required_anchors) or "[]"
    if required_anchors:
        anchors_block = f"required_anchors:\n{anchors_yaml}"
    else:
        anchors_block = "required_anchors: []"
    path.write_text(
        f"---\n"
        f"archetype: {name}\n"
        f"signature_id: {sig}\n"
        f"{anchors_block}\n"
        f"precedents: []\n"
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

    def test_load_archetype_frontmatter_with_extension(self):
        """Loads with explicit .md extension."""
        fm = load_archetype_frontmatter(
            "post-exploit-interactive.md", "wazuh-rule-100001"
        )
        assert fm is not None
        assert fm["required_anchors"] == []

    def test_load_archetype_missing(self):
        assert load_archetype_frontmatter("nonexistent", "wazuh-rule-100001") is None

    def test_check_archetype_exists_real(self):
        assert check_archetype_exists(
            "operator-runtime-debug", "wazuh-rule-100001"
        ) is True

    def test_check_archetype_exists_missing(self):
        assert check_archetype_exists("nope", "wazuh-rule-100001") is False

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
            matched_precedent=None,
            leads_pursued=2,
        )
        defaults.update(overrides)
        return ReportFrontmatter(**defaults)

    def test_resolved_with_archetype_only_passes(self):
        r = self._make_resolved(matched_archetype="some-arch")
        assert r.validate() == []

    def test_resolved_with_neither_fails(self):
        r = self._make_resolved()
        errors = r.validate()
        assert any("matched_archetype" in e for e in errors)

    def test_resolved_with_both_passes(self):
        r = self._make_resolved(
            matched_archetype="arch", matched_precedent="p.json"
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
