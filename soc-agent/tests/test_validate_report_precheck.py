"""Tests for the REPORT transition verification hook.

Tests validate_report_precheck.py: helper unit tests, plus end-to-end via
subprocess simulating PreToolUse events on stdin. Judge subprocess
calls are intercepted by shadowing the `claude` CLI with a fake
script on PATH whose stdout is controlled per-test.
"""

import json
import os
import stat
import subprocess
import sys
import textwrap
from pathlib import Path

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from hooks.scripts.investigation_parse import (
    has_report_header,
    is_screen_resolved,
)
from hooks.scripts.validate_report_precheck import (
    check_frontier_closure,
    check_termination_vs_verdict,
    extract_conclude_yaml,
    extract_status,
    load_archetype_description,
    load_sibling_archetypes,
)

HOOK_SCRIPT = SOC_AGENT_ROOT / "hooks" / "scripts" / "validate_report_precheck.py"


# ---------------------------------------------------------------------------
# Unit tests: extract_status
# ---------------------------------------------------------------------------


class TestExtractStatus:
    def test_resolved(self):
        text = "## REPORT\n\n**Verdict:** resolved — monitoring probe\n"
        assert extract_status(text) == "resolved"

    def test_escalated(self):
        text = "## REPORT\n\n**Verdict:** escalated — two live hypotheses\n"
        assert extract_status(text) == "escalated"

    def test_case_insensitive(self):
        text = "## REPORT\n\n**Verdict:** Resolved — foo\n"
        assert extract_status(text) == "resolved"

    def test_missing(self):
        text = "## REPORT\nno verdict line here\n"
        assert extract_status(text) is None

    def test_empty(self):
        assert extract_status("") is None


# ---------------------------------------------------------------------------
# Unit tests: extract_conclude_yaml
# ---------------------------------------------------------------------------


class TestExtractConcludeYaml:
    def test_extracts_conclude_block(self):
        text = textwrap.dedent("""\
            ## REPORT
            text

            ```yaml
            conclude:
              disposition: benign
              matched_archetype: monitoring-probe
              confidence: high
              summary: ok
            ```
            """)
        result = extract_conclude_yaml(text)
        assert result is not None
        assert result["matched_archetype"] == "monitoring-probe"
        assert result["disposition"] == "benign"

    def test_no_yaml_block(self):
        text = "## REPORT\n**Verdict:** resolved — foo\n"
        assert extract_conclude_yaml(text) is None

    def test_other_yaml_block_only(self):
        # A non-conclude yaml block (e.g., a gather: block earlier in
        # the file) does not satisfy the gate.
        text = textwrap.dedent("""\
            ```yaml
            gather:
              - id: l-1
                name: foo
            ```
            """)
        assert extract_conclude_yaml(text) is None

    def test_skips_unparseable_block_finds_next(self):
        text = textwrap.dedent("""\
            ```yaml
            : invalid : yaml :
            ```

            ```yaml
            conclude:
              matched_archetype: foo
            ```
            """)
        result = extract_conclude_yaml(text)
        assert result is not None
        assert result["matched_archetype"] == "foo"


# ---------------------------------------------------------------------------
# Unit tests: check_frontier_closure
# ---------------------------------------------------------------------------


def _companion_md(yaml_blocks: list[str]) -> str:
    """Wrap raw YAML strings into ```yaml blocks inside a minimal investigation.md."""
    parts = ["## CONTEXTUALIZE\n"]
    for block in yaml_blocks:
        parts.append("\n```yaml\n" + block + "\n```\n")
    parts.append("\n## REPORT\n\n**Verdict:** resolved\n")
    return "".join(parts)


_RESOLVING_CONCLUDE = (
    "conclude:\n"
    "  termination:\n"
    "    category: adversarial-refuted\n"
    "    rationale: \"tests refuted\"\n"
    "  disposition: benign\n"
    "  confidence: high\n"
    "  summary: \"test\"\n"
)

_ESCALATION_CONCLUDE = (
    "conclude:\n"
    "  termination:\n"
    "    category: severity-ceiling\n"
    "    rationale: \"tool-unavailable\"\n"
    "  disposition: inconclusive\n"
    "  confidence: medium\n"
    "  ceiling_test:\n"
    "    kind: tool-unavailable\n"
    "    subject: \"vpn-audit\"\n"
    "  ceiling_rationale: \"no vpn audit source\"\n"
    "  summary: \"escalated\"\n"
)


class TestCheckFrontierClosure:
    def test_no_yaml_blocks_passes(self):
        assert check_frontier_closure("## REPORT\nprose only\n") is None

    def test_all_resolved_passes(self):
        hypothesize = (
            "hypothesize:\n"
            "  hypotheses:\n"
            "    - id: h-001\n"
            "      name: \"?scanner\"\n"
        )
        lead = (
            "gather:\n"
            "  - id: l-001\n"
            "    loop: 1\n"
            "    name: t\n"
            "    target: v-001\n"
            "    query_details: {}\n"
            "    outcome:\n"
            "      observations:\n"
            "        vertices: []\n"
            "        edges: []\n"
            "    resolutions:\n"
            "      - hypothesis: h-001\n"
            "        after: \"++\"\n"
            "        supporting_edges: []\n"
        )
        text = _companion_md([hypothesize, lead, _RESOLVING_CONCLUDE])
        assert check_frontier_closure(text) is None

    def test_active_hypothesis_in_resolving_investigation_fails(self):
        hypothesize = (
            "hypothesize:\n"
            "  hypotheses:\n"
            "    - id: h-001\n"
            "      name: \"?scanner\"\n"
            "    - id: h-002\n"
            "      name: \"?credential-stuffing\"\n"
        )
        # Only h-001 gets a resolution; h-002 remains active.
        lead = (
            "gather:\n"
            "  - id: l-001\n"
            "    loop: 1\n"
            "    name: t\n"
            "    target: v-001\n"
            "    query_details: {}\n"
            "    outcome:\n"
            "      observations:\n"
            "        vertices: []\n"
            "        edges: []\n"
            "    resolutions:\n"
            "      - hypothesis: h-001\n"
            "        after: \"++\"\n"
            "        supporting_edges: []\n"
        )
        text = _companion_md([hypothesize, lead, _RESOLVING_CONCLUDE])
        err = check_frontier_closure(text)
        assert err is not None
        assert "h-002" in err
        assert "active" in err.lower()

    def test_active_hypothesis_in_escalation_passes(self):
        """severity-ceiling escalations legitimately hand off active hypotheses."""
        hypothesize = (
            "hypothesize:\n"
            "  hypotheses:\n"
            "    - id: h-001\n"
            "      name: \"?scanner\"\n"
            "    - id: h-002\n"
            "      name: \"?credential-stuffing\"\n"
        )
        text = _companion_md([hypothesize, _ESCALATION_CONCLUDE])
        assert check_frontier_closure(text) is None

    def test_active_hypothesis_in_exhaustion_escalation_passes(self):
        hypothesize = (
            "hypothesize:\n"
            "  hypotheses:\n"
            "    - id: h-001\n"
            "      name: \"?scanner\"\n"
        )
        conclude = (
            "conclude:\n"
            "  termination:\n"
            "    category: exhaustion-escalation\n"
            "    rationale: \"loop budget exhausted\"\n"
            "  disposition: inconclusive\n"
            "  confidence: low\n"
            "  summary: \"out of loops\"\n"
        )
        text = _companion_md([hypothesize, conclude])
        assert check_frontier_closure(text) is None

    def test_no_conclude_block_passes(self):
        """Without termination.category, structural validation owns the error."""
        hypothesize = (
            "hypothesize:\n"
            "  hypotheses:\n"
            "    - id: h-001\n"
            "      name: \"?scanner\"\n"
        )
        text = _companion_md([hypothesize])
        assert check_frontier_closure(text) is None

    def test_shelved_hypothesis_in_resolving_passes(self):
        hypothesize = (
            "hypothesize:\n"
            "  hypotheses:\n"
            "    - id: h-001\n"
            "      name: \"?scanner\"\n"
        )
        lead = (
            "gather:\n"
            "  - id: l-001\n"
            "    loop: 1\n"
            "    name: t\n"
            "    target: v-001\n"
            "    query_details: {}\n"
            "    outcome:\n"
            "      observations:\n"
            "        vertices: []\n"
            "        edges: []\n"
            "    shelved: [h-001]\n"
            "    resolutions: []\n"
        )
        text = _companion_md([hypothesize, lead, _RESOLVING_CONCLUDE])
        assert check_frontier_closure(text) is None

    def test_refuted_via_minus_minus_in_resolving_passes(self):
        hypothesize = (
            "hypothesize:\n"
            "  hypotheses:\n"
            "    - id: h-001\n"
            "      name: \"?scanner\"\n"
        )
        lead = (
            "gather:\n"
            "  - id: l-001\n"
            "    loop: 1\n"
            "    name: t\n"
            "    target: v-001\n"
            "    query_details: {}\n"
            "    outcome:\n"
            "      observations:\n"
            "        vertices: []\n"
            "        edges: []\n"
            "    resolutions:\n"
            "      - hypothesis: h-001\n"
            "        after: \"--\"\n"
            "        matched_refutation_ids: [r1]\n"
            "        supporting_edges: []\n"
        )
        text = _companion_md([hypothesize, lead, _RESOLVING_CONCLUDE])
        assert check_frontier_closure(text) is None

    def test_explicit_status_refuted_in_resolving_passes(self):
        hypothesize = (
            "hypothesize:\n"
            "  hypotheses:\n"
            "    - id: h-001\n"
            "      name: \"?scanner\"\n"
            "      status: refuted\n"
        )
        text = _companion_md([hypothesize, _RESOLVING_CONCLUDE])
        assert check_frontier_closure(text) is None

    def test_trust_root_category_also_gates(self):
        hypothesize = (
            "hypothesize:\n"
            "  hypotheses:\n"
            "    - id: h-001\n"
            "      name: \"?scanner\"\n"
        )
        conclude = (
            "conclude:\n"
            "  termination:\n"
            "    category: trust-root\n"
            "    rationale: \"reached trust root\"\n"
            "  disposition: benign\n"
            "  confidence: high\n"
            "  summary: \"resolved at trust root\"\n"
        )
        text = _companion_md([hypothesize, conclude])
        err = check_frontier_closure(text)
        assert err is not None
        assert "h-001" in err


# ---------------------------------------------------------------------------
# Unit tests: archetype loaders
# ---------------------------------------------------------------------------


class TestArchetypeLoaders:
    def test_load_archetype_description_existing(self, monkeypatch, tmp_path):
        # Build a fake knowledge tree under tmp_path and point the module
        # at it via monkeypatching SOC_AGENT_ROOT.
        from hooks.scripts import validate_report_precheck as vc

        sig_dir = tmp_path / "knowledge" / "signatures" / "sig-1" / "archetypes"
        (sig_dir / "alpha").mkdir(parents=True)
        (sig_dir / "alpha" / "story.md").write_text("# alpha story\n")
        (sig_dir / "alpha" / "trust-anchors.md").write_text("# alpha anchors\n")
        (sig_dir / "beta").mkdir(parents=True)
        (sig_dir / "beta" / "story.md").write_text("# beta story\n")
        (sig_dir / "gamma").mkdir(parents=True)
        # gamma has neither file — should be skipped silently

        monkeypatch.setattr(vc, "SOC_AGENT_ROOT", tmp_path)
        assert vc.load_archetype_description("sig-1", "alpha") == (
            "# alpha story\n\n\n# alpha anchors\n"
        )

    def test_load_archetype_description_missing(self, monkeypatch, tmp_path):
        from hooks.scripts import validate_report_precheck as vc
        monkeypatch.setattr(vc, "SOC_AGENT_ROOT", tmp_path)
        assert vc.load_archetype_description("sig-1", "nonexistent") is None

    def test_load_archetype_description_empty_inputs(self):
        assert load_archetype_description("", "alpha") is None
        assert load_archetype_description("sig-1", "") is None

    def test_load_sibling_archetypes_excludes_matched(self, monkeypatch, tmp_path):
        from hooks.scripts import validate_report_precheck as vc

        sig_dir = tmp_path / "knowledge" / "signatures" / "sig-1" / "archetypes"
        (sig_dir / "alpha").mkdir(parents=True)
        (sig_dir / "alpha" / "story.md").write_text("alpha\n")
        (sig_dir / "beta").mkdir(parents=True)
        (sig_dir / "beta" / "story.md").write_text("beta\n")
        (sig_dir / "gamma").mkdir(parents=True)
        (sig_dir / "gamma" / "story.md").write_text("gamma\n")

        monkeypatch.setattr(vc, "SOC_AGENT_ROOT", tmp_path)
        result = vc.load_sibling_archetypes("sig-1", "alpha")
        assert "alpha" not in result
        assert "beta" in result
        assert "gamma" in result

    def test_load_sibling_archetypes_no_signature(self):
        assert load_sibling_archetypes("", None) == ""

    def test_load_sibling_archetypes_unknown_signature(self, monkeypatch, tmp_path):
        from hooks.scripts import validate_report_precheck as vc
        monkeypatch.setattr(vc, "SOC_AGENT_ROOT", tmp_path)
        assert vc.load_sibling_archetypes("nope", None) == ""


# ---------------------------------------------------------------------------
# Unit tests: is_screen_resolved (text-based, defined in investigation_parse)
# ---------------------------------------------------------------------------


class TestIsScreenResolved:
    def test_screen_only(self):
        text = "## CONTEXTUALIZE\n## SCREEN\n**Result:** match\n## REPORT\n"
        assert is_screen_resolved(text) is True

    def test_screen_with_full_loop(self):
        text = (
            "## CONTEXTUALIZE\n## SCREEN\n## PREDICT (loop 1)\n"
            "## GATHER (loop 1)\n## ANALYZE (loop 1)\n## REPORT\n"
        )
        assert is_screen_resolved(text) is False

    def test_full_loop_only(self):
        text = (
            "## CONTEXTUALIZE\n## PREDICT (loop 1)\n"
            "## GATHER (loop 1)\n## ANALYZE (loop 1)\n## REPORT\n"
        )
        assert is_screen_resolved(text) is False


# ---------------------------------------------------------------------------
# Integration helpers
# ---------------------------------------------------------------------------


VALID_INVESTIGATION = """\
## CONTEXTUALIZE

**Alert:** SEC-001
**Source entity:** 10.0.1.50
**Playbook hypotheses:** ?monitoring-probe, ?brute-force

## PREDICT (loop 1)

**Selected lead:** authentication-history

## GATHER (loop 1)

**Lead:** authentication-history
**Raw observation:** 1 authentication attempt from 10.0.1.50

## ANALYZE (loop 1)

hypotheses:
  ?monitoring-probe:
    weight: "++"
    reasoning: matches monitoring cadence
  ?brute-force:
    weight: "--"
    reasoning: single attempt contradicts brute-force prediction of >50

## REPORT

**Verdict:** resolved — monitoring probe from approved source
**Confirmed hypothesis:** ?monitoring-probe

```yaml
conclude:
  termination:
    category: trust-root
    rationale: anchor confirmed
  disposition: benign
  confidence: high
  matched_archetype: monitoring-probe
  summary: monitoring probe from approved-monitoring-sources entry
```
"""


SCREEN_RESOLVED_INVESTIGATION = """\
## CONTEXTUALIZE

**Alert:** SEC-003

## SCREEN

**Result:** match
**Leads run:** authentication-history (no anomalies)
**Outcome:** proceeding to REPORT

## REPORT

**Verdict:** resolved — known monitoring probe pattern

```yaml
conclude:
  termination:
    category: trust-root
    rationale: screen match
  disposition: benign
  confidence: high
  matched_archetype: monitoring-probe
  summary: screen pattern match
```
"""


def _setup_run(
    tmp_path: Path,
    investigation_text: str = VALID_INVESTIGATION,
    signature_id: str = "wazuh-rule-5710",
    with_ticket_context: bool = True,
) -> tuple[Path, Path]:
    """Create a runs_dir + run_dir with the artifacts a passing run needs."""
    runs_dir = tmp_path / "runs"
    runs_dir.mkdir()
    run_dir = runs_dir / "run-test"
    run_dir.mkdir()
    meta = {"run_id": "run-test", "signature_id": signature_id, "salt": "deadbeef"}
    (run_dir / "meta.json").write_text(json.dumps(meta))
    (run_dir / "investigation.md").write_text(investigation_text)
    (run_dir / "alert.json").write_text(json.dumps({"id": "SEC-001"}))
    if with_ticket_context:
        (run_dir / "ticket_context.yaml").write_text("situation: ok\n")
    return runs_dir, run_dir


def _make_hook_event(
    file_path: str,
    tool_name: str = "Write",
    content: str | None = None,
    old_string: str = "",
    new_string: str = "",
) -> str:
    tool_input: dict = {"file_path": file_path}
    if tool_name == "Write":
        if content is None:
            try:
                content = Path(file_path).read_text()
            except OSError:
                content = ""
        tool_input["content"] = content
    elif tool_name == "Edit":
        tool_input["old_string"] = old_string
        tool_input["new_string"] = new_string
    return json.dumps(
        {
            "tool_name": tool_name,
            "tool_input": tool_input,
            "tool_use_id": "test-001",
            "session_id": "session-001",
        }
    )


def _make_fake_claude(
    bin_dir: Path,
    *,
    judge_a_output: str = "VERDICT: PASS — looks fine",
    judge_b_output: str = "VERDICT: PASS — looks fine",
    returncode: int = 0,
) -> Path:
    """Write a fake `claude` CLI that returns canned VERDICT lines.

    The shim reads the prompt from stdin (matching how the hook now
    invokes claude) and distinguishes Judge A from Judge B by sniffing
    for the unique heading from each prompt file. Tests call this once
    per case to set up; the resulting directory is prepended to PATH
    for the hook subprocess.
    """
    bin_dir.mkdir(parents=True, exist_ok=True)
    script = bin_dir / "claude"
    script.write_text(
        textwrap.dedent(
            f"""\
            #!/usr/bin/env python3
            import sys
            # `claude -p --model haiku --output-format text` with prompt on stdin
            prompt = sys.stdin.read()
            if "Pre-REPORT Judge — Log Integrity" in prompt:
                sys.stdout.write({judge_a_output!r})
            elif "Pre-REPORT Judge — Archetype" in prompt:
                sys.stdout.write({judge_b_output!r})
            else:
                sys.stdout.write("VERDICT: PASS — unknown prompt, defaulting")
            sys.exit({returncode})
            """
        )
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return script


def _run_hook(
    event: str,
    runs_dir: Path,
    fake_claude_dir: Path | None = None,
) -> subprocess.CompletedProcess:
    env = {**os.environ, "SOC_AGENT_RUNS_DIR": str(runs_dir)}
    if fake_claude_dir is not None:
        env["PATH"] = f"{fake_claude_dir}{os.pathsep}{env.get('PATH', '')}"
    return subprocess.run(
        [sys.executable, str(HOOK_SCRIPT)],
        input=event,
        capture_output=True,
        text=True,
        env=env,
    )


# ---------------------------------------------------------------------------
# Integration tests: hook via subprocess (with fake claude CLI)
# ---------------------------------------------------------------------------


class TestHookHappyPath:
    def test_both_judges_pass(self, tmp_path):
        runs_dir, run_dir = _setup_run(tmp_path)
        bin_dir = tmp_path / "bin"
        _make_fake_claude(bin_dir)
        event = _make_hook_event(str(run_dir / "investigation.md"))
        result = _run_hook(event, runs_dir, fake_claude_dir=bin_dir)
        assert result.returncode == 0, f"stderr: {result.stderr}"

    def test_edit_event_appending_conclude(self, tmp_path):
        # Realistic Edit: on-disk investigation.md ends at ANALYZE; the
        # Edit replaces the full pre-REPORT text with itself plus a
        # trailing ## REPORT section + conclude: yaml block.
        pre_conclude = VALID_INVESTIGATION.split("## REPORT", 1)[0]
        new_text = VALID_INVESTIGATION
        runs_dir, run_dir = _setup_run(tmp_path, investigation_text=pre_conclude)
        bin_dir = tmp_path / "bin"
        _make_fake_claude(bin_dir)
        event = _make_hook_event(
            str(run_dir / "investigation.md"),
            tool_name="Edit",
            old_string=pre_conclude,
            new_string=new_text,
        )
        result = _run_hook(event, runs_dir, fake_claude_dir=bin_dir)
        assert result.returncode == 0, f"stderr: {result.stderr}"


class TestHookJudgeFlags:
    def test_judge_a_flag_blocks(self, tmp_path):
        runs_dir, run_dir = _setup_run(tmp_path)
        bin_dir = tmp_path / "bin"
        _make_fake_claude(
            bin_dir,
            judge_a_output="LEGITIMACY_CHECK: FLAG — legitimacy_contract on live hypothesis not resolved\nVERDICT: FLAG — legitimacy",
        )
        event = _make_hook_event(str(run_dir / "investigation.md"))
        result = _run_hook(event, runs_dir, fake_claude_dir=bin_dir)
        assert result.returncode == 2
        assert "Judge A" in result.stderr
        assert "legitimacy" in result.stderr.lower()

    def test_judge_b_flag_blocks(self, tmp_path):
        runs_dir, run_dir = _setup_run(tmp_path)
        bin_dir = tmp_path / "bin"
        _make_fake_claude(
            bin_dir,
            judge_b_output="SHAPE_MATCH: FLAG — evidence contradicts story\nVERDICT: FLAG — shape",
        )
        event = _make_hook_event(str(run_dir / "investigation.md"))
        result = _run_hook(event, runs_dir, fake_claude_dir=bin_dir)
        assert result.returncode == 2
        assert "Judge B" in result.stderr

    def test_both_flag_surfaces_both(self, tmp_path):
        runs_dir, run_dir = _setup_run(tmp_path)
        bin_dir = tmp_path / "bin"
        _make_fake_claude(
            bin_dir,
            judge_a_output="VERDICT: FLAG — A reason",
            judge_b_output="VERDICT: FLAG — B reason",
        )
        event = _make_hook_event(str(run_dir / "investigation.md"))
        result = _run_hook(event, runs_dir, fake_claude_dir=bin_dir)
        assert result.returncode == 2
        assert "Judge A" in result.stderr
        assert "Judge B" in result.stderr

    def test_judge_subprocess_failure_blocks(self, tmp_path):
        runs_dir, run_dir = _setup_run(tmp_path)
        bin_dir = tmp_path / "bin"
        _make_fake_claude(bin_dir, returncode=1)
        event = _make_hook_event(str(run_dir / "investigation.md"))
        result = _run_hook(event, runs_dir, fake_claude_dir=bin_dir)
        assert result.returncode == 2
        assert "rc=1" in result.stderr or "CLI error" in result.stderr


class TestScreenResolved:
    def test_screen_resolved_skips_judges(self, tmp_path):
        # No fake claude on PATH — if the hook tried to invoke a judge it
        # would fail with FileNotFoundError. Screen-resolved runs must
        # bypass the judge dispatch entirely.
        runs_dir, run_dir = _setup_run(
            tmp_path, investigation_text=SCREEN_RESOLVED_INVESTIGATION
        )
        event = _make_hook_event(str(run_dir / "investigation.md"))
        result = _run_hook(event, runs_dir, fake_claude_dir=None)
        assert result.returncode == 0, f"stderr: {result.stderr}"

    def test_screen_resolved_still_checks_ticket_context(self, tmp_path):
        runs_dir, run_dir = _setup_run(
            tmp_path,
            investigation_text=SCREEN_RESOLVED_INVESTIGATION,
            with_ticket_context=False,
        )
        (runs_dir / "tool_audit.jsonl").write_text(
            json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}}) + "\n"
        )
        event = _make_hook_event(str(run_dir / "investigation.md"))
        result = _run_hook(event, runs_dir, fake_claude_dir=None)
        assert result.returncode == 2
        assert "ticket-context" in result.stderr


class TestPreYamlConcludeWrite:
    """First REPORT write (header + prose only, no yaml block yet) is
    a deferred-pass — wait for the conclude: yaml block before judging."""

    def test_header_only_passes(self, tmp_path):
        # Strip the yaml block — leaves just ## REPORT + verdict prose.
        text = VALID_INVESTIGATION.split("```yaml", 1)[0]
        runs_dir, run_dir = _setup_run(tmp_path, investigation_text=text)
        # No fake claude — must not invoke a judge.
        event = _make_hook_event(str(run_dir / "investigation.md"))
        result = _run_hook(event, runs_dir, fake_claude_dir=None)
        assert result.returncode == 0, f"stderr: {result.stderr}"


class TestHookNonTriggers:
    def test_no_investigation_md_target(self, tmp_path):
        runs_dir = tmp_path / "runs"
        runs_dir.mkdir()
        event = _make_hook_event("/tmp/other.md")
        result = _run_hook(event, runs_dir)
        assert result.returncode == 0

    def test_investigation_without_conclude(self, tmp_path):
        text = VALID_INVESTIGATION.replace("## REPORT", "## ANALYZE (loop 3)")
        runs_dir, run_dir = _setup_run(tmp_path, investigation_text=text)
        event = _make_hook_event(str(run_dir / "investigation.md"))
        result = _run_hook(event, runs_dir)
        assert result.returncode == 0

    def test_file_outside_runs_dir(self, tmp_path):
        runs_dir = tmp_path / "runs"
        runs_dir.mkdir()
        other = tmp_path / "other"
        other.mkdir()
        (other / "investigation.md").write_text("## REPORT\n")
        event = _make_hook_event(str(other / "investigation.md"))
        result = _run_hook(event, runs_dir)
        assert result.returncode == 0

    def test_nested_subdir_rejected(self, tmp_path):
        runs_dir = tmp_path / "runs"
        runs_dir.mkdir()
        nested = runs_dir / "run-x" / "subdir"
        nested.mkdir(parents=True)
        (nested / "investigation.md").write_text("## REPORT\n")
        event = _make_hook_event(str(nested / "investigation.md"))
        result = _run_hook(event, runs_dir)
        assert result.returncode == 0

    def test_unrelated_tool(self, tmp_path):
        # Bash event — hook should silently no-op.
        runs_dir = tmp_path / "runs"
        runs_dir.mkdir()
        event = json.dumps({
            "tool_name": "Bash",
            "tool_input": {"command": "ls"},
            "tool_use_id": "x",
            "session_id": "s",
        })
        result = _run_hook(event, runs_dir)
        assert result.returncode == 0


class TestTicketContextGate:
    def test_ticket_context_yaml_satisfies(self, tmp_path):
        runs_dir, run_dir = _setup_run(tmp_path, with_ticket_context=True)
        bin_dir = tmp_path / "bin"
        _make_fake_claude(bin_dir)
        event = _make_hook_event(str(run_dir / "investigation.md"))
        result = _run_hook(event, runs_dir, fake_claude_dir=bin_dir)
        assert result.returncode == 0

    def test_audit_log_satisfies(self, tmp_path):
        runs_dir, run_dir = _setup_run(tmp_path, with_ticket_context=False)
        (runs_dir / "tool_audit.jsonl").write_text(
            json.dumps({
                "tool_name": "Agent",
                "tool_input": {"prompt": "Read ticket-context.md ..."},
            }) + "\n"
        )
        bin_dir = tmp_path / "bin"
        _make_fake_claude(bin_dir)
        event = _make_hook_event(str(run_dir / "investigation.md"))
        result = _run_hook(event, runs_dir, fake_claude_dir=bin_dir)
        assert result.returncode == 0

    def test_no_audit_no_marker_silent_pass(self, tmp_path):
        # If the audit hook isn't running we have no signal — gate stays silent.
        runs_dir, run_dir = _setup_run(tmp_path, with_ticket_context=False)
        bin_dir = tmp_path / "bin"
        _make_fake_claude(bin_dir)
        event = _make_hook_event(str(run_dir / "investigation.md"))
        result = _run_hook(event, runs_dir, fake_claude_dir=bin_dir)
        assert result.returncode == 0

    def test_audit_present_no_dispatch_fails(self, tmp_path):
        runs_dir, run_dir = _setup_run(tmp_path, with_ticket_context=False)
        (runs_dir / "tool_audit.jsonl").write_text(
            json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}}) + "\n"
        )
        bin_dir = tmp_path / "bin"
        _make_fake_claude(bin_dir)
        event = _make_hook_event(str(run_dir / "investigation.md"))
        result = _run_hook(event, runs_dir, fake_claude_dir=bin_dir)
        assert result.returncode == 2
        assert "ticket-context" in result.stderr


# ---------------------------------------------------------------------------
# Unit tests: check_termination_vs_verdict
# ---------------------------------------------------------------------------


def _conclude_md(verdict: str, category: str, matched_archetype: str | None) -> str:
    ma_line = (
        f"  matched_archetype: {matched_archetype}\n"
        if matched_archetype is not None
        else "  matched_archetype: null\n"
    )
    return (
        "## REPORT\n\n"
        f"**Verdict:** {verdict} — test\n\n"
        "```yaml\n"
        "conclude:\n"
        "  termination:\n"
        f"    category: {category}\n"
        "    rationale: \"test\"\n"
        "  disposition: benign\n"
        "  confidence: high\n"
        f"{ma_line}"
        "  summary: \"test\"\n"
        "```\n"
    )


class TestCheckTerminationVsVerdict:
    def test_run_34_rejected_shape_fails(self):
        """Run #34's self-contradiction: exhaustion + resolved + archetype."""
        text = _conclude_md("resolved", "exhaustion-escalation", "monitoring-probe")
        err = check_termination_vs_verdict(text)
        assert err is not None
        assert "resolved" in err
        assert "exhaustion-escalation" in err
        assert "monitoring-probe" in err

    def test_run_34_recovered_shape_passes(self):
        text = _conclude_md("escalated", "exhaustion-escalation", None)
        assert check_termination_vs_verdict(text) is None

    def test_resolving_category_with_resolved_passes(self):
        text = _conclude_md("resolved", "trust-root", "monitoring-probe")
        assert check_termination_vs_verdict(text) is None

    def test_resolving_category_adversarial_refuted_passes(self):
        text = _conclude_md("resolved", "adversarial-refuted", "monitoring-probe")
        assert check_termination_vs_verdict(text) is None

    def test_severity_ceiling_allows_archetype_but_blocks_resolved(self):
        """severity-ceiling escalations can name an archetype (the archetype
        fits, but severity mandates escalation) — only Verdict is gated."""
        text = _conclude_md("resolved", "severity-ceiling", "monitoring-probe")
        err = check_termination_vs_verdict(text)
        assert err is not None
        assert "severity-ceiling" in err
        assert "resolved" in err
        # archetype block should NOT be present — allowed under severity-ceiling
        assert "matched_archetype: 'monitoring-probe'" not in err

    def test_severity_ceiling_with_escalated_passes(self):
        text = _conclude_md("escalated", "severity-ceiling", "monitoring-probe")
        assert check_termination_vs_verdict(text) is None

    def test_exhaustion_archetype_without_resolved_still_fails(self):
        """exhaustion-escalation blocks non-null archetype even if verdict is escalated."""
        text = _conclude_md("escalated", "exhaustion-escalation", "monitoring-probe")
        err = check_termination_vs_verdict(text)
        assert err is not None
        assert "exhaustion-escalation" in err

    def test_no_conclude_yaml_passes(self):
        text = "## REPORT\n\n**Verdict:** resolved\n"
        assert check_termination_vs_verdict(text) is None

    def test_missing_termination_category_passes(self):
        text = (
            "## REPORT\n\n**Verdict:** resolved\n"
            "```yaml\nconclude:\n  disposition: benign\n```\n"
        )
        assert check_termination_vs_verdict(text) is None
