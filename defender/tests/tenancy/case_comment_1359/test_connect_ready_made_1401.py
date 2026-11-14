"""#1401 (design r4 D2, r5): connect's scaffold validator over a ready-made case adapter's handoff.

- An adapter with no investigator tools beyond `health-check` needs no staged tenant half (skill, seed queries).
- `--case <file>` judges the handoff's system and the case record as the store will, comment cover included.
- The report prints the comment route the adapter sends for the handoff's settings.

Driven through the real command over the checkout's `jira`, `servicenow` and `cmdb` adapters.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[4]

JIRA_CLOUD = ("POST", "/rest/api/3/issue/*/comment")
JIRA_DESK = ("POST", "/rest/servicedeskapi/request/*/comment")
SERVICENOW = ("PATCH", "/api/now/table/incident/*")

CASE_BODY = "Disposition: {disposition}\n"


def _access(base: str, writes: tuple[tuple[str, str], ...]) -> str:
    return json.dumps({"access": "http-proxy", "base": base, "auth": {"scheme": "basic"}, "reads": [],
                       "writes": [{"method": m, "path": p} for m, p in writes]}) + "\n"


def _handoff(where: Path, system: str, config: str, access: str) -> Path:
    folder = where / system
    folder.mkdir(parents=True)
    (folder / "config.env").write_text(config, encoding="utf-8")
    (folder / "access.yaml").write_text(access, encoding="utf-8")
    return folder


def _jira(where: Path, *, desk: str, writes: tuple[tuple[str, str], ...]) -> Path:
    return _handoff(where, "jira", f'JIRA_TIMEOUT_SEC="30"\nJIRA_SERVICE_DESK="{desk}"\n',
                    _access("https://example.atlassian.net", writes))


def _servicenow(where: Path) -> Path:
    return _handoff(where, "servicenow", 'SERVICENOW_TIMEOUT_SEC="30"\nSERVICENOW_TABLE="incident"\n',
                    _access("https://example.service-now.com", (SERVICENOW,)))


def _case(where: Path, system: str, body: str = CASE_BODY) -> Path:
    path = where / "case-record.yaml"
    path.write_text(json.dumps({"system": system, "comment": {"body": body}}) + "\n", encoding="utf-8")
    return path


def _validate(*args: str) -> tuple[int, list[str], str]:
    """The command's exit code, its failure rows and its whole output."""
    done = subprocess.run([sys.executable, "-m", "defender.skills.connect.validate_scaffold", *args], cwd=REPO,
                          env={**os.environ, "PYTHONPATH": str(REPO)}, capture_output=True, text=True,
                          timeout=120, check=False)
    out = done.stdout + done.stderr
    assert "Traceback" not in out, out
    return done.returncode, [line for line in out.splitlines() if "[✗]" in line], out


@pytest.mark.parametrize("system", ["jira", "servicenow"])
def test_1401_a_ready_made_case_adapter_needs_no_staged_tenant_half(tmp_path, system):
    """A correct handoff for an adapter with no investigator tools passes with no `--staged`: there is no skill or seed
    query to stage for it."""
    folder = _jira(tmp_path, desk="no", writes=(JIRA_CLOUD,)) if system == "jira" else _servicenow(tmp_path)

    rc, failed, out = _validate(system, "--handoff", str(folder))

    assert failed == [], out
    assert rc == 0, out


def test_1401_an_adapter_with_investigator_tools_still_needs_its_staged_tenant_half(tmp_path):
    """Control: `cmdb` has tools the investigator calls, so its skill and seed queries are still asked for."""
    folder = _handoff(tmp_path, "cmdb", 'CMDB_TIMEOUT_SEC="10"\n',
                      _access("https://cmdb.example", ()))

    rc, failed, out = _validate("cmdb", "--handoff", str(folder))

    assert rc != 0, out
    assert any("--staged" in line for line in failed), out


def test_1401_case_check_fails_a_comment_route_the_access_does_not_cover(tmp_path):
    """A Jira service-desk handoff whose access declares only the cloud comment route is refused at `--case`, naming
    the route the adapter sends; the same handoff declaring the service-desk route passes."""
    bad = _jira(tmp_path / "bad", desk="yes", writes=(JIRA_CLOUD,))
    rc, failed, out = _validate("jira", "--handoff", str(bad), "--case", str(_case(tmp_path / "bad", "jira")))
    assert rc != 0, out
    assert any(JIRA_DESK[1] in line for line in failed), out

    good = _jira(tmp_path / "good", desk="yes", writes=(JIRA_DESK,))
    rc, failed, out = _validate("jira", "--handoff", str(good), "--case", str(_case(tmp_path / "good", "jira")))
    assert failed == [], out
    assert rc == 0, out


def test_1401_case_check_fails_a_case_record_naming_another_system(tmp_path):
    """The case record names the system the store will look for; one naming a system the handoff does not hold is
    refused, naming that system."""
    folder = _jira(tmp_path, desk="no", writes=(JIRA_CLOUD,))

    rc, failed, out = _validate("jira", "--handoff", str(folder), "--case", str(_case(tmp_path, "servicenow")))

    assert rc != 0, out
    assert any("servicenow" in line for line in failed), out


def test_1401_case_check_fails_an_unusable_case_record_naming_its_file(tmp_path):
    """A case record with no comment body is refused, naming the file the maintainer fixes."""
    folder = _jira(tmp_path, desk="no", writes=(JIRA_CLOUD,))
    case = tmp_path / "case-record.yaml"
    case.write_text(json.dumps({"system": "jira"}) + "\n", encoding="utf-8")

    rc, failed, out = _validate("jira", "--handoff", str(folder), "--case", str(case))

    assert rc != 0, out
    assert any(str(case) in line and "comment.body" in line for line in failed), out


@pytest.mark.parametrize(("make", "route"), [
    (lambda where: _jira(where, desk="no", writes=(JIRA_CLOUD,)), JIRA_CLOUD),
    (lambda where: _jira(where, desk="yes", writes=(JIRA_DESK,)), JIRA_DESK),
    (_servicenow, SERVICENOW),
], ids=["jira-cloud", "jira-desk", "servicenow"])
def test_1401_the_report_prints_the_comment_route_for_the_handoffs_settings(tmp_path, make, route):
    """The maintainer reads the route the adapter will send from the report, not from prose."""
    folder = make(tmp_path)

    _rc, _failed, out = _validate(folder.name, "--handoff", str(folder))

    assert any("[✓]" in line and f"{route[0]} {route[1]}" in line for line in out.splitlines()), out


@pytest.mark.parametrize(("verbs", "needed"), [
    ({}, False),
    ({"health-check": object()}, False),
    ({"health-check": object(), "get-host": object()}, True),
    ({"get-host": object()}, True),
    (None, True),
], ids=["no-tools", "health-check-only", "a-tool-beside-health-check", "a-tool-alone", "unresolved"])
def test_1401_the_tenant_half_is_needed_exactly_when_the_adapter_offers_a_tool_beyond_health_check(verbs, needed):
    """A health check is not a tool the investigator queries (#1460 gives Jira and ServiceNow one); any other verb is.
    An adapter that could not be resolved still has its missing half reported."""
    from defender.skills.connect import validate_scaffold

    assert validate_scaffold.needs_tenant_half(verbs) is needed


def test_1401_case_without_a_handoff_is_a_failure_not_a_silent_skip(tmp_path):
    """`--case` is judged together with the handoff's system; given alone it fails, saying so."""
    rc, failed, out = _validate("jira", "--case", str(_case(tmp_path, "jira")))

    assert rc != 0, out
    assert any("--case" in line and "--handoff" in line for line in failed), out


@pytest.mark.parametrize("link", ["symlink", "hard link"])
def test_1401_case_check_reads_the_file_as_set_case_does_refusing_a_link(tmp_path, link):
    """`tenant.py set-case` reads the case record as a regular file with one link, never following one; a file it would
    refuse is a failure here too, naming the path given, not a pass."""
    folder = _jira(tmp_path, desk="no", writes=(JIRA_CLOUD,))
    target = _case(tmp_path, "jira")
    given = tmp_path / "given.yaml"
    if link == "symlink":
        given.symlink_to(target)
    else:
        os.link(target, given)

    rc, failed, out = _validate("jira", "--handoff", str(folder), "--case", str(given))

    assert rc != 0, out
    assert any(str(given) in line for line in failed), out


def test_1401_a_staged_half_given_for_a_no_tools_adapter_is_still_judged(tmp_path):
    """Not asking for a tenant half is not ignoring one that was given: a broken staged skill still fails."""
    folder = _jira(tmp_path, desk="no", writes=(JIRA_CLOUD,))
    skill = tmp_path / "staged" / "skills" / "jira"
    skill.mkdir(parents=True)
    (skill / "SKILL.md").write_text("---\nname: not-jira\ndescription: x\n---\nbody\n", encoding="utf-8")

    rc, failed, out = _validate("jira", "--handoff", str(folder), "--staged", str(tmp_path / "staged"))

    assert rc != 0, out
    assert any("SKILL.md" in line for line in failed), out
