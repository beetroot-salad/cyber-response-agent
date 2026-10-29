# ruff: noqa: PT018
"""#1214 attack-3 hole 7 (DC-14, deck PR #1042): the `__main__` block of `python -m defender.lifecycle` is exercised in a
real subprocess: it parses its own arguments, refuses a missing database address, and runs a subcommand, not only `--help`.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — fixture

DEFENDER = Path(__file__).resolve().parents[3]
TENANT = "7f3c1a52-9d4e-4b8a-a1c6-2e5d8b9f0c13"
DSN_ENV = "DEFENDER_DATABASE_DSN"


def _lifecycle(*args: str, dsn: str | None = None) -> subprocess.CompletedProcess[str]:
    env = {k: v for k, v in os.environ.items() if not k.startswith(("DEFENDER_", "LIFECYCLE_"))}
    env["PYTHONPATH"] = str(DEFENDER.parent)
    if dsn is not None:
        env[DSN_ENV] = dsn
    return subprocess.run([sys.executable, "-m", "defender.lifecycle", *args], cwd=DEFENDER.parent, env=env,  # noqa: S603
                          capture_output=True, text=True, timeout=120, check=False)


def test_the_command_with_no_subcommand_is_a_usage_error():
    """No argument: exit 2 with a usage line, not the help page and success (DC-14)."""
    done = _lifecycle()
    assert done.returncode == 2, (done.returncode, done.stdout, done.stderr)
    assert "usage" in done.stderr.lower()


def test_adopt_describes_the_old_issuer_directory_option():
    """`adopt --help` documents `--issuer-dir`, the old issuer directory adoption retires (Flow 5, O9)."""
    helped = _lifecycle("adopt", "--help")
    assert helped.returncode == 0 and "--issuer-dir" in helped.stdout


@pytest.mark.parametrize("command", [["serve"], ["adopt", TENANT, "--issuer-dir", "/nonexistent-issuer"]])
def test_a_subcommand_with_no_database_address_refuses_naming_it(command):
    """`serve` and `adopt` run their work: with no `DEFENDER_DATABASE_DSN` they exit non-zero naming it (DC-14)."""
    done = _lifecycle(*command)
    assert done.returncode != 0
    assert DSN_ENV in done.stderr, done.stderr
    assert "usage:" not in done.stdout


@pytest.mark.postgres
@pytest.mark.parametrize("command", [["serve"], ["adopt", TENANT, "--issuer-dir", "/nonexistent-issuer"]])
def test_a_subcommand_with_a_database_and_no_settings_refuses_as_the_command(migrated_database, command):  # noqa: F811
    """With a database at this revision but none of the lifecycle's settings, the subcommand itself refuses: exit 2, naming it (DC-14)."""
    done = _lifecycle(*command, dsn=migrated_database)
    assert done.returncode == 2, (done.returncode, done.stdout, done.stderr)
    assert command[0] in done.stderr, done.stderr
