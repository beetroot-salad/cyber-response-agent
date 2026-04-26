"""Unit tests for the stub asset/identity adapter CLI.

Exercises the LookupContract surface against a synthetic JSON fixture:
    - health-check returns connected:true with bucket sizes when the file loads
    - health-check returns connected:false on missing/malformed data
    - lookup hits return the verbatim record
    - lookup misses return found=false (exit 0; not-found is valid)
    - missing SOC_AGENT_ASSET_DATA_PATH fails when invoked, not at import
    - unsupported key_field is a usage error
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest


SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
CLI_PATH = SOC_AGENT_ROOT / "scripts" / "tools" / "stub_asset_cli.py"


def _run(argv: list[str], *, env: dict | None = None) -> subprocess.CompletedProcess:
    cmd = [sys.executable, str(CLI_PATH), *argv]
    return subprocess.run(cmd, capture_output=True, text=True, env=env)


@pytest.fixture
def fixture_data(tmp_path) -> Path:
    data = {
        "ips": {
            "172.22.0.10": {"hostname": "monitoring-host", "role": "monitoring"},
            "10.0.0.5": {"hostname": "db-01", "role": "workload"},
        },
        "users": {
            "nagios": {"display_name": "Nagios", "type": "service"},
        },
        "hosts": {
            "target-endpoint": {"role": "workload", "env": "prod"},
        },
    }
    path = tmp_path / "asset_data.json"
    path.write_text(json.dumps(data))
    return path


@pytest.fixture
def base_env(fixture_data) -> dict:
    return {
        "SOC_AGENT_ASSET_DATA_PATH": str(fixture_data),
        "PATH": "/usr/bin:/bin",
    }


class TestHealthCheck:
    def test_connected_when_data_loads(self, base_env):
        proc = _run(["health-check"], env=base_env)
        assert proc.returncode == 0, proc.stderr
        out = json.loads(proc.stdout)
        assert out["connected"] is True
        assert out["detail"]["ips"] == 2
        assert out["detail"]["users"] == 1
        assert out["detail"]["hosts"] == 1

    def test_disconnected_when_env_var_missing(self):
        proc = _run(["health-check"], env={"PATH": "/usr/bin:/bin"})
        assert proc.returncode == 1
        out = json.loads(proc.stdout)
        assert out["connected"] is False
        assert "SOC_AGENT_ASSET_DATA_PATH" in out["error"]

    def test_disconnected_when_path_does_not_exist(self, tmp_path):
        env = {
            "SOC_AGENT_ASSET_DATA_PATH": str(tmp_path / "missing.json"),
            "PATH": "/usr/bin:/bin",
        }
        proc = _run(["health-check"], env=env)
        assert proc.returncode == 1
        out = json.loads(proc.stdout)
        assert out["connected"] is False
        assert "does not exist" in out["error"]

    def test_disconnected_when_data_malformed(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text("not valid json {")
        env = {
            "SOC_AGENT_ASSET_DATA_PATH": str(path),
            "PATH": "/usr/bin:/bin",
        }
        proc = _run(["health-check"], env=env)
        assert proc.returncode == 1
        out = json.loads(proc.stdout)
        assert out["connected"] is False
        assert "did not parse as JSON" in out["error"]


class TestLookupHits:
    def test_ip_hit_returns_record(self, base_env):
        proc = _run(["lookup", "ip", "172.22.0.10"], env=base_env)
        assert proc.returncode == 0, proc.stderr
        out = json.loads(proc.stdout)
        assert out["found"] is True
        assert out["record"] == {"hostname": "monitoring-host", "role": "monitoring"}
        assert out["key_field"] == "ip"
        assert out["key_value"] == "172.22.0.10"
        assert out["error"] is None

    def test_user_hit_returns_record(self, base_env):
        proc = _run(["lookup", "user", "nagios"], env=base_env)
        assert proc.returncode == 0, proc.stderr
        out = json.loads(proc.stdout)
        assert out["found"] is True
        assert out["record"]["type"] == "service"

    def test_host_hit_returns_record(self, base_env):
        proc = _run(["lookup", "host", "target-endpoint"], env=base_env)
        assert proc.returncode == 0, proc.stderr
        out = json.loads(proc.stdout)
        assert out["found"] is True
        assert out["record"]["env"] == "prod"


class TestLookupMisses:
    def test_ip_miss_is_not_an_error(self, base_env):
        proc = _run(["lookup", "ip", "203.0.113.99"], env=base_env)
        assert proc.returncode == 0, proc.stderr
        out = json.loads(proc.stdout)
        assert out["found"] is False
        assert out["record"] is None
        assert out["error"] is None

    def test_user_miss_is_not_an_error(self, base_env):
        proc = _run(["lookup", "user", "ghost"], env=base_env)
        assert proc.returncode == 0
        out = json.loads(proc.stdout)
        assert out["found"] is False


class TestLookupErrors:
    def test_unsupported_key_field_rejected(self, base_env):
        proc = _run(["lookup", "bogus", "x"], env=base_env)
        # argparse rejects values outside `choices` with exit 2.
        assert proc.returncode == 2
        assert "invalid choice" in proc.stderr.lower()

    def test_lookup_without_env_var_fails(self):
        proc = _run(
            ["lookup", "ip", "172.22.0.10"],
            env={"PATH": "/usr/bin:/bin"},
        )
        assert proc.returncode == 1
        assert "SOC_AGENT_ASSET_DATA_PATH" in proc.stderr

    def test_lookup_with_corrupt_bucket_shape_fails(self, tmp_path):
        path = tmp_path / "bad.json"
        path.write_text(json.dumps({"ips": "not a dict"}))
        env = {
            "SOC_AGENT_ASSET_DATA_PATH": str(path),
            "PATH": "/usr/bin:/bin",
        }
        proc = _run(["lookup", "ip", "1.2.3.4"], env=env)
        assert proc.returncode == 1
        assert "must be a JSON object" in proc.stderr


class TestPlaygroundFixture:
    """Sanity-check the shipped playground fixture used by integration tests."""

    def test_fixture_contains_expected_records(self):
        fixture = (
            SOC_AGENT_ROOT / "tests" / "fixtures" / "asset_data" / "playground.json"
        )
        env = {
            "SOC_AGENT_ASSET_DATA_PATH": str(fixture),
            "PATH": "/usr/bin:/bin",
        }
        proc = _run(["lookup", "ip", "172.22.0.10"], env=env)
        out = json.loads(proc.stdout)
        assert out["found"] is True
        assert out["record"]["hostname"] == "monitoring-host"

        proc = _run(["lookup", "user", "nagios"], env=env)
        out = json.loads(proc.stdout)
        assert out["found"] is True
        assert out["record"]["type"] == "service"
