"""Tests for scripts/siem/wazuh_cli.py — config loading, pagination, input validation."""

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

# Add scripts/siem to path so we can import wazuh_cli
SIEM_DIR = Path(__file__).resolve().parent.parent / "scripts" / "siem"
sys.path.insert(0, str(SIEM_DIR))

# Patch opensearchpy before importing wazuh_cli (it's not installed in test env)
sys.modules["opensearchpy"] = MagicMock()

import wazuh_cli  # noqa: E402


# ---------------------------------------------------------------------------
# Config loading
# ---------------------------------------------------------------------------

class TestLoadConfig:
    def test_loads_from_config_env(self, tmp_path, monkeypatch):
        config_file = tmp_path / "config.env"
        config_file.write_text(
            'WAZUH_INDEX="my-alerts-*"\n'
            'WAZUH_API_ENDPOINT="https://mgr:55000"\n'
            'WAZUH_INDEXER_ENDPOINT="https://idx:9200"\n'
            'WAZUH_RETENTION_DAYS="30"\n'
            'WAZUH_SSL_VERIFY="true"\n'
        )
        monkeypatch.setattr(wazuh_cli, "CONFIG_PATH", config_file)
        # Clear any env overrides
        for key in wazuh_cli.REQUIRED_CONFIG_KEYS:
            monkeypatch.delenv(key, raising=False)

        config = wazuh_cli.load_config()
        assert config["WAZUH_INDEX"] == "my-alerts-*"
        assert config["WAZUH_RETENTION_DAYS"] == "30"
        assert config["WAZUH_SSL_VERIFY"] == "true"

    def test_env_vars_override_config_file(self, tmp_path, monkeypatch):
        config_file = tmp_path / "config.env"
        config_file.write_text(
            'WAZUH_INDEX="file-index"\n'
            'WAZUH_API_ENDPOINT="https://mgr:55000"\n'
            'WAZUH_INDEXER_ENDPOINT="https://idx:9200"\n'
            'WAZUH_RETENTION_DAYS="90"\n'
            'WAZUH_SSL_VERIFY="false"\n'
        )
        monkeypatch.setattr(wazuh_cli, "CONFIG_PATH", config_file)
        monkeypatch.setenv("WAZUH_INDEX", "env-index")

        config = wazuh_cli.load_config()
        assert config["WAZUH_INDEX"] == "env-index"

    def test_missing_config_file_exits(self, tmp_path, monkeypatch):
        monkeypatch.setattr(wazuh_cli, "CONFIG_PATH", tmp_path / "nonexistent.env")
        for key in wazuh_cli.REQUIRED_CONFIG_KEYS:
            monkeypatch.delenv(key, raising=False)
        with pytest.raises(SystemExit) as exc_info:
            wazuh_cli.load_config()
        assert exc_info.value.code == 2

    def test_missing_required_keys_exits(self, tmp_path, monkeypatch):
        config_file = tmp_path / "config.env"
        config_file.write_text('WAZUH_INDEX="alerts-*"\n')  # Missing other keys
        monkeypatch.setattr(wazuh_cli, "CONFIG_PATH", config_file)
        for key in wazuh_cli.REQUIRED_CONFIG_KEYS:
            monkeypatch.delenv(key, raising=False)
        with pytest.raises(SystemExit) as exc_info:
            wazuh_cli.load_config()
        assert exc_info.value.code == 2

    def test_comments_and_blank_lines_ignored(self, tmp_path, monkeypatch):
        config_file = tmp_path / "config.env"
        config_file.write_text(
            "# This is a comment\n"
            "\n"
            'WAZUH_INDEX="alerts-*"\n'
            "# Another comment\n"
            'WAZUH_API_ENDPOINT="https://mgr:55000"\n'
            'WAZUH_INDEXER_ENDPOINT="https://idx:9200"\n'
            'WAZUH_RETENTION_DAYS="90"\n'
            'WAZUH_SSL_VERIFY="false"\n'
        )
        monkeypatch.setattr(wazuh_cli, "CONFIG_PATH", config_file)
        for key in wazuh_cli.REQUIRED_CONFIG_KEYS:
            monkeypatch.delenv(key, raising=False)
        config = wazuh_cli.load_config()
        assert config["WAZUH_INDEX"] == "alerts-*"


# ---------------------------------------------------------------------------
# SSL config
# ---------------------------------------------------------------------------

class TestSSLConfig:
    def test_ssl_verify_false(self):
        assert wazuh_cli._ssl_verify({"WAZUH_SSL_VERIFY": "false"}) is False

    def test_ssl_verify_true(self):
        assert wazuh_cli._ssl_verify({"WAZUH_SSL_VERIFY": "true"}) is True

    def test_ssl_verify_yes(self):
        assert wazuh_cli._ssl_verify({"WAZUH_SSL_VERIFY": "yes"}) is True

    def test_ssl_verify_missing_warns(self, capsys):
        assert wazuh_cli._ssl_verify({}) is False
        assert "warning: WAZUH_SSL_VERIFY not set" in capsys.readouterr().err

    def test_ca_cert_path_empty(self):
        assert wazuh_cli._ca_cert_path({"WAZUH_CA_CERT": ""}) is None

    def test_ca_cert_path_set(self):
        assert wazuh_cli._ca_cert_path({"WAZUH_CA_CERT": "/etc/ssl/ca.pem"}) == "/etc/ssl/ca.pem"


# ---------------------------------------------------------------------------
# Credential validation
# ---------------------------------------------------------------------------

class TestCredentials:
    def test_indexer_missing_user_exits(self, monkeypatch):
        monkeypatch.delenv("WAZUH_INDEXER_USER", raising=False)
        monkeypatch.delenv("WAZUH_INDEXER_PASSWORD", raising=False)
        config = {"WAZUH_INDEXER_ENDPOINT": "https://idx:9200"}
        with pytest.raises(SystemExit) as exc_info:
            wazuh_cli.get_indexer_client(config)
        assert exc_info.value.code == 2

    def test_indexer_missing_password_exits(self, monkeypatch):
        monkeypatch.setenv("WAZUH_INDEXER_USER", "admin")
        monkeypatch.delenv("WAZUH_INDEXER_PASSWORD", raising=False)
        config = {"WAZUH_INDEXER_ENDPOINT": "https://idx:9200"}
        with pytest.raises(SystemExit) as exc_info:
            wazuh_cli.get_indexer_client(config)
        assert exc_info.value.code == 2

    def test_manager_missing_creds_exits(self, monkeypatch):
        monkeypatch.delenv("WAZUH_API_USER", raising=False)
        monkeypatch.delenv("WAZUH_API_PASSWORD", raising=False)
        config = {"WAZUH_API_ENDPOINT": "https://mgr:55000"}
        with pytest.raises(SystemExit) as exc_info:
            wazuh_cli.authenticate_manager(config)
        assert exc_info.value.code == 2


# ---------------------------------------------------------------------------
# Pagination
# ---------------------------------------------------------------------------

def _make_hit(ts, doc_id):
    """Create a mock OpenSearch hit."""
    return {
        "_source": {"timestamp": ts, "rule": {"id": "5710"}},
        "sort": [ts, doc_id],
    }


class TestQueryAlertsPagination:
    def _mock_search(self, pages):
        """Return a side_effect function that yields pages in order, then empty."""
        call_count = [0]
        def search_fn(**kwargs):
            idx = call_count[0]
            call_count[0] += 1
            if idx < len(pages):
                return pages[idx]
            return {"hits": {"total": {"value": 0}, "hits": []}}
        return search_fn

    def test_single_page(self):
        hits = [_make_hit(f"2026-04-0{i+1}T00:00:00Z", str(i)) for i in range(3)]
        pages = [
            {"hits": {"total": {"value": 3}, "hits": hits}},
        ]
        client = MagicMock()
        client.search.side_effect = self._mock_search(pages)
        config = {"WAZUH_INDEX": "alerts-*"}

        items, total = wazuh_cli.query_alerts(client, config, "*", "2026-04-01", "2026-04-05", limit=10)
        assert len(items) == 3
        assert total == 3
        # First call returns 3 hits, second call returns empty → 2 calls total
        assert client.search.call_count == 2

    def test_count_only_limit_zero(self):
        client = MagicMock()
        client.search.return_value = {"hits": {"total": {"value": 42}, "hits": []}}
        config = {"WAZUH_INDEX": "alerts-*"}

        items, total = wazuh_cli.query_alerts(client, config, "*", "2026-04-01", "2026-04-05", limit=0)
        assert items == []
        assert total == 42
        body = client.search.call_args.kwargs["body"]
        assert body["size"] == 0

    def test_multi_page(self, monkeypatch):
        monkeypatch.setattr(wazuh_cli, "PAGE_SIZE", 2)
        page1_hits = [_make_hit("2026-04-05T00:00:00Z", "a"), _make_hit("2026-04-04T00:00:00Z", "b")]
        page2_hits = [_make_hit("2026-04-03T00:00:00Z", "c")]

        pages = [
            {"hits": {"total": {"value": 3}, "hits": page1_hits}},
            {"hits": {"total": {"value": 3}, "hits": page2_hits}},
        ]
        client = MagicMock()
        client.search.side_effect = self._mock_search(pages)
        config = {"WAZUH_INDEX": "alerts-*"}

        items, total = wazuh_cli.query_alerts(client, config, "*", "2026-04-01", "2026-04-06", limit=5)
        assert len(items) == 3
        assert total == 3
        # page1 (2 hits) + page2 (1 hit) + empty page = 3 calls
        assert client.search.call_count == 3
        # Second call should have search_after from last hit of page 1
        second_body = client.search.call_args_list[1].kwargs["body"]
        assert "search_after" in second_body
        assert second_body["search_after"] == ["2026-04-04T00:00:00Z", "b"]

    def test_stops_at_limit(self, monkeypatch):
        monkeypatch.setattr(wazuh_cli, "PAGE_SIZE", 2)
        page1_hits = [_make_hit("2026-04-05T00:00:00Z", "a"), _make_hit("2026-04-04T00:00:00Z", "b")]
        page2_hits = [_make_hit("2026-04-03T00:00:00Z", "c"), _make_hit("2026-04-02T00:00:00Z", "d")]

        pages = [
            {"hits": {"total": {"value": 100}, "hits": page1_hits}},
            {"hits": {"total": {"value": 100}, "hits": page2_hits}},
        ]
        client = MagicMock()
        client.search.side_effect = self._mock_search(pages)
        config = {"WAZUH_INDEX": "alerts-*"}

        items, total = wazuh_cli.query_alerts(client, config, "*", "2026-04-01", "2026-04-06", limit=3)
        assert len(items) == 3
        # Second call should request size=1 (remaining)
        second_body = client.search.call_args_list[1].kwargs["body"]
        assert second_body["size"] == 1

    def test_empty_result(self):
        pages = [{"hits": {"total": {"value": 0}, "hits": []}}]
        client = MagicMock()
        client.search.side_effect = self._mock_search(pages)
        config = {"WAZUH_INDEX": "alerts-*"}

        items, total = wazuh_cli.query_alerts(client, config, "*", "2026-04-01", "2026-04-05", limit=10)
        assert items == []
        assert total == 0


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

class TestInputValidation:
    def test_limit_capped(self):
        """--limit is capped at 10000 in main()."""
        parser = wazuh_cli.build_parser()
        args = parser.parse_args(["--query", "test", "--limit", "50000"])
        args.limit = min(args.limit, 10000)
        assert args.limit == 10000

    def test_parse_duration_valid(self):
        td = wazuh_cli.parse_duration("1h")
        assert td.total_seconds() == 3600

    def test_parse_duration_invalid(self):
        with pytest.raises(ValueError):
            wazuh_cli.parse_duration("abc")
