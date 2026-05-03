"""Tests for scripts/cleanup_runs.py and schemas/retention.py."""

import json
import os
import sys
from datetime import datetime, timedelta, UTC
from pathlib import Path
from unittest.mock import patch

import pytest

SOC_AGENT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(SOC_AGENT_ROOT))

from schemas.retention import (  # noqa: E402
    DEFAULT_AUDIT_MAX_AGE_DAYS,
    DEFAULT_RUN_MAX_AGE_DAYS,
    DEFAULT_TRACE_MAX_AGE_DAYS,
    RetentionPolicy,
    load_retention_policy,
)
from scripts.cleanup_runs import (  # noqa: E402
    clean_jsonl,
    clean_run_dirs,
    get_run_timestamp,
    is_dir_expired,
    parse_jsonl_timestamp,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_run_dir(runs_dir: Path, name: str, age_days: float) -> Path:
    """Create a fake run directory with a meta.json containing created_at."""
    d = runs_dir / name
    d.mkdir(parents=True)
    (d / "alert.json").write_text("{}")
    created_at = (datetime.now(UTC) - timedelta(days=age_days)).isoformat()
    (d / "meta.json").write_text(json.dumps({"run_id": name, "created_at": created_at}))
    return d


def _make_run_dir_no_meta(runs_dir: Path, name: str, age_days: float) -> Path:
    """Create a run directory without meta.json — exercises the mtime fallback."""
    d = runs_dir / name
    d.mkdir(parents=True)
    (d / "alert.json").write_text("{}")
    mtime = (datetime.now(UTC) - timedelta(days=age_days)).timestamp()
    os.utime(d, (mtime, mtime))
    return d


def _make_jsonl_line(age_days: float, **extra) -> str:
    """Return a JSONL line whose timestamp is age_days in the past."""
    ts = (datetime.now(UTC) - timedelta(days=age_days)).isoformat()
    entry = {"timestamp": ts, "run_id": "test-run"}
    entry.update(extra)
    return json.dumps(entry) + "\n"


def _write_jsonl(path: Path, lines: list[str]) -> None:
    path.write_text("".join(lines), encoding="utf-8")


def _cutoff(days: float) -> datetime:
    return datetime.now(UTC) - timedelta(days=days)


# ---------------------------------------------------------------------------
# RetentionPolicy schema
# ---------------------------------------------------------------------------

class TestRetentionSchema:
    def test_defaults_are_positive(self):
        assert DEFAULT_RUN_MAX_AGE_DAYS > 0
        assert DEFAULT_AUDIT_MAX_AGE_DAYS > 0
        assert DEFAULT_TRACE_MAX_AGE_DAYS > 0

    def test_validate_returns_empty_for_valid(self):
        assert RetentionPolicy(90, 365, 30).validate() == []

    @pytest.mark.parametrize("field,value,fragment", [
        ("run",   0,  "run_max_age_days"),
        ("audit", 0,  "audit_max_age_days"),
        ("trace", 0,  "trace_max_age_days"),
        ("run",   -1, "run_max_age_days"),
    ], ids=["run-zero", "audit-zero", "trace-zero", "run-negative"])
    def test_validate_returns_error_for_nonpositive(self, field, value, fragment):
        policy = RetentionPolicy(
            run_max_age_days=value if field == "run" else 90,
            audit_max_age_days=value if field == "audit" else 365,
            trace_max_age_days=value if field == "trace" else 30,
        )
        errors = policy.validate()
        assert any(fragment in e for e in errors), errors

    def test_load_uses_defaults_when_env_unset(self):
        clean = {
            k: v for k, v in os.environ.items()
            if k not in {"SOC_AGENT_RUN_MAX_AGE_DAYS",
                         "SOC_AGENT_AUDIT_MAX_AGE_DAYS",
                         "SOC_AGENT_TRACE_MAX_AGE_DAYS"}
        }
        with patch.dict("os.environ", clean, clear=True):
            policy = load_retention_policy()
        assert policy.run_max_age_days   == DEFAULT_RUN_MAX_AGE_DAYS
        assert policy.audit_max_age_days == DEFAULT_AUDIT_MAX_AGE_DAYS
        assert policy.trace_max_age_days == DEFAULT_TRACE_MAX_AGE_DAYS

    def test_load_reads_env_vars(self):
        with patch.dict("os.environ", {"SOC_AGENT_RUN_MAX_AGE_DAYS": "45"}):
            policy = load_retention_policy()
        assert policy.run_max_age_days == 45

    @pytest.mark.parametrize("bad_value", ["not-a-number", "1.5", "abc", ""],
                              ids=["word", "float", "letters", "empty-non-issue"])
    def test_load_exits_on_non_integer(self, bad_value):
        if bad_value == "":
            # empty string means unset → uses default, not an error
            with patch.dict("os.environ", {"SOC_AGENT_RUN_MAX_AGE_DAYS": bad_value}):
                policy = load_retention_policy()
            assert policy.run_max_age_days == DEFAULT_RUN_MAX_AGE_DAYS
        else:
            with patch.dict("os.environ", {"SOC_AGENT_RUN_MAX_AGE_DAYS": bad_value}):
                with pytest.raises(SystemExit) as exc:
                    load_retention_policy()
            assert exc.value.code == 1

    @pytest.mark.parametrize("bad_value", ["0", "-1", "-100"],
                              ids=["zero", "neg-one", "large-neg"])
    def test_load_exits_on_nonpositive(self, bad_value):
        with patch.dict("os.environ", {"SOC_AGENT_AUDIT_MAX_AGE_DAYS": bad_value}):
            with pytest.raises(SystemExit) as exc:
                load_retention_policy()
        assert exc.value.code == 1


# ---------------------------------------------------------------------------
# get_run_timestamp / is_dir_expired
# ---------------------------------------------------------------------------

class TestGetRunTimestamp:
    def test_reads_created_at_from_meta_json(self, tmp_path):
        d = _make_run_dir(tmp_path, "run", age_days=50)
        ts = get_run_timestamp(d)
        # Should be ~50 days ago; allow a few seconds of test execution slack.
        age = (datetime.now(UTC) - ts).total_seconds()
        assert 49.9 * 86400 < age < 50.1 * 86400

    def test_falls_back_to_mtime_when_no_meta(self, tmp_path):
        d = _make_run_dir_no_meta(tmp_path, "run", age_days=50)
        ts = get_run_timestamp(d)
        age = (datetime.now(UTC) - ts).total_seconds()
        assert 49.9 * 86400 < age < 50.1 * 86400

    def test_falls_back_to_mtime_on_corrupt_meta(self, tmp_path):
        d = _make_run_dir_no_meta(tmp_path, "run", age_days=50)
        (d / "meta.json").write_text("not json")
        # Writing meta.json updated the dir mtime — reset it so fallback is testable.
        mtime = (datetime.now(UTC) - timedelta(days=50)).timestamp()
        os.utime(d, (mtime, mtime))
        ts = get_run_timestamp(d)
        age = (datetime.now(UTC) - ts).total_seconds()
        assert 49.9 * 86400 < age < 50.1 * 86400

    def test_meta_takes_precedence_over_mtime(self, tmp_path):
        # meta.json says 100 days old; mtime says 1 day old.
        # get_run_timestamp should return the meta.json value.
        d = _make_run_dir(tmp_path, "run", age_days=100)
        recent_mtime = (datetime.now(UTC) - timedelta(days=1)).timestamp()
        os.utime(d, (recent_mtime, recent_mtime))
        ts = get_run_timestamp(d)
        age_days = (datetime.now(UTC) - ts).days
        assert age_days >= 99  # meta.json wins, not the recent mtime

    def test_old_dir_is_expired(self, tmp_path):
        d = _make_run_dir(tmp_path, "old", age_days=100)
        assert is_dir_expired(d, _cutoff(90)) is True

    def test_new_dir_is_not_expired(self, tmp_path):
        d = _make_run_dir(tmp_path, "new", age_days=10)
        assert is_dir_expired(d, _cutoff(90)) is False

    def test_boundary_is_strictly_less_than(self, tmp_path):
        # A run whose created_at equals the cutoff is NOT expired (strict <).
        d = _make_run_dir(tmp_path, "boundary", age_days=89.99)
        assert is_dir_expired(d, _cutoff(90)) is False


# ---------------------------------------------------------------------------
# parse_jsonl_timestamp
# ---------------------------------------------------------------------------

class TestParseJsonlTimestamp:
    def test_iso_utc_timestamp(self):
        line = json.dumps({"timestamp": "2026-01-01T00:00:00+00:00"})
        dt = parse_jsonl_timestamp(line)
        assert dt is not None
        assert dt.tzinfo is not None

    def test_isoformat_with_microseconds(self):
        line = json.dumps({"timestamp": "2026-01-01T00:00:00.123456+00:00"})
        assert parse_jsonl_timestamp(line) is not None

    def test_missing_timestamp_field(self):
        line = json.dumps({"run_id": "x"})
        assert parse_jsonl_timestamp(line) is None

    def test_null_timestamp_field(self):
        line = json.dumps({"timestamp": None})
        assert parse_jsonl_timestamp(line) is None

    def test_malformed_timestamp_string(self):
        line = json.dumps({"timestamp": "not-a-date"})
        assert parse_jsonl_timestamp(line) is None

    def test_malformed_json(self):
        assert parse_jsonl_timestamp("this is not json") is None

    def test_empty_string(self):
        assert parse_jsonl_timestamp("") is None

    def test_naive_timestamp_treated_as_utc(self):
        # Timestamps without timezone info should be accepted (assumed UTC).
        line = json.dumps({"timestamp": "2026-01-01T00:00:00"})
        dt = parse_jsonl_timestamp(line)
        assert dt is not None
        assert dt.tzinfo == UTC


# ---------------------------------------------------------------------------
# clean_run_dirs
# ---------------------------------------------------------------------------

class TestCleanRunDirs:
    def test_deletes_expired_dirs(self, tmp_path):
        _make_run_dir(tmp_path, "old", age_days=100)
        deleted, skipped = clean_run_dirs(tmp_path, _cutoff(90), dry_run=False, verbose=False)
        assert deleted == 1
        assert skipped == 0
        assert not (tmp_path / "old").exists()

    def test_keeps_recent_dirs(self, tmp_path):
        _make_run_dir(tmp_path, "new", age_days=10)
        deleted, skipped = clean_run_dirs(tmp_path, _cutoff(90), dry_run=False, verbose=False)
        assert deleted == 0
        assert skipped == 1
        assert (tmp_path / "new").exists()

    def test_mixed_dirs(self, tmp_path):
        _make_run_dir(tmp_path, "old1", age_days=120)
        _make_run_dir(tmp_path, "old2", age_days=95)
        _make_run_dir(tmp_path, "new1", age_days=5)
        _make_run_dir(tmp_path, "new2", age_days=30)
        _make_run_dir(tmp_path, "new3", age_days=89)
        deleted, skipped = clean_run_dirs(tmp_path, _cutoff(90), dry_run=False, verbose=False)
        assert deleted == 2
        assert skipped == 3
        assert not (tmp_path / "old1").exists()
        assert not (tmp_path / "old2").exists()

    def test_dry_run_leaves_dirs_intact(self, tmp_path):
        _make_run_dir(tmp_path, "old", age_days=100)
        deleted, skipped = clean_run_dirs(tmp_path, _cutoff(90), dry_run=True, verbose=False)
        assert deleted == 1  # reported as would-delete
        assert (tmp_path / "old").exists()  # but not actually deleted

    def test_empty_runs_dir(self, tmp_path):
        deleted, skipped = clean_run_dirs(tmp_path, _cutoff(90), dry_run=False, verbose=False)
        assert deleted == 0
        assert skipped == 0

    def test_missing_runs_dir(self, tmp_path):
        missing = tmp_path / "does_not_exist"
        deleted, skipped = clean_run_dirs(missing, _cutoff(90), dry_run=False, verbose=False)
        assert deleted == 0
        assert skipped == 0

    def test_dotfiles_are_skipped(self, tmp_path):
        d = tmp_path / ".sessions"
        d.mkdir()
        mtime = (datetime.now(UTC) - timedelta(days=200)).timestamp()
        os.utime(d, (mtime, mtime))
        deleted, skipped = clean_run_dirs(tmp_path, _cutoff(90), dry_run=False, verbose=False)
        assert deleted == 0
        assert (tmp_path / ".sessions").exists()

    def test_files_in_runs_dir_are_skipped(self, tmp_path):
        # JSONL files sit directly in runs_dir; they should not be touched here.
        f = tmp_path / "audit.jsonl"
        f.write_text("{}\n")
        mtime = (datetime.now(UTC) - timedelta(days=200)).timestamp()
        os.utime(f, (mtime, mtime))
        deleted, skipped = clean_run_dirs(tmp_path, _cutoff(90), dry_run=False, verbose=False)
        assert deleted == 0
        assert f.exists()


# ---------------------------------------------------------------------------
# clean_jsonl
# ---------------------------------------------------------------------------

class TestCleanJsonl:
    def test_drops_old_keeps_new(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        _write_jsonl(path, [
            _make_jsonl_line(200),
            _make_jsonl_line(100),
            _make_jsonl_line(10),
            _make_jsonl_line(5),
        ])
        kept, dropped = clean_jsonl(path, _cutoff(90), dry_run=False, verbose=False)
        assert dropped == 2
        assert kept == 2
        lines = [line for line in path.read_text().splitlines() if line.strip()]
        assert len(lines) == 2

    def test_keeps_malformed_timestamp_lines(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        _write_jsonl(path, [
            _make_jsonl_line(200),              # old — would be dropped
            json.dumps({"run_id": "x"}) + "\n", # no timestamp — conservative keep
            _make_jsonl_line(5),                # new — kept
        ])
        kept, dropped = clean_jsonl(path, _cutoff(90), dry_run=False, verbose=False)
        assert dropped == 1
        assert kept == 2

    def test_keeps_unparseable_json_lines(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        _write_jsonl(path, [
            _make_jsonl_line(200),   # old
            "not json at all\n",     # malformed — conservative keep
        ])
        kept, dropped = clean_jsonl(path, _cutoff(90), dry_run=False, verbose=False)
        assert dropped == 1
        lines = [line for line in path.read_text().splitlines() if line.strip()]
        assert "not json at all" in lines

    def test_dry_run_does_not_rewrite(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        original = [_make_jsonl_line(200), _make_jsonl_line(200)]
        _write_jsonl(path, original)
        kept, dropped = clean_jsonl(path, _cutoff(90), dry_run=True, verbose=False)
        assert dropped == 2
        # File must be untouched.
        assert path.read_text() == "".join(original)

    def test_missing_file_returns_zero(self, tmp_path):
        path = tmp_path / "nonexistent.jsonl"
        kept, dropped = clean_jsonl(path, _cutoff(90), dry_run=False, verbose=False)
        assert kept == 0
        assert dropped == 0

    def test_no_tmp_file_left_behind(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        _write_jsonl(path, [_make_jsonl_line(200), _make_jsonl_line(5)])
        clean_jsonl(path, _cutoff(90), dry_run=False, verbose=False)
        assert not path.with_suffix(".jsonl.tmp").exists()

    def test_empty_file_is_noop(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        path.write_text("")
        kept, dropped = clean_jsonl(path, _cutoff(90), dry_run=False, verbose=False)
        assert kept == 0
        assert dropped == 0
        assert path.read_text() == ""

    def test_blank_lines_pass_through(self, tmp_path):
        path = tmp_path / "audit.jsonl"
        _write_jsonl(path, [
            _make_jsonl_line(5),
            "\n",
            _make_jsonl_line(5),
        ])
        kept, dropped = clean_jsonl(path, _cutoff(90), dry_run=False, verbose=False)
        assert dropped == 0
        assert "\n" in path.read_text()

    def test_all_lines_kept_skips_rewrite(self, tmp_path):
        # When nothing is dropped, the file should not be rewritten at all
        # (no .tmp file created).
        path = tmp_path / "audit.jsonl"
        _write_jsonl(path, [_make_jsonl_line(5), _make_jsonl_line(10)])
        mtime_before = path.stat().st_mtime
        clean_jsonl(path, _cutoff(90), dry_run=False, verbose=False)
        assert path.stat().st_mtime == mtime_before

    def test_audit_and_tool_audit_same_cutoff(self, tmp_path):
        # Both compliance logs accept the same cutoff datetime.
        audit = tmp_path / "audit.jsonl"
        tool_audit = tmp_path / "tool_audit.jsonl"
        for p in (audit, tool_audit):
            _write_jsonl(p, [_make_jsonl_line(400), _make_jsonl_line(5)])
        cutoff = _cutoff(365)
        for p in (audit, tool_audit):
            kept, dropped = clean_jsonl(p, cutoff, dry_run=False, verbose=False)
            assert dropped == 1
            assert kept == 1


# ---------------------------------------------------------------------------
# Integration: main()
# ---------------------------------------------------------------------------

class TestMainIntegration:
    def _setup_runs_dir(self, tmp_path) -> dict:
        """Create a populated runs dir and return paths."""
        _make_run_dir(tmp_path, "old-run", age_days=200)
        _make_run_dir(tmp_path, "new-run", age_days=5)

        audit = tmp_path / "audit.jsonl"
        tool_audit = tmp_path / "tool_audit.jsonl"
        tool_trace = tmp_path / "tool_trace.jsonl"

        _write_jsonl(audit,      [_make_jsonl_line(400), _make_jsonl_line(5)])
        _write_jsonl(tool_audit, [_make_jsonl_line(400), _make_jsonl_line(5)])
        _write_jsonl(tool_trace, [_make_jsonl_line(60),  _make_jsonl_line(5)])
        return dict(audit=audit, tool_audit=tool_audit, tool_trace=tool_trace)

    def test_full_run(self, tmp_path):
        from scripts.cleanup_runs import main
        self._setup_runs_dir(tmp_path)
        with patch.dict("os.environ", {"SOC_AGENT_RUNS_DIR": str(tmp_path)}):
            rc = main([])
        assert rc == 0
        assert not (tmp_path / "old-run").exists()
        assert (tmp_path / "new-run").exists()
        audit_lines = [line for line in (tmp_path / "audit.jsonl").read_text().splitlines() if line.strip()]
        assert len(audit_lines) == 1  # old line filtered

    def test_dry_run_touches_nothing(self, tmp_path):
        from scripts.cleanup_runs import main
        paths = self._setup_runs_dir(tmp_path)
        audit_before = paths["audit"].read_text()
        with patch.dict("os.environ", {"SOC_AGENT_RUNS_DIR": str(tmp_path)}):
            rc = main(["--dry-run"])
        assert rc == 0
        assert (tmp_path / "old-run").exists()
        assert paths["audit"].read_text() == audit_before

    def test_summary_output(self, tmp_path, capsys):
        from scripts.cleanup_runs import main
        self._setup_runs_dir(tmp_path)
        with patch.dict("os.environ", {"SOC_AGENT_RUNS_DIR": str(tmp_path)}):
            main([])
        out = capsys.readouterr().out
        assert "Deleted" in out
        assert "skipped" in out
        assert "audit.jsonl" in out

    def test_bad_env_var_exits_1(self, tmp_path):
        from scripts.cleanup_runs import main
        with patch.dict("os.environ", {
            "SOC_AGENT_RUNS_DIR": str(tmp_path),
            "SOC_AGENT_RUN_MAX_AGE_DAYS": "garbage",
        }), pytest.raises(SystemExit) as exc:
            main([])
        assert exc.value.code == 1

    def test_missing_runs_dir_exits_0(self, tmp_path):
        from scripts.cleanup_runs import main
        missing = tmp_path / "no_such_dir"
        with patch.dict("os.environ", {"SOC_AGENT_RUNS_DIR": str(missing)}):
            rc = main([])
        assert rc == 0
