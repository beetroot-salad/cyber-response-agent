"""Run only by test_tmp_retention.py, in a child pytest: one passing and one failing test that
record where their tmp dir and data root were."""
import json
import os
from pathlib import Path


def _record(name: str, tmp_path: Path, data_root: Path) -> None:
    # Named by the test: a removed dir's number is free again, so the next test may get its path.
    (data_root / name).write_text(name)
    (tmp_path / name).write_text(name)
    out = Path(os.environ["RETENTION_RECORD"]) / f"{name}.json"
    out.write_text(json.dumps({"tmp_path": str(tmp_path), "data_root": str(data_root)}))


def test_passes(tmp_path, data_root):
    _record("passed", tmp_path, data_root)


def test_fails(tmp_path, data_root):
    _record("failed", tmp_path, data_root)
    raise AssertionError("fails on purpose")
