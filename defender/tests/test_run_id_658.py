from __future__ import annotations

import pytest

from defender import run_common
from defender._run_id import is_valid_run_id
from defender.runtime.box import container_name


VALID_RUN_IDS = (
    "a",
    "9",
    "run-123",
    "A_1",
    "a.b",
    "a..b",
)

INVALID_RUN_IDS = (
    "",
    ".",
    "..",
    "_leading",
    "-leading",
    "run/id",
    r"run\id",
    "../escape",
    "run:id",
    "run id",
    "run\nid",
    "rún",
    "bad\x00id",
)


@pytest.mark.parametrize("run_id", VALID_RUN_IDS)
def test_run_id_slug_accepts_the_container_name_grammar(run_id):
    assert is_valid_run_id(run_id)
    assert container_name(run_id) == f"defender-run-{run_id}"


@pytest.mark.parametrize("run_id", INVALID_RUN_IDS)
def test_run_id_slug_rejects_values_outside_the_container_name_grammar(run_id):
    assert not is_valid_run_id(run_id)
    with pytest.raises(ValueError, match="cannot name a container"):
        container_name(run_id)


@pytest.mark.parametrize("run_id", INVALID_RUN_IDS)
def test_materialize_rejects_an_invalid_explicit_run_id_before_writing(
    tmp_path, monkeypatch, run_id
):
    alert = tmp_path / "fixture.json"
    alert.write_text("{}\n", encoding="utf-8")
    runs_base = tmp_path / "runs"
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(runs_base))

    with pytest.raises(SystemExit, match="invalid run id"):
        run_common.materialize_run_dir(alert, run_id)

    assert not runs_base.exists()


@pytest.mark.parametrize("run_id", VALID_RUN_IDS)
def test_materialize_accepts_a_valid_run_id(tmp_path, monkeypatch, run_id):
    alert = tmp_path / "fixture.json"
    alert.write_text("{}\n", encoding="utf-8")
    runs_base = tmp_path / "runs"
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(runs_base))

    run_dir, salt = run_common.materialize_run_dir(alert, run_id)

    assert run_dir == runs_base / run_id
    assert sorted(path.name for path in run_dir.iterdir()) == ["alert.json", "gather_raw"]
    assert salt


@pytest.mark.parametrize("kind", [("absolute",), ("traversal",)])
def test_materialize_cannot_create_a_run_outside_the_runs_base(tmp_path, monkeypatch, kind):
    alert = tmp_path / "fixture.json"
    alert.write_text("{}\n", encoding="utf-8")
    runs_base = tmp_path / "runs"
    outside = tmp_path / "escape"
    run_id = str(outside) if kind == "absolute" else "../escape"
    monkeypatch.setenv("DEFENDER_RUNS_BASE", str(runs_base))

    with pytest.raises(SystemExit, match="invalid run id"):
        run_common.materialize_run_dir(alert, run_id)

    assert not runs_base.exists()
    assert not outside.exists()
