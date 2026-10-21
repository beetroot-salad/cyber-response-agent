"""Explicit location construction and raw paths for filesystem fixtures (#1210)."""
from pathlib import Path
from typing import Any
from defender.records import _locations as L


def location_path(value: Any) -> Any:
    """Use a location's raw spelling in a fixture; leave ordinary paths/test doubles alone."""
    return value._record_location_path if isinstance(value, L._Location) else value


def fixture_data_root(value: Any) -> L.DataRoot:
    return value if isinstance(value, L.DataRoot) else L.DataRoot(Path(value))


def fixture_runs_base(value: Any) -> L.RunsBase:
    return value if isinstance(value, L.RunsBase) else L.RunsBase(Path(value))
