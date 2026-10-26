"""Plant a run's alert and its record the way `materialize_run` leaves them (#1222 A1).

Shared by the hand-built run folders of the older suites: since the front door settles an alert
once, a folder with an `alert.json` and no record is not a run. Underscore-prefixed so pytest
does not collect it; it defines no tests.
"""
from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from defender.records import _alert_input
from defender.records import RunPaths

#: The mapping a hand-built folder's record is derived with: the committed tenants' mapping.
COMMITTED_MAPPING: Mapping[str, str] = {
    "signature": "rule.id", "event_time": "alert_timestamp", "summary": "rule.description"}


def plant_alert(run_dir: Path, alert: bytes | Mapping[str, Any] | None = None, *,
                mapping: Mapping[str, str] = COMMITTED_MAPPING) -> bytes:
    """`alert` (bytes written verbatim, or a document serialised as JSON; default `{}`) and its
    record in `run_dir`'s input directory, the facts derived through `mapping`. Returns the
    bytes planted."""
    raw = alert if isinstance(alert, bytes) else json.dumps(
        {} if alert is None else dict(alert)).encode("utf-8")
    paths = RunPaths(Path(run_dir))
    paths.alert_input_dir.mkdir(parents=True, exist_ok=True)
    admitted = _alert_input.admit(raw)
    facts = _alert_input.derive_facts(
        admitted.document, _alert_input.AlertMapping(paths=dict(mapping)))
    paths.alert.write_bytes(raw)
    paths.alert_record.write_text(
        _alert_input.record_text(admitted.digest, facts), encoding="utf-8")
    return raw


def plant_source_copy(episode_dir: Path, alert: bytes, *,
                      mapping: Mapping[str, str] = COMMITTED_MAPPING) -> None:
    """The copies a launch puts in an episode (#1222 A1): the source run's alert and its
    record, which the judge reads in place of the world's `alert.json`."""
    from defender.episodes._episode_paths import EpisodePaths

    paths = EpisodePaths(Path(episode_dir))
    try:
        admitted = _alert_input.admit(alert)
        digest = admitted.digest
        facts = _alert_input.derive_facts(
            admitted.document, _alert_input.AlertMapping(paths=dict(mapping)))
    except _alert_input.AlertRefused:
        # A hostile copy a display test wants on the page: the bytes as they are, no facts.
        digest, facts = _alert_input.digest_of(alert), _alert_input.AlertFacts()
    paths.source_alert.write_bytes(alert)
    paths.source_record.write_text(_alert_input.record_text(digest, facts), encoding="utf-8")


def unseal_fixture_input(run_dir: Path) -> None:
    """Unlock this test's own sealed input for an explicit host mutation or cleanup."""
    paths = RunPaths(run_dir)
    paths.alert_input_dir.chmod(0o755)
    for child in paths.alert_input_dir.iterdir():
        if child.is_file() and not child.is_symlink():
            child.chmod(0o644)
