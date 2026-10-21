"""Run pages display stamped labels and start times without treating them as identity."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import datetime as _dt
import json
import re
from pathlib import Path
from typing import Any

import pytest

from defender.tests.support.learning.judge import _judge_921 as J
from defender.tests.storage.ids_1187 import _spec1187 as X
from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H
from defender.tests.storage.tenant_1105_run_repository import _spec1105_pr2 as P

#: (alert file name, folder under the test's input dir or None, the label the design means).
ALERTS = (
    pytest.param("ssh-brute-force.json", "in", "ssh-brute-force", id="named-by-its-rule"),
    pytest.param("alert.json", "lateral-move", "lateral-move", id="generic-name-uses-folder"),
)


def _utc(text: object) -> _dt.datetime:
    """`text` as an aware UTC instant; fails the test when it is not ISO-8601 UTC text."""
    assert isinstance(text, str), f"started_at is not text: {text!r}"
    assert text, "started_at is empty"
    parsed = _dt.datetime.fromisoformat(text)
    assert parsed.tzinfo is not None, f"started_at has no zone, so it is not UTC text: {text!r}"
    assert parsed.utcoffset() == _dt.timedelta(0), f"started_at is not UTC: {text!r}"
    return parsed


def _setup(tmp_path: Path, data_root: Path, alert_name: str, folder: str, *,
           run_id: str | None = None) -> tuple[Any, _dt.datetime, _dt.datetime]:
    """Run setup for a fresh natural run of tenant `acme` from `<tmp>/<folder>/<alert_name>`."""
    from defender import run_common

    t = H.tenant(data_root, H.T_ID)
    alert = H.alert_file(tmp_path / folder, alert_name)
    before = _dt.datetime.now(_dt.UTC)
    run = run_common.materialize_run(alert, run_id, tenant=t)
    after = _dt.datetime.now(_dt.UTC)
    return run, before, after


def _stamp_path(run: Any) -> Path:
    from defender.run_repository import RunPaths

    return RunPaths(run.run_dir).provenance


def _stamp(run: Any) -> dict:
    return json.loads(_stamp_path(run).read_text(encoding="utf-8"))


def _rewrite_stamp(run: Any, **changes: Any) -> dict:
    """The run's own stamp with `changes` applied (a value of `...` removes the key), written back in place: the file a box could have written."""
    doc = _stamp(run)
    for key, value in changes.items():
        if value is ...:
            doc.pop(key, None)
        else:
            doc[key] = value
    _stamp_path(run).write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n",
                                encoding="utf-8")
    return doc


def _page(run: Any) -> str:
    from defender.presentation.visualize_run import render_runtime_page

    return render_runtime_page(run.run_dir)


def _shows_time(page: str, instant: _dt.datetime) -> bool:
    """The page shows `instant` to the minute, either `YYYY-MM-DDTHH:MM` or `YYYY-MM-DD HH:MM`."""
    return re.search(
        rf"{instant:%Y-%m-%d}[T ]{instant:%H:%M}", page) is not None
# O7 — run setup stamps the display facts

@pytest.mark.parametrize(("alert_name", "folder", "label"), ALERTS)
@pytest.mark.parametrize("pinned", [False, True], ids=["minted", "pinned"])
def test_run_setup_stamps_display_facts_without_encoding_them_in_identity(
        tmp_path, data_root, alert_name, folder, label, pinned):
    run_id = X.new_id() if pinned else None
    run, before, after = _setup(tmp_path, data_root, alert_name, folder, run_id=run_id)
    stamp = _stamp(run)
    assert stamp["tenant_id"] == H.T_ID
    assert stamp["commit"] or stamp["unavailable"], "control: the stamp records the code"
    assert stamp.get("alert_label") == label
    started = _utc(stamp.get("started_at"))
    assert before.replace(microsecond=0) <= started <= after
    assert stamp.get("world_id") is None
    assert "base_world_id" not in _stamp_path(run).read_text(encoding="utf-8")
    name = run.run_dir.name
    assert X.is_canonical_uuid(name), name
    if pinned:
        assert name == run_id, "the pinned id names the run folder"
    assert label not in name
    for moment in (before, after):
        assert f"{moment:%Y%m%d}" not in name.replace("-", "").casefold()
        assert f"{moment:%Y%m%dt%H%M%Sz}" not in name.casefold()


# O7 — the run page shows them

@pytest.mark.parametrize("source", ["setup", "rewritten"])
def test_the_run_page_reads_its_display_facts_only_from_the_stamp(tmp_path, data_root, source):
    run, _before, _after = _setup(tmp_path, data_root, "ssh-brute-force.json", "in", run_id=X.new_id())
    stamp = (_rewrite_stamp(run, started_at="2031-03-04T05:06:07Z", alert_label="planted-label-xyz")
             if source == "rewritten" else _stamp(run))
    started = _utc(stamp["started_at"])
    label = stamp["alert_label"]
    page = _page(run)
    assert label in page
    assert _shows_time(page, started), started
    _rewrite_stamp(run, started_at=..., alert_label=...)
    bare = _page(run)
    assert "<html" in bare, "a stamp lacking the facts still renders"
    assert label not in bare, "the label reached the page from elsewhere"
    assert not _shows_time(bare, started), "the time reached the page from elsewhere"
    if source == "rewritten":
        assert "2031-03-04" not in bare


def test_a_forged_label_is_shown_as_text_never_as_markup(tmp_path, data_root):
    run, _b, _a = _setup(tmp_path, data_root, "ssh-brute-force.json", "in", run_id=X.new_id())
    forged = '<img src=x onerror=alert(1)>'
    _rewrite_stamp(run, alert_label=forged)
    page = _page(run)
    assert forged not in page, "the label reached the page as live markup"
    assert "<img src=x onerror" not in page

    _rewrite_stamp(run, alert_label="benign-label-q")
    assert "benign-label-q" in _page(run), "control: a plain label is shown"


@pytest.mark.parametrize(("started", "label"), [
    ("not a time", 17),
    (["2031-03-04"], {"a": 1}),
    (None, None),
    (12345, ""),
])
def test_unusable_display_facts_never_stop_the_page(tmp_path, data_root, started, label):
    run, _b, _a = _setup(tmp_path, data_root, "ssh-brute-force.json", "in", run_id=X.new_id())
    assert _page(run), "control: the page renders with the stamp as run setup wrote it"
    _rewrite_stamp(run, started_at=started, alert_label=label)
    page = _page(run)
    assert "<html" in page, "the page did not render over unusable display facts"
# O7 — the stamp's reader keeps the facts and survives bad ones

@pytest.mark.parametrize(("changes", "expected"), [
    ({"started_at": "2031-03-04T05:06:07Z", "alert_label": "planted-label-xyz"},
     {"started_at": "2031-03-04T05:06:07Z", "alert_label": "planted-label-xyz"}),
    ({"started_at": 17, "alert_label": ["x"]}, {"started_at": None, "alert_label": None}),
    ({"started_at": ..., "alert_label": ...}, {}),
], ids=["valid", "wrong-types", "older-stamp"])
def test_the_stamp_reader_preserves_the_record_over_display_fact_changes(
        tmp_path, data_root, changes, expected):
    from defender.records import _provenance

    run, _b, _a = _setup(tmp_path, data_root, "ssh-brute-force.json", "in", run_id=X.new_id())
    _rewrite_stamp(run, **changes)
    read = _provenance.read(_stamp_path(run))
    assert read is not None, changes
    wire = json.loads(read.as_json())
    assert wire["tenant_id"] == H.T_ID, "the rest of the record survived"
    for key, value in expected.items():
        assert wire.get(key) == value
# N5 — no decision compares the display facts (the fork check's field table)

#: The fork check's classes that are NOT compared (`learning/branch/cli.py`'s
#: `STAMP_FIELD_CLASSES`, #1204 D4): a field in either is recorded and never judged.
NOT_COMPARED = frozenset({"informational", "expected_to_differ"})


def test_the_fork_checks_field_table_never_compares_the_display_facts():
    from defender.learning.branch.cli import STAMP_FIELD_CLASSES

    assert STAMP_FIELD_CLASSES.get("commit") == "anchored", (
        f"control: not the fork check's table: {STAMP_FIELD_CLASSES}")
    for fact in ("started_at", "alert_label"):
        assert STAMP_FIELD_CLASSES.get(fact) in NOT_COMPARED, (
            f"{fact} is classed {STAMP_FIELD_CLASSES.get(fact)!r}; a display fact is never "
            f"compared ({sorted(NOT_COMPARED)})")
# R1b — the launcher's family stamp

def _arg(argv: list[str], flag: str) -> str:
    return argv[argv.index(flag) + 1]


class _Siblings(J.FakeSibling):
    """Use the shared completed-sibling fixture, then forge selected display/stamp facts."""

    def __init__(self, edits: dict[str, dict[str, Any]] | None = None) -> None:
        super().__init__(data_root=location_path(P.data_root)())
        self.edits = edits or {}
        self.labels: list[str] = []

    def __call__(self, argv: list[str], **kw: Any) -> int:
        code = super().__call__(argv, **kw)
        if code == 97:
            return code
        label = _arg(argv, "--world")
        if label in self.edits:
            stamp = self.episode_dir / "runs" / X.read_roster(self.episode_dir)[J.world_id(self.episode_dir, label)] / "provenance.json"
            doc = json.loads(stamp.read_text(encoding="utf-8"))
            stamp.write_text(json.dumps({**doc, **self.edits[label]}), encoding="utf-8")
        self.labels.append(label)
        return code


def _launch(root: Path, monkeypatch: Any, *, edits: dict[str, dict[str, Any]] | None = None
            ) -> tuple[Any, _Siblings, dict | None]:
    """One real launch under fresh roots at `root`, over a UUID source run of the launch fixture tenant."""
    root.mkdir(parents=True, exist_ok=True)
    P.roots(root, monkeypatch)
    monkeypatch.setenv(P.DATA_ROOT_ENV, str(root / "data-root"))
    est, src = P.launch_source(root, source_run_id=X.new_id())
    # The natural container in #1187's shape: no `_tenant.json` (R1).
    (src.parent / "_tenant.json").unlink(missing_ok=True)
    siblings = _Siblings(edits)
    got = P.drive_launch(est, P.new_launch_argv(P.LAUNCH_TENANT, src.name), spawn=siblings)
    base = location_path(P.data_root)() / P.LAUNCH_TENANT / "episodes"
    made = [d for d in (base.iterdir() if base.is_dir() else ()) if (d / "family.yaml").is_file()]
    stamps = [d / "provenance.json" for d in made if (d / "provenance.json").is_file()]
    assert len(stamps) <= 1, f"more than one episode stamped a family: {stamps}"
    doc = json.loads(stamps[0].read_text(encoding="utf-8")) if stamps else None
    return got, siblings, doc


def test_the_launchers_family_stamp_has_no_base_world_id(tmp_path, monkeypatch):
    got, siblings, stamp = _launch(tmp_path, monkeypatch)
    assert got.rc == 0, f"the launch did not complete: {got.message!r} {got.raised!r}"
    assert sorted(siblings.labels) == ["a", "b", "c"], "control: the siblings ran"
    assert stamp is not None, "control: an accepted family leaves a family stamp"
    assert stamp["agreed"]["commit"] == "deadbee", "control: the stamp is this family's"
    assert set(stamp) == {"agreed", "allow_dirty", "source", "waived"}, sorted(stamp)
    assert "base_world_id" not in json.dumps(stamp)


def test_siblings_with_different_display_facts_are_still_one_comparable_family(
        tmp_path, monkeypatch):
    differing = {
        "a": {"started_at": "2031-01-01T00:00:01Z", "alert_label": "label-a"},
        "b": {"started_at": "2031-01-01T09:59:59Z", "alert_label": "label-b"},
        "c": {"started_at": "2031-06-30T12:00:00Z", "alert_label": "label-c"},
    }
    got, _siblings, stamp = _launch(tmp_path / "facts", monkeypatch, edits=differing)
    assert got.rc == 0, f"the launch did not complete: {got.message!r} {got.raised!r}"
    assert stamp is not None, "differing display facts withheld the family stamp"
    assert stamp["agreed"]["commit"] == "deadbee"

    _got, _sib, withheld = _launch(
        tmp_path / "commit", monkeypatch, edits={"b": {"commit": "feedbee"}})
    assert withheld is None, "control: arms on different commits must not be stamped as a family"
