"""Run pages display stamped labels and start times without treating them as identity."""
from __future__ import annotations

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
def test_a_natural_runs_provenance_carries_started_at_and_the_alert_label(
        tmp_path, data_root, alert_name, folder, label):
    run, before, after = _setup(tmp_path, data_root, alert_name, folder)
    stamp = _stamp(run)
    assert stamp["tenant_id"] == H.T_ID, "control: the stamp read back is the run's real stamp"
    assert stamp["commit"] or stamp["unavailable"], "control: the stamp records the code"
    assert stamp.get("alert_label") == label, (
        f"the alert's label is {label!r}; the stamp says {stamp.get('alert_label')!r}")
    started = _utc(stamp.get("started_at"))
    assert before.replace(microsecond=0) <= started <= after, (
        f"started_at {started.isoformat()} is outside the call's window "
        f"[{before.isoformat()}, {after.isoformat()}]")


def test_a_pinned_run_is_stamped_with_the_same_facts(tmp_path, data_root):
    pinned = X.new_id()
    run, before, after = _setup(tmp_path, data_root, "ssh-brute-force.json", "in", run_id=pinned)
    assert run.run_dir.name == pinned, "control: the pinned id names the run folder"
    stamp = _stamp(run)
    assert stamp.get("alert_label") == "ssh-brute-force"
    assert before.replace(microsecond=0) <= _utc(stamp.get("started_at")) <= after


def test_a_natural_run_is_stamped_with_no_world_id(tmp_path, data_root):
    run, _before, _after = _setup(tmp_path, data_root, "ssh-brute-force.json", "in")
    raw = _stamp_path(run).read_text(encoding="utf-8")
    stamp = json.loads(raw)
    assert stamp["tenant_id"] == H.T_ID, "control: the real stamp, with its remaining facts"
    assert stamp.get("world_id") is None, (
        f"a natural run carries no world id; the stamp says {stamp.get('world_id')!r}")
    assert "base_world_id" not in raw


def test_the_run_folder_name_holds_neither_the_label_nor_the_time(tmp_path, data_root):
    run, before, after = _setup(tmp_path, data_root, "ssh-brute-force.json", "in")
    name = run.run_dir.name
    assert X.is_canonical_uuid(name), f"the run id is not a canonical UUID: {name!r}"
    assert "ssh-brute-force" not in name
    squeezed = name.replace("-", "").casefold()
    for moment in (before, after):
        assert f"{moment:%Y%m%d}" not in squeezed, f"the run id spells the date: {name!r}"
        assert f"{moment:%Y%m%dt%H%M%Sz}" not in name.casefold()
    assert _stamp(run).get("alert_label") == "ssh-brute-force", (
        "control: the label is recorded, in the stamp rather than the id")
# O7 — the run page shows them

def test_the_run_page_shows_the_start_time_and_the_label_of_a_run_setup_stamped(
        tmp_path, data_root):
    run, _before, _after = _setup(
        tmp_path, data_root, "ssh-brute-force.json", "in", run_id=X.new_id())
    stamp = _stamp(run)
    started = _utc(stamp.get("started_at"))
    page = _page(run)
    assert "ssh-brute-force" in page, "the page does not show the alert's label"
    assert _shows_time(page, started), (
        f"the page does not show the start time {started.isoformat()}")

    _rewrite_stamp(run, started_at=..., alert_label=...)
    bare = _page(run)
    assert "ssh-brute-force" not in bare, "control: the label reached the page from elsewhere"
    assert not _shows_time(bare, started), "control: the time reached the page from elsewhere"


def test_the_run_page_shows_the_values_the_stamp_holds(tmp_path, data_root):
    run, _b, _a = _setup(tmp_path, data_root, "ssh-brute-force.json", "in", run_id=X.new_id())
    _rewrite_stamp(run, started_at="2031-03-04T05:06:07Z", alert_label="planted-label-xyz")
    page = _page(run)
    assert "planted-label-xyz" in page
    assert re.search(r"2031-03-04[T ]05:06", page), "the stamped start time is not on the page"

    _rewrite_stamp(run, started_at=..., alert_label=...)
    bare = _page(run)
    assert "<html" in bare, "control: a stamp lacking the facts still renders a page"
    assert "planted-label-xyz" not in bare
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

def test_the_stamp_reader_returns_the_display_facts_and_folds_bad_ones(tmp_path, data_root):
    from defender.records import _provenance

    run, _b, _a = _setup(tmp_path, data_root, "ssh-brute-force.json", "in", run_id=X.new_id())
    path = _stamp_path(run)

    _rewrite_stamp(run, started_at="2031-03-04T05:06:07Z", alert_label="planted-label-xyz")
    read = _provenance.read(path)
    assert read is not None, "a stamp with the display facts did not read"
    wire = json.loads(read.as_json())
    assert wire["started_at"] == "2031-03-04T05:06:07Z"
    assert wire["alert_label"] == "planted-label-xyz"

    _rewrite_stamp(run, started_at=17, alert_label=["x"])
    folded = _provenance.read(path)
    assert folded is not None, "wrong-typed display facts voided the whole record"
    wire = json.loads(folded.as_json())
    assert wire.get("started_at") is None
    assert wire.get("alert_label") is None
    assert wire["tenant_id"] == H.T_ID, "the rest of the record survived"

    _rewrite_stamp(run, started_at=..., alert_label=...)
    older = _provenance.read(path)
    assert older is not None, "a stamp from before the display facts no longer reads"
    assert json.loads(older.as_json())["tenant_id"] == H.T_ID
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


class _Siblings:
    """Record sibling launches and materialize their completed run artifacts."""

    def __init__(self, edits: dict[str, dict[str, Any]] | None = None) -> None:
        self.edits = edits or {}
        self.labels: list[str] = []
        self.faults: list[str] = []

    def __call__(self, argv: list[str], *, env: dict[str, str] | None = None, **kw: Any) -> int:
        label, episode, tenant = _arg(argv, "--world"), _arg(argv, "--episode"), _arg(argv, "--tenant")
        folder = P.data_root() / tenant / "episodes" / episode
        roster = folder / X.ROSTER_NAME
        arm = json.loads(roster.read_text(encoding="utf-8")).get(label) \
            if roster.is_file() else None
        if arm is None:
            self.faults.append(f"sibling {label}: no roster naming it at {roster}")
            return 97
        code = J.FakeSibling(data_root=P.data_root())(argv, env=env, **kw)
        if label in self.edits:
            stamp = folder / "runs" / arm / "provenance.json"
            doc = json.loads(stamp.read_text(encoding="utf-8"))
            doc.update(self.edits[label])
            stamp.write_text(json.dumps(doc), encoding="utf-8")
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
    base = P.data_root() / P.LAUNCH_TENANT / "episodes"
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
