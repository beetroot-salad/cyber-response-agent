"""#1187 slice E — display facts and stamps (O7, R1b, declared change 11, N5).

A natural run's provenance gains two DISPLAY facts, `started_at` and `alert_label`, so an
operator can still see when a run started and which alert it ran now that the run id is an
opaque UUID (O1/O2). Under R1b the natural run's `world_id` and the family stamp's
`base_world_id` are retired with `_tenant.json`. The display facts live in a folder the box can
write, so no decision reads them (P-host, N5): the run page shows them, nothing else does.

Scenarios, and the one observation channel of each:

* run setup (`run_common.materialize_run`, the function `run.py` calls; the same entry
  `tenant_1105_run_repository/test_1105_run_setup.py` drives): the stamp file on disk.
* the run page (`visualize_run.render_runtime_page`, what `publish_page` renders): the HTML.
* the family stamp: written by the REAL launcher (`learning/branch/cli.main`, driven through
  `_spec1105_pr2.drive_launch`), read back from the episode folder as a file. The stamp writer
  `verify_family` is not called directly: today it only writes `base_world_id` when the
  launcher hands one in, so a direct call without the argument would be green for the wrong
  reason; the launcher is the seam that decides.
* N5: a launch whose siblings carry DIFFERENT display facts still writes the family stamp, and
  the fork check's field table (`STAMP_FIELD_CLASSES`) classes both facts as never compared.

Fixtures stated up front:

* `ssh-brute-force.json` (a file named by its rule): `_alert_label` is the file's stem,
  `ssh-brute-force`.
* `lateral-move/alert.json` (the generic stem `alert`): `_alert_label` is the folder's name,
  `lateral-move`.
* There is no clock seam on run setup; `started_at` is bounded by the wall clock read just
  before and just after the call.

Red at base d50c16ad, each for its own reason (classified in the author's report); the family
stamp tests need the launcher's new shape (UUID source, no `_tenant.json`, the roster at
`<T>/episodes/<ep>/arms.json`) to run through: their fake sibling reads the roster and serves
no other shape (review F15), so they are red at base for that reason.
"""
from __future__ import annotations

import datetime as _dt
import json
import re
from pathlib import Path
from typing import Any

import pytest

from defender.tests import _judge_921 as J
from defender.tests.ids_1187 import _spec1187 as X
from defender.tests.tenant_1105_run_repository import _spec1105 as H
from defender.tests.tenant_1105_run_repository import _spec1105_pr2 as P

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
    """Run setup for a fresh natural run of tenant `acme` from `<tmp>/<folder>/<alert_name>`.
    Returns `(run, before, after)`: the wall clock read just before and just after the call."""
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
    """The run's own stamp with `changes` applied (a value of `...` removes the key), written
    back in place: the file a box could have written. Returns the new document."""
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
    from defender.scripts.visualize.visualize_run import render_runtime_page

    return render_runtime_page(run.run_dir)


def _shows_time(page: str, instant: _dt.datetime) -> bool:
    """The page shows `instant` to the minute, either `YYYY-MM-DDTHH:MM` or `YYYY-MM-DD HH:MM`."""
    return re.search(
        rf"{instant:%Y-%m-%d}[T ]{instant:%H:%M}", page) is not None


# ======================================================================================
# O7 — run setup stamps the display facts
# ======================================================================================

@pytest.mark.parametrize(("alert_name", "folder", "label"), ALERTS)
def test_a_natural_runs_provenance_carries_started_at_and_the_alert_label(
        tmp_path, data_root, alert_name, folder, label):
    """O7: run setup for a natural run (the entry `run.py` calls) writes `started_at` and
    `alert_label` into the run's provenance stamp. `started_at` is ISO-8601 UTC text within the
    wall-clock window of the call (second precision allowed); `alert_label` is what the design
    means by the alert's name: the file's stem, or the folder's name when the stem is the
    generic `alert` (fixtures stated in the module docstring).

    Positive control in the same file: the stamp is the real one (it carries the tenant and a
    commit), so a missing key is a missing fact, not a missing stamp."""
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
    """O7: the facts do not depend on how the id was obtained. A run pinned with `--run-id <uuid>`
    gets `alert_label` and `started_at` exactly as a minted one does."""
    pinned = X.new_id()
    run, before, after = _setup(tmp_path, data_root, "ssh-brute-force.json", "in", run_id=pinned)
    assert run.run_dir.name == pinned, "control: the pinned id names the run folder"
    stamp = _stamp(run)
    assert stamp.get("alert_label") == "ssh-brute-force"
    assert before.replace(microsecond=0) <= _utc(stamp.get("started_at")) <= after


def test_a_natural_run_is_stamped_with_no_world_id(tmp_path, data_root):
    """R1b / declared change 11: a natural run stops stamping a `world_id` (it was the tenant
    record's `base_world_id`, copied in), and nothing in the stamp names a base world. Positive
    control: the stamp is the real one, and carries the facts that remain."""
    run, _before, _after = _setup(tmp_path, data_root, "ssh-brute-force.json", "in")
    raw = _stamp_path(run).read_text(encoding="utf-8")
    stamp = json.loads(raw)
    assert stamp["tenant_id"] == H.T_ID, "control: the real stamp, with its remaining facts"
    assert stamp.get("world_id") is None, (
        f"a natural run carries no world id; the stamp says {stamp.get('world_id')!r}")
    assert "base_world_id" not in raw


def test_the_run_folder_name_holds_neither_the_label_nor_the_time(tmp_path, data_root):
    """O1/O2 cross-check for the display facts: they live in provenance, and the run id
    (the folder's name) is an opaque UUID that holds neither the alert's label
    (`ssh-brute-force`, stated) nor the moment the run was made (its date or its clock time,
    from the wall clock around the call). Positive control: the facts ARE in the stamp of the
    same run."""
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


# ======================================================================================
# O7 — the run page shows them
# ======================================================================================

def test_the_run_page_shows_the_start_time_and_the_label_of_a_run_setup_stamped(
        tmp_path, data_root):
    """O7: for a run stamped by run setup (pinned UUID id, so nothing in the run's path spells
    the label), the page carries the label text and the start time the stamp recorded.
    Positive control: removing both keys from the SAME run's stamp removes them from the page."""
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
    """O7: the page shows what the stamp holds, planted here as values nothing else could spell:
    start `2031-03-04T05:06:07Z`, label `planted-label-xyz`. Positive control: the page without
    them (keys removed from the same stamp) shows neither, and still renders."""
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
    """N5: the stamp sits in a folder the box can write, so its label is not trusted — the page
    shows it escaped. Positive control: a benign label in the same place is shown."""
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
    """O7/N5: display facts are display only. A stamp whose `started_at`/`alert_label` are junk
    (wrong type, empty, null, not a time) is still a run the operator can open: the page
    renders. Positive control: the same run renders with valid facts."""
    run, _b, _a = _setup(tmp_path, data_root, "ssh-brute-force.json", "in", run_id=X.new_id())
    assert _page(run), "control: the page renders with the stamp as run setup wrote it"
    _rewrite_stamp(run, started_at=started, alert_label=label)
    page = _page(run)
    assert "<html" in page, "the page did not render over unusable display facts"


# ======================================================================================
# O7 — the stamp's reader keeps the facts and survives bad ones
# ======================================================================================

def test_the_stamp_reader_returns_the_display_facts_and_folds_bad_ones(tmp_path, data_root):
    """O7: the provenance reader (`_provenance.read`, the reader the page and the launcher share)
    returns a stamp carrying `started_at` and `alert_label` when they are text, and folds a
    wrong-typed value to nothing WITHOUT voiding the record (the file is box-writable). A stamp
    from before this change (neither key) still reads. The record is observed through its own
    wire (`as_json`)."""
    from defender import _provenance

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


# ======================================================================================
# N5 — no decision compares the display facts (the fork check's field table)
# ======================================================================================

#: The fork check's classes that are NOT compared (`learning/branch/cli.py`'s
#: `STAMP_FIELD_CLASSES`, #1204 D4): a field in either is recorded and never judged.
NOT_COMPARED = frozenset({"informational", "expected_to_differ"})


def test_the_fork_checks_field_table_never_compares_the_display_facts():
    """N5 / P-host / declared change 11 (review F3): the one decision that reads a run's whole
    stamp is the fork check, and it reads it through its field table
    (`learning.branch.cli.STAMP_FIELD_CLASSES`, which #1204 requires to classify EVERY
    `RunProvenance` field). Once the stamp carries `started_at` and `alert_label`, the table
    classifies each as a field the check does not compare — `informational` or
    `expected_to_differ` — never `anchored`, `constant` or `dedicated`. Which class each takes
    is pinned by `test_1204_family_knowledge.py`'s D4 table (`started_at: expected_to_differ`,
    `alert_label: informational`), which asserts the table equals D4; this test asserts only
    the property N5 needs, so it holds whichever not-compared class D4 names. Positive control:
    the table is the real one
    — it classes `commit` as anchored. The behavioural arm is
    `test_siblings_with_different_display_facts_are_still_one_comparable_family`. RED at base:
    the table has no entry for either fact."""
    from defender.learning.branch.cli import STAMP_FIELD_CLASSES

    assert STAMP_FIELD_CLASSES.get("commit") == "anchored", (
        f"control: not the fork check's table: {STAMP_FIELD_CLASSES}")
    for fact in ("started_at", "alert_label"):
        assert STAMP_FIELD_CLASSES.get(fact) in NOT_COMPARED, (
            f"{fact} is classed {STAMP_FIELD_CLASSES.get(fact)!r}; a display fact is never "
            f"compared ({sorted(NOT_COMPARED)})")


# ======================================================================================
# R1b — the launcher's family stamp
# ======================================================================================

def _arg(argv: list[str], flag: str) -> str:
    return argv[argv.index(flag) + 1]


class _Siblings:
    """The launcher's `spawn=` seam: a sibling that RAN. `J.FakeSibling` materialises a finished
    arm (report, investigation, stamp, scrub verdict, served ledger) in the episode's `runs/`, at
    the arm id the launcher gave it — the roster's UUID for its label, read back from
    `<data root>/<T>/episodes/<ep>/arms.json` as the sibling reads it (#1187). It implements no
    other policy: with no roster, or a roster not naming the label, it records the fault in
    `faults` and exits 97 without materialising anything (review F15). `edits` is
    `{label: {provenance key: value}}` applied to that arm's own stamp, the file a box can
    write."""

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
    """One real launch under fresh roots at `root`, over a UUID source run of the launch fixture
    tenant. Returns `(launched, siblings, family stamp or None)`; the stamp is the episode
    root's `provenance.json`, found in the episode folder the launcher made."""
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
    """R1b / declared change 11: the family stamp the launcher writes for an accepted family
    holds `agreed`, `allow_dirty`, `source` and `waived`, and no `base_world_id` anywhere in
    it. Driven through the real launcher (`drive_launch`, a UUID source, siblings that ran).
    Positive control: the stamp exists and is the family's real one — its `agreed.commit` is the
    commit the siblings were stamped at."""
    got, siblings, stamp = _launch(tmp_path, monkeypatch)
    assert got.rc == 0, f"the launch did not complete: {got.message!r} {got.raised!r}"
    assert sorted(siblings.labels) == ["a", "b", "c"], "control: the siblings ran"
    assert stamp is not None, "control: an accepted family leaves a family stamp"
    assert stamp["agreed"]["commit"] == "deadbee", "control: the stamp is this family's"
    assert set(stamp) == {"agreed", "allow_dirty", "source", "waived"}, sorted(stamp)
    assert "base_world_id" not in json.dumps(stamp)


def test_siblings_with_different_display_facts_are_still_one_comparable_family(
        tmp_path, monkeypatch):
    """N5: no decision reads the display facts. Arms start at different moments and may report
    different labels in a box-writable stamp; the family is still comparable and its stamp is
    written. Positive control through the same channel: arms that differ on the commit — a fact
    the comparison does read — withhold the stamp."""
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
