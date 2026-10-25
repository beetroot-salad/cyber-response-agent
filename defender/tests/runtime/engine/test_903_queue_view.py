"""#903 — the queue-state page: the serializer contract, the renderer, and the writers' stamps."""
from __future__ import annotations

from defender.tests.support.shared._locations_1210 import location_path

import copy
import html
import json
import logging
import os
import re
from datetime import UTC, datetime
from pathlib import Path

import pytest

from defender.tests.support.shared.contracts._frontend_outputs import frontend_outputs_lock  # noqa: F401 — shared pytest fixture

from defender._io import read_jsonl_rows
from defender.learning.author import drain
from defender.learning.core import quarantine
from defender.learning.core.config import LoopPaths
from defender.learning.core.state import FINDINGS, PITFALLS, QUESTIONER_FINDINGS, Channel, LearningState
from defender.learning.frontend import build, serialize_queues
from defender.learning.leads import pitfalls_curator

#: A queued row's own content, carrying the one character the embedded JSON must not emit
#: raw. It rides inside a dead-letter row, i.e. the deepest string the page renders.
SCRIPT_PAYLOAD = "<script>alert(1)</script>"
BENIGN_PAYLOAD = "an ordinary lesson title"

#: A physical line no tolerant reader can parse. One per sidecar.
TORN = '{"finding_id": "torn", '


# --------------------------------------------------------------------------------------
# the writers' exact shapes, as literals


#: `drain.retire` — nested under `row`, with `attempts`, stamped by mechanism 3.
NESTED_STAMPED = {
    "finding_id": "g-1",
    "attempts": 3,
    "deadletter_reason": "the author never took it",
    "retired_at": "2026-09-10T04:05:06+00:00",
    "row": {"finding_id": "g-1", "title": SCRIPT_PAYLOAD},
}
#: The same writer BEFORE mechanism 3 — an old record, which reads as `when: null`.
NESTED_UNSTAMPED = {
    "finding_id": "g-3",
    "attempts": 2,
    "deadletter_reason": "the author never took it",
    "row": {"finding_id": "g-3", "k": "v"},
}
#: `drain._retire_unkeyable` — the row SPREAD, no `row` key, no id under the channel's key.
FLAT_UNSTAMPED = {
    "run_id": "r9",
    "note": "no id under finding_id",
    "attempts": 1,
    "deadletter_reason": "row carries no value under 'finding_id'",
}
FLAT_STAMPED = {
    "run_id": "r10",
    "attempts": 2,
    "deadletter_reason": "row carries no value under 'finding_id'",
    "retired_at": "2026-09-12T07:08:09+00:00",
}
#: `pitfalls_curator._graveyard_dropped_rows` — nested, and NO `attempts` at all (D13).
CURATOR_DROP = {
    "pitfall_id": "p-9",
    "deadletter_reason": "undeclared-system:evil",
    "row": {"pitfall_id": "p-9", "system": "evil", "occurrences": 2},
}

#: `drain._record_stuck` — two records, the second stamped by mechanism 3.
STUCK_FIRST = {
    "fault_class": "TimeoutError",
    "row_ids": ["f-1"],
    "consecutive_ticks": 1,
    "reason": "the append lock never came free",
}
STUCK_MIDDLE = {
    "fault_class": "BranchError",
    "row_ids": ["f-1", "f-2"],
    "consecutive_ticks": 4,
    "reason": "push rejected, non-fast-forward",
    "recorded_at": "2026-09-17T12:00:00+00:00",
}
#: The LAST record is the weakest — a new class at one tick — so "the most ticks" and "the
#: last one" are different answers, and only the last is the channel's most recent fault.
STUCK_LAST = {
    "fault_class": "GitProbeError<b>",
    "row_ids": ["f-1", "f-2", "f-4"],
    "consecutive_ticks": 1,
    "reason": "read-only git probe (worktree status) failed: <index.lock> held",
    "recorded_at": "2026-09-17T12:05:00+00:00",
}

#: `quarantine._manifest`. `verdict: {}` is the writer's "no scan recorded", kept for
#: exactly this reader; `cause: null` is a taint with nothing chained behind it.
TAINT_EARLIER: dict = {
    "batch_id": "a-earlier",
    "branch": "learning/lessons/a-earlier",
    "label": "lessons author",
    "worktree": "/srv/.worktrees/lessons-a-earlier",
    "archive": "a-earlier.tar.gz",
    "quarantined_at": "2026-09-11T08:00:00+00:00",
    "taint": "symlink escapes the worktree",
    "cause": None,
    "verdict": {},
    "findings": [
        {"path": "/srv/a", "kind": "symlink", "filemode": "0o777", "nlink": 1,
         "target": "/etc/passwd", "detail": "escapes the tree"},
        {"path": "/srv/b", "kind": "hardlink", "filemode": "0o644", "nlink": 2,
         "target": None, "detail": "outside the tree"},
    ],
}
TAINT_LATER: dict = {
    "batch_id": "b-later",
    "branch": "learning/leads/b-later",
    "label": "lead author",
    "worktree": "/srv/.worktrees/leads-b-later",
    "archive": "b-later.tar.gz",
    "quarantined_at": "2026-09-14T09:10:11+00:00",
    "taint": "a world-writable file survived the scrub",
    "cause": "RuntimeError('the batch was already dying')",
    "verdict": {"scanned": True, "clean": False},
    "findings": [],
}


# --------------------------------------------------------------------------------------
# what the contract says the serializer makes of them


EXPECTED_FINDINGS_DEADLETTER = [
    # newest first = file order reversed
    {"id": None, "reason": "row carries no value under 'finding_id'",
     "when": "2026-09-12T07:08:09+00:00", "row": {"run_id": "r10"}},
    {"id": "g-3", "reason": "the author never took it", "when": None,
     "row": {"finding_id": "g-3", "k": "v"}},
    {"id": None, "reason": "row carries no value under 'finding_id'", "when": None,
     "row": {"run_id": "r9", "note": "no id under finding_id"}},
    {"id": "g-1", "reason": "the author never took it",
     "when": "2026-09-10T04:05:06+00:00",
     "row": {"finding_id": "g-1", "title": SCRIPT_PAYLOAD}},
]

EXPECTED_MARKERS = [
    {"queue": "delivery", "identity": "z-delivery-1",
     "failed": "unreadable pending-delivery record", "tenant_id": None, "run_id": None},
    {"queue": "lead_author", "identity": "run-a",
     "failed": "unreadable: run_dir is not an absolute path", "tenant_id": None,
     "run_id": "run-a"},
    {"queue": "lead_author", "identity": "run-b",
     "failed": "artifact-missing <img src=x onerror=alert(2)>", "tenant_id": None,
     "run_id": "run-b"},
]

EXPECTED_DELIVERIES = [
    # `at` descending — the opposite of these records' filename order, on purpose.
    {"branch": "learning/leads/b2", "batch_id": "b2", "label": "lead author",
     "at": "2026-09-16T10:00:00+00:00", "reason": "opening the PR failed"},
    {"branch": "learning/lessons/b1", "batch_id": "b1", "label": "lessons author",
     "at": "2026-09-15T10:00:00+00:00", "reason": "push rejected"},
]

EXPECTED_TAINTED = [
    # `quarantined_at` descending — again the opposite of filename order.
    {"batch_id": "b-later", "archive": "b-later.tar.gz",
     "quarantined_at": "2026-09-14T09:10:11+00:00", "label": "lead author",
     "taint": "a world-writable file survived the scrub",
     "cause": "RuntimeError('the batch was already dying')",
     "verdict": {"scanned": True, "clean": False}, "findings": 0},
    {"batch_id": "a-earlier", "archive": "a-earlier.tar.gz",
     "quarantined_at": "2026-09-11T08:00:00+00:00", "label": "lessons author",
     "taint": "symlink escapes the worktree", "cause": None,
     "verdict": {}, "findings": 2},
]


# --------------------------------------------------------------------------------------
# seeding


def _make_paths(tmp_path: Path) -> LoopPaths:
    """`LoopPaths` over a state root that exists: the handle never creates it (#1135)."""
    paths = LoopPaths(repo_root=tmp_path / "repo", state_dir=tmp_path / "state")
    location_path(paths.state_root).mkdir(parents=True, exist_ok=True)
    return paths


def _build(paths: LoopPaths) -> dict:
    """`serialize_queues.build_view` over a handle opened on `paths` for the one call."""
    with LearningState.open(paths) as state:
        return serialize_queues.build_view(paths, state)


def _graveyard_file(paths: LoopPaths, channel: Channel) -> Path:
    """The channel's dead-letter sidecar, beside its queue (the layout is unchanged)."""
    return location_path(paths.state_root) / channel.deadletter


def _stuck_file(paths: LoopPaths, channel: Channel) -> Path:
    return location_path(paths.state_root) / channel.stuck


def _write_lines(path: Path, entries: list) -> None:
    """Seed a JSONL sidecar. A `str` entry is written verbatim, so a torn line is a torn
    line rather than a JSON-encoded string that happens to look like one."""
    path.parent.mkdir(parents=True, exist_ok=True)
    body = "".join(
        (e if isinstance(e, str) else json.dumps(e)) + "\n" for e in entries
    )
    path.write_text(body, encoding="utf-8")


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")


def _write_torn_json(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"batch_id": \n', encoding="utf-8")


def _seed_findings(paths: LoopPaths) -> None:
    ch = FINDINGS
    _write_lines(location_path(paths.state_root) / ch.queue, [
        {"finding_id": "f-1", "run_id": "r1", "title": BENIGN_PAYLOAD},
        {"finding_id": "f-2", "held_reason": "waits on a fact with no writer"},
        # PRESENCE, not truthiness — `drains._pending_queue_counts`' own rule.
        {"finding_id": "f-3", "held_reason": ""},
        # The forward-check bucket's field is NOT a hold: one field, one meaning.
        {"finding_id": "f-4", "forward_bad_reason": "the corpus moved under it"},
        TORN,
    ])
    _write_lines(_graveyard_file(paths, ch), [
        NESTED_STAMPED, TORN, FLAT_UNSTAMPED, NESTED_UNSTAMPED, FLAT_STAMPED, TORN,
    ])
    _write_lines(_stuck_file(paths, ch), [STUCK_FIRST, STUCK_MIDDLE, STUCK_LAST])


def _seed_questioner(paths: LoopPaths) -> None:
    ch = QUESTIONER_FINDINGS
    _write_lines(location_path(paths.state_root) / ch.queue, [
        {"finding_id": "q-1", "subject": "world"},
        {"finding_id": "q-2", "held_reason": "no source bundle"},
    ])
    # EMPTY, not absent: the file exists and holds no record.
    _write_lines(_stuck_file(paths, ch), [])
    # No graveyard file at all — the empty-dead-letters arm.


def _seed_pitfalls(paths: LoopPaths) -> None:
    ch = PITFALLS
    _write_lines(location_path(paths.state_root) / ch.queue, [
        {"pitfall_id": "p-1", "offers_declined": 0},
        {"pitfall_id": "p-2", "offers_declined": 2},
        {"pitfall_id": "p-3", "system": "elastic"},
    ])
    _write_lines(_graveyard_file(paths, ch), [CURATOR_DROP])
    # A STRAY stuck file — a copied state dir, a stale write. The lane records no stuck tick,
    # so `has_stuck_record` must stay false and `stuck` null whatever this file holds.
    _write_lines(_stuck_file(paths, ch), [STUCK_FIRST])


def _seed_set_aside(paths: LoopPaths) -> None:
    lead_failed = location_path(paths.state_root) / "author-queue" / "failed"
    _write_json(lead_failed / "run-a.json", {
        "run_id": "run-a", "failed": "unreadable: run_dir is not an absolute path",
    })
    _write_json(lead_failed / "run-b.json", {
        "run_id": "run-b", "run_dir": "/srv/runs/run-b",
        "failed": "artifact-missing <img src=x onerror=alert(2)>",
    })
    _write_torn_json(lead_failed / "torn.json")
    _write_torn_json(lead_failed / "torn-2.json")

    delivery_failed = location_path(paths.state_root) / "_pending_delivery" / "failed"
    # `_pending_deliveries` quarantines with an EMPTY spec, so `failed` is the whole record.
    _write_json(delivery_failed / "z-delivery-1.json", {
        "failed": "unreadable pending-delivery record",
    })

    _write_json(location_path(paths.state_root) / "_pending_delivery" / "a-older.json", {
        "branch": "learning/lessons/b1", "batch_id": "b1", "label": "lessons author",
        "reason": "push rejected", "at": "2026-09-15T10:00:00+00:00",
    })
    _write_json(location_path(paths.state_root) / "_pending_delivery" / "b-newer.json", {
        "branch": "learning/leads/b2", "batch_id": "b2", "label": "lead author",
        "reason": "opening the PR failed", "at": "2026-09-16T10:00:00+00:00",
    })
    _write_torn_json(location_path(paths.state_root) / "_pending_delivery" / "c-torn.json")

    qdir = paths.quarantine_dir
    _write_json(qdir / "a-earlier.json", TAINT_EARLIER)
    _write_json(qdir / "b-later.json", TAINT_LATER)
    for stem in ("a-earlier", "b-later"):
        (qdir / f"{stem}.tar.gz").write_bytes(b"")
    _write_torn_json(qdir / "c-torn.json")


def test_a_manifest_or_record_of_the_wrong_type_degrades_that_row_never_the_page(tmp_path):
    paths = _make_paths(tmp_path)
    _write_lines(location_path(paths.state_root) / FINDINGS.queue, [])
    _write_lines(_graveyard_file(paths, FINDINGS), [
        {"finding_id": "g-list", "deadletter_reason": "r", "row": ["not", "a", "mapping"]},
        {"finding_id": 7, "deadletter_reason": None, "retired_at": 12, "row": {"k": "v"}},
    ])
    _write_lines(_stuck_file(paths, FINDINGS), [
        {"fault_class": ["X"], "row_ids": "f-1", "consecutive_ticks": "many", "reason": None,
         "recorded_at": 5},
    ])
    _write_lines(location_path(paths.state_root) / PITFALLS.queue, [
        {"pitfall_id": "p-prose", "offers_declined": "lots"},
        {"pitfall_id": "p-bool", "offers_declined": True},
        {"pitfall_id": "p-real", "offers_declined": 1},
        # Held, with no usable id: COUNTED (the wake gate counts it) but not named.
        {"pitfall_id": 7, "offers_declined": 3},
    ])
    _write_lines(_graveyard_file(paths, PITFALLS), [
        # `json.loads` accepts a bare NaN; the contract must not write one back.
        '{"pitfall_id": "p-nan", "deadletter_reason": "r", "row": {"pitfall_id": "p-nan", "score": NaN}}',
    ])
    qdir = paths.quarantine_dir
    _write_json(qdir / "odd.json", {
        "batch_id": "odd", "archive": "odd.tar.gz", "quarantined_at": 20260914,
        "label": ["lead"], "taint": "t", "cause": 5, "verdict": "clean", "findings": 3,
    })
    _write_json(location_path(paths.state_root) / "_pending_delivery" / "odd.json", {"batch_id": "b", "at": 3})

    view = _build(paths)
    page = build.render_queues(view)

    assert _channel(view, "findings")["deadletter"] == [
        {"id": None, "reason": "", "when": None, "row": {"k": "v"}},
        {"id": "g-list", "reason": "r", "when": None, "row": {"value": ["not", "a", "mapping"]}},
    ]
    assert _channel(view, "findings")["stuck"] == {
        "fault_class": "", "row_ids": [], "consecutive_ticks": 0, "reason": "",
        "recorded_at": None,
    }
    assert _channel(view, "pitfalls")["held"] == {"count": 2, "ids": ["p-real"]}
    assert _channel(view, "pitfalls")["deadletter"][0]["row"] == {"pitfall_id": "p-nan", "score": None}
    assert "NaN" not in serialize_queues.dump_contract(view)
    json.loads(serialize_queues.dump_contract(view))            # strict: no bare NaN
    assert "0 ticks running" in _rendered(page)
    assert "2 held" in _rendered(page)
    [taint] = view["quarantine"]["tainted"]["rows"]
    assert taint["findings"] == 0
    assert taint["verdict"] == {}
    assert taint["quarantined_at"] is None
    assert taint["cause"] is None
    [delivery] = view["quarantine"]["deliveries"]["rows"]
    assert delivery["at"] is None


def test_an_empty_state_root_reads_as_three_idle_channels_and_nothing_set_aside(tmp_path):
    paths = _make_paths(tmp_path)

    view = _build(paths)

    assert view["state_root"] == str(location_path(paths.state_root))
    for name, accent, flag in (("findings", "defender", True),
                               ("questioner_findings", "learning", True),
                               ("pitfalls", "oracle", False)):
        assert _channel(view, name) == {
            "name": name, "accent": accent, "has_stuck_record": flag,
            "hold_means": _channel(view, name)["hold_means"],
            "depth": {"queued": 0}, "unreadable": 0, "held": {"count": 0, "ids": []},
            "deadletter": [], "stuck": None,
        }
        assert _channel(view, name)["hold_means"]
    assert view["quarantine"] == {
        "markers": {"rows": [], "unreadable": 0},
        "deliveries": {"rows": [], "unreadable": 0},
        "tainted": {"dir": str(paths.quarantine_dir), "cap": 10, "held": 0, "rows": [],
                    "unreadable": 0},
    }


def test_one_more_row_moves_exactly_one_number(paths):
    """The seeded root plus one dead letter on the questioner channel: only that channel's
    list and count move, and the rest of the view is byte-identical."""
    before = _build(paths)
    _write_lines(_graveyard_file(paths, QUESTIONER_FINDINGS), [
        {"finding_id": "q-dead", "attempts": 3, "deadletter_reason": "ceiling",
         "retired_at": "2026-09-18T00:00:00+00:00", "row": {"finding_id": "q-dead"}},
    ])

    after = _build(paths)

    assert _channel(after, "questioner_findings")["deadletter"] == [
        {"id": "q-dead", "reason": "ceiling", "when": "2026-09-18T00:00:00+00:00",
         "row": {"finding_id": "q-dead"}},
    ]
    for ch in after["channels"]:
        if ch["name"] != "questioner_findings":
            assert ch == _channel(before, ch["name"])
    assert after["quarantine"] == before["quarantine"]


@pytest.fixture
def paths(tmp_path: Path) -> LoopPaths:
    """A whole state root, seeded from every writer that feeds the page."""
    out = _make_paths(tmp_path)
    _seed_findings(out)
    _seed_questioner(out)
    _seed_pitfalls(out)
    _seed_set_aside(out)
    return out


@pytest.fixture
def view(paths: LoopPaths) -> dict:
    return _build(paths)


def _channel(view: dict, name: str) -> dict:
    match = [ch for ch in view["channels"] if ch["name"] == name]
    assert match, f"{name} is not in the view: {[c['name'] for c in view['channels']]}"
    return match[0]


# --------------------------------------------------------------------------------------
# the serializer — O6, O9, O7


def test_each_channel_carries_its_accent_and_whether_a_stuck_record_exists_for_it(view):
    accents = {ch["name"]: ch["accent"] for ch in view["channels"]}
    assert accents == {
        "findings": "defender",
        "questioner_findings": "learning",
        "pitfalls": "oracle",
    }
    flags = {ch["name"]: ch["has_stuck_record"] for ch in view["channels"]}
    assert flags == {
        "findings": True, "questioner_findings": True, "pitfalls": False,
    }


def test_queue_depth_is_the_readable_rows_of_the_pending_file(view):
    assert _channel(view, "findings")["depth"] == {"queued": 4}
    assert _channel(view, "questioner_findings")["depth"] == {"queued": 2}
    assert _channel(view, "pitfalls")["depth"] == {"queued": 3}


def test_unreadable_sums_a_channels_three_sidecars_counting_each_once(view):
    assert _channel(view, "findings")["unreadable"] == 3
    assert _channel(view, "questioner_findings")["unreadable"] == 0
    assert _channel(view, "pitfalls")["unreadable"] == 0


# --------------------------------------------------------------------------------------
# held — O3, per the lane's own marker


def test_findings_holds_are_every_row_carrying_held_reason_however_empty(view):
    held = _channel(view, "findings")["held"]
    assert held["ids"] == ["f-2", "f-3"]
    assert held["count"] == len(held["ids"])


# --------------------------------------------------------------------------------------
# dead letters — O1, mechanism 2


def test_dead_letters_are_newest_first_and_normalised_field_by_field(view):
    assert _channel(view, "findings")["deadletter"] == EXPECTED_FINDINGS_DEADLETTER


def test_a_curator_drop_reads_as_a_dead_letter_with_no_attempts_in_the_contract(view):
    [entry] = _channel(view, "pitfalls")["deadletter"]
    assert entry == {
        "id": "p-9",
        "reason": "undeclared-system:evil",
        "when": None,
        "row": {"pitfall_id": "p-9", "system": "evil", "occurrences": 2},
    }
    assert set(entry) == {"id", "reason", "when", "row"}


def test_a_channel_with_no_graveyard_file_lists_no_dead_letters(view):
    """The empty arm is an empty LIST, not a missing key: the card renders "no dead letters"
    rather than failing on the lookup."""
    assert _channel(view, "questioner_findings")["deadletter"] == []


# --------------------------------------------------------------------------------------
# stuck — O2, mechanism 4


def test_stuck_is_the_last_record_of_the_report_with_its_own_time(view):
    assert _channel(view, "findings")["stuck"] == STUCK_LAST
    # ...and NOT the record with the most ticks, which is the middle one.
    assert _channel(view, "findings")["stuck"]["consecutive_ticks"] == 1
    # Carried whole BECAUSE the writer's record is already the contract's five typed fields;
    # `STUCK_FIRST` predates the stamp, so it gains `recorded_at: null` rather than a KeyError.
    assert set(STUCK_LAST) == {"fault_class", "row_ids", "consecutive_ticks", "reason",
                               "recorded_at"}


def test_the_findings_lane_records_stuck_ticks_even_before_it_has_written_one(tmp_path):
    """The other half of "structural": a findings root with NO stuck file at all still says
    `has_stuck_record: true` — the lane records them, it just has not had one."""
    paths = _make_paths(tmp_path)
    _write_lines(location_path(paths.state_root) / FINDINGS.queue, [])
    ch = _channel(_build(paths), "findings")
    assert ch["has_stuck_record"] is True
    assert ch["stuck"] is None


# --------------------------------------------------------------------------------------
# set aside — O4, mechanism 6


def test_failed_markers_from_both_queue_dirs_are_listed_and_told_apart(view):
    assert view["quarantine"]["markers"]["rows"] == EXPECTED_MARKERS


def test_pending_deliveries_are_listed_newest_first(view):
    """The "retrying itself" half: a batch committed on a local branch whose push or PR has
    not landed. Newest first, by `at` — the records' filename order here is the reverse."""
    assert view["quarantine"]["deliveries"]["rows"] == EXPECTED_DELIVERIES


def test_tainted_manifests_are_listed_newest_first_with_the_verdict_kept(view):
    assert view["quarantine"]["tainted"]["rows"] == EXPECTED_TAINTED


def test_each_set_aside_list_counts_its_own_unreadable_files(view):
    q = view["quarantine"]
    assert q["markers"]["unreadable"] == 2
    assert q["deliveries"]["unreadable"] == 1
    assert q["tainted"]["unreadable"] == 1
    assert [ch["unreadable"] for ch in view["channels"]] == [3, 0, 0]


def test_held_is_the_writers_count_of_archives_not_of_readable_manifests(paths):
    qdir = paths.quarantine_dir
    (qdir / "orphan.tar.gz").write_bytes(b"")          # archive, no manifest
    (qdir / "c-torn.tar.gz").write_bytes(b"")          # archive, torn manifest (seeded)

    tainted = _build(paths)["quarantine"]["tainted"]

    assert len(tainted["rows"]) == 2
    assert tainted["held"] == 4
    assert tainted["held"] == quarantine.held_archives(qdir)
    assert "4 / 10" in _rendered(build.render_queues(_build(paths)))


def test_the_page_names_the_quarantine_directory_because_it_is_not_under_the_state_root(view, paths):
    assert view["quarantine"]["tainted"]["dir"] == str(paths.quarantine_dir)
    assert not str(paths.quarantine_dir).startswith(str(location_path(paths.state_root)))
    assert html.escape(str(paths.quarantine_dir), quote=True) in _rendered(build.render_queues(view))


def test_the_near_cap_warning_shows_at_two_slots_left_and_never_on_an_empty_directory(paths, monkeypatch):
    def page_for(cap: int) -> str:
        monkeypatch.setenv("LEARNING_TAINT_QUARANTINE_MAX", str(cap))
        return _rendered(build.render_queues(_build(paths)))

    assert 'class="cap">2 / 10</span>' in page_for(10)         # eight slots left
    assert 'class="cap near">2 / 4</span>' in page_for(4)      # two left
    assert 'class="cap near">2 / 2</span>' in page_for(2)      # full
    for stem in ("a-earlier", "b-later"):
        (paths.quarantine_dir / f"{stem}.tar.gz").unlink()
    assert 'class="cap">0 / 2</span>' in page_for(2)           # empty is never near
    assert ".q-group h3 .cap.near" in build.QUEUES_CSS


def test_an_unreadable_sidecar_or_directory_is_counted_not_fatal(paths):
    if not hasattr(os, "geteuid") or os.geteuid() == 0:
        pytest.skip("permission bits do not bind root")
    _graveyard_file(paths, FINDINGS).chmod(0)
    paths.quarantine_dir.chmod(0)
    try:
        view = _build(paths)
        page = build.render_queues(view)
    finally:
        paths.quarantine_dir.chmod(0o700)
        _graveyard_file(paths, FINDINGS).chmod(0o600)

    findings = _channel(view, "findings")
    assert findings["deadletter"] == []
    assert findings["unreadable"] == 2          # the torn pending line + the whole graveyard
    tainted = view["quarantine"]["tainted"]
    assert tainted == {"dir": str(paths.quarantine_dir), "cap": 10, "held": None, "rows": [],
                       "unreadable": 1}
    assert "? / 10" in _rendered(page)
    assert "1 unreadable file skipped" in _rendered(page)
    assert "2 unreadable lines skipped" in _rendered(page)


# --------------------------------------------------------------------------------------
# the header — O5


def test_stamped_view_uses_the_explicit_tenant_root_and_stamps_it(data_root, tmp_path, monkeypatch):
    """#1186 O1/O3: the explicit tenant supplies state despite an old ambient override."""
    from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant

    tenant = set_up_tenant(data_root)
    location_path(tenant.learning).mkdir(parents=True, exist_ok=True)
    poison = tmp_path / "old-env-root"
    poison.mkdir()
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(poison))
    paths = LoopPaths.for_tenant(tenant)

    with _Clock() as clock:
        stamped = serialize_queues.stamped_view(paths)

    assert Path(stamped["state_root"]) == location_path(tenant.learning)
    assert stamped["quarantine"]["tainted"]["dir"] == str(paths.quarantine_dir)
    clock.check(stamped["generated_at"].replace("Z", "+00:00"))
    assert [ch["name"] for ch in stamped["channels"]] == [
        "findings", "questioner_findings", "pitfalls",
    ]
    assert not list(poison.iterdir())


def test_stamped_view_takes_the_paths_it_is_handed(paths):
    """The seam the CLI and the tests share: handed a `LoopPaths`, nothing is resolved from
    the environment, so a test's root is the whole input surface."""
    stamped = serialize_queues.stamped_view(paths)
    assert stamped["state_root"] == str(location_path(paths.state_root))
    assert stamped["quarantine"]["tainted"]["dir"] == str(paths.quarantine_dir)
    assert stamped["generated_at"]


# --------------------------------------------------------------------------------------
# the renderer — mechanism 7


def _embedded_data(page: str) -> dict:
    match = re.search(r"^const DATA = (.*);\s*$", page, re.MULTILINE)
    assert match, "the page carries no `const DATA = ...;` line"
    return json.loads(match.group(1))


def _rewrite_strings(obj, old: str, new: str):
    if isinstance(obj, dict):
        return {k: _rewrite_strings(v, old, new) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_rewrite_strings(v, old, new) for v in obj]
    if isinstance(obj, str):
        return obj.replace(old, new)
    return obj


def test_a_row_that_looks_like_a_script_tag_opens_no_script_tag(view):
    quiet = _rewrite_strings(copy.deepcopy(view), SCRIPT_PAYLOAD, BENIGN_PAYLOAD)
    assert SCRIPT_PAYLOAD in json.dumps(view), "the fixture lost its payload"
    assert SCRIPT_PAYLOAD not in json.dumps(quiet)

    loud_page = build.render_queues(view)
    quiet_page = build.render_queues(quiet)

    assert loud_page.count("<script") == quiet_page.count("<script")
    assert loud_page.count("</script") == quiet_page.count("</script")
    assert SCRIPT_PAYLOAD not in loud_page
    assert "alert(1)" in loud_page, "the row's own content never reached the page"
    assert _embedded_data(loud_page) == view


def _rendered(page: str) -> str:
    """The page MINUS its embedded contract: what a browser shows, not what it carries. A
    substring found here was rendered, not merely serialized."""
    return re.sub(r"^const DATA = .*;\s*$", "", page, flags=re.MULTILINE)


def test_the_page_renders_every_dead_letter_and_hold_it_carries(view):
    body = _rendered(build.render_queues(view))
    for ch in view["channels"]:
        assert ch["name"] in body
        for entry in ch["deadletter"]:
            if entry["id"] is not None:
                assert entry["id"] in body
            assert html.escape(entry["reason"], quote=True) in body
            for value in entry["row"].values():
                assert html.escape(str(value), quote=True) in body
        for rid in ch["held"]["ids"]:
            assert rid in body
    assert "no id" in body
    assert "No dead letters" in body            # questioner's empty arm
    assert "2 held" in body                     # findings: f-2, f-3
    assert 'queued</span><span class="qt-val">4</span>' in body   # findings' depth
    assert 'dead</span><span class="qt-val n-warn">4</span>' in body


def test_the_page_renders_what_was_set_aside_and_tells_the_two_groups_apart(view):
    body = _rendered(build.render_queues(view))
    q = view["quarantine"]
    for m in q["markers"]["rows"]:
        assert m["identity"] in body
        # Escaped, with any event-handler attribute split (the untrusted-text escaper's rule).
        assert html.escape(m["failed"], quote=True).replace("onerror=", "on\u200berror=") in body
    for d in q["deliveries"]["rows"]:
        assert d["branch"] in body
    for t in q["tainted"]["rows"]:
        assert t["batch_id"] in body
        assert t["taint"] in body
    assert "Needs a person" in body
    assert "Retrying itself" in body
    assert "2 / 10" in body
    assert "no scan recorded" in body           # a-earlier's verdict is {}
    # One record per FILE in the set-aside dirs, one per LINE in a channel's sidecars, and
    # the count says which — an operator grepping a marker dir for torn lines finds files.
    assert "2 unreadable files skipped" in body  # markers
    assert "1 unreadable file skipped" in body   # deliveries, tainted
    assert "3 unreadable lines skipped" in body  # findings


def test_every_attacker_influenced_string_reaches_the_page_escaped(view):
    body = _rendered(build.render_queues(view))
    for hostile in (SCRIPT_PAYLOAD, "GitProbeError<b>", "<index.lock>"):
        assert hostile not in body, hostile
        assert html.escape(hostile, quote=True) in body, hostile
    assert "<img src=x onerror=alert(2)>" not in body
    assert "onerror=" not in body
    assert "&lt;img src=x on\u200berror=alert(2)&gt;" in body
    # ONE script element: the page's own contract carrier (its `const DATA` line is stripped
    # above, its tag is not), and none opened by content. `<img` has no legitimate twin.
    assert body.count("<script") == 1
    assert body.count("</script") == 1
    assert body.count("<img") == 0


def test_content_that_spells_a_placeholder_is_content(view):
    loud = copy.deepcopy(view)
    _channel(loud, "findings")["stuck"]["reason"] = "${cards} __CARDS__"
    _channel(loud, "findings")["deadletter"][0]["row"]["k"] = "${queues_json} __QUEUES_JSON__"

    page = build.render_queues(loud)
    body = _rendered(page)

    assert body.count('<details class="q-card') == len(view["channels"]) + 1
    assert page.count('"state_root":') == 1          # the contract is on the page ONCE
    assert "${cards}" in body
    assert "${queues_json}" in body
    assert _embedded_data(page) == loud


@pytest.mark.usefixtures("frontend_outputs_lock")
def test_main_publishes_the_four_pages_into_the_tenants_publish_area(
        paths, data_root, run_visualizations_dir, monkeypatch):
    """O1 (conflict updated from `..._beside_the_lessons_pages`): `main` writes the pages to `<root>/<T>/learning/`, not the tree."""
    from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H
    from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant

    monkeypatch.setenv("DEFENDER_DEPLOYMENT", "dev")
    import shutil

    tenant = set_up_tenant(data_root, H.TID)
    # `main(tenant)` derives the tenant's own LoopPaths (the learning-build flow): seed the tenant's state.
    shutil.copytree(location_path(paths.state_root), location_path(tenant.learning), dirs_exist_ok=True)
    area = run_visualizations_dir / tenant.id / "learning"
    area.mkdir(parents=True)
    (area / "queues.html").write_text("STALE", encoding="utf-8")
    before = _in_tree_pages()
    try:
        assert build.main(tenant) == 0

        assert sorted(p.name for p in area.iterdir()) == sorted(_PAGE_NAMES)
        queues = json.loads((area / "queues.json").read_text(encoding="utf-8"))
        assert [ch["name"] for ch in queues["channels"]] == [
            "findings", "questioner_findings", "pitfalls",
        ]
        assert queues["generated_at"]
        assert Path(queues["state_root"]) == location_path(tenant.learning)
        assert _channel(queues, "findings")["deadletter"] == EXPECTED_FINDINGS_DEADLETTER
        # The quarantine dir is the tenant's own LoopPaths' (host-wide until #1108 P4), not the
        # fixture's: its rows are not asserted here.
        assert Path(queues["quarantine"]["tainted"]["dir"]) == LoopPaths.for_tenant(tenant).quarantine_dir
        assert _embedded_data((area / "queues.html").read_text(encoding="utf-8")) == queues
        lessons = json.loads((area / "lessons.json").read_text(encoding="utf-8"))
        assert set(lessons["groups"]) == {"defender", "questioner"}  # U5 (#1108 P4)
        assert 'href="queues.html"' in (area / "lessons.html").read_text(encoding="utf-8")
        assert 'href="lessons.html"' in (area / "queues.html").read_text(encoding="utf-8")
        assert [p.name for p in run_visualizations_dir.iterdir()] == [tenant.id]
        assert _in_tree_pages() == before, "main wrote its pages into the source tree"
    finally:
        _restore_in_tree_pages(before)


# --------------------------------------------------------------------------------------
# #1279 O1/O4 — the learning pages are published per tenant, never into the source tree

_PAGE_NAMES = ("lessons.json", "lessons.html", "queues.json", "queues.html")


def _in_tree_pages() -> dict[str, bytes | None]:
    frontend = Path(build.__file__).resolve().parent
    return {n: (frontend / n).read_bytes() if (frontend / n).is_file() else None
            for n in _PAGE_NAMES}


def _restore_in_tree_pages(before: dict[str, bytes | None]) -> None:
    frontend = Path(build.__file__).resolve().parent
    for name, blob in before.items():
        if blob is None:
            (frontend / name).unlink(missing_ok=True)
        else:
            (frontend / name).write_bytes(blob)


def _build_cli(tenant_id: str, data_root: Path, **env: str):
    from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H

    return H.run_script(Path(build.__file__), "--tenant", tenant_id, root=data_root, **env)


@pytest.mark.parametrize("order", ["a-then-b", "b-then-a"])
@pytest.mark.usefixtures("frontend_outputs_lock")
def test_1279_o1_two_tenants_each_keep_their_own_pages_in_their_own_publish_area(
        paths, data_root, run_visualizations_dir, order):
    """O1: each tenant's four pages land in `<root>/<T>/learning/`, built in either order; none in the tree."""
    import shutil
    from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H
    from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H5

    # `create_tenant` admits one tenant per root; H5 plants the second by hand (F36).
    a, b = H5.tenant(data_root, H.TID), H5.tenant(data_root, H.OTHER)
    shutil.copytree(location_path(paths.state_root), location_path(a.learning), dirs_exist_ok=True)
    Path(location_path(b.learning)).mkdir(parents=True, exist_ok=True)
    area = {t.id: run_visualizations_dir / t.id / "learning" for t in (a, b)}
    before = _in_tree_pages()
    try:
        first, second = (a, b) if order == "a-then-b" else (b, a)
        proc = _build_cli(first.id, data_root, DEFENDER_DEPLOYMENT="dev")
        assert proc.returncode == 0, H.output(proc)
        first_pages = {n: (area[first.id] / n).read_bytes() for n in _PAGE_NAMES}
        proc = _build_cli(second.id, data_root, DEFENDER_DEPLOYMENT="dev")
        assert proc.returncode == 0, H.output(proc)

        assert {n: (area[first.id] / n).read_bytes() for n in _PAGE_NAMES} == first_pages, (
            "the second tenant's build rewrote the first tenant's pages")
        for t in (a, b):
            assert sorted(p.name for p in area[t.id].iterdir()) == sorted(_PAGE_NAMES)
            queues = json.loads((area[t.id] / "queues.json").read_text(encoding="utf-8"))
            assert Path(queues["state_root"]) == location_path(t.learning)
            assert _embedded_data((area[t.id] / "queues.html").read_text(encoding="utf-8")) == queues
        a_q = json.loads((area[a.id] / "queues.json").read_text(encoding="utf-8"))
        b_q = json.loads((area[b.id] / "queues.json").read_text(encoding="utf-8"))
        assert _channel(a_q, "findings")["deadletter"] == EXPECTED_FINDINGS_DEADLETTER
        assert _channel(b_q, "findings")["deadletter"] == [], "B's page shows A's dead letters"
        a_text, b_text = (area[t.id] / "queues.json" for t in (a, b))
        assert '"g-1"' in a_text.read_text(encoding="utf-8"), "positive control: A's page shows its own dead letter"
        assert '"g-1"' not in b_text.read_text(encoding="utf-8"), "B's page carries A's state-root rows"
        assert _in_tree_pages() == before, "the build wrote its pages into the source tree"
    finally:
        _restore_in_tree_pages(before)


@pytest.mark.usefixtures("frontend_outputs_lock")
def test_1279_o1_the_cli_builds_the_selected_tenants_state_not_an_ambient_one(
        paths, data_root, run_visualizations_dir, tmp_path):
    """O1/#1186 O3 (moved with the pages): the CLI publishes the selected tenant's state, whatever a legacy variable names."""
    import shutil
    from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H
    from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant

    tenant = set_up_tenant(data_root, H.TID)
    shutil.copytree(location_path(paths.state_root), location_path(tenant.learning), dirs_exist_ok=True)
    poison = tmp_path / "ambient-state"
    poison.mkdir()
    before = _in_tree_pages()
    try:
        proc = _build_cli(tenant.id, data_root, DEFENDER_DEPLOYMENT="dev",
                            DEFENDER_LEARNING_STATE_DIR=str(poison))
        assert proc.returncode == 0, H.output(proc)

        area = run_visualizations_dir / tenant.id / "learning"
        selected = json.loads((area / "queues.json").read_text(encoding="utf-8"))
        assert Path(selected["state_root"]) == location_path(tenant.learning)
        assert _channel(selected, "findings")["deadletter"] == EXPECTED_FINDINGS_DEADLETTER
        assert _embedded_data((area / "queues.html").read_text(encoding="utf-8")) == selected
        assert not list(poison.iterdir())
        assert _in_tree_pages() == before
    finally:
        _restore_in_tree_pages(before)


@pytest.mark.usefixtures("frontend_outputs_lock")
def test_1279_o4_the_learning_build_outside_dev_refuses_naming_the_deployment(
        data_root, run_visualizations_dir):
    """O4: with no publish destination (production), the build refuses, names the deployment, writes nothing."""
    from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H
    from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant

    t = set_up_tenant(data_root, H.TID)
    Path(location_path(t.learning)).mkdir(parents=True, exist_ok=True)
    before = _in_tree_pages()
    try:
        proc = _build_cli(t.id, data_root, DEFENDER_DEPLOYMENT="production")
        out = H.output(proc)
        H.assert_ran(proc)
        assert proc.returncode != 0, f"the build ran outside dev: {out}"
        assert "production" in out, f"the refusal does not name the deployment: {out}"
        assert not list(run_visualizations_dir.iterdir()), "a refused build published a page"
        assert _in_tree_pages() == before, "a refused build wrote into the source tree"
    finally:
        _restore_in_tree_pages(before)


@pytest.mark.usefixtures("frontend_outputs_lock")
def test_1279_a11_the_learning_build_in_dev_with_no_folder_set_refuses_naming_the_setting(
        data_root, run_visualizations_dir):
    """A9/A11: in dev with no publish folder set there is nowhere to publish: the build refuses
    cleanly, naming the setting, with no traceback, and writes nothing."""
    from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H
    from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant

    t = set_up_tenant(data_root, H.TID)
    Path(location_path(t.learning)).mkdir(parents=True, exist_ok=True)
    before = _in_tree_pages()
    try:
        proc = _build_cli(t.id, data_root, DEFENDER_DEPLOYMENT="dev",
                          DEFENDER_RUN_VISUALIZATIONS_DIR="")
        out = H.output(proc)
        H.assert_ran(proc)
        assert proc.returncode == 2, f"the build did not refuse: {out}"
        assert "DEFENDER_RUN_VISUALIZATIONS_DIR is unset" in out, f"the refusal does not name the setting: {out}"
        assert not list(run_visualizations_dir.iterdir()), "a refused build published a page"
        assert _in_tree_pages() == before, "a refused build wrote into the source tree"
    finally:
        _restore_in_tree_pages(before)


# --------------------------------------------------------------------------------------
# O8 — the writers stamp what they write


def _stamp(value) -> datetime:
    """The written stamp, parsed. A record with no stamp fails on the assert; one with a
    stamp nothing can read fails on the parse."""
    assert value, f"no timestamp was written: {value!r}"
    return datetime.fromisoformat(value)


class _Clock:
    """Brackets a write: the stamp must fall between entry and exit, to the second. A frozen
    constant, however well-formed, falls outside the bracket on any day but its own."""

    def __enter__(self):
        self.before = datetime.now(UTC).replace(microsecond=0)
        return self

    def __exit__(self, *_exc):
        self.after = datetime.now(UTC)

    def check(self, value) -> None:
        stamp = _stamp(value)
        assert stamp.tzinfo is not None, "a stamp with no zone cannot be placed"
        assert self.before <= stamp <= self.after, (self.before, stamp, self.after)


@pytest.fixture
def bare(tmp_path: Path) -> LoopPaths:
    """State only — every writer below appends beside its own queue and reads no tree."""
    return _make_paths(tmp_path)


def test_retire_stamps_the_dead_letter_it_writes(bare):
    """O8, writer 1 of 4. A dead letter with no time is a row a human cannot place against
    anything else that happened — and `when` is the only column the page can sort on."""
    ch = FINDINGS
    _write_lines(location_path(bare.state_root) / ch.queue, [{"finding_id": "a/0", "run_id": "a"}])

    with _Clock() as clock, LearningState.open(bare) as state:
        drain.retire(state, channel=FINDINGS, batch_ids=["a/0"], reason="the ceiling", max_attempts=1)

    [record] = read_jsonl_rows(_graveyard_file(bare, ch))
    assert record["deadletter_reason"] == "the ceiling"
    assert record["row"] == {"finding_id": "a/0", "run_id": "a"}
    clock.check(record.get("retired_at"))


def test_retiring_an_unkeyable_row_stamps_its_flat_record(bare):
    """O8, writer 2 of 4 — and the stamp rides on the FLAT shape without giving it a `row`
    key, since that key is the very thing a reader branches on."""
    ch = QUESTIONER_FINDINGS
    _write_lines(location_path(bare.state_root) / ch.queue, [])

    with _Clock() as clock, LearningState.open(bare) as state:
        drain._retire_unkeyable(state, QUESTIONER_FINDINGS, [{"run_id": "r9", "note": "no id here"}], logging.getLogger("defender.test"), 5)

    [record] = read_jsonl_rows(_graveyard_file(bare, ch))
    assert "row" not in record
    assert record["run_id"] == "r9"
    assert record["deadletter_reason"] == "row carries no value under 'finding_id'"
    clock.check(record.get("retired_at"))


def test_the_curators_dropped_row_carries_the_time_it_was_dropped(bare):
    """O8, writer 3 of 4. This writer is the one with no `attempts` to date the record by
    even loosely, so it is the one a missing stamp costs most."""
    rows = [{"pitfall_id": "p-9", "system": "evil", "occurrences": 2}]

    with _Clock() as clock, LearningState.open(bare) as state:
        pitfalls_curator._graveyard_dropped_rows(state, rows, ["p-9"])

    [record] = read_jsonl_rows(_graveyard_file(bare, PITFALLS))
    assert record["deadletter_reason"] == "undeclared-system:evil"
    assert record["row"] == rows[0]
    clock.check(record.get("retired_at"))


def test_recording_a_stuck_tick_stamps_when_it_was_recorded(bare):
    ch = FINDINGS

    with _Clock() as clock, LearningState.open(bare) as state:
        drain.record_stuck(state, FINDINGS, TimeoutError("the append lock never came free"), [
            {"finding_id": "a/0"},
        ])

    [record] = read_jsonl_rows(_stuck_file(bare, ch))
    assert record["fault_class"] == "TimeoutError"
    assert record["row_ids"] == ["a/0"]
    assert record["consecutive_ticks"] == 1
    clock.check(record.get("recorded_at"))


# --------------------------------------------------------------------------------------
# structural pins — O6, the cap's owner, the deferral closure, the ignore file
