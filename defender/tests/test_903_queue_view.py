"""#903 — the queue-state page: the serializer contract, the renderer, and the writers' stamps.

Written BEFORE the implementation, against the design doc posted on the issue.
`defender.learning.frontend.serialize_queues` does not exist at this base, so this module
errors at collection — the expected red — and `build.render_queues` is the second name that
has to appear for it to go green.

The fixture is ONE temp state root seeded with every writer's exact shape, taken off the
writers themselves rather than off the doc's prose: `drain.retire`'s nested record,
`drain._retire_unkeyable`'s flat one, `pitfalls_curator._graveyard_dropped_rows`' nested one
with no `attempts`, `drain._record_stuck`'s record, `markers.quarantine_marker`'s spec+failed
marker under BOTH failed dirs, `drains._record_pending_delivery`'s record, and
`quarantine._manifest`'s tainted manifest. A torn line rides in each sidecar, because a
tolerant reader that drops one silently is O7's own defect.

Every expectation here is a LITERAL, never rebuilt from the serializer's own output: an
oracle derived from the thing it checks is a tautology (`test_lessons_frontend.py`'s rule).
"""
from __future__ import annotations

import ast
import copy
import html
import inspect
import json
import os
import re
import types
from datetime import UTC, datetime
from pathlib import Path

import pytest

from defender._io import read_jsonl_rows
from defender.learning.author import drain
from defender.learning.author.branch import AuthorBranch
from defender.learning.core import quarantine
from defender.learning.core.config import LoopPaths, loop_paths
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
    # sorted by (queue, identity): "delivery" before "lead_author", whatever the
    # directories' own walk order is.
    {"queue": "delivery", "identity": "z-delivery-1",
     "failed": "unreadable pending-delivery record", "run_dir": None},
    {"queue": "lead_author", "identity": "run-a",
     "failed": "unreadable: run_dir is not an absolute path", "run_dir": None},
    {"queue": "lead_author", "identity": "run-b",
     "failed": "artifact-missing <img src=x onerror=alert(2)>", "run_dir": "/srv/runs/run-b"},
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
    ch = paths.findings
    _write_lines(ch.file, [
        {"finding_id": "f-1", "run_id": "r1", "title": BENIGN_PAYLOAD},
        {"finding_id": "f-2", "held_reason": "waits on a fact with no writer"},
        # PRESENCE, not truthiness — `drains._pending_queue_counts`' own rule.
        {"finding_id": "f-3", "held_reason": ""},
        # The forward-check bucket's field is NOT a hold: one field, one meaning.
        {"finding_id": "f-4", "forward_bad_reason": "the corpus moved under it"},
        TORN,
    ])
    _write_lines(drain.graveyard_file(ch), [
        NESTED_STAMPED, TORN, FLAT_UNSTAMPED, NESTED_UNSTAMPED, FLAT_STAMPED, TORN,
    ])
    _write_lines(drain.stuck_report_file(ch), [STUCK_FIRST, STUCK_MIDDLE, STUCK_LAST])


def _seed_questioner(paths: LoopPaths) -> None:
    ch = paths.questioner_findings
    _write_lines(ch.file, [
        {"finding_id": "q-1", "subject": "world"},
        {"finding_id": "q-2", "held_reason": "no source bundle"},
    ])
    # EMPTY, not absent: the file exists and holds no record.
    _write_lines(drain.stuck_report_file(ch), [])
    # No graveyard file at all — the empty-dead-letters arm.


def _seed_pitfalls(paths: LoopPaths) -> None:
    ch = paths.pitfalls
    _write_lines(ch.file, [
        {"pitfall_id": "p-1", "offers_declined": 0},
        {"pitfall_id": "p-2", "offers_declined": 2},
        {"pitfall_id": "p-3", "system": "elastic"},
    ])
    _write_lines(drain.graveyard_file(ch), [CURATOR_DROP])
    # A STRAY stuck file — a copied state dir, a stale write. The lane records no stuck tick,
    # so `has_stuck_record` must stay false and `stuck` null whatever this file holds.
    _write_lines(drain.stuck_report_file(ch), [STUCK_FIRST])


def _seed_set_aside(paths: LoopPaths) -> None:
    lead_failed = paths.author_queue_dir / "failed"
    _write_json(lead_failed / "run-a.json", {
        "run_id": "run-a", "failed": "unreadable: run_dir is not an absolute path",
    })
    _write_json(lead_failed / "run-b.json", {
        "run_id": "run-b", "run_dir": "/srv/runs/run-b",
        "failed": "artifact-missing <img src=x onerror=alert(2)>",
    })
    _write_torn_json(lead_failed / "torn.json")
    _write_torn_json(lead_failed / "torn-2.json")

    delivery_failed = paths.pending_delivery_dir / "failed"
    # `_pending_deliveries` quarantines with an EMPTY spec, so `failed` is the whole record.
    _write_json(delivery_failed / "z-delivery-1.json", {
        "failed": "unreadable pending-delivery record",
    })

    _write_json(paths.pending_delivery_dir / "a-older.json", {
        "branch": "learning/lessons/b1", "batch_id": "b1", "label": "lessons author",
        "reason": "push rejected", "at": "2026-09-15T10:00:00+00:00",
    })
    _write_json(paths.pending_delivery_dir / "b-newer.json", {
        "branch": "learning/leads/b2", "batch_id": "b2", "label": "lead author",
        "reason": "opening the PR failed", "at": "2026-09-16T10:00:00+00:00",
    })
    _write_torn_json(paths.pending_delivery_dir / "c-torn.json")

    qdir = paths.quarantine_dir
    _write_json(qdir / "a-earlier.json", TAINT_EARLIER)
    _write_json(qdir / "b-later.json", TAINT_LATER)
    for stem in ("a-earlier", "b-later"):
        (qdir / f"{stem}.tar.gz").write_bytes(b"")
    _write_torn_json(qdir / "c-torn.json")


def test_a_manifest_or_record_of_the_wrong_type_degrades_that_row_never_the_page(tmp_path):
    """The absent member of the ill-formed class: a file that PARSES but carries the wrong
    type where the reader expects a list, a mapping, a string or an int. A tainted manifest
    with `findings: 3` and `verdict: "clean"`, a graveyard record whose `row` is a list, a
    stuck record whose tick count is prose, a pitfalls row whose decline counter is prose —
    each is one degraded row, and the page still lists everything else. The contract is the
    typed boundary: nothing off disk reaches the renderer un-coerced, so the whole page is
    built here rather than asserted not to raise."""
    paths = LoopPaths(repo_root=tmp_path / "repo", state_dir=tmp_path / "state")
    _write_lines(paths.findings.file, [])
    _write_lines(drain.graveyard_file(paths.findings), [
        {"finding_id": "g-list", "deadletter_reason": "r", "row": ["not", "a", "mapping"]},
        {"finding_id": 7, "deadletter_reason": None, "retired_at": 12, "row": {"k": "v"}},
    ])
    _write_lines(drain.stuck_report_file(paths.findings), [
        {"fault_class": ["X"], "row_ids": "f-1", "consecutive_ticks": "many", "reason": None,
         "recorded_at": 5},
    ])
    _write_lines(paths.pitfalls.file, [
        {"pitfall_id": "p-prose", "offers_declined": "lots"},
        {"pitfall_id": "p-bool", "offers_declined": True},
        {"pitfall_id": "p-real", "offers_declined": 1},
        # Held, with no usable id: COUNTED (the wake gate counts it) but not named.
        {"pitfall_id": 7, "offers_declined": 3},
    ])
    _write_lines(drain.graveyard_file(paths.pitfalls), [
        # `json.loads` accepts a bare NaN; the contract must not write one back.
        '{"pitfall_id": "p-nan", "deadletter_reason": "r", "row": {"pitfall_id": "p-nan", "score": NaN}}',
    ])
    qdir = paths.quarantine_dir
    _write_json(qdir / "odd.json", {
        "batch_id": "odd", "archive": "odd.tar.gz", "quarantined_at": 20260914,
        "label": ["lead"], "taint": "t", "cause": 5, "verdict": "clean", "findings": 3,
    })
    _write_json(paths.pending_delivery_dir / "odd.json", {"batch_id": "b", "at": 3})

    view = serialize_queues.build_view(paths)
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
    """The negative control for the whole contract: a root with nothing in it. Every channel
    is present and idle, every set-aside list is empty, and the cap is still reported — so a
    serializer that answered from anything but the files it was handed would be caught by the
    difference between this and the seeded root."""
    paths = LoopPaths(repo_root=tmp_path / "repo", state_dir=tmp_path / "state")

    view = serialize_queues.build_view(paths)

    assert view["state_root"] == str(paths.state_root)
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
    before = serialize_queues.build_view(paths)
    _write_lines(drain.graveyard_file(paths.questioner_findings), [
        {"finding_id": "q-dead", "attempts": 3, "deadletter_reason": "ceiling",
         "retired_at": "2026-09-18T00:00:00+00:00", "row": {"finding_id": "q-dead"}},
    ])

    after = serialize_queues.build_view(paths)

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
    out = LoopPaths(repo_root=tmp_path / "repo", state_dir=tmp_path / "state")
    _seed_findings(out)
    _seed_questioner(out)
    _seed_pitfalls(out)
    _seed_set_aside(out)
    return out


@pytest.fixture
def view(paths: LoopPaths) -> dict:
    return serialize_queues.build_view(paths)


def _channel(view: dict, name: str) -> dict:
    match = [ch for ch in view["channels"] if ch["name"] == name]
    assert match, f"{name} is not in the view: {[c['name'] for c in view['channels']]}"
    return match[0]


# --------------------------------------------------------------------------------------
# the serializer — O6, O9, O7


def test_the_channels_are_the_serializers_own_literal_three_in_order(view):
    """O6: the page's channel set is a named list in one place, in the order it names them.
    Derived from `LoopPaths`' attributes or from a config table instead (#922's trap), the
    order is whatever that other table happens to hold."""
    assert [ch["name"] for ch in view["channels"]] == [
        "findings", "questioner_findings", "pitfalls",
    ]


def test_each_channel_carries_its_accent_and_whether_a_stuck_record_exists_for_it(view):
    """The two per-channel constants that ride beside the name. `has_stuck_record` is
    structural, not a fact about today's files: it is false for pitfalls, whose lane records
    no stuck tick at all, and true for the two that do."""
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
    """O9: the queued count beside the dead letters is what the pending file holds — four
    readable rows on findings, the torn fifth line excluded, so an empty dead-letter list
    next to a full queue reads differently from an idle channel."""
    assert _channel(view, "findings")["depth"] == {"queued": 4}
    assert _channel(view, "questioner_findings")["depth"] == {"queued": 2}
    assert _channel(view, "pitfalls")["depth"] == {"queued": 3}


def test_unreadable_sums_a_channels_three_sidecars_counting_each_once(view):
    """O7: a line the tolerant reader cannot parse is COUNTED, not dropped. Findings carries
    one torn line in its pending file, TWO in its graveyard and none in its stuck report —
    three, which only a sum of lines produces (a count of files-with-a-torn-line says two) —
    and pitfalls, whose sidecars are all clean, carries none."""
    assert _channel(view, "findings")["unreadable"] == 3
    assert _channel(view, "questioner_findings")["unreadable"] == 0
    assert _channel(view, "pitfalls")["unreadable"] == 0


# --------------------------------------------------------------------------------------
# held — O3, per the lane's own marker


def test_findings_holds_are_every_row_carrying_held_reason_however_empty(view):
    """O3, the findings/questioner lane: PRESENCE of `held_reason`, not truthiness. `f-3`
    carries `held_reason: ""` — a holder that had no wording to give — and a truthiness test
    reads it as authorable, which is the defect by the one route no gate spells. `f-1` (no
    marker) and `f-4` (the forward check's own field) are the negative arm."""
    held = _channel(view, "findings")["held"]
    assert held["ids"] == ["f-2", "f-3"]
    assert held["count"] == len(held["ids"])


def test_pitfalls_holds_are_rows_the_curator_was_offered_and_declined(view):
    """O3, the pitfalls lane: its own marker, `offers_declined > 0`. A row at 0 has been
    offered nothing and a row with no counter at all has never been offered — neither is
    held, and reading the findings lane's marker here would count all three or none."""
    held = _channel(view, "pitfalls")["held"]
    assert held["ids"] == ["p-2"]
    assert held["count"] == len(held["ids"])


def test_questioner_holds_use_the_same_marker_as_findings(view):
    """The second findings-shaped channel is not a special case: one lane, one marker."""
    held = _channel(view, "questioner_findings")["held"]
    assert held == {"count": 1, "ids": ["q-2"]}


def test_each_lane_says_what_its_own_hold_means(view):
    """The two markers END differently, and the page must not tell an operator one story for
    both: a findings hold waits on a fact with no writer and nothing retries it; a pitfalls
    hold is re-offered every tick and retired at the offer ceiling, so "held until a person
    moves it" there sends the operator to move a row the lane would have retried itself.
    The wording rides on the channel spec — the same census that owns the marker."""
    means = {ch["name"]: ch["hold_means"] for ch in view["channels"]}
    assert means["findings"] == means["questioner_findings"]
    assert "person" in means["findings"]
    assert "retries" in means["findings"]
    assert "person" not in means["pitfalls"]
    assert "every tick" in means["pitfalls"]
    assert "ceiling" in means["pitfalls"]
    body = _rendered(build.render_queues(view))
    assert f'2 held</b> · {means["findings"]}' in body
    assert f'1 held</b> · {means["pitfalls"]}' in body


# --------------------------------------------------------------------------------------
# dead letters — O1, mechanism 2


def test_dead_letters_are_newest_first_and_normalised_field_by_field(view):
    """O1 and mechanism 2, whole. Both writers' shapes collapse to one record: the nested
    one keeps its `row` and answers with the id under the channel's key, the flat one has no
    id and its row is the record minus the three bookkeeping fields. `when` is `retired_at`
    where a record has one and `null` where it predates mechanism 3, and the whole list is
    file order reversed."""
    assert _channel(view, "findings")["deadletter"] == EXPECTED_FINDINGS_DEADLETTER


def test_a_curator_drop_reads_as_a_dead_letter_with_no_attempts_in_the_contract(view):
    """`_graveyard_dropped_rows` writes `{pitfall_id, deadletter_reason, row}` and no
    `attempts` at all, so the contract has no slot for one — a record is exactly four fields
    on every channel, and a reader that reached for `attempts` would find it on two of the
    three writers' records and not the third."""
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
    """O2: the band is the channel's most recent non-retiring fault — the LAST record, not
    the first, not the one with the most ticks, and not a fold — carried whole, `recorded_at`
    included. `consecutive_ticks` resets to 1 whenever the class or row set changes, so the
    record with the most ticks is routinely a STALE fault. The file is
    append-only and nothing truncates it, so the band means "last faulted at"."""
    assert _channel(view, "findings")["stuck"] == STUCK_LAST
    # ...and NOT the record with the most ticks, which is the middle one.
    assert _channel(view, "findings")["stuck"]["consecutive_ticks"] == 1
    # Carried whole BECAUSE the writer's record is already the contract's five typed fields;
    # `STUCK_FIRST` predates the stamp, so it gains `recorded_at: null` rather than a KeyError.
    assert set(STUCK_LAST) == {"fault_class", "row_ids", "consecutive_ticks", "reason",
                               "recorded_at"}


def test_stuck_is_null_when_the_report_exists_but_holds_no_record(view):
    """An empty report is no fault, and `has_stuck_record` stays true: this lane records
    stuck ticks, it just has not had one. Paired with the findings channel above, which has
    the same flag and a record."""
    ch = _channel(view, "questioner_findings")
    assert ch["stuck"] is None
    assert ch["has_stuck_record"] is True


def test_the_pitfalls_lane_has_no_stuck_record_and_says_so_structurally(view):
    """`stuck: null` on pitfalls is not "no fault yet" — the lane writes no stuck record at
    all, and `has_stuck_record: false` is what tells the page's band the difference. The
    fixture plants a stray stuck file under pitfalls, so a flag read off the filesystem
    answers true here and a `stuck` read off the file answers a record."""
    ch = _channel(view, "pitfalls")
    assert ch["stuck"] is None
    assert ch["has_stuck_record"] is False


def test_the_findings_lane_records_stuck_ticks_even_before_it_has_written_one(tmp_path):
    """The other half of "structural": a findings root with NO stuck file at all still says
    `has_stuck_record: true` — the lane records them, it just has not had one."""
    paths = LoopPaths(repo_root=tmp_path / "repo", state_dir=tmp_path / "state")
    _write_lines(paths.findings.file, [])
    ch = _channel(serialize_queues.build_view(paths), "findings")
    assert ch["has_stuck_record"] is True
    assert ch["stuck"] is None


# --------------------------------------------------------------------------------------
# set aside — O4, mechanism 6


def test_failed_markers_from_both_queue_dirs_are_listed_and_told_apart(view):
    """O4: `quarantine_marker` writes under its CALLER's dir and it has two callers, so a
    page reading only the lead-author queue omits every quarantined delivery record. Each row
    names which queue it came from, its identity, the reason and the run dir it pointed at —
    `null` for a marker that carried none, which is one of the two ways a marker gets
    quarantined in the first place. Sorted by `(queue, identity)`."""
    assert view["quarantine"]["markers"]["rows"] == EXPECTED_MARKERS


def test_pending_deliveries_are_listed_newest_first(view):
    """The "retrying itself" half: a batch committed on a local branch whose push or PR has
    not landed. Newest first, by `at` — the records' filename order here is the reverse."""
    assert view["quarantine"]["deliveries"]["rows"] == EXPECTED_DELIVERIES


def test_tainted_manifests_are_listed_newest_first_with_the_verdict_kept(view):
    """The tainted archive, newest first by `quarantined_at`. `verdict: {}` is preserved as
    the empty dict the writer stored — "no scan recorded", which must not read as a clean
    scan to the human triaging the directory — and `findings` is the COUNT of what the scrub
    found, not the list."""
    assert view["quarantine"]["tainted"]["rows"] == EXPECTED_TAINTED


def test_each_set_aside_list_counts_its_own_unreadable_files(view):
    """O7 again, on the three JSON lists: two torn files in the markers dir, one each in the
    pending-delivery dir and the quarantine dir, counted per list and never folded into a
    channel's own count."""
    q = view["quarantine"]
    assert q["markers"]["unreadable"] == 2
    assert q["deliveries"]["unreadable"] == 1
    assert q["tainted"]["unreadable"] == 1
    assert [ch["unreadable"] for ch in view["channels"]] == [3, 0, 0]


def test_held_is_the_writers_count_of_archives_not_of_readable_manifests(paths):
    """`preserve_tainted_tree` refuses at `held >= cap` counting TARBALLS, and the page must
    show that number: an archive that survived without its manifest (the writer's own logged
    failure) and one whose manifest is torn both spend a slot. Counting manifests reads
    headroom that does not exist in exactly the failure the page exists to show."""
    qdir = paths.quarantine_dir
    (qdir / "orphan.tar.gz").write_bytes(b"")          # archive, no manifest
    (qdir / "c-torn.tar.gz").write_bytes(b"")          # archive, torn manifest (seeded)

    tainted = serialize_queues.build_view(paths)["quarantine"]["tainted"]

    assert len(tainted["rows"]) == 2
    assert tainted["held"] == 4
    assert tainted["held"] == quarantine.held_archives(qdir)
    assert "4 / 10" in _rendered(build.render_queues(serialize_queues.build_view(paths)))


def test_the_page_names_the_quarantine_directory_because_it_is_not_under_the_state_root(view, paths):
    """The tainted list is the one thing on the page that does not move with
    `DEFENDER_LEARNING_STATE_DIR` — it lives beside the live worktrees, off the repo root — so
    an operator pointing the page at a copied state dir sees THIS checkout's tainted trees and
    must be told where they came from."""
    assert view["quarantine"]["tainted"]["dir"] == str(paths.quarantine_dir)
    assert paths.quarantine_dir == AuthorBranch(repo_root=paths.repo_root).quarantine_dir
    assert not str(paths.quarantine_dir).startswith(str(paths.state_root))
    assert html.escape(str(paths.quarantine_dir), quote=True) in _rendered(build.render_queues(view))


def test_the_near_cap_warning_shows_at_two_slots_left_and_never_on_an_empty_directory(paths, monkeypatch):
    """The `near` class turns the count warm, so it must be a rule the page's own markup can
    match, and it must mean "two or fewer slots left" — not "cap minus two is at most the
    count", which at a cap of two is true of nothing at all."""
    def page_for(cap: int) -> str:
        monkeypatch.setenv("LEARNING_TAINT_QUARANTINE_MAX", str(cap))
        return _rendered(build.render_queues(serialize_queues.build_view(paths)))

    assert 'class="cap">2 / 10</span>' in page_for(10)         # eight slots left
    assert 'class="cap near">2 / 4</span>' in page_for(4)      # two left
    assert 'class="cap near">2 / 2</span>' in page_for(2)      # full
    for stem in ("a-earlier", "b-later"):
        (paths.quarantine_dir / f"{stem}.tar.gz").unlink()
    assert 'class="cap">0 / 2</span>' in page_for(2)           # empty is never near
    assert ".q-group h3 .cap.near" in build.QUEUES_CSS


def test_an_unreadable_sidecar_or_directory_is_counted_not_fatal(paths):
    """The tolerant reader's tolerance extends to the file it cannot OPEN: a sidecar with no
    read permission is one unreadable on its channel, an unlistable set-aside directory is
    one unreadable on its list and a `held` of null, and the page is still built."""
    if not hasattr(os, "geteuid") or os.geteuid() == 0:
        pytest.skip("permission bits do not bind root")
    drain.graveyard_file(paths.findings).chmod(0)
    paths.quarantine_dir.chmod(0)
    try:
        view = serialize_queues.build_view(paths)
        page = build.render_queues(view)
    finally:
        paths.quarantine_dir.chmod(0o700)
        drain.graveyard_file(paths.findings).chmod(0o600)

    findings = _channel(view, "findings")
    assert findings["deadletter"] == []
    assert findings["unreadable"] == 2          # the torn pending line + the whole graveyard
    tainted = view["quarantine"]["tainted"]
    assert tainted == {"dir": str(paths.quarantine_dir), "cap": 10, "held": None, "rows": [],
                       "unreadable": 1}
    assert "? / 10" in _rendered(page)
    assert "1 unreadable file skipped" in _rendered(page)
    assert "2 unreadable lines skipped" in _rendered(page)


def test_the_taint_cap_defaults_to_ten(view):
    """Past the cap the writer preserves nothing and only logs, so the page can under-report
    — which is why the cap is on the page at all."""
    assert view["quarantine"]["tainted"]["cap"] == 10


def test_the_taint_cap_follows_its_environment_variable(paths, monkeypatch):
    """The same address, moved: the cap is `LEARNING_TAINT_QUARANTINE_MAX`, read where the
    writer reads it, not a constant copied into the serializer."""
    monkeypatch.setenv("LEARNING_TAINT_QUARANTINE_MAX", "3")
    assert serialize_queues.build_view(paths)["quarantine"]["tainted"]["cap"] == 3


# --------------------------------------------------------------------------------------
# the header — O5


def test_build_view_says_which_state_root_it_read_and_carries_no_timestamp(view, paths):
    """`build_view` is pure over the filesystem it was handed: it names the root, and the
    stamping lives one layer up so a test of the contract is not a test of the clock."""
    assert view["state_root"] == str(paths.state_root)
    assert "generated_at" not in view


def test_stamped_view_resolves_the_state_root_at_call_time_and_stamps_it(tmp_path, monkeypatch):
    """O5: the page says which host's state it shows and when it was built. Resolved at CALL
    time — a module-level constant freezes the state root at import, and the CLI is exactly
    the caller that must honour one set after it.

    The env var moves the STATE root only: the tainted list stays with this checkout's
    worktrees, which is why the contract names that directory — and why this is the one test
    that reads it (nothing here asserts on what it holds; `main` and every other test hand
    their own `LoopPaths`)."""
    root = tmp_path / "late-state"
    (root / "_pending").mkdir(parents=True)
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(root))

    with _Clock() as clock:
        stamped = serialize_queues.stamped_view()

    assert Path(stamped["state_root"]) == root.resolve()
    assert stamped["quarantine"]["tainted"]["dir"] == str(loop_paths().quarantine_dir)
    clock.check(stamped["generated_at"].replace("Z", "+00:00"))
    assert [ch["name"] for ch in stamped["channels"]] == [
        "findings", "questioner_findings", "pitfalls",
    ]


def test_stamped_view_takes_the_paths_it_is_handed(paths):
    """The seam the CLI and the tests share: handed a `LoopPaths`, nothing is resolved from
    the environment, so a test's root is the whole input surface."""
    stamped = serialize_queues.stamped_view(paths)
    assert stamped["state_root"] == str(paths.state_root)
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


def test_the_page_embeds_the_view_it_was_handed_unchanged(view):
    """The page is self-contained: everything it renders it carries. Parsed back out of the
    embedded literal, it must be the view field for field — an escape that mangled a value
    on the way in would show up here rather than in a browser."""
    assert _embedded_data(build.render_queues(view)) == view


def test_a_row_that_looks_like_a_script_tag_opens_no_script_tag(view):
    """The security dive's one claim, executed. A dead-letter row carries `<script>` verbatim
    (alert data is attacker-influenced by definition, and a queue row is alert data's
    descendant). The page must contain no more script tags than the identical page built from
    a view with a harmless string in that slot — and must still carry the row's content, or
    the count would be trivially equal because nothing was rendered."""
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
    """O1, on the surface a person reads. For each channel: its name, its queued count, each
    dead letter's id and reason and its row's own content, and the held ids — present in the
    rendered HTML, not only inside the `const DATA` line. The empty-list arm renders its own
    words, and the flat record renders "no id" rather than nothing."""
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
    """O4 on the surface: every marker's identity and reason, every undelivered branch,
    every tainted batch and its taint, with the two groups under their own headings and the
    cap beside the tainted list."""
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


def test_the_fault_band_carries_the_class_the_ticks_and_the_time(view):
    """O2 on the surface: the band names the channel, the fault class, the run of ticks and
    `recorded_at` — the four things that let a person judge whether it is still live."""
    body = _rendered(build.render_queues(view))
    stuck = _channel(view, "findings")["stuck"]
    assert html.escape(stuck["fault_class"], quote=True) in body
    assert stuck["recorded_at"] in body
    assert "1 tick" in body
    assert html.escape(stuck["reason"], quote=True) in body


def test_every_attacker_influenced_string_reaches_the_page_escaped(view):
    """The security dive's claim on EVERY surface the page renders, not one: a dead-letter
    row value, a stuck fault class and reason, a marker's failure text. Each hostile literal
    is absent raw and present escaped in the rendered HTML, and a harmless twin proves the
    slot renders at all."""
    body = _rendered(build.render_queues(view))
    for hostile in (SCRIPT_PAYLOAD, "GitProbeError<b>", "<index.lock>"):
        assert hostile not in body, hostile
        assert html.escape(hostile, quote=True) in body, hostile
    # The marker's text is attacker-influenced, so it takes the run visualizer's escaper for
    # that class: escaped, AND its `onerror=` split by a zero-width space so nothing that
    # re-reads the page as plain text sees a live handler.
    assert "<img src=x onerror=alert(2)>" not in body
    assert "onerror=" not in body
    assert "&lt;img src=x on\u200berror=alert(2)&gt;" in body
    # ONE script element: the page's own contract carrier (its `const DATA` line is stripped
    # above, its tag is not), and none opened by content. `<img` has no legitimate twin.
    assert body.count("<script") == 1
    assert body.count("</script") == 1
    assert body.count("<img") == 0


def test_content_that_spells_a_placeholder_is_content(view):
    """The template is filled in ONE pass. Filled by successive replacements, a stuck reason
    of `${cards}` re-expanded into every card a second time and a row value of
    `${queues_json}` dumped the whole contract — the host's state-root path included — inside
    that row's own card. Both reproduced against the first cut."""
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


def test_a_timestamp_is_escaped_once(view):
    """`_when` slices, the list item escapes — one escape, at the point of writing markup. A
    date escaped on both sides showed a reader `&amp;lt;b&amp;gt;` where `<b>` was on disk."""
    odd = copy.deepcopy(view)
    odd["quarantine"]["tainted"]["rows"][0]["quarantined_at"] = "<b>2026-09-14"
    odd["quarantine"]["deliveries"]["rows"][0]["at"] = "&2026-09-16"
    _channel(odd, "findings")["deadletter"][0]["when"] = "<i>2026-09-12"

    body = _rendered(build.render_queues(odd))

    assert "&lt;b&gt;2026-0" in body
    assert "&amp;lt;" not in body
    assert "since &amp;2026-09-" in body
    assert "&amp;amp;" not in body
    assert "&lt;i&gt;2026-0" in body


def test_the_row_is_rendered_by_the_run_visualizers_own_highlighter(view):
    """One JSON highlighter and one escaper in the tree, not a second copy each: the row's
    `<pre>` is `visualize_primitives.pretty_json_html`'s output, which classes booleans and
    nulls the copy dropped, and every attacker-influenced string goes through
    `esc_untrusted`."""
    from defender.scripts.visualize import visualize_primitives

    odd = copy.deepcopy(view)
    _channel(odd, "findings")["deadletter"][0]["row"]["flag"] = True
    _channel(odd, "findings")["deadletter"][0]["row"]["none"] = None
    body = _rendered(build.render_queues(odd))

    assert visualize_primitives.pretty_json_html(
        _channel(odd, "findings")["deadletter"][0]["row"]) in body
    assert '<span class="j-bool">true</span>' in body
    assert '<span class="j-null">null</span>' in body
    assert build.esc_untrusted is visualize_primitives.esc_untrusted
    assert not hasattr(build, "_esc")
    assert not hasattr(build, "_json_pretty")


def test_the_last_fault_band_is_on_the_page_only_when_a_channel_is_stuck(view):
    """The band is machinery health, rendered once for the page rather than per card, and it
    is titled by the record's time — so a page whose channels have all drained cleanly must
    not offer an operator a fault heading with nothing under it."""
    calm = copy.deepcopy(view)
    for channel in calm["channels"]:
        channel["stuck"] = None

    assert "Last fault" in _rendered(build.render_queues(view))
    assert "Last fault" not in _rendered(build.render_queues(calm))


def test_the_two_pages_link_to_each_other(view):
    """The lessons page and the queue page are one surface; each header names the other."""
    assert 'href="queues.html"' in build.render({"groups": {}})
    assert 'href="lessons.html"' in build.render_queues(view)


def test_main_writes_the_queue_pages_beside_the_lessons_pages(paths):
    """One command builds all four files, on demand — nothing here runs on a drain tick.

    The build writes into the real frontend dir (that is the point), so this restores every
    one of the four to whatever it found, including "absent"."""
    frontend = Path(build.__file__).resolve().parent
    names = ("lessons.json", "lessons.html", "queues.json", "queues.html")
    before = {
        n: (frontend / n).read_bytes() if (frontend / n).is_file() else None for n in names
    }
    try:
        assert build.main(paths) == 0
        queues = json.loads((frontend / "queues.json").read_text(encoding="utf-8"))
        assert [ch["name"] for ch in queues["channels"]] == [
            "findings", "questioner_findings", "pitfalls",
        ]
        assert queues["generated_at"]
        assert Path(queues["state_root"]) == paths.state_root
        # Hermetic: the seeded root's two tainted trees, not whatever this checkout holds.
        assert [t["batch_id"] for t in queues["quarantine"]["tainted"]["rows"]] == [
            "b-later", "a-earlier",
        ]
        assert _embedded_data((frontend / "queues.html").read_text(encoding="utf-8")) == queues
        assert (frontend / "lessons.json").is_file()
        assert (frontend / "lessons.html").is_file()
    finally:
        for name, blob in before.items():
            if blob is None:
                (frontend / name).unlink(missing_ok=True)
            else:
                (frontend / name).write_bytes(blob)


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
    return LoopPaths(repo_root=tmp_path / "repo", state_dir=tmp_path / "state")


def test_retire_stamps_the_dead_letter_it_writes(bare):
    """O8, writer 1 of 4. A dead letter with no time is a row a human cannot place against
    anything else that happened — and `when` is the only column the page can sort on."""
    ch = bare.findings
    _write_lines(ch.file, [{"finding_id": "a/0", "run_id": "a"}])

    with _Clock() as clock:
        drain.retire(channel=ch, batch_ids=["a/0"], reason="the ceiling", max_attempts=1)

    [record] = read_jsonl_rows(drain.graveyard_file(ch))
    assert record["deadletter_reason"] == "the ceiling"
    assert record["row"] == {"finding_id": "a/0", "run_id": "a"}
    clock.check(record.get("retired_at"))


def test_retiring_an_unkeyable_row_stamps_its_flat_record(bare):
    """O8, writer 2 of 4 — and the stamp rides on the FLAT shape without giving it a `row`
    key, since that key is the very thing a reader branches on."""
    ch = bare.questioner_findings
    _write_lines(ch.file, [])

    with _Clock() as clock:
        drain._retire_unkeyable(ch, [{"run_id": "r9", "note": "no id here"}], lambda _m: None, 5)

    [record] = read_jsonl_rows(drain.graveyard_file(ch))
    assert "row" not in record
    assert record["run_id"] == "r9"
    assert record["deadletter_reason"] == "row carries no value under 'finding_id'"
    clock.check(record.get("retired_at"))


def test_the_curators_dropped_row_carries_the_time_it_was_dropped(bare):
    """O8, writer 3 of 4. This writer is the one with no `attempts` to date the record by
    even loosely, so it is the one a missing stamp costs most."""
    rows = [{"pitfall_id": "p-9", "system": "evil", "occurrences": 2}]

    with _Clock() as clock:
        pitfalls_curator._graveyard_dropped_rows(bare, rows, ["p-9"])

    [record] = read_jsonl_rows(drain.graveyard_file(bare.pitfalls))
    assert record["deadletter_reason"] == "undeclared-system:evil"
    assert record["row"] == rows[0]
    clock.check(record.get("retired_at"))


def test_recording_a_stuck_tick_stamps_when_it_was_recorded(bare):
    """O8, writer 4 of 4. The stuck file is append-only and nothing clears it, so the band is
    "last faulted at" and NOT "stuck right now" — without `recorded_at` the page cannot say
    which of those it is showing."""
    ch = bare.findings

    with _Clock() as clock:
        drain.record_stuck(ch, TimeoutError("the append lock never came free"), [
            {"finding_id": "a/0"},
        ])

    [record] = read_jsonl_rows(drain.stuck_report_file(ch))
    assert record["fault_class"] == "TimeoutError"
    assert record["row_ids"] == ["a/0"]
    assert record["consecutive_ticks"] == 1
    clock.check(record.get("recorded_at"))


# --------------------------------------------------------------------------------------
# structural pins — O6, the cap's owner, the deferral closure, the ignore file


def test_the_channel_list_is_the_serializers_own_literal_and_reads_no_other_table():
    """O6, structurally: the three names live in one module-level literal in the serializer,
    and the module neither walks `LoopPaths`' attributes nor asks the drain's wake table.
    #922's trap is a serializer whose channel set moves when some other table does."""
    names = [spec.name for spec in serialize_queues._CHANNELS]
    assert names == ["findings", "questioner_findings", "pitfalls"]
    # CODE, not prose: the docstring is allowed to name the other table while explaining
    # why it is not read. Walk the AST for the two ways a module could derive the set.
    tree = ast.parse(inspect.getsource(serialize_queues))
    calls = {n.func.id for n in ast.walk(tree)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)}
    assert not calls & {"dir", "vars", "getattr"}, calls
    attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert "_curator_queue_checks" not in attrs
    imported = {m.__name__ for m in vars(serialize_queues).values()
                if isinstance(m, types.ModuleType)}
    assert "defender.learning.core.drains" not in imported


def test_the_taint_cap_is_read_where_the_writer_reads_it():
    """The cap on the page is the writer's own function, not a copy of its env name and
    default: change the writer's default and the page follows without an edit here."""
    assert serialize_queues.quarantine_cap is quarantine.quarantine_cap
    assert serialize_queues.held_archives is quarantine.held_archives
    assert quarantine.quarantine_cap() == quarantine._MAX_DEFAULT
    # ...and the writer counts through the same function it exposes.
    assert "held_archives(quarantine_dir)" in inspect.getsource(quarantine.preserve_tainted_tree)


def test_nothing_in_the_tree_still_says_the_graveyard_is_unread():
    """Mechanism 8: every docstring, test and spec-graph clause that deferred to #903 now
    names the page as the reader. `graveyard_file`'s own docstring is the one the issue
    quoted."""
    assert "nothing in production reads this back" not in (drain.graveyard_file.__doc__ or "")
    assert "serialize_queues" in (drain.graveyard_file.__doc__ or "")
    repo = Path(build.__file__).resolve().parents[3]
    stale = []
    for path in [*(repo / "defender").rglob("*.py"), *(repo / "spec-flow" / "specs").glob("*.yaml")]:
        if ".venv" in path.parts or "worktrees" in path.parts or path == Path(__file__).resolve():
            continue
        text = path.read_text(encoding="utf-8")
        if "unread until #903" in text or "open until #903" in text or "Until #903 lands" in text:
            stale.append(str(path.relative_to(repo)))
    assert stale == []


def test_the_built_pages_are_ignored_by_git():
    ignore = (Path(build.__file__).resolve().parent / ".gitignore").read_text(encoding="utf-8")
    assert "queues.html" in ignore.split()
    assert "queues.json" in ignore.split()
