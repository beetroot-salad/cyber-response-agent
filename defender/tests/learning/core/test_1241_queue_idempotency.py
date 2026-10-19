"""#1241: queue identity is finding_id, across retries and within an append.
"""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

import pytest

from defender.learning.core.state import FINDINGS, QUESTIONER_FINDINGS
from defender.learning.judge import enqueue
from defender.tests.support.learning.branch import _world_1007 as W
from defender.tests.learning.branch.test_1007_partition import queue_row, world_row


@pytest.fixture(params=[False, True], ids=["defender", "questioner"])
def channel_case(request, tmp_path):
    paths = W.loop_paths(tmp_path)
    if request.param:
        return paths, QUESTIONER_FINDINGS, world_row, enqueue.append_world_rows_report
    return paths, FINDINGS, queue_row, enqueue.append_rows_report


def test_retry_keeps_first_row_and_appends_distinct_ids(channel_case, tmp_path):
    paths, channel, build, append = channel_case
    first = build(finding_id="episode/b/0/0", finding="first content")
    changed = dict(first, finding="retry content must not replace the first")
    other = build(finding_id="episode/b/1/0", finding=first["finding"])
    assert append(tmp_path, [first], state=W.learning_state(paths)) == (1, 0)
    assert append(tmp_path, [changed, other], state=W.learning_state(paths)) == (1, 0)
    assert W.queue_rows(paths, channel) == [first, other]
    assert append(tmp_path, [changed, other], state=W.learning_state(paths)) == (0, 0)
    assert W.queue_rows(paths, channel) == [first, other]


def test_same_batch_duplicates_land_once_in_input_order(channel_case, tmp_path):
    paths, channel, build, append = channel_case
    first = build(finding_id="episode/b/0/0", finding="first")
    other = build(finding_id="episode/b/0/1", finding="second")
    assert append(tmp_path, [first, other, dict(first, finding="changed"), other],
                  state=W.learning_state(paths)) == (2, 0)
    assert W.queue_rows(paths, channel) == [first, other]


def test_concurrent_retries_share_persistent_identity(channel_case, tmp_path):
    paths, channel, build, append = channel_case
    row = build(finding_id="episode/b/0/0")

    def retry(_):
        return append(tmp_path, [row], state=W.learning_state(paths))

    with ThreadPoolExecutor(max_workers=4) as pool:
        reports = list(pool.map(retry, range(8)))
    assert sorted(reports) == [(0, 0)] * 7 + [(1, 0)]
    assert W.queue_rows(paths, channel) == [row]


def test_duplicate_does_not_bypass_validation(channel_case, tmp_path):
    paths, channel, build, append = channel_case
    row = build(finding_id="episode/b/0/0")
    assert append(tmp_path, [row], state=W.learning_state(paths)) == (1, 0)
    with pytest.raises(W.refusals()):
        append(tmp_path, [dict(row, subject_anchor="")], state=W.learning_state(paths))
    assert W.queue_rows(paths, channel) == [row]


def test_enqueue_report_retry_counts_only_new_findings(tmp_path):
    paths = W.loop_paths(tmp_path)
    first = queue_row(finding_id="episode/b/0/0")
    second = queue_row(finding_id="episode/b/1/0")
    drawn = enqueue.DrawnRows(defender=[first, first], world=[])
    report = enqueue.enqueue_report(tmp_path, {"world": "b"},
                                    state=W.learning_state(paths), drawn=drawn)
    assert (report.appended, report.malformed) == (1, 0)
    drawn = enqueue.DrawnRows(defender=[first, second], world=[])
    report = enqueue.enqueue_report(tmp_path, {"world": "b"},
                                    state=W.learning_state(paths), drawn=drawn)
    assert (report.appended, report.malformed) == (1, 0)
    assert W.queue_rows(paths, FINDINGS) == [first, second]


def test_existing_queue_identity_survives_torn_tail(channel_case, tmp_path):
    import json

    paths, channel, build, append = channel_case
    first = build(finding_id="episode/b/0/0")
    second = build(finding_id="episode/b/0/1")
    queue = paths.state_root / channel.queue
    queue.parent.mkdir(parents=True, exist_ok=True)
    original = json.dumps(first) + '\n{"torn": '
    queue.write_text(original, encoding="utf-8")
    assert append(tmp_path, [first, second, second], state=W.learning_state(paths)) == (1, 1)
    assert queue.read_text(encoding="utf-8") == original + "\n" + json.dumps(second) + "\n"
    assert append(tmp_path, [first, second], state=W.learning_state(paths)) == (0, 1)


def _append_in_fresh_process(tmp_path, questioner, row):
    paths = W.loop_paths(tmp_path)
    append = enqueue.append_world_rows_report if questioner else enqueue.append_rows_report
    return append(tmp_path, [row], state=W.learning_state(paths))


def test_another_process_append_is_seen_by_existing_handle(channel_case, tmp_path):
    import multiprocessing
    from concurrent.futures import ProcessPoolExecutor

    paths, channel, build, append = channel_case
    first = build(finding_id="episode/b/0/0")
    second = build(finding_id="episode/b/0/1")
    state = W.learning_state(paths)
    assert append(tmp_path, [first], state=state) == (1, 0)
    with ProcessPoolExecutor(max_workers=1,
                             mp_context=multiprocessing.get_context("spawn")) as pool:
        result = pool.submit(_append_in_fresh_process, tmp_path,
                             channel == QUESTIONER_FINDINGS, second).result(timeout=30)
    assert result == (1, 0)
    assert append(tmp_path, [second], state=state) == (0, 0)
    assert W.queue_rows(paths, channel) == [first, second]
