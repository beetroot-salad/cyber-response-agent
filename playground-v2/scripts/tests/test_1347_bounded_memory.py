"""Reading the frozen copy holds one page of documents, and copying an image holds none of it.

The first live case write (freeze live-20261114) was killed by the operator machine's memory
limit: the content digest collected every document, with its source, of each index the base
overlay touched (the lab's busiest backing indices, millions of documents) before digesting any.
`frozen_copy.each` yields a page at a time; the digest keeps only each document's sha256. An image
copied into the engine goes through a file, never through this process's memory.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

SCRIPTS = Path(__file__).resolve().parents[1]
for _path in (SCRIPTS, SCRIPTS.parent, SCRIPTS.parent.parent):
    if str(_path) not in sys.path:
        sys.path.insert(0, str(_path))

import frozen_copy  # noqa: E402

_spec = importlib.util.spec_from_file_location("lab_ops_1347_memory", SCRIPTS / "lab_ops.py")
lab_ops = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lab_ops)


class PagedEs:
    """A point-in-time over `count` documents, answered `PAGE` at a time; records every request."""

    def __init__(self, count: int, total: int | None = None):
        self.docs = [{"_index": "i", "_id": str(n), "_version": 1, "_source": {"n": n}, "sort": [n]}
                     for n in range(count)]
        self.total = count if total is None else total
        self.requests: list[tuple[str, str]] = []

    def es_request(self, method, path, body=None):
        self.requests.append((method, path))
        if path.endswith("_pit?keep_alive=5m&expand_wildcards=open,hidden"):
            return {"id": "pit-1"}
        if path == "/_pit":
            return {}
        after = (body.get("search_after") or [-1])[0]
        page = [d for d in self.docs if d["sort"][0] > after][: body["size"]]
        return {"pit_id": "pit-1", "hits": {"total": {"value": self.total}, "hits": page}}

    def searches(self):
        return sum(1 for _, p in self.requests if p == "/_search")


def test_each_hands_over_the_first_page_before_reading_the_second():
    es = PagedEs(frozen_copy.PAGE * 3)
    hits = frozen_copy.each(es, "i", {"match_all": {}}, source=True)
    first = next(hits)
    assert first["_id"] == "0"
    assert es.searches() == 1
    rest = list(hits)
    assert len(rest) == frozen_copy.PAGE * 3 - 1
    assert es.requests[-1] == ("DELETE", "/_pit")   # the view closes once the last hit is read


def test_each_refuses_a_walk_short_of_the_count_after_the_last_page():
    es = PagedEs(5, total=7)
    with pytest.raises(frozen_copy.CopyFault, match="read 5 documents of the 7"):
        list(frozen_copy.each(es, "i", {"match_all": {}}))
    assert es.requests[-1] == ("DELETE", "/_pit")


def test_walk_is_still_every_hit_in_order():
    es = PagedEs(frozen_copy.PAGE + 3)
    assert [h["_id"] for h in frozen_copy.walk(es, "i", {"match_all": {}})] == \
        [str(n) for n in range(frozen_copy.PAGE + 3)]


def test_the_document_digests_read_the_index_a_page_at_a_time(monkeypatch):
    # The digest list must be built while the walk runs, not from a finished list of documents.
    es = PagedEs(frozen_copy.PAGE * 2 + 1)
    seen_while_walking = []
    real_each = frozen_copy.each

    def watched(*args, **kwargs):
        for hit in real_each(*args, **kwargs):
            seen_while_walking.append(es.searches())
            yield hit

    monkeypatch.setattr(frozen_copy, "each", watched)
    monkeypatch.setattr(frozen_copy, "walk", lambda *a, **k: pytest.fail("digest collected the whole index"))
    digests = lab_ops.LabOps._document_digests(es, "i")
    assert len(digests) == frozen_copy.PAGE * 2 + 1
    assert seen_while_walking[0] == 1 and seen_while_walking[-1] == 3


class ImageDocker:
    """`docker save` and `load` over the outer and inner daemons; records how each was fed."""

    def __init__(self):
        self.calls: list[tuple[list[str], dict]] = []

    def __call__(self, argv, **kw):
        self.calls.append((argv, kw))
        out = ""
        if argv[3:6] == ["image", "inspect", "-f"]:
            out = "sha256:" + "a" * 64
        if "save" in argv and "-o" in argv:
            Path(argv[argv.index("-o") + 1]).write_bytes(b"IMAGE-BYTES")
        rc = 1 if argv[-2:-1] == ["inspect"] or ("image" in argv and "inspect" in argv and "exec" in argv) else 0
        return type("P", (), {"returncode": rc, "stdout": out, "stderr": ""})()


def test_an_image_reaches_the_engine_through_a_file_not_this_process():
    docker = ImageDocker()
    lab_ops.LabOps(run=docker)._ensure_image("soc-playground/edge:local")
    saves = [(a, kw) for a, kw in docker.calls if "save" in a]
    loads = [(a, kw) for a, kw in docker.calls if "load" in a]
    assert saves and "-o" in saves[0][0], saves
    assert loads and "input" not in loads[0][1], "the image went through memory"
    handle = loads[0][1]["stdin"]
    assert handle.closed and not Path(handle.name).exists(), "the scratch archive outlived the load"


class CurlRig:
    """The frozen node's curl through `docker exec`: answers each call with the next (code, body)."""

    def __init__(self, answers):
        self.answers = list(answers)

    def __call__(self, argv, **kw):
        code, body = self.answers.pop(0) if self.answers else (200, {"status": "green"})
        out = f"{__import__('json').dumps(body)}\n{code}"
        return type("P", (), {"returncode": 0, "stdout": out, "stderr": ""})()


class Clock:
    def __init__(self):
        self.t = 0.0

    def now(self):
        from datetime import datetime, timezone
        return datetime.fromtimestamp(self.t, tz=timezone.utc)

    def sleep(self, seconds):
        self.t += seconds


UNAUTHENTICATED = {"error": {"type": "security_exception",
                             "reason": "unable to authenticate user [elastic] for REST request [/_cluster/health]"},
                   "status": 401}


def test_a_node_refusing_logins_while_it_starts_is_waited_out():
    # Live, 2026-11-14: a fresh frozen node answered 401 for ~16 s after its port opened.
    rig = CurlRig([(401, UNAUTHENTICATED), (401, UNAUTHENTICATED), (200, {"status": "green"})])
    es = lab_ops.FrozenEs(lab_ops.LabOps(run=rig))
    frozen_copy.wait_for_cluster(es, Clock(), "the node start")
    assert rig.answers == []


def test_a_login_never_accepted_fails_the_wait_naming_it():
    rig = CurlRig([(401, UNAUTHENTICATED)] * 10_000)
    es = lab_ops.FrozenEs(lab_ops.LabOps(run=rig))
    with pytest.raises(frozen_copy.CopyFault, match="HTTP 401"):
        frozen_copy.wait_for_cluster(es, Clock(), "the node start", timeout_s=30)


def test_any_other_refusal_still_ends_the_wait_at_once():
    rig = CurlRig([(403, {"error": {"type": "security_exception", "reason": "action is unauthorized"}})])
    es = lab_ops.FrozenEs(lab_ops.LabOps(run=rig))
    with pytest.raises(lab_ops.LabOpsError, match="HTTP 403"):
        frozen_copy.wait_for_cluster(es, Clock(), "the node start")
