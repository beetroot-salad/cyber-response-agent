"""#903 — the queue-state page: the serializer contract and the renderer.

#1278 replaced the file queues this page was built from with the learning store (design O2, "Flows"); the contract for the
rows it shows (status, reason, batch, PR, tenant isolation, the unreachable-store failure) is
`test_903_queue_view_1278.py`. This file keeps what survives of the page's own obligations over the store's rows and
the tainted-worktree archive (the one set-aside list that is not a queue).

Retired with the file state (#1278 A1/O10, design "Flows" and "Locks"), each pinning the on-disk shape of a queue:
the serializer's reads of the pending/graveyard/stuck sidecars (unreadable-line counts, torn lines, wrong-typed rows,
newest-first dead letters from `retired_at`, the stuck band), the failed-marker and pending-delivery lists, the stamps the
file writers put on what they wrote (`drain.retire`, `drain._retire_unkeyable`, `_graveyard_dropped_rows`,
`record_stuck`: those writers are deleted, and a store row carries its own `updated_at`), and the chmod-0 sidecar test.
What a held or dead item shows is `test_o2_the_view_names_each_items_status_batch_and_pr`.
"""
from __future__ import annotations

import copy
import dataclasses
import html
import json
import os
import re
from pathlib import Path

import pytest

from defender.tests.support.shared.contracts._frontend_outputs import frontend_outputs_lock  # noqa: F401 — shared pytest fixture
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — fixture

from defender.cli.learning import lessons_page as build
from defender.learning.core import quarantine
from defender.learning.core.config import LoopPaths
from defender.learning.frontend import serialize_queues
from defender.presentation import lessons_page as queues_page
from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.learning.core._store1278 import AUTHOR_LANE, ONE, finding

#: A queued row's own content, carrying the one character the embedded JSON must not emit raw.
SCRIPT_PAYLOAD = "<script>alert(1)</script>"
BENIGN_PAYLOAD = "an ordinary lesson title"
IMG_PAYLOAD = "unkeyable <img src=x onerror=alert(2)>"


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


class _NoWork:
    """A store holding nothing: the page's tainted-archive half and its empty state do not read a queue."""

    def work(self, tenant: str) -> list:  # noqa: ARG002 — the store's verb
        return []


def blocking(dsn: str):
    from defender.learning.store import blocking as open_blocking

    return open_blocking(dsn)


def _outcome(name: str, *reason: str):
    from defender.learning.store import Outcome

    return getattr(Outcome, name)(*reason)


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(payload) + "\n", encoding="utf-8")


def _write_torn_json(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"batch_id": "torn", ', encoding="utf-8")


def _tenant_paths(tmp_path: Path, data_root, tenant_id: str | None = None) -> LoopPaths:
    from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant

    tenant = set_up_tenant(data_root, tenant_id) if tenant_id else set_up_tenant(data_root)
    # `worktree_base` (hence the archive) follows `repo_root`: the checkout's own would be every test's archive.
    return dataclasses.replace(LoopPaths.for_tenant(tenant), repo_root=tmp_path / "checkout")


def _seed_set_aside(paths: LoopPaths) -> None:
    qdir = paths.quarantine_dir
    _write_json(qdir / "a-earlier.json", TAINT_EARLIER)
    _write_json(qdir / "b-later.json", TAINT_LATER)
    for stem in ("a-earlier", "b-later"):
        (qdir / f"{stem}.tar.gz").write_bytes(b"")
    _write_torn_json(qdir / "c-torn.json")


def _channel(view: dict, name: str) -> dict:
    match = [ch for ch in view["channels"] if ch["name"] == name]
    assert match, f"{name} is not in the view: {[c['name'] for c in view['channels']]}"
    return match[0]


def _rendered(page: str) -> str:
    """The page MINUS its embedded contract: what a browser shows, not what it carries."""
    return re.sub(r"^const DATA = .*;\s*$", "", page, flags=re.MULTILINE)


def _card_of(body: str, name: str) -> str:
    """The card of the channel `name`, from its summary to the next card."""
    start = body.index(f'<span class="qc-name">{name}</span>')
    end = body.find('<details class="q-card', start)
    return body[start:end if end != -1 else len(body)]


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


@pytest.fixture
def paths(tmp_path: Path, data_root) -> LoopPaths:
    """A tenant's paths with the tainted-worktree archive seeded (two manifests, one torn)."""
    out = _tenant_paths(tmp_path, data_root)
    _seed_set_aside(out)
    return out


@pytest.fixture
def stored(migrated_database, data_root, tmp_path):  # noqa: F811 — the imported fixture
    """A registered tenant whose store holds four findings in every state a person reads (waiting, held with a hostile
    reason, dead with a hostile reason, in batch) and one pitfall, with the tainted archive seeded: `(dsn, paths)`."""
    from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant

    dsn = migrated_database
    tenant = set_up_tenant(data_root)
    register_tenant(dsn, str(tenant.id))
    with blocking(dsn) as store:
        store.publish_findings(str(tenant.id), "run-1", [finding(f) for f in ("f1", "f2", "f3", "f4")], kind="finding")
        claim = store.claim(str(tenant.id), AUTHOR_LANE, owner="host-a", thresholds=ONE)
        store.in_review(claim, 7, {("finding", "f1"): _outcome("waiting"), ("finding", "f2"): _outcome("held", SCRIPT_PAYLOAD),
                                   ("finding", "f3"): _outcome("dead", IMG_PAYLOAD)})
    paths = dataclasses.replace(LoopPaths.for_tenant(tenant), repo_root=tmp_path / "checkout")  # its own archive
    _seed_set_aside(paths)
    return dsn, paths


def _view(stored) -> dict:
    dsn, paths = stored
    with blocking(dsn) as store:
        return serialize_queues.stamped_view(paths, store=store)


# --------------------------------------------------------------------------------------
# the serializer


def test_an_empty_store_reads_as_four_idle_channels_and_nothing_set_aside(tmp_path, data_root):
    """A tenant with nothing queued reads as four idle channels with no rows, and an empty archive as none held. (O2)"""
    paths = _tenant_paths(tmp_path, data_root)

    view = serialize_queues.build_view(paths, _NoWork())

    assert [ch["name"] for ch in view["channels"]] == ["findings", "questioner_findings", "pitfalls", "curation_requests"]
    for ch in view["channels"]:
        assert ch["items"] == []
        assert ch["deadletter"] == []
        assert ch["depth"] == {"waiting": 0, "queued": 0}
        assert ch["held"] == {"count": 0, "ids": []}
    assert view["quarantine"]["tainted"]["rows"] == []
    assert view["quarantine"]["tainted"]["held"] == 0
    assert "state_root" not in view


def test_each_channel_carries_its_accent(stored):
    view = _view(stored)
    assert {ch["name"]: ch["accent"] for ch in view["channels"]} == {
        "findings": "defender", "questioner_findings": "learning", "pitfalls": "oracle", "curation_requests": "raw"}


def test_one_more_row_moves_exactly_one_number(stored):
    """One more finding published raises the findings channel's waiting and queued counts by one and nothing else."""
    dsn, paths = stored
    before = _view(stored)

    with blocking(dsn) as store:
        store.publish_findings(str(paths.tenant.id), "run-2", [finding("f9")], kind="finding")
    after = _view(stored)

    b, a = _channel(before, "findings"), _channel(after, "findings")
    assert a["depth"] == {"waiting": b["depth"]["waiting"] + 1, "queued": b["depth"]["queued"] + 1}
    assert [r["id"] for r in a["items"]] == sorted([r["id"] for r in b["items"]] + ["f9"])
    for ch in after["channels"]:
        if ch["name"] != "findings":
            assert ch == _channel(before, ch["name"])
    assert after["quarantine"] == before["quarantine"]


def test_dead_letters_list_the_dead_items_with_their_reason(stored):
    """A dead item is listed under `deadletter` with its id and the reason the curator gave. (O2)"""
    findings = _channel(_view(stored), "findings")
    assert [(d["id"], d["reason"]) for d in findings["deadletter"]] == [("f3", IMG_PAYLOAD)]
    assert findings["held"]["ids"] == ["f2"]


def test_tainted_manifests_are_listed_newest_first_with_the_verdict_kept(paths):
    assert serialize_queues.build_view(paths, _NoWork())["quarantine"]["tainted"]["rows"] == EXPECTED_TAINTED


def test_the_tainted_list_counts_its_own_unreadable_files(paths):
    assert serialize_queues.build_view(paths, _NoWork())["quarantine"]["tainted"]["unreadable"] == 1


def test_held_is_the_writers_count_of_archives_not_of_readable_manifests(paths):
    qdir = paths.quarantine_dir
    (qdir / "orphan.tar.gz").write_bytes(b"")          # archive, no manifest
    (qdir / "c-torn.tar.gz").write_bytes(b"")          # archive, torn manifest (seeded)

    view = serialize_queues.build_view(paths, _NoWork())
    tainted = view["quarantine"]["tainted"]

    assert len(tainted["rows"]) == 2
    assert tainted["held"] == 4
    assert tainted["held"] == quarantine.held_archives(qdir)
    assert "4 / 10" in _rendered(queues_page.render_queues(view))


def test_the_page_names_the_quarantine_directory(paths):
    """The archive lives off the repo root, so the page names where it is."""
    view = serialize_queues.build_view(paths, _NoWork())
    assert view["quarantine"]["tainted"]["dir"] == str(paths.quarantine_dir)
    assert html.escape(str(paths.quarantine_dir), quote=True) in _rendered(queues_page.render_queues(view))


def test_the_near_cap_warning_shows_at_two_slots_left_and_never_on_an_empty_directory(paths, monkeypatch):
    def page_for(cap: int) -> str:
        monkeypatch.setenv("LEARNING_TAINT_QUARANTINE_MAX", str(cap))
        return _rendered(queues_page.render_queues(serialize_queues.build_view(paths, _NoWork())))

    assert 'class="cap">2 / 10</span>' in page_for(10)         # eight slots left
    assert 'class="cap near">2 / 4</span>' in page_for(4)      # two left
    assert 'class="cap near">2 / 2</span>' in page_for(2)      # full
    for stem in ("a-earlier", "b-later"):
        (paths.quarantine_dir / f"{stem}.tar.gz").unlink()
    assert 'class="cap">0 / 2</span>' in page_for(2)           # empty is never near
    assert ".q-group h3 .cap.near" in queues_page.QUEUES_CSS


def test_an_unreadable_archive_directory_is_counted_not_fatal(paths):
    if not hasattr(os, "geteuid") or os.geteuid() == 0:
        pytest.skip("permission bits do not bind root")
    paths.quarantine_dir.chmod(0)
    try:
        view = serialize_queues.build_view(paths, _NoWork())
        page = queues_page.render_queues(view)
    finally:
        paths.quarantine_dir.chmod(0o700)

    tainted = view["quarantine"]["tainted"]
    assert tainted == {"dir": str(paths.quarantine_dir), "cap": 10, "held": None, "rows": [], "unreadable": 1}
    assert "? / 10" in _rendered(page)
    assert "1 unreadable file skipped" in _rendered(page)


# --------------------------------------------------------------------------------------
# the header


def test_stamped_view_builds_from_the_tenant_its_paths_name_not_an_ambient_variable(paths, tmp_path, monkeypatch):
    """Handed a tenant's `LoopPaths`, nothing is resolved from the environment: a legacy learning-state variable is
    not read, written or listed, and the view is stamped with when it was built."""
    poison = tmp_path / "old-env-root"
    poison.mkdir()
    monkeypatch.setenv("DEFENDER_LEARNING_STATE_DIR", str(poison))  # lint-stale-ref: ok — the retired variable is set on purpose to prove it is ignored

    stamped = serialize_queues.stamped_view(paths, store=_NoWork())

    assert stamped["quarantine"]["tainted"]["dir"] == str(paths.quarantine_dir)
    assert stamped["generated_at"]
    assert not list(poison.iterdir())


# --------------------------------------------------------------------------------------
# the renderer


def test_a_row_that_looks_like_a_script_tag_opens_no_script_tag(stored):
    view = _view(stored)
    quiet = _rewrite_strings(copy.deepcopy(view), SCRIPT_PAYLOAD, BENIGN_PAYLOAD)
    assert SCRIPT_PAYLOAD in json.dumps(view), "the fixture lost its payload"
    assert SCRIPT_PAYLOAD not in json.dumps(quiet)

    loud_page = queues_page.render_queues(view)
    quiet_page = queues_page.render_queues(quiet)

    assert loud_page.count("<script") == quiet_page.count("<script")
    assert loud_page.count("</script") == quiet_page.count("</script")
    assert SCRIPT_PAYLOAD not in loud_page
    assert "alert(1)" in loud_page, "the row's own content never reached the page"
    assert _embedded_data(loud_page) == view


def test_the_page_renders_every_dead_letter_and_hold_it_carries(stored):
    view = _view(stored)
    body = _rendered(queues_page.render_queues(view))
    for ch in view["channels"]:
        assert ch["name"] in body
        # the page lists a channel's items, a dead one among them with its status and reason (the contract's separate
        # `deadletter` list rides in the embedded data only, asserted by `test_dead_letters_list_the_dead_items_with_their_reason`); an update, design O2.
        for entry in ch["items"]:
            assert entry["id"] in body
            if entry["reason"]:
                assert html.escape(entry["reason"], quote=True).replace("onerror=", "on\u200berror=") in body
        for rid in ch["held"]["ids"]:
            assert rid in body
        assert (not ch["items"]) == ("Nothing waiting, held or dead." in _card_of(body, ch["name"]))


def test_the_page_renders_what_was_set_aside(stored):
    view = _view(stored)
    body = _rendered(queues_page.render_queues(view))
    for t in view["quarantine"]["tainted"]["rows"]:
        assert t["batch_id"] in body
        assert t["taint"] in body
    assert "2 / 10" in body
    assert "no scan recorded" in body           # a-earlier's verdict is {}
    assert "1 unreadable file skipped" in body


def test_every_attacker_influenced_string_reaches_the_page_escaped(stored):
    body = _rendered(queues_page.render_queues(_view(stored)))
    for hostile in (SCRIPT_PAYLOAD,):
        assert hostile not in body, hostile
        assert html.escape(hostile, quote=True) in body, hostile
    assert "<img src=x onerror=alert(2)>" not in body
    assert "onerror=" not in body
    assert "&lt;img src=x on\u200berror=alert(2)&gt;" in body
    # ONE script element: the page's own contract carrier (its `const DATA` line is stripped above, its tag is not).
    assert body.count("<script") == 1
    assert body.count("</script") == 1
    assert body.count("<img") == 0


def test_content_that_spells_a_placeholder_is_content(stored):
    view = _view(stored)
    loud = copy.deepcopy(view)
    _channel(loud, "findings")["items"][0]["reason"] = "${cards} __CARDS__"
    _channel(loud, "findings")["items"][1]["reason"] = "${queues_json} __QUEUES_JSON__"

    page = queues_page.render_queues(loud)
    body = _rendered(page)

    assert body.count('<details class="q-card') == len(view["channels"]) + 1
    assert page.count('"generated_at":') == 1          # the contract is on the page ONCE
    assert "${cards}" in body
    assert "${queues_json}" in body
    assert _embedded_data(page) == loud


# --------------------------------------------------------------------------------------
# the learning pages are published per tenant, never into the source tree

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
    """`lessons_page.py --tenant T` as the operator's command line, through the test-side launcher (r10.1 C9: the
    command admits its tenant only from a directory): the launcher's directory holds the tenant active. The learning
    store is reached through `DEFENDER_DATABASE_DSN` when the case names one."""
    import subprocess

    from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H
    from defender.tests.support.tenancy import _launcher1214 as launcher

    command = launcher.command("lessons_page", ["--tenant", tenant_id], seed=[tenant_id], data_root=Path(data_root))
    return subprocess.run(  # noqa: S603 — fixed argv, the test's own interpreter
        command, env=launcher.environment(H.tenant_env(data_root, **env)), cwd=str(H.REPO_ROOT),
        capture_output=True, text=True, timeout=180, check=False)


@pytest.mark.postgres
@pytest.mark.usefixtures("frontend_outputs_lock")
def test_main_publishes_the_four_pages_into_the_tenants_publish_area(
        migrated_database, data_root, run_visualizations_dir, monkeypatch):  # noqa: F811 — the imported fixture
    """`main` writes the four pages to the tenant's publish area (`<root>/<T>/learning/`), replacing a stale page, built from
    the tenant's rows in the learning store, and nothing into the source tree."""
    from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H
    from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant

    monkeypatch.setenv("DEFENDER_DEPLOYMENT", "dev")
    monkeypatch.setenv("DEFENDER_DATABASE_DSN", migrated_database)
    tenant = set_up_tenant(data_root, H.TID)
    register_tenant(migrated_database, str(tenant.id))
    with blocking(migrated_database) as store:
        store.publish_findings(str(tenant.id), "run-1", [finding("g-1"), finding("g-2")], kind="finding")
    area = run_visualizations_dir / tenant.id / "learning"
    area.mkdir(parents=True)
    (area / "queues.html").write_text("STALE", encoding="utf-8")
    before = _in_tree_pages()
    try:
        assert build.build(tenant) == 0  # the builder takes the accepted tenant (r10.1 C1); `main` accepts it

        assert sorted(p.name for p in area.iterdir()) == sorted(_PAGE_NAMES)
        queues = json.loads((area / "queues.json").read_text(encoding="utf-8"))
        assert [ch["name"] for ch in queues["channels"]] == [
            "findings", "questioner_findings", "pitfalls", "curation_requests",
        ]
        assert queues["generated_at"]
        assert "state_root" not in queues
        assert sorted(r["id"] for r in _channel(queues, "findings")["items"]) == ["g-1", "g-2"]
        assert Path(queues["quarantine"]["tainted"]["dir"]) == LoopPaths.for_tenant(tenant).quarantine_dir
        assert _embedded_data((area / "queues.html").read_text(encoding="utf-8")) == queues
        lessons = json.loads((area / "lessons.json").read_text(encoding="utf-8"))
        assert set(lessons["groups"]) == {"defender", "questioner"}
        assert 'href="queues.html"' in (area / "lessons.html").read_text(encoding="utf-8")
        assert 'href="lessons.html"' in (area / "queues.html").read_text(encoding="utf-8")
        assert [p.name for p in run_visualizations_dir.iterdir()] == [tenant.id]
        assert _in_tree_pages() == before, "main wrote its pages into the source tree"
    finally:
        _restore_in_tree_pages(before)


@pytest.mark.postgres
@pytest.mark.parametrize("order", ["a-then-b", "b-then-a"])
@pytest.mark.usefixtures("frontend_outputs_lock")
def test_1279_o1_two_tenants_each_keep_their_own_pages_in_their_own_publish_area(
        migrated_database, data_root, run_visualizations_dir, order):  # noqa: F811 — the imported fixture
    """Each tenant's four pages land in `<root>/<T>/learning/`, built in either order from that tenant's own rows; none
    in the tree."""
    from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H
    from defender.tests.storage.tenant_1105_run_repository import _spec1105 as H5

    # `create_tenant` admits one tenant per root; H5 plants the second by hand.
    a, b = H5.tenant(data_root, H.TID), H5.tenant(data_root, H.OTHER)
    for t in (a, b):
        register_tenant(migrated_database, str(t.id))
    with blocking(migrated_database) as store:
        store.publish_findings(str(a.id), "run-a", [finding("g-1")], kind="finding")
    area = {t.id: run_visualizations_dir / t.id / "learning" for t in (a, b)}
    before = _in_tree_pages()
    env = {"DEFENDER_DEPLOYMENT": "dev", "DEFENDER_DATABASE_DSN": migrated_database}
    try:
        first, second = (a, b) if order == "a-then-b" else (b, a)
        proc = _build_cli(first.id, data_root, **env)
        assert proc.returncode == 0, H.output(proc)
        first_pages = {n: (area[first.id] / n).read_bytes() for n in _PAGE_NAMES}
        proc = _build_cli(second.id, data_root, **env)
        assert proc.returncode == 0, H.output(proc)

        assert {n: (area[first.id] / n).read_bytes() for n in _PAGE_NAMES} == first_pages, (
            "the second tenant's build rewrote the first tenant's pages")
        for t in (a, b):
            assert sorted(p.name for p in area[t.id].iterdir()) == sorted(_PAGE_NAMES)
            queues = json.loads((area[t.id] / "queues.json").read_text(encoding="utf-8"))
            assert _embedded_data((area[t.id] / "queues.html").read_text(encoding="utf-8")) == queues
        a_q = json.loads((area[a.id] / "queues.json").read_text(encoding="utf-8"))
        b_q = json.loads((area[b.id] / "queues.json").read_text(encoding="utf-8"))
        assert [r["id"] for r in _channel(a_q, "findings")["items"]] == ["g-1"], "positive control: A's page shows its own row"
        assert _channel(b_q, "findings")["items"] == [], "B's page shows A's rows"
        assert '"g-1"' not in (area[b.id] / "queues.json").read_text(encoding="utf-8")
        assert _in_tree_pages() == before, "the build wrote its pages into the source tree"
    finally:
        _restore_in_tree_pages(before)


@pytest.mark.usefixtures("frontend_outputs_lock")
def test_1279_o4_the_learning_build_outside_dev_refuses_naming_the_deployment(
        data_root, run_visualizations_dir):
    """With no publish destination (production), the build refuses, names the deployment and
    writes nothing."""
    from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H
    from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant

    t = set_up_tenant(data_root, H.TID)
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
    """In dev with no publish folder set there is nowhere to publish: the build refuses cleanly,
    naming the setting, with no traceback, and writes nothing."""
    from defender.tests.tenancy.tenant_1120_piece1 import _spec1120 as H
    from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant

    t = set_up_tenant(data_root, H.TID)
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
