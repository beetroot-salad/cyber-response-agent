"""#1278 O2: the queue page shows, per tenant, what is waiting, held or dead, in which batch and which PR, from the
learning store, not from a state root. The view and its page are `serialize_queues` and `lessons_page`.

Interface request (names chosen here): `serialize_queues.stamped_view(paths, store=)` builds the view for the tenant
`paths` names from the store's sync facade; its channels are `findings`, `questioner_findings`, `pitfalls`,
`curation_requests`, each with `items` (rows `id`, `status`, `reason`, `batch_id`, `pr_number`, `source_run`), `depth.waiting` and
`held.ids`; there is no `state_root`; `quarantine.tainted` stays (the worktree archive is not a queue)."""
from __future__ import annotations

import pytest

from defender.learning.core.config import LoopPaths
from defender.tests.support.jobs._jobs1342 import register_tenant
from defender.tests.support.learning.core._store1278 import AUTHOR_LANE, ONE, finding, world_finding
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.support.shared._locations_1210 import location_path
from defender.tests.support.shared._postgres1339 import migrated_database  # noqa: F401 — fixture

pytestmark = pytest.mark.postgres

BLUE = fixture_uuid("tenant:1278-view-blue")
GREEN = fixture_uuid("tenant:1278-view-green")
SCRIPT = "<script>alert(1)</script>"


def blocking(dsn: str):
    from defender.learning.store import blocking as open_blocking

    return open_blocking(dsn)


def _outcome(name: str, *reason: str):
    from defender.learning.store import Outcome

    return getattr(Outcome, name)(*reason)


@pytest.fixture
def seen(migrated_database, data_root):  # noqa: F811 — the imported fixture
    """Blue's items in every state a person reads, Green's one item, and Blue's PR 7: `(dsn, blue paths, batch id)`."""
    from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant

    dsn = migrated_database
    blue = set_up_tenant(data_root, BLUE)
    set_up_tenant(data_root, GREEN)
    register_tenant(dsn, BLUE)
    register_tenant(dsn, GREEN)
    with blocking(dsn) as store:
        store.publish_findings(BLUE, "run-1", [finding(f) for f in ("f1", "f2", "f3", "f4")], kind="finding")
        store.publish_findings(BLUE, "run-1", [world_finding("q1")], kind="questioner_finding")
        store.publish_findings(GREEN, "run-2", [finding("g1")], kind="finding")
        claim = store.claim(BLUE, AUTHOR_LANE, owner="host-a", thresholds=ONE)
        store.in_review(claim, 7, {("finding", "f1"): _outcome("waiting"), ("finding", "f2"): _outcome("held", SCRIPT),
                                   ("finding", "f3"): _outcome("dead", "unkeyable")})
        store.add_pitfall(BLUE, {"schema_version": 1, "pitfall_id": "p1", "source_run": "r", "system": "elastic",
                                 "query_id": "elastic.esql", "goal": "g", "executed_query": "x",
                                 "stderr_digest": "exit=1; d", "error_class": "agent-fixable"})
        store.enqueue_request(BLUE, "run-9", "case-9", {"case": "case-9"})
    return dsn, LoopPaths.for_tenant(blue), claim.batch_id


def _rows(view: dict) -> dict[tuple[str, str], dict]:
    return {(ch["name"], row["id"]): row for ch in view["channels"] for row in ch["items"]}


def test_o2_the_page_has_a_channel_for_every_kind_the_store_holds(seen):
    """A person's feedback instruction held at the attempt ceiling must be as visible as a held finding: every work-item
    kind the store can hold is a channel of the page. (finding 9 of the #1476 review)"""
    from defender.jobs.learning_models import KINDS
    from defender.learning.frontend import serialize_queues

    dsn, paths, _batch = seen
    with blocking(dsn) as store:
        view = serialize_queues.stamped_view(paths, store=store)

    assert len(view["channels"]) == len(KINDS)
    assert "feedback_instructions" in {ch["name"] for ch in view["channels"]}


def test_o2_the_view_names_each_items_status_batch_and_pr(seen):
    """Waiting, held, dead and in-batch items each show their status, reason, batch and PR; the others' counts follow. (O2)"""
    dsn, paths, batch_id = seen
    from defender.learning.frontend import serialize_queues

    with blocking(dsn) as store:
        view = serialize_queues.stamped_view(paths, store=store)

    rows = _rows(view)
    got = {k: (r["status"], r["batch_id"], r["pr_number"]) for k, r in rows.items()}
    assert got[("findings", "f4")] == ("in_batch", batch_id, 7)
    assert got[("findings", "f2")] == ("held", batch_id, 7)
    assert got[("findings", "f3")] == ("dead", batch_id, 7)
    assert got[("findings", "f1")] == ("waiting", None, None), "a waiting item shows the batch it left (#1476 review 10)"
    assert got[("questioner_findings", "q1")][0] == "in_batch"
    assert got[("pitfalls", "p1")] == ("waiting", None, None)
    assert got[("curation_requests", "run-9")] == ("waiting", None, None)
    assert rows[("findings", "f3")]["reason"] == "unkeyable"
    channel = {ch["name"]: ch for ch in view["channels"]}
    assert channel["findings"]["held"]["ids"] == ["f2"]
    assert channel["findings"]["depth"]["waiting"] == 1
    assert "state_root" not in view
    assert view["generated_at"]


def test_o2_the_view_shows_the_run_each_item_came_from(seen):
    """Each row of the view names its `source_run`: the run that published it, a pitfall's own, a request's run. (input 24, ruling)"""
    dsn, paths, _batch = seen
    from defender.learning.frontend import serialize_queues

    with blocking(dsn) as store:
        view = serialize_queues.stamped_view(paths, store=store)

    got = {k: r.get("source_run") for k, r in _rows(view).items()}
    assert got[("findings", "f1")] == got[("findings", "f4")] == "run-1"
    assert got[("questioner_findings", "q1")] == "run-1"
    assert got[("pitfalls", "p1")] == "r"
    assert got[("curation_requests", "run-9")] == "run-9"


def test_o2_another_tenants_items_never_show(seen):
    """Green's finding is not in Blue's view. (O2, O6)"""
    dsn, paths, _batch = seen
    from defender.learning.frontend import serialize_queues

    with blocking(dsn) as store:
        view = serialize_queues.stamped_view(paths, store=store)

    assert ("findings", "g1") not in _rows(view)
    assert "g1" not in str(view)


def test_o2_the_view_builds_with_no_learning_folder_and_writes_none(seen):
    """The queues are rows, so the page builds for a tenant whose learning folder is absent and leaves it absent.
    (O2, O10)"""
    dsn, paths, _batch = seen
    from defender.learning.frontend import serialize_queues

    folder = location_path(paths.tenant.tenant_root) / "learning"  # the old root's place: the handle to it is deleted (O10)
    if folder.exists():
        import shutil

        shutil.rmtree(folder)
    with blocking(dsn) as store:
        serialize_queues.stamped_view(paths, store=store)

    assert not folder.exists()


def test_o2_the_page_shows_the_rows_escaped(seen):
    """The rendered page carries each item's id, status, PR and batch, and a hostile reason is escaped. (O2)"""
    dsn, paths, batch_id = seen
    from defender.learning.frontend import serialize_queues
    from defender.presentation import lessons_page

    with blocking(dsn) as store:
        page = lessons_page.render_queues(serialize_queues.stamped_view(paths, store=store))

    for needle in ("f2", "f3", "q1", "p1", "run-9", batch_id):
        assert needle in page, needle
    assert SCRIPT not in page.split("const DATA", 1)[0], "a held item's reason reached the page unescaped"
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page


def test_o2_a_store_that_cannot_be_read_fails_the_build_instead_of_an_empty_page(seen):
    """An unreachable store is a failed build, never a page of idle queues. (O2, E2)"""
    _dsn, paths, _batch = seen
    from defender.learning.frontend import serialize_queues

    with pytest.raises(Exception, match=r"(?i)connect|refused"), \
            blocking("postgresql://postgres:postgres@127.0.0.1:1/postgres") as store:  # a closed local port
        serialize_queues.stamped_view(paths, store=store)


#: One hostile marker per string a person's or a model's text puts on the page; each is unique so a miss names its field.
def _hostile(n: int) -> str:
    return f"<u>m{n}</u>"


def _escaped(n: int) -> str:
    return f"&lt;u&gt;m{n}&lt;/u&gt;"


def test_o2_hostile_text_in_every_rendered_string_field_is_escaped_on_the_page(migrated_database, data_root):  # noqa: F811
    """Item ids of each channel, held ids, reasons: markup in any of them is escaped; a clean twin is untouched. (O2, E1)"""
    from defender.learning.frontend import serialize_queues
    from defender.presentation import lessons_page
    from defender.tests.support.shared.contracts._data_root_1078 import set_up_tenant

    dsn = migrated_database
    paths = LoopPaths.for_tenant(set_up_tenant(data_root, BLUE))
    register_tenant(dsn, BLUE)
    fields = {name: _hostile(n) for n, name in enumerate(
        ["finding id", "held id", "dead id", "in-batch id", "questioner id", "request run", "held reason",
         "dead reason", "waiting id"], start=1)}
    with blocking(dsn) as store:
        store.publish_findings(BLUE, "run-1", [finding(fields[k]) for k in
                                               ("finding id", "held id", "dead id", "in-batch id", "waiting id")],
                               kind="finding")
        store.publish_findings(BLUE, "run-1", [world_finding(fields["questioner id"])], kind="questioner_finding")
        store.enqueue_request(BLUE, fields["request run"], "case-1", {"case": "case-1"})
        claim = store.claim(BLUE, AUTHOR_LANE, owner="host-a", thresholds=ONE)
        outcomes = {("finding", fields["held id"]): _outcome("held", fields["held reason"]),
                    ("finding", fields["dead id"]): _outcome("dead", fields["dead reason"])}
        for key in (fields["finding id"], fields["in-batch id"], fields["waiting id"]):
            outcomes[("finding", key)] = _outcome("waiting")
        store.in_review(claim, 7, outcomes)
        view = serialize_queues.stamped_view(paths, store=store)

    page = lessons_page.render_queues(view).split("const DATA", 1)[0]
    for name, raw in fields.items():
        n = int(raw.removeprefix("<u>m").removesuffix("</u>"))
        assert raw not in page, f"the {name} reached the page unescaped"
        assert _escaped(n) in page, f"the {name} is not on the page (control)"
