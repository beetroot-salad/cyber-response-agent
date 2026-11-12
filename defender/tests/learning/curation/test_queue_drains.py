"""Queue drains are best-effort only where proven: a mixed batch commits only what is attributable; a served request is the drain's own tenant's.

Over the learning store (#1278 D1, A1): a claim's items come from the store and its fates are the `outcomes` map.

Retired with the file queue (design r8 Locks and Items, A1):
- F-03 `a_held_queue_lock_leaves_the_whole_batch_queued` and `the_skip_rc_is_distinct_from_a_completed_serve`: the
  lead-queue file lock and `QUEUE_LOCK_SKIP_RC` are deleted. That one holder serves a lane at a time, and a pass that
  serves nothing neither deletes, charges nor dead-letters the requests, is the store claim's:
  `tests/tenancy/tenant_1108_p4/test_1278_tick.py::test_locks_a_tick_finding_a_live_batch_of_another_holder_authors_nothing_and_exits_quietly`
  (and `test_locks_a_by_hand_lead_author_run_*` for a by-hand run);
- F-04 `a_transient_retry_does_not_clobber_a_fresher_request`, `requeue_is_create_if_absent_and_leaves_no_staging_file`
  and `a_free_slot_still_takes_the_re_queue`: no re-queue write exists (a request returns to waiting by status); a
  fresher request for a case supersedes an older waiting one in the store:
  `tests/learning/store_1278/test_items_1278.py::test_a_later_request_for_one_case_supersedes_the_waiting_one` and
  `::test_a_request_returning_to_waiting_beside_a_fresher_one_is_superseded`.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from defender.tests.support.learning.curation import _spec773 as S
from defender.tests.support.learning.core import _state1135
from defender.tests.support.learning.core._store1278 import call, migrated_database, world  # noqa: F401 — fixtures
from defender.tests.support.shared._fixture_uuid import fixture_uuid
from defender.tests.tenancy.tenant_1108_p4.conftest import p4_tenant  # noqa: F401 — fixture `world` is built on


# F-02 — attribution bounds what a mixed batch commits
#
# Each tick runs the real lessons config over a batch's git-free draft: "committed" is read on the
# batch branch (`agent/lessons/...`), "restored away" is the draft back at the batch base.


def _write_corpus_file(corpus_dir: Path, stem: str, field: str, cited: list[str]) -> Path:
    """One curator-written corpus file, citing `cited` under `field` (or nothing at all)."""
    provenance = f"{field}:\n" + "".join(f"  - {c}\n" for c in cited) if cited else ""
    path = corpus_dir / f"{stem}.md"
    path.write_text(
        f"---\nname: {stem}\ndescription: a teachable pitfall\n{provenance}---\n\nbody\n",
        encoding="utf-8",
    )
    return path


def _f02_scene(tmp_path: Path, curate, seed_corpus: dict[str, str] | None = None):
    """The draft scene, claiming run-G/0 and run-B/0, its curator the function `curate`."""
    return S.build_draft_scene(
        tmp_path,
        rows=[S.finding_row("run-G/0", run_id="run-G"), S.finding_row("run-B/0", run_id="run-B")],
        seed_corpus=seed_corpus, invoke_agent=curate)


def test_852_f02_a_forward_bad_lesson_is_not_swept_into_a_mixed_batch_commit(tmp_path: Path):
    """An unattributable lesson faults the whole mixed batch: nothing lands, both files are reset
    away, and neither row is given a fate."""
    def curate(rows, batch_id, cfg):
        _write_corpus_file(cfg.corpus_dir, "vouched", "source_finding_ids", ["run-G/0"])
        _write_corpus_file(cfg.corpus_dir, "forward-bad", "source_finding_ids", [])
        return {
            "committed": ["run-G/0"],
            "consumed_skip": [],
            "commit_message": "defender: lesson vouched",
        }

    sc = _f02_scene(tmp_path, curate)
    assert sc.run() == 2, "the unattributable file did not fault the tick"

    assert not (sc.corpus / "forward-bad.md").exists(), \
        "the rejected lesson survived in the corpus"
    assert not (sc.corpus / "vouched.md").exists(), \
        "the tick faulted but its batch-mate's edit was not restored away with it"
    assert sc.head_files() == [], "a commit landed on a faulted tick"
    assert sc.outcomes == {}, "the batch was decided on a tick that committed nothing"


def test_852_f02_an_attributable_mixed_batch_still_commits(tmp_path: Path):
    """The control: without the unattributable file the batch commits, and the row the tick
    never mentioned is given no fate (no hold reason it was never given)."""
    def curate(rows, batch_id, cfg):
        _write_corpus_file(cfg.corpus_dir, "vouched", "source_finding_ids", ["run-G/0"])
        return {
            "committed": ["run-G/0"],
            "consumed_skip": [],
            "commit_message": "defender: lesson vouched",
        }

    sc = _f02_scene(tmp_path, curate)
    assert sc.run() == 0

    assert sc.head_files() == ["agent/lessons/vouched.md"]
    assert sc.fate("run-G/0") is None
    assert sc.fate("run-B/0") is None, (
        "a row this tick never mentioned was given a fate it was never given"
    )
    assert sc.outcomes == {}


def test_852_f02_a_modified_file_that_claims_a_new_source_still_needs_a_voucher(
    tmp_path: Path,
):
    """A base lesson edited to fold in a held-back row (`run-B/0`) does not land with its
    batch-mate. Only the stray `held_forward_bad` bucket refuses this tick now: a batch id
    citation is itself the voucher."""
    # An earlier batch's lesson, published in the export the batch starts from.
    earlier = tmp_path / "earlier"
    earlier.mkdir()
    old_text = _write_corpus_file(earlier, "old-fact", "source_finding_ids",
                                  ["run-A/0"]).read_text(encoding="utf-8")

    def curate(rows, batch_id, cfg):
        _write_corpus_file(cfg.corpus_dir, "vouched", "source_finding_ids", ["run-G/0"])
        # The curator folds the held-back run-B/0 into the earlier lesson anyway.
        _write_corpus_file(
            cfg.corpus_dir, "old-fact", "source_finding_ids", ["run-A/0", "run-B/0"]
        )
        return {
            "committed": ["run-G/0"],
            "consumed_skip": [],
            "held_forward_bad": [{"finding_id": "run-B/0", "reason": "flips a green case"}],
            "commit_message": "defender: lesson vouched",
        }

    sc = _f02_scene(tmp_path, curate, seed_corpus={"old-fact.md": old_text})
    old = sc.corpus / "old-fact.md"
    assert old.read_text(encoding="utf-8") == old_text

    assert sc.run() == 2, "the rejected fold rode in on its batch-mate"
    assert sc.head_files() == []
    assert "run-B/0" not in old.read_text(encoding="utf-8"), "the rejected fold survived"
    assert sc.outcomes == {}


# F-03 — a served request is the drain's own tenant's


def _curation_request(w, case_id: str, tenant_id: str, run_id: str) -> None:
    """File the curation request for `case_id` over the run `(tenant_id, run_id)` in `w`'s tenant's store."""
    row = {"case_id": case_id, "tenant_id": tenant_id, "run_id": run_id}
    call(w.dsn, "enqueue_request", w.t.tenant_id, run_id, case_id, row)


@pytest.mark.postgres
def test_1186_drain_never_serves_another_tenants_request_and_serves_its_own(world, tmp_path, monkeypatch):  # noqa: F811 — the imported fixture
    """A valid-looking foreign run address in A's store cannot grant access to tenant B: it is never served and is
    not mistaken for an absent run (dead as `artifact-missing`), while the tenant's own request is served. Only the
    refusal is pinned, not what then becomes of the foreign request (the store waits it and counts its attempts)."""
    from defender.tests.tenancy.tenant_1108_p4._drain_support import BoxSpy, lead_author_drain

    w = world
    own_run = _state1135.curation_run_dir("own-1186", tenant_id=w.t.tenant_id)
    other_id = fixture_uuid("tenant:other-1186")
    assert other_id != w.t.tenant_id
    _curation_request(w, "a-foreign", other_id, fixture_uuid("foreign-1186"))
    _curation_request(w, "b-own", w.t.tenant_id, own_run.name)
    # Once selected, the tenant supplies request acceptance even if ambient selection changes.
    monkeypatch.setenv("DEFENDER_DATA_ROOT", str(tmp_path / "not-the-selected-root"))
    served: list[Path] = []

    def serve(_paths, _state, run, *, on_done=None, **_kw):
        served.append(Path(run.run_dir))
        if on_done is not None:
            on_done(None)

    assert lead_author_drain(w.t, w.paths, box=BoxSpy(), run_lead_author=serve,
                             run_pitfalls=lambda *_a, **_kw: 0) == 0

    assert served == [own_run.resolve()], "a foreign request reached the author"
    items = {i.key: i for i in call(w.dsn, "work", w.t.tenant_id) if i.kind == "curation_request"}
    assert items[fixture_uuid("foreign-1186")].status != "dead", "the foreign address was read as an absent run"
    assert items[fixture_uuid("foreign-1186")].status == "waiting", "the foreign request was decided"
