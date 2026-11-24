"""#1592 OD-6 "Feedback" (amends #1414): the tick takes in a comment exactly when its author's login is `p-` followed by
the canonical id of a user wanted in T, by the tick's one membership read (`people=`); every other login is passed over.
S3-1, S3-2, S3-3 and S3-5; the scene (`conftest.fb`) hands every tick a `people=` of its own unless a case gives one.
"""
from __future__ import annotations

import importlib
import inspect
import logging

import pytest

from defender.tests.learning.feedback_1414 import _spec1414 as S
from defender.tests.learning.feedback_1414._spec1414 import People
from defender.tests.support.identity._wanted1592 import plant_member
from defender.tests.support.shared._fixture_uuid import fixture_uuid

pytestmark = pytest.mark.postgres

WANTED = fixture_uuid("user:1592-feedback-wanted")
NOT_WANTED = fixture_uuid("user:1592-feedback-not-wanted")


def test_1592_a_comment_counts_by_its_authors_membership_read_once_per_tick(fb, caplog):
    """S3-1: `p-<wanted>` is taken in; an unwanted `p-` login, the wanted id in upper case, a plain login and the bot
    are passed over and logged. The tick reads the membership once, for its tenant."""
    people = People(WANTED)
    number = fb.opened("case-1592", S.Decider())
    taken = fb.forge.add_comment(number, user=f"p-{WANTED}", body="expected")
    for login in (f"p-{NOT_WANTED}", f"p-{WANTED.upper()}", "ann", fb.bot):
        fb.forge.add_comment(number, user=login, body="approved, add it")

    decider = S.Decider()
    with caplog.at_level(logging.INFO):
        assert fb.tick(decider, people=people) == 0

    assert decider.decided == [taken["id"]]
    assert people.reads == [fb.tid], "the tick did not read the membership exactly once, for its tenant"
    assert any(f"p-{NOT_WANTED}" in r.getMessage() for r in caplog.records), "the passed-over author is not logged"
    assert fb.requests_to("branch_protections", "/teams", "/orgs/") == [], "the tick read Forgejo's team"


def test_1592_a_failed_membership_read_is_a_transient_refusal_that_takes_nothing_in(fb, caplog):
    """S3-2: with `people=` raising `RecordsUnreachable` the tick is skipped with a warning and nothing is lost; the
    next tick takes the comment in."""
    from defender.tenancy import RecordsUnreachable

    number = fb.opened("case-1592-down", S.Decider())
    comment = fb.forge.add_comment(number, user=f"p-{WANTED}", body="expected")
    down = People(WANTED)
    down.error = RecordsUnreachable("the database is down")

    decider = S.Decider()
    with caplog.at_level(logging.WARNING):
        assert fb.tick(decider, people=down) == 0
    assert decider.decided == [], "a comment was taken in while the membership read failed"
    assert any(r.levelno >= logging.WARNING for r in caplog.records), "the refusal is not logged"

    assert fb.tick(decider, people=People(WANTED)) == 0
    assert decider.decided == [comment["id"]], "the comment was lost to the failed tick"


def test_1592_the_default_seam_reads_the_products_memberships_at_the_database_dsn(fb):
    """S3-3: `feedback_drain` with no `people=` takes in the wanted person's comment and passes over the one whose
    membership has ended, reading memberships in `DEFENDER_DATABASE_DSN`."""
    wanted = plant_member(fb.dsn, fb.tid, "wanted-1592@example.org")
    gone = plant_member(fb.dsn, fb.tid, "gone-1592@example.org", "ended")
    number = fb.opened("case-1592-default", S.Decider())
    taken = fb.forge.add_comment(number, user=f"p-{wanted}", body="expected")
    fb.forge.add_comment(number, user=f"p-{gone}", body="approved, add it")

    decider = S.Decider()
    assert S.feedback_drain(fb.t, fb.paths, decide=decider) == 0
    assert decider.decided == [taken["id"]]


def test_1592_eligibility_is_removed_from_the_product():
    """S3-5: no `MergeEligibility`, `merge_eligibility`, `eligible_to_merge`, `ELIGIBILITY_REFRESH` or
    `eligibility_max_age` remains; `listed_logins` and `_team_id` stay."""
    tenancy = importlib.import_module("defender.tenancy")
    directory = importlib.import_module("defender.tenancy._directory")
    eligibility = importlib.import_module("defender.lifecycle._eligibility")
    service = importlib.import_module("defender.lifecycle._service")
    drains = importlib.import_module("defender.learning.core.drains")
    feedback = importlib.import_module("defender.learning.core.feedback")

    assert not hasattr(tenancy, "MergeEligibility")
    assert not hasattr(directory.TenantDirectory, "merge_eligibility")
    assert not hasattr(eligibility, "eligible_to_merge")
    assert not hasattr(service, "ELIGIBILITY_REFRESH")
    assert "eligibility_max_age" not in inspect.signature(drains.feedback_drain).parameters
    assert "eligibility_max_age" not in inspect.signature(feedback.run).parameters
    assert "people" in inspect.signature(drains.feedback_drain).parameters
    assert "people" in inspect.signature(feedback.run).parameters
    from defender.tenancy.memory import InMemoryTenantRepository
    from defender.tenancy.postgres import PostgresTenantRepository

    for repository in (InMemoryTenantRepository, PostgresTenantRepository):
        assert not hasattr(repository, "merge_eligibility")
        assert not hasattr(repository, "record_merge_eligibility")
    assert hasattr(eligibility, "listed_logins")
    assert hasattr(eligibility, "_team_id")
    assert not hasattr(feedback, "ELIGIBILITY_MAX_AGE_ENV")
