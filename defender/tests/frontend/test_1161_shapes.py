# ruff: noqa: PT018 — each compound assert states one fact about one value
"""#1161 B3 machinery self-test: the shape classifier and the generated set, with no code under test."""
from __future__ import annotations

import re

import pytest

from defender.tests.support.frontend import _shapes1161 as S

HEX = set("0123456789abcdef")


def _investigation_by_hand(value: str) -> bool:
    """A segment-by-segment check with no regular expression (an oracle independent of the classifier)."""
    parts = value.split("/")
    if len(parts) != 5 or parts[0] != "" or parts[1] != "t" or parts[3] != "investigations":
        return False

    def uuid(text: str) -> bool:
        groups = text.split("-")
        return [len(g) for g in groups] == [8, 4, 4, 4, 12] and all(c in HEX for g in groups for c in g)

    return uuid(parts[2]) and uuid(parts[4])


@pytest.mark.parametrize("shape", S.SHAPES, ids=lambda s: s.name)
def test_every_generated_member_classifies_to_its_shape(shape):
    """Members of a shape are that shape's, and no other's (B3 members)."""
    values = S.members(shape, seed=7, count=20)
    assert {S.classify(v) for v in values} == {shape.name}
    assert S.members(shape, 7, 20) == values, "seeded: the same seed gives the same members"
    assert (S.members(shape, 8, 20) != values) == ("{uuid}" in shape.template)


def test_the_classifier_is_exact_ascii_case_sensitive_with_no_tolerance():
    """Whole-string, case-sensitive, no trailing-slash or newline tolerance (S2)."""
    [m] = S.members(S.SHAPES[1], 1, 1)
    assert S.classify(m) == "investigation"
    for bad in (m + "/", m + "\n", m.upper(), "/" + m, m.replace("/t/", "/T/"), "", "//", "/sign-in-failed/",
                "/Sign-in-failed", "/sign-in-failed\n", "\uff0f"):
        assert S.classify(bad) is None, bad
    assert S.classify("/sign-in-failed") == "sign-in-failed" and S.classify("/") == "root"
    assert {"root", "investigation"} == S.RETURNABLE


def test_the_near_misses_cover_every_edit_kind_and_leave_the_member_out():
    """Insert, replace, delete, case flip, doubled and appended `/` all occur (B3 near misses)."""
    [m] = S.members(S.SHAPES[1], 1, 1)
    misses = list(S.near_misses(m))
    assert len(misses) == len(set(misses)) and m not in misses
    have = set(misses)
    assert m[:5] + "\x00" + m[5:] in have and m[:5] + "\x7f" + m[5:] in have  # insert, both ASCII ends
    assert m[:3] + "\uff0f" + m[4:] in have  # replace `/` by fullwidth
    assert m[:-1] in have and m[1:] in have  # delete
    assert m.replace("/t/", "/T/") in have  # case flip
    assert m.replace("/t/", "//t/", 1) in have and m + "/" in have  # doubled, appended
    assert any("\u017f" in x for x in misses) and any("\u0663" in x for x in misses)
    assert len(misses) > 10_000


def test_the_classifier_agrees_with_an_independent_check_on_every_near_miss():
    """Each near miss is a member exactly when a regex-free check says so: no near miss is taken for its member
    wrongly, and the hex-for-hex replacements, which are members, are named as such (never "near miss = refused")."""
    for shape in S.SHAPES:
        for m in S.members(shape, 3, 2):
            members_found = 0
            for miss in S.near_misses(m):
                got = S.classify(miss)
                if shape.name == "investigation":
                    assert (got == "investigation") == _investigation_by_hand(miss), miss
                else:
                    assert got is None, (m, miss, got)  # no other shape has a neighbour that is a member
                members_found += got is not None
            assert (members_found == 64 * 15) if shape.name == "investigation" else members_found == 0


def test_the_generated_set_holds_members_misses_and_their_classifier_answers():
    """One set for all three checks: members of every shape, misses with their origin, deduplicated (B3)."""
    cases = S.generated_set(seed=5, per_shape=1)
    assert len({c.value for c in cases}) == len(cases)
    assert {c.shape for c in cases if c.origin is None} == {s.name for s in S.SHAPES}
    assert all(S.classify(c.value) == c.shape for c in cases)
    assert any(c.shape == "investigation" and c.origin for c in cases), "hex-for-hex misses are members"
    picked = S.sample(cases, 1, 40)
    assert len(picked) == 40 and {c.shape for c in picked} >= {"root", "investigation", "sign-in-failed", None}
    assert S.sample(cases, 1, 40) == picked


def test_the_uuid_grammar_is_written_as_the_dialect_allows():
    """ASCII classes and counted repetition only: no `\\d`, `\\w`, `.`, anchor or flag (S2)."""
    assert not re.search(r"\\[dws]|\.|\^|\$|\(\?", S.UUID)


def test_the_browser_sample_takes_one_near_miss_for_each_special_character():
    """The seeded sample picks one fitting near miss per special, `/` by a doubled one, and is repeatable (B3)."""
    cases = [c for c in S.generated_set() if c.value.startswith("/")]
    picked = S.sample(cases, 1161, 30)
    picks = S.special_picks(cases, 1161, picked)
    assert len(picks) == len(S.SPECIALS) == 8
    assert all(S.has_special(c, special) for c, special in zip(picks, S.SPECIALS, strict=True))
    assert len({c.value for c in picks}) == 8 and not set(picks) & set(picked)
    assert S.special_picks(cases, 1161, picked) == picks
