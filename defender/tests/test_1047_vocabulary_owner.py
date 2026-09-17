"""#1047 — the vocabulary owner: ONE answer to what a `truncated_by` value means.

Before this piece `session_store` defined `TRUNCATED_BY_VALUES` and nothing owned MEMBERSHIP
in it: every reader that wants to know whether a value is an exit class wrote its own test.
This piece adds two readers at once (the judge's reader, the ticket lane), so the design gives
the vocabulary an owner before it gives it consumers — `normalized_truncated_by(value)`, the
`_vocab.normalized_disposition` shape, in the module that defines the words. That module is
now `runtime/run_end.py` — the vocabulary moved there WITH its normalizer so that readers
which are not store readers need not import the store — and `session_store` re-exports both,
which is the spelling these tests keep using.

Claim h11: `lint_borrowed_vocabulary` arms only when the DEFINING module has a membership
function, and the vocabulary had none before — so the owner function is also what makes that
gate bite on the two new consumers.

FORK F-M IS RESOLVED STRICT (§7 round 2, auto): whitespace padding, case variants and Unicode
confusables all return `None`. This is a DELIBERATE divergence from `normalized_disposition`,
which strips whitespace before its exact test — under the resolved F2/F3 mechanism the value's
only producer is the driver's own stamp, constrained to `TRUNCATED_BY_VALUES` at every site, so
no legitimate source of a variant spelling exists; leniency would buy nothing and cost a
coercion path a future less-careful producer could lean on. Settled premises 79/80 already
establish that no box-writable content reaches this function, so this is a host-to-host
contract choice, not a security surface.

RED against `59bdea44`: `session_store.normalized_truncated_by` does not exist.
"""
from __future__ import annotations

import json

from defender.tests import _spec1047 as S


def _owner():
    """The owner function, imported at CALL time — `AttributeError` here is a real red."""
    return S.sym("runtime.session_store", "normalized_truncated_by")


# ---------------------------------------------------------------------------------------
# the seam itself
# ---------------------------------------------------------------------------------------


def test_session_store_owns_what_a_truncated_by_value_means():
    """`session_store.normalized_truncated_by(value)` returns the member for every
    TRUNCATED_BY_VALUES spelling and None for everything else — a non-str, an empty string, a
    near-miss — never coercing a value into the member it resembles, the rule
    `_vocab.normalized_disposition` states for its own vocabulary.

    The positive half is driven over the WHOLE vocabulary read off `TRUNCATED_BY_VALUES`
    itself, not a list spelled here: a suite carrying its own copy of the words would stay
    green the day a member is added and the owner is not taught about it."""
    normalized = _owner()
    members = S.vocabulary()
    assert members, "TRUNCATED_BY_VALUES is empty; the vocabulary has no members to own"
    for member in members:
        assert normalized(member) == member, (
            f"{member!r} is a declared member of TRUNCATED_BY_VALUES and the owner refused it")
    for outside in (None, "", "request_limit", "REQUEST-LIMIT", 7, ["aborted"]):
        assert normalized(outside) is None, (
            f"{outside!r} is not a member and the owner answered something other than None")


def test_normalized_truncated_by_is_strict_about_whitespace_case_and_confusables():
    """The owner is STRICT (fork F-M, §7 round 2): a whitespace-padded member, a case variant
    and a Unicode confusable each return None rather than being folded onto the member they
    resemble.

    The Cyrillic arm is the security-relevant one — `аborted` with U+0430 renders identically
    to `aborted` to a person — and the answer must be the same as for a value that was never a
    member at all. Positive control on the same call: the unpadded, exactly-spelled member
    still resolves, so the refusals below are about the SPELLING and not about the owner
    refusing everything."""
    normalized = _owner()
    assert normalized("aborted") == "aborted", (
        "the control failed: the owner refused an exactly-spelled member, so the refusals "
        "below would not be about how the near-misses are spelled")
    for spelling, why in (
        (" request-limit ", "whitespace-padded"),
        ("\trequest-limit\n", "whitespace-padded with tabs and newlines"),
        ("REQUEST-LIMIT", "a case variant"),
        ("Request-Limit", "a title-case variant"),
        ("аborted", "a Cyrillic-а confusable"),
        ("aborted​", "a zero-width space inside a member"),
    ):
        assert normalized(spelling) is None, (
            f"{spelling!r} ({why}) was coerced into the member it resembles; on READ there is "
            "no author left to ask, so a value that only becomes a member after something "
            "strips or folds it must be answered exactly as one that never was")


def test_normalized_truncated_by_given_a_future_vocabulary_member():
    """A plausible FUTURE member the vocabulary does not carry today — `context-limit` — is
    refused, not admitted on resemblance (fork F-Y, §7 round 2, convergent on the demand's own
    pinned language).

    The domain is the CURRENT `TRUNCATED_BY_VALUES` and nothing else. A reader that admitted a
    word merely because it is shaped like an exit class would silently start filing cut-short
    rows the day any producer invented one."""
    normalized = _owner()
    assert "context-limit" not in S.vocabulary(), (
        "the control failed: `context-limit` is now a real member, so this test no longer "
        "pins a FUTURE spelling — pick one the vocabulary still does not carry")
    assert normalized("context-limit") is None


# ---------------------------------------------------------------------------------------
# the owner's input domain, one settled premise per value
# ---------------------------------------------------------------------------------------


def test_normalized_truncated_by_given_a_non_string_int():
    """An int handed to the owner returns None — the demand seed's own `non-str` branch."""
    assert _owner()(7) is None
    assert _owner()(0) is None


def test_normalized_truncated_by_given_a_bool():
    """True and False both return None; bool/int kinship buys no exception from the owner's
    membership rule."""
    for value in (True, False):
        assert _owner()(value) is None, (
            f"{value!r} answered as a member; a bool is an int is not an exit class")


def test_normalized_truncated_by_given_none():
    """None returns None, and this is the LEGITIMATE case: "no exit class" is a real domain
    member meaning the run was not cut short, not a rejection.

    It is also why every consumer branches on `is None` rather than on falsiness — the empty
    string answers None too, and the two must not be told apart by their answer alone."""
    assert _owner()(None) is None


def test_normalized_truncated_by_given_the_empty_string():
    """The empty string returns None — named explicitly in the owner demand's seed, and the
    falsy member of the owner's own input domain."""
    assert _owner()("") is None


def test_normalized_truncated_by_given_an_underscore_near_miss():
    """`request_limit` returns None — the seed's own worked example of a near-miss that is
    never coerced into the member it resembles."""
    assert _owner()("request_limit") is None
    assert _owner()("retry_exhausted") is None


def test_normalized_truncated_by_given_a_non_scalar_container():
    """A list, a dict and bytes each return None.

    Rejected BEFORE the membership test rather than fed to it: a `set` membership test on an
    unhashable value raises `TypeError` out of whatever gate asked, which is the failure mode
    `normalized_disposition`'s own non-str guard exists for."""
    for value in (["aborted"], {"truncated_by": "aborted"}, b"aborted", ("aborted",)):
        assert _owner()(value) is None, f"{value!r} answered as a member"


def test_normalized_truncated_by_given_a_value_torn_by_a_partial_write():
    """A fragment left by a partial write returns None — a torn value is a near-miss, never
    coerced.

    The fragments are taken from the real members: a prefix, a suffix and a value with its
    separator lost are what a truncated write actually leaves behind, and each of them is
    closer to a member than any random string, which is exactly why the owner must refuse
    them."""
    for torn in ("request-", "-limit", "requestlimit", "retry-exhaust"):
        assert _owner()(torn) is None, f"the torn value {torn!r} was completed into a member"


def test_normalized_truncated_by_given_an_older_vocabulary_spelling():
    """A retired spelling returns None: the domain is the CURRENT TRUNCATED_BY_VALUES, with no
    backward-compatibility carve-out.

    `request_limit` (underscored) and `usage-limit` are the two shapes an older writer would
    plausibly have used for the member now spelled `request-limit`; neither is admitted, so a
    record written by a version that predates the vocabulary reads as "not cut short" rather
    than as a member nothing in this tree produces."""
    for retired in ("usage-limit", "usage_limit", "truncated", "limit"):
        assert _owner()(retired) is None, (
            f"{retired!r} was admitted; a retired spelling must answer the same as any other "
            "non-member so no reader silently keeps a vocabulary this tree no longer writes")


# ---------------------------------------------------------------------------------------
# coherence — the three interpretation sites give one answer
# ---------------------------------------------------------------------------------------


def _three_sites(tmp_path, value):
    """Drive the exit value through the archive and both interpretation sites and return what
    each made of it: the archive's copied record, the judge's read, and the ticket lane's calls.

    ONE spelling, three frames, driven end to end rather than compared symbolically — a
    coherence demand bound at the owner's own altitude is green when one of two readers
    moved, which is the bug (schema.md's rule for `kind: coherence`). The archive is NOT an
    interpretation site: it copies the sidecar's bytes exactly as it copies the scrub
    verdict's, and what is returned for it is the copy, asserted VERBATIM — an archive that
    rewrote the value would be a third interpreter, the shape #785 was."""
    base, _src = S.runs_base(tmp_path)
    ep = S.episode(tmp_path)
    run_dir = S.sibling_run_dir(base, "b")
    S.plant_sidecar(run_dir, truncated_by=value)
    S.mod("learning.branch.archive").archive_episode(ep, {"b": run_dir})
    archived = json.loads((ep / "worlds" / "b" / S.run_end_name()).read_text(encoding="utf-8"))

    graded_ep = S.cut_short_episode(tmp_path / "graded")
    S.plant_archived_record(graded_ep, "b", raw=json.dumps(S.record_doc(value)))
    row = S.graded(graded_ep)["b"]

    ticket_run = S.closed_run_dir(tmp_path / "ticket")
    fake = S.close_ticket(ticket_run, truncated_by=value)
    return archived, row, fake


def test_every_reader_of_the_exit_class_takes_the_owners_answer(tmp_path):
    """The archive writer, the judge's reader and the ticket lane give one answer to what an
    exit value means: a value the owner refuses is refused identically at all three, and none
    of them carries its own membership test.

    Driven per reader EDGE rather than at the owner's altitude, on one spelling the owner
    refuses (`REQUEST-LIMIT`, fork F-M's case variant) and one it accepts (`request-limit`):
    the refused spelling produces a null archived record, a world that grades as today and a
    report-driven ticket close; the accepted one produces a recorded exit class, the third row
    shape and the ticket lane's own per-class arm.

    THE FOURTH READER IS DELIBERATELY DIFFERENT AND THAT IS RECORDED, NOT REPAIRED (fork F-E,
    §7 round 2): `run_common.learning_refusal_gate` refuses on ANY non-None value with no
    vocabulary test of its own, because "can this feed training data" and "how should the
    ticket close" are different questions with different acceptable risk postures. It is bound
    here so this coherence demand cannot ship green while missing a real reader."""
    refused_archived, refused_row, refused_ticket = _three_sites(tmp_path / "no", "REQUEST-LIMIT")
    assert refused_archived["truncated_by"] == "REQUEST-LIMIT", (
        "the archive rewrote the sidecar's value instead of copying it — a third interpreter")
    assert refused_row.get("cut_short") is None, "the judge read a value the owner refuses"
    assert len(refused_ticket.transitions) == 1, (
        "a value the owner refuses did not take the report-driven fallback at the ticket lane")

    ok_archived, ok_row, ok_ticket = _three_sites(tmp_path / "yes", "request-limit")
    assert ok_archived["truncated_by"] == "request-limit", (
        "the control failed: the archive did not carry a real member through")
    assert ok_row.get("cut_short") == "request-limit"
    assert len(ok_ticket.transitions) == 1, "the request-limit arm made no transition at all"

    gate = S.mod("run_common").learning_refusal_gate
    assert gate(tmp_path, tmp_path / "alert.json", truncated_by="REQUEST-LIMIT") is not None, (
        "the corpus-refusal gate stopped refusing an unrecognized exit class; F-E's recorded "
        "divergence between the two lanes is intentional and this is its pin")


def test_the_recorded_exit_value_is_a_spelling_that_only_the_owner_resolves(tmp_path):
    """A recorded value whose meaning only the owner can settle is answered identically by
    both consumers, through the owner — which is what `one_interpreter_for_the_exit_class`
    asserts, driven on a single spelling.

    ` aborted ` is the spelling: a person reading the record sees `aborted`, and only the
    owner's membership rule (fork F-M, strict) says whether that is one. Both consumers must
    say "not an exit class" together — a lane that stripped it would leave a ticket open and
    a world ungradable on a value its sibling read as absent. The archive carries the spelling
    through untouched, so the judge meets exactly what the host wrote."""
    archived, row, ticket = _three_sites(tmp_path, " aborted ")
    assert archived["truncated_by"] == " aborted ", "the archive rewrote the sidecar's value"
    assert row.get("cut_short") is None
    assert row.get("ungradable") is not True, (
        "a padded spelling only the owner can settle made a world ungradable at the judge "
        "while the archive and the ticket lane read it as absent")
    assert ticket.notes == [], "the padded spelling reached the aborted arm's escalation note"
    assert len(ticket.transitions) == 1, "the padded spelling did not take the report fallback"


def test_the_exit_value_is_not_a_string_at_all_at_each_of_the_three_interpretation_sites(
        tmp_path):
    """A non-string exit value answers "no exit class" consistently at both interpretation
    sites — the joint coherence property no single demand tests.

    Each site meets it on its own channel: the archived record the judge reads carries `7`
    (copied verbatim from the sidecar), and the ticket lane is handed `7` as its in-process
    parameter. Neither may raise, and neither may treat it as a member."""
    archived, row, ticket = _three_sites(tmp_path, 7)
    assert archived["truncated_by"] == 7, "the archive rewrote the sidecar's value"
    assert row.get("cut_short") is None, "the judge read a non-string as an exit class"
    assert row.get("ungradable") is not True, "a non-string made a world ungradable"
    assert len(ticket.transitions) == 1, (
        "a non-string exit value did not take the ticket lane's report-driven fallback")
    assert ticket.notes == [], "a non-string exit value reached the escalation-note arm"
