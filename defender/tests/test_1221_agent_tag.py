"""#1221 O1 — every comment the host posts opens with the agent tag naming the authoring run.

The design (issue #1221, D1/M1): the write-back stays a plain comment, and the host marks it as
model-made by putting ONE plain-text line at the START of the body — a fixed prefix
(`case_ticket.AGENT_TAG_PREFIX`) plus the authoring run's id (`case_ticket.agent_comment_tag`).
It is added at the single POST every comment leaves through, never through the tenant's
`comment.body` template, so a tenant mapping cannot drop it and a future comment kind cannot
miss it. It names the RUN (`run_dir.name`), not the case key, which on the platform is the
vendor's ticket id. Its bytes come out of the body's wire bound, and it sits at the start
because a long reply reaches gather with each string leaf clipped to its first 600 characters
(`runtime/payload_view.py`): a trailing tag would be cut while the verdict above it survived.

Every test here drives the REAL writer (`ticket_writer.record_case_ticket`) through its one
seam, `TicketWriterDeps.request`, with a fake that CAPTURES the outbound payload, and asserts
on what the fake received. The two new names are reached through `require` at call time, so a
missing one is one red per test, never a collection error.
"""
from __future__ import annotations

import html
import json

import pytest

from defender.runtime import case_ticket
from defender.runtime.payload_view import LEAF_MAX_CHARS, PASSTHROUGH_MAX_BYTES_DEFAULT
from defender.tests._spec767 import (
    COMMENTS_SUFFIX,
    ELLIPSIS,
    HOST_CAUSE,
    TICKETS_PATH,
    WIRE_BOUND_BYTES,
    FakeStore,
    comment,
    listing,
    make_run,
    mapping_doc,
    record,
    rendered,
    require,
    shipped_mapping_doc,
    ticket,
    use_mapping,
)

#: Run ids in the shapes the product mints: a live run's `{UTC stamp}-{alert slug}`, and the
#: longest one, a branch run's `{source run}-n{N}-{label}` (runtime/branch/_family.py).
RUN_ID = "20261008T091500Z-5710-sshd-invalid-user"
BRANCH_RUN_ID = "20261008T091500Z-5710-sshd-invalid-user-n12-world-b-no-cmdb-owner"

NARRATIVE = "The account is a decommissioned service identity; no egress followed."

#: Every character a UI may break a line on (the writer's own `_LINE_BREAKS` set, plus `\n`).
_LINE_BREAKS = ("\n", "\r", " ", " ", "\x85", "\x0b", "\x0c")


def _prefix() -> str:
    return require(case_ticket, "AGENT_TAG_PREFIX",
                   "#1221 M1: the agent tag's fixed prefix, defined once as a constant")


def _tag(run_id: str) -> str:
    fn = require(case_ticket, "agent_comment_tag",
                 "#1221 M1: the one line every posted comment opens with, naming the run")
    return fn(run_id)


def _tag_and_rest(body: str) -> tuple[str, str]:
    first, newline, rest = body.partition("\n")
    assert newline, f"the posted body is one line — no comment follows a tag: {body[:160]!r}"
    return first, rest


def _comment_post(store: FakeStore) -> tuple[str, str]:
    """(the path the one comment went to, its body as posted)."""
    posts = [c for c in store.calls if c.method == "POST" and c.path.endswith(COMMENTS_SUFFIX)]
    assert len(posts) == 1, f"expected one comment POST, saw {[(c.method, c.path) for c in store.calls]}"
    return posts[0].path, store.wire_body()


# =======================================================================================
# The tag itself
# =======================================================================================


def test_1221_the_tag_is_one_plain_line_naming_the_run():
    """The tag is one plain-text line: the fixed prefix, then the run id verbatim. It carries
    no line break of any kind, and it reads the same after the two encodings it meets on its
    way to a model or a person: JSON escaping (gather is served every reply as escaped JSON,
    and the teaching quotes the prefix, so an escaped tag would not match the words the model
    was taught) and HTML escaping (a vendor's ticket UI). It carries none of the markdown
    characters that would restyle it, and it is short — under 200 characters even for the
    longest run id the product mints — so it sits well inside the 600-character leaf clip."""
    prefix = _prefix()
    assert isinstance(prefix, str), f"the tag prefix is not a string: {prefix!r}"
    assert prefix.strip(), f"the tag prefix is blank: {prefix!r}"
    for brk in _LINE_BREAKS:
        assert brk not in prefix, f"the tag prefix carries a line break ({brk!r})"

    for run_id in (RUN_ID, BRANCH_RUN_ID):
        tag = _tag(run_id)
        assert tag.startswith(prefix), f"the tag does not open with the prefix: {tag!r}"
        assert run_id in tag, f"the tag does not carry the run id verbatim: {tag!r}"
        for brk in _LINE_BREAKS:
            assert brk not in tag, f"the tag for {run_id} carries a line break ({brk!r})"
        assert json.dumps(tag)[1:-1] == tag, (
            f"JSON escaping changes the tag ({json.dumps(tag)}), so the model never reads the "
            "words it was taught"
        )
        assert html.escape(tag, quote=False) == tag, f"the tag carries HTML markup: {tag!r}"
        for mark in ("`", "*"):
            assert mark not in tag, f"the tag carries the markdown character {mark!r}: {tag!r}"
        assert not tag.startswith(("#", ">", "-", "+")), (
            f"the tag opens like a markdown heading, quote or list item: {tag!r}"
        )
        assert len(tag) < 200, f"the tag is {len(tag)} characters — the leaf clip is 600"

    assert _tag(RUN_ID) != _tag(BRANCH_RUN_ID), "two runs' tags are the same line"


# =======================================================================================
# Every comment the host posts
# =======================================================================================


@pytest.mark.parametrize(
    ("arm", "report_kw", "record_kw", "expected_rest"),
    [
        ("the record", {"body": NARRATIVE}, {},
         f"benign — {HOST_CAUSE}\n\n{NARRATIVE}"),
        ("the unreadable report", {"text": ""}, {},
         case_ticket.UNREADABLE_COMMENT_BODY),
        ("the escalation note (aborted)", {"body": NARRATIVE}, {"truncated_by": "aborted"},
         case_ticket.ESCALATION_COMMENT_BODY.format(exit="aborted")),
        ("the escalation note (a forced close that left no report)", {"text": ""},
         {"truncated_by": "request-limit"},
         case_ticket.ESCALATION_COMMENT_BODY.format(exit="request-limit")),
    ],
)
def test_1221_every_posted_comment_opens_with_the_tag(
        tmp_path, arm, report_kw, record_kw, expected_rest):
    """Every comment kind the host posts — the record, the unreadable-report sentence, and
    the escalation note on both of its paths — reaches the store with the agent tag naming
    the run as its FIRST line, and the comment the tenant's mapping renders on the next line,
    unchanged. The tenant is the committed fixture, whose `comment.body` is
    `{disposition} — {cause}\\n\\n{narrative}`; the expected remainder is spelled here, never
    read back from the renderer under test. The positive control is that remainder: the tag
    is ADDED, nothing it displaces."""
    assert shipped_mapping_doc()["comment"]["body"] == "{disposition} — {cause}\n\n{narrative}", (
        "the fixture tenant's comment template moved; re-spell the expected record body"
    )
    run_dir = make_run(tmp_path, name=RUN_ID, **report_kw)
    store = FakeStore()
    record(run_dir, store, **record_kw)

    path, body = _comment_post(store)
    assert path == f"{TICKETS_PATH}/{RUN_ID}{COMMENTS_SUFFIX}", f"{arm}: posted to {path}"
    first, rest = _tag_and_rest(body)
    assert first == _tag(RUN_ID), f"{arm}: the body's first line is {first!r}, not the agent tag"
    assert rest == expected_rest, f"{arm}: the comment below the tag is {rest!r}"


def test_1221_the_tag_names_the_run_not_the_case_key(tmp_path, monkeypatch):
    """The tag names the run (`run_dir.name`) even when the case is written under another key —
    on the platform the case key is the vendor's ticket id — and it reaches the wire even when
    the tenant's `comment.body` template has no placeholder for either id: the tag never goes
    through the template, so a mapping cannot drop it.

    The complementary control: a template that DOES render `{case_id}` renders the KEY there,
    while the tag line still names the run."""
    key = "SOC-VENDOR-4242"
    run_dir = make_run(tmp_path, name=RUN_ID, body=NARRATIVE)
    assert _tag(RUN_ID) != _tag(key), "the control is vacuous: the two ids tag alike"

    use_mapping(monkeypatch, tmp_path / "dfn",
                mapping_doc(comment_body="{disposition}"))
    bare = FakeStore()
    record(run_dir, bare, key=key)
    path, body = _comment_post(bare)
    assert path == f"{TICKETS_PATH}/{key}{COMMENTS_SUFFIX}", f"posted to {path}, not the case key"
    first, rest = _tag_and_rest(body)
    assert first == _tag(RUN_ID), (
        f"the first line {first!r} is not the tag naming the RUN — the case key was {key}"
    )
    assert rest == "benign", f"the template's own rendering changed: {rest!r}"
    assert RUN_ID not in rest, "the run id leaked into the template's rendering"

    use_mapping(monkeypatch, tmp_path / "dfn",
                mapping_doc(comment_body="[{case_id}] {disposition}"))
    named = FakeStore()
    record(run_dir, named, key=key)
    first, rest = _tag_and_rest(_comment_post(named)[1])
    assert first == _tag(RUN_ID)
    assert rest == f"[{key}] benign", f"the template's `{{case_id}}` rendered {rest!r}"


# =======================================================================================
# The bound, and the model-facing clip
# =======================================================================================


@pytest.mark.parametrize("run_id", [RUN_ID, BRANCH_RUN_ID])
@pytest.mark.parametrize("filler", ["x", "é", "🜁"])
def test_1221_the_tag_survives_the_wire_bound(tmp_path, run_id, filler):
    """With a narrative far past the bound, the whole posted body — tag line included — is at
    most `WIRE_BOUND_BYTES` UTF-8 bytes, the tag line is intact at its start, and the cut is
    the narrative's (the body still ends in the one visible `…`). The tag's bytes come out of
    the bound, never on top of it, for the longest run id too.

    The complementary control: a narrative well under the bound crosses whole, with no `…`."""
    run_dir = make_run(tmp_path, name=run_id, body=filler * 20000)
    store = FakeStore()
    record(run_dir, store)
    body = store.wire_body()

    size = len(body.encode("utf-8"))
    assert size <= WIRE_BOUND_BYTES, f"{size} bytes crossed, over the {WIRE_BOUND_BYTES} bound"
    first, rest = _tag_and_rest(body)
    assert first == _tag(run_id), f"the bound cut into the tag line: {first[:120]!r}"
    assert rest.startswith(f"benign — {HOST_CAUSE}\n\n"), "the disposition line was lost"
    assert body.endswith(ELLIPSIS), "the cut is not visibly marked"
    assert body.count(ELLIPSIS) == 1, f"{body.count(ELLIPSIS)} ellipses, not one"
    assert size > WIRE_BOUND_BYTES - 8, (
        f"only {size} bytes crossed — the tag was reserved as more than its own bytes"
    )

    small_dir = make_run(tmp_path / "small", name=run_id, body=NARRATIVE)
    small = FakeStore()
    record(small_dir, small)
    first, rest = _tag_and_rest(small.wire_body())
    assert first == _tag(run_id)
    assert rest == f"benign — {HOST_CAUSE}\n\n{NARRATIVE}", "a short comment was cut anyway"


def test_1221_the_tag_survives_the_listing_view_clip(tmp_path):
    """scale_model_view_stays_bounded, and the tag inside it. A ticket listing reaches gather
    through `payload_view.render`: verbatim below `PASSTHROUGH_MAX_BYTES_DEFAULT` (8192 bytes),
    and above it reduced, with every string leaf clipped to its first `LEAF_MAX_CHARS` (600)
    characters or fewer and the reduction marked.

    The comments here are the writer's own maximal bodies, each opening with its tag, over a
    narrative of distinct words so what a view kept can be told apart. One such case still
    renders verbatim, its last surviving word included; two do not, and in the reduced view
    each comment still opens with its tag line and its first words while its last surviving
    word is gone — the clip is real, so the tag's survival is not a view that kept
    everything."""
    narrative = " ".join(f"word{i:05d}" for i in range(4000))
    bodies, last_words = {}, {}
    for run_id in (RUN_ID, BRANCH_RUN_ID):
        run_dir = make_run(tmp_path / run_id[-6:], name=run_id, body=narrative)
        store = FakeStore()
        record(run_dir, store)
        bodies[run_id] = store.wire_body()
        assert bodies[run_id][:LEAF_MAX_CHARS].startswith(_tag(run_id) + "\n"), (
            "the tag line is not inside the first LEAF_MAX_CHARS characters of the body"
        )
        # The last whole word the wire bound let through (the one before it may be cut).
        last_words[run_id] = bodies[run_id].rstrip(ELLIPSIS).split()[-2]

    def case(key: str, run_id: str) -> dict:
        return ticket(key, status="open", labels=["sig:5710"],
                      comments=[comment(bodies[run_id])])

    one = listing(case("SOC-1", RUN_ID))
    assert len(json.dumps(one)) < PASSTHROUGH_MAX_BYTES_DEFAULT
    assert rendered(one, tmp_path) == json.dumps(one), (
        "a single case carrying a maximal comment no longer renders verbatim"
    )
    assert last_words[RUN_ID] in rendered(one, tmp_path)

    two = listing(case("SOC-1", RUN_ID), case("SOC-2", BRANCH_RUN_ID))
    assert len(json.dumps(two)) > PASSTHROUGH_MAX_BYTES_DEFAULT
    view = rendered(two, tmp_path)
    assert view != json.dumps(two), (
        "two maximal comments rendered verbatim — the ceiling moved, which widens every "
        "other gather payload in the system"
    )
    assert "<<ELIDED" in view, "the view grew past the ceiling without marking a reduction"
    assert "word00000" in view, "the view dropped the comments outright instead of clipping them"
    for run_id in (RUN_ID, BRANCH_RUN_ID):
        assert last_words[run_id] not in view, (
            "the control failed: the view kept the end of the comment, so nothing was clipped"
        )
        assert json.dumps(_tag(run_id) + "\n")[1:-1] in view, (
            f"the tag line naming {run_id} did not survive the leaf clip into gather's view"
        )
