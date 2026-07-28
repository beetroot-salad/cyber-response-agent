"""#672 §E — the key boundary and the self-case exclusions (forks A, C, G, H).

Split out of `test_closed_ticket_tool_672.py` by #720; that module holds the spec
narrative and the registration/seam demands, and `_closed_ticket_672.py` holds the
drive harness these tests share.
"""
from __future__ import annotations

import re

import pytest

pytest.importorskip("pydantic_ai")  # CI installs the runtime extra; skip otherwise

from defender.scripts.adapters import _stub_transport as transport  # noqa: E402
from defender.scripts.adapters.faults import ConfigFault, UpstreamFault  # noqa: E402
from defender.tests.e2e._replay_harness import DEFENDER, Turn, VerbRecorder  # noqa: E402
from defender.tests._closed_ticket_672 import (  # noqa: E402
    DATED,
    CASE,
    CLOSED_TKT,
    DONE,
    OTHER_KEY,
    SHIPPED_KEY_PATTERN,
    TOOL_GET,
    WRAP_RE,
    _case,
    _drive,
    _feedback,
    _get,
    _get_calls,
    _list,
    _list_calls,
    _store_calls,
    _ticket_registry,
    _tool_delta,
)

pytestmark = pytest.mark.e2e



@pytest.mark.parametrize(
    ("key", "reaches_store"),
    [
        ("", False),
        ("   ", False),
        ("../SOC-1", False),
        ("a/b", False),
        ("SOC-1?x=1", False),
        ("%2e%2e%2f", False),
        ("SOC-1#frag", False),
        ("a&b", False),
        ("k=v", False),
        ("SOC-`id`", False),
        ("SOC 1", False),
        ("SOC-1\r\nHost: evil.internal", False),
        ("SOC-1\n", False),
        ("\tSOC-1", False),
        ("SOC-1\x01", False),
        ("SOC-1\x00", False),
        ("SOC-λ42", False),
        (42, False),
        ("SOC-1042", True),
        ("20260719T2300Z-sshd-999", True),
        ("S" + "0" * 600, True),
    ],
    ids=["empty", "whitespace-only", "dotdot-segment", "path-separator", "query-delimiter",
         "percent-encoded", "fragment", "ampersand", "equals", "backtick", "internal-space",
         "crlf-request-reshape", "trailing-newline", "leading-tab", "control-byte", "nul",
         "non-ascii", "wrong-json-type", "well-formed", "minted-case-id-shape",
         "long-but-well-formed"],
)
def test_malformed_key_model_retry(tmp_path, key, reaches_store):
    """[d10_model_retry_malformed] The key meets Fork A's DEFINED schema before any store
    attempt — a GRAMMAR (`_KEY_RE`), not a metacharacter blacklist: anything outside
    the declared grammar draws a retry-class response with ZERO store attempts. The
    wrong-JSON-type key (the §7 silent branch) pins the same model-visible observable
    LAYER-AGNOSTICALLY — a retry-class response and zero store attempts, whether the
    framework's schema validation or the tool body rejects; the test must not assert which
    layer. What still flows OPAQUELY: a well-formed key stands alone (no prior list call —
    get has no ordering dependency), the real minted case-id shape
    (`{%Y%m%dT%H%M%SZ}-{alert_label}`, run_common.py:98) reads through, and length is an
    explicit NON-clause. A store refusal of a schema-clearing key folds into the O4 fault
    path, not this boundary.

    TIGHTENED at #684 (F1). The old set sampled `/ .. path-sep ? % non-str` only, so a
    blacklist trimmed to exactly those stayed green while `SOC-1#frag`, `a&b`, `k=v`,
    backtick and an internal space reached the store — and, sharpest, the set omitted
    whitespace and CR/LF entirely: `"SOC-1\\r\\nHost: …"` cleared the old screen, the
    canonical way to reshape a request and drop the hard-coded `require_closed`. Every
    such row is now pinned per-character.

    #684 also REVERSES #672's `non-ascii-clean` row (`SOC-λ42` used to reach the store).
    The grammar is anchored on the shape keys are actually MINTED in, and the reversal is
    free of cost: the ticket WRITER percent-encodes every key it mints
    (ticket_writer.py:189) while this reader does not, so a non-ASCII key is unfetchable
    through this path regardless — rejecting it forfeits no readable ticket. Recorded as a
    decision reversal, not a mechanical tighten (the graph's d10 note carries it)."""
    rec = VerbRecorder()
    run = _drive(tmp_path, [Turn(tool_calls=[(TOOL_GET, {"key": key})]), DONE],
                 registry=_ticket_registry(rec))
    assert run.out.strip(), "the run must continue past the boundary either way"
    if reaches_store:
        (g,) = _get_calls(rec)
        assert g.params["key"] == key            # verbatim, opaque
        assert g.params["require_closed"] is True
    else:
        assert not _store_calls(rec), (
            f"key {key!r} reached the store — the schema must reject first"
        )
        # Fork A's OTHER half (cold C4 — previously asserted nowhere): the rejection is
        # RETRY-CLASS, layer-agnostic. The old `len(seen) >= 2` was true on every path
        # including success; bind the retry path itself: feedback for the rejected call
        # reached the model, it is NOT the O4 fault envelope (no exit-code result — an
        # implementation folding ill-formed keys into the fault path contradicts the
        # resolved wording), and it is not a bare empty tool return.
        assert len(run.script.seen) >= 2, "the model was never re-invoked after the rejection"
        feedback = _feedback(run)
        assert feedback.strip(), f"key {key!r}: the rejection produced no model-visible feedback"
        assert "exit=" not in feedback, (
            f"key {key!r} was rejected through the fault-envelope path — Fork A owes a "
            "retry-class response"
        )
        assert "TKT-CONTENT-777" not in run.all_text


@pytest.mark.parametrize(
    ("pattern", "key", "reaches_store"),
    [
        ("SOC-[0-9]+", "SOC-1042", True),
        ("SOC-[0-9]+", "20260719T2300Z-sshd-999", False),
        ("[A-Za-z0-9À-ɏ._-]+", "SOC-é42", True),
        (SHIPPED_KEY_PATTERN, "SOC-é42", False),
    ],
    ids=["narrow-accepts-its-own", "narrow-rejects-what-the-shipped-one-takes",
         "wide-accepts-accented", "shipped-rejects-accented"],
)
def test_key_grammar_comes_from_this_environments_config(tmp_path, pattern, key, reaches_store):
    """[d30_key_grammar_from_config] The key grammar is an ENVIRONMENT fact, read from the
    ticket system's own config (`TICKET_KEY_PATTERN`, a REQUIRED key of
    ticket_adapter.REQUIRED_CONFIG_KEYS) through the same `verbs=` registry seam the store is
    reached through — never a constant in the judge's code. What a ticket key looks like is
    the deployed store's statement to make: swapping this playground for a tracker with
    another key vocabulary is a config edit, not a code change.

    The rows drive the discrimination BOTH ways against the same tool build: a NARROWER
    configured pattern rejects a key the shipped one accepts (with zero store attempts), and
    a WIDER one lets through a key the shipped pattern rejects. An implementation that
    hardcodes any single grammar — including the one this repo ships — fails a row.

    That second direction is also where #672's "clean non-ASCII flows opaquely" decision
    went: #684 did not settle whether non-ASCII keys exist, it moved the question to whoever
    describes the environment. This store declares an ASCII grammar, so `SOC-é42` refuses
    here; a store that mints accented keys says so in its pattern and they read through."""
    rec = VerbRecorder()
    run = _drive(tmp_path, [Turn(tool_calls=[(TOOL_GET, {"key": key})]), DONE],
                 registry=_ticket_registry(rec, key_pattern=("return", pattern)))
    assert run.out.strip()
    if reaches_store:
        (g,) = _get_calls(rec)
        assert g.params["key"] == key
    else:
        assert not _store_calls(rec), (
            f"key {key!r} reached the store under the configured grammar {pattern!r}"
        )
        feedback = _feedback(run)
        assert "exit=" not in feedback, "an off-grammar key owes a retry-class response"
        assert pattern in feedback, (
            "the retry feedback must name the grammar the key was judged against — the model "
            "cannot correct a key against a rule it is never told"
        )


@pytest.mark.parametrize(
    "registry_kwargs",
    [
        {"key_pattern": ("raise", ConfigFault(
            "missing required config keys in ticket/config.env: TICKET_KEY_PATTERN"))},
        {"declare_key_pattern": False},
        {"key_pattern": ("return", "SOC-[0-9")},
        {"key_pattern": ("return", "SOC-[0-9]{99999999999}")},
        {"key_pattern": ("return", "")},
    ],
    ids=["config-key-absent", "verb-undeclared", "pattern-uncompilable",
         "pattern-overflows-the-compiler", "pattern-empty"],
)
def test_absent_key_grammar_fails_closed_and_loud(tmp_path, registry_kwargs):
    """[d30_key_grammar_from_config — the fail-closed half] A ticket store that declares no
    usable key grammar stops the read. There is no built-in fallback: the screen exists to
    keep a model-chosen key out of a store that cannot hold it, and screening against a
    grammar this environment never agreed to would be a guess standing in for the missing
    fact. So the tool fails CLOSED — zero store attempts, the key never sent — on every shape
    the missing fact can take: the config key absent (ConfigFault out of load_config), the
    adapter declaring no such verb at all, and a declared value that is empty or will not
    compile — including the two ways "will not compile" is NOT a `re.error`: a repeat count
    that overflows the compiler, and (its sibling) a pattern deep enough to recurse. That
    compile runs OUTSIDE `_run_verb`'s fault seam, so an uncaught one would unwind the judge
    stage and write no row at all, not fail closed.

    And LOUD, in all three channels the tool owns, because a silent refusal reads to the
    judge exactly like a store that has nothing to say: the model sees a FAILED result naming
    the missing grammar (never a success envelope, never an empty return), the capture row
    records it as infra, and it contributes to the `ticket` breaker — so a persistently
    misconfigured store trips the breaker instead of paying full price every judgment."""
    rec = VerbRecorder()
    run = _drive(tmp_path, [_get(OTHER_KEY), DONE],
                 registry=_ticket_registry(rec, **registry_kwargs))
    assert run.out.strip(), "the judge run continues to its verdict — no unwind"
    assert not _store_calls(rec), "the store was read with no grammar to screen the key by"
    assert "TKT-CONTENT-777" not in run.all_text

    feedback = _feedback(run)
    assert "exit=0" not in feedback, "a missing key grammar returned a SUCCESS envelope"
    assert "key grammar" in feedback, (
        "the refusal must say WHY on the model-visible channel — an unexplained failure is "
        "indistinguishable from a store with nothing to say"
    )
    (row,) = run.rows()
    assert row["exit_code"] == 2
    assert row["error_class"] == "infra"
    # The row names the verb that actually ran and FAILED. Filing it as a `get-ticket`
    # carrying the model's key would write a store attempt that never happened into the one
    # artifact that EVIDENCES "zero store attempts" — and would land an unscreened
    # model-chosen key in the queries table on the path whose point is that it sent none.
    assert row["verb"] == "key-pattern", (
        "the fail-closed row claims a store verb the tool never reached"
    )
    assert "key" not in row["params"], "the unscreened model key was filed as if it were sent"
    assert run.breaker().get("systems", {}).get("ticket", {}).get("failures") == 1, (
        "a store with no declared key grammar must contribute to the breaker like any other "
        "infra fault — otherwise a misconfigured store is retried at full price forever"
    )


def test_shipped_ticket_config_declares_the_key_grammar():
    """[d30_key_grammar_from_config — the currency half] The grammar every other test in this
    module drives is the one this repo actually ships: `TICKET_KEY_PATTERN` is present in the
    ticket system's config.env, it compiles, and it matches the two key shapes the store is
    known to hold — the minted case id (`{%Y%m%dT%H%M%SZ}-{alert_label}`, run_common.py:98,
    which ticket_writer mints every real ticket under) and the seeded `SOC-<n>`. Without this
    the suite could go green against a fake grammar while the deployed judge screens every
    legitimate key out — and the failure would look like 'the store confirmed nothing'.

    It also pins the REQUIRED-ness: the key is in ticket_adapter's own required set, so a
    config missing it is a ConfigFault (exit 2, infra) rather than a silent default."""
    from defender.scripts.adapters import ticket_adapter

    assert "KEY_PATTERN" in ticket_adapter.REQUIRED_CONFIG_KEYS, (
        "the key grammar must be REQUIRED config — an optional one resolves silently"
    )
    cfg = DEFENDER / "knowledge" / "environment" / "systems" / "ticket" / "config.env"
    # The REAL loader's parser, not a second copy of its grammar: a currency test that
    # re-derives the quoting/comment handling can pass against a value `load_config` would
    # read differently — this module's own lesson (#684/F1) one layer down.
    pattern = transport._parse_env_file(cfg).get("TICKET_KEY_PATTERN")
    assert pattern, f"{cfg} declares no TICKET_KEY_PATTERN — every ticket verb now faults"
    assert pattern == SHIPPED_KEY_PATTERN, (
        "the shipped grammar drifted from the one this suite drives its screens with"
    )
    grammar = re.compile(rf"\A(?:{pattern})\Z")
    assert grammar.match(CASE), "the shipped grammar rejects the minted case-id shape"
    assert grammar.match(OTHER_KEY), "the shipped grammar rejects the seeded SOC-<n> shape"


def test_case_own_key_refused_at_tool_boundary(tmp_path):
    """[d23_self_key_excluded] (Fork C, §7-minted; extended to BOTH tool paths at V-A) The
    case-under-judgment's OWN key — the leg's deps already identify it: the learning run
    dir's basename — is EXCLUDED at the get boundary with zero store attempts, even when
    that ticket is genuinely closed: the circular-confirmation path where a case confirms
    its own survived verdict is closed structurally, state-independent, not left to the
    status pin, which cannot express it. And the LIST path — Fork C's main use case, a
    precedent search that can return the case itself — filters the self-case's record by
    IDENTITY, per-item, before the envelope (V-A: without it a `list_closed_tickets`
    result delivers the protected asset the get screen refuses). Positive controls on the
    same addresses: any other well-formed closed key reads through the get edge in the
    same run, and the sibling closed item in the same listing is servable.

    Fixture rebuilt at the F round (cold C1): the old queue front-loaded a self-payload a
    conforming implementation never requests, so its positive control could never pass —
    the fake now serves its default closed record per call, so a conforming implementation
    PASSES and a non-screening one FAILS on the keys the store was asked for."""
    rec = VerbRecorder()
    self_listed = {**DATED, "key": CASE, "status": "closed", "summary": "TKT-SELF-LISTED"}
    other_ok = {**DATED, "key": "SOC-OK2", "status": "closed", "summary": "TKT-LIST-OK"}
    run = _drive(
        tmp_path,
        [_get(CASE), _get(OTHER_KEY), _list(q="precedent"), DONE],
        registry=_ticket_registry(
            rec, lst=[("return", {"tickets": [self_listed, other_ok], "total": 2})]),
    )
    assert run.out.strip()
    keys_asked = [c.params["key"] for c in _get_calls(rec)]
    assert CASE not in keys_asked, "the self-key reached the store — the exclusion is boundary-side"
    # Positive control on the same address, complementary condition:
    assert OTHER_KEY in keys_asked
    assert "TKT-CONTENT-777" in run.all_text
    # V-A: the list path filters the self record by IDENTITY (its status is genuinely
    # closed — only the key marks it), a self-key item handled the way a non-closed item
    # is (d24's resolved arm: drop or fault, never silent pass-through).
    assert "TKT-SELF-LISTED" not in run.all_text, (
        "a precedent search returned the case itself — the self-key screen has a list hole"
    )
    # #684 (F2): a CONJUNCTION on the list call's own appended result — the good sibling
    # is served in the SAME response the self record is excluded from. The old
    # `served OR faulted` disjunction was satisfied by faulting the whole listing whenever
    # any item is the self-case, which guts Fork C's own use case (a precedent search that
    # returns the self-case beside good siblings would serve NONE of them). d23's exclusion
    # is per-item, so the per-item observable is what this pins.
    list_delta = _tool_delta(run)
    assert "TKT-LIST-OK" in list_delta, (
        "the sibling was not served in the SAME response the self record was excluded "
        "from — a whole-listing fault is not the resolved per-item exclusion"
    )
    assert "exit=0" in list_delta, "the screened listing must still be a SUCCESS view"
    assert "TKT-SELF-LISTED" not in list_delta


def _names_self(field: str) -> dict:
    """A genuinely-closed, legitimately fetched ticket that names the case's own key in
    exactly ONE field — never in ``summary``, which carries the leak marker instead
    (#684/F3: the old fixture put the self-key in ``summary`` only, so a screen scoped to
    ``summary`` stayed green while a self-key in ``resolution`` leaked). ``comments`` puts
    it one level DOWN, so a screen over the top-level values alone also fails a row."""
    tkt = {**DATED, "key": "SOC-800", "status": "closed", "summary": "nightly TKT-QUOTES-SELF"}
    if field == "key":
        tkt["key"] = CASE
    elif field == "comments":
        tkt["comments"] = [{"author": "soc", "body": f"duplicate of in-flight {CASE}"}]
    else:
        tkt[field] = f"duplicate of in-flight {CASE}"
    return tkt


@pytest.mark.parametrize("field", ["resolution", "key", "comments"])
def test_closed_ticket_naming_self_key_refused(tmp_path, field):
    """[d25_self_key_payload_screen] (Fork H, §7-minted) Fork C's exclusion EXTENDS to a
    genuinely closed, legitimately fetched ticket whose payload names the case-under-
    judgment's own key: the one instance of the transitive answer-key path whose identifier
    this seam actually knows is refused — the quoted content never reaches the judge. The
    other half of the resolved premise: a closed ticket quoting any OTHER non-closed ticket
    rides the salted untrusted envelope UNREDACTED (O2 is scoped record-wise; the residual
    transitive path is the graph's N-note — general free-text screening is not owed).
    Positive control: a clean payload through the same edge is served.

    PARAMETRIZED at #684 (F3): the screen runs over the SERIALIZED WHOLE payload, so the
    field carrying the self-key is varied across rows — a screen scoped to one field, or
    to the payload's top level, fails at least one row."""
    rec = VerbRecorder()
    names_self = _names_self(field)
    names_other = {**DATED, "key": "SOC-801", "status": "closed",
                   "summary": "see also open ticket 20260101T0000Z-other-case TKT-QUOTES-OTHER"}
    run = _drive(
        tmp_path,
        [_get("SOC-800"), _get("SOC-801"), _get(OTHER_KEY), DONE],
        registry=_ticket_registry(rec, get=[("return", names_self),
                                            ("return", names_other),
                                            ("return", CLOSED_TKT)]),
    )
    assert run.out.strip()
    assert len(_get_calls(rec)) == 3             # all three were legitimately fetchable
    assert "TKT-QUOTES-SELF" not in run.all_text, (
        f"the payload naming the self-case in `{field}` leaked — the screen must run over "
        "the SERIALIZED WHOLE payload, not one field"
    )
    assert "duplicate of in-flight" not in run.all_text, "the quoting free text leaked"
    # The withheld read is a BUSINESS refusal: the breaker stays clean (shipping it as an
    # infra fault would trip the breaker on three cases). It files the dedicated policy code
    # (3), NOT the adapter's generic business code (1) — a withheld self-read and a genuine
    # 404 must not be indistinguishable in the audit trail. Non-infra either way.
    assert run.rows()[0]["exit_code"] == 3
    assert run.rows()[0]["error_class"] == "agent-fixable"
    assert not run.breaker().get("systems", {}).get("ticket", {}).get("failures")
    # The N-note half: other-ticket quotes ride wrapped, unredacted.
    assert "TKT-QUOTES-OTHER" in run.all_text
    # Control: the clean read is served.
    assert "TKT-CONTENT-777" in run.all_text


@pytest.mark.parametrize("field", ["resolution", "comments"])
def test_listed_ticket_naming_self_key_dropped(tmp_path, field):
    """[d31_self_key_payload_screen_on_list] (#683, merge gate) d25's screen was scoped to
    `get`, so the judge's PRIMARY surface — the precedent search — could serve a sibling
    closed ticket whose free text NAMES the case under judgment: the identical payload that
    a confirm withholds. The gate ruled the asymmetry a defect (protected asset, higher
    traffic), not a scoping the N-note had earned, so the same predicate now binds both
    surfaces and the SAME fixture drives them.

    The withhold SHAPE differs from `get`'s, per #684/F2's per-item resolution: this path
    DROPS the naming item and serves its siblings from the same response, because faulting a
    listing over one sibling's wording would gut O1's precedent search. So the demand is a
    CONJUNCTION on the list call's own response — the drop AND the serve — and the listing
    stays a success view rather than becoming d25's whole-read refusal.

    The N-note's surviving half is a positive control: a sibling quoting some OTHER ticket's
    key rides through unredacted, so this cannot be discharged by a screen that drops
    anything key-shaped.

    NOT parametrized over `key`: a listed item whose key IS the self-case is already excluded
    by d24/V-A's identity filter, so that row would stay green against the get-scoped screen
    this test exists to fail."""
    rec = VerbRecorder()
    listing = {"tickets": [
        {**DATED, "key": "SOC-OK", "status": "closed", "summary": "TKT-ITEM-CLOSED"},
        _names_self(field),
        {**DATED, "key": "SOC-801", "status": "closed",
         "summary": "see also open ticket 20260101T0000Z-other-case TKT-QUOTES-OTHER"},
    ], "total": 9}   # deliberately DISAGREES with len(tickets): a passed-through count fails
    run = _drive(tmp_path, [_list(q="precedent"), DONE],
                 registry=_ticket_registry(rec, lst=[("return", listing)]))
    assert run.out.strip()
    delta = _tool_delta(run)
    assert "TKT-QUOTES-SELF" not in run.all_text, (
        f"a listed sibling naming the self-case in `{field}` was served — the precedent "
        "search still delivers what the confirm withholds"
    )
    assert "duplicate of in-flight" not in run.all_text, "the quoting free text leaked"
    # The per-item arm, asserted as a conjunction on this call's own response: the drop does
    # not cost the siblings, and the response is a SUCCESS view, not d25's refusal.
    assert "TKT-ITEM-CLOSED" in delta, (
        "the clean sibling was not served in the SAME response the naming item was dropped "
        "from — a whole-listing fault is not the resolved per-item arm"
    )
    assert "exit=0" in delta, "the screened listing must still be a success view"
    assert run.rows()[0]["exit_code"] == 0, "a per-item drop is not a fault"
    # A business drop contributes NOTHING to the breaker. `record_outcome` writes the file only
    # for an infra exit code, so the discriminating form is that no breaker state exists at all
    # — the `.get(...) is falsy` spelling passes vacuously against an absent file.
    assert run.breaker() == {}, "a per-item policy drop contributed to the ticket breaker"
    # The N-note half still declined: an OTHER ticket's key rides wrapped, unredacted — and
    # `wrapped` is the demand's `salt` bind, so observe the frame rather than assume it.
    assert "TKT-QUOTES-OTHER" in delta
    assert WRAP_RE.search(delta), (
        "the served listing did not ride the per-bind salted untrusted envelope"
    )
    # #683 item 2: the envelope's count reports what was SERVED, not the store's count over
    # matches it never returned — the sampled view prints `total` as confirmable precedents.
    assert '"total": 2' in delta, "the screened listing advertises records it withheld"


def test_list_response_non_closed_item_dropped_or_faulted(tmp_path):
    """[d24_list_item_recheck] (Fork G, §7-minted) The list path re-checks each returned
    item's status CLIENT-SIDE and drops or faults non-closed items before the envelope —
    mirroring onto list the body check get already performs (c2) — so a store that
    misfilters (or a `q` value that crosses the server's inherited filter semantics) cannot
    ride a non-closed record into the judge's context: O2's outcome wording holds on the
    response side, not just request formation. `in_progress` is the store's REAL third
    enum member (Fork D probe, executed); a case-variant status string is an unenumerated
    state and refuses like open (the binary contract) — what counts as 'closed' is now this
    seam's decision, strict. V-A extends the re-check beyond status: the case-under-
    judgment's OWN record is excluded per-item by IDENTITY even when genuinely closed
    (the get-path screen mirrored onto list — Fork C's main use case). Duplicates survive
    intact: the re-check is status + self-key identity, and it does NOT dedup (the
    recorded non-consequence). Positive control: the closed item is servable — and at
    #684 (F2) that control became a CONJUNCTION with the exclusions, on the list call's
    own response: drop-or-fault is per ITEM, not per listing."""
    rec = VerbRecorder()
    mixed = {"tickets": [
        {**DATED, "key": "SOC-OK", "status": "closed", "summary": "TKT-ITEM-CLOSED"},
        {**DATED, "key": "SOC-BAD", "status": "in_progress", "summary": "TKT-ITEM-INPROGRESS"},
        {**DATED, "key": "SOC-VAR", "status": "Closed", "summary": "TKT-ITEM-CASEVARIANT"},
        {**DATED, "key": CASE, "status": "closed", "summary": "TKT-ITEM-SELF"},
    ], "total": 4}
    run = _drive(tmp_path, [_list(label="x"), DONE],
                 registry=_ticket_registry(rec, lst=[("return", mixed)]))
    assert run.out.strip()
    assert "TKT-ITEM-INPROGRESS" not in run.all_text, "a non-closed item crossed the envelope"
    assert "TKT-ITEM-CASEVARIANT" not in run.all_text, "an unenumerated status was read as closed"
    assert "TKT-ITEM-SELF" not in run.all_text, (
        "the self-case's closed record crossed the list envelope — V-A's identity filter"
    )
    # #684 (F2): a CONJUNCTION on the list call's own appended result. d24's "drop OR
    # fault" is PER-ITEM: the good sibling rides the SAME response the non-closed and
    # self records are excluded from. The old whole-response disjunction (`served or
    # faulted` over run.all_text / run.last) was satisfied by faulting the ENTIRE listing
    # whenever any item is bad — an implementation that serves nothing whenever a store
    # misfilters, silently gutting O1's precedent search.
    delta = _tool_delta(run)
    assert "TKT-ITEM-CLOSED" in delta, (
        "the closed sibling was not served in the SAME response the non-closed/self items "
        "were excluded from — a whole-listing fault is not the resolved per-item arm"
    )
    assert "exit=0" in delta, "the screened listing must still be a SUCCESS view"
    for marker in ("TKT-ITEM-INPROGRESS", "TKT-ITEM-CASEVARIANT", "TKT-ITEM-SELF"):
        assert marker not in delta

    # Duplicates: the status-only re-check does not dedup.
    rec2 = VerbRecorder()
    dupes = {"tickets": [
        {**DATED, "key": "SOC-DUP", "status": "closed", "summary": "TKT-DUP-A"},
        {**DATED, "key": "SOC-DUP", "status": "closed", "summary": "TKT-DUP-B"},
    ], "total": 2}
    run2 = _drive(tmp_path, [_list(label="x"), DONE],
                  registry=_ticket_registry(rec2, lst=[("return", dupes)]),
                  case=_case(tmp_path, name=CASE + "-dup"))
    assert "TKT-DUP-A" in run2.all_text
    assert "TKT-DUP-B" in run2.all_text


# ── Fork J: the recency arm ──────────────────────────────────────────────────────────────

AFTER_CASE = {"created": "2026-05-02T09:15:00+00:00", "updated": "2026-07-20T06:30:00+00:00"}


def test_listed_ticket_written_after_case_opened_dropped(tmp_path):
    """[d32_recency_screen] (Fork J) Every other self-case arm screens on what a record SAYS,
    so all of them are defeated by a sibling that describes the live case WITHOUT spelling its
    key — the service and the date, in prose, which is how an analyst actually writes. This
    fixture is exactly that: a closed ticket whose text names no key at all, so the identity
    filter, the free-text screen, and the closed-only re-check all pass it. Only its
    timestamp gives it away.

    The withhold shape is the per-item one #684/F2 resolved, so the demand is a CONJUNCTION on
    one response: the contaminated record is dropped AND the genuinely-older sibling is served
    from the same listing, at exit 0.

    `updated`, not `created`, is the dated field — the fixture was CREATED long before the case
    and amended during it, which is the leak this arm exists to close and the one a
    creation-dated screen would admit."""
    rec = VerbRecorder()
    listing = {"tickets": [
        {**DATED, "key": "SOC-OLD", "status": "closed", "summary": "TKT-PRECEDENT-OLD"},
        {**AFTER_CASE, "key": "SOC-NEW", "status": "closed",
         "summary": "sshd brute force on the jump host, 20 July — same pattern, benign",
         "resolution": "TKT-WRITTEN-DURING-CASE"},
    ], "total": 2}
    run = _drive(tmp_path, [_list(q="sshd"), DONE],
                 registry=_ticket_registry(rec, lst=[("return", listing)]))
    assert run.out.strip()
    delta = _tool_delta(run)
    assert "TKT-WRITTEN-DURING-CASE" not in run.all_text, (
        "a ticket last written after the case opened was served as precedent — it cannot be "
        "precedent for a case that did not exist when it was written"
    )
    assert "20 July" not in delta, "the contaminating free text leaked"
    assert "TKT-PRECEDENT-OLD" in delta, (
        "the genuinely-older sibling was not served in the SAME response — a whole-listing "
        "fault is not the resolved per-item arm"
    )
    assert "exit=0" in delta, "a per-item recency drop must still be a success view"
    assert run.rows()[0]["exit_code"] == 0, "a per-item drop is not a fault"
    assert run.breaker() == {}, "a per-item policy drop contributed to the ticket breaker"
    assert '"total": 1' in delta, "the screened listing advertises a record it withheld"


def test_fetched_ticket_written_after_case_opened_withheld(tmp_path):
    """[d32_recency_screen] The confirm surface answers with ONE record, so the same predicate
    fails the whole read rather than dropping an item — under the distinguishable policy code,
    which is what lets a later reader tell a withheld read from a genuine 404.

    Driving the SAME shape of fixture through both surfaces is the point: #683's defect was two
    screens disagreeing about one record, and this arm must not reintroduce it one fork later."""
    rec = VerbRecorder()
    fresh = {**AFTER_CASE, "key": "SOC-NEW", "status": "closed",
             "summary": "sshd brute force on the jump host, 20 July",
             "resolution": "TKT-CONFIRM-DURING-CASE"}
    run = _drive(tmp_path, [_get("SOC-NEW"), DONE],
                 registry=_ticket_registry(rec, get=[("return", fresh)]))
    assert run.out.strip()
    assert "TKT-CONFIRM-DURING-CASE" not in run.all_text, (
        "the confirm served a record the listing withholds — the two surfaces disagree again"
    )
    assert run.rows()[0]["exit_code"] == 3, (
        "a recency withhold must carry the distinguishable policy code, not a generic "
        "business refusal a 404 also carries"
    )
    assert run.breaker() == {}, "a policy withhold contributed to the ticket breaker"
    assert "after the case you are scoring was opened" in _tool_delta(run), (
        "the model was not told WHY the read was refused, so it cannot correct its citation"
    )


def test_undated_ticket_withheld_on_both_surfaces(tmp_path):
    """[d32_recency_screen] A record carrying no usable timestamp is not older, it is UNDATED.
    It is withheld, on the same reasoning gather refuses a ticket it cannot prove distinct from
    its own case: on the surface where the answer key is at stake, unprovable is not safe.

    Both surfaces, because a screen that only holds on the confirm is the #683 defect."""
    rec = VerbRecorder()
    undated = {"key": "SOC-UNDATED", "status": "closed", "summary": "TKT-NO-STAMP"}
    listed = _drive(tmp_path, [_list(q="x"), DONE],
                    registry=_ticket_registry(
                        rec, lst=[("return", {"tickets": [undated], "total": 1})]))
    assert "TKT-NO-STAMP" not in listed.all_text, "an undated record rode the precedent search"
    assert listed.rows()[0]["exit_code"] == 0, "a per-item drop is not a fault"

    fetched = _drive(tmp_path, [_get("SOC-UNDATED"), DONE],
                     registry=_ticket_registry(VerbRecorder(), get=[("return", undated)]),
                     case=_case(tmp_path, name=CASE + "-undated"))
    assert "TKT-NO-STAMP" not in fetched.all_text, "an undated record rode the confirm"
    assert fetched.rows()[0]["exit_code"] == 3


def test_case_with_no_ticket_leaves_the_precedent_search_usable(tmp_path):
    """[d32_recency_screen] A case that never filed a ticket has no boundary to screen
    against — and the store saying so (a 404, a real answer) must NOT fault the read. Most
    cases never open a ticket; failing here would make the precedent search unusable for them
    and buy nothing, since the other three conjuncts are unaffected.

    The discriminating half is that the OTHER arms still run with no boundary in hand: the
    self-naming sibling is still dropped."""
    rec = VerbRecorder()
    listing = {"tickets": [
        {**DATED, "key": "SOC-OLD", "status": "closed", "summary": "TKT-NO-BOUNDARY-SERVED"},
        {**DATED, "key": "SOC-NAMES", "status": "closed",
         "summary": f"duplicate of in-flight {CASE} TKT-STILL-SCREENED"},
    ], "total": 2}
    run = _drive(tmp_path, [_list(q="x"), DONE],
                 registry=_ticket_registry(
                     rec, lst=[("return", listing)],
                     case_opened=("raise", UpstreamFault(f"ticket {CASE} not found"))))
    delta = _tool_delta(run)
    assert "TKT-NO-BOUNDARY-SERVED" in delta, (
        "a case with no ticket lost its precedent search — a 404 on the boundary is an "
        "answer, not a fault"
    )
    assert "exit=0" in delta
    assert "TKT-STILL-SCREENED" not in run.all_text, (
        "with no boundary the OTHER self-case arms stopped running too"
    )
    assert run.breaker() == {}, "a missing case ticket contributed to the ticket breaker"


@pytest.mark.parametrize(
    ("kwargs", "why"),
    [
        ({"case_opened": ("raise", ConfigFault("ticket URL_BASE unset"))}, "store unreachable"),
        ({"case_opened": ("return", "not-a-timestamp")}, "boundary unparseable"),
        ({"case_opened": None}, "adapter declares no such verb"),
    ],
    ids=["unreachable", "unparseable", "undeclared"],
)
def test_unreadable_case_boundary_fails_the_read_closed(tmp_path, kwargs, why):
    """[d32_recency_screen] The three ways the environment can fail to date the case, all
    resolved the same way: FAIL THE READ. An arm that stands down when its input is missing
    protects nothing — and the failure modes here are indistinguishable from the inside, so
    "serve unscreened, it is probably fine" would be a guess made on the answer-key path.

    Loud in the three channels this module owns, and the discriminating half is the first:
    the store is never asked for precedent at all, so this cannot be discharged by an
    implementation that reads the listing and then discards it."""
    rec = VerbRecorder()
    run = _drive(tmp_path, [_list(q="x"), DONE],
                 registry=_ticket_registry(rec, **kwargs))
    assert _list_calls(rec) == [], (
        f"the precedent read reached the store with no usable boundary ({why})"
    )
    assert "TKT-CONTENT-777" not in run.all_text, "an unscreened listing was served"
    row = run.rows()[0]
    assert row["exit_code"] == 2, "an unreadable boundary is an infra fault, not a refusal"
    assert row["verb"] == "case-opened-at", (
        "the row names a verb that did not run — the trail must record what actually failed"
    )
    assert run.breaker().get("systems", {}).get("ticket", {}).get("failures"), (
        "a persistently undatable store never trips the ticket breaker"
    )
