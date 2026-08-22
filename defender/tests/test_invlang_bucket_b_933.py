"""#933 bucket B — the seven spec'd-but-unbuilt validator rules, pinned from the spec text.

Rules #13, #18, #26, #29, #30, #31 and #34 are written down in
`docs/investigation-language.md` §Validator rules and given column shapes in
`docs/dense-investigation-format.md`, and none of them is enforced. Their data is not even
projected: `parser._project_t_block` swallows every `:T conclude.*` sub-table but
`conclude.surviving`, and `_project_lead_subblock` has no branch for `:L l-NNN.lead_preds` or
`:L l-NNN.impact_preds`, so a companion can declare an impact threshold, never grade it, and
validate clean. Every test below therefore FAILS until the projection and the checks land —
that is the point of writing them first.

This file was written as an independent oracle: from the rule text, with the implementation
deliberately unread. So it enumerates each rule's arms rather than the arms some code happens
to have. Concretely that means, per rule: every legal enum member gets its own passing test and
illegal members get failing ones (a rule pinned by one member of three is a rule two thirds
free to be wrong); every id shape is probed at several points of the malformation space
(trailing junk, leading junk, no digits, wrong case, wrong namespace) rather than one; every
conditional-presence rule gets all four cells of its truth table; every closure rule gets
resolved / deferred-with-rationale / deferred-with-EMPTY-rationale / neither, plus the mixed
case; every reference rule gets local, cross-scope, wrong-scope and dangling.

Each rule also gets a **liveness control** — a clean document asserted `== []`. A check that
refuses everything passes every failure test in here and only the controls catch it. For the
same reason failures assert an exact error count and a token the message cannot omit (the
offending id), never merely "something was raised": an assertion that only demands non-empty
is satisfied by the wrong rule firing.

Where the spec contradicts itself the fixture follows the reading the rest of the surface
already implements, and the docstring says so. Three such places are load-bearing here:

* `ceiling_test` — `dense-investigation-format.md` gives it a `:T conclude.ceiling_test
  [kind|subject]` sub-table; `SKILL.md`, `schema.Conclude.ceiling_test: list[str]` and
  `parser._CONCLUDE_LISTS` all make it a REPEATED flat `<key> <value>` row in `:T conclude`.
  Three surfaces to one, so the flat row is what these tests write.
* the contract reference spelling — rule #26 names a deferred contract `h-{id}.ac{n}` while
  `:R authz`'s own `fulfills` column is the bare `ac{n}` (`ac<n>` numbers across the document,
  per SKILL.md §Authz contracts). Both spellings are used here, each on the side that
  specifies it.
* `impact_verdict` — rule #31's enum is `{none, within, exceeds, indeterminate}`, but
  `examples/example-c-cumulative-escalation.md` ships `none-detected` and both e2e goldens
  ship `none-detected` / `attempted-lateral-movement`. `test_shipped_invlang_documents.py`
  requires every shipped document to be gate-clean, so landing #31's enum breaks those
  documents until they are fixed. The test that pins `none-detected` as illegal says so.
"""

from __future__ import annotations

from collections.abc import Sequence

import pytest

from defender.skills.invlang.parser import parse_dense_companion
from defender.skills.invlang.validate import diagnose, validate_companion, warn_diagnostics

# --------------------------------------------------------------------------- #
# shared scaffolding
# --------------------------------------------------------------------------- #

#: Two hosts and the failed auth between them. Every fixture in this file hangs off it, so no
#: test is answering a question about the prologue when it means to ask about a closure rule.
_PROLOGUE = """\
:V prologue.vertices [id|type|class|ident|attrs?]
v-001|compute|app-server/internal/known-corp|app-server-01|os=linux
v-002|compute|bastion/internal/known-corp|bastion-01|os=linux

:E prologue.edges [id|rel|src|tgt|when|auth_kind:source|attrs?]
e-001|attempted_auth|v-002|v-001|2026-05-05T03:47:12Z|siem-event:siem|outcome=failed"""

#: Two leads in document order. `volume-baseline` carries the pre-registrations; the follower
#: `dlp-scope-check` is what rule #18's route-compliance clause compares an `advance_to`
#: against, and what a cross-lead `l-002.ip*` reference needs to exist.
_LEADS = """\
:L findings [id|loop|name|target|tests|system|window]
l-001|1|volume-baseline|v-001||siem|30d
l-002|1|dlp-scope-check|v-002||dlp|n/a"""


def _doc(*blocks: str) -> str:
    """Wrap dense blocks in the ```invlang fence the validator reads."""
    body = "\n\n".join(b.strip("\n") for b in blocks if b.strip())
    return f"```invlang\n{body}\n```\n"


def _errors(doc: str) -> list[str]:
    return validate_companion(doc, None)


def _one_error(doc: str, *tokens: str) -> str:
    """Exactly one error, and it names every token given.

    Both halves matter. The count keeps a fixture that trips a second rule from reading as a
    pass, and the tokens keep the WRONG rule firing from reading as a pass — an assertion that
    only demands a non-empty list is satisfied by any error at all.
    """
    errors = _errors(doc)
    assert len(errors) == 1, errors
    for token in tokens:
        assert token in errors[0], errors[0]
    return errors[0]


def _conclude(
    *,
    category: str = "exhaustion-escalation",
    impact_verdict: str = "none",
    impact_severity: str | None = None,
    ceiling_test: str | None = None,
    ceiling_rationale: str | None = None,
) -> str:
    """A `:T conclude` scalar block. `None` omits the row; a string writes it verbatim, so
    `impact_severity="null"` is how the explicit-null spelling is tested apart from absence."""
    rows = [
        ":T conclude",
        f"termination.category   {category}",
        "disposition            inconclusive",
        f"impact_verdict         {impact_verdict}",
        "confidence             medium",
    ]
    if impact_severity is not None:
        rows.append(f"impact_severity        {impact_severity}")
    if ceiling_test is not None:
        rows.append(f"ceiling_test           {ceiling_test}")
    if ceiling_rationale is not None:
        rows.append(f"ceiling_rationale      {ceiling_rationale}")
    rows.append('summary                "Failure series left one threshold ungraded"')
    return "\n".join(rows)


def _table(name: str, columns: str, rows: Sequence[str]) -> str:
    """A `:T conclude.*` sub-table. No rows means the `none` marker, which is how the format
    spells an empty array (`dense-investigation-format.md` §`:T`)."""
    return "\n".join([f":T conclude.{name} [{columns}]", *(rows or ["none"])])


def _deferred_authz(*rows: str) -> str:
    return _table("deferred_authz", "contract_ref|rationale", rows)


def _deferred_impact(*rows: str) -> str:
    return _table("deferred_impact", "prediction_ref|rationale", rows)


def _deferred_preds(*rows: str) -> str:
    return _table("deferred_preds", "prediction_ref|rationale", rows)


# --------------------------------------------------------------------------- #
# rule #13 — `ceiling_test` required when termination is severity-ceiling, forbidden otherwise
# --------------------------------------------------------------------------- #

#: The four members of the termination-category enum (§Conclude → Termination categories).
#: Parametrising over all four is deliberate: `severity-ceiling` is the only cell where
#: `ceiling_test` is required, and a check keyed on "not severity-ceiling" that actually reads
#: "is exhaustion-escalation" passes a one-member test and fails the other two.
_TERMINATION_CATEGORIES = [
    "trust-root",
    "adversarial-refuted",
    "severity-ceiling",
    "exhaustion-escalation",
]

_A_CEILING_TEST = '"authorized_keys FIM on app-server-01 (auditd write events) not retrieved"'


def _ceiling_doc(category: str, ceiling_test: str | None) -> str:
    return _doc(_PROLOGUE, _LEADS, _conclude(category=category, ceiling_test=ceiling_test))


def test_severity_ceiling_with_a_ceiling_test_is_the_clean_shape() -> None:
    """Liveness control for #13's required arm."""
    assert _errors(_ceiling_doc("severity-ceiling", _A_CEILING_TEST)) == []


def test_severity_ceiling_without_a_ceiling_test_is_refused() -> None:
    _one_error(_ceiling_doc("severity-ceiling", None), "ceiling_test")


def test_severity_ceiling_whose_ceiling_test_is_the_none_marker_is_refused() -> None:
    """`none` is the format's spelling of absence — `parser.is_conclude_empty_marker` drops it
    from the projected list — so it must land in the same cell as omitting the row, not buy the
    termination category a row that says nothing."""
    _one_error(_ceiling_doc("severity-ceiling", "none"), "ceiling_test")


@pytest.mark.parametrize(
    "category", [c for c in _TERMINATION_CATEGORIES if c != "severity-ceiling"]
)
@pytest.mark.xfail(
    strict=True,
    reason="rule #13's 'forbidden otherwise' half is deliberately unenforced. It was "
    "written against the pilot spec's `ceiling_test: {kind, subject}` — the out-of-band "
    "step that would RESOLVE a ceiling — while the shipped field is the list of checks a "
    "run could not make, which the lessons corpus instructs writing under any termination "
    "category. Recorded at rule #13 in `docs/investigation-language.md`, in "
    "`docs/dense-investigation-format.md` §`:T conclude`, and as ramp item 14. Arming it "
    "turns this xfail red, which is the point.",
)
def test_a_ceiling_test_under_any_other_termination_category_is_refused(category: str) -> None:
    """The forbidden-and-present cell, once per remaining enum member."""
    _one_error(_ceiling_doc(category, _A_CEILING_TEST), "ceiling_test")


@pytest.mark.parametrize(
    "category", [c for c in _TERMINATION_CATEGORIES if c != "severity-ceiling"]
)
def test_any_other_termination_category_without_a_ceiling_test_is_clean(category: str) -> None:
    """The forbidden-and-absent cell — liveness control against a check that refuses every
    document that merely mentions a termination category."""
    assert _errors(_ceiling_doc(category, None)) == []


@pytest.mark.parametrize(
    "category", [c for c in _TERMINATION_CATEGORIES if c != "severity-ceiling"]
)
def test_the_none_marker_is_how_a_non_ceiling_close_says_nothing_was_out_of_reach(
    category: str,
) -> None:
    """SKILL.md §`:T conclude`: "Omit the row (or write `none`) when nothing was out of reach."
    So the marker must not read as presence under the forbidding categories."""
    assert _errors(_ceiling_doc(category, "none")) == []


@pytest.mark.xfail(
    strict=True,
    reason="rule #13's `ceiling_rationale` clause is not implemented. It appears only in "
    "`dense-investigation-format.md`'s translation table, never in rule #13's own text, "
    "and that document is reconciled to '`ceiling_rationale` is the companion scalar and "
    "carries no validator rule'. Recorded there and at ramp item 14.",
)
def test_severity_ceiling_without_a_ceiling_rationale_is_refused() -> None:
    """This arm comes from `dense-investigation-format.md` §Validator translation, which
    renders #13 as "`:T conclude.ceiling_test` row ≠ `none` *iff* `termination.category` =
    `severity-ceiling`; `ceiling_rationale` non-empty under the same condition." Rule #13's own
    one-sentence text in `investigation-language.md` mentions only `ceiling_test`. Pinned here
    because the two documents disagree about whether the companion scalar is part of the rule,
    and an unpinned disagreement gets resolved by whoever writes the code."""
    doc = _doc(
        _PROLOGUE,
        _LEADS,
        _conclude(category="severity-ceiling", ceiling_test=_A_CEILING_TEST),
    )
    _one_error(doc, "ceiling_rationale")


def test_severity_ceiling_with_both_rows_is_clean() -> None:
    doc = _doc(
        _PROLOGUE,
        _LEADS,
        _conclude(
            category="severity-ceiling",
            ceiling_test=_A_CEILING_TEST,
            ceiling_rationale='"no host agent is deployed in this environment"',
        ),
    )
    assert _errors(doc) == []


# --------------------------------------------------------------------------- #
# rule #18 — lead-level prediction structure (`lp*`)
# --------------------------------------------------------------------------- #

_LP_COLS = ("id", "if", "read_as", "advance_to")
_LP_DEFAULTS = {
    "id": "lp1",
    "if": '"session volume stays within 1 sigma of the prior 30d cadence"',
    "read_as": '"periodic tooling pattern"',
    "advance_to": "dlp-scope-check",
}


def _lead_preds(lead: str, *rows: dict[str, str]) -> str:
    """A `:L l-NNN.lead_preds` block. Columns are the shape
    `dense-investigation-format.md` §`:L` declares."""
    lines = [f":L {lead}.lead_preds [" + "|".join(_LP_COLS) + "]"]
    for row in rows or ({},):
        cells = {**_LP_DEFAULTS, **row}
        lines.append("|".join(cells[c] for c in _LP_COLS))
    return "\n".join(lines)


def _lp_doc(*rows: dict[str, str], lead: str = "l-001") -> str:
    return _doc(_PROLOGUE, _LEADS, _lead_preds(lead, *rows))


def test_a_well_formed_lead_prediction_validates_clean() -> None:
    """Liveness control for #18. `advance_to` names the follower lead, so the route-compliance
    clause is satisfied too and nothing at all should be emitted."""
    assert _errors(_lp_doc()) == []


def test_lead_predictions_project_onto_the_lead() -> None:
    """#18 cannot be checked over data nobody carries: `_project_lead_subblock` has no
    `lead_preds` branch today, so the block is dropped in silence — no warning, no rows. The
    schema-mapping table binds it to `findings[].predictions[]`."""
    body, warnings = parse_dense_companion(_lp_doc())
    assert warnings == []
    lead = next(f for f in body["findings"] if f["id"] == "l-001")
    assert [p["id"] for p in lead["predictions"]] == ["lp1"]


@pytest.mark.parametrize("lp_id", ["lp1", "lp2", "lp01", "lp10"])
def test_every_well_formed_lp_id_is_accepted(lp_id: str) -> None:
    """`^lp\\d+$` — one or more digits, any of them, including a leading zero."""
    assert _errors(_lp_doc({"id": lp_id})) == []


@pytest.mark.parametrize(
    "lp_id",
    [
        "lp",       # no digits at all
        "lp1x",     # trailing junk
        "xlp1",     # leading junk
        "LP1",      # wrong case
        "p1",       # hypothesis-prediction namespace
        "ip1",      # impact-prediction namespace
        "lp-1",     # separator the shape does not carry
        "lp1.2",    # qualified where a bare ordinal is required
    ],
)
def test_a_malformed_lp_id_is_refused(lp_id: str) -> None:
    """The malformation space sampled at eight points, not one. A regex written `lp\\d+` with
    no anchors passes `xlp1` and `lp1x`; one written `^lp\\d$` passes `lp1` and refuses `lp10`;
    a case-insensitive one passes `LP1`. Each of those is a different bug and only its own
    fixture catches it."""
    _one_error(_lp_doc({"id": lp_id}), lp_id)


def test_two_lead_predictions_sharing_an_id_within_one_lead_are_refused() -> None:
    _one_error(
        _lp_doc(
            {"id": "lp1"},
            {"id": "lp1", "if": '"volume is above 3 sigma"', "read_as": '"anomalous spike"'},
        ),
        "lp1",
    )


def test_two_lead_predictions_with_distinct_ids_in_one_lead_are_clean() -> None:
    assert _errors(
        _lp_doc(
            {"id": "lp1"},
            {"id": "lp2", "if": '"volume is above 3 sigma"', "read_as": '"anomalous spike"'},
        )
    ) == []


def test_the_same_lp_id_on_two_different_leads_is_clean() -> None:
    """Uniqueness is scoped to the lead ("unique within the lead"), so `lp1` on l-001 and `lp1`
    on l-002 are two ids, not a collision. A document-wide uniqueness check passes every other
    test in this section and fails only here."""
    doc = _doc(
        _PROLOGUE,
        _LEADS,
        _lead_preds("l-001"),
        _lead_preds("l-002", {"advance_to": "CONCLUDE"}),
    )
    assert _errors(doc) == []


@pytest.mark.parametrize("field", ["if", "read_as", "advance_to"])
def test_a_lead_prediction_missing_a_required_field_is_refused(field: str) -> None:
    """"each entry has `id` …, `if`, `read_as`, `advance_to`" — all three, one test apiece, so
    a check that happens to read only `advance_to` is caught."""
    _one_error(_lp_doc({field: ""}), "lp1", field)


@pytest.mark.parametrize("target", ["CONCLUDE", "HYPOTHESIZE"])
def test_the_two_terminal_advance_to_values_resolve(target: str) -> None:
    """Both sentinels, because a check pinned by one of them leaves the other free to be
    rejected. Written on the LAST lead so the route-compliance clause has no follower to
    compare against and cannot contribute a second finding."""
    doc = _doc(_PROLOGUE, _LEADS, _lead_preds("l-002", {"advance_to": target}))
    assert _errors(doc) == []


def test_advance_to_naming_a_lead_declared_elsewhere_resolves() -> None:
    assert _errors(_lp_doc({"advance_to": "dlp-scope-check"})) == []


def test_advance_to_naming_no_lead_at_all_is_refused() -> None:
    _one_error(_lp_doc({"advance_to": "process-lineage-walk"}), "process-lineage-walk")


@pytest.mark.parametrize("target", ["conclude", "Conclude", "hypothesize"])
def test_a_lowercase_terminal_advance_to_is_not_a_lead_name_either(target: str) -> None:
    """The spec spells the two escapes `CONCLUDE` / `HYPOTHESIZE`. A lowercase spelling is
    neither the literal nor a declared lead name, so it dangles — and a case-insensitive
    comparison would also accept `conclude` as a lead nobody declared."""
    _one_error(_lp_doc({"advance_to": target}, lead="l-002"), target)


def test_advance_to_naming_a_lead_id_rather_than_its_name_is_refused() -> None:
    """"a lead name appearing elsewhere in the companion" — the `name` column, not the `id`.
    Accepting `l-002` here would make the route unauditable against the run's own naming."""
    _one_error(_lp_doc({"advance_to": "l-002"}), "l-002")


# --- #18's route-compliance clause is a WARNING, not an error ---------------- #


def _warning_messages(doc: str) -> list[str]:
    return [d.message for d in diagnose(doc, None) if d.severity == "warning"]


@pytest.mark.xfail(
    strict=True,
    reason="rule #18's route-compliance clause is not implemented, and honouring "
    "'warning' is why: a locus-less warn is dropped by `runtime/tools._addressable`, and "
    "a warn WITH a locus lets `fix_row` rewrite the row — which would let a run edit its "
    "own pre-registration to match where it ended up. Recorded at rule #18 in "
    "`docs/investigation-language.md` and as the third 'Open, from #933' item in "
    "`docs/decisions/defender-invlang-enforcement-ramp.md`.",
)
def test_a_follower_matching_no_advance_to_warns_and_does_not_refuse_the_write() -> None:
    """The one clause of #18 the spec grades softly: "otherwise a route-compliance warning is
    emitted." l-001 pre-registers a route to CONCLUDE and is then followed by l-002, so the
    actually-run next lead matched nothing pre-committed. That is worth saying and is not worth
    refusing the document over — a warning LANDS the write and gates the next one.

    Asserted through both surfaces: zero errors out of `validate_companion` (which filters
    warn severity out) and exactly one finding out of `warn_diagnostics`.
    """
    doc = _lp_doc({"advance_to": "CONCLUDE"})
    assert _errors(doc) == []
    warnings = _warning_messages(doc)
    assert len(warnings) == 1, warnings
    assert "l-002" in warnings[0], warnings[0]
    assert len(warn_diagnostics(doc)) == 1


def test_a_follower_matching_an_advance_to_produces_no_warning() -> None:
    """Liveness control for the warning: the same document shape with the route honoured must
    be silent, or the warning above is just noise every companion earns."""
    assert _warning_messages(_lp_doc({"advance_to": "dlp-scope-check"})) == []


def test_a_follower_matching_one_of_several_advance_to_values_produces_no_warning() -> None:
    """"the follower's `name` should match at least one `advance_to` value" — at least one, so
    a second branch routing to CONCLUDE does not spoil the match."""
    doc = _lp_doc(
        {"id": "lp1", "advance_to": "dlp-scope-check"},
        {
            "id": "lp2",
            "if": '"volume is above 3 sigma"',
            "read_as": '"anomalous spike"',
            "advance_to": "CONCLUDE",
        },
    )
    assert _warning_messages(doc) == []


def test_the_last_lead_in_the_companion_has_no_follower_to_comply_with() -> None:
    """No following lead means the clause has no subject; a check that warns anyway fires on
    every terminating companion."""
    doc = _doc(_PROLOGUE, _LEADS, _lead_preds("l-002", {"advance_to": "CONCLUDE"}))
    assert _warning_messages(doc) == []


def test_a_dangling_advance_to_is_an_error_and_not_merely_a_warning() -> None:
    """The severity split inside #18: resolution is structural (error), route compliance is
    advisory (warning). A build that files both as warnings passes the warning tests above and
    lets an unresolvable branch plan through.

    Written on the LAST lead so the route clause has no follower and cannot contribute the
    warning this test is asserting the absence of."""
    doc = _lp_doc({"advance_to": "process-lineage-walk"}, lead="l-002")
    assert len(_errors(doc)) == 1
    assert warn_diagnostics(doc) == ()


# --------------------------------------------------------------------------- #
# rule #26 — authorization contract closure at CONCLUDE
# --------------------------------------------------------------------------- #

#: A contract-carrying hypothesis with NO predictions, deliberately: rule #34 would otherwise
#: fire on the same documents and every count assertion below would be reading two rules at
#: once. Predictionless hypotheses are legal (rule #23 exempts them explicitly) and are exactly
#: the shape SKILL.md §Sibling-fork uniqueness writes for a legitimacy question.
_ONE_CONTRACT = """\
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?documented-monitoring-probe|v-002|runs_on|identity|service-account/known-corp||null|active

:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-001|approved-source-list|"source host documented in CMDB at event time"|escalate|escalate"""

_TWO_CONTRACTS = """\
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?documented-monitoring-probe|v-002|runs_on|identity|service-account/known-corp||null|active

:H h-001.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac1|e-001|approved-source-list|"source host documented in CMDB at event time"|escalate|escalate
ac2|e-001|change-mgmt|"an approved change window covers this attempt"|escalate|escalate"""

#: `ac<n>` numbers across the DOCUMENT (SKILL.md §Authz contracts), so a second declaring
#: hypothesis continues the sequence rather than restarting it.
_CONTRACT_ON_A_LEAD_BORN_HYPOTHESIS = """\
:H l-002.new_hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-002|?scheduled-batch-mount|v-002|runs_on|identity|service-account/known-corp||null|active

:H h-002.authz [id|edge_ref|anchor_kind|predicate|on_unauth|on_indet]
ac2|e-001|change-mgmt|"an approved change window covers this attempt"|escalate|escalate"""


def _authz_row(contract: str = "ac1", verdict: str = "authorized") -> str:
    return (
        ":R authz [resolved_by|edge|fulfills|verdict|anchor_kind|reasoning]\n"
        f'l-001|e-001|{contract}|{verdict}|approved-source-list|"host is listed in CMDB"'
    )


def _authz_closure_doc(hypotheses: str, resolutions: str, deferred: str) -> str:
    return _doc(_PROLOGUE, hypotheses, _LEADS, resolutions, _conclude(), deferred)


def test_a_contract_with_a_fulfilling_resolution_closes_clean() -> None:
    """Liveness control for #26 arm (a)."""
    assert _errors(
        _authz_closure_doc(_ONE_CONTRACT, _authz_row(), _deferred_authz())
    ) == []


def test_a_contract_deferred_with_a_rationale_closes_clean() -> None:
    """Liveness control for #26 arm (b)."""
    doc = _authz_closure_doc(
        _ONE_CONTRACT,
        "",
        _deferred_authz('h-001.ac1|"CMDB export was stale; no authority anchor answered"'),
    )
    assert _errors(doc) == []


def test_a_contract_deferred_with_an_empty_rationale_is_refused() -> None:
    """"appear in `conclude.deferred_authorizations[]` with a NON-EMPTY rationale". Listing the
    id and saying nothing is the orphan-contract loophole with a row in front of it."""
    doc = _authz_closure_doc(_ONE_CONTRACT, "", _deferred_authz("h-001.ac1|"))
    _one_error(doc, "ac1")


def test_a_contract_deferred_with_a_whitespace_rationale_is_refused() -> None:
    """A cell holding a quoted blank is empty in every sense the rule cares about."""
    doc = _authz_closure_doc(_ONE_CONTRACT, "", _deferred_authz('h-001.ac1|"   "'))
    _one_error(doc, "ac1")


def test_a_contract_neither_resolved_nor_deferred_is_refused() -> None:
    """"A contract that is declared and silently abandoned — never resolved, never deferred —
    fails this rule.\""""
    doc = _authz_closure_doc(_ONE_CONTRACT, "", _deferred_authz())
    _one_error(doc, "ac1")


def test_a_contract_left_out_of_an_absent_deferral_table_is_refused() -> None:
    """Omitting the `:T conclude.deferred_authz` block entirely is not a third way to close a
    contract — an absent table and an empty one say the same thing."""
    doc = _doc(_PROLOGUE, _ONE_CONTRACT, _LEADS, _conclude())
    _one_error(doc, "ac1")


def test_one_contract_resolved_and_the_other_deferred_closes_clean() -> None:
    """The boundary the rule is actually written for: closure is per contract, not per
    document, so a mixed close is legal."""
    doc = _authz_closure_doc(
        _TWO_CONTRACTS,
        _authz_row("ac1"),
        _deferred_authz('h-001.ac2|"change-mgmt anchor unavailable for this window"'),
    )
    assert _errors(doc) == []


def test_one_contract_resolved_and_the_other_abandoned_is_refused_for_the_orphan_only() -> None:
    """The other half of the boundary: resolving one contract must not discharge its sibling.
    Exactly one error, and it names `ac2` — the count is what catches a check that gives up on
    the whole hypothesis once any contract on it resolves."""
    doc = _authz_closure_doc(_TWO_CONTRACTS, _authz_row("ac1"), _deferred_authz())
    _one_error(doc, "ac2")


def test_a_contract_on_a_lead_born_hypothesis_is_in_scope() -> None:
    """"across `hypothesize.hypotheses[]` and any `lead.outcome.new_hypotheses[]`" — a
    hypothesis raised mid-run carries the same obligation as one declared at PREDICT."""
    doc = _doc(
        _PROLOGUE,
        _ONE_CONTRACT,
        _LEADS,
        _CONTRACT_ON_A_LEAD_BORN_HYPOTHESIS,
        _authz_row("ac1"),
        _conclude(),
        _deferred_authz(),
    )
    _one_error(doc, "ac2")


def test_an_unresolved_contract_without_a_conclude_block_is_not_yet_a_failure() -> None:
    """"When a `conclude:` block is written" — the gate is the REPORT boundary. A mid-run
    companion whose contract has not been resolved yet is a companion in progress, and a check
    that fires on it denies every write on the way to satisfying it."""
    assert _errors(_doc(_PROLOGUE, _ONE_CONTRACT, _LEADS)) == []


def test_deferred_authorizations_project_onto_the_conclude_block() -> None:
    """`_project_t_block` returns True for every unrecognised `conclude.*` name and keeps
    nothing, so the deferral table is discarded today. #26 has nothing to read until it lands
    at `conclude.deferred_authorizations[]` (the schema-mapping table's binding)."""
    doc = _authz_closure_doc(
        _ONE_CONTRACT,
        "",
        _deferred_authz('h-001.ac1|"CMDB export was stale; no authority anchor answered"'),
    )
    body, warnings = parse_dense_companion(doc)
    assert warnings == []
    deferred = body["conclude"]["deferred_authorizations"]
    assert [d["contract_ref"] for d in deferred] == ["h-001.ac1"]


# --------------------------------------------------------------------------- #
# rule #29 — impact prediction structure (`ip*`)
# --------------------------------------------------------------------------- #

_IP_COLS = ("id", "dim", "claim", "on_match", "on_mismatch", "on_indeterminate", "escalation_on")
_IP_DEFAULTS = {
    "id": "ip1",
    "dim": "confidentiality",
    "claim": '"session_total_bytes stays within the 30d baseline plus 2 sigma"',
    "on_match": "within",
    "on_mismatch": "exceeds",
    "on_indeterminate": "indeterminate",
    "escalation_on": "exceeds",
}

#: The `dimension` enum rule #29 declares. All four are tested as passing, individually: two of
#: three legal members of a neighbouring enum were once pinned by nothing but a substring of an
#: error message, which is what testing one member and assuming the rest buys.
_IMPACT_DIMENSIONS = ["confidentiality", "integrity", "availability", "scope"]


def _impact_preds(lead: str, *rows: dict[str, str]) -> str:
    lines = [f":L {lead}.impact_preds [" + "|".join(_IP_COLS) + "]"]
    for row in rows or ({},):
        cells = {**_IP_DEFAULTS, **row}
        lines.append("|".join(cells[c] for c in _IP_COLS))
    return "\n".join(lines)


def _ip_doc(*rows: dict[str, str], lead: str = "l-001") -> str:
    """An impact-prediction document with NO `:T conclude`, so rule #31's closure gate cannot
    fire alongside #29 and every error count below reads one rule."""
    return _doc(_PROLOGUE, _LEADS, _impact_preds(lead, *rows))


def test_a_well_formed_impact_prediction_validates_clean() -> None:
    """Liveness control for #29."""
    assert _errors(_ip_doc()) == []


def test_impact_predictions_project_onto_the_lead() -> None:
    """As with `lead_preds`, the block is dropped in silence today. The schema-mapping table
    binds it to `findings[].impact_predictions[]`, and rules #30 and #31 both resolve against
    that list — neither can be written until it exists."""
    body, warnings = parse_dense_companion(_ip_doc())
    assert warnings == []
    lead = next(f for f in body["findings"] if f["id"] == "l-001")
    assert [p["id"] for p in lead["impact_predictions"]] == ["ip1"]
    assert lead["impact_predictions"][0]["dimension"] == "confidentiality"


@pytest.mark.parametrize("ip_id", ["ip1", "ip2", "ip01", "ip10"])
def test_every_well_formed_ip_id_is_accepted(ip_id: str) -> None:
    assert _errors(_ip_doc({"id": ip_id})) == []


@pytest.mark.parametrize(
    "ip_id",
    [
        "ip",       # no digits at all
        "ip1x",     # trailing junk
        "xip1",     # leading junk
        "IP1",      # wrong case
        "p1",       # hypothesis-prediction namespace
        "lp1",      # lead-prediction namespace
        "ap1",      # attribute-prediction namespace
        "l-001.ip1",  # the cross-lead identity, which is not the local id
    ],
)
def test_a_malformed_ip_id_is_refused(ip_id: str) -> None:
    """`^ip\\d+$`, sampled across the malformation space. `l-001.ip1` is in the list on
    purpose: rule #29 says "the full cross-lead identity of the prediction is `l-{lead_id}.
    ip{n}`" — derived, never written into the `id` cell, which the anchored shape forbids."""
    _one_error(_ip_doc({"id": ip_id}), ip_id)


def test_two_impact_predictions_sharing_an_id_within_one_lead_are_refused() -> None:
    _one_error(
        _ip_doc(
            {"id": "ip1"},
            {"id": "ip1", "dim": "scope", "claim": '"no second bucket prefix is touched"'},
        ),
        "ip1",
    )


def test_two_impact_predictions_with_distinct_ids_in_one_lead_are_clean() -> None:
    assert _errors(
        _ip_doc(
            {"id": "ip1"},
            {"id": "ip2", "dim": "scope", "claim": '"no second bucket prefix is touched"'},
        )
    ) == []


def test_the_same_ip_id_on_two_different_leads_is_clean() -> None:
    """"unique within the lead" — which is exactly why the cross-lead identity is qualified.
    A document-wide uniqueness check refuses the shape rule #30's qualified form assumes."""
    doc = _doc(_PROLOGUE, _LEADS, _impact_preds("l-001"), _impact_preds("l-002", {"dim": "scope"}))
    assert _errors(doc) == []


@pytest.mark.parametrize("dimension", _IMPACT_DIMENSIONS)
def test_every_legal_impact_dimension_is_accepted(dimension: str) -> None:
    assert _errors(_ip_doc({"dim": dimension})) == []


@pytest.mark.parametrize(
    "dimension",
    [
        "reputation",                 # plausible, not in the enum
        "Confidentiality",            # wrong case
        "confidentiality,integrity",  # two members where the shape carries one
        "financial",
    ],
)
def test_an_off_enum_impact_dimension_is_refused(dimension: str) -> None:
    _one_error(_ip_doc({"dim": dimension}), dimension)


def test_an_impact_prediction_with_no_dimension_is_refused() -> None:
    _one_error(_ip_doc({"dim": ""}), "dimension")


@pytest.mark.parametrize(
    "field", ["claim", "on_match", "on_mismatch", "on_indeterminate", "escalation_on"]
)
def test_an_impact_prediction_missing_a_required_field_is_refused(field: str) -> None:
    """Five required fields beside `id` and `dimension`, one test apiece. `on_indeterminate`
    is the one a hand-written check forgets — it is the branch that fires when the measurement
    could not be taken, which is the branch the closure rules exist for."""
    _one_error(_ip_doc({field: ""}), "ip1", field)


@pytest.mark.parametrize(
    "claim",
    [
        '"session_total_bytes exceeds baseline AND a second bucket prefix is touched"',
        '"session_total_bytes exceeds baseline OR the object count exceeds 10000"',
        '"session_total_bytes exceeds baseline; a second bucket prefix is touched"',
    ],
)
@pytest.mark.xfail(
    strict=True,
    reason="rule #29's one-observable-per-entry clause is semantic and deliberately not "
    "enforced: it is a judgment about what a sentence asserts, and a lexical AND/OR/`;` "
    "test would refuse 'session bytes and connection count stay within baseline' written "
    "about one measurement — the model-authored-prose test rule #32 was struck for. "
    "Recorded at rules #29 and #33 in `docs/investigation-language.md`.",
)
def test_a_compound_impact_claim_is_refused(claim: str) -> None:
    """"`claim` names one observable per entry — compound `AND` / `OR` / semicolon predicates
    must be split across entries." Stated in the rule text, so pinned here; it is also the
    clause of #29 most likely to be dropped as unmechanisable, and dropping it silently is the
    thing this test exists to prevent. Its sibling clause in rule #33 says the same for `ap*`
    and is likewise unbuilt, so there is no precedent to copy."""
    _one_error(_ip_doc({"claim": claim}), "ip1")


def test_a_claim_containing_the_letters_and_inside_a_word_is_not_compound() -> None:
    """The liveness control for the clause above, and the reason it has to be tokenised rather
    than substring-matched: "bandwidth" contains "and", "scoring" contains "or"."""
    assert _errors(
        _ip_doc({"claim": '"egress bandwidth scoring stays inside the sanctioned envelope"'})
    ) == []


# --------------------------------------------------------------------------- #
# rule #30 — impact resolution back-refs and grounding
# --------------------------------------------------------------------------- #

_R_IMPACT_COLS = (
    "resolved_by", "pred_ref", "dim", "observed", "verdict",
    "grounding", "anchor_id", "anchor_kind", "authority", "as_of", "reasoning",
)
_R_IMPACT_DEFAULTS = {
    "resolved_by": "l-001",
    "pred_ref": "ip1",
    "dim": "confidentiality",
    "observed": "180GB against a 60GB 30d mean",
    "verdict": "exceeds",
    "grounding": "telemetry-baseline",
    "anchor_id": "session-volume-30d",
    "anchor_kind": "runtime-evidence",
    "authority": "partial",
    "as_of": "2026-05-05T04:00:00Z",
    "reasoning": '"observed 3 sigma against a 2 sigma threshold"',
}

#: Two leads, each declaring one impact prediction under a DIFFERENT id and dimension. That is
#: what makes the reference arms separable: `ip1` exists only on l-001, `ip2` only on l-002,
#: so a bare `ip1` written on an l-002 row is a reference that resolves somewhere in the
#: companion and must still be refused.
_TWO_LEADS_WITH_IMPACT_PREDS = """\
:L l-001.impact_preds [id|dim|claim|on_match|on_mismatch|on_indeterminate|escalation_on]
ip1|confidentiality|"session_total_bytes stays within the 30d baseline plus 2 sigma"|within|exceeds|indeterminate|exceeds

:L l-002.impact_preds [id|dim|claim|on_match|on_mismatch|on_indeterminate|escalation_on]
ip2|scope|"no object outside the sanctioned prefix is read"|within|exceeds|indeterminate|exceeds"""


def _r_impact(*rows: dict[str, str]) -> str:
    lines = [":R impact [" + "|".join(_R_IMPACT_COLS) + "]"]
    for row in rows or ({},):
        cells = {**_R_IMPACT_DEFAULTS, **row}
        lines.append("|".join(cells[c] for c in _R_IMPACT_COLS))
    return "\n".join(lines)


def _r_impact_doc(*rows: dict[str, str]) -> str:
    """No `:T conclude`, again so #31 stays out of the counts."""
    return _doc(_PROLOGUE, _LEADS, _TWO_LEADS_WITH_IMPACT_PREDS, _r_impact(*rows))


def test_an_impact_resolution_against_a_local_prediction_validates_clean() -> None:
    """Liveness control for #30."""
    assert _errors(_r_impact_doc()) == []


def test_a_bare_prediction_ref_resolves_within_the_emitting_lead() -> None:
    assert _errors(_r_impact_doc({"resolved_by": "l-001", "pred_ref": "ip1"})) == []


def test_a_qualified_prediction_ref_resolves_across_leads() -> None:
    """"fully qualified `l-{id}.ip{n}` resolves across leads" — l-002 grades a threshold l-001
    pre-registered, which is the ordinary shape when the measuring lead and the grading lead
    are different."""
    assert _errors(
        _r_impact_doc({"resolved_by": "l-002", "pred_ref": "l-001.ip1"})
    ) == []


def test_a_bare_prediction_ref_does_not_reach_another_leads_prediction() -> None:
    """The arm that separates a real scope check from a document-wide id lookup: `ip1` IS
    declared in this companion, just not on l-002. A resolver that searches every lead accepts
    this and silently grades l-002's row against l-001's threshold."""
    _one_error(_r_impact_doc({"resolved_by": "l-002", "pred_ref": "ip1"}), "ip1")


def test_a_bare_prediction_ref_naming_nothing_at_all_is_refused() -> None:
    _one_error(_r_impact_doc({"pred_ref": "ip9"}), "ip9")


def test_a_qualified_prediction_ref_naming_an_undeclared_lead_is_refused() -> None:
    _one_error(_r_impact_doc({"pred_ref": "l-009.ip1"}), "l-009.ip1")


def test_a_qualified_prediction_ref_naming_a_real_lead_without_that_id_is_refused() -> None:
    """l-002 exists and declares `ip2`; it does not declare `ip1`. Resolution is (lead, id),
    not lead-exists-and-id-exists-somewhere."""
    _one_error(_r_impact_doc({"resolved_by": "l-002", "pred_ref": "l-002.ip1"}), "l-002.ip1")


def test_a_matching_dimension_validates_clean() -> None:
    assert _errors(
        _r_impact_doc({"resolved_by": "l-002", "pred_ref": "ip2", "dim": "scope"})
    ) == []


def test_a_dimension_that_disagrees_with_the_referenced_prediction_is_refused() -> None:
    """"`dimension` must match the referenced prediction's `dimension`." `ip1` was registered
    on confidentiality; grading it as availability re-labels the threshold after the fact,
    which is the retroactive-shift the whole impact axis is built to prevent."""
    _one_error(_r_impact_doc({"dim": "availability"}), "ip1")


def test_a_cross_lead_dimension_mismatch_is_refused_too() -> None:
    """The same check across the qualified form — a resolver that only compares within the
    emitting lead misses it."""
    _one_error(
        _r_impact_doc({"resolved_by": "l-002", "pred_ref": "l-001.ip1", "dim": "scope"}),
        "l-001.ip1",
    )


@pytest.mark.parametrize("verdict", ["within", "exceeds", "indeterminate"])
def test_every_legal_impact_verdict_on_a_resolution_is_accepted(verdict: str) -> None:
    assert _errors(_r_impact_doc({"verdict": verdict})) == []


@pytest.mark.parametrize(
    "verdict",
    ["none", "breached", "Exceeds", "authorized", "unauthorized"],
)
def test_an_off_enum_resolution_verdict_is_refused(verdict: str) -> None:
    """`none` and the two authz verdicts are in the list on purpose: `none` is legal on
    `conclude.impact_verdict` and illegal here, and `authorized`/`unauthorized` are what a
    check that reuses the `:R authz` verdict enum would wave through."""
    _one_error(_r_impact_doc({"verdict": verdict}), verdict)


@pytest.mark.parametrize(
    "grounding", ["telemetry-baseline", "business-owner-attestation", "dlp-policy"]
)
def test_every_legal_impact_grounding_kind_is_accepted(grounding: str) -> None:
    assert _errors(_r_impact_doc({"grounding": grounding})) == []


def test_past_case_grounding_on_an_impact_resolution_is_refused() -> None:
    """Called out by name in the rule: "`past-case` is forbidden on impact resolutions (impact
    is per-instance reasoning, not category-of-event)." It is also the one off-enum value that
    is legal on a neighbouring row shape (`:R authz`), so a shared grounding enum accepts it."""
    _one_error(_r_impact_doc({"grounding": "past-case"}), "past-case")


@pytest.mark.parametrize("grounding", ["org-authority", "runtime-evidence", "Telemetry-Baseline"])
def test_an_off_enum_impact_grounding_kind_is_refused(grounding: str) -> None:
    """`org-authority` is the other authz-side member — legal there, not here, because an
    authority answers permission and not consequence."""
    _one_error(_r_impact_doc({"grounding": grounding}), grounding)


@pytest.mark.parametrize(
    ("cell", "token"),
    [
        ("verdict", "verdict"),
        ("grounding", "grounding_kind"),
        ("authority", "authority_for_question"),
        ("as_of", "as_of"),
        ("reasoning", "reasoning"),
    ],
)
def test_an_impact_resolution_missing_a_required_field_is_refused(cell: str, token: str) -> None:
    """"Required fields: `prediction_ref`, `dimension`, `verdict`, `grounding_kind`,
    `authority_for_question`, `as_of`, `reasoning`." The first two get their own tests above
    (they also carry resolution and match obligations); the remaining five are here.

    The token asserted is the CANONICAL field name, not the column alias
    (`parser._RESOLUTION_KEY_CANONICAL` maps `grounding`→`grounding_kind`,
    `authority`→`authority_for_question`), because the header spelling is the author's choice
    and the message has to name the field the rule names.
    """
    _one_error(_r_impact_doc({cell: ""}), token)


def test_an_impact_resolution_with_no_prediction_ref_is_refused() -> None:
    _one_error(_r_impact_doc({"pred_ref": ""}), "prediction_ref")


def test_an_impact_resolution_with_no_dimension_is_refused() -> None:
    _one_error(_r_impact_doc({"dim": ""}), "dimension")


def test_two_resolutions_may_fulfil_two_different_predictions() -> None:
    """Liveness control across the whole family: the ordinary multi-threshold shape, one row
    per pre-registered predicate, must stay writable."""
    assert _errors(
        _r_impact_doc(
            {"resolved_by": "l-001", "pred_ref": "ip1", "dim": "confidentiality"},
            {
                "resolved_by": "l-002",
                "pred_ref": "ip2",
                "dim": "scope",
                "verdict": "within",
                "observed": "no prefix outside s3://prod-data/reports/ was read",
                "grounding": "dlp-policy",
                "reasoning": '"DLP scan covered the whole session window"',
            },
        )
    ) == []


# --------------------------------------------------------------------------- #
# rule #31 — impact closure at CONCLUDE, plus the verdict/severity pair
# --------------------------------------------------------------------------- #


def _impact_closure_doc(
    *,
    preds: str,
    resolutions: str = "",
    deferred: str = "",
    impact_verdict: str = "exceeds",
    impact_severity: str | None = "moderate",
) -> str:
    return _doc(
        _PROLOGUE,
        _LEADS,
        preds,
        resolutions,
        _conclude(impact_verdict=impact_verdict, impact_severity=impact_severity),
        deferred or _deferred_impact(),
    )


_ONE_IMPACT_PRED = _impact_preds("l-001")
_TWO_IMPACT_PREDS = _impact_preds(
    "l-001",
    {"id": "ip1"},
    {"id": "ip2", "dim": "scope", "claim": '"no object outside the sanctioned prefix is read"'},
)


def test_an_impact_prediction_with_a_fulfilling_resolution_closes_clean() -> None:
    """Liveness control for #31 arm (a)."""
    assert _errors(
        _impact_closure_doc(preds=_ONE_IMPACT_PRED, resolutions=_r_impact())
    ) == []


def test_an_impact_prediction_deferred_with_a_rationale_closes_clean() -> None:
    """Liveness control for #31 arm (b). The reference is the cross-lead identity rule #29
    defines, `l-{lead_id}.ip{n}` — rule #31 does not restate the shape, and the bare `ip1`
    would be unresolvable in a document-level table where no lead is in scope."""
    doc = _impact_closure_doc(
        preds=_ONE_IMPACT_PRED,
        deferred=_deferred_impact('l-001.ip1|"volume telemetry adapter was down for the window"'),
        impact_verdict="indeterminate",
        impact_severity="low",
    )
    assert _errors(doc) == []


def test_an_impact_prediction_deferred_with_an_empty_rationale_is_refused() -> None:
    doc = _impact_closure_doc(
        preds=_ONE_IMPACT_PRED,
        deferred=_deferred_impact("l-001.ip1|"),
        impact_verdict="indeterminate",
        impact_severity="low",
    )
    _one_error(doc, "ip1")


def test_an_impact_prediction_neither_resolved_nor_deferred_is_refused() -> None:
    doc = _impact_closure_doc(
        preds=_ONE_IMPACT_PRED, impact_verdict="indeterminate", impact_severity="low"
    )
    _one_error(doc, "ip1")


def test_one_impact_prediction_resolved_and_the_other_deferred_closes_clean() -> None:
    doc = _impact_closure_doc(
        preds=_TWO_IMPACT_PREDS,
        resolutions=_r_impact(),
        deferred=_deferred_impact('l-001.ip2|"DLP scope report did not cover this bucket"'),
    )
    assert _errors(doc) == []


def test_one_impact_prediction_resolved_and_the_other_abandoned_is_refused() -> None:
    """Per prediction, not per lead: grading `ip1` must not discharge `ip2` beside it."""
    doc = _impact_closure_doc(preds=_TWO_IMPACT_PREDS, resolutions=_r_impact())
    _one_error(doc, "ip2")


def test_an_unresolved_impact_prediction_without_a_conclude_block_is_not_yet_a_failure() -> None:
    """Same REPORT-boundary gating as #26 — mid-run the threshold is simply not graded yet."""
    assert _errors(_doc(_PROLOGUE, _LEADS, _ONE_IMPACT_PRED)) == []


def test_deferred_impact_predictions_project_onto_the_conclude_block() -> None:
    doc = _impact_closure_doc(
        preds=_ONE_IMPACT_PRED,
        deferred=_deferred_impact('l-001.ip1|"volume telemetry adapter was down for the window"'),
        impact_verdict="indeterminate",
        impact_severity="low",
    )
    body, warnings = parse_dense_companion(doc)
    assert warnings == []
    deferred = body["conclude"]["deferred_impact_predictions"]
    assert [d["prediction_ref"] for d in deferred] == ["l-001.ip1"]


# --- #31's `impact_verdict` enum -------------------------------------------- #


def _verdict_doc(impact_verdict: str, impact_severity: str | None) -> str:
    """A closed companion carrying one graded threshold, so the closure half of #31 is always
    satisfied and only the verdict/severity half is under test."""
    return _doc(
        _PROLOGUE,
        _LEADS,
        _ONE_IMPACT_PRED,
        _r_impact({"verdict": "exceeds"}),
        _conclude(impact_verdict=impact_verdict, impact_severity=impact_severity),
        _deferred_impact(),
    )


def test_impact_verdict_none_is_legal_on_a_companion_that_declared_no_thresholds() -> None:
    """"`impact_verdict: none` means the investigation declared no impact predicates." So the
    member is tested on the document shape it describes, with no `impact_preds` block at
    all."""
    doc = _doc(_PROLOGUE, _LEADS, _conclude(impact_verdict="none"), _deferred_impact())
    assert _errors(doc) == []


@pytest.mark.parametrize(
    ("impact_verdict", "impact_severity"),
    [("within", None), ("exceeds", "moderate"), ("indeterminate", "low")],
)
def test_every_other_legal_impact_verdict_is_accepted(
    impact_verdict: str, impact_severity: str | None
) -> None:
    """Each member paired with the severity its own conditional-presence clause demands, so
    this test reads the enum and nothing else."""
    assert _errors(_verdict_doc(impact_verdict, impact_severity)) == []


@pytest.mark.parametrize(
    "impact_verdict",
    [
        "none-detected",              # what examples/example-c ships today
        "attempted-lateral-movement",  # what fixtures-e2e/golden-sshpivot-ab3 ships today
        "Within",                     # wrong case
        "unclear",                    # a `disposition` value, one axis over
        "exceeded",                   # near miss
    ],
)
@pytest.mark.xfail(
    strict=True,
    reason="`conclude.impact_verdict` is TAUGHT and not ARMED. `skills/invlang/SKILL.md` "
    "has never stated the vocabulary, and both shipped e2e goldens already hold a value "
    "outside it (`none-detected`, `attempted-lateral-movement`) in recorded runs replayed "
    "through this very gate — so arming it refuses the recorded write. Registered in "
    "`vocab.SLOTS` as the teaching step; recorded at rule #31 in "
    "`docs/investigation-language.md` and as the second 'Open, from #933' item in the "
    "enforcement ramp.",
)
def test_an_off_enum_impact_verdict_is_refused(impact_verdict: str) -> None:
    """`conclude.impact_verdict ∈ {none, within, exceeds, indeterminate}`.

    The first two entries are the reason this test matters beyond the enum: they are LIVE
    values in shipped documents (`examples/example-c-cumulative-escalation.md`,
    `defender/fixtures-e2e/golden-*/investigation.md`, and both
    `_golden_invlang/*.companion.json`). `test_shipped_invlang_documents.py` demands every
    shipped document be gate-clean, so #31's enum cannot land until those files are corrected.
    That is a real cost of the rule and it should be paid deliberately, not discovered.

    No `impact_severity` row, so the conditional-presence clause cannot contribute a second
    finding whichever way it reads an unrecognised verdict.
    """
    _one_error(_verdict_doc(impact_verdict, None), impact_verdict)


# --- #31's `impact_severity` conditional presence ---------------------------- #


@pytest.mark.parametrize("impact_severity", ["low", "moderate", "high"])
@pytest.mark.parametrize("impact_verdict", ["exceeds", "indeterminate"])
def test_severity_is_required_and_may_be_any_member_when_the_verdict_demands_it(
    impact_verdict: str, impact_severity: str
) -> None:
    """Required-and-present, across both demanding verdicts and all three non-null members."""
    assert _errors(_verdict_doc(impact_verdict, impact_severity)) == []


@pytest.mark.parametrize("impact_verdict", ["exceeds", "indeterminate"])
def test_severity_absent_under_a_verdict_that_requires_it_is_refused(impact_verdict: str) -> None:
    """Required-and-absent."""
    _one_error(_verdict_doc(impact_verdict, None), "impact_severity")


@pytest.mark.parametrize("impact_verdict", ["exceeds", "indeterminate"])
def test_an_explicit_null_severity_under_a_demanding_verdict_is_refused(
    impact_verdict: str,
) -> None:
    """`impact_severity null` is the format's spelling of absence (the parser projects it as
    `None`), so it has to fail wherever omitting the row fails — otherwise the required arm is
    satisfied by writing the word "null"."""
    _one_error(_verdict_doc(impact_verdict, "null"), "impact_severity")


@pytest.mark.parametrize("impact_severity", ["low", "moderate", "high"])
def test_a_severity_under_verdict_within_is_refused(impact_severity: str) -> None:
    """Forbidden-and-present. "`impact_severity` is null unless `impact_verdict ∈ {exceeds,
    indeterminate}`" — `within` means every threshold cleared, so there is no severity to
    report and a number here is a claim the resolutions do not carry."""
    _one_error(_verdict_doc("within", impact_severity), "impact_severity")


def test_a_severity_under_verdict_none_is_refused() -> None:
    """Forbidden-and-present on the other non-demanding member — `none` and `within` are
    different states (nothing declared vs everything cleared) and a check pinned by one leaves
    the other open."""
    doc = _doc(
        _PROLOGUE,
        _LEADS,
        _conclude(impact_verdict="none", impact_severity="high"),
        _deferred_impact(),
    )
    _one_error(doc, "impact_severity")


@pytest.mark.parametrize("impact_verdict", ["within", "none"])
def test_no_severity_under_a_verdict_that_forbids_it_is_clean(impact_verdict: str) -> None:
    """Forbidden-and-absent — the liveness control for the severity truth table."""
    doc = (
        _doc(_PROLOGUE, _LEADS, _conclude(impact_verdict="none"), _deferred_impact())
        if impact_verdict == "none"
        else _verdict_doc("within", None)
    )
    assert _errors(doc) == []


@pytest.mark.parametrize("impact_verdict", ["within", "none"])
def test_an_explicit_null_severity_under_a_verdict_that_forbids_it_is_clean(
    impact_verdict: str,
) -> None:
    """The other half of forbidden-and-absent: writing the row as `null` is the canonical
    spelling in `dense-investigation-format.md`'s own worked example, so a check reading
    "the row is present" rather than "a severity was stated" refuses the shipped shape."""
    doc = (
        _doc(
            _PROLOGUE,
            _LEADS,
            _conclude(impact_verdict="none", impact_severity="null"),
            _deferred_impact(),
        )
        if impact_verdict == "none"
        else _verdict_doc("within", "null")
    )
    assert _errors(doc) == []


@pytest.mark.parametrize("impact_severity", ["critical", "Moderate", "medium", "severe"])
@pytest.mark.xfail(
    strict=True,
    reason="`conclude.impact_severity` is TAUGHT and not ARMED, with "
    "`conclude.impact_verdict` — the two are one decision (`vocab.IMPACT_SEVERITY`). It "
    "measures zero fires on the corpus, but a vocabulary the runtime prompt never stated "
    "is not one a run can be refused on. Same record: rule #31 in "
    "`docs/investigation-language.md`, 'Open, from #933' in the enforcement ramp.",
)
def test_an_off_enum_impact_severity_is_refused(impact_severity: str) -> None:
    """`conclude.impact_severity ∈ {null, low, moderate, high}`. `severe` is in the list
    because it IS a member of the neighbouring `severity_of_test` enum on `:T resolutions`, and
    `medium` because it is a member of `confidence` two rows up in the same block."""
    _one_error(_verdict_doc("exceeds", impact_severity), impact_severity)


# --------------------------------------------------------------------------- #
# rule #34 — prediction closure at CONCLUDE
# --------------------------------------------------------------------------- #

_PRED_HYPOTHESES = """\
:H hypothesize.hypotheses [id|name|attached_to|rel|parent_type|parent_class|integrity_waived?|weight|status]
h-001|?scheduled-service-retry|v-002|runs_on|process|??||null|active"""

_H1_PREDS = """\
:H h-001.preds [id|subject|claim]
p1|proposed_parent|"failures repeat on a fixed interval"
p2|proposed_parent|"the caller image is the documented monitoring binary\""""

_H1_ONE_PRED = """\
:H h-001.preds [id|subject|claim]
p1|proposed_parent|"failures repeat on a fixed interval\""""

_H1_ATTR_PRED = """\
:H h-001.attr_preds [id|target|attribute|claim]
ap1|attached_vertex|signing|"the image is signed by the corp CA\""""

_H1_REFUT = """\
:H h-001.refuts [id|refutes|claim]
r1|p1|"failures arrive in bursts with no fixed interval\""""


def _resolutions(*rows: str) -> str:
    return "\n".join([":T resolutions", *rows])


def _cites(ids: str, after: str = "+", severity: str = "moderate") -> str:
    return f"h-001  null → {after}   [l-001 {ids} {severity} ⟂ e-001 :: the series is cadenced]"


def _pred_closure_doc(
    *,
    preds: str = _H1_ONE_PRED,
    attr_preds: str = "",
    refuts: str = "",
    resolutions: str | None = None,
    deferred: str = "",
) -> str:
    """`resolutions=None` writes the default `p1` citation; `resolutions=""` writes no
    `:T resolutions` block at all."""
    if resolutions is None:
        resolutions = _resolutions(_cites("p1"))
    return _doc(
        _PROLOGUE,
        _PRED_HYPOTHESES,
        preds,
        attr_preds,
        refuts,
        _LEADS,
        resolutions,
        _conclude(),
        deferred or _deferred_preds(),
    )


def test_a_prediction_cited_by_a_resolution_closes_clean() -> None:
    """Liveness control for #34 arm (a)."""
    assert _errors(_pred_closure_doc()) == []


def test_a_prediction_deferred_with_a_rationale_closes_clean() -> None:
    """Liveness control for #34 arm (b). "Each `deferred_predictions[]` entry has
    `prediction_ref: h-{id}.{p|ap}{n}` and `rationale: "<why>"`.\""""
    doc = _pred_closure_doc(
        preds=_H1_PREDS,
        resolutions=_resolutions(_cites("p1")),
        deferred=_deferred_preds('h-001.p2|"the image-identity lead never returned"'),
    )
    assert _errors(doc) == []


def test_a_prediction_deferred_with_an_empty_rationale_is_refused() -> None:
    """"listed in `conclude.deferred_predictions[]` with a NON-EMPTY rationale" — naming the
    id without saying why is the walked-past prediction with paperwork."""
    doc = _pred_closure_doc(
        preds=_H1_PREDS,
        resolutions=_resolutions(_cites("p1")),
        deferred=_deferred_preds("h-001.p2|"),
    )
    _one_error(doc, "p2")


def test_a_prediction_neither_cited_nor_deferred_is_refused() -> None:
    doc = _pred_closure_doc(preds=_H1_PREDS, resolutions=_resolutions(_cites("p1")))
    _one_error(doc, "p2")


def test_a_prediction_cited_only_by_a_resolution_with_a_null_after_is_refused() -> None:
    """"cited in some resolution's `matched_prediction_ids[]` WITH A NON-NULL `after`". A row
    that names the prediction and moves the weight nowhere records that the prediction was
    looked at, not that it was graded — which is exactly the state the rule asks the run to
    justify instead of glossing."""
    doc = _pred_closure_doc(resolutions=_resolutions(_cites("p1", after="null", severity="weak")))
    _one_error(doc, "p1")


def test_a_prediction_cited_by_a_null_move_and_then_graded_closes_clean() -> None:
    """The liveness control for the clause above: one ungraded look followed by a real one
    closes, so the check reads "some resolution", not "the last one"."""
    doc = _pred_closure_doc(
        resolutions=_resolutions(
            _cites("p1", after="null", severity="weak"),
            _cites("p1"),
        )
    )
    assert _errors(doc) == []


def test_an_attribute_prediction_must_close_too() -> None:
    """"every declared `predictions[].id` (`p*`) AND `attribute_predictions[].id` (`ap*`)". The
    `ap*` half is the one a check written off `predictions[]` alone silently skips."""
    doc = _pred_closure_doc(attr_preds=_H1_ATTR_PRED, resolutions=_resolutions(_cites("p1")))
    _one_error(doc, "ap1")


def test_an_attribute_prediction_cited_by_a_resolution_closes_clean() -> None:
    doc = _pred_closure_doc(
        attr_preds=_H1_ATTR_PRED, resolutions=_resolutions(_cites("p1,ap1"))
    )
    assert _errors(doc) == []


def test_an_attribute_prediction_deferred_with_a_rationale_closes_clean() -> None:
    doc = _pred_closure_doc(
        attr_preds=_H1_ATTR_PRED,
        resolutions=_resolutions(_cites("p1")),
        deferred=_deferred_preds('h-001.ap1|"the collector does not expose signing metadata"'),
    )
    assert _errors(doc) == []


def test_predictions_on_a_refuted_hypothesis_are_exempt() -> None:
    """"on a hypothesis whose final status is not `refuted`". `:H` rows are immutable, so
    `--` on the resolution chain is the only way a run can say "refuted" after the fact — which is also how `_check_benign_authz` already reads survival."""
    doc = _pred_closure_doc(
        preds=_H1_PREDS,
        refuts=_H1_REFUT,
        resolutions=_resolutions(
            "h-001  null → --   [l-001 r1 severe ⟂ e-001 :: the series is bursty, not cadenced]"
        ),
    )
    assert _errors(doc) == []


def test_predictions_on_a_live_hypothesis_are_not_exempt() -> None:
    """The control for both exemptions: the same document with the hypothesis left active must
    fail, or the two tests above are passing because the rule refuses nothing."""
    doc = _pred_closure_doc(preds=_H1_PREDS, resolutions=_resolutions(_cites("p1")))
    _one_error(doc, "p2")


def test_one_prediction_cited_and_the_other_deferred_closes_clean() -> None:
    doc = _pred_closure_doc(
        preds=_H1_PREDS,
        attr_preds=_H1_ATTR_PRED,
        resolutions=_resolutions(_cites("p1")),
        deferred=_deferred_preds(
            'h-001.p2|"the image-identity lead never returned"',
            'h-001.ap1|"the collector does not expose signing metadata"',
        ),
    )
    assert _errors(doc) == []


def test_one_prediction_cited_and_the_other_abandoned_is_refused_for_the_orphan_only() -> None:
    """Per prediction, not per hypothesis: grading `p1` must not discharge `p2` beside it. The
    exact count is what catches a check that stops at the first citation it finds."""
    doc = _pred_closure_doc(
        preds=_H1_PREDS,
        attr_preds=_H1_ATTR_PRED,
        resolutions=_resolutions(_cites("p1,ap1")),
    )
    _one_error(doc, "p2")


def test_an_uncited_prediction_without_a_conclude_block_is_not_yet_a_failure() -> None:
    """The late gate is the REPORT boundary — rule #6 is the early one, and it fires only on
    `++`. A mid-run companion owes nothing yet."""
    doc = _doc(_PROLOGUE, _PRED_HYPOTHESES, _H1_PREDS, _LEADS, _resolutions(_cites("p1")))
    assert _errors(doc) == []


def test_deferred_predictions_project_onto_the_conclude_block() -> None:
    doc = _pred_closure_doc(
        preds=_H1_PREDS,
        resolutions=_resolutions(_cites("p1")),
        deferred=_deferred_preds('h-001.p2|"the image-identity lead never returned"'),
    )
    body, warnings = parse_dense_companion(doc)
    assert warnings == []
    deferred = body["conclude"]["deferred_predictions"]
    assert [d["prediction_ref"] for d in deferred] == ["h-001.p2"]
