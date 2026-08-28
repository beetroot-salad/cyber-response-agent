"""The SHAPE of a row, and the closed vocabularies its cells may draw from.

One family of `validate.py`'s rules, split out at 4038 lines. Where `_refs` asks whether
a cited id resolves, these rules ask whether the row carrying it is filled in at all.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from . import _walkers, vocab
from ._cells import _unquote
from .schema import (
    CompanionBody,
    ImpactPrediction,
)
from ._refs import _LEAD_PRED_ID_RE, _known_ids, _leads
from ._predictions import auth_kind_of


def _check_vocab(value: Any, allowed: Any, errmsg: str) -> list[str]:
    if isinstance(value, str) and value and value not in allowed:
        return [errmsg]
    return []


def _cell(record: Mapping[str, object], key: str) -> str:
    """One cell of a projected row as stripped, UNQUOTED text, read by a column name held in a
    variable.

    A TypedDict `.get()` with a non-literal key is typed `object`, so a loop over a tuple of
    required columns cannot call `.strip()` on the result. Every projected cell is a `str`;
    stating that once here beats a cast at each of the sites that walk a column list.

    `_unquote`d because the two sides of the impact axis disagree about quoting and the checks
    have to see through it. `_impact_pred_row` unquotes `dim` and `claim`; the `:R impact` row
    beside it goes through `_canonicalize_resolution_row`, which copies every cell verbatim —
    so an author who wraps cells uniformly registers `confidentiality` and grades
    `"confidentiality"`, and the enum tests and the `dim`-vs-predicate comparison refuse a row
    whose values are all correct. It is a BELT over the parser's braces elsewhere rather than
    in place of them: `_lead_header_record` already unquotes its cells on the way in, and
    unquoting an unquoted cell is identity — so a projector that grows a new lead column still
    meets a closed-set comparison the way the rule means it.

    Stripped on BOTH sides of the unquote. Stripping only before it leaves the padding INSIDE a
    quoted cell, so `" confidentiality "` reads as a padded `confidentiality` — and the two
    halves of every comparison below then disagree about a value they spell identically, on
    committed rows neither side can rewrite. `is_conclude_empty_marker` reads a cell the same
    way, and for the same reason.
    """
    value = record.get(key)
    return _unquote(value.strip()).strip() if isinstance(value, str) else ""


#: The two destinations an `advance_to` may name that are not a lead. `CONCLUDE` ends the run;
#: `HYPOTHESIZE` sends it back for a mechanism the plan did not have.
#:
#: `docs/dense-investigation-format.md` §`:L` wrote `PREDICT` for the second in one worked
#: example. That is the PHASE name for the block `:H hypothesize.hypotheses` lives in, not a
#: third sentinel — spec rule #18 names these two, so the doc's example was corrected rather
#: than the enum widened. Widening it instead would have meant accepting two spellings of one
#: destination and, with `REPORT` beside `CONCLUDE` by the same argument, four.
_ROUTE_SENTINELS: tuple[str, ...] = ("CONCLUDE", "HYPOTHESIZE")

#: `:L l-NNN.lead_preds`' three content cells, each with what a BLANK one costs. The `if`
#: column projects as `condition` (`if` cannot be a TypedDict key); everything the author sees
#: uses the column spelling.
_LEAD_PRED_CELLS: tuple[tuple[str, str, str], ...] = (
    (
        "condition", "if",
        "the row pre-commits to WHICH result sends the run down this branch, and a blank cell "
        "branches on nothing",
    ),
    (
        "read_as", "read_as",
        "the row says what that result MEANS, and a blank cell commits to no reading — which "
        "is the whole reason a route is registered before the data lands rather than chosen "
        "after it",
    ),
    (
        "advance_to", "advance_to",
        "the row names WHERE that reading routes, and a blank cell routes nowhere",
    ),
)


def _check_lead_prediction_structure(companion: CompanionBody) -> list[str]:
    """`:L l-NNN.lead_preds` rows — a lead's pre-committed ROUTE, checked for the four things
    that make a route followable.

    A route is not a prediction about the world; it is a prediction about the RUN. Nothing
    grades an `lp*`, no resolution head can cite one, and `_check_tested_commitment_refs`
    leaves an `lp*` alone. What it buys is that the interpretation was fixed before the data
    arrived — so the cells that matter are the ones that make it a commitment: a condition, the
    reading that condition licenses, and where that reading goes next. `_lead_pred_row`
    `_require`s only `id` and never looks at what any cell says, so `lp1|||` parses clean and
    lands a route committing to nothing.

    `advance_to` is a hard reference: a lead NAME some `:L findings` row declares, or a
    sentinel. Resolved against every declared lead INCLUDING the declaring one. The spec says
    "elsewhere in the companion", and the only ordering the dense surface carries is
    `:L findings` DOCUMENT ORDER — under which "elsewhere" can only mean "not this row", so
    enforcing it would refuse a self-route and nothing else. That is left alone deliberately:
    two loops may declare same-named leads under different ids, and there is no cell that says
    which one a name means, so a self-route test can be wrong where accepting one costs
    nothing. A destination that does not exist YET is refused, the way `_check_lead_refs`
    refuses a forward `l-*`: PLAN writes its `:L findings` rows before the routes that point
    at them, so the ordering the rule demands is the ordering PLAN already has.

    UNIQUENESS is not checked, for the reason `_check_attribute_prediction_structure` records
    at length: `_warn_repeated_ids` makes a repeat within one block a parse error and
    `_extend_by_id` keeps the first record per id across blocks, so a duplicate never reaches
    this list — and refusing the cross-block case would refuse the documented append shape.

    NOT checked: the ROUTE-COMPLIANCE clause. "Followed by another lead" would read as the
    next `:L findings` row in DOCUMENT ORDER — the ordering `_check_screen_structure`'s
    intermediate arm used for "the final lead in a SCREEN sequence" until v2.22 STRUCK it, and
    that strike is now a second reason not to arm this clause: it has the same shape, refusing
    a committed row for which lead FOLLOWS it. The CHANNEL blocks it independently: spec
    rule #18 asks for a WARNING, and there is no honest way to emit one here. A warn
    diagnostic without a `Locus` is dropped by
    `runtime/tools._addressable` and does nothing at all; a warn diagnostic WITH one FLAGS that
    row and blocks every later write until `fix_row` rewrites it — and both candidate rows must
    not be rewritten. The follower's `:L findings` row is a committed lead declaration, which
    the warn family has never been able to reach (`_tool_fix_row`: "the warn family walks
    `:R attr_updates` blocks and nothing else"). The `lead_preds` row is worse: letting a run
    edit its own pre-registration to match where it ended up destroys the only thing
    pre-registration is for. See the enforcement ramp for the deferral.
    """
    # Through `_cell`, which unquotes AND strips — `_lead_header_record` does neither to the
    # `name` it lands, while `advance_to` is unquoted by `_lead_pred_row` and stripped below.
    # Without one reading for both halves, a document that quotes its cells uniformly (or
    # pads one) is refused with a message listing the destination among the names it says do
    # not match. The declaring row is a committed `:L findings` row the author cannot rewrite,
    # so the refusal has no repair.
    #
    # ONE `_leads` walk, bound: the destination set and the loop below ask the same list.
    leads = _leads(companion)
    names = {
        _cell(f, "name") for f in leads
        if isinstance(f.get("name"), str) and f["name"]
    } - {""}
    destinations = names | set(_ROUTE_SENTINELS)
    errors: list[str] = []
    for lead in leads:
        lid = lead.get("id", "?")
        for lp in lead.get("predictions") or []:
            if not isinstance(lp, dict):
                continue
            lpid = lp.get("id") or "?"
            where = f"`:L {lid}.lead_preds` row {lpid!r}"
            if not _LEAD_PRED_ID_RE.fullmatch(lpid):
                errors.append(
                    f"{where}: a lead-level route is numbered `lp<n>` — the namespace is what "
                    f"keeps a route out of the `p*`/`ap*`/`r*` a resolution head and "
                    f"`:L findings`' `tests` column resolve against, so a route spelled `p1` "
                    f"collides with the hypothesis prediction of that name at both sites"
                )
            for key, column, cost in _LEAD_PRED_CELLS:
                if not _cell(lp, key):
                    errors.append(f"{where}: empty `{column}` — {cost}")
            dest = _cell(lp, "advance_to")
            if dest and dest not in destinations:
                errors.append(
                    f"{where}: `advance_to` names {dest!r}, which is neither a lead NAME this "
                    f"document declares ({_known_ids(names)}) nor one of "
                    f"{', '.join(_ROUTE_SENTINELS)} — the cell carries the lead's `name`, not "
                    f"its `l-*` id, and a route nobody can follow is not a plan"
                )
    return errors


_IMPACT_PRED_ID_RE = re.compile(r"ip\d+")

#: `:L l-NNN.impact_preds`' six required cells, spelled as the CANONICAL key the projector
#: emits — the same choice `_IMPACT_RESOLUTION_REQUIRED` makes and for the same reason: `dim`
#: projects as `dimension` (`_impact_pred_row`), and naming the column alias sends a reader
#: looking up a name the spec does not use. Grouped rather than spelled out one branch apiece
#: because they fail the same way and for the same reason: the row is a PREDICATE, and a
#: predicate missing its axis or one of its outcomes cannot be graded on that outcome.
_IMPACT_PRED_CELLS: tuple[str, ...] = (
    "dimension", "claim", "on_match", "on_mismatch", "on_indeterminate", "escalation_on",
)


def _check_impact_prediction_structure(companion: CompanionBody) -> list[str]:
    """`:L l-NNN.impact_preds` rows — the impact predicate a lead registers at PREDICT, checked
    for the cells that make it gradeable.

    Impact is the third axis: an authorized, uncompromised action can still be
    escalation-worthy if its consequence exceeds a threshold. What makes that checkable rather
    than a post-hoc judgment is that the threshold and BOTH of its outcomes are written down
    before the measurement lands — so a row with a `claim` and no `on_mismatch` has registered
    a number without registering what exceeding it means, and ANALYZE grades it whichever way
    the answer came out.

    `_impact_pred_row` `_require`s only `id`, so every cell below is present-and-empty rather
    than missing: `ip1|confidentiality|||||` parses clean today.

    `dimension` is closed (`vocab.IMPACT_DIMENSION`) because `:R impact` rows must MATCH it —
    `_check_impact_resolution_refs` compares the two, and a free-text dimension makes that
    comparison a string coincidence.

    NOT checked: the one-observable-per-entry clause. "Compound `AND` / `OR` / semicolon
    predicates must be split across entries" is a judgment about what a sentence asserts, not a
    property of the row, and a lexical test would refuse "session bytes and connection count
    stay within baseline" written about one measurement. Rule #33 leaves the identical clause
    to the author on `attribute_predictions[]`, and
    `_check_attribute_prediction_structure` records why.
    """
    errors: list[str] = []
    for lead in _leads(companion):
        lid = lead.get("id", "?")
        for ip in lead.get("impact_predictions") or []:
            if not isinstance(ip, dict):
                continue
            ipid = ip.get("id") or "?"
            where = f"`:L {lid}.impact_preds` row {ipid!r}"
            if not _IMPACT_PRED_ID_RE.fullmatch(ipid):
                errors.append(
                    f"{where}: an impact prediction is numbered `ip<n>` — a `:R impact` row's "
                    f"`pred_ref` resolves in that namespace, both bare and as the "
                    f"cross-lead `{lid}.ip<n>`, so an id outside it can be graded by nothing"
                )
            # Through `_cell`, like every neighbouring read: `_impact_pred_row` unquotes `dim`
            # but does not re-strip it, so a uniformly quoted `" confidentiality "` reaches
            # here with its padding and a raw membership test refuses the row for naming an
            # axis it names correctly. Reading it twice — raw for the enum, stripped for the
            # blank test — also drew TWO refusals for one whitespace-only cell.
            dimension = _cell(ip, "dimension")
            errors += _check_vocab(
                dimension, vocab.IMPACT_DIMENSION,
                f"{where}: dimension {dimension!r} is not one of "
                f"{', '.join(vocab.IMPACT_DIMENSION)} — the cell says which axis the "
                f"consequence is measured on, and `:R impact` grades against it",
            )
            # ONE error per ROW, not per column, for the reason
            # `_check_impact_resolution_refs` gives on the grading side: an under-filled row
            # is one defect, and seven near-identical refusals for one row bury every other
            # check. `dim` rides with them — the columns differ only in what each is for, and
            # the sentence below says that once.
            blank = [c for c in _IMPACT_PRED_CELLS if not _cell(ip, c)]
            if blank:
                errors.append(
                    f"{where}: empty {', '.join(f'`{c}`' for c in blank)} — an impact "
                    f"predicate registers its axis, its threshold AND every outcome before "
                    f"the measurement lands, so all of {', '.join(_IMPACT_PRED_CELLS)} are "
                    f"required; a blank cell lets ANALYZE decide that outcome after seeing "
                    f"the answer"
                )
    return errors


#: The `:R impact` cells rule #30 requires, spelled as the CANONICAL key the projector emits
#: — which is also the name the rule uses. `_RESOLUTION_KEY_CANONICAL` renames four of them
#: on the way in (`pred_ref` → `prediction_ref`, `dim` → `dimension`, `grounding` →
#: `grounding_kind`, `authority` → `authority_for_question`), and the refusal names the
#: FIELD rather than the column: the header spelling is the author's choice, so a message
#: naming the alias sends a reader looking up a name the spec does not use.
_IMPACT_RESOLUTION_REQUIRED: tuple[str, ...] = (
    "prediction_ref",
    "dimension",
    "verdict",
    "grounding_kind",
    "authority_for_question",
    "as_of",
    "reasoning",
)


def _qualify(lid: str, ref: str) -> str:
    """A `pred_ref` under its CROSS-LEAD identity: a bare `ip<n>` is scoped to the lead the row
    landed on, a qualified `l-NNN.ip<n>` already names its own.

    ONE owner, because rules #30 and #31 both resolve this cell and a document in which they
    resolve it differently is reported as graded by one and abandoned by the other — with a
    deferral row for a predicate the run did grade as the only exit.
    """
    return ref if "." in ref else f"{lid}.{ref}"


def _declared_impact_predictions(
    companion: CompanionBody,
) -> dict[str, ImpactPrediction]:
    """Every `ip*` in the document under its CROSS-LEAD identity `l-{id}.ip{n}` — the one
    spelling both reference forms resolve to."""
    out: dict[str, ImpactPrediction] = {}
    for lead in _leads(companion):
        lid = lead.get("id", "?")
        for ip in lead.get("impact_predictions") or []:
            if isinstance(ip, dict) and isinstance(ip.get("id"), str) and ip["id"]:
                out.setdefault(f"{lid}.{ip['id']}", ip)
    return out


def _check_impact_resolution_refs(companion: CompanionBody) -> list[str]:
    """`:R impact` rows — what each grades, how it graded it, and on what authority.

    The impact analog of `_check_prediction_refs`, and it exists for the same reason: nothing
    joins a `:R impact` row back to the `:L l-NNN.impact_preds` row it claims to grade. The
    projector canonicalizes `pred_ref` into a string and stops, so a typo, a forward reference
    and ANOTHER lead's `ip1` all land identically — and a verdict attached to no predicate is a
    consequence claim with no pre-registered threshold behind it, which is the one thing the
    impact axis exists to prevent.

    `dimension` is compared against the predicate's, not merely checked for membership. A row
    that grades an availability predicate under `confidentiality` has answered a question
    nobody asked, and the roll-up into `conclude.impact_verdict` cannot tell that from a real
    answer.

    `past-case` is refused by name rather than left to the enum's silence, because the omission
    is a judgment and not an oversight: impact is per-instance reasoning about what THIS event
    did, and a past case establishes what a CATEGORY of event was permitted to do. Rule #11
    excludes it from consultations for the neighbouring reason.

    NOT checked: whether the observation supports the verdict. `observed` is free text — "180GB
    (3σ above 60GB μ)" — and reading it against `claim` is the judgment ANALYZE is for. This
    checks that the row is ANSWERABLE, not that the answer is right.
    """
    declared = _declared_impact_predictions(companion)
    errors: list[str] = []
    #: Every verdict each `ip*` was graded to, to catch the predicate graded TWICE with
    #: different answers. `_check_impact_closure` asks only whether SOME row names the ref, so
    #: without this a run can register one threshold, grade it `exceeds` AND `within`, and roll
    #: up to whichever it prefers — the after-the-fact choice the whole pre-registration axis
    #: exists to prevent. The authz axis already refuses the analogous disagreement
    #: (`_authz_contract_error`: `bad = [v for v in rows if v != "authorized"]`).
    verdicts_by_ref: dict[str, set[str]] = {}
    for lead in _leads(companion):
        lid = lead.get("id", "?")
        for row in (lead.get("outcome") or {}).get("impact_resolutions") or []:
            if not isinstance(row, dict):
                continue
            # Every cell read through `_cell`, which unquotes: `_impact_pred_row` unquotes the
            # cells on the DECLARING side and `_canonicalize_resolution_row` unquotes nothing,
            # so reading these raw refuses a uniformly quoted row three times over for values
            # it spells correctly.
            raw_ref = _cell(row, "prediction_ref")
            where = f"lead {lid}: `:R impact` row for {raw_ref or '<no prediction_ref>'}"
            # ONE error per ROW, not per column: an under-filled row is one defect, and seven
            # near-identical refusals for one row would bury the six other checks below.
            blank = [key for key in _IMPACT_RESOLUTION_REQUIRED if not _cell(row, key)]
            if blank:
                errors.append(
                    f"{where}: empty {', '.join(f'`{c}`' for c in blank)} — an impact "
                    f"resolution carries a consequence verdict AND the provenance that makes "
                    f"it checkable, so all of "
                    f"{', '.join(_IMPACT_RESOLUTION_REQUIRED)} are required; a "
                    f"blank cell records the verdict without what it rests on"
                )
            verdict = _cell(row, "verdict")
            errors += _check_vocab(
                verdict, vocab.IMPACT_VERDICT,
                f"{where}: verdict {verdict!r} is not one of "
                f"{', '.join(vocab.IMPACT_VERDICT)} — the cell says whether the measurement "
                f"landed inside the registered threshold, not what was measured",
            )
            grounding = _cell(row, "grounding_kind")
            if grounding == "past-case":
                errors.append(
                    f"{where}: `grounding past-case` — impact is per-instance reasoning about "
                    f"what THIS event did, and a past case establishes only what a CATEGORY "
                    f"of event was permitted to do. Re-send this row grounded on "
                    f"{', '.join(vocab.IMPACT_GROUNDING)}. Deferring the predicate in "
                    f"`:T conclude.deferred_impact` does NOT clear this: the refusal is on the "
                    f"`:R impact` row, and append-only leaves it on disk"
                )
            else:
                errors += _check_vocab(
                    grounding, vocab.IMPACT_GROUNDING,
                    f"{where}: grounding {grounding!r} is not one of "
                    f"{', '.join(vocab.IMPACT_GROUNDING)}",
                )
            if not raw_ref:
                continue
            # Bare `ip{n}` is scoped to the lead the row landed on — the one the `resolved_by`
            # column named, which is the only lead that could have measured it.
            ref = _qualify(lid, raw_ref)
            pred = declared.get(ref)
            if pred is None:
                errors.append(
                    f"{where}: `prediction_ref` resolves to {ref!r}, which no "
                    f"`:L l-NNN.impact_preds` row declares (declared: "
                    f"{_known_ids(set(declared))}) — a bare `ip<n>` resolves within {lid} and "
                    f"a qualified `l-NNN.ip<n>` across leads; register the predicate before "
                    f"grading it"
                )
                continue
            if verdict:
                verdicts_by_ref.setdefault(ref, set()).add(verdict)
            # BOTH sides through `_cell`. `_impact_pred_row` unquotes `dim` but does not
            # re-strip it, so a declaring cell written `" confidentiality "` keeps its
            # padding — and a correct `:R impact` row grading `confidentiality` is then
            # refused for an axis it names correctly, on a committed `:L l-NNN.impact_preds`
            # row the author cannot rewrite. The blank test one screen up already reads the
            # predicate this way (`_check_impact_prediction_structure`); this is the same
            # read.
            dim, pred_dim = _cell(row, "dimension"), _cell(pred, "dimension")
            if dim and pred_dim and dim != pred_dim:
                errors.append(
                    f"{where}: `dimension {dim}` but {ref} was registered on {pred_dim!r} — a "
                    f"resolution grades the predicate it names, so the two axes have to be "
                    f"the same one; fix the column, or point `pred_ref` at the predicate this "
                    f"row actually measured"
                )
    errors += [
        f"impact prediction {ref}: graded {', '.join(sorted(seen))} by different "
        f"`:R impact` rows — a predicate registers ONE threshold and the measurement lands "
        f"inside it or outside it, so two verdicts on one `ip<n>` let the close pick which of "
        f"its own answers to be measured against. Keep the grading that measured the "
        f"registered claim, or register a second predicate for the second measurement"
        for ref, seen in sorted(verdicts_by_ref.items())
        if len(seen) > 1
    ]
    return errors


def _check_vocab_vertices(companion: CompanionBody) -> list[str]:
    errors: list[str] = []
    for v in _walkers.all_vertices(companion):
        t = v.get("type")
        errors += _check_vocab(
            t, vocab.TYPES,
            f"vertex {v.get('id', '?')}: type {t!r} is not a known vertex "
            f"type (`enum types`)",
        )
    return errors


def _check_vocab_edges(companion: CompanionBody) -> list[str]:
    errors: list[str] = []
    for e in _walkers.all_edges(companion):
        rel = e.get("relation")
        errors += _check_vocab(
            rel, vocab.RELATIONS,
            f"edge {e.get('id', '?')}: rel {rel!r} is not a known relation "
            f"(`enum relations`)",
        )
        kind = auth_kind_of(e)
        errors += _check_vocab(
            kind, vocab.AUTH_KINDS,
            f"edge {e.get('id', '?')}: auth_kind {kind!r} is not a known "
            f"observational authority (`enum auth-kinds`)",
        )
    return errors


def _check_vocab_hypotheses(companion: CompanionBody) -> list[str]:
    errors: list[str] = []
    for h in _walkers.all_hypotheses(companion).values():
        pv = (h.get("proposed_edge") or {}).get("parent_vertex") or {}
        pt = pv.get("type")
        errors += _check_vocab(
            pt, vocab.TYPES,
            f"hypothesis {h.get('id', '?')}: parent_type {pt!r} is not a "
            f"known vertex type (`enum types`)",
        )
        rel = (h.get("proposed_edge") or {}).get("relation")
        errors += _check_vocab(
            rel, vocab.RELATIONS,
            f"hypothesis {h.get('id', '?')}: rel {rel!r} is not a known "
            f"relation (`enum relations`)",
        )
    return errors


def _check_vocab_weights(companion: CompanionBody) -> list[str]:
    """The two cells that carry a weight, against the bucket list plus `null`.

    The one enum in the language that had no arm here, and the gap was not inert: every
    weight-keyed gate reads one of these two cells and every one of them is a membership test,
    so an off-vocabulary token skips all of them at once. `h-001 null → confirmed` cleared the
    strong-move provenance gate (which fires on `STRONG_WEIGHTS`), the `++` coverage gate
    (which fires on `CONFIRMED_WEIGHT`) and the refutation-citation gate, where the honest
    `++` is refused for the predictions it leaves open — while `_walkers.final_weights`
    propagated the token verbatim and reported the hypothesis live. One typo was strictly
    better for the author than telling the truth.

    `:H`'s cell is checked as well as the resolution's: `_hypothesis_record` maps `null` to
    `None` and stores anything else verbatim, so a weight declared at birth is the same
    unvalidated token by another route.
    """
    errors: list[str] = []
    for hid, h in _walkers.all_hypotheses(companion).items():
        errors += _check_vocab(
            h.get("weight"), vocab.WEIGHT_CELL_VALUES,
            f"hypothesis {hid}: weight {h.get('weight')!r} is not a weight — a `:H` row's "
            f"cell is one of {', '.join(vocab.WEIGHT_CELL_VALUES)}",
        )
    for lid, res in _walkers.iter_resolutions(companion):
        for cell in ("before", "after"):
            errors += _check_vocab(
                res.get(cell), vocab.WEIGHT_CELL_VALUES,
                f"lead {lid}: resolution of {res.get('hypothesis', '?')} has "
                f"{cell} {res.get(cell)!r}, which is not a weight — the cells either side of "
                f"the arrow are one of {', '.join(vocab.WEIGHT_CELL_VALUES)}; a token outside "
                f"the list moves nothing and skips every gate that reads the grade",
            )
    return errors


def _check_vocab_anchor_kinds(companion: CompanionBody) -> list[str]:
    errors: list[str] = []
    for h in _walkers.all_hypotheses(companion).values():
        for c in h.get("authorization_contract") or []:
            if not isinstance(c, dict):
                continue
            ak = c.get("anchor_kind")
            errors += _check_vocab(
                ak, vocab.ANCHOR_KINDS,
                f"hypothesis {h.get('id', '?')} contract "
                f"{c.get('id', '?')}: anchor_kind {ak!r} is not known "
                f"(`enum anchor-kinds`)",
            )
    for row in _walkers.iter_authz_resolutions(companion):
        row_ak = row.get("anchor_kind")
        errors += _check_vocab(
            row_ak, vocab.ANCHOR_KINDS,
            f"authz resolution for contract {row.get('fulfills_contract', '?')}: "
            f"anchor_kind {row_ak!r} is not known (`enum anchor-kinds`)",
        )
    return errors

def _check_conclude_vocab(companion: CompanionBody) -> list[str]:
    """`conclude`'s disposition is the run's headline, so it carries a vocabulary check like
    every other conclude field: an out-of-enum value silently skips the benign gating below,
    and a typo would buy a document past the checks a `benign` conclusion has to pass."""
    disposition = (companion.get("conclude") or {}).get("disposition")
    return _check_vocab(
        disposition, vocab.DISPOSITION,
        f"conclude: disposition {disposition!r} is not a known disposition "
        f"(`enum disposition`)",
    )
