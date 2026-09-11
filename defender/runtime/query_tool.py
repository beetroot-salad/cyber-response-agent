
from __future__ import annotations

import asyncio
import inspect
import json
import re
import sys
from collections.abc import Mapping
from typing import Any

from pydantic import ValidationError
from pydantic_ai import RunContext
from pydantic_ai.capabilities.abstract import AbstractCapability
from pydantic_ai.exceptions import (
    ApprovalRequired,
    CallDeferred,
    ModelRetry,
    SkipToolExecution,
    ToolRetryError,
)

from defender.hooks.budget_enforcer import BudgetKill
from defender._text import as_str
from defender._untrusted import wrap_fresh
from defender.learning.branch.redaction import redact_model_visible
from defender.scripts.adapters.faults import USAGE_EXIT_CODE, AdapterFault
from defender.scripts.gather_tools.payload_view import render as _render_payload
from defender.scripts.gather_tools.record_query import (
    ABOVE_GUARD_QUERY_ID,
    REPEAT_ESCAPE,
    REPEAT_TRIP_QUERY_ID,
    GatherDeadEnd,
    RejectionBudgetTrip,
    RepeatTrip,
    _json_safe_params,  # noqa: F401 — re-export: test_repeat_breaker_807 imports it from here
    append_query_row,
    dead_end_reason,
    is_reserved_query_id,
    lead_rows,
    names_something_readable,
    payload_digest,
    payload_status,
    # Re-exported under its old private name: `_spec771` measures the site
    # `query_tool._persist_payload` by that name.
    persist_payload as _persist_payload,  # noqa: F401
    raw_command,
    rejection_budget_trip,
    rejection_dead_end,
    rejection_detail,
    rejection_trip,
    repeat_note,
    repeat_trip,
    repeat_trip_detail,
    system_fingerprint,
)

from . import circuit_breaker
from .ticket_screen import (
    TICKET_GET,
    TICKET_LIST,
    TICKET_SYSTEM,
    screen_get,
    screen_list,
    self_case_key,
)
from .verbs import (
    DENIED,
    GRANTED,
    VerbContext,
    _ann_name,
    _resolved_hints,
    SYSTEM_MAX_LEN,
    is_system_name,
    model_facing_params,
    validate_params,
)

TOOL_NAME = "query"

CONTROL_FLOW_EXCEPTIONS: tuple[type[BaseException], ...] = (
    circuit_breaker.RunAborted,
    ModelRetry,
    SkipToolExecution,
    CallDeferred,
    ApprovalRequired,
    ToolRetryError,
)

DEFAULT_FAULT_EXIT = 2

#: How the host names a system it withheld — ONE spelling, spent by `_undeclared_target` on the
#: sentence MAIN reads and by `UNDECLARED_SYSTEM_DETAIL` on the row. Not a shared PREDICATE (see
#: below), a shared WORDING: two hand-kept copies would let a reword reach the dead-end message
#: and not the digest, leaving an operator joining the two surfaces with two names for one class.
UNDECLARED_SYSTEM = "an undeclared system"

#: What the GRANT CHECK's unresolvable-verb rejection records when the host COARSENED the
#: system away (#1016 M1) — that placement only; the schema placement renders
#: `_coarse_schema_detail(e)`, and the adapter-load writer coarsens nothing. A literal, because
#: the specifics are on the same row already: `system_key` tells one ghost from another, `verb`
#: and `params` hold the call's own arguments.
#:
#: Deliberately NOT a second spelling of `_undeclared_target`'s readability question (N8), and
#: the cost is real: on a call naming nothing READABLE that function returns `""` and the dead
#: end declines to say a system was named, while this row says one was. The row is the coarser
#: of the two by design — a reader joining the two surfaces reads the `system` column beside it.
UNDECLARED_SYSTEM_DETAIL = "unresolvable: " + UNDECLARED_SYSTEM

#: The `query` tool's OWN parameter names — `register_query_tool`'s signature minus `ctx`, and
#: HOST material for that reason. Pydantic reports a failure's `loc`, which on `extra_forbidden`
#: is the offending key, a name the MODEL chose; membership here separates "the schema is
#: complaining about the tool's `system` argument" from "the schema is quoting a string the
#: model invented". Anything outside it renders as the placeholder `argument`.
#:
#: HAND-COPIED and underivable — the tool is a closure inside `register_query_tool`, out of
#: `inspect.signature`'s reach from module scope — and nothing fails when it drifts. So
#: `_coarse_schema_detail` refuses `extra_forbidden`'s `loc[0]` separately, which keeps a stale
#: entry a DEGRADATION (a real argument printed as `argument`) rather than a leak.
DECLARED_ARGS = frozenset({"system", "verb", "params", "query_id"})

#: Characters a `query_id` may not carry. The first four are PATH shapes — a traversal that
#: would walk the id out of the directory it names a file in. The last three are RENDER
#: shapes: a catalog id is interpolated into markdown three offline collectors read, and a
#: newline or a heading marker in it forges document structure inside the judge's per-lead
#: comparison. Both families screen as one rule: a `query_id` is a catalog IDENTIFIER the
#: collectors partition on, not free text.
_QID_FORBIDDEN = ("/", "\\", "..", "\x00", "\n", "\r", "#")

#: The kebab half: the remainder after the first `.` in a coined `query_id`. No dot — a second
#: dot lets `'system.foo.bar'` slip past a prefix-only check and become a SECOND unvalidated
#: model-supplied path component at the host-side draft writer
#: (`draft_synthesis._draft_candidate_segments`'s `split('.', 1)`).
_KEBAB_SEGMENT = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9_-]*\Z")


def resolve_query_id(system: str, verb: str, model_query_id: str | None) -> str:
    # The `∅.` sentinels are reserved for the writer sites that pass them directly (never
    # through here) to mark a row whose ROUTING the offline collectors take on trust. A
    # model-supplied `query_id` spelling one — or carrying a character `_screen` would reject —
    # must not reach a real row through this path: the repeat-trip's own record sits ABOVE
    # `_screen`, so nothing else screens it. Keyed on the whole PREFIX, not on each literal, so
    # it cannot fall behind the set.
    if (
        model_query_id
        and not is_reserved_query_id(model_query_id)
        and not any(t in model_query_id for t in _QID_FORBIDDEN)
    ):
        # The WHOLE `{system}.{kebab-name}` shape, not only the prefix: the prefix must
        # EXACTLY equal the dispatched system (no case folding, no NFC) and the remainder must
        # be a single well-formed segment. A foreign prefix, a missing separator, an empty
        # remainder, or a second `.` all fall back to the untagged value.
        prefix, sep, remainder = model_query_id.partition(".")
        if sep and prefix == system and remainder and _KEBAB_SEGMENT.match(remainder):
            return model_query_id
    return f"{system}.{verb}" if verb else f"{system}.ad-hoc"


def _fault_exit(e: BaseException) -> int:
    if isinstance(e, SystemExit) and isinstance(e.code, int) and e.code != 0:
        return e.code
    return DEFAULT_FAULT_EXIT


def _self_ticket_reject_reason(
    self_key: str, system: str, verb: str, params: dict,
) -> str | None:
    """Reject a direct gather read of its own case before the ticket store is contacted.

    Gather deliberately retains unrestricted access to OTHER tickets — including open and
    in-progress records used for correlation. The protected identity is only this run's case
    key, which is carried explicitly on deps rather than inferred from a filesystem path
    (``ticket_screen.self_case_key``).
    """
    if system == TICKET_SYSTEM and verb == TICKET_GET and params.get("key") == self_key:
        return (
            "that key is the current investigation's own ticket and cannot be read through "
            "gather. Correlate a different ticket; open and in-progress related cases remain "
            "available."
        )
    return None


def _screen_ticket_payload(
    self_key: str, system: str, verb: str, payload: Any,
) -> tuple[Any, int, str]:
    """Apply gather's current-case exclusion before capture and model display.

    Bound here is gather's own predicate, intentionally IDENTITY-ONLY: another ticket may
    mention ``self_key`` in its free text and remains useful correlation evidence — unlike the
    judge, gather is not scoring the case, so a mention is not an answer key. A record whose
    key cannot be established is withheld, being unprovably distinct from this case.
    """
    if system != TICKET_SYSTEM:
        return payload, 0, ""

    if verb == TICKET_GET:
        return screen_get(
            payload,
            require_key=True,
            withhold=lambda ticket: (
                "the ticket store returned the current investigation's own ticket; its "
                "content was withheld from gather."
                if ticket["key"] == self_key else None
            ),
        )

    if verb == TICKET_LIST:
        return screen_list(
            payload,
            keep=lambda ticket: (
                isinstance(ticket.get("key"), str) and ticket["key"] != self_key
            ),
        )

    return payload, 0, ""


class QueryCapture(AbstractCapability[Any]):

    def __init__(self, registry: Any, role: str = "gather"):
        self._registry = registry
        self._role = role
        self._seq_lock = asyncio.Lock()

    def _denial_logger_for(self, run_dir: Any) -> Any:
        # Process-wide per run dir, NOT per capability (see `observe._DENIAL_LOGGERS`): one
        # QueryCapture is built per gather lead against one shared run dir.
        from . import observe

        return observe.denial_logger(run_dir)

    def _decide_guarded(self, system: str, verb: str) -> tuple[Any, str | None]:
        """THE grant decision, guarded against a broken adapter import: the agreement check is
        deferred to first resolution, not policy compile, so a broken sibling adapter must not
        unwind the stage (§7 R2)."""
        try:
            return self._registry.decide(system, verb), None
        except CONTROL_FLOW_EXCEPTIONS:
            raise
        except (BudgetKill, KeyboardInterrupt, GeneratorExit, asyncio.CancelledError):
            raise
        except BaseException as e:  # noqa: BLE001 — the registry could not LOAD this system's module
            return None, f"{system} adapter failed to load: {type(e).__name__}: {e}"

    def _system_of_record(self, system: str) -> str:
        """The `system` an ABOVE-GUARD row is allowed to carry: the model's own string when the
        registry declares that system, `""` when it does not. Two answers and no third: the
        roster is fixed at the registry's construction and read from no I/O here
        (`VerbRegistry.systems`, #1031), so "the registry could not say" is not a state this
        function can be in. It was, once — `systems()` globbed the adapters directory per
        call — and the fault path #1017 D4 built for it (an exception, a reserved breaker
        key, an `infra` row at both placements) went with the glob.

        The two writers that spend this function record what the MODEL named, and nothing
        between them and the offline collectors re-checks it (`_grant_check`'s adapter-load
        branch is a third above-guard writer and does NOT coarsen — its rows are `infra`, which
        `collect_general_failures` drops before any corpus path is composed). That is not
        inert: an exit-64 `agent-fixable` row is the pitfalls channel's input, and
        `_build_pitfalls_handoffs` spends its `system` verbatim as
        `defender/skills/<system>/execution.md`, so a schema the model can fail on purpose was
        a route to naming a corpus write. `""` needs no new branch downstream —
        `collect_general_failures` already skips a systemless row.

        Spent on the rejection guard's identity as well as on the row, never one without the
        other: the guard recovers its count from the rows it wrote.

        THE IDENTITY CONSEQUENCE, and what #871 did about it: coarsening alone made every
        undeclared system key the SAME, so three rejections naming three ghost systems under
        one verb and params were one repeat group and the third ended a lead the guard promises
        never to end for calls that differ. `system_fingerprint` now carries the distinction
        the row cannot — a hash of the raw string in `system_key`, beside this `""` and never
        instead of it. The dead-end message still says "an undeclared system"
        (`_undeclared_target`): the guard can tell the ghosts apart, and main still must not
        be told their names."""
        return system if system in self._registry.systems() else ""

    def _coarsen(self, raw_system: str) -> tuple[str, str]:
        """THE above-guard pair, minted once: `(system of record, system_key)`.

        `_system_of_record`'s own docstring says the coarsening is "spent on the rejection
        guard's identity as well as on the row, NEVER one without the other" — and before this
        helper that was a rule two placements each kept by hand, in mirrored spellings whose
        `system_fingerprint(raw, recorded)` arguments read in opposite orders. Both arguments
        are `str` and only one of them is hashed, so a transposition returns `""` for every
        ghost, fixes nothing, raises nothing, and is caught only by a test that drives that
        one placement to the threshold. Returned as a pair, the two halves cannot be computed
        from different inputs, ordered wrongly, or handed on one without the other."""
        recorded = self._system_of_record(raw_system)
        return recorded, system_fingerprint(raw_system, recorded)

    @staticmethod
    def _was_coarsened(recorded: str) -> bool:
        """THE SOLE ANSWER to "did `_system_of_record` throw the model's `system` argument away
        on this row?" — the question that scopes #1016's O1 to the rows where the host chose to
        withhold a name, and leaves every other row's detail exactly as it was (N3).

        ASKED OF THE RECORDED VALUE ALONE, which is the whole predicate and not a shortcut past
        one: `_system_of_record` returns `system if system in declared else ""`, so the recorded
        value is either byte-identical to what the caller handed it or empty, and "is it empty"
        answers "does it differ from what was sent" over this module's own producer. Taking the
        raw half too would add an argument that cannot change the answer and a mirrored
        `(raw, recorded)` pair to pass positionally — `system` is the RECORDED half at the schema
        check and the RAW half at the grant check — which is the hazard `_undeclared_target` is
        keyword-only to prevent, two functions below.

        ONE function for both placements, though #1016's design spells the predicate at each:
        they arrive from different argument surfaces but ask the same question of the one value
        `_coarsen` returns, and `_coarsen`'s own docstring records what a rule kept by hand at
        both placements cost the last time.

        THE POPULATION IS "does this row carry a system at all?" — the question the ROW'S READERS
        ask. #1016's design first left a literal `system=""` out of it, on the grounds that the
        host recorded precisely what the model sent. True of the system STRING, false of the
        DETAIL this branch selects: such a call still records pydantic's `loc` (the model's own
        chosen argument key) at the schema placement and `decision.refusal` (which names the
        verb) at the grant check, onto a row that is `system=""`, `system_key=""` — byte-identical
        in both identity columns to one the host really did coarsen, and indistinguishable from
        it to every reader. One character of model output is not a licence to reopen the leak.
        A non-`str` `system` (already `""` by `as_str`) and a missing key coarsen the same way."""
        return not recorded

    @staticmethod
    def _coarse_schema_detail(e: BaseException) -> str:
        """THE SOLE PRODUCER of the detail a COARSENED argument-schema rejection records
        (#1016 M2) — pydantic's complaint re-composed from host material, in place of the
        `str(e)` a row that kept its system still gets.

        `str(e)` cannot be used here and neither can a scrub of it. It carries the model's text
        three ways: the failing `input_value=` (a non-string `system` lands there whole), the
        offending `loc` (which is the model's own chosen key on an extra argument), and the
        repr-escaping around both — and a substring replace over escaped text leaves fragments
        for any name holding a quote or a backslash (#1016 N5). So nothing is subtracted; the
        sentence is BUILT, from three host-owned pieces and no fourth:

        * the error COUNT, a number;
        * the FIELD, which is `loc[0]` only when it is one of the tool's own parameter names
          (`DECLARED_ARGS`) AND the error is not `extra_forbidden`; the literal `argument`
          otherwise. `loc` beyond its first element is dropped whole — a deeper element is a key
          inside the model's `params`. The type test is redundant against today's set and is
          spelled anyway, because `DECLARED_ARGS` is a hand-copy of a signature ~1000 lines off:
          `extra_forbidden` is the ONE error whose `loc[0]` is a name the model chose, so a
          stale entry (a parameter renamed or removed) is otherwise a licence to echo the model
          spelling that old name back into a host-authored column. Membership can then only
          DEGRADE the digest (a real argument rendered as `argument`), never leak;
        * pydantic's `msg`, which for every error type this schema can raise quotes no input.
          Against a decoded object it is a fixed template ("Input should be a valid string",
          "Extra inputs are not permitted", "Field required", "Input should be a valid
          dictionary"). When the framework hands the tool a JSON STRING instead — what every
          real provider sends, and why `_raw_args` exists, though no replay arm drives it — a
          malformed body yields `json_invalid` at `loc=()`, whose message names a POSITION in
          the model's own text ("Invalid JSON: expected ident at line 1 column 13"). Kept: the
          parser is describing its own state and the diagnosis is useless without the offset.
          But the licence here is "quotes no input", never "is a constant".

        `include_input=False` ALONE is not enough, and that is the trap worth naming: it drops
        the value and leaves `loc` standing, so the model still gets to choose a string in a
        host-authored column just by misspelling an argument.

        A non-`ValidationError` — the `ModelRetry` this seam also catches — keeps `str(e)`, and
        the reason is narrow enough to be worth stating: it is NOT that pydantic-ai's retries
        carry no arguments. The unknown-tool one is raised in `_resolve_tool` before any
        validate hook runs and the timeout one on the EXECUTE path, so neither reaches here;
        what could is a per-tool `args_validator_func`, which `register_query_tool` does not
        supply. Give `query` an args validator that formats an argument into its message and
        this arm stops being safe."""
        if not isinstance(e, ValidationError):
            return str(e)
        errs = e.errors(include_input=False, include_url=False)
        parts = []
        for err in errs:
            # Nothing in this loop may raise. It runs inside a rejection handler with no `try`
            # of its own, so any exception replaces the rejection outright — no row, hence no
            # occurrence for the companion guard to recover from the rows it wrote, and the
            # repeat loop #826 item 4 closed stops being bounded. Hence `.get` on every key,
            # and `isinstance(head, str)` before the membership test rather than for mypy:
            # `x in frozenset` HASHES x, so an unhashable `loc` element would raise here too.
            head = next(iter(err.get("loc") or ()), None)
            field = (
                head if isinstance(head, str) and head in DECLARED_ARGS
                and err.get("type") != "extra_forbidden"
                else "argument"
            )
            parts.append(f"{field}: {err.get('msg', '')}")
        return f"{len(errs)} validation error(s): " + "; ".join(parts)

    @staticmethod
    def _undeclared_target(*, recorded: str, raw: str) -> str:
        """What the dead-end message calls the request's target. The coarsened `""` makes
        `rejection_dead_end_reason` say "system/verb unreadable in the call's own arguments",
        false for a call that named a system readably but not one that exists; and the raw
        string cannot be echoed, being unbounded model text on a path into MAIN's context.

        KEYWORD-ONLY, for the reason `_coarsen` exists and with a worse blast radius than the
        transposition that motivated it: this is the SAME `(raw, recorded)` pair one function
        over, in the opposite order, spelled at two placements whose local names for the two
        halves are mirrored (`(system, raw_system)` here, `(recorded_system, system)` at the
        grant check). Both halves are `str` and only one may be echoed, so a swap returns the
        model's own ghost string, `rejection_dead_end_reason` puts it in `GatherDeadEnd.reason`,
        and it crosses into MAIN's context — the #855 leak — raising nothing and caught only by
        a test that drives that one placement to the threshold.

        "Readable" is `names_something_readable`, THE SAME predicate `system_fingerprint` folds
        the N5 group with, and not a second spelling of it: this message describes a whole
        repeat GROUP, so the two must answer alike or the sentence MAIN receives is chosen by
        whichever member of the group happened to land third."""
        return recorded or (UNDECLARED_SYSTEM if names_something_readable(raw) else "")

    def _forbidden_reject(self, model_query_id: Any) -> str | None:
        # The message names the WHOLE screen, not just its path half: `_QID_FORBIDDEN` reaches
        # past the traversal set, and a refusal listing four characters the caller did not use
        # is one the caller cannot act on.
        if model_query_id and any(t in str(model_query_id) for t in _QID_FORBIDDEN):
            return (
                f"invalid query_id {model_query_id!r}: no '/', '\\', '..', NUL, newline or '#' "
                "— it becomes a catalog path segment and a markdown span the offline collectors "
                "render. Coin a `{system}.{kebab-name}` id."
            )
        return None

    def _rejection_guard(
        self, deps, system: str, verb: str, params: dict, *, system_key: str,
    ) -> RepeatTrip | RejectionBudgetTrip | None:
        """The two guards on the calls rejected ABOVE `wrap_tool_execute`'s own guard — the
        argument schema, and the grant check's unresolvable-verb branch. Its counted domain is
        the complement of the first guard's, so `wrap_tool_execute`'s guard and these can never
        both own one call. The identity is extracted at the CALLER, because the two placements
        read different argument surfaces — raw pre-validation arguments at the schema,
        validated ones at the grant check — and `system_key` for the same reason: each
        placement holds the RAW string this coarsened `system` was made from, and only there
        can `system_fingerprint` still see it.

        ONE `lead_rows` READ feeds both predicates. They count the same domain and differ only
        in whether identity is read, so a second load would be a second answer to the same
        question over a table another process may have appended to in between — and this sits
        on the per-call path.

        REPEAT IS ASKED FIRST, and the order is the answer main gets, not an optimisation: a
        call that is both the third repeat and the B-th rejection is described by BOTH, and the
        repeat sentence is the more specific one — it names the earlier request being repeated,
        which the lead can act on. The budget's sentence can only say "you have spent the
        allowance". Reversed, every repeat loop long enough to reach the budget would lose the
        specific explanation it had before #1015.

        The budget is IDENTITY-BLIND, so it is asked with neither `system_key` nor the request
        triple — which is exactly why it catches the family the guard above cannot: an
        undeclared name per turn, whitespace drift, assigned-but-font-blank codepoints."""
        if deps.lead_id is None:
            return None
        rows = lead_rows(deps.run_dir, deps.lead_id)
        trip = rejection_trip(
            rows, deps.lead_id,
            system=system, verb=verb, params=params, system_key=system_key,
        )
        if trip is not None:
            return trip
        return rejection_budget_trip(rows, deps.lead_id)

    async def wrap_tool_validate(self, ctx, *, call, args, handler, **_):  # noqa: ANN001 — **_ absorbs the framework's tool_def
        if call.tool_name != TOOL_NAME:
            return await handler(args)
        try:
            return await handler(args)
        except (ValidationError, ModelRetry) as e:
            raw = _raw_args(args)
            # THE SECOND IDENTITY EXTRACTION. These are the RAW arguments: this frame runs
            # precisely because the schema refused to produce validated ones. A non-dict
            # `params` coarsens to `{}` here — what the row already stores, so the live count
            # and a replay over the recorded table read the same identity. `system` coarsens
            # the same way when the registry does not declare it, and for a stronger reason:
            # this row's `system` steers an offline corpus write (`_system_of_record`).
            raw_system = as_str(raw.get("system"))
            verb = as_str(raw.get("verb"))
            params = _as_dict(raw.get("params"))
            system, system_key = self._coarsen(raw_system)
            trip = self._rejection_guard(ctx.deps, system, verb, params, system_key=system_key)
            # #1016 M2. `str(e)` names whatever the model sent — the failing value, and the
            # offending KEY when the model invented one — so on a row whose `system` this writer
            # just threw away it puts the model's text back in a host-authored column. Asked of
            # `system`, the value the ROW records and the population O1 is stated over.
            rejection = (
                self._coarse_schema_detail(e)
                if self._was_coarsened(system) else str(e)
            )
            # #1015. THE TRIP PHRASE WRAPS WHATEVER #1016 JUST DECIDED, rather than either
            # choosing the tail itself: the two changes own different halves of this string —
            # #1016 owns what the CALL's own error may say on a coarsened row, #1015 owns which
            # GUARD's phrase leads it — and composing them in this order keeps the coarsening
            # in force on a trip row too. Spelled the other way round, a lead's LAST rejection
            # (the one that ends it, and the one an operator reads first) would be the single
            # row where the model's text came back.
            #
            # `rejection_detail`, not `rejection_trip_detail`: since #1015 two guards write
            # this row and only the dispatcher knows both their sentences.
            #
            # BOUND before the `_record` call rather than spelled in its argument list: the
            # dispatcher is TOTAL over the trip types and RAISES on one it does not know, and
            # an argument expression is evaluated BEFORE the call it belongs to — so inlined, a
            # future third guard would cost this rejection its row entirely and the append-only
            # table would forget the call happened at all. Bound here, the raise happens where
            # a row was never owed.
            detail = rejection if trip is None else rejection_detail(trip, rejection)
            await self._record(
                ctx.deps,
                system=system, verb=verb, system_key=system_key,
                query_id=ABOVE_GUARD_QUERY_ID,
                params=params,
                payload=None,
                exit_code=USAGE_EXIT_CODE,
                detail=detail,
            )
            if trip is not None:
                raise rejection_dead_end(
                    trip,
                    target=self._undeclared_target(recorded=system, raw=raw_system),
                    verb=verb,
                ) from e
            raise

    async def _grant_check(
        self, deps, system: str, verb: str, params: dict,
    ) -> tuple[Any, str | None]:
        """THE GRANT CHECK, ahead of everything else (§7 R3/R23, reversed at phase F — a denied
        call always produces its denial record and never an evidence row, whatever else is
        wrong with it). Returns `(decision, early_result)`; `early_result` is set when the
        caller must return without ever reaching execution."""
        decision, load_error = self._decide_guarded(system, verb)
        if load_error is not None:
            # THE BREAKER CHECK, consulted HERE and not only in `wrap_tool_execute`. These
            # `infra` rows are excluded from `rejection_trip` on the promise that
            # `circuit_breaker` owns this repeat end to end, which is false unless the check
            # sits above this return: `verbs._load_adapter_module` caches only on success, so
            # the same import re-fails on every call and the fifth failure crosses
            # `RUN_FAIL_KILL_LIMIT`. Ahead of `_record`, so the down-answer neither writes a
            # row nor counts a failure. NOT hoisted above `_grant_check` entirely — the DENIED
            # branch below owes its denial record whatever else is wrong (§7 R3/R23).
            tripped = _tripped_message(deps, system)
            if tripped is not None:
                return None, tripped
            row, text = await self._record(
                deps, system=system, verb=verb,
                query_id=ABOVE_GUARD_QUERY_ID, params=params, payload=None,
                exit_code=DEFAULT_FAULT_EXIT, detail=load_error,
                # `""`, and NOT because nothing was named: this is the THIRD above-guard
                # writer, and the only one that records the model's own string in `system`
                # un-coarsened. Its rows are `infra` (exit 2), which puts them outside
                # `rejection_trip`'s domain entirely — so there is no count for a fingerprint
                # to separate. Written out rather than defaulted so that changing this row's
                # exit code cannot silently enrol it in a guard it was never keyed for.
                system_key="",
            )
            return None, self._model_view(deps, row, text, DEFAULT_FAULT_EXIT, load_error)

        if decision.outcome == DENIED:
            self._denial_logger_for(deps.run_dir).log_policy_denial(
                role=self._role, system=system, verb=verb,
                call_id=f"{system}.{verb}", params=params,
            )
            return None, _format_bash_result(
                DEFAULT_FAULT_EXIT, "", wrap_fresh(decision.refusal or "", "untrusted"), "",
            )

        if decision.outcome != GRANTED:
            # The unresolvable-verb repeat class — the schema class's shape at a different
            # placement, which is why the companion guard is reached from both. The load-error
            # branch above is deliberately NOT guarded by it: those rows are `infra`, outside
            # `rejection_trip`'s domain. Same coarsening as the schema placement, since an
            # unresolvable call reached no system by that name and its string is the one least
            # entitled to become a `skills/<system>/` path; a REAL system with an unknown verb
            # still records itself.
            #
            refusal = decision.refusal or f"unresolvable: {system}.{verb}"
            recorded_system, system_key = self._coarsen(system)
            trip = self._rejection_guard(
                deps, recorded_system, verb, params, system_key=system_key,
            )
            # #1016 M1. `decision.refusal` names the system AND the verb — right for the model
            # (it is how a subagent corrects a typo, and the `ModelRetry` below carries it
            # whole) and wrong for the row, which just coarsened that system to `""`. A host
            # literal when coarsened; `refusal` verbatim otherwise, since a rejection against a
            # DECLARED system is the pitfalls channel's input and must keep naming the verb.
            rejection = (
                UNDECLARED_SYSTEM_DETAIL
                if self._was_coarsened(recorded_system)
                else (decision.refusal or "unresolvable")
            )
            # #1015's trip phrase wraps it, and bound before the call — both for the reasons
            # the schema placement's twin gives.
            detail = rejection if trip is None else rejection_detail(trip, rejection)
            await self._record(
                deps, system=recorded_system, verb=verb, system_key=system_key,
                query_id=ABOVE_GUARD_QUERY_ID, params=params, payload=None,
                exit_code=USAGE_EXIT_CODE,
                detail=detail,
            )
            if trip is not None:
                raise rejection_dead_end(
                    trip,
                    target=self._undeclared_target(recorded=recorded_system, raw=system),
                    verb=verb,
                )
            raise ModelRetry(refusal)

        return decision, None

    async def _screen(
        self, deps, decision: Any, system: str, verb: str, params: dict,
        model_query_id: Any, self_key: str,
    ) -> None:
        """The per-call screens BELOW the grant and the breaker: the traversal screen, param
        validation, and the self-ticket screen. Raises `ModelRetry` (after its usage row) when
        one of them refuses."""
        reason = self._forbidden_reject(model_query_id)
        if reason is None:
            reason = validate_params(decision.fn, params)
        if reason is None:
            reason = _self_ticket_reject_reason(self_key, system, verb, params)
        if reason is not None:
            await self._record(
                deps, system=system, verb=verb,
                query_id=resolve_query_id(system, verb, None),
                params=params, payload=None,
                exit_code=USAGE_EXIT_CODE, detail=reason, system_key="",
            )
            raise ModelRetry(reason)

    async def wrap_tool_execute(self, ctx, *, call, args, handler, **_):  # noqa: ANN001 — **_ absorbs the framework's tool_def
        if call.tool_name != TOOL_NAME:
            return await handler(args)

        deps = ctx.deps
        system = as_str(args.get("system"))
        verb = as_str(args.get("verb"))
        params = _as_dict(args.get("params"))
        model_query_id = args.get("query_id")
        self_key = self_case_key(deps)

        decision, early_result = await self._grant_check(deps, system, verb, params)
        if early_result is not None:
            return early_result

        # The breaker sits between the grant and the screens, where it sat before the grant
        # landed: a system already known down answers "down" rather than a param complaint
        # plus a usage row for a call that was never going to reach it.
        tripped = _tripped_message(deps, system)
        if tripped is not None:
            return tripped

        # The repeat guard sits ABOVE `_screen`, so it owns every repeat it can see —
        # including a call the verb's own parameter check would refuse — rather than earning a
        # third identical corrective `ModelRetry` the model already ignored twice.
        rows = lead_rows(deps.run_dir, deps.lead_id)
        trip = repeat_trip(rows, deps.lead_id, system=system, verb=verb, params=params)
        if trip is not None:
            # REPEAT_TRIP_QUERY_ID, not `resolve_query_id(...)`: three offline collectors
            # partition this table on `query_id`, and the model's id sends the trip row to the
            # wrong two — a coined id is minted as a `_draft/` template proposing the refused
            # query, a catalog id is handed to the lead-author as a failure of that template.
            # The guard's own counted domain keys on ABOVE_GUARD_QUERY_ID alone, so untouched.
            await self._record(
                deps, system=system, verb=verb, query_id=REPEAT_TRIP_QUERY_ID, params=params,
                payload=None, exit_code=USAGE_EXIT_CODE, detail=repeat_trip_detail(trip),
                system_key="",
            )
            executed = sum(1 for r in rows if r.get("exit_code") == 0)
            raise GatherDeadEnd(
                reason=dead_end_reason(system, verb, trip, executed),
                escape=REPEAT_ESCAPE,
            )

        await self._screen(
            deps, decision, system, verb, params, model_query_id, self_key,
        )

        query_id = resolve_query_id(system, verb, as_str(model_query_id) or None)

        payload: Any = None
        try:
            payload = await handler(args)
            payload, exit_code, detail = _screen_ticket_payload(
                self_key, system, verb, payload,
            )
        except CONTROL_FLOW_EXCEPTIONS:
            raise
        except (BudgetKill, KeyboardInterrupt, GeneratorExit, asyncio.CancelledError):
            raise
        except AdapterFault as e:
            exit_code, detail = e.exit_code, e.detail
        except BaseException as e:  # noqa: BLE001 — the point: an unmapped fault still writes a row
            exit_code, detail = _fault_exit(e), str(e) or type(e).__name__

        row, text = await self._record(
            deps, system=system, verb=verb, query_id=query_id, params=params,
            payload=payload, exit_code=exit_code, detail=detail, system_key="",
        )
        return self._model_view(deps, row, text, exit_code, detail)

    async def _record(  # noqa: PLR0913 — one per row column the CALLER decides, plus `deps`
        self, deps, *, system: str, verb: str, query_id: str, params: dict,
        payload: Any, exit_code: int, detail: str, system_key: str,
    ) -> tuple[dict, str]:
        """The circuit breaker is charged to the row's own `system` — every writer's, since
        #1031 removed the one that charged a host constant instead. A coarsened above-guard row
        charges `""`, which `record_outcome` skips; those rows are bounded by the rejection
        guards (`rejection_trip`, `rejection_budget_trip`), which count them by the
        `(system, system_key)` pair the row carries.

        `system_key` is REQUIRED here for the reason `append_query_row` requires it, and the
        reason binds HARDER at this frame: every real writer of the column reaches the row
        through `_record`, never through `append_query_row` directly, so a default here would
        satisfy the column's requirement on the writer's behalf and leave the discipline
        protecting nothing. `""` is a real answer at four of the six call sites and each says
        so in its own argument list; the two that mint a fingerprint (`wrap_tool_validate` and
        `_grant_check`'s unresolvable branch) are the ones a reader has to check, and a
        required keyword is what puts each of the four in front of that reader rather than
        letting a writer that OUGHT to fingerprint pass for one that has nothing to."""
        if deps.lead_id is None:
            raise RuntimeError("internal: query reached capture without a dispatched lead_id")

        text = "" if exit_code != 0 else json.dumps(payload, default=str)
        run_dir = deps.run_dir

        async with self._seq_lock:
            # The row's keys are assembled by `append_query_row`, which the gather bash lane's
            # shim recorder also calls. The lock stays: cheaper to keep than to argue that
            # nothing will ever add an `await` here.
            row = append_query_row(
                run_dir,
                lead_id=deps.lead_id,
                system=system,
                verb=verb,
                query_id=query_id,
                params=params,
                raw_command=raw_command(system, verb, params),
                payload_text=text,
                exit_code=exit_code,
                payload_status=payload_status(exit_code, payload),
                # REDACTED, and this is one of the exact two sites §7 NEW-DECISION-1 names.
                # The failure digest is the fault's own detail, and this table sits in the
                # gather agent's read scope while every downstream joiner reads it too — so a
                # staged corpus name written here reaches the model on a second channel, one
                # step later than the wrap below and with nothing between it and a reader.
                # Redacted BEFORE the truncation, so the 160 characters kept are 160 characters
                # of a redacted string rather than a window that happens to have cut the name.
                #
                # THE FAILURE ENVELOPE IS SPELLED HERE, not taken from `payload_digest`: this
                # is one of three writers (`tools/_bash.py`, `lead_zero/_capture.py`) that hand
                # that function only the SUCCESS arm and compose `exit={code}; {detail}`
                # themselves, so its `exit_code != 0` branch has no production caller at all.
                # `payload_digest`'s docstring is still where the column's contract is argued —
                # including #1016's collapse of every coarsened above-guard row onto one host
                # literal and what keeps that safe — so read it for THIS line, not for the
                # branch it is attached to.
                payload_digest=(
                    payload_digest(text, "", 0) if exit_code == 0
                    else f"exit={exit_code}; {redact_model_visible(detail).strip()[:160]}"
                ),
                system_key=system_key,
            )

        circuit_breaker.record_outcome(run_dir, system, exit_code)
        return row, text

    def _model_view(self, deps, row: dict, text: str, exit_code: int, detail: str) -> str:
        note = _payload_note(deps, row)
        # ABOVE the exit-code split, not inside the success arm: a lead repeating a request
        # whose calls keep FAILING is the population most likely to loop — a failure gives it
        # nothing new to reason from — so it needs the "you are repeating yourself" signal
        # most. Ahead of the view, because the repeat is what the caller must read first.
        repeat = repeat_note(
            deps.run_dir, deps.lead_id, seq=row["seq"], system=row["system"],
            verb=row["verb"], params=row["params"],
            payload_digest=row["payload_digest"], payload_sha256=row["payload_sha256"],
            exit_code=exit_code,
        )
        if exit_code != 0:
            # Prepended to `detail` INSIDE the wrap, mirroring the success arm: the wrap is
            # the untrusted boundary for this whole stream, and lifting one defender-authored
            # line out of it would put a second, differently-trusted region in a result the
            # main loop reads as one span.
            # REDACTED HERE, at the boundary rather than at each raising site. This frame is
            # what hands a fault's detail to the model, and the details arriving on it are
            # authored in three different places — the stager, confinement, and the CLUSTER,
            # whose error text is relayed verbatim and was the one observed naming a staged
            # index. A filter at the sites we author would leave the one we do not.
            # `redaction.redact_model_visible` says what is removed and what survives.
            visible = redact_model_visible(detail)
            body = visible if repeat is None else f"{repeat}\n{visible}"
            return _format_bash_result(exit_code, "", wrap_fresh(body, "untrusted"), note)
        # ONE call, no condition: `render` returns the payload verbatim when it fits and a
        # bounded view when it does not. "What counts as too big" belongs to the renderer, not
        # to its callers — stated here as well as at the judge's mirror it could drift.
        view = _render_payload(text, row["payload_path"], deps.run_dir)
        if repeat is not None:
            view = f"{repeat}\n{view}"
        return _format_bash_result(0, wrap_fresh(view, "untrusted"), "", note)



#: What a param renders as when its declared annotation could not be resolved. NOT cosmetic:
#: `_resolved_hints` swallows an unresolvable annotation and returns `{}`, after which
#: `validate_params` type-checks NOTHING — printing the annotation would promise a check the
#: boundary does not make. The blast radius is the whole VERB (`typing.get_type_hints` resolves
#: a signature as a unit), which is why the marker is applied from the ABSENCE of a hint rather
#: than the presence of a bad one.
UNENFORCED_TYPE = "type unenforced"

#: The GRANT-FIRST answer, and the one branch that deliberately refuses to distinguish two
#: conditions. `VerbRegistry.decide` decides from the grant ALONE first — no adapter imported
#: unless the grant admits the call (§7 R11); a discovery tool that resolved first would both
#: execute an ungranted adapter's import-time code and turn its own degradations into an
#: oracle over the on-disk roster, read across the grant boundary. So absent is spelled exactly
#: like withheld. Naming the reachable systems discloses nothing — the dispatch prompt's
#: descriptor index already lists every system in this role's grant — and is a better
#: correction for the common cause, a mistyped name.
_LIST_VERBS_UNREACHABLE = (
    "`{system}` — your grant reaches no verb on any system by that name, so there is nothing "
    "here you may run and no surface to show you.{roster} Measure this lead against a system "
    "you do hold, or say so in your summary rather than reporting a measurement you could not "
    "take."
)

_LIST_VERBS_UNKNOWN_SYSTEM = (
    "`{system}` — no adapter is registered under that name, so no verb surface can be derived "
    "for it. The Dispatch block at the end of your prompt names the system you were dispatched "
    "to; confirm it there and call this again with that name."
)

#: Reached only for a name that already passed `_adapter_path`'s `is_system_name` and
#: containment checks — an unmatched name raises `KeyError` into the branch above — so
#: interpolating it into a path here cannot mint an arbitrary model-named one.
#:
#: THE FALLBACK NAMES WHAT THAT FILE STILL HOLDS, and no more: `execution.md` carries no
#: verb/param blocks (its `## Verbs` section says "call `list_verbs`" — the call that just
#: failed), only value constraints and recorded pitfalls.
_LIST_VERBS_UNLOADABLE = (
    "`{system}` — UNAVAILABLE: its adapter could not be loaded ({err}). No verb surface can be "
    "derived for it right now, and no file carries a copy — the verb roster and its params are "
    "read from the live signatures and nowhere else. "
    "`defender/skills/{system}/execution.md` still states this system's value constraints and "
    "recorded pitfalls; report the failure in your summary rather than guessing a verb or a "
    "param name."
)

#: A THIRD failure, distinct from both of the above: the adapter loaded and the grant is not
#: the question — the surface itself could not be derived (a grant/declaration class
#: disagreement raised out of `decide`, say). Saying "could not be loaded" there would be
#: false, and saying "your grant admits none" would send the lead to re-dispatch over a
#: defender-side fault it cannot route around.
_LIST_VERBS_UNDERIVABLE = (
    "`{system}` — UNAVAILABLE: its verb surface could not be derived ({err}). That is a "
    "defender-side fault, not something your call can fix, and no file carries a copy of the "
    "surface. `defender/skills/{system}/execution.md` still states this system's value "
    "constraints and recorded pitfalls; report the failure in your summary rather than guessing "
    "a verb or a param name."
)

#: A system whose registry answer carries NO verb at all — a missing or malformed `VERBS`
#: table reads as `{}` through `ModuleVerbRegistry.verbs`, which is a broken adapter and not a
#: withheld grant. It must not fall into `_LIST_VERBS_NONE_GRANTED` below, whose whole point is
#: that the two emptinesses call for opposite responses.
_LIST_VERBS_NO_VERBS = (
    "`{system}` — UNAVAILABLE: its adapter declares no verbs at all, so no verb surface can be "
    "derived for it, and no file carries a copy. "
    "`defender/skills/{system}/execution.md` still states this system's value constraints and "
    "recorded pitfalls; report the failure in your summary rather than guessing a verb or a "
    "param name."
)

#: The OTHER emptiness, not the one above — the same split `_INDEX_NONE_GRANTED` draws for the
#: template index. A system that will not load and a system whose every verb this role is
#: refused both render "nothing to show", and they call for opposite responses.
_LIST_VERBS_NONE_GRANTED = (
    "`{system}` — its adapter declares verbs, but your grant admits none of them. This is not "
    "an empty system and not a read failure: there is nothing here you may run. Measure this "
    "lead against a system you do hold, or say so in your summary rather than reporting a "
    "measurement you could not take."
)

_LIST_VERBS_HEADER = (
    "`{system}` — the {count} verb(s) your grant admits, read from the adapter's live "
    "signatures. Copy a line and bind the values in place of each `<…>`:\n"
)

_LIST_VERBS_LEGEND = (
    "\nParams bind **by name**; there are no flags and no positional args. Types are literal "
    "JSON: a number is a number (`20`, never `\"20\"`), a boolean is `true`/`false` (never "
    "`\"false\"`, which is truthy and would have meant the opposite). A param whose descriptor "
    "carries a `default` is OPTIONAL — drop it to take that default; every other param is "
    "REQUIRED.\n"
    "\nAdd `query_id=\"{system}.<id>\"` to the call — a catalog template's id when you reused "
    "one, or a coined `{system}.<descriptive-kebab>` when none fit.\n"
)

#: Names the marker as a PREFIX, not as the whole descriptor: an unenforced param that also
#: declares a default renders `<type unenforced, default …>`, so a note quoting `<{marker}>`
#: whole would name a string that appears nowhere in the answer it is annotating.
_LIST_VERBS_UNENFORCED_NOTE = (
    "\nA descriptor opening `<{marker}` marks a param whose declared annotation could not be "
    "resolved, so the boundary does NOT type-check it — a wrong-typed value there reaches the "
    "adapter instead of being refused. Bind it to the value constraint this system's "
    "`execution.md` states, and treat a surprising answer as suspect rather than as data.\n"
)


def _json_default(value: Any) -> str:
    """A param default in the JSON spelling the legend demands, never `repr`'s python one.

    `repr` renders `None`/`True`/`'desc'` where the call the model must emit needs
    `null`/`true`/`"desc"`, so a lead copying the descriptor verbatim sends invalid JSON — or,
    for a quoted `"false"`, the exact truthiness inversion the legend warns about.
    """
    try:
        return json.dumps(value)
    except (TypeError, ValueError):
        return json.dumps(repr(value))


def _rendered_param(param: inspect.Parameter, hints: Mapping[str, Any]) -> str:
    """One declared param as a `"name": <descriptor>` entry of a `params={…}` body.

    Keyed on the param, never on `hints`: `_resolved_hints` also returns `ctx` and `return`,
    neither of which is a param the model may bind.
    """
    inner = _ann_name(hints[param.name]) if param.name in hints else UNENFORCED_TYPE
    if param.default is not inspect.Parameter.empty:
        inner = f"{inner}, default {_json_default(param.default)}"
    return f'"{param.name}": <{inner}>'


def _echoed_system(system: str) -> str:
    """The `system` string a degradation message may interpolate.

    A well-formed name goes back verbatim — that is what makes the correction actionable. Any
    other string is a model-authored blob that would land unescaped inside a backticked span of
    a markdown answer, where a newline or a `#` forges document structure in the lead's own
    context; `repr` on a bounded slice keeps it legible without letting it carry structure. The
    BACKTICK is dropped separately, since `repr` passes it through: one backtick closes the
    span early and the rest of the model's string lands as prose.
    """
    if is_system_name(system):
        return system
    return repr(system[:SYSTEM_MAX_LEN]).replace("`", "")


#: What every guarded read below RE-RAISES rather than degrading: the framework's own control
#: flow plus the kills that end the process. Named once so a reader added later cannot copy
#: half of it.
_RERAISE: tuple[type[BaseException], ...] = (
    *CONTROL_FLOW_EXCEPTIONS,
    BudgetKill, KeyboardInterrupt, GeneratorExit, asyncio.CancelledError,
)


def _registry_declares(registry: Any, system: str) -> bool:
    """Does the registry list `system` among the systems it knows? A membership test over a
    roster fixed at the registry's construction (`VerbRegistry.systems`, #1031) — no arm for
    "it cannot say", because there is no longer a way for it not to."""
    return system in registry.systems()


def _granted_systems(registry: Any) -> tuple[str, ...]:
    """The systems this role's grant reaches, or `()` when the registry cannot say."""
    try:
        return tuple(sorted(registry.grant.systems))
    except _RERAISE:
        raise
    except BaseException as e:  # noqa: BLE001 — a registry that cannot name its grant reaches nothing
        # LOUD on the operator channel — the one stderr line this module writes. This
        # arm has no row of its own to write: it answers "your grant
        # reaches nothing" for EVERY system in the run, which reads to the lead as a
        # correctly-empty grant rather than a broken registry. The tool's own answer cannot
        # carry the distinction without turning a defender fault into a routing instruction.
        print(f"[query_tool] verb registry could not name its grant "
              f"({type(e).__name__}: {e}); list_verbs will answer 'no system reached'",
              file=sys.stderr)
        return ()


def _list_verbs_declared(
    registry: Any, system: str, shown: str,
) -> tuple[Mapping[str, Any], str | None]:
    """`(declared_verbs, degradation)` — the registry's own table for `system`, or the message
    that must be answered instead. Never both, and never an exception out of the tool."""
    try:
        declared = registry.verbs(system)
    except KeyError as e:
        # A bare `KeyError` is `ModuleVerbRegistry.verbs`' "no adapter under that name" — but
        # ALSO whatever a broken adapter raises while importing (a module-scope
        # `os.environ[...]`). Answering the second with "confirm the name and call again" sends
        # the lead to re-ask a question that keeps failing, so the registry's own system list
        # decides which this is. The KEY rides into the message: for an import-time `KeyError`
        # the missing name (`TICKET_URL`, say) is the whole of the diagnosis.
        if _registry_declares(registry, system):
            return {}, _LIST_VERBS_UNLOADABLE.format(system=shown, err=f"KeyError: {e}")
        return {}, _LIST_VERBS_UNKNOWN_SYSTEM.format(system=shown)
    except _RERAISE:
        raise
    except BaseException as e:  # noqa: BLE001 — an adapter that will not import is a degradation
        return {}, _LIST_VERBS_UNLOADABLE.format(system=shown, err=f"{type(e).__name__}: {e}")
    if not declared:
        # NOT the grant's emptiness: `ModuleVerbRegistry.verbs` answers `{}` for a module whose
        # `VERBS` is absent or is not a Mapping, which is a broken adapter wearing the shape of
        # a fully-withheld one.
        return {}, _LIST_VERBS_NO_VERBS.format(system=shown)
    return declared, None


def _list_verbs_line(
    registry: Any, system: str, verb: Any, shown: str,
) -> tuple[tuple[str, bool] | None, str | None]:
    """`((rendered_call, any_param_unenforced), degradation)` for one verb — `(None, None)`
    when the grant withholds it, which is a skip and not a failure.

    GUARDED END TO END, over the RENDER as much as the decision: `decide` raises `GrantError`
    on a grant/declaration class disagreement, and the render raises just as readily on a
    malformed `VERBS` table (a non-callable body reaches `inspect.signature` as a `TypeError`).
    An exception out of a discovery tool ends the lead's turn, which O4 forbids of every branch
    here, so deciding and rendering are one guarded unit.
    """
    try:
        decision = registry.decide(system, verb)
        if decision.outcome != GRANTED or decision.fn is None:
            return None, None
        # `model_facing_params`, not `declared_params`: a `wrapper_only` param is refused by
        # `validate_params`, so publishing it would advertise a binding that cannot be made.
        params = model_facing_params(decision.fn)
        hints = _resolved_hints(decision.fn)
        rendered = ", ".join(_rendered_param(p, hints) for p in params.values())
        # `shown`, not the raw `system` (`_echoed_system`): every other span of this answer
        # goes through that bound, and the one line the lead is told to COPY is the last place
        # an unbounded model-authored name should land unescaped.
        line = f'query(system="{shown}", verb="{verb}", params={{{rendered}}})'
        return (line, any(name not in hints for name in params)), None
    except _RERAISE:
        raise
    except BaseException as e:  # noqa: BLE001 — a surface that cannot be derived degrades loud
        return None, _LIST_VERBS_UNDERIVABLE.format(
            system=shown, err=f"{shown}.{verb}: {type(e).__name__}: {e}",
        )


def _tool_list_verbs(registry: Any, system: str) -> str:
    """`system`'s granted verbs and their declared params, derived at call time.

    The two readers are `model_facing_params` and `_resolved_hints` — the SAME pair
    `validate_params` enforces on — so what this publishes and what the boundary accepts
    cannot drift apart. The grant filter goes through `registry.decide`, the dispatch path's
    own decision point, so a verb this names is a verb `query` would admit. The SYSTEM-level
    check runs first and separately, because reaching `decide` already costs the adapter
    import that ordering exists to withhold.

    Nothing is persisted: no queries-table row, no circuit breaker, no repeat guard — this is
    a read of our own adapter signatures, so the offline loop's `.queries` keeps meaning "what
    the defender ran", and the first-party output carries no `wrap_fresh` untrusted frame.
    """
    shown = _echoed_system(system)
    # GRANT FIRST, before anything resolves an adapter — `decide`'s own ordering (§7 R11).
    reachable = _granted_systems(registry)
    if system not in reachable:
        roster = f" The systems your grant reaches: {', '.join(reachable)}." if reachable else ""
        return _LIST_VERBS_UNREACHABLE.format(system=shown, roster=roster)

    declared, degradation = _list_verbs_declared(registry, system, shown)
    if degradation is not None:
        return degradation

    lines: list[str] = []
    any_unenforced = False
    # `key=str`, because the sort must not be the branch that raises: a broken adapter's
    # `VERBS` may mix key types (`{"a": …, 7: …}`), and a bare `sorted` over that is a
    # TypeError ending the lead's turn before any degradation can be composed. A non-string
    # key survives the sort and is then withheld by the grant filter below.
    for verb in sorted(declared, key=str):
        rendered, failure = _list_verbs_line(registry, system, verb, shown)
        if failure is not None:
            return failure
        if rendered is None:
            continue
        line, unenforced = rendered
        any_unenforced = any_unenforced or unenforced
        lines.append(line)

    if not lines:
        return _LIST_VERBS_NONE_GRANTED.format(system=shown)

    out = (
        _LIST_VERBS_HEADER.format(system=shown, count=len(lines))
        + "\n" + "\n".join(f"    {line}" for line in lines) + "\n"
        + _LIST_VERBS_LEGEND.format(system=shown)
    )
    if any_unenforced:
        out += _LIST_VERBS_UNENFORCED_NOTE.format(marker=UNENFORCED_TYPE)
    return out


def register_list_verbs_tool(agent, registry) -> None:

    @agent.tool
    async def list_verbs(ctx: RunContext[Any], system: str) -> str:
        """The verbs one system of record declares and the params each one binds — read from
        the adapter's live signatures, filtered to what your grant admits. Call it before you
        coin a query no template covers: it is the same surface the `query` tool enforces, so
        a param it names is a param that will bind and one it omits will be refused. `system`
        is the system you were dispatched to (the Dispatch block names it); call it again for
        another system if this lead crosses one. It runs nothing against the system of record
        and is not recorded as a query."""
        # OFF THE EVENT LOOP, as the `query` tool's own dispatch is: this reads no system of
        # record, but it imports the adapter MODULE on first use and re-parses its source per
        # withheld verb (`declared_verb_names`) — synchronous filesystem work that would
        # otherwise stall every sibling lead's turn in the process.
        return await asyncio.to_thread(_tool_list_verbs, registry, system)


def register_query_tool(agent, registry) -> None:

    @agent.tool
    async def query(
        ctx: RunContext[Any], system: str, verb: str,
        params: dict[str, Any], query_id: str | None = None,
    ) -> Any:
        """Run one data-source query. `system` and `verb` name a declared verb — `list_verbs`
        answers which verbs this role holds on a system and what each one binds; `params` binds
        that verb's declared params by NAME (a verb declares exactly what it takes — there are
        no flags, no shell, and no `--help`).
        `query_id` binds this call to a catalog template id (`{system}.{template}`), or a fresh
        `{system}.{kebab-name}` you coin for a query no template covers; omit it and it derives
        as `{system}.{verb}`. The payload is captured to the queries table and persisted whole on
        disk automatically — you get a field-shape view plus the path to compute over."""
        deps = ctx.deps
        fn = registry.verbs(system)[verb]
        vctx = VerbContext(
            defender_dir=deps.defender_dir, run_dir=deps.run_dir, env=_bash_env(deps),
        )
        return await asyncio.to_thread(fn, vctx, **params)



def _raw_args(args: Any) -> dict:
    """The call's arguments as the MODEL sent them, coerced to a dict it cannot escape.

    `RecursionError` sits beside the decode errors and is not decoration. The one production
    caller is `wrap_tool_validate`'s rejection handler — no `try` of its own — and the string
    re-parsed here is the SAME one pydantic just refused. A deeply nested body fails pydantic
    with `json_invalid: recursion limit exceeded` (a `ValidationError`, so the handler runs) and
    then exhausts `json.loads`'s own limit here. `RecursionError` is a `RuntimeError`, so the
    other two arms miss it: it escapes, NO ROW is written, the companion guard loses the
    occurrence it recovers from the rows it wrote, and the fault unwinds past
    `_run_validate_hooks`, which catches only `(ValidationError, ModelRetry)`. `{}` is the
    honest answer — the arguments amounted to nothing readable, which is what the row records."""
    if isinstance(args, str):
        try:
            args = json.loads(args or "{}")
        except (json.JSONDecodeError, ValueError, RecursionError):
            return {}
    return args if isinstance(args, dict) else {}


def _as_dict(v: Any) -> dict:
    return v if isinstance(v, dict) else {}


from .tools import _bash_env, _format_bash_result  # noqa: E402
from .tools_gather import _payload_note, _tripped_message  # noqa: E402


__all__ = [
    "CONTROL_FLOW_EXCEPTIONS",
    "DEFAULT_FAULT_EXIT",
    "QueryCapture",
    "TOOL_NAME",
    "UNENFORCED_TYPE",
    "register_list_verbs_tool",
    "register_query_tool",
    "resolve_query_id",
]
