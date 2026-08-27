"""The content schema for the run's two model-authored artifacts.

`report.md` and `investigation.md` are the only files a model authors that leave the
system: the report and investigation ride verbatim into the judge LLM prompt, and the
report body into the ticket bridge's HTTP egress. This module owns what a well-formed one
IS — the report's frontmatter grammar, its `disposition` enum, the UTF-8 byte bounds on
both, and the investigation's invlang structure.

It owns NO authorization. Who may write where is `runtime/permission/files.py`'s job (the
`write_allow` allowlist, the `write ⊆ read roots` containment check, and the resolve-then-key
decision that picks which artifact a path IS); this module is called only after those gates
have already said yes, and it never sees a policy, a run dir, or a path.

Every entry point returns `str | None` — the deny reason, or `None` for "well-formed" —
deliberately NOT a `permission.Decision`. `Decision` is authorization vocabulary, and keeping
it out is what lets this module sit as a neutral leaf: the permission gate and the learning
loop's read-side validators both import it without importing each other. The gate wraps a
returned reason back into `Decision(False, reason)`.
"""

from __future__ import annotations

import sys

import yaml

from defender._frontmatter import FrontmatterError, split_frontmatter
# Imported to be USED, not re-exported: other readers of the vocabulary import `_vocab`
# directly. The normalizer is deliberately NOT imported — this module holds the WRITE gate,
# and on write the value is tested exactly (see `validate_report`).
from defender._vocab import DISPOSITION_ENUM
from defender.skills.invlang.validate import Diagnostic, diagnose, warn_diagnostics

# Output-structure bounds for the run's two model-authored artifacts, all in UTF-8 BYTES.
# A VOLUME + STRUCTURE control on bytes that leave the system, not a content oracle: an
# in-bound, well-formed payload still passes.
REPORT_FRONTMATTER_MAX = 512
REPORT_FILE_MAX = 8192
INVESTIGATION_FILE_MAX = 65536

# Still refused even though the judge now places report bytes inside an invocation-salted
# frame (`_untrusted.wrap`): accepting the sequence would loosen the report contract
# independently of that prompt-layer hardening.
REPORT_CLOSE_DELIMITER = "</report>"

REPORT_NAME = "report.md"
INVESTIGATION_NAME = "investigation.md"

# The artifacts this module has a schema for. The gate iterates this to decide whether a
# resolved write target is a gated artifact at all, so adding a third one is a change HERE
# rather than a new branch in `decide_write`.
ARTIFACT_NAMES = (REPORT_NAME, INVESTIGATION_NAME)

# Which artifacts need the CURRENT on-disk text as a baseline. Only invlang does (it is
# append-only, so validation is against the document's history, not the text alone). The
# gate reads the baseline and passes it in — this module does no filesystem access — and
# it must read for THESE names only: an unconditional read would put a `read_text` that can
# raise on the report.md path, where none ran before.
NEEDS_BASELINE = frozenset({INVESTIGATION_NAME})


def _utf8_len(text: str) -> int:
    """Byte length under UTF-8 — the basis for every bound here. A multibyte codepoint costs
    its real transport bytes, so a `len(str)` codepoint count would under-count and let a body
    over the byte bound through."""
    return len(text.encode("utf-8"))


def _has_duplicate_top_level_key(raw: str) -> bool:
    """True iff the frontmatter YAML declares the same top-level key twice. PyYAML's `safe_load`
    silently resolves duplicates last-wins, so a `disposition:` declared twice (a valid member
    shadowing an invalid one) would pass a plain membership check on the parsed mapping — this
    catches it at the node level instead. Returns False on any parse trouble: `raw` already
    parsed once via `split_frontmatter`, so trouble here means no reliable duplicate signal and
    the other checks stand.

    Duplicates are judged on the CONSTRUCTED key — what `safe_load` would put in the mapping —
    not on the raw scalar node text. The node text is the wrong equality: it FALSE-POSITIVES
    (`1:` and `"1":` are distinct keys, one int and one str, but share `key_node.value` `"1"`)
    and FALSE-NEGATIVES (`1:` / `0x1:`, `yes:` / `true:` construct to the same key from
    different text). ONE `SafeLoader` — the class `split_frontmatter` parses under — both
    composes and constructs, so the two readings of "the same key" cannot diverge. That
    includes `flatten_mapping`: `safe_load` expands a `<<:` merge INTO the mapping before
    building it, so a merge-injected key is a real last-wins entry that skipping the flatten
    would hide. A key that cannot be constructed or compared (an untabled tag, an unhashable
    list/mapping key, an out-of-range implicit timestamp — all of which `safe_load` would
    reject upstream anyway) is skipped rather than raised out of this blocking gate."""
    loader = yaml.SafeLoader(raw)
    try:
        try:
            node = loader.get_single_node()
            if not isinstance(node, yaml.MappingNode):
                return False
            loader.flatten_mapping(node)  # `<<:` merges become real top-level pairs
        except (yaml.YAMLError, RecursionError):
            return False
        seen: set[object] = set()
        for key_node, _value_node in node.value:
            try:
                key = loader.construct_object(key_node, deep=True)
                duplicate = key in seen
            except (yaml.YAMLError, RecursionError, TypeError, ValueError):
                continue  # unconstructible / unhashable — no reliable signal for THIS key
            if duplicate:
                return True
            seen.add(key)
        return False
    finally:
        loader.dispose()


def encodable_or_reason(proposed_text: str, artifact: str) -> str | None:
    """Deny text that is not UTF-8-encodable, BEFORE either artifact's own schema runs.

    Both artifact schemas measure UTF-8 BYTES (`_utf8_len`) and their text splices into live
    egresses. Content that is not UTF-8-encodable — a lone surrogate, reachable from a model
    tool-call JSON arg (`json.loads('"\\ud800"')` yields one) — can be neither byte-measured
    nor written (`write_text(encoding="utf-8")` raises the SAME error), so it is denied
    FAIL-CLOSED here rather than letting `_utf8_len`'s `.encode()` raise out of the gate: the
    gate's contract is to return a Decision, never propagate (its RESOLVE_ERRORS rule)."""
    try:
        proposed_text.encode("utf-8")
    except UnicodeEncodeError:
        return (
            f"{artifact} contains bytes that are not valid UTF-8 (e.g. a lone surrogate) — "
            "rewrite it as UTF-8 text and retry."
        )
    return None


def validate_report(proposed_text: str) -> str | None:
    """The report.md output-structure schema. Fail-closed on any of: unparseable frontmatter
    (leading+closing fence, valid YAML, a mapping); a missing / duplicated / non-string /
    out-of-enum top-level `disposition`; a frontmatter or whole file over its byte bound; or a
    literal `</report>` that would break out of the judge's report block. Only `disposition` is
    required — `case_id`/`confidence` are deliberately unvalidated (the ticket path derives
    case_id from the run dir; confidence is untyped everywhere). Each reason is actionable text
    the tool lane raises as ModelRetry."""
    try:
        fm, raw, _body = split_frontmatter(proposed_text)
    except FrontmatterError as e:
        return f"report.md frontmatter is malformed — fix and rewrite: {e}"
    if _has_duplicate_top_level_key(raw):
        return (
            "report.md frontmatter declares a top-level key more than once — remove the "
            "duplicate and rewrite."
        )
    disposition = fm.get("disposition")
    # `isinstance(str)` FIRST: a non-string value (a list / mapping) is unhashable, so a bare
    # `value in DISPOSITION_ENUM` (a set) would raise TypeError out of the gate instead of denying.
    #
    # lint-vocabulary: ok — the WRITE gate is exact where every reader normalizes, and the
    # asymmetry is the point: here there is still an author to ask, so an exact test denies a
    # zero-width-laced disposition with actionable retry text. `normalized_disposition` would
    # silently ACCEPT it and write a document no reader can tell from a clean one.
    if not (isinstance(disposition, str) and disposition in DISPOSITION_ENUM):
        return (
            "report.md frontmatter must carry a top-level `disposition` in "
            f"{sorted(DISPOSITION_ENUM)} (got {disposition!r}) — fix and rewrite."
        )
    if _utf8_len(raw) > REPORT_FRONTMATTER_MAX:
        return (
            f"report.md frontmatter is {_utf8_len(raw)} bytes, over the "
            f"{REPORT_FRONTMATTER_MAX}-byte limit — trim it and rewrite."
        )
    if _utf8_len(proposed_text) > REPORT_FILE_MAX:
        return (
            f"report.md is {_utf8_len(proposed_text)} bytes, over the "
            f"{REPORT_FILE_MAX}-byte limit — trim it and rewrite."
        )
    if REPORT_CLOSE_DELIMITER in proposed_text:
        return (
            f"report.md contains the literal {REPORT_CLOSE_DELIMITER!r} delimiter, which would "
            "break out of the judge's report block — remove it and rewrite."
        )
    return None


#: Every refusal on this artifact carries it. The model is told its own context IS the file
#: (`SKILL.md`, "Re-sync, don't re-read"), so the refusal text is its primary signal about what
#: is on disk: a model that believes a refused block landed anchors its next edit to text that
#: was never written.
#: The leading fragment is minted separately because some refusal paths have no proposed text
#: of their own — a refused CLOSE offered no bytes, so "does not contain your text" would be a
#: claim about nothing. Every refusal LEADS with this and an ACCEPT leads with its byte count,
#: so the model tells the two apart by the first sentence and does not re-emit on a warning.
UNCHANGED_LEAD = "No changes were made"

UNCHANGED_NOTICE = (
    f"{UNCHANGED_LEAD} — the file on disk is unchanged and does not contain your text."
)


def render_diagnostic(d: Diagnostic) -> str:
    """One diagnostic as the model sees it: the message leads, with locus and corrections as
    additive lines beneath it.

    The row is suppressed when the message already contains it — a parse warning's `format()`
    embeds `row=...`, and repeating it is noise. That embedding is a `repr()`, so the raw
    substring test alone misses any row carrying a backslash or a quote; both spellings are
    checked. A row past `format()`'s 200-char truncation matches NEITHER and is printed whole,
    which is the point of the line.

    MODULE-PUBLIC because the ACCEPT path needs it too: a warn-only document makes this module
    return no text at all, so the tool bodies render through this one renderer rather than
    growing a second, drifting spelling of the same three lines."""
    lines = [f"  - {d.message}"]
    if d.locus is not None and not (
        d.locus.row_text in d.message or repr(d.locus.row_text) in d.message
    ):
        lines.append(f"    row: {d.locus.row_text}")
    if d.fix:
        lines.append(f"    use: {d.fix[0]}")
        lines.extend(f"         {alt}" for alt in d.fix[1:])
    return "\n".join(lines)


def _warns_quietly(current: str) -> bool:
    """Is a row flagged on the ON-DISK document? Answered for one purpose only: picking which
    REMEDY the size refusal names.

    It swallows a validator error rather than propagating it: the branch that asks has already
    decided its verdict (the write is denied either way), and letting `diagnose` raise out of
    `validate_investigation` here would escape the module's fail-closed contract and take the
    tool call down instead of denying it."""
    try:
        return bool(warn_diagnostics(current))
    except Exception:  # noqa: BLE001 — a prose choice must not decide the gate's control flow
        return False


def validate_investigation(proposed_text: str, current: str | None) -> str | None:
    """The investigation.md schema: the byte bound FIRST (so an over-bound document yields a
    deterministic SIZE-failure reason without the invlang validator ever running on the
    oversize text), then structural invlang validation of the full proposed text (`current`,
    the caller-supplied on-disk text, supplies the append-only baseline). Empty /
    whitespace-only text is under bound and invlang-empty, so it accepts.

    Every refusing branch states that nothing was written. This module owns the rendering and
    `skills.invlang.validate` owns the finding — hence `diagnose` here rather than the
    `validate_companion` string surface.

    WARN-severity findings do not refuse and are not returned through this surface at all; the
    tool bodies derive that window themselves."""
    if _utf8_len(proposed_text) > INVESTIGATION_FILE_MAX:
        # The size is the WHOLE document and the only writer APPENDS to it, so "trim it and
        # re-send" is advice the model cannot always take: once what is committed fills the
        # bound, no block is small enough. Name the on-disk share so the model can tell "send
        # less" from "you are out of room".
        on_disk = _utf8_len(current) if current is not None else 0
        # With a row flagged, "close the investigation" is a verb the M5 gate refuses — that
        # remedy would name the one move the model cannot make. `fix_row(old, "")` is the
        # escape that actually shrinks the document.
        if on_disk and current is not None and _warns_quietly(current):
            remedy = (
                f"{on_disk} of those bytes are already committed and cannot be removed, and a "
                "flagged row is blocking the close — repair or delete it with "
                '`fix_row(old_row, "")`, then send a smaller block.'
            )
        elif on_disk:
            remedy = (
                f"{on_disk} of those bytes are already committed and cannot be removed — send a "
                "smaller block, or close the investigation on the evidence you already have."
            )
        else:
            remedy = "Trim it and re-send."
        return (
            f"investigation.md is {_utf8_len(proposed_text)} bytes, over the "
            f"{INVESTIGATION_FILE_MAX}-byte limit. {UNCHANGED_NOTICE} {remedy}"
        )
    # Fail closed on an internal validator error — same as invlang_validate's
    # hook, which exits 2 (block) rather than letting the write through.
    try:
        found = diagnose(proposed_text, current)
    except Exception as e:  # noqa: BLE001 — a blocking gate must fail closed
        return (
            f"investigation.md validation errored — failing closed: {e!r}. "
            f"{UNCHANGED_NOTICE} Simplify the invlang and re-send."
        )
    rendered = _rendered_errors(found)
    if rendered is not None:
        return (
            f"investigation.md failed invlang validation. {UNCHANGED_NOTICE}\n\n"
            + rendered
            + "\n\nRe-send the block with those rows corrected."
        )
    return None


def _rendered_errors(found: list[Diagnostic]) -> str | None:
    """The ERROR-severity findings as the model sees them, or `None` when there are none.

    One filter and one renderer for both readings of this schema — the WRITE gate above and
    the CLOSE gate below. They frame the result differently (a refused write can say the
    file is unchanged; a refused close offered no bytes to be unchanged FROM) and that is the
    only thing they differ in, so the frame is the caller's and everything under it is here.

    WARN severity is excluded on both paths for the same reason: it is the repair window
    `runtime.tools` owns, not a reason to refuse."""
    errors = [d for d in found if d.severity != "warning"]
    if not errors:
        return None
    return "\n".join(render_diagnostic(d) for d in errors)


def committed_investigation_reason(text: str) -> str | None:
    """Is `investigation.md` AS IT STANDS well-formed enough to publish? The deny reason, or
    `None`.

    This is the CLOSE's reading of the same schema `validate_investigation` gates writes with,
    and it is deliberately narrower in two ways:

      * NO BYTE BOUND. The bound is a volume control on what a write ADDS, and a close adds
        nothing to this document. Enforcing it here would also make the write gate's own
        refusal text false — over-bound, that text offers "close the investigation on the
        evidence you already have" as the way out, which is exactly the move a size-checking
        close would refuse.
      * THE DOCUMENT IS ITS OWN BASELINE. Every check that keys on `current` asks what THIS
        WRITE INTRODUCES, and a close introduces nothing — so the honest baseline for a
        committed document is the document. `None` is the WRONG spelling of that, and not
        harmlessly: `_check_surface` subtracts the baseline's orphaned headers from the
        proposal's, so with no baseline every unfenced header already on disk reads as newly
        added. `investigation.md` is append-only and `fix_row` reaches `:R attr_updates` rows
        only, so those bytes can never be fenced after the fact — the close would refuse, for
        the life of the run, a document every write gate had accepted, with no repair the
        model can make. Passed the text itself, `_check_surface` subtracts to nothing and
        `_check_append_only` compares the document to itself (equal fence counts, every
        record mapping to itself), which is exactly the no-op "nothing is proposed" means.

    Fails OPEN on an internal validator error, and this is where it parts company with the
    write gate above. There, failing closed is free — nothing is written and the model
    re-sends. Here the same choice makes a validator BUG an unclosable run: no repair exists
    for it, so the model retries until the framework force-closes `inconclusive` and the
    disposition the run reached is discarded. `runtime.tools.committed_document_refusal`, the
    only caller, already fails open when the document cannot be READ, for exactly that reason
    (#836's H7) — a gate that failed open on unreadable bytes and closed on an unreadable
    validator would be answering one question two ways. The condition is logged, because a
    validator that raises is a defect to chase and silence is how it would go unchased.

    WHY THE CLOSE NEEDS ITS OWN READING AT ALL. Every other write verb reaches this module
    through `permission.decide_write`, so "a committed investigation parses" held by
    construction — except at the close, which is the one verb that PUBLISHES: it commits the
    report whose frontmatter the learning loop trains on and hands the parsed companion to the
    review gate. The one verb that publishes was the one verb that did not check (#961)."""
    try:
        found = diagnose(text, text)
    except Exception as e:  # noqa: BLE001 — fail open (H7); an unclosable run is worse
        print(
            f"[artifact_schema] investigation.md could not be validated for the close, "
            f"treating it as publishable: {e!r}",
            file=sys.stderr,
        )
        return None
    rendered = _rendered_errors(found)
    if rendered is None:
        return None
    return (
        "close blocked: `investigation.md` does not pass invlang validation, and the close is "
        "what publishes it — the report commits against this document and the review gate "
        "reads it.\n\n"
        + rendered
        + "\n\nRepair those rows with `fix_row(old_row, new_row)` — or delete one with "
        '`fix_row(old_row, "")` — and close again.'
    )


def validate_artifact(name: str, proposed_text: str, current: str | None) -> str | None:
    """Validate `proposed_text` as the artifact `name` (one of `ARTIFACT_NAMES`), returning the
    deny reason or `None`. The UTF-8-encodability check runs for BOTH artifacts before either
    schema, because both measure bytes. `current` is the on-disk baseline, required for the
    artifacts in `NEEDS_BASELINE` and ignored for the rest. An unknown `name` raises rather
    than silently accepting, so a third artifact added to the tuple without a schema cannot
    ship as a permanently-allowed write."""
    reason = encodable_or_reason(proposed_text, name)
    if reason is not None:
        return reason
    if name == REPORT_NAME:
        return validate_report(proposed_text)
    if name == INVESTIGATION_NAME:
        return validate_investigation(proposed_text, current)
    raise ValueError(f"no content schema for artifact {name!r}")
