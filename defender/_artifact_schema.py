"""The content schema for the run's two model-authored artifacts.

`report.md` and `investigation.md` are the only model-authored files that leave the system
(into the judge prompt and the ticket bridge's HTTP egress). This module owns what a
well-formed one is: the report's frontmatter grammar and `disposition` enum, UTF-8 byte
bounds, and the investigation's invlang structure.

It owns no authorization (`runtime/permission/files.py` does) and never sees a policy, run
dir, or path. Entry points return a deny reason or `None`, not a `permission.Decision`, so
this stays a neutral leaf both the gate and read-side validators can import.
"""

from __future__ import annotations

import logging

from defender import _run_paths
from defender._frontmatter import FrontmatterError, split_frontmatter
from defender._yaml import duplicate_top_level_key
# Not the normalizer: the write gate tests the value exactly (see `validate_report`).
from defender._vocab import DISPOSITION_ENUM
from defender.skills.invlang.validate import Diagnostic, diagnose, warn_diagnostics

_logger = logging.getLogger(__name__)

# Volume bounds on bytes that leave the system, in UTF-8 bytes — not a content check.
REPORT_FRONTMATTER_MAX = 512
REPORT_FILE_MAX = 8192
INVESTIGATION_FILE_MAX = 65536

# Refused even though the judge frames report bytes in a salted frame: the report contract
# should not depend on that prompt-layer hardening.
REPORT_CLOSE_DELIMITER = "</report>"

# The gate iterates this to decide whether a write target is a gated artifact, so a third
# artifact is added here. A function so names always come from the run-dir owner; this module
# must not hold record names of its own.
def artifact_names() -> tuple[str, ...]:
    """The artifacts this module has a schema for, by name, from the run-dir owner."""
    return (_run_paths.RUN_LAYOUT.report.name, _run_paths.RUN_LAYOUT.investigation.name)

# Only the append-only investigation validates against its history. The gate reads the
# baseline only for these names, keeping a raising `read_text` off the report path.
def needs_baseline(name: str) -> bool:
    """Does validating this artifact need the CURRENT on-disk text?"""
    return name == _run_paths.RUN_LAYOUT.investigation.name


def _utf8_len(text: str) -> int:
    """Byte length under UTF-8 — `len(str)` would under-count multibyte codepoints."""
    return len(text.encode("utf-8"))


def _has_duplicate_top_level_key(raw: str) -> bool:
    """True iff the frontmatter declares a top-level key twice — `safe_load` keeps the last,
    so a valid `disposition:` could shadow an invalid one. Delegates to `_yaml` so the gate and
    the permission table agree on what `safe_load` collapses; False on parse trouble.
    """
    return duplicate_top_level_key(raw)


def encodable_or_reason(proposed_text: str, artifact: str) -> str | None:
    """Deny text that is not UTF-8-encodable, before either artifact's schema runs.

    A lone surrogate (reachable from a model's JSON tool arg, `json.loads('"\\ud800"')`) can be
    neither byte-measured nor written; denying here keeps `.encode()` from raising out of a
    gate that must always return a decision."""
    try:
        proposed_text.encode("utf-8")
    except UnicodeEncodeError:
        return (
            f"{artifact} contains bytes that are not valid UTF-8 (e.g. a lone surrogate) — "
            "rewrite it as UTF-8 text and retry."
        )
    return None


def validate_report(proposed_text: str) -> str | None:
    """The report.md schema. Fail-closed on: unparseable frontmatter; a missing, duplicated,
    non-string or out-of-enum top-level `disposition`; frontmatter or file over its byte bound;
    or a literal `</report>`. Only `disposition` is required (`case_id` comes from the run dir,
    `confidence` is untyped).

    Reasons are model-facing (raised as ModelRetry). After the frontmatter parses, all
    independent problems are reported together so the model fixes them in one retry."""
    try:
        fm, raw, _body = split_frontmatter(proposed_text)
    except FrontmatterError as e:
        return f"report.md frontmatter is malformed — fix and rewrite: {e}"  # lint-run-records: ok — a message naming the record for the model or operator, not a path
    problems: list[str] = []
    if _has_duplicate_top_level_key(raw):
        problems.append(
            "report.md frontmatter declares a top-level key more than once — remove the "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
            "duplicate and rewrite."
        )
    disposition = fm.get("disposition")
    # `isinstance(str)` first: an unhashable value would raise TypeError in the set test.
    # lint-vocabulary: ok — the write gate is exact where readers normalize: there is still an
    # author to ask, so a zero-width-laced disposition is denied with retry text.
    if not (isinstance(disposition, str) and disposition in DISPOSITION_ENUM):
        problems.append(
            "report.md frontmatter must carry a top-level `disposition` in "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
            f"{sorted(DISPOSITION_ENUM)} (got {disposition!r}) — fix and rewrite."
        )
    if _utf8_len(raw) > REPORT_FRONTMATTER_MAX:
        problems.append(
            f"report.md frontmatter is {_utf8_len(raw)} bytes, over the "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
            f"{REPORT_FRONTMATTER_MAX}-byte limit — trim it and rewrite."
        )
    if _utf8_len(proposed_text) > REPORT_FILE_MAX:
        problems.append(
            f"report.md is {_utf8_len(proposed_text)} bytes, over the "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
            f"{REPORT_FILE_MAX}-byte limit — trim it and rewrite."
        )
    if REPORT_CLOSE_DELIMITER in proposed_text:
        problems.append(
            f"report.md contains the literal {REPORT_CLOSE_DELIMITER!r} delimiter, which would "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
            "break out of the judge's report block — remove it and rewrite."
        )
    if not problems:
        return None
    return " ".join(problems)


#: Every refusal on this artifact leads with it. The model treats its context as the file, so
#: it must be told plainly that a refused block did not land; an accept leads with its byte
#: count instead. The lead is separate because a refused close has no text of its own.
UNCHANGED_LEAD = "No changes were made"

UNCHANGED_NOTICE = (
    f"{UNCHANGED_LEAD} — the file on disk is unchanged and does not contain your text."
)


def render_diagnostic(d: Diagnostic) -> str:
    """One diagnostic as the model sees it: the message, then locus and corrections.

    The row is omitted when the message already embeds it (raw or `repr()` form); a row past
    `format()`'s 200-char truncation matches neither and is printed whole. Public because the
    tool bodies also render warnings on the accept path."""
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
    """Is a row flagged on the on-disk document? Only picks which remedy the size refusal
    names, so a validator error is swallowed — the write is denied either way."""
    try:
        return bool(warn_diagnostics(current))
    except Exception:  # noqa: BLE001 — a prose choice must not decide the gate's control flow
        return False


def validate_investigation(proposed_text: str, current: str | None) -> str | None:
    """The investigation.md schema: the byte bound first (so invlang never runs on oversize
    text), then invlang validation of the full proposed text against `current` as the
    append-only baseline. Empty text accepts.

    Every refusal states that nothing was written. Warnings do not refuse and are not returned
    here; the tool bodies handle that repair window."""
    if _utf8_len(proposed_text) > INVESTIGATION_FILE_MAX:
        # The bound covers the whole append-only document, so name the committed share: the
        # model must tell "send less" from "out of room".
        on_disk = _utf8_len(current) if current is not None else 0
        # With a row flagged the close is refused, so name `fix_row(old, "")`, which shrinks
        # the document.
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
            f"investigation.md is {_utf8_len(proposed_text)} bytes, over the "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
            f"{INVESTIGATION_FILE_MAX}-byte limit. {UNCHANGED_NOTICE} {remedy}"
        )
    # Fail closed on an internal validator error. (The adapter roster was read at run start,
    # so an unreadable adapters dir cannot surface here.)
    try:
        found = diagnose(proposed_text, current)
    except Exception as e:  # noqa: BLE001 — a blocking gate must fail closed
        return (
            f"investigation.md validation errored — failing closed: {e!r}. "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
            f"{UNCHANGED_NOTICE} Simplify the invlang and re-send."
        )
    rendered = _rendered_errors(found)
    if rendered is not None:
        return (
            f"investigation.md failed invlang validation. {UNCHANGED_NOTICE}\n\n"  # lint-run-records: ok — a message naming the record for the model or operator, not a path
            + rendered
            + "\n\nRe-send the block with those rows corrected."
        )
    return None


def _rendered_errors(found: list[Diagnostic]) -> str | None:
    """The error-severity findings rendered for the model, or `None`. Shared by the write and
    close gates, which differ only in framing. Warnings are `runtime.tools`' repair window."""
    errors = [d for d in found if d.severity != "warning"]
    if not errors:
        return None
    return "\n".join(render_diagnostic(d) for d in errors)


def committed_investigation_reason(text: str) -> str | None:
    """Is `investigation.md` as it stands well-formed enough to publish? The deny reason, or
    `None`. The close publishes without going through `permission.decide_write`, so it needs
    its own check.

    Narrower than `validate_investigation`:

      * No byte bound: a close adds nothing, and the write gate's over-bound refusal offers
        closing as the way out.
      * The document is its own baseline: checks keyed on `current` ask what a write
        introduces, and a close introduces nothing. With `None`, every unfenced header already
        on disk would read as new, and since the document is append-only the close would be
        refused for the rest of the run with no possible repair.

    Fails open (logged) on an internal validator error: failing closed would make a validator
    bug an unclosable run. Unreadable documents are handled by the close before this gate."""
    try:
        found = diagnose(text, text)
    except Exception as e:  # noqa: BLE001 — fail open; an unclosable run is worse
        _logger.warning(
            f"investigation.md could not be validated for the close, "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
            f"treating it as publishable: {e!r}",
        )
        return None
    rendered = _rendered_errors(found)
    if rendered is None:
        return None
    return (
        "close blocked: `investigation.md` does not pass invlang validation, and the close is "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
        "what publishes it — the report commits against this document and the review gate "
        "reads it.\n\n"
        + rendered
        + "\n\nRepair those rows with `fix_row(old_row, new_row)` — or delete one with "
        '`fix_row(old_row, "")` — and close again.'
    )


def validate_artifact(name: str, proposed_text: str, current: str | None) -> str | None:
    """Validate `proposed_text` as the artifact `name`, returning the deny reason or `None`.
    `current` is the on-disk baseline for artifacts `needs_baseline` names. An unknown `name`
    raises, so an artifact without a schema can never be a permanently-allowed write."""
    reason = encodable_or_reason(proposed_text, name)
    if reason is not None:
        return reason
    if name == _run_paths.RUN_LAYOUT.report.name:
        return validate_report(proposed_text)
    if name == _run_paths.RUN_LAYOUT.investigation.name:
        return validate_investigation(proposed_text, current)
    raise ValueError(f"no content schema for artifact {name!r}")
