"""The content schema for the run's model-authored artifact.

`investigation.md` is the only model-authored file that leaves the system (into the judge
prompt). This module owns what a well-formed one is: its UTF-8 byte bound and its invlang
structure. (The run's headline is the closing record the close writes, #1534, which no model
write reaches.)

It owns no authorization (`investigation/permission/files.py` does) and never sees a policy, run
dir, or path. Entry points return a deny reason or `None`, not a `permission.Decision`, so
this stays a neutral leaf both the gate and read-side validators can import.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from typing import Protocol

from defender.records import RUN_LAYOUT

_logger = logging.getLogger(__name__)


class _Locus(Protocol):
    @property
    def row_text(self) -> str: ...


class Diagnostic(Protocol):
    """What this gate reads of one invlang finding; `skills.invlang.validate.Diagnostic` is it."""

    @property
    def message(self) -> str: ...
    @property
    def locus(self) -> _Locus | None: ...
    @property
    def fix(self) -> tuple[str, ...]: ...
    @property
    def severity(self) -> str: ...


# The invlang validator lives above this layer, so it is handed in rather than imported: the
# `skills.invlang.validate` package registers itself when it loads, and the `investigation`
# package, home of every writer and closer, loads it. Until it has, a write is refused and a
# close raises, rather than either passing text unvalidated.
_diagnose: Callable[[str, str | None], Sequence[Diagnostic]] | None = None
_warn_diagnostics: Callable[[str], Sequence[Diagnostic]] | None = None


class ValidatorNotRegistered(RuntimeError):
    """The invlang validator never registered: the process did not load `skills.invlang.validate`."""


def register_invlang_validator(
    diagnose: Callable[[str, str | None], Sequence[Diagnostic]],
    warn_diagnostics: Callable[[str], Sequence[Diagnostic]],
) -> None:
    """Hand this gate the invlang validator. Called once by the validator's own package."""
    global _diagnose, _warn_diagnostics
    _diagnose, _warn_diagnostics = diagnose, warn_diagnostics


def _validator() -> tuple[
    Callable[[str, str | None], Sequence[Diagnostic]], Callable[[str], Sequence[Diagnostic]]
]:
    if _diagnose is None or _warn_diagnostics is None:
        raise ValidatorNotRegistered(
            "the invlang validator is not registered — import `defender.skills.invlang.validate` "
            "at startup; an unvalidated investigation is neither written nor closed"
        )
    return _diagnose, _warn_diagnostics

# Volume bounds on bytes that leave the system, in UTF-8 bytes — not a content check.
INVESTIGATION_FILE_MAX = 65536

# The gate iterates this to decide whether a write target is a gated artifact, so a third
# artifact is added here. A function so names always come from the run-dir owner; this module
# must not hold record names of its own.
def artifact_names() -> tuple[str, ...]:
    """The artifacts this module has a schema for, by name, from the run-dir owner."""
    return (RUN_LAYOUT.investigation.name,)

# Only the append-only investigation validates against its history. The gate reads the
# baseline only for these names.
def needs_baseline(name: str) -> bool:
    """Does validating this artifact need the CURRENT on-disk text?"""
    return name == RUN_LAYOUT.investigation.name


def utf8_len(text: str) -> int:
    """Byte length under UTF-8 — `len(str)` would under-count multibyte codepoints."""
    return len(text.encode("utf-8"))


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
        return bool(_validator()[1](current))
    except Exception:  # noqa: BLE001 — a prose choice must not decide the gate's control flow
        return False


def validate_investigation(proposed_text: str, current: str | None) -> str | None:
    """The investigation.md schema: the byte bound first (so invlang never runs on oversize
    text), then invlang validation of the full proposed text against `current` as the
    append-only baseline. Empty text accepts.

    Every refusal states that nothing was written. Warnings do not refuse and are not returned
    here; the tool bodies handle that repair window."""
    # Before the size branch, whose remedy depends on the validator too. A refusal, not a
    # raise: the permission gate's callers expect a deny reason, and this still writes nothing.
    if _diagnose is None or _warn_diagnostics is None:
        _logger.error(
            "investigation.md write refused: the invlang validator is not registered — "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
            "this process never loaded `defender.skills.invlang.validate`"
        )
        return (
            "investigation.md cannot be validated in this process: the invlang validator is "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
            f"not loaded. {UNCHANGED_NOTICE} This is a deployment fault, not a fault in your "
            "text — re-sending will not help."
        )
    if utf8_len(proposed_text) > INVESTIGATION_FILE_MAX:
        # The bound covers the whole append-only document, so name the committed share: the
        # model must tell "send less" from "out of room".
        on_disk = utf8_len(current) if current is not None else 0
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
            f"investigation.md is {utf8_len(proposed_text)} bytes, over the "  # lint-run-records: ok — a message naming the record for the model or operator, not a path
            f"{INVESTIGATION_FILE_MAX}-byte limit. {UNCHANGED_NOTICE} {remedy}"
        )
    # Fail closed on an internal validator error. (The adapter roster was read at run start,
    # so an unreadable adapters dir cannot surface here.)
    diagnose = _validator()[0]
    try:
        found = list(diagnose(proposed_text, current))
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


def _rendered_errors(found: Sequence[Diagnostic]) -> str | None:
    """The error-severity findings rendered for the model, or `None`. Shared by the write and
    close gates, which differ only in framing. Warnings are `investigation.tools`' repair window."""
    errors = [d for d in found if d.severity != "warning"]
    if not errors:
        return None
    return "\n".join(render_diagnostic(d) for d in errors)


def committed_investigation_reason(text: str) -> str | None:
    """Is `investigation.md` as it stands well-formed enough to publish? The deny reason, or
    `None`. The close publishes without going through `permission.decide_write`, so it needs
    its own check."""
    diagnose = _validator()[0]
    try:
        found = list(diagnose(text, text))
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
        "what records the disposition — the closing record commits against this document and the review gate "
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
    if name == RUN_LAYOUT.investigation.name:
        return validate_investigation(proposed_text, current)
    raise ValueError(f"no content schema for artifact {name!r}")
