"""The read side of the `report.md` contract — one typed accessor for every consumer.

`_artifact_schema.py` enforces the report's shape on write; this is where a completed run's
report becomes a typed value, so no consumer re-implements disposition extraction or coerces a
malformed verdict.

Gates that cannot act without a headline call `require_report` and re-wrap
`ReportUnreadable` in their own domain error; views and metrics that must keep going call
`read_report` and use `disposition` (`None`) or `disposition_or_unknown` (`"?"`, a display
choice, not a parse outcome).

Every `reason` starts with the artifact name, so callers can prefix it with the case id.
"""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from defender.run_repository import RUN_LAYOUT
from defender._frontmatter import FrontmatterError, parse_frontmatter
from defender._io import read_text_soft
from defender._model import model
# From `_vocab`, not `_artifact_schema`: invlang surfaces share the placeholder and cannot
# import this module without a cycle.
from defender._vocab import DISPOSITION_ENUM, UNKNOWN_DISPOSITION, normalized_disposition


class ReportUnreadable(ValueError):
    """A completed `report.md` yielded no disposition; the message is the reason."""


@model(frozen=True)
class Report:
    """A report that has a headline; `disposition` is already a validated `DISPOSITION_ENUM`
    member."""

    disposition: str
    frontmatter: Mapping[str, Any]
    body: str


@model(frozen=True)
class ReportRead:
    """One read of a `report.md`, whether or not it produced a headline. Unparseable
    frontmatter still returns the bytes as `body` so views can show what the model wrote.
    """

    disposition: str | None
    reason: str | None
    #: Keys `Any`, not `str`: YAML builds `on:` as `True`, a bare date as a `date`, `1:` as an
    #: `int`, and the write gate accepts those. `@model` validates the annotation, so `str`
    #: would make this never-raising reader raise.
    frontmatter: Mapping[Any, Any]
    body: str
    text: str
    #: Nothing at the name at all. Only the world-archive reader (`family.read_archived_report`)
    #: sets it; `read_report` reports "not found" through `reason`.
    absent: bool = False

    @property
    def report(self) -> Report | None:
        """The typed report, or `None` when there is no usable headline."""
        if self.disposition is None:
            return None
        return Report(self.disposition, self.frontmatter, self.body)

    @property
    def disposition_or_unknown(self) -> str:
        """The headline as a view shows it: the disposition, or the unknown placeholder."""
        if self.disposition is None:
            return UNKNOWN_DISPOSITION
        return self.disposition


def _no_headline(reason: str, *, text: str = "", body: str = "") -> ReportRead:
    return ReportRead(disposition=None, reason=reason, frontmatter={}, body=body, text=text)


def read_report(path: Path) -> ReportRead:
    """Read and interpret a completed run's `report.md`. Never raises: a missing, unreadable,
    undecodable or malformed report comes back as a `reason` plus whatever was recoverable.
    """
    if not path.is_file():
        return _no_headline(f"{RUN_LAYOUT.report.name} not found: {path}")
    text, error = read_text_soft(path)
    if text is None:
        return _no_headline(f"{RUN_LAYOUT.report.name} is unreadable: {error}")
    return parse_report_text(text)


def parse_report_text(text: str) -> ReportRead:
    """The interpretation half of `read_report`, for callers that open the file their own way."""
    try:
        frontmatter, body = parse_frontmatter(text)
    except FrontmatterError as e:
        # No frontmatter means no headline, but the bytes are still the report a view renders.
        return _no_headline(f"{RUN_LAYOUT.report.name} {e}", text=text, body=text)
    raw = frontmatter.get("disposition")
    disposition = normalized_disposition(raw)
    if disposition is None:
        return ReportRead(
            disposition=None,
            reason=f"{RUN_LAYOUT.report.name} disposition={raw!r} not in "
                   f"{sorted(DISPOSITION_ENUM)}",
            frontmatter=frontmatter,
            body=body,
            text=text,
        )
    return ReportRead(
        disposition=disposition, reason=None, frontmatter=frontmatter, body=body, text=text
    )


def require_report(path: Path) -> Report:
    """`read_report` for a caller that cannot proceed without a headline; raises
    `ReportUnreadable`."""
    read = read_report(path)
    report = read.report
    if report is None:
        raise ReportUnreadable(read.reason)
    return report
