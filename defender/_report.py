"""The READ side of the `report.md` contract — one typed accessor for six consumers (#785).

`_artifact_schema.py` owns what a well-formed report IS and enforces it on WRITE, through the
permission gate. This module is its mirror: the single place a COMPLETED run's report becomes
a typed value. Before it, six consumers each re-implemented disposition extraction on top of
the shared frontmatter parse and disagreed on the same bytes — three different reactions to a
missing or invalid disposition, and only ONE of the six still applied #722's zero-width strip,
on data an attacker influences by construction.

INTERPRETATION is centralized here; REACTION deliberately is not. They are different
questions, and the consumers split cleanly into two kinds:

  * gates that must REFUSE — the learning loop's run cycle and the ticket bridge cannot act on
    a run whose headline they cannot read. They call `require_report` and re-wrap
    `ReportUnreadable` in their own domain error, so a drain can still dead-letter the case.
  * views and metrics that must DEGRADE — the transcript pages, the lesson tracer and the
    held-out eval must render or score the rest of the corpus when one report is broken. They
    call `read_report` and take `disposition` (`None`) or `disposition_or_unknown` (`"?"`).

`"?"` is therefore a RENDERING choice, not a third parse outcome — a display property rather
than a return convention some future reader has to re-derive.

Every `reason` starts with the artifact name, so a caller can prefix it with the case it was
reading (`f"{case_id}/{read.reason}"`) and get a sentence that names the file.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from defender._artifact_schema import DISPOSITION_ENUM, REPORT_NAME, normalized_disposition
from defender._frontmatter import FrontmatterError, parse_frontmatter
from defender._io import read_text_soft

# What a view shows where a disposition should be. One definition, because the transcript
# pages and the lesson tracer both render it and a reader comparing two screens must not have
# to wonder whether `?` and `?` mean the same thing.
UNKNOWN_DISPOSITION = "?"


class ReportUnreadable(ValueError):
    """A completed `report.md` yielded no disposition. The message IS the reason — callers
    that must refuse re-wrap it in their own domain error rather than restating it."""


@dataclass(frozen=True)
class Report:
    """A report that HAS a headline. `disposition` is a `DISPOSITION_ENUM` member, already
    stripped of the zero-width characters #722 is about — the type carries that guarantee, so
    a consumer holding one never re-validates."""

    disposition: str
    frontmatter: Mapping[str, Any]
    body: str


@dataclass(frozen=True)
class ReportRead:
    """One read of a `report.md`, whether or not it produced a headline.

    Partial results survive on purpose: a report whose frontmatter will not parse still hands
    back its bytes as `body`, because the transcript's job is to show an operator what the
    model actually wrote — refusing to render is the worse failure there.
    """

    disposition: str | None
    reason: str | None
    frontmatter: Mapping[str, Any]
    body: str
    text: str

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
    undecodable or malformed report comes back as a `reason` and whatever was recoverable.

    The `read_text_soft` lane matters — `report.md` is model-authored and read once per case in
    whole-corpus walks, so one undecodable byte in one historical report must cost that row and
    not the walk.
    """
    if not path.is_file():
        return _no_headline(f"{REPORT_NAME} not found: {path}")
    text, error = read_text_soft(path)
    if text is None:
        return _no_headline(f"{REPORT_NAME} is unreadable: {error}")
    try:
        frontmatter, body = parse_frontmatter(text)
    except FrontmatterError as e:
        # No frontmatter means no headline, but the bytes are still the report a view renders.
        return _no_headline(f"{REPORT_NAME} {e}", text=text, body=text)
    raw = frontmatter.get("disposition")
    disposition = normalized_disposition(raw)
    if disposition is None:
        return ReportRead(
            disposition=None,
            reason=f"{REPORT_NAME} disposition={raw!r} not in {sorted(DISPOSITION_ENUM)}",
            frontmatter=frontmatter,
            body=body,
            text=text,
        )
    return ReportRead(
        disposition=disposition, reason=None, frontmatter=frontmatter, body=body, text=text
    )


def require_report(path: Path) -> Report:
    """The same read for a caller that cannot proceed without a headline. Raises
    `ReportUnreadable` carrying the one reason text every consumer now reports."""
    read = read_report(path)
    report = read.report
    if report is None:
        raise ReportUnreadable(read.reason)
    return report
