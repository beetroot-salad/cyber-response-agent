"""The tenant's case record as text (#1359, #1366): which system records its cases and the comment body template, and
the rules that make it usable. Split from `case_ticket` (#1470 D-E) so the record judgement, which the API loads, reads
the rules without the run-side comment writer."""
from __future__ import annotations

from typing import TYPE_CHECKING

from defender._model import model

if TYPE_CHECKING:
    from defender.tenancy.models import CaseRecord as StoredCaseRecord

#: The tenant's case-record file inside its `settings/` folder (#1359): which system records its
#: cases and the comment body template. Optional: a tenant with no case system has none.
CASE_RECORD_REL = "case-record.yaml"

#: How a case-record fault names the record when its caller names it no other way: the retired file.
CASE_RECORD_FILE = f"settings/{CASE_RECORD_REL}"

#: The keys a comment body template may render (`render_context`).
RENDER_KEYS = ("case_id", "signature", "summary", "disposition", "cause", "narrative", "event_time")


class CaseTicketError(Exception):
    """A case record (or a comment rendered from it) that cannot be used."""


@model(frozen=True)
class CaseRecordSettings:
    """One tenant's case record, parsed ONCE when the run's tenant is resolved and read-only from then on (#1359): the
    system that records cases, and the comment body template."""

    system: str
    body: str


def format_template(template: str, ctx: dict[str, str], where: str) -> str:
    """`str.format_map`, with every bad-template fault folded into `CaseTicketError` so a
    broken tenant template refuses with a receipt like any other case-settings fault."""
    try:
        return template.format_map(ctx)
    except KeyError as e:
        raise CaseTicketError(
            f"the case record's `{where}` names a render key the context does not "
            f"carry: {e}"
        ) from e
    except (ValueError, IndexError, AttributeError, TypeError) as e:
        raise CaseTicketError(
            f"the case record's `{where}` is not a valid template: {e}"
        ) from e


def render_context(**kw: str) -> dict[str, str]:
    """Every render key (`RENDER_KEYS`) empty, then `kw`."""
    base = dict.fromkeys(RENDER_KEYS, "")
    base.update(kw)
    return base


def parse_case_record(text: str, *, named: str = CASE_RECORD_FILE) -> CaseRecordSettings:
    """The case record's text as settings, or `CaseTicketError` naming it as `named` (the record, a file, a folder's
    entry): a YAML mapping with a non-empty text `system` and a `comment` mapping whose `body` is non-empty text (no
    product default: the body is the tenant's)."""

    def _fault(text: str) -> CaseTicketError:
        return CaseTicketError(f"{named} {text}")

    import yaml

    from defender._yaml import safe_load

    try:
        data = safe_load(text)
    except (yaml.YAMLError, RecursionError):
        raise _fault("is not valid YAML") from None
    if not isinstance(data, dict):
        raise _fault("must be a YAML mapping with a `system` and a `comment.body`")
    system = data.get("system")
    if not isinstance(system, str) or not system.strip():
        raise _fault("must name the case system in `system` (a non-empty string)")
    comment = data.get("comment")
    body = comment.get("body") if isinstance(comment, dict) else None
    if not isinstance(body, str) or not body.strip():
        raise _fault("must carry a `comment.body` template (a non-empty string)")
    try:
        # A template that cannot render is the record's fault whichever branch is posted (an
        # escalation does not use it, but a tenant who wrote `{0}` is told so all the same).
        format_template(body, render_context(), "comment.body")
    except CaseTicketError as bad:
        raise _fault(f"is unusable: {bad}") from None
    return CaseRecordSettings(system=system.strip(), body=body)


def case_record_text(record: StoredCaseRecord) -> str:
    """A stored case record (#1366) as the case-record text `parse_case_record` reads."""
    from defender._yaml import safe_dump

    return safe_dump({"system": record.system_id, "comment": {"body": record.comment_body}}, sort_keys=False)


__all__ = ["CASE_RECORD_FILE", "CASE_RECORD_REL", "RENDER_KEYS", "CaseRecordSettings", "CaseTicketError",
           "case_record_text", "format_template", "parse_case_record", "render_context"]
