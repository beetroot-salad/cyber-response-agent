"""The tenant's case record as text (#1359, #1366): which system records its cases, and
the rules that make it usable. Split from `case_ticket` (#1470 D-E) so the record judgement, which the API loads, reads
the rules without the run-side comment writer."""
from __future__ import annotations

from typing import TYPE_CHECKING

from defender._model import model

if TYPE_CHECKING:
    from defender.tenancy.models import CaseRecord as StoredCaseRecord

#: The tenant's case-record file inside its `settings/` folder (#1359): which system records its
#: cases. Optional: a tenant with no case system has none.
CASE_RECORD_REL = "case-record.yaml"

#: How a case-record fault names the record when its caller names it no other way: the retired file.
CASE_RECORD_FILE = f"settings/{CASE_RECORD_REL}"

class CaseTicketError(Exception):
    """A case record (or a comment rendered from it) that cannot be used."""


@model(frozen=True)
class CaseRecordSettings:
    """One tenant's case record, parsed ONCE when the run's tenant is resolved and read-only from then on (#1359): the
    system that records cases."""

    system: str


def parse_case_record(text: str, *, named: str = CASE_RECORD_FILE) -> CaseRecordSettings:
    """The case record's text as settings, or `CaseTicketError` naming it as `named` (the record, a file, a folder's
    entry): a YAML mapping with a non-empty text `system` and nothing about a comment (#1471 W7: the comment's wording is
    fixed, so a record that still carries `comment:` is refused)."""

    def _fault(text: str) -> CaseTicketError:
        return CaseTicketError(f"{named} {text}")

    import yaml

    from defender._yaml import safe_load

    try:
        data = safe_load(text)
    except (yaml.YAMLError, RecursionError):
        raise _fault("is not valid YAML") from None
    if not isinstance(data, dict):
        raise _fault("must be a YAML mapping with a `system`")
    system = data.get("system")
    if not isinstance(system, str) or not system.strip():
        raise _fault("must name the case system in `system` (a non-empty string)")
    if "comment" in data:
        raise _fault("carries `comment:`, which no longer exists: the comment's wording is fixed (#1471); remove the key")
    return CaseRecordSettings(system=system.strip())


def case_record_text(record: StoredCaseRecord) -> str:
    """A stored case record (#1366) as the case-record text `parse_case_record` reads."""
    from defender._yaml import safe_dump

    return safe_dump({"system": record.system_id}, sort_keys=False)


__all__ = ["CASE_RECORD_FILE", "CASE_RECORD_REL", "CaseRecordSettings", "CaseTicketError",
           "case_record_text", "parse_case_record"]
