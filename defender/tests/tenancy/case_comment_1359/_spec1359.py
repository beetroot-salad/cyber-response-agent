"""Shared names and planting for the #1359 case-comment contract (no test functions).

Every name the design (r3 + amendment r4) fixes is one constant here, so the suites cannot
disagree."""
from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from defender.tests.support.storage._alert_plant import plant_alert as plant_alert_with_record
from defender.tests.support.tenancy import _tenants1106 as T1106
from defender.tests.tenancy.tenant_1107_settings import _spec1107 as S

# ======================================================================================
# Names the design fixes.
# ======================================================================================

#: The fourth alert fact (design "Data").
CASE_KEY = "case_key"
#: The receipt's words and shape (O5, unchanged).
RECEIPT_KEYS = {"key", "status", "url", "ok", "reason"}
COMMENTED, ESCALATED, ERROR = "commented", "escalated", "error"
#: A comment whose outcome the read-back could not settle (#1374 O4).
UNKNOWN = "unknown"
#: The retired system and its settings prefix (O2 census).
RETIRED_SYSTEM = "case-history"
RETIRED_PREFIX = "CASE_HISTORY"
RETIRED_MAPPING_REL = f"{T1106.RETIRED_CASE_FOLDER}/mapping.yaml"

# ======================================================================================
# Names fixed by amendment r4.
# ======================================================================================

#: The adapter's literally named comment function (design: "one literally named function").
COMMENT_ACTION = "add_case_comment"
#: The optional read beside it (#1374): the case's comments, for the host's read-back.
READBACK_ACTION = "read_case_comments"
#: The tenant case-record settings file under `settings/` (r4 Data).
CASE_RECORD_REL = "case-record.yaml"
#: The ready-made adapters' system names (module `<system>_adapter.py`, prefix `<SYSTEM>_`).
#: The playground system that records cases.
CASE_SYSTEM_TICKET = "ticket"
JIRA_SYSTEM = "jira"
SERVICENOW_SYSTEM = "servicenow"
#: Receipt reason substrings (r4 "Receipt reasons").
REASON_NO_KEY = "names no ticket"
REASON_NOT_FOUND = "not found"
#: The record leg's entry point: run.py's module, name and keywords (r4 keeps the seam)
#: (`run, tenant=, defender_dir=, env=, truncated_by=, closed_before_cut=, request_token=,
#: proxy_url=`).
RECORD_LEG = ("investigation.ticket_writer", "record_case_ticket")

MARKER = "c1359"
#: The ticket key the planted alert names, in the fixture ticket store's own key grammar
#: (`_tenants1106.config_texts`: `<MARKER upper>-[0-9]+`).
TICKET_KEY = f"{MARKER.upper()}-4471"
#: The comment body template the case-record file carries.
BODY_TEMPLATE = T1106.COMMENT_BODY

#: The alert mapping run start reads, with the fourth fact on the alert's own id (P3).
ALERT_MAPPING = {"signature": "rule.id", "event_time": "timestamp",
                 "summary": "rule.description", CASE_KEY: "alert_id"}


def record_leg() -> Any:
    module, name = RECORD_LEG
    return getattr(S.mod(module), name)


def case_record_text(system: str, *, body: str = BODY_TEMPLATE) -> str:
    """The tenant's case-record settings: which system records cases, and the comment body."""
    return T1106.case_record_text(system, body=body)


def alert_mapping_text(mapping: Mapping[str, str] = ALERT_MAPPING) -> str:
    return "".join(f"{k}: {v}\n" for k, v in mapping.items())


def alert_doc(*, key: str | None = TICKET_KEY) -> dict[str, Any]:
    """An alert whose own id (`alert_id`, set by the alerting system) is the ticket key; `None`
    leaves the field out."""
    doc: dict[str, Any] = {"rule": {"id": "r-1359", "description": "spec 1359"},
                           "timestamp": "2026-11-02T00:00:00Z"}
    if key is not None:
        doc["alert_id"] = key
    return doc


def plant_alert(where: Path, *, key: str | None = TICKET_KEY) -> Path:
    where = Path(where)
    where.mkdir(parents=True, exist_ok=True)
    path = where / "alert.json"
    path.write_text(json.dumps(alert_doc(key=key)), encoding="utf-8")
    return path


def plant_case_tenant(root: Path, *, case_system: str | None = "ticket",
                      configs: dict[str, str] | None = None, **kw: Any) -> Path:
    """The playground tenant as the machinery plants it after #1359: no `case-history` folder, an
    alert mapping carrying `case_key`, and (unless `case_system` is None: a tenant with no case
    file) a case-record file naming `case_system`. Returns the knowledge folder."""
    return S.plant(root, marker=MARKER, configs=configs, case_system=case_system, **kw)


class CaseRunRecorder(S.RunRecorder):
    """`S.RunRecorder` whose stand-in setup derives the run's record through the real
    `derive_facts` with `ALERT_MAPPING` (`case_key` included), not the three-fact mapping."""

    def materialize(self, alert: Path, **kw: Any) -> Any:
        self.order.append("materialize")
        run_dir = self.run_dir_at
        run_dir.mkdir(parents=True, exist_ok=True)
        plant_alert_with_record(run_dir, Path(alert).read_bytes(), mapping=ALERT_MAPPING)
        S.seed_session_store(run_dir)
        from defender.tests.support.shared.contracts._spec1077 import fixture_run

        return fixture_run(run_dir)


def comment_calls(shim: S.DockerShim) -> list[list[str]]:
    """The docker argvs whose curl POSTs to a `/comments` URL."""
    return [c["argv"] for c in shim.calls()
            if "POST" in c["argv"] and (S.curl_url(c["argv"]) or "").endswith("/comments")]


def plant_record(run_dir: Path, *, key: str | None = TICKET_KEY) -> None:
    """A hand-built run folder's alert and record, derived through `ALERT_MAPPING`."""
    plant_alert_with_record(run_dir, alert_doc(key=key), mapping=ALERT_MAPPING)


__all__ = ["T1106"]
