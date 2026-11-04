"""The alert's front door (#1222): admission, the tenant's alert mapping, the three facts and the
run's record — the one owner of each, so no reader re-derives what another already settled."""
from __future__ import annotations

import dataclasses
import hashlib
import json
import re
from collections.abc import Mapping
from pathlib import Path, PurePath
from typing import Any

import yaml

from defender import _io, _yaml
from defender._text import postgres_can_hold

#: The four facts, in the design's words; also the record's keys.
FACT_KEYS = ("signature", "event_time", "summary", "case_key")
#: What a tenant also maps for the alert list (#1345): the alert's title and description.
DISPLAY_KEYS = ("title", "description")
#: The alert mapping's only entries (#1345): the four facts and the two display fields. The one owner of the names;
#: the table's columns and the API's wire model are necessary copies, pinned by tests.
MAPPING_KEYS = FACT_KEYS + DISPLAY_KEYS
#: What a case key IS (#1359 P3): one URL path segment of at most 128 printable ASCII characters,
#: with no `/`, `\\`, `;` (the credential proxy refuses any `;` in a decoded path) or whitespace, and
#: not made only of dots (curl collapses `.` and `..` segments, so the request would go elsewhere).
CASE_KEY_RE = re.compile(r"[\x21-\x7e]{1,128}")
_CASE_KEY_FORBIDDEN = frozenset("/\\;")
#: The record's digest key.
DIGEST_KEY = "digest"

#: What a signature IS (A6): ASCII, key-shaped, no leading dash, at most 128 characters. Matched
#: with `fullmatch`.
SIGNATURE_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/@+=-]{0,127}")
_DIGEST_RE = re.compile(r"[0-9a-f]{64}")
_SURROGATE_RE = re.compile("[\ud800-\udfff]")
_BOM = b"\xef\xbb\xbf"


class AlertRefused(Exception):  # noqa: N818 — named for what it reports
    """The operator's alert is not admitted; `str()` is the fixed reason."""


class AlertMappingFault(Exception):  # noqa: N818 — named for what it reports
    """The alert mapping cannot be used; `str()` is the fixed reason naming the file."""


class AlertReplaced(Exception):  # noqa: N818 — named for what it reports
    """A run's stored alert no longer matches the digest its record carries; `str()` names the
    run and carries no byte of either file."""


# =============================================================================================
# Admission (A8)
# =============================================================================================

REFUSE_ENCODING = ("the alert is not admitted: it is not UTF-8 text (a byte-order mark, UTF-16 "
                   "or bytes that are not UTF-8)")
REFUSE_NOT_ONE_OBJECT = "the alert is not admitted: it is not exactly one JSON object"
REFUSE_NESTING = "the alert is not admitted: it nests deeper than the parser can follow"
REFUSE_SURROGATE = "the alert is not admitted: it holds an unpaired surrogate escape"
REFUSE_SIZE = "the alert is not admitted: it is larger than the size the harness reads whole"


@dataclasses.dataclass(frozen=True)
class Admitted:
    """An alert that passed `admit`: the parsed object and the sha256 hex of its bytes."""

    document: dict[str, Any]
    digest: str


def digest_of(raw: bytes) -> str:
    """@owns digest — the lowercase hex sha256 of an alert's admitted bytes: the alert's only
    identity (evaluation exclusion, curation key, launch check, sibling union)."""
    return hashlib.sha256(raw).hexdigest()


#: The one byte cap on an alert (#1342 M5): admission refuses more (`REFUSE_SIZE`), and the
#: operator's file read stops there. The store's insert takes it through `admit`.
ALERT_BYTE_CAP = _io.READ_LIMIT


def read_operator_alert(path: Path) -> bytes:
    """The operator's input file, whole, or `AlertRefused` when it is over the read limit."""
    try:
        return _io.read_bytes_capped(path, limit=ALERT_BYTE_CAP)
    except _io.TEXT_READ_ERRORS as error:
        if getattr(error, "errno", None) == 27:  # EFBIG: the read step's own size refusal
            raise AlertRefused(REFUSE_SIZE) from None
        raise


def _has_surrogate(document: Any) -> bool:
    """Whether any key or string value of `document` holds a surrogate code point. Iterative:
    the parser followed the nesting, but a walk must not depend on the recursion limit."""
    stack: list[Any] = [document]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            if _SURROGATE_RE.search(item):
                return True
        elif isinstance(item, dict):
            for key, value in item.items():
                if _SURROGATE_RE.search(key):
                    return True
                stack.append(value)
        elif isinstance(item, list):
            stack.extend(item)
    return False


def admit(raw: bytes) -> Admitted:
    """The admitted alert, or `AlertRefused`. @owns alert admission"""
    if len(raw) > ALERT_BYTE_CAP:
        raise AlertRefused(REFUSE_SIZE)
    if raw.startswith(_BOM):
        raise AlertRefused(REFUSE_ENCODING)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise AlertRefused(REFUSE_ENCODING) from None
    try:
        document = json.loads(text)
    except RecursionError:
        raise AlertRefused(REFUSE_NESTING) from None
    except ValueError:
        raise AlertRefused(REFUSE_NOT_ONE_OBJECT) from None
    if not isinstance(document, dict):
        raise AlertRefused(REFUSE_NOT_ONE_OBJECT)
    if _has_surrogate(document):
        raise AlertRefused(REFUSE_SURROGATE)
    return Admitted(document=document, digest=digest_of(raw))


# =============================================================================================
# The alert mapping (A5; stored in the database since #1345)
# =============================================================================================

#: What a run or an investigation is refused with while its tenant has saved no mapping (#1345 O4): the one
#: wording, used by the store and by run start alike. It names the missing mapping, the command-line verb and the API route.
ALERT_MAPPING_MISSING = (
    "the tenant has no alert mapping: save one with `tenant.py set-alert-mapping <tenant-id> <file>` "
    "or `PUT /tenants/<tenant-id>/alert-mapping`")


def _reasons(kind: str) -> str:
    return {
        "yaml": "the alert mapping is not valid YAML",
        "shape": "the alert mapping must be a YAML mapping of entry names (" + ", ".join(MAPPING_KEYS)
                 + ") to dotted alert paths",
    }[kind]


def _unknown_entry_reason(entry: object) -> str:
    shown = repr(entry)[:60]
    return f"the alert mapping names {shown}, which is not one of " + ", ".join(MAPPING_KEYS)


def _entry_reason(entry: str) -> str:
    return (f"the alert mapping's entry for {entry} must be a dotted alert path (a non-empty "
            "string of non-empty segments with no surrounding whitespace); leave it unmapped to map nothing")


@dataclasses.dataclass(frozen=True)
class AlertMapping:
    """A tenant's alert mapping: for each entry it maps, the dotted path into the alert."""

    paths: Mapping[str, str]

    def path_of(self, entry: str) -> str | None:
        return self.paths.get(entry)


def check_mapping(doc: object) -> AlertMapping:
    """@owns alert mapping rules — the mapping in `doc` (entry name -> dotted path, or `None` for an unmapped
    entry; an entry left out is unmapped too), or `AlertMappingFault` naming the entry. The one validator: the
    file parser, the API's wire model and the store's re-check all go through it."""
    if not isinstance(doc, dict):
        raise AlertMappingFault(_reasons("shape"))
    for key in doc:
        if key not in MAPPING_KEYS:
            raise AlertMappingFault(_unknown_entry_reason(key))
    paths: dict[str, str] = {}
    for entry in MAPPING_KEYS:
        value = doc.get(entry)
        if value is None:
            continue
        if (not isinstance(value, str) or not value or value != value.strip()
                or any(not segment for segment in value.split("."))):
            raise AlertMappingFault(_entry_reason(entry))
        paths[entry] = value
    return AlertMapping(paths=paths)


def parse_mapping(text: str) -> AlertMapping:
    """The alert mapping in `text` (the file format of `tenant.py set-alert-mapping`: YAML, an entry left out or
    `null` is unmapped), or `AlertMappingFault` carrying a fixed reason."""
    try:
        doc: object = _yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError):
        raise AlertMappingFault(_reasons("yaml")) from None
    return check_mapping(doc)


# =============================================================================================
# The facts (A1, A6)
# =============================================================================================

@dataclasses.dataclass(frozen=True)
class AlertFacts:
    """The four facts, each text or `None` (unmapped, absent from the alert, or not a fact)."""

    signature: str | None = None
    event_time: str | None = None
    summary: str | None = None
    #: The ticket the alert names (#1359): from a field the alerting system sets, read by the host.
    case_key: str | None = None

    def as_json(self) -> dict[str, str]:
        return {k: v for k, v in dataclasses.asdict(self).items() if v is not None}


def _walk(document: Mapping[str, Any], dotted: str) -> Any:
    """The value at `dotted` (a walk over JSON objects only), or `None`."""
    current: Any = document
    for key in dotted.split("."):
        if not isinstance(current, dict) or key not in current:
            return None
        current = current[key]
    return current


def _scalar_text(value: Any) -> str | None:
    """A string as it is, an integer as its decimal text; anything else (float, bool, null,
    list, object) is no fact. Empty text is no fact."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value)
    if isinstance(value, str):
        return value or None
    return None


def signature_of(value: Any) -> str | None:
    """A mapped value as a signature, or `None` when it is not a key (A6)."""
    text = _scalar_text(value)
    if text is None or SIGNATURE_RE.fullmatch(text) is None:
        return None
    return text


def case_key_of(value: Any) -> str | None:
    """A mapped value as a ticket key, or `None` when it is not one URL path segment (#1359 P3):
    the same text rules as any fact (an integer is its decimal text), then the segment shape."""
    text = _scalar_text(value)
    if (text is None or CASE_KEY_RE.fullmatch(text) is None
            or _CASE_KEY_FORBIDDEN & set(text) or not text.strip(".")):
        return None
    return text


def derive_facts(document: Mapping[str, Any], mapping: AlertMapping) -> AlertFacts:
    """@owns signature @owns event_time @owns summary @owns case_key — the four facts of an admitted alert
    through the tenant's mapping, derived once at run start and recorded; every later reader
    takes them from the record. A fact whose key is unmapped, whose path is absent, or whose
    value is not text (or, for the signature, not key-shaped) is `None`: no vendor default
    stands in."""
    def at(fact: str) -> Any:
        path = mapping.path_of(fact)
        return None if path is None else _walk(document, path)

    return AlertFacts(
        signature=signature_of(at("signature")),
        event_time=_scalar_text(at("event_time")),
        summary=_scalar_text(at("summary")),
        case_key=case_key_of(at("case_key")),
    )


def derive_display(document: Mapping[str, Any], mapping: AlertMapping) -> tuple[str | None, str | None]:
    """@owns title @owns description — the alert's `(title, description)` through the tenant's mapping (#1345 M3): the
    fact text rule over the same path walk, and `None` for what PostgreSQL text cannot hold, so a store never
    writes a value its column refuses."""
    def at(entry: str) -> str | None:
        path = mapping.path_of(entry)
        text = None if path is None else _scalar_text(_walk(document, path))
        return text if text is not None and postgres_can_hold(text) else None

    return at("title"), at("description")


def derive_display_of_stored(raw: bytes, mapping: AlertMapping | None) -> tuple[str | None, str | None]:
    """`derive_display` over an alert's stored bytes, for a recompute (#1345 M3): the bytes are parsed as JSON only
    and admission is not re-run (its rules may have tightened since the alert was stored). Bytes that do not parse
    as one JSON object, or no mapping at all, give `(None, None)`."""
    if mapping is None:
        return None, None
    try:
        document = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError):
        return None, None
    return derive_display(document, mapping) if isinstance(document, dict) else (None, None)


# =============================================================================================
# The record
# =============================================================================================

@dataclasses.dataclass(frozen=True)
class AlertRecord:
    """A run's record: the alert's digest and its facts."""

    digest: str
    facts: AlertFacts

    @property
    def signature(self) -> str | None:
        return self.facts.signature


def record_text(digest: str, facts: AlertFacts) -> str:
    """@owns record — the record's bytes: a JSON object of `digest` and each fact that exists."""
    return json.dumps({DIGEST_KEY: digest, **facts.as_json()}, indent=1, ensure_ascii=False) + "\n"


#: The record's file name inside the input directory, beside the alert (the layout's
#: `ALERT_RECORD` is this value).
RECORD_FILE = "record.json"


def record_beside(alert_path: Path) -> Path:
    """Where the record sits for an alert stored at `alert_path`: the same directory."""
    return alert_path.with_name(RECORD_FILE)


def parse_alert_record(text: str) -> AlertRecord | None:
    """The record in `text`, or `None` when it is not one: not a JSON object, no hex digest. A
    fact that is not text, or a signature that is not key-shaped, reads as absent — the record
    is the run's certificate, never a place a malformed value reaches a sink."""
    try:
        doc = json.loads(text)
    except (ValueError, RecursionError):
        return None
    if not isinstance(doc, dict):
        return None
    digest = doc.get(DIGEST_KEY)
    if not isinstance(digest, str) or _DIGEST_RE.fullmatch(digest) is None:
        return None
    def fact(name: str) -> str | None:
        value = doc.get(name)
        return value if isinstance(value, str) and value else None

    return AlertRecord(digest=digest, facts=AlertFacts(
        signature=signature_of(fact("signature")), event_time=fact("event_time"),
        summary=fact("summary"), case_key=case_key_of(fact("case_key"))))


def read_record(record_path: Path) -> AlertRecord | None:
    """The record at `record_path` (read no-follow, bounded), or `None` when there is none or it
    is not one."""
    text, _reason = _io.read_guarded(record_path)
    return None if text is None else parse_alert_record(text)


def _matches_record(raw: bytes | None, record: AlertRecord | None) -> bool:
    """Integrity is always measured on original bytes, before decoding or parsing."""
    return raw is not None and record is not None and digest_of(raw) == record.digest


def verified_document(bound: _io.Bound, alert_name: str | PurePath,
                      record_name: str | PurePath) -> dict[str, Any] | None:
    """Load an archived alert once, verify its original bytes, then decode and parse them.

    Missing, unreadable, damaged or malformed input has no displayable document.
    """
    text = bound.read(record_name).text
    record = None if text is None else parse_alert_record(text)
    if record is None:
        return None
    raw = bound.read_bytes(alert_name).data  # lint-whole-read: ok — Bound enforces READ_LIMIT and no-follow guards
    if not _matches_record(raw, record):
        return None
    assert raw is not None
    try:
        document = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError):
        return None
    return document if isinstance(document, dict) else None


def verified_input(alert_path: Path, record_path: Path, *, run_name: str | None) -> tuple[bytes, str]:
    """The stored alert's bytes and the text of the record they match: both read once, the
    bytes' digest compared with the record's. Raises `AlertReplaced` (a fixed reason naming
    `run_name` — or "this run" when it is `None`, for a reason the model reads (#1255 C5) —
    carrying no byte of either file) when the record is missing or malformed, the
    alert is unreadable, or the digest differs."""
    text, _reason = _io.read_guarded(record_path)
    raw, _reason = _io.read_bytes_guarded(alert_path)
    return verify_input_bytes(raw, text, run_name=run_name)


def verify_input_bytes(
    raw: bytes | None, text: str | None, *, run_name: str | None,
) -> tuple[bytes, str]:
    """Verify already-read original bytes against the recorded digest."""
    which = "this run" if run_name is None else f"run {run_name}"
    refusal = AlertReplaced(
        f"the alert stored for {which} does not match the digest its record carries "
        "(or one of the two is missing) — the run's input was replaced or damaged, and nothing "
        "is read from it")
    record = None if text is None else parse_alert_record(text)
    if text is None or record is None:
        raise refusal
    if not _matches_record(raw, record):
        raise refusal
    assert raw is not None
    return raw, text


def verified_alert(
    alert_path: Path, record_path: Path, *, run_name: str | None,
) -> tuple[bytes, AlertRecord]:
    """The stored alert's bytes and the record they match (see `verified_input`)."""
    raw, text = verified_input(alert_path, record_path, run_name=run_name)
    record = parse_alert_record(text)
    assert record is not None  # verified_input just parsed it
    return raw, record
