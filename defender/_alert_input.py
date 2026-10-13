"""The alert's front door (#1222): admission, the tenant's alert mapping, the three facts and the
run's record — the one owner of each, so no reader re-derives what another already settled.

* `admit` — run start's check of the operator's raw alert bytes, before any run folder exists.
  Strict UTF-8, no byte-order mark, exactly one JSON object the parser can follow (what Python's `json` accepts: a duplicate member is last-wins, by ruling), no unpaired
  surrogate escape. A refusal is `AlertRefused`, a fixed sentence naming the cause and echoing
  nothing of the alert.
* `AlertMapping` / `settings_reasons` / `load_alert_mapping` — the tenant's REQUIRED
  `settings/alert-mapping.yaml` (dotted paths for `signature`, `event_time`, `summary`) and the
  tenant check's reasons for it and for the case-history mapping: one fixed sentence per fault,
  naming the file, never the parser's own words or a host path.
* `derive_facts` — the one derivation of the three facts from an admitted alert and a mapping.
* `AlertRecord` / `record_text` / `read_record` / `verified_record` — the per-run record the
  facts are written to, once, with the alert's byte digest. Every later reader takes the alert's
  identity and its facts from it; a host-side read of the alert's bytes checks them against the
  digest first (`verified_alert`).
"""
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

#: The alert mapping's name under a tenant's `settings/`, and the case-history mapping's.
ALERT_MAPPING_REL = "alert-mapping.yaml"
CASE_MAPPING_REL = "systems/case-history/mapping.yaml"

#: The three facts, in the design's words; also the mapping's only keys and the record's keys.
FACT_KEYS = ("signature", "event_time", "summary")
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
    identity (held-out check, curation key, launch check, sibling union)."""
    return hashlib.sha256(raw).hexdigest()


def read_operator_alert(path: Path) -> bytes:
    """The operator's input file, whole, or `AlertRefused` when it is over the read limit."""
    try:
        return _io.read_bytes_capped(path)
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
# The alert mapping (A5) and the one tenant check's reasons
# =============================================================================================

_ALERT_FILE = f"settings/{ALERT_MAPPING_REL}"
_CASE_FILE = CASE_MAPPING_REL


def _reasons(kind: str) -> str:
    return {
        "missing": f"{_ALERT_FILE} is missing: every tenant maps its alerts' signature, "
                   "event_time and summary there",
        "unreadable": f"{_ALERT_FILE} cannot be read: it must be a plain file this user can read",
        "encoding": f"{_ALERT_FILE} is not UTF-8 text",
        "yaml": f"{_ALERT_FILE} is not valid YAML",
        "shape": f"{_ALERT_FILE} must be a YAML mapping of fact names (signature, event_time, "
                 "summary) to dotted alert paths",
        "key": f"{_ALERT_FILE} names a key that is not one of signature, event_time, summary",
        "case_unreadable": f"{_CASE_FILE} cannot be read: it must be a plain file this user "
                           "can read",
        "case_encoding": f"{_CASE_FILE} is not UTF-8 text",
        "case_yaml": f"{_CASE_FILE} is not valid YAML",
        "case_shape": f"{_CASE_FILE} must be a YAML mapping",
        "case_source": f"{_CASE_FILE} still carries a top-level `source:` section: the "
                       "tenant's alert mapping now holds the signature, event_time and summary "
                       "paths — move them there and drop the section",
    }[kind]


def _entry_reason(fact: str) -> str:
    return (f"{_ALERT_FILE}: the entry for {fact} must be a dotted alert path (a non-empty "
            "string of non-empty segments); leave the key out to map nothing")


@dataclasses.dataclass(frozen=True)
class AlertMapping:
    """A tenant's alert mapping: for each fact it maps, the dotted path into the alert."""

    paths: Mapping[str, str]

    def path_of(self, fact: str) -> str | None:
        return self.paths.get(fact)


def _check_mapping_doc(doc: object) -> AlertMapping:
    """The parsed file, or `AlertMappingFault`."""
    if not isinstance(doc, dict):
        raise AlertMappingFault(_reasons("shape"))
    paths: dict[str, str] = {}
    for key in doc:
        if key not in FACT_KEYS:
            raise AlertMappingFault(_reasons("key"))
    for fact in FACT_KEYS:
        if fact not in doc:
            continue
        value = doc[fact]
        if (not isinstance(value, str) or not value or value != value.strip()
                or any(not segment for segment in value.split("."))):
            raise AlertMappingFault(_entry_reason(fact))
        paths[fact] = value
    return AlertMapping(paths=paths)


def parse_mapping(text: str) -> AlertMapping:
    """The alert mapping in `text`, or `AlertMappingFault` carrying a fixed reason."""
    try:
        doc: object = _yaml.safe_load(text)
    except (yaml.YAMLError, RecursionError):
        raise AlertMappingFault(_reasons("yaml")) from None
    if not isinstance(doc, dict):
        raise AlertMappingFault(_reasons("shape"))
    return _check_mapping_doc(doc)


def _read_setting(settings: _io.Bound, rel: str) -> tuple[str | None, str | None]:
    """A settings file's text, or `(None, kind)` — `kind` one of missing / unreadable /
    encoding."""
    found = settings.read(rel)
    if found.absent:
        return None, "missing"
    if found.text is None:
        return None, "encoding" if found.refused_by == _io.REFUSED_UNDECODABLE else "unreadable"
    return found.text, None


def settings_reasons(settings: _io.Bound) -> list[str]:
    """The one tenant check's reasons about the two mapping files of the `settings/` folder
    `settings` is bound to: every fault, one fixed reason each, alert mapping first. Empty when
    both stand. The case-history mapping's absence is `REQUIRED_SETTINGS`' to report, not this
    check's."""
    reasons: list[str] = []
    text, kind = _read_setting(settings, ALERT_MAPPING_REL)
    if text is None:
        reasons.append(_reasons(kind or "unreadable"))
    else:
        try:
            parse_mapping(text)
        except AlertMappingFault as fault:
            reasons.append(str(fault))
    case_text, case_kind = _read_setting(settings, CASE_MAPPING_REL)
    if case_text is not None:
        try:
            case_doc = _yaml.safe_load(case_text)
        except (yaml.YAMLError, RecursionError):
            reasons.append(_reasons("case_yaml"))
        else:
            if not isinstance(case_doc, dict):
                reasons.append(_reasons("case_shape"))
            elif "source" in case_doc:
                reasons.append(_reasons("case_source"))
    elif case_kind in ("unreadable", "encoding"):
        reasons.append(_reasons("case_unreadable" if case_kind == "unreadable"
                                else "case_encoding"))
    return reasons


def load_alert_mapping(settings: Path) -> AlertMapping:
    """The tenant's alert mapping off its `settings/` folder, read once at run start, or
    `AlertMappingFault`."""
    with _io.bind(Path(settings)) as bound:
        text, kind = _read_setting(bound, ALERT_MAPPING_REL)
    if text is None:
        raise AlertMappingFault(_reasons(kind or "unreadable"))
    return parse_mapping(text)


# =============================================================================================
# The facts (A1, A6)
# =============================================================================================

@dataclasses.dataclass(frozen=True)
class AlertFacts:
    """The three facts, each text or `None` (unmapped, absent from the alert, or not a fact)."""

    signature: str | None = None
    event_time: str | None = None
    summary: str | None = None

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


def derive_facts(document: Mapping[str, Any], mapping: AlertMapping) -> AlertFacts:
    """@owns signature @owns event_time @owns summary — the three facts of an admitted alert
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
    )


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
        summary=fact("summary")))


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
    raw = bound.read_bytes(alert_name).data
    if not _matches_record(raw, record):
        return None
    assert raw is not None
    try:
        document = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError):
        return None
    return document if isinstance(document, dict) else None


def verified_input(alert_path: Path, record_path: Path, *, run_name: str) -> tuple[bytes, str]:
    """The stored alert's bytes and the text of the record they match: both read once, the
    bytes' digest compared with the record's. Raises `AlertReplaced` (a fixed reason naming
    `run_name`, carrying no byte of either file) when the record is missing or malformed, the
    alert is unreadable, or the digest differs."""
    refusal = AlertReplaced(
        f"the alert stored for run {run_name} does not match the digest its record carries "
        "(or one of the two is missing) — the run's input was replaced or damaged, and nothing "
        "is read from it")
    text, _reason = _io.read_guarded(record_path)
    record = None if text is None else parse_alert_record(text)
    if text is None or record is None:
        raise refusal
    raw, _reason = _io.read_bytes_guarded(alert_path)
    if not _matches_record(raw, record):
        raise refusal
    assert raw is not None
    return raw, text


def verified_alert(alert_path: Path, record_path: Path, *, run_name: str) -> tuple[bytes, AlertRecord]:
    """The stored alert's bytes and the record they match (see `verified_input`)."""
    raw, text = verified_input(alert_path, record_path, run_name=run_name)
    record = parse_alert_record(text)
    assert record is not None  # verified_input just parsed it
    return raw, record
