"""The internal record ids (#1382): every id the system mints is canonical lowercase UUID text, one
str subclass per family so a function that declares `AlertId` tells mypy a tenant id, or an
unchecked `str`, does not belong there. The grammar is `_run_id`'s; this module owns the classes.
`TenantId` (in `_tenant_id`) is one of them, with its own refusal."""
from __future__ import annotations

from typing import Any, ClassVar, Self

from pydantic_core import core_schema

from defender._shown import escaped
from defender.records._run_id import _UUID_TEXT, mint_uuid, uuid_id_fault

#: The grammar as a regular expression anchored at both ends: what a pydantic field or an API
#: parameter typed with an id class checks first, so a malformed value is pydantic's own
#: validation error (an API answers 422), never the family's refusal (which is not a `ValueError`
#: and would escape validation as a 500).
UUID_PATTERN = f"^{_UUID_TEXT.pattern}$"


class IdRefused(Exception):
    """A value refused as a record id; the message names the value, escaped where it is built (a
    value read off disk can carry a control character). An `Exception`, not a `ValueError`, for
    the reason `TenantRefused` gives; `TenantRefused` is one."""

    def __init__(self, message: object = "") -> None:
        super().__init__(escaped(message))


class UuidId(str):
    """A record id: constructing one is the check. `Family(raw)` returns the id or raises the
    family's refusal naming `raw`; an id of the same family handed back in is returned as-is."""

    __slots__ = ()
    domain: ClassVar[str] = "record"
    refused: ClassVar[type[Exception]] = IdRefused

    def __new__(cls, raw: object) -> Self:
        if isinstance(raw, cls):
            return raw
        fault = uuid_id_fault(raw, cls.domain)
        if fault is not None:
            raise cls.refused(fault)
        assert isinstance(raw, str)
        return super().__new__(cls, raw)

    @classmethod
    def stored(cls, text: str) -> Self:
        """An id read back from a store that holds only canonical UUID text (a PostgreSQL `uuid`
        column): not checked again. Parsing belongs where outside text becomes an id."""
        return super().__new__(cls, text)

    @classmethod
    def mint(cls) -> Self:
        """A fresh id of this family, without creating or writing anything."""
        return cls(mint_uuid())

    @classmethod
    def __get_pydantic_core_schema__(cls, _source: Any, _handler: Any) -> Any:
        return core_schema.no_info_after_validator_function(cls, core_schema.str_schema(pattern=UUID_PATTERN))


class UserId(UuidId):
    __slots__ = ()
    domain = "user"


class ProgramId(UuidId):
    """A program's id (#1454): a `programs` row, never a user."""

    __slots__ = ()
    domain = "program"


class MembershipId(UuidId):
    __slots__ = ()
    domain = "membership"


class CredentialId(UuidId):
    """A program credential's id; for an OAuth client it is also the realm client's id (#1307)."""

    __slots__ = ()
    domain = "program credential"


class AlertId(UuidId):
    __slots__ = ()
    domain = "alert"


class InvestigationId(UuidId):
    """An investigation's id; its run's id is the same UUID (`RunId.parse` turns one into the other)."""

    __slots__ = ()
    domain = "investigation"


class LearningJobId(UuidId):
    __slots__ = ()
    domain = "learning job"
