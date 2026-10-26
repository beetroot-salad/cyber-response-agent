"""The tenant id and its refusal: the vocabulary run storage and tenancy share. Apart from
`_run_id` so that module stays loadable without pydantic."""
from __future__ import annotations

from typing import Any

from pydantic_core import core_schema

from defender._shown import escaped
from defender.records._run_id import mint_uuid, uuid_id_fault


class TenantRefused(Exception):
    """The one refusal shape (#0, F0/J29) for every tenant owner — this module (acceptance
    and its knowledge-folder rules included) and the run's grants (`run_tenant`): the
    message names the value that was refused, and every entry catches THIS and surfaces it
    verbatim. An `Exception`, not a `ValueError` (#1067's `_model.py` convention): pydantic
    wraps a `ValueError` raised inside a validator into its own `ValidationError`, where an
    `except TenantRefused` would silently miss it."""

    def __init__(self, message: object = "") -> None:
        # Escaped where it is built, as `RunRefused` is: a path or a value read off disk can
        # carry a control character, and no raising site has to remember to escape it.
        super().__init__(escaped(message))


class TenantId(str):
    """An opaque tenant id in canonical lowercase UUID text — the ONE place it is checked. Constructing one
    is the check: `TenantId(raw)` returns the id or raises `TenantRefused` naming `raw`, and a
    `TenantId` handed back in is returned as-is. It IS a `str` (paths, JSON, argv and log lines
    take it unchanged, and its repr is the string's), but a function that declares `TenantId`
    tells mypy a plain, unchecked `str` does not belong there. Entry points build one from the
    request; records and rows build one as they parse."""

    __slots__ = ()

    def __new__(cls, raw: object) -> TenantId:
        if isinstance(raw, TenantId):
            return raw
        fault = uuid_id_fault(raw, "tenant")
        if fault is not None:
            raise TenantRefused(fault)
        assert isinstance(raw, str)
        return super().__new__(cls, raw)

    @classmethod
    def mint(cls) -> TenantId:
        """Mint a tenant UUID without creating a tenant or writing any state."""
        return cls(mint_uuid())

    @classmethod
    def __get_pydantic_core_schema__(cls, _source: Any, _handler: Any) -> Any:
        return core_schema.no_info_after_validator_function(cls, core_schema.str_schema())
