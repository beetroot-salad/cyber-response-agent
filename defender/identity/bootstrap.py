"""The deployment bootstrap file: who the platform administrators are. Plain data; the service
applies it at start. Since #1214 it names no tenants: tenants are created through the API and their
first members invited by an administrator, so a file that still has a `tenants` section is refused."""

from __future__ import annotations

from typing import Any

from pydantic import model_validator

from defender._model import model, unwrap_before

from .models import Email


@model(frozen=True)
class Bootstrap:
    administrators: tuple[Email, ...]

    # TypeError, as for any unknown field of a dataclass, but naming what replaced the section.
    @model_validator(mode="before")
    @classmethod
    def _no_tenants_section(cls, value: Any) -> Any:
        given = unwrap_before(cls, value)
        if isinstance(given, dict) and "tenants" in given:
            raise TypeError("the bootstrap file has no tenants section since #1214: create a tenant through "
                            "the API and invite its first members as an administrator")
        return given
