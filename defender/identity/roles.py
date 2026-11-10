"""The fixed roles (#1307 D4): a role is a set of permissions, defined here in code. A route names the one
permission it needs and never a role; a role is read only to answer whether it grants a permission."""

from __future__ import annotations

from typing import Literal

from .models import Role

Permission = Literal[
    "work.read", "investigations.run", "learning.run", "investigations.delete",
    "config.read", "config.write", "people.manage",
]

_ALL: frozenset[Permission] = frozenset({
    "work.read", "investigations.run", "learning.run", "investigations.delete",
    "config.read", "config.write", "people.manage",
})

#: `admin` holds every permission; `automation` reads work and runs investigations, and starts no learning
#: job until a caller asks (D8).
ROLE_PERMISSIONS: dict[Role, frozenset[Permission]] = {
    "admin": _ALL,
    "automation": frozenset({"work.read", "investigations.run"}),
}


def grants(role: Role, permission: Permission) -> bool:
    return permission in ROLE_PERMISSIONS[role]
