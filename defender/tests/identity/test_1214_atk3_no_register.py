"""#1214 attack-3 hole 11 (DC-6): no tenancy port, repository or directory can register a tenant; rows are written only by
`request_create`, the workers, the backfill and adoption (seeders are named `add_*`).
"""
from __future__ import annotations


def _holders() -> list[type]:
    from defender.tenancy import InMemoryTenantRepository, TenantDirectory, TenantRepository
    from defender.tenancy.postgres import PostgresTenantRepository

    return [InMemoryTenantRepository, PostgresTenantRepository, TenantRepository, TenantDirectory]


def test_no_tenancy_class_has_a_register_method():
    """None of the tenancy repositories, the port or the directory has a method with `register` in its name (DC-6)."""
    found = [f"{holder.__name__}.{name}" for holder in _holders() for name in dir(holder)
             if "register" in name.lower()]
    assert found == []
    assert hasattr(_holders()[0], "request_create")  # control: the scan sees real methods
