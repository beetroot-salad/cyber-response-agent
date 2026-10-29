"""Tenant registration, acceptance, and tenant ownership; the tenant record and its lifecycle
tables (#1214): the models, the repository port with its in-memory and PostgreSQL implementations
(`tenancy.postgres`, never served here, so importing this door loads no database driver), and the
synchronous `TenantDirectory` for host code."""
from __future__ import annotations

from typing import TYPE_CHECKING

from defender.lazy_door import lazy_door

if TYPE_CHECKING:
    from defender.tenancy._command_line_run import (
        open_command_line_run as open_command_line_run,
    )
    from defender.tenancy._directory import TenantDirectory as TenantDirectory
    from defender.tenancy._exports import (
        DeliveryRefused as DeliveryRefused,
        POINTER as POINTER,
        TenantExport as TenantExport,
        current_export as current_export,
        knowledge_lock_holder as knowledge_lock_holder,
        lock_pid as lock_pid,
        read_export_text as read_export_text,
        regular_files as regular_files,
        remove_entry as remove_entry,
    )
    from defender.tenancy._owner import (
        OWNER_FILE as OWNER_FILE,
        owner_alive as owner_alive,
        process_start as process_start,
        write_owner as write_owner,
    )
    from defender.tenancy._publish_status import (
        FRESH as FRESH,
        MISCONFIGURED as MISCONFIGURED,
        OPERATOR as OPERATOR,
        STALE_OPERATOR as STALE_OPERATOR,
        STALE_TRANSIENT as STALE_TRANSIENT,
        TRANSIENT as TRANSIENT,
        read_status as read_status,
        record_published as record_published,
        record_refusal as record_refusal,
        record_report as record_report,
    )
    from defender.tenancy._tenant import (
        ForgeBinding as ForgeBinding,
        ISSUER_ROLE as ISSUER_ROLE,
        Tenant as Tenant,
        TenantId as TenantId,
        accept_placed_knowledge as accept_placed_knowledge,
        accept_tenant as accept_tenant,
        box_mounted_arm_container as box_mounted_arm_container,
        box_mounted_episodes as box_mounted_episodes,
        check_knowledge_folder as check_knowledge_folder,
        check_run_settings as check_run_settings,
        clone_halves as clone_halves,
        create_tenant as create_tenant,
        data_root_for_child as data_root_for_child,
        data_root_from_path as data_root_from_path,
        is_valid_tenant_id as is_valid_tenant_id,
        learning_root_for_setup as learning_root_for_setup,
        parse_tenant_id_bytes as parse_tenant_id_bytes,
        read_forge_binding as read_forge_binding,
        refuse_foreign_data_root as refuse_foreign_data_root,
        requested_tenant as requested_tenant,
        requested_tenant_id as requested_tenant_id,
        resolve_data_root as resolve_data_root,
        retire_row as retire_row,
        tenant_id_file_text as tenant_id_file_text,
    )
    from defender.tenancy._tenants import (
        AGENT_HALF as AGENT_HALF,
        SETTINGS_HALF as SETTINGS_HALF,
        TENANT_ID_FILE as TENANT_ID_FILE,
        add_tenant_arguments as add_tenant_arguments,
        template_dir as template_dir,
    )
    from defender.tenancy.memory import InMemoryTenantRepository as InMemoryTenantRepository
    from defender.tenancy.models import (
        ForgeWiring as ForgeWiring,
        Generation as Generation,
        PublishStatus as PublishStatus,
        TenantRecord as TenantRecord,
    )
    from defender.tenancy.repository import (
        ADOPT_FAILURE as ADOPT_FAILURE,
        ALL as ALL,
        Conflict as Conflict,
        FenceMissed as FenceMissed,
        HeldTenant as HeldTenant,
        KEEP as KEEP,
        NotFound as NotFound,
        TenantRepository as TenantRepository,
        claimable_now as claimable_now,
    )

#: Each name this door serves, and the submodule that defines it.
_HOMES: dict[str, str] = {
    **dict.fromkeys(("open_command_line_run",), "_command_line_run"),
    **dict.fromkeys(("TenantDirectory",), "_directory"),
    **dict.fromkeys(("DeliveryRefused", "POINTER", "TenantExport", "current_export", "knowledge_lock_holder", "lock_pid", "read_export_text", "regular_files", "remove_entry",), "_exports"),
    **dict.fromkeys(("OWNER_FILE", "owner_alive", "process_start", "write_owner",), "_owner"),
    **dict.fromkeys(("FRESH", "MISCONFIGURED", "OPERATOR", "STALE_OPERATOR", "STALE_TRANSIENT", "TRANSIENT", "read_status", "record_published", "record_refusal", "record_report",), "_publish_status"),
    **dict.fromkeys(("ForgeBinding", "ISSUER_ROLE", "Tenant", "TenantId", "accept_placed_knowledge", "accept_tenant", "box_mounted_arm_container", "box_mounted_episodes", "check_knowledge_folder", "check_run_settings", "clone_halves", "create_tenant", "data_root_for_child", "data_root_from_path", "is_valid_tenant_id", "learning_root_for_setup", "parse_tenant_id_bytes", "read_forge_binding", "refuse_foreign_data_root", "requested_tenant", "requested_tenant_id", "resolve_data_root", "retire_row", "tenant_id_file_text",), "_tenant"),
    **dict.fromkeys(("AGENT_HALF", "SETTINGS_HALF", "TENANT_ID_FILE", "add_tenant_arguments", "template_dir",), "_tenants"),
    **dict.fromkeys(("InMemoryTenantRepository",), "memory"),
    **dict.fromkeys(("ForgeWiring", "Generation", "PublishStatus", "TenantRecord",), "models"),
    **dict.fromkeys(("ADOPT_FAILURE", "ALL", "Conflict", "FenceMissed", "HeldTenant", "KEEP", "NotFound", "TenantRepository", "claimable_now",), "repository"),
}

__getattr__ = lazy_door(globals(), _HOMES)
