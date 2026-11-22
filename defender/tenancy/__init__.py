"""Tenant registration, acceptance, and tenant ownership; the tenant record and its lifecycle
tables (#1214): the models, the repository port with its in-memory and PostgreSQL implementations
(`tenancy.postgres`, never served here, so importing this door loads no database driver), and the
synchronous `TenantDirectory` for host code."""
from __future__ import annotations

from typing import TYPE_CHECKING

from defender.lazy_door import lazy_door

if TYPE_CHECKING:
    from defender.tenancy._access import (
        ACCESS_FILE as ACCESS_FILE,
        access_pointer as access_pointer,
        parse_access as parse_access,
        read_access as read_access,
        read_export_access as read_export_access,
    )
    from defender.tenancy._approle_login import (
        DELIVERY_LOGIN as DELIVERY_LOGIN,
        LOGIN_PATH as LOGIN_PATH,
        SIGN_LOGIN as SIGN_LOGIN,
        AppRoleLogin as AppRoleLogin,
        AppRoleLoginError as AppRoleLoginError,
        CleartextAddress as CleartextAddress,
        LoginPair as LoginPair,
        LoginRefused as LoginRefused,
        LoginUnreachable as LoginUnreachable,
        LoginUnrecorded as LoginUnrecorded,
        NoLiveGeneration as NoLiveGeneration,
        SecretFileUnusable as SecretFileUnusable,
        approle_login as approle_login,
        live_generation as live_generation,
        recorded_login as recorded_login,
    )
    from defender.tenancy._admission import (
        admit_tenant as admit_tenant,
        database_address_variable as database_address_variable,
        host_directory as host_directory,
        in_lifecycle_process as in_lifecycle_process,
        mark_lifecycle_process as mark_lifecycle_process,
        still_active as still_active,
    )
    from defender.tenancy._command_line_run import (
        open_command_line_run as open_command_line_run,
    )
    from defender.tenancy._directory import (
        RecordsUnreachable as RecordsUnreachable,
        TenantDirectory as TenantDirectory,
    )
    from defender.tenancy._exports import (
        DeliveryRefused as DeliveryRefused,
        POINTER as POINTER,
        TenantExport as TenantExport,
        current_export as current_export,
        current_export_at as current_export_at,
        read_export_text as read_export_text,
        regular_files as regular_files,
        remove_entry as remove_entry,
    )
    from defender.tenancy._owner import (
        OWNER_FILE as OWNER_FILE,
        REPO_SCRATCH as REPO_SCRATCH,
        mark_alive as mark_alive,
        owned_temporary as owned_temporary,
        owner_alive as owner_alive,
        private_folder as private_folder,
        process_mark as process_mark,
        process_start as process_start,
        sweep_dead_owners as sweep_dead_owners,
        write_owner as write_owner,
    )
    from defender.tenancy._tenant import (
        ISSUER_ROLE as ISSUER_ROLE,
        Tenant as Tenant,
        TenantId as TenantId,
        accept_tenant as accept_tenant,
        box_mounted_arm_container as box_mounted_arm_container,
        box_mounted_episodes as box_mounted_episodes,
        check_knowledge_folder as check_knowledge_folder,
        check_run_settings as check_run_settings,
        data_root_for_child as data_root_for_child,
        data_root_from_path as data_root_from_path,
        is_valid_tenant_id as is_valid_tenant_id,
        job_tenant_folder as job_tenant_folder,
        parse_tenant_id_bytes as parse_tenant_id_bytes,
        refuse_unplaceable_data_root as refuse_unplaceable_data_root,
        requested_tenant as requested_tenant,
        requested_tenant_id as requested_tenant_id,
        resolve_data_root as resolve_data_root,
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
        MergeEligibility as MergeEligibility,
        TenantRecord as TenantRecord,
        offboard as offboard,
    )
    from defender.tenancy.record_values import (
        CaseRecord as CaseRecord,
        SystemRecord as SystemRecord,
        TenantRecords as TenantRecords,
    )
    from defender.tenancy.repository import (
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
    **dict.fromkeys(("ACCESS_FILE", "access_pointer", "parse_access", "read_access", "read_export_access",), "_access"),
    **dict.fromkeys(("DELIVERY_LOGIN", "LOGIN_PATH", "SIGN_LOGIN", "AppRoleLogin", "AppRoleLoginError", "CleartextAddress", "LoginPair", "LoginRefused", "LoginUnreachable", "LoginUnrecorded", "NoLiveGeneration", "SecretFileUnusable", "approle_login", "live_generation", "recorded_login",), "_approle_login"),
    **dict.fromkeys(("admit_tenant", "database_address_variable", "host_directory", "in_lifecycle_process", "mark_lifecycle_process", "still_active",), "_admission"),
    **dict.fromkeys(("open_command_line_run",), "_command_line_run"),
    **dict.fromkeys(("RecordsUnreachable", "TenantDirectory",), "_directory"),
    **dict.fromkeys(("DeliveryRefused", "POINTER", "TenantExport", "current_export", "current_export_at", "read_export_text", "regular_files", "remove_entry",), "_exports"),
    **dict.fromkeys(("OWNER_FILE", "REPO_SCRATCH", "mark_alive", "owned_temporary", "owner_alive", "private_folder", "process_mark", "process_start", "sweep_dead_owners", "write_owner",), "_owner"),
    **dict.fromkeys(("ISSUER_ROLE", "Tenant", "TenantId", "accept_tenant", "box_mounted_arm_container", "box_mounted_episodes", "check_knowledge_folder", "check_run_settings", "data_root_for_child", "data_root_from_path", "is_valid_tenant_id", "job_tenant_folder", "parse_tenant_id_bytes", "refuse_unplaceable_data_root", "requested_tenant", "requested_tenant_id", "resolve_data_root", "tenant_id_file_text",), "_tenant"),
    **dict.fromkeys(("AGENT_HALF", "SETTINGS_HALF", "TENANT_ID_FILE", "add_tenant_arguments", "template_dir",), "_tenants"),
    **dict.fromkeys(("InMemoryTenantRepository",), "memory"),
    **dict.fromkeys(("ForgeWiring", "Generation", "MergeEligibility", "TenantRecord", "offboard", ), "models"),
    **dict.fromkeys(("SystemRecord", "CaseRecord", "TenantRecords"), "record_values"),
    **dict.fromkeys(("ALL", "Conflict", "FenceMissed", "HeldTenant", "KEEP", "NotFound", "TenantRepository", "claimable_now",), "repository"),
}

__getattr__ = lazy_door(globals(), _HOMES)
