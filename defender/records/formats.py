"""The record formats other areas read and write (#1315): alert input, artifact schemas, run ids,
provenance, reports, families, episode paths and handles, record locations. A door, served lazily
(`defender.lazy_door`); the runs repository has its own door, the package `defender.records`."""
from __future__ import annotations

from typing import TYPE_CHECKING

from defender.lazy_door import lazy_door

if TYPE_CHECKING:
    from defender.records._alert_input import (
        AlertFacts as AlertFacts,
        AlertMappingFault as AlertMappingFault,
        AlertRecord as AlertRecord,
        AlertRefused as AlertRefused,
        AlertReplaced as AlertReplaced,
        admit as admit,
        derive_facts as derive_facts,
        digest_of as digest_of,
        load_alert_mapping as load_alert_mapping,
        parse_alert_record as parse_alert_record,
        read_operator_alert as read_operator_alert,
        read_record as read_record,
        record_beside as record_beside,
        record_text as record_text,
        settings_reasons as settings_reasons,
        verified_alert as verified_alert,
        verified_document as verified_document,
        verified_input as verified_input,
        verify_input_bytes as verify_input_bytes,
    )
    from defender.records._artifact_schema import (
        REPORT_CLOSE_DELIMITER as REPORT_CLOSE_DELIMITER,
        UNCHANGED_LEAD as UNCHANGED_LEAD,
        UNCHANGED_NOTICE as UNCHANGED_NOTICE,
        artifact_names as artifact_names,
        committed_investigation_reason as committed_investigation_reason,
        encodable_or_reason as encodable_or_reason,
        needs_baseline as needs_baseline,
        register_invlang_validator as register_invlang_validator,
        render_diagnostic as render_diagnostic,
        utf8_len as utf8_len,
        validate_artifact as validate_artifact,
        validate_report as validate_report,
    )
    from defender.records._episode_handle import (
        AppendRecord as AppendRecord,
        Episode as Episode,
        EpisodeRefused as EpisodeRefused,
        refuse_bad_episode_id as refuse_bad_episode_id,
    )
    from defender.records._episode_paths import (
        EpisodePaths as EpisodePaths,
        LAYOUT as LAYOUT,
        OracleStorePaths as OracleStorePaths,
        WORLD_LEAVES as WORLD_LEAVES,
        WorldPaths as WorldPaths,
    )
    from defender.records._family import (
        BASE_ROLE as BASE_ROLE,
        Family as Family,
        FamilyError as FamilyError,
        ManifestPredatesOracle as ManifestPredatesOracle,
        ResumeWorld as ResumeWorld,
        accept_family as accept_family,
        family_identities as family_identities,
        label_for_world_id as label_for_world_id,
        load_family as load_family,
        load_manifest_document as load_manifest_document,
        parse_family as parse_family,
        resume_world_from as resume_world_from,
        runnable_worlds as runnable_worlds,
        world_id_for as world_id_for,
        write_family as write_family,
    )
    from defender.records._knowledge_pin import (
        PinUnreadable as PinUnreadable,
        pin_text as pin_text,
        read_pin as read_pin,
    )
    from defender.records._knowledge_status import (
        FRESH as FRESH,
        OPERATOR as OPERATOR,
        TRANSIENT as TRANSIENT,
        knowledge_status as knowledge_status,
        read_knowledge_status as read_knowledge_status,
    )
    from defender.records._locations import (
        CommitRecord as CommitRecord,
        DataRoot as DataRoot,
        DraftsRoot as DraftsRoot,
        EpisodesRoot as EpisodesRoot,
        ExportsRoot as ExportsRoot,
        KnowledgeLock as KnowledgeLock,
        LearningRoot as LearningRoot,
        LegacyEpisodesRoot as LegacyEpisodesRoot,
        LegacyRunsRoot as LegacyRunsRoot,
        RunsBase as RunsBase,
        SessionsRoot as SessionsRoot,
        TenantRecord as TenantRecord,
        TenantRoot as TenantRoot,
        WorktreesRoot as WorktreesRoot,
        unwrap_commit_record as unwrap_commit_record,
        unwrap_data_root as unwrap_data_root,
        unwrap_drafts_root as unwrap_drafts_root,
        unwrap_episodes_root as unwrap_episodes_root,
        unwrap_exports_root as unwrap_exports_root,
        unwrap_knowledge_lock as unwrap_knowledge_lock,
        unwrap_learning_root as unwrap_learning_root,
        unwrap_runs_base as unwrap_runs_base,
        unwrap_tenant_root as unwrap_tenant_root,
    )
    from defender.records._provenance import (
        KnowledgeRevision as KnowledgeRevision,
        RunProvenance as RunProvenance,
        capture_tree as capture_tree,
        read_provenance as read_provenance,
    )
    from defender.records._report import (
        ReportRead as ReportRead,
        ReportUnreadable as ReportUnreadable,
        UNKNOWN_DISPOSITION as UNKNOWN_DISPOSITION,
        parse_report_text as parse_report_text,
        read_report as read_report,
        repeats_disposition as repeats_disposition,
        require_report as require_report,
    )
    from defender.records._run_id import (
        OID as OID,
        RUN_ID_ALLOWED as RUN_ID_ALLOWED,
        is_valid_run_id as is_valid_run_id,
        run_id_fault as run_id_fault,
        uuid_id_fault as uuid_id_fault,
    )
    from defender.records._seeded import (
        BranchError as BranchError,
        holds_content as holds_content,
        inherited_artifact_names as inherited_artifact_names,
        lead_dirs as lead_dirs,
        refuse_seeded_run_dir as refuse_seeded_run_dir,
    )
    from defender.records._tenant_id import (
        TenantId as TenantId,
        TenantRefused as TenantRefused,
    )
    from defender.records._wire import (
        wire_digest as wire_digest,
    )

#: Each name this door serves, and the submodule that defines it.
_HOMES: dict[str, str] = {
    **dict.fromkeys(("AlertFacts", "AlertMappingFault", "AlertRecord", "AlertRefused", "AlertReplaced", "admit", "derive_facts", "digest_of", "load_alert_mapping", "parse_alert_record", "read_operator_alert", "read_record", "record_beside", "record_text", "settings_reasons", "verified_alert", "verified_document", "verified_input", "verify_input_bytes",), "_alert_input"),  # lint-run-records: ok — the submodule `records/_alert_input.py`, not the run folder of that name
    **dict.fromkeys(("REPORT_CLOSE_DELIMITER", "UNCHANGED_LEAD", "UNCHANGED_NOTICE", "artifact_names", "committed_investigation_reason", "encodable_or_reason", "needs_baseline", "register_invlang_validator", "render_diagnostic", "utf8_len", "validate_artifact", "validate_report",), "_artifact_schema"),
    **dict.fromkeys(("AppendRecord", "Episode", "EpisodeRefused", "refuse_bad_episode_id",), "_episode_handle"),
    **dict.fromkeys(("EpisodePaths", "LAYOUT", "OracleStorePaths", "WORLD_LEAVES", "WorldPaths",), "_episode_paths"),
    **dict.fromkeys(("BASE_ROLE", "Family", "FamilyError", "ManifestPredatesOracle", "ResumeWorld", "accept_family", "family_identities", "label_for_world_id", "load_family", "load_manifest_document", "parse_family", "resume_world_from", "runnable_worlds", "world_id_for", "write_family",), "_family"),
    **dict.fromkeys(("PinUnreadable", "pin_text", "read_pin",), "_knowledge_pin"),
    **dict.fromkeys(("FRESH", "OPERATOR", "TRANSIENT", "knowledge_status", "read_knowledge_status",), "_knowledge_status"),
    **dict.fromkeys(("CommitRecord", "DataRoot", "DraftsRoot", "EpisodesRoot", "ExportsRoot", "KnowledgeLock", "LearningRoot", "LegacyEpisodesRoot", "LegacyRunsRoot", "RunsBase", "SessionsRoot", "TenantRecord", "TenantRoot", "WorktreesRoot", "unwrap_commit_record", "unwrap_data_root", "unwrap_drafts_root", "unwrap_episodes_root", "unwrap_exports_root", "unwrap_knowledge_lock", "unwrap_learning_root", "unwrap_runs_base", "unwrap_tenant_root",), "_locations"),
    **dict.fromkeys(("KnowledgeRevision", "RunProvenance", "capture_tree", "read_provenance",), "_provenance"),
    **dict.fromkeys(("ReportRead", "ReportUnreadable", "UNKNOWN_DISPOSITION", "parse_report_text", "read_report", "repeats_disposition", "require_report",), "_report"),
    **dict.fromkeys(("OID", "RUN_ID_ALLOWED", "is_valid_run_id", "run_id_fault", "uuid_id_fault",), "_run_id"),
    **dict.fromkeys(("BranchError", "holds_content", "inherited_artifact_names", "lead_dirs", "refuse_seeded_run_dir",), "_seeded"),
    **dict.fromkeys(("TenantId", "TenantRefused",), "_tenant_id"),
    **dict.fromkeys(("wire_digest",), "_wire"),
}

__getattr__ = lazy_door(globals(), _HOMES)
