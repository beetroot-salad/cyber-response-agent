"""Tenant knowledge layout, corpus access, and scaffold rules."""
from __future__ import annotations

from typing import TYPE_CHECKING

from defender.lazy_door import lazy_door

if TYPE_CHECKING:
    from defender.knowledge._corpus import (
        FENCE_LINE_RE as FENCE_LINE_RE,
        Lesson as Lesson,
        PROVENANCE_KEYS as PROVENANCE_KEYS,
        QueryTemplate as QueryTemplate,
        as_list as as_list,
        is_established as is_established,
        iter_lesson_paths as iter_lesson_paths,
        iter_lessons as iter_lessons,
        iter_query_templates as iter_query_templates,
        parse_query_template as parse_query_template,
        read_query_template as read_query_template,
        section_bodies as section_bodies,
        template_names as template_names,
    )
    from defender.knowledge._knowledge import (
        AGENT_REL as AGENT_REL,
        CATALOG as CATALOG,
        CATALOG_SCHEMA_NAME as CATALOG_SCHEMA_NAME,
        CHECKOUT_KNOWLEDGE as CHECKOUT_KNOWLEDGE,
        KnowledgePaths as KnowledgePaths,
        LESSONS as LESSONS,
        LESSONS_QUESTIONER as LESSONS_QUESTIONER,
        LESSON_CORPORA as LESSON_CORPORA,
        REDUCER_PITFALLS as REDUCER_PITFALLS,
        RUNTIME_LESSON_CORPORA as RUNTIME_LESSON_CORPORA,
        SKILLS as SKILLS,
    )
    from defender.knowledge._query_rules import (
        ABOVE_GUARD_QUERY_ID as ABOVE_GUARD_QUERY_ID,
        BASH_SHIM_QUERY_ID as BASH_SHIM_QUERY_ID,
        DENIED_QUERY_ID as DENIED_QUERY_ID,
        ParamsTooDeep as ParamsTooDeep,
        QID_FORBIDDEN as QID_FORBIDDEN,
        REPEAT_TRIP_QUERY_ID as REPEAT_TRIP_QUERY_ID,
        call_args_too_deep as call_args_too_deep,
        is_reserved_query_id as is_reserved_query_id,
        json_safe_params as json_safe_params,
        query_request_key as query_request_key,
        resolve_query_id as resolve_query_id,
    )

#: Each name this door serves, and the submodule that defines it.
_HOMES: dict[str, str] = {
    **dict.fromkeys(("FENCE_LINE_RE", "Lesson", "PROVENANCE_KEYS", "QueryTemplate", "as_list", "is_established", "iter_lesson_paths", "iter_lessons", "iter_query_templates", "parse_query_template", "read_query_template", "section_bodies", "template_names",), "_corpus"),
    **dict.fromkeys(("AGENT_REL", "CATALOG", "CATALOG_SCHEMA_NAME", "CHECKOUT_KNOWLEDGE", "KnowledgePaths", "LESSONS", "LESSONS_QUESTIONER", "LESSON_CORPORA", "REDUCER_PITFALLS", "RUNTIME_LESSON_CORPORA", "SKILLS",), "_knowledge"),
    **dict.fromkeys(("ABOVE_GUARD_QUERY_ID", "BASH_SHIM_QUERY_ID", "DENIED_QUERY_ID", "ParamsTooDeep", "QID_FORBIDDEN", "REPEAT_TRIP_QUERY_ID", "call_args_too_deep", "is_reserved_query_id", "json_safe_params", "query_request_key", "resolve_query_id",), "_query_rules"),
}

__getattr__ = lazy_door(globals(), _HOMES)
