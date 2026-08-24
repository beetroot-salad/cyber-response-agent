"""Snapshot-scoped pull tools for knowledge and source navigation."""

from __future__ import annotations

import hashlib
import math
import re
from typing import Any

from pydantic_ai import ModelRetry, RunContext

from .adaptive_models import (
    AdaptiveDeps,
    KnowledgeEntryView,
    KnowledgeQueryRecord,
    KnowledgeSearchHit,
    KnowledgeSearchResult,
    KnowledgeThreadView,
    SourceReadResult,
    SourceSearchHit,
    SourceSearchResult,
)
from .journal import digest
from .recursive_models import KnowledgeRelation, KnowledgeTag


_TOKEN = re.compile(r"[a-z0-9_]+")


def _tokens(value: str) -> list[str]:
    return _TOKEN.findall(value.lower())


def _score(query: str, text: str) -> float:
    query_tokens = list(dict.fromkeys(_tokens(query)))
    if not query_tokens:
        return 0.1
    lowered = text.lower()
    text_tokens = _tokens(text)
    counts: dict[str, int] = {}
    for token in text_tokens:
        counts[token] = counts.get(token, 0) + 1
    score = sum(
        1.0 + math.log1p(counts.get(token, 0))
        for token in query_tokens
        if token in counts
    )
    if query.lower().strip() and query.lower().strip() in lowered:
        score += 3.0
    return score


def _record(
    deps: AdaptiveDeps,
    tool: str,
    arguments: dict[str, Any],
    result: Any,
    result_ids: list[str],
) -> None:
    deps.query_log.append(
        KnowledgeQueryRecord(
            sequence=len(deps.query_log) + 1,
            tool=tool,
            arguments=arguments,
            result_ids=result_ids,
            result=result,
            result_sha256=digest(result),
        )
    )


def _tag_values(tags: list[str] | None) -> set[str]:
    if not tags:
        return set()
    known = {tag.value for tag in KnowledgeTag}
    return {tag for tag in tags if tag in known}


def _link_dict(link: Any) -> dict[str, Any]:
    return link.model_dump(mode="json")


class KnowledgeNavigator:
    """Read-only search over one immutable, visibility-scoped dependency snapshot."""

    def __init__(self, deps: AdaptiveDeps):
        self.deps = deps
        self.board = deps.knowledge_board

    def search_questions(
        self,
        query: str = "",
        tags: list[str] | None = None,
        unanswered_only: bool = False,
        limit: int = 10,
    ) -> KnowledgeSearchResult:
        limit = max(1, min(limit, self.deps.max_query_results, 50))
        wanted_tags = _tag_values(tags)
        hits: list[KnowledgeSearchHit] = []
        for question in self.board.questions_by_id.values():
            question_tags = {tag.value for tag in question.tags}
            answer_count = len(self.board.answer_ids_by_question.get(question.id, []))
            if wanted_tags and not wanted_tags.issubset(question_tags):
                continue
            if unanswered_only and answer_count:
                continue
            text = " ".join(
                [question.text, question.rationale, question.acceptance_condition]
            )
            score = _score(query, text)
            if query.strip() and score == 0:
                continue
            hits.append(
                KnowledgeSearchHit(
                    id=question.id,
                    kind="question",
                    score=score,
                    text=question.text,
                    tags=question.tags,
                    answer_count=answer_count,
                )
            )
        hits.sort(key=lambda hit: (-hit.score, hit.id))
        result = KnowledgeSearchResult(
            snapshot_sha256=self.board.content_sha256,
            query=query,
            hits=hits[:limit],
            truncated=len(hits) > limit,
        )
        _record(
            self.deps,
            "search_questions",
            {
                "query": query,
                "tags": tags or [],
                "unanswered_only": unanswered_only,
                "limit": limit,
            },
            result,
            [hit.id for hit in result.hits],
        )
        return result

    def search_answers(
        self,
        query: str = "",
        question_ids: list[str] | None = None,
        tags: list[str] | None = None,
        limit: int = 10,
    ) -> KnowledgeSearchResult:
        limit = max(1, min(limit, self.deps.max_query_results, 50))
        wanted_tags = _tag_values(tags)
        allowed_answers: set[str] | None = None
        if question_ids:
            allowed_answers = {
                answer_id
                for question_id in question_ids
                for answer_id in self.board.answer_ids_by_question.get(question_id, [])
            }
        hits: list[KnowledgeSearchHit] = []
        for answer in self.board.answers_by_id.values():
            if allowed_answers is not None and answer.id not in allowed_answers:
                continue
            answer_tags = {tag.value for tag in answer.tags}
            if wanted_tags and not wanted_tags.issubset(answer_tags):
                continue
            packet = (
                self.deps.packets_by_id.get(answer.packet_id)
                if answer.packet_id is not None
                else None
            )
            post = (
                self.deps.posts_by_id.get(answer.post_id)
                if answer.post_id is not None
                else None
            )
            claim_text = (
                " ".join(claim.statement for claim in packet.claims) if packet else ""
            )
            body = post.body if post is not None else (answer.body or answer.summary)
            text = " ".join([body, claim_text, *answer.unresolved])
            response_effects = [
                link.response_effect
                for link_id in self.board.outgoing_link_ids_by_entry.get(answer.id, [])
                if (link := self.board.links_by_id[link_id]).relation
                == KnowledgeRelation.RESPONDS_TO
                and link.response_effect is not None
            ]
            score = _score(query, text)
            if query.strip() and score == 0:
                continue
            hits.append(
                KnowledgeSearchHit(
                    id=answer.id,
                    kind="answer",
                    score=score,
                    text=body[:2000],
                    tags=answer.tags,
                    response_effects=response_effects,
                    sufficiency=answer.sufficiency,
                    unresolved_count=len(answer.unresolved),
                )
            )
        hits.sort(key=lambda hit: (-hit.score, hit.id))
        result = KnowledgeSearchResult(
            snapshot_sha256=self.board.content_sha256,
            query=query,
            hits=hits[:limit],
            truncated=len(hits) > limit,
        )
        _record(
            self.deps,
            "search_answers",
            {
                "query": query,
                "question_ids": question_ids or [],
                "tags": tags or [],
                "limit": limit,
            },
            result,
            [hit.id for hit in result.hits],
        )
        return result

    def entry(self, entry_id: str, *, record: bool = True) -> KnowledgeEntryView:
        if entry_id in self.board.questions_by_id:
            entry = self.board.questions_by_id[entry_id]
            kind = "question"
            content = entry.model_dump(mode="json")
            content["answer_ids"] = self.board.answer_ids_by_question.get(entry_id, [])
        elif entry_id in self.board.answers_by_id:
            entry = self.board.answers_by_id[entry_id]
            kind = "answer"
            content = entry.model_dump(mode="json")
            packet = (
                self.deps.packets_by_id.get(entry.packet_id)
                if entry.packet_id is not None
                else None
            )
            post = (
                self.deps.posts_by_id.get(entry.post_id)
                if entry.post_id is not None
                else None
            )
            if packet is not None:
                content["packet"] = packet.model_dump(mode="json")
            if post is not None:
                content["post"] = post.model_dump(mode="json")
            content["question_ids"] = self.board.question_ids_by_answer.get(
                entry_id, []
            )
        else:
            raise KeyError(entry_id)
        incoming = [
            _link_dict(self.board.links_by_id[link_id])
            for link_id in self.board.incoming_link_ids_by_entry.get(entry_id, [])
        ]
        outgoing = [
            _link_dict(self.board.links_by_id[link_id])
            for link_id in self.board.outgoing_link_ids_by_entry.get(entry_id, [])
        ]
        result = KnowledgeEntryView(
            id=entry_id,
            kind=kind,
            content=content,
            incoming_links=incoming,
            outgoing_links=outgoing,
        )
        if record:
            _record(self.deps, "get_entry", {"entry_id": entry_id}, result, [entry_id])
        return result

    def thread(
        self,
        question_id: str,
        max_answers: int = 8,
        include_related_questions: bool = True,
    ) -> KnowledgeThreadView:
        if question_id not in self.board.questions_by_id:
            raise KeyError(question_id)
        max_answers = max(1, min(max_answers, self.deps.max_query_results, 30))
        question = self.entry(question_id, record=False)
        answer_ids = self.board.answer_ids_by_question.get(question_id, [])
        answers = [
            self.entry(answer_id, record=False)
            for answer_id in answer_ids[:max_answers]
        ]
        related_ids: set[str] = set()
        if include_related_questions:
            for link_id in [
                *self.board.incoming_link_ids_by_entry.get(question_id, []),
                *self.board.outgoing_link_ids_by_entry.get(question_id, []),
            ]:
                link = self.board.links_by_id[link_id]
                if link.relation not in {
                    KnowledgeRelation.REFINES,
                    KnowledgeRelation.DEPENDS_ON,
                    KnowledgeRelation.DUPLICATES,
                }:
                    continue
                other_id = (
                    link.source_id if link.target_id == question_id else link.target_id
                )
                if other_id in self.board.questions_by_id:
                    related_ids.add(other_id)
        related = [
            self.entry(entry_id, record=False)
            for entry_id in sorted(related_ids)[: self.deps.max_query_results]
        ]
        result = KnowledgeThreadView(
            snapshot_sha256=self.board.content_sha256,
            question=question,
            answers=answers,
            related_questions=related,
            truncated=len(answer_ids) > max_answers
            or len(related_ids) > self.deps.max_query_results,
        )
        _record(
            self.deps,
            "get_thread",
            {
                "question_id": question_id,
                "max_answers": max_answers,
                "include_related_questions": include_related_questions,
            },
            result,
            [
                question_id,
                *answer_ids[:max_answers],
                *sorted(related_ids)[: self.deps.max_query_results],
            ],
        )
        return result

    def neighbors(
        self,
        entry_id: str,
        relations: list[str] | None = None,
        limit: int = 12,
    ) -> list[KnowledgeEntryView]:
        if entry_id not in {
            *self.board.questions_by_id,
            *self.board.answers_by_id,
        }:
            raise KeyError(entry_id)
        limit = max(1, min(limit, self.deps.max_query_results, 50))
        allowed_relations = set(relations or [])
        neighbor_ids: set[str] = set()
        for link_id in [
            *self.board.incoming_link_ids_by_entry.get(entry_id, []),
            *self.board.outgoing_link_ids_by_entry.get(entry_id, []),
        ]:
            link = self.board.links_by_id[link_id]
            if allowed_relations and link.relation.value not in allowed_relations:
                continue
            neighbor_ids.add(
                link.source_id if link.target_id == entry_id else link.target_id
            )
        selected = sorted(neighbor_ids)[:limit]
        result = [self.entry(neighbor_id, record=False) for neighbor_id in selected]
        _record(
            self.deps,
            "get_neighbors",
            {"entry_id": entry_id, "relations": relations or [], "limit": limit},
            result,
            selected,
        )
        return result

    def _sources(self) -> dict[str, tuple[str, str]]:
        sources = {
            path: (document.content, document.content_sha256)
            for path, document in self.deps.workspace_documents_by_path.items()
        }
        for source_id, material in self.deps.source_materials_by_id.items():
            sources[source_id] = (
                material.content,
                hashlib.sha256(material.content.encode("utf-8")).hexdigest(),
            )
        return sources

    def search_sources(
        self,
        query: str,
        source_ids: list[str] | None = None,
        limit: int = 8,
    ) -> SourceSearchResult:
        limit = max(1, min(limit, self.deps.max_query_results, 30))
        sources = self._sources()
        if source_ids:
            sources = {
                key: value for key, value in sources.items() if key in source_ids
            }
        candidates: list[SourceSearchHit] = []
        for source_id, (content, content_sha256) in sources.items():
            lines = content.splitlines()
            for start in range(0, len(lines) or 1, 24):
                end = min(start + 32, len(lines))
                excerpt = "\n".join(lines[start:end])
                score = _score(query, excerpt)
                if score == 0:
                    continue
                candidates.append(
                    SourceSearchHit(
                        source_id=source_id,
                        locator=f"lines {start + 1}-{max(end, start + 1)}",
                        excerpt=excerpt[:1600],
                        score=score,
                        content_sha256=content_sha256,
                    )
                )
        candidates.sort(key=lambda hit: (-hit.score, hit.source_id, hit.locator))
        result = SourceSearchResult(
            query=query,
            hits=candidates[:limit],
            truncated=len(candidates) > limit,
        )
        disclosed = [hit.source_id for hit in result.hits]
        self.deps.disclosed_source_ids[:] = list(
            dict.fromkeys([*self.deps.disclosed_source_ids, *disclosed])
        )
        _record(
            self.deps,
            "search_sources",
            {"query": query, "source_ids": source_ids or [], "limit": limit},
            result,
            disclosed,
        )
        return result

    def read_source(
        self,
        source_id: str,
        start_line: int = 1,
        line_count: int = 80,
    ) -> SourceReadResult:
        sources = self._sources()
        if source_id not in sources:
            raise KeyError(source_id)
        content, content_sha256 = sources[source_id]
        lines = content.splitlines()
        start = max(start_line - 1, 0)
        count = max(1, min(line_count, 240))
        selected = "\n".join(lines[start : start + count])
        max_chars = self.deps.max_source_chunk_chars
        truncated = len(selected) > max_chars or start + count < len(lines)
        selected = selected[:max_chars]
        end = min(start + count, len(lines))
        result = SourceReadResult(
            source_id=source_id,
            locator=f"lines {start + 1}-{max(end, start + 1)}",
            content=selected,
            content_sha256=content_sha256,
            truncated=truncated,
        )
        if source_id not in self.deps.disclosed_source_ids:
            self.deps.disclosed_source_ids.append(source_id)
        _record(
            self.deps,
            "read_source",
            {
                "source_id": source_id,
                "start_line": start_line,
                "line_count": line_count,
            },
            result,
            [source_id],
        )
        return result


def _navigator(ctx: RunContext[AdaptiveDeps]) -> KnowledgeNavigator:
    return KnowledgeNavigator(ctx.deps)


def search_questions(
    ctx: RunContext[AdaptiveDeps],
    query: str = "",
    tags: list[str] | None = None,
    unanswered_only: bool = False,
    limit: int = 10,
) -> KnowledgeSearchResult:
    """Search first-class questions in the immutable visible snapshot."""
    return _navigator(ctx).search_questions(query, tags, unanswered_only, limit)


def search_answers(
    ctx: RunContext[AdaptiveDeps],
    query: str = "",
    question_ids: list[str] | None = None,
    tags: list[str] | None = None,
    limit: int = 10,
) -> KnowledgeSearchResult:
    """Search first-class answers, optionally within one or more question threads."""
    return _navigator(ctx).search_answers(query, question_ids, tags, limit)


def get_entry(ctx: RunContext[AdaptiveDeps], entry_id: str) -> KnowledgeEntryView:
    """Fetch one exact question or answer, including its typed links and provenance."""
    try:
        return _navigator(ctx).entry(entry_id)
    except KeyError as exc:
        raise ModelRetry(f"Entry is not visible in this snapshot: {entry_id}") from exc


def get_thread(
    ctx: RunContext[AdaptiveDeps],
    question_id: str,
    max_answers: int = 8,
    include_related_questions: bool = True,
) -> KnowledgeThreadView:
    """Open a question thread with answers and related first-class questions."""
    try:
        return _navigator(ctx).thread(
            question_id, max_answers, include_related_questions
        )
    except KeyError as exc:
        raise ModelRetry(f"Question is not visible: {question_id}") from exc


def get_neighbors(
    ctx: RunContext[AdaptiveDeps],
    entry_id: str,
    relations: list[str] | None = None,
    limit: int = 12,
) -> list[KnowledgeEntryView]:
    """Traverse typed question-question, answer-question, or answer-answer links."""
    try:
        return _navigator(ctx).neighbors(entry_id, relations, limit)
    except KeyError as exc:
        raise ModelRetry(f"Entry is not visible: {entry_id}") from exc


def search_sources(
    ctx: RunContext[AdaptiveDeps],
    query: str,
    source_ids: list[str] | None = None,
    limit: int = 8,
) -> SourceSearchResult:
    """Search source chunks without injecting complete files into the prompt."""
    return _navigator(ctx).search_sources(query, source_ids, limit)


def read_source(
    ctx: RunContext[AdaptiveDeps],
    source_id: str,
    start_line: int = 1,
    line_count: int = 80,
) -> SourceReadResult:
    """Read a bounded line range from an exact snapshotted source."""
    try:
        return _navigator(ctx).read_source(source_id, start_line, line_count)
    except KeyError as exc:
        raise ModelRetry(
            f"Source is not visible in this snapshot: {source_id}"
        ) from exc


KNOWLEDGE_TOOLS = [
    search_questions,
    search_answers,
    get_entry,
    get_thread,
    get_neighbors,
    search_sources,
    read_source,
]
