from __future__ import annotations

import json
import random
from pathlib import Path
from uuid import uuid4
from typing import Any


from defender import _yaml

from defender._io import Bound, Held
from defender.learning._prompt import stage_user_message, structured_json_body
from defender._text import is_content_less
from defender._untrusted import wrap
from defender._clock import now_iso
from defender.knowledge._corpus import PROVENANCE_KEYS, iter_lessons
from defender.knowledge._knowledge import AGENT_REL, KnowledgePaths
from defender.learning.core.lane_trees import DrainTrees
from defender.learning.core.state import Channel, LearningState



class AuthorError(Exception):
    pass


def lane_corpus(trees: DrainTrees, corpus_dir: Path) -> Held:
    """@owns corpus — the curator's corpus mount (`CorpusAuthorConfig.corpus`): the `Held`
    the lane's open trees hold at `corpus_dir` exactly (`trees.mount`), never a handle built here.

    Trees that hold no mount at `corpus_dir` itself (opened for another lane's label or an
    unknown one, or over a mount list that moved or omits the corpus, or holds only a folder
    above it) are fatal config, never a fall-back to plain paths (#1134)."""
    from defender.learning.core.config import FatalConfigError

    try:
        return trees.mount(corpus_dir)
    except ValueError:
        raise FatalConfigError(
            f"refused: the lane's held trees {[str(m) for m in trees.mounts]} hold no mount at "
            f"{corpus_dir}"
        ) from None


def lane_corpus_dir(paths: Any, batch: Any, corpus: str) -> tuple[Path, Path, str]:
    """`(root, corpus_dir, corpus_rel)` of the channel's corpus `corpus`: with a batch, the
    corpus lies in its draft (`<draft_root>/agent/<corpus>`, the root being the box's `staged`
    mount); without one, in the checkout-shaped tree `paths` names (a scene, which never
    claims). `corpus_rel` is the corpus' spelling in the tenant repository (OD6)."""
    if batch is not None:
        root = Path(batch.draft_root)
        knowledge = KnowledgePaths(agent_root=root / AGENT_REL)
    else:
        root = Path(paths.repo_root)
        knowledge = paths.knowledge
    return root, knowledge.corpus_dir(corpus), knowledge.rel(corpus)


def without_consumed_category(rec: dict) -> dict:
    return {k: v for k, v in rec.items() if k != "consumed_category"}


def existing_finding_ids(cfg: Any) -> set[str]:
    """Every queue-row id this corpus already attributes a lesson to — the pre-author
    idempotency read, shared by every corpus-author channel.

    Uses `provenance_field`, the same derivation the drain's attribution gate reads; if they
    disagreed a file would be re-authored every tick.
    """
    from defender.learning.core.config import provenance_field

    ids: set[str] = set()
    field = provenance_field(cfg.channel.id_key)
    for lesson in iter_lessons(
        cfg.corpus.view(), where=cfg.corpus_dir,
        warn_label=lambda p: f"finding-id pre-flight: {p.name}",
    ):
        sids = lesson.fm.get(field) or []  # lint-lesson-text: ok — ids compared as set members, never printed
        if isinstance(sids, list):
            ids.update(sid for sid in sids if isinstance(sid, str))
    return ids


def by_id(rows: list[dict], id_key: str) -> dict[str, dict]:
    return {r[id_key]: r for r in rows}


def partition_committed(
    committed: list[dict], *, hold_committed: bool
) -> tuple[list[dict], list[dict]]:
    if hold_committed:
        return [without_consumed_category(c) for c in committed], []
    return [], committed




def result_list(result: dict, key: str) -> list[Any]:
    value = result.get(key, [])
    if value is None:
        return []
    if not isinstance(value, list):
        raise AuthorError(f"AUTHOR_RESULT field {key!r} must be a list")
    return value


def commit_message(result: dict, noun: str) -> str:
    msg = result.get("commit_message")
    # Refuse to commit a lesson edit with a message that renders as nothing.
    if not isinstance(msg, str) or is_content_less(msg):
        raise AuthorError(
            f"AUTHOR_RESULT reported committed {noun} without a non-empty "
            "commit_message; refusing to commit"
        )
    return msg


def _result_entry_id(bucket: str, entry: Any, id_key: str) -> str:
    if bucket == "committed":
        if not isinstance(entry, str) or is_content_less(entry):
            raise AuthorError(
                f"AUTHOR_RESULT committed entries must be non-empty {id_key} strings"
            )
        return entry
    if not isinstance(entry, dict):
        raise AuthorError(f"AUTHOR_RESULT {bucket} entries must be objects")
    rid = entry.get(id_key)
    if not isinstance(rid, str) or is_content_less(rid):
        raise AuthorError(
            f"AUTHOR_RESULT {bucket} entries must include a non-empty {id_key}"
        )
    return rid


#: Fields an AUTHOR_RESULT may carry beyond its declared buckets: `commit_message`, read
#: elsewhere.
_NON_BUCKET_RESULT_KEYS = frozenset({"commit_message"})


def validate_agent_result_partition(
    result: dict,
    to_author: list[dict],
    *,
    id_key: str,
    buckets: tuple[str, ...],
    noun: str,
) -> None:
    """Validate the AUTHOR_RESULT's buckets against the batch: no unknown ids, no id in two
    buckets, and no unrecognized bucket-shaped key (e.g. a stale or invented bucket name).

    A row in no bucket is not an error; downstream leaves it queued."""
    expected = {row[id_key] for row in to_author}
    occurrences: dict[str, list[str]] = {}
    for bucket in buckets:
        for entry in result_list(result, bucket):
            rid = _result_entry_id(bucket, entry, id_key)
            occurrences.setdefault(rid, []).append(bucket)

    unknown = sorted(rid for rid in occurrences if rid not in expected)
    if unknown:
        raise AuthorError(f"author result contains unknown {noun}: {unknown}")
    repeated = {
        rid: where for rid, where in sorted(occurrences.items()) if len(where) != 1
    }
    if repeated:
        raise AuthorError(
            f"author result classified {noun} more than once: "
            + json.dumps(repeated, sort_keys=True)
        )
    # A stray key is rejected only when bucket-shaped (a list of row-like dicts), since that
    # looks like a real bucket. Scalars or string lists under unknown keys are unread noise
    # and tolerated.
    allowed_keys = set(buckets) | _NON_BUCKET_RESULT_KEYS
    stray_bucket_keys = sorted(
        k for k, v in result.items()
        if k not in allowed_keys and isinstance(v, list) and any(isinstance(e, dict) for e in v)
    )
    if stray_bucket_keys:
        raise AuthorError(f"author result carries unrecognized bucket key(s): {stray_bucket_keys}")


def verify_agent_report(result: dict, *, corpus_changed: bool, corpus_rel: str, noun: str) -> None:
    """Refuse a spawn whose report and tree disagree: `committed` non-empty with the corpus
    unchanged against the batch's base, or empty with it changed (`corpus_changed`: the claim's
    change set holds a lesson edit or a deletion under the corpus)."""
    committed = result_list(result, "committed")
    if committed and not corpus_changed:
        raise AuthorError(
            f"author reported committed {noun} but left {corpus_rel} "
            "unchanged; refusing to rotate queue"
        )
    if not committed and corpus_changed:
        raise AuthorError(
            f"author reported no commits but left edits in {corpus_rel}; "
            "refusing to rotate queue"
        )


def build_corpus_manifest(
    corpus: Bound | Path, *, where: Path | None = None, seed: str | None = None,
) -> str:
    """The curator's frontmatter manifest of the corpus. A shared reader (#1134 A4): the drain
    hands its corpus mount's view with `where`, that folder's spelling; a caller outside the
    drain hands a `Path` (no `where`), opened for the call. A lesson that cannot be read (a link
    or hard link at its name included) or parsed keeps its stem under an "unavailable"
    placeholder."""
    sections: list[str] = []
    skipped: list[Path] = []
    for lesson in iter_lessons(
        corpus, where=where, warn_label=lambda p: f"corpus manifest: {p.name}",
        on_skip=skipped.append,
    ):
        kept = {k: v for k, v in lesson.fm.items() if k not in PROVENANCE_KEYS}  # lint-lesson-text: ok — the manifest reaches the curator only inside its curator_context frame
        if "source_signature" in kept:
            # Each entry is one printed line (a break or control in a hand-written entry would
            # forge a key), shown as the text written.
            kept["source_signature"] = lesson.lines("source_signature")
        rendered = _yaml.safe_dump(
            kept, sort_keys=True, default_flow_style=False, allow_unicode=True
        )
        slug = " ".join(lesson.path.stem.split())
        sections.append(f"## {slug}\n{rendered}")
    for path in skipped:
        slug = " ".join(path.stem.split())
        sections.append(
            f"## {slug}\n(unavailable: this lesson file is malformed or unreadable, so its "
            "frontmatter cannot be shown. The stem is taken — repair this lesson rather than "
            "authoring an overlapping one.)\n"
        )
    if seed is not None:
        random.Random(seed).shuffle(sections)
    return "\n".join(sections)


def build_curator_user_prompt(
    rows: list[dict], batch_id: str, *, corpus: Bound, corpus_dir: Path, corpus_dir_rel: str,
    label: str,
    manifest_seed: str | None = None,
    salt: str | None = None,
) -> str:
    """The curator spawn's user turn. The manifest is read through `corpus`, the corpus mount's
    view (#1134); `corpus_dir` is that folder's spelling only."""
    seed = manifest_seed if manifest_seed is not None else batch_id
    manifest = build_corpus_manifest(
        corpus, where=corpus_dir, seed=seed,
    ) or "(none — the corpus is empty)"
    manifest_stems = "\n".join(
        line.removeprefix("## ")
        for line in manifest.splitlines()
        if line.startswith("## ")
    )
    context = (
        f"batch_id: {batch_id}\n"
        f"lessons_dir: {corpus_dir_rel}\n"
        f"{label} ({len(rows)}): in the lesson_rows frame\n\n"
        f"existing lessons (frontmatter manifest):\n{manifest}"
    )
    stage_salt = salt if salt is not None else uuid4().hex
    return stage_user_message(
        stage_salt,
        wrap(context, "curator_context", stage_salt),
        wrap(manifest_stems, "corpus_manifest", stage_salt),
        wrap(structured_json_body(rows) if rows else "", "lesson_rows", stage_salt),
    )


def write_disposition_report(
    state: LearningState, channel: Channel, *, batch_id: str, groups: dict[str, list[dict]],
) -> None:
    """One line per tick naming what the tick declined, under one label per reason.

    Shared by both curators: a skip is terminal, so this line is the only trace that a
    skipped finding was ever seen. Labels are the caller's and never merged, since each
    implies a different recovery. Counts first, then ids, in the caller's order; then, for each
    label whose rows carry a gate's `held_reason`, `<label>_reasons={id: reason}` — a held row
    stays queued tick after tick, so the line is where an operator reads why.

    Nothing is written when the tick declined nothing.
    """
    if not any(groups.values()):
        return
    counts = " ".join(f"{label}={len(rows)}" for label, rows in groups.items())
    ids = " ".join(
        f"{label}_ids={[r.get('finding_id') for r in rows]}" for label, rows in groups.items())
    reasons = "".join(
        f" {label}_reasons={why}" for label, rows in groups.items()
        if (why := {r.get("finding_id"): r["held_reason"] for r in rows if "held_reason" in r}))
    state.disposition_report(
        channel, f"{now_iso()} batch={batch_id} {counts} {ids}{reasons}\n")
