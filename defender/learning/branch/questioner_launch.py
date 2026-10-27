"""Questioner samples and invocation for an episode launch."""
from __future__ import annotations

import argparse



import json

import logging





from collections.abc import Callable, Mapping, Sequence

from pathlib import Path

from typing import Any


from defender.records._episode_handle import Episode


from defender._io import (
    load_json_artifact,
    read_text_soft,
    read_text_utf8,
)


from defender.records import (
    Run,
    artifact_dir,
    artifact_file,
)











from defender.runtime import branch

from defender.runtime.branch import _family

from defender.runtime.branch._family import (
    Family,
)


from defender import _yaml

from defender.learning.branch.preflight import _source_store as _source_store




_logger = logging.getLogger(__name__)




def served_systems(grant: Any) -> list[str]:
    """The systems a branch over this gather grant serves, sorted and once each.

    @owns served_systems — the manifest's `served_systems`, written by `_author` from this and
    nowhere else. M20: a system is served when the grant admits at least one read verb on it
    other than `health-check` (which reaches no data). The live grant still decides every query
    at query time (M21); this list governs the judge, lessons and the question-writer."""
    from defender.runtime.verb_dispositions import HEALTH_CHECK

    return sorted({system for system, verb, verb_class in grant.entries
                   if verb_class == "r" and verb != HEALTH_CHECK})




def branch_point_clock(source: Run, branch_message_id: int) -> Any:
    """T0 — the moment every sibling resumes into — derived once for the whole family so the
    siblings share one clock.

    With a session store this is `branch_point_time`. Without one it falls back to the newest
    mtime in the source run dir — the moment its evidence stopped, which is closer to a branch
    point than the launch time.
    """
    import datetime as _dt

    source_run_dir = source.run_dir
    store = _source_store(source)
    if store is not None:
        try:
            return branch.branch_point_time(store, Path(source_run_dir), branch_message_id, source_run=source)
        finally:
            store.close()
    newest = max(
        (p.stat().st_mtime for p in Path(source_run_dir).rglob("*") if artifact_file(p)),
        default=Path(source_run_dir).stat().st_mtime)
    return _dt.datetime.fromtimestamp(newest, tz=_dt.UTC).replace(microsecond=0)




def write_questioner_samples(episode: Episode, samples: Mapping[str, Any]) -> Path:
    """Write `samples.yaml`, the per-system samples document (`system_samples`), into the
    episode, so the judge is shown the same bytes the question-writer was even after the source
    run is pruned. Normalised to one `dict` before dumping, so the file never relies on a YAML
    loader's handling of repeated keys."""
    record = episode.samples
    record.write(_yaml.safe_dump(dict(samples), sort_keys=False, allow_unicode=True,
                                default_flow_style=False))
    return record.path




#: How many example answers one verb of one system keeps.
_SAMPLES_PER_VERB = 2


#: The most characters one example answer keeps; a longer one is cut, with a marker saying so.
_SAMPLE_CAP = 4000




def system_samples(source_run_dir: Path, served_systems: Sequence[str]) -> dict[str, dict]:
    """The samples document: real example answers from the source run's capture, keyed by
    served system and grouped per verb (O16, N26)."""
    from defender.learning.lead_repository import load_queries_report

    served = list(dict.fromkeys(served_systems))
    rows, unreadable = load_queries_report(Path(source_run_dir))
    if unreadable and not rows:
        reason = (f"the source run's queries table could not be read ({unreadable} unreadable "
                  "record(s)), so no answer was captured to show")
        return {system: {"unavailable": reason} for system in served}
    verbs: dict[str, dict[str, list[str]]] = {system: {} for system in served}
    lost: dict[str, int] = dict.fromkeys(served, 0)
    for row in rows:
        if row.system not in verbs or row.is_sentinel or row.exit_code != 0:
            continue
        kept = verbs[row.system].get(row.verb, [])
        if len(kept) >= _SAMPLES_PER_VERB:
            continue
        text = _sample_text(row.raw_ref)
        if text is None:
            lost[row.system] += 1
            continue
        verbs[row.system][row.verb] = [*kept, text]
    out: dict[str, dict] = {}
    for system in served:
        if not verbs[system] and lost[system]:
            out[system] = {"unavailable": f"{lost[system]} captured {system} answer(s) could "
                                          "not be read back from the source run"}
        else:
            out[system] = {"verbs": verbs[system]}
    return out




def _sample_text(source_answer: Path | None) -> str | None:
    """One captured answer (a file in the source run) as sample text, or `None` when it cannot
    be read as JSON."""
    if source_answer is None:
        return None
    text = read_text_soft(source_answer)[0]
    if text is None:
        return None
    payload, unreadable = load_json_artifact(text)
    if unreadable is not None:
        return None
    shown = json.dumps(payload, sort_keys=True, ensure_ascii=True, default=str)
    if len(shown) > _SAMPLE_CAP:
        shown = (f"{shown[:_SAMPLE_CAP]} ... [cut: the answer is {len(shown)} characters, the "
                 f"first {_SAMPLE_CAP} are shown]")
    return shown




def _author(  # noqa: PLR0913 — the step's inputs
    ns: argparse.Namespace, *, source: Run, episode: Episode, questioner: Any,
    lessons_dir: Path, served: Sequence[str],
) -> Family:
    """`Step.QUESTIONER`: the questioner authors the family, and it is validated before anything
    reads it.

    The launcher's derived fields (episode id, source run, branch point, T0, served
    systems) overwrite whatever the model returned, so a family cannot name a different
    source, or a different set of served systems, than it was authored from. One identity gate
    runs over the whole manifest before it is written."""
    from defender.knowledge._corpus import iter_lesson_paths
    from defender.learning.branch import questioner as questioner_mod
    from defender.learning.lead_repository import joined, questioner_leads

    source_run_dir = source.run_dir
    as_of = branch_point_clock(source, ns.branch_message_id)
    fences = _fence_count(source, ns.branch_message_id, as_of=as_of)
    leads = _joined_leads(source_run_dir, joined)
    samples = system_samples(source_run_dir, served)
    # Archived before the model call, so the judge sees exactly what the questioner saw.
    write_questioner_samples(episode, samples)
    # Paths only; `author_family` opens and screens them. A missing corpus is not a refusal
    # (N24): the launch goes on with no lessons, and says so.
    if not artifact_dir(Path(lessons_dir)):
        _logger.warning(f"the questioner lessons directory {lessons_dir} is not a directory; "
                        "the question-writer is shown no lessons this launch")
    lessons = iter_lesson_paths(lessons_dir)
    document = questioner_mod.author_family(
        source_run_dir=source_run_dir, episode_dir=episode.dir,
        invoke=questioner,
        leads=questioner_leads(leads),
        alert=branch.source_alert(source) or {},  # lint-run-records: ok — the branch package's reader of the source run's alert, not the episode's copy accessor
        frontier=questioner_mod.read_frontier(source_run_dir, fences_at=fences),
        served_systems=tuple(served),
        samples=samples,
        lessons=lessons,
    )
    # The source is named by its id alone (O1(c), declared change 9): no run-folder path is
    # written into the manifest.
    document.update({
        "episode_id": episode.dir.name,
        "source_run_id": str(source.id),
        "branch_message_id": ns.branch_message_id,
        "fences_at": fences,
        "as_of": as_of.isoformat().replace("+00:00", "Z"),
        # The tenant's served systems as this launch's grant decided them (`served_systems`):
        # the judge, lessons and question-writer read them from here (M21).
        "served_systems": list(served),
    })
    document, family = _family.accept_family(document)
    _family.write_family(episode, document)
    return family




def _fence_count(source: Run, branch_message_id: int, *, as_of: Any) -> int:
    """How many invlang fences the source run's document closed at the branch point.

    Through `branch.fence_count_at`: the document says how many fences the run ever wrote,
    and only the session says which had landed by the branch message. A source with no session
    store falls back to the document's total, as `branch_point_clock` falls back to its last
    mtime.
    """
    from defender.runtime.branch import BranchSpec, fence_count_at, source_session
    from defender.skills.invlang.parser import scan_fences

    path = source.documents.investigation.path
    if not artifact_file(path):
        return 0
    document = read_text_utf8(path)
    total = len(scan_fences(document).bodies)  # lint-row-drop: ok — a count of fences, not a read of their content; `fence_count_at` below answers whenever a session exists  # noqa: E501
    store = _source_store(source)
    if store is None:
        return total
    try:
        spec = BranchSpec(source_run_dir=source.run_dir, branch_message_id=branch_message_id,
                          as_of=as_of)
        return fence_count_at(store, source_session(store, spec, source_run=source), branch_message_id, document)
    finally:
        store.close()




def _joined_leads(source: Path, joined: Callable[[Path], list[Any]]) -> list[Any]:
    """`lead_repository.joined` over the source: the launcher's one read of the two tables.

    The surface already absorbs bad content; what can still raise is the host (a directory it
    refuses to walk), which yields a thinner prompt rather than no episode."""
    try:
        return joined(source)
    except Exception as unreadable:  # noqa: BLE001 — a fault at the read is a thinner prompt, not no episode
        _logger.warning(f"could not join the source's leads ({unreadable!r}); the questioner is "
                        "shown none")
        return []
