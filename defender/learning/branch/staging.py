"""Write a world's corpus onto the cluster, record it before it exists, and take it away again.

This is the only code in `defender/` that writes to the corpus engine. The read path
(`guard_outbound`, the four-endpoint read allowlist, the capture recorder) assumes no verb can
change the estate, and that stays true: the write door is a host-side object the launcher
constructs and hands to `stage_world`, `teardown` and `sweep`, and nothing in the verb registry
can reach it. That is why `write_door` lives here and not beside the adapters.

Three guards hold this module up:

* **No staging call targets a name a configured corpus pattern reaches.** Such a view would be
  read by the base run and every non-staging sibling — contamination posing as a measured
  difference.
* **No staging call targets a name outside `is_world_view` for its own token.** A sibling's
  alias and a view of an unconfigured corpus are well-formed but out of bounds; the world moves
  which name is admissible, never which corpus is.
* **Nothing staging creates is unrecorded when it is created.** The write door bypasses
  `guard_outbound` (the capture recorder), so `staged.yaml` is the only record of a cluster
  write. Each append is flushed and fsynced before the create is issued, so a launcher killed
  between the two leaves a record teardown and the next start's sweep can reconcile.

The reading half lives in the per-vendor stager under `estate/stagers/`, which retargets queries
at the names this module creates. It is reached from inside a run box on every served call; this
module only from the launcher on the host, and nothing that can dispatch the first can name the
second.
"""

from __future__ import annotations

import json
import os
import urllib.parse
from collections.abc import Iterable, Mapping, Sequence
from defender._model import model
from pathlib import Path
from typing import Any

import yaml

from defender import _yaml
from defender._clock import now_iso
from defender._episode_handle import Episode
from defender._episode_paths import LAYOUT, EpisodePaths
from defender._io import Bound, bind
from defender.runtime.branch._family import World, world_token_for
from defender.scripts.adapters._stub_transport import docker_exec_curl, split_status
from defender.scripts.adapters.elastic_adapter import (
    config_from as elastic_config_from,
    config_path as elastic_config_path,
)
from defender.scripts.adapters.confinement import (
    VIEW_NAMESPACE,
    _reach_ok,
    _view_stem,
    is_world_view,
    world_view,
)
from defender.scripts.adapters.faults import TransportFault

#: The suffix that turns a world's view name into the index its injected documents live in.
#: One spelling, because the alias is built over it and the guard is applied to it; two would
#: create an index no alias names.
INJECT_SUFFIX = ".inject"

#: The two kinds of thing staging creates. Recorded per row because teardown deletes them
#: through different cluster APIs.
KIND_INDEX = "index"
KIND_ALIAS = "alias"

#: Every clause type an exclusion predicate may carry. An allow-list over the query grammar
#: rather than a denylist of executable clauses (`script`, `runtime_mappings`, ...), which would
#: admit the next executable clause the engine ships. The predicate only selects documents for
#: removal, so anything outside this set is refused whether or not it is executable.
#:
#: `match_all` is admitted because an exclusion that removes the whole corpus is a legitimate
#: world to author; the review, not staging, must be the one to record and reject it.
ALLOWED_CLAUSES = frozenset({"term", "terms", "range", "match", "bool", "match_all"})

#: The keys a `bool` clause may carry. The four occurrence slots hold clauses and are walked;
#: the two tuning keys hold scalars and are not.
_BOOL_OCCURRENCES = ("must", "must_not", "should", "filter")
_BOOL_SCALARS = ("minimum_should_match", "boost")

#: The one status a DELETE may answer that is not a failure — see `_Door._call`.
_HTTP_NOT_FOUND = 404

#: What a staged name may be spelled with. Narrower than the engine allows: every name is
#: derived from an episode token, a world label and a configured pattern, so anything outside
#: this set reached the derivation from somewhere it should not have.
_NAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789.-_")
_EXPRESSION_CHARS = _NAME_CHARS | {"*"}


class StagingRefused(Exception):
    """A staging, teardown or sweep call this module will not make.

    Distinct from `ValueError` so the launcher can tell a refusal it must abort the episode on
    from an infrastructure fault. Every guard is a pre-flight check on the name, run before a
    connection is opened, so a caller meeting this knows nothing was half-created.
    """


# ---------------------------------------------------------------------------------------
# the namespace guard
# ---------------------------------------------------------------------------------------


def overlay_key_admitted(pattern: str, configured_patterns: Iterable[str]) -> bool:
    """May a world's overlay declare `pattern`?

    Uses the same `confinement._reach_ok` that `confine_index` and the staging guard use, so an
    admitted key is exactly a corpus the base run could read and one whose view `is_world_view`
    will admit. Two independent reach checks would drift: one direction silently drops a
    declared difference at staging, the other refuses a world over a configured corpus.
    `_reach_ok` already handles equality, so it is not restated here.
    """
    return any(_reach_ok(pattern, p) for p in configured_patterns)


# lint-dup: ok — a homonym: `_io.stage_name` mints a temp-file name for atomic writes; this one
# admits or refuses a cluster name, and the spec's tests name this symbol.
def stage_name(name: str, *, episode_token: str, world_id: str,  # lint-dup: ok — see above
               configured_patterns: Iterable[str], door: Any) -> str:
    """`name`, or the refusal every write to it would have been.

    The pre-flight check, asked once per name before any connection is opened. `door` is taken
    and unused so the guard's signature matches where the write would have run.

    A name a configured pattern still reaches is refused first, because that is the
    contamination case and calling it "not a world view" would send the operator to the token
    instead of the name. Anything outside `is_world_view` for this world's token (a sibling's
    alias, an unconfigured corpus, a name outside the namespace) is refused second.
    """
    patterns = tuple(configured_patterns)
    token = world_token_for(episode_token, world_id)
    reaching = [p for p in patterns if _reach_ok(name, p)]
    if reaching:
        raise StagingRefused(
            f"staging target {name!r} is still reached by the configured corpus pattern(s) "
            f"{reaching} — the base run and every sibling that does not stage this corpus "
            "would read this world's documents through it, which is contamination rather than "
            "a measured difference")
    if not is_world_view(name, patterns, token):
        raise StagingRefused(
            f"staging target {name!r} is not a world view of {token!r} over the configured "
            f"corpus patterns {patterns} — a world moves which NAME is admissible, never which "
            "corpus is, so a sibling's name and a view of an unconfigured corpus are both out "
            "of bounds")
    return name


def _derived_names(pattern: str, token: str) -> tuple[str, str]:
    """The `(view, injection index)` pair a world stages for one declared base pattern.

    Both are checked against `is_world_view` for the pattern they came from, which is stricter
    than `stage_name`: a pattern with no trailing wildcard (`logs-2026`) yields an admissible
    view but an injection index (`logs-2026.inject`) the pattern does not reach, so staging
    would refuse its own index and half-stage the world. Refused here, where the pattern can
    still be changed.
    """
    try:
        view = world_view(pattern, token)
    except ValueError as bad_name:      # ViewNameError — naming, not confinement
        raise StagingRefused(
            f"corpus pattern {pattern!r} cannot carry a world view for {token!r}: {bad_name}"
        ) from bad_name
    inject = f"{view}{INJECT_SUFFIX}"
    for name in (view, inject):
        if not is_world_view(name, (pattern,), token):
            raise StagingRefused(
                f"corpus pattern {pattern!r} derives {name!r}, which is not a world view of "
                f"{token!r} over that pattern — a pattern with no trailing wildcard names its "
                "alias and refuses its own injection index, so the world would stage an alias "
                "over the base corpus with its injected documents silently missing")
    return view, inject


def check_configured_patterns(patterns: Sequence[str]) -> tuple[str, ...]:
    """`patterns`, or the refusal every staged world in this episode would have hit.

    Asked at startup, before the questioner is paid for: configured patterns are deployment
    config, and a bad one (a bare `*`, or no trailing wildcard) breaks every staged world, so
    the operator should hear it while the config can still be fixed. Two patterns whose view
    stems collide are refused because one alias cannot serve two corpora.
    """
    # An empty tuple would pass every check below vacuously, and `_probe_cluster` skips it too,
    # so the episode id would be claimed and the questioner paid before every overlay key was
    # refused.
    if not patterns:
        raise StagingRefused(
            "this deployment configures no corpus pattern — a world is a difference on the "
            "corpora the deployment configures, so with none there is nothing any world could "
            "stage and no overlay key the manifest could admit. Name the corpus patterns in "
            "the elastic adapter's config (or in the environment) before branching")  # lint-shippable: ok — the per-vendor config the reader beside this one loads  # noqa: E501
    probe = "probe"
    stems: dict[str, str] = {}
    for pattern in patterns:
        _derived_names(pattern, probe)
        stem = _view_stem(pattern)
        if stem in stems:
            raise StagingRefused(
                f"configured corpus patterns {stems[stem]!r} and {pattern!r} trim to one view "
                f"stem {stem!r}, so one alias would have to serve two corpora")
        stems[stem] = pattern
    return tuple(patterns)


# ---------------------------------------------------------------------------------------
# the exclusion predicate gate
# ---------------------------------------------------------------------------------------


def check_exclusion_predicate(predicate: Any, *, where: str = "exclude") -> dict:
    """`predicate`, or a refusal naming the clause type that is not admitted.

    The predicate is model-authored and sent to the cluster as an alias filter, so the engine
    itself interprets it. Checked against `ALLOWED_CLAUSES` recursively, since an executable
    clause can hide inside `bool.must`. Anything unparseable (a string, a list, an empty
    mapping, a non-mapping clause body) is refused rather than forwarded: a create the cluster
    rejects against an already-recorded name is the failure the record does not tolerate.
    """
    if not isinstance(predicate, Mapping):
        raise StagingRefused(
            f"{where} is {type(predicate).__name__}, which is not a query document — an "
            f"exclusion predicate is a mapping of clause type to clause body: {predicate!r}")
    if not predicate:
        raise StagingRefused(
            f"{where} is an empty mapping, which names no clause at all — an exclusion that "
            "removes nothing is not a declared difference, and `null` is how a world says it "
            "excludes nothing")
    for clause, body in predicate.items():
        _check_clause(str(clause), body, where)
    return dict(predicate)


def _check_clause(clause: str, body: Any, where: str) -> None:
    if clause not in ALLOWED_CLAUSES:
        raise StagingRefused(
            f"{where} carries the clause type {clause!r}, which is not one of the admitted "
            f"document-matching clauses {sorted(ALLOWED_CLAUSES)} — the predicate selects "
            "documents for removal at staging and is never a search interface, so a clause "
            "outside that set is refused whether or not it is executable")
    if not isinstance(body, Mapping):
        raise StagingRefused(
            f"{where}.{clause} is {type(body).__name__} rather than a mapping — a clause body "
            f"this module cannot read is one the cluster would interpret its own way: {body!r}")
    if clause == "bool":
        _check_bool(body, f"{where}.bool")
    if clause == "terms":
        _check_terms(body, f"{where}.terms")


def _check_terms(body: Mapping, where: str) -> None:
    """A `terms` clause must match against a list of values, never another index.

    The mapping form (`{"field": {"index": ..., "id": ..., "path": ...}}`) is a terms lookup:
    the cluster reads a term set out of an arbitrary index at query time. Inside a staged
    alias's filter that is a cross-index read the verb allowlist never granted, and the world's
    model can observe its result through which documents survive. `boost` is a scalar tuning
    knob and is skipped.
    """
    for field_name, value in body.items():
        if str(field_name) == "boost":
            continue
        if not isinstance(value, (list, tuple)):
            raise StagingRefused(
                f"{where}.{field_name} is {type(value).__name__} rather than a list of values "
                "— a mapping here is the terms LOOKUP form, which reads a term set out of "
                "another index at query time. That is a cross-index read from inside the "
                "alias filter, and the world's own model can observe its result")
        bad = [v for v in value if not isinstance(v, (str, int, float, bool)) and v is not None]
        if bad:
            raise StagingRefused(
                f"{where}.{field_name} holds non-scalar term(s) {bad!r} — a terms clause "
                "matches values, and a document here is a clause body this module cannot read")


def _check_bool(body: Mapping, where: str) -> None:
    unknown = sorted(set(body) - set(_BOOL_OCCURRENCES) - set(_BOOL_SCALARS))
    if unknown:
        raise StagingRefused(
            f"{where} names {unknown}, which is not one of a boolean clause's occurrence slots "
            f"{list(_BOOL_OCCURRENCES)}")
    for slot in _BOOL_OCCURRENCES:
        if slot not in body:
            continue
        nested = body[slot]
        # A single clause may be bare or a one-element list; both are walked so the shorthand
        # is not a way past the gate.
        for entry in (nested if isinstance(nested, list) else [nested]):
            check_exclusion_predicate(entry, where=f"{where}.{slot}")


# ---------------------------------------------------------------------------------------
# the write-ahead record
# ---------------------------------------------------------------------------------------


def staged_path(episode_dir: Path) -> Path:
    return EpisodePaths(episode_dir).staged


def read_staged(bound: Bound) -> list[dict] | None:
    """Every row of the staging record in written order; `None` when nothing is at the name,
    `[]` for a present but empty (or comment-only) document.

    An unparseable record is refused rather than guessed at: acting on half of it means deleting
    a name this code did not write, or leaving a live alias under a token the next episode will
    reuse. Read through the bound reader's screen because the episode dir is writable by a
    sibling's box; a link planted at the name is refused rather than read as empty, which would
    have teardown sweep nothing.
    """
    rec = bound.read(LAYOUT.staged)
    if rec.absent:
        return None
    if rec.text is None:
        raise StagingRefused(f"{LAYOUT.staged} is refused: {rec.reason}")
    try:
        rows = _yaml.safe_load(rec.text)
    except yaml.YAMLError as bad:
        raise StagingRefused(
            f"{LAYOUT.staged} does not parse ({bad}) — acting on a staging record this code "
            "cannot read means deleting a name it did not write, or leaving one it did") from bad
    if rows is None:
        return []
    if not isinstance(rows, list) or any(not isinstance(r, dict) for r in rows):
        raise StagingRefused(
            f"{LAYOUT.staged} is not a list of rows — the record is append-only and every "
            "row names one created thing")
    return list(rows)


def record_staged(episode: Episode, row: Mapping[str, Any]) -> dict:
    """Append one row to `staged.yaml`, on disk before returning.

    This file is the only record that a cluster write was about to happen, so a row still in a
    userspace buffer when the launcher is killed is a live name nothing on disk names: teardown
    would miss it and the next sweep would refuse the episode. Append-only — rewriting the
    whole list would open a window where the record is shorter than the cluster.
    """
    entry = yaml.safe_dump([dict(row)], sort_keys=True, default_flow_style=False)
    # The durable append: the record and its entry in the episode dir are synced before this
    # returns (the episode dir's own entry was synced when `Episode.create` made it).
    episode.staged.append_durable(entry)
    return dict(row)


def _row(*, world: str, name: str, kind: str, derived_from: str) -> dict:
    return {"world": world, "name": name, "kind": kind, "derived_from": derived_from,
            "created_at": now_iso()}


# ---------------------------------------------------------------------------------------
# staging one world
# ---------------------------------------------------------------------------------------


@model(frozen=True)
class _Plan:
    """One declared base pattern, resolved into the two names it stages."""

    pattern: str
    view: str
    inject: str
    docs: list[dict]
    exclude: dict | None


def _plan_world(world: World, *, token: str,
                configured_patterns: Sequence[str]) -> list[_Plan]:
    """Everything this world would stage, validated before a single connection is opened.

    Validating the whole world first means a bad second pattern cannot leave the first already
    created for a world that was never admitted; every refusal here happens with
    `door.connections == 0`.
    """
    plans: list[_Plan] = []
    stems: dict[str, str] = {}
    # lint-shippable: ok — the vendor name is `_family.Overlay`'s own field, read rather than
    # restated here.
    for pattern, entry in world.overlay.elastic.items():  # lint-shippable: ok — the manifest's own field
        if not overlay_key_admitted(pattern, configured_patterns):
            raise StagingRefused(
                f"overlay declares the base pattern {pattern!r}, which no configured corpus "
                f"pattern {tuple(configured_patterns)} reaches — a world is a difference on "
                "the corpora this deployment configures, and staging one it does not would "
                "write documents no run reads")
        stem = _view_stem(pattern)
        if stem in stems:
            raise StagingRefused(
                f"overlay keys {stems[stem]!r} and {pattern!r} trim to one view stem {stem!r}, "
                "so one alias would have to serve two declared corpora — a query for the "
                "narrow corpus would silently read the wide one's documents")
        stems[stem] = pattern
        view, inject = _derived_names(pattern, token)
        exclude = None if entry.exclude is None else check_exclusion_predicate(
            # lint-shippable: ok — `where` names the manifest path an operator must edit, so it
            # spells the manifest's own field name.
            entry.exclude, where=f"overlay.elastic[{pattern!r}].exclude")  # lint-shippable: ok — the manifest path an operator edits
        plans.append(_Plan(pattern=pattern, view=view, inject=inject,
                           docs=[dict(d) for d in entry.inject], exclude=exclude))
    return plans


def stage_world(world: World, *, episode: Episode, episode_token: str,
                configured_patterns: Sequence[str], door: Any) -> list[dict]:
    """Create this world's corpus on the cluster, recording every name before it exists.

    Per declared base pattern: an injection index holding the world's documents, then an alias
    over the pattern's concrete indices plus that index, carrying the exclusion as its filter —
    `base − exclude + inject` in one name, so a `STATS … BY …` over the view is correct by
    construction.

    Ordering is the invariant: each name is appended to `staged.yaml` and fsynced before its
    create is issued, so a failed create, a cluster refusal or a kill in between all leave the
    name recorded for teardown and sweep. A world with no staged difference creates nothing.
    """
    token = world_token_for(episode_token, world.world_id)
    plans = _plan_world(world, token=token, configured_patterns=configured_patterns)
    for plan in plans:
        for name in (plan.inject, plan.view):
            stage_name(name, episode_token=episode_token, world_id=world.world_id,
                       configured_patterns=configured_patterns, door=door)
    rows: list[dict] = []
    for plan in plans:
        rows.append(record_staged(episode, _row(
            world=token, name=plan.inject, kind=KIND_INDEX, derived_from=plan.pattern)))
        door.create_index(plan.inject, docs=plan.docs)
        rows.append(record_staged(episode, _row(
            world=token, name=plan.view, kind=KIND_ALIAS, derived_from=plan.pattern)))
        over = [*door.resolve(plan.pattern), plan.inject]
        # The exclusion applies to the base only; the injection index is exempt.
        door.create_alias(plan.view, over=over, filter=plan.exclude,
                          unfiltered=(plan.inject,))
    return rows


# ---------------------------------------------------------------------------------------
# teardown and sweep
# ---------------------------------------------------------------------------------------


def teardown(episode: Episode, *, door: Any) -> list[str]:
    """Remove exactly the names `staged.yaml` records, newest first, verifying each is gone.

    Newest first because the record is in dependency order (index before the alias spanning
    it), so no alias is ever left over a deleted member. Only recorded names are touched —
    teardown never lists or globs. A delete that returns but leaves the name present is the
    failure that matters (the next episode reusing the token finds a live alias), so every
    failure is written into the review record (or, when that record is refused, carried in the
    raised failure) and then raised.
    """
    rows = read_staged(episode.view()) or []
    failures: list[dict] = []
    for row in reversed(rows):
        name = str(row.get("name") or "")
        if not name:
            failures.append({"name": None, "detail": f"staging row names nothing: {row!r}"})
            continue
        try:
            door.delete(name)
            if door.exists(name):
                failures.append({"name": name, "detail": "still present after delete"})
        except Exception as bad:  # noqa: BLE001 — every fault is collected and raised below
            failures.append({"name": name, "detail": f"{type(bad).__name__}: {bad}"})
    if failures:
        unrecorded = _record_teardown_failure(failures, episode)
        raise StagingRefused(
            "teardown did not verify every staged name gone: "
            + "; ".join(f"{f['name']} ({f['detail']})" for f in failures) + unrecorded)
    return [str(r.get("name")) for r in rows]


def _record_teardown_failure(failures: list[dict], episode: Episode) -> str:
    """Put the failure in the review record before raising it; `""`, or — when the record is
    refused — the sentence the raised failure carries instead, so the names are never lost.

    The names are still live on the cluster and the review's reader is who has to remove them.
    Merged rather than rewritten, because the review step has already written its verdicts.
    """
    try:
        merge_review(episode, "teardown",
                     {"ok": False, "failures": failures,
                      "names": [f["name"] for f in failures], "at": now_iso()})
    except StagingRefused as unmerged:
        return f" — and the review record was not updated with them ({unmerged})"
    return ""


def merge_review(episode: Episode, key: str, block: dict) -> None:
    """Merge one block into the review record, leaving everything else it holds.

    The single merger for `review.yaml` outside the review itself, shared by teardown and
    `cli._record_episode_outcome` so both write the file with one serialisation.

    Read through the episode's view and replaced through its handle. An absent record starts
    empty, and one that does not parse as a mapping is replaced (as it always was). A REFUSED
    record — a link, hard link or other non-plain entry at the name, or undecodable bytes — is
    `StagingRefused` and is left exactly as it is: replacing it would drop whatever it holds.
    """
    rec = episode.view().read(LAYOUT.review)
    if rec.text is None and not rec.absent:
        raise StagingRefused(
            f"{LAYOUT.review} is refused ({rec.reason}); the {key!r} block was not merged, "
            "since replacing a record this code cannot read drops whatever it holds")
    doc: dict[str, Any] = {}
    if rec.text is not None:
        try:
            loaded = _yaml.safe_load(rec.text)
        except yaml.YAMLError:
            loaded = None
        if isinstance(loaded, dict):
            doc = loaded
    held = doc.get(key)
    if isinstance(held, dict):
        held.update(block)
    else:
        doc[key] = dict(block)
    episode.review.write(
        yaml.safe_dump(doc, sort_keys=False, allow_unicode=True, default_flow_style=False))


def sweep_glob(episode_token: str) -> str:
    """The one glob this episode's namespace answers to.

    The token is injective over episode ids, so every name under it is this episode's; any
    wider and the sweep reaches a concurrent episode's live corpus. The prefix is imported from
    confinement so the glob follows `world_view` if the namespace spelling changes.
    """
    return f"{VIEW_NAMESPACE}-{episode_token}.*"


def sweep(episode_dir: Path, *, episode_token: str, door: Any) -> list[str]:
    """Remove what an earlier death left behind in this episode's own token namespace.

    A killed launcher runs no teardown, so this is the next start's first act. It probes before
    listing because an unreachable cluster's empty listing looks like a clean namespace; the
    probe fails loudly instead. A name under the token that `staged.yaml` does not hold was not
    written by this code, so the whole listing is validated and refused before anything is
    deleted.
    """
    glob = sweep_glob(episode_token)
    door.count(glob)
    found = list(door.list_names(glob))
    with bind(Path(episode_dir)) as bound:
        rows = read_staged(bound) or []
    recorded = {str(r.get("name")) for r in rows}
    unrecorded = sorted(n for n in found if n not in recorded)
    if unrecorded:
        raise StagingRefused(
            f"the sweep found {unrecorded} under {glob!r}, which the staging record does not "
            "name — that is a name this code did not write, and removing it would be guessing")
    removed: list[str] = []
    # Newest-first over the record, as `teardown` does — never `sorted(reverse=True)`. An alias
    # name is a prefix of its injection index (`wv-<token>-logs-` vs `wv-<token>-logs-.inject`),
    # so reverse-lexicographic order would delete the index while the alias still spans it.
    live = set(found)
    for name in (str(r.get("name") or "") for r in reversed(rows)):
        if name not in live:
            continue
        live.discard(name)
        door.delete(name)
        if door.exists(name):
            raise StagingRefused(
                f"the sweep deleted {name!r} and it is still present — the episode's namespace "
                "cannot be reused while an earlier death's names are live in it")
        removed.append(name)
    return removed


# ---------------------------------------------------------------------------------------
# the write door
# ---------------------------------------------------------------------------------------


def _checked(value: str, allowed: frozenset[str], what: str) -> str:
    """`value`, or a refusal if any character is outside the derived-name alphabet.

    Names reach the transport as discrete URL arguments, never a shell string, so this is not
    guarding a live injection; it is here so the boundary does not depend on the transport.
    """
    if not value or not isinstance(value, str):
        raise StagingRefused(f"{what} is empty, which names nothing on the cluster")
    illegal = sorted({c for c in value if c not in allowed})
    if illegal:
        raise StagingRefused(
            f"{what} {value!r} carries {illegal}, which a derived staging name never holds — "
            "every name this door sends is built from an episode token, a world label and a "
            "configured corpus pattern, so a character outside that alphabet is a value that "
            "reached the derivation from somewhere it should not have")
    return value


@model(frozen=True)
class _Door:
    """The cluster's write surface, as an object the launcher holds and no verb can name.

    Separate from `elastic_adapter`'s HTTP helper, which is confined to four read endpoints and
    carries the capture recorder. This reaches `docker_exec_curl` directly with PUT and DELETE,
    which is why `staged.yaml` must be durable before every create. `transport` is injected so
    tests drive the real door over a recording transport.
    """

    ctx: Any
    container: str
    transport: Any
    base_url: str
    timeout_sec: int
    insecure: bool
    auth: str | None

    # -- the transport ------------------------------------------------------------------
    def _call(self, method: str, path: str, *, body: dict | None = None,
              absent_ok: bool = False) -> tuple[int, dict[str, Any]]:
        """One request, and the only reading of its status this module admits.

        An unparseable status is a failure. `split_status` answers `("", <whole body>)` when
        curl's trailing status line is missing, and reading that as success would have the
        review measure a world that was never staged. Anything but a 2xx integer is refused.
        """
        url = f"{self.base_url.rstrip('/')}{path}"
        returncode, stdout, stderr = self.transport(
            self.ctx, self.container, url, method=method, body=body,
            timeout_sec=self.timeout_sec, insecure=self.insecure, auth=self.auth)
        if returncode != 0:
            raise TransportFault(
                f"docker exec curl failed ({returncode}) for {method} {url}: {stderr.strip()}")
        payload, status = split_status(stdout)
        if not status.isdigit():
            raise StagingRefused(
                f"{method} {url} answered with no parseable HTTP status line — an unreadable "
                "status is a FAILURE and never a success: the name is already recorded, and "
                "believing a failed create succeeded stages a world that does not exist")
        code = int(status)
        # 404 is success only for a delete that asked for it: the name being gone is the goal.
        # A 404 on a create or read stays a failure.
        if absent_ok and code == _HTTP_NOT_FOUND:
            return code, {}
        if not 200 <= code < 300:
            raise StagingRefused(
                f"{method} {url} answered HTTP {code}: {payload.strip()[:200]}")
        # Every response this door reads is a JSON object; anything else is answered `{}` so
        # `resolve` and `count` never receive an unchecked `Any`.
        if not payload.strip():
            return code, {}
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError:
            return code, {}
        return code, parsed if isinstance(parsed, dict) else {}

    @staticmethod
    def _quoted(value: str) -> str:
        return urllib.parse.quote(value, safe="")

    # -- the surface --------------------------------------------------------------------
    def create_index(self, name: str, *, docs: list[dict]) -> None:
        """Create `name` and put `docs` in it, one document per request.

        `_id` goes in the URL, not the body: the cluster rejects a source object carrying that
        metadata field.
        """
        _checked(name, _NAME_CHARS, "index name")
        self._call("PUT", f"/{self._quoted(name)}")
        for doc in docs:
            body = {k: v for k, v in doc.items() if k != "_id"}
            doc_id = doc.get("_id")
            if doc_id is None:
                self._call("POST", f"/{self._quoted(name)}/_doc?refresh=true", body=body)
            else:
                self._call(
                    "PUT",
                    f"/{self._quoted(name)}/_doc/{self._quoted(str(doc_id))}?refresh=true",
                    body=body)

    def create_alias(  # noqa: A002 — `filter` is the door's shape, and the cluster's
            self, name: str, *, over: list[str], filter: dict | None,
            unfiltered: Sequence[str] = ()) -> None:
        """Point `name` at every index in `over`, carrying `filter` as its exclusion.

        One `_aliases` action list, so the alias appears whole or not at all. The predicate is
        `must_not`-wrapped because the world declares what it removes and an alias filter says
        what it keeps.

        `unfiltered` members are exempt from the exclusion, giving `base − exclude + inject`
        rather than `(base + inject) − exclude`: the exclusion describes the corpus the world
        branched from, and applied to the injection index it would delete the world's own
        documents (a `match_all` exclusion would serve nothing at all).
        """
        _checked(name, _NAME_CHARS, "alias name")
        exempt = set(unfiltered)
        actions = [{"add": {"index": _checked(index, _EXPRESSION_CHARS, "alias member"),
                            "alias": name,
                            **({} if filter is None or index in exempt
                               else {"filter": {"bool": {"must_not": [filter]}}})}}
                   for index in over]
        self._call("POST", "/_aliases", body={"actions": actions})

    def delete(self, name: str) -> None:
        """Remove `name`, whichever of alias or index it is (asked of the cluster).

        Already absent counts as done (`absent_ok`): the record is written ahead of every
        create, so a failed create leaves a row for a name that never existed, and deleting an
        index can remove its alias implicitly. Teardown's `exists` check verifies the outcome.
        """
        _checked(name, _NAME_CHARS, "name to delete")
        if self._is_alias(name):
            self._call("DELETE", f"/*/_alias/{self._quoted(name)}", absent_ok=True)
            return
        self._call("DELETE", f"/{self._quoted(name)}", absent_ok=True)

    def exists(self, name: str) -> bool:
        """Is `name` still on the cluster?"""
        _checked(name, _NAME_CHARS, "name")
        found = self._resolved(name)
        # All three classes, so a name held in a form this door did not create still reads as
        # present rather than verified gone.
        return bool(found["indices"] or found["aliases"] or found["data_streams"])

    def _is_alias(self, name: str) -> bool:
        return name in self._resolved(name)["aliases"]

    def list_names(self, glob: str) -> list[str]:
        """Every index and alias under `glob` — what the sweep reconciles against the record."""
        _checked(glob, _EXPRESSION_CHARS, "namespace glob")
        found = self._resolved(glob)
        return sorted(found["indices"] + found["aliases"])

    def count(self, index: str, *, query: dict | None = None) -> int:
        """How many documents `index` holds, optionally under `query`.

        `_count` must never be added to the adapter's read-endpoint allowlist: this is a
        host-side measurement, and on the model-reachable door it would be a cardinality oracle
        over the whole corpus.
        """
        _checked(index, _EXPRESSION_CHARS, "index expression")
        body = None if query is None else {"query": query}
        _code, payload = self._call("POST", f"/{self._quoted(index)}/_count", body=body)
        found = payload.get("count", 0)
        return int(found) if isinstance(found, int) else 0

    def resolve(self, pattern: str) -> list[str]:
        """The concrete indices `pattern` names right now — what an alias is built over.

        Concrete rather than the pattern, so the record of which indices a view spanned makes
        the staged corpus reproducible.
        """
        _checked(pattern, _EXPRESSION_CHARS, "corpus pattern")
        return sorted(self._resolved(pattern)["indices"])

    # -- the one read the door needs ----------------------------------------------------
    def _resolved(self, expression: str) -> dict[str, list[str]]:
        """What `expression` names, in the three classes `_resolve/index` answers.

        Data streams are included because a stream-backed corpus has hidden backing indices
        that don't match the pattern; without them `exists` and `delete` read a live name as
        absent.
        """
        _code, payload = self._call("GET", f"/_resolve/index/{self._quoted(expression)}")
        return {key: [str(e.get("name")) for e in payload.get(key, [])
                      if isinstance(e, dict) and e.get("name")]
                for key in ("indices", "aliases", "data_streams")}



def write_door(*, ctx: Any = None, container: str, transport: Any = docker_exec_curl,
               base_url: str = "http://localhost:9200", timeout_sec: int = 30,
               insecure: bool = False, auth: str | None = None) -> _Door:
    """The cluster's write door — host-side, and reachable from this module alone.

    Adding writes to the read adapter's HTTP helper would widen the door every model-dispatched
    verb resolves through. Instead the launcher constructs this and hands it to `stage_world` /
    `teardown` / `sweep`, so no model-dispatched call has a route to a cluster write.
    """
    return _Door(ctx=ctx, container=container, transport=transport, base_url=base_url,
                 timeout_sec=timeout_sec, insecure=insecure, auth=auth)


#: The `config.env` keys this door reads. Named rather than derived from the file's contents so
#: an environment override applies even when the file omits the key.
_DOOR_CONFIG_KEYS = ("ELASTICSEARCH_URL", "ELASTIC_SSL_VERIFY")  # lint-shippable: ok — the per-vendor config keys the read adapter loads  # noqa: E501


@model(frozen=True)
class _HostContext:
    """The two fields `docker_exec_curl` reads off a context, for a caller that has no run.

    The launcher opens the door before any episode dir, run dir or `VerbContext` exists, so
    only `env` and `defender_dir` are supplied; inventing a run identity would be worse than
    having none.
    """

    env: dict[str, str]
    defender_dir: Path
    #: The episode tenant's `settings/` folder, where the door reads the cluster's address.
    #: Resolved by the launcher, never looked up here.
    settings_dir: Path


def host_context(settings_dir: Path) -> _HostContext:
    """The launcher's context for the door, before any run exists: the process env, the code
    tree the transport's child env is rooted in, and the episode tenant's settings folder."""
    from defender._paths import PATHS

    return _HostContext(env=dict(os.environ), defender_dir=PATHS.defender_dir,
                        settings_dir=Path(settings_dir))


def write_door_from_env(ctx: Any, *, transport: Any = docker_exec_curl) -> _Door:
    """The write door this deployment's configuration describes.

    One reading of where the cluster is, shared by sweep, staging and teardown, using the same
    `config.env` and env-var precedence as the read adapter — so staging and the siblings' reads
    always address the same cluster. The credential is expanded inside the container, so the
    secret never appears on the host's argv.

    `ctx` is a `VerbContext` or `host_context(...)`; config is read only from its
    `settings_dir`.
    """
    # `is not None`, not `or`: `_HostContext(env={}, ...)` is the normal hermetic construction,
    # and treating an empty env as absent would read the config from the real shell while the
    # transport uses the empty one — two different clusters.
    ctx_env = getattr(ctx, "env", None)
    env: dict[str, str] = dict(os.environ if ctx_env is None else ctx_env)
    # The read adapter's own parse and precedence. `expected` lets the environment supply a key
    # the file lacks; otherwise a trimmed `config.env` would stage on the default cluster while
    # siblings read the one the operator named.
    values = elastic_config_from(
        elastic_config_path(Path(ctx.settings_dir)), env, expected=_DOOR_CONFIG_KEYS)
    return write_door(
        ctx=ctx,
        container=env.get("SOC_PLAYGROUND_ES_CONTAINER", "elasticsearch"),  # lint-shippable: ok — the container the read adapter execs into
        transport=transport,
        base_url=values.get("ELASTICSEARCH_URL", "https://localhost:9200"),  # lint-shippable: ok — the per-vendor config key
        insecure=values.get("ELASTIC_SSL_VERIFY", "false").lower() != "true",  # lint-shippable: ok — the per-vendor config key
        auth="elastic:${ELASTIC_PASSWORD}")  # lint-shippable: ok — expanded inside the container, as the read path does it



#: The launcher's name for the door when the caller injected none. An alias, not a second
#: constructor, so the two can never read the config differently.
default_door = write_door_from_env


__all__ = [
    "ALLOWED_CLAUSES",
    "INJECT_SUFFIX",
    "KIND_ALIAS",
    "KIND_INDEX",
    "StagingRefused",
    "check_configured_patterns",
    "check_exclusion_predicate",
    "default_door",
    "write_door_from_env",
    "overlay_key_admitted",
    "read_staged",
    "record_staged",
    "stage_name",
    "stage_world",
    "staged_path",
    "sweep",
    "sweep_glob",
    "teardown",
    "write_door",
]
