"""Write a world's corpus onto the cluster, record it before it exists, and take it away again.

This is the FIRST code in `defender/` that writes to the corpus engine. Everything the read
path has — `guard_outbound`, the four-endpoint read allowlist, the capture recorder that rides on
it — is built around the premise that no verb can change the estate, and that premise stays
true: the door below is a host-side object the launcher constructs and hands to `stage_world`,
`teardown` and `sweep`, and nothing in the registry every model-dispatched verb resolves
through can reach it. That is why `write_door` lives HERE and not beside the adapters.

Three negative universals hold this file up, and each one is a guard rather than a convention.

* **No staging call targets a name a configured corpus pattern reaches.** A view the base
  pattern still matches is a view the base run and every non-staging sibling read this world's
  documents through — contamination dressed up as a measured difference, which is the one
  failure the whole per-world namespace exists to prevent.
* **No staging call targets a name outside `is_world_view` for its OWN token.** A sibling's
  alias and a view of a corpus this run never configured are both well-formed names in the
  namespace and both out of bounds; the world moves which NAME is admissible, never which
  corpus is.
* **Nothing staging creates is unrecorded at the moment it is created.** The write door
  bypasses `guard_outbound`, which is also the capture recorder, so `staged.yaml` is the SOLE
  record that a cluster write happened. The append is therefore made DURABLE — written,
  flushed and fsynced — before the create is issued, not merely ordered before it: a launcher
  killed between the two must leave a record teardown and the next start's sweep can
  reconcile, and a buffered line is not that.

The reading half of the same mechanism lives in the per-vendor stager under `estate/stagers/`,
which retargets a query at the names this module creates. The two are separate modules: the reader
is reached on every served call from inside a run box, the writer only from the launcher on
the host, and nothing that can dispatch the first can name the second.
"""

from __future__ import annotations

import json
import os
import urllib.parse
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from defender._clock import now_iso
from defender._io import guarded_mkdir, open_guarded, write_guarded
from defender.runtime.branch._family import World, world_token_for
from defender.scripts.adapters._stub_transport import docker_exec_curl, split_status
from defender.scripts.adapters.confinement import (
    _reach_ok,
    _view_stem,
    is_world_view,
    world_view,
)
from defender.scripts.adapters.faults import TransportFault

#: The suffix that turns a world's view name into the index its injected documents live in.
#: ONE spelling, because the alias is built OVER it and the guard is applied TO it: two
#: spellings would create an index no alias names, and the documents would be written into a
#: corpus nobody reads while every row still read honestly.
INJECT_SUFFIX = ".inject"

#: The staging record's filename under the episode dir.
STAGED_FILENAME = "staged.yaml"

#: The review record a teardown failure is reported into.
REVIEW_FILENAME = "review.yaml"

#: The two kinds of thing staging creates. Recorded per row because teardown deletes them
#: through different cluster APIs and a row that cannot say which is a row teardown has to
#: guess at.
KIND_INDEX = "index"
KIND_ALIAS = "alias"

#: Every clause type an exclusion predicate may carry — an ALLOW-list over the query grammar
#: rather than a census of the executable clause names, and the difference is the whole point.
#: A census of `script`/`script_score`/`runtime_mappings` admits every clause type nobody
#: thought of, including the next executable one the engine ships; an allow-list admits only
#: what expresses DOCUMENT MATCHING, which is all a staging exclusion ever needs to say. The
#: predicate selects documents for removal at staging time and is never a search interface, so
#: a clause type outside this set is refused whether or not it is executable.
#:
#: `match_all` is here for a reason a five-member set does not serve: an exclusion that removes
#: the whole corpus is a legitimate world to AUTHOR and a rejected one to REVIEW, and without
#: an admissible spelling it would be refused at staging and never reach the review that must
#: record it.
ALLOWED_CLAUSES = frozenset({"term", "terms", "range", "match", "bool", "match_all"})

#: The keys a `bool` clause may carry. The four occurrence slots hold CLAUSES and are walked;
#: the two tuning keys hold scalars and are not.
_BOOL_OCCURRENCES = ("must", "must_not", "should", "filter")
_BOOL_SCALARS = ("minimum_should_match", "boost")

#: What a name staging writes may be spelled with. Deliberately narrower than what
#: the engine tolerates: every name this module sends is DERIVED — an episode token, a world
#: label and a configured corpus pattern — so anything outside this set is a value that reached
#: the derivation from somewhere it should not have, and refusing is cheaper than reasoning
#: about which layer would have escaped it.
_NAME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyz0123456789.-_")
_EXPRESSION_CHARS = _NAME_CHARS | {"*"}


class StagingRefused(Exception):
    """A staging, teardown or sweep call this module will not make.

    Its own class, and never a bare `ValueError`: the launcher distinguishes a refusal it must
    abort the episode on from an infrastructure fault it may report differently, and the three
    negative universals in the module docstring are all discharged by raising THIS. A refusal
    also costs the cluster nothing — every guard here is a pre-flight check on the NAME, run
    before a connection is opened — so a caller meeting it knows nothing was half-created.
    """


# ---------------------------------------------------------------------------------------
# the namespace guard
# ---------------------------------------------------------------------------------------


def overlay_key_admitted(pattern: str, configured_patterns: Iterable[str]) -> bool:
    """May a world's overlay declare `pattern`?

    THE SAME CALL the staging guard makes, not a second spelling that happens to agree.
    `confinement._reach_ok` is what `confine_index` holds every unstaged index expression to,
    so an overlay key admitted here is exactly a corpus the base run could itself have read —
    and a key this returns `True` for is one whose view `is_world_view` will admit. Two
    independently-written reach checks would drift in the direction nobody notices: a key the
    gate admits and the guard refuses drops a whole declared difference at staging time, while
    a key the gate refuses and the guard would have admitted refuses a world for a corpus the
    run configures.

    `_reach_ok(pattern, p)` already answers `True` on equality, so the equality case is not
    restated here — restating it is how the two spellings start.
    """
    return any(_reach_ok(pattern, p) for p in configured_patterns)


# lint-dup: ok — a homonym, not a duplicate. `_io.stage_name` mints an unpredictable TEMP FILE
# name for the atomic-write lane; this one admits or refuses a CLUSTER name. Nothing is shared,
# and the spec's tests name this symbol, so the two live side by side under one word.
def stage_name(name: str, *, episode_token: str, world_id: str,  # lint-dup: ok — see above
               configured_patterns: Iterable[str], door: Any) -> str:
    """`name`, or the refusal every write to it would have been.

    THE pre-flight check, asked once per name and before any connection is opened, which is why
    `door` is taken and never used: the signature says the guard runs where the write would
    have, and a refusal that had already reached the cluster would leave a name recorded and
    half-created.

    Two conditions, in the order that produces the honest message. A name a configured pattern
    still REACHES is refused first, because that is the contamination case and naming it as
    "not a world view" would send the operator looking at the token instead of at the name. A
    name outside `is_world_view` for THIS world's token is refused second: a sibling's alias, a
    view of a corpus this run never configured, and anything that is not in the namespace at
    all all land here.
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

    BOTH are held to `is_world_view` against the pattern they were derived FROM, and that is a
    stricter question than the one `stage_name` asks. `_view_stem` trims a trailing `*` and
    nothing else, so a pattern with no trailing wildcard (`logs-2026`) yields a view whose stem
    IS the pattern — admissible — and an injection index whose stem is `logs-2026.inject`,
    which the pattern does not reach. Staging's own guard would then refuse the index staging
    must create, and the world would be half-staged: an alias over a base corpus with the
    injected documents silently missing. Refused here, where the pattern can still be changed.
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

    ASKED AT STARTUP, before the questioner is paid for. A configured corpus pattern is
    deployment configuration rather than model output, and the two ways it breaks the name
    algebra break it for the whole episode: a bare `*` reduces to nothing an alias can be named
    by, and a pattern with no trailing wildcard names an alias whose injection index the guard
    then refuses. Either way no staged world could ever exist, so the refusal belongs
    where the operator can still fix the config — not three model calls later.

    Two patterns whose view stems collide are refused for the same reason `stage_world` refuses
    two overlay keys that collide: one alias cannot serve two corpora.
    """
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

    MODEL-AUTHORED and sent to the cluster as an alias filter, which makes it the one piece of
    this design's data that the search engine itself will interpret. `script`, `script_score` and
    `runtime_mappings` are the clause types that carry code, but refusing exactly those three
    is a census and a census only names what somebody thought of — so this is an ALLOW-list
    over the grammar instead, and a clause type outside it is refused whether or not it is
    executable.

    WALKED RECURSIVELY, because a top-level key census does not reach
    `{"bool": {"must": [{"script": ...}]}}` — the same executable clause one level down, where
    the alias filter would still run it.

    Unparseable is refused rather than forwarded. A bare string, a list, an empty mapping and a
    clause whose body is not a mapping are all things the engine would interpret its own way
    or reject at create time, and a create refused by the cluster against a write-ahead-recorded
    name is the direction the record does not tolerate.
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
        # A single clause is spelled either bare or as a one-element list; both are walked, so
        # the shorthand is not a way past the gate.
        for entry in (nested if isinstance(nested, list) else [nested]):
            check_exclusion_predicate(entry, where=f"{where}.{slot}")


# ---------------------------------------------------------------------------------------
# the write-ahead record
# ---------------------------------------------------------------------------------------


def staged_path(episode_dir: Path) -> Path:
    """`episodes/<id>/staged.yaml` — one spelling, because four callers open it."""
    return Path(episode_dir) / STAGED_FILENAME


def read_staged(episode_dir: Path) -> list[dict]:
    """Every row the staging record holds, in written order — or a refusal.

    A record that does not PARSE is refused rather than guessed at, and the asymmetry is why:
    acting on half a record means deleting a name this code did not write, or leaving one it
    did. Both are worse than stopping and saying so, because the second leaves a live alias
    under a token the next episode is about to reuse.
    """
    path = staged_path(episode_dir)
    if not path.is_file():
        return []
    try:
        rows = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as bad:
        raise StagingRefused(
            f"{STAGED_FILENAME} at {path} does not parse ({bad}) — acting on a staging record "
            "this code cannot read means deleting a name it did not write, or leaving one it "
            "did") from bad
    if rows is None:
        return []
    if not isinstance(rows, list) or any(not isinstance(r, dict) for r in rows):
        raise StagingRefused(
            f"{STAGED_FILENAME} at {path} is not a list of rows — the record is append-only "
            "and every row names one created thing")
    return list(rows)


def record_staged(episode_dir: Path, row: Mapping[str, Any]) -> dict:
    """Append one row to `staged.yaml` and make it DURABLE before returning.

    Flushed AND fsynced, not merely written. The write door bypasses `guard_outbound`, which is
    also the capture recorder, so this file is the only record anywhere that a cluster write
    was about to happen — and a row sitting in a userspace buffer when the launcher is killed
    is a name live on the cluster that nothing on disk names. Teardown would not delete it and
    the next start's sweep would refuse the episode over it.

    APPEND-ONLY, across worlds and across calls: the file is opened for append and one YAML
    sequence entry is written, so no earlier row is ever rewritten or re-serialised. A
    rewrite-the-whole-list implementation would be a window in which the record is shorter than
    the cluster.
    """
    path = staged_path(episode_dir)
    # The episode dir is a tree a sibling's box can write into, so the dir components below
    # the episodes root are judged rather than followed: a symlinked `episodes/<id>/` would
    # put the one record of a cluster write somewhere nobody tearing down will look.
    guarded_mkdir(path.parent, base=path.parent.parent)
    entry = yaml.safe_dump([dict(row)], sort_keys=True, default_flow_style=False)
    # `open_guarded` rather than `write_guarded(mode="append")`: the seam's append lane does not
    # fsync, and the fsync is the whole invariant here — a row in a userspace buffer is a row
    # a killed launcher never wrote. The alias refusal is the same one either lane applies.
    with open_guarded(path, "a") as handle:
        handle.write(entry)
        handle.flush()
        os.fsync(handle.fileno())
    return dict(row)


def _row(*, world: str, name: str, kind: str, derived_from: str) -> dict:
    return {"world": world, "name": name, "kind": kind, "derived_from": derived_from,
            "created_at": now_iso()}


# ---------------------------------------------------------------------------------------
# staging one world
# ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class _Plan:
    """One declared base pattern, resolved into the two names it stages."""

    pattern: str
    view: str
    inject: str
    docs: list[dict]
    exclude: dict | None


def _plan_world(world: World, *, token: str,
                configured_patterns: Sequence[str]) -> list[_Plan]:
    """Everything this world would stage, validated, before a single connection is opened.

    ONE PASS OVER THE WHOLE WORLD FIRST. Validating as we go would leave a world whose second
    declared pattern carries an executable clause with its first pattern already created on the
    cluster — recorded, so teardown reaches it, but created for a world that was never
    admitted. Every refusal below is therefore reachable with `door.connections == 0`.
    """
    plans: list[_Plan] = []
    stems: dict[str, str] = {}
    # lint-shippable: ok — the overlay's staged half is named by `_family.Overlay`'s own field,
    # and this seam reads that field rather than restating the schema; the vendor name is the
    # manifest's, not this module's, and renaming it here would be a second spelling.
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
            # lint-shippable: ok — the `where` string names the MANIFEST PATH an operator has
            # to go and edit, so it spells the manifest's own field name or it points nowhere.
            entry.exclude, where=f"overlay.elastic[{pattern!r}].exclude")  # lint-shippable: ok — the manifest path an operator edits
        plans.append(_Plan(pattern=pattern, view=view, inject=inject,
                           docs=[dict(d) for d in entry.inject], exclude=exclude))
    return plans


def stage_world(world: World, *, episode_dir: Path, episode_token: str,
                configured_patterns: Sequence[str], door: Any) -> list[dict]:
    """Create this world's corpus on the cluster, recording every name before it exists.

    Per declared base pattern: the injection index holding the world's authored documents,
    then the alias over the pattern's concrete indices PLUS that injection index, carrying the
    exclusion as its filter. `base − exclude + inject` in one name, which is what makes a
    `STATS … BY …` over a staged world correct by construction rather than composed.

    THE ORDER IS THE INVARIANT. Each name is appended to `staged.yaml` and fsynced, and only
    then is its create issued — so a door that fails on its first create, a cluster that
    refuses it, and a launcher killed between the two all leave that name recorded. The record
    is what teardown deletes from and what the next start's sweep reconciles against, and a
    name it does not hold is a name nothing will ever remove.

    Nothing is created for a world that declares no staged difference; `world.touches` is
    derived from these same keys, so a world with an empty half is not a staged world.
    """
    token = world_token_for(episode_token, world.world_id)
    plans = _plan_world(world, token=token, configured_patterns=configured_patterns)
    for plan in plans:
        for name in (plan.inject, plan.view):
            stage_name(name, episode_token=episode_token, world_id=world.world_id,
                       configured_patterns=configured_patterns, door=door)
    rows: list[dict] = []
    for plan in plans:
        rows.append(record_staged(episode_dir, _row(
            world=token, name=plan.inject, kind=KIND_INDEX, derived_from=plan.pattern)))
        door.create_index(plan.inject, docs=plan.docs)
        rows.append(record_staged(episode_dir, _row(
            world=token, name=plan.view, kind=KIND_ALIAS, derived_from=plan.pattern)))
        over = [*door.resolve(plan.pattern), plan.inject]
        door.create_alias(plan.view, over=over, filter=plan.exclude)
    return rows


# ---------------------------------------------------------------------------------------
# teardown and sweep
# ---------------------------------------------------------------------------------------


def teardown(episode_dir: Path, *, door: Any, review_path: Path | None = None) -> list[str]:
    """Remove exactly the names `staged.yaml` records, newest first, verifying each is gone.

    NEWEST FIRST because the record is written in dependency order: the injection index is
    created before the alias that spans it, so removing in reverse takes the alias away before
    the index it points at and never leaves an alias over a deleted member.

    EXACTLY THE RECORD, and nothing else on the cluster. A name this code did not write is not
    this code's to remove — that rule is what lets the sweep refuse rather than guess — so
    teardown never lists, never globs, and visits a duplicated row twice.

    VERIFIED, not assumed. A delete that returns and leaves the name present is the failure
    mode that matters: the launcher exits clean, the operator believes the namespace is empty,
    and the next episode reusing the token finds a live alias. Every failure is collected,
    written into the review record, and then RAISED — a teardown failure swallowed into a clean
    exit is the same lie one step later.
    """
    rows = read_staged(episode_dir)
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
        except Exception as bad:  # noqa: BLE001 — every fault is REPORTED, never re-raised here
            failures.append({"name": name, "detail": f"{type(bad).__name__}: {bad}"})
    if failures:
        _record_teardown_failure(failures, review_path)
        raise StagingRefused(
            "teardown did not verify every staged name gone: "
            + "; ".join(f"{f['name']} ({f['detail']})" for f in failures))
    return [str(r.get("name")) for r in rows]


def _record_teardown_failure(failures: list[dict], review_path: Path | None) -> None:
    """Put the failure in the review record before raising it.

    The review is the episode's own account of what happened, and a teardown that failed is
    part of that account rather than a launcher-console line: the names are still live on the
    cluster, and whoever reads the review is the reader who has to go and remove them. Merged
    onto whatever the review already holds — the review step writes it first on every path that
    reaches teardown, and rewriting the file with only this block would delete the verdicts the
    episode exists to produce.
    """
    if review_path is None:
        return
    path = Path(review_path)
    doc: dict[str, Any] = {}
    if path.is_file():
        try:
            loaded = yaml.safe_load(path.read_text(encoding="utf-8"))
        except yaml.YAMLError:
            loaded = None
        if isinstance(loaded, dict):
            doc = loaded
    doc["teardown"] = {"ok": False, "failures": failures,
                       "names": [f["name"] for f in failures], "at": now_iso()}
    guarded_mkdir(path.parent, base=path.parent.parent)
    write_guarded(path, yaml.safe_dump(doc, sort_keys=True), encoding="utf-8")


def sweep_glob(episode_token: str) -> str:
    """The one glob this episode's namespace answers to.

    `wv-{episode_token}.*` and nothing wider. The token is injective over episode ids, so every
    name under it belongs to THIS episode and removing it is safe; one character wider and the
    sweep is reaching into a concurrently-running episode's live corpus.
    """
    return f"wv-{episode_token}.*"


def sweep(episode_dir: Path, *, episode_token: str, door: Any) -> list[str]:
    """Remove what an earlier death left behind in this episode's own token namespace.

    Teardown runs on rejection, on completion and on any exception after the first append — but
    a killed launcher runs none of that, so the next start's FIRST act is this. The glob is the
    episode token's own, which is what makes removal safe without asking anyone: no other
    episode's names can appear under it.

    IT REFUSES WHEN IT CANNOT REACH THE CLUSTER, and that is why it probes before it lists. An
    empty listing from an unreachable cluster is indistinguishable from a clean namespace, so a
    sweep that treated "no names" as "nothing to do" would skip in silence exactly when it is
    needed — leaving an earlier death's aliases live under a namespace this episode is about to
    reuse, which is the whole of the crash-recovery story. The probe is a call that FAILS
    LOUDLY on an unreachable cluster rather than answering emptily.

    IT REFUSES A NAME THE RECORD DOES NOT HOLD. A `wv-` name under this token that
    `staged.yaml` does not name is a name this code did not write; removing it would be
    guessing, and the guess destroys data. Validated over the whole listing BEFORE anything is
    deleted, so a refusal leaves the cluster exactly as it was found.
    """
    glob = sweep_glob(episode_token)
    door.count(glob)
    found = list(door.list_names(glob))
    recorded = {str(r.get("name")) for r in read_staged(episode_dir)}
    unrecorded = sorted(n for n in found if n not in recorded)
    if unrecorded:
        raise StagingRefused(
            f"the sweep found {unrecorded} under {glob!r}, which the staging record does not "
            "name — that is a name this code did not write, and removing it would be guessing")
    removed: list[str] = []
    for name in sorted(found, reverse=True):
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
    """`value`, or a refusal — every character held to a derived-name alphabet.

    The door's own last line, below every guard above it. Names reach the transport as DISCRETE
    ARGUMENTS in the URL slot and are never concatenated into a shell string, so a metacharacter
    is not an injection today; it is refused anyway because the door is the frame that knows
    the value is derived, and "not exploitable through the transport we happen to use" is not a
    property a security boundary should rest on.
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


@dataclass(frozen=True)
class _Door:
    """The cluster's write surface, as an object the launcher holds and no verb can name.

    HOST-SIDE and SEPARATE from `elastic_adapter`'s HTTP helper, whose door is confined to four
    read endpoints and which also carries `guard_outbound` — the capture recorder. This one
    reaches `docker_exec_curl` directly with PUT and DELETE, which is precisely why
    `staged.yaml` has to be durable before every create: nothing else records that this door
    was used.

    `transport` is a constructor argument rather than a module lookup, so a caller drives the
    real door over a recording transport instead of patching a module attribute.
    """

    ctx: Any
    container: str
    transport: Any
    base_url: str
    timeout_sec: int
    insecure: bool
    auth: str | None

    # -- the transport ------------------------------------------------------------------
    def _call(self, method: str, path: str, *,
              body: dict | None = None) -> tuple[int, dict[str, Any]]:
        """One request, and the ONE reading of its status this module admits.

        AN UNPARSEABLE STATUS IS A FAILURE. `split_status` recovers `(body, code)` from curl's
        trailing `-w '\\n%{http_code}'` line, and when there is no parseable trailing line it
        answers `("", <whole body>)` — so a caller comparing the second element to `"200"`
        reads a FAILED create as a success. Against a write-ahead-recorded name that is the one
        direction the record does not tolerate: the launcher believes the corpus exists, the
        review measures a world that was never staged, and the difference reads as the world's.
        Anything that is not a 2xx integer is therefore refused.
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
        if not 200 <= code < 300:
            raise StagingRefused(
                f"{method} {url} answered HTTP {code}: {payload.strip()[:200]}")
        # NARROWED HERE, once. Every cluster response this door reads is a JSON OBJECT, and a
        # body that is anything else — a bare array, a number, a truncated fragment — is a
        # shape this module has no reading of. Answering `{}` rather than handing `Any` on is
        # what keeps `resolve` and `count` from inheriting an annotation nothing checks.
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

        `_id` is lifted out of the document and into the URL rather than sent in the body: it
        is a metadata field, and a source object carrying it is rejected by the cluster — which
        would be a create failing against an already-recorded name for a reason nobody reading
        the world would guess at.
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
            self, name: str, *, over: list[str], filter: dict | None) -> None:
        """Point `name` at every index in `over`, carrying `filter` as its exclusion.

        ONE `_aliases` action list rather than one request per member: the alias appears whole
        or not at all, so there is no window in which a query reads a view spanning half its
        corpus. The predicate is `must_not`-wrapped, because the world DECLARES what it removes
        and an alias filter says what it keeps.
        """
        _checked(name, _NAME_CHARS, "alias name")
        actions = [{"add": {"index": _checked(index, _EXPRESSION_CHARS, "alias member"),
                            "alias": name,
                            **({} if filter is None
                               else {"filter": {"bool": {"must_not": [filter]}}})}}
                   for index in over]
        self._call("POST", "/_aliases", body={"actions": actions})

    def delete(self, name: str) -> None:
        """Remove `name`, whichever of the two things it is.

        An alias and an index are removed through different APIs, and the door is handed only a
        name — so it asks the cluster which it is rather than trusting the caller's record. The
        record's `kind` is what teardown reads; this is what makes the door correct on its own.
        """
        _checked(name, _NAME_CHARS, "name to delete")
        if self._is_alias(name):
            self._call("DELETE", f"/*/_alias/{self._quoted(name)}")
            return
        self._call("DELETE", f"/{self._quoted(name)}")

    def exists(self, name: str) -> bool:
        """Is `name` still on the cluster? The half of teardown that is not a delete."""
        _checked(name, _NAME_CHARS, "name")
        found = self._resolved(name)
        return bool(found["indices"] or found["aliases"])

    def list_names(self, glob: str) -> list[str]:
        """Every index and alias under `glob` — what the sweep reconciles against the record."""
        _checked(glob, _EXPRESSION_CHARS, "namespace glob")
        found = self._resolved(glob)
        return sorted(found["indices"] + found["aliases"])

    def count(self, index: str, *, query: dict | None = None) -> int:
        """How many documents `index` holds, optionally under `query`.

        `_count` is deliberately NOT on the adapter's read-endpoint allowlist and must never be
        added to it: the review's exclusion count is a HOST-side measurement, and putting the
        endpoint on the model-reachable door would hand every verb a cardinality oracle over
        the whole corpus.
        """
        _checked(index, _EXPRESSION_CHARS, "index expression")
        body = None if query is None else {"query": query}
        _code, payload = self._call("POST", f"/{self._quoted(index)}/_count", body=body)
        found = payload.get("count", 0)
        return int(found) if isinstance(found, int) else 0

    def resolve(self, pattern: str) -> list[str]:
        """The concrete indices `pattern` names right now — what an alias is built OVER.

        Concrete, never the pattern itself: an alias declared over a wildcard is a wildcard
        resolved at declaration time anyway, and recording which indices a world's view spanned
        is what makes the staged corpus reproducible.
        """
        _checked(pattern, _EXPRESSION_CHARS, "corpus pattern")
        return sorted(self._resolved(pattern)["indices"])

    # -- the one read the door needs ----------------------------------------------------
    def _resolved(self, expression: str) -> dict[str, list[str]]:
        _code, payload = self._call("GET", f"/_resolve/index/{self._quoted(expression)}")
        return {key: [str(e.get("name")) for e in payload.get(key, [])
                      if isinstance(e, dict) and e.get("name")]
                for key in ("indices", "aliases")}

    def _is_alias(self, name: str) -> bool:
        return name in self._resolved(name)["aliases"]


def write_door(*, ctx: Any = None, container: str, transport: Any = docker_exec_curl,
               base_url: str = "http://localhost:9200", timeout_sec: int = 30,
               insecure: bool = False, auth: str | None = None) -> _Door:
    """The cluster's write door — host-side, and reachable from this module alone.

    IT LIVES HERE ON PURPOSE. The adapters' HTTP helper is read-confined to four endpoints and
    carries `guard_outbound`; adding a write method there would widen the door every
    model-dispatched verb resolves through, for a capability only the launcher needs. Instead
    the launcher constructs this, hands it to `stage_world` / `teardown` / `sweep`, and the
    registry never sees it — so a model-dispatched call has no route to a cluster write at all.

    `transport` is a parameter with the real `docker_exec_curl` as its default, which is the
    injection seam: a caller drives the real door over a recording transport rather than
    patching a module attribute.
    """
    return _Door(ctx=ctx, container=container, transport=transport, base_url=base_url,
                 timeout_sec=timeout_sec, insecure=insecure, auth=auth)


@dataclass(frozen=True)
class _HostContext:
    """The two fields `docker_exec_curl` reads off a context, for a caller that has no run.

    The launcher opens this door BEFORE any episode dir, run dir or `VerbContext` exists — the
    sweep is step one — so there is nothing to borrow. Only `env` and `defender_dir` are
    supplied, which is all the transport touches; anything else a verb context carries would be
    a field this frame would have to invent, and an invented run identity is worse than an
    absent one.
    """

    env: dict[str, str]
    defender_dir: Path


def write_door_from_env(ctx: Any = None, *, transport: Any = docker_exec_curl) -> _Door:
    """The write door this deployment's configuration describes.

    ONE reading of where the cluster is, shared by the sweep, staging and teardown, so a
    deployment that moves does not move for one of the three. The URL, the container and the
    TLS posture come from the same `config.env` the read adapter loads and are overridden by
    the environment with the same precedence — a caller steering the deployment steers both
    doors at once, which is what keeps the staged names and the read of them in one place.

    The credential is expanded INSIDE the container, exactly as the read path does it: the
    `${…}` reaches the container's own shell, so the secret is never on this host's argv.
    """
    from defender._paths import PATHS

    defender_dir = getattr(ctx, "defender_dir", None) or PATHS.defender_dir
    env: dict[str, str] = dict(getattr(ctx, "env", None) or os.environ)
    values: dict[str, str] = {}
    path = Path(defender_dir) / "knowledge" / "environment" / "systems" / "elastic" / "config.env"  # lint-shippable: ok — the per-vendor config the read adapter loads
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or "=" not in stripped:
                continue
            key, _, val = stripped.partition("=")
            values[key.strip()] = val.strip().strip('"').strip("'")
    values.update({k: v for k, v in env.items() if k in values})
    return write_door(
        ctx=ctx if ctx is not None else _HostContext(env=env, defender_dir=Path(defender_dir)),
        container=env.get("SOC_PLAYGROUND_ES_CONTAINER", "elasticsearch"),  # lint-shippable: ok — the container the read adapter execs into
        transport=transport,
        base_url=values.get("ELASTICSEARCH_URL", "https://localhost:9200"),  # lint-shippable: ok — the per-vendor config key
        insecure=values.get("ELASTIC_SSL_VERIFY", "false").lower() != "true",  # lint-shippable: ok — the per-vendor config key
        auth="elastic:${ELASTIC_PASSWORD}")  # lint-shippable: ok — expanded inside the container, as the read path does it



#: The launcher's own spelling of the door above. ONE function, two names, because the two
#: readers mean different things by it: a LIVE probe asks for "the door this environment
#: describes" (`write_door_from_env`), while the launcher asks for "the door when the caller
#: injected none" (`default_door`). Aliased rather than duplicated — two constructors reading the
#: same config is two readings that can drift, and the one that drifts is the one that stages
#: into a cluster nothing later tears down.
default_door = write_door_from_env


__all__ = [
    "ALLOWED_CLAUSES",
    "INJECT_SUFFIX",
    "KIND_ALIAS",
    "KIND_INDEX",
    "REVIEW_FILENAME",
    "STAGED_FILENAME",
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
