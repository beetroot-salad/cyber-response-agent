#!/usr/bin/env python3
"""Defender entrypoint — investigate one alert end-to-end.

The investigation is driven by the in-process PydanticAI driver
(`runtime/driver.py`): materialize the run dir → run → cross-check the two live
tables → enqueue learning → visualize. Run-dir + post-step helpers are shared
via `run_common.py`.

Usage:
    python3 defender/run.py <alert.json> [--run-id ID] [--no-learn] [--model M]

Billing / credentials: the engine calls the first-party Anthropic REST API and
needs a real billable API key. Inside a Claude Code session the *ambient*
ANTHROPIC_API_KEY is the subscription credential (it 401s against the REST API),
so the billable key is sourced from a `.env` file (`resolve_first_party_key`) and
takes precedence over the ambient value.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

# Hand-rolled rather than `scripts/_venv.reexec_into_venv`, and irreducibly so: this must
# run BEFORE any `defender.*` import resolves, and reaching that helper is itself such an
# import.
_DEFENDER_DIR = Path(__file__).resolve().parent
_VENV_PY = _DEFENDER_DIR / ".venv" / "bin" / "python3"
if __name__ == "__main__" and _VENV_PY.is_file() and Path(sys.executable) != _VENV_PY:
    os.execv(str(_VENV_PY), [str(_VENV_PY), __file__, *sys.argv[1:]])

import argparse  # noqa: E402
import asyncio  # noqa: E402
import inspect  # noqa: E402
from collections.abc import Callable  # noqa: E402
from typing import Any, Protocol  # noqa: E402

if (_root := str(_DEFENDER_DIR.parent)) not in sys.path:
    sys.path.insert(0, _root)

from defender import _provenance  # noqa: E402
from defender import run_common as _run  # noqa: E402
from defender._run_paths import RunPaths  # noqa: E402
from defender.runtime import box as box_mod  # noqa: E402
from defender.runtime import driver  # noqa: E402
from defender.runtime import providers  # noqa: E402
from defender.runtime.verbs import ModuleVerbRegistry  # noqa: E402
from defender.scripts.case_history import ticket_writer as _default_ticket_writer  # noqa: E402

DEFENDER_DIR = _DEFENDER_DIR


from defender._first_party_key import (  # noqa: E402,F401
    _read_env_key,
    resolve_first_party_key,
)


def parse_args(argv: list[str]) -> argparse.Namespace:
    """The entry point's whole argument surface — the ordinary run's, and the sibling's.

    #947's D1 makes a sibling world a `run.py --resume` PROCESS rather than an in-process
    call, so this parser grows exactly two arguments and one refusal. `--resume` names the
    family manifest and `--world` names which arm of it this process is; everything else a
    sibling needs — the source run, the branch point, T0, the continuation prompt, the world's
    overlay — is DERIVED from that one document, which is what makes the manifest the contract
    rather than a hint.

    THE POSITIONAL ALERT BECOMES ILLEGAL UNDER `--resume`, refused rather than ignored. The
    manifest already names the source run the alert would be copied from, so a command line
    carrying both names two case inputs and there is no rule for which wins that is not a
    guess. Refused at the parser, where the operator's own words are still in hand.
    """
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("alert", type=Path, nargs="?", default=None,
                   help="Path to alert.json fixture (illegal with --resume)")
    p.add_argument("--resume", type=Path, default=None,
                   help="a family manifest (episodes/<id>/family.yaml) to resume a world of")
    p.add_argument("--world", default=None,
                   help="which world of --resume's manifest this process is")
    p.add_argument("--run-id", default=None,
                   help="Pin the run id for a named A/B or live run (learning-loop "
                        "commits reference it) instead of the auto timestamp id; a "
                        "collision with an existing run dir is rejected by materialize_run_dir")
    p.add_argument("--no-learn", action="store_true",
                   help="Skip enqueuing for learning (also skips catalog curation — the "
                        "flag now governs both lanes)")
    p.add_argument("--update-ticket", action="store_true",
                   help="Write/close a case-history ticket for this alert (default off)")
    p.add_argument("--model", default=None,
                   help="model id (overrides $DEFENDER_MODEL); e.g. a claude-* id, "
                        "or 'glm-5.2' / 'fireworks:<id>' for the Fireworks-served GLM")
    ns = p.parse_args(argv)
    if ns.resume is not None and ns.alert is not None:
        p.error(
            "the positional alert is illegal with --resume: the manifest already names the "
            "source run the alert would come from, and a command line carrying both names two "
            "case inputs with no rule for which wins")
    if ns.resume is None and ns.alert is None:
        p.error("an alert path is required unless --resume names a family manifest")
    if ns.resume is not None and not ns.world:
        p.error("--resume needs --world: a manifest declares a family, and a process is one arm")
    return ns


def _source_one_provider_key(prov: providers.Provider) -> int:
    var = prov.api_key_var
    key, src = resolve_first_party_key(var=var)
    if key:
        os.environ[var] = key
        note = " (overrides the ambient subscription credential)" if prov.id == "anthropic" else ""
        print(f"[run.py] {var} sourced from {src}{note}", file=sys.stderr)
        return 0
    if os.environ.get(var):
        if prov.id == "anthropic":
            print("[run.py] WARNING: no .env key found; using the ambient "
                  "ANTHROPIC_API_KEY — inside a Claude Code session this is the "
                  "subscription credential and will 401 against the first-party API.",
                  file=sys.stderr)
        else:
            print(f"[run.py] using the ambient {var} for the {prov.id} model",
                  file=sys.stderr)
        return 0
    if prov.id == "anthropic":
        print("[run.py] ERROR: no first-party ANTHROPIC_API_KEY — set it in "
              "<repo>/.env or $DEFENDER_ENV_FILE (the PydanticAI engine bills the "
              "first-party Anthropic API).", file=sys.stderr)
    else:
        print(f"[run.py] ERROR: a {prov.id} model is selected but no {var} — set it "
              f"in <repo>/.env or $DEFENDER_ENV_FILE ({prov.id} bills its "
              "OpenAI-compatible API).", file=sys.stderr)
    return 2


def _accepts(sig: inspect.Signature, *args: Any, **kwargs: Any) -> bool:
    """Can the accessor this signature describes be CALLED this way?

    Asked of the signature rather than by calling and catching `TypeError` — that would also
    swallow a `TypeError` raised from INSIDE an accessor that took the argument fine, and
    report a role with a broken model config as one that simply owns its own model."""
    try:
        sig.bind(*args, **kwargs)
    except TypeError:
        return False
    return True


def _role_model_name(defn: Any, model_override: str | None) -> str:
    """The model name this role will ACTUALLY run on.

    The operator's per-run `--model` reaches every role whose accessor can TAKE it, and no
    role that owns a knob of its own. Checking `defn.model()` alone would validate the ambient
    default while the run is about to execute on the override.

    Which roles those are is read off the accessor's SIGNATURE rather than a hand-list, which
    would be a second registry to forget to update. Accepting the parameter is the whole of
    what makes a role overridable: the already-resolved accessors (`gather_model`, the bundle
    builder's `lambda: name`, the learning stages' own knobs) take none by construction.

    What is read is whether the accessor can be HANDED the override, not merely whether it has
    parameters. Non-empty arity is strictly weaker: `def m(*, explicit=None)` — the natural
    spelling for an override parameter — reports a parameter and REFUSES a positional call, so
    an arity check hands it one, the `TypeError` lands in `preflight_role_models`' broad
    `except`, and every `--model` run refuses to start with "model config raised". A
    keyword-only override is therefore passed by its NAME. An accessor naming more than one
    keyword-only parameter names no single override, and is treated as one that owns its
    model rather than guessed at."""
    if model_override is None:
        return str(defn.model())
    try:
        sig = inspect.signature(defn.model)
    except (TypeError, ValueError):
        # A callable whose signature cannot be read is not one we can hand an override to.
        return str(defn.model())
    if _accepts(sig, model_override):
        return str(defn.model(model_override))
    by_keyword = [p.name for p in sig.parameters.values() if p.kind is p.KEYWORD_ONLY]
    if len(by_keyword) == 1 and _accepts(sig, **{by_keyword[0]: model_override}):
        return str(defn.model(**{by_keyword[0]: model_override}))
    return str(defn.model())


def preflight_role_models(model_override: str | None = None) -> int:
    """Iterate EVERY registered role's model config at investigation STARTUP and fail fast if
    a role's provider key is unusable. Build-time failure is provider-dependent (one provider
    raises immediately on a missing key, another defers to first live call), and each review
    stage's agent is built fresh per call — so a misconfigured review role would otherwise
    silently downgrade confident investigations to unresolved ones, one at a time, deep into
    paid-for runs."""
    from defender.agents import AGENTS

    seen_provider_ids: set[str] = set()
    for defn in AGENTS.values():
        try:
            name = _role_model_name(defn, model_override)
        except Exception as e:  # noqa: BLE001 — a broken model accessor is a preflight failure
            print(f"[run.py] preflight: {defn.role.name} model config raised: {e!r}",
                  file=sys.stderr)
            return 2
        try:
            prov = providers.provider_for(name)
        except ValueError as e:
            print(f"[run.py] preflight: {defn.role.name}: {e}", file=sys.stderr)
            return 2
        if prov.id in seen_provider_ids:
            continue
        seen_provider_ids.add(prov.id)
        rc = _source_one_provider_key(prov)
        if rc:
            print(f"[run.py] preflight: {defn.role.name} ({name}) has no usable model config",
                  file=sys.stderr)
            return rc
    return 0


class _Investigate(Protocol):
    """The investigation seam's exact shape.

    Spelled out rather than left as a bare `Callable[..., dict]` so BOTH halves of the
    injection stay type-checked: the lifecycle's call site against this signature, and
    `_drive_investigation` against `driver.run_investigation`'s own parameters. A `**kwargs`
    passthrough checks neither, so a renamed driver keyword would type-check clean, pass every
    test (they all inject the seam) and fail only on a real credentialed run.
    """

    def __call__(
        self, *, alert_path: Path, run_dir: Path, run_id: str, defender_dir: Path,
        model_name: str, model_override: str | None, box: Any, world: Any = None,
    ) -> dict[str, Any]: ...


def _run_the_driver(**kwargs: Any) -> dict[str, Any]:
    """The driver's coroutine, as a synchronous call.

    Split out of `_drive_investigation` so the REGISTRY DECISION below has a seam of its own:
    a test asking which registry a world does or does not build has no reason to also build an
    event loop, and injecting one function for both questions made the registry unobservable.
    """
    return asyncio.run(driver.run_investigation(**kwargs))


def _drive_investigation(  # noqa: PLR0913 — one investigation's whole identity plus its seams
    *,
    alert_path: Path,
    run_dir: Path,
    run_id: str,
    defender_dir: Path,
    model_name: str,
    model_override: str | None,
    box: Any,
    #: The world this process IS, on the `--resume` path; `None` on an ordinary run. The
    #: parity that matters is that `None` builds exactly what it builds today.
    world: Any = None,
    registry_cls: Any = ModuleVerbRegistry,
    investigate: Callable[..., dict[str, Any]] = _run_the_driver,
) -> dict[str, Any]:
    """The production investigation call, as a SYNCHRONOUS callable.

    `_run_investigation_lifecycle` injects this rather than reaching for the driver directly,
    so a test can hand in a plain function — no coroutine to build, no event loop to drive,
    no model credentials.

    The ONLY real caller of `run_investigation`, so `verbs=` is built and passed HERE rather
    than left to `run_investigation`'s internal fallback (`ModuleVerbRegistry(...)` when
    `verbs is None`). That fallback is deliberately NOT what lead-0 reads (K12/d49): a test
    `drive()` site injecting no registry asked for no backend, and lead-0 must stay off for
    it — which is why `run_investigation` captures `lead_zero_verbs` before applying the
    fallback. A real investigation always has a credentialed adapters tree, so it injects the
    registry itself rather than riding the default the hermetic suite depends on lead-0 NOT
    acquiring.

    ON THE RESUME PATH THE PRODUCTION REGISTRY IS NEVER CONSTRUCTED, and that is a NEGATIVE
    rather than a preference. A sibling's queries are answered from the family's primed
    recording first and from its own staged corpus second; a module registry built beside that
    is a live route from a model-dispatched verb to a real adapter body for every key the
    capture happens not to hold, which is exactly the post-branch query the design forbids. The
    two registries are therefore built in the two arms of one `if`, so there is no path on
    which both exist.
    """
    if world is not None:
        from defender.learning.branch.estate.applier import WorldApplier
        from defender.learning.branch.estate.registry import WorldRegistry
        from defender.learning.branch.ledger import Ledger
        from defender.runtime import branch as branch_mod

        family = world.family
        verbs: Any = WorldRegistry(
            defender_dir / "scripts" / "adapters", driver.GATHER_DEF.verb_grant,
            world=world, ledger=Ledger.for_world(world.episode_dir, world.world_id),
            as_of=world.as_of, applier=WorldApplier(),
        )
        resume = branch_mod.BranchSpec(
            source_run_dir=Path(family.source_run_dir),
            branch_message_id=family.branch_message_id,
            continuation_prompt=family.continuation_prompt,
            as_of=family.as_of,
        )
        return investigate(
            alert_path=alert_path, run_dir=run_dir, run_id=run_id,
            defender_dir=defender_dir, model_name=model_name,
            model_override=model_override, box=box, verbs=verbs, resume=resume,
        )
    verbs = registry_cls(defender_dir / "scripts" / "adapters", driver.GATHER_DEF.verb_grant)
    return investigate(
        alert_path=alert_path, run_dir=run_dir, run_id=run_id, defender_dir=defender_dir,
        model_name=model_name, model_override=model_override, box=box, verbs=verbs,
    )


def _run_investigation_lifecycle(  # noqa: PLR0913 — the lifecycle's inputs plus its four injection seams
    *,
    run_dir: Path,
    model: str,
    #: The operator's RAW `--model`, carried alongside the resolved `model` rather than
    #: derived from it. The review roles pin their own default; resolving this against the
    #: investigator's would hand them a non-`None` model on every run, making that default
    #: unreachable in production.
    model_override: str | None,
    defender_dir: Path,
    #: The world this process IS, threaded through so the drive function can build the world
    #: registry rather than the production one. Five signatures carry it — the parser, this
    #: lifecycle, `main`'s call to it, the drive function and the protocol — so a world
    #: declared on the command line cannot be dropped between any two of them.
    world: Any = None,
    investigate: _Investigate = _drive_investigation,
    start_box: Callable[..., Any] = box_mod.start_box,
    stop_box: Callable[..., None] = box_mod.stop_box,
    scrub: Callable[[Path], None] = box_mod.scrub,
) -> dict[str, Any]:
    """Start the box, run the investigation inside it, and reap both on every exit.

    Sited one layer in from `main` so the lifecycle carries an injection seam a test can reach
    (like `drains._run_worktree_batch`, `run_cycle.run_one`); `main` stays an argv entrypoint.

    The exit half belongs to `box_mod.stop_and_scrub`, which owns the ordering, the
    only-scrub-a-provably-dead-box rule, and the exception preference for both writable lanes.
    """
    box = start_box(run_dir, defender_dir)
    investigation_ok = False
    try:
        summary = investigate(
            alert_path=RunPaths(run_dir).alert,
            run_dir=run_dir,
            run_id=run_dir.name,
            defender_dir=defender_dir,
            model_name=model,
            model_override=model_override,
            box=box,
            world=world,
        )
        investigation_ok = True
    finally:
        box_mod.stop_and_scrub(
            box, run_dir, stop_box=stop_box, scrub_tree=scrub,
            in_flight=not investigation_ok,
        )
    return summary


def _announce_provenance(run_dir: Path) -> None:
    """Say out loud what this run was made against, reading the stamp back off the run dir
    rather than re-asking git — so the line an operator sees is the RECORD, not a second
    capture that could disagree with it.

    The dirty marker is not decoration. A sha over a modified tree does not name the bytes that
    ran, and an operator reading a later comparison needs to have been told so at the moment it
    stopped being true, not months afterwards when they go looking."""
    rec = _provenance.read(RunPaths(run_dir).provenance)
    if rec is None:
        print("[run.py] commit=unrecorded", file=sys.stderr)
        return
    if rec.commit is None:
        print(f"[run.py] commit=unavailable ({rec.unavailable})", file=sys.stderr)
        return
    # `dirty is None` is neither clean nor dirty: git answered for HEAD and then could not
    # answer for the working tree, and flattening that to either word would be a claim.
    mark = {True: " +dirty", False: "", None: " +dirt-unknown"}[rec.dirty]
    if rec.dirty is None:
        # The REASON, on the one branch where it is most actionable: a corrupt index and a
        # missing git send an operator at different knobs, and " +dirt-unknown" alone names
        # neither. `capture_tree` kept the string for exactly this line.
        detail = f" ({rec.unavailable})" if rec.unavailable else ""
    else:
        # `if rec.dirty_path_count`, not `if rec.dirty`: this file is in the box's rw bind, so
        # the count read back may be a default standing in for a corrupted one, and " (0
        # paths)" beside "+dirty" is a QUANTITY nobody wrote — the announce's own version of
        # filing an unknown as a fact.
        detail = f" ({rec.dirty_path_count} paths)" if rec.dirty_path_count else ""
    print(f"[run.py] commit={rec.commit[:12]}{mark}{detail}", file=sys.stderr)


def resume_world(manifest: Path, world_label: str) -> Any:
    """The world this process IS, from the manifest alone.

    The episode dir is the manifest's own PARENT, and that is what makes the world ledger
    resolve: the file a sibling appends to sits beside the family's primed base recording,
    wherever the manifest lives. Deriving it any other way — from a configured root, from the
    run dir — would make a sibling's ledger depend on something the manifest does not say, and
    the manifest is the whole of what a sibling is told.
    """
    from defender.runtime.branch import _family

    manifest = Path(manifest)
    return _family.resume_world_from(
        _family.load_family(manifest), world_label, manifest.parent)


def _screened_source_alert(source_run_dir: Path) -> Path:
    """The source run's alert, or the refusal that says it is not a plain file.

    THE SOURCE RUN DIR IS A PRIOR BOX'S WRITABLE BIND. `alert.json` there is model-writable, so
    an entry at that name may be a link the model planted, and `materialize_run_dir` admits it
    with `alert.is_file()` and copies it with `shutil.copy` — both of which FOLLOW a link. Asked
    here, before the copy, so bytes from outside the source run never arrive in this run's own
    dir under the case input's name, where the visualizer and the archive read them as the alert.
    """
    from defender._run_paths import artifact_file

    alert = RunPaths(Path(source_run_dir)).alert
    if not artifact_file(alert):
        sys.exit(
            f"source alert {alert} is not a plain file — the alert is the case input this "
            "sibling investigates, and a link wearing its name would copy bytes from outside "
            "the source run into this run dir")
    return alert


def _resume_target(ns: argparse.Namespace) -> Any:
    """The world this process is, or `None` for an ordinary run — and the sibling's two refusals.

    BOTH BEFORE ANYTHING IS SPENT, which is the whole reason this sits ahead of the preflight
    rather than beside the lifecycle. `--update-ticket` is refused OUTRIGHT rather than accepted
    and ignored: the two ticket calls are ordered around the curation marker, so suppressing one
    of them would break the pairing instead of the obligation. And the world is resolved from the
    manifest before the run dir exists, so a label the manifest does not declare costs an
    operator a message rather than a materialised run dir nothing will ever fill.
    """
    if ns.resume is None:
        return None
    from defender.runtime.branch._family import FamilyError

    if ns.update_ticket:
        sys.exit(
            "--update-ticket is not available with --resume: a sibling world is a synthetic "
            "continuation of someone else's case, and a ticket row for it would enter the "
            "case history as a real investigation of a real alert")
    try:
        return resume_world(ns.resume, ns.world)
    except FamilyError as refusal:
        sys.exit(f"[run.py] {refusal}")


def _materialize_run_dir(alert: Path, run_id: str | None, *, model: str | None) -> Path:
    """Build this run's directory, stamped with the code and the model it will run on.

    A one-line wrapper, and it earns its place twice. It is the seam `main` injects, so a test
    can observe run-dir creation without a real runs base; and it is the ONE site that names the
    builder, which is what keeps "the run dir has a single origin" a property of this file rather
    than of whoever reads it — two call sites are two places for the stamp to be forgotten.
    """
    run_dir = _run.materialize_run_dir(alert, run_id, model=model)
    return run_dir


def main(  # noqa: PLR0913 — the entry point's inputs plus its six injection seams
    argv: list[str],
    *,
    lifecycle: Callable[..., dict[str, Any]] = _run_investigation_lifecycle,
    visualize: Callable[[Path], None] = _run.visualize,
    ticket_writer: Any = _default_ticket_writer,
    enqueue: Callable[..., bool] = _run.enqueue_curation,
    preflight: Callable[[str | None], int] = preflight_role_models,
    materialize: Callable[..., Path] = _materialize_run_dir,
) -> int:
    # The tail's three UNDRIVABLE dependencies — the credentialed investigation lifecycle, the
    # HTML render, the case-ticket endpoint — take an injection seam, each defaulting to
    # production, so what the tail DOES is observable. The curation trigger below is
    # deliberately NOT part of that seam: it runs for real against a real queue.
    ns = parse_args(argv)
    # RESOLVED AT THE BOUNDARY and threaded inward under its own name: the curation lane is a DI
    # seam, and the name it is called by is what a reader — and the entry point's own shape
    # demand — follows to see that the lane is still reached from here.
    enqueue_curation = enqueue

    # THE SIBLING'S TWO REFUSALS, BOTH BEFORE ANYTHING IS SPENT. `--update-ticket` is refused
    # OUTRIGHT rather than accepted and ignored: the two ticket calls are ordered around the
    # curation marker, so suppressing one of them would break the pairing instead of the
    # obligation. And the world is resolved from the manifest before the run dir exists, so a
    # label the manifest does not declare costs nothing at all.
    world = _resume_target(ns)

    model = driver.resolve_main_model(ns.model)
    # ONE provider-key pass: the all-roles preflight is a strict superset of the
    # investigator+gather pair (same resolvers, same per-provider key sourcing, and MAIN/GATHER
    # are two of the roles it walks). IT RUNS IN THE SIBLING TOO, and the family-level pass the
    # launcher makes is an early exit rather than a substitute: the model is resolved PER
    # PROCESS, so three siblings launched into a changed environment are a comparison across
    # two models unless each one checks and each one records what it resolved.
    rc = preflight(ns.model)
    if rc:
        return rc

    # ONE BUILDER CALL, and the two paths differ only in what they hand it. A sibling's case
    # input is the SOURCE run's alert, screened first because that directory is a prior box's
    # rw bind; an ordinary run's is the operator's own path. The run id follows the same split:
    # a sibling's is derived from the manifest (`{episode_id}-{world}`), an ordinary run's is
    # the operator's `--run-id` or the auto timestamp.
    if world is not None:
        alert = _screened_source_alert(Path(world.family.source_run_dir))
        run_id: str | None = world.run_id
    else:
        alert = ns.alert.resolve()
        run_id = ns.run_id
    run_dir = materialize(alert, run_id, model=model)

    if ns.update_ticket:
        ticket_writer.open_case_ticket(run_dir)

    print(f"[run.py] run_dir={run_dir} model={model}", file=sys.stderr)
    _announce_provenance(run_dir)

    summary = lifecycle(
        run_dir=run_dir,
        model=model,
        model_override=ns.model,
        defender_dir=DEFENDER_DIR,
        world=world,
    )

    # Every consumer below reads the tree the lifecycle just scrubbed. None of them is
    # reachable on a tainted tree: `summary` only exists if the lifecycle returned, and
    # nothing here catches what it raises.
    out = str(summary.get("output") or "")
    print(f"[run.py] done ({summary.get('requests')} model requests); "
          f"output: {out[:200]}", file=sys.stderr)

    print("[run.py] artifacts:", file=sys.stderr)
    for entry in sorted(run_dir.iterdir()):
        sys.stderr.write(f"  {entry.name}\n")
    # The reap scan's verdict is deliberately sited OUTSIDE the tree it judges (§7 D8: in-tree
    # it would be both plantable and forgeable by the box that is root on that mount), so the
    # run-dir listing above can never show it. Named explicitly because this run dir SURVIVES
    # as the artifact an operator opens, and whether the tree was ever walked is part of what
    # they are opening it to find out.
    verdict = box_mod.verdict_path(run_dir)
    sys.stderr.write(
        f"  ../{verdict.name}   (the reap scan's verdict — sits beside the run dir, not in it)\n"
        if verdict.is_file() else
        f"  ../{verdict.name}   MISSING — this tree was never scrubbed\n"
    )

    _run.cross_check_tables(run_dir)

    # There is no automatic feed into the offline learning pipeline: the only path onto the
    # learn queue is the operator's own invocation of the learning entrypoint over a run dir.
    # Catalog curation has its own trigger here instead, behind the tree certification the
    # lifecycle already performed — a corpus optimisation, cheap to lose, so its failure is
    # reported and swallowed rather than costing the investigation its exit status.
    # The case ticket is settled BEFORE the request is published: a curation drainer can start
    # the moment the marker lands, and must never read this case with its ticket still open.
    if ns.update_ticket:
        ticket_writer.close_case_ticket(run_dir)

    # A SIBLING FORCES THE NO-LEARN BRANCH, and that is a POSITIVE refusal rather than an
    # omission. Routing a sibling through this `main` acquires both automatic lanes; a world is
    # a synthetic continuation whose evidence was staged on purpose, so a curation marker for
    # it would feed an authored corpus back into the lesson catalog as if it were a real case.
    if world is not None:
        print("[run.py] --resume: a sibling world is not enqueued for curation",
              file=sys.stderr)
    elif ns.no_learn:
        # Fail-closed: the flag governs catalog curation, the one automatic lane left.
        print("[run.py] --no-learn set; not enqueuing for curation", file=sys.stderr)
    elif enqueue_curation(run_dir, alert, truncated_by=summary.get("truncated_by")):
        print("[run.py] enqueued for catalog curation", file=sys.stderr)

    try:
        visualize(run_dir)
    except _run.VisualizeFailed as e:
        print(f"[run.py] {e}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
