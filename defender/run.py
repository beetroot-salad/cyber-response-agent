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
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("alert", type=Path, help="Path to alert.json fixture")
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
    return p.parse_args(argv)


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
        model_name: str, model_override: str | None, box: Any,
    ) -> dict[str, Any]: ...


def _drive_investigation(
    *,
    alert_path: Path,
    run_dir: Path,
    run_id: str,
    defender_dir: Path,
    model_name: str,
    model_override: str | None,
    box: Any,
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
    """
    verbs = ModuleVerbRegistry(defender_dir / "scripts" / "adapters", driver.GATHER_DEF.verb_grant)
    return asyncio.run(driver.run_investigation(
        alert_path=alert_path,
        run_dir=run_dir,
        run_id=run_id,
        defender_dir=defender_dir,
        model_name=model_name,
        model_override=model_override,
        box=box,
        verbs=verbs,
    ))


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
        )
        investigation_ok = True
    finally:
        box_mod.stop_and_scrub(
            box, run_dir, stop_box=stop_box, scrub_tree=scrub,
            in_flight=not investigation_ok,
        )
    return summary


def main(
    argv: list[str],
    *,
    lifecycle: Callable[..., dict[str, Any]] = _run_investigation_lifecycle,
    visualize: Callable[[Path], None] = _run.visualize,
    ticket_writer: Any = _default_ticket_writer,
) -> int:
    # The tail's three UNDRIVABLE dependencies — the credentialed investigation lifecycle, the
    # HTML render, the case-ticket endpoint — take an injection seam, each defaulting to
    # production, so what the tail DOES is observable. The curation trigger below is
    # deliberately NOT part of that seam: it runs for real against a real queue.
    ns = parse_args(argv)

    model = driver.resolve_main_model(ns.model)
    # ONE provider-key pass: the all-roles preflight is a strict superset of the
    # investigator+gather pair (same resolvers, same per-provider key sourcing, and MAIN/GATHER
    # are two of the roles it walks).
    rc = preflight_role_models(ns.model)
    if rc:
        return rc

    alert = ns.alert.resolve()
    run_dir = _run.materialize_run_dir(alert, ns.run_id)

    if ns.update_ticket:
        ticket_writer.open_case_ticket(run_dir)

    print(f"[run.py] run_dir={run_dir} model={model}", file=sys.stderr)

    summary = lifecycle(
        run_dir=run_dir,
        model=model,
        model_override=ns.model,
        defender_dir=DEFENDER_DIR,
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

    if ns.no_learn:
        # Fail-closed: the flag governs catalog curation, the one automatic lane left.
        print("[run.py] --no-learn set; not enqueuing for curation", file=sys.stderr)
    elif _run.enqueue_curation(run_dir, alert, truncated_by=summary.get("truncated_by")):
        print("[run.py] enqueued for catalog curation", file=sys.stderr)

    try:
        visualize(run_dir)
    except _run.VisualizeFailed as e:
        print(f"[run.py] {e}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
