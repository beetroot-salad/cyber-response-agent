"""Shared machinery for #1224's spec — "branching through a live oracle". NO test functions;
underscore-prefixed so pytest never collects it.

Imported by every test file here as `from defender.tests.live_oracle_1224 import _spec1224 as S`.

The change (`spec-flow/specs/spec_graph_1224.yaml`; `.spec-flow/design-doc.md` as amended by
`.spec-flow/design-amendments.md`, with the human's answers in
`.spec-flow/frontiers/70-resolutions.md`): a sibling's world is served by a live ORACLE at the
`serve_one` seam instead of the staging/applier machinery. A world carries natural-language
`facts`; every uncached call in a world with facts gets one oracle turn (it may `run_query`,
`forge` telemetry, `record_fact`, run `python` in a sandboxed box, self-`check`, then `submit`
a served answer plus a claim), host checks 1-5, and a verifier pass in its own context. N
failed attempts on one call raise `OracleUnservable`, which never reaches the investigator.
Pre-flight replays the original calls through each world's oracle to CALIBRATE (Amendment 2:
it keeps only forged rows and recorded facts, never a served answer) and writes the
write-once episode outcome record (`accepted` / `unusable` / `refused`); a sibling writes its
own per-world record when it goes unservable, the launcher writes "did not finish" when a
sibling process exits without one. The judge model decides each world's bucket.

NONE OF THE NEW NAMES EXISTS AT BASE 96e4cdb0. Every import goes through `mod()` / `sym()` PER
TEST (the `_triplet_947` idiom), so a missing target is one failure per test, never one
collection error hiding the other four hundred.

COINED NAMES LIVE HERE AND NOWHERE ELSE (`COINED` below). The design leaves these names to
the implementer (fork F-01, provisional, non-material); this suite spells them once, and if
write-code-from-spec names anything differently it renames it HERE, never in a test file:

  Module `defender.learning.branch.estate.oracle` (M3/M4/M5/M6/M7/M13):
    * `OracleUnservable(Exception)` with `.reason` (a short word: "retries", "budget",
      "sandbox", ...) and `.call` (the `(system, verb, params)` it failed on).
    * `OracleSandboxError(Exception)` — the oracle's box is not sandboxed (M18, H-05).
    * `start_box(*, env)` — the production oracle box factory; it never yields an
      unsandboxed executor, `DEFENDER_ALLOW_UNSANDBOXED=1` notwithstanding.
    * `oracle_settings(env)` -> an object with `retry_cap`, `rate`, `budget`,
      `turn_deadline`, `model`, `check_model`; a bad knob raises `FatalConfigError` naming it.
    * `check_submission(base, served, claim, *, world, store, real_data)` -> list of failure
      texts (empty = passes) — M4's ONE host checker, shared by the host and the oracle's
      advisory `check` tool.
  Module `defender.learning.branch.estate.limiter`: `RateLimiter(rate, *, clock, sleep)` with
    `.acquire()` — waits, never refuses (M11=A); a limiter that cannot read its own state
    raises (fails closed, S17).

  `WorldRegistry(roster, grant, *, world, ledger, as_of, serving, oracle_dir, limiter, tenant,
    grant_home)` — `serving` is `registry.oracle_serving(settings, *, oracle, verifier, box,
    restart_after)`: `oracle` / `verifier` are pydantic-ai `Model`s (the doubles below are
    `FunctionModel`s), `box` is a zero-arg callable returning a `BoxExecutor`, and `settings`
    the oracle's knobs (`retry_cap`, `turn_deadline`, `budget`, `rate`); `oracle_dir` is the
    world's oracle-side state directory. They are settled once at the boundary and passed in
    whole; `registry_seams` below holds the suite's defaults for the ones a scenario does not
    set.
  `cli.main(argv, *, spawn, questioner, preflight, judge, lessons_dir, live_tree, oracle,
    verifier, roster)` — the launcher; `door=`, `door_transport=`, `adapters=` and `invoke=`
    leave with staging/review. `roster=` is pre-flight's grant-decided reader's roster.
  `run.main(argv, *, ..., oracle, verifier, roster)` — the sibling, the same three seams.
  `Step.PREFLIGHT` between `Step.QUESTIONER` and `Step.RUNS` (F-21); `Step.STAGING` and
    `Step.REVIEW` are gone.
  `AgentRole.ORACLE == "oracle"`, `AgentRole.ORACLE_CHECK == "oracle_check"` (M11).
  `run.preflight_role_models(model_override=None, *, branching=False)` (M25: the oracle roles
    are preflighted only where `branching=True`).

  Oracle tools (the `ToolCallPart.tool_name`s the doubles emit): `run_query(system, verb,
    params)`, `forge(forged_id, fact_id, system, row)`, `record_fact(entity, field, value)`,
    `python(code)`, `check(served, claim)`, `submit(served, claim)` (ends the turn).
  Verifier tools: `run_query(system, verb, params)`, `verdict(passed, reason)` (ends its pass).
  A failed attempt's verdict reaches the oracle's next request naming `check <n>` (1-5) or
  `verifier` (`verdict_names`).

  Claim (`claim()` below): `added: [{forged_id, fact_id}]`, `removed: [{row, side_query:
    {system, verb, params}, count}]`, `changed: [{entity, field, old, new}]`, `counts: [{group,
    base, added, removed, served}]`, `entity_refs: [{forged_id, column, entity}]` (M12=A's
    entity-reference exemption).

  Records (all paths relative to the episode dir):
    * `outcome.yaml` — pre-flight's write-once outcome record: `{outcome: accepted|unusable|
      refused, reason, unservable_worlds: [{world, reason, call}], not_replayable: [{system,
      verb, params, reason}], drift: [{system, verb, params, status: drifted|unknown}]}`. It
      replaces `review.yaml` and `staged.yaml`. An absent or torn one is "no record".
    * `world_records/<label>.yaml` — a world's own record: `{world, reason: "oracle
      unservable"|"did not finish"|"budget", call, detail}`.
    * `oracle/<label>/` — the world's oracle-side state, ONE writer (S19), outside the archive
      tree and the run dir (N14): `forged.jsonl` (frozen rows `{forged_id, fact_id, system,
      row}`), `facts.jsonl` (`{entity, field, value}`), `answers.jsonl` (the served-answer
      cache, `{system, verb, params, served}`), `ledger.jsonl` (the oracle-side ledger:
      `{actor: oracle|verifier|preflight|host-check, system, verb, params}`), `base.jsonl`
      (this world's own live base answers, M16).
    * `samples.yaml` — keyed by system: `{<system>: {verbs: {<verb>: [<answer text>, ...]}}}`
      or `{<system>: {unavailable: <reason>}}`; a citation names `samples.yaml#<system>`.
    * `served/<episode token>.<label>.jsonl` — the world ledger (unchanged path). Decisions
      (`source`): `passthrough`, `oracle`, `real-error`, `refused`, and `fault` only for
      `decide_call`'s adapter-cannot-load row (F-02=A). An `oracle` row also carries
      `base_digest`, `claim`, `verifier_verdict`, `attempts`.
  Manifest v2 (`family_v2`): a world carries `facts: [{fact_id, statement, entities}]` (an
    explicit `facts: []` for the control world, M07=A); the top level carries `served_systems`;
    `discriminator` keeps only `predicate`. `overlay`, `configured_patterns`,
    `captured_patterns`, `discriminator.holding_system` and `discriminator.envelope` refuse the
    manifest naming that it predates the oracle (O15).
  Judge reply v2: a world-scope reply carries a top-level `bucket` (`lead-set`,
    `lead-quality`, `analyze-discipline`, `decision-discipline`, `observability`, `none`) and
    `systems: [..]`; findings carry no `pattern` / `holding_system`. A family-scope reply
    carries `verdict_word` from `JUDGE_OUTCOME_ENUM`. `judge.yaml` records per world `bucket`,
    `systems`, findings, and a family `validity: usable|unusable`.
  Lesson frontmatter: `systems: [..]` replaces `pattern` / `holding_system`.
  Question-writer: `author_family(*, source_run_dir, episode_dir, invoke, leads, alert, frontier,
    served_systems, samples, lessons)` (`stageable_patterns` -> `served_systems`,
    `corpus_samples` -> `samples`, the per-system samples document);
    `_questioner_lessons_section(lessons, *, served_systems)`;
    `cli.system_samples(source_run_dir, served_systems)` -> the samples document.
  Pre-flight: `cli.preflight_replay(episode, *, roster, tenant, oracle, verifier, **knobs)` is
    the coined unit entry; scenarios prefer the whole launcher (`launch`). The launcher hands
    each sibling its rate slice as the CHILD ENV's `ORACLE_RATE` (= R/k, k = worlds launched,
    the control world included), observable on `FakeSpawn.launches[i]["env"]`.
  Knobs (environment, set with `monkeypatch.setenv`): `ORACLE_MODEL`, `ORACLE_CHECK_MODEL`,
    `ORACLE_EFFORT`, `ORACLE_CHECK_EFFORT`, `ORACLE_RETRY_CAP`, `ORACLE_RATE` (queries/second
    per episode), `ORACLE_BUDGET`, `ORACLE_TURN_DEADLINE` (seconds).
  The run's host-only oracle-held sidecar (`RunPaths.oracle_held`, beside the run dir — never
    the box-writable `budget.json`) carries the investigator clock's excluded oracle-held total
    under `oracle_held_seconds` (S15).

EVERY FAULT HERE IS A REAL INPUT THROUGH THE REAL PRIMITIVE, OR A FAKE CITING ITS CLAIM:
  * adapter errors are the real `AdapterFault` subclasses (`scripts/adapters/faults.py`), raised
    by real adapter modules this file plants on disk (GA-40, GD-36: exit 2 for Config/Transport,
    exit 1 for Upstream);
  * the unsandboxed box is a real `BoxExecutor()` (GD-16: `sandboxed` is False for anything
    but a docker transport); the sandboxed one is a `_DockerTransport` subclass that records
    the frame and answers it, the one property GD-16 says tells the two apart;
  * a model's bad submission is SCRIPTED CONTENT the design itself names as the failure (O3:
    "an oracle double that adds an undeclared row, edits a base row silently, or drops a
    covered fact's telemetry");
  * a model provider outage is the exception GPR-01 observed the model client raise once its
    own bounded retries give up: `provider_outage(status)` builds it (`ModelHTTPError` 503 / 429,
    or `ModelAPIError` "Connection error." when no connection is made); a model double raises it
    from a request (`raising(...)` moves, or `Fault(raise_after=n)`);
  * a box run cut off by its time bound raises `subprocess.TimeoutExpired`, unwrapped, out of
    `BoxExecutor.run_parsed` — never a `BoxResult`, never an exit code (GPR-02).

Fakes enter through the injection seams above and never by `monkeypatch.setattr` (the project
profile's `tests.idioms`, `scripts/lint/lint_monkeypatch.py`). Every fake RECORDS what it was
handed; payload demands assert against what the fake saw, never against its canned reply.
"""
from __future__ import annotations

import contextlib
import hashlib
import importlib
import json
import os
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from defender import _yaml
from defender.tests import _triplet_947 as T
from defender.tests import _judge_921 as J
from defender.tests import _tenants1106 as T6

DEFENDER = Path(__file__).resolve().parents[2]
REPO_ROOT = DEFENDER.parent
SPEC_GRAPH = REPO_ROOT / "spec-flow" / "specs" / "spec_graph_1224.yaml"

# --------------------------------------------------------------------------------------
# Per-test imports.
# --------------------------------------------------------------------------------------


def mod(dotted: str):
    """Import `defender.<dotted>` at CALL time, never at collection time."""
    return importlib.import_module(f"defender.{dotted}")


def sym(dotted: str, name: str):
    """One attribute off a lazily-imported module — `AttributeError` is a real red."""
    return getattr(mod(dotted), name)


#: The modules this suite drives, spelled once.
ORACLE = "learning.branch.estate.oracle"          # NEW (coined)
LIMITER = "learning.branch.estate.limiter"        # NEW (coined)
REGISTRY = "learning.branch.estate.registry"
LEDGER = "learning.branch.ledger"
FAMILY = "runtime.branch._family"
CLI = "learning.branch.cli"
EPISODE = "learning.branch.episode"
STEPS = "learning.branch.steps"
QUESTIONER = "learning.branch.questioner"
JUDGE = "learning.judge"
JUDGE_RUN = "learning.judge.run"
JUDGE_RENDER = "learning.judge.render"
JUDGE_ENQUEUE = "learning.judge.enqueue"
VOCAB = "_vocab"
RUN = "run"
QUERY_TOOL = "runtime.query_tool"
VERBS = "runtime.verbs"
AGENT_ROLE = "runtime.agent_role"
VISUALIZE = "scripts.visualize.visualize_episode"
SERIALIZE = "learning.frontend.serialize"
LESSONS_RUN = "learning.author.lessons.run"

#: Every spelling this suite coins (see the module docstring). Renamed here, and only here.
COINED = {
    "module.oracle": f"defender.{ORACLE}",
    "module.limiter": f"defender.{LIMITER}",
    "exc.unservable": "OracleUnservable",
    "exc.sandbox": "OracleSandboxError",
    "fn.start_box": "start_box",
    "fn.settings": "oracle_settings",
    "fn.check": "check_submission",
    "cls.limiter": "RateLimiter",
    "tool.run_query": "run_query",
    "tool.forge": "forge",
    "tool.record_fact": "record_fact",
    "tool.python": "python",
    "tool.check": "check",
    "tool.submit": "submit",
    "tool.verdict": "verdict",
    "record.outcome": "outcome.yaml",
    "record.world_dir": "world_records",
    "record.oracle_dir": "oracle",
    "record.forged": "forged.jsonl",
    "record.facts": "facts.jsonl",
    "record.answers": "answers.jsonl",
    "record.oracle_ledger": "ledger.jsonl",
    "record.world_base": "base.jsonl",
    "record.samples": "samples.yaml",
    "decision.oracle": "oracle",
    "decision.real_error": "real-error",
    "role.oracle": "oracle",
    "role.oracle_check": "oracle_check",
    "step.preflight": "PREFLIGHT",
    "knob.model": "ORACLE_MODEL",
    "knob.check_model": "ORACLE_CHECK_MODEL",
    "knob.retry_cap": "ORACLE_RETRY_CAP",
    "knob.rate": "ORACLE_RATE",
    "knob.budget": "ORACLE_BUDGET",
    "knob.turn_deadline": "ORACLE_TURN_DEADLINE",
    "knob.effort": "ORACLE_EFFORT",
    "knob.check_effort": "ORACLE_CHECK_EFFORT",
    "fn.preflight": "preflight_replay",
    "budget.oracle_held": "oracle_held_seconds",
    "fn.samples": "system_samples",
    "kw.served_systems": "served_systems",
    "kw.samples": "samples",
    "reason.unservable": "oracle unservable",
    "reason.did_not_finish": "did not finish",
    "reason.budget": "budget",
}

# Names, as the tests spell them.
OUTCOME_NAME = COINED["record.outcome"]
WORLD_RECORDS = COINED["record.world_dir"]
ORACLE_DIRNAME = COINED["record.oracle_dir"]
SAMPLES_NAME = COINED["record.samples"]
PASSTHROUGH = "passthrough"
ORACLE_DECISION = COINED["decision.oracle"]
REAL_ERROR = COINED["decision.real_error"]
REFUSED = "refused"
FAULT = "fault"
RETIRED_DECISIONS = ("staged", "patched")
OUTCOMES = ("accepted", "unusable", "refused")
RETIRED_OUTCOME = "incomplete"
REASON_UNSERVABLE = COINED["reason.unservable"]
REASON_DID_NOT_FINISH = COINED["reason.did_not_finish"]
REASON_BUDGET = COINED["reason.budget"]
BUCKETS = ("lead-set", "lead-quality", "analyze-discipline", "decision-discipline",
           "observability", "none")
OLD_MANIFEST_KEYS = ("overlay", "discriminator.holding_system", "discriminator.envelope",
                     "captured_patterns", "configured_patterns")
PREDATES = "predates the oracle"

ORACLE_HELD_KEY = COINED["budget.oracle_held"]
KNOB_MODEL = COINED["knob.model"]
KNOB_CHECK_MODEL = COINED["knob.check_model"]
KNOB_RETRY_CAP = COINED["knob.retry_cap"]
KNOB_RATE = COINED["knob.rate"]
KNOB_BUDGET = COINED["knob.budget"]
KNOB_TURN_DEADLINE = COINED["knob.turn_deadline"]
KNOB_EFFORT = COINED["knob.effort"]
KNOB_CHECK_EFFORT = COINED["knob.check_effort"]
UNSANDBOXED_ENV = "DEFENDER_ALLOW_UNSANDBOXED"


def unservable_cls() -> type[BaseException]:
    return sym(ORACLE, COINED["exc.unservable"])


def sandbox_error_cls() -> type[BaseException]:
    return sym(ORACLE, COINED["exc.sandbox"])


def judge_refused_cls() -> type[BaseException]:
    return sym(JUDGE, "JudgeRefused")


# Re-exported from the #947 / #921 machinery, unchanged.
EPISODE_ID = T.EPISODE_ID
EPISODE_TOKEN = T.EPISODE_TOKEN
SOURCE_RUN_ID = T.SOURCE_RUN_ID
AS_OF = T.AS_OF
AS_OF_DT = datetime(2026, 7, 28, 16, 18, 45, tzinfo=UTC)
WORLDS = ("a", "b", "c")
Fault = T.Fault
CLEAN = T.CLEAN
FakeSpawn = T.FakeSpawn
FakeAgent = T.FakeAgent
FakeJudge = J.FakeJudge


def no_preflight(*_args: Any, **_kw: Any) -> int:
    """The role-model preflight, neutralised (`_triplet_947.no_preflight`'s reasoning), taking
    any arguments: M25 adds a keyword (`branching=`) the one-argument #947 spelling would
    refuse with a TypeError."""
    return 0

world_token = T.world_token
untrusted_frames = T.untrusted_frames
outside_untrusted_frames = T.outside_untrusted_frames
assert_wrapped_untrusted = T.assert_wrapped_untrusted
as_reply_text = J.as_reply_text


def judge_reply(*, systems: tuple[str, ...] = ("idp",), bucket: str = "lead-set") -> str:
    """A judge reply in the coined v2 shape: a world-scope `bucket` and `systems`, plus the
    family-scope `verdict_word`, so one default answers both scopes."""
    return as_reply_text(J.reply_doc(findings=[], bucket=bucket, systems=list(systems),
                                     verdict_word="caught"))


def judge_label(agent_id: str) -> str | None:
    """The world a judge call is about, from its agent id: `judge:<label>:<n>` -> `<label>`
    (the family-scope call is `judge:family:<n>`)."""
    parts = str(agent_id).split(":")
    return parts[1] if len(parts) >= 3 and parts[0] == "judge" else None


def judge_called_for(judge: FakeJudge, label: str) -> bool:
    """Whether the judge model was called for world `label` (agent id `judge:<label>:<n>`)."""
    return any(str(a).startswith(f"judge:{label}:") for a in judge.agent_ids)
archived_judge_world = J.archived_judge_world


#: The model name GPR-01's probe saw on the provider error (Anthropic arm).
OUTAGE_MODEL = "claude-sonnet-4-5"

#: A model `defender._pricing` prices (R-08): every model double is named after it, so an oracle
#: request accrues positive spend whatever unit the implementer picks (USD from pricing, request
#: count, tokens). D1 dropped the unpriced-model fallback from the spec; no test may lean on it.
PRICED_MODEL = "claude-sonnet-4-6"


def double_model_name(role: str) -> str:
    """The model name every double carries: `fake-<role>/<PRICED_MODEL>`. `_pricing` keeps only
    the part after the last `/` (it strips a registry path), so the double is priced, and the
    `fake-<role>` head still marks its traffic in any log a test reads."""
    return f"fake-{role}/{PRICED_MODEL}"
#: HTTP statuses GPR-01 observed: a provider outage (5xx) and a rate limit (429).
OUTAGE = 503
RATE_LIMITED = 429


def provider_outage(status: int | None = OUTAGE, *,
                    model_name: str = OUTAGE_MODEL) -> Exception:
    """What the oracle's / verifier's model client raises once its own bounded transient
    retries give up — GPR-01 (executed against a local stub server, Anthropic and Fireworks
    alike): `ModelHTTPError(status_code, model_name, body)` for a 5xx outage or a 429 it could
    not absorb, `ModelAPIError(model_name, "Connection error.")` when no connection is made
    (`status=None`). The SDK's retries sit below the model layer, so a model double raises
    this once per request. Returns a FRESH instance each call; the caller raises it."""
    from pydantic_ai.exceptions import ModelAPIError, ModelHTTPError

    if status is None:
        return ModelAPIError(model_name, "Connection error.")
    return ModelHTTPError(status, model_name, {
        "type": "error", "error": {"type": "api_error",
                                   "message": f"provider answered {status}"}})


# --------------------------------------------------------------------------------------
# The fixture tenant (O1): systems that are not the lab's, served by stub adapters on disk.
# --------------------------------------------------------------------------------------

#: The fixture tenant's systems — O1's own example, none of them a lab system.
SYSTEMS = ("edr", "idp", "siem-x")
LAB_SYSTEMS = ("change-mgmt", "cmdb", "elastic", "host-state", "identity", "tacit-knowledge",
               "threat-intel", "ticket")
FIXTURE_TENANT = "acme"

#: One stub adapter module, planted per system. It reads its answers from the estate's JSON
#: file AT CALL TIME (so a scenario may change an answer mid-test) and appends every call it
#: receives — with `ctx.as_of` — to the estate's call log. Faults are the REAL `AdapterFault`
#: subclasses (GA-40 / GD-36), so the query tool classifies them as it does on a real run.
_ADAPTER = '''\
"""Stub adapter for the #1224 fixture tenant: system {system!r}. Planted by _spec1224."""
from __future__ import annotations

import json
import time
from pathlib import Path

from defender.runtime.verbs import VerbContext, verb
from defender.scripts.adapters import faults

_STATE = Path({state!r})
SYSTEM = {system!r}


def _answer(ctx: VerbContext, name: str, params: dict):
    as_of = getattr(ctx, "as_of", None)
    row = {{"system": SYSTEM, "verb": name, "params": params,
           "as_of": None if as_of is None else as_of.isoformat(),
           "world_id": getattr(ctx, "world_id", None),
           "run_dir": str(getattr(ctx, "run_dir", "")), "t": time.time()}}
    with (_STATE / "calls.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row, sort_keys=True) + "\\n")
    table = json.loads((_STATE / "answers.json").read_text(encoding="utf-8"))
    key = SYSTEM + "|" + name + "|" + json.dumps(params, sort_keys=True, separators=(",", ":"))
    entry = table.get(key) or table.get(SYSTEM + "|" + name + "|*")
    if entry is None:
        return {{"rows": []}}
    if "fault" in entry:
        raise getattr(faults, entry["fault"])(entry.get("detail", "upstream said no"))
    return entry["payload"]


@verb()
def query(ctx: VerbContext, *, q: str = "*", start: str = "", end: str = "",
          limit: int = 50) -> dict:
    return _answer(ctx, "query", {{"q": q, "start": start, "end": end, "limit": limit}})


@verb()
def lookup(ctx: VerbContext, *, entity: str) -> dict:
    return _answer(ctx, "lookup", {{"entity": entity}})


@verb()
def health_check(ctx: VerbContext) -> dict:
    return _answer(ctx, "health-check", {{}})


@verb(verb_class="rw")
def isolate(ctx: VerbContext, *, host: str) -> dict:
    return _answer(ctx, "isolate", {{"host": host}})


VERBS = {{"query": query, "lookup": lookup, "health-check": health_check, "isolate": isolate}}
'''

#: The read verbs every fixture system declares, and the one write verb no grant names.
READ_VERBS = ("query", "lookup", "health-check")
WRITE_VERB = "isolate"


def canonical(params: Mapping[str, Any]) -> str:
    """Canonical JSON of a params map (N08: the cache key's spelling)."""
    return json.dumps(params, sort_keys=True, separators=(",", ":"))


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def query_params(q: str = "*", *, start: str = "", end: str = "", limit: int = 50) -> dict:
    """The full params a stub `query` verb is called with (the adapter logs every one)."""
    return {"q": q, "start": start, "end": end, "limit": limit}


@dataclass
class Estate:
    """The fixture tenant's estate: a fake `defender_dir` whose `scripts/adapters/` holds one
    stub adapter per system, its answers table and its call log.

    `withheld` names `(system, verb)` pairs the tenant's grant table gives no role (with a
    reason) — `isolate` is always withheld, so the write verb exists and is never granted (O6's
    "no branching path reaches a write door" has a door to not reach).
    """

    root: Path
    systems: tuple[str, ...] = SYSTEMS
    withheld: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        self.root = Path(self.root)
        self.state.mkdir(parents=True, exist_ok=True)
        self.adapters.mkdir(parents=True, exist_ok=True)
        if not (self.state / "answers.json").exists():
            (self.state / "answers.json").write_text("{}", encoding="utf-8")
        (self.state / "calls.jsonl").touch()
        for system in self.systems:
            (self.adapters / f"{system.replace('-', '_')}_adapter.py").write_text(
                _ADAPTER.format(system=system, state=str(self.state)), encoding="utf-8")

    # --- where things are --------------------------------------------------------------
    @property
    def defender_dir(self) -> Path:
        return self.root

    @property
    def adapters(self) -> Path:
        return self.root / "scripts" / "adapters"

    @property
    def state(self) -> Path:
        return self.root / "_estate"

    # --- scripting answers -------------------------------------------------------------
    def _table(self) -> dict:
        return json.loads((self.state / "answers.json").read_text(encoding="utf-8"))

    def _put(self, key: str, entry: dict) -> None:
        table = self._table()
        table[key] = entry
        (self.state / "answers.json").write_text(json.dumps(table, sort_keys=True),
                                                 encoding="utf-8")

    def answer(self, system: str, verb: str, params: Mapping[str, Any] | None,
               payload: Any) -> Any:
        """What the real system answers to this exact call (`params=None`: to any call)."""
        key = f"{system}|{verb}|" + ("*" if params is None else canonical(params))
        self._put(key, {"payload": payload})
        return payload

    def fail(self, system: str, verb: str, params: Mapping[str, Any] | None, *,
             fault: str = "UpstreamFault", detail: str = "upstream said no") -> None:
        """The real system errors on this call — a REAL `AdapterFault` subclass (GA-40)."""
        assert fault in ("UpstreamFault", "TransportFault", "ConfigFault", "AdapterFault"), fault
        key = f"{system}|{verb}|" + ("*" if params is None else canonical(params))
        self._put(key, {"fault": fault, "detail": detail})

    # --- observing ---------------------------------------------------------------------
    def calls(self, system: str | None = None, verb: str | None = None) -> list[dict]:
        """Every call any stub adapter RECEIVED (the wire, as the tenant saw it)."""
        rows = read_jsonl(self.state / "calls.jsonl")
        return [r for r in rows if (system is None or r["system"] == system)
                and (verb is None or r["verb"] == verb)]

    # --- the tenant --------------------------------------------------------------------
    def table(self) -> str:
        """The tenant's `verb-grants.yaml`: gather reads every read verb not withheld."""
        lines = ["dispositions:"]
        for system in self.systems:
            lines.append(f"  {system}:")
            for verb in (*READ_VERBS, WRITE_VERB):
                if verb == WRITE_VERB or (system, verb) in self.withheld:
                    lines.append(f'    {verb}: {{roles: [], reason: "withheld by the #1224 '
                                 'fixture on purpose"}')
                else:
                    lines.append(f"    {verb}: {{roles: [gather]}}")
        return "\n".join(lines) + "\n"

    def roster(self) -> Any:
        return sym(VERBS, "read_roster")(self.adapters)

    def place(self, data_root: Path | None = None, tenant_id: str = FIXTURE_TENANT) -> Any:
        """Set the tenant up under the data root (`DEFENDER_DATA_ROOT` by default) and return
        it accepted (`Tenant`)."""
        root = Path(data_root if data_root is not None else os.environ["DEFENDER_DATA_ROOT"])
        if not (root / tenant_id / "tenant.json").is_file():
            T6.place_tenant(root, tenant_id, table=self.table(), configs={})
        return T6.accept(root, tenant_id)

    def run_tenant(self, data_root: Path | None = None,
                   tenant_id: str = FIXTURE_TENANT) -> Any:
        return T6.run_tenant(self.place(data_root, tenant_id))

    def grant(self, data_root: Path | None = None, tenant_id: str = FIXTURE_TENANT) -> Any:
        """The tenant's gather `VerbGrant` — the grant every branching query goes through."""
        return self.run_tenant(data_root, tenant_id).grants.gather

    def served_systems(self) -> list[str]:
        """M20's served set: a system with at least one non-health-check read verb granted."""
        return sorted(s for s in self.systems
                      if any((s, v) not in self.withheld for v in ("query", "lookup")))

    def ctx(self, run_dir: Path, *, tenant: Any = None, **kw: Any) -> Any:
        """A `VerbContext` for the investigator's side of a call."""
        run_dir = Path(run_dir)
        run_dir.mkdir(parents=True, exist_ok=True)
        return sym(VERBS, "VerbContext")(
            defender_dir=self.defender_dir, run_dir=run_dir, env={},
            tenant=tenant if tenant is not None else self.run_tenant(), **kw)


def estate(tmp_path: Path, **kw: Any) -> Estate:
    return Estate(tmp_path / "estate", **kw)


# --------------------------------------------------------------------------------------
# The model doubles (the oracle and the verifier): pydantic-ai FunctionModels driven by DATA.
# --------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Move:
    """One model request's answer: a tool call (`tool`, `args`) or, with `tool=None`, a
    text-only reply (`text`) — a turn that ends without a valid submission (M03=A)."""

    tool: str | None
    args: dict = field(default_factory=dict)
    text: str = ""
    #: A provider failure instead of an answer: a zero-argument factory of the exception the
    #: request raises (`raising(...)`; GPR-01). Called per request, so each raise is fresh.
    raises: Callable[[], BaseException] | None = None


def raising(status: int | None = OUTAGE) -> Move:
    """A model request that fails as the provider client fails once its retries give up
    (GPR-01): `provider_outage(status)`, built fresh for each request this move answers."""
    return Move(None, raises=lambda: provider_outage(status))


def run_query(system: str, verb: str, params: Mapping[str, Any] | None = None) -> Move:
    return Move(COINED["tool.run_query"], {"system": system, "verb": verb,
                                           "params": dict(params or {})})


def forge(forged_id: str, fact_id: str, system: str, row: Mapping[str, Any]) -> Move:
    return Move(COINED["tool.forge"], {"forged_id": forged_id, "fact_id": fact_id,
                                       "system": system, "row": dict(row)})


def record_fact(entity: str, field_: str, value: Any) -> Move:
    return Move(COINED["tool.record_fact"], {"entity": entity, "field": field_, "value": value})


def python(code: str) -> Move:
    return Move(COINED["tool.python"], {"code": code})


def check(served: Any, claim_: Mapping[str, Any] | None = None) -> Move:
    return Move(COINED["tool.check"], {"served": served, "claim": dict(claim_ or claim())})


def submit(served: Any, claim_: Mapping[str, Any] | None = None) -> Move:
    return Move(COINED["tool.submit"], {"served": served, "claim": dict(claim_ or claim())})


def verdict(passed: bool, reason: str = "the fact's telemetry is present and plausible") -> Move:
    return Move(COINED["tool.verdict"], {"passed": passed, "reason": reason})


def text_only(text: str = "I could not decide what to serve.") -> Move:
    return Move(None, text=text)


def claim(*, added: Iterable[Mapping] = (), removed: Iterable[Mapping] = (),
          changed: Iterable[Mapping] = (), counts: Iterable[Mapping] = (),
          entity_refs: Iterable[Mapping] = ()) -> dict:
    """A claim document (coined schema; see the module docstring)."""
    return {"added": [dict(a) for a in added], "removed": [dict(r) for r in removed],
            "changed": [dict(c) for c in changed], "counts": [dict(c) for c in counts],
            "entity_refs": [dict(e) for e in entity_refs]}


EMPTY_CLAIM = claim()


def added(forged_id: str, fact_id: str) -> dict:
    return {"forged_id": forged_id, "fact_id": fact_id}


def removed(row: Mapping[str, Any], *, system: str, verb: str, params: Mapping[str, Any],
            count: int) -> dict:
    return {"row": dict(row), "side_query": {"system": system, "verb": verb,
                                             "params": dict(params)}, "count": count}


def changed(entity: str, field_: str, old: Any, new: Any) -> dict:
    return {"entity": entity, "field": field_, "old": old, "new": new}


def counted(group: str, *, base: int, added_: int = 0, removed_: int = 0,
            served: int | None = None) -> dict:
    return {"group": group, "base": base, "added": added_, "removed": removed_,
            "served": base + added_ - removed_ if served is None else served}


def entity_ref(forged_id: str, column: str, entity: str) -> dict:
    return {"forged_id": forged_id, "column": column, "entity": entity}


def _messages_text(messages: Any) -> str:
    """Everything the HOST handed the model: the parts of every `ModelRequest` (system
    prompt, user turns, tool returns, retry prompts) — never the model's own earlier
    `ModelResponse`s, whose tool-call args are the model's text, not the host's."""
    from pydantic_ai.messages import ModelRequest

    out: list[str] = []
    for msg in messages:
        if not isinstance(msg, ModelRequest):
            continue
        for part in getattr(msg, "parts", []):
            content = getattr(part, "content", None)
            if content is not None:
                out.append(content if isinstance(content, str) else json.dumps(
                    content, sort_keys=True, default=str))
    return "\n".join(out)


def _usage_without_utf8(messages: list[Any], response: Any) -> None:
    """Give `response` a usage estimate when its tool-call args cannot be encoded as UTF-8
    JSON (a lone surrogate, s_p084). `FunctionModel` estimates usage itself by UTF-8-encoding
    the args and raises on such a value before the host ever sees the response — a limit of
    the double, not of a provider (a real provider reports usage and hands the args over). The
    estimate is the one `FunctionModel` would make over the JSON-escaped form; any response
    whose args do encode is left untouched (FunctionModel estimates it as before)."""
    import pydantic_core
    from pydantic_ai.messages import ModelResponse, ToolCallPart
    from pydantic_ai.models.function import _estimate_usage

    part = response.parts[0]
    try:
        pydantic_core.to_json(part.args)
    except pydantic_core.PydanticSerializationError:
        escaped = ModelResponse(parts=[ToolCallPart(tool_name=part.tool_name,
                                                    args=json.dumps(part.args))])
        response.usage = _estimate_usage([*messages, escaped])


class ScriptedModel:
    """A recording, fault-injecting model double: each model request pops the next `Move`.

    Tier 2 of the fault hierarchy: a model is neither cheap nor deterministic to drive, so its
    replies are SCRIPTED and everything it is handed is RECORDED — `seen` (every request's
    INBOUND text: the host-authored `ModelRequest` parts plus the agent's instructions; the
    double's own earlier tool-call args are not in it), `messages` (the raw message lists),
    `tools` (the tool names offered on each request). Payload demands assert against these.

    `fault` is data: `delay` sleeps that many seconds before each answer (oracle latency, O4's
    "an investigator time limit fires because of oracle latency"); `raise_after=n` is a
    provider outage after n answers (`provider_outage()`, GPR-01). A `raising(...)` move is
    the same failure at one point of the script.

    `then` is the move repeated once the script is spent (e.g. a verifier that always passes);
    without it a spent script answers text-only and sets `overrun`, which a scenario asserts
    False — a double cannot invent a submission.
    """

    __name__ = "ScriptedModel"

    def __init__(self, *moves: Move, then: Move | None = None, fault: Fault = CLEAN,
                 name: str = "scripted") -> None:
        self.moves = list(moves)
        self._script = list(moves)
        self.then = then
        self.fault = fault
        self.name = name
        self.seen: list[str] = []
        self.messages: list[list[Any]] = []
        self.tools: list[tuple[str, ...]] = []
        self.instructions: list[str] = []
        self.answered = 0
        self.overrun = False
        self.started: list[float] = []
        self.finished: list[float] = []
        self._lock = threading.Lock()
        self._model: Any = None

    @property
    def model(self) -> Any:
        """The pydantic-ai `Model` handed to the seam (one per double, built on first use)."""
        if self._model is None:
            from pydantic_ai.models.function import FunctionModel
            self._model = FunctionModel(self._answer, model_name=double_model_name(self.name))
        return self._model

    async def _answer(self, messages: list[Any], info: Any) -> Any:
        """The scripted answer from a worker thread the caller may stop waiting on, as a real
        provider's request can be cancelled mid-flight: a host deadline cuts a slow (`delay`)
        answer off when it passes, not when the double's sleep happens to end."""
        import anyio.to_thread

        return await anyio.to_thread.run_sync(self, messages, info, abandon_on_cancel=True)

    def __call__(self, messages: list[Any], info: Any) -> Any:
        from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart

        with self._lock:
            self.started.append(time.monotonic())
            instructions = getattr(info, "instructions", None) or ""
            self.instructions.append(instructions)
            self.seen.append(_messages_text(messages) + "\n" + instructions)
            self.messages.append(list(messages))
            offered = [*getattr(info, "function_tools", ()), *getattr(info, "output_tools", ())]
            self.tools.append(tuple(sorted(t.name for t in offered)))
            if self.fault.raise_after is not None and self.answered >= self.fault.raise_after:
                self.finished.append(time.monotonic())
                raise provider_outage()  # GPR-01
            if self.moves:
                move = self.moves.pop(0)
            elif self.then is not None:
                move = self.then
            else:
                self.overrun = True
                move = text_only("(script spent)")
            self.answered += 1
        if self.fault.delay:
            time.sleep(self.fault.delay)
        self.finished.append(time.monotonic())
        if move.raises is not None:
            raise move.raises()  # GPR-01
        if move.tool is None:
            return ModelResponse(parts=[TextPart(content=move.text)])
        response = ModelResponse(parts=[ToolCallPart(tool_name=move.tool, args=dict(move.args))])
        _usage_without_utf8(messages, response)
        return response

    # --- observing ---------------------------------------------------------------------
    @property
    def requests(self) -> int:
        return len(self.seen)

    def all_seen(self) -> str:
        return "\n".join(self.seen)

    def submissions(self) -> int:
        """How many `submit` moves were consumed (one per attempt that submitted)."""
        return sum(1 for m in self.consumed if m.tool == COINED["tool.submit"])

    @property
    def consumed(self) -> list[Move]:
        """The moves answered so far, in order (the repeated `then` included)."""
        out = self._script[: self.answered]
        if self.answered > len(self._script) and self.then is not None:
            out = out + [self.then] * (self.answered - len(self._script))
        return out


def oracle(*moves: Move, then: Move | None = None, fault: Fault = CLEAN) -> ScriptedModel:
    return ScriptedModel(*moves, then=then, fault=fault, name="oracle")


def verifier(*moves: Move, then: Move | None = None, fault: Fault = CLEAN) -> ScriptedModel:
    return ScriptedModel(*moves, then=then, fault=fault, name="verifier")


def passing_verifier(*, fault: Fault = CLEAN) -> ScriptedModel:
    """A verifier that passes every submission it is shown (and records what it was shown)."""
    return verifier(then=verdict(True), fault=fault)


def failing_verifier(reason: str = "fact f1's logon is missing from the served answer",
                     *, fault: Fault = CLEAN) -> ScriptedModel:
    return verifier(then=verdict(False, reason), fault=fault)


def verdict_names(text: str, what: str) -> bool:
    """Whether a failure verdict the host appended names `what` — `"check 1"`.. `"check 5"`
    or `"verifier"` (coined spelling, case-insensitive)."""
    return what.lower() in text.lower()


def all_parts_text(messages: list[Any]) -> str:
    """Every part of one request's message list, the model's own replies (text and tool-call
    args) included — for asserting something is NOWHERE in a context. `ScriptedModel.seen`
    (host-authored request parts only) skips a handed-down history; this does not."""
    out: list[str] = []
    for msg in messages:
        for part in getattr(msg, "parts", []):
            for attr in ("content", "args"):
                value = getattr(part, attr, None)
                if value is not None:
                    out.append(value if isinstance(value, str)
                               else json.dumps(value, sort_keys=True, default=str))
    return "\n".join(out)


def host_tail(messages: list[Any]) -> str:
    """The host-authored request parts after the model's last response in one request's
    message list — the tool return, retry prompt or verdict the host appended to the move just
    made. The static instructions are not in it, so a verdict naming a check is the host's
    verdict, not the prompt's prose."""
    from pydantic_ai.messages import ModelRequest, ModelResponse

    last = -1
    for i, msg in enumerate(messages):
        if isinstance(msg, ModelResponse):
            last = i
    out: list[str] = []
    for msg in messages[last + 1:]:
        if not isinstance(msg, ModelRequest):
            continue
        for part in msg.parts:
            content = getattr(part, "content", None)
            if content is None:
                continue
            out.append(content if isinstance(content, str)
                       else json.dumps(content, sort_keys=True, default=str))
    return "\n".join(out)


# --------------------------------------------------------------------------------------
# The oracle's box (M18): sandboxed and recording, or the real unsandboxed executor.
# --------------------------------------------------------------------------------------


@dataclass
class BoxLog:
    frames: list[bytes] = field(default_factory=list)
    starts: int = 0

    def requests(self) -> list[Any]:
        decode = sym("runtime.box_codec", "decode_request")
        return [decode(f) for f in self.frames]


def sandboxed_box(log: BoxLog | None = None, *, out: bytes = b"", rc: int = 0,
                  kill_after: int | None = None) -> tuple[Callable[[], Any], BoxLog]:
    """A box FACTORY whose executors are sandboxed (`_DockerTransport`, GD-16) and record each
    frame. `kill_after=n` makes the n+1-th frame on one box fail as a dead container does
    (`BoxFault`), so N11's "a killed box is a tool error and a fresh box is started" is
    observable as `log.starts`."""
    spec_mod = mod("runtime.box._spec")
    codec = mod("runtime.box_codec")
    log = log if log is not None else BoxLog()  # lint-default: ok — a test builder's fresh per-call double or fixture, never a shared instance

    @dataclass(frozen=True)
    class _Recording(spec_mod._DockerTransport):
        sink: Any = None
        served: Any = None

        def __call__(self, frame: bytes, *, cwd: Path, timeout: float) -> Any:
            self.sink.frames.append(frame)
            self.served.append(frame)
            if kill_after is not None and len(self.served) > kill_after:
                raise spec_mod.BoxFault("the box was killed (container gone)")
            return codec.RawExec(rc=rc, stdout=codec.encode_response(
                codec.BoxResult(rc=rc, out=out, err=b"")), stderr=b"")

    def factory() -> Any:
        log.starts += 1
        transport = _Recording(name=f"oracle-box-{log.starts}", spec=spec_mod.BoxSpec(),
                               sink=log, served=[])
        return spec_mod.BoxExecutor(spec=spec_mod.BoxSpec(), transport=transport,
                                    name=transport.name)

    return factory, log


def unsandboxed_box() -> tuple[Callable[[], Any], BoxLog]:
    """A box factory handing out the REAL default executor: `BoxExecutor()`, `sandboxed`
    False (GD-16). It records the factory starts; it has no frames to record, because its
    transport is the real `_unattached` one, which raises `BoxFault` on any frame."""
    log = BoxLog()

    def factory() -> Any:
        log.starts += 1
        return sym("runtime.box._spec", "BoxExecutor")()

    return factory, log


# --------------------------------------------------------------------------------------
# Manifest v2 and the episode on disk.
# --------------------------------------------------------------------------------------


def fact(fact_id: str = "f1",
         statement: str = "alice obtained a TGT and logged on to db-1 at 15:22Z",
         entities: Iterable[str] = ("alice", "db-1")) -> dict:
    return {"fact_id": fact_id, "statement": statement, "entities": list(entities)}


def world_v2(label: str, *, facts: list[dict] | None = None, role: str = "B",
             story: str = "a story", axis: str | None = "an axis",
             disposition_declared: str = "malicious", label_basis: str = "policy-rule",
             **over: Any) -> dict:
    """One v2 world. `facts=None` gives one default fact; pass `[]` for a control world."""
    doc = {"world_id": label, "role": role, "story": story, "axis": axis,
           "disposition_declared": disposition_declared, "label_basis": label_basis,
           "facts": [fact()] if facts is None else facts}
    doc.update(over)
    return doc


def control_world(label: str = "a", **over: Any) -> dict:
    """M07=A's control world: an EXPLICIT `facts: []`."""
    return world_v2(label, facts=[], role="A", axis=None,
                    disposition_declared=over.pop("disposition_declared", "benign"), **over)


def family_v2(*, worlds: list[dict] | None = None,
              served_systems: Iterable[str] = SYSTEMS, source_run_dir: str = "/runs/source",
              as_of: str = AS_OF, predicate: str = "did the analyst look at idp after the "
              "branch", **over: Any) -> dict:
    """A v2 `Family` document: facts in place of overlays, `served_systems` recorded."""
    doc: dict[str, Any] = {
        "episode_id": EPISODE_ID,
        "source_run_dir": source_run_dir,
        "source_run_id": SOURCE_RUN_ID,
        "branch_message_id": T.BRANCH_MESSAGE_ID,
        "fences_at": 4,
        "as_of": as_of,
        "continuation_prompt": "Continue from here.",
        "base_story": "the captured story",
        "served_systems": list(served_systems),
        "discriminator": {"predicate": predicate},
        "worlds": worlds if worlds is not None else [
            control_world("a"),
            world_v2("b", facts=[fact("f1")]),
            world_v2("c", role="C", facts=[fact("f2", "bob reset carol's password from 10.0.0.9",
                                                ("bob", "carol", "10.0.0.9"))]),
        ],
    }
    doc.update(over)
    return doc


def old_manifest(key: str, *, value: Any = None) -> dict:
    """A v2 document carrying ONE pre-oracle key (O15). `key` is one of `OLD_MANIFEST_KEYS`."""
    doc = family_v2()
    defaults = {
        "overlay": {"patches": {"identity": {"web-1": {"owner": "platform"}}}},
        "discriminator.holding_system": "elastic",
        "discriminator.envelope": {"system": "elastic", "verb": "esql",
                                   "params": {"query": "FROM logs-* | LIMIT 5"}},
        "captured_patterns": ["logs-*"],
        "configured_patterns": ["logs-*"],
    }
    v = defaults[key] if value is None else value
    if key == "overlay":
        doc["worlds"][1]["overlay"] = v
    elif key.startswith("discriminator."):
        doc["discriminator"][key.split(".", 1)[1]] = v
    else:
        doc[key] = v
    return doc


def episode_v2(tmp_path: Path, *, doc: dict | None = None, root: Path | None = None,
               episode_id: str = EPISODE_ID, base_rows: list[dict] | None = None) -> Path:
    """An episode dir with a v2 manifest and a primed base recording (`served/base.jsonl`)."""
    ep = T.episode(tmp_path, doc=doc if doc is not None else family_v2(), root=root,
                   episode_id=episode_id)
    if base_rows is not None:
        T.base_capture(ep, base_rows)
    return ep


def write_manifest(ep: Path, doc: dict) -> Path:
    return T.write_family(ep, doc)


def captured(system: str, verb: str, params: Mapping[str, Any], payload: Any, *,
             key: str | None = None) -> dict:
    """One captured row of the family's base recording (the source run's own call)."""
    return {"system": system, "verb": verb,
            "correlation_key": key or f"{system}|{verb}|{canonical(params)}",
            "params": dict(params), "payload_text": json.dumps(payload, sort_keys=True),
            "source": "captured", "world_id": None}


def base_recording(ep: Path, rows: list[dict]) -> Path:
    return T.base_capture(ep, rows)


def outcome_record(ep: Path, outcome: str = "accepted", *, reason: str = "",
                   unservable: Iterable[Mapping] = (), not_replayable: Iterable[Mapping] = (),
                   drift: Iterable[Mapping] = (), family_stamp: bool = True) -> Path:
    """Write pre-flight's outcome record by hand (for readers' scenarios). An `accepted`
    record also gets `verify_family`'s family stamp (`J.comparable_family_stamp`) unless
    `family_stamp=False`: PR #1232 round 7 grades and compares only a stamped family."""
    path = Path(ep) / OUTCOME_NAME
    path.write_text(_yaml.safe_dump({
        "outcome": outcome, "reason": reason,
        "unservable_worlds": [dict(u) for u in unservable],
        "not_replayable": [dict(n) for n in not_replayable],
        "drift": [dict(d) for d in drift]}), encoding="utf-8")
    if family_stamp and outcome == "accepted":
        J.comparable_family_stamp(Path(ep))
    return path


def read_outcome(ep: Path) -> dict | None:
    path = Path(ep) / OUTCOME_NAME
    if not path.is_file():
        return None
    return _yaml.safe_load(path.read_text(encoding="utf-8"))


def world_record(ep: Path, label: str, reason: str = REASON_UNSERVABLE, *,
                 call: Mapping[str, Any] | None = None, detail: str = "") -> Path:
    path = Path(ep) / WORLD_RECORDS / f"{label}.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_yaml.safe_dump({"world": label, "reason": reason,
                                     "call": dict(call) if call else None, "detail": detail}),
                    encoding="utf-8")
    return path


def read_world_record(ep: Path, label: str) -> dict | None:
    path = Path(ep) / WORLD_RECORDS / f"{label}.yaml"
    if not path.is_file():
        return None
    return _yaml.safe_load(path.read_text(encoding="utf-8"))


def samples_record(ep: Path, mapping: Mapping[str, Any]) -> Path:
    path = Path(ep) / SAMPLES_NAME
    path.write_text(_yaml.safe_dump(dict(mapping)), encoding="utf-8")
    return path


def read_samples(ep: Path) -> dict | None:
    path = Path(ep) / SAMPLES_NAME
    if not path.is_file():
        return None
    return _yaml.safe_load(path.read_text(encoding="utf-8"))


def oracle_dir(ep: Path, label: str) -> Path:
    return Path(ep) / ORACLE_DIRNAME / label


def oracle_rows(ep: Path, label: str, name: str) -> list[dict]:
    """Rows of one oracle-side store: `forged`, `facts`, `answers`, `ledger` or `base`."""
    return read_jsonl(oracle_dir(ep, label) / f"{name}.jsonl")


def ledger_path(ep: Path, label: str) -> Path:
    return Path(ep) / "served" / f"{world_token(label)}.jsonl"


def ledger_rows(ep: Path, label: str) -> list[dict]:
    """The WORLD ledger, read raw off disk (never through the code under test)."""
    return read_jsonl(ledger_path(ep, label))


def base_rows(ep: Path) -> list[dict]:
    return read_jsonl(Path(ep) / "served" / "base.jsonl")


def write_ledger(ep: Path, label: str, rows: list[dict]) -> Path:
    return J.write_ledger(ep, label, rows)


def ledger_row(source: str, *, system: str = "idp", verb: str = "query",
               params: Mapping[str, Any] | None = None, payload: Any = None,
               label: str = "b", **extra: Any) -> dict:
    """One world-ledger row in today's row shape plus the coined oracle fields."""
    row = {"system": system, "verb": verb, "params": dict(params or query_params()),
           "payload_text": json.dumps(payload if payload is not None else {"rows": []},
                                      sort_keys=True),
           "source": source, "world_id": world_token(label)}
    row.update(extra)
    return row


def read_jsonl(path: Path) -> list[dict]:
    """A JSONL record's rows, read raw off disk through the project's one JSONL reader
    (`defender._io.read_jsonl_rows`): an absent file is no rows, and a line that is not a row
    (a torn trailing write) is not a row."""
    from defender._io import read_jsonl_rows

    return read_jsonl_rows(Path(path))


def strings_in(value: Any) -> list[str]:
    """Every string inside a nested loaded YAML/JSON document (keys and values)."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        return [s for k, v in value.items() for s in (*strings_in(k), *strings_in(v))]
    if isinstance(value, (list, tuple)):
        return [s for v in value for s in strings_in(v)]
    return []


def judged_episode(tmp_path: Path, *, doc: dict | None = None,
                   labels: tuple[str, ...] = WORLDS, outcome: str | None = "accepted",
                   ledgers: dict[str, list[dict]] | None = None,
                   root: Path | None = None, samples: bool = True, **world_kw: Any) -> Path:
    """A fully archived v2 episode — the judge's and the page's whole input: v2 manifest, a
    base recording, every world archived under `worlds/<X>/` (the #921 archive builder), the
    world ledgers, and pre-flight's outcome record (`outcome=None` writes none)."""
    ep = episode_v2(tmp_path, doc=doc, root=root, base_rows=[
        captured("idp", "query", query_params("user:alice"),
                 {"rows": [{"user": "alice", "event_id": "e-100", "action": "logon"}]})])
    manifest = _yaml.safe_load((ep / "family.yaml").read_text(encoding="utf-8"))
    declared = {w["world_id"]: w.get("disposition_declared", "malicious")
                for w in manifest["worlds"]}
    for label in labels:
        J.archived_judge_world(ep, label, disposition=declared.get(label, "malicious"),
                               **world_kw)
        write_ledger(ep, label, (ledgers or {}).get(label, []))
    if samples:
        # O16: every served system has a samples section (one example per system here).
        samples_record(ep, {system: {"verbs": {"query": [json.dumps({"rows": []})]}}
                            for system in manifest.get("served_systems") or []})
    if outcome is not None:
        outcome_record(ep, outcome)
    return ep


# --------------------------------------------------------------------------------------
# Serving: a world registry over the fixture estate, and one investigator call through it.
# --------------------------------------------------------------------------------------


def load_world(ep: Path, label: str) -> Any:
    """The sibling's `ResumeWorld` for `label`, through the REAL loader."""
    fam = mod(FAMILY)
    with mod("_episode_handle").Episode.create(Path(ep)) as handle:
        family = fam.load_family(handle.view())
    return fam.resume_world_from(family, label, Path(ep))


def world_ledger(ep: Path, label: str) -> Any:
    """`Ledger.for_world(...).declare()` over the primed base — as the sibling builds it."""
    episode = mod("_episode_handle").Episode.create(Path(ep))
    with contextlib.suppress(FileExistsError):
        episode.served_base.create("")
    return sym(LEDGER, "Ledger").for_world(episode, world_token(label)).declare()


def serving(*, oracle: Any = None, verifier: Any = None, box: Callable[[], Any] | None = None,
            restart_after: int | None = None, **knobs: Any) -> Any:
    """A world's settled oracle side (`registry.oracle_serving`), the test defaults in one
    place: `oracle` / `verifier` are models (production's lazy ones when `None`), the box
    production's when `None`, and `knobs` the oracle's (`retry_cap=`, `turn_deadline=`,
    `budget=`, `rate=`) over the process's environment."""
    reg = importlib.import_module(f"defender.{REGISTRY}")
    config = importlib.import_module("defender.learning.core.config")
    extra = {} if restart_after is None else {"restart_after": restart_after}
    return reg.oracle_serving(config.oracle_settings_with(**knobs), oracle=oracle,
                              verifier=verifier, box=box, **extra)


def registry_seams(world: Any, ledger: Any, *, oracle_dir: Path | None = None,
                   limiter: Any = None, **knobs: Any) -> dict[str, Any]:
    """`WorldRegistry`'s settled oracle-side keywords (`serving=`, `oracle_dir=`, `limiter=`)
    for `world` over `ledger`: `serving(**knobs)`, the world's default `oracle_dir`, and a fresh
    limiter at the settled rate, unless given."""
    reg = importlib.import_module(f"defender.{REGISTRY}")
    limiter_mod = importlib.import_module("defender.learning.branch.estate.limiter")
    settled = serving(**knobs)
    return {
        "serving": settled,
        "oracle_dir": oracle_dir if oracle_dir is not None else reg.default_oracle_dir(
            world, ledger),
        "limiter": limiter if limiter is not None else limiter_mod.RateLimiter(
            settled.settings.rate),
    }


def build_registry(roster: Any, grant: Any, *, world: Any, ledger: Any, as_of: Any,
                   tenant: Any = None, grant_home: str | None = None, **knobs: Any) -> Any:
    """`WorldRegistry(roster, grant, ...)` with its settled oracle side from
    `registry_seams(world, ledger, **knobs)` — the constructor as a test that does not care
    about the oracle side spells it. `prebranch=` (the source run's pre-branch request keys)
    goes to the registry itself, not its oracle side."""
    extra = {} if grant_home is None else {"grant_home": grant_home}
    if "prebranch" in knobs:
        extra["prebranch"] = knobs.pop("prebranch")
    return sym(REGISTRY, "WorldRegistry")(
        roster, grant, world=world, ledger=ledger, as_of=as_of, tenant=tenant,
        **registry_seams(world, ledger, **knobs), **extra)


def world_registry(ep: Path, label: str, est: Estate, *, oracle: ScriptedModel | None = None,
                   verifier: ScriptedModel | None = None, box: Callable[[], Any] | None = None,
                   tenant: Any = None, world: Any = None, **knobs: Any) -> Any:
    """`WorldRegistry` for world `label` of episode `ep`, over the fixture estate's roster and
    gather grant, with the doubles injected through the coined seams. `knobs` are the coined
    keywords (`retry_cap=`, `turn_deadline=`, `budget=`, `rate=`, `restart_after=`,
    `limiter=`), settled by `registry_seams`, and `as_of=` (the branch point by default)."""
    rt = tenant if tenant is not None else est.run_tenant()
    served = world if world is not None else load_world(ep, label)
    ledger = world_ledger(ep, label)
    as_of = knobs.pop("as_of", AS_OF_DT)
    return build_registry(
        est.roster(), rt.grants.gather, world=served, ledger=ledger, as_of=as_of,
        tenant=rt, grant_home=rt.table_pointer,
        oracle=None if oracle is None else oracle.model,
        verifier=None if verifier is None else verifier.model, box=box,
        oracle_dir=oracle_dir(ep, label), **knobs)


def sandboxed_registry(ep: Path, label: str, est: Estate, oracle: ScriptedModel | None = None,
                       verifier: ScriptedModel | None = None, *,
                       box: Callable[[], Any] | None = None, **knobs: Any) -> Any:
    """`world_registry` with `retry_cap=3` by default and the oracle box a recording SANDBOXED
    factory unless the scenario hands its own (so no test reaches the production box)."""
    knobs.setdefault("retry_cap", 3)
    if box is None:
        box, _log = sandboxed_box()
    return world_registry(ep, label, est, oracle=oracle, verifier=verifier, box=box, **knobs)


def plain_registry(est: Estate) -> Any:
    """The registry an ordinary UNBRANCHED run queries through over the same estate — the
    "as on a real run" parity reference."""
    rt = est.run_tenant()
    return sym(VERBS, "ModuleVerbRegistry")(est.roster(), rt.grants.gather,
                                            grant_home=rt.table_pointer)


def call(registry: Any, system: str, verb: str, ctx: Any, **params: Any) -> Any:
    """One investigator call through the registry's wrapped verb — the production frame the
    query tool calls (`registry.verbs(system)[verb](ctx, **params)`)."""
    return registry.verbs(system)[verb](ctx, **params)


LEAD = "l-001"


def replay_harness() -> Any:
    """The replay harness module (`defender.tests.e2e._replay_harness`)."""
    return importlib.import_module("defender.tests.e2e._replay_harness")


def lead_rows(run_dir: Path) -> list[dict]:
    """The evidence rows of the scenario's own gather lead (`LEAD`); lead zero's correlation
    row (`l-000`), which every driven run writes, is not the scenario's."""
    return [r for r in read_jsonl(Path(run_dir) / "executed_queries.jsonl")
            if r.get("lead_id") == LEAD]


def drive_gather(tmp_path: Path, *, verbs: Any, gather_turns: list[Any], system: str = "idp",
                 run_id: str = "run-1224", limits: Any = None, tenant: Any = None,
                 **kw: Any) -> tuple[Path, Any]:
    """A whole investigation through the replay harness (the `test_1106_query_lane` shape):
    the main loop dispatches ONE gather lead on `system`, whose scripted turns are
    `gather_turns` (`query_turn(...)`s then `DONE`), with the registry injected as `verbs=`.
    Returns `(run dir, the gather ReplayFn)` — `gather.seen` is what the investigator saw."""
    H = replay_harness()
    run_dir = H.materialize(tmp_path / run_id, H.GOLDEN_AB3)
    main = H.ReplayFn([
        H.Turn(tool_calls=[("gather", {
            "lead_id": LEAD, "system": system, "goal": f"measure the {system} lead",
            "what_to_summarize": ["what the system says"]})]),
        H.Turn(text="Investigation complete."),
    ])
    gather = H.ReplayFn(gather_turns)
    H.drive(run_dir, run_id=run_id, main=main, gather=gather, verbs=verbs, limits=limits,
            tenant=tenant, **kw)
    return run_dir, gather


def done_turn() -> Any:
    H = replay_harness()
    return H.Turn(text="Summary: measured the lead.")


def query_turn(system: str, verb: str, params: Mapping[str, Any]) -> Any:
    """One gather-agent `query` tool call, as the replay harness scripts it."""
    H = replay_harness()
    return H.Turn(tool_calls=[("query", {"system": system, "verb": verb,
                                         "params": dict(params)})])


# --------------------------------------------------------------------------------------
# Repository text readers (census / removal demands) — reading the tree, not importing it.
# --------------------------------------------------------------------------------------


def source_text(rel: str) -> str:
    """A shipped file's text under `defender/` (empty when it does not exist)."""
    path = DEFENDER / rel
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def shipped_python(*, exclude_tests: bool = True) -> list[Path]:
    out = []
    for p in DEFENDER.rglob("*.py"):
        rel = p.relative_to(DEFENDER).as_posix()
        if exclude_tests and (rel.startswith("tests/") or rel.startswith("evals/")):
            continue
        if "/.venv/" in f"/{rel}" or "__pycache__" in rel:
            continue
        out.append(p)
    return sorted(out)


def grep_shipped(needle: str, *, suffixes: tuple[str, ...] = (".py",)) -> list[str]:
    """`rel:line` for every shipped (non-test) file line containing `needle`."""
    hits = []
    for p in DEFENDER.rglob("*"):
        if not p.is_file() or p.suffix not in suffixes:
            continue
        rel = p.relative_to(DEFENDER).as_posix()
        if rel.startswith(("tests/", "evals/", ".venv/")) or "__pycache__" in rel:
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for i, line in enumerate(text.splitlines(), 1):
            if needle in line:
                hits.append(f"{rel}:{i}")
    return hits


# --------------------------------------------------------------------------------------
# The launcher (M8): a source run on the fixture tenant, and one launch through `cli.main`.
# --------------------------------------------------------------------------------------

BRANCH_MESSAGE_ID = T.BRANCH_MESSAGE_ID


#: The lead a post-branch captured call is landed under (R-01). `l-001` (`LEAD`) carries the
#: pre-branch calls: no `gather` dispatch accounts for it, so `_frontier.leads_at` always keeps
#: it (inherited). `l-002`'s `gather` call/return pair lands in MAIN's session AFTER the branch
#: message, so `leads_at` drops it: its calls are not in the sibling's inherited transcript.
POST_BRANCH_LEAD = "l-002"


@dataclass(frozen=True)
class Call:
    """One call the SOURCE run made (and so one call pre-flight replays). `post_branch=True`
    lands it under `POST_BRANCH_LEAD`, a lead dispatched after the branch point, so it is not
    part of the inherited prefix; the default is a pre-branch call (M01=A: fixed, served
    unchanged; a world whose facts would change one fails pre-flight)."""

    system: str
    verb: str
    params: dict
    payload: Any = None
    post_branch: bool = False


def post_branch_call(q: str = "user:alice host:db-1", payload: Any = None) -> Call:
    """One idp call the source run made AFTER the branch point (R-01): a call a world may
    change, because no sibling inherits its real answer. Its params carry `q` as a marker
    distinct from every default (pre-branch) call."""
    rows = payload if payload is not None else {"rows": [
        {"user": "alice", "event_id": "e-200", "action": "logon", "host": "web-2",
         "ts": "2026-07-28T15:30:00Z"}]}
    return Call("idp", "query", query_params(q), rows, post_branch=True)


def default_calls() -> list[Call]:
    """Three captured calls over the fixture tenant's three systems."""
    return [
        Call("idp", "query", query_params("user:alice"),
             {"rows": [{"user": "alice", "event_id": "e-100", "action": "logon",
                        "host": "web-1", "ts": "2026-07-28T15:00:00Z"}]}),
        Call("edr", "query", query_params("host:db-1"),
             {"events": [{"event_id": "x-7", "host": "db-1", "process": "sshd",
                          "ts": "2026-07-28T15:10:00Z"}]}),
        Call("siem-x", "lookup", {"entity": "alice"},
             {"entity": "alice", "risk": "low", "record_id": "r-0001"}),
    ]


def source_run(tmp_path: Path, est: Estate, *, calls: Iterable[Call] | None = None,
               tenant_id: str = FIXTURE_TENANT) -> tuple[Path, Path]:
    """A runs base on the fixture tenant holding ONE finished source run whose captured calls
    are `calls` (default `default_calls()`), each also answered by the live estate with the
    same payload — so a clean replay finds no drift. Returns `(runs base, source run dir)`."""
    calls = list(default_calls() if calls is None else calls)
    est.place(tenant_id=tenant_id)
    base, src = T.runs_base(tmp_path, tenant_id=tenant_id)
    # `runs_base` lands one elastic capture; this tenant has no elastic, so the scenario's own
    # calls replace it.
    (src / "executed_queries.jsonl").write_text("", encoding="utf-8")
    seqs = {LEAD: 0, POST_BRANCH_LEAD: 0}
    for c in calls:
        lead = POST_BRANCH_LEAD if c.post_branch else LEAD
        T.capture_call(src, system=c.system, verb=c.verb, params=dict(c.params),
                       payload=c.payload, lead=lead, seq=seqs[lead])
        seqs[lead] += 1
        est.answer(c.system, c.verb, c.params, c.payload)
    if seqs[POST_BRANCH_LEAD]:
        _dispatch_after_branch_point(base, src, POST_BRANCH_LEAD)
    return base, src


def _dispatch_after_branch_point(base: Path, src: Path, lead: str) -> None:
    """Append `lead`'s `gather` call/return pair to the source run's MAIN session, after the
    branch message `T.runs_base` already seeded (R-01). `_frontier.leads_at` dates a lead by
    that pair's return: past `BRANCH_MESSAGE_ID`, so the lead is not inherited. Only scenarios
    with a post-branch call get the pair; every other launch keeps `runs_base`'s session as is."""
    from defender.runtime import session_store as ss
    from defender.runtime.branch._frontier import session_for_run
    from defender.tests import _session_store_705 as SS

    store = ss.open_store(case_id=T.SOURCE_CASE_ID, runs_base=base)
    try:
        session_id = session_for_run(store, src)
        call_id = f"gather-{lead}-after-branch"
        store.append(session_id, [
            SS.tool_call_response("gather", {
                "lead_id": lead, "system": "idp", "goal": "a lead dispatched after the branch",
                "what_to_summarize": ["what idp says"]}, tool_call_id=call_id),
            SS.tool_return_request("gather", f"lead {lead} returned", tool_call_id=call_id),
        ], agent_id="main")
    finally:
        store.close()


def questioner_for(doc: dict | None = None) -> FakeAgent:
    """The question-writer double: call 1 answers the family, then one call per authored seat
    (`author_family`'s protocol), each reply a document."""
    doc = doc if doc is not None else family_v2()  # lint-default: ok — a test builder's fresh per-call double or fixture, never a shared instance
    seats = [w for w in doc["worlds"] if w.get("role") != "A"]
    return FakeAgent(doc, *seats)


def launch(tmp_path: Path, est: Estate, *, calls: Iterable[Call] | None = None,
           spawn: Any = None, argv_extra: Iterable[str] = (),
           oracle: ScriptedModel | None = None, verifier: ScriptedModel | None = None,
           **seams: Any) -> Launch:
    """Drive one episode through the REAL launcher over the fixture tenant. Returns a `Launch`
    (`rc`, `message` — the `sys.exit` text of a refusal, else "" —, `spawn`, `ep`). Every seam
    not named defaults to a recording double; the role preflight is neutralised
    (`no_preflight`) for every scenario not about it."""
    _base, src = source_run(tmp_path, est, calls=calls)
    spawn = spawn if spawn is not None else FakeSpawn()  # lint-default: ok — a test builder's fresh per-call double or fixture, never a shared instance
    seams.setdefault("questioner", questioner_for())
    seams.setdefault("preflight", no_preflight)
    seams.setdefault("live_tree", T.source_capture())
    seams.setdefault("roster", est.roster())
    # The judge runs at the end of an accepted launch; a scenario not about it must never reach
    # a real provider, so the default is a recording double whose reply grades nothing.
    seams.setdefault("judge", FakeJudge(default="bucket: none\nsystems: []\nfindings: []\n"))
    if oracle is not None:
        seams["oracle"] = oracle.model
    if verifier is not None:
        seams["verifier"] = verifier.model
    cli = mod(CLI)
    message = ""
    root = Path(os.environ.get(T.EPISODES_BASE_ENV, "")) if os.environ.get(
        T.EPISODES_BASE_ENV) else None
    before = {p.name for p in root.iterdir()} if root is not None and root.is_dir() else set()
    try:
        rc = cli.main([str(src), str(BRANCH_MESSAGE_ID), "--continuation-prompt", "go",
                       *argv_extra], spawn=spawn, **seams)
    except SystemExit as stop:
        if isinstance(stop.code, int):
            rc = stop.code
        else:
            rc, message = 2, str(stop.code)
    # The episode this launch created: the ONE new directory under the configured episodes root
    # (N17: a launch never reuses a directory, so an implementation may mint a fresh id per
    # launch); the derived id's directory when nothing new appeared (a refusal before minting).
    fresh = sorted(p for p in root.iterdir() if p.is_dir() and p.name not in before) \
        if root is not None and root.is_dir() else []
    if len(fresh) == 1:
        ep = fresh[0]
    else:
        ep = cli.episode_dir_for(EPISODE_ID, tenant=T.current_tenant())
    return Launch(rc=rc, message=message, spawn=spawn, ep=ep)


@dataclass(frozen=True)
class Launch:
    rc: int
    message: str
    spawn: Any
    ep: Path
