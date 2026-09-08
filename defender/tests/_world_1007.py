"""Shared machinery for #1007's grade-the-world spec — NO test scripts.

This is the executable form of the spec in `spec-flow/specs/spec_graph_1007-world-quality.yaml`
(145 demands), as amended by the human seam (`.spec-flow/frontiers/70-resolutions.md`). The
change: the review re-asks the capture's own queries live against each world's staged view and
records three executed facts (M1); the serve path takes one extra base-pattern read per staged
call so "the sibling was shown the difference" stops being inferred (M2); the mechanical pass
gains a ladder row that WITHHOLDS a defender finding from a world that measured nothing (M3);
the per-world judge is shown the questioner's own sample and the world's reachability block
(M4); a family-level call judges what one world cannot (M5); findings partition by `subject`
into a second queue channel (M6) feeding a second authored corpus, `defender/lessons-questioner/`,
with its own curator (M7), which the questioner reads back at call 1 (M8).

**Almost nothing this suite drives exists at the base commit.** That is the expected state of a
spec — RED against HEAD. Every import goes through `mod()` / `sym()` PER TEST (the
`_triplet_947` idiom this module extends) so a missing target is one failure per test rather
than one collection error hiding the other hundred-odd assertions.

FOUR THINGS THIS SUITE DELIBERATELY DOES NOT ASSERT, each a decision on the record:

1. **G-1 is an accepted security gap.** `review.py:569-582`'s `envelope_failed = str(fault)`
   carries `AdapterFault.detail` verbatim into `review.yaml`, which M4 renders into the
   per-world judge's prompt. The untrusted wrapper (H2) IS applied; the redaction filter is NOT.
   NO TEST HERE MAY IMPLY THE `wv-<world>-<stem>` NAMING SCHEME IS PROTECTED ON THAT PATH — the
   human declined the filter knowingly after being shown that it is total, idempotent, strips
   exactly those names, and already runs at five model-facing production call sites.
2. **The world-finding vocabulary is OPEN** (15-resolutions R2, accepted gap G-3). There is no
   `WORLD_FINDING_TYPES` enum, `validate_reply` refuses no unknown world bucket, and the
   design's four names are PROMPT EXAMPLES. No test here asserts a closed world set; the
   positive demand is that an unlisted bucket is ADMITTED.
   G-3 IS ABOUT ADMISSION AND NOTHING ELSE, and phase F separated the two questions §7 had run
   together. Which bucket STRINGS are admitted is the human's open decision and stays open. How
   an admitted string is SERIALIZED into a document is a different obligation, owed under a
   closed vocabulary too, and `test_a_lesson_frontmatter_value_cannot_forge_the_key_the_selector
   _reads` pins it: a model-chosen value may not stop being a value and become a lesson's own
   structure. That test reads no bucket against a set, and no test here does.
3. **O5 is scoped to one attempt** (RS-1 / accepted gap G-2). A re-entered step 2 overwrites
   `samples.yaml`, so the byte-identity obligation holds WITHIN ONE ATTEMPT. A byte-identity
   test that never exercises a re-entry would pass while the obligation is false, so the
   re-entry's accepted behaviour (the second attempt's samples win) is pinned by its own test.
4. **H1's applied-counter change has three independent consumers**, each with its own test:
   the serve path's `PATCHED`/`PASSTHROUGH` ledger source, `_patched_visible` ->
   `_rejection`'s world-rejection gate, and `judge/family.py`'s `doctored_answer_served` ->
   bucket-table selection. 316 existing tests passed both before and after the executed change
   with 0 flips, so a test that does not exercise an empty or content-identical patch
   discharges nothing.

FAULT INDUCTION follows the hierarchy: a real input through the real primitive wherever the
primitive can be driven (the elastic search envelope is read off a REAL `_search` over a REAL
raw Elasticsearch response, through a fake `docker` on the run's own PATH); a declarative
fault-injection fake whose fault content cites a probed ledger claim where the dependency is a
model or a cluster; and nothing imagined. Every fault shape reused here comes from
`_triplet_947.Fault`, whose spellings cite #947's own executed claims.

FAKES ENTER THROUGH INJECTION SEAMS — a `deps`-shaped keyword, a constructor argument, an
environment root the shipped resolver already reads — and never by `monkeypatch.setattr`
(the project profile's `tests.idioms`, ratcheted in CI by `scripts/lint/lint_monkeypatch.py`).

Underscore-prefixed so pytest does not collect it; it defines no tests.
"""
from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from defender.tests._judge_921 import (  # noqa: F401 — re-exported: the judge-side builders
    ALERT_ID,
    HOLDING_SYSTEM,
    STATE_DIR_ENV,
    accepted_episode,
    archived_judge_world as archived_world,
    judge_record,
    ledger_row,
    review_record as _review_record_921,
    write_ledger,
)
from defender.tests._triplet_947 import (  # noqa: F401 — re-exported: one spelling per fixture
    ALERTS_PATTERN,
    AS_OF,
    BRANCH_MESSAGE_ID,
    CLEAN,
    CONFIGURED,
    DEFENDER,
    EPISODE_ID,
    EPISODE_TOKEN,
    EPISODES_BASE_ENV,
    EVENTS_PATTERN,
    RUNS_BASE_ENV,
    SOURCE_RUN_ID,
    WORLDS,
    Fault,
    FakeAdapters,
    FakeAgent,
    FakeDoor,
    FakeSpawn,
    FakeTransport,
    assert_wrapped_untrusted,
    base_capture,
    base_world,
    capture_call,
    captured_row,
    configured_layout as _configured_layout_947,
    elastic_overlay,
    episode,
    family_doc,
    mod,
    no_preflight,
    outside_untrusted_frames,
    overlay,
    provenance_record,
    refusals,
    report_text,
    review_doc,
    runs_base,
    sibling_run_dir,
    sym,
    untrusted_frames,
    world_doc,
    world_token,
    write_family,
)

# ---------------------------------------------------------------------------------------
# The names #1007 introduces. Spelled ONCE, because the graph's address space and the code's
# symbol table join BY NAME (schema.md, "Coin ids from the code's name"): a private synonym
# here would cost the join, silently.
# ---------------------------------------------------------------------------------------

#: `defender/lessons-questioner/` — the second authored corpus (M7/D3). The path accessor pair
#: the graph binds as boundary `lessons_questioner_dir` lives on `_paths.DefenderPaths`, beside
#: `lessons_dir` / `lessons_dir_rel`, because that class is the one owner of corpus directory
#: NAMES (its own docstring: the names stay owned by `_paths.py` alone).
QUESTIONER_CORPUS_DIRNAME = "lessons-questioner"
QUESTIONER_CORPUS_REL = "defender/lessons-questioner/"

#: `_pending/questioner_findings.jsonl` — the second queue channel (M6). A2 (§7) settled its
#: lock topology: its OWN `append_lock` and `consumed` file, and the SHARED drain lock, so two
#: curators never hold the worktree at once.
QUESTIONER_QUEUE_FILENAME = "questioner_findings.jsonl"

#: The `_CURATOR_MODULES` key and the drain-trigger module name for M7's curator. `author` is
#: the incumbent defender-side one; after this change the fixed dict has a fourth key and the
#: drain triggers exactly these two.
QUESTIONER_CURATOR_MODULE = "questioner_curator"
DEFENDER_CURATOR_MODULE = "author"

#: The two `subject` literals. Exactly two string literals, no case-fold and no trim anywhere
#: (the graph's `subject` domain) — which is what makes the appender's guard and the bucket
#: selector agree by construction.
SUBJECT_DEFENDER = "defender"
SUBJECT_WORLD = "world"

#: The ONE world bucket the MECHANICAL pass mints (M3 row 4). Every other world bucket in this
#: suite is a model's own string, and the suite never asserts the set is closed.
MECHANICAL_WORLD_BUCKET = "unreachable-difference"

#: The four names that reach the per-world prompt as EXAMPLES. Listed so a test can assert they
#: are PRESENT AS EXAMPLES; never so a test can assert nothing else is admitted.
EXAMPLE_WORLD_BUCKETS = (
    "unreachable-difference", "shape-invention", "story-overlay-gap", "undiscriminating-family",
)

#: The three episode-level files a `subject: world` finding's evidence pointer may name (A3,
#: cell widening S7). The defender arm is UNCHANGED and stays world-subtree-only.
WORLD_EVIDENCE_FILES = ("samples.yaml", "review.yaml", "judge.yaml")

#: `withheld_reason`'s members: three from O4's own cells plus A3 cell (h)'s fourth.
WITHHELD_REASONS = (
    "measured_nothing", "capture_unaddressed", "reachability_unmeasured", "episode_incomplete",
)

#: The applier decisions H1's counter selects between, spelled off the production module at
#: call time by `applier_decisions()` below rather than restated here.
SAMPLES_NAME = "samples.yaml"
JUDGE_NAME = "judge.yaml"
REVIEW_NAME = "review.yaml"


def applier_decisions() -> tuple[str, str, str]:
    """`(PASSTHROUGH, PATCHED, STAGED)` read off the production module, never restated here.

    H1 changes what makes the applier pick between the first two; the LITERALS are the ledger's
    own and belong to `estate/applier.py`. A copy spelled in this file would keep a test green
    across a rename of the very column the ledger's readers key on.
    """
    applier = mod("learning.branch.estate.applier")
    return applier.PASSTHROUGH, applier.PATCHED, applier.STAGED


# ---------------------------------------------------------------------------------------
# The episode's new artifacts, as builders. A new scenario is a few lines of data.
# ---------------------------------------------------------------------------------------


def write_yaml(path: Path, doc: Any) -> Path:
    import yaml

    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(doc, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return path


def read_yaml(path: Path) -> Any:
    import yaml

    return yaml.safe_load(path.read_text(encoding="utf-8"))


#: One real corpus document, the shape `stagers/elastic.py::source_pattern` keys a sample by.
SAMPLE_DOCUMENT = {
    "@timestamp": "2026-07-28T16:00:00Z",
    "host": {"name": "web-1"},
    "event": {"action": "ssh_login", "outcome": "success"},
    "user": {"name": "svc-deploy"},
}


def samples_document(*, pattern: str = EVENTS_PATTERN,
                     document: Any = None) -> dict[str, Any]:
    """`{pattern: document}` — `samples.yaml`'s whole shape (M4, key flow step 1).

    ONE DOCUMENT PER PATTERN, which is what makes O5's byte-identity obligation askable at all:
    the judge's rendered sample is compared against the value under the SAME key the questioner
    was handed, so a writer that stored a list, or that let a duplicate key decide by
    last-key-wins, has no single document for either side to name.
    """
    return {pattern: document if document is not None else dict(SAMPLE_DOCUMENT)}


def write_samples(episode_dir: Path, samples: dict[str, Any] | None = None) -> Path:
    """Materialise `<episode>/samples.yaml`."""
    return write_yaml(Path(episode_dir) / SAMPLES_NAME,
                      samples if samples is not None else samples_document())


def reachability_block(  # noqa: PLR0913 — the block's own fields, one keyword each
    *, capture_replays: list[dict] | None = None, capture_addressed: bool = True,
    capture_reasks_faulted: int = 0, reachable_by_capture: Any = True,
    injected_retrieved: int = 1, injected_present: int = 1,
    envelope_ran: bool = True, envelope_failed: Any = None,
    patched_visible: bool = False, exclusion_matches: Any = None,
    exclusion_count_failed: bool = False, base_documents: Any = 10,
) -> dict[str, Any]:
    """One world's `reachability` block, review-record shaped (M1 + N4/M9's honest counts).

    The three EXECUTED facts M1 adds are `capture_replays` (one `{key, differs, faulted}` entry
    per re-asked captured query), `capture_addressed` and `reachable_by_capture`; the split
    `injected_retrieved` / `injected_present` is N4's honesty repair on a count that today
    conflates the envelope's own hits with the door's. The incumbent fields ride along because
    `_rejection` still reads them and the survival demands drive exactly that.
    """
    return {
        "capture_replays": list(capture_replays if capture_replays is not None else []),
        "capture_addressed": capture_addressed,
        "capture_reasks_faulted": capture_reasks_faulted,
        "reachable_by_capture": reachable_by_capture,
        "injected_retrieved": injected_retrieved,
        "injected_present": injected_present,
        "envelope_ran": envelope_ran,
        "envelope_failed": envelope_failed,
        "patched_visible": patched_visible,
        "exclusion_matches": exclusion_matches,
        "exclusion_count_failed": exclusion_count_failed,
        "base_documents": base_documents,
    }


def replay_entry(key: str = "k1", *, differs: Any = True, faulted: bool = False) -> dict:
    """One `capture_replays` entry. Three keys and no fewer — an entry missing one is
    `unmeasured`, never a completed non-differing re-ask."""
    return {"key": key, "differs": differs, "faulted": faulted}


def write_review(episode_dir: Path, *, worlds: dict[str, dict] | None = None,
                 decision: str = "accepted", outcome: str = "accepted") -> Path:
    """Materialise `<episode>/review.yaml` AS THE LAUNCHER LEAVES IT for the judge.

    Delegated to `_judge_921.review_record` rather than composed here, because the key the
    judge reads is not the key `review._record` writes: step 4 puts a human sentence in
    `episode.outcome` and step 6 overwrites the same key with the enum word, so by grading time
    it always holds step 6's. A fixture that spelled step 4's shape would make every judge
    scenario grade `not-graded` for a reason no scenario is about.
    """
    return _review_record_921(episode_dir, outcome=outcome, decision=decision,
                              worlds=dict(worlds or {}))


def reviewed_world(*, role: str | None = "B", label: str = "b", decision: str = "accepted",
                   reachability: dict | None = None,
                   consistency: dict | None = None) -> dict[str, Any]:
    """One `worlds:` entry of `review.yaml`, carrying its reachability block."""
    return {
        "role": role,
        "world_token": world_token(label),
        "consistency": consistency if consistency is not None else {
            "mismatches": [], "control_mismatch_keys": [], "replayed": 1, "drifted_keys": [],
        },
        "reachability": reachability if reachability is not None else reachability_block(),
        "inventions": [],
        "decision": decision,
    }


def configured_layout(tmp_path: Path, monkeypatch) -> tuple[Path, Path, Path]:
    """`_triplet_947.configured_layout`, plus the LEARNING STATE ROOT pointed inside `tmp_path`.

    The judge's appender writes to the ONE configured queue, resolved through
    `config.loop_paths()`. A scenario that left this root ambient would append its fixture rows
    into the developer's — and CI's — real `learning/_pending/`, which is a shared sink no test
    may touch. Environment steering through the resolver the shipped code already reads.
    """
    base, src, root = _configured_layout_947(tmp_path, monkeypatch)
    monkeypatch.setenv(STATE_DIR_ENV, str(tmp_path / "learning-state"))
    return base, src, root


def served_row(*, world: str = "b", key: str = "k1", source: str = "staged",
               payload_text: str | None = None, differs_from_base: Any = True,
               base_pattern_digest: str | None = "sha256:deadbeef",
               **extra: Any) -> dict[str, Any]:
    """One `served/<world>.jsonl` row, `ServedCall.row()`-shaped, with M2's witness pair.

    Built on `_judge_921.ledger_row` so `world_id` is the COMPOSED world token a real row
    carries — never the short archive label — and `asked_params` is the form the model actually
    asked while `params` is the retargeted form staging ran. A hand-rolled row spelling either
    the other way reads to `family.py`'s scope check as a scope failure the scenario is not
    about. `source: staged` rows, and only those, carry `differs_from_base` +
    `base_pattern_digest`.
    """
    view = f"wv-{world_token(world)}-logs-"
    asked = {"index": EVENTS_PATTERN, "window": "24h", "scope_key": "host.name"}
    ran = dict(asked, index=view) if source == "staged" else dict(asked)
    row = ledger_row(
        source=source, world_label=world, params=ran,
        asked_params=asked,
        payload=payload_text if payload_text is not None else json.dumps(
            {"hits": [{"_id": "d1"}]}, sort_keys=True))
    row["correlation_key"] = key
    if source == "staged":
        row["differs_from_base"] = differs_from_base
        if base_pattern_digest is not None:
            row["base_pattern_digest"] = base_pattern_digest
    row.update(extra)
    return row


def write_served(episode_dir: Path, world: str, rows: list[dict]) -> Path:
    """Materialise one world's served ledger under `<episode>/served/`.

    Through `_judge_921.write_ledger` so the FILENAME is the composed world token rather than
    the short archive label — a reader opening `served/<label>.jsonl` finds nothing, and a
    fixture that spelled the short name would make every ledger assertion pass on an empty read.
    """
    return write_ledger(episode_dir, world, list(rows))


# ---------------------------------------------------------------------------------------
# The judge's reply, as data. A fake that only returns answers leaves the outbound channel
# unpinned, so every scenario that scripts a reply also reads `agent.prompts`.
# ---------------------------------------------------------------------------------------


def finding(*, bucket: str = "lead-set", subject: str = SUBJECT_DEFENDER,
            claim: str = "the sibling never asked the holding system",
            root_cause: str = "no query named the corpus",
            anchor: str = "lead l-001", topic: str = "coverage",
            evidence: list[str] | None = None, **extra: Any) -> dict[str, Any]:
    """One finding as the model writes it, `subject` included.

    `subject` is a REQUIRED key on every finding after O1/M6 — the partition is at the
    validator, and a finding without one is not routable to either channel.
    """
    doc: dict[str, Any] = {
        "bucket": bucket, "subject": subject, "claim": claim, "root_cause": root_cause,
        "anchor": anchor, "topic": topic,
        "evidence": list(evidence if evidence is not None else ["report.md#L1"]),
    }
    doc.update(extra)
    return doc


def world_finding(*, bucket: str = "story-overlay-gap", pattern: str = EVENTS_PATTERN,
                  holding_system: str = "elastic", evidence: list[str] | None = None,
                  **extra: Any) -> dict[str, Any]:
    """A `subject: world` finding. `pattern` and `holding_system` are REQUIRED at the appender
    (A3(b)) because the questioner channel's own gate is idempotency-only, so the appender is
    the last screen before the corpus."""
    return finding(
        bucket=bucket, subject=SUBJECT_WORLD,
        claim="the overlay's story names a field the corpus does not carry",
        root_cause="the sample was not matched",
        anchor=f"world {pattern}", topic="overlay shape",
        evidence=list(evidence if evidence is not None else [f"samples.yaml#{pattern}"]),
        pattern=pattern, holding_system=holding_system, **extra)


def reply_document(*, findings: list[dict] | None = None, outcome: str = "gradable",
                   **extra: Any) -> dict[str, Any]:
    """The judge's whole reply as a mapping, before it is dumped to the text a seam returns."""
    doc: dict[str, Any] = {
        "episode_outcome": outcome,
        "noise_floor_note": "nothing notable",
        "correlations": [], "scope_checks": [], "derivations": [],
        "findings": list(findings if findings is not None else []),
    }
    doc.update(extra)
    return doc


def reply_text(**kw: Any) -> str:
    """A judge reply as the TEXT a model seam hands back — the shape `validate_reply` parses."""
    import yaml

    return yaml.safe_dump(reply_document(**kw), sort_keys=False, allow_unicode=True)


class FakeJudge(FakeAgent):
    """The judge's model seam (`judge=` on `grade_episode`), recording and fault-injecting.

    Inherits `_triplet_947.FakeAgent` rather than restating it: the same recording contract
    (`prompts`, `kwargs`, `agent_ids`) is what every payload demand in both suites asserts
    against. `replies` may hold either raw reply TEXT or a mapping this class dumps, so a
    scenario writes `FakeJudge(reply_document(findings=[...]))` in one line.

    ROUND-ROBIN over the last reply, because a pass makes `draws x (worlds + 1)` calls and a
    scenario that is not about draw count should not have to spell one reply per call. A
    scenario that IS about the per-call payload reads `prompts` and asserts per index.
    """

    def __call__(self, prompt: str, **kw: Any) -> Any:
        import yaml

        if len(self.replies) == 1:
            reply = self.replies[0]
            self.prompts.append(prompt)
            self.kwargs.append(dict(kw))
            if "agent_id" in kw:
                self.agent_ids.append(kw["agent_id"])
            if self.fault.raise_after is not None and len(self.prompts) > self.fault.raise_after:
                raise RuntimeError("the judge provider degraded mid-fan-out")
            if self.fault.hits(str(kw.get("agent_id", ""))):
                raise RuntimeError(f"the judge provider refused {kw.get('agent_id')!r}")
            return reply if isinstance(reply, str) else yaml.safe_dump(reply, sort_keys=False)
        reply = super().__call__(prompt, **kw)
        return reply if isinstance(reply, str) else yaml.safe_dump(reply, sort_keys=False)

    def prompt_for(self, agent_id: str) -> str:
        """The one prompt handed to the call with this agent id — `AssertionError` if the call
        was never made, which is a demand failing rather than a silence nobody can see."""
        hits = [p for p, a in zip(self.prompts, self.agent_ids, strict=False) if a == agent_id]
        assert hits, f"no call was made with agent_id={agent_id!r}; ids seen: {self.agent_ids}"
        return hits[0]

    @property
    def family_prompts(self) -> list[str]:
        return [p for p, a in zip(self.prompts, self.agent_ids, strict=False)
                if a.startswith("judge:family")]


@dataclass
class RecordingReader:
    """A counting wrapper over any single-argument read, as an injection seam.

    Two demands need "how many times was this read" as an OBSERVATION rather than an
    inspection: the base arm is read once per key per episode across all worlds, and the review
    record is read once through the guarded reader. A counter that only counts leaves the
    argument unpinned, so every call's argument is recorded too.
    """

    inner: Any
    calls: list[Any] = field(default_factory=list)

    def __call__(self, *a: Any, **kw: Any) -> Any:
        self.calls.append((a, dict(kw)))
        return self.inner(*a, **kw)

    @property
    def count(self) -> int:
        return len(self.calls)


class CountingAdapters(FakeAdapters):
    """`FakeAdapters` that also answers DIFFERENTLY per read, so a re-read is observable.

    `sequence` is a per-target list of answers consumed in order; once exhausted the last one
    repeats. That is the only way a "one confirming back-to-back re-read" demand (H4) can
    discriminate: a first read that differs and a second that agrees must produce NO recorded
    difference, and that is unaskable of a fake whose two reads cannot disagree.
    """

    def __init__(self, *args: Any, sequence: dict[str, list[Any]] | None = None,
                 **kw: Any) -> None:
        super().__init__(*args, **kw)
        self.sequence = {k: list(v) for k, v in (sequence or {}).items()}

    def __call__(self, system: str, verb: str, **params: Any) -> Any:
        rendered = json.dumps(params, sort_keys=True, default=str)
        for needle, answers in self.sequence.items():
            if needle in rendered and answers:
                self.calls.append((system, verb, dict(params)))
                return answers.pop(0) if len(answers) > 1 else answers[0]
        return super().__call__(system, verb, **params)

    def reads_of(self, needle: str) -> int:
        return sum(1 for _s, _v, p in self.calls
                   if needle in json.dumps(p, sort_keys=True, default=str))


# ---------------------------------------------------------------------------------------
# The one place this suite drives a REAL primitive over a REAL response: `elastic_adapter`.
#
# H4 names `_search`'s normalization LOAD-BEARING (pd-8): it strips `took`, `_shards` and the
# per-hit `_id` before the ledger or the comparator ever sees a payload, and that — not
# `mechanical` — is why two live reads of this adapter cannot differ on incidental fields. The
# claim is about what the primitive DOES to a raw cluster response, so the test writes a raw
# cluster response and runs the real adapter over it, rather than pinning a shape once.
# ---------------------------------------------------------------------------------------

#: A `docker` on the run's own PATH that answers the curl lane from a JSON file the test wrote,
#: and records nothing it does not need to. The shebang is the RUNNING interpreter's absolute
#: path because the child's PATH holds this directory alone.
_ES_DOCKER_SHIM = r'''
import json
import os
import sys

argv = sys.argv[1:]
if "inspect" in argv:
    sys.stdout.write('"/canary-1"\t"elasticsearch:8"\n')
elif "sh" in argv:
    with open(os.environ["ES_RESPONSE_FILE"], encoding="utf-8") as fh:
        sys.stdout.write(fh.read().strip())
    sys.stdout.write("\n200")
else:
    sys.stdout.write("")
'''

#: A RAW Elasticsearch search response, carrying every incidental field `_search` discards.
#: `took` moves with cluster load, `_shards` moves with the cluster's own topology, and `_id`
#: is minted per indexed document — so a staged corpus and its base pattern differ on all three
#: for reasons that have nothing to do with what any world changed.
RAW_ES_RESPONSE = {
    "took": 37,
    "timed_out": False,
    "_shards": {"total": 3, "successful": 3, "skipped": 0, "failed": 0},
    "hits": {
        "total": {"value": 2, "relation": "eq"},
        "max_score": 1.0,
        "hits": [
            {"_index": "logs-000001", "_id": "AXbQ1", "_score": 1.0,
             "_source": {"host": {"name": "web-1"}, "event": {"action": "ssh_login"}}},
            {"_index": "logs-000001", "_id": "AXbQ2", "_score": 1.0,
             "_source": {"host": {"name": "web-2"}, "event": {"action": "ssh_login"}}},
        ],
    },
}


def elastic_ctx(tmp_path: Path, *, response: dict | None = None):
    """A real `VerbContext` whose transport reaches a `docker` shim answering `response`.

    Environment steering through the ctx the production caller already builds — `query_tool`
    constructs a `VerbContext(defender_dir=…, run_dir=…, env=…)` and the transport forks into
    exactly that env — so nothing here patches a module attribute.
    """
    verbs = mod("runtime.verbs")
    bindir = tmp_path / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    shim = bindir / "docker"
    shim.write_text(f"#!{sys.executable}\n{_ES_DOCKER_SHIM}", encoding="utf-8")
    shim.chmod(0o755)
    payload = tmp_path / "es-response.json"
    payload.write_text(json.dumps(response if response is not None else RAW_ES_RESPONSE),
                       encoding="utf-8")
    defender_dir = tmp_path / "defender"
    config = defender_dir / "knowledge" / "environment" / "systems" / "elastic" / "config.env"
    config.parent.mkdir(parents=True, exist_ok=True)
    config.write_text(
        "ELASTICSEARCH_URL=http://elasticsearch:9200\nKIBANA_URL=http://kibana:5601\n"
        f"ELASTIC_EVENTS_INDEX={EVENTS_PATTERN}\n"
        f"ELASTIC_ALERTS_INDEX={ALERTS_PATTERN}\n", encoding="utf-8")
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    return verbs.VerbContext(
        defender_dir=defender_dir, run_dir=run_dir,
        env={"PATH": str(bindir), "ES_RESPONSE_FILE": str(payload),
             "SOC_PLAYGROUND_DOCKER_CONTEXT": "spec-1007"},
    )


# ---------------------------------------------------------------------------------------
# The serving estate: a REAL adapters directory whose verb bodies answer from a table.
#
# `WorldRegistry` COLD-READS the adapter text (`declared_verb_names` parses the `VERBS = {...}`
# literal without importing) and checks the grant against it at construction, so a module-object
# stand-in never reaches that check and would not be the shape the seam admits. The answers are
# DATA on disk, keyed by a substring of the index/query the body was asked for — which is how one
# fixture answers a base pattern and a staged view differently without ever being told which is
# asking, and is what makes M2's two-live-reads comparison expressible at all.
# ---------------------------------------------------------------------------------------

ANSWERS_FILE = "world_1007_answers.json"

_ANSWERING_ADAPTER = '''\
"""An elastic-shaped estate that answers from a table beside the ctx's defender dir."""
from __future__ import annotations

import json
from pathlib import Path

from defender.runtime.verbs import VerbContext, verb

CALLS = "adapter-calls.jsonl"
ANSWERS = "world_1007_answers.json"


def _answer(ctx, target):
    """The scripted payload for this target, or the fault the table names.

    `"__raise__"` raises the real `UpstreamFault` — the class the shipped adapters raise when
    the cluster refuses — so a scenario can fail ONE arm of a two-arm read by naming the arm's
    own index, without the fake deciding what a failure means.
    """
    from defender.scripts.adapters.faults import UpstreamFault

    path = Path(ctx.defender_dir) / ANSWERS
    table = json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}
    payload = None
    for needle, scripted in table.items():
        if needle != "*" and needle in str(target):
            payload = scripted
            break
    else:
        payload = table.get("*", {"hits": []})
    if payload == "__raise__":
        raise UpstreamFault(f"Elasticsearch query failed (HTTP 503) for {target}")
    return payload


def _record(ctx, name, params):
    log = Path(ctx.run_dir) / CALLS
    log.parent.mkdir(parents=True, exist_ok=True)
    with log.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(
            {"verb": name, "params": params, "world_id": ctx.world_id}) + "\\n")


@verb(engine="lucene", body_param="native_query")
def query(ctx: VerbContext, *, native_query: str, index: str | None = None,
          limit: int = 5) -> dict:
    _record(ctx, "query", {"native_query": native_query, "index": index, "limit": limit})
    return _answer(ctx, index)


@verb(engine="esql", body_param="query")
def esql(ctx: VerbContext, *, query: str, limit: int = 5) -> dict:  # noqa: A002
    _record(ctx, "esql", {"query": query, "limit": limit})
    return _answer(ctx, query)


@verb()
def get_host(ctx: VerbContext, *, host: str) -> dict:
    _record(ctx, "get-host", {"host": host})
    return {"host": host, "owner": "base-team"}


@verb()
def health_check(ctx: VerbContext) -> dict:
    return {"ok": True}


VERBS = {"query": query, "esql": esql, "get-host": get_host, "health-check": health_check}
'''


def estate(tmp_path: Path, *, answers: dict[str, Any] | None = None) -> tuple[Path, Any, Any]:
    """`(adapters_dir, grant, ctx)` — a real serving estate answering from `answers`.

    `answers` maps a SUBSTRING of the index (or ESQL query) the body was asked for to the
    payload it answers with, with `"*"` as the fallback. A world's staged read carries its own
    view name in that value, so one table answers a control and a staged sibling differently
    without the fake ever being told which world is asking.
    """
    verbs = mod("runtime.verbs")
    grant_mod = mod("runtime.verb_grant")
    adapters = tmp_path / "adapters"
    adapters.mkdir(parents=True, exist_ok=True)
    for name in ("elastic_adapter.py", "identity_adapter.py"):
        (adapters / name).write_text(_ANSWERING_ADAPTER, encoding="utf-8")
    defender_dir = tmp_path / "defender"
    defender_dir.mkdir(parents=True, exist_ok=True)
    (defender_dir / ANSWERS_FILE).write_text(
        json.dumps(answers if answers is not None else {}), encoding="utf-8")
    run_dir = tmp_path / "run"
    run_dir.mkdir(parents=True, exist_ok=True)
    grant = grant_mod.VerbGrant(role="gather", entries=(
        ("elastic", "query", "r"), ("elastic", "esql", "r"), ("elastic", "health-check", "r"),
        ("identity", "get-host", "r"), ("identity", "health-check", "r"),
    ))
    ctx = verbs.VerbContext(defender_dir=defender_dir, run_dir=run_dir, env={})
    return adapters, grant, ctx


def estate_calls(ctx: Any) -> list[dict]:
    """Every call the estate's verb bodies actually ran — the observation channel a witness or
    a base-arm read must appear in."""
    path = Path(ctx.run_dir) / "adapter-calls.jsonl"
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


# ---------------------------------------------------------------------------------------
# The queues and the corpora.
# ---------------------------------------------------------------------------------------


def loop_paths(tmp_path: Path, *, repo_root: Path | None = None):
    """A `LoopPaths` rooted in `tmp_path` — the shipped injection seam every drain frame takes.

    `state_dir` is separated from `repo_root` deliberately: the queues are mutable state and
    the corpora are checked-in trees, and a scenario about one must be able to move it without
    moving the other.
    """
    cfg = mod("learning.core.config")
    root = repo_root if repo_root is not None else tmp_path / "repo"
    (root / "defender").mkdir(parents=True, exist_ok=True)
    return cfg.LoopPaths(repo_root=root, state_dir=tmp_path / "learning-state")


def questioner_channel(paths: Any):
    """`paths.questioner_findings` — the second channel, named off the paths object.

    Reached through the attribute rather than by composing `_pending/questioner_findings.jsonl`
    here, because the channel is a `QueueChannel` carrying its own lock topology and id key: a
    test that spelled the filename would go green against a channel whose locks were wrong.
    """
    return paths.questioner_findings


def queue_rows(channel: Any) -> list[dict]:
    """Every row on a channel's file, in written order. Missing file reads as no rows, which is
    the honest answer for a pass that enqueued nothing."""
    path = Path(channel.file)
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()]


def questioner_lesson(paths: Any, name: str = "q-lesson", *, body: str = "Ask the corpus.",
                      pattern: str = EVENTS_PATTERN, holding_system: str = "elastic",
                      **frontmatter: Any) -> Path:
    """One `<name>.md` in the questioner corpus — the shape `_corpus.iter_lessons` globs.

    The selection keys (`pattern`, `holding_system`) live in the frontmatter because that is
    what M8's selector reads: a lesson is shown at call 1 when its pattern is one this
    episode's capture named, or its holding system is the discriminator's.
    """
    import yaml

    corpus = Path(paths.lessons_questioner_dir)
    corpus.mkdir(parents=True, exist_ok=True)
    meta: dict[str, Any] = {"name": name, "pattern": pattern,
                            "holding_system": holding_system}
    meta.update(frontmatter)
    path = corpus / f"{name}.md"
    path.write_text(
        "---\n" + yaml.safe_dump(meta, sort_keys=False) + "---\n" + body + "\n",
        encoding="utf-8")
    return path


def questioner_lesson_raw(paths: Any, name: str, *, frontmatter: str,
                          body: str = "Ask the corpus.") -> Path:
    """One `<name>.md` whose frontmatter is written as RAW TEXT, not through a dumper.

    `questioner_lesson` above composes its frontmatter with `yaml.safe_dump`, which quotes a
    hostile value and makes the forgery this fixture exists to express UNSPELLABLE. The lesson
    document is authored by the curator MODEL through the box's file tools, not by a dumper in
    production — so the bytes a forged lesson actually carries are these, and a fixture that can
    only hand the reader the easy shape is the taxonomy assumption in disguise (rules.md's
    `primitive` value-type discipline, applied to a document).

    PB3 (executed): `_frontmatter.split_frontmatter` applies no schema and no key validation, and
    `yaml` resolves a repeated key LAST-WINS in silence — which is how a model-chosen value
    carrying a newline forges a key the reader keys on.
    """
    corpus = Path(paths.lessons_questioner_dir)
    corpus.mkdir(parents=True, exist_ok=True)
    path = corpus / f"{name}.md"
    path.write_text("---\n" + frontmatter.rstrip("\n") + "\n---\n" + body + "\n",
                    encoding="utf-8")
    return path


__all__ = [
    "ALERTS_PATTERN", "AS_OF", "BRANCH_MESSAGE_ID", "CLEAN", "CONFIGURED", "DEFENDER",
    "DEFENDER_CURATOR_MODULE", "EPISODES_BASE_ENV", "EPISODE_ID", "EPISODE_TOKEN",
    "EVENTS_PATTERN", "EXAMPLE_WORLD_BUCKETS", "JUDGE_NAME", "MECHANICAL_WORLD_BUCKET",
    "QUESTIONER_CORPUS_DIRNAME", "QUESTIONER_CORPUS_REL", "QUESTIONER_CURATOR_MODULE",
    "QUESTIONER_QUEUE_FILENAME", "RAW_ES_RESPONSE", "REVIEW_NAME", "RUNS_BASE_ENV",
    "SAMPLES_NAME", "SAMPLE_DOCUMENT", "SOURCE_RUN_ID", "SUBJECT_DEFENDER", "SUBJECT_WORLD",
    "WITHHELD_REASONS", "WORLDS", "WORLD_EVIDENCE_FILES",
    "CountingAdapters", "FakeAdapters", "FakeAgent", "FakeDoor", "FakeJudge", "FakeTransport",
    "Fault", "RecordingReader",
    "ANSWERS_FILE", "applier_decisions", "archived_world", "assert_wrapped_untrusted", "base_capture",
    "base_world", "capture_call", "captured_row", "configured_layout", "elastic_ctx",
    "elastic_overlay", "estate", "estate_calls", "episode", "family_doc", "finding", "loop_paths", "mod",
    "outside_untrusted_frames", "overlay", "provenance_record", "queue_rows",
    "questioner_channel", "questioner_lesson", "questioner_lesson_raw",
    "reachability_block", "read_yaml", "refusals",
    "replay_entry", "reply_document", "reply_text", "report_text", "review_doc",
    "reviewed_world", "runs_base", "samples_document", "served_row", "sibling_run_dir", "sym",
    "untrusted_frames", "world_doc", "world_finding", "world_token", "write_family",
    "write_review", "write_samples", "write_served", "write_yaml",
]
