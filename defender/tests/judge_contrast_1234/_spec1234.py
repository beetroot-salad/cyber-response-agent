"""Shared machinery for #1234's spec — "the judge grounded in contrast with reference runs". NO
test functions; underscore-prefixed so pytest never collects it.

Imported by every test file here as `from defender.tests.judge_contrast_1234 import _spec1234 as S`.

The change (`spec-flow/specs/spec_graph_1234.yaml`; `.spec-flow/design.md` as amended by
`.spec-flow/design-amendments.md` A1-A15, with the human's rulings in
`.spec-flow/frontiers/70-resolutions.md` and `78-gate-resolutions.md`): each planted world is
judged against the control and every gradable sibling as labelled reference runs (A1's typed,
episode-relative, no-follow pointers; a two-run contrast pair on every investigator finding);
world findings `unreachable` / `incoherent` / `mislabelled`; deployment gaps; draws combine by
UNANIMITY (A7); a user section in `judge.yaml` (named gaps, found gaps, serving findings); a
per-world `queueing` -> append -> `queued` commit (A6); a host-written CALL ID on both call
records (A12); retired shapes refused at every reader (A4).

WHERE THINGS ENTER. The judge's one entry point is `grade_episode(runs, episode_id, *, judge,
state, draws, git_show)` (main's signature at 463833df, unchanged by #1234), driven here through
`_judge_921.grade_at` (`grade`). The page is `open_episode_view(runs, id)` + `build_page(view)`
(`page`). Fakes enter through those seams (`judge=`, `git_show=`, `state=`, the launcher's
`spawn=`/`oracle=`/`verifier=`), NEVER by `monkeypatch.setattr` (profile `tests.idioms`,
`scripts/lint/lint_monkeypatch.py`). `monkeypatch.setenv` for the configured roots is fine.

NONE OF THE NEW BEHAVIOUR EXISTS AT BASE 463833df. Every import of the code under test goes
through `mod()` / `sym()` PER TEST, so a missing target is one failure per test, never one
collection error hiding the rest.

TWO EPISODE BUILDERS — pick by the demand, as `80-survey.md` assigns:

1. `family(...)` — a HAND-BUILT archived episode (`Built`): manifest v2, pre-flight's outcome
   record + family stamp, samples, and per world `worlds/<X>/` (report, investigation, alert,
   lessons record, gather summaries, provenance, the query table with payload sidecars and lead
   claims), the served ledger `served/<token>.<X>.jsonl`, the oracle store `oracle/<X>/`. A
   scenario is a few `World(...)` / `CallRow(...)` lines. Ledger and table rows carry the COINED
   call id (`call_id()`), because A3/A12 make a ledger row without one malformed.
2. `real_family(...)` — the REAL path (I-10, 45-dispositions-drift): the launcher (`cli.main`)
   over the #1224 fixture tenant with real pre-flight; every sibling is the REAL
   `run.main --tenant T --episode <id> --world L`, run in-process by `InProcessSiblings` (the
   launcher's `spawn=` seam); then the real `verify_family` -> `archive_episode` -> family
   stamp. The call records are written by the real writers (registry `authorize_call`/`_deliver`/
   `_record_beside`, query tool `append_query_row`/`_record_denied`, `_inherit_evidence`), so a
   test reads the call id OFF the rows (`call_ids`) and never plants it. Every A12/A14
   situation, d03b-d03d, d08a and the n_t8_* runtime demands use this path. The launcher's own
   JUDGE step is suppressed (its learning-state root is absent for the launch, so `cli._grade`
   logs and writes nothing); the test grades explicitly with its own judge and draw count.
   About 2 s for a triad.

COINED NAMES LIVE HERE AND NOWHERE ELSE (`COINED` below). F2 left field names to the
implementer except those the spec rules by name (`RULED` below). If write-code-from-spec names
anything differently, it renames it HERE, never in a test file. main's OWN names a test relies on
(`malformed_replies`, the `not_graded` stamp, `held_reason`, ...) sit apart, in `EXISTING`.

SHARED READINGS (fixed here so the slices agree): a found/named gap's run is the world label
(`found_run`); a world with no completed draw or refused at prompt build is `measured: false`
with its reason in `not_measured_reason` (d00a's one slot), an A3 exclusion's in
`ungradable_reason`; "byte-identical" prompts compare modulo the frame salt (`unsalted`); a run's
labelled block is owned by the run label host text names last before it (`label_re`); "in the
user record" is `in_user_record`; a stopped pass may raise `stops()`; a FIFO-facing pass runs
under `no_hang`.

EVERY FAULT HERE IS A REAL INPUT THROUGH THE REAL PRIMITIVE, OR A FAKE CITING ITS CLAIM:
  * damaged archive files are planted on disk (`plant_symlink`, `plant_hardlink`, `plant_fifo`,
    `plant_dir`, `plant_oversize` (a sparse file one byte over `_io.READ_LIMIT`), `tear_jsonl`,
    `second_disposition`): the real bounded no-follow reader meets them on every run;
  * a failed write of a call record is a DIRECTORY planted at the record's name mid-run by the
    estate's adapter (`Estate1234.break_write`), so the real writer's open fails. Mode bits
    cannot do it — this box runs as root. Observed on main by this survey's smoke run: the
    query-table write (`write_guarded`) raises `NotPlainEntry` (Errno 40) out of `run.main`
    (the sibling exits 1, the launcher records `did not finish`, it is not archived); the
    served-ledger write is refused and SWALLOWED (the sibling finishes and is archived) —
    AP-01/JP-02 (44-probes-amended) observed `_record_beside` / `_record_denied` swallowing;
  * the judge model's failed call is `RunUnprocessable` (`RoutedJudge(fail=...)`): #921's P9,
    EXECUTED against the real `run_stage` (a wall-clock timeout and a transport failure both
    surface as that class). No #1234 claim re-observes it; it is carried from
    `spec_graph_921-family-judge.yaml` exactly as `_judge_921.FakeJudge` carries it; a call
    that fails ON SIZE is the same class over an HTTP 413 `ModelHTTPError`
    (`RoutedJudge(overflow=...)`), claim P-AM28, executed against the real seam;
  * a model reply is SCRIPTED CONTENT in the shape the design names (`world_reply`, `inv`, `wf`,
    `gap`, and the retired-name variants A4 / FX-reply-retired-names rule refused).

Every fake RECORDS what it was handed (`RoutedJudge.prompts`, `InProcessSiblings.launches`);
payload demands assert on what the fake saw, never on its canned reply.
"""
from __future__ import annotations

from defender.tests._spec1077 import fixture_run as _run_handle_1165

import ast
import contextlib
import importlib
import json
import os
import re
import shutil
import signal
import threading
from collections.abc import Callable, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from defender import _yaml
from defender.tests import _judge_921 as J
from defender.tests import _triplet_947 as T
from defender.tests.live_oracle_1224 import _spec1224 as S24

DEFENDER = Path(__file__).resolve().parents[2]
REPO_ROOT = DEFENDER.parent
SPEC_GRAPH = REPO_ROOT / "spec-flow" / "specs" / "spec_graph_1234.yaml"

# --------------------------------------------------------------------------------------
# Per-test imports.
# --------------------------------------------------------------------------------------


def mod(dotted: str) -> Any:
    """Import `defender.<dotted>` at CALL time, never at collection time."""
    return importlib.import_module(f"defender.{dotted}")


def sym(dotted: str, name: str) -> Any:
    """One attribute off a lazily-imported module — `AttributeError` is a real red."""
    return getattr(mod(dotted), name)


#: The modules this suite drives, spelled once.
JUDGE = "learning.judge"
JUDGE_RUN = "learning.judge.run"
JUDGE_RENDER = "learning.judge.render"
JUDGE_ENQUEUE = "learning.judge.enqueue"
JUDGE_FAMILY = "learning.judge.family"
OUTCOME = "learning.branch.outcome"
EPISODE_MOD = "learning.branch.episode"
REGISTRY = "learning.branch.estate.registry"
QUERY_TOOL = "runtime.query_tool"
RECORD_QUERY = "scripts.gather_tools.record_query"
SEED = "runtime.branch._seed"
BASH_TOOL = "runtime.tools._bash"
LESSONS_RUN = "learning.author.lessons.run"
QUESTIONER_RUN = "learning.author.questioner.run"
DRAIN = "learning.author.drain"
CONFIG = "learning.core.config"
STATE = "learning.core.state"
VOCAB = "_vocab"
REPORT = "_report"
PROMPT = "learning._prompt"
VISUALIZE = "scripts.visualize.visualize_episode"
FAMILY_LOADER = "runtime.branch._family"
CLI = "learning.branch.cli"
RUN = "run"

#: Environment knobs, re-exported so a test never spells them.
EPISODES_BASE_ENV = T.EPISODES_BASE_ENV
LEARNING_STATE_ENV = T.LEARNING_STATE_ENV
DRAWS_KNOB = J.DRAWS_KNOB
CAP_KNOB = J.CAP_KNOB
KNOB_RATE = S24.KNOB_RATE
isolate_learning_state = T.isolate_learning_state

# --------------------------------------------------------------------------------------
# Names: RULED (the spec says the name) and COINED (the implementer's, F2; renamed HERE).
# --------------------------------------------------------------------------------------

#: Names a demand, ruling or amendment spells. A test may rely on these by name.
RULED = {
    "finding.contrast": "contrast_evidence",          # A1, design M4
    "finding.on_path": "on_verdict_path",              # design M4
    "row.doubt": "world_label_doubted",                # design data model
    "gap.kept_facts": "kept_facts_from_investigator",  # F-14, 78-gate-resolutions
    "row.state": "state",                              # NA01 / s_AM21
    "state.queueing": "queueing",                      # A6
    "state.queued": "queued",                          # A6
    "row.citations": "citations",                      # A1: the resolving pointers
    "row.systems": "systems",
    "reply.bucket": "bucket",
    "reply.systems": "systems",
    "row.completed_draws": "completed_draws",
}

#: The implementer's names, spelled ONCE. F2 (70-resolutions): field names are the writer's;
#: lane words too, distinct from the retired `withheld` and learnt by every LEDGER_LANES reader.
COINED = {
    # A12: the host-written call id, one field on a served-ledger row and on a table row.
    "field.call_id": "call_id",
    # The three filed lists of a reply (A13 indexes over them in this order).
    "reply.investigator": "investigator_findings",
    "reply.world": "world_findings",
    "reply.gaps": "gaps",
    # A world finding's and a gap's pointer list (an investigator finding's is RULED).
    "finding.evidence": "evidence",
    "gap.what": "what",
    "gap.how": "how",
    # judge.yaml: the user section and its three lists (design M7, A2, A7).
    "record.user": "user",
    "user.named": "named_gaps",
    "user.found": "found_gaps",
    "user.serving": "serving_findings",
    # R1 (c) (human, 2026-10-12): the user record's own list of named gaps with no blocked-call
    # key that a draw flagged `kept_facts_from_investigator` (I3's "a served system that
    # doesn't hold the field", brief F03) — beside, never inside, `named_gaps`.
    "user.unkeyed": "unkeyed_named_gaps",
    # A found-gap entry: the blocked-call key and its count (A2); a family entry's run; an
    # entry named unread with its cause (NA04).
    "found.run": "run",
    "found.system": "system",
    "found.verb": "verb",
    "found.params": "params",
    "found.count": "count",
    "found.family_run": "family",
    "found.unread": "unread",
    # judge.yaml: the family's own row (A6 commit, completed draws) — a mapping beside `worlds`.
    "record.family": "family",
    # A world row's measurement (d00a): measured, and why not.
    "row.measured": "measured",
    "row.not_measured_reason": "not_measured_reason",
    "row.draws_disagree": "draws_disagree",
    "row.draws": "draws",
    "row.malformed": "malformed",
    "row.ungradable_reason": "ungradable_reason",
    # The ledger (A13: one lane per filed finding).
    "record.ledger": "dispositions",
    "lane.defender": "defender",
    "lane.questioner": "world",
    "lane.user_record": "user_record",
    "lane.not_measured": "not_measured",
    "lane.unauthored": "unauthored",
    "lane.draws_disagree": "draws_disagree",
    "lane.gap_not_unanimous": "gap_not_unanimous",
    "lane.dropped_unresolved": "dropped_unresolved",
    "lane.dropped_other_run": "dropped_other_run",
    "lane.dropped_no_pair": "dropped_no_pair",
    "lane.unqueueable": "unqueueable",
    # render's return type (design data model names it).
    "cls.context": "JudgeContext",
    # A1's plan-pointer fragments: a world's entry, and the family-level part.
    "frag.plan_world": "worlds/{label}",
    "frag.plan_family": "discriminator",
    # How a found/named gap entry spells the run it belongs to (`found.run`'s VALUE): the world
    # label, the spelling world rows and finding ids use (`found_run`).
    "found.run_of": "{label}",
    # A13/I-6: the one lane a named gap with no blocked-call key and no `kept_facts` flag takes
    # (its resolving pointers are only outage rows or context, so no draw can name a matching
    # blocked call). A FLAGGED keyless gap is listed in the user record (R1 (c): `user.unkeyed`)
    # and takes `lane.user_record`, as a listed keyed gap does.
    "lane.gap_unkeyed": "gap_no_blocked_call",
    # `build_finding_row`'s doubt-mark keyword (d00d, g13).
    "kw.doubted": "world_label_doubted",
    # M2: the contrast table's statement that the judged world was never shown its facts (d03e).
    "context.never_shown": "never shown its facts",
    # JudgeContext (render's return, d00f): every run's contrast row, and the two call lists.
    "ctx.contrast": "contrast_rows",           # run label -> that run's contrast row
    "ctx.focus_calls": "focus_calls",          # section 6: the judged world's call list
    "ctx.reference_calls": "reference_calls",  # section 5: run label -> that run's call list
    # One run's contrast row (design M2; A2, A12, A14).
    "contrast.shown": "shown_its_facts",            # bool: any `oracle` ledger row of the run
    "contrast.first_altered": "first_altered_call",  # call number, or None
    "contrast.altered_leads": "altered_leads",      # lead ids
    "contrast.counts": "call_counts",               # "<system>.<verb>" -> rows of the table
    "contrast.blocked": "blocked_calls",            # entries; a ledger-only one has call None
    "contrast.errored": "errored_calls",            # call numbers served with an error (outage)
    "contrast.unserved": "unserved_calls",          # call numbers: this run's id, no ledger row
    "contrast.unmapped": "unmapped_calls",          # entries: ledger rows whose id is in no table
    "contrast.baseline": "shared_baseline",         # call numbers in the shared baseline region
    # One entry of a call list, of the blocked list or of the unmapped list (an unmapped entry
    # also carries the ledger row's call id under `CALL_ID`).
    "entry.call": "call",                      # its table call number; None: no table row
    "entry.source": "source",                  # its ledger decision; None: no ledger row
    "entry.blocked": "blocked",                # bool (call lists only)
    # The token a cut-short world's reason names its failed write by (A12), per record, matched
    # as a whole word (`word_re`): the record's own name, never a bare English word a free-text
    # reason carries anyway ("served").
    "cut.ledger": "served_ledger",
    "cut.table": "executed_queries",
    # M3's section titles: host text, outside every untrusted frame (A10), one occurrence each.
    "title.header": "COMPUTED HEADER",
    "title.contrast": "CONTRAST TABLE",
    "title.surfaces": "FACT SURFACES",
    "title.aligned": "ALIGNED LEAD VIEW",
    "title.references": "REFERENCE RUNS",
    "title.focus": "JUDGED WORLD VIEWS",
    "title.noise": "NOISE CONTEXT",
    # A9: the words a stated cut uses, and what a cap refusal names (regular expressions).
    "re.cut": r"truncat|\bcut\b|trimmed",
    "re.cap_reason": r"payload[ _-]?cap|JUDGE_PAYLOAD_CAP|\bcap\b",
    # The episode page's per-world state words (A6 states as rendered), and the queue a
    # re-run's queueing refusal names.
    "page.in_progress": "in progress",
    "page.graded": "graded",
    "page.ungraded": "ungraded",
    "page.not_enqueued": "not enqueued",
    "refusal.defender_queue": "defender",
    "refusal.questioner_queue": "questioner",
    # A10: the reader contract's statement that text OUTSIDE the frames is the host's (titles,
    # run labels) — s_D2's contract sentence.
    "contract.host_text": "outside the frames",
    # Model-facing prose a ruling requires, spelled ONCE so the implementer's wording changes in
    # one place (matched case-insensitively; `re.*` entries are regular expressions over one
    # sentence or one span). M2/A2: the aligned lead view and fact surfaces label every match
    # with the heuristic word and mark the shared baseline region with the baseline word.
    "label.heuristic": "heuristic",
    "label.baseline": "baseline",
    # M3 / role.md: no sentence says every other world's facts are withheld; one says a
    # reference run's facts sit only in that run's labelled section.
    "re.withheld_rule": r"(?=.*withh(?:e|o)ld)(?=.*fact)(?=.*world)",
    "re.reference_rule": r"(?=.*reference)(?=.*fact)(?=.*section)(?=.*(?:only|labell?ed))",
    # g03: a line saying a layer is absent, and the word naming each optional layer.
    "re.layer_absent": r"\b(?:no|none|absent|not|unavailable|missing|never)\b",
    "layer.lessons": "lesson",
    "layer.samples": "sample",
    # M5 (i): the prompt instruction "cite family.yaml only where the flaw is in the plan".
    "re.plan_cite_rule": r"family\.yaml.{0,120}?\bonly\b.{0,120}?\bplan\b",
    # O16: the word a sample-citation drop's reason carries (A13 `unqueueable`).
    "reason.samples": "samples",
    # d08h/d08i "one home" (78-gate-resolutions, 2026-10-12): the ONE module, relative to
    # `defender/`, allowed to spell the retired names; every refusing reader imports from it.
    "module.retired_names": "learning/core/retired.py",
}

#: main's OWN names at 463833df that a test reads, or asserts the absence of. Not coinages: they
#: exist today (`EpisodeGrade`, `family.read_world`, the gates, `FindingRow`), so they live apart
#: from `COINED`; a test never spells one.
EXISTING = {
    "row.malformed_replies": "malformed_replies",      # EpisodeGrade: refused asks of a world
    "row.cut_short": "cut_short",                      # family.read_world's cut-short mark
    "row.ungradable": "ungradable",
    "record.stamp": "not_graded",                      # EpisodeGrade.not_graded
    "queue.held_reason": "held_reason",                # a row held at its gate
    "queue.alert_rule_key": "alert_rule_key",          # FindingRow
    "draw.dropped_findings": "dropped_findings",       # today's per-draw drop count (A13 retires)
    "row.draws_failed_reason": "draws_failed_reason",  # EpisodeGrade: a call that raised (P9)
    "row.finding_join": " — ",                         # FindingRow.finding: claim — root cause
}
STAMP = EXISTING["record.stamp"]

CALL_ID = COINED["field.call_id"]
INVESTIGATOR = COINED["reply.investigator"]
WORLD_FINDINGS = COINED["reply.world"]
GAPS = COINED["reply.gaps"]
EVIDENCE = COINED["finding.evidence"]
CONTRAST = RULED["finding.contrast"]
ON_PATH = RULED["finding.on_path"]
DOUBT = RULED["row.doubt"]
KEPT_FACTS = RULED["gap.kept_facts"]
STATE_KEY = RULED["row.state"]
QUEUEING = RULED["state.queueing"]
QUEUED = RULED["state.queued"]
USER = COINED["record.user"]
NAMED_GAPS = COINED["user.named"]
UNKEYED_GAPS = COINED["user.unkeyed"]
FOUND_GAPS = COINED["user.found"]
SERVING = COINED["user.serving"]
FAMILY_ROW = COINED["record.family"]
LEDGER = COINED["record.ledger"]

#: Every lane word a fate may take — distinct from each other and from the retired `withheld`.
LANES = {k.split(".", 1)[1]: v for k, v in COINED.items() if k.startswith("lane.")}

#: The four investigator buckets and `none` (WORLD_BUCKETS after M7); the three world-finding
#: buckets (design M4); the retired ones.
INVESTIGATOR_BUCKETS = ("lead-set", "lead-quality", "analyze-discipline", "decision-discipline")
NO_BUCKET = "none"
WORLD_FINDING_BUCKETS = ("unreachable", "incoherent", "mislabelled")
OBSERVABILITY = "observability"
#: Retired names A4 refuses by name at every reader (and FX-reply-retired-names at reply
#: validation): record fields, the reply words, the lanes.
RETIRED_RECORD_FIELDS = ("judge_outcome", "verdict_word", "episode_outcome", "family_outcome")
RETIRED_REPLY_WORDS = ("episode_outcome", "verdict_word")
RETIRED_FINDING_FIELD = "evidence"  # on an INVESTIGATOR finding (A1, NA08/AM7)
RETIRED_LANES = ("never_eligible", "withheld")
#: The family word vocabulary A4 / M19=A retires (`JUDGE_OUTCOME_ENUM` cannot be imported once
#: it is deleted), and the two retired enums by name (d08h).
RETIRED_FAMILY_WORDS = ("verdict_word", "caught", "survived", "undecidable")
RETIRED_ENUMS = ("JUDGE_OUTCOME_ENUM", "_REPLY_OUTCOME_ENUM")

#: The pointers A1 lists as never resolving (`{label}` filled by `never_resolving`).
NEVER_RESOLVE = ("judge.yaml", "worlds/{label}/judge/0.yaml", "wire_logs/x_framed_trace.jsonl",
                 "world_records/{label}.yaml", "not_comparable.yaml", "served/base.jsonl")

#: The family-scope call's label in agent ids (`judge:family:<n>`) and finding ids.
FAMILY = "family"

# --------------------------------------------------------------------------------------
# Re-exported vocabulary from the #947 / #921 / #1224 machinery.
# --------------------------------------------------------------------------------------

EPISODE_ID = T.EPISODE_ID
EPISODE_TOKEN = T.EPISODE_TOKEN
SYSTEMS = S24.SYSTEMS                       # ("edr", "idp", "siem-x") — the fixture tenant's
FIXTURE_TENANT = S24.FIXTURE_TENANT
world_token = T.world_token
report_text = T.report_text
provenance_record = T.provenance_record
investigation_document = J.investigation_document
untrusted_frames = T.untrusted_frames
outside_untrusted_frames = T.outside_untrusted_frames
assert_wrapped_untrusted = T.assert_wrapped_untrusted
FakeGitShow = J.FakeGitShow
refusals = J.refusals
read_jsonl = S24.read_jsonl
strings_in = S24.strings_in
grep_shipped = S24.grep_shipped
shipped_python = S24.shipped_python
source_text = S24.source_text
query_params = S24.query_params
canonical = S24.canonical
DENIED_QUERY_ID = "∅.denied"
REPEAT_TRIP_QUERY_ID = "∅.repeat-trip"
BASH_SHIM_QUERY_ID = "∅.bash-shim"
DENIED_EXIT = 77
REJECT_EXIT = 64


def marker(label: str, what: str) -> str:
    """A unique, grep-able token for one piece of one world's archived text (`MARK-b-report`).
    Every hand-built text artifact carries its own, so a test asks where a world's text LANDED
    (which prompt, inside which frame) by searching for it."""
    return f"MARK-{label}-{what}"


def label_re(label: str) -> re.Pattern[str]:
    """A run label as a whole token in host text: `wb` in `run wb` or `worlds/wb/`, never inside
    `MARK-wb-x` or another word. The ONE reading of A10's "a block labelled with that world"
    both prompt readers use: the run label the host text names last before a frame (or a span)
    owns it."""
    return re.compile(rf"(?<![A-Za-z0-9_\-]){re.escape(label)}(?![A-Za-z0-9_\-])")


#: An untrusted frame tag's per-message salt (`_untrusted.message_salt`, random by design).
_FRAME_SALT = re.compile(r"run-[0-9a-f]+-")


def unsalted(text: str) -> str:
    """`text` with every frame salt spelled alike. The salt is random per message by #680's
    design (an unguessable closer is what makes a frame hold), and A10 does not ask for it to be
    deterministic, so "byte-identical" prompts (s_A9, s_L24, d03k) are compared modulo it."""
    return _FRAME_SALT.sub("run-SALT-", text)


def normalized_prompt(prompt: str, where: Any) -> str:
    """`prompt` with what two otherwise-identical episodes differ by taken out: the frame salt
    and the episode's own root directory."""
    return unsalted(prompt).replace(str(_ep(where).parent), "<ROOT>")


def call_id(label: str, n: int, *, episode_token: str = EPISODE_TOKEN) -> str:
    """COINED (A12): the host-written id of call `n` of world `label`'s run — it names the run
    (the world token every ledger row of that run carries as `world_id`) and the call. The
    hand-built archive writes ONLY this spelling; a real-path archive is read, never planted."""
    return f"{world_token(label, episode_token=episode_token)}/{n}"


def call_ids(rows: Iterable[Mapping[str, Any]]) -> list[Any]:
    """The call id each row carries (`None` where it carries none), in row order."""
    return [r.get(CALL_ID) for r in rows]


def found_run(label: str) -> str:
    """How a found or named gap entry spells world `label`'s run (COINED `found.run_of`)."""
    return COINED["found.run_of"].format(label=label)


# --------------------------------------------------------------------------------------
# Pointers (A1's classes), episode-relative strings.
# --------------------------------------------------------------------------------------


def conduct(label: str, leaf: str = "report.md", frag: str | None = None) -> str:
    """A conduct pointer into world `label`'s archive (`worlds/<X>/<leaf>[#frag]`): report,
    investigation, gather summaries, query-table rows."""
    return f"worlds/{label}/{leaf}" + (f"#{frag}" if frag is not None else "")


def table_ptr(label: str, row: int) -> str:
    """COINED fragment: the query table's row by its 0-based line index."""
    return conduct(label, "executed_queries.jsonl", str(row))


def served_ptr(label: str, row: int | None, *, episode_token: str = EPISODE_TOKEN) -> str:
    """A1's served form, `served/<token>.<X>.jsonl#<row>` (0-based line index); `row=None`
    drops the fragment (NA03: unresolved)."""
    base = f"served/{world_token(label, episode_token=episode_token)}.jsonl"
    return base if row is None else f"{base}#{row}"


def oracle_ptr(label: str, leaf: str = "forged.jsonl", frag: str | None = None) -> str:
    """A built-layer pointer (`oracle/<X>/<leaf>[#frag]`) — its own class, never conduct."""
    return f"oracle/{label}/{leaf}" + (f"#{frag}" if frag is not None else "")


def plan_ptr(label: str | None = None) -> str:
    """A plan pointer: `family.yaml#worlds/<X>` names X's entry (A15); `label=None` is the
    family-level part (names no run). COINED fragment grammar."""
    frag = (COINED["frag.plan_family"] if label is None
            else COINED["frag.plan_world"].format(label=label))
    return f"family.yaml#{frag}"


def samples_ptr(system: str) -> str:
    """A context pointer at one served system's samples section."""
    return f"samples.yaml#{system}"


def outcome_ptr(frag: str = "not_replayable") -> str:
    """A context pointer into pre-flight's record."""
    return f"outcome.yaml#{frag}"


def never_resolving(label: str = "b") -> list[str]:
    """A1's never-resolve list, spelled for world `label`."""
    return [p.format(label=label) for p in NEVER_RESOLVE]


# --------------------------------------------------------------------------------------
# The hand-built archived episode.
# --------------------------------------------------------------------------------------

#: "Leave this field to the builder's default" — distinct from an explicit `None`.
AUTO: Any = object()


@dataclass
class CallRow:
    """One investigator call as BOTH records see it: the table row (`executed_queries.jsonl`,
    with its payload sidecar) and the served-ledger row, joined by one call id (A12).

    `source` is the ledger decision (`passthrough`, `oracle`, `real-error`, `refused`, `fault`);
    `None` writes no ledger row (a table-only sentinel: a reject, `∅.repeat-trip`,
    `∅.bash-shim`). `table=False` writes no table row (a ledger-only denial: the door closed,
    or an unmapped row). `inherited=True` is a pre-branch row seeded from the source: a table
    row carrying NO id of this run, never a ledger row (A12) — pass it in `family(inherited=)`
    so it lands identically at the head of every world's table. `call_id=None` omits the id,
    `call_id="<text>"` writes that text (malformed / foreign rows); `AUTO` mints `call_id()`.
    `world_id` likewise overrides the ledger row's world token (a foreign row).
    """

    system: str = "idp"
    verb: str = "query"
    params: dict | None = None
    source: str | None = "passthrough"
    table: bool = True
    lead: str = "l-001"
    query_id: str | None = None
    exit_code: int = 0
    payload: Any = None
    inherited: bool = False
    call_id: Any = AUTO
    world_id: Any = AUTO
    ledger_extra: dict = field(default_factory=dict)

    @property
    def the_params(self) -> dict:
        return dict(self.params) if self.params is not None else query_params("user:alice")


def oracle_call(q: str = "user:alice host:db-1", *, system: str = "idp", fact_id: str = "f1",
                forged_id: str = "fg-1", **kw: Any) -> CallRow:
    """An altered answer: an `oracle` ledger row carrying its claim and verifier verdict."""
    extra = {"claim": {"added": [{"forged_id": forged_id, "fact_id": fact_id}], "removed": [],
                       "changed": [], "counts": [], "entity_refs": []},
             "verifier_verdict": {"passed": True, "reason": "the fact's telemetry is present"},
             "attempts": 1, "base_digest": "0" * 64, **kw.pop("ledger_extra", {})}
    return CallRow(system=system, params=query_params(q), source="oracle", ledger_extra=extra,
                   **kw)


def refused_call(system: str = "edr", verb: str = "lookup", params: dict | None = None,
                 **kw: Any) -> CallRow:
    """A deployment refusal: the grant check's `∅.denied` table row (exit 77, error_class
    `denied`) and the registry's `refused` ledger row, one call id."""
    return CallRow(system=system, verb=verb, params=params or {"entity": "sent-real"},
                   source="refused", query_id=DENIED_QUERY_ID, exit_code=DENIED_EXIT, **kw)


def fault_call(system: str = "edr", verb: str = "query", params: dict | None = None,
               **kw: Any) -> CallRow:
    """An adapter that could not load: a `fault` ledger row (`resolve_call`, F-02=A) and an
    infra-exit table row."""
    return CallRow(system=system, verb=verb, params=params or query_params("host:db-1"),
                   source="fault", exit_code=2, **kw)


def error_call(system: str = "idp", verb: str = "query", params: dict | None = None,
               **kw: Any) -> CallRow:
    """A live outage the investigator saw: a `real-error` ledger row (served with an error,
    NOT a gap, A2) and a failed table row."""
    return CallRow(system=system, verb=verb, params=params or query_params("user:alice"),
                   source="real-error", exit_code=1, **kw)


def inherited_denial(system: str = "edr", verb: str = "lookup",
                     params: dict | None = None) -> CallRow:
    """J3's row: a pre-branch `∅.denied` table row the source wrote, inherited identically by
    every sibling (no id of any sibling run, no ledger row)."""
    return CallRow(system=system, verb=verb, params=params or {"entity": "sent-real"},
                   source=None, query_id=DENIED_QUERY_ID, exit_code=DENIED_EXIT,
                   inherited=True)


def fact(fact_id: str = "f1", statement: str | None = None,
         entities: Iterable[str] = ("alice", "db-1"), *, label: str = "b") -> dict:
    """One manifest fact; its default statement carries `marker(label, 'fact-<id>')`."""
    text = statement if statement is not None else (
        f"alice obtained a TGT and logged on to db-1 at 15:22Z {marker(label, 'fact-' + fact_id)}")
    return {"fact_id": fact_id, "statement": text, "entities": list(entities)}


@dataclass
class World:
    """One world of a hand-built family. A control is `role="A"` with `facts=[]` (M07=A).

    `reached` is the archived report's disposition (`AUTO`: the declared one; `None`: no
    report.md); `report` overrides the whole text. `calls` are the world's own post-branch
    calls (the family's `inherited` rows go first in its table). `forged` are the oracle
    store's frozen rows (`None`: one per fact on `forged_system`); `oracle=False` writes no
    store (a control legitimately has none, AM15). `run_end` writes `run_end.json` (a cut-short
    run: `{"truncated_by": "budget", "closed_before_cut": false}`). `world_record` writes
    `world_records/<X>.yaml` with that reason; `archived=False` leaves no `worlds/<X>/` at all
    (with `world_record`: a not-archived world)."""

    label: str
    role: str = "B"
    facts: list[dict] | None = None
    declared: str = "malicious"
    reached: Any = AUTO
    report: str | None = None
    investigation: Any = AUTO
    calls: list[CallRow] | None = None
    forged: list[dict] | None = None
    forged_system: str = "idp"
    oracle: Any = AUTO
    alert: bool = True
    lessons: bool = True
    summaries: bool = True
    provenance: bool = True
    run_end: dict | None = None
    world_record: str | None = None
    world_record_detail: str = ""
    archived: bool = True
    story: str | None = None
    axis: Any = AUTO
    label_basis: str = "policy-rule"
    goal: str | None = None

    @property
    def is_control(self) -> bool:
        return self.role == "A"


def control(label: str = "a", **kw: Any) -> World:
    """The control world: `facts: []`, declared benign (reached = declared), no oracle store."""
    kw.setdefault("declared", "benign")
    return World(label, role="A", facts=[], axis=None, **kw)


def planted(label: str, *, fact_id: str | None = None, role: str = "B", **kw: Any) -> World:
    """A planted world with one fact (`f-<label>` unless named) on `forged_system`."""
    fid = fact_id if fact_id is not None else f"f-{label}"
    kw.setdefault("facts", [fact(fid, label=label)])
    return World(label, role=role, **kw)


def triad(**per_world: dict[str, Any]) -> list[World]:
    """The default family: control `a`, planted `b` (one `oracle` answer: shown its facts) and
    `c` (one ordinary passthrough call on edr). `per_world={"b": {...}}` overrides a world's
    fields; a new label adds a planted world."""
    worlds: dict[str, dict[str, Any]] = {
        "a": {"calls": [CallRow()]},
        "b": {"calls": [CallRow(), oracle_call(fact_id="f-b", forged_id="fg-b-1")]},
        "c": {"calls": [CallRow(system="edr", params=query_params("host:db-1"))],
              "forged_system": "edr", "role": "C"},
    }
    for label, over in per_world.items():
        worlds.setdefault(label, {}).update(over)
    return [control(label, **spec) if label == "a" else planted(label, **spec)
            for label, spec in sorted(worlds.items())]


def pair(**per_world: dict[str, Any]) -> list[World]:
    """A pair family: control `a` and planted `b` only."""
    return [w for w in triad(**per_world) if w.label in ("a", "b")]


@dataclass
class Built:
    """A hand-built archived episode: its directory, token and worlds, and the addresses into it
    a test needs (every one episode-relative unless it ends in `_path`)."""

    ep: Path
    token: str
    worlds: dict[str, World]
    inherited: list[CallRow]

    @property
    def episode_id(self) -> str:
        return self.ep.name

    def world_dir(self, label: str) -> Path:
        return self.ep / "worlds" / label

    def table_path(self, label: str) -> Path:
        return self.world_dir(label) / "executed_queries.jsonl"

    def ledger_path(self, label: str) -> Path:
        return self.ep / "served" / f"{world_token(label, episode_token=self.token)}.jsonl"

    def oracle_path(self, label: str, leaf: str = "forged.jsonl") -> Path:
        return self.ep / "oracle" / label / leaf

    def conduct(self, label: str, leaf: str = "report.md", frag: str | None = None) -> str:
        return conduct(label, leaf, frag)

    def table(self, label: str, row: int) -> str:
        return table_ptr(label, row)

    def served(self, label: str, row: int | None) -> str:
        return served_ptr(label, row, episode_token=self.token)

    def oracle(self, label: str, leaf: str = "forged.jsonl", frag: str | None = None) -> str:
        return oracle_ptr(label, leaf, frag)

    def plan(self, label: str | None = None) -> str:
        return plan_ptr(label)

    def table_rows(self, label: str) -> list[dict]:
        return read_jsonl(self.table_path(label))

    def ledger_rows(self, label: str) -> list[dict]:
        return read_jsonl(self.ledger_path(label))

    def own_row(self, label: str, i: int) -> int:
        """The table line index of world `label`'s `i`-th own call (inherited rows go first)."""
        return len(self.inherited) + sum(1 for c in (self.worlds[label].calls or [])[:i]
                                         if c.table)

    def served_row(self, label: str, i: int) -> int:
        """The ledger line index of world `label`'s `i`-th own call (it must have a ledger row)."""
        calls = self.worlds[label].calls or []
        assert calls[i].source is not None, f"world {label}'s call {i} has no ledger row"
        return sum(1 for c in calls[:i] if c.source is not None)

    def finding_id(self, label: str, draw: int, index: int) -> str:
        """`<episode>/<world>/<draw>/<index>` (A11: form kept)."""
        return f"{self.ep.name}/{label}/{draw}/{index}"


def episodes_root(tmp_path: Path | None = None) -> Path:
    """The configured episodes root (this suite's conftest points it under `tmp_path`)."""
    configured = os.environ.get(EPISODES_BASE_ENV)
    if configured:
        return Path(configured)
    if tmp_path is None:
        raise AssertionError("no configured episodes root and no tmp_path")
    return Path(tmp_path) / "episodes-root"


def manifest_doc(worlds: Sequence[World], *, served_systems: Iterable[str] = SYSTEMS,
                 predicate: str = "did the analyst look at idp after the branch",
                 base_story: str | None = None, episode_id: str = EPISODE_ID,
                 **over: Any) -> dict:
    """The v2 manifest for `worlds` (`_spec1224.family_v2` underneath)."""
    entries = []
    for w in worlds:
        facts = [] if w.is_control else (w.facts if w.facts is not None else
                                         [fact(f"f-{w.label}", label=w.label)])
        axis = (None if w.is_control else "an axis") if w.axis is AUTO else w.axis
        entries.append(S24.world_v2(
            w.label, facts=facts, role=w.role,
            story=w.story if w.story is not None else f"story {marker(w.label, 'story')}",
            axis=axis, disposition_declared=w.declared, label_basis=w.label_basis))
    doc = S24.family_v2(worlds=entries, served_systems=served_systems, predicate=predicate,
                        **over)
    doc["episode_id"] = episode_id
    doc["base_story"] = base_story if base_story is not None else (
        f"the captured story {marker('base', 'story')}")
    return doc


def _payload_of(call: CallRow) -> Any:
    if call.payload is not None:
        return call.payload
    return {"rows": []} if call.exit_code == 0 else {"error": "never reached a system"}


def table_row(call: CallRow, *, seq: int, cid: Any) -> dict:
    """One `executed_queries.jsonl` row in the writer's column set (`QUERY_ROW_COLUMNS`), plus
    the coined call id where `cid` is not `None`."""
    rq = mod(RECORD_QUERY)
    breaker = mod("runtime.circuit_breaker")
    params = call.the_params
    body = _payload_of(call)
    text = json.dumps(body, sort_keys=True)
    out: dict[str, Any] = {
        "lead_id": call.lead, "seq": seq, "system": call.system, "verb": call.verb,
        "query_id": call.query_id or f"{call.system}.{call.verb}", "params": params,
        "raw_command": rq.raw_command(call.system, call.verb, params),
        "payload_path": f"gather_raw/{call.lead}/{seq}.json", "exit_code": call.exit_code,
        "error_class": breaker.error_class_for_exit(call.exit_code),
        "payload_status": rq.payload_status(call.exit_code, body), "payload_digest": "",
        "payload_sha256": rq.payload_sha256(text), "system_key": "",
    }
    if cid is not None:
        out[CALL_ID] = cid
    return out


def ledger_row(call: CallRow, *, label: str, token: str, cid: Any) -> dict:
    """One world-ledger row (`ServedCall.row()` shape plus the oracle fields), carrying the
    coined call id where `cid` is not `None`."""
    payload = call.payload if call.payload is not None else {"rows": []}
    wid = world_token(label, episode_token=token) if call.world_id is AUTO else call.world_id
    out: dict[str, Any] = {
        "system": call.system, "verb": call.verb, "params": call.the_params,
        "payload_text": json.dumps(payload, sort_keys=True), "source": call.source,
        "world_id": wid, **call.ledger_extra}
    if cid is not None:
        out[CALL_ID] = cid
    return out


def _write_table(world_dir: Path, written: list[tuple[CallRow, dict]]) -> None:
    lines = []
    for call, r in written:
        sidecar = world_dir / r["payload_path"]
        sidecar.parent.mkdir(parents=True, exist_ok=True)
        sidecar.write_text(json.dumps(_payload_of(call), sort_keys=True), encoding="utf-8")
        lines.append(json.dumps(r) + "\n")
    (world_dir / "executed_queries.jsonl").write_text("".join(lines), encoding="utf-8")


def _write_texts(wd: Path, w: World) -> None:
    """The world's text artifacts, each carrying its marker."""
    reached = w.declared if w.reached is AUTO else w.reached
    if w.report is not None:
        (wd / "report.md").write_text(w.report, encoding="utf-8")
    elif reached is not None:
        (wd / "report.md").write_text(report_text(
            reached, body=f"World {w.label} closed {reached}. {marker(w.label, 'report')}"),
            encoding="utf-8")
    investigation = (investigation_document(w.label) + f"\n{marker(w.label, 'investigation')}\n"
                     if w.investigation is AUTO else w.investigation)
    if investigation is not None:
        (wd / "investigation.md").write_text(investigation, encoding="utf-8")
    if w.provenance:
        (wd / "provenance.json").write_text(json.dumps(provenance_record()), encoding="utf-8")
    (wd / "scrub_verdict.json").write_text(json.dumps({"ran": True}), encoding="utf-8")
    if w.alert:
        (wd / "alert.json").write_text(json.dumps({
            "alert_id": J.ALERT_ID, "rule": {"id": J.ALERT_ID},
            "summary": marker(w.label, "alert")}), encoding="utf-8")
    if w.lessons:
        (wd / "lessons_loaded.jsonl").write_text(json.dumps({
            "lesson_name": "L1", "loaded_at": "2026-07-28T17:00:00Z",
            "path": "defender/lessons/L1.md", "note": marker(w.label, "lessons")}) + "\n",
            encoding="utf-8")
    if w.run_end is not None:
        (wd / "run_end.json").write_text(json.dumps(w.run_end), encoding="utf-8")


def _write_leads(wd: Path, w: World, leads: list[str]) -> None:
    if w.summaries:
        (wd / "gather_summaries").mkdir(exist_ok=True)
        for lead in leads:
            (wd / "gather_summaries" / f"{lead}.md").write_text(
                f"summary of {lead} for world {w.label} {marker(w.label, 'summary-' + lead)}\n",
                encoding="utf-8")
    gather_raw = wd / "gather_raw"
    gather_raw.mkdir(exist_ok=True)
    for lead in leads:
        (gather_raw / f"{lead}.lead.json").write_text(json.dumps({
            "goal": w.goal if w.goal is not None else
            f"measure {lead} {marker(w.label, 'goal-' + lead)}",
            "what_to_summarize": ["what the system says"]}), encoding="utf-8")


def _write_store(ep: Path, w: World) -> None:
    store = ep / "oracle" / w.label
    store.mkdir(parents=True, exist_ok=True)
    facts = w.facts if w.facts is not None else [fact(f"f-{w.label}", label=w.label)]
    forged = w.forged if w.forged is not None else [
        {"forged_id": f"fg-{w.label}-{i + 1}", "fact_id": f["fact_id"],
         "system": w.forged_system,
         "row": {"user": "alice", "event_id": f"e-{w.label}-{i + 1}", "host": "db-1",
                 "note": marker(w.label, "forged-" + f["fact_id"])}}
        for i, f in enumerate(facts)]
    (store / "forged.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in forged), encoding="utf-8")
    (store / "facts.jsonl").write_text(json.dumps(
        {"entity": "alice", "field": "logon_host", "value": "db-1"}) + "\n", encoding="utf-8")


def _archive_world(ep: Path, w: World, *, token: str, inherited: list[CallRow]) -> None:
    """`worlds/<X>/` plus its ledger and oracle store, as `archive_episode` and the sibling
    leave them."""
    wd = ep / "worlds" / w.label
    wd.mkdir(parents=True, exist_ok=True)
    _write_texts(wd, w)
    calls = list(w.calls or [])
    _write_leads(wd, w, sorted({c.lead for c in [*inherited, *calls]} | {"l-001"}))
    seqs: dict[str, int] = {}
    table: list[tuple[CallRow, dict]] = []
    ledger_out: list[dict] = []
    own_n = 0
    for call in [*inherited, *calls]:
        if call.inherited:
            cid = None if call.call_id is AUTO else call.call_id
        else:
            cid = (call_id(w.label, own_n, episode_token=token) if call.call_id is AUTO
                   else call.call_id)
            own_n += 1
        if call.table:
            seq = seqs.get(call.lead, 0)
            seqs[call.lead] = seq + 1
            table.append((call, table_row(call, seq=seq, cid=cid)))
        if call.source is not None and not call.inherited:
            ledger_out.append(ledger_row(call, label=w.label, token=token, cid=cid))
    _write_table(wd, table)
    served = ep / "served"
    served.mkdir(exist_ok=True)
    (served / f"{world_token(w.label, episode_token=token)}.jsonl").write_text(
        "".join(json.dumps(r) + "\n" for r in ledger_out), encoding="utf-8")
    if (not w.is_control) if w.oracle is AUTO else w.oracle:
        _write_store(ep, w)


def family(tmp_path: Path, worlds: Sequence[World] | None = None, *,  # noqa: PLR0913 — one switch per archived input
           inherited: Sequence[CallRow] = (), outcome: str | None = "accepted",
           not_replayable: Iterable[Mapping] = (), drift: Iterable[Mapping] = (),
           unservable: Iterable[Mapping] = (), samples: Any = AUTO,
           served_systems: Iterable[str] = SYSTEMS, family_stamp: bool = True,
           episode_id: str = EPISODE_ID, root: Path | None = None,
           predicate: str = "did the analyst look at idp after the branch",
           base_story: str | None = None, manifest_over: Mapping[str, Any] | None = None,
           base_rows: list[dict] | None = None, outcome_reason: str | None = None) -> Built:
    """A hand-built, archived, ACCEPTED v2 family (`triad()` by default) — the judge's and the
    page's whole input. No `runs/` container is written, so the door admits it (AP-10,
    45-dispositions-drift's door fixture obligation). `samples=AUTO` gives every served system
    one section of real answers; `None` writes no samples record. `outcome=None` writes no
    pre-flight record; `family_stamp=False` leaves the family not comparable; `outcome_reason`
    is pre-flight's `reason` text. `served/base.jsonl` (the family capture ledger) is written
    EMPTY unless `base_rows=` names its rows — a pointer at `base.jsonl#0` otherwise fails to
    resolve for the wrong reason (no such row)."""
    worlds = list(worlds if worlds is not None else triad())
    systems = list(served_systems)
    doc = manifest_doc(worlds, served_systems=systems, predicate=predicate,
                       base_story=base_story, episode_id=episode_id, **dict(manifest_over or {}))
    ep = T.episode(tmp_path, doc=doc, root=Path(root) if root is not None else
                   episodes_root(tmp_path), episode_id=episode_id)
    if base_rows is not None:
        T.base_capture(ep, base_rows)
    token = sym(FAMILY_LOADER, "episode_token_for")(episode_id)
    for w in worlds:
        if w.archived:
            _archive_world(ep, w, token=token, inherited=list(inherited))
        if w.world_record is not None:
            S24.world_record(ep, w.label, w.world_record, detail=w.world_record_detail)
    if samples is AUTO:
        S24.samples_record(ep, {s: {"verbs": {"query": [json.dumps(
            {"rows": [], "note": marker(s, "samples")})]}} for s in systems})
    elif samples is not None:
        S24.samples_record(ep, samples)
    if outcome is not None:
        extra = {} if outcome_reason is None else {"reason": outcome_reason}
        S24.outcome_record(ep, outcome, unservable=unservable, not_replayable=not_replayable,
                           drift=drift, family_stamp=family_stamp, **extra)
    return Built(ep=ep, token=token, worlds={w.label: w for w in worlds},
                 inherited=list(inherited))


# --------------------------------------------------------------------------------------
# Archive damage: real inputs through the real primitive.
# --------------------------------------------------------------------------------------


def _clear(path: Path) -> Path:
    path = Path(path)
    if path.is_symlink() or path.is_file():
        path.unlink()
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def plant_symlink(path: Path, target: Path | str) -> Path:
    """Replace `path` with a symbolic link to `target` (a relative target stays relative). Link
    to a `scratch_copy` outside the episode unless the target's own reading is the subject."""
    path = _clear(path)
    path.symlink_to(target)
    return path


def plant_hardlink(path: Path, target: Path) -> Path:
    """Replace `path` with a hard link to `target` (st_nlink > 1 on BOTH: a target inside the
    archive is damaged too — link to a `scratch_copy` outside the episode)."""
    path = _clear(path)
    os.link(target, path)
    return path


def plant_fifo(path: Path) -> Path:
    """Replace `path` with a FIFO (a reader that opens it blocking would hang)."""
    path = _clear(path)
    os.mkfifo(path)
    return path


def plant_dir(path: Path) -> Path:
    """Replace `path` with a directory (a no-follow writer or reader refuses it: `EISDIR`, or
    `NotPlainEntry` from the guarded `_io` primitives)."""
    path = _clear(path)
    path.mkdir(parents=True, exist_ok=True)
    return path


def plant_oversize(path: Path, *, over: int = 1) -> Path:
    """Make `path` a SPARSE file `over` bytes past `_io.READ_LIMIT` (no data written, so the
    test pays no disk): a bounded reader refuses it by `fstat` before reading."""
    limit = sym("_io", "READ_LIMIT")
    path = Path(path)
    if path.is_symlink():
        path.unlink()
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("ab"):
        pass
    os.truncate(path, limit + over)
    return path


def tear_jsonl(path: Path, text: str = '{"system": "idp", "verb"') -> Path:
    """Append a torn (unterminated, unparseable) line to a JSONL record."""
    with Path(path).open("a", encoding="utf-8") as fh:
        fh.write(text)
    return Path(path)


def second_disposition(path: Path, first: str = "benign", second: str = "malicious") -> Path:
    """Rewrite a report.md so its frontmatter carries TWO top-level `disposition:` keys (A3,
    GT-3: today `parse_report_text` and `episode.verdicts` read different ones)."""
    Path(path).write_text(
        "---\n"
        f"disposition: {first}\n"
        "outcome: stands\n"
        f"disposition: {second}\n"
        "---\nTwo headlines.\n", encoding="utf-8")
    return Path(path)


class _Hung(BaseException):
    """Raised by `no_hang`'s SIGALRM handler. A `BaseException`, so no `except Exception` in
    the pass can swallow the hang it names."""


@contextlib.contextmanager
def no_hang(seconds: float, what: str = "the pass") -> Iterator[None]:
    """Fail, never hang (OB5's alarm): a reader that opens a FIFO blocking waits forever, and
    `pytest-timeout` is not installed, so a hang would hold the shared test lock. Main thread
    only (true under `-p no:xdist` and in an xdist worker)."""
    def _expired(_sig: int, _frame: Any) -> None:
        raise _Hung

    previous = signal.signal(signal.SIGALRM, _expired)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    except _Hung:
        raise AssertionError(f"{what} hung past {seconds}s: a reader opened a special file "
                             "blocking") from None
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def scratch_copy(tmp_path: Path, src: Path, name: str) -> Path:
    """A byte copy of `src` OUTSIDE the episode (same filesystem), to link to: a hard link to a
    file inside the archive raises `st_nlink` on that file too and damages a second input."""
    out = Path(tmp_path) / "outside-the-episode" / name
    out.parent.mkdir(parents=True, exist_ok=True)
    if Path(src).is_dir():
        shutil.copytree(src, out)
    else:
        shutil.copyfile(src, out)
    return out


def copy_episode(src: Path, dest_root: Path) -> Path:
    """An archived episode copied under another episodes root, links kept as links (one real
    launch reused across variants)."""
    dest = Path(dest_root) / Path(src).name
    shutil.copytree(src, dest, symlinks=True)
    return dest


def rewrite_jsonl(path: Path, edit: Callable[[list[dict]], list[dict]]) -> list[dict]:
    """Read a JSONL record raw, apply `edit` to its rows, write it back; returns the rows."""
    out = edit(read_jsonl(path))
    Path(path).write_text("".join(json.dumps(r) + "\n" for r in out), encoding="utf-8")
    return out


# --------------------------------------------------------------------------------------
# The reply, in the amended shape (A1, A5, A13, F-14) — and the retired shapes (A4).
# --------------------------------------------------------------------------------------


def inv(bucket: str = "lead-quality", *, contrast: Sequence[str] | None = None,
        on_path: Any = True, claim: str = "the lead was never revisited",
        root_cause: str = "the investigator stopped after the first answer",
        anchor: str = "l-001", topic: str = "lead revisit", **over: Any) -> dict:
    """One investigator finding: `contrast_evidence` (default: b's report against the
    control's — a resolving two-run conduct pair when the focus world is `b`) and a boolean
    `on_verdict_path`. `over` adds or replaces any key (a retired `evidence=` included)."""
    doc: dict[str, Any] = {
        "bucket": bucket, "claim": claim, "root_cause": root_cause, "anchor": anchor,
        "topic": topic,
        CONTRAST: list(contrast) if contrast is not None else [conduct("b"), conduct("a")],
        ON_PATH: on_path}
    doc.update(over)
    return doc


def wf(bucket: str = "unreachable", *, systems: Sequence[str] | None = ("idp",),
       evidence: Sequence[str] | None = None, claim: str = "no served system shows the fact",
       root_cause: str = "the fact touches a system the tenant does not serve",
       anchor: str = "f1", topic: str = "fact reachability", **over: Any) -> dict:
    """One world finding with its OWN `systems` (A5; `systems=None` omits them) and its pointers
    (default: the plan pointer at b's entry — design-routed when not gap-only)."""
    doc: dict[str, Any] = {
        "bucket": bucket, "claim": claim, "root_cause": root_cause, "anchor": anchor,
        "topic": topic, EVIDENCE: list(evidence) if evidence is not None else [plan_ptr("b")]}
    if systems is not None:
        doc["systems"] = list(systems) if isinstance(systems, (list, tuple)) else systems
    doc.update(over)
    return doc


def gap(what: str = "edr lookup", how: str = "refused by the grant (denied)", *,
        evidence: Sequence[str] | None = None, kept_facts: Any = False, **over: Any) -> dict:
    """One deployment gap: what was blocked, how, its pointers, and F-14's boolean flag."""
    doc: dict[str, Any] = {
        COINED["gap.what"]: what, COINED["gap.how"]: how,
        EVIDENCE: list(evidence) if evidence is not None else [], KEPT_FACTS: kept_facts}
    doc.update(over)
    return doc


_PASSES = {"correlations": [{"from": "l-001", "to": "l-002", "fact": "db-1"}],
           "scope_checks": [{"lead": "l-001", "window": "24h"}],
           "derivations": [{"row": "h1", "from": "payload", "held": True}]}


def world_reply(bucket: Any = "lead-quality", systems: Any = ("idp",), *,
                investigator: Sequence[dict] = (), world: Sequence[dict] = (),
                gaps: Sequence[dict] = (), passes: bool = True,
                noise_floor_note: str = "one trial, no replicate", **over: Any) -> dict:
    """One world-scope reply in the amended shape: `bucket`, `systems`, and the three filed
    lists. No `episode_outcome` (retired). `over` adds or replaces keys (`episode_outcome=` for
    the retired-name scenarios); `bucket=None` omits bucket and systems."""
    doc: dict[str, Any] = {"noise_floor_note": noise_floor_note}
    if bucket is not None:
        doc["bucket"] = bucket
        doc["systems"] = list(systems) if isinstance(systems, (list, tuple)) else systems
    doc[INVESTIGATOR] = list(investigator)
    doc[WORLD_FINDINGS] = list(world)
    doc[GAPS] = list(gaps)
    if passes:
        doc.update(_PASSES)
    doc.update(over)
    return doc


def family_reply(*, world: Sequence[dict] = (), passes: bool = True,
                 noise_floor_note: str = "the family as a whole", **over: Any) -> dict:
    """One family-scope reply: family-scope world findings only, no verdict word (retired)."""
    doc: dict[str, Any] = {"noise_floor_note": noise_floor_note, WORLD_FINDINGS: list(world)}
    if passes:
        doc.update(_PASSES)
    doc.update(over)
    return doc


def as_text(doc: Any) -> str:
    """A reply document as the BARE text a model seam returns (#1018: one bare document)."""
    return doc if isinstance(doc, str) else _yaml.safe_dump(doc, sort_keys=False)


#: A world reply with nothing to queue (bucket `none`, no findings) — the default answer of a
#: judge whose subject is not the reply; and the family's equivalent.
QUIET = world_reply(NO_BUCKET, [])
QUIET_FAMILY = family_reply()


def validate(doc: Any, *, scope: str = "world", served_systems: Any = SYSTEMS, **kw: Any) -> Any:
    """`run.validate_reply(text, scope=, served_systems=)` over a reply document — the unit
    door for reply-shape demands (the pass's own re-ask is pinned through `grade`)."""
    return sym(JUDGE_RUN, "validate_reply")(as_text(doc), scope=scope,
                                            served_systems=served_systems, **kw)


def validate_refused(doc: Any, **kw: Any) -> BaseException:
    """`validate` expecting a refusal (`refusals()`, never bare `Exception`); an accepted reply
    is an `AssertionError`."""
    try:
        validate(doc, **kw)
    except refusals() as refused:
        return refused
    raise AssertionError("the reply validator accepted a reply the rulings refuse")


def defender_row(fid: str, *, label: str = "b", **over: Any) -> dict:
    """A defender queue row in d00d's post-change shape — today's keys and values minus
    `judge_outcome`, plus `contrast_evidence` (the resolving two-run pair, also its
    `citations`), `on_verdict_path` and `world_label_doubted` — under finding id `fid`; `over`
    replaces or adds any key (a retired `judge_outcome=`, `type=`, the alert key). For the
    appenders and gates driven with a hand-fed row (d05h, g10, d12a, the gate scenarios)."""
    run = fid.split("/", 1)[0]
    pair = [conduct(label), conduct("a")]
    row: dict[str, Any] = {
        "schema_version": 1, "finding_id": fid, "run_id": run,
        EXISTING["queue.alert_rule_key"]: "rule-5710", "direction": "family",
        "subject": "defender", "type": "lead-quality", "subject_anchor": "l-001",
        "subject_topic": "lead revisit",
        "finding": "the lead was never revisited — the investigator stopped after one answer",
        RULED["row.citations"]: list(pair), CONTRAST: list(pair), ON_PATH: True, DOUBT: False,
        "source_run_dir": f"episodes/{run}/worlds/{label}"}
    row.update(over)
    return row


def world_row(fid: str, *, label: str = "b", **over: Any) -> dict:
    """A questioner row in the post-change shape (d00e, d12b): a design world finding with its
    own systems and a plan-class citation, no `judge_outcome` key."""
    run = fid.split("/", 1)[0]
    row: dict[str, Any] = {
        "schema_version": 1, "finding_id": fid, "run_id": run,
        EXISTING["queue.alert_rule_key"]: "rule-5710", "direction": "world",
        "subject": "world", "type": "unreachable", "subject_anchor": "f1",
        "subject_topic": "fact reachability",
        "finding": "no served system shows the fact — the plan put it on an unserved system",
        RULED["row.citations"]: [plan_ptr(label)],
        "source_run_dir": f"episodes/{run}/worlds/{label}", "world": label,
        "systems": ["idp"], "provenance": "model"}
    row.update(over)
    return row


def pre_change_row(fid: str, *, judge_outcome: Any = "survived", **over: Any) -> dict:
    """A defender row as the pre-#1234 appender wrote it: the thirteen keys of G29, with
    `judge_outcome`, none of the three new fields, `citations` the old pointer list. The
    world is the one `fid` names (`<run>/<world>/<draw>/<index>`)."""
    label = fid.split("/")[1]
    row = {k: v for k, v in defender_row(fid, label=label).items()
           if k not in (CONTRAST, ON_PATH, DOUBT)}
    row["judge_outcome"] = judge_outcome
    row[RULED["row.citations"]] = [conduct(label)]
    row.update(over)
    return row


def pre_change_world_row(fid: str, **over: Any) -> dict:
    """A questioner row as the pre-#1234 appender wrote it: `judge_outcome` forced to None
    (G27), a non-plan citation (none could cite the manifest), valid `systems` — so what a
    reader meets is the retired name, not today's no-systems arm. The world is the one `fid`
    names."""
    label = fid.split("/")[1]
    row = world_row(fid, label=label, **{RULED["row.citations"]: [conduct(label)]})
    row["judge_outcome"] = None
    row.update(over)
    return row


# --------------------------------------------------------------------------------------
# The judge model seam: a recording, routed, fault-injecting stand-in.
# --------------------------------------------------------------------------------------


def parse_agent_id(agent_id: str) -> tuple[str | None, int | None, int]:
    """`judge:<label>:<n>[:<attempt>]` -> `(label, n, attempt)`; `(None, None, 0)` otherwise."""
    parts = str(agent_id).split(":")
    if len(parts) < 3 or parts[0] != "judge":
        return None, None, 0
    try:
        n = int(parts[2])
        attempt = int(parts[3]) if len(parts) > 3 else 0
    except ValueError:
        return parts[1], None, 0
    return parts[1], n, attempt


@dataclass
class RoutedJudge:
    """The judge's model seam (`judge=`): each call is answered by the reply routed to its
    world, draw and attempt, and RECORDED (prompt, agent id, kwargs).

    `replies` keys, most specific first: `(label, n, attempt)`, `(label, n)`, `label`
    (`"family"` for the family call). A value is reply text or a document (dumped bare), or a
    LIST consumed one per call made under that key. `default` answers any unrouted world call,
    `family_default` any unrouted family call; with neither, an unrouted call is an
    `AssertionError` (a scenario must say what every call answers).

    `fail` names calls that raise `RunUnprocessable` instead (#921's P9: the one class a
    timeout and a transport failure both surface as): an agent id, a label, or `(label, n)`.
    `overflow` names calls that raise `RunUnprocessable` over an HTTP 413 `ModelHTTPError` —
    claim P-AM28 (83-writer-probes, executed against the real `run_stage` seam with a mocked
    provider transport): a prompt over the provider's limit surfaces as exactly that chain,
    for the Anthropic and the Fireworks provider alike. The fake classifies nothing and
    decides nothing."""

    replies: dict[Any, Any] = field(default_factory=dict)
    default: Any = None
    family_default: Any = None
    fail: set[Any] = field(default_factory=set)
    overflow: set[Any] = field(default_factory=set)
    prompts: list[str] = field(default_factory=list)
    agent_ids: list[str] = field(default_factory=list)
    kwargs: list[dict] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def __call__(self, prompt: str, *, role: Any = None, agent_id: str = "judge",
                 **kw: Any) -> str:
        with self._lock:
            self.prompts.append(prompt)
            self.agent_ids.append(agent_id)
            self.kwargs.append({"role": role, "agent_id": agent_id, **kw})
        label, n, attempt = parse_agent_id(agent_id)
        if agent_id in self.fail or label in self.fail or (label, n) in self.fail:
            raise self._unprocessable(agent_id, RuntimeError("TransportFault"))
        if agent_id in self.overflow or label in self.overflow or (label, n) in self.overflow:
            raise self._unprocessable(agent_id, self._too_large())
        for key in ((label, n, attempt), (label, n), label):
            if key in self.replies:
                value = self.replies[key]
                if isinstance(value, list):
                    if not value:
                        raise AssertionError(
                            f"RoutedJudge: replies[{key!r}] ran out at {agent_id}")
                    value = value.pop(0)
                return as_text(value)
        if label == FAMILY and self.family_default is not None:
            return as_text(self.family_default)
        if label != FAMILY and self.default is not None:
            return as_text(self.default)
        raise AssertionError(f"RoutedJudge: no reply routed for {agent_id}")

    @staticmethod
    def _unprocessable(agent_id: str, inner: BaseException) -> BaseException:
        unprocessable = sym(CONFIG, "RunUnprocessable")
        raised = unprocessable(f"judge ({agent_id}) failed: {inner!r}")
        raised.__cause__ = inner
        return raised

    @staticmethod
    def _too_large() -> BaseException:
        """The provider's answer to an over-long prompt, as P-AM28 observed it (status 413)."""
        http_error = importlib.import_module("pydantic_ai.exceptions").ModelHTTPError
        return http_error(status_code=413, model_name="judge-model",
                          body={"error": {"type": "request_too_large",
                                          "message": "prompt is too long"}})

    @property
    def calls(self) -> int:
        return len(self.prompts)

    def calls_for(self, label: str) -> list[str]:
        """Agent ids of every call about world `label` (or `"family"`), in call order."""
        return [a for a in self.agent_ids if parse_agent_id(a)[0] == label]

    def called(self, label: str) -> bool:
        return bool(self.calls_for(label))

    def prompt_for(self, label: str, draw: int = 0, attempt: int = 0) -> str:
        """The prompt handed to the call `(label, draw, attempt)`."""
        for agent, prompt in zip(self.agent_ids, self.prompts, strict=True):
            if parse_agent_id(agent) == (label, draw, attempt):
                return prompt
        raise AssertionError(f"RoutedJudge: no call for {(label, draw, attempt)}; "
                             f"calls were {self.agent_ids}")

    def prompts_for(self, label: str) -> list[str]:
        return [p for a, p in zip(self.agent_ids, self.prompts, strict=True)
                if parse_agent_id(a)[0] == label]

    def system_prompts(self) -> list[Any]:
        """The system turn each call's wiring carried (`StageWiring.prompt_path`), in order."""
        return [getattr(k.get("wiring"), "prompt_path", None) for k in self.kwargs]


def judge(replies: Mapping[Any, Any] | None = None, **kw: Any) -> RoutedJudge:
    """A `RoutedJudge` answering every unrouted world call `QUIET` and the family call
    `QUIET_FAMILY` unless told otherwise."""
    kw.setdefault("default", QUIET)
    kw.setdefault("family_default", QUIET_FAMILY)
    return RoutedJudge(replies=dict(replies or {}), **kw)


# --------------------------------------------------------------------------------------
# Driving the pass, the page and the render.
# --------------------------------------------------------------------------------------


def env_state() -> Any:
    """A handle over the learning state root the environment names (what the launcher opens)."""
    from defender.tests._state1135 import env_state as _env_state

    return _env_state()


def state_over(root: Path) -> Any:
    """A handle over a queue folder of the test's own (`_state1135.state_over`): a variant that
    must not share the env-named queues (they dedup on `finding_id`)."""
    from defender.tests._state1135 import state_over as _state_over

    return _state_over(root)


def _ep(where: Any) -> Path:
    return Path(where.ep) if hasattr(where, "ep") else Path(where)


def grade(where: Any, judge_seam: Any = None, *, draws: int | None = 1, **kw: Any) -> Any:
    """`grade_episode(runs, episode_id, judge=, state=, draws=, git_show=)` over the episode
    (`_judge_921.grade_at`). `judge_seam=None` is `judge()`; `draws=None` reads `JUDGE_DRAWS`.
    Every A7/A13 scenario passes `draws>1` (I-6/I-7)."""
    kw.setdefault("git_show", FakeGitShow())
    kw.setdefault("state", env_state())
    if draws is not None:
        kw["draws"] = draws
    return J.grade_at(_ep(where), judge=judge_seam if judge_seam is not None else judge(), **kw)


def grade_refused(where: Any, judge_seam: Any = None, **kw: Any) -> BaseException:
    """Run `grade` expecting a refusal (`refusals()` — never bare `Exception`); return it."""
    try:
        grade(where, judge_seam, **kw)
    except refusals() as refused:
        return refused
    raise AssertionError("the pass was expected to refuse and did not")


def stops() -> tuple[type[BaseException], ...]:
    """What a stopped pass may raise: a refusal, or `StateRefused` (a `BaseException` the state
    handle raises when a queue append is refused — a directory planted at the queue's name).
    Kept apart from `refusals()`, so a "refused loudly" read never loosens; no ruling says
    whether the pass converts `StateRefused` into a run refusal."""
    return (*refusals(), sym(STATE, "StateRefused"))


def page(where: Any) -> str:
    """The episode page's HTML through `open_episode_view(runs, id)` + `build_page(view)`."""
    ep = _ep(where)
    ve = mod(VISUALIZE)
    with J.episodes_base(ep.parent), ve.open_episode_view(J.judge_runs(), ep.name) as view:
        return ve.build_page(view)


def render_context(where: Any, label: str, *, payload_cap: int = 20000,
                   git_show: Any = None) -> Any:
    """`render.render(episode_dir, label, ...)` with main's keyword tail threaded from the
    production readers (manifest, samples, pre-flight's record, the world's facts). Returns
    what render returns (#1234: a `JudgeContext`). If #1234 changes render's keyword tail,
    THIS is the one place to change."""
    ep = _ep(where)
    io = mod("_io")
    fam = mod(JUDGE_FAMILY)
    rnd = mod(JUDGE_RENDER)
    outcome = mod(OUTCOME)
    token_for = sym(FAMILY_LOADER, "episode_token_for")
    with io.bind(ep) as bound:
        manifest = fam.read_manifest(bound)
        samples = fam.read_samples_record(bound)
        try:
            pre = outcome.read_outcome(bound)
            failed = outcome.failed_worlds(bound, pre)
        except outcome.OutcomeUnreadable:
            pre, failed = None, {}
        world = next(w for w in manifest["worlds"] if w["world_id"] == label)
        _row, facts = fam.read_world(bound, world, episode_dir=ep,
                                     episode_token=token_for(fam.episode_id_of(manifest)))
        return rnd.render(ep, label, git_show=git_show if git_show is not None else FakeGitShow(),
                          payload_cap=payload_cap, facts=facts, lessons_commit=None,
                          manifest=manifest, samples=samples,
                          family_text=rnd.render_family_text(pre, failed), bound=bound)


# --------------------------------------------------------------------------------------
# Reading what the pass left.
# --------------------------------------------------------------------------------------


def record(where: Any) -> dict:
    """`judge.yaml`, read raw off disk (`{}` when absent)."""
    path = _ep(where) / "judge.yaml"
    if not path.is_file():
        return {}
    return _yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def record_text(where: Any) -> str:
    path = _ep(where) / "judge.yaml"
    return path.read_text(encoding="utf-8") if path.is_file() else ""


def rewrite_record(where: Any, edit: Callable[[dict], Any]) -> None:
    """Stage a persisted state in a judge.yaml a real pass wrote: read it raw, apply `edit` (in
    place), write it back; every other field stays as the pass wrote it."""
    path = _ep(where) / "judge.yaml"
    doc = record(where)
    assert doc, f"no judge.yaml at {path} to stage a state in"
    edit(doc)
    path.write_text(_yaml.safe_dump(doc, sort_keys=False), encoding="utf-8")


def stamp(where: Any) -> dict:
    """The family's not-graded stamp (main's `not_graded` mapping, with its `reason`); `{}`
    when the record carries none."""
    value = record(where).get(STAMP)
    return value if isinstance(value, dict) else {}


def page_text(where: Any) -> str:
    """The episode page's visible text (`_episode_1025.Page.parse(page(where)).text`)."""
    from defender.tests import _episode_1025 as E

    return E.Page.parse(page(where)).text


def rows(where: Any) -> dict[str, dict]:
    """World rows keyed by label — off disk (anything with `.ep`, or a path) or off a returned
    grade (an `EpisodeGrade` or its document)."""
    if hasattr(where, "ep") or isinstance(where, Path):
        worlds = record(where).get("worlds") or []
    else:
        worlds = where["worlds"] if isinstance(where, dict) else where.worlds
    return {r["world"]: r for r in worlds if isinstance(r, dict) and "world" in r}


def row(where: Any, label: str) -> dict:
    return rows(where).get(label) or {}


def family_row(where: Any) -> dict:
    """The family's own row on judge.yaml (COINED `family` mapping)."""
    value = record(where).get(FAMILY_ROW)
    return value if isinstance(value, dict) else {}


def user(where: Any) -> dict:
    """judge.yaml's user section (COINED `user`)."""
    value = record(where).get(USER)
    return value if isinstance(value, dict) else {}


def found_gaps(where: Any) -> list[dict]:
    return list(user(where).get(FOUND_GAPS) or [])


def named_gaps(where: Any) -> list[dict]:
    return list(user(where).get(NAMED_GAPS) or [])


def serving_findings(where: Any) -> list[dict]:
    return list(user(where).get(SERVING) or [])


def unkeyed_gaps(where: Any) -> list[dict]:
    """The user record's list of flagged named gaps with no blocked-call key (R1 (c))."""
    return list(user(where).get(UNKEYED_GAPS) or [])


def in_user_record(where: Any, *needles: str) -> bool:
    """Does judge.yaml's user section carry any of `needles` (a finding id, a claim marker)?
    Which of its lists holds a gap-only or serving finding is F2's; that it is there is the
    observation every slice shares (pair it with the finding's `user_record` lane)."""
    text = json.dumps(user(where), sort_keys=True, default=str)
    return any(n in text for n in needles)


def gap_key(entry: Mapping[str, Any]) -> tuple[Any, Any, Any, str]:
    """A found/named gap entry's blocked-call key (run, system, verb, canonical params)."""
    params = entry.get(COINED["found.params"])
    return (entry.get(COINED["found.run"]), entry.get(COINED["found.system"]),
            entry.get(COINED["found.verb"]),
            canonical(params) if isinstance(params, Mapping) else str(params))


def ledger(where: Any) -> list[dict]:
    """The record's ledger entries (`{finding_id, lane, reason}`), in walk order."""
    return list(record(where).get(LEDGER) or [])


def lanes(where: Any) -> dict[str, list[str]]:
    """Finding id -> every lane the ledger gives it (A13: exactly one each)."""
    out: dict[str, list[str]] = {}
    for entry in ledger(where):
        out.setdefault(str(entry.get("finding_id")), []).append(entry.get("lane"))
    return out


def lane_of(where: Any, finding_id: str) -> str | None:
    """The one lane the ledger gives `finding_id` (`None`: no entry; more than one fails)."""
    found = lanes(where).get(finding_id) or []
    assert len(found) <= 1, f"{finding_id} has {len(found)} ledger lanes: {found}"
    return found[0] if found else None


def draw_files(where: Any, label: str) -> list[Path]:
    return J.draw_files(_ep(where), label)


def draw_doc(where: Any, label: str, n: int) -> dict:
    return J.draw_doc(_ep(where), label, n)


def wire_log_records(where: Any) -> list[dict]:
    """Every judge wire-log record (`wire_logs/*_framed_trace.jsonl` rows naming an agent)."""
    d = _ep(where) / "wire_logs"
    out: list[dict] = []
    if not d.is_dir():
        return out
    for path in sorted(d.iterdir()):
        if path.is_file() and path.name.endswith("_framed_trace.jsonl"):
            out.extend(r for r in read_jsonl(path) if "agent_id" in r)
    return out


def episode_texts(where: Any, *, skip: Iterable[str] = ("wire_logs",)) -> dict[str, str]:
    """Every regular file under the episode as text (relative path -> text), `skip`ped top-level
    dirs out — for "stored nowhere but the wire log" (d03k)."""
    ep = _ep(where)
    skipped = tuple(skip)
    out: dict[str, str] = {}
    for path in sorted(ep.rglob("*")):
        rel = path.relative_to(ep).as_posix()
        if rel.split("/", 1)[0] in skipped or path.is_symlink() or not path.is_file():
            continue
        try:
            out[rel] = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
    return out


def defender_queue(state: Any = None) -> list[dict]:
    """The defender findings channel's rows, through the state handle's own reader."""
    return (state if state is not None else env_state()).rows(sym(STATE, "FINDINGS"))


def questioner_queue(state: Any = None) -> list[dict]:
    """The questioner findings channel's rows."""
    return (state if state is not None else env_state()).rows(sym(STATE, "QUESTIONER_FINDINGS"))


def from_world(queue_rows: Iterable[Mapping[str, Any]], label: str) -> list[dict]:
    """Queue rows whose finding id names world `label` (`<run>/<label>/<draw>/<i>`)."""
    return [dict(r) for r in queue_rows if f"/{label}/" in str(r.get("finding_id"))]


def queue_bytes(state: Any = None) -> tuple[str, str]:
    """Both queue files' raw text (defender, questioner) — for "byte-identical" demands."""
    st = state if state is not None else env_state()
    out = []
    for channel in ("FINDINGS", "QUESTIONER_FINDINGS"):
        described = Path(st.describe(sym(STATE, channel)))
        out.append(described.read_text(encoding="utf-8") if described.is_file() else "")
    return out[0], out[1]


# --------------------------------------------------------------------------------------
# The real path (I-10): the launcher, real pre-flight, real siblings in-process, real archive.
# --------------------------------------------------------------------------------------

#: The fixture's recorded answer, the forged row world b's oracle adds for its fact, and the
#: calls the source run made (three pre-branch on the held lead `l-001`, one post-branch).
BASE_ROW = {"user": "alice", "event_id": "e-100", "action": "logon", "host": "web-1",
            "ts": "2026-07-28T15:00:00Z"}
BASE_ANSWER = {"rows": [BASE_ROW]}
FORGED_B = {"user": "alice", "event_id": "e-1234-f1", "action": "logon", "host": "db-1",
            "ts": "2026-07-28T15:22:00Z"}
CHANGED_B = {"rows": [BASE_ROW, FORGED_B]}
Q1 = query_params("user:alice")
Q2 = query_params("host:db-1")
L3 = {"entity": "svc-1234"}
POST = S24.post_branch_call(payload=BASE_ANSWER)
QP = POST.params
DENIED_LOOKUP = {"entity": "sent-real"}
FACT_B = S24.fact("f1", "alice obtained a TGT and logged on to db-1 at 15:22Z", ("alice", "db-1"))
FACT_C = S24.fact("f2", "bob reset carol's password from 10.0.0.9", ("bob", "carol", "10.0.0.9"))
_MARK_FACT = {"b": "obtained a TGT", "c": "reset carol"}


def source_calls(*, post: bool = True) -> list[Any]:
    """The source run's captured calls (`_spec1224.Call`): three pre-branch, one post-branch."""
    calls = [S24.Call("idp", "query", Q1, BASE_ANSWER), S24.Call("edr", "query", Q2, BASE_ANSWER),
             S24.Call("siem-x", "lookup", L3, BASE_ANSWER)]
    return [*calls, POST] if post else calls


def capture_sentinel(src: Path, *, system: str = "edr", verb: str = "lookup",  # noqa: PLR0913 — one column each
                     params: Mapping[str, Any] | None = None, seq: int = 3,
                     query_id: str = DENIED_QUERY_ID, exit_code: int = DENIED_EXIT,
                     lead: str = "l-001") -> None:
    """Append one pre-branch sentinel row to the SOURCE run's table in the writer's own column
    set (J3's inherited `∅.denied` by default) — a real row the real `_inherit_evidence` seeds
    into every sibling."""
    rq = mod(RECORD_QUERY)
    breaker = mod("runtime.circuit_breaker")
    body = {"error": "never reached a system"}
    text = json.dumps(body, sort_keys=True)
    rel = f"gather_raw/{lead}/{seq}.json"
    sidecar = Path(src) / rel
    sidecar.parent.mkdir(parents=True, exist_ok=True)
    sidecar.write_text(text, encoding="utf-8")
    p = dict(params if params is not None else DENIED_LOOKUP)
    out = {"lead_id": lead, "seq": seq, "system": system, "verb": verb, "query_id": query_id,
           "params": p, "raw_command": rq.raw_command(system, verb, p), "payload_path": rel,
           "exit_code": exit_code, "error_class": breaker.error_class_for_exit(exit_code),
           "payload_status": rq.payload_status(exit_code, body), "payload_digest": "",
           "payload_sha256": rq.payload_sha256(text), "system_key": ""}
    with (Path(src) / "executed_queries.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(out) + "\n")


class Routed:
    """A model double that hands each request to the scripted double whose MARKER the request's
    inbound text carries (`last_wins`: the marker occurring last). It injects nothing: an
    unmatched request goes to `default`, else is answered text-only and recorded in `unrouted`
    (assert it empty). The `_spec1224` routing idiom (test_1224_preflight_and_outcome)."""

    __name__ = "Routed"

    def __init__(self, routes: Mapping[str, Any], *, default: Any = None, name: str = "routed",
                 last_wins: bool = False) -> None:
        self.routes = dict(routes)
        self.default = default
        self.name = name
        self.last_wins = last_wins
        self.unrouted: list[str] = []
        self._lock = threading.Lock()
        self._model: Any = None

    @property
    def model(self) -> Any:
        if self._model is None:
            from pydantic_ai.models.function import FunctionModel
            self._model = FunctionModel(self, model_name=S24.double_model_name(self.name))
        return self._model

    def __call__(self, messages: list[Any], info: Any) -> Any:
        text = S24._messages_text(messages) + "\n" + (getattr(info, "instructions", None) or "")
        hits = [double for m, double in self.routes.items() if m in text]
        if len(hits) > 1 and self.last_wins:
            hits = [self.routes[max(self.routes, key=text.rfind)]]
        if len(hits) == 1:
            return hits[0](messages, info)
        if not hits and self.default is not None:
            return self.default(messages, info)
        with self._lock:
            self.unrouted.append(text)
        from pydantic_ai.messages import ModelResponse, TextPart
        return ModelResponse(parts=[TextPart(content="(no scripted double for this request)")])


def passing_oracle() -> Any:
    """An oracle serving the recorded answer unchanged, empty claim, for every call."""
    return S24.oracle(then=S24.submit(BASE_ANSWER, S24.EMPTY_CLAIM))


def on_post(double: Any, *, name: str) -> Routed:
    """`double` answers the post-branch call (routed by its `q`); every other call passes."""
    return Routed({QP["q"]: double}, default=passing_oracle(), name=name, last_wins=True)


def altering_oracle(*, name: str = "oracle-b") -> Routed:
    """World b's sibling oracle: on the post-branch call it serves the forged row (claim adds
    fg-b-1 for f1); every other call passes unchanged."""
    return on_post(S24.oracle(S24.submit(CHANGED_B, S24.claim(added=[S24.added("fg-b-1", "f1")]))),
                   name=name)


def preflight_oracle() -> Routed:
    """Pre-flight's oracle for the default triad: b forges f1 on the post-branch call; c
    passes; routed by each world's fact statement."""
    forging = on_post(S24.oracle(
        S24.forge("fg-b-1", "f1", "idp", FORGED_B),
        S24.record_fact("alice", "logon_host", "db-1"),
        S24.submit(CHANGED_B, S24.claim(added=[S24.added("fg-b-1", "f1")]))), name="pre-b")
    return Routed({_MARK_FACT["b"]: forging, _MARK_FACT["c"]: passing_oracle()},
                  name="preflight")


def real_manifest() -> dict:
    """The questioner's family for the real path: control a, b (f1), c (f2)."""
    return S24.family_v2(worlds=[S24.control_world("a"), S24.world_v2("b", facts=[FACT_B]),
                                 S24.world_v2("c", role="C", facts=[FACT_C])])


def query_turn(system: str, verb: str, params: Mapping[str, Any]) -> Any:
    """One gather-agent `query` tool call, as the replay harness scripts it."""
    return S24.query_turn(system, verb, params)


def done_turn() -> Any:
    return S24.done_turn()


def default_turns() -> list[Any]:
    """Each sibling's gather lead: a repeat of the inherited pre-branch call, the post-branch
    call (world b's oracle alters it), and a call on the withheld `edr lookup` (refused: a
    `∅.denied` table row and a `refused` ledger row), then done."""
    return [query_turn("idp", "query", Q1), query_turn("idp", "query", QP),
            query_turn("edr", "lookup", DENIED_LOOKUP), done_turn()]


@dataclass
class RealWorld:
    """One real sibling's script: its gather `turns` (default `default_turns()`), its oracle
    double (default: passing; world b's `altering_oracle()` in the default triad), the report
    disposition written after the run (`None`: no report.md), `scrub=False` (no scrub verdict:
    archived as `not archived`), `exit_code` (the spawn reports it WITHOUT running the sibling:
    the launcher records `did not finish`), `after(run_dir)` (a hook before the archive).
    `concurrent_leads=True` puts every `main_leads` gather call in ONE main turn, which
    pydantic-ai runs concurrently (GT-1); otherwise each lead gets a turn of its own and the
    leads run one after another."""

    label: str
    turns: list[Any] | None = None
    oracle: Any = None
    disposition: str | None = "malicious"
    scrub: bool = True
    exit_code: int | None = None
    main_leads: tuple[str, ...] = ("l-001",)
    after: Callable[[Path], None] | None = None
    concurrent_leads: bool = False


class Estate1234(S24.Estate):
    """The #1224 fixture estate, its stub adapters re-planted with ONE extra, injection-only
    hook: an answers-table entry may carry `replace_with_dir` — a path pattern (`{run_dir}`,
    `{episode}`, `{label}` filled from the call's context, then globbed) whose matches the
    adapter replaces with a DIRECTORY just before it answers. The next write of that record by
    the real writer fails (the failed-write fault of A12 / n_t8_*; on main the table write
    raises `NotPlainEntry` out of `run.main`, the ledger write is swallowed — AP-01/JP-02).

    ONLY A FRESH KEY REACHES THE ADAPTER: inside a sibling, a key the family recording already
    holds (Q1, QP, Q2 — the pre-branch and post-branch calls of `default_turns()`) is served
    from that recording and the adapter is never called. Script the broken call on a key no
    recording holds (e.g. `query_params("user:bob")`) and add its `query_turn` to the world's
    turns. `{run_dir}` is then the sibling's run dir; during pre-flight it is the episode dir."""

    def __post_init__(self) -> None:
        super().__post_init__()
        for system in self.systems:
            (self.adapters / f"{system.replace('-', '_')}_adapter.py").write_text(
                _ADAPTER_1234.format(system=system, state=str(self.state)), encoding="utf-8")

    def break_write(self, system: str, verb: str, params: Mapping[str, Any] | None,  # noqa: PLR0913 — the call's key plus what it answers
                    pattern: str, *, payload: Any = None, fault: str | None = None) -> None:
        """On this call, replace every path `pattern` names with a directory before answering
        (`payload`, default the recorded answer) or raising the real `fault` class."""
        key = f"{system}|{verb}|" + ("*" if params is None else canonical(params))
        entry: dict[str, Any] = {"replace_with_dir": pattern}
        if fault is not None:
            entry.update(fault=fault, detail="upstream said no")
        else:
            entry["payload"] = payload if payload is not None else BASE_ANSWER
        self._put(key, entry)


_ADAPTER_1234 = S24._ADAPTER.replace(
    "    if \"fault\" in entry:\n",
    "    if \"replace_with_dir\" in entry:\n"
    "        import glob as _glob\n"
    "        run_dir = Path(str(getattr(ctx, \"run_dir\", \"\")))\n"
    "        pattern = entry[\"replace_with_dir\"].format(\n"
    "            run_dir=run_dir, episode=run_dir.parent.parent,\n"
    "            label=run_dir.name.rsplit(\"-\", 1)[-1])\n"
    "        for hit in _glob.glob(pattern):\n"
    "            p = Path(hit)\n"
    "            if p.is_dir() and not p.is_symlink():\n"
    "                continue\n"
    "            p.unlink()\n"
    "            p.mkdir()\n"
    "    if \"fault\" in entry:\n")
assert _ADAPTER_1234 != S24._ADAPTER, "fixture bug: the #1224 adapter template changed shape"


def _no_visualize(*_a: Any, **_k: Any) -> None:
    return None


def _no_preflight(*_a: Any, **_k: Any) -> int:
    return 0


class InProcessSiblings:
    """The launcher's `spawn=` seam: each sibling is the REAL `run.main --tenant T --episode
    <id> --world L`, run in-process (serialised: `start_family` spawns from N threads), its
    lifecycle driving the real investigation loop (replay harness) over the real world registry
    and query tool. After the drive it writes what the replay harness does not: the report
    (`RealWorld.disposition`), the reap scan's verdict sidecar (`scrub`), and a provenance
    stamp matching the source's (`verify_family` anchors siblings to the source commit; the
    real checkout's own stamp would make the family not comparable, which is not what these
    scenarios are about). Records every launch, run dir, rc and escaped exception."""

    def __init__(self, est: Estate1234, worlds: Mapping[str, RealWorld], *,
                 verifier: Any = None) -> None:
        self.est = est
        self.worlds = dict(worlds)
        self.verifier = verifier if verifier is not None else S24.passing_verifier()
        self._lock = threading.Lock()
        self.launches: list[dict[str, Any]] = []
        self.run_dirs: dict[str, Path] = {}
        self.rcs: dict[str, int] = {}
        self.errors: dict[str, BaseException] = {}
        self.gathers: dict[str, Any] = {}

    def __call__(self, argv: list[str], *, env: dict[str, str] | None = None, **_kw: Any) -> int:
        label = argv[argv.index("--world") + 1]
        with self._lock:
            self.launches.append({"argv": list(argv), "env": dict(env or {})})
            script = self.worlds.get(label) or RealWorld(label)
            if script.exit_code is not None:
                self.rcs[label] = script.exit_code
                return script.exit_code
            rc = self._run(script, argv[argv.index("--tenant"):])
            self.rcs[label] = rc
            return rc

    def _run(self, script: RealWorld, tail: list[str]) -> int:
        from defender.learning.branch.estate.registry import prebranch_calls
        from defender.runtime import branch as branch_mod

        harness = S24.replay_harness()
        oracle = script.oracle if script.oracle is not None else passing_oracle()
        label = script.label

        def lifecycle(**kw: Any) -> Any:
            run_dir = Path(kw["run"].run_dir)
            self.run_dirs[label] = run_dir
            fam = kw["world"].family
            src = Path(kw["source"].run_dir)
            spec = branch_mod.BranchSpec(
                source_run_dir=src, branch_message_id=fam.branch_message_id,
                continuation_prompt=fam.continuation_prompt, as_of=fam.as_of)
            leads = [("gather", {"lead_id": lid, "system": "idp", "goal": f"measure {lid}",
                                 "what_to_summarize": ["what the system says"]})
                     for lid in script.main_leads]
            gathers = ([harness.Turn(tool_calls=leads)] if script.concurrent_leads
                       else [harness.Turn(tool_calls=[call]) for call in leads])
            main = harness.ReplayFn([*gathers, harness.Turn(text="Investigation complete.")])
            gather = harness.ReplayFn(list(script.turns if script.turns is not None
                                           else default_turns()))
            self.gathers[label] = gather
            reg = S24.world_registry(Path(kw["episode"].dir), label, self.est, oracle=oracle,
                                     verifier=self.verifier, world=kw.get("world"),
                                     prebranch=prebranch_calls(_run_handle_1165(src), fam.branch_message_id))
            out = harness.drive(run_dir, run_id=run_dir.name, main=main, gather=gather,
                                verbs=reg, tenant=self.est.place(), resume=spec)
            if script.disposition is not None:
                (run_dir / "report.md").write_text(report_text(
                    script.disposition, body=f"World {label} closed. {marker(label, 'report')}"),
                    encoding="utf-8")
            (run_dir / "provenance.json").write_text(json.dumps(provenance_record()),
                                                     encoding="utf-8")
            if script.scrub:
                (run_dir.parent / f"{run_dir.name}.scrub-verdict.json").write_text(
                    json.dumps({"ran": True}), encoding="utf-8")
            if script.after is not None:
                script.after(run_dir)
            return out

        try:
            from defender.runtime.verbs import read_roster

            return mod(RUN).main(tail, lifecycle=lifecycle, visualize=_no_visualize,
                                 preflight=_no_preflight, oracle=oracle.model,
                                 verifier=self.verifier.model, roster=read_roster(self.est.adapters))
        except SystemExit as stop:
            return 0 if stop.code is None else (stop.code if isinstance(stop.code, int) else 2)
        except Exception as escaped:  # noqa: BLE001 — recorded for the scenario; rc 1 like a crashed child
            self.errors[label] = escaped
            return 1


@dataclass
class RealBuilt:
    """A real-path family: the episode, the estate, the spawn (its run dirs, rcs, errors,
    launches), and the launcher's rc and refusal text."""

    ep: Path
    est: Estate1234
    spawn: InProcessSiblings
    rc: int
    message: str

    @property
    def episode_id(self) -> str:
        return self.ep.name

    @property
    def token(self) -> str:
        return sym(FAMILY_LOADER, "episode_token_for")(self.ep.name)

    def table_path(self, label: str) -> Path:
        return self.ep / "worlds" / label / "executed_queries.jsonl"

    def ledger_path(self, label: str) -> Path:
        return self.ep / "served" / f"{world_token(label, episode_token=self.token)}.jsonl"

    def table_rows(self, label: str) -> list[dict]:
        return read_jsonl(self.table_path(label))

    def ledger_rows(self, label: str) -> list[dict]:
        return read_jsonl(self.ledger_path(label))

    def run_table_rows(self, label: str) -> list[dict]:
        """The sibling's own run-dir table (before archive), for runtime demands."""
        return read_jsonl(self.spawn.run_dirs[label] / "executed_queries.jsonl")

    def served(self, label: str, row: int | None) -> str:
        return served_ptr(label, row, episode_token=self.token)

    def finding_id(self, label: str, draw: int, index: int) -> str:
        return f"{self.ep.name}/{label}/{draw}/{index}"


@contextlib.contextmanager
def _launcher_judge_suppressed(tmp_path: Path) -> Iterator[None]:
    """For the launch only, the learning-state root names a directory that does not exist, so
    the launcher's JUDGE step (`cli._grade`) refuses to open its state, logs, and writes
    nothing; the test grades afterwards with its own judge. Restored after."""
    before = os.environ.get(LEARNING_STATE_ENV)
    os.environ[LEARNING_STATE_ENV] = str(Path(tmp_path) / "no-learning-state-during-launch")
    try:
        yield
    finally:
        if before is None:
            os.environ.pop(LEARNING_STATE_ENV, None)
        else:
            os.environ[LEARNING_STATE_ENV] = before


def real_family(tmp_path: Path, worlds: Mapping[str, RealWorld] | None = None, *,  # noqa: PLR0913 — one switch per real-path input
                calls: Iterable[Any] | None = None,
                withheld: Iterable[tuple[str, str]] = (("edr", "lookup"),),
                manifest: dict | None = None, preflight: Any = None, verifier: Any = None,
                after_source: Callable[[Path], None] | None = None,
                estate: Estate1234 | None = None) -> RealBuilt:
    """One episode through the REAL launcher and REAL siblings (I-10). Default: control `a`
    (reaches benign), `b` (its oracle alters the post-branch call: shown its facts), `c`
    (passes), each running `default_turns()`; `edr lookup` withheld, so every sibling's third
    call is refused. `after_source(src)` edits the source run before the launch (J3:
    `capture_sentinel(src)` plants the inherited pre-branch denial). `estate=` lets a scenario
    script faults (`Estate1234.break_write`) before the launch. Grade with `grade(built, ...)`."""
    est = estate if estate is not None else Estate1234(Path(tmp_path) / "estate",
                                                       withheld=tuple(withheld))
    scripts = {"a": RealWorld("a", disposition="benign"),
               "b": RealWorld("b", oracle=altering_oracle()),
               "c": RealWorld("c")}
    scripts.update(dict(worlds or {}))
    _base, src = S24.source_run(tmp_path, est, calls=list(calls) if calls is not None
                                else source_calls())
    if after_source is not None:
        after_source(src)
    spawn = InProcessSiblings(est, scripts, verifier=verifier)
    doc = manifest if manifest is not None else real_manifest()
    pre = preflight if preflight is not None else preflight_oracle()
    check = verifier if verifier is not None else S24.passing_verifier()
    seams = {"questioner": S24.questioner_for(doc), "preflight": S24.no_preflight,
             "live_tree": T.source_capture(), "roster": est.roster(), "judge": judge(),
             "oracle": pre.model, "verifier": check.model}
    root = episodes_root(tmp_path)
    before = {p.name for p in root.iterdir()} if root.is_dir() else set()
    message = ""
    with _launcher_judge_suppressed(tmp_path):
        try:
            rc = mod(CLI).main(["--tenant", src.parent.parent.name, src.name,
                                str(T.BRANCH_MESSAGE_ID), "--continuation-prompt", "go"],
                               spawn=spawn, **seams)
        except SystemExit as stop:
            rc, message = (stop.code, "") if isinstance(stop.code, int) else (2, str(stop.code))
    fresh = sorted(p for p in root.iterdir() if p.is_dir() and p.name not in before)
    if len(fresh) != 1:
        raise AssertionError(f"real_family: the launch made {len(fresh)} episodes "
                             f"(rc={rc}, {message!r})")
    return RealBuilt(ep=fresh[0], est=est, spawn=spawn, rc=rc, message=message)


# --------------------------------------------------------------------------------------
# Census helpers (parity demands): who calls / writes what, over the shipped tree.
# --------------------------------------------------------------------------------------


def _shipped_trees(under: str) -> Iterator[tuple[str, ast.AST]]:
    base = DEFENDER / under if under else DEFENDER
    for path in sorted(base.rglob("*.py")):
        rel = path.relative_to(DEFENDER).as_posix()
        if "__pycache__" in rel or rel.startswith(("tests/", ".venv/")):
            continue
        try:
            yield rel, ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue


def call_sites(name: str, *, under: str = "learning/judge") -> list[str]:
    """`rel:line` of every call to a function or method named `name` in shipped Python under
    `defender/<under>` (AST, so a comment or a string never counts)."""
    hits: list[str] = []
    for rel, tree in _shipped_trees(under):
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                fn = node.func
                called = fn.attr if isinstance(fn, ast.Attribute) else (
                    fn.id if isinstance(fn, ast.Name) else None)
                if called == name:
                    hits.append(f"{rel}:{node.lineno}")
    return hits


def defs_named(name: str, *, under: str = "") -> list[str]:
    """`rel:line` of every `def name` (module-level or nested) in shipped Python."""
    return [f"{rel}:{n.lineno}" for rel, tree in _shipped_trees(under) for n in ast.walk(tree)
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == name]


def word_re(word: str) -> re.Pattern[str]:
    """A whole-word pattern for a retired name (so `judge_outcomes_x` is not `judge_outcome`)."""
    return re.compile(rf"(?<![A-Za-z0-9_]){re.escape(word)}(?![A-Za-z0-9_])")
