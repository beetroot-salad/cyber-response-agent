"""Shared machinery for the #992 spec suite — NO test scripts (the leading underscore keeps
pytest from collecting it).

#992 puts the one close that claims a ceiling — `inconclusive` — through the challenge review
it used to bypass. Every test in the five `test_992_*.py` modules is one demand of
`spec-flow/specs/spec_graph_992.yaml`, named by that demand's `discharged_by`; this module
holds only what more than one of them needs.

RED AGAINST 67d29090 IS THE EXPECTED STATE. No implementation exists: `NO_REVIEW_DISPOSITIONS`
still carries `inconclusive`, `composer_projection` takes no disposition, `_route`/`_fail`
still hand every forced arm back as `unresolved`, the reviewed `_CloseFields` site has no
`ceiling_test`, and `REPORT_CAUSES` has six members. The fixtures below declare the DEMANDED
shapes, not today's.

THE §7 DECISIONS ENCODED HERE, AND NOT TO BE LOOSENED (70-resolutions.md):

* **FK-10 (human, against the judge): a ceiling-held `inconclusive` has its OWN cause.**
  `CEILING_EXAMINED` is the seventh `REPORT_CAUSES` member, verbatim. A composer `holds` on an
  `inconclusive` close commits it; a composer `holds` on a confident close still commits
  `CAUSE_STORY_SETTLED` and never the new sentence. The six shipped sentences are pinned as
  LITERALS (`SHIPPED_CAUSES`) rather than imported, so a reworded member fails the vocabulary
  demand instead of following it.
* **R6 (human, against the judge): the `ceiling_test` note is CAPPED at the entry-price gate**,
  at both boundaries, with the same refusal shape the over-cap receipt block already has. The
  VALUE is the implementer's (the spine's assumption was 2048 B over the accumulated rendered
  notes); the tests assert refusal-before-any-stage at whatever bound the code declares, and
  that the whole-file cap is unreachable by notes alone (`NOTE_LADDER`).
* **FK-8/FK-14 (human, with the judge): `_was_reviewed` keys on what the attempt LEFT BEHIND**
  — that round's trace rows and, for the terminal attempt, the report's cause — never on
  `NO_REVIEW_DISPOSITIONS`. Two populations: `reviewed_inconclusive_dir` (driven through the
  REAL close, so its record/traces/report are what production writes) and
  `pre_change_inconclusive_dir` (hand-written to G17's observed shape — the population the
  five Measurement run dirs belong to, which no post-change code can produce).
* **FK-6 (human, with the judge): the composer's ceiling sentence requires a RECORDED id**
  (`RECORD_ID_PREFIXES`), agreeing with the `citable_refs` guard it is read through.
* **FK-2 (human): a partially bound `ReviewStages` is a supported shape** — `RecordingBundle`
  builds one on request (`unbound=`), and it fails uniformly when the unbound role is
  dispatched.
* **C16 is REFUTED** — every e2e replay through `_replay_harness.drive` already reaches the
  gate BOUND (a `holds` composer). Nothing here "repairs" a fault that does not occur; the
  unbound-bundle rows use the two spellings that DO reach the gate unbound (`None`,
  `ReviewStages()`).
* **The composer-unreadable site carries `failure_kind: unreadable`, never `error`** (rg3,
  executed at every `_fail` site).
* **M4 sources receipts from the PRICE GATE's parse** (design M4, C14, G18): the committed
  block is `ceiling_test_block(conclude_ceiling_test_rows(<the priced companion>))`.

THE FIXTURES. `ceiling_companion()` is the shipped inconclusive golden (`golden-v2sshd`): two
paying receipts (`l-004`, `l-006`), a strong belief move citing `e-002` so the ablation lens IS
dispatched (executed: `ablation_target` → `('e-002', 2)`), and citable ids of all four prefixes.
`sparse_companion()` is `_spec923.paid()`: one receipt, NO strong move, so the ablation lens is
skipped with a `skipped` row and the per-close floor is two calls (G12/a2). Every fault below
is real input through the real primitive where one exists (a non-UTF-8 byte written into the
file, a directory where a file should be, an empty or missing companion); where the dependency
is a model, the fake injects the fault the ledger observed (a raise → `error`, a sleep past the
bound → `timeout`, text outside the reply contract → `unreadable`; x12/a1, rg3) and decides
nothing.

The fakes RECORD what they receive: `RecordingBundle` keeps every `StageRequest` per role, so
a payload demand asserts on the captured inbound prompt, never on the fake's canned reply.
"""
from __future__ import annotations

import asyncio
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

from defender.tests import _review_bundle, _spec923

DEFENDER = Path(__file__).resolve().parents[1]
GOLDEN_V2SSHD = DEFENDER / "fixtures-e2e" / "golden-v2sshd"

#: The keyword this change puts through the review, and the confident control beside it.
GAP = _spec923.GAP_MEMBER
CONFIDENT = "malicious"

#: §7 FK-10 — the SEVENTH `REPORT_CAUSES` member, verbatim: the ceiling-held arm's own sentence.
CEILING_EXAMINED = (
    "the challenge review examined the ceiling claim and found nothing further measurable"
)

#: The six shipped sentences, as LITERALS (close_tool.py:121-138 at 67d29090) so that a member
#: reworded at its home fails the vocabulary demand rather than being followed by it.
SHIPPED_CAUSES: tuple[str, ...] = (
    "the disposition was recorded without a challenge review",
    "the challenge review ran and left nothing about the finding unsettled",
    "the challenge review did not complete",
    "the evidence gathered cannot discriminate what the challenge review left unsettled",
    "the forced-turn budget was spent without settling what the challenge review raised",
    "nothing discriminating remains that the investigation was not already asked for",
)

#: SB-1: the three confident-question phrasings composer.md carries today (lines 1-2, 9, 32)
#: and must carry NOWHERE after M2 — grep-level, case-insensitive.
CONFIDENT_QUESTION_PHRASES: tuple[str, ...] = (
    "conclusion follows", "confident disposition", "evidence carries the conclusion",
)
#: The design's own words for the confident host sentence M2 moves into the user message
#: ("today's 'judge whether the conclusion follows'").
CONFIDENT_QUESTION = "conclusion follows"
#: The design's own words for the ceiling sentence (M2): the run closed `inconclusive`
#: claiming a ceiling; name anything MEASURABLE the record neither cited nor tested.
CEILING_QUESTION_MARKERS: tuple[str, ...] = ("inconclusive", "ceiling", "measurable")
#: §7 FK-6: the id prefixes the ceiling sentence must require the named thing be recorded
#: under — the same four `citable_refs` admits.
RECORD_ID_PREFIXES: tuple[str, ...] = ("v-", "e-", "l-", "h-")

#: One untrusted frame, whatever salt it carries — `_untrusted.wrap`'s exact shape.
FRAME_RE = re.compile(
    r"<run-(?P<salt>[0-9a-f]+)-(?P<tag>[^>\n]+)>\n(?P<body>.*?)\n</run-(?P=salt)-(?P=tag)>",
    re.DOTALL,
)


def host_text(prompt: str) -> str:
    """The prompt with every framed body cut out — what remains is the HOST's own text."""
    return FRAME_RE.sub("<FRAME>", prompt)


def framed_bodies(prompt: str) -> list[str]:
    return [m.group("body") for m in FRAME_RE.finditer(prompt)]


def normalized(prompt: str) -> str:
    """Salt-blind form of a prompt, so two calls' prompts can be compared for equality."""
    return re.sub(r"run-[0-9a-f]+-", "run-<SALT>-", prompt)


# ---------------------------------------------------------------------------------------
# Companions.
# ---------------------------------------------------------------------------------------

_V2SSHD_ARCHETYPE_ROW = "matched_archetype      unattributed-loopback-ssh-retry\n"
#: The note of the golden's first receipt (`l-004`), verbatim — the analyst-facing free text
#: the composer now reads.
V2SSHD_NOTE = "auditd/execve not collected on this non-containerized host"
#: The golden's receipts as `(state, ref)`, in document order — what the price gate prices.
V2SSHD_RECEIPTS = (("query-empty", "l-004"), ("query-failed", "l-006"))
#: A rationale row for the variant that carries one (`conclude.ceiling_rationale`, a real
#: companion scalar — schema.py:350).
V2SSHD_RATIONALE = (
    "authorized owner, no post-auth harm; the initiator process is the only unmeasured dimension"
)


def ceiling_companion(*, rationale: bool = False, note_prefix: str | None = None) -> str:
    """The shipped inconclusive golden, optionally with a `ceiling_rationale` row and/or a
    prefix spliced onto the first receipt's note (a note written to steer the reviewer).

    Both variants were executed through `validate_companion` at 67d29090 with zero
    diagnostics, so a scenario built on them is about the review and not about the price."""
    text = (GOLDEN_V2SSHD / "investigation.md").read_text(encoding="utf-8")
    assert _V2SSHD_ARCHETYPE_ROW in text, "the golden's conclude block moved; re-anchor"
    if rationale:
        text = text.replace(
            _V2SSHD_ARCHETYPE_ROW,
            _V2SSHD_ARCHETYPE_ROW + f'ceiling_rationale      "{V2SSHD_RATIONALE}"\n',
        )
    if note_prefix is not None:
        assert V2SSHD_NOTE in text
        text = text.replace(V2SSHD_NOTE, f"{note_prefix} {V2SSHD_NOTE}", 1)
    return text


def sparse_companion(*rows: str, disposition: str = GAP) -> str:
    """`_spec923.paid()` — one paying receipt (`l-002`), no strong belief move: the two-call
    floor (the ablation lens is skipped with a `skipped` row)."""
    return _spec923.paid(*rows, disposition=disposition)


def non_utf8_companion() -> bytes:
    """The golden with ONE undecodable byte in its prose, outside every invlang fence.

    Real input through the real primitive: the price gate reads leniently (`errors="replace"`)
    and prices the fences untouched, so the close reaches the gate — whose strict
    `read_text_utf8` raises. The one within-process way the gate's SECOND read alone fails
    (x6/a4): a missing or empty companion is refused by the price gate first."""
    raw = (GOLDEN_V2SSHD / "investigation.md").read_bytes()
    marker = b"Alert `v2-sshd-success-after-failures`"
    assert marker in raw, "the golden's prose moved; re-anchor"
    idx = raw.index(marker)
    return raw[:idx] + b"\xff" + raw[idx:]


def deps_over(tmp_path: Path, companion: str | bytes | None) -> tuple[Any, Path]:
    """MAIN deps through the real `bind` seam with `companion` as the run's investigation.md."""
    deps, run_dir = _spec923.main_deps(tmp_path, companion if isinstance(companion, str) else None)
    if isinstance(companion, bytes):
        (run_dir / "investigation.md").write_bytes(companion)
    return deps, run_dir


# ---------------------------------------------------------------------------------------
# The recording, fault-injecting review bundle.
# ---------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Fault:
    """One role's declarative fault. `raise_`: the stage raises `payload` (a real exception
    instance — the provider dropping the call). `sleep`: the stage sleeps `payload` seconds,
    past a `Bounds.stage_timeout` the scenario sets below it. `reply`: the stage answers
    `payload` verbatim — text outside the reply contract is how an `unreadable` is induced."""

    kind: str
    payload: Any = None


def raises(exc: BaseException) -> Fault:
    return Fault("raise", exc)


def sleeps(seconds: float) -> Fault:
    return Fault("sleep", seconds)


def replies(text: str) -> Fault:
    return Fault("reply", text)


class RecordingBundle:
    """A review bundle that RECORDS every `StageRequest` each role received and injects the
    declared faults — it classifies nothing and decides no policy.

    `composer` is the composer's reply (a `_review_bundle.composer_reply` line); `lens` every
    lens's reading; `faults` maps a role to its `Fault`; `unbound` names roles left `None` on
    the `ReviewStages` (FK-2's partial bundle). `calls` is the dispatch order the gate
    actually took."""

    def __init__(
        self, composer: str | Fault | None = None, *, lens: str = _review_bundle.LENS_READING,
        faults: dict[str, Fault] | None = None, unbound: tuple[str, ...] = (),
    ) -> None:
        self.faults = dict(faults or {})
        if isinstance(composer, Fault):
            # `recording(replies("not json"))`: a composer given as a fault spec IS the
            # composer's fault.
            self.faults["composer"] = composer
            composer = None
        self.composer = composer if composer is not None else _review_bundle.composer_reply("holds")
        self.lens = lens
        self.unbound = tuple(unbound)
        self.requests: list[tuple[str, Any]] = []

    @property
    def calls(self) -> list[str]:
        return [role for role, _ in self.requests]

    def prompts(self, role: str) -> list[str]:
        return [req.prompt for r, req in self.requests if r == role]

    def prompt(self, role: str) -> str:
        prompts = self.prompts(role)
        assert prompts, f"the {role} stage was never dispatched"
        return prompts[-1]

    def request(self, role: str) -> Any:
        found = [req for r, req in self.requests if r == role]
        assert found, f"the {role} stage was never dispatched"
        return found[-1]

    def _stage(self, role: str, reply: str) -> Any:
        fault = self.faults.get(role)

        async def call(request: Any) -> str:
            self.requests.append((role, request))
            if fault is None:
                return reply
            if fault.kind == "raise":
                raise fault.payload
            if fault.kind == "sleep":
                await asyncio.sleep(fault.payload)
                return reply
            return str(fault.payload)

        return call

    def bundle(self) -> Any:
        from defender.runtime.review_roles import ReviewStages

        stages = {
            "support": self._stage("support", self.lens),
            "ablation": self._stage("ablation", self.lens),
            "composer": self._stage("composer", self.composer),
        }
        for role in self.unbound:
            stages[role] = None
        return ReviewStages(**stages)


def recording(composer: str | Fault | None = None, **kw: Any) -> RecordingBundle:
    return RecordingBundle(composer, **kw)


def holds(review: str = "reads sound") -> str:
    return _review_bundle.composer_reply("holds", review=review)


def gap(target: str | None, prose: str = "the dimension nobody measured") -> str:
    """A `gap` reply: with `target` an ask naming it, with `None` the null-ask shape."""
    ask = None if target is None else {"target": target, "prose": prose}
    return _review_bundle.composer_reply("gap", review="something measurable was missed", ask=ask)


# ---------------------------------------------------------------------------------------
# Driving the real close, and reading what it left.
# ---------------------------------------------------------------------------------------

def close_with(
    deps: Any, disposition: str, stages: Any, *, bounds: Any = None, forced: bool = False,
) -> Any:
    """The REAL close (`_close_investigation_async`, both lanes' body) with `stages` bound.
    `stages` may be a `RecordingBundle`, a `ReviewStages`, or `None` (the unbound spelling
    the driver's fall-through would produce)."""
    bundle = stages.bundle() if isinstance(stages, RecordingBundle) else stages
    return _spec923.close(deps, disposition, stages=bundle, bounds=bounds, forced=forced)


def refusal(deps: Any, disposition: str, stages: Any, **kw: Any) -> str:
    """Drive the real close and return the refusal text, failing loudly if it committed."""
    from pydantic_ai.exceptions import ModelRetry

    with pytest.raises(ModelRetry) as e:
        close_with(deps, disposition, stages, **kw)
    return str(e.value)


def bounds(**kw: Any) -> Any:
    from defender.runtime import challenge_gate

    return challenge_gate.Bounds(**kw)


def review_state(deps: Any) -> Any:
    from defender.runtime import challenge_gate

    return challenge_gate.ReviewState.of(deps)


def trace_rows(run_dir: Path, role: str) -> list[dict]:
    """One role's trace METADATA rows (the framed raw-reply lines are skipped by the shared
    reader, exactly as every other trace consumer skips them)."""
    from defender._io import read_jsonl_rows
    from defender.runtime.challenge_gate import review_trace_path

    path = review_trace_path(run_dir, role)
    return list(read_jsonl_rows(path)) if path.is_file() else []


def trace_files(run_dir: Path) -> list[str]:
    from defender.runtime.challenge_gate import REVIEW_ROLES, review_trace_path

    return [role for role in REVIEW_ROLES if review_trace_path(run_dir, role).is_file()]


def record(run_dir: Path, turn: int) -> dict:
    from defender.runtime.challenge_gate import review_record_path

    return json.loads(review_record_path(run_dir, turn).read_text(encoding="utf-8"))


def record_files(run_dir: Path) -> list[int]:
    out = []
    for p in run_dir.glob("review_record.*.json"):
        m = re.fullmatch(r"review_record\.(\d+)\.json", p.name)
        if m:
            out.append(int(m.group(1)))
    return sorted(out)


def frontmatter(run_dir: Path) -> dict:
    """The committed report's frontmatter through the shared accessor."""
    return _spec923.committed(run_dir)


def report_text(run_dir: Path) -> str:
    return (run_dir / "report.md").read_text(encoding="utf-8")


def report_parts(run_dir: Path) -> tuple[str, str]:
    """`(raw frontmatter block, body)` of the committed report, as bytes on disk."""
    text = report_text(run_dir)
    head, _, rest = text.partition("---\n")[2].partition("---\n")
    return head, rest


def receipt_note_lines(body: str) -> list[str]:
    return [line for line in body.splitlines() if line.startswith("ceiling_test (")]


def priced_block(companion_text: str) -> str:
    """What the price gate's own parse of `companion_text` renders as the frontmatter receipt
    block — the bytes M4 must carry onto the reviewed commit."""
    from defender.runtime.review.projector import parse_investigation
    from defender.skills.invlang.validate import ceiling_test_block, conclude_ceiling_test_rows

    return ceiling_test_block(conclude_ceiling_test_rows(parse_investigation(companion_text)))


def citable(companion_text: str) -> frozenset[str]:
    from defender.runtime.review.projector import parse_investigation
    from defender.runtime.review.reply import citable_refs

    return citable_refs(parse_investigation(companion_text))


# ---------------------------------------------------------------------------------------
# The two run-dir populations the run page's readers must agree on (FK-8 / FK-14).
# ---------------------------------------------------------------------------------------

def reviewed_inconclusive_dir(tmp_path: Path, *, name: str = "reviewed") -> Path:
    """A POST-CHANGE run dir: an `inconclusive` close driven through the REAL close with a
    `holds` composer — whatever record, traces and report production writes for a reviewed,
    ceiling-held close is what lands here."""
    deps, run_dir = deps_over(tmp_path / name, ceiling_companion())
    result = close_with(deps, GAP, recording(holds()))
    assert result.outcome == "stands", f"the fixture close did not stand: {result!r}"
    run_dir.joinpath("alert.json").write_text(
        json.dumps({"rule": {"id": "5710", "key": "spec.rule"}, "timestamp": "2026-05-25T15:27:22Z"}),
        encoding="utf-8",
    )
    return run_dir


def pre_change_inconclusive_dir(tmp_path: Path, *, name: str = "historical") -> Path:
    """A PRE-#992 `inconclusive` run dir, in the shape the bypass wrote (G17, x1, executed):
    `review_record.1.json` = `{verdict: stands, reviewed_disposition: inconclusive, detail: "",
    failure_kind: null}`, `report.md` with `cause: CAUSE_NOT_REVIEWED` and the priced receipts,
    and NO `wire_logs/` at all — the five Measurement run dirs are this population, and no
    post-change code can produce it, so it is written by hand from the observed bytes."""
    from defender.runtime.challenge_gate import review_record_path

    run_dir = tmp_path / name
    (run_dir / "gather_raw").mkdir(parents=True)
    run_dir.joinpath("investigation.md").write_text(ceiling_companion(), encoding="utf-8")
    run_dir.joinpath("alert.json").write_text(
        json.dumps({"rule": {"id": "5710", "key": "spec.rule"}, "timestamp": "2026-05-25T15:27:22Z"}),
        encoding="utf-8",
    )
    run_dir.joinpath("report.md").write_text(
        "---\ndisposition: inconclusive\noutcome: stands\n"
        f"cause: {SHIPPED_CAUSES[0]}\n"
        "ceiling_test:\n- state: query-empty\n  ref: l-004\n- state: query-failed\n  ref: l-006\n"
        "---\nDisposition recorded by the close gate. outcome=stands.\n"
        f"ceiling_test (query-empty, l-004): {V2SSHD_NOTE}; process identity of the SSH "
        "initiator on office-ws-1 is unresolvable\n",
        encoding="utf-8",
    )
    review_record_path(run_dir, 1).write_text(json.dumps({
        "verdict": "stands", "reviewed_disposition": "inconclusive", "detail": "",
        "failure_kind": None,
    }, indent=2), encoding="utf-8")
    assert not (run_dir / "wire_logs").exists()
    return run_dir


def parsed_report(run_dir: Path) -> Any:
    from defender.scripts.visualize.visualize_primitives import parse_report

    return parse_report(run_dir)


# ---------------------------------------------------------------------------------------
# The note-cap ladder (§7 R6).
# ---------------------------------------------------------------------------------------

#: Note sizes, doubling, from well under any sane bound to past the WHOLE-FILE cap
#: (`_artifact_schema.REPORT_FILE_MAX` = 8192). The bound itself is the implementer's; the
#: ladder is how a test observes that the FIRST refusal is the price gate's and never the
#: commit's, whatever the value.
NOTE_LADDER: tuple[int, ...] = (128, 256, 512, 1024, 2048, 4096, 8192, 9000)


def note_text(note_len: int) -> str:
    """`note_len` characters of analyst-facing prose for a receipt's note."""
    return ("the EDR collector returned HTTP 503 and every retry did too; " * 400)[:note_len]


def noted_companion(note_len: int) -> str:
    """`_spec923.paid()` with a receipt whose note is `note_len` characters of prose."""
    return sparse_companion(f"state=query-failed ref=l-002 note={note_text(note_len)}")


def lenient_text(raw: bytes) -> str:
    """The bytes as the PRICE GATE reads them — `errors="replace"`, the decode
    `_read_companion_text` applies — so a scenario can name the parse M4's receipts come from."""
    return raw.decode("utf-8", errors="replace")


#: How many `query-failed` leads the wide companion declares — enough that the block cap, not
#: the lead count, bounds how many receipts pay.
_WIDE_LEAD_COUNT = 16


def _wide_leads() -> str:
    rows = ["l-001|1|sshd-auth-events-detail|v-001|||elastic|30d"]
    rows += [
        f"l-{n:03d}|1|collector-{n:03d}|v-001|collector {n:03d} returned HTTP 503||elastic|30d"
        for n in range(2, 2 + _WIDE_LEAD_COUNT)
    ]
    return (
        "```invlang\n"
        ":L findings [id|loop|name|target|fail_reason|tests|system|window]\n"
        + "".join(f"{row}\n" for row in rows) + "```\n"
    )


def wide_companion(receipts: int, note: str) -> str:
    """`_spec923`'s prologue and lead result over a WIDE `:L findings` table: `receipts`
    distinct paying `query-failed` receipts (one per failed lead) each carrying `note`."""
    assert 1 <= receipts <= _WIDE_LEAD_COUNT
    rows = tuple(f"state=query-failed ref=l-{n:03d} note={note}" for n in range(2, 2 + receipts))
    return _spec923.doc(_spec923.PROLOGUE, _wide_leads(), _spec923.LEAD_RESULT, _spec923.conclude(
        disposition=GAP, confidence="medium", **{"termination.category": "data-ceiling"},
        summary='"could not settle the actor"', ceiling_test=rows,
    ))


def receipts_at_block_cap() -> int:
    """The largest number of distinct `ref=` receipts the price gate's FRONTMATTER block cap
    admits (`_MAX_CEILING_FRONTMATTER_BYTES` over the rendered block) — computed against the
    real renderer, never assumed."""
    from defender.runtime.review.projector import parse_investigation
    from defender.skills.invlang.validate import ceiling_test_block, conclude_ceiling_test_rows
    from defender.skills.invlang.validate._gating import _MAX_CEILING_FRONTMATTER_BYTES

    best = 0
    for n in range(1, _WIDE_LEAD_COUNT + 1):
        block = ceiling_test_block(conclude_ceiling_test_rows(parse_investigation(wide_companion(n, "x"))))
        if len(block.encode("utf-8")) > _MAX_CEILING_FRONTMATTER_BYTES:
            break
        best = n
    assert 0 < best < _WIDE_LEAD_COUNT, best
    return best


__all__ = [
    "CEILING_EXAMINED",
    "CEILING_QUESTION_MARKERS",
    "CONFIDENT",
    "CONFIDENT_QUESTION",
    "CONFIDENT_QUESTION_PHRASES",
    "FRAME_RE",
    "GAP",
    "NOTE_LADDER",
    "RECORD_ID_PREFIXES",
    "SHIPPED_CAUSES",
    "V2SSHD_NOTE",
    "V2SSHD_RATIONALE",
    "V2SSHD_RECEIPTS",
    "Fault",
    "RecordingBundle",
    "bounds",
    "ceiling_companion",
    "citable",
    "close_with",
    "deps_over",
    "framed_bodies",
    "frontmatter",
    "gap",
    "holds",
    "host_text",
    "lenient_text",
    "non_utf8_companion",
    "normalized",
    "note_text",
    "noted_companion",
    "parsed_report",
    "pre_change_inconclusive_dir",
    "priced_block",
    "raises",
    "receipt_note_lines",
    "receipts_at_block_cap",
    "record",
    "record_files",
    "recording",
    "refusal",
    "replies",
    "report_parts",
    "report_text",
    "review_state",
    "reviewed_inconclusive_dir",
    "sleeps",
    "sparse_companion",
    "trace_files",
    "trace_rows",
    "wide_companion",
]
