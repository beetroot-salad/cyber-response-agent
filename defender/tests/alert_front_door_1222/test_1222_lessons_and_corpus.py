"""#1222 S10 — lessons and the invlang corpus: the signature as a key, end to end.

The slice's subject is what happens to a run's RECORDED signature after run start: the lessons
lookups (orientation's, and MAIN's taught one in its sandbox) match it exactly; the lesson author
is handed it on the queue row and a lesson written with it is found again; every lesson reader
takes a `source_signature` entry as the text written (C42); the invlang corpus, the held-out
index and the lesson tracer read past runs by their record and skip a recordless folder by name.

HOW EACH ACTOR IS REACHED (no attribute is ever patched):

* `cmd_grep` / `cmd_tags` (`defender-lessons`) have no corpus seam (`lessons_fm.LESSONS_DIR` is a
  module constant). They are reached the two ways production reaches them: orientation's lessons
  section (`S.run_alert(orient_shim=S.RecordingShim())`, the real `orient._shim` subprocesses),
  and MAIN's own `bash` call in its sandbox (drive's unboxed executor, the run's own env). MAIN's
  lookup is the one its INSTRUCTIONS teach: `_TaughtLookups` reads the `defender-lessons …
  <…signature…>` command line from the system prompt MAIN received and runs it as taught.
* `load_corpus` / the invlang CLI: orientation's vocabulary section, MAIN's `bash`, the CLI's
  own `main`, and `load_corpus` itself.
* `build_corpus_manifest`, `iter_lessons`, `match_lessons`, `trace_lesson`, `held_out`,
  `serialize.build_view`: their own entry points over a planted corpus or runs base.
* The lesson author: the REAL judge enqueue (`_judge_921.grade`) writes the queue rows from an
  episode carrying the record copy, and the REAL drain (`drain.run_batch`) hands them to the
  curator through the `invoke_agent=` seam. `_Curator` stands in for the model: it records what
  it was handed (and the user turn production builds for those rows) and writes the lesson text
  the TEST gives it — a fixture, never a policy. What the author writes is the model's; what
  production controls, and what these tests pin, is what it is handed and what becomes of the
  file it writes.

SCOPE (user correction, 2026-10-13): the curator and runtime retain one checkout-owned
corpus until #1108 P4 migrates writers, data, all retrieval paths, mounts and permissions
atomically. These tests run real shims in isolated product checkouts; they do not patch a
reader or redirect only discovery into a tenant folder.

BASE REGRESSIONS: (1) case-insensitive substring matching over-matches signatures.
(2) `S.plant_run(record=…)` and
`S.plant_episode_copy` fail at base on the coined record accessors; `_with_record` plants the
record AFTER the folder (alert, investigation, report) so the behavioural observation comes
first, and every test asserts the record was planted only after its behavioural assertions.
(3) The lesson-author tests fail first on the key the judge's enqueue writes today
(`rule-<world rule.id>`, not the recorded signature). p189 is green at base: the design leaves
the committed eval scenario as committed (C54), and its drive leg is blocked by a pre-existing
gap (82-writer red flag).
"""
from __future__ import annotations

import json
import os
import re
import shlex
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest

from defender import _tenant, _yaml
from defender.tests import _drain719 as D
from defender.tests import _judge_921 as J
from defender.tests.alert_front_door_1222 import _spec1222 as S

# =================================================================================================
# The shipped corpus and lesson files
# =================================================================================================

#: The frontier selector a lesson needs to be on `match_lessons`' lane (an open `class` cell on
#: a `process` vertex), written through `S.lesson_text(extra_lines=...)`.
_SELECTOR_LINES = ("frontier_nodes:", "  - {type: process, slot: class}")

_SOURCE_SIGNATURE_LINE = re.compile(r"^source_signature:\s*\[(.*)\]\s*$", re.M)


def _shipped_corpus() -> Path:
    """The shipped defender corpus, wherever it lives: production's own knowledge location
    first (`_knowledge.CHECKOUT_KNOWLEDGE.lessons_dir` until #1108 P4), then the committed
    tenants' agent corpora (where P4 may move it)."""
    candidates: list[Path] = []
    knowledge = S.mod("_knowledge")
    checkout = getattr(knowledge, "CHECKOUT_KNOWLEDGE", None)
    if checkout is not None:
        candidates.append(Path(checkout.lessons_dir))
    for corpus in candidates:
        if corpus.is_dir() and any(corpus.glob("*.md")):
            return corpus
    raise AssertionError(f"no shipped lesson corpus found among {candidates}")


def _declared(text: str) -> list[str]:
    """The entries a lesson file's `source_signature:` line declares, as written — read off the
    file's own line (the fixture), never through the production parser."""
    m = _SOURCE_SIGNATURE_LINE.search(text)
    if m is None:
        return []
    return [e.strip() for e in m.group(1).split(",") if e.strip()]


def _plant_shipped(planted: S.Planted) -> dict[str, list[str]]:
    """Copy the shipped corpus into the isolated checkout corpus; return stem -> declared entries."""
    shipped: dict[str, list[str]] = {}
    for path in sorted(_shipped_corpus().glob("*.md")):
        if path.name.startswith("_"):
            continue
        text = path.read_text(encoding="utf-8")
        S.plant_lesson(path.stem, text=text)
        shipped[path.stem] = _declared(text)
    assert shipped, "the shipped corpus holds no lesson"
    return shipped


def _manifest_entries(body: str) -> list[str] | None:
    """The non-blank `source_signature` entry lines of one manifest section (YAML block style:
    the key line, then one `- ` line per entry, or more lines when an entry wraps), up to the
    next key. None when the section lists no source_signature."""
    lines = body.splitlines()
    for i, line in enumerate(lines):
        if line.rstrip() == "source_signature:":
            out = []
            for nxt in lines[i + 1:]:
                if nxt.strip() and not nxt.startswith(("- ", " ", "\t")):
                    break
                if nxt.strip():
                    out.append(nxt)
            return out
    return None


def _declaring(lessons: Mapping[str, Sequence[str]], sig: str) -> set[str]:
    return {stem for stem, entries in lessons.items() if sig in entries}


# =================================================================================================
# Reading what the model received
# =================================================================================================

_HIT_LINE = re.compile(r"([^/\t\n]+)\.md\t")


def _section(text: str, want: Callable[[str], bool]) -> str | None:
    """The `## ` section of `text` whose heading line satisfies `want` — headings inside an
    untrusted frame are data, never sections — from its heading to the next one."""
    frames = S.untrusted_frames(text)

    def framed(pos: int) -> bool:
        return any(start <= pos < end for start, _o, _c, end in frames)

    heads = [m.start() for m in re.finditer(r"(?m)^## ", text) if not framed(m.start())]
    for i, at in enumerate(heads):
        nl = text.find("\n", at)
        heading = text[at: nl if nl >= 0 else len(text)]
        if want(heading):
            return text[at: heads[i + 1] if i + 1 < len(heads) else len(text)]
    return None


def _lessons_section(d: S.Drive) -> str:
    section = _section(d.opening_message, lambda h: h.lower().startswith("## lessons"))
    assert section is not None, (
        "MAIN's opening message carries no Lessons section:\n" + d.opening_message[-3000:])
    return section


def _vocab_section(d: S.Drive) -> str | None:
    return _section(d.opening_message, lambda h: "vocabulary" in h.lower())


def _listed(text: str) -> list[str]:
    """The lessons a lookup listed, by stem (`<path>\\t<description>` rows)."""
    return _HIT_LINE.findall(text)


def _tag_frame(section: str) -> str:
    """The framed `defender-lessons --tags` listing inside a Lessons section."""
    for body in S.framed_bodies(section):
        if re.search(r"(?m)^source_signature:", body):
            return body
    raise AssertionError("the Lessons section carries no framed tags listing:\n" + section)


def _tag_counts(section: str, dimension: str = "source_signature") -> dict[str, int]:
    """One dimension's block of the framed tags listing: value -> count."""
    body = _tag_frame(section)
    counts: dict[str, int] = {}
    inside = False
    for line in body.splitlines():
        if not line.startswith((" ", "\t")):
            inside = line.strip() == f"{dimension}:"
            continue
        if inside and line.strip():
            value, _, count = line.strip().rpartition(" ")
            counts[value.strip()] = int(count) if count.isdigit() else -1
    return counts


def _naming(section: str | None, sig: str, d: S.Drive) -> list[str]:
    """The HOST's lines of `section` that name `sig`, normalised (frames, run folder, run id)."""
    if section is None:
        return []
    prose = S.normalize(S.harness_text(section), run_dir=d.run_dir,
                        run_id=d.run_dir.name if d.run_dir else None)
    return [ln.strip() for ln in prose.splitlines() if sig in ln]


def _same_text(section: str | None, d: S.Drive) -> str | None:
    if section is None:
        return None
    return S.normalize(section, run_dir=d.run_dir, run_id=d.run_dir.name if d.run_dir else None)


# =================================================================================================
# MAIN running the lessons lookup its instructions teach
# =================================================================================================

_PLACEHOLDER = re.compile(r"<[^<>\n]*(?:signature|rule)[^<>\n]*>", re.IGNORECASE)
_TAUGHT_LINE = re.compile(r"^\s*(defender-lessons\b[^\n]*)$", re.MULTILINE)


def _taught_lookup(instructions: str) -> str | None:
    """The `defender-lessons` command line MAIN's instructions teach for the alert's signature:
    the first such line carrying a `<…signature…>` / `<…rule…>` placeholder."""
    for m in _TAUGHT_LINE.finditer(instructions):
        line = m.group(1).rstrip().removesuffix("\\").rstrip()
        if _PLACEHOLDER.search(line):
            return line
    return None


def _instantiate(line: str, sig: str) -> list[str]:
    """The taught command for `sig`: its words up to and including the one holding the
    placeholder, with the placeholder replaced by `sig`."""
    words = shlex.split(line)
    for i, word in enumerate(words):
        if _PLACEHOLDER.search(word):
            return [*words[:i], _PLACEHOLDER.sub(lambda _m: sig, word, count=1)]
    raise AssertionError(f"no placeholder word in the taught lookup {line!r}")


class _TaughtLookups(S.MainScript):
    """MAIN runs, once per signature, the lessons lookup its received instructions teach, then
    stops. The command is read off the system prompt MAIN was handed (never spelled here), so a
    lookup that is taught but refused by MAIN's own gate, or taught and inexact, shows."""

    def __init__(self, signatures: Sequence[str]) -> None:
        super().__init__([S.text(S.DONE)])
        self.signatures = list(signatures)
        self.taught: str | None = None
        self.argvs: list[list[str]] = []

    def __call__(self, messages: Any, info: Any) -> Any:
        with self._lock:
            if not self._script.seen:
                self.taught = _taught_lookup(getattr(info, "instructions", None) or "")
                if self.taught is not None:
                    self.argvs = [_instantiate(self.taught, sig) for sig in self.signatures]
                    self._script.turns[:0] = [S.call("bash", command=shlex.join(argv))
                                              for argv in self.argvs]
            return self._script.answer(messages, info)

    def results(self) -> dict[str, str]:
        """signature -> the tool result its lookup came back with."""
        assert self.taught is not None, (
            "MAIN's instructions teach no lessons lookup keyed on the signature (no "
            "`defender-lessons … <…signature…>` line in the system prompt MAIN received)")
        out: dict[str, str] = {}
        for k, sig in enumerate(self.signatures, start=1):
            assert len(self.seen) > k, f"MAIN was never answered for its lookup of {sig!r}"
            back = [t for kind, t in self.seen[k].parts if kind in ("tool-return", "retry-prompt")]
            out[sig] = back[-1] if back else ""
        return out


# =================================================================================================
# Past runs
# =================================================================================================

_GOLDEN_HYPOTHESIS = "?scanner-or-noise-probe"


def _investigation(tag: str) -> str:
    """The golden investigation with one hypothesis renamed `?<tag>-probe`, so a vocabulary
    listing shows which past run it counted."""
    doc = (S.H.GOLDEN / "investigation.md").read_text(encoding="utf-8")
    assert _GOLDEN_HYPOTHESIS in doc
    return doc.replace(_GOLDEN_HYPOTHESIS, f"?{tag}-probe")


def _with_record(runs_base: Path, run_id: str, *, alert: Mapping[str, Any] | bytes,
                 facts: Mapping[str, str | None] | None = None,
                 record: Mapping[str, Any] | None = None, digest: str | None = None) -> bool:
    """Give an already-planted folder its record (`S.plant_run`). False when the coined record
    accessor is absent (base): the folder then stays recordless, and the caller asserts the
    record was planted only after its behavioural observation."""
    try:
        S.plant_run(runs_base, run_id, alert=alert,
                    record=dict(record) if record is not None else True,
                    digest=digest, facts=facts)
    except AssertionError:
        return False
    return True


def _past_run(runs_base: Path, run_id: str, *, tag: str, rule_id: str = "R-PAST",  # noqa: PLR0913 — one past run's every part
              alert: Mapping[str, Any] | bytes | None = None,
              signature: str | None = None, recorded: bool = True,
              digest: str | None = None, report: str | None = None) -> bool:
    """A finished past run: its alert, an investigation whose hypothesis carries `tag`, an
    optional report, then (when `recorded`) its record with `signature`. Returns whether the
    record landed (always True for a recordless folder)."""
    doc = alert if alert is not None else S.generic_alert(rule_id=rule_id)
    files = {"investigation.md": _investigation(tag)}
    if report is not None:
        files["report.md"] = report
    S.plant_run(runs_base, run_id, alert=doc, record=False, files=files)
    if not recorded:
        return True
    return _with_record(runs_base, run_id, alert=doc,
                        facts={"signature": signature} if signature is not None else {},
                        digest=digest)


# =================================================================================================
# The lesson author, through the real judge enqueue and the real drain
# =================================================================================================

FINDINGS = S.sym("learning.core.state", "FINDINGS")


@dataclass
class _Curator:
    """The curator model's place at the `invoke_agent=` seam. Records what it was HANDED (the
    rows, and the user turn production's own builder makes of them) and writes the lesson files
    the test gives it. It decides nothing about any row."""

    lessons: Mapping[str, str]
    handed: list[list[dict]] = field(default_factory=list)
    user_turns: list[str] = field(default_factory=list)

    def __call__(self, rows: list[dict], batch_id: str, cfg: Any) -> dict:
        self.handed.append([dict(r) for r in rows])
        builder = S.sym("learning.author.lessons.run", "build_user_prompt")
        self.user_turns.append(builder(rows, batch_id, cfg))
        for name, text in self.lessons.items():
            (Path(cfg.corpus_dir) / f"{name}.md").write_text(text, encoding="utf-8")
        ids = [r["finding_id"] for r in rows]
        return {"committed": ids, "consumed_skip": [], "held_forward_bad": [],
                "commit_message": "front-door fixture lessons"}

    def rows(self) -> list[dict]:
        return [r for batch in self.handed for r in batch]


def _judged(tmp_path: Path, *, signature: str | None, world_rule: str | None = None,
            sub: str = "judged") -> tuple[list[dict], bool]:
    """Grade an accepted episode whose record copy holds `signature` (None: no signature) and
    return the finding rows the REAL enqueue appended. `world_rule` rewrites every world copy's
    `alert.json` to that id first — what a box that rewrote its alert leaves (PR-17)."""
    ep = J.accepted_episode(tmp_path / sub)
    if world_rule is not None:
        for alert in (ep / "worlds").glob("*/alert.json"):
            alert.write_text(json.dumps({"alert_id": world_rule, "rule": {"id": world_rule}}),
                             encoding="utf-8")
    try:
        S.plant_episode_copy(ep, facts={"signature": signature} if signature else {})
        copied = True
    except AssertionError:
        copied = False
    runs_base = tmp_path / sub / "runs-base"
    runs_base.mkdir(parents=True, exist_ok=True)
    J.grade(ep, runs_base=runs_base)
    return J.enqueued_rows(J.judge_record(ep)), copied


def _drain(tmp_path: Path, curator: _Curator, *, extra_rows: Iterable[dict] = (),
           corpus: Mapping[str, str] | None = None) -> Any:
    """One REAL drain tick (`drain.run_batch`) over the learning state the judge appended to,
    the curator at `invoke_agent=`; `corpus` lessons are committed to the drain's corpus first
    (lessons a fold lands in). Returns the drain's `LoopPaths`."""
    paths = D.make_paths(tmp_path, state_dir=tmp_path / "learning-state")
    if corpus:
        for name, text in corpus.items():
            (Path(paths.lessons_dir) / f"{name}.md").write_text(text, encoding="utf-8")
        D.git(Path(paths.repo_root), "add", "-A")
        D.git(Path(paths.repo_root), "commit", "-q", "-m", "existing lessons")
    extra = list(extra_rows)
    if extra:
        D.seed(paths, FINDINGS, D.pending(paths, FINDINGS) + extra)
    cfg = D.cfg_for(paths, "findings", invoke_agent=curator)
    rc = S.sym("learning.author.drain", "run_batch")(cfg=cfg)
    assert rc == 0, f"the drain tick failed (rc={rc})"
    return paths


def _committed(paths: Any) -> dict[str, Any]:
    """The drain corpus as production's own reader yields it: stem -> Lesson."""
    iter_lessons = S.sym("_corpus", "iter_lessons")
    return {lesson.path.stem: lesson for lesson in iter_lessons(Path(paths.lessons_dir))}


def _keys_handed(curator: _Curator) -> dict[str, Any]:
    return {r["finding_id"]: r.get("alert_rule_key") for r in curator.rows()}


def _signatures_handed(curator: _Curator) -> dict[str, Any]:
    """Each handed row's recorded signature as the row carries it in its own field (B2); None
    when the row carries none there (an unsigned run's row, a row queued before the change)."""
    return {r["finding_id"]: r.get(S.QUEUE_SIGNATURE_FIELD) for r in curator.rows()}


def _signature_paragraphs(prompt: str) -> list[str]:
    """The curator-instruction paragraphs naming both a lesson's `source_signature` and the row's
    signature field — where the instructions say a lesson's signature comes from that field (B2).
    A word-level pin: an implementer whose correct wording trips it loosens the word list to their
    own words and never removes the check (§7 round 3, B5)."""
    return [para for para in re.split(r"\n\s*\n", prompt)
            if "source_signature" in para and S.QUEUE_SIGNATURE_FIELD in para]


def _queued_row(finding_id: str, key: str, *, pre_change: bool = False, **over: Any) -> dict:
    """A defender finding row in the shape the judge appends (a family finding that survived).
    `key` is its `alert_rule_key`: after the change the recorded signature verbatim, `unkeyed`
    when there is none (C27); before it, the old `rule-<id>` form (the eval's `rule-5710`). A
    post-change row with a signature also carries it in `S.QUEUE_SIGNATURE_FIELD` (B2, coined); a
    `pre_change` row and an unkeyed one carry no such field — rows queued before the change lack
    it."""
    row = {
        "schema_version": 1, "finding_id": finding_id, "run_id": finding_id.split("/")[0],
        "alert_rule_key": key, "direction": "family", "subject": "defender", "type": "lead-set",
        "subject_anchor": "l-001", "subject_topic": "coverage",
        "finding": "the holding system was never re-queried",
        "contrast_evidence": ["worlds/a/report.md", "worlds/b/report.md"],
        "on_verdict_path": True, "world_label_doubted": False,
        "citations": ["investigation.md#l-001"],
        "source_run_dir": f"episodes/{finding_id.split('/')[0]}/worlds/b",
    }
    if not pre_change and key != S.UNKEYED:
        row[S.QUEUE_SIGNATURE_FIELD] = key
    row.update(over)
    return row


def _author_lesson(name: str, entries: Sequence[str] | None, finding_ids: Iterable[str]) -> str:
    """The lesson file the curator is told to write: the shipped frontmatter shape, entries
    unquoted (C42), no `source_signature` key at all when `entries` is None (C28)."""
    text = S.lesson_text(name, source_signature=entries)
    ids = list(finding_ids)
    return text.replace(f"  - front-door/{name}/0", "\n".join(f"  - {i}" for i in ids) or "  []")


def _prompt_text(paths: Any) -> str:
    """The curator's system prompt as the drain wires it (`AuthorConfig.author_prompt`), read
    from the checkout that ships it."""
    cfg = D.cfg_for(paths, "findings")
    rel = Path(cfg.author_prompt).relative_to(Path(paths.repo_root))
    return (S.REPO_ROOT / rel).read_text(encoding="utf-8")


#: A tenant mapping that takes the signature from `rule.uuid` (a remap away from `rule.id`).
_UUID_MAPPING = {"signature": "rule.uuid", "event_time": "detected_at", "summary": "rule.description"}


def _lesson_alert(sig: str, **rule: Any) -> dict[str, Any]:
    """A generic alert whose `rule.id` is `sig` (the default mapping's signature path)."""
    return S.generic_alert(rule_id=sig, rule={"id": sig, "name": "front door",
                                              "description": "front door lesson lookup", **rule})


# =================================================================================================
# o8 / r6 / r7 / r8 — the gate's lesson demands
# =================================================================================================

def test_o8_lesson_authored_from_a_run_is_found_on_a_later_run(tmp_path):
    """A lesson authored from a run of an alert_id-mapped tenant is listed in orientation's
    lesson hits on a later run of the same recorded signature.

    Observed: the first run of a committed Kibana fixture alert on a tenant whose mapping takes
    the signature from `alert_id` records that value; the lesson the author writes from the run
    (that recorded signature, unquoted) and a decoy keyed on the alert's `rule.id` sit in the
    isolated checkout corpus; a later run of the same alert lists the first in orientation's hits and not
    the decoy. The author's own leg — queue row to lesson file — is p074's and p077's.
    """
    alert = S.fixture_alert("v2-sshd-success-after-failures")
    alert_id, rule_id = alert["alert_id"], alert["rule"]["id"]
    planted = S.plant_tenant(alert_mapping=S.ALERT_ID_MAPPING)
    first = S.run_alert(tmp_path, alert=alert, tenant=planted, run_id="o8-first",
                        orient_shim=S.RecordingShim())
    assert first.rc == 0, (first.rc, first.refusal, first.raised)
    S.plant_lesson("fd-o8-mapped", source_signature=[alert_id])
    S.plant_lesson("fd-o8-rule-id", source_signature=[rule_id])

    later = S.run_alert(tmp_path, alert=alert, tenant=planted, run_id="o8-later",
                        orient_shim=S.RecordingShim())
    hits = _listed(_lessons_section(later))
    assert "fd-o8-mapped" in hits, (
        f"the later run's orientation does not list the lesson keyed on the recorded signature "
        f"{alert_id!r}; it listed {hits}")
    assert "fd-o8-rule-id" not in hits, (
        f"orientation listed the lesson keyed on the vendor field rule.id {rule_id!r}: {hits}")
    assert first.recorded("signature") == alert_id, (
        "the first run's record does not hold the alert_id the lesson was authored with")


def test_curated_checkout_lesson_is_discovered_and_read_by_main(tmp_path):
    """A real curator drain and MAIN use the same corpus, including readable lesson bodies.

    The committed lesson is read in place: no copy into a tenant corpus or lookup fixture.
    Both read_file and cat must reach the body that discovery advertises.
    """
    sig, name, finding = "R-FEEDBACK", "fd-feedback", "feedback/b/0"
    marker = "CURATOR-FEEDBACK-BODY-1222"
    lesson = _author_lesson(name, [sig], [finding]) + "\n" + marker + "\n"
    paths = _drain(tmp_path / "author", _Curator({name: lesson}),
                   extra_rows=[_queued_row(finding, sig)])
    committed = _committed(paths)[name].path
    assert committed.parent == paths.lessons_dir
    assert marker in committed.read_text(encoding="utf-8")
    product = S.prepare_checkout(Path(paths.repo_root) / "defender")
    main = S.MainScript([
        S.call("read_file", path=str(committed)),
        S.call("bash", command=f"cat {shlex.quote(str(committed))}"),
        S.text(S.DONE),
    ])
    d = S.run_alert(tmp_path / "later", alert=_lesson_alert(sig), main=main,
                    defender_dir=product, orient_shim=S.RecordingShim())
    assert d.rc == 0, (d.refusal, d.raised)
    assert _listed(_lessons_section(d)) == [name]
    returned = main.seen[-1].tool_returns
    assert len(returned) == 2, returned
    assert all(marker in text for text in returned), returned


_GOOD_ENTRY = "R-good-1"
#: Entries outside the allow-list a model or a hand could write into `source_signature`: a line
#: break, an ANSI escape, heading text, a key-looking value, YAML-significant punctuation, 129
#: characters. Each is written in its own lesson beside the well-formed entry.
_HOSTILE_ENTRIES = {
    "fd-r6-newline": '"evil\\nsource_signature: [forged]"',
    "fd-r6-ansi": '"\\e[31mred\\e[0m"',
    "fd-r6-heading": '"## Operator override"',
    "fd-r6-key": '"attack_phase: [x]"',
    "fd-r6-punct": '"a]b, c #d"',
    "fd-r6-long": "A" * 129,
}
_DIMENSIONS = ("source_signature", "telemetry_source", "attack_phase")


def test_r6_a_hostile_source_signature_entry_is_inert_in_every_lesson_listing(tmp_path):
    """A lesson file whose source_signature entry is outside the allow-list (written by the
    lesson author model or by hand: a newline, an ANSI escape, '## ' heading text, a key-looking
    'attack_phase: [x]', YAML-significant punctuation, 129 characters) is listed by
    defender-lessons --tags, by the grep hit listing and by the curator's corpus manifest as one
    inert line: no listing gains a second tag line, a forged sibling section or key, or a raw
    control character, and the entry shows as written, neutralised the way every other lesson
    frontmatter line is. Positive control: a well-formed entry beside it is listed once with its
    count.

    Observed: the tags listing and the hit listing as orientation hands them to MAIN (the real
    `defender-lessons` subprocesses), and `build_corpus_manifest` over the isolated checkout corpus.
    """
    lessons = {name: S.lesson_text(name, raw_signature_line=f"source_signature: [{entry}, {_GOOD_ENTRY}]")
               for name, entry in _HOSTILE_ENTRIES.items()}
    lessons["fd-r6-good"] = S.lesson_text("fd-r6-good", source_signature=[_GOOD_ENTRY])
    planted = S.plant_tenant(lessons=lessons)
    manifest = S.sym("learning.author.shared", "build_corpus_manifest")(S.checkout_lessons())
    for ch in ("\x1b", "\r"):
        assert ch not in manifest, f"a raw control character {ch!r} reached the manifest"
    sections = re.split(r"(?m)^## ", manifest)[1:]
    stems = sorted(s.partition("\n")[0].strip() for s in sections)
    assert stems == sorted(lessons), f"the manifest gained or lost a section: {stems}"
    for chunk in sections:
        stem, _, body = chunk.partition("\n")
        doc = _yaml.safe_load(body)
        assert isinstance(doc, dict), f"manifest section {stem!r} is not one mapping: {body!r}"
        assert set(doc) == {"name", "description", "telemetry_source", "attack_phase",
                            "source_signature"}, f"manifest section {stem!r} gained a key: {sorted(doc)}"
        assert _GOOD_ENTRY in [str(v) for v in doc["source_signature"]], (stem, doc)
        entry_lines = _manifest_entries(body)
        assert entry_lines is not None, f"manifest section {stem!r} lists no source_signature"
        assert entry_lines, f"manifest section {stem!r} lists no source_signature entry"
        assert all(ln.startswith("- ") for ln in entry_lines), (
            f"manifest section {stem!r} lists an entry over more than one line: {entry_lines}")
        assert len(entry_lines) == len(doc["source_signature"]), (stem, entry_lines)

    d = S.run_alert(tmp_path, alert=_lesson_alert(_GOOD_ENTRY), tenant=planted,
                    orient_shim=S.RecordingShim())
    section = _lessons_section(d)

    counts = _tag_counts(section)
    assert counts.get(_GOOD_ENTRY) == len(lessons), (
        f"the well-formed entry is not listed once with its count {len(lessons)}: {counts}")
    tags = _tag_frame(section)
    headers = [ln for ln in tags.splitlines() if ln.strip() and not ln.startswith((" ", "\t"))]
    assert sorted(headers) == sorted(f"{dim}:" for dim in _DIMENSIONS), (
        f"the tags listing gained a forged section or key line: {headers}")
    assert len(counts) == len(_HOSTILE_ENTRIES) + 1, (
        f"each hostile entry must list as exactly one line: {counts}")

    hit_lines = [ln for body in S.framed_bodies(section) if _listed(body)
                 for ln in body.splitlines() if ln.strip()]
    assert sorted(_listed("\n".join(hit_lines))) == sorted(lessons), (
        f"the hit listing does not list every lesson carrying {_GOOD_ENTRY!r}: {hit_lines}")
    assert all(_HIT_LINE.search(ln) for ln in hit_lines), (
        f"the hit listing gained a line that is not a lesson row: {hit_lines}")
    for ch in ("\x1b", "\r"):
        assert ch not in section, f"a raw control character {ch!r} reached MAIN's lessons section"


#: Unquoted entries YAML 1.1 retypes (PA-21): 000123 -> 83, yes -> True, a date, 0x1F -> 31,
#: null -> None. Every one is inside C43's allow-list.
_RETYPED = ["000123", "yes", "2026-05-01", "0x1F", "null"]


def _frontier() -> Any:
    """An investigation frontier with one open `class` cell on a `process` vertex — what the
    `frontier_nodes` selector of `_SELECTOR_LINES` matches."""
    open_slot = S.sym("skills.invlang.frontier", "OpenSlot")(
        vertex_id="v-001", type="process", class_tuple="??", slot="class", value="??")
    return S.sym("skills.invlang.frontier", "Frontier")(slots=(open_slot,), contracts=())


def _loaded_row(lesson: str) -> str:
    return json.dumps({"lesson_name": lesson, "ts": "2026-10-02T00:00:00Z", "kind": "read",
                       "role": "main"}) + "\n"


def test_r7_the_shared_lesson_readers_agree_on_an_unquoted_signature_entry(tmp_path, capsys):
    """A lesson whose source_signature is written unquoted with entries YAML retypes (000123, yes,
    2026-05-01, 0x1F, null) is yielded by iter_lessons (not skipped as malformed), scored by
    match_lessons exactly as the same lesson written with quoted entries is, with the entry in the
    hit's frontmatter as the text written, and indexed by the lesson tracer with its case count;
    every one of them agrees with what defender-lessons --tags lists for it. Positive control: the
    quoted twin gives identical scores and counts.

    Observed: each reader's own entry point over two corpora holding the unquoted lesson and its
    quoted twin; the tags listing as orientation hands it to MAIN.
    """
    name = "fd-r7-retyped"
    twins = {
        "unquoted": S.lesson_text(name, source_signature=_RETYPED, extra_lines=_SELECTOR_LINES),
        "quoted": S.lesson_text(name, source_signature=_RETYPED, quoted=True,
                                extra_lines=_SELECTOR_LINES),
    }
    corpora: dict[str, Path] = {}
    for spelling, text in twins.items():
        corpus = tmp_path / spelling / "lessons"
        corpus.mkdir(parents=True)
        (corpus / f"{name}.md").write_text(text, encoding="utf-8")
        corpora[spelling] = corpus

    match_lessons = S.sym("runtime.lessons_engine.lessons_frontier", "match_lessons")
    hits = {spelling: match_lessons(_frontier(), corpus) for spelling, corpus in corpora.items()}
    for spelling, found in hits.items():
        assert [h.name for h in found] == [name], f"match_lessons over the {spelling} lesson: {found}"
        assert list(found[0].frontmatter["source_signature"]) == _RETYPED, (
            f"the {spelling} hit's source_signature is not the text written: "
            f"{found[0].frontmatter['source_signature']!r}")
    assert hits["unquoted"][0].score == hits["quoted"][0].score
    assert hits["unquoted"][0].matched == hits["quoted"][0].matched

    iter_lessons = S.sym("_corpus", "iter_lessons")
    for spelling, corpus in corpora.items():
        assert [lesson.path.stem for lesson in iter_lessons(corpus)] == [name], (
            f"iter_lessons skipped the {spelling} lesson")

    runs = S.plant_tenant().accept().runs
    runs.mkdir(parents=True, exist_ok=True)
    _tenant.ensure_runs_base_record(runs, "acme")
    alert = S.generic_alert(rule_id="R-R7-TRACE")
    S.plant_run(runs, "r7-traced", alert=alert, record=False,
                files={"lessons_loaded.jsonl": _loaded_row(name)})
    recorded = _with_record(runs, "r7-traced", alert=alert, facts={"signature": "R-R7-TRACE"})
    main = S.sym("learning.ops.trace_lesson", "main")
    traced: dict[str, list[str]] = {}
    for spelling, corpus in corpora.items():
        capsys.readouterr()
        assert main(["--all", "--lessons-dir", str(corpus), "--tenant", "acme"]) == 0
        traced[spelling] = [ln for ln in capsys.readouterr().out.splitlines()
                            if ln.startswith(f"{name}\t")]
    assert len(traced["unquoted"]) == 1, f"the tracer did not index the unquoted lesson once: {traced}"
    assert traced["unquoted"][0].split("\t")[2:] == traced["quoted"][0].split("\t")[2:] == ["1", "1"], (
        f"the tracer's case counts differ between the twins or miss the case: {traced}")

    planted = S.plant_tenant(lessons={name: twins["unquoted"]})
    d = S.run_alert(tmp_path, alert=_lesson_alert(_RETYPED[0]), tenant=planted,
                    orient_shim=S.RecordingShim())
    section = _lessons_section(d)
    assert _tag_counts(section) == dict.fromkeys(_RETYPED, 1), (
        f"defender-lessons --tags does not list the entries as written: {_tag_counts(section)}")
    assert _listed(section) == [name], f"orientation's lookup of {_RETYPED[0]!r}: {_listed(section)}"
    assert recorded, "the traced run's record could not be planted (S.COINED accessors)"


def test_r8_each_shipped_lesson_is_found_by_exact_lookup_of_its_declared_signature(tmp_path):
    """The 16 lessons in defender/lessons, written before the change (source_signature
    v2-cross-tier-ssh-pivot, v2-falco-suspicious-network-tool, v2-sshd-success-after-failures; a
    lesson may list several), are each found by the exact, case-sensitive lookup of each
    signature they declare -- orientation's lookup and MAIN's in-box lookup alike -- for a
    committed alert whose rule.id is that signature under the fixture tenant's rule.id mapping;
    the lookup returns the lessons declaring it and none of the others, and a near miss (case
    change, prefix, suffix) finds none. Positive control: the result is non-empty for every
    declared signature.

    Observed: the shipped corpus (resolved where production keeps it) in the isolated checkout corpus; one
    run per signature and per near miss, orientation's hits and MAIN's taught lookup each read.
    """
    planted = S.plant_tenant(alert_mapping=S.DEFAULT_MAPPING)
    shipped = _plant_shipped(planted)
    declared = sorted({e for entries in shipped.values() for e in entries})
    assert declared, "the shipped lessons declare no signature"
    by_rule = {S.fixture_alert(slug)["rule"]["id"]: slug for slug in S.FIXTURE_SLUGS}

    def lookup(sig: str, run_id: str) -> tuple[list[str], list[str]]:
        slug = by_rule.get(sig, S.FIXTURE_SLUGS[0])
        alert = S.kibana_alert(slug, rule={**S.fixture_alert(slug)["rule"], "id": sig})
        main = _TaughtLookups([sig])
        d = S.run_alert(tmp_path, alert=alert, tenant=planted, run_id=run_id, main=main,
                        orient_shim=S.RecordingShim())
        return _listed(_lessons_section(d)), _listed(main.results()[sig])

    near = {
        "case": declared[0].upper(),
        "prefix": declared[1 % len(declared)].rsplit("-", 1)[0],
        "suffix": declared[2 % len(declared)] + "-x",
    }
    for kind, sig in near.items():
        assert sig not in declared
        oriented, in_box = lookup(sig, f"r8-near-{kind}")
        assert oriented == [], f"orientation's lookup of the {kind} near miss {sig!r} found {oriented}"
        assert in_box == [], f"MAIN's lookup of the {kind} near miss {sig!r} found {in_box}"
    for i, sig in enumerate(declared):
        want = _declaring(shipped, sig)
        oriented, in_box = lookup(sig, f"r8-exact-{i}")
        assert want, sig
        assert set(oriented) == want, f"orientation's lookup of {sig!r}: {sorted(oriented)} != {sorted(want)}"
        assert set(in_box) == want, f"MAIN's lookup of {sig!r}: {sorted(in_box)} != {sorted(want)}"


def _held_out_fixture(fixtures: Path, slug: str, *, disposition: str = "benign") -> None:
    """One labelled held-out fixture (`ground_truth.yaml`, `alert.json`), the alert written
    where the fixture reader looks (`RunPaths(<fixture>).alert`) and at the folder's own
    `alert.json`."""
    folder = fixtures / slug
    folder.mkdir(parents=True)
    (folder / "ground_truth.yaml").write_text(
        f"held_out: true\ndisposition: {disposition}\n", encoding="utf-8")
    raw = S.alert_bytes(S.generic_alert(rule_id="R-HELD"))
    for target in {folder / "alert.json", S.alert_file(folder)}:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)


def _report(disposition: str) -> str:
    return f"---\ndisposition: {disposition}\n---\n\nbody\n"


def _age(runs: Path, order: Sequence[str]) -> None:
    """Give the folders strictly increasing mtimes in `order` (the last is the newest)."""
    for i, name in enumerate(order):
        stamp = 1_800_000_000 + 60 * i
        os.utime(runs / name, (stamp, stamp))


def test_r7_the_eval_index_and_the_lesson_tracer_skip_a_recordless_run_folder_by_name(tmp_path, capsys):
    """Over a runs base holding a run with a readable record and folders with none (a pre-change
    run, a crashed setup), the held-out eval index and the lesson tracer each skip a recordless
    folder by name and count it, as the corpus and the sibling union do, and still index and
    trace the recorded run; neither raises on a recordless folder, and neither picks it as the
    newest run of a slug. Positive control: with its record present the folder is indexed and
    traced.

    Observed: `evals/held_out.main` and `learning/ops/trace_lesson.main --all` over one runs
    base, first with only recordless folders (the newest of them a pre-change run whose report
    says malicious), then with records planted.
    """
    slug, lesson = "fd-slug", "fd-traced"
    fixtures, runs, corpus = tmp_path / "fixtures", S.plant_tenant().accept().runs, tmp_path / "lessons"
    runs.mkdir(parents=True, exist_ok=True)
    _tenant.ensure_runs_base_record(runs, "acme")
    _held_out_fixture(fixtures, slug)
    corpus.mkdir()
    (corpus / f"{lesson}.md").write_text(S.lesson_text(lesson), encoding="utf-8")
    alert = S.generic_alert(rule_id="R-HELD")
    pre, crashed, recorded_run = f"{slug}-pre", f"{slug}-crashed", slug
    S.plant_run(runs, pre, alert=alert, record=False,
                files={"report.md": _report("malicious"), "lessons_loaded.jsonl": _loaded_row(lesson)})
    S.plant_run(runs, crashed, alert=alert, record=False)
    _age(runs, [pre, crashed])

    held_out = S.sym("evals.held_out", "main")
    trace = S.sym("learning.ops.trace_lesson", "main")

    def both() -> tuple[str, str]:
        capsys.readouterr()
        held_out([str(runs), "--fixtures-dir", str(fixtures)])
        scored = capsys.readouterr()
        assert trace(["--all", "--lessons-dir", str(corpus), "--tenant", "acme"]) == 0
        traced = capsys.readouterr()
        return scored.out + scored.err, traced.out + traced.err

    scored, traced = both()
    assert "predicted=" not in scored, (
        f"the held-out index scored {slug!r} off a recordless folder:\n{scored}")
    row = [ln for ln in traced.splitlines() if ln.startswith(f"{lesson}\t")]
    assert len(row) == 1, f"the lesson tracer did not index {lesson!r} once:\n{traced}"
    assert row[0].split("\t")[2] == "0", (
        f"the lesson tracer counted a recordless folder's case:\n{traced}")
    for out, walker in ((scored, "held-out index"), (traced, "lesson tracer")):
        for name in (pre, crashed):
            assert name in out, f"the {walker} did not name the recordless folder {name!r}:\n{out}"
        assert any(re.search(r"\b2\b", ln) and "record" in ln.lower() for ln in out.splitlines()), (
            f"the {walker} does not count the two recordless folders:\n{out}")

    S.plant_run(runs, recorded_run, alert=alert, record=False,
                files={"report.md": _report("benign"), "lessons_loaded.jsonl": _loaded_row(lesson)})
    planted = [_with_record(runs, name, alert=alert, facts={"signature": "R-HELD"})
               for name in (recorded_run, pre)]
    _age(runs, [recorded_run, pre, crashed])
    scored, traced = both()
    assert "predicted='malicious'" in scored, (
        f"with its record present the newest run {pre!r} is not the one scored:\n{scored}")
    row = [ln for ln in traced.splitlines() if ln.startswith(f"{lesson}\t")]
    assert len(row) == 1, f"the lesson tracer did not index {lesson!r} once:\n{traced}"
    assert row[0].split("\t")[2] == "2", f"with records present both runs are traced:\n{traced}"
    assert crashed in scored, "the held-out index does not name the still-recordless folder"
    assert crashed in traced, "the lesson tracer does not name the still-recordless folder"
    assert all(planted), "the records could not be planted (S.COINED accessors)"


# =================================================================================================
# The invlang corpus and the vocabulary lookup
# =================================================================================================

def _vocab_cli(capsys: Any, root: Path, sig: str) -> tuple[int, str]:
    """`defender-invlang <root> hypothesis-vocabulary --signature <sig>` — the CLI's own main —
    and everything it printed."""
    capsys.readouterr()
    rc = S.sym("skills.invlang.cli", "main")([str(root), "hypothesis-vocabulary", "--signature", sig])
    out = capsys.readouterr()
    return rc, out.out + out.err


def _skipped_runs(report: Any, base: Path) -> dict[str, str]:
    """`load_corpus`'s skipped entries as run folder -> reason (the entry may name the folder
    or a file inside it)."""
    out: dict[str, str] = {}
    for path, reason in report.skipped:
        p = Path(path)
        try:
            run = p.relative_to(base).parts[0]
        except (ValueError, IndexError):
            run = p.name
        out[run] = str(reason)
    return out


def _probes(text: str) -> set[str]:
    """The `?<tag>-probe` hypotheses a vocabulary listing counted (one per past run, `_investigation`)."""
    return set(re.findall(r"\?([a-z0-9]+(?:-[a-z0-9]+)*)-probe", text)) - {"scanner-or-noise"}


def test_p063_main_calls_the_corpus_in_box_with_the_mapped_sig(tmp_path, capsys, monkeypatch):
    """The in-box corpus filters on the signature it is handed, exactly, never on rule.id. An
    in-box lookup that cannot see past runs says so and never reads as an empty corpus.

    Observed: (1) the corpus CLI over a runs base holding only the current run, run as it runs in
    the sandbox (`DEFENDER_BOX` set — PR-24's observed in-box view, where past runs are not
    mounted) against the same CLI on the host, where that runs base truly holds no past run;
    (2) MAIN's own `defender-invlang hypothesis-vocabulary --signature` call, handed the mapped
    signature, over past runs whose records and `rule.id`s disagree.
    """
    sig = "M-777"
    only_current = tmp_path / "only-current"
    current = S.generic_alert(rule_id="R-1", rule={"id": "R-1", "uuid": sig})
    S.plant_run(only_current, "current-run", alert=current, record=False,
                files={"investigation.md": "# investigation in progress\n"})
    current_recorded = _with_record(only_current, "current-run", alert=current,
                                    facts={"signature": sig})
    monkeypatch.delenv("DEFENDER_BOX", raising=False)
    _rc, on_host = _vocab_cli(capsys, only_current, sig)
    monkeypatch.setenv("DEFENDER_BOX", "1")
    _rc, in_box = _vocab_cli(capsys, only_current, sig)
    monkeypatch.delenv("DEFENDER_BOX")
    assert in_box.strip(), "the in-box corpus lookup printed nothing"
    assert in_box != on_host, (
        "an in-box corpus lookup that cannot see past runs reads exactly as a corpus with no "
        "past run:\n" + in_box)

    planted = S.plant_tenant(alert_mapping=_UUID_MAPPING)
    past: dict[str, dict[str, Any]] = {
        "p1": dict(signature=sig, rule_id="R-1"),
        "p2": dict(signature="M-778", rule_id=sig),
        "p3": dict(signature=sig.lower(), rule_id="R-3"),
        "p4": dict(signature=sig + "0", rule_id="R-4"),
    }
    recorded = [_past_run(planted.runs, f"past-{tag}", tag=tag, **spec) for tag, spec in past.items()]
    main = S.MainScript([S.call("bash", command=f"defender-invlang hypothesis-vocabulary --signature {sig}"),
                         S.text(S.DONE)])
    d = S.run_alert(tmp_path, alert=current, tenant=planted, main=main)
    back = [t for kind, t in d.main.seen[1].parts if kind in ("tool-return", "retry-prompt")]
    assert back, "MAIN's corpus call came back with nothing"
    assert _probes(back[-1]) == {"p1"}, (
        f"MAIN's in-box corpus lookup of {sig!r} counted {sorted(_probes(back[-1]))}, not exactly "
        f"the run recorded under it:\n{back[-1]}")
    assert all(recorded), "records could not be planted (S.COINED accessors)"
    assert current_recorded, "the current run's record could not be planted (S.COINED accessors)"


def test_p065_corpus_subprocess_cannot_obtain_the_mapping(tmp_path):
    """Orientation tells "vocabulary unavailable" apart from "no past runs". The corpus reads
    recorded facts, not the mapping.

    Observed: orientation's vocabulary section when the corpus lookup failed (the shim runner's
    own "failed" answer, PR-05) against the same section over a runs base with no past run; then
    a past run whose record holds the signature while its `rule.id` and the field the tenant now
    maps say otherwise.
    """
    sig = "R-P065"
    planted = S.plant_tenant("acme-a")
    failed = S.run_alert(tmp_path, alert=_lesson_alert(sig), tenant=planted, run_id="p065-failed",
                         orient_shim=S.RecordingShim(fail=("defender-invlang",)))
    empty = S.run_alert(tmp_path, alert=_lesson_alert(sig), tenant=planted, run_id="p065-empty",
                        orient_shim=S.RecordingShim())
    unavailable = _vocab_section(failed)
    assert unavailable is not None, (
        "a vocabulary lookup that could not run left no vocabulary section in MAIN's opening message")
    assert _same_text(unavailable, failed) != _same_text(_vocab_section(empty), empty), (
        "the unavailable vocabulary reads exactly as a corpus with no past runs")

    mapped = S.plant_tenant("acme-c", alert_mapping=_UUID_MAPPING)
    recorded = _past_run(mapped.runs, "past-pc", tag="pc", signature="SIG-P065",
                         alert=S.generic_alert(rule_id="R-9", rule={"id": "R-9", "uuid": "U-9",
                                                                     "description": "past"}))
    d = S.run_alert(tmp_path, alert=S.generic_alert(rule_id="R-other", rule={"id": "R-other", "uuid": "SIG-P065",
                                                                              "description": "now"}),
                    tenant=mapped, run_id="p065-recorded", orient_shim=S.RecordingShim())
    section = _vocab_section(d) or ""
    assert _probes(section) == {"pc"}, (
        f"the corpus did not attribute the past run by its recorded signature:\n{section}")
    assert recorded, "the past run's record could not be planted (S.COINED accessors)"


def test_p066_corpus_subprocess_misses_orientations_time_allow(tmp_path):
    """A lookup that did not finish is named in the section it would have filled. The run
    continues.

    Observed: both orientation lookups answering the shim runner's "did not finish" (`None`, the
    contract's spelling of a timeout, PR-05) against the same run with both lookups finishing
    over an empty corpus and no past run.
    """
    sig = "R-P066"
    planted = S.plant_tenant()
    cut = S.run_alert(tmp_path, alert=_lesson_alert(sig), tenant=planted, run_id="p066-cut",
                      orient_shim=S.RecordingShim(fail=("defender-lessons", "defender-invlang")))
    whole = S.run_alert(tmp_path, alert=_lesson_alert(sig), tenant=planted, run_id="p066-whole",
                        orient_shim=S.RecordingShim())
    assert _naming(_lessons_section(cut), sig, cut) != _naming(_lessons_section(whole), sig, whole), (
        "a lessons lookup that did not finish reads exactly as one that matched nothing:\n"
        + _lessons_section(cut))
    named = _vocab_section(cut)
    assert named is not None, "a vocabulary lookup that did not finish left no section"
    assert _same_text(named, cut) != _same_text(_vocab_section(whole), whole), (
        "a vocabulary lookup that did not finish reads exactly as one that found nothing")
    assert cut.rc == 0, f"the run did not finish past the cut lookups (rc={cut.rc})"
    assert cut.main.requests == whole.main.requests, (
        f"MAIN was asked {cut.main.requests} times, not as often as in the whole run "
        f"({whole.main.requests})")


def test_p107_vendor_changes_the_alert_shape_mid_life(tmp_path):
    """An alert lacking the path gives no signature. The corpus leaves runs whose record holds
    none out of the signature filter, never attributing them via rule.id.

    Observed: a tenant mapping the signature from `rule.uuid`; one past run whose alert lacked
    that path (record without a signature, `rule.id` equal to the looked-up value) and one
    recorded under it; orientation's vocabulary lookup for that value.
    """
    sig = "SIG-P107"
    planted = S.plant_tenant(alert_mapping=_UUID_MAPPING)
    recorded = [
        _past_run(planted.runs, "past-p1", tag="p1", signature=None,
                  alert=S.generic_alert(rule_id=sig)),
        _past_run(planted.runs, "past-p2", tag="p2", signature=sig,
                  alert=S.generic_alert(rule_id="R-x", rule={"id": "R-x", "uuid": sig})),
    ]
    d = S.run_alert(tmp_path, alert=S.generic_alert(rule_id="R-cur", rule={"id": "R-cur", "uuid": sig}),
                    tenant=planted, orient_shim=S.RecordingShim())
    section = _vocab_section(d) or ""
    assert _probes(section) == {"p2"}, (
        f"the corpus lookup of {sig!r} did not count exactly the run recorded under it:\n{section}")
    assert all(recorded), "the past runs' records could not be planted (S.COINED accessors)"


def test_p108_past_run_alert_missing_or_unparseable(tmp_path):
    """A past run with no readable record is skipped by name and counted in what the index
    returns, and the rest are served.

    Observed: `load_corpus` over a runs base holding a recordless run, a recordless run with its
    alert gone, a recordless run with an unparseable alert, and a recorded run whose alert is
    gone.
    """
    base = tmp_path / "runs"
    for name in ("p108-no-record", "p108-no-alert", "p108-garbage"):
        _past_run(base, name, tag=name.replace("p108-", ""), recorded=False)
    S.alert_file(base / "p108-no-alert").unlink()
    S.alert_file(base / "p108-garbage").write_bytes(b"not json at all {")
    recorded = _past_run(base, "p108-served", tag="served", signature="SIG-P108")
    S.alert_file(base / "p108-served").unlink()

    companions, report = S.sym("skills.invlang.corpus", "load_corpus")(base)
    skipped = set(_skipped_runs(report, base))
    assert skipped == {"p108-no-record", "p108-no-alert", "p108-garbage"}, (
        f"the index did not skip exactly the recordless runs by name: skipped {sorted(skipped)}, "
        f"loaded {[c.case_id for c in companions]}")
    assert [c.case_id for c in companions] == ["p108-served"]
    assert companions[0].signature_id == "SIG-P108"
    assert recorded, "the served run's record could not be planted (S.COINED accessors)"


def test_p115_past_run_rewrote_its_alert_to_change_the_corpus(tmp_path, capsys):
    """The corpus attributes each past run by its recorded signature.

    Observed: a past run whose box rewrote its alert (PR-17: the run folder was a read-write
    bind) to another rule id after the record was written; `load_corpus` and the corpus CLI's
    filter for each value.
    """
    base = tmp_path / "runs"
    original = S.generic_alert(rule_id="TRUE-P115")
    forged = S.generic_alert(rule_id="FORGED-P115")
    recorded = _past_run(base, "p115-rewritten", tag="rewritten", alert=forged,
                         signature="TRUE-P115", digest=S.sha256_hex(S.alert_bytes(original)))
    companions, _report = S.sym("skills.invlang.corpus", "load_corpus")(base)
    assert [(c.case_id, c.signature_id) for c in companions] == [("p115-rewritten", "TRUE-P115")], (
        f"the corpus attributed the past run by its rewritten alert: "
        f"{[(c.case_id, c.signature_id) for c in companions]}")
    _rc, true_listing = _vocab_cli(capsys, base, "TRUE-P115")
    _rc, forged_listing = _vocab_cli(capsys, base, "FORGED-P115")
    assert _probes(true_listing) == {"rewritten"}, true_listing
    assert _probes(forged_listing) == set(), forged_listing
    assert recorded, "the record could not be planted (S.COINED accessors)"


def _raw_record(run_dir: Path, data: bytes) -> bool:
    """Write `data` verbatim where the run's record goes (an unreadable record, p143). False
    when the coined record accessor is absent (base)."""
    try:
        target = S.record_file(run_dir)
    except AssertionError:
        return False
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data)
    return True


def test_p143_record_unreadable_partial_or_of_another_shape(tmp_path):
    """A run whose record cannot be read is skipped by name and counted. It is listed with its
    own reason ("record unreadable"), apart from runs with no record.

    Observed: past runs of one alert, each finished with a report: one with no record; records
    that are not JSON, cut short, missing the digest, or a JSON list; and one whole record. Read
    by `load_corpus`; the judge excludes every prior run under J3 when grading an
    episode carrying that alert's copy and record.
    """
    sig = "R-P143"
    raw = S.alert_bytes(S.generic_alert(rule_id=sig))
    runs = tmp_path / "runs-base"
    whole = json.dumps(S.record_doc(raw, signature=sig)).encode("utf-8")
    unreadable = {
        "p143-not-json": b"\xff\xfe not json {",
        "p143-cut-short": whole[: len(whole) // 2],
        "p143-no-digest": json.dumps({"signature": sig}).encode("utf-8"),
        "p143-a-list": json.dumps([sig]).encode("utf-8"),
    }
    none, served = "p143-no-record", "p143-served"
    for name in (*unreadable, none, served):
        S.plant_run(runs, name, alert=raw, record=False,
                    files={"investigation.md": _investigation(name.removeprefix("p143-")),
                           "report.md": _report("benign")})
    planted = [_raw_record(runs / name, data) for name, data in unreadable.items()]
    planted.append(_with_record(runs, served, alert=raw, facts={"signature": sig}))

    companions, report = S.sym("skills.invlang.corpus", "load_corpus")(runs)
    skipped = _skipped_runs(report, runs)
    assert set(skipped) == {*unreadable, none}, (
        f"the index did not skip each run without a readable record by name: {skipped}")
    assert len(report.skipped) == len(unreadable) + 1, f"a skipped run was counted twice: {skipped}"
    assert [c.case_id for c in companions] == [served]
    for name in unreadable:
        assert skipped[name].replace(name, "<run>") != skipped[none].replace(none, "<run>"), (
            f"{name!r} (record unreadable) is listed with the same reason as a run with no "
            f"record: {skipped[name]!r}")

    ep = J.accepted_episode(tmp_path / "judged")
    try:
        S.plant_episode_copy(ep, alert=raw, facts={"signature": sig})
        copied = True
    except AssertionError:
        copied = False
    judge = J.scripted_judge()
    J.grade(ep, runs_base=runs, judge=judge)
    lines = [ln for prompt in judge.prompts for ln in prompt.splitlines()]

    def naming(name: str) -> list[str]:
        return sorted({ln.replace(name, "<run>") for ln in lines if name in ln})

    # J3 retired the sibling union: neither served priors nor skip notes reach the judge.
    for name in (*unreadable, none, served):
        assert not naming(name), f"a prior run entered the judge prompt: {name!r}"
    assert all(planted), "the records could not be planted (S.COINED accessors)"
    assert copied, "the episode's record copy could not be planted (S.COINED accessors)"


def test_p187_lesson_authored_with_no_source_signature_meets_c(tmp_path):
    """A lesson for a run with no signature has no source_signature key at all (not null, not
    []).
      - The tags listing, the manifest, the frontend and the lint all load it.
      - The curator's "populate every dimension list" instruction no longer forces a value.

    Observed: a lesson written with no source_signature key beside a signed one; the tags
    listing orientation hands MAIN (`defender-lessons --tags`), the curator's corpus manifest
    (`build_corpus_manifest`), the lessons posture view (`serialize.build_view`); and the
    curator's instructions as the drain wires them.
    """
    sig, unsigned, signed = "R-P187", "fd-p187-unsigned", "fd-p187-signed"
    texts = {unsigned: S.lesson_text(unsigned, source_signature=None),
             signed: S.lesson_text(signed, source_signature=[sig])}
    planted = S.plant_tenant(lessons=texts)

    manifest = S.sym("learning.author.shared", "build_corpus_manifest")(S.checkout_lessons())
    sections = {chunk.partition("\n")[0].strip(): chunk.partition("\n")[2]
                for chunk in re.split(r"(?m)^## ", manifest)[1:]}
    assert set(sections) == {unsigned, signed}, f"the manifest lost a lesson: {sorted(sections)}"
    doc = _yaml.safe_load(sections[unsigned])
    assert isinstance(doc, dict), f"the manifest's unsigned section is not a mapping: {doc!r}"
    assert doc.get("telemetry_source") == ["auth-log"], (
        f"the manifest does not load the unsigned lesson: {sections[unsigned]!r}")
    assert "source_signature" not in doc, (
        f"the manifest shows the unsigned lesson a source_signature: {sections[unsigned]!r}")

    defender_dir = tmp_path / "posture" / "defender"
    corpus = defender_dir / "lessons"
    corpus.mkdir(parents=True)
    for name, text in texts.items():
        (corpus / f"{name}.md").write_text(text, encoding="utf-8")
    view = S.sym("learning.frontend.serialize", "build_view")(defender_dir)
    shown = {rec["title"]: rec for group in view["groups"].values() for rec in group["lessons"]}
    assert unsigned in shown, f"the posture view lost the unsigned lesson: {sorted(shown)}"
    assert shown[unsigned]["status"] != "malformed", (
        f"the posture view does not load the unsigned lesson: {shown[unsigned]}")
    assert shown[unsigned]["metadata"].get("telemetry_source") == ["auth-log"]
    assert "source_signature" not in shown[unsigned]["metadata"], shown[unsigned]["metadata"]

    paths = D.make_paths(tmp_path / "drain", state_dir=tmp_path / "drain-state")
    prompt = _prompt_text(paths)
    populate = [para for para in re.split(r"\n\s*\n", prompt)
                if re.search(r"\bpopulate", para, re.I) and re.search(r"dimension", para, re.I)]
    assert populate, "the curator's instructions no longer say how the dimension lists are filled"
    for para in populate:
        assert S.UNKEYED in para or re.search(
            r"no (recorded )?signature|without a signature|no source_signature", para, re.I), (
            "the curator's dimension-list instruction forces a source_signature on a lesson for a "
            f"run with none:\n{para}")

    d = S.run_alert(tmp_path, alert=_lesson_alert(sig), tenant=planted, orient_shim=S.RecordingShim())
    section = _lessons_section(d)
    assert _tag_counts(section, "telemetry_source") == {"auth-log": 2}, (
        f"the tags listing does not count the unsigned lesson: {_tag_frame(section)}")
    assert _tag_counts(section) == {sig: 1}, _tag_frame(section)


def test_p064_in_box_lessons_grep_with_a_mapped_signature(tmp_path):
    """The in-box lessons lookup returns exactly the lessons with an entry equal to the
    signature.

    Observed: MAIN's own lessons lookup in its sandbox (the `defender-lessons` command its
    instructions teach, run through its `bash` tool) for the signature a `rule.uuid`-mapped
    tenant records, a prefix of a shipped signature, over the shipped corpus plus lessons keyed
    on that value, on a longer value, and on its case variant; the alert's `rule.id` is a
    shipped signature.
    """
    shipped_sig, sig = "v2-sshd-success-after-failures", "v2-sshd"
    planted = S.plant_tenant(alert_mapping=_UUID_MAPPING)
    shipped = _plant_shipped(planted)
    assert _declaring(shipped, shipped_sig), f"no shipped lesson declares {shipped_sig!r}"
    for name, entries in {"fd-p064-mapped": [sig], "fd-p064-second": ["R-other", sig],
                          "fd-p064-longer": [sig + "-x"], "fd-p064-case": [sig.upper()]}.items():
        S.plant_lesson(name, source_signature=entries)
    alert = _lesson_alert(shipped_sig, uuid=sig)
    main = _TaughtLookups([sig])
    S.run_alert(tmp_path, alert=alert, tenant=planted, main=main)
    found = sorted(_listed(main.results()[sig]))
    assert found == ["fd-p064-mapped", "fd-p064-second"], (
        f"MAIN's in-box lookup of the mapped signature {sig!r} returned {found}")


def test_p183_main_runs_its_taught_lessons_lookup_in_the_box(tmp_path):
    """The lessons lookup taught to MAIN is exact, whole-value and case-sensitive.

    Observed: the `defender-lessons` command MAIN's received instructions teach, run by MAIN
    through its `bash` tool in the sandbox: for a case variant of a shipped signature, and for
    signatures whose lessons sit beside entries a pattern or a fold would also take (a case
    variant, a longer value, a value the signature's `.` matches as a pattern, a prefix).
    """
    planted = S.plant_tenant()
    shipped = _plant_shipped(planted)
    declared = sorted({e for entries in shipped.values() for e in entries})
    for name, entries in {"fd-p183-exact": ["R-183"], "fd-p183-second": ["Z-1", "R-183"],
                          "fd-p183-case": ["r-183"], "fd-p183-longer": ["R-1830"],
                          "fd-p183-dot": ["R.183"], "fd-p183-dot-as-pattern": ["RX183"]}.items():
        S.plant_lesson(name, source_signature=entries)
    case_miss = declared[0].upper()
    want = {case_miss: [], "R-183": ["fd-p183-exact", "fd-p183-second"], "R.183": ["fd-p183-dot"],
            "R-18": []}
    main = _TaughtLookups(list(want))
    S.run_alert(tmp_path, alert=_lesson_alert("R-183"), tenant=planted, main=main)
    found = {sig: sorted(_listed(out)) for sig, out in main.results().items()}
    for sig, lessons in want.items():
        assert found[sig] == lessons, (
            f"MAIN's taught lookup {main.taught!r} of {sig!r} returned {found[sig]}, not {lessons}")


def test_p080_short_signature_substring_matches_other_lessons(tmp_path):
    """Orientation lists exactly the lessons with an entry equal to the signature.
      - A one-character signature matches only an entry of that character.
      - A blank or whitespace value is no signature.
      - The corpus filter agrees.

    Observed: the shipped corpus plus lessons keyed on `R`, on a longer value, on `r`, and on
    `R` as a second entry; past runs recorded under each; orientation's lessons and vocabulary
    sections for a run whose signature is `R` and for one whose mapped value is a single space.
    """
    planted = S.plant_tenant()
    _plant_shipped(planted)
    for name, entries in {"fd-p080-r": ["R"], "fd-p080-second": ["Q", "R"],
                          "fd-p080-longer": ["R-1001"], "fd-p080-lower": ["r"]}.items():
        S.plant_lesson(name, source_signature=entries)
    recorded = [_past_run(planted.runs, f"past-{tag}", tag=tag, rule_id=sig, signature=sig)
                for tag, sig in (("pr", "R"), ("plonger", "R-1001"), ("plower", "r"))]

    one = S.run_alert(tmp_path, alert=_lesson_alert("R"), tenant=planted, run_id="p080-one",
                      orient_shim=S.RecordingShim())
    hits = sorted(_listed(_lessons_section(one)))
    assert hits == ["fd-p080-r", "fd-p080-second"], f"orientation's lookup of 'R' listed {hits}"
    assert _probes(_vocab_section(one) or "") == {"pr"}, _vocab_section(one)

    blank = S.run_alert(tmp_path, alert=_lesson_alert(" "), tenant=planted, run_id="p080-blank",
                        orient_shim=S.RecordingShim())
    assert _listed(_lessons_section(blank)) == [], (
        f"a blank value was looked up as a signature: {_listed(_lessons_section(blank))}")
    assert _probes(_vocab_section(blank) or "") == set(), _vocab_section(blank)
    assert all(recorded), "the past runs' records could not be planted (S.COINED accessors)"


def test_checkout_corpus_stays_authoritative_until_atomic_tenant_migration(tmp_path):
    """Until #1108 P4, discovery uses the curator's checkout corpus for every tenant.

    A tenant-local lesson folder must not prematurely replace that corpus. Tenant isolation
    is deferred to the atomic writer, reader, mount and permissions migration in P4.
    """
    sig = "R-P081"
    tenant = S.plant_tenant("acme-b")
    private = S.sym("_knowledge", "KnowledgePaths")(tenant.agent, "agent").lessons_dir
    private.mkdir(parents=True)
    (private / "fd-p081-private.md").write_text(
        S.lesson_text("fd-p081-private", source_signature=[sig]), encoding="utf-8")
    S.plant_lesson("fd-p081-checkout", source_signature=[sig])
    main = _TaughtLookups([sig])
    d = S.run_alert(tmp_path, alert=_lesson_alert(sig), tenant=tenant, main=main,
                    orient_shim=S.RecordingShim())
    assert _listed(_lessons_section(d)) == ["fd-p081-checkout"]
    assert _listed(main.results()[sig]) == ["fd-p081-checkout"]


def test_p084_lessons_authored_before_the_change_under_a_remap(tmp_path):
    """Lessons written under the old value are not found after a remap, and the miss reads as
    "no lesson applies".

    Observed: a tenant that remapped its signature from `rule.id` to `rule.uuid`, holding a
    lesson written under the alert's old value; orientation's lessons section for the alert;
    then, as the positive control, the same alert once a lesson keyed on the new value is in
    the corpus.
    """
    old, new = "R-OLD84", "U-NEW84"
    planted = S.plant_tenant(alert_mapping=_UUID_MAPPING)
    S.plant_lesson("fd-p084-old", source_signature=[old])
    alert = _lesson_alert(old, uuid=new)
    before = S.run_alert(tmp_path, alert=alert, tenant=planted, run_id="p084-before",
                         orient_shim=S.RecordingShim())
    section = _lessons_section(before)
    assert _listed(section) == [], f"the lesson under the old value was found: {_listed(section)}"
    assert _naming(section, old, before) == [], (
        f"the host's lessons prose names the old value {old!r}: {_naming(section, old, before)}")
    assert "fd-p084-old" not in S.harness_text(section), "the host's prose points at the old lesson"

    S.plant_lesson("fd-p084-new", source_signature=[new])
    after = S.run_alert(tmp_path, alert=alert, tenant=planted, run_id="p084-after",
                        orient_shim=S.RecordingShim())
    assert _listed(_lessons_section(after)) == ["fd-p084-new"], (
        f"the lesson under the remapped value is not found: {_listed(_lessons_section(after))}")


def test_p144_first_run_after_upgrade_finds_only_recordless_ru(tmp_path):
    """On the first run after the upgrade, orientation's vocabulary section states how many past
    runs were skipped for having no record. It does not read as "no past runs".

    Observed: a tenant whose runs base holds only pre-change runs of the alert (no record, an
    investigation, `rule.id` equal to the signature); orientation's vocabulary section, against
    the same section for a tenant with no past run.
    """
    sig = "R-P144"
    upgraded, fresh = S.plant_tenant("acme-up"), S.plant_tenant("acme-fresh")
    for tag in ("old1", "old2", "old3"):
        _past_run(upgraded.runs, f"pre-{tag}", tag=tag, rule_id=sig, recorded=False)
    d = S.run_alert(tmp_path, alert=_lesson_alert(sig), tenant=upgraded, run_id="p144-upgraded",
                    orient_shim=S.RecordingShim())
    e = S.run_alert(tmp_path, alert=_lesson_alert(sig), tenant=fresh, run_id="p144-fresh",
                    orient_shim=S.RecordingShim())
    section = _vocab_section(d)
    assert section is not None, "the first run after the upgrade carries no vocabulary section"
    assert _probes(section) == set(), f"the vocabulary served recordless pre-change runs:\n{section}"
    assert any(re.search(r"\b3\b", ln) and "record" in ln.lower() for ln in section.splitlines()), (
        f"the vocabulary section does not count the 3 runs skipped for having no record:\n{section}")
    assert _same_text(section, d) != _same_text(_vocab_section(e), e), (
        "the vocabulary over only recordless runs reads exactly as no past runs")


_WRITTEN_P182 = ["000123", "yes", "2026-05-01", "5710"]


def test_p182_lesson_signature_entry_that_frontmatter_reads_as(tmp_path):
    """The lessons reader takes each source_signature entry as the text written, with no YAML
    retyping: an unquoted 000123, yes or 2026-05-01 entry matches a recorded signature of that
    exact text, and every listing shows the written text.

    Observed: a lesson whose entries are written unquoted (000123, yes, 2026-05-01, 5710); the
    curator's corpus manifest; the tags listing and orientation's hits for a run recorded under
    each entry; and runs recorded under the values YAML retypes them to (83, True).
    """
    name = "fd-p182-retyped"
    planted = S.plant_tenant()
    S.plant_lesson(name, source_signature=_WRITTEN_P182)

    manifest = S.sym("learning.author.shared", "build_corpus_manifest")(S.checkout_lessons())
    entries = _manifest_entries(manifest)
    assert entries is not None, f"the manifest lists no source_signature:\n{manifest}"
    shown = [ln.strip().removeprefix("- ").strip().strip("'\"") for ln in entries]
    assert shown == _WRITTEN_P182, f"the manifest shows {shown}, not the text written"

    for i, sig in enumerate(_WRITTEN_P182):
        d = S.run_alert(tmp_path, alert=_lesson_alert(sig), tenant=planted, run_id=f"p182-{i}",
                        orient_shim=S.RecordingShim())
        section = _lessons_section(d)
        if i == 0:
            assert _tag_counts(section) == dict.fromkeys(_WRITTEN_P182, 1), (
                f"the tags listing does not show the text written: {_tag_frame(section)}")
        assert _listed(section) == [name], f"orientation's lookup of {sig!r}: {_listed(section)}"
    for i, sig in enumerate(["83", "True"]):
        d = S.run_alert(tmp_path, alert=_lesson_alert(sig), tenant=planted,
                        run_id=f"p182-retyped-{i}", orient_shim=S.RecordingShim())
        assert _listed(_lessons_section(d)) == [], (
            f"orientation found the lesson for its retyped value {sig!r}")


# =================================================================================================
# The lesson author: queue row to lesson file, through the real judge enqueue and drain
# =================================================================================================

def _ids(rows: Iterable[dict]) -> list[str]:
    return [r["finding_id"] for r in rows]


def _later_hits(tmp_path: Path, planted: S.Planted, sig: str, run_id: str) -> list[str]:
    """Orientation's lesson hits on a later run of an alert whose `rule.id` is `sig`."""
    d = S.run_alert(tmp_path, alert=_lesson_alert(sig), tenant=planted, run_id=run_id,
                    orient_shim=S.RecordingShim())
    return sorted(_listed(_lessons_section(d)))


def _adopt(planted: S.Planted, paths: Any, *names: str) -> dict[str, Any]:
    """Put the lessons the drain committed into the isolated checkout corpus, as written; return them."""
    committed = _committed(paths)
    for name in names:
        assert name in committed, f"the drain did not commit {name!r}: {sorted(committed)}"
        S.plant_lesson(name,
                       text=committed[name].path.read_text(encoding="utf-8"))
    return committed


_LESSON_KEYS = {"name", "description", "telemetry_source", "attack_phase", "source_signature",
                "source_finding_ids", "created_at"}


def test_p072_curator_batch_mixes_findings_of_two_signatures(tmp_path):
    """Each lesson's source_signature is its own finding's, carried on the queue row. The curator
    never re-reads a world copy.

    Observed: one drain batch holding the REAL judge's findings for an episode recorded under
    one signature, whose world copies' alerts carry another rule id, and a queued finding
    recorded under a second signature; the rows and user turn the curator is handed; the lessons
    it writes from them (each with its own finding's signature, unquoted) as the drain commits
    them; and a later run of each signature with those lessons in the isolated checkout corpus.
    """
    sig_a, sig_b, world = "SIG-P072-A", "SIG-P072-B", "R-P072-WORLD"
    rows_a, copied = _judged(tmp_path, signature=sig_a, world_rule=world)
    assert rows_a, "the judge enqueued no finding"
    row_b = _queued_row("p072-other/1", sig_b)
    curator = _Curator({"fd-p072-a": _author_lesson("fd-p072-a", [sig_a], _ids(rows_a)),
                        "fd-p072-b": _author_lesson("fd-p072-b", [sig_b], _ids([row_b]))})
    paths = _drain(tmp_path, curator, extra_rows=[row_b])

    handed = _keys_handed(curator)
    assert handed == {**dict.fromkeys(_ids(rows_a), sig_a), row_b["finding_id"]: sig_b}, (
        f"the curator was not handed each finding's recorded signature: {handed}")
    carried = _signatures_handed(curator)
    assert carried == {**dict.fromkeys(_ids(rows_a), sig_a), row_b["finding_id"]: sig_b}, (
        f"the rows do not carry each finding's recorded signature in their signature field: {carried}")
    turn = "\n".join(curator.user_turns)
    for sig in (sig_a, sig_b):
        assert sig in turn, f"the user turn does not carry {sig!r}"
    assert world not in turn, f"the world copies' rule id {world!r} reached the curator"
    planted = S.plant_tenant()
    committed = _adopt(planted, paths, "fd-p072-a", "fd-p072-b")
    assert committed["fd-p072-a"].lines("source_signature") == [sig_a]
    assert committed["fd-p072-b"].lines("source_signature") == [sig_b]
    assert _later_hits(tmp_path, planted, sig_a, "p072-later-a") == ["fd-p072-a"]
    assert _later_hits(tmp_path, planted, sig_b, "p072-later-b") == ["fd-p072-b"]
    assert copied, "the episode's record copy could not be planted (S.COINED accessors)"


#: The committed eval scenario's old-form key (`evals/scenarios/01-real-baseline`, PA-26).
_PRE_CHANGE_KEY = "rule-5710"


def test_p073_queue_rows_from_before_the_change_drained_after(tmp_path):
    """A row with no signature in the row's signature field gives the curator no signature to
    copy: an unsigned run's rows carry none there, and a row queued before the change lacks the
    field and is handed on unchanged, so it reads as unsigned by construction (no old-shape
    recognition, N13). The curator's instructions say a lesson's source_signature comes from that
    field, so the curator never invents one.

    Observed: one drain batch holding the REAL judge's findings for an episode whose record
    holds no signature (its world copies' alerts carry a rule id) and a finding queued before
    the change (old-form key, no signature field); the rows and user turn the curator is handed;
    the curator's instructions as the drain wires them; the queue after the tick; the lesson
    file the drain commits as the curator wrote it (the drain adds no source_signature).
    """
    world = "R-P073-WORLD"
    rows, copied = _judged(tmp_path, signature=None, world_rule=world)
    assert rows, "the judge enqueued no finding"
    pre = _queued_row("p073-before/1", _PRE_CHANGE_KEY, pre_change=True)
    curator = _Curator({"fd-p073": _author_lesson("fd-p073", None, [*_ids(rows), pre["finding_id"]])})
    paths = _drain(tmp_path, curator, extra_rows=[pre])

    handed = {r["finding_id"]: r for r in curator.rows()}
    keys = {fid: handed.get(fid, {}).get("alert_rule_key") for fid in _ids(rows)}
    assert keys == dict.fromkeys(_ids(rows), S.UNKEYED), (
        f"the curator was handed a key for findings of a run with no signature: {keys}")
    assert world not in "\n".join(curator.user_turns), (
        f"the world copies' rule id {world!r} reached the curator")
    assert pre["finding_id"] in handed, "the row queued before the change was not handed on"
    assert {k: handed[pre["finding_id"]].get(k) for k in pre} == pre, (
        f"the row queued before the change was rewritten: {handed[pre['finding_id']]}")
    carried = _signatures_handed(curator)
    assert carried == dict.fromkeys([*_ids(rows), pre["finding_id"]]), (
        f"the curator was handed a signature for a row that has none: {carried}")
    assert _signature_paragraphs(_prompt_text(paths)), (
        "the curator's instructions never say a lesson's source_signature comes from the row's "
        f"{S.QUEUE_SIGNATURE_FIELD!r} field, so an old row's key can still become one")
    assert D.pending(paths, FINDINGS) == [], "a row was left on the queue after the tick"
    lesson = _committed(paths)["fd-p073"]
    assert lesson.lines("source_signature") == [], (
        f"the drain added a source_signature to the lesson: {lesson.lines('source_signature')}")
    assert copied, "the episode's record copy could not be planted (S.COINED accessors)"


@pytest.mark.parametrize("sig", ["SIG-B2:r3.q", "unkeyed"])
def test_b2_finding_rows_carry_the_signature_in_a_field_old_rows_lack(tmp_path, sig):
    """A finding row the judge enqueues for a run with a recorded signature carries that
    signature, verbatim, in its own field (`S.QUEUE_SIGNATURE_FIELD`, coined) -- a field rows
    queued before the change lack; the rows reach the curator with that field as written, and
    the curator's instructions take a lesson's source_signature from that field alone, never
    from the row's rule key, which rows queued before the change also carry. (An unsigned run's
    rows carry none there: p073.)

    Observed: the REAL judge's rows for an episode recorded under a signature (its world copies'
    alerts carry another rule id); one REAL drain tick over them; the rows the curator is
    handed; the curator's instructions as the drain wires them. The instruction checks are
    word-level pins: an implementer whose correct wording trips one loosens the word list to
    their own words and never removes the check (§7 round 3, B5).
    """
    world = "R-B2-WORLD"
    rows, copied = _judged(tmp_path, signature=sig, world_rule=world)
    assert rows, "the judge enqueued no finding"
    written = {r["finding_id"]: r.get(S.QUEUE_SIGNATURE_FIELD) for r in rows}
    assert written == dict.fromkeys(_ids(rows), sig), (
        f"the judge's rows do not carry the recorded signature in {S.QUEUE_SIGNATURE_FIELD!r}: "
        f"{written}")
    curator = _Curator({"fd-b2": _author_lesson("fd-b2", [sig], _ids(rows))})
    paths = _drain(tmp_path, curator)
    assert _signatures_handed(curator) == dict.fromkeys(_ids(rows), sig), (
        f"the curator was not handed each row's signature field as written: "
        f"{_signatures_handed(curator)}")
    prompt = _prompt_text(paths)
    assert _signature_paragraphs(prompt), (
        "the curator's instructions never say a lesson's source_signature comes from the row's "
        f"{S.QUEUE_SIGNATURE_FIELD!r} field")
    from_key = [ln.strip() for ln in prompt.splitlines()
                if "source_signature" in ln and "alert_rule_key" in ln]
    assert not from_key, f"the curator's instructions take source_signature from the rule key: {from_key}"
    assert copied, "the episode's record copy could not be planted (S.COINED accessors)"


@pytest.mark.parametrize("sig", ["Rule:Brute/Force@v2", "unkeyed"])
def test_p074_lesson_round_trip_for_a_signature_whose_slug_dif(tmp_path, sig):
    """The curator writes the recorded signature verbatim as source_signature, and a later run's
    orientation lists that lesson.

    Observed: the REAL judge's findings for an episode recorded under a signature a slug would
    rewrite (case, `:`, `/`, `@`); the keys and user turn the curator is handed; the lesson it
    writes with that value (unquoted) as the drain commits it; a later run of an alert whose
    `rule.id` is that signature, with the committed lesson in the isolated checkout corpus.
    """
    rows, copied = _judged(tmp_path, signature=sig, world_rule="R-P074-WORLD")
    assert rows, "the judge enqueued no finding"
    curator = _Curator({"fd-p074": _author_lesson("fd-p074", [sig], _ids(rows))})
    paths = _drain(tmp_path, curator)
    assert set(_keys_handed(curator).values()) == {sig}, (
        f"the curator was not handed the recorded signature verbatim: {_keys_handed(curator)}")
    assert sig in "\n".join(curator.user_turns)
    planted = S.plant_tenant()
    committed = _adopt(planted, paths, "fd-p074")
    assert committed["fd-p074"].lines("source_signature") == [sig]
    assert _later_hits(tmp_path, planted, sig, "p074-later") == ["fd-p074"]
    assert copied, "the episode's record copy could not be planted (S.COINED accessors)"


def test_p077_signature_carries_frontmatter_significant_charac(tmp_path):
    """The lesson writer writes each source_signature entry as the token, unquoted; under the
    allow-list no character changes the list's structure, the saved lesson carries exactly the
    recorded signature with no extra frontmatter keys, and a later run of that signature finds
    it.

    Observed: the REAL judge's findings for an episode recorded under `R-P077:` (a trailing
    `:`, which an unquoted inline list reads as a mapping key) and a queued finding recorded
    under a value using every other punctuation the allow-list admits; the keys the curator is
    handed; the lessons it writes with each value unquoted, as the drain commits them; later
    runs of each signature with those lessons in the isolated checkout corpus.
    """
    colon, mixed = "R-P077:", "k8s_x:pod/exec@ns=prod+v1.2-x"
    rows, copied = _judged(tmp_path, signature=colon, world_rule="R-P077-WORLD")
    assert rows, "the judge enqueued no finding"
    other = _queued_row("p077-other/1", mixed)
    curator = _Curator({"fd-p077-colon": _author_lesson("fd-p077-colon", [colon], _ids(rows)),
                        "fd-p077-mixed": _author_lesson("fd-p077-mixed", [mixed], _ids([other]))})
    paths = _drain(tmp_path, curator, extra_rows=[other])
    assert _keys_handed(curator) == {**dict.fromkeys(_ids(rows), colon), other["finding_id"]: mixed}, (
        f"the curator was not handed the recorded signatures verbatim: {_keys_handed(curator)}")
    planted = S.plant_tenant()
    committed = _adopt(planted, paths, "fd-p077-colon", "fd-p077-mixed")
    for name, sig in (("fd-p077-colon", colon), ("fd-p077-mixed", mixed)):
        assert committed[name].lines("source_signature") == [sig], (
            f"{name}: the saved lesson reads back {committed[name].lines('source_signature')}, "
            f"not the recorded signature {sig!r}")
        assert set(committed[name].fm) == _LESSON_KEYS, sorted(committed[name].fm)
    assert _later_hits(tmp_path, planted, colon, "p077-later-colon") == ["fd-p077-colon"]
    assert _later_hits(tmp_path, planted, mixed, "p077-later-mixed") == ["fd-p077-mixed"]
    assert copied, "the episode's record copy could not be planted (S.COINED accessors)"


def test_p111_lesson_author_runs_for_a_run_whose_alert_is_unma(tmp_path):
    """A lesson authored from a run with no signature has no source_signature. The curator never
    invents one, and orientation never finds the lesson by signature.

    Observed: the REAL judge's findings for an episode whose record holds no signature (its
    alert was unmapped) while its world copies' alerts carry a rule id; the keys, user turn and
    instructions the curator is handed; the lesson it writes with no source_signature, as the
    drain commits it; later runs of that rule id and of a signature spelled `unkeyed`, with the
    lesson in the isolated checkout corpus beside a control keyed on the rule id.
    """
    world = "R-P111-WORLD"
    rows, copied = _judged(tmp_path, signature=None, world_rule=world)
    assert rows, "the judge enqueued no finding"
    curator = _Curator({"fd-p111": _author_lesson("fd-p111", None, _ids(rows))})
    paths = _drain(tmp_path, curator)
    assert set(_keys_handed(curator).values()) == {S.UNKEYED}, (
        f"the curator was handed a key for a run with no signature: {_keys_handed(curator)}")
    assert world not in "\n".join(curator.user_turns), (
        f"the world copies' rule id {world!r} reached the curator")
    prompt = _prompt_text(paths)
    assert any(S.UNKEYED in para and "source_signature" in para
               for para in re.split(r"\n\s*\n", prompt)), (
        f"the curator's instructions never say what a finding keyed {S.UNKEYED!r} writes as its "
        "source_signature")
    planted = S.plant_tenant()
    _adopt(planted, paths, "fd-p111")
    S.plant_lesson("fd-p111-control", source_signature=[world])
    assert _later_hits(tmp_path, planted, world, "p111-later-rule") == ["fd-p111-control"]
    assert _later_hits(tmp_path, planted, S.UNKEYED, "p111-later-unkeyed") == []
    assert copied, "the episode's record copy could not be planted (S.COINED accessors)"


def test_p116_lesson_author_reads_a_source_alert_the_run_rewro(tmp_path):
    """The lesson author is handed the recorded signature.

    Observed: the REAL judge's findings for an episode recorded under one signature whose world
    copies' alerts the box rewrote to another rule id (PR-17); the keys, user turn and
    instructions the curator is handed; the lesson it writes, as the drain commits it.
    """
    sig, forged = "SIG-P116", "FORGED-P116"
    rows, copied = _judged(tmp_path, signature=sig, world_rule=forged)
    assert rows, "the judge enqueued no finding"
    curator = _Curator({"fd-p116": _author_lesson("fd-p116", [sig], _ids(rows))})
    paths = _drain(tmp_path, curator)
    assert set(_keys_handed(curator).values()) == {sig}, (
        f"the curator was not handed the recorded signature: {_keys_handed(curator)}")
    assert set(_signatures_handed(curator).values()) == {sig}, (
        f"the rows do not carry the recorded signature in their signature field: "
        f"{_signatures_handed(curator)}")
    turn = "\n".join(curator.user_turns)
    assert sig in turn, f"the curator's user turn does not carry {sig!r}"
    assert forged not in turn, (
        f"the curator's user turn carries the rewritten alert's rule id {forged!r}")
    sends = [ln.strip() for ln in _prompt_text(paths).splitlines()
             if "source_signature" in ln and re.search(r"rule\.id|alert\.json", ln)]
    assert not sends, f"the curator's instructions take source_signature from the alert: {sends}"
    assert _committed(paths)["fd-p116"].lines("source_signature") == [sig]
    assert copied, "the episode's record copy could not be planted (S.COINED accessors)"


def test_p188_fold_between_signed_and_unsigned(tmp_path):
    """A folded lesson's source_signature lists the recorded signatures of the findings it
    carries; folding never invents one; a lesson listing several matches any one exactly.

    Observed: a drain corpus holding a lesson signed SIG-P188-A and one with no
    source_signature; one batch with the REAL judge's findings for an episode recorded under
    SIG-P188-B (world copies carrying another rule id), a queued finding recorded under
    SIG-P188-C and an unkeyed one; the keys the curator is handed; the two lessons it folds them
    into, as the drain commits them; later runs of each signature and of a near miss.
    """
    sig_a, sig_b, sig_c, world = "SIG-P188-A", "SIG-P188-B", "SIG-P188-C", "R-P188-WORLD"
    signed, unsigned = "fd-p188-signed", "fd-p188-unsigned"
    existing = {signed: S.lesson_text(signed, source_signature=[sig_a]),
                unsigned: S.lesson_text(unsigned, source_signature=None)}
    rows_b, copied = _judged(tmp_path, signature=sig_b, world_rule=world)
    assert rows_b, "the judge enqueued no finding"
    row_c, row_u = _queued_row("p188-c/1", sig_c), _queued_row("p188-u/1", S.UNKEYED)
    curator = _Curator({
        signed: _author_lesson(signed, [sig_a, sig_b],
                               [f"front-door/{signed}/0", *_ids(rows_b), row_u["finding_id"]]),
        unsigned: _author_lesson(unsigned, [sig_c], [f"front-door/{unsigned}/0", row_c["finding_id"]]),
    })
    paths = _drain(tmp_path, curator, extra_rows=[row_c, row_u], corpus=existing)
    assert _keys_handed(curator) == {**dict.fromkeys(_ids(rows_b), sig_b),
                                     row_c["finding_id"]: sig_c, row_u["finding_id"]: S.UNKEYED}, (
        f"the curator was not handed each finding's recorded signature: {_keys_handed(curator)}")
    assert world not in "\n".join(curator.user_turns)
    planted = S.plant_tenant()
    committed = _adopt(planted, paths, signed, unsigned)
    assert committed[signed].lines("source_signature") == [sig_a, sig_b]
    assert committed[unsigned].lines("source_signature") == [sig_c]
    for i, (sig, want) in enumerate(((sig_a, [signed]), (sig_b, [signed]), (sig_c, [unsigned]),
                                     ("SIG-P188", []))):
        assert _later_hits(tmp_path, planted, sig, f"p188-later-{i}") == want, sig
    assert copied, "the episode's record copy could not be planted (S.COINED accessors)"


def test_p189_eval_scenario_queue_rows_in_the_old_shape(tmp_path, monkeypatch):
    """The committed eval scenario's rows stay as committed; the lessons it authors come out
    with no source_signature, and nothing the eval measures changes.

    Observed: the committed scenario (`evals/scenarios/01-real-baseline`, rows keyed
    `rule-5710` with no recorded signature) materialized by the eval harness
    (`evals/harness.materialize`): the queue it leaves for the lesson author against the
    committed rows, and the corpus it leaves. The author's own leg over these rows is blocked
    before this change (82-writer red flag: the rows predate the `direction` field the
    lessons gate indexes).
    """
    monkeypatch.syspath_prepend(str(S.DEFENDER / "evals"))
    harness = S.mod("evals.harness")
    scenario = S.DEFENDER / "evals" / "scenarios" / "01-real-baseline"
    committed = (scenario / "findings.jsonl").read_bytes()
    rows = [json.loads(ln) for ln in committed.decode("utf-8").splitlines() if ln.strip()]
    assert {r.get("alert_rule_key") for r in rows} == {_PRE_CHANGE_KEY}, (
        "the committed scenario no longer holds the old-shape rows this demand is about")
    root = tmp_path / "eval"
    root.mkdir()
    harness.materialize(scenario, root)
    queued = root / "defender" / "learning" / "_pending" / "findings.jsonl"
    assert queued.read_bytes() == committed, "the eval harness did not queue the rows as committed"
    corpus = S.sym("_knowledge", "KnowledgePaths").of_defender_dir(root / "defender").lessons_dir
    assert corpus.is_dir(), f"the eval harness laid out no corpus at {corpus}"
    assert sorted(p.name for p in corpus.glob("*.md")) == sorted(
        p.name for p in (scenario / "lessons").glob("*.md")), "the eval's starting corpus changed"
