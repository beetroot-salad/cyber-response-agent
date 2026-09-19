"""Substrate for the issue-773 executable spec (`spec_graph_773-forward-check-authority.yaml`).

Pre-implementation. The forward check is still a TOOL the curator calls
(`verify_forward/tool.py`); the drain-owned gate this spec is the contract for does not
exist at the base commit, so most modules that import this one fail on their first scene
build. That is the expected red — it is what a spec written before the code looks like.
`_drain719.py` is the sibling substrate for the fold this one extends; everything that is
already true of the drain (the repo, the paths, the queue rows, the lock helpers) is
imported from there rather than re-spelled.

**The seam contract this spec pins** (write-code-from-spec implements it). Where the
intent+design doc named a mechanism but no symbol, the symbol is pinned HERE and the
choice is recorded in `80-author-digest.md` — a dependency the design gives no seam is a
demand, not an author's private convenience:

* `defender/learning/author/verify_forward/shared.py`
  - `VerdictError(RuntimeError)` — replaces `parse_verdict`'s `SystemExit` (Data model).
    Raised for a reply with no VERDICT line, an unrecognised token, **or more than one
    distinct verdict line** (§7 FK-11).
* `defender/learning/author/verify_forward/checks.py`
  - `ForwardCheck.run: Callable[[CheckContext], tuple[str, str]]` — `(verdict, reasoning)`,
    verdict ∈ {GOOD, BAD}. EXEMPT is the drain's via `cfg.exempt(row)`, never the check's.
* `defender/learning/author/_config.py` — `CorpusAuthorConfig` gains
  - `forward_check: ForwardCheck | None`, `exempt: Callable[[dict], bool]`,
    `repair_prompt: Path | None` (M2 / Data model);
  - `invoke_repair: Callable[[list[PairVerdict], str, cfg], dict]` — M4's repair spawn,
    the injection seam its fake enters through, mirroring `invoke_agent` (§7 F8: the
    restricted toolset is fixed on `CORPUS_REPAIR_DEF`, so what varies per call is only
    which BAD pairs it is handed);
  - `source_key: Callable[..., object]` — the verifier-key preflight's resolver, the seam
    `run_curator_stage` already carries under this exact name (C16), moved to the drain by
    M3.3 and gated per §7 FK-27.
* `defender/learning/author/drain.py`
  - `PairVerdict(rel_path, finding_id, source_id, verdict, reasoning, pass_no)` — frozen
    (Data model, `rel_path` per §7 FK-14).
  - `GAP_LEDGER_NAME = "findings.forward_bad.jsonl"` under `cfg.pending_dir` (M6/S5).
  - `DEFERRED_CEILING_REASON = "deferred_ceiling"` — the deferral exit's own
    `deadletter_reason`, distinct from a fault's (§7 FK-17).
  - `TERMINAL_BLOCK_HEADER = "Forward-check terminal:"` — the drain's commit-message block
    (M6), advisory prose beside the authoritative ledger (§7 FK-15).
* `defender/learning/author/shared.py`
  - `commit_corpus_paths(message, cfg, approved_paths, deletion_paths) -> str | None` —
    M5's explicit-list commit. **A NEW, SEPARATE FUNCTION**: `commit_fn` and `git_commit`
    are byte-for-byte unchanged and keep their seams (§7 FK-1 / section G). The drain's M5
    step calls this directly, never through `cfg.commit_fn`.
* `defender/learning/author/curator_engine.py`
  - `CORPUS_REPAIR_DEF` — a fixed, separate `AgentDefinition` whose `ToolSet` grants write
    and lesson_read and no bash (§7 F8: safe by construction, never a per-spawn override).
  - `ToolSet.forward_check`, `register_forward_check_tool`, `Pair`, `ForwardCheckConfig`,
    `no_forward_check`, `forward_checkable_ids`, `forward_exempt_ids`,
    `questioner_exempt_ids` are all GONE (M1, RF-5).

Project idioms this file obeys, because CI ratchets them: fakes enter through
`dataclasses.replace(cfg, ...)` and constructor arguments, never `monkeypatch.setattr`;
each fake injects faults only and never classifies or decides policy; every injected fault
cites the ledger claim that observed that shape on the real dependency.
"""
from __future__ import annotations

import dataclasses
import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from collections.abc import Callable
from typing import Any

from defender.tests._drain719 import (  # noqa: F401 — re-exported substrate
    Background,
    Holder,
    consumed,
    finding_row,
    git,
    graveyard,
    make_paths,
    make_repo,
    pending,
    pending_by_id,
    read_rows,
    seed,
    stuck_records,
    write_source_refs,
)

from defender.learning.author import drain
from defender.learning.author import shared as author_shared
from defender.learning.author.lessons import run as lessons_run
from defender.learning.core.config import LoopPaths, QueueChannel


class _NotYetWritten:
    """Stands in for a symbol the delta has not created yet.

    NOT a skip and NOT a soften: every attribute access raises, so each test fails loudly
    on its own reason. The indirection exists only so a missing target does not abort
    pytest's whole collection and take the rest of the tree's suite down with it — the same
    device `_drain719.py` used when `author/drain.py` was the thing that did not exist."""

    def __init__(self, dotted: str, err: BaseException | None = None) -> None:
        self._dotted, self._err = dotted, err

    def __getattr__(self, item: str) -> Any:
        raise ImportError(
            f"{self._dotted}.{item} does not exist yet — this suite is the executable spec "
            f"for it (spec_graph_773-forward-check-authority.yaml). Original: {self._err}"
        )

    def __call__(self, *a: Any, **k: Any) -> Any:
        raise ImportError(
            f"{self._dotted} does not exist yet — this suite is the executable spec for it "
            f"(spec_graph_773-forward-check-authority.yaml). Original: {self._err}"
        )


try:
    from defender.learning.author.verify_forward.shared import (  # type: ignore[attr-defined]
        VerdictError,
    )
except ImportError as _no_verdict_error:  # pragma: no cover — pre-implementation state

    class VerdictError(RuntimeError):  # type: ignore[no-redef]
        """Local stand-in so a test can NAME the class it expects the drain to raise.

        A test that expects production's `VerdictError` and gets this one still fails —
        `parse_verdict` raises `SystemExit` today, which is neither."""


try:
    from defender.learning.author.verify_forward.checks import (
        CheckContext,
        ForwardCheck,
        skips_forward_check,
    )
except ImportError as _no_checks:  # pragma: no cover
    CheckContext = _NotYetWritten("verify_forward.checks.CheckContext", _no_checks)  # type: ignore[assignment,misc]
    ForwardCheck = _NotYetWritten("verify_forward.checks.ForwardCheck", _no_checks)  # type: ignore[assignment,misc]
    skips_forward_check = _NotYetWritten("verify_forward.checks.skips_forward_check", _no_checks)  # type: ignore[assignment]


#: M6's ledger file name, under the HOST-SIDE pending dir (S5/G6).
GAP_LEDGER_NAME = "findings.forward_bad.jsonl"
#: The reasoning prefix a doubly-failed pair's recorded BAD carries (M3.3, §7 FK-10).
ERROR_PREFIX = "forward_check_error: "
#: M6's commit-message block header (§7 FK-15: advisory prose, ledger is the record).
TERMINAL_BLOCK_HEADER = "Forward-check terminal:"
#: §7 FK-17: a deferral that reaches the ceiling is greppable apart from a fault exit.
DEFERRED_CEILING_REASON = "deferred_ceiling"


# ---------------------------------------------------------------------------
# corpus bytes
# ---------------------------------------------------------------------------


def lesson(*finding_ids: str, body: str = "the lesson body", **frontmatter: Any) -> str:
    """One corpus `*.md` citing `finding_ids` under the channel's own provenance key.

    `source_finding_ids` is the key `provenance_field("finding_id")` derives and the key
    both the pre-author idempotency gate and M3.2's vouching read (C13/G13), so a file
    written with it is one a later tick recognises."""
    lines = ["---", "source_finding_ids:"]
    lines += [f"- {fid}" for fid in finding_ids]
    for key, val in frontmatter.items():
        lines.append(f"{key}: {json.dumps(val)}")
    lines += ["---", "", body, ""]
    return "\n".join(lines)


def malformed_lesson(body: str = "no frontmatter here at all\n") -> str:
    """Bytes whose frontmatter block cannot be parsed, written by the test itself.

    Real input through the real primitive: `_cited_ids` runs `split_frontmatter` over these
    bytes on every run, so the taxonomy assumption ("malformed cites nothing") is re-probed
    rather than pinned once."""
    return "---\nsource_finding_ids: [unterminated\nbody without a closing fence\n" + body


# ---------------------------------------------------------------------------
# the scene
# ---------------------------------------------------------------------------


@dataclass
class Scene:
    """One tick's world: a real git repo, a real queue file, and the injected fakes."""

    paths: LoopPaths
    cfg: Any
    channel: QueueChannel
    repo: Path
    corpus: Path
    rows: list[dict]
    curator: FakeCurator
    verifier: FakeVerifier
    repair: FakeRepair
    keys: FakeKeySource
    #: The channel module's own `run_batch`; the lessons channel's unless a sibling scene
    #: replaces it. Named so `Scene.run` always drives a production front door.
    runner: Callable[..., int] | None = None
    #: HEAD as the scene was built, so `head_files()` can answer "what this tick committed".
    base_sha: str = ""

    # -- observations -------------------------------------------------------

    def run(self, **kw: Any) -> int:
        """Drive the REAL entry point. `lessons_run.run_batch` -> `drain.run_batch` ->
        `_tick` -> `_author_and_rotate`: the whole tick, not a re-implementation of it."""
        runner = self.runner if self.runner is not None else lessons_run.run_batch
        return runner(cfg=self.cfg, **kw)

    def head_files(self) -> list[str]:
        """The paths THIS TICK committed — asked of git, never of the drain's own record.

        Computed against the sha the scene was built at, so an empty list means "HEAD did
        not move". Reading the tip commit's own name list would answer the repo's whole
        file set on a tick that committed nothing, because the tip would still be the
        fixture's initial commit — and `== []` would then never be true of anything.

        `--no-renames`: the commit itself never records a rename — `commit_corpus_paths`
        stages an add and a delete as two independent index entries (M5) — a rename is
        purely a similarity heuristic `git diff` applies after the fact, and the fixture
        lessons here are near-identical short files (one frontmatter line differs) that
        cross git's default 50% threshold easily. Without this flag a deletion this tick
        genuinely made is silently absent from the list whenever its replacement happens
        to read as similar, which answers a question about content resemblance, not about
        which paths this operator's own instrument says the commit touched."""
        if self.head_sha() == self.base_sha:
            return []
        out = git(self.repo, "diff", "--no-renames", "--name-only", self.base_sha, "HEAD").stdout
        return sorted(p for p in out.splitlines() if p.strip())

    def head_message(self) -> str:
        return git(self.repo, "log", "-1", "--format=%B").stdout

    def head_sha(self) -> str:
        return git(self.repo, "rev-parse", "HEAD").stdout.strip()

    def head_text(self, rel: str) -> str | None:
        proc = git(self.repo, "show", f"HEAD:{rel}", check=False)
        return proc.stdout if proc.returncode == 0 else None

    def commit_count(self) -> int:
        return int(git(self.repo, "rev-list", "--count", "HEAD").stdout.strip())

    def corpus_files(self) -> list[str]:
        return sorted(
            str(p.relative_to(self.corpus))
            for p in self.corpus.rglob("*")
            if p.is_file() and p.name != ".gitkeep"
        )

    def gap_records(self) -> list[dict]:
        return read_rows(self.cfg.pending_dir / GAP_LEDGER_NAME)

    def report_lines(self) -> list[str]:
        """The channel's own disposition report — `held_report` on the lessons channel,
        `skip_report` on the questioner's. One accessor, because both are written by the
        same `shared.write_disposition_report` and both are what "reported" means."""
        path = getattr(self.cfg, "held_report", None) or self.cfg.skip_report
        return path.read_text(encoding="utf-8").splitlines() if path.is_file() else []

    def pending(self) -> list[dict]:
        return pending(self.channel)

    def pending_by_id(self) -> dict[str, dict]:
        return pending_by_id(self.channel)

    def consumed(self) -> list[dict]:
        return consumed(self.channel)

    def consumed_by_id(self) -> dict[str, dict]:
        return {r["finding_id"]: r for r in self.consumed() if "finding_id" in r}

    def graveyard(self) -> list[dict]:
        return graveyard(self.channel)

    def category_of(self, fid: str) -> str | None:
        row = self.consumed_by_id().get(fid)
        return None if row is None else row.get("consumed_category")


def build_scene(  # noqa: PLR0913 — one tick's whole world, threaded rather than global
    tmp_path: Path,
    *,
    rows: list[dict] | None = None,
    dispositions: dict[str, str] | None = None,
    state_dir: Path | None = None,
    curator: FakeCurator | None = None,
    verifier: FakeVerifier | None = None,
    repair: FakeRepair | None = None,
    keys: FakeKeySource | None = None,
    seed_corpus: dict[str, str] | None = None,
    channel_name: str = "findings",
    **cfg_overrides: Any,
) -> Scene:
    """A lessons-channel tick, wired through the config's own injection seams.

    Every collaborator the tick would otherwise reach over the network — the curator spawn,
    the repair spawn, the verifier model call, the provider key source — enters through a
    `dataclasses.replace` on the real config builder's output. Nothing is patched onto a
    module.

    `dispositions` overrides the `source_refs.yaml` ground truth a row's direction needs to
    pass `_gate_findings` (adversarial rows need `benign`, benign rows need `malicious`);
    the default satisfies whatever direction each row declares, so a test that does not
    care about the pre-author gate does not have to think about it."""
    paths = make_paths(tmp_path, state_dir=state_dir)
    repo = paths.repo_root
    corpus = paths.lessons_dir
    rows = list(rows if rows is not None else [finding_row("f1", run_id="f1")])

    wanted = {"adversarial": "benign", "benign": "malicious", "family": "benign"}
    for row in rows:
        run_id = row.get("run_id")
        if not isinstance(run_id, str) or not run_id:
            continue
        disp = (dispositions or {}).get(run_id)
        if disp is None:
            disp = wanted.get(str(row.get("direction")), "benign")
        write_source_refs(paths, run_id, disp)

    for rel, text in (seed_corpus or {}).items():
        target = corpus / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    if seed_corpus:
        git(repo, "add", "-A")
        git(repo, "commit", "-q", "-m", "seed corpus")

    channel = getattr(paths, channel_name)
    seed(channel, rows)

    curator = curator if curator is not None else FakeCurator()
    verifier = verifier if verifier is not None else FakeVerifier()
    repair = repair if repair is not None else FakeRepair()
    keys = keys if keys is not None else FakeKeySource()

    base = lessons_run.build_author_config(paths)
    wiring: dict[str, Any] = {
        "invoke_agent": curator,
        "forward_check": verifier.as_check(),
        "exempt": skips_forward_check,
        "repair_prompt": _repair_prompt(paths),
        "invoke_repair": repair,
        "source_key": keys,
    }
    wiring.update(cfg_overrides)
    cfg = dataclasses.replace(base, **wiring)

    return Scene(
        paths=paths, cfg=cfg, channel=channel, repo=repo, corpus=corpus, rows=rows,
        curator=curator, verifier=verifier, repair=repair, keys=keys,
        base_sha=git(repo, "rev-parse", "HEAD").stdout.strip(),
    )


def world_row(fid: str, **extra: Any) -> dict:
    """One QUESTIONER-channel row: a finding about the WORLD, not about the defender.

    That channel carries no `run_id` and no defender disposition, so its gate is
    idempotency-only (#1007 N1) and O7 obliges this delta to leave its behaviour alone."""
    return {
        "schema_version": 1,
        "finding_id": fid,
        "subject": "world",
        "type": "lead-set",
        "finding": "the overlay never backed this field",
        **extra,
    }


def build_questioner_scene(
    tmp_path: Path,
    *,
    rows: list[dict] | None = None,
    curator: FakeCurator | None = None,
    keys: FakeKeySource | None = None,
    seed_corpus: dict[str, str] | None = None,
    **cfg_overrides: Any,
) -> Scene:
    """The SIBLING channel's tick — `forward_check=None`, `exempt=lambda r: True` (M2).

    O7 obliges this channel to keep today's behaviour, including the #852 vouching gate, so
    it is the negative control every preflight and verdict-step demand needs: a lane that
    never wanted a forward check must not meet one."""
    from defender.learning.author.questioner import run as questioner_run

    paths = make_paths(tmp_path)
    repo = paths.repo_root
    corpus = paths.lessons_questioner_dir
    corpus.mkdir(parents=True, exist_ok=True)
    (corpus / ".gitkeep").write_text("", encoding="utf-8")
    for rel, text in (seed_corpus or {}).items():
        target = corpus / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "questioner corpus")

    rows = list(rows if rows is not None else [world_row("w1")])
    channel = paths.questioner_findings
    seed(channel, rows)

    curator = curator if curator is not None else FakeCurator()
    keys = keys if keys is not None else FakeKeySource()
    verifier = FakeVerifier()
    repair = FakeRepair()

    base = questioner_run.build_questioner_config(paths)
    wiring: dict[str, Any] = {
        "invoke_agent": curator,
        "forward_check": None,
        "exempt": (lambda row: True),
        "repair_prompt": None,
        "invoke_repair": repair,
        "source_key": keys,
    }
    wiring.update(cfg_overrides)
    cfg = dataclasses.replace(base, **wiring)

    scene = Scene(
        paths=paths, cfg=cfg, channel=channel, repo=repo, corpus=corpus, rows=rows,
        curator=curator, verifier=verifier, repair=repair, keys=keys,
        base_sha=git(repo, "rev-parse", "HEAD").stdout.strip(),
    )
    scene.runner = questioner_run.run_batch  # type: ignore[attr-defined]
    return scene


def _repair_prompt(paths: LoopPaths) -> Path:
    """M4's repair prompt, written into the scene's own tree.

    Written rather than pointed at the shipped `lessons/repair.md`, which does not exist
    yet: what the spec pins is that the drain READS a configured path, not the prose."""
    target = paths.learning_dir / "author" / "lessons" / "repair.md"
    target.parent.mkdir(parents=True, exist_ok=True)
    if not target.is_file():
        target.write_text("# repair\nRewrite the lesson, keeping its citations.\n", "utf-8")
    return target


# ---------------------------------------------------------------------------
# fakes — each injects faults or canned content, and classifies nothing
# ---------------------------------------------------------------------------


@dataclass
class FakeCurator:
    """The first curator spawn (`cfg.invoke_agent`).

    A fault-spec, not a policy: `writes` is what the agent leaves in the worktree,
    `committed`/`consumed_skip` are what it SELF-REPORTS, and the two are deliberately
    independent so a test can drive any report/tree disagreement O5 names. `raises` is the
    declarative fault slot; every use cites the ledger claim that observed its class on the
    real dependency (GL2 for the `RETIRE_SET` members)."""

    writes: dict[str, str] = field(default_factory=dict)
    deletes: tuple[str, ...] = ()
    outside: dict[str, str] = field(default_factory=dict)
    committed: list[str] | None = None
    consumed_skip: list[dict] | None = None
    commit_message: str = "author findings batch"
    extra_result: dict[str, Any] = field(default_factory=dict)
    result: dict[str, Any] | None = None
    raises: BaseException | None = None
    also: Callable[..., None] | None = None
    calls: list[dict] = field(default_factory=list)

    def __call__(self, rows: list[dict], batch_id: str, cfg: Any) -> dict:
        self.calls.append({"rows": list(rows), "batch_id": batch_id, "cfg": cfg})
        if self.raises is not None:
            raise self.raises
        for rel, text in self.writes.items():
            target = cfg.corpus_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        for rel in self.deletes:
            target = cfg.corpus_dir / rel
            if target.is_file():
                target.unlink()
        for rel, text in self.outside.items():
            target = cfg.repo_root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        if self.also is not None:
            self.also(rows, batch_id, cfg)
        if self.result is not None:
            return dict(self.result)
        ids = [r["finding_id"] for r in rows]
        out: dict[str, Any] = {
            "committed": list(self.committed if self.committed is not None else ids),
            "consumed_skip": list(self.consumed_skip or []),
            "commit_message": self.commit_message,
        }
        out.update(self.extra_result)
        return out


@dataclass
class FakeRepair:
    """M4's repair spawn (`cfg.invoke_repair`), recording what it was handed.

    The drain hands it the BAD `PairVerdict`s; this fake records them verbatim so a test
    can assert on the INBOUND payload — which findings, which text, which reasoning, and
    whether each section arrived `wrap()`ed (S4) — rather than on a canned reply."""

    writes: dict[str, str] = field(default_factory=dict)
    deletes: tuple[str, ...] = ()
    outside: dict[str, str] = field(default_factory=dict)
    raises: BaseException | None = None
    raise_after_writes: bool = False
    also: Callable[..., None] | None = None
    calls: list[dict] = field(default_factory=list)

    @property
    def spawned(self) -> int:
        return len(self.calls)

    @property
    def last_pairs(self) -> list[Any]:
        return list(self.calls[-1]["pairs"]) if self.calls else []

    def __call__(self, pairs: Any, batch_id: str, cfg: Any, **kw: Any) -> dict:
        self.calls.append({"pairs": list(pairs), "batch_id": batch_id, "cfg": cfg, **kw})
        if self.raises is not None and not self.raise_after_writes:
            raise self.raises
        for rel, text in self.writes.items():
            target = cfg.corpus_dir / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        for rel in self.deletes:
            target = cfg.corpus_dir / rel
            if target.is_file():
                target.unlink()
        for rel, text in self.outside.items():
            target = cfg.repo_root / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8")
        if self.also is not None:
            self.also(pairs, batch_id, cfg)
        if self.raises is not None:
            raise self.raises
        return {"repaired": [getattr(p, "finding_id", None) for p in pairs]}


@dataclass
class FakeVerifier:
    """The verifier model call, as a `ForwardCheck` whose `run` is a data fault-spec.

    THE DEPENDENCY IS THE ONE THE HIERARCHY ALLOWS TO BE FAKED: an LLM call over the
    network is neither cheap nor deterministic, so the fault CONTENT is canned — and every
    canned fault cites the ledger claim that observed that shape on the real dependency
    (C1 for `CheckContext`'s fields and the trace-name axis, C2 for `parse_verdict`'s two
    raising shapes, P3/§7 FK-9 for the `benign` direction's out-of-process ticket-adapter
    call). It injects only: it never decides whether a verdict is terminal, never decides
    what EXEMPT means, and never touches the queue.

    IT RECORDS WHAT IT RECEIVES. `calls` holds the `CheckContext` objects the drain built,
    so the outbound channel is pinned by assertion rather than assumed from a reply.

    Keys are `(lesson file name, source_id)`, `source_id` alone, or the file name alone —
    the drain mints one pair per (changed file, this-batch cited id), and a test usually
    cares about only one coordinate of that pair."""

    verdicts: dict[Any, str] = field(default_factory=dict)
    default: str = "GOOD"
    reasoning: str = "the lesson leaves the case's own call intact"
    reasonings: dict[Any, str] = field(default_factory=dict)
    #: key -> one entry per ATTEMPT; `None` means "this attempt returns a verdict".
    faults: dict[Any, list[BaseException | None]] = field(default_factory=dict)
    #: a fault every pair's Nth attempt raises, for the batch-wide shapes (a provider outage)
    fault_every: list[BaseException | None] = field(default_factory=list)
    prompt_path: Path | None = Path("verifier-prompt.md")
    error_prefix: str = "verify_forward"
    calls: list[Any] = field(default_factory=list)
    attempts: dict[Any, int] = field(default_factory=dict)
    on_call: Callable[[Any], None] | None = None

    # -- observations -------------------------------------------------------

    @property
    def call_count(self) -> int:
        return len(self.calls)

    @property
    def indices(self) -> list[int]:
        return [c.check_index for c in self.calls]

    @property
    def pairs_seen(self) -> list[tuple[str, str]]:
        return [(c.lesson_path.name, c.source_id) for c in self.calls]

    def texts_for(self, name: str) -> list[str]:
        return [c.lesson_text for c in self.calls if c.lesson_path.name == name]

    def calls_for(self, name: str) -> list[Any]:
        return [c for c in self.calls if c.lesson_path.name == name]

    # -- the seam -----------------------------------------------------------

    def as_check(self) -> Any:
        if isinstance(ForwardCheck, _NotYetWritten):  # pragma: no cover
            return _StubCheck(self)
        return ForwardCheck(
            error_prefix=self.error_prefix, prompt_path=self.prompt_path, run=self.run
        )

    def _key(self, ctx: Any) -> tuple[str, str]:
        return (ctx.lesson_path.name, ctx.source_id)

    def _lookup(self, table: dict[Any, Any], ctx: Any, fallback: Any, *, n: int | None = None) -> Any:
        """Look `ctx`'s pair up in `table`, keyed by `(name, source_id)`, `source_id` alone,
        or `name` alone. PER-ATTEMPT SCHEDULING (§7 FK-7/FK-8's pass-1-vs-pass-2 shape):
        when the stored value is a `list`, `n` (this key's 0-indexed call count, the same
        counter `run()` already keys `faults`/`fault_every` on) selects the entry, clamped
        to the last one once the schedule runs out — so a second call to the same pair (a
        retry, or a pass-2 re-check) gets its own declared answer WITHOUT the fake reading
        the inbound payload to decide anything. A scalar value still means "every attempt"."""
        key = self._key(ctx)
        for candidate in (key, ctx.source_id, key[0]):
            if candidate in table:
                value = table[candidate]
                if n is not None and isinstance(value, list):
                    return value[min(n, len(value) - 1)]
                return value
        return fallback

    def run(self, ctx: Any) -> tuple[str, str]:
        self.calls.append(ctx)
        if self.on_call is not None:
            self.on_call(ctx)
        key = self._key(ctx)
        n = self.attempts.get(key, 0)
        self.attempts[key] = n + 1
        schedule = self._lookup(self.faults, ctx, None) or self.fault_every
        if schedule and n < len(schedule) and schedule[n] is not None:
            raise schedule[n]
        verdict = self._lookup(self.verdicts, ctx, self.default, n=n)
        return verdict, self._lookup(self.reasonings, ctx, self.reasoning, n=n)


class _StubCheck:
    """What `as_check()` returns before `ForwardCheck` widens to `(verdict, reasoning)`.

    Carries the same three attributes the real dataclass does, so a config that stores it
    still fails on the field's ABSENCE rather than on this stand-in's shape."""

    def __init__(self, fake: FakeVerifier) -> None:
        self.error_prefix = fake.error_prefix
        self.prompt_path = fake.prompt_path
        self.run = fake.run


@dataclass
class FakeKeySource:
    """`cfg.source_key` — the provider-key resolver the M3.3 preflight calls (C16).

    `missing` names the models whose key is unset; sourcing one raises the same
    `FatalConfigError` the real `source_first_party_key` raises (C16), which is O10's
    fatal-config path. Every sourced label is recorded, so a test can assert the preflight
    ran, ran ONCE, and ran before the first spawn."""

    missing: tuple[str, ...] = ()
    labels: list[str] = field(default_factory=list)
    models: list[str] = field(default_factory=list)

    def __call__(self, model: str, *, label: str = "", **kw: Any) -> object:
        from defender.learning.core.config import FatalConfigError

        self.models.append(model)
        self.labels.append(label)
        if model in self.missing:
            raise FatalConfigError(f"{label}: no api key for {model}")
        return object()


# ---------------------------------------------------------------------------
# fault content, each citing the claim that observed it
# ---------------------------------------------------------------------------


def unreadable_reply(text: str = "the verifier mused and never said VERDICT") -> BaseException:
    """What an unparseable verifier reply raises once `parse_verdict` stops exiting.

    C2: `parse_verdict` raises on exactly two shapes today — a missing VERDICT line and an
    unrecognised token — and the Data model replaces that `SystemExit` with
    `VerdictError`. §7 FK-11 adds the third shape (more than one distinct verdict line)."""
    return VerdictError(f"verify_forward: no VERDICT line found in verifier output:\n{text}")


def call_never_completed(what: str = "connection reset by the verifier's provider") -> BaseException:
    """A call that never COMPLETED, as distinct from a reply that cannot be read.

    §7 FK-9 (dissolved): the two failure kinds are different exception classes at the point
    of catching, so an infrastructure failure can never become a permanent
    `consumed_forward_bad`. The class is the ordinary transport error the provider raises;
    what the spec pins is that it is NOT a `VerdictError`."""
    return ConnectionError(what)


def ticket_adapter_unreachable() -> BaseException:
    """The `benign` direction's out-of-process ticket-adapter call failing.

    P3 / §7 FK-9, probe-confirmed at `verify_forward/forward.py:75-94`
    (`_POLICY_FETCH_TIMEOUT = 15`): `load_cited_policy` shells out per `benign` pair inside
    the doubled repo-lock hold. A subprocess that times out is a call that never completed,
    not a verdict."""
    return subprocess.TimeoutExpired(cmd=["ticket_adapter.py", "policy"], timeout=15)


def author_error(msg: str = "injected") -> BaseException:
    """GL2: `AuthorError` is a `RETIRE_SET` member, declared once at `drain.py:73`."""
    return drain.AuthorError(msg)


def git_error(msg: str = "injected") -> BaseException:
    """GL2: `GitError` is a `RETIRE_SET` member."""
    from defender._git import GitError

    return GitError(["status"], 128, msg)


def model_retry(msg: str = "injected") -> BaseException:
    """GL2: `ModelRetry` is a `RETIRE_SET` member."""
    from pydantic_ai.exceptions import ModelRetry

    return ModelRetry(msg)


def stage_abort(msg: str = "injected") -> BaseException:
    """GL2: `StageAbort` is an explicit `RETIRE_SET` EXCLUSION (§7 E waives the cell)."""
    from defender.learning.core.config import StageAbort

    return StageAbort(msg)


def fatal_config(msg: str = "injected") -> BaseException:
    """GL2 / F8: `FatalConfigError` is a `ValueError` and a `RETIRE_SET` exclusion, which is
    why the per-pair handler must re-raise it BEFORE its broad `except Exception`."""
    from defender.learning.core.config import FatalConfigError

    return FatalConfigError(msg)


__all__ = [
    "Background",
    "CheckContext",
    "DEFERRED_CEILING_REASON",
    "ERROR_PREFIX",
    "FakeCurator",
    "FakeKeySource",
    "FakeRepair",
    "FakeVerifier",
    "GAP_LEDGER_NAME",
    "Holder",
    "Scene",
    "TERMINAL_BLOCK_HEADER",
    "VerdictError",
    "author_error",
    "author_shared",
    "build_scene",
    "call_never_completed",
    "drain",
    "fatal_config",
    "finding_row",
    "git",
    "git_error",
    "lesson",
    "lessons_run",
    "malformed_lesson",
    "model_retry",
    "read_rows",
    "seed",
    "stage_abort",
    "ticket_adapter_unreachable",
    "unreadable_reply",
    "write_source_refs",
]
