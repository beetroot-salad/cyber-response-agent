"""The file gates: deny-by-default read allowlist + write/invlang validation.

Both return a plain `Decision`. Reads must resolve inside the run dir or the
defender corpus (with a belt-and-suspenders secret/ground-truth denylist on top);
writes must `fullmatch` one of the agent's `policy.write_allow` patterns (its
declared paths — a flat, deny-by-default allowlist). On top of the allowlist, the
run's two model-authored output artifacts get an OUTPUT-STRUCTURE gate (#629): a
`report.md` write must carry parseable frontmatter with a valid `disposition` and
stay within its frontmatter/whole-file byte bounds, and an `investigation.md` write
must stay within its byte bound — checked before the structural invlang validator.
`is_untrusted_read` flags attacker-influenced data the caller must tag-wrap."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from defender._frontmatter import FrontmatterError, split_frontmatter
from defender.learning.core.config import DISPOSITION_ENUM
from defender.runtime import bash_policy
from defender.skills.invlang.validate import validate_companion

from .decision import Decision
from .policy import AgentPolicy

# #629 — output-structure bounds for the run's two model-authored artifacts, all in
# UTF-8 BYTES. These are a VOLUME + STRUCTURE control on bytes that leave the system
# (the report/investigation ride verbatim into the judge LLM prompt, and the report
# body into the ticket bridge's HTTP egress) — not a content oracle: an in-bound,
# well-formed payload still passes. Values are policy inputs decided in the #629
# intent+design doc (report frontmatter 512 B / whole file 8 KiB; investigation 64 KiB).
_REPORT_FRONTMATTER_MAX = 512
_REPORT_FILE_MAX = 8192
_INVESTIGATION_FILE_MAX = 65536

# The judge splices report.md verbatim into a `<report>…</report>` block with no
# tag-delimiter escaping (learning/pipeline/judge/run.py + pipeline/_prompt.py::_section),
# so a literal closing delimiter in the report could close the tag early and forge an
# adjacent prompt section — deny it fail-closed alongside the size bounds (#629 cc7).
_REPORT_CLOSE_DELIMITER = "</report>"

# Everything `Path.resolve()` can throw on a hostile operand, so every gate that
# resolves one fails CLOSED instead of propagating. `OSError`/`RuntimeError` are the
# filesystem + symlink-cycle cases; `ValueError` is an embedded NUL (`cat a\0b`),
# which `shlex` happily tokenizes into an operand — without it the exception escapes
# `decide_read`/`decide_bash` and crashes the tool call rather than denying it.
RESOLVE_ERRORS: tuple[type[BaseException], ...] = (OSError, RuntimeError, ValueError)


def _is_within(p: Path, root: Path) -> bool:
    """True iff resolved path `p` is `root` or below it."""
    try:
        p.relative_to(root)
        return True
    except ValueError:
        return False


def denylisted(rp: Path) -> bool:
    """True iff a resolved path hits the secret/ground-truth denylist — a denied
    filename substring (`.env` / `cases.json` / `ground_truth` / `credentials`) or a
    denied path component (`.ssh`). Belt-and-suspenders that applies INSIDE every
    allowed root, on BOTH read surfaces: the read tool (`decide_read`) and the judge's
    bash operand lane (`read_allowed_path`) — so the two surfaces can't disagree about a
    denied file that resolves within-root (the held-out `ground_truth.yaml` under the
    defender corpus, a captured `.env` in the run dir)."""
    return any(d in set(rp.parts) for d in bash_policy.read_deny_dirs()) or any(
        s in rp.name for s in bash_policy.read_deny_substrings()
    )


def _resolved_read_roots(
    policy: AgentPolicy, run_dir: Path, defender_dir: Path
) -> tuple[Path, ...]:
    """The resolved roots a read must land within for `policy`. When
    `policy.read_confine` is non-empty it REPLACES the `defender_dir` base (the
    gray-box confine — a confined actor sees only its lesson corpora, not the whole
    corpus); `run_dir` and the agent's `read_roots` still widen. Empty confine is
    the legacy `{run_dir, defender_dir, *read_roots}`. May raise `OSError` /
    `RuntimeError` / `ValueError` from `resolve()` (a symlink cycle, an embedded NUL) —
    every caller FAILS CLOSED."""
    base = policy.read_confine if policy.read_confine else (Path(defender_dir),)
    return tuple(
        r.resolve() for r in (Path(run_dir), *base, *policy.read_roots)
    )


def build_write_allow(root: Path, *, suffix: str = "") -> re.Pattern[str]:
    """Build one `AgentPolicy.write_allow` pattern admitting `root` itself and everything
    under it — optionally only paths whose basename ends `suffix` (a `re`-escaped literal,
    e.g. `".md"`). `decide_write` `fullmatch`es this against the RESOLVED operand, so `root`
    is `resolve()`d here to align the two, and a `..` in the operand is collapsed before the
    match (a subtree, not a string prefix — `<root>-evil/x` can't match either). The write
    twin of the bash lane's baked reader anchors (`policies._common`), used by every writer's
    policy (`policies.main`, `lead_author_engine`) so the flat allowlist has one builder."""
    base = re.escape(str(root.resolve()))
    tail = r"/[^\x00]*" + re.escape(suffix) if suffix else r"(?:/[^\x00]*)?"
    return re.compile(base + tail)


def build_scoped_write_allow(root: Path, *, suffix: str = "") -> re.Pattern[str]:
    """Build one `AgentPolicy.write_allow` pattern admitting `root` and everything under it,
    narrowed to the SAME filename segment class the read side's `Grant.scope` shapes use
    (`grant.SEG`, `[\\w.@=+-]+`, one-or-more nested segments) rather than `build_write_allow`'s
    `[^\\x00]*` — so a write and its matching read-back admit EXACTLY the same names (#691 MD-7),
    foreclosing a space/newline write-only name from the frame-injection channel a wide tail would
    otherwise open. `root` is `resolve()`d to align with the RESOLVED operand `decide_write`
    matches against, same as `build_write_allow`."""
    from .grant import SEG

    base = re.escape(str(root.resolve()))
    tail = rf"/{SEG}(?:/{SEG})*"
    if suffix:
        tail += re.escape(suffix)
    return re.compile(base + tail)


def build_named_write_allow(root: Path, names: tuple[str, ...]) -> tuple[re.Pattern[str], ...]:
    """A POSITIVE allow-list of EXACTLY `<root>/<name>` for each name — one anchored
    pattern per basename, matched against the RESOLVED operand (#631, S2). Deliberately
    tighter than `build_write_allow`'s subtree/`.md`-suffix forms: a suffix filter is a
    filename filter, not a subtree narrowing (`decide_write` applies no path shapes), so
    it would admit `gather_raw/evil.md` and `sub/report.md` at depth. Resolving both
    sides means an alias that resolves to `<root>/investigation.md` matches the
    investigation.md pattern (and is then invlang-validated on the RESOLVED name), while
    `<root>/sub/report.md` never matches the report.md pattern."""
    base = re.escape(str(root.resolve()))
    return tuple(re.compile(base + "/" + re.escape(name)) for name in names)


def read_allowed_path(
    path: str | Path, *, run_dir: Path | None, defender_dir: Path | None,
    policy: AgentPolicy,
) -> bool:
    """Whether a file operand resolves within `policy`'s read roots — the
    ROOTS half of `decide_read` (the shape half is `policy.read_allow`), reused by `decide_write`
    for its `write_allow ⊆ read roots` check. FAILS CLOSED: a `resolve()` error (a symlink cycle,
    an embedded NUL) OR a missing root context (`run_dir`/`defender_dir` `None`) returns `False`,
    never raises. The secret/ground-truth denylist IS applied (parity with `decide_read`, so a
    write can't land on a denied file the read tool refuses — the held-out `ground_truth.yaml`, a
    captured `.env`). It applies NO path shapes: containment by shape is the caller's job (the
    read tool checks `read_allow`; the bash lane checks the claiming grant's scope)."""
    if run_dir is None or defender_dir is None:
        return False  # no root context to gate against — fail closed
    try:
        rp = Path(path).resolve()
        roots = _resolved_read_roots(policy, run_dir, defender_dir)
    except RESOLVE_ERRORS:
        return False
    if denylisted(rp):
        return False  # a secret / ground-truth file is denied even inside a root
    return any(_is_within(rp, root) for root in roots)


def decide_read(
    path: Path, *, run_dir: Path, defender_dir: Path, policy: AgentPolicy
) -> Decision:
    """Allow/deny a file read — a **deny-by-default allowlist** over the RESOLVED path, the
    shape `decide_write` already uses for writes. Two gates, both necessary:

    1. **the roots** — a read must resolve inside the run dir, the defender corpus
       (`defender_dir`) or, when the policy declares a `read_confine`, that confine set IN
       PLACE of the corpus (the gray-box actor sees only its lesson dirs), plus the agent's
       declared `read_roots` (the judge's comparison dir under the investigation run dir).
       `resolve()` collapses `..` and symlinks, so an allowed-root prefix can't be escaped;
    2. **`policy.read_allow`** — the agent's path SHAPES (#575). This is the same tuple object
       the agent's bash `cat` grant carries as its scope, so the read tool admits exactly the
       paths `cat` does: read↔bash parity by construction, with nothing to keep in sync. This
       is also what makes "main cannot read gather_raw" positive enumeration rather than a
       clamp — the gather_raw shape is simply not in main's list. Empty `read_allow` (every
       non-reader agent) applies no shape filter, leaving the gate root-only.

    On top of both, the declarative secret/ground-truth denylist (`bash_policy.json`) denies a
    sensitive file that lands INSIDE an allowed shape — a captured `.env` in the run dir, the
    eval `cases.json`/`ground_truth.yaml` — cheap belt-and-suspenders applied to every agent.
    A `resolve()` error (a symlink cycle, an embedded NUL) FAILS CLOSED rather than propagating
    out of a blocking gate."""
    p = Path(path)
    try:
        rp = p.resolve()
        roots = _resolved_read_roots(policy, run_dir, defender_dir)
    except RESOLVE_ERRORS:
        return Decision(False, f"Blocked: {p!r} could not be resolved (failing closed).")
    if not any(_is_within(rp, root) for root in roots):
        return Decision(
            False,
            "Blocked: reads are limited to the run dir, the defender corpus (or "
            "this agent's read confine), and its declared roots; "
            f"{p} is outside them.",
        )
    admitted = any(shape.fullmatch(str(rp)) for shape in policy.read_allow)
    # The attacker-influenced channel is OPT-IN, for EVERY agent — including one that declares no
    # shapes at all. An empty `read_allow` means "no shape filter", which is a WIDENING default,
    # and `gather_raw` is the one path class where a widening default is a security failure: the
    # learning loop STAGES the investigation's whole `gather_raw/` tree into the learning run dir
    # (`lead_repository.stage_tables`), and that dir IS the actor's own root — so a root-only read
    # would hand the gray-box actor the very payloads it must write its story WITHOUT seeing.
    # Reading a payload therefore requires a shape that NAMES it (gather's own raw shape; the
    # judge's scope over its comparison roots), never merely a root that happens to contain it.
    # This is the same enumeration everywhere else obeys, applied to the default that would
    # otherwise widen; the reason is the one the model needs (re-dispatch gather), and the e2e
    # deny-tail asserts it as a substring.
    if _names_raw(rp) and not admitted:
        return Decision(False, RAW_DENY_REASON)
    if policy.read_allow and not admitted:
        return Decision(
            False,
            f"Blocked: {rp.name} is not a readable path for this agent — its reads are the "
            "paths it declares (its own run dir + the corpus `.md` under "
            "lessons/skills/examples), and this is not one of them.",
        )
    # Belt-and-suspenders: a secret / ground-truth file INSIDE an allowed shape is still denied
    # (substrings match the filename, dirs match any path component). Shared with the bash
    # operand lane (`bash._in_scope`) so both surfaces agree.
    if denylisted(rp):
        return Decision(False, f"Blocked: {rp.name} is a denied read (secrets / ground truth).")
    return Decision(True)


# The `gather_raw/` path component, and the reason a read of one earns. Both used to live in
# `hooks/block_main_loop_raw_access.py`, a retired `claude -p` PreToolUse script whose OTHER
# mechanism — a `RAW_MARKER in <command text>` substring clamp — this package deliberately does
# NOT implement (see `bash.py`: containment is positive grant enumeration, and the substring scan
# wrongly denied `… | grep gather_raw`, where the word is a search PATTERN, not a path). Only the
# marker and the reason survived that supersession, and this is their sole reader.
RAW_MARKER = "gather_raw"
RAW_DENY_REASON = (
    "Blocked: the main loop must not read gather_raw/. Gather's returned "
    "summary is the authoritative record (defender SKILL §Principles). If a "
    "field you need is missing, re-dispatch gather with a stricter "
    "what_to_summarize — do not Read/Grep/jq the raw payload from the main "
    "loop; that defeats the subagent isolation."
)


def _names_raw(p: Path) -> bool:
    """Whether a resolved path is INSIDE `gather_raw/` — a path COMPONENT test, never a substring
    scan of the whole string. A substring scan is decided by text the path's owner does not
    control: an ancestor dir that merely carries the word (a pytest tmp dir named
    `test_gather_raw_…`, a checkout under `~/gather_raw-notes/`) would tag every file in the tree
    as an attacker-influenced payload. The component is the fact; the substring was a proxy."""
    return RAW_MARKER in p.parts


# The two path components that together name a draft query template:
# `{defender_dir}/skills/gather/queries/{system}/_draft/{verb}.md`.
QUERIES_MARKER = "queries"
DRAFT_MARKER = "_draft"


def _names_query_draft(p: Path) -> bool:
    """Whether a resolved path is a DRAFT query template — inside `_draft/` under the gather query
    catalog. Two path COMPONENTS, for the reason `_names_raw` gives: `_draft` alone would tag any
    file under any dir of that name anywhere in the tree."""
    return QUERIES_MARKER in p.parts and DRAFT_MARKER in p.parts


def is_untrusted_read(path: Path) -> bool:
    """True for reads of attacker-influenced data the caller must SALT-TAG WRAP: the alert
    payload, the raw gather payloads, and a DRAFT query template.

    Keyed on the gather_raw SHAPE, and deliberately kept when the raw *clamp* was deleted
    (#575): the clamp was containment (now positive enumeration), while this is the TRUST
    boundary. gather_raw is the primary attacker-influenced channel — untagging it would leave
    the model unable to tell data from instructions, failing the prompt-injection defense OPEN.
    A deletion of the clamp is not a deletion of the boundary.

    `queries/{system}/_draft/` joins it (#585). A draft is not curated prose: `draft_synthesis`
    mints it from an EXECUTED gather query, and the skeleton it writes embeds the lead's goal text
    and the query body the gather LLM coined *in response to alert data* — attacker-influenced by
    definition, on the same channel as the payload that produced it. `template_search` now returns
    hits from those files, so without this the text would reach the model bare. An ESTABLISHED
    template stays trusted (False): it is the curated corpus gather exists to reuse, and wrapping
    it would teach gather to distrust its own catalog."""
    p = Path(path)
    return p.name == "alert.json" or _names_raw(p) or _names_query_draft(p)


def decide_write(
    path: Path, proposed_text: str = "", *,
    run_dir: Path, defender_dir: Path,
    policy: AgentPolicy,
) -> Decision:
    """Allow/deny a write of `proposed_text` to `path` — a **flat, deny-by-default allowlist**
    (the write twin of `bash_allow`): the RESOLVED path must `fullmatch` one of the agent's
    `policy.write_allow` patterns (the specific paths it declares it may author — the main
    loop's run-dir subtree, the lead author's `defender/skills/**.md`). Empty `write_allow`
    (every read-only / predictor stage) denies all writes. `resolve()` collapses `..`/symlinks
    before the match so a pattern is a true path set, not a string prefix an operand can escape;
    a `resolve()` error (a symlink cycle, or an embedded NUL — `ValueError`, reachable from any
    model-supplied operand) FAILS CLOSED rather than propagating out of the gate.

    `run_dir`/`defender_dir` are REQUIRED run roots — the same shape `decide_read` has always
    had, and REQUIRED rather than optional since #681. A write target must ALSO resolve within
    the agent's read CONTAINMENT — its read roots (`read_confine`/`read_roots`/run dir/
    `defender_dir`) minus the secret/ground-truth denylist (`read_allowed_path`), the
    `write_allow ⊆ read roots` invariant `edit_file` relies on. NOTE this is containment +
    denylist, NOT the full `decide_read` gate: it does not apply the read-side path SHAPES
    (`read_allow`), so a writer whose `write_allow` admits a path its read shapes exclude is not
    additionally blocked here — a writer's declared paths are its own, and MAIN legitimately
    writes run-dir artifacts.

    The roots are threaded by TYPE because the output-structure gate below KEYS on
    `<run_dir>/<name>`: under the former `run_dir: Path | None = None` an omitted kwarg silently
    skipped that whole gate and fell through to `Decision(True)` — a caller could lose a blocking
    gate by forgetting an argument, with no signal (#681). Requiring both moves that failure to
    the call site (a `TypeError`, and a mypy error in CI) where it cannot hide, and retires the
    guard's former dormant-when-omitted mode: the containment check now always runs, a pinned
    no-op for every real writer whose `write_allow` already sits inside its read roots.

    For `investigation.md`, run the structural invlang validator against the
    full proposed text (current on-disk text supplies the append-only baseline);
    any error denies with the validator's messages so the model can fix its
    invlang — the in-process equivalent of the hook's exit-2 feedback.
    """
    path = Path(path)
    try:
        rp = path.resolve()
    except RESOLVE_ERRORS:
        return Decision(False, f"Blocked: {path!r} could not be resolved (failing closed).")
    if not any(pat.fullmatch(str(rp)) for pat in policy.write_allow):
        return Decision(
            False,
            "Blocked: writes are limited to this agent's declared paths "
            f"(its write allowlist); {path} is not one of them.",
        )
    # Defense-in-depth (write ⊆ read roots): the write target must also sit inside the agent's
    # read CONTAINMENT — its read roots minus the secret/ground-truth denylist
    # (`read_allowed_path`), fails closed on a resolve error. This is containment + denylist, NOT
    # the full `decide_read` (the read-side path SHAPES are not applied: a writer's declared paths
    # are its own). A no-op for every real writer (its write_allow already sits within its read
    # roots); it only closes a hypothetical write_allow that escapes them.
    if not read_allowed_path(rp, run_dir=run_dir, defender_dir=defender_dir, policy=policy):
        return Decision(
            False,
            f"Blocked: {path} is outside this agent's read roots — a write must land within the "
            "agent's read containment (write ⊆ read roots).",
        )

    # #629 — the run's two model-authored output artifacts get a structural + volume gate,
    # keyed on the operand RESOLVING to the run-dir ROOT (not `path.name` alone). Resolving
    # first closes the symlink/subdir disguise (a `decoy.md` -> `<run_dir>/report.md` IS
    # gated; a `<run_dir>/sub/report.md` is NOT), and scoping to the run-dir root leaves a
    # same-named lesson in a curator's corpus untouched (the verify_forward forward-check
    # operand — F-A2: gating it would flip its pure-containment allow into a deny).
    # BOTH artifacts key that one way. investigation.md's legacy exact-basename fallback
    # retired with the run_dir-less caller it existed for (#681): the roots are required now,
    # so nothing reaches here without a run root and the fallback was unreachable — while
    # keeping a name-only key would gate a corpus file that merely SHARES the basename, the
    # F-A2 regression above. Resolving still decides for investigation.md too (#631, PBW2D):
    # a symlink `alias.md` resolving to investigation.md clears the allowlist on `rp`, so it
    # must face the same validator the direct write does, or identical text is refused through
    # the real name and admitted through the alias.
    is_report = _is_run_dir_file(rp, run_dir, "report.md")
    is_investigation = _is_run_dir_file(rp, run_dir, "investigation.md")
    if is_report or is_investigation:
        # Both artifact gates measure UTF-8 BYTES (`_utf8_len`) and splice the text into live
        # egresses. Content that is not UTF-8-encodable — a lone surrogate, reachable from a model
        # tool-call JSON arg (`json.loads('"\\ud800"')` yields one) — can be neither byte-measured
        # nor written (`write_text(encoding="utf-8")` raises the SAME error), so deny it FAIL-CLOSED
        # here rather than let `_utf8_len`'s `.encode()` raise out of the gate: the gate's contract
        # is to return a Decision, never propagate (the RESOLVE_ERRORS fail-closed rule above).
        try:
            proposed_text.encode("utf-8")
        except UnicodeEncodeError:
            artifact = "report.md" if is_report else "investigation.md"
            return Decision(
                False,
                f"{artifact} contains bytes that are not valid UTF-8 (e.g. a lone surrogate) — "
                "rewrite it as UTF-8 text and retry.",
            )
    if is_report:
        return _decide_report_write(proposed_text)
    if is_investigation:
        return _decide_investigation_write(proposed_text, rp)
    return Decision(True)


def _is_run_dir_file(rp: Path, run_dir: Path, name: str) -> bool:
    """True iff the RESOLVED operand `rp` is exactly `<run_dir>/<name>` — the run-dir ROOT,
    exact basename, symlinks already collapsed into `rp` by the caller's `resolve()`. `run_dir`
    is resolved here to align with `rp`'s resolution. A `resolve()` error returns False — the
    artifact branch then simply does not fire, and the write stands on the generic allowlist
    decision that already ran above."""
    try:
        return rp == run_dir.resolve() / name
    except RESOLVE_ERRORS:
        return False


def _utf8_len(text: str) -> int:
    """Byte length under UTF-8 — the basis for every #629 bound. A multibyte codepoint costs
    its real transport bytes, so a `len(str)` (codepoint-count) impl would under-count and let
    a body over the byte bound through; the multibyte fixtures pin exactly that."""
    return len(text.encode("utf-8"))


def _has_duplicate_top_level_key(raw: str) -> bool:
    """True iff the frontmatter YAML declares the same top-level key twice. PyYAML's `safe_load`
    silently resolves duplicates last-wins, so a `disposition:` declared twice (a valid member
    shadowing an invalid one) would pass a plain membership check on the parsed mapping — this
    catches it at the node level instead. Returns False on any parse trouble: `raw` already
    parsed once via `split_frontmatter`, so trouble here means no reliable duplicate signal and
    the other checks stand.

    Duplicates are judged on the CONSTRUCTED key — what `safe_load` would put in the mapping —
    not on the raw scalar node text (#681). The node text is the wrong equality: it both
    FALSE-POSITIVES (`1:` and `"1":` are distinct keys to `safe_load`, one int and one str, but
    carry the same `key_node.value` `"1"`) and FALSE-NEGATIVES (`1:` / `0x1:`, `yes:` / `true:`
    construct to the same key from different text, a real last-wins shadowing the raw compare
    would miss). ONE `SafeLoader` — the same class `split_frontmatter` parses under — both
    composes and constructs, so the two readings of "the same key" cannot diverge. That includes
    `flatten_mapping`: `safe_load` expands a `<<:` merge INTO the mapping before building it, so
    a merge-injected key is a real last-wins entry; skipping the flatten would hide exactly the
    shadowing this check exists to catch (`<<: [*a, *b]` where both anchors carry `disposition`
    — the parsed mapping keeps one, the raw text shows two). A key that cannot be constructed or
    compared — an untabled tag, an unhashable list/mapping key, an out-of-range implicit
    timestamp, all of which `safe_load` would have rejected upstream anyway — is skipped rather
    than raised out of this blocking gate."""
    loader = yaml.SafeLoader(raw)
    try:
        try:
            node = loader.get_single_node()
            if not isinstance(node, yaml.MappingNode):
                return False
            loader.flatten_mapping(node)  # `<<:` merges become real top-level pairs
        except (yaml.YAMLError, RecursionError):
            return False
        seen: set[object] = set()
        for key_node, _value_node in node.value:
            try:
                key = loader.construct_object(key_node, deep=True)
                duplicate = key in seen
            except (yaml.YAMLError, RecursionError, TypeError, ValueError):
                continue  # unconstructible / unhashable — no reliable signal for THIS key
            if duplicate:
                return True
            seen.add(key)
        return False
    finally:
        loader.dispose()


def _decide_report_write(proposed_text: str) -> Decision:
    """The report.md output-structure gate (#629). Fail-closed on any of: unparseable
    frontmatter (the one canonical grammar — leading+closing fence, valid YAML, a mapping);
    a missing / duplicated / non-string / out-of-enum top-level `disposition`; a frontmatter
    over 512 B or a whole file over 8,192 B (UTF-8); or a literal `</report>` that would break
    out of the judge's report block. Only `disposition` is required — `case_id`/`confidence`
    are deliberately unvalidated (the ticket path derives case_id from the run dir; confidence
    is untyped everywhere). Each deny carries actionable text the tool lane raises as ModelRetry."""
    try:
        fm, raw, _body = split_frontmatter(proposed_text)
    except FrontmatterError as e:
        return Decision(False, f"report.md frontmatter is malformed — fix and rewrite: {e}")
    if _has_duplicate_top_level_key(raw):
        return Decision(
            False,
            "report.md frontmatter declares a top-level key more than once — remove the "
            "duplicate and rewrite.",
        )
    disposition = fm.get("disposition")
    # `isinstance(str)` FIRST: a non-string value (a list / mapping) is unhashable, so a bare
    # `value in DISPOSITION_ENUM` (a set) would raise TypeError out of the gate instead of denying.
    if not (isinstance(disposition, str) and disposition in DISPOSITION_ENUM):
        return Decision(
            False,
            "report.md frontmatter must carry a top-level `disposition` in "
            f"{sorted(DISPOSITION_ENUM)} (got {disposition!r}) — fix and rewrite.",
        )
    if _utf8_len(raw) > _REPORT_FRONTMATTER_MAX:
        return Decision(
            False,
            f"report.md frontmatter is {_utf8_len(raw)} bytes, over the "
            f"{_REPORT_FRONTMATTER_MAX}-byte limit — trim it and rewrite.",
        )
    if _utf8_len(proposed_text) > _REPORT_FILE_MAX:
        return Decision(
            False,
            f"report.md is {_utf8_len(proposed_text)} bytes, over the "
            f"{_REPORT_FILE_MAX}-byte limit — trim it and rewrite.",
        )
    if _REPORT_CLOSE_DELIMITER in proposed_text:
        return Decision(
            False,
            f"report.md contains the literal {_REPORT_CLOSE_DELIMITER!r} delimiter, which would "
            "break out of the judge's report block — remove it and rewrite.",
        )
    return Decision(True)


def _decide_investigation_write(proposed_text: str, rp: Path) -> Decision:
    """The investigation.md gate: the #629 byte bound FIRST (size-first short-circuit, so an
    over-bound document yields a deterministic SIZE-failure reason without the invlang validator
    ever running on the oversize text), then the pre-existing structural invlang validation
    against the full proposed text (current on-disk text supplies the append-only baseline).
    Empty / whitespace-only text is 0-ish bytes under bound and invlang-empty, so it accepts."""
    if _utf8_len(proposed_text) > _INVESTIGATION_FILE_MAX:
        return Decision(
            False,
            f"investigation.md is {_utf8_len(proposed_text)} bytes, over the "
            f"{_INVESTIGATION_FILE_MAX}-byte limit — trim it and rewrite.",
        )
    current = rp.read_text(encoding="utf-8") if rp.is_file() else None
    # Fail closed on an internal validator error — same as invlang_validate's
    # hook, which exits 2 (block) rather than letting the write through.
    try:
        errors = validate_companion(proposed_text, current)
    except Exception as e:  # noqa: BLE001 — a blocking gate must fail closed
        return Decision(
            False,
            f"investigation.md validation errored — failing closed: {e!r}. "
            "Simplify the invlang and rewrite.",
        )
    if errors:
        return Decision(
            False,
            "investigation.md failed invlang validation — fix and rewrite:\n"
            + "\n".join(f"  - {e}" for e in errors),
        )
    return Decision(True)
