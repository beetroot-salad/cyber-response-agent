"""The content schema for the run's two model-authored artifacts.

`report.md` and `investigation.md` are the only files a model authors that leave the
system: the report and investigation ride verbatim into the judge LLM prompt, and the
report body into the ticket bridge's HTTP egress. This module owns what a well-formed one
IS — the report's frontmatter grammar, its `disposition` enum, the UTF-8 byte bounds on
both, and the investigation's invlang structure.

It owns NO authorization. Who may write where is `runtime/permission/files.py`'s job (the
`write_allow` allowlist, the `write ⊆ read roots` containment check, and the resolve-then-key
decision that picks which artifact a path IS); this module is called only after those gates
have already said yes, and it never sees a policy, a run dir, or a path.

Every entry point returns `str | None` — the deny reason, or `None` for "well-formed" —
deliberately NOT a `permission.Decision`. `Decision` is authorization vocabulary, and
keeping it out is what lets this module sit as a neutral leaf: the permission gate imports
it, and so can the learning loop's read-side validators, without either importing the other
(#714). The gate wraps a returned reason back into `Decision(False, reason)`, so the deny
text the model sees as ModelRetry is unchanged.
"""

from __future__ import annotations

import yaml

from defender._frontmatter import FrontmatterError, split_frontmatter
# Imported to be USED, not to be passed on. The vocabulary reached this module from the
# learning loop's config (#714, to break a `runtime/` → `learning/` import inside a security
# boundary) and left it for `_vocab.py` once invlang's `conclude` block turned out to carry the
# same headline. It briefly stayed re-exported so the loop's config and the ticket builder
# could keep importing it from here; that put a schema module in the path between a vocabulary
# and its readers for no reason other than history, so those two now import the owner directly.
# The normalizer is deliberately NOT imported here: this module holds the WRITE gate, and on
# write the value is tested exactly — see the disposition check in `validate_report` below.
from defender._vocab import DISPOSITION_ENUM
from defender.skills.invlang.validate import Diagnostic, diagnose, warn_diagnostics

# #629 — output-structure bounds for the run's two model-authored artifacts, all in
# UTF-8 BYTES. These are a VOLUME + STRUCTURE control on bytes that leave the system
# (the report/investigation ride verbatim into the judge LLM prompt, and the report
# body into the ticket bridge's HTTP egress) — not a content oracle: an in-bound,
# well-formed payload still passes. Values are policy inputs decided in the #629
# intent+design doc (report frontmatter 512 B / whole file 8 KiB; investigation 64 KiB).
REPORT_FRONTMATTER_MAX = 512
REPORT_FILE_MAX = 8192
INVESTIGATION_FILE_MAX = 65536

# Preserve #629's fail-closed output-structure policy for the legacy report delimiter.
# The judge now places report bytes inside an invocation-salted frame via
# defender._untrusted.wrap, but accepting the formerly forbidden sequence would loosen
# the report contract independently of that prompt-layer hardening.
REPORT_CLOSE_DELIMITER = "</report>"

REPORT_NAME = "report.md"
INVESTIGATION_NAME = "investigation.md"

# The artifacts this module has a schema for. The gate iterates this to decide whether a
# resolved write target is a gated artifact at all, so adding a third one is a change HERE
# rather than a new branch in `decide_write`.
ARTIFACT_NAMES = (REPORT_NAME, INVESTIGATION_NAME)

# Which artifacts need the CURRENT on-disk text as a baseline. Only invlang does (it is
# append-only, so validation is against the document's history, not the text alone). The
# gate reads the baseline and passes it in — this module does no filesystem access — and
# it must read for THESE names only: an unconditional read would put a `read_text` that can
# raise on the report.md path, where none ran before.
NEEDS_BASELINE = frozenset({INVESTIGATION_NAME})


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


def encodable_or_reason(proposed_text: str, artifact: str) -> str | None:
    """Deny text that is not UTF-8-encodable, BEFORE either artifact's own schema runs.

    Both artifact schemas measure UTF-8 BYTES (`_utf8_len`) and their text splices into live
    egresses. Content that is not UTF-8-encodable — a lone surrogate, reachable from a model
    tool-call JSON arg (`json.loads('"\\ud800"')` yields one) — can be neither byte-measured
    nor written (`write_text(encoding="utf-8")` raises the SAME error), so it is denied
    FAIL-CLOSED here rather than letting `_utf8_len`'s `.encode()` raise out of the gate: the
    gate's contract is to return a Decision, never propagate (its RESOLVE_ERRORS rule)."""
    try:
        proposed_text.encode("utf-8")
    except UnicodeEncodeError:
        return (
            f"{artifact} contains bytes that are not valid UTF-8 (e.g. a lone surrogate) — "
            "rewrite it as UTF-8 text and retry."
        )
    return None


def validate_report(proposed_text: str) -> str | None:
    """The report.md output-structure schema (#629). Fail-closed on any of: unparseable
    frontmatter (the one canonical grammar — leading+closing fence, valid YAML, a mapping);
    a missing / duplicated / non-string / out-of-enum top-level `disposition`; a frontmatter
    over 512 B or a whole file over 8,192 B (UTF-8); or a literal `</report>` that would break
    out of the judge's report block. Only `disposition` is required — `case_id`/`confidence`
    are deliberately unvalidated (the ticket path derives case_id from the run dir; confidence
    is untyped everywhere). Each reason is actionable text the tool lane raises as ModelRetry."""
    try:
        fm, raw, _body = split_frontmatter(proposed_text)
    except FrontmatterError as e:
        return f"report.md frontmatter is malformed — fix and rewrite: {e}"
    if _has_duplicate_top_level_key(raw):
        return (
            "report.md frontmatter declares a top-level key more than once — remove the "
            "duplicate and rewrite."
        )
    disposition = fm.get("disposition")
    # `isinstance(str)` FIRST: a non-string value (a list / mapping) is unhashable, so a bare
    # `value in DISPOSITION_ENUM` (a set) would raise TypeError out of the gate instead of denying.
    #
    # lint-vocabulary: ok — the WRITE gate is exact where every reader normalizes, and the
    # asymmetry is the point. Here there is still an author to ask: an exact test denies a
    # zero-width-laced disposition with retry text the model can act on. `normalized_disposition`
    # would silently ACCEPT it and write a document no reader can tell from a clean one.
    if not (isinstance(disposition, str) and disposition in DISPOSITION_ENUM):
        return (
            "report.md frontmatter must carry a top-level `disposition` in "
            f"{sorted(DISPOSITION_ENUM)} (got {disposition!r}) — fix and rewrite."
        )
    if _utf8_len(raw) > REPORT_FRONTMATTER_MAX:
        return (
            f"report.md frontmatter is {_utf8_len(raw)} bytes, over the "
            f"{REPORT_FRONTMATTER_MAX}-byte limit — trim it and rewrite."
        )
    if _utf8_len(proposed_text) > REPORT_FILE_MAX:
        return (
            f"report.md is {_utf8_len(proposed_text)} bytes, over the "
            f"{REPORT_FILE_MAX}-byte limit — trim it and rewrite."
        )
    if REPORT_CLOSE_DELIMITER in proposed_text:
        return (
            f"report.md contains the literal {REPORT_CLOSE_DELIMITER!r} delimiter, which would "
            "break out of the judge's report block — remove it and rewrite."
        )
    return None


#: Every refusal on this artifact carries it (#810). The model is told its own context IS the
#: file (`SKILL.md`, "Re-sync, don't re-read"), so the refusal text is a primary signal about
#: what is on disk — and the old "fix and rewrite" wording implied the opposite of the truth.
#: A model that believes a refused block landed then anchors its next edit to text that was
#: never written, which is where six of the recovery failures measured on #810 came from.
#: The notice's leading fragment, minted separately because #836 adds refusal paths that have
#: no proposed text of their own — a refused CLOSE never offered any bytes, so "does not
#: contain your text" would be a claim about nothing. Every new refusal LEADS with this, and
#: an ACCEPT leads with its byte count instead: the model tells the two apart by the first
#: sentence, which is what stops a warning from being read as a refusal and re-emitted.
UNCHANGED_LEAD = "No changes were made"

UNCHANGED_NOTICE = (
    f"{UNCHANGED_LEAD} — the file on disk is unchanged and does not contain your text."
)


def render_diagnostic(d: Diagnostic) -> str:
    """One diagnostic as the model sees it. The message leads and is unchanged from before
    #810; the locus and the corrections are additive lines beneath it, so a diagnostic that
    carries neither renders exactly as it always did.

    The row is suppressed when the message already contains it — a parse warning's
    `format()` embeds `row=...`, and repeating it would be noise rather than help. That
    embedding is a `repr()`, so the raw-substring test alone misses any row carrying a
    backslash or a quote; both spellings are checked. A row past `format()`'s 200-char
    truncation matches NEITHER, and is printed whole, which is the point of the line.

    MODULE-PUBLIC since #836. It was private to the DENY path, which is exactly why the
    accept path had no channel to show a warning through: a warn-only document makes this
    module return no text at all, so the tool bodies re-derive and render through this one
    renderer rather than growing a second, drifting spelling of the same three lines."""
    lines = [f"  - {d.message}"]
    if d.locus is not None and not (
        d.locus.row_text in d.message or repr(d.locus.row_text) in d.message
    ):
        lines.append(f"    row: {d.locus.row_text}")
    if d.fix:
        lines.append(f"    use: {d.fix[0]}")
        lines.extend(f"         {alt}" for alt in d.fix[1:])
    return "\n".join(lines)


def _warns_quietly(current: str) -> bool:
    """Is a row flagged on the ON-DISK document? Answered for one purpose only: picking which
    REMEDY the size refusal names.

    It swallows a validator error rather than propagating it, because the branch that asks is
    the one branch of this gate that has already decided its verdict — the write is denied
    either way, and letting `diagnose` raise out of `validate_investigation` here would escape
    the module's own fail-closed contract and take the tool call down instead of denying it."""
    try:
        return bool(warn_diagnostics(current))
    except Exception:  # noqa: BLE001 — a prose choice must not decide the gate's control flow
        return False


def validate_investigation(proposed_text: str, current: str | None) -> str | None:
    """The investigation.md schema: the #629 byte bound FIRST (size-first short-circuit, so an
    over-bound document yields a deterministic SIZE-failure reason without the invlang validator
    ever running on the oversize text), then the pre-existing structural invlang validation
    against the full proposed text (`current`, the caller-supplied on-disk text, supplies the
    append-only baseline). Empty / whitespace-only text is 0-ish bytes under bound and
    invlang-empty, so it accepts.

    Every refusing branch states that nothing was written (#810). This module owns the
    rendering; `skills.invlang.validate` owns the finding — hence `diagnose` here rather than
    the `validate_companion` string surface.

    WARN-severity findings do not refuse (#836). They are not returned through this surface at
    all — the `str | None` contract is unchanged, and the window is DERIVED by the tool bodies
    rather than carried out of the gate."""
    if _utf8_len(proposed_text) > INVESTIGATION_FILE_MAX:
        # The size is the WHOLE document, and since #810 the only writer APPENDS to it — so
        # "trim it and re-send" is advice the model cannot always take: once what is already
        # committed fills the bound, no block is small enough and nothing can shrink the file.
        # Name the on-disk share so the model can tell "send less" from "you are out of room".
        on_disk = _utf8_len(current) if current is not None else 0
        # #836: with a row flagged, "close the investigation" is a verb the M5 gate refuses —
        # the remedy would name the one move the model cannot make. `fix_row(old, "")` is the
        # escape that actually shrinks the document, and it is available exactly here.
        if on_disk and current is not None and _warns_quietly(current):
            remedy = (
                f"{on_disk} of those bytes are already committed and cannot be removed, and a "
                "flagged row is blocking the close — repair or delete it with "
                '`fix_row(old_row, "")`, then send a smaller block.'
            )
        elif on_disk:
            remedy = (
                f"{on_disk} of those bytes are already committed and cannot be removed — send a "
                "smaller block, or close the investigation on the evidence you already have."
            )
        else:
            remedy = "Trim it and re-send."
        return (
            f"investigation.md is {_utf8_len(proposed_text)} bytes, over the "
            f"{INVESTIGATION_FILE_MAX}-byte limit. {UNCHANGED_NOTICE} {remedy}"
        )
    # Fail closed on an internal validator error — same as invlang_validate's
    # hook, which exits 2 (block) rather than letting the write through.
    try:
        found = diagnose(proposed_text, current)
    except Exception as e:  # noqa: BLE001 — a blocking gate must fail closed
        return (
            f"investigation.md validation errored — failing closed: {e!r}. "
            f"{UNCHANGED_NOTICE} Simplify the invlang and re-send."
        )
    errors = [d for d in found if d.severity != "warning"]
    if errors:
        return (
            f"investigation.md failed invlang validation. {UNCHANGED_NOTICE}\n\n"
            + "\n".join(render_diagnostic(d) for d in errors)
            + "\n\nRe-send the block with those rows corrected."
        )
    return None


def validate_artifact(name: str, proposed_text: str, current: str | None) -> str | None:
    """Validate `proposed_text` as the artifact `name` (one of `ARTIFACT_NAMES`), returning the
    deny reason or `None`. The UTF-8-encodability check runs for BOTH artifacts before either
    schema, because both measure bytes. `current` is the on-disk baseline, required for the
    artifacts in `NEEDS_BASELINE` and ignored for the rest. An unknown `name` is a caller bug —
    the gate only calls with a name it took from `ARTIFACT_NAMES` — and raises rather than
    silently accepting, so a third artifact added to the tuple without a schema cannot ship as
    a permanently-allowed write."""
    reason = encodable_or_reason(proposed_text, name)
    if reason is not None:
        return reason
    if name == REPORT_NAME:
        return validate_report(proposed_text)
    if name == INVESTIGATION_NAME:
        return validate_investigation(proposed_text, current)
    raise ValueError(f"no content schema for artifact {name!r}")
