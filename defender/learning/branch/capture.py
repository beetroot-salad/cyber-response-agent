"""The family's base tier, taken from the source run's own capture.

The base world is captured, not authored: its state is whatever the real adapters returned
during the real run, and a sibling is that capture plus a diff. Recording the base from a live
call mid-episode would make it depend on when the estate was asked, so an archived episode's
`ΔO` would not be replayable.

The base file is written once, here, before any sibling forks, and is read-only for the rest of
the run, so parallel siblings never contend for it and no check-then-act race exists for a
captured key.

Not covered: a sibling continuing an investigation asks questions the source never asked. Those
keys have no captured row, each world reads them live, and two worlds can get two answers. Each
such read records a `base` row in the world's own file, so counting them sizes the residual.
"""

from __future__ import annotations

import json
from pathlib import Path

from defender._model import model
from defender._episode_handle import Episode
from defender._episode_paths import LAYOUT
from defender._io import load_json_artifact, read_text_soft
from defender.learning.lead_repository import QueryRow, load_queries_report

from .ledger import CAPTURED, LedgerError, ServedCall, payload_text


@model(frozen=True)
class PrimeReport:
    """What the capture yielded, and what it did not.

    Each skip names a key that will reach the live estate instead of replaying, so the counts
    state the size of the episode's non-deterministic surface.
    """

    primed: int = 0
    duplicates: int = 0
    failed: int = 0
    sentinels: int = 0
    unreadable: int = 0

    @property
    def skipped(self) -> int:
        """Every row the capture held that this episode will not replay.

        Summed here so a new skip class is counted the day it is added.
        """
        return self.duplicates + self.failed + self.sentinels + self.unreadable


def prime_base(source_run_dir: Path, base_path: Path) -> PrimeReport:
    """Write `base_path` from `source_run_dir`'s capture. Once, before any sibling exists.

    The whole capture, not a slice at the branch point. The run dir's evidence is truncated
    because it is what the model may read; the base ledger is what the estate answers from, and
    a post-branch row is only reached if a sibling independently re-asks that question. Slicing
    would cost determinism on exactly those keys.
    """
    # The base is its episode's `served_base` record; a path that is not one is refused.
    base_path = Path(base_path)
    episode = Episode(base_path.parent.parent)
    if base_path != episode.served_base.path:
        raise ValueError(f"{base_path} is not an episode's primed base ({LAYOUT.served_base})")
    # Refuse a second prime: `_absorb` is first-row-wins, so the earlier source's answers would
    # silently stay the estate while `PrimeReport` reported a clean prime. Retrying a
    # partly-failed episode makes this a common path. (The exclusive create below refuses one
    # too; this names the case.)
    if base_path.exists() or base_path.is_symlink():
        raise LedgerError(
            f"{base_path} already holds a primed base — a family's capture is written once, "
            "before any sibling forks, and priming over it merges two runs' estates under "
            "first-row-wins with nothing in the table to tell them apart. Name a fresh "
            "episode id, or remove the episode directory to re-prime it")
    # Through `lead_repository`, the single read surface for the queries table, so this reader
    # cannot disagree with others (e.g. about a string `"0"` exit code).
    rows, table_unreadable = load_queries_report(Path(source_run_dir))
    seen: set[str] = set()
    out: list[dict] = []
    counts = {
        "duplicates": 0, "failed": 0, "sentinels": 0,
        "unreadable": table_unreadable,
    }
    for row in rows:
        call = _captured_call(row, counts)
        if call is None:
            continue
        # First key wins, the same rule the ledger's memo uses.
        if call.key in seen:
            counts["duplicates"] += 1
            continue
        seen.add(call.key)
        out.append(call.row())
    if not out:
        # `branch.validate` already refuses a source with nothing captured, so an empty prime
        # means every row was skipped. Continuing would silently send every key live.
        #
        # The counts name which skip; don't guess. `validate` does not screen `exit_code`, so
        # a source whose every capture errored arrives here with only `failed` set.
        raise LedgerError(
            f"{source_run_dir} primed no base rows — every row in its capture was skipped "
            f"({counts}), so every sibling would read the live estate for every key with "
            "nothing in the record to say so. The counts name which rule skipped them: "
            "`failed` is a non-zero exit, `sentinels` never reached a system, `unreadable` is "
            "a payload this episode could not read back")
    # Written whole by one exclusive create: a reader sees no base or all of it, and a racing
    # second primer is the "already primed" refusal.
    text = "".join(json.dumps(row) + "\n" for row in out)  # lint-jsonl-io: ok — the rows are handed whole to the rooted create  # noqa: E501
    try:
        episode.served_base.create(text)
    except FileExistsError as taken:
        raise LedgerError(
            f"{base_path} already holds a primed base — a family's capture is written once, "
            "before any sibling forks") from taken
    # Named fields, not `**counts`: a field mismatch would raise after the base file is
    # written, leaving the episode id permanently unusable.
    return PrimeReport(
        primed=len(out), duplicates=counts["duplicates"], failed=counts["failed"],
        sentinels=counts["sentinels"], unreadable=counts["unreadable"])


def _captured_call(row: QueryRow, counts: dict) -> ServedCall | None:
    """One capture row as a family-tier `ServedCall`, or `None` with `counts` advanced.

    Successful answers only. The family tier never holds a failure (a live adapter error is
    filed in the world tier as a fault). Priming an error digest would hand it to the applier as
    a successful response; refusing any capture containing an error would make real sources
    unbranchable. So a captured failure is re-attempted live by each world; `PrimeReport.failed`
    sizes that, and an exit of `1` is not an infra code, so it cannot trip the circuit breaker.

    A `QueryRow`, so sentinel detection, `exit_code` coercion and `payload_path` containment are
    `lead_repository`'s. `params` arrives as `{}` when the stored value is not a dict, matching
    what `request_key` does, so primed and live keys agree.
    """
    if row.is_sentinel:
        # A `∅.` row never reached a system; there is no estate answer to replay.
        counts["sentinels"] += 1
        return None
    if row.exit_code != 0:
        counts["failed"] += 1
        return None
    if row.raw_ref is None:
        counts["unreadable"] += 1
        return None
    text = read_text_soft(row.raw_ref)[0]
    if text is None:
        counts["unreadable"] += 1
        return None
    canonical = _canonical_payload(text)
    if canonical is None:
        counts["unreadable"] += 1
        return None
    system, verb = row.system, row.verb
    if not system or not verb:
        counts["unreadable"] += 1
        return None
    return ServedCall(
        system=system, verb=verb, params=row.params,
        payload_text=canonical, source=CAPTURED, world_id=None,
    )


def _canonical_payload(text: str) -> str | None:
    """One captured sidecar re-spelled in the ledger's canonical form, or `None`.

    Re-dumped, never copied: `query_tool` wrote the sidecar without `sort_keys` and the ledger
    canonicalises with it, so copied bytes would never match a live serve's key and every call
    would silently miss the base tier.

    Decoded by `_io.load_json_artifact` so an undecodable sidecar (including one nested deeply
    enough to hit `RecursionError`) counts as unreadable rather than crashing the episode.
    """
    payload, unreadable = load_json_artifact(text)
    return None if unreadable is not None else payload_text(payload)
