"""#1537 (design r3): the one migration after `0020_signin_attempts` adds the cause, parked and request columns and backfills
every row already stored. The revision is found as the one built directly on `0020_signin_attempts`; rows are planted by SQL at
the revision before it (the head store cannot write them), with the texts today's code writes, frozen here."""
from __future__ import annotations

import ast
import datetime as _dt
import itertools
import pathlib
import uuid

import httpx
import pytest

from defender.tests.migrations.test_1214_migrations import _upgrade_to
from defender.tests.support.learning.core._faults1537 import FAULTS
from defender.tests.support.shared import _revisions1485 as revisions
from defender.tests.support.shared._postgres1339 import execute

pytestmark = pytest.mark.postgres

TENANT = "b1537000-0000-4000-8000-000000000001"
CREATED = _dt.datetime(2026, 11, 1, 8, 0, tzinfo=_dt.UTC)
CREDENTIAL = "forge_credential_refused"
PARK = "the forge refused 3 times: "
#: A 422 whose URL (not its status line) holds "403".
STATUS_422 = "Forgejo GET failed: Client error '422 Unprocessable Entity' for url 'https://forge.invalid/api/v1/repos/403/r/pulls/7'"

#: Every fault shape the loop counts, as the park text the real paths wrote for it (the one table in `_faults1537`, which the
#: loop's tests drive through each counting path), and the cause it must backfill to: the cause the live classifier gives it.
FAULT_TEXTS = {f"fault {fault.name} ({path})": (fault.park_text(path).replace("{tenant}", TENANT).replace("{file}", "/srv/secrets/g1"),
                                                fault.cause)
               for fault in FAULTS for path in fault.texts}

#: (reason as stored today, parked-batch cause it backfills to)
PARKED = {
    **FAULT_TEXTS,
    "422 with 403 in its url": (PARK + STATUS_422, "forge_refused"),
    # The repository itself answering 404 is the token not seeing it, as the live classifier reads it (#1558 review).
    "the repository itself 404": (PARK + "the tenant t's delivery refused: Forgejo GET failed: Client error '404 Not Found' "
                                  "for url 'http://forge.invalid/api/v1/repos/tenants/fixture' For more information check: "
                                  "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/404", "forge_credential_refused"),
    "a PR's reviews 404": (PARK + "Forgejo GET failed: Client error '404 Not Found' for url 'http://forge.invalid/api/v1/"
                           "repos/tenants/fixture/pulls/7/reviews?page=1&limit=50' For more information check: "
                           "https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/404", "forge_refused"),
    "foreign tip on the forge": ("the branch lessons/ab12 on the forge holds commits the commit-maker did not make for batch "
                                 "b1 (tip abc123)", "foreign_commits_remote"),
    "foreign local commits": ("the local branch lessons/ab12 holds commits outside batch b1's record", "foreign_commits_local"),
    "foreign pr": ("an open PR on lessons/ that no batch made holds the lane: #5 (lessons/other)", "foreign_pr"),
    "model text": ("the batch looked odd to the curator", "unrecorded"),
    "no reason": (None, "unrecorded"),
}
ENDED_ABANDONED = {
    "no commits": ("no commits", "no_commits"), "stopped": ("stopped", "stopped"),
    "crashed": ("its holder crashed", "holder_crashed"), "lost": ("its holder was lost", "holder_lost"),
    # A batch's cause is why it was parked, never who ended it (the live settle keeps the park cause): a person's abandon
    # before #1537 overwrote that text, so there is no park cause left to give.
    "person": ("abandoned by a person", "unrecorded"), "text": ("something a person typed", "unrecorded"),
    "none": (None, "unrecorded"),
}
#: (status, reason as stored today, cause) of items
ITEMS = {
    "held attempts": ("held", "reached the attempt ceiling (5)", "attempt_ceiling"),
    "held person": ("held", "abandoned by a person", "abandoned_by_person"),
    "held replacement nothing": ("held", "the replacement committed nothing", "replacement_committed_nothing"),
    "held replacement ceiling": ("held", "feedback reached the replacement ceiling (3 replacement PRs)", "replacement_ceiling"),
    "held closed": ("held", "PR #3 of batch b1 was closed with no feedback: held for a person", "closed_without_feedback"),
    "held cut": ("held", "cited at the branch tip, not in PR #3's merge", "cut_from_merge"),
    "dead declined": ("dead", "declined by the curator 5 times", "declined_ceiling"),
    "dead deferred": ("dead", "deferred 5 times", "deferral_ceiling"),
    "skipped superseded": ("skipped", "superseded by a later run", "superseded"),
    "skipped superseded by run": ("skipped", "superseded by run r-2", "superseded"),
    "dead artifact missing": ("dead", "artifact-missing", "artifact_missing"),
    "dead row without a value": ("dead", "row carries no value under 'finding_id'", "malformed_row"),
    "dead pitfall row without an id": ("dead", "row carries no value under 'pitfall_id'", "malformed_row"),
    "skipped consumed no systems": ("skipped", "consumed_no_systems: the world finding names no systems", "consumed_no_systems"),
    "skipped declined at the gate": ("skipped", "declined at the gate", "declined_at_gate"),
    "skipped no system": ("skipped", "no-system", "unteachable_system"),
    "skipped malformed system": ("skipped", "malformed-system", "unteachable_system"),
    "skipped undeclared system": ("skipped", "undeclared-system:elastik", "unteachable_system"),
    "held by the curator's default": ("held", "held by the curator", "curator_held"),
    "held model text": ("held", "this finding is not about the alert", "unrecorded"),
    "held no reason": ("held", None, "unrecorded"),
    "waiting stale reason": ("waiting", "reached the attempt ceiling (5)", None),
    "published stale reason": ("published", "held for a person", None),
}


def _after_ticket_write() -> str:
    """The one revision built directly on `0021_ticket_write` (#1471's, merged first)."""
    base = revisions.by_suffix("_ticket_write")
    [child] = [r.revision for r in revisions.scripts().walk_revisions() if r.down_revision == base]
    return child


def _tenant(dsn: str) -> None:
    execute(dsn, "INSERT INTO tenancy.tenants (id, created_at, state, pending_action, step, step_actor, failure) "
                 "VALUES (%s, %s, 'active', NULL, NULL, NULL, NULL)", (TENANT, CREATED))


def _batch(dsn: str, *, kind: str, lane: str, phase: str, outcome: str | None = None, reason: str | None = None,
           pr: int | None = None) -> str:
    batch = str(uuid.uuid4())
    execute(dsn, """INSERT INTO learning.batches (id, tenant_id, kind, lane, branch, phase, outcome, fencing_token,
        cancel_requested, pr_number, generation, refusals, reason, created_at, ended_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, 2, false, %s, 0, 3, %s, %s, %s)""",
            (batch, TENANT, kind, lane, f"lessons/{batch[:8]}", phase, outcome, pr, reason, CREATED,
             CREATED if phase == "ended" else None))
    return batch


def _item(dsn: str, key: str, status: str, reason: str | None) -> None:
    execute(dsn, """INSERT INTO learning.work_items (tenant_id, kind, id, item_key, payload, status, reason, attempts,
        deferrals, offers_declined, enqueued_at, updated_at) VALUES (%s, 'finding', %s, %s, '{}', %s, %s, 1, 0, 0, %s, %s)""",
            (TENANT, str(uuid.uuid4()), key, status, reason, CREATED, CREATED))


def backfilled_batch_cause(dsn: str, reason: str) -> str | None:
    """The cause the migration gives a parked batch whose stored reason is `reason`: planted at the revision before it, upgraded, read."""
    _upgrade_to(dsn, revisions.down_of(_after_ticket_write()))
    _tenant(dsn)
    batch = _batch(dsn, kind="revert", lane="author", phase="needs_person", reason=reason)
    _upgrade_to(dsn, _after_ticket_write())
    [(cause,)] = execute(dsn, "SELECT cause FROM learning.batches WHERE id = %s", (batch,))
    return cause


@pytest.fixture
def planted(empty_database):
    """The database at the revision before the migration, holding a row for each text above."""
    dsn = empty_database
    _upgrade_to(dsn, revisions.down_of(_after_ticket_write()))
    _tenant(dsn)
    rows: dict[str, tuple[str, str | None]] = {}
    for name, (reason, want) in PARKED.items():
        rows[f"parked: {name}"] = (_batch(dsn, kind="revert", lane="author", phase="needs_person", reason=reason), want)
    for name, (reason, want) in ENDED_ABANDONED.items():
        rows[f"abandoned: {name}"] = (_batch(dsn, kind="revert", lane="author", phase="ended", outcome="abandoned", reason=reason), want)
    rows["merged with a reason"] = (_batch(dsn, kind="revert", lane="author", phase="ended", outcome="merged",
                                           reason="cited at the branch tip, not in PR #3's merge", pr=3), None)
    rows["closed with a reason"] = (_batch(dsn, kind="revert", lane="author", phase="ended", outcome="closed",
                                           reason="revert PR #4 closed unmerged", pr=4), None)
    rows["in review"] = (_batch(dsn, kind="revert", lane="author", phase="in_review", pr=5), None)
    for name, (status, reason, _cause) in ITEMS.items():
        _item(dsn, name, status, reason)
    return dsn, rows


def test_the_migration_is_the_one_revision_after_0021_and_the_head_is_not_behind_it():
    """Exactly one revision sits on `0021_ticket_write`, and it is an ancestor of the head. (Data)"""
    child = _after_ticket_write()
    heads = revisions.scripts().get_heads()
    assert len(heads) == 1
    assert child in revisions.ancestors(heads[0])


def test_the_backfill_gives_every_batch_the_cause_its_frozen_text_names_and_unmatched_text_is_unrecorded(planted):
    """Each stored batch reason maps to its cause (every fault shape of the loop's one table: a 401 or 403 in the status line or a credential failure at delivery open is `forge_credential_refused`, another status `forge_refused`, a misconfigured credential or missing forge wiring `delivery_unavailable`; a 403 elsewhere in the text is not), unmatched or missing text `unrecorded`; merged, closed and in-review batches get none. (Data backfill, PR1)"""
    dsn, rows = planted
    _upgrade_to(dsn, _after_ticket_write())
    got = {name: execute(dsn, "SELECT cause FROM learning.batches WHERE id = %s", (batch,))[0][0] for name, (batch, _w) in rows.items()}
    assert got == {name: want for name, (_b, want) in rows.items()}


def test_the_backfill_gives_every_held_dead_and_skipped_item_its_cause_and_the_rest_none(planted):
    """Each stored item reason maps to its cause; unmatched or missing reasons are `unrecorded`; a waiting or published item has none. (Data backfill, PR1)"""
    dsn, _rows = planted
    _upgrade_to(dsn, _after_ticket_write())
    got = dict(execute(dsn, "SELECT item_key, cause FROM learning.work_items WHERE tenant_id = %s", (TENANT,)))
    assert got == {name: cause for name, (_s, _r, cause) in ITEMS.items()}


def test_the_backfill_leaves_parked_at_and_the_request_empty_and_keeps_every_reason_as_the_detail(planted):
    """Already-parked batches get `parked_at` NULL (the screen falls back to `created_at`); no batch has a request; reasons are untouched. (Data backfill, O5)"""
    dsn, _rows = planted
    before = execute(dsn, "SELECT id, reason FROM learning.batches ORDER BY id")
    items_before = execute(dsn, "SELECT item_key, status FROM learning.work_items ORDER BY item_key")
    _upgrade_to(dsn, _after_ticket_write())
    assert execute(dsn, "SELECT count(*) FROM learning.batches WHERE parked_at IS NOT NULL OR abandon_requested_at IS NOT NULL "
                        "OR abandon_requested_by IS NOT NULL") == [(0,)]
    assert execute(dsn, "SELECT id, reason FROM learning.batches ORDER BY id") == before
    assert execute(dsn, "SELECT item_key, status FROM learning.work_items ORDER BY item_key") == items_before


def test_the_upgraded_database_carries_the_new_columns_as_nullable_text_and_timestamps(migrated_database):
    """`cause` on both tables, `parked_at`, `abandon_requested_at` (timestamptz) and `abandon_requested_by` (text) exist and are nullable. (Data)"""
    got = {(t, c): (ty, n) for t, c, ty, n in execute(migrated_database, """SELECT table_name, column_name, data_type, is_nullable
        FROM information_schema.columns WHERE table_schema = 'learning' AND (table_name, column_name) IN
        (('work_items', 'cause'), ('batches', 'cause'), ('batches', 'parked_at'), ('batches', 'abandon_requested_at'),
         ('batches', 'abandon_requested_by'))""")}
    assert got == {("work_items", "cause"): ("text", "YES"), ("batches", "cause"): ("text", "YES"),
                   ("batches", "parked_at"): ("timestamp with time zone", "YES"),
                   ("batches", "abandon_requested_at"): ("timestamp with time zone", "YES"),
                   ("batches", "abandon_requested_by"): ("text", "YES")}


# --- the census of credential-shaped refusal texts: the live classifier and the backfill agree on every one ----------------------------

_SOURCE_ROOT = pathlib.Path(__file__).resolve().parents[2]
#: Every file that raises the credential refusals a tenant's delivery meets.
_RAISERS = sorted((_SOURCE_ROOT / "learning" / "author" / "version_control").glob("*.py")) + [_SOURCE_ROOT / "tenancy" / "_approle_login.py"]
#: The exception classes the census covers, and the login errors whose texts they wrap (`the issuer AppRole login failed: ...`).
_CENSUS = {"ForgejoAuthError", "CredentialMisconfigured", "LoginUnrecorded", "SecretFileUnusable"}
_WRAPPED = {"CleartextAddress", "LoginUnreachable", "LoginRefused"}
#: What each f-string placeholder of those raise sites stands for in a stored text (a census that meets another fails, naming it).
_SAMPLES = {
    "tenant_id": [TENANT], "self.tenant_id": [TENANT], "pair.name": ["delivery"], "path": ["/srv/secrets/g1"],
    "ca": ["/etc/ssl/ca.pem"], "type(bad).__name__": ["SSLError"], "type(down).__name__": ["ConnectError"],
    "unreadable.strerror or type(unreadable).__name__": ["No such file or directory"], "self.purpose": ["drain"],
    "response.status_code": ["401", "403", "404"],
}


def _sites(*names: str) -> list[tuple[str, str, ast.expr | None]]:
    """`(where, class name, first argument)` of every `raise <name>(...)` in the files that raise them."""
    found = []
    for path in _RAISERS:
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if isinstance(node, ast.Raise) and isinstance(node.exc, ast.Call):
                name = ast.unparse(node.exc.func).rsplit(".", 1)[-1]
                if name in names:
                    found.append((f"{path.name}:{node.lineno}", name, node.exc.args[0] if node.exc.args else None))
    return found


def _renders(where: str, node: ast.expr | None, wrapped: dict[str, list[str]]) -> list[str]:
    """The texts a raise site's message takes: its constant words, with each placeholder replaced by its samples."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return [node.value]
    if isinstance(node, ast.JoinedStr):
        options = []
        for part in node.values:
            if isinstance(part, ast.Constant):
                options.append([str(part.value)])
                continue
            key = ast.unparse(part.value)
            assert key in {**_SAMPLES, **wrapped}, f"{where}: the census has no sample for {{{key}}}: add one to _SAMPLES"
            options.append({**_SAMPLES, **wrapped}[key])
        return ["".join(parts) for parts in itertools.product(*options)]
    if isinstance(node, ast.Call) and ast.unparse(node.func) == "str" and ast.unparse(node.args[0]) in wrapped:
        return wrapped[ast.unparse(node.args[0])]
    raise AssertionError(f"{where}: the census cannot render {ast.unparse(node) if node else 'no message'}")


def _status_error(status: int) -> httpx.HTTPStatusError:
    request = httpx.Request("GET", "https://openbao.test/v1/identity/oidc/token/role")
    return httpx.HTTPStatusError("refused", request=request, response=httpx.Response(status, request=request))


def _login_failures() -> list[BaseException]:
    """The login errors an issuer login wraps (`the issuer AppRole login failed: ...`), built as `approle_login` raises them: a
    refused login carries its HTTP status and the `HTTPStatusError` it was made from, an answer with no client token carries 200."""
    from defender import tenancy

    failures: list[BaseException] = []
    for where, name, arg in _sites(*_WRAPPED):
        for text in _renders(where, arg, {}):
            if name != "LoginRefused":
                failures.append(getattr(tenancy, name)(text))
                continue
            status = int(text.rsplit("HTTP ", 1)[1].rstrip(")")) if "(HTTP " in text else 200
            refused = tenancy.LoginRefused(text, status)
            if "(HTTP " in text:
                refused.__cause__ = _status_error(status)
            failures.append(refused)
    return failures


def _met(where: str, name: str, arg: ast.expr | None, wrapped: dict[str, list[str]], failures: list[BaseException]) -> list[tuple[str, BaseException]]:
    """The exceptions the delivery's open meets from one raise site, chained as the code chains them."""
    from defender.learning.author.version_control import ForgejoAuthError
    from defender.learning.author.version_control.auth import CredentialMisconfigured

    out: list[tuple[str, BaseException]] = []
    for text in _renders(where, arg, wrapped):
        if name in {"LoginUnrecorded", "SecretFileUnusable"}:  # met as the credential wraps it: `raise CredentialMisconfigured(str(unusable)) from None`
            out.append((f"{where} {name}: {text}", CredentialMisconfigured(text)))
        elif "{failed}" in ast.unparse(arg):
            error = ForgejoAuthError(text)
            error.__cause__ = failures[wrapped["failed"].index(text.split("login failed: ", 1)[1])]
            out.append((f"{where} {text}", error))
        elif text == "Vault identity token request failed":  # `from e`: the issuer's HTTP answer, or a body that is not JSON
            for cause in (_status_error(401), _status_error(403), ValueError("not json")):
                error = ForgejoAuthError(text)
                error.__cause__ = cause
                out.append((f"{where} {text} after {type(cause).__name__} {getattr(getattr(cause, 'response', None), 'status_code', '')}", error))
        else:
            out.append((f"{where} {name}: {text}", (CredentialMisconfigured if name == "CredentialMisconfigured" else ForgejoAuthError)(text)))
    return out


def _refusals() -> list[tuple[str, BaseException]]:
    """Every credential refusal the delivery's open can meet, built as the code builds it: `(label, exception)`."""
    failures = _login_failures()
    wrapped = {"failed": [str(f) for f in failures],
               "unusable": [t for where, _n, arg in _sites("LoginUnrecorded", "SecretFileUnusable") for t in _renders(where, arg, {})]}
    return [met for where, name, arg in _sites(*_CENSUS) for met in _met(where, name, arg, wrapped, failures)]


def test_every_credential_refusal_text_the_code_can_raise_is_given_one_cause_by_the_live_classifier_and_the_backfill_alike(empty_database):
    """Each text a `ForgejoAuthError`, `CredentialMisconfigured`, `LoginUnrecorded` or `SecretFileUnusable` raise site can carry (read off the source, the real exceptions built as the code builds and chains them, met as the delivery's open wraps them and as three refusals park the batch) is given a cause by the live classifier, the same cause by the migration's backfill of the stored park text, and never `unrecorded`. (PR1, classifier, Data backfill)"""
    from defender._text import one_line
    from defender.learning.core.store_tick import FAULT_TEXT_LIMIT, classified_refusal, refusal_cause

    built = _refusals()
    assert len(built) > 25, f"the census found only {len(built)} texts: the raise sites moved"
    live: dict[str, tuple[str, str]] = {}
    for label, error in built:
        refused = classified_refusal(f"the tenant {TENANT}'s delivery refused: {error}", error)
        assert refused.transient is False, f"{label}: a refusal the loop counts is not an outage"
        live[label] = (refusal_cause(refused), PARK + one_line(str(refused))[:FAULT_TEXT_LIMIT])

    dsn = empty_database
    _upgrade_to(dsn, revisions.down_of(_after_ticket_write()))
    _tenant(dsn)
    planted = {label: _batch(dsn, kind="revert", lane="author", phase="needs_person", reason=text) for label, (_c, text) in live.items()}
    _upgrade_to(dsn, _after_ticket_write())
    got = {label: execute(dsn, "SELECT cause FROM learning.batches WHERE id = %s", (batch,))[0][0] for label, batch in planted.items()}
    assert {label: cause for label, (cause, _t) in live.items() if cause == "unrecorded"} == {}
    disagree = {label: (live[label][0], got[label]) for label in live if got[label] != live[label][0]}
    assert disagree == {}, "(live classifier, backfill) differ for these texts"
