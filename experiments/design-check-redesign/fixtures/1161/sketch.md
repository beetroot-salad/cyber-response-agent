# #1161 piece 1 — sketch (write-tests §2)

Base `bdc39ca80`, design r8 + Am-1. Uncommitted, in `/workspace/.worktrees/1161-tests`.

## Files

- `defender/tests/api/test_1083_real_server.py` — appended `test_1161_*` (API level, in-process over `served`).
- `defender/tests/support/api/_server1083.py` — CONFLICT (flag for review): `environment()`'s
  `DEFENDER_KEYCLOAK_REDIRECT_URI` → `{ORIGIN}/api/auth/callback` (B3 moves it).
- `defender/tests/support/api/_signin1161.py` — new, test-only: `authorize()` (the front channel's redirect),
  `exchange`/`exchanging()` (the code grant on FakeKeycloak's sign-in token step, self-describing codes),
  `link_account()`, `set_cookies()`/`deleted()`, `child()` (the program over an exchanging fake, issuers on a given
  front), `FrontChannel` (loopback authorize server, with hold/release).
- `defender/tests/support/frontend/_ingress1161.py` — new, test-only: `build()` (npm), `ingress()` (Caddy with
  the repo's Caddyfile).
- `defender/tests/frontend/{conftest.py,test_1161_browser.py}` — new: Playwright + Caddy + `Child`. New directory
  because no existing file covers the browser/ingress surface; piece 2's O7 joins it. Sync Playwright cannot share
  the anyio-marked real-server module.
- `defender/tests/jobs/test_job_entry.py` — appended B6 job-lane case.
- `defender/tests/tenancy/case_comment_1359/test_record_leg.py` — appended B6 operator case.

## Case table

| # | Obligation | Condition | Action | Observation (boundary) | Expected | Wrong impl rejected | Node |
|---|---|---|---|---|---|---|---|
| 1 | P2, B1 | accepted return: ticket path+query; path with `.`,`;`,`,`,`=`,`%20`; exactly 1024 B; `/` | `GET /api/auth/login?return=P` → front channel → callback with its cookie | callback 303 `Location` (resolved on ORIGIN), session works on `/api/me` | lands exactly at P | always root; truncates at `.`/`;`; drops query; 1023-byte cap | `api/test_1083_real_server.py::test_1161_p2_sign_in_lands_on_its_return_path_with_the_query_kept` |
| 2 | B2, P2 | refused class: absent, empty, relative, `//`, `/\`, absolute, C0, LF, DEL, `/api`, `/api/me`, `/api/auth/login…`, 1025 B | same | callback 303 | `/`, session opened | login refused (4xx) instead of fallback; open redirect; API prefix accepted | `…::test_1161_b2_a_refused_return_path_still_signs_in_and_lands_on_the_root` |
| 3 | D6, B1 | two logins in flight | callbacks in reverse order | each login's `Set-Cookie` (name, Path, flags, Max-Age); callback's `Set-Cookie` | distinct names; `Path=/api/auth/callback`, HttpOnly, Secure, Lax, 0<Max-Age≤600, no `__Host-`; each lands on own P; callback clears only its own | one shared cookie (second overwrites first); clearing every pre-login cookie; `__Host-` with sub-path (Chromium drops it) | `…::test_1161_d6_two_sign_ins_in_flight_each_complete_to_their_own_return_path` |
| 4 | D6, B4 | callback for attempt 1 carrying only attempt 2's cookie; and carrying none | callback | 303 target | failed screen (not P1/P2/root), `reason=prelogin-missing`, `return` absent or `/`, no session | falls back to another cookie's return path; success on mismatch | `…::test_1161_d6_b4_a_callback_without_its_own_pre_login_cookie_never_uses_another_attempts_return_path` |
| 5 | B4, S1 | code refused (400); unknown account; token endpoint 503 | callback with own cookie | 303 target, `Set-Cookie` | failed screen, `reason` = `login-attempt-invalid`/`unknown-account`/`unavailable`, `return` = kept path, no session, pre-login cookie cleared | 403/503 problem JSON (today); reason lost; return path lost | `…::test_1161_b4_every_failed_callback_is_a_303_to_the_sign_in_failed_screen_naming_its_reason` |
| 6 | B3 | ops | `POST /api/admin/tenants` | `Location`; GET of it | `/api/admin/tenants/<id>`, reads 200 | `url_path_for` under root_path (C17) | `…::test_1161_b3_the_location_create_tenant_builds_carries_the_api_prefix_and_reads_back` |
| 7 | B5 | Ann's cookie, foreign Origin; preflight | GET, OPTIONS `/api/me` | headers | 200 with cookie only; no `access-control-*` anywhere | CORS middleware added for the frontend | `…::test_1161_b5_a_cookie_alone_reads_the_api_and_no_origin_is_granted_cors` |
| 8 | B6 | job's investigation; origin in launch record | `run_job` | ticket receipt sidecar; accepted-comment record | launch taken (`calls`, job-end SETTLED), receipt exists; a body holds `<origin>/t/<T>/investigations/<I>` | job lane writes nothing (today); link from run id of another run; no origin | `jobs/test_job_entry.py::test_1161_b6_an_investigation_jobs_ticket_write_back_links_its_investigation_screen` |
| 9 | B6 | operator run (`run.main`) | comment posted | posted body | no `/t/`, no `/investigations/` | link written for operator runs | `tenancy/case_comment_1359/test_record_leg.py::test_1161_b6_an_operator_runs_comment_links_no_investigation_screen` |
| 10 | B8, B1, B7, B5, S3 | signed out; path / path+query | open ticket link in a new profile | final URL, body text, request log | URL exactly target; "completed" and "malicious" shown; one `/api/auth/login?return=target`; every `/api` call same-origin, no `Authorization` | lands on root; adds a `?attempt=` to the URL; bearer token in page | `frontend/test_1161_browser.py::test_1161_b8_a_ticket_link_opened_signed_out_lands_signed_in_on_its_investigation_screen` |
| 11 | B1, B8 | sessions deleted after the callback (real revocation) | open ticket link | `[data-testid=sign-in-failed]`; login log; retry click | failed screen; exactly one automatic login; retry → second login with return = target | redirect loop; retry with the failed screen's own address | `…::test_1161_b1_a_401_after_sign_in_shows_sign_in_failed_and_retries_only_on_request` |
| 12 | B8, D6, S3 | two new tabs, both parked at the IdP | release in reverse order | each tab's URL | each on its own address with the screen | one pre-login cookie; return path in a shared store | `…::test_1161_b8_d6_two_tabs_opened_signed_out_each_land_on_their_own_address` |
| 13 | B7 | Bob (tenant B) opens A's link | sign in | login log; API status; body | one login; `GET /api/tenants/A/investigations/I` 404 (as `test_another_tenants_member_reads_every_work_record_of_a_tenant_as_absent` shows in-process); "malicious" absent | treating 404 as 401 (loop); showing cached data | `…::test_1161_b7_a_signed_in_non_member_is_not_shown_the_investigation_and_not_sent_to_sign_in_again` |
| 14 | B9 | `/`, deep link, `/me`, `/auth/login`, `/apix`, unknown | GET through Caddy | status, type, body, headers | 200 html, the app's one document; `Referrer-Policy: strict-origin-when-cross-origin`; `form-action 'self' https://*.<artifact-domain>` exactly | 404 for deep links; `no-referrer`; `/api` prefix matched as a string prefix | `…::test_1161_b9_the_ingress_serves_the_app_with_its_headers_for_every_path_outside_api` |
| 15 | B3, B9 | through Caddy | `/api/me` signed out; create tenant; GET Location | status/type; read-back | 401 problem; Location reads 200 | ingress strips prefix while API builds unprefixed Location | `…::test_1161_b3_b9_through_the_ingress_api_paths_reach_the_api_and_its_locations_read_back` |

## Forced choices (the design does not make these)

- **FC-1 (case 1–7, 15). How the API comes to live under `/api`.** In-process tests must address either
  `/api/...` (app mounts its routes under the prefix) or the root with `root_path` (ingress strips). I chose mounted
  (`_api()` is the one place). Consequences: mounted → every existing root-path API test, `Child.ready`'s
  `/openapi.json`, `_routes1307a.PUBLIC`, `test_unknown_query`'s `/auth/login` become conflicts; stripped → C17
  bites, and P2's "refuse the API prefix" needs the API to know its prefix (a new setting, which also trips
  `environment()`'s `SETTING_NAMES` assertion). Case 15 is mechanism-agnostic.
- **FC-2 (10–15). Where the frontend and the Caddyfile live and how a test builds them.** Chose
  `defender/frontend/` (`package.json`, `npm ci && npm run build` → `dist/index.html`) and
  `defender/frontend/Caddyfile`; the test builds once per session.
- **FC-3 (10–15). What the Caddyfile reads.** Chose env: `DEFENDER_INGRESS_ADDRESS` (site address, plain http
  in tests vs TLS in deployment), `DEFENDER_INGRESS_API`, `DEFENDER_INGRESS_ROOT`, `DEFENDER_ARTIFACT_DOMAIN`,
  `DEFENDER_INGRESS_ADMIN` (`off`: parallel Caddys collide on :2019). The artifact domain's name in piece 1 is
  unset (I used `artifacts.defender.test`).
- **FC-4 (10–15). The frontend origin in tests vs the API's `ORIGIN`.** The real frontend origin is the
  ingress's (`http://localhost:<port>`), so the browser stack overrides `DEFENDER_API_FRONTEND_ORIGIN` and the
  redirect URI; in-process tests keep `ORIGIN = http://localhost:8000` as the frontend origin.
- **FC-5 (1, 4, 5). The failed screen's address and how reason and kept return travel.** I pinned only: a
  frontend address that is neither the return path nor the root, with `reason=<code>` and `return=<kept path>` in
  its query. B1 says the failed screen keeps a return path; the design does not say whether it is in the URL or
  the tab. Also: relative vs absolute `Location` (tests accept both, same origin).
- **FC-6 (4). The reason for a mismatched cookie.** With per-attempt names a callback whose state has no matching
  cookie is `prelogin-missing`; today a mismatch is `login-attempt-invalid`. I pinned `prelogin-missing` for both
  missing and mismatched.
- **FC-7 (3). The per-attempt cookie's name and lifetime.** `__Host-` cannot carry `Path=/api/auth/callback`
  (Chromium drops it: probed). Name base, prefix length and lifetime ("short") are unset; I pinned distinct names,
  no `__Host-`, Max-Age ≤ 600 (today's constant).
- **FC-8 (13). What the investigation screen shows when the investigation is missing or the caller is not a
  member** (both 404). I pinned only: no second sign-in, no data shown. Likewise "outcome" = `disposition` and the
  words shown are the raw enum values (10).
- **FC-9 (11). How a test finds the screens.** Chose `data-testid="sign-in-failed"` and `"sign-in-retry"`.
- **FC-B6a (8). B6's premise is false at the base:** the job lane (`run.py` ~1651) calls `_post_steps(…,
  update_ticket=False)` with no record step; only the operator run (`run.py:1401`) comments. So today no job
  writes to a ticket, and B6's link has no carrier. The design must decide that the job lane gains the record
  step (with its write-back token through the helper's pass).
- **FC-B6b (8). How the origin reaches the job.** "passed to the job by the worker with its settings": which
  worker setting (none exists; `worker/_start.Settings` has no origin), then launch record vs container env vs
  launch facts. Chose the launch record field `frontend_origin`. Also open: host-appended link vs a case-record
  template variable.
- **FC-10 (none written). Sign-in start's failure has no real fault on the real server:**
  `KeycloakSignIn.begin_signin` only builds a URL; only the fakes #1496 deletes raise there. B4's "sign-in start's
  unavailable" is untestable through the real program.
- **FC-11 (none written). The callback's re-check of the return path** is observable only by forging a pre-login
  cookie, whose encoding the design leaves open.
- **FC-12 (1, 2). 1024 bytes of what:** raw vs percent-encoded vs decoded; and whether control characters are
  judged on the decoded or raw value (`/t/%0a`). Cases use ASCII only. Also whether `/apix` is "the API prefix"
  (case 14 pins it as the app's).
- **FC-13 (10–15). CI** has no Node, Caddy, Playwright or Chromium step: the browser file skips there (no caddy /
  no playwright) — a meaningless green until CI provisions them.

- **FC-14 (13). Which read the screen makes:** pinned `GET /api/tenants/<T>/investigations/<I>` (the existing
  investigation read under B3's prefix).

## Not covered / unreached

- `otp-required` callback outcome: FakeKeycloak does not model `GET …/users/<id>/credentials` and `served` asserts
  `unmodelled == []`; the thorough pass must model it.
- B1's storage-unavailable branch (no automatic redirect, failed screen with its button): deferred.
- Sign-in start's failure (FC-10) and the callback re-check (FC-11): no case.
- Unreached assertions: in cases 1–5 everything after the first `_login` with a `return` parameter has never run
  (today 404 at `/api`; at the root, 422 for the unknown `return` query). The sign-in machinery itself was proven
  against today's root routes (a scratch copy: login → front channel → code exchange → callback 303 → `/me` 200),
  and the browser harness end to end against a throwaway Caddyfile (stripping `/api`) and throwaway page in the
  scratchpad (test-double evidence only: they say nothing of the product's ingress or frontend).
- B6 case 8's second half needs the scene to proxy a case store (none yet).
- Lint: only ruff was run on the changed files (clean); no mypy.

## Probes (executed, Chromium headless shell, Playwright 1.65.2)

- `sessionStorage` survives a same-tab cross-origin round trip (A → B 302 → A 303): yes. A `noopener` new tab
  starts empty; a tab opened with an opener copies it.
- On `http://localhost`, a `Secure` `__Host-` cookie with `Path=/` is kept; a `__Host-` cookie with
  `Path=/api/auth/callback` is dropped; a plain-named `Secure` cookie with that path is kept.
- Playwright does not route a request reached by a server redirect (the browser connects for real), so the
  front channel is a loopback server, not `context.route`.

## Wrong code-map entries

- record.md "Ticket write-back … called from `defender/run.py:1393`" and C14 "the ticket write-back runs inside the
  job": the call (`run.py:1401`) is the operator composition only; the job lane writes back nothing.
- record.md: `FakeKeycloak` "back channel only" — also models no authorization-code grant (token step answers only
  `client_credentials`); added in `_signin1161`.
- record.md: the scratch Playwright venv is Python 3.12; the project venv is 3.11 (greenlet will not import). A 3.11
  target is at `<scratchpad>/pw311`.
