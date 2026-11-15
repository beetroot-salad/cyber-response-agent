# #1161 piece 1 — spike friction log

Throwaway worktree `/workspace/.worktrees/1161-spike` (base `4f94f147c`); diff in `spike.diff` (backend `defender/api/app.py`,
`defender/frontend/{package.json,tsconfig.json,index.html,src/main.ts,Caddyfile}`). Nothing committed. Built with npm
(registry reachable; TypeScript 5.6.3 only, `tsc` emits ES modules, no bundler, no UI framework).

Result against the sketch: 24/24 API cases green; 12/12 browser cases green only after two sketch-harness fixes (H1, H2,
patched in a scratch copy, not in the tests); B6 job case red (open design question), B6 operator case green (premise
already true).

## Sketch harness defects (not design friction; fix in the tests)

- H1. `defender/tests/frontend/test_1161_browser.py:~105,~110` (`stack` fixture: `anyio.run(seed_identity …)`, `anyio.run(link_account …)`,
  `anyio.run(_completed …)`) vs the session-scoped `chromium` fixture (`sync_playwright()` holds the thread's event
  loop; `browsing(chromium, stack, …)` instantiates it first). Every browser test errors in setup with
  "Cannot run the event loop while another loop is running". b9 alone passed (it does not use `chromium`). I ran a scratch copy that runs
  `anyio.run` on a helper thread. The harness needs that (or an async-free seed).
- H2. `test_1161_browser.py` `Browsing.__init__`: `self.context.on("request", self.requests.append)` raises
  `AttributeError: 'builtin_function_or_method' … '_pw_impl_instance_'` (Playwright wraps handlers by setting an
  attribute). Needs a lambda. Scratch copy patched.
- H3. A first run of all 12 browser tests in one process seemed to hang past 6 minutes (killed); each test alone, and then the whole file,
  passed in ~80 s after. Not reproduced; possibly Caddy/Chromium cold start while the machine was busy with another suite. Watch for flakiness.

## Friction entries

1. **The first API call of a screen: `/api/me` or the investigation read?** `defender/frontend/src/main.ts` `investigationScreen`;
   design B1 ("the load's first API answer"), Flow ("frontend calls `/api/me` → 401"), B7 ("the existing investigation read").
   I first read the investigation directly (one call fewer). Sketch case 13 (b7) then went red: it lists every call to
   `/api/tenants/A/investigations/I` and expects `[404]`, but the signed-out load's own 401 on that URL is in the list.
   The design's Flow names `/api/me` as the probe; I switched to it (two calls per screen: `/api/me`, then the read). The design never says the
   screens probe `/api/me`, nor that a 401 on the read (session lost between the two calls) is treated like a 401 on the probe;
   I made only the probe subject to the attempt rule, so a 401 on the read shows "not available".

2. **The return-path check is not only lexical.** `defender/api/app.py` `_return_path`; design P2's refused list
   ("not one leading `/`, `//`, `/\`, control characters, the API prefix, > 1024 bytes"). A value passing that list can still reach
   the API once the browser and ingress read it: `/t/../api/auth/login` (the browser resolves dot segments), `/%61pi/me` (Caddy's `path`
   matcher percent-decodes before matching `/api/*`; I did not probe this, it is Caddy's documented behavior). I check the percent-decoded,
   dot-resolved path against the prefix. The design says "the API prefix" without saying judged on which form (FC-12 in the sketch is the same
   question for the 1024 bytes). The sketch has no case for it. The frontend repeats a weaker copy of the rule (`localPath`) for the failed
   screen's `return` query: two owners of one rule, in two languages; retry goes through `/api/auth/login`, which re-checks, so the copy could be dropped.

3. **Two places own the pre-login cookie's format; one owns its "mismatch".** `defender/identity/service.py:387` builds
   `state.nonce.verifier`, `:391-396` parses it and reports a state mismatch as `login-attempt-invalid`; `app.py` `login`/`callback` now append and split off
   a fourth segment (the base64url return path) with `rpartition(".")` and re-compare the state itself so a mismatched cookie's return path is
   never used (B4/D6) and the reason is `prelogin-missing` (sketch FC-6). The alternative, `complete_signin` returning the return path or
   `begin_signin(return_path)`, changes a signature used by `tests/identity/test_identity_service_postgres.py:171-172` and the fakes in
   `tests/support/api/_identity1306.py`; I kept the service untouched and put the return path in the API layer. A design that says where the
   cookie's format lives would avoid the double ownership. Note the service's mismatch branch is now unreachable through the API (the API
   passes `prelogin=None` when states differ) but live in the service.

4. **How the callback finds "its own" cookie.** D6 "named by a short prefix of its state" does not say how long, nor that the name comes from the
   callback's `state` query value (attacker-chosen). `app.py` `_prelogin_name`: `__Secure-defender_prelogin_` + first 8 characters of `state`, only if they are
   `[A-Za-z0-9_-]` (a cookie *name* built from a request value). 8 characters = 48 bits; a prefix collision between two attempts in one browser is
   then resolved by the full-state comparison above. Name base, prefix length, `__Secure-` vs plain: unset in the design (sketch FC-7). `__Host-` is
   impossible with `Path=/api/auth/callback`.

5. **Unbounded pre-login cookies.** `app.py` `login`: each login sets a cookie that lives 600 s and is sent on every request to the callback path; the
   design bounds a *single* attempt, not the number. N abandoned attempts inside 10 minutes make the callback's request header N cookies long
   (about 250 bytes each) until a server's header limit refuses the callback. The old single shared cookie had no such growth. No bound in the design
   (a count cap needs a cookie to count, so it would sit in a second cookie or be left to the browser's own limits); not handled.

6. **Callback path is owned three times.** `app.py` `_CALLBACK_PATH` (the cookie's `Path`), `API_PREFIX` + route `/auth/callback`,
   and the `DEFENDER_KEYCLOAK_REDIRECT_URI` setting (`defender/api_server/_settings.py`, `identity/keycloak.py:73 check_redirect_uri`, which accepts any
   absolute URL). A redirect URI that still says `/auth/callback` (the deployment move B3 lists as #1498) fails with a 404 at the callback and,
   if only the host moved, with a cookie that is never sent. The design lists the move; nothing in code checks the setting's path against the
   route. Not changed.

7. **Mounting under `/api` is one line but the API's other surfaces are not routers.** `app.py` `create_app`:
   `include_router(router, prefix=API_PREFIX)` was enough for every route, `url_path_for` (create_tenant's `Location`, `app.py:~853`) and the
   census (`undeclared_routes`, `unauthenticated_routes` read `route.path`). `/openapi.json`, `/docs`, `/redoc` are FastAPI's own routes and stayed at the
   root until I moved them (`openapi_url`/`docs_url`/`redoc_url` under the prefix). B3 does not list them; consumers: `Child.ready`
   (`tests/support/api/_server1083.py:512`), `tests/api/test_1083_real_server.py:454,471`, bearer clients' docs.
   FC-1 settled as "mounted"; the stripped alternative would have needed a new prefix setting for P2's API-prefix refusal.

8. **`Location`/redirects built from the request's URL behind a TLS ingress.** `app.py:432` (`_created_at`: `str(request.url_for(...))`, absolute
   URLs of the request's own base). The ingress terminates TLS and proxies plain http to the API in another container; uvicorn (`api_server/_program.py:244`,
   `uvicorn.Config(running.app, …)` with defaults) trusts `X-Forwarded-Proto` only from `127.0.0.1`, so such `Location`s would say `http://`
   in deployment. Caddy preserves `Host` (so the host is right). B3 says every Location "carries the prefix", not what scheme/host. Not probed (tests run
   plain http); not changed. `create_tenant` is path-only (`url_path_for`), unaffected.

9. **Sign-in start's failure cannot occur on the real program.** `app.py` `login` handles `SignInUnavailable` with a 303 to the failed screen
   (`reason=unavailable`), but `KeycloakSignIn.begin_signin` (`identity/keycloak.py:318`) only builds a URL and never raises it. The handler is unreachable
   outside fakes (sketch FC-10); I wrote it from B4's text. A discovery or key probe at start would be a design change.
   The old exception handler for `SignInUnavailable` (503 problem, `app.py` `create_app`) stays: it is still what any other route raising it answers.

10. **The sign-in-failed screen's address and reason vocabulary.** `app.py` `_failed_screen` (`/sign-in-failed?reason=<code>&return=<path>`, absolute on
    `frontend_origin`), `src/main.ts` `failedScreen`. S1/B4/S2 give the screen no address (sketch FC-5). The query carries `return` only when it is not the root. I invented two
    frontend-only reasons the design's "existing reason codes" do not have: `session-lost` (B1's 401-after-sign-in) and `storage-unavailable` (B1's no-storage branch).
    The failed screen's `return` is read from the URL (so a crafted link can set it), which is safe only because retry goes through `/api/auth/login`'s
    re-check (see 2).

11. **Who deletes the attempt record.** `src/main.ts` `takeAttempt`/`failedRoute`; B1 "a screen reads that record once at load and deletes it". The
    callback's failure lands on the failed screen with the record still set (the investigation screen never loaded to consume it); if the failed screen
    does not delete it, a later hand-typed load of an investigation in that tab sees a stale record and shows failed instead of redirecting. I made every
    screen (the failed screen and the root included) consume it. The design's "a screen" does not say all. Retry re-records before navigating (B1's "before sending the
    browser to sign-in"), and when storage is unavailable the retry navigates anyway; a second 401 then ends in the failed screen again (no loop).

12. **No design element for the frontend's build, repo layout or Caddyfile inputs.** Followed the sketch (FC-2, FC-3): `defender/frontend/`,
    `npm ci && npm run build` → `dist/index.html` + `dist/main.js` (`tsc` then `cp index.html`), env-driven Caddyfile
    (`DEFENDER_INGRESS_ADDRESS/API/ROOT/ADMIN`, `DEFENDER_ARTIFACT_DOMAIN`). Fit: Caddy's `{$VAR}` placeholders worked for the site address,
    upstream, root, admin (`off`) and the CSP's domain. `package-lock.json` must be committed for `npm ci`. `index.html` loads `/main.js` (absolute path: deep links
    `/t/x/investigations/y` must not resolve it relative).

13. **B9 under-specifies the CSP and the response set.** `defender/frontend/Caddyfile`. The design names `form-action 'self' https://*.<artifact-domain>`
    and `Referrer-Policy`; a CSP with only that directive protects nothing else, so I added `default-src 'self'; frame-ancestors 'none'; base-uri 'none'`
    and `X-Content-Type-Options: nosniff`. Whether the frontend's own CSP needs `script-src`/`connect-src` rules (it loads one same-origin module and
    fetches same-origin) is not in the design; likewise cache headers for `index.html`/`main.js`, and which headers `/api` responses get (I put none on
    the proxied side; the sketch's case 14 checks only non-`/api` paths). The "ingress serves the app for every path outside `/api`"
    came out as `@api path /api /api/*` + `try_files {path} /index.html` (so `/apix` is the app's; `/api` and `/api/...` the API's).
    Unknown static-looking paths (`/foo.js`) get the app's document, not 404 (B9 says every path).

14. **B6 left alone.** `defender/run.py:~1651` (job lane `_post_steps(…, update_ticket=False)`, no record step): nothing writes a ticket from a job, so the link
    has no carrier; I did not invent one. The operator case passes because no link is written today. The origin has no worker setting either (sketch FC-B6a/b).

15. **Local CI/run prerequisites.** No Node, Caddy, Playwright or Chromium in CI (FC-13); here the browser file needs `PYTHONPATH` + `PLAYWRIGHT_BROWSERS_PATH` + `CF1161_CADDY`
    (the shared venv has no Playwright; the scratch 3.11 target lives at `scratchpad/pw311`, not under a `lib/*/site-packages` layout: its dir itself is the path).

## Existing tests turned red by the spike (stale-test signal)

See the report; counts below.

Run: `defender/tests/api`, `tests/identity`, `tests/tenancy/tenant_1108_p4` (3,200 tests): 1,203 failed + 16 errors, all in files that
address the app at the root (`/me`, `/auth/*`, `/tenants/...`, `/admin/...`, `/openapi.json`) or through `Child.ready`'s `/openapi.json`; per file:
test_api_stub 420, test_programs_1307_auth 159, test_identity_signin 79, test_programs_1307_credentials 75, test_programs_1307_refusals 75,
test_admin_tenants 55, test_identity_sender 46, test_programs_1307_responses 44, test_programs_1307_roles 42, test_unknown_query 36,
test_identity_admin 31, test_identity_membership 27, test_1083_real_server 21 (every pre-existing test; the 24 `test_1161_*` pass),
test_programs_1454_edges 15, test_stale_visibility 14, test_programs_1307_audit 13, test_identity_audit 12, test_programs_1307_effects 9,
test_admin_edge_cases 7, test_uuid_ids 6, test_programs_1454_tenant_active 6, test_1083_program 5 (Child.ready/openapi), test_programs_1307_loop 5,
test_programs_1307_path_ids 5, test_identity_lifespan 3, test_identity_purge 2, one each: test_api_model_fields, test_programs_1307_names,
test_programs_1307_wiring, identity/test_tenant_seam. Also `tenant_1108_p4/test_run_isolation_e2e.py` (2; not examined: probably root-path) and
`test_live_dev_issuer.py` (1; docker/openbao environment, unrelated). Also stale by assertion rather than path: `tests/api/test_identity_signin.py:78-190`
(`PRELOGIN_COOKIE = "__Host-defender_prelogin"`, `tests/support/api/_identity1306.py:77`: the name, Path=/ and the 403/503 problem shapes), `test_unknown_query.py`
(`/auth/login` with `x=1`: `return` is now declared), `tests/support/api/_routes1307a.py:19` (`PUBLIC` census paths).
The non-API tests nearest the change (`tests/jobs/test_job_entry.py`, `tests/tenancy/case_comment_1359/`: 196 pass, 1 red = B6 job case) are unaffected.
