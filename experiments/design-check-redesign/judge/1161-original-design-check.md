# #1161 piece 1 — design check (write-tests §2)

Reader: design-check seat. Read once, whole: `design-r8.md` (piece 1: S1–S4, P2, B1–B9, D6), `record.md` (Am-1),
`sketch.md` + the uncommitted sketch tests in `/workspace/.worktrees/1161-tests` (base `bdc39ca80`), `spike.diff`
(working tree `/workspace/.worktrees/1161-spike`, base `4f94f147c`) and `spike-log.md`; grounding `design-r4-grounding.md`
as needed; `docs/principles.md`; deployment design `defender/docs/decisions/vps-compose-deployment.md`.

Checks run (all read-only except a scratch Caddy):
- Read `run.py:1385-1424` (operator `ticket_and_curation`, `record_case_ticket`) and `run.py:1630-1652` (job lane:
  `_post_steps(..., update_ticket=False)`, no record step); `run.py:684-697` (`_TokenMint.write_back`) and `:1499`
  (`_HelperPass`: read pass only, no write-back mint); `worker/_start.py:65` (`Settings`: no origin).
- `gh issue list/view` for an owner of a job-lane write-back: none open. #1131 (umbrella) says "the verdict and a link to
  the run page land on the ticket"; #1172 and #1121 do not own it.
- Read `identity/service.py:382-418` (pre-login format and its two refusal reasons), `identity/keycloak.py:318`
  (`begin_signin` builds a URL only), `:73` (`check_redirect_uri` accepts any absolute URL), `api/app.py:367-383, 428-432,
  853` (`_any_query`, `_no_unknown_query`, `_created_at` = `request.url_for`), `api_server/_program.py:244` (uvicorn
  defaults), `tests/api/test_unknown_query.py:136` (D-ai: `/auth/login?x=1` refused), `.devcontainer/keycloak/realm-defender.json:59`,
  `docs/development-operations.md:137,153`.
- **Probe (executed):** Caddy v2.11.9 with the spike's matcher (`@api path /api /api/*` → upstream echo; else
  `try_files {path} /index.html`), requests sent with `curl --path-as-is`. Routed to the API: `/api/me`, `/API/me`,
  `/Api/me`, `/%61pi/me`, `/api%2fme`, `/%2fapi/me`, `/t/../api/me`, `/t/%2e%2e/api/me`, `/api`. Routed to the app:
  `/apix`. Caddy forwards the raw path unchanged.
- **Probe (executed):** the spike's `_return_path` accepts `/API/me`, `/Api/auth/login`, `/t\..\api\me`, `/t/%0a`,
  `/t/x?a=/api`; refuses `/t/../api/me`, `/%61pi/me`.

Not run: any pytest (the sketch's and spike's results are taken from their logs, including the ~1,200 reds).

Verdict: **not ready for thorough authoring.**
- **Owner calls:** G1 (B6 scope: false premise), G3's cookie protection (amends D6), G5's prefix mechanism and dev
  topology, G6's login query rule (amends the standing D-ai decision), G9's CI provisioning.
- **Follows from settled intent, but must be written down:** G2 (canonical return path), G3's format owner, G4
  (one origin, one callback address), G6's scoping, G7 (load protocol), G8 (failed screen), G9's headers.
- G10 is speculation.

IDs are `G<n>` so they do not collide with the repo's own `DC-<n>` decision IDs.

Labels: **confirmed** means read in code or probed. **Inferred** means reasoned from the code or the spec, not run.

---

## G1. B6 has no carrier: no job writes to a ticket (confirmed; needs the owner)

**Evidence.** The job lane `run.py:1651` calls `_post_steps(started, summary, ..., update_ticket=False, mirror=False)`
and has no record step. Only the operator composition (`run.py:1391-1404`, `ticket_and_curation`, `if ns.update_ticket`)
calls `ticket_writer.record_case_ticket`, and it mints its write-back token from `_TokenMint` (`run.py:1397`: "the
operator's own signer"). The job lane's `_HelperPass` (`run.py:1499`) holds a read pass and has no `write_back`. No
worker setting carries a frontend origin (`worker/_start.py:65`). No open issue owns adding job-lane write-back. #1131
only states the goal ("the verdict and a link to the run page land on the ticket"). Grounding C14 ("the ticket
write-back runs inside the job") is wrong: it read `run.py:1393`, which is the operator path.

**What it does to B6.** Both halves are vacuous at the base. "An investigation's write-back links its screen" has no
write-back to carry the link. "An operator run writes no link" holds today only because nothing writes a link
(sketch case 9 passes at base, per the spike log). Sketch case 8 cannot pass without inventing a write-back lane
(sketch FC-B6a). Even with one, the scene has no case store to accept the comment.

**Realistic options.**
- **(a) Move B6 out of piece 1.** #1161 closes on sign-in, `/api`, the frontend and B7. A new issue owns "a job's
  investigation writes back to its ticket, with the screen's link" and takes B6 whole, the origin plumbing included.
  *Trade-offs:* the analyst-facing payoff (a link on the ticket) waits. The issue title already promises "the ticket
  link", so it must be retitled. Piece 1 stays small and fully observable.
- **(b) Piece 1 adds the job-lane record step.** The job asks its helper for a write-back pass (`rw` on the case system,
  through the credential proxy, deployment B3), runs `record_case_ticket` with the link, and the worker passes the
  origin through the launch record. *Trade-offs:* this is a new credentialed capability for jobs. It has to be squared
  with deployment B3 ("a job holds only its pass"), the access declaration and #1491 (forge/model calls through the
  proxy). It also needs a case-store fake for the scene. That makes piece 1 several times larger and brings in an
  architecture decision unrelated to browsers.
- **(c) The trusted side writes the comment.** After the job ends, the worker or helper posts the comment through the
  proxy from the typed outcome record, which it already reads (deployment §5: "the worker reads only the small typed
  outcome record"). It would need a new worker setting for the origin (none exists, `worker/_start.py:65`) and has
  the investigation id from the claim. *Trade-offs:* the origin never enters the job, which dissolves the launch-record
  half of FC-B6b, and deployment B8 holds (no attacker bytes are read beyond the
  typed record). But this is a second write-back implementation beside the operator's in-run step, and the comment's
  content (verdict text) must come from the typed record only.
- **(d) Piece 1 ships only the link builder** (a pure function or template variable). *Trade-offs:* there is no real
  boundary to observe the link at, so the contract would test a helper, not a promise. Not recommended.

**Recommendation:** (a), unless the owner wants the ticket link to set the order. In that case (c) fits the
deployment's trust split better than (b). Whatever the choice: the frontend origin then has a third owner (G4), and
#1131 names the *run page* as the ticket's link while B6 names the *investigation screen*. The new owner of B6 should
reconcile the two.

**Route:** design amendment (owner: scope/architecture). Sketch cases 8 and 9 are affected.

---

## G2. "The API prefix" is decided in three places, and P2's lexical rule does not match the ingress (confirmed; follows from settled intent)

**Evidence.**
- P2 refuses "not one leading `/`, `//`, `/\`, control characters, the API prefix, > 1024 bytes": a lexical list.
- The ingress decides what is an API path differently (probe above). Caddy's `path` matcher is case-insensitive,
  percent-decodes, and cleans dot segments and `//`: `/API/me`, `/%61pi/me`, `/%2fapi/me` and `/t/%2e%2e/api/me` all
  reach the API. It forwards the raw path, so FastAPI (case-sensitive, no normalisation) presumably answers 404 problem JSON (inferred, not run).
  *Inferred, not probed:* browsers apply WHATWG URL parsing to a `Location` before sending. That parsing resolves
  `..`/`%2e%2e` and treats `\` as `/`, so `/t\..\api\me` becomes `/api/me`.
- The spike's `_return_path` (`app.py`) already went beyond P2's text (it decodes and dot-resolves). It still accepts
  `/API/me`, `/Api/auth/login` and `/t\..\api\me` (probe). After sign-in each of them lands a person on API JSON,
  which breaks S1 ("only the frontend is a landing place").
- A third, weaker copy lives in the frontend: `main.ts` `localPath`, used for the failed screen's `return` (spike
  friction 2). FC-12 (1024 bytes of *what*; control characters judged raw or decoded) is the same open question.

**Underlying decision.** One fact, "is this address a frontend address", is decided in Caddy (matcher), the API (P2)
and the frontend (`localPath`). Each works on a different form of the path.

**Dissolution.** State the return path's canonical form and judge only that.
- **(i) Allow-list (recommended).** At login, refuse a return path that is not already in canonical form: printable
  ASCII only, no `\`, no `.`/`..` segments (raw or `%2e`), no percent-encoding of `/`, `\` or `.`, nothing that
  changes under RFC 3986 dot-removal. Then deny any first segment equal to `api` compared case-insensitively. The byte
  limit applies to the raw value as received. A path that passes is one every reader (browser, Caddy, router) reads
  the same way. *Trade-offs:* it refuses some odd but harmless addresses (they fall back to the root, B2). It is
  simple to state and test.
- **(ii) Grammar allow-list.** Accept only S2's grammar (`/`, `/t/<T>/investigations/<I>`, later the opener) plus a
  query. *Trade-offs:* strongest, but every new screen must extend the API's list. That couples the API to the
  frontend's routes, which the "frontend owns every other path" split avoids.
- **Either way:** the frontend keeps no copy of the rule. The failed screen hands `return` back to `/api/auth/login`,
  which re-checks it (spike friction 2 already notes the copy can go). The Caddyfile's matcher becomes part of the
  contract: `/api` paths in any case and encoding go to the API, and the rule makes sure no accepted return path is one
  of them.

**Route:** design amendment to P2 (settled intent: S1, principle 3 "one owner"). Sketch cases 1, 2 and 14 need the new
classes (case, backslash, encoded dot, the byte measure).

---

## G3. The pre-login cookie: two owners of its format, the `__Host-` rule broken by D6, and an unobservable re-check (confirmed; one part needs the owner)

**Evidence.**
- **Format.** `identity/service.py:387` builds `state.nonce.verifier`, and `:391-396` parses it and reports a mismatch
  as `login-attempt-invalid`. The spike's `app.py` appends a fourth segment (the return path), splits it with
  `rpartition(".")`, re-compares the state itself, and passes `prelogin=None` on a mismatch so the reason becomes
  `prelogin-missing` (spike friction 3, sketch FC-6). It also derives the cookie name from `start.prelogin.split(".")[0]`.
  The result: the API layer knows the service's format, and the service's mismatch branch is dead through the API.
- **D6 against the cookie-prefix rule.** `app.py:83` reads "`__Host-` cookies are Secure, Path=/ and carry no Domain".
  D6's `Path=/api/auth/callback` makes `__Host-` impossible, and Chromium drops the cookie (sketch probe). The spike
  fell back to `__Secure-`, which allows a `Domain=` cookie set from any host under the app's registrable domain.
  Deployment §2 already warns that sibling subdomains are same-site. The pre-login value is unsigned (C16: "single-use
  and the provider checks them"), and it now also carries the return path. Existing assertions pin the old rule
  (`tests/api/test_identity_signin.py:78-190`, `tests/support/api/_identity1306.py:77`: the `__Host-` name, `Path=/`).
  r8's amendment list does not retire it: D6 breaks the rule silently.
- **Why `__Host-` mattered: login CSRF.** An attacker can start a sign-in of their own, keep the pre-login cookie it
  issues (a genuine one), and finish the provider step to get a code. If a host under the app's registrable domain
  can then plant that cookie in a victim's browser (`Domain=`), the attacker's callback link signs the victim in as
  the attacker. `__Host-` is what blocks the planting. Signing the cookie does not: the planted value is one the
  server really issued. *Inferred: no such host was shown to exist. The artifact domain is a separate registrable
  domain (deployment §5); what else runs under the app's domain is a deployment fact.*
- **The re-check.** P2's callback-side check exists because that cookie can be planted. Sketch FC-11 says it is
  observable only by forging a cookie whose encoding the design leaves open, so no case was written.
- **Unbounded count.** Each login adds a 10-minute cookie sent on every callback. N abandoned attempts make the
  callback header grow until a header limit refuses the callback (spike friction 5).
- **Name.** It is "a short prefix of its state": the length is unset, and the name is built from the attacker-chosen
  `state` query value (spike friction 4).

**Underlying decision.** Who owns the pre-login record (format, name, return path, mismatch rule), and what protects
it now that `__Host-` is gone.

**Dissolution.**
- **One owner (follows from settled intent).** The identity service owns the whole record:
  `begin_signin(return_path) -> LoginStart(url, cookie_name, cookie_value)` and
  `complete_signin(state, code, cookies) -> (session, return_path) | CallbackRefused(reason, kept_return)`. The API only
  moves cookies. One module owns the return-path rule (G2) and the service applies it at both ends. One reason code
  is chosen for "no cookie of this attempt", covering both missing and mismatched. *Trade-off:* it changes the
  signature used by `tests/identity/test_identity_service_postgres.py:171-172` and the `_identity1306` fakes, which
  #1496 deletes anyway.
- **Protection (needs the owner, because it amends D6 or the `__Host-` rule).** The options, ranked by whether they
  block planting:
  - **(i) Per-attempt `__Host-` cookies with `Path=/`.** Blocks planting and keeps D6's per-tab model. A planted cookie
    is then impossible, so the callback's return-path re-check guards nothing reachable. Principle 3 suggests dropping
    it, which also dissolves FC-11. *Cost:* every same-origin request (API calls, frontend assets) carries the open
    attempts for 10 minutes, and the count is still unbounded (spike friction 5).
  - **(ii) One `__Host-` cookie with `Path=/` holding the last N attempts.** Blocks planting and bounds the count.
    *Cost:* two logins started within one round trip can overwrite each other. The loser gets `prelogin-missing` and
    "retry from the root", which breaks D6's per-tab promise in that race.
  - **(iii) Keep `__Secure-` with `Path=/api/auth/callback`,** and state the premise as a deployment constraint: no host
    under the app's registrable domain serves anything that can set cookies for it. The callback re-check is then
    load-bearing, and its case needs the cookie format stated (FC-11). The count stays unbounded. Signing the cookie
    adds nothing against planting (see above).

**Route:** design amendment (D6 protection: owner). The format's owner follows from intent. Sketch cases 3 and 4
are affected, plus an FC-11 case once the format is stated.

---

## G4. The shared origin and the callback address have several owners each (confirmed; follows from settled intent)

**Evidence.**
- **Callback path.** It is owned three times: the route (`API_PREFIX` + `/auth/callback`), the cookie `Path`
  (`_CALLBACK_PATH`), and the `DEFENDER_KEYCLOAK_REDIRECT_URI` setting. `check_redirect_uri` accepts any absolute URL,
  so nothing checks that the setting's path names the callback route. (Dev ops separately lists the setting's
  equality with the realm's registered URI as not checked at start.) A stale
  `/auth/callback` setting gives a 404 at the callback. A redirect URI on another host gives a callback that never sees
  the host-only pre-login cookie (spike friction 6).
- **B3's named owner for the move.** B3 names "#1498" for moving the identity provider's registered redirect URL, but
  #1498 is merged (`gh`: "The API on PostgreSQL and real sign-in ... MERGED"). The in-repo carriers are
  `.devcontainer/keycloak/realm-defender.json:59` (`http://localhost:8000/auth/callback`) and
  `development-operations.md:137,153`.
- **Frontend origin.** `DEFENDER_API_FRONTEND_ORIGIN` (Origin check, the callback's absolute 303s), the redirect URI's
  origin, and under B6 a new worker setting (FC-B6b). S2 makes them one value: the shared origin. The sketch's FC-4
  shows the cost: the browser stack must override two settings, the frontend origin and the redirect URI, in step.
- **Absolute `Location`s built from the request.** `_created_at` (`app.py:432`) uses `request.url_for`, an absolute
  URL on the request's own base. Uvicorn runs with defaults (`_program.py:244`) and trusts `X-Forwarded-Proto` only from
  127.0.0.1. Behind the TLS ingress in another container those `Location`s say `http://` (spike friction 8; inferred,
  not probed). Starlette's trailing-slash redirect is built the same way (inferred). B3 promises the prefix, not the
  origin.

**Dissolution.**
- Derive the redirect URI as `frontend_origin + url_path_for("callback")` and drop the setting, or refuse at start a
  setting that differs. Derive the cookie `Path` from the same route. S2's shared origin makes any other value
  unworkable anyway.
- Every API-built `Location` is either path-only or built from `frontend_origin`, never from the request's base. This
  needs no proxy-trust configuration.
- If B6 stays in scope, the worker reads the same deployment value. There is still one origin, configured once per
  deployment.
- B3 names its real carriers (the realm import and dev ops) instead of #1498.

*Trade-offs:* one setting fewer (the `environment()` `SETTING_NAMES` census changes), and the API can no longer be
configured with a callback on a host other than the frontend's, which S2 already forbids.

**Route:** design amendment, small (settled intent: S2, principle 3).

---

## G5. How the API comes to live under `/api`, and what else is at the root (confirmed; needs the owner for the mechanism and the dev topology)

**Evidence.**
- B3 says "lives under `/api`" and cites C17 (`url_path_for` omits a `root_path`). C17 only bites if the ingress strips
  the prefix. The sketch (FC-1) and spike mounted the routers instead, and C17 vanished.
- Mounting turned about 1,200 existing tests red (spike log, as reported: almost all root-path addressing plus
  `Child.ready`'s `/openapi.json`). Some of them ride the fakes #1496 deletes: at least `test_api_stub` (420) and
  `test_identity_signin` (79). The rest were not classified.
- FastAPI's own surfaces are not routers: `/openapi.json`, `/docs` and `/redoc` stayed at the root until the spike
  moved them by hand (spike friction 7). B3 does not list them. At the root they would be shadowed by the ingress (the
  frontend owns every other path, S2).
- **Dev topology.** The documented dev walk-through runs the API alone with frontend origin = API origin
  (`development-operations.md:153`: "the built-in docs page is then the client"). After B4, a refused first admin
  sign-in (the walk-through expects `otp-required`) 303s to `/sign-in-failed` on the API's own origin. With no ingress
  or frontend, that is a 404 JSON (the reason survives only in the URL). S1 also says "the API answers code, never a
  person", while `/docs` is a person-facing page. Under the ingress it is an HTML document on the app origin, outside
  B9's headers, that loads third-party CDN scripts (inferred: FastAPI's default Swagger UI; not probed).
- "Piece 1 ships first and leaves the system working": the design does not say what dev runs after the change
  (the Caddyfile and built frontend in dev, or the API alone).

**Underlying decision.** Where the prefix is applied (API routes, ingress strip, or the server program) and what the
person-facing dev client becomes.

**Dissolution.**
- **Mount in the API (recommended).** The prefix is one constant in the API, and Caddy forwards unchanged. B3 then
  says this and lists the non-router surfaces (`/api/openapi.json`; docs UI under `/api/docs` or off).
  *Trade-offs:* re-addressing the existing suites is mechanical follow-through, but there is a lot of it. Sequencing it after #1496's deletions shrinks it. Strip instead: the old tests stay green in-process, but
  C17 bites, P2 needs a prefix setting, and the prefix gets two owners (Caddy and the API).
- **Dev topology (owner).** Either dev runs the ingress and the built frontend (needs Node and Caddy in the devcontainer),
  or the API keeps a dev-only docs client and the failed screen degrades to its URL. Also decide whether `/api/docs`
  ships in deployment (S1 suggests off, or `openapi.json` only).

**Route:** design amendment (mechanism and dev topology: owner/architecture). Sketch cases 1–7, 15, and every existing
API suite are affected.

---

## G6. Sign-in start's failure: the promised one is unreachable, a reachable one is unpromised, and "every outcome" is wider than piece 1 (unreachable failure confirmed, the rest inferred; scoping follows from intent, the login query rule needs the owner)

**Evidence.**
- **The promised failure is unreachable.** B4 and S1 promise a 303 for sign-in start's "unavailable". But
  `KeycloakSignIn.begin_signin` (`keycloak.py:318`) only builds a URL, and only the fakes #1496 deletes raise there
  (sketch FC-10, spike friction 9). No case can reach it on the real program.
- **A reachable failure is unpromised.** `_no_unknown_query` refuses unknown query parameters on `/auth/login`
  (`test_unknown_query.py:136`, decision D-ai: only the callback is exempt). A navigation to
  `/api/auth/login?return=/t/..&utm_source=x` (a mangled or tracked link) gets 422 problem JSON, against S1. The spike
  kept that guard on login (read in the diff, not run).
- **"Every outcome of the callback"** (S1, B4) includes an internal fault: the session insert or user lookup failing
  with the database down. That presumably answers the generic 500 problem JSON (inferred, not run), and the design
  does not say whether it should be a 303 (`unavailable`). It is reachable on the real program.
- **S1's wording is wider than piece 1.** S1 says "every outcome of a browser navigation to the API that ends on our
  side ends in a 303". Read literally, that covers a navigation to `/api/me` (401 JSON, C2), `/api/docs`, and the 307
  artifact route B3 keeps until piece 2.

**Dissolution.**
- Scope S1 and B4 to the two sign-in routes.
- For start: either drop "start's unavailable" (start has no failure on the real program) or make `login` accept any
  query, as the callback does, so its only outcomes are 302 to the provider or 303 to the failed screen. Recommended:
  `_any_query` on login plus dropping "unavailable" from start (principle 3: no handler for a condition that cannot
  occur). This overrides the standing decision D-ai (only the callback is exempt from the unknown-query refusal), so
  two settled rules conflict here, and the owner rules on it. The other way out: S1 explicitly excludes malformed
  sign-in links, and the 422 stays.
- For the callback: state that a fault after the provider answered is a 303 with `unavailable` (the person's browser is
  mid-navigation, and JSON helps no one) and that it is logged. Alternatively, exclude internal faults explicitly.

**Route:** design amendment, small. New cases: unknown query on login, callback with the store down. FC-10's dead case
is removed.

---

## G7. The frontend's load flow is implied but not stated (confirmed; follows from settled intent)

**Evidence.**
- **The first call.** B1 keys the loop bound to "the load's first API answer". The Flow names `/api/me`, while B7 says
  the screen reads "the existing investigation read". The spike first read the investigation, sketch case 13 went red
  (the signed-out read's 401 polluted its call list), and the spike switched to `/api/me` first (friction 1).
  The design names three different first calls: the Flow's `/api/me`, B7's investigation read, and for piece 2's
  opener O1's grant POST ("401 → B1").
- **A later 401.** A 401 on a call after the first (the session expired between `/api/me` and the read, or during use)
  is unstated. The spike shows "not available" for it.
- **Who consumes the attempt record.** "A screen reads that record once at load and deletes it" does not say *every*
  screen. A callback failure lands on the failed screen with the record still set. If that screen does not consume
  it, the next ordinary load in that tab shows sign-in-failed instead of signing in (spike friction 11).
- **The root and unknown paths.** The root is where B2's fallback and D6's "retry from the root" land, but the design
  never says what it shows or whether it needs sign-in. Unknown frontend paths (B9 serves the app for them) are also
  unstated. In the spike, both make no API call, so B1's "any frontend address followed while signed out leads through
  sign-in" does not hold for them.
- **What the screen shows on 404 or 5xx.** FC-8: not a member, missing, or a 5xx/network failure. FC-14: which read.

**Dissolution.** State one load protocol for every screen except the sign-in-failed screen, which by B1 makes no
authenticated call at load:
1. Consume the attempt record. Every route does this, the failed screen included.
2. Call `GET /api/me` first. Its 401 is the only "signed out" signal at load: with no record, record one and redirect;
   with a record, or with no storage, show sign-in-failed.
3. Only then make the screen's own calls (the opener's grant POST becomes one of them). A 401 from any later call,
   during the load or during use, goes through the same rule. The record makes it at most one automatic redirect per
   return.
4. Every screen other than the failed screen requires sign-in, the root and the not-found screen included.
5. A 404 from a screen's read shows "not available" with no second sign-in. A 5xx shows an error state.

*Trade-offs:* one extra call per load. This settles case 13's observable and gives piece 2 the same rule. The
alternative is that a screen's own first call is the probe, with B1 applied to it. It saves a call, but each screen
then has its own first call, and case 13 must exclude the signed-out load's 401.

**Route:** design amendment (flow). Sketch cases 10, 11 and 13 are affected. New cases: a 401 on a later call, a
signed-out root, an unknown path.

---

## G8. The sign-in-failed screen has no address, no vocabulary and no stated return channel (confirmed; follows from settled intent)

**Evidence.**
- **No address.** S2 lists only the investigation and opener addresses. B1 says the failed screen keeps a return path
  and retries with it, but not where it keeps it (FC-5). For callback failures, the URL is the only channel: the API
  cannot write `sessionStorage`. The spike uses `/sign-in-failed?reason=<code>&return=<path>` (friction 10), which sits
  against B1's "nothing is added to a shareable address" (that sentence was written about the attempt marker).
- **No vocabulary.** "The existing reason codes" are the callback's: `prelogin-missing`, `login-attempt-invalid`,
  `unknown-account`, `otp-required`, and `unavailable`. B1's two frontend-detected states (a 401 after sign-in, storage
  unavailable) have no code, and the spike invented `session-lost` and `storage-unavailable`. The mismatch reason is
  also open (FC-6, see G3).
- **Who reads `return`.** A crafted failed-screen link can set `return`. That is safe only because retry goes through
  `/api/auth/login`'s check (G2).

**Dissolution.**
- Add the failed screen to S2: `/sign-in-failed?reason=<code>[&return=<path>]`. State that `return` is passed only to
  `/api/auth/login` and never navigated to directly.
- Define one reason vocabulary as the union of the API's codes and the two frontend codes, and narrow B1's
  "shareable address" sentence to the attempt marker.

**Route:** design amendment, small. Sketch cases 4, 5 and 11 are affected.

---

## G9. B9 and the ingress: under-specified headers, a second owner of the artifact domain, and an unenforced e2e promise in CI (confirmed / plausible; mostly follows from settled intent, CI needs the owner)

**Evidence.**
- **Headers.** B9 names only `form-action` and `Referrer-Policy`. A CSP with only `form-action` protects nothing else.
  The spike added `default-src 'self'; frame-ancestors 'none'; base-uri 'none'` and `nosniff` without a design basis
  (friction 13). B9 does not say whether `/api` responses (including any HTML docs, G5) get headers.
- **Artifact domain.** Piece 1 must put `<artifact-domain>` in the frontend's CSP, but no component owns that name yet.
  The spike's Caddyfile reads an env, the sketch uses `artifacts.defender.test`, and piece 2's frontend must also know
  it to build `https://<T>.<artifact-domain>/_open`. Because the frontend is static (Am-1), the frontend's copy needs a
  runtime or build-time channel.
- **CI.** B8 promises a headless-browser check, but CI has no Node, Caddy, Playwright or Chromium. The sketch's browser
  file skips there (FC-13), so the promise is unenforced on every push.

**Dissolution.**
- B9 states the full frontend CSP (`default-src 'self'` baseline plus `frame-ancestors 'none'`, `base-uri 'none'`, and
  the `form-action` it already has) and `nosniff`. It says that `/api` responses get none, or `default-src 'none'` if
  an HTML docs page ships.
- Name one deployment setting for the artifact domain, read by the ingress config now and by the frontend through
  `/api/me` or a config endpoint in piece 2.
- **CI (owner/infra):** provision the four tools in the `test` job, or accept that B8's check runs only locally and say
  so in the contract.

**Route:** design amendment (headers: settled intent from A5's counterpart). CI provisioning: owner.

---

## G10. D6's per-tab completion is unprobed against the real identity provider (speculation)

D6 assumes the provider completes two concurrent attempts in one browser independently. The sketch's front channel
is a loopback fake (case 12), so no case observes Keycloak's own handling of two `prompt=login` auth sessions in one
browser profile (its tab-aware auth-session cookie). If Keycloak ends the second tab's attempt with "already logged in"
or an expired-action page, the attempt ends on Keycloak's side (outside S1), and D6's promise holds only in our half.
**Route:** grounding probe against the dev Keycloak, or state D6's scope as "our side of the round trip".

---

## Dismissed as spike or sketch mechanics

H1–H3 (event loop, Playwright handler, cold-start hang), FC-2, FC-3 (except the artifact domain's name, G9), FC-9, spike friction 12 and 15 (layout, build,
local paths), and FC-7's exact numbers once G3 settles. These conflict with no design choice. FC-4 is folded into G4, and FC-13 into G9.
