# #1161 — Browser access: signing in, moving around, and opening untrusted pages

Revision r4 (candidate; r3 plus the local fixes from its third independent review and sort; r1 → r2 → r3 → r4).
Grounding base: `77e36c0ac` (main).

## Problem and intended change

People use the product through a browser: analysts follow the link on their own ticket, app users browse
alerts and investigations, and both open what the system generates — a run's page, a learning job's episode
page (which links to each sibling run's page), the lessons and queues views. Generated pages are built from
attacker-influenced content and must never act with the viewer's authority.

Two related questions, kept explicit:

- **A. Serving untrusted pages.** Where generated HTML is served, how a page and its linked files are
  authorized, and what the serving layer guarantees about what the bytes may do.
- **B. Signing in, navigating, calling the API.** How a person reaches any screen by a link, signs in if
  needed, lands where they were going, and how the frontend's code calls the API.

They meet at one seam this design owns: **the page opener** — how a person opens a page and gets back into it.
With the opener fixed, B no longer depends on A (D5).

**Already true** (background): the API signs browsers in with an opaque HttpOnly `SameSite=Lax` host-only
cookie and programs with bearer credentials; state-changing cookie requests must carry the frontend's
`Origin`; the artifact route answers a cookie-only GET with 307 (C1). **Missing:**

- Sign-in always lands on the frontend root (C3).
- Sign-in failures answer problem JSON to a top-level navigation (C13); a signed-out request gets JSON 401 (C2).
- Frontend and API share one origin, API paths at the root (C4). No frontend exists in the repo (C19).
- Three documents disagree on serving: platform §2.9, the links port (C5), deployment §5. The real server wires
  nothing yet (C6).
- Episode pages (learning job) have no API resource (C7). The lessons page builds its markup in the browser
  (C20); queue data has no API and lives only on the learning host (C15).
- The ticket write-back links nothing of ours (C11); the job has its investigation id (C21) but not the
  frontend's origin (C14).

## Principles

Inherits `docs/principles.md` and the approved deployment design §2, §5 and its B-properties as binding,
except the amendments listed below for the owner. Owner decisions (2026-11-14): analysts have accounts; the
ticket should carry enough that they rarely need the platform, but a link that asks them to sign in is
acceptable; every generated page is in scope, as groundwork for a proper frontend; A and B stated separately.

Proposed design properties:

- **P1. Only the frontend is a landing place.** Every address handed to a person is a frontend address. The
  API answers code, never a person: its one navigation endpoint, the sign-in callback, always ends in a
  redirect to a frontend address (the return path, or a sign-in-failed screen with the reason code). The
  artifact host answers every refusal a person can reach (a page address without a valid cookie, any `/_open`
  refusal, a missing page) with a 303 to the page's frontend address carrying a reason — built only from
  verified fields (the request's tenant host plus a kind-table-matched path, or a verified grant); a grant
  that fails verification goes to a fixed frontend "refused" screen.
  *Why:* one owner for "what a person sees when not signed in or refused".
- **P2. A person lands where they were going.** Sign-in carries a return path: a relative frontend path,
  checked at login and again at the callback (refused: not one leading `/`, `//`, `/\`, control characters,
  the API prefix), encoded so it cannot collide with the pre-login cookie's separators (C16).
- **P3. Untrusted pages are top-level documents on the artifact domain only** (deployment §5).
- **P4. The API grants; the artifact server verifies.** The API decides who may open which owner's output
  and signs a grant naming tenant, owner, the accepted output's storage prefix, issue time and expiry. The
  artifact server holds the grant-verifying key, its own cookie-signing key and blob read access, never the database.
- **P5. What may be served is decided by name pattern, not by a stored list.** The owner's accepted output is
  the prefix the store's acceptance recorded (deployment: claim-scoped keys made the run's by a database
  transaction). Within it, the artifact server serves only entry names that match its closed kind table; every
  other name is 404 without touching blob. Session database, logs and other records match no pattern.
- **P5a. A page name holds only what our renderer wrote in this job.** The box can write the run folder
  (C25), so a file at a page's name may be model-planted. The page savers remove the page's name before
  rendering (a failed render leaves nothing, which is then "not available"), and the push takes page-kind
  names only from the renderer's own save in this job, never from whatever is in the folder. Sound because
  no box can still write when the page is saved (C27: shown for investigations, owed for episodes). Closes
  the same hole in today's dev mirror.
- **P6. The serving layer, not the bytes, decides what a file may do.** The kind table gives each pattern a
  kind: a generated page (HTML under the page CSP), text (`text/plain`), JSON (`application/json`). One response
  rule applies to every artifact-server response (A5).
- **P7. One audit event per grant.** Files fetched under the bundle cookie are not audited one by one.
- **P8. Our page scripts write no markup from data** (no `innerHTML`, `document.write`, `insertAdjacentHTML`),
  so hostile HTML on the page cannot reuse them. Holds for `runtime.js` (C22); the lessons page violates it
  (C20), which is one reason D3 retires it.

## Intent (obligations)

Part B — signing in and navigating:

- **B1.** Any frontend address followed while signed out leads through sign-in and back to it (path and query
  kept).
- **B2.** The return path is checked per P2; a refused one falls back to the root.
- **B3.** The API lives under `/api` on the shared origin, the frontend owns every other path. Every `Location`
  and redirect the API builds carries the prefix (today `create_tenant`'s would not, C17). Moved with it: the
  identity provider's registered redirect URL, bearer clients' base URL, operator docs quoting `/admin/...`.
- **B4.** Every callback outcome is a redirect to a frontend address (P1), failures carrying the existing
  reason codes.
- **B5.** The frontend's code calls the API with the session cookie only; no token in the page, no CORS.
- **B6.** The ticket write-back links the investigation's frontend address `/t/<T>/investigations/<I>`, built
  from the frontend origin (passed to the job by the worker with its settings) and the job's investigation id.
  The address needs nothing from part A and is valid before the run's output is accepted; what it shows
  until a real investigation screen exists does (D5). A run with no investigation
  (an operator run) writes no link. A rerun is a new investigation with its own link.

The page opener — the seam:

- **O1.** Every page has a frontend address `/t/<T>/<owner>/<id>/pages/<entry>`. On a fresh entry with no
  reason, the opener asks the API for a grant (`POST /api/tenants/<T>/<owner>/<id>/page-grants {entry}`,
  Origin-checked; 401 → B1) and submits it as a top-level form POST to `https://<T>.<artifact-domain>/_open`.
  The grant never appears in a URL. Before submitting it marks its history entry (so Back does not re-submit).
- **O2.** The opener auto-submits only on a fresh entry with no reason. If it loads with a reason, on its own
  marked history entry, or returning from sign-in (it gives sign-in a return path carrying `after=signin`,
  which counts as a reason), it shows the reason ("not available yet", "reopen", "refused") and an Open button.
  The host cannot tell an expired cookie from a blocked one, so neither retries automatically. This bounds every
  loop to one automatic attempt.
- **O3.** The artifact host's page addresses are logical, `/<owner>/<id>/<entry>`. Without a valid bundle
  cookie for that owner a page address 303s to its frontend address with a reason (reload, bookmark, a sibling
  after expiry, session restore). A non-page entry without a valid cookie is 404.
- **O4.** The grant route refuses (404) a caller who is not an active member, an owner not visible, or an owner
  with no accepted output yet; the opener shows that as "not available yet".
- **O5.** The `GET .../artifacts/{key}` 307 route is replaced by the grant route. Program access to artifacts is
  out of scope.
- **O6.** This issue ships the minimal frontend pieces the seam needs: the opener page, the sign-in-failed
  page, and the signed-out rule (B1) — plus a headless-browser end-to-end check of the whole flow (D7).

Part A — untrusted pages:

- **A1.** `/_open` accepts a grant only with `Origin` equal to the frontend origin, a valid signature, the
  hostname's tenant, and an unexpired time; it sets the bundle cookie and 303s to the logical address. Any
  refusal follows P1.
- **A2.** The bundle cookie: `__Secure-`, host-only, `HttpOnly`, `Secure`, `SameSite=Lax` (never `Strict`: the
  cookie must ride the 303 that follows the cross-site POST), `Path=/<owner>/<id>/`, 15 minutes (D2). Its signed
  value binds hostname, tenant, owner, storage prefix and expiry.
- **A3.** Under the cookie, relative links to other entries of the same owner's output work. A learning job's
  episode page and its siblings' run pages are all in the learning job's own accepted output (the episode is
  produced inside the job, C23), at `runs/<arm>/runtime.html` relative to the episode page.
- **A4.** Owners with pages: investigations (the run page, its report, its raw query results) and learning jobs
  (the episode page, its siblings' run pages).
- **A5.** The response rule, on every artifact-server response: `Cache-Control: private, no-store`;
  `X-Content-Type-Options: nosniff`; `Referrer-Policy: no-referrer`; non-page responses `Content-Security-Policy:
  default-src 'none'; sandbox`; pages the page CSP. The edge bypasses its cache for the artifact domain.
- **A6.** The page CSP for the existing renderers: `default-src 'none'`; `script-src` the fingerprints of our
  shipped page scripts (a script found defective is removed; old pages using it lose interactivity, accepted);
  `style-src 'unsafe-inline'` (inline `<style>` and `style=` attributes, C18; with no network allowed, injected
  CSS cannot send anything out); `img-src data:`; `frame-ancestors 'none'`; `form-action 'none'`;
  `base-uri 'none'`.
- **A7.** A pattern-matched entry whose object is missing is "not available" (a page: 303 to its frontend
  address, P1; any other entry: 404); no entry is "required" (a run
  or episode may lawfully finish without its page: render failures only warn, C26). `/_open` checks that the
  entry exists before setting the cookie; if not, 303 to the frontend address with "not available". Losing a
  stored object is detected at push or acceptance (#1082 precondition), not at serving.
- **A9. The kind table**, per owner kind, patterns anchored to the whole entry name (no `..`, no encoded
  separators, exact case):

  | Owner | Entry | Kind |
  |---|---|---|
  | investigation | `runtime.html` | page |
  | investigation | `report.md` | text |
  | investigation | `gather_raw/<lead>/<seq>.json` (not `gather_raw/<lead>.lead.json`) | JSON |
  | learning job | `learning.html` | page |
  | learning job | `runs/<run id>/runtime.html` | page |

  Anything else is 404 without a blob read.
- **A8.** Issued grants are audited (P7).

Preconditions owed by #1082 (and the deployment's "run evidence into blob" item): acceptance closes the
claim's pushes, or objects are create-only; pages are pushed by the owning job before acceptance and sit under
its accepted prefix; store loss is detected at push or acceptance.

Non-obligations: choosing the blob backend; moving run and episode output into blob and recording its
acceptance (#1082 and the deployment's "run evidence into blob" work item); a full frontend; model-written HTML;
program access to artifacts; lessons and queues app screens and their API reads (D3).

## Design

### Data model and ownership

- **Accepted output** (owned by the store, #1082): per owner, the claim-scoped storage prefix the acceptance
  transaction made the owner's. The API reads it to build a grant; it is the only record of what an owner's
  output is.
- **Grant** (not stored): signed by the API (deployment §2 "blob signing key"): tenant, owner kind and id,
  prefix, entry, issue time, expiry (60 s).
- **Bundle cookie** (not stored): signed by the artifact server, scope as A2.
- **Kind table** (code, artifact server): entry name pattern → kind (A9).
- **Ports while #1082 is unbuilt:** the API reads an owner's accepted output through a port (fake: an in-memory
  map owner → prefix, or none); the artifact server reads objects through a blob-reader port (fake: a local
  directory). Contract tests run against both fakes; #1082 supplies the real ones.

### Flows

Ticket link, signed out: analyst opens `/t/T/investigations/I` → frontend calls `/api/me` → 401 →
`/api/auth/login?return=/t/T/investigations/I` → identity provider → callback sets session, 303 to the path.
Until a real investigation screen exists, the frontend routes that address to the run page's opener (D5), so
the analyst lands on the run page, or on "not available yet" before the output is accepted.

Opening a run page: `/t/T/investigations/I/pages/runtime.html` → grant POST → form POST `/_open` → cookie, 303 →
`https://T.<artifact-domain>/investigations/I/runtime.html`.

Episode sibling: episode page links `runs/<arm>/runtime.html` → same owner, same cookie. After expiry → 303 to
the sibling's frontend address with reason `reopen` → the opener shows the Open button (one click) → page.

### Amendments to binding text (for the owner to confirm)

- Deployment §5 "short-lived, one-time link" → a short-lived grant posted in a form body, not single-use (D4).
- Deployment §2 "logout and membership changes take effect at once" → for open pages, within the cookie's
  15 minutes (D2).
- Platform §2.9 (stream or redirect, links rewritten through the API) and the links port's "blob store's own
  origin" → the page opener and artifact server above.
- Platform §2.10 "all artifact reads are audit events" → one audit event per grant (P7).
- #1161's second "done when" (a cookie-only navigation reaches the redirect) is retired: the route is replaced.
- The 307 artifact route and its four tests (`tests/api/test_api_stub.py:855-880, 1889`) are replaced (O5).

## Choices for the owner

- **D2. How long an open page stays authorized after logout or losing membership.** Recommended 15 minutes,
  no per-file check (the artifact server stays out of the database). Alternative: per-file check against the
  session, immediate, makes the artifact server a database client.
- **D3. Lessons and queues.** This narrows your "every page in scope": these two stay in scope as frontend
  screens, not as served pages. Recommended: they become app screens over API reads in a follow-up issue, and
  their generated pages retire when that lands (dev users keep today's views until then; production has
  neither today). The lessons page builds markup in the browser (fails P8 and the page CSP), queue data exists only on
  the learning host, and a tenant-level page would need a renderer on the trusted side, against the
  deployment's rule that renderers run confined. The reads and screens go to a follow-up issue. Alternative:
  rewrite the lessons page server-side and add a confined per-tenant publishing job and a tenant output owner.
- **D4. Single-use grants.** Recommended: drop single use. It was asked for when grants sat in URLs; here a grant
  lives 60 s, only in a form body, bound to one tenant host and the frontend origin. Alternative: keep it with a
  used-id object created conditionally in blob (works across replicas, no database).
- **D5. Split.** B (return path, failure redirects, `/api`) is independent of A and small; A (artifact server,
  grants, CSP, opener) waits on #1082's accepted output. Recommended: the ticket link (B6) ships with A, and
  until a real investigation screen exists the frontend routes `/t/T/investigations/I` to that run page's
  opener. Alternative: B also ships a minimal investigation screen over the existing investigation read, so the
  link can ship first.
- **D6. Cut against #1082.** This issue builds part A against the two ports above with fakes and places
  three preconditions on #1082 (listed under Intent). Alternative: wait for #1082's real acceptance before
  building A.
- **D7. Frontend ownership.** No frontend exists. Recommended: this issue ships only the opener page, the
  sign-in-failed page and the signed-out rule (O6), as the first frontend code; screens come later.

## Grounding

```yaml
claims:
  - id: C1
    kind: behavior
    claim: "The API answers a cookie-only GET of the artifact route with no Origin header (and with a cross-site Origin) with 307 to the signed link."
    probe: "scratchpad probe_nav.py using tests/api/test_api_stub.Api in-process TestClient at 77e36c0ac"
    probe_kind: executed
    observed: "cookie only, no Origin 307 https://blobs.invalid/signed?sig=1; cookie + cross-site Origin 307; nothing 401 application/problem+json"
    verdict: holds
  - id: C1b
    kind: behavior
    claim: "A real browser attaches the Lax session cookie on a cross-site top-level click to the API address."
    probe: "none run (no headless browser in this pass); browser SameSite=Lax semantics"
    probe_kind: read
    observed: "not executed"
    verdict: unprobed
  - id: C2
    kind: behavior
    claim: "A request with no session answers 401 problem+json, no redirect."
    probe: "same probe as C1, 'nothing' case"
    probe_kind: executed
    observed: "401 application/problem+json"
    verdict: holds
  - id: C3
    kind: referential
    claim: "Sign-in has no return target: /auth/login takes no parameter and the callback 303s to deps.frontend_origin."
    probe: "read defender/api/app.py:667-697; defender/identity/service.py:382 begin_signin(self)"
    probe_kind: read
    observed: "begin_signin() has no arguments; RedirectResponse(deps.frontend_origin, 303)"
    verdict: holds
  - id: C4
    kind: referential
    claim: "Frontend and API share one origin in deployment; the API sends no CORS headers and has no path prefix."
    probe: "read defender/api/demo.py:55-58; grep -rn 'root_path|CORSMiddleware|/api/' defender/api defender/api_server"
    probe_kind: search
    observed: "demo comment: 'as in deployment, where the proxy serves both on one origin'; no root_path, no CORS, routers at /tenants/{tenant_id}, /auth, /me, /admin"
    verdict: holds
  - id: C5
    kind: referential
    claim: "The links port and artifact route promise a signed link on the blob store's own origin."
    probe: "read defender/api/ports.py:237-240, defender/api/app.py:522-540"
    probe_kind: read
    observed: "ArtifactLinks.signed_url docstring and read_artifact docstring"
    verdict: holds
  - id: C6
    kind: referential
    claim: "The real server wires artifact links to an unbuilt piece."
    probe: "read defender/api_server/_program.py:189"
    probe_kind: read
    observed: "artifact_links=piece_2"
    verdict: holds
  - id: C7
    kind: referential
    claim: "Only investigations carry an artifacts list in the API models."
    probe: "grep -n artifacts defender/api/models.py"
    probe_kind: search
    observed: "one hit, models.py:143 (Investigation)"
    verdict: holds
  - id: C8
    kind: census
    claim: "HTML-producing renderers are visualize_run (run page), visualize_episode (+episode_verdict, episode_worlds) and lessons_page (lessons, queues); run page inlines CSS and one fixed script with data islands; episode page has no script and links to sibling run pages by relative path runs/<arm>/runtime.html."
    probe: "grep -rln '.html|<html|<!doctype' --include=*.py defender (non-test); grep '<script|href=|src=' in those files"
    probe_kind: search
    observed: "visualize_run.py:598,615; visualize_runtime.py:211; visualize_episode.py:595-603; episode_worlds.py:254; episode_models.py:256; lessons_page.py:113-125,321-330; publisher.py layout"
    verdict: holds
  - id: C9
    kind: referential
    claim: "The lessons and queues pages embed data in their inline script (const DATA = __LESSONS_JSON__)."
    probe: "read defender/presentation/lessons_page.py:120-130"
    probe_kind: read
    observed: "inline <script> with const DATA = ...; script text varies per page"
    verdict: holds
  - id: C10
    kind: referential
    claim: "The run page is rendered inside the job and saved in the run folder; the host helper copies it after exit."
    probe: "read defender/presentation/visualize_run.py:125-141; defender/job_host/_common.py:177-189; job_host/_learning.py:276-318"
    probe_kind: read
    observed: "runtime_html record saved via run handle; mirror_run_page copies to publish area; sibling pages copied from the job's episode"
    verdict: holds
  - id: C11
    kind: referential
    claim: "The ticket write-back posts a comment and records the ticket's own web link; no run-page link is written."
    probe: "read defender/investigation/ticket_writer.py:260-370"
    probe_kind: read
    observed: "receipt url is 'the ticket's web link'"
    verdict: holds
  - id: C12
    kind: referential
    claim: "Artifact-read audit is pinned per key at link issue."
    probe: "read defender/tests/api/test_api_stub.py:855-880, 1889"
    probe_kind: read
    observed: "test_an_artifact_read_redirects_to_the_signed_link_and_is_audited, ..._link_fails_is_not_audited, ..._not_handed_out_unless_its_read_is_audited, test_1083_only_the_artifact_read_announces_through_the_audit_port"
    verdict: holds
  - id: C13
    kind: referential
    claim: "The sign-in callback answers its failures as problem JSON (403 with four reason types, 503) to a top-level navigation."
    probe: "read defender/api/app.py:681-697"
    probe_kind: read
    observed: "CallbackRefused -> problem(403, type urn:defender:problem:<reason>); SignInUnavailable -> problem(503)"
    verdict: holds
  - id: C14
    kind: referential
    claim: "The ticket write-back runs inside the job; the frontend origin exists only in the API's wiring."
    probe: "read defender/run.py:1393; grep frontend_origin defender (non-test)"
    probe_kind: search
    observed: "record_case_ticket called from run.py; frontend_origin only in api/ports.py:266, api/demo.py, api/serve.py"
    verdict: holds
  - id: C15
    kind: census
    claim: "No API route exposes learning queue data; /lessons is declared but unbacked."
    probe: "grep -n 'queue' defender/api/app.py; read app.py:583"
    probe_kind: search
    observed: "only docstring mentions; lessons router responses=_UNBACKED"
    verdict: holds
  - id: C16
    kind: referential
    claim: "The pre-login cookie is the unsigned value state.nonce.verifier and the callback requires exactly three dot-separated parts."
    probe: "read defender/identity/service.py:382-392"
    probe_kind: read
    observed: "as claimed (verified by reviewer and sorter)"
    verdict: holds
  - id: C17
    kind: behavior
    claim: "Under a FastAPI root_path, app.url_path_for omits the prefix while request.url_for includes it; create_tenant's Location uses url_path_for."
    probe: "reviewer probe scratchpad/rp.py; read defender/api/app.py:853"
    probe_kind: executed
    observed: "url_for -> /api/tenants/a; url_path_for -> /tenants/a"
    verdict: holds
  - id: C18
    kind: referential
    claim: "The run page renderers emit inline style= attributes."
    probe: "grep -c 'style=\"' defender/presentation/*.py"
    probe_kind: search
    observed: "visualize_run.py:2, visualize_runtime.py:3"
    verdict: holds
  - id: C19
    kind: census
    claim: "The repository has no frontend; the demo only names http://localhost:3000 as its origin."
    probe: "ls /workspace; grep -rn frontend_origin defender (non-test); reviewer and sorter r2 searches"
    probe_kind: search
    observed: "no frontend package; demo.py:58 DEMO_FRONTEND_ORIGIN"
    verdict: holds
  - id: C20
    kind: referential
    claim: "The lessons page builds its markup in the browser with innerHTML."
    probe: "read defender/presentation/lessons_page.py:210"
    probe_kind: read
    observed: "document.getElementById('root').innerHTML = ... (verified by reviewer r2 and sorter)"
    verdict: holds
  - id: C21
    kind: referential
    claim: "An investigation's job knows its investigation id: the helper launches run.py --job <inv> and the run folder is <T>/runs/<inv>."
    probe: "read defender/job_host/_investigation.py:78-79"
    probe_kind: read
    observed: "as claimed (reviewer r2)"
    verdict: holds
  - id: C22
    kind: referential
    claim: "runtime.js is inlined from assets, loads nothing and writes no markup; it sets location.hash, title and classes."
    probe: "read defender/presentation/assets/runtime.js; visualize_run.py:381,615"
    probe_kind: read
    observed: "as claimed (reviewer r2)"
    verdict: holds
  - id: C23
    kind: referential
    claim: "A learning job's sibling runs are produced inside the job's own episode; sibling run pages sit at runs/<run dir>/runtime.html relative to the episode page."
    probe: "read defender/job_host/_learning.py:298-318; defender/records/_episode_paths.py:421"
    probe_kind: read
    observed: "siblings opened from the job's episode by id; relative path as claimed. Blob layout under #1082 not yet built: obligation, not fact."
    verdict: holds
  - id: C25
    kind: referential
    claim: "The box mounts the run folder read-write and the scrub permits ordinary files, so a file at runtime.html may be box-written; a successful render replaces it, a failed one leaves it."
    probe: "read defender/box/_lifecycle.py:120; defender/box/_scrub.py _PERMITTED; visualize_run.py:124-141"
    probe_kind: read
    observed: "readonly=False; regular files permitted (reviewer r3, sorter spot-check)"
    verdict: holds
  - id: C26
    kind: referential
    claim: "A failed run-page or episode-page render only warns; the run or launch still completes."
    probe: "read defender/run.py:1257-1261; defender/learning/branch/cli.py:1050-1058"
    probe_kind: read
    observed: "VisualizeFailed caught and logged; learning.html failure logged, not raised"
    verdict: holds
  - id: C27
    kind: reachability
    claim: "No box can still write when a page is saved: for an investigation the box is proven stopped and its tree scrubbed before save_page runs; for a learning job's episode page, the same holds for every sibling box."
    probe: "read defender/run.py:1230-1270 (TEARDOWN_FAULTED returns before any read; visualize after scrub); learning side not read"
    probe_kind: read
    observed: "investigation: box stopped and scrubbed first, so only a leftover file (failed render) is a risk; episode: not probed"
    verdict: unrefuted
  - id: C24
    kind: behavior
    claim: "A browser stores a SameSite=Lax cookie set on the response to a cross-site top-level form POST and sends it on the following 303 GET; the form POST carries Origin equal to the frontend origin under the frontend's Referrer-Policy (not null); the frontend's CSP must allow form-action to the artifact domain."
    probe: "none run; RFC 6265bis and HTML spec reading by reviewer r2; no headless browser here (no chromium binary, no playwright in the venv)"
    probe_kind: read
    observed: "not executed; owed to the O6 headless-browser check, which write-tests must add (install a pinned headless Chromium)"
    verdict: unprobed
```

C1b is no longer load-bearing: under the page opener no person navigates to an API address.

### Code map

- Login/session: `defender/api/app.py:84-85` cookie names; `:103-112` `_way_in`; `:122-141` origin check;
  `:661-705` `/auth/login`, `/auth/callback`, `/auth/logout`; `defender/identity/service.py:382` `begin_signin`.
- Artifact route: `defender/api/app.py:522-540`; port `defender/api/ports.py:237-240`; fake
  `defender/api/fakes.py:355-361`; real wiring `defender/api_server/_program.py:189`.
- Tenant prefix router: `defender/api/app.py:974`; frontend origin setting `defender/api/ports.py:266`.
- Renderers: `defender/presentation/visualize_run.py:125-141, 596-617`; `visualize_episode.py:585-603`;
  `episode_worlds.py:250-255`; `lessons_page.py:110-130, 318-330`; assets `presentation/assets/runtime.js`.
- Publishing (dev): `defender/presentation/publisher.py`; `defender/job_host/_common.py:177-189`;
  `job_host/_learning.py:276-318`.
- Ticket write-back: `defender/investigation/ticket_writer.py:260-370`.
- Tests: `defender/tests/api/test_api_stub.py` (`Api` harness, `AUTH` cookie headers at :84-92, artifact
  tests :855-880, :1889); real server `defender/tests/api/test_1083_real_server.py`.
- Sign-in callback failures `defender/api/app.py:681-697`; pre-login cookie `defender/identity/service.py:382-392`;
  `create_tenant` Location `defender/api/app.py:853`; ticket write-back call `defender/run.py:1393`;
  sibling link `defender/presentation/visualize_episode.py:293-296`; queues page rendering `lessons_page.py:330-334, 444`.
- Settled design: `defender/docs/decisions/vps-compose-deployment.md` §2 (:244-276), §5 (:445-473), work order
  (:598-604); `defender/docs/platform-design.md` §2.9 (:322-327).
