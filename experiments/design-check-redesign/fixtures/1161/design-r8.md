# #1161 — Browser access: signing in, moving around, and opening untrusted pages

Revision r8 (current; supersedes r7; r8 = r7 with the owner's decisions on D3–D6 of 2026-11-14 and the page
sandbox that settles D5). r7 (superseded): r7 = r6 plus the sort of its narrow review, `review-r6.md`, `sort-r6.md`).
r6 (superseded): r5 = r4 plus the owner's decisions of 2026-11-14 (below): the work splits
in two, the run-page half folds into #1082's artifact piece, and each pass and cookie covers one page. r6 = r5 plus
the fixes from its independent review and sort (`review-r5.md`, `sort-r5.md`).
Grounding base: `77e36c0ac` (main); r5 additions checked at `bdc39ca80`.

## Problem and intended change

People use the product through a browser: analysts follow the link on their own ticket, app users browse
alerts and investigations, and both open what the system generates — a run's page, a learning job's episode
page (which links to each sibling run's page), the lessons and queues views. Generated pages are built from
attacker-influenced content and must never act with the viewer's authority.

Two related questions, kept explicit, and now two pieces:

- **Piece 1 — signing in, navigating, calling the API** (stays in #1161). How a person reaches any screen by a
  link, signs in if needed, lands where they were going, and how the frontend's code calls the API.
- **Piece 2 — serving untrusted pages** (folds into #1082's artifact piece). Where generated HTML is served, how
  a page is authorized, and what the serving layer guarantees about what the bytes may do.

They share no storage model: piece 1 touches identity, routing and the ticket write-back; piece 2 depends on
#1082's accepted output, its push and its blob layout. They meet at the frontend: piece 2's page opener is a
frontend screen and relies on piece 1's signed-out rule. Piece 1 ships first and leaves the system working.

**Already true** (background): the API signs browsers in with an opaque HttpOnly `SameSite=Lax` host-only
cookie and programs with bearer credentials; state-changing cookie requests must carry the frontend's
`Origin`; the artifact route answers a cookie-only GET with 307 (C1); the real server backs investigation reads
(C28). **Missing:**

- Sign-in always lands on the frontend root (C3).
- Sign-in failures answer problem JSON to a top-level navigation (C13); a signed-out request gets JSON 401 (C2).
- Frontend and API share one origin, API paths at the root (C4). No frontend exists in the repo (C19).
- Three documents disagree on serving: platform §2.9, the links port (C5), deployment §5. The real server wires
  nothing yet (C6), and its audit port refuses (C28).
- The lessons page builds its markup in the browser (C20); queue data has no API and lives only on the learning
  host (C15).
- The ticket write-back links nothing of ours (C11); the job has its investigation id (C21) but not the
  frontend's origin (C14).

## Principles

Inherits `docs/principles.md` and the approved deployment design §2, §5 and its B-properties as binding,
except the amendments listed below.

Owner decisions:
- (2026-11-14, earlier) Analysts have accounts; the ticket should carry enough that they rarely need the
  platform, but a link that asks them to sign in is acceptable; every generated page is in scope, as groundwork
  for a proper frontend; the two questions are stated separately.
- (2026-11-14) **Split and fold.** Piece 1 stays in #1161; piece 2 folds into #1082's artifact piece, whose
  design pass takes the shared decisions below as settled. This also removes r4's fake ports, which #1496
  (no second implementation of the store's ports) forbids.
- (2026-11-14) **One page per pass and per cookie.** Stale access after logout or losing membership is accepted
  for up to the cookie's 15 minutes because it is limited to reloading pages already opened.

### Shared decisions (cross the cut)

- **S1. Only the frontend is a landing place.** Every address handed to a person is a frontend address. The API
  answers code, never a person: every outcome of a browser navigation to the API that ends on our side ends in
  a 303 to a frontend address — sign-in start's failures and every outcome of the callback (sign-in start's
  success is a 302 to the identity provider). Sign-in happens automatically at most once per attempt (B1).
  The artifact host answers every refusal a person can reach with a 303 to the page's
  frontend address carrying a reason, built only from verified fields (the request's tenant host plus a
  kind-table-matched path, or a verified grant); a grant that fails verification goes to a fixed frontend
  "refused" screen. *Why:* one owner for "what a person sees when not signed in or refused".
- **S2. Frontend addresses.** `/t/<T>/investigations/<I>` is an investigation's screen (piece 1).
  `/t/<T>/<owner>/<id>/pages/<entry>` is a page's opener (piece 2), with `<owner>` one of `investigations`,
  `learning-jobs`. The API lives under `/api`; the frontend owns every other path.
- **S3. A person lands where they were going** (piece 1's P2): any frontend address, the opener's included,
  survives sign-in.
- **S4. Untrusted pages are top-level documents on the artifact domain only** (deployment §5), each opened under
  its own pass.

## Piece 1 — signing in and navigating (#1161)

### Properties

- **P2. A person lands where they were going.** Sign-in carries a return path: a relative frontend path,
  checked at login and again at the callback (refused: not one leading `/`, `//`, `/\`, control characters,
  the API prefix, longer than 1024 bytes), encoded so it cannot collide with the pre-login cookie's separators
  (C16; opener entries such as `runtime.html` contain the `.` separator).

### Obligations

- **B1.** Any frontend address followed while signed out leads through sign-in and back to it (path and query
  kept). The loop bound lives in the tab, not the URL: before sending the browser to sign-in, the frontend
  records an attempt in `sessionStorage`. A screen reads that record once at load and deletes it; if it was
  there and the load's first API answer is still 401, the screen shows sign-in-failed instead of redirecting.
  If storage is unavailable, the frontend does not redirect automatically: it shows the failed screen with its
  button. The failed screen makes no authenticated call at load, and its retry uses its kept return path, never
  its own address. Nothing is added to a shareable address.
- **B2.** The return path is checked per P2; a refused one falls back to the root.
- **B3.** The API lives under `/api` on the shared origin. Every `Location` and redirect the API builds carries
  the prefix (today `create_tenant`'s would not, C17). Moved with it: the identity provider's registered
  redirect URL (#1498), bearer clients' base URL, operator docs quoting `/admin/...`. The existing 307 artifact
  route moves with everything else; piece 2 replaces it.
- **B4.** Sign-in start's failures and every outcome of the callback are a 303 to a frontend address (S1): the
  return path, or the sign-in-failed screen with the existing reason codes, sign-in start's "unavailable"
  included (today the callback's success goes to the root and its refusals are 403 or 503 problems, C13). On a
  missing or mismatched pre-login cookie the callback never uses a cookie's return path: sign-in-failed, retry
  from the root (D6).
- **B5.** The frontend's code calls the API with the session cookie only; no token in the page, no CORS.
- **B6.** The ticket write-back links the investigation's screen `/t/<T>/investigations/<I>`, built from the
  frontend origin (passed to the job by the worker with its settings) and the job's investigation id. A run
  with no investigation (an operator run) writes no link. A rerun is a new investigation with its own link.
- **B7. The minimal investigation screen** shows the investigation's status and outcome from the existing
  investigation read. It is where the ticket link lands; piece 2 adds its "open run page" action.
- **B8.** This piece ships the first frontend code: the signed-out rule (B1), the sign-in-failed screen (B4) and
  the investigation screen (B7), plus a headless-browser end-to-end check of sign-in from a ticket link
  (including the 401-after-sign-in case of B1, and any frontend address opened signed out in a new tab).
- **B9. The frontend's response headers** (the frontend's counterpart to A5): CSP `form-action 'self'
  https://*.<artifact-domain>` (the browser re-checks it on every redirect of a form navigation, so `/_open`'s
  redirects back to the frontend must be allowed); `Referrer-Policy: strict-origin-when-cross-origin`, never
  `no-referrer` or `same-origin` (they make a cross-origin POST's Origin `null`, and A1 would refuse every open);
  the ingress serves the app for every path outside `/api`.

Non-obligations: a full frontend; lessons and queues screens (D3); anything served from the artifact domain.

### Flow

Ticket link, signed out: analyst opens `/t/T/investigations/I` → frontend calls `/api/me` → 401 →
`/api/auth/login?return=/t/T/investigations/I` → identity provider → callback sets session, 303 to the path →
investigation screen.

## Piece 2 — serving untrusted pages (#1082's artifact piece)

### Properties

- **P4. The API grants; the artifact server verifies.** The API decides who may open which page and signs a
  grant naming tenant, owner, the accepted output's storage prefix, one entry, issue time and expiry. The
  artifact server holds the grant-verifying key, its own cookie-signing key and blob read access, never the
  database.
- **P5. What may be served is decided by name pattern, not by a stored list.** The owner's accepted output is
  the prefix the store's acceptance recorded (deployment: claim-scoped keys made the run's by a database
  transaction). Within it, the artifact server serves only entry names that match its closed kind table, and
  every kind-table entry is a page. Every other name is 404 without touching blob: report, raw query results,
  session database, logs and other records included (nothing links to them; C29).
- **P5a. A page name holds only bytes our renderer produced in this job.** The box can write the run folder
  (C25), so a file at a page's name may be model-planted, before or after rendering. The pusher takes a page's
  bytes only from its renderer's return value or result channel, never from the run or episode folder; the
  folder push leaves out every kind-table name. The page savers still remove the page's name before rendering,
  so a failed render leaves nothing ("not available"). Every page renderer holds its bytes and can return them
  (C32). *Why the return channel, not timing:* it holds whenever boxes stop, so it needs nothing from the
  launcher under k3s. *Scope:* this rules out a plant or swap between render and push; what hostile bytes the
  renderer was fed is the response rule's concern (P7, A5). When the renderer moves to the confined reader pod,
  the pod returns the page over its own result channel, never through the shared volume.
  **Opens for #1082's push design:** how a sibling run's page (rendered in its own `run.py` subprocess, whose
  only channel back today is its exit code) reaches the pusher — the sibling pushes it mid-job under the claim,
  or a pipe the parent opens carries the bytes — and whether pushes happen mid-job or once at the end. Neither
  may go through a box-writable volume.
- **P6. One page, one pass, one cookie.** A grant names one entry, and the cookie it buys covers that page's
  exact address only. Every page opened is its own grant. *Why:* after logout or losing membership, a browser
  can only reload pages it already had, for at most the cookie's lifetime.
- **P7. The serving layer, not the bytes, decides what a response may do.** One response rule (A5).
- **P8. One audit event per page opened** (per grant). Pages cannot navigate without a click (A6's sandbox), so
  a grant follows a person's action: the opener, or a click on a link in a page.
- **P9. Our page scripts write no markup from data** (no `innerHTML`, `document.write`, `insertAdjacentHTML`),
  so hostile HTML on the page cannot reuse them. Holds for `runtime.js` (C22); the lessons page violates it
  (C20).

### Obligations — the page opener

- **O1.** On a page's frontend address, the opener asks the API for a grant (`POST
  /api/tenants/<T>/<owner>/<id>/page-grants {entry}`, Origin-checked; 401 → B1) and submits it as a top-level
  form POST to `https://<T>.<artifact-domain>/_open`. The grant never appears in a URL. Before submitting it marks
  its history entry (so Back does not re-submit).
- **O2.** The opener auto-submits on a fresh entry with no reason or with reason `open`. On any other reason
  (`blocked`, `not-available`, `refused`) or on its own marked history entry, it shows the reason and an Open
  button. A 401 from the grant route goes through B1, whose own bound applies. The `blocked` message does not claim cookies are blocked: an expired
  cookie gives the same reason. This bounds every loop to one automatic
  attempt.
- **O3.** The artifact host's page addresses are `/<owner>/<id>/<entry>`. A page address without a valid cookie
  for that exact page 303s to its frontend address: with reason `open` normally (a sibling link, a bookmark, a
  reload after expiry), with reason `blocked` when the request carries the marker `/_open` adds to its redirect
  (`?opened=1`: the cookie was just set and did not come back — cookies blocked, or expiry in between).
- **O4.** The grant route refuses (404) a caller who is not an active member, an owner not visible, an owner with
  no accepted output yet, or an entry not in the kind table; the opener shows "not available yet".
- **O5.** The `GET /api/.../artifacts/{key}` 307 route and the links port are replaced by the grant route.
  Program access to artifacts is out of scope.
- **O6.** The investigation screen (B7) gains "open run page", linking the run page's frontend address.
- **O7.** A headless-browser end-to-end check (C24), under the real B9 headers and with third-party cookies
  blocked: open, reload, sibling link, Back, expiry, and one run per reason the artifact host and `/_open` can
  produce (`open`, `blocked`, `not-available`, `refused`), each ending on its frontend screen.

### Obligations — the artifact server

- **A1.** `/_open` accepts a grant only with `Origin` equal to the frontend origin, a valid signature, the
  hostname's tenant, and an unexpired time; it checks the entry exists, sets the page cookie and 303s to the page
  address with `?opened=1`. A missing entry 303s to the frontend address with `not-available`; any other refusal
  follows S1.
- **A2.** The page cookie: `__Secure-`, host-only, `HttpOnly`, `Secure`, `SameSite=Lax` (never `Strict`: it
  must ride the 303 after the cross-site POST), `Path=/<owner>/<id>/<entry>` (the exact page address, so an
  episode page's cookie does not reach `runs/...` below it), 15 minutes. Its signed value binds hostname,
  tenant, owner, storage prefix, entry and expiry; the server checks the entry equals the requested page. All
  page cookies share one name; the browser keeps one per path.
- **A3.** Owners with pages: investigations (the run page) and learning jobs (the episode page; its siblings'
  run pages, which are in the learning job's own accepted output, C23, at `runs/<run id>/runtime.html`).
  A sibling link from an episode page is a normal page address and goes through O3 → opener → its own grant.
- **A4. The kind table**, per owner kind, patterns anchored to the whole entry name (no `..`, no encoded
  separators, exact case):

  | Owner | Entry |
  |---|---|
  | investigation | `runtime.html` |
  | learning job | `learning.html` |
  | learning job | `runs/<run id>/runtime.html` |

  Anything else is 404 without a blob read. Matching is on the raw request path, never a decoded one; `<owner>`
  is checked against the closed set and `<id>` and `<run id>` against the UUID shape before any frontend
  redirect is built from them. The kind table is one module, imported by both the grant route (O4) and the
  artifact server.
- **A5.** The response rule, on every artifact-server response: `Cache-Control: private, no-store`;
  `X-Content-Type-Options: nosniff`; `Referrer-Policy: no-referrer`; pages the page CSP; every other response
  `Content-Security-Policy: default-src 'none'; sandbox`. The edge bypasses its cache for the artifact domain.
- **A6.** The page CSP for the existing renderers: `default-src 'none'`; `script-src` the fingerprints of our
  shipped page scripts (a script found defective is removed; old pages using it lose interactivity, accepted);
  `style-src 'unsafe-inline'` (C18; with no network allowed, injected CSS cannot send anything out);
  `img-src data:`; `frame-ancestors 'none'`; `form-action 'none'`; `base-uri 'none'`; `sandbox allow-scripts`
  (D5: a sandboxed document follows no `<meta http-equiv=refresh>`, opens no popups, submits no forms and gets an
  opaque origin with no storage; our scripts need none of these, C22). O7 adds two cases: `runtime.js` works
  sandboxed, and a click on a sibling link from a sandboxed page carries that page's Lax cookie (C33).
- **A7.** No page is "required": a run or episode may lawfully finish without its page (C26). Losing a stored
  object is detected at push or acceptance, not at serving.
- **A8.** Issued grants are audited (P8). The real server's audit port refuses today (C28). This piece builds
  the backed write: the existing `audit.announce` port (#1083 piece 1's shape: log events after commit) with a
  log-emitting implementation on the real server, unless #1470 lands it first.

### Decided inside #1082 (were r4's preconditions)

Acceptance closes the claim's pushes, or objects are create-only; pages are pushed by the owning job before
acceptance and sit under its accepted prefix; store loss is detected at push or acceptance.

### Data model

- **Accepted output** (#1082): per owner, the claim-scoped storage prefix the acceptance transaction made the
  owner's; the API reads it to build a grant.
- **Grant** (not stored): signed by the API with its own grant key, distinct from the deployment's blob signing
  key; the artifact server holds only the verifier. Fields: tenant, owner kind and id, prefix, entry, issue time,
  expiry (60 s).
- **Page cookie** (not stored): signed by the artifact server, scope as A2.
- **Kind table** (code, artifact server): A4.

### Flows

Opening a run page: investigation screen → `/t/T/investigations/I/pages/runtime.html` → grant POST → form POST
`/_open` → cookie, 303 → `https://T.<artifact-domain>/investigations/I/runtime.html?opened=1`.

Episode sibling: episode page links `runs/<arm>/runtime.html` → no cookie for that page → 303 to the sibling's
frontend address with `open` → opener auto-submits → own grant, own cookie → page. Back to the episode page: its
own cookie still holds for 15 minutes.

Reload after 15 minutes, or a bookmark (the address bar keeps `?opened=1`): no cookie → `blocked` → Open button
(one click).

## Amendments to binding text (for the owner to confirm)

- Deployment §5 "short-lived, one-time link" → a short-lived grant for one page posted in a form body, not
  single-use (D4); and §5's cookie "scoped to that tenant hostname and run" → scoped to one page's exact
  address; sibling pages go through the opener; pages load no relative files.
- Deployment §2 "logout and membership changes take effect at once" → for pages already open in a browser,
  within the cookie's 15 minutes (owner decision above).
- Deployment holdings table: add a row for the artifact server (grant-verifying key, its cookie key, blob read;
  reaches blob only).
- Platform §2.9 (stream or redirect, links rewritten through the API) and the links port's "blob store's own
  origin" → the page opener and artifact server above.
- Platform §2.10 "all artifact reads are audit events" → one audit event per grant obtained (P8).
- Deployment holdings: the API gains a grant-signing key separate from the blob signing key.
- #1161 is retitled to piece 1 and closes on piece 1 plus S1–S4. Its second "done when" (a cookie-only
  navigation reaches the redirect) moves to #1082 as retired: O5 replaces the route.
- The 307 artifact route and its four tests (`tests/api/test_api_stub.py:855-880, 1889`) are replaced (O5);
  #1496 deletes the fake links port they use.

## Owner decisions on the choices (2026-11-14)

- **D3. Lessons and queues** become app screens over API reads in a follow-up issue; their generated pages
  retire when that lands (dev users keep today's views until then; production has neither today). Why: the
  lessons page builds markup in the browser (fails P9 and the page CSP), queue data exists only on the learning
  host, and a tenant-level page would need a renderer on the trusted side.
- **D4. Grants are not single-use.** A grant lives 60 s, only in a form body, names one page, bound to one tenant
  host and the frontend origin; the lingering access after logout comes from the cookie, not the grant.
- **D5. Pages cannot navigate without a click:** the page CSP adds `sandbox allow-scripts` (A6). HttpOnly (already
  on every cookie) does not bear on this: the risk is navigation, not reading the cookie. What remains is a
  person clicking a link in a page, which P8 counts as their choice.
- **D6. One pre-login cookie per sign-in attempt,** named by a short prefix of its state,
  `Path=/api/auth/callback`, short lifetime; the callback reads and deletes only its own, so each tab completes to
  its own return path. A mismatched or missing one still never uses a cookie's return path (B4).

## Grounding

r4's claims C1–C27 hold unchanged at `77e36c0ac` (see `design-1161-r4.md`), except C1b (not load-bearing). Added:

```yaml
claims:
  - id: C28
    kind: referential
    claim: "The real server backs investigation reads with the job store; its artifact links and audit ports refuse."
    probe: "read defender/api_server/_program.py:181-188 at bdc39ca80"
    probe_kind: read
    observed: "investigations=ports (JobStorePorts); artifact_links=piece_2, audit=piece_2 (Refusing)"
    verdict: holds
  - id: C29
    kind: census
    claim: "The run page links to nothing outside itself; the episode page's only outward links are sibling run pages."
    probe: "grep -n 'href=' defender/presentation/visualize_run.py visualize_runtime.py visualize_episode.py episode_worlds.py at bdc39ca80"
    probe_kind: search
    observed: "run page: only '#...' anchors; episode: '#...' anchors and episode_worlds.py:254 entry.run_page"
    verdict: holds
  - id: C30
    kind: referential
    claim: "#1496's approved design forbids a second implementation of the store's ports and deletes fakes.py (StubArtifactLinks included)."
    probe: "gh issue view 1496 (design r1, O1-O2)"
    probe_kind: read
    observed: "O1 deletes serve.py, demo.py, fakes.py; O2 no second implementation of the store ports"
    verdict: holds
  - id: C31
    kind: referential
    claim: "Under the deployment design, boxes are pods on a volume shared with their job, and the job holds only its pass (no pod rights); the job pushes its rendered page."
    probe: "read defender/docs/decisions/vps-compose-deployment.md holdings table (:206-213), decision C, run-folder rows (:430-431)"
    probe_kind: read
    observed: "Job holds 'its pass', reaches 'proxy'; boxes as pods sharing a local-path volume; 'the helper's run-page mirroring moves into the job, which pushes the page'"
    verdict: holds
  - id: C24
    kind: behavior
    claim: "A browser stores a SameSite=Lax cookie with an exact-file Path set on the response to a cross-site top-level form POST and sends it on the following 303 GET to that path (with a query); the form POST carries Origin equal to the frontend origin (not null) under B9's Referrer-Policy; B9's form-action allows the POST and its redirects back to the frontend."
    probe: "none run; RFC 6265bis path-match and HTML spec reading; no headless browser here"
    probe_kind: read
    observed: "not executed; owed to O7, which write-tests must add (install a pinned headless Chromium)"
    verdict: unprobed
```

C27 is no longer load-bearing: P5a rests on the renderer's return channel, not on box lifetime.

```yaml
  - id: C32
    kind: referential
    claim: "Each page renderer holds its bytes and can return them: save_page returns the text and publish_page passes it on; render_episode returns only a Path (_write_page drops the bytes) and the PageRenderer seam's result is discarded, so that seam must be widened to return the encoded bytes."
    probe: "read defender/presentation/visualize_run.py:124-150; visualize_episode.py:540-560; learning/branch/cli.py:59, 332, 564, 1055 (reviewer r6, sorter r6 spot-check at bdc39ca80)"
    probe_kind: read
    observed: "as claimed; siblings are separate run.py subprocesses rendering in place under runs/<R>/runtime.html"
    verdict: holds
  - id: C33
    kind: behavior
    claim: "A document under CSP `sandbox allow-scripts` does not follow a meta refresh, and a top-level click from it to a same-site sibling address carries a SameSite=Lax cookie set for that path."
    probe: "none run; HTML spec (sandboxed automatic features flag; navigation from an opaque origin) and RFC 6265bis Lax top-level GET; no headless browser here"
    probe_kind: read
    observed: "not executed; owed to O7"
    verdict: unprobed
```

### Code map

As r4, plus: real server ports `defender/api_server/_program.py:181-188`; deployment holdings table and
run-folder rows `defender/docs/decisions/vps-compose-deployment.md:206-213, 422-440`.
