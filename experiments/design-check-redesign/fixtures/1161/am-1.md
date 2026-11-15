## Amendment Am-1 (owner rulings, 2026-11-14, during write-tests §1)
- The frontend is TypeScript with a build step, rendered in the browser (CSR); built to static files. No SSR. UI framework: not ruled (agent-local unless it changes the contract).
- The ingress is Caddy. Its config lives in the repo; it serves the built frontend files with B9's headers and routes `/api` to the API. The browser end-to-end checks run through that Caddy config.
- Browser checks: Playwright for Python, under pytest / defender-pytest, pinned headless Chromium.

