// The app shell (#1161 B1): it owns the signed-out rule, not each screen.
//
// On every load, and on every `pageshow` with `persisted` set, it reads and deletes this tab's attempt record, asks
// `/api/me` (every route but the sign-in-failed screen), and runs the screen on a 200. A 401 from any API call
// records an attempt and sends the browser to sign in, unless this load already came back from one (a record read
// at this load, counting only for the answer to the load's own `/api/me`): then the sign-in-failed screen.
import * as attempt from "./attempt";
import { literalAddress } from "./addresses";
import { route } from "./router";
import { element, type Fetched, type ScreenContext } from "./screen";

const app = document.getElementById("app");
let generation = 0;

function mount(root: HTMLElement): void {
  app?.replaceChildren(root);
}

function showError(): void {
  const main = element("main", { "data-screen": "error" });
  main.append(element("h1", {}, "Something went wrong"), element("p", {}, "The app could not reach its server. Reload to try again."));
  mount(main);
}

function request(path: string): Promise<Response> {
  // The session cookie alone: same-origin, no Authorization header.
  return fetch(path, { credentials: "same-origin", headers: { Accept: "application/json" }, cache: "no-store" });
}

function withReturn(base: string, target: string | null): string {
  return target === null ? base : `${base}${base.includes("?") ? "&" : "?"}return=${encodeURIComponent(target)}`;
}

function toFailedScreen(reason: string, target: string | null): void {
  window.location.replace(withReturn(`${literalAddress("sign-in-failed")}?reason=${reason}`, target));
}

/** A 401: sign in (recording the attempt), or, when this load came back from one, the failed screen. */
function unauthorized(target: string | null, consumed: attempt.Read | null): void {
  generation += 1; // this document is going away: nothing of the running load shows
  if (consumed?.status === "found") return toFailedScreen("session-lost", target);
  if (consumed?.status === "unavailable" || !attempt.record(target)) return toFailedScreen("storage-unavailable", target);
  window.location.assign(withReturn("/api/auth/login", target));
}

async function load(): Promise<void> {
  generation += 1;
  const mine = generation;
  const consumed = attempt.take();
  const { screen, target } = route(window.location.pathname);

  const context: ScreenContext = {
    segments: window.location.pathname.split("/").slice(1),
    attempt: consumed,
    mount(root) {
      if (mine === generation) mount(root);
    },
    async read(path): Promise<Fetched> {
      let response: Response;
      try {
        response = await request(path);
      } catch {
        return mine === generation ? { kind: "error" } : { kind: "gone" };
      }
      if (mine !== generation) return { kind: "gone" };
      if (response.status === 401) {
        unauthorized(target, null); // a later 401 records a fresh attempt
        return { kind: "gone" };
      }
      if (response.status === 404) return { kind: "not-available" };
      if (response.status !== 200) return { kind: "error" };
      try {
        return { kind: "ok", body: await response.json() };
      } catch {
        return { kind: "error" };
      }
    },
  };

  if (screen.needsSession) {
    let me: Response;
    try {
      me = await request("/api/me");
    } catch {
      if (mine === generation) showError();
      return;
    }
    if (mine !== generation) return;
    if (me.status === 401) return unauthorized(target, consumed);
    if (me.status !== 200) return showError();
  }
  await screen.render(context);
}

function start(): void {
  void load();
  // A page restored from the back-forward cache counts as a load. `isTrusted` is not checked.
  window.addEventListener("pageshow", (event) => {
    if (event.persisted) void load();
  });
}

start();
