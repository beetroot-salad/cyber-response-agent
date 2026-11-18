// The shell's bootstrap (#1161 B1, #1540 Am-5): on every document load and every back-forward restore it makes one load
// outside React, decides what the address needs, asks `/api/me` through the load's client, and renders the chosen screen
// into one React root under the load's provider.
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { route, type Route } from "../router";
import * as attempt from "./attempt";
import { ErrorBoundary, ErrorScreen, type ErrorKind } from "./errors";
import { makeLoad, type Effects, type Load, type MeResult } from "./load";
import { ShellProvider, type AddressQuery, type Shell } from "./provider";
import type { CallbackReason, Person } from "./types";

const effects: Effects = {
  // The session cookie alone: same-origin, no Authorization header.
  fetch: (request) => window.fetch(request),
  record: (target, again) => attempt.record(target, again),
  assign: (url) => window.location.assign(url),
  replace: (url) => window.location.replace(url),
};

/** The API's refusal of the return address itself: the failed screen must not offer that address again. */
const REFUSED_RETURN: CallbackReason = "bad-request";

function reachedByHistory(): boolean {
  const entry = performance.getEntriesByType("navigation")[0];
  return entry instanceof PerformanceNavigationTiming && entry.type === "back_forward";
}

function parseQuery(search: string): AddressQuery {
  const params = new URLSearchParams(search);
  return { get: (name) => params.get(name), getAll: (name) => params.getAll(name) };
}

/** The failed screen's `return`, settled into the address before render (PR2): the consumed record's target, unless the
 * address has a return already or the target was the one refused. */
function settleReturn(taken: attempt.Read): void {
  const params = new URLSearchParams(window.location.search);
  if (params.has("return") || params.get("reason") === REFUSED_RETURN) return;
  if (taken.status !== "found" || taken.target === null) return;
  params.set("return", taken.target);
  const state: unknown = window.history.state; // kept as it is: this only changes the address
  window.history.replaceState(state, "", `${window.location.pathname}?${params.toString()}`);
}

/** True when `url` is a script file of the page's origin. Every script of the app is one (the CSP allows no other, and
 * no inline script), so the page's own address is not: the browser names it for what no script raised, as its own
 * ResizeObserver report. */
function isAppScript(url: string): boolean {
  const own = `${window.location.origin}/`;
  if (!url.startsWith(own)) return false;
  const [pathname] = url.slice(own.length - 1).split(/[?#]/);
  return pathname !== window.location.pathname;
}

/** A stack frame's URL: V8 writes a frame as "    at f (url:line:col)", Gecko and WebKit as "f@url:line:col". */
const FRAME = /^\s+at\s.*?(https?:\/\/[^\s()]+?):\d+:\d+|@(https?:\/\/[^\s()]+?):\d+:\d+/;

/** A failure is the app's when the code that raised it is an app script: an error event's file, or the first frame of
 * a rejected `Error`'s stack that names a file (a built-in, as `JSON.parse`, names none). A rejection with no stack (a
 * plain object, a string) names no origin: not counted. */
function raisedByApp(event: Event): boolean {
  if (event instanceof ErrorEvent) return isAppScript(event.filename);
  if (!(event instanceof PromiseRejectionEvent)) return false;
  const reason: unknown = event.reason;
  if (!(reason instanceof Error) || reason.stack === undefined) return false;
  for (const line of reason.stack.split("\n")) {
    const found = FRAME.exec(line);
    const url = found?.[1] ?? found?.[2];
    if (url !== undefined) return isAppScript(url);
  }
  return false;
}

export function start(): void {
  const container = document.getElementById("app");
  if (container === null) throw new Error("the page has no #app");
  const root = createRoot(container);
  let current: Load | null = null;
  let sequence = 0;

  function showError(load: Load, kind: ErrorKind): void {
    if (load !== current || !load.mayShow()) return;
    root.render(<ErrorScreen kind={kind} />);
  }

  /** The person the screen is drawn for: asked of `/api/me` when the screen needs a session, else none. */
  async function sessionFor(load: Load, routed: Route): Promise<{ readonly kind: "ok"; readonly me: Person | null } | Exclude<MeResult, { readonly kind: "ok" }>> {
    if (!routed.needsSession) return { kind: "ok", me: null };
    const asked = await load.client.me();
    return load === current ? asked : { kind: "gone" };
  }

  /** What the screen's hooks read, for this load. */
  function shellFor(load: Load, routed: Route, me: Person | null): Shell {
    const query = parseQuery(window.location.search);
    return {
      read: load.client.read,
      queryClient: load.queryClient,
      me,
      pathname: window.location.pathname,
      shape: routed.shape,
      query,
      actions: {
        retry: () => load.signIn(query.getAll("return")),
        signOut: () => {
          load.client.signOut().then(
            (result) => (result.kind === "error" ? showError(load, "unreachable") : undefined),
            () => showError(load, "broken"),
          );
        },
      },
    };
  }

  async function begin(byHistory: boolean): Promise<void> {
    current?.supersede();
    sequence += 1;
    const taken = attempt.take();
    const routed = route(window.location.pathname);
    const load = makeLoad({ taken, byHistory, target: routed.target, origin: window.location.origin, effects });
    current = load;
    try {
      if (routed.shape === "sign-in-failed") settleReturn(taken);
      const session = await sessionFor(load, routed);
      if (session.kind === "gone") return;
      if (session.kind === "error") return showError(load, "unreachable");
      const Screen = routed.Screen;
      root.render(
        <StrictMode>
          <ShellProvider key={sequence} shell={shellFor(load, routed, session.me)}>
            <ErrorBoundary load={load}>
              <Screen />
            </ErrorBoundary>
          </ShellProvider>
        </StrictMode>,
      );
    } catch {
      showError(load, "broken");
    }
  }

  // An uncaught error or unhandled rejection the app's own code raised is the error state, unless the load may no
  // longer show anything. One the app's code did not raise (the browser's own reports, an extension's script, an
  // injected script) leaves the screen as it is: it says nothing about the app.
  const stray = (event: Event): void => {
    if (current !== null && raisedByApp(event)) showError(current, "broken");
  };
  window.addEventListener("error", stray);
  window.addEventListener("unhandledrejection", stray);
  void begin(reachedByHistory());
  // A page restored from the back-forward cache is a new load, reached by history. `isTrusted` is not checked.
  window.addEventListener("pageshow", (event) => {
    if (event.persisted) void begin(true);
  });
}
