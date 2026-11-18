// The shell's bootstrap (#1161 B1, #1540 Am-5): on every document load and every back-forward restore it makes one load
// outside React, decides what the address needs, asks `/api/me` through the load's client, and renders the chosen screen
// into one React root under the load's provider.
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { route } from "../router";
import * as attempt from "./attempt";
import { ErrorBoundary, ErrorScreen } from "./errors";
import { makeLoad, type Effects, type Load } from "./load";
import { ShellProvider, type Actions, type Query } from "./provider";

const effects: Effects = {
  // The session cookie alone: same-origin, no Authorization header.
  fetch: (request) => window.fetch(request),
  record: (target, again) => attempt.record(target, again),
  assign: (url) => window.location.assign(url),
  replace: (url) => window.location.replace(url),
};

function reachedByHistory(): boolean {
  const entry = performance.getEntriesByType("navigation")[0];
  return entry instanceof PerformanceNavigationTiming && entry.type === "back_forward";
}

function queryOf(search: string): Query {
  const params = new URLSearchParams(search);
  return { get: (name) => params.get(name), getAll: (name) => params.getAll(name) };
}

/** The failed screen's `return`, settled into the address before render (PR2): the consumed record's target, unless the
 * address has a return already or the target was the one refused. */
function settleReturn(taken: attempt.Read): void {
  const params = new URLSearchParams(window.location.search);
  if (params.has("return") || params.get("reason") === "bad-request") return;
  if (taken.status !== "found" || taken.target === null) return;
  params.set("return", taken.target);
  const state: unknown = window.history.state; // kept as it is: this only changes the address
  window.history.replaceState(state, "", `${window.location.pathname}?${params.toString()}`);
}

export function start(): void {
  const container = document.getElementById("app");
  if (container === null) throw new Error("the page has no #app");
  const root = createRoot(container);
  let current: Load | null = null;
  let sequence = 0;

  function showError(load: Load): void {
    if (load !== current || load.isGone()) return;
    root.render(<ErrorScreen />);
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
      let me = null;
      if (routed.needsSession) {
        const asked = await load.client.me();
        if (asked.kind === "gone" || load !== current) return;
        if (asked.kind === "error") return showError(load);
        me = asked.me;
      }
      const actions: Actions = {
        retry: () => load.signIn(new URLSearchParams(window.location.search).getAll("return")),
        signOut: () => {
          load.client.signOut().then(
            (result) => (result === "error" ? showError(load) : undefined),
            () => showError(load),
          );
        },
      };
      const shell = { read: load.client.read, queryClient: load.queryClient, me, segments: window.location.pathname.split("/").slice(1), query: queryOf(window.location.search), actions };
      const Screen = routed.Screen;
      root.render(
        <StrictMode>
          <ShellProvider key={sequence} shell={shell}>
            <ErrorBoundary load={load}>
              <Screen />
            </ErrorBoundary>
          </ShellProvider>
        </StrictMode>,
      );
    } catch {
      showError(load);
    }
  }

  // Every uncaught error or unhandled rejection in the document is the error state, except while the load is leaving.
  const stray = (): void => {
    if (current !== null) showError(current);
  };
  window.addEventListener("error", stray);
  window.addEventListener("unhandledrejection", stray);
  void begin(reachedByHistory());
  // A page restored from the back-forward cache is a new load, reached by history. `isTrusted` is not checked.
  window.addEventListener("pageshow", (event) => {
    if (event.persisted) void begin(true);
  });
}
