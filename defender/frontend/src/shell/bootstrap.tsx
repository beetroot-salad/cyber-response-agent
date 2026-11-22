// The shell's bootstrap (#1161 B1, #1540 Am-5): on every document load and every back-forward restore it makes one load
// outside React, decides what the address needs, asks `/api/me` through the load's client, and renders the chosen
// screen into one React root under the load's provider.
//
// A fault of the shell's own (a throw in a step below, or in an action's call) is caught where it happens, logged, and
// shown as the error state's "something stopped working" (Am-5 point 6).
import { StrictMode, type ReactNode } from "react";
import { createRoot, type Root } from "react-dom/client";
import { route, type Route } from "../router";
import * as attempt from "./attempt";
import { ErrorBoundary, ErrorScreen, raisedByApp, type ErrorKind } from "./errors";
import { makeLoad, type Effects, type Load } from "./load";
import { ShellProvider, type AddressQuery, type Shell } from "./provider";
import type { CallbackReason, Outcome, Person } from "./types";

const effects: Effects = {
  // The session cookie alone: same-origin, no Authorization header.
  fetch: (request) => window.fetch(request),
  record: attempt.record,
  assign: (url) => window.location.assign(url),
  replace: (url) => window.location.replace(url),
};

/** The API's refusal of the return address itself: the failed screen must not offer that address again. */
const REFUSED_RETURN: CallbackReason = "bad-request";

/** The address a load is for, read once when it starts. */
interface Address {
  readonly pathname: string;
  readonly search: string;
}

function reachedByHistory(): boolean {
  const entry = performance.getEntriesByType("navigation")[0];
  return entry instanceof PerformanceNavigationTiming && entry.type === "back_forward";
}

function parseQuery(search: string): AddressQuery {
  const params = new URLSearchParams(search);
  return { get: (name) => params.get(name), getAll: (name) => params.getAll(name) };
}

/** The failed screen's address with its `return` settled in (PR2): the consumed record's target, unless the address has
 * a return already or the target was the one refused. The page's address is changed to it, before render. */
function settleReturn(taken: attempt.TakenRecord, address: Address): Address {
  const params = new URLSearchParams(address.search);
  if (params.has("return") || params.get("reason") === REFUSED_RETURN) return address;
  if (taken.status !== "found" || taken.target === null) return address;
  params.set("return", taken.target);
  const settled = { pathname: address.pathname, search: `?${params.toString()}` };
  const state: unknown = window.history.state; // kept as it is: this only changes the address
  window.history.replaceState(state, "", `${settled.pathname}${settled.search}`);
  return settled;
}

/** The page's one React root: a load's screen, or the error state, drawn into it. */
interface View {
  /** The error state of `kind`, unless `load` may no longer show anything. */
  readonly error: (load: Load, kind: ErrorKind) => void;
  /** A fault of the shell's own: logged for whoever debugs it, and shown as "something stopped working". */
  readonly broken: (load: Load, fault: unknown) => void;
  readonly screen: (node: ReactNode) => void;
}

function viewOn(root: Root): View {
  const error = (load: Load, kind: ErrorKind): void => {
    if (load.mayShow()) root.render(<ErrorScreen kind={kind} />);
  };
  return {
    error,
    broken: (load, fault) => {
      console.error(fault);
      error(load, "broken");
    },
    screen: (node) => {
      root.render(<StrictMode>{node}</StrictMode>);
    },
  };
}

/** An action's call: the server's error is the error state, and so is a fault of the shell's own. */
function runAction(view: View, load: Load, call: Promise<{ readonly kind: string }>): void {
  call.then(
    (result) => {
      if (result.kind === "error") view.error(load, "server");
    },
    (fault: unknown) => {
      view.broken(load, fault);
    },
  );
}

/** The person the screen is drawn for: asked of `/api/me` when the screen needs a session, else none. */
async function sessionFor(
  load: Load,
  routed: Route,
): Promise<Outcome<{ readonly kind: "ok"; readonly me: Person | null }>> {
  return routed.needsSession ? load.client.me() : { kind: "ok", me: null };
}

/** What a load has found out before its screen is drawn. */
interface Opened {
  readonly routed: Route;
  readonly address: Address;
  readonly me: Person | null;
}

/** What the screen's hooks read, for this load. */
function shellFor(view: View, load: Load, { routed, address, me }: Opened): Shell {
  const query = parseQuery(address.search);
  return {
    read: load.client.read,
    queryClient: load.queryClient,
    me,
    pathname: address.pathname,
    shape: routed.shape,
    query,
    actions: {
      retry: () => {
        load.signIn(query.getAll("return"));
      },
      signOut: () => {
        runAction(view, load, load.client.signOut());
      },
      outbound: (address) => load.outbound(address),
      // Not `runAction`: its error is the screen's to show beside the invitation, not the error state. A fault of the
      // shell's own still is the error state's.
      acceptInvitation: (id) =>
        load.client.acceptInvitation(id).catch((fault: unknown) => {
          view.broken(load, fault);
          return { kind: "gone" } as const;
        }),
    },
  };
}

/** What a load starts from: the record it took, the address it was opened at and that address's route, and its key,
 * new for every load, so no screen state outlives its load. */
interface Start {
  readonly taken: attempt.TakenRecord;
  readonly opened: Address;
  readonly routed: Route;
  readonly key: number;
}

/** One load, from its address to its screen. */
async function begin(view: View, load: Load, { taken, opened, routed, key }: Start): Promise<void> {
  try {
    const address = routed.shape === "sign-in-failed" ? settleReturn(taken, opened) : opened;
    const session = await sessionFor(load, routed);
    if (session.kind === "gone") return;
    if (session.kind === "error") {
      view.error(load, "server");
      return;
    }
    const Screen = routed.Screen;
    view.screen(
      <ShellProvider key={key} shell={shellFor(view, load, { routed, address, me: session.me })}>
        <ErrorBoundary load={load}>
          <Screen />
        </ErrorBoundary>
      </ShellProvider>,
    );
  } catch (fault) {
    view.broken(load, fault);
  }
}

export function start(): void {
  const container = document.getElementById("app");
  if (container === null) throw new Error("the page has no #app");
  const view = viewOn(createRoot(container));
  let current: Load | null = null;
  let sequence = 0;

  const open = (byHistory: boolean): void => {
    current?.supersede();
    sequence += 1;
    const taken = attempt.take();
    const opened = { pathname: window.location.pathname, search: window.location.search };
    const routed = route(opened.pathname);
    const load = makeLoad({ taken, byHistory, target: routed.target, origin: window.location.origin, effects });
    current = load;
    void begin(view, load, { taken, opened, routed, key: sequence });
  };

  // An uncaught error or unhandled rejection the app's own code raised is the error state, unless the load may no
  // longer show anything. One the app's code did not raise (the browser's own reports, an extension's script, an
  // injected script) leaves the screen as it is: it says nothing about the app.
  const stray = (event: Event): void => {
    if (current !== null && raisedByApp(event)) view.error(current, "broken");
  };
  window.addEventListener("error", stray);
  window.addEventListener("unhandledrejection", stray);
  open(reachedByHistory());
  // A page restored from the back-forward cache is a new load, reached by history. `isTrusted` is not checked.
  window.addEventListener("pageshow", (event) => {
    if (event.persisted) open(true);
  });
}
