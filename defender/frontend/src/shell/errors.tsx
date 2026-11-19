// The shell's error state (#1161 B1, #1540 Am-7): one screen with a message per kind of failure, the boundary that
// shows it for a render error, and what tells the app's own uncaught failures from everyone else's.
import { Component, type ReactNode } from "react";
import type { Load } from "./load";

/** Why the error state shows: the server could not be reached or answered wrongly, or the app's own code failed. */
export type ErrorKind = "server" | "broken";

const MESSAGES: Readonly<Record<ErrorKind, string>> = {
  server: "The server did not answer as expected. Reload to try again.",
  broken: "Something on this page stopped working. Reload to try again.",
};

export function ErrorScreen({ kind }: { readonly kind: ErrorKind }) {
  return (
    <main data-screen="error" data-kind={kind}>
      <h1>Something went wrong</h1>
      <p>{MESSAGES[kind]}</p>
    </main>
  );
}

/** Turns a render error of a screen into the error state, unless the load may no longer show anything. */
export class ErrorBoundary extends Component<
  { readonly load: Load; readonly children: ReactNode },
  { readonly failed: boolean }
> {
  override state = { failed: false };

  static getDerivedStateFromError(): { failed: boolean } {
    return { failed: true };
  }

  override render(): ReactNode {
    if (!this.state.failed) return this.props.children;
    return this.props.load.mayShow() ? <ErrorScreen kind="broken" /> : null;
  }
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
export function raisedByApp(event: Event): boolean {
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
