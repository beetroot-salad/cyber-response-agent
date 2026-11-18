// The shell's error state (#1161 B1, #1540 Am-5 point 6): one screen with a message per kind, and the boundary that shows it for a render error.
import { Component, type ReactNode } from "react";
import type { Load } from "./load";

/** Why the error state shows: the server could not be reached or answered wrongly, or the app's own code failed. */
export type ErrorKind = "unreachable" | "broken";

const MESSAGES: Readonly<Record<ErrorKind, string>> = {
  unreachable: "The app could not reach its server. Reload to try again.",
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

/** Turns a render error of a screen into the error state, unless the load is leaving (then nothing shows). */
export class ErrorBoundary extends Component<{ readonly load: Load; readonly children: ReactNode }, { readonly failed: boolean }> {
  override state = { failed: false };

  static getDerivedStateFromError(): { failed: boolean } {
    return { failed: true };
  }

  override render(): ReactNode {
    if (!this.state.failed) return this.props.children;
    return this.props.load.isLeaving() ? null : <ErrorScreen kind="broken" />;
  }
}
