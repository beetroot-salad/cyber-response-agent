// The shell's error state (#1161 B1, #1540 Am-5 point 6): one screen, and the boundary that shows it for a render error.
import { Component, type ReactNode } from "react";
import type { Load } from "./load";

export function ErrorScreen() {
  return (
    <main data-screen="error">
      <h1>Something went wrong</h1>
      <p>The app could not reach its server. Reload to try again.</p>
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
    return this.props.load.isLeaving() ? null : <ErrorScreen />;
  }
}
