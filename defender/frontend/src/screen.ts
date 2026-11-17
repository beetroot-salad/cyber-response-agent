// What the shell hands a screen, and what a screen is.
import type { Read } from "./attempt";

export type Fetched =
  | { readonly kind: "ok"; readonly body: unknown }
  | { readonly kind: "not-available" }
  | { readonly kind: "error" }
  /** The shell is sending the browser to sign in, or this load is no longer the page's: the screen does nothing. */
  | { readonly kind: "gone" };

export interface ScreenContext {
  /** The pathname's segments after the leading `/` (the placeholders' values sit in them). */
  readonly segments: readonly string[];
  /** The attempt record this load consumed. */
  readonly attempt: Read;
  /** Put the screen's root element on the page. */
  mount(root: HTMLElement): void;
  /** An authenticated read of the API (session cookie only). A 401 is the shell's to handle. */
  read(path: string): Promise<Fetched>;
}

export interface Screen {
  /** Whether the shell asks `/api/me` before the screen runs (every screen but the sign-in-failed one). */
  readonly needsSession: boolean;
  render(context: ScreenContext): void | Promise<void>;
}

export function element<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  attributes: Readonly<Record<string, string>> = {},
  text?: string,
): HTMLElementTagNameMap[K] {
  const created = document.createElement(tag);
  for (const [name, value] of Object.entries(attributes)) created.setAttribute(name, value);
  if (text !== undefined) created.textContent = text;
  return created;
}
