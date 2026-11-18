// The load in React (#1540 Am-5, Am-7): the provider, and the hooks that are a screen's only way to the session, the
// address, the server and the shell's actions. A screen has no other way to the network, storage or the address (PR2);
// the screens' own compile and the source check enforce it (F8).
import { useQuery, type QueryClient } from "@tanstack/react-query";
import { createContext, useContext, type ReactNode } from "react";
import { valuesOf, type ShapeName, type ShapeValues } from "../addresses";
import type { Gone, Person, ReadKey, ReadParams, ReadResult } from "./types";

// The shell's types a screen may need, from the one module screens import the shell through.
export type { FailedReason } from "./decision";
export type { CallbackReason, Person } from "./types";

/** The closed list of actions a screen may take (PR2). Writes and streams will be added here, each with a stated 401 policy. */
export interface Actions {
  /** The failed screen's retry: sign in again, handing the address's `return` values on unjudged. */
  retry(): void;
  /** `POST /api/auth/logout`, then to the landing page by replace. */
  signOut(): void;
}

/** A read-only copy of the address's query. */
export interface AddressQuery {
  get(name: string): string | null;
  getAll(name: string): string[];
}

/** What a screen's hooks read. Nothing here names a browser type: screens are compiled without the browser library
 * (`tsconfig.screens.json`), and this module is compiled with them. */
export interface Shell {
  /** The load's one read path (`source: "later"`), and the query cache it sends each read through at most once. */
  read<K extends ReadKey>(key: K, params: ReadParams<K>): Promise<ReadResult<K>>;
  readonly queryClient: QueryClient;
  readonly me: Person | null;
  /** The address's path and the shape it is a member of (null: the not-found screen). */
  readonly pathname: string;
  readonly shape: ShapeName | null;
  readonly query: AddressQuery;
  readonly actions: Actions;
}

const ShellContext = createContext<Shell | null>(null);

export function ShellProvider({ shell, children }: { readonly shell: Shell; readonly children: ReactNode }) {
  return <ShellContext.Provider value={shell}>{children}</ShellContext.Provider>;
}

function useShell(): Shell {
  const shell = useContext(ShellContext);
  if (shell === null) throw new Error("a screen was drawn outside the shell's provider");
  return shell;
}

/** The signed-in person: only for a screen the shell asked `/api/me` for. */
export function useMe(): Person {
  const { me } = useShell();
  if (me === null) throw new Error("this screen needs a session, but the shell asked for none");
  return me;
}

/** The address's read-only query. */
export function useQueryOfAddress(): AddressQuery {
  return useShell().query;
}

/** The address's placeholder values, in its template's order, for the screen of shape `name` (the router drew it for
 * that shape, so any other is a bug: it throws, and the boundary shows the error state). */
export function usePlaceholders<N extends ShapeName>(name: N): ShapeValues[N] {
  const { pathname, shape } = useShell();
  if (shape !== name) throw new Error(`the ${name} screen was drawn for ${shape ?? "no"} shape`);
  return valuesOf(name, pathname);
}

export function useActions(): Actions {
  return useShell().actions;
}

/** What a screen's read shows: the answer, or loading. A gone load shows nothing new, so it reads as loading. */
export type ScreenRead<K extends ReadKey> = Exclude<ReadResult<K>, Gone> | { readonly kind: "loading" };

/** A data screen's state, as its `data-state` says it: one name per kind of read. */
type ScreenState = "loading" | "ready" | "not-available" | "error";

const STATES: Readonly<Record<ScreenRead<ReadKey>["kind"], ScreenState>> = {
  loading: "loading",
  ok: "ready",
  "not-available": "not-available",
  error: "error",
};

/** The state a screen shows for its read. */
export function stateOf<K extends ReadKey>(result: ScreenRead<K>): ScreenState {
  return STATES[result.kind];
}

/** A typed GET keyed by the OpenAPI document's own path key. Sent at most once per load; a 401 is the shell's. */
export function useRead<K extends ReadKey>(key: K, params: ReadParams<K>): ScreenRead<K> {
  const { read, queryClient } = useShell();
  const result = useQuery({ queryKey: [key, params], queryFn: () => read(key, params) }, queryClient);
  if (result.status === "error") throw result.error; // the read's own fault: the boundary shows the error state
  if (result.status === "pending" || result.data.kind === "gone") return { kind: "loading" };
  return result.data;
}
