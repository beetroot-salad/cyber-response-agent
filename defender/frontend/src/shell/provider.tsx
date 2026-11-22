// The load in React (#1540 Am-5, Am-7): the provider, and the hooks that are a screen's only way to the session, the
// address, the server and the shell's actions. A screen has no other way to the network, storage or the address (PR2);
// the screens' own compile and the source check enforce it (F8).
import { useInfiniteQuery, useQuery, type QueryClient } from "@tanstack/react-query";
import { createContext, useContext, useEffect, useRef, type ReactNode } from "react";
import { valuesOf, type ShapeName, type ShapeValues } from "../addresses";
import { isPageOf } from "./page";
import type { AcceptResult, Gone, Person, ReadBody, ReadKey, ReadParams, ReadResult } from "./types";

// The shell's types a screen may need, from the one module screens import the shell through.
export type { FailedReason } from "./decision";
export type { AcceptResult, CallbackReason, Person } from "./types";

/** The closed list of actions a screen may take (PR2). Writes and streams will be added here, each with a stated 401
 * policy. */
export interface Actions {
  /** The failed screen's retry: sign in again, handing the address's `return` values on unjudged. */
  readonly retry: () => void;
  /** `POST /api/auth/logout`, then to the landing page by replace. */
  readonly signOut: () => void;
  /** Accept the invitation `id`: on success the shell loads the accepted tenant's alerts (a full load, Back returns
   * here), on a 401 it signs in again. What it came to is the screen's to show, the server's error included: it is
   * not the error state. */
  readonly acceptInvitation: (id: string) => Promise<AcceptResult>;
  /** A way out of the app to `address` (the knowledge repository's page the API served): a function that sends the
   * browser there, replacing this page so Back returns to where the person came from; null when the shell will not
   * send a browser there (not http or https, a user part, or the app's own origin). Calling `outbound` does nothing
   * by itself. */
  readonly outbound: (address: string) => (() => void) | null;
}

/** A read-only copy of the address's query. */
export interface AddressQuery {
  readonly get: (name: string) => string | null;
  readonly getAll: (name: string) => string[];
}

/** What a screen's hooks read. Nothing here names a browser type: screens are compiled without the browser library
 * (`tsconfig.screens.json`), and this module is compiled with them. */
export interface Shell {
  /** The load's one read path (`source: "later"`), and the query cache it sends each read through at most once. */
  read: <K extends ReadKey>(key: K, params: ReadParams<K>) => Promise<ReadResult<K>>;
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

/** A read whose answer is a page of items with the cursor of the next (`{items, next_cursor}`), and whose query takes
 * that cursor back: what `usePagedRead` reads. */
export type PagedKey = {
  [K in ReadKey]: ReadBody<K> extends { readonly items: readonly unknown[]; readonly next_cursor: string | null }
    ? ReadParams<K> extends { readonly query?: { readonly cursor?: string | null } }
      ? K
      : never
    : never;
}[ReadKey];

/** One item of a paged read's pages. */
type ItemOf<K extends ReadKey> = ReadBody<K> extends { readonly items: readonly (infer I)[] } ? I : never;

interface Page<I> {
  readonly items: readonly I[];
  readonly next_cursor: string | null;
}

/** What a screen's paged read shows. */
export interface PagedRead<K extends PagedKey> {
  /** Page 1's read, as `useRead` answers it: its state is the screen's. */
  readonly first: ScreenRead<K>;
  /** The items of every page loaded so far, in order. */
  readonly items: readonly ItemOf<K>[];
  /** The last later page's state: loading, failed (any failure, a fault of the shell's or an answer that is not a
   * page included), or null when there is none or it was read. A failed page stays failed for the load: it is not
   * read again. */
  readonly later: "loading" | "failed" | null;
  /** Read the next page and append it: only while the last page read has a next cursor and none has failed. */
  readonly more: (() => void) | null;
}

/** `params` with the page's `cursor` added to their query. */
function withCursor<K extends PagedKey>(params: ReadParams<K>, cursor: string): ReadParams<K> {
  const given: unknown = params;
  if (typeof given !== "object" || given === null) throw new Error("a read's params are an object");
  const query = "query" in given && typeof given.query === "object" && given.query !== null ? given.query : {};
  // trust: a paged read's query takes `cursor` (PagedKey), so its params with one added are still K's
  return { ...given, query: { ...query, cursor } } as ReadParams<K>;
}

/** A paged read's answer as its page. Page 1's is trusted to match the document (PR3), as every read's is. */
function pageOf<K extends PagedKey>(body: ReadBody<K>): Page<ItemOf<K>> {
  // trust: K's body is a page of its items (PagedKey)
  return body as Page<ItemOf<K>>;
}

/** Page 1's page parameter: no cursor. */
const FIRST_PAGE: string | null = null;

/** A later page's answer that is not a page of the read's items, or not the page at all: that page's failure. */
class LaterPageFailed extends Error {}

/**
 * A typed GET of a paged read, page by page (alert list design, Flows "Shell, paged read"; r3.4: TanStack Query's
 * infinite query). Page 1 is read as `useRead` reads it (a fault of its own goes to the boundary). Each later page is
 * one more page of the same entry, keyed `[key, params]`, with the cursor the page before it gave, sent at most once
 * per load (the once-per-load client never refetches or retries); the entry holds the cursors, so a change of `params`
 * starts from page 1 again, and a screen never sees one. A later page's failure, a fault or an answer that is not a
 * page included, is that page's state and never thrown, so the rows already shown stay.
 */
export function usePagedRead<K extends PagedKey>(key: K, params: ReadParams<K>): PagedRead<K> {
  const { read, queryClient } = useShell();
  const shown = useRef<readonly unknown[]>([key, params]); // the read the hook shows, once it is drawn
  useEffect(() => {
    shown.current = [key, params];
  });
  const result = useInfiniteQuery(
    {
      queryKey: [key, params],
      initialPageParam: FIRST_PAGE,
      queryFn: async ({ pageParam }): Promise<ReadResult<K>> => {
        if (pageParam === null) return read(key, params);
        const answer = await read(key, withCursor(params, pageParam));
        if (answer.kind === "gone") return answer;
        if (answer.kind !== "ok" || !isPageOf(key, answer.body)) throw new LaterPageFailed();
        return answer;
      },
      getNextPageParam: (last) => (last.kind === "ok" ? (pageOf<K>(last.body).next_cursor ?? undefined) : undefined),
    },
    queryClient,
  );
  if (result.data === undefined) {
    if (result.status === "error") throw result.error; // page 1's own fault: the boundary shows the error state
    return { first: { kind: "loading" }, items: [], later: null, more: null };
  }
  const [firstAnswer, ...laterAnswers] = result.data.pages;
  if (firstAnswer === undefined) throw new Error("a paged read has a first page");
  const first: ScreenRead<K> = firstAnswer.kind === "gone" ? { kind: "loading" } : firstAnswer;
  const items: ItemOf<K>[] = [];
  for (const answer of [firstAnswer, ...laterAnswers]) {
    if (answer.kind === "ok") items.push(...pageOf<K>(answer.body).items);
  }
  const lastAnswer = laterAnswers.at(-1);
  const later: PagedRead<K>["later"] = result.isFetchNextPageError
    ? "failed"
    : result.isFetchingNextPage || lastAnswer?.kind === "gone"
      ? "loading"
      : null;
  const more =
    first.kind === "ok" && result.hasNextPage && later === null
      ? () => {
          // a press drawn before the shown read's later page failed does nothing: that page stays failed for the load
          // (#1604). The shown read's, not this render's: `fetchNextPage` acts on the read the hook shows now
          if (queryClient.getQueryState(shown.current)?.status === "error") return;
          void result.fetchNextPage({ cancelRefetch: false });
        }
      : null;
  return { first, items, later, more };
}
