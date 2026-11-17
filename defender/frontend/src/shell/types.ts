// The API's types, from the OpenAPI document the API's own app produced (PR3, F3). Nothing here describes a response by hand.
import type { components, paths } from "../generated/api";

/** The OpenAPI path keys that have a GET: what `useRead` and the load's `client.read` are keyed by. */
export type ReadKey = { [K in keyof paths]: paths[K] extends { get: object } ? K : never }[keyof paths];
type GetOperation<K extends ReadKey> = paths[K] extends { get: infer Operation } ? Operation : never;
/** That operation's parameters, path and query together, as the generated types declare them. */
export type ReadParams<K extends ReadKey> = GetOperation<K> extends { parameters: infer P } ? P : never;
export type ReadBody<K extends ReadKey> = GetOperation<K> extends { responses: { 200: { content: { "application/json": infer B } } } }
  ? B
  : never;

/** A read's closed result (Am-5 point 4). */
export type ReadResult<K extends ReadKey> =
  /** The load is leaving or is no longer the page's: the screen does nothing, whatever the answer was. */
  | { readonly kind: "gone" }
  | { readonly kind: "ok"; readonly body: ReadBody<K> }
  | { readonly kind: "not-available" }
  | { readonly kind: "error" };

export type Person = components["schemas"]["Me"];
