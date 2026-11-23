// The alert list (alert list design O5, O6, O7, O12): a tenant's alerts newest first, each with its outcome or where it
// stands, filtered by the address's query and paged with "Load more". The filters live in the address (AP3): Apply is
// a plain GET form, a full load; the screen never writes the address.
import { useState, type ReactNode } from "react";
import { addressOf } from "../../addresses";
import { stateOf, usePagedRead, usePlaceholders, useQueryOfAddress, type PagedRead } from "../../shell/provider";
import type { ReadParams } from "../../shell/types";
import { TopBar } from "../TopBar";
import { anySet, firedLabel, readFilters, wallTime, type Filters } from "./format";
import { NO_OUTCOME, OUTCOME_CODES, OUTCOMES, statusOf } from "./outcomes";

const READ = "/api/tenants/{tenant_id}/alerts";
/** Rows per read. */
const PAGE_SIZE = 50;
const NO_TITLE = "No title — the alert mapping had no title entry when this alert arrived";

/** The screen's states, as its `data-state` says them: page 1's, and the three the screen adds. */
type State = ReturnType<typeof stateOf> | "empty" | "no-match" | "invalid";

export function Alerts() {
  const [tenant] = usePlaceholders("alerts");
  const query = useQueryOfAddress();
  const [zone] = useState(() => Intl.DateTimeFormat().resolvedOptions().timeZone);
  const [filters] = useState(() => readFilters(query, zone));
  if (filters.kind === "invalid") {
    return (
      <Screen state="invalid">
        <p>These filters aren't valid.</p>
        <a href={addressOf("alerts", [tenant])} data-action="clear-filters">
          Clear filters
        </a>
      </Screen>
    );
  }
  return <List tenant={tenant} filters={filters} zone={zone} />;
}

function Screen({ state, children }: { readonly state: State; readonly children?: ReactNode }) {
  return (
    <>
      <TopBar />
      <main data-screen="alerts" data-state={state}>
        <h1>Alerts</h1>
        <p>Every alert pulled from your ticket system, newest first, with what Sluice concluded.</p>
        {children}
      </main>
    </>
  );
}

/** The read's params for `filters`: only the filters set, so an unset one is not sent. */
function paramsOf(tenant: string, filters: Filters): ReadParams<typeof READ> {
  return {
    path: { tenant_id: tenant },
    query: {
      limit: PAGE_SIZE,
      ...(filters.outcome === null ? {} : { outcome: filters.outcome }),
      ...(filters.after === null ? {} : { fired_after: filters.after }),
      ...(filters.before === null ? {} : { fired_before: filters.before }),
    },
  };
}

interface ListProps {
  readonly tenant: string;
  readonly filters: Filters;
  readonly zone: string;
}

function List({ tenant, filters, zone }: ListProps) {
  const [params] = useState(() => paramsOf(tenant, filters));
  const paged = usePagedRead(READ, params);
  const read = stateOf(paged.first);
  switch (paged.first.kind) {
    case "loading":
      return <Screen state={read} />;
    case "not-available":
      return (
        <Screen state={read}>
          <p>These alerts are not available.</p>
        </Screen>
      );
    case "error":
      return (
        <Screen state={read}>
          <p>The alerts could not be loaded. Reload the page to try again.</p>
        </Screen>
      );
    case "ok":
      break;
  }
  if (paged.items.length === 0 && !anySet(filters)) {
    return (
      <Screen state="empty">
        <p>No alerts yet</p>
      </Screen>
    );
  }
  return (
    <Screen state={paged.items.length === 0 ? "no-match" : "ready"}>
      <FilterBar tenant={tenant} filters={filters} zone={zone} />
      <Table tenant={tenant} items={paged.items} zone={zone} />
      <More paged={paged} />
    </Screen>
  );
}

/** The rows, or with none (the filters matched nothing) one row that says so with a clear link. */
function Table({
  tenant,
  items,
  zone,
}: {
  readonly tenant: string;
  readonly items: readonly Item[];
  readonly zone: string;
}) {
  const [now] = useState(() => new Date());
  return (
    <table>
      <thead>
        <tr>
          <th scope="col">Fired</th>
          <th scope="col">Ticket</th>
          <th scope="col">Title</th>
          <th scope="col">Outcome</th>
        </tr>
      </thead>
      <tbody>
        {items.length === 0 ? (
          <tr>
            <td colSpan={4} data-empty="no-match">
              <span>No alerts match these filters</span>{" "}
              <a href={addressOf("alerts", [tenant])} data-action="clear-filters">
                Clear filters
              </a>
            </td>
          </tr>
        ) : (
          items.map((alert) => <Row key={alert.alert_id} alert={alert} now={now} zone={zone} />)
        )}
      </tbody>
    </table>
  );
}

type Item = PagedRead<typeof READ>["items"][number];

function Row({ alert, now, zone }: { readonly alert: Item; readonly now: Date; readonly zone: string }) {
  const fired = firedLabel(alert.fired_at, { now, timeZone: zone });
  const status = statusOf(alert);
  return (
    <tr data-row="alert">
      <td>
        <div data-field="fired-time">{fired.time}</div>
        <div data-field="fired-day">{fired.day}</div>
      </td>
      <td>
        <div data-field="ticket">{alert.vendor_ticket_id}</div>
        <div data-field="vendor">{alert.vendor}</div>
      </td>
      <td>
        <div data-field="title" data-missing={alert.title === null ? "" : undefined}>
          {alert.title ?? NO_TITLE}
        </div>
      </td>
      <td>
        <span data-field="status" data-tone={status.tone}>
          {status.word}
        </span>
      </td>
    </tr>
  );
}

/** Outcome, Fired after and Fired before, sent as a plain GET to the tenant's alerts address with the viewer's zone
 * (O7): a full load. The form is filled with what the address asked for, the times written in the viewer's zone. */
function FilterBar({ tenant, filters, zone }: ListProps) {
  const time = (instant: string | null): string => (instant === null ? "" : wallTime(instant, zone));
  return (
    <form method="get" action={addressOf("alerts", [tenant])} data-form="filters">
      <label>
        <span>Outcome</span>
        <select name="outcome" defaultValue={filters.outcome ?? ""}>
          <option value="">All</option>
          {OUTCOME_CODES.map((code) => (
            <option key={code} value={code}>
              {OUTCOMES[code].label}
            </option>
          ))}
          <option value={NO_OUTCOME}>No outcome yet</option>
        </select>
      </label>
      <label>
        <span>Fired after</span>
        <input type="datetime-local" name="fired_after" defaultValue={time(filters.after)} />
      </label>
      <label>
        <span>Fired before</span>
        <input type="datetime-local" name="fired_before" defaultValue={time(filters.before)} />
      </label>
      <input type="hidden" name="tz" defaultValue={zone} />
      <div data-form="actions">
        {anySet(filters) ? (
          <a
            href={addressOf("alerts", [tenant])}
            data-action="clear-filters"
            aria-label="Clear filters"
            title="Clear filters"
          >
            ×
          </a>
        ) : null}
        <button type="submit" data-action="apply">
          Apply
        </button>
      </div>
    </form>
  );
}

/** "Load more" while there is a next page; a later page that failed says so instead, and is not read again (O5). */
function More({ paged }: { readonly paged: PagedRead<typeof READ> }) {
  if (paged.later === "failed")
    return <p data-later="failed">Couldn't load more alerts. Reload the page to try again.</p>;
  if (paged.later === "loading")
    return (
      <button type="button" data-action="load-more" disabled>
        Loading…
      </button>
    );
  if (paged.more === null) return null;
  const more = paged.more;
  return (
    <button type="button" data-action="load-more" onClick={() => more()}>
      Load more
    </button>
  );
}
