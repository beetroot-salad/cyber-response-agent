import { element, type Screen } from "../screen";

/** What a pathname that matches no shape gets. It is not a route. */
export const notFound: Screen = {
  needsSession: true,
  render(context) {
    const main = element("main", { "data-screen": "not-found" });
    main.append(element("h1", {}, "Not found"), element("p", {}, "There is nothing at this address."));
    context.mount(main);
  },
};
