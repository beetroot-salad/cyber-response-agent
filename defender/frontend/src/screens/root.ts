import { element, type Screen } from "../screen";

export const root: Screen = {
  needsSession: true,
  render(context) {
    const main = element("main", { "data-screen": "root" });
    main.append(element("h1", {}, "Defender"));
    context.mount(main);
  },
};
