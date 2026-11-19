declare module "*.svg" {
  /** The built file's URL: assets are never inlined (F1). */
  const url: string;
  export default url;
}
