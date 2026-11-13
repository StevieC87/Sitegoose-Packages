// analytics-platform/hono for `import`: hono.js's named exports, for the
// bundlers that can't find them in CommonJS (Netlify's Edge Functions).
import hono from "./hono.js";

export const { createHonoPlatform } = hono;
export default hono;
