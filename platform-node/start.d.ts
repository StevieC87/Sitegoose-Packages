import type { Platform } from "./index";

/**
 * The process's one platform, made from ANALYTICS_SITE_ID, ANALYTICS_SITE_SECRET
 * and ANALYTICS_ENDPOINT (the environment, else the ANALYTICS_* lines of ./.env).
 * Importing it adds the middleware and error handler to an Express app by itself.
 *
 *   import platform from "analytics-platform/start";
 */
declare const platform: Platform;
export = platform;
