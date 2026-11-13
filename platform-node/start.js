// The one-line setup. At the top of the file that starts your server:
//
//   import platform from "analytics-platform/start";   // or require(...)
//
// or, without touching your code: node --require analytics-platform/start app.js
//
// It reads ANALYTICS_SITE_ID, ANALYTICS_SITE_SECRET and ANALYTICS_ENDPOINT
// from the environment, or else from the .env file in the folder you start
// in (only its ANALYTICS_* lines). It never writes them into process.env, so
// your own dotenv (a .env.production, say) still sets everything as before.
//
// It makes the platform once, for the whole process, and returns it: import
// it wherever you call track(), lead(), watchDatabase() and the rest. In an
// Express app it adds the middleware and the error handler by itself
// (lib/auto.js). Fastify and Koa still need their one line:
// fastify.register(platform.fastify()) or app.use(platform.koa()).
//
// On SIGTERM (a deploy or a restart) it sends what's waiting before the
// process exits. If your app handles SIGTERM itself, your handler still runs
// and decides when to exit.
"use strict";

const path = require("node:path");
const { fromEnvironment, readDotEnv } = require("./lib/env.js");

const STARTED = Symbol.for("analytics-platform.started");

function start() {
  if (globalThis[STARTED]) return globalThis[STARTED];
  // The environment first; the .env file only for what it doesn't set.
  const options = fromEnvironment(fromEnvironment({}), readDotEnv(path.join(process.cwd(), ".env")));
  const { createPlatform } = require("./index.js");
  const platform = createPlatform(options);
  require("./lib/auto.js").watchExpress(platform);

  // Node exits on SIGTERM only while nothing listens for it, so this listener
  // re-sends the signal once the sends are done, unless the app has its own
  // listener, which then decides when to exit.
  const onSigterm = () => {
    const others = process.listenerCount("SIGTERM") > 1;
    process.off("SIGTERM", onSigterm);
    const closing = platform.close().catch(() => {});
    if (!others) closing.then(() => process.kill(process.pid, "SIGTERM"));
  };
  process.on("SIGTERM", onSigterm);

  globalThis[STARTED] = platform;
  return platform;
}

module.exports = start();
