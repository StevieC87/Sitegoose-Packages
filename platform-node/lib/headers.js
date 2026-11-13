// Security headers module: adds the headers picked on the dashboard's
// Security page (they come with the module switches, core.js) to every
// response, unless the app sets that header itself: your own code wins.
"use strict";

function createHeaders(core) {
  function middleware(req, res, next = () => {}) {
    try {
      if (core.isOn("headers")) {
        for (const [name, value] of core.headers()) {
          if (!res.hasHeader(name)) res.setHeader(name, value);
        }
      }
    } catch (error) {
      core.log("headers", "could not add headers:", error?.message);
    }
    next();
  }
  return { middleware };
}

module.exports = { createHeaders };
