// Form protection module: checks a form your server received before you
// accept it (POST /collectanalytics/shield/verify, the same check as spam
// protection's). It reads the hidden "analytics-shield" answer the tracker
// puts in protected forms, and checks the email, name and text for fake
// sign-ups. Spam lands in the site's spam folder (Leads → Spam). Passwords,
// card numbers and tokens are never sent. Fails open: when the check can't be
// made, the form is accepted (checked: false).
"use strict";

const PRIVATE_FIELD = /pass|card|cvc|cvv|secret|token|ssn|iban|csrf|analytics-shield/i;
const MAX_FIELDS = 50;
const ANSWER = "analytics-shield";

function plainFields(body) {
  const out = {};
  if (!body || typeof body !== "object") return out;
  for (const [label, value] of Object.entries(body).slice(0, MAX_FIELDS)) {
    if (PRIVATE_FIELD.test(label)) continue;
    if (typeof value === "string") out[label] = value.slice(0, 2000);
    else if (Array.isArray(value)) out[label] = value.filter((v) => typeof v === "string").join(", ").slice(0, 2000);
  }
  return out;
}

// clientIp(req): the firewall's way of finding the visitor's address.
function createForms(core, { clientIp } = {}) {
  const log = (...args) => core.log("forms", ...args);
  const open = (reason) => ({ ok: true, spam: false, reasons: reason ? [reason] : [], checked: false });

  // req: the request (its body is the form, parsed by your body parser), or
  // null with options.fields. Options: fields, email, name, form (its name in
  // the spam folder). Resolves to { ok, spam, reasons, checked }.
  async function checkForm(req, options = {}) {
    if (!core.isOn("forms")) return open();
    try {
      const body = options.fields || req?.body || {};
      const token = typeof body[ANSWER] === "string" ? body[ANSWER] : "";
      const ip = req ? (clientIp ? clientIp(req) : req.ip || req.socket?.remoteAddress || "") : "";
      const res = await core.send("forms", "/collectanalytics/shield/verify", {
        body: {
          token,
          fields: plainFields(body),
          email: typeof options.email === "string" ? options.email : undefined,
          name: typeof options.name === "string" ? options.name : undefined,
          form: typeof options.form === "string" ? options.form : undefined,
          ip,
        },
      });
      if (!res || res.status >= 500 || res.status === 429) return open("unchecked");
      const data = await res.json().catch(() => null);
      if (res.status === 403) {
        log("the site secret was refused; forms aren't checked");
        return open("unchecked");
      }
      const spam = data?.success === false;
      return { ok: !spam, spam, reasons: Array.isArray(data?.reasons) ? data.reasons : [], checked: true };
    } catch (error) {
      log("could not check a form:", error?.message);
      return open("unchecked");
    }
  }

  // Express middleware for a form's route (after your body parser). Spam gets
  // a 422 (or your onSpam(req, res, result)); otherwise req.formCheck holds the
  // result and the route runs.
  function protectForm(options = {}) {
    return async function analyticsProtectForm(req, res, next = () => {}) {
      const result = await checkForm(req, options);
      req.formCheck = result;
      if (!result.spam) return next();
      if (options.onSpam) return options.onSpam(req, res, result);
      res.statusCode = 422;
      res.setHeader("content-type", "text/plain; charset=utf-8");
      res.end("Your message looks automated, so it wasn't sent. Please try again.");
    };
  }

  return { checkForm, protectForm };
}

module.exports = { createForms, plainFields };
