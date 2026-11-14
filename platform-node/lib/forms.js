// Form protection module: checks a form your server received before you
// accept it (POST /collectanalytics/shield/verify, the same check as spam
// protection's). It reads the hidden "analytics-shield" answer the tracker
// puts in protected forms, and checks the email, name and text for fake
// sign-ups. Spam lands in the site's spam folder (Leads → Spam). Passwords,
// card numbers and tokens are never sent. Fails open: when the check can't be
// made, the form is accepted (checked: false).
"use strict";

// Fields never sent, by name. protectForm() hands over the whole body, so
// whoever adds it to a sign-up or a checkout route relies on this list: keep
// it wide, and the same as every package's (`pass` also covers passwd and
// passport; `cc-number`, `cc-csc` and `cc-exp` are the autocomplete names).
const PRIVATE_FIELD = /pass|pwd|card|cc[-_]?(num|no|number|csc|exp)|cvc|cvv|cvn|expiry|exp[-_]?(month|year|date)|secret|token|\bauth\b|authoriz|api[-_]?key|otp|mfa|2fa|\bpin\b|security[-_]?code|signature|private|ssn|sin\b|nino|tax[-_]?id|iban|bic|swift|routing|account[-_]?(no|num|number)|dob|birth|licen[cs]e|csrf|nonce|analytics-shield/i;
// A card number in a field nobody thought to name "card" still must not be
// sent, so values are checked too: 13-19 digits that pass Luhn are taken out
// of the text and the rest of the message is kept, so spam is still judged.
const DIGITS = /\b(?:\d[ -]?){12,18}\d\b/g;
const MAX_FIELDS = 50;
const ANSWER = "analytics-shield";

// Replaces anything shaped like a card number, and passing Luhn, with
// [removed]. Luhn is what keeps order numbers and phone numbers readable.
function withoutCardNumbers(text) {
  return String(text).replace(DIGITS, (match) => {
    const digits = match.replace(/\D/g, "");
    let sum = 0;
    let alt = false;
    for (let i = digits.length - 1; i >= 0; i--) {
      let n = Number(digits[i]);
      if (alt) {
        n *= 2;
        if (n > 9) n -= 9;
      }
      sum += n;
      alt = !alt;
    }
    return sum % 10 === 0 ? "[removed]" : match;
  });
}

function plainFields(body) {
  const out = {};
  if (!body || typeof body !== "object") return out;
  for (const [label, value] of Object.entries(body).slice(0, MAX_FIELDS)) {
    if (PRIVATE_FIELD.test(label)) continue;
    let text;
    if (typeof value === "string") text = value;
    else if (typeof value === "number" && Number.isFinite(value)) text = String(value);
    else if (Array.isArray(value)) text = value.filter((v) => typeof v === "string").join(", ");
    else continue;
    out[label.slice(0, 100)] = withoutCardNumbers(text.slice(0, 2000));
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

module.exports = { createForms, plainFields, withoutCardNumbers };
