// What a form check is allowed to send. protectForm() hands over the whole
// body, so a sign-up or a checkout route depends entirely on this filter. The
// same fields as the PHP package's test/FormsTest.php, and the autocomplete
// names (cc-number, cc-csc, cc-exp).
"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const { plainFields, withoutCardNumbers } = require("../lib/forms.js");

const KEPT = { name: "Ada Lovelace", email: "ada@example.com", message: "Hello, I would like a quote.", author: "Ada", subject: "Enquiry" };
const DROPPED = {
  password: "hunter2", pwd: "hunter2", passwd: "hunter2", user_pass: "hunter2",
  card: "4111111111111111", cc_number: "4111111111111111", "cc-number": "4111111111111111", "cc-csc": "123", "cc-exp": "12/27",
  "exp-month": "12", "api-key": "sk-live-xyz", "security-code": "999", "tax-id": "GB123", "account-number": "12345678", cvc: "123", cvv: "123", expiry: "12/27", exp_month: "12",
  api_key: "sk-live-xyz", apikey: "sk-live-xyz", auth: "Bearer xyz", authorization: "Bearer xyz",
  access_token: "xyz", client_secret: "xyz", otp: "123456", mfa_code: "123456", pin: "4321", security_code: "999",
  ssn: "078-05-1120", tax_id: "GB123", iban: "GB33BUKB20201555555555", swift: "BUKBGB22", routing: "021000021",
  account_number: "12345678", dob: "1815-12-10", birthday: "1815-12-10", licence: "ABC123", signature: "xyz",
  private_notes: "xyz", _csrf: "xyz", _wpnonce: "xyz", "analytics-shield": "answer",
};

test("passwords, card details, keys and codes never leave the server", () => {
  const sent = plainFields({ ...KEPT, phone: "+44 20 7946 0958", order_number: "100000123", ...DROPPED });
  for (const name of Object.keys(KEPT)) assert.equal(sent[name], KEPT[name], `${name} is still sent, so spam can still be judged`);
  for (const name of Object.keys(DROPPED)) assert.equal(name in sent, false, `${name} is never sent`);
  const blob = JSON.stringify(sent).toLowerCase();
  for (const secret of ["hunter2", "sk-live-xyz", "bearer xyz", "4111111111111111"]) assert.equal(blob.includes(secret), false, secret);
  // Numbers that are not cards stay readable, or the spam check loses context.
  assert.match(sent.phone, /7946/);
  assert.equal(sent.order_number, "100000123");
});

test("a card number is taken out of a field nobody named card, and the rest kept", () => {
  const sent = plainFields({ field_12: "my card is 4111 1111 1111 1111 thanks", amount: 4111111111111111 });
  assert.equal(sent.field_12, "my card is [removed] thanks");
  assert.equal(sent.amount, "[removed]");
  assert.equal(withoutCardNumbers("ref 1234567890123"), "ref 1234567890123", "a long number that fails Luhn is kept");
});

test("only the first fields are sent", () => {
  const many = Object.fromEntries(Array.from({ length: 200 }, (_, i) => [`f${i}`, "x"]));
  assert.ok(Object.keys(plainFields(many)).length <= 50);
});
