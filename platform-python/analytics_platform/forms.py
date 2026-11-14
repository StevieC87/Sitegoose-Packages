"""Form protection module: checks a form your server received before you
accept it (POST /collectanalytics/shield/verify, the same check as spam
protection's). It reads the hidden "analytics-shield" answer the tracker puts
in protected forms, and checks the email, name and text for fake sign-ups.
Spam lands in the site's spam folder (Leads -> Spam). Passwords, card numbers
and tokens are never sent. Fails open: when the check can't be made, the form
is accepted (checked False).
"""
import re

# Fields never sent, by name. check() is handed the whole form, so whoever
# protects a sign-up or a checkout relies on this list: keep it wide, and the
# same as platform-php's Forms.php, with "-" as well as "_" between words: the
# browser's own autofill names are "cc-number", "cc-csc" and "cc-exp".
# ("pass" also covers passwd and passport.)
PRIVATE_FIELD = re.compile(
    r"pass|pwd|card|cc[-_]?(num|no|number|csc|exp)|cvc|cvv|cvn|expiry|exp[-_]?(month|year|date)|secret|token"
    r"|\bauth\b|authoriz|api[-_]?key|otp|mfa|2fa|\bpin\b|security[-_]?code|signature|private|ssn|sin\b|nino"
    r"|tax[-_]?id|iban|bic|swift|routing|account[-_]?(no|num|number)|dob|birth|licen[cs]e|csrf|nonce"
    r"|analytics-shield", re.I | re.A)
# A card number in a field nobody thought to name "card" still must not be
# sent, so values are checked too: 13-19 digits that pass Luhn are taken out
# of the text and the rest of the message is kept, so spam is still judged.
DIGITS = re.compile(r"\b(?:\d[ -]?){12,18}\d\b", re.A)
MAX_FIELDS = 50
ANSWER = "analytics-shield"


def plain_fields(fields):
    out = {}
    for label, value in list((fields or {}).items())[:MAX_FIELDS]:
        if PRIVATE_FIELD.search(str(label)):
            continue
        if isinstance(value, (list, tuple)):
            value = ", ".join(v for v in value if isinstance(v, str))
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            value = str(value)
        if isinstance(value, str):
            out[str(label)[:100]] = without_card_numbers(value[:2000])
    return out


def _luhn(digits):
    total = 0
    for index, char in enumerate(reversed(digits)):
        n = int(char)
        if index % 2:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


def without_card_numbers(text):
    """Anything shaped like a card number, and passing Luhn, as [removed].
    Luhn is what keeps order numbers and phone numbers readable."""
    return DIGITS.sub(lambda m: "[removed]" if _luhn(re.sub(r"\D", "", m.group(0))) else m.group(0), str(text))


class Forms:
    def __init__(self, core, **_):
        self.core = core

    def check(self, fields, ip="", email=None, name=None, form=None):
        """fields: the form as a dict. -> {"ok", "spam", "reasons", "checked"}."""
        unchecked = {"ok": True, "spam": False, "reasons": ["unchecked"], "checked": False}
        if not self.core.is_on("forms"):
            return {"ok": True, "spam": False, "reasons": [], "checked": False}
        fields = dict(fields or {})
        token = fields.get(ANSWER)
        if isinstance(token, (list, tuple)):
            token = token[0] if token else ""
        body = {"token": token if isinstance(token, str) else "", "fields": plain_fields(fields), "ip": ip or ""}
        for key, value in (("email", email), ("name", name), ("form", form)):
            if isinstance(value, str):
                body[key] = value
        res = self.core.send("forms", "/collectanalytics/shield/verify", body=body)
        if res is None or res.status >= 500 or res.status in (403, 429):
            if res is not None and res.status == 403:
                self.core.log("forms", "the site secret was refused; forms aren't checked")
            return unchecked
        data = res.json() or {}
        spam = data.get("success") is False
        return {"ok": not spam, "spam": spam, "reasons": list(data.get("reasons") or []), "checked": True}

    def flush(self):
        pass

    def close(self):
        pass
