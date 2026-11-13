"""Form protection module: checks a form your server received before you
accept it (POST /collectanalytics/shield/verify, the same check as spam
protection's). It reads the hidden "analytics-shield" answer the tracker puts
in protected forms, and checks the email, name and text for fake sign-ups.
Spam lands in the site's spam folder (Leads -> Spam). Passwords, card numbers
and tokens are never sent. Fails open: when the check can't be made, the form
is accepted (checked False).
"""
import re

PRIVATE_FIELD = re.compile(r"pass|card|cvc|cvv|secret|token|ssn|iban|csrf|analytics-shield", re.I)
MAX_FIELDS = 50
ANSWER = "analytics-shield"


def plain_fields(fields):
    out = {}
    for label, value in list((fields or {}).items())[:MAX_FIELDS]:
        if PRIVATE_FIELD.search(str(label)):
            continue
        if isinstance(value, (list, tuple)):
            value = ", ".join(v for v in value if isinstance(v, str))
        if isinstance(value, str):
            out[str(label)[:100]] = value[:2000]
    return out


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
