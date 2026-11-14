package com.sitegoose.analytics;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Form protection module: checks a form your server received before you
 * accept it (POST /collectanalytics/shield/verify, the same check as spam
 * protection's). It reads the hidden "analytics-shield" answer the tracker
 * puts in protected forms, and checks the email, name and text for fake
 * sign-ups. Spam lands in Leads -> Spam. Passwords, card numbers and tokens
 * are never sent. Fails open: when the check can't be made, the form is
 * accepted (checked false).
 */
final class Forms {
    /**
     * Fields never sent, by name. Whoever protects a sign-up or checkout form
     * relies on this list, so it is wide: passwords, cards (the browser's own
     * autofill names are "cc-number", "cc-csc" and "cc-exp"), one-time codes,
     * keys, identity numbers, bank details. ("pass" also covers passwd and
     * passport.) The same list as the PHP and Python packages.
     */
    static final Pattern PRIVATE_FIELD = Pattern.compile(
            "pass|pwd|card|cc[-_]?(num|no|number|csc|exp)|cvc|cvv|cvn|expiry|exp[-_]?(month|year|date)|secret|token"
                    + "|\\bauth\\b|authoriz|api[-_]?key|otp|mfa|2fa|\\bpin\\b|security[-_]?code|signature|private|ssn|sin\\b|nino"
                    + "|tax[-_]?id|iban|bic|swift|routing|account[-_]?(no|num|number)|dob|birth|licen[cs]e|csrf|nonce"
                    + "|analytics-shield", Pattern.CASE_INSENSITIVE);
    /**
     * A card number in a field nobody thought to name "card" still must not be
     * sent, so values are checked too: 13-19 digits that pass Luhn are taken
     * out of the text and the rest of the message is kept, so spam is still judged.
     */
    static final Pattern DIGITS = Pattern.compile("\\b(?:\\d[ -]?){12,18}\\d\\b");
    static final int MAX_FIELDS = 50;
    static final String ANSWER = "analytics-shield";

    private final Core core;

    Forms(Core core) {
        this.core = core;
    }

    static Map<String, String> plainFields(Map<String, ?> fields) {
        Map<String, String> out = new LinkedHashMap<>();
        int n = 0;
        for (Map.Entry<String, ?> entry : fields.entrySet()) {
            if (n++ >= MAX_FIELDS) {
                break;
            }
            String label = String.valueOf(entry.getKey());
            if (PRIVATE_FIELD.matcher(label).find()) {
                continue;
            }
            String value = text(entry.getValue());
            if (value != null) {
                out.put(label.length() > 100 ? label.substring(0, 100) : label,
                        withoutCardNumbers(value.length() > 2000 ? value.substring(0, 2000) : value));
            }
        }
        return out;
    }

    private static boolean luhn(String digits) {
        int total = 0;
        for (int i = 0; i < digits.length(); i++) {
            int n = digits.charAt(digits.length() - 1 - i) - '0';
            if (i % 2 == 1) {
                n = n > 4 ? n * 2 - 9 : n * 2;
            }
            total += n;
        }
        return total % 10 == 0;
    }

    /** Anything shaped like a card number, and passing Luhn, as [removed]. Luhn is what keeps order numbers and phone numbers readable. */
    static String withoutCardNumbers(String text) {
        return DIGITS.matcher(text).replaceAll(found -> Matcher.quoteReplacement(
                luhn(found.group().replaceAll("\\D", "")) ? "[removed]" : found.group()));
    }

    /** A field's text: a string, or the strings of a list or array joined with ", "; null otherwise. */
    private static String text(Object value) {
        if (value instanceof String) {
            return (String) value;
        }
        if (value instanceof Number) {
            return String.valueOf(value);
        }
        Collection<?> items = value instanceof String[] ? java.util.Arrays.asList((String[]) value)
                : value instanceof Collection ? (Collection<?>) value : null;
        if (items == null) {
            return null;
        }
        if (items.size() == 1 && items.iterator().next() instanceof String) {
            return (String) items.iterator().next();
        }
        List<String> parts = new ArrayList<>();
        for (Object item : items) {
            if (item instanceof String) {
                parts.add((String) item);
            }
        }
        return String.join(", ", parts);
    }

    static FormCheck unchecked() {
        return new FormCheck(true, false, Collections.singletonList("unchecked"), false);
    }

    FormCheck check(Map<String, ?> given, String ip, String email, String name, String form) {
        if (!core.isOn("forms")) {
            return new FormCheck(true, false, Collections.emptyList(), false);
        }
        Map<String, ?> fields = given == null ? Collections.emptyMap() : given;
        Object token = fields.get(ANSWER);
        if (token instanceof String[]) {
            token = ((String[]) token).length > 0 ? ((String[]) token)[0] : "";
        } else if (token instanceof List) {
            token = ((List<?>) token).isEmpty() ? "" : ((List<?>) token).get(0);
        }
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("token", token instanceof String ? token : "");
        body.put("fields", plainFields(fields));
        body.put("ip", ip == null ? "" : ip);
        if (email != null) {
            body.put("email", email);
        }
        if (name != null) {
            body.put("name", name);
        }
        if (form != null) {
            body.put("form", form);
        }
        Core.Response res = core.post("forms", "/collectanalytics/shield/verify", body);
        if (res == null || res.status >= 500 || res.status == 403 || res.status == 429) {
            if (res != null && res.status == 403) {
                core.log("forms", "the site secret was refused; forms aren't checked");
            }
            return unchecked();
        }
        Map<String, Object> data = res.status == 200 ? Json.map(res.json()) : null;
        // A verdict, spam or not, is always a 200 with `success`. Anything else
        // judged nothing, and must not look like protection that works.
        if (data == null || !(data.get("success") instanceof Boolean)) {
            return unchecked();
        }
        boolean spam = Boolean.FALSE.equals(data.get("success"));
        return new FormCheck(!spam, spam, Json.strings(data.get("reasons")), true);
    }
}
