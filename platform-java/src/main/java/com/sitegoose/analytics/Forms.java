package com.sitegoose.analytics;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
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
    static final Pattern PRIVATE_FIELD = Pattern.compile("pass|card|cvc|cvv|secret|token|ssn|iban|csrf|analytics-shield",
            Pattern.CASE_INSENSITIVE);
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
                out.put(label.length() > 100 ? label.substring(0, 100) : label, value.length() > 2000 ? value.substring(0, 2000) : value);
            }
        }
        return out;
    }

    /** A field's text: a string, or the strings of a list or array joined with ", "; null otherwise. */
    private static String text(Object value) {
        if (value instanceof String) {
            return (String) value;
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
        Map<String, Object> data = Json.map(res.json());
        if (data == null) {
            data = Collections.emptyMap();
        }
        boolean spam = Boolean.FALSE.equals(data.get("success"));
        return new FormCheck(!spam, spam, Json.strings(data.get("reasons")), true);
    }
}
