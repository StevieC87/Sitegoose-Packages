package com.sitegoose.analytics;

import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * The little JSON the package needs, with no dependency: objects become
 * {@code LinkedHashMap<String, Object>}, arrays {@code ArrayList<Object>},
 * numbers {@code Long} when whole and in range, else {@code Double}.
 * Not a general-purpose library: what the collector sends and what the
 * modules write.
 */
public final class Json {
    private Json() {
    }

    /** The value, or null when the text isn't JSON. */
    public static Object parse(String text) {
        if (text == null) {
            return null;
        }
        try {
            Parser parser = new Parser(text);
            parser.space();
            Object value = parser.value(0);
            parser.space();
            return parser.at == text.length() ? value : null;
        } catch (RuntimeException error) {
            return null;
        }
    }

    /**
     * A copy made of what JSON holds (maps with text keys, lists, text,
     * numbers, true/false, null); anything else as its toString(). Taken
     * when your code hands a value over, so an object that can't be read
     * later (a JPA entity outside its session) fails there, in your call,
     * rather than when the batch is sent. Throws IllegalArgumentException
     * when a value can't be turned into text.
     */
    static Object safe(Object value) {
        return safe(value, 0);
    }

    private static Object safe(Object value, int depth) {
        if (depth > 32) {
            throw new IllegalArgumentException("nested too deep");
        }
        if (value == null || value instanceof String || value instanceof Boolean || value instanceof Long
                || value instanceof Integer || value instanceof Short || value instanceof Byte || value instanceof Double
                || value instanceof Float) {
            return value;
        }
        try {
            if (value instanceof java.math.BigDecimal || value instanceof java.math.BigInteger) {
                return value;
            }
            if (value instanceof Number) {
                return ((Number) value).doubleValue();
            }
            if (value instanceof Map) {
                Map<String, Object> out = new java.util.LinkedHashMap<>();
                for (Map.Entry<?, ?> entry : ((Map<?, ?>) value).entrySet()) {
                    out.put(String.valueOf(entry.getKey()), safe(entry.getValue(), depth + 1));
                }
                return out;
            }
            if (value instanceof Iterable) {
                List<Object> out = new java.util.ArrayList<>();
                for (Object item : (Iterable<?>) value) {
                    out.add(safe(item, depth + 1));
                }
                return out;
            }
            if (value instanceof Object[]) {
                List<Object> out = new java.util.ArrayList<>();
                for (Object item : (Object[]) value) {
                    out.add(safe(item, depth + 1));
                }
                return out;
            }
            if (value instanceof int[] || value instanceof long[] || value instanceof double[]) {
                return parse(write(value));
            }
            return String.valueOf(value);
        } catch (IllegalArgumentException error) {
            throw error;
        } catch (RuntimeException | StackOverflowError error) {
            throw new IllegalArgumentException("a value that can't be sent (" + value.getClass().getName() + "): " + error, error);
        }
    }

    @SuppressWarnings("unchecked")
    static Map<String, Object> safeMap(Map<String, ?> value) {
        return value == null ? null : (Map<String, Object>) safe(value);
    }

    public static String write(Object value) {
        StringBuilder out = new StringBuilder();
        write(out, value, 0);
        return out.toString();
    }

    @SuppressWarnings("unchecked")
    private static void write(StringBuilder out, Object value, int depth) {
        if (depth > 64) {
            out.append("null");
        } else if (value == null) {
            out.append("null");
        } else if (value instanceof String) {
            quote(out, (String) value);
        } else if (value instanceof Boolean) {
            out.append(value);
        } else if (value instanceof Double || value instanceof Float) {
            double d = ((Number) value).doubleValue();
            if (Double.isNaN(d) || Double.isInfinite(d)) {
                out.append("null");
            } else if (d == Math.rint(d) && Math.abs(d) < 1e15) {
                out.append((long) d);
            } else {
                out.append(d);
            }
        } else if (value instanceof Number) {
            out.append(value);
        } else if (value instanceof Map) {
            out.append('{');
            boolean first = true;
            for (Map.Entry<Object, Object> entry : ((Map<Object, Object>) value).entrySet()) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                quote(out, String.valueOf(entry.getKey()));
                out.append(':');
                write(out, entry.getValue(), depth + 1);
            }
            out.append('}');
        } else if (value instanceof Collection) {
            out.append('[');
            boolean first = true;
            for (Object item : (Collection<Object>) value) {
                if (!first) {
                    out.append(',');
                }
                first = false;
                write(out, item, depth + 1);
            }
            out.append(']');
        } else if (value instanceof Object[]) {
            out.append('[');
            Object[] items = (Object[]) value;
            for (int i = 0; i < items.length; i++) {
                if (i > 0) {
                    out.append(',');
                }
                write(out, items[i], depth + 1);
            }
            out.append(']');
        } else if (value instanceof int[]) {
            out.append('[');
            int[] items = (int[]) value;
            for (int i = 0; i < items.length; i++) {
                if (i > 0) {
                    out.append(',');
                }
                out.append(items[i]);
            }
            out.append(']');
        } else {
            quote(out, String.valueOf(value));
        }
    }

    private static void quote(StringBuilder out, String text) {
        out.append('"');
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            switch (c) {
                case '"':
                    out.append("\\\"");
                    break;
                case '\\':
                    out.append("\\\\");
                    break;
                case '\n':
                    out.append("\\n");
                    break;
                case '\r':
                    out.append("\\r");
                    break;
                case '\t':
                    out.append("\\t");
                    break;
                case '\b':
                    out.append("\\b");
                    break;
                case '\f':
                    out.append("\\f");
                    break;
                default:
                    // Plain ASCII on the wire, as Python's json.dumps writes it;
                    // U+2028/2029 escaped so the text is safe inside a script too.
                    if (c < 0x20 || c > 0x7e) {
                        out.append(String.format("\\u%04x", (int) c));
                    } else {
                        out.append(c);
                    }
            }
        }
        out.append('"');
    }

    // ---- Reading values out of parsed JSON, without casts all over ----

    @SuppressWarnings("unchecked")
    static Map<String, Object> map(Object value) {
        return value instanceof Map ? (Map<String, Object>) value : null;
    }

    @SuppressWarnings("unchecked")
    static List<Object> list(Object value) {
        return value instanceof List ? (List<Object>) value : null;
    }

    /** A whole number: JSON numbers and numeric strings, as Python's int() takes them. */
    static long whole(Object value, long otherwise) {
        if (value instanceof Number) {
            double d = ((Number) value).doubleValue();
            return Double.isNaN(d) || Double.isInfinite(d) ? otherwise : (long) d;
        }
        if (value instanceof String) {
            try {
                return Long.parseLong(((String) value).trim());
            } catch (NumberFormatException error) {
                return otherwise;
            }
        }
        return otherwise;
    }

    /** Strings of a JSON list (anything else in it skipped). */
    static List<String> strings(Object value) {
        List<String> out = new ArrayList<>();
        List<Object> items = list(value);
        if (items != null) {
            for (Object item : items) {
                if (item instanceof String) {
                    out.add((String) item);
                }
            }
        }
        return out;
    }

    private static final class Parser {
        final String text;
        int at;

        Parser(String text) {
            this.text = text;
        }

        void space() {
            while (at < text.length()) {
                char c = text.charAt(at);
                if (c == ' ' || c == '\n' || c == '\r' || c == '\t') {
                    at++;
                } else {
                    break;
                }
            }
        }

        Object value(int depth) {
            if (depth > 200) {
                throw new IllegalArgumentException("too deep");
            }
            char c = text.charAt(at);
            switch (c) {
                case '{':
                    return object(depth);
                case '[':
                    return array(depth);
                case '"':
                    return string();
                case 't':
                    expect("true");
                    return Boolean.TRUE;
                case 'f':
                    expect("false");
                    return Boolean.FALSE;
                case 'n':
                    expect("null");
                    return null;
                default:
                    return number();
            }
        }

        void expect(String word) {
            if (!text.startsWith(word, at)) {
                throw new IllegalArgumentException("bad literal");
            }
            at += word.length();
        }

        Map<String, Object> object(int depth) {
            Map<String, Object> out = new LinkedHashMap<>();
            at++;
            space();
            if (text.charAt(at) == '}') {
                at++;
                return out;
            }
            while (true) {
                space();
                if (text.charAt(at) != '"') {
                    throw new IllegalArgumentException("key");
                }
                String key = string();
                space();
                if (text.charAt(at++) != ':') {
                    throw new IllegalArgumentException("colon");
                }
                space();
                out.put(key, value(depth + 1));
                space();
                char c = text.charAt(at++);
                if (c == '}') {
                    return out;
                }
                if (c != ',') {
                    throw new IllegalArgumentException("comma");
                }
            }
        }

        List<Object> array(int depth) {
            List<Object> out = new ArrayList<>();
            at++;
            space();
            if (text.charAt(at) == ']') {
                at++;
                return out;
            }
            while (true) {
                space();
                out.add(value(depth + 1));
                space();
                char c = text.charAt(at++);
                if (c == ']') {
                    return out;
                }
                if (c != ',') {
                    throw new IllegalArgumentException("comma");
                }
            }
        }

        String string() {
            at++;
            StringBuilder out = new StringBuilder();
            while (true) {
                char c = text.charAt(at++);
                if (c == '"') {
                    return out.toString();
                }
                if (c == '\\') {
                    char e = text.charAt(at++);
                    switch (e) {
                        case '"':
                        case '\\':
                        case '/':
                            out.append(e);
                            break;
                        case 'b':
                            out.append('\b');
                            break;
                        case 'f':
                            out.append('\f');
                            break;
                        case 'n':
                            out.append('\n');
                            break;
                        case 'r':
                            out.append('\r');
                            break;
                        case 't':
                            out.append('\t');
                            break;
                        case 'u':
                            out.append((char) Integer.parseInt(text.substring(at, at + 4), 16));
                            at += 4;
                            break;
                        default:
                            throw new IllegalArgumentException("escape");
                    }
                } else if (c < 0x20) {
                    throw new IllegalArgumentException("control character");
                } else {
                    out.append(c);
                }
            }
        }

        Object number() {
            int start = at;
            if (text.charAt(at) == '-') {
                at++;
            }
            boolean decimal = false;
            while (at < text.length()) {
                char c = text.charAt(at);
                if (c >= '0' && c <= '9') {
                    at++;
                } else if (c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') {
                    decimal = true;
                    at++;
                } else {
                    break;
                }
            }
            String number = text.substring(start, at);
            if (number.isEmpty() || "-".equals(number)) {
                throw new IllegalArgumentException("number");
            }
            if (!decimal) {
                try {
                    return Long.parseLong(number);
                } catch (NumberFormatException tooBig) {
                    return Double.parseDouble(number);
                }
            }
            return Double.parseDouble(number);
        }
    }
}
