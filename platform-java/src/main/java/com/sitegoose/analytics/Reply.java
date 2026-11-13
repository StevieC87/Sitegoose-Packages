package com.sitegoose.analytics;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * An answer the package gives in place of the site: the firewall's 403/429,
 * the browser check's page, the maintenance page, a proxied tracker file.
 * An integration sends the status, headers and body as they are.
 */
public final class Reply {
    private final int status;
    private final List<String[]> headers = new ArrayList<>();
    private byte[] body = new byte[0];

    public Reply(int status) {
        this.status = status;
    }

    Reply header(String name, String value) {
        headers.add(new String[] {name, value});
        return this;
    }

    Reply body(byte[] content) {
        body = content == null ? new byte[0] : content;
        return this;
    }

    Reply body(String content) {
        return body(content.getBytes(StandardCharsets.UTF_8));
    }

    public int status() {
        return status;
    }

    /** Header name/value pairs, in order. */
    public List<String[]> headers() {
        return Collections.unmodifiableList(headers);
    }

    /** The first value of a header, or null. */
    public String header(String name) {
        for (String[] pair : headers) {
            if (pair[0].equalsIgnoreCase(name)) {
                return pair[1];
            }
        }
        return null;
    }

    public byte[] body() {
        return body;
    }
}
