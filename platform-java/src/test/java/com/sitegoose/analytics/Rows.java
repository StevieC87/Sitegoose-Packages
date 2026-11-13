package com.sitegoose.analytics;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/** For tests outside this package: a platform's call rows, summed per call method and host. */
public final class Rows {
    private Rows() {
    }

    /** "METHOD host count=N errors=N", one per row, sorted, joined by "; ". */
    public static String summary(Platform platform) {
        List<String> out = new ArrayList<>();
        for (Map<String, Object> row : platform.calls().take(true)) {
            out.add(row.get("call_method") + " " + row.get("host") + " count=" + row.get("count") + " errors=" + row.get("errors"));
        }
        java.util.Collections.sort(out);
        return String.join("; ", out);
    }
}
