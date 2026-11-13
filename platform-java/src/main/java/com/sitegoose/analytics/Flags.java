package com.sitegoose.analytics;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

/**
 * Feature flags module: turn features of your app on or off from the
 * dashboard, for everyone, a share of users, or listed user IDs.
 * isEnabled() answers from memory; the flags come with the module switches,
 * about once a minute.
 */
final class Flags {
    private final Core core;

    Flags(Core core) {
        this.core = core;
    }

    /** FNV-1a over "key:user", 0-99: the same as the Node, PHP and Python packages. */
    static int bucket(String key, String user) {
        int h = 0x811C9DC5;
        for (byte b : (key + ":" + user).getBytes(StandardCharsets.UTF_8)) {
            h ^= b & 0xFF;
            h *= 0x01000193;
        }
        return (int) (Integer.toUnsignedLong(h) % 100);
    }

    static boolean evaluate(Map<String, Object> flag, String key, String user) {
        if (!Boolean.TRUE.equals(flag.get("on"))) {
            return false;
        }
        String uid = user == null ? "" : user;
        List<String> users = Json.strings(flag.get("users"));
        if (!uid.isEmpty() && users.contains(uid)) {
            return true;
        }
        long rollout = flag.containsKey("rollout") ? Json.whole(flag.get("rollout"), 100) : 100;
        if (rollout >= 100) {
            return true;
        }
        if (rollout <= 0 || uid.isEmpty()) {
            return false;
        }
        return bucket(key, uid) < rollout;
    }

    boolean isEnabled(String key, String user, boolean otherwise) {
        try {
            Map<String, Object> flag = core.isOn("flags") ? Json.map(core.flags().get(key)) : null;
            return flag != null ? evaluate(flag, key, user) : otherwise;
        } catch (RuntimeException error) {
            return otherwise;
        }
    }
}
