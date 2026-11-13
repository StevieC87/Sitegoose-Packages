package com.sitegoose.analytics;

import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * This machine's host name, as Python's socket.gethostname() gives it,
 * without a DNS lookup where it can be helped: InetAddress.getLocalHost()
 * resolves the name, which can take seconds on a misconfigured machine.
 */
final class Hosts {
    private Hosts() {
    }

    private static volatile String cached;

    static String hostName() {
        String name = cached;
        if (name != null) {
            return name;
        }
        name = firstOf(System.getenv("HOSTNAME"), read("/proc/sys/kernel/hostname"), read("/etc/hostname"),
                System.getenv("COMPUTERNAME"));
        if (name.isEmpty()) {
            try {
                name = InetAddress.getLocalHost().getHostName();
            } catch (Exception unknown) {
                name = "";
            }
        }
        cached = name;
        return name;
    }

    private static String firstOf(String... names) {
        for (String name : names) {
            if (name != null && !name.trim().isEmpty()) {
                return name.trim();
            }
        }
        return "";
    }

    private static String read(String path) {
        try {
            return new String(Files.readAllBytes(Paths.get(path)), StandardCharsets.UTF_8).trim();
        } catch (Exception unreadable) {
            return "";
        }
    }

    /** The host name for X-Server-Name: plain ASCII, 100 characters at most. */
    static String serverHeader() {
        String name = hostName().replaceAll("[^\\x21-\\x7e]", "");
        return name.length() > 100 ? name.substring(0, 100) : name;
    }

    /** A host name as inventory and posture take it: [A-Za-z0-9._-], 100 at most, else "server". */
    static String hostField(String given) {
        String name = (given == null ? hostName() : given).replaceAll("[^A-Za-z0-9._-]", "-");
        if (name.length() > 100) {
            name = name.substring(0, 100);
        }
        return name.isEmpty() ? "server" : name;
    }
}
