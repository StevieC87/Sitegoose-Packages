package com.sitegoose.analytics;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Map;

/** The shared protocol files (sdk/protocols) and what the Python package gives for the same input. */
final class Fixtures {
    private Fixtures() {
    }

    static Path protocols() {
        String dir = System.getProperty("protocols.dir");
        return Paths.get(dir == null ? "../protocols" : dir);
    }

    static Map<String, Object> protocol(String name) {
        try {
            return Json.map(Json.parse(new String(Files.readAllBytes(protocols().resolve(name)), StandardCharsets.UTF_8)));
        } catch (IOException error) {
            throw new IllegalStateException(error);
        }
    }

    static Map<String, Object> python() {
        try (InputStream in = Fixtures.class.getResourceAsStream("/python-fixtures.json")) {
            return Json.map(Json.parse(new String(in.readAllBytes(), StandardCharsets.UTF_8)));
        } catch (IOException error) {
            throw new IllegalStateException(error);
        }
    }

    @SuppressWarnings("unchecked")
    static List<Map<String, Object>> rows(Object value) {
        return (List<Map<String, Object>>) value;
    }

    /** A core that sends nothing (no endpoint): the modules decide, nothing goes out. */
    static Core offline(String secret) {
        return new Core("a".repeat(24), secret, "", false, "test");
    }

    static Firewall firewall(String secret, Map<String, Object> rules) {
        Firewall wall = new Firewall(offline(secret), null, null);
        wall.rules = rules == null ? null : Firewall.compile(rules);
        return wall;
    }
}
