package com.sitegoose.analytics;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.URL;
import java.net.URLClassLoader;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.jar.JarEntry;
import java.util.jar.JarFile;
import java.util.jar.JarInputStream;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Stream;

/**
 * Software inventory module (sdk/protocols/inventory.md): the libraries on
 * the application's classpath and its Java version, sent to POST
 * /events/inventory a minute after start and then once a day (the
 * collector's {@code every}), so the Security check can match them against
 * known security holes. Runs in a background thread, never in a request;
 * names and versions only.
 *
 * <p>Ecosystem {@code Maven}, named {@code groupId:artifactId} as OSV.dev
 * names them. Read from, in order: a CycloneDX SBOM (the {@code sbom}
 * option, or {@code META-INF/sbom/application.cdx.json} on the classpath,
 * which Spring Boot 3.3+ writes with the CycloneDX plugin), which also says
 * which libraries the app asks for by name ({@code direct}); else the
 * {@code META-INF/maven/.../pom.properties} every Maven-built jar carries,
 * in the classpath's jars, a Spring Boot fat jar's {@code BOOT-INF/lib} and
 * a war's {@code WEB-INF/lib}. Jars built without Maven metadata (some built
 * by Gradle) carry no group and are left out rather than guessed.
 */
final class Inventory {
    static final double FIRST = 60;
    static final double RETRY_EVERY = 60 * 60;
    static final double EVERY = 24 * 60 * 60;
    static final int MAX_PACKAGES = 5000;
    static final int MAX_JARS = 3000;
    static final String ECOSYSTEM = "Maven";
    static final String SBOM_RESOURCE = "META-INF/sbom/application.cdx.json";
    private static final Pattern POM = Pattern.compile("^(?:BOOT-INF/classes/|WEB-INF/classes/)?META-INF/maven/[^/]+/[^/]+/pom\\.properties$");
    private static final Pattern NESTED = Pattern.compile("^(?:BOOT-INF/lib|WEB-INF/lib|lib)/[^/]+\\.jar$");
    private static final Pattern PURL = Pattern.compile("^pkg:maven/([^/@?#]+)/([^/@?#]+)@([^?#]+)");

    private final Core core;
    final String host;
    private final String sbom;
    private final ClassLoader loader;
    private final Periodic job;

    Inventory(Core core, PlatformOptions.InventoryOptions options, String serverName, ClassLoader loader) {
        this.core = core;
        String given = options != null && options.host != null ? options.host : serverName;
        this.host = Hosts.hostField(given);
        this.sbom = options == null ? null : options.sbom;
        this.loader = loader;
        this.job = core.valid ? core.every(this::report, FIRST) : null;
    }

    static final int POM_MAX = 16 * 1024;

    static Map<String, Object> pkg(String name, String version, boolean direct) {
        Map<String, Object> row = new LinkedHashMap<>();
        row.put("ecosystem", ECOSYSTEM);
        row.put("name", name);
        row.put("version", version);
        if (direct) {
            row.put("direct", true);
        }
        return row;
    }

    /** The libraries, one per group:artifact, sorted by name. */
    List<Map<String, Object>> packages() {
        Map<String, Map<String, Object>> found = new LinkedHashMap<>();
        String text = sbomText();
        if (text != null) {
            fromSbom(text, found);
        }
        if (found.isEmpty()) {
            for (Path place : classpath()) {
                if (found.size() >= MAX_PACKAGES * 2) {
                    break;
                }
                scan(place, found);
            }
        }
        List<Map<String, Object>> out = new ArrayList<>(found.values());
        out.sort((a, b) -> ((String) a.get("name")).toLowerCase(Locale.ROOT).compareTo(((String) b.get("name")).toLowerCase(Locale.ROOT)));
        return out;
    }

    private String sbomText() {
        try {
            if (sbom != null && !sbom.isEmpty()) {
                return new String(Files.readAllBytes(Paths.get(sbom)), StandardCharsets.UTF_8);
            }
            ClassLoader from = loader != null ? loader : Inventory.class.getClassLoader();
            URL url = from == null ? null : from.getResource(SBOM_RESOURCE);
            if (url != null) {
                try (InputStream in = url.openStream()) {
                    return new String(in.readNBytes(32 * 1024 * 1024), StandardCharsets.UTF_8);
                }
            }
        } catch (IOException | RuntimeException unreadable) {
            core.log("inventory", "SBOM not read: " + unreadable);
        }
        return null;
    }

    /** Maven components of a CycloneDX SBOM; direct: what the root component depends on. */
    static void fromSbom(String text, Map<String, Map<String, Object>> found) {
        Map<String, Object> bom = Json.map(Json.parse(text));
        if (bom == null) {
            return;
        }
        Set<String> direct = new LinkedHashSet<>();
        Map<String, Object> metadata = Json.map(bom.get("metadata"));
        Map<String, Object> root = metadata == null ? null : Json.map(metadata.get("component"));
        Object rootRef = root == null ? null : root.get("bom-ref");
        List<Object> dependencies = Json.list(bom.get("dependencies"));
        if (rootRef != null && dependencies != null) {
            for (Object item : dependencies) {
                Map<String, Object> dependency = Json.map(item);
                if (dependency != null && rootRef.equals(dependency.get("ref"))) {
                    direct.addAll(Json.strings(dependency.get("dependsOn")));
                }
            }
        }
        List<Object> components = Json.list(bom.get("components"));
        if (components == null) {
            return;
        }
        for (Object item : components) {
            Map<String, Object> component = Json.map(item);
            Object purl = component == null ? null : component.get("purl");
            if (!(purl instanceof String)) {
                continue;
            }
            Matcher m = PURL.matcher((String) purl);
            if (!m.find()) {
                continue;
            }
            String name = decode(m.group(1)) + ":" + decode(m.group(2));
            String version = decode(m.group(3));
            Object ref = component.get("bom-ref");
            found.putIfAbsent(name, pkg(name, version, ref != null && direct.contains(ref)));
        }
    }

    private static String decode(String text) {
        try {
            return URLDecoder.decode(text, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException malformed) {
            return text;
        }
    }

    /** The jars and folders the app's classes come from (the outer file of a nested jar URL). */
    private List<Path> classpath() {
        Set<Path> places = new LinkedHashSet<>();
        String path = System.getProperty("java.class.path", "");
        for (String entry : path.split(File.pathSeparator)) {
            if (!entry.isEmpty()) {
                places.add(Paths.get(entry).toAbsolutePath().normalize());
            }
        }
        for (ClassLoader at = loader; at != null; at = at.getParent()) {
            if (at instanceof URLClassLoader) {
                for (URL url : ((URLClassLoader) at).getURLs()) {
                    Path outer = outerFile(url.toString());
                    if (outer != null) {
                        places.add(outer);
                    }
                }
            }
        }
        List<Path> out = new ArrayList<>();
        for (Path place : places) {
            if (out.size() >= MAX_JARS) {
                break;
            }
            out.add(place);
        }
        return out;
    }

    /** file:/a.jar, jar:file:/a.jar!/BOOT-INF/lib/x.jar!/ and jar:nested:/a.jar/!BOOT-INF/... as /a.jar. */
    static Path outerFile(String url) {
        try {
            String text = url;
            if (text.startsWith("jar:")) {
                text = text.substring(4);
            }
            if (text.startsWith("nested:")) {
                text = "file:" + text.substring(7);
                int bang = text.indexOf("/!");
                if (bang >= 0) {
                    text = text.substring(0, bang);
                }
            }
            int bang = text.indexOf("!/");
            if (bang >= 0) {
                text = text.substring(0, bang);
            }
            if (!text.startsWith("file:")) {
                return null;
            }
            return Paths.get(new URL(text).toURI()).toAbsolutePath().normalize();
        } catch (Exception unusable) {
            return null;
        }
    }

    private void scan(Path place, Map<String, Map<String, Object>> found) {
        try {
            if (Files.isDirectory(place)) {
                Path maven = place.resolve("META-INF").resolve("maven");
                if (Files.isDirectory(maven)) {
                    try (Stream<Path> walk = Files.walk(maven, 3)) {
                        walk.filter(p -> p.getFileName().toString().equals("pom.properties")).limit(1000).forEach(p -> {
                            try (InputStream in = Files.newInputStream(p)) {
                                add(in, found);
                            } catch (IOException unreadable) {
                                // skipped
                            }
                        });
                    }
                }
                return;
            }
            if (!Files.isRegularFile(place)) {
                return;
            }
            String name = place.getFileName().toString().toLowerCase(Locale.ROOT);
            if (!name.endsWith(".jar") && !name.endsWith(".war")) {
                return;
            }
            try (JarFile jar = new JarFile(place.toFile(), false)) {
                Enumeration<JarEntry> entries = jar.entries();
                int nested = 0;
                boolean described = false;
                while (entries.hasMoreElements()) {
                    JarEntry entry = entries.nextElement();
                    String entryName = entry.getName();
                    if (POM.matcher(entryName).matches()) {
                        described = true;
                        try (InputStream in = jar.getInputStream(entry)) {
                            add(in, found);
                        }
                    } else if (NESTED.matcher(entryName).matches() && nested++ < MAX_JARS) {
                        try (JarInputStream inner = new JarInputStream(jar.getInputStream(entry), false)) {
                            JarEntry innerEntry;
                            boolean innerDescribed = false;
                            while ((innerEntry = inner.getNextJarEntry()) != null) {
                                if (POM.matcher(innerEntry.getName()).matches()) {
                                    innerDescribed = true;
                                    add(inner, found);
                                    // One library per jar: the rest of it isn't read.
                                    break;
                                }
                            }
                            if (!innerDescribed) {
                                fromJarName(entryName.substring(entryName.lastIndexOf('/') + 1), inner.getManifest(), found);
                            }
                        } catch (IOException unreadable) {
                            // one jar we can't read: the rest still count
                        }
                    }
                }
                if (!described && name.endsWith(".jar")) {
                    fromJarName(place.getFileName().toString(), jar.getManifest(), found);
                }
            }
        } catch (IOException | RuntimeException unreadable) {
            core.log("inventory", "could not read " + place + ": " + unreadable);
        }
    }

    /** Version at the end of a jar's name: spring-core-6.1.14.jar, tomcat-embed-core-10.1.31.jar. */
    private static final Pattern JAR_NAME = Pattern.compile("^([A-Za-z][A-Za-z0-9_.]*(?:-[A-Za-z][A-Za-z0-9_.]*)*)-(\\d+(?:\\.\\d+)*(?:[.-][A-Za-z0-9]+)*)\\.jar$");
    /** group#artifact;version, as Gradle-built jars give Implementation-Title (Micrometer). */
    private static final Pattern IVY_TITLE = Pattern.compile("^([A-Za-z0-9_.\\-]+)#([A-Za-z0-9_.\\-]+);(.+)$");
    /**
     * The groups of well-known families built without pom.properties
     * (Gradle: Spring; Ant: Tomcat), longest prefix first.
     */
    private static final String[][] FAMILIES = {
        {"spring-boot", "org.springframework.boot"},
        {"spring-security-", "org.springframework.security"},
        {"spring-data-", "org.springframework.data"},
        {"spring-session-", "org.springframework.session"},
        {"spring-integration-", "org.springframework.integration"},
        {"spring-batch-", "org.springframework.batch"},
        {"spring-kafka", "org.springframework.kafka"},
        {"spring-amqp", "org.springframework.amqp"},
        {"spring-rabbit", "org.springframework.amqp"},
        {"spring-graphql", "org.springframework.graphql"},
        {"spring-ws-", "org.springframework.ws"},
        {"spring-", "org.springframework"},
        {"tomcat-embed-", "org.apache.tomcat.embed"},
        {"tomcat-", "org.apache.tomcat"},
        {"micrometer-", "io.micrometer"},
        {"undertow-", "io.undertow"},
        {"netty-", "io.netty"},
    };

    /**
     * A jar with no pom.properties: its name gives artifact and version,
     * the manifest or the family the group. Left out when the group can't
     * be told: a guess would match another library's holes.
     */
    static void fromJarName(String fileName, java.util.jar.Manifest manifest, Map<String, Map<String, Object>> found) {
        java.util.regex.Matcher m = JAR_NAME.matcher(fileName == null ? "" : fileName);
        if (!m.matches()) {
            return;
        }
        String artifact = m.group(1);
        String version = m.group(2);
        String group = null;
        String title = manifest == null ? null : manifest.getMainAttributes().getValue("Implementation-Title");
        java.util.regex.Matcher ivy = IVY_TITLE.matcher(title == null ? "" : title.trim());
        if (ivy.matches() && ivy.group(2).equals(artifact)) {
            group = ivy.group(1);
        } else {
            for (String[] family : FAMILIES) {
                if (artifact.startsWith(family[0])) {
                    group = family[1];
                    break;
                }
            }
        }
        if (group == null) {
            return;
        }
        String name = group + ":" + artifact;
        found.putIfAbsent(name, pkg(name, version, false));
    }

    /** One pom.properties (groupId, artifactId, version), unless that library is already listed. */
    static void add(InputStream in, Map<String, Map<String, Object>> found) throws IOException {
        // A real one is a few hundred bytes: more is not read (and the jar stream stays open).
        byte[] data = in.readNBytes(POM_MAX);
        if (data.length >= POM_MAX) {
            return;
        }
        Properties properties = new Properties();
        properties.load(new java.io.InputStreamReader(new java.io.ByteArrayInputStream(data), StandardCharsets.ISO_8859_1));
        String group = properties.getProperty("groupId", "").trim();
        String artifact = properties.getProperty("artifactId", "").trim();
        String version = properties.getProperty("version", "").trim();
        if (group.isEmpty() || artifact.isEmpty() || version.isEmpty() || version.contains("${")) {
            return;
        }
        String name = group + ":" + artifact;
        found.putIfAbsent(name, pkg(name, version.startsWith("v") && version.length() > 1 && Character.isDigit(version.charAt(1))
                ? version.substring(1) : version, false));
    }

    /** What would be sent now (also used by tests). */
    Map<String, Object> body() {
        List<Map<String, Object>> packages = packages();
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("site_id", core.siteId);
        body.put("host", host);
        body.put("at", Instant.now().toString());
        Map<String, Object> runtime = new LinkedHashMap<>();
        runtime.put("java", System.getProperty("java.version", ""));
        body.put("runtime", runtime);
        body.put("packages", packages.size() > MAX_PACKAGES ? packages.subList(0, MAX_PACKAGES) : packages);
        body.put("truncated", packages.size() > MAX_PACKAGES);
        return body;
    }

    double report() {
        if (!core.isOn("inventory")) {
            return RETRY_EVERY;
        }
        Core.Response res = core.postBearer("inventory", "/events/inventory", body());
        if (res == null || !res.ok()) {
            return RETRY_EVERY;
        }
        Map<String, Object> answer = Json.map(res.json());
        long every = answer == null ? 0 : Json.whole(answer.get("every"), 0);
        return every > 0 ? Math.max(RETRY_EVERY, every) : EVERY;
    }

    void close() {
        if (job != null) {
            job.stop(core.stopWait());
        }
    }
}
