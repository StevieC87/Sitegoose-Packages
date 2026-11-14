package com.sitegoose.analytics.spring;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.springframework.core.env.MapPropertySource;
import org.springframework.core.env.StandardEnvironment;

class SpringSupportTest {
    static StandardEnvironment env(Map<String, Object> properties) {
        StandardEnvironment env = new StandardEnvironment();
        env.getPropertySources().addFirst(new MapPropertySource("test", properties));
        return env;
    }

    static Map<String, String> states(List<Map<String, Object>> checks) {
        Map<String, String> out = new HashMap<>();
        for (Map<String, Object> check : checks) {
            out.put((String) check.get("id"), check.get("state") + (check.containsKey("value") ? " " + check.get("value") : ""));
        }
        return out;
    }

    @Test
    void settingsThatLeaveTheSiteOpen() {
        PlatformSpringSupport.Checks quiet = new PlatformSpringSupport.Checks(com.sitegoose.analytics.Platform.create(
                new com.sitegoose.analytics.PlatformOptions().shutdownHook(false)), env(new HashMap<>()));
        Map<String, String> defaults = states(quiet.checks());
        assertEquals("pass", defaults.get("app.session_cookie_httponly"));
        assertEquals("pass", defaults.get("app.error_details"));

        Map<String, Object> open = new HashMap<>();
        open.put("server.servlet.session.cookie.http-only", "false");
        open.put("server.ssl.enabled", "true");
        open.put("server.error.include-stacktrace", "always");
        open.put("management.endpoints.web.exposure.include", "*");
        open.put("management.endpoints.web.exposure.exclude", "shutdown");
        PlatformSpringSupport.Checks checks = new PlatformSpringSupport.Checks(com.sitegoose.analytics.Platform.create(
                new com.sitegoose.analytics.PlatformOptions().shutdownHook(false)), env(open));
        Map<String, String> got = states(checks.checks());
        assertEquals("fail", got.get("app.session_cookie_httponly"));
        assertEquals("fail", got.get("app.session_cookie_secure"));
        assertEquals("fail include-stacktrace=always", got.get("app.error_details"));
        List<String> exposed = checks.actuatorOpen();
        assertTrue(exposed.contains("env") && exposed.contains("heapdump"), exposed.toString());
        assertTrue(!exposed.contains("shutdown"), exposed.toString());
    }

    @Test
    void propertiesBecomeOptions() {
        Map<String, Object> p = new HashMap<>();
        p.put("analytics.site-id", "a".repeat(24));
        p.put("analytics.site-secret", "s");
        p.put("analytics.endpoint", "http://127.0.0.1:1");
        p.put("analytics.resources.enabled", "false");
        p.put("analytics.proxy.enabled", "off");
        com.sitegoose.analytics.Platform platform = com.sitegoose.analytics.Platform.create(PlatformAutoConfiguration.options(env(p)));
        try {
            assertTrue(platform.isConfigured());
            List<String> modules = platform.modules();
            assertTrue(!modules.contains("resources") && !modules.contains("proxy") && modules.contains("firewall"), modules.toString());
        } finally {
            platform.close();
        }
    }

    static Map<String, Object> site(Map<String, Object> more) {
        Map<String, Object> p = new HashMap<>(more);
        p.put("analytics.site-id", "a".repeat(24));
        p.put("analytics.site-secret", "s");
        p.put("analytics.endpoint", "http://127.0.0.1:9");
        p.put("analytics.trust-proxy", "1");
        return p;
    }

    static String ipFor(Map<String, Object> properties) {
        com.sitegoose.analytics.Platform platform = com.sitegoose.analytics.Platform.create(
                PlatformAutoConfiguration.options(env(properties)).shutdownHook(false));
        try {
            return platform.clientIp("198.51.100.7", java.util.Collections.singletonMap("x-forwarded-for", "203.0.113.5"));
        } finally {
            platform.close();
        }
    }

    @Test
    void trustProxyIsIgnoredWhenTheServerReadsTheProxyHeadersItself() {
        assertEquals("203.0.113.5", ipFor(site(new HashMap<>())), "no strategy: trust-proxy as configured");
        Map<String, Object> nativeStrategy = new HashMap<>();
        nativeStrategy.put("server.forward-headers-strategy", "native");
        assertEquals("198.51.100.7", ipFor(site(nativeStrategy)));
        Map<String, Object> framework = new HashMap<>();
        framework.put("server.forward-headers-strategy", "FRAMEWORK");
        // The filter reads from under Spring's ForwardedHeaderFilter, so trust-proxy
        // counts from the right there; without one, one proxy.
        assertEquals("203.0.113.5", ipFor(site(framework)));
        Map<String, Object> frameworkAlone = site(framework);
        frameworkAlone.remove("analytics.trust-proxy");
        assertEquals("203.0.113.5", ipFor(frameworkAlone));
        Map<String, Object> kubernetes = new HashMap<>();
        kubernetes.put("spring.main.cloud-platform", "kubernetes");
        assertEquals("framework", PlatformAutoConfiguration.forwardStrategy(env(framework)).toLowerCase(java.util.Locale.ROOT));
        assertEquals("native", PlatformAutoConfiguration.forwardStrategy(env(kubernetes)));
        assertEquals("198.51.100.7", ipFor(site(kubernetes)), "a cloud platform turns native on");
        Map<String, Object> none = new HashMap<>(kubernetes);
        none.put("server.forward-headers-strategy", "none");
        assertEquals("203.0.113.5", ipFor(site(none)));
    }

    @Test
    void yamlListsAndTheManagementPort() {
        Map<String, Object> yaml = new HashMap<>();
        yaml.put("management.endpoints.web.exposure.include[0]", "health");
        yaml.put("management.endpoints.web.exposure.include[1]", "env");
        yaml.put("management.endpoints.web.exposure.include[2]", "beans");
        PlatformSpringSupport.Checks checks = new PlatformSpringSupport.Checks(com.sitegoose.analytics.Platform.create(
                new com.sitegoose.analytics.PlatformOptions().shutdownHook(false)), env(yaml));
        assertEquals(java.util.Arrays.asList("env", "beans"), checks.actuatorOpen());
        yaml.put("management.server.port", "9090");
        assertTrue(new PlatformSpringSupport.Checks(com.sitegoose.analytics.Platform.create(
                new com.sitegoose.analytics.PlatformOptions().shutdownHook(false)), env(yaml)).actuatorOpen().isEmpty(), "not on the site's port");
        yaml.put("server.port", "9090");
        assertEquals(2, new PlatformSpringSupport.Checks(com.sitegoose.analytics.Platform.create(
                new com.sitegoose.analytics.PlatformOptions().shutdownHook(false)), env(yaml)).actuatorOpen().size(), "the same port");
    }

    @Test
    void withoutAServletFilterTheRequestModulesAreOff() {
        PlatformAutoConfiguration config = new PlatformAutoConfiguration();
        Map<String, Object> p = site(new HashMap<>());
        com.sitegoose.analytics.Platform reactive = config.analyticsPlatform(env(p), new org.springframework.context.support.GenericApplicationContext());
        com.sitegoose.analytics.Platform servlet = config.analyticsPlatform(env(p), new org.springframework.web.context.support.GenericWebApplicationContext());
        try {
            List<String> off = reactive.modules();
            assertTrue(!off.contains("firewall") && !off.contains("proxy") && !off.contains("performance") && off.contains("errors"), off.toString());
            assertTrue(servlet.modules().contains("firewall"), servlet.modules().toString());
        } finally {
            reactive.close();
            servlet.close();
        }
    }
}
