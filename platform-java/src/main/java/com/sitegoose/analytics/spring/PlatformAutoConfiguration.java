package com.sitegoose.analytics.spring;

import com.sitegoose.analytics.Platform;
import com.sitegoose.analytics.PlatformOptions;
import com.sitegoose.analytics.jakarta.PlatformFilter;
import com.sitegoose.analytics.logback.PlatformAppender;
import java.io.IOException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.function.BiConsumer;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.env.Environment;

/**
 * Spring Boot 3 (Jakarta): the whole package from application properties,
 * nothing else to write.
 *
 * <pre>
 * analytics.site-id=...
 * analytics.site-secret=${ANALYTICS_SITE_SECRET}
 * analytics.endpoint=https://...
 * </pre>
 *
 * The filter goes in front of every other filter (Spring Security's too);
 * exceptions Spring handles itself and answers with a 500 are still
 * reported; RestTemplate, RestClient and WebClient calls are timed for
 * Server speed -> Calls and become breadcrumbs; Spring
 * Security's failed logins count for bot protection and its logins and
 * logouts go in the audit log; posture reads the settings that matter
 * (actuator, error details, H2 console, session cookie) and the folders
 * Spring serves as static files; the queries run through every DataSource
 * bean, Spring Boot's MongoClient and Spring Data Redis's Lettuce client are
 * timed for Server speed -> Queries.
 * Nothing loads without analytics.site-id.
 */
@AutoConfiguration
@ConditionalOnClass(name = "jakarta.servlet.Filter")
@ConditionalOnProperty(prefix = "analytics", name = "site-id")
public class PlatformAutoConfiguration {
    static final List<String> MODULES = Arrays.asList("proxy", "firewall", "errors", "analytics", "performance", "crawlers",
            "forms", "headers", "audit", "flags", "maintenance", "inventory", "posture", "resources");

    @Bean(destroyMethod = "close")
    @ConditionalOnMissingBean
    public Platform analyticsPlatform(Environment env, org.springframework.context.ApplicationContext context) {
        PlatformOptions options = options(env);
        if (!servletWeb(context)) {
            // No servlet filter to put in front (WebFlux, or no web server at
            // all): the modules that work on requests would load and do nothing,
            // and the dashboard would show the firewall as on. Errors, events,
            // the audit log, flags and the server reports still work.
            Core_warn("not a servlet web app (WebFlux isn't supported yet): the firewall, proxy, maintenance page, "
                    + "security headers, Server speed and crawler counts are off");
            options.firewall(false).proxy(false).maintenance(false).headers(false).performance(false).crawlers(false);
        }
        return Platform.create(options);
    }

    static boolean servletWeb(Object context) {
        try {
            return Class.forName("org.springframework.web.context.WebApplicationContext", false,
                    PlatformAutoConfiguration.class.getClassLoader()).isInstance(context);
        } catch (ClassNotFoundException | LinkageError absent) {
            return false;
        }
    }

    private static void Core_warn(String message) {
        System.getLogger("com.sitegoose.analytics").log(System.Logger.Level.WARNING, "[analytics-platform] " + message);
    }

    /**
     * How Spring Boot reads the proxy headers: server.forward-headers-strategy,
     * else "native" on a cloud platform that sets them (Kubernetes, Cloud
     * Foundry, Heroku, Azure App Service), as Spring Boot itself decides.
     */
    static String forwardStrategy(Environment env) {
        String given = text(env, "server.forward-headers-strategy").toLowerCase(Locale.ROOT);
        if (!given.isEmpty()) {
            return given;
        }
        try {
            org.springframework.boot.cloud.CloudPlatform cloud = org.springframework.boot.cloud.CloudPlatform.getActive(env);
            if (cloud != null && cloud.isUsingForwardHeaders()) {
                return "native";
            }
        } catch (RuntimeException | LinkageError unknown) {
            // not one Spring Boot knows
        }
        return "none";
    }

    /** The options from analytics.* properties (and so from ANALYTICS_* environment variables). */
    static PlatformOptions options(Environment env) {
        PlatformOptions o = new PlatformOptions()
                .siteId(text(env, "analytics.site-id"))
                .secret(first(text(env, "analytics.site-secret"), text(env, "analytics.secret")))
                .endpoint(text(env, "analytics.endpoint"))
                .debug(flag(env, "analytics.debug", false))
                // Spring closes the platform with the context, after its last request.
                .shutdownHook(false);
        String trust = text(env, "analytics.trust-proxy");
        String strategy = forwardStrategy(env);
        if (!trust.isEmpty() && ("native".equals(strategy) || "framework".equals(strategy))) {
            // The container (RemoteIpValve) or Spring (ForwardedHeaderFilter) has
            // already taken the visitor's address from X-Forwarded-For and puts it in
            // getRemoteAddr(): what is left in the header is the visitor's own
            // writing, and believing it would let anyone pick their address.
            Core_warn("analytics.trust-proxy is ignored: server.forward-headers-strategy is " + strategy
                    + ", so Spring Boot already gives the visitor's address");
        } else if (!trust.isEmpty()) {
            o.trustProxy(trust);
        }
        String server = text(env, "analytics.server-name");
        if (!server.isEmpty()) {
            o.serverName(server);
        }
        o.queries(flag(env, "analytics.queries.enabled", true));
        o.calls(flag(env, "analytics.calls.enabled", true));
        for (String module : MODULES) {
            if (!flag(env, "analytics." + module + ".enabled", true)) {
                toggle(o, module);
            }
        }
        o.firewall(f -> {
            String mode = text(env, "analytics.firewall.mode");
            if (!mode.isEmpty()) {
                f.mode(mode);
            }
            String cache = text(env, "analytics.firewall.cache-file");
            if (!cache.isEmpty()) {
                f.cacheFile(cache);
            }
        });
        o.errors(e -> {
            String release = text(env, "analytics.errors.release");
            if (!release.isEmpty()) {
                e.release(release);
            }
            e.captureUncaught(flag(env, "analytics.errors.capture-uncaught", true));
            // Logged errors come through Logback (below): Spring Boot bridges
            // java.util.logging into it, so a handler on both would send twice.
            e.captureLogging(false);
            String spool = text(env, "analytics.errors.spool-dir");
            if (!spool.isEmpty()) {
                e.spoolDir(spool);
            }
        });
        o.proxy(p -> {
            String prefix = text(env, "analytics.proxy.prefix");
            if (!prefix.isEmpty()) {
                p.prefix(prefix);
            }
        });
        o.inventory(i -> {
            String sbom = text(env, "analytics.inventory.sbom");
            if (!sbom.isEmpty()) {
                i.sbom(sbom);
            }
        });
        o.posture(p -> {
            String root = text(env, "analytics.posture.root");
            if (!root.isEmpty()) {
                p.root(root);
            }
        });
        return o;
    }

    private static void toggle(PlatformOptions o, String module) {
        Map<String, BiConsumer<PlatformOptions, Boolean>> off = new LinkedHashMap<>();
        off.put("proxy", PlatformOptions::proxy);
        off.put("firewall", PlatformOptions::firewall);
        off.put("errors", PlatformOptions::errors);
        off.put("analytics", PlatformOptions::analytics);
        off.put("performance", PlatformOptions::performance);
        off.put("crawlers", PlatformOptions::crawlers);
        off.put("forms", PlatformOptions::forms);
        off.put("headers", PlatformOptions::headers);
        off.put("audit", PlatformOptions::audit);
        off.put("flags", PlatformOptions::flags);
        off.put("maintenance", PlatformOptions::maintenance);
        off.put("inventory", PlatformOptions::inventory);
        off.put("posture", PlatformOptions::posture);
        off.put("resources", PlatformOptions::resources);
        BiConsumer<PlatformOptions, Boolean> set = off.get(module);
        if (set != null) {
            set.accept(o, false);
        }
    }

    static String text(Environment env, String key) {
        String value = env.getProperty(key);
        return value == null ? "" : value.trim();
    }

    private static String first(String a, String b) {
        return a.isEmpty() ? b : a;
    }

    static boolean flag(Environment env, String key, boolean otherwise) {
        String value = text(env, key).toLowerCase(Locale.ROOT);
        if (value.isEmpty()) {
            return otherwise;
        }
        return !(value.equals("false") || value.equals("0") || value.equals("no") || value.equals("off"));
    }

    // ---- The filter, first of all ----

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    @ConditionalOnClass(name = "org.springframework.boot.web.servlet.FilterRegistrationBean")
    static class FilterConfiguration {
        @Bean
        @ConditionalOnMissingBean(name = "analyticsPlatformFilter")
        FilterRegistrationBean<PlatformFilter> analyticsPlatformFilter(Platform platform, Environment env) {
            FilterRegistrationBean<PlatformFilter> registration = new FilterRegistrationBean<>(new PlatformFilter(platform));
            registration.setName("analyticsPlatformFilter");
            // First of all; with forward-headers-strategy=framework, just after
            // Spring's ForwardedHeaderFilter (itself first), so the visitor's
            // address is the one it worked out.
            registration.setOrder("framework".equals(forwardStrategy(env)) ? Ordered.HIGHEST_PRECEDENCE + 1 : Ordered.HIGHEST_PRECEDENCE);
            registration.setAsyncSupported(true);
            registration.addUrlPatterns("/*");
            return registration;
        }

        /** Folders Spring serves as they are (static/, public/...), for posture's exposure check. */
        @Bean
        PlatformSpringSupport.StaticFolders analyticsStaticFolders(Platform platform, Environment env) {
            return new PlatformSpringSupport.StaticFolders(platform, env);
        }
    }

    // ---- Exceptions Spring MVC handles itself ----

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.springframework.web.servlet.HandlerExceptionResolver")
    @ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
    static class MvcConfiguration {
        @Bean
        PlatformSpringSupport.ErrorResolver analyticsErrorResolver() {
            return new PlatformSpringSupport.ErrorResolver();
        }
    }

    // ---- Outgoing calls: timed, and steps in the error trail ----

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = {"org.springframework.boot.web.client.RestTemplateCustomizer", "org.springframework.web.client.RestTemplate"})
    static class RestTemplateConfiguration {
        @Bean
        org.springframework.boot.web.client.RestTemplateCustomizer analyticsRestTemplateCustomizer(Platform platform) {
            return template -> template.getInterceptors().add(new PlatformSpringSupport.Breadcrumbs(platform));
        }
    }

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = {"org.springframework.boot.web.client.RestClientCustomizer", "org.springframework.web.client.RestClient"})
    static class RestClientConfiguration {
        @Bean
        org.springframework.boot.web.client.RestClientCustomizer analyticsRestClientCustomizer(Platform platform) {
            return builder -> builder.requestInterceptor(new PlatformSpringSupport.Breadcrumbs(platform));
        }
    }

    /** WebClient.Builder (spring-webflux on the classpath, in a servlet app too). */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = {"org.springframework.boot.web.reactive.function.client.WebClientCustomizer",
        "org.springframework.web.reactive.function.client.WebClient"})
    static class WebClientConfiguration {
        @Bean
        org.springframework.boot.web.reactive.function.client.WebClientCustomizer analyticsWebClientCustomizer(Platform platform) {
            return builder -> builder.filter(new PlatformSpringSupport.WebClientCalls(platform));
        }
    }

    // ---- Spring Security ----

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent")
    static class SecurityConfiguration {
        @Bean
        ApplicationListener<org.springframework.security.authentication.event.AbstractAuthenticationEvent> analyticsLoginListener(Platform platform) {
            return new PlatformSpringSupport.Logins(platform);
        }
    }

    // ---- Database queries ----

    /** Off with analytics.performance.enabled=false or analytics.queries.enabled=false. */
    static boolean queriesOn(Environment env) {
        return flag(env, "analytics.performance.enabled", true) && flag(env, "analytics.queries.enabled", true);
    }

    /**
     * Every DataSource bean, its queries timed. Static, as a post-processor's
     * bean method must be: the platform is looked up on the first query.
     */
    @Bean
    static BeanPostProcessor analyticsDataSources(ObjectProvider<Platform> platform, Environment env) {
        if (!queriesOn(env)) {
            return new BeanPostProcessor() {
            };
        }
        return new PlatformSpringSupport.DataSources(platform);
    }

    /** Spring Boot's MongoClient (and the reactive one), with the platform's command listener. */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = {"com.mongodb.MongoClientSettings", "org.springframework.boot.autoconfigure.mongo.MongoClientSettingsBuilderCustomizer"})
    static class MongoConfiguration {
        @Bean
        org.springframework.boot.autoconfigure.mongo.MongoClientSettingsBuilderCustomizer analyticsMongoListener(Platform platform, Environment env) {
            boolean on = queriesOn(env);
            return builder -> {
                if (on) {
                    builder.addCommandListener(platform.mongoListener());
                }
            };
        }
    }

    /**
     * Spring Data Redis's Lettuce client, with the platform's command
     * listener, added before its first connection (Spring Data Redis connects
     * on first use). A connection factory left for later start-up
     * (setEarlyStartup(false)) has no client yet, so it isn't watched; Jedis
     * has no hook to time its commands through.
     */
    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = {"io.lettuce.core.event.command.CommandListener", "org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory"})
    static class RedisConfiguration {
        @Bean
        static BeanPostProcessor analyticsRedisListener(ObjectProvider<Platform> platform, Environment env) {
            if (!queriesOn(env)) {
                return new BeanPostProcessor() {
                };
            }
            return new BeanPostProcessor() {
                @Override
                public Object postProcessAfterInitialization(Object bean, String beanName) {
                    if (bean instanceof org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory) {
                        try {
                            io.lettuce.core.AbstractRedisClient client =
                                    ((org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory) bean).getNativeClient();
                            if (client != null) {
                                client.addListener(Platform.<io.lettuce.core.event.command.CommandListener>redisListener(platform::getIfAvailable));
                            }
                        } catch (RuntimeException | LinkageError notThisOne) {
                            // a Lettuce before 6.1, or a factory not started: its commands aren't timed
                        }
                    }
                    return bean;
                }
            };
        }
    }

    // ---- Settings for posture ----

    @Bean
    PlatformSpringSupport.Checks analyticsPostureChecks(Platform platform, Environment env) {
        return new PlatformSpringSupport.Checks(platform, env);
    }

    // ---- Logged errors (Logback, Spring Boot's default) ----

    @Configuration(proxyBeanMethods = false)
    @ConditionalOnClass(name = "ch.qos.logback.classic.LoggerContext")
    @ConditionalOnProperty(prefix = "analytics.errors", name = "capture-logging", havingValue = "true")
    static class LogbackConfiguration {
        @Bean
        LogbackHook analyticsLogback(Platform platform) {
            return new LogbackHook(platform);
        }
    }

    /** Puts the appender on Logback's root logger for as long as the context lives. */
    static final class LogbackHook implements DisposableBean {
        private final PlatformAppender appender;

        LogbackHook(Platform platform) {
            appender = PlatformAppender.attach(platform);
        }

        @Override
        public void destroy() {
            if (appender != null) {
                appender.detach();
            }
        }
    }

    /** Resource URLs for a "classpath:" location, for posture. */
    static List<String> resourceUrls(ClassLoader loader, String location) {
        List<String> out = new ArrayList<>();
        try {
            if (location.startsWith("classpath:")) {
                String name = location.substring("classpath:".length());
                while (name.startsWith("/")) {
                    name = name.substring(1);
                }
                Enumeration<URL> found = loader.getResources(name);
                while (found.hasMoreElements()) {
                    out.add(found.nextElement().toString());
                }
            } else if (location.startsWith("file:")) {
                out.add(location);
            }
        } catch (IOException | RuntimeException unusable) {
            // left out
        }
        return out;
    }
}
