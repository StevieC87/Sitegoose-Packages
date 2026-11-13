package com.sitegoose.analytics.spring;

import com.sitegoose.analytics.Platform;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.reflect.Method;
import java.sql.Connection;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.function.Supplier;
import javax.sql.DataSource;
import org.aopalliance.intercept.MethodInterceptor;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.aop.Advisor;
import org.springframework.aop.framework.Advised;
import org.springframework.aop.framework.ProxyFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.config.BeanPostProcessor;
import org.springframework.context.ApplicationListener;
import org.springframework.core.Ordered;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.authentication.event.AbstractAuthenticationEvent;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.InteractiveAuthenticationSuccessEvent;
import org.springframework.security.authentication.event.LogoutSuccessEvent;
import org.springframework.web.servlet.HandlerExceptionResolver;
import org.springframework.web.servlet.ModelAndView;

/** The pieces the auto-configuration registers, each loaded only when its library is there. */
public final class PlatformSpringSupport {
    private PlatformSpringSupport() {
    }

    /**
     * First of Spring MVC's exception resolvers: notes the exception on the
     * request and lets the others handle it. When the answer is still a 500,
     * the filter reports it at the end of the request.
     */
    public static final class ErrorResolver implements HandlerExceptionResolver, Ordered {
        @Override
        public ModelAndView resolveException(HttpServletRequest request, HttpServletResponse response, Object handler, Exception error) {
            if (request.getAttribute(Platform.ERROR_ATTRIBUTE) == null) {
                request.setAttribute(Platform.ERROR_ATTRIBUTE, error);
            }
            return null;
        }

        @Override
        public int getOrder() {
            return Ordered.HIGHEST_PRECEDENCE;
        }
    }

    /**
     * RestTemplate / RestClient calls, timed for Server speed -> Calls (from
     * sending to the response's headers: execute() returns before the body is
     * read) and added to the error trail: method, address without its query,
     * status. Only the host goes into the timings.
     */
    public static final class Breadcrumbs implements ClientHttpRequestInterceptor {
        private final Platform platform;

        public Breadcrumbs(Platform platform) {
            this.platform = platform;
        }

        @Override
        public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {
            // An outer hook times this call already (a second interceptor of these): counted once, there.
            // An OkHttp interceptor inside execute() sees this one and leaves the call to it.
            if (!Platform.beginCallTiming()) {
                return execution.execute(request, body);
            }
            try {
                String method = String.valueOf(request.getMethod());
                String url = String.valueOf(request.getURI());
                long started = System.nanoTime();
                ClientHttpResponse response;
                try {
                    response = execution.execute(request, body);
                } catch (IOException | RuntimeException error) {
                    record(method, url, started, 0);
                    throw error;
                }
                int status = 0;
                try {
                    status = response.getStatusCode().value();
                } catch (IOException | RuntimeException unknown) {
                    // no status: an answer that can't be read counts as none
                }
                record(method, url, started, status);
                return response;
            } finally {
                Platform.endCallTiming();
            }
        }

        private void record(String method, String url, long started, int status) {
            try {
                platform.recordCall(method, url, started, status);
            } catch (RuntimeException ignored) {
                // never in the way of the call
            }
        }
    }

    /**
     * WebClient calls, timed as {@link Breadcrumbs} times RestTemplate's: from
     * subscribing to the response (its status and headers) arriving. The
     * request the call belongs to is the one on the thread that subscribed
     * (a block() in a controller); the answer comes on another. A cancelled
     * call isn't counted.
     */
    public static final class WebClientCalls implements org.springframework.web.reactive.function.client.ExchangeFilterFunction {
        private final Platform platform;

        public WebClientCalls(Platform platform) {
            this.platform = platform;
        }

        @Override
        public reactor.core.publisher.Mono<org.springframework.web.reactive.function.client.ClientResponse> filter(
                org.springframework.web.reactive.function.client.ClientRequest request,
                org.springframework.web.reactive.function.client.ExchangeFunction next) {
            return reactor.core.publisher.Mono.defer(() -> {
                com.sitegoose.analytics.RequestContext context = com.sitegoose.analytics.RequestContext.current();
                String method = String.valueOf(request.method());
                String url = String.valueOf(request.url());
                long started = System.nanoTime();
                java.util.concurrent.atomic.AtomicBoolean done = new java.util.concurrent.atomic.AtomicBoolean();
                return next.exchange(request)
                        .doOnNext(response -> {
                            if (done.compareAndSet(false, true)) {
                                int status = 0;
                                try {
                                    status = response.statusCode().value();
                                } catch (RuntimeException unknown) {
                                    // counted as no answer
                                }
                                record(method, url, started, status, context);
                            }
                        })
                        .doOnError(error -> {
                            if (done.compareAndSet(false, true)) {
                                record(method, url, started, 0, context);
                            }
                        });
            });
        }

        private void record(String method, String url, long started, int status, com.sitegoose.analytics.RequestContext context) {
            try {
                platform.recordCall(method, url, started, status, context);
            } catch (RuntimeException ignored) {
                // never in the way of the call
            }
        }
    }

    /** Spring Security: failed logins count for bot protection; logins and logouts go in the audit log. */
    public static final class Logins implements ApplicationListener<AbstractAuthenticationEvent> {
        private final Platform platform;

        public Logins(Platform platform) {
            this.platform = platform;
        }

        @Override
        public void onApplicationEvent(AbstractAuthenticationEvent event) {
            try {
                if (event instanceof AbstractAuthenticationFailureEvent) {
                    platform.loginFailed();
                } else if (event instanceof InteractiveAuthenticationSuccessEvent) {
                    platform.audit("user.login", name(event), "", null);
                } else if (event instanceof LogoutSuccessEvent) {
                    platform.audit("user.logout", name(event), "", null);
                }
            } catch (RuntimeException ignored) {
                // never in the way of the login
            }
        }

        private static String name(AbstractAuthenticationEvent event) {
            return event.getAuthentication() == null ? "" : String.valueOf(event.getAuthentication().getName());
        }
    }

    /** The folders Spring serves as static files (spring.web.resources.static-locations). */
    public static final class StaticFolders {
        static final List<String> DEFAULTS = Arrays.asList("classpath:/META-INF/resources/", "classpath:/resources/",
                "classpath:/static/", "classpath:/public/");

        public StaticFolders(Platform platform, Environment env) {
            try {
                if (!PlatformAutoConfiguration.flag(env, "spring.web.resources.add-mappings", true)) {
                    return;
                }
                String pattern = PlatformAutoConfiguration.text(env, "spring.mvc.static-path-pattern");
                String prefix = pattern.isEmpty() ? "" : pattern.replaceAll("/\\*+$", "");
                List<String> locations = Checks.strings(env, "spring.web.resources.static-locations", DEFAULTS);
                ClassLoader loader = Thread.currentThread().getContextClassLoader();
                List<String[]> found = new ArrayList<>();
                for (String location : locations) {
                    for (String url : PlatformAutoConfiguration.resourceUrls(loader, location)) {
                        found.add(new String[] {url, prefix});
                    }
                }
                platform.servedLocations(found);
            } catch (RuntimeException ignored) {
                // posture goes without
            }
        }
    }

    /** Spring Boot settings that decide how much a hole in the site is worth. */
    public static final class Checks {
        static final Set<String> SENSITIVE = new LinkedHashSet<>(Arrays.asList("env", "configprops", "heapdump", "threaddump",
                "logfile", "shutdown", "loggers", "beans", "mappings", "httpexchanges", "sessions", "jolokia"));
        private final Environment env;

        public Checks(Platform platform, Environment env) {
            this.env = env;
            platform.frameworkChecks(this::checks);
        }

        List<Map<String, Object>> checks() {
            List<Map<String, Object>> out = new ArrayList<>();
            add(out, "app.session_cookie_httponly", !PlatformAutoConfiguration.flag(env, "server.servlet.session.cookie.http-only", true), "");
            // Cookie flags only matter once the site is on HTTPS, which these say it is.
            boolean https = PlatformAutoConfiguration.flag(env, "server.ssl.enabled", false)
                    || !PlatformAutoConfiguration.text(env, "server.servlet.session.cookie.secure").isEmpty();
            if (https) {
                add(out, "app.session_cookie_secure", !PlatformAutoConfiguration.flag(env, "server.servlet.session.cookie.secure", false), "");
            }
            String trace = PlatformAutoConfiguration.text(env, "server.error.include-stacktrace").toLowerCase(Locale.ROOT).replace('-', '_');
            boolean exception = PlatformAutoConfiguration.flag(env, "server.error.include-exception", false);
            boolean details = trace.equals("always") || trace.equals("on_param") || trace.equals("on_trace_param") || exception;
            add(out, "app.error_details", details, details ? (trace.isEmpty() ? "include-exception" : "include-stacktrace=" + trace) : "");
            if (present("org.springframework.boot.actuate.endpoint.annotation.Endpoint")) {
                List<String> open = actuatorOpen();
                add(out, "app.actuator_exposed", !open.isEmpty(), String.join(", ", open));
            }
            if (present("org.h2.Driver")) {
                add(out, "app.h2_console", PlatformAutoConfiguration.flag(env, "spring.h2.console.enabled", false), "");
            }
            return out;
        }

        /** Actuator endpoints that hand out secrets or control, open on the site's own port. */
        List<String> actuatorOpen() {
            List<String> open = new ArrayList<>();
            String port = PlatformAutoConfiguration.text(env, "management.server.port");
            String site = PlatformAutoConfiguration.text(env, "server.port");
            // -1: no HTTP endpoints; another port than the site's: not reachable through the site.
            if (port.equals("-1") || (!port.isEmpty() && !port.equals(site.isEmpty() ? "8080" : site))) {
                return open;
            }
            Set<String> include = lower(strings(env, "management.endpoints.web.exposure.include", Arrays.asList("health")));
            Set<String> exclude = lower(strings(env, "management.endpoints.web.exposure.exclude", new ArrayList<>()));
            for (String id : SENSITIVE) {
                if ((include.contains("*") || include.contains(id)) && !exclude.contains(id) && !exclude.contains("*")) {
                    open.add(id);
                }
            }
            return open;
        }

        /**
         * A list property as Spring Boot binds it: "a,b" in a .properties
         * file, or a YAML list (x[0], x[1]).
         */
        static List<String> strings(Environment env, String key, List<String> otherwise) {
            try {
                return org.springframework.boot.context.properties.bind.Binder.get(env)
                        .bind(key, org.springframework.boot.context.properties.bind.Bindable.listOf(String.class))
                        .orElse(otherwise);
            } catch (RuntimeException unbindable) {
                String value = PlatformAutoConfiguration.text(env, key);
                return value.isEmpty() ? otherwise : Arrays.asList(value.split("\\s*,\\s*"));
            }
        }

        private static Set<String> lower(List<String> values) {
            Set<String> out = new LinkedHashSet<>();
            for (String value : values) {
                String part = value == null ? "" : value.trim();
                if (!part.isEmpty()) {
                    out.add(part.toLowerCase(Locale.ROOT));
                }
            }
            return out;
        }

        private static boolean present(String name) {
            try {
                Class.forName(name, false, Thread.currentThread().getContextClassLoader());
                return true;
            } catch (ClassNotFoundException | LinkageError absent) {
                return false;
            }
        }

        private static void add(List<Map<String, Object>> out, String id, boolean failed, String value) {
            Map<String, Object> row = new LinkedHashMap<>();
            row.put("id", id);
            row.put("state", failed ? "fail" : "pass");
            if (value != null && !value.isEmpty()) {
                row.put("value", value.length() > 200 ? value.substring(0, 200) : value);
            }
            out.add(row);
        }
    }
    /**
     * Every DataSource bean with its queries timed (Health -> Server speed ->
     * Queries). The bean keeps its own class (a HikariDataSource is still
     * one, for whoever injects it by that type): only getConnection() is
     * intercepted, and hands out the connections Platform.wrap() times. A
     * final class gets Platform.wrap()'s DataSource-only wrapper instead. The
     * platform is looked up on the first query, so no bean is made early.
     */
    public static final class DataSources implements BeanPostProcessor {
        private final ObjectProvider<Platform> platform;

        public DataSources(ObjectProvider<Platform> platform) {
            this.platform = platform;
        }

        @Override
        public Object postProcessAfterInitialization(Object bean, String beanName) {
            if (!(bean instanceof DataSource) || isTimed(bean)) {
                return bean;
            }
            return wrap((DataSource) bean, platform::getIfAvailable);
        }

        static boolean isTimed(Object bean) {
            if (bean instanceof DataSource && Platform.isWrapped((DataSource) bean)) {
                return true;
            }
            if (bean instanceof Advised) {
                for (Advisor advisor : ((Advised) bean).getAdvisors()) {
                    if (advisor.getAdvice() instanceof Connections) {
                        return true;
                    }
                }
            }
            return false;
        }

        static Object wrap(DataSource bean, Supplier<Platform> platform) {
            DataSource timed = Platform.wrap(bean, platform);
            try {
                ProxyFactory factory = new ProxyFactory(bean);
                factory.setProxyTargetClass(true);
                factory.addAdvice(new Connections(timed));
                return factory.getProxy(bean.getClass().getClassLoader());
            } catch (RuntimeException | LinkageError finalClass) {
                return timed;
            }
        }
    }

    /** getConnection() through the timed DataSource; everything else is the bean's own. */
    static final class Connections implements MethodInterceptor {
        private final DataSource timed;

        Connections(DataSource timed) {
            this.timed = timed;
        }

        @Override
        public Object invoke(MethodInvocation invocation) throws Throwable {
            Method method = invocation.getMethod();
            if ("getConnection".equals(method.getName()) && method.getReturnType() == Connection.class) {
                Object[] args = invocation.getArguments();
                if (args.length == 0) {
                    return timed.getConnection();
                }
                if (args.length == 2 && (args[0] == null || args[0] instanceof String) && (args[1] == null || args[1] instanceof String)) {
                    return timed.getConnection((String) args[0], (String) args[1]);
                }
            }
            return invocation.proceed();
        }
    }
}
