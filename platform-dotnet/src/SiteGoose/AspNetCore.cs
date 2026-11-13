using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Antiforgery;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HostFiltering;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace SiteGoose;

/// <summary>ASP.NET Core wiring: the services, and the middleware.</summary>
public static class PlatformExtensions
{
    /// <summary>Everything, in one call: the platform, its middleware (first
    /// in the pipeline, so UseSiteGoose is optional), its background work (a
    /// hosted service, which sends what's waiting at shutdown), the error
    /// logger and the sign-in audit. Options come from the "SiteGoose"
    /// section of the configuration (appsettings.json, SiteGoose__Secret in
    /// the environment, ...), then configure, then ANALYTICS_SITE_ID,
    /// ANALYTICS_SITE_SECRET and ANALYTICS_ENDPOINT for what is still empty.</summary>
    public static IServiceCollection AddSiteGoose(this IServiceCollection services, Action<PlatformOptions>? configure = null)
    {
        if (services == null) throw new ArgumentNullException(nameof(services));
        var again = services.Any(d => d.ServiceType == typeof(PlatformHolder));
        if (configure != null) services.Configure(configure);
        if (again) return services;
        services.AddOptions<PlatformOptions>().BindConfiguration("SiteGoose");
        services.AddSingleton<PlatformHolder>();
        services.AddSingleton(provider =>
        {
            var options = provider.GetRequiredService<IOptions<PlatformOptions>>().Value;
            var environment = provider.GetService<IWebHostEnvironment>();
            List<PostureRoot>? roots = null;
            var web = environment?.WebRootPath;
            if (!string.IsNullOrEmpty(web) && Directory.Exists(web)) roots = new List<PostureRoot> { new() { Dir = web!, Prefix = "/" } };
            Platform? platform = null;
            platform = new Platform(options, roots, () => FrameworkChecks.Of(provider, environment, platform), provider.GetRequiredService<PlatformHolder>());
            return platform;
        });
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ILoggerProvider, ErrorLoggerProvider>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<CookieAuthenticationOptions>, CookieAudit>());
        services.AddHostedService<PlatformHostedService>();
        services.AddSingleton<Placement>();
        // First of all the startup filters, so its middleware runs before the
        // ones the host adds (IIS out-of-process, ASPNETCORE_FORWARDEDHEADERS_ENABLED)
        // and before any of yours: it notes the connection and X-Forwarded-For
        // as they arrived, then puts the platform's middleware in front of
        // the whole app.
        services.Insert(0, ServiceDescriptor.Transient<IStartupFilter, FirstFilter>());
        return services;
    }

    /// <summary>Optional: AddSiteGoose already puts the middleware (the
    /// firewall, maintenance mode, the proxy, security headers, request
    /// errors and timing) first in the pipeline, and then this adds nothing.
    /// Without AddSiteGoose (a Platform registered by hand), it adds the
    /// middleware here: call it first, before UseExceptionHandler, so it
    /// sees every request and every error.</summary>
    public static IApplicationBuilder UseSiteGoose(this IApplicationBuilder app)
    {
        if (app == null) throw new ArgumentNullException(nameof(app));
        // Decided when the pipeline is built, after the startup filters have
        // run: with minimal hosting this line runs before them.
        return app.Use(next =>
        {
            var placement = app.ApplicationServices.GetService<Placement>();
            if (placement?.Placed == true) return next;
            return new PlatformMiddleware(next, app.ApplicationServices.GetRequiredService<Platform>()).InvokeAsync;
        });
    }
}

/// <summary>Whether FirstFilter has put the middleware first, so an
/// explicit UseSiteGoose adds no second one.</summary>
internal sealed class Placement
{
    public bool Placed;
}

/// <summary>Starts the platform's background work, and stops it at shutdown
/// once what's waiting is sent.</summary>
internal sealed class PlatformHostedService : IHostedService
{
    private readonly Platform platform;

    public PlatformHostedService(Platform platform)
    {
        this.platform = platform;
    }

    public Task StartAsync(CancellationToken cancellationToken)
    {
        try
        {
            platform.Start();
        }
        catch (Exception error)
        {
            Console.WriteLine("[analytics-platform] could not start: " + error.Message);
        }
        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        try
        {
            var closing = platform.CloseAsync(cancellationToken);
            await Task.WhenAny(closing, Task.Delay(Timeout.Infinite, cancellationToken)).ConfigureAwait(false);
        }
        catch (Exception)
        {
        }
    }
}

/// <summary>The connection's address and X-Forwarded-For as the request
/// arrived, before a ForwardedHeadersMiddleware rewrote them: TrustProxy counts
/// proxies from the right of the whole header, as the other packages do.</summary>
internal sealed class Arrival
{
    public const string Item = "SiteGoose.Arrival";
    public string Remote = "";
    public string ForwardedFor = "";
}

/// <summary>Runs first of everything (AddSiteGoose inserts it before every
/// other startup filter): notes the request as it arrived (Arrival), then
/// puts the platform's middleware in front of the whole app.</summary>
internal sealed class FirstFilter : IStartupFilter
{
    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
    {
        var placement = app.ApplicationServices.GetService<Placement>();
        app.Use((context, nextMiddleware) =>
        {
            try
            {
                if (!context.Items.ContainsKey(Arrival.Item))
                {
                    context.Items[Arrival.Item] = new Arrival
                    {
                        Remote = Ip.Display(context.Connection.RemoteIpAddress),
                        ForwardedFor = context.Request.Headers["X-Forwarded-For"].ToString(),
                    };
                }
            }
            catch (Exception)
            {
            }
            return nextMiddleware();
        });
        // The platform's middleware, right after: in front of every one the
        // host and the app add, as UseSiteGoose first in Program.cs was.
        // Not with TrustProxy "aspnetcore": that reads the address your
        // UseForwardedHeaders() leaves, so it stays where UseSiteGoose puts
        // it, after that.
        var platform = placement != null ? app.ApplicationServices.GetRequiredService<Platform>() : null;
        if (platform != null && !platform.TrustsAspNetCore)
        {
            placement!.Placed = true;
            app.Use(nextMiddleware => new PlatformMiddleware(nextMiddleware, platform).InvokeAsync);
        }
        next(app);
    };
}

internal sealed class PlatformMiddleware
{
    private const int ClientClosed = 499;
    private readonly RequestDelegate next;
    private readonly Platform platform;

    public PlatformMiddleware(RequestDelegate next, Platform platform)
    {
        this.next = next;
        this.platform = platform;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        // Run again for the same request (UseExceptionHandler or status code
        // pages in front of this middleware): already seen and timed.
        if (context.Items.ContainsKey(Watchers.ItemOurs))
        {
            await next(context).ConfigureAwait(false);
            return;
        }
        var started = Stopwatch.GetTimestamp();
        var request = context.Request;
        var method = request.Method;
        var path = request.PathBase.Add(request.Path).Value ?? "/";
        // The connection and X-Forwarded-For as they arrived (Arrival), not as
        // a ForwardedHeadersMiddleware in front of this one left them.
        var remote = platform.RemoteOf(context);
        var header = Platform.HeaderReader(context);
        try
        {
            if (request.IsHttps) platform.SawHttpsDirect = platform.SawHttps = true;
            else if (string.Equals(header("x-forwarded-proto"), "https", StringComparison.OrdinalIgnoreCase)) platform.SawHttps = true;
        }
        catch (Exception)
        {
        }

        // The tracker's own addresses, answered before the rest: a visitor's
        // beacon is our traffic, not a page of the site. Only an address the
        // site turned away (deny, bans) is refused here too.
        var proxied = await ProxyAsync(context, remote, header).ConfigureAwait(false);
        if (proxied != null)
        {
            await WriteAsync(context, proxied).ConfigureAwait(false);
            return;
        }

        LateHit? late = null;
        if (!Skipped(context))
        {
            var blocked = platform.Blocked(remote, header, method, Target(context), out late);
            if (blocked != null)
            {
                await WriteAsync(context, blocked).ConfigureAwait(false);
                // A crawler the firewall turned away is still a crawler, and
                // counted with the status it got.
                platform.RecordCrawler(header("user-agent"), path, blocked.Status, started, 0, SafeIp(context));
                return;
            }
        }

        var closed = platform.MaintenanceResponse(remote, header, request.Path.Value ?? "/", request.QueryString.Value);
        if (closed?.Page != null)
        {
            await WriteAsync(context, closed.Page).ConfigureAwait(false);
            return;
        }
        var remember = closed?.RememberCookie;

        context.Items[Watchers.ItemOurs] = true;
        context.Response.OnStarting(() =>
        {
            var headers = context.Response.Headers;
            try
            {
                foreach (var pair in platform.SecurityHeaders(headers.Keys))
                {
                    // One header the server won't take never costs the others.
                    try
                    {
                        headers[pair.Key] = pair.Value;
                    }
                    catch (Exception)
                    {
                    }
                }
            }
            catch (Exception)
            {
            }
            try
            {
                if (remember != null) headers.Append("Set-Cookie", remember);
            }
            catch (Exception)
            {
            }
            return Task.CompletedTask;
        });

        var status = 0;
        // A static-looking request counts after the response if the router
        // sent it to a page (firewall.md, `rate`): once it is sent, so the
        // visitor never waits on it; status is the one the finally below took.
        if (late != null)
        {
            try
            {
                context.Response.OnCompleted(() =>
                {
                    CountStatic(context, late, status);
                    return Task.CompletedTask;
                });
            }
            catch (Exception)
            {
            }
        }
        // Errors captured during the request (logged, or caught deep in your
        // code) still know which request they came from, and its trail. Taken
        // when the request starts: an error captured after it ended (a task it
        // left running) must not read the next request on the same connection.
        var fields = new LiveFields(context);
        // Requests in progress at once, for the resources module's inflight_peak.
        var performance = platform.PerformanceModule;
        using (Scope.Enter(new Scope(fields.Get)))
        {
            // A WebSocket is known now, and runs its queries for as long as the
            // visitor stays: they are background ones as they run, not held for its end.
            if (Untimed(context)) platform.Untimed(Scope.Current);
            performance?.RequestStarted();
            try
            {
                await next(context).ConfigureAwait(false);
                status = context.Response.StatusCode;
            }
            catch (OperationCanceledException) when (context.RequestAborted.IsCancellationRequested)
            {
                // The visitor went away: not an error of the site's.
                status = ClientClosed;
                throw;
            }
            catch (IOException) when (context.RequestAborted.IsCancellationRequested)
            {
                // The connection was reset while reading or writing: the same.
                status = ClientClosed;
                throw;
            }
            catch (BadHttpRequestException error)
            {
                // A request the server refused (too large, malformed): the
                // visitor's mistake, answered with its own status, not a 500.
                status = error.StatusCode;
                throw;
            }
            catch (Exception error)
            {
                status = context.Response.HasStarted ? Math.Max(context.Response.StatusCode, 500) : 500;
                platform.CaptureException(error, Fields(context, path), status, "error");
                throw;
            }
            finally
            {
                performance?.RequestEnded();
                if (status == 0) status = context.Response.StatusCode;
                var route = Finish(context, method, path, status, started);
                fields.End(route);
            }
        }
    }

    /// <summary>The request's fields for its scope: method, path and visit as
    /// the request started; its route while it runs, then the one it ended with.</summary>
    private sealed class LiveFields
    {
        private readonly string method;
        private readonly string path;
        private readonly string session;
        private volatile HttpContext? context;
        private volatile string route = "";

        public LiveFields(HttpContext context)
        {
            this.context = context;
            method = context.Request.Method;
            path = context.Request.PathBase.Add(context.Request.Path).Value ?? "/";
            session = Platform.SessionId(context);
        }

        public RequestFields Get()
        {
            var live = context;
            var r = route;
            if (live != null)
            {
                try
                {
                    r = RouteOf(live);
                }
                catch (Exception)
                {
                }
            }
            return new RequestFields { Method = method, Path = path, Route = r, SessionId = session };
        }

        public void End(string finalRoute)
        {
            route = finalRoute;
            context = null;
        }
    }

    /// <summary>Upgraded connections (WebSockets) and event streams last as
    /// long as the visitor stays: their time isn't the server's speed.</summary>
    internal static bool Untimed(HttpContext context)
    {
        try
        {
            if (context.Features.Get<IHttpUpgradeFeature>()?.IsUpgradableRequest == true &&
                string.Equals(context.Request.Headers.Upgrade.ToString(), "websocket", StringComparison.OrdinalIgnoreCase)) return true;
            if (context.WebSockets.IsWebSocketRequest) return true;
            var type = context.Response.ContentType ?? "";
            return type.StartsWith("text/event-stream", StringComparison.OrdinalIgnoreCase);
        }
        catch (Exception)
        {
            return false;
        }
    }

    private string Finish(HttpContext context, string method, string path, int status, long started)
    {
        try
        {
            // Exceptions UseExceptionHandler, the developer exception page or
            // an MVC exception filter turned into a page, when the request
            // still ended as a server error (an exception handler that answers
            // 404 for a NotFoundException has handled it).
            if (status >= 500)
            {
                var items = context.Items;
                Exception? handled = null;
                if (items.TryGetValue(Watchers.ItemPending, out var pending)) handled = pending as Exception;
                handled ??= context.Features.Get<IExceptionHandlerFeature>()?.Error;
                if (handled != null && handled is not BadHttpRequestException) platform.CaptureException(handled, Fields(context, path), status, "error");
                if (items.TryGetValue(Watchers.ItemPendingFiltered, out var filtered) && filtered is Exception filteredError)
                {
                    platform.CaptureException(filteredError, Fields(context, path), status, "error");
                }
            }
        }
        catch (Exception)
        {
        }
        var route = "";
        try
        {
            var own = platform.Options.Performance.Route;
            if (own != null) route = own(context) ?? "";
            if (route.Length == 0) route = RouteOf(context);
            if (!Untimed(context)) platform.TimeRequest(method, route, status, started, path);
            else platform.Untimed(Scope.Current);
            if (platform.CrawlersModule != null)
            {
                platform.RecordCrawler(context.Request.Headers.UserAgent.ToString(), path, status, started, context.Response.ContentLength ?? 0, SafeIp(context));
            }
        }
        catch (Exception)
        {
        }
        return route;
    }

    /// <summary>A static-looking request the firewall only compared with the
    /// counts: counted after all when it answered 400 or more, or routing
    /// matched an endpoint for it (Razor Pages, MVC, minimal APIs) whose
    /// route pattern isn't a file's ("Home/Search/{q}" took
    /// "/Home/Search/x.css"). The static files middleware serves a file only
    /// when no endpoint matched; an endpoint answering a file's Content-Type
    /// is left alone too. Never throws.</summary>
    private void CountStatic(HttpContext context, LateHit late, int status)
    {
        try
        {
            // 499 is ours for a visitor who went away (a page left while its
            // files load), not an answer: the status the app had set stands.
            if (status == 0 || status == ClientClosed) status = context.Response.StatusCode;
            var routed = false;
            if (context.GetEndpoint() is RouteEndpoint endpoint && endpoint.RequestDelegate != null)
            {
                routed = Firewall.RoutedToPage(endpoint.RoutePattern.RawText ?? "", context.Response.ContentType);
            }
            platform.FirewallModule?.CountStatic(late, status, routed);
        }
        catch (Exception error)
        {
            platform.Core.Log("firewall", "could not count a static file: " + error.Message);
        }
    }

    private static RequestFields Fields(HttpContext context, string path)
    {
        var fields = Platform.FieldsOf(context, RouteOf(context));
        // The path as it arrived, not the error page's.
        fields.Path = path;
        return fields;
    }

    private string SafeIp(HttpContext context)
    {
        try
        {
            return platform.RequestIp(context);
        }
        catch (Exception)
        {
            return "";
        }
    }

    private bool Skipped(HttpContext context)
    {
        try
        {
            return platform.Options.Firewall.Skip?.Invoke(context) == true;
        }
        catch (Exception)
        {
            return false;
        }
    }

    /// <summary>The request target as sent (Kestrel's, IIS's and HTTP.sys's RawTarget).</summary>
    internal static string Target(HttpContext context)
    {
        string? raw = null;
        try
        {
            raw = context.Features.Get<IHttpRequestFeature>()?.RawTarget;
        }
        catch (Exception)
        {
        }
        var request = context.Request;
        return Core.RequestTarget(request.PathBase.Add(request.Path).Value, request.QueryString.Value, raw);
    }

    private async Task<Answer?> ProxyAsync(HttpContext context, string remote, Func<string, string> header)
    {
        var proxy = platform.Proxy;
        if (proxy == null) return null;
        try
        {
            var found = proxy.Match(context.Request.Path.Value);
            if (found == null) return null;
            var (kind, rest) = found.Value;
            var ip = platform.ClientIp(remote, header);
            if (!Skipped(context) && platform.FirewallModule?.AddressBlocked(ip, context.Request.Method, context.Request.Path.Value) != null)
            {
                return new Answer(403, new List<KeyValuePair<string, string>> { new("Cache-Control", "no-store") }, Array.Empty<byte>());
            }
            byte[]? body = null;
            if (HttpMethods.IsPost(context.Request.Method))
            {
                body = await Proxy.ReadLimited(context.Request.Body, Proxy.MaxBody + 1, context.RequestAborted).ConfigureAwait(false);
            }
            return await proxy.HandleAsync(kind, rest, context.Request.Method, context.Request.QueryString.Value, header, body, ip).ConfigureAwait(false);
        }
        catch (Exception error)
        {
            platform.Core.Log("proxy", "failed: " + error.Message);
            return new Answer(502, new List<KeyValuePair<string, string>>(), Array.Empty<byte>());
        }
    }

    internal static async Task WriteAsync(HttpContext context, Answer answer)
    {
        var response = context.Response;
        if (response.HasStarted) return;
        response.StatusCode = answer.Status;
        foreach (var pair in answer.Headers) response.Headers.Append(pair.Key, pair.Value);
        if (answer.Body.Length == 0 || HttpMethods.IsHead(context.Request.Method)) return;
        response.ContentLength = answer.Body.Length;
        await response.Body.WriteAsync(answer.Body, 0, answer.Body.Length, context.RequestAborted).ConfigureAwait(false);
    }

    private static readonly Regex Tokens = new("\\{(controller|action|area)(?:=([^}]*))?\\}", RegexOptions.CultureInvariant | RegexOptions.IgnoreCase);

    /// <summary>The route the request matched, as Server speed names it: the
    /// endpoint's route pattern ("/orders/{id:int}"), with a conventional MVC
    /// route's controller and action filled in ("/Home/Index/{id?}"). After
    /// UseExceptionHandler or status code pages ran, the endpoint the request
    /// first matched, not the error page's (.NET 7 and later). "" when
    /// nothing matched.</summary>
    internal static string RouteOf(HttpContext context)
    {
        var endpoint = context.GetEndpoint();
        RouteValueDictionary? values = context.Request.RouteValues;
#if NET7_0_OR_GREATER
        var handled = context.Features.Get<IExceptionHandlerFeature>();
        var again = context.Features.Get<IStatusCodeReExecuteFeature>();
        if (handled != null)
        {
            endpoint = handled.Endpoint;
            values = handled.RouteValues;
        }
        else if (again != null)
        {
            endpoint = again.Endpoint;
            values = again.RouteValues;
        }
#else
        if (context.Features.Get<IExceptionHandlerFeature>() != null || context.Features.Get<IStatusCodeReExecuteFeature>() != null) endpoint = null;
#endif
        if (endpoint is not RouteEndpoint matched) return "";
        var text = matched.RoutePattern.RawText ?? "";
        text = Tokens.Replace(text, m =>
        {
            var value = values != null && values.TryGetValue(m.Groups[1].Value.ToLowerInvariant(), out var v) ? v?.ToString() : null;
            if (string.IsNullOrEmpty(value)) value = m.Groups[2].Success ? m.Groups[2].Value : "";
            return value ?? "";
        });
        text = text.Replace("//", "/");
        if (!text.StartsWith("/", StringComparison.Ordinal)) text = "/" + text;
        var pathBase = context.Request.PathBase.Value;
        if (!string.IsNullOrEmpty(pathBase)) text = pathBase!.TrimEnd('/') + text;
        if (text.Length > 1 && text.EndsWith("/", StringComparison.Ordinal)) text = text.TrimEnd('/');
        return J.Clip(text, 200);
    }
}

/// <summary>Cookie authentication's sign-ins and sign-outs in the audit log,
/// as "user.login" and "user.logout" (AuditOptions.SignIns).</summary>
internal sealed class CookieAudit : IPostConfigureOptions<CookieAuthenticationOptions>
{
    private readonly IServiceProvider services;

    public CookieAudit(IServiceProvider services)
    {
        this.services = services;
    }

#if NET8_0_OR_GREATER
    public void PostConfigure(string? name, CookieAuthenticationOptions options)
#else
    public void PostConfigure(string name, CookieAuthenticationOptions options)
#endif
    {
        try
        {
            var platform = services.GetService<Platform>();
            if (platform == null || platform.AuditModule == null || !platform.Options.Audit.SignIns) return;
            if (!Audited(name, services.GetService<IOptions<AuthenticationOptions>>()?.Value)) return;
            // EventsType (events from the container) replaces Events: nothing to wrap then.
            var events = options.Events ?? new CookieAuthenticationEvents();
            var signedIn = events.OnSignedIn;
            var signingOut = events.OnSigningOut;
            events.OnSignedIn = context =>
            {
                platform.Audit("user.login", context.Principal?.Identity?.Name ?? "", "", null, context.HttpContext);
                return signedIn(context);
            };
            events.OnSigningOut = context =>
            {
                platform.Audit("user.logout", context.HttpContext.User?.Identity?.Name ?? "", "", null, context.HttpContext);
                return signingOut(context);
            };
            options.Events = events;
        }
        catch (Exception)
        {
        }
    }

    /// <summary>One sign-in is one login: only the scheme that keeps the
    /// signed-in user. Identity signs in and out of several cookie schemes at
    /// once (external logins, two-factor steps, "remember this browser"), and
    /// only Identity.Application is the user's own.</summary>
    internal static bool Audited(string? name, AuthenticationOptions? auth)
    {
        if (string.IsNullOrEmpty(name)) return false;
        if (name == "Identity.Application") return true;
        if (name!.StartsWith("Identity.", StringComparison.Ordinal)) return false;
        var main = auth?.DefaultAuthenticateScheme ?? auth?.DefaultScheme;
        // No default named: a single cookie scheme is the one.
        return main == null || main == name;
    }
}

/// <summary>The ASP.NET Core settings that decide how much a hole in the site
/// is worth (sdk/protocols/posture.md).</summary>
internal static class FrameworkChecks
{
    public static IEnumerable<PostureCheck> Of(IServiceProvider services, IWebHostEnvironment? environment, Platform? platform)
    {
        var checks = new List<PostureCheck>();
        void Add(string id, bool? failed, string? value = null)
        {
            checks.Add(new PostureCheck
            {
                Id = id,
                State = failed == null ? "unknown" : failed.Value ? "fail" : "pass",
                Value = string.IsNullOrEmpty(value) ? null : J.Clip(value, 200),
            });
        }

        // The Development environment shows visitors the developer exception page, stack and source.
        try
        {
            if (environment != null) Add("app.aspnetcore_env", environment.IsDevelopment(), environment.EnvironmentName);
        }
        catch (Exception)
        {
        }
        try
        {
            var hosts = services.GetService<IOptions<HostFilteringOptions>>()?.Value.AllowedHosts;
            if (hosts != null && hosts.Count > 0) Add("app.allowed_hosts", hosts.Contains("*"), string.Join(", ", hosts.Take(10)));
        }
        catch (Exception)
        {
        }

        // Cookie flags only matter once the site is on HTTPS, which a request has shown it is.
        var https = platform?.SawHttps == true;
        // SameAsRequest marks a cookie Secure only when the app itself sees
        // HTTPS: behind a proxy that ends TLS without UseForwardedHeaders, never.
        bool NotSecure(CookieSecurePolicy policy) =>
            policy == CookieSecurePolicy.None || (policy == CookieSecurePolicy.SameAsRequest && platform?.SawHttpsDirect != true);
        try
        {
            var schemes = services.GetService<IAuthenticationSchemeProvider>();
            var monitor = services.GetService<IOptionsMonitor<CookieAuthenticationOptions>>();
            if (schemes != null && monitor != null)
            {
                var cookies = schemes.GetAllSchemesAsync().GetAwaiter().GetResult()
                    .Where(s => typeof(CookieAuthenticationHandler).IsAssignableFrom(s.HandlerType))
                    .Select(s => monitor.Get(s.Name))
                    .ToList();
                if (cookies.Count > 0)
                {
                    Add("app.session_cookie_httponly", cookies.Any(c => !c.Cookie.HttpOnly));
                    if (https) Add("app.session_cookie_secure", cookies.Any(c => NotSecure(c.Cookie.SecurePolicy)));
                }
            }
        }
        catch (Exception)
        {
        }
        try
        {
            if (https && services.GetService<IAntiforgery>() != null)
            {
                var antiforgery = services.GetService<IOptions<AntiforgeryOptions>>()?.Value;
                if (antiforgery != null) Add("app.csrf_cookie_secure", NotSecure(antiforgery.Cookie.SecurePolicy));
            }
        }
        catch (Exception)
        {
        }
        return checks;
    }
}
